"""test_sha.py - unit test for src/arm64/sha.S (sha256_compress, sha1_block).

Standalone: assembles src/arm64/sha.S with clang, links a test DLL in its own
temp dir, and drives both routines under tools/a64/unit.py (AArch64 emulation
with the docs/ARM64.md ABI checker).  Padding/finalization is done in Python so
full SHA-256 / SHA-1 / HMAC-SHA1 digests can be compared with hashlib/hmac.

Besides digests it checks, on EVERY call, the exact register contract of the
x64 originals:
  sha256_compress: x0, x3..x10 (and x8 = rax) unchanged, x1 += 64*count,
                   x2 = 0, v0..v5 = 0, v6/v7 (xmm14/15) unchanged, no residue
                   in v16..v31, no stack writes, no writes outside the 32-byte
                   state, block buffer unchanged.
  sha1_block:      x0..x10 unchanged, v0 = 0, v1..v7 unchanged, no residue,
                   no stack writes, ctx+20.. untouched, block unchanged.
plus count = 0 (no memory access at all), unaligned buffers, and
constant-time traces (identical PC + memory-address sequences for different
secrets).

Env overrides: VORDR_SHA_SRC (source to test), VORDR_CLANG, VORDR_MSVC_ENV (vcvars-style .cmd that puts link.exe
on PATH).  Prints PASS/FAIL; exit code 0 on success.
"""
import hashlib
import hmac
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "a64"))
import unit  # noqa: E402
from unit import A64Unit, V, X  # noqa: E402
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X18, UC_ARM64_REG_X30  # noqa: E402

CLANG = os.environ.get("VORDR_CLANG", r"C:\Program Files\LLVM\bin\clang.exe")
MSVC_ENV = os.environ.get(
    "VORDR_MSVC_ENV",
    r"C:\Users\code\.gemini\antigravity\brain\84bae22e-21a6-460a-ba50-58fbdf011d5a\scratch\msvc\env.cmd")
SRC = Path(os.environ.get("VORDR_SHA_SRC", ROOT / "src" / "arm64" / "sha.S"))

M64 = (1 << 64) - 1
REP = 0x0101010101010101
CALL_SP = unit.STACK_BASE + unit.STACK_SIZE - 0x1000 - 32   # sp the harness uses (<=4 args)
STACK_PROBE = 0x1000                                         # bytes below sp checked for writes

FAILS = []
CHECKS = 0


def check(cond, what):
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(what)
        if len(FAILS) <= 25:
            print("  FAIL:", what)
    return cond


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
def build(tmp):
    obj = tmp / "sha.obj"
    dll = tmp / "sha.dll"
    subprocess.run([CLANG, "--target=aarch64-pc-windows-msvc", "-march=armv8.2-a+crypto",
                    "-c", str(SRC), "-o", str(obj)], check=True)
    link = (f'link /nologo /dll /noentry /machine:arm64 /nodefaultlib '
            f'/export:sha256_compress /export:sha1_block /out:"{dll}" "{obj}"')
    bat = tmp / "link.cmd"            # a batch file sidesteps cmd /c quoting rules
    pre = f'call "{MSVC_ENV}" >nul\r\n' if os.path.exists(MSVC_ENV) else ""
    bat.write_text(f"@echo off\r\n{pre}{link}\r\nexit /b %errorlevel%\r\n")
    subprocess.run(["cmd", "/c", str(bat)], check=True)
    return dll


# ---------------------------------------------------------------------------
# instrumented call wrapper
# ---------------------------------------------------------------------------
class Harness:
    def __init__(self, dll, rng):
        self.u = A64Unit(str(dll))
        self.rng = rng
        self.arena_size = 1_200_000
        self.arena = self.u.alloc(self.arena_size + 256)
        self.ctx = self.u.alloc(256)          # state lives at ctx+64 (guards on both sides)
        self.calls = 0
        self.stack_pat = rng.randbytes(STACK_PROBE)

    def _vpattern(self, i):
        return (0xA5 ^ i) * 0x01010101010101010101010101010101

    def call(self, fn, args, vzero, vkeep, xmod):
        """Run fn under the ABI checker with random poison and verify the
        exact post-call register contract.  vzero: v regs that must be 0;
        vkeep: v regs (besides v8-v15) that must be unchanged; xmod: dict of
        x-reg index -> expected value for regs the routine legitimately changes."""
        u, uc, rng = self.u, self.u.uc, self.rng
        fill = rng.getrandbits(64)
        vin = {i: rng.randbytes(16) for i in range(8)}
        probe_lo = CALL_SP - STACK_PROBE
        stack_pat = self.stack_pat
        uc.mem_write(probe_lo, stack_pat)
        rax = u.call(fn, *args, fill=fill, vin=vin)
        self.calls += 1
        tag = f"{fn}#{self.calls}"
        # integer registers x0..x10 (x0-x3 args, x4-x10 poison incl. x8 = rax)
        for i in range(11):
            want = (args[i] & M64) if i < len(args) else (fill ^ (i * REP)) & M64
            if i in xmod:
                want = xmod[i] & M64
            got = uc.reg_read(X[i])
            check(got == want, f"{tag}: x{i} = {got:#x}, want {want:#x}")
        check(rax == (fill ^ (8 * REP)) & M64, f"{tag}: rax/x8 modified")
        # vector registers
        for i in vzero:
            check(uc.reg_read(V[i]) == 0, f"{tag}: v{i} not zeroed")
        for i in vkeep:
            check(uc.reg_read(V[i]) == int.from_bytes(vin[i], "little"), f"{tag}: v{i} modified")
        for i in range(16, 32):
            val = uc.reg_read(V[i])
            check(val in (0, self._vpattern(i)), f"{tag}: v{i} left data residue {val:#x}")
        # no stack writes (below sp, and the callee-owned home area untouched too)
        check(bytes(uc.mem_read(probe_lo, STACK_PROBE)) == stack_pat, f"{tag}: wrote below sp")
        check(bytes(uc.mem_read(CALL_SP, 32)) == b"\xCC" * 32, f"{tag}: wrote home area")
        return rax

    # ---- sha256_compress -------------------------------------------------
    def sha256_compress(self, state_addr, data_addr, n):
        self.call("sha256_compress", (state_addr, data_addr, n),
                  vzero=range(0, 6), vkeep=(6, 7), xmod={1: data_addr + 64 * n, 2: 0})

    def sha256(self, msg, data_off=0, state_off=0, max_chunk=None):
        """SHA-256 of msg through sha256_compress, splitting the block run into
        random chunk counts (max_chunk) to exercise multi-block calls."""
        u, rng = self.u, self.rng
        ml = len(msg)
        padded = msg + b"\x80" + b"\0" * ((55 - ml) % 64) + struct.pack(">Q", ml * 8)
        assert len(padded) % 64 == 0 and len(padded) <= self.arena_size
        data = self.arena + data_off
        u.write(data, padded)
        st = self.ctx + 64 + state_off
        g1, g2 = rng.randbytes(64), rng.randbytes(64)
        u.write(st - 64, g1)
        u.write(st + 32, g2)
        u.write(st, struct.pack("<8I", 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19))
        nblk = len(padded) // 64
        done = 0
        while done < nblk:
            n = nblk - done if max_chunk is None else rng.randint(1, min(max_chunk, nblk - done))
            self.sha256_compress(st, data + 64 * done, n)
            done += n
        check(u.read(st - 64, 64) == g1 and u.read(st + 32, 64) == g2,
              f"sha256 len={ml}: wrote outside the 32-byte state")
        check(u.read(data, len(padded)) == padded, f"sha256 len={ml}: modified input")
        words = struct.unpack("<8I", u.read(st, 32))     # native LE words, as x64
        return b"".join(struct.pack(">I", w) for w in words)

    # ---- sha1_block -------------------------------------------------------
    def sha1_block(self, ctx_addr, blk_addr):
        self.call("sha1_block", (ctx_addr, blk_addr),
                  vzero=(0,), vkeep=(1, 2, 3, 4, 5, 6, 7), xmod={})

    def sha1(self, msg, data_off=0, state_off=0):
        u, rng = self.u, self.rng
        ml = len(msg)
        padded = msg + b"\x80" + b"\0" * ((55 - ml) % 64) + struct.pack(">Q", ml * 8)
        assert len(padded) <= self.arena_size
        data = self.arena + data_off
        u.write(data, padded)
        st = self.ctx + 64 + state_off
        g1, tail = rng.randbytes(64), rng.randbytes(76 + 64)   # ctx+20..95 (buflen, len, buf)
        u.write(st - 64, g1)
        u.write(st + 20, tail)
        u.write(st, struct.pack("<5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0))
        for b in range(len(padded) // 64):
            self.sha1_block(st, data + 64 * b)
        check(u.read(st - 64, 64) == g1 and u.read(st + 20, len(tail)) == tail,
              f"sha1 len={ml}: wrote outside h0..h4")
        check(u.read(data, len(padded)) == padded, f"sha1 len={ml}: modified input")
        words = struct.unpack("<5I", u.read(st, 20))
        return b"".join(struct.pack(">I", w) for w in words)

    def hmac_sha1(self, key, msg):
        if len(key) > 64:
            key = self.sha1(key)
        key = key.ljust(64, b"\0")
        inner = self.sha1(bytes(k ^ 0x36 for k in key) + msg)
        return self.sha1(bytes(k ^ 0x5C for k in key) + inner)

    def hmac_sha256(self, key, msg):
        if len(key) > 64:
            key = self.sha256(key)
        key = key.ljust(64, b"\0")
        inner = self.sha256(bytes(k ^ 0x36 for k in key) + msg)
        return self.sha256(bytes(k ^ 0x5C for k in key) + inner)

    # ---- constant-time trace ---------------------------------------------
    def trace(self, fn, args):
        uc = self.u.uc
        pcs, mem, bad = [], [], []

        def on_code(uc_, addr, size, _):
            pcs.append(addr)
            if (uc_.reg_read(UC_ARM64_REG_SP) != CALL_SP or uc_.reg_read(UC_ARM64_REG_X30) != unit.RET_MAGIC
                    or uc_.reg_read(UC_ARM64_REG_X18) != self.u.teb):
                bad.append(addr)

        def on_mem(uc_, access, addr, size, value, _):
            mem.append((access, addr, size))

        h1 = uc.hook_add(UC_HOOK_CODE, on_code)
        h2 = uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, on_mem)
        uc.ctl_flush_tb()                 # re-translate cached blocks with the hooks
        try:
            self.u.call(fn, *args)
        finally:
            uc.hook_del(h1)
            uc.hook_del(h2)
            uc.ctl_flush_tb()
        if not pcs or not mem:
            bad.append("nothing traced")
        return pcs, mem, bad


# ---------------------------------------------------------------------------
# known-answer data
# ---------------------------------------------------------------------------
M448 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
M896 = (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
FIPS256 = [
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (M448, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    (M896, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
    (b"a" * 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
]
FIPS1 = [
    (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    (M448, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
    (M896, "a49b2446a02c645bf419f995b67091253a04a259"),
    (b"a" * 1000000, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"),
]
RFC2202 = [
    (b"\x0b" * 20, b"Hi There", "b617318655057264e28bc0b6fb378c8ef146be00"),
    (b"Jefe", b"what do ya want for nothing?", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
    (b"\xaa" * 20, b"\xdd" * 50, "125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
    (bytes(range(1, 26)), b"\xcd" * 50, "4c9007f4026250c6bc8414f9bf50c86c2d7235da"),
    (b"\x0c" * 20, b"Test With Truncation", "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"),
    (b"\xaa" * 80, b"Test Using Larger Than Block-Size Key - Hash Key First",
     "aa4ae5e15272d00e95705637ce8a3b55ed402112"),
    (b"\xaa" * 80, b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
     "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"),
]


def run():
    rng = random.Random(0x5EED_A64)
    tmp = Path(tempfile.mkdtemp(prefix="vordr_test_sha_"))
    try:
        dll = build(tmp)
        h = Harness(dll, rng)
        u = h.u

        print("[1] FIPS 180-4 vectors")
        for m, hx in FIPS256:
            check(hashlib.sha256(m).hexdigest() == hx, f"self-check sha256 KAT len={len(m)}")
            check(h.sha256(m).hex() == hx, f"SHA-256 FIPS len={len(m)}")
        for m, hx in FIPS1:
            check(hashlib.sha1(m).hexdigest() == hx, f"self-check sha1 KAT len={len(m)}")
            check(h.sha1(m).hex() == hx, f"SHA-1 FIPS len={len(m)}")

        print("[2] all lengths 0..300 (random data / chunking / alignment)")
        for ml in range(301):
            m = rng.randbytes(ml)
            do, so = rng.randrange(16), rng.choice((0, 0, 4, 1, 7))
            check(h.sha256(m, do, so, max_chunk=rng.choice((None, 1, 2, 3))) == hashlib.sha256(m).digest(),
                  f"SHA-256 len={ml}")
            check(h.sha1(m, do, so) == hashlib.sha1(m).digest(), f"SHA-1 len={ml}")

        print("[3] large random inputs, multi-block runs")
        for ml in (1000, 4095, 4096, 4097, 65536 + 13, 250_000, 1_000_000):
            m = rng.randbytes(ml)
            for mc in (None, 7, 1000):
                check(h.sha256(m, rng.randrange(64), max_chunk=mc) == hashlib.sha256(m).digest(),
                      f"SHA-256 large len={ml} chunk={mc}")
            if ml <= 250_000:
                check(h.sha1(m, rng.randrange(64)) == hashlib.sha1(m).digest(), f"SHA-1 large len={ml}")

        print("[4] block count 0 == x64 (no access, x1 kept, x2=0, v0-v5 zeroed)")
        # unmapped pointers: any access would fault
        h.sha256_compress(0x1000, 0x2000, 0)
        st = h.ctx + 64
        junk = rng.randbytes(32)
        u.write(st, junk)
        h.sha256_compress(st, h.arena, 0)
        check(u.read(st, 32) == junk, "count 0 changed the state")

        print("[5] HMAC-SHA1 (RFC 2202) through sha1_block")
        for key, msg, hx in RFC2202:
            check(hmac.new(key, msg, hashlib.sha1).hexdigest() == hx, "self-check RFC 2202")
            check(h.hmac_sha1(key, msg).hex() == hx, f"HMAC-SHA1 RFC2202 key={len(key)} msg={len(msg)}")
        for _ in range(20):
            key, msg = rng.randbytes(rng.randrange(0, 150)), rng.randbytes(rng.randrange(0, 300))
            check(h.hmac_sha1(key, msg) == hmac.new(key, msg, hashlib.sha1).digest(), "HMAC-SHA1 random")
            check(h.hmac_sha256(key, msg) == hmac.new(key, msg, hashlib.sha256).digest(), "HMAC-SHA256 random")

        print("[6] constant-time traces (PC + memory addresses independent of data)")
        st, data = h.ctx + 64, h.arena
        traces = []
        for _ in range(3):
            u.write(st, rng.randbytes(32))
            u.write(data, rng.randbytes(64 * 3))
            traces.append(h.trace("sha256_compress", (st, data, 3)))
        for pcs, mem, bad in traces:
            check(not bad, "sha256_compress changed sp/lr/x18 mid-routine")
        check(all(t[0] == traces[0][0] and t[1] == traces[0][1] for t in traces),
              "sha256_compress trace depends on data")
        traces = []
        for _ in range(3):
            u.write(st, rng.randbytes(20))
            u.write(data, rng.randbytes(64))
            traces.append(h.trace("sha1_block", (st, data)))
        for pcs, mem, bad in traces:
            check(not bad, "sha1_block changed sp/lr/x18 mid-routine")
        check(all(t[0] == traces[0][0] and t[1] == traces[0][1] for t in traces),
              "sha1_block trace depends on data")
        n256 = len(h.trace("sha256_compress", (st, data, 1))[0])
        n1 = len(h.trace("sha1_block", (st, data))[0])
        print(f"    instructions: sha256_compress {n256}/block-run of 1, sha1_block {n1}")

        print(f"    {h.calls} ABI-checked calls")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if FAILS:
        print(f"FAIL ({len(FAILS)} of {CHECKS} checks failed)")
        return 1
    print(f"PASS ({CHECKS} checks)")
    return 0


if __name__ == "__main__":
    sys.exit(run())
