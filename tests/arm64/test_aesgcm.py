#!/usr/bin/env python3
"""test_aesgcm.py - unit tests for src/arm64/aesgcm.S under AArch64 emulation.

Builds src/arm64/aesgcm.S + tests/arm64/stubs_aesgcm.S into a throw-away DLL
(temp dir), loads it with tools/a64/unit.py (unicorn, max CPU model) and checks:

  * FIPS-197 C.1-C.3 (aes_expand_key + aes_ecb_block), unsupported key sizes,
    the aes_ecb_block Nr bound (fastfail through ff_trap), aes256_expand;
  * NIST GCM vectors (McGrew/Viega test cases 13-16, AES-256) incl. AAD and
    non-multiple-of-16 lengths, empty plaintext, in-place seal/open;
  * gcm_open tag-mismatch rejection: returns 1, zeroes a distinct outp, leaves
    outp == inp untouched, tolerates outp == NULL; SP 800-38D length bounds;
  * the streaming internals gcm_init / gcm_aad / gcm_crypt / gcm_final
    (context layout identical to the x64 GC_* offsets);
  * WinZip-AES CTR (aes_ctr_xor): little-endian 128-bit counter, chaining,
    wrap-around, x64-compatible return value, Nr bound;
  * random differential tests against the `cryptography` package;
  * the internal ABI on every call (unit.py) plus the stricter "only clobber
    what the x64 original clobbers" register sets and register/stack wiping.

Exit code 0 on success.  Environment overrides: CLANG, VORDR_MSVC_ENV (a .cmd
that puts link.exe on PATH), LINK (lld-link fallback).
"""
import os
import random
import struct
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "a64"))

from unit import A64Unit, V, X, STACK_BASE, STACK_SIZE  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_PC  # noqa: E402

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

CLANG = os.environ.get("CLANG", r"C:\Program Files\LLVM\bin\clang.exe")
MSVC_ENV = os.environ.get(
    "VORDR_MSVC_ENV",
    r"C:\Users\code\.gemini\antigravity\brain\84bae22e-21a6-460a-ba50-58fbdf011d5a\scratch\msvc\env.cmd")
LLD = os.environ.get("LINK", r"C:\Program Files\LLVM\bin\lld-link.exe")

EXPORTS = ["aes256_expand", "gcm_init", "gcm_aad", "gcm_crypt", "gcm_final",
           "gcm_seal", "gcm_open", "aes_expand_key", "aes_ecb_block",
           "aes_ctr_xor", "ff_trap", "secure_zero", "ct_memcmp"]

M64 = (1 << 64) - 1
FILL = 0x5A5A5A5A5A5A5A5A
FF_BOUNDS = 0xF004
CTX = 336


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
def build(outdir):
    objs = []
    for src, obj in ((ROOT / "src" / "arm64" / "aesgcm.S", "aesgcm.obj"),
                     (ROOT / "tests" / "arm64" / "stubs_aesgcm.S", "stubs_aesgcm.obj")):
        o = os.path.join(outdir, obj)
        subprocess.run([CLANG, "--target=aarch64-pc-windows-msvc", "-march=armv8.2-a+crypto",
                        "-c", str(src), "-o", o], check=True)
        objs.append(o)
    dll = os.path.join(outdir, "aesgcm_test.dll")
    largs = ["/nologo", "/dll", "/noentry", "/machine:arm64", "/nodefaultlib"]
    largs += ["/export:" + e for e in EXPORTS] + ["/out:" + dll] + objs
    if os.path.exists(MSVC_ENV):
        bat = os.path.join(outdir, "link.cmd")
        with open(bat, "w") as f:
            f.write("@echo off\r\n")
            f.write('call "%s" >nul\r\n' % MSVC_ENV)
            f.write("link %s\r\n" % " ".join('"%s"' % a for a in largs))
        r = subprocess.run(["cmd", "/c", bat], capture_output=True, text=True)
    else:
        r = subprocess.run([LLD] + largs, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("link failed:\n" + r.stdout + r.stderr)
    return dll


# ---------------------------------------------------------------------------
# reference models
# ---------------------------------------------------------------------------
def aes_ecb(key, block):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()


def winzip_ctr(key, data, ctr=0):
    out = bytearray()
    for i in range(0, len(data), 16):
        ctr = (ctr + 1) & ((1 << 128) - 1)
        ks = aes_ecb(key, ctr.to_bytes(16, "little"))
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out), ctr


def gcm_ref(key, iv, aad, pt):
    r = AESGCM(key).encrypt(iv, pt, aad or None)
    return r[:-16], r[-16:]


def vinit(i):
    return ((0xA5 ^ i) * 0x01010101010101010101010101010101) & ((1 << 128) - 1)


def xinit(i):
    return FILL ^ (i * 0x0101010101010101)


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------
class T:
    def __init__(self, dll):
        self.u = A64Unit(dll)
        self.passed = 0
        self.failed = 0

    def ok(self, cond, msg):
        if cond:
            self.passed += 1
        else:
            self.failed += 1
            print("  FAIL:", msg)

    def eq(self, got, exp, msg):
        self.ok(got == exp, "%s: got %s expected %s" % (
            msg, got.hex() if isinstance(got, (bytes, bytearray)) else got,
            exp.hex() if isinstance(exp, (bytes, bytearray)) else exp))

    def sp_at_call(self, nargs):
        nstack = max(0, nargs - 4)
        frame = (32 + 8 * nstack + 15) & ~15
        return STACK_BASE + STACK_SIZE - 0x1000 - frame

    def call(self, fn, *args, keep_x=(), zero_v=(), keep_v=(6, 7), tag=""):
        """u.call + x64-equivalence register checks.
        keep_x: ARM64 GPRs whose x64 counterpart the x64 routine leaves intact.
        zero_v: vector regs the x64 routine explicitly zeroes.
        keep_v: vector regs that must be untouched.
        Always: every volatile vector reg is either untouched or zero (wiped)."""
        u = self.u
        r = u.call(fn, *args)
        name = "%s%s" % (fn, tag)
        for i in keep_x:
            exp = (args[i] & M64) if (i < 4 and i < len(args)) else xinit(i)
            self.ok(u.uc.reg_read(X[i]) == exp, "%s: x%d modified" % (name, i))
        for i in keep_v:
            self.ok(u.uc.reg_read(V[i]) == vinit(i), "%s: v%d modified" % (name, i))
        for i in zero_v:
            self.ok(u.uc.reg_read(V[i]) == 0, "%s: v%d not zeroed" % (name, i))
        for i in list(range(0, 8)) + list(range(16, 32)):
            val = u.uc.reg_read(V[i])
            self.ok(val in (0, vinit(i)), "%s: v%d left with residue" % (name, i))
        return r

    def call_trap(self, fn, *args):
        """Expect a fastfail: execution must stop on ff_trap's BRK with w0 = code."""
        u = self.u
        try:
            u.call(fn, *args)
        except RuntimeError:
            pc = u.uc.reg_read(UC_ARM64_REG_PC)
            trap = u.sym("ff_trap")
            if trap <= pc <= trap + 4:
                return u.uc.reg_read(X[0]) & 0xFFFFFFFF
            raise
        return None

    def req(self, key, iv, aad, aadlen, inp, inlen, outp, tag):
        u = self.u
        p = u.alloc(64)
        u.write(p, struct.pack("<8Q", key, iv, aad, aadlen, inp, inlen, outp, tag))
        return p


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------
FIPS_PT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS_CT = {16: "69c4e0d86a7b0430d8cdb78070b4c55a",
           24: "dda97ca4864cdfe06eaf70a0ec0d7191",
           32: "8ea2b7ca516745bfeafc49904b496089"}


def test_ecb(t):
    u = t.u
    rk = u.alloc(240)
    blk = u.alloc(16)
    keyp = u.buf(bytes(range(32)))
    for kl, nr in ((16, 10), (24, 12), (32, 14)):
        u.write(rk, b"\x77" * 240)
        r = t.call("aes_expand_key", keyp, kl, rk, keep_v=(1, 2, 3, 4, 5, 6, 7), zero_v=(0,))
        t.eq(r, nr, "aes_expand_key(%d) Nr" % kl)
        t.eq(u.uc.reg_read(X[0]), 0, "aes_expand_key ecx=0")
        t.eq(u.uc.reg_read(X[1]), 0, "aes_expand_key edx=0")
        t.eq(u.read(rk + (nr + 1) * 16, 240 - (nr + 1) * 16), b"\x77" * (240 - (nr + 1) * 16),
             "aes_expand_key(%d) writes only (Nr+1)*16 bytes" % kl)
        u.write(blk, FIPS_PT)
        # high garbage in the Nr qword must be ignored (x64: mov r8d, r8d)
        r = t.call("aes_ecb_block", rk, blk, nr | 0xABCD123400000000,
                   keep_x=(0, 1, 3), keep_v=(2, 3, 4, 5, 6, 7), zero_v=(0, 1))
        t.eq(u.read(blk, 16), bytes.fromhex(FIPS_CT[kl]), "FIPS-197 C.%d" % {16: 1, 24: 2, 32: 3}[kl])
        t.eq(r, nr, "aes_ecb_block returns Nr in rax")
        t.eq(u.uc.reg_read(X[2]), nr, "aes_ecb_block zero-extends r8")
    # unsupported key lengths -> 0, nothing written, ecx/edx/r9 untouched
    for kl in (0, 1, 15, 17, 20, 23, 25, 31, 33, 64, 1 << 32 | 16):
        u.write(rk, b"\x77" * 240)
        r = t.call("aes_expand_key", keyp, kl, rk, keep_x=(0, 1, 2, 3), keep_v=tuple(range(8)))
        t.eq(r, 0, "aes_expand_key(%#x) rejected" % kl)
        t.eq(u.read(rk, 240), b"\x77" * 240, "aes_expand_key(%#x) wrote nothing" % kl)
    # aes_ecb_block Nr bound
    u.call("aes_expand_key", keyp, 32, rk)
    for nr in (0, 1, 9, 11, 13, 15, 16, 0xFFFFFFFF, 0x0000000100000009):
        code = t.call_trap("aes_ecb_block", rk, blk, nr)
        t.eq(code, FF_BOUNDS, "aes_ecb_block(Nr=%#x) fastfails FF_BOUNDS" % nr)
    # random-key differential (exercises the full key schedules)
    rnd = random.Random(1)
    for i in range(60):
        kl = (16, 24, 32)[i % 3]
        key = rnd.randbytes(kl)
        pt = rnd.randbytes(16)
        u.write(keyp, key)
        u.call("aes_expand_key", keyp, kl, rk)
        u.write(blk, pt)
        u.call("aes_ecb_block", rk, blk, kl // 4 + 6)
        t.eq(u.read(blk, 16), aes_ecb(key, pt), "random AES-%d ECB #%d" % (kl * 8, i))
    # aes256_expand == aes_expand_key(32); x64 touches only xmm0-4
    rk2 = u.alloc(240)
    for i in range(10):
        key = rnd.randbytes(32)
        u.write(keyp, key)
        u.call("aes_expand_key", keyp, 32, rk)
        t.call("aes256_expand", keyp, rk2, 0x1234, 0x5678,
               keep_x=(0, 1, 2, 3, 8, 9, 10), zero_v=(0, 1, 2, 3, 4), keep_v=(5, 6, 7))
        t.eq(u.read(rk2, 240), u.read(rk, 240), "aes256_expand schedule #%d" % i)
    u.write(keyp, bytes(range(32)))
    t.call("aes256_expand", keyp, rk2)
    u.write(blk, FIPS_PT)
    u.call("aes_ecb_block", rk2, blk, 14)
    t.eq(u.read(blk, 16), bytes.fromhex(FIPS_CT[32]), "aes256_expand FIPS-197 C.3")


# McGrew/Viega GCM spec test cases 13-16 (AES-256)
K16 = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
P16 = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
C16 = bytes.fromhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad")
GCM_VECTORS = [
    ("TC13 empty", bytes(32), bytes(12), b"", b"", b"", "530f8afbc74536b9a963b4f1c4cb738b"),
    ("TC14 16B", bytes(32), bytes(12), b"", bytes(16),
     bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18"), "d0d1c8a799996bf0265b98b5d48ab919"),
    ("TC15 64B", K16, bytes.fromhex("cafebabefacedbaddecaf888"), b"", P16, C16,
     "b094dac5d93471bdec1a502270e3cc6c"),
    ("TC16 60B+AAD20", K16, bytes.fromhex("cafebabefacedbaddecaf888"),
     bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"), P16[:60], C16[:60],
     "76fc6ece0f4e1768cddf8853bb2d551b"),
]


def seal(t, key, iv, aad, pt, inplace=False, tag=""):
    u = t.u
    kp, ivp = u.buf(key), u.buf(iv)
    ap = u.buf(aad) if aad else 0
    ip = u.buf(pt, 16)
    op = ip if inplace else u.alloc(len(pt) + 16)
    tp = u.alloc(16)
    rq = t.req(kp, ivp, ap, len(aad), ip, len(pt), op, tp)
    r = t.call("gcm_seal", rq, zero_v=(0, 1, 2, 3, 4, 5), tag=tag)
    # the on-stack context (round keys, H) must be wiped
    sp = t.sp_at_call(1)
    ctx = sp - 16 - 384 + 32
    t.eq(u.read(ctx, CTX), bytes(CTX), "gcm_seal%s wipes its context" % tag)
    return r, u.read(op, len(pt)), u.read(tp, 16)


def open_(t, key, iv, aad, ct, tg, outmode="distinct", tag=""):
    """outmode: distinct (prefilled 0xCC) | inplace | null"""
    u = t.u
    kp, ivp = u.buf(key), u.buf(iv)
    ap = u.buf(aad) if aad else 0
    ip = u.buf(ct, 16)
    if outmode == "inplace":
        op = ip
    elif outmode == "null":
        op = 0
    else:
        op = u.buf(b"\xCC" * len(ct), 16)
    tp = u.buf(tg)
    rq = t.req(kp, ivp, ap, len(aad), ip, len(ct), op, tp)
    r = t.call("gcm_open", rq, zero_v=(0, 1, 2, 3, 4, 5), tag=tag)
    sp = t.sp_at_call(1)
    ctx = sp - 16 - 400 + 32
    t.eq(u.read(ctx, CTX + 16), bytes(CTX + 16), "gcm_open%s wipes context + computed tag" % tag)
    out = u.read(op, len(ct)) if op else None
    return r, out, u.read(ip, len(ct))


def test_gcm_vectors(t):
    for name, key, iv, aad, pt, ct, tg in GCM_VECTORS:
        tg = bytes.fromhex(tg)
        rc, rt = gcm_ref(key, iv, aad, pt)
        t.ok(rc == ct and rt == tg, "%s: reference vector disagrees with cryptography" % name)
        r, c, g = seal(t, key, iv, aad, pt, tag=" " + name)
        t.eq(r, 0, name + " seal rc")
        t.eq(c, ct, name + " ciphertext")
        t.eq(g, tg, name + " tag")
        r, p, _ = open_(t, key, iv, aad, ct, tg, tag=" " + name)
        t.eq(r, 0, name + " open rc")
        t.eq(p, pt, name + " plaintext")
        # in place
        r, c2, g2 = seal(t, key, iv, aad, pt, inplace=True)
        t.ok(r == 0 and c2 == ct and g2 == tg, name + " in-place seal")
        r, p2, _ = open_(t, key, iv, aad, ct, tg, outmode="inplace")
        t.ok(r == 0 and p2 == pt, name + " in-place open")


def test_gcm_reject(t):
    _, key, iv, aad, pt, ct, tg = GCM_VECTORS[3]
    tg = bytes.fromhex(tg)
    bad_tag = bytes([tg[0] ^ 1]) + tg[1:]
    bad_ct = ct[:59] + bytes([ct[59] ^ 0x80])
    bad_aad = bytes([aad[0] ^ 4]) + aad[1:]
    cases = [("tag", aad, ct, bad_tag), ("ct", aad, bad_ct, tg), ("aad", bad_aad, ct, tg),
             ("aadlen", aad[:-1], ct, tg), ("ctlen", aad, ct[:-1], tg),
             ("tag-last-byte", aad, ct, tg[:15] + bytes([tg[15] ^ 0x40]))]
    for name, a, c, g in cases:
        r, out, inp = open_(t, key, iv, a, c, g, tag=" reject-" + name)
        t.eq(r, 1, "open rejects forged " + name)
        t.eq(out, bytes(len(c)), "forged %s: distinct outp zeroed" % name)
        t.eq(inp, c, "forged %s: input untouched" % name)
        r, out, _ = open_(t, key, iv, a, c, g, outmode="inplace")
        t.eq(r, 1, "in-place open rejects forged " + name)
        t.eq(out, c, "forged %s in place: buffer left as ciphertext" % name)
        r, out, _ = open_(t, key, iv, a, c, g, outmode="null")
        t.eq(r, 1, "outp=NULL open rejects forged " + name)
    # empty ciphertext with a bad tag
    k0 = bytes(32)
    r, out, _ = open_(t, k0, bytes(12), b"", b"", bytes(16))
    t.eq(r, 1, "empty ct + bad tag rejected")
    r, out, _ = open_(t, k0, bytes(12), b"", b"", bytes.fromhex(GCM_VECTORS[0][6]))
    t.eq(r, 0, "empty ct + good tag accepted")


def test_gcm_bounds(t):
    u = t.u
    kp, ivp, ip = u.buf(bytes(32)), u.buf(bytes(12)), u.buf(bytes(64))
    for fn in ("gcm_seal", "gcm_open"):
        for inlen, aadlen, exp in ((0xFFFFFFFE1, 0, 1), (M64, 0, 1), (1 << 40, 0, 1),
                                   (16, 0x2000000000000000, 1), (16, M64, 1),
                                   (0xFFFFFFFE1, M64, 1)):
            op = u.buf(b"\xAB" * 64)
            tp = u.buf(b"\xCD" * 16)
            rq = t.req(kp, ivp, 0, aadlen, ip, inlen, op, tp)
            r = t.call(fn, rq, keep_v=tuple(range(8)), tag=" bound")
            t.eq(r, exp, "%s inlen=%#x aadlen=%#x rejected" % (fn, inlen, aadlen))
            t.eq(u.read(op, 64), b"\xAB" * 64, "%s over-limit: outp untouched" % fn)
            if fn == "gcm_seal":
                t.eq(u.read(tp, 16), b"\xCD" * 16, "gcm_seal over-limit: tag untouched")


def test_gcm_random(t):
    rnd = random.Random(0xC0FFEE)
    lens = list(range(0, 49)) + [63, 64, 65, 255, 256, 257, 1000, 4096 + 7]
    for i, n in enumerate(lens):
        key, iv = rnd.randbytes(32), rnd.randbytes(12)
        aad = rnd.randbytes(rnd.choice([0, 1, 12, 15, 16, 17, 31, 32, 33, 80]))
        pt = rnd.randbytes(n)
        ec, et = gcm_ref(key, iv, aad, pt)
        r, c, g = seal(t, key, iv, aad, pt)
        t.ok(r == 0 and c == ec and g == et, "random seal len=%d aad=%d" % (n, len(aad)))
        mode = ("distinct", "inplace")[i % 2]
        r, p, _ = open_(t, key, iv, aad, ec, et, outmode=mode)
        t.ok(r == 0 and p == pt, "random open len=%d aad=%d (%s)" % (n, len(aad), mode))
        if n:
            j = rnd.randrange(n)
            bad = ec[:j] + bytes([ec[j] ^ (1 << rnd.randrange(8))]) + ec[j + 1:]
            r, p, _ = open_(t, key, iv, aad, bad, et)
            t.ok(r == 1 and p == bytes(n), "random forged open len=%d" % n)


def bswap16(b):
    return b[::-1]


def test_gcm_streaming(t):
    """gcm_init / gcm_aad / gcm_crypt / gcm_final (x64 globals, same ctx layout)."""
    u = t.u
    rnd = random.Random(7)
    ctx = u.alloc(CTX)
    tagp = u.alloc(16)
    for it in range(12):
        key, iv = rnd.randbytes(32), rnd.randbytes(12)
        aad = rnd.randbytes(rnd.choice([0, 5, 16, 40, 47]))
        pt = rnd.randbytes(rnd.choice([0, 3, 16, 48, 77, 160]))
        ec, et = gcm_ref(key, iv, aad, pt)
        kp, ivp = u.buf(key), u.buf(iv)
        u.write(ctx, b"\xEE" * CTX)
        mode = it % 2
        t.call("gcm_init", ctx, kp, ivp, mode, zero_v=(0, 1, 2, 3, 4, 5))
        c = u.read(ctx, CTX)
        rkref = u.alloc(240)
        u.call("aes256_expand", kp, rkref)
        t.eq(c[0:240], u.read(rkref, 240), "gcm_init round keys")
        t.eq(c[240:256], bswap16(aes_ecb(key, bytes(16))), "gcm_init H (byte-reflected)")
        t.eq(c[256:272], bytes(16), "gcm_init Y = 0")
        t.eq(c[272:288], iv + b"\0\0\0\1", "gcm_init J0")
        t.eq(c[288:304], iv + b"\0\0\0\1", "gcm_init CTR")
        t.eq(c[304:328], struct.pack("<3Q", 0, 0, mode), "gcm_init AADN/PTN/MODE")
        # AAD in 16-byte multiples, tail last
        ap = u.buf(aad)
        off = 0
        while off < len(aad):
            n = min(len(aad) - off, 16 * rnd.randint(1, 2))
            if len(aad) - off > n and n % 16:
                n -= n % 16
            u.write(STACK_BASE + STACK_SIZE - 0x1000 - 32, b"\xCC" * 32)
            t.call("gcm_aad", ctx, ap + off, n, keep_x=(0, 1, 2), zero_v=(0, 1, 2, 3, 4, 5))
            if n % 16:
                t.eq(u.read(t.sp_at_call(3), 16), bytes(16), "gcm_aad wipes tail scratch")
            off += n
        if mode == 0:
            data, expect = pt, ec
        else:
            data, expect = ec, pt
        ip = u.buf(data, 16)
        op = u.alloc(len(data) + 16)
        off = 0
        while True:
            n = min(len(data) - off, 16 * rnd.randint(0, 3))
            if off + n < len(data) and n % 16:
                n -= n % 16
            if off + n == len(data) or rnd.random() < 0.3:
                n = len(data) - off
            t.call("gcm_crypt", ctx, ip + off, op + off, n, keep_x=(0, 1), zero_v=(0, 1, 2, 3, 4, 5))
            t.eq(u.read(t.sp_at_call(4), 32), bytes(32), "gcm_crypt wipes home-area scratch")
            off += n
            if off >= len(data):
                break
        t.eq(u.read(op, len(data)), expect, "gcm_crypt output (mode %d)" % mode)
        c = u.read(ctx, CTX)
        nblk = (len(data) + 15) // 16
        t.eq(c[288:304], iv + struct.pack(">I", 1 + nblk), "gcm_crypt counter write-back")
        t.eq(struct.unpack("<2Q", c[304:320]), (len(aad), len(data)), "AADN/PTN accumulate")
        t.call("gcm_final", ctx, tagp, keep_x=(0, 1), zero_v=(0, 1, 2, 3, 4, 5))
        t.eq(u.read(tagp, 16), et, "gcm_final tag (mode %d, aad %d, len %d)" % (mode, len(aad), len(pt)))


def test_ctr(t):
    u = t.u
    rnd = random.Random(42)
    rk = u.alloc(240)
    keyp = u.alloc(32)
    ctr = u.alloc(16)

    def ctr_call(data_p, n, nr, tag=""):
        # 5th argument = Nr (dword); garbage in the high half must be ignored
        return t.call("aes_ctr_xor", rk, data_p, n, ctr, (0xABCDEF01 << 32) | nr,
                      keep_v=(2, 3, 4, 5, 6, 7), zero_v=(0, 1), tag=tag)

    # selftest vector: AES-256 key 00..1f, 19 bytes 00..12, decrypt round-trip
    key = bytes(range(32))
    u.write(keyp, key)
    u.call("aes_expand_key", keyp, 32, rk)
    pt = bytes(range(19))
    dp = u.buf(pt)
    u.write(ctr, bytes(16))
    r = ctr_call(dp, 19, 14)
    exp, _ = winzip_ctr(key, pt)
    t.eq(u.read(dp, 19), exp, "WinZip CTR 19-byte selftest vector")
    t.eq(r, 3, "aes_ctr_xor rax = bytes left at last block")
    t.eq(u.uc.reg_read(X[9]), 0, "aes_ctr_xor r10 = 0")
    t.eq(u.read(ctr, 16), (2).to_bytes(16, "little"), "counter advanced by 2")
    u.write(ctr, bytes(16))
    ctr_call(dp, 19, 14)
    t.eq(u.read(dp, 19), pt, "WinZip CTR decrypt round-trip")

    for kl in (16, 24, 32):
        nr = kl // 4 + 6
        for n in list(range(0, 40)) + [64, 100, 1000]:
            key = rnd.randbytes(kl)
            data = rnd.randbytes(n)
            u.write(keyp, key)
            u.call("aes_expand_key", keyp, kl, rk)
            start = rnd.choice([0, 0, rnd.getrandbits(128), (1 << 64) - 1, (1 << 128) - 1])
            u.write(ctr, start.to_bytes(16, "little"))
            dp = u.buf(data)
            r = ctr_call(dp, n, nr)
            exp, endc = winzip_ctr(key, data, start)
            t.eq(u.read(dp, n), exp, "AES-%d CTR len=%d start=%#x" % (kl * 8, n, start))
            t.eq(u.read(ctr, 16), endc.to_bytes(16, "little"), "AES-%d CTR counter after len=%d" % (kl * 8, n))
            exp_rax = nr if n == 0 else (16 if n % 16 == 0 else n % 16)
            t.eq(r, exp_rax, "aes_ctr_xor rax len=%d" % n)
    # chaining: 16-multiple chunks continue the stream (zipexport pattern)
    key = rnd.randbytes(32)
    u.write(keyp, key)
    u.call("aes_expand_key", keyp, 32, rk)
    data = rnd.randbytes(203)
    dp = u.buf(data)
    u.write(ctr, bytes(16))
    for a, b in ((0, 48), (48, 160), (160, 203)):
        ctr_call(dp + a, b - a, 14)
    exp, _ = winzip_ctr(key, data)
    t.eq(u.read(dp, 203), exp, "chained CTR calls")
    # wrap-around of the full 128-bit counter
    u.write(ctr, b"\xff" * 16)
    dp = u.buf(bytes(16))
    ctr_call(dp, 16, 14)
    t.eq(u.read(dp, 16), aes_ecb(key, bytes(16)), "counter wraps to 0")
    t.eq(u.read(ctr, 16), bytes(16), "counter is 0 after wrap")
    # Nr bound: len 0 never validates; len > 0 fastfails
    u.write(ctr, bytes(16))
    r = ctr_call(dp, 0, 7, tag=" len0")
    t.eq(r, 7, "aes_ctr_xor len=0 returns Nr, no check")
    t.eq(u.read(ctr, 16), bytes(16), "aes_ctr_xor len=0 leaves counter")
    for nr in (0, 11, 13, 15):
        code = t.call_trap("aes_ctr_xor", rk, dp, 16, ctr, nr)
        t.eq(code, FF_BOUNDS, "aes_ctr_xor Nr=%d fastfails" % nr)


def main():
    with tempfile.TemporaryDirectory(prefix="vordr_a64_aesgcm_") as d:
        dll = build(d)
        t = T(dll)
        groups = [("AES ECB / key schedules", test_ecb),
                  ("GCM NIST vectors + in-place", test_gcm_vectors),
                  ("GCM tag mismatch rejection", test_gcm_reject),
                  ("GCM SP 800-38D length bounds", test_gcm_bounds),
                  ("GCM streaming internals", test_gcm_streaming),
                  ("WinZip-AES CTR", test_ctr),
                  ("GCM random differential", test_gcm_random)]
        for name, fn in groups:
            before = t.failed
            try:
                fn(t)
            except Exception:
                t.failed += 1
                traceback.print_exc()
            print("%-34s %s" % (name, "PASS" if t.failed == before else "FAIL"))
        print("checks: %d passed, %d failed" % (t.passed, t.failed))
        print("PASS" if t.failed == 0 else "FAIL")
        t.u.pe.close()
        return 0 if t.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
