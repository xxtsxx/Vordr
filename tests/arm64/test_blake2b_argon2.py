#!/usr/bin/env python3
"""test_blake2b_argon2.py - unit tests for src/arm64/blake2b_argon2.S under emulation.

Builds the hand-written AArch64 file into a throw-away DLL (own temp dir), runs it
in unicorn through tools/a64/unit.py (Vordr internal ARM64 ABI checker on every
call) and checks:

  (a) blake2b_compress
      - directly against a Python BLAKE2b F (random h, t incl. carries, block,
        last flag 0 / ~0 / arbitrary 64-bit value - the x64 code XORs r8 as is),
        including a block that aliases the ctx;
      - driven through a Python copy of blake2b_init/update/final's exact x64
        buffering (byte-wise update, lazy compress only when the 128-byte buffer
        is full AND more data follows, t += 128 before compress, final t += buflen,
        zero pad, lastflag = ~0), compared with hashlib.blake2b for every digest
        size 1..64, unkeyed and keyed, many lengths incl. 0, 128, 129, 256.
  (b) argon2_compress against a Python RFC 9106 G (fBlaMka, P on rows then
      columns, final XOR) and its with_xor variant, on random blocks, with every
      aliasing pattern (dst==X, dst==Y as in the address-block generation,
      X==Y, all equal), unaligned blocks, with_xor given only in the high bits,
      and on the exact block KAT of src/selftest.asm (arg_cksum / arg_out0).
  (c) end-to-end Argon2id driven exactly like argon2.asm (same call pattern,
      address block via compress(addr, zero, inp) + compress(addr, zero, addr))
      with H0/H' also hashed through the emulated blake2b_compress: the RFC 9106
      test vector (p=4) and p=1 configurations against a pure-Python reference
      (and the `cryptography` package's Argon2id when available).
  (d) every call: x19-x29 / sp / v8-v15 / x18 (unit.py), plus x0-x10 (all
      x64-mapped GPRs) unchanged, v0-v7 / v16-v31 returned zeroed (scrub), the
      argon2 stack work area wiped, and blake2b_compress not touching the stack.

Prints emulated instruction counts per call.  Exit 0 = PASS.
"""
import hashlib, os, random, shutil, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "a64"))
import unit  # noqa: E402
from unit import A64Unit, X, V, STACK_BASE, STACK_SIZE  # noqa: E402
from unicorn import UC_HOOK_CODE  # noqa: E402

CLANG = os.environ.get("CLANG", r"C:\Program Files\LLVM\bin\clang.exe")
MSVC_ENV = os.environ.get(
    "MSVC_ENV",
    r"C:\Users\code\.gemini\antigravity\brain\84bae22e-21a6-460a-ba50-58fbdf011d5a\scratch\msvc\env.cmd")
SRC = os.environ.get("B2A2_SRC", os.path.join(ROOT, "src", "arm64", "blake2b_argon2.S"))

M64 = (1 << 64) - 1
FILL = 0x5A5A5A5A5A5A5A5A
FAILS = []


def check(ok, what):
    if not ok:
        FAILS.append(what)
        print("FAIL:", what)
    return ok


# ============================================================== build ======
def build(tmp):
    obj = os.path.join(tmp, "b2a2.obj")
    stobj = os.path.join(tmp, "stubs.obj")
    dll = os.path.join(tmp, "b2a2.dll")
    stubs_src = os.path.join(ROOT, "tests", "arm64", "stubs_aesgcm.S")
    subprocess.run([CLANG, "--target=aarch64-pc-windows-msvc", "-march=armv8.2-a+crypto",
                    "-c", SRC, "-o", obj], check=True)
    subprocess.run([CLANG, "--target=aarch64-pc-windows-msvc", "-march=armv8.2-a+crypto",
                    "-c", stubs_src, "-o", stobj], check=True)
    script = os.path.join(tmp, "link.cmd")      # a script sidesteps cmd /c quoting
    with open(script, "w") as f:
        f.write("@echo off\r\n"
                f'call "{MSVC_ENV}" >nul || exit /b 1\r\n'
                "link /nologo /dll /noentry /machine:arm64 /nodefaultlib "
                "/export:blake2b_compress /export:argon2_compress "
                f'/out:"{dll}" "{obj}" "{stobj}" || exit /b 1\r\n')
    subprocess.run(["cmd", "/c", script], check=True, stdout=subprocess.DEVNULL)
    return dll


# ===================================================== checked calling ======
class Harness:
    def __init__(self, dll):
        self.u = A64Unit(dll)
        self.calls = 0

    def _sp(self, nargs):
        frame = (32 + 8 * max(0, nargs - 4) + 15) & ~15
        return STACK_BASE + STACK_SIZE - 0x1000 - frame

    def call(self, fn, *args, below=0):
        """Checked call.  below = bytes under the caller's sp the routine may use
        and must leave zeroed (0 = must not touch the stack at all)."""
        u, uc = self.u, self.u.uc
        sp = self._sp(len(args))
        probe = 2048
        pattern = bytes([0xEE]) * probe
        uc.mem_write(sp - probe, pattern)
        u.call(fn, *args, check_abi=True)        # x19-x29, sp, x18, v8-v15
        self.calls += 1
        # all x64-mapped volatile GPRs (rcx rdx r8 r9 rax r10 r11 = x0-x3 x8-x10)
        # and x4-x7 come back unchanged
        for i in range(11):
            exp = (args[i] & M64) if i < len(args) and i < 4 else FILL ^ (i * 0x0101010101010101)
            got = uc.reg_read(X[i])
            if got != exp:
                raise RuntimeError(f"{fn}: x{i} clobbered ({got:#x} != {exp:#x})")
        # scrub: every volatile vector register returned zeroed
        for i in list(range(8)) + list(range(16, 32)):
            if uc.reg_read(V[i]) != 0:
                raise RuntimeError(f"{fn}: v{i} not scrubbed")
        # stack: work area wiped, nothing else below sp touched
        after = u.read(sp - probe, probe)
        if below == 0:
            if after != pattern:
                raise RuntimeError(f"{fn}: wrote below sp")
        else:
            work = after[probe - below:probe - 16]          # under the fp/lr pair
            if work != bytes(len(work)):
                raise RuntimeError(f"{fn}: stack work area not wiped")
            if after[:probe - below] != pattern[:probe - below]:
                raise RuntimeError(f"{fn}: wrote below its frame")


# =========================================================== BLAKE2b ref ===
IV = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
      0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]]


def ror(x, n):
    return ((x >> n) | (x << (64 - n))) & M64


def b2_compress_ref(h, block, t0, t1, last):
    m = struct.unpack("<16Q", block)
    v = list(h) + list(IV)
    v[12] ^= t0; v[13] ^= t1; v[14] ^= last
    def g(a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) & M64; v[d] = ror(v[d] ^ v[a], 32)
        v[c] = (v[c] + v[d]) & M64;     v[b] = ror(v[b] ^ v[c], 24)
        v[a] = (v[a] + v[b] + y) & M64; v[d] = ror(v[d] ^ v[a], 16)
        v[c] = (v[c] + v[d]) & M64;     v[b] = ror(v[b] ^ v[c], 63)
    for r in range(12):
        s = SIGMA[r % 10]
        g(0, 4, 8, 12, m[s[0]], m[s[1]]);  g(1, 5, 9, 13, m[s[2]], m[s[3]])
        g(2, 6, 10, 14, m[s[4]], m[s[5]]); g(3, 7, 11, 15, m[s[6]], m[s[7]])
        g(0, 5, 10, 15, m[s[8]], m[s[9]]); g(1, 6, 11, 12, m[s[10]], m[s[11]])
        g(2, 7, 8, 13, m[s[12]], m[s[13]]); g(3, 4, 9, 14, m[s[14]], m[s[15]])
    return [h[i] ^ v[i] ^ v[i + 8] for i in range(8)]


# ================================================= BLAKE2b x64 driver ======
CTX_SIZE = 64 + 16 + 128 + 4 + 4        # BLAKE2B_CTX
OFF_T, OFF_BUF = 64, 80


class B2Emu:
    """blake2b_init/update/final exactly as src/blake2b.asm drives
    blake2b_compress, with the ctx in emulated memory."""

    def __init__(self, hz):
        self.hz = hz
        self.u = hz.u
        self.ctx = self.u.alloc(CTX_SIZE)
        self.ncomp = 0

    def _t(self):
        return struct.unpack("<2Q", self.u.read(self.ctx + OFF_T, 16))

    def _add_t(self, n):
        t0, t1 = self._t()
        s = t0 + n
        self.u.write(self.ctx + OFF_T, struct.pack("<2Q", s & M64, (t1 + (s >> 64)) & M64))

    def init(self, outlen, key=b""):
        outlen = min(max(outlen, 1), 64)
        h = list(IV)
        h[0] ^= 0x01010000 | (len(key) << 8) | outlen   # x64 init: keylen 0
        self.u.write(self.ctx, struct.pack("<8Q", *h) + bytes(16))
        self.buflen, self.outlen = 0, outlen
        if key:                                          # RFC 7693 keyed mode
            self.update(key + bytes(128 - len(key)))

    def _compress(self, last):
        self.hz.call("blake2b_compress", self.ctx, self.ctx + OFF_BUF, last)
        self.ncomp += 1

    def update(self, data):
        pos = 0
        while pos < len(data):
            if self.buflen == 128:                       # full AND more data
                self._add_t(128)
                self._compress(0)
                self.buflen = 0
            n = min(128 - self.buflen, len(data) - pos)
            self.u.write(self.ctx + OFF_BUF + self.buflen, data[pos:pos + n])
            self.buflen += n
            pos += n

    def final(self):
        self._add_t(self.buflen)
        self.u.write(self.ctx + OFF_BUF + self.buflen, bytes(128 - self.buflen))
        self._compress(M64)
        out = self.u.read(self.ctx, self.outlen)
        self.u.write(self.ctx, bytes(CTX_SIZE))          # secure_zero(ctx)
        return out

    def hash(self, data, outlen, key=b""):
        self.init(outlen, key)
        self.update(data)
        return self.final()

    def long(self, data, outlen):                        # blake2b_long / H'
        pre = struct.pack("<I", outlen)
        if outlen <= 64:
            return self.hash(pre + data, outlen)
        v = self.hash(pre + data, 64)
        out, rem = v[:32], outlen - 32
        while rem > 64:
            v = self.hash(v, 64)
            out += v[:32]; rem -= 32
        return out + self.hash(v, rem)


# ============================================================ Argon2 ref ===
def _gb(v, a, b, c, d):
    va, vb, vc, vd = v[a], v[b], v[c], v[d]
    va = (va + vb + 2 * (va & 0xFFFFFFFF) * (vb & 0xFFFFFFFF)) & M64
    vd = ror(vd ^ va, 32)
    vc = (vc + vd + 2 * (vc & 0xFFFFFFFF) * (vd & 0xFFFFFFFF)) & M64
    vb = ror(vb ^ vc, 24)
    va = (va + vb + 2 * (va & 0xFFFFFFFF) * (vb & 0xFFFFFFFF)) & M64
    vd = ror(vd ^ va, 16)
    vc = (vc + vd + 2 * (vc & 0xFFFFFFFF) * (vd & 0xFFFFFFFF)) & M64
    vb = ror(vb ^ vc, 63)
    v[a], v[b], v[c], v[d] = va, vb, vc, vd


def _p(v):
    _gb(v, 0, 4, 8, 12); _gb(v, 1, 5, 9, 13); _gb(v, 2, 6, 10, 14); _gb(v, 3, 7, 11, 15)
    _gb(v, 0, 5, 10, 15); _gb(v, 1, 6, 11, 12); _gb(v, 2, 7, 8, 13); _gb(v, 3, 4, 9, 14)


_COLS = [[16 * r + 2 * i + k for r in range(8) for k in (0, 1)] for i in range(8)]


def g_ref(x, y, old=None):
    r = [a ^ b for a, b in zip(x, y)]
    q = r[:]
    for i in range(8):
        row = q[16 * i:16 * i + 16]; _p(row); q[16 * i:16 * i + 16] = row
    for cols in _COLS:
        col = [q[k] for k in cols]; _p(col)
        for k, val in zip(cols, col):
            q[k] = val
    z = [a ^ b for a, b in zip(q, r)]
    if old is not None:
        z = [a ^ b for a, b in zip(z, old)]
    return z


def blk(b):
    return struct.pack("<128Q", *b)


def unblk(b):
    return list(struct.unpack("<128Q", b))


def h_ref(data, n):
    return hashlib.blake2b(data, digest_size=n).digest()


def hprime_ref(x, t):
    if t <= 64:
        return h_ref(struct.pack("<I", t) + x, t)
    r = -(-t // 32) - 2
    v = h_ref(struct.pack("<I", t) + x, 64); out = v[:32]
    for _ in range(r - 1):
        v = h_ref(v, 64); out += v[:32]
    return out + h_ref(v, t - 32 * r)


def argon2id_drive(pwd, salt, t, m, p, tag_len, secret=b"", ad=b"",
                   G=None, H=None, Hp=None, emu=None):
    """RFC 9106 Argon2id (v0x13) with the loop structure of argon2.asm.
    Reference mode: G = g_ref on Python lists.  Emulated mode (emu=(hz, b2)):
    blocks live in emulated memory and every compression is one
    argon2_compress call with exactly argon2.asm's arguments."""
    y = 2
    hdr = (struct.pack("<6I", p, tag_len, m, t, 0x13, y)
           + struct.pack("<I", len(pwd)) + pwd + struct.pack("<I", len(salt)) + salt
           + struct.pack("<I", len(secret)) + secret + struct.pack("<I", len(ad)) + ad)
    h0 = H(hdr, 64)
    mp = 4 * p * (m // (4 * p)); q = mp // p; sl = q // 4
    if emu:
        hz, _ = emu
        u = hz.u
        arena = u.alloc(mp * 1024, align=1024)
        zero, inp, addr = u.alloc(1024), u.alloc(1024), u.alloc(1024)
        bp = lambda l, c: arena + (l * q + c) * 1024
        rd0 = lambda l, c: struct.unpack("<Q", u.read(bp(l, c), 8))[0]
    else:
        B = [[None] * q for _ in range(p)]
    for l in range(p):
        for c in (0, 1):
            b = Hp(h0 + struct.pack("<II", c, l), 1024)
            if emu:
                u.write(bp(l, c), b)
            else:
                B[l][c] = unblk(b)
    for r in range(t):
        for s in range(4):
            for l in range(p):
                indep = r == 0 and s < 2
                start = 2 if (r == 0 and s == 0) else 0
                ctr = [0]
                state = {}

                def next_block():
                    ctr[0] += 1
                    words = [r, l, s, mp, t, y, ctr[0]] + [0] * 121
                    if emu:
                        u.write(inp, blk(words))
                        hz.call("argon2_compress", addr, zero, inp, 0, below=1056)
                        hz.call("argon2_compress", addr, zero, addr, 0, below=1056)  # dst == Y
                        return unblk(u.read(addr, 1024))
                    return G([0] * 128, G([0] * 128, words))
                if indep and start:
                    state["a"] = next_block()
                for i in range(start, sl):
                    col = s * sl + i
                    prev = col - 1 if col else q - 1
                    if indep:
                        if i % 128 == 0:
                            state["a"] = next_block()
                        rnd = state["a"][i % 128]
                    else:
                        rnd = rd0(l, prev) if emu else B[l][prev][0]
                    j1, j2 = rnd & 0xFFFFFFFF, rnd >> 32
                    rl = l if (r == 0 and s == 0) else j2 % p
                    if r == 0:
                        w = s * sl + i - 1 if rl == l else s * sl - (1 if i == 0 else 0)
                    else:
                        w = q - sl + i - 1 if rl == l else q - sl - (1 if i == 0 else 0)
                    rel = w - 1 - ((w * ((j1 * j1) >> 32)) >> 32)
                    st = 0 if (r == 0 or s == 3) else (s + 1) * sl
                    ref = (st + rel) % q
                    if emu:
                        hz.call("argon2_compress", bp(l, col), bp(l, prev), bp(rl, ref),
                                1 if r else 0, below=1056)
                    else:
                        new = G(B[l][prev], B[rl][ref])
                        B[l][col] = new if r == 0 else [a ^ b for a, b in zip(new, B[l][col])]
    if emu:
        c = unblk(u.read(bp(0, q - 1), 1024))
        for l in range(1, p):
            c = [a ^ b for a, b in zip(c, unblk(u.read(bp(l, q - 1), 1024)))]
    else:
        c = B[0][q - 1]
        for l in range(1, p):
            c = [a ^ b for a, b in zip(c, B[l][q - 1])]
    return Hp(blk(c), tag_len)


# ================================================================ tests =====
def test_blake2b_direct(hz, rng):
    u = hz.u
    ctx = u.alloc(CTX_SIZE + 64)
    blkp = u.alloc(128 + 16)
    n = 0
    for it in range(60):
        h = [rng.getrandbits(64) for _ in range(8)]
        t0 = rng.choice([0, 128, rng.getrandbits(64), M64 - 127, M64])
        t1 = rng.choice([0, 0, 1, rng.getrandbits(64)])
        last = rng.choice([0, M64, rng.getrandbits(64)])
        block = rng.randbytes(128)
        mode = it % 3            # 0: separate block, 1: block = ctx.buf, 2: unaligned
        base = ctx + (5 if mode == 2 else 0)
        u.write(base, struct.pack("<8Q2Q", *h, t0, t1) + block + bytes(8))
        bptr = base + OFF_BUF if mode == 1 else blkp + (3 if mode == 2 else 0)
        if mode != 1:
            u.write(bptr, block)
        hz.call("blake2b_compress", base, bptr, last)
        got = struct.unpack("<8Q2Q", u.read(base, 80))
        exp = b2_compress_ref(h, block, t0, t1, last)
        ok = list(got[:8]) == exp and got[8:] == (t0, t1) and u.read(bptr, 128) == block
        n += check(ok, f"blake2b_compress direct #{it} (mode {mode})")
    return n


def test_blake2b_hash(hz, rng):
    b2 = B2Emu(hz)
    lengths = [0, 1, 3, 63, 64, 65, 127, 128, 129, 200, 255, 256, 257, 384, 513]
    n = bad = 0
    for outlen in range(1, 65):
        for ln in lengths:
            msg = rng.randbytes(ln)
            got = b2.hash(msg, outlen)
            if not check(got == hashlib.blake2b(msg, digest_size=outlen).digest(),
                         f"blake2b unkeyed outlen={outlen} len={ln}"):
                bad += 1
            key = rng.randbytes(1 + (outlen * 7 + ln) % 64)
            got = b2.hash(msg, outlen, key)
            if not check(got == hashlib.blake2b(msg, digest_size=outlen, key=key).digest(),
                         f"blake2b keyed outlen={outlen} len={ln} klen={len(key)}"):
                bad += 1
            n += 2
    for ln in (1000, 1024, 4097):                # longer: many lazy compresses
        msg = rng.randbytes(ln)
        n += 1
        check(b2.hash(msg, 64) == hashlib.blake2b(msg).digest(), f"blake2b len={ln}")
    # selftest.asm KAT: BLAKE2b-512("abc")
    check(b2.hash(b"abc", 64) == hashlib.blake2b(b"abc").digest(), "blake2b('abc')")
    return n, b2.ncomp


def kat_blocks():
    x = [((i + 1) * 0x0101010101010101) & M64 for i in range(128)]
    y = [((i + 1) * 0x0202020202020202) & M64 for i in range(128)]
    return x, y


def test_argon2_blocks(hz, rng):
    u = hz.u
    bufs = [u.alloc(1024 + 64, align=1024) for _ in range(3)]
    n = 0
    # selftest.asm block KAT
    x, y = kat_blocks()
    u.write(bufs[0], blk(x)); u.write(bufs[1], blk(y)); u.write(bufs[2], rng.randbytes(1024))
    hz.call("argon2_compress", bufs[2], bufs[0], bufs[1], 0, below=1056)
    out = unblk(u.read(bufs[2], 1024))
    cks = 0
    for w in out:
        cks ^= w
    n += 1
    check(out == g_ref(x, y), "argon2 KAT block vs reference")
    check(cks == 0x5EE3A5C79EBA0A63 and out[0] == 0xDC71308D33513477,
          f"argon2 KAT block vs selftest.asm (cksum {cks:#x}, out0 {out[0]:#x})")
    check(u.read(bufs[0], 1024) == blk(x) and u.read(bufs[1], 1024) == blk(y),
          "argon2 KAT inputs unchanged")
    # random blocks, every aliasing pattern
    cases = ["distinct", "dst=X", "dst=Y", "X=Y", "all"]
    for it in range(40):
        case = cases[it % len(cases)]
        wx = rng.choice([0, 0, 1, 1, 1 << 40, M64])      # with_xor tested as 64-bit
        off = 8 if it % 7 == 6 else 0                    # occasionally unaligned
        A, Bb, C = (b + off for b in bufs)
        xs = [rng.getrandbits(64) for _ in range(128)]
        ys = [rng.getrandbits(64) for _ in range(128)]
        ds = [rng.getrandbits(64) for _ in range(128)]
        if case == "distinct":
            d, xp, yp = C, A, Bb
        elif case == "dst=X":
            d = xp = A; yp = Bb; ds = xs
        elif case == "dst=Y":
            d = yp = Bb; xp = A; ds = ys
        elif case == "X=Y":
            d = C; xp = yp = A; ys = xs
        else:
            d = xp = yp = A; ys = xs; ds = xs
        u.write(xp, blk(xs)); u.write(yp, blk(ys))
        if d not in (xp, yp):
            u.write(d, blk(ds))
        hz.call("argon2_compress", d, xp, yp, wx, below=1056)
        exp = g_ref(xs, ys, ds if wx else None)
        n += 1
        ok = unblk(u.read(d, 1024)) == exp
        if d != xp:
            ok = ok and u.read(xp, 1024) == blk(xs)
        if d != yp:
            ok = ok and u.read(yp, 1024) == blk(ys)
        check(ok, f"argon2_compress random #{it} ({case}, with_xor={wx:#x}, off={off})")
    return n


def main():
    tmp = tempfile.mkdtemp(prefix="vordr_b2a2_")
    try:
        dll = build(tmp)
        hz = Harness(dll)
        rng = random.Random(0xA64B2A2)

        n = test_blake2b_direct(hz, rng)
        print(f"  blake2b_compress direct vs reference: {n} cases")
        n, nc = test_blake2b_hash(hz, rng)
        print(f"  blake2b init/update/final driver vs hashlib: {n} hashes, {nc} compress calls")
        n = test_argon2_blocks(hz, rng)
        print(f"  argon2_compress vs RFC 9106 G (+KAT, aliasing, with_xor): {n} cases")

        # (c) end-to-end Argon2id
        b2 = B2Emu(hz)
        emu_kw = dict(G=None, H=b2.hash, Hp=b2.long, emu=(hz, b2))
        ref_kw = dict(G=g_ref, H=h_ref, Hp=hprime_ref)
        rfc = dict(pwd=b"\x01" * 32, salt=b"\x02" * 16, t=3, m=32, p=4, tag_len=32,
                   secret=b"\x03" * 8, ad=b"\x04" * 12)
        rfc_tag = bytes.fromhex("0d640df58d78766c08c037a34a8b53c9"
                                "d01ef0452d75b65eb52520e96b01e659")
        c0 = hz.calls
        tag = argon2id_drive(**rfc, **emu_kw)
        check(tag == rfc_tag, f"Argon2id RFC 9106 vector (emulated): {tag.hex()}")
        check(argon2id_drive(**rfc, **ref_kw) == rfc_tag, "Argon2id RFC 9106 vector (reference)")
        print(f"  Argon2id RFC 9106 vector (t=3, m=32, p=4): {tag.hex()} "
              f"({hz.calls - c0} emulated calls)")
        try:
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id as _CA
        except Exception:
            _CA = None
        for (pw, sa, t, m, p, tl) in [(b"password", b"somesalt" * 2, 2, 64, 1, 32),
                                      (b"correct horse", b"\xA5" * 32, 1, 1024, 1, 64)]:
            c0 = hz.calls
            got = argon2id_drive(pw, sa, t, m, p, tl, **emu_kw)
            exp = argon2id_drive(pw, sa, t, m, p, tl, **ref_kw)
            check(got == exp, f"Argon2id t={t} m={m} p={p} emulated vs reference")
            extra = ""
            if _CA is not None:
                try:
                    lib = _CA(salt=sa, length=tl, iterations=t, lanes=p,
                              memory_cost=m).derive(pw)
                    check(lib == got, f"Argon2id t={t} m={m} p={p} vs cryptography")
                    extra = ", matches cryptography"
                except Exception as e:  # older cryptography without argon2
                    extra = f", cryptography unavailable ({type(e).__name__})"
            print(f"  Argon2id t={t} m={m} p={p}: {got.hex()[:32]}... "
                  f"({hz.calls - c0} emulated calls{extra})")

        # instruction counts (fresh instance: the code hook must exist before
        # unicorn translates the routine, or cached blocks bypass it)
        hc = Harness(dll)
        hc.cnt = [0]
        def _h(uc_, addr, size, ud):
            hc.cnt[0] += 1
        hc.u.uc.hook_add(UC_HOOK_CODE, _h)
        u = hc.u
        a, b, c = (u.alloc(1024, align=1024) for _ in range(3))
        u.write(a, rng.randbytes(1024)); u.write(b, rng.randbytes(1024))
        def count(fn, *args, below=0):
            hc.cnt[0] = 0
            hc.call(fn, *args, below=below)
            return hc.cnt[0]
        n0 = count("argon2_compress", c, a, b, 0, below=1056)
        n1 = count("argon2_compress", c, a, b, 1, below=1056)
        ctx = u.alloc(CTX_SIZE)
        nb = count("blake2b_compress", ctx, ctx + OFF_BUF, M64)
        check(n0 > 1000 and nb > 500, "instruction counter works")
        print(f"  instructions: argon2_compress {n0} (with_xor=0), {n1} (with_xor=1); "
              f"blake2b_compress {nb}")
        print(f"  ABI-checked calls: {hz.calls}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if FAILS:
        print(f"FAIL ({len(FAILS)} checks failed)")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
