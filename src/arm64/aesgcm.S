// =============================================================================
// src/arm64/aesgcm.S - AES-256-GCM and variable-key AES on the ARMv8
// Cryptography Extensions (AESE/AESMC, PMULL/PMULL2).
// =============================================================================

#include "frame.inc"
// -----------------------------------------------------------------------------
// Hand-written AArch64 replacement for src/aesgcm.asm.  Every global symbol of
// the x64 object is provided with the same semantics, return values, length
// bounds, wipe behaviour and context layout:
//
//   aes256_expand(x0 = key32, x1 = rk out 240)              leaf
//   gcm_init (x0 = ctx, x1 = key, x2 = iv12, x3 = mode)       leaf
//   gcm_aad  (x0 = ctx, x1 = aad, x2 = len)                   leaf
//   gcm_crypt(x0 = ctx, x1 = in, x2 = out, x3 = len)          leaf
//   gcm_final(x0 = ctx, x1 = tag16 out)                       leaf
//   gcm_seal (x0 = GCMREQ*) -> x8 = 0 ok, 1 length over SP 800-38D limit
//   gcm_open (x0 = GCMREQ*) -> x8 = 0 tag valid, 1 otherwise
//   aes_expand_key(x0 = key, x1 = keylen{16,24,32}, x2 = rk) -> x8 = Nr | 0
//   aes_ecb_block(x0 = rk, x1 = io16, w2 = Nr)  -> fastfail on bad Nr
//   aes_ctr_xor(x0 = rk, x1 = data, x2 = len, x3 = ctr16, [sp+32] = Nr)
//
// Calling convention: docs/ARM64.md (x64 register meaning on fixed ARM64
// registers, result in x8).  Beyond the documented volatile set, each routine
// only writes registers whose x64 counterpart the x64 original also writes;
// v6/v7 (xmm14/xmm15) are never touched.  v16-v31 and x11-x17 are translator
// scratch; every vector register used is zeroed before return.
//
// GHASH runs in the same byte-reflected domain as the x64 code (H and Y are
// stored byte-reversed in the context), with the 64-bit-lane form of the Intel
// shift reduction (Gueron/Kounavis, Algorithm 5).  No table lookups and no
// secret-dependent branches or addresses anywhere.
//
// Assemble: clang --target=aarch64-pc-windows-msvc -march=armv8.2-a+crypto -c
// =============================================================================

        .text

// ---- GCMREQ field offsets ---------------------------------------------------
        .set RQ_KEY,    0
        .set RQ_IV,     8
        .set RQ_AAD,    16
        .set RQ_AADLEN, 24
        .set RQ_INP,    32
        .set RQ_INLEN,  40
        .set RQ_OUTP,   48
        .set RQ_TAG,    56

// ---- streaming context layout (identical to the x64 GC_* offsets) -----------
        .set GC_RK,     0               // 240  round keys
        .set GC_H,      240             // 16   hash subkey (byte-reflected)
        .set GC_Y,      256             // 16   GHASH accumulator (byte-reflected)
        .set GC_J0,     272             // 16   pre-counter block
        .set GC_CTR,    288             // 16   running counter
        .set GC_AADN,   304             // 8    total AAD bytes
        .set GC_PTN,    312             // 8    total data bytes
        .set GC_MODE,   320             // 8    0 = seal, 1 = open
        .set GCM_CTX_SIZE, 336

        .set FF_BOUNDS, 0xF004

// =============================================================================
// Macros
// =============================================================================

// d = byte-reverse(s), all 16 bytes (x64: pshufb bswap_mask)
.macro BSWAP128 d, s
        rev64   \d\().16b, \s\().16b
        ext     \d\().16b, \d\().16b, \d\().16b, #8
.endm

.macro ZERO_V r, rest:vararg
        movi    \r\().16b, #0
  .ifnb \rest
        ZERO_V  \rest
  .endif
.endm

// r = prefix-xor of its four 32-bit lanes (x64 EXP_CORE: three times
// r ^= r << 4 bytes).  Uses v3; z = zero register.
.macro PREFIX4 r, z
        ext     v3.16b, \z\().16b, \r\().16b, #12
        eor     \r\().16b, \r\().16b, v3.16b
        ext     v3.16b, \z\().16b, \r\().16b, #12
        eor     \r\().16b, \r\().16b, v3.16b
        ext     v3.16b, \z\().16b, \r\().16b, #12
        eor     \r\().16b, \r\().16b, v3.16b
.endm

// EXPA: k0 (v0) <- next even round key from k1 (v1).  SubWord via AESE with a
// zero key on a broadcast word (ShiftRows is the identity when all four
// columns are equal); RotWord = rotate each lane right by 8.
.macro EXPA rcon, z
        dup     v2.4s, v1.s[3]
        aese    v2.16b, \z\().16b
        ushr    v3.4s, v2.4s, #8
        sli     v3.4s, v2.4s, #24
        movi    v4.4s, #\rcon
        eor     v2.16b, v3.16b, v4.16b
        PREFIX4 v0, \z
        eor     v0.16b, v0.16b, v2.16b
.endm

// EXPB: k1 (v1) <- next odd round key from k0 (v0) (SubWord only).
.macro EXPB z
        dup     v2.4s, v0.s[3]
        aese    v2.16b, \z\().16b
        PREFIX4 v1, \z
        eor     v1.16b, v1.16b, v2.16b
.endm

// AES-256 key schedule: [key] -> [out .. out+240).  Uses v0-v4; z must hold 0.
.macro AES256_EXPAND key, out, z
        ldr     q0, [\key]
        ldr     q1, [\key, #16]
        str     q0, [\out, #0]
        str     q1, [\out, #16]
        EXPA    0x01, \z
        str     q0, [\out, #32]
        EXPB    \z
        str     q1, [\out, #48]
        EXPA    0x02, \z
        str     q0, [\out, #64]
        EXPB    \z
        str     q1, [\out, #80]
        EXPA    0x04, \z
        str     q0, [\out, #96]
        EXPB    \z
        str     q1, [\out, #112]
        EXPA    0x08, \z
        str     q0, [\out, #128]
        EXPB    \z
        str     q1, [\out, #144]
        EXPA    0x10, \z
        str     q0, [\out, #160]
        EXPB    \z
        str     q1, [\out, #176]
        EXPA    0x20, \z
        str     q0, [\out, #192]
        EXPB    \z
        str     q1, [\out, #208]
        EXPA    0x40, \z
        str     q0, [\out, #224]
.endm

// v16..v30 <- the 15 AES-256 round keys at [base]
.macro LOAD_RK base, tmp
        mov     \tmp, \base
        ld1     {v16.16b, v17.16b, v18.16b, v19.16b}, [\tmp], #64
        ld1     {v20.16b, v21.16b, v22.16b, v23.16b}, [\tmp], #64
        ld1     {v24.16b, v25.16b, v26.16b, v27.16b}, [\tmp], #64
        ld1     {v28.16b, v29.16b, v30.16b}, [\tmp]
.endm

// s = AES-256-Encrypt(s) with round keys in v16..v30
.macro AES256_ENC s
        aese    \s\().16b, v16.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v17.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v18.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v19.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v20.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v21.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v22.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v23.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v24.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v25.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v26.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v27.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v28.16b
        aesmc   \s\().16b, \s\().16b
        aese    \s\().16b, v29.16b
        eor     \s\().16b, \s\().16b, v30.16b
.endm

// v1 (Y) <- v1 * v2 (H) in GF(2^128), byte-reflected domain.
// Clobbers v0, v3, v4, v5, v31.  v2 is preserved.
.macro GF_MUL
        pmull   v0.1q, v1.1d, v2.1d             // L  = Y0*H0
        pmull2  v3.1q, v1.2d, v2.2d             // Hh = Y1*H1
        ext     v4.16b, v1.16b, v1.16b, #8      // Y halves swapped
        pmull   v5.1q, v4.1d, v2.1d             // Y1*H0
        pmull2  v4.1q, v4.2d, v2.2d             // Y0*H1
        eor     v4.16b, v4.16b, v5.16b          // M
        movi    v5.16b, #0                      // zero
        ext     v31.16b, v5.16b, v4.16b, #8     // [M0 : 0]  (d1 = M0)
        eor     v0.16b, v0.16b, v31.16b         // lo = [X1 : X0]
        ext     v31.16b, v4.16b, v5.16b, #8     // [0 : M1]  (d0 = M1)
        eor     v3.16b, v3.16b, v31.16b         // hi = [X3 : X2]
        // 256-bit product <<= 1 (reflected-operand correction)
        ushr    v4.2d, v0.2d, #63               // [X1>>63 : X0>>63]
        ushr    v31.2d, v3.2d, #63              // [X3>>63 : X2>>63]
        ext     v31.16b, v4.16b, v31.16b, #8    // [X2>>63 : X1>>63]
        shl     v3.2d, v3.2d, #1
        orr     v3.16b, v3.16b, v31.16b         // hi'
        ext     v4.16b, v5.16b, v4.16b, #8      // [X0>>63 : 0]
        shl     v0.2d, v0.2d, #1
        orr     v0.16b, v0.16b, v4.16b          // lo' = [X1 : X0]
        // reduction: D = X1 ^ X0<<63 ^ X0<<62 ^ X0<<57
        shl     v4.2d, v0.2d, #63
        shl     v31.2d, v0.2d, #62
        eor     v4.16b, v4.16b, v31.16b
        shl     v31.2d, v0.2d, #57
        eor     v4.16b, v4.16b, v31.16b
        ext     v4.16b, v5.16b, v4.16b, #8
        eor     v0.16b, v0.16b, v4.16b          // [D : X0]
        // H = [D:X0] ^ [D:X0]>>1 ^ >>2 ^ >>7   (128-bit shifts)
        ushr    v4.2d, v0.2d, #1
        ushr    v31.2d, v0.2d, #2
        eor     v4.16b, v4.16b, v31.16b
        ushr    v31.2d, v0.2d, #7
        eor     v4.16b, v4.16b, v31.16b         // per-lane parts
        shl     v1.2d, v0.2d, #63
        shl     v31.2d, v0.2d, #62
        eor     v1.16b, v1.16b, v31.16b
        shl     v31.2d, v0.2d, #57
        eor     v1.16b, v1.16b, v31.16b
        ext     v31.16b, v1.16b, v5.16b, #8     // carries D -> low lane
        eor     v0.16b, v0.16b, v4.16b
        eor     v0.16b, v0.16b, v31.16b
        eor     v1.16b, v3.16b, v0.16b          // Y = hi' ^ H
.endm

// v0 = next GCM counter block: low 32-bit big-endian counter (native in w13)
// incremented; x14 = counter bytes 0..7, x15 = bytes 8..15.
.macro CTR_NEXT
        add     w13, w13, #1
        rev     w16, w13
        bfi     x15, x16, #32, #32
        fmov    d0, x14
        mov     v0.d[1], x15
.endm

// =============================================================================
// aes256_expand(x0 = key ptr, x1 = round-key out, 15*16 bytes)
// Leaf.  x64 writes only xmm0..xmm4 -> v0..v4 (zeroed); v16 = zero scratch.
// =============================================================================
        .globl  aes256_expand
        .p2align 4
aes256_expand:
        movi    v16.16b, #0
        AES256_EXPAND x0, x1, v16
        ZERO_V  v0, v1, v2, v3, v4
        ret

// =============================================================================
// gcm_init(x0 = ctx, x1 = key, x2 = iv, x3 = mode)
// Leaf.  Expands the key into ctx, H = bswap(E_K(0)), J0 = CTR = iv||0^31||1,
// Y = 0, AADN = PTN = 0, MODE = x3.  Writes x9-x11, v0-v5, v16-v30 (zeroed).
// =============================================================================
        .globl  gcm_init
        .p2align 4
gcm_init:
        movi    v5.16b, #0
        AES256_EXPAND x1, x0, v5
        str     x3, [x0, #GC_MODE]
        LOAD_RK x0, x9
        movi    v0.16b, #0
        AES256_ENC v0
        BSWAP128 v0, v0
        str     q0, [x0, #GC_H]
        ldr     w9, [x2, #0]
        ldr     w10, [x2, #4]
        ldr     w11, [x2, #8]
        str     w9, [x0, #GC_J0+0]
        str     w10, [x0, #GC_J0+4]
        str     w11, [x0, #GC_J0+8]
        str     w9, [x0, #GC_CTR+0]
        str     w10, [x0, #GC_CTR+4]
        str     w11, [x0, #GC_CTR+8]
        mov     w9, #0x01000000                 // big-endian 1
        str     w9, [x0, #GC_J0+12]
        str     w9, [x0, #GC_CTR+12]
        stp     xzr, xzr, [x0, #GC_Y]
        stp     xzr, xzr, [x0, #GC_AADN]        // AADN, PTN
        ZERO_V  v0, v1, v2, v3, v4, v5
        ZERO_V  v16, v17, v18, v19, v20, v21, v22, v23
        ZERO_V  v24, v25, v26, v27, v28, v29, v30
        ret

// =============================================================================
// gcm_aad(x0 = ctx, x1 = aad, x2 = len)
// Leaf.  AADN += len; GHASH the data (last partial block zero-padded via the
// home area [sp, sp+16), wiped afterwards).  x0-x2 preserved.
// Writes x9-x12, v0-v5, v31 (zeroed).
// =============================================================================
        .globl  gcm_aad
        .p2align 4
gcm_aad:
        ldr     x11, [x0, #GC_AADN]
        add     x11, x11, x2
        str     x11, [x0, #GC_AADN]
        ldr     q1, [x0, #GC_Y]
        ldr     q2, [x0, #GC_H]
        mov     x9, x1
        mov     x10, x2
1:      cmp     x10, #16
        b.lo    2f
        ld1     {v0.16b}, [x9], #16
        BSWAP128 v0, v0
        eor     v1.16b, v1.16b, v0.16b
        GF_MUL
        sub     x10, x10, #16
        b       1b
2:      cbz     x10, 4f
        stp     xzr, xzr, [sp]
        mov     x11, #0
3:      ldrb    w12, [x9, x11]
        strb    w12, [sp, x11]
        add     x11, x11, #1
        cmp     x11, x10
        b.lo    3b
        ldr     q0, [sp]
        BSWAP128 v0, v0
        eor     v1.16b, v1.16b, v0.16b
        GF_MUL
        stp     xzr, xzr, [sp]
4:      str     q1, [x0, #GC_Y]
        mov     w12, #0
        ZERO_V  v0, v1, v2, v3, v4, v5, v31
        ret

// =============================================================================
// gcm_crypt(x0 = ctx, x1 = in, x2 = out, x3 = len)
// Leaf.  PTN += len; CTR encrypt/decrypt in -> out (in == out allowed) and
// GHASH the ciphertext (output when MODE = 0, input when MODE != 0).  Only the
// final call may have len % 16 != 0.  Tail keystream + padded ciphertext use
// the home area [sp, sp+32), wiped afterwards.  x0, x1 preserved.
// Writes x2, x3, x8-x17, v0-v5, v16-v31 (zeroed).
// =============================================================================
        .globl  gcm_crypt
        .p2align 4
gcm_crypt:
        ldr     x9, [x0, #GC_PTN]
        add     x9, x9, x3
        str     x9, [x0, #GC_PTN]
        ldr     q1, [x0, #GC_Y]
        ldr     q2, [x0, #GC_H]
        LOAD_RK x0, x9
        ldr     x12, [x0, #GC_MODE]
        ldp     x14, x15, [x0, #GC_CTR]
        lsr     x13, x15, #32
        rev     w13, w13                        // native 32-bit counter
        mov     x9, x1
        mov     x10, x2
        mov     x11, x3
1:      cmp     x11, #16
        b.lo    3f
        ld1     {v3.16b}, [x9], #16
        CTR_NEXT
        AES256_ENC v0
        eor     v0.16b, v0.16b, v3.16b
        st1     {v0.16b}, [x10], #16
        cbz     x12, 2f                         // seal: GHASH the output
        mov     v0.16b, v3.16b                  // open: GHASH the input
2:      BSWAP128 v0, v0
        eor     v1.16b, v1.16b, v0.16b
        GF_MUL
        sub     x11, x11, #16
        b       1b
3:      cbz     x11, 7f
        CTR_NEXT
        AES256_ENC v0
        str     q0, [sp]                        // keystream
        stp     xzr, xzr, [sp, #16]             // zero-padded ciphertext
        add     x2, sp, #16
        mov     x16, #0
4:      ldrb    w17, [x9, x16]                  // input byte (read before write)
        ldrb    w8, [sp, x16]                   // keystream byte
        cbnz    x12, 5f
        eor     w17, w17, w8                    // seal: ct = in ^ ks
        strb    w17, [x2, x16]
        strb    w17, [x10, x16]
        b       6f
5:      strb    w17, [x2, x16]                  // open: ct = in
        eor     w17, w17, w8
        strb    w17, [x10, x16]
6:      add     x16, x16, #1
        cmp     x16, x11
        b.lo    4b
        ldr     q0, [x2]
        BSWAP128 v0, v0
        eor     v1.16b, v1.16b, v0.16b
        GF_MUL
7:      str     q1, [x0, #GC_Y]
        str     x15, [x0, #GC_CTR+8]            // counter write-back
        stp     xzr, xzr, [sp]                  // wipe tail keystream and
        stp     xzr, xzr, [sp, #16]             //   padded ciphertext scratch
        mov     w8, #0
        mov     w17, #0
        ZERO_V  v0, v1, v2, v3, v4, v5
        ZERO_V  v16, v17, v18, v19, v20, v21, v22, v23
        ZERO_V  v24, v25, v26, v27, v28, v29, v30, v31
        ret

// =============================================================================
// gcm_final(x0 = ctx, x1 = tag out 16 bytes)
// Leaf.  GHASH the length block, tag = bswap(Y) ^ E_K(J0).  x0, x1 preserved.
// Writes x9, x10, v0-v5, v16-v31 (zeroed).
// =============================================================================
        .globl  gcm_final
        .p2align 4
gcm_final:
        ldr     q1, [x0, #GC_Y]
        ldr     q2, [x0, #GC_H]
        ldp     x9, x10, [x0, #GC_AADN]
        lsl     x9, x9, #3
        rev     x9, x9
        lsl     x10, x10, #3
        rev     x10, x10
        fmov    d0, x9
        mov     v0.d[1], x10                    // len(A)||len(C) in bits, BE
        BSWAP128 v0, v0
        eor     v1.16b, v1.16b, v0.16b
        GF_MUL
        LOAD_RK x0, x9
        ldr     q5, [x0, #GC_J0]
        AES256_ENC v5
        BSWAP128 v0, v1
        eor     v0.16b, v0.16b, v5.16b
        str     q0, [x1]
        ZERO_V  v0, v1, v2, v3, v4, v5
        ZERO_V  v16, v17, v18, v19, v20, v21, v22, v23
        ZERO_V  v24, v25, v26, v27, v28, v29, v30, v31
        ret

// =============================================================================
// gcm_seal(x0 = GCMREQ*) -> x8 = 0 ok, 1 length over NIST SP 800-38D limit
// Frame: [sp, sp+32) callee home area, [sp+32, sp+368) context,
//        [x29-16] request pointer.
// =============================================================================
        .globl  gcm_seal
        .p2align 4
        .seh_proc gcm_seal
gcm_seal:
        pacibsp
        .seh_pac_sign_lr
        stp     x29, x30, [sp, #-16]!
        .seh_save_fplr_x 16
        mov     x29, sp
        .seh_set_fp
        sub     sp, sp, #384
        .seh_stackalloc 384
        .seh_endprologue
        A64_FRAME_GUARD_ENTER .Lgs_ss_in
        // NIST SP 800-38D: P <= 2^36 - 32 bytes so the 32-bit counter never
        // wraps back to J0; A <= 2^61 - 1 bytes.
        ldr     x9, [x0, #RQ_INLEN]
        mov     x10, #0xFFFFFFFE0
        cmp     x9, x10
        b.hi    9f
        ldr     x9, [x0, #RQ_AADLEN]
        mov     x10, #0x1FFFFFFFFFFFFFFF
        cmp     x9, x10
        b.hi    9f
        str     x0, [x29, #-16]
        mov     x9, x0
        add     x0, sp, #32
        ldp     x1, x2, [x9, #RQ_KEY]           // key, iv
        mov     x3, #0
        bl      gcm_init
        ldr     x9, [x29, #-16]
        add     x0, sp, #32
        ldp     x1, x2, [x9, #RQ_AAD]           // aad, aadlen
        bl      gcm_aad
        ldr     x9, [x29, #-16]
        add     x0, sp, #32
        ldr     x1, [x9, #RQ_INP]
        ldr     x2, [x9, #RQ_OUTP]
        ldr     x3, [x9, #RQ_INLEN]
        bl      gcm_crypt
        ldr     x9, [x29, #-16]
        add     x0, sp, #32
        ldr     x1, [x9, #RQ_TAG]
        bl      gcm_final
        add     x0, sp, #32                     // wipe round keys + GHASH subkey
        mov     x1, #GCM_CTX_SIZE
        bl      secure_zero
        ZERO_V  v0, v1, v2, v3, v4, v5
        ZERO_V  v16, v17, v18, v19, v20, v21, v22, v23
        ZERO_V  v24, v25, v26, v27, v28, v29, v30, v31
        mov     x8, #0
        b       10f
9:      mov     x8, #1
10:     A64_FRAME_GUARD_EXIT .Lgs_cok, .Lgs_ssfail, .Lgs_ssdone
        .seh_startepilogue
        add     sp, sp, #384
        .seh_stackalloc 384
        ldp     x29, x30, [sp], #16
        .seh_save_fplr_x 16
        autibsp
        .seh_pac_sign_lr
        .seh_endepilogue
        ret
        .seh_endproc

// =============================================================================
// gcm_open(x0 = GCMREQ*) -> x8 = 0 if tag valid (plaintext written), 1 else
// The tag is verified (constant time) BEFORE any plaintext is written.  On
// mismatch a distinct, non-null outp is zeroed (inlen bytes); outp == inp is
// left untouched.
// Frame: [sp, sp+32) home, [sp+32, sp+368) context, [sp+368, sp+384) computed
//        tag, [x29-24] result, [x29-16] request pointer, [x29-8] stack canary.
// =============================================================================
        .globl  gcm_open
        .p2align 4
        .seh_proc gcm_open
gcm_open:
        pacibsp
        .seh_pac_sign_lr
        stp     x29, x30, [sp, #-16]!
        .seh_save_fplr_x 16
        mov     x29, sp
        .seh_set_fp
        sub     sp, sp, #416
        .seh_stackalloc 416
        .seh_endprologue
        A64_FRAME_GUARD_ENTER .Lgo_ss_in
        ldr     x9, [x0, #RQ_INLEN]
        mov     x10, #0xFFFFFFFE0
        cmp     x9, x10
        b.hi    9f
        ldr     x9, [x0, #RQ_AADLEN]
        mov     x10, #0x1FFFFFFFFFFFFFFF
        cmp     x9, x10
        b.hi    9f
        str     x0, [x29, #-16]
        mov     x9, x0
        add     x0, sp, #32
        ldp     x1, x2, [x9, #RQ_KEY]
        mov     x3, #1
        bl      gcm_init
        // GHASH(aad) then GHASH(ciphertext) - authenticate before decrypting
        ldr     x9, [x29, #-16]
        add     x0, sp, #32
        ldp     x1, x2, [x9, #RQ_AAD]
        bl      gcm_aad
        ldr     x9, [x29, #-16]
        add     x0, sp, #32
        ldr     x1, [x9, #RQ_INP]
        ldr     x2, [x9, #RQ_INLEN]
        bl      gcm_aad
        ldr     x9, [x29, #-16]
        add     x0, sp, #32
        ldr     x10, [x9, #RQ_AADLEN]
        str     x10, [x0, #GC_AADN]
        ldr     x10, [x9, #RQ_INLEN]
        str     x10, [x0, #GC_PTN]
        add     x1, sp, #32+GCM_CTX_SIZE
        bl      gcm_final
        ldr     x9, [x29, #-16]
        add     x0, sp, #32+GCM_CTX_SIZE
        ldr     x1, [x9, #RQ_TAG]
        mov     x2, #16
        bl      ct_memcmp
        str     w8, [x29, #-24]
        cbnz    w8, 5f
        // Tag verified: decrypt inp -> outp via CTR.
        add     x0, sp, #32
        str     xzr, [x0, #GC_PTN]
        ldr     x9, [x29, #-16]
        ldr     x1, [x9, #RQ_INP]
        ldr     x2, [x9, #RQ_OUTP]
        ldr     x3, [x9, #RQ_INLEN]
        bl      gcm_crypt
        b       6f
5:      // Mismatch: zero a distinct destination buffer.
        ldr     x9, [x29, #-16]
        ldr     x0, [x9, #RQ_OUTP]
        cbz     x0, 6f
        ldr     x10, [x9, #RQ_INP]
        cmp     x0, x10
        b.eq    6f
        ldr     x1, [x9, #RQ_INLEN]
        bl      secure_zero
6:      // Wipe round keys, GHASH subkey and the computed tag behind them.
        add     x0, sp, #32
        mov     x1, #GCM_CTX_SIZE+16
        bl      secure_zero
        mov     x10, #0                         // A3-30: scrub address/length residue
        mov     x3, #0
        ZERO_V  v0, v1, v2, v3, v4, v5
        ZERO_V  v16, v17, v18, v19, v20, v21, v22, v23
        ZERO_V  v24, v25, v26, v27, v28, v29, v30, v31
        ldr     w8, [x29, #-24]                 // 0 = authentic, 1 = mismatch
        b       10f
9:      mov     x8, #1
10:     A64_FRAME_GUARD_EXIT .Lgo_cok, .Lgo_ssfail, .Lgo_ssdone
        .seh_startepilogue
        add     sp, sp, #416
        .seh_stackalloc 416
        ldp     x29, x30, [sp], #16
        .seh_save_fplr_x 16
        autibsp
        .seh_pac_sign_lr
        .seh_endepilogue
        ret
        .seh_endproc

// =============================================================================
// aes_expand_key(x0 = key, x1 = keylen{16,24,32}, x2 = rkout) -> x8 = Nr
//   Returns 0 on an unsupported key length (nothing else written).  rkout
//   receives (Nr+1)*16 bytes.  Leaf.  On success x0 = x1 = 0 and x3 = Nk
//   (as the x64 ecx/edx/r9); writes x9-x16, v0 and v16 (zeroed).
// =============================================================================
        .globl  aes_expand_key
        .p2align 4
aes_expand_key:
        cmp     x1, #16
        b.eq    1f
        cmp     x1, #24
        b.eq    1f
        cmp     x1, #32
        b.eq    1f
        mov     x8, #0
        ret
1:      lsr     x3, x1, #2                      // Nk
        mov     x9, #0
2:      ldrb    w10, [x0, x9]
        strb    w10, [x2, x9]
        add     x9, x9, #1
        cmp     x9, x1
        b.lo    2b
        add     x11, x3, #7
        lsl     x11, x11, #2                    // total words = 4*(Nk+7)
        mov     w12, #1                         // rcon
        mov     x9, x3                          // i = Nk
        mov     x13, #0                         // i mod Nk
        movi    v16.16b, #0
3:      cmp     x9, x11
        b.hs    6f
        sub     x10, x9, #1
        ldr     w14, [x2, x10, lsl #2]          // temp = w[i-1]
        cbnz    x13, 4f
        dup     v0.4s, w14
        aese    v0.16b, v16.16b
        mov     w14, v0.s[0]                    // SubWord
        ror     w14, w14, #8                    // RotWord
        eor     w14, w14, w12                   // ^ rcon
        ubfx    w15, w12, #7, #1                // rcon = xtime(rcon)
        neg     w15, w15
        mov     w16, #0x1B
        and     w15, w15, w16
        eor     w12, w15, w12, lsl #1
        and     w12, w12, #0xFF
        b       5f
4:      cmp     x3, #6                          // Nk > 6 (AES-256) only
        b.ls    5f
        cmp     x13, #4
        b.ne    5f
        dup     v0.4s, w14
        aese    v0.16b, v16.16b
        mov     w14, v0.s[0]                    // SubWord
5:      sub     x10, x9, x3
        ldr     w15, [x2, x10, lsl #2]          // w[i-Nk]
        eor     w15, w15, w14
        str     w15, [x2, x9, lsl #2]
        add     x9, x9, #1
        add     x13, x13, #1
        cmp     x13, x3
        csel    x13, xzr, x13, eq
        b       3b
6:      movi    v0.16b, #0
        mov     w10, #0
        mov     w14, #0
        mov     w15, #0
        mov     x0, #0
        mov     x1, #0
        add     x8, x3, #6                      // Nr = Nk + 6
        ret

// =============================================================================
// aes_ecb_block(x0 = rk, x1 = io16, w2 = Nr) - encrypt one block in place.
// Nr not in {10, 12, 14} -> __fastfail(FF_BOUNDS) via ff_trap (w0 = code).
// Leaf.  x2 = zero-extended Nr, x8 = Nr on return (as the x64 rax/r8).
// Writes x9, x10, v0, v1 (zeroed).
// =============================================================================
        .globl  aes_ecb_block
        .p2align 4
aes_ecb_block:
        mov     w2, w2
        cmp     w2, #10
        b.eq    1f
        cmp     w2, #12
        b.eq    1f
        cmp     w2, #14
        b.eq    1f
        mov     w0, #FF_BOUNDS
        b       ff_trap
1:      ldr     q0, [x1]
        mov     x9, x0
        sub     w10, w2, #1
2:      ld1     {v1.16b}, [x9], #16
        aese    v0.16b, v1.16b
        aesmc   v0.16b, v0.16b
        subs    w10, w10, #1
        b.ne    2b
        ldr     q1, [x9]
        aese    v0.16b, v1.16b
        ldr     q1, [x9, #16]
        eor     v0.16b, v0.16b, v1.16b
        str     q0, [x1]
        movi    v0.16b, #0
        movi    v1.16b, #0
        mov     x8, x2
        ret

// =============================================================================
// aes_ctr_xor(x0 = rk, x1 = data, x2 = len, x3 = ctr16, [sp+32] = Nr (u32))
// -----------------------------------------------------------------------------
// WinZip-AES CTR: the 16-byte counter is incremented as a LITTLE-ENDIAN
// 128-bit integer BEFORE each block (first block uses 1), encrypted with the
// Nr-round AES and XORed over the data in place.  The counter is written back
// so a following call continues the stream.  len == 0 touches nothing and
// does not validate Nr; otherwise a bad Nr fastfails (FF_BOUNDS).
// Leaf.  x8 = Nr if len == 0, else the bytes remaining at the start of the
// last block (16 or len % 16) - the x64 rax.  x9 = 0 on return (x64 r10).
// Writes x0-x3, x8-x15, v0, v1 (zeroed).
// =============================================================================
        .globl  aes_ctr_xor
        .p2align 4
aes_ctr_xor:
        ldr     w9, [sp, #32]                   // Nr (dword, zero-extended)
        mov     x8, x9
        cbz     x2, 7f
1:      ldp     x10, x11, [x3]                  // ctr += 1 (128-bit LE)
        adds    x10, x10, #1
        adc     x11, x11, xzr
        stp     x10, x11, [x3]
        cmp     w9, #10
        b.eq    2f
        cmp     w9, #12
        b.eq    2f
        cmp     w9, #14
        b.eq    2f
        mov     w0, #FF_BOUNDS
        b       ff_trap
2:      fmov    d0, x10
        mov     v0.d[1], x11
        mov     x12, x0
        sub     w13, w9, #1
3:      ld1     {v1.16b}, [x12], #16
        aese    v0.16b, v1.16b
        aesmc   v0.16b, v0.16b
        subs    w13, w13, #1
        b.ne    3b
        ldr     q1, [x12]
        aese    v0.16b, v1.16b
        ldr     q1, [x12, #16]
        eor     v0.16b, v0.16b, v1.16b          // keystream
        mov     x8, x2
        cmp     x2, #16
        b.lo    5f
        ldr     q1, [x1]
        eor     v1.16b, v1.16b, v0.16b
        st1     {v1.16b}, [x1], #16
        sub     x2, x2, #16
        cbnz    x2, 1b
        b       7f
5:      fmov    x12, d0
        mov     x13, v0.d[1]
        mov     x14, #0
6:      ldrb    w15, [x1, x14]
        eor     w15, w15, w12
        strb    w15, [x1, x14]
        extr    x12, x13, x12, #8
        lsr     x13, x13, #8
        add     x14, x14, #1
        cmp     x14, x2
        b.lo    6b
7:      mov     x9, #0
        mov     x12, #0
        mov     x13, #0
        mov     w15, #0
        movi    v0.16b, #0
        movi    v1.16b, #0
        ret
