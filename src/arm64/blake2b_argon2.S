// =============================================================================
// blake2b_argon2.S - hand-written AArch64 NEON replacements for
//   blake2b_compress  (src/blake2b.asm, BLAKE2b F, RFC 7693 3.2)
//   argon2_compress   (src/argon2.asm,  Argon2 compression G, RFC 9106 3.5)
// -----------------------------------------------------------------------------
// Vordr internal ARM64 calling convention (docs/ARM64.md): x64 register meaning
// on fixed ARM64 registers - rcx=x0, rdx=x1, r8=x2, r9=x3, rax=x8.  Both routines
// are leaves; they touch only x11-x15 (translator scratch), v0-v7 and v16-v31,
// and leave every x64-mapped GPR (x0-x10, x19-x29) unchanged.  v8-v15 (the
// callee-saved xmm6-xmm13) are never used.  Every vector register that held
// state, message or block data is zeroed before return, and argon2_compress
// wipes its 1 KiB stack work area (mirroring the x64 scrub).
//
// Constant time: no data-dependent branches or addresses.  The only branches
// are fixed-trip loop counters and argon2_compress's with_xor test, which is a
// public parameter (the pass number), exactly as in the x64 code.
//
// Lane layout shared by both permutations (16 x 64-bit words v[0..15]):
//   A0=[v0,v1]  A1=[v2,v3]  B0=[v4,v5]  B1=[v6,v7]
//   C0=[v8,v9]  C1=[v10,v11] D0=[v12,v13] D1=[v14,v15]
// so one "column step" G(0,4,8,12) G(1,5,9,13) G(2,6,10,14) G(3,7,11,15) runs on
// (A0,B0,C0,D0) and (A1,B1,C1,D1) in parallel.  The diagonal step
// G(0,5,10,15) G(1,6,11,12) G(2,7,8,13) G(3,4,9,14) runs on
//   B0'=[v5,v6]=ext(B0,B1)  B1'=[v7,v4]=ext(B1,B0)  C0'=C1  C1'=C0
//   D0'=[v15,v12]=ext(D1,D0)  D1'=[v13,v14]=ext(D0,D1)
// and the inverse EXTs restore the row layout.
//
// Rotations (right, 64-bit lanes): 32 = REV64 .4s; 24 and 16 = TBL byte
// shuffles; 63 = (x << 1) + (x >> 63) via ADD + USRA.
// fBlaMka(a, b) = a + b + 2 * lo32(a) * lo32(b): UZP1 gathers the low halves of
// both lane pairs, then UMLAL (pair 0) / UMLAL2 (pair 1) accumulate twice.
//
// Build: clang --target=aarch64-pc-windows-msvc -march=armv8.2-a+crypto -c
// =============================================================================

        .text

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// rotr63 of (b ^ c) for two lane pairs: b = rotl1(b ^ c).  temps v22, v23.
.macro XROT63 b0, b1, c0, c1
        eor     v22.16b, \b0\().16b, \c0\().16b
        eor     v23.16b, \b1\().16b, \c1\().16b
        add     \b0\().2d, v22.2d, v22.2d
        add     \b1\().2d, v23.2d, v23.2d
        usra    \b0\().2d, v22.2d, #63
        usra    \b1\().2d, v23.2d, #63
.endm

// d = rotr32(d ^ a) for two lane pairs
.macro XROT32 d0, d1, a0, a1
        eor     \d0\().16b, \d0\().16b, \a0\().16b
        eor     \d1\().16b, \d1\().16b, \a1\().16b
        rev64   \d0\().4s, \d0\().4s
        rev64   \d1\().4s, \d1\().4s
.endm

// x = rotr(x ^ y, 24 or 16) through the TBL mask m (v30 = 24, v31 = 16)
.macro XROTT x0, x1, y0, y1, m
        eor     \x0\().16b, \x0\().16b, \y0\().16b
        eor     \x1\().16b, \x1\().16b, \y1\().16b
        tbl     \x0\().16b, {\x0\().16b}, \m\().16b
        tbl     \x1\().16b, {\x1\().16b}, \m\().16b
.endm

// row layout -> diagonal layout (B into v24/v25, D into v26/v27)
.macro DIAG
        ext     v24.16b, v2.16b, v3.16b, #8     // B0' = [v5 , v6 ]
        ext     v25.16b, v3.16b, v2.16b, #8     // B1' = [v7 , v4 ]
        ext     v26.16b, v7.16b, v6.16b, #8     // D0' = [v15, v12]
        ext     v27.16b, v6.16b, v7.16b, #8     // D1' = [v13, v14]
.endm

// diagonal layout -> row layout
.macro UNDIAG
        ext     v2.16b, v25.16b, v24.16b, #8    // B0 = [v4 , v5 ]
        ext     v3.16b, v24.16b, v25.16b, #8    // B1 = [v6 , v7 ]
        ext     v6.16b, v26.16b, v27.16b, #8    // D0 = [v12, v13]
        ext     v7.16b, v27.16b, v26.16b, #8    // D1 = [v14, v15]
.endm

// =============================================================================
// BLAKE2b
// =============================================================================

// MP n, i, j : v<n> = [m[i], m[j]]  (m = block at x1).  temp v20.
.macro MP n, i, j
        ldr     d\n, [x1, #(\i * 8)]
        ldr     d20, [x1, #(\j * 8)]
        mov     v\n\().d[1], v20.d[0]
.endm

// Two BLAKE2b G functions per lane pair, message pairs x (first add), y (second)
.macro B2G a0, a1, b0, b1, c0, c1, d0, d1, x0, x1, y0, y1
        add     \a0\().2d, \a0\().2d, \b0\().2d
        add     \a1\().2d, \a1\().2d, \b1\().2d
        add     \a0\().2d, \a0\().2d, \x0\().2d
        add     \a1\().2d, \a1\().2d, \x1\().2d
        XROT32  \d0, \d1, \a0, \a1
        add     \c0\().2d, \c0\().2d, \d0\().2d
        add     \c1\().2d, \c1\().2d, \d1\().2d
        XROTT   \b0, \b1, \c0, \c1, v30
        add     \a0\().2d, \a0\().2d, \b0\().2d
        add     \a1\().2d, \a1\().2d, \b1\().2d
        add     \a0\().2d, \a0\().2d, \y0\().2d
        add     \a1\().2d, \a1\().2d, \y1\().2d
        XROTT   \d0, \d1, \a0, \a1, v31
        add     \c0\().2d, \c0\().2d, \d0\().2d
        add     \c1\().2d, \c1\().2d, \d1\().2d
        XROT63  \b0, \b1, \c0, \c1
.endm

// One BLAKE2b round with message schedule sigma = s0..s15
.macro B2ROUND s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15
        MP      16, \s0, \s2
        MP      17, \s4, \s6
        MP      18, \s1, \s3
        MP      19, \s5, \s7
        B2G     v0, v1, v2, v3, v4, v5, v6, v7, v16, v17, v18, v19
        DIAG
        MP      16, \s8, \s10
        MP      17, \s12, \s14
        MP      18, \s9, \s11
        MP      19, \s13, \s15
        B2G     v0, v1, v24, v25, v5, v4, v26, v27, v16, v17, v18, v19
        UNDIAG
.endm

// =============================================================================
// blake2b_compress(x0 = ctx, x1 = block (128 bytes), x2 = lastflag)
//   ctx layout (BLAKE2B_CTX): h[8] @0, t[2] @64, buf[128] @80, buflen, outlen
//   v[0..7] = h, v[8..15] = IV, v12 ^= t0, v13 ^= t1, v14 ^= lastflag (full
//   64 bits, as the x64 code XORs r8 unmodified; callers pass 0 or ~0)
//   h[i] ^= v[i] ^ v[i+8].  ctx.t is read only (the callers advance it).
// Leaf, no stack.  Preserves x0-x10 (x64 rcx/rdx/r8/r9/rax/r10/r11 - the x64
// original clobbers rax/r10/r11 and may clobber r8; nothing here depends on
// that).  Clobbers x11, v0-v7, v16-v31 (all returned zeroed except x11).
// Any aliasing between block and ctx is safe: h is written only at the end.
// =============================================================================
        .globl  blake2b_compress
        .def    blake2b_compress
        .scl    2
        .type   32
        .endef
        .p2align 4
blake2b_compress:
        adrp    x11, vordr_a64_b2b_iv
        add     x11, x11, :lo12:vordr_a64_b2b_iv
        ld1     {v0.2d, v1.2d, v2.2d, v3.2d}, [x0]      // v[0..7]  = h
        ld1     {v4.2d, v5.2d, v6.2d, v7.2d}, [x11]     // v[8..15] = IV
        ldp     q30, q31, [x11, #64]                    // rotr24 / rotr16 masks
        ldr     q16, [x0, #64]                          // [t0, t1]
        fmov    d17, x2                                 // [last, 0]
        eor     v6.16b, v6.16b, v16.16b                 // v12 ^= t0, v13 ^= t1
        eor     v7.16b, v7.16b, v17.16b                 // v14 ^= last

        B2ROUND  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15
        B2ROUND 14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3
        B2ROUND 11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4
        B2ROUND  7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8
        B2ROUND  9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13
        B2ROUND  2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9
        B2ROUND 12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11
        B2ROUND 13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10
        B2ROUND  6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5
        B2ROUND 10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0
        B2ROUND  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15
        B2ROUND 14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3

        // feed-forward: h[i] ^= v[i] ^ v[i+8]
        ld1     {v16.2d, v17.2d, v18.2d, v19.2d}, [x0]
        eor     v0.16b, v0.16b, v4.16b
        eor     v1.16b, v1.16b, v5.16b
        eor     v2.16b, v2.16b, v6.16b
        eor     v3.16b, v3.16b, v7.16b
        eor     v16.16b, v16.16b, v0.16b
        eor     v17.16b, v17.16b, v1.16b
        eor     v18.16b, v18.16b, v2.16b
        eor     v19.16b, v19.16b, v3.16b
        st1     {v16.2d, v17.2d, v18.2d, v19.2d}, [x0]

        // scrub working state, message pairs and temps
        movi    v0.2d, #0
        movi    v1.2d, #0
        movi    v2.2d, #0
        movi    v3.2d, #0
        movi    v4.2d, #0
        movi    v5.2d, #0
        movi    v6.2d, #0
        movi    v7.2d, #0
        movi    v16.2d, #0
        movi    v17.2d, #0
        movi    v18.2d, #0
        movi    v19.2d, #0
        movi    v20.2d, #0
        movi    v21.2d, #0
        movi    v22.2d, #0
        movi    v23.2d, #0
        movi    v24.2d, #0
        movi    v25.2d, #0
        movi    v26.2d, #0
        movi    v27.2d, #0
        movi    v28.2d, #0
        movi    v29.2d, #0
        movi    v30.2d, #0
        movi    v31.2d, #0
        ret

// =============================================================================
// Argon2 (RFC 9106) - BlaMka permutation P on a 16-word group in v0..v7
// =============================================================================

// a = fBlaMka(a, b) for the lane pairs (a0, b0), (a1, b1).  temps v20, v21.
.macro FBLA a0, a1, b0, b1
        uzp1    v20.4s, \a0\().4s, \a1\().4s    // [lo a0.0, lo a0.1, lo a1.0, lo a1.1]
        uzp1    v21.4s, \b0\().4s, \b1\().4s
        add     \a0\().2d, \a0\().2d, \b0\().2d
        add     \a1\().2d, \a1\().2d, \b1\().2d
        umlal   \a0\().2d, v20.2s, v21.2s
        umlal2  \a1\().2d, v20.4s, v21.4s
        umlal   \a0\().2d, v20.2s, v21.2s
        umlal2  \a1\().2d, v20.4s, v21.4s
.endm

// Two BlaMka G functions per lane pair (GB in RFC 9106 3.6)
.macro AG a0, a1, b0, b1, c0, c1, d0, d1
        FBLA    \a0, \a1, \b0, \b1
        XROT32  \d0, \d1, \a0, \a1
        FBLA    \c0, \c1, \d0, \d1
        XROTT   \b0, \b1, \c0, \c1, v30
        FBLA    \a0, \a1, \b0, \b1
        XROTT   \d0, \d1, \a0, \a1, v31
        FBLA    \c0, \c1, \d0, \d1
        XROT63  \b0, \b1, \c0, \c1
.endm

// P on v0..v7 (16 words in the shared lane layout)
.macro AROUND
        AG      v0, v1, v2, v3, v4, v5, v6, v7
        DIAG
        AG      v0, v1, v24, v25, v5, v4, v26, v27
        UNDIAG
.endm

// =============================================================================
// argon2_compress(x0 = dst, x1 = X, x2 = Y, x3 = with_xor)
//   R = X ^ Y ; Q = P_columns(P_rows(R)) ; Z = Q ^ R
//   dst = with_xor ? dst ^ Z : Z        (with_xor tested as a full 64-bit value)
// Byte-identical to argon2_compress_{avx2,sse2,scalar}.  dst may alias X and/or
// Y (the address-block generation calls it with dst == Y): X and Y are read
// row by row in the row pass, and re-read in the column pass only for the
// 16-byte chunks of the column being finished, each chunk being read before
// the same chunk of dst is written; the row-pass state lives on the stack.
//
// Frame: fp/lr pair + 1 KiB work area Q (wiped before return).
// Preserves x0-x10 (x64: the dispatcher's variants leave rcx = dst and rdx = X;
// r8/r9/rax/r10/r11 are clobbered there, so callers rely on none of them).
// Clobbers x11-x15, v0-v7, v16-v31 (vectors returned zeroed).
// =============================================================================
        .globl  argon2_compress
        .def    argon2_compress
        .scl    2
        .type   32
        .endef
        .p2align 4
argon2_compress:
        .seh_proc argon2_compress
        pacibsp
        .seh_pac_sign_lr
        stp     x29, x30, [sp, #-16]!
        .seh_save_fplr_x 16
        mov     x29, sp
        .seh_set_fp
        sub     sp, sp, #1024
        .seh_stackalloc 1024
        .seh_endprologue

        adrp    x11, vordr_a64_rot24
        add     x11, x11, :lo12:vordr_a64_rot24
        ldp     q30, q31, [x11]                 // rotr24 / rotr16 masks

        // ---- row pass: Q[row] = P(X[row] ^ Y[row]) ---------------------------
        mov     x11, x1                         // X row
        mov     x12, x2                         // Y row
        mov     x13, sp                         // Q row
        mov     x14, #8
.La2_row:
        ldp     q0, q1, [x11]
        ldp     q2, q3, [x11, #32]
        ldp     q4, q5, [x11, #64]
        ldp     q6, q7, [x11, #96]
        ldp     q16, q17, [x12]
        ldp     q18, q19, [x12, #32]
        ldp     q20, q21, [x12, #64]
        ldp     q22, q23, [x12, #96]
        add     x11, x11, #128
        add     x12, x12, #128
        eor     v0.16b, v0.16b, v16.16b
        eor     v1.16b, v1.16b, v17.16b
        eor     v2.16b, v2.16b, v18.16b
        eor     v3.16b, v3.16b, v19.16b
        eor     v4.16b, v4.16b, v20.16b
        eor     v5.16b, v5.16b, v21.16b
        eor     v6.16b, v6.16b, v22.16b
        eor     v7.16b, v7.16b, v23.16b
        AROUND
        stp     q0, q1, [x13]
        stp     q2, q3, [x13, #32]
        stp     q4, q5, [x13, #64]
        stp     q6, q7, [x13, #96]
        add     x13, x13, #128
        subs    x14, x14, #1
        b.ne    .La2_row

        // ---- column pass: column c = 16-byte chunk c of every row ------------
        //      then dst chunk = Q' ^ X ^ Y (^ dst)
        mov     x13, sp                         // Q  + 16c
        mov     x11, x1                         // X  + 16c
        mov     x12, x2                         // Y  + 16c
        mov     x15, x0                         // dst + 16c
        mov     x14, #8
.La2_col:
        ldr     q0, [x13, #0]
        ldr     q1, [x13, #128]
        ldr     q2, [x13, #256]
        ldr     q3, [x13, #384]
        ldr     q4, [x13, #512]
        ldr     q5, [x13, #640]
        ldr     q6, [x13, #768]
        ldr     q7, [x13, #896]
        AROUND
        ldr     q16, [x11, #0]
        ldr     q17, [x11, #128]
        ldr     q18, [x11, #256]
        ldr     q19, [x11, #384]
        ldr     q20, [x11, #512]
        ldr     q21, [x11, #640]
        ldr     q22, [x11, #768]
        ldr     q23, [x11, #896]
        eor     v0.16b, v0.16b, v16.16b
        eor     v1.16b, v1.16b, v17.16b
        eor     v2.16b, v2.16b, v18.16b
        eor     v3.16b, v3.16b, v19.16b
        eor     v4.16b, v4.16b, v20.16b
        eor     v5.16b, v5.16b, v21.16b
        eor     v6.16b, v6.16b, v22.16b
        eor     v7.16b, v7.16b, v23.16b
        ldr     q16, [x12, #0]
        ldr     q17, [x12, #128]
        ldr     q18, [x12, #256]
        ldr     q19, [x12, #384]
        ldr     q20, [x12, #512]
        ldr     q21, [x12, #640]
        ldr     q22, [x12, #768]
        ldr     q23, [x12, #896]
        eor     v0.16b, v0.16b, v16.16b
        eor     v1.16b, v1.16b, v17.16b
        eor     v2.16b, v2.16b, v18.16b
        eor     v3.16b, v3.16b, v19.16b
        eor     v4.16b, v4.16b, v20.16b
        eor     v5.16b, v5.16b, v21.16b
        eor     v6.16b, v6.16b, v22.16b
        eor     v7.16b, v7.16b, v23.16b
        cbz     x3, .La2_store                  // public: pass == 0
        ldr     q16, [x15, #0]
        ldr     q17, [x15, #128]
        ldr     q18, [x15, #256]
        ldr     q19, [x15, #384]
        ldr     q20, [x15, #512]
        ldr     q21, [x15, #640]
        ldr     q22, [x15, #768]
        ldr     q23, [x15, #896]
        eor     v0.16b, v0.16b, v16.16b
        eor     v1.16b, v1.16b, v17.16b
        eor     v2.16b, v2.16b, v18.16b
        eor     v3.16b, v3.16b, v19.16b
        eor     v4.16b, v4.16b, v20.16b
        eor     v5.16b, v5.16b, v21.16b
        eor     v6.16b, v6.16b, v22.16b
        eor     v7.16b, v7.16b, v23.16b
.La2_store:
        str     q0, [x15, #0]
        str     q1, [x15, #128]
        str     q2, [x15, #256]
        str     q3, [x15, #384]
        str     q4, [x15, #512]
        str     q5, [x15, #640]
        str     q6, [x15, #768]
        str     q7, [x15, #896]
        add     x11, x11, #16
        add     x12, x12, #16
        add     x13, x13, #16
        add     x15, x15, #16
        subs    x14, x14, #1
        b.ne    .La2_col

        // ---- scrub: work area + every vector register that held block data ----
        movi    v0.2d, #0
        mov     x13, sp
        mov     x14, #8
.La2_wipe:
        stp     q0, q0, [x13]
        stp     q0, q0, [x13, #32]
        stp     q0, q0, [x13, #64]
        stp     q0, q0, [x13, #96]
        add     x13, x13, #128
        subs    x14, x14, #1
        b.ne    .La2_wipe
        movi    v1.2d, #0
        movi    v2.2d, #0
        movi    v3.2d, #0
        movi    v4.2d, #0
        movi    v5.2d, #0
        movi    v6.2d, #0
        movi    v7.2d, #0
        movi    v16.2d, #0
        movi    v17.2d, #0
        movi    v18.2d, #0
        movi    v19.2d, #0
        movi    v20.2d, #0
        movi    v21.2d, #0
        movi    v22.2d, #0
        movi    v23.2d, #0
        movi    v24.2d, #0
        movi    v25.2d, #0
        movi    v26.2d, #0
        movi    v27.2d, #0
        movi    v28.2d, #0
        movi    v29.2d, #0
        movi    v30.2d, #0
        movi    v31.2d, #0

        add     sp, sp, #1024
        ldp     x29, x30, [sp], #16
        autibsp
        ret
        .seh_endproc

// =============================================================================
        .section .rdata,"dr"
        .p2align 4
vordr_a64_b2b_iv:                               // BLAKE2b IV (+0..63), masks (+64)
        .quad   0x6a09e667f3bcc908, 0xbb67ae8584caa73b
        .quad   0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
        .quad   0x510e527fade682d1, 0x9b05688c2b3e6c1f
        .quad   0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
vordr_a64_rot24:                                // TBL: rotr 24 per 64-bit lane
        .byte   3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10
vordr_a64_rot16:                                // TBL: rotr 16 per 64-bit lane
        .byte   2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9
