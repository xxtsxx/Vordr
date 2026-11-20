// =============================================================================
// sha.S - SHA-256 and SHA-1 block compression on the ARMv8 SHA extensions.
// -----------------------------------------------------------------------------
// Hand-written AArch64 replacements for two x64 routines; everything else in
// src/sha256.asm and src/sha1.asm (init/update/final/hash/hmac) is machine
// translated and calls these with the x64 arguments on the docs/ARM64.md
// register map (rcx=x0, rdx=x1, r8=x2, ..., xmm0-5=v0-v5, xmm14/15=v6/v7).
//
//   sha256_compress(x0 = state ptr, x1 = blocks ptr, x2 = block count)
//       state = H0..H7 as native (little-endian) dwords, 32 bytes.
//       Processes x2 64-byte blocks (64-bit count; 0 = no-op, state untouched).
//       Exit, exactly as the SHA-NI original: x1 += 64*count, x2 = 0,
//       v0-v5 (xmm0-5) zeroed; x0, x3-x10, v6-v15 unchanged.
//
//   sha1_block(x0 = ctx, x1 = block64)
//       ctx = h0..h4 as native dwords (20 bytes; ctx+20.. is not touched).
//       Exactly one 64-byte block.  Exit: v0 (xmm0) zeroed, as the original's
//       trailing secure_zero leaves it; x0-x10 and v1-v15 unchanged.
//       The original returns no value (rax is incidental), so x8 is unchanged.
//
// Both are pure leaves: sp and lr untouched, no stack use, so no SEH unwind
// data is needed.  Scratch: x11 (K pointer) and v16-v31 only; every vector
// register that held state, message or schedule data is zeroed before return.
// Constant time: the only branch is the public block-count loop, and the only
// memory addresses are the caller's buffers and the constant K table.
// Build: clang --target=aarch64-pc-windows-msvc -march=armv8.2-a+crypto -c
// =============================================================================

        .section .rdata,"dr"
        .p2align 4
sha256_k:
        .long 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
        .long 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
        .long 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
        .long 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
        .long 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
        .long 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070
        .long 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
        .long 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        .p2align 4
sha1_k:
        .long 0x5a827999,0x5a827999,0x5a827999,0x5a827999
        .long 0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
        .long 0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc
        .long 0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6

        .text

// -----------------------------------------------------------------------------
// SHA-256 register map:
//   v16 = ABCD   v17 = EFGH   v18/v19 = block-entry copies (feed-forward)
//   v20..v23 = message window W[t..t+15]   v24 = W+K   v25 = K   v26 = ABCD copy
//   x11 = K pointer (advances 16 bytes per group, reset per block)
// S256G m0,m1,m2,m3,upd: 4 rounds on m0 (W[t..t+3]); when upd=1 also turn m0
// into W[t+16..t+19] from the window (m1 = W[t+4..], m2 = W[t+8..], m3 = W[t+12..]).
// -----------------------------------------------------------------------------
.macro S256G m0, m1, m2, m3, upd
        ld1     {v25.4s}, [x11], #16
        add     v24.4s, \m0\().4s, v25.4s
.if \upd
        sha256su0 \m0\().4s, \m1\().4s
.endif
        mov     v26.16b, v16.16b
        sha256h  q16, q17, v24.4s
        sha256h2 q17, q26, v24.4s
.if \upd
        sha256su1 \m0\().4s, \m2\().4s, \m3\().4s
.endif
.endm

        .globl  sha256_compress
        .p2align 4
sha256_compress:
        cbz     x2, 2f
        ld1     {v16.4s, v17.4s}, [x0]          // ABCD, EFGH (lane 0 = A / E)
1:
        ld1     {v20.16b, v21.16b, v22.16b, v23.16b}, [x1], #64
        adrp    x11, sha256_k
        add     x11, x11, :lo12:sha256_k
        rev32   v20.16b, v20.16b                // big-endian message words
        rev32   v21.16b, v21.16b
        rev32   v22.16b, v22.16b
        rev32   v23.16b, v23.16b
        mov     v18.16b, v16.16b
        mov     v19.16b, v17.16b

        S256G   v20, v21, v22, v23, 1           // rounds  0..3
        S256G   v21, v22, v23, v20, 1
        S256G   v22, v23, v20, v21, 1
        S256G   v23, v20, v21, v22, 1
        S256G   v20, v21, v22, v23, 1           // rounds 16..19
        S256G   v21, v22, v23, v20, 1
        S256G   v22, v23, v20, v21, 1
        S256G   v23, v20, v21, v22, 1
        S256G   v20, v21, v22, v23, 1           // rounds 32..35
        S256G   v21, v22, v23, v20, 1
        S256G   v22, v23, v20, v21, 1
        S256G   v23, v20, v21, v22, 1
        S256G   v20, v21, v22, v23, 0           // rounds 48..51
        S256G   v21, v22, v23, v20, 0
        S256G   v22, v23, v20, v21, 0
        S256G   v23, v20, v21, v22, 0

        add     v16.4s, v16.4s, v18.4s          // feed-forward
        add     v17.4s, v17.4s, v19.4s
        subs    x2, x2, #1
        b.ne    1b
        st1     {v16.4s, v17.4s}, [x0]
2:
        movi    v0.2d, #0                       // as the original: xmm0-5 = 0
        movi    v1.2d, #0
        movi    v2.2d, #0
        movi    v3.2d, #0
        movi    v4.2d, #0
        movi    v5.2d, #0
        movi    v16.2d, #0                      // scrub state / message / schedule
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
        ret

// -----------------------------------------------------------------------------
// SHA-1 register map:
//   v16 = abcd   v17 / v26 = e (alternating per group)   v18/v19 = entry copies
//   v20..v23 = message window   v24 = W+K   v28..v31 = K1..K4 (broadcast)
// S1G op,k,m0,m1,m2,m3,ecur,enext,upd: 4 rounds of op (sha1c/p/m) on m0 with
// e in s<ecur>; the next group's e (rol30(a)) goes to s<enext>.  upd=1 also
// turns m0 into W[t+16..t+19] (m1 = W[t+4..], m2 = W[t+8..], m3 = W[t+12..]).
// -----------------------------------------------------------------------------
.macro S1G op, k, m0, m1, m2, m3, ecur, enext, upd
        add     v24.4s, \m0\().4s, \k\().4s
.if \upd
        sha1su0 \m0\().4s, \m1\().4s, \m2\().4s
.endif
        sha1h   s\enext, s16
        \op     q16, s\ecur, v24.4s
.if \upd
        sha1su1 \m0\().4s, \m3\().4s
.endif
.endm

        .globl  sha1_block
        .p2align 4
sha1_block:
        adrp    x11, sha1_k
        add     x11, x11, :lo12:sha1_k
        ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x11]
        ld1     {v20.16b, v21.16b, v22.16b, v23.16b}, [x1]
        ld1     {v16.4s}, [x0]                  // h0..h3 (lane 0 = h0)
        ldr     s17, [x0, #16]                  // h4
        rev32   v20.16b, v20.16b
        rev32   v21.16b, v21.16b
        rev32   v22.16b, v22.16b
        rev32   v23.16b, v23.16b
        mov     v18.16b, v16.16b
        mov     v19.16b, v17.16b

        S1G     sha1c, v28, v20, v21, v22, v23, 17, 26, 1   // rounds  0..3
        S1G     sha1c, v28, v21, v22, v23, v20, 26, 17, 1
        S1G     sha1c, v28, v22, v23, v20, v21, 17, 26, 1
        S1G     sha1c, v28, v23, v20, v21, v22, 26, 17, 1
        S1G     sha1c, v28, v20, v21, v22, v23, 17, 26, 1   // rounds 16..19
        S1G     sha1p, v29, v21, v22, v23, v20, 26, 17, 1   // rounds 20..23
        S1G     sha1p, v29, v22, v23, v20, v21, 17, 26, 1
        S1G     sha1p, v29, v23, v20, v21, v22, 26, 17, 1
        S1G     sha1p, v29, v20, v21, v22, v23, 17, 26, 1
        S1G     sha1p, v29, v21, v22, v23, v20, 26, 17, 1   // rounds 36..39
        S1G     sha1m, v30, v22, v23, v20, v21, 17, 26, 1   // rounds 40..43
        S1G     sha1m, v30, v23, v20, v21, v22, 26, 17, 1
        S1G     sha1m, v30, v20, v21, v22, v23, 17, 26, 1
        S1G     sha1m, v30, v21, v22, v23, v20, 26, 17, 1
        S1G     sha1m, v30, v22, v23, v20, v21, 17, 26, 1   // rounds 56..59
        S1G     sha1p, v31, v23, v20, v21, v22, 26, 17, 1   // rounds 60..63
        S1G     sha1p, v31, v20, v21, v22, v23, 17, 26, 0
        S1G     sha1p, v31, v21, v22, v23, v20, 26, 17, 0
        S1G     sha1p, v31, v22, v23, v20, v21, 17, 26, 0
        S1G     sha1p, v31, v23, v20, v21, v22, 26, 17, 0   // rounds 76..79

        add     v16.4s, v16.4s, v18.4s          // h += a..e
        add     v17.4s, v17.4s, v19.4s
        st1     {v16.4s}, [x0]
        str     s17, [x0, #16]

        movi    v0.2d, #0                       // as the original: xmm0 = 0
        movi    v16.2d, #0                      // scrub state / message / schedule
        movi    v17.2d, #0
        movi    v18.2d, #0
        movi    v19.2d, #0
        movi    v20.2d, #0
        movi    v21.2d, #0
        movi    v22.2d, #0
        movi    v23.2d, #0
        movi    v24.2d, #0
        movi    v26.2d, #0
        movi    v28.2d, #0
        movi    v29.2d, #0
        movi    v30.2d, #0
        movi    v31.2d, #0
        ret
