// =============================================================================
// tests/arm64/stubs_aesgcm.S - TEST-ONLY stand-ins for the externs used by
// src/arm64/aesgcm.S, honouring the Vordr internal ARM64 convention
// (docs/ARM64.md).  After doing their job they deliberately trash every
// register a callee may clobber (x0-x17 except the x8 result, v0-v5,
// v16-v31) so the unit tests catch any caller that keeps live state there.
// v6/v7 (xmm14/xmm15) are left alone: the real x64-translated secure_zero /
// ct_memcmp never write xmm14/xmm15.
//
//   secure_zero(x0 = ptr, x1 = len)
//   ct_memcmp(x0 = a, x1 = b, x2 = len) -> x8 = 0 equal, 1 different
//   ff_trap(w0 = fastfail code)         -> brk #0xF003 (never returns)
// =============================================================================
        .text

.macro TRASHX r, rest:vararg
        movz    \r, #0xDEAD, lsl #48
        movk    \r, #0xBEEF
  .ifnb \rest
        TRASHX  \rest
  .endif
.endm

.macro TRASHV r, rest:vararg
        movi    \r\().16b, #0xEE
  .ifnb \rest
        TRASHV  \rest
  .endif
.endm

.macro TRASH keep8
        TRASHX  x0, x1, x2, x3, x4, x5, x6, x7, x9
        TRASHX  x10, x11, x12, x13, x14, x15, x16, x17
  .if \keep8 == 0
        movz    x8, #0xDEAD, lsl #48
  .endif
        TRASHV  v0, v1, v2, v3, v4, v5, v16, v17, v18, v19, v20
        TRASHV  v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31
.endm

        .globl  secure_zero
        .p2align 4
secure_zero:
        cbz     x1, 2f
1:      strb    wzr, [x0], #1
        subs    x1, x1, #1
        b.ne    1b
2:      dmb     ish
        TRASH   0
        ret

        .globl  ct_memcmp
        .p2align 4
ct_memcmp:
        mov     w8, #0
        mov     x9, #0
        cbz     x2, 2f
1:      ldrb    w10, [x0, x9]
        ldrb    w11, [x1, x9]
        eor     w10, w10, w11
        orr     w8, w8, w10
        add     x9, x9, #1
        cmp     x9, x2
        b.lo    1b
2:      cmp     w8, #0
        cset    w8, ne
        TRASH   1
        ret

        .globl  ff_trap
        .p2align 4
ff_trap:
        brk     #0xF003
        b       ff_trap
