// =============================================================================
// src/arm64/frame.inc - shared stack canary & software shadow-stack macros
// -----------------------------------------------------------------------------
// Mirrors src/macros.inc FRAME_PROLOG / FRAME_EPILOG for hand-written AArch64
// framed procedures (gcm_seal, gcm_open, argon2_compress, rng_fill):
//   - Stack canary at [x29, #-8] = g_stack_canary ^ x29 (scrubbed on exit)
//   - Per-thread software shadow stack via TEB TLS slot g_sstk_tls - 1
//     (x18 + 0x1480 + slot * 8), pushing/checking the signed LR at [x29, #8].
// Clobbers ONLY scratch x14-x17; preserves x0-x10 (incl. return x8) & x19-x29.
// =============================================================================

.equ    A64_FF_STACK_COOKIE, 2
.equ    A64_FF_SHADOW_STACK, 0xF001
.equ    A64_TEB_TLS_HI,      0x1000
.equ    A64_TEB_TLS_LO,      0x480
.equ    A64_SSTK_HDR,        16
.equ    A64_SSTK_CAPACITY,   256

.macro A64_FRAME_GUARD_ENTER lbl_skip
        adrp    x16, g_stack_canary
        ldr     x16, [x16, :lo12:g_stack_canary]
        eor     x16, x16, x29
        str     x16, [x29, #-8]
        adrp    x16, g_sstk_tls
        ldr     w16, [x16, :lo12:g_sstk_tls]
        cbz     w16, \lbl_skip
        sub     w16, w16, #1
        add     x17, x18, #A64_TEB_TLS_HI
        add     x17, x17, #A64_TEB_TLS_LO
        ldr     x16, [x17, x16, lsl #3]
        cbz     x16, \lbl_skip
        ldr     x17, [x16]
        cmp     x17, #A64_SSTK_CAPACITY
        b.hs    sstk_overflow_fail
        add     x15, x16, #A64_SSTK_HDR
        ldr     x14, [x29, #8]
        str     x14, [x15, x17, lsl #3]
        add     x17, x17, #1
        str     x17, [x16]
\lbl_skip:
.endm

.macro A64_FRAME_GUARD_EXIT lbl_cok, lbl_ssfail, lbl_done
        adrp    x16, g_stack_canary
        ldr     x16, [x16, :lo12:g_stack_canary]
        eor     x16, x16, x29
        ldr     x17, [x29, #-8]
        cmp     x16, x17
        b.eq    \lbl_cok
        mov     w0, #A64_FF_STACK_COOKIE
        b       ff_trap
\lbl_cok:
        str     xzr, [x29, #-8]
        adrp    x16, g_sstk_tls
        ldr     w16, [x16, :lo12:g_sstk_tls]
        cbz     w16, \lbl_done
        sub     w16, w16, #1
        add     x17, x18, #A64_TEB_TLS_HI
        add     x17, x17, #A64_TEB_TLS_LO
        ldr     x16, [x17, x16, lsl #3]
        cbz     x16, \lbl_done
        ldr     x17, [x16]
        cbz     x17, \lbl_ssfail
        sub     x17, x17, #1
        str     x17, [x16]
        add     x15, x16, #A64_SSTK_HDR
        ldr     x14, [x15, x17, lsl #3]
        ldr     x15, [x29, #8]
        cmp     x14, x15
        b.eq    \lbl_done
\lbl_ssfail:
        mov     w0, #A64_FF_SHADOW_STACK
        b       ff_trap
\lbl_done:
.endm
