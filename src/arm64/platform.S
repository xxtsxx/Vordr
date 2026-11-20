// =============================================================================
// src/arm64/platform.S - ARM64 platform-specific runtime primitives
// -----------------------------------------------------------------------------
// Replaces the x86-specific routines that cannot be mechanically translated:
//   - cpu_gate        : IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO) + HKLM
//                       CP 4030 (ID_AA64ISAR0_EL1.RNDR) probe for FEAT_RNG
//   - rng_fill        : BCryptGenRandom + optional ARMv8.5 RNDRRS XOR mix
//   - ff_trap         : re-entrancy-safe panic wipe + ARM64 __fastfail (brk #0xF003)
//   - guard_check_icall_nop / guard_dispatch_icall_nop (ARM64 CFG default stubs)
//
// Calling convention: Vordr internal ARM64 ABI (docs/ARM64.md).
//   Args 1-4 in x0-x3, return in x8, preserve x19-x29, sp, v8-v15, never touch x18.
// =============================================================================

        .equ    CPUF_AESNI,         1
        .equ    CPUF_PCLMUL,        2
        .equ    CPUF_SSE41,         4
        .equ    CPUF_SHANI,         8
        .equ    CPUF_AVX2,          16
        .equ    CPUF_RDSEED,        32
        .equ    CPUF_ARM64_BASE,    31      // AESNI|PCLMUL|SSE41|SHANI|AVX2

        .equ    PF_ARM_V8_CRYPTO,   30      // PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE
        .equ    BCRYPT_SYS_RNG,     2       // BCRYPT_USE_SYSTEM_PREFERRED_RNG
        .equ    KEY_READ,           0x20019
        .equ    REG_QWORD,          11

        .section .rdata,"dr"
        .p2align 1
w_cpu0_key:
        .hword  'H','A','R','D','W','A','R','E','\\'
        .hword  'D','E','S','C','R','I','P','T','I','O','N','\\'
        .hword  'S','y','s','t','e','m','\\'
        .hword  'C','e','n','t','r','a','l','P','r','o','c','e','s','s','o','r','\\'
        .hword  '0', 0
        .p2align 1
w_cp4030:
        .hword  'C','P',' ','4','0','3','0', 0

        .text

// =============================================================================
// cpu_gate() -> w8 = 1 if ARMv8 Cryptography Extensions present, 0 otherwise.
// Raw frame (runs before hardening_init).
// =============================================================================
        .globl  cpu_gate
        .p2align 2
        .seh_proc cpu_gate
cpu_gate:
        pacibsp
        .seh_pac_sign_lr
        stp     x29, x30, [sp, #-16]!
        .seh_save_fplr_x 16
        mov     x29, sp
        .seh_set_fp
        stp     x19, x20, [sp, #-16]!
        .seh_save_regp_x x19, 16
        sub     sp, sp, #64
        .seh_stackalloc 64
        .seh_endprologue

        // [sp+0]:  hKey (8)
        // [sp+8]:  dwType (4), cbData (4)
        // [sp+16]: val64 (8)
        mov     w19, #0
        mov     w0, #PF_ARM_V8_CRYPTO
        bl      IsProcessorFeaturePresent
        cbz     w0, cg_store

        mov     w19, #CPUF_ARM64_BASE

        // Probe HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\CP 4030
        // (cached ID_AA64ISAR0_EL1) for FEAT_RNG (bits [63:60] >= 1).
        str     xzr, [sp]
        movn    x0, #0x7FFF, lsl #16
        movk    x0, #0x0002                 // 0xFFFFFFFF80000002 = HKEY_LOCAL_MACHINE
        adrp    x16, w_cpu0_key
        add     x1, x16, :lo12:w_cpu0_key
        mov     w2, #0
        movz    w3, #0x0019
        movk    w3, #0x0002, lsl #16        // KEY_READ = 0x20019
        add     x4, sp, #0                  // &hKey
        bl      RegOpenKeyExW
        cbnz    w0, cg_store

        mov     w11, #8
        str     w11, [sp, #12]              // cbData = 8
        str     wzr, [sp, #8]               // dwType = 0
        str     xzr, [sp, #16]              // val64 = 0
        ldr     x0, [sp]                    // hKey
        adrp    x16, w_cp4030
        add     x1, x16, :lo12:w_cp4030
        mov     x2, #0                      // lpReserved
        add     x3, sp, #8                  // &dwType
        add     x4, sp, #16                 // &val64
        add     x5, sp, #12                 // &cbData
        bl      RegQueryValueExW
        mov     w20, w0

        ldr     x0, [sp]
        bl      RegCloseKey

        cbnz    w20, cg_store
        ldr     w11, [sp, #8]
        cmp     w11, #REG_QWORD
        b.ne    cg_store
        ldr     w11, [sp, #12]
        cmp     w11, #8
        b.ne    cg_store
        ldr     x11, [sp, #16]
        lsr     x11, x11, #60               // ID_AA64ISAR0_EL1.RNDR [63:60]
        cbz     x11, cg_store
        orr     w19, w19, #CPUF_RDSEED

cg_store:
        adrp    x16, g_cpu_features
        str     w19, [x16, :lo12:g_cpu_features]
        cmp     w19, #0
        cset    w8, ne

        add     sp, sp, #64
        ldp     x19, x20, [sp], #16
        ldp     x29, x30, [sp], #16
        autibsp
        ret
        .seh_endproc

// =============================================================================
// rng_fill(x0 = buf, w1 = len) -> w8 = 1 ok, 0 failure
// Primary: BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG).
// Defense in depth: XOR-mix ARMv8.5 RNDRRS when FEAT_RNG (CPUF_RDSEED) is set.
// =============================================================================
        .globl  rng_fill
        .p2align 2
        .seh_proc rng_fill
rng_fill:
        pacibsp
        .seh_pac_sign_lr
        stp     x29, x30, [sp, #-16]!
        .seh_save_fplr_x 16
        mov     x29, sp
        .seh_set_fp
        sub     sp, sp, #64
        .seh_stackalloc 64
        .seh_endprologue

        // [sp+0..31]:  internal callee home area (for secure_zero)
        // [x29-16]:    buf
        // [x29-8]:     len (w)
        cbz     x0, rf_fail
        cbz     w1, rf_ok

        str     x0, [x29, #-16]
        str     w1, [x29, #-8]

        // Windows ARM64 ABI: BCryptGenRandom(NULL, pbBuffer, cbBuffer, dwFlags)
        mov     w3, #BCRYPT_SYS_RNG
        mov     w2, w1
        mov     x1, x0
        mov     x0, #0
        bl      BCryptGenRandom
        cbnz    w0, rf_wipe_fail

        adrp    x16, g_cpu_features
        ldr     w11, [x16, :lo12:g_cpu_features]
        tbz     w11, #5, rf_ok              // bit 5 = CPUF_RDSEED (32)

        ldr     x10, [x29, #-16]            // cursor
        ldr     w11, [x29, #-8]             // remaining bytes
rf_mix_loop:
        cmp     w11, #8
        b.lo    rf_tail
        mov     w12, #16                    // retry budget per lane
rf_retry:
        mrs     x9, s3_3_c2_c4_1            // RNDRRS (Z=0 valid, Z=1 retry)
        b.ne    rf_have_seed
        yield
        subs    w12, w12, #1
        b.ne    rf_retry
        b       rf_ok                       // starved: keep OS CSPRNG bytes
rf_have_seed:
        ldr     x13, [x10]
        eor     x13, x13, x9
        str     x13, [x10], #8
        sub     w11, w11, #8
        b       rf_mix_loop

rf_tail:
        cbz     w11, rf_ok
        mov     w12, #16
rf_t_retry:
        mrs     x9, s3_3_c2_c4_1            // RNDRRS for 1..7-byte tail
        b.ne    rf_t_have
        yield
        subs    w12, w12, #1
        b.ne    rf_t_retry
        b       rf_ok
rf_t_have:
        ldrb    w13, [x10]
        eor     w13, w13, w9
        strb    w13, [x10], #1
        lsr     x9, x9, #8
        subs    w11, w11, #1
        b.ne    rf_t_have

rf_ok:
        mov     x9, #0                      // scrub last hardware RNG qword
        mov     x13, #0
        mov     w8, #1
        b       rf_done

rf_wipe_fail:
        ldr     x0, [x29, #-16]
        ldr     w1, [x29, #-8]
        bl      secure_zero
rf_fail:
        mov     x9, #0
        mov     x13, #0
        mov     w8, #0
rf_done:
        mov     sp, x29
        ldp     x29, x30, [sp], #16
        autibsp
        ret
        .seh_endproc

// =============================================================================
// ff_trap(w0 = fail code) - central fail-fast handler.  Never returns.
// =============================================================================
        .globl  ff_trap
        .p2align 2
ff_trap:
        mov     w25, w0                     // preserve code (r15d)
        mov     x11, sp
        and     x11, x11, #-16
        mov     sp, x11
        sub     sp, sp, #48                 // 32-byte home + alignment
#ifdef DBG_TRACE
        bl      crash_try_enter
        cbz     w8, ff_dbg_reent
        bl      sstk_reset_current
        bl      secmem_panic_wipe
        bl      crash_restore_desktop
        mov     w8, #'F'
        bl      dbg_putc
        mov     w8, #'F'
        bl      dbg_putc
        mov     w24, #12                    // print 4 hex nibbles, high to low
ff_hexloop:
        sub     w24, w24, #4
        lsr     w8, w25, w24
        and     w8, w8, #0xF
        cmp     w8, #10
        b.lo    ff_dec
        add     w8, w8, #('a' - 10)
        b       ff_emit
ff_dec:
        add     w8, w8, #'0'
ff_emit:
        bl      dbg_putc
        cbnz    w24, ff_hexloop
        mov     w8, #13
        bl      dbg_putc
        mov     w8, #10
        bl      dbg_putc
        movz    w0, #0xFADE, lsl #16
        orr     w0, w0, w25
        bl      ExitProcess
ff_dbg_reent:
        bl      GetCurrentProcess
        movz    w1, #0x0409
        movk    w1, #0xC000, lsl #16
        bl      TerminateProcess
        mov     w0, w25
        brk     #0xF003
#endif
        bl      crash_try_enter
        cbz     w8, ff_rel_reent
        bl      sstk_reset_current
        bl      secmem_panic_wipe
        bl      crash_restore_desktop
ff_rel_reent:
        mov     w0, w25
        brk     #0xF003                     // Windows ARM64 __fastfail(w0)
        b       ff_rel_reent
