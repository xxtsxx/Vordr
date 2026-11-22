// =============================================================================
// src/arm64/platform.S - ARM64 platform-specific runtime primitives
// -----------------------------------------------------------------------------
// Replaces the x86-specific routines that cannot be mechanically translated:
//   - cpu_gate              : IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO) +
//                             all-core HKLM CentralProcessor\*\CP 4030 probe
//                             for FEAT_RNG (heterogeneous big.LITTLE safe)
//   - rng_fill              : BCryptGenRandom + optional ARMv8.5 RNDRRS XOR mix
//   - ff_trap               : re-entrancy-safe panic wipe + register scrub +
//                             ARM64 __fastfail (brk #0xF003)
//   - crash_capture_context : DBG_TRACE ARM64_NT_CONTEXT register snapshot
//
// Calling convention: Vordr internal ARM64 ABI (docs/ARM64.md).
//   Args 1-4 in x0-x3, return in x8, preserve x19-x29, sp, v8-v15, never touch x18.
// =============================================================================

#include "frame.inc"

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
        .equ    ERROR_NO_MORE_ITEMS, 259

        .section .rdata,"dr"
        .p2align 1
w_cpu_parent:
        .hword  'H','A','R','D','W','A','R','E','\\'
        .hword  'D','E','S','C','R','I','P','T','I','O','N','\\'
        .hword  'S','y','s','t','e','m','\\'
        .hword  'C','e','n','t','r','a','l','P','r','o','c','e','s','s','o','r', 0
        .p2align 1
w_cp4030:
        .hword  'C','P',' ','4','0','3','0', 0
        .p2align 1
w_dw_empty:
        .hword  0

        .text

// =============================================================================
// cpu_gate() -> w8 = 1 if ARMv8 Cryptography Extensions present, 0 otherwise.
// Raw frame (runs before hardening_init).
// A3-18: enumerates EVERY numeric CentralProcessor\<N> subkey so FEAT_RNG is
// only advertised when ALL cores (big + little) implement RNDRRS.
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
        stp     x21, x22, [sp, #-16]!
        .seh_save_regp_x x21, 16
        sub     sp, sp, #80
        .seh_stackalloc 80
        .seh_endprologue

        // [sp+0]:     hParent (8)
        // [sp+8]:     hCore (8)
        // [sp+16]:    dwType (4), cbData (4)
        // [sp+24]:    val64 (8)
        // [sp+32]:    cbName (4)
        // [sp+40..71]: subkey name buffer (16 UTF-16 chars)
        mov     w19, #0
        mov     w0, #PF_ARM_V8_CRYPTO
        bl      IsProcessorFeaturePresent
        cbz     w0, cg_store

        mov     w19, #CPUF_ARM64_BASE

        // Open HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor
        str     xzr, [sp]
        movn    x0, #0x7FFF, lsl #16
        movk    x0, #0x0002                 // 0xFFFFFFFF80000002 = HKEY_LOCAL_MACHINE
        adrp    x16, w_cpu_parent
        add     x1, x16, :lo12:w_cpu_parent
        mov     w2, #0
        movz    w3, #0x0019
        movk    w3, #0x0002, lsl #16        // KEY_READ = 0x20019
        add     x4, sp, #0                  // &hParent
        bl      RegOpenKeyExW
        cbnz    w0, cg_store

        mov     w20, #0                     // enum index
        mov     w21, #0                     // seen_any numeric core
        mov     w22, #1                     // all_cores_have_rng

cg_enum_lp:
        cmp     w20, #256                   // safety cap (A4-20: fail closed if >256 subkeys)
        b.hs    cg_no_rng
        mov     w11, #16
        str     w11, [sp, #32]              // cbName = 16 wchars
        ldr     x0, [sp]                    // hParent
        mov     w1, w20                     // dwIndex
        add     x2, sp, #40                 // lpName
        add     x3, sp, #32                 // lpcchName
        mov     x4, #0                      // lpReserved
        mov     x5, #0                      // lpClass
        mov     x6, #0                      // lpcchClass
        mov     x7, #0                      // lpftLastWriteTime
        bl      RegEnumKeyExW
        cmp     w0, #ERROR_NO_MORE_ITEMS
        b.eq    cg_enum_done
        cbz     w0, cg_enum_chk
        mov     w22, #0                     // unexpected enum error -> fail closed
        b       cg_enum_done

cg_enum_chk:
        add     w20, w20, #1
        // Accept only numeric subkeys ('0'..'9'+)
        ldr     w11, [sp, #32]
        cbz     w11, cg_enum_lp
        add     x12, sp, #40
        mov     w13, #0
cg_dig_lp:
        ldrh    w14, [x12, x13, lsl #1]
        sub     w14, w14, #'0'
        cmp     w14, #9
        b.hi    cg_enum_lp                  // non-numeric metadata subkey -> skip
        add     w13, w13, #1
        cmp     w13, w11
        b.lo    cg_dig_lp

        mov     w21, #1                     // saw at least one numeric core
        str     xzr, [sp, #8]
        ldr     x0, [sp]                    // hParent
        add     x1, sp, #40                 // subkey name ("0", "1", ...)
        mov     w2, #0
        movz    w3, #0x0019
        movk    w3, #0x0002, lsl #16        // KEY_READ
        add     x4, sp, #8                  // &hCore
        bl      RegOpenKeyExW
        cbz     w0, cg_query_core
        mov     w22, #0
        b       cg_enum_done

cg_query_core:
        mov     w11, #8
        str     w11, [sp, #20]              // cbData = 8
        str     wzr, [sp, #16]              // dwType = 0
        str     xzr, [sp, #24]              // val64 = 0
        ldr     x0, [sp, #8]                // hCore
        adrp    x16, w_cp4030
        add     x1, x16, :lo12:w_cp4030
        mov     x2, #0
        add     x3, sp, #16                 // &dwType
        add     x4, sp, #24                 // &val64
        add     x5, sp, #20                 // &cbData
        bl      RegQueryValueExW
        str     w0, [sp, #36]               // A4-07: spill across RegCloseKey (w13 is volatile!)
        ldr     x0, [sp, #8]
        bl      RegCloseKey
        ldr     w11, [sp, #36]
        cbnz    w11, cg_no_rng
        ldr     w11, [sp, #16]
        cmp     w11, #REG_QWORD
        b.ne    cg_no_rng
        ldr     w11, [sp, #20]
        cmp     w11, #8
        b.ne    cg_no_rng
        ldr     x11, [sp, #24]
        lsr     x11, x11, #60               // ID_AA64ISAR0_EL1.RNDR [63:60]
        cbz     x11, cg_no_rng
        b       cg_enum_lp

cg_no_rng:
        mov     w22, #0
cg_enum_done:
        ldr     x0, [sp]
        bl      RegCloseKey
        cbz     w21, cg_store
        cbz     w22, cg_store
        orr     w19, w19, #CPUF_RDSEED

cg_store:
        adrp    x16, g_cpu_features
        str     w19, [x16, :lo12:g_cpu_features]
        cmp     w19, #0
        cset    w8, ne

        .seh_startepilogue
        add     sp, sp, #80
        .seh_stackalloc 80
        ldp     x21, x22, [sp], #16
        .seh_save_regp_x x21, 16
        ldp     x19, x20, [sp], #16
        .seh_save_regp_x x19, 16
        ldp     x29, x30, [sp], #16
        .seh_save_fplr_x 16
        autibsp
        .seh_pac_sign_lr
        .seh_endepilogue
        ret
        .seh_endproc

// =============================================================================
// rng_fill(x0 = buf, w1 = len) -> w8 = 1 ok, 0 failure
// Primary: BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG).
// Defense in depth: XOR-mix ARMv8.5 RNDRRS when FEAT_RNG (CPUF_RDSEED) is set.
// Protected by stack canary [x29, #-8] + software shadow stack (A3-18).
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
        sub     sp, sp, #80
        .seh_stackalloc 80
        .seh_endprologue
        A64_FRAME_GUARD_ENTER .Lrf_ss_in

        // [sp+0..31]:  internal callee home area (for secure_zero)
        // [x29-8]:     stack canary
        // [x29-16]:    buf
        // [x29-24]:    len (w)
        cbz     x0, rf_fail
        cbz     w1, rf_ok

        str     x0, [x29, #-16]
        str     w1, [x29, #-24]

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
        ldr     w11, [x29, #-24]            // remaining bytes
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
        ldr     w1, [x29, #-24]
        bl      secure_zero
rf_fail:
        mov     x9, #0
        mov     x13, #0
        mov     w8, #0
rf_done:
        A64_FRAME_GUARD_EXIT .Lrf_cok, .Lrf_ssfail, .Lrf_ssdone
        .seh_startepilogue
        add     sp, sp, #80
        .seh_stackalloc 80
        ldp     x29, x30, [sp], #16
        .seh_save_fplr_x 16
        autibsp
        .seh_pac_sign_lr
        .seh_endepilogue
        ret
        .seh_endproc

// =============================================================================
// ff_trap(w0 = fail code) - central fail-fast handler.  Never returns.
// A3-18/A3-30: wipes every secret buffer, zeroes v0..v31 & GPRs before fastfail,
// fixes DBG_TRACE 4-nibble loop (w24=16) and separates #else release path.
// =============================================================================
.macro A64_SCRUB_ALL_REGS
        movi    v0.2d, #0
        movi    v1.2d, #0
        movi    v2.2d, #0
        movi    v3.2d, #0
        movi    v4.2d, #0
        movi    v5.2d, #0
        movi    v6.2d, #0
        movi    v7.2d, #0
        movi    v8.2d, #0
        movi    v9.2d, #0
        movi    v10.2d, #0
        movi    v11.2d, #0
        movi    v12.2d, #0
        movi    v13.2d, #0
        movi    v14.2d, #0
        movi    v15.2d, #0
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
        mov     x1, #0
        mov     x2, #0
        mov     x3, #0
        mov     x4, #0
        mov     x5, #0
        mov     x6, #0
        mov     x7, #0
        mov     x8, #0
        mov     x9, #0
        mov     x10, #0
        mov     x11, #0
        mov     x12, #0
        mov     x13, #0
        mov     x14, #0
        mov     x15, #0
        mov     x16, #0
        mov     x17, #0
        mov     x19, #0
        mov     x20, #0
        mov     x21, #0
        mov     x22, #0
        mov     x23, #0
        mov     x24, #0
        mov     x26, #0
        mov     x27, #0
        mov     x28, #0
        mov     x29, #0
.endm

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
        mov     w24, #16                    // A3-30: print ALL 4 hex nibbles (12,8,4,0)
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
        A64_SCRUB_ALL_REGS
        mov     w0, w25
        brk     #0xF003
        b       ff_dbg_reent
#else
        bl      crash_try_enter
        cbz     w8, ff_rel_reent
        bl      sstk_reset_current
        bl      secmem_panic_wipe
        bl      crash_restore_desktop
ff_rel_reent:
        A64_SCRUB_ALL_REGS
        mov     w0, w25
        brk     #0xF003                     // Windows ARM64 __fastfail(w0)
        b       ff_rel_reent
#endif

#ifdef DBG_TRACE
// =============================================================================
// crash_capture_context(x0 = ARM64_NT_CONTEXT*) - DBG_TRACE override (A3-18).
// Captures native ARM64_NT_CONTEXT registers into g_crash_regs[0..9] in the
// canonical slot order (rax/x8, rcx/x0, rdx/x1, rbx/x19, rsp/Sp, rbp/Fp,
// rsi/x20, rdi/x21, rip/Pc, r8/x2).  Leaf; never touches stack.
// =============================================================================
        .globl  crash_capture_context
        .p2align 2
crash_capture_context:
        cbz     x0, 1f
        adrp    x16, g_crash_regs
        add     x16, x16, :lo12:g_crash_regs
        ldr     x17, [x0, #0x48]            // X8 (mapped rax)
        str     x17, [x16, #0]
        ldr     x17, [x0, #0x08]            // X0 (mapped rcx)
        str     x17, [x16, #8]
        ldr     x17, [x0, #0x10]            // X1 (mapped rdx)
        str     x17, [x16, #16]
        ldr     x17, [x0, #0xA0]            // X19 (mapped rbx)
        str     x17, [x16, #24]
        ldr     x17, [x0, #0x100]           // Sp
        str     x17, [x16, #32]
        ldr     x17, [x0, #0xF0]            // Fp (X29)
        str     x17, [x16, #40]
        ldr     x17, [x0, #0xA8]            // X20 (mapped rsi)
        str     x17, [x16, #48]
        ldr     x17, [x0, #0xB0]            // X21 (mapped rdi)
        str     x17, [x16, #56]
        ldr     x17, [x0, #0x108]           // Pc
        str     x17, [x16, #64]
        ldr     x17, [x0, #0x18]            // X2 (mapped r8)
        str     x17, [x16, #72]
1:      ret
#endif

// =============================================================================
// dwrite_create_fmt(x0=pDw, x1=familyW, w2=sizeF32Bits, x3=ppFmt) -> w8=HRESULT
// Native AAPCS64 wrapper for IDWriteFactory::CreateTextFormat (vtbl[15] = +120),
// placing FLOAT fontSize into s0 as required by Windows ARM64 ABI and returning
// the HRESULT in Vordr's internal return register x8.
// =============================================================================
        .globl  dwrite_create_fmt
        .p2align 2
        .seh_proc dwrite_create_fmt
dwrite_create_fmt:
        pacibsp
        .seh_pac_sign_lr
        stp     x29, x30, [sp, #-16]!
        .seh_save_fplr_x 16
        mov     x29, sp
        .seh_set_fp
        .seh_endprologue
        fmov    s0, w2                      // FLOAT fontSize -> s0
        mov     x7, x3                      // IDWriteTextFormat** -> x7
        adrp    x6, w_dw_empty              // localeName = L"" -> x6
        add     x6, x6, :lo12:w_dw_empty
        mov     x2, #0                      // fontCollection = NULL
        mov     w3, #400                    // DWRITE_FONT_WEIGHT_NORMAL
        mov     w4, #0                      // DWRITE_FONT_STYLE_NORMAL
        mov     w5, #5                      // DWRITE_FONT_STRETCH_NORMAL
        ldr     x16, [x0]
        ldr     x16, [x16, #120]            // IDWriteFactory::CreateTextFormat [15]
        blr     x16
        mov     x8, x0                      // return HRESULT in Vordr internal rax (x8)
        .seh_startepilogue
        ldp     x29, x30, [sp], #16
        .seh_save_fplr_x 16
        autibsp
        .seh_pac_sign_lr
        .seh_endepilogue
        ret
        .seh_endproc
