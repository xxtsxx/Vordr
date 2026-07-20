; =============================================================================
; main.asm - entry point, CPU gate, command-line parsing, dispatch
; =============================================================================
; Startup order (deliberate):
;   1. cpu_gate        - raw frame; sets g_cpu_features (rng_fill reads RDSEED)
;   2. hardening_init  - raw frame; canary + shadow stack become live
;   3. con_init        - first FRAME_PROLOG-protected call
;   4. iat_lockdown    - IAT pages -> read-only BEFORE any user input is parsed
;   5. parse_cmdline / validate / dispatch (DLPV-guarded indirect call)
; =============================================================================

include macros.inc

extern GetCommandLineW:proc
extern ExitProcess:proc
extern WideCharToMultiByte:proc
extern GetStdHandle:proc
extern WriteFile:proc

STD_OUTPUT_HANDLE_   equ -11

; ---------------------------------------------------------------------------
; DBG ch - startup breadcrumb (only assembled with /DDBG_TRACE).  Prints one
; character to stdout, preserving no volatile registers (caller must not rely
; on them across a DBG point).  Used to localize early-startup faults.
; ---------------------------------------------------------------------------
DBG macro ch
ifdef DBG_TRACE
    mov     al, ch
    call    dbg_putc
endif
endm

extern hardening_init:proc
extern sec_lock_statics:proc
extern iat_lockdown:proc
extern secure_zero:proc
extern run_selftest:proc
extern log_result:proc
externdef g_readonly:dword              ; E9: read-only launch flag (owned by gui.asm)
extern do_bench:proc                    ; benchmark (bench.asm)
extern gui_phtest:proc                  ; pw-history capture probe (gui.asm)
extern gui_tmptest:proc                 ; secure temp-file lifecycle probe (gui.asm)
extern fuzzy_score:proc                 ; fuzzy-search scoring (gui.asm)
extern gui_trtest:proc                  ; trash timestamp/threshold probe (gui.asm)
extern cmd_secscan:proc                 ; secret-wipe page-scan probe (secmem.asm)
ifdef DBG_TRACE
extern cmd_securedesk:proc              ; secure-desktop spike (gui.asm)
endif
extern cmd_vfuzz:proc                   ; vault record-parser fuzzer (vault.asm)
extern cmd_zfuzz:proc                   ; zip-import parser fuzzer (zipimport.asm)
extern cmd_bktest:proc                  ; atomic-save + backup rotation probe (vault.asm)
extern cmd_mactest:proc                 ; full-file MAC tamper-detection probe (vault.asm)
extern cmd_rbtest:proc                  ; anti-rollback detection probe (vault.asm)
extern cmd_reload:proc                  ; C8: vault_reload refresh probe (vault.asm)
extern cmd_xctest:proc                  ; external-change detection probe (vault.asm)
extern cmd_mvtest:proc                  ; multi-vault state snapshot/restore probe (vault.asm)
extern cmd_mvswitch:proc                ; multi-vault context switch probe (vault.asm)
extern cmd_avtest:proc                  ; availability retry state-machine probe (vault.asm)
extern cmd_pkat:proc                    ; parallel fail-closed KAT gate (selftest.asm)
extern read_file:proc
ifdef DBG_TRACE
extern cmd_redteam:proc                 ; fault-injection self-test (redteam.asm)
extern cmd_tpmtest:proc                 ; TPM seal/unseal round-trip (tpm.asm)
extern cmd_cttest:proc                  ; ct_memcmp timing probe (hardening.asm)
endif

extern con_init:proc
extern print_a:proc
extern pwgen_ex:proc                    ; styled password generator (pwgen.asm)
extern do_seed:proc                     ; bulk test-vault seeder (vault.asm)
extern print_err:proc
extern vault_unlock:proc
extern vault_reseal:proc
extern mem_free:proc
; --- attachment export/import probes (atgen / zitest) ------------------------
extern do_attgen:proc
extern zi_stage:proc
extern zi_commit:proc
extern write_file:proc
extern ze_compose:proc
extern ze_free:proc
externdef g_zbuf:qword
externdef g_sel:byte

CP_UTF8              equ 65001
WC_ERR_INVALID_CHARS equ 80h

ARGBUF_CHARS         equ 20000h      ; total UTF-16 units for all parsed args
                                    ; (holds two extended-length paths + options)

; -----------------------------------------------------------------------------
; Parsed configuration (single-threaded; statics are simplest and safest here)
; -----------------------------------------------------------------------------
.data
public g_cfg_in, g_cfg_out, g_cfg_passlen, g_cfg_t, g_cfg_m
public g_cfg_pwminlen, g_cfg_pwminclasses
g_argc          dd 0
g_cfg_in        dq 0                ; -> UTF-16 input path  (into g_argbuf)
g_cfg_out       dq 0                ; -> UTF-16 output path (into g_argbuf)
g_cfg_passlen   dd 0                ; UTF-8 password length in bytes
g_cfg_t         dd ARGON2_DEF_T
g_cfg_m         dd ARGON2_DEF_M_KIB
g_cfg_pwminlen      dd 12           ; password policy: min length (code points)
g_cfg_pwminclasses  dd 3            ; password policy: min distinct char classes
public g_cfg_loglevel
g_cfg_loglevel      dd 0            ; log verbosity (0 = none/off by default; see log.asm)
public g_cfg_logfile
g_cfg_logfile       dq 0            ; --log-file PATH override (0 = default path)

; --- modular field list (the GUI composes this; vault_build_entry consumes it) --
; g_field_list[] = up to MAX_FIELDS descriptors of 3 qwords each:
;   { qword type(base kind), qword label-wide ptr (0=none), qword value-wide ptr }
; Sized for the worst committed entry: title + up to MAXROWS-1 non-tile fields +
; up to MAX_TFILES attachment files (the tile expands to one field per file) +
; the reserved favorite/icon markers (see gui_tile_expand).
MAX_FIELDS          equ 56
public g_field_list, g_field_n
g_field_n           dd 0                ; number of composed fields
align 8
g_field_list        dq 3*MAX_FIELDS dup (0)

.data?
public g_cfg_pass, g_positionals, g_poscount
public g_argv
g_argv          dq MAX_ARGS dup (?)
g_argbuf        dw ARGBUF_CHARS dup (?)
g_gen_buf       db 160 dup (?)           ; genpw: sample output buffer
g_cfg_pass      db MAX_PASSWORD_BYTES+1 dup (?)
g_positionals   dq MAX_ARGS dup (?)  ; -> UTF-16 positional argument strings
g_poscount      dq ?                 ; number of positionals

; -----------------------------------------------------------------------------
.const
msg_usage label byte
    db "Vordr - hardened password manager (AES-256-GCM vault, Argon2id KDF)",13,10
    db 13,10
    db "  Vordr is a GUI application.  The vault, entry secrets, and the password",13,10
    db "  generator are reached only through the windowed interface, so no master",13,10
    db "  password or secret is ever passed on the command line (where it would",13,10
    db "  leak into shell history and process listings).  Launch vordr with no",13,10
    db "  arguments to open it.",13,10
    db 13,10
    db "  The command line exposes only non-sensitive diagnostics:",13,10
    db "    vordr selftest             run all known-answer self-tests",13,10
    db "    vordr bench [-m MIB] [-t N] benchmark the crypto core",13,10
    db 13,10
    db "  Every launch runs the self-test gate first and fails closed on mismatch.",13,10
msg_usage_len equ $ - msg_usage
CSTR msg_nocpu,    "error: CPU lacks required features (AES-NI, PCLMULQDQ, SSE4.1)",13,10
CSTR msg_badnum,   "error: numeric argument out of range",13,10
CSTR msg_st_ok,    "all self-tests passed",13,10
CSTR msg_st_fail,  "SELFTEST FAILURE",13,10
gl_rand   db "  random     : "
gl_rand_len   equ $ - gl_rand
gl_phrase db "  passphrase : "
gl_phrase_len equ $ - gl_phrase
gl_pron   db "  pronounce  : "
gl_pron_len   equ $ - gl_pron
gl_pin    db "  pin        : "
gl_pin_len    equ $ - gl_pin
gl_hex    db "  hex        : "
gl_hex_len    equ $ - gl_hex
gp_crlf   db 13,10
CSTR msg_seed_ok, "seeded 5000 realistic test entries.  unlock the vault with password: vordrtest",13,10
seed_pw   db "vordrtest", 0
align 2                                   ; keep the verb-name WSTRs even-aligned

WSTR w_selftest, <selftest>
WSTR w_bench,    <bench>
WSTR w_genpw,    <genpw>
WSTR w_seedtest, <seedtest>
WSTR w_atgen,    <atgen>
WSTR w_zitest,   <zitest>
WSTR w_phtest,   <phtest>
WSTR w_secscan,  <secscan>
WSTR w_tmptest,  <tmptest>
WSTR w_fztest,   <fztest>
WSTR w_vfuzz,    <vfuzz>
WSTR w_fuzzzip,  <fuzzzip>
WSTR w_bktest,   <bktest>
WSTR w_mactest,  <mactest>
WSTR w_rbtest,   <rbtest>
WSTR w_xctest,   <xctest>
WSTR w_ro,       <--ro>                  ; E9: GUI read-only launch flag (not a verb)
WSTR w_reload,   <reload>                ; C8: vault_reload refresh probe
WSTR w_pkat,     <pkat>
WSTR w_trtest,   <trtest>
WSTR w_mvtest,   <mvtest>
WSTR w_mvswitch, <mvswitch>
WSTR w_avtest,   <avtest>
ifdef DBG_TRACE
WSTR w_securedesk, <securedesk>
endif
WSTR wpw_exp,    <VordrExp1234>
ifdef DBG_TRACE
WSTR w_redteam,  <redteam>
WSTR w_tpmtest,  <tpmtest>
WSTR w_cttest,   <cttest>
WSTR w_crashme,  <crashme>
endif
WSTR w_opt_m,    <-m>
WSTR w_opt_t,    <-t>
WSTR w_opt_log,        <--log>
WSTR w_opt_logfile,    <--log-file>
WSTR w_lvl_none,       <none>
WSTR w_lvl_error,      <error>
WSTR w_lvl_warning,    <warning>
WSTR w_lvl_full,       <full>
WSTR w_lvl_debug,      <debug>

; command table: UTF-16 name ptr | handler ptr | required positional args
CMDENT struct
    name_ptr    dq ?
    handler     dq ?
    pos_args    dd ?                ; positional (non-option) args after command
    needs_pass  dd ?                ; 1 if -p is mandatory
CMDENT ends

; The CLI exposes only non-sensitive diagnostics: no positionals, no secrets.
; All vault / secret / generator operations live in the GUI.
cmd_table label CMDENT
    CMDENT { w_selftest,  cmd_selftest,  0, 0 }
    CMDENT { w_bench,     cmd_bench,     0, 0 }
    CMDENT { w_genpw,     cmd_genpw,     0, 0 }   ; print one sample of each generator style
    CMDENT { w_seedtest,  cmd_seedtest,  1, 0 }   ; bulk-fill a test vault with 5000 entries
    CMDENT { w_atgen,     cmd_atgen,     1, 0 }   ; headless attachment-export probe: <out.zip>
    CMDENT { w_zitest,    cmd_zitest,    2, 0 }   ; headless encrypted-zip import probe
    CMDENT { w_phtest,    cmd_phtest,    0, 0 }   ; headless pw-history capture probe
    CMDENT { w_secscan,   cmd_secscan,   0, 0 }   ; secret-wipe page-scan probe
    CMDENT { w_tmptest,   cmd_tmptest,   0, 0 }   ; secure temp-file lifecycle probe
    CMDENT { w_fztest,    cmd_fztest,    0, 0 }   ; fuzzy-search scoring KAT
    CMDENT { w_vfuzz,     cmd_vfuzz,     0, 0 }   ; vault record-parser structural fuzzer
    CMDENT { w_fuzzzip,   cmd_zfuzz,     0, 0 }   ; zip-import parser structural fuzzer
    CMDENT { w_bktest,    cmd_bktest,    1, 0 }   ; atomic-save + backup-rotation probe
    CMDENT { w_mactest,   cmd_mactest,   1, 0 }   ; full-file MAC tamper-detection probe
    CMDENT { w_rbtest,    cmd_rbtest,    1, 0 }   ; anti-rollback detection probe
    CMDENT { w_xctest,    cmd_xctest,    1, 0 }   ; external-change detection probe
    CMDENT { w_reload,    cmd_reload,    1, 0 }   ; C8: vault_reload refresh probe
    CMDENT { w_mvtest,    cmd_mvtest,    0, 0 }   ; multi-vault snapshot/restore probe
    CMDENT { w_mvswitch,  cmd_mvswitch,  0, 0 }   ; multi-vault context switch probe
    CMDENT { w_avtest,    cmd_avtest,    0, 0 }   ; availability retry state-machine probe
    CMDENT { w_pkat,      cmd_pkat,      0, 0 }   ; parallel fail-closed KAT gate
    CMDENT { w_trtest,    cmd_trtest,    0, 0 }   ; trash timestamp/threshold KAT
ifdef DBG_TRACE
    CMDENT { w_securedesk, cmd_securedesk, 0, 0 } ; private-desktop spike dialog (dbg)
    CMDENT { w_redteam,   cmd_redteam,   1, 0 }   ; fault-injection self-test (dbg)
    CMDENT { w_tpmtest,   cmd_tpmtest,   0, 0 }   ; TPM round-trip probe (dbg)
    CMDENT { w_cttest,    cmd_cttest,    0, 0 }   ; ct_memcmp timing probe (dbg)
    CMDENT { w_crashme,   cmd_crashme,   0, 0 }   ; deliberate AV -> crash-containment (dbg)
endif
; Derive the count from the table's actual size so adding a CMDENT never needs a
; manual bump (a stale count silently drops trailing verbs to GUI fall-through).
CMD_COUNT equ ($ - cmd_table) / (sizeof CMDENT)

.data?
ifdef DBG_TRACE
dbg_char    db ?
dbg_written dd ?
endif

.code

ifdef DBG_TRACE
; al = character to print; clobbers volatiles only
dbg_putc proc
    mov     byte ptr [dbg_char], al
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    WINCALL GetStdHandle, STD_OUTPUT_HANDLE_
    WINCALL WriteFile, rax, addr dbg_char, 1, addr dbg_written, 0
    mov     rsp, rbp
    pop     rbp
    ret
dbg_putc endp
endif

; =============================================================================
; ff_trap - central fail handler.  ecx = fail code (FF_*).  Never returns.
; Release build: immediate __fastfail (int 29h) - non-catchable termination.
; Debug build  : prints "FF" + 4 hex digits of the code so a fault can be
;                attributed to the exact check that fired, then exits.
; =============================================================================
public ff_trap
ff_trap proc
ifdef DBG_TRACE
    mov     r15d, ecx                   ; preserve code (r15 nonvolatile, unused)
    and     rsp, -16                    ; realign (we never return from here)
    mov     al, 'F'
    call    dbg_putc
    mov     al, 'F'
    call    dbg_putc
    mov     ecx, 12                     ; print 4 nibbles, high to low
ff_hexloop:
    sub     ecx, 4
    mov     eax, r15d
    shr     eax, cl
    and     eax, 0Fh
    cmp     al, 10
    jb      ff_dec
    add     al, 'a' - 10
    jmp     ff_emit
ff_dec:
    add     al, '0'
ff_emit:
    push    rcx
    call    dbg_putc
    pop     rcx
    test    ecx, ecx
    jnz     ff_hexloop
    mov     al, 13
    call    dbg_putc
    mov     al, 10
    call    dbg_putc
    ; encode the FF code into the exit status so a test harness can attribute the
    ; fault even when stdout is redirected away by AttachConsole (0xFADE<code>).
    mov     eax, r15d
    or      eax, 0FADE0000h
    WINCALL ExitProcess, eax
endif
    int     29h                         ; release: real fast-fail
ff_trap endp

; =============================================================================
; cpu_gate - detect required/optional CPU features into g_cpu_features.
; Raw frame (runs before hardening_init).  Returns eax=1 if required set ok.
; Required: AES-NI, PCLMULQDQ, SSE4.1.  Optional: SHA-NI, AVX2, RDSEED.
; =============================================================================
cpu_gate proc frame
    push    rbx                         ; cpuid clobbers rbx (non-volatile)
    .pushreg rbx
    .endprolog
    xor     r10d, r10d                  ; feature accumulator

    xor     eax, eax                    ; leaf 0: highest supported leaf
    xor     ecx, ecx
    cpuid
    mov     r9d, eax                    ; r9d = max leaf

    mov     eax, 1
    xor     ecx, ecx
    cpuid
    test    ecx, 1 SHL 25               ; AES-NI
    jz      @F
    or      r10d, CPUF_AESNI
@@: test    ecx, 1 SHL 1                ; PCLMULQDQ
    jz      @F
    or      r10d, CPUF_PCLMUL
@@: test    ecx, 1 SHL 19               ; SSE4.1
    jz      @F
    or      r10d, CPUF_SSE41
@@:
    cmp     r9d, 7                      ; leaf 7 may not exist on old CPUs
    jb      cg_store
    mov     eax, 7
    xor     ecx, ecx
    cpuid
    test    ebx, 1 SHL 29               ; SHA-NI
    jz      @F
    or      r10d, CPUF_SHANI
@@: test    ebx, 1 SHL 5                ; AVX2
    jz      @F
    or      r10d, CPUF_AVX2
@@: test    ebx, 1 SHL 18               ; RDSEED
    jz      @F
    or      r10d, CPUF_RDSEED
@@:
cg_store:
    mov     dword ptr [g_cpu_features], r10d
    mov     eax, r10d
    ; sha256.asm uses the SHA-NI instructions unconditionally, so a CPU with
    ; AES-NI but no SHA-NI (Skylake-class) must be refused here, not #UD later
    and     eax, CPUF_AESNI or CPUF_PCLMUL or CPUF_SSE41 or CPUF_SHANI
    cmp     eax, CPUF_AESNI or CPUF_PCLMUL or CPUF_SSE41 or CPUF_SHANI
    sete    al
    movzx   eax, al
    pop     rbx
    ret
cpu_gate endp

; =============================================================================
; wstr_eq(rcx, rdx) -> eax = 1 if equal NUL-terminated UTF-16 strings
; =============================================================================
public wstr_eq
wstr_eq proc
    xor     r10d, r10d
we_loop:
    movzx   eax, word ptr [rcx+r10*2]
    movzx   r11d, word ptr [rdx+r10*2]
    cmp     eax, r11d
    jne     we_no
    test    eax, eax
    jz      we_yes
    inc     r10
    cmp     r10, MAX_PATH_CHARS         ; bound the scan
    jb      we_loop
we_no:
    xor     eax, eax
    ret
we_yes:
    mov     eax, 1
    ret
wstr_eq endp

; =============================================================================
; parse_loglevel(rcx = wide LEVEL) -> eax = level 0..4, or -1 if unrecognized.
; none=0 error=1 warning=2 full=3 debug=4
; =============================================================================
parse_loglevel proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [w_lvl_none]
    call    wstr_eq
    test    eax, eax
    jnz     pl_0
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [w_lvl_error]
    call    wstr_eq
    test    eax, eax
    jnz     pl_1
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [w_lvl_warning]
    call    wstr_eq
    test    eax, eax
    jnz     pl_2
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [w_lvl_full]
    call    wstr_eq
    test    eax, eax
    jnz     pl_3
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [w_lvl_debug]
    call    wstr_eq
    test    eax, eax
    jnz     pl_4
    mov     eax, -1
    jmp     pl_done
pl_0:
    xor     eax, eax
    jmp     pl_done
pl_1:
    mov     eax, 1
    jmp     pl_done
pl_2:
    mov     eax, 2
    jmp     pl_done
pl_3:
    mov     eax, 3
    jmp     pl_done
pl_4:
    mov     eax, 4
pl_done:
    FRAME_EPILOG
    ret
parse_loglevel endp

; =============================================================================
; wstr_to_u32(rcx) -> eax = value, edx = 1 ok / 0 bad
; Decimal only, overflow-checked, rejects empty and non-digits.
; =============================================================================
wstr_to_u32 proc
    xor     eax, eax                    ; value
    xor     r10d, r10d                  ; index
    movzx   r11d, word ptr [rcx]
    test    r11d, r11d
    jz      wu_bad                      ; empty string
wu_loop:
    movzx   r11d, word ptr [rcx+r10*2]
    test    r11d, r11d
    jz      wu_ok
    sub     r11d, '0'
    cmp     r11d, 9
    ja      wu_bad                      ; non-digit
    imul    rax, rax, 10                ; 64-bit math, then range check
    add     rax, r11
    mov     rdx, rax
    shr     rdx, 32
    jnz     wu_bad                      ; exceeded 32 bits
    inc     r10
    cmp     r10, 12
    jb      wu_loop
wu_bad:
    xor     eax, eax
    xor     edx, edx
    ret
wu_ok:
    mov     edx, 1
    ret
wstr_to_u32 endp

; =============================================================================
; parse_cmdline - tokenize GetCommandLineW into g_argv/g_argc using the
; standard Windows quoting rules (incl. backslash-quote and "" handling).
; Every write into g_argbuf is bounds-checked.  Returns nothing; overlong
; input fastfails (it cannot occur from a legitimate shell).
; =============================================================================
public parse_cmdline
parse_cmdline proc frame
    FRAME_PROLOG 48
    ; locals: [rbp-24] = cursor (source), using regs:
    ;   rsi-like roles via r8 = src cursor, r9 = dst index (units),
    ;   r10 = scratch, r11d = in-quotes flag, rbx avoided (volatile only)

    WINCALL GetCommandLineW
    mov     r8, rax                     ; r8 = source cursor
    xor     r9d, r9d                    ; r9 = output index into g_argbuf
    mov     dword ptr [g_argc], 0

    ; ---- program name = argv[0] (simplified rule: only '"' toggles) ----------
    ; We STORE it so the rest of the program can use C-style indexing:
    ; argv[0]=exe, argv[1]=command, argv[2..]=positional/option args.
    lea     r10, [g_argbuf]
    lea     r11, [g_argv]
    mov     qword ptr [r11], r10        ; argv[0] -> start of buffer
    mov     dword ptr [g_argc], 1
    movzx   eax, word ptr [r8]
    cmp     eax, '"'
    jne     pc_prog_plain
    add     r8, 2                       ; consume opening quote
pc_prog_q:
    movzx   eax, word ptr [r8]
    test    eax, eax
    jz      pc_prog_term
    add     r8, 2
    cmp     eax, '"'
    je      pc_prog_term                ; closing quote consumed
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], ax
    inc     r9
    jmp     pc_prog_q
pc_prog_plain:
    movzx   eax, word ptr [r8]
    test    eax, eax
    jz      pc_prog_term
    cmp     eax, ' '
    je      pc_prog_term
    cmp     eax, 9                      ; tab
    je      pc_prog_term
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], ax
    inc     r9
    add     r8, 2
    jmp     pc_prog_plain
pc_prog_term:
    BOUND_CHECK r9, ARGBUF_CHARS
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], 0      ; NUL-terminate argv[0]
    inc     r9

pc_args_start:
    ; ---- token loop ---------------------------------------------------------
pc_next_token:
    ; skip whitespace
pc_skip_ws:
    movzx   eax, word ptr [r8]
    test    eax, eax
    jz      pc_done
    cmp     eax, ' '
    je      pc_ws
    cmp     eax, 9
    jne     pc_token_begin
pc_ws:
    add     r8, 2
    jmp     pc_skip_ws

pc_token_begin:
    ; register the token start in g_argv
    mov     eax, dword ptr [g_argc]
    cmp     eax, MAX_ARGS               ; arg table full?
    jae     pc_done                     ; yes - ignore any remaining tokens
    lea     r10, [g_argbuf]
    lea     r10, [r10+r9*2]
    lea     r11, [g_argv]
    mov     qword ptr [r11+rax*8], r10
    inc     eax
    mov     dword ptr [g_argc], eax
    xor     r11d, r11d                  ; in-quotes = 0

pc_char:
    movzx   eax, word ptr [r8]
    test    eax, eax
    jz      pc_token_end
    cmp     eax, '\'
    je      pc_backslashes
    cmp     eax, '"'
    je      pc_quote
    ; whitespace ends the token only when not inside quotes
    test    r11d, r11d
    jnz     pc_emit
    cmp     eax, ' '
    je      pc_token_end
    cmp     eax, 9
    je      pc_token_end
pc_emit:
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], ax
    inc     r9
    add     r8, 2
    jmp     pc_char

pc_backslashes:
    ; count consecutive backslashes
    xor     edx, edx                    ; count
pc_bs_count:
    movzx   eax, word ptr [r8]
    cmp     eax, '\'
    jne     pc_bs_decide
    inc     edx
    add     r8, 2
    jmp     pc_bs_count
pc_bs_decide:
    cmp     eax, '"'
    je      pc_bs_quote
    ; not followed by quote: emit all backslashes literally
pc_bs_emit_all:
    test    edx, edx
    jz      pc_char
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], '\'
    inc     r9
    dec     edx
    jmp     pc_bs_emit_all
pc_bs_quote:
    ; 2n -> n backslashes, quote is delimiter; 2n+1 -> n backslashes + literal "
    mov     eax, edx
    shr     eax, 1                      ; n = count/2
pc_bs_emit_half:
    test    eax, eax
    jz      pc_bs_half_done
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], '\'
    inc     r9
    dec     eax
    jmp     pc_bs_emit_half
pc_bs_half_done:
    test    edx, 1
    jz      pc_char                     ; even: leave quote for pc_quote
    ; odd: consume the quote as a literal character
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], '"'
    inc     r9
    add     r8, 2                       ; consume the quote
    jmp     pc_char

pc_quote:
    add     r8, 2                       ; consume quote
    test    r11d, r11d
    jz      pc_quote_open
    ; closing quote - check for "" (literal quote) rule
    movzx   eax, word ptr [r8]
    cmp     eax, '"'
    jne     pc_quote_close
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], '"'
    inc     r9
    add     r8, 2
    jmp     pc_char
pc_quote_open:
    mov     r11d, 1
    jmp     pc_char
pc_quote_close:
    xor     r11d, r11d
    jmp     pc_char

pc_token_end:
    ; NUL-terminate the token
    BOUND_CHECK r9, ARGBUF_CHARS
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], 0
    inc     r9
    movzx   eax, word ptr [r8]
    test    eax, eax
    jnz     pc_next_token
pc_done:
    FRAME_EPILOG
    ret
parse_cmdline endp

; OPTMATCH wopt, takelabel - if argv[[rbp-32]] equals wopt, jump to takelabel.
; (Same shape as the hand-written matches above; used for the newer options.)
OPTMATCH macro wopt, takelabel
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [wopt]
    call    wstr_eq
    test    eax, eax
    jnz     takelabel
endm

; =============================================================================
; collect_options - walk g_argv[2..] for the active command.
;   rcx -> CMDENT for the command
; Only -m/-t (Argon2 cost for bench) and --log/--log-file are accepted.
; Returns eax = exit code (EXIT_OK if all good).
; =============================================================================
collect_options proc frame
    FRAME_PROLOG 64
    ; locals: [rbp-24] CMDENT ptr, [rbp-32] arg index, [rbp-40] positional count
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], 2       ; argv[0]=exe, argv[1]=command
    mov     qword ptr [rbp-40], 0
co_loop:
    mov     rax, qword ptr [rbp-32]
    mov     r10d, dword ptr [g_argc]
    cmp     rax, r10
    jae     co_check
    OPTMATCH w_opt_m,       co_take_m
    OPTMATCH w_opt_t,       co_take_t
    OPTMATCH w_opt_log,     co_take_log
    OPTMATCH w_opt_logfile, co_take_logfile
    ; any other token is a positional (only the dbg `redteam` case name uses one)
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    mov     rdx, qword ptr [rbp-40]
    BOUND_CHECK rdx, MAX_ARGS
    lea     r11, [g_positionals]
    mov     qword ptr [r11+rdx*8], rcx
    inc     qword ptr [rbp-40]
    inc     qword ptr [rbp-32]
    jmp     co_loop
co_take_m:
    call    co_next_arg
    test    rax, rax
    jz      co_usage
    mov     rcx, rax
    call    wstr_to_u32
    test    edx, edx
    jz      co_badnum
    cmp     eax, 8
    jb      co_badnum
    cmp     eax, 4096
    ja      co_badnum
    shl     eax, 10                     ; MiB -> KiB
    mov     dword ptr [g_cfg_m], eax
    jmp     co_loop
co_take_t:
    call    co_next_arg
    test    rax, rax
    jz      co_usage
    mov     rcx, rax
    call    wstr_to_u32
    test    edx, edx
    jz      co_badnum
    cmp     eax, ARGON2_MIN_T
    jb      co_badnum
    cmp     eax, ARGON2_MAX_T
    ja      co_badnum
    mov     dword ptr [g_cfg_t], eax
    jmp     co_loop
co_take_log:
    call    co_next_arg
    test    rax, rax
    jz      co_usage
    mov     rcx, rax
    call    parse_loglevel
    cmp     eax, -1
    je      co_usage
    mov     dword ptr [g_cfg_loglevel], eax
    jmp     co_loop
co_take_logfile:
    call    co_next_arg
    test    rax, rax
    jz      co_usage
    mov     qword ptr [g_cfg_logfile], rax
    jmp     co_loop
co_check:
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [g_poscount], rax
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [r10].CMDENT.pos_args
    cmp     qword ptr [rbp-40], rax     ; exact positional count must match
    jne     co_usage
    cmp     qword ptr [rbp-40], 0
    je      co_ok
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+0]
    mov     qword ptr [g_cfg_in], rcx
co_ok:
    mov     eax, EXIT_OK
    jmp     co_done
co_usage:
    lea     rcx, [msg_usage]
    mov     edx, msg_usage_len
    call    print_err
    mov     eax, EXIT_USAGE
    jmp     co_done
co_badnum:
    lea     rcx, [msg_badnum]
    mov     edx, msg_badnum_len
    call    print_err
    mov     eax, EXIT_USAGE
co_done:
    FRAME_EPILOG
    ret

; -- helper: advance to next arg, return its ptr in rax (0 if none) ----------
co_next_arg:
    inc     qword ptr [rbp-32]          ; skip the option itself
    mov     rax, qword ptr [rbp-32]
    mov     r10d, dword ptr [g_argc]
    cmp     rax, r10
    jae     cna_none
    lea     r11, [g_argv]
    mov     rax, qword ptr [r11+rax*8]
    inc     qword ptr [rbp-32]          ; consume the value
    ret
cna_none:
    xor     eax, eax
    ret
collect_options endp

; =============================================================================
; password_to_utf8(rcx = wide password ptr) -> eax = 1 ok / 0 invalid
; Strict conversion (rejects invalid UTF-16), enforces 1..1024 bytes,
; then wipes the wide original at the source (also used by the GUI password box).
; =============================================================================
public password_to_utf8
password_to_utf8 proc frame
    FRAME_PROLOG 32 + 32 + 16
    ; locals: [rbp-24] = wide ptr
    mov     qword ptr [rbp-24], rcx

    ; WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, src, -1,
    ;                     g_cfg_pass, MAX+1, NULL, NULL)
    WINCALL WideCharToMultiByte, CP_UTF8, WC_ERR_INVALID_CHARS, rcx, -1, addr g_cfg_pass, MAX_PASSWORD_BYTES+1, 0, 0
    test    eax, eax
    jz      p2u_bad                     ; invalid UTF-16 or too long
    dec     eax                         ; exclude NUL
    cmp     eax, MIN_PASSWORD_BYTES
    jb      p2u_bad
    cmp     eax, MAX_PASSWORD_BYTES
    ja      p2u_bad
    mov     dword ptr [g_cfg_passlen], eax

    ; ---- wipe the wide password copy in g_argbuf ----------------------------
    mov     rcx, qword ptr [rbp-24]
    xor     edx, edx
p2u_measure:
    cmp     word ptr [rcx+rdx*2], 0
    je      p2u_wipe
    inc     edx
    cmp     edx, ARGBUF_CHARS
    jb      p2u_measure
p2u_wipe:
    shl     edx, 1                      ; chars -> bytes
    call    secure_zero                 ; rcx = ptr, rdx = bytes
    mov     eax, 1
    jmp     p2u_done
p2u_bad:
    ; wipe whatever partial conversion landed in the buffer
    lea     rcx, [g_cfg_pass]
    mov     edx, MAX_PASSWORD_BYTES+1
    call    secure_zero
    xor     eax, eax
p2u_done:
    FRAME_EPILOG
    ret
password_to_utf8 endp

; =============================================================================
; Command handlers.  Each is a DLPV landing-pad target reached through the
; CALL_GUARDED dispatch - thin wrappers over the implementation modules.
; =============================================================================
; --- diagnostics command handlers (DLPV landing-pad targets) ----------------
LANDING_PAD
cmd_bench proc frame
    FRAME_PROLOG 32
    call    do_bench
    FRAME_EPILOG
    ret
cmd_bench endp


LANDING_PAD
cmd_selftest proc frame
    FRAME_PROLOG 32
    mov     ecx, 1                      ; verbose: print the full report
    call    run_selftest
    test    eax, eax
    jz      cst_ok
    lea     rcx, [msg_st_fail]
    mov     edx, msg_st_fail_len
    call    print_a
    mov     eax, EXIT_SELFTEST
    FRAME_EPILOG
    ret
cst_ok:
    lea     rcx, [msg_st_ok]
    mov     edx, msg_st_ok_len
    call    print_a
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
cmd_selftest endp

; gp_println - print g_gen_buf (NUL-terminated, <160) then CRLF.  Internal.
gp_println proc frame
    FRAME_PROLOG 32
    lea     r10, [g_gen_buf]
    xor     ecx, ecx
gpl_len:
    cmp     byte ptr [r10+rcx], 0
    je      gpl_go
    inc     ecx
    cmp     ecx, 159
    jb      gpl_len
gpl_go:
    WINCALL print_a, addr g_gen_buf, ecx
    WINCALL print_a, addr gp_crlf, 2
    FRAME_EPILOG
    ret
gp_println endp

; cmd_genpw - print one sample of each generator style (visual smoke test).
;   Non-sensitive: fresh random samples, never a stored secret.
LANDING_PAD
cmd_genpw proc frame
    FRAME_PROLOG 48
    WINCALL print_a, addr gl_rand, gl_rand_len
    lea     rcx, [g_gen_buf]
    mov     edx, 20
    mov     r8d, PWS_RANDOM
    mov     r9d, 15 or PWO_NOAMBIG
    call    pwgen_ex
    call    gp_println
    WINCALL print_a, addr gl_phrase, gl_phrase_len
    lea     rcx, [g_gen_buf]
    mov     edx, 5
    mov     r8d, PWS_PASSPHRASE
    mov     r9d, PWO_CAP or PWO_DASH or PWO_DIGIT
    call    pwgen_ex
    call    gp_println
    WINCALL print_a, addr gl_pron, gl_pron_len
    lea     rcx, [g_gen_buf]
    mov     edx, 14
    mov     r8d, PWS_PRONOUNCE
    mov     r9d, PWO_CAP or PWO_DIGIT
    call    pwgen_ex
    call    gp_println
    WINCALL print_a, addr gl_pin, gl_pin_len
    lea     rcx, [g_gen_buf]
    mov     edx, 8
    mov     r8d, PWS_PIN
    xor     r9d, r9d
    call    pwgen_ex
    call    gp_println
    WINCALL print_a, addr gl_hex, gl_hex_len
    lea     rcx, [g_gen_buf]
    mov     edx, 24
    mov     r8d, PWS_HEX
    xor     r9d, r9d
    call    pwgen_ex
    call    gp_println
    xor     eax, eax
    FRAME_EPILOG
    ret
cmd_genpw endp

; cmd_seedtest - create a fresh vault at argv[2] with 5000 realistic entries
;   (perf/search testing), unlockable with the fixed test password "vordrtest".
LANDING_PAD
cmd_seedtest proc frame
    FRAME_PROLOG 48
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]           ; argv[2] = vault path
    mov     qword ptr [g_cfg_in], rax
    lea     r10, [seed_pw]                     ; fixed test password
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
cst_cp:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      cst_cpd
    inc     ecx
    cmp     ecx, 32
    jb      cst_cp
cst_cpd:
    mov     dword ptr [g_cfg_passlen], 9
    mov     ecx, 5000
    call    do_seed
    mov     dword ptr [rbp-24], eax
    test    eax, eax
    jnz     cst_fail
    WINCALL print_a, addr msg_seed_ok, msg_seed_ok_len
    xor     eax, eax
    FRAME_EPILOG
    ret
cst_fail:
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
cmd_seedtest endp

; cmd_atgen - headless attachment-export probe.  Build an in-memory vault with a
;   single entry carrying one staged attachment, JSON-export it WITH attachments
;   into the AES-256 ZIP, and write the archive to argv[2].  exit 0 = OK.  Pairs
;   with a Python check that the zip contains both vordr.json and the attachment.
LANDING_PAD
cmd_atgen proc frame
    FRAME_PROLOG 48
    call    do_attgen
    test    eax, eax
    jnz     atg_fail
    lea     r10, [g_sel]                         ; select the one entry for export
    mov     byte ptr [r10], 1
    lea     rcx, [wpw_exp]
    mov     edx, 24                              ; "VordrExp1234" = 12 chars * 2
    call    ze_compose
    test    eax, eax                             ; 0 = zip in g_zbuf
    jnz     atg_fail
    lea     r10, [g_argv]
    mov     rcx, qword ptr [r10+16]              ; argv[2] = out path
    lea     r11, [g_zbuf]
    mov     rdx, qword ptr [r11]
    mov     r8, qword ptr [r11+8]
    call    write_file
    mov     dword ptr [rbp-24], eax
    call    ze_free
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
atg_fail:
    call    ze_free
    mov     eax, 0E0CDh
    FRAME_EPILOG
    ret
cmd_atgen endp

; cmd_zitest - headless encrypted-zip import probe.  Unlock the vault at argv[2]
;   with the fixed test password, import the Vordr .zip at argv[3] using the fixed
;   export test password, reseal.  exit = entries imported (or 0xE0xx on error).
LANDING_PAD
cmd_zitest proc frame
    FRAME_PROLOG 128
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [g_cfg_in], rax
    lea     r10, [seed_pw]
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
zit_cp:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      zit_cpd
    inc     ecx
    cmp     ecx, 32
    jb      zit_cp
zit_cpd:
    mov     dword ptr [g_cfg_passlen], 9
    call    vault_unlock
    test    eax, eax
    jnz     zit_fail
    lea     r10, [g_argv]
    mov     rcx, qword ptr [r10+24]              ; argv[3] = zip path
    lea     rdx, [rbp-24]                        ; *raw
    lea     r8, [rbp-32]                         ; *rawlen
    call    read_file
    test    eax, eax
    jnz     zit_fail
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    lea     r8, [wpw_exp]                        ; UTF-16 export password
    mov     r9d, 24                              ; "VordrExp1234" = 12 chars * 2
    call    zi_stage                            ; -> eax = staged count / <0 error
    mov     dword ptr [rbp-40], eax
    cmp     eax, 0
    jl      zit_freeraw                         ; error: zi_stage already freed the arena
    lea     r10, [g_sel]                        ; headless probe: import every staged entry
    xor     r8d, r8d
zit_sel:
    cmp     r8d, dword ptr [rbp-40]
    jae     zit_seld
    cmp     r8d, 8192
    jae     zit_seld
    mov     byte ptr [r10+r8], 1
    inc     r8d
    jmp     zit_sel
zit_seld:
    call    zi_commit                           ; imports selected, frees the arena
    mov     dword ptr [rbp-40], eax
zit_freeraw:
    mov     rcx, qword ptr [rbp-24]              ; free the raw zip
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
    call    vault_reseal
    mov     eax, dword ptr [rbp-40]
    FRAME_EPILOG
    ret
zit_fail:
    mov     eax, 0E0CEh
    FRAME_EPILOG
    ret
cmd_zitest endp

; cmd_phtest - headless password-history capture probe.  exit = g_pwhist_n after a
;   synthetic overwrite (1 = capture works, 0 = broken).
LANDING_PAD
cmd_phtest proc frame
    FRAME_PROLOG 32
    call    gui_phtest
    FRAME_EPILOG
    ret
cmd_phtest endp

; cmd_tmptest - headless secure-temp-file lifecycle probe.  exit 0 = pass
;   (a tracked %TEMP% file was overwritten + deleted by gui_temp_purge).
LANDING_PAD
cmd_tmptest proc frame
    FRAME_PROLOG 32
    call    gui_tmptest
    FRAME_EPILOG
    ret
cmd_tmptest endp

; fuzzy_score KAT strings (upper-cased, since fuzzy_score assumes pre-folded input)
WSTR fz_gm,        <GM>
WSTR fz_gmail,     <GMAIL>
WSTR fz_gmwk,      <GMWK>
WSTR fz_gmailwork, <GMAIL WORK>
WSTR fz_agmb,      <AGMB>
WSTR fz_empty,     <>
WSTR fz_any,       <ANYTHING>
WSTR fz_workgmail, <WORK GMAIL ACCOUNT>
WSTR fz_gmailwrk,  <GMAIL WRK>
WSTR fz_zz,        <ZZ>
CSTR fzt_ok,   "fztest: PASS (fuzzy scoring + ranking)",13,10
CSTR fzt_bad,  "fztest: FAIL",13,10

; cmd_fztest - fuzzy-search scoring known-answer test.  exit 0 = pass.
;   [rbp-24] holds score(GM,GMAIL) while the ordering comparison runs.
LANDING_PAD
cmd_fztest proc frame
    FRAME_PROLOG 32
    lea     rcx, [fz_gm]                    ; match: "GM" in "GMAIL"
    lea     rdx, [fz_gmail]
    call    fuzzy_score
    test    eax, eax
    js      fzt_fail
    lea     rcx, [fz_gmwk]                  ; nomatch: "GMWK" (no W in "GMAIL")
    lea     rdx, [fz_gmail]
    call    fuzzy_score
    test    eax, eax
    jns     fzt_fail
    lea     rcx, [fz_gmwk]                  ; match: "GMWK" in "GMAIL WORK"
    lea     rdx, [fz_gmailwork]
    call    fuzzy_score
    test    eax, eax
    js      fzt_fail
    lea     rcx, [fz_empty]                 ; empty needle matches anything (score 0)
    lea     rdx, [fz_any]
    call    fuzzy_score
    test    eax, eax
    js      fzt_fail
    lea     rcx, [fz_gmailwrk]              ; nomatch: term "WRK" absent from "GMAIL"
    lea     rdx, [fz_gmail]
    call    fuzzy_score
    test    eax, eax
    jns     fzt_fail
    lea     rcx, [fz_gmailwrk]              ; match: both terms in "WORK GMAIL ACCOUNT"
    lea     rdx, [fz_workgmail]
    call    fuzzy_score
    test    eax, eax
    js      fzt_fail
    lea     rcx, [fz_zz]                    ; nomatch: "ZZ" absent
    lea     rdx, [fz_gmail]
    call    fuzzy_score
    test    eax, eax
    jns     fzt_fail
    lea     rcx, [fz_gm]                    ; ordering: word-start+contiguous beats mid-word
    lea     rdx, [fz_gmail]
    call    fuzzy_score
    mov     dword ptr [rbp-24], eax         ; score(GM,GMAIL)
    lea     rcx, [fz_gm]
    lea     rdx, [fz_agmb]
    call    fuzzy_score                     ; score(GM,AGMB)
    cmp     dword ptr [rbp-24], eax
    jle     fzt_fail                        ; GMAIL must rank strictly higher
    lea     rcx, [fzt_ok]
    mov     edx, fzt_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
fzt_fail:
    lea     rcx, [fzt_bad]
    mov     edx, fzt_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_fztest endp

ifdef DBG_TRACE
; cmd_crashme - deliberately fault to exercise crash containment.  It
;   plants a sentinel into the master-password buffer, then writes through a null
;   pointer.  The unhandled exception must reach crash_filter, which wipes every
;   secret (secmem_panic_wipe) and terminates with no WER dump.  Never returns.
LANDING_PAD
cmd_crashme proc frame
    FRAME_PROLOG 32
    lea     r10, [g_cfg_pass]                   ; plant a recognizable secret
    mov     byte ptr [r10+0], 'S'
    mov     byte ptr [r10+1], 'E'
    mov     byte ptr [r10+2], 'C'
    mov     dword ptr [g_cfg_passlen], 3
    xor     rax, rax                            ; deliberate null-pointer write -> AV
    mov     byte ptr [rax], 0
    xor     eax, eax                            ; unreachable
    FRAME_EPILOG
    ret
cmd_crashme endp
endif

CSTR trt_ok,   "trtest: PASS (trash timestamp + 30-day purge threshold)",13,10
CSTR trt_bad,  "trtest: FAIL",13,10

; cmd_trtest - trash timestamp encode/decode + purge-threshold KAT.  exit 0 = pass.
LANDING_PAD
cmd_trtest proc frame
    FRAME_PROLOG 32
    call    gui_trtest
    test    eax, eax
    jnz     trt_fail
    lea     rcx, [trt_ok]
    mov     edx, trt_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
trt_fail:
    lea     rcx, [trt_bad]
    mov     edx, trt_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_trtest endp

; =============================================================================
; is_cli_command -> eax = 1 if argv[1] names a known command verb, else 0.
; Used by the hybrid entry point to choose CLI vs GUI mode.  Requires
; parse_cmdline to have already populated g_argv/g_argc.  Read-only (no output).
; =============================================================================
public is_cli_command
is_cli_command proc frame
    FRAME_PROLOG 48
    ; locals: [rbp-24] = table cursor, [rbp-32] = table index
    cmp     dword ptr [g_argc], 2
    jb      icc_no
    lea     rax, [cmd_table]
    mov     qword ptr [rbp-24], rax
    mov     qword ptr [rbp-32], 0
icc_loop:
    cmp     qword ptr [rbp-32], CMD_COUNT
    jae     icc_optck
    mov     r10, qword ptr [rbp-24]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+8]      ; argv[1]
    mov     rdx, qword ptr [r10].CMDENT.name_ptr
    call    wstr_eq
    test    eax, eax
    jnz     icc_yes
    add     qword ptr [rbp-24], sizeof CMDENT
    inc     qword ptr [rbp-32]
    jmp     icc_loop
icc_optck:
    ; not a known verb - but a leading '-' means an option (e.g. --help, -h):
    ; route those to the CLI too so terminal usage prints to the console.  A
    ; file path handed by Explorer/drag-drop is drive-absolute, never '-'.
    ; Exception (E9): "--ro" is a GUI read-only launch flag, not a CLI verb - set
    ; the flag and stay in GUI mode.
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+8]      ; argv[1] ptr
    lea     rdx, [w_ro]
    call    wstr_eq
    test    eax, eax
    jz      icc_dash
    mov     dword ptr [g_readonly], 1
    jmp     icc_no                      ; --ro is not a CLI command -> GUI mode
icc_dash:
    lea     r11, [g_argv]
    mov     r10, qword ptr [r11+8]      ; argv[1] ptr
    movzx   eax, word ptr [r10]         ; first UTF-16 unit
    cmp     eax, '-'
    je      icc_yes
    xor     eax, eax
    FRAME_EPILOG
    ret
icc_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
icc_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
is_cli_command endp

; =============================================================================
; dispatch - match argv[1] against cmd_table, validate options, run handler
; through a DLPV-guarded indirect call.  Returns exit code in eax.
; =============================================================================
public dispatch
dispatch proc frame
    FRAME_PROLOG 48
    ; locals: [rbp-24] = table cursor, [rbp-32] = table index

    cmp     dword ptr [g_argc], 2
    jb      dp_usage

    lea     rax, [cmd_table]
    mov     qword ptr [rbp-24], rax
    mov     qword ptr [rbp-32], 0
dp_loop:
    cmp     qword ptr [rbp-32], CMD_COUNT
    jae     dp_usage
    mov     r10, qword ptr [rbp-24]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+8]      ; argv[1] = command word
    mov     rdx, qword ptr [r10].CMDENT.name_ptr
    call    wstr_eq
    test    eax, eax
    jnz     dp_found
    add     qword ptr [rbp-24], sizeof CMDENT
    inc     qword ptr [rbp-32]
    jmp     dp_loop

dp_found:
    mov     rcx, qword ptr [rbp-24]     ; CMDENT*
    call    collect_options
    cmp     eax, EXIT_OK
    jne     dp_done                     ; validation failed; eax = exit code
    mov     r10, qword ptr [rbp-24]
    mov     rax, qword ptr [r10].CMDENT.handler
    CALL_GUARDED rax                    ; DLPV-checked indirect call
    ; ---- audit log: command name + outcome -> the Vordr log text file --------
    mov     dword ptr [rbp-32], eax     ; stash exit code (index local is done)
    mov     r10, qword ptr [rbp-24]
    mov     rcx, qword ptr [r10].CMDENT.name_ptr
    mov     edx, dword ptr [rbp-32]
    call    log_result
    mov     eax, dword ptr [rbp-32]     ; restore exit code
    jmp     dp_done

dp_usage:
    lea     rcx, [msg_usage]
    mov     edx, msg_usage_len
    call    print_err
    mov     eax, EXIT_USAGE
dp_done:
    FRAME_EPILOG
    ret
dispatch endp

; =============================================================================
; start - process entry point
; =============================================================================
public start
start proc frame
    sub     rsp, 56                     ; 32 shadow + 2 locals + align
    .allocstack 56
    .endprolog
    ; locals: [rsp+32] = cpu-ok flag, [rsp+40] = exit code

    DBG     'A'
    call    cpu_gate                    ; 1. feature detect (raw frame)
    mov     dword ptr [rsp+32], eax
    DBG     'B'
    call    hardening_init              ; 2. canary + shadow stack live
    test    eax, eax
    jz      st_oom_raw
    call    sec_lock_statics           ; VirtualLock the static secret buffers
    DBG     'C'
    call    con_init                    ; 3. console up (protected calls ok now)
    DBG     'D'
    cmp     dword ptr [rsp+32], 0
    je      st_nocpu
    call    iat_lockdown                ; 4. imports now read-only
    DBG     'E'
    call    parse_cmdline               ; 5. tokenize + dispatch
    DBG     'F'
    call    dispatch
    mov     dword ptr [rsp+40], eax
    DBG     'G'

st_exit:
    ; wipe password material before leaving, belt and braces
    lea     rcx, [g_cfg_pass]
    mov     edx, MAX_PASSWORD_BYTES+1
    call    secure_zero
    WINCALL ExitProcess, dword ptr [rsp+40]     ; never returns

st_nocpu:
    lea     rcx, [msg_nocpu]
    mov     edx, msg_nocpu_len
    call    print_err
    mov     dword ptr [rsp+40], EXIT_NOCPU
    jmp     st_exit
st_oom_raw:
    ; hardened runtime unavailable: exit without touching protected helpers
    WINCALL ExitProcess, EXIT_OOM
start endp

end
