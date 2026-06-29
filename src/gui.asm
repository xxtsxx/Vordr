; =============================================================================
; gui.asm - hybrid entry point (wstart) + minimal GUI shell
; -----------------------------------------------------------------------------
; The single vordr.exe is linked /subsystem:windows with entry point `wstart`.
; wstart runs the full CLI when argv[1] is a known verb (handled by main.asm's
; is_cli_command / dispatch); otherwise it opens the windowed front-end.
;
; SCAFFOLD: the GUI is reduced to an About message box.  The full vault UI
; (entry list, reveal/copy panes, generator, share dialog) lands in a later
; step.  What is preserved here and must not regress:
;   * the exact CLI-vs-GUI startup order from Myrkr, and
;   * the per-run SELF-TEST GATE: every launch runs the KATs first and fails
;     closed (EXIT_SELFTEST) before doing any work (brief requirement).
; =============================================================================

include macros.inc

extern cpu_gate:proc
extern hardening_init:proc
extern con_init:proc
extern con_attach_parent:proc
extern iat_lockdown:proc
extern parse_cmdline:proc                ; CLI tokenizer (main.asm)
extern is_cli_command:proc               ; argv[1] is a known verb? (main.asm)
extern dispatch:proc                     ; CLI command dispatch (main.asm)
extern run_selftest:proc                 ; KAT gate (selftest.asm)
extern secure_zero:proc
extern print_err:proc

extern MessageBoxW:proc
extern ExitProcess:proc

externdef g_cfg_pass:byte

MB_OK               equ 0
MB_ICONERROR        equ 10h
MB_ICONINFORMATION  equ 40h

.const
; --- ASCII (console) diagnostics ----------------------------------------------
CSTR c_nocpu,   "error: CPU lacks required features (AES-NI/PCLMULQDQ/SSE4.1)",13,10
CSTR c_stfail,  "SELFTEST FAILURE - refusing to run",13,10

; --- wide (message box) strings -----------------------------------------------
; (WSTR text may not contain commas; keep these comma-free single lines.)
WSTR t_vordr,   <Vordr>
WSTR t_err,     <Vordr - error>
WSTR m_about,   <Vordr - hardened password manager (scaffold build). Run vordr selftest in a terminal.>
WSTR m_nocpu,   <This CPU lacks required features (AES-NI / PCLMULQDQ / SSE4.1) - cannot run.>
WSTR m_stfail,  <Self-test FAILED - refusing to run. The binary may be corrupt.>

.code

; =============================================================================
; gui_main - the windowed front-end (scaffold: an About box).  Returns to
; wstart, which exits the process.
; =============================================================================
gui_main proc frame
    FRAME_PROLOG 32
    WINCALL MessageBoxW, 0, addr m_about, addr t_vordr, <MB_OK or MB_ICONINFORMATION>
    FRAME_EPILOG
    ret
gui_main endp

; =============================================================================
; wstart - process entry point (linker /entry:wstart).
; Raw frame (runs before the hardening machinery is live for cpu_gate/
; hardening_init, exactly as in Myrkr).
; =============================================================================
public wstart
wstart proc
    sub     rsp, 56
    ; locals: [rsp+48] = cpu-ok flag, [rsp+52] = exit code

    call    cpu_gate                     ; raw frame; sets g_cpu_features
    mov     dword ptr [rsp+48], eax
    call    hardening_init               ; canary + shadow stack live
    test    eax, eax
    jz      ws_oom

    call    parse_cmdline                ; tokenize into the CLI g_argv/g_argc
    call    is_cli_command               ; eax = 1 if argv[1] is a known verb
    test    eax, eax
    jz      ws_gui

    ; ========================= CLI MODE =====================================
    call    con_attach_parent            ; connect to the launching terminal
    call    con_init                     ; cache stdout/stderr handles
    cmp     dword ptr [rsp+48], 0
    je      ws_nocpu_cli
    call    iat_lockdown                 ; imports now read-only
    xor     ecx, ecx                     ; selftest gate: silent
    call    run_selftest
    test    eax, eax
    jnz     ws_stfail_cli
    call    dispatch                     ; run the command; eax = exit code
    mov     dword ptr [rsp+52], eax
    lea     rcx, [g_cfg_pass]            ; wipe password material, belt & braces
    mov     edx, MAX_PASSWORD_BYTES+1
    call    secure_zero
    WINCALL ExitProcess, dword ptr [rsp+52]
ws_stfail_cli:
    lea     rcx, [c_stfail]
    mov     edx, c_stfail_len
    call    print_err
    WINCALL ExitProcess, EXIT_SELFTEST
ws_nocpu_cli:
    lea     rcx, [c_nocpu]
    mov     edx, c_nocpu_len
    call    print_err
    WINCALL ExitProcess, EXIT_NOCPU

    ; ========================= GUI MODE =====================================
ws_gui:
    call    con_init
    cmp     dword ptr [rsp+48], 0
    je      ws_nocpu
    call    iat_lockdown
    xor     ecx, ecx                     ; selftest gate: silent
    call    run_selftest
    test    eax, eax
    jnz     ws_stfail_gui
    call    gui_main
    WINCALL ExitProcess, 0
ws_stfail_gui:
    WINCALL MessageBoxW, 0, addr m_stfail, addr t_err, <MB_OK or MB_ICONERROR>
    WINCALL ExitProcess, EXIT_SELFTEST
ws_nocpu:
    WINCALL MessageBoxW, 0, addr m_nocpu, addr t_err, <MB_OK or MB_ICONERROR>
    WINCALL ExitProcess, EXIT_NOCPU
ws_oom:
    WINCALL ExitProcess, EXIT_OOM
wstart endp

end
