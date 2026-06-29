; =============================================================================
; console.asm - console / redirection-safe output helpers
; -----------------------------------------------------------------------------
;   con_init      : caches stdout/stderr handles, switches console to UTF-8
;   print_a       : rcx = ASCII ptr, edx = len      -> stdout
;   print_err     : rcx = ASCII ptr, edx = len      -> stderr
;   print_wz      : rcx = UTF-16Z ptr               -> stdout (as UTF-8)
;   print_hex     : rcx = byte ptr, edx = len(<=64) -> stdout (lowercase hex)
;   print_u64     : rcx = value                     -> stdout (decimal)
;
; All output goes through WriteFile, which works for real consoles and for
; redirected handles alike.  Single-threaded by design (whole program is).
; =============================================================================

include macros.inc

extern GetStdHandle:proc
extern WriteFile:proc
extern SetConsoleOutputCP:proc
extern WideCharToMultiByte:proc
extern AttachConsole:proc
extern GetFileType:proc

STD_OUTPUT_HANDLE   equ -11
STD_ERROR_HANDLE    equ -12
ATTACH_PARENT_PROCESS equ -1
CP_UTF8             equ 65001
FILE_TYPE_DISK      equ 1
FILE_TYPE_PIPE      equ 3

.data
public g_hstdout
g_hstdout   dq 0
g_hstderr   dq 0
; shell-provided handles captured before AttachConsole, with a flag marking
; whether each was a real redirection (file/pipe) that must survive the attach.
g_pre_out       dq 0
g_pre_err       dq 0
g_pre_out_redir dd 0
g_pre_err_redir dd 0

.data?
; static UTF-8 conversion buffer: worst case 3 bytes per UTF-16 unit
g_conv_buf  db (MAX_PATH_CHARS*3) dup (?)

.const
hexdigits   db "0123456789abcdef"

.code

; =============================================================================
public con_init
con_init proc frame
    FRAME_PROLOG 32
    WINCALL SetConsoleOutputCP, CP_UTF8     ; make UTF-8 output render correctly
    ; stdout: a shell redirection (> file / | pipe) captured before AttachConsole
    ; must win; otherwise use the (now attached) console handle.
    cmp     dword ptr [g_pre_out_redir], 0
    je      ci_out_con
    mov     rax, qword ptr [g_pre_out]
    jmp     ci_out_set
ci_out_con:
    WINCALL GetStdHandle, STD_OUTPUT_HANDLE
ci_out_set:
    mov     qword ptr [g_hstdout], rax
    ; stderr: same rule
    cmp     dword ptr [g_pre_err_redir], 0
    je      ci_err_con
    mov     rax, qword ptr [g_pre_err]
    jmp     ci_err_set
ci_err_con:
    WINCALL GetStdHandle, STD_ERROR_HANDLE
ci_err_set:
    mov     qword ptr [g_hstderr], rax
    FRAME_EPILOG
    ret
con_init endp

; =============================================================================
; con_attach_parent - best-effort AttachConsole(ATTACH_PARENT_PROCESS).
; Used by the hybrid (GUI-subsystem) binary when it runs in CLI mode so that
; output reaches the launching terminal's console.  Call BEFORE con_init.
;
; Crucially, it first captures the shell-provided stdout/stderr handles and
; notes whether each is a real redirection (a disk file or a pipe).  AttachConsole
; replaces the process's standard handles with the console's, which would
; otherwise discard a `myrkr ... > file` / `| tool` redirection and send output
; to the terminal instead.  con_init then restores the captured handle for any
; stream that was redirected, so redirection and piping work as expected.
; =============================================================================
public con_attach_parent
con_attach_parent proc frame
    FRAME_PROLOG 32
    WINCALL GetStdHandle, STD_OUTPUT_HANDLE
    mov     qword ptr [g_pre_out], rax
    mov     rcx, rax
    call    is_redirected
    mov     dword ptr [g_pre_out_redir], eax
    WINCALL GetStdHandle, STD_ERROR_HANDLE
    mov     qword ptr [g_pre_err], rax
    mov     rcx, rax
    call    is_redirected
    mov     dword ptr [g_pre_err_redir], eax
    WINCALL AttachConsole, ATTACH_PARENT_PROCESS     ; result ignored (best effort)
    FRAME_EPILOG
    ret
con_attach_parent endp

; =============================================================================
; is_redirected(rcx = handle) -> eax = 1 if the handle is a disk file or pipe
; (i.e. a real shell redirection), 0 for a console / invalid / null handle.
; =============================================================================
is_redirected proc frame
    FRAME_PROLOG 32
    cmp     rcx, -1
    je      ir_no
    test    rcx, rcx
    jz      ir_no
    WINCALL GetFileType, rcx            ; DISK=1, CHAR(console)=2, PIPE=3
    cmp     eax, FILE_TYPE_DISK
    je      ir_yes
    cmp     eax, FILE_TYPE_PIPE
    je      ir_yes
ir_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
ir_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
is_redirected endp

; =============================================================================
; write_handle(rcx = handle, rdx = ptr, r8d = len)  - internal
; =============================================================================
write_handle proc frame
    FRAME_PROLOG 32 + 16 + 8            ; shadow + arg5 slot + local dword
    ; local: [rbp-24] = bytes-written
    xIFT r8d                            ; nothing to do for a zero-length write
        WINCALL WriteFile, rcx, rdx, r8, addr rbp-24, 0
    xENDIF
    FRAME_EPILOG
    ret
write_handle endp

; =============================================================================
public print_a
print_a proc frame
    FRAME_PROLOG 32
    mov     r8d, edx
    mov     rdx, rcx
    mov     rcx, qword ptr [g_hstdout]
    call    write_handle
    FRAME_EPILOG
    ret
print_a endp

; =============================================================================
public print_err
print_err proc frame
    FRAME_PROLOG 32
    mov     r8d, edx
    mov     rdx, rcx
    mov     rcx, qword ptr [g_hstderr]
    call    write_handle
    FRAME_EPILOG
    ret
print_err endp

; =============================================================================
; print_wz - print a NUL-terminated UTF-16 string (e.g. a filename) as UTF-8.
; Conversion is bounded by the static buffer; oversized input is truncated
; by WideCharToMultiByte failing, in which case nothing is printed.
; =============================================================================
public print_wz
print_wz proc frame
    FRAME_PROLOG 32 + 32                ; shadow + 4 stack args for WC2MB
    ; WideCharToMultiByte(CP_UTF8, 0, src, -1, g_conv_buf, cap, NULL, NULL)
    WINCALL WideCharToMultiByte, CP_UTF8, 0, rcx, -1, addr g_conv_buf, MAX_PATH_CHARS*3, 0, 0
    test    eax, eax                    ; 0 = conversion failed
    jz      pw_done
    dec     eax                         ; drop the terminating NUL
    jz      pw_done
    lea     rcx, [g_conv_buf]
    mov     edx, eax
    call    print_a
pw_done:
    FRAME_EPILOG
    ret
print_wz endp

; =============================================================================
; print_hex - rcx = bytes, edx = len (bounded to 64): lowercase hex to stdout
; =============================================================================
public print_hex
print_hex proc frame
    FRAME_PROLOG 32 + 144               ; shadow + 128-byte hex buffer + pad
    mov     edx, edx                    ; zero-extend length
    BOUND_CHECK rdx, 65                 ; at most 64 input bytes per call

    lea     r8, [hexdigits]
    xor     r10d, r10d                  ; input index
    lea     r11, [rsp+32]               ; output cursor
ph_loop:
    cmp     r10d, edx
    jae     ph_flush
    movzx   eax, byte ptr [rcx+r10]
    mov     r9d, eax
    shr     eax, 4                      ; high nibble
    movzx   eax, byte ptr [r8+rax]
    mov     byte ptr [r11], al
    and     r9d, 0Fh                    ; low nibble
    movzx   eax, byte ptr [r8+r9]
    mov     byte ptr [r11+1], al
    add     r11, 2
    inc     r10d
    jmp     ph_loop
ph_flush:
    lea     rcx, [rsp+32]
    mov     edx, r10d
    shl     edx, 1                      ; two hex chars per byte
    call    print_a
    FRAME_EPILOG
    ret
print_hex endp

; =============================================================================
; print_u64 - rcx = unsigned 64-bit value, printed in decimal
; =============================================================================
public print_u64
print_u64 proc frame
    FRAME_PROLOG 32 + 32                ; shadow + 24-byte digit buffer + pad
    lea     r10, [rsp+32+24]            ; build digits backwards from end
    mov     rax, rcx
    mov     r8, 10
    xor     r11d, r11d                  ; digit count
pu_loop:
    xor     edx, edx
    div     r8                          ; rax = quotient, rdx = remainder
    add     dl, '0'
    dec     r10
    mov     byte ptr [r10], dl
    inc     r11d
    test    rax, rax
    jnz     pu_loop
    mov     rcx, r10
    mov     edx, r11d
    call    print_a
    FRAME_EPILOG
    ret
print_u64 endp

; =============================================================================
; print_u64e - rcx = unsigned 64-bit value, printed in decimal to STDERR
; =============================================================================
public print_u64e
print_u64e proc frame
    FRAME_PROLOG 32 + 32
    lea     r10, [rsp+32+24]
    mov     rax, rcx
    mov     r8, 10
    xor     r11d, r11d
pue_loop:
    xor     edx, edx
    div     r8
    add     dl, '0'
    dec     r10
    mov     byte ptr [r10], dl
    inc     r11d
    test    rax, rax
    jnz     pue_loop
    mov     rcx, r10
    mov     edx, r11d
    call    print_err
    FRAME_EPILOG
    ret
print_u64e endp

end
