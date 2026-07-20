; =============================================================================
; log.asm - plain-text audit log file (no admin rights, no registration).
; -----------------------------------------------------------------------------
; Every command's outcome is appended as one UTF-8 text line to a log file:
;
;   2026-06-29 14:23:01  INFO   seedtest: completed successfully
;   2026-06-29 14:23:05  WARN   zitest: authentication failed (wrong password or tampered data)
;   2026-06-29 14:23:09  ERROR  bktest: I/O error
;
; Default path is %LOCALAPPDATA%\Vordr\vordr.log (per-user, always writable);
; override with `--log-file PATH`.  Logging is OFF by default; opt in (and pick
; verbosity) with `--log LEVEL`:
;
;   none(0)    nothing                                                (DEFAULT)
;   error(1)   hard failures only            -> ERROR lines
;   warning(2) + authentication failures     -> WARN lines
;   full(3)    + successful operations       -> INFO lines
;   debug(4)   + input/output file paths appended to the line
;
; The file is opened in append mode per event (FILE_APPEND_DATA), so concurrent
; runs interleave cleanly and there is no handle to keep open.  Best effort: if
; the file can't be opened the event is silently dropped.
; =============================================================================

include macros.inc

extern CreateFileW:proc
extern WriteFile:proc
extern CloseHandle:proc
extern GetEnvironmentVariableW:proc
extern CreateDirectoryW:proc
extern GetLocalTime:proc
extern WideCharToMultiByte:proc

externdef g_cfg_loglevel:dword
externdef g_cfg_logfile:qword
externdef g_cfg_in:qword
externdef g_cfg_out:qword

LOG_ERROR   equ 1
LOG_WARNING equ 2
LOG_FULL    equ 3
LOG_DEBUG   equ 4

CP_UTF8              equ 65001
FILE_APPEND_DATA     equ 4
FILE_SHARE_RW        equ 3            ; FILE_SHARE_READ | FILE_SHARE_WRITE
OPEN_ALWAYS          equ 4
FILE_ATTR_NORMAL     equ 80h
INVALID              equ -1
LINELEN              equ 16384        ; one log line, UTF-8 bytes

.const
WSTR w_localappdata, <LOCALAPPDATA>
WSTR w_subdir,       <\Vordr>
WSTR w_logname,      <\vordr.log>

CSTR rm_ok,      "completed successfully"
CSTR rm_auth,    "authentication failed (wrong password or tampered data)"
CSTR rm_io,      "I/O error"
CSTR rm_corrupt, "corrupt or invalid container"
CSTR rm_oom,     "out of memory"
CSTR rm_nospace, "insufficient disk space"
CSTR rm_usage,   "invalid usage"
CSTR rm_nocpu,   "unsupported CPU"
CSTR rm_self,    "self-test failure"
CSTR rm_err,     "operation failed"
CSTR sv_info,    "INFO "
CSTR sv_warn,    "WARN "
CSTR sv_err,     "ERROR"
CSTR sep_2sp,    "  "
CSTR sep_colon,  ": "
CSTR sep_in,     " [in="
CSTR sep_out,    " out="
CSTR sep_close,  "]"
CSTR sep_crlf,   13,10

.data?
align 16
g_logline   db LINELEN dup (?)        ; assembled UTF-8 line
align 2
g_logpath   dw 1024 dup (?)           ; resolved default log path
g_systime   db 16 dup (?)             ; SYSTEMTIME
g_logwrote  dd ?

.code

; -----------------------------------------------------------------------------
; log_putn(rcx = dst, edx = value, r8d = digits) -> rax = dst+digits.  Writes a
; fixed-width, zero-padded decimal number (low digits if value overflows).  Leaf.
; -----------------------------------------------------------------------------
log_putn proc
    lea     r9, [rcx + r8]              ; end / return ptr
    mov     r10, r9                     ; cursor
    mov     eax, edx                    ; value
    mov     r11d, 10
pn_loop:
    dec     r10
    xor     edx, edx
    div     r11d                        ; eax /= 10, edx = remainder
    add     dl, '0'
    mov     byte ptr [r10], dl
    cmp     r10, rcx
    ja      pn_loop
    mov     rax, r9
    ret
log_putn endp

; -----------------------------------------------------------------------------
; log_puta(rcx = dst, rdx = src, r8 = len) -> rax = dst+len.  Byte copy.  Leaf.
; -----------------------------------------------------------------------------
log_puta proc
    test    r8, r8
    jz      pa_done
pa_l:
    mov     al, byte ptr [rdx]
    mov     byte ptr [rcx], al
    inc     rcx
    inc     rdx
    dec     r8
    jnz     pa_l
pa_done:
    mov     rax, rcx
    ret
log_puta endp

; -----------------------------------------------------------------------------
; log_wapp(rcx = dst, rdx = wideZ src) -> rax = new dst.  UTF-16 copy, no NUL.
; -----------------------------------------------------------------------------
log_wapp proc
wa_l:
    movzx   eax, word ptr [rdx]
    test    ax, ax
    jz      wa_d
    mov     word ptr [rcx], ax
    add     rcx, 2
    add     rdx, 2
    jmp     wa_l
wa_d:
    mov     rax, rcx
    ret
log_wapp endp

; -----------------------------------------------------------------------------
; log_putw(rcx = dst, rdx = wideZ src) -> rax = new dst.  Appends src as UTF-8,
; bounded by the end of g_logline.  On failure leaves dst unchanged.
; -----------------------------------------------------------------------------
log_putw proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx     ; dst
    mov     qword ptr [rbp-32], rdx     ; src
    lea     rax, [g_logline + LINELEN - 1]
    sub     rax, rcx                    ; remaining bytes
    jle     pw_none
    mov     dword ptr [rbp-40], eax
    WINCALL WideCharToMultiByte, CP_UTF8, 0, qword ptr [rbp-32], -1, \
            qword ptr [rbp-24], dword ptr [rbp-40], 0, 0
    test    eax, eax
    jz      pw_none
    dec     eax                         ; drop the NUL from the byte count
    mov     rcx, qword ptr [rbp-24]
    add     rcx, rax
    mov     rax, rcx
    FRAME_EPILOG
    ret
pw_none:
    mov     rax, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
log_putw endp

; -----------------------------------------------------------------------------
; log_open() -> rax = file handle (append mode) or INVALID.
; Uses g_cfg_logfile if set, else %LOCALAPPDATA%\Vordr\vordr.log (creating the
; Vordr directory if needed).
; -----------------------------------------------------------------------------
log_open proc frame
    FRAME_PROLOG 128
    ; [rbp-24]=saved cursor  [rbp-32]=path ptr
    mov     rax, qword ptr [g_cfg_logfile]
    test    rax, rax
    jz      lo_default
    mov     qword ptr [rbp-32], rax
    jmp     lo_open
lo_default:
    WINCALL GetEnvironmentVariableW, addr w_localappdata, addr g_logpath, 1024
    test    eax, eax
    jz      lo_fail
    cmp     eax, 1000                   ; value didn't fit (returns required size), or
    jae     lo_fail                     ; leaves no room for "\Vordr\vordr.log" -> skip
    mov     ecx, eax                    ; dir length (chars)
    lea     rdx, [g_logpath]
    lea     rdx, [rdx + rcx*2]          ; cursor at the NUL
    mov     rcx, rdx
    lea     rdx, [w_subdir]
    call    log_wapp                    ; append "\Vordr"
    mov     word ptr [rax], 0
    mov     qword ptr [rbp-24], rax
    WINCALL CreateDirectoryW, addr g_logpath, 0     ; ignore result (may exist)
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [w_logname]
    call    log_wapp                    ; append "\vordr.log"
    mov     word ptr [rax], 0
    lea     rax, [g_logpath]
    mov     qword ptr [rbp-32], rax
lo_open:
    WINCALL CreateFileW, qword ptr [rbp-32], FILE_APPEND_DATA, FILE_SHARE_RW, 0, \
            OPEN_ALWAYS, FILE_ATTR_NORMAL, 0
    FRAME_EPILOG
    ret
lo_fail:
    mov     rax, INVALID
    FRAME_EPILOG
    ret
log_open endp

; -----------------------------------------------------------------------------
; log_result(rcx = command wide name, edx = exit code)
; Classifies the outcome, applies the level, formats one UTF-8 line, and appends
; it to the log file.  No-op when the level filters the outcome out.
; -----------------------------------------------------------------------------
public log_result
log_result proc frame
    FRAME_PROLOG 128
    ; [rbp-24]=cmd [rbp-32]=code [rbp-40]=needed [rbp-48]=sevptr
    ; [rbp-64]=resptr [rbp-72]=reslen [rbp-80]=linelen [rbp-88]=handle
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx

    test    edx, edx
    jnz     lr_notok
    mov     dword ptr [rbp-40], LOG_FULL
    lea     rax, [sv_info]
    mov     qword ptr [rbp-48], rax
    lea     rax, [rm_ok]
    mov     qword ptr [rbp-64], rax
    mov     dword ptr [rbp-72], rm_ok_len
    jmp     lr_have
lr_notok:
    cmp     edx, EXIT_AUTH
    jne     lr_err
    mov     dword ptr [rbp-40], LOG_WARNING
    lea     rax, [sv_warn]
    mov     qword ptr [rbp-48], rax
    lea     rax, [rm_auth]
    mov     qword ptr [rbp-64], rax
    mov     dword ptr [rbp-72], rm_auth_len
    jmp     lr_have
lr_err:
    mov     dword ptr [rbp-40], LOG_ERROR
    lea     rax, [sv_err]
    mov     qword ptr [rbp-48], rax
    mov     edx, dword ptr [rbp-32]
    lea     rax, [rm_io]
    mov     r8d, rm_io_len
    cmp     edx, EXIT_IO
    je      lr_setres
    lea     rax, [rm_corrupt]
    mov     r8d, rm_corrupt_len
    cmp     edx, EXIT_CORRUPT
    je      lr_setres
    lea     rax, [rm_oom]
    mov     r8d, rm_oom_len
    cmp     edx, EXIT_OOM
    je      lr_setres
    lea     rax, [rm_nospace]
    mov     r8d, rm_nospace_len
    cmp     edx, EXIT_NOSPACE
    je      lr_setres
    lea     rax, [rm_usage]
    mov     r8d, rm_usage_len
    cmp     edx, EXIT_USAGE
    je      lr_setres
    lea     rax, [rm_nocpu]
    mov     r8d, rm_nocpu_len
    cmp     edx, EXIT_NOCPU
    je      lr_setres
    lea     rax, [rm_self]
    mov     r8d, rm_self_len
    cmp     edx, EXIT_SELFTEST
    je      lr_setres
    lea     rax, [rm_err]
    mov     r8d, rm_err_len
lr_setres:
    mov     qword ptr [rbp-64], rax
    mov     dword ptr [rbp-72], r8d
lr_have:
    mov     eax, dword ptr [g_cfg_loglevel]
    cmp     eax, dword ptr [rbp-40]
    jb      lr_skip                     ; level filters this outcome out

    ; ---- timestamp "YYYY-MM-DD HH:MM:SS" -----------------------------------
    WINCALL GetLocalTime, addr g_systime
    lea     rcx, [g_logline]
    movzx   edx, word ptr [g_systime+0]     ; year
    mov     r8d, 4
    call    log_putn
    mov     byte ptr [rax], '-'
    lea     rcx, [rax+1]
    movzx   edx, word ptr [g_systime+2]     ; month
    mov     r8d, 2
    call    log_putn
    mov     byte ptr [rax], '-'
    lea     rcx, [rax+1]
    movzx   edx, word ptr [g_systime+6]     ; day
    mov     r8d, 2
    call    log_putn
    mov     byte ptr [rax], ' '
    lea     rcx, [rax+1]
    movzx   edx, word ptr [g_systime+8]     ; hour
    mov     r8d, 2
    call    log_putn
    mov     byte ptr [rax], ':'
    lea     rcx, [rax+1]
    movzx   edx, word ptr [g_systime+10]    ; minute
    mov     r8d, 2
    call    log_putn
    mov     byte ptr [rax], ':'
    lea     rcx, [rax+1]
    movzx   edx, word ptr [g_systime+12]    ; second
    mov     r8d, 2
    call    log_putn
    ; ---- "  LEVEL  command: result" ----------------------------------------
    mov     rcx, rax
    lea     rdx, [sep_2sp]
    mov     r8d, sep_2sp_len
    call    log_puta
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-48]         ; severity tag (5 chars)
    mov     r8d, 5
    call    log_puta
    mov     rcx, rax
    lea     rdx, [sep_2sp]
    mov     r8d, sep_2sp_len
    call    log_puta
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-24]         ; command name (wide -> UTF-8)
    call    log_putw
    mov     rcx, rax
    lea     rdx, [sep_colon]
    mov     r8d, sep_colon_len
    call    log_puta
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-64]         ; result text
    mov     r8d, dword ptr [rbp-72]
    call    log_puta
    ; ---- debug: " [in=<path> out=<path>]" ----------------------------------
    cmp     dword ptr [g_cfg_loglevel], LOG_DEBUG
    jne     lr_crlf
    mov     rdx, qword ptr [g_cfg_in]
    test    rdx, rdx
    jz      lr_crlf
    mov     rcx, rax
    lea     rdx, [sep_in]
    mov     r8d, sep_in_len
    call    log_puta
    mov     rcx, rax
    mov     rdx, qword ptr [g_cfg_in]
    call    log_putw
    mov     rdx, qword ptr [g_cfg_out]
    test    rdx, rdx
    jz      lr_closebr
    mov     rcx, rax
    lea     rdx, [sep_out]
    mov     r8d, sep_out_len
    call    log_puta
    mov     rcx, rax
    mov     rdx, qword ptr [g_cfg_out]
    call    log_putw
lr_closebr:
    mov     rcx, rax
    lea     rdx, [sep_close]
    mov     r8d, sep_close_len
    call    log_puta
lr_crlf:
    mov     rcx, rax
    lea     rdx, [sep_crlf]
    mov     r8d, sep_crlf_len
    call    log_puta
    ; ---- write the line ----------------------------------------------------
    lea     rdx, [g_logline]
    sub     rax, rdx                        ; length
    mov     dword ptr [rbp-80], eax
    call    log_open
    cmp     rax, INVALID
    je      lr_skip
    mov     qword ptr [rbp-88], rax
    WINCALL WriteFile, qword ptr [rbp-88], addr g_logline, dword ptr [rbp-80], \
            addr g_logwrote, 0
    WINCALL CloseHandle, qword ptr [rbp-88]
lr_skip:
    FRAME_EPILOG
    ret
log_result endp

end
