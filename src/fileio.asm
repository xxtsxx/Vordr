; =============================================================================
; fileio.asm - file read/write and memory helpers
; -----------------------------------------------------------------------------
;   mem_alloc(rcx = size)               -> rax = ptr (0 on failure)
;   mem_free (rcx = ptr, rdx = size)    (wipes then releases)
;   read_file(rcx = wpath, rdx = *outbuf, r8 = *outsize) -> eax 0 / EXIT_IO
;   write_file(rcx = wpath, rdx = buf, r8 = size)        -> eax 0 / EXIT_IO
; =============================================================================

include macros.inc
externdef g_cfg_in:qword                ; set ONLY through cfg_in_set below
externdef g_allow_unc:dword             ; HKLM-only AllowUncVault policy (regcfg.asm)

extern CreateFileW:proc
extern GetLastError:proc
extern Sleep:proc
extern ReadFile:proc
extern WriteFile:proc
extern GetFileSizeEx:proc
extern SetFilePointerEx:proc
extern CloseHandle:proc
extern GetFileType:proc
extern GetFileInformationByHandle:proc
extern GetFinalPathNameByHandleW:proc
extern ReplaceFileW:proc
extern MoveFileExW:proc
extern DeleteFileW:proc
extern CopyFileW:proc
extern FlushFileBuffers:proc
extern GetDiskFreeSpaceExW:proc
extern GetFullPathNameW:proc            ; a relative long path must be resolved first
extern GetCurrentDirectoryW:proc        ; ...and measured against what it resolves to
extern tagged_alloc:proc
extern tagged_free:proc

MOVEFILE_REPLACE_EXISTING equ 1
MOVEFILE_WRITE_THROUGH    equ 8
REPLACEFILE_WRITE_THROUGH equ 1

GENERIC_READ        equ 80000000h
GENERIC_WRITE       equ 40000000h
FILE_SHARE_RWD      equ 7               ; READ|WRITE|DELETE - read-only-by-default opens
                                        ;   never block another writer / sync tool (redesign B1)
OPEN_EXISTING       equ 3
CREATE_ALWAYS       equ 2
FILE_ATTR_NORMAL    equ 80h
FILE_FLAG_OPEN_RP   equ 00200000h       ; FILE_FLAG_OPEN_REPARSE_POINT
FILE_TYPE_DISK_     equ 1
IO_CHUNK            equ 1000000h         ; 16 MiB per ReadFile/WriteFile

.data?
public g_io_err
g_io_err    dd ?                 ; Win32 error from the last failed write/rename.
                                 ;   Lets a caller distinguish transient contention
                                 ;   (a sync client holding the file) from a real
                                 ;   failure, instead of seeing a flat EXIT_IO.
align 4
public g_rf_cap
g_rf_cap    dq ?                       ; one-shot read_file size cap (0 = none): a file
                                       ;   past it is refused before anything is allocated
public g_wf_disp
g_wf_disp   dd ?                       ; C7: one-shot write_file disposition override
public g_wf_created
g_wf_created dd ?                     ; last write_file actually created/opened its file
align 2                               ;     (0 = CREATE_ALWAYS default; caller sets CREATE_NEW)

; These are single-slot and process-wide.  That is safe because file work is
; serialised: the only worker thread (secdesk) runs while the main thread blocks
; waiting for it, so one caller is in here at a time.  The exception is the
; watchdog's orphan path in gui_secdesk_show - see the comment there - where an
; abandoned worker keeps running; in that window these are shared, along with
; every other piece of vault state, and the answer is not a lock on these.
;
; .data? and not .data.  "dup (?)" in an INITIALISED section is not a promise
; to leave the bytes alone - it emits them.  Five 64 KB buffers put 320 KB of
; zeros in the image and nearly doubled the exe.  Uninitialised data costs
; virtual size only.
align 2
ci_path     dw (MAX_PATH_CHARS + 16) dup (?)   ; the vault path g_cfg_in points at
fr_from     dw (MAX_PATH_CHARS + 16) dup (?)   ; file_rename's two paths are live at
fr_to       dw (MAX_PATH_CHARS + 16) dup (?)   ;   the same time, so two buffers
rf_path     dw (MAX_PATH_CHARS + 16) dup (?)   ; read_file's Win32-form path
wf_path     dw (MAX_PATH_CHARS + 16) dup (?)   ; write_file's, kept separate so a
                                               ;   read during a write cannot share it
fv_final    dw (MAX_PATH_CHARS + 16) dup (?)   ; GetFinalPathNameByHandleW scratch
align 8
fv_bhfi     db 64 dup (?)                      ; BY_HANDLE_FILE_INFORMATION (52 bytes)

.code

; =============================================================================
; file_path_allowed(rcx = wide path) -> eax = 1 allowed / 0 refused.
;   Pre-CreateFileW gate: blocks Win32 device namespace (\\.\, \\?\GLOBALROOT)
;   unconditionally and blocks UNC paths (\\server\..., \\?\UNC\...) before any
;   SMB/WebDAV NTLM handshake can occur unless HKLM AllowUncVault != 0.
; =============================================================================
public file_path_allowed
file_path_allowed proc
    test    rcx, rcx
    jz      fpa_no
    cmp     word ptr [rcx], 0
    je      fpa_no
    movzx   eax, word ptr [rcx]
    cmp     ax, 5Ch
    je      fpa_bs1
    cmp     ax, '/'
    jne     fpa_ok
fpa_bs1:
    movzx   eax, word ptr [rcx+2]
    cmp     ax, 5Ch
    je      fpa_bs2
    cmp     ax, '/'
    jne     fpa_ok
fpa_bs2:
    ; starts with "\\" or "//"
    movzx   eax, word ptr [rcx+4]
    cmp     ax, '.'
    je      fpa_no                              ; "\\.\" device namespace -> refuse
    cmp     ax, '?'
    jne     fpa_unc                             ; "\\server\..." -> check g_allow_unc
    movzx   eax, word ptr [rcx+6]
    cmp     ax, 5Ch
    je      fpa_qbody
    cmp     ax, '/'
    jne     fpa_no
fpa_qbody:
    ; "\\?\" prefix: allow "\\?\X:\..." local drive; check "\\?\UNC\..."; refuse others
    movzx   eax, word ptr [rcx+8]
    or      ax, 20h
    cmp     ax, 'a'
    jb      fpa_no
    cmp     ax, 'z'
    ja      fpa_no
    cmp     word ptr [rcx+10], ':'
    je      fpa_qdrive
    ; check "UNC\"
    cmp     ax, 'u'
    jne     fpa_no                              ; e.g. "\\?\GLOBALROOT\..." -> refuse
    movzx   eax, word ptr [rcx+10]
    or      ax, 20h
    cmp     ax, 'n'
    jne     fpa_no
    movzx   eax, word ptr [rcx+12]
    or      ax, 20h
    cmp     ax, 'c'
    jne     fpa_no
    movzx   eax, word ptr [rcx+14]
    cmp     ax, 5Ch
    je      fpa_unc
    cmp     ax, '/'
    je      fpa_unc
    jmp     fpa_no
fpa_qdrive:
    movzx   eax, word ptr [rcx+12]
    cmp     ax, 5Ch
    je      fpa_ok
    cmp     ax, '/'
    je      fpa_ok
    jmp     fpa_no
fpa_unc:
    cmp     dword ptr [g_allow_unc], 0
    je      fpa_no
fpa_ok:
    mov     eax, 1
    ret
fpa_no:
    xor     eax, eax
    ret
file_path_allowed endp

; =============================================================================
; file_validate_handle(rcx = hFile) -> eax = 1 valid disk file / 0 refused.
;   Post-CreateFileW handle gate:
;     1. GetFileType(h) == FILE_TYPE_DISK
;     2. GetFileInformationByHandle: (dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0
;     3. GetFinalPathNameByHandleW: resolves parent junctions / mapped drives;
;        enforces g_allow_unc on "\\?\UNC\..." and rejects NTFS ADS ':' streams.
; =============================================================================
public file_validate_handle
file_validate_handle proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    WINCALL GetFileType, rcx
    cmp     eax, FILE_TYPE_DISK_
    jne     fvh_no
    WINCALL GetFileInformationByHandle, qword ptr [rbp-24], addr fv_bhfi
    test    eax, eax
    jz      fvh_no
    test    dword ptr [fv_bhfi], 400h           ; FILE_ATTRIBUTE_REPARSE_POINT
    jnz     fvh_no
    WINCALL GetFinalPathNameByHandleW, qword ptr [rbp-24], addr fv_final, <MAX_PATH_CHARS + 16>, 0
    test    eax, eax
    jz      fvh_no
    cmp     eax, MAX_PATH_CHARS + 16
    jae     fvh_no
    mov     dword ptr [rbp-32], eax             ; cch
    lea     rcx, [fv_final]
    call    file_path_allowed                   ; catches junction/mapped-drive -> UNC
    test    eax, eax
    jz      fvh_no
    ; Scan fv_final for NTFS Alternate Data Stream ':' after drive colon
    lea     r10, [fv_final]
    mov     ecx, dword ptr [rbp-32]
    xor     r8d, r8d
fvh_colon_lp:
    cmp     r8d, ecx
    jae     fvh_ok
    cmp     word ptr [r10 + r8*2], ':'
    jne     fvh_colon_next
    cmp     r8d, 1                              ; "X:\..."
    je      fvh_colon_next
    cmp     r8d, 5                              ; "\\?\X:\..."
    jne     fvh_no
    cmp     word ptr [r10], 5Ch
    jne     fvh_no
    cmp     word ptr [r10+4], '?'
    jne     fvh_no
fvh_colon_next:
    inc     r8d
    jmp     fvh_colon_lp
fvh_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
fvh_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
file_validate_handle endp


; =============================================================================
public mem_alloc
mem_alloc proc frame
    FRAME_PROLOG 48
    xIFZ rcx
        mov     rcx, 1                   ; never request 0 bytes
    xENDIF
    call    tagged_alloc
    FRAME_EPILOG
    ret
mem_alloc endp

; =============================================================================
public mem_free
mem_free proc frame
    FRAME_PROLOG 48
    call    tagged_free
    FRAME_EPILOG
    ret
mem_free endp

; =============================================================================
; read_file(rcx = wpath, rdx = *outbuf, r8 = *outsize) -> eax
; =============================================================================
public read_file
; Both entry points convert the path here rather than at their call sites.  A
; long path is otherwise refused by CreateFileW no matter how big our buffers
; are, and doing it at the two chokepoints means an import, an export, an
; attachment and anything added later all get it without being told.
read_file proc frame
    FRAME_PROLOG 144                          ; [rbp-88] = the size cap; 144 puts the
                                              ;   CreateFileW/ReadFile stack args BELOW every
                                              ;   local (at 112 the 6th arg landed on the cap)
    ; [rbp-24]=outbuf* [rbp-32]=outsize* [rbp-40]=handle
    ; [rbp-48]=filesize [rbp-56]=buf [rbp-64]=cursor [rbp-72]=remaining
    mov     qword ptr [rbp-24], rdx           ; stash the OUT-PARAMS first: they live
    mov     qword ptr [rbp-32], r8            ;   in the two registers path_longify
                                              ;   needs for its own arguments
    mov     rax, qword ptr [g_rf_cap]         ; the one-shot cap is consumed HERE, on
    mov     qword ptr [rbp-88], rax           ;   every call: taken only after a successful
    mov     qword ptr [g_rf_cap], 0           ;   open, a failed open left it armed for the
                                              ;   next, unrelated read (a vault reload)
    lea     rdx, [rf_path]                    ; -> the form Win32 accepts
    mov     r8d, MAX_PATH_CHARS + 16
    call    path_longify
    mov     qword ptr [rbp-80], rax
    mov     rcx, rax
    call    file_path_allowed
    test    eax, eax
    jz      rf_denied
    mov     rcx, qword ptr [rbp-80]

    WINCALL CreateFileW, rcx, GENERIC_READ, FILE_SHARE_RWD, 0, OPEN_EXISTING, <FILE_ATTR_NORMAL or FILE_FLAG_OPEN_RP>, 0
    cmp     rax, -1
    je      rf_io
    mov     qword ptr [rbp-40], rax
    mov     rcx, rax
    call    file_validate_handle
    test    eax, eax
    jz      rf_badtype

    WINCALL GetFileSizeEx, qword ptr [rbp-40], addr rbp-48
    test    eax, eax
    jz      rf_io_close
    mov     rax, qword ptr [rbp-88]          ; the cap taken at entry
    test    rax, rax
    jz      rf_nocap
    cmp     qword ptr [rbp-48], rax
    ja      rf_toobig
rf_nocap:

    ; allocate buffer
    mov     rcx, qword ptr [rbp-48]
    call    mem_alloc
    test    rax, rax
    jz      rf_oom_close
    mov     qword ptr [rbp-56], rax
    mov     qword ptr [rbp-64], rax              ; cursor
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [rbp-72], rax              ; remaining

    xWHILE qword ptr [rbp-72], ne, 0         ; while bytes remain
        mov     r10, qword ptr [rbp-72]
        xIF r10, a, IO_CHUNK
            mov     r10, IO_CHUNK
        xENDIF
        WINCALL ReadFile, qword ptr [rbp-40], qword ptr [rbp-64], r10, addr rbp-80, 0
        test    eax, eax
        jz      rf_io_freebuf                    ; I/O error -> cleanup
        mov     r10d, dword ptr [rbp-80]
        xIFZ r10d                                ; 0 bytes read = EOF
            xBREAK
        xENDIF
        add     qword ptr [rbp-64], r10
        sub     qword ptr [rbp-72], r10
    xENDW
rf_ok:
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     rax, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-56]
    mov     qword ptr [rax], r10                 ; *outbuf
    mov     rax, qword ptr [rbp-32]
    mov     r10, qword ptr [rbp-64]              ; cursor - base = bytes ACTUALLY read
    sub     r10, qword ptr [rbp-56]              ;   (a file shrunk mid-read reports the
    mov     qword ptr [rax], r10                 ;   real count, not the pre-read filesize
    xor     eax, eax                             ;   with a zero-padded tail; the full-file
    jmp     rf_done                              ;   MAC still rejects such a truncated image)

rf_io_freebuf:
    mov     rcx, qword ptr [rbp-56]             ; wipe what was READ, not the whole
    mov     rdx, qword ptr [rbp-64]             ;   allocation: zeroing never-touched
    sub     rdx, rcx                            ;   pages only commits them
    call    mem_free
rf_io_close:
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     eax, EXIT_IO
    jmp     rf_done
rf_toobig:
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     eax, EXIT_TOOBIG
    jmp     rf_done
rf_oom_close:
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     eax, EXIT_OOM
    jmp     rf_done
rf_badtype:
    mov     dword ptr [g_io_err], 5             ; ERROR_ACCESS_DENIED (reparse/device/UNC refused)
    jmp     rf_io_close
rf_denied:
    mov     dword ptr [g_io_err], 5
    mov     eax, EXIT_IO
    jmp     rf_done
rf_io:
    call    GetLastError
    mov     dword ptr [g_io_err], eax
    mov     eax, EXIT_IO
rf_done:
    FRAME_EPILOG
    ret
read_file endp

; =============================================================================
; write_file(rcx = wpath, rdx = buf, r8 = size) -> eax
; =============================================================================
public write_file
write_file proc frame
    FRAME_PROLOG 128
    mov     dword ptr [g_wf_created], 0
    ; [rbp-24]=buf [rbp-32]=size [rbp-40]=handle [rbp-48]=cursor [rbp-56]=remaining
    mov     qword ptr [rbp-24], rdx           ; stash the buffer and size first - they
    mov     qword ptr [rbp-32], r8            ;   are in path_longify's argument
                                              ;   registers
    lea     rdx, [wf_path]                    ; -> the form Win32 accepts
    mov     r8d, MAX_PATH_CHARS + 16
    call    path_longify
    mov     rcx, rax

    mov     r10d, dword ptr [g_wf_disp]          ; C7: one-shot disposition (0 = default)
    mov     dword ptr [g_wf_disp], 0             ;     auto-reset so it applies once
    test    r10d, r10d
    jnz     @F
    mov     r10d, CREATE_ALWAYS
@@:
    mov     dword ptr [rbp-64], r10d
    mov     qword ptr [rbp-72], rcx
    call    file_path_allowed
    test    eax, eax
    jz      wf_denied
    mov     rcx, qword ptr [rbp-72]
    mov     r10d, dword ptr [rbp-64]
    WINCALL CreateFileW, rcx, GENERIC_WRITE, 0, 0, r10d, <FILE_ATTR_NORMAL or FILE_FLAG_OPEN_RP>, 0
    cmp     rax, -1
    je      wf_io
    mov     qword ptr [rbp-40], rax
    mov     rcx, rax
    call    file_validate_handle
    test    eax, eax
    jz      wf_badtype

    mov     rax, qword ptr [rbp-24]
    mov     dword ptr [g_wf_created], 1
    mov     qword ptr [rbp-48], rax              ; cursor
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-56], rax              ; remaining
    xWHILE qword ptr [rbp-56], ne, 0         ; while bytes remain
        mov     r10, qword ptr [rbp-56]
        xIF r10, a, IO_CHUNK
            mov     r10, IO_CHUNK
        xENDIF
        WINCALL WriteFile, qword ptr [rbp-40], qword ptr [rbp-48], r10, addr rbp-64, 0
        test    eax, eax
        jz      wf_io_close                      ; I/O error -> cleanup
        mov     r10d, dword ptr [rbp-64]
        test    r10d, r10d
        jz      wf_io_close                      ; 0 bytes written -> stop (no spin)
        add     qword ptr [rbp-48], r10
        sub     qword ptr [rbp-56], r10
    xENDW
wf_ok:
    ; force the bytes to the disk before we close (and, upstream, rename over the
    ; live vault): without this the temp file can still be in the cache when the
    ; atomic replace happens, so a power cut would leave a truncated vault.
    WINCALL FlushFileBuffers, qword ptr [rbp-40]
    test    eax, eax
    jz      wf_flush_close
    WINCALL CloseHandle, qword ptr [rbp-40]
    xor     eax, eax
    jmp     wf_done
wf_flush_close:
    ; A failed flush means durability was not established.  Never let an
    ; upstream atomic-replace path publish this image as a successful save.
    ; EXCEPT where the file system does not implement flushing at all (some network
    ; redirectors and virtual drives answer ERROR_INVALID_FUNCTION or
    ; ERROR_NOT_SUPPORTED): there was never any durability to establish, and failing
    ; would make every save on that volume fail forever while the data is written.
    call    GetLastError
    cmp     eax, 1                              ; ERROR_INVALID_FUNCTION
    je      wf_flush_nosupp
    cmp     eax, 50                             ; ERROR_NOT_SUPPORTED
    je      wf_flush_nosupp
    mov     dword ptr [g_io_err], eax
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     eax, EXIT_IO
    jmp     wf_done
wf_flush_nosupp:
    WINCALL CloseHandle, qword ptr [rbp-40]
    xor     eax, eax
    jmp     wf_done
wf_badtype:
    mov     dword ptr [g_io_err], 5             ; ERROR_ACCESS_DENIED (reparse/device refused)
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     eax, EXIT_IO
    jmp     wf_done
wf_denied:
    mov     dword ptr [g_io_err], 5
    mov     eax, EXIT_IO
    jmp     wf_done
wf_io_close:
    call    GetLastError                         ; capture BEFORE CloseHandle overwrites it
    mov     dword ptr [g_io_err], eax
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     eax, EXIT_IO
    jmp     wf_done
wf_io:
    call    GetLastError
    mov     dword ptr [g_io_err], eax
    mov     eax, EXIT_IO
wf_done:
    FRAME_EPILOG
    ret
write_file endp

; =============================================================================
; Handle-based primitives for streaming I/O
; =============================================================================








; file_rename(rcx = from, rdx = to) -> eax 0/EXIT_IO  (atomic replace).
;   WRITE_THROUGH flushes the rename itself to disk before returning, so the
;   directory entry can't be lost in a crash after we think the save succeeded.
;   The write lock on the target is held only for this call.  If the target is
;   momentarily locked by another program (sync tool, second instance), retry
;   once a second for up to 10s before giving up rather than losing the save
;   (redesign B2).  Only sharing/lock/access errors are retried; other errors
;   fail immediately.  (Blocking retry; a non-blocking WM_TIMER variant with UI
;   feedback is a planned follow-up.)
public file_rename
file_rename proc frame
    FRAME_PROLOG 80   ; >= 80: keep locals clear of ReplaceFileW's 6-arg spill area
    mov     qword ptr [rbp-24], rcx             ; from
    mov     qword ptr [rbp-32], rdx             ; to
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [fr_from]
    mov     r8d, MAX_PATH_CHARS + 16
    call    path_longify
    mov     qword ptr [rbp-24], rax
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [fr_to]
    mov     r8d, MAX_PATH_CHARS + 16
    call    path_longify
    mov     qword ptr [rbp-32], rax
    mov     dword ptr [rbp-40], 0               ; attempt count
frn_try:
    ; Prefer ReplaceFileW(to, from, NULL, REPLACEFILE_WRITE_THROUGH, 0, 0) so an
    ; existing target's DACLs, owner, encryption attributes, and creation metadata
    ; are preserved across saves; fall back to MoveFileExW when the target does
    ; not yet exist or the volume does not implement ReplaceFileW.
    WINCALL ReplaceFileW, qword ptr [rbp-32], qword ptr [rbp-24], 0, \
            REPLACEFILE_WRITE_THROUGH, 0, 0
    test    eax, eax
    jnz     frn_ok
    call    GetLastError
    mov     dword ptr [g_io_err], eax
    cmp     eax, 2                              ; ERROR_FILE_NOT_FOUND (dest absent)
    je      frn_move
    cmp     eax, 1                              ; ERROR_INVALID_FUNCTION
    je      frn_move
    cmp     eax, 50                             ; ERROR_NOT_SUPPORTED
    je      frn_move
    cmp     eax, 1177                           ; ERROR_UNABLE_TO_MOVE_REPLACEMENT_2
    je      frn_move
    cmp     eax, 5                              ; ERROR_ACCESS_DENIED -> try MoveFileExW
    je      frn_move
    cmp     eax, 32                             ; ERROR_SHARING_VIOLATION
    je      frn_retry
    cmp     eax, 33                             ; ERROR_LOCK_VIOLATION
    je      frn_retry
    cmp     eax, 1175                           ; ERROR_UNABLE_TO_REMOVE_REPLACED
    je      frn_retry
    cmp     eax, 1176                           ; ERROR_UNABLE_TO_MOVE_REPLACEMENT
    je      frn_retry
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
frn_move:
    WINCALL MoveFileExW, qword ptr [rbp-24], qword ptr [rbp-32], \
            <MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH>
    test    eax, eax
    jnz     frn_ok
    call    GetLastError                        ; read the failure reason immediately
    mov     dword ptr [g_io_err], eax
    cmp     eax, 32                             ; ERROR_SHARING_VIOLATION
    je      frn_retry
    cmp     eax, 33                             ; ERROR_LOCK_VIOLATION
    je      frn_retry
    cmp     eax, 5                              ; ERROR_ACCESS_DENIED
    je      frn_retry
    mov     eax, EXIT_IO                        ; other error -> fail now
    FRAME_EPILOG
    ret
frn_retry:
    mov     eax, dword ptr [rbp-40]
    inc     eax
    mov     dword ptr [rbp-40], eax
    cmp     eax, 10                             ; 10 attempts (~9s) then give up
    jae     frn_io
    WINCALL Sleep, 1000
    jmp     frn_try
frn_io:
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
frn_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
file_rename endp



.data
align 2
pfx_q       dw 5Ch,5Ch,'?',5Ch,0                     ; "\\?\"
pfx_unc     dw 5Ch,5Ch,'?',5Ch,'U','N','C',5Ch,0     ; "\\?\UNC\"

.code

; =============================================================================
; path_longify(rcx = src wide path, rdx = dst buffer, r8d = dst cap in chars)
;   -> rax = the path to hand to Win32: dst when a prefix was added, otherwise
;      rcx unchanged.
;
; vordr.manifest declares longPathAware, which is necessary and not sufficient:
; it only takes effect when the machine also has
; HKLM\SYSTEM\CurrentControlSet\Control\FileSystem : LongPathsEnabled = 1, and
; that is 0 by default.  On such a machine every Win32 path API still enforces
; MAX_PATH (260), whatever the manifest says.  The "\\?\" prefix does not depend
; on the policy - it is the escape hatch the kernel honours unconditionally - so
; that is what actually buys long paths.
;
; Applied only to paths that NEED it (>= PATH_LONG_MIN).  "\\?\" also switches
; off path normalisation: no "." or ".." collapsing, no trailing-space or
; trailing-dot trimming, forward slashes no longer accepted.  Turning that off
; for every path in a program that opens the user's vault would be a semantic
; change for the sake of a case almost nobody hits, so short paths are handed
; back untouched and keep the normal rules.
;
; Handles the two forms that can be prefixed:
;     C:\very\long\...        ->  \\?\C:\very\long\...
;     \\server\share\...      ->  \\?\UNC\server\share\...
; A relative path cannot be prefixed at all ("\\?\" requires a fully-qualified
; path) and is returned unchanged; so is one that is already prefixed.
; =============================================================================
PATH_LONG_MIN   equ 248             ; MAX_PATH(260) less room for a "\name.tmp" tail
; The smallest destination this will write into.  pl_rel subtracts the 8-char
; prefix head from the caller's capacity and hands the remainder to
; GetFullPathNameW as nBufferLength - so a capacity under 8 would wrap to
; ~4 billion and invite it to write as far as it liked.  Every caller passes
; MAX_PATH_CHARS + 16, but that is a fact about the callers, not a property of
; this proc, and it is the callers that change.
PATH_MIN_CAP    equ 32

; path_io(rcx = raw wide path) -> rax = the path to store in g_cfg_in.
;   Everything the vault layer touches is derived from g_cfg_in as a string -
;   "<vault>.tmp", "<vault>.lock", "<vault>.bak0" - so converting the base here
;   converts all of them, and there is exactly one place to get it right.  The
;   copy is static and single-slot: g_cfg_in names one vault at a time, which is
;   the same assumption the rest of the vault layer already makes.
; cfg_in_set(rcx = raw wide path) -> rax = the pointer now in g_cfg_in.
;
;   The ONE way g_cfg_in is set.  It used to be assigned directly in 37 places
;   across three files, and after long-path support went in, some of those
;   assignments stored a converted path and the rest stored a raw one.  Both
;   worked - the consumers convert - but "is g_cfg_in raw?" had no single
;   answer, and an invariant nobody can state is one that gets broken by the
;   next change rather than by this one.
;
;   It preserves every volatile register.  Several of the 37 sites assign
;   g_cfg_in in the middle of a sequence that has other things live, and making
;   each of them prove it does not care is how a mechanical change turns into a
;   bug hunt.  tools/wstrcheck.py fails the build on a direct assignment.
public cfg_in_set
cfg_in_set proc frame
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 96
    .allocstack 96
    .endprolog
    mov     qword ptr [rbp-16], rdx
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    mov     qword ptr [rbp-40], r10
    mov     qword ptr [rbp-48], r11
    call    path_io
    mov     qword ptr [g_cfg_in], rax
    mov     rdx, qword ptr [rbp-16]
    mov     r8,  qword ptr [rbp-24]
    mov     r9,  qword ptr [rbp-32]
    mov     r10, qword ptr [rbp-40]
    mov     r11, qword ptr [rbp-48]
    mov     rsp, rbp
    pop     rbp
    ret
cfg_in_set endp

public path_io
path_io proc frame
    FRAME_PROLOG 48
    lea     rdx, [ci_path]
    mov     r8d, MAX_PATH_CHARS + 16
    call    path_longify
    FRAME_EPILOG
    ret
path_io endp

public path_longify
path_longify proc frame
    FRAME_PROLOG 96                           ; locals to rbp-64, clear of the
                                              ;   callee home area below them
    mov     qword ptr [rbp-24], rcx           ; src
    mov     qword ptr [rbp-32], rdx           ; dst
    mov     dword ptr [rbp-40], r8d           ; cap
    cmp     r8d, PATH_MIN_CAP                 ; too small to build anything in:
    jb      pl_asis                           ;   hand the path back untouched
    ; ---- length -----------------------------------------------------------
    mov     r10, rcx
    xor     r8d, r8d
pl_len:
    cmp     word ptr [r10+r8*2], 0
    je      pl_have
    inc     r8d
    cmp     r8d, MAX_PATH_CHARS
    jb      pl_len
pl_have:
    mov     dword ptr [rbp-48], r8d           ; length in chars
    ; ---- classify BEFORE deciding whether it is long ----------------------
    ; The threshold cannot be applied to a relative path's own length: "v.vordr"
    ; is seven characters and still resolves past MAX_PATH when the current
    ; directory is deep, which is the ordinary way a relative long path happens.
    ; A relative path is measured against the directory it will resolve against.
    mov     r10, qword ptr [rbp-24]
    cmp     word ptr [r10], 5Ch
    jne     pl_cl_drive
    cmp     word ptr [r10+2], 5Ch
    jne     pl_asis                           ; a lone leading backslash: leave it
    cmp     word ptr [r10+4], '?'
    je      pl_asis                           ; already prefixed
    mov     dword ptr [rbp-72], 1             ; kind = UNC
    jmp     pl_measure
pl_cl_drive:
    cmp     word ptr [r10+2], ':'
    jne     pl_cl_rel
    cmp     word ptr [r10+4], 5Ch
    jne     pl_cl_rel                         ; "X:name" is drive-relative
    mov     dword ptr [rbp-72], 2             ; kind = drive-absolute
    jmp     pl_measure
pl_cl_rel:
    mov     dword ptr [rbp-72], 3             ; kind = relative
    WINCALL GetCurrentDirectoryW, 0, 0        ; -> chars needed, including the NUL
    test    eax, eax
    jz      pl_asis
    add     eax, dword ptr [rbp-48]           ; + this path, + the separator the
    mov     dword ptr [rbp-48], eax           ;   NUL already accounts for
pl_measure:
    mov     eax, dword ptr [rbp-48]
    cmp     eax, PATH_LONG_MIN
    jb      pl_asis                           ; short enough for the normal rules
    cmp     dword ptr [rbp-72], 3
    je      pl_rel
    cmp     dword ptr [rbp-72], 1
    jne     pl_drive
    ; ---- UNC: "\\server\..." -> "\\?\UNC\server\..." ----------------------
    mov     eax, dword ptr [rbp-48]
    add     eax, 8
    cmp     eax, dword ptr [rbp-40]
    jae     pl_asis                           ; would not fit: unchanged, and it
                                              ;   fails exactly as it did before
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [pfx_unc]
    call    pl_copy
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-24]
    add     rdx, 4                            ; skip the leading "\\"
    call    pl_copy
    ; advance collapse floor past "\\?\UNC\server\share\"
    mov     rcx, qword ptr [rbp-32]
    add     rcx, 16                           ; past "\\?\UNC\"
    xor     edx, edx                          ; count 2 slashes (server\share\)
pl_unc_shr:
    movzx   eax, word ptr [rcx]
    test    ax, ax
    jz      pl_unc_done
    add     rcx, 2
    cmp     ax, 5Ch
    je      pl_unc_sl
    cmp     ax, '/'
    jne     pl_unc_shr
pl_unc_sl:
    mov     word ptr [rcx-2], 5Ch
    inc     edx
    cmp     edx, 2
    jb      pl_unc_shr
    call    pl_collapse
pl_unc_done:
    mov     rax, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
pl_drive:
    ; ---- drive-absolute: "X:\..." -> "\\?\X:\..." -------------------------
    mov     eax, dword ptr [rbp-48]
    add     eax, 5                            ; "\\?\" + NUL
    cmp     eax, dword ptr [rbp-40]
    jae     pl_asis
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [pfx_q]
    call    pl_copy
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-24]
    call    pl_copy
    mov     rcx, qword ptr [rbp-32]
    mov     word ptr [rcx+12], 5Ch            ; normalise drive root slash ("X:/" -> "X:\")
    add     rcx, 14                           ; floor right after "\\?\X:\"
    call    pl_collapse
    mov     rax, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
pl_rel:
    ; ---- relative, and it resolves past what Win32 will take ---------------
    ; "\\?\" requires a fully-qualified path, so a relative one has to be
    ; resolved against the current directory first.
    ;
    ; GetFullPathNameW writes the result EIGHT CHARACTERS IN, which is the whole
    ; trick: the longest prefix this proc ever adds is "\\?\UNC\", also eight, so
    ; the room is already there and the prefix is written backwards into the gap.
    ; Expanding at the start of the buffer would mean shifting the whole path
    ; afterwards to make room for it.
    mov     rax, qword ptr [rbp-32]
    add     rax, 16                           ; dst + 8 chars
    mov     qword ptr [rbp-64], rax
    mov     eax, dword ptr [rbp-40]
    sub     eax, 8                            ; the reserved head
    mov     dword ptr [rbp-56], eax
    WINCALL GetFullPathNameW, qword ptr [rbp-24], dword ptr [rbp-56], \
            qword ptr [rbp-64], 0
    test    eax, eax
    jz      pl_asis                           ; could not resolve: unchanged
    cmp     eax, dword ptr [rbp-56]
    jae     pl_asis                           ; did not fit: unchanged
    mov     r10, qword ptr [rbp-32]           ; dst
    cmp     word ptr [r10+16], 5Ch            ; resolved to a UNC path?
    jne     pl_rel_drive
    cmp     word ptr [r10+18], 5Ch
    jne     pl_rel_drive
    ; "\\server\..." sits at char 8; write "\\?\UNC\" over chars 2..9 so the
    ; "server" already at char 10 continues the string.
    mov     word ptr [r10+4],  5Ch
    mov     word ptr [r10+6],  5Ch
    mov     word ptr [r10+8],  '?'
    mov     word ptr [r10+10], 5Ch
    mov     word ptr [r10+12], 'U'
    mov     word ptr [r10+14], 'N'
    mov     word ptr [r10+16], 'C'
    mov     word ptr [r10+18], 5Ch
    lea     rax, [r10+4]
    FRAME_EPILOG
    ret
pl_rel_drive:
    cmp     word ptr [r10+18], ':'            ; "X:\..." at char 8?
    jne     pl_asis
    mov     word ptr [r10+8],  5Ch            ; "\\?\" over chars 4..7
    mov     word ptr [r10+10], 5Ch
    mov     word ptr [r10+12], '?'
    mov     word ptr [r10+14], 5Ch
    lea     rax, [r10+8]
    FRAME_EPILOG
    ret
pl_asis:
    mov     rax, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
path_longify endp

; pl_copy(rcx = dst, rdx = src) -> rax = the NUL written.  Bounded by the caller
;   having checked the total above; kept private so nothing else can call it
;   without that check.
pl_copy proc
    xor     r8d, r8d
plc_l:
    mov     ax, word ptr [rdx+r8*2]
    mov     word ptr [rcx+r8*2], ax
    test    ax, ax
    jz      plc_d
    inc     r8d
    cmp     r8d, MAX_PATH_CHARS
    jb      plc_l
plc_d:
    lea     rax, [rcx+r8*2]
    ret
pl_copy endp

; pl_collapse(rcx = floor_ptr) - in-place Win32 path normaliser for "\\?\" paths:
;   converts '/' -> '\', collapses "\\", "\.\", and "\seg\..\" (never retreating
;   past floor_ptr), and trims trailing dots/spaces.  Leaf; clobbers volatiles.
pl_collapse proc
    mov     r8, rcx                             ; floor
    mov     r9, rcx
plc_slash:
    movzx   eax, word ptr [r9]
    test    ax, ax
    jz      plc_scan_init
    cmp     ax, '/'
    jne     @F
    mov     word ptr [r9], 5Ch
@@: add     r9, 2
    jmp     plc_slash
plc_scan_init:
    mov     r9, r8                              ; read cursor
    mov     r10, r8                             ; write cursor
plc_seg_lp:
    cmp     word ptr [r9], 5Ch
    jne     plc_seg_start
    add     r9, 2
    jmp     plc_seg_lp
plc_seg_start:
    cmp     word ptr [r9], 0
    je      plc_finish
    mov     r11, r9                             ; find segment end
plc_find_end:
    movzx   eax, word ptr [r11]
    test    ax, ax
    jz      plc_got_end
    cmp     ax, 5Ch
    je      plc_got_end
    add     r11, 2
    jmp     plc_find_end
plc_got_end:
    mov     rax, r11
    sub     rax, r9                             ; byte length of segment
    cmp     rax, 2                              ; "." (1 wchar = 2 bytes)?
    jne     plc_chk_dd
    cmp     word ptr [r9], '.'
    jne     plc_emit
    mov     r9, r11
    jmp     plc_seg_lp
plc_chk_dd:
    cmp     rax, 4                              ; ".." (2 wchars = 4 bytes)?
    jne     plc_emit
    cmp     word ptr [r9], '.'
    jne     plc_emit
    cmp     word ptr [r9+2], '.'
    jne     plc_emit
    ; pop previous segment back to floor r8
    cmp     r10, r8
    jbe     plc_dd_next
    cmp     word ptr [r10-2], 5Ch
    jne     plc_dd_back
    sub     r10, 2
plc_dd_back:
    cmp     r10, r8
    jbe     plc_dd_sl
    cmp     word ptr [r10-2], 5Ch
    je      plc_dd_sl
    sub     r10, 2
    jmp     plc_dd_back
plc_dd_sl:
    cmp     r10, r8
    jbe     plc_dd_next
    cmp     word ptr [r10-2], 5Ch
    jne     plc_dd_next
    sub     r10, 2
plc_dd_next:
    mov     r9, r11
    jmp     plc_seg_lp
plc_emit:
    cmp     r10, r8
    jbe     plc_cp_lp
    mov     word ptr [r10], 5Ch
    add     r10, 2
plc_cp_lp:
    cmp     r9, r11
    jae     plc_seg_lp
    mov     ax, word ptr [r9]
    mov     word ptr [r10], ax
    add     r9, 2
    add     r10, 2
    jmp     plc_cp_lp
plc_finish:
    cmp     r10, r8
    jbe     plc_nul
    movzx   eax, word ptr [r10-2]
    cmp     ax, ' '
    je      plc_trim1
    cmp     ax, '.'
    jne     plc_nul
plc_trim1:
    sub     r10, 2
    jmp     plc_finish
plc_nul:
    mov     word ptr [r10], 0
    ret
pl_collapse endp

end
