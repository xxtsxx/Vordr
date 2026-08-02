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

extern CreateFileW:proc
extern GetLastError:proc
extern Sleep:proc
extern ReadFile:proc
extern WriteFile:proc
extern GetFileSizeEx:proc
extern SetFilePointerEx:proc
extern CloseHandle:proc
extern VirtualAlloc:proc
extern VirtualFree:proc
extern MoveFileExW:proc
extern DeleteFileW:proc
extern CopyFileW:proc
extern FlushFileBuffers:proc
extern GetDiskFreeSpaceExW:proc
extern GetFullPathNameW:proc            ; a relative long path must be resolved first
extern GetCurrentDirectoryW:proc        ; ...and measured against what it resolves to
extern secure_zero:proc

MOVEFILE_REPLACE_EXISTING equ 1
MOVEFILE_WRITE_THROUGH    equ 8

GENERIC_READ        equ 80000000h
GENERIC_WRITE       equ 40000000h
FILE_SHARE_RWD      equ 7               ; READ|WRITE|DELETE - read-only-by-default opens
                                        ;   never block another writer / sync tool (redesign B1)
OPEN_EXISTING       equ 3
CREATE_ALWAYS       equ 2
FILE_ATTR_NORMAL    equ 80h
MEM_COMMIT          equ 1000h
MEM_RESERVE         equ 2000h
MEM_RELEASE         equ 8000h
PAGE_READWRITE      equ 04h
IO_CHUNK            equ 1000000h         ; 16 MiB per ReadFile/WriteFile

.data?
public g_io_err
g_io_err    dd ?                 ; Win32 error from the last failed write/rename.
                                 ;   Lets a caller distinguish transient contention
                                 ;   (a sync client holding the file) from a real
                                 ;   failure, instead of seeing a flat EXIT_IO.
align 4
public g_wf_disp
g_wf_disp   dd ?                       ; C7: one-shot write_file disposition override
align 2                               ;     (0 = CREATE_ALWAYS default; caller sets CREATE_NEW)

.code


; =============================================================================
public mem_alloc
mem_alloc proc frame
    FRAME_PROLOG 48
    xIFZ rcx
        mov     rcx, 1                   ; never request 0 bytes
    xENDIF
    WINCALL VirtualAlloc, 0, rcx, <MEM_RESERVE or MEM_COMMIT>, PAGE_READWRITE
    FRAME_EPILOG
    ret
mem_alloc endp

; =============================================================================
public mem_free
mem_free proc frame
    FRAME_PROLOG 48
    xIFT rcx                             ; ptr != 0
        mov     qword ptr [rbp-24], rcx
        xIFT rdx                         ; len != 0 -> wipe before release
            call    secure_zero          ; (rcx=ptr, rdx=len)
        xENDIF
        WINCALL VirtualFree, qword ptr [rbp-24], 0, MEM_RELEASE
    xENDIF
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
    FRAME_PROLOG 96
    ; [rbp-24]=outbuf* [rbp-32]=outsize* [rbp-40]=handle
    ; [rbp-48]=filesize [rbp-56]=buf [rbp-64]=cursor [rbp-72]=remaining
    mov     qword ptr [rbp-24], rdx           ; stash the OUT-PARAMS first: they live
    mov     qword ptr [rbp-32], r8            ;   in the two registers path_longify
                                              ;   needs for its own arguments
    lea     rdx, [rf_path]                    ; -> the form Win32 accepts
    mov     r8d, MAX_PATH_CHARS + 16
    call    path_longify
    mov     rcx, rax

    WINCALL CreateFileW, rcx, GENERIC_READ, FILE_SHARE_RWD, 0, OPEN_EXISTING, FILE_ATTR_NORMAL, 0
    cmp     rax, -1
    je      rf_io
    mov     qword ptr [rbp-40], rax

    WINCALL GetFileSizeEx, rax, addr rbp-48
    test    eax, eax
    jz      rf_io_close

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
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-48]
    call    mem_free
rf_io_close:
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     eax, EXIT_IO
    jmp     rf_done
rf_oom_close:
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     eax, EXIT_OOM
    jmp     rf_done
rf_io:
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
    FRAME_PROLOG 96
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
    WINCALL CreateFileW, rcx, GENERIC_WRITE, 0, 0, r10d, FILE_ATTR_NORMAL, 0
    cmp     rax, -1
    je      wf_io
    mov     qword ptr [rbp-40], rax

    mov     rax, qword ptr [rbp-24]
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
    WINCALL CloseHandle, qword ptr [rbp-40]
    xor     eax, eax
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
    FRAME_PROLOG 64   ; >= 64: keep locals clear of the callee 32-byte home area
    mov     qword ptr [rbp-24], rcx             ; from
    mov     qword ptr [rbp-32], rdx             ; to
    ; Both ends need the Win32 form.  The atomic save renames "<vault>.tmp" onto
    ; "<vault>", and the destination came straight from g_cfg_in - so on a long
    ; path the temp file was written correctly and then could not be moved into
    ; place, leaving a .tmp orphan next to a vault that never got the update.
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
align 2
; These are single-slot and process-wide.  That is safe because file work is
; serialised: the only worker thread (secdesk) runs while the main thread blocks
; waiting for it, so one caller is in here at a time.  The exception is the
; watchdog's orphan path in gui_secdesk_show - see the comment there - where an
; abandoned worker keeps running; in that window these are shared, along with
; every other piece of vault state, and the answer is not a lock on these.
ci_path     dw (MAX_PATH_CHARS + 16) dup (?)   ; the vault path g_cfg_in points at
fr_from     dw (MAX_PATH_CHARS + 16) dup (?)   ; file_rename's two paths are live at
fr_to       dw (MAX_PATH_CHARS + 16) dup (?)   ;   the same time, so two buffers
rf_path     dw (MAX_PATH_CHARS + 16) dup (?)   ; read_file's Win32-form path
wf_path     dw (MAX_PATH_CHARS + 16) dup (?)   ; write_file's, kept separate so a
                                               ;   read during a write cannot share it
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
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    mov     qword ptr [rbp-40], r9
    mov     qword ptr [rbp-48], r10
    mov     qword ptr [rbp-56], r11
    call    path_io
    mov     qword ptr [g_cfg_in], rax
    mov     rdx, qword ptr [rbp-24]
    mov     r8,  qword ptr [rbp-32]
    mov     r9,  qword ptr [rbp-40]
    mov     r10, qword ptr [rbp-48]
    mov     r11, qword ptr [rbp-56]
    FRAME_EPILOG
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

end
