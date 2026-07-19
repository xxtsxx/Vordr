; =============================================================================
; fileio.asm - file read/write and memory helpers
; -----------------------------------------------------------------------------
;   mem_alloc(rcx = size)               -> rax = ptr (0 on failure)
;   mem_free (rcx = ptr, rdx = size)    (wipes then releases)
;   read_file(rcx = wpath, rdx = *outbuf, r8 = *outsize) -> eax 0 / EXIT_IO
;   write_file(rcx = wpath, rdx = buf, r8 = size)        -> eax 0 / EXIT_IO
; =============================================================================

include macros.inc

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
align 2

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
read_file proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=outbuf* [rbp-32]=outsize* [rbp-40]=handle
    ; [rbp-48]=filesize [rbp-56]=buf [rbp-64]=cursor [rbp-72]=remaining
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8

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
    mov     r10, qword ptr [rbp-48]
    mov     qword ptr [rax], r10                 ; *outsize
    xor     eax, eax
    jmp     rf_done

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
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8

    WINCALL CreateFileW, rcx, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTR_NORMAL, 0
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
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     eax, EXIT_IO
    jmp     wf_done
wf_io:
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
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx             ; from
    mov     qword ptr [rbp-32], rdx             ; to
    mov     dword ptr [rbp-40], 0               ; attempt count
frn_try:
    WINCALL MoveFileExW, qword ptr [rbp-24], qword ptr [rbp-32], \
            <MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH>
    test    eax, eax
    jnz     frn_ok
    call    GetLastError                        ; read the failure reason immediately
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


end
