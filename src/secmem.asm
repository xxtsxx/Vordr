; =============================================================================
; secmem.asm - locked secret memory for decrypted vault / pad material
; -----------------------------------------------------------------------------
;   secmem_alloc(rcx = len) -> rax = ptr (page-granular) or 0
;       VirtualAlloc(PAGE_READWRITE) then VirtualLock so the plaintext is never
;       written to the pagefile.  This is a core hostile-OS defense: decrypted
;       secrets must not leak through swap or a hibernation image.
;
;   secmem_free(rcx = ptr, rdx = len)
;       secure_zero the region, VirtualUnlock, VirtualFree.  Fail-closed: a NULL
;       pointer is a no-op; the wipe always runs before the pages are released.
;
; NOTE: VirtualLock is best-effort (it can fail if the process working-set
; minimum is too small).  We treat a lock failure as non-fatal here but the
; allocation still succeeds; a future step may raise the working-set quota via
; SetProcessWorkingSetSize so the lock is guaranteed.  Against a fully
; compromised *kernel* this is a cost-raiser, not an absolute guarantee
; (documented in docs/formats.md).
; =============================================================================

include macros.inc

extern VirtualAlloc:proc
extern VirtualFree:proc
extern VirtualLock:proc
extern VirtualUnlock:proc
extern secure_zero:proc

MEM_COMMIT          equ 1000h
MEM_RESERVE         equ 2000h
MEM_RELEASE         equ 8000h
PAGE_READWRITE      equ 04h

.code

public secmem_alloc
secmem_alloc proc frame
    FRAME_PROLOG 48
    ; locals: [rbp-24] len, [rbp-32] base
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], 0
    test    rcx, rcx
    jz      sa_fail                         ; zero-length: fail closed

    WINCALL VirtualAlloc, 0, qword ptr [rbp-24], <MEM_RESERVE or MEM_COMMIT>, PAGE_READWRITE
    test    rax, rax
    jz      sa_fail
    mov     qword ptr [rbp-32], rax         ; remember the base across the lock call

    ; VirtualLock(addr, len) - keep it resident / out of the pagefile.
    ; Best-effort: a lock failure does not invalidate the allocation.
    WINCALL VirtualLock, qword ptr [rbp-32], qword ptr [rbp-24]

    mov     rax, qword ptr [rbp-32]         ; return the (locked) base
    FRAME_EPILOG
    ret
sa_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
secmem_alloc endp

public secmem_free
secmem_free proc frame
    FRAME_PROLOG 48
    ; locals: [rbp-24] ptr, [rbp-32] len
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    test    rcx, rcx
    jz      sf_done

    ; wipe first - secrets must be gone before the pages can be reused
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    secure_zero

    WINCALL VirtualUnlock, qword ptr [rbp-24], qword ptr [rbp-32]
    WINCALL VirtualFree, qword ptr [rbp-24], 0, MEM_RELEASE
sf_done:
    FRAME_EPILOG
    ret
secmem_free endp

end
