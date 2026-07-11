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
extern GetCurrentProcess:proc
extern SetProcessWorkingSetSize:proc

; the fixed static secret buffers, locked once at startup by sec_lock_statics
externdef g_cfg_pass:byte           ; master password (main.asm)
externdef g_vkey:byte               ; derived vault key (vault.asm)
externdef g_pwbuf:byte              ; unlock/create password field (gui.asm)
externdef g_pw2buf:byte             ; confirm-password field (gui.asm)
externdef g_secret_w:byte           ; revealed secret for reveal/copy (gui.asm)
externdef g_e_totp:byte             ; entry-form TOTP key (gui.asm)
externdef g_totp_b32:byte           ; selected entry TOTP key (gui.asm)

MEM_COMMIT          equ 1000h
MEM_RESERVE         equ 2000h
MEM_RELEASE         equ 8000h
PAGE_READWRITE      equ 04h
SEC_WS_MIN          equ 00800000h   ; 8 MiB min working set (room for locked pages)
SEC_WS_MAX          equ 04000000h   ; 64 MiB max

.code

; =============================================================================
; sec_lock(rcx = ptr, rdx = len) -> eax = nonzero if the region is now locked.
;   VirtualLock keeps the pages resident (out of the pagefile).  It is capped by
;   the process working-set minimum, so on a first failure we grow the working
;   set and retry once.  Best-effort: a persistent failure returns 0.
; =============================================================================
public sec_lock
sec_lock proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    WINCALL VirtualLock, qword ptr [rbp-24], qword ptr [rbp-32]
    test    eax, eax
    jnz     sl_done
    ; working set too small -> grow it, then retry the lock
    WINCALL GetCurrentProcess
    WINCALL SetProcessWorkingSetSize, rax, SEC_WS_MIN, SEC_WS_MAX
    WINCALL VirtualLock, qword ptr [rbp-24], qword ptr [rbp-32]
sl_done:
    FRAME_EPILOG
    ret
sec_lock endp

; =============================================================================
; sec_lock_statics() - VirtualLock every fixed static secret buffer.  Called
;   once from start (main.asm) after hardening_init; the pages are committed at
;   load, so the locks hold for the process lifetime (these buffers are always
;   secret-capable and are never unlocked).  See docs/SECRETS.md.
; =============================================================================
public sec_lock_statics
sec_lock_statics proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_cfg_pass]
    mov     edx, 1025
    call    sec_lock
    lea     rcx, [g_vkey]
    mov     edx, 32
    call    sec_lock
    lea     rcx, [g_pwbuf]
    mov     edx, 2048
    call    sec_lock
    lea     rcx, [g_pw2buf]
    mov     edx, 2048
    call    sec_lock
    lea     rcx, [g_secret_w]
    mov     edx, 16384
    call    sec_lock
    lea     rcx, [g_e_totp]
    mov     edx, 512
    call    sec_lock
    lea     rcx, [g_totp_b32]
    mov     edx, 256
    call    sec_lock
    FRAME_EPILOG
    ret
sec_lock_statics endp

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

    ; keep it resident / out of the pagefile (grows the working set if needed).
    ; Best-effort: a lock failure does not invalidate the allocation.
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-24]
    call    sec_lock

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
