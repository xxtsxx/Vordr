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
extern vault_slots_lock:proc            ; vault.asm: VirtualLock the g_vaults table
extern vault_panic_wipe_slots:proc      ; vault.asm: crash-path wipe of slot secrets
extern GetCurrentProcess:proc
extern SetProcessWorkingSetSize:proc
extern rng_fill:proc
extern VirtualQuery:proc
extern print_a:proc
externdef g_cfg_passlen:dword

; the fixed static secret buffers, locked once at startup by sec_lock_statics
externdef g_cfg_pass:byte           ; master password (main.asm)
externdef g_vkey:byte               ; derived vault key (vault.asm)
externdef g_pwbuf:byte              ; unlock/create password field (gui.asm)
externdef g_pw2buf:byte             ; confirm-password field (gui.asm)
externdef g_secret_w:byte           ; revealed secret for reveal/copy (gui.asm)
externdef g_rowpw_w:byte            ; reveal-overlay secret copy (gui.asm)
externdef g_e_totp:byte             ; entry-form TOTP key (gui.asm)
externdef g_totp_b32:byte           ; selected entry TOTP key (gui.asm)
externdef g_body_ptr:qword          ; decrypted vault body arena (vault.asm)
externdef g_body_len:qword

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
    cmp     dword ptr [g_force_lockfail], 0     ; C3 test hook: force a lock failure
    jne     sl_failed
    WINCALL VirtualLock, qword ptr [rbp-24], qword ptr [rbp-32]
    test    eax, eax
    jnz     sl_done
    ; working set too small -> grow it, then retry the lock
    WINCALL GetCurrentProcess
    WINCALL SetProcessWorkingSetSize, rax, SEC_WS_MIN, SEC_WS_MAX
    WINCALL VirtualLock, qword ptr [rbp-24], qword ptr [rbp-32]
    test    eax, eax
    jz      sl_failed
sl_done:
    mov     eax, 1                              ; locked
    FRAME_EPILOG
    ret
sl_failed:
    ; C3: a secret buffer could not be pinned - it may reach the pagefile.  Record
    ; it (the GUI shows a one-time warning; we do NOT fail closed, which would lock
    ; the user out of their own vault on a constrained system).
    mov     dword ptr [g_seclock_failed], 1
    xor     eax, eax
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
    lea     rcx, [g_rowpw_w]                   ; D6: lock the reveal-overlay copy too
    mov     edx, 512*2
    call    sec_lock
    lea     rcx, [g_e_totp]
    mov     edx, 512
    call    sec_lock
    lea     rcx, [g_totp_b32]
    mov     edx, 256
    call    sec_lock
    call    vault_slots_lock                  ; the g_vaults table (slot master keys)
    FRAME_EPILOG
    ret
sec_lock_statics endp

; =============================================================================
; secmem_panic_wipe() - zero every live secret buffer in one shot.  Called from
;   the unhandled-exception filter (hardening.asm) BEFORE the process dies, so a
;   crash can never leave key material in a minidump / hibernation image.  It
;   only secure_zero's known buffers (the fixed statics + the decrypted body) -
;   no allocation, no frees - because the heap may already be corrupt at crash
;   time.  Safe to call redundantly.
; =============================================================================
public secmem_panic_wipe
secmem_panic_wipe proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_cfg_pass]
    mov     edx, 1025
    call    secure_zero
    lea     rcx, [g_vkey]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_pwbuf]
    mov     edx, 2048
    call    secure_zero
    lea     rcx, [g_pw2buf]
    mov     edx, 2048
    call    secure_zero
    lea     rcx, [g_secret_w]
    mov     edx, 16384
    call    secure_zero
    lea     rcx, [g_e_totp]
    mov     edx, 512
    call    secure_zero
    lea     rcx, [g_totp_b32]
    mov     edx, 256
    call    secure_zero
    mov     rax, qword ptr [g_body_ptr]         ; decrypted vault body, if resident
    test    rax, rax
    jz      spw_slots
    mov     rcx, rax
    mov     rdx, qword ptr [g_body_len]
    call    secure_zero
spw_slots:
    call    vault_panic_wipe_slots            ; every open context's key + body
spw_done:
    FRAME_EPILOG
    ret
secmem_panic_wipe endp

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

; =============================================================================
; cmd_secscan (probe) - prove the secret-wipe path leaves no residue.
;   Plant a random 16-byte sentinel into g_cfg_pass; scan this process's own
;   committed read/write pages for it (must find the plant -> the scanner
;   works); wipe g_cfg_pass with the real secure_zero; scan again (must find 0
;   -> the wipe removed it).  The reference copy in secscan_ref is excluded by
;   address.  exit 0 = pass.
; =============================================================================
.data?
secscan_ref db 16 dup (?)               ; runtime-random reference sentinel
align 8
ss_mbi      db 48 dup (?)               ; MEMORY_BASIC_INFORMATION (static: no stack use)
align 4
public g_seclock_failed
g_seclock_failed dd ?                    ; C3: set if any VirtualLock failed (pageable secret)
public g_force_lockfail
g_force_lockfail dd ?                    ; C3: test hook - force sec_lock to fail

.code
CSTR ss_pass, "secscan: PASS (sentinel found before wipe, absent after)",13,10
CSTR ss_res,  "secscan: FAIL (sentinel survived the wipe)",13,10
CSTR ss_blind,"secscan: FAIL (scanner never found the plant)",13,10
CSTR lk_ok,   "lktest: PASS (VirtualLock failure detected + recovered)",13,10
CSTR lk_bad,  "lktest: FAIL",13,10

; ss_scan() -> eax = count of 16-byte sentinel copies in committed RW pages,
;   excluding the reference buffer secscan_ref itself.
ss_scan proc frame
    FRAME_PROLOG 48
    ; [rbp-24] scan cursor, [rbp-32] count
    mov     qword ptr [rbp-24], 0
    mov     dword ptr [rbp-32], 0
ss_loop:
    WINCALL VirtualQuery, qword ptr [rbp-24], addr ss_mbi, 48
    test    rax, rax
    jz      ss_done                         ; walked off the end of the address space
    lea     r10, [ss_mbi]
    cmp     dword ptr [r10+32], MEM_COMMIT   ; State
    jne     ss_next
    cmp     dword ptr [r10+36], PAGE_READWRITE ; Protect (exact RW -> readable, no guard)
    jne     ss_next
    mov     r8, qword ptr [r10+0]            ; region base
    mov     r9, qword ptr [r10+24]           ; region size
    lea     r9, [r8+r9]
    sub     r9, 16                           ; last start offset
    mov     r11, r8                          ; cursor
ss_scanb:
    cmp     r11, r9
    ja      ss_next
    lea     r10, [secscan_ref]
    xor     ecx, ecx
ss_cmp:
    mov     al, byte ptr [r11+rcx]
    cmp     al, byte ptr [r10+rcx]
    jne     ss_nomatch
    inc     ecx
    cmp     ecx, 16
    jb      ss_cmp
    cmp     r11, r10                         ; the reference copy itself -> skip
    je      ss_nomatch
    inc     dword ptr [rbp-32]
ss_nomatch:
    inc     r11
    jmp     ss_scanb
ss_next:
    lea     r10, [ss_mbi]
    mov     rax, qword ptr [r10+0]
    add     rax, qword ptr [r10+24]
    mov     qword ptr [rbp-24], rax
    jmp     ss_loop
ss_done:
    mov     eax, dword ptr [rbp-32]
    FRAME_EPILOG
    ret
ss_scan endp

public cmd_secscan
LANDING_PAD                              ; dispatch reaches handlers via CALL_GUARDED
cmd_secscan proc frame
    FRAME_PROLOG 48
    ; [rbp-24] = hit count before the wipe
    lea     rcx, [secscan_ref]
    mov     edx, 16
    call    rng_fill
    test    eax, eax
    jz      ss_fail                          ; no RNG -> can't run the probe
    lea     r10, [secscan_ref]              ; plant into g_cfg_pass (byte loop: no
    lea     r11, [g_cfg_pass]               ;   16-contiguous copy lands on the stack)
    xor     ecx, ecx
ss_plant:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    inc     ecx
    cmp     ecx, 16
    jb      ss_plant
    mov     dword ptr [g_cfg_passlen], 16
    call    ss_scan                          ; phase 1: must find the plant
    mov     dword ptr [rbp-24], eax
    lea     rcx, [g_cfg_pass]               ; wipe with the real primitive
    mov     edx, MAX_PASSWORD_BYTES+1
    call    secure_zero
    mov     dword ptr [g_cfg_passlen], 0
    call    ss_scan                          ; phase 2: must find nothing
    test    eax, eax
    jnz     ss_residue
    cmp     dword ptr [rbp-24], 1
    jb      ss_blind_fail
    lea     rcx, [ss_pass]
    mov     edx, ss_pass_len
    call    print_a
    lea     rcx, [secscan_ref]
    mov     edx, 16
    call    secure_zero
    xor     eax, eax
    FRAME_EPILOG
    ret
ss_residue:
    lea     rcx, [ss_res]
    mov     edx, ss_res_len
    call    print_a
    jmp     ss_fail
ss_blind_fail:
    lea     rcx, [ss_blind]
    mov     edx, ss_blind_len
    call    print_a
ss_fail:
    lea     rcx, [secscan_ref]
    mov     edx, 16
    call    secure_zero
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_secscan endp

; ===========================================================================
; cmd_lktest (probe) - C3: prove a VirtualLock failure is detected (g_seclock_
;   failed set) via the force hook, and that a normal lock still works after.
; ===========================================================================
LANDING_PAD
public cmd_lktest
cmd_lktest proc frame
    FRAME_PROLOG 48
    mov     dword ptr [g_seclock_failed], 0
    mov     dword ptr [g_force_lockfail], 1     ; force the next lock to fail
    lea     rcx, [secscan_ref]
    mov     edx, 16
    call    sec_lock
    mov     dword ptr [g_force_lockfail], 0
    test    eax, eax
    jnz     lk_fail                             ; forced call must report failure
    cmp     dword ptr [g_seclock_failed], 0
    je      lk_fail                             ; and must set the flag
    mov     dword ptr [g_seclock_failed], 0     ; a real lock must still succeed
    lea     rcx, [secscan_ref]
    mov     edx, 16
    call    sec_lock
    test    eax, eax
    jz      lk_fail
    lea     rcx, [lk_ok]
    mov     edx, lk_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
lk_fail:
    mov     dword ptr [g_force_lockfail], 0
    lea     rcx, [lk_bad]
    mov     edx, lk_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_lktest endp

end
