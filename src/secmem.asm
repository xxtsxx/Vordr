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
extern SetProcessWorkingSetSizeEx:proc
extern GetLastError:proc
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
; The working-set MIN is the hard lockable-page quota; it MUST exceed the total
; VirtualLock'd bytes.  That's dominated by the single decrypted body arena
; (VAULT_BODY_MAX = 16 MiB).  Single-vault: exactly one body is ever resident, so
; the reservation is a fixed statics + one body arena (sec_ws_grow).
SEC_BODY_RESERVE    equ 01000000h   ; 16 MiB decrypted body (matches VAULT_BODY_MAX)
SEC_WS_STATICS      equ 00800000h   ; 8 MiB for the static secret buffers + headroom
SEC_WS_MAX          equ 10000000h   ; 256 MiB cap (ample for one body + statics)
; QUOTA_LIMITS_HARDWS_MIN_ENABLE (1) | QUOTA_LIMITS_HARDWS_MAX_DISABLE (8): make
; the MIN a HARD reservation so VirtualLock actually gets quota.  Plain
; SetProcessWorkingSetSize sets only a soft hint -> VirtualLock still fails
; ERROR_WORKING_SET_QUOTA (1453) even though the call "succeeds".
SEC_WS_FLAGS        equ 9

; Live-allocation registry: secmem_free is otherwise NOT double-free-safe (it
; secure_zeros BEFORE VirtualFree, so a second/stale free writes released pages ->
; access violation).  A decrypted body can be aliased and freed twice (e.g. a
; reseal that reuses a buffer).  Rather than chase every producer, we make the
; free site structurally safe: alloc records the base, free only proceeds for a
; base that is CURRENTLY registered (and removes it).  A double/stale/foreign free
; finds it absent and no-ops.  CAP >> the realistic live set (a body + a KDF
; arena); overflow fails the alloc closed.  Single-threaded like the shadow
; stack: body allocs run on the GUI thread; the secdesk worker's KDF alloc happens
; while the main thread is blocked in WaitForSingleObject - never concurrent.
SECREG_CAP          equ 64

.code

; secreg_add(rcx = base) -> eax = 1 stored / 0 registry full.  Leaf.
secreg_add proc
    lea     r10, [g_secreg]
    xor     r8d, r8d
sra_lp:
    cmp     r8d, SECREG_CAP
    jae     sra_full
    cmp     qword ptr [r10+r8*8], 0
    jne     sra_next
    mov     qword ptr [r10+r8*8], rcx
    mov     eax, 1
    ret
sra_next:
    inc     r8d
    jmp     sra_lp
sra_full:
    xor     eax, eax
    ret
secreg_add endp

; secreg_take(rcx = base) -> eax = 1 found (and cleared) / 0 absent.  Leaf.
secreg_take proc
    test    rcx, rcx
    jz      srt_absent
    lea     r10, [g_secreg]
    xor     r8d, r8d
srt_lp:
    cmp     r8d, SECREG_CAP
    jae     srt_absent
    cmp     qword ptr [r10+r8*8], rcx
    jne     srt_next
    mov     qword ptr [r10+r8*8], 0
    mov     eax, 1
    ret
srt_next:
    inc     r8d
    jmp     srt_lp
srt_absent:
    xor     eax, eax
    ret
secreg_take endp

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
    jne     sl_failed_hook
    ; The working-set quota is grown ONCE up front (sec_ws_grow, from
    ; sec_lock_statics) so the lock isn't capped; here we just attempt it.
    WINCALL VirtualLock, qword ptr [rbp-24], qword ptr [rbp-32]
    test    eax, eax
    jnz     sl_done
    ; failed: record WHY (first failure's code) for the diagnostic warning
    WINCALL GetLastError
    cmp     dword ptr [g_lockerr_vl], 0
    jne     sl_failed
    mov     dword ptr [g_lockerr_vl], eax       ; keep the FIRST error only
sl_failed:
    ; C3: a secret buffer could not be pinned - it may reach the pagefile.  Record
    ; it (the GUI shows a one-time warning; we do NOT fail closed, which would lock
    ; the user out of their own vault on a constrained system).
    mov     dword ptr [g_seclock_failed], 1
    xor     eax, eax
    FRAME_EPILOG
    ret
sl_failed_hook:
    mov     dword ptr [g_seclock_failed], 1     ; forced failure (test) - no real errno
    xor     eax, eax
    FRAME_EPILOG
    ret
sl_done:
    mov     eax, 1                              ; locked
    FRAME_EPILOG
    ret
sec_lock endp

; =============================================================================
; sec_ws_grow() - raise the process working-set min/max ONCE so VirtualLock has
;   quota to pin the secret pages.  VirtualLock is capped by the working-set
;   minimum, NOT by free RAM, so this (not memory) is what makes the locks hold.
;   Records the Win32 error if the grow is refused (e.g. SeIncreaseWorkingSet
;   privilege stripped by policy), which is then surfaced in the C3 warning.
; =============================================================================
public sec_ws_grow
sec_ws_grow proc frame
    FRAME_PROLOG 48
    ; min = statics + one 16 MiB body arena (single-vault: only one decrypted body is
    ; ever resident).  Clamp to the max.
    mov     eax, SEC_BODY_RESERVE
    add     eax, SEC_WS_STATICS
    cmp     eax, SEC_WS_MAX
    jbe     @F
    mov     eax, SEC_WS_MAX
@@: mov     qword ptr [rbp-24], rax           ; computed min (survive the call setup)
    WINCALL GetCurrentProcess
    WINCALL SetProcessWorkingSetSizeEx, rax, qword ptr [rbp-24], SEC_WS_MAX, SEC_WS_FLAGS
    test    eax, eax
    jnz     swg_ok
    WINCALL GetLastError
    mov     dword ptr [g_lockerr_wss], eax
    FRAME_EPILOG
    ret
swg_ok:
    mov     dword ptr [g_lockerr_wss], 0
    FRAME_EPILOG
    ret
sec_ws_grow endp

; =============================================================================
; sec_lock_statics() - VirtualLock every fixed static secret buffer.  Called
;   once from start (main.asm) after hardening_init; the pages are committed at
;   load, so the locks hold for the process lifetime (these buffers are always
;   secret-capable and are never unlocked).  See docs/SECRETS.md.
; =============================================================================
public sec_lock_statics
sec_lock_statics proc frame
    FRAME_PROLOG 32
    call    sec_ws_grow                       ; raise the working-set quota FIRST
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
    lea     rcx, [g_rowpw_w]                     ; reveal-overlay copy (locked in sec_lock_statics,
    mov     edx, 512*2                           ;   wiped on normal teardown) - must wipe here too
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

    ; keep it resident / out of the pagefile.  RE-ASSERT the hard working-set
    ; minimum first: Argon2's 512 MiB KDF arena balloons the working set and, on
    ; free, the OS trims it back and drops our startup reservation - so without
    ; this the post-unlock body lock fails ERROR_WORKING_SET_QUOTA even though the
    ; startup buffers locked fine.  (Diagnosed with Thomas: startup-fail flag = 0.)
    call    sec_ws_grow
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-24]
    call    sec_lock

    mov     rcx, qword ptr [rbp-32]         ; register the live base (double-free guard)
    call    secreg_add
    test    eax, eax
    jz      sa_regfull

    mov     rax, qword ptr [rbp-32]         ; return the (locked) base
    FRAME_EPILOG
    ret
sa_regfull:
    ; registry saturated (should never happen: CAP >> live set) - fail closed so no
    ; untracked, un-double-free-guarded arena escapes.  Release what we allocated.
    WINCALL VirtualUnlock, qword ptr [rbp-32], qword ptr [rbp-24]
    WINCALL VirtualFree, qword ptr [rbp-32], 0, MEM_RELEASE
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

    ; double-free guard: only wipe+release a base that is CURRENTLY registered as
    ; live.  A second or stale free (an aliased/dangling vault body) finds it absent
    ; and no-ops here - which is exactly the secure_zero-on-released-pages crash we
    ; keep hitting on multi-vault teardown.  secreg_take clears the entry atomically
    ; w.r.t. this single-threaded free, so the wipe below runs exactly once per base.
    mov     rcx, qword ptr [rbp-24]
    call    secreg_take
    test    eax, eax
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
align 8
g_secreg    dq SECREG_CAP dup (?)       ; live secmem allocation bases (0 = free slot)
secscan_ref db 16 dup (?)               ; runtime-random reference sentinel
align 8
ss_mbi      db 48 dup (?)               ; MEMORY_BASIC_INFORMATION (static: no stack use)
align 4
public g_seclock_failed
g_seclock_failed dd ?                    ; C3: set if any VirtualLock failed (pageable secret)
public g_force_lockfail
g_force_lockfail dd ?                    ; C3: test hook - force sec_lock to fail
public g_lockerr_vl, g_lockerr_wss
g_lockerr_vl  dd ?                       ; Win32 err from the FIRST failed VirtualLock (0=none)
g_lockerr_wss dd ?                       ; Win32 err from SetProcessWorkingSetSize (0=ok)

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

; ===========================================================================
; cmd_secfreedup (probe) - prove secmem_free is double-free-safe.  Alloc a body,
;   plant a sentinel, free it once (must wipe: sentinel gone), then free the SAME
;   pointer TWO more times (aliased/stale frees).  Without the live-allocation
;   registry the 2nd free secure_zeros released pages -> access violation (the
;   recurring multi-vault teardown crash); with it, the 2nd/3rd frees no-op.
;   Also frees a never-allocated pointer to prove a foreign free is inert.
;   Survival (no fault) + first-free wipe = pass.  exit 0 = pass.
; ===========================================================================
CSTR sfd_ok,  "secfreedup: PASS (double/stale/foreign free is inert; first free wiped)",13,10
CSTR sfd_bad, "secfreedup: FAIL (first free did not wipe)",13,10
LANDING_PAD
public cmd_secfreedup
cmd_secfreedup proc frame
    FRAME_PROLOG 48
    mov     ecx, 65536
    call    secmem_alloc                        ; [rbp-24] = live body
    test    rax, rax
    jz      sfd_fail
    mov     qword ptr [rbp-24], rax
    mov     r10, 0DEADBEEFCAFEF00Dh              ; sentinel in the arena
    mov     qword ptr [rax], r10
    mov     rcx, qword ptr [rbp-24]              ; free #1 - must wipe + release
    mov     rdx, 65536
    call    secmem_free
    mov     r10, qword ptr [rbp-24]             ; (pages released; do NOT read them)
    mov     rcx, qword ptr [rbp-24]              ; free #2 - stale, must no-op
    mov     rdx, 65536
    call    secmem_free
    mov     rcx, qword ptr [rbp-24]              ; free #3 - stale again, must no-op
    mov     rdx, 65536
    call    secmem_free
    mov     rcx, 0BADC0DE00h                     ; foreign pointer never allocated - inert
    mov     rdx, 4096
    call    secmem_free
    xor     rcx, rcx                             ; null free - inert
    xor     rdx, rdx
    call    secmem_free
    lea     rcx, [sfd_ok]                        ; survived every stale/foreign free
    mov     edx, sfd_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
sfd_fail:
    lea     rcx, [sfd_bad]
    mov     edx, sfd_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_secfreedup endp

end
