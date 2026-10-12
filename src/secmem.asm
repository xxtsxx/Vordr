; =============================================================================
; secmem.asm - locked secret memory for decrypted vault / pad material
; -----------------------------------------------------------------------------
;   secmem_alloc(rcx = len) -> rax = ptr (page-granular) or 0
;       VirtualAlloc(PAGE_READWRITE) then VirtualLock so the plaintext is never
;       written to the pagefile.  It does NOT keep it out of a hibernation image:
;       hibernation writes all of RAM, locked pages included.  What protects
;       secrets there is that they are wiped on lock/exit, not that they are locked.
;
;   secmem_free(rcx = ptr, rdx = len)
;       secure_zero the region, VirtualUnlock, VirtualFree.  Fail-closed: a NULL
;       pointer is a no-op; the wipe always runs before the pages are released.
;
; Fixed static buffers are locked best-effort and produce a visible warning if
; pinning fails.  Dynamic secret arenas (including the decrypted vault body)
; fail allocation when VirtualLock fails, so pageable plaintext is never handed
; to a caller.  Against a fully compromised *kernel* this is still a cost-raiser,
; not an absolute guarantee (documented in docs/formats.md).
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
extern K32QueryWorkingSetEx:proc        ; lktest: read back each page's Locked bit
extern print_a:proc
externdef g_cfg_passlen:dword

; the fixed static secret buffers, locked once at startup by sec_lock_statics
externdef g_cfg_pass:byte           ; master password (main.asm)
externdef g_vkey:byte               ; derived vault key (vault.asm)
externdef g_xs_vkey:byte            ; parked copy of it during export / pw check (vault.asm)
externdef g_pwbuf:byte              ; unlock/create password field (gui.asm)
externdef g_pw2buf:byte             ; confirm-password field (gui.asm)
externdef g_secret_w:byte           ; revealed secret for reveal/copy (gui.asm)
externdef g_rowpw_w:byte            ; reveal-overlay secret copy (gui.asm)
externdef g_e_totp:byte             ; entry-form TOTP key (gui.asm)
externdef g_totp_b32:byte           ; selected entry TOTP key (gui.asm)
externdef g_pwhist:byte             ; archived superseded field values (gui.asm)
externdef g_pworig:byte             ; every field value of the open entry (gui.asm)
externdef g_pwhblob:byte            ; history emit scratch (gui.asm)
externdef g_body_ptr:qword          ; decrypted vault body arena (vault.asm)
externdef g_body_len:qword
externdef g_conv:byte               ; field value UTF-8 scratch (vault.asm)
externdef g_convlabel:byte          ; field label UTF-8 scratch (vault.asm)
externdef g_conv_w:byte             ; field value wide display scratch (gui.asm)
externdef g_valblob:byte            ; commit scratch: every value of the entry (gui.asm)
externdef g_lblblob:byte            ; commit scratch: its custom labels (gui.asm)
externdef g_tilefiles:byte          ; open entry's AttachRefs - each embeds a key (gui.asm)
externdef g_tileblob:byte           ;   and their commit copies (gui.asm)
externdef g_imgstageref:byte        ;   and the last staged one (gui.asm)
externdef g_readpw:byte             ; "read password" popup text (gui.asm)
externdef g_phon_w:byte             ;   and its phonetic spelling (gui.asm)
externdef g_genout:byte             ; generator output (gui.asm)
externdef g_genout_w:byte
externdef g_xlpw:byte               ; export/import archive passwords (gui.asm)
externdef g_xlpw2:byte
externdef g_match_w:byte            ; search: a field value folded for matching (gui.asm)
externdef g_sub_w:byte              ; list subtitle: a username (gui.asm)
externdef g_zi_u8pw:byte            ; ZIP import: password (zipimport.asm)
externdef g_zi_sbuf:byte            ;   last decoded JSON string - a value
externdef g_zi_nbuf:byte            ;   last decoded attachment name
externdef g_zi_ref:byte             ;   last staged AttachRef
externdef g_ze_u8pw:byte            ; ZIP export: password (zipexport.asm)
externdef g_ae_dk:byte              ;   PBKDF2 output = AES key + HMAC key
externdef g_ze_rk:byte              ;   expanded AES key schedule
externdef g_totp_key:byte           ; decoded TOTP secret (totp.asm)

; Sizes of the buffers above, mirrored from the modules that allocate them -
; constcheck fails the build if any of these drifts from its original.
CONV_CAP     equ 49152
EBUF         equ 4096
MAXROWS      equ 64
LBLBLOB_W    equ MAXROWS*128
VALBLOB_W    equ (MAXROWS+1)*CONVW_MAX
MAX_TFILES   equ 24
TFILE_ENTRY  equ 328
ZI_SBUF      equ 256*1024
ZI_PWCAP     equ 1024
ZE_PWCAP     equ 1024
ARF_SIZE     equ 68

MEM_COMMIT          equ 1000h
MEM_RESERVE         equ 2000h
MEM_RELEASE         equ 8000h
PAGE_READWRITE      equ 04h
; The working-set MIN is the hard lockable-page quota; it MUST exceed the total
; VirtualLock'd bytes.  That is dominated by the decrypted body arenas
; (VAULT_BODY_MAX = 16 MiB each).
;
; THREE can be resident at once: attachment-carry export holds the live body, a
; stable source snapshot, and the child body while it is sealed.  Cross-vault
; import normally needs two.  Reserving for one was left over from when that
; could not happen, and it
; showed up as the C3 warning (VirtualLock 1453 = ERROR_WORKING_SET_QUOTA) after
; importing a large vault - a quota failure, not a shortage of RAM, on a machine
; with 110 GB free.
SEC_BODY_RESERVE    equ 03000000h   ; 3 x 16 MiB: live + snapshot + export child
; Static buffers plus page rounding and transient locked allocations need more
; than the historical 8 MiB estimate during cross-vault export.  With dynamic
; arenas now correctly failing closed on a lock error, under-reserving this
; quota becomes an availability failure instead of silently pageable memory.
SEC_WS_STATICS      equ 02000000h   ; 32 MiB for statics, rounding, and transient headroom
SEC_WS_MAX          equ 10000000h   ; 256 MiB hard maximum
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

; ---------------------------------------------------------------------------
; sec_regions - every STATIC buffer that can hold a secret: {address, bytes}.
; sec_lock_statics pins each one at startup and secmem_panic_wipe zeroes each one
; on a crash, so the two lists can no longer disagree (they did: the crash wipe
; and the lock list had drifted from each other and from the buffers in use).
; Adding a buffer that holds plaintext, a password or a key = one row here.
; ---------------------------------------------------------------------------
.data
align 8
sec_regions label qword
    dq  g_cfg_pass,     MAX_PASSWORD_BYTES+1
    dq  g_vkey,         32
    dq  g_xs_vkey,      32
    dq  g_pwbuf,        2048
    dq  g_pw2buf,       2048
    dq  g_secret_w,     CONVW_MAX*2
    dq  g_rowpw_w,      512*2
    dq  g_e_totp,       512
    dq  g_totp_b32,     256
    dq  g_pwhist,       MAX_PWHIST*PWHIST_ENTRY
    dq  g_pworig,       MAX_PWORIG*PWORIG_STRIDE
    dq  g_pwhblob,      MAX_PWHIST*PWHBLOB_ENTRY
    dq  g_conv,         CONV_CAP
    dq  g_convlabel,    MAX_LABEL_BYTES
    dq  g_conv_w,       CONVW_MAX*2
    dq  g_valblob,      VALBLOB_W*2
    dq  g_lblblob,      LBLBLOB_W*2
    dq  g_tilefiles,    MAX_TFILES*TFILE_ENTRY
    dq  g_tileblob,     MAX_TFILES*336
    dq  g_imgstageref,  ARF_SIZE
    dq  g_readpw,       260*2
    dq  g_phon_w,       6144*2
    dq  g_genout,       260
    dq  g_genout_w,     260*2
    dq  g_xlpw,         256*2
    dq  g_xlpw2,        256*2
    dq  g_match_w,      EBUF*2*2
    dq  g_sub_w,        512*2
    dq  g_zi_u8pw,      ZI_PWCAP
    dq  g_zi_sbuf,      ZI_SBUF
    dq  g_zi_nbuf,      1024
    dq  g_zi_ref,       ARF_SIZE
    dq  g_ze_u8pw,      ZE_PWCAP
    dq  g_ae_dk,        80
    dq  g_ze_rk,        15*16
    dq  g_totp_key,     64
sec_regions_end label qword

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
    ; min = statics + all concurrently live body arenas.
    ; Clamp to the max.
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
    FRAME_PROLOG 48
    call    sec_ws_grow                       ; raise the working-set quota FIRST
    lea     rax, [sec_regions]
    mov     qword ptr [rbp-24], rax
sls_lp:
    mov     r10, qword ptr [rbp-24]
    lea     rax, [sec_regions_end]
    cmp     r10, rax
    jae     sls_done
    mov     rcx, qword ptr [r10]
    mov     rdx, qword ptr [r10+8]
    call    sec_lock                          ; a failure sets g_seclock_failed -> the
    add     qword ptr [rbp-24], 16            ;   one-time "not pinned" warning
    jmp     sls_lp
sls_done:
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
externdef g_edit_backup:qword
externdef g_edit_backup_len:qword
externdef g_edit_history:qword
; secmem_wipe_statics() - zero every static secret buffer in sec_regions.  The
;   lock path runs this too: a locked Vordr must not keep the last entry's history,
;   originals or attachment keys around until the next one overwrites them.
public secmem_wipe_statics
secmem_wipe_statics proc frame
    FRAME_PROLOG 48
    lea     rax, [sec_regions]
    mov     qword ptr [rbp-24], rax
sws_lp:
    mov     r10, qword ptr [rbp-24]
    lea     rax, [sec_regions_end]
    cmp     r10, rax
    jae     sws_done
    mov     rcx, qword ptr [r10]
    mov     rdx, qword ptr [r10+8]
    call    secure_zero
    add     qword ptr [rbp-24], 16
    jmp     sws_lp
sws_done:
    FRAME_EPILOG
    ret
secmem_wipe_statics endp

secmem_panic_wipe proc frame
    FRAME_PROLOG 48
    call    secmem_wipe_statics                 ; every static secret buffer
spw_body:
    mov     rax, qword ptr [g_body_ptr]         ; decrypted vault body, if resident
    test    rax, rax
    jz      spw_slots
    mov     rcx, rax
    mov     rdx, qword ptr [g_body_len]
    call    secure_zero
spw_slots:
    mov     rcx, qword ptr [g_edit_backup]
    test    rcx, rcx
    jz      spw_history
    mov     rdx, qword ptr [g_edit_backup_len]
    call    secure_zero
spw_history:
    mov     rcx, qword ptr [g_edit_history]
    test    rcx, rcx
    jz      spw_done
    mov     edx, MAX_PWHIST*PWHIST_ENTRY
    call    secure_zero
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
    test    eax, eax
    jz      sa_lockfail

    mov     rcx, qword ptr [rbp-32]         ; register the live base (double-free guard)
    call    secreg_add
    test    eax, eax
    jz      sa_regfull

    mov     rax, qword ptr [rbp-32]         ; return the (locked) base
    FRAME_EPILOG
    ret
sa_lockfail:
    ; A secret arena that cannot be pinned must never escape to a caller.  It is
    ; still zero-filled by VirtualAlloc, but wipe it explicitly before release
    ; so this cleanup remains correct if the allocation strategy changes.
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-24]
    call    secure_zero
    WINCALL VirtualFree, qword ptr [rbp-32], 0, MEM_RELEASE
    xor     eax, eax
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
ss_wsx      dq 2 dup (?)                ; PSAPI_WORKING_SET_EX_INFORMATION (lktest)
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
CSTR lk_ok,   "lktest: PASS (VirtualLock failure detected + recovered; every static secret buffer pinned)",13,10
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
;   failed set), prevents a dynamic secret allocation from escaping, and that a
;   normal lock still works after.
; ===========================================================================
LANDING_PAD
public cmd_lktest
cmd_lktest proc frame
    FRAME_PROLOG 48
    mov     dword ptr [g_seclock_failed], 0
    mov     dword ptr [g_force_lockfail], 1     ; force the next lock to fail
    mov     ecx, 16
    call    secmem_alloc                        ; dynamic arena must fail closed
    mov     dword ptr [g_force_lockfail], 0
    test    eax, eax
    jnz     lk_fail                             ; pageable allocation must not escape
    cmp     dword ptr [g_seclock_failed], 0
    je      lk_fail                             ; and must set the flag
    mov     dword ptr [g_seclock_failed], 0     ; a real lock must still succeed
    lea     rcx, [secscan_ref]
    mov     edx, 16
    call    sec_lock
    test    eax, eax
    jz      lk_fail
    call    sec_statics_locked                  ; and the statics were pinned at startup
    test    eax, eax                            ;   - by the entry point actually used
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

; sec_statics_locked() -> eax = 1 if EVERY page of every sec_regions buffer reports
;   Locked in the working set (it checked only each buffer's first page; several
;   span more than one).  This is what nothing checked: lktest proved sec_lock
;   could fail and recover, while the code that locks the statics was never reached.
sec_statics_locked proc frame
    FRAME_PROLOG 64
    lea     rax, [sec_regions]
    mov     qword ptr [rbp-24], rax
ssl_lp:
    mov     r10, qword ptr [rbp-24]
    lea     rax, [sec_regions_end]
    cmp     r10, rax
    jae     ssl_yes
    mov     rcx, qword ptr [r10]                ; start
    mov     rax, rcx
    add     rax, qword ptr [r10+8]
    mov     qword ptr [rbp-40], rax             ; end
    and     rcx, -1000h                         ; first page
    mov     qword ptr [rbp-32], rcx
ssl_page:
    mov     rcx, qword ptr [rbp-32]
    cmp     rcx, qword ptr [rbp-40]
    jae     ssl_next
    mov     qword ptr [ss_wsx], rcx             ; PSAPI_WORKING_SET_EX_INFORMATION.VirtualAddress
    mov     qword ptr [ss_wsx+8], 0
    WINCALL GetCurrentProcess
    WINCALL K32QueryWorkingSetEx, rax, addr ss_wsx, 16
    test    eax, eax
    jz      ssl_no
    mov     rax, qword ptr [ss_wsx+8]           ; VirtualAttributes: bit 0 Valid,
    bt      rax, 22                             ;   bit 22 Locked
    jnc     ssl_no
    add     qword ptr [rbp-32], 1000h
    jmp     ssl_page
ssl_next:
    add     qword ptr [rbp-24], 16
    jmp     ssl_lp
ssl_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
ssl_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
sec_statics_locked endp

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
