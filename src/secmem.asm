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
extern VirtualProtect:proc
extern VirtualLock:proc
extern VirtualUnlock:proc
extern AcquireSRWLockExclusive:proc
extern ReleaseSRWLockExclusive:proc
extern secure_zero:proc
extern GetCurrentProcess:proc
extern SetProcessWorkingSetSizeEx:proc
extern GetLastError:proc
ifdef PROBE_IO
extern rng_fill:proc
extern VirtualQuery:proc
extern K32QueryWorkingSetEx:proc        ; lktest: read back each page's Locked bit
extern print_a:proc
externdef g_cfg_passlen:dword
endif

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
externdef g_zi_rk:byte              ;   expanded AES key schedule (zipimport.asm)
externdef g_zi_tbuf:byte            ;   staged entry titles (zipimport.asm)
externdef g_ze_u8pw:byte            ; ZIP export: password (zipexport.asm)
externdef g_ae_dk:byte              ;   PBKDF2 output = AES key + HMAC key
externdef g_ze_rk:byte              ;   expanded AES key schedule
externdef g_pb_u:byte               ;   PBKDF2 block scratch (zipexport.asm)
externdef g_pb_un:byte
externdef g_pb_t:byte
externdef g_fmac_ctx:byte           ; keyed BLAKE2b file-MAC state (vault.asm)
externdef g_sha32:byte              ; SHA-256(vkey) KCV scratch (vault.asm)
externdef g_totp_key:byte           ; decoded TOTP secret (totp.asm)
externdef g_b2bctx:byte             ; Argon2id BLAKE2b state (argon2.asm)
externdef g_hbuf:byte               ; Argon2id H0 pre-hash (argon2.asm)
externdef g_arena:qword             ; Argon2id active arena ptr (argon2.asm)
externdef g_mb:qword                ; Argon2id active arena block count (argon2.asm)
externdef g_tpm_sha_ctx:byte        ; TPM key-binding SHA-256 state (tpm.asm)
externdef g_tpm_label:byte          ; TPM OAEP context label (tpm.asm)
externdef g_zj_fld:byte             ; ZIP export field descriptor scratch (zipexport.asm)
externdef g_zj_fn:byte              ; ZIP export attachment filename scratch (zipexport.asm)
externdef g_search_w:byte           ; Vault search query wide buffer (gui.asm)
externdef g_totp_code6:byte         ; Live 6-digit TOTP ASCII buffer (gui.asm)
externdef g_totp_code_w:byte        ; Live 6-digit TOTP wide buffer (gui.asm)
externdef g_totp_disp_w:byte        ; Live grouped TOTP display buffer (gui.asm)
externdef g_wordtmp:byte            ; Phonetic word scratch buffer (gui.asm)
externdef g_tpm_state:byte          ; TPM+PIN decrypted InnerState scratch (vault.asm)
externdef g_tpm_sec:byte            ; TPM+PIN / TPM+Hello secret material (vault.asm)
externdef g_tpm_dk:byte             ; Argon2id(PIN) 64-byte output (vault.asm)
externdef g_tpm_cand:byte           ; Transient 32-byte wrap/state key (vault.asm)
externdef g_tpm_pin_u8:byte         ; UTF-8 PIN staging buffer (vault.asm)
externdef g_tpm_pt64:byte           ; TPM OAEP 64-byte plaintext staging (tpm.asm)
externdef g_tpm_prf32:byte          ; WebAuthn hmac-secret 32-byte PRF output (tpm.asm)
externdef g_tpm_cand_out:byte       ; TPM+Hello pre-MAC 32-byte candidate (tpm.asm)
externdef g_zi_wname:byte           ; ZIP import wide attachment name scratch (zipimport.asm)
externdef g_zi_sha_hex:byte         ; ZIP import SHA-256 hex scratch (zipimport.asm)
externdef g_zi_sha_exp:byte         ; ZIP import expected SHA-256 (zipimport.asm)
externdef g_zi_sha_act:byte         ; ZIP import actual SHA-256 (zipimport.asm)
externdef g_zj_sha:byte             ; ZIP export attachment SHA-256 (zipexport.asm)
externdef g_zj_shahex:byte          ; ZIP export attachment SHA-256 hex (zipexport.asm)
externdef g_comp_wbuf:byte          ; Off-screen compositor text scratch (gui.asm)
externdef g_rlabel:byte             ; Detail row label scratch (gui.asm)
externdef g_grouptxt:byte           ; Group heading scratch (gui.asm)
externdef g_cmpbuf:byte             ; Sort comparison title scratch (gui.asm)
externdef g_imgfn_w:byte            ; Attachment filename scratch (gui.asm)
externdef g_urlbuf:byte             ; URL launch scratch (gui.asm)
externdef g_urlbuf2:byte            ; URL scheme-prepended scratch (gui.asm)
externdef g_times_w:byte            ; Timestamp line scratch (gui.asm)
externdef g_phdate:byte             ; Password history date scratch (gui.asm)
externdef g_health_flags:byte       ; Per-entry password health flags (vault.asm)
externdef g_san_tmp:byte            ; Attachment filename sanitizer scratch (gui.asm)
externdef g_san_stem:byte           ; Attachment filename stem scratch (gui.asm)
externdef g_extw:byte               ; Attachment extension scratch (gui.asm)
externdef g_deleted_ft:byte         ; Soft-deleted timestamp scratch (gui.asm)
externdef g_tmpfile:byte            ; Opened attachment temp path (gui.asm)
externdef g_motw_w:byte             ; Opened attachment MOTW path (gui.asm)
externdef g_motw_io:byte            ; Opened attachment MOTW long path (gui.asm)

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
ZI_TBUF      equ 1024*1024
ZI_NBUF      equ 1024
ZI_PWCAP     equ 1024
ZE_PWCAP     equ 1024
ARF_SIZE     equ 68
HFLG_CAP     equ 8192
VAULT_BODY_MAX equ 16777216

MEM_COMMIT          equ 1000h
MEM_RESERVE         equ 2000h
MEM_RELEASE         equ 8000h
PAGE_NOACCESS       equ 01h
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
SECREG_CAP          equ 1024

; ---------------------------------------------------------------------------
; sec_regions - every STATIC buffer that can hold a secret: {address, bytes}.
; sec_lock_statics pins each one at startup and secmem_panic_wipe zeroes each one
; on a crash, so the two lists can no longer disagree (they did: the crash wipe
; and the lock list had drifted from each other and from the buffers in use).
; Adding a buffer that holds plaintext, a password or a key = one row here.
; ---------------------------------------------------------------------------
.const
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
    dq  g_zi_nbuf,      ZI_NBUF
    dq  g_zi_ref,       ARF_SIZE
    dq  g_zi_rk,        15*16
    dq  g_zi_tbuf,      ZI_TBUF
    dq  g_ze_u8pw,      ZE_PWCAP
    dq  g_ae_dk,        80
    dq  g_ze_rk,        15*16
    dq  g_pb_u,         20
    dq  g_pb_un,        20
    dq  g_pb_t,         20
    dq  g_fmac_ctx,     256
    dq  g_sha32,        32
    dq  g_totp_key,     160
    dq  g_b2bctx,       256
    dq  g_hbuf,         80
    dq  g_tpm_sha_ctx,  128
    dq  g_tpm_label,    32
    dq  g_zj_fld,       40
    dq  g_zj_fn,        512
    dq  g_search_w,     512*2
    dq  g_totp_code6,   8
    dq  g_totp_code_w,  16*2
    dq  g_totp_disp_w,  16*2
    dq  g_wordtmp,      32*2
    dq  g_tpm_state,    384
    dq  g_tpm_sec,      64
    dq  g_tpm_dk,       64
    dq  g_tpm_cand,     32
    dq  g_tpm_pin_u8,   256
    dq  g_tpm_pt64,     64
    dq  g_tpm_prf32,    32
    dq  g_tpm_cand_out, 32
    dq  g_zi_wname,     260*2
    dq  g_zi_sha_hex,   128
    dq  g_zi_sha_exp,   32
    dq  g_zi_sha_act,   32
    dq  g_zj_sha,       32
    dq  g_zj_shahex,    64
    dq  g_comp_wbuf,    260*2
    dq  g_rlabel,       128*2
    dq  g_grouptxt,     128*2
    dq  g_cmpbuf,       256
    dq  g_imgfn_w,      200*2
    dq  g_urlbuf,       1024*2
    dq  g_urlbuf2,      1040*2
    dq  g_times_w,      128*2
    dq  g_phdate,       40*2
    dq  g_health_flags, HFLG_CAP
    dq  g_san_tmp,      260*2
    dq  g_san_stem,     40*2
    dq  g_extw,         40*2
    dq  g_deleted_ft,   20*2
    dq  g_tmpfile,      MAX_PATH_CHARS*2
    dq  g_motw_w,       (MAX_PATH_CHARS+32)*2
    dq  g_motw_io,      (MAX_PATH_CHARS+48)*2
sec_regions_end label qword

.code

; secreg_add(rcx = base, rdx = len) -> eax = 1 stored / 0 registry full.  Leaf.
secreg_add proc
    lea     r10, [g_secreg]
    xor     r8d, r8d
sra_lp:
    cmp     r8d, SECREG_CAP
    jae     sra_full
    mov     rax, r8
    shl     rax, 4
    cmp     qword ptr [r10+rax], 0
    jne     sra_next
    mov     qword ptr [r10+rax+8], rdx          ; AUD-10: publish size BEFORE base
    mfence
    mov     qword ptr [r10+rax], rcx
    mov     eax, 1
    ret
sra_next:
    inc     r8d
    jmp     sra_lp
sra_full:
    xor     eax, eax
    ret
secreg_add endp

; secreg_find(rcx = base, rdx = *out_slot) -> rax = stored_len (0 if absent).  Leaf.
secreg_find proc
    test    rcx, rcx
    jz      srf_absent
    lea     r10, [g_secreg]
    xor     r8d, r8d
srf_lp:
    cmp     r8d, SECREG_CAP
    jae     srf_absent
    mov     r9, r8
    shl     r9, 4
    cmp     qword ptr [r10+r9], rcx
    jne     srf_next
    lea     rax, [r10+r9]
    mov     qword ptr [rdx], rax
    mov     rax, qword ptr [r10+r9+8]
    test    rax, rax
    jnz     @F
    mov     eax, 1
@@: ret
srf_next:
    inc     r8d
    jmp     srf_lp
srf_absent:
    xor     eax, eax
    ret
secreg_find endp

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
ifdef PROBE_IO
    cmp     dword ptr [g_force_lockfail], 0     ; C3 test hook: force a lock failure (PROBE_IO only)
    jne     sl_failed_hook
endif
    WINCALL VirtualLock, qword ptr [rbp-24], qword ptr [rbp-32]
    test    eax, eax
    jnz     sl_done
    ; Retry once after growing the process working-set quota (handles transient WS trim)
    call    sec_ws_grow
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
    ; it (the GUI shows a one-time warning; we do NOT fail closed on statics, which
    ; would lock the user out of their own vault on a constrained system).
    mov     dword ptr [g_seclock_failed], 1
    xor     eax, eax
    FRAME_EPILOG
    ret
ifdef PROBE_IO
sl_failed_hook:
    mov     dword ptr [g_seclock_failed], 1     ; forced failure (test) - no real errno
    xor     eax, eax
    FRAME_EPILOG
    ret
endif
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
    ; A3-10: serialize registry/pending reads against worker thread allocations
    WINCALL AcquireSRWLockExclusive, addr g_secreg_lock
    ; Sum all currently registered dynamic arenas + pending request + statics,
    ; floored at SEC_BODY_RESERVE + SEC_WS_STATICS so large attachment/ZIP
    ; secmem arenas never exhaust the VirtualLock working-set quota.
    mov     rax, qword ptr [g_secreg_pending]
    add     rax, 0FFFh
    and     rax, -1000h
    lea     r10, [g_secreg]
    xor     r8d, r8d
swg_sum:
    cmp     r8d, SECREG_CAP
    jae     swg_sumd
    mov     r9, r8
    shl     r9, 4
    cmp     qword ptr [r10+r9], 0
    je      swg_next
    mov     rcx, qword ptr [r10+r9+8]
    add     rcx, 0FFFh
    and     rcx, -1000h
    add     rax, rcx
swg_next:
    inc     r8d
    jmp     swg_sum
swg_sumd:
    add     rax, SEC_WS_STATICS
    mov     ecx, SEC_BODY_RESERVE + SEC_WS_STATICS
    cmp     rax, rcx
    jae     @F
    mov     rax, rcx
@@: mov     qword ptr [rbp-24], rax           ; computed min
    lea     rdx, [rax + 04000000h]            ; max = max(SEC_WS_MAX, min + 64 MiB)
    mov     ecx, SEC_WS_MAX
    cmp     rdx, rcx
    jae     @F
    mov     rdx, rcx
@@: mov     qword ptr [rbp-32], rdx           ; computed max
    WINCALL ReleaseSRWLockExclusive, addr g_secreg_lock
    WINCALL GetCurrentProcess
    WINCALL SetProcessWorkingSetSizeEx, rax, qword ptr [rbp-24], qword ptr [rbp-32], SEC_WS_FLAGS
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
    ; Wipe every dynamic secret arena registered in g_secreg ({base, size})
    mov     dword ptr [rbp-24], 0
spw_reg:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, SECREG_CAP
    jae     spw_body
    shl     rax, 4
    lea     r10, [g_secreg]
    mov     rcx, qword ptr [r10+rax]
    test    rcx, rcx
    jz      spw_reg_next
    mov     rdx, qword ptr [r10+rax+8]
    call    secure_zero
spw_reg_next:
    inc     dword ptr [rbp-24]
    jmp     spw_reg
spw_body:
    mov     rax, qword ptr [g_body_ptr]         ; decrypted vault body, if resident
    test    rax, rax
    jz      spw_slots
    mov     rcx, rax
    mov     rdx, qword ptr [g_body_len]
    cmp     rdx, VAULT_BODY_MAX                 ; A3-20: clamp length so corrupt len cannot fault
    jbe     @F
    mov     rdx, VAULT_BODY_MAX
@@: call    secure_zero
spw_slots:
    mov     rcx, qword ptr [g_edit_backup]
    test    rcx, rcx
    jz      spw_history
    mov     rdx, qword ptr [g_edit_backup_len]
    cmp     rdx, VAULT_BODY_MAX
    jbe     @F
    mov     rdx, VAULT_BODY_MAX
@@: call    secure_zero
spw_history:
    mov     rcx, qword ptr [g_edit_history]
    test    rcx, rcx
    jz      spw_a2
    mov     edx, MAX_PWHIST*PWHIST_ENTRY
    call    secure_zero
spw_a2:
    mov     rcx, qword ptr [g_arena]            ; active Argon2id arena, if mid-KDF
    test    rcx, rcx
    jz      spw_done
    mov     rdx, qword ptr [g_mb]
    cmp     rdx, 262144                         ; cap at 256 MiB blocks
    jbe     @F
    mov     rdx, 262144
@@: shl     rdx, 10
    call    secure_zero
spw_done:
    FRAME_EPILOG
    ret
secmem_panic_wipe endp

public secmem_alloc
secmem_alloc proc frame
    FRAME_PROLOG 80
    ; locals: [rbp-24] page-rounded len, [rbp-32] base, [rbp-40] oldprot,
    ;         [rbp-44] lock_ok, [rbp-48] reg_ok
    mov     qword ptr [rbp-32], 0
    test    rcx, rcx
    jz      sa_fail                         ; zero-length: fail closed
    mov     rax, 07FFFFFFFFFF0000h
    cmp     rcx, rax
    ja      sa_fail                         ; overflow guard before 4 KiB page rounding + guard page
    add     rcx, 0FFFh
    and     rcx, -1000h                     ; round up to full 4 KiB pages (no unwiped slack)
    mov     qword ptr [rbp-24], rcx

    ; A3-26: append a trailing 4 KiB PAGE_NOACCESS hardware guard page after every secret arena
    lea     rdx, [rcx + 1000h]
    WINCALL VirtualAlloc, 0, rdx, <MEM_RESERVE or MEM_COMMIT>, PAGE_READWRITE
    test    rax, rax
    jz      sa_fail
    mov     qword ptr [rbp-32], rax         ; remember the base across the guard/lock calls
    mov     rcx, rax
    add     rcx, qword ptr [rbp-24]
    WINCALL VirtualProtect, rcx, 1000h, PAGE_NOACCESS, addr rbp-40
    test    eax, eax
    jz      sa_protfail

    ; keep it resident / out of the pagefile.  RE-ASSERT the hard working-set
    ; minimum first, accounting for this pending allocation (SRWLOCK-serialized, A3-10).
    WINCALL AcquireSRWLockExclusive, addr g_secreg_lock
    mov     rax, qword ptr [rbp-24]
    add     qword ptr [g_secreg_pending], rax
    WINCALL ReleaseSRWLockExclusive, addr g_secreg_lock
    call    sec_ws_grow
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-24]
    call    sec_lock
    mov     dword ptr [rbp-44], eax
    mov     dword ptr [rbp-48], 0
    WINCALL AcquireSRWLockExclusive, addr g_secreg_lock
    mov     rax, qword ptr [rbp-24]
    sub     qword ptr [g_secreg_pending], rax
    cmp     dword ptr [rbp-44], 0
    je      sa_rel_lk
    mov     rcx, qword ptr [rbp-32]         ; register {base, page_rounded_len}
    mov     rdx, qword ptr [rbp-24]
    call    secreg_add
    mov     dword ptr [rbp-48], eax
sa_rel_lk:
    WINCALL ReleaseSRWLockExclusive, addr g_secreg_lock
    cmp     dword ptr [rbp-44], 0
    je      sa_lockfail
    cmp     dword ptr [rbp-48], 0
    je      sa_regfull

    mov     rax, qword ptr [rbp-32]         ; return the (locked) base
    FRAME_EPILOG
    ret
sa_lockfail:
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-24]
    call    secure_zero
sa_protfail:
    WINCALL VirtualFree, qword ptr [rbp-32], 0, MEM_RELEASE
    xor     eax, eax
    FRAME_EPILOG
    ret
sa_regfull:
    WINCALL VirtualUnlock, qword ptr [rbp-32], qword ptr [rbp-24]
    WINCALL VirtualFree, qword ptr [rbp-32], 0, MEM_RELEASE
sa_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
secmem_alloc endp

public secmem_free
secmem_free proc frame
    FRAME_PROLOG 64
    ; locals: [rbp-24] ptr, [rbp-32] authoritative page-rounded len, [rbp-40] slot ptr
    mov     qword ptr [rbp-24], rcx
    test    rcx, rcx
    jz      sf_done

    ; A3-10: serialize registry lookup, wipe, and removal (panic_wipe remains lock-free)
    WINCALL AcquireSRWLockExclusive, addr g_secreg_lock
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [rbp-40]
    call    secreg_find
    test    rax, rax
    jz      sf_unlock_done
    ; Wipe BEFORE clearing g_secreg slot, then clear slot BEFORE VirtualFree unmaps (AUD-10)
    mov     qword ptr [rbp-32], rax
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, rax
    call    secure_zero
    mov     r10, qword ptr [rbp-40]
    mov     qword ptr [r10], 0
    mov     qword ptr [r10+8], 0
    mfence
    WINCALL ReleaseSRWLockExclusive, addr g_secreg_lock

    WINCALL VirtualUnlock, qword ptr [rbp-24], qword ptr [rbp-32]
    WINCALL VirtualFree, qword ptr [rbp-24], 0, MEM_RELEASE
sf_done:
    FRAME_EPILOG
    ret
sf_unlock_done:
    WINCALL ReleaseSRWLockExclusive, addr g_secreg_lock
    FRAME_EPILOG
    ret
secmem_free endp

; =============================================================================
; cmd_secscan (probe) - prove the secret-wipe path leaves no residue.
; =============================================================================
.data?
align 8
g_secreg_lock    dq ?                        ; A3-10: SRWLOCK protecting g_secreg / g_secreg_pending
g_secreg         dq (SECREG_CAP * 2) dup (?) ; live secmem {base, size} pairs
g_secreg_pending dq ?                        ; in-flight secmem_alloc request size
ifdef PROBE_IO
secscan_ref db 16 dup (?)               ; runtime-random reference sentinel
align 8
ss_mbi      db 48 dup (?)               ; MEMORY_BASIC_INFORMATION (static: no stack use)
ss_wsx      dq 2 dup (?)                ; PSAPI_WORKING_SET_EX_INFORMATION (lktest)
endif
align 4
public g_seclock_failed
g_seclock_failed dd ?                    ; C3: set if any VirtualLock failed (pageable secret)
ifdef PROBE_IO
public g_force_lockfail
g_force_lockfail dd ?                    ; C3: test hook - force sec_lock to fail (PROBE_IO only)
endif
public g_lockerr_vl, g_lockerr_wss
g_lockerr_vl  dd ?                       ; Win32 err from the FIRST failed VirtualLock (0=none)
g_lockerr_wss dd ?                       ; Win32 err from SetProcessWorkingSetSize (0=ok)

ifdef PROBE_IO
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
endif ; PROBE_IO

end
