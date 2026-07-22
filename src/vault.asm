; =============================================================================
; vault.asm - the single encrypted vault file (.vordr)
; -----------------------------------------------------------------------------
; File layout (see docs/formats.md / VAULT_HDR in macros.inc):
;   [VAULT_HDR 64][KCV 16][ AES-256-GCM( body ) ][GCM tag 16]
; The 80-byte header (VAULT_HDR + KCV) is the GCM AAD; KCV = SHA-256(key)[0..15]
; rejects a wrong master password right after the KDF (key-committing).
;
; Body (plaintext, decrypted into VirtualLock'd secmem):
;   u32 entry_count
;   entry* :  id db16 | created u64 | modified u64 | field_count u32 |
;             field* { u16 type, u32 len, bytes }
;
; The GUI drives everything through vault_unlock / vault_build_entry /
; vault_reseal and the field accessors (vault_count, vault_title_at,
; vault_field_get, ...).  Attachments (VF_IMAGE/VF_FILE) store an AttachRef in
; the body and their ciphertext in a separate file section (attach_stage/open).
; Reuses the proven core: argon2id_hash, gcm_seal/gcm_open, sha256_hash,
; rng_fill, secure_zero, secmem_alloc/free, fileio, console.
; =============================================================================

include macros.inc

externdef g_vpath:word                  ; multi-vault: file identity, snapshotted per ctx
externdef g_is_default:dword
externdef g_vault_lock:dword
extern argon2id_hash:proc
extern gcm_seal:proc
extern gcm_open:proc
extern sha256_hash:proc
extern ct_memcmp:proc
extern rng_fill:proc
extern reg_fed_set:proc                 ; M2: federation record registry I/O (regcfg.asm)
extern reg_fed_get:proc
extern reg_fed_del:proc
extern tpm_available:proc               ; M2: TPM machine-secret binding (tpm.asm)
extern tpm_seal:proc
extern tpm_unseal:proc
extern tpm_delete:proc
extern secure_zero:proc
extern secmem_alloc:proc
extern sec_lock:proc
extern pwgen_ex:proc
externdef g_pwgen_outcap:dword          ; E16: one-shot pwgen output capacity
extern secmem_free:proc
extern read_file:proc
extern write_file:proc
extern file_rename:proc
extern MoveFileExW:proc
extern CopyFileW:proc
extern DeleteFileW:proc
extern CreateFileW:proc                 ; C8: <vault>.lock write coordination
extern CloseHandle:proc
externdef g_wf_disp:dword               ; C7: one-shot write_file disposition (fileio)
extern mem_alloc:proc
extern mem_free:proc
extern print_a:proc
extern print_err:proc
extern print_u64:proc
extern fuzz_seed:proc                   ; G7: reproducible/logged fuzzer seed (main.asm)
extern WideCharToMultiByte:proc
extern GetSystemTimeAsFileTime:proc
extern GetFileAttributesW:proc
extern blake2b_init:proc
extern blake2b_update:proc
extern blake2b_final:proc
extern blake2b_hash:proc
extern tpm_seal:proc
extern tpm_unseal:proc
extern tpm_delete:proc
extern reg_tpm_set:proc
extern reg_tpm_get:proc
extern reg_tpm_del:proc
extern reg_prune_all:proc               ; C6: drop legacy path-named reg values
externdef g_readonly:dword              ; E9: read-only mode flag (owned by gui.asm)
extern reg_ctr_set:proc
extern reg_ctr_get:proc

externdef g_cfg_in:qword
externdef g_argv:qword
externdef g_cfg_pass:byte
externdef g_cfg_passlen:dword
externdef g_cfg_t:dword
externdef g_cfg_m:dword
externdef g_cfg_title:qword
externdef g_cfg_user:qword
externdef g_cfg_secret:qword
externdef g_cfg_url:qword
externdef g_cfg_notes:qword
externdef g_cfg_totp:qword
externdef g_field_list:qword
externdef g_field_n:dword

CP_UTF8         equ 65001

; ARGON2REQ / GCMREQ mirror the definitions in argon2.asm / aesgcm.asm
ARGON2REQ struct
    t_cost      dd ?
    m_cost      dd ?
    lanes       dd ?
    outlen      dd ?
    version     dd ?
    atype       dd ?
    pwd         dq ?
    pwdlen      dd ?
    saltlen     dd ?
    salt        dq ?
    secret      dq ?
    secretlen   dd ?
    adlen       dd ?
    ad          dq ?
    outp        dq ?
ARGON2REQ ends

GCMREQ struct
    key     dq ?
    iv      dq ?
    aad     dq ?
    aadlen  dq ?
    inp     dq ?
    inlen   dq ?
    outp    dq ?
    tag     dq ?
GCMREQ ends

; VAULT_HDR field byte offsets
VH_T            equ 8
VH_M            equ 12
VH_LANES        equ 16
VH_SALT         equ 20
VH_NONCE        equ 52
VH_KCV          equ 64
VH_TOTAL        equ 80          ; header + KCV (= GCM AAD)
VAULT_BODY_MAX  equ 16777216    ; 16 MiB plaintext cap (record fields only)
CONV_CAP        equ 16384
MOVEFILE_REPLACE_EXISTING equ 1
BAK_GENS        equ 3           ; rotated backup generations (.bak1 .. .bak3)

; --- large-attachment section (separate part of the vault file) --------------
; The record body stays small: a VF_IMAGE field's value is a 68-byte AttachRef,
; not the pixels.  Each attachment's bytes live after the body tag, individually
; AES-256-GCM'd under a per-attachment random key/nonce that is itself stored
; (encrypted) inside the body.  A 12-byte trailer terminates the file so an
; attachment-free vault is byte-identical to the old format (fully compatible).
;   file = [80 hdr][body_ct][16 tag] ( [id16][u64 ctlen][ct][tag16] )* [trailer]
;   trailer = [u32 ATT_MAGIC][u64 entries_len]   (present only when >=1 image)
ATT_MAGIC       equ 54544156h   ; "VATT"
ATT_TRAILER     equ 12          ; sizeof trailer
; Full-file MAC + anti-rollback trailer, appended after everything
; else.  Additive + backward compatible: legacy vaults simply lack the magic.
;   [u64 save_counter][32-byte BLAKE2b-keyed MAC over the whole file + counter]
;   [u32 FMAC_MAGIC]
FMAC_MAGIC      equ 43414D56h   ; "VMAC"
FMAC_MACLEN     equ 32
FMAC_TRAILER    equ 8 + FMAC_MACLEN + 4   ; counter + mac + magic = 44
ARF_ID          equ 0           ; AttachRef: 16-byte attachment id
ARF_KEY         equ 16          ;            32-byte AES-256 key
ARF_NONCE       equ 48          ;            12-byte GCM nonce
ARF_PTLEN       equ 60          ;            u64 plaintext length
ARF_SIZE        equ 68
ATT_ENThDR      equ 24          ; on-disk entry header = id16 + u64 ctlen
MAX_ATT         equ 512         ; index / pending-table capacity

; multi-vault state slot (redesign items 6/7/9): a complete open-vault state, so
; several vaults can be held decrypted at once and switched between.  The heap
; pointers (body/filebuf) stay valid because an open vault's buffers are not freed.
VSLOT struct
    s_vkey      db 32 dup(?)
    s_hdr       db VH_TOTAL dup(?)
    s_ext_hash  db 32 dup(?)
    s_body_ptr  dq ?
    s_body_len  dq ?
    s_save_ctr  dq ?
    s_fmac_len  dq ?
    s_ext_size  dq ?
    s_filebuf   dq ?
    s_filesize  dq ?
    s_att_start dq ?
    s_att_total dq ?
    s_rollback  dd ?
    s_newatt_n  dd ?
    s_attidx_n  dd ?
    s_pad       dd ?
    s_newatt    db MAX_ATT * 32 dup(?)
    s_attidx    db MAX_ATT * 32 dup(?)
    s_vpath     db 2048 dup(?)              ; file identity: g_vpath contents (per-ctx save target)
    s_is_default dd ?
    s_vault_lock dd ?
    s_pad2      dd ?
    s_name      db 128 dup(?)               ; tab display name (wide, NUL-term); set at open,
                                            ;   not part of the swapped live state
VSLOT ends

MAX_VAULTS      equ 8           ; simultaneously-open vaults (redesign items 6/7/9)

; --- M2: the machine-local federation record (one per master) --------------
; A fixed-layout table of foreign-vault links.  The whole struct is what
; keyring_seal/open encrypt, so no variable-length serialization is needed.
FED_MAXLINKS    equ MAX_VAULTS
LINK_STALE      equ 1           ; cached key no longer matches the foreign KCV
LINK_MISSING    equ 2           ; foreign file not found at the locator
LINK_PROMPT     equ 4           ; opt-out: no cached key, always prompt

FEDLINK struct
    fl_id       db 16 dup(?)    ; foreign vault_id (SHA-256(salt)[0..15])
    fl_kcv      db 16 dup(?)    ; foreign KCV (staleness check)
    fl_key      db 32 dup(?)    ; cached derived key (zeroed when LINK_PROMPT)
    fl_flags    dd ?
    fl_pad      dd ?
    fl_name     dw 64 dup(?)    ; display name (wide, NUL-term)
    fl_loc      dw 260 dup(?)   ; locator = foreign file path (wide, NUL-term)
FEDLINK ends

FEDREC struct
    fr_count    dd ?            ; number of live links (0..FED_MAXLINKS)
    fr_rsv      dd ?
    fr_links    FEDLINK FED_MAXLINKS dup(<>)
FEDREC ends

; Availability retry state (redesign item 9): a vault whose file can't be opened
; (locked/missing) is not displayed; it is retried AVAIL_MAX_TRIES times at
; AVAIL_INTERVAL_MS spacing, then given up until the user unlocks again.  All
; time-based procs take "now" (a GetTickCount64 value) explicitly so the state
; machine is deterministic and headless-testable.
AVAIL_MAX_TRIES   equ 3
AVAIL_INTERVAL_MS equ 5000
AVSTAT_AVAIL      equ 0         ; open/usable, displayed
AVSTAT_RETRY      equ 1         ; unavailable, auto-retrying
AVSTAT_GAVEUP     equ 2         ; exhausted retries, dormant until manual unlock

AVSLOT struct
    av_status   dd ?
    av_tries    dd ?           ; failed retry attempts so far (0..AVAIL_MAX_TRIES)
    av_next     dq ?           ; tick deadline of the next retry attempt
AVSLOT ends

.const
vst_src     db "vault-kat-test!!"      ; 16-byte plaintext for vault_selftest
; --- field-serialization KAT (labeled + duplicate fields) ------------------
align 2
kat_title   dw 'A','c','c','t',0
kat_url1    dw 'a','.','c','o','m',0
kat_work    dw 'W','o','r','k',0
kat_url2    dw 'b','.','c','o','m',0
kat_pinlbl  dw 'P','I','N',0
kat_pinval  dw '1','2','3','4',0
kat_exp_url1 db "a.com"
kat_exp_pin  db "1234"
align 4
kat_img      dd 7                              ; {u32 len, raw bytes} for VFL_RAW
kat_img_b    db 089h,'P','N','G',000h,001h,0FFh   ; binary incl NUL + high byte
kat_exp_img  db 089h,'P','N','G',000h,001h,0FFh
; --- vfuzz fixture: one valid two-field entry the parser fuzzer mutates ------
align 4
vfz_fix label byte
    dd  1                               ; entry_count
    db  16 dup(41h)                     ; id
    dq  0                               ; created FILETIME
    dq  0                               ; modified FILETIME
    dd  2                               ; field_count
    dw  VF_TITLE
    dd  4
    db  'A','c','c','t'
    dw  VF_SECRET
    dd  5
    db  's','3','c','r','3'
vfz_fix_end label byte
VFZ_FIX_LEN equ vfz_fix_end - vfz_fix
VFZ_ITERS   equ 100000
CSTR vfz_m1, "vfuzz: "
CSTR vfz_m2, " iters  "
CSTR vfz_m3, " parsed  "
CSTR vfz_m4, " rejected  0 crashes",13,10
bk_pw       db "vordrtest", 0
fmac_domain db "vordr-file-mac-v1"          ; MAC domain-separation prefix
FMAC_DOMLEN equ 17
fed_kek_domain db "vordr-federation-kek-v1" ; M2: keyring KEK domain-separation prefix
FED_KEK_DOMLEN equ 23
even
fed_valname db 'r',0,'e',0,'c',0,'o',0,'r',0,'d',0,0,0  ; M2: record value name (wide)
even
fms_key     db 'V',0,'o',0,'r',0,'d',0,'r',0,'-',0,'F',0,'e',0,'d',0,'B',0,'i',0,'n',0,'d',0,0,0  ; M2: machine-binding TPM key
fms_val     db 'm',0,'a',0,'c',0,'h',0,'i',0,'n',0,'e',0,'k',0,'e',0,'y',0,0,0  ; M2: sealed-secret registry value
fms_kat_key db 'V',0,'o',0,'r',0,'d',0,'r',0,'-',0,'F',0,'B',0,'K',0,'A',0,'T',0,0,0  ; fmskat TPM key
fms_kat_val db 'm',0,'k',0,'k',0,'a',0,'t',0,0,0        ; fmskat registry value
ffk_seedpw  db "vordrtest",0                            ; fedfanout: seed vault password (9)
CSTR bk_ok,  "bktest: PASS (bak1..3 rotated and bak1 opens)",13,10
CSTR bk_bad, "bktest: FAIL (backup missing or unopenable)",13,10
CSTR mt_ok,  "mactest: PASS (counter tamper rejected, restore opens)",13,10
CSTR mt_bad, "mactest: FAIL",13,10
CSTR mt_leak,"mactest: FAIL (file-MAC did not catch the trailer tamper)",13,10
CSTR rb_ok,  "rbtest: PASS (older counter flagged, current one not)",13,10
CSTR rb_bad, "rbtest: FAIL",13,10
CSTR rl_ok,  "reload: PASS (in-memory body refreshed from disk)",13,10
CSTR rl_bad, "reload: FAIL",13,10
CSTR cw_ok,  "cowrite: PASS (write lock is exclusive + reacquirable)",13,10
CSTR cw_bad, "cowrite: FAIL",13,10
CSTR af_ok,  "attfuzz: PASS (attach_index_build survived the mutations)",13,10
CSTR af_bad, "attfuzz: FAIL",13,10
CSTR xc_ok,  "xctest: PASS (external header change detected)",13,10
CSTR xc_bad, "xctest: FAIL",13,10
CSTR e_io,      "error: cannot read/write the vault file",13,10
CSTR e_oom,     "error: out of memory",13,10
CSTR m_created, "vault created.",13,10

.data?
align 16
g_mvslot    db (sizeof VSLOT) dup (?)  ; multi-vault: one held vault-state slot (probe/scratch)
            even                       ; keep the wide scratch below 2-aligned
g_mvnamebuf dw 8 dup (?)               ; cmd_mvname: scratch wide name source (probe)
align 16
public g_vaults
public g_vault_n
public g_vault_cur
g_vaults    db (sizeof VSLOT) * MAX_VAULTS dup (?) ; multi-vault: per-open-vault held state
g_vault_n   dd ?                       ; number of open vaults (0..MAX_VAULTS)
g_vault_cur dd ?                       ; index of the fronted vault, or -1 if none live
align 8
g_avslot    db (sizeof AVSLOT) dup (?) ; availability retry state (probe/scratch)
g_vfz_rng   dq ?                       ; vfuzz xorshift64 state (dbg/test only)
g_kat_body  db 512 dup (?)             ; scratch body for the field-serialization KAT
public g_vkey
g_vkey      db 32 dup (?)
g_sha32     db 32 dup (?)
g_hdr       db VH_TOTAL dup (?)
align 8
g_areq      ARGON2REQ <>
g_greq      GCMREQ <>
public g_body_ptr
g_body_ptr  dq ?
public g_body_len
g_body_len  dq ?
public g_save_counter
g_save_counter dq ?                         ; monotonic save number (anti-rollback)
public g_rollback
g_rollback  dd ?                            ; 1 if this file's counter < the HKCU mirror
g_ctr_io    dq ?                            ; reg_ctr_get/set scratch (u64 counter)
g_fmac_len  dq ?                            ; 0 (legacy) or FMAC_TRAILER for this image
g_ext_size  dq ?                            ; on-disk size snapshotted at load/save
g_ext_hash  db 32 dup (?)                   ; BLAKE2b of the header snapshotted then
g_reuse_key dd ?                            ; C8: vault_reload reuses g_vkey (skip Argon2)
align 8
g_lock_h    dq ?                            ; C8: <vault>.lock handle (0 = not held)
g_lock_path dw (MAX_PATH_CHARS + 8) dup (?) ; C8: "<vault>.lock" wide path
align 16
g_fmac_ctx  db 256 dup (?)                  ; BLAKE2B_CTX scratch (216 used)
g_fed_ctx   db 256 dup (?)                  ; M2: keyring KEK BLAKE2B_CTX scratch
g_fmac_out  db 32 dup (?)                   ; computed file MAC
g_filebuf   dq ?
g_filesize  dq ?
g_outbuf    dq ?
g_outlen    dq ?
align 16
g_att_greq  GCMREQ <>                          ; GCM req for attachment seal/open
g_fedreq    GCMREQ <>                          ; M2: GCM req for the keyring blob seal/open
align 8
g_fedrec    FEDREC <>                          ; M2: the live federation record (link table)
g_fedblob   db (sizeof FEDREC) + 32 dup (?)    ;   sealed form (nonce+ct+tag)
g_fedlink_tmp FEDLINK <>                        ;   scratch link template (fedkat)
g_fedkat_bak  db (sizeof FEDREC) + 32 dup (?)   ;   backup of the REAL record (hermetic KATs)
g_fedkat_baklen dd ?
g_fed_mkblob db 512 dup (?)                     ; M2: sealed machine-secret blob
g_fms_out1  db 32 dup (?)                       ;   fmskat scratch
g_fms_out2  db 32 dup (?)
g_fed_tpmsec db 32 dup (?)                      ; M2: working tpm_secret (wiped after use)
g_fed_workkek db 32 dup (?)                     ; M2: working KEK (wiped after use)
g_fedkat_rec  db 128 dup (?)                   ; M2 keyringkat scratch: plaintext record
g_fedkat_blob db 192 dup (?)                   ;   sealed blob (nonce+ct+tag)
g_fedkat_out  db 128 dup (?)                   ;   opened plaintext
g_fedkat_mk   db 32 dup (?)                     ;   synthetic master key
g_fedkat_tpm  db 32 dup (?)                     ;   synthetic tpm secret
g_fedkat_kek  db 32 dup (?)                     ;   derived KEK
g_newatt    db MAX_ATT * 32 dup (?)            ; pending new: {id16, qword pt, qword ptlen}
g_newatt_n  dd ?
g_attidx    db MAX_ATT * 32 dup (?)            ; from file: {id16, qword ct, qword ctlen}
g_attidx_n  dd ?
g_att_aad   db 32 dup (?)                       ; GCM AAD scratch = id16 | u64 ptlen
g_att_start dq ?                                ; file offset where attachments begin
g_att_total dq ?                                ; attachment entries byte length
g_conv      db CONV_CAP dup (?)
g_convlabel db MAX_LABEL_BYTES dup (?)        ; utf8 label scratch (va_field_labeled)
align 2
g_tmppath   dw MAX_PATH_CHARS dup (?)        ; "<vault>.tmp" for atomic replace
g_bak_a     dw MAX_PATH_CHARS dup (?)        ; backup-rotation path scratch (from)
g_bak_b     dw MAX_PATH_CHARS dup (?)        ; backup-rotation path scratch (to)
g_ts        dq ?                ; GetSystemTimeAsFileTime scratch
seed_title_w dw 80 dup (?)      ; seedtest scratch: entry field strings (wide)
seed_user_w  dw 96 dup (?)
seed_url_w   dw 96 dup (?)
seed_pass_a  db 40 dup (?)
seed_pass_w  dw 40 dup (?)
public g_carry_created
g_carry_created dq ?            ; if !=0, vault_build_entry uses it as `created`
                               ; (one-shot; lets a GUI edit preserve the orig date)
vst_ct      db 16 dup (?)
vst_dec     db 16 dup (?)
vst_tag     db 16 dup (?)
align 16
att_katpt   db 40 dup (?)               ; attachment KAT: plaintext
att_katct   db 80 dup (?)               ;                 ciphertext+tag scratch
att_katref  db ARF_SIZE dup (?)         ;                 AttachRef
att_katout  dq ?                        ;                 opened plaintext len
align 4
public g_use_tpm
g_use_tpm   dd ?                    ; GUI sets 1 to unlock via TPM, else password
align 2
g_tpm_kn    dw 64 dup (?)           ; TPM key name (wide): "Vordr-" + KCV[0..7] hex
align 8
g_tpm_blob  db 512 dup (?)          ; sealed 32-byte master key (RSA-OAEP blob)

.code

; ===========================================================================
; conv_w2u(rcx = wideZ ptr, rdx = outbuf, r8d = cap) -> eax = byte len (no NUL),
;   0 if the pointer is NULL, the string is empty, or conversion fails.
; ===========================================================================
conv_w2u proc frame
    FRAME_PROLOG 32 + 32            ; +32 for WC2MB stack args
    test    rcx, rcx
    jz      cw_zero
    ; WideCharToMultiByte(CP_UTF8, 0, src, -1, out, cap, NULL, NULL)
    WINCALL WideCharToMultiByte, CP_UTF8, 0, rcx, -1, rdx, r8d, 0, 0
    test    eax, eax
    jz      cw_zero
    dec     eax                     ; drop terminating NUL
    FRAME_EPILOG
    ret
cw_zero:
    xor     eax, eax
    FRAME_EPILOG
    ret
conv_w2u endp

; ===========================================================================
; vk_derive() - Argon2id(master pw, g_hdr salt/t/m, p=1) -> g_vkey (32 bytes).
;   -> eax = 0 on success, EXIT_OOM on KDF failure.
; ===========================================================================
vk_derive proc frame
    FRAME_PROLOG 32
    lea     r10, [g_areq]
    mov     eax, dword ptr [g_hdr+VH_T]
    mov     dword ptr [r10].ARGON2REQ.t_cost, eax
    mov     eax, dword ptr [g_hdr+VH_M]
    mov     dword ptr [r10].ARGON2REQ.m_cost, eax
    mov     dword ptr [r10].ARGON2REQ.lanes, 1
    mov     dword ptr [r10].ARGON2REQ.outlen, 32
    mov     dword ptr [r10].ARGON2REQ.version, 19
    mov     dword ptr [r10].ARGON2REQ.atype, 2          ; Argon2id
    lea     rax, [g_cfg_pass]
    mov     qword ptr [r10].ARGON2REQ.pwd, rax
    mov     eax, dword ptr [g_cfg_passlen]
    mov     dword ptr [r10].ARGON2REQ.pwdlen, eax
    mov     dword ptr [r10].ARGON2REQ.saltlen, 32
    lea     rax, [g_hdr+VH_SALT]
    mov     qword ptr [r10].ARGON2REQ.salt, rax
    mov     qword ptr [r10].ARGON2REQ.secret, 0
    mov     dword ptr [r10].ARGON2REQ.secretlen, 0
    mov     dword ptr [r10].ARGON2REQ.adlen, 0
    mov     qword ptr [r10].ARGON2REQ.ad, 0
    lea     rax, [g_vkey]
    mov     qword ptr [r10].ARGON2REQ.outp, rax
    lea     rcx, [g_areq]
    call    argon2id_hash
    test    eax, eax
    jz      vd_ok
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
vd_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
vk_derive endp

; ===========================================================================
; tpm_kn_build() - g_tpm_kn = L"Vordr-" + 16 lowercase hex of g_hdr KCV[0..7].
;   A per-vault, per-machine TPM key name (the KCV ties it to this exact key).
; ===========================================================================
tpm_kn_build proc frame
    FRAME_PROLOG 32
    lea     r10, [g_tpm_kn]
    mov     word ptr [r10+0],  'V'
    mov     word ptr [r10+2],  'o'
    mov     word ptr [r10+4],  'r'
    mov     word ptr [r10+6],  'd'
    mov     word ptr [r10+8],  'r'
    mov     word ptr [r10+10], '-'
    add     r10, 12
    lea     r11, [g_hdr+VH_KCV]
    xor     r8d, r8d
kn_loop:
    movzx   eax, byte ptr [r11+r8]
    mov     ecx, eax
    shr     ecx, 4
    and     ecx, 0Fh
    cmp     ecx, 10
    jb      kn_hi_d
    add     ecx, 'a'-10
    jmp     kn_hi_s
kn_hi_d:
    add     ecx, '0'
kn_hi_s:
    mov     word ptr [r10], cx
    add     r10, 2
    mov     ecx, eax
    and     ecx, 0Fh
    cmp     ecx, 10
    jb      kn_lo_d
    add     ecx, 'a'-10
    jmp     kn_lo_s
kn_lo_d:
    add     ecx, '0'
kn_lo_s:
    mov     word ptr [r10], cx
    add     r10, 2
    inc     r8d
    cmp     r8d, 8
    jb      kn_loop
    mov     word ptr [r10], 0
    FRAME_EPILOG
    ret
tpm_kn_build endp

; ===========================================================================
; vk_derive_tpm() - fetch the wrapped key from HKCU\..\TPM-Unlock and TPM-unseal
;   it into g_vkey.  Precondition: g_hdr holds the vault header (KCV) and
;   g_cfg_in points at the wide vault path.  -> eax = 0 / EXIT_LOCKED.
; ===========================================================================
vk_derive_tpm proc frame
    FRAME_PROLOG 48
    call    tpm_kn_build
    mov     rcx, qword ptr [g_cfg_in]       ; value name = vault path
    lea     rdx, [g_tpm_blob]
    mov     r8d, 512
    call    reg_tpm_get
    test    eax, eax
    jz      vdt_no
    mov     dword ptr [rbp-32], eax         ; blob length
    lea     rcx, [g_tpm_kn]
    lea     rdx, [g_tpm_blob]
    mov     r8d, dword ptr [rbp-32]
    lea     r9, [g_vkey]
    call    tpm_unseal
    test    eax, eax
    jz      vdt_no
    xor     eax, eax
    FRAME_EPILOG
    ret
vdt_no:
    mov     eax, EXIT_LOCKED
    FRAME_EPILOG
    ret
vk_derive_tpm endp

; ===========================================================================
; vault_tpm_remember() -> eax = 1/0.  Seal the current master key (g_vkey) to
;   the TPM and store the wrapped blob under HKCU\..\TPM-Unlock, enabling fast
;   unlock on this PC.  Precondition: vault just unlocked (g_vkey + g_hdr valid,
;   g_cfg_in = path).
; ===========================================================================
public vault_tpm_remember
vault_tpm_remember proc frame
    FRAME_PROLOG 48
    call    tpm_kn_build
    lea     rcx, [g_tpm_kn]
    lea     rdx, [g_vkey]
    lea     r8, [g_tpm_blob]
    mov     r9d, 512
    call    tpm_seal
    test    eax, eax
    jz      vtr_fail
    mov     dword ptr [rbp-32], eax         ; blob length
    mov     rcx, qword ptr [g_cfg_in]       ; value name = vault path
    lea     rdx, [g_tpm_blob]
    mov     r8d, dword ptr [rbp-32]
    call    reg_tpm_set
    test    eax, eax
    jz      vtr_fail
    mov     eax, 1
    FRAME_EPILOG
    ret
vtr_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_tpm_remember endp

; ===========================================================================
; vault_tpm_forget() -> eax = 1.  Delete the TPM key + the HKCU\..\TPM-Unlock
;   entry for this vault.  Precondition: g_hdr holds the vault header (so the key
;   name resolves) and g_cfg_in points at the vault path.
; ===========================================================================
public vault_tpm_forget
vault_tpm_forget proc frame
    FRAME_PROLOG 32
    call    tpm_kn_build
    lea     rcx, [g_tpm_kn]
    call    tpm_delete
    mov     rcx, qword ptr [g_cfg_in]       ; value name = vault path
    call    reg_tpm_del
    mov     eax, 1
    FRAME_EPILOG
    ret
vault_tpm_forget endp

; ===========================================================================
; vault_tpm_has() -> eax = 1 if a TPM-Unlock registry entry exists for g_cfg_in,
;   else 0.  Keyed by the vault path, so it works before the header is read.
; ===========================================================================
public vault_tpm_has
vault_tpm_has proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_tpm_blob]
    mov     r8d, 512
    call    reg_tpm_get
    test    eax, eax
    jz      vth_no
    mov     eax, 1
    FRAME_EPILOG
    ret
vth_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_tpm_has endp

; vk_kcv() - g_sha32 = SHA-256(g_vkey); leaves the 32-byte digest in g_sha32.
vk_kcv proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_vkey]
    mov     rdx, 32
    lea     r8, [g_sha32]
    call    sha256_hash
    FRAME_EPILOG
    ret
vk_kcv endp

; vk_kcv_ok() -> eax = 0 if KCV(g_vkey) matches the file header, else 1.
;   Constant-time compare (ct_memcmp) of the recomputed KCV against g_filebuf.
vk_kcv_ok proc frame
    FRAME_PROLOG 32
    call    vk_kcv
    lea     rcx, [g_sha32]
    mov     r10, qword ptr [g_filebuf]
    lea     rdx, [r10+VH_KCV]
    mov     r8, KCV_LEN
    call    ct_memcmp
    FRAME_EPILOG
    ret
vk_kcv_ok endp

; ===========================================================================
; vault_mkbak(rcx = out wide buf, dl = digit char) - write "<g_cfg_in>.bak<d>"
;   into the caller's buffer.  Leaf; clobbers rax/r8/r10/r11, preserves rdx.
; ===========================================================================
vault_mkbak proc
    mov     r10, qword ptr [g_cfg_in]
    mov     r11, rcx
    xor     r8, r8
vmb_cp:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      vmb_suf
    inc     r8
    cmp     r8, MAX_PATH_CHARS-8
    jb      vmb_cp
vmb_suf:
    mov     word ptr [r11+r8*2], '.'
    inc     r8
    mov     word ptr [r11+r8*2], 'b'
    inc     r8
    mov     word ptr [r11+r8*2], 'a'
    inc     r8
    mov     word ptr [r11+r8*2], 'k'
    inc     r8
    movzx   eax, dl
    mov     word ptr [r11+r8*2], ax
    inc     r8
    mov     word ptr [r11+r8*2], 0
    ret
vault_mkbak endp

; ===========================================================================
; vault_file_mac(rcx = data ptr, rdx = data len, r8 = out 32-byte) - keyed MAC
;   over the whole file image (+ trailing counter).  BLAKE2b is not length-
;   extendable, so prefix-keying MAC = BLAKE2b(domain || g_vkey || data) is a
;   sound MAC; the domain string separates it from any other use of the key.
; ===========================================================================
vault_file_mac proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx             ; data
    mov     qword ptr [rbp-32], rdx             ; len
    mov     qword ptr [rbp-40], r8              ; out
    lea     rcx, [g_fmac_ctx]
    mov     edx, FMAC_MACLEN
    call    blake2b_init
    lea     rcx, [g_fmac_ctx]                   ; domain-separation prefix
    lea     rdx, [fmac_domain]
    mov     r8, FMAC_DOMLEN
    call    blake2b_update
    lea     rcx, [g_fmac_ctx]                   ; key material (the vault key)
    lea     rdx, [g_vkey]
    mov     r8, 32
    call    blake2b_update
    lea     rcx, [g_fmac_ctx]                   ; the file image + counter
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    blake2b_update
    lea     rcx, [g_fmac_ctx]
    mov     rdx, qword ptr [rbp-40]
    call    blake2b_final
    FRAME_EPILOG
    ret
vault_file_mac endp

; ===========================================================================
; vault_ext_snapshot(rcx = on-disk size) - record (size, BLAKE2b of the header)
;   for the file we just loaded or wrote, so a later external change (a sync
;   tool or a second instance rewriting the file) can be detected before we
;   overwrite it.  Called after every unlock and every successful save.
; ===========================================================================
public vault_ext_snapshot
vault_ext_snapshot proc frame
    FRAME_PROLOG 32
    mov     qword ptr [g_ext_size], rcx
    lea     rcx, [g_hdr]
    mov     rdx, VH_TOTAL
    lea     r8, [g_ext_hash]
    mov     r9, 32
    call    blake2b_hash
    FRAME_EPILOG
    ret
vault_ext_snapshot endp

; ===========================================================================
; vault_ext_changed() -> eax = 1 if the vault file on disk no longer matches the
;   snapshot (size or header changed, or it can't be read), else 0.  A fresh
;   salt/nonce is written on every save, so any rewrite by another writer flips
;   the header hash.  Best-effort tripwire against silent clobbering.
; ===========================================================================
public vault_ext_changed
vault_ext_changed proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=buf [rbp-32]=size [rbp-40]=compare result
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [rbp-24]
    lea     r8, [rbp-32]
    call    read_file
    test    eax, eax
    jnz     vxc_changed                         ; unreadable/moved -> treat as changed
    mov     rax, qword ptr [rbp-32]
    cmp     rax, qword ptr [g_ext_size]
    jne     vxc_free_changed
    cmp     rax, VH_TOTAL
    jb      vxc_free_changed
    mov     rcx, qword ptr [rbp-24]             ; hash the current header
    mov     rdx, VH_TOTAL
    lea     r8, [g_fmac_out]                    ; scratch (32 bytes)
    mov     r9, 32
    call    blake2b_hash
    lea     rcx, [g_fmac_out]
    lea     rdx, [g_ext_hash]
    mov     r8, 32
    call    ct_memcmp                           ; 0 = header unchanged
    mov     dword ptr [rbp-40], eax
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
    cmp     dword ptr [rbp-40], 0
    jne     vxc_changed
    xor     eax, eax
    FRAME_EPILOG
    ret
vxc_free_changed:
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
vxc_changed:
    mov     eax, 1
    FRAME_EPILOG
    ret
vault_ext_changed endp

; ===========================================================================
; vault_rotate_backups() - before the atomic replace, roll the CURRENT vault
;   file into a ring of BAK_GENS generations: bak2->bak3, bak1->bak2, then copy
;   the live file to bak1.  A crash mid-save can thus never lose the vault - the
;   old copy survives as bak1.  Every step is best-effort (a missing generation
;   is fine); on the very first save g_cfg_in does not exist yet so the copy is
;   a harmless no-op.  Frame proc; no failure is fatal to the save.
; ===========================================================================
vault_rotate_backups proc frame
    FRAME_PROLOG 48
    lea     rcx, [g_bak_a]                      ; delete the oldest (bak3)
    mov     dl, '0' + BAK_GENS
    call    vault_mkbak
    WINCALL DeleteFileW, addr g_bak_a
    lea     rcx, [g_bak_a]                      ; bak2 -> bak3
    mov     dl, '0' + BAK_GENS - 1
    call    vault_mkbak
    lea     rcx, [g_bak_b]
    mov     dl, '0' + BAK_GENS
    call    vault_mkbak
    WINCALL MoveFileExW, addr g_bak_a, addr g_bak_b, MOVEFILE_REPLACE_EXISTING
    lea     rcx, [g_bak_a]                      ; bak1 -> bak2
    mov     dl, '1'
    call    vault_mkbak
    lea     rcx, [g_bak_b]
    mov     dl, '2'
    call    vault_mkbak
    WINCALL MoveFileExW, addr g_bak_a, addr g_bak_b, MOVEFILE_REPLACE_EXISTING
    lea     rcx, [g_bak_a]                      ; live vault -> bak1 (overwrite)
    mov     dl, '1'
    call    vault_mkbak
    WINCALL CopyFileW, qword ptr [g_cfg_in], addr g_bak_a, 0
    FRAME_EPILOG
    ret
vault_rotate_backups endp

; ===========================================================================
; vault_seal_write() - seal g_body (g_body_len bytes) under g_vkey with a fresh
;   nonce already placed in g_hdr, build the file image, write it to g_cfg_in.
;   -> eax = 0 / EXIT_IO / EXIT_OOM.
; ===========================================================================
vault_seal_write proc frame
    FRAME_PROLOG 80
    ; [rbp-32] = attachment section bytes (entries + trailer)  [rbp-40] = base len
    xor     ecx, ecx                            ; emit=0: size the attachment section
    xor     edx, edx
    call    attach_build
    mov     qword ptr [rbp-32], rax
    ; base image = VH_TOTAL + body_len + 16 + attachment section
    mov     rax, qword ptr [g_body_len]
    add     rax, VH_TOTAL + 16
    add     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-40], rax             ; base length (before the MAC trailer)
    add     rax, FMAC_TRAILER                   ; + [u64 counter][32 MAC][u32 magic]
    mov     qword ptr [g_outlen], rax
    mov     rcx, rax
    call    mem_alloc
    test    rax, rax
    jz      vsw_oom
    mov     qword ptr [g_outbuf], rax
    ; copy header (80 bytes)
    lea     r10, [g_hdr]
    mov     r11, rax
    xor     r8, r8
vsw_hcpy:
    mov     cl, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], cl
    inc     r8
    cmp     r8, VH_TOTAL
    jb      vsw_hcpy
    ; gcm_seal: ct -> outbuf+80, tag -> outbuf+80+body_len
    lea     r10, [g_greq]
    lea     rax, [g_vkey]
    mov     qword ptr [r10].GCMREQ.key, rax
    lea     rax, [g_hdr+VH_NONCE]
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_hdr]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, VH_TOTAL
    mov     rax, qword ptr [g_body_ptr]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     rax, qword ptr [g_body_len]
    mov     qword ptr [r10].GCMREQ.inlen, rax
    mov     rax, qword ptr [g_outbuf]
    add     rax, VH_TOTAL
    mov     qword ptr [r10].GCMREQ.outp, rax
    mov     rax, qword ptr [g_outbuf]
    add     rax, VH_TOTAL
    add     rax, qword ptr [g_body_len]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_greq]
    call    gcm_seal
    ; emit the attachment section right after the body tag (seals new blobs,
    ; copies existing ones from the old image)
    cmp     qword ptr [rbp-32], 0
    je      vsw_write
    mov     ecx, 1                              ; emit=1
    mov     rdx, qword ptr [g_outbuf]
    add     rdx, VH_TOTAL + 16
    add     rdx, qword ptr [g_body_len]
    call    attach_build
vsw_write:
    ; --- full-file MAC + anti-rollback trailer ------------------
    ; layout at offset base: [u64 counter][32 MAC over image+counter][u32 magic]
    inc     qword ptr [g_save_counter]          ; monotonic: this save's number
    mov     r10, qword ptr [g_outbuf]
    add     r10, qword ptr [rbp-40]             ; -> trailer start (= base offset)
    mov     rax, qword ptr [g_save_counter]
    mov     qword ptr [r10], rax                ; write the counter
    mov     rcx, qword ptr [g_outbuf]           ; MAC over image + counter
    mov     rdx, qword ptr [rbp-40]
    add     rdx, 8                              ; len = base + 8 (counter)
    lea     r8, [g_fmac_out]
    call    vault_file_mac
    mov     r10, qword ptr [g_outbuf]           ; copy MAC after the counter
    add     r10, qword ptr [rbp-40]
    add     r10, 8
    lea     r11, [g_fmac_out]
    xor     r8, r8
vsw_maccp:
    mov     al, byte ptr [r11+r8]
    mov     byte ptr [r10+r8], al
    inc     r8
    cmp     r8, FMAC_MACLEN
    jb      vsw_maccp
    mov     dword ptr [r10+FMAC_MACLEN], FMAC_MAGIC
    mov     qword ptr [g_fmac_len], FMAC_TRAILER
    ; --- atomic write: build temp path = g_cfg_in + ".tmp" -----------------
    mov     r10, qword ptr [g_cfg_in]
    lea     r11, [g_tmppath]
    xor     r8, r8
vsw_pcpy:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      vsw_pdone
    inc     r8
    cmp     r8, MAX_PATH_CHARS-8
    jb      vsw_pcpy
vsw_pdone:
    mov     word ptr [r11+r8*2], '.'
    inc     r8
    mov     word ptr [r11+r8*2], 't'
    inc     r8
    mov     word ptr [r11+r8*2], 'm'
    inc     r8
    mov     word ptr [r11+r8*2], 'p'
    inc     r8
    mov     word ptr [r11+r8*2], 0
    ; write the image to the temp file.  C7: delete any stale/pre-planted temp,
    ; then create it exclusively (CREATE_NEW) so a re-planted symlink at that name
    ; is refused rather than silently followed.
    WINCALL DeleteFileW, addr g_tmppath
    mov     dword ptr [g_wf_disp], 1             ; CREATE_NEW (one-shot)
    lea     rcx, [g_tmppath]
    mov     rdx, qword ptr [g_outbuf]
    mov     r8, qword ptr [g_outlen]
    call    write_file
    test    eax, eax
    jnz     vsw_io
    ; roll the current file into .bak1..N before we overwrite it (best-effort)
    call    vault_rotate_backups
    ; atomic replace: rename temp -> the real vault path
    lea     rcx, [g_tmppath]
    mov     rdx, qword ptr [g_cfg_in]
    call    file_rename
    mov     dword ptr [rbp-24], eax
    test    eax, eax
    jnz     vsw_free                            ; write/rename failed -> free outbuf
    ; success: the image we just wrote becomes the resident file image, so newly
    ; sealed attachments are readable without a re-read.  Retire the old image,
    ; drop the pending list, and rebuild the attachment index.
    mov     rcx, qword ptr [g_filebuf]
    test    rcx, rcx
    jz      vsw_swap
    mov     rdx, qword ptr [g_filesize]
    call    mem_free
vsw_swap:
    mov     rax, qword ptr [g_outbuf]
    mov     qword ptr [g_filebuf], rax
    mov     rax, qword ptr [g_outlen]
    mov     qword ptr [g_filesize], rax
    mov     qword ptr [g_outbuf], 0             ; ownership moved to g_filebuf
    call    attach_reset
    call    attach_rescan
    ; mirror the new save counter in HKCU so a later restore of an older file
    ; can be flagged as a rollback (best-effort - registry failure is non-fatal)
    mov     rax, qword ptr [g_save_counter]
    mov     qword ptr [g_ctr_io], rax
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_ctr_io]
    mov     r8d, 8
    call    reg_ctr_set
    mov     rcx, qword ptr [g_filesize]         ; re-snapshot: this save is now baseline
    call    vault_ext_snapshot
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
vsw_io:
    mov     dword ptr [rbp-24], EXIT_IO
vsw_free:
    ; free outbuf (ciphertext only - no plaintext secret - but wipe anyway)
    mov     rcx, qword ptr [g_outbuf]
    mov     rdx, qword ptr [g_outlen]
    call    mem_free
    mov     qword ptr [g_outbuf], 0
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
vsw_oom:
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
vault_seal_write endp

; ===========================================================================
; vault_unlock() - read g_cfg_in, derive key, KCV-check, gcm_open into secmem.
;   On success: g_body_ptr (secmem, VAULT_BODY_MAX), g_body_len set.  g_hdr holds
;   the 80-byte header (so a reseal reuses salt/t/m).  -> eax = 0 / EXIT_*.
; ===========================================================================
public vault_unlock
vault_unlock proc frame
    FRAME_PROLOG 48
    ; [rbp-24] = ciphertext length
    mov     qword ptr [g_body_ptr], 0
    ; read the whole file
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_filebuf]
    lea     r8, [g_filesize]
    call    read_file
    test    eax, eax
    jnz     vu_io
    ; minimum size: header + 4-byte empty body + tag
    mov     rax, qword ptr [g_filesize]
    cmp     rax, VH_TOTAL + 4 + 16
    jb      vu_corrupt
    ; magic + version
    mov     r10, qword ptr [g_filebuf]
    cmp     dword ptr [r10], VAULT_MAGIC
    jne     vu_corrupt
    cmp     dword ptr [r10+4], VAULT_VERSION
    jne     vu_corrupt
    ; copy 80-byte header into g_hdr
    lea     r9, [g_hdr]
    xor     r8, r8
vu_hcpy:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r9+r8], al
    inc     r8
    cmp     r8, VH_TOTAL
    jb      vu_hcpy
    ; derive key (TPM sidecar or master password) + KCV check
    cmp     dword ptr [g_reuse_key], 0  ; C8 reload: g_vkey already derived - skip Argon2
    jne     vu_havekey                  ; (KCV below still re-verifies it fits the file)
    cmp     dword ptr [g_use_tpm], 0
    je      vu_pwderive
    call    vk_derive_tpm
    test    eax, eax
    jnz     vu_locked                   ; no/failed TPM -> GUI falls back to pw
    jmp     vu_havekey
vu_pwderive:
    call    vk_derive                   ; Argon2id
    test    eax, eax
    jnz     vu_oom
vu_havekey:
    call    vk_kcv_ok
    test    eax, eax
    jnz     vu_locked
    ; --- full-file MAC + anti-rollback trailer ------------------
    ; The file MUST end in FMAC_MAGIC and carry a valid keyed MAC over everything
    ; before it.  This authenticates the attachment section (which GCM does NOT
    ; cover - GCM authenticates only the record body via the header AAD) and makes
    ; the anti-rollback counter non-strippable.  The trailer is MANDATORY: every
    ; save (vault_seal_write) writes it, so a file lacking it is rejected as tamper
    ; rather than silently accepted (which would let an attacker strip the MAC and
    ; splice arbitrary, unauthenticated attachment bytes - see attach_index_build).
    call    reg_prune_all                       ; C6: drop legacy path-named reg values
    mov     qword ptr [g_fmac_len], 0
    mov     qword ptr [g_save_counter], 0
    mov     dword ptr [g_rollback], 0
    mov     rax, qword ptr [g_filesize]
    cmp     rax, VH_TOTAL + 4 + 16 + FMAC_TRAILER
    jb      vu_auth                             ; too small to carry the MAC -> reject
    mov     r11, qword ptr [g_filebuf]
    add     r11, rax
    cmp     dword ptr [r11-4], FMAC_MAGIC       ; magic at the very end?
    jne     vu_auth                             ; no trailer -> reject (MAC is mandatory)
    mov     rcx, qword ptr [g_filebuf]          ; MAC over image + counter
    mov     rdx, rax
    sub     rdx, FMAC_MACLEN + 4                ; data len = filesize - 36
    lea     r8, [g_fmac_out]
    call    vault_file_mac
    lea     rcx, [g_fmac_out]                   ; constant-time compare vs stored MAC
    mov     r11, qword ptr [g_filebuf]
    add     r11, qword ptr [g_filesize]
    sub     r11, FMAC_MACLEN + 4
    mov     rdx, r11
    mov     r8, FMAC_MACLEN
    call    ct_memcmp
    test    eax, eax
    jnz     vu_auth                             ; file MAC mismatch = tamper
    mov     r11, qword ptr [g_filebuf]          ; read the save counter
    add     r11, qword ptr [g_filesize]
    sub     r11, FMAC_TRAILER
    mov     rax, qword ptr [r11]
    mov     qword ptr [g_save_counter], rax
    mov     qword ptr [g_fmac_len], FMAC_TRAILER
    ; anti-rollback: compare this file's counter against the HKCU mirror.  If the
    ; file is OLDER than the last one this machine saved, flag it (the GUI warns).
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_ctr_io]
    mov     r8d, 8
    call    reg_ctr_get
    cmp     eax, 8                              ; got a full u64 mirror?
    jne     vu_nofmac
    mov     rax, qword ptr [g_save_counter]
    cmp     rax, qword ptr [g_ctr_io]
    jae     vu_nofmac                           ; counter >= mirror -> not a rollback
    mov     dword ptr [g_rollback], 1
vu_nofmac:
    ; detect the attachments trailer at the end of the base image (absent = old)
    mov     qword ptr [g_att_total], 0
    mov     rax, qword ptr [g_filesize]
    sub     rax, qword ptr [g_fmac_len]         ; effective end = image without MAC
    cmp     rax, VH_TOTAL + 4 + 16 + ATT_TRAILER
    jb      vu_ctlen
    mov     r11, qword ptr [g_filebuf]
    add     r11, rax
    sub     r11, ATT_TRAILER
    cmp     dword ptr [r11], ATT_MAGIC
    jne     vu_ctlen
    mov     r9, qword ptr [r11+4]               ; attachment entries length
    mov     rcx, r9
    add     rcx, VH_TOTAL + 16 + ATT_TRAILER + 4
    cmp     rcx, rax
    ja      vu_ctlen                            ; implausible -> ignore
    mov     qword ptr [g_att_total], r9
vu_ctlen:
    ; body ciphertext length = effective_end - 80 - 16 - (att_total + trailer)
    mov     rax, qword ptr [g_filesize]
    sub     rax, qword ptr [g_fmac_len]
    sub     rax, VH_TOTAL + 16
    mov     r9, qword ptr [g_att_total]
    test    r9, r9
    jz      vu_ctset
    sub     rax, r9
    sub     rax, ATT_TRAILER
vu_ctset:
    mov     qword ptr [rbp-24], rax
    ; attachments begin right after the body tag
    mov     r10, rax
    add     r10, VH_TOTAL + 16
    mov     qword ptr [g_att_start], r10
    cmp     rax, VAULT_BODY_MAX
    ja      vu_corrupt
    ; allocate locked plaintext arena
    mov     rcx, VAULT_BODY_MAX
    call    secmem_alloc
    test    rax, rax
    jz      vu_oom
    mov     qword ptr [g_body_ptr], rax
    ; gcm_open(key, iv=hdr.nonce, aad=hdr80, inp=file+80, inlen=ctlen, outp=body, tag=file+80+ctlen)
    lea     r10, [g_greq]
    lea     rax, [g_vkey]
    mov     qword ptr [r10].GCMREQ.key, rax
    lea     rax, [g_hdr+VH_NONCE]
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_hdr]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, VH_TOTAL
    mov     r11, qword ptr [g_filebuf]
    lea     rax, [r11+VH_TOTAL]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [r10].GCMREQ.inlen, rax
    mov     rax, qword ptr [g_body_ptr]
    mov     qword ptr [r10].GCMREQ.outp, rax
    mov     r11, qword ptr [g_filebuf]
    lea     rax, [r11+VH_TOTAL]
    add     rax, qword ptr [rbp-24]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_greq]
    call    gcm_open
    test    eax, eax
    jnz     vu_auth
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [g_body_len], rax
    ; fail closed if the (now authenticated) record stream is structurally
    ; malformed, so the trusting accessors never walk past the buffer.
    call    vault_body_validate
    test    eax, eax
    jnz     vu_auth
    ; keep the file image resident: attachment ciphertext lives in it.  Build the
    ; id->ciphertext index from the attachments section.
    call    attach_index_build
    mov     rcx, qword ptr [g_filesize]         ; snapshot for external-change detection
    call    vault_ext_snapshot
    xor     eax, eax
    FRAME_EPILOG
    ret
vu_io:
    mov     eax, EXIT_IO
    jmp     vu_cleanfile
vu_corrupt:
    mov     eax, EXIT_CORRUPT
    jmp     vu_cleanfile
vu_locked:
    mov     eax, EXIT_LOCKED
    jmp     vu_cleanfile
vu_auth:
    mov     eax, EXIT_AUTH
    jmp     vu_cleanall
vu_oom:
    mov     eax, EXIT_OOM
    jmp     vu_cleanall
vu_cleanall:
    ; free secmem body if allocated
    mov     qword ptr [rbp-24], rax
    mov     rcx, qword ptr [g_body_ptr]
    test    rcx, rcx
    jz      vu_cleanfile2
    mov     rdx, VAULT_BODY_MAX
    call    secmem_free
    mov     qword ptr [g_body_ptr], 0
vu_cleanfile2:
    mov     eax, dword ptr [rbp-24]
vu_cleanfile:
    mov     qword ptr [rbp-24], rax
    mov     rcx, qword ptr [g_filebuf]
    test    rcx, rcx
    jz      vu_ret
    mov     rdx, qword ptr [g_filesize]
    call    mem_free
    mov     qword ptr [g_filebuf], 0
vu_ret:
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
vault_unlock endp

; vault_lock() - wipe + free the secmem body and wipe the master key.
public vault_lock
vault_lock proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [g_body_ptr]
    test    rcx, rcx
    jz      vl_key
    mov     rdx, VAULT_BODY_MAX
    call    secmem_free
    mov     qword ptr [g_body_ptr], 0
vl_key:
    call    attach_reset                        ; free pending attachment plaintext
    mov     rcx, qword ptr [g_filebuf]           ; free the resident file image
    test    rcx, rcx
    jz      vl_wipe
    mov     rdx, qword ptr [g_filesize]
    call    mem_free
    mov     qword ptr [g_filebuf], 0
vl_wipe:
    lea     rcx, [g_vkey]
    mov     rdx, 32
    call    secure_zero
    lea     rcx, [g_conv]                       ; wipe plaintext field-value scratch
    mov     edx, CONV_CAP
    call    secure_zero
    lea     rcx, [g_convlabel]                  ; wipe plaintext field-label scratch
    mov     edx, MAX_LABEL_BYTES
    call    secure_zero
    FRAME_EPILOG
    ret
vault_lock endp

; ===========================================================================
; vault_reload() - C8: re-read the vault file and re-decrypt with the EXISTING key
;   (no Argon2 re-run), replacing the in-memory body.  Used when another user
;   saved the vault on a shared drive.  Frees the current resident image + body
;   first (keeps g_vkey / g_hdr / g_cfg_in).  -> eax = 0 / EXIT_*.
; ===========================================================================
public vault_reload
vault_reload proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [g_body_ptr]         ; free the current secmem body
    test    rcx, rcx
    jz      vr_nobody
    mov     rdx, VAULT_BODY_MAX
    call    secmem_free
    mov     qword ptr [g_body_ptr], 0
vr_nobody:
    call    attach_reset                        ; free pending attachment plaintext
    mov     rcx, qword ptr [g_filebuf]          ; free the current resident file image
    test    rcx, rcx
    jz      vr_nofile
    mov     rdx, qword ptr [g_filesize]
    call    mem_free
    mov     qword ptr [g_filebuf], 0
vr_nofile:
    mov     dword ptr [g_reuse_key], 1          ; re-open reusing g_vkey (skip the KDF)
    call    vault_unlock
    mov     dword ptr [g_reuse_key], 0
    FRAME_EPILOG
    ret
vault_reload endp

; ===========================================================================

; ===========================================================================
; do_init - create a new empty vault at g_cfg_in.
; ===========================================================================
public do_init
do_init proc frame
    FRAME_PROLOG 48
    mov     qword ptr [g_save_counter], 0       ; fresh vault: first save is counter 1
    ; build header
    mov     dword ptr [g_hdr+0], VAULT_MAGIC
    mov     dword ptr [g_hdr+4], VAULT_VERSION
    mov     eax, dword ptr [g_cfg_t]
    mov     dword ptr [g_hdr+VH_T], eax
    mov     eax, dword ptr [g_cfg_m]
    mov     dword ptr [g_hdr+VH_M], eax
    mov     dword ptr [g_hdr+VH_LANES], 1
    lea     rcx, [g_hdr+VH_SALT]
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      di_oom
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      di_oom
    call    vk_derive
    test    eax, eax
    jnz     di_oom
    call    vk_kcv                      ; g_sha32 = SHA-256(key)
    ; KCV = sha32[0..15] -> g_hdr+VH_KCV
    lea     r10, [g_sha32]
    lea     r9, [g_hdr+VH_KCV]
    xor     r8, r8
di_kcv:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r9+r8], al
    inc     r8
    cmp     r8, KCV_LEN
    jb      di_kcv
    ; empty body: count = 0 (4 bytes) in a freshly allocated secmem arena
    mov     rcx, VAULT_BODY_MAX
    call    secmem_alloc
    test    rax, rax
    jz      di_oom
    mov     qword ptr [g_body_ptr], rax
    mov     dword ptr [rax], 0
    mov     qword ptr [g_body_len], 4
    call    vault_seal_write
    mov     qword ptr [rbp-24], rax
    call    vault_lock
    mov     eax, dword ptr [rbp-24]
    test    eax, eax
    jnz     di_io
    lea     rcx, [m_created]
    mov     edx, m_created_len
    call    print_a
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
di_io:
    lea     rcx, [e_io]
    mov     edx, e_io_len
    call    print_err
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
di_oom:
    call    vault_lock
    lea     rcx, [e_oom]
    mov     edx, e_oom_len
    call    print_err
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
do_init endp

; ===========================================================================
; seedtest: bulk-create a fresh vault full of realistic entries (perf/search
;   testing).  do_seed(ecx = count).  Uses g_cfg_in/pass/t/m already set up.
; ===========================================================================
url_pfx db "https://www.", 0
include seed_data.inc

; asc2w(rcx = dst wide, rdx = src ascii NUL-term, r8d = lowercase) -> rax = dst end.
asc2w proc
a2w_lp:
    movzx   eax, byte ptr [rdx]
    test    al, al
    jz      a2w_done
    test    r8d, r8d
    jz      a2w_put
    cmp     al, 'A'
    jb      a2w_put
    cmp     al, 'Z'
    ja      a2w_put
    add     al, 20h
a2w_put:
    mov     word ptr [rcx], ax
    add     rcx, 2
    inc     rdx
    jmp     a2w_lp
a2w_done:
    mov     rax, rcx
    ret
asc2w endp

; seed_make_entry(ecx = index) - build g_field_list (title/user/url/secret) for a
;   deterministic, realistic entry.
seed_make_entry proc frame
    FRAME_PROLOG 96
    mov     dword ptr [rbp-24], ecx           ; i
    mov     eax, ecx                           ; svc = i mod SVC_COUNT
    xor     edx, edx
    mov     r8d, SVC_COUNT
    div     r8d
    mov     dword ptr [rbp-28], edx            ; svc
    xor     edx, edx                           ; qual = (i / SVC_COUNT) mod QUAL_COUNT
    mov     r8d, QUAL_COUNT
    div     r8d
    mov     dword ptr [rbp-32], edx            ; qual
    mov     eax, dword ptr [rbp-24]            ; first = (i*7+3) mod FN_COUNT
    imul    eax, eax, 7
    add     eax, 3
    xor     edx, edx
    mov     r8d, FN_COUNT
    div     r8d
    mov     dword ptr [rbp-36], edx
    mov     eax, dword ptr [rbp-24]            ; last = (i*13+5) mod LN_COUNT
    imul    eax, eax, 13
    add     eax, 5
    xor     edx, edx
    mov     r8d, LN_COUNT
    div     r8d
    mov     dword ptr [rbp-40], edx
    mov     eax, dword ptr [rbp-28]            ; svc name / domain ptrs
    imul    eax, eax, SVC_W
    lea     r10, [svc_names]
    add     r10, rax
    mov     qword ptr [rbp-48], r10
    mov     eax, dword ptr [rbp-28]
    imul    eax, eax, DOM_W
    lea     r10, [svc_doms]
    add     r10, rax
    mov     qword ptr [rbp-56], r10
    ; title = "<name> <qual>"
    lea     rcx, [seed_title_w]
    mov     rdx, qword ptr [rbp-48]
    xor     r8d, r8d
    call    asc2w
    mov     word ptr [rax], ' '
    add     rax, 2
    mov     rcx, rax
    mov     eax, dword ptr [rbp-32]
    imul    eax, eax, QUAL_W
    lea     r10, [quals]
    add     r10, rax
    mov     rdx, r10
    xor     r8d, r8d
    call    asc2w
    mov     word ptr [rax], 0
    ; username = "<first>.<last>@<domain>" (lowercased)
    lea     rcx, [seed_user_w]
    mov     eax, dword ptr [rbp-36]
    imul    eax, eax, NAME_W
    lea     r10, [first_names]
    add     r10, rax
    mov     rdx, r10
    mov     r8d, 1
    call    asc2w
    mov     word ptr [rax], '.'
    add     rax, 2
    mov     rcx, rax
    mov     eax, dword ptr [rbp-40]
    imul    eax, eax, NAME_W
    lea     r10, [last_names]
    add     r10, rax
    mov     rdx, r10
    mov     r8d, 1
    call    asc2w
    mov     word ptr [rax], '@'
    add     rax, 2
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-56]
    xor     r8d, r8d
    call    asc2w
    mov     word ptr [rax], 0
    ; url = "https://www.<domain>"
    lea     rcx, [seed_url_w]
    lea     rdx, [url_pfx]
    xor     r8d, r8d
    call    asc2w
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-56]
    xor     r8d, r8d
    call    asc2w
    mov     word ptr [rax], 0
    ; secret = random 16 (no ambiguous)
    lea     rcx, [seed_pass_a]
    mov     edx, 16
    mov     r8d, PWS_RANDOM
    mov     r9d, 15 or PWO_NOAMBIG
    mov     dword ptr [g_pwgen_outcap], 40      ; E16: seed_pass_a capacity
    call    pwgen_ex
    lea     rcx, [seed_pass_w]
    lea     rdx, [seed_pass_a]
    xor     r8d, r8d
    call    asc2w
    mov     word ptr [rax], 0
    ; compose g_field_list (title / username / url / secret)
    lea     r11, [g_field_list]
    mov     qword ptr [r11+0], VF_TITLE
    mov     qword ptr [r11+8], 0
    lea     rax, [seed_title_w]
    mov     qword ptr [r11+16], rax
    mov     qword ptr [r11+24], VF_USERNAME
    mov     qword ptr [r11+32], 0
    lea     rax, [seed_user_w]
    mov     qword ptr [r11+40], rax
    mov     qword ptr [r11+48], VF_URL
    mov     qword ptr [r11+56], 0
    lea     rax, [seed_url_w]
    mov     qword ptr [r11+64], rax
    mov     qword ptr [r11+72], VF_SECRET
    mov     qword ptr [r11+80], 0
    lea     rax, [seed_pass_w]
    mov     qword ptr [r11+88], rax
    mov     dword ptr [g_field_n], 4
    FRAME_EPILOG
    ret
seed_make_entry endp

public do_seed
do_seed proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], ecx            ; count
    mov     dword ptr [g_hdr+0], VAULT_MAGIC
    mov     dword ptr [g_hdr+4], VAULT_VERSION
    mov     eax, dword ptr [g_cfg_t]
    mov     dword ptr [g_hdr+VH_T], eax
    mov     eax, dword ptr [g_cfg_m]
    mov     dword ptr [g_hdr+VH_M], eax
    mov     dword ptr [g_hdr+VH_LANES], 1
    lea     rcx, [g_hdr+VH_SALT]
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      ds_oom
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      ds_oom
    call    vk_derive
    test    eax, eax
    jnz     ds_oom
    call    vk_kcv
    lea     r10, [g_sha32]
    lea     r9, [g_hdr+VH_KCV]
    xor     r8, r8
ds_kcv:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r9+r8], al
    inc     r8
    cmp     r8, KCV_LEN
    jb      ds_kcv
    mov     rcx, VAULT_BODY_MAX
    call    secmem_alloc
    test    rax, rax
    jz      ds_oom
    mov     qword ptr [g_body_ptr], rax
    mov     dword ptr [rax], 0
    mov     qword ptr [g_body_len], 4
    mov     dword ptr [rbp-28], 0             ; i
ds_loop:
    mov     eax, dword ptr [rbp-28]
    cmp     eax, dword ptr [rbp-24]
    jae     ds_seal
    mov     ecx, eax
    call    seed_make_entry
    call    vault_build_entry
    inc     dword ptr [rbp-28]
    jmp     ds_loop
ds_seal:
    call    vault_seal_write
    mov     dword ptr [rbp-32], eax
    call    vault_lock
    mov     eax, dword ptr [rbp-32]
    FRAME_EPILOG
    ret
ds_oom:
    call    vault_lock
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
do_seed endp

; ===========================================================================
; do_attgen() -> eax 0/err.  Build an in-memory vault body holding a single
;   entry with one image/file attachment (staged pending), for headless export
;   testing.  No key derivation / seal - just enough state for ze_compose to walk
;   the body and attach_open the pending blob.
; ===========================================================================
.const
align 2
ag_title dw 'A','t','t','a','c','h','T','e','s','t',0
ag_fname dw 'h','e','l','l','o','.','t','x','t',0        ; 10 wide chars incl NUL
ag_fnam2 dw 'w','o','r','l','d','.','d','a','t',0        ; 10 wide chars incl NUL
ag_plain db "HELLO-ATTACHMENT-PAYLOAD-0123456789"        ; 35 plaintext bytes
AG_PLAIN_LEN equ 35
ag_plai2 db "WORLD-SECOND-ATTACHMENT-9876543210"         ; 34 plaintext bytes
AG_PLAI2_LEN equ 34
AG_FNAME_BYTES equ 20                                     ; 10 wide chars * 2
.data?
ag_ref  db ARF_SIZE dup (?)
ag_ref2 db ARF_SIZE dup (?)
ag_blob db 4 + ARF_SIZE + AG_FNAME_BYTES dup (?)          ; {u32 rawlen, AttachRef, filename}
ag_blb2 db 4 + ARF_SIZE + AG_FNAME_BYTES dup (?)
.code
; ag_mkblob(rcx = AttachRef ptr, rdx = wide filename ptr, r8 = dst blob ptr) -
;   dst = {u32 rawlen=68+20, AttachRef[68], filename[10 wide]}.  Leaf.
ag_mkblob proc
    mov     dword ptr [r8], ARF_SIZE + AG_FNAME_BYTES
    xor     r9d, r9d
amk_ref:
    mov     al, byte ptr [rcx+r9]
    mov     byte ptr [r8+4+r9], al
    inc     r9d
    cmp     r9d, ARF_SIZE
    jb      amk_ref
    xor     r9d, r9d
amk_fn:
    mov     ax, word ptr [rdx+r9*2]
    mov     word ptr [r8+4+ARF_SIZE+r9*2], ax
    inc     r9d
    cmp     r9d, 10
    jb      amk_fn
    ret
ag_mkblob endp

public do_attgen
do_attgen proc frame
    FRAME_PROLOG 48
    call    attach_reset                        ; clear any pending attachments
    mov     rcx, VAULT_BODY_MAX
    call    secmem_alloc
    test    rax, rax
    jz      ag_oom
    mov     qword ptr [g_body_ptr], rax
    mov     dword ptr [rax], 0                   ; entry_count = 0
    mov     qword ptr [g_body_len], 4
    lea     rcx, [ag_plain]                      ; stage attachment #1
    mov     edx, AG_PLAIN_LEN
    lea     r8, [ag_ref]
    call    attach_stage
    test    eax, eax
    jnz     ag_err
    lea     rcx, [ag_plai2]                      ; stage attachment #2
    mov     edx, AG_PLAI2_LEN
    lea     r8, [ag_ref2]
    call    attach_stage
    test    eax, eax
    jnz     ag_err
    lea     rcx, [ag_ref]                        ; blobs = {u32 len, ref, filename}
    lea     rdx, [ag_fname]
    lea     r8, [ag_blob]
    call    ag_mkblob
    lea     rcx, [ag_ref2]
    lea     rdx, [ag_fnam2]
    lea     r8, [ag_blb2]
    call    ag_mkblob
    ; g_field_list: [0]=title, [1]=image (hello.txt), [2]=file (world.dat)
    lea     r10, [g_field_list]
    mov     qword ptr [r10+0], VF_TITLE
    mov     qword ptr [r10+8], 0
    lea     rax, [ag_title]
    mov     qword ptr [r10+16], rax
    mov     qword ptr [r10+24], VF_IMAGE or VFL_RAW
    mov     qword ptr [r10+32], 0
    lea     rax, [ag_blob]
    mov     qword ptr [r10+40], rax
    mov     qword ptr [r10+48], VF_FILE or VFL_RAW
    mov     qword ptr [r10+56], 0
    lea     rax, [ag_blb2]
    mov     qword ptr [r10+64], rax
    mov     dword ptr [g_field_n], 3
    call    vault_build_entry
    FRAME_EPILOG
    ret
ag_err:
    mov     eax, 1
    FRAME_EPILOG
    ret
ag_oom:
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
do_attgen endp






; ===========================================================================
; vault_entry_len(rcx = entry ptr) -> rax = total entry length in bytes.  Leaf.
; (id16 + created8 + modified8 + fcount4 + sum over fields of 6+len)
; ===========================================================================
vault_entry_len proc
    lea     r10, [rcx+32]                   ; -> field_count
    mov     r8d, dword ptr [r10]
    add     r10, 4
vel_loop:
    test    r8d, r8d
    jz      vel_done
    mov     r9d, dword ptr [r10+2]          ; field len
    add     r10, 6
    add     r10, r9
    dec     r8d
    jmp     vel_loop
vel_done:
    sub     r10, rcx
    mov     rax, r10
    ret
vault_entry_len endp

; ===========================================================================
; find_field_in(rcx = entry ptr, edx = field type) -> rax = value ptr (0 if
;   absent), rdx = value len.  Leaf.
; ===========================================================================
find_field_in proc
    lea     r10, [rcx+32]
    mov     r8d, dword ptr [r10]
    add     r10, 4
ffi_loop:
    test    r8d, r8d
    jz      ffi_none
    movzx   eax, word ptr [r10]             ; raw type (kind | VF_LABELED)
    mov     r9d, dword ptr [r10+2]          ; field bytes len
    mov     ecx, eax
    and     ecx, VF_KINDMASK                ; base kind
    cmp     ecx, edx
    jne     ffi_skip
    lea     rcx, [r10+6]                    ; -> bytes
    test    eax, VF_LABELED                 ; skip "u16 labellen | label" prefix
    jz      ffi_plain
    movzx   eax, word ptr [rcx]             ; labellen
    add     rcx, 2
    add     rcx, rax
    sub     r9, 2
    sub     r9, rax                         ; value len = fieldlen - 2 - labellen
ffi_plain:
    mov     rax, rcx
    mov     rdx, r9
    ret
ffi_skip:
    add     r10, 6
    add     r10, r9
    dec     r8d
    jmp     ffi_loop
ffi_none:
    xor     eax, eax
    xor     edx, edx
    ret
find_field_in endp

; ===========================================================================
; vault_body_validate() -> eax = 0 if the plaintext body (g_body_ptr /
;   g_body_len) is a well-formed entry/field stream fully contained within
;   g_body_len; eax = 1 if any count or length field would drive a walk past
;   the buffer.  The trusting accessors (vault_entry_len / find_field_in) read
;   in-band lengths WITHOUT re-bounding, so this runs once right after gcm_open
;   succeeds and fails the unlock closed on a malformed stream - defence in
;   depth even though GCM already authenticates the plaintext.  Leaf; every
;   step is bounded, so a hostile count/length can only cause an early reject,
;   never a long loop.  Layout: u32 entry_count, then per entry
;   { id16, created8, modified8, u32 field_count, {u16 type,u32 len,bytes}* }.
; ===========================================================================
public vault_body_validate
vault_body_validate proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=body ptr  [rbp-32]=body_len  [rbp-40]=offset
    ; [rbp-48]=entries remaining  [rbp-56]=fields remaining
    mov     r10, qword ptr [g_body_ptr]
    test    r10, r10
    jz      vbv_bad
    mov     qword ptr [rbp-24], r10
    mov     r11, qword ptr [g_body_len]
    mov     qword ptr [rbp-32], r11
    cmp     r11, 4                              ; must hold at least the u32 count
    jb      vbv_bad
    mov     eax, dword ptr [r10]                ; entry_count
    mov     dword ptr [rbp-48], eax
    mov     qword ptr [rbp-40], 4               ; first entry begins after the count
vbv_entry:
    mov     eax, dword ptr [rbp-48]
    test    eax, eax
    jz      vbv_tail
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [rcx+36]                       ; entry header = id16+c8+m8+fc4
    cmp     rdx, qword ptr [rbp-32]
    ja      vbv_bad
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [r10+rcx+32]         ; field_count
    mov     dword ptr [rbp-56], eax
    add     rcx, 36
    mov     qword ptr [rbp-40], rcx             ; -> first field
vbv_field:
    mov     eax, dword ptr [rbp-56]
    test    eax, eax
    jz      vbv_entrynext
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [rcx+6]                        ; room for the {u16 type,u32 len} header
    cmp     rdx, qword ptr [rbp-32]
    ja      vbv_bad
    mov     r10, qword ptr [rbp-24]
    movzx   eax, word ptr [r10+rcx]             ; raw type (kind | flags)
    mov     r8d, dword ptr [r10+rcx+2]          ; field len (zero-extended into r8)
    lea     rdx, [rcx+6]
    add     rdx, r8                             ; field end offset
    cmp     rdx, qword ptr [rbp-32]             ; whole field within the body?
    ja      vbv_bad
    test    eax, VF_LABELED                     ; labelled field: {u16 labellen, label, value}
    jz      vbv_fadv
    cmp     r8, 2
    jb      vbv_bad                             ; no room for the labellen prefix
    movzx   eax, word ptr [r10+rcx+6]           ; labellen
    add     eax, 2
    cmp     rax, r8                             ; 2 + labellen must fit inside the field
    ja      vbv_bad
vbv_fadv:
    mov     rcx, qword ptr [rbp-40]
    add     rcx, 6
    add     rcx, r8
    mov     qword ptr [rbp-40], rcx
    dec     dword ptr [rbp-56]
    jmp     vbv_field
vbv_entrynext:
    dec     dword ptr [rbp-48]
    jmp     vbv_entry
vbv_tail:
    ; the walk must consume the body exactly - a reseal writes no slack, and a
    ; shortfall would mean a bogus (too-small) count hid trailing records.
    mov     rcx, qword ptr [rbp-40]
    cmp     rcx, qword ptr [rbp-32]
    jne     vbv_bad
    xor     eax, eax
    FRAME_EPILOG
    ret
vbv_bad:
    mov     eax, 1
    FRAME_EPILOG
    ret
vault_body_validate endp

; vfz_rand() -> rax = next xorshift64 value (updates g_vfz_rng).  Leaf; rcx dead.
vfz_rand proc
    mov     rax, qword ptr [g_vfz_rng]
    mov     rcx, rax
    shl     rcx, 13
    xor     rax, rcx
    mov     rcx, rax
    shr     rcx, 7
    xor     rax, rcx
    mov     rcx, rax
    shl     rcx, 17
    xor     rax, rcx
    mov     qword ptr [g_vfz_rng], rax
    ret
vfz_rand endp

; ===========================================================================
; cmd_vfuzz - in-proc structural fuzzer for the vault record parser.
;   Deterministically xorshift-mutates a copy of a valid one-entry body
;   (bit flips, random byte sets, TLV length/count smashes, truncations),
;   then runs vault_body_validate + the trusting accessors on it VFZ_ITERS
;   times.  Every malformed body must be cleanly rejected or cleanly parsed -
;   never an access violation.  Prints the parsed/rejected split; exit 0 = the
;   run completed (a crash would fail-fast the process, so reaching the end
;   with exit 0 IS the pass).  Seed is random per run and logged (G7); pass
;   --seed N to reproduce a logged failure.
; ===========================================================================
LANDING_PAD
public cmd_vfuzz
cmd_vfuzz proc frame
    FRAME_PROLOG 112
    ; [rbp-16]=buf [rbp-32]=iters [rbp-40]=parsed [rbp-48]=rejected
    ; [rbp-56]=curlen [rbp-64]=n [rbp-72]=i [rbp-80]=outlen scratch [rbp-88]=nmut
    call    fuzz_seed                                    ; G7: random (or --seed) + logged
    mov     qword ptr [g_vfz_rng], rax
    mov     rcx, VFZ_FIX_LEN
    call    mem_alloc
    test    rax, rax
    jz      vfz_oom
    mov     qword ptr [rbp-16], rax
    mov     qword ptr [g_body_ptr], rax
    mov     qword ptr [rbp-40], 0                        ; parsed
    mov     qword ptr [rbp-48], 0                        ; rejected
    mov     qword ptr [rbp-32], VFZ_ITERS
vfz_iter:
    cmp     qword ptr [rbp-32], 0
    je      vfz_report
    ; restore the pristine fixture into the working buffer
    mov     r11, qword ptr [rbp-16]
    lea     r10, [vfz_fix]
    xor     r8, r8
vfz_restore:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    cmp     r8, VFZ_FIX_LEN
    jb      vfz_restore
    mov     qword ptr [rbp-56], VFZ_FIX_LEN              ; curlen
    ; apply (rand & 3) + 1 mutations
    call    vfz_rand
    and     rax, 3
    inc     rax
    mov     qword ptr [rbp-88], rax
vfz_mut:
    cmp     qword ptr [rbp-88], 0
    je      vfz_run
    mov     rax, qword ptr [rbp-56]                      ; curlen
    test    rax, rax
    jz      vfz_mutnext                                  ; nothing to mutate at len 0
    call    vfz_rand
    mov     rcx, rax                                     ; rcx = r (kept across the op)
    xor     edx, edx
    div     qword ptr [rbp-56]                           ; rdx = off = r mod curlen
    mov     r8, rdx                                      ; off
    mov     rax, rcx
    shr     rax, 2
    and     rax, 3                                       ; op selector
    cmp     rax, 0
    je      vfz_flip
    cmp     rax, 1
    je      vfz_set
    cmp     rax, 2
    je      vfz_trunc
    ; op 3: smash a u32 (targets TLV length + count fields) if it fits
    mov     rax, r8
    add     rax, 4
    cmp     rax, qword ptr [rbp-56]
    ja      vfz_mutnext
    mov     r9, qword ptr [rbp-16]
    add     r9, r8
    mov     rax, rcx
    shr     rax, 8
    mov     dword ptr [r9], eax
    jmp     vfz_mutnext
vfz_flip:
    mov     r9, qword ptr [rbp-16]
    add     r9, r8
    mov     rax, rcx
    and     rax, 7
    mov     r10, 1
    mov     rcx, rax
    shl     r10, cl
    mov     al, byte ptr [r9]
    xor     al, r10b
    mov     byte ptr [r9], al
    jmp     vfz_mutnext
vfz_set:
    mov     r9, qword ptr [rbp-16]
    add     r9, r8
    mov     rax, rcx
    shr     rax, 8
    mov     byte ptr [r9], al
    jmp     vfz_mutnext
vfz_trunc:
    mov     rax, rcx
    shr     rax, 8
    xor     edx, edx
    mov     r10, VFZ_FIX_LEN + 1
    div     r10                                          ; rdx = 0..VFZ_FIX_LEN
    mov     qword ptr [rbp-56], rdx
vfz_mutnext:
    dec     qword ptr [rbp-88]
    jmp     vfz_mut
vfz_run:
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [g_body_len], rax
    call    vault_body_validate
    test    eax, eax
    jz      vfz_parsed
    inc     qword ptr [rbp-48]                           ; rejected
    jmp     vfz_next
vfz_parsed:
    inc     qword ptr [rbp-40]
    ; validated body: exercise the trusting accessors so any mismatch between
    ; the validator's model and find_field_in surfaces as a crash here.
    call    vault_count
    mov     dword ptr [rbp-64], eax
    mov     qword ptr [rbp-72], 0
vfz_walk:
    mov     eax, dword ptr [rbp-64]
    cmp     qword ptr [rbp-72], rax
    jae     vfz_next
    mov     rcx, qword ptr [rbp-72]
    call    vault_entry_ptr
    mov     rcx, qword ptr [rbp-72]
    lea     rdx, [rbp-80]
    call    vault_title_at
    mov     rcx, qword ptr [rbp-72]
    mov     edx, VF_SECRET
    lea     r8, [rbp-80]
    call    vault_field_at
    mov     rcx, qword ptr [rbp-72]
    mov     edx, VF_URL
    lea     r8, [rbp-80]
    call    vault_field_at
    inc     qword ptr [rbp-72]
    jmp     vfz_walk
vfz_next:
    dec     qword ptr [rbp-32]
    jmp     vfz_iter
vfz_report:
    lea     rcx, [vfz_m1]
    mov     edx, vfz_m1_len
    call    print_a
    mov     rcx, VFZ_ITERS
    call    print_u64
    lea     rcx, [vfz_m2]
    mov     edx, vfz_m2_len
    call    print_a
    mov     rcx, qword ptr [rbp-40]
    call    print_u64
    lea     rcx, [vfz_m3]
    mov     edx, vfz_m3_len
    call    print_a
    mov     rcx, qword ptr [rbp-48]
    call    print_u64
    lea     rcx, [vfz_m4]
    mov     edx, vfz_m4_len
    call    print_a
    mov     qword ptr [g_body_ptr], 0                    ; heap buf, not secmem: unref it
    mov     qword ptr [g_body_len], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
vfz_oom:
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
cmd_vfuzz endp

; ===========================================================================
; copy_bytes(rcx=dst, rdx=src, r8d=len) - byte copy using volatile regs only.  Leaf.
copy_bytes proc
    xor     r9d, r9d
cpb_lp:
    cmp     r9d, r8d
    jae     cpb_done
    mov     al, byte ptr [rdx+r9]
    mov     byte ptr [rcx+r9], al
    inc     r9d
    jmp     cpb_lp
cpb_done:
    ret
copy_bytes endp

; vault_snapshot(rcx = VSLOT*) - copy the live open-vault state into the slot so
;   another vault can be made active.  Additive: no existing path changed.
public vault_snapshot
vault_snapshot proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_vkey]
    mov     r8d, 32
    call    copy_bytes
    mov     rcx, qword ptr [rbp-24]
    add     rcx, VSLOT.s_hdr
    lea     rdx, [g_hdr]
    mov     r8d, VH_TOTAL
    call    copy_bytes
    mov     rcx, qword ptr [rbp-24]
    add     rcx, VSLOT.s_ext_hash
    lea     rdx, [g_ext_hash]
    mov     r8d, 32
    call    copy_bytes
    mov     rcx, qword ptr [rbp-24]
    add     rcx, VSLOT.s_newatt
    lea     rdx, [g_newatt]
    mov     r8d, MAX_ATT * 32
    call    copy_bytes
    mov     rcx, qword ptr [rbp-24]
    add     rcx, VSLOT.s_attidx
    lea     rdx, [g_attidx]
    mov     r8d, MAX_ATT * 32
    call    copy_bytes
    mov     r10, qword ptr [rbp-24]
    mov     rax, qword ptr [g_body_ptr]
    mov     qword ptr [r10+VSLOT.s_body_ptr], rax
    mov     rax, qword ptr [g_body_len]
    mov     qword ptr [r10+VSLOT.s_body_len], rax
    mov     rax, qword ptr [g_save_counter]
    mov     qword ptr [r10+VSLOT.s_save_ctr], rax
    mov     rax, qword ptr [g_fmac_len]
    mov     qword ptr [r10+VSLOT.s_fmac_len], rax
    mov     rax, qword ptr [g_ext_size]
    mov     qword ptr [r10+VSLOT.s_ext_size], rax
    mov     rax, qword ptr [g_filebuf]
    mov     qword ptr [r10+VSLOT.s_filebuf], rax
    mov     rax, qword ptr [g_filesize]
    mov     qword ptr [r10+VSLOT.s_filesize], rax
    mov     rax, qword ptr [g_att_start]
    mov     qword ptr [r10+VSLOT.s_att_start], rax
    mov     rax, qword ptr [g_att_total]
    mov     qword ptr [r10+VSLOT.s_att_total], rax
    mov     eax, dword ptr [g_rollback]
    mov     dword ptr [r10+VSLOT.s_rollback], eax
    mov     eax, dword ptr [g_newatt_n]
    mov     dword ptr [r10+VSLOT.s_newatt_n], eax
    mov     eax, dword ptr [g_attidx_n]
    mov     dword ptr [r10+VSLOT.s_attidx_n], eax
    mov     rcx, qword ptr [rbp-24]              ; file identity: g_vpath -> slot
    add     rcx, VSLOT.s_vpath
    lea     rdx, [g_vpath]
    mov     r8d, 2048
    call    copy_bytes
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [g_is_default]
    mov     dword ptr [r10+VSLOT.s_is_default], eax
    mov     eax, dword ptr [g_vault_lock]
    mov     dword ptr [r10+VSLOT.s_vault_lock], eax
    FRAME_EPILOG
    ret
vault_snapshot endp

; vault_restore(rcx = VSLOT*) - make the slot's vault state the live one.
public vault_restore
vault_restore proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    lea     rcx, [g_vkey]
    mov     rdx, qword ptr [rbp-24]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [g_hdr]
    mov     rdx, qword ptr [rbp-24]
    add     rdx, VSLOT.s_hdr
    mov     r8d, VH_TOTAL
    call    copy_bytes
    lea     rcx, [g_ext_hash]
    mov     rdx, qword ptr [rbp-24]
    add     rdx, VSLOT.s_ext_hash
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [g_newatt]
    mov     rdx, qword ptr [rbp-24]
    add     rdx, VSLOT.s_newatt
    mov     r8d, MAX_ATT * 32
    call    copy_bytes
    lea     rcx, [g_attidx]
    mov     rdx, qword ptr [rbp-24]
    add     rdx, VSLOT.s_attidx
    mov     r8d, MAX_ATT * 32
    call    copy_bytes
    mov     r10, qword ptr [rbp-24]
    mov     rax, qword ptr [r10+VSLOT.s_body_ptr]
    mov     qword ptr [g_body_ptr], rax
    mov     rax, qword ptr [r10+VSLOT.s_body_len]
    mov     qword ptr [g_body_len], rax
    mov     rax, qword ptr [r10+VSLOT.s_save_ctr]
    mov     qword ptr [g_save_counter], rax
    mov     rax, qword ptr [r10+VSLOT.s_fmac_len]
    mov     qword ptr [g_fmac_len], rax
    mov     rax, qword ptr [r10+VSLOT.s_ext_size]
    mov     qword ptr [g_ext_size], rax
    mov     rax, qword ptr [r10+VSLOT.s_filebuf]
    mov     qword ptr [g_filebuf], rax
    mov     rax, qword ptr [r10+VSLOT.s_filesize]
    mov     qword ptr [g_filesize], rax
    mov     rax, qword ptr [r10+VSLOT.s_att_start]
    mov     qword ptr [g_att_start], rax
    mov     rax, qword ptr [r10+VSLOT.s_att_total]
    mov     qword ptr [g_att_total], rax
    mov     eax, dword ptr [r10+VSLOT.s_rollback]
    mov     dword ptr [g_rollback], eax
    mov     eax, dword ptr [r10+VSLOT.s_newatt_n]
    mov     dword ptr [g_newatt_n], eax
    mov     eax, dword ptr [r10+VSLOT.s_attidx_n]
    mov     dword ptr [g_attidx_n], eax
    lea     rcx, [g_vpath]                       ; file identity: slot -> g_vpath
    mov     rdx, qword ptr [rbp-24]
    add     rdx, VSLOT.s_vpath
    mov     r8d, 2048
    call    copy_bytes
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [r10+VSLOT.s_is_default]
    mov     dword ptr [g_is_default], eax
    mov     eax, dword ptr [r10+VSLOT.s_vault_lock]
    mov     dword ptr [g_vault_lock], eax
    FRAME_EPILOG
    ret
vault_restore endp

; ---------------------------------------------------------------------------
; Multi-vault context manager (redesign items 6/7/9).  The live open-vault
; globals are always the fronted vault; every other open vault's state sits in
; its g_vaults[] slot.  vault_ctx_open claims a fresh slot for the vault the
; caller is about to load; vault_ctx_front swaps which slot is live.  Because a
; VSLOT captures the heap pointers (body/filebuf) and those buffers are never
; freed while a vault is open, switching is a pure pointer/state swap.
; ---------------------------------------------------------------------------

; vault_ctx_reset() - drop every open context: wipe each slot's master key and
;   free its resident decrypted body, then clear the table.  Called when the
;   vault window closes (lock/leave) and at startup - the lock-all path must
;   never leave another vault's secrets resident.
public vault_ctx_reset
vault_ctx_reset proc frame
    FRAME_PROLOG 80
    mov     dword ptr [rbp-24], 0               ; i
vcr_loop:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, MAX_VAULTS
    jae     vcr_zeroed
    mov     ecx, dword ptr [rbp-24]
    call    vault_ctx_slotptr
    mov     qword ptr [rbp-32], rax             ; slot
    mov     rcx, rax                            ; wipe the master-key copy
    add     rcx, VSLOT.s_vkey
    mov     edx, 32
    call    secure_zero
    mov     r10, qword ptr [rbp-32]             ; free + wipe the resident body
    mov     rcx, qword ptr [r10 + VSLOT.s_body_ptr]
    test    rcx, rcx
    jz      vcr_next
    mov     qword ptr [rbp-40], rcx             ; P = this slot's body pointer
    ; The live arena (g_body_ptr) ALIASES the current slot's body_ptr - after a
    ; fan-out, slot[0].s_body_ptr == g_body_ptr (the master body).  On the lock
    ; path this proc runs right before vault_lock, which also frees g_body_ptr;
    ; drop the alias here so vault_lock's free is a no-op.  Without this the
    ; second secmem_free secure_zero's already-released pages -> access violation
    ; (crash on lock with multiple vaults open).
    cmp     rcx, qword ptr [g_body_ptr]
    jne     vcr_free
    mov     qword ptr [g_body_ptr], 0
    mov     qword ptr [g_body_len], 0
vcr_free:
    mov     rdx, qword ptr [r10 + VSLOT.s_body_len]
    mov     rcx, qword ptr [rbp-40]
    call    secmem_free
    mov     r10, qword ptr [rbp-32]
    mov     qword ptr [r10 + VSLOT.s_body_ptr], 0
    ; DEFENSIVE: null any OTHER slot that ALIASES the same body pointer, so a
    ; duplicate arising from ANY source (ctx compaction, a snapshot, a stale slot)
    ; is freed exactly once here - never twice.  secmem_free is not double-free
    ; safe (it secure_zeros before VirtualFree), and this teardown has crashed on
    ; that class more than once; make it structurally impossible.
    mov     eax, dword ptr [rbp-24]
    inc     eax
    mov     dword ptr [rbp-48], eax             ; j = i + 1
vcr_dedup:
    cmp     dword ptr [rbp-48], MAX_VAULTS
    jae     vcr_next
    mov     ecx, dword ptr [rbp-48]
    call    vault_ctx_slotptr
    mov     r10, rax
    mov     rax, qword ptr [rbp-40]             ; P
    cmp     qword ptr [r10 + VSLOT.s_body_ptr], rax
    jne     vcr_dedupnext
    mov     qword ptr [r10 + VSLOT.s_body_ptr], 0
    mov     qword ptr [r10 + VSLOT.s_body_len], 0
vcr_dedupnext:
    inc     dword ptr [rbp-48]
    jmp     vcr_dedup
vcr_next:
    inc     dword ptr [rbp-24]
    jmp     vcr_loop
vcr_zeroed:
    mov     dword ptr [g_vault_n], 0
    mov     dword ptr [g_vault_cur], -1
    FRAME_EPILOG
    ret
vault_ctx_reset endp

; vault_slots_lock() - VirtualLock the whole g_vaults table (every slot's s_vkey
;   is a master key copy; the table must stay out of the pagefile).
public vault_slots_lock
vault_slots_lock proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_vaults]
    mov     edx, (sizeof VSLOT) * MAX_VAULTS
    call    sec_lock
    FRAME_EPILOG
    ret
vault_slots_lock endp

; vault_panic_wipe_slots() - crash-path wipe of every slot's master key and
;   resident body bytes (no frees - the heap may already be corrupt).
public vault_panic_wipe_slots
vault_panic_wipe_slots proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], 0               ; i
vpws_loop:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, MAX_VAULTS
    jae     vpws_done
    mov     ecx, dword ptr [rbp-24]
    call    vault_ctx_slotptr
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    add     rcx, VSLOT.s_vkey
    mov     edx, 32
    call    secure_zero
    mov     r10, qword ptr [rbp-32]
    mov     rcx, qword ptr [r10 + VSLOT.s_body_ptr]
    test    rcx, rcx
    jz      vpws_next
    mov     rdx, qword ptr [r10 + VSLOT.s_body_len]
    call    secure_zero
vpws_next:
    inc     dword ptr [rbp-24]
    jmp     vpws_loop
vpws_done:
    FRAME_EPILOG
    ret
vault_panic_wipe_slots endp

; vault_ctx_slotptr(ecx = index) -> rax = &g_vaults[index].  Leaf, no bounds
;   check (callers validate against g_vault_n first).
public vault_ctx_slotptr
vault_ctx_slotptr proc
    mov     eax, ecx                        ; zero-extend index into rax
    imul    rax, rax, sizeof VSLOT
    lea     rcx, [g_vaults]
    add     rax, rcx
    ret
vault_ctx_slotptr endp

; vault_ctx_open() -> eax = new vault index, or -1 if MAX_VAULTS reached.  Saves
;   the currently-fronted vault into its slot; the caller then loads the new
;   vault into the live globals (fresh slot, nothing to restore).
public vault_ctx_open
vault_ctx_open proc frame
    FRAME_PROLOG 48
    mov     eax, dword ptr [g_vault_n]
    cmp     eax, MAX_VAULTS
    jb      vco_have_room
    mov     eax, -1
    FRAME_EPILOG
    ret
vco_have_room:
    cmp     dword ptr [g_vault_cur], 0
    jl      vco_no_current                  ; -1: nothing live to save
    mov     ecx, dword ptr [g_vault_cur]
    call    vault_ctx_slotptr
    mov     rcx, rax
    call    vault_snapshot
vco_no_current:
    mov     eax, dword ptr [g_vault_n]      ; idx = n
    mov     dword ptr [rbp-24], eax
    inc     eax
    mov     dword ptr [g_vault_n], eax      ; n = n + 1
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_vault_cur], eax    ; cur = idx
    ; A freshly-claimed slot must NOT inherit a stale body pointer from a prior
    ; life in that slot: the caller loads the new vault into the LIVE globals and
    ; only snapshots it here on the next front, so until then a leftover
    ; s_body_ptr would be a dead pointer that vault_ctx_reset frees on lock ->
    ; secmem_free secure_zeros already-released pages -> crash.  Seen as
    ; "create a fresh master, lock, crash" (the master claims slot 0 with the
    ; fan-out opening nothing, so no snapshot ever populates it).
    mov     ecx, dword ptr [rbp-24]
    call    vault_ctx_slotptr
    mov     qword ptr [rax + VSLOT.s_body_ptr], 0
    mov     qword ptr [rax + VSLOT.s_body_len], 0
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
vault_ctx_open endp

; vault_ctx_front(ecx = target index) -> eax = 0 ok / 1 bad index.  Snapshots
;   the live vault into its slot, then restores the target slot into the live
;   globals.  A no-op if the target is already fronted.
public vault_ctx_front
vault_ctx_front proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], ecx         ; target
    cmp     ecx, dword ptr [g_vault_n]
    jb      vcf_valid
    mov     eax, 1
    FRAME_EPILOG
    ret
vcf_valid:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_vault_cur]
    jne     vcf_switch
    xor     eax, eax                        ; already fronted
    FRAME_EPILOG
    ret
vcf_switch:
    cmp     dword ptr [g_vault_cur], 0
    jl      vcf_no_current                  ; -1: nothing live to save
    mov     ecx, dword ptr [g_vault_cur]
    call    vault_ctx_slotptr
    mov     rcx, rax
    call    vault_snapshot
vcf_no_current:
    mov     ecx, dword ptr [rbp-24]
    call    vault_ctx_slotptr
    mov     rcx, rax
    call    vault_restore
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_vault_cur], eax
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_ctx_front endp

; vault_ctx_setname(ecx=idx, rdx=src wide name) - store a tab display name
;   (<=63 wide chars, NUL-terminated).  Leaf.
public vault_ctx_setname
vault_ctx_setname proc
    mov     eax, ecx
    imul    rax, rax, sizeof VSLOT
    lea     r10, [g_vaults]
    add     rax, r10
    add     rax, VSLOT.s_name                 ; rax = dst
    xor     r9d, r9d
vcsn_lp:
    cmp     r9d, 63
    jae     vcsn_end
    movzx   r8d, word ptr [rdx + r9*2]
    mov     word ptr [rax + r9*2], r8w
    test    r8w, r8w
    jz      vcsn_done
    inc     r9d
    jmp     vcsn_lp
vcsn_end:
    mov     word ptr [rax + r9*2], 0
vcsn_done:
    ret
vault_ctx_setname endp

; vault_ctx_nameptr(ecx=idx) -> rax = &g_vaults[idx].s_name.  Leaf.
public vault_ctx_nameptr
vault_ctx_nameptr proc
    mov     eax, ecx
    imul    rax, rax, sizeof VSLOT
    lea     rcx, [g_vaults]
    add     rax, rcx
    add     rax, VSLOT.s_name
    ret
vault_ctx_nameptr endp

; vault_ctx_pathptr(ecx=idx) -> rax = &g_vaults[idx].s_vpath (UTF-8 file path).
;   Leaf.  Used by the M4 vault-management list to show each slot's locator.
public vault_ctx_pathptr
vault_ctx_pathptr proc
    mov     eax, ecx
    imul    rax, rax, sizeof VSLOT
    lea     rcx, [g_vaults]
    add     rax, rcx
    add     rax, VSLOT.s_vpath
    ret
vault_ctx_pathptr endp

; vault_ctx_close(ecx=idx) - remove open-vault context idx: securely wipe its
;   master key + decrypted body, compact the g_vaults array, wipe the trailing
;   slot's key copy, and shift g_vault_cur down if it was above idx.  The caller
;   must first front a different vault if idx is the currently-fronted one.
public vault_ctx_close
vault_ctx_close proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], ecx
    mov     ecx, dword ptr [rbp-24]
    call    vault_ctx_slotptr
    mov     qword ptr [rbp-32], rax
    lea     rcx, [rax + VSLOT.s_vkey]         ; wipe master key
    mov     edx, 32
    call    secure_zero
    mov     r10, qword ptr [rbp-32]           ; free the decrypted body (its own alloc).
    mov     rcx, qword ptr [r10 + VSLOT.s_body_ptr]   ; secmem_free wipes THEN releases; the
    test    rcx, rcx                          ; caller fronts the master first, so this is
    jz      vcc_compact                       ; never the live g_body_ptr.  (A bare wipe here
    mov     rdx, qword ptr [r10 + VSLOT.s_body_len]   ; leaked the alloc, and - worse - left the
    call    secmem_free                       ; pointer to be duplicated by the shift below.)
vcc_compact:
    mov     eax, dword ptr [rbp-24]           ; shift slots [idx+1 .. n-1] down one
    mov     dword ptr [rbp-40], eax
vcc_shift:
    mov     eax, dword ptr [g_vault_n]
    dec     eax
    cmp     dword ptr [rbp-40], eax
    jae     vcc_shifted
    mov     ecx, dword ptr [rbp-40]
    call    vault_ctx_slotptr
    mov     qword ptr [rbp-48], rax           ; dst
    mov     ecx, dword ptr [rbp-40]
    inc     ecx
    call    vault_ctx_slotptr                 ; src
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, rax
    mov     r8d, sizeof VSLOT
    call    copy_bytes
    inc     dword ptr [rbp-40]
    jmp     vcc_shift
vcc_shifted:
    dec     dword ptr [g_vault_n]
    mov     ecx, dword ptr [g_vault_n]        ; the now-excluded trailing slot
    call    vault_ctx_slotptr
    mov     qword ptr [rbp-32], rax
    lea     rcx, [rax + VSLOT.s_vkey]         ; wipe its master-key copy
    mov     edx, 32
    call    secure_zero
    mov     r10, qword ptr [rbp-32]           ; drop its DUPLICATE body reference: the shift
    mov     qword ptr [r10 + VSLOT.s_body_ptr], 0   ; copied this slot's body_ptr down into a
    mov     qword ptr [r10 + VSLOT.s_body_len], 0   ; live slot, so the stale copy up here must
                                              ; NOT survive - else vault_ctx_reset (on lock)
                                              ; frees the same body twice -> crash.
    mov     eax, dword ptr [g_vault_cur]      ; cur > idx -> shift down with the array
    cmp     eax, dword ptr [rbp-24]
    jle     vcc_done
    dec     eax
    mov     dword ptr [g_vault_cur], eax
vcc_done:
    FRAME_EPILOG
    ret
vault_ctx_close endp

; ---------------------------------------------------------------------------
; Availability retry state machine (redesign item 9).  Leaf procs; the caller
; supplies "now" (GetTickCount64) so the machine is deterministic to test.
; ---------------------------------------------------------------------------

; vault_avail_begin(rcx = AVSLOT*, rdx = now) - a vault just went unavailable:
;   enter RETRY with 0 tries and the first retry due one interval out.
public vault_avail_begin
vault_avail_begin proc
    mov     dword ptr [rcx+AVSLOT.av_status], AVSTAT_RETRY
    mov     dword ptr [rcx+AVSLOT.av_tries], 0
    add     rdx, AVAIL_INTERVAL_MS
    mov     qword ptr [rcx+AVSLOT.av_next], rdx
    ret
vault_avail_begin endp

; vault_avail_due(rcx = AVSLOT*, rdx = now) -> eax = 1 if a retry attempt should
;   run now (RETRY state and the deadline has passed), else 0.
public vault_avail_due
vault_avail_due proc
    xor     eax, eax
    cmp     dword ptr [rcx+AVSLOT.av_status], AVSTAT_RETRY
    jne     vad_no
    cmp     rdx, qword ptr [rcx+AVSLOT.av_next]
    jb      vad_no
    mov     eax, 1
vad_no:
    ret
vault_avail_due endp

; vault_avail_fail(rcx = AVSLOT*, rdx = now) - a retry attempt just failed:
;   count it; after AVAIL_MAX_TRIES give up, else schedule the next interval.
public vault_avail_fail
vault_avail_fail proc
    mov     eax, dword ptr [rcx+AVSLOT.av_tries]
    inc     eax
    mov     dword ptr [rcx+AVSLOT.av_tries], eax
    cmp     eax, AVAIL_MAX_TRIES
    jb      vaf_reschedule
    mov     dword ptr [rcx+AVSLOT.av_status], AVSTAT_GAVEUP
    ret
vaf_reschedule:
    add     rdx, AVAIL_INTERVAL_MS
    mov     qword ptr [rcx+AVSLOT.av_next], rdx
    ret
vault_avail_fail endp

; vault_avail_ok(rcx = AVSLOT*) - a retry attempt succeeded: vault is available.
public vault_avail_ok
vault_avail_ok proc
    mov     dword ptr [rcx+AVSLOT.av_status], AVSTAT_AVAIL
    ret
vault_avail_ok endp

; vault_avail_unlock(rcx = AVSLOT*, rdx = now) - user asked to unlock again:
;   restart RETRY from zero, first attempt due immediately.
public vault_avail_unlock
vault_avail_unlock proc
    mov     dword ptr [rcx+AVSLOT.av_status], AVSTAT_RETRY
    mov     dword ptr [rcx+AVSLOT.av_tries], 0
    mov     qword ptr [rcx+AVSLOT.av_next], rdx
    ret
vault_avail_unlock endp

; cmd_mvtest - headless probe: plant a distinct sentinel in every open-vault state
;   field, snapshot, clobber every field to zero, restore, and verify each field
;   came back.  Proves vault_snapshot/vault_restore cover the complete state (a
;   missed field would stay zero -> fail).  Exit 0 = pass.
LANDING_PAD
public cmd_mvtest
cmd_mvtest proc frame
    FRAME_PROLOG 48
    mov     byte ptr [g_vkey], 0AAh
    mov     byte ptr [g_hdr], 0BBh
    mov     byte ptr [g_ext_hash], 0CCh
    mov     byte ptr [g_newatt], 0DDh
    mov     byte ptr [g_attidx], 0EEh
    mov     byte ptr [g_newatt + MAX_ATT*32 - 1], 44h   ; last byte too
    mov     byte ptr [g_attidx + MAX_ATT*32 - 1], 55h
    mov     rax, 1111111111111111h
    mov     qword ptr [g_body_ptr], rax
    mov     rax, 2222222222222222h
    mov     qword ptr [g_body_len], rax
    mov     rax, 3333333333333333h
    mov     qword ptr [g_save_counter], rax
    mov     rax, 4444444444444444h
    mov     qword ptr [g_fmac_len], rax
    mov     rax, 5555555555555555h
    mov     qword ptr [g_ext_size], rax
    mov     rax, 6666666666666666h
    mov     qword ptr [g_filebuf], rax
    mov     rax, 7777777777777777h
    mov     qword ptr [g_filesize], rax
    mov     rax, 8888888888888888h
    mov     qword ptr [g_att_start], rax
    mov     rax, 9999999999999999h
    mov     qword ptr [g_att_total], rax
    mov     dword ptr [g_rollback], 0A1A1A1A1h
    mov     dword ptr [g_newatt_n], 0B2B2B2B2h
    mov     dword ptr [g_attidx_n], 0C3C3C3C3h
    mov     word ptr [g_vpath], 1234h
    mov     dword ptr [g_is_default], 71717171h
    mov     dword ptr [g_vault_lock], 82828282h
    lea     rcx, [g_mvslot]
    call    vault_snapshot
    ; clobber everything to zero
    lea     rcx, [g_vkey]
    mov     edx, 32
    call    mvt_zero
    lea     rcx, [g_hdr]
    mov     edx, VH_TOTAL
    call    mvt_zero
    lea     rcx, [g_ext_hash]
    mov     edx, 32
    call    mvt_zero
    lea     rcx, [g_newatt]
    mov     edx, MAX_ATT * 32
    call    mvt_zero
    lea     rcx, [g_attidx]
    mov     edx, MAX_ATT * 32
    call    mvt_zero
    xor     eax, eax
    mov     qword ptr [g_body_ptr], rax
    mov     qword ptr [g_body_len], rax
    mov     qword ptr [g_save_counter], rax
    mov     qword ptr [g_fmac_len], rax
    mov     qword ptr [g_ext_size], rax
    mov     qword ptr [g_filebuf], rax
    mov     qword ptr [g_filesize], rax
    mov     qword ptr [g_att_start], rax
    mov     qword ptr [g_att_total], rax
    mov     dword ptr [g_rollback], eax
    mov     dword ptr [g_newatt_n], eax
    mov     dword ptr [g_attidx_n], eax
    mov     word ptr [g_vpath], ax
    mov     dword ptr [g_is_default], eax
    mov     dword ptr [g_vault_lock], eax
    lea     rcx, [g_mvslot]
    call    vault_restore
    ; verify each field
    cmp     byte ptr [g_vkey], 0AAh
    jne     mvt_fail
    cmp     byte ptr [g_hdr], 0BBh
    jne     mvt_fail
    cmp     byte ptr [g_ext_hash], 0CCh
    jne     mvt_fail
    cmp     byte ptr [g_newatt], 0DDh
    jne     mvt_fail
    cmp     byte ptr [g_attidx], 0EEh
    jne     mvt_fail
    cmp     byte ptr [g_newatt + MAX_ATT*32 - 1], 44h
    jne     mvt_fail
    cmp     byte ptr [g_attidx + MAX_ATT*32 - 1], 55h
    jne     mvt_fail
    mov     rax, 1111111111111111h
    cmp     qword ptr [g_body_ptr], rax
    jne     mvt_fail
    mov     rax, 2222222222222222h
    cmp     qword ptr [g_body_len], rax
    jne     mvt_fail
    mov     rax, 3333333333333333h
    cmp     qword ptr [g_save_counter], rax
    jne     mvt_fail
    mov     rax, 4444444444444444h
    cmp     qword ptr [g_fmac_len], rax
    jne     mvt_fail
    mov     rax, 5555555555555555h
    cmp     qword ptr [g_ext_size], rax
    jne     mvt_fail
    mov     rax, 6666666666666666h
    cmp     qword ptr [g_filebuf], rax
    jne     mvt_fail
    mov     rax, 7777777777777777h
    cmp     qword ptr [g_filesize], rax
    jne     mvt_fail
    mov     rax, 8888888888888888h
    cmp     qword ptr [g_att_start], rax
    jne     mvt_fail
    mov     rax, 9999999999999999h
    cmp     qword ptr [g_att_total], rax
    jne     mvt_fail
    cmp     dword ptr [g_rollback], 0A1A1A1A1h
    jne     mvt_fail
    cmp     dword ptr [g_newatt_n], 0B2B2B2B2h
    jne     mvt_fail
    cmp     dword ptr [g_attidx_n], 0C3C3C3C3h
    jne     mvt_fail
    cmp     word ptr [g_vpath], 1234h
    jne     mvt_fail
    cmp     dword ptr [g_is_default], 71717171h
    jne     mvt_fail
    cmp     dword ptr [g_vault_lock], 82828282h
    jne     mvt_fail
    xor     eax, eax
    FRAME_EPILOG
    ret
mvt_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_mvtest endp

; cmd_mvname - headless probe for the cross-vault-search enumeration.  Reproduces
;   what search_overlay_xfill does: open N vaults (each coupling a distinct body
;   seed with a distinct display name), sit on tab 0 (the front() no-op path),
;   then front every vault in turn and assert BOTH its live body state (mv_check)
;   AND its cached name (vault_ctx_nameptr) still belong to that vault.  A slot
;   whose name and body got crossed (the reported "vault N shows another vault's
;   file") would fail here.  Exit 0 = pass.  Uses fake seed body pointers, so -
;   like cmd_mvswitch - it never closes/resets at the end (those free the body).
LANDING_PAD
public cmd_mvname
cmd_mvname proc frame
    FRAME_PROLOG 48
    call    vault_ctx_reset
    mov     dword ptr [rbp-24], 0            ; v = 0
mvn_open:
    cmp     dword ptr [rbp-24], 6
    jae     mvn_switch
    call    vault_ctx_open                  ; snapshot prev live -> its slot; cur = v
    mov     eax, dword ptr [rbp-24]          ; live = vault v (seed 40h+v)
    add     eax, 40h
    mov     ecx, eax
    call    mv_plant
    mov     eax, dword ptr [rbp-24]          ; name(v) = wide "<'0'+v>"
    add     eax, '0'
    mov     word ptr [g_mvnamebuf], ax
    mov     word ptr [g_mvnamebuf+2], 0
    mov     ecx, dword ptr [rbp-24]
    lea     rdx, [g_mvnamebuf]
    call    vault_ctx_setname
    inc     dword ptr [rbp-24]
    jmp     mvn_open
mvn_switch:
    xor     ecx, ecx                         ; sit on tab 0 (exercises the front() no-op)
    call    vault_ctx_front
    mov     dword ptr [rbp-24], 0            ; enumerate exactly like the search fill
mvn_enum:
    cmp     dword ptr [rbp-24], 6
    jae     mvn_pass
    mov     ecx, dword ptr [rbp-24]
    call    vault_ctx_front
    test    eax, eax
    jnz     mvn_fail
    mov     eax, dword ptr [rbp-24]          ; live body must be vault v's seed
    add     eax, 40h
    mov     ecx, eax
    call    mv_check
    test    eax, eax
    jnz     mvn_fail
    mov     ecx, dword ptr [rbp-24]          ; name(v) must still be vault v's name
    call    vault_ctx_nameptr
    movzx   edx, word ptr [rax]
    mov     eax, dword ptr [rbp-24]
    add     eax, '0'
    cmp     dx, ax
    jne     mvn_fail
    inc     dword ptr [rbp-24]
    jmp     mvn_enum
mvn_pass:
    xor     eax, eax
    FRAME_EPILOG
    ret
mvn_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_mvname endp

; cmd_mvremove - verify the M4 "Remove" recording.  fed_remember_open keys each
;   foreign link by vault_id = SHA-256(slot salt), and fed_add dedups by that id.
;   Phase 1 (DISTINCT salts): remove 1 of 4 -> g_vault_n=3 and the rebuilt record
;   has 2 links.  Phase 2 (SHARED salt = same vault copied): the record dedups to
;   1.  Confirms the remove logic is correct for distinct vaults, and documents
;   that same-salt copies collapse (they are one vault to the federation).
CSTR mvr_ok,  "mvremove: PASS (distinct remove keeps the rest; shared-salt dedups)",13,10
CSTR mvr_bad, "mvremove: FAIL",13,10
LANDING_PAD
public cmd_mvremove
cmd_mvremove proc frame
    FRAME_PROLOG 48
    ; ---- phase 1: four vaults with DISTINCT salts ----
    call    vault_ctx_reset
    mov     qword ptr [g_body_ptr], 0
    call    vault_ctx_open
    call    vault_ctx_open
    call    vault_ctx_open
    call    vault_ctx_open                   ; master + 3 foreign, n=4, cur=3
    xor     ecx, ecx
    call    vault_ctx_front                  ; cur=0
    mov     dword ptr [rbp-24], 0
mvr_ds:
    cmp     dword ptr [rbp-24], 4
    jae     mvr_d1
    mov     ecx, dword ptr [rbp-24]
    call    vault_ctx_slotptr
    mov     r10, rax
    mov     eax, dword ptr [rbp-24]
    add     eax, 30h
    mov     byte ptr [r10 + VSLOT.s_hdr + VH_SALT], al   ; distinct salt -> distinct id
    inc     dword ptr [rbp-24]
    jmp     mvr_ds
mvr_d1:
    mov     ecx, 1                           ; remove slot 1 (a foreign vault)
    call    vault_ctx_close
    cmp     dword ptr [g_vault_n], 3
    jne     mvr_fail
    call    mvr_rebuild
    cmp     dword ptr [g_fedrec + FEDREC.fr_count], 2     ; the other two survive
    jne     mvr_fail
    ; ---- phase 2: four vaults with the SAME salt (copies) ----
    call    vault_ctx_reset
    mov     qword ptr [g_body_ptr], 0
    call    vault_ctx_open
    call    vault_ctx_open
    call    vault_ctx_open
    call    vault_ctx_open
    xor     ecx, ecx
    call    vault_ctx_front
    mov     dword ptr [rbp-24], 0
mvr_ss:
    cmp     dword ptr [rbp-24], 4
    jae     mvr_s1
    mov     ecx, dword ptr [rbp-24]
    call    vault_ctx_slotptr
    mov     byte ptr [rax + VSLOT.s_hdr + VH_SALT], 77h   ; identical salt for all
    inc     dword ptr [rbp-24]
    jmp     mvr_ss
mvr_s1:
    mov     ecx, 1
    call    vault_ctx_close
    call    mvr_rebuild
    cmp     dword ptr [g_fedrec + FEDREC.fr_count], 1     ; same id -> collapse to 1
    jne     mvr_fail
    lea     rcx, [mvr_ok]
    mov     edx, mvr_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
mvr_fail:
    lea     rcx, [mvr_bad]
    mov     edx, mvr_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_mvremove endp

; mvr_rebuild - replicate fed_remember_open's link-recording loop (slots 1..n-1),
;   keying each by vault_id_hdr(salt) and fed_add (which dedups by id).
mvr_rebuild proc frame
    FRAME_PROLOG 32
    call    fed_reset
    mov     dword ptr [rbp-24], 1
mrb_loop:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_vault_n]
    jae     mrb_done
    mov     ecx, dword ptr [rbp-24]
    call    vault_ctx_slotptr
    lea     rcx, [rax + VSLOT.s_hdr + VH_SALT]
    lea     rdx, [g_fedlink_tmp + FEDLINK.fl_id]
    call    vault_id_hdr
    mov     dword ptr [g_fedlink_tmp + FEDLINK.fl_flags], 0
    lea     rcx, [g_fedlink_tmp]
    call    fed_add
    inc     dword ptr [rbp-24]
    jmp     mrb_loop
mrb_done:
    FRAME_EPILOG
    ret
mvr_rebuild endp

; ===========================================================================
; cmd_mvclose - headless regression for the vault-close teardown (the M4 "Remove"
;   path).  Historically two lock-crashes came from secmem_free being asked to
;   free the same decrypted body twice (it secure_zeros BEFORE VirtualFree, so a
;   second free writes released pages -> access violation): (1) g_body_ptr
;   aliasing slot[cur] on the fan-out, and (2) vault_ctx_close's compaction
;   copying a slot's body_ptr DOWN into a live slot without clearing the stale
;   copy up top.  This probe stands up 4 vaults each with its OWN locked body,
;   removes the middle one repeatedly (exercising the shift), asserts no slot
;   retains a duplicate body_ptr, then tears down.  With the bug, the teardown
;   double-frees and this process crashes (non-zero exit); fixed, exit 0 = pass.
CSTR mvc_ok,  "mvclose: PASS (no duplicate body_ptr; teardown freed each once)",13,10
CSTR mvc_bad, "mvclose: FAIL (a duplicate body_ptr survived close)",13,10
LANDING_PAD
public cmd_mvclose
cmd_mvclose proc frame
    FRAME_PROLOG 48
    call    vault_ctx_reset                  ; clean slate
    mov     dword ptr [rbp-24], 0            ; v
mvc_open:
    cmp     dword ptr [rbp-24], 4
    jae     mvc_ready
    call    vault_ctx_open                   ; snapshot prev live -> its slot; cur = v
    mov     ecx, 65536                       ; give the live vault its OWN locked body
    call    secmem_alloc
    test    rax, rax
    jz      mvc_fail                         ; OOM -> cannot run
    mov     qword ptr [g_body_ptr], rax
    mov     qword ptr [g_body_len], 65536
    inc     dword ptr [rbp-24]
    jmp     mvc_open
mvc_ready:
    xor     ecx, ecx                         ; front the master: snapshots the last-opened
    call    vault_ctx_front                  ;   body into its slot, live = slot 0
mvc_close:
    cmp     dword ptr [g_vault_n], 1         ; remove the middle vault until only master left
    jbe     mvc_closed
    mov     ecx, 1
    call    vault_ctx_close
    jmp     mvc_close
mvc_closed:
    mov     dword ptr [rbp-24], 1            ; assert slots 1..MAX_VAULTS-1 hold no stale body
mvc_scan:
    cmp     dword ptr [rbp-24], MAX_VAULTS
    jae     mvc_teardown
    mov     ecx, dword ptr [rbp-24]
    call    vault_ctx_slotptr
    cmp     qword ptr [rax + VSLOT.s_body_ptr], 0
    jne     mvc_fail                         ; a duplicate survived -> would double-free
    inc     dword ptr [rbp-24]
    jmp     mvc_scan
mvc_teardown:
    call    vault_ctx_reset                  ; frees the master body once; a duplicate here
                                             ; would fault (released-page wipe) -> crash
    lea     rcx, [mvc_ok]
    mov     edx, mvc_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
mvc_fail:
    ; do NOT reset here: if a duplicate is present, freeing it is the very crash
    ; we are detecting.  Report cleanly and let process exit reclaim the leak.
    lea     rcx, [mvc_bad]
    mov     edx, mvc_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_mvclose endp

; cmd_mvlock - headless regression for the LOCK teardown with many vaults open
;   (the fan-out / M4 "Add all" then lock path).  Mirrors fed_fanout: open N
;   vaults, each with its OWN locked body, WITHOUT fronting between (the next open
;   snapshots the prior into its slot), front the master at the end, then run the
;   real lock sequence vault_ctx_reset -> vault_lock.  If any body is freed twice
;   the process crashes; fixed, exit 0 = pass.
CSTR mvl_ok,  "mvlock: PASS (reset+lock freed every body exactly once)",13,10
CSTR mvl_bad, "mvlock: FAIL (a slot body survived teardown)",13,10
LANDING_PAD
public cmd_mvlock
cmd_mvlock proc frame
    FRAME_PROLOG 48
    call    vault_ctx_reset
    mov     qword ptr [g_filebuf], 0         ; no resident file image in this probe
    mov     qword ptr [g_body_ptr], 0
    mov     dword ptr [rbp-24], 0            ; v
mvl_open:
    cmp     dword ptr [rbp-24], 6
    jae     mvl_ready
    call    vault_ctx_open                   ; snapshot prev live -> its slot; cur = v
    mov     ecx, 65536
    call    secmem_alloc
    test    rax, rax
    jz      mvl_fail
    mov     qword ptr [g_body_ptr], rax      ; new live body (prior stays in its slot)
    mov     qword ptr [g_body_len], 65536
    inc     dword ptr [rbp-24]
    jmp     mvl_open
mvl_ready:
    xor     ecx, ecx                         ; ffo_done + gui_lb_seldata: front the master
    call    vault_ctx_front
    call    vault_ctx_reset                  ; the lock path: forget contexts, then wipe live
    call    vault_lock
    mov     dword ptr [rbp-24], 0            ; every slot body must be cleared
mvl_scan:
    cmp     dword ptr [rbp-24], MAX_VAULTS
    jae     mvl_pass
    mov     ecx, dword ptr [rbp-24]
    call    vault_ctx_slotptr
    cmp     qword ptr [rax + VSLOT.s_body_ptr], 0
    jne     mvl_fail
    inc     dword ptr [rbp-24]
    jmp     mvl_scan
mvl_pass:
    lea     rcx, [mvl_ok]
    mov     edx, mvl_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
mvl_fail:
    lea     rcx, [mvl_bad]
    mov     edx, mvl_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_mvlock endp

; cmd_mvlockreal <path> - faithful multi-REAL-vault lock repro.  Seeds a vault,
;   opens a real master, then fans out N real foreign contexts (distinct link ids,
;   same file so each gets its own decrypted body + resident image), and runs the
;   real lock path (vault_ctx_reset -> vault_lock).  Reproduces the user's
;   "crash on lock after adding all vaults" with actual bodies/filebufs.  Exit 0 =
;   survived (no double-free); a fault crashes the process.
CSTR mlr_ok, "mvlockreal: PASS (N real vaults locked, freed once each)",13,10
LANDING_PAD
public cmd_mvlockreal
cmd_mvlockreal proc frame
    FRAME_PROLOG 48
    lea     r10, [g_argv]                     ; path = argv[2]
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [g_cfg_in], rax
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_loc]   ; link locator = the same file
    mov     rdx, rax
    mov     r8d, 512
    call    copy_bytes
    lea     r10, [ffk_seedpw]                 ; seed password
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
mlr_pw:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      mlr_pwd
    inc     ecx
    cmp     ecx, 32
    jb      mlr_pw
mlr_pwd:
    mov     dword ptr [g_cfg_passlen], 9
    mov     ecx, 3
    call    do_seed
    test    eax, eax
    mov     eax, 2
    jnz     mlr_ret
    call    vk_derive                         ; g_vkey = master key
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_key]   ; link key = master key
    lea     rdx, [g_vkey]
    mov     r8d, 32
    call    copy_bytes
    mov     dword ptr [g_fedlink_tmp + FEDLINK.fl_flags], 0
    ; open the master for real (its own body)
    call    vault_ctx_reset
    call    vault_ctx_open
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [g_cfg_in], rax
    mov     dword ptr [g_reuse_key], 1
    call    vault_unlock
    mov     dword ptr [g_reuse_key], 0
    test    eax, eax
    mov     eax, 3
    jnz     mlr_ret
    ; build a record of 5 foreign links (distinct ids, same file + key)
    call    fed_reset
    mov     dword ptr [rbp-24], 0            ; i
mlr_build:
    cmp     dword ptr [rbp-24], 5
    jae     mlr_fanout
    mov     eax, dword ptr [rbp-24]           ; fl_id = 16 bytes of (0x10 + i)
    add     eax, 10h
    lea     r10, [g_fedlink_tmp + FEDLINK.fl_id]
    xor     ecx, ecx
mlr_id:
    mov     byte ptr [r10+rcx], al
    inc     ecx
    cmp     ecx, 16
    jb      mlr_id
    lea     rcx, [g_fedlink_tmp]
    call    fed_add
    inc     dword ptr [rbp-24]
    jmp     mlr_build
mlr_fanout:
    call    fed_fanout                        ; opens 5 real foreign contexts
    ; the lock path
    call    vault_ctx_reset
    call    vault_lock
    lea     rcx, [mlr_ok]
    mov     edx, mlr_ok_len
    call    print_a
    xor     eax, eax
mlr_ret:
    FRAME_EPILOG
    ret
cmd_mvlockreal endp

; cmd_mvstale - headless regression for "create a fresh master, lock, crash".
;   A slot reused across the app's lifetime could carry a stale (already-freed)
;   body pointer; when vault_ctx_open re-claims it for a new vault WITHOUT the
;   next front ever snapshotting a real body over it (the single-master, empty
;   fan-out case), vault_ctx_reset on lock frees that dangling pointer -> crash.
;   Plants a freed pointer in slot 0, claims it, and asserts the claim dropped it.
CSTR mvs_ok,  "mvstale: PASS (claimed slot dropped the stale body pointer)",13,10
CSTR mvs_bad, "mvstale: FAIL (stale body pointer survived claim -> lock would crash)",13,10
LANDING_PAD
public cmd_mvstale
cmd_mvstale proc frame
    FRAME_PROLOG 48
    call    vault_ctx_reset                  ; clean slate (n=0, cur=-1)
    mov     ecx, 65536                        ; a real body, then freed -> dangling pointer
    call    secmem_alloc
    test    rax, rax
    jz      mvs_fail
    mov     qword ptr [rbp-24], rax
    mov     rcx, rax
    mov     rdx, 65536
    call    secmem_free
    xor     ecx, ecx                          ; plant the dangling pointer in slot 0
    call    vault_ctx_slotptr
    mov     r10, rax
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [r10 + VSLOT.s_body_ptr], rax
    mov     qword ptr [r10 + VSLOT.s_body_len], 65536
    call    vault_ctx_open                    ; "create master": claim slot 0 (cur=-1)
    xor     ecx, ecx
    call    vault_ctx_slotptr
    cmp     qword ptr [rax + VSLOT.s_body_ptr], 0   ; the claim must have dropped it
    jne     mvs_fail
    mov     qword ptr [g_body_ptr], 0         ; the lock: reset must skip the (dropped) slot
    call    vault_ctx_reset
    lea     rcx, [mvs_ok]
    mov     edx, mvs_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
mvs_fail:
    lea     rcx, [mvs_bad]
    mov     edx, mvs_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_mvstale endp

; cmd_mvrecreate <path> - reproduce "create a master, use it, lock; then create
;   ANOTHER master, crash".  Runs the full go_vault sequence (seed+derive, claim
;   slot 0, real unlock, fed_unlock_master, fed_fanout) then the lock (reset+lock)
;   TWICE in one process - the tray-persistent app's second create cycle.  Exit
;   0 = both cycles survived.
CSTR mrc_ok, "mvrecreate: PASS (two create+lock cycles survived)",13,10
LANDING_PAD
public cmd_mvrecreate
cmd_mvrecreate proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-32], 0            ; cycle
mrc_cycle:
    cmp     dword ptr [rbp-32], 2
    jae     mrc_pass
    lea     r10, [g_argv]                     ; g_cfg_in = argv[2]
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [g_cfg_in], rax
    lea     r10, [ffk_seedpw]                 ; seed password
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
mrc_pw:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      mrc_pwd
    inc     ecx
    cmp     ecx, 32
    jb      mrc_pw
mrc_pwd:
    mov     dword ptr [g_cfg_passlen], 9
    mov     ecx, 1
    call    do_seed                           ; create the vault file
    test    eax, eax
    mov     eax, 2
    jnz     mrc_ret
    call    vk_derive                         ; master key
    call    vault_ctx_reset                   ; go_vault: claim slot 0 + unlock
    call    vault_ctx_open
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [g_cfg_in], rax
    mov     dword ptr [g_reuse_key], 1
    call    vault_unlock
    mov     dword ptr [g_reuse_key], 0
    test    eax, eax
    mov     eax, 3
    jnz     mrc_ret
    call    fed_unlock_master
    call    fed_fanout
    call    vault_ctx_reset                   ; lock
    call    vault_lock
    inc     dword ptr [rbp-32]
    jmp     mrc_cycle
mrc_pass:
    lea     rcx, [mrc_ok]
    mov     edx, mrc_ok_len
    call    print_a
    xor     eax, eax
mrc_ret:
    FRAME_EPILOG
    ret
cmd_mvrecreate endp

; ===========================================================================
; M1 (master-vault federation): vault identity.  The machine-local keyring
; keys foreign vaults by a 16-byte vault_id.  It is derived from the header
; salt - SHA-256(salt)[0..15] - which is stable (the salt is fixed at vault
; creation) and unique, and needs no format change.  A pinned system-item ID
; supersedes this once system items land (M1.2).
; ===========================================================================
; vault_id_of(rcx = out16) - write SHA-256(g_hdr salt)[0..15] to out.
public vault_id_of
; vault_id_hdr(rcx = &salt32, rdx = out16) - out = SHA-256(salt)[0..15].
public vault_id_hdr
vault_id_hdr proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rdx           ; out16
    mov     edx, 32                           ; rcx already = &salt
    lea     r8, [rbp-64]                      ; 32-byte digest scratch (above the shadow)
    call    sha256_hash
    mov     rcx, qword ptr [rbp-24]           ; out = digest[0..15]
    lea     rdx, [rbp-64]
    mov     r8d, 16
    call    copy_bytes
    FRAME_EPILOG
    ret
vault_id_hdr endp

; vault_id_of(rcx = out16) - out = SHA-256(g_hdr salt)[0..15] (the live vault).
public vault_id_of
vault_id_of proc frame
    FRAME_PROLOG 32
    mov     rdx, rcx                          ; out
    lea     rcx, [g_hdr+VH_SALT]
    call    vault_id_hdr
    FRAME_EPILOG
    ret
vault_id_of endp

; cmd_idkat - headless KAT for vault_id_of: (1) it equals SHA-256(salt)[0..15],
;   (2) it is deterministic (same salt -> same id), (3) it differs for a
;   different salt.  Clobbers g_hdr salt (scratch when no vault is open).
;   Exit 0 = pass.
LANDING_PAD
public cmd_idkat
cmd_idkat proc frame
    FRAME_PROLOG 112
    lea     rcx, [g_hdr+VH_SALT]              ; salt = 0x11 * 32
    mov     edx, 32
    mov     r8b, 011h
    call    idk_fill
    lea     rcx, [rbp-32]                     ; id_a = vault_id_of()
    call    vault_id_of
    lea     rcx, [g_hdr+VH_SALT]              ; ref = SHA-256(salt), compare [0..15]
    mov     edx, 32
    lea     r8, [rbp-80]
    call    sha256_hash
    lea     rcx, [rbp-32]
    lea     rdx, [rbp-80]
    mov     r8d, 16
    call    idk_eq
    test    eax, eax
    jz      idk_fail                          ; (1) must equal SHA-256(salt)[0..15]
    lea     rcx, [rbp-48]                     ; (2) determinism: id again == id_a
    call    vault_id_of
    lea     rcx, [rbp-32]
    lea     rdx, [rbp-48]
    mov     r8d, 16
    call    idk_eq
    test    eax, eax
    jz      idk_fail
    lea     rcx, [g_hdr+VH_SALT]              ; (3) distinctness: salt = 0x22 -> id_b != id_a
    mov     edx, 32
    mov     r8b, 022h
    call    idk_fill
    lea     rcx, [rbp-48]
    call    vault_id_of
    lea     rcx, [rbp-32]
    lea     rdx, [rbp-48]
    mov     r8d, 16
    call    idk_eq
    test    eax, eax
    jnz     idk_fail
    xor     eax, eax
    FRAME_EPILOG
    ret
idk_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_idkat endp

; idk_fill(rcx=ptr, edx=len, r8b=val) - byte-fill helper.  Leaf, volatile regs.
idk_fill proc
    xor     r9d, r9d
idkf_lp:
    cmp     r9d, edx
    jae     idkf_done
    mov     byte ptr [rcx+r9], r8b
    inc     r9d
    jmp     idkf_lp
idkf_done:
    ret
idk_fill endp

; idk_eq(rcx=a, rdx=b, r8d=len) -> eax = 1 if equal else 0.  Leaf, volatile regs.
idk_eq proc
    xor     r9d, r9d
idke_lp:
    cmp     r9d, r8d
    jae     idke_eq
    mov     al, byte ptr [rcx+r9]
    cmp     al, byte ptr [rdx+r9]
    jne     idke_ne
    inc     r9d
    jmp     idke_lp
idke_eq:
    mov     eax, 1
    ret
idke_ne:
    xor     eax, eax
    ret
idk_eq endp

; ===========================================================================
; M2 (machine-local keyring): at-rest crypto.  The federation record is
; AES-256-GCM'd under KEK = BLAKE2b-256("vordr-federation-kek-v1" || master_key
; || tpm_secret): the master key is the unlock gate, the TPM-sealed machine
; secret is the machine binding.  Reuses the shipped keyed-BLAKE2b - no new
; primitive.
; ===========================================================================
; keyring_kek(rcx = out32, rdx = master_key32, r8 = tpm_secret32) - derive the
;   32-byte keyring key.  Domain-separated, order-fixed (master then tpm).
public keyring_kek
keyring_kek proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx           ; out32
    mov     qword ptr [rbp-32], rdx           ; master_key
    mov     qword ptr [rbp-40], r8            ; tpm_secret
    lea     rcx, [g_fed_ctx]
    mov     edx, 32
    call    blake2b_init
    lea     rcx, [g_fed_ctx]                  ; domain prefix
    lea     rdx, [fed_kek_domain]
    mov     r8, FED_KEK_DOMLEN
    call    blake2b_update
    lea     rcx, [g_fed_ctx]                  ; master key (unlock gate)
    mov     rdx, qword ptr [rbp-32]
    mov     r8, 32
    call    blake2b_update
    lea     rcx, [g_fed_ctx]                  ; tpm secret (machine binding)
    mov     rdx, qword ptr [rbp-40]
    mov     r8, 32
    call    blake2b_update
    lea     rcx, [g_fed_ctx]
    mov     rdx, qword ptr [rbp-24]
    call    blake2b_final
    FRAME_EPILOG
    ret
keyring_kek endp

; cmd_kekkat - headless KAT for keyring_kek: deterministic, and sensitive to
;   BOTH the master key and the tpm secret (changing either changes the KEK).
;   Exit 0 = pass.
LANDING_PAD
public cmd_kekkat
cmd_kekkat proc frame
    FRAME_PROLOG 224                           ; 5x 32-byte buffers down to [rbp-176]
    lea     rcx, [rbp-40]                     ; master = 0x33 * 32  (rbp-40..-9)
    mov     edx, 32
    mov     r8b, 033h
    call    idk_fill
    lea     rcx, [rbp-80]                     ; tpm = 0x44 * 32      (rbp-80..-49)
    mov     edx, 32
    mov     r8b, 044h
    call    idk_fill
    lea     rcx, [rbp-112]                    ; kek1 = KEK(master,tpm)  (rbp-112..-81)
    lea     rdx, [rbp-40]
    lea     r8, [rbp-80]
    call    keyring_kek
    lea     rcx, [rbp-144]                    ; kek1b = KEK(master,tpm) again
    lea     rdx, [rbp-40]
    lea     r8, [rbp-80]
    call    keyring_kek
    lea     rcx, [rbp-112]                    ; determinism: kek1 == kek1b
    lea     rdx, [rbp-144]
    mov     r8d, 32
    call    idk_eq
    test    eax, eax
    jz      kek_fail
    lea     rcx, [rbp-144]                    ; master sensitivity: master = 0x55
    mov     edx, 32
    mov     r8b, 055h
    call    idk_fill                          ; (reuse rbp-144 as a 2nd master buf)
    lea     rcx, [rbp-176]                    ; kek2 = KEK(master2, tpm)
    lea     rdx, [rbp-144]
    lea     r8, [rbp-80]
    call    keyring_kek
    lea     rcx, [rbp-112]                    ; kek1 != kek2
    lea     rdx, [rbp-176]
    mov     r8d, 32
    call    idk_eq
    test    eax, eax
    jnz     kek_fail
    lea     rcx, [rbp-80]                     ; tpm sensitivity: tpm = 0x66
    mov     edx, 32
    mov     r8b, 066h
    call    idk_fill
    lea     rcx, [rbp-176]                    ; kek3 = KEK(master1, tpm2)
    lea     rdx, [rbp-40]
    lea     r8, [rbp-80]
    call    keyring_kek
    lea     rcx, [rbp-112]                    ; kek1 != kek3
    lea     rdx, [rbp-176]
    mov     r8d, 32
    call    idk_eq
    test    eax, eax
    jnz     kek_fail
    xor     eax, eax
    FRAME_EPILOG
    ret
kek_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_kekkat endp

; keyring_seal(rcx=&record, edx=reclen, r8=&kek32, r9=&outblob) -> eax = blob len.
;   outblob = [nonce12][ciphertext(reclen)][tag16]; caller supplies reclen+28 cap.
public keyring_seal
keyring_seal proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx           ; record
    mov     qword ptr [rbp-32], r8            ; kek
    mov     qword ptr [rbp-40], r9            ; outblob
    mov     dword ptr [rbp-48], edx           ; reclen (below the qwords - no overlap)
    mov     rcx, r9                           ; nonce = 12 fresh CSPRNG bytes at outblob[0]
    mov     edx, 12
    call    rng_fill
    lea     r10, [g_fedreq]
    mov     rax, qword ptr [rbp-32]           ; key = KEK
    mov     qword ptr [r10].GCMREQ.key, rax
    mov     rax, qword ptr [rbp-40]           ; iv = outblob (the nonce)
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [fed_kek_domain]             ; aad = domain (bind the blob to a version)
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, FED_KEK_DOMLEN
    mov     rax, qword ptr [rbp-24]           ; inp = record
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     eax, dword ptr [rbp-48]           ; inlen = reclen
    mov     qword ptr [r10].GCMREQ.inlen, rax
    mov     rax, qword ptr [rbp-40]           ; outp = outblob + 12
    add     rax, 12
    mov     qword ptr [r10].GCMREQ.outp, rax
    mov     rax, qword ptr [rbp-40]           ; tag = outblob + 12 + reclen
    add     rax, 12
    mov     ecx, dword ptr [rbp-48]
    add     rax, rcx
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_fedreq]
    call    gcm_seal
    mov     eax, dword ptr [rbp-48]           ; 12 + reclen + 16
    add     eax, 28
    FRAME_EPILOG
    ret
keyring_seal endp

; keyring_open(rcx=&blob, edx=bloblen, r8=&kek32, r9=&outrec) -> eax = reclen, or
;   -1 on a too-short blob or authentication failure (wrong key = wrong machine).
public keyring_open
keyring_open proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx           ; blob
    mov     qword ptr [rbp-32], r8            ; kek
    mov     qword ptr [rbp-40], r9            ; outrec
    mov     dword ptr [rbp-44], edx           ; bloblen (below the qwords - no overlap)
    mov     eax, dword ptr [rbp-44]           ; ptlen = bloblen - 28
    sub     eax, 28
    js      ko_fail                           ; too short to hold nonce+tag
    mov     dword ptr [rbp-48], eax           ; ptlen
    lea     r10, [g_fedreq]
    mov     rax, qword ptr [rbp-32]           ; key = KEK
    mov     qword ptr [r10].GCMREQ.key, rax
    mov     rax, qword ptr [rbp-24]           ; iv = blob (the nonce)
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [fed_kek_domain]             ; aad = domain (bind the blob to a version)
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, FED_KEK_DOMLEN
    mov     rax, qword ptr [rbp-24]           ; inp = ciphertext = blob + 12
    add     rax, 12
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     eax, dword ptr [rbp-48]           ; inlen = ptlen
    mov     qword ptr [r10].GCMREQ.inlen, rax
    mov     rax, qword ptr [rbp-40]           ; outp = outrec
    mov     qword ptr [r10].GCMREQ.outp, rax
    mov     rax, qword ptr [rbp-24]           ; tag = blob + 12 + ptlen
    add     rax, 12
    mov     ecx, dword ptr [rbp-48]
    add     rax, rcx
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_fedreq]
    call    gcm_open
    test    eax, eax
    jnz     ko_fail                           ; auth failed
    mov     eax, dword ptr [rbp-48]           ; return ptlen
    FRAME_EPILOG
    ret
ko_fail:
    mov     eax, -1
    FRAME_EPILOG
    ret
keyring_open endp

; cmd_keyringkat - headless KAT for the keyring blob crypto: seal a synthetic
;   record, open it with the same KEK and assert a byte-exact round-trip, then
;   open with a KEK from a different tpm_secret and assert it fails (machine
;   binding).  Exit 0 = pass.
KEYRINGKAT_RECLEN equ 100
LANDING_PAD
public cmd_keyringkat
cmd_keyringkat proc frame
    FRAME_PROLOG 48
    lea     rcx, [g_fedkat_rec]               ; record = 0xAB * 100, with distinct end bytes
    mov     edx, KEYRINGKAT_RECLEN
    mov     r8b, 0ABh
    call    idk_fill
    mov     byte ptr [g_fedkat_rec], 1
    mov     byte ptr [g_fedkat_rec + KEYRINGKAT_RECLEN - 1], 099h
    lea     rcx, [g_fedkat_mk]                ; master = 0x33 * 32
    mov     edx, 32
    mov     r8b, 033h
    call    idk_fill
    lea     rcx, [g_fedkat_tpm]               ; tpm = 0x44 * 32
    mov     edx, 32
    mov     r8b, 044h
    call    idk_fill
    lea     rcx, [g_fedkat_kek]               ; kek = KEK(master, tpm)
    lea     rdx, [g_fedkat_mk]
    lea     r8, [g_fedkat_tpm]
    call    keyring_kek
    lea     rcx, [g_fedkat_rec]               ; blob = seal(record, kek)
    mov     edx, KEYRINGKAT_RECLEN
    lea     r8, [g_fedkat_kek]
    lea     r9, [g_fedkat_blob]
    call    keyring_seal
    mov     dword ptr [rbp-24], eax           ; bloblen (= reclen + 28)
    cmp     eax, KEYRINGKAT_RECLEN + 28
    mov     eax, 2
    jne     krk_ret
    lea     rcx, [g_fedkat_blob]              ; open with the right kek
    mov     edx, dword ptr [rbp-24]
    lea     r8, [g_fedkat_kek]
    lea     r9, [g_fedkat_out]
    call    keyring_open
    cmp     eax, KEYRINGKAT_RECLEN            ; reclen must round-trip
    mov     eax, 3
    jne     krk_ret
    lea     rcx, [g_fedkat_rec]               ; plaintext must round-trip byte-exact
    lea     rdx, [g_fedkat_out]
    mov     r8d, KEYRINGKAT_RECLEN
    call    idk_eq
    test    eax, eax
    mov     eax, 4
    jz      krk_ret
    lea     rcx, [g_fedkat_tpm]               ; wrong machine: tpm = 0x55 -> different KEK
    mov     edx, 32
    mov     r8b, 055h
    call    idk_fill
    lea     rcx, [g_fedkat_kek]
    lea     rdx, [g_fedkat_mk]
    lea     r8, [g_fedkat_tpm]
    call    keyring_kek
    lea     rcx, [g_fedkat_blob]              ; open with the wrong KEK must fail (-1)
    mov     edx, dword ptr [rbp-24]
    lea     r8, [g_fedkat_kek]
    lea     r9, [g_fedkat_out]
    call    keyring_open
    cmp     eax, -1
    mov     eax, 5
    jne     krk_ret
    xor     eax, eax
krk_ret:
    FRAME_EPILOG
    ret
cmd_keyringkat endp

; --- M2: federation link-table management -----------------------------------
; fed_reset() - empty the record.  Leaf.
public fed_reset
fed_reset proc
    mov     dword ptr [g_fedrec + FEDREC.fr_count], 0
    ret
fed_reset endp

; fed_slot(ecx = index) -> rax = &g_fedrec link[index].  Leaf, no bounds check.
public fed_slot
fed_slot proc
    mov     eax, ecx
    imul    rax, rax, sizeof FEDLINK
    lea     rcx, [g_fedrec + FEDREC.fr_links]
    add     rax, rcx
    ret
fed_slot endp

; fed_find(rcx = &id16) -> eax = index of the link with that vault_id, else -1.
public fed_find
fed_find proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx           ; &id
    mov     dword ptr [rbp-32], 0             ; i
ff_lp:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [g_fedrec + FEDREC.fr_count]
    jae     ff_none
    mov     ecx, dword ptr [rbp-32]
    call    fed_slot                          ; rax = &link[i] (fl_id at offset 0)
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-24]
    mov     r8d, 16
    call    idk_eq
    test    eax, eax
    jnz     ff_hit
    inc     dword ptr [rbp-32]
    jmp     ff_lp
ff_hit:
    mov     eax, dword ptr [rbp-32]
    FRAME_EPILOG
    ret
ff_none:
    mov     eax, -1
    FRAME_EPILOG
    ret
fed_find endp

; fed_add(rcx = &FEDLINK src) -> eax = index (update the link with the same id, or
;   append a new one), or -1 if the table is full.  Copies the whole fixed FEDLINK.
public fed_add
fed_add proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx           ; src (fl_id at offset 0)
    call    fed_find                          ; already have this vault_id?
    cmp     eax, -1
    jne     fa_have
    mov     eax, dword ptr [g_fedrec + FEDREC.fr_count]   ; append
    cmp     eax, FED_MAXLINKS
    jae     fa_full
    mov     dword ptr [rbp-32], eax           ; idx = count
    inc     eax
    mov     dword ptr [g_fedrec + FEDREC.fr_count], eax
    jmp     fa_copy
fa_have:
    mov     dword ptr [rbp-32], eax           ; idx = existing
fa_copy:
    mov     ecx, dword ptr [rbp-32]
    call    fed_slot
    mov     rcx, rax                          ; dst = &link[idx]
    mov     rdx, qword ptr [rbp-24]           ; src
    mov     r8d, sizeof FEDLINK
    call    copy_bytes
    mov     eax, dword ptr [rbp-32]
    FRAME_EPILOG
    ret
fa_full:
    mov     eax, -1
    FRAME_EPILOG
    ret
fed_add endp

; cmd_fedkat - headless KAT for the link table + record round-trip: add 3 links,
;   assert count + lookups, seal the record, clear it, open it back, and assert
;   the links survive (count, id lookup, and a cached-key byte-pattern).  Exit 0.
LANDING_PAD
public cmd_fedkat
cmd_fedkat proc frame
    FRAME_PROLOG 48
    call    fed_reset
    mov     dword ptr [rbp-24], 0             ; v
fk_build:
    cmp     dword ptr [rbp-24], 3
    jae     fk_built
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_id]   ; id = (0x10+v) * 16
    mov     edx, 16
    mov     r8d, dword ptr [rbp-24]
    add     r8d, 010h
    call    idk_fill
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_key]  ; key = (0x20+v) * 32
    mov     edx, 32
    mov     r8d, dword ptr [rbp-24]
    add     r8d, 020h
    call    idk_fill
    mov     dword ptr [g_fedlink_tmp + FEDLINK.fl_flags], LINK_STALE or LINK_MISSING or LINK_PROMPT
    lea     rcx, [g_fedlink_tmp]
    call    fed_add
    inc     dword ptr [rbp-24]
    jmp     fk_build
fk_built:
    cmp     dword ptr [g_fedrec + FEDREC.fr_count], 3
    mov     eax, 2
    jne     fk_ret
    ; derive a kek and seal the record
    lea     rcx, [g_fedkat_mk]
    mov     edx, 32
    mov     r8b, 077h
    call    idk_fill
    lea     rcx, [g_fedkat_tpm]
    mov     edx, 32
    mov     r8b, 088h
    call    idk_fill
    lea     rcx, [g_fedkat_kek]
    lea     rdx, [g_fedkat_mk]
    lea     r8, [g_fedkat_tpm]
    call    keyring_kek
    lea     rcx, [g_fedrec]
    mov     edx, sizeof FEDREC
    lea     r8, [g_fedkat_kek]
    lea     r9, [g_fedblob]
    call    keyring_seal
    mov     dword ptr [rbp-28], eax           ; bloblen
    call    fed_reset                          ; wipe the live record
    lea     rcx, [g_fedblob]                  ; open back into g_fedrec
    mov     edx, dword ptr [rbp-28]
    lea     r8, [g_fedkat_kek]
    lea     r9, [g_fedrec]
    call    keyring_open
    cmp     eax, sizeof FEDREC
    mov     eax, 3
    jne     fk_ret
    cmp     dword ptr [g_fedrec + FEDREC.fr_count], 3   ; count survived
    mov     eax, 4
    jne     fk_ret
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_id]   ; find id for v=1 -> index 1
    mov     edx, 16
    mov     r8b, 011h
    call    idk_fill
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_id]
    call    fed_find
    cmp     eax, 1
    mov     eax, 5
    jne     fk_ret
    mov     ecx, 1                             ; link[1].fl_key must be 0x21 * 32
    call    fed_slot
    lea     rcx, [g_fedkat_out]
    mov     edx, 32
    mov     r8b, 021h
    call    idk_fill
    mov     ecx, 1
    call    fed_slot
    lea     rcx, [rax + FEDLINK.fl_key]
    lea     rdx, [g_fedkat_out]
    mov     r8d, 32
    call    idk_eq
    test    eax, eax
    mov     eax, 6
    jz      fk_ret
    mov     ecx, 1                             ; flags round-trip intact
    call    fed_slot
    cmp     dword ptr [rax + FEDLINK.fl_flags], LINK_STALE or LINK_MISSING or LINK_PROMPT
    mov     eax, 7
    jne     fk_ret
    xor     eax, eax
fk_ret:
    FRAME_EPILOG
    ret
cmd_fedkat endp

; --- M2: federation record registry persistence -----------------------------
; fed_store(rcx = &kek32) -> eax = 1/0.  Seal the live record and write it to
;   HKCU\SOFTWARE\Vordr\Federation (machine-local, non-exportable).
public fed_store
fed_store proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx           ; kek
    lea     rcx, [g_fedrec]                   ; blob = seal(record, kek)
    mov     edx, sizeof FEDREC
    mov     r8, qword ptr [rbp-24]
    lea     r9, [g_fedblob]
    call    keyring_seal
    mov     dword ptr [rbp-32], eax           ; bloblen
    lea     rcx, [fed_valname]
    lea     rdx, [g_fedblob]
    mov     r8d, dword ptr [rbp-32]
    call    reg_fed_set
    FRAME_EPILOG
    ret
fed_store endp

; fed_load(rcx = &kek32) -> eax = 1 if a record was decrypted into g_fedrec, else
;   0 (no stored record, or auth failed = wrong master key / wrong machine).
public fed_load
fed_load proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx           ; kek
    lea     rcx, [fed_valname]                ; blob = registry read
    lea     rdx, [g_fedblob]
    mov     r8d, (sizeof FEDREC) + 32
    call    reg_fed_get
    test    eax, eax
    jz      fl_none                            ; no stored record
    mov     dword ptr [rbp-32], eax           ; bloblen
    lea     rcx, [g_fedblob]
    mov     edx, dword ptr [rbp-32]
    mov     r8, qword ptr [rbp-24]
    lea     r9, [g_fedrec]
    call    keyring_open
    cmp     eax, 0
    jl      fl_none                            ; auth fail
    mov     eax, 1
    FRAME_EPILOG
    ret
fl_none:
    xor     eax, eax
    FRAME_EPILOG
    ret
fed_load endp

; cmd_fedregkat - headless KAT for registry persistence: build a record, store it,
;   wipe the live copy, load it back and assert it survives, then delete the value
;   and assert a subsequent load reports "none".  Self-cleaning.  Exit 0 = pass.
LANDING_PAD
public cmd_fedregkat
cmd_fedregkat proc frame
    FRAME_PROLOG 64
    call    fed_rec_backup                    ; preserve the user's real record
    call    fed_reset
    mov     dword ptr [rbp-24], 0             ; v
frk_build:
    cmp     dword ptr [rbp-24], 2
    jae     frk_built
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_id]
    mov     edx, 16
    mov     r8d, dword ptr [rbp-24]
    add     r8d, 030h
    call    idk_fill
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_key]
    mov     edx, 32
    mov     r8d, dword ptr [rbp-24]
    add     r8d, 040h
    call    idk_fill
    mov     dword ptr [g_fedlink_tmp + FEDLINK.fl_flags], 0
    lea     rcx, [g_fedlink_tmp]
    call    fed_add
    inc     dword ptr [rbp-24]
    jmp     frk_build
frk_built:
    lea     rcx, [g_fedkat_mk]                ; kek = KEK(0x99, 0xAA)
    mov     edx, 32
    mov     r8b, 099h
    call    idk_fill
    lea     rcx, [g_fedkat_tpm]
    mov     edx, 32
    mov     r8b, 0AAh
    call    idk_fill
    lea     rcx, [g_fedkat_kek]
    lea     rdx, [g_fedkat_mk]
    lea     r8, [g_fedkat_tpm]
    call    keyring_kek
    lea     rcx, [g_fedkat_kek]              ; store -> registry
    call    fed_store
    test    eax, eax
    mov     eax, 2
    jz      frk_ret
    call    fed_reset                          ; wipe the live record
    lea     rcx, [g_fedkat_kek]              ; load back
    call    fed_load
    cmp     eax, 1
    mov     eax, 3
    jne     frk_ret
    cmp     dword ptr [g_fedrec + FEDREC.fr_count], 2
    mov     eax, 4
    jne     frk_ret
    lea     rcx, [fed_valname]               ; cleanup: delete the value
    call    reg_fed_del
    lea     rcx, [g_fedkat_kek]              ; load now reports none
    call    fed_load
    test    eax, eax
    mov     eax, 5
    jnz     frk_ret
    xor     eax, eax
frk_ret:
    mov     dword ptr [rbp-32], eax           ; save exit code across the restore
    call    fed_rec_restore                    ; restore the user's real record
    mov     eax, dword ptr [rbp-32]
    FRAME_EPILOG
    ret
cmd_fedregkat endp

; --- M2: TPM machine-secret provisioning (the KEK's machine-binding input) ---
; fed_machine_secret(rcx = out32, rdx = keyname_wide, r8 = valname_wide) -> eax:
;   1 = out holds the per-machine secret (unsealed the stored one, or freshly
;   generated+sealed+stored); 0 = no usable TPM (caller falls back to
;   master-key-only, with the copyable-keyring UI warning).
public fed_machine_secret
fed_machine_secret proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx           ; out32
    mov     qword ptr [rbp-32], rdx           ; keyname
    mov     qword ptr [rbp-40], r8            ; valname
    call    tpm_available
    test    eax, eax
    jz      fms_notpm
    mov     rcx, qword ptr [rbp-40]           ; stored sealed blob?
    lea     rdx, [g_fed_mkblob]
    mov     r8d, 512
    call    reg_fed_get
    test    eax, eax
    jz      fms_new
    mov     dword ptr [rbp-44], eax           ; bloblen
    mov     rcx, qword ptr [rbp-32]           ; unseal into out32
    lea     rdx, [g_fed_mkblob]
    mov     r8d, dword ptr [rbp-44]
    mov     r9, qword ptr [rbp-24]
    call    tpm_unseal
    test    eax, eax
    jz      fms_new                           ; stored blob unusable -> regenerate
    mov     eax, 1
    FRAME_EPILOG
    ret
fms_new:
    mov     rcx, qword ptr [rbp-24]           ; fresh 32-byte secret into out
    mov     edx, 32
    call    rng_fill
    mov     rcx, qword ptr [rbp-32]           ; seal it
    mov     rdx, qword ptr [rbp-24]
    lea     r8, [g_fed_mkblob]
    mov     r9d, 512
    call    tpm_seal
    test    eax, eax
    jz      fms_notpm                         ; seal failed -> treat as no TPM
    mov     dword ptr [rbp-44], eax           ; bloblen
    mov     rcx, qword ptr [rbp-40]           ; store the sealed blob
    lea     rdx, [g_fed_mkblob]
    mov     r8d, dword ptr [rbp-44]
    call    reg_fed_set
    mov     eax, 1
    FRAME_EPILOG
    ret
fms_notpm:
    xor     eax, eax
    FRAME_EPILOG
    ret
fed_machine_secret endp

; cmd_fmskat - headless KAT for machine-secret provisioning: provision a secret
;   under TEST key/value names, retrieve it again, and assert the two match (the
;   secret is stable = machine-bound).  No TPM -> 0, trivially passes.  Deletes
;   the test TPM key + registry value on entry and exit (self-cleaning).  Exit 0.
LANDING_PAD
public cmd_fmskat
cmd_fmskat proc frame
    FRAME_PROLOG 48
    lea     rcx, [fms_kat_key]                ; clean any leftover from a prior run
    call    tpm_delete
    lea     rcx, [fms_kat_val]
    call    reg_fed_del
    lea     rcx, [g_fms_out1]                 ; provision
    lea     rdx, [fms_kat_key]
    lea     r8, [fms_kat_val]
    call    fed_machine_secret
    test    eax, eax
    jz      fms_kat_notpm                     ; no TPM -> can't test, pass
    lea     rcx, [g_fms_out2]                 ; retrieve again -> must be identical
    lea     rdx, [fms_kat_key]
    lea     r8, [fms_kat_val]
    call    fed_machine_secret
    test    eax, eax
    mov     dword ptr [rbp-24], 2
    jz      fms_kat_done
    lea     rcx, [g_fms_out1]
    lea     rdx, [g_fms_out2]
    mov     r8d, 32
    call    idk_eq
    test    eax, eax
    mov     dword ptr [rbp-24], 3
    jz      fms_kat_done
    mov     dword ptr [rbp-24], 0             ; pass
fms_kat_done:
    lea     rcx, [fms_kat_key]                ; cleanup (self-cleaning)
    call    tpm_delete
    lea     rcx, [fms_kat_val]
    call    reg_fed_del
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
fms_kat_notpm:
    xor     eax, eax
    FRAME_EPILOG
    ret
cmd_fmskat endp

; --- M2: master-key-level federation API (the glue the GUI unlock path calls) --
; fed_save_all(rcx=&master_key32, rdx=keyname, r8=valname) -> eax = 1/0.  Derive
;   tpm_secret (or zero it when no TPM), derive the KEK, seal+store g_fedrec.
public fed_save_all
fed_save_all proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx           ; master_key
    mov     qword ptr [rbp-32], rdx           ; keyname
    mov     qword ptr [rbp-40], r8            ; valname
    lea     rcx, [g_fed_tpmsec]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, qword ptr [rbp-40]
    call    fed_machine_secret
    test    eax, eax
    jnz     @F
    lea     rcx, [g_fed_tpmsec]               ; no TPM -> master-key-only (zero secret)
    mov     edx, 32
    call    secure_zero
@@: lea     rcx, [g_fed_workkek]              ; kek = KEK(master_key, tpm_secret)
    mov     rdx, qword ptr [rbp-24]
    lea     r8, [g_fed_tpmsec]
    call    keyring_kek
    lea     rcx, [g_fed_workkek]
    call    fed_store
    mov     dword ptr [rbp-48], eax
    lea     rcx, [g_fed_tpmsec]               ; wipe working key material
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_fed_workkek]
    mov     edx, 32
    call    secure_zero
    mov     eax, dword ptr [rbp-48]
    FRAME_EPILOG
    ret
fed_save_all endp

; fed_unlock_all(rcx=&master_key32, rdx=keyname, r8=valname) -> eax = link count
;   (0 = no stored record or auth failed).  Loads the record into g_fedrec.
public fed_unlock_all
fed_unlock_all proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx           ; master_key
    mov     qword ptr [rbp-32], rdx           ; keyname
    mov     qword ptr [rbp-40], r8            ; valname
    lea     rcx, [fed_valname]                ; peek: is there a stored record at all?
    lea     rdx, [g_fedblob]                  ;   (skip TPM provisioning for users who
    mov     r8d, (sizeof FEDREC) + 32         ;    never federate - no record, no key)
    call    reg_fed_get
    test    eax, eax
    jz      fua_none
    lea     rcx, [g_fed_tpmsec]               ; provision/get the machine secret
    mov     rdx, qword ptr [rbp-32]
    mov     r8, qword ptr [rbp-40]
    call    fed_machine_secret
    test    eax, eax
    jnz     @F
    lea     rcx, [g_fed_tpmsec]               ; no TPM -> master-key-only
    mov     edx, 32
    call    secure_zero
@@: lea     rcx, [g_fed_workkek]              ; kek = KEK(master_key, tpm_secret)
    mov     rdx, qword ptr [rbp-24]
    lea     r8, [g_fed_tpmsec]
    call    keyring_kek
    lea     rcx, [g_fed_workkek]
    call    fed_load
    mov     dword ptr [rbp-48], eax           ; 1 = loaded, 0 = auth fail
    lea     rcx, [g_fed_tpmsec]               ; wipe working key material
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_fed_workkek]
    mov     edx, 32
    call    secure_zero
    cmp     dword ptr [rbp-48], 0
    je      fua_none
    mov     eax, dword ptr [g_fedrec + FEDREC.fr_count]
    FRAME_EPILOG
    ret
fua_none:
    call    fed_reset                          ; no record / auth fail -> empty table
    xor     eax, eax
    FRAME_EPILOG
    ret
fed_unlock_all endp

; fed_unlock_master() -> eax = link count.  Load the machine-local federation
;   record under the currently-unlocked master key (g_vkey).  Called by the GUI
;   immediately after the master vault decrypts.
public fed_unlock_master
fed_unlock_master proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_vkey]
    lea     rdx, [fms_key]
    lea     r8, [fms_val]
    call    fed_unlock_all
    FRAME_EPILOG
    ret
fed_unlock_master endp

; cmd_fedapikat - headless KAT for the master-key API: build a record, save it
;   under a master key, wipe the live copy, unlock with the same key and assert
;   the links return.  Uses TEST TPM/registry names and self-cleans.  Exit 0.
LANDING_PAD
public cmd_fedapikat
cmd_fedapikat proc frame
    FRAME_PROLOG 64
    call    fed_rec_backup                    ; preserve the user's real record
    lea     rcx, [fms_kat_key]                ; clean start
    call    tpm_delete
    lea     rcx, [fms_kat_val]
    call    reg_fed_del
    lea     rcx, [fed_valname]
    call    reg_fed_del
    call    fed_reset                          ; build 2 links
    mov     dword ptr [rbp-24], 0
fak_build:
    cmp     dword ptr [rbp-24], 2
    jae     fak_built
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_id]
    mov     edx, 16
    mov     r8d, dword ptr [rbp-24]
    add     r8d, 050h
    call    idk_fill
    mov     dword ptr [g_fedlink_tmp + FEDLINK.fl_flags], 0
    lea     rcx, [g_fedlink_tmp]
    call    fed_add
    inc     dword ptr [rbp-24]
    jmp     fak_build
fak_built:
    lea     rcx, [g_fedkat_mk]                ; a synthetic master key
    mov     edx, 32
    mov     r8b, 0C3h
    call    idk_fill
    lea     rcx, [g_fedkat_mk]                ; save under it
    lea     rdx, [fms_kat_key]
    lea     r8, [fms_kat_val]
    call    fed_save_all
    test    eax, eax
    mov     dword ptr [rbp-28], 2
    jz      fak_done
    call    fed_reset                          ; wipe the live record
    lea     rcx, [g_fedkat_mk]                ; unlock with the same master key
    lea     rdx, [fms_kat_key]
    lea     r8, [fms_kat_val]
    call    fed_unlock_all
    cmp     eax, 2                             ; both links must return
    mov     dword ptr [rbp-28], 3
    jne     fak_done
    mov     dword ptr [rbp-28], 0             ; pass
fak_done:
    lea     rcx, [fms_kat_key]                ; self-clean
    call    tpm_delete
    lea     rcx, [fms_kat_val]
    call    reg_fed_del
    call    fed_rec_restore                    ; restore the user's real record
    mov     eax, dword ptr [rbp-28]
    FRAME_EPILOG
    ret
cmd_fedapikat endp

; fed_rec_backup() - stash the real federation record blob so a KAT can clobber
;   fed_valname and put it back.  fed_rec_restore() undoes it (deletes if none).
fed_rec_backup proc frame
    FRAME_PROLOG 32
    lea     rcx, [fed_valname]
    lea     rdx, [g_fedkat_bak]
    mov     r8d, (sizeof FEDREC) + 32
    call    reg_fed_get
    mov     dword ptr [g_fedkat_baklen], eax
    FRAME_EPILOG
    ret
fed_rec_backup endp

fed_rec_restore proc frame
    FRAME_PROLOG 32
    cmp     dword ptr [g_fedkat_baklen], 0
    jne     frr_set
    lea     rcx, [fed_valname]
    call    reg_fed_del
    FRAME_EPILOG
    ret
frr_set:
    lea     rcx, [fed_valname]
    lea     rdx, [g_fedkat_bak]
    mov     r8d, dword ptr [g_fedkat_baklen]
    call    reg_fed_set
    FRAME_EPILOG
    ret
fed_rec_restore endp

; --- M2: fan-out — open every foreign vault with its cached key ---------------
; fed_fanout() - for each link in g_fedrec (skipping LINK_PROMPT), open the
;   foreign vault into a new multi-vault context using its cached key (the
;   g_reuse_key / KDF-skip path).  On failure, mark the link (MISSING if the
;   file is gone, else STALE = the cached key no longer matches) and roll the
;   claimed slot back.  Leaves the master (slot 0) fronted.  Call after
;   fed_unlock_master, with the master already registered as slot 0.
public fed_fanout
fed_fanout proc frame
    FRAME_PROLOG 80
    mov     dword ptr [rbp-24], 0            ; i
ffo_loop:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_fedrec + FEDREC.fr_count]
    jae     ffo_done
    mov     ecx, dword ptr [rbp-24]
    call    fed_slot
    mov     qword ptr [rbp-32], rax          ; link
    test    dword ptr [rax + FEDLINK.fl_flags], LINK_PROMPT
    jnz     ffo_next                          ; opt-out: no cached key, skip
    mov     eax, dword ptr [g_vault_cur]      ; remember the vault to restore on failure
    mov     dword ptr [rbp-36], eax
    call    vault_ctx_open                    ; claim a slot (cur = new)
    cmp     eax, -1
    je      ffo_done                          ; table full (MAX_VAULTS)
    mov     dword ptr [rbp-40], eax           ; new idx
    mov     r10, qword ptr [rbp-32]           ; g_vkey = cached key
    lea     rcx, [g_vkey]
    lea     rdx, [r10 + FEDLINK.fl_key]
    mov     r8d, 32
    call    copy_bytes
    mov     dword ptr [g_reuse_key], 1        ; reuse g_vkey (skip Argon2)
    mov     r10, qword ptr [rbp-32]
    lea     rax, [r10 + FEDLINK.fl_loc]       ; g_cfg_in = foreign path
    mov     qword ptr [g_cfg_in], rax
    call    vault_unlock
    mov     dword ptr [rbp-44], eax           ; rc
    mov     dword ptr [g_reuse_key], 0
    cmp     dword ptr [rbp-44], 0
    jne     ffo_fail
    mov     ecx, dword ptr [rbp-40]           ; success: name the tab
    mov     r10, qword ptr [rbp-32]
    lea     rdx, [r10 + FEDLINK.fl_name]
    call    vault_ctx_setname
    mov     r10, qword ptr [rbp-32]           ; clear stale/missing
    and     dword ptr [r10 + FEDLINK.fl_flags], NOT (LINK_STALE or LINK_MISSING)
    jmp     ffo_next
ffo_fail:
    mov     r10, qword ptr [rbp-32]
    mov     eax, dword ptr [rbp-44]
    cmp     eax, EXIT_IO                       ; file gone -> MISSING, else STALE
    jne     @F
    or      dword ptr [r10 + FEDLINK.fl_flags], LINK_MISSING
    jmp     ffo_rollback
@@: or      dword ptr [r10 + FEDLINK.fl_flags], LINK_STALE
ffo_rollback:
    mov     eax, dword ptr [g_vault_n]         ; drop the claimed slot
    dec     eax
    mov     dword ptr [g_vault_n], eax
    mov     ecx, dword ptr [rbp-36]           ; restore the previous vault
    call    vault_ctx_front
ffo_next:
    inc     dword ptr [rbp-24]
    jmp     ffo_loop
ffo_done:
    xor     ecx, ecx                          ; front the master (slot 0)
    call    vault_ctx_front
    FRAME_EPILOG
    ret
fed_fanout endp

; fed_remember_open() - capture the currently-open set into the machine-local
;   federation record so the next launch's fan-out reopens it.  Rebuilds the
;   record from every open slot except the master (slot 0), keyed/sealed under
;   the master's key (slot 0's s_vkey).  An empty set deletes the record (no
;   federation, no provisioning).  Call when the open set changes (a foreign
;   vault opened or a tab closed).  slot 0 is assumed to be the master.
public fed_remember_open
fed_remember_open proc frame
    FRAME_PROLOG 64
    mov     eax, dword ptr [g_vault_cur]      ; snapshot live -> its slot (make all current)
    cmp     eax, 0
    jl      fro_build
    mov     ecx, eax
    call    vault_ctx_slotptr
    mov     rcx, rax
    call    vault_snapshot
fro_build:
    call    fed_reset
    mov     dword ptr [rbp-24], 1             ; i = 1 (slot 0 = master, skip)
fro_loop:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_vault_n]
    jae     fro_save
    mov     ecx, dword ptr [rbp-24]
    call    vault_ctx_slotptr
    mov     qword ptr [rbp-32], rax           ; &slot[i]
    lea     rcx, [rax + VSLOT.s_hdr + VH_SALT]  ; fl_id = SHA-256(slot salt)[0..15]
    lea     rdx, [g_fedlink_tmp + FEDLINK.fl_id]
    call    vault_id_hdr
    mov     r10, qword ptr [rbp-32]           ; fl_kcv = slot header KCV
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_kcv]
    lea     rdx, [r10 + VSLOT.s_hdr + VH_KCV]
    mov     r8d, 16
    call    copy_bytes
    mov     r10, qword ptr [rbp-32]           ; fl_key = slot's cached key
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_key]
    lea     rdx, [r10 + VSLOT.s_vkey]
    mov     r8d, 32
    call    copy_bytes
    mov     r10, qword ptr [rbp-32]           ; fl_loc = slot's file path
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_loc]
    lea     rdx, [r10 + VSLOT.s_vpath]
    mov     r8d, 512
    call    copy_bytes
    mov     r10, qword ptr [rbp-32]           ; fl_name = slot's display name
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_name]
    lea     rdx, [r10 + VSLOT.s_name]
    mov     r8d, 128
    call    copy_bytes
    mov     dword ptr [g_fedlink_tmp + FEDLINK.fl_flags], 0
    lea     rcx, [g_fedlink_tmp]
    call    fed_add
    inc     dword ptr [rbp-24]
    jmp     fro_loop
fro_save:
    cmp     dword ptr [g_fedrec + FEDREC.fr_count], 0
    jne     fro_dosave
    lea     rcx, [fed_valname]                ; empty set -> forget the record
    call    reg_fed_del
    FRAME_EPILOG
    ret
fro_dosave:
    xor     ecx, ecx                          ; master key = slot 0's s_vkey
    call    vault_ctx_slotptr
    lea     rcx, [rax + VSLOT.s_vkey]
    lea     rdx, [fms_key]
    lea     r8, [fms_val]
    call    fed_save_all
    FRAME_EPILOG
    ret
fed_remember_open endp

; cmd_fedfanout <path> - headless KAT: seed a real vault at <path>, link it with
;   its own key, fan out and assert it opens as a 2nd context; then corrupt the
;   cached key, fan out again, and assert the link is marked STALE and the slot
;   rolled back.  Exit 0 = pass.
LANDING_PAD
public cmd_fedfanout
cmd_fedfanout proc frame
    FRAME_PROLOG 48
    lea     r10, [g_argv]                     ; path = argv[2]
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [g_cfg_in], rax
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_loc]  ; copy path (dst) <- argv[2] (src)
    mov     rdx, rax
    mov     r8d, 512
    call    copy_bytes
    lea     r10, [ffk_seedpw]                  ; password = the fixed seed password
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
ffk_pw:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      ffk_pwd
    inc     ecx
    cmp     ecx, 32
    jb      ffk_pw
ffk_pwd:
    mov     dword ptr [g_cfg_passlen], 9
    mov     ecx, 3                             ; seed a small foreign vault
    call    do_seed
    test    eax, eax
    mov     eax, 2
    jnz     ffk_ret
    call    vk_derive                          ; re-derive the key (do_seed wipes g_vkey);
                                               ;   same password + the salt it left in g_hdr
    lea     rcx, [g_fedlink_tmp + FEDLINK.fl_key]   ; capture its key
    lea     rdx, [g_vkey]
    mov     r8d, 32
    call    copy_bytes
    mov     dword ptr [g_fedlink_tmp + FEDLINK.fl_flags], 0
    call    fed_reset                          ; record = this one link
    lea     rcx, [g_fedlink_tmp]
    call    fed_add
    call    vault_ctx_reset                    ; master = slot 0
    call    vault_ctx_open
    call    fed_fanout                          ; SUCCESS path
    cmp     dword ptr [g_vault_n], 2           ; master + foreign opened
    mov     eax, 3
    jne     ffk_ret
    xor     ecx, ecx
    call    fed_slot
    test    dword ptr [rax + FEDLINK.fl_flags], LINK_STALE or LINK_MISSING
    mov     eax, 4
    jnz     ffk_ret
    xor     ecx, ecx                           ; FAILURE path: corrupt the cached key
    call    fed_slot
    xor     byte ptr [rax + FEDLINK.fl_key], 0FFh
    mov     dword ptr [rax + FEDLINK.fl_flags], 0
    call    vault_ctx_reset
    call    vault_ctx_open
    call    fed_fanout
    cmp     dword ptr [g_vault_n], 1           ; rolled back to master only
    mov     eax, 5
    jne     ffk_ret
    xor     ecx, ecx
    call    fed_slot
    test    dword ptr [rax + FEDLINK.fl_flags], LINK_STALE
    mov     eax, 6
    jz      ffk_ret
    xor     eax, eax
ffk_ret:
    FRAME_EPILOG
    ret
cmd_fedfanout endp

; mvt_zero(rcx=ptr, edx=len) - zero a buffer (probe helper).  Leaf, volatile regs.
mvt_zero proc
    xor     r9d, r9d
mvz_lp:
    cmp     r9d, edx
    jae     mvz_done
    mov     byte ptr [rcx+r9], 0
    inc     r9d
    jmp     mvz_lp
mvz_done:
    ret
mvt_zero endp

; mv_plant(ecx = seed byte in cl) - stamp the live open-vault state with a value
;   derived only from the seed, across a byte array, both big arrays' head+tail,
;   and scalar qword/dword fields.  Leaf, volatile regs.  (probe helper)
mv_plant proc
    movzx   r8d, cl                         ; seed byte
    lea     r10, [g_vkey]
    xor     r9d, r9d
mpl_vk:
    cmp     r9d, 32
    jae     mpl_vkd
    mov     byte ptr [r10+r9], r8b
    inc     r9d
    jmp     mpl_vk
mpl_vkd:
    lea     r10, [g_newatt]
    mov     byte ptr [r10], r8b
    mov     byte ptr [r10 + MAX_ATT*32 - 1], r8b
    lea     r10, [g_attidx]
    mov     byte ptr [r10], r8b
    mov     byte ptr [r10 + MAX_ATT*32 - 1], r8b
    movzx   rax, cl                         ; replicate seed across all 8 bytes
    mov     rdx, rax
    shl     rdx, 8
    or      rax, rdx
    mov     rdx, rax
    shl     rdx, 16
    or      rax, rdx
    mov     rdx, rax
    shl     rdx, 32
    or      rax, rdx
    mov     qword ptr [g_body_ptr], rax
    mov     qword ptr [g_save_counter], rax
    mov     dword ptr [g_rollback], eax     ; low 32 bits = seed replicated 4x
    mov     word ptr [g_vpath], r8w         ; file-identity fields (per-ctx)
    mov     dword ptr [g_is_default], eax
    ret
mv_plant endp

; mv_check(ecx = seed byte in cl) -> eax = 0 match / 1 mismatch.  Verifies every
;   field mv_plant wrote still carries this seed.  Leaf, volatile regs.
mv_check proc
    movzx   r8d, cl
    lea     r10, [g_vkey]
    xor     r9d, r9d
mck_vk:
    cmp     r9d, 32
    jae     mck_vkd
    cmp     byte ptr [r10+r9], r8b
    jne     mck_bad
    inc     r9d
    jmp     mck_vk
mck_vkd:
    lea     r10, [g_newatt]
    cmp     byte ptr [r10], r8b
    jne     mck_bad
    cmp     byte ptr [r10 + MAX_ATT*32 - 1], r8b
    jne     mck_bad
    lea     r10, [g_attidx]
    cmp     byte ptr [r10], r8b
    jne     mck_bad
    cmp     byte ptr [r10 + MAX_ATT*32 - 1], r8b
    jne     mck_bad
    movzx   rax, cl
    mov     rdx, rax
    shl     rdx, 8
    or      rax, rdx
    mov     rdx, rax
    shl     rdx, 16
    or      rax, rdx
    mov     rdx, rax
    shl     rdx, 32
    or      rax, rdx
    cmp     qword ptr [g_body_ptr], rax
    jne     mck_bad
    cmp     qword ptr [g_save_counter], rax
    jne     mck_bad
    cmp     dword ptr [g_rollback], eax
    jne     mck_bad
    cmp     word ptr [g_vpath], r8w
    jne     mck_bad
    cmp     dword ptr [g_is_default], eax
    jne     mck_bad
    xor     eax, eax
    ret
mck_bad:
    mov     eax, 1
    ret
mv_check endp

; cmd_mvswitch - headless proof of the multi-vault context manager.  Opens two
;   vault contexts, plants a distinct seed in each, then fronts back and forth
;   and verifies each front restores exactly that vault's state (no cross-vault
;   bleed), plus that fronting an out-of-range index is rejected.  exit 0 = pass.
LANDING_PAD
public cmd_mvswitch
cmd_mvswitch proc frame
    FRAME_PROLOG 48
    call    vault_ctx_reset
    call    vault_ctx_open                  ; vault 0 (cur=0)
    mov     ecx, 05Ah
    call    mv_plant                        ; live = vault 0 state
    call    vault_ctx_open                  ; saves vault 0 -> slot0; vault 1 (cur=1)
    mov     ecx, 0B7h
    call    mv_plant                        ; live = vault 1 state
    xor     ecx, ecx                        ; front vault 0
    call    vault_ctx_front
    test    eax, eax
    jnz     mvs_fail
    mov     ecx, 05Ah
    call    mv_check                        ; must see vault 0's seed
    test    eax, eax
    jnz     mvs_fail
    mov     ecx, 1                          ; front vault 1
    call    vault_ctx_front
    test    eax, eax
    jnz     mvs_fail
    mov     ecx, 0B7h
    call    mv_check                        ; must see vault 1's seed
    test    eax, eax
    jnz     mvs_fail
    xor     ecx, ecx                        ; front vault 0 again
    call    vault_ctx_front
    test    eax, eax
    jnz     mvs_fail
    mov     ecx, 05Ah
    call    mv_check
    test    eax, eax
    jnz     mvs_fail
    mov     ecx, dword ptr [g_vault_n]      ; out-of-range front is rejected
    call    vault_ctx_front
    cmp     eax, 1
    jne     mvs_fail
    xor     eax, eax
    FRAME_EPILOG
    ret
mvs_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_mvswitch endp


; cmd_avtest - headless proof of the availability retry state machine (item 9).
;   Drives a single AVSLOT through the full unavailable->retry->give-up->manual-
;   unlock->available lifecycle with fixed "now" values and asserts every
;   transition (status, tries, next-deadline, due-ness).  exit 0 = pass.
LANDING_PAD
public cmd_avtest
cmd_avtest proc frame
    FRAME_PROLOG 48
    ; begin at now=0 -> RETRY, tries 0, next 5000
    lea     rcx, [g_avslot]
    xor     edx, edx
    call    vault_avail_begin
    cmp     dword ptr [g_avslot + AVSLOT.av_status], AVSTAT_RETRY
    jne     avt_fail
    cmp     dword ptr [g_avslot + AVSLOT.av_tries], 0
    jne     avt_fail
    cmp     qword ptr [g_avslot + AVSLOT.av_next], 5000
    jne     avt_fail
    ; not due before the deadline, due at it
    lea     rcx, [g_avslot]
    mov     edx, 4999
    call    vault_avail_due
    test    eax, eax
    jnz     avt_fail
    lea     rcx, [g_avslot]
    mov     edx, 5000
    call    vault_avail_due
    cmp     eax, 1
    jne     avt_fail
    ; first retry fails -> tries 1, next 10000, still RETRY
    lea     rcx, [g_avslot]
    mov     edx, 5000
    call    vault_avail_fail
    cmp     dword ptr [g_avslot + AVSLOT.av_tries], 1
    jne     avt_fail
    cmp     dword ptr [g_avslot + AVSLOT.av_status], AVSTAT_RETRY
    jne     avt_fail
    cmp     qword ptr [g_avslot + AVSLOT.av_next], 10000
    jne     avt_fail
    ; second retry fails -> tries 2, next 15000
    lea     rcx, [g_avslot]
    mov     edx, 10000
    call    vault_avail_due
    cmp     eax, 1
    jne     avt_fail
    lea     rcx, [g_avslot]
    mov     edx, 10000
    call    vault_avail_fail
    cmp     dword ptr [g_avslot + AVSLOT.av_tries], 2
    jne     avt_fail
    cmp     qword ptr [g_avslot + AVSLOT.av_next], 15000
    jne     avt_fail
    ; third retry fails -> tries 3 -> GAVEUP, no longer due
    lea     rcx, [g_avslot]
    mov     edx, 15000
    call    vault_avail_due
    cmp     eax, 1
    jne     avt_fail
    lea     rcx, [g_avslot]
    mov     edx, 15000
    call    vault_avail_fail
    cmp     dword ptr [g_avslot + AVSLOT.av_tries], 3
    jne     avt_fail
    cmp     dword ptr [g_avslot + AVSLOT.av_status], AVSTAT_GAVEUP
    jne     avt_fail
    lea     rcx, [g_avslot]
    mov     edx, 20000
    call    vault_avail_due
    test    eax, eax
    jnz     avt_fail
    ; manual unlock -> RETRY, tries 0, due immediately
    lea     rcx, [g_avslot]
    mov     edx, 20000
    call    vault_avail_unlock
    cmp     dword ptr [g_avslot + AVSLOT.av_status], AVSTAT_RETRY
    jne     avt_fail
    cmp     dword ptr [g_avslot + AVSLOT.av_tries], 0
    jne     avt_fail
    cmp     qword ptr [g_avslot + AVSLOT.av_next], 20000
    jne     avt_fail
    lea     rcx, [g_avslot]
    mov     edx, 20000
    call    vault_avail_due
    cmp     eax, 1
    jne     avt_fail
    ; success -> AVAIL, never due again
    lea     rcx, [g_avslot]
    call    vault_avail_ok
    cmp     dword ptr [g_avslot + AVSLOT.av_status], AVSTAT_AVAIL
    jne     avt_fail
    lea     rcx, [g_avslot]
    mov     edx, 99999
    call    vault_avail_due
    test    eax, eax
    jnz     avt_fail
    xor     eax, eax
    FRAME_EPILOG
    ret
avt_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_avtest endp

; cmd_bktest <path> - headless proof of atomic save + backup rotation (plan 37).
; cmd_bktest <path> - headless proof of atomic save + backup rotation.
;   Creates the vault BAK_GENS+1 times at the same path (fast KDF); each save
;   after the first rolls the live file into .bak1..N.  Then it asserts every
;   generation exists and re-opens .bak1 with the master password to prove a
;   rotated backup is a complete, valid vault.  exit 0 = pass.
; ===========================================================================
LANDING_PAD
public cmd_bktest
cmd_bktest proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=counter [rbp-32]=saved path [rbp-40]=unlock result
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]             ; argv[2] = vault path
    mov     qword ptr [g_cfg_in], rax
    lea     r10, [bk_pw]                        ; fixed test password
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
bk_pwcp:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      bk_pwd
    inc     ecx
    cmp     ecx, 32
    jb      bk_pwcp
bk_pwd:
    mov     dword ptr [g_cfg_passlen], 9
    mov     dword ptr [g_cfg_t], 1              ; fast KDF for the test
    mov     dword ptr [g_cfg_m], 8192
    mov     dword ptr [rbp-24], 0
bk_loop:
    call    do_init
    test    eax, eax
    jnz     bk_fail
    inc     dword ptr [rbp-24]
    cmp     dword ptr [rbp-24], BAK_GENS+1
    jb      bk_loop
    mov     dword ptr [rbp-24], 1               ; assert bak1..N exist
bk_chk:
    cmp     dword ptr [rbp-24], BAK_GENS
    ja      bk_open
    lea     rcx, [g_bak_a]
    mov     edx, dword ptr [rbp-24]
    add     edx, '0'
    call    vault_mkbak
    WINCALL GetFileAttributesW, addr g_bak_a
    cmp     eax, -1                             ; INVALID_FILE_ATTRIBUTES
    je      bk_fail
    inc     dword ptr [rbp-24]
    jmp     bk_chk
bk_open:
    mov     rax, qword ptr [g_cfg_in]           ; open bak1 to prove it is valid
    mov     qword ptr [rbp-32], rax
    lea     rcx, [g_bak_a]
    mov     dl, '1'
    call    vault_mkbak
    lea     rax, [g_bak_a]
    mov     qword ptr [g_cfg_in], rax
    call    vault_unlock
    mov     dword ptr [rbp-40], eax
    call    vault_lock
    mov     rax, qword ptr [rbp-32]             ; restore the real path
    mov     qword ptr [g_cfg_in], rax
    cmp     dword ptr [rbp-40], 0
    jne     bk_fail
    lea     rcx, [bk_ok]
    mov     edx, bk_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
bk_fail:
    lea     rcx, [bk_bad]
    mov     edx, bk_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_bktest endp

; ===========================================================================
; cmd_mactest <path> - prove the full-file MAC catches tampering the trailer
;  .  Create a vault, then flip a byte in the save-counter - a region
;   GCM does NOT authenticate - and confirm the unlock now fails; restore the
;   byte and confirm it opens again.  exit 0 = pass.
; ===========================================================================
LANDING_PAD
public cmd_mactest
cmd_mactest proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=filebuf [rbp-32]=filesize [rbp-40]=result
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [g_cfg_in], rax
    lea     r10, [bk_pw]
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
mt_pwcp:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      mt_pwd
    inc     ecx
    cmp     ecx, 32
    jb      mt_pwcp
mt_pwd:
    mov     dword ptr [g_cfg_passlen], 9
    mov     dword ptr [g_cfg_t], 1
    mov     dword ptr [g_cfg_m], 8192
    call    do_init
    test    eax, eax
    jnz     mt_fail
    ; read the freshly written file so we can tamper it on disk
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [rbp-24]
    lea     r8, [rbp-32]
    call    read_file
    test    eax, eax
    jnz     mt_fail
    ; flip a byte inside the save counter (offset = size - FMAC_TRAILER)
    mov     r10, qword ptr [rbp-24]
    add     r10, qword ptr [rbp-32]
    sub     r10, FMAC_TRAILER
    xor     byte ptr [r10], 0FFh
    mov     rcx, qword ptr [g_cfg_in]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    write_file
    call    vault_unlock                        ; must FAIL (MAC mismatch)
    mov     dword ptr [rbp-40], eax
    test    eax, eax
    jz      mt_leaked                           ; opened a tampered file -> MAC missed it
    ; restore the byte and confirm the vault opens again
    mov     r10, qword ptr [rbp-24]
    add     r10, qword ptr [rbp-32]
    sub     r10, FMAC_TRAILER
    xor     byte ptr [r10], 0FFh
    mov     rcx, qword ptr [g_cfg_in]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    write_file
    call    vault_unlock
    mov     dword ptr [rbp-40], eax
    call    vault_lock
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
    cmp     dword ptr [rbp-40], 0
    jne     mt_fail                             ; restored file must open
    lea     rcx, [mt_ok]
    mov     edx, mt_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
mt_leaked:
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
    lea     rcx, [mt_leak]
    mov     edx, mt_leak_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
mt_fail:
    lea     rcx, [mt_bad]
    mov     edx, mt_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_mactest endp

; ===========================================================================
; cmd_rbtest <path> - prove anti-rollback detection.  Create a vault
;   (counter 1, mirror 1), force the HKCU mirror ahead to 5, and confirm the
;   next unlock flags g_rollback; then set the mirror back to 1 and confirm a
;   fresh unlock does NOT flag it.  exit 0 = pass.
; ===========================================================================
LANDING_PAD
public cmd_rbtest
cmd_rbtest proc frame
    FRAME_PROLOG 48
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [g_cfg_in], rax
    lea     r10, [bk_pw]
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
rb_pwcp:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      rb_pwd
    inc     ecx
    cmp     ecx, 32
    jb      rb_pwcp
rb_pwd:
    mov     dword ptr [g_cfg_passlen], 9
    mov     dword ptr [g_cfg_t], 1
    mov     dword ptr [g_cfg_m], 8192
    call    do_init
    test    eax, eax
    jnz     rb_fail
    ; force the mirror ahead of the file's counter (simulate a later save)
    mov     qword ptr [g_ctr_io], 5
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_ctr_io]
    mov     r8d, 8
    call    reg_ctr_set
    call    vault_unlock                        ; must flag a rollback
    test    eax, eax
    jnz     rb_fail
    call    vault_lock
    cmp     dword ptr [g_rollback], 1
    jne     rb_fail
    ; restore the mirror to the file's counter -> no rollback
    mov     qword ptr [g_ctr_io], 1
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_ctr_io]
    mov     r8d, 8
    call    reg_ctr_set
    call    vault_unlock
    test    eax, eax
    jnz     rb_fail
    call    vault_lock
    cmp     dword ptr [g_rollback], 0
    jne     rb_fail
    lea     rcx, [rb_ok]
    mov     edx, rb_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
rb_fail:
    lea     rcx, [rb_bad]
    mov     edx, rb_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_rbtest endp

; ===========================================================================
; cmd_reload <path> - C8: prove vault_reload re-reads a vault changed on disk.
;   Seed a 3-entry vault, open it, delete one entry in memory (no save), then
;   vault_reload -> the in-memory count must return to 3 (the on-disk state).
; ===========================================================================
LANDING_PAD
public cmd_reload
cmd_reload proc frame
    FRAME_PROLOG 48
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]             ; argv[2] = vault path
    mov     qword ptr [g_cfg_in], rax
    lea     r10, [bk_pw]                        ; fixed test password
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
rl_pwcp:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      rl_pwd
    inc     ecx
    cmp     ecx, 32
    jb      rl_pwcp
rl_pwd:
    mov     dword ptr [g_cfg_passlen], 9
    mov     dword ptr [g_cfg_t], 1
    mov     dword ptr [g_cfg_m], 8192
    mov     ecx, 3                              ; create + seed 3 entries (seals + closes)
    call    do_seed
    test    eax, eax
    jnz     rl_fail
    call    vault_unlock                        ; open (fresh Argon2 derive)
    test    eax, eax
    jnz     rl_fail
    call    vault_count
    cmp     eax, 3
    jne     rl_faillk
    xor     ecx, ecx                            ; delete entry 0 in memory only (no reseal)
    call    vault_remove_at
    call    vault_count                         ; memory now 2, disk still 3
    cmp     eax, 2
    jne     rl_faillk
    call    vault_reload                        ; re-read disk with the existing key
    test    eax, eax
    jnz     rl_faillk
    call    vault_count                         ; memory back to 3
    cmp     eax, 3
    jne     rl_faillk
    call    vault_lock
    lea     rcx, [rl_ok]
    mov     edx, rl_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
rl_faillk:
    call    vault_lock
rl_fail:
    lea     rcx, [rl_bad]
    mov     edx, rl_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_reload endp

; ===========================================================================
; cmd_cowrite <path> - C8: prove the <vault>.lock write lock is exclusive and
;   reacquirable.  Acquire (must succeed), acquire again while held (must fail),
;   release, then re-acquire (must succeed).
; ===========================================================================
LANDING_PAD
public cmd_cowrite
cmd_cowrite proc frame
    FRAME_PROLOG 32
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]             ; argv[2] = a path (its ".lock" is used)
    mov     qword ptr [g_cfg_in], rax
    call    vault_lock_acquire                  ; 1) must acquire
    cmp     eax, 1
    jne     cw_fail
    call    vault_lock_acquire                  ; 2) held -> must fail (exclusive)
    test    eax, eax
    jnz     cw_faillk
    call    vault_lock_release                  ; 3) release
    call    vault_lock_acquire                  ; 4) must acquire again
    cmp     eax, 1
    jne     cw_fail
    call    vault_lock_release
    lea     rcx, [cw_ok]
    mov     edx, cw_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
cw_faillk:
    call    vault_lock_release
cw_fail:
    lea     rcx, [cw_bad]
    mov     edx, cw_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_cowrite endp

; ===========================================================================
; cmd_attfuzz - G8: hammer attach_index_build with a fully random attachment
;   section (seeded xorshift) and a random section length, asserting it never
;   crashes or reads past the section (the per-entry bounds added in the audit).
;   Analogous to vfuzz, but for the attachment index instead of the record parser.
; ===========================================================================
ATTFZ_LEN   equ 512
ATTFZ_ITERS equ 4000
LANDING_PAD
public cmd_attfuzz
cmd_attfuzz proc frame
    FRAME_PROLOG 48
    call    fuzz_seed                            ; G7: random (or --seed) + logged
    mov     qword ptr [g_vfz_rng], rax
    mov     rcx, ATTFZ_LEN
    call    mem_alloc
    test    rax, rax
    jz      af_oom
    mov     qword ptr [rbp-24], rax
    mov     qword ptr [g_filebuf], rax           ; attach_index_build reads g_filebuf+start
    mov     qword ptr [rbp-32], ATTFZ_ITERS
af_iter:
    cmp     qword ptr [rbp-32], 0
    je      af_pass
    mov     r11, qword ptr [rbp-24]              ; fill the section with random bytes
    xor     r8d, r8d
af_fill:
    call    vfz_rand
    mov     qword ptr [r11+r8], rax
    add     r8d, 8
    cmp     r8d, ATTFZ_LEN
    jb      af_fill
    call    vfz_rand                             ; random section length in [0, ATTFZ_LEN]
    xor     edx, edx
    mov     rcx, ATTFZ_LEN + 1
    div     rcx
    mov     qword ptr [g_att_start], 0
    mov     qword ptr [g_att_total], rdx
    mov     dword ptr [g_attidx_n], 0
    call    attach_index_build                   ; must not crash / read OOB
    dec     qword ptr [rbp-32]
    jmp     af_iter
af_pass:
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, ATTFZ_LEN
    call    mem_free
    mov     qword ptr [g_filebuf], 0
    lea     rcx, [af_ok]
    mov     edx, af_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
af_oom:
    lea     rcx, [af_bad]
    mov     edx, af_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_attfuzz endp

; ===========================================================================
; cmd_xctest <path> - prove external-change detection.  Create a vault
;   (snapshots itself), confirm no change is reported; externally flip a header
;   byte and confirm a change IS reported; recreate the vault (re-baselines) and
;   confirm no change again.  exit 0 = pass.
; ===========================================================================
LANDING_PAD
public cmd_xctest
cmd_xctest proc frame
    FRAME_PROLOG 48
    ; [rbp-24]=buf [rbp-32]=size
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [g_cfg_in], rax
    lea     r10, [bk_pw]
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
xc_pwcp:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      xc_pwd
    inc     ecx
    cmp     ecx, 32
    jb      xc_pwcp
xc_pwd:
    mov     dword ptr [g_cfg_passlen], 9
    mov     dword ptr [g_cfg_t], 1
    mov     dword ptr [g_cfg_m], 8192
    call    do_init                             ; creates + snapshots
    test    eax, eax
    jnz     xc_fail
    call    vault_ext_changed                   ; unchanged -> 0
    test    eax, eax
    jnz     xc_fail
    ; externally rewrite a header byte
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [rbp-24]
    lea     r8, [rbp-32]
    call    read_file
    test    eax, eax
    jnz     xc_fail
    mov     r10, qword ptr [rbp-24]
    xor     byte ptr [r10+10], 0FFh             ; flip a salt byte
    mov     rcx, qword ptr [g_cfg_in]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    write_file
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
    call    vault_ext_changed                   ; changed -> 1
    cmp     eax, 1
    jne     xc_fail
    call    do_init                             ; recreate -> re-baseline the snapshot
    test    eax, eax
    jnz     xc_fail
    call    vault_ext_changed                   ; unchanged again -> 0
    test    eax, eax
    jnz     xc_fail
    lea     rcx, [xc_ok]
    mov     edx, xc_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
xc_fail:
    lea     rcx, [xc_bad]
    mov     edx, xc_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_xctest endp


; ===========================================================================
; va_field_raw(rcx = type, rdx = src bytes, r8 = len) - append a TLV field with
;   raw utf8 bytes at g_body[g_body_len].  Fastfails on overflow.  -> eax = 1.
; ===========================================================================
va_field_raw proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx         ; type
    mov     qword ptr [rbp-32], rdx         ; src
    mov     qword ptr [rbp-40], r8          ; len
    mov     r10, qword ptr [g_body_len]
    add     r10, 6
    add     r10, r8
    cmp     r10, VAULT_BODY_MAX
    ja      vfr_of
    mov     r11, qword ptr [g_body_ptr]
    add     r11, qword ptr [g_body_len]
    mov     rax, qword ptr [rbp-24]
    mov     word ptr [r11], ax
    mov     rax, qword ptr [rbp-40]
    mov     dword ptr [r11+2], eax
    add     r11, 6
    mov     r9, qword ptr [rbp-32]
    xor     r8, r8
vfr_cp:
    cmp     r8, qword ptr [rbp-40]
    jae     vfr_done
    mov     al, byte ptr [r9+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    jmp     vfr_cp
vfr_done:
    mov     rax, qword ptr [g_body_len]
    add     rax, 6
    add     rax, qword ptr [rbp-40]
    mov     qword ptr [g_body_len], rax
    mov     eax, 1
    FRAME_EPILOG
    ret
vfr_of:
    FASTFAIL FF_BOUNDS
va_field_raw endp

; ===========================================================================
; va_field_bin_labeled(rcx = base type, rdx = label wide (0=none), r8 = raw
;   value ptr, r9 = raw value len) - append a TLV field whose value is raw bytes
;   (e.g. an encoded image), with an optional wide custom label.  Mirrors
;   va_field_labeled but does NOT wide->utf8 the value.  -> eax = 1.
; ===========================================================================
va_field_bin_labeled proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=type [rbp-32]=rawptr [rbp-40]=rawlen [rbp-48]=labellen
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], r8
    mov     qword ptr [rbp-40], r9
    xor     eax, eax
    mov     qword ptr [rbp-48], rax             ; labellen = 0 default
    test    rdx, rdx
    jz      vfb_write
    cmp     word ptr [rdx], 0                   ; empty label -> plain
    je      vfb_write
    mov     rcx, rdx
    lea     rdx, [g_convlabel]
    mov     r8d, MAX_LABEL_BYTES
    call    conv_w2u
    mov     ecx, eax
    mov     qword ptr [rbp-48], rcx
vfb_write:
    cmp     qword ptr [rbp-48], 0
    jne     vfb_labeled
    ; --- plain: {type, rawlen, rawbytes} ---
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    mov     r8,  qword ptr [rbp-40]
    call    va_field_raw
    mov     eax, 1
    FRAME_EPILOG
    ret
vfb_labeled:
    ; --- labeled: {type|VF_LABELED, 2+labellen+rawlen, u16 labellen|label|raw} ---
    mov     r9, qword ptr [rbp-48]
    add     r9, qword ptr [rbp-40]
    add     r9, 2
    mov     r10, qword ptr [g_body_len]
    add     r10, 6
    add     r10, r9
    cmp     r10, VAULT_BODY_MAX
    ja      vfb_of
    mov     r11, qword ptr [g_body_ptr]
    add     r11, qword ptr [g_body_len]
    mov     rax, qword ptr [rbp-24]
    or      eax, VF_LABELED
    mov     word ptr [r11], ax
    mov     eax, r9d
    mov     dword ptr [r11+2], eax
    add     r11, 6
    mov     eax, dword ptr [rbp-48]
    mov     word ptr [r11], ax                  ; u16 labellen
    add     r11, 2
    lea     r9, [g_convlabel]
    xor     r8, r8
vfb_lcopy:
    cmp     r8, qword ptr [rbp-48]
    jae     vfb_lcdone
    mov     al, byte ptr [r9+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    jmp     vfb_lcopy
vfb_lcdone:
    add     r11, qword ptr [rbp-48]
    mov     r9, qword ptr [rbp-32]              ; raw value bytes
    xor     r8, r8
vfb_vcopy:
    cmp     r8, qword ptr [rbp-40]
    jae     vfb_vcdone
    mov     al, byte ptr [r9+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    jmp     vfb_vcopy
vfb_vcdone:
    mov     rax, qword ptr [g_body_len]
    add     rax, 6
    mov     r9, qword ptr [rbp-48]
    add     r9, qword ptr [rbp-40]
    add     r9, 2
    add     rax, r9
    mov     qword ptr [g_body_len], rax
    mov     eax, 1
    FRAME_EPILOG
    ret
vfb_of:
    FASTFAIL FF_BOUNDS
va_field_bin_labeled endp




; ===========================================================================
; vault_selftest() -> eax = 0 on success, 1 on failure.
; In-memory KAT for the vault crypto composition (Argon2id KDF -> KCV ->
; AES-256-GCM seal/open with the header as AAD).  Uses tiny KDF params so the
; per-run startup gate stays fast.  Run on every launch (selftest.asm).
; ===========================================================================
public vault_selftest
vault_selftest proc frame
    FRAME_PROLOG 48
    ; master password = "pw"
    lea     r10, [g_cfg_pass]
    mov     byte ptr [r10], 'p'
    mov     byte ptr [r10+1], 'w'
    mov     dword ptr [g_cfg_passlen], 2
    ; header with tiny KDF params and deterministic (zero) salt/nonce
    mov     dword ptr [g_hdr+0], VAULT_MAGIC
    mov     dword ptr [g_hdr+4], VAULT_VERSION
    mov     dword ptr [g_hdr+VH_T], 1
    mov     dword ptr [g_hdr+VH_M], 8
    mov     dword ptr [g_hdr+VH_LANES], 1
    lea     r9, [g_hdr+VH_SALT]
    xor     r8, r8
vst_z:
    mov     byte ptr [r9+r8], 0
    inc     r8
    cmp     r8, 44                          ; 32 salt + 12 nonce
    jb      vst_z
    call    vk_derive
    test    eax, eax
    jnz     vst_fail
    call    vk_kcv
    lea     r10, [g_sha32]
    lea     r9, [g_hdr+VH_KCV]
    xor     r8, r8
vst_k:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r9+r8], al
    inc     r8
    cmp     r8, KCV_LEN
    jb      vst_k
    ; seal vst_src (16 bytes) -> vst_ct + vst_tag
    lea     r10, [g_greq]
    lea     rax, [g_vkey]
    mov     qword ptr [r10].GCMREQ.key, rax
    lea     rax, [g_hdr+VH_NONCE]
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_hdr]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, VH_TOTAL
    lea     rax, [vst_src]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     qword ptr [r10].GCMREQ.inlen, 16
    lea     rax, [vst_ct]
    mov     qword ptr [r10].GCMREQ.outp, rax
    lea     rax, [vst_tag]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_greq]
    call    gcm_seal
    ; open vst_ct -> vst_dec, must authenticate and match
    lea     r10, [g_greq]
    lea     rax, [vst_ct]
    mov     qword ptr [r10].GCMREQ.inp, rax
    lea     rax, [vst_dec]
    mov     qword ptr [r10].GCMREQ.outp, rax
    lea     rcx, [g_greq]
    call    gcm_open
    test    eax, eax
    jnz     vst_fail
    lea     rcx, [vst_dec]
    lea     rdx, [vst_src]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     vst_fail
    call    vault_field_selftest            ; TLV labeled/duplicate-field roundtrip
    test    eax, eax
    jnz     vst_fail
    call    attach_selftest                 ; per-attachment seal/open + AAD binding
    test    eax, eax
    jnz     vst_fail
    xor     eax, eax
    FRAME_EPILOG
    ret
vst_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
vault_selftest endp

; ===========================================================================
; vault_field_selftest() -> eax = 0 ok / 1 fail.  Builds an entry with a plain
; title, a plain URL, a *labelled* duplicate URL, and a *labelled custom* TEXT
; field via vault_build_entry, then reads it back: positional decode
; (vault_field_get) and by-kind lookup with label-skip (find_field_in).
; Uses a private scratch body so it runs before any vault is unlocked.
; ===========================================================================
public vault_field_selftest
vault_field_selftest proc frame
    FRAME_PROLOG 96
    ; point the body at the KAT scratch, entry_count = 0
    lea     rax, [g_kat_body]
    mov     qword ptr [g_body_ptr], rax
    mov     dword ptr [rax], 0
    mov     qword ptr [g_body_len], 4
    ; compose g_field_list: title / url1 / (Work)url2 / (PIN)text
    lea     r10, [g_field_list]
    mov     qword ptr [r10+0], VF_TITLE
    mov     qword ptr [r10+8], 0
    lea     rax, [kat_title]
    mov     qword ptr [r10+16], rax
    mov     qword ptr [r10+24], VF_URL
    mov     qword ptr [r10+32], 0
    lea     rax, [kat_url1]
    mov     qword ptr [r10+40], rax
    mov     qword ptr [r10+48], VF_URL
    lea     rax, [kat_work]
    mov     qword ptr [r10+56], rax
    lea     rax, [kat_url2]
    mov     qword ptr [r10+64], rax
    mov     qword ptr [r10+72], VF_TEXT
    lea     rax, [kat_pinlbl]
    mov     qword ptr [r10+80], rax
    lea     rax, [kat_pinval]
    mov     qword ptr [r10+88], rax
    mov     qword ptr [r10+96], VF_IMAGE or VFL_RAW   ; raw binary value field
    mov     qword ptr [r10+104], 0              ; no label
    lea     rax, [kat_img]
    mov     qword ptr [r10+112], rax            ; -> {u32 len, bytes}
    mov     dword ptr [g_field_n], 5
    call    vault_build_entry
    test    eax, eax
    jnz     vfst_fail
    ; field count == 5
    xor     ecx, ecx
    call    vault_field_count
    cmp     eax, 5
    jne     vfst_fail
    ; find_field_in(VF_TEXT) must skip the "PIN" label and return "1234"
    lea     rcx, [g_kat_body+4]
    mov     edx, VF_TEXT
    call    find_field_in
    cmp     rdx, 4
    jne     vfst_fail
    mov     rcx, rax
    lea     rdx, [kat_exp_pin]
    mov     r8, 4
    call    ct_memcmp
    test    eax, eax
    jnz     vfst_fail
    ; find_field_in(VF_URL) returns the FIRST (plain) url = "a.com"
    lea     rcx, [g_kat_body+4]
    mov     edx, VF_URL
    call    find_field_in
    cmp     rdx, 5
    jne     vfst_fail
    mov     rcx, rax
    lea     rdx, [kat_exp_url1]
    mov     r8, 5
    call    ct_memcmp
    test    eax, eax
    jnz     vfst_fail
    ; positional: field 2 is the labelled URL (kind VF_URL, labellen 4)
    xor     ecx, ecx
    mov     edx, 2
    lea     r8, [rbp-48]
    call    vault_field_get
    test    eax, eax
    jz      vfst_fail
    cmp     qword ptr [rbp-48], VF_URL
    jne     vfst_fail
    cmp     qword ptr [rbp-32], 4               ; out.labellen (= [rbp-48+16])
    jne     vfst_fail
    ; vault_field_at(0, VF_TITLE) must also find the title (ptr != 0, len 4)
    xor     ecx, ecx
    mov     edx, VF_TITLE
    lea     r8, [rbp-56]
    call    vault_field_at
    test    rax, rax
    jz      vfst_fail
    cmp     qword ptr [rbp-56], 4
    jne     vfst_fail
    mov     al, byte ptr [rax]                  ; first byte must be 'A'
    cmp     al, 'A'
    jne     vfst_fail
    ; positional field 4 = VF_IMAGE: 7 raw bytes (incl NUL) round-trip verbatim
    xor     ecx, ecx
    mov     edx, 4
    lea     r8, [rbp-48]
    call    vault_field_get
    test    eax, eax
    jz      vfst_fail
    cmp     qword ptr [rbp-48], VF_IMAGE        ; out.kind
    jne     vfst_fail
    cmp     qword ptr [rbp-16], 7               ; out.vallen (= [rbp-48+32])
    jne     vfst_fail
    mov     rcx, qword ptr [rbp-24]             ; out.valptr (= [rbp-48+24])
    lea     rdx, [kat_exp_img]
    mov     r8, 7
    call    ct_memcmp
    test    eax, eax
    jnz     vfst_fail
    xor     eax, eax
    jmp     vfst_done
vfst_fail:
    mov     eax, 1
vfst_done:
    mov     qword ptr [g_body_ptr], 0           ; leave globals clean for the real unlock
    mov     qword ptr [g_body_len], 0
    mov     dword ptr [g_field_n], 0
    FRAME_EPILOG
    ret
vault_field_selftest endp

; ===========================================================================
; GUI session API.  The GUI unlocks the vault ONCE (key in g_vkey, body in
; secmem), then reads entries and mutates the in-memory body, re-sealing to
; disk without re-deriving the master key.  All of these assume the vault is
; already unlocked (vault_unlock succeeded) unless noted.
; ===========================================================================

; ===========================================================================
; C8: <vault>.lock advisory write lock.  Held only around a save so a vault on a
;   shared drive has at most one writer at a time.  FILE_FLAG_DELETE_ON_CLOSE
;   makes a crashed holder's lock vanish when the OS closes the handle; an
;   orphaned lock (file left but no holder) is reclaimed by DeleteFileW-then-retry,
;   which fails on a live-held lock so it can never steal an active one.
; ===========================================================================
LK_GENERIC_WRITE  equ 40010000h              ; GENERIC_WRITE | DELETE (delete-on-close)
LK_CREATE_NEW     equ 1
LK_DELONCLOSE     equ 04000000h              ; FILE_FLAG_DELETE_ON_CLOSE

; vault_lock_acquire() -> eax = 1 if <vault>.lock is now held (g_lock_h), else 0.
vault_lock_acquire proc frame
    FRAME_PROLOG 64
    mov     r10, qword ptr [g_cfg_in]           ; g_lock_path = g_cfg_in + ".lock"
    lea     r11, [g_lock_path]
    xor     ecx, ecx
lka_cp:
    mov     ax, word ptr [r10+rcx*2]
    mov     word ptr [r11+rcx*2], ax
    test    ax, ax
    jz      lka_cpd
    inc     ecx
    cmp     ecx, MAX_PATH_CHARS
    jb      lka_cp
lka_cpd:
    lea     r11, [g_lock_path]
    lea     r11, [r11+rcx*2]                    ; at the NUL
    mov     word ptr [r11+0], '.'
    mov     word ptr [r11+2], 'l'
    mov     word ptr [r11+4], 'o'
    mov     word ptr [r11+6], 'c'
    mov     word ptr [r11+8], 'k'
    mov     word ptr [r11+10], 0
    WINCALL CreateFileW, addr g_lock_path, LK_GENERIC_WRITE, 0, 0, LK_CREATE_NEW, LK_DELONCLOSE, 0
    cmp     rax, -1
    jne     lka_got
    WINCALL DeleteFileW, addr g_lock_path       ; reclaim an orphan (fails if live-held)
    WINCALL CreateFileW, addr g_lock_path, LK_GENERIC_WRITE, 0, 0, LK_CREATE_NEW, LK_DELONCLOSE, 0
    cmp     rax, -1
    je      lka_busy
lka_got:
    mov     qword ptr [g_lock_h], rax
    mov     eax, 1
    FRAME_EPILOG
    ret
lka_busy:
    xor     eax, eax                            ; failed - leave g_lock_h untouched
    FRAME_EPILOG                                ; (never clobber an already-held handle)
    ret
vault_lock_acquire endp

; vault_lock_release() - close the lock handle (DELETE_ON_CLOSE removes the file).
public vault_lock_release
vault_lock_release proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [g_lock_h]
    test    rcx, rcx
    jz      lkr_done
    WINCALL CloseHandle, qword ptr [g_lock_h]
    mov     qword ptr [g_lock_h], 0
lkr_done:
    FRAME_EPILOG
    ret
vault_lock_release endp

; vault_reseal() - persist the current in-memory body to disk under a fresh GCM
;   nonce (key/salt unchanged).  C8: serialized by the <vault>.lock write lock,
;   and refuses to overwrite a vault another writer changed since we loaded it.
;   -> eax = 0 / EXIT_OOM / EXIT_CHANGED (reload-safe) / EXIT_BUSY (locked).
public vault_reseal
vault_reseal proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_readonly], 0           ; E9: a read-only vault never writes to
    jne     vrs_ro                              ; disk - report success, change nothing
    call    vault_lock_acquire                  ; C8: brief exclusive write lock
    test    eax, eax
    jz      vrs_busy                            ; another instance is saving
    call    vault_ext_changed                   ; C8: changed under us since load?
    test    eax, eax
    jnz     vrs_changed                         ; yes -> do not clobber (reload-safe)
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      vrs_oom
    call    vault_seal_write                    ; re-snapshots the file on success
    mov     dword ptr [rbp-24], eax
    call    vault_lock_release
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
vrs_changed:
    call    vault_lock_release
    mov     eax, EXIT_CHANGED
    FRAME_EPILOG
    ret
vrs_oom:
    call    vault_lock_release
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
vrs_busy:
    mov     eax, EXIT_BUSY
    FRAME_EPILOG
    ret
vrs_ro:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_reseal endp

; vault_count() -> eax = number of entries (0 if locked).  Leaf.
public vault_count
vault_count proc
    mov     rax, qword ptr [g_body_ptr]
    test    rax, rax
    jz      vc_zero
    mov     eax, dword ptr [rax]
    ret
vc_zero:
    xor     eax, eax
    ret
vault_count endp

; vault_entry_ptr(rcx = index) -> rax = pointer to that entry (0 if out of range)
public vault_entry_ptr
vault_entry_ptr proc frame
    FRAME_PROLOG 48
    ; [rbp-24] = remaining index, [rbp-32] = cursor
    mov     r10, qword ptr [g_body_ptr]
    test    r10, r10
    jz      vep_none
    mov     eax, dword ptr [r10]
    cmp     rcx, rax
    jae     vep_none
    mov     qword ptr [rbp-24], rcx
    lea     r10, [r10+4]
    mov     qword ptr [rbp-32], r10
vep_loop:
    cmp     qword ptr [rbp-24], 0
    je      vep_done
    mov     rcx, qword ptr [rbp-32]
    call    vault_entry_len
    mov     r10, qword ptr [rbp-32]
    add     r10, rax
    mov     qword ptr [rbp-32], r10
    dec     qword ptr [rbp-24]
    jmp     vep_loop
vep_done:
    mov     rax, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
vep_none:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_entry_ptr endp

; vault_title_at(rcx = index, rdx = *outlen) -> rax = title bytes ptr (0 if none)
public vault_title_at
vault_title_at proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rdx     ; outlen ptr
    call    vault_entry_ptr             ; rcx = index
    test    rax, rax
    jz      vta_none
    mov     rcx, rax
    mov     edx, VF_TITLE
    call    find_field_in               ; rax=ptr, rdx=len
    test    rax, rax
    jz      vta_none
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [r10], rdx
    FRAME_EPILOG
    ret
vta_none:
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [r10], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_title_at endp

; vault_field_at(rcx = index, edx = field type, r8 = *outlen) -> rax = ptr (0 none)
public vault_field_at
vault_field_at proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], r8      ; outlen ptr
    mov     dword ptr [rbp-32], edx     ; type
    call    vault_entry_ptr             ; rcx = index
    test    rax, rax
    jz      vfa_none
    mov     rcx, rax
    mov     edx, dword ptr [rbp-32]
    call    find_field_in
    test    rax, rax
    jz      vfa_none
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [r10], rdx
    FRAME_EPILOG
    ret
vfa_none:
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [r10], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_field_at endp

; ===========================================================================
; E6 vault-health analysis.  Thresholds are fixed (independent of vault policy)
; so headless health counts are deterministic and self-describing.
; ===========================================================================
HEALTH_MINLEN     equ 12                          ; code points
HEALTH_MINCLASS   equ 3                            ; distinct character classes
HEALTH_OLD_100NS  equ 365 * 86400 * 10000000       ; 365 days in FILETIME ticks
HDIG              equ 16                            ; BLAKE2b digest bytes / entry
HSTRIDE           equ 17                            ; {digest16, haspw1} per entry

; vh_pw_weak(rcx = utf8 bytes, edx = len) -> eax = 1 if the password is weak.
;   Weak = fewer than HEALTH_MINLEN bytes, or fewer than HEALTH_MINCLASS of
;   {lower, upper, digit, other} present.  (Byte length over-counts multi-byte
;   UTF-8, which only makes a password look stronger - never falsely weak.)
public vh_pw_weak
vh_pw_weak proc frame
    FRAME_PROLOG 32
    xor     r10d, r10d                  ; class bitmask
    xor     r9d, r9d                    ; index
    mov     r11d, edx                   ; len
vw_lp:
    cmp     r9d, r11d
    jae     vw_eval
    movzx   eax, byte ptr [rcx+r9]
    cmp     eax, 'a'
    jb      vw_c1
    cmp     eax, 'z'
    ja      vw_c1
    or      r10d, 1
    jmp     vw_adv
vw_c1:
    cmp     eax, 'A'
    jb      vw_c2
    cmp     eax, 'Z'
    ja      vw_c2
    or      r10d, 2
    jmp     vw_adv
vw_c2:
    cmp     eax, '0'
    jb      vw_c3
    cmp     eax, '9'
    ja      vw_c3
    or      r10d, 4
    jmp     vw_adv
vw_c3:
    or      r10d, 8                     ; symbol / non-ASCII
vw_adv:
    inc     r9d
    jmp     vw_lp
vw_eval:
    cmp     r11d, HEALTH_MINLEN
    jb      vw_weak
    ; class count = popcount of the low nibble of r10d (0..4), computed by hand
    mov     eax, r10d
    and     eax, 1
    mov     r8d, r10d
    shr     r8d, 1
    and     r8d, 1
    add     eax, r8d
    mov     r8d, r10d
    shr     r8d, 2
    and     r8d, 1
    add     eax, r8d
    mov     r8d, r10d
    shr     r8d, 3
    and     r8d, 1
    add     eax, r8d
    cmp     eax, HEALTH_MINCLASS
    jb      vw_weak
    xor     eax, eax
    FRAME_EPILOG
    ret
vw_weak:
    mov     eax, 1
    FRAME_EPILOG
    ret
vh_pw_weak endp

; vault_health(rcx = out) - fill four dwords at [out]: {weak, reused, old,
;   total}.  reused = entries whose VF_SECRET is byte-identical (BLAKE2b-128)
;   to some other entry's; old = modified more than HEALTH_OLD_100NS ago.
;   Entries with no password count toward total only.  Requires an unlocked
;   body; if the scratch allocation fails the dup pass is skipped (reused = 0).
public vault_health
vault_health proc frame
    FRAME_PROLOG 128
    ; [rbp-24]=out [rbp-32]=n [rbp-40]=scratch [rbp-48]=i [rbp-56]=len
    ; [rbp-64]=weak [rbp-72]=old [rbp-80]=now [rbp-88]=reused [rbp-96]=j
    ; [rbp-104]=pw ptr
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rcx+0], 0
    mov     dword ptr [rcx+4], 0
    mov     dword ptr [rcx+8], 0
    mov     dword ptr [rcx+12], 0
    mov     dword ptr [rbp-64], 0
    mov     dword ptr [rbp-72], 0
    mov     dword ptr [rbp-88], 0
    call    vault_count
    mov     dword ptr [rbp-32], eax
    mov     r10, qword ptr [rbp-24]
    mov     dword ptr [r10+12], eax             ; total
    test    eax, eax
    jz      vh_done
    mov     ecx, dword ptr [rbp-32]
    imul    rcx, rcx, HSTRIDE
    call    mem_alloc
    mov     qword ptr [rbp-40], rax             ; 0 => dup pass disabled
    lea     rcx, [g_ts]
    call    GetSystemTimeAsFileTime
    mov     rax, qword ptr [g_ts]
    mov     qword ptr [rbp-80], rax             ; now
    mov     dword ptr [rbp-48], 0               ; i
vh_loop:
    mov     eax, dword ptr [rbp-48]
    cmp     eax, dword ptr [rbp-32]
    jae     vh_dups
    ; default haspw = 0
    mov     rax, qword ptr [rbp-40]
    test    rax, rax
    jz      vh_pw
    mov     ecx, dword ptr [rbp-48]
    imul    rcx, rcx, HSTRIDE
    mov     byte ptr [rax+rcx+16], 0
vh_pw:
    mov     ecx, dword ptr [rbp-48]
    mov     edx, VF_SECRET
    lea     r8, [rbp-56]
    call    vault_field_at                      ; rax=ptr, [rbp-56]=len
    test    rax, rax
    jz      vh_next                             ; no password
    mov     qword ptr [rbp-104], rax
    mov     rcx, rax
    mov     edx, dword ptr [rbp-56]
    call    vh_pw_weak
    test    eax, eax
    jz      vh_old
    inc     dword ptr [rbp-64]
vh_old:
    mov     ecx, dword ptr [rbp-48]
    call    vault_entry_ptr
    test    rax, rax
    jz      vh_hash
    mov     rdx, qword ptr [rbp-80]             ; now
    sub     rdx, qword ptr [rax+24]             ; now - modified
    js      vh_hash                             ; future timestamp -> not old
    mov     r8, HEALTH_OLD_100NS                ; 64-bit: can't be a cmp immediate
    cmp     rdx, r8
    jbe     vh_hash
    inc     dword ptr [rbp-72]
vh_hash:
    mov     rax, qword ptr [rbp-40]
    test    rax, rax
    jz      vh_next
    mov     ecx, dword ptr [rbp-48]
    imul    rcx, rcx, HSTRIDE
    lea     r8, [rax+rcx]                       ; digest dest
    mov     byte ptr [r8+16], 1                 ; haspw
    mov     rcx, qword ptr [rbp-104]
    mov     edx, dword ptr [rbp-56]
    mov     r9, HDIG
    call    blake2b_hash
vh_next:
    inc     dword ptr [rbp-48]
    jmp     vh_loop
vh_dups:
    mov     rax, qword ptr [rbp-40]
    test    rax, rax
    jz      vh_store                            ; no scratch -> reused = 0
    mov     dword ptr [rbp-48], 0               ; i
vh_di:
    mov     eax, dword ptr [rbp-48]
    cmp     eax, dword ptr [rbp-32]
    jae     vh_store
    mov     r10, qword ptr [rbp-40]
    mov     ecx, dword ptr [rbp-48]
    imul    rcx, rcx, HSTRIDE
    cmp     byte ptr [r10+rcx+16], 0
    je      vh_di_next
    mov     dword ptr [rbp-96], 0               ; j
vh_dj:
    mov     eax, dword ptr [rbp-96]
    cmp     eax, dword ptr [rbp-32]
    jae     vh_di_next                          ; no partner found
    cmp     eax, dword ptr [rbp-48]
    je      vh_dj_next
    mov     r10, qword ptr [rbp-40]
    mov     ecx, dword ptr [rbp-96]
    imul    rcx, rcx, HSTRIDE
    cmp     byte ptr [r10+rcx+16], 0
    je      vh_dj_next
    mov     r8, qword ptr [rbp-40]
    mov     eax, dword ptr [rbp-48]
    imul    rax, rax, HSTRIDE
    lea     r10, [r8+rax]                       ; digest[i]
    mov     eax, dword ptr [rbp-96]
    imul    rax, rax, HSTRIDE
    lea     r11, [r8+rax]                       ; digest[j]
    mov     rax, qword ptr [r10]
    cmp     rax, qword ptr [r11]
    jne     vh_dj_next
    mov     rax, qword ptr [r10+8]
    cmp     rax, qword ptr [r11+8]
    jne     vh_dj_next
    inc     dword ptr [rbp-88]                  ; entry i is reused
    jmp     vh_di_next
vh_dj_next:
    inc     dword ptr [rbp-96]
    jmp     vh_dj
vh_di_next:
    inc     dword ptr [rbp-48]
    jmp     vh_di
vh_store:
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [rbp-64]
    mov     dword ptr [r10+0], eax              ; weak
    mov     eax, dword ptr [rbp-88]
    mov     dword ptr [r10+4], eax              ; reused
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [r10+8], eax              ; old
    mov     rcx, qword ptr [rbp-40]
    test    rcx, rcx
    jz      vh_done
    ; wipe the scratch before releasing it: it holds unsalted BLAKE2b-128
    ; fingerprints of every password, which must not linger in freed pages.
    mov     eax, dword ptr [rbp-32]             ; n
    imul    rax, rax, HSTRIDE
    mov     rdx, rax                            ; mem_free wipes rdx bytes
    call    mem_free
vh_done:
    FRAME_EPILOG
    ret
vault_health endp

; vault_entry_stale(rcx = index) -> eax = 1 if that entry was modified more than
;   HEALTH_OLD_100NS ago (same "old" rule as vault_health), else 0.  Used by the
;   sidebar to tint a tile's health dot amber.  Requires an unlocked body.
public vault_entry_stale
vault_entry_stale proc frame
    FRAME_PROLOG 48
    call    vault_entry_ptr                     ; rcx = index -> rax = entry ptr
    test    rax, rax
    jz      ves_no
    mov     qword ptr [rbp-24], rax
    lea     rcx, [g_ts]
    call    GetSystemTimeAsFileTime
    mov     rax, qword ptr [g_ts]               ; now
    mov     r10, qword ptr [rbp-24]
    sub     rax, qword ptr [r10+24]             ; now - modified
    js      ves_no                              ; future timestamp -> not stale
    mov     r8, HEALTH_OLD_100NS
    cmp     rax, r8
    jbe     ves_no
    mov     eax, 1
    FRAME_EPILOG
    ret
ves_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_entry_stale endp

; ===========================================================================
; cmd_healthkat - E6 known-answer test for vault_health.  Points g_body_ptr at
;   a hand-built 10-entry fixture with a known health profile, runs the
;   analysis, and asserts the four counts.  No vault file, no unlock: the
;   fixture is a raw body image, exactly the layout the trusting accessors
;   expect.  exit 0 = counts match, 1 = mismatch.
;
;   Fixture profile:
;     e0 "abc"                old,  weak(len),   dup with e9
;     e1 "Password1!"         new,  weak(len)
;     e2 "Str0ng#Password9"   new,  strong,      dup with e3
;     e3 "Str0ng#Password9"   new,  strong,      dup with e2
;     e4 "reused-pass-000"    new,  strong,      dup with e5
;     e5 "reused-pass-000"    new,  strong,      dup with e4
;     e6 "aaaaaaaaaaaaaaaa"   new,  weak(1 class)
;     e7 (title only, no pw)  new,  -            counted in total only
;     e8 "Zx9$Qw7!Lp2@"       old,  strong
;     e9 "abc"                new,  weak(len),   dup with e0
;   => weak=4  reused=6  old=2  total=10
; ===========================================================================
.data
align 8
hk_body:
    dd  10                                   ; entry_count
    ; --- e0 "abc" (old) -----------------------------------------------------
    db  16 dup(0)
    dq  0                                     ; created
    dq  0                                     ; modified (old)
    dd  1
    dw  VF_SECRET
    dd  3
    db  "abc"
    ; --- e1 "Password1!" (new) ---------------------------------------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_SECRET
    dd  10
    db  "Password1!"
    ; --- e2 "Str0ng#Password9" (new) ---------------------------------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_SECRET
    dd  16
    db  "Str0ng#Password9"
    ; --- e3 "Str0ng#Password9" (new, dup of e2) ----------------------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_SECRET
    dd  16
    db  "Str0ng#Password9"
    ; --- e4 "reused-pass-000" (new) ----------------------------------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_SECRET
    dd  15
    db  "reused-pass-000"
    ; --- e5 "reused-pass-000" (new, dup of e4) -----------------------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_SECRET
    dd  15
    db  "reused-pass-000"
    ; --- e6 "aaaaaaaaaaaaaaaa" (new, single class) -------------------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_SECRET
    dd  16
    db  "aaaaaaaaaaaaaaaa"
    ; --- e7 title only, no password (new) ----------------------------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_TITLE
    dd  4
    db  "note"
    ; --- e8 "Zx9$Qw7!Lp2@" (old, strong) -----------------------------------
    db  16 dup(0)
    dq  0
    dq  0
    dd  1
    dw  VF_SECRET
    dd  12
    db  "Zx9$Qw7!Lp2@"
    ; --- e9 "abc" (new, dup of e0) -----------------------------------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_SECRET
    dd  3
    db  "abc"
.code

LANDING_PAD
public cmd_healthkat
cmd_healthkat proc frame
    FRAME_PROLOG 80
    ; [rbp-24] saved g_body_ptr ; [rbp-48..-33] health {weak,reused,old,total}
    ; [rbp-56]=vault_entry_stale(0) [rbp-64]=vault_entry_stale(1)
    mov     rax, qword ptr [g_body_ptr]
    mov     qword ptr [rbp-24], rax
    lea     rax, [hk_body]
    mov     qword ptr [g_body_ptr], rax
    lea     rcx, [rbp-48]
    call    vault_health
    ; per-entry stale probe while the fixture body is still mounted: e0 is old
    ; (modified=0), e1 is recent (modified=max).
    xor     ecx, ecx
    call    vault_entry_stale
    mov     dword ptr [rbp-56], eax
    mov     ecx, 1
    call    vault_entry_stale
    mov     dword ptr [rbp-64], eax
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [g_body_ptr], rax         ; restore before any assert exit
    cmp     dword ptr [rbp-48], 4               ; weak
    jne     hk_fail
    cmp     dword ptr [rbp-44], 6               ; reused
    jne     hk_fail
    cmp     dword ptr [rbp-40], 2               ; old
    jne     hk_fail
    cmp     dword ptr [rbp-36], 10              ; total
    jne     hk_fail
    cmp     dword ptr [rbp-56], 1               ; e0 stale
    jne     hk_fail
    cmp     dword ptr [rbp-64], 0               ; e1 not stale
    jne     hk_fail
    xor     eax, eax
    FRAME_EPILOG
    ret
hk_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_healthkat endp


; ===========================================================================
; va_field_labeled(rcx = base type, rdx = label wide ptr (0/empty = none),
;   r8 = value wide ptr) - append one TLV field at g_body[g_body_len], writing
;   a custom-label prefix (and the VF_LABELED flag) when a non-empty label is
;   supplied.  Empty values ARE persisted (composition is preserved).  -> eax=1.
; ===========================================================================
va_field_labeled proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=type [rbp-32]=labellen [rbp-40]=vallen [rbp-48]=valwide [rbp-56]=lblwide
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-56], rdx
    mov     qword ptr [rbp-48], r8
    xor     eax, eax
    mov     qword ptr [rbp-40], rax             ; vallen = 0 default
    test    r8, r8
    jz      vfl_lbl
    mov     rcx, r8
    lea     rdx, [g_conv]
    mov     r8d, CONV_CAP
    call    conv_w2u
    mov     ecx, eax
    mov     qword ptr [rbp-40], rcx
vfl_lbl:
    xor     eax, eax
    mov     qword ptr [rbp-32], rax             ; labellen = 0 default
    mov     r10, qword ptr [rbp-56]
    test    r10, r10
    jz      vfl_write
    cmp     word ptr [r10], 0                   ; empty label -> treat as plain
    je      vfl_write
    mov     rcx, r10
    lea     rdx, [g_convlabel]
    mov     r8d, MAX_LABEL_BYTES
    call    conv_w2u
    mov     ecx, eax
    mov     qword ptr [rbp-32], rcx
vfl_write:
    cmp     qword ptr [rbp-32], 0
    jne     vfl_labeled
    ; --- plain field: {type, vallen, value} ---
    mov     r9, qword ptr [rbp-40]
    mov     r10, qword ptr [g_body_len]
    add     r10, 6
    add     r10, r9
    cmp     r10, VAULT_BODY_MAX
    ja      vfl_of
    mov     r11, qword ptr [g_body_ptr]
    add     r11, qword ptr [g_body_len]
    mov     rax, qword ptr [rbp-24]
    mov     word ptr [r11], ax
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r11+2], eax
    add     r11, 6
    lea     r9, [g_conv]
    xor     r8, r8
vfl_pcopy:
    cmp     r8, qword ptr [rbp-40]
    jae     vfl_pdone
    mov     al, byte ptr [r9+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    jmp     vfl_pcopy
vfl_pdone:
    mov     rax, qword ptr [g_body_len]
    add     rax, 6
    add     rax, qword ptr [rbp-40]
    mov     qword ptr [g_body_len], rax
    mov     eax, 1
    FRAME_EPILOG
    ret
vfl_labeled:
    ; --- labeled: {type|VF_LABELED, 2+labellen+vallen, u16 labellen|label|value} ---
    mov     r9, qword ptr [rbp-32]
    add     r9, qword ptr [rbp-40]
    add     r9, 2
    mov     r10, qword ptr [g_body_len]
    add     r10, 6
    add     r10, r9
    cmp     r10, VAULT_BODY_MAX
    ja      vfl_of
    mov     r11, qword ptr [g_body_ptr]
    add     r11, qword ptr [g_body_len]
    mov     rax, qword ptr [rbp-24]
    or      eax, VF_LABELED
    mov     word ptr [r11], ax
    mov     eax, r9d
    mov     dword ptr [r11+2], eax
    add     r11, 6
    mov     eax, dword ptr [rbp-32]
    mov     word ptr [r11], ax                  ; u16 labellen
    add     r11, 2
    lea     r9, [g_convlabel]
    xor     r8, r8
vfl_lcopy:
    cmp     r8, qword ptr [rbp-32]
    jae     vfl_lcdone
    mov     al, byte ptr [r9+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    jmp     vfl_lcopy
vfl_lcdone:
    add     r11, qword ptr [rbp-32]
    lea     r9, [g_conv]
    xor     r8, r8
vfl_vcopy:
    cmp     r8, qword ptr [rbp-40]
    jae     vfl_vcdone
    mov     al, byte ptr [r9+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    jmp     vfl_vcopy
vfl_vcdone:
    mov     rax, qword ptr [g_body_len]
    add     rax, 6
    mov     r9, qword ptr [rbp-32]
    add     r9, qword ptr [rbp-40]
    add     r9, 2
    add     rax, r9
    mov     qword ptr [g_body_len], rax
    mov     eax, 1
    FRAME_EPILOG
    ret
vfl_of:
    FASTFAIL FF_BOUNDS
va_field_labeled endp

; ===========================================================================
; vault_field_count(rcx = entry index) -> eax = number of TLV fields (0 if oob).
; ===========================================================================
public vault_field_count
vault_field_count proc frame
    FRAME_PROLOG 32
    call    vault_entry_ptr                     ; rcx = index -> rax = entry ptr
    test    rax, rax
    jz      vfc_zero
    mov     eax, dword ptr [rax+32]
    FRAME_EPILOG
    ret
vfc_zero:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_field_count endp

; ===========================================================================
; vault_field_get(rcx = entry index, edx = field n, r8 = *out) - decode the
;   n-th field (by position) into a 5-qword struct:
;     [out+0]=kind  [out+8]=labelptr(0)  [out+16]=labellen
;     [out+24]=valptr  [out+32]=vallen
;   -> eax = 1 ok, 0 if index/n out of range.
; ===========================================================================
public vault_field_get
vault_field_get proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], edx             ; n
    mov     qword ptr [rbp-32], r8              ; out
    call    vault_entry_ptr                     ; rcx = index -> rax = entry ptr
    test    rax, rax
    jz      vfg_none
    lea     r10, [rax+32]
    mov     r9d, dword ptr [r10]                ; field_count
    add     r10, 4                              ; -> first field
    mov     ecx, dword ptr [rbp-24]             ; n
    cmp     ecx, r9d
    jae     vfg_none
vfg_walk:
    test    ecx, ecx
    jz      vfg_at
    mov     eax, dword ptr [r10+2]              ; field len
    add     r10, 6
    add     r10, rax
    dec     ecx
    jmp     vfg_walk
vfg_at:
    movzx   eax, word ptr [r10]                 ; raw type
    mov     ecx, eax
    and     ecx, VF_KINDMASK                    ; kind
    mov     r9d, dword ptr [r10+2]              ; field len
    lea     r11, [r10+6]                        ; -> bytes
    mov     r8, qword ptr [rbp-32]              ; out
    mov     qword ptr [r8], rcx                 ; out.kind
    test    eax, VF_LABELED
    jnz     vfg_labeled
    mov     qword ptr [r8+8], 0                 ; labelptr
    mov     qword ptr [r8+16], 0               ; labellen
    mov     qword ptr [r8+24], r11              ; valptr
    mov     qword ptr [r8+32], r9               ; vallen
    mov     eax, 1
    FRAME_EPILOG
    ret
vfg_labeled:
    movzx   ecx, word ptr [r11]                 ; labellen
    lea     rax, [r11+2]
    mov     qword ptr [r8+8], rax               ; labelptr
    mov     qword ptr [r8+16], rcx              ; labellen
    lea     rax, [r11+2]
    add     rax, rcx
    mov     qword ptr [r8+24], rax              ; valptr (after label)
    sub     r9, 2
    sub     r9, rcx
    mov     qword ptr [r8+32], r9               ; vallen = fieldlen-2-labellen
    mov     eax, 1
    FRAME_EPILOG
    ret
vfg_none:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_field_get endp

; ===========================================================================
; vault_build_entry() - append one entry built from the GUI's ordered field
;   list g_field_list[0..g_field_n) (each = {qword type, qword labelwide,
;   qword valuewide}).  Field 0 must be a non-empty title.  Does NOT reseal.
;   -> eax = 0 ok / EXIT_USAGE (no title) / EXIT_NOSPACE (full).
; ===========================================================================
public vault_build_entry
vault_build_entry proc frame
    FRAME_PROLOG 80
    ; [rbp-32]=entry start [rbp-40]=written fcount [rbp-48]=i [rbp-56]=carried created
    mov     rax, qword ptr [g_carry_created]    ; consume the one-shot carry immediately
    mov     qword ptr [rbp-56], rax
    mov     qword ptr [g_carry_created], 0
    cmp     dword ptr [g_field_n], 0
    je      vbe_fail
    mov     r10, qword ptr [g_field_list+16]    ; field 0 value wide
    test    r10, r10
    jz      vbe_fail
    cmp     word ptr [r10], 0                   ; require a non-empty title
    je      vbe_fail
    mov     rax, qword ptr [g_body_len]
    add     rax, 36
    cmp     rax, VAULT_BODY_MAX
    ja      vbe_full
    mov     r11, qword ptr [g_body_ptr]
    add     r11, qword ptr [g_body_len]
    mov     qword ptr [rbp-32], r11
    mov     rcx, r11
    mov     edx, 16
    call    rng_fill                            ; 16-byte random id
    test    eax, eax
    jz      vbe_fail
    lea     rcx, [g_ts]
    call    GetSystemTimeAsFileTime
    mov     r11, qword ptr [rbp-32]
    mov     rax, qword ptr [g_ts]               ; now
    mov     qword ptr [r11+24], rax             ; modified = now
    mov     rdx, qword ptr [rbp-56]             ; carried created (0 = none -> now)
    test    rdx, rdx
    jz      vbe_crnow
    mov     rax, rdx
vbe_crnow:
    mov     qword ptr [r11+16], rax             ; created
    mov     dword ptr [r11+32], 0               ; field_count placeholder
    mov     rax, qword ptr [g_body_len]
    add     rax, 36
    mov     qword ptr [g_body_len], rax
    mov     dword ptr [rbp-40], 0
    mov     dword ptr [rbp-48], 0
vbe_loop:
    mov     eax, dword ptr [rbp-48]
    cmp     eax, dword ptr [g_field_n]
    jae     vbe_patch
    imul    eax, eax, 24                        ; descriptor stride = 3 qwords
    lea     r10, [g_field_list]
    add     r10, rax
    mov     rcx, qword ptr [r10]                ; descriptor type
    test    ecx, VFL_RAW                        ; raw binary value (image)?
    jnz     vbe_bin
    mov     rdx, qword ptr [r10+8]              ; label wide (0=none)
    mov     r8,  qword ptr [r10+16]             ; value wide
    call    va_field_labeled
    jmp     vbe_acc
vbe_bin:
    and     ecx, NOT VFL_RAW                    ; strip GUI marker -> base kind
    mov     rdx, qword ptr [r10+8]              ; label wide (0=none)
    mov     r9,  qword ptr [r10+16]             ; -> {u32 len, raw bytes}
    mov     r8d, dword ptr [r9]                 ; rawlen
    add     r9, 4                               ; rawptr
    xchg    r8, r9                              ; r8=rawptr, r9=rawlen
    call    va_field_bin_labeled
vbe_acc:
    add     dword ptr [rbp-40], eax
    inc     dword ptr [rbp-48]
    jmp     vbe_loop
vbe_patch:
    mov     r11, qword ptr [rbp-32]
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r11+32], eax             ; patch field_count
    mov     r11, qword ptr [g_body_ptr]
    inc     dword ptr [r11]                     ; entry_count++
    xor     eax, eax
    FRAME_EPILOG
    ret
vbe_full:
    mov     eax, EXIT_NOSPACE
    FRAME_EPILOG
    ret
vbe_fail:
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
vault_build_entry endp

; vault_remove_at(rcx = index) - delete entry `index` from the in-memory body
;   (memmove the tail down, entry_count--).  Does NOT reseal.  -> eax = 0 / 1.
public vault_remove_at
vault_remove_at proc frame
    FRAME_PROLOG 48
    ; [rbp-24] = entry start, [rbp-32] = entry len
    call    vault_entry_ptr
    test    rax, rax
    jz      vra_none
    mov     qword ptr [rbp-24], rax
    mov     rcx, rax
    call    vault_entry_len
    mov     qword ptr [rbp-32], rax
    mov     r10, qword ptr [g_body_ptr]
    add     r10, qword ptr [g_body_len]     ; body end
    mov     r11, qword ptr [rbp-24]
    add     r11, qword ptr [rbp-32]         ; src = start + len
    sub     r10, r11                        ; n
    mov     rcx, qword ptr [rbp-24]         ; dst = start
    xor     r8, r8
vra_mv:
    cmp     r8, r10
    jae     vra_done
    mov     al, byte ptr [r11+r8]
    mov     byte ptr [rcx+r8], al
    inc     r8
    jmp     vra_mv
vra_done:
    mov     rax, qword ptr [g_body_len]
    sub     rax, qword ptr [rbp-32]
    mov     qword ptr [g_body_len], rax
    mov     r11, qword ptr [g_body_ptr]
    dec     dword ptr [r11]
    xor     eax, eax
    FRAME_EPILOG
    ret
vra_none:
    mov     eax, 1
    FRAME_EPILOG
    ret
vault_remove_at endp

; ===========================================================================
; ATTACHMENTS - large per-attachment-encrypted blobs in a separate file section
; ===========================================================================

; att_cpy(rcx=dst, rdx=src, r8=len) - byte copy.  Leaf.
att_cpy proc
    xor     r9, r9
ac_l:
    cmp     r9, r8
    jae     ac_d
    mov     al, byte ptr [rdx+r9]
    mov     byte ptr [rcx+r9], al
    inc     r9
    jmp     ac_l
ac_d:
    ret
att_cpy endp

; att_aad(rcx=id ptr, rdx=ptlen) - build g_att_aad = id[16] | u64 ptlen.  Leaf.
att_aad proc
    lea     r10, [g_att_aad]
    xor     r9d, r9d
aa_l:
    mov     al, byte ptr [rcx+r9]
    mov     byte ptr [r10+r9], al
    inc     r9d
    cmp     r9d, 16
    jb      aa_l
    mov     qword ptr [r10+16], rdx
    ret
att_aad endp

; attach_find(rcx=id ptr, rdx=table base, r8d=count) -> eax = index or -1.  Leaf.
attach_find proc
    xor     r9d, r9d
af_row:
    cmp     r9d, r8d
    jae     af_none
    mov     r10, rdx
    mov     eax, r9d
    imul    eax, eax, 32
    add     r10, rax
    xor     r11d, r11d
af_cmp:
    mov     al, byte ptr [rcx+r11]
    cmp     al, byte ptr [r10+r11]
    jne     af_next
    inc     r11d
    cmp     r11d, 16
    jb      af_cmp
    mov     eax, r9d
    ret
af_next:
    inc     r9d
    jmp     af_row
af_none:
    mov     eax, -1
    ret
attach_find endp

; attach_reset() - free pending new-attachment plaintext buffers, clear tables.
public attach_reset
attach_reset proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], 0
ar_loop:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_newatt_n]
    jae     ar_done
    imul    eax, eax, 32
    lea     r10, [g_newatt]
    add     r10, rax
    mov     rcx, qword ptr [r10+16]
    test    rcx, rcx
    jz      ar_next
    mov     rdx, qword ptr [r10+24]
    call    mem_free
ar_next:
    inc     dword ptr [rbp-24]
    jmp     ar_loop
ar_done:
    mov     dword ptr [g_newatt_n], 0
    mov     dword ptr [g_attidx_n], 0
    FRAME_EPILOG
    ret
attach_reset endp

; attach_stage(rcx=plaintext ptr, rdx=len, r8=AttachRef out) -> eax = 0 / 1(err).
;   Copies the plaintext to a heap buffer and fills a fresh AttachRef
;   (random id/key/nonce, ptlen).  The bytes are sealed into the file on save.
public attach_stage
attach_stage proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx             ; plaintext
    mov     qword ptr [rbp-32], rdx             ; len
    mov     qword ptr [rbp-40], r8              ; ref
    mov     eax, dword ptr [g_newatt_n]
    cmp     eax, MAX_ATT
    jae     as_err
    mov     rcx, qword ptr [rbp-32]
    call    mem_alloc
    test    rax, rax
    jz      as_err
    mov     qword ptr [rbp-48], rax             ; buf
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    att_cpy
    ; fill AttachRef: id(16) key(32) nonce(12) ptlen
    mov     rcx, qword ptr [rbp-40]
    mov     edx, 16
    call    rng_fill
    test    eax, eax
    jz      as_err
    mov     rcx, qword ptr [rbp-40]
    add     rcx, ARF_KEY
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      as_err
    mov     rcx, qword ptr [rbp-40]
    add     rcx, ARF_NONCE
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      as_err
    mov     r10, qword ptr [rbp-40]
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [r10+ARF_PTLEN], rax
    ; append to g_newatt = {id16, buf, len}
    mov     eax, dword ptr [g_newatt_n]
    imul    eax, eax, 32
    lea     r10, [g_newatt]
    add     r10, rax
    mov     qword ptr [rbp-56], r10
    lea     rcx, [r10+ARF_ID]                   ; write the 16-byte ref id at ARF_ID
    mov     rdx, qword ptr [rbp-40]
    mov     r8, 16
    call    att_cpy
    mov     r10, qword ptr [rbp-56]
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [r10+16], rax
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [r10+24], rax
    inc     dword ptr [g_newatt_n]
    xor     eax, eax
    FRAME_EPILOG
    ret
as_err:
    mov     eax, 1
    FRAME_EPILOG
    ret
attach_stage endp

; attach_index_build() - scan the file image's attachment section (g_att_start,
;   g_att_total in g_filebuf) into g_attidx = {id16, ct ptr, ctlen}.
attach_index_build proc frame
    FRAME_PROLOG 48
    mov     dword ptr [g_attidx_n], 0
    mov     rax, qword ptr [g_att_total]
    test    rax, rax
    jz      aib_done
    mov     r10, qword ptr [g_filebuf]
    add     r10, qword ptr [g_att_start]
    mov     r11, r10
    add     r11, qword ptr [g_att_total]
aib_loop:
    cmp     r10, r11
    jae     aib_done
    ; ---- bounds: the 24-byte entry header (id16 + u64 ctlen) must fit ----
    mov     rax, r10
    add     rax, ATT_ENThDR
    cmp     rax, r11
    ja      aib_done                            ; truncated header -> stop
    ; ---- bounds: ct (ctlen bytes) + 16-byte tag must fit too.  ctlen is an
    ;      untrusted u64, so compare against the AVAILABLE space (never add ctlen
    ;      to a pointer, which could wrap) ----
    mov     rax, qword ptr [r10+16]             ; ctlen
    mov     rdx, r11
    sub     rdx, r10
    sub     rdx, ATT_ENThDR                     ; bytes available after the header
    cmp     rdx, 16
    jb      aib_done                            ; no room for the tag
    sub     rdx, 16
    cmp     rax, rdx
    ja      aib_done                            ; ct+tag overruns the section -> stop
    mov     eax, dword ptr [g_attidx_n]
    cmp     eax, MAX_ATT
    jae     aib_done
    imul    eax, eax, 32
    lea     r8, [g_attidx]
    add     r8, rax
    xor     r9d, r9d
aib_idcp:
    mov     al, byte ptr [r10+r9]
    mov     byte ptr [r8+r9], al
    inc     r9d
    cmp     r9d, 16
    jb      aib_idcp
    mov     rax, qword ptr [r10+16]             ; ctlen
    lea     rcx, [r10+ATT_ENThDR]               ; ct ptr
    mov     qword ptr [r8+16], rcx
    mov     qword ptr [r8+24], rax
    inc     dword ptr [g_attidx_n]
    add     r10, ATT_ENThDR
    add     r10, rax
    add     r10, 16
    jmp     aib_loop
aib_done:
    FRAME_EPILOG
    ret
attach_index_build endp

; attach_rescan() - recompute g_att_start/g_att_total for the current file image
;   (g_filebuf/g_filesize, body = g_body_len) and rebuild the index.
public attach_rescan
attach_rescan proc frame
    FRAME_PROLOG 48
    mov     rax, qword ptr [g_filesize]         ; [rbp-24] = effective end (no MAC)
    sub     rax, qword ptr [g_fmac_len]
    mov     qword ptr [rbp-24], rax
    mov     rax, qword ptr [g_body_len]
    add     rax, VH_TOTAL + 16
    mov     qword ptr [g_att_start], rax        ; att_start = 80 + bodyct + 16
    mov     qword ptr [g_att_total], 0
    mov     rax, qword ptr [g_att_start]
    add     rax, ATT_TRAILER
    cmp     rax, qword ptr [rbp-24]
    ja      ars_build
    mov     r11, qword ptr [g_filebuf]
    add     r11, qword ptr [rbp-24]
    sub     r11, ATT_TRAILER
    cmp     dword ptr [r11], ATT_MAGIC
    jne     ars_build
    mov     r9, qword ptr [r11+4]               ; entries_len
    mov     rax, qword ptr [g_att_start]
    add     rax, r9
    add     rax, ATT_TRAILER
    cmp     rax, qword ptr [rbp-24]
    jne     ars_build                           ; inconsistent -> ignore
    mov     qword ptr [g_att_total], r9
ars_build:
    call    attach_index_build
    FRAME_EPILOG
    ret
attach_rescan endp

; attach_open(rcx=AttachRef ptr, rdx=*outlen) -> rax = heap plaintext ptr (0 err).
;   Pending (unsaved) attachments return a copy of their plaintext; on-disk ones
;   are GCM-opened from the resident file image with the ref's key/nonce.
public attach_open
attach_open proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx             ; ref
    mov     qword ptr [rbp-32], rdx             ; outlen*
    mov     rax, qword ptr [rcx+ARF_PTLEN]
    mov     qword ptr [rbp-40], rax             ; ptlen
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_newatt]
    mov     r8d, dword ptr [g_newatt_n]
    call    attach_find
    cmp     eax, -1
    je      ao_disk
    ; pending: return a copy of the plaintext
    mov     rcx, qword ptr [rbp-40]
    call    mem_alloc
    test    rax, rax
    jz      ao_fail
    mov     qword ptr [rbp-48], rax
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_newatt]
    mov     r8d, dword ptr [g_newatt_n]
    call    attach_find
    imul    eax, eax, 32
    lea     r10, [g_newatt]
    add     r10, rax
    mov     rdx, qword ptr [r10+16]
    mov     rcx, qword ptr [rbp-48]
    mov     r8, qword ptr [rbp-40]
    call    att_cpy
    jmp     ao_ok
ao_disk:
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_attidx]
    mov     r8d, dword ptr [g_attidx_n]
    call    attach_find
    cmp     eax, -1
    je      ao_fail
    imul    eax, eax, 32
    lea     r10, [g_attidx]
    add     r10, rax
    mov     r11, qword ptr [r10+16]
    mov     qword ptr [rbp-56], r11             ; ct ptr
    mov     rcx, qword ptr [r10+24]
    mov     qword ptr [rbp-64], rcx             ; ctlen
    ; defence in depth: the on-disk ctlen must equal the body's ptlen (GCM is
    ; length-preserving).  Refuse a mismatch BEFORE allocating, so gcm_open can
    ; never be asked to write ctlen plaintext bytes into a ptlen-sized buffer.
    mov     rax, qword ptr [rbp-64]
    cmp     rax, qword ptr [rbp-40]
    jne     ao_fail
    mov     rcx, qword ptr [rbp-40]
    call    mem_alloc
    test    rax, rax
    jz      ao_fail
    mov     qword ptr [rbp-48], rax
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    call    att_aad
    lea     r10, [g_att_greq]
    mov     rax, qword ptr [rbp-24]
    add     rax, ARF_KEY
    mov     qword ptr [r10].GCMREQ.key, rax
    mov     rax, qword ptr [rbp-24]
    add     rax, ARF_NONCE
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_att_aad]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, 24
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [r10].GCMREQ.inlen, rax
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [r10].GCMREQ.outp, rax
    mov     rax, qword ptr [rbp-56]
    add     rax, qword ptr [rbp-64]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_att_greq]
    call    gcm_open
    test    eax, eax
    jnz     ao_authfail
ao_ok:
    mov     r10, qword ptr [rbp-32]
    test    r10, r10
    jz      ao_ret
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [r10], rax
ao_ret:
    mov     rax, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
ao_authfail:
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-40]
    call    mem_free
ao_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
attach_open endp

; attach_emit_one(rcx=AttachRef ptr, rdx=cur out ptr, r8=ptlen) - write one
;   attachment entry [id16][u64 ctlen][ct][tag16] at cur.  New (pending) refs are
;   GCM-sealed from their plaintext; existing refs are copied from the old image.
attach_emit_one proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx             ; ref
    mov     qword ptr [rbp-32], rdx             ; cur
    mov     qword ptr [rbp-40], r8              ; ptlen
    ; id16 at cur
    mov     rcx, rdx
    mov     rdx, qword ptr [rbp-24]
    mov     r8, 16
    call    att_cpy
    ; ctlen (= ptlen) at cur+16
    mov     r10, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [r10+16], rax
    ; AAD = id | ptlen
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    call    att_aad
    ; pending?
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_newatt]
    mov     r8d, dword ptr [g_newatt_n]
    call    attach_find
    cmp     eax, -1
    jne     aeo_new
    ; existing -> copy ct+tag from old image
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_attidx]
    mov     r8d, dword ptr [g_attidx_n]
    call    attach_find
    cmp     eax, -1
    je      aeo_done
    imul    eax, eax, 32
    lea     r10, [g_attidx]
    add     r10, rax
    mov     rdx, qword ptr [r10+16]             ; src ct
    mov     rcx, qword ptr [rbp-32]
    add     rcx, ATT_ENThDR                     ; dst = cur+24
    mov     r8, qword ptr [rbp-40]
    add     r8, 16                              ; ct + tag
    call    att_cpy
    jmp     aeo_done
aeo_new:
    imul    eax, eax, 32
    lea     r10, [g_newatt]
    add     r10, rax
    mov     r11, qword ptr [r10+16]             ; plaintext ptr
    lea     r10, [g_att_greq]
    mov     rax, qword ptr [rbp-24]
    add     rax, ARF_KEY
    mov     qword ptr [r10].GCMREQ.key, rax
    mov     rax, qword ptr [rbp-24]
    add     rax, ARF_NONCE
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_att_aad]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, 24
    mov     qword ptr [r10].GCMREQ.inp, r11
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [r10].GCMREQ.inlen, rax
    mov     rcx, qword ptr [rbp-32]
    add     rcx, ATT_ENThDR
    mov     qword ptr [r10].GCMREQ.outp, rcx
    mov     rcx, qword ptr [rbp-32]
    add     rcx, ATT_ENThDR
    add     rcx, qword ptr [rbp-40]
    mov     qword ptr [r10].GCMREQ.tag, rcx
    lea     rcx, [g_att_greq]
    call    gcm_seal
aeo_done:
    FRAME_EPILOG
    ret
attach_emit_one endp

; attach_build(ecx=emit, rdx=out ptr) -> rax = total section bytes (entries + the
;   12-byte trailer), or 0 when the vault has no image fields.  emit=0 sizes only;
;   emit=1 also writes the section at [rdx].  Walks every VF_IMAGE AttachRef.
attach_build proc frame
    FRAME_PROLOG 192
    mov     dword ptr [rbp-24], ecx             ; emit
    mov     qword ptr [rbp-32], rdx             ; cur
    mov     qword ptr [rbp-40], 0               ; total
    mov     dword ptr [rbp-48], 0               ; count
    call    vault_count
    mov     dword ptr [rbp-56], eax             ; nentries
    mov     dword ptr [rbp-64], 0               ; ei
ab_erow:
    mov     eax, dword ptr [rbp-64]
    cmp     eax, dword ptr [rbp-56]
    jae     ab_edone
    mov     ecx, dword ptr [rbp-64]
    call    vault_field_count
    mov     dword ptr [rbp-72], eax             ; fc
    mov     dword ptr [rbp-80], 0               ; fj
ab_frow:
    mov     eax, dword ptr [rbp-80]
    cmp     eax, dword ptr [rbp-72]
    jae     ab_fnext
    mov     ecx, dword ptr [rbp-64]
    mov     edx, dword ptr [rbp-80]
    lea     r8, [rbp-128]                       ; out struct
    call    vault_field_get
    cmp     qword ptr [rbp-128], VF_IMAGE       ; image + generic-file fields carry
    je      ab_isatt                           ;   an AttachRef value
    cmp     qword ptr [rbp-128], VF_FILE
    jne     ab_fadv
ab_isatt:
    mov     rax, qword ptr [rbp-104]            ; out.valptr (= [rbp-128+24])
    mov     qword ptr [rbp-136], rax            ; ref
    mov     rcx, qword ptr [rax+ARF_PTLEN]
    mov     qword ptr [rbp-144], rcx            ; ptlen
    cmp     dword ptr [rbp-24], 0
    je      ab_acc
    mov     rcx, qword ptr [rbp-136]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, qword ptr [rbp-144]
    call    attach_emit_one
ab_acc:
    mov     rax, qword ptr [rbp-144]
    add     rax, ATT_ENThDR + 16                ; 24 + ptlen + 16
    add     qword ptr [rbp-40], rax
    cmp     dword ptr [rbp-24], 0
    je      ab_cnt
    mov     rcx, qword ptr [rbp-32]
    add     rcx, rax
    mov     qword ptr [rbp-32], rcx
ab_cnt:
    inc     dword ptr [rbp-48]
ab_fadv:
    inc     dword ptr [rbp-80]
    jmp     ab_frow
ab_fnext:
    inc     dword ptr [rbp-64]
    jmp     ab_erow
ab_edone:
    cmp     dword ptr [rbp-48], 0
    je      ab_ret
    cmp     dword ptr [rbp-24], 0
    je      ab_trail
    mov     rcx, qword ptr [rbp-32]
    mov     dword ptr [rcx], ATT_MAGIC
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [rcx+4], rax
ab_trail:
    add     qword ptr [rbp-40], ATT_TRAILER
ab_ret:
    mov     rax, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
attach_build endp

; attach_selftest() -> eax = 0 ok / 1 fail.  Stage a blob, seal it, then open it
;   from a synthetic disk index and check the plaintext round-trips (+ AAD bind).
public attach_selftest
attach_selftest proc frame
    FRAME_PROLOG 64
    call    attach_reset
    ; fill a 40-byte plaintext pattern
    lea     r10, [att_katpt]
    xor     r9d, r9d
ast_fill:
    mov     eax, r9d
    add     eax, 7
    mov     byte ptr [r10+r9], al
    inc     r9d
    cmp     r9d, 40
    jb      ast_fill
    ; stage -> att_katref, g_newatt[0]
    lea     rcx, [att_katpt]
    mov     rdx, 40
    lea     r8, [att_katref]
    call    attach_stage
    test    eax, eax
    jnz     ast_fail
    ; seal manually into att_katct (like emit does): AAD = id|ptlen
    lea     rcx, [att_katref]
    mov     rdx, 40
    call    att_aad
    lea     r10, [g_att_greq]
    lea     rax, [att_katref+ARF_KEY]
    mov     qword ptr [r10].GCMREQ.key, rax
    lea     rax, [att_katref+ARF_NONCE]
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_att_aad]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, 24
    lea     rax, [att_katpt]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     qword ptr [r10].GCMREQ.inlen, 40
    lea     rax, [att_katct]
    mov     qword ptr [r10].GCMREQ.outp, rax
    lea     rax, [att_katct+40]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_att_greq]
    call    gcm_seal
    ; synthesize a disk index entry {id, ct=att_katct, ctlen=40}; drop the pending
    mov     dword ptr [g_newatt_n], 0
    lea     r10, [g_attidx]
    lea     rcx, [att_katref]                   ; id
    xor     r9d, r9d
ast_idcp:
    mov     al, byte ptr [rcx+r9]
    mov     byte ptr [r10+r9], al
    inc     r9d
    cmp     r9d, 16
    jb      ast_idcp
    lea     rax, [att_katct]
    mov     qword ptr [r10+16], rax
    mov     qword ptr [r10+24], 40
    mov     dword ptr [g_attidx_n], 1
    ; open it back
    lea     rcx, [att_katref]
    lea     rdx, [att_katout]
    call    attach_open
    test    rax, rax
    jz      ast_fail
    mov     qword ptr [rbp-24], rax             ; opened buf
    cmp     qword ptr [att_katout], 40
    jne     ast_freefail
    mov     rcx, rax
    lea     rdx, [att_katpt]
    mov     r8, 40
    call    ct_memcmp
    test    eax, eax
    jnz     ast_freefail
    ; free the opened buffer
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, 40
    call    mem_free
    call    attach_reset
    xor     eax, eax
    FRAME_EPILOG
    ret
ast_freefail:
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, 40
    call    mem_free
ast_fail:
    call    attach_reset
    mov     eax, 1
    FRAME_EPILOG
    ret
attach_selftest endp

end
