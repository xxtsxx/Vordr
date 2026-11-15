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
extern tpm_available:proc               ; M2: TPM machine-secret binding (tpm.asm)
extern tpm_seal:proc
extern tpm_unseal:proc
extern tpm_delete:proc
extern tpm_hello_seal:proc
extern tpm_hello_unseal:proc
extern tpm_hello_delete:proc
externdef g_tpm_reqhello:dword
ifdef PROBE_IO
extern GetTempPathW:proc
endif
extern secure_zero:proc
extern secmem_alloc:proc
extern sec_lock:proc
extern pwgen_ex:proc
externdef g_pwgen_outcap:dword          ; E16: one-shot pwgen output capacity
externdef g_sel:byte                    ; per-entry export selection mask (gui.asm)
extern zi_stage_vault:proc              ; .vordr import staging (zipimport.asm)
externdef g_zi_hide:byte                ;   rows the checklist must not show
externdef g_zi_stg_n:dword              ;   staged row count
extern secmem_free:proc
extern read_file:proc
extern path_io:proc                     ; the vault path in the form Win32 accepts
extern cfg_in_set:proc                  ; the ONLY way to set g_cfg_in
extern write_file:proc
extern file_rename:proc
extern MoveFileExW:proc
extern CopyFileW:proc
extern DeleteFileW:proc
extern Sleep:proc                       ; back-off between contended temp-write tries
externdef g_io_err:dword                ; Win32 reason from the last failed write
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
extern reg_tpm_set:proc
extern reg_tpm_get:proc
extern reg_tpm_del:proc
extern reg_prune_all:proc               ; C6: drop legacy path-named reg values
externdef g_readonly:dword              ; E9: read-only mode flag (owned by gui.asm)
extern reg_ctr_set:proc
extern reg_ctr_get:proc
extern reg_ctr_del:proc
extern GetNamedSecurityInfoW:proc
extern GetSecurityDescriptorControl:proc
extern SetNamedSecurityInfoW:proc
extern LocalFree:proc

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
externdef g_cfg_pinminlen:dword
externdef g_cfg_pinnotriv:dword

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
VH_INV_AAD      equ 68          ; invariant header AAD (g_hdr[0..51] || g_hdr[64..79], sans VH_NONCE)
VAULT_BODY_MAX  equ 16777216    ; 16 MiB plaintext cap (record fields only)
; UTF-8 scratch for one field value.  Must cover the widest value the UI can hold
; (CONVW_MAX-1 = 16383 wide chars) in the WORST script: a BMP character is up to 3
; UTF-8 bytes, so 16383*3 + NUL.  Undersizing this is what made conv_w2u fail, and
; a failed conversion used to be indistinguishable from an empty one.
CONV_CAP        equ 49152
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
MAX_ATT         equ 8192        ; pending (staged, not yet saved) attachments
; The ON-DISK index is sized separately and far larger.  It was MAX_ATT too, and an
; attachment past the 512th was simply never indexed - so the next save could not
; find its ciphertext and wrote an empty blob in its place.  Overflowing this one
; is now detected (g_att_ovf) and REFUSES the save instead.
MAX_ATTIDX      equ 16384
ATT_FILE_MAX    equ 10000000h   ; 256 MiB per-attachment cap (mirrors gui.asm)
ATT_TOTAL_MAX   equ 0F0000000h  ; 3.75 GiB cumulative attachment section cap

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
ffk_seedpw  db "vordrtest",0                            ; export-KAT seed vault password (9)
vxk_exppw   db "exportpw2",0                             ; vaultexportkat: export vault password (9)
CSTR vxk_ok,  "vaultexportkat: PASS (export round-trips ids; re-merge idempotent)",13,10
CSTR vxk_bad, "vaultexportkat: FAIL",13,10
CSTR vea_ok,  "vaultexpattkat: PASS (attachments carried; blobs decrypt in the child vault)",13,10
CSTR vea_bad, "vaultexpattkat: FAIL",13,10
CSTR bk_ok,  "bktest: PASS (bak1..3 rotated and bak1 opens)",13,10
CSTR bk_bad, "bktest: FAIL (backup missing or unopenable)",13,10
CSTR mt_ok,  "mactest: PASS (counter tamper rejected, restore opens)",13,10
CSTR mt_bad, "mactest: FAIL",13,10
CSTR si_ok,  "sysitemkat: PASS (hidden, stamp round-trips, idempotent, not exported)",13,10
CSTR si_bad, "sysitemkat: FAIL",13,10
CSTR xs_okm,  "vexselkat: PASS (selection honoured, master untouched, child re-keyed)",13,10
CSTR xs_badm, "vexselkat: FAIL",13,10
CSTR c9_okm,  "c9kat: PASS (interval boundary, reminder is pure + never escalates, pw check)",13,10
CSTR c9_badm, "c9kat: FAIL",13,10
CSTR vi_okm,  "vimpkat: PASS (foreign vault read, master untouched, selection, idempotent)",13,10
CSTR vi_badm, "vimpkat: FAIL",13,10
CSTR mt_leak,"mactest: FAIL (file-MAC did not catch the trailer tamper)",13,10
CSTR rb_ok,  "rbtest: PASS (older counter flagged, current one not, under any spelling of the path)",13,10
CSTR rb_bad, "rbtest: FAIL",13,10
CSTR rl_ok,  "reload: PASS (refreshed from disk; a failed reload keeps the vault; a malformed body is never sealed)",13,10
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
align 8
g_eidx      dq ?                        ; vault_index_begin: one entry pointer per entry
g_eidx_body dq ?                        ;   built from this body,
g_eidx_blen dq ?                        ;   of this length
g_eidx_cap  dd ?                        ; entries the array holds
g_eidx_n    dd ?                        ; entries indexed (0 = no index in use)
g_eidx_dep  dd ?                        ; begin/end nesting
align 2
; convcap's scratch output buffer - written by every caller before it is read,
; so it needs no initial contents.  In .data it was 4 KB of zeros in the image;
; aligncheck now refuses a "dup (?)" array this size in an initialised section.
cvc_out db 4096 dup (?)
align 16
g_vx_pathb  dw MAX_PATH_CHARS dup (?)  ; vaultexportkat: export target path (source + ".exp")
align 16
g_vx_ids    db 16*16 dup (?)           ; vaultexportkat: snapshot of source entry ids
align 8
g_vfz_rng   dq ?                       ; vfuzz xorshift64 state (dbg/test only)
g_kat_body  db 512 dup (?)             ; scratch body for the field-serialization KAT
public g_vkey, g_sha32, g_hdr
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
; vault_export_sel parks the live vault's state here while it seals a CHILD file, so
; the master stays open and untouched throughout.  g_xs_vkey holds key material and is
; wiped the moment it has been restored.
align 8
public g_merge_sel
MAX_SEL     equ 8192                        ; mirrors gui.asm (constcheck gates the pair)
g_merge_sel dd ?                            ; 1 = fed_merge honours g_sel (GUI import);
                                            ;   0 = merge every source entry (headless)
g_seal_noadopt dd ?                         ; 1 = this seal writes a DIFFERENT vault, so
                                            ;   vault_seal_write must not adopt the image
                                            ;   it just wrote as the live one
align 8
g_xs_hdr    db VH_TOTAL dup (?)             ; parked live header
align 2
g_xs_path   dw (MAX_PATH_CHARS + 16) dup (?) ; owned path snapshot, never ci_path alias
public g_xs_vkey
g_xs_vkey   db 32 dup (?)                   ; parked live vault key (wiped after restore)
g_xs_ehash  db 32 dup (?)                   ; parked external-change hash
g_reuse_key dd ?                            ; C8: vault_reload reuses g_vkey (skip Argon2)
align 8
g_ps_body     dq ?                          ; vault_state_park: the open vault, parked
g_ps_bodylen  dq ?                          ;   across a second vault_unlock
g_ps_filebuf  dq ?
g_ps_filesize dq ?
g_ps_fmac     dq ?
g_ps_atttotal dq ?
g_ps_attstart dq ?
g_ps_counter  dq ?
g_ps_extsize  dq ?
g_ps_attidxn  dd ?
g_ps_attovf   dd ?
g_ps_rollback dd ?
g_ps_hdr      db VH_TOTAL dup (?)
g_ps_ehash    db 32 dup (?)
align 8
g_lock_h    dq ?                            ; C8: <vault>.lock handle (0 = not held)
g_lock_path dw (MAX_PATH_CHARS + 8) dup (?) ; C8: "<vault>.lock" wide path
align 16
public g_fmac_ctx
g_fmac_ctx  db 256 dup (?)                  ; BLAKE2B_CTX scratch (216 used)
g_fmac_out  db 32 dup (?)                   ; computed file MAC
g_filebuf   dq ?
g_filesize  dq ?
g_outbuf    dq ?
g_outlen    dq ?
align 16
g_att_greq  GCMREQ <>                          ; GCM req for attachment seal/open
g_newatt    db MAX_ATT * 32 dup (?)            ; pending new: {id16, qword pt, qword ptlen}
g_newatt_n  dd ?
g_attidx    db MAX_ATTIDX * 32 dup (?)         ; from file: {id16, qword ct, qword ctlen}
g_attidx_n  dd ?
g_att_ovf   dd ?                                ; 1 = the file held more attachments than
                                                ;   g_attidx can index: saving would drop some
align 8
g_ps_attidx db MAX_ATTIDX * 32 dup (?)         ; vault_state_park's copy of g_attidx
g_att_missing dd ?                              ; 1 = a referenced attachment had no
                                                ;   ciphertext to carry: the save is refused
g_att_aad   db 32 dup (?)                       ; GCM AAD scratch = id16 | u64 ptlen
g_att_start dq ?                                ; file offset where attachments begin
g_att_total dq ?                                ; attachment entries byte length
public g_conv, g_convlabel                      ; pinned + crash-wiped by secmem.asm
g_conv      db CONV_CAP dup (?)
g_convlabel db MAX_LABEL_BYTES dup (?)        ; utf8 label scratch (va_field_labeled)
align 2
g_tmppath   dw MAX_PATH_CHARS dup (?)        ; "<vault>.tmp" for atomic replace
g_preloaded dd ?                             ; 1 = g_filebuf was filled by vault_preload;
                                             ;   vault_unlock must not re-read or free it
g_bak_a     dw MAX_PATH_CHARS dup (?)        ; backup-rotation path scratch (from)
g_bak_b     dw MAX_PATH_CHARS dup (?)        ; backup-rotation path scratch (to)
g_bak_staged dd ?                            ; 1 if .bak0 was staged before file_rename
align 8
public g_vof_buf, g_vof_len
g_vof_buf   dq ?                             ; one-shot pre-read foreign image (TOCTOU-free import)
g_vof_len   dq ?
g_ts        dq ?                ; GetSystemTimeAsFileTime scratch
g_sys_ver   db ?                ; VF_SYSTEM value byte (schema version) - write scratch
align 8
g_sys_ft    dq ?                ; VF_SYS_PWVERIFY value staging - write scratch
seed_title_w dw 80 dup (?)      ; seedtest scratch: entry field strings (wide)
seed_user_w  dw 96 dup (?)
seed_url_w   dw 96 dup (?)
seed_pass_a  db 40 dup (?)
seed_pass_w  dw 40 dup (?)
public g_carry_created
g_carry_created dq ?            ; if !=0, vault_build_entry uses it as `created`
                               ; (one-shot; lets a GUI edit preserve the orig date)
g_vfe_err   dd ?                ; a va_field_* writer refused (no room / did not fit);
                               ;   the entry being built is rolled back, never kept half
vst_ct      db 16 dup (?)
vst_dec     db 16 dup (?)
vst_tag     db 16 dup (?)
align 16
att_katpt   db 40 dup (?)               ; attachment KAT: plaintext
att_katct   db 80 dup (?)               ;                 ciphertext+tag scratch
att_katref  db ARF_SIZE dup (?)         ;                 AttachRef
att_katout  dq ?                        ;                 opened plaintext len
align 4
public g_use_tpm, g_tpm_pin_u8len
g_use_tpm       dd ?                ; 0=pw, 1=TPM_MODE_ALONE, 2=TPM_MODE_PIN, 3=TPM_MODE_HELLO
g_tpm_pin_u8len dd ?                ; UTF-8 byte length of g_tpm_pin_u8
align 2
g_tpm_kn        dw 64 dup (?)       ; TPM key name (wide): "Vordr-" + KCV[0..7] hex
g_tpm_kn_s      dw 64 dup (?)       ; TPM state slot key name: "Vordr-<hex>-S0" / "-S1"
align 8
g_tpm_blob      db TPM_BLOB_CAP dup (?)
g_tpm_oldblob   db TPM_BLOB_CAP dup (?)
public g_tpm_state, g_tpm_sec, g_tpm_dk, g_tpm_cand, g_tpm_pin_u8
g_tpm_state     db 384 dup (?)      ; InnerState (380 bytes used, padded to 384)
g_tpm_sec       db 64 dup (?)       ; tpm_secret[32] || second_half[32]
g_tpm_dk        db 64 dup (?)       ; Argon2id(PIN) 64-byte output
g_tpm_cand      db 32 dup (?)       ; transient 32-byte key scratch (state_key / wrap_key)
g_tpm_aad       db 112 dup (?)      ; AAD scratch (96 bytes Mode 2, 100 bytes Mode 3)
g_tpm_pin_u8    db 256 dup (?)      ; UTF-8 PIN scratch for enroll / unlock

.data
align 4
public g_tpm_pin_max, g_tpm_pin_rem
g_tpm_pin_max   dd TPM_PIN_TRIES_DEF
g_tpm_pin_rem   dd 0
g_tpm_pin_t     dd 2
g_tpm_pin_m     dd 65536

.code

; ===========================================================================
; conv_w2u(rcx = wideZ ptr, rdx = outbuf, r8d = cap) -> eax = byte len (no NUL),
;   0 for a NULL pointer or a genuinely empty string, -1 if it DID NOT FIT.
;
;   The -1 matters.  WideCharToMultiByte returns 0 both for an empty result and
;   for ERROR_INSUFFICIENT_BUFFER, and this used to collapse the two into 0 - so a
;   value too long for the buffer was written to the vault as an EMPTY field,
;   silently destroying it.  The same conflation produced an empty-password export
;   (ef9fc8b) and phantom history rows (e08e6d2).  Callers must treat -1 as fatal,
;   never as "no text": with a NUL-terminated source, 0 from the API can ONLY mean
;   failure (an empty string still returns 1, for the terminator).
; ===========================================================================
conv_w2u proc frame
    FRAME_PROLOG 32 + 32            ; +32 for WC2MB stack args
    test    rcx, rcx
    jz      cw_zero
    ; WideCharToMultiByte(CP_UTF8, 0, src, -1, out, cap, NULL, NULL)
    WINCALL WideCharToMultiByte, CP_UTF8, 0, rcx, -1, rdx, r8d, 0, 0
    test    eax, eax
    jz      cw_fail
    dec     eax                     ; drop terminating NUL
    FRAME_EPILOG
    ret
cw_zero:
    xor     eax, eax                ; NULL source -> genuinely nothing to write
    FRAME_EPILOG
    ret
cw_fail:
    or      eax, -1                 ; did not fit - NOT the same as empty
    FRAME_EPILOG
    ret
conv_w2u endp

; ===========================================================================
; vk_derive() - Argon2id(master pw, g_hdr salt/t/m, p=1) -> g_vkey (32 bytes).
;   -> eax = 0 on success, EXIT_OOM on KDF failure.
; ===========================================================================
; vk_params_ok() -> eax = 1 if the header's Argon2 cost params are within the
;   range a legitimate Vordr vault can carry, else 0.  Bounds match the config/CLI:
;   t_cost in [ARGON2_MIN_T .. ARGON2_MAX_T], m_cost in (0 .. ARGON2_MAX_M_KIB].
;   A too-SMALL m is allowed (fast test vaults use m=8 KiB); only the exhaustion
;   direction is dangerous.  Called before the KDF (pre-auth) so a crafted header
;   can never drive a giant allocation.  Leaf.
public vk_params_ok
vk_params_ok proc
    mov     eax, dword ptr [g_hdr+VH_T]
    cmp     eax, ARGON2_MIN_T
    jb      vp_bad
    cmp     eax, ARGON2_MAX_T
    ja      vp_bad
    mov     eax, dword ptr [g_hdr+VH_M]
    cmp     eax, ARGON2_MIN_M_KIB               ; RFC 9106 floor: 8 KiB per lane (p=1).
    jb      vp_bad                              ;   Below it the fill geometry degenerates
    cmp     eax, ARGON2_MAX_M_KIB               ;   and the result matches no reference.
    ja      vp_bad
    ; The lane count is written (always 1) but vk_derive never reads it: it derives
    ; with p = 1 whatever the header says.  A file claiming p != 1 - written by an
    ; independent implementation, say - would then fail as a WRONG PASSWORD.  It is
    ; a format this reader does not support, so it is refused as one.
    cmp     dword ptr [g_hdr+VH_LANES], 1
    jne     vp_bad
    mov     eax, 1
    ret
vp_bad:
    xor     eax, eax
    ret
vk_params_ok endp

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

; --- Mode 2 (TPM + PIN) InnerState byte offsets (380 bytes total) -------------
ST_GEN          equ 0
ST_FAILS        equ 8
ST_MAXFAILS     equ 12
ST_LASTFT       equ 16
ST_SALT         equ 24
ST_TLEN         equ 56
ST_CTTPM        equ 60
ST_VKIV         equ 316
ST_VKCT         equ 328
ST_VKTAG        equ 360
ST_SIZE         equ 380
TPM_PIN_BLOB_SZ equ 680

; tpm_kn_slot_build(ecx = slot 0|1) - build L"Vordr-<16hex>-S0" / L"-S1" in g_tpm_kn_s.
tpm_kn_slot_build proc frame
    FRAME_PROLOG 32
    mov     dword ptr [rbp-24], ecx
    call    tpm_kn_build
    lea     r10, [g_tpm_kn]
    lea     r11, [g_tpm_kn_s]
    xor     r8d, r8d
tks_cp:
    mov     ax, word ptr [r10+r8*2]
    test    ax, ax
    jz      tks_tail
    mov     word ptr [r11+r8*2], ax
    inc     r8d
    cmp     r8d, 56
    jb      tks_cp
tks_tail:
    mov     word ptr [r11+r8*2+0], '-'
    mov     word ptr [r11+r8*2+2], 'S'
    mov     eax, dword ptr [rbp-24]
    and     eax, 1
    add     eax, '0'
    mov     word ptr [r11+r8*2+4], ax
    mov     word ptr [r11+r8*2+6], 0
    FRAME_EPILOG
    ret
tpm_kn_slot_build endp

; tpm_wipe_scratch() - wipe all transient Mode 2 / Mode 3 secret buffers.
tpm_wipe_scratch proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_tpm_state]
    mov     edx, 384
    call    secure_zero
    lea     rcx, [g_tpm_sec]
    mov     edx, 64
    call    secure_zero
    lea     rcx, [g_tpm_dk]
    mov     edx, 64
    call    secure_zero
    lea     rcx, [g_tpm_cand]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_tpm_aad]
    mov     edx, 112
    call    secure_zero
    lea     rcx, [g_tpm_pin_u8]
    mov     edx, 256
    call    secure_zero
    mov     dword ptr [g_tpm_pin_u8len], 0
    FRAME_EPILOG
    ret
tpm_wipe_scratch endp

; tpm_del_slots_silent() - delete S0 and S1 state keys silently.
tpm_del_slots_silent proc frame
    FRAME_PROLOG 32
    mov     eax, dword ptr [g_tpm_reqhello]
    mov     dword ptr [rbp-24], eax
    mov     dword ptr [g_tpm_reqhello], 0
    xor     ecx, ecx
    call    tpm_kn_slot_build
    lea     rcx, [g_tpm_kn_s]
    call    tpm_delete
    mov     ecx, 1
    call    tpm_kn_slot_build
    lea     rcx, [g_tpm_kn_s]
    call    tpm_delete
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_tpm_reqhello], eax
    FRAME_EPILOG
    ret
tpm_del_slots_silent endp

; tpm_stash_prev_hello() -> eax = ct_hello_len (>0) if g_cfg_in currently has a
;   Mode 3 (WHLO) envelope in HKCU\..\TPM-Unlock (copied into g_tpm_oldblob), else 0.
tpm_stash_prev_hello proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [g_cfg_in]
    test    rcx, rcx
    jz      tsph_no
    lea     rdx, [g_tpm_oldblob]
    mov     r8d, TPM_BLOB_CAP
    call    reg_tpm_get
    cmp     eax, 84
    jb      tsph_no
    cmp     eax, TPM_BLOB_CAP
    ja      tsph_no
    lea     r10, [g_tpm_oldblob]
    cmp     dword ptr [r10+0], TPM_ENV_MAGIC
    jne     tsph_no
    cmp     word ptr [r10+4], TPM_ENV_VER
    jne     tsph_no
    cmp     byte ptr [r10+6], TPM_MODE_HELLO
    jne     tsph_no
    cmp     dword ptr [r10+12], eax
    jne     tsph_no
    cmp     word ptr [r10+16], 256
    jne     tsph_no
    movzx   ecx, word ptr [r10+18]
    cmp     ecx, 65
    jb      tsph_no
    cmp     ecx, 512
    ja      tsph_no
    lea     edx, [rcx + 276 + 60]
    cmp     edx, eax
    jne     tsph_no
    mov     eax, ecx
    FRAME_EPILOG
    ret
tsph_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_stash_prev_hello endp

; tpm_del_stashed_hello(ecx = ct_hello_len) - delete stashed WHLO platform credential if any.
tpm_del_stashed_hello proc frame
    FRAME_PROLOG 32
    test    ecx, ecx
    jz      tdsh_ret
    mov     edx, ecx
    lea     rcx, [g_tpm_oldblob + 276]
    call    tpm_hello_delete
tdsh_ret:
    FRAME_EPILOG
    ret
tpm_del_stashed_hello endp

; tpm_pin_stretch() -> eax = 1 ok / 0 fail.
;   Argon2id(g_tpm_pin_u8[0..g_tpm_pin_u8len], salt = ST_SALT[32]) -> g_tpm_dk[64],
;   and wipes g_tpm_pin_u8.
tpm_pin_stretch proc frame
    FRAME_PROLOG 32
    mov     eax, dword ptr [g_tpm_pin_u8len]
    test    eax, eax
    jz      tps_bad
    cmp     eax, 255
    ja      tps_bad
    lea     r10, [g_areq]
    mov     ecx, dword ptr [g_tpm_pin_t]
    mov     dword ptr [r10].ARGON2REQ.t_cost, ecx
    mov     ecx, dword ptr [g_tpm_pin_m]
    mov     dword ptr [r10].ARGON2REQ.m_cost, ecx
    mov     dword ptr [r10].ARGON2REQ.lanes, 1
    mov     dword ptr [r10].ARGON2REQ.outlen, 64
    mov     dword ptr [r10].ARGON2REQ.version, 19
    mov     dword ptr [r10].ARGON2REQ.atype, 2
    lea     rcx, [g_tpm_pin_u8]
    mov     qword ptr [r10].ARGON2REQ.pwd, rcx
    mov     dword ptr [r10].ARGON2REQ.pwdlen, eax
    mov     dword ptr [r10].ARGON2REQ.saltlen, 32
    lea     rcx, [g_tpm_state + ST_SALT]
    mov     qword ptr [r10].ARGON2REQ.salt, rcx
    mov     qword ptr [r10].ARGON2REQ.secret, 0
    mov     dword ptr [r10].ARGON2REQ.secretlen, 0
    mov     dword ptr [r10].ARGON2REQ.adlen, 0
    mov     qword ptr [r10].ARGON2REQ.ad, 0
    lea     rcx, [g_tpm_dk]
    mov     qword ptr [r10].ARGON2REQ.outp, rcx
    lea     rcx, [g_areq]
    call    argon2id_hash
    mov     dword ptr [rbp-24], eax
    lea     rcx, [g_tpm_pin_u8]
    mov     edx, 256
    call    secure_zero
    mov     dword ptr [g_tpm_pin_u8len], 0
    cmp     dword ptr [rbp-24], 0
    jne     tps_bad
    mov     eax, 1
    FRAME_EPILOG
    ret
tps_bad:
    lea     rcx, [g_tpm_pin_u8]
    mov     edx, 256
    call    secure_zero
    mov     dword ptr [g_tpm_pin_u8len], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_pin_stretch endp

; tpm_build_aad(ecx = prefix_bytes) - g_tpm_aad = g_tpm_blob[0..prefix_bytes-1]
;   || g_hdr[0..51] || g_hdr[64..79] (prefix_bytes + VH_INV_AAD = prefix_bytes + 68).
;   Excludes mutable VH_NONCE (g_hdr[52..63]) so vault_reseal never invalidates TPM blobs.
tpm_build_aad proc
    lea     r10, [g_tpm_blob]
    lea     r11, [g_tpm_aad]
    xor     r8d, r8d
tba_p:
    cmp     r8d, ecx
    jae     tba_h0
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8d
    jmp     tba_p
tba_h0:
    add     r11, rcx
    lea     r10, [g_hdr]
    xor     r8d, r8d
tba_h1:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8d
    cmp     r8d, VH_NONCE
    jb      tba_h1
    add     r11, VH_NONCE
    lea     r10, [g_hdr + VH_KCV]
    xor     r8d, r8d
tba_h2:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8d
    cmp     r8d, VH_TOTAL - VH_KCV
    jb      tba_h2
    ret
tpm_build_aad endp

; tpm_pin_seal_state(ecx = slot 0|1) -> eax = 1 ok / 0 fail.
;   Creates fresh RSA-2048 key in Vordr-<KCV>-S{slot}, seals random state_key[32],
;   AES-256-GCM-encrypts g_tpm_state[380] with AAD = OuterHdr[16] || InvHdr[68],
;   and commits the 680-byte envelope to HKCU\..\TPM-Unlock.
tpm_pin_seal_state proc frame
    FRAME_PROLOG 48
    and     ecx, 1
    mov     dword ptr [rbp-24], ecx             ; slot
    mov     eax, dword ptr [g_tpm_reqhello]
    mov     dword ptr [rbp-28], eax
    mov     dword ptr [g_tpm_reqhello], 0
    lea     rcx, [g_tpm_cand]                   ; state_key[32]
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      tpss_fail
    lea     rcx, [g_tpm_blob + 272]             ; outer_iv[12]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      tpss_fail
    mov     ecx, dword ptr [rbp-24]
    call    tpm_kn_slot_build
    lea     rcx, [g_tpm_kn_s]
    lea     rdx, [g_tpm_cand]
    lea     r8, [g_tpm_blob + 16]
    mov     r9d, 256
    call    tpm_seal
    cmp     eax, 256
    jne     tpss_fail
    lea     r10, [g_tpm_blob]
    mov     dword ptr [r10+0],  TPM_ENV_MAGIC
    mov     word ptr  [r10+4],  TPM_ENV_VER
    mov     byte ptr  [r10+6],  TPM_MODE_PIN
    mov     eax, dword ptr [rbp-24]
    mov     byte ptr  [r10+7],  al
    mov     dword ptr [r10+8],  0
    mov     dword ptr [r10+12], TPM_PIN_BLOB_SZ
    mov     ecx, 16
    call    tpm_build_aad
    lea     r10, [g_greq]
    lea     rax, [g_tpm_cand]
    mov     qword ptr [r10].GCMREQ.key, rax
    lea     rax, [g_tpm_blob + 272]
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_tpm_aad]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, 16 + VH_INV_AAD
    lea     rax, [g_tpm_state]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     qword ptr [r10].GCMREQ.inlen, ST_SIZE
    lea     rax, [g_tpm_blob + 284]
    mov     qword ptr [r10].GCMREQ.outp, rax
    lea     rax, [g_tpm_blob + 664]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_greq]
    call    gcm_seal
    lea     rcx, [g_tpm_cand]
    mov     edx, 32
    call    secure_zero
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_tpm_blob]
    mov     r8d, TPM_PIN_BLOB_SZ
    call    reg_tpm_set
    test    eax, eax
    jz      tpss_delslot
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [g_tpm_reqhello], eax
    mov     eax, 1
    FRAME_EPILOG
    ret
tpss_delslot:
    lea     rcx, [g_tpm_kn_s]
    call    tpm_delete
tpss_fail:
    lea     rcx, [g_tpm_cand]
    mov     edx, 32
    call    secure_zero
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [g_tpm_reqhello], eax
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_pin_seal_state endp

; ===========================================================================
; vault_tpm_mode_get() -> eax = 0 (none/invalid) or TPM_MODE_ALONE..TPM_MODE_HELLO (1..3).
;   Inspects HKCU\..\TPM-Unlock for g_cfg_in (keyed by path, works pre-header).
; ===========================================================================
public vault_tpm_mode_get
vault_tpm_mode_get proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [g_cfg_in]
    test    rcx, rcx
    jz      vtmg_no
    lea     rdx, [g_tpm_blob]
    mov     r8d, TPM_BLOB_CAP
    call    reg_tpm_get
    test    eax, eax
    jz      vtmg_no
    cmp     eax, 16
    jb      vtmg_no
    lea     r10, [g_tpm_blob]
    cmp     dword ptr [r10+0], TPM_ENV_MAGIC
    jne     vtmg_legacy
    cmp     word ptr [r10+4], TPM_ENV_VER
    jne     vtmg_no
    cmp     dword ptr [r10+12], eax
    jne     vtmg_no
    movzx   ecx, byte ptr [r10+6]
    cmp     ecx, TPM_MODE_ALONE
    je      vtmg_m1
    cmp     ecx, TPM_MODE_PIN
    je      vtmg_m2
    cmp     ecx, TPM_MODE_HELLO
    je      vtmg_m3
    jmp     vtmg_no
vtmg_m1:
    cmp     eax, 272
    jne     vtmg_no
    mov     eax, TPM_MODE_ALONE
    FRAME_EPILOG
    ret
vtmg_m2:
    cmp     eax, TPM_PIN_BLOB_SZ
    jne     vtmg_no
    mov     eax, TPM_MODE_PIN
    FRAME_EPILOG
    ret
vtmg_m3:
    cmp     eax, 84
    jb      vtmg_no
    cmp     eax, TPM_BLOB_CAP
    ja      vtmg_no
    mov     eax, TPM_MODE_HELLO
    FRAME_EPILOG
    ret
vtmg_legacy:
    cmp     eax, 256                            ; legacy v0.2.3 raw RSA-2048 OAEP blob
    jne     vtmg_no
    mov     eax, TPM_MODE_ALONE
    FRAME_EPILOG
    ret
vtmg_no:
    mov     eax, TPM_MODE_OFF
    FRAME_EPILOG
    ret
vault_tpm_mode_get endp

; ===========================================================================
; vk_derive_tpm_alone() - Mode 1 unseal (accepts VTPM Mode 1 or legacy 256B ONLY).
; ===========================================================================
vk_derive_tpm_alone proc frame
    FRAME_PROLOG 48
    call    tpm_kn_build
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_tpm_blob]
    mov     r8d, TPM_BLOB_CAP
    call    reg_tpm_get
    test    eax, eax
    jz      vdta_no
    lea     r10, [g_tpm_blob]
    cmp     eax, 272
    jne     vdta_chk_leg
    cmp     dword ptr [r10+0], TPM_ENV_MAGIC
    jne     vdta_no
    cmp     word ptr [r10+4], TPM_ENV_VER
    jne     vdta_no
    cmp     byte ptr [r10+6], TPM_MODE_ALONE
    jne     vdta_no
    cmp     dword ptr [r10+12], 272
    jne     vdta_no
    lea     rcx, [g_tpm_kn]
    lea     rdx, [g_tpm_blob + 16]
    mov     r8d, 256
    lea     r9, [g_vkey]
    call    tpm_unseal
    test    eax, eax
    jz      vdta_no
    xor     eax, eax
    FRAME_EPILOG
    ret
vdta_chk_leg:
    cmp     eax, 256
    jne     vdta_no
    cmp     dword ptr [r10+0], TPM_ENV_MAGIC
    je      vdta_no
    lea     rcx, [g_tpm_kn]
    lea     rdx, [g_tpm_blob]
    mov     r8d, 256
    lea     r9, [g_vkey]
    call    tpm_unseal
    test    eax, eax
    jz      vdta_no
    xor     eax, eax
    FRAME_EPILOG
    ret
vdta_no:
    mov     eax, EXIT_LOCKED
    FRAME_EPILOG
    ret
vk_derive_tpm_alone endp

; ===========================================================================
; vk_derive_tpm_pin() - Mode 2 (TPM + PIN) atomic pre-commit unlock.
;   -> eax = 0 (unlocked) / EXIT_AUTH (wrong PIN, g_tpm_pin_rem > 0) /
;            EXIT_LOCKED (tamper/replay or threshold reached -> auto-revoked).
; ===========================================================================
vk_derive_tpm_pin proc frame
    FRAME_PROLOG 64
    ; [rbp-16]=saved reqhello [rbp-20]=cur_slot [rbp-24]=next_slot [rbp-28]=fails_after
    mov     eax, dword ptr [g_tpm_reqhello]
    mov     dword ptr [rbp-16], eax
    mov     dword ptr [g_tpm_reqhello], 0
    mov     dword ptr [g_tpm_pin_rem], 0
    call    tpm_kn_build
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_tpm_blob]
    mov     r8d, TPM_BLOB_CAP
    call    reg_tpm_get
    cmp     eax, TPM_PIN_BLOB_SZ
    jne     vdtp_revoke
    lea     r10, [g_tpm_blob]
    cmp     dword ptr [r10+0], TPM_ENV_MAGIC
    jne     vdtp_revoke
    cmp     word ptr [r10+4], TPM_ENV_VER
    jne     vdtp_revoke
    cmp     byte ptr [r10+6], TPM_MODE_PIN
    jne     vdtp_revoke
    movzx   ecx, byte ptr [r10+7]               ; slot in {0, 1}
    cmp     ecx, 1
    ja      vdtp_revoke
    cmp     dword ptr [r10+8], 0
    jne     vdtp_revoke
    cmp     dword ptr [r10+12], TPM_PIN_BLOB_SZ
    jne     vdtp_revoke
    mov     dword ptr [rbp-20], ecx             ; cur_slot
    xor     ecx, 1
    mov     dword ptr [rbp-24], ecx             ; next_slot

    ; 1) Unseal outer state_key[32] using Vordr-<KCV>-S{cur_slot}
    mov     ecx, dword ptr [rbp-20]
    call    tpm_kn_slot_build
    lea     rcx, [g_tpm_kn_s]
    lea     rdx, [g_tpm_blob + 16]
    mov     r8d, 256
    lea     r9, [g_tpm_cand]
    call    tpm_unseal
    cmp     eax, 1
    jne     vdtp_revoke                         ; replayed old HKCU snapshot -> S{cur_slot} gone/rotated!

    ; 2) Authenticate + decrypt InnerState[380]
    mov     ecx, 16
    call    tpm_build_aad
    lea     r10, [g_greq]
    lea     rax, [g_tpm_cand]
    mov     qword ptr [r10].GCMREQ.key, rax
    lea     rax, [g_tpm_blob + 272]
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_tpm_aad]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, 16 + VH_INV_AAD
    lea     rax, [g_tpm_blob + 284]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     qword ptr [r10].GCMREQ.inlen, ST_SIZE
    lea     rax, [g_tpm_state]
    mov     qword ptr [r10].GCMREQ.outp, rax
    lea     rax, [g_tpm_blob + 664]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_greq]
    call    gcm_open
    mov     dword ptr [rbp-32], eax
    lea     rcx, [g_tpm_cand]
    mov     edx, 32
    call    secure_zero
    cmp     dword ptr [rbp-32], 0
    jne     vdtp_revoke

    ; 3) Validate InnerState invariants + honour tightened policy ceiling
    cmp     qword ptr [g_tpm_state + ST_GEN], 1
    jb      vdtp_revoke
    cmp     word ptr [g_tpm_state + ST_TLEN], 256
    jne     vdtp_revoke
    mov     eax, dword ptr [g_tpm_state + ST_MAXFAILS]
    cmp     eax, 1
    jb      vdtp_revoke
    cmp     eax, TPM_PIN_TRIES_MAX
    ja      vdtp_revoke
    mov     ecx, dword ptr [g_tpm_pin_max]
    cmp     ecx, 1
    jb      @F
    cmp     ecx, eax
    jae     @F
    mov     eax, ecx
    mov     dword ptr [g_tpm_state + ST_MAXFAILS], eax
@@: mov     edx, dword ptr [g_tpm_state + ST_FAILS]
    cmp     edx, eax
    jae     vdtp_revoke

    ; 4) ATOMIC PRE-COMMIT BEFORE TESTING PIN:
    ;    Increment fails' = fails + 1, gen' = gen + 1, rotate S{cur} -> S{next},
    ;    write updated HKCU blob, and destroy S{cur} BEFORE Argon2id / PIN check!
    inc     edx
    mov     dword ptr [rbp-28], edx             ; fails_after
    mov     dword ptr [g_tpm_state + ST_FAILS], edx
    inc     qword ptr [g_tpm_state + ST_GEN]
    WINCALL GetSystemTimeAsFileTime, addr g_tpm_state + ST_LASTFT
    mov     ecx, dword ptr [rbp-24]             ; next_slot
    call    tpm_pin_seal_state
    test    eax, eax
    jz      vdtp_failclosed                     ; could not commit counter -> refuse PIN check!
    mov     ecx, dword ptr [rbp-20]             ; delete old S{cur_slot}
    call    tpm_kn_slot_build
    lea     rcx, [g_tpm_kn_s]
    call    tpm_delete

    ; 5) Stretch entered PIN + unseal machine PCP secret + unwrap g_vkey
    call    tpm_pin_stretch
    test    eax, eax
    jz      vdtp_badpin
    call    tpm_kn_build
    lea     rcx, [g_tpm_kn]
    lea     rdx, [g_tpm_state + ST_CTTPM]
    mov     r8d, 256
    lea     r9, [g_tpm_sec]
    call    tpm_unseal
    cmp     eax, 1
    jne     vdtp_badpin
    lea     r10, [g_tpm_dk + 32]
    lea     r11, [g_tpm_sec + 32]
    xor     ecx, ecx
vdtp_cpw:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      vdtp_cpw
    lea     rcx, [g_tpm_sec]
    mov     edx, 64
    lea     r8, [g_tpm_cand]
    mov     r9d, 32
    call    blake2b_hash
    xor     ecx, ecx
    call    tpm_build_aad
    lea     r10, [g_greq]
    lea     rax, [g_tpm_cand]
    mov     qword ptr [r10].GCMREQ.key, rax
    lea     rax, [g_tpm_state + ST_VKIV]
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_tpm_aad]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, VH_INV_AAD
    lea     rax, [g_tpm_state + ST_VKCT]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     qword ptr [r10].GCMREQ.inlen, 32
    lea     rax, [g_vkey]
    mov     qword ptr [r10].GCMREQ.outp, rax
    lea     rax, [g_tpm_state + ST_VKTAG]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_greq]
    call    gcm_open
    test    eax, eax
    jnz     vdtp_badpin
    call    vk_kcv
    lea     rcx, [g_sha32]
    lea     rdx, [g_hdr + VH_KCV]
    mov     r8, KCV_LEN
    call    ct_memcmp
    test    eax, eax
    jnz     vdtp_badpin

    ; 6) PIN VALID: reset fails = 0, increment gen, rotate S{next} -> S{cur}
    mov     dword ptr [g_tpm_state + ST_FAILS], 0
    inc     qword ptr [g_tpm_state + ST_GEN]
    WINCALL GetSystemTimeAsFileTime, addr g_tpm_state + ST_LASTFT
    mov     eax, dword ptr [g_tpm_state + ST_MAXFAILS]
    mov     dword ptr [g_tpm_pin_rem], eax
    mov     ecx, dword ptr [rbp-20]             ; rotate back to fresh S{cur_slot}
    call    tpm_pin_seal_state
    test    eax, eax
    jz      @F
    mov     ecx, dword ptr [rbp-24]             ; delete S{next_slot}
    call    tpm_kn_slot_build
    lea     rcx, [g_tpm_kn_s]
    call    tpm_delete
@@: call    tpm_wipe_scratch
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_tpm_reqhello], eax
    xor     eax, eax
    FRAME_EPILOG
    ret

vdtp_badpin:
    lea     rcx, [g_vkey]
    mov     edx, 32
    call    secure_zero
    mov     eax, dword ptr [g_tpm_state + ST_MAXFAILS]
    mov     edx, dword ptr [rbp-28]             ; fails_after
    cmp     edx, eax
    jae     vdtp_revoke                         ; reached X failed attempts -> revoke!
    sub     eax, edx
    mov     dword ptr [g_tpm_pin_rem], eax
    call    tpm_wipe_scratch
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_tpm_reqhello], eax
    mov     eax, EXIT_AUTH
    FRAME_EPILOG
    ret

vdtp_revoke:
    call    tpm_wipe_scratch
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_tpm_reqhello], eax
    call    vault_tpm_forget
    mov     dword ptr [g_tpm_pin_rem], 0
    mov     eax, EXIT_LOCKED
    FRAME_EPILOG
    ret

vdtp_failclosed:
    call    tpm_wipe_scratch
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_tpm_reqhello], eax
    mov     eax, EXIT_LOCKED
    FRAME_EPILOG
    ret
vk_derive_tpm_pin endp

; ===========================================================================
; vk_derive_tpm_hello() - Mode 3 (TPM + Windows Hello) dual-key unlock.
; ===========================================================================
vk_derive_tpm_hello proc frame
    FRAME_PROLOG 48
    ; [rbp-16]=saved reqhello [rbp-20]=blob_len [rbp-24]=ct_hello_len [rbp-32]=tail_ptr
    mov     eax, dword ptr [g_tpm_reqhello]
    mov     dword ptr [rbp-16], eax
    mov     dword ptr [g_tpm_reqhello], 0
    call    tpm_kn_build
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_tpm_blob]
    mov     r8d, TPM_BLOB_CAP
    call    reg_tpm_get
    cmp     eax, 84
    jb      vdth_fail
    cmp     eax, TPM_BLOB_CAP
    ja      vdth_fail
    mov     dword ptr [rbp-20], eax
    lea     r10, [g_tpm_blob]
    cmp     dword ptr [r10+0], TPM_ENV_MAGIC
    jne     vdth_fail
    cmp     word ptr [r10+4], TPM_ENV_VER
    jne     vdth_fail
    cmp     byte ptr [r10+6], TPM_MODE_HELLO
    jne     vdth_fail
    cmp     dword ptr [r10+12], eax
    jne     vdth_fail
    cmp     word ptr [r10+16], 256              ; ct_tpm_len == 256
    jne     vdth_fail
    movzx   ecx, word ptr [r10+18]              ; ct_hello_len in [64, 512]
    cmp     ecx, 64
    jb      vdth_fail
    cmp     ecx, 512
    ja      vdth_fail
    mov     dword ptr [rbp-24], ecx
    lea     edx, [rcx + 276 + 60]
    cmp     edx, eax
    jne     vdth_fail
    lea     rax, [g_tpm_blob + 276]
    add     rax, rcx
    mov     qword ptr [rbp-32], rax             ; tail = vkey_iv[12] || vkey_ct[32] || vkey_tag[16]

    ; 1) Silent machine-bound PCP unseal -> g_tpm_sec[0..31]
    lea     rcx, [g_tpm_kn]
    lea     rdx, [g_tpm_blob + 20]
    mov     r8d, 256
    lea     r9, [g_tpm_sec]
    call    tpm_unseal
    cmp     eax, 1
    jne     vdth_fail

    ; 2) Live Windows Hello unseal (Face / Fingerprint / Hello PIN) -> g_tpm_sec[32..63]
    lea     rcx, [g_tpm_blob + 276]
    mov     edx, dword ptr [rbp-24]
    lea     r8, [g_tpm_sec + 32]
    call    tpm_hello_unseal
    cmp     eax, 1
    jne     vdth_fail

    ; 3) Derive dual-key AES-256-GCM key and unwrap g_vkey
    mov     ecx, 20
    call    tpm_build_aad
    lea     rcx, [g_tpm_sec]
    mov     edx, 64
    lea     r8, [g_tpm_cand]
    mov     r9d, 32
    call    blake2b_hash
    mov     r11, qword ptr [rbp-32]
    lea     r10, [g_greq]
    lea     rax, [g_tpm_cand]
    mov     qword ptr [r10].GCMREQ.key, rax
    mov     qword ptr [r10].GCMREQ.iv, r11
    lea     rax, [g_tpm_aad]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, 20 + VH_INV_AAD
    lea     rax, [r11 + 12]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     qword ptr [r10].GCMREQ.inlen, 32
    lea     rax, [g_vkey]
    mov     qword ptr [r10].GCMREQ.outp, rax
    lea     rax, [r11 + 44]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_greq]
    call    gcm_open
    test    eax, eax
    jnz     vdth_fail
    call    tpm_wipe_scratch
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_tpm_reqhello], eax
    xor     eax, eax
    FRAME_EPILOG
    ret

vdth_fail:
    lea     rcx, [g_vkey]
    mov     edx, 32
    call    secure_zero
    call    tpm_wipe_scratch
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_tpm_reqhello], eax
    mov     eax, EXIT_LOCKED
    FRAME_EPILOG
    ret
vk_derive_tpm_hello endp

; ===========================================================================
; vk_derive_tpm() - dispatch by g_use_tpm (TPM_MODE_ALONE / PIN / HELLO).
;   -> eax = 0 / EXIT_AUTH / EXIT_LOCKED.
; ===========================================================================
vk_derive_tpm proc frame
    FRAME_PROLOG 32
    mov     eax, dword ptr [g_use_tpm]
    cmp     eax, TPM_MODE_ALONE
    je      vdt_m1
    cmp     eax, TPM_MODE_PIN
    je      vdt_m2
    cmp     eax, TPM_MODE_HELLO
    je      vdt_m3
    mov     eax, EXIT_LOCKED
    FRAME_EPILOG
    ret
vdt_m1:
    call    vk_derive_tpm_alone
    FRAME_EPILOG
    ret
vdt_m2:
    call    vk_derive_tpm_pin
    FRAME_EPILOG
    ret
vdt_m3:
    call    vk_derive_tpm_hello
    FRAME_EPILOG
    ret
vk_derive_tpm endp

; ===========================================================================
; vault_tpm_remember() -> eax = 1/0.  Mode 1 (TPM Alone) enrollment.
; ===========================================================================
public vault_tpm_remember
vault_tpm_remember proc frame
    FRAME_PROLOG 48
    call    tpm_stash_prev_hello
    mov     dword ptr [rbp-16], eax
    call    tpm_kn_build
    lea     rcx, [g_tpm_kn]
    lea     rdx, [g_vkey]
    lea     r8, [g_tpm_blob + 16]
    mov     r9d, 256
    call    tpm_seal
    cmp     eax, 256
    jne     vtr_fail
    lea     r10, [g_tpm_blob]
    mov     dword ptr [r10+0],  TPM_ENV_MAGIC
    mov     word ptr  [r10+4],  TPM_ENV_VER
    mov     byte ptr  [r10+6],  TPM_MODE_ALONE
    mov     byte ptr  [r10+7],  0
    mov     dword ptr [r10+8],  0
    mov     dword ptr [r10+12], 272
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_tpm_blob]
    mov     r8d, 272
    call    reg_tpm_set
    test    eax, eax
    jz      vtr_fail
    call    tpm_del_slots_silent
    mov     ecx, dword ptr [rbp-16]
    call    tpm_del_stashed_hello
    mov     eax, 1
    FRAME_EPILOG
    ret
vtr_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_tpm_remember endp

; ===========================================================================
; vault_tpm_enroll_pin() -> eax = 1/0.  Mode 2 (TPM + PIN) enrollment.
;   Precondition: g_vkey + g_hdr + g_cfg_in valid; g_tpm_pin_u8[0..g_tpm_pin_u8len]
;   holds the validated UTF-8 PIN (always wiped before returning).
; ===========================================================================
public vault_tpm_enroll_pin
vault_tpm_enroll_pin proc frame
    FRAME_PROLOG 48
    ; [rbp-16]=saved reqhello [rbp-20]=old_hello_len
    mov     eax, dword ptr [g_tpm_reqhello]
    mov     dword ptr [rbp-16], eax
    mov     dword ptr [g_tpm_reqhello], 0
    cmp     dword ptr [g_tpm_pin_u8len], 0
    je      vtep_fail
    call    tpm_stash_prev_hello
    mov     dword ptr [rbp-20], eax
    lea     rcx, [g_tpm_state]
    mov     edx, 384
    call    secure_zero
    lea     rcx, [g_tpm_state + ST_SALT]
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      vtep_fail
    lea     rcx, [g_tpm_sec]
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      vtep_fail
    lea     rcx, [g_tpm_state + ST_VKIV]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      vtep_fail
    call    tpm_pin_stretch
    test    eax, eax
    jz      vtep_fail
    call    tpm_kn_build
    lea     rcx, [g_tpm_kn]
    lea     rdx, [g_tpm_sec]
    lea     r8, [g_tpm_state + ST_CTTPM]
    mov     r9d, 256
    call    tpm_seal
    cmp     eax, 256
    jne     vtep_fail
    mov     word ptr [g_tpm_state + ST_TLEN], 256
    lea     r10, [g_tpm_dk + 32]
    lea     r11, [g_tpm_sec + 32]
    xor     ecx, ecx
vtep_cpw:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      vtep_cpw
    lea     rcx, [g_tpm_sec]
    mov     edx, 64
    lea     r8, [g_tpm_cand]
    mov     r9d, 32
    call    blake2b_hash
    xor     ecx, ecx
    call    tpm_build_aad
    lea     r10, [g_greq]
    lea     rax, [g_tpm_cand]
    mov     qword ptr [r10].GCMREQ.key, rax
    lea     rax, [g_tpm_state + ST_VKIV]
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_tpm_aad]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, VH_INV_AAD
    lea     rax, [g_vkey]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     qword ptr [r10].GCMREQ.inlen, 32
    lea     rax, [g_tpm_state + ST_VKCT]
    mov     qword ptr [r10].GCMREQ.outp, rax
    lea     rax, [g_tpm_state + ST_VKTAG]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_greq]
    call    gcm_seal
    mov     qword ptr [g_tpm_state + ST_GEN], 1
    mov     dword ptr [g_tpm_state + ST_FAILS], 0
    mov     eax, dword ptr [g_tpm_pin_max]
    cmp     eax, 1
    jae     @F
    mov     eax, TPM_PIN_TRIES_DEF
@@: cmp     eax, TPM_PIN_TRIES_MAX
    jbe     @F
    mov     eax, TPM_PIN_TRIES_MAX
@@: mov     dword ptr [g_tpm_state + ST_MAXFAILS], eax
    mov     dword ptr [g_tpm_pin_rem], eax
    WINCALL GetSystemTimeAsFileTime, addr g_tpm_state + ST_LASTFT
    xor     ecx, ecx                            ; initial slot = S0
    call    tpm_pin_seal_state
    test    eax, eax
    jz      vtep_delmain
    mov     ecx, 1                              ; remove stale S1 if any
    call    tpm_kn_slot_build
    lea     rcx, [g_tpm_kn_s]
    call    tpm_delete
    mov     ecx, dword ptr [rbp-20]
    call    tpm_del_stashed_hello
    call    tpm_wipe_scratch
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_tpm_reqhello], eax
    mov     eax, 1
    FRAME_EPILOG
    ret
vtep_delmain:
    lea     rcx, [g_tpm_kn]
    call    tpm_delete
vtep_fail:
    call    tpm_wipe_scratch
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_tpm_reqhello], eax
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_tpm_enroll_pin endp

; ===========================================================================
; vault_tpm_enroll_hello() -> eax = 1/0.  Mode 3 (TPM + Windows Hello) enrollment.
;   Prompts live Windows Hello verification BEFORE touching existing TPM keys/HKCU.
; ===========================================================================
public vault_tpm_enroll_hello
vault_tpm_enroll_hello proc frame
    FRAME_PROLOG 64
    ; [rbp-16]=saved reqhello [rbp-20]=ct_hello_len [rbp-24]=total_len
    ; [rbp-32]=tail_ptr       [rbp-36]=old_hello_len
    mov     eax, dword ptr [g_tpm_reqhello]
    mov     dword ptr [rbp-16], eax
    mov     dword ptr [g_tpm_reqhello], 0
    call    tpm_stash_prev_hello
    mov     dword ptr [rbp-36], eax
    lea     rcx, [g_tpm_sec]                    ; tpm_secret[32] || hello_secret[32]
    mov     edx, 64
    call    rng_fill
    test    eax, eax
    jz      vteh_fail
    ; 1) Create Windows Hello FIDO2 PRF credential FIRST (so user cancel leaves
    ;    any existing Mode 1 / Mode 2 / Mode 3 enrollment untouched!)
    lea     rcx, [g_tpm_sec + 32]
    lea     rdx, [g_tpm_blob + 276]
    mov     r8d, 512
    call    tpm_hello_seal
    cmp     eax, 65
    jb      vteh_fail
    cmp     eax, 512
    ja      vteh_fail
    mov     dword ptr [rbp-20], eax
    lea     ecx, [rax + 276 + 60]
    mov     dword ptr [rbp-24], ecx
    lea     rdx, [g_tpm_blob + 276]
    add     rdx, rax
    mov     qword ptr [rbp-32], rdx             ; tail = vkey_iv[12] || vkey_ct[32] || vkey_tag[16]
    mov     rcx, rdx
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      vteh_delnew
    ; 2) Seal tpm_secret[32] to machine PCP key Vordr-<KCV>
    call    tpm_kn_build
    lea     rcx, [g_tpm_kn]
    lea     rdx, [g_tpm_sec]
    lea     r8, [g_tpm_blob + 20]
    mov     r9d, 256
    call    tpm_seal
    cmp     eax, 256
    jne     vteh_delnew
    ; 3) Header + dual-key AES-256-GCM wrap of g_vkey
    lea     r10, [g_tpm_blob]
    mov     dword ptr [r10+0],  TPM_ENV_MAGIC
    mov     word ptr  [r10+4],  TPM_ENV_VER
    mov     byte ptr  [r10+6],  TPM_MODE_HELLO
    mov     byte ptr  [r10+7],  0
    mov     dword ptr [r10+8],  0
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [r10+12], eax
    mov     word ptr  [r10+16], 256
    mov     eax, dword ptr [rbp-20]
    mov     word ptr  [r10+18], ax
    mov     ecx, 20
    call    tpm_build_aad
    lea     rcx, [g_tpm_sec]
    mov     edx, 64
    lea     r8, [g_tpm_cand]
    mov     r9d, 32
    call    blake2b_hash
    mov     r11, qword ptr [rbp-32]
    lea     r10, [g_greq]
    lea     rax, [g_tpm_cand]
    mov     qword ptr [r10].GCMREQ.key, rax
    mov     qword ptr [r10].GCMREQ.iv, r11
    lea     rax, [g_tpm_aad]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, 20 + VH_INV_AAD
    lea     rax, [g_vkey]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     qword ptr [r10].GCMREQ.inlen, 32
    lea     rax, [r11 + 12]
    mov     qword ptr [r10].GCMREQ.outp, rax
    lea     rax, [r11 + 44]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_greq]
    call    gcm_seal
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_tpm_blob]
    mov     r8d, dword ptr [rbp-24]
    call    reg_tpm_set
    test    eax, eax
    jz      vteh_delmain
    call    tpm_del_slots_silent
    mov     ecx, dword ptr [rbp-36]
    call    tpm_del_stashed_hello
    call    tpm_wipe_scratch
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_tpm_reqhello], eax
    mov     eax, 1
    FRAME_EPILOG
    ret
vteh_delmain:
    lea     rcx, [g_tpm_kn]
    call    tpm_delete
vteh_delnew:
    lea     rcx, [g_tpm_blob + 276]
    mov     edx, dword ptr [rbp-20]
    call    tpm_hello_delete
vteh_fail:
    call    tpm_wipe_scratch
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_tpm_reqhello], eax
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_tpm_enroll_hello endp

; ===========================================================================
; vault_tpm_forget() -> eax = 1.  Delete all TPM keys (main + S0 + S1), any
;   Windows Hello platform credential, and HKCU\..\TPM-Unlock for this vault.
; ===========================================================================
public vault_tpm_forget
vault_tpm_forget proc frame
    FRAME_PROLOG 32
    ; [rbp-16]=saved reqhello [rbp-20]=old_hello_len
    call    tpm_stash_prev_hello
    mov     dword ptr [rbp-20], eax
    call    tpm_kn_build
    mov     eax, dword ptr [g_tpm_reqhello]
    mov     dword ptr [rbp-16], eax
    mov     dword ptr [g_tpm_reqhello], 0
    lea     rcx, [g_tpm_kn]
    call    tpm_delete
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_tpm_reqhello], eax
    test    eax, eax
    jz      @F
    lea     rcx, [g_tpm_kn]
    call    tpm_delete
@@: call    tpm_del_slots_silent
    mov     rcx, qword ptr [g_cfg_in]       ; value name = vault path
    call    reg_tpm_del
    mov     ecx, dword ptr [rbp-20]
    call    tpm_del_stashed_hello
    mov     eax, 1
    FRAME_EPILOG
    ret
vault_tpm_forget endp

; ===========================================================================
; vault_tpm_has() -> eax = 1 if a valid TPM-Unlock registry entry exists for
;   g_cfg_in, else 0.  Keyed by the vault path, so it works pre-header.
; ===========================================================================
public vault_tpm_has
vault_tpm_has proc frame
    FRAME_PROLOG 32
    call    vault_tpm_mode_get
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
;   into the caller's buffer.  Clobbers rax/rcx/r8/r9/r10/r11, preserves rdx.
;
;   The base comes through path_io rather than straight from g_cfg_in.  All three
;   derived names - .bak<n>, .tmp, .lock - are built by copying that string and
;   appending, so if the base is a long path that Win32 will not accept without
;   a "\?" prefix, every derivation inherits the problem.  Converting here means
;   it does not matter which of the thirty-odd places that set g_cfg_in did so.
; ===========================================================================
vault_mkbak proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rdx           ; path_io is not a leaf: save the digit
    mov     qword ptr [rbp-32], rcx
    mov     rcx, qword ptr [g_cfg_in]
    call    path_io
    mov     r10, rax
    mov     rdx, qword ptr [rbp-24]
    mov     r11, qword ptr [rbp-32]
    xor     r8, r8
vmb_cp:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      vmb_suf
    inc     r8
    cmp     r8, MAX_PATH_CHARS-8
    jb      vmb_cp
    mov     word ptr [r11], 0                   ; base path too long -> refuse truncation
    xor     eax, eax
    FRAME_EPILOG
    ret
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
    mov     eax, 1
    FRAME_EPILOG
    ret
vault_mkbak endp

; ===========================================================================
; vault_copy_dacl(rcx = src_wpath, rdx = dst_wpath) - best-effort copy of the
;   source file's DACL (including SE_DACL_PROTECTED when set) onto dst_wpath so
;   MoveFileExW fallbacks and .bak1..3 backups never widen explicit vault ACLs.
; ===========================================================================
vault_copy_dacl proc frame
    FRAME_PROLOG 128
    ; [rbp-24]=src [rbp-32]=dst [rbp-40]=pDacl [rbp-48]=pSD [rbp-56]=ctrl [rbp-60]=rev
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], 0
    mov     qword ptr [rbp-48], 0
    WINCALL GetNamedSecurityInfoW, rcx, 1, 4, 0, 0, addr rbp-40, 0, addr rbp-48
    test    eax, eax
    jnz     vcd_done
    cmp     qword ptr [rbp-40], 0
    je      vcd_free
    mov     word ptr [rbp-56], 0
    mov     dword ptr [rbp-60], 0
    WINCALL GetSecurityDescriptorControl, qword ptr [rbp-48], addr rbp-56, addr rbp-60
    mov     r8d, 4                              ; DACL_SECURITY_INFORMATION
    test    eax, eax
    jz      vcd_set
    test    word ptr [rbp-56], 1000h            ; SE_DACL_PROTECTED
    jz      vcd_set
    mov     r8d, 80000004h                      ; DACL | PROTECTED_DACL_SECURITY_INFORMATION
vcd_set:
    WINCALL SetNamedSecurityInfoW, qword ptr [rbp-32], 1, r8d, 0, 0, qword ptr [rbp-40], 0
vcd_free:
    cmp     qword ptr [rbp-48], 0
    je      vcd_done
    WINCALL LocalFree, qword ptr [rbp-48]
vcd_done:
    FRAME_EPILOG
    ret
vault_copy_dacl endp

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
; bak_not_reparse(rcx = wpath) -> eax = 1 safe (absent or regular file) / 0 reparse point.
bak_not_reparse proc frame
    FRAME_PROLOG 32
    WINCALL GetFileAttributesW, rcx
    cmp     eax, -1
    je      bnr_ok                              ; absent -> safe
    test    eax, 0400h                          ; FILE_ATTRIBUTE_REPARSE_POINT
    jnz     bnr_bad
bnr_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
bnr_bad:
    xor     eax, eax
    FRAME_EPILOG
    ret
bak_not_reparse endp

vault_rotate_backups proc frame
    FRAME_PROLOG 80
    mov     dword ptr [g_bak_staged], 0
    ; Skip backup staging if live vault does not exist yet or is a reparse point.
    mov     rcx, qword ptr [g_cfg_in]
    call    path_io
    mov     qword ptr [rbp-48], rax
    WINCALL GetFileAttributesW, rax
    cmp     eax, -1
    je      vrb_done
    test    eax, 0400h                          ; FILE_ATTRIBUTE_REPARSE_POINT
    jnz     vrb_done
    ; Refuse to stage/rotate if any .bak0..3 slot is a planted reparse point / too long.
    lea     rcx, [g_bak_a]
    mov     dl, '0' + BAK_GENS
    call    vault_mkbak
    test    eax, eax
    jz      vrb_done
    lea     rcx, [g_bak_a]
    call    bak_not_reparse
    test    eax, eax
    jz      vrb_done
    lea     rcx, [g_bak_b]
    mov     dl, '0' + BAK_GENS - 1
    call    vault_mkbak
    test    eax, eax
    jz      vrb_done
    lea     rcx, [g_bak_b]
    call    bak_not_reparse
    test    eax, eax
    jz      vrb_done
    lea     rcx, [g_bak_b]
    mov     dl, '1'
    call    vault_mkbak
    test    eax, eax
    jz      vrb_done
    lea     rcx, [g_bak_b]
    call    bak_not_reparse
    test    eax, eax
    jz      vrb_done
    lea     rcx, [g_bak_a]
    mov     dl, '0'
    call    vault_mkbak
    test    eax, eax
    jz      vrb_done
    lea     rcx, [g_bak_a]
    call    bak_not_reparse
    test    eax, eax
    jz      vrb_done
    ; Stage live vault -> .bak0 BEFORE touching .bak1..3; only rotate after file_rename succeeds!
    WINCALL DeleteFileW, addr g_bak_a
    WINCALL CopyFileW, qword ptr [rbp-48], addr g_bak_a, 1
    test    eax, eax
    jz      vrb_done
    mov     rcx, qword ptr [rbp-48]
    lea     rdx, [g_bak_a]
    call    vault_copy_dacl
    mov     dword ptr [g_bak_staged], 1
vrb_done:
    FRAME_EPILOG
    ret
vault_rotate_backups endp

vault_commit_backups proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_bak_staged], 0
    je      vcb_done
    mov     dword ptr [g_bak_staged], 0
    lea     rcx, [g_bak_a]                      ; delete oldest (bak3)
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
    lea     rcx, [g_bak_a]                      ; staged bak0 -> bak1
    mov     dl, '0'
    call    vault_mkbak
    lea     rcx, [g_bak_b]
    mov     dl, '1'
    call    vault_mkbak
    WINCALL MoveFileExW, addr g_bak_a, addr g_bak_b, MOVEFILE_REPLACE_EXISTING
vcb_done:
    FRAME_EPILOG
    ret
vault_commit_backups endp

vault_abort_backup proc frame
    FRAME_PROLOG 32
    cmp     dword ptr [g_bak_staged], 0
    je      vab_done
    mov     dword ptr [g_bak_staged], 0
    lea     rcx, [g_bak_a]
    mov     dl, '0'
    call    vault_mkbak
    test    eax, eax
    jz      vab_done
    WINCALL DeleteFileW, addr g_bak_a
vab_done:
    FRAME_EPILOG
    ret
vault_abort_backup endp

; ===========================================================================
; vault_seal_write() - seal g_body (g_body_len bytes) under g_vkey with a fresh
;   nonce already placed in g_hdr, build the file image, write it to g_cfg_in.
;   -> eax = 0 / EXIT_IO / EXIT_OOM.
; ===========================================================================
vault_seal_write proc frame
    FRAME_PROLOG 96
    ; [rbp-32] = attachment section bytes (entries + trailer)  [rbp-40] = base len
    ; Never write a vault that cannot be opened again.  vault_unlock validates the
    ; body after decrypting and refuses a malformed one outright - so a body that
    ; fails here would lock the user out, and the backup ring (three saves deep)
    ; rotates the last good copy away.  Checking costs one linear walk.
    call    vault_body_validate
    test    eax, eax
    jnz     vsw_refuse
    cmp     dword ptr [g_att_ovf], 0            ; the index could not hold every
    jne     vsw_refuse                          ;   attachment: saving would drop some
    cmp     qword ptr [g_save_counter], -1      ; refuse u64 counter wrap to 0
    je      vsw_refuse
    mov     dword ptr [g_att_missing], 0
    xor     ecx, ecx                            ; emit=0: size the attachment section
    xor     edx, edx
    xor     r8d, r8d
    call    attach_build
    cmp     dword ptr [g_att_missing], 0
    jne     vsw_refuse
    mov     qword ptr [rbp-32], rax
    ; base image = VH_TOTAL + body_len + 16 + attachment section (checked u64 adds)
    mov     rax, qword ptr [g_body_len]
    cmp     rax, VAULT_BODY_MAX
    ja      vsw_refuse
    add     rax, VH_TOTAL + 16
    jc      vsw_refuse
    add     rax, qword ptr [rbp-32]
    jc      vsw_refuse
    mov     qword ptr [rbp-40], rax             ; base length (before the MAC trailer)
    add     rax, FMAC_TRAILER                   ; + [u64 counter][32 MAC][u32 magic]
    jc      vsw_refuse
    mov     ecx, ATT_TOTAL_MAX + VAULT_BODY_MAX + 4096
    cmp     rax, rcx
    ja      vsw_refuse
    mov     qword ptr [g_outlen], rax
    mov     rcx, rax
    call    mem_alloc
    test    rax, rax
    jz      vsw_oom
    mov     qword ptr [g_outbuf], rax
    mov     dword ptr [rbp-56], 0               ; nonce retry count (VATT tag collision guard)
vsw_seal_try:
    ; copy header (80 bytes)
    lea     r10, [g_hdr]
    mov     r11, qword ptr [g_outbuf]
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
    jne     vsw_emit_att
    ; No attachments: the last 12 bytes of the base image are tag[4..15].  Ensure
    ; tag[4..7] never accidentally equals ATT_MAGIC ("VATT"), re-noncing if so.
    mov     r10, qword ptr [g_outbuf]
    add     r10, VH_TOTAL
    add     r10, qword ptr [g_body_len]
    cmp     dword ptr [r10+4], ATT_MAGIC
    jne     vsw_write
    inc     dword ptr [rbp-56]
    cmp     dword ptr [rbp-56], 8
    jae     vsw_io
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      vsw_io
    jmp     vsw_seal_try
vsw_emit_att:
    mov     ecx, 1                              ; emit=1
    mov     rdx, qword ptr [g_outbuf]
    add     rdx, VH_TOTAL + 16
    add     rdx, qword ptr [g_body_len]
    mov     r8, qword ptr [g_outbuf]
    add     r8, qword ptr [rbp-40]              ; dst_end = base offset (before FMAC_TRAILER)
    call    attach_build
    cmp     dword ptr [g_att_missing], 0
    je      vsw_write
    mov     dword ptr [rbp-24], EXIT_CORRUPT    ; an attachment had no ciphertext: refuse
    jmp     vsw_free                            ;   rather than write it away
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
    mov     rcx, qword ptr [g_cfg_in]         ; via path_io, so a long vault path
    call    path_io                           ;   yields a usable "<vault>.tmp"
    mov     r10, rax
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
    mov     word ptr [r11], 0                   ; base path too long -> refuse truncation
    jmp     vsw_io_dec
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
    ; Retry the delete+create pair, not just the rename below.  A vault in a synced
    ; folder (OneDrive) is routinely held open by the sync client: the DeleteFileW
    ; then fails, the exclusive CREATE_NEW that follows fails with ERROR_FILE_EXISTS,
    ; and nothing retried it - which is what surfaced as "Could not create the vault"
    ; on a machine with 110 GB free and an idle disk.  Same cadence as file_rename.
    mov     dword ptr [rbp-48], 0                ; attempt count
vsw_wtry:
    WINCALL DeleteFileW, addr g_tmppath
    mov     dword ptr [g_wf_disp], 1             ; CREATE_NEW (one-shot; re-armed per try)
    lea     rcx, [g_tmppath]
    mov     rdx, qword ptr [g_outbuf]
    mov     r8, qword ptr [g_outlen]
    call    write_file
    test    eax, eax
    jz      vsw_wok
    mov     r10d, dword ptr [g_io_err]           ; only transient contention is retried;
    cmp     r10d, 80                             ;   a real failure still fails at once
    je      vsw_wretry                           ; ERROR_FILE_EXISTS (stale temp still held)
    cmp     r10d, 32
    je      vsw_wretry                           ; ERROR_SHARING_VIOLATION
    cmp     r10d, 33
    je      vsw_wretry                           ; ERROR_LOCK_VIOLATION
    cmp     r10d, 5
    je      vsw_wretry                           ; ERROR_ACCESS_DENIED
    jmp     vsw_io_cleanup
vsw_wretry:
    inc     dword ptr [rbp-48]
    cmp     dword ptr [rbp-48], 10               ; 10 attempts (~9s), then give up
    jae     vsw_io_cleanup
    WINCALL Sleep, 1000
    jmp     vsw_wtry
vsw_wok:
    ; Preserve any explicit/protected DACL from the live vault onto .tmp (for MoveFileExW fallback)
    mov     rcx, qword ptr [g_cfg_in]
    call    path_io
    mov     rcx, rax
    lea     rdx, [g_tmppath]
    call    vault_copy_dacl
    ; Stage the current file into .bak0 before overwrite (.bak1..3 untouched until rename succeeds)
    call    vault_rotate_backups
    ; atomic replace: rename temp -> the real vault path
    lea     rcx, [g_tmppath]
    mov     rdx, qword ptr [g_cfg_in]
    call    file_rename
    mov     dword ptr [rbp-24], eax
    test    eax, eax
    jnz     vsw_rename_fail                     ; rename failed -> abort backup, delete .tmp, roll back counter
    call    vault_commit_backups
    ; success: the image we just wrote becomes the resident file image, so newly
    ; sealed attachments are readable without a re-read.  Retire the old image,
    ; drop the pending list, and rebuild the attachment index.
    ;
    ; ...unless this seal wrote a DIFFERENT vault (vault_export_sel).  Adopting there is
    ; actively destructive: it frees the master's resident image, repoints g_filebuf at
    ; the child, and attach_reset drops g_attidx - so every attachment in the still-open
    ; master then resolves against the child's image, and the next master save feeds
    ; attach_build from it.  That is the shape of 9ee91da, where stranded attachments
    ; were destroyed on the following save.  Nothing can be "restored" afterwards either,
    ; because the master's image has already been freed by then.
    cmp     dword ptr [g_seal_noadopt], 0
    je      vsw_adopt
    mov     rcx, qword ptr [g_outbuf]           ; nobody takes ownership -> release it
    test    rcx, rcx
    jz      vsw_naret
    mov     rdx, qword ptr [g_outlen]
    call    mem_free
    mov     qword ptr [g_outbuf], 0
vsw_naret:
    mov     eax, dword ptr [rbp-24]             ; the live vault is left exactly as it was
    FRAME_EPILOG
    ret
vsw_adopt:
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
vsw_rename_fail:
    call    vault_abort_backup
    WINCALL DeleteFileW, addr g_tmppath
    dec     qword ptr [g_save_counter]
    jmp     vsw_free
vsw_io_cleanup:
    WINCALL DeleteFileW, addr g_tmppath
vsw_io_dec:
    dec     qword ptr [g_save_counter]
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
vsw_refuse:
    mov     eax, EXIT_CORRUPT                   ; nothing allocated, nothing written
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
    ; read the whole file - unless the caller already did it for us, off the
    ; secure desktop (vault_preload)
    cmp     dword ptr [g_preloaded], 0
    jne     vu_haveimage
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_filebuf]
    lea     r8, [g_filesize]
    call    read_file
    test    eax, eax
    jnz     vu_io
vu_haveimage:
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
    ; PRE-AUTH DoS guard: the KDF cost parameters come straight from the (as-yet
    ; unauthenticated) header and must be run BEFORE the file MAC can be checked.
    ; A crafted file could set m_cost to a huge value -> a giant KDF allocation on
    ; a victim who merely OPENS the file (no password needed).  Reject params no
    ; legitimate Vordr vault could carry (bounds below) as corrupt/tamper.
    call    vk_params_ok
    test    eax, eax
    jz      vu_corrupt
    ; derive key (TPM sidecar or master password) + KCV check
    cmp     dword ptr [g_reuse_key], 0  ; C8 reload: g_vkey already derived - skip Argon2
    jne     vu_havekey                  ; (KCV below still re-verifies it fits the file)
    cmp     dword ptr [g_use_tpm], 0
    je      vu_pwderive
    call    vk_derive_tpm
    test    eax, eax
    jnz     vu_cleanfile                ; preserve EXIT_AUTH vs EXIT_LOCKED from vk_derive_tpm
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
    mov     r9, qword ptr [r11+4]               ; attachment entries length (untrusted u64)
    cmp     r9, rax                             ; entries_len alone must be < effective end;
    jae     vu_ctlen                            ;   reject first so the +112 below cannot WRAP
    mov     rcx, r9                             ;   (a near-2^64 value would wrap small and slip
    add     rcx, VH_TOTAL + 16 + ATT_TRAILER + 4 ;   past the plausibility check)
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
    jz      vu_gcm_ok
    ; VATT tag-collision fallback: an attachment-free vault whose 16-byte GCM tag
    ; happened to carry ATT_MAGIC at tag[4..7] and a small u64 at tag[8..15] would
    ; otherwise subtract a phantom attachment section from ctlen.  Retry once with
    ; g_att_total = 0 before reporting EXIT_AUTH.
    cmp     qword ptr [g_att_total], 0
    je      vu_auth
    mov     qword ptr [g_att_total], 0
    mov     rax, qword ptr [g_filesize]
    sub     rax, qword ptr [g_fmac_len]
    sub     rax, VH_TOTAL + 16
    cmp     rax, VAULT_BODY_MAX
    ja      vu_auth
    mov     qword ptr [rbp-24], rax
    mov     r10, rax
    add     r10, VH_TOTAL + 16
    mov     qword ptr [g_att_start], r10
    lea     r10, [g_greq]
    mov     qword ptr [r10].GCMREQ.inlen, rax
    mov     r11, qword ptr [g_filebuf]
    lea     rcx, [r11+VH_TOTAL]
    add     rcx, rax
    mov     qword ptr [r10].GCMREQ.tag, rcx
    lea     rcx, [g_greq]
    call    gcm_open
    test    eax, eax
    jnz     vu_auth
vu_gcm_ok:
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
    lea     rcx, [g_sha32]
    mov     edx, 32
    call    secure_zero
    cmp     dword ptr [g_reuse_key], 0          ; vault_reload reuses the live master key:
    jne     @F                                  ;   only wipe newly-derived candidate keys
    lea     rcx, [g_vkey]
    mov     edx, 32
    call    secure_zero
@@: cmp     dword ptr [g_preloaded], 0          ; a preloaded image belongs to the caller:
    jne     vu_ret                              ;   freeing it here would send the next
                                                ;   wrong-password retry back to the file,
                                                ;   which is the I/O we moved off the
                                                ;   secure desktop in the first place
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

; =============================================================================
; vault_preload() -> eax = 0 ok / EXIT_*.  Read the vault image into g_filebuf
;   BEFORE the unlock dialog opens, so vault_unlock does no file I/O.
;
;   The unlock dialog can run on a private desktop, and that desktop is only
;   restored once the dialog returns - so a read that blocks inside it (a vault in
;   a OneDrive-synced folder, a cloud placeholder being materialised, a busy sync
;   engine) strands the user on a desktop with no shell.  Argon2 and the AEAD are
;   bounded CPU and stay in the dialog, where a wrong password can keep it open;
;   only the unbounded part moves out.
;
;   No-op when something is already resident: this is only for the clean
;   launch -> unlock path, and silently discarding a live image would be worse
;   than the read it saves.
; =============================================================================
public vault_preload
vault_preload proc frame
    FRAME_PROLOG 48
    mov     dword ptr [g_preloaded], 0
    cmp     qword ptr [g_filebuf], 0
    jne     vpl_skip
    cmp     qword ptr [g_cfg_in], 0
    je      vpl_skip
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_filebuf]
    lea     r8, [g_filesize]
    call    read_file
    test    eax, eax
    jnz     vpl_ret                              ; leave it unset: vault_unlock will
    mov     dword ptr [g_preloaded], 1           ;   read (and report) the error itself
vpl_skip:
    xor     eax, eax
vpl_ret:
    FRAME_EPILOG
    ret
vault_preload endp

; =============================================================================
; vault_preload_end(ecx = 1 if the vault is now open) - drop the preload claim.
;   On success the image IS the live vault image and vault_unlock owns it from
;   here.  On failure or cancel nobody owns it, so release it - vault_unlock's
;   cleanup deliberately left it alone while retries were still possible.
; =============================================================================
public vault_preload_end
vault_preload_end proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], ecx
    cmp     dword ptr [g_preloaded], 0
    je      vpe_ret
    mov     dword ptr [g_preloaded], 0
    cmp     dword ptr [rbp-24], 0
    jne     vpe_ret                              ; opened: the image is the vault's now
    mov     rcx, qword ptr [g_filebuf]
    test    rcx, rcx
    jz      vpe_ret
    mov     rdx, qword ptr [g_filesize]
    call    mem_free
    mov     qword ptr [g_filebuf], 0
vpe_ret:
    FRAME_EPILOG
    ret
vault_preload_end endp

; vault_lock() - wipe + free the secmem body and wipe the master key.
public vault_lock
vault_lock proc frame
    FRAME_PROLOG 32
    mov     dword ptr [g_eidx_n], 0              ; no entry index survives a lock
    mov     dword ptr [g_eidx_dep], 0
    mov     rcx, qword ptr [g_eidx]
    mov     edx, dword ptr [g_eidx_cap]
    shl     rdx, 3
    call    mem_free
    mov     qword ptr [g_eidx], 0
    mov     dword ptr [g_eidx_cap], 0
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
    lea     rcx, [g_sha32]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_fmac_ctx]
    mov     edx, 256
    call    secure_zero
    lea     rcx, [g_fmac_out]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_conv]                       ; wipe plaintext field-value scratch
    mov     edx, CONV_CAP
    call    secure_zero
    lea     rcx, [g_convlabel]                  ; wipe plaintext field-label scratch
    mov     edx, MAX_LABEL_BYTES
    call    secure_zero
    call    tpm_wipe_scratch
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
    FRAME_PROLOG 48
    ; The open vault is parked, not freed, before the re-read.  This used to free the
    ; body and image FIRST and then try - so any failure (the file momentarily
    ; unreadable, a network share gone, a different password on the new file) left
    ; the window open on no vault at all, every caller reporting success or saying
    ; nothing, and the next Save dereferencing a null body.
    call    vault_state_park
    mov     qword ptr [g_body_ptr], 0           ; vault_unlock allocates its own
    mov     qword ptr [g_filebuf], 0
    mov     dword ptr [g_reuse_key], 1          ; re-open reusing g_vkey (skip the KDF)
    call    vault_unlock
    mov     dword ptr [g_reuse_key], 0
    mov     dword ptr [rbp-24], eax
    test    eax, eax
    jnz     vr_fail
    mov     rcx, qword ptr [g_ps_body]          ; success: release what it replaced
    mov     rdx, VAULT_BODY_MAX
    call    secmem_free
    mov     rcx, qword ptr [g_ps_filebuf]
    test    rcx, rcx
    jz      vr_drop
    mov     rdx, qword ptr [g_ps_filesize]
    call    mem_free
vr_drop:
    call    attach_reset_pending                ; staged attachments belonged to the
    jmp     vr_ret                              ;   edit the reload just discarded
vr_fail:
    call    vault_state_restore                 ; vault_unlock released its own partial
vr_ret:                                         ;   allocations; the old vault is back
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
vault_reload endp

; ===========================================================================
; vault_state_park / vault_state_restore - snapshot every global vault_unlock
;   writes for an OPEN vault, so a second vault_unlock (a reload, or a foreign
;   vault being read for import) can be undone exactly.  The attachment INDEX is
;   copied as a table, not just its count: vault_unlock rebuilds it from whatever
;   file it opened, and restoring only g_attidx_n left the open vault's slots
;   holding the other file's ids and pointers into an image that was then freed -
;   so the next save wrote every affected attachment away as empty ciphertext.
; ===========================================================================
vault_state_park proc frame
    FRAME_PROLOG 48
    mov     rax, qword ptr [g_body_ptr]
    mov     qword ptr [g_ps_body], rax
    mov     rax, qword ptr [g_body_len]
    mov     qword ptr [g_ps_bodylen], rax
    mov     rax, qword ptr [g_filebuf]
    mov     qword ptr [g_ps_filebuf], rax
    mov     rax, qword ptr [g_filesize]
    mov     qword ptr [g_ps_filesize], rax
    mov     rax, qword ptr [g_fmac_len]
    mov     qword ptr [g_ps_fmac], rax
    mov     rax, qword ptr [g_att_total]
    mov     qword ptr [g_ps_atttotal], rax
    mov     rax, qword ptr [g_att_start]
    mov     qword ptr [g_ps_attstart], rax
    mov     rax, qword ptr [g_save_counter]
    mov     qword ptr [g_ps_counter], rax
    mov     rax, qword ptr [g_ext_size]
    mov     qword ptr [g_ps_extsize], rax
    mov     eax, dword ptr [g_attidx_n]
    mov     dword ptr [g_ps_attidxn], eax
    mov     eax, dword ptr [g_att_ovf]
    mov     dword ptr [g_ps_attovf], eax
    mov     eax, dword ptr [g_rollback]
    mov     dword ptr [g_ps_rollback], eax
    lea     rcx, [g_ps_hdr]
    lea     rdx, [g_hdr]
    mov     r8d, VH_TOTAL
    call    copy_bytes
    lea     rcx, [g_ps_ehash]
    lea     rdx, [g_ext_hash]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [g_ps_attidx]
    lea     rdx, [g_attidx]
    mov     r8d, dword ptr [g_attidx_n]
    shl     r8d, 5                              ; 32 bytes per index row
    call    copy_bytes
    FRAME_EPILOG
    ret
vault_state_park endp

vault_state_restore proc frame
    FRAME_PROLOG 48
    mov     rax, qword ptr [g_ps_body]
    mov     qword ptr [g_body_ptr], rax
    mov     rax, qword ptr [g_ps_bodylen]
    mov     qword ptr [g_body_len], rax
    mov     rax, qword ptr [g_ps_filebuf]
    mov     qword ptr [g_filebuf], rax
    mov     rax, qword ptr [g_ps_filesize]
    mov     qword ptr [g_filesize], rax
    mov     rax, qword ptr [g_ps_fmac]
    mov     qword ptr [g_fmac_len], rax
    mov     rax, qword ptr [g_ps_atttotal]
    mov     qword ptr [g_att_total], rax
    mov     rax, qword ptr [g_ps_attstart]
    mov     qword ptr [g_att_start], rax
    mov     rax, qword ptr [g_ps_counter]
    mov     qword ptr [g_save_counter], rax
    mov     rax, qword ptr [g_ps_extsize]
    mov     qword ptr [g_ext_size], rax
    mov     eax, dword ptr [g_ps_attidxn]
    mov     dword ptr [g_attidx_n], eax
    mov     eax, dword ptr [g_ps_attovf]
    mov     dword ptr [g_att_ovf], eax
    mov     eax, dword ptr [g_ps_rollback]
    mov     dword ptr [g_rollback], eax
    lea     rcx, [g_hdr]
    lea     rdx, [g_ps_hdr]
    mov     r8d, VH_TOTAL
    call    copy_bytes
    lea     rcx, [g_ext_hash]
    lea     rdx, [g_ps_ehash]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [g_attidx]
    mov     edx, MAX_ATTIDX * 32
    call    secure_zero
    lea     rcx, [g_attidx]
    lea     rdx, [g_ps_attidx]
    mov     r8d, dword ptr [g_attidx_n]
    shl     r8d, 5
    call    copy_bytes
    FRAME_EPILOG
    ret
vault_state_restore endp

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
    FRAME_PROLOG 80
    ; [rbp-24]=body ptr  [rbp-32]=body_len  [rbp-40]=offset
    ; [rbp-48]=entries remaining  [rbp-56]=fields remaining  [rbp-64]=att section total
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
    mov     qword ptr [rbp-64], 0               ; cumulative attachment section bytes
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
    movzx   r9d, word ptr [r10+rcx]             ; raw type (kind | flags)
    mov     r8d, dword ptr [r10+rcx+2]          ; field len (zero-extended into r8)
    lea     rdx, [rcx+6]
    add     rdx, r8                             ; field end offset
    jc      vbv_bad
    cmp     rdx, qword ptr [rbp-32]             ; whole field within the body?
    ja      vbv_bad
    lea     rdx, [r10+rcx+6]                    ; default val_ptr = field+6
    mov     r11, r8                             ; default val_len = field len
    test    r9d, VF_LABELED                     ; labelled field: {u16 labellen, label, value}
    jz      vbv_kind
    cmp     r8, 2
    jb      vbv_bad                             ; no room for the labellen prefix
    movzx   eax, word ptr [r10+rcx+6]           ; labellen
    add     eax, 2
    cmp     rax, r8                             ; 2 + labellen must fit inside the field
    ja      vbv_bad
    add     rdx, rax                            ; val_ptr past {u16 labellen, label}
    sub     r11, rax                            ; val_len = field len - (2 + labellen)
vbv_kind:
    ; Validate typed binary fields so downstream readers can never OOB-read or wrap u64:
    ;   1) VF_IMAGE / VF_FILE: >= ARF_SIZE, ARF_PTLEN <= ATT_FILE_MAX, cumulative section
    ;      <= ATT_TOTAL_MAX, and any trailing wide filename even-length + NUL-terminated.
    ;   2) VF_PWHIST (13): unlabelled, even length >= 10, wide NUL-terminated string(s)
    ;      after the 8-byte FILETIME, with 0 or 4 trailing action bytes after the 2nd NUL.
    mov     eax, r9d
    and     eax, VF_KINDMASK                    ; base kind
    cmp     eax, VF_IMAGE
    je      vbv_atref
    cmp     eax, VF_FILE
    je      vbv_atref
    cmp     eax, VF_PWHIST
    je      vbv_pwhist
    jmp     vbv_fadv
vbv_atref:
    cmp     r11, ARF_SIZE
    jb      vbv_bad
    mov     rax, qword ptr [rdx+ARF_PTLEN]      ; untrusted u64 plaintext length
    cmp     rax, ATT_FILE_MAX
    ja      vbv_bad
    add     rax, ATT_ENThDR + 16
    add     qword ptr [rbp-64], rax
    jc      vbv_bad
    mov     eax, ATT_TOTAL_MAX
    cmp     qword ptr [rbp-64], rax
    ja      vbv_bad
    cmp     r11, ARF_SIZE                       ; bare 68-byte AttachRef (no filename) is ok
    je      vbv_fadv
    mov     rax, r11
    sub     rax, ARF_SIZE
    test    rax, 1                              ; trailing wide filename must be even bytes
    jnz     vbv_bad
    cmp     word ptr [rdx+r11-2], 0             ; ...and end with a wide NUL
    jne     vbv_bad
    jmp     vbv_fadv
vbv_pwhist:
    test    r9d, VF_LABELED                     ; VF_PWHIST is never labelled
    jnz     vbv_bad
    cmp     r11, 10                             ; at least {u64 ft, wide NUL}
    jb      vbv_bad
    test    r11, 1                              ; 8 + wide*2 (+ optional u32 action) -> even
    jnz     vbv_bad
    mov     rax, 8
vbv_ph1:
    cmp     rax, r11
    jae     vbv_bad                             ; missing 1st wide NUL
    cmp     word ptr [rdx+rax], 0
    lea     rax, [rax+2]
    jne     vbv_ph1
    cmp     rax, r11
    je      vbv_fadv                            ; legacy v1 shape: {u64 ft, pw\0}
vbv_ph2:
    cmp     rax, r11
    jae     vbv_bad                             ; missing 2nd wide NUL
    cmp     word ptr [rdx+rax], 0
    lea     rax, [rax+2]
    jne     vbv_ph2
    mov     rcx, r11
    sub     rcx, rax
    test    rcx, rcx
    jz      vbv_fadv                            ; v2 shape: {u64 ft, label\0, pw\0}
    cmp     rcx, 4
    jne     vbv_bad                             ; v3 shape: {u64 ft, label\0, pw\0, u32 act}
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
public copy_bytes
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

; ===========================================================================
; cmd_kdfparam - regression for the PRE-AUTH KDF-parameter DoS guard.  A crafted
;   .vordr header carries the Argon2 t_cost/m_cost, which vault_unlock must run
;   BEFORE it can authenticate the file (the key is needed to check the MAC).  An
;   out-of-range m_cost would otherwise drive a giant allocation on a victim who
;   merely opens the file.  vk_params_ok gates it.  This probe asserts the exact
;   accept/reject boundary; with the guard removed the "reject" cases would pass
;   vk_params_ok and this probe FAILS (exit 1).
; ===========================================================================
CSTR kdp_ok,  "kdfparam: PASS (out-of-range KDF params rejected pre-auth; valid accepted)",13,10
CSTR kdp_bad, "kdfparam: FAIL (a dangerous KDF parameter was not rejected)",13,10
LANDING_PAD
public cmd_kdfparam
cmd_kdfparam proc frame
    FRAME_PROLOG 32
    ; --- must ACCEPT: legitimate params ---
    mov     dword ptr [g_hdr+VH_LANES], 1               ; native vaults always use p=1
    mov     dword ptr [g_hdr+VH_T], ARGON2_DEF_T        ; t=3, m=512 MiB (default)
    mov     dword ptr [g_hdr+VH_M], ARGON2_DEF_M_KIB
    call    vk_params_ok
    test    eax, eax
    jz      kdp_fail
    mov     dword ptr [g_hdr+VH_T], 1                   ; fast test vault: t=1, m=8 KiB
    mov     dword ptr [g_hdr+VH_M], 8
    call    vk_params_ok
    test    eax, eax
    jz      kdp_fail
    mov     dword ptr [g_hdr+VH_T], ARGON2_MAX_T        ; upper boundary: t=16, m=4 GiB
    mov     dword ptr [g_hdr+VH_M], ARGON2_MAX_M_KIB
    call    vk_params_ok
    test    eax, eax
    jz      kdp_fail
    ; --- must REJECT: the DoS / tamper vectors ---
    mov     dword ptr [g_hdr+VH_T], ARGON2_DEF_T        ; lanes != 1
    mov     dword ptr [g_hdr+VH_M], ARGON2_DEF_M_KIB
    mov     dword ptr [g_hdr+VH_LANES], 0
    call    vk_params_ok
    test    eax, eax
    jnz     kdp_fail
    mov     dword ptr [g_hdr+VH_LANES], 2
    call    vk_params_ok
    test    eax, eax
    jnz     kdp_fail
    mov     dword ptr [g_hdr+VH_LANES], 1               ; restore valid lanes for t/m tests
    mov     dword ptr [g_hdr+VH_T], ARGON2_DEF_T        ; m_cost = 0
    mov     dword ptr [g_hdr+VH_M], 0
    call    vk_params_ok
    test    eax, eax
    jnz     kdp_fail
    mov     dword ptr [g_hdr+VH_M], ARGON2_MIN_M_KIB - 1 ; below the RFC 9106 floor
    call    vk_params_ok
    test    eax, eax
    jnz     kdp_fail
    mov     dword ptr [g_hdr+VH_M], ARGON2_MAX_M_KIB + 1 ; just over 4 GiB
    call    vk_params_ok
    test    eax, eax
    jnz     kdp_fail
    mov     dword ptr [g_hdr+VH_M], 0FFFFFFFFh          ; attacker's ~4 TiB request
    call    vk_params_ok
    test    eax, eax
    jnz     kdp_fail
    mov     dword ptr [g_hdr+VH_T], 0                   ; t_cost = 0
    mov     dword ptr [g_hdr+VH_M], ARGON2_DEF_M_KIB
    call    vk_params_ok
    test    eax, eax
    jnz     kdp_fail
    mov     dword ptr [g_hdr+VH_T], ARGON2_MAX_T + 1    ; t_cost > 16
    call    vk_params_ok
    test    eax, eax
    jnz     kdp_fail
    lea     rcx, [kdp_ok]
    mov     edx, kdp_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
kdp_fail:
    lea     rcx, [kdp_bad]
    mov     edx, kdp_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_kdfparam endp

; ===========================================================================
; cmd_vaultexportkat <path> - M6 headless KAT for vault export + merge-import.
;   Seeds a 3-entry source vault at <path>, exports every entry to a fresh vault
;   <path>.exp under a DIFFERENT password, reopens it, and asserts the 3 entry ids
;   round-trip (export preserved id16/created/modified, not a rebuild).  Then it
;   snapshots the exported body and merges it back into itself, asserting ZERO
;   changes (dedup by entry id is idempotent).  Uses m=8 KiB Argon2 for speed.
;   Exit 0 = pass.  (No attachments in v1 - the entries are text-only.)
; ===========================================================================
LANDING_PAD
public cmd_vaultexportkat
cmd_vaultexportkat proc frame
    FRAME_PROLOG 64
    ; locals (all above the callee shadow): [rbp-24]=scratch1 [rbp-32]=scratch2 [rbp-40]=i
    mov     dword ptr [g_cfg_t], 1            ; fast KDF for the gate (logic KAT, not a cost test)
    mov     dword ptr [g_cfg_m], 8
    lea     r10, [g_argv]                     ; source path A = argv[2]
    mov     rax, qword ptr [r10+16]
    mov     rcx, rax
    call    cfg_in_set
    mov     r10, rax                          ; build g_vx_pathb = A + ".exp"
    lea     r11, [g_vx_pathb]
    xor     r8d, r8d
vxk_pcpy:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      vxk_pdone
    inc     r8d
    cmp     r8d, MAX_PATH_CHARS-8
    jb      vxk_pcpy
vxk_pdone:
    mov     word ptr [r11+r8*2], '.'
    inc     r8d
    mov     word ptr [r11+r8*2], 'e'
    inc     r8d
    mov     word ptr [r11+r8*2], 'x'
    inc     r8d
    mov     word ptr [r11+r8*2], 'p'
    inc     r8d
    mov     word ptr [r11+r8*2], 0
    lea     r10, [ffk_seedpw]                 ; seed password -> g_cfg_pass
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
vxk_pw1:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      vxk_pw1d
    inc     ecx
    cmp     ecx, 32
    jb      vxk_pw1
vxk_pw1d:
    mov     dword ptr [g_cfg_passlen], 9
    mov     ecx, 3                            ; seed a 3-entry source vault
    call    do_seed
    test    eax, eax
    mov     eax, 2
    jnz     vxk_ret
    call    vk_derive                         ; unlock A (re-derive + reuse key)
    mov     dword ptr [g_reuse_key], 1
    call    vault_unlock
    mov     dword ptr [g_reuse_key], 0
    test    eax, eax
    mov     eax, 3
    jnz     vxk_ret
    call    vault_count
    cmp     eax, 3
    jne     vxk_fail
    mov     dword ptr [rbp-40], 0            ; snapshot the 3 entry ids
vxk_idsnap:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, 3
    jae     vxk_idsnapd
    mov     ecx, eax
    call    vault_entry_ptr
    mov     r10d, dword ptr [rbp-40]
    imul    r10d, r10d, 16
    lea     r11, [g_vx_ids]
    add     r11, r10
    xor     ecx, ecx
vxk_idcp:
    mov     dl, byte ptr [rax+rcx]
    mov     byte ptr [r11+rcx], dl
    inc     ecx
    cmp     ecx, 16
    jb      vxk_idcp
    inc     dword ptr [rbp-40]
    jmp     vxk_idsnap
vxk_idsnapd:
    mov     rcx, VAULT_BODY_MAX               ; snapshot the source body to scratch1
    call    secmem_alloc
    test    rax, rax
    jz      vxk_fail
    mov     qword ptr [rbp-24], rax
    mov     rcx, rax
    mov     rdx, qword ptr [g_body_ptr]
    mov     r8d, dword ptr [g_body_len]
    call    copy_bytes
    call    vault_lock                        ; free A body/image/key
    lea     r10, [vxk_exppw]                  ; export password -> g_cfg_pass
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
vxk_pw2:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      vxk_pw2d
    inc     ecx
    cmp     ecx, 32
    jb      vxk_pw2
vxk_pw2d:
    mov     dword ptr [g_cfg_passlen], 9
    lea     rax, [g_vx_pathb]                 ; export target = B
    mov     rcx, rax
    call    cfg_in_set
    mov     rcx, qword ptr [rbp-24]           ; source body scratch
    xor     edx, edx                          ; carry=0 (entries only)
    call    fed_export
    test    eax, eax
    mov     eax, 4
    jnz     vxk_ret
    call    vault_lock                        ; free the new body + B image
    call    vk_derive                         ; reopen B under the export password
    mov     dword ptr [g_reuse_key], 1
    call    vault_unlock
    mov     dword ptr [g_reuse_key], 0
    test    eax, eax
    mov     eax, 5
    jnz     vxk_ret
    call    vault_count
    cmp     eax, 3
    jne     vxk_fail
    mov     dword ptr [rbp-40], 0            ; assert the 3 ids survived the export
vxk_idchk:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, 3
    jae     vxk_idchkd
    mov     ecx, eax
    call    vault_entry_ptr
    mov     r10d, dword ptr [rbp-40]
    imul    r10d, r10d, 16
    lea     rdx, [g_vx_ids]
    add     rdx, r10
    mov     rcx, rax
    mov     r8d, 16
    call    ct_memcmp
    test    eax, eax
    jnz     vxk_fail
    inc     dword ptr [rbp-40]
    jmp     vxk_idchk
vxk_idchkd:
    mov     rcx, VAULT_BODY_MAX               ; idempotent re-merge: snapshot B, merge back
    call    secmem_alloc
    test    rax, rax
    jz      vxk_fail
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    mov     rdx, qword ptr [g_body_ptr]
    mov     r8d, dword ptr [g_body_len]
    call    copy_bytes
    mov     rcx, qword ptr [rbp-32]
    call    fed_merge
    test    eax, eax                          ; changed count must be 0 (idempotent)
    jnz     vxk_fail
    call    vault_count
    cmp     eax, 3
    jne     vxk_fail
    lea     rcx, [vxk_ok]
    mov     edx, vxk_ok_len
    call    print_a
    call    vault_lock
    xor     eax, eax
vxk_ret:
    FRAME_EPILOG
    ret
vxk_fail:
    lea     rcx, [vxk_bad]
    mov     edx, vxk_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_vaultexportkat endp

; ===========================================================================
; cmd_vaultexpattkat <path> - M6 attachment-carry KAT.  Builds a source vault at
;   <path> with one entry carrying two attachments (do_attgen: hello.txt + world.dat),
;   seals it, then EXPORTS it with carry=1 to <path>.ec under a DIFFERENT password,
;   reopens the child, and attach_open's both attachments - asserting the decrypted
;   plaintext matches the originals byte-for-byte.  Proves the export carries the
;   attachment ciphertext verbatim and it still decrypts under the child vault (the
;   blob is keyed by the AttachRef's own key, which travels in the entry).  Exit 0=pass.
; ===========================================================================
LANDING_PAD
public cmd_vaultexpattkat
cmd_vaultexpattkat proc frame
    FRAME_PROLOG 80                            ; [rbp-24]=scratch [rbp-32]=outlen [rbp-40]=entry
    mov     dword ptr [g_cfg_t], 1            ; fast KDF for the gate
    mov     dword ptr [g_cfg_m], 8
    lea     r10, [g_argv]                     ; source path A = argv[2]
    mov     rax, qword ptr [r10+16]
    mov     rcx, rax
    call    cfg_in_set
    mov     r10, rax                          ; child path = A + ".ec"
    lea     r11, [g_vx_pathb]
    xor     r8d, r8d
vea_pcpy:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      vea_pdone
    inc     r8d
    cmp     r8d, MAX_PATH_CHARS-8
    jb      vea_pcpy
vea_pdone:
    mov     word ptr [r11+r8*2], '.'
    inc     r8d
    mov     word ptr [r11+r8*2], 'e'
    inc     r8d
    mov     word ptr [r11+r8*2], 'c'
    inc     r8d
    mov     word ptr [r11+r8*2], 0
    lea     r10, [ffk_seedpw]                 ; seed password -> g_cfg_pass
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
vea_pw1:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      vea_pw1d
    inc     ecx
    cmp     ecx, 32
    jb      vea_pw1
vea_pw1d:
    mov     dword ptr [g_cfg_passlen], 9
    mov     dword ptr [g_hdr+0], VAULT_MAGIC  ; --- build source vault A on disk ---
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
    jz      vea_fail
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      vea_fail
    call    vk_derive
    test    eax, eax
    jnz     vea_fail
    call    vk_kcv
    lea     r10, [g_sha32]
    lea     r9, [g_hdr+VH_KCV]
    xor     r8d, r8d
vea_kcv:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r9+r8], al
    inc     r8d
    cmp     r8d, KCV_LEN
    jb      vea_kcv
    call    do_attgen                         ; 1 entry, title + 2 pending attachments
    test    eax, eax
    jnz     vea_fail
    mov     qword ptr [g_save_counter], 0
    call    vault_seal_write                  ; A on disk; attachments sealed; g_attidx live
    test    eax, eax
    jnz     vea_fail
    mov     rcx, VAULT_BODY_MAX               ; snapshot A body (keep A's attachment context)
    call    secmem_alloc
    test    rax, rax
    jz      vea_fail
    mov     qword ptr [rbp-24], rax
    mov     rcx, rax
    mov     rdx, qword ptr [g_body_ptr]
    mov     r8d, dword ptr [g_body_len]
    call    copy_bytes
    lea     r10, [vxk_exppw]                  ; export password -> g_cfg_pass
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
vea_pw2:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      vea_pw2d
    inc     ecx
    cmp     ecx, 32
    jb      vea_pw2
vea_pw2d:
    mov     dword ptr [g_cfg_passlen], 9
    lea     rax, [g_vx_pathb]                 ; export target = child
    mov     rcx, rax
    call    cfg_in_set
    mov     rcx, qword ptr [rbp-24]           ; source body scratch
    mov     edx, 1                            ; carry=1 (attachments)
    call    fed_export
    test    eax, eax
    jnz     vea_fail
    call    vault_lock
    call    vk_derive                         ; reopen the child under the export password
    mov     dword ptr [g_reuse_key], 1
    call    vault_unlock
    mov     dword ptr [g_reuse_key], 0
    test    eax, eax
    jnz     vea_fail
    call    vault_count
    cmp     eax, 1
    jne     vea_fail
    xor     ecx, ecx                          ; entry 0
    call    vault_entry_ptr
    mov     qword ptr [rbp-40], rax
    mov     rcx, rax                          ; VF_IMAGE attachment
    mov     edx, VF_IMAGE
    call    find_field_in
    test    rax, rax
    jz      vea_fail
    mov     rcx, rax                          ; rcx = AttachRef
    lea     rdx, [rbp-32]                     ; &outlen
    call    attach_open
    test    rax, rax
    jz      vea_fail
    mov     r10d, dword ptr [rbp-32]
    cmp     r10d, AG_PLAIN_LEN
    jne     vea_fail
    lea     r11, [ag_plain]                   ; compare decrypted bytes
    xor     ecx, ecx
vea_cmp1:
    mov     dl, byte ptr [rax+rcx]
    cmp     dl, byte ptr [r11+rcx]
    jne     vea_fail
    inc     ecx
    cmp     ecx, AG_PLAIN_LEN
    jb      vea_cmp1
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-32]
    call    attach_free
    mov     rcx, qword ptr [rbp-40]           ; VF_FILE attachment
    mov     edx, VF_FILE
    call    find_field_in
    test    rax, rax
    jz      vea_fail
    mov     rcx, rax
    lea     rdx, [rbp-32]
    call    attach_open
    test    rax, rax
    jz      vea_fail
    mov     r10d, dword ptr [rbp-32]
    cmp     r10d, AG_PLAI2_LEN
    jne     vea_fail
    lea     r11, [ag_plai2]
    xor     ecx, ecx
vea_cmp2:
    mov     dl, byte ptr [rax+rcx]
    cmp     dl, byte ptr [r11+rcx]
    jne     vea_fail
    inc     ecx
    cmp     ecx, AG_PLAI2_LEN
    jb      vea_cmp2
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-32]
    call    attach_free
    lea     rcx, [vea_ok]
    mov     edx, vea_ok_len
    call    print_a
    call    vault_lock
    xor     eax, eax
    FRAME_EPILOG
    ret
vea_fail:
    lea     rcx, [vea_bad]
    mov     edx, vea_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_vaultexpattkat endp

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
    mov     rcx, rax
    call    cfg_in_set
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
    mov     rcx, rax
    call    cfg_in_set
    call    vault_unlock
    mov     dword ptr [rbp-40], eax
    call    vault_lock
    mov     rax, qword ptr [rbp-32]             ; restore the real path
    mov     rcx, rax
    call    cfg_in_set
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
    mov     rcx, rax
    call    cfg_in_set
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
; cmd_rbtest <path> - prove anti-rollback detection and monotonic high-water
;   counter enforcement.  Create a vault (counter 1, mirror 1), force the HKCU
;   mirror ahead to 5, confirm unlock flags g_rollback == 1, confirm attempting
;   to lower the mirror back to 1 is refused by reg_ctr_set (still flags 1),
;   advance the vault on disk to counter 5 and confirm unlock clears g_rollback,
;   then push mirror to 9 and confirm upper-cased path spelling still flags 1.
; ===========================================================================
LANDING_PAD
public cmd_rbtest
cmd_rbtest proc frame
    FRAME_PROLOG 64                             ; [rbp-32] result scratch
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]
    mov     rcx, rax
    call    cfg_in_set
    mov     rcx, qword ptr [g_cfg_in]
    call    reg_ctr_del
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
    ; clear any recycled NTFS file-id counter from a prior run, then seed mirror = 1
    mov     rcx, qword ptr [g_cfg_in]
    call    reg_ctr_del
    mov     qword ptr [g_ctr_io], 1
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_ctr_io]
    mov     r8d, 8
    call    reg_ctr_set
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
    ; monotonic guard: attempting to lower the mirror from 5 -> 1 must be refused
    mov     qword ptr [g_ctr_io], 1
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_ctr_io]
    mov     r8d, 8
    call    reg_ctr_set
    call    vault_unlock
    test    eax, eax
    jnz     rb_fail
    call    vault_lock
    cmp     dword ptr [g_rollback], 1
    jne     rb_fail
    ; advance the vault's sealed counter to 5 -> catches up with mirror -> no rollback
    call    vault_unlock
    test    eax, eax
    jnz     rb_fail
    mov     qword ptr [g_save_counter], 4       ; vault_seal_write increments to 5
    call    vault_seal_write
    mov     dword ptr [rbp-32], eax
    call    vault_lock
    cmp     dword ptr [rbp-32], 0
    jne     rb_fail
    call    vault_unlock
    test    eax, eax
    jnz     rb_fail
    call    vault_lock
    cmp     dword ptr [g_rollback], 0
    jne     rb_fail
    ; ---- the mirror belongs to the FILE, not to one spelling of its path --------
    ; Push the mirror ahead again (9 > 5), then open the same vault under an
    ; upper-cased spelling: it must still be flagged.
    mov     qword ptr [g_ctr_io], 9
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [g_ctr_io]
    mov     r8d, 8
    call    reg_ctr_set
    mov     r10, qword ptr [g_cfg_in]            ; g_vx_pathb = upper-cased copy
    lea     r11, [g_vx_pathb]
    xor     ecx, ecx
rb_up:
    movzx   eax, word ptr [r10+rcx*2]
    cmp     eax, 'a'
    jb      rb_upput
    cmp     eax, 'z'
    ja      rb_upput
    sub     eax, 20h
rb_upput:
    mov     word ptr [r11+rcx*2], ax
    test    eax, eax
    jz      rb_updone
    inc     ecx
    cmp     ecx, MAX_PATH_CHARS-1
    jb      rb_up
    mov     word ptr [r11+rcx*2], 0
rb_updone:
    lea     rcx, [g_vx_pathb]
    call    cfg_in_set
    call    vault_unlock
    mov     dword ptr [rbp-32], eax
    call    vault_lock
    lea     r10, [g_argv]                        ; the original spelling back
    mov     rcx, qword ptr [r10+16]
    call    cfg_in_set
    cmp     dword ptr [rbp-32], 0
    jne     rb_fail
    cmp     dword ptr [g_rollback], 1
    jne     rb_fail
    mov     rcx, qword ptr [g_cfg_in]            ; scrub the scratch vault's mirror
    call    reg_ctr_del
    lea     rcx, [rb_ok]
    mov     edx, rb_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
rb_fail:
    cmp     qword ptr [g_cfg_in], 0
    je      @F
    mov     rcx, qword ptr [g_cfg_in]
    call    reg_ctr_del
@@: lea     rcx, [rb_bad]
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
    FRAME_PROLOG 80                             ; locals to -48, clear of the home area
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]             ; argv[2] = vault path
    mov     rcx, rax
    call    cfg_in_set
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
    ; ---- seal guard: a body the unlock would reject must never be written ------
    ; Mark field 0 of entry 0 as labelled without giving it a label prefix: exactly
    ; the shape a crafted import produced, which then locked the vault for good.
    xor     ecx, ecx
    call    vault_entry_ptr
    mov     qword ptr [rbp-40], rax
    or      word ptr [rax+36], VF_LABELED
    call    vault_reseal
    mov     dword ptr [rbp-48], eax
    mov     rax, qword ptr [rbp-40]
    and     word ptr [rax+36], 7FFFh            ; put it back
    cmp     dword ptr [rbp-48], EXIT_CORRUPT    ; refused, and refused as corrupt...
    jne     rl_faillk
    call    vault_ext_changed                   ; ...with nothing written
    test    eax, eax
    jnz     rl_faillk
    ; ---- a reload that FAILS must leave the open vault exactly as it was -------
    mov     rcx, qword ptr [g_cfg_in]           ; break the key check on disk: the
    lea     rdx, [rbp-24]                       ;   reload reuses g_vkey, so this file
    lea     r8, [rbp-32]                        ;   now reads as another password's
    call    read_file
    test    eax, eax
    jnz     rl_faillk
    mov     r10, qword ptr [rbp-24]
    xor     byte ptr [r10+VH_KCV], 0FFh
    mov     rcx, qword ptr [g_cfg_in]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-32]
    call    write_file
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
    mov     rax, qword ptr [g_body_ptr]
    mov     qword ptr [rbp-40], rax
    call    vault_reload
    test    eax, eax
    jz      rl_faillk                           ; it must not have "succeeded"
    mov     rax, qword ptr [g_body_ptr]
    cmp     rax, qword ptr [rbp-40]             ; same body, not freed or nulled
    jne     rl_faillk
    call    vault_count
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
; cmd_sysitemkat <path> - system items: prove the item is hidden from the user-facing
;   count, that the pwverify stamp survives a real seal/reload, and that adding twice
;   cannot produce two.  Seeds 3 user entries (do_seed makes NO system item, by
;   design) so the physical/user split is observable.
; ===========================================================================
LANDING_PAD
public cmd_sysitemkat
cmd_sysitemkat proc frame
    FRAME_PROLOG 80                             ; 80 -> 96 bytes: the 16-byte health struct at
                                                ;   [rbp-48] must clear the callee home area
    ; [rbp-24] = the stamp we plant and expect back; [rbp-48..-36] = vault_health out
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]             ; argv[2] = vault path
    mov     rcx, rax
    call    cfg_in_set
    lea     r10, [bk_pw]                        ; same fixed test password as cmd_reload
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
si_pwcp:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      si_pwd
    inc     ecx
    cmp     ecx, 32
    jb      si_pwcp
si_pwd:
    mov     dword ptr [g_cfg_passlen], 9
    mov     dword ptr [g_cfg_t], 1
    mov     dword ptr [g_cfg_m], 8192
    mov     ecx, 3                              ; create + seed 3 user entries
    call    do_seed
    test    eax, eax
    jnz     si_fail
    call    vault_unlock
    test    eax, eax
    jnz     si_fail
    ; --- a seeded vault has no system item -------------------------------------
    call    vault_sys_find
    cmp     eax, -1
    jne     si_faillk
    call    vault_user_count
    cmp     eax, 3
    jne     si_faillk
    call    vault_pwverify_get                  ; nothing stored yet
    test    rax, rax
    jnz     si_faillk
    ; --- lazy creation: a vault with no system item gains one on first set ------
    ; This is the migration path for vaults made before system items existed - no
    ; rewrite on unlock, just an item when there is finally something to keep.
    mov     rcx, 4142434445464748h
    call    vault_pwverify_set
    test    eax, eax
    jz      si_faillk
    call    vault_count                         ; the set created it: 3 users + 1 system
    cmp     eax, 4
    jne     si_faillk
    call    vault_pwverify_get
    mov     rcx, 4142434445464748h
    cmp     rax, rcx
    jne     si_faillk
    ; --- add one: physical 4, user still 3 -------------------------------------
    call    vault_add_system_item               ; already present -> must be a no-op
    test    eax, eax
    jz      si_faillk
    call    vault_count
    cmp     eax, 4
    jne     si_faillk
    call    vault_user_count
    cmp     eax, 3
    jne     si_faillk
    call    vault_sys_find                      ; appended last
    cmp     eax, 3
    jne     si_faillk
    mov     ecx, 3
    call    vault_is_system
    test    eax, eax
    jz      si_faillk
    xor     ecx, ecx                            ; a user entry must NOT read as system
    call    vault_is_system
    test    eax, eax
    jnz     si_faillk
    ; --- idempotent: a second add must not make a second item ------------------
    call    vault_add_system_item
    test    eax, eax
    jz      si_faillk
    call    vault_count
    cmp     eax, 4
    jne     si_faillk
    ; --- plant the stamp, persist, and re-read from disk ------------------------
    mov     rcx, 1122334455667788h
    mov     qword ptr [rbp-24], rcx
    call    vault_pwverify_set
    test    eax, eax
    jz      si_faillk
    call    vault_pwverify_get
    cmp     rax, qword ptr [rbp-24]
    jne     si_faillk
    call    vault_reseal
    test    eax, eax
    jnz     si_faillk
    call    vault_lock
    call    vault_unlock                        ; fresh Argon2 derive + body from disk
    test    eax, eax
    jnz     si_fail
    call    vault_count                         ; the item survived the round trip...
    cmp     eax, 4
    jne     si_faillk
    call    vault_user_count                    ; ...and is still hidden
    cmp     eax, 3
    jne     si_faillk
    call    vault_pwverify_get                  ; ...and the stamp came back intact
    cmp     rax, qword ptr [rbp-24]
    jne     si_faillk
    ; --- the exclusions: health totals and last-user selection -------------------
    ; vault_health's loop bound stays physical (it indexes entries) but its reported
    ; total must not count the system item.
    lea     rcx, [rbp-48]                       ; health {weak,reused,old,total}
    call    vault_health
    cmp     dword ptr [rbp-36], 3               ; total = users only, not 4
    jne     si_faillk
    ; "the entry just written" must never resolve to the system item, which sits LAST
    ; here because this vault gained it after seeding (the migrated-vault shape).
    call    vault_last_user
    cmp     eax, 2                              ; entries 0..2 are users, 3 is the system item
    jne     si_faillk
    ; --- M6 merge: a FOREIGN system item must not land as a second one -----------
    ; Merging a body into itself would prove nothing: dedup is by entry id, so the
    ; system item would be skipped as "not newer" whether or not the filter exists.
    ; Flip a byte of the snapshot's id so it looks like another vault's item.
    mov     rcx, VAULT_BODY_MAX
    call    secmem_alloc
    test    rax, rax
    jz      si_faillk
    mov     qword ptr [rbp-32], rax             ; snapshot
    mov     rcx, rax
    mov     rdx, qword ptr [g_body_ptr]
    mov     r8d, dword ptr [g_body_len]
    call    copy_bytes
    mov     ecx, 3                              ; live entry 3 = the system item
    call    vault_entry_ptr
    sub     rax, qword ptr [g_body_ptr]         ; -> its byte offset within the body
    add     rax, qword ptr [rbp-32]             ; -> the same spot in the snapshot
    xor     byte ptr [rax], 0FFh                ; now a foreign entry id
    mov     rcx, qword ptr [rbp-32]
    call    fed_merge
    mov     dword ptr [rbp-40], eax             ; changed count (checked after the free)
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, VAULT_BODY_MAX
    call    secmem_free
    cmp     dword ptr [rbp-40], 0               ; users dedup, system item filtered -> 0
    jne     si_faillk
    call    vault_count                         ; and no second system item was appended
    cmp     eax, 4
    jne     si_faillk
    call    vault_user_count                    ; a second one would also hide a user entry
    cmp     eax, 3
    jne     si_faillk
    ; --- M6: a child vault must not inherit the parent's system item -------------
    ; fed_export builds the child body, ADOPTS it as the live body, then seals - so
    ; after it returns the live state IS the child and can be inspected directly.
    mov     r10, qword ptr [g_cfg_in]           ; g_vx_pathb = <path> + ".exp"
    lea     r11, [g_vx_pathb]
    xor     r8d, r8d
si_pcpy:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      si_pdone
    inc     r8d
    cmp     r8d, MAX_PATH_CHARS-8
    jb      si_pcpy
si_pdone:
    mov     word ptr [r11+r8*2], '.'
    inc     r8d
    mov     word ptr [r11+r8*2], 'e'
    inc     r8d
    mov     word ptr [r11+r8*2], 'x'
    inc     r8d
    mov     word ptr [r11+r8*2], 'p'
    inc     r8d
    mov     word ptr [r11+r8*2], 0
    lea     rax, [g_vx_pathb]
    mov     rcx, rax
    call    cfg_in_set           ; child target
    mov     rcx, qword ptr [g_body_ptr]         ; export the live body, text-only
    xor     edx, edx
    call    fed_export
    test    eax, eax
    jnz     si_fail                             ; on failure the body is already freed/adopted
    call    vault_count                         ; the child carries the 3 user entries only
    cmp     eax, 3
    jne     si_faillk
    call    vault_sys_find                      ; ...no system item came across...
    cmp     eax, -1
    jne     si_faillk
    call    vault_pwverify_get                  ; ...so its clock starts at "never" rather
    test    rax, rax                            ;    than inheriting the parent's verification
    jnz     si_faillk
    call    vault_lock
    lea     rcx, [si_ok]
    mov     edx, si_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
si_faillk:
    call    vault_lock
si_fail:
    lea     rcx, [si_bad]
    mov     edx, si_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_sysitemkat endp

; ===========================================================================
; cmd_vexselkat <path> - vault_export_sel: prove a .vordr export writes ONLY the
;   ticked entries, never the system item, and leaves the master vault open and
;   byte-identical - the whole point of not reusing fed_export.
; ===========================================================================
LANDING_PAD
public cmd_vexselkat
cmd_vexselkat proc frame
    FRAME_PROLOG 96
    ; [rbp-24] = saved master body ptr, [rbp-32] = child path
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]             ; argv[2] = master vault path
    mov     rcx, rax
    call    cfg_in_set
    mov     r10, rax                            ; g_vx_pathb = <path> + ".exp"
    lea     r11, [g_vx_pathb]
    xor     r8d, r8d
xk_pcpy:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      xk_pdone
    inc     r8d
    cmp     r8d, MAX_PATH_CHARS-8
    jb      xk_pcpy
xk_pdone:
    mov     word ptr [r11+r8*2], '.'
    inc     r8d
    mov     word ptr [r11+r8*2], 'e'
    inc     r8d
    mov     word ptr [r11+r8*2], 'x'
    inc     r8d
    mov     word ptr [r11+r8*2], 'p'
    inc     r8d
    mov     word ptr [r11+r8*2], 0
    lea     rax, [g_vx_pathb]
    mov     qword ptr [rbp-32], rax
    lea     r10, [ffk_seedpw]                   ; master password
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
xk_pw1:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      xk_pw1d
    inc     ecx
    cmp     ecx, 32
    jb      xk_pw1
xk_pw1d:
    mov     dword ptr [g_cfg_passlen], 9
    mov     dword ptr [g_cfg_t], 1
    mov     dword ptr [g_cfg_m], 8192
    mov     ecx, 3
    call    do_seed
    test    eax, eax
    jnz     xk_fail
    call    vault_unlock
    test    eax, eax
    jnz     xk_fail
    ; Put entry 2 in the trash BEFORE the system item is appended, while it is still the
    ; last entry - a field can then be appended to it by extending the body, with nothing
    ; after it to shift.  (VF_DELETED's value is a 16-hex timestamp; the exporters only
    ; test for the field's presence, so a placeholder is enough here.)
    mov     ecx, 2
    call    vault_entry_ptr
    mov     qword ptr [rbp-40], rax
    mov     r10, qword ptr [g_body_ptr]
    add     r10, qword ptr [g_body_len]
    mov     word ptr [r10], VF_DELETED
    mov     dword ptr [r10+2], 16
    xor     r8d, r8d
xk_delv:
    mov     byte ptr [r10+6+r8], '0'
    inc     r8d
    cmp     r8d, 16
    jb      xk_delv
    add     qword ptr [g_body_len], 6 + 16
    mov     rax, qword ptr [rbp-40]
    inc     dword ptr [rax+32]                  ; that entry now carries one more field
    mov     ecx, 2
    call    vault_is_deleted
    test    eax, eax
    jz      xk_faillk
    call    vault_add_system_item               ; 3 users + 1 system = 4 physical
    test    eax, eax
    jz      xk_faillk
    call    vault_reseal
    test    eax, eax
    jnz     xk_faillk
    mov     rax, qword ptr [g_body_ptr]
    mov     qword ptr [rbp-24], rax
    mov     rax, qword ptr [g_filebuf]          ; the RESIDENT FILE IMAGE and the attachment
    mov     qword ptr [rbp-48], rax             ;   index built from it: vault_seal_write
    mov     rax, qword ptr [g_filesize]         ;   frees and replaces these on a normal
    mov     qword ptr [rbp-56], rax             ;   save, which for an export would leave
    mov     eax, dword ptr [g_attidx_n]         ;   the master pointing at the CHILD's image
    mov     dword ptr [rbp-64], eax
    ; Tick 0, 2 and 3, leaving 1 unticked.  All three exclusions then have to fire on
    ; their own merits rather than by luck: 1 is dropped by the SELECTION, 2 by being
    ; TRASHED, 3 by being the SYSTEM item - so only entry 0 may reach the child.
    lea     r10, [g_sel]
    mov     byte ptr [r10+0], 1
    mov     byte ptr [r10+1], 0
    mov     byte ptr [r10+2], 1
    mov     byte ptr [r10+3], 1
    lea     r10, [vxk_exppw]                    ; a DIFFERENT password for the child
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
xk_pw2:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      xk_pw2d
    inc     ecx
    cmp     ecx, 32
    jb      xk_pw2
xk_pw2d:
    mov     dword ptr [g_cfg_passlen], 9
    mov     rcx, qword ptr [rbp-32]
    ; File pickers return ordinary long paths, not an already-prefixed copy.
    ; Exercise conversion of the child while the master points into ci_path.
    cmp     word ptr [rcx+4], '?'
    jne     xk_rawpath
    cmp     word ptr [rcx+10], ':'            ; only strip a drive prefix, not UNC
    jne     xk_rawpath
    add     rcx, 8
xk_rawpath:
    call    vault_export_sel
    test    eax, eax
    jnz     xk_faillk
    ; ---- the master must be exactly as it was --------------------------------
    mov     rax, qword ptr [g_body_ptr]
    cmp     rax, qword ptr [rbp-24]             ; same body, never freed or swapped
    jne     xk_faillk
    call    vault_count
    cmp     eax, 4
    jne     xk_faillk
    call    vault_ext_changed                   ; the on-disk snapshot still describes the
    test    eax, eax                            ;   MASTER, not the child we just sealed
    jnz     xk_faillk
    ; These three MUST be checked before the reload below.  vault_reload re-reads the
    ; master from disk and rebuilds g_filebuf/g_attidx, so it REPAIRS this corruption -
    ; the original version of this test asserted "master untouched" only after the
    ; reload and therefore passed while the export was freeing the master's image.
    mov     rax, qword ptr [g_filebuf]
    cmp     rax, qword ptr [rbp-48]             ; image neither freed nor swapped...
    jne     xk_faillk
    mov     rax, qword ptr [g_filesize]
    cmp     rax, qword ptr [rbp-56]
    jne     xk_faillk
    mov     eax, dword ptr [g_attidx_n]         ; ...and the attachment index survived
    cmp     eax, dword ptr [rbp-64]
    jne     xk_faillk
    call    vault_reload                        ; re-decrypts with g_vkey: proves the key,
    test    eax, eax                            ;   header and path all came back
    jnz     xk_faillk
    call    vault_count
    cmp     eax, 4
    jne     xk_faillk
    call    vault_lock
    ; ---- the child: only the ticked user entries, under its own password ------
    mov     rax, qword ptr [rbp-32]
    mov     rcx, rax
    call    cfg_in_set
    call    vault_unlock                        ; g_cfg_pass is still the export password
    test    eax, eax
    jnz     xk_fail
    call    vault_count                         ; entry 0 only: 1 unticked, 2 trashed,
    cmp     eax, 1                              ;   3 the system item
    jne     xk_faillk
    call    vault_sys_find
    cmp     eax, -1
    jne     xk_faillk
    call    vault_pwverify_get                  ; child's clock starts at "never"
    test    rax, rax
    jnz     xk_faillk
    call    vault_lock
    lea     rcx, [xs_okm]
    mov     edx, xs_okm_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
xk_faillk:
    call    vault_lock
xk_fail:
    lea     rcx, [xs_badm]
    mov     edx, xs_badm_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_vexselkat endp

; ===========================================================================
; cmd_c9kat <path> - C9 policy: the interval, the anchored grace window, the
;   escalation to "required", and the password check.  Time is passed in, so the whole
;   schedule is exercised without waiting days for it.
; ===========================================================================
LANDING_PAD
public cmd_c9kat
cmd_c9kat proc frame
    FRAME_PROLOG 96
    ; [rbp-24] = a fixed "now"; [rbp-32] = now + 31 days; [rbp-40] = now + 35 days
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]
    mov     rcx, rax
    call    cfg_in_set
    lea     r10, [ffk_seedpw]
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
c9_pwcp:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      c9_pwd
    inc     ecx
    cmp     ecx, 32
    jb      c9_pwcp
c9_pwd:
    mov     dword ptr [g_cfg_passlen], 9
    mov     dword ptr [g_cfg_t], 1
    mov     dword ptr [g_cfg_m], 8192
    mov     ecx, 2
    call    do_seed
    test    eax, eax
    jnz     c9_fail
    call    vault_unlock
    test    eax, eax
    jnz     c9_fail
    ; A fixed epoch-ish "now", well clear of 0 so day arithmetic has room either way.
    ; Day offsets go through a register: FT_PER_DAY * n exceeds a 32-bit immediate.
    mov     r11, FT_PER_DAY
    mov     rax, r11
    imul    rax, rax, 1000
    mov     qword ptr [rbp-24], rax             ; now
    mov     rdx, r11
    imul    rdx, rdx, 31
    add     rdx, rax
    mov     qword ptr [rbp-32], rdx             ; now + 31 days
    mov     rdx, r11
    imul    rdx, rdx, 35
    add     rdx, rax
    mov     qword ptr [rbp-40], rdx             ; now + 35 days
    ; ---- interval 0 disables the feature entirely -----------------------------
    mov     rcx, qword ptr [rbp-24]
    xor     edx, edx
    call    vault_pw_due
    test    eax, eax
    jnz     c9_faillk
    ; ---- freshly stamped -> not due -------------------------------------------
    mov     rcx, qword ptr [rbp-24]
    call    vault_pwverify_set
    test    eax, eax
    jz      c9_faillk
    mov     rcx, qword ptr [rbp-24]
    mov     edx, C9_DAYS_DEFAULT
    call    vault_pw_due
    test    eax, eax
    jnz     c9_faillk
    ; ---- one day short of the interval -> still not due ----------------------
    mov     rcx, FT_PER_DAY
    imul    rcx, rcx, C9_DAYS_DEFAULT-1
    add     rcx, qword ptr [rbp-24]
    mov     edx, C9_DAYS_DEFAULT
    call    vault_pw_due
    test    eax, eax
    jnz     c9_faillk
    ; ---- 31 days on -> due, and it STAYS due; nothing escalates --------------
    mov     rcx, qword ptr [rbp-32]
    mov     edx, C9_DAYS_DEFAULT
    call    vault_pw_due
    cmp     eax, 1
    jne     c9_faillk
    mov     rcx, qword ptr [rbp-40]             ; days later, still just a reminder
    mov     edx, C9_DAYS_DEFAULT
    call    vault_pw_due
    cmp     eax, 1
    jne     c9_faillk
    ; ---- the query is PURE: being due must not have written anything ---------
    mov     rcx, qword ptr [rbp-24]             ; the stamp is untouched, so a smaller
    call    vault_pwverify_get                  ;   interval still reads the original
    cmp     rax, qword ptr [rbp-24]
    jne     c9_faillk
    ; ---- verifying clears it ------------------------------------------------
    mov     rcx, qword ptr [rbp-40]
    call    vault_pwverify_set
    test    eax, eax
    jz      c9_faillk
    mov     rcx, qword ptr [rbp-40]
    mov     edx, C9_DAYS_DEFAULT
    call    vault_pw_due
    test    eax, eax
    jnz     c9_faillk
    ; ---- a never-stamped vault is due at once (it has demonstrably not been typed)
    xor     ecx, ecx
    call    vault_pwverify_set
    test    eax, eax
    jz      c9_faillk
    mov     rcx, qword ptr [rbp-24]
    mov     edx, C9_DAYS_DEFAULT
    call    vault_pw_due
    cmp     eax, 1
    jne     c9_faillk
    ; ---- the password check accepts only the real master password ------------
    lea     rcx, [ffk_seedpw]
    mov     edx, 9
    call    vault_pw_check
    cmp     eax, 1
    jne     c9_faillk
    lea     rcx, [vxk_exppw]                    ; a different, valid-looking password
    mov     edx, 9
    call    vault_pw_check
    test    eax, eax
    jnz     c9_faillk
    call    vault_count                         ; and the vault is still usable after both
    cmp     eax, 3                              ;   (2 seeded + the lazily added system item)
    jne     c9_faillk
    call    vault_lock
    lea     rcx, [c9_okm]
    mov     edx, c9_okm_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
c9_faillk:
    call    vault_lock
c9_fail:
    lea     rcx, [c9_badm]
    mov     edx, c9_badm_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_c9kat endp

; ===========================================================================
; cmd_vimpkat <path> - .vordr import: read a FOREIGN vault while the master is open,
;   merge only the ticked entries, and leave the master byte-identical.  Builds the
;   source at <path>.src under its own password first, since do_seed seals and closes.
; ===========================================================================
LANDING_PAD
public cmd_vimpkat
cmd_vimpkat proc frame
    FRAME_PROLOG 128
    ; [rbp-24]=src path [rbp-32]=src body [rbp-40]=master body
    ; [rbp-48]=filebuf [rbp-56]=filesize [rbp-64]=attidx_n
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]
    mov     rcx, rax
    call    cfg_in_set
    mov     r10, rax                            ; g_vx_pathb = <path> + ".src"
    lea     r11, [g_vx_pathb]
    xor     r8d, r8d
vi_pcpy:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      vi_pdone
    inc     r8d
    cmp     r8d, MAX_PATH_CHARS-8
    jb      vi_pcpy
vi_pdone:
    mov     word ptr [r11+r8*2], '.'
    inc     r8d
    mov     word ptr [r11+r8*2], 's'
    inc     r8d
    mov     word ptr [r11+r8*2], 'r'
    inc     r8d
    mov     word ptr [r11+r8*2], 'c'
    inc     r8d
    mov     word ptr [r11+r8*2], 0
    lea     rax, [g_vx_pathb]
    mov     qword ptr [rbp-24], rax
    ; ---- source vault: 3 entries under its OWN password ----------------------
    mov     rcx, rax
    call    cfg_in_set
    lea     r10, [vxk_exppw]
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
vi_pw1:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      vi_pw1d
    inc     ecx
    cmp     ecx, 32
    jb      vi_pw1
vi_pw1d:
    mov     dword ptr [g_cfg_passlen], 9
    mov     dword ptr [g_cfg_t], 1
    mov     dword ptr [g_cfg_m], 8192
    mov     ecx, 3
    call    do_seed
    test    eax, eax
    jnz     vi_fail
    ; ---- master vault: 2 entries, and leave it OPEN --------------------------
    lea     r10, [g_argv]
    mov     rax, qword ptr [r10+16]
    mov     rcx, rax
    call    cfg_in_set
    lea     r10, [ffk_seedpw]
    lea     r11, [g_cfg_pass]
    xor     ecx, ecx
vi_pw2:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    test    al, al
    jz      vi_pw2d
    inc     ecx
    cmp     ecx, 32
    jb      vi_pw2
vi_pw2d:
    mov     dword ptr [g_cfg_passlen], 9
    mov     ecx, 2
    call    do_seed
    test    eax, eax
    jnz     vi_fail
    call    vault_unlock
    test    eax, eax
    jnz     vi_fail
    mov     rax, qword ptr [g_body_ptr]
    mov     qword ptr [rbp-40], rax
    mov     rax, qword ptr [g_filebuf]
    mov     qword ptr [rbp-48], rax
    mov     rax, qword ptr [g_filesize]
    mov     qword ptr [rbp-56], rax
    mov     eax, dword ptr [g_attidx_n]
    mov     dword ptr [rbp-64], eax
    ; ---- read the foreign vault WITHOUT disturbing the open master -----------
    mov     rcx, qword ptr [rbp-24]
    cmp     word ptr [rcx+4], '?'
    jne     vi_rawpath
    cmp     word ptr [rcx+10], ':'
    jne     vi_rawpath
    add     rcx, 8                            ; ordinary long file-picker path
vi_rawpath:
    lea     rdx, [vxk_exppw]
    mov     r8d, 9
    lea     r9, [rbp-32]
    call    vault_open_foreign
    test    eax, eax
    jnz     vi_faillk
    ; the master's live state must be exactly as it was - same body, same resident
    ; image, same attachment index, and its on-disk snapshot still its own
    mov     rax, qword ptr [g_body_ptr]
    cmp     rax, qword ptr [rbp-40]
    jne     vi_faillk
    mov     rax, qword ptr [g_filebuf]
    cmp     rax, qword ptr [rbp-48]
    jne     vi_faillk
    mov     rax, qword ptr [g_filesize]
    cmp     rax, qword ptr [rbp-56]
    jne     vi_faillk
    mov     eax, dword ptr [g_attidx_n]
    cmp     eax, dword ptr [rbp-64]
    jne     vi_faillk
    call    vault_count
    cmp     eax, 2
    jne     vi_faillk
    call    vault_ext_changed
    test    eax, eax
    jnz     vi_faillk
    ; ---- staging must offer the source's entries to the checklist ------------
    ; The GUI reaches fed_merge only through this: if staging reports nothing, the user
    ; is told "no importable entries" no matter how good the source is.
    mov     rcx, qword ptr [rbp-32]
    call    zi_stage_vault
    cmp     eax, 3                              ; all three source entries staged...
    jne     vi_faillk
    cmp     dword ptr [g_zi_stg_n], 3
    jne     vi_faillk
    lea     r10, [g_zi_hide]                    ; ...and none of them hidden (do_seed makes
    cmp     byte ptr [r10+0], 0                 ;   no system item and trashes nothing)
    jne     vi_faillk
    cmp     byte ptr [r10+1], 0
    jne     vi_faillk
    cmp     byte ptr [r10+2], 0
    jne     vi_faillk
    ; ---- merge only the ticked source entries -------------------------------
    lea     r10, [g_sel]
    mov     byte ptr [r10+0], 1
    mov     byte ptr [r10+1], 0                 ; this one must NOT arrive
    mov     byte ptr [r10+2], 1
    mov     dword ptr [g_merge_sel], 1
    mov     rcx, qword ptr [rbp-32]
    call    fed_merge
    mov     dword ptr [g_merge_sel], 0
    cmp     eax, 2                              ; two added, not three
    jne     vi_faillk
    call    vault_count
    cmp     eax, 4                              ; 2 master + 2 imported
    jne     vi_faillk
    ; ---- re-merging the same source changes nothing (dedup by entry id) ------
    mov     dword ptr [g_merge_sel], 1
    mov     rcx, qword ptr [rbp-32]
    call    fed_merge
    mov     dword ptr [g_merge_sel], 0
    test    eax, eax
    jnz     vi_faillk
    call    vault_count
    cmp     eax, 4
    jne     vi_faillk
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, VAULT_BODY_MAX
    call    secmem_free
    call    vault_lock
    lea     rcx, [vi_okm]
    mov     edx, vi_okm_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
vi_faillk:
    call    vault_lock
vi_fail:
    lea     rcx, [vi_badm]
    mov     edx, vi_badm_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_vimpkat endp

; ===========================================================================
; kat_newvault_att() -> eax 0/err.  Create a vault at g_cfg_in under g_cfg_pass whose
;   one entry carries two attachments (do_attgen), seal it and close it.  Fast KDF.
kat_newvault_att proc frame
    FRAME_PROLOG 48
    mov     dword ptr [g_cfg_t], 1
    mov     dword ptr [g_cfg_m], 8
    mov     dword ptr [g_hdr+0], VAULT_MAGIC
    mov     dword ptr [g_hdr+4], VAULT_VERSION
    mov     dword ptr [g_hdr+VH_T], 1
    mov     dword ptr [g_hdr+VH_M], 8
    mov     dword ptr [g_hdr+VH_LANES], 1
    lea     rcx, [g_hdr+VH_SALT]
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      knv_fail
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      knv_fail
    call    vk_derive
    test    eax, eax
    jnz     knv_fail
    call    vk_kcv
    lea     r10, [g_sha32]
    lea     r9, [g_hdr+VH_KCV]
    xor     r8d, r8d
knv_kcv:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r9+r8], al
    inc     r8d
    cmp     r8d, KCV_LEN
    jb      knv_kcv
    call    do_attgen
    test    eax, eax
    jnz     knv_fail
    mov     qword ptr [g_save_counter], 0
    call    vault_seal_write
    mov     dword ptr [rbp-24], eax
    call    vault_lock
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
knv_fail:
    call    vault_lock
    mov     eax, 1
    FRAME_EPILOG
    ret
kat_newvault_att endp

; kat_setpw(rcx = 9-char ascii password) - g_cfg_pass = it.  Leaf.
kat_setpw proc
    lea     r11, [g_cfg_pass]
    xor     edx, edx
ksp_lp:
    mov     al, byte ptr [rcx+rdx]
    mov     byte ptr [r11+rdx], al
    inc     edx
    cmp     edx, 9
    jb      ksp_lp
    mov     dword ptr [g_cfg_passlen], 9
    ret
kat_setpw endp

; ===========================================================================
; cmd_vimpattkat <path> - .vordr import and merge where BOTH vaults carry
;   attachments.  vimpkat cannot see this class: its vaults have none, and every
;   bug here lives in the attachment index.  Asserts that (1) importing a foreign
;   vault with attachments leaves the open vault's own attachments decryptable after
;   the save that follows, and (2) a NEWER copy of an entry merged over it keeps that
;   entry's attachments instead of replacing it with a stripped copy.
; ===========================================================================
CSTR via_ok,  "vimpattkat: PASS (own attachments survive a foreign import and a newer-copy merge)",13,10
CSTR via_bad, "vimpattkat: FAIL",13,10
LANDING_PAD
public cmd_vimpattkat
cmd_vimpattkat proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=src path [rbp-32]=foreign body / snapshot [rbp-40]=merge count
    lea     r10, [g_argv]
    mov     rcx, qword ptr [r10+16]
    call    cfg_in_set
    mov     r10, rax                            ; g_vx_pathb = <path> + ".src"
    lea     r11, [g_vx_pathb]
    xor     r8d, r8d
via_pcpy:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      via_pdone
    inc     r8d
    cmp     r8d, MAX_PATH_CHARS-8
    jb      via_pcpy
via_pdone:
    mov     word ptr [r11+r8*2], '.'
    mov     word ptr [r11+r8*2+2], 's'
    mov     word ptr [r11+r8*2+4], 'r'
    mov     word ptr [r11+r8*2+6], 'c'
    mov     word ptr [r11+r8*2+8], 0
    lea     rax, [g_vx_pathb]
    mov     qword ptr [rbp-24], rax
    ; ---- the open vault: one entry, two attachments --------------------------
    lea     rcx, [ffk_seedpw]
    call    kat_setpw
    call    kat_newvault_att
    test    eax, eax
    jnz     via_fail
    ; ---- the foreign vault: also two attachments, other ids, other password ---
    mov     rcx, qword ptr [rbp-24]
    call    cfg_in_set
    lea     rcx, [vxk_exppw]
    call    kat_setpw
    call    kat_newvault_att
    test    eax, eax
    jnz     via_fail
    ; ---- open the first one and import the second into it --------------------
    lea     r10, [g_argv]
    mov     rcx, qword ptr [r10+16]
    call    cfg_in_set
    lea     rcx, [ffk_seedpw]
    call    kat_setpw
    call    vault_unlock
    test    eax, eax
    jnz     via_fail
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [vxk_exppw]
    mov     r8d, 9
    lea     r9, [rbp-32]
    call    vault_open_foreign
    test    eax, eax
    jnz     via_faillk
    mov     rcx, qword ptr [rbp-32]
    call    fed_merge                           ; g_merge_sel = 0: everything
    mov     dword ptr [rbp-40], eax
    mov     rcx, qword ptr [rbp-32]
    call    vault_free_foreign
    cmp     dword ptr [rbp-40], 1
    jne     via_faillk
    call    vault_reseal                        ; the save that used to zero them
    test    eax, eax
    jnz     via_faillk
    call    vault_lock
    lea     rcx, [ffk_seedpw]
    call    kat_setpw
    call    vault_unlock                        ; back from disk
    test    eax, eax
    jnz     via_fail
    mov     ecx, 2                              ; own entry (2 attachments) + the import
    call    zi_att_verify
    cmp     eax, 2
    jne     via_faillk
    ; ---- merge a NEWER copy of the own entry over it --------------------------
    mov     rcx, VAULT_BODY_MAX
    call    secmem_alloc
    test    rax, rax
    jz      via_faillk
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    mov     rdx, qword ptr [g_body_ptr]
    mov     r8d, dword ptr [g_body_len]
    call    copy_bytes
    xor     ecx, ecx                            ; entry 0 = the own entry
    call    vault_entry_ptr
    sub     rax, qword ptr [g_body_ptr]
    add     rax, qword ptr [rbp-32]
    inc     qword ptr [rax+24]                  ; ...but newer
    mov     rcx, qword ptr [rbp-32]
    call    fed_merge
    mov     dword ptr [rbp-40], eax
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, VAULT_BODY_MAX
    call    secmem_free
    cmp     dword ptr [rbp-40], 1               ; replaced, not added
    jne     via_faillk
    call    vault_count
    cmp     eax, 2
    jne     via_faillk
    call    vault_reseal
    test    eax, eax
    jnz     via_faillk
    call    vault_lock
    lea     rcx, [ffk_seedpw]
    call    kat_setpw
    call    vault_unlock
    test    eax, eax
    jnz     via_fail
    mov     ecx, 2
    call    zi_att_verify                       ; the replacement still has both files
    cmp     eax, 2
    jne     via_faillk
    call    vault_lock
    lea     rcx, [via_ok]
    mov     edx, via_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
via_faillk:
    call    vault_lock
via_fail:
    lea     rcx, [via_bad]
    mov     edx, via_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_vimpattkat endp

; ===========================================================================
; cmd_vattgen <path> - a fixture for tests/verify_vault.py, the independent reader:
;   a vault (password "vordrtest", t=1 m=8 KiB) whose entry carries two attachments,
;   sealed once and then saved three more times, so the file has a save counter of
;   4 (the first write is 1) and .bak1..3 hold the earlier saves - same salt and
;   key, a fresh nonce each.
; cmd_vopen <path> - open a vault with Vordr's OWN reader under the same password:
;   exit 0 = it opened, else the EXIT_* it was refused with.  verify_vault.py
;   tampers a copy region by region and requires this to refuse every one.
; ===========================================================================
CSTR vag_ok,  "vattgen: PASS (2 attachments, saved 4 times)",13,10
CSTR vag_bad, "vattgen: FAIL",13,10
CSTR vop_ok,  "vopen: OK, entries "
CSTR vop_bad, "vopen: refused, exit "
CSTR vop_nl,  13,10
LANDING_PAD
public cmd_vattgen
cmd_vattgen proc frame
    FRAME_PROLOG 48
    lea     r10, [g_argv]
    mov     rcx, qword ptr [r10+16]
    call    cfg_in_set
    lea     rcx, [bk_pw]
    call    kat_setpw
    call    kat_newvault_att
    test    eax, eax
    jnz     vag_fail
    mov     dword ptr [rbp-24], 3
vag_lp:
    lea     rcx, [bk_pw]                        ; unlock wipes the password it used
    call    kat_setpw
    call    vault_unlock
    test    eax, eax
    jnz     vag_fail
    call    vault_reseal
    mov     dword ptr [rbp-28], eax
    call    vault_lock
    cmp     dword ptr [rbp-28], 0
    jne     vag_fail
    dec     dword ptr [rbp-24]
    jnz     vag_lp
    lea     rcx, [vag_ok]
    mov     edx, vag_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
vag_fail:
    lea     rcx, [vag_bad]
    mov     edx, vag_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_vattgen endp

; ===========================================================================
; cmd_seedbig <path> - a vault (password "vordrtest", t=1 m=8 MiB) whose one entry
;   has SEEDBIG_N fields - more cards than the detail pane shows at once, for the
;   GUI tests of its scrolling.  Fields are numbered so a test can tell them apart.
; ===========================================================================
SEEDBIG_N   equ 40
CSTR sbg_ok,  "seedbig: PASS (one entry, 40 fields)",13,10
CSTR sbg_bad, "seedbig: FAIL",13,10
WSTR sbg_title, <Many fields>
WSTR sbg_lbl,   <Field>
.data?
align 2
sbg_vals    dw SEEDBIG_N*8 dup (?)              ; "value NN" per field
.code
LANDING_PAD
public cmd_seedbig
cmd_seedbig proc frame
    FRAME_PROLOG 48
    lea     r10, [g_argv]
    mov     rcx, qword ptr [r10+16]
    call    cfg_in_set
    lea     rcx, [bk_pw]
    call    kat_setpw
    mov     dword ptr [g_cfg_t], 1
    mov     dword ptr [g_cfg_m], 8192
    call    do_init
    test    eax, eax
    jnz     sbg_fail
    lea     rcx, [bk_pw]
    call    kat_setpw
    call    vault_unlock
    test    eax, eax
    jnz     sbg_fail
    lea     r10, [g_field_list]                 ; field 0: the title
    mov     qword ptr [r10], VF_TITLE
    mov     qword ptr [r10+8], 0
    lea     rax, [sbg_title]
    mov     qword ptr [r10+16], rax
    xor     ecx, ecx
sbg_fl:
    lea     r11, [sbg_vals]                     ; value text "vNN", NUL-terminated
    mov     eax, ecx
    shl     eax, 4                              ; 8 wide chars per slot
    add     r11, rax
    mov     word ptr [r11], 'v'
    mov     eax, ecx
    xor     edx, edx
    mov     r8d, 10
    div     r8d
    add     eax, '0'
    mov     word ptr [r11+2], ax
    add     edx, '0'
    mov     word ptr [r11+4], dx
    mov     word ptr [r11+6], 0
    lea     eax, [ecx+1]
    imul    eax, eax, 24
    mov     qword ptr [r10+rax], VF_TEXT or VF_LABELED
    lea     r8, [sbg_lbl]
    mov     qword ptr [r10+rax+8], r8
    mov     qword ptr [r10+rax+16], r11
    inc     ecx
    cmp     ecx, SEEDBIG_N
    jb      sbg_fl
    mov     dword ptr [g_field_n], SEEDBIG_N + 1
    call    vault_build_entry
    test    eax, eax
    jnz     sbg_faillock
    call    vault_reseal
    mov     dword ptr [rbp-24], eax
    call    vault_lock
    cmp     dword ptr [rbp-24], 0
    jne     sbg_fail
    lea     rcx, [sbg_ok]
    mov     edx, sbg_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
sbg_faillock:
    call    vault_lock
sbg_fail:
    lea     rcx, [sbg_bad]
    mov     edx, sbg_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_seedbig endp

LANDING_PAD
public cmd_vopen
cmd_vopen proc frame
    FRAME_PROLOG 48
    lea     r10, [g_argv]
    mov     rcx, qword ptr [r10+16]
    call    cfg_in_set
    lea     rcx, [bk_pw]
    call    kat_setpw
    call    vault_unlock
    mov     dword ptr [rbp-24], eax
    test    eax, eax
    jnz     vop_refused
    call    vault_count
    mov     dword ptr [rbp-28], eax
    call    vault_lock
    lea     rcx, [vop_ok]
    mov     edx, vop_ok_len
    call    print_a
    mov     ecx, dword ptr [rbp-28]
    call    print_u64
    lea     rcx, [vop_nl]
    mov     edx, vop_nl_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
vop_refused:
    lea     rcx, [vop_bad]
    mov     edx, vop_bad_len
    call    print_a
    mov     ecx, dword ptr [rbp-24]
    call    print_u64
    lea     rcx, [vop_nl]
    mov     edx, vop_nl_len
    call    print_a
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
cmd_vopen endp

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
    mov     rcx, rax
    call    cfg_in_set
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
    mov     rcx, rax
    call    cfg_in_set
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
    and     eax, VF_KINDMASK                    ; never a flag bit on a raw field
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
    ; No room.  Refuse rather than fastfail: the caller (vault_build_entry) rolls the
    ; half-built entry back, and the session - with its unsaved work - survives.
    mov     dword ptr [g_vfe_err], 1
    xor     eax, eax
    FRAME_EPILOG
    ret
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
    cmp     eax, -1                             ; a dropped label is silent data loss too
    je      vfb_of
    mov     ecx, eax
    mov     qword ptr [rbp-48], rcx
vfb_write:
    cmp     qword ptr [rbp-48], 0
    jne     vfb_labeled
    ; --- plain: {type, rawlen, rawbytes} ---
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    mov     r8,  qword ptr [rbp-40]
    call    va_field_raw                        ; eax = 1 written / 0 refused
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
    and     eax, VF_KINDMASK
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
    mov     dword ptr [g_vfe_err], 1            ; see vfr_of
    xor     eax, eax
    FRAME_EPILOG
    ret
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
    mov     dword ptr [rbp-24], 0
    jmp     vst_cleanup
vst_fail:
    mov     dword ptr [rbp-24], 1
vst_cleanup:
    lea     rcx, [g_cfg_pass]
    mov     edx, MAX_PASSWORD_BYTES+1
    call    secure_zero
    mov     dword ptr [g_cfg_passlen], 0
    lea     rcx, [g_vkey]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_sha32]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_hdr]
    mov     edx, VH_TOTAL
    call    secure_zero
    lea     rcx, [vst_ct]
    mov     edx, 16
    call    secure_zero
    lea     rcx, [vst_dec]
    mov     edx, 16
    call    secure_zero
    lea     rcx, [vst_tag]
    mov     edx, 16
    call    secure_zero
    mov     eax, dword ptr [rbp-24]
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
    mov     rcx, qword ptr [g_cfg_in]           ; g_lock_path = g_cfg_in + ".lock"
    call    path_io                             ;   in the form Win32 accepts
    mov     r10, rax
    lea     r11, [g_lock_path]
    xor     ecx, ecx
lka_cp:
    mov     ax, word ptr [r10+rcx*2]
    mov     word ptr [r11+rcx*2], ax
    test    ax, ax
    jz      lka_cpd
    inc     ecx
    cmp     ecx, MAX_PATH_CHARS-8
    jb      lka_cp
    mov     word ptr [r11], 0                   ; base path too long -> refuse truncation
    jmp     lka_busy
lka_cpd:
    lea     r11, [g_lock_path]
    lea     r11, [r11+rcx*2]                    ; at the NUL
    mov     word ptr [r11+0], '.'
    mov     word ptr [r11+2], 'l'
    mov     word ptr [r11+4], 'o'
    mov     word ptr [r11+6], 'c'
    mov     word ptr [r11+8], 'k'
    mov     word ptr [r11+10], 0
    ; Share read (1 = FILE_SHARE_READ) so cloud sync/backup indexers do not fail
    ; mid-scan while write exclusion (no FILE_SHARE_WRITE/DELETE) still holds.
    WINCALL CreateFileW, addr g_lock_path, LK_GENERIC_WRITE, 1, 0, LK_CREATE_NEW, LK_DELONCLOSE, 0
    cmp     rax, -1
    jne     lka_got
    WINCALL DeleteFileW, addr g_lock_path       ; reclaim an orphan (fails if live-held)
    WINCALL CreateFileW, addr g_lock_path, LK_GENERIC_WRITE, 1, 0, LK_CREATE_NEW, LK_DELONCLOSE, 0
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

; ===========================================================================
; M6. Vault export / merge-import (headless core).
;   Export = seal a chosen set of entries into a fresh standalone .vordr with its
;   own new salt + password (a portable child vault).  Merge-import = copy entries
;   from a decrypted source body into the live vault, deduped by the 16-byte entry
;   id (newer `modified` wins), so a re-merge is idempotent.  Both PRESERVE each
;   entry's id16/created/modified (raw-ish copy, not a rebuild).
;   Text-only export strips VF_IMAGE/VF_FILE fields so the copy never leaves a
;   dangling AttachRef.  Full export carries the attachment ciphertext verbatim;
;   its per-attachment key remains protected inside the newly sealed vault body.
; ===========================================================================

; entry_copy_filtered(rcx = src entry ptr, rdx = dst ptr) -> eax = bytes written.
;   Copies the 36-byte entry header (id16/created/modified) verbatim, then every
;   field EXCEPT attachment kinds (VF_IMAGE/VF_FILE), patching the destination
;   field_count.  Call-free (no shadow-region hazard); leaf.
entry_copy_filtered proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-32], rdx           ; dst base
    xor     r8d, r8d                          ; header: 36 bytes src->dst
ecf_hc:
    mov     al, byte ptr [rcx+r8]
    mov     byte ptr [rdx+r8], al
    inc     r8d
    cmp     r8d, 36
    jb      ecf_hc
    mov     r10, rcx                          ; src field cursor
    mov     r9d, dword ptr [r10+32]           ; src field_count
    add     r10, 36
    mov     r11, rdx                          ; dst field cursor
    add     r11, 36
    mov     dword ptr [rbp-24], 0             ; kept field count
ecf_loop:
    test    r9d, r9d
    jz      ecf_done
    movzx   eax, word ptr [r10]              ; field type
    mov     ecx, eax
    and     ecx, VF_KINDMASK                  ; base kind
    mov     r8d, dword ptr [r10+2]           ; field value len
    add     r8d, 6                            ; + {u16 type, u32 len} header = total bytes
    cmp     ecx, VF_IMAGE
    je      ecf_adv                           ; attachment field -> drop (don't copy)
    cmp     ecx, VF_FILE
    je      ecf_adv
    cmp     ecx, VF_PWHIST
    jne     ecf_do_cp
    test    eax, VF_LABELED                   ; defensive: drop malformed history blobs
    jnz     ecf_adv
    cmp     r8d, 16                           ; 6-byte header + >=10-byte payload
    jb      ecf_adv
    test    r8d, 1
    jnz     ecf_adv
ecf_do_cp:
    xor     ecx, ecx                          ; copy r8d bytes r10 -> r11
ecf_cp:
    cmp     ecx, r8d
    jae     ecf_cpd
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    inc     ecx
    jmp     ecf_cp
ecf_cpd:
    add     r11, r8                           ; advance dst
    inc     dword ptr [rbp-24]                ; kept++
ecf_adv:
    add     r10, r8                           ; advance src (valid on the skip path too)
    dec     r9d
    jmp     ecf_loop
ecf_done:
    mov     r10, qword ptr [rbp-32]           ; patch dst field_count
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [r10+32], eax
    mov     rax, r11
    sub     rax, qword ptr [rbp-32]           ; bytes written
    FRAME_EPILOG
    ret
entry_copy_filtered endp

; fed_find_by_id(rcx = 16-byte id ptr) -> eax = index of that entry in the live body,
;   or -1 if absent.
fed_find_by_id proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx           ; wanted id
    call    vault_count
    mov     dword ptr [rbp-28], eax
    mov     dword ptr [rbp-32], 0             ; i
ffbi_loop:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [rbp-28]
    jae     ffbi_none
    mov     ecx, eax
    call    vault_entry_ptr
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-24]
    mov     r8d, 16
    call    ct_memcmp
    test    eax, eax
    jz      ffbi_found
    inc     dword ptr [rbp-32]
    jmp     ffbi_loop
ffbi_found:
    mov     eax, dword ptr [rbp-32]
    FRAME_EPILOG
    ret
ffbi_none:
    mov     eax, -1
    FRAME_EPILOG
    ret
fed_find_by_id endp

; entry_copy_full(rcx = src entry ptr, rdx = dst ptr) -> eax = bytes written.
;   Verbatim entry copy INCLUDING attachment fields - the 68-byte AttachRef (with the
;   attachment's own key/nonce/id) travels, so the blob can be carried into the new
;   file.  Same signature as entry_copy_filtered.
entry_copy_full proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rdx           ; dst
    mov     qword ptr [rbp-32], rcx           ; src
    call    vault_entry_len                   ; rcx = src -> rax = len
    mov     dword ptr [rbp-40], eax
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    mov     r8d, dword ptr [rbp-40]
    call    copy_bytes
    mov     eax, dword ptr [rbp-40]
    FRAME_EPILOG
    ret
entry_copy_full endp

; fed_export(rcx = source body ptr {u32 count, entries}, edx = carry) -> eax = 0/EXIT_*.
;   Build a NEW vault from every entry in the source body, sealed under a fresh salt +
;   the password in g_cfg_pass, written to g_cfg_in.
;   carry=0: attachment fields are STRIPPED (portable text-only child vault); the
;     attachment section is reset to empty.  The caller may lock the source first.
;   carry=1: entries copied VERBATIM and the source's attachment context
;     (g_attidx/g_filebuf/g_newatt) is KEPT live, so vault_seal_write copies every
;     referenced blob into the new file (ct verbatim - keyed by the AttachRef's own
;     key, so it still decrypts under the new vault).  The caller must NOT lock the
;     source first (its attachment image must stay resident); fed_export frees the
;     old body itself.  Either way this clobbers the live header/key/body.
public fed_export
fed_export proc frame
    FRAME_PROLOG 96                            ; locals -24..-72 all above the callee shadow
    mov     qword ptr [rbp-24], rcx           ; source body
    mov     dword ptr [rbp-72], edx           ; carry flag
    mov     qword ptr [rbp-32], 0             ; new body (0 until allocated; fx_oom frees it)
    mov     rcx, VAULT_BODY_MAX
    call    secmem_alloc
    test    rax, rax
    jz      fx_oom
    mov     qword ptr [rbp-32], rax           ; new body
    mov     dword ptr [rax], 0
    mov     qword ptr [rbp-40], 4             ; new body_len
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [r10]
    mov     dword ptr [rbp-48], eax           ; source count
    add     r10, 4
    mov     qword ptr [rbp-56], r10           ; source entry cursor
    mov     dword ptr [rbp-64], 0            ; i
fx_loop:
    mov     eax, dword ptr [rbp-64]
    cmp     eax, dword ptr [rbp-48]
    jae     fx_built
    mov     rcx, qword ptr [rbp-56]           ; A child vault is a DIFFERENT vault: it must
    call    sys_first_kind                    ;   not inherit the parent's system item, which
    cmp     eax, VF_SYSTEM                    ;   would hand it the parent's pwverify stamp
    je      fx_adv                            ;   and start its clock pre-verified.  It gains
                                              ;   its own on first save.  Pointer-based: the
                                              ;   source body is NOT g_body_ptr here, so
                                              ;   vault_is_system (which indexes the live
                                              ;   body) would be the wrong test.
    mov     rcx, qword ptr [rbp-56]           ; bounds: worst case = full src entry len
    call    vault_entry_len
    mov     r8, qword ptr [rbp-40]
    add     r8, rax
    cmp     r8, VAULT_BODY_MAX
    ja      fx_adv                            ; no room -> stop copying (drop the rest)
    mov     rcx, qword ptr [rbp-56]           ; src entry
    mov     rdx, qword ptr [rbp-32]           ; dst = new body + len
    add     rdx, qword ptr [rbp-40]
    cmp     dword ptr [rbp-72], 0
    je      fx_filt
    call    entry_copy_full                   ; carry: keep attachment fields
    jmp     fx_added
fx_filt:
    call    entry_copy_filtered               ; v1: drop attachment fields
fx_added:
    mov     r8d, eax
    add     qword ptr [rbp-40], r8
    mov     r10, qword ptr [rbp-32]
    inc     dword ptr [r10]                   ; entry_count++
fx_adv:
    mov     rcx, qword ptr [rbp-56]
    call    vault_entry_len
    add     qword ptr [rbp-56], rax
    inc     dword ptr [rbp-64]
    jmp     fx_loop
fx_built:
    mov     rcx, qword ptr [g_body_ptr]       ; free the old (source) body; its attachment
    test    rcx, rcx                          ; image/index (g_filebuf/g_attidx) stay live for
    jz      fx_hdr                            ; the carry seal below
    mov     rdx, VAULT_BODY_MAX
    call    secmem_free
    mov     qword ptr [g_body_ptr], 0         ; freed - null it now so a later fx_oom (RNG/KDF
                                              ; failure) can't leave g_body_ptr dangling at
                                              ; released pages (UAF / panic-wipe writes freed mem)
fx_hdr:
    mov     dword ptr [g_hdr+0], VAULT_MAGIC  ; fresh header
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
    jz      fx_oom
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      fx_oom
    call    vk_derive                         ; new key from g_cfg_pass
    test    eax, eax
    jnz     fx_oom
    call    vk_kcv
    lea     r10, [g_sha32]
    lea     r9, [g_hdr+VH_KCV]
    xor     r8d, r8d
fx_kcv:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r9+r8], al
    inc     r8d
    cmp     r8d, KCV_LEN
    jb      fx_kcv
    mov     rax, qword ptr [rbp-32]           ; adopt the new body
    mov     qword ptr [g_body_ptr], rax
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [g_body_len], rax
    cmp     dword ptr [rbp-72], 0             ; carry -> keep the source attachment context
    jne     fx_seal
    mov     qword ptr [g_att_total], 0        ; no-carry: emit an empty attachment section
    mov     dword ptr [g_newatt_n], 0
    mov     dword ptr [g_attidx_n], 0
    mov     dword ptr [g_att_ovf], 0
fx_seal:
    mov     qword ptr [g_save_counter], 0     ; fresh vault: first save = counter 1
    call    vault_seal_write
    FRAME_EPILOG
    ret
fx_oom:
    mov     rcx, qword ptr [rbp-32]           ; free the new body if allocated (null-safe +
    mov     rdx, VAULT_BODY_MAX               ;   double-free-safe); on the alloc-fail path
    call    secmem_free                       ;   [rbp-32]=0 so this no-ops
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
fed_export endp

; ===========================================================================
; vault_export_sel(rcx = target path wide) -> eax = 0 / EXIT_*.
;   Export the entries ticked in g_sel to a NEW .vordr at `path`, sealed under a fresh
;   salt/nonce and the password already in g_cfg_pass.
;
;   Unlike fed_export this is NON-CLOBBERING: fed_export frees the live body and adopts
;   the child as the open vault, which is right for a headless "convert this vault" but
;   wrong for a GUI export - the user would silently continue editing the CHILD.  Here
;   every global the seal path mutates is parked and restored, and the master body is
;   never freed, so the vault stays open exactly as it was.
;
;   Selection is honoured (matching the ZIP export), attachments travel
;   (entry_copy_full + the live g_attidx), and system items are never copied - the
;   child mints its own on first save, so its pwverify stamp starts at "never" rather
;   than inheriting the parent's verification date.
;
;   Note it deliberately does NOT consult g_readonly: exporting never writes to the
;   master, so it stays available on a read-only vault.
; ===========================================================================
; Export and foreign-open are serialized and already share g_xs_hdr/key.
; Copy the path too: cfg_in_set can overwrite the storage behind g_cfg_in.
vault_park_path proc
    lea     rax, [g_xs_path]
    xor     r8d, r8d
vpp_copy:
    mov     cx, word ptr [rdx+r8*2]
    mov     word ptr [rax+r8*2], cx
    test    cx, cx
    jz      vpp_done
    inc     r8d
    cmp     r8d, MAX_PATH_CHARS+15
    jb      vpp_copy
    mov     word ptr [rax+r8*2], 0
vpp_done:
    ret
vault_park_path endp

public vault_export_sel
vault_export_sel proc frame
    FRAME_PROLOG 160
    ; [rbp-24]=path [rbp-32]=saved body ptr [rbp-40]=saved body len [rbp-48]=saved cfg_in
    ; [rbp-56]=saved counter [rbp-64]=saved ext_size [rbp-72]=child body [rbp-80]=child len
    ; [rbp-88]=cursor [rbp-92]=i [rbp-96]=result [rbp-104]=saved att_total
    ; [rbp-108]=saved newatt_n [rbp-112]=saved attidx_n
    mov     qword ptr [rbp-24], rcx
    cmp     qword ptr [g_body_ptr], 0
    je      xs_novault
    ; ---- park every global the seal path touches --------------------------
    mov     rax, qword ptr [g_body_ptr]
    mov     qword ptr [rbp-32], rax
    mov     rax, qword ptr [g_body_len]
    mov     qword ptr [rbp-40], rax
    mov     rax, qword ptr [g_cfg_in]
    mov     qword ptr [rbp-48], rax
    mov     rax, qword ptr [g_save_counter]
    mov     qword ptr [rbp-56], rax
    mov     rax, qword ptr [g_ext_size]
    mov     qword ptr [rbp-64], rax
    mov     rax, qword ptr [g_att_total]
    mov     qword ptr [rbp-104], rax
    mov     eax, dword ptr [g_newatt_n]
    mov     dword ptr [rbp-108], eax
    mov     eax, dword ptr [g_attidx_n]
    mov     dword ptr [rbp-112], eax
    mov     rdx, qword ptr [rbp-48]
    call    vault_park_path
    mov     qword ptr [rbp-48], rax
    lea     rcx, [g_xs_hdr]                   ; header, key and change-hash are too big
    lea     rdx, [g_hdr]                      ;   for the frame - park them in statics
    mov     r8d, VH_TOTAL
    call    copy_bytes
    lea     rcx, [g_xs_vkey]
    lea     rdx, [g_vkey]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [g_xs_ehash]
    lea     rdx, [g_ext_hash]
    mov     r8d, 32
    call    copy_bytes
    ; ---- build the child body: selected, non-system entries only ----------
    mov     rcx, VAULT_BODY_MAX
    call    secmem_alloc
    test    rax, rax
    jz      xs_nomem
    mov     qword ptr [rbp-72], rax
    mov     dword ptr [rax], 0                ; entry_count = 0
    mov     qword ptr [rbp-80], 4
    mov     r10, qword ptr [rbp-32]
    add     r10, 4
    mov     qword ptr [rbp-88], r10           ; source cursor
    mov     dword ptr [rbp-92], 0
xs_loop:
    mov     eax, dword ptr [rbp-92]
    mov     r10, qword ptr [rbp-32]
    cmp     eax, dword ptr [r10]
    jae     xs_built
    cmp     eax, MAX_SEL                      ; the checklist cannot list more than this, so
    jae     xs_next                           ;   an entry past it was never SELECTED.  Reading
                                              ;   g_sel here ran off the array into the next
                                              ;   global - on a vault of >8192 entries that
                                              ;   decided what got written into a file the user
                                              ;   was about to share.  Same defect as fed_merge,
                                              ;   mirrored onto export, where it is worse.
    lea     r11, [g_sel]                      ; honour the checklist, exactly as the ZIP
    movzx   ecx, byte ptr [r11+rax]           ;   export does
    test    ecx, ecx
    jz      xs_next
    mov     rcx, qword ptr [rbp-88]           ; and never carry the system item
    call    sys_first_kind
    cmp     eax, VF_SYSTEM
    je      xs_next
    mov     ecx, dword ptr [rbp-92]           ; nor anything sitting in the trash: a record
    call    vault_is_deleted                  ;   the user deleted must not walk back out
    test    eax, eax                          ;   in a file they are about to share
    jnz     xs_next
    mov     rcx, qword ptr [rbp-88]
    call    vault_entry_len
    mov     r8, qword ptr [rbp-80]
    add     r8, rax
    cmp     r8, VAULT_BODY_MAX
    ja      xs_next                           ; no room -> drop it rather than overrun
    mov     rcx, qword ptr [rbp-88]
    mov     rdx, qword ptr [rbp-72]
    add     rdx, qword ptr [rbp-80]
    call    entry_copy_full                   ; verbatim: AttachRefs travel
    mov     r8d, eax
    add     qword ptr [rbp-80], r8
    mov     r10, qword ptr [rbp-72]
    inc     dword ptr [r10]
xs_next:
    mov     rcx, qword ptr [rbp-88]
    call    vault_entry_len
    add     qword ptr [rbp-88], rax
    inc     dword ptr [rbp-92]
    jmp     xs_loop
xs_built:
    ; ---- point the seal machinery at the child ----------------------------
    mov     rax, qword ptr [rbp-24]
    mov     rcx, rax
    call    cfg_in_set
    mov     rax, qword ptr [rbp-72]
    mov     qword ptr [g_body_ptr], rax
    mov     rax, qword ptr [rbp-80]
    mov     qword ptr [g_body_len], rax
    mov     dword ptr [g_hdr+0], VAULT_MAGIC  ; fresh header: new salt, new nonce, new key
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
    jz      xs_sealbad
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      xs_sealbad
    call    vk_derive                         ; child key from g_cfg_pass (the export pw)
    test    eax, eax
    jnz     xs_sealbad
    call    vk_kcv
    lea     r10, [g_sha32]
    lea     r9, [g_hdr+VH_KCV]
    xor     r8d, r8d
xs_kcv:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r9+r8], al
    inc     r8d
    cmp     r8d, KCV_LEN
    jb      xs_kcv
    mov     qword ptr [g_save_counter], 0     ; fresh vault: first save = counter 1
    mov     dword ptr [g_seal_noadopt], 1     ; do NOT let the child become the live image
    call    vault_seal_write
    mov     dword ptr [g_seal_noadopt], 0
    mov     dword ptr [rbp-96], eax
    jmp     xs_restore
xs_sealbad:
    mov     dword ptr [g_seal_noadopt], 0
    mov     dword ptr [rbp-96], EXIT_OOM
xs_restore:
    ; ---- put the live vault back exactly as it was ------------------------
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [g_body_ptr], rax
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [g_body_len], rax
    mov     rax, qword ptr [rbp-48]
    mov     rcx, rax
    call    cfg_in_set
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [g_save_counter], rax
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [g_ext_size], rax       ; vault_seal_write re-snapshotted these for
    mov     rax, qword ptr [rbp-104]          ;   the CHILD; the master's own snapshot must
    mov     qword ptr [g_att_total], rax      ;   survive or vault_ext_changed misfires
    mov     eax, dword ptr [rbp-108]
    mov     dword ptr [g_newatt_n], eax
    mov     eax, dword ptr [rbp-112]
    mov     dword ptr [g_attidx_n], eax
    lea     rcx, [g_hdr]
    lea     rdx, [g_xs_hdr]
    mov     r8d, VH_TOTAL
    call    copy_bytes
    lea     rcx, [g_vkey]
    lea     rdx, [g_xs_vkey]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [g_ext_hash]
    lea     rdx, [g_xs_ehash]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [g_xs_vkey]                  ; no second copy of the key outlives this
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_sha32]                    ; scrub child KCV digest
    mov     edx, 32
    call    secure_zero
    mov     rcx, qword ptr [rbp-72]
    mov     rdx, VAULT_BODY_MAX
    call    secmem_free
    mov     eax, dword ptr [rbp-96]
    FRAME_EPILOG
    ret
xs_nomem:
    lea     rcx, [g_xs_vkey]                  ; parked a key copy already - wipe it
    mov     edx, 32
    call    secure_zero
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
xs_novault:
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
vault_export_sel endp

; ===========================================================================
; vault_open_foreign(rcx = path wide, rdx = utf8 password, r8d = pwlen,
;                    r9 = *out body ptr) -> eax = 0 / EXIT_*.
;   Decrypt ANOTHER .vordr while the master vault stays open, handing the caller its
;   plaintext body (secmem-owned; caller frees with VAULT_BODY_MAX).
;
;   vault_unlock works entirely through the live globals, so this parks every one it
;   writes and puts them back - the same discipline vault_export_sel needs, for the same
;   reason: the master must be byte-identical afterwards.  On success it also frees the
;   FOREIGN file image; only the body survives, which is all a merge needs (attachment
;   fields are stripped by entry_copy_filtered, so the foreign blob store is not wanted).
; ===========================================================================
public vault_open_foreign
vault_open_foreign proc frame
    FRAME_PROLOG 208
    ; [rbp-24]=path [rbp-32]=pw [rbp-40]=pwlen [rbp-48]=out
    ; parked: [rbp-56]=body [rbp-64]=bodylen [rbp-72]=cfg_in [rbp-80]=counter
    ;         [rbp-88]=ext_size [rbp-96]=filebuf [rbp-104]=filesize [rbp-112]=fmac_len
    ;         [rbp-120]=att_total [rbp-124]=newatt_n [rbp-128]=attidx_n [rbp-132]=passlen
    ;         [rbp-140]=use_tpm [rbp-144]=preloaded [rbp-152]=vof_buf [rbp-160]=vof_len
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     dword ptr [rbp-40], r8d
    mov     qword ptr [rbp-48], r9
    mov     rax, qword ptr [g_vof_buf]          ; consume one-shot pre-read buffer
    mov     qword ptr [g_vof_buf], 0
    mov     qword ptr [rbp-152], rax
    mov     rax, qword ptr [g_vof_len]
    mov     qword ptr [g_vof_len], 0
    mov     qword ptr [rbp-160], rax
    mov     rax, qword ptr [g_body_ptr]
    mov     qword ptr [rbp-56], rax
    mov     rax, qword ptr [g_body_len]
    mov     qword ptr [rbp-64], rax
    mov     rax, qword ptr [g_cfg_in]
    mov     qword ptr [rbp-72], rax
    mov     rax, qword ptr [g_save_counter]
    mov     qword ptr [rbp-80], rax
    mov     rax, qword ptr [g_ext_size]
    mov     qword ptr [rbp-88], rax
    mov     rax, qword ptr [g_filebuf]
    mov     qword ptr [rbp-96], rax
    mov     rax, qword ptr [g_filesize]
    mov     qword ptr [rbp-104], rax
    mov     rax, qword ptr [g_fmac_len]
    mov     qword ptr [rbp-112], rax
    mov     rax, qword ptr [g_att_total]
    mov     qword ptr [rbp-120], rax
    mov     eax, dword ptr [g_newatt_n]
    mov     dword ptr [rbp-124], eax
    mov     eax, dword ptr [g_attidx_n]
    mov     dword ptr [rbp-128], eax
    mov     eax, dword ptr [g_cfg_passlen]
    mov     dword ptr [rbp-132], eax
    mov     eax, dword ptr [g_use_tpm]
    mov     dword ptr [rbp-140], eax
    mov     eax, dword ptr [g_preloaded]
    mov     dword ptr [rbp-144], eax
    mov     rdx, qword ptr [rbp-72]
    call    vault_park_path
    mov     qword ptr [rbp-72], rax
    lea     rcx, [g_xs_hdr]
    lea     rdx, [g_hdr]
    mov     r8d, VH_TOTAL
    call    copy_bytes
    lea     rcx, [g_xs_vkey]
    lea     rdx, [g_vkey]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [g_xs_ehash]
    lea     rdx, [g_ext_hash]
    mov     r8d, 32
    call    copy_bytes
    call    vault_state_park                    ; incl. the attachment index TABLE (see there)
    ; ---- open the foreign file in place of the live one ----------------------
    mov     rax, qword ptr [rbp-24]
    mov     rcx, rax
    call    cfg_in_set
    lea     rcx, [g_cfg_pass]
    mov     rdx, qword ptr [rbp-32]
    mov     r8d, dword ptr [rbp-40]
    call    copy_bytes
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [g_cfg_passlen], eax
    mov     dword ptr [g_use_tpm], 0            ; a foreign vault is never TPM-enrolled here
    mov     dword ptr [g_reuse_key], 0          ; and its key must be derived, not reused
    mov     qword ptr [g_body_ptr], 0           ; vault_unlock allocates its own
    mov     rax, qword ptr [rbp-152]            ; optional pre-read foreign image
    test    rax, rax
    jz      vof_diskread
    mov     qword ptr [g_filebuf], rax
    mov     rax, qword ptr [rbp-160]
    mov     qword ptr [g_filesize], rax
    mov     dword ptr [g_preloaded], 1
    jmp     vof_call_unlock
vof_diskread:
    mov     qword ptr [g_filebuf], 0
    mov     dword ptr [g_preloaded], 0
vof_call_unlock:
    call    vault_unlock
    mov     dword ptr [g_preloaded], 0          ; vof_restore/vof_failed owns & frees g_filebuf
    mov     dword ptr [rbp-136], eax
    test    eax, eax
    jnz     vof_failed
    mov     rax, qword ptr [g_body_ptr]         ; hand the body to the caller
    mov     r10, qword ptr [rbp-48]
    mov     qword ptr [r10], rax
    mov     rcx, qword ptr [g_filebuf]          ; the foreign image itself is not wanted
    test    rcx, rcx
    jz      vof_restore
    mov     rdx, qword ptr [g_filesize]
    call    mem_free
    jmp     vof_restore
vof_failed:
    mov     rcx, qword ptr [g_body_ptr]         ; partial open: release whatever it took
    test    rcx, rcx
    jz      vof_f2
    mov     rdx, VAULT_BODY_MAX
    call    secmem_free
vof_f2:
    mov     rcx, qword ptr [g_filebuf]
    test    rcx, rcx
    jz      vof_restore
    mov     rdx, qword ptr [g_filesize]
    call    mem_free
vof_restore:
    ; ---- put the master back, byte for byte ---------------------------------
    call    vault_state_restore
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [g_body_ptr], rax
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [g_body_len], rax
    mov     rax, qword ptr [rbp-72]
    mov     rcx, rax
    call    cfg_in_set
    mov     rax, qword ptr [rbp-80]
    mov     qword ptr [g_save_counter], rax
    mov     rax, qword ptr [rbp-88]
    mov     qword ptr [g_ext_size], rax
    mov     rax, qword ptr [rbp-96]
    mov     qword ptr [g_filebuf], rax
    mov     rax, qword ptr [rbp-104]
    mov     qword ptr [g_filesize], rax
    mov     rax, qword ptr [rbp-112]
    mov     qword ptr [g_fmac_len], rax
    mov     rax, qword ptr [rbp-120]
    mov     qword ptr [g_att_total], rax
    mov     eax, dword ptr [rbp-124]
    mov     dword ptr [g_newatt_n], eax
    mov     eax, dword ptr [rbp-128]
    mov     dword ptr [g_attidx_n], eax
    lea     rcx, [g_hdr]
    lea     rdx, [g_xs_hdr]
    mov     r8d, VH_TOTAL
    call    copy_bytes
    lea     rcx, [g_vkey]
    lea     rdx, [g_xs_vkey]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [g_ext_hash]
    lea     rdx, [g_xs_ehash]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [g_xs_vkey]                    ; no second copy of the master key survives
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_sha32]                      ; nor foreign KCV digest
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_cfg_pass]                   ; nor the foreign password we were handed
    mov     edx, MAX_PASSWORD_BYTES+1
    call    secure_zero
    mov     dword ptr [g_cfg_passlen], 0
    mov     eax, dword ptr [rbp-140]
    mov     dword ptr [g_use_tpm], eax
    mov     eax, dword ptr [rbp-144]
    mov     dword ptr [g_preloaded], eax
    mov     eax, dword ptr [rbp-136]
    FRAME_EPILOG
    ret
vault_open_foreign endp

; vault_free_foreign(rcx = body from vault_open_foreign) - release it.  Null-safe.
;   Keeps VAULT_BODY_MAX in the module that allocates, so callers cannot mirror it and
;   drift (constcheck would only catch a mismatch after it was already written).
public vault_free_foreign
vault_free_foreign proc frame
    FRAME_PROLOG 32
    test    rcx, rcx
    jz      vff_done
    mov     rdx, VAULT_BODY_MAX
    call    secmem_free
vff_done:
    FRAME_EPILOG
    ret
vault_free_foreign endp

; fed_merge(rcx = source body ptr) -> eax = number of entries added or updated.
;   Merge every source entry into the live body, deduped by the 16-byte entry id:
;   an id already present is updated only if the source's `modified` is newer, else
;   skipped.  Attachments filtered (v1).  The caller reseals.  Idempotent.
public fed_merge
fed_merge proc frame
    FRAME_PROLOG 96                             ; locals to -72, clear of the home area
    mov     qword ptr [rbp-24], rcx           ; source body
    mov     dword ptr [rbp-28], 0             ; changed count
    mov     r10, rcx
    mov     eax, dword ptr [r10]
    mov     dword ptr [rbp-32], eax           ; source count
    add     r10, 4
    mov     qword ptr [rbp-40], r10           ; source entry cursor
    mov     dword ptr [rbp-44], 0             ; i
fm_loop:
    mov     eax, dword ptr [rbp-44]
    cmp     eax, dword ptr [rbp-32]
    jae     fm_done
    cmp     dword ptr [g_merge_sel], 0        ; GUI import: honour the checklist.  Off by
    je      fm_nosel                          ;   default, so the headless callers that
                                              ;   merge everything are unchanged.
    cmp     eax, MAX_SEL                      ; g_sel is MAX_SEL BYTES and the checklist
    jae     fm_next                           ;   cannot list more, so an entry past the
                                              ;   end was never selectable.  Reading it
                                              ;   ran off the array into whatever global
                                              ;   follows: a 10000-entry source imported
                                              ;   8602 records - the 8192 genuinely ticked
                                              ;   plus ~410 decided by adjacent memory.
    lea     r11, [g_sel]
    movzx   ecx, byte ptr [r11+rax]
    test    ecx, ecx
    jz      fm_next
fm_nosel:
    mov     rcx, qword ptr [rbp-40]           ; never merge in a foreign system item: dedup is
    call    sys_first_kind                    ;   by ENTRY id, so it would not collide with
    cmp     eax, VF_SYSTEM                    ;   ours - it would land as a SECOND system item,
    je      fm_next                           ;   and vault_sys_find takes the first, silently
                                              ;   shadowing this vault's own stamp.
    mov     rcx, qword ptr [rbp-40]           ; nor a record the SOURCE had in its trash -
    mov     edx, VF_DELETED                   ;   importing someone's deleted secrets back
    call    entry_has_field                   ;   into a live vault is never wanted.  Scans
    test    eax, eax                          ;   the fields: VF_DELETED is appended, not
    jnz     fm_next                           ;   field[0], so sys_first_kind cannot see it.
    mov     rcx, qword ptr [rbp-40]           ; src entry (id at +0)
    call    fed_find_by_id
    cmp     eax, -1
    je      fm_append
    mov     dword ptr [rbp-48], eax           ; dest idx
    mov     ecx, eax
    call    vault_entry_ptr                   ; rax = dest entry
    mov     r10, qword ptr [rbp-40]           ; src entry
    mov     r8, qword ptr [r10+24]           ; src modified
    cmp     r8, qword ptr [rax+24]           ; vs dest modified
    jbe     fm_next                           ; src not newer -> keep dest, skip
    ; Src is newer: replace dest.  Two things this used to get wrong.  It removed dest
    ; BEFORE checking there was room for the replacement, so a full body simply lost
    ; the entry.  And the replacement is attachment-stripped (the source's blobs are
    ; not carried), so dest's own attachments vanished with it - re-importing an
    ; exported copy that had been edited deleted every file on that entry.  Now: room
    ; for src + all of dest is checked first, the replacement is appended, dest's
    ; attachment fields are carried onto it, and only then is dest removed.
    mov     qword ptr [rbp-56], rax           ; dest ptr (stays valid: appends go after it)
    mov     rcx, rax
    call    vault_entry_len
    mov     qword ptr [rbp-64], rax           ; dest len
    mov     rcx, qword ptr [rbp-40]
    call    vault_entry_len
    mov     r8, qword ptr [g_body_len]
    add     r8, rax
    add     r8, qword ptr [rbp-64]
    cmp     r8, VAULT_BODY_MAX
    ja      fm_next                           ; no room -> keep dest untouched
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, qword ptr [g_body_ptr]
    add     rdx, qword ptr [g_body_len]
    mov     qword ptr [rbp-72], rdx           ; the replacement entry
    call    entry_copy_filtered
    mov     r8d, eax
    add     qword ptr [g_body_len], r8
    mov     r10, qword ptr [g_body_ptr]
    inc     dword ptr [r10]
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-72]
    call    entry_carry_att                   ; dest's attachments -> the replacement
    mov     ecx, dword ptr [rbp-48]           ; now drop dest (it precedes the new one,
    call    vault_remove_at                   ;   so its index is unchanged)
    inc     dword ptr [rbp-28]                ; changed++
    jmp     fm_next
fm_append:
    mov     rcx, qword ptr [rbp-40]           ; bounds: room for the full src entry
    call    vault_entry_len
    mov     r8, qword ptr [g_body_len]
    add     r8, rax
    cmp     r8, VAULT_BODY_MAX
    ja      fm_next
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, qword ptr [g_body_ptr]
    add     rdx, qword ptr [g_body_len]
    call    entry_copy_filtered
    mov     r8d, eax
    add     qword ptr [g_body_len], r8
    mov     r10, qword ptr [g_body_ptr]
    inc     dword ptr [r10]
    inc     dword ptr [rbp-28]                ; changed++
fm_next:
    mov     rcx, qword ptr [rbp-40]
    call    vault_entry_len
    add     qword ptr [rbp-40], rax
    inc     dword ptr [rbp-44]
    jmp     fm_loop
fm_done:
    mov     eax, dword ptr [rbp-28]
    FRAME_EPILOG
    ret
fed_merge endp

; entry_carry_att(rcx = from entry, rdx = to entry) - append every VF_IMAGE/VF_FILE
;   field of `from` to the end of the body, as fields of `to`, which must be the LAST
;   entry.  Raw field copies: the AttachRef (id/key/nonce) travels unchanged, so the
;   ciphertext already in the file still resolves.  The caller has checked the room.
;   Leaf.
entry_carry_att proc
    mov     r9d, dword ptr [rcx+32]             ; from: field count
    lea     r10, [rcx+36]                       ; from: field cursor
    mov     r11, qword ptr [g_body_ptr]
    add     r11, qword ptr [g_body_len]         ; write cursor = body end
eca_lp:
    test    r9d, r9d
    jz      eca_done
    movzx   eax, word ptr [r10]
    and     eax, VF_KINDMASK
    mov     r8d, dword ptr [r10+2]
    add     r8d, 6                              ; whole field
    cmp     eax, VF_IMAGE
    je      eca_copy
    cmp     eax, VF_FILE
    jne     eca_next
eca_copy:
    xor     ecx, ecx
eca_cb:
    cmp     ecx, r8d
    jae     eca_cbd
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    inc     ecx
    jmp     eca_cb
eca_cbd:
    add     r11, r8
    add     qword ptr [g_body_len], r8
    inc     dword ptr [rdx+32]                  ; to: one more field
eca_next:
    add     r10, r8
    dec     r9d
    jmp     eca_lp
eca_done:
    ret
entry_carry_att endp

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
    ; inside a vault_index_begin/end bracket, and the body still the one indexed:
    ; one load instead of a walk from the first entry
    cmp     dword ptr [g_eidx_n], 0
    je      vep_walk
    cmp     r10, qword ptr [g_eidx_body]
    jne     vep_walk
    mov     rax, qword ptr [g_body_len]
    cmp     rax, qword ptr [g_eidx_blen]
    jne     vep_walk
    cmp     ecx, dword ptr [g_eidx_n]
    jae     vep_walk
    mov     r11, qword ptr [g_eidx]
    mov     rax, qword ptr [r11+rcx*8]
    FRAME_EPILOG
    ret
vep_walk:
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

; vault_index_begin / vault_index_end - a bracket inside which entry lookups by
;   index take one load instead of a walk from the first entry.  vault_entry_ptr
;   walks because entries are variable-length records packed in the body; a
;   bulk read (a search refill: ~60,000 sort comparisons, each looking up two
;   titles; a list paint near the end of a large vault) made that O(n^2) - 3.5 s
;   to refill 5,000 entries.  The index is built in one pass at the outermost
;   begin and used only until the outermost end, so it never outlives a body it
;   was built from: nothing writes the body in between (the UI thread is busy
;   with the read).  A lookup also checks the body's pointer and length against
;   the ones indexed, and walks if either differs.
public vault_index_begin, vault_index_end
vault_index_begin proc frame
    FRAME_PROLOG 64
    inc     dword ptr [g_eidx_dep]
    cmp     dword ptr [g_eidx_dep], 1
    jne     vib_ret
    mov     dword ptr [g_eidx_n], 0
    mov     r10, qword ptr [g_body_ptr]
    test    r10, r10
    jz      vib_ret
    mov     eax, dword ptr [r10]
    test    eax, eax
    jz      vib_ret
    mov     dword ptr [rbp-24], eax              ; entries
    cmp     eax, dword ptr [g_eidx_cap]
    jbe     vib_have
    mov     rcx, qword ptr [g_eidx]              ; grow (whole KiB of entries)
    mov     edx, dword ptr [g_eidx_cap]
    shl     rdx, 3
    call    mem_free
    mov     qword ptr [g_eidx], 0
    mov     dword ptr [g_eidx_cap], 0
    mov     eax, dword ptr [rbp-24]
    add     eax, 1023
    and     eax, -1024
    mov     dword ptr [rbp-28], eax
    mov     ecx, eax
    shl     rcx, 3
    call    mem_alloc
    test    rax, rax
    jz      vib_ret                              ; no index: lookups walk, as before
    mov     qword ptr [g_eidx], rax
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [g_eidx_cap], eax
vib_have:
    mov     r10, qword ptr [g_body_ptr]
    lea     rcx, [r10+4]
    mov     qword ptr [rbp-40], rcx              ; cursor
    mov     dword ptr [rbp-32], 0                ; i
vib_lp:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [rbp-24]
    jae     vib_done
    mov     r10, qword ptr [g_eidx]
    mov     rcx, qword ptr [rbp-40]
    mov     qword ptr [r10+rax*8], rcx
    call    vault_entry_len
    add     qword ptr [rbp-40], rax
    inc     dword ptr [rbp-32]
    jmp     vib_lp
vib_done:
    mov     rax, qword ptr [g_body_ptr]
    mov     qword ptr [g_eidx_body], rax
    mov     rax, qword ptr [g_body_len]
    mov     qword ptr [g_eidx_blen], rax
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_eidx_n], eax
vib_ret:
    FRAME_EPILOG
    ret
vault_index_begin endp

vault_index_end proc frame
    FRAME_PROLOG 32
    cmp     dword ptr [g_eidx_dep], 0
    je      vie_ret
    dec     dword ptr [g_eidx_dep]
    jnz     vie_ret
    mov     dword ptr [g_eidx_n], 0
vie_ret:
    FRAME_EPILOG
    ret
vault_index_end endp

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
HDIG              equ 16                            ; BLAKE2b digest bytes / field
HCRED_STRIDE      equ 24                            ; {digest16, u32 entry_idx, u32 kind}

; ===========================================================================
; pin_eval(rcx = utf8 bytes, edx = len, r8d = minlen)
;   -> eax = grade (0 = Weak, 2 = Good, 3 = Strong), edx = reason (PIN_*).
;   Evaluates a PIN / passcode with NO character-class requirement:
;     - Strict UTF-8 scalar decoding (digits, letters, symbols all welcome)
;     - Length >= minlen codepoints (else grade 0, PIN_SHORT)
;     - Rejects trivial patterns as grade 0, PIN_TRIVIAL:
;         1) All codepoints identical ("000000", "aaaaaa")
;         2) Straight +1 or -1 arithmetic run ("123456", "654321", "abcdef")
;         3) Exact repeating 2- or 3-codepoint cycle ("121212", "123123", "ababab")
;         4) Exact palindrome of length >= 4 ("123321", "1221", "984489")
;     - Non-trivial: length >= max(minlen+2, 8) -> 3 (Strong), else 2 (Good).
;   Decoded scalar scratch on the stack is wiped via secure_zero before return.
; ===========================================================================
public pin_eval
pin_eval proc frame
    FRAME_PROLOG 608
    ; [rbp-16]=utf8 [rbp-24]=len [rbp-28]=minlen [rbp-32]=cp_total
    ; [rbp-36]=stream_same [rbp-40]=stream_step [rbp-44]=prev_cp [rbp-48]=step_delta
    ; [rbp-52]=grade [rbp-56]=reason [rbp-576..-65]=cp_buf[128]
    mov     qword ptr [rbp-16], rcx
    mov     dword ptr [rbp-24], edx
    cmp     r8d, 1
    jge     @F
    mov     r8d, PIN_MINLEN_DEF
@@: mov     dword ptr [rbp-28], r8d
    mov     dword ptr [rbp-32], 0
    mov     dword ptr [rbp-36], 1
    mov     dword ptr [rbp-40], 1
    mov     dword ptr [rbp-44], 0
    mov     dword ptr [rbp-48], 0
    mov     dword ptr [rbp-52], 0
    mov     dword ptr [rbp-56], PIN_SHORT
    lea     rcx, [rbp-576]
    mov     edx, 512
    call    secure_zero
    mov     r10, qword ptr [rbp-16]
    mov     r11d, dword ptr [rbp-24]
    test    r10, r10
    jz      pe_finish
    test    r11d, r11d
    jz      pe_finish
    xor     r9d, r9d                            ; byte cursor
    xor     ecx, ecx                            ; cp_total
pe_u8_lp:
    cmp     r9d, r11d
    jae     pe_u8_done
    movzx   eax, byte ptr [r10+r9]
    cmp     eax, 80h
    jae     pe_u8_mb
    mov     edx, eax
    inc     r9d
    jmp     pe_got_cp
pe_u8_mb:
    cmp     eax, 0C2h
    jb      pe_badutf                           ; 80..C1: stray continuation or overlong
    cmp     eax, 0DFh
    ja      pe_u8_3or4
    lea     r8d, [r9+2]
    cmp     r8d, r11d
    ja      pe_badutf
    movzx   edx, byte ptr [r10+r9+1]
    mov     r8d, edx
    and     r8d, 0C0h
    cmp     r8d, 80h
    jne     pe_badutf
    and     eax, 1Fh
    shl     eax, 6
    and     edx, 3Fh
    or      edx, eax
    add     r9d, 2
    jmp     pe_got_cp
pe_u8_3or4:
    cmp     eax, 0EFh
    ja      pe_u8_4
    lea     r8d, [r9+3]
    cmp     r8d, r11d
    ja      pe_badutf
    movzx   edx, byte ptr [r10+r9+1]
    mov     r8d, edx
    and     r8d, 0C0h
    cmp     r8d, 80h
    jne     pe_badutf
    and     eax, 0Fh
    shl     eax, 12
    and     edx, 3Fh
    shl     edx, 6
    or      eax, edx
    movzx   edx, byte ptr [r10+r9+2]
    mov     r8d, edx
    and     r8d, 0C0h
    cmp     r8d, 80h
    jne     pe_badutf
    and     edx, 3Fh
    or      edx, eax
    cmp     edx, 800h
    jb      pe_badutf                           ; overlong 3-byte
    cmp     edx, 0D800h
    jb      pe_3ok
    cmp     edx, 0DFFFh
    jbe     pe_badutf                           ; UTF-16 surrogate half
pe_3ok:
    add     r9d, 3
    jmp     pe_got_cp
pe_u8_4:
    cmp     eax, 0F4h
    ja      pe_badutf
    lea     r8d, [r9+4]
    cmp     r8d, r11d
    ja      pe_badutf
    and     eax, 07h
    shl     eax, 18
    movzx   edx, byte ptr [r10+r9+1]
    mov     r8d, edx
    and     r8d, 0C0h
    cmp     r8d, 80h
    jne     pe_badutf
    and     edx, 3Fh
    shl     edx, 12
    or      eax, edx
    movzx   edx, byte ptr [r10+r9+2]
    mov     r8d, edx
    and     r8d, 0C0h
    cmp     r8d, 80h
    jne     pe_badutf
    and     edx, 3Fh
    shl     edx, 6
    or      eax, edx
    movzx   edx, byte ptr [r10+r9+3]
    mov     r8d, edx
    and     r8d, 0C0h
    cmp     r8d, 80h
    jne     pe_badutf
    and     edx, 3Fh
    or      edx, eax
    cmp     edx, 10000h
    jb      pe_badutf                           ; overlong 4-byte
    cmp     edx, 10FFFFh
    ja      pe_badutf                           ; > Unicode max
    add     r9d, 4
pe_got_cp:
    cmp     ecx, 128
    jae     pe_stream
    mov     dword ptr [rbp-576+rcx*4], edx
pe_stream:
    test    ecx, ecx
    jnz     pe_not_first
    mov     dword ptr [rbp-44], edx             ; prev_cp = cp[0]
    inc     ecx
    jmp     pe_u8_lp
pe_not_first:
    cmp     edx, dword ptr [rbp-576]
    je      @F
    mov     dword ptr [rbp-36], 0               ; differs from cp[0] -> not all-same
@@: mov     eax, edx
    sub     eax, dword ptr [rbp-44]             ; delta = cp[i] - cp[i-1]
    cmp     ecx, 1
    jne     pe_step_n
    mov     dword ptr [rbp-48], eax             ; step_delta = cp[1] - cp[0]
    cmp     eax, 1
    je      pe_step_done
    cmp     eax, -1
    je      pe_step_done
    mov     dword ptr [rbp-40], 0
    jmp     pe_step_done
pe_step_n:
    cmp     eax, dword ptr [rbp-48]
    je      pe_step_done
    mov     dword ptr [rbp-40], 0
pe_step_done:
    mov     dword ptr [rbp-44], edx
    inc     ecx
    jmp     pe_u8_lp

pe_badutf:
    mov     dword ptr [rbp-52], 0
    mov     dword ptr [rbp-56], PIN_BADUTF8
    jmp     pe_finish

pe_u8_done:
    mov     dword ptr [rbp-32], ecx
    cmp     ecx, dword ptr [rbp-28]             ; cp_total < minlen?
    jb      pe_short
    ; 1) All identical ("000000", "aaaaaa")
    cmp     ecx, 2
    jb      pe_grade_ok
    cmp     dword ptr [rbp-36], 0
    jne     pe_triv
    ; 2) Straight +1 / -1 run ("123456", "654321", "abcdef")
    cmp     ecx, 3
    jb      pe_chk_bounded
    cmp     dword ptr [rbp-40], 0
    jne     pe_triv
pe_chk_bounded:
    cmp     ecx, 128
    ja      pe_grade_ok                         ; > 128 non-same non-run codepoints
    ; 3a) Period-2 repeating cycle ("121212", "ababab", len >= 4)
    cmp     ecx, 4
    jb      pe_grade_ok
    mov     r8d, 2
pe_p2_lp:
    cmp     r8d, ecx
    jae     pe_triv                             ; all cp[i] == cp[i-2] -> period-2!
    mov     eax, dword ptr [rbp-576+r8*4]
    cmp     eax, dword ptr [rbp-576+r8*4-8]
    jne     pe_chk_p3
    inc     r8d
    jmp     pe_p2_lp
pe_chk_p3:
    ; 3b) Period-3 repeating cycle ("123123", "abcabc", len >= 6)
    cmp     ecx, 6
    jb      pe_chk_pal
    mov     r8d, 3
pe_p3_lp:
    cmp     r8d, ecx
    jae     pe_triv                             ; all cp[i] == cp[i-3] -> period-3!
    mov     eax, dword ptr [rbp-576+r8*4]
    cmp     eax, dword ptr [rbp-576+r8*4-12]
    jne     pe_chk_pal
    inc     r8d
    jmp     pe_p3_lp
pe_chk_pal:
    ; 4) Exact palindrome of length >= 4 ("123321", "1221", "984489")
    xor     r8d, r8d
    lea     r9d, [rcx-1]
pe_pal_lp:
    cmp     r8d, r9d
    jae     pe_triv                             ; mirrored across entire length -> palindrome!
    mov     eax, dword ptr [rbp-576+r8*4]
    cmp     eax, dword ptr [rbp-576+r9*4]
    jne     pe_grade_ok
    inc     r8d
    dec     r9d
    jmp     pe_pal_lp

pe_grade_ok:
    mov     dword ptr [rbp-56], PIN_OK
    mov     eax, dword ptr [rbp-28]             ; strong floor = max(minlen + 2, 8)
    add     eax, 2
    cmp     eax, 8
    jae     @F
    mov     eax, 8
@@: mov     edx, 2                              ; Good
    cmp     ecx, eax
    jb      @F
    mov     edx, 3                              ; Strong
@@: mov     dword ptr [rbp-52], edx
    jmp     pe_finish

pe_short:
    mov     dword ptr [rbp-52], 0
    mov     dword ptr [rbp-56], PIN_SHORT
    jmp     pe_finish

pe_triv:
    mov     dword ptr [rbp-52], 0
    mov     dword ptr [rbp-56], PIN_TRIVIAL

pe_finish:
    lea     rcx, [rbp-576]
    mov     edx, 512
    call    secure_zero
    mov     eax, dword ptr [rbp-52]
    mov     edx, dword ptr [rbp-56]
    FRAME_EPILOG
    ret
pin_eval endp

; vh_pin_weak(rcx = utf8 bytes, edx = len) -> eax = 1 if the PIN is weak (grade 0).
public vh_pin_weak
vh_pin_weak proc frame
    FRAME_PROLOG 32
    mov     r8d, dword ptr [g_cfg_pinminlen]
    call    pin_eval
    xor     ecx, ecx
    test    eax, eax
    setz    cl
    mov     eax, ecx
    FRAME_EPILOG
    ret
vh_pin_weak endp

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
;   total}.  Walks every non-empty VF_SECRET (graded via vh_pw_weak) and VF_PIN
;   (graded via vh_pin_weak) across all user entries:
;     - weak   = entries carrying at least one weak password or weak PIN
;     - reused = entries sharing a same-kind credential (BLAKE2b-128, domain-
;                separated by base kind so VF_PIN never collides with VF_SECRET)
;                with at least one other entry
;     - old    = credential-bearing entries modified > HEALTH_OLD_100NS ago
;     - total  = vault_user_count (entries with no credentials count here only)
public vault_health
vault_health proc frame
    FRAME_PROLOG 176
    ; [rbp-16]=out [rbp-24]=n [rbp-32]=scratch [rbp-40]=cred_total [rbp-48]=cred_written
    ; [rbp-56]=i [rbp-64]=weak [rbp-72]=old [rbp-80]=reused [rbp-88]=now
    ; [rbp-96]=f_ptr [rbp-104]=f_rem [rbp-112]=val_ptr [rbp-116]=val_len
    ; [rbp-120]=base_kind [rbp-124]=has_cred [rbp-128]=is_weak
    ; [rbp-132]=last_reused_ei [rbp-136]=j
    mov     qword ptr [rbp-16], rcx
    mov     dword ptr [rcx+0], 0
    mov     dword ptr [rcx+4], 0
    mov     dword ptr [rcx+8], 0
    mov     dword ptr [rcx+12], 0
    mov     dword ptr [rbp-40], 0
    mov     dword ptr [rbp-48], 0
    mov     dword ptr [rbp-64], 0
    mov     dword ptr [rbp-72], 0
    mov     dword ptr [rbp-80], 0
    mov     qword ptr [rbp-32], 0
    call    vault_count
    mov     dword ptr [rbp-24], eax
    call    vault_user_count
    mov     r10, qword ptr [rbp-16]
    mov     dword ptr [r10+12], eax             ; total
    mov     eax, dword ptr [rbp-24]
    test    eax, eax
    jz      vh_done

    ; --- Pass 1: count non-empty VF_SECRET / VF_PIN fields across user entries ---
    mov     dword ptr [rbp-56], 0
vh_cnt_ent:
    mov     eax, dword ptr [rbp-56]
    cmp     eax, dword ptr [rbp-24]
    jae     vh_alloc
    mov     ecx, eax
    call    vault_is_system
    test    eax, eax
    jnz     vh_cnt_next
    mov     ecx, dword ptr [rbp-56]
    call    vault_entry_ptr
    test    rax, rax
    jz      vh_cnt_next
    mov     r8d, dword ptr [rax+32]             ; field_count
    lea     r10, [rax+36]
vh_cnt_fld:
    test    r8d, r8d
    jz      vh_cnt_next
    movzx   eax, word ptr [r10]
    mov     r9d, dword ptr [r10+2]              ; field bytes len
    mov     ecx, eax
    and     ecx, VF_KINDMASK
    cmp     ecx, VF_SECRET
    je      vh_cnt_cred
    cmp     ecx, VF_PIN
    jne     vh_cnt_fadv
vh_cnt_cred:
    mov     edx, r9d
    test    eax, VF_LABELED
    jz      @F
    movzx   eax, word ptr [r10+6]
    add     eax, 2
    sub     edx, eax
@@: test    edx, edx
    jle     vh_cnt_fadv
    inc     dword ptr [rbp-40]
vh_cnt_fadv:
    add     r10, 6
    add     r10, r9
    dec     r8d
    jmp     vh_cnt_fld
vh_cnt_next:
    inc     dword ptr [rbp-56]
    jmp     vh_cnt_ent

vh_alloc:
    mov     ecx, dword ptr [rbp-40]
    test    ecx, ecx
    jz      vh_time
    imul    rcx, rcx, HCRED_STRIDE
    call    mem_alloc
    mov     qword ptr [rbp-32], rax             ; 0 => dup pass gracefully skipped
vh_time:
    lea     rcx, [g_ts]
    call    GetSystemTimeAsFileTime
    mov     rax, qword ptr [g_ts]
    mov     qword ptr [rbp-88], rax             ; now

    ; --- Pass 2: evaluate weak/old per entry and emit domain-tagged digests ------
    mov     dword ptr [rbp-56], 0               ; i
vh_loop:
    mov     eax, dword ptr [rbp-56]
    cmp     eax, dword ptr [rbp-24]
    jae     vh_dups
    mov     ecx, eax
    call    vault_is_system
    test    eax, eax
    jnz     vh_next
    mov     ecx, dword ptr [rbp-56]
    call    vault_entry_ptr
    test    rax, rax
    jz      vh_next
    mov     dword ptr [rbp-124], 0              ; has_cred = 0
    mov     dword ptr [rbp-128], 0              ; is_weak = 0
    mov     ecx, dword ptr [rax+32]
    mov     dword ptr [rbp-104], ecx            ; f_rem
    lea     rcx, [rax+36]
    mov     qword ptr [rbp-96], rcx             ; f_ptr
vh_floop:
    cmp     dword ptr [rbp-104], 0
    je      vh_entry_fin
    mov     r10, qword ptr [rbp-96]
    movzx   eax, word ptr [r10]                 ; raw type
    mov     r9d, dword ptr [r10+2]              ; field bytes len
    lea     rdx, [r10+6]                        ; val_ptr
    mov     r11d, r9d                           ; val_len
    lea     rcx, [r10+6]
    add     rcx, r9
    mov     qword ptr [rbp-96], rcx             ; advance f_ptr now
    dec     dword ptr [rbp-104]
    mov     ecx, eax
    and     ecx, VF_KINDMASK
    cmp     ecx, VF_SECRET
    je      vh_fcred
    cmp     ecx, VF_PIN
    jne     vh_floop
vh_fcred:
    test    eax, VF_LABELED
    jz      @F
    movzx   eax, word ptr [rdx]
    add     eax, 2
    add     rdx, rax
    sub     r11d, eax
@@: test    r11d, r11d
    jle     vh_floop
    mov     dword ptr [rbp-124], 1              ; has_cred = 1
    mov     qword ptr [rbp-112], rdx            ; val_ptr
    mov     dword ptr [rbp-116], r11d           ; val_len
    mov     dword ptr [rbp-120], ecx            ; base_kind
    cmp     ecx, VF_PIN
    je      vh_chk_pin
    mov     rcx, rdx
    mov     edx, r11d
    call    vh_pw_weak
    jmp     vh_got_weak
vh_chk_pin:
    mov     rcx, rdx
    mov     edx, r11d
    call    vh_pin_weak
vh_got_weak:
    test    eax, eax
    jz      vh_fhash
    mov     dword ptr [rbp-128], 1
vh_fhash:
    mov     r10, qword ptr [rbp-32]
    test    r10, r10
    jz      vh_floop
    mov     eax, dword ptr [rbp-48]
    cmp     eax, dword ptr [rbp-40]
    jae     vh_floop
    imul    rax, rax, HCRED_STRIDE
    lea     r8, [r10+rax]                       ; &row[cred_written]
    mov     ecx, dword ptr [rbp-56]
    mov     dword ptr [r8+16], ecx              ; entry_idx
    mov     ecx, dword ptr [rbp-120]
    mov     dword ptr [r8+20], ecx              ; kind (domain tag)
    mov     rcx, qword ptr [rbp-112]
    mov     edx, dword ptr [rbp-116]
    mov     r9, HDIG
    call    blake2b_hash
    inc     dword ptr [rbp-48]
    jmp     vh_floop

vh_entry_fin:
    cmp     dword ptr [rbp-124], 0
    je      vh_next
    cmp     dword ptr [rbp-128], 0
    je      @F
    inc     dword ptr [rbp-64]                  ; weak++
@@: mov     ecx, dword ptr [rbp-56]
    call    vault_entry_ptr
    test    rax, rax
    jz      vh_next
    mov     rdx, qword ptr [rbp-88]             ; now
    sub     rdx, qword ptr [rax+24]             ; now - modified
    js      vh_next
    mov     r8, HEALTH_OLD_100NS
    cmp     rdx, r8
    jbe     vh_next
    inc     dword ptr [rbp-72]                  ; old++
vh_next:
    inc     dword ptr [rbp-56]
    jmp     vh_loop

    ; --- Pass 3: cross-entry, same-kind duplicate check (at most 1 per entry) ----
vh_dups:
    mov     rax, qword ptr [rbp-32]
    test    rax, rax
    jz      vh_store
    mov     dword ptr [rbp-132], -1             ; last_reused_ei = -1
    mov     dword ptr [rbp-56], 0               ; a = 0
vh_da:
    mov     eax, dword ptr [rbp-56]
    cmp     eax, dword ptr [rbp-48]
    jae     vh_store
    mov     r8, qword ptr [rbp-32]
    imul    rcx, rax, HCRED_STRIDE
    lea     r10, [r8+rcx]                       ; row[a]
    mov     edx, dword ptr [r10+16]             ; ei = row[a].entry_idx
    cmp     edx, dword ptr [rbp-132]
    je      vh_da_next                          ; entry ei already counted as reused
    mov     dword ptr [rbp-136], 0              ; b = 0
vh_db:
    mov     eax, dword ptr [rbp-136]
    cmp     eax, dword ptr [rbp-48]
    jae     vh_da_next
    mov     r8, qword ptr [rbp-32]
    mov     ecx, dword ptr [rbp-56]
    imul    rcx, rcx, HCRED_STRIDE
    lea     r10, [r8+rcx]                       ; row[a]
    mov     ecx, dword ptr [rbp-136]
    imul    rcx, rcx, HCRED_STRIDE
    lea     r11, [r8+rcx]                       ; row[b]
    mov     edx, dword ptr [r10+16]
    cmp     edx, dword ptr [r11+16]             ; same entry? skip
    je      vh_db_next
    mov     ecx, dword ptr [r10+20]
    cmp     ecx, dword ptr [r11+20]             ; different kind (VF_SECRET vs VF_PIN)? skip
    jne     vh_db_next
    mov     rax, qword ptr [r10]
    cmp     rax, qword ptr [r11]
    jne     vh_db_next
    mov     rax, qword ptr [r10+8]
    cmp     rax, qword ptr [r11+8]
    jne     vh_db_next
    inc     dword ptr [rbp-80]                  ; entry ei is reused
    mov     dword ptr [rbp-132], edx
    jmp     vh_da_next
vh_db_next:
    inc     dword ptr [rbp-136]
    jmp     vh_db
vh_da_next:
    inc     dword ptr [rbp-56]
    jmp     vh_da

vh_store:
    mov     r10, qword ptr [rbp-16]
    mov     eax, dword ptr [rbp-64]
    mov     dword ptr [r10+0], eax              ; weak
    mov     eax, dword ptr [rbp-80]
    mov     dword ptr [r10+4], eax              ; reused
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [r10+8], eax              ; old
    mov     rcx, qword ptr [rbp-32]
    test    rcx, rcx
    jz      vh_done
    mov     eax, dword ptr [rbp-40]
    imul    rax, rax, HCRED_STRIDE
    mov     rdx, rax
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

; vault_entry_health_status(rcx = index) -> eax = 0 (healthy / no credentials),
;   1 (stale: >= 1yr unmodified), or 2 (weak VF_SECRET or VF_PIN).
;   Powers the sidebar tile health dot identically for passwords and PINs.
public vault_entry_health_status
vault_entry_health_status proc frame
    FRAME_PROLOG 64
    ; [rbp-16]=index [rbp-24]=f_ptr [rbp-32]=f_rem [rbp-36]=has_cred
    mov     qword ptr [rbp-16], rcx
    call    vault_is_system
    test    eax, eax
    jnz     vehs_zero
    mov     rcx, qword ptr [rbp-16]
    call    vault_entry_ptr
    test    rax, rax
    jz      vehs_zero
    mov     ecx, dword ptr [rax+32]
    mov     dword ptr [rbp-32], ecx
    lea     rcx, [rax+36]
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-36], 0
vehs_lp:
    cmp     dword ptr [rbp-32], 0
    je      vehs_stale
    mov     r10, qword ptr [rbp-24]
    movzx   eax, word ptr [r10]
    mov     r9d, dword ptr [r10+2]
    lea     rdx, [r10+6]
    mov     r11d, r9d
    lea     rcx, [r10+6]
    add     rcx, r9
    mov     qword ptr [rbp-24], rcx
    dec     dword ptr [rbp-32]
    mov     ecx, eax
    and     ecx, VF_KINDMASK
    cmp     ecx, VF_SECRET
    je      vehs_cred
    cmp     ecx, VF_PIN
    jne     vehs_lp
vehs_cred:
    test    eax, VF_LABELED
    jz      @F
    movzx   eax, word ptr [rdx]
    add     eax, 2
    add     rdx, rax
    sub     r11d, eax
@@: test    r11d, r11d
    jle     vehs_lp
    mov     dword ptr [rbp-36], 1
    cmp     ecx, VF_PIN
    je      vehs_pin
    mov     rcx, rdx
    mov     edx, r11d
    call    vh_pw_weak
    jmp     vehs_chk
vehs_pin:
    mov     rcx, rdx
    mov     edx, r11d
    call    vh_pin_weak
vehs_chk:
    test    eax, eax
    jz      vehs_lp
    mov     eax, 2
    FRAME_EPILOG
    ret
vehs_stale:
    cmp     dword ptr [rbp-36], 0
    je      vehs_zero
    mov     rcx, qword ptr [rbp-16]
    call    vault_entry_stale
    FRAME_EPILOG
    ret
vehs_zero:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_entry_health_status endp

; ===========================================================================
; cmd_pinkat - Known-answer test for pin_eval (UTF-8 codepoints, zero char-class
;   requirements, configurable minlen, and trivial-pattern rejection).
; ===========================================================================
.data
CSTR pnk_ok,  "pinkat: PASS (PIN length, UTF-8 scalar count, no-class rule, trivial patterns)",13,10
CSTR pnk_bad, "pinkat: FAIL",13,10
pnk_good6   db "839204"
pnk_good8   db "83920471"
pnk_alpha6  db "kqmpzv"
pnk_utf8_6  db 0C3h,0A4h,'9',0C3h,0B6h,'2',0C3h,0BCh,'7'    ; "ä9ö2ü7" (9 bytes, 6 codepoints)
pnk_utf8_5  db 0C3h,0A4h,0C3h,0B6h,0C3h,0BCh,'1','2'        ; "äöü12"  (8 bytes, 5 codepoints)
pnk_short5  db "48291"
pnk_same6   db "000000"
pnk_samea   db "aaaaaa"
pnk_asc6    db "123456"
pnk_asca    db "abcdef"
pnk_desc6   db "654321"
pnk_desca   db "fedcba"
pnk_cyc2    db "121212"
pnk_cyc2a   db "ababab"
pnk_cyc3    db "123123"
pnk_cyc3a   db "abcabc"
pnk_pal6    db "123321"
pnk_pal4    db "1221"
pnk_good4   db "4829"
pnk_badu8   db 0FFh,'8','3','9','2','0','4'

align 8
pnk_cases label qword
    ; { ptr, byte_len, minlen, exp_grade, exp_reason } (5 qwords = 40 bytes/row)
    dq pnk_good6,   6, 6, 2, PIN_OK
    dq pnk_good8,   8, 6, 3, PIN_OK
    dq pnk_alpha6,  6, 6, 2, PIN_OK
    dq pnk_utf8_6,  9, 6, 2, PIN_OK
    dq pnk_utf8_5,  8, 6, 0, PIN_SHORT
    dq pnk_short5,  5, 6, 0, PIN_SHORT
    dq pnk_good6,   0, 6, 0, PIN_SHORT
    dq pnk_same6,   6, 6, 0, PIN_TRIVIAL
    dq pnk_samea,   6, 6, 0, PIN_TRIVIAL
    dq pnk_asc6,    6, 6, 0, PIN_TRIVIAL
    dq pnk_asca,    6, 6, 0, PIN_TRIVIAL
    dq pnk_desc6,   6, 6, 0, PIN_TRIVIAL
    dq pnk_desca,   6, 6, 0, PIN_TRIVIAL
    dq pnk_cyc2,    6, 6, 0, PIN_TRIVIAL
    dq pnk_cyc2a,   6, 6, 0, PIN_TRIVIAL
    dq pnk_cyc3,    6, 6, 0, PIN_TRIVIAL
    dq pnk_cyc3a,   6, 6, 0, PIN_TRIVIAL
    dq pnk_pal6,    6, 6, 0, PIN_TRIVIAL
    dq pnk_pal4,    4, 4, 0, PIN_TRIVIAL
    dq pnk_good4,   4, 4, 2, PIN_OK
    dq pnk_badu8,   7, 6, 0, PIN_BADUTF8
PNK_CASES_N equ ($ - pnk_cases) / 40
.code

LANDING_PAD
public cmd_pinkat
cmd_pinkat proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], 0               ; i
pnk_lp:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, PNK_CASES_N
    jae     pnk_pass
    imul    rax, rax, 40
    lea     r10, [pnk_cases]
    add     r10, rax
    mov     qword ptr [rbp-32], r10
    mov     rcx, qword ptr [r10+0]
    mov     edx, dword ptr [r10+8]
    mov     r8d, dword ptr [r10+16]
    call    pin_eval
    mov     r10, qword ptr [rbp-32]
    cmp     eax, dword ptr [r10+24]
    jne     pnk_fail
    cmp     edx, dword ptr [r10+32]
    jne     pnk_fail
    inc     dword ptr [rbp-24]
    jmp     pnk_lp
pnk_pass:
    lea     rcx, [pnk_ok]
    mov     edx, pnk_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
pnk_fail:
    lea     rcx, [pnk_bad]
    mov     edx, pnk_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_pinkat endp

; ===========================================================================
; cmd_healthkat - E6 known-answer test for vault_health (VF_SECRET + VF_PIN).
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

align 8
hk_pin_body:
    dd  7                                     ; entry_count
    ; --- p0 VF_PIN "839204" (old, strong PIN, dup with p5) -----------------
    db  16 dup(0)
    dq  0
    dq  0
    dd  1
    dw  VF_PIN
    dd  6
    db  "839204"
    ; --- p1 VF_PIN "k9m2p7" (new, strong alphanumeric PIN) -----------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_PIN
    dd  6
    db  "k9m2p7"
    ; --- p2 VF_PIN "123456" (new, weak trivial run) ------------------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_PIN
    dd  6
    db  "123456"
    ; --- p3 VF_PIN "9472" (new, weak < 6 chars) ----------------------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_PIN
    dd  4
    db  "9472"
    ; --- p4 VF_PIN "984489" (new, weak palindrome) -------------------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_PIN
    dd  6
    db  "984489"
    ; --- p5 VF_PIN "839204" (new, dup of p0) -------------------------------
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_PIN
    dd  6
    db  "839204"
    ; --- p6 VF_SECRET "839204" (new, weak password; MUST NOT dup VF_PIN!) --
    db  16 dup(0)
    dq  0
    dq  7FFFFFFFFFFFFFFFh
    dd  1
    dw  VF_SECRET
    dd  6
    db  "839204"
.code

LANDING_PAD
public cmd_healthkat
cmd_healthkat proc frame
    FRAME_PROLOG 96
    ; [rbp-24] saved g_body_ptr ; [rbp-48..-33] health {weak,reused,old,total}
    ; [rbp-56]=stale(0) [rbp-64]=stale(1) [rbp-72]=saved pinminlen
    mov     rax, qword ptr [g_body_ptr]
    mov     qword ptr [rbp-24], rax
    mov     eax, dword ptr [g_cfg_pinminlen]
    mov     dword ptr [rbp-72], eax
    mov     dword ptr [g_cfg_pinminlen], PIN_MINLEN_DEF

    ; 1) Original 10-entry VF_SECRET fixture
    lea     rax, [hk_body]
    mov     qword ptr [g_body_ptr], rax
    lea     rcx, [rbp-48]
    call    vault_health
    xor     ecx, ecx
    call    vault_entry_stale
    mov     dword ptr [rbp-56], eax
    mov     ecx, 1
    call    vault_entry_stale
    mov     dword ptr [rbp-64], eax
    cmp     dword ptr [rbp-48], 4               ; weak
    jne     hk_fail_rest
    cmp     dword ptr [rbp-44], 6               ; reused
    jne     hk_fail_rest
    cmp     dword ptr [rbp-40], 2               ; old
    jne     hk_fail_rest
    cmp     dword ptr [rbp-36], 10              ; total
    jne     hk_fail_rest
    cmp     dword ptr [rbp-56], 1               ; e0 stale
    jne     hk_fail_rest
    cmp     dword ptr [rbp-64], 0               ; e1 not stale
    jne     hk_fail_rest

    ; 2) 7-entry VF_PIN + domain-separation fixture:
    ;    weak = 4 (p2, p3, p4, p6), reused = 2 (p0, p5 only!), old = 1 (p0), total = 7
    lea     rax, [hk_pin_body]
    mov     qword ptr [g_body_ptr], rax
    lea     rcx, [rbp-48]
    call    vault_health
    cmp     dword ptr [rbp-48], 4               ; weak
    jne     hk_fail_rest
    cmp     dword ptr [rbp-44], 2               ; reused (p6 VF_SECRET != VF_PIN!)
    jne     hk_fail_rest
    cmp     dword ptr [rbp-40], 1               ; old
    jne     hk_fail_rest
    cmp     dword ptr [rbp-36], 7               ; total
    jne     hk_fail_rest
    xor     ecx, ecx                            ; p0: healthy PIN, stale -> status 1
    call    vault_entry_health_status
    cmp     eax, 1
    jne     hk_fail_rest
    mov     ecx, 1                              ; p1: healthy PIN, fresh -> status 0
    call    vault_entry_health_status
    test    eax, eax
    jnz     hk_fail_rest
    mov     ecx, 2                              ; p2: trivial PIN -> status 2 (weak)
    call    vault_entry_health_status
    cmp     eax, 2
    jne     hk_fail_rest

    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [g_cfg_pinminlen], eax
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [g_body_ptr], rax
    xor     eax, eax
    FRAME_EPILOG
    ret
hk_fail_rest:
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [g_cfg_pinminlen], eax
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [g_body_ptr], rax
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
    ; Enforce UTF-16 code-unit cap (CONVW_MAX - 1) so every written/imported field
    ; is guaranteed to round-trip losslessly through vault_field_get's CONVW_MAX buffer.
    xor     ecx, ecx
vfl_wchk:
    cmp     word ptr [r8 + rcx*2], 0
    je      vfl_wok
    inc     ecx
    cmp     ecx, CONVW_MAX
    jb      vfl_wchk
    jmp     vfl_of
vfl_wok:
    mov     rcx, r8
    lea     rdx, [g_conv]
    mov     r8d, CONV_CAP
    call    conv_w2u
    cmp     eax, -1                             ; would have written the field EMPTY,
    je      vfl_of                              ;   destroying it - refuse instead
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
    cmp     eax, -1                             ; a dropped label is silent data loss too
    je      vfl_of
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
    and     eax, VF_KINDMASK                    ; a PLAIN field carries no flag bits: a
    mov     word ptr [r11], ax                  ;   stray VF_LABELED here would make the
                                                ;   value's first bytes read as a label
                                                ;   length and the vault fail to reopen
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
    and     eax, VF_KINDMASK
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
    mov     dword ptr [g_vfe_err], 1            ; see vfr_of - a value that does not fit is
    xor     eax, eax                            ;   refused with the WHOLE entry, never stored
    FRAME_EPILOG                                ;   empty and never a process kill
    ret
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
; System items - permanent per-vault metadata (docs/SYSITEM_DESIGN.md).
;
; A system item is an ORDINARY entry whose field[0] is VF_SYSTEM, so the on-disk
; container, the body walk and vault_body_validate are all unchanged.  What makes it
; "system" is purely that user-facing code skips it.
;
; vault_count() stays the PHYSICAL count - seal/teardown/format code and every probe
; that asserts a physical count depend on that.  User-facing code uses
; vault_user_count().  List builders skip system items but still tag each row with the
; PHYSICAL entry index, so no vault_entry_ptr caller needs remapping.
;
; NOTE on cost: vault_entry_ptr rescans from the body start, so calling
; vault_is_system in a loop is quadratic.  vault_user_count and vault_sys_find
; therefore walk the body ONCE themselves rather than calling it per index.
; ===========================================================================

; sys_first_kind(rcx = entry ptr) -> eax = kind of field[0] (0 if the entry has none).
;   Leaf; clobbers eax/r10.
sys_first_kind proc
    test    rcx, rcx
    jz      sfk_none
    mov     eax, dword ptr [rcx+32]             ; field_count
    test    eax, eax
    jz      sfk_none
    movzx   eax, word ptr [rcx+36]              ; field[0] raw type
    and     eax, VF_KINDMASK
    ret
sfk_none:
    xor     eax, eax
    ret
sys_first_kind endp

; vault_is_system(ecx = index) -> eax = 1 if that entry is the system item.
;   O(index) - do NOT call this in a loop; see vault_user_count.
public vault_is_system
vault_is_system proc frame
    FRAME_PROLOG 32
    call    vault_entry_ptr                     ; rcx = index -> rax = entry ptr
    mov     rcx, rax
    call    sys_first_kind
    cmp     eax, VF_SYSTEM
    jne     vis_no
    mov     eax, 1
    FRAME_EPILOG
    ret
vis_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_is_system endp

; sys_walk(rcx = 0 -> return the system item's INDEX or -1
;              1 -> return the count of NON-system entries)
;   One linear pass over the body (vault_entry_len per entry), so callers never pay
;   vault_entry_ptr's rescan.  -> eax.
sys_walk proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=mode [rbp-32]=cursor [rbp-40]=i [rbp-48]=total [rbp-56]=result
    mov     qword ptr [rbp-24], rcx
    mov     r10, qword ptr [g_body_ptr]
    test    r10, r10
    jz      sw_none
    mov     eax, dword ptr [r10]                ; entry_count
    mov     dword ptr [rbp-48], eax
    lea     r10, [r10+4]
    mov     qword ptr [rbp-32], r10
    mov     dword ptr [rbp-40], 0
    mov     dword ptr [rbp-56], -1              ; mode 0: "not found"
    cmp     qword ptr [rbp-24], 0
    je      sw_loop
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [rbp-56], eax             ; mode 1: start from the physical count
sw_loop:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [rbp-48]
    jae     sw_done
    mov     rcx, qword ptr [rbp-32]
    call    sys_first_kind
    cmp     eax, VF_SYSTEM
    jne     sw_next
    cmp     qword ptr [rbp-24], 0
    jne     sw_dec
    mov     eax, dword ptr [rbp-40]             ; mode 0: first match wins
    mov     dword ptr [rbp-56], eax
    jmp     sw_done
sw_dec:
    dec     dword ptr [rbp-56]                  ; mode 1: one fewer user entry
sw_next:
    mov     rcx, qword ptr [rbp-32]
    call    vault_entry_len
    mov     r10, qword ptr [rbp-32]
    add     r10, rax
    mov     qword ptr [rbp-32], r10
    inc     dword ptr [rbp-40]
    jmp     sw_loop
sw_done:
    mov     eax, dword ptr [rbp-56]
    FRAME_EPILOG
    ret
sw_none:
    xor     eax, eax                            ; no body: 0 users / index -1
    cmp     qword ptr [rbp-24], 0
    jne     sw_nret
    mov     eax, -1
sw_nret:
    FRAME_EPILOG
    ret
sys_walk endp

; vault_sys_find() -> eax = index of the system item, or -1.
public vault_sys_find
vault_sys_find proc frame
    FRAME_PROLOG 32
    xor     ecx, ecx
    call    sys_walk
    FRAME_EPILOG
    ret
vault_sys_find endp

; vault_user_count() -> eax = entries excluding system items (what the user sees).
public vault_user_count
vault_user_count proc frame
    FRAME_PROLOG 32
    mov     ecx, 1
    call    sys_walk
    FRAME_EPILOG
    ret
vault_user_count endp

; sys_field_ptr(ecx = kind) -> rax = pointer to that field's VALUE bytes inside the
;   system item, 0 if absent.  rdx = value length on success.
sys_field_ptr proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=wanted kind [rbp-32]=cursor [rbp-40]=remaining fields
    mov     dword ptr [rbp-24], ecx
    call    vault_sys_find
    cmp     eax, -1
    je      sfp_none
    mov     ecx, eax
    call    vault_entry_ptr
    test    rax, rax
    jz      sfp_none
    mov     r10d, dword ptr [rax+32]            ; field_count
    mov     dword ptr [rbp-40], r10d
    lea     r10, [rax+36]
    mov     qword ptr [rbp-32], r10
sfp_loop:
    cmp     dword ptr [rbp-40], 0
    je      sfp_none
    mov     r10, qword ptr [rbp-32]
    movzx   eax, word ptr [r10]
    and     eax, VF_KINDMASK
    cmp     eax, dword ptr [rbp-24]
    je      sfp_hit
    mov     eax, dword ptr [r10+2]              ; field len
    add     r10, 6
    add     r10, rax
    mov     qword ptr [rbp-32], r10
    dec     dword ptr [rbp-40]
    jmp     sfp_loop
sfp_hit:
    mov     r10, qword ptr [rbp-32]
    mov     edx, dword ptr [r10+2]              ; value length
    lea     rax, [r10+6]
    FRAME_EPILOG
    ret
sfp_none:
    xor     eax, eax
    xor     edx, edx
    FRAME_EPILOG
    ret
sys_field_ptr endp

; vault_add_system_item() - append a fresh system item to the live body.  Called on
;   the REAL vault-creation path only; do_seed/do_init deliberately leave test vaults
;   system-item-free so every probe that asserts a physical count is untouched.
;   Does NOT reseal.  -> eax = 1 ok / 0 failed.
public vault_add_system_item
vault_add_system_item proc frame
    FRAME_PROLOG 64
    ; [rbp-24] = entry start, [rbp-32] = fields written
    cmp     qword ptr [g_body_ptr], 0
    je      vasi_fail
    call    vault_sys_find                      ; never create a second one
    cmp     eax, -1
    jne     vasi_ok
    mov     rax, qword ptr [g_body_len]
    add     rax, 36
    cmp     rax, VAULT_BODY_MAX
    ja      vasi_fail
    mov     dword ptr [g_vfe_err], 0
    mov     rax, qword ptr [g_body_len]         ; rollback point (see vault_build_entry)
    mov     qword ptr [rbp-40], rax
    mov     r11, qword ptr [g_body_ptr]
    add     r11, qword ptr [g_body_len]
    mov     qword ptr [rbp-24], r11
    mov     rcx, r11
    mov     edx, 16
    call    rng_fill                            ; 16-byte random entry id
    test    eax, eax
    jz      vasi_fail
    lea     rcx, [g_ts]
    call    GetSystemTimeAsFileTime
    mov     r11, qword ptr [rbp-24]
    mov     rax, qword ptr [g_ts]
    mov     qword ptr [r11+16], rax             ; created
    mov     qword ptr [r11+24], rax             ; modified
    mov     dword ptr [r11+32], 0               ; field_count placeholder
    mov     rax, qword ptr [g_body_len]
    add     rax, 36
    mov     qword ptr [g_body_len], rax
    mov     byte ptr [g_sys_ver], SYSITEM_VER   ; field[0]: the marker (MUST be first)
    mov     rcx, VF_SYSTEM
    xor     rdx, rdx
    lea     r8, [g_sys_ver]
    mov     r9, 1
    call    va_field_bin_labeled
    mov     dword ptr [rbp-32], eax
    mov     qword ptr [g_sys_ft], 0             ; field[1]: pwverify, "never" until set
    mov     rcx, VF_SYS_PWVERIFY
    xor     rdx, rdx
    lea     r8, [g_sys_ft]
    mov     r9, 8
    call    va_field_bin_labeled
    add     dword ptr [rbp-32], eax
    cmp     dword ptr [g_vfe_err], 0
    je      vasi_patch
    mov     rax, qword ptr [rbp-40]             ; no room for both fields -> no item at all
    mov     qword ptr [g_body_len], rax
    mov     dword ptr [g_vfe_err], 0
    jmp     vasi_fail
vasi_patch:
    mov     r11, qword ptr [rbp-24]
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [r11+32], eax             ; patch field_count
    mov     r11, qword ptr [g_body_ptr]
    inc     dword ptr [r11]                     ; entry_count++
vasi_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
vasi_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_add_system_item endp

; entry_has_field(rcx = entry ptr, edx = field kind) -> eax = 1 if that entry carries one.
;   POINTER-based, so it works on a FOREIGN body (an import source) where the
;   index-based vault_is_deleted - which resolves against the live g_body_ptr - would
;   inspect the wrong vault entirely.  Leaf; walks the entry's own field list.
entry_has_field proc
    test    rcx, rcx
    jz      ehf_no
    mov     r9d, dword ptr [rcx+32]             ; field_count
    lea     r10, [rcx+36]
ehf_lp:
    test    r9d, r9d
    jz      ehf_no
    movzx   eax, word ptr [r10]
    and     eax, VF_KINDMASK
    cmp     eax, edx
    je      ehf_yes
    mov     eax, dword ptr [r10+2]              ; field len
    add     r10, 6
    add     r10, rax
    dec     r9d
    jmp     ehf_lp
ehf_yes:
    mov     eax, 1
    ret
ehf_no:
    xor     eax, eax
    ret
entry_has_field endp

; entry_field_ptr(rcx = entry ptr, edx = kind, r8 = *out len) -> rax = value ptr, 0 none.
;   Pointer-based twin of vault_field_at, for walking a FOREIGN body.  Skips the
;   {u16 labellen, label} prefix on a VF_LABELED field so the caller always gets the
;   value itself.  Leaf.
public entry_field_ptr
entry_field_ptr proc
    test    rcx, rcx
    jz      efp_no
    mov     r9d, dword ptr [rcx+32]             ; field_count
    lea     r10, [rcx+36]
efp_lp:
    test    r9d, r9d
    jz      efp_no
    movzx   eax, word ptr [r10]                 ; raw type
    mov     r11d, eax
    and     eax, VF_KINDMASK
    cmp     eax, edx
    je      efp_hit
    mov     eax, dword ptr [r10+2]
    add     r10, 6
    add     r10, rax
    dec     r9d
    jmp     efp_lp
efp_hit:
    mov     eax, dword ptr [r10+2]              ; field length
    lea     r10, [r10+6]                        ; -> bytes
    test    r11d, VF_LABELED
    jz      efp_plain
    cmp     eax, 2
    jb      efp_no
    movzx   r11d, word ptr [r10]                ; labellen
    lea     r11d, [r11d+2]
    cmp     eax, r11d
    jb      efp_no
    sub     eax, r11d
    add     r10, r11
efp_plain:
    mov     dword ptr [r8], eax
    mov     rax, r10
    ret
efp_no:
    mov     dword ptr [r8], 0
    xor     eax, eax
    ret
entry_field_ptr endp

; vault_is_deleted(ecx = index) -> eax = 1 if that entry is in the trash.
;   The vault-side twin of gui_entry_is_deleted, so the export paths can refuse trashed
;   records without reaching into gui.asm.
public vault_is_deleted
vault_is_deleted proc frame
    FRAME_PROLOG 48
    mov     edx, VF_DELETED
    lea     r8, [rbp-24]
    call    vault_field_at
    xor     ecx, ecx
    test    rax, rax
    setnz   cl
    mov     eax, ecx
    FRAME_EPILOG
    ret
vault_is_deleted endp

; ===========================================================================
; C9 - periodic master-password re-verification (docs/SYSITEM_DESIGN.md).
;   Under TPM Unlock the master password is never typed, so it rots.  After
;   PwVerifyDays we start asking for it at every unlock; the user may skip for
;   C9_GRACE_DAYS, after which entry is required.
; ===========================================================================

; ft_days(rcx = FILETIME) -> rax = whole days since the FILETIME epoch.  Leaf.
;   Day granularity throughout: the policy is expressed in days, and comparing whole
;   days avoids "29.99 days" behaving differently from 30.
ft_days proc
    mov     rax, rcx
    xor     edx, edx
    mov     r10, FT_PER_DAY
    div     r10
    ret
ft_days endp

; vault_pw_due(rcx = now FILETIME, edx = interval days) -> eax = 1 if the master-password
;   reminder is due.
;   A pure query: no writes, nothing to reseal, and no read-only special case.  It was
;   briefly stateful, anchoring a grace window so the prompt could escalate to "entry
;   required" - but the reminder does not enforce anything, so there was nothing for the
;   window to escalate TO and the whole mechanism went away with it.
;   A vault that has never stored a stamp reads 0 and is simply due now, which is right:
;   the password has demonstrably not been typed within any interval.
public vault_pw_due
vault_pw_due proc frame
    FRAME_PROLOG 48
    ; [rbp-24] = interval, [rbp-32] = today
    mov     dword ptr [rbp-24], edx
    test    edx, edx
    jz      vpd_no                              ; 0 = off
    call    ft_days                             ; rcx is still `now`
    mov     qword ptr [rbp-32], rax
    call    vault_pwverify_get
    test    rax, rax
    jz      vpd_due                             ; never verified -> due
    mov     rcx, rax
    call    ft_days
    mov     ecx, dword ptr [rbp-24]
    add     rax, rcx                            ; last + interval
    cmp     qword ptr [rbp-32], rax
    jae     vpd_due
vpd_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
vpd_due:
    mov     eax, 1
    FRAME_EPILOG
    ret
vault_pw_due endp

; vault_pw_check(rcx = utf8 password, edx = length) -> eax = 1 if it derives the key
;   this vault is already open under.
;   The vault is open (TPM gave us g_vkey), so the check is: derive from the typed
;   password under THIS vault's salt and compare, constant time.  g_vkey is parked and
;   restored around vk_derive, which writes straight into it.
public vault_pw_check
vault_pw_check proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=pw [rbp-32]=len [rbp-48]=result.  g_cfg_passlen is deliberately NOT saved
    ; for restoring: the candidate password is wiped out of g_cfg_pass below, so the only
    ; correct length afterwards is 0.  (An earlier version parked it, then loaded it into
    ; eax and dropped it - dead code that read as an intended restore.)
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    lea     rcx, [g_xs_vkey]                    ; park the live key
    lea     rdx, [g_vkey]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [g_cfg_pass]                   ; vk_derive reads g_cfg_pass
    mov     rdx, qword ptr [rbp-24]
    mov     r8d, dword ptr [rbp-32]
    call    copy_bytes
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [g_cfg_passlen], eax
    call    vk_derive
    mov     dword ptr [rbp-48], 0
    test    eax, eax
    jnz     vpc_restore                         ; derive failed -> not a match
    lea     rcx, [g_vkey]
    lea     rdx, [g_xs_vkey]
    mov     r8, 32
    call    ct_memcmp
    test    eax, eax
    jnz     vpc_restore
    mov     dword ptr [rbp-48], 1
vpc_restore:
    lea     rcx, [g_vkey]                       ; the live key comes back either way
    lea     rdx, [g_xs_vkey]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [g_xs_vkey]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_cfg_pass]                   ; never leave the typed password behind
    mov     edx, MAX_PASSWORD_BYTES+1
    call    secure_zero
    mov     dword ptr [g_cfg_passlen], 0        ; the buffer is wiped, so 0 is the truth
    mov     eax, dword ptr [rbp-48]
    FRAME_EPILOG
    ret
vault_pw_check endp

; vault_last_user() -> eax = index of the LAST non-system entry, or -1 if none.
;   The GUI selects "the entry just written" with count-1.  That is only safe while the
;   system item is not last - true for a vault created with one, false for a vault that
;   gained it on a later save, where it is APPENDED.  Walks down from the end.
public vault_last_user
vault_last_user proc frame
    FRAME_PROLOG 48
    call    vault_count
    mov     dword ptr [rbp-24], eax
vlu_loop:
    cmp     dword ptr [rbp-24], 0
    jle     vlu_none
    dec     dword ptr [rbp-24]
    mov     ecx, dword ptr [rbp-24]
    call    vault_is_system
    test    eax, eax
    jnz     vlu_loop
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
vlu_none:
    mov     eax, -1
    FRAME_EPILOG
    ret
vault_last_user endp

; vault_pwverify_get() -> rax = the stored FILETIME (0 = never / no system item).
public vault_pwverify_get
vault_pwverify_get proc frame
    FRAME_PROLOG 32
    mov     ecx, VF_SYS_PWVERIFY
    call    sys_field_ptr
    test    rax, rax
    jz      vpg_zero
    cmp     rdx, 8                              ; a short field is not a timestamp
    jb      vpg_zero
    mov     rax, qword ptr [rax]
    FRAME_EPILOG
    ret
vpg_zero:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_pwverify_get endp

; vault_pwverify_set(rcx = FILETIME) -> eax = 1 ok / 0 no slot.  Updates in place (the
;   field is fixed-width), so it never moves the body.  Does NOT reseal - the caller
;   decides when to persist, and on a read-only vault it simply never will.
;
;   Creates the system item on demand.  That is how a vault made before system items
;   existed acquires one: LAZILY, at the moment there is a real setting to store, riding
;   the save the caller was going to make anyway.  Migrating on unlock instead would
;   mean rewriting every existing vault the first time it is opened - a silent write to
;   the user's file for no benefit, and impossible on a read-only vault.
public vault_pwverify_set
vault_pwverify_set proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     ecx, VF_SYS_PWVERIFY
    call    sys_field_ptr
    test    rax, rax
    jnz     vps_have
    call    vault_add_system_item
    test    eax, eax
    jz      vps_no
    mov     ecx, VF_SYS_PWVERIFY
    call    sys_field_ptr
vps_have:
    test    rax, rax
    jz      vps_no
    cmp     rdx, 8
    jb      vps_no
    mov     rcx, qword ptr [rbp-24]
    mov     qword ptr [rax], rcx
    mov     eax, 1
    FRAME_EPILOG
    ret
vps_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_pwverify_set endp

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
    mov     dword ptr [g_vfe_err], 0
    mov     rax, qword ptr [g_body_len]         ; rollback point: if any field is refused
    mov     qword ptr [rbp-64], rax             ;   the whole entry goes, body untouched
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
    cmp     dword ptr [g_vfe_err], 0
    jne     vbe_rollback
    mov     r11, qword ptr [rbp-32]
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r11+32], eax             ; patch field_count
    mov     r11, qword ptr [g_body_ptr]
    inc     dword ptr [r11]                     ; entry_count++
    xor     eax, eax
    FRAME_EPILOG
    ret
vbe_rollback:
    ; A field did not fit.  entry_count was never bumped, so dropping g_body_len back
    ; to where this entry began removes every trace of it; the bytes past the new
    ; end are dead and get overwritten by the next append.
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [g_body_len], rax
    mov     dword ptr [g_vfe_err], 0
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

; attach_free(rcx = secmem plaintext ptr, rdx = ptlen) - wipe + release an
;   attachment plaintext buffer allocated by attach_open / attach_stage.
;   0-byte attachments allocate a 1-byte locked page, so clamp rdx >= 1.
public attach_free
attach_free proc frame
    FRAME_PROLOG 32
    test    rcx, rcx
    jz      atf_done
    test    rdx, rdx
    jnz     @F
    mov     edx, 1
@@: call    secmem_free
atf_done:
    FRAME_EPILOG
    ret
attach_free endp

; attach_reset_pending() - free the pending new-attachment plaintext buffers and
;   clear the pending table, leaving the ON-DISK index (g_attidx) intact.  Use
;   this whenever a vault stays open: g_attidx is what attach_open resolves a
;   saved attachment through, and only a save (attach_rescan) rebuilds it.
public attach_reset_pending
attach_reset_pending proc frame
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
    call    attach_free
    mov     eax, dword ptr [rbp-24]
    imul    eax, eax, 32
    lea     r10, [g_newatt]
    add     r10, rax
    mov     qword ptr [r10+16], 0
    mov     qword ptr [r10+24], 0
ar_next:
    inc     dword ptr [rbp-24]
    jmp     ar_loop
ar_done:
    mov     dword ptr [g_newatt_n], 0
    FRAME_EPILOG
    ret
attach_reset_pending endp

; attach_reset() - the above, PLUS drop the on-disk index.  Only correct where the
;   index is about to be rebuilt (the attach_rescan right after a save) or where
;   the vault is going away (lock / reload).  Anywhere else this silently strands
;   every saved attachment: attach_open stops resolving them, and the next save
;   cannot find their ciphertext to carry forward, which destroys it.
public attach_reset
attach_reset proc frame
    FRAME_PROLOG 32
    call    attach_reset_pending
    mov     dword ptr [g_attidx_n], 0
    mov     dword ptr [g_att_ovf], 0            ; the index it described is gone too
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
    add     eax, dword ptr [g_attidx_n]
    cmp     eax, MAX_ATTIDX
    jae     as_err
    mov     rcx, qword ptr [rbp-32]
    cmp     rcx, ATT_FILE_MAX
    ja      as_err
    test    rcx, rcx
    jnz     @F
    mov     ecx, 1                              ; 0-byte attachment -> 1-byte locked page
@@: call    secmem_alloc
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
    jz      as_errbuf
    mov     rcx, qword ptr [rbp-40]
    add     rcx, ARF_KEY
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      as_errbuf
    mov     rcx, qword ptr [rbp-40]
    add     rcx, ARF_NONCE
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      as_errbuf
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
as_errbuf:
    mov     rcx, qword ptr [rbp-40]             ; wipe partially-generated AttachRef (key/id)
    mov     edx, ARF_SIZE
    call    secure_zero
    mov     rcx, qword ptr [rbp-48]             ; wipe + release locked plaintext copy
    mov     rdx, qword ptr [rbp-32]
    call    attach_free
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
    mov     dword ptr [g_att_ovf], 0
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
    cmp     eax, MAX_ATTIDX
    jae     aib_full
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
aib_full:
    mov     dword ptr [g_att_ovf], 1            ; a well-formed entry that does not fit
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
    ; pending: return a locked secmem copy of the plaintext
    mov     rcx, qword ptr [rbp-40]
    cmp     rcx, ATT_FILE_MAX
    ja      ao_fail
    test    rcx, rcx
    jnz     @F
    mov     ecx, 1
@@: call    secmem_alloc
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
    ; length-preserving) and stay within ATT_FILE_MAX.
    mov     rax, qword ptr [rbp-64]
    cmp     rax, qword ptr [rbp-40]
    jne     ao_fail
    cmp     rax, ATT_FILE_MAX
    ja      ao_fail
    mov     rcx, rax
    test    rcx, rcx
    jnz     @F
    mov     ecx, 1
@@: call    secmem_alloc
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
    call    attach_free
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
    je      aeo_missing
    imul    eax, eax, 32
    lea     r10, [g_attidx]
    add     r10, rax
    mov     rax, qword ptr [r10+24]             ; on-disk ctlen must equal the body ref's ptlen
    cmp     rax, qword ptr [rbp-40]             ;   (attach_open enforces the same); otherwise
    jne     aeo_badlen                          ;   att_cpy(ptlen+16) would over-read g_filebuf
    mov     rdx, qword ptr [r10+16]             ; src ct
    mov     rcx, qword ptr [rbp-32]
    add     rcx, ATT_ENThDR                     ; dst = cur+24
    mov     r8, qword ptr [rbp-40]
    add     r8, 16                              ; ct + tag
    call    att_cpy
    jmp     aeo_done
aeo_badlen:                                     ; crafted body: ctlen/ptlen mismatch
aeo_missing:
    ; Nothing to carry.  Writing the header and leaving the ciphertext as whatever the
    ; buffer held (zeros) produced a well-formed, MAC'd file whose attachment could
    ; never decrypt again - silently.  Flag it; vault_seal_write refuses the save.
    mov     dword ptr [g_att_missing], 1
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

; attach_build(ecx=emit, rdx=out ptr, r8=out_end) -> rax = total section bytes
;   (entries + the 12-byte trailer), or 0 when the vault has no attachment fields.
;   emit=0 sizes only; emit=1 writes the section at [rdx..r8) with strict bounds.
;   Any u64 wrap, oversized ptlen, or buffer overrun sets g_att_missing = 1.
attach_build proc frame
    FRAME_PROLOG 192
    mov     dword ptr [rbp-24], ecx             ; emit
    mov     qword ptr [rbp-32], rdx             ; cur
    mov     qword ptr [rbp-152], r8             ; out_end (valid when emit != 0)
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
    je      ab_isatt                            ;   an AttachRef value
    cmp     qword ptr [rbp-128], VF_FILE
    jne     ab_fadv
ab_isatt:
    mov     rax, qword ptr [rbp-104]            ; out.valptr (= [rbp-128+24])
    mov     qword ptr [rbp-136], rax            ; ref
    mov     rcx, qword ptr [rax+ARF_PTLEN]
    cmp     rcx, ATT_FILE_MAX
    ja      ab_ovf
    mov     qword ptr [rbp-144], rcx            ; ptlen
    mov     r9, rcx
    add     r9, ATT_ENThDR + 16                 ; entry_bytes = 24 + ptlen + 16
    jc      ab_ovf
    mov     rax, qword ptr [rbp-40]
    add     rax, r9
    jc      ab_ovf
    mov     ecx, ATT_TOTAL_MAX
    cmp     rax, rcx
    ja      ab_ovf
    cmp     dword ptr [rbp-24], 0
    je      ab_acc
    mov     r10, qword ptr [rbp-32]             ; cur
    mov     r11, qword ptr [rbp-152]            ; out_end
    cmp     r10, r11
    ja      ab_ovf
    sub     r11, r10
    cmp     r9, r11
    ja      ab_ovf
    mov     rcx, qword ptr [rbp-136]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, qword ptr [rbp-144]
    call    attach_emit_one
ab_acc:
    mov     rax, qword ptr [rbp-144]
    add     rax, ATT_ENThDR + 16                ; 24 + ptlen + 16
    add     qword ptr [rbp-40], rax
    jc      ab_ovf
    cmp     dword ptr [rbp-24], 0
    je      ab_cnt
    mov     rcx, qword ptr [rbp-32]
    add     rcx, rax
    jc      ab_ovf
    mov     qword ptr [rbp-32], rcx
ab_cnt:
    cmp     dword ptr [rbp-48], MAX_ATTIDX
    jae     ab_ovf
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
    mov     rax, qword ptr [rbp-40]
    add     rax, ATT_TRAILER
    jc      ab_ovf
    cmp     dword ptr [rbp-24], 0
    je      ab_trail
    mov     rcx, qword ptr [rbp-32]
    mov     r11, qword ptr [rbp-152]
    cmp     rcx, r11
    ja      ab_ovf
    sub     r11, rcx
    cmp     r11, ATT_TRAILER
    jb      ab_ovf
    mov     dword ptr [rcx], ATT_MAGIC
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [rcx+4], rax
ab_trail:
    add     qword ptr [rbp-40], ATT_TRAILER
    jc      ab_ovf
ab_ret:
    mov     rax, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
ab_ovf:
    mov     dword ptr [g_att_missing], 1
    xor     eax, eax
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
    call    attach_free
    call    attach_reset
    xor     eax, eax
    FRAME_EPILOG
    ret
ast_freefail:
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, 40
    call    attach_free
ast_fail:
    call    attach_reset
    mov     eax, 1
    FRAME_EPILOG
    ret
attach_selftest endp

; ===========================================================================
; zi_att_verify() -> eax = attachment fields whose ciphertext opened AND whose
;   plaintext matched one of the two do_attgen payloads.
;   Walks every entry, opens every VF_IMAGE/VF_FILE AttachRef in the CURRENT
;   vault and checks the bytes really came back.  cmd_zitest asserts the count,
;   which is what turns the import probe from "an entry arrived" into "the
;   attachment content survived" - the distinction that let an import silently
;   destroy saved attachments (9ee91da) while the probe still reported success.
; ===========================================================================
; ===========================================================================
; zi_att_verify(ecx = trailing entries to check) -> eax = attachment fields among
;   them whose ciphertext opened AND whose plaintext matched a do_attgen payload.
;
;   Only the LAST n: zi_commit APPENDS, so imported records sit at the end.  Walking
;   every entry instead is quadratic - vault_entry_ptr rescans from the body start -
;   and the seeded probe vault carries 5000 records, which turns a correct walk into
;   minutes of CPU that reads as a hang.
;
;   cmd_zitest asserts the count, which is what turns the import probe from "an
;   entry arrived" into "the attachment content survived" - the distinction that
;   let an import silently destroy saved attachments (9ee91da) while the probe
;   still reported success.
; ===========================================================================
public zi_att_verify
zi_att_verify proc frame
    FRAME_PROLOG 96
    mov     dword ptr [rbp-64], ecx             ; entries still to check
    xor     eax, eax
    mov     dword ptr [rbp-24], eax             ; ok count
    call    vault_count
    mov     dword ptr [rbp-40], eax             ; index, walked backwards from the end
zav_entry:
    cmp     dword ptr [rbp-64], 0
    je      zav_done
    cmp     dword ptr [rbp-40], 0
    je      zav_done
    dec     dword ptr [rbp-64]
    dec     dword ptr [rbp-40]
    mov     ecx, dword ptr [rbp-40]
    call    vault_entry_ptr
    test    rax, rax
    jz      zav_entry
    mov     qword ptr [rbp-32], rax
    mov     dword ptr [rbp-36], VF_IMAGE        ; both attachment kinds
zav_kind:
    mov     rcx, qword ptr [rbp-32]
    mov     edx, dword ptr [rbp-36]
    call    find_field_in
    test    rax, rax
    jz      zav_kindnext
    cmp     rdx, ARF_SIZE                       ; must carry a whole AttachRef
    jb      zav_kindnext
    mov     rcx, rax                            ; ref -> plaintext
    lea     rdx, [rbp-48]
    call    attach_open
    test    rax, rax
    jz      zav_kindnext                        ; ciphertext gone / unauthentic
    mov     qword ptr [rbp-56], rax
    mov     rax, qword ptr [rbp-48]             ; length must match one payload
    cmp     rax, AG_PLAIN_LEN
    je      zav_cmp1
    cmp     rax, AG_PLAI2_LEN
    jne     zav_free
    lea     r11, [ag_plai2]
    mov     r8d, AG_PLAI2_LEN
    jmp     zav_cmp
zav_cmp1:
    lea     r11, [ag_plain]
    mov     r8d, AG_PLAIN_LEN
zav_cmp:
    mov     r10, qword ptr [rbp-56]
    xor     ecx, ecx
zav_cmplp:
    cmp     ecx, r8d
    jae     zav_hit
    mov     al, byte ptr [r10+rcx]
    cmp     al, byte ptr [r11+rcx]
    jne     zav_free
    inc     ecx
    jmp     zav_cmplp
zav_hit:
    inc     dword ptr [rbp-24]
zav_free:
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-48]
    call    attach_free
zav_kindnext:
    mov     eax, dword ptr [rbp-36]
    cmp     eax, VF_IMAGE
    jne     zav_entry
    mov     dword ptr [rbp-36], VF_FILE
    jmp     zav_kind
zav_done:
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
zi_att_verify endp

; ===========================================================================
; cmd_convcap - regression for the silent field-destruction bug.
;   conv_w2u wraps WideCharToMultiByte, which returns 0 BOTH for an empty result
;   and for ERROR_INSUFFICIENT_BUFFER.  Collapsing those into 0 meant a value too
;   long for the buffer was written to the vault as an EMPTY field - the user's
;   text was destroyed on save with no error.  conv_w2u now returns -1 for "did
;   not fit", and the writers refuse rather than store the empty.
;   Asserts, in order: a normal string converts; an empty string is 0 and NOT -1
;   (the two must stay distinguishable); a string that overflows its buffer is -1
;   and NOT 0; and CONV_CAP is large enough for the longest value the UI accepts
;   even if every character is a 3-byte one.  Revert conv_w2u's cw_fail and the
;   third assert FAILS (exit 1).
; ===========================================================================
.data
CSTR cvc_ok,  "convcap: PASS (overflow is distinguishable from empty; cap covers the UI limit)",13,10
CSTR cvc_bad, "convcap: FAIL (an over-long value would be stored as an EMPTY field)",13,10
align 2
cvc_hi  dw 'h','i',0
cvc_mt  dw 0
cvc_big dw 300 dup ('A'), 0                 ; 300 chars into a 64-byte buffer
.code
LANDING_PAD
public cmd_convcap
cmd_convcap proc frame
    FRAME_PROLOG 48
    lea     rcx, [cvc_hi]                       ; 1. a normal string converts
    lea     rdx, [cvc_out]
    mov     r8d, 4096
    call    conv_w2u
    cmp     eax, 2
    jne     cvc_fail
    lea     rcx, [cvc_mt]                       ; 2. empty is 0, and must NOT be -1
    lea     rdx, [cvc_out]
    mov     r8d, 4096
    call    conv_w2u
    test    eax, eax
    jnz     cvc_fail
    lea     rcx, [cvc_big]                      ; 3. overflow is -1, and must NOT be 0 -
    lea     rdx, [cvc_out]                      ;    0 here is what destroyed the field
    mov     r8d, 64
    call    conv_w2u
    cmp     eax, -1
    jne     cvc_fail
    ; 4. the cap must cover the widest value the UI can hold, worst-case 3 bytes
    ;    per wide char, or a legitimate value could still fail to fit.
    mov     eax, CONVW_MAX - 1
    imul    eax, eax, 3
    inc     eax
    cmp     eax, CONV_CAP
    ja      cvc_fail
    lea     rcx, [cvc_ok]
    mov     edx, cvc_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
cvc_fail:
    lea     rcx, [cvc_bad]
    mov     edx, cvc_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_convcap endp

; ===========================================================================
; cmd_attovfkat - VDR-02 attachment u64 wrap / per-file cap / cumulative section
;   cap / emit=1 destination bounds regression probe.
; ===========================================================================
.data
CSTR avk_ok,  "attovfkat: PASS (attachment u64 wrap, file/section caps, and emit bounds enforced)",13,10
CSTR avk_bad, "attovfkat: FAIL (hostile ARF_PTLEN slipped past validator or attach_build)",13,10
.data?
avk_tiny db 32 dup (?)
.code
LANDING_PAD
public cmd_attovfkat
cmd_attovfkat proc frame
    FRAME_PROLOG 48
    mov     rcx, VAULT_BODY_MAX
    call    secmem_alloc
    test    rax, rax
    jz      avk_fail
    mov     qword ptr [g_body_ptr], rax
    mov     r10, rax
    xor     ecx, ecx
avk_zlp:
    mov     byte ptr [r10+rcx], 0
    inc     ecx
    cmp     ecx, 1280
    jb      avk_zlp
    ; 1-entry, 1-field VF_FILE body (40 + 6 + ARF_SIZE = 114 bytes)
    mov     dword ptr [r10+0], 1                ; entry_count = 1
    mov     dword ptr [r10+36], 1               ; field_count = 1
    mov     word ptr [r10+40], VF_FILE
    mov     dword ptr [r10+42], ARF_SIZE
    mov     qword ptr [g_body_len], 40 + 6 + ARF_SIZE

    ; 1) Inclusive upper bound: ARF_PTLEN = ATT_FILE_MAX is structurally valid
    mov     r10, qword ptr [g_body_ptr]
    mov     rax, ATT_FILE_MAX
    mov     qword ptr [r10 + 46 + ARF_PTLEN], rax
    call    vault_body_validate
    test    eax, eax
    jnz     avk_faillk

    ; 2) Near-2^64 ARF_PTLEN (-32) used to wrap ptlen+40 to 8 -> must reject in BOTH
    mov     r10, qword ptr [g_body_ptr]
    mov     rax, 0FFFFFFFFFFFFFFE0h
    mov     qword ptr [r10 + 46 + ARF_PTLEN], rax
    call    vault_body_validate
    test    eax, eax
    jz      avk_faillk
    mov     dword ptr [g_att_missing], 0
    xor     ecx, ecx
    xor     edx, edx
    xor     r8d, r8d
    call    attach_build
    test    rax, rax
    jnz     avk_faillk
    cmp     dword ptr [g_att_missing], 1
    jne     avk_faillk

    ; 3) ARF_PTLEN = ATT_FILE_MAX + 1 -> must reject in BOTH
    mov     r10, qword ptr [g_body_ptr]
    mov     rax, ATT_FILE_MAX + 1
    mov     qword ptr [r10 + 46 + ARF_PTLEN], rax
    call    vault_body_validate
    test    eax, eax
    jz      avk_faillk
    mov     dword ptr [g_att_missing], 0
    xor     ecx, ecx
    xor     edx, edx
    xor     r8d, r8d
    call    attach_build
    test    rax, rax
    jnz     avk_faillk
    cmp     dword ptr [g_att_missing], 1
    jne     avk_faillk

    ; 4) emit=1 destination bounds check: 64-byte payload into a 32-byte out window
    mov     r10, qword ptr [g_body_ptr]
    mov     qword ptr [r10 + 46 + ARF_PTLEN], 64
    call    vault_body_validate
    test    eax, eax
    jnz     avk_faillk
    mov     dword ptr [g_att_missing], 0
    mov     ecx, 1
    lea     rdx, [avk_tiny]
    lea     r8, [avk_tiny + 32]
    call    attach_build
    test    rax, rax
    jnz     avk_faillk
    cmp     dword ptr [g_att_missing], 1
    jne     avk_faillk

    ; 5) Cumulative ATT_TOTAL_MAX cap: 16 fields * ATT_FILE_MAX = 4 GiB > ATT_TOTAL_MAX
    mov     r10, qword ptr [g_body_ptr]
    mov     dword ptr [r10+36], 16              ; field_count = 16
    lea     r11, [r10+40]
    mov     rax, ATT_FILE_MAX
    xor     ecx, ecx
avk_mk16:
    mov     word ptr [r11+0], VF_FILE
    mov     dword ptr [r11+2], ARF_SIZE
    mov     qword ptr [r11 + 6 + ARF_PTLEN], rax
    add     r11, 6 + ARF_SIZE
    inc     ecx
    cmp     ecx, 16
    jb      avk_mk16
    mov     qword ptr [g_body_len], 40 + 16 * (6 + ARF_SIZE)
    call    vault_body_validate
    test    eax, eax
    jz      avk_faillk
    mov     dword ptr [g_att_missing], 0
    xor     ecx, ecx
    xor     edx, edx
    xor     r8d, r8d
    call    attach_build
    test    rax, rax
    jnz     avk_faillk
    cmp     dword ptr [g_att_missing], 1
    jne     avk_faillk

    call    vault_lock
    lea     rcx, [avk_ok]
    mov     edx, avk_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
avk_faillk:
    call    vault_lock
avk_fail:
    lea     rcx, [avk_bad]
    mov     edx, avk_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_attovfkat endp

; ===========================================================================
; cmd_vattcolkat <path> - VDR-19 deterministic real-AES-GCM VATT tag-collision KAT.
;   Solves a 128x128 GF(2) affine system over an 80-byte plaintext body's final
;   16-byte VF_NOTES block so the genuine AES-256-GCM tag has tag[4..7] == "VATT"
;   (ATT_MAGIC) and tag[8..15] == 8.  Asserts vault_unlock recovers cleanly via
;   the retry path (g_att_total == 0, vault_count == 1), while a 1-bit ciphertext
;   tamper with re-signed outer MAC still fails closed with EXIT_AUTH.
; ===========================================================================
VCK_FILE_LEN equ 220                            ; 80 hdr + 80 ct + 16 tag + 44 fmac

.data
CSTR vck_ok,  "vattcolkat: PASS (authentic VATT-colliding GCM tag unlocked; tampered ct rejected)",13,10
CSTR vck_bad, "vattcolkat: FAIL (VATT tag-collision fallback regressed)",13,10
.data?
align 8
vck_mat  db 4096 dup (?)                        ; 128 rows * 32B: [lhs16 | rhs16]
vck_file db 224 dup (?)                         ; 220B vault image (padded to 8B)
vck_body db 80 dup (?)                          ; 80B plaintext body
vck_t0   db 16 dup (?)
vck_dt   db 16 dup (?)
vck_x    db 16 dup (?)
.code
vck_seal_once proc frame
    FRAME_PROLOG 32
    lea     r10, [g_greq]
    lea     rax, [g_vkey]
    mov     qword ptr [r10].GCMREQ.key, rax
    lea     rax, [g_hdr + VH_NONCE]
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_hdr]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, VH_TOTAL
    lea     rax, [vck_body]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     qword ptr [r10].GCMREQ.inlen, 80
    lea     rax, [vck_file + VH_TOTAL]
    mov     qword ptr [r10].GCMREQ.outp, rax
    lea     rax, [vck_file + VH_TOTAL + 80]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [g_greq]
    call    gcm_seal
    FRAME_EPILOG
    ret
vck_seal_once endp

LANDING_PAD
public cmd_vattcolkat
cmd_vattcolkat proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=i/c  [rbp-28]=p  [rbp-32]=r
    lea     r10, [g_argv]
    mov     rcx, qword ptr [r10+16]
    call    cfg_in_set
    lea     rcx, [g_cfg_pass]
    lea     rdx, [bk_pw]
    mov     r8d, 10
    call    copy_bytes
    mov     dword ptr [g_cfg_passlen], 9
    mov     dword ptr [g_cfg_t], 1
    mov     dword ptr [g_cfg_m], 8

    ; Build 80-byte vault header + derive real AES-256 vault key
    mov     dword ptr [g_hdr+0], VAULT_MAGIC
    mov     dword ptr [g_hdr+4], VAULT_VERSION
    mov     dword ptr [g_hdr+VH_T], 1
    mov     dword ptr [g_hdr+VH_M], 8
    mov     dword ptr [g_hdr+VH_LANES], 1
    lea     rcx, [g_hdr+VH_SALT]
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      vck_fail
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      vck_fail
    call    vk_derive
    test    eax, eax
    jnz     vck_fail
    call    vk_kcv
    lea     rcx, [g_hdr+VH_KCV]
    lea     rdx, [g_sha32]
    mov     r8d, KCV_LEN
    call    copy_bytes
    lea     rcx, [vck_file]
    lea     rdx, [g_hdr]
    mov     r8d, VH_TOTAL
    call    copy_bytes

    ; Construct 80-byte body: 1 entry, VF_TITLE(12)="VattCollTest", VF_NOTES(16)@[64..79]
    lea     r10, [vck_body]
    xor     ecx, ecx
vck_zb:
    mov     qword ptr [r10+rcx], 0
    add     ecx, 8
    cmp     ecx, 80
    jb      vck_zb
    mov     dword ptr [r10+0], 1
    mov     byte ptr [r10+4], 77h
    mov     qword ptr [r10+20], 1
    mov     qword ptr [r10+28], 1
    mov     dword ptr [r10+36], 2
    mov     word ptr [r10+40], VF_TITLE
    mov     dword ptr [r10+42], 12
    mov     rax, 6C6C6F4374746156h              ; "VattColl"
    mov     qword ptr [r10+46], rax
    mov     dword ptr [r10+54], 74736554h       ; "Test"
    mov     word ptr [r10+58], VF_NOTES
    mov     dword ptr [r10+60], 16

    ; T0 = tag(0^128)
    call    vck_seal_once
    lea     rcx, [vck_t0]
    lea     rdx, [vck_file + 160]
    mov     r8d, 16
    call    copy_bytes

    ; Sample L(e_i) = tag(e_i) XOR T0 for i = 0..127 -> vck_mat[i] = [L(e_i) | e_i]
    mov     dword ptr [rbp-24], 0
vck_basis:
    lea     r10, [vck_body + 64]
    mov     qword ptr [r10+0], 0
    mov     qword ptr [r10+8], 0
    mov     eax, dword ptr [rbp-24]
    mov     edx, eax
    shr     edx, 3
    mov     ecx, eax
    and     ecx, 7
    mov     r8d, 1
    shl     r8d, cl
    mov     byte ptr [r10+rdx], r8b
    call    vck_seal_once
    mov     eax, dword ptr [rbp-24]
    shl     eax, 5                              ; i * 32
    lea     r11, [vck_mat]
    add     r11, rax
    lea     r9, [vck_file + 160]
    lea     r8, [vck_t0]
    mov     rax, qword ptr [r9+0]
    xor     rax, qword ptr [r8+0]
    mov     qword ptr [r11+0], rax
    mov     rax, qword ptr [r9+8]
    xor     rax, qword ptr [r8+8]
    mov     qword ptr [r11+8], rax
    lea     r10, [vck_body + 64]
    mov     rax, qword ptr [r10+0]
    mov     qword ptr [r11+16], rax
    mov     rax, qword ptr [r10+8]
    mov     qword ptr [r11+24], rax
    inc     dword ptr [rbp-24]
    cmp     dword ptr [rbp-24], 128
    jb      vck_basis

    ; Gauss-Jordan elimination over GF(2) on columns c = 0..127
    mov     dword ptr [rbp-24], 0
vck_col:
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [rbp-28], eax             ; p = c
vck_piv:
    mov     eax, dword ptr [rbp-28]
    cmp     eax, 128
    jae     vck_faillk                          ; singular (H == 0, prob 2^-128)
    shl     eax, 5
    lea     r10, [vck_mat]
    add     r10, rax
    mov     ecx, dword ptr [rbp-24]
    mov     edx, ecx
    shr     edx, 3
    and     ecx, 7
    movzx   eax, byte ptr [r10+rdx]
    shr     eax, cl
    test    al, 1
    jnz     vck_swap
    inc     dword ptr [rbp-28]
    jmp     vck_piv
vck_swap:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [rbp-28]
    je      vck_elim
    shl     eax, 5
    lea     r10, [vck_mat]
    add     r10, rax                            ; row c
    mov     edx, dword ptr [rbp-28]
    shl     edx, 5
    lea     r11, [vck_mat]
    add     r11, rdx                            ; row p
    xor     ecx, ecx
vck_swlp:
    mov     rax, qword ptr [r10+rcx]
    mov     r8, qword ptr [r11+rcx]
    mov     qword ptr [r10+rcx], r8
    mov     qword ptr [r11+rcx], rax
    add     ecx, 8
    cmp     ecx, 32
    jb      vck_swlp
vck_elim:
    mov     dword ptr [rbp-32], 0               ; r = 0
vck_row:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, 128
    jae     vck_colnext
    cmp     eax, dword ptr [rbp-24]
    je      vck_rownext
    shl     eax, 5
    lea     r11, [vck_mat]
    add     r11, rax                            ; row r
    mov     ecx, dword ptr [rbp-24]
    mov     edx, ecx
    shr     edx, 3
    and     ecx, 7
    movzx   eax, byte ptr [r11+rdx]
    shr     eax, cl
    test    al, 1
    jz      vck_rownext
    mov     eax, dword ptr [rbp-24]
    shl     eax, 5
    lea     r10, [vck_mat]
    add     r10, rax                            ; row c
    xor     ecx, ecx
vck_xrow:
    mov     rax, qword ptr [r10+rcx]
    xor     qword ptr [r11+rcx], rax
    add     ecx, 8
    cmp     ecx, 32
    jb      vck_xrow
vck_rownext:
    inc     dword ptr [rbp-32]
    jmp     vck_row
vck_colnext:
    inc     dword ptr [rbp-24]
    cmp     dword ptr [rbp-24], 128
    jb      vck_col

    ; Target delta: dt = T_target XOR T0, where T_target = [T0[0..3], ATT_MAGIC, u64(8)]
    lea     r8, [vck_t0]
    lea     r9, [vck_dt]
    mov     dword ptr [r9+0], 0
    mov     eax, ATT_MAGIC
    xor     eax, dword ptr [r8+4]
    mov     dword ptr [r9+4], eax
    mov     rax, 8
    xor     rax, qword ptr [r8+8]
    mov     qword ptr [r9+8], rax

    ; Reconstruct x = XOR_{c : dt_c == 1} rhs_c
    lea     r10, [vck_x]
    mov     qword ptr [r10+0], 0
    mov     qword ptr [r10+8], 0
    xor     r8d, r8d                            ; c = 0..127
vck_rec:
    mov     edx, r8d
    shr     edx, 3
    mov     ecx, r8d
    and     ecx, 7
    lea     r9, [vck_dt]
    movzx   eax, byte ptr [r9+rdx]
    shr     eax, cl
    test    al, 1
    jz      vck_recnext
    mov     eax, r8d
    shl     eax, 5
    lea     r11, [vck_mat]
    add     r11, rax
    mov     rax, qword ptr [r11+16]
    xor     qword ptr [r10+0], rax
    mov     rax, qword ptr [r11+24]
    xor     qword ptr [r10+8], rax
vck_recnext:
    inc     r8d
    cmp     r8d, 128
    jb      vck_rec

    ; Seal solved body and verify genuine tag collides with ATT_MAGIC + entries_len=8
    lea     rcx, [vck_body + 64]
    lea     rdx, [vck_x]
    mov     r8d, 16
    call    copy_bytes
    call    vck_seal_once
    cmp     dword ptr [vck_file + 164], ATT_MAGIC
    jne     vck_faillk
    cmp     qword ptr [vck_file + 168], 8
    jne     vck_faillk

    ; Append counter=1 + full-file MAC + FMAC_MAGIC, write, and unlock via retry path
    mov     qword ptr [vck_file + 176], 1
    lea     rcx, [vck_file]
    mov     edx, 184
    lea     r8, [g_fmac_out]
    call    vault_file_mac
    lea     rcx, [vck_file + 184]
    lea     rdx, [g_fmac_out]
    mov     r8d, FMAC_MACLEN
    call    copy_bytes
    mov     dword ptr [vck_file + 216], FMAC_MAGIC
    call    vault_lock

    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [vck_file]
    mov     r8d, VCK_FILE_LEN
    call    write_file
    test    eax, eax
    jnz     vck_fail
    lea     rcx, [g_cfg_pass]
    lea     rdx, [bk_pw]
    mov     r8d, 10
    call    copy_bytes
    mov     dword ptr [g_cfg_passlen], 9
    call    vault_unlock
    test    eax, eax
    jnz     vck_faillk
    cmp     qword ptr [g_att_total], 0
    jne     vck_faillk
    call    vault_count
    cmp     eax, 1
    jne     vck_faillk

    ; Negative control: flip 1 ct bit, re-sign outer MAC (using still-live g_vkey),
    ; lock, write, and verify the VATT retry path still rejects unauthentic ct!
    xor     byte ptr [vck_file + VH_TOTAL], 1
    lea     rcx, [vck_file]
    mov     edx, 184
    lea     r8, [g_fmac_out]
    call    vault_file_mac
    lea     rcx, [vck_file + 184]
    lea     rdx, [g_fmac_out]
    mov     r8d, FMAC_MACLEN
    call    copy_bytes
    call    vault_lock
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [vck_file]
    mov     r8d, VCK_FILE_LEN
    call    write_file
    test    eax, eax
    jnz     vck_fail
    lea     rcx, [g_cfg_pass]
    lea     rdx, [bk_pw]
    mov     r8d, 10
    call    copy_bytes
    mov     dword ptr [g_cfg_passlen], 9
    call    vault_unlock
    cmp     eax, EXIT_AUTH
    jne     vck_faillk
    call    vault_lock

    lea     rcx, [vck_ok]
    mov     edx, vck_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
vck_faillk:
    call    vault_lock
vck_fail:
    lea     rcx, [vck_bad]
    mov     edx, vck_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_vattcolkat endp

ifdef PROBE_IO
; ===========================================================================
; vault_tpm_pin_kat() -> eax = 0 (PASS) / 1 (FAIL).
;   Headless Mode 2 (TPM + PIN) anti-replay, 3-strike revocation & disk lifecycle KAT.
;   Verifies:
;     1) Mode 2 enroll + Mode 1 downgrade refusal (EXIT_LOCKED).
;     2) Valid PIN round-trip + S0 -> S1 -> S0 key rotation.
;     3) Registry snapshot replay refusal (replaying old S0 blob fails & revokes).
;     4) Failed-attempt counter tracking + reset to 0 on subsequent valid PIN.
;     5) Automatic 3-strike revocation (deletes TPM keys + HKCU entry).
;     6) Disk lifecycle: Vault 1 reseal (VH_NONCE rotation) + PIN unlock + 3-strike
;        revocation + Master Password A unlock + Vault 2 create + PIN enroll +
;        PIN unlock + Master Password B unlock.
; ===========================================================================
.data
WSTR vtpk_path, <C:\VordrTpmPinKat\kat.vordr>
WSTR vtpk_fn1,  <vordr_tpkat1.vordr>
WSTR vtpk_fn2,  <vordr_tpkat2.vordr>
vtpk_pin_ok  db "739284"
vtpk_pin_ok2 db "849205"
vtpk_pin_b1  db "111111"
vtpk_pin_b2  db "222222"
vtpk_pin_b3  db "333333"
vtpk_pw_a    db "CorrectHorse#99", 0
vtpk_pw_b    db "SecondVault$88", 0
.data?
align 8
vtpk_hdr_bk  db VH_TOTAL dup (?)
vtpk_vkey_bk db 32 dup (?)
vtpk_vkey_ex db 32 dup (?)
vtpk_snap    db TPM_PIN_BLOB_SZ dup (?)
vtpk_p1      dw 320 dup (?)
vtpk_p2      dw 320 dup (?)
.code
vtpk_set_pin proc
    ; rcx = ptr, edx = len (<= 32)
    mov     dword ptr [g_tpm_pin_u8len], edx
    lea     r10, [g_tpm_pin_u8]
    xor     r8d, r8d
vsp_lp:
    cmp     r8d, edx
    jae     vsp_dn
    mov     al, byte ptr [rcx+r8]
    mov     byte ptr [r10+r8], al
    inc     r8d
    jmp     vsp_lp
vsp_dn:
    ret
vtpk_set_pin endp

vtpk_set_pw proc
    ; rcx = ascii ptr, edx = len
    mov     dword ptr [g_cfg_passlen], edx
    lea     r10, [g_cfg_pass]
    xor     r8d, r8d
vspw_lp:
    cmp     r8d, edx
    jae     vspw_dn
    mov     al, byte ptr [rcx+r8]
    mov     byte ptr [r10+r8], al
    inc     r8d
    jmp     vspw_lp
vspw_dn:
    mov     byte ptr [r10+r8], 0
    ret
vtpk_set_pw endp

vtpk_mk_tmppath proc frame
    ; rcx = dst (320 wchars), rdx = leaf wideZ -> eax = 1 ok / 0 fail
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    WINCALL GetTempPathW, 260, rcx
    test    eax, eax
    jz      vmtp_fail
    cmp     eax, 260
    jae     vmtp_fail
    mov     r10, qword ptr [rbp-16]
    lea     r10, [r10 + rax*2]
    cmp     word ptr [r10-2], 5Ch
    je      @F
    mov     word ptr [r10], 5Ch
    add     r10, 2
@@: mov     r11, qword ptr [rbp-24]
    xor     ecx, ecx
vmtp_cp:
    mov     ax, word ptr [r11 + rcx*2]
    mov     word ptr [r10 + rcx*2], ax
    test    ax, ax
    jz      vmtp_ok
    inc     ecx
    cmp     ecx, 48
    jb      vmtp_cp
vmtp_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
vmtp_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
vtpk_mk_tmppath endp

vtpk_clean_disk proc frame
    ; rcx = wide vault path; locks, deletes TPM + anti-rollback reg entries + file + backups
    FRAME_PROLOG 32
    cmp     word ptr [rcx], 0
    je      vpcd_ret
    call    cfg_in_set
    call    vault_lock
    call    vault_tpm_forget
    mov     rcx, qword ptr [g_cfg_in]
    call    reg_ctr_del
    WINCALL DeleteFileW, qword ptr [g_cfg_in]
    lea     rcx, [g_bak_a]
    mov     dl, '0'
    call    vault_mkbak
    WINCALL DeleteFileW, addr g_bak_a
    lea     rcx, [g_bak_a]
    mov     dl, '1'
    call    vault_mkbak
    WINCALL DeleteFileW, addr g_bak_a
    lea     rcx, [g_bak_a]
    mov     dl, '2'
    call    vault_mkbak
    WINCALL DeleteFileW, addr g_bak_a
    lea     rcx, [g_bak_a]
    mov     dl, '3'
    call    vault_mkbak
    WINCALL DeleteFileW, addr g_bak_a
vpcd_ret:
    FRAME_EPILOG
    ret
vtpk_clean_disk endp

public vault_tpm_pin_kat
vault_tpm_pin_kat proc frame
    FRAME_PROLOG 80
    ; [rbp-16]=saved use_tpm [rbp-20]=saved reqhello
    ; [rbp-24]=saved pin_t   [rbp-28]=saved pin_m   [rbp-32]=saved pin_max
    ; [rbp-36]=saved cfg_t   [rbp-40]=saved cfg_m   [rbp-44]=rc
    mov     eax, dword ptr [g_use_tpm]
    mov     dword ptr [rbp-16], eax
    mov     eax, dword ptr [g_tpm_reqhello]
    mov     dword ptr [rbp-20], eax
    mov     eax, dword ptr [g_tpm_pin_t]
    mov     dword ptr [rbp-24], eax
    mov     eax, dword ptr [g_tpm_pin_m]
    mov     dword ptr [rbp-28], eax
    mov     eax, dword ptr [g_tpm_pin_max]
    mov     dword ptr [rbp-32], eax
    mov     eax, dword ptr [g_cfg_t]
    mov     dword ptr [rbp-36], eax
    mov     eax, dword ptr [g_cfg_m]
    mov     dword ptr [rbp-40], eax
    mov     dword ptr [rbp-44], 1
    mov     word ptr [vtpk_p1], 0
    mov     word ptr [vtpk_p2], 0

    lea     rcx, [vtpk_hdr_bk]
    lea     rdx, [g_hdr]
    mov     r8d, VH_TOTAL
    call    copy_bytes
    lea     rcx, [vtpk_vkey_bk]
    lea     rdx, [g_vkey]
    mov     r8d, 32
    call    copy_bytes

    ; Set isolated test vault path + deterministic header/vkey + fast KDF params
    lea     rcx, [vtpk_path]
    call    cfg_in_set
    mov     dword ptr [g_tpm_reqhello], 0
    mov     dword ptr [g_tpm_pin_t], 1
    mov     dword ptr [g_tpm_pin_m], 64
    mov     dword ptr [g_tpm_pin_max], 3

    xor     ecx, ecx
vtpk_seed:
    lea     eax, [rcx + 31h]
    lea     r10, [g_vkey]
    mov     byte ptr [r10+rcx], al
    lea     r10, [vtpk_vkey_ex]
    mov     byte ptr [r10+rcx], al
    lea     r10, [g_hdr + VH_SALT]
    xor     eax, 55h
    mov     byte ptr [r10+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      vtpk_seed
    call    vk_kcv
    lea     rcx, [g_hdr + VH_KCV]
    lea     rdx, [g_sha32]
    mov     r8d, KCV_LEN
    call    copy_bytes

    ; 1) Enroll Mode 2 with PIN "739284"
    lea     rcx, [vtpk_pin_ok]
    mov     edx, 6
    call    vtpk_set_pin
    call    vault_tpm_enroll_pin
    cmp     eax, 1
    jne     vtpk_out
    call    vault_tpm_mode_get
    cmp     eax, TPM_MODE_PIN
    jne     vtpk_out

    ; 2) Mode 1 (TPM Alone) MUST refuse a Mode 2 envelope (no policy-downgrade bypass)
    mov     dword ptr [g_use_tpm], TPM_MODE_ALONE
    call    vk_derive_tpm
    cmp     eax, EXIT_LOCKED
    jne     vtpk_out

    ; Snapshot HKCU envelope BEFORE first unlock (S0 key #1, gen=1)
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [vtpk_snap]
    mov     r8d, TPM_PIN_BLOB_SZ
    call    reg_tpm_get
    cmp     eax, TPM_PIN_BLOB_SZ
    jne     vtpk_out

    ; 3) Unlock with valid PIN "739284" -> recovers g_vkey & rotates S0 -> S1 -> S0 (key #3)
    lea     rcx, [g_vkey]
    mov     edx, 32
    call    secure_zero
    mov     dword ptr [g_use_tpm], TPM_MODE_PIN
    lea     rcx, [vtpk_pin_ok]
    mov     edx, 6
    call    vtpk_set_pin
    call    vk_derive_tpm
    test    eax, eax
    jnz     vtpk_out
    lea     rcx, [g_vkey]
    lea     rdx, [vtpk_vkey_ex]
    mov     r8d, 32
    call    ct_memcmp
    test    eax, eax
    jnz     vtpk_out

    ; 4) REPLAY ATTACK: restore old HKCU snapshot -> MUST fail closed & revoke!
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [vtpk_snap]
    mov     r8d, TPM_PIN_BLOB_SZ
    call    reg_tpm_set
    cmp     eax, 1
    jne     vtpk_out
    lea     rcx, [vtpk_pin_ok]
    mov     edx, 6
    call    vtpk_set_pin
    call    vk_derive_tpm
    cmp     eax, EXIT_LOCKED
    jne     vtpk_out
    call    vault_tpm_has
    test    eax, eax
    jnz     vtpk_out                            ; must have auto-revoked on replay!

    ; 5) Re-enroll "739284": 2 wrong PINs (rem=2, rem=1) then valid PIN resets fails to 0
    lea     rcx, [g_vkey]
    lea     rdx, [vtpk_vkey_ex]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [vtpk_pin_ok]
    mov     edx, 6
    call    vtpk_set_pin
    call    vault_tpm_enroll_pin
    cmp     eax, 1
    jne     vtpk_out

    lea     rcx, [vtpk_pin_b1]
    mov     edx, 6
    call    vtpk_set_pin
    call    vk_derive_tpm
    cmp     eax, EXIT_AUTH
    jne     vtpk_out
    cmp     dword ptr [g_tpm_pin_rem], 2
    jne     vtpk_out

    lea     rcx, [vtpk_pin_b2]
    mov     edx, 6
    call    vtpk_set_pin
    call    vk_derive_tpm
    cmp     eax, EXIT_AUTH
    jne     vtpk_out
    cmp     dword ptr [g_tpm_pin_rem], 1
    jne     vtpk_out

    lea     rcx, [vtpk_pin_ok]
    mov     edx, 6
    call    vtpk_set_pin
    call    vk_derive_tpm
    test    eax, eax
    jnz     vtpk_out
    cmp     dword ptr [g_tpm_pin_rem], 3
    jne     vtpk_out

    ; 6) 3-strike automatic revocation: 3 consecutive wrong PINs -> EXIT_LOCKED + deleted
    lea     rcx, [vtpk_pin_b1]
    mov     edx, 6
    call    vtpk_set_pin
    call    vk_derive_tpm
    cmp     eax, EXIT_AUTH
    jne     vtpk_out
    cmp     dword ptr [g_tpm_pin_rem], 2
    jne     vtpk_out

    lea     rcx, [vtpk_pin_b2]
    mov     edx, 6
    call    vtpk_set_pin
    call    vk_derive_tpm
    cmp     eax, EXIT_AUTH
    jne     vtpk_out
    cmp     dword ptr [g_tpm_pin_rem], 1
    jne     vtpk_out

    lea     rcx, [vtpk_pin_b3]
    mov     edx, 6
    call    vtpk_set_pin
    call    vk_derive_tpm
    cmp     eax, EXIT_LOCKED
    jne     vtpk_out
    cmp     dword ptr [g_tpm_pin_rem], 0
    jne     vtpk_out
    call    vault_tpm_has
    test    eax, eax
    jnz     vtpk_out

    ; Valid PIN after revocation MUST still return EXIT_LOCKED
    lea     rcx, [vtpk_pin_ok]
    mov     edx, 6
    call    vtpk_set_pin
    call    vk_derive_tpm
    cmp     eax, EXIT_LOCKED
    jne     vtpk_out
    call    vault_tpm_forget

    ; 7) Full disk lifecycle regression (VH_NONCE reseal + 3-strike pw survival + 2nd vault)
    lea     rcx, [vtpk_p1]
    lea     rdx, [vtpk_fn1]
    call    vtpk_mk_tmppath
    test    eax, eax
    jz      vtpk_out
    lea     rcx, [vtpk_p2]
    lea     rdx, [vtpk_fn2]
    call    vtpk_mk_tmppath
    test    eax, eax
    jz      vtpk_out
    lea     rcx, [vtpk_p1]
    call    vtpk_clean_disk
    lea     rcx, [vtpk_p2]
    call    vtpk_clean_disk

    ; 7a) Create Vault 1 ("CorrectHorse#99"), enroll PIN, reseal (rotates VH_NONCE!), unlock by PIN
    lea     rcx, [vtpk_p1]
    call    cfg_in_set
    mov     dword ptr [g_cfg_t], 1
    mov     dword ptr [g_cfg_m], 64
    mov     dword ptr [g_use_tpm], TPM_MODE_OFF
    lea     rcx, [vtpk_pw_a]
    mov     edx, 15
    call    vtpk_set_pw
    call    do_init
    test    eax, eax
    jnz     vtpk_out
    lea     rcx, [vtpk_pw_a]
    mov     edx, 15
    call    vtpk_set_pw
    call    vault_unlock
    test    eax, eax
    jnz     vtpk_out
    call    vault_add_system_item
    test    eax, eax
    jz      vtpk_out
    call    vault_reseal
    test    eax, eax
    jnz     vtpk_out
    lea     rcx, [vtpk_pin_ok]
    mov     edx, 6
    call    vtpk_set_pin
    call    vault_tpm_enroll_pin
    cmp     eax, 1
    jne     vtpk_out
    call    vault_reseal                        ; rotates VH_NONCE at g_hdr[52..63]!
    test    eax, eax
    jnz     vtpk_out
    call    vault_lock

    mov     dword ptr [g_use_tpm], TPM_MODE_PIN
    lea     rcx, [vtpk_pin_ok]
    mov     edx, 6
    call    vtpk_set_pin
    call    vault_unlock
    test    eax, eax
    jnz     vtpk_out
    call    vault_lock

    ; 7b) Trigger 3-strike revocation on Vault 1 -> Master Password A MUST still open Vault 1!
    mov     dword ptr [g_use_tpm], TPM_MODE_PIN
    lea     rcx, [vtpk_pin_b1]
    mov     edx, 6
    call    vtpk_set_pin
    call    vault_unlock
    cmp     eax, EXIT_AUTH
    jne     vtpk_out
    lea     rcx, [vtpk_pin_b2]
    mov     edx, 6
    call    vtpk_set_pin
    call    vault_unlock
    cmp     eax, EXIT_AUTH
    jne     vtpk_out
    lea     rcx, [vtpk_pin_b3]
    mov     edx, 6
    call    vtpk_set_pin
    call    vault_unlock
    cmp     eax, EXIT_LOCKED
    jne     vtpk_out
    call    vault_tpm_has
    test    eax, eax
    jnz     vtpk_out

    mov     dword ptr [g_use_tpm], TPM_MODE_OFF
    lea     rcx, [vtpk_pw_a]
    mov     edx, 15
    call    vtpk_set_pw
    call    vault_unlock
    test    eax, eax
    jnz     vtpk_out
    call    vault_lock

    ; 7c) Delete Vault 1 -> Create Vault 2 ("SecondVault$88") -> Enroll PIN -> Verify BOTH open!
    lea     rcx, [vtpk_p1]
    call    vtpk_clean_disk
    lea     rcx, [vtpk_p2]
    call    cfg_in_set
    mov     dword ptr [g_use_tpm], TPM_MODE_OFF
    lea     rcx, [vtpk_pw_b]
    mov     edx, 14
    call    vtpk_set_pw
    call    do_init
    test    eax, eax
    jnz     vtpk_out
    lea     rcx, [vtpk_pw_b]
    mov     edx, 14
    call    vtpk_set_pw
    call    vault_unlock
    test    eax, eax
    jnz     vtpk_out
    lea     rcx, [vtpk_pin_ok2]
    mov     edx, 6
    call    vtpk_set_pin
    call    vault_tpm_enroll_pin
    cmp     eax, 1
    jne     vtpk_out
    call    vault_reseal
    test    eax, eax
    jnz     vtpk_out
    call    vault_lock

    mov     dword ptr [g_use_tpm], TPM_MODE_PIN
    lea     rcx, [vtpk_pin_ok2]
    mov     edx, 6
    call    vtpk_set_pin
    call    vault_unlock
    test    eax, eax
    jnz     vtpk_out
    call    vault_lock

    mov     dword ptr [g_use_tpm], TPM_MODE_OFF
    lea     rcx, [vtpk_pw_b]
    mov     edx, 14
    call    vtpk_set_pw
    call    vault_unlock
    test    eax, eax
    jnz     vtpk_out
    call    vault_lock

    mov     dword ptr [rbp-44], 0

vtpk_out:
    call    vault_lock
    lea     rcx, [vtpk_path]
    call    cfg_in_set
    call    vault_tpm_forget
    lea     rcx, [vtpk_p1]
    call    vtpk_clean_disk
    lea     rcx, [vtpk_p2]
    call    vtpk_clean_disk
    lea     rcx, [g_cfg_pass]
    mov     edx, MAX_PASSWORD_BYTES + 1
    call    secure_zero
    mov     dword ptr [g_cfg_passlen], 0
    lea     rcx, [vtpk_vkey_ex]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_hdr]
    lea     rdx, [vtpk_hdr_bk]
    mov     r8d, VH_TOTAL
    call    copy_bytes
    lea     rcx, [g_vkey]
    lea     rdx, [vtpk_vkey_bk]
    mov     r8d, 32
    call    copy_bytes
    lea     rcx, [vtpk_vkey_bk]
    mov     edx, 32
    call    secure_zero
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_use_tpm], eax
    mov     eax, dword ptr [rbp-20]
    mov     dword ptr [g_tpm_reqhello], eax
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_tpm_pin_t], eax
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [g_tpm_pin_m], eax
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [g_tpm_pin_max], eax
    mov     eax, dword ptr [rbp-36]
    mov     dword ptr [g_cfg_t], eax
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [g_cfg_m], eax
    mov     eax, dword ptr [rbp-44]
    FRAME_EPILOG
    ret
vault_tpm_pin_kat endp
endif

end
