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
; Commands: do_init / do_add / do_list / do_get (each -> exit code in eax).
; Reuses the proven core: argon2id_hash, gcm_seal/gcm_open, sha256_hash,
; ct_memcmp, rng_fill, secure_zero, secmem_alloc/free, fileio, console.
; =============================================================================

include macros.inc

extern argon2id_hash:proc
extern gcm_seal:proc
extern gcm_open:proc
extern sha256_hash:proc
extern ct_memcmp:proc
extern rng_fill:proc
extern secure_zero:proc
extern secmem_alloc:proc
extern pwgen_ex:proc
extern secmem_free:proc
extern read_file:proc
extern write_file:proc
extern file_rename:proc
extern mem_alloc:proc
extern mem_free:proc
extern print_a:proc
extern print_err:proc
extern WideCharToMultiByte:proc
extern GetSystemTimeAsFileTime:proc
extern tpm_seal:proc
extern tpm_unseal:proc
extern tpm_delete:proc
extern reg_tpm_set:proc
extern reg_tpm_get:proc
extern reg_tpm_del:proc

externdef g_cfg_in:qword
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
ARF_ID          equ 0           ; AttachRef: 16-byte attachment id
ARF_KEY         equ 16          ;            32-byte AES-256 key
ARF_NONCE       equ 48          ;            12-byte GCM nonce
ARF_PTLEN       equ 60          ;            u64 plaintext length
ARF_SIZE        equ 68
ATT_ENThDR      equ 24          ; on-disk entry header = id16 + u64 ctlen
MAX_ATT         equ 512         ; index / pending-table capacity

.const
lbl_title   db "  title : "
lbl_title_n equ $ - lbl_title
lbl_user    db "  user  : "
lbl_user_n  equ $ - lbl_user
lbl_secret  db "  secret: "
lbl_secret_n equ $ - lbl_secret
lbl_url     db "  url   : "
lbl_url_n   equ $ - lbl_url
lbl_notes   db "  notes : "
lbl_notes_n equ $ - lbl_notes
nlcrlf      db 13,10
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
CSTR e_io,      "error: cannot read/write the vault file",13,10
CSTR e_corrupt, "error: not a Vordr vault (bad magic/version) or corrupt",13,10
CSTR e_locked,  "error: wrong master password (key-check failed)",13,10
CSTR e_auth,    "error: vault authentication failed (tampered or corrupt)",13,10
CSTR e_full,    "error: vault is full (1 MiB entry limit)",13,10
CSTR e_oom,     "error: out of memory",13,10
CSTR e_notitle, "error: 'add' needs --title (and usually --secret)",13,10
CSTR e_noopt,   "error: 'get' needs --title NAME",13,10
CSTR e_notfound,"no entry with that title",13,10
CSTR m_added,   "entry added.",13,10
CSTR m_created, "vault created.",13,10
CSTR m_removed, "entry removed.",13,10
CSTR m_updated, "entry updated.",13,10
CSTR m_empty,   "(vault is empty)",13,10

.data?
align 16
g_kat_body  db 512 dup (?)             ; scratch body for the field-serialization KAT
g_vkey      db 32 dup (?)
g_sha32     db 32 dup (?)
g_hdr       db VH_TOTAL dup (?)
align 8
g_areq      ARGON2REQ <>
g_greq      GCMREQ <>
g_body_ptr  dq ?
g_body_len  dq ?
g_filebuf   dq ?
g_filesize  dq ?
g_outbuf    dq ?
g_outlen    dq ?
align 16
g_att_greq  GCMREQ <>                          ; GCM req for attachment seal/open
g_newatt    db MAX_ATT * 32 dup (?)            ; pending new: {id16, qword pt, qword ptlen}
g_newatt_n  dd ?
g_attidx    db MAX_ATT * 32 dup (?)            ; from file: {id16, qword ct, qword ctlen}
g_attidx_n  dd ?
g_att_aad   db 32 dup (?)                       ; GCM AAD scratch = id16 | u64 ptlen
g_att_start dq ?                                ; file offset where attachments begin
g_att_total dq ?                                ; attachment entries byte length
g_conv      db CONV_CAP dup (?)
g_convlabel db MAX_LABEL_BYTES dup (?)        ; utf8 label scratch (va_field_labeled)
g_match     db CONV_CAP dup (?)
align 2
g_tmppath   dw MAX_PATH_CHARS dup (?)        ; "<vault>.tmp" for atomic replace
g_matchlen  dq ?
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
g_editbuf   db MAX_ENTRY_BYTES dup (?)     ; scratch copy of an entry for `edit`
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

; ===========================================================================
; vault_seal_write() - seal g_body (g_body_len bytes) under g_vkey with a fresh
;   nonce already placed in g_hdr, build the file image, write it to g_cfg_in.
;   -> eax = 0 / EXIT_IO / EXIT_OOM.
; ===========================================================================
vault_seal_write proc frame
    FRAME_PROLOG 48
    ; [rbp-32] = attachment section bytes (entries + trailer)
    xor     ecx, ecx                            ; emit=0: size the attachment section
    xor     edx, edx
    call    attach_build
    mov     qword ptr [rbp-32], rax
    ; total = VH_TOTAL + body_len + 16 + attachment section
    mov     rax, qword ptr [g_body_len]
    add     rax, VH_TOTAL + 16
    add     rax, qword ptr [rbp-32]
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
    ; write the image to the temp file
    lea     rcx, [g_tmppath]
    mov     rdx, qword ptr [g_outbuf]
    mov     r8, qword ptr [g_outlen]
    call    write_file
    test    eax, eax
    jnz     vsw_io
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
    cmp     dword ptr [g_use_tpm], 0
    je      vu_pwderive
    call    vk_derive_tpm
    test    eax, eax
    jnz     vu_locked                   ; no/failed TPM -> GUI falls back to pw
    jmp     vu_havekey
vu_pwderive:
    call    vk_derive
    test    eax, eax
    jnz     vu_oom
vu_havekey:
    call    vk_kcv
    lea     rcx, [g_sha32]
    mov     r10, qword ptr [g_filebuf]
    lea     rdx, [r10+VH_KCV]
    mov     r8, KCV_LEN
    call    ct_memcmp
    test    eax, eax
    jnz     vu_locked
    ; detect the attachments trailer at the end of the file (absent = old format)
    mov     qword ptr [g_att_total], 0
    mov     rax, qword ptr [g_filesize]
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
    ; body ciphertext length = filesize - 80 - 16 - (att_total + trailer)
    mov     rax, qword ptr [g_filesize]
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
    ; keep the file image resident: attachment ciphertext lives in it.  Build the
    ; id->ciphertext index from the attachments section.
    call    attach_index_build
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
    FRAME_EPILOG
    ret
vault_lock endp

; ===========================================================================
; va_field(rcx = type, rdx = wideZ value) -> eax = 1 if a field was appended,
;   0 if the value pointer was NULL/empty.  Fastfails on body overflow.
;   Appends { u16 type, u32 len, utf8 bytes } at g_body[g_body_len].
; ===========================================================================
va_field proc frame
    FRAME_PROLOG 48
    ; [rbp-24]=type [rbp-32]=len
    test    rdx, rdx
    jz      vf_skip
    mov     qword ptr [rbp-24], rcx
    mov     rcx, rdx
    lea     rdx, [g_conv]
    mov     r8d, CONV_CAP
    call    conv_w2u
    test    eax, eax
    jz      vf_skip
    mov     ecx, eax
    mov     qword ptr [rbp-32], rcx     ; len (zero-extended)
    ; bounds: g_body_len + 6 + len <= VAULT_BODY_MAX
    mov     r10, qword ptr [g_body_len]
    add     r10, 6
    add     r10, qword ptr [rbp-32]
    cmp     r10, VAULT_BODY_MAX
    ja      vf_overflow
    ; write header
    mov     r11, qword ptr [g_body_ptr]
    add     r11, qword ptr [g_body_len]
    mov     rax, qword ptr [rbp-24]
    mov     word ptr [r11], ax
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [r11+2], eax
    ; copy bytes
    add     r11, 6
    lea     r9, [g_conv]
    xor     r8, r8
vf_copy:
    cmp     r8, qword ptr [rbp-32]
    jae     vf_copydone
    mov     al, byte ptr [r9+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    jmp     vf_copy
vf_copydone:
    mov     rax, qword ptr [g_body_len]
    add     rax, 6
    add     rax, qword ptr [rbp-32]
    mov     qword ptr [g_body_len], rax
    mov     eax, 1
    FRAME_EPILOG
    ret
vf_skip:
    xor     eax, eax
    FRAME_EPILOG
    ret
vf_overflow:
    FASTFAIL FF_BOUNDS
va_field endp

; ===========================================================================
; do_init - create a new empty vault at g_cfg_in.
; ===========================================================================
public do_init
do_init proc frame
    FRAME_PROLOG 48
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
; do_add - unlock, append one entry from --title/--user/--secret/--url/--notes,
;   reseal + write.
; ===========================================================================
public do_add
do_add proc frame
    FRAME_PROLOG 64
    ; locals: [rbp-24]=result [rbp-32]=entry start [rbp-40]=field count
    ; require a title
    cmp     qword ptr [g_cfg_title], 0
    je      da_notitle
    call    vault_unlock
    test    eax, eax
    jnz     da_unlockerr
    ; --- append entry header: id(16) created(8) modified(8) fcount(4) ---
    mov     rax, qword ptr [g_body_len]
    add     rax, 36
    cmp     rax, VAULT_BODY_MAX
    ja      da_full
    mov     r11, qword ptr [g_body_ptr]
    add     r11, qword ptr [g_body_len]     ; entry start
    mov     qword ptr [rbp-32], r11         ; remember for fcount patch
    ; id = 16 random bytes
    mov     rcx, r11
    mov     edx, 16
    call    rng_fill
    test    eax, eax
    jz      da_oom
    ; timestamps
    lea     rcx, [g_ts]
    call    GetSystemTimeAsFileTime
    mov     r11, qword ptr [rbp-32]
    mov     rax, qword ptr [g_ts]
    mov     qword ptr [r11+16], rax         ; created
    mov     qword ptr [r11+24], rax         ; modified
    mov     dword ptr [r11+32], 0           ; field_count placeholder
    ; advance body_len past the 36-byte entry header
    mov     rax, qword ptr [g_body_len]
    add     rax, 36
    mov     qword ptr [g_body_len], rax
    ; --- append fields, counting ---
    mov     dword ptr [rbp-40], 0           ; field count
    mov     ecx, VF_TITLE
    mov     rdx, qword ptr [g_cfg_title]
    call    va_field
    add     dword ptr [rbp-40], eax
    mov     ecx, VF_USERNAME
    mov     rdx, qword ptr [g_cfg_user]
    call    va_field
    add     dword ptr [rbp-40], eax
    mov     ecx, VF_SECRET
    mov     rdx, qword ptr [g_cfg_secret]
    call    va_field
    add     dword ptr [rbp-40], eax
    mov     ecx, VF_URL
    mov     rdx, qword ptr [g_cfg_url]
    call    va_field
    add     dword ptr [rbp-40], eax
    mov     ecx, VF_NOTES
    mov     rdx, qword ptr [g_cfg_notes]
    call    va_field
    add     dword ptr [rbp-40], eax
    ; patch field_count and bump entry_count
    mov     r11, qword ptr [rbp-32]
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r11+32], eax
    mov     r11, qword ptr [g_body_ptr]
    inc     dword ptr [r11]                 ; entry_count++
    ; reseal with a fresh nonce
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      da_oom
    call    vault_seal_write
    mov     qword ptr [rbp-24], rax
    call    vault_lock
    mov     eax, dword ptr [rbp-24]
    test    eax, eax
    jnz     da_io
    lea     rcx, [m_added]
    mov     edx, m_added_len
    call    print_a
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
da_full:
    call    vault_lock
    lea     rcx, [e_full]
    mov     edx, e_full_len
    call    print_err
    mov     eax, EXIT_NOSPACE
    FRAME_EPILOG
    ret
da_oom:
    call    vault_lock
    lea     rcx, [e_oom]
    mov     edx, e_oom_len
    call    print_err
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
da_io:
    lea     rcx, [e_io]
    mov     edx, e_io_len
    call    print_err
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
da_notitle:
    lea     rcx, [e_notitle]
    mov     edx, e_notitle_len
    call    print_err
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
da_unlockerr:
    mov     qword ptr [rbp-24], rax
    call    vault_lock
    mov     ecx, dword ptr [rbp-24]
    call    vault_print_err
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
do_add endp

; vault_print_err(ecx = exit code) - print the matching message to stderr.
vault_print_err proc frame
    FRAME_PROLOG 32
    cmp     ecx, EXIT_IO
    jne     vpe_1
    lea     rcx, [e_io]
    mov     edx, e_io_len
    jmp     vpe_out
vpe_1:
    cmp     ecx, EXIT_CORRUPT
    jne     vpe_2
    lea     rcx, [e_corrupt]
    mov     edx, e_corrupt_len
    jmp     vpe_out
vpe_2:
    cmp     ecx, EXIT_LOCKED
    jne     vpe_3
    lea     rcx, [e_locked]
    mov     edx, e_locked_len
    jmp     vpe_out
vpe_3:
    cmp     ecx, EXIT_AUTH
    jne     vpe_4
    lea     rcx, [e_auth]
    mov     edx, e_auth_len
    jmp     vpe_out
vpe_4:
    lea     rcx, [e_oom]
    mov     edx, e_oom_len
vpe_out:
    call    print_err
    FRAME_EPILOG
    ret
vault_print_err endp

; ===========================================================================
; do_list - unlock and print every entry's title.
; ===========================================================================
public do_list
do_list proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=cursor [rbp-32]=entries left [rbp-40]=fields left [rbp-48]=value len
    call    vault_unlock
    test    eax, eax
    jnz     dl_err
    mov     r10, qword ptr [g_body_ptr]
    mov     eax, dword ptr [r10]            ; entry_count
    mov     qword ptr [rbp-32], rax
    test    eax, eax
    jz      dl_empty
    lea     r10, [r10+4]                    ; cursor past entry_count
    mov     qword ptr [rbp-24], r10
dl_entry:
    cmp     qword ptr [rbp-32], 0
    je      dl_done
    ; skip id(16)+created(8)+modified(8); read field_count
    mov     r10, qword ptr [rbp-24]
    add     r10, 32
    mov     eax, dword ptr [r10]
    mov     qword ptr [rbp-40], rax
    add     r10, 4
    mov     qword ptr [rbp-24], r10
dl_field:
    cmp     qword ptr [rbp-40], 0
    je      dl_nextentry
    mov     r10, qword ptr [rbp-24]
    movzx   eax, word ptr [r10]             ; type
    mov     r8d, dword ptr [r10+2]          ; len
    mov     qword ptr [rbp-48], r8          ; remember len
    add     r10, 6                          ; cursor -> value
    mov     qword ptr [rbp-24], r10
    cmp     eax, VF_TITLE
    jne     dl_skip
    mov     rcx, r10
    mov     edx, r8d
    call    print_a
    lea     rcx, [nlcrlf]
    mov     edx, 2
    call    print_a
dl_skip:
    mov     r10, qword ptr [rbp-24]
    add     r10, qword ptr [rbp-48]         ; skip value bytes
    mov     qword ptr [rbp-24], r10
    dec     qword ptr [rbp-40]
    jmp     dl_field
dl_nextentry:
    dec     qword ptr [rbp-32]
    jmp     dl_entry
dl_empty:
    lea     rcx, [m_empty]
    mov     edx, m_empty_len
    call    print_a
dl_done:
    call    vault_lock
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
dl_err:
    mov     qword ptr [rbp-24], rax
    mov     ecx, eax
    call    vault_print_err
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
do_list endp

; vault_memeq(rcx = a, rdx = b, r8 = len) -> eax = 1 if equal, else 0.  Leaf.
vault_memeq proc
    xor     r9, r9
vm_loop:
    cmp     r9, r8
    jae     vm_eq
    mov     al, byte ptr [rcx+r9]
    cmp     al, byte ptr [rdx+r9]
    jne     vm_ne
    inc     r9
    jmp     vm_loop
vm_eq:
    mov     eax, 1
    ret
vm_ne:
    xor     eax, eax
    ret
vault_memeq endp

; ===========================================================================
; do_get - unlock, find the FIRST entry whose title equals --title, print it.
; Per entry: pass 1 locates+compares the title field; pass 2 prints all fields.
; ===========================================================================
public do_get
do_get proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=between-entry cursor [rbp-32]=entries left [rbp-40]=field cursor
    ; [rbp-48]=fields left [rbp-56]=entry start [rbp-64]=field_count
    ; [rbp-72]=found [rbp-80]=value len
    cmp     qword ptr [g_cfg_title], 0
    je      dg_noopt
    mov     rcx, qword ptr [g_cfg_title]
    lea     rdx, [g_match]
    mov     r8d, CONV_CAP
    call    conv_w2u
    mov     qword ptr [g_matchlen], rax
    call    vault_unlock
    test    eax, eax
    jnz     dg_err
    mov     r10, qword ptr [g_body_ptr]
    mov     eax, dword ptr [r10]
    mov     qword ptr [rbp-32], rax
    lea     r10, [r10+4]
    mov     qword ptr [rbp-24], r10
    mov     dword ptr [rbp-72], 0
dg_entry:
    cmp     qword ptr [rbp-32], 0
    je      dg_done
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [rbp-56], r10         ; entry start
    add     r10, 32
    mov     eax, dword ptr [r10]
    mov     qword ptr [rbp-64], rax         ; field_count
    add     r10, 4                          ; ffirst
    ; ---- pass 1: find + compare the title field ----------------------------
    mov     qword ptr [rbp-40], r10
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [rbp-48], rax
dg_p1:
    cmp     qword ptr [rbp-48], 0
    je      dg_advance
    mov     r10, qword ptr [rbp-40]
    movzx   eax, word ptr [r10]             ; type
    mov     r8d, dword ptr [r10+2]          ; len
    cmp     eax, VF_TITLE
    jne     dg_p1_skip
    mov     rax, qword ptr [g_matchlen]
    cmp     rax, r8
    jne     dg_p1_skip
    lea     rcx, [r10+6]                    ; value ptr
    lea     rdx, [g_match]
    call    vault_memeq                     ; r8 = len still valid
    test    eax, eax
    jnz     dg_found
dg_p1_skip:
    mov     r10, qword ptr [rbp-40]
    mov     r8d, dword ptr [r10+2]
    add     r10, 6
    add     r10, r8
    mov     qword ptr [rbp-40], r10
    dec     qword ptr [rbp-48]
    jmp     dg_p1
dg_found:
    mov     dword ptr [rbp-72], 1
    ; ---- pass 2: print every field of this entry ---------------------------
    mov     r10, qword ptr [rbp-56]
    add     r10, 36                         ; ffirst
    mov     qword ptr [rbp-40], r10
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [rbp-48], rax
dg_p2:
    cmp     qword ptr [rbp-48], 0
    je      dg_done
    mov     r10, qword ptr [rbp-40]
    movzx   ecx, word ptr [r10]             ; type -> ecx (survives FRAME_PROLOG)
    mov     r8d, dword ptr [r10+2]          ; len
    mov     qword ptr [rbp-80], r8
    add     r10, 6
    mov     qword ptr [rbp-40], r10         ; value ptr
    call    print_label                     ; ecx = type
    mov     rcx, qword ptr [rbp-40]
    mov     edx, dword ptr [rbp-80]
    call    print_a
    lea     rcx, [nlcrlf]
    mov     edx, 2
    call    print_a
    mov     r10, qword ptr [rbp-40]
    add     r10, qword ptr [rbp-80]
    mov     qword ptr [rbp-40], r10
    dec     qword ptr [rbp-48]
    jmp     dg_p2
dg_advance:
    ; walk all fields from ffirst to reach the next entry
    mov     r10, qword ptr [rbp-56]
    add     r10, 32
    mov     ecx, dword ptr [r10]
    add     r10, 4
dg_walk:
    test    ecx, ecx
    jz      dg_walkdone
    mov     r8d, dword ptr [r10+2]
    add     r10, 6
    add     r10, r8
    dec     ecx
    jmp     dg_walk
dg_walkdone:
    mov     qword ptr [rbp-24], r10
    dec     qword ptr [rbp-32]
    jmp     dg_entry
dg_done:
    call    vault_lock
    cmp     dword ptr [rbp-72], 0
    jne     dg_ok
    lea     rcx, [e_notfound]
    mov     edx, e_notfound_len
    call    print_a
dg_ok:
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
dg_noopt:
    lea     rcx, [e_noopt]
    mov     edx, e_noopt_len
    call    print_err
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
dg_err:
    mov     qword ptr [rbp-24], rax
    mov     ecx, eax
    call    vault_print_err
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
do_get endp

; print_label(ecx = field type) - print "  <name>: " for the value that follows.
print_label proc frame
    FRAME_PROLOG 32
    cmp     ecx, VF_TITLE
    jne     pl_u
    lea     rcx, [lbl_title]
    mov     edx, lbl_title_n
    jmp     pl_out
pl_u:
    cmp     ecx, VF_USERNAME
    jne     pl_s
    lea     rcx, [lbl_user]
    mov     edx, lbl_user_n
    jmp     pl_out
pl_s:
    cmp     ecx, VF_SECRET
    jne     pl_r
    lea     rcx, [lbl_secret]
    mov     edx, lbl_secret_n
    jmp     pl_out
pl_r:
    cmp     ecx, VF_URL
    jne     pl_n
    lea     rcx, [lbl_url]
    mov     edx, lbl_url_n
    jmp     pl_out
pl_n:
    lea     rcx, [lbl_notes]
    mov     edx, lbl_notes_n
pl_out:
    call    print_a
    FRAME_EPILOG
    ret
print_label endp

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
; vault_find(rcx = match utf8 ptr, rdx = match len) -> rax = entry start ptr
;   (0 if not found), rdx = entry length.  Matches on the TITLE field.
; ===========================================================================
vault_find proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=match [rbp-32]=matchlen [rbp-40]=entry cursor [rbp-48]=entries
    ; [rbp-56]=field cursor [rbp-64]=fields left
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     r10, qword ptr [g_body_ptr]
    mov     eax, dword ptr [r10]
    mov     qword ptr [rbp-48], rax
    lea     r10, [r10+4]
    mov     qword ptr [rbp-40], r10
vfn_entry:
    cmp     qword ptr [rbp-48], 0
    je      vfn_none
    mov     r10, qword ptr [rbp-40]
    add     r10, 32
    mov     eax, dword ptr [r10]
    mov     qword ptr [rbp-64], rax
    add     r10, 4
    mov     qword ptr [rbp-56], r10
vfn_fl:
    cmp     qword ptr [rbp-64], 0
    je      vfn_nextentry
    mov     r10, qword ptr [rbp-56]
    movzx   eax, word ptr [r10]
    mov     r8d, dword ptr [r10+2]
    cmp     eax, VF_TITLE
    jne     vfn_skip
    mov     rax, qword ptr [rbp-32]
    cmp     rax, r8
    jne     vfn_skip
    lea     rcx, [r10+6]
    mov     rdx, qword ptr [rbp-24]
    call    vault_memeq                     ; r8 = len
    test    eax, eax
    jnz     vfn_found
vfn_skip:
    mov     r10, qword ptr [rbp-56]
    mov     r8d, dword ptr [r10+2]
    add     r10, 6
    add     r10, r8
    mov     qword ptr [rbp-56], r10
    dec     qword ptr [rbp-64]
    jmp     vfn_fl
vfn_nextentry:
    mov     rcx, qword ptr [rbp-40]
    call    vault_entry_len
    add     qword ptr [rbp-40], rax
    dec     qword ptr [rbp-48]
    jmp     vfn_entry
vfn_found:
    mov     rcx, qword ptr [rbp-40]
    call    vault_entry_len
    mov     rdx, rax
    mov     rax, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
vfn_none:
    xor     eax, eax
    xor     edx, edx
    FRAME_EPILOG
    ret
vault_find endp

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
; edit_field(rcx = type, rdx = override wide ptr) -> eax = field-count delta.
;   If an override is supplied, append it (via va_field, wide->utf8); else keep
;   the existing value from g_editbuf (via va_field_raw).
; ===========================================================================
edit_field proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx         ; type
    mov     qword ptr [rbp-32], rdx         ; override
    test    rdx, rdx
    jz      ef_keep
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    va_field                        ; eax = 0/1
    FRAME_EPILOG
    ret
ef_keep:
    lea     rcx, [g_editbuf]
    mov     edx, dword ptr [rbp-24]
    call    find_field_in                   ; rax=ptr, rdx=len
    test    rax, rax
    jz      ef_none
    mov     r8, rdx
    mov     rdx, rax
    mov     rcx, qword ptr [rbp-24]
    call    va_field_raw
    mov     eax, 1
    FRAME_EPILOG
    ret
ef_none:
    xor     eax, eax
    FRAME_EPILOG
    ret
edit_field endp

; ===========================================================================
; do_remove - unlock, delete the entry whose title matches --title, reseal.
; ===========================================================================
public do_remove
do_remove proc frame
    FRAME_PROLOG 80
    ; [rbp-24]=result [rbp-32]=entry start [rbp-40]=entry len
    cmp     qword ptr [g_cfg_title], 0
    je      dr_noopt
    mov     rcx, qword ptr [g_cfg_title]
    lea     rdx, [g_match]
    mov     r8d, CONV_CAP
    call    conv_w2u
    mov     qword ptr [g_matchlen], rax
    call    vault_unlock
    test    eax, eax
    jnz     dr_err
    lea     rcx, [g_match]
    mov     rdx, qword ptr [g_matchlen]
    call    vault_find
    test    rax, rax
    jz      dr_notfound
    mov     qword ptr [rbp-32], rax
    mov     qword ptr [rbp-40], rdx
    ; memmove the tail over [start, start+len)
    mov     r10, qword ptr [g_body_ptr]
    add     r10, qword ptr [g_body_len]     ; body end
    mov     r11, qword ptr [rbp-32]
    add     r11, qword ptr [rbp-40]         ; src = start+len
    sub     r10, r11                        ; n = bytes to move
    mov     rcx, qword ptr [rbp-32]         ; dst = start
    xor     r8, r8
dr_mv:
    cmp     r8, r10
    jae     dr_mvdone
    mov     al, byte ptr [r11+r8]
    mov     byte ptr [rcx+r8], al
    inc     r8
    jmp     dr_mv
dr_mvdone:
    mov     rax, qword ptr [g_body_len]
    sub     rax, qword ptr [rbp-40]
    mov     qword ptr [g_body_len], rax
    mov     r11, qword ptr [g_body_ptr]
    dec     dword ptr [r11]                 ; entry_count--
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      dr_oom
    call    vault_seal_write
    mov     dword ptr [rbp-24], eax
    call    vault_lock
    mov     eax, dword ptr [rbp-24]
    test    eax, eax
    jnz     dr_io
    lea     rcx, [m_removed]
    mov     edx, m_removed_len
    call    print_a
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
dr_notfound:
    call    vault_lock
    lea     rcx, [e_notfound]
    mov     edx, e_notfound_len
    call    print_a
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
dr_noopt:
    lea     rcx, [e_noopt]
    mov     edx, e_noopt_len
    call    print_err
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
dr_io:
    lea     rcx, [e_io]
    mov     edx, e_io_len
    call    print_err
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
dr_oom:
    call    vault_lock
    lea     rcx, [e_oom]
    mov     edx, e_oom_len
    call    print_err
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
dr_err:
    mov     dword ptr [rbp-24], eax
    mov     ecx, eax
    call    vault_print_err
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
do_remove endp

; ===========================================================================
; do_edit - unlock, replace the matching entry's fields (provided overrides
; win; unspecified fields keep their existing value), reseal.  Title selects
; the entry and is preserved; id/created carry over, modified is refreshed.
; ===========================================================================
public do_edit
do_edit proc frame
    FRAME_PROLOG 128
    ; [rbp-24]=result [rbp-32]=old start [rbp-40]=old len
    ; [rbp-48]=new entry start [rbp-56]=field count
    cmp     qword ptr [g_cfg_title], 0
    je      de_noopt
    mov     rcx, qword ptr [g_cfg_title]
    lea     rdx, [g_match]
    mov     r8d, CONV_CAP
    call    conv_w2u
    mov     qword ptr [g_matchlen], rax
    call    vault_unlock
    test    eax, eax
    jnz     de_err
    lea     rcx, [g_match]
    mov     rdx, qword ptr [g_matchlen]
    call    vault_find
    test    rax, rax
    jz      de_notfound
    mov     qword ptr [rbp-32], rax
    mov     qword ptr [rbp-40], rdx
    cmp     rdx, MAX_ENTRY_BYTES
    ja      de_corrupt
    ; copy old entry -> g_editbuf
    mov     r9, rax
    lea     r11, [g_editbuf]
    xor     r8, r8
de_cp:
    cmp     r8, qword ptr [rbp-40]
    jae     de_cpdone
    mov     al, byte ptr [r9+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    jmp     de_cp
de_cpdone:
    ; remove old entry from the body (memmove tail down)
    mov     r10, qword ptr [g_body_ptr]
    add     r10, qword ptr [g_body_len]
    mov     r11, qword ptr [rbp-32]
    add     r11, qword ptr [rbp-40]
    sub     r10, r11
    mov     rcx, qword ptr [rbp-32]
    xor     r8, r8
de_mv:
    cmp     r8, r10
    jae     de_mvdone
    mov     al, byte ptr [r11+r8]
    mov     byte ptr [rcx+r8], al
    inc     r8
    jmp     de_mv
de_mvdone:
    mov     rax, qword ptr [g_body_len]
    sub     rax, qword ptr [rbp-40]
    mov     qword ptr [g_body_len], rax
    mov     r11, qword ptr [g_body_ptr]
    dec     dword ptr [r11]
    ; --- append the rebuilt entry at the new end ---
    mov     r11, qword ptr [g_body_ptr]
    add     r11, qword ptr [g_body_len]
    mov     qword ptr [rbp-48], r11
    mov     rax, qword ptr [g_body_len]
    add     rax, 36
    cmp     rax, VAULT_BODY_MAX
    ja      de_full
    ; id (16) + created (8) carried over from g_editbuf
    lea     r10, [g_editbuf]
    xor     r8, r8
de_idcpy:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    cmp     r8, 16
    jb      de_idcpy
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [r11+16], rax         ; created
    ; modified = now
    lea     rcx, [g_ts]
    call    GetSystemTimeAsFileTime
    mov     r11, qword ptr [rbp-48]
    mov     rax, qword ptr [g_ts]
    mov     qword ptr [r11+24], rax
    mov     dword ptr [r11+32], 0           ; field_count placeholder
    mov     rax, qword ptr [g_body_len]
    add     rax, 36
    mov     qword ptr [g_body_len], rax
    ; merge fields (title kept; others: override else existing)
    mov     dword ptr [rbp-56], 0
    mov     ecx, VF_TITLE
    xor     edx, edx
    call    edit_field
    add     dword ptr [rbp-56], eax
    mov     ecx, VF_USERNAME
    mov     rdx, qword ptr [g_cfg_user]
    call    edit_field
    add     dword ptr [rbp-56], eax
    mov     ecx, VF_SECRET
    mov     rdx, qword ptr [g_cfg_secret]
    call    edit_field
    add     dword ptr [rbp-56], eax
    mov     ecx, VF_URL
    mov     rdx, qword ptr [g_cfg_url]
    call    edit_field
    add     dword ptr [rbp-56], eax
    mov     ecx, VF_NOTES
    mov     rdx, qword ptr [g_cfg_notes]
    call    edit_field
    add     dword ptr [rbp-56], eax
    ; patch field_count and bump entry_count
    mov     r11, qword ptr [rbp-48]
    mov     eax, dword ptr [rbp-56]
    mov     dword ptr [r11+32], eax
    mov     r11, qword ptr [g_body_ptr]
    inc     dword ptr [r11]
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      de_oom
    call    vault_seal_write
    mov     dword ptr [rbp-24], eax
    call    vault_lock
    mov     eax, dword ptr [rbp-24]
    test    eax, eax
    jnz     de_io
    lea     rcx, [m_updated]
    mov     edx, m_updated_len
    call    print_a
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
de_notfound:
    call    vault_lock
    lea     rcx, [e_notfound]
    mov     edx, e_notfound_len
    call    print_a
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
de_noopt:
    lea     rcx, [e_noopt]
    mov     edx, e_noopt_len
    call    print_err
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
de_full:
    call    vault_lock
    lea     rcx, [e_full]
    mov     edx, e_full_len
    call    print_err
    mov     eax, EXIT_NOSPACE
    FRAME_EPILOG
    ret
de_corrupt:
    call    vault_lock
    mov     ecx, EXIT_CORRUPT
    call    vault_print_err
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
de_io:
    lea     rcx, [e_io]
    mov     edx, e_io_len
    call    print_err
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
de_oom:
    call    vault_lock
    lea     rcx, [e_oom]
    mov     edx, e_oom_len
    call    print_err
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
de_err:
    mov     dword ptr [rbp-24], eax
    mov     ecx, eax
    call    vault_print_err
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
do_edit endp

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

; vault_reseal() - persist the current in-memory body to disk under a fresh
;   GCM nonce (key/salt unchanged).  -> eax = 0 / EXIT_IO / EXIT_OOM.
public vault_reseal
vault_reseal proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_hdr+VH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      vrs_oom
    call    vault_seal_write
    FRAME_EPILOG
    ret
vrs_oom:
    mov     eax, EXIT_OOM
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

; vault_add_entry() - append one entry to the in-memory body from the
;   g_cfg_title/user/secret/url/notes wide pointers (set by the GUI).  Does NOT
;   reseal.  -> eax = 0 ok / EXIT_NOSPACE if full / EXIT_USAGE if no title.
public vault_add_entry
vault_add_entry proc frame
    FRAME_PROLOG 64
    ; [rbp-32] = entry start, [rbp-40] = field count
    cmp     qword ptr [g_cfg_title], 0
    je      vae_fail
    mov     rax, qword ptr [g_body_len]
    add     rax, 36
    cmp     rax, VAULT_BODY_MAX
    ja      vae_full
    mov     r11, qword ptr [g_body_ptr]
    add     r11, qword ptr [g_body_len]
    mov     qword ptr [rbp-32], r11
    mov     rcx, r11
    mov     edx, 16
    call    rng_fill                    ; id = 16 random bytes
    test    eax, eax
    jz      vae_fail
    lea     rcx, [g_ts]
    call    GetSystemTimeAsFileTime
    mov     r11, qword ptr [rbp-32]
    mov     rax, qword ptr [g_ts]
    mov     qword ptr [r11+16], rax     ; created
    mov     qword ptr [r11+24], rax     ; modified
    mov     dword ptr [r11+32], 0       ; field_count placeholder
    mov     rax, qword ptr [g_body_len]
    add     rax, 36
    mov     qword ptr [g_body_len], rax
    mov     dword ptr [rbp-40], 0
    mov     ecx, VF_TITLE
    mov     rdx, qword ptr [g_cfg_title]
    call    va_field
    add     dword ptr [rbp-40], eax
    mov     ecx, VF_USERNAME
    mov     rdx, qword ptr [g_cfg_user]
    call    va_field
    add     dword ptr [rbp-40], eax
    mov     ecx, VF_SECRET
    mov     rdx, qword ptr [g_cfg_secret]
    call    va_field
    add     dword ptr [rbp-40], eax
    mov     ecx, VF_URL
    mov     rdx, qword ptr [g_cfg_url]
    call    va_field
    add     dword ptr [rbp-40], eax
    mov     ecx, VF_NOTES
    mov     rdx, qword ptr [g_cfg_notes]
    call    va_field
    add     dword ptr [rbp-40], eax
    mov     ecx, VF_TOTP
    mov     rdx, qword ptr [g_cfg_totp]
    call    va_field
    add     dword ptr [rbp-40], eax
    mov     r11, qword ptr [rbp-32]
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r11+32], eax
    mov     r11, qword ptr [g_body_ptr]
    inc     dword ptr [r11]             ; entry_count++
    xor     eax, eax
    FRAME_EPILOG
    ret
vae_full:
    mov     eax, EXIT_NOSPACE
    FRAME_EPILOG
    ret
vae_fail:
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
vault_add_entry endp

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
    mov     rcx, r10
    mov     rdx, qword ptr [rbp-40]             ; ref id (ARF_ID=0)
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
    mov     rax, qword ptr [g_body_len]
    add     rax, VH_TOTAL + 16
    mov     qword ptr [g_att_start], rax        ; att_start = 80 + bodyct + 16
    mov     qword ptr [g_att_total], 0
    mov     rax, qword ptr [g_att_start]
    add     rax, ATT_TRAILER
    cmp     rax, qword ptr [g_filesize]
    ja      ars_build
    mov     r11, qword ptr [g_filebuf]
    add     r11, qword ptr [g_filesize]
    sub     r11, ATT_TRAILER
    cmp     dword ptr [r11], ATT_MAGIC
    jne     ars_build
    mov     r9, qword ptr [r11+4]               ; entries_len
    mov     rax, qword ptr [g_att_start]
    add     rax, r9
    add     rax, ATT_TRAILER
    cmp     rax, qword ptr [g_filesize]
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
