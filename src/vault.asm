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
VAULT_BODY_MAX  equ 1048576     ; 1 MiB plaintext cap
CONV_CAP        equ 16384

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
g_conv      db CONV_CAP dup (?)
g_match     db CONV_CAP dup (?)
align 2
g_tmppath   dw MAX_PATH_CHARS dup (?)        ; "<vault>.tmp" for atomic replace
g_matchlen  dq ?
g_ts        dq ?                ; GetSystemTimeAsFileTime scratch
vst_ct      db 16 dup (?)
vst_dec     db 16 dup (?)
vst_tag     db 16 dup (?)
g_editbuf   db MAX_ENTRY_BYTES dup (?)     ; scratch copy of an entry for `edit`

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
    ; total = VH_TOTAL + body_len + 16
    mov     rax, qword ptr [g_body_len]
    add     rax, VH_TOTAL + 16
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
    jmp     vsw_free
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
    ; derive key + KCV check
    call    vk_derive
    test    eax, eax
    jnz     vu_oom
    call    vk_kcv
    lea     rcx, [g_sha32]
    mov     r10, qword ptr [g_filebuf]
    lea     rdx, [r10+VH_KCV]
    mov     r8, KCV_LEN
    call    ct_memcmp
    test    eax, eax
    jnz     vu_locked
    ; ciphertext length = filesize - 80 - 16
    mov     rax, qword ptr [g_filesize]
    sub     rax, VH_TOTAL + 16
    mov     qword ptr [rbp-24], rax
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
    ; free the (non-secret) ciphertext buffer
    mov     rcx, qword ptr [g_filebuf]
    mov     rdx, qword ptr [g_filesize]
    call    mem_free
    mov     qword ptr [g_filebuf], 0
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
    movzx   eax, word ptr [r10]
    mov     r9d, dword ptr [r10+2]
    cmp     eax, edx
    jne     ffi_skip
    lea     rax, [r10+6]
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
    xor     eax, eax
    FRAME_EPILOG
    ret
vst_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
vault_selftest endp

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

end
