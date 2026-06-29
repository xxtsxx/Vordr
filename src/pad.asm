; =============================================================================
; pad.asm - file-backed one-time-pad management and OTP secret sharing
; -----------------------------------------------------------------------------
; A .vpad holds pre-shared random pad material that two parties each possess
; (the plaintext pad is exchanged once over a secure out-of-band channel).  The
; file is encrypted at rest under a pad password (Argon2id -> KCV -> AES-256-GCM,
; same discipline as the vault).  A local consumed-offset high-water mark in the
; header guarantees no pad region is ever reused - the single invariant on which
; OTP security rests, so it is persisted BEFORE any share is emitted.
;
; Pad file layout (offsets; the first 80 bytes match VAULT_HDR+KCV):
;   0  magic "VPAD" | 4 version | 8 t | 12 m_kib | 16 lanes | 20 salt(32)
;   52 nonce(12) | 64 KCV(16) | 80 pad_id(16) | 96 total_len(8)
;   104 consumed_offset(8) | 112 source(4) | [116 = AAD len]
;   116 AES-256-GCM( pad bytes )[total_len] | tag(16)
;
; Share file (.vshare) layout:
;   0 magic "VOTP" | 4 version | 8 pad_id(16) | 24 pad_offset(8)
;   32 msg_len(8) | [40 = header] | 40 ciphertext[msg_len] | one-time MAC(16)
;
; Commands: do_padnew / do_padimport / do_share / do_open (-> exit code in eax).
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
extern otp_share_seal:proc
extern otp_share_open:proc

externdef g_cfg_in:qword
externdef g_cfg_out:qword
externdef g_cfg_pass:byte
externdef g_cfg_passlen:dword
externdef g_cfg_t:dword
externdef g_cfg_m:dword
externdef g_cfg_size:dword
externdef g_cfg_from:qword
externdef g_cfg_share:qword
externdef g_cfg_secret:qword

CP_UTF8         equ 65001

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

; pad header byte offsets
PH_T            equ 8
PH_M            equ 12
PH_LANES        equ 16
PH_SALT         equ 20
PH_NONCE        equ 52
PH_KCV          equ 64
PH_ID           equ 80
PH_TOTLEN       equ 96
PH_CONSUMED     equ 104
PH_SOURCE       equ 112
PH_AAD          equ 116          ; header length (= GCM AAD)
; share header byte offsets
SH_ID           equ 8
SH_OFFSET       equ 24
SH_MSGLEN       equ 32
SH_HDR          equ 40
PAD_MAX         equ 4194304      ; 4 MiB pad cap
CONV_CAP        equ 16384

.const
nlp         db 13,10
CSTR pe_io,      "error: cannot read/write the file",13,10
CSTR pe_corrupt, "error: not a Vordr pad/share (bad magic) or corrupt",13,10
CSTR pe_locked,  "error: wrong pad password (key-check failed)",13,10
CSTR pe_auth,    "error: authentication failed (tampered or corrupt)",13,10
CSTR pe_oom,     "error: out of memory",13,10
CSTR pe_size,    "error: padnew needs --size N (1..4194304 bytes)",13,10
CSTR pe_from,    "error: padimport needs --from RAWFILE",13,10
CSTR pe_shareopt,"error: share needs --secret S and -o SHAREFILE",13,10
CSTR pe_openopt, "error: open needs --share SHAREFILE",13,10
CSTR pe_exhaust, "error: pad exhausted - not enough unused material left",13,10
CSTR pe_padid,   "error: this share was not made for this pad",13,10
CSTR pm_padnew,  "pad created.",13,10
CSTR pm_import,  "pad imported.",13,10
CSTR pm_shared,  "share written.",13,10

.data?
align 16
p_vkey      db 32 dup (?)
p_sha32     db 32 dup (?)
g_phdr      db PH_AAD dup (?)
align 8
p_areq      ARGON2REQ <>
p_greq      GCMREQ <>
p_pad_ptr   dq ?
p_pad_total dq ?
p_filebuf   dq ?
p_filesize  dq ?
p_outbuf    dq ?
p_outlen    dq ?
p_sharebuf  dq ?
p_sharesize dq ?
p_ptout     dq ?
p_ptout_len dq ?
p_msgbuf    db CONV_CAP dup (?)
align 2
p_tmppath   dw MAX_PATH_CHARS dup (?)

.code

; ---------------------------------------------------------------------------
; pk_derive() - Argon2id(pad pw, g_phdr salt/t/m, p=1) -> p_vkey. eax=0/EXIT_OOM
; ---------------------------------------------------------------------------
pk_derive proc frame
    FRAME_PROLOG 32
    lea     r10, [p_areq]
    mov     eax, dword ptr [g_phdr+PH_T]
    mov     dword ptr [r10].ARGON2REQ.t_cost, eax
    mov     eax, dword ptr [g_phdr+PH_M]
    mov     dword ptr [r10].ARGON2REQ.m_cost, eax
    mov     dword ptr [r10].ARGON2REQ.lanes, 1
    mov     dword ptr [r10].ARGON2REQ.outlen, 32
    mov     dword ptr [r10].ARGON2REQ.version, 19
    mov     dword ptr [r10].ARGON2REQ.atype, 2
    lea     rax, [g_cfg_pass]
    mov     qword ptr [r10].ARGON2REQ.pwd, rax
    mov     eax, dword ptr [g_cfg_passlen]
    mov     dword ptr [r10].ARGON2REQ.pwdlen, eax
    mov     dword ptr [r10].ARGON2REQ.saltlen, 32
    lea     rax, [g_phdr+PH_SALT]
    mov     qword ptr [r10].ARGON2REQ.salt, rax
    mov     qword ptr [r10].ARGON2REQ.secret, 0
    mov     dword ptr [r10].ARGON2REQ.secretlen, 0
    mov     dword ptr [r10].ARGON2REQ.adlen, 0
    mov     qword ptr [r10].ARGON2REQ.ad, 0
    lea     rax, [p_vkey]
    mov     qword ptr [r10].ARGON2REQ.outp, rax
    lea     rcx, [p_areq]
    call    argon2id_hash
    test    eax, eax
    jz      pkd_ok
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
pkd_ok:
    xor     eax, eax
    FRAME_EPILOG
    ret
pk_derive endp

; pk_kcv() - p_sha32 = SHA-256(p_vkey)
pk_kcv proc frame
    FRAME_PROLOG 32
    lea     rcx, [p_vkey]
    mov     rdx, 32
    lea     r8, [p_sha32]
    call    sha256_hash
    FRAME_EPILOG
    ret
pk_kcv endp

; pad_print_err(ecx = exit code) - matching message to stderr.
pad_print_err proc frame
    FRAME_PROLOG 32
    cmp     ecx, EXIT_IO
    jne     ppe1
    lea     rcx, [pe_io]
    mov     edx, pe_io_len
    jmp     ppe_out
ppe1:
    cmp     ecx, EXIT_CORRUPT
    jne     ppe2
    lea     rcx, [pe_corrupt]
    mov     edx, pe_corrupt_len
    jmp     ppe_out
ppe2:
    cmp     ecx, EXIT_LOCKED
    jne     ppe3
    lea     rcx, [pe_locked]
    mov     edx, pe_locked_len
    jmp     ppe_out
ppe3:
    cmp     ecx, EXIT_AUTH
    jne     ppe4
    lea     rcx, [pe_auth]
    mov     edx, pe_auth_len
    jmp     ppe_out
ppe4:
    lea     rcx, [pe_oom]
    mov     edx, pe_oom_len
ppe_out:
    call    print_err
    FRAME_EPILOG
    ret
pad_print_err endp

; ---------------------------------------------------------------------------
; pad_seal_write() - g_phdr (116) is current; seal p_pad_ptr (p_pad_total) and
; write [hdr][ct][tag] atomically to g_cfg_in.  -> eax = 0 / EXIT_IO / EXIT_OOM.
; ---------------------------------------------------------------------------
pad_seal_write proc frame
    FRAME_PROLOG 48
    mov     rax, qword ptr [p_pad_total]
    add     rax, PH_AAD + 16
    mov     qword ptr [p_outlen], rax
    mov     rcx, rax
    call    mem_alloc
    test    rax, rax
    jz      psw_oom
    mov     qword ptr [p_outbuf], rax
    ; copy header (116 bytes)
    lea     r10, [g_phdr]
    mov     r11, rax
    xor     r8, r8
psw_hcpy:
    mov     cl, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], cl
    inc     r8
    cmp     r8, PH_AAD
    jb      psw_hcpy
    ; gcm_seal pad bytes -> outbuf+116, tag -> outbuf+116+total
    lea     r10, [p_greq]
    lea     rax, [p_vkey]
    mov     qword ptr [r10].GCMREQ.key, rax
    lea     rax, [g_phdr+PH_NONCE]
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_phdr]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, PH_AAD
    mov     rax, qword ptr [p_pad_ptr]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     rax, qword ptr [p_pad_total]
    mov     qword ptr [r10].GCMREQ.inlen, rax
    mov     rax, qword ptr [p_outbuf]
    add     rax, PH_AAD
    mov     qword ptr [r10].GCMREQ.outp, rax
    mov     rax, qword ptr [p_outbuf]
    add     rax, PH_AAD
    add     rax, qword ptr [p_pad_total]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [p_greq]
    call    gcm_seal
    ; atomic write: temp path = g_cfg_in + ".tmp"
    mov     r10, qword ptr [g_cfg_in]
    lea     r11, [p_tmppath]
    xor     r8, r8
psw_pcpy:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      psw_pdone
    inc     r8
    cmp     r8, MAX_PATH_CHARS-8
    jb      psw_pcpy
psw_pdone:
    mov     word ptr [r11+r8*2], '.'
    inc     r8
    mov     word ptr [r11+r8*2], 't'
    inc     r8
    mov     word ptr [r11+r8*2], 'm'
    inc     r8
    mov     word ptr [r11+r8*2], 'p'
    inc     r8
    mov     word ptr [r11+r8*2], 0
    lea     rcx, [p_tmppath]
    mov     rdx, qword ptr [p_outbuf]
    mov     r8, qword ptr [p_outlen]
    call    write_file
    test    eax, eax
    jnz     psw_io
    lea     rcx, [p_tmppath]
    mov     rdx, qword ptr [g_cfg_in]
    call    file_rename
    mov     dword ptr [rbp-24], eax
    jmp     psw_free
psw_io:
    mov     dword ptr [rbp-24], EXIT_IO
psw_free:
    mov     rcx, qword ptr [p_outbuf]
    mov     rdx, qword ptr [p_outlen]
    call    mem_free
    mov     qword ptr [p_outbuf], 0
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
psw_oom:
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
pad_seal_write endp

; ---------------------------------------------------------------------------
; pad_unlock() - read g_cfg_in, validate, derive key, KCV-check, gcm_open the
; pad bytes into secmem p_pad_ptr (p_pad_total).  g_phdr holds the 116-byte
; header.  -> eax = 0 / EXIT_*.
; ---------------------------------------------------------------------------
pad_unlock proc frame
    FRAME_PROLOG 48
    ; [rbp-24] = total_len
    mov     qword ptr [p_pad_ptr], 0
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, [p_filebuf]
    lea     r8, [p_filesize]
    call    read_file
    test    eax, eax
    jnz     pu_io
    mov     rax, qword ptr [p_filesize]
    cmp     rax, PH_AAD + 16
    jb      pu_corrupt
    mov     r10, qword ptr [p_filebuf]
    cmp     dword ptr [r10], PAD_MAGIC
    jne     pu_corrupt
    cmp     dword ptr [r10+4], PAD_VERSION
    jne     pu_corrupt
    ; copy 116-byte header
    lea     r9, [g_phdr]
    xor     r8, r8
pu_hcpy:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r9+r8], al
    inc     r8
    cmp     r8, PH_AAD
    jb      pu_hcpy
    ; total_len must match the ciphertext length and fit the cap
    mov     rax, qword ptr [g_phdr+PH_TOTLEN]
    mov     qword ptr [rbp-24], rax
    cmp     rax, PAD_MAX
    ja      pu_corrupt
    mov     r11, qword ptr [p_filesize]
    sub     r11, PH_AAD + 16
    cmp     r11, rax
    jne     pu_corrupt
    call    pk_derive
    test    eax, eax
    jnz     pu_oom
    call    pk_kcv
    lea     rcx, [p_sha32]
    mov     r10, qword ptr [p_filebuf]
    lea     rdx, [r10+PH_KCV]
    mov     r8, KCV_LEN
    call    ct_memcmp
    test    eax, eax
    jnz     pu_locked
    mov     rcx, qword ptr [rbp-24]         ; total_len
    call    secmem_alloc
    test    rax, rax
    jz      pu_oom
    mov     qword ptr [p_pad_ptr], rax
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [p_pad_total], r10
    ; gcm_open pad bytes
    lea     r10, [p_greq]
    lea     rax, [p_vkey]
    mov     qword ptr [r10].GCMREQ.key, rax
    lea     rax, [g_phdr+PH_NONCE]
    mov     qword ptr [r10].GCMREQ.iv, rax
    lea     rax, [g_phdr]
    mov     qword ptr [r10].GCMREQ.aad, rax
    mov     qword ptr [r10].GCMREQ.aadlen, PH_AAD
    mov     r11, qword ptr [p_filebuf]
    lea     rax, [r11+PH_AAD]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [r10].GCMREQ.inlen, rax
    mov     rax, qword ptr [p_pad_ptr]
    mov     qword ptr [r10].GCMREQ.outp, rax
    mov     r11, qword ptr [p_filebuf]
    lea     rax, [r11+PH_AAD]
    add     rax, qword ptr [rbp-24]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [p_greq]
    call    gcm_open
    test    eax, eax
    jnz     pu_auth
    ; free the ciphertext buffer
    mov     rcx, qword ptr [p_filebuf]
    mov     rdx, qword ptr [p_filesize]
    call    mem_free
    mov     qword ptr [p_filebuf], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
pu_io:
    mov     eax, EXIT_IO
    jmp     pu_cleanfile
pu_corrupt:
    mov     eax, EXIT_CORRUPT
    jmp     pu_cleanfile
pu_locked:
    mov     eax, EXIT_LOCKED
    jmp     pu_cleanfile
pu_auth:
    mov     eax, EXIT_AUTH
    jmp     pu_cleanall
pu_oom:
    mov     eax, EXIT_OOM
    jmp     pu_cleanall
pu_cleanall:
    mov     dword ptr [rbp-24], eax
    mov     rcx, qword ptr [p_pad_ptr]
    test    rcx, rcx
    jz      pu_cf2
    mov     rdx, qword ptr [p_pad_total]
    call    secmem_free
    mov     qword ptr [p_pad_ptr], 0
pu_cf2:
    mov     eax, dword ptr [rbp-24]
pu_cleanfile:
    mov     dword ptr [rbp-24], eax
    mov     rcx, qword ptr [p_filebuf]
    test    rcx, rcx
    jz      pu_ret
    mov     rdx, qword ptr [p_filesize]
    call    mem_free
    mov     qword ptr [p_filebuf], 0
pu_ret:
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
pad_unlock endp

; pad_lock() - wipe + free the secmem pad and wipe the derived key.
pad_lock proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [p_pad_ptr]
    test    rcx, rcx
    jz      plk_key
    mov     rdx, qword ptr [p_pad_total]
    call    secmem_free
    mov     qword ptr [p_pad_ptr], 0
plk_key:
    lea     rcx, [p_vkey]
    mov     rdx, 32
    call    secure_zero
    FRAME_EPILOG
    ret
pad_lock endp

; ---------------------------------------------------------------------------
; pad_build_header(r8d = source) - fill g_phdr for a NEW pad of p_pad_total
; bytes: magic/version/KDF params, fresh salt+nonce+pad_id, total_len, consumed=0.
; Derives the key and writes the KCV.  -> eax = 0 / EXIT_OOM.
; ---------------------------------------------------------------------------
pad_build_header proc frame
    FRAME_PROLOG 32
    mov     dword ptr [rbp-24], r8d         ; source
    mov     dword ptr [g_phdr+0], PAD_MAGIC
    mov     dword ptr [g_phdr+4], PAD_VERSION
    mov     eax, dword ptr [g_cfg_t]
    mov     dword ptr [g_phdr+PH_T], eax
    mov     eax, dword ptr [g_cfg_m]
    mov     dword ptr [g_phdr+PH_M], eax
    mov     dword ptr [g_phdr+PH_LANES], 1
    lea     rcx, [g_phdr+PH_SALT]
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      pbh_oom
    lea     rcx, [g_phdr+PH_NONCE]
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      pbh_oom
    lea     rcx, [g_phdr+PH_ID]
    mov     edx, 16
    call    rng_fill
    test    eax, eax
    jz      pbh_oom
    mov     rax, qword ptr [p_pad_total]
    mov     qword ptr [g_phdr+PH_TOTLEN], rax
    mov     qword ptr [g_phdr+PH_CONSUMED], 0
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_phdr+PH_SOURCE], eax
    call    pk_derive
    test    eax, eax
    jnz     pbh_oom
    call    pk_kcv
    lea     r10, [p_sha32]
    lea     r9, [g_phdr+PH_KCV]
    xor     r8, r8
pbh_kcv:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r9+r8], al
    inc     r8
    cmp     r8, KCV_LEN
    jb      pbh_kcv
    xor     eax, eax
    FRAME_EPILOG
    ret
pbh_oom:
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
pad_build_header endp

; ===========================================================================
; do_padnew - create a fresh CSPRNG pad of --size bytes at g_cfg_in.
; ===========================================================================
public do_padnew
do_padnew proc frame
    FRAME_PROLOG 48
    mov     eax, dword ptr [g_cfg_size]
    test    eax, eax
    jz      pn_badsize
    cmp     eax, PAD_MAX
    ja      pn_badsize
    mov     qword ptr [p_pad_total], rax
    mov     rcx, rax
    call    secmem_alloc
    test    rax, rax
    jz      pn_oom
    mov     qword ptr [p_pad_ptr], rax
    ; fill pad bytes with CSPRNG
    mov     rcx, rax
    mov     edx, dword ptr [g_cfg_size]
    call    rng_fill
    test    eax, eax
    jz      pn_oom
    mov     r8d, PAD_SRC_CSPRNG
    call    pad_build_header
    test    eax, eax
    jnz     pn_oom
    call    pad_seal_write
    mov     dword ptr [rbp-24], eax
    call    pad_lock
    mov     eax, dword ptr [rbp-24]
    test    eax, eax
    jnz     pn_io
    lea     rcx, [pm_padnew]
    mov     edx, pm_padnew_len
    call    print_a
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
pn_badsize:
    lea     rcx, [pe_size]
    mov     edx, pe_size_len
    call    print_err
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
pn_io:
    lea     rcx, [pe_io]
    mov     edx, pe_io_len
    call    print_err
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
pn_oom:
    call    pad_lock
    lea     rcx, [pe_oom]
    mov     edx, pe_oom_len
    call    print_err
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
do_padnew endp

; ===========================================================================
; do_padimport - import raw (TRNG) bytes from --from into a new pad at g_cfg_in.
; ===========================================================================
public do_padimport
do_padimport proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_cfg_from], 0
    je      pi_badopt
    ; read the raw material (reuse p_filebuf/p_filesize as input holder)
    mov     rcx, qword ptr [g_cfg_from]
    lea     rdx, [p_filebuf]
    lea     r8, [p_filesize]
    call    read_file
    test    eax, eax
    jnz     pi_io
    mov     rax, qword ptr [p_filesize]
    test    rax, rax
    jz      pi_badsize
    cmp     rax, PAD_MAX
    ja      pi_badsize
    mov     qword ptr [p_pad_total], rax
    mov     rcx, rax
    call    secmem_alloc
    test    rax, rax
    jz      pi_oom
    mov     qword ptr [p_pad_ptr], rax
    ; copy raw bytes into the locked pad buffer
    mov     r11, rax                        ; dst
    mov     r10, qword ptr [p_filebuf]      ; src
    xor     r8, r8
pi_copy:
    cmp     r8, qword ptr [p_pad_total]
    jae     pi_copydone
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8
    jmp     pi_copy
pi_copydone:
    ; free the raw input buffer (wipe: it is key material)
    mov     rcx, qword ptr [p_filebuf]
    mov     rdx, qword ptr [p_filesize]
    call    mem_free
    mov     qword ptr [p_filebuf], 0
    mov     r8d, PAD_SRC_TRNG
    call    pad_build_header
    test    eax, eax
    jnz     pi_oom
    call    pad_seal_write
    mov     dword ptr [rbp-24], eax
    call    pad_lock
    mov     eax, dword ptr [rbp-24]
    test    eax, eax
    jnz     pi_io
    lea     rcx, [pm_import]
    mov     edx, pm_import_len
    call    print_a
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
pi_badopt:
    lea     rcx, [pe_from]
    mov     edx, pe_from_len
    call    print_err
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
pi_badsize:
    ; free raw buffer if held
    mov     rcx, qword ptr [p_filebuf]
    test    rcx, rcx
    jz      pi_bs2
    mov     rdx, qword ptr [p_filesize]
    call    mem_free
    mov     qword ptr [p_filebuf], 0
pi_bs2:
    lea     rcx, [pe_size]
    mov     edx, pe_size_len
    call    print_err
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
pi_io:
    lea     rcx, [pe_io]
    mov     edx, pe_io_len
    call    print_err
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
pi_oom:
    call    pad_lock
    lea     rcx, [pe_oom]
    mov     edx, pe_oom_len
    call    print_err
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
do_padimport endp

; ===========================================================================
; do_share - OTP-encrypt --secret using pad[consumed..], write -o SHAREFILE,
; advance + persist consumed_offset BEFORE emitting the share (no reuse).
; ===========================================================================
public do_share
do_share proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=result [rbp-32]=msglen [rbp-40]=consumed [rbp-48]=need
    ; [rbp-56]=share image ptr [rbp-64]=share image len
    ; (frame sized so the otp_share_seal 5th-arg slot at [rsp+32] sits below
    ;  the deepest local rbp-64, not on top of it.)
    cmp     qword ptr [g_cfg_secret], 0
    je      ds_badopt
    cmp     qword ptr [g_cfg_out], 0
    je      ds_badopt
    call    pad_unlock
    test    eax, eax
    jnz     ds_unlockerr
    ; convert --secret to utf8 in p_msgbuf
    mov     rcx, qword ptr [g_cfg_secret]
    lea     rdx, [p_msgbuf]
    mov     r8d, CONV_CAP
    call    p_conv
    test    eax, eax
    jz      ds_badopt_locked
    mov     ecx, eax
    mov     qword ptr [rbp-32], rcx         ; msglen
    ; need = msglen + MAC_KEY_LEN
    mov     rax, rcx
    add     rax, MAC_KEY_LEN
    mov     qword ptr [rbp-48], rax
    mov     rax, qword ptr [g_phdr+PH_CONSUMED]
    mov     qword ptr [rbp-40], rax
    ; consumed + need <= total ?
    add     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [p_pad_total]
    ja      ds_exhaust
    ; allocate the share image: SH_HDR + msglen + 16
    mov     rax, qword ptr [rbp-32]
    add     rax, SH_HDR + 16
    mov     qword ptr [rbp-64], rax
    mov     rcx, rax
    call    mem_alloc
    test    rax, rax
    jz      ds_oom
    mov     qword ptr [rbp-56], rax
    ; share header
    mov     r11, rax
    mov     dword ptr [r11+0], SHARE_MAGIC
    mov     dword ptr [r11+4], SHARE_VERSION
    ; pad_id (16 bytes from g_phdr+PH_ID)
    lea     r10, [g_phdr+PH_ID]
    xor     r8, r8
ds_idcpy:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+SH_ID+r8], al
    inc     r8
    cmp     r8, 16
    jb      ds_idcpy
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [r11+SH_OFFSET], rax
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [r11+SH_MSGLEN], rax
    ; otp_share_seal(pt=p_msgbuf, len=msglen, pad=p_pad_ptr+consumed,
    ;                ctout=image+SH_HDR, tagout=image+SH_HDR+msglen)
    lea     rcx, [p_msgbuf]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, qword ptr [p_pad_ptr]
    add     r8, qword ptr [rbp-40]
    mov     r9, qword ptr [rbp-56]
    add     r9, SH_HDR
    mov     rax, qword ptr [rbp-56]
    add     rax, SH_HDR
    add     rax, qword ptr [rbp-32]
    mov     qword ptr [rsp+32], rax         ; 5th arg = tagout
    call    otp_share_seal
    ; ---- persist the advanced consumed_offset FIRST (no reuse) -------------
    mov     rax, qword ptr [rbp-40]
    add     rax, qword ptr [rbp-48]
    mov     qword ptr [g_phdr+PH_CONSUMED], rax
    lea     rcx, [g_phdr+PH_NONCE]          ; fresh nonce
    mov     edx, 12
    call    rng_fill
    test    eax, eax
    jz      ds_oom_img
    call    pad_seal_write                  ; re-encrypt + persist pad
    test    eax, eax
    jnz     ds_io_img
    ; ---- now write the share file -----------------------------------------
    mov     rcx, qword ptr [g_cfg_out]
    mov     rdx, qword ptr [rbp-56]
    mov     r8, qword ptr [rbp-64]
    call    write_file
    mov     dword ptr [rbp-24], eax
    ; free share image + lock pad
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-64]
    call    mem_free
    call    pad_lock
    mov     eax, dword ptr [rbp-24]
    test    eax, eax
    jnz     ds_io
    lea     rcx, [pm_shared]
    mov     edx, pm_shared_len
    call    print_a
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
ds_io_img:
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-64]
    call    mem_free
ds_io:
    call    pad_lock
    lea     rcx, [pe_io]
    mov     edx, pe_io_len
    call    print_err
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
ds_oom_img:
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-64]
    call    mem_free
ds_oom:
    call    pad_lock
    lea     rcx, [pe_oom]
    mov     edx, pe_oom_len
    call    print_err
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
ds_exhaust:
    call    pad_lock
    lea     rcx, [pe_exhaust]
    mov     edx, pe_exhaust_len
    call    print_err
    mov     eax, EXIT_PAD_EXHAUSTED
    FRAME_EPILOG
    ret
ds_badopt_locked:
    call    pad_lock
ds_badopt:
    lea     rcx, [pe_shareopt]
    mov     edx, pe_shareopt_len
    call    print_err
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
ds_unlockerr:
    mov     dword ptr [rbp-24], eax
    call    pad_lock                        ; wipe derived key on failure
    mov     ecx, dword ptr [rbp-24]
    call    pad_print_err
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
do_share endp

; ===========================================================================
; do_open - decrypt --share SHAREFILE with the pad, print/-o the plaintext,
; then advance + persist the recipient's consumed_offset.
; ===========================================================================
public do_open
do_open proc frame
    FRAME_PROLOG 80
    ; [rbp-24]=result [rbp-32]=msglen [rbp-40]=offset [rbp-48]=need
    mov     qword ptr [p_ptout], 0
    cmp     qword ptr [g_cfg_share], 0
    je      do_badopt
    call    pad_unlock
    test    eax, eax
    jnz     do_unlockerr
    ; read the share file
    mov     rcx, qword ptr [g_cfg_share]
    lea     rdx, [p_sharebuf]
    lea     r8, [p_sharesize]
    call    read_file
    test    eax, eax
    jnz     do_io_locked
    mov     rax, qword ptr [p_sharesize]
    cmp     rax, SH_HDR + 16
    jb      do_corrupt
    mov     r10, qword ptr [p_sharebuf]
    cmp     dword ptr [r10], SHARE_MAGIC
    jne     do_corrupt
    cmp     dword ptr [r10+4], SHARE_VERSION
    jne     do_corrupt
    ; pad_id must match this pad
    lea     rcx, [r10+SH_ID]
    lea     rdx, [g_phdr+PH_ID]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     do_padid
    mov     r10, qword ptr [p_sharebuf]
    mov     rax, qword ptr [r10+SH_OFFSET]
    mov     qword ptr [rbp-40], rax         ; offset
    mov     rax, qword ptr [r10+SH_MSGLEN]
    mov     qword ptr [rbp-32], rax         ; msglen
    ; validate: sharesize == SH_HDR + msglen + 16
    mov     rax, qword ptr [rbp-32]
    add     rax, SH_HDR + 16
    cmp     rax, qword ptr [p_sharesize]
    jne     do_corrupt
    ; validate: offset + msglen + MAC_KEY_LEN <= total
    mov     rax, qword ptr [rbp-40]
    add     rax, qword ptr [rbp-32]
    add     rax, MAC_KEY_LEN
    mov     qword ptr [rbp-48], rax
    cmp     rax, qword ptr [p_pad_total]
    ja      do_corrupt
    ; output buffer in locked memory
    mov     rcx, qword ptr [rbp-32]
    test    rcx, rcx
    jz      do_corrupt
    call    secmem_alloc
    test    rax, rax
    jz      do_oom
    mov     qword ptr [p_ptout], rax
    mov     r10, qword ptr [rbp-32]
    mov     qword ptr [p_ptout_len], r10
    ; otp_share_open(ct=share+SH_HDR, len=msglen, pad=p_pad_ptr+offset,
    ;                ptout, tag=share+SH_HDR+msglen)
    mov     r10, qword ptr [p_sharebuf]
    lea     rcx, [r10+SH_HDR]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, qword ptr [p_pad_ptr]
    add     r8, qword ptr [rbp-40]
    mov     r9, qword ptr [p_ptout]
    mov     r10, qword ptr [p_sharebuf]
    lea     rax, [r10+SH_HDR]
    add     rax, qword ptr [rbp-32]
    mov     qword ptr [rsp+32], rax         ; 5th arg = tag
    call    otp_share_open
    test    eax, eax
    jnz     do_auth
    ; ---- output the recovered plaintext -----------------------------------
    cmp     qword ptr [g_cfg_out], 0
    je      do_stdout
    mov     rcx, qword ptr [g_cfg_out]
    mov     rdx, qword ptr [p_ptout]
    mov     r8, qword ptr [rbp-32]
    call    write_file
    mov     dword ptr [rbp-24], eax
    jmp     do_after_out
do_stdout:
    mov     rcx, qword ptr [p_ptout]
    mov     edx, dword ptr [rbp-32]
    call    print_a
    lea     rcx, [nlp]
    mov     edx, 2
    call    print_a
    mov     dword ptr [rbp-24], EXIT_OK
do_after_out:
    ; ---- advance + persist recipient consumed_offset ----------------------
    mov     rax, qword ptr [g_phdr+PH_CONSUMED]
    cmp     rax, qword ptr [rbp-48]
    jae     do_persisted                    ; already past -> nothing to do
    mov     rax, qword ptr [rbp-48]
    mov     qword ptr [g_phdr+PH_CONSUMED], rax
    lea     rcx, [g_phdr+PH_NONCE]
    mov     edx, 12
    call    rng_fill
    call    pad_seal_write                  ; best-effort persist (ignore err here)
do_persisted:
    ; free output secmem + share buffer, lock pad
    mov     rcx, qword ptr [p_ptout]
    mov     rdx, qword ptr [rbp-32]
    call    secmem_free
    mov     qword ptr [p_ptout], 0
    mov     rcx, qword ptr [p_sharebuf]
    mov     rdx, qword ptr [p_sharesize]
    call    mem_free
    mov     qword ptr [p_sharebuf], 0
    call    pad_lock
    mov     eax, dword ptr [rbp-24]
    test    eax, eax
    jnz     do_io
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
do_io:
    lea     rcx, [pe_io]
    mov     edx, pe_io_len
    call    print_err
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
do_io_locked:
    call    pad_lock
    lea     rcx, [pe_io]
    mov     edx, pe_io_len
    call    print_err
    mov     eax, EXIT_IO
    FRAME_EPILOG
    ret
do_corrupt:
    call    do_cleanup_open
    lea     rcx, [pe_corrupt]
    mov     edx, pe_corrupt_len
    call    print_err
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
do_padid:
    call    do_cleanup_open
    lea     rcx, [pe_padid]
    mov     edx, pe_padid_len
    call    print_err
    mov     eax, EXIT_CORRUPT
    FRAME_EPILOG
    ret
do_auth:
    call    do_cleanup_open
    lea     rcx, [pe_auth]
    mov     edx, pe_auth_len
    call    print_err
    mov     eax, EXIT_AUTH
    FRAME_EPILOG
    ret
do_oom:
    call    do_cleanup_open
    lea     rcx, [pe_oom]
    mov     edx, pe_oom_len
    call    print_err
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
do_badopt:
    lea     rcx, [pe_openopt]
    mov     edx, pe_openopt_len
    call    print_err
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
do_unlockerr:
    mov     dword ptr [rbp-24], eax
    call    pad_lock                        ; wipe derived key on failure
    mov     ecx, dword ptr [rbp-24]
    call    pad_print_err
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
do_open endp

; do_cleanup_open - free output secmem (sized via p_ptout_len), the share
; buffer, and lock the pad.
do_cleanup_open proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [p_ptout]
    test    rcx, rcx
    jz      dco_share
    mov     rdx, qword ptr [p_ptout_len]
    call    secmem_free
    mov     qword ptr [p_ptout], 0
dco_share:
    mov     rcx, qword ptr [p_sharebuf]
    test    rcx, rcx
    jz      dco_lock
    mov     rdx, qword ptr [p_sharesize]
    call    mem_free
    mov     qword ptr [p_sharebuf], 0
dco_lock:
    call    pad_lock
    FRAME_EPILOG
    ret
do_cleanup_open endp

; ---------------------------------------------------------------------------
; p_conv(rcx = wideZ, rdx = out, r8d = cap) -> eax = utf8 byte len (no NUL),
;   0 if NULL/empty/failure.
; ---------------------------------------------------------------------------
p_conv proc frame
    FRAME_PROLOG 32 + 32
    test    rcx, rcx
    jz      pc_zero
    WINCALL WideCharToMultiByte, CP_UTF8, 0, rcx, -1, rdx, r8d, 0, 0
    test    eax, eax
    jz      pc_zero
    dec     eax
    FRAME_EPILOG
    ret
pc_zero:
    xor     eax, eax
    FRAME_EPILOG
    ret
p_conv endp

end
