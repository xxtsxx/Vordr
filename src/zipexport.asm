; =============================================================================
; zipexport.asm - write a password-protected ZIP using WinZip AES-256 (AE-2), so
; the export opens in 7-Zip / Windows / any AES-zip tool with the password.
;
;   ze_reset()                                  -> eax 0 / EXIT_OOM   (alloc g_zbuf)
;   ze_set_pw(rcx = utf8 pw, edx = pwlen)
;   ze_add_file(rcx=name, edx=namelen, r8=data, r9=datalen)
;   ze_finish()
;   ze_free()
;   g_zbuf {ptr,len,cap}  - the finished archive
;
; Each entry: STORE method inside AES; per-file 16-byte salt; PBKDF2-HMAC-SHA1
; (1000 iters) -> 32-byte AES key + 32-byte HMAC key + 2-byte password verifier;
; AES-256-CTR ciphertext (aes_ctr_xor); 10-byte HMAC-SHA1 authentication trailer.
; =============================================================================

include macros.inc

extern buf_putb:proc
extern buf_putn:proc
extern buf_pu16:proc
extern buf_pu32:proc
extern buf_zero:proc
externdef g_xl_err:byte
extern aes_expand_key:proc
extern aes_ctr_xor:proc
extern hmac_sha1:proc
extern rng_fill:proc
extern mem_alloc:proc
extern mem_free:proc
extern secure_zero:proc
extern buf_putcstr:proc
extern buf_pu32dec:proc
extern vault_count:proc
extern vault_title_at:proc
extern vault_field_count:proc
extern vault_field_get:proc
extern attach_open:proc
extern WideCharToMultiByte:proc
; --- Excel builder / agile encryptor (for the excel format inside ze_compose) ---
extern xl_build_xlsx:proc
extern xl_free:proc
extern xl_encrypt:proc
extern g_xlsx_ptr:qword
extern g_xlsx_len:qword

VF_IMAGE_   equ 9
VF_FILE_    equ 10
VFL_RAW_    equ 40000000h
JSON_CAP    equ 16*1024*1024
CP_UTF8_    equ 65001

ZE_CAP      equ 32*1024*1024
ZE_MAXFILE  equ 512
ZE_NAMEPOOL equ 256*1024             ; persistent copies of every entry's name
PBKDF2_ITERS equ 1000

.data?
align 16
public g_zbuf
g_zbuf      dq 3 dup (?)             ; {ptr,len,cap}
g_ze_pw     dq ?                     ; UTF-8 password ptr
g_ze_pwlen  dd ?
g_ze_cn     dd ?                     ; central-dir record count
; cd record = offset(4) csize(4) usize(4) namelen(4) nameptr(8) = 24 bytes
g_ze_cd     db ZE_MAXFILE*24 dup (?)
g_ze_names  db ZE_NAMEPOOL dup (?)    ; per-record name copies (nameptr must survive)
g_ze_np     dd ?                      ; name-pool write cursor
g_ae_dk     db 80 dup (?)            ; PBKDF2 output (enc32 | auth32 | verify2..)
g_ze_salt   db 16 dup (?)
g_ze_rk     db 15*16 dup (?)         ; AES round keys
g_ze_ctr    db 16 dup (?)
g_ze_auth   db 20 dup (?)
g_ze_nr     dd ?
g_pb_msg    db 32 dup (?)            ; salt || INT32BE(i)
g_pb_u      db 20 dup (?)
g_pb_un     db 20 dup (?)
g_pb_t      db 20 dup (?)

.code

; =============================================================================
; pbkdf2_ae(rcx=pw, edx=pwlen, r8=salt, r9d=saltlen) -> g_ae_dk (66 bytes used)
;   PBKDF2-HMAC-SHA1, PBKDF2_ITERS iterations, 4 x 20-byte blocks.
; =============================================================================
pbkdf2_ae proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx             ; pw
    mov     dword ptr [rbp-32], edx             ; pwlen
    mov     qword ptr [rbp-40], r8              ; salt
    mov     dword ptr [rbp-48], r9d             ; saltlen
    mov     dword ptr [rbp-52], 1               ; block i
pb_block:
    cmp     dword ptr [rbp-52], 4
    ja      pb_done
    ; g_pb_msg = salt || INT32BE(i)
    mov     rax, qword ptr [rbp-40]
    lea     r11, [g_pb_msg]
    xor     r10d, r10d
pb_cs:
    cmp     r10d, dword ptr [rbp-48]
    jae     pb_csd
    mov     r8b, byte ptr [rax+r10]
    mov     byte ptr [r11+r10], r8b
    inc     r10d
    jmp     pb_cs
pb_csd:
    mov     eax, dword ptr [rbp-52]             ; INT32BE(i)
    bswap   eax
    mov     dword ptr [r11+r10], eax
    add     r10d, 4
    mov     dword ptr [rbp-56], r10d            ; msg length
    ; U = HMAC-SHA1(pw, msg)
    WINCALL hmac_sha1, qword ptr [rbp-24], dword ptr [rbp-32], addr g_pb_msg, \
            dword ptr [rbp-56], addr g_pb_u
    ; T = U
    lea     r10, [g_pb_u]
    lea     r11, [g_pb_t]
    xor     eax, eax
pb_t0:
    mov     cl, byte ptr [r10+rax]
    mov     byte ptr [r11+rax], cl
    inc     eax
    cmp     eax, 20
    jb      pb_t0
    ; iterate c = 2..ITERS
    mov     dword ptr [rbp-60], 2
pb_iter:
    cmp     dword ptr [rbp-60], PBKDF2_ITERS
    ja      pb_wrblk
    WINCALL hmac_sha1, qword ptr [rbp-24], dword ptr [rbp-32], addr g_pb_u, 20, addr g_pb_un
    lea     r10, [g_pb_un]
    lea     r11, [g_pb_t]
    lea     r9, [g_pb_u]
    xor     eax, eax
pb_xor:
    mov     cl, byte ptr [r10+rax]              ; U_new
    xor     byte ptr [r11+rax], cl              ; T ^= U_new
    mov     byte ptr [r9+rax], cl               ; U = U_new
    inc     eax
    cmp     eax, 20
    jb      pb_xor
    inc     dword ptr [rbp-60]
    jmp     pb_iter
pb_wrblk:
    ; g_ae_dk[(i-1)*20 ..] = T
    mov     eax, dword ptr [rbp-52]
    dec     eax
    imul    eax, eax, 20
    lea     r11, [g_ae_dk]
    add     r11, rax
    lea     r10, [g_pb_t]
    xor     eax, eax
pb_wr:
    mov     cl, byte ptr [r10+rax]
    mov     byte ptr [r11+rax], cl
    inc     eax
    cmp     eax, 20
    jb      pb_wr
    inc     dword ptr [rbp-52]
    jmp     pb_block
pb_done:
    FRAME_EPILOG
    ret
pbkdf2_ae endp

; =============================================================================
; ze_reset() -> eax 0 / EXIT_OOM
; =============================================================================
public ze_reset
ze_reset proc frame
    FRAME_PROLOG 32
    mov     byte ptr [g_xl_err], 0
    mov     dword ptr [g_ze_cn], 0
    mov     dword ptr [g_ze_np], 0
    mov     rcx, ZE_CAP
    call    mem_alloc
    test    rax, rax
    jz      zr_oom
    lea     r10, [g_zbuf]
    mov     qword ptr [r10], rax
    mov     qword ptr [r10+8], 0
    mov     qword ptr [r10+16], ZE_CAP
    xor     eax, eax
    FRAME_EPILOG
    ret
zr_oom:
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
ze_reset endp

; ze_set_pw(rcx = utf8 pw, edx = pwlen)
public ze_set_pw
ze_set_pw proc
    mov     qword ptr [g_ze_pw], rcx
    mov     dword ptr [g_ze_pwlen], edx
    ret
ze_set_pw endp

; ze_free() - wipe + release the archive buffer
public ze_free
ze_free proc frame
    FRAME_PROLOG 32
    lea     r10, [g_zbuf]
    mov     rcx, qword ptr [r10]
    test    rcx, rcx
    jz      zf_done
    mov     rdx, qword ptr [r10+16]
    call    mem_free
    lea     r10, [g_zbuf]
    mov     qword ptr [r10], 0
zf_done:
    lea     rcx, [g_ae_dk]                       ; wipe key material
    mov     edx, 80
    call    secure_zero
    lea     rcx, [g_ze_rk]
    mov     edx, 15*16
    call    secure_zero
    FRAME_EPILOG
    ret
ze_free endp

; ZP16/ZP32/ZPB - append to g_zbuf
ZB16 macro v
    lea     rcx, [g_zbuf]
    mov     edx, v
    call    buf_pu16
endm
ZB32 macro v
    lea     rcx, [g_zbuf]
    mov     edx, v
    call    buf_pu32
endm
ZBB macro v
    lea     rcx, [g_zbuf]
    mov     dl, v
    call    buf_putb
endm

; ze_aextra - emit the 11-byte AE-2 extra field (id 0x9901)
ze_aextra proc
    ZB16    09901h
    ZB16    7
    ZB16    2                                    ; AE-2
    ZB16    04541h                               ; vendor 'A','E'
    ZBB     3                                    ; AES-256
    ZB16    0                                    ; stored inside AES
    ret
ze_aextra endp

; =============================================================================
; ze_add_file(rcx=name, edx=namelen, r8=data, r9=datalen)
; =============================================================================
public ze_add_file
ze_add_file proc frame
    FRAME_PROLOG 128                            ; keep locals (to rbp-80) above the
                                                ; callee shadow region
    mov     qword ptr [rbp-24], rcx             ; name
    mov     dword ptr [rbp-32], edx             ; namelen
    mov     qword ptr [rbp-40], r8              ; data
    mov     qword ptr [rbp-48], r9              ; datalen
    ; ---- copy the name into the persistent pool: the central-dir nameptr must
    ; stay valid until ze_finish, but callers reuse one name buffer across files
    ; (e.g. g_zj_fn per attachment), so a stored pointer would alias the last name.
    mov     eax, dword ptr [rbp-32]             ; namelen
    mov     r10d, dword ptr [g_ze_np]           ; pool cursor
    mov     r11d, ZE_NAMEPOOL
    sub     r11d, r10d                          ; remaining
    cmp     eax, r11d
    jbe     zaf_ncap
    mov     eax, r11d                           ; clamp (pathological only)
    mov     dword ptr [rbp-32], eax
zaf_ncap:
    lea     r11, [g_ze_names]
    add     r11, r10                            ; dst slot
    mov     rcx, qword ptr [rbp-24]             ; src name
    xor     r9d, r9d
zaf_ncp:
    cmp     r9d, eax
    jae     zaf_ncpd
    mov     r8b, byte ptr [rcx+r9]
    mov     byte ptr [r11+r9], r8b
    inc     r9d
    jmp     zaf_ncp
zaf_ncpd:
    mov     qword ptr [rbp-24], r11             ; name -> pooled copy
    add     dword ptr [g_ze_np], eax            ; advance cursor
    ; record cd offset
    lea     r10, [g_zbuf]
    mov     rax, qword ptr [r10+8]
    mov     dword ptr [rbp-56], eax             ; local-header offset
    ; csize = 16 + 2 + datalen + 10
    mov     eax, dword ptr [rbp-48]
    add     eax, 28
    mov     dword ptr [rbp-60], eax             ; csize
    ; ---- local file header ----
    ZB32    04034b50h
    ZB16    20
    ZB16    1                                    ; flag bit0 = encrypted (WinZip AE)
    ZB16    99
    ZB16    0
    ZB16    0
    ZB32    0                                    ; crc (AE-2 -> 0)
    ZB32    dword ptr [rbp-60]                   ; csize
    ZB32    dword ptr [rbp-48]                   ; usize
    ZB16    dword ptr [rbp-32]                   ; namelen
    ZB16    11                                   ; extra len
    lea     rcx, [g_zbuf]
    mov     rdx, qword ptr [rbp-24]
    mov     r8d, dword ptr [rbp-32]
    call    buf_putn
    call    ze_aextra
    ; ---- salt ----
    lea     rcx, [g_ze_salt]
    mov     edx, 16
    call    rng_fill
    lea     rcx, [g_zbuf]
    lea     rdx, [g_ze_salt]
    mov     r8, 16
    call    buf_putn
    ; ---- derive keys ----
    mov     rcx, qword ptr [g_ze_pw]
    mov     edx, dword ptr [g_ze_pwlen]
    lea     r8, [g_ze_salt]
    mov     r9d, 16
    call    pbkdf2_ae
    ; ---- password verifier (dk[64..66]) ----
    lea     rcx, [g_zbuf]
    lea     rdx, [g_ae_dk+64]
    mov     r8, 2
    call    buf_putn
    ; ---- ciphertext: append plaintext, encrypt in place ----
    lea     r10, [g_zbuf]
    mov     rax, qword ptr [r10+8]
    mov     qword ptr [rbp-72], rax             ; cipher start offset
    lea     rcx, [g_zbuf]
    mov     rdx, qword ptr [rbp-40]
    mov     r8, qword ptr [rbp-48]
    call    buf_putn
    ; expand AES-256 key (dk[0..32])
    lea     rcx, [g_ae_dk]
    mov     rdx, 32
    lea     r8, [g_ze_rk]
    call    aes_expand_key
    mov     dword ptr [g_ze_nr], eax
    ; counter := 0
    lea     rcx, [g_ze_ctr]
    xor     eax, eax
    mov     qword ptr [rcx], rax
    mov     qword ptr [rcx+8], rax
    ; encrypt in place over [zbuf.ptr + cipher-start, datalen)
    lea     r10, [g_zbuf]
    mov     r11, qword ptr [r10]
    add     r11, qword ptr [rbp-72]
    mov     qword ptr [rbp-80], r11             ; cipher ptr
    WINCALL aes_ctr_xor, addr g_ze_rk, qword ptr [rbp-80], qword ptr [rbp-48], \
            addr g_ze_ctr, dword ptr [g_ze_nr]
    ; ---- auth = HMAC-SHA1(authkey dk[32..64], ciphertext)[:10] ----
    WINCALL hmac_sha1, addr g_ae_dk+32, 32, qword ptr [rbp-80], qword ptr [rbp-48], addr g_ze_auth
    lea     rcx, [g_zbuf]
    lea     rdx, [g_ze_auth]
    mov     r8, 10
    call    buf_putn
    ; ---- record central-dir entry ----
    mov     eax, dword ptr [g_ze_cn]
    imul    eax, eax, 24
    lea     r11, [g_ze_cd]
    add     r11, rax
    mov     eax, dword ptr [rbp-56]
    mov     dword ptr [r11+0], eax               ; offset
    mov     eax, dword ptr [rbp-60]
    mov     dword ptr [r11+4], eax               ; csize
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [r11+8], eax               ; usize
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [r11+12], eax              ; namelen
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [r11+16], rax              ; nameptr
    inc     dword ptr [g_ze_cn]
    FRAME_EPILOG
    ret
ze_add_file endp

; =============================================================================
; ze_finish() - central directory + end-of-central-directory
; =============================================================================
public ze_finish
ze_finish proc frame
    FRAME_PROLOG 96                             ; locals above the callee shadow region
    lea     r10, [g_zbuf]
    mov     rax, qword ptr [r10+8]
    mov     qword ptr [rbp-24], rax              ; cd start
    mov     dword ptr [rbp-32], 0                ; i
zfn_lp:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [g_ze_cn]
    jae     zfn_eocd
    imul    eax, eax, 24
    lea     r11, [g_ze_cd]
    add     r11, rax
    mov     qword ptr [rbp-40], r11              ; record ptr
    ZB32    02014b50h
    ZB16    20                                   ; version made by
    ZB16    20                                   ; version needed
    ZB16    1                                    ; flag bit0 = encrypted (WinZip AE)
    ZB16    99                                   ; method AES
    ZB16    0
    ZB16    0
    ZB32    0                                    ; crc
    mov     r11, qword ptr [rbp-40]
    ZB32    dword ptr [r11+4]                     ; csize
    mov     r11, qword ptr [rbp-40]
    ZB32    dword ptr [r11+8]                     ; usize
    mov     r11, qword ptr [rbp-40]
    ZB16    dword ptr [r11+12]                    ; namelen
    ZB16    11                                   ; extra
    ZB16    0                                    ; comment
    ZB16    0                                    ; disk
    ZB16    0                                    ; internal attrs
    ZB32    0                                    ; external attrs
    mov     r11, qword ptr [rbp-40]
    ZB32    dword ptr [r11+0]                     ; local-header offset
    lea     rcx, [g_zbuf]
    mov     r11, qword ptr [rbp-40]
    mov     rdx, qword ptr [r11+16]              ; nameptr
    mov     r8d, dword ptr [r11+12]              ; namelen
    call    buf_putn
    call    ze_aextra
    inc     dword ptr [rbp-32]
    jmp     zfn_lp
zfn_eocd:
    lea     r10, [g_zbuf]
    mov     rax, qword ptr [r10+8]
    sub     rax, qword ptr [rbp-24]
    mov     dword ptr [rbp-48], eax              ; cd size
    ZB32    06054b50h
    ZB16    0
    ZB16    0
    ZB16    dword ptr [g_ze_cn]
    ZB16    dword ptr [g_ze_cn]
    ZB32    dword ptr [rbp-48]                    ; cd size
    ZB32    dword ptr [rbp-24]                    ; cd offset
    ZB16    0                                    ; comment length
    FRAME_EPILOG
    ret
ze_finish endp

.const
zj_title  db '{"title":',0
zj_fields db ',"fields":[',0
zj_ftype  db '{"type":',0
zj_flabel db ',"label":',0
zj_fvalue db ',"value":',0
zj_jsonname db "vordr.json"
zj_defname  db "attachment.bin"
zj_csvname  db "vordr.csv"
zj_xlsxname db "vordr.xlsx"
csv_hdr   db "title,username,password,url,notes,totp",13,10,0
csv_kinds db VF_TITLE, VF_USERNAME, VF_SECRET, VF_URL, VF_NOTES, VF_TOTP
hexdig    db "0123456789abcdef"

.data?
g_json      dq 3 dup (?)             ; {ptr,len,cap} for the fields JSON
g_csvbuf    dq 3 dup (?)             ; {ptr,len,cap} for the CSV text
g_ze_u8pw   db 512 dup (?)           ; wide->UTF-8 export password scratch
g_zj_fld    db 40 dup (?)            ; vault_field_get out struct
g_zj_fn     db 512 dup (?)           ; attachment filename (UTF-8)

.code

; json_str(rcx=buf desc, rdx=src, r8=len) - append a JSON-escaped "..." string.
json_str proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     rcx, qword ptr [rbp-24]
    mov     dl, '"'
    call    buf_putb
    mov     qword ptr [rbp-48], 0
js_lp:
    mov     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [rbp-40]
    jae     js_close
    mov     r10, qword ptr [rbp-32]
    movzx   eax, byte ptr [r10+rax]
    mov     dword ptr [rbp-56], eax             ; b
    cmp     eax, '"'
    je      js_bs
    cmp     eax, '\'
    je      js_bs
    cmp     eax, 10
    je      js_nl
    cmp     eax, 13
    je      js_cr
    cmp     eax, 9
    je      js_tab
    cmp     eax, 20h
    jb      js_uni
    mov     rcx, qword ptr [rbp-24]
    mov     dl, byte ptr [rbp-56]
    call    buf_putb
    jmp     js_next
js_bs:
    mov     rcx, qword ptr [rbp-24]
    mov     dl, '\'
    call    buf_putb
    mov     rcx, qword ptr [rbp-24]
    mov     dl, byte ptr [rbp-56]
    call    buf_putb
    jmp     js_next
js_nl:
    mov     r8b, 'n'
    jmp     js_esc2
js_cr:
    mov     r8b, 'r'
    jmp     js_esc2
js_tab:
    mov     r8b, 't'
js_esc2:
    mov     byte ptr [rbp-57], r8b
    mov     rcx, qword ptr [rbp-24]
    mov     dl, '\'
    call    buf_putb
    mov     rcx, qword ptr [rbp-24]
    mov     dl, byte ptr [rbp-57]
    call    buf_putb
    jmp     js_next
js_uni:
    mov     rcx, qword ptr [rbp-24]
    mov     dl, '\'
    call    buf_putb
    mov     rcx, qword ptr [rbp-24]
    mov     dl, 'u'
    call    buf_putb
    mov     rcx, qword ptr [rbp-24]
    mov     dl, '0'
    call    buf_putb
    mov     rcx, qword ptr [rbp-24]
    mov     dl, '0'
    call    buf_putb
    mov     eax, dword ptr [rbp-56]             ; hi nibble
    shr     eax, 4
    lea     r10, [hexdig]
    mov     dl, byte ptr [r10+rax]
    mov     rcx, qword ptr [rbp-24]
    call    buf_putb
    mov     eax, dword ptr [rbp-56]             ; lo nibble
    and     eax, 0Fh
    lea     r10, [hexdig]
    mov     dl, byte ptr [r10+rax]
    mov     rcx, qword ptr [rbp-24]
    call    buf_putb
js_next:
    inc     qword ptr [rbp-48]
    jmp     js_lp
js_close:
    mov     rcx, qword ptr [rbp-24]
    mov     dl, '"'
    call    buf_putb
    FRAME_EPILOG
    ret
json_str endp

; ze_build_json() -> eax 0/err.  Builds g_json = [{"title":..,"fields":[..]},..].
ze_build_json proc frame
    FRAME_PROLOG 96
    mov     rcx, JSON_CAP
    call    mem_alloc
    test    rax, rax
    jz      zbj_err
    lea     r10, [g_json]
    mov     qword ptr [r10], rax
    mov     qword ptr [r10+8], 0
    mov     qword ptr [r10+16], JSON_CAP
    lea     rcx, [g_json]
    mov     dl, '['
    call    buf_putb
    call    vault_count
    mov     dword ptr [rbp-24], eax             ; n
    mov     dword ptr [rbp-28], 0               ; e
zbj_elp:
    mov     eax, dword ptr [rbp-28]
    cmp     eax, dword ptr [rbp-24]
    jae     zbj_edone
    cmp     eax, 0
    je      zbj_e0
    lea     rcx, [g_json]
    mov     dl, ','
    call    buf_putb
zbj_e0:
    lea     rcx, [g_json]
    lea     rdx, [zj_title]
    call    buf_putcstr
    mov     ecx, dword ptr [rbp-28]
    lea     rdx, [rbp-40]
    call    vault_title_at                      ; rax=ptr, [rbp-40]=len
    lea     rcx, [g_json]
    mov     rdx, rax
    mov     r8, qword ptr [rbp-40]
    call    json_str
    lea     rcx, [g_json]
    lea     rdx, [zj_fields]
    call    buf_putcstr
    mov     ecx, dword ptr [rbp-28]
    call    vault_field_count
    mov     dword ptr [rbp-44], eax             ; fc
    mov     dword ptr [rbp-48], 0               ; f
    mov     dword ptr [rbp-52], 1               ; first
zbj_flp:
    mov     eax, dword ptr [rbp-48]
    cmp     eax, dword ptr [rbp-44]
    jae     zbj_fdone
    mov     ecx, dword ptr [rbp-28]
    mov     edx, dword ptr [rbp-48]
    lea     r8, [g_zj_fld]
    call    vault_field_get
    test    eax, eax
    jz      zbj_fnext
    mov     eax, dword ptr [g_zj_fld]
    cmp     eax, VF_IMAGE_
    je      zbj_fnext
    cmp     eax, VF_FILE_
    je      zbj_fnext
    cmp     dword ptr [rbp-52], 0
    jne     zbj_ffirst
    lea     rcx, [g_json]
    mov     dl, ','
    call    buf_putb
zbj_ffirst:
    mov     dword ptr [rbp-52], 0
    lea     rcx, [g_json]
    lea     rdx, [zj_ftype]
    call    buf_putcstr
    lea     rcx, [g_json]
    mov     edx, dword ptr [g_zj_fld]
    call    buf_pu32dec
    lea     rcx, [g_json]
    lea     rdx, [zj_flabel]
    call    buf_putcstr
    lea     rcx, [g_json]
    mov     rdx, qword ptr [g_zj_fld+8]
    mov     r8, qword ptr [g_zj_fld+16]
    call    json_str
    lea     rcx, [g_json]
    lea     rdx, [zj_fvalue]
    call    buf_putcstr
    lea     rcx, [g_json]
    mov     rdx, qword ptr [g_zj_fld+24]
    mov     r8, qword ptr [g_zj_fld+32]
    call    json_str
    lea     rcx, [g_json]
    mov     dl, '}'
    call    buf_putb
zbj_fnext:
    inc     dword ptr [rbp-48]
    jmp     zbj_flp
zbj_fdone:
    lea     rcx, [g_json]
    mov     dl, ']'
    call    buf_putb
    lea     rcx, [g_json]
    mov     dl, '}'
    call    buf_putb
    inc     dword ptr [rbp-28]
    jmp     zbj_elp
zbj_edone:
    lea     rcx, [g_json]
    mov     dl, ']'
    call    buf_putb
    xor     eax, eax
    FRAME_EPILOG
    ret
zbj_err:
    mov     eax, 1
    FRAME_EPILOG
    ret
ze_build_json endp

; =============================================================================
; ze_add_attachments() -> eax 0/err.  Append every image/file attachment in the
;   vault to the open archive (ze_reset + ze_set_pw must precede).  Each blob is
;   decrypted to plaintext, added under its stored filename, then wiped + freed.
; =============================================================================
public ze_add_attachments
ze_add_attachments proc frame
    FRAME_PROLOG 144
    call    vault_count
    mov     dword ptr [rbp-40], eax             ; n
    mov     dword ptr [rbp-44], 0               ; e
zea_elp:
    mov     eax, dword ptr [rbp-44]
    cmp     eax, dword ptr [rbp-40]
    jae     zea_fin
    mov     ecx, dword ptr [rbp-44]
    call    vault_field_count
    mov     dword ptr [rbp-48], eax             ; fc
    mov     dword ptr [rbp-52], 0               ; f
zea_flp:
    mov     eax, dword ptr [rbp-52]
    cmp     eax, dword ptr [rbp-48]
    jae     zea_enext
    mov     ecx, dword ptr [rbp-44]
    mov     edx, dword ptr [rbp-52]
    lea     r8, [g_zj_fld]
    call    vault_field_get
    test    eax, eax
    jz      zea_fnext
    mov     eax, dword ptr [g_zj_fld]
    cmp     eax, VF_IMAGE_
    je      zea_att
    cmp     eax, VF_FILE_
    je      zea_att
    jmp     zea_fnext
zea_att:
    ; the serialized value is {AttachRef[68], filename wide} - AttachRef at +0,
    ; filename at +68 (this matches the GUI's own read path in gui_showdetail).
    mov     r11, qword ptr [g_zj_fld+24]        ; value ptr
    mov     qword ptr [rbp-64], r11
    mov     rax, qword ptr [g_zj_fld+32]        ; value len (>68 => a filename follows)
    mov     qword ptr [rbp-96], rax
    mov     rcx, r11                             ; AttachRef = value + 0
    lea     rdx, [rbp-72]                        ; &outlen
    call    attach_open
    test    rax, rax
    jz      zea_fnext
    mov     qword ptr [rbp-80], rax             ; plaintext ptr
    ; filename (wide) at value+68 -> UTF-8 g_zj_fn (default if none stored)
    cmp     qword ptr [rbp-96], 68
    jbe     zea_defname
    mov     r11, qword ptr [rbp-64]
    lea     rax, [r11+68]
    mov     qword ptr [rbp-88], rax
    WINCALL WideCharToMultiByte, CP_UTF8_, 0, qword ptr [rbp-88], -1, addr g_zj_fn, 500, 0, 0
    dec     eax                                  ; strip the terminating NUL
    cmp     eax, 0
    jg      zea_havefn
zea_defname:
    lea     r10, [zj_defname]                    ; empty/absent name -> default
    lea     r11, [g_zj_fn]
    xor     r8d, r8d
zea_dcp:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8d
    cmp     r8d, 14
    jb      zea_dcp
    mov     eax, 14
zea_havefn:
    mov     dword ptr [rbp-56], eax             ; fnlen
    lea     rcx, [g_zj_fn]
    mov     edx, dword ptr [rbp-56]
    mov     r8, qword ptr [rbp-80]
    mov     r9, qword ptr [rbp-72]
    call    ze_add_file
    mov     rcx, qword ptr [rbp-80]              ; free plaintext (holds secret bytes)
    mov     rdx, qword ptr [rbp-72]
    call    mem_free
zea_fnext:
    inc     dword ptr [rbp-52]
    jmp     zea_flp
zea_enext:
    inc     dword ptr [rbp-44]
    jmp     zea_elp
zea_fin:
    xor     eax, eax
    FRAME_EPILOG
    ret
ze_add_attachments endp

; =============================================================================
; ze_export_all(rcx = utf8 pw, edx = pwlen) -> eax 0/err.  Builds the finished
;   encrypted archive in g_zbuf: vordr.json (all text fields) + every attachment.
; =============================================================================
public ze_export_all
ze_export_all proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    call    ze_reset
    test    eax, eax
    jnz     zea_err
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    call    ze_set_pw
    call    ze_build_json
    test    eax, eax
    jnz     zea_err
    lea     rcx, [zj_jsonname]
    mov     edx, 10
    lea     r10, [g_json]
    mov     r8, qword ptr [r10]
    mov     r9, qword ptr [r10+8]
    call    ze_add_file
    lea     r10, [g_json]                       ; free the JSON (already copied in)
    mov     rcx, qword ptr [r10]
    mov     rdx, qword ptr [r10+16]
    call    mem_free
    call    ze_add_attachments
    test    eax, eax
    jnz     zea_err
    call    ze_finish
    xor     eax, eax
    FRAME_EPILOG
    ret
zea_err:
    mov     eax, 1
    FRAME_EPILOG
    ret
ze_export_all endp

; =============================================================================
; ze_csv_cell(rcx = g_csvbuf, rdx = ptr, r8 = len) - append one RFC-4180 CSV
;   cell.  If the value contains a quote, comma, CR or LF it is wrapped in double
;   quotes with internal quotes doubled; otherwise the raw bytes are copied.
; =============================================================================
ze_csv_cell proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx             ; buf
    mov     qword ptr [rbp-32], rdx             ; ptr
    mov     qword ptr [rbp-40], r8              ; len
    ; ---- scan for characters that force quoting ----
    xor     r10d, r10d                          ; index
    xor     r11d, r11d                          ; needQuote
cc_scan:
    cmp     r10, qword ptr [rbp-40]
    jae     cc_scandone
    mov     rax, qword ptr [rbp-32]
    movzx   eax, byte ptr [rax+r10]
    cmp     eax, '"'
    je      cc_need
    cmp     eax, ','
    je      cc_need
    cmp     eax, 13
    je      cc_need
    cmp     eax, 10
    je      cc_need
    jmp     cc_scannext
cc_need:
    mov     r11d, 1
cc_scannext:
    inc     r10
    jmp     cc_scan
cc_scandone:
    test    r11d, r11d
    jnz     cc_quoted
    ; ---- plain: raw bytes ----
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    mov     r8d, dword ptr [rbp-40]
    call    buf_putn
    FRAME_EPILOG
    ret
cc_quoted:
    mov     rcx, qword ptr [rbp-24]             ; opening quote
    mov     dl, '"'
    call    buf_putb
    xor     r10d, r10d
cc_qlp:
    cmp     r10, qword ptr [rbp-40]
    jae     cc_qdone
    mov     rax, qword ptr [rbp-32]
    movzx   eax, byte ptr [rax+r10]
    mov     dword ptr [rbp-48], eax
    cmp     eax, '"'
    jne     cc_qput
    mov     rcx, qword ptr [rbp-24]             ; double an embedded quote
    mov     dl, '"'
    call    buf_putb
cc_qput:
    mov     rcx, qword ptr [rbp-24]
    mov     dl, byte ptr [rbp-48]
    call    buf_putb
    inc     r10
    jmp     cc_qlp
cc_qdone:
    mov     rcx, qword ptr [rbp-24]             ; closing quote
    mov     dl, '"'
    call    buf_putb
    FRAME_EPILOG
    ret
ze_csv_cell endp

; =============================================================================
; ze_csv_field(ecx = entry, edx = kind) -> rax = value ptr, rdx = len (0/0 none).
;   Returns the first field of the given base kind for the entry.
; =============================================================================
ze_csv_field proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], ecx             ; entry
    mov     dword ptr [rbp-28], edx             ; kind
    mov     ecx, dword ptr [rbp-24]
    call    vault_field_count
    mov     dword ptr [rbp-32], eax             ; fc
    mov     dword ptr [rbp-36], 0               ; f
cf_lp:
    mov     eax, dword ptr [rbp-36]
    cmp     eax, dword ptr [rbp-32]
    jae     cf_none
    mov     ecx, dword ptr [rbp-24]
    mov     edx, dword ptr [rbp-36]
    lea     r8, [g_zj_fld]
    call    vault_field_get
    test    eax, eax
    jz      cf_next
    mov     eax, dword ptr [g_zj_fld]
    cmp     eax, dword ptr [rbp-28]
    jne     cf_next
    mov     rax, qword ptr [g_zj_fld+24]        ; value ptr
    mov     rdx, qword ptr [g_zj_fld+32]        ; value len
    FRAME_EPILOG
    ret
cf_next:
    inc     dword ptr [rbp-36]
    jmp     cf_lp
cf_none:
    xor     eax, eax
    xor     edx, edx
    FRAME_EPILOG
    ret
ze_csv_field endp

; =============================================================================
; ze_build_csv() -> eax 0/err.  Builds g_csvbuf: a UTF-8 CSV (BOM + header row)
;   with one row per entry and the canonical columns title,username,password,
;   url,notes,totp.  Round-trips through the CSV importer's header keywords.
; =============================================================================
public ze_build_csv
ze_build_csv proc frame
    FRAME_PROLOG 48
    mov     rcx, JSON_CAP
    call    mem_alloc
    test    rax, rax
    jz      bc_err
    lea     r10, [g_csvbuf]
    mov     qword ptr [r10], rax
    mov     qword ptr [r10+8], 0
    mov     qword ptr [r10+16], JSON_CAP
    lea     rcx, [g_csvbuf]                     ; UTF-8 BOM (EF BB BF) for Excel
    mov     dl, 0EFh
    call    buf_putb
    lea     rcx, [g_csvbuf]
    mov     dl, 0BBh
    call    buf_putb
    lea     rcx, [g_csvbuf]
    mov     dl, 0BFh
    call    buf_putb
    lea     rcx, [g_csvbuf]
    lea     rdx, [csv_hdr]
    call    buf_putcstr
    call    vault_count
    mov     dword ptr [rbp-24], eax             ; n
    mov     dword ptr [rbp-28], 0               ; e
bc_elp:
    mov     eax, dword ptr [rbp-28]
    cmp     eax, dword ptr [rbp-24]
    jae     bc_done
    mov     dword ptr [rbp-32], 0               ; col
bc_clp:
    cmp     dword ptr [rbp-32], 6
    jae     bc_erow
    cmp     dword ptr [rbp-32], 0
    je      bc_c0
    lea     rcx, [g_csvbuf]                     ; column separator
    mov     dl, ','
    call    buf_putb
bc_c0:
    mov     r10d, dword ptr [rbp-32]
    lea     r11, [csv_kinds]
    movzx   edx, byte ptr [r11+r10]             ; kind
    mov     ecx, dword ptr [rbp-28]             ; entry
    call    ze_csv_field                        ; rax=ptr, rdx=len (0/0 none)
    test    rax, rax
    jz      bc_ncol
    mov     r8, rdx
    mov     rdx, rax
    lea     rcx, [g_csvbuf]
    call    ze_csv_cell
bc_ncol:
    inc     dword ptr [rbp-32]
    jmp     bc_clp
bc_erow:
    lea     rcx, [g_csvbuf]                     ; CRLF row terminator
    mov     dl, 13
    call    buf_putb
    lea     rcx, [g_csvbuf]
    mov     dl, 10
    call    buf_putb
    inc     dword ptr [rbp-28]
    jmp     bc_elp
bc_done:
    xor     eax, eax
    FRAME_EPILOG
    ret
bc_err:
    mov     eax, 1
    FRAME_EPILOG
    ret
ze_build_csv endp

; =============================================================================
; ze_compose(rcx = wide password ptr, edx = password bytes, r8d = EXP_* format,
;   r9d = include-attachments flag) -> eax:
;     0 = an encrypted ZIP is ready in g_zbuf   (caller: write it, then ze_free)
;     2 = a standalone encrypted .xlsx is ready in g_ole_ptr/g_ole_len
;         (caller: write it, then xl_encrypt_free + xl_free)
;     1 = error
;   Excel with no attachments -> the standalone encrypted workbook (2); every
;   other combination (CSV, JSON, or any format WITH attachments) is wrapped in
;   the AES-256 encrypted ZIP (0).
; =============================================================================
public ze_compose
ze_compose proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx             ; wide pw
    mov     dword ptr [rbp-32], edx             ; pw bytes
    mov     dword ptr [rbp-36], r8d             ; format
    mov     dword ptr [rbp-40], r9d             ; attachments
    cmp     dword ptr [rbp-36], EXP_EXCEL
    jne     comp_zip
    cmp     dword ptr [rbp-40], 0
    jne     comp_zip
    ; ---- standalone encrypted .xlsx ----
    call    xl_build_xlsx
    test    eax, eax
    jnz     comp_err
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    call    xl_encrypt
    test    eax, eax
    jnz     comp_xerr
    mov     eax, 2
    FRAME_EPILOG
    ret
comp_xerr:
    call    xl_free                             ; encrypt failed -> free plaintext package
    mov     eax, 1
    FRAME_EPILOG
    ret
comp_zip:
    ; ---- encrypted ZIP: wide pw -> UTF-8, then assemble ----
    mov     eax, dword ptr [rbp-32]
    shr     eax, 1                              ; wide chars
    WINCALL WideCharToMultiByte, CP_UTF8_, 0, qword ptr [rbp-24], eax, addr g_ze_u8pw, 500, 0, 0
    mov     dword ptr [rbp-44], eax             ; UTF-8 length
    call    ze_reset
    test    eax, eax
    jnz     comp_err
    lea     rcx, [g_ze_u8pw]
    mov     edx, dword ptr [rbp-44]
    call    ze_set_pw
    mov     eax, dword ptr [rbp-36]
    cmp     eax, EXP_JSON
    je      comp_json
    cmp     eax, EXP_CSV
    je      comp_csv
    ; ---- excel format wrapped in the zip: plain .xlsx package (zip encrypts) ----
    call    xl_build_xlsx
    test    eax, eax
    jnz     comp_ziperr
    lea     rcx, [zj_xlsxname]
    mov     edx, 10
    mov     r8, qword ptr [g_xlsx_ptr]
    mov     r9, qword ptr [g_xlsx_len]
    call    ze_add_file
    call    xl_free
    jmp     comp_attach
comp_json:
    call    ze_build_json
    test    eax, eax
    jnz     comp_ziperr
    lea     rcx, [zj_jsonname]
    mov     edx, 10
    lea     r10, [g_json]
    mov     r8, qword ptr [r10]
    mov     r9, qword ptr [r10+8]
    call    ze_add_file
    lea     r10, [g_json]
    mov     rcx, qword ptr [r10]
    mov     rdx, qword ptr [r10+16]
    call    mem_free
    jmp     comp_attach
comp_csv:
    call    ze_build_csv
    test    eax, eax
    jnz     comp_ziperr
    lea     rcx, [zj_csvname]
    mov     edx, 9
    lea     r10, [g_csvbuf]
    mov     r8, qword ptr [r10]
    mov     r9, qword ptr [r10+8]
    call    ze_add_file
    lea     r10, [g_csvbuf]
    mov     rcx, qword ptr [r10]
    mov     rdx, qword ptr [r10+16]
    call    mem_free
    jmp     comp_attach
comp_attach:
    cmp     dword ptr [rbp-40], 0
    je      comp_fin
    call    ze_add_attachments
    test    eax, eax
    jnz     comp_ziperr
comp_fin:
    call    ze_finish
    lea     rcx, [g_ze_u8pw]                    ; wipe the UTF-8 password copy
    mov     edx, 500
    call    secure_zero
    xor     eax, eax
    FRAME_EPILOG
    ret
comp_ziperr:
    lea     rcx, [g_ze_u8pw]
    mov     edx, 500
    call    secure_zero
    mov     eax, 1
    FRAME_EPILOG
    ret
comp_err:
    mov     eax, 1
    FRAME_EPILOG
    ret
ze_compose endp

end
