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

extern aes_expand_key:proc
extern aes_ctr_xor:proc
extern hmac_sha1:proc
extern rng_fill:proc
extern mem_alloc:proc
extern mem_free:proc
extern secure_zero:proc
extern vault_count:proc
extern vault_title_at:proc
extern vault_field_count:proc
extern vault_field_get:proc
extern attach_open:proc
externdef g_sel:byte                     ; per-entry export selection mask (gui.asm)
extern WideCharToMultiByte:proc
VF_IMAGE_   equ 9
VF_FILE_    equ 10
VF_PWHIST_  equ 13                   ; reserved field history - never exported
JSON_CAP    equ 16*1024*1024
CP_UTF8_    equ 65001

ZE_CAP      equ 32*1024*1024
ZE_MAXFILE  equ 512
ZE_NAMEPOOL equ 512*1024             ; persistent copies of every entry's name
PBKDF2_ITERS equ 1000

.data?
g_xl_err    db ?                     ; shared build-error flag (moved from xlexport)
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
public pbkdf2_ae
public g_ae_dk
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
hexdig    db "0123456789abcdef"

.data?
g_json      dq 3 dup (?)             ; {ptr,len,cap} for the fields JSON
g_ze_u8pw   db 512 dup (?)           ; wide->UTF-8 export password scratch
g_zj_fld    db 40 dup (?)            ; vault_field_get out struct
g_zj_fn     db 512 dup (?)           ; attachment filename (UTF-8)
g_zj_path   db 768 dup (?)           ; "<title-folder>/<filename>" zip path

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
    mov     dword ptr [rbp-56], 1               ; first emitted entry
zbj_elp:
    mov     eax, dword ptr [rbp-28]
    cmp     eax, dword ptr [rbp-24]
    jae     zbj_edone
    lea     r10, [g_sel]                        ; export selection: skip unchecked entries
    movzx   ecx, byte ptr [r10+rax]
    test    ecx, ecx
    je      zbj_eskip
    cmp     dword ptr [rbp-56], 0               ; comma before every emitted entry but the 1st
    jne     zbj_e0
    lea     rcx, [g_json]
    mov     dl, ','
    call    buf_putb
zbj_e0:
    mov     dword ptr [rbp-56], 0
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
    mov     eax, dword ptr [g_zj_fld]           ; never export the reserved history field
    and     eax, 0FFh
    cmp     eax, VF_PWHIST_
    je      zbj_fnext
    ; image/file fields are emitted too, but their value carries the ZIP path
    ; (<title>/<filename>) that ze_add_attachments uses - so import can reconnect
    ; each attachment to its record.
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
    ; value: attachment fields -> the ZIP path, everything else -> the raw value
    mov     eax, dword ptr [g_zj_fld]
    cmp     eax, VF_IMAGE_
    je      zbj_attval
    cmp     eax, VF_FILE_
    je      zbj_attval
    lea     rcx, [g_json]
    mov     rdx, qword ptr [g_zj_fld+24]
    mov     r8, qword ptr [g_zj_fld+32]
    call    json_str
    jmp     zbj_valdone
zbj_attval:
    mov     ecx, dword ptr [rbp-28]             ; entry
    mov     rdx, qword ptr [g_zj_fld+24]        ; value ptr
    mov     r8d, dword ptr [g_zj_fld+32]        ; value len
    call    ze_att_zippath                      ; eax = pathlen, path in g_zj_path
    lea     rcx, [g_json]
    lea     rdx, [g_zj_path]
    mov     r8d, eax
    call    json_str
zbj_valdone:
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
zbj_eskip:
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
; (ze_pathsan was removed: attachment folders are now opaque 8-hex entry ids built
;  inline in ze_att_zippath, so no user-controlled text - and in particular no
;  entry title - is ever placed in a cleartext ZIP member name.)

; =============================================================================
; ze_att_zippath(ecx = entry index, rdx = attachment value ptr, r8d = value len)
;   -> eax = path byte length; the path "<sanitized title>/<filename>" is written
;   into g_zj_path.  The serialized value is {AttachRef[68], filename wide}; the
;   filename lives at value+68 (default "attachment.bin" when absent).  This is
;   THE single source of the export path so the JSON/CSV references and the actual
;   ZIP member name always agree.
; =============================================================================
public ze_att_zippath
ze_att_zippath proc frame
    FRAME_PROLOG 128
    mov     dword ptr [rbp-24], ecx             ; entry
    mov     qword ptr [rbp-32], rdx             ; value ptr
    mov     dword ptr [rbp-40], r8d             ; value len
    ; ---- filename (wide) at value+68 -> UTF-8 g_zj_fn (default if none) ----
    cmp     dword ptr [rbp-40], 68
    jbe     azp_def
    mov     r11, qword ptr [rbp-32]
    lea     rax, [r11+68]
    mov     qword ptr [rbp-72], rax
    WINCALL WideCharToMultiByte, CP_UTF8_, 0, qword ptr [rbp-72], -1, addr g_zj_fn, 500, 0, 0
    dec     eax                                  ; strip the terminating NUL
    cmp     eax, 0
    jg      azp_havefn
azp_def:
    lea     r10, [zj_defname]
    lea     r11, [g_zj_fn]
    xor     r8d, r8d
azp_dcp:
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8d
    cmp     r8d, 14
    jb      azp_dcp
    mov     eax, 14
azp_havefn:
    mov     dword ptr [rbp-48], eax             ; fnlen
    ; ---- opaque per-entry folder (8 hex of the entry index) + '/' ----
    ; The entry TITLE must never appear in a cleartext ZIP member name (WinZip-AES
    ; leaves member names unencrypted, so a title folder leaked secrets like "Swiss
    ; Bank" to anyone holding the archive).  A unique but non-identifying id keeps
    ; the JSON reference and the actual member name in agreement (both come from
    ; here) while disclosing nothing; the real title stays inside encrypted json.
    mov     eax, dword ptr [rbp-24]             ; entry index
    lea     r10, [g_zj_path]
    mov     ecx, 8                              ; 8 hex digits, most-significant first
azp_hex:
    mov     edx, eax
    shr     edx, 28
    and     edx, 0Fh
    cmp     edx, 10
    jb      azp_hd
    add     edx, 'a'-10
    jmp     azp_hput
azp_hd:
    add     edx, '0'
azp_hput:
    mov     byte ptr [r10], dl
    inc     r10
    shl     eax, 4
    dec     ecx
    jnz     azp_hex
    mov     byte ptr [r10], '/'
    mov     eax, 9                              ; prefix length = 8 hex + '/'
    mov     dword ptr [rbp-56], eax
    ; ---- append the filename bytes ----
    lea     r10, [g_zj_path]
    add     r10, rax
    lea     r11, [g_zj_fn]
    mov     ecx, dword ptr [rbp-48]             ; fnlen
    xor     r8d, r8d
azp_cp:
    cmp     r8d, ecx
    jae     azp_cpd
    mov     al, byte ptr [r11+r8]
    mov     byte ptr [r10+r8], al
    inc     r8d
    jmp     azp_cp
azp_cpd:
    mov     eax, dword ptr [rbp-56]
    add     eax, dword ptr [rbp-48]             ; pathlen = prefix + fnlen
    FRAME_EPILOG
    ret
ze_att_zippath endp

; =============================================================================
; ze_add_attachments() -> eax 0/err.  Append every image/file attachment in the
;   vault to the open archive (ze_reset + ze_set_pw must precede).  Each blob is
;   decrypted to plaintext and added as "<secret title>/<filename>" (so all of a
;   record's attachments land in one folder), then wiped + freed.  The same path
;   is recorded in the data file by ze_build_json (ze_att_zippath).
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
    ; the serialized value is {AttachRef[68], filename wide} - AttachRef at +0.
    mov     r11, qword ptr [g_zj_fld+24]        ; value ptr
    mov     qword ptr [rbp-64], r11
    mov     eax, dword ptr [g_zj_fld+32]        ; value len
    mov     dword ptr [rbp-96], eax
    mov     rcx, r11                             ; AttachRef = value + 0
    lea     rdx, [rbp-72]                        ; &outlen
    call    attach_open
    test    rax, rax
    jz      zea_fnext
    mov     qword ptr [rbp-80], rax             ; plaintext ptr
    mov     ecx, dword ptr [rbp-44]             ; build "<title>/<filename>"
    mov     rdx, qword ptr [rbp-64]
    mov     r8d, dword ptr [rbp-96]
    call    ze_att_zippath                      ; eax = pathlen (path in g_zj_path)
    lea     rcx, [g_zj_path]
    mov     edx, eax
    mov     r8, qword ptr [rbp-80]
    mov     r9, qword ptr [rbp-72]
    call    ze_add_file
    mov     rcx, qword ptr [rbp-80]              ; wipe plaintext (holds secret bytes)
    mov     rdx, qword ptr [rbp-72]              ; before returning it to the heap
    call    secure_zero
    mov     rcx, qword ptr [rbp-80]
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




; =============================================================================

public ze_compose
; ze_compose(rcx = wide pw, edx = pw bytes) -> eax 0 ok / 1 error.  Builds the one
;   supported archive: an AES-256 encrypted ZIP holding vordr.json (all tiles of
;   the selected entries, history excluded) + every attachment.
ze_compose proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx             ; wide pw
    mov     dword ptr [rbp-32], edx             ; pw bytes
    mov     eax, dword ptr [rbp-32]
    shr     eax, 1                              ; wide chars
    mov     r9d, eax                            ; stage cchWideChar in r9d (WINCALL rax footgun)
    WINCALL WideCharToMultiByte, CP_UTF8_, 0, qword ptr [rbp-24], r9d, addr g_ze_u8pw, 500, 0, 0
    mov     dword ptr [rbp-44], eax             ; UTF-8 length
    call    ze_reset
    test    eax, eax
    jnz     comp_err
    lea     rcx, [g_ze_u8pw]
    mov     edx, dword ptr [rbp-44]
    call    ze_set_pw
    call    ze_build_json                       ; all tiles, history excluded
    test    eax, eax
    jnz     comp_ziperr
    lea     rcx, [zj_jsonname]
    mov     edx, 10
    lea     r10, [g_json]
    mov     r8, qword ptr [r10]
    mov     r9, qword ptr [r10+8]
    call    ze_add_file
    lea     r10, [g_json]                       ; wipe the plaintext json (every field value
    mov     rcx, qword ptr [r10]                ; of every exported entry) before freeing it
    mov     rdx, qword ptr [r10+16]
    call    secure_zero
    lea     r10, [g_json]
    mov     rcx, qword ptr [r10]
    mov     rdx, qword ptr [r10+16]
    call    mem_free
    call    ze_add_attachments                  ; every image/file, path recorded in json
    test    eax, eax
    jnz     comp_ziperr
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


; ---------------------------------------------------------------------------
; Byte-buffer append helpers (moved from the removed xlexport.asm; the
; encrypted-zip builder is now their only user).  Buffer desc = {ptr,len,cap}.
; ---------------------------------------------------------------------------
buf_putb proc
    mov     rax, qword ptr [rcx+8]
    cmp     rax, qword ptr [rcx+16]
    jae     bpb_over
    mov     r10, qword ptr [rcx]
    mov     byte ptr [r10+rax], dl
    inc     qword ptr [rcx+8]
    ret
bpb_over:
    mov     byte ptr [g_xl_err], 1
    ret
buf_putb endp

; buf_putn(rcx=desc, rdx=src, r8=len)                                          leaf
buf_putn proc
    test    r8, r8
    jz      bpn_ret
    mov     rax, qword ptr [rcx+8]
    mov     r9, rax
    add     r9, r8
    cmp     r9, qword ptr [rcx+16]
    ja      bpn_over
    mov     r10, qword ptr [rcx]
    add     r10, rax
    xor     r11, r11
bpn_lp:
    mov     r9b, byte ptr [rdx+r11]
    mov     byte ptr [r10+r11], r9b
    inc     r11
    cmp     r11, r8
    jb      bpn_lp
    add     qword ptr [rcx+8], r8
bpn_ret:
    ret
bpn_over:
    mov     byte ptr [g_xl_err], 1
    ret
buf_putn endp

; buf_pu16(rcx=desc, edx=val)                                                  leaf
buf_pu16 proc
    mov     rax, qword ptr [rcx+8]
    mov     r9, rax
    add     r9, 2
    cmp     r9, qword ptr [rcx+16]
    ja      bp16_over
    mov     r10, qword ptr [rcx]
    mov     byte ptr [r10+rax], dl
    shr     edx, 8
    mov     byte ptr [r10+rax+1], dl
    add     qword ptr [rcx+8], 2
    ret
bp16_over:
    mov     byte ptr [g_xl_err], 1
    ret
buf_pu16 endp

; buf_pu32(rcx=desc, edx=val)                                                  leaf
buf_pu32 proc
    mov     rax, qword ptr [rcx+8]
    mov     r9, rax
    add     r9, 4
    cmp     r9, qword ptr [rcx+16]
    ja      bp32_over
    mov     r10, qword ptr [rcx]
    mov     byte ptr [r10+rax], dl
    shr     edx, 8
    mov     byte ptr [r10+rax+1], dl
    shr     edx, 8
    mov     byte ptr [r10+rax+2], dl
    shr     edx, 8
    mov     byte ptr [r10+rax+3], dl
    add     qword ptr [rcx+8], 4
    ret
bp32_over:
    mov     byte ptr [g_xl_err], 1
    ret
buf_pu32 endp

; buf_putcstr(rcx=desc, rdx=cstr)                                              leaf
buf_putcstr proc
bpc_lp:
    mov     r8b, byte ptr [rdx]
    test    r8b, r8b
    jz      bpc_ret
    mov     rax, qword ptr [rcx+8]
    cmp     rax, qword ptr [rcx+16]
    jae     bpc_over
    mov     r10, qword ptr [rcx]
    mov     byte ptr [r10+rax], r8b
    inc     qword ptr [rcx+8]
    inc     rdx
    jmp     bpc_lp
bpc_ret:
    ret
bpc_over:
    mov     byte ptr [g_xl_err], 1
    ret
buf_putcstr endp

; buf_pu32dec(rcx=desc, edx=val) - append value in decimal
buf_pu32dec proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     eax, edx                         ; value
    lea     r9, [rbp-32]                     ; one past a 16-byte digit scratch
    mov     r8d, 10
    test    eax, eax
    jnz     bpd_lp
    dec     r9
    mov     byte ptr [r9], '0'
    jmp     bpd_emit
bpd_lp:
    xor     edx, edx
    div     r8d
    add     dl, '0'
    dec     r9
    mov     byte ptr [r9], dl
    test    eax, eax
    jnz     bpd_lp
bpd_emit:
    lea     rax, [rbp-32]
    sub     rax, r9                          ; length
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, r9
    mov     r8, rax
    call    buf_putn
    FRAME_EPILOG
    ret
buf_pu32dec endp

end
