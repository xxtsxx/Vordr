; =============================================================================
; zipimport.asm - import a Vordr WinZip-AE-2 (AES-256) encrypted .zip produced by
; zipexport.asm: decrypt the members, parse the vordr.json data file, and rebuild
; every record (all fields + attachments) into the open vault.
;
;   zi_import(rcx=raw, edx=rawlen, r8=wide pw ptr, r9d=pw bytes) -> eax
;       >=0  entries imported
;       -3   wrong password
;       -1   not a readable Vordr zip / error
;
; The archive is: repeated local file headers, each STORE-inside-AES (method 99),
; body = salt(16) | pwverify(2) | AES-256-CTR ciphertext(usize) | HMAC-SHA1(10).
; Attachments are members named "<title>/<filename>"; the json references them by
; that path in image/file field values, so each is decrypted + re-staged.
; =============================================================================

include macros.inc

extern mem_alloc:proc
extern mem_free:proc
extern secure_zero:proc
extern pbkdf2_ae:proc                    ; PBKDF2-HMAC-SHA1 1000 iters -> g_ae_dk
extern aes_expand_key:proc
extern aes_ctr_xor:proc
extern MultiByteToWideChar:proc
extern WideCharToMultiByte:proc
extern attach_reset:proc
extern attach_stage:proc
extern vault_build_entry:proc
extern csv_to_wide:proc                  ; vordr.csv route
extern csv_import_buffer:proc
extern xlsx_import:proc                  ; vordr.xlsx route
externdef g_ae_dk:byte
externdef g_field_list:qword
externdef g_field_n:dword
externdef g_csv_alloc:qword

ARF_SIZE    equ 68
CP_UTF8_    equ 65001
ZI_MAXMEM   equ 8192                      ; max archive members
ZI_ARENA    equ 4*1024*1024              ; per-entry wide/blob scratch
ZI_SBUF     equ 256*1024                  ; one string's decoded UTF-8
MEMREC      equ 32                        ; {nameptr8, namelen4, _4, dataptr8, usize4, _4}

.data?
align 8
g_zi_end    dq ?                          ; raw end
g_zi_pwptr  dq ?                          ; UTF-8 pw ptr (= g_zi_u8pw)
g_zi_pwlen  dd ?
g_zi_u8pw   db 512 dup (?)
g_zi_n      dd ?                          ; member count
g_zi_mem    db ZI_MAXMEM * MEMREC dup (?)
g_zi_rk     db 15*16 dup (?)
g_zi_ctr    db 16 dup (?)
g_zi_auth   db 20 dup (?)
g_zi_nr     dd ?
g_zi_arena  dq ?                          ; heap arena ptr
g_zi_ap     dd ?                          ; arena bump offset
g_zi_sbuf   db ZI_SBUF dup (?)            ; decoded-string scratch (UTF-8)
g_zi_ref    db ARF_SIZE dup (?)           ; attach_stage AttachRef out
g_zi_p      dq ?                          ; json parse cursor
g_zi_jend   dq ?
g_zi_count  dd ?
g_zi_slot   dd ?                          ; zi_addattach: field slot
g_zi_atype  dd ?                          ; zi_addattach: base type (9/10)
g_zi_alabel dq ?                          ; zi_addattach: label wide (0/none)

.const
zi_jsonname db "vordr.json"
zi_csvname  db "vordr.csv"
zi_xlsxname db "vordr.xlsx"
zl_title    db '"title":'
zl_fields   db ',"fields":['
zl_type     db '"type":'
zl_label    db ',"label":'
zl_value    db ',"value":'

.code

; =============================================================================
; zi_scan(rcx = raw, edx = rawlen) -> eax = member count.  Walk the local file
;   headers into g_zi_mem; stop at the central directory / EOCD.
; =============================================================================
zi_scan proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx             ; p (current header)
    mov     eax, edx
    add     rax, rcx
    mov     qword ptr [g_zi_end], rax           ; raw end
    xor     r10d, r10d                          ; n
zs_lp:
    mov     rcx, qword ptr [rbp-24]
    lea     rax, [rcx+30]
    cmp     rax, qword ptr [g_zi_end]
    ja      zs_done
    cmp     dword ptr [rcx], 04034b50h          ; local file header sig?
    jne     zs_done
    movzx   r8d, word ptr [rcx+26]              ; namelen
    movzx   r9d, word ptr [rcx+28]              ; extralen
    mov     eax, dword ptr [rcx+18]             ; csize
    mov     dword ptr [rbp-28], eax
    mov     eax, dword ptr [rcx+22]             ; usize
    mov     dword ptr [rbp-32], eax
    lea     r11, [rcx+30]                       ; nameptr
    ; dataptr = p + 30 + namelen + extralen
    lea     rax, [rcx+30]
    add     rax, r8
    add     rax, r9
    mov     qword ptr [rbp-40], rax             ; dataptr
    ; record
    mov     eax, r10d
    imul    eax, eax, MEMREC
    lea     rcx, [g_zi_mem]
    add     rcx, rax
    mov     qword ptr [rcx+0], r11              ; nameptr
    mov     dword ptr [rcx+8], r8d              ; namelen
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [rcx+16], rax             ; dataptr
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [rcx+24], eax             ; usize
    inc     r10d
    ; advance p = dataptr + csize
    mov     rcx, qword ptr [rbp-40]             ; dataptr
    mov     eax, dword ptr [rbp-28]             ; csize (zero-extended)
    add     rcx, rax
    mov     qword ptr [rbp-24], rcx
    cmp     r10d, ZI_MAXMEM
    jae     zs_done
    jmp     zs_lp
zs_done:
    mov     dword ptr [g_zi_n], r10d
    mov     eax, r10d
    FRAME_EPILOG
    ret
zi_scan endp

; =============================================================================
; zi_find(rcx = name UTF-8, edx = namelen) -> eax = member index or -1.
; =============================================================================
zi_find proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-28], edx
    xor     r10d, r10d                          ; i
zf_lp:
    cmp     r10d, dword ptr [g_zi_n]
    jae     zf_none
    mov     eax, r10d
    imul    eax, eax, MEMREC
    lea     r11, [g_zi_mem]
    add     r11, rax
    mov     eax, dword ptr [r11+8]              ; namelen
    cmp     eax, dword ptr [rbp-28]
    jne     zf_next
    ; memcmp
    mov     r8, qword ptr [r11+0]               ; member name
    mov     r9, qword ptr [rbp-24]              ; wanted
    xor     ecx, ecx
zf_cmp:
    cmp     ecx, dword ptr [rbp-28]
    jae     zf_hit
    mov     al, byte ptr [r8+rcx]
    cmp     al, byte ptr [r9+rcx]
    jne     zf_next
    inc     ecx
    jmp     zf_cmp
zf_hit:
    mov     eax, r10d
    FRAME_EPILOG
    ret
zf_next:
    inc     r10d
    jmp     zf_lp
zf_none:
    mov     eax, -1
    FRAME_EPILOG
    ret
zi_find endp

; =============================================================================
; zi_decrypt(ecx = member index) -> eax = 0 ok / -3 wrong pw / -1 corrupt.
;   Verifies the 2-byte password check + the HMAC, then AES-256-CTR decrypts the
;   ciphertext IN PLACE.  Plaintext = member.dataptr+18, length member.usize.
; =============================================================================
zi_decrypt proc frame
    FRAME_PROLOG 96                             ; room for 5-arg WINCALL arg spill
    mov     eax, ecx
    imul    eax, eax, MEMREC
    lea     r10, [g_zi_mem]
    add     r10, rax
    mov     rax, qword ptr [r10+16]             ; dataptr (salt)
    mov     qword ptr [rbp-24], rax             ; salt
    mov     eax, dword ptr [r10+24]             ; usize
    mov     dword ptr [rbp-32], eax
    ; cipher = salt+18 ; auth = cipher+usize
    mov     rax, qword ptr [rbp-24]
    add     rax, 18
    mov     qword ptr [rbp-40], rax             ; cipher ptr
    ; ---- PBKDF2(pw, salt, 16) -> g_ae_dk ----
    mov     rcx, qword ptr [g_zi_pwptr]
    mov     edx, dword ptr [g_zi_pwlen]
    mov     r8, qword ptr [rbp-24]              ; salt
    mov     r9d, 16
    call    pbkdf2_ae
    ; ---- 2-byte password verifier: g_ae_dk[64..66] vs salt[16..18] ----
    lea     r10, [g_ae_dk]
    mov     r11, qword ptr [rbp-24]
    mov     al, byte ptr [r10+64]
    cmp     al, byte ptr [r11+16]
    jne     zd_wrongpw
    mov     al, byte ptr [r10+65]
    cmp     al, byte ptr [r11+17]
    jne     zd_wrongpw
    ; ---- AES-256-CTR decrypt in place ----
    lea     rcx, [g_ae_dk]
    mov     rdx, 32
    lea     r8, [g_zi_rk]
    call    aes_expand_key
    mov     dword ptr [g_zi_nr], eax
    lea     rcx, [g_zi_ctr]                     ; counter := 0
    xor     eax, eax
    mov     qword ptr [rcx], rax
    mov     qword ptr [rcx+8], rax
    WINCALL aes_ctr_xor, addr g_zi_rk, qword ptr [rbp-40], dword ptr [rbp-32], \
            addr g_zi_ctr, dword ptr [g_zi_nr]
    xor     eax, eax
    FRAME_EPILOG
    ret
zd_wrongpw:
    mov     eax, -3
    FRAME_EPILOG
    ret
zi_decrypt endp

; zi_plain(ecx = member index) -> rax = plaintext ptr, edx = length.  (After a
;   successful zi_decrypt: the ciphertext region now holds plaintext.)
zi_plain proc
    mov     eax, ecx
    imul    eax, eax, MEMREC
    lea     r10, [g_zi_mem]
    add     r10, rax
    mov     rax, qword ptr [r10+16]
    add     rax, 18
    mov     edx, dword ptr [r10+24]
    ret
zi_plain endp

; =============================================================================
; zi_u2w(rcx = src UTF-8, edx = srclen) -> rax = NUL-terminated wide ptr in the
;   arena (advances g_zi_ap).  Empty input yields an empty wide string.
; =============================================================================
zi_u2w proc frame
    FRAME_PROLOG 96                             ; room for 6-arg MBtoWC arg spill
    mov     qword ptr [rbp-24], rcx             ; src
    mov     dword ptr [rbp-28], edx             ; srclen
    mov     r10, qword ptr [g_zi_arena]         ; dst = arena + ap
    mov     eax, dword ptr [g_zi_ap]
    add     r10, rax
    mov     qword ptr [rbp-40], r10             ; dst
    ; cap (wchars) = (ZI_ARENA - ap - 2) / 2
    mov     ecx, ZI_ARENA
    sub     ecx, dword ptr [g_zi_ap]
    sub     ecx, 2
    shr     ecx, 1
    mov     dword ptr [rbp-44], ecx             ; wide cap
    cmp     dword ptr [rbp-28], 0
    je      zw_empty
    WINCALL MultiByteToWideChar, CP_UTF8_, 0, qword ptr [rbp-24], dword ptr [rbp-28], \
            qword ptr [rbp-40], dword ptr [rbp-44]
    jmp     zw_term
zw_empty:
    xor     eax, eax
zw_term:
    ; NUL-terminate + advance ap by (wchars+1)*2
    mov     r10, qword ptr [rbp-40]
    mov     word ptr [r10+rax*2], 0
    inc     eax
    lea     eax, [eax*2]
    add     dword ptr [g_zi_ap], eax
    mov     rax, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
zi_u2w endp

; zj_lit(rcx = literal bytes, edx = len) -> eax = 1 if g_zi_p matches (and is
;   advanced past it), else 0.  Leaf.
zj_lit proc
    mov     r10, qword ptr [g_zi_p]
    xor     r8d, r8d
zjl_lp:
    cmp     r8d, edx
    jae     zjl_ok
    mov     r9, r10
    add     r9, r8
    cmp     r9, qword ptr [g_zi_jend]
    jae     zjl_no
    mov     al, byte ptr [rcx+r8]
    cmp     al, byte ptr [r10+r8]
    jne     zjl_no
    inc     r8d
    jmp     zjl_lp
zjl_ok:
    add     r10, r8
    mov     qword ptr [g_zi_p], r10
    mov     eax, 1
    ret
zjl_no:
    xor     eax, eax
    ret
zj_lit endp

; zj_num() -> eax = parsed unsigned integer at g_zi_p (advances past digits).  Leaf.
zj_num proc
    mov     r10, qword ptr [g_zi_p]
    xor     eax, eax
zjn_lp:
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjn_done
    movzx   r8d, byte ptr [r10]
    cmp     r8d, '0'
    jb      zjn_done
    cmp     r8d, '9'
    ja      zjn_done
    imul    eax, eax, 10
    sub     r8d, '0'
    add     eax, r8d
    inc     r10
    jmp     zjn_lp
zjn_done:
    mov     qword ptr [g_zi_p], r10
    ret
zj_num endp

; =============================================================================
; zj_str(rcx = dst UTF-8) -> eax = decoded byte length.  g_zi_p must point at the
;   opening quote; decodes JSON escapes and advances past the closing quote.
; =============================================================================
zj_str proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx             ; dst
    xor     r11d, r11d                          ; out len
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_end
    cmp     byte ptr [r10], '"'
    jne     zjs_end
    inc     r10                                 ; past opening quote
zjs_lp:
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_end
    movzx   eax, byte ptr [r10]
    cmp     eax, '"'
    je      zjs_close
    cmp     eax, '\'
    je      zjs_esc
    ; literal byte
    mov     rcx, qword ptr [rbp-24]
    mov     byte ptr [rcx+r11], al
    inc     r11d
    inc     r10
    jmp     zjs_lp
zjs_esc:
    inc     r10                                 ; past backslash
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_end
    movzx   eax, byte ptr [r10]
    inc     r10
    cmp     eax, 'n'
    je      zjs_e_n
    cmp     eax, 'r'
    je      zjs_e_r
    cmp     eax, 't'
    je      zjs_e_t
    cmp     eax, 'b'
    je      zjs_e_b
    cmp     eax, 'f'
    je      zjs_e_f
    cmp     eax, 'u'
    je      zjs_e_u
    ; \" \\ \/ and any other -> the literal char in eax
    jmp     zjs_put
zjs_e_n:
    mov     eax, 0Ah
    jmp     zjs_put
zjs_e_r:
    mov     eax, 0Dh
    jmp     zjs_put
zjs_e_t:
    mov     eax, 09h
    jmp     zjs_put
zjs_e_b:
    mov     eax, 08h
    jmp     zjs_put
zjs_e_f:
    mov     eax, 0Ch
    jmp     zjs_put
zjs_put:
    mov     rcx, qword ptr [rbp-24]
    mov     byte ptr [rcx+r11], al
    inc     r11d
    jmp     zjs_lp
zjs_e_u:
    ; read 4 hex digits -> codepoint in edx, UTF-8 encode
    xor     edx, edx
    mov     r9d, 4
zjs_uhex:
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjs_end
    movzx   eax, byte ptr [r10]
    inc     r10
    shl     edx, 4
    cmp     eax, '9'
    jbe     zjs_udig
    or      eax, 20h                            ; lower-case
    sub     eax, 'a'-10
    jmp     zjs_uadd
zjs_udig:
    sub     eax, '0'
zjs_uadd:
    and     eax, 0Fh
    or      edx, eax
    dec     r9d
    jnz     zjs_uhex
    ; UTF-8 encode edx (BMP) into dst
    mov     rcx, qword ptr [rbp-24]
    cmp     edx, 80h
    jae     zjs_u2
    mov     byte ptr [rcx+r11], dl              ; 1 byte
    inc     r11d
    jmp     zjs_lp
zjs_u2:
    cmp     edx, 800h
    jae     zjs_u3
    mov     eax, edx                            ; 2 bytes: 110xxxxx 10xxxxxx
    shr     eax, 6
    or      eax, 0C0h
    mov     byte ptr [rcx+r11], al
    inc     r11d
    mov     eax, edx
    and     eax, 3Fh
    or      eax, 80h
    mov     byte ptr [rcx+r11], al
    inc     r11d
    jmp     zjs_lp
zjs_u3:
    mov     eax, edx                            ; 3 bytes: 1110xxxx 10xxxxxx 10xxxxxx
    shr     eax, 12
    or      eax, 0E0h
    mov     byte ptr [rcx+r11], al
    inc     r11d
    mov     eax, edx
    shr     eax, 6
    and     eax, 3Fh
    or      eax, 80h
    mov     byte ptr [rcx+r11], al
    inc     r11d
    mov     eax, edx
    and     eax, 3Fh
    or      eax, 80h
    mov     byte ptr [rcx+r11], al
    inc     r11d
    jmp     zjs_lp
zjs_close:
    inc     r10                                 ; past closing quote
zjs_end:
    mov     qword ptr [g_zi_p], r10
    mov     eax, r11d
    FRAME_EPILOG
    ret
zj_str endp

; zj_skipch(al = char) - if *g_zi_p == char, advance past it.  Leaf.
zj_skipch proc
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zjc_done
    cmp     byte ptr [r10], al
    jne     zjc_done
    inc     r10
    mov     qword ptr [g_zi_p], r10
zjc_done:
    ret
zj_skipch endp

; =============================================================================
; zi_addattach(ecx = base type 9/10, rdx = label wide (0/none), r8 = path UTF-8,
;   r9d = pathlen, [rbp+? via mem] n) - decrypt the referenced member, stage it,
;   and write g_field_list[n] as a VFL_RAW {AttachRef, filename} field.
;   -> eax = 1 field added / 0 skipped (missing / undecryptable attachment).
;   n (field slot) passed in g_zi_slot.
; =============================================================================
zi_addattach proc frame
    FRAME_PROLOG 128                            ; room for 6-arg MBtoWC arg spill
    mov     dword ptr [g_zi_atype], ecx
    mov     qword ptr [g_zi_alabel], rdx
    mov     qword ptr [rbp-24], r8              ; path
    mov     dword ptr [rbp-28], r9d             ; pathlen
    ; find the member
    mov     rcx, r8
    mov     edx, r9d
    call    zi_find
    cmp     eax, -1
    je      za_skip
    mov     dword ptr [rbp-32], eax             ; member idx
    mov     ecx, eax
    call    zi_decrypt
    test    eax, eax
    jnz     za_skip
    mov     ecx, dword ptr [rbp-32]
    call    zi_plain                            ; rax=ptr edx=len
    mov     qword ptr [rbp-40], rax
    mov     dword ptr [rbp-44], edx
    ; stage the plaintext -> g_zi_ref
    mov     rcx, rax
    mov     edx, dword ptr [rbp-44]
    lea     r8, [g_zi_ref]
    call    attach_stage
    test    eax, eax
    jnz     za_skip
    ; filename = basename(path) (after the last '/')
    mov     r10, qword ptr [rbp-24]             ; path
    mov     r8d, dword ptr [rbp-28]             ; pathlen
    mov     ecx, r8d                            ; start = pathlen
    xor     r9d, r9d                            ; last-slash+1 = 0
zaf_scan:
    test    ecx, ecx
    jz      zaf_done
    dec     ecx
    cmp     byte ptr [r10+rcx], '/'
    jne     zaf_scan
    lea     r9d, [rcx+1]                        ; base starts after '/'
zaf_done:
    mov     eax, r8d
    sub     eax, r9d                            ; fnlen = pathlen - base
    mov     dword ptr [rbp-48], eax             ; fnlen
    mov     r10, qword ptr [rbp-24]
    add     r10, r9                             ; fnptr
    mov     qword ptr [rbp-56], r10
    ; build blob in arena: {u32 rawlen, AttachRef[68], filename wide (NUL-term)}
    mov     r11, qword ptr [g_zi_arena]
    mov     eax, dword ptr [g_zi_ap]
    add     r11, rax
    mov     qword ptr [rbp-64], r11             ; blob base
    ; copy AttachRef into blob+4
    lea     rax, [r11+4]
    lea     r8, [g_zi_ref]
    xor     ecx, ecx
za_cpref:
    mov     dl, byte ptr [r8+rcx]
    mov     byte ptr [rax+rcx], dl
    inc     ecx
    cmp     ecx, ARF_SIZE
    jb      za_cpref
    ; append the filename as wide (convert), directly after AttachRef
    ; wide dst = blob + 4 + 68
    mov     r10, qword ptr [rbp-64]
    lea     r10, [r10+4+ARF_SIZE]
    mov     qword ptr [rbp-40], r10             ; wide dst (reuse -40)
    WINCALL MultiByteToWideChar, CP_UTF8_, 0, qword ptr [rbp-56], dword ptr [rbp-48], \
            qword ptr [rbp-40], 255
    ; NUL-terminate the wide filename
    mov     r10, qword ptr [rbp-40]
    mov     word ptr [r10+rax*2], 0
    inc     eax                                 ; wchars incl NUL
    lea     eax, [eax*2]                        ; filename bytes
    ; rawlen = ARF_SIZE + filename bytes
    add     eax, ARF_SIZE
    mov     r11, qword ptr [rbp-64]
    mov     dword ptr [r11], eax                ; u32 rawlen
    ; advance ap by 4 + rawlen
    add     eax, 4
    add     dword ptr [g_zi_ap], eax
    ; write g_field_list[slot] = {type|VFL_RAW, label, blob}
    mov     eax, dword ptr [g_zi_slot]
    imul    eax, eax, 24
    lea     r10, [g_field_list]
    add     r10, rax
    mov     ecx, dword ptr [g_zi_atype]
    or      ecx, VFL_RAW
    mov     qword ptr [r10+0], rcx
    mov     rax, qword ptr [g_zi_alabel]
    mov     qword ptr [r10+8], rax
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [r10+16], rax
    mov     eax, 1
    FRAME_EPILOG
    ret
za_skip:
    xor     eax, eax
    FRAME_EPILOG
    ret
zi_addattach endp

; =============================================================================
; zi_import_json(rcx = json ptr, edx = json len) -> eax = entries imported.
; =============================================================================
zi_import_json proc frame
    FRAME_PROLOG 96
    mov     qword ptr [g_zi_p], rcx
    mov     eax, edx
    add     rax, rcx
    mov     qword ptr [g_zi_jend], rax
    mov     dword ptr [g_zi_count], 0
    mov     al, '['
    call    zj_skipch
zij_entry:
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_done
    movzx   eax, byte ptr [r10]
    cmp     eax, ']'
    je      zij_done
    cmp     eax, ','
    jne     zij_e0
    inc     r10
    mov     qword ptr [g_zi_p], r10
zij_e0:
    mov     al, '{'
    call    zj_skipch
    lea     rcx, [zl_title]                     ; "title": (skip the redundant value)
    mov     edx, 8
    call    zj_lit
    lea     rcx, [g_zi_sbuf]
    call    zj_str
    lea     rcx, [zl_fields]                    ; ,"fields":[
    mov     edx, 11
    call    zj_lit
    mov     dword ptr [g_zi_ap], 0              ; fresh arena for this entry
    mov     dword ptr [rbp-24], 0               ; n (field slot)
zij_field:
    mov     r10, qword ptr [g_zi_p]
    cmp     r10, qword ptr [g_zi_jend]
    jae     zij_fend
    movzx   eax, byte ptr [r10]
    cmp     eax, ']'
    je      zij_fend
    cmp     eax, ','
    jne     zij_f0
    inc     r10
    mov     qword ptr [g_zi_p], r10
zij_f0:
    mov     al, '{'
    call    zj_skipch
    lea     rcx, [zl_type]                      ; "type":
    mov     edx, 7
    call    zj_lit
    call    zj_num
    mov     dword ptr [rbp-28], eax             ; type
    lea     rcx, [zl_label]                     ; ,"label":
    mov     edx, 9
    call    zj_lit
    lea     rcx, [g_zi_sbuf]                    ; decode label -> sbuf
    call    zj_str
    mov     dword ptr [rbp-32], eax             ; labellen
    mov     qword ptr [rbp-40], 0               ; label wide (0 = none)
    test    eax, eax
    jz      zij_lbldone
    lea     rcx, [g_zi_sbuf]
    mov     edx, eax
    call    zi_u2w
    mov     qword ptr [rbp-40], rax             ; label wide
zij_lbldone:
    lea     rcx, [zl_value]                     ; ,"value":
    mov     edx, 9
    call    zj_lit
    lea     rcx, [g_zi_sbuf]                    ; decode value -> sbuf
    call    zj_str
    mov     dword ptr [rbp-48], eax             ; vallen
    mov     al, '}'
    call    zj_skipch
    ; ---- build the field ----
    mov     eax, dword ptr [rbp-28]             ; type
    cmp     eax, VF_IMAGE
    je      zij_att
    cmp     eax, VF_FILE
    je      zij_att
    ; text field: value UTF-8 -> wide
    lea     rcx, [g_zi_sbuf]
    mov     edx, dword ptr [rbp-48]
    call    zi_u2w                              ; rax = value wide
    mov     r10d, dword ptr [rbp-24]            ; slot
    imul    r10d, r10d, 24
    lea     r11, [g_field_list]
    add     r11, r10
    mov     ecx, dword ptr [rbp-28]
    mov     qword ptr [r11+0], rcx
    mov     rcx, qword ptr [rbp-40]             ; label wide
    mov     qword ptr [r11+8], rcx
    mov     qword ptr [r11+16], rax
    inc     dword ptr [rbp-24]
    jmp     zij_field
zij_att:
    ; attachment: value = zip path in g_zi_sbuf
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_zi_slot], eax
    mov     ecx, dword ptr [rbp-28]             ; base type
    mov     rdx, qword ptr [rbp-40]             ; label wide
    lea     r8, [g_zi_sbuf]                     ; path
    mov     r9d, dword ptr [rbp-48]             ; pathlen
    call    zi_addattach
    test    eax, eax
    jz      zij_field                           ; skipped -> slot unchanged
    inc     dword ptr [rbp-24]
    jmp     zij_field
zij_fend:
    mov     al, ']'
    call    zj_skipch
    mov     al, '}'
    call    zj_skipch
    ; commit the entry if it has a (title) field
    mov     eax, dword ptr [rbp-24]
    test    eax, eax
    jz      zij_entry
    mov     dword ptr [g_field_n], eax
    call    vault_build_entry
    test    eax, eax
    jnz     zij_entry
    inc     dword ptr [g_zi_count]
    jmp     zij_entry
zij_done:
    mov     eax, dword ptr [g_zi_count]
    FRAME_EPILOG
    ret
zi_import_json endp

; =============================================================================
; zi_import(rcx=raw, edx=rawlen, r8=wide pw, r9d=pw bytes) -> eax
;   >=0 imported / -3 wrong pw / -1 not a Vordr zip / error.
; =============================================================================
public zi_import
zi_import proc frame
    FRAME_PROLOG 160                            ; room for the 8-arg WCtoMB arg spill
    mov     qword ptr [rbp-24], rcx             ; raw
    mov     dword ptr [rbp-28], edx             ; rawlen
    ; wide pw -> UTF-8 g_zi_u8pw (stage count in r9d: WINCALL rax-clobber footgun)
    shr     r9d, 1                              ; wide chars
    mov     dword ptr [rbp-32], r9d
    WINCALL WideCharToMultiByte, CP_UTF8_, 0, r8, dword ptr [rbp-32], addr g_zi_u8pw, 500, 0, 0
    mov     dword ptr [g_zi_pwlen], eax
    lea     rax, [g_zi_u8pw]
    mov     qword ptr [g_zi_pwptr], rax
    ; allocate the per-entry arena
    mov     rcx, ZI_ARENA
    call    mem_alloc
    test    rax, rax
    jz      zim_err
    mov     qword ptr [g_zi_arena], rax
    ; scan members
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-28]
    call    zi_scan
    call    attach_reset                        ; start fresh pending-attachment set
    ; find + route the data file
    lea     rcx, [zi_jsonname]
    mov     edx, 10
    call    zi_find
    cmp     eax, -1
    jne     zim_json
    lea     rcx, [zi_csvname]
    mov     edx, 9
    call    zi_find
    cmp     eax, -1
    jne     zim_csv
    lea     rcx, [zi_xlsxname]
    mov     edx, 10
    call    zi_find
    cmp     eax, -1
    jne     zim_xlsx
    mov     dword ptr [rbp-40], -1              ; no recognizable data file
    jmp     zim_free
zim_json:
    mov     dword ptr [rbp-36], eax             ; member idx
    mov     ecx, eax
    call    zi_decrypt
    test    eax, eax
    jz      zim_json_ok
    mov     dword ptr [rbp-40], eax             ; -3 wrong pw / -1 corrupt
    jmp     zim_free
zim_json_ok:
    mov     ecx, dword ptr [rbp-36]
    call    zi_plain
    mov     rcx, rax
    call    zi_import_json
    mov     dword ptr [rbp-40], eax
    jmp     zim_free
zim_csv:
    mov     dword ptr [rbp-36], eax
    mov     ecx, eax
    call    zi_decrypt
    test    eax, eax
    jz      zim_csv_ok
    mov     dword ptr [rbp-40], eax
    jmp     zim_free
zim_csv_ok:
    mov     ecx, dword ptr [rbp-36]
    call    zi_plain
    lea     r8, [rbp-48]                        ; *wptr
    lea     r9, [rbp-56]                        ; *wcount
    mov     rcx, rax
    call    csv_to_wide
    test    eax, eax
    jnz     zim_csv_fail
    mov     rcx, qword ptr [rbp-48]
    mov     edx, dword ptr [rbp-56]
    call    csv_import_buffer
    mov     dword ptr [rbp-40], eax
    cmp     qword ptr [g_csv_alloc], 0
    je      zim_free
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [g_csv_alloc]
    call    mem_free
    jmp     zim_free
zim_csv_fail:
    mov     dword ptr [rbp-40], -1
    jmp     zim_free
zim_xlsx:
    mov     dword ptr [rbp-36], eax
    mov     ecx, eax
    call    zi_decrypt
    test    eax, eax
    jz      zim_xlsx_ok
    mov     dword ptr [rbp-40], eax
    jmp     zim_free
zim_xlsx_ok:
    mov     ecx, dword ptr [rbp-36]
    call    zi_plain
    mov     rcx, rax
    call    xlsx_import
    mov     dword ptr [rbp-40], eax
zim_free:
    mov     rcx, qword ptr [g_zi_arena]
    test    rcx, rcx
    jz      zim_wipe
    mov     rdx, ZI_ARENA
    call    mem_free
    mov     qword ptr [g_zi_arena], 0
zim_wipe:
    lea     rcx, [g_zi_u8pw]                    ; wipe the UTF-8 password
    mov     edx, 512
    call    secure_zero
    mov     dword ptr [g_zi_pwlen], 0
    mov     eax, dword ptr [rbp-40]
    FRAME_EPILOG
    ret
zim_err:
    mov     eax, -1
    FRAME_EPILOG
    ret
zi_import endp

end
