; =============================================================================
; oleagile.asm - import from a password-protected (ECMA-376 agile) .xlsx.
;
;   xlsx_decrypt(rcx=raw, edx=rawlen, r8=wpw, r9d=pwbytes) -> eax
;       >=0 entries imported (delegated to xlsx_import on the decrypted zip)
;       -1  not a readable compound file / parse error
;       -3  wrong password (decrypted package is not a zip)
;
; An agile-encrypted workbook is an OLE2/CFBF compound file holding two streams:
;   EncryptionInfo   - XML: salts, spinCount, the password-encrypted package key
;   EncryptedPackage - LE64(size) then AES-256-CBC segments (4096 bytes each) of
;                      the real .xlsx zip.
;
; We read those streams (walking FAT / mini-FAT chains), derive the package key
; from the password (SHA-512 spin), CBC-decrypt the package into the inner zip,
; and hand that to xlsx_import.  Inverse of the encryptor in xlcrypt.asm;
; validated against Vordr-produced encrypted workbooks (msoffcrypto reference).
; =============================================================================

include macros.inc

extern sha512_hash:proc                 ; (rcx=msg, rdx=len, r8=out64)
extern aes_expand_key:proc              ; (rcx=key, rdx=keylen, r8=rkout) -> Nr
extern aes_ecb_decrypt:proc             ; (rcx=rk, rdx=io16, r8=Nr)
extern mem_alloc:proc                   ; (rcx=size) -> rax
extern mem_free:proc                    ; (rcx=ptr, rdx=size)
extern xlsx_import:proc                 ; (rcx=raw, edx=len) -> eax

ENDCHAIN   equ 0FFFFFFFEh

.const
bk_kv   db 014h,06eh,00bh,0e7h,0abh,0ach,0d0h,0d6h   ; blockKey: encryptedKeyValue
tag_kd  db "<keyData"
tag_ek  db "<p:encryptedKey"
n_salt  db "saltValue=",22h                          ; saltValue="
n_spin  db "spinCount=",22h
n_ekv   db "encryptedKeyValue=",22h
w_ei    dw 'E','n','c','r','y','p','t','i','o','n','I','n','f','o',0
w_ep    dw 'E','n','c','r','y','p','t','e','d','P','a','c','k','a','g','e',0

.data?
align 8
g_ol_raw    dq ?                        ; raw file bytes
g_ol_len    dd ?
g_ol_ssz    dd ?                        ; sector size
g_ol_mcut   dd ?                        ; mini-stream cutoff
g_ol_dir    dd ?                        ; first directory sector
g_ol_mfat   dd ?                        ; first mini-FAT sector
g_ol_nmfat  dd ?                        ; mini-FAT sector count
g_ol_dif0   dd ?                        ; first DIFAT sector
g_ol_ndif   dd ?                        ; DIFAT sector count
g_ms_ptr    dq ?                        ; mini-stream container
g_ms_cap    dd ?
g_mf_ptr    dq ?                        ; mini-FAT
g_mf_cap    dd ?
g_ei_ptr    dq ?                        ; EncryptionInfo stream
g_ei_len    dd ?
g_ei_cap    dd ?
g_ep_ptr    dq ?                        ; EncryptedPackage stream
g_ep_len    dd ?
g_ep_cap    dd ?
g_pl_ptr    dq ?                        ; decrypted inner zip
g_pl_len    dd ?
g_pl_cap    dd ?
g_kdSalt    db 16 dup (?)
g_pwSalt    db 16 dup (?)
g_spin      dd ?
g_encKV     db 32 dup (?)
g_H         db 64 dup (?)
g_dk        db 32 dup (?)
g_pkgKey    db 32 dup (?)
g_rk        db 240 dup (?)
g_tmp64     db 64 dup (?)
g_scr       db 8320 dup (?)             ; hashing scratch
g_ol_wpw    dq ?                        ; password (UTF-16) ptr
g_ol_pwb    dd ?                        ; password bytes
.code

; ole_find(rcx=hay, rdx=hayend, r8=needle, r9d=nlen) -> rax = ptr / 0.
ole_find proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     dword ptr [rbp-48], r9d
of_lp:
    mov     rax, qword ptr [rbp-32]
    mov     ecx, dword ptr [rbp-48]
    sub     rax, rcx
    cmp     qword ptr [rbp-24], rax
    ja      of_no
    mov     r10, qword ptr [rbp-24]
    mov     r11, qword ptr [rbp-40]
    xor     r8d, r8d
of_cmp:
    cmp     r8d, dword ptr [rbp-48]
    jae     of_hit
    mov     al, byte ptr [r10+r8]
    cmp     al, byte ptr [r11+r8]
    jne     of_nx
    inc     r8d
    jmp     of_cmp
of_nx:
    inc     qword ptr [rbp-24]
    jmp     of_lp
of_hit:
    mov     rax, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
of_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
ole_find endp

; oa_difat(ecx = FAT-sector index) -> eax = FAT sector location.
oa_difat proc frame
    FRAME_PROLOG 48
    cmp     ecx, 109
    jae     od_chain
    mov     r10, qword ptr [g_ol_raw]
    mov     eax, dword ptr [r10+76+rcx*4]
    FRAME_EPILOG
    ret
od_chain:
    mov     r9d, dword ptr [g_ol_ssz]
    shr     r9d, 2
    dec     r9d                                 ; entries per DIFAT sector
    mov     eax, ecx
    sub     eax, 109
    xor     edx, edx
    div     r9d                                 ; eax=DIFAT sector #, edx=entry
    mov     dword ptr [rbp-24], edx             ; entry
    mov     dword ptr [rbp-28], eax             ; DIFAT sectors to skip
    mov     r8d, dword ptr [g_ol_dif0]          ; current DIFAT sector
    mov     r9d, dword ptr [g_ol_ssz]
    shr     r9d, 2
    dec     r9d                                 ; epd (index of the next-pointer)
od_walk:
    cmp     dword ptr [rbp-28], 0
    je      od_have
    lea     r10d, [r8d+1]
    mov     edx, dword ptr [g_ol_ssz]
    imul    r10, rdx
    add     r10, qword ptr [g_ol_raw]
    mov     eax, r9d
    shl     eax, 2
    mov     r8d, dword ptr [r10+rax]            ; next DIFAT sector
    dec     dword ptr [rbp-28]
    jmp     od_walk
od_have:
    lea     r10d, [r8d+1]
    mov     edx, dword ptr [g_ol_ssz]
    imul    r10, rdx
    add     r10, qword ptr [g_ol_raw]
    mov     eax, dword ptr [rbp-24]
    shl     eax, 2
    mov     eax, dword ptr [r10+rax]
    FRAME_EPILOG
    ret
oa_difat endp

; ole_fatnext(ecx = sector) -> eax = next sector.
ole_fatnext proc frame
    FRAME_PROLOG 48
    mov     r9d, dword ptr [g_ol_ssz]
    shr     r9d, 2
    mov     eax, ecx
    xor     edx, edx
    div     r9d                                 ; eax=FAT idx, edx=entry
    mov     dword ptr [rbp-24], edx
    mov     ecx, eax
    call    oa_difat
    lea     r10d, [eax+1]
    mov     edx, dword ptr [g_ol_ssz]
    imul    r10, rdx
    mov     eax, dword ptr [rbp-24]
    shl     eax, 2
    add     r10, rax
    add     r10, qword ptr [g_ol_raw]
    mov     eax, dword ptr [r10]
    FRAME_EPILOG
    ret
ole_fatnext endp

; ole_readreg(ecx=startSector, edx=size, r8=dst) - copy a FAT-chained stream.
ole_readreg proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-24], ecx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], r8
orr_lp:
    cmp     dword ptr [rbp-32], 0
    je      orr_done
    mov     eax, dword ptr [rbp-24]
    cmp     eax, ENDCHAIN
    jae     orr_done
    lea     r10d, [eax+1]
    mov     edx, dword ptr [g_ol_ssz]
    imul    r10, rdx
    add     r10, qword ptr [g_ol_raw]
    mov     ecx, dword ptr [g_ol_ssz]
    cmp     ecx, dword ptr [rbp-32]
    jbe     orr_n
    mov     ecx, dword ptr [rbp-32]
orr_n:
    mov     r11, qword ptr [rbp-40]
    xor     r8d, r8d
orr_cp:
    cmp     r8d, ecx
    jae     orr_cpd
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8d
    jmp     orr_cp
orr_cpd:
    mov     eax, ecx
    add     qword ptr [rbp-40], rax
    sub     dword ptr [rbp-32], ecx
    mov     ecx, dword ptr [rbp-24]
    call    ole_fatnext
    mov     dword ptr [rbp-24], eax
    jmp     orr_lp
orr_done:
    FRAME_EPILOG
    ret
ole_readreg endp

; ole_finddir(rcx=nameW, edx=nameBytes, r8=&outStart, r9=&outSize) -> eax 1/0.
;   nameBytes==0 returns the Root entry (mini-stream container).
ole_finddir proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9
    mov     eax, dword ptr [g_ol_dir]
    mov     dword ptr [rbp-56], eax
fd_sec:
    mov     eax, dword ptr [rbp-56]
    cmp     eax, ENDCHAIN
    jae     fd_no
    lea     r10d, [eax+1]
    mov     edx, dword ptr [g_ol_ssz]
    imul    r10, rdx
    add     r10, qword ptr [g_ol_raw]
    mov     qword ptr [rbp-64], r10
    xor     r11d, r11d
fd_ent:
    mov     eax, dword ptr [g_ol_ssz]
    shr     eax, 7                              ; 128-byte entries per sector
    cmp     r11d, eax
    jae     fd_next
    mov     r10, qword ptr [rbp-64]
    mov     eax, r11d
    shl     eax, 7
    add     r10, rax
    cmp     dword ptr [rbp-32], 0
    je      fd_match
    movzx   eax, byte ptr [r10+66]              ; object type
    cmp     eax, 2                              ; stream
    jne     fd_entn
    movzx   eax, word ptr [r10+64]              ; name length (bytes)
    cmp     eax, dword ptr [rbp-32]
    jne     fd_entn
    mov     rcx, qword ptr [rbp-24]
    mov     r8d, dword ptr [rbp-32]
    xor     r9d, r9d
fd_cmp:
    cmp     r9d, r8d
    jae     fd_match
    mov     al, byte ptr [r10+r9]
    cmp     al, byte ptr [rcx+r9]
    jne     fd_entn
    inc     r9d
    jmp     fd_cmp
fd_match:
    mov     eax, dword ptr [r10+116]
    mov     rcx, qword ptr [rbp-40]
    mov     dword ptr [rcx], eax
    mov     eax, dword ptr [r10+120]
    mov     rcx, qword ptr [rbp-48]
    mov     dword ptr [rcx], eax
    mov     eax, 1
    FRAME_EPILOG
    ret
fd_entn:
    inc     r11d
    jmp     fd_ent
fd_next:
    mov     ecx, dword ptr [rbp-56]
    call    ole_fatnext
    mov     dword ptr [rbp-56], eax
    jmp     fd_sec
fd_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
ole_finddir endp

; ole_materialize() - build mini-FAT + mini-stream container.  eax 1/0.
ole_materialize proc frame
    FRAME_PROLOG 80
    mov     eax, dword ptr [g_ol_nmfat]
    imul    eax, dword ptr [g_ol_ssz]
    add     eax, 64
    mov     dword ptr [g_mf_cap], eax
    mov     ecx, eax
    call    mem_alloc
    test    rax, rax
    jz      om_no
    mov     qword ptr [g_mf_ptr], rax
    mov     ecx, dword ptr [g_ol_mfat]
    mov     edx, dword ptr [g_ol_nmfat]
    imul    edx, dword ptr [g_ol_ssz]
    mov     r8, rax
    call    ole_readreg
    xor     ecx, ecx                            ; nameW = 0
    xor     edx, edx                            ; nameBytes = 0 -> Root entry
    lea     r8, [rbp-32]
    lea     r9, [rbp-40]
    call    ole_finddir                         ; Root entry
    mov     edx, dword ptr [rbp-40]             ; mini-stream length
    mov     ecx, edx
    add     ecx, 64
    mov     dword ptr [g_ms_cap], ecx
    call    mem_alloc
    test    rax, rax
    jz      om_no
    mov     qword ptr [g_ms_ptr], rax
    mov     ecx, dword ptr [rbp-32]
    mov     edx, dword ptr [rbp-40]
    mov     r8, rax
    call    ole_readreg
    mov     eax, 1
    FRAME_EPILOG
    ret
om_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
ole_materialize endp

; ole_readmini(ecx=startMiniSector, edx=size, r8=dst) - copy a sub-cutoff stream.
ole_readmini proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-24], ecx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], r8
orm_lp:
    cmp     dword ptr [rbp-32], 0
    je      orm_done
    mov     eax, dword ptr [rbp-24]
    cmp     eax, ENDCHAIN
    jae     orm_done
    mov     r10, qword ptr [g_ms_ptr]
    mov     eax, dword ptr [rbp-24]
    shl     eax, 6                              ; *64
    add     r10, rax
    mov     ecx, 64
    cmp     ecx, dword ptr [rbp-32]
    jbe     orm_n
    mov     ecx, dword ptr [rbp-32]
orm_n:
    mov     r11, qword ptr [rbp-40]
    xor     r8d, r8d
orm_cp:
    cmp     r8d, ecx
    jae     orm_cpd
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8d
    jmp     orm_cp
orm_cpd:
    mov     eax, ecx
    add     qword ptr [rbp-40], rax
    sub     dword ptr [rbp-32], ecx
    mov     r10, qword ptr [g_mf_ptr]
    mov     eax, dword ptr [rbp-24]
    mov     eax, dword ptr [r10+rax*4]
    mov     dword ptr [rbp-24], eax
    jmp     orm_lp
orm_done:
    FRAME_EPILOG
    ret
ole_readmini endp

; ole_readstream(rcx=nameW, edx=nameBytes, r8=&outptr, r9=&outlen, [rbp+48]=&outcap)
;   -> eax 1/0.  Allocates and fills a buffer.
ole_readstream proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rbp-72], rax             ; &outcap
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    lea     r8, [rbp-56]                         ; start
    lea     r9, [rbp-64]                         ; size
    call    ole_finddir
    test    eax, eax
    jz      ors_no
    mov     ecx, dword ptr [rbp-64]
    add     ecx, 64
    mov     r10, qword ptr [rbp-72]
    mov     dword ptr [r10], ecx                 ; outcap
    call    mem_alloc
    test    rax, rax
    jz      ors_no
    mov     r10, qword ptr [rbp-40]
    mov     qword ptr [r10], rax                 ; outptr
    mov     r10, qword ptr [rbp-48]
    mov     ecx, dword ptr [rbp-64]
    mov     dword ptr [r10], ecx                 ; outlen
    mov     eax, dword ptr [rbp-64]
    cmp     eax, dword ptr [g_ol_mcut]
    jb      ors_mini
    mov     rax, qword ptr [rbp-40]
    mov     r8, qword ptr [rax]
    mov     ecx, dword ptr [rbp-56]
    mov     edx, dword ptr [rbp-64]
    call    ole_readreg
    mov     eax, 1
    FRAME_EPILOG
    ret
ors_mini:
    mov     rax, qword ptr [rbp-40]
    mov     r8, qword ptr [rax]
    mov     ecx, dword ptr [rbp-56]
    mov     edx, dword ptr [rbp-64]
    call    ole_readmini
    mov     eax, 1
    FRAME_EPILOG
    ret
ors_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
ole_readstream endp

; ole_parse() - validate header, cache geometry, read the two streams.  eax 1/0.
ole_parse proc frame
    FRAME_PROLOG 64
    mov     r10, qword ptr [g_ol_raw]
    cmp     byte ptr [r10], 0D0h
    jne     op_no
    cmp     byte ptr [r10+1], 0CFh
    jne     op_no
    cmp     byte ptr [r10+2], 011h
    jne     op_no
    cmp     byte ptr [r10+3], 0E0h
    jne     op_no
    movzx   ecx, word ptr [r10+30]
    mov     eax, 1
    shl     eax, cl
    mov     dword ptr [g_ol_ssz], eax
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [g_ol_dir], eax
    mov     eax, dword ptr [r10+56]
    mov     dword ptr [g_ol_mcut], eax
    mov     eax, dword ptr [r10+60]
    mov     dword ptr [g_ol_mfat], eax
    mov     eax, dword ptr [r10+64]
    mov     dword ptr [g_ol_nmfat], eax
    mov     eax, dword ptr [r10+68]
    mov     dword ptr [g_ol_dif0], eax
    mov     eax, dword ptr [r10+72]
    mov     dword ptr [g_ol_ndif], eax
    call    ole_materialize
    test    eax, eax
    jz      op_no
    lea     rcx, [w_ei]
    mov     edx, 30
    lea     r8, [g_ei_ptr]
    lea     r9, [g_ei_len]
    lea     rax, [g_ei_cap]
    mov     qword ptr [rsp+32], rax
    call    ole_readstream
    test    eax, eax
    jz      op_no
    lea     rcx, [w_ep]
    mov     edx, 34
    lea     r8, [g_ep_ptr]
    lea     r9, [g_ep_len]
    lea     rax, [g_ep_cap]
    mov     qword ptr [rsp+32], rax
    call    ole_readstream
    test    eax, eax
    jz      op_no
    mov     eax, 1
    FRAME_EPILOG
    ret
op_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
ole_parse endp

; xml_get(rcx=hay, rdx=hayend, r8=needle, r9d=nlen, [rbp+48]=&valend)
;   -> rax = value start (0 if not found); *valend = end (at the closing quote).
xml_get proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-24], r9d             ; nlen
    mov     qword ptr [rbp-32], rdx             ; hayend
    mov     rax, qword ptr [rbp+48]
    mov     qword ptr [rbp-40], rax             ; &valend
    call    ole_find                            ; (rcx,rdx,r8,r9d)
    test    rax, rax
    jz      xg_no
    mov     ecx, dword ptr [rbp-24]
    add     rax, rcx                            ; skip needle -> value start
    mov     r10, rax
xg_e:
    cmp     r10, qword ptr [rbp-32]
    jae     xg_setend
    cmp     byte ptr [r10], 22h
    je      xg_setend
    inc     r10
    jmp     xg_e
xg_setend:
    mov     rcx, qword ptr [rbp-40]
    mov     qword ptr [rcx], r10
    FRAME_EPILOG
    ret
xg_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
xml_get endp

; b64dec(rcx=src, edx=srclen, r8=dst) -> eax = bytes written.
b64dec proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], r8
    xor     r9d, r9d                            ; out count
    xor     r10d, r10d                          ; accumulator
    xor     r11d, r11d                          ; bits held
    xor     ecx, ecx                            ; i
bd_lp:
    cmp     ecx, dword ptr [rbp-32]
    jae     bd_done
    mov     rax, qword ptr [rbp-24]
    movzx   eax, byte ptr [rax+rcx]
    inc     ecx
    cmp     eax, '='
    je      bd_done
    cmp     eax, 'A'
    jb      bd_dig
    cmp     eax, 'Z'
    ja      bd_low
    sub     eax, 'A'
    jmp     bd_acc
bd_low:
    cmp     eax, 'a'
    jb      bd_lp
    cmp     eax, 'z'
    ja      bd_lp
    sub     eax, 'a'-26
    jmp     bd_acc
bd_dig:
    cmp     eax, '0'
    jb      bd_sym
    cmp     eax, '9'
    ja      bd_lp
    sub     eax, '0'-52
    jmp     bd_acc
bd_sym:
    cmp     eax, '+'
    je      bd_plus
    cmp     eax, '/'
    je      bd_slash
    jmp     bd_lp
bd_plus:
    mov     eax, 62
    jmp     bd_acc
bd_slash:
    mov     eax, 63
bd_acc:
    shl     r10d, 6
    or      r10d, eax
    add     r11d, 6
    cmp     r11d, 8
    jb      bd_lp
    sub     r11d, 8
    mov     eax, r10d
    push    rcx
    mov     ecx, r11d
    shr     eax, cl
    pop     rcx
    and     eax, 0FFh
    mov     r8, qword ptr [rbp-40]
    mov     byte ptr [r8+r9], al
    inc     r9d
    jmp     bd_lp
bd_done:
    mov     eax, r9d
    FRAME_EPILOG
    ret
b64dec endp

; parse_ei() - pull kdSalt, pwSalt, spinCount, encryptedKeyValue out of the
;   EncryptionInfo XML.  eax 1/0.
parse_ei proc frame
    FRAME_PROLOG 96
    mov     rax, qword ptr [g_ei_ptr]
    add     rax, 8                              ; skip the 8-byte version header
    mov     qword ptr [rbp-24], rax             ; xmlstart
    mov     rax, qword ptr [g_ei_ptr]
    mov     ecx, dword ptr [g_ei_len]
    add     rax, rcx
    mov     qword ptr [rbp-32], rax             ; xmlend
    ; keyData salt
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [tag_kd]
    mov     r9d, 8
    call    ole_find
    test    rax, rax
    jz      pe_no
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [n_salt]
    mov     r9d, 11
    lea     rax, [rbp-40]
    mov     qword ptr [rsp+32], rax
    call    xml_get
    test    rax, rax
    jz      pe_no
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-40]
    sub     rdx, rcx                            ; b64 length
    lea     r8, [g_kdSalt]
    call    b64dec
    ; encryptedKey element
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [tag_ek]
    mov     r9d, 15
    call    ole_find
    test    rax, rax
    jz      pe_no
    mov     qword ptr [rbp-48], rax             ; p_ek
    ; pwSalt
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [n_salt]
    mov     r9d, 11
    lea     rax, [rbp-40]
    mov     qword ptr [rsp+32], rax
    call    xml_get
    test    rax, rax
    jz      pe_no
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-40]
    sub     rdx, rcx
    lea     r8, [g_pwSalt]
    call    b64dec
    ; spinCount (decimal)
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [n_spin]
    mov     r9d, 11
    lea     rax, [rbp-40]
    mov     qword ptr [rsp+32], rax
    call    xml_get
    test    rax, rax
    jz      pe_no
    mov     r10, rax                            ; digits ptr
    mov     r11, qword ptr [rbp-40]            ; end
    xor     eax, eax
pe_spin:
    cmp     r10, r11
    jae     pe_spindone
    movzx   ecx, byte ptr [r10]
    cmp     ecx, '0'
    jb      pe_spindone
    cmp     ecx, '9'
    ja      pe_spindone
    imul    eax, eax, 10
    sub     ecx, '0'
    add     eax, ecx
    inc     r10
    jmp     pe_spin
pe_spindone:
    mov     dword ptr [g_spin], eax
    ; encryptedKeyValue
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [n_ekv]
    mov     r9d, 19
    lea     rax, [rbp-40]
    mov     qword ptr [rsp+32], rax
    call    xml_get
    test    rax, rax
    jz      pe_no
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-40]
    sub     rdx, rcx
    lea     r8, [g_encKV]
    call    b64dec
    mov     eax, 1
    FRAME_EPILOG
    ret
pe_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
parse_ei endp

; kdf() - H = SHA512(pwSalt || password); spin: H = SHA512(LE32(i) || H).
kdf proc frame
    FRAME_PROLOG 48
    lea     rcx, [g_scr]
    lea     rdx, [g_pwSalt]
    xor     r8d, r8d
kd_cs:
    mov     al, byte ptr [rdx+r8]
    mov     byte ptr [rcx+r8], al
    inc     r8d
    cmp     r8d, 16
    jb      kd_cs
    ; append password
    mov     rdx, qword ptr [g_ol_wpw]
    mov     r9d, dword ptr [g_ol_pwb]
    xor     r8d, r8d
kd_cp:
    cmp     r8d, r9d
    jae     kd_cpd
    mov     al, byte ptr [rdx+r8]
    lea     r10, [g_scr]
    mov     byte ptr [r10+r8+16], al
    inc     r8d
    jmp     kd_cp
kd_cpd:
    lea     rcx, [g_scr]
    mov     edx, dword ptr [g_ol_pwb]
    add     rdx, 16
    lea     r8, [g_H]
    call    sha512_hash
    mov     dword ptr [rbp-24], 0               ; i
kd_spin:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_spin]
    jae     kd_done
    lea     r10, [g_scr]
    mov     dword ptr [r10], eax               ; LE32(i)
    xor     r8d, r8d
kd_sh:
    lea     r10, [g_H]
    mov     al, byte ptr [r10+r8]
    lea     r11, [g_scr]
    mov     byte ptr [r11+r8+4], al
    inc     r8d
    cmp     r8d, 64
    jb      kd_sh
    lea     rcx, [g_scr]
    mov     rdx, 68
    lea     r8, [g_H]
    call    sha512_hash
    inc     dword ptr [rbp-24]
    jmp     kd_spin
kd_done:
    FRAME_EPILOG
    ret
kdf endp

; cbc_dec(rcx=key32, rdx=iv16, r8=buf, r9d=len) - in-place AES-256-CBC decrypt.
cbc_dec proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], r8              ; buf
    mov     dword ptr [rbp-32], r9d             ; len
    movdqu  xmm0, xmmword ptr [rdx]
    movdqu  xmmword ptr [rbp-64], xmm0          ; prev = iv
    mov     rdx, 32
    lea     r8, [g_rk]
    call    aes_expand_key                      ; rcx=key still valid
    mov     dword ptr [rbp-40], eax             ; Nr
    mov     dword ptr [rbp-48], 0               ; off
cbd_lp:
    mov     eax, dword ptr [rbp-48]
    cmp     eax, dword ptr [rbp-32]
    jae     cbd_done
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [rbp-48]
    movdqu  xmm2, xmmword ptr [r10+rax]         ; ct
    movdqu  xmmword ptr [rbp-80], xmm2          ; scratch block to decrypt
    lea     rcx, [g_rk]
    lea     rdx, [rbp-80]
    mov     r8d, dword ptr [rbp-40]
    call    aes_ecb_decrypt
    movdqu  xmm0, xmmword ptr [rbp-80]          ; dec(ct)
    movdqu  xmm1, xmmword ptr [rbp-64]          ; prev
    pxor    xmm0, xmm1
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [rbp-48]
    movdqu  xmmword ptr [r10+rax], xmm0         ; plaintext
    movdqu  xmmword ptr [rbp-64], xmm2          ; prev = ct
    add     dword ptr [rbp-48], 16
    jmp     cbd_lp
cbd_done:
    FRAME_EPILOG
    ret
cbc_dec endp

; derive_pkgkey() - dk = SHA512(H || bk_kv)[:32]; pkgKey = CBC-dec(dk, pwSalt, encKV).
derive_pkgkey proc frame
    FRAME_PROLOG 48
    lea     rcx, [g_scr]
    lea     rdx, [g_H]
    xor     r8d, r8d
dp_h:
    mov     al, byte ptr [rdx+r8]
    mov     byte ptr [rcx+r8], al
    inc     r8d
    cmp     r8d, 64
    jb      dp_h
    lea     rcx, [g_scr+64]
    lea     rdx, [bk_kv]
    xor     r8d, r8d
dp_bk:
    mov     al, byte ptr [rdx+r8]
    mov     byte ptr [rcx+r8], al
    inc     r8d
    cmp     r8d, 8
    jb      dp_bk
    lea     rcx, [g_scr]
    mov     rdx, 72
    lea     r8, [g_tmp64]
    call    sha512_hash
    lea     rcx, [g_dk]
    lea     rdx, [g_tmp64]
    xor     r8d, r8d
dp_dk:
    mov     al, byte ptr [rdx+r8]
    mov     byte ptr [rcx+r8], al
    inc     r8d
    cmp     r8d, 32
    jb      dp_dk
    lea     rcx, [g_dk]
    lea     rdx, [g_pwSalt]
    lea     r8, [g_encKV]
    mov     r9d, 32
    call    cbc_dec
    lea     rcx, [g_pkgKey]
    lea     rdx, [g_encKV]
    xor     r8d, r8d
dp_pk:
    mov     al, byte ptr [rdx+r8]
    mov     byte ptr [rcx+r8], al
    inc     r8d
    cmp     r8d, 32
    jb      dp_pk
    FRAME_EPILOG
    ret
derive_pkgkey endp

; decrypt_package() - size=LE64(ep); decrypt each 4096-byte CBC segment.  eax 1/0.
decrypt_package proc frame
    FRAME_PROLOG 64
    mov     r10, qword ptr [g_ep_ptr]
    mov     eax, dword ptr [r10]               ; low 32 of size (files < 4 GiB)
    mov     dword ptr [rbp-24], eax             ; final length
    mov     eax, dword ptr [g_ep_len]
    sub     eax, 8
    mov     dword ptr [rbp-32], eax             ; datalen
    mov     ecx, eax
    add     ecx, 64
    mov     dword ptr [g_pl_cap], ecx
    call    mem_alloc
    test    rax, rax
    jz      dp2_no
    mov     qword ptr [g_pl_ptr], rax
    ; copy ciphertext (ep+8) -> plain
    mov     r10, qword ptr [g_ep_ptr]
    add     r10, 8
    mov     r11, rax
    xor     r8d, r8d
dp2_cp:
    cmp     r8d, dword ptr [rbp-32]
    jae     dp2_cpd
    mov     al, byte ptr [r10+r8]
    mov     byte ptr [r11+r8], al
    inc     r8d
    jmp     dp2_cp
dp2_cpd:
    mov     dword ptr [rbp-40], 0               ; off
    mov     dword ptr [rbp-48], 0               ; segidx
dp2_seg:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [rbp-32]
    jae     dp2_done
    ; IV = SHA512(kdSalt || LE32(segidx))[:16]
    lea     rcx, [g_scr]
    lea     rdx, [g_kdSalt]
    xor     r8d, r8d
dp2_iv:
    mov     al, byte ptr [rdx+r8]
    mov     byte ptr [rcx+r8], al
    inc     r8d
    cmp     r8d, 16
    jb      dp2_iv
    mov     eax, dword ptr [rbp-48]
    lea     r10, [g_scr]
    mov     dword ptr [r10+16], eax
    lea     rcx, [g_scr]
    mov     rdx, 20
    lea     r8, [g_tmp64]
    call    sha512_hash
    ; seglen = min(4096, datalen - off)
    mov     eax, dword ptr [rbp-32]
    sub     eax, dword ptr [rbp-40]
    cmp     eax, 4096
    jbe     dp2_sl
    mov     eax, 4096
dp2_sl:
    mov     dword ptr [rbp-56], eax             ; seglen
    ; cbc_dec(key=pkgKey, iv=tmp64, buf=plain+off, len=seglen)
    lea     rcx, [g_pkgKey]
    lea     rdx, [g_tmp64]
    mov     r8, qword ptr [g_pl_ptr]
    mov     eax, dword ptr [rbp-40]
    add     r8, rax
    mov     r9d, dword ptr [rbp-56]
    call    cbc_dec
    mov     eax, dword ptr [rbp-56]
    add     dword ptr [rbp-40], eax
    inc     dword ptr [rbp-48]
    jmp     dp2_seg
dp2_done:
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_pl_len], eax
    mov     eax, 1
    FRAME_EPILOG
    ret
dp2_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
decrypt_package endp

; ole_freeall() - release every buffer allocated during decryption.
ole_freeall proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [g_mf_ptr]
    test    rcx, rcx
    jz      fa1
    mov     edx, dword ptr [g_mf_cap]
    call    mem_free
    mov     qword ptr [g_mf_ptr], 0
fa1:
    mov     rcx, qword ptr [g_ms_ptr]
    test    rcx, rcx
    jz      fa2
    mov     edx, dword ptr [g_ms_cap]
    call    mem_free
    mov     qword ptr [g_ms_ptr], 0
fa2:
    mov     rcx, qword ptr [g_ei_ptr]
    test    rcx, rcx
    jz      fa3
    mov     edx, dword ptr [g_ei_cap]
    call    mem_free
    mov     qword ptr [g_ei_ptr], 0
fa3:
    mov     rcx, qword ptr [g_ep_ptr]
    test    rcx, rcx
    jz      fa4
    mov     edx, dword ptr [g_ep_cap]
    call    mem_free
    mov     qword ptr [g_ep_ptr], 0
fa4:
    mov     rcx, qword ptr [g_pl_ptr]
    test    rcx, rcx
    jz      fa5
    mov     edx, dword ptr [g_pl_cap]
    call    mem_free
    mov     qword ptr [g_pl_ptr], 0
fa5:
    FRAME_EPILOG
    ret
ole_freeall endp

; =============================================================================
; xlsx_decrypt(rcx=raw, edx=rawlen, r8=wpw, r9d=pwbytes) -> eax
; =============================================================================
public xlsx_decrypt
xlsx_decrypt proc frame
    FRAME_PROLOG 48
    mov     qword ptr [g_ol_raw], rcx
    mov     dword ptr [g_ol_len], edx
    mov     qword ptr [g_ol_wpw], r8
    mov     dword ptr [g_ol_pwb], r9d
    mov     qword ptr [g_mf_ptr], 0
    mov     qword ptr [g_ms_ptr], 0
    mov     qword ptr [g_ei_ptr], 0
    mov     qword ptr [g_ep_ptr], 0
    mov     qword ptr [g_pl_ptr], 0
    call    ole_parse
    test    eax, eax
    jz      xd_err
    call    parse_ei
    test    eax, eax
    jz      xd_err
    call    kdf
    call    derive_pkgkey
    call    decrypt_package
    test    eax, eax
    jz      xd_err
    mov     r10, qword ptr [g_pl_ptr]
    cmp     byte ptr [r10], 'P'
    jne     xd_wrongpw
    cmp     byte ptr [r10+1], 'K'
    jne     xd_wrongpw
    mov     rcx, r10
    mov     edx, dword ptr [g_pl_len]
    call    xlsx_import
    mov     dword ptr [rbp-24], eax
    call    ole_freeall
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
xd_wrongpw:
    call    ole_freeall
    mov     eax, -3
    FRAME_EPILOG
    ret
xd_err:
    call    ole_freeall
    mov     eax, -1
    FRAME_EPILOG
    ret
xlsx_decrypt endp

end
