; =============================================================================
; xlcrypt.asm - MS-OFFCRYPTO "agile" encryption of the .xlsx package into a
;   password-protected OLE2 compound file (opens directly in Excel).
;
;   xl_encrypt(rcx = wide password ptr, edx = password length in BYTES)
;       -> eax = 0 ok / 1 error; on success g_ole_ptr/g_ole_len point at the
;          finished .xlsx in a locked buffer.  Requires xl_build_xlsx() first
;          (consumes g_xlsx_ptr/g_xlsx_len).
;   xl_encrypt_free() - wipe + release the encryption buffers.
;
; Pipeline (ECMA-376 agile): SHA-512 spin key derivation -> verifier + encrypted
; package key, AES-256-CBC segmented package encryption, HMAC-SHA512 integrity,
; EncryptionInfo XML, then a CFB (compound file) with EncryptionInfo (mini
; stream) + EncryptedPackage (regular sectors).
; =============================================================================

include macros.inc

extern sha512_hash:proc
extern hmac_sha512:proc
extern aes_expand_key:proc
extern aes_ecb_block:proc
extern rng_fill:proc
extern secmem_alloc:proc
extern secmem_free:proc
; shared buffer primitives (xlexport.asm)
extern buf_putb:proc
extern buf_putn:proc
extern buf_pu16:proc
extern buf_pu32:proc
extern buf_pu64:proc
extern buf_putcstr:proc
extern buf_zero:proc
extern g_xl_err:byte
extern g_xlsx_ptr:qword
extern g_xlsx_len:qword

XL_ECAP     equ 24*1024*1024         ; buffer cap for encrypted package / ole file
SPIN_COUNT  equ 100000
ENDCHAIN    equ 0FFFFFFFEh
FREESECT    equ 0FFFFFFFFh
FATSECT     equ 0FFFFFFFDh

.data?
align 16
g_encbuf    dq 3 dup (?)             ; EncryptedPackage stream {ptr,len,cap}
g_olebuf    dq 3 dup (?)             ; final compound file    {ptr,len,cap}
g_eibuf     dq 3 dup (?)             ; EncryptionInfo         {ptr,len,cap}
g_ei        db 8192 dup (?)          ; EncryptionInfo backing store
g_segwork   db 4112 dup (?)          ; one package segment (4096 + pad)
; secret material (wiped at the end)
g_pwSalt    db 16 dup (?)
g_kdSalt    db 16 dup (?)
g_pkgKey    db 32 dup (?)
g_vin       db 16 dup (?)
g_hmKey     db 64 dup (?)
g_H         db 64 dup (?)
g_dk        db 32 dup (?)
g_scr       db 256 dup (?)
g_tmp64     db 64 dup (?)
g_ivt       db 16 dup (?)
g_le4       dd ?
; agile encrypted blobs
g_encVHI    db 16 dup (?)
g_encVHV    db 64 dup (?)
g_encKV     db 32 dup (?)
g_encHK     db 64 dup (?)
g_encHV     db 64 dup (?)
; ole layout scratch
g_EIlen     dd ?
g_EPlen     dd ?
g_numMini   dd ?
g_miniCLen  dd ?
g_miniCSec  dd ?
g_pkgSec    dd ?
g_miniFSec  dd ?
g_F         dd ?
g_T         dd ?
g_dirStart  dd ?
g_mfStart   dd ?
g_mcStart   dd ?
g_pkgStart  dd ?
g_de_right  dd ?
g_de_child  dd ?
g_de_start  dd ?
g_de_size   dd ?
g_de_color  dd ?
g_eiMS      dd ?                    ; EncryptionInfo mini-sector count
public g_ole_ptr, g_ole_len
g_ole_ptr   dq ?
g_ole_len   dq ?

.const
ole_sig db 0D0h,0CFh,011h,0E0h,0A1h,0B1h,01Ah,0E1h
ei_hdr  db 4,0,4,0,40h,0,0,0
bk_vhi  db 0feh,0a7h,0d2h,076h,03bh,04bh,09eh,079h
bk_vhv  db 0d7h,0aah,00fh,06dh,030h,061h,034h,04eh
bk_kv   db 014h,06eh,00bh,0e7h,0abh,0ach,0d0h,0d6h
bk_hk   db 05fh,0b2h,0adh,001h,00ch,0b9h,0e1h,0f6h
bk_hv   db 0a0h,067h,07fh,002h,0b2h,02ch,084h,033h
b64tab  db 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
w_root  dw 'R','o','o','t',' ','E','n','t','r','y',0
w_ei    dw 'E','n','c','r','y','p','t','i','o','n','I','n','f','o',0
w_ep    dw 'E','n','c','r','y','p','t','e','d','P','a','c','k','a','g','e',0
w_ds    dw 6,'D','a','t','a','S','p','a','c','e','s',0
w_ver   dw 'V','e','r','s','i','o','n',0
w_dsmap dw 'D','a','t','a','S','p','a','c','e','M','a','p',0
w_dsinf dw 'D','a','t','a','S','p','a','c','e','I','n','f','o',0
w_strds dw 'S','t','r','o','n','g','E','n','c','r','y','p','t','i','o','n','D','a','t','a','S','p','a','c','e',0
w_tinf  dw 'T','r','a','n','s','f','o','r','m','I','n','f','o',0
w_strtr dw 'S','t','r','o','n','g','E','n','c','r','y','p','t','i','o','n','T','r','a','n','s','f','o','r','m',0
w_prim  dw 6,'P','r','i','m','a','r','y',0
; MiniFAT chain values for the 9 fixed DataSpaces mini-sectors (0..8)
mf_fixed dd 1, ENDCHAIN, 3, ENDCHAIN, ENDCHAIN, 6, 7, 8, ENDCHAIN
; the four fixed OOXML "Data Spaces" transform streams (constant for agile enc)
ds_version db 03ch,000h,000h,000h,04dh,000h,069h,000h,063h,000h,072h,000h
        db 06fh,000h,073h,000h,06fh,000h,066h,000h,074h,000h,02eh,000h
        db 043h,000h,06fh,000h,06eh,000h,074h,000h,061h,000h,069h,000h
        db 06eh,000h,065h,000h,072h,000h,02eh,000h,044h,000h,061h,000h
        db 074h,000h,061h,000h,053h,000h,070h,000h,061h,000h,063h,000h
        db 065h,000h,073h,000h,001h,000h,000h,000h,001h,000h,000h,000h
        db 001h,000h,000h,000h
ds_dsmap db 008h,000h,000h,000h,001h,000h,000h,000h,068h,000h,000h,000h
        db 001h,000h,000h,000h,000h,000h,000h,000h,020h,000h,000h,000h
        db 045h,000h,06eh,000h,063h,000h,072h,000h,079h,000h,070h,000h
        db 074h,000h,065h,000h,064h,000h,050h,000h,061h,000h,063h,000h
        db 06bh,000h,061h,000h,067h,000h,065h,000h,032h,000h,000h,000h
        db 053h,000h,074h,000h,072h,000h,06fh,000h,06eh,000h,067h,000h
        db 045h,000h,06eh,000h,063h,000h,072h,000h,079h,000h,070h,000h
        db 074h,000h,069h,000h,06fh,000h,06eh,000h,044h,000h,061h,000h
        db 074h,000h,061h,000h,053h,000h,070h,000h,061h,000h,063h,000h
        db 065h,000h,000h,000h
ds_strongds db 008h,000h,000h,000h,001h,000h,000h,000h,032h,000h,000h,000h
        db 053h,000h,074h,000h,072h,000h,06fh,000h,06eh,000h,067h,000h
        db 045h,000h,06eh,000h,063h,000h,072h,000h,079h,000h,070h,000h
        db 074h,000h,069h,000h,06fh,000h,06eh,000h,054h,000h,072h,000h
        db 061h,000h,06eh,000h,073h,000h,066h,000h,06fh,000h,072h,000h
        db 06dh,000h,000h,000h
ds_primary db 058h,000h,000h,000h,001h,000h,000h,000h,04ch,000h,000h,000h
        db 07bh,000h,046h,000h,046h,000h,039h,000h,041h,000h,033h,000h
        db 046h,000h,030h,000h,033h,000h,02dh,000h,035h,000h,036h,000h
        db 045h,000h,046h,000h,02dh,000h,034h,000h,036h,000h,031h,000h
        db 033h,000h,02dh,000h,042h,000h,044h,000h,044h,000h,035h,000h
        db 02dh,000h,035h,000h,041h,000h,034h,000h,031h,000h,043h,000h
        db 031h,000h,044h,000h,030h,000h,037h,000h,032h,000h,034h,000h
        db 036h,000h,07dh,000h,04eh,000h,000h,000h,04dh,000h,069h,000h
        db 063h,000h,072h,000h,06fh,000h,073h,000h,06fh,000h,066h,000h
        db 074h,000h,02eh,000h,043h,000h,06fh,000h,06eh,000h,074h,000h
        db 061h,000h,069h,000h,06eh,000h,065h,000h,072h,000h,02eh,000h
        db 045h,000h,06eh,000h,063h,000h,072h,000h,079h,000h,070h,000h
        db 074h,000h,069h,000h,06fh,000h,06eh,000h,054h,000h,072h,000h
        db 061h,000h,06eh,000h,073h,000h,066h,000h,06fh,000h,072h,000h
        db 06dh,000h,000h,000h,001h,000h,000h,000h,001h,000h,000h,000h
        db 001h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h
        db 000h,000h,000h,000h,004h,000h,000h,000h
; EncryptionInfo XML (single-quote delimiters -> literal ")
ei_c1   db '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',13,10
        db '<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password" xmlns:c="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">'
        db '<keyData saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="',0
ei_c2   db '"/><dataIntegrity encryptedHmacKey="',0
ei_c3   db '" encryptedHmacValue="',0
ei_c4   db '"/><keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">'
        db '<p:encryptedKey spinCount="100000" saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="',0
ei_c5   db '" encryptedVerifierHashInput="',0
ei_c6   db '" encryptedVerifierHashValue="',0
ei_c7   db '" encryptedKeyValue="',0
ei_c8   db '"/></keyEncryptor></keyEncryptors></encryption>',0

.code

; xcopy(rcx=dst, rdx=src, r8=len)                                              leaf
xcopy proc
    test    r8, r8
    jz      xc_ret
    xor     r9, r9
xc_lp:
    mov     al, byte ptr [rdx+r9]
    mov     byte ptr [rcx+r9], al
    inc     r9
    cmp     r9, r8
    jb      xc_lp
xc_ret:
    ret
xcopy endp

; =============================================================================
; xl_cbc(rcx=key32, rdx=iv16, r8=buf, r9=len) - in-place AES-256-CBC, len%16==0
; =============================================================================
xl_cbc proc frame
    FRAME_PROLOG 384
    ; [rbp-24]=buf [rbp-32]=len [rbp-40]=Nr [rbp-64]=prev(iv) [rbp-72]=off
    ; rk (240 bytes) at [rbp-320]
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    movdqu  xmm0, xmmword ptr [rdx]
    movdqu  xmmword ptr [rbp-64], xmm0          ; prev = iv
    mov     rdx, 32                             ; expand key (rcx=key already)
    lea     r8, [rbp-320]
    call    aes_expand_key
    mov     dword ptr [rbp-40], eax             ; Nr
    mov     qword ptr [rbp-72], 0
cbc_lp:
    mov     r11, qword ptr [rbp-72]
    cmp     r11, qword ptr [rbp-32]
    jae     cbc_done
    mov     rax, qword ptr [rbp-24]
    movdqu  xmm0, xmmword ptr [rax+r11]
    movdqu  xmm1, xmmword ptr [rbp-64]
    pxor    xmm0, xmm1
    movdqu  xmmword ptr [rax+r11], xmm0         ; pt ^ prev
    lea     rcx, [rbp-320]
    lea     rdx, [rax+r11]
    mov     r8d, dword ptr [rbp-40]
    call    aes_ecb_block                       ; block = AES(pt^prev)
    mov     rax, qword ptr [rbp-24]
    mov     r11, qword ptr [rbp-72]
    movdqu  xmm0, xmmword ptr [rax+r11]         ; prev = ct
    movdqu  xmmword ptr [rbp-64], xmm0
    add     qword ptr [rbp-72], 16
    jmp     cbc_lp
cbc_done:
    FRAME_EPILOG
    ret
xl_cbc endp

; =============================================================================
; b64_put(rdx=src, r8=len) - append base64 of src to g_eibuf
; =============================================================================
B64E macro
    lea     r8, [b64tab]
    mov     r9b, byte ptr [r8+rcx]
    lea     rcx, [g_eibuf]
    mov     dl, r9b
    call    buf_putb
endm
b64_put proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-32], rdx             ; src
    mov     qword ptr [rbp-40], r8              ; len
    mov     qword ptr [rbp-48], 0               ; i
b64_lp:
    mov     rax, qword ptr [rbp-48]
    add     rax, 3
    cmp     rax, qword ptr [rbp-40]
    ja      b64_rem
    mov     r8, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-48]
    movzx   r9d, byte ptr [r8+rax]              ; b0  (saved into stack; r9 volatile)
    mov     dword ptr [rbp-56], r9d
    movzx   r10d, byte ptr [r8+rax+1]           ; b1
    mov     dword ptr [rbp-60], r10d
    movzx   r11d, byte ptr [r8+rax+2]           ; b2
    mov     dword ptr [rbp-64], r11d
    mov     ecx, dword ptr [rbp-56]
    shr     ecx, 2
    B64E
    mov     ecx, dword ptr [rbp-56]
    and     ecx, 3
    shl     ecx, 4
    mov     edx, dword ptr [rbp-60]
    shr     edx, 4
    or      ecx, edx
    B64E
    mov     ecx, dword ptr [rbp-60]
    and     ecx, 15
    shl     ecx, 2
    mov     edx, dword ptr [rbp-64]
    shr     edx, 6
    or      ecx, edx
    B64E
    mov     ecx, dword ptr [rbp-64]
    and     ecx, 63
    B64E
    add     qword ptr [rbp-48], 3
    jmp     b64_lp
b64_rem:
    mov     rax, qword ptr [rbp-40]
    sub     rax, qword ptr [rbp-48]             ; rem
    test    rax, rax
    jz      b64_done
    cmp     rax, 1
    je      b64_r1
    ; rem == 2
    mov     r8, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-48]
    movzx   r9d, byte ptr [r8+rax]
    mov     dword ptr [rbp-56], r9d
    movzx   r10d, byte ptr [r8+rax+1]
    mov     dword ptr [rbp-60], r10d
    mov     ecx, dword ptr [rbp-56]
    shr     ecx, 2
    B64E
    mov     ecx, dword ptr [rbp-56]
    and     ecx, 3
    shl     ecx, 4
    mov     edx, dword ptr [rbp-60]
    shr     edx, 4
    or      ecx, edx
    B64E
    mov     ecx, dword ptr [rbp-60]
    and     ecx, 15
    shl     ecx, 2
    B64E
    lea     rcx, [g_eibuf]
    mov     dl, '='
    call    buf_putb
    jmp     b64_done
b64_r1:
    mov     r8, qword ptr [rbp-32]
    mov     rax, qword ptr [rbp-48]
    movzx   r9d, byte ptr [r8+rax]
    mov     dword ptr [rbp-56], r9d
    mov     ecx, dword ptr [rbp-56]
    shr     ecx, 2
    B64E
    mov     ecx, dword ptr [rbp-56]
    and     ecx, 3
    shl     ecx, 4
    B64E
    lea     rcx, [g_eibuf]
    mov     dl, '='
    call    buf_putb
    lea     rcx, [g_eibuf]
    mov     dl, '='
    call    buf_putb
b64_done:
    FRAME_EPILOG
    ret
b64_put endp

; derive_key(rcx=blockKey8) -> g_dk = SHA512(g_H || blockKey)[:32]
derive_key proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    lea     rcx, [g_scr]
    lea     rdx, [g_H]
    mov     r8, 64
    call    xcopy
    lea     rcx, [g_scr+64]
    mov     rdx, qword ptr [rbp-24]
    mov     r8, 8
    call    xcopy
    lea     rcx, [g_scr]
    mov     rdx, 72
    lea     r8, [g_tmp64]
    call    sha512_hash
    lea     rcx, [g_dk]
    lea     rdx, [g_tmp64]
    mov     r8, 32
    call    xcopy
    FRAME_EPILOG
    ret
derive_key endp

; iv_from(rcx=extraptr, edx=extralen) -> g_ivt = SHA512(g_kdSalt || extra)[:16]
iv_from proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    lea     rcx, [g_scr]
    lea     rdx, [g_kdSalt]
    mov     r8, 16
    call    xcopy
    lea     rcx, [g_scr+16]
    mov     rdx, qword ptr [rbp-24]
    mov     r8d, dword ptr [rbp-32]
    call    xcopy
    lea     rcx, [g_scr]
    mov     edx, 16
    add     edx, dword ptr [rbp-32]
    lea     r8, [g_tmp64]
    call    sha512_hash
    lea     rcx, [g_ivt]
    lea     rdx, [g_tmp64]
    mov     r8, 16
    call    xcopy
    FRAME_EPILOG
    ret
iv_from endp

; xl_enc_package() - build g_encbuf = LE64(pkglen) || CBC segments of the package
xl_enc_package proc frame
    FRAME_PROLOG 64
    lea     rcx, [g_encbuf]
    mov     rdx, qword ptr [g_xlsx_len]
    call    buf_pu64
    mov     qword ptr [rbp-24], 0               ; off
    mov     dword ptr [rbp-32], 0               ; segidx
ep_lp:
    mov     rax, qword ptr [rbp-24]
    cmp     rax, qword ptr [g_xlsx_len]
    jae     ep_done
    mov     rax, qword ptr [g_xlsx_len]
    sub     rax, qword ptr [rbp-24]             ; rem
    mov     rcx, 4096
    cmp     rax, rcx
    cmovb   rcx, rax
    mov     qword ptr [rbp-40], rcx             ; seg
    mov     rax, rcx
    add     rax, 15
    and     rax, -16
    mov     qword ptr [rbp-48], rax             ; padlen
    ; copy segment bytes
    lea     rcx, [g_segwork]
    mov     rdx, qword ptr [g_xlsx_ptr]
    add     rdx, qword ptr [rbp-24]
    mov     r8, qword ptr [rbp-40]
    call    xcopy
    ; zero-pad to padlen
    mov     rax, qword ptr [rbp-40]
    lea     r10, [g_segwork]
    add     r10, rax
    mov     r11, qword ptr [rbp-48]
    sub     r11, rax
ep_zp:
    test    r11, r11
    jz      ep_zpd
    mov     byte ptr [r10], 0
    inc     r10
    dec     r11
    jmp     ep_zp
ep_zpd:
    ; iv from LE32(segidx)
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [g_le4], eax
    lea     rcx, [g_le4]
    mov     edx, 4
    call    iv_from
    ; CBC encrypt the padded segment with the package key
    lea     rcx, [g_pkgKey]
    lea     rdx, [g_ivt]
    lea     r8, [g_segwork]
    mov     r9, qword ptr [rbp-48]
    call    xl_cbc
    lea     rcx, [g_encbuf]
    lea     rdx, [g_segwork]
    mov     r8, qword ptr [rbp-48]
    call    buf_putn
    mov     rax, qword ptr [rbp-40]
    add     qword ptr [rbp-24], rax
    inc     dword ptr [rbp-32]
    jmp     ep_lp
ep_done:
    FRAME_EPILOG
    ret
xl_enc_package endp

; xl_build_ei() - assemble the EncryptionInfo stream into g_eibuf
EIC macro s
    lea     rcx, [g_eibuf]
    lea     rdx, [s]
    call    buf_putcstr
endm
EIB macro src, len
    lea     rdx, [src]
    mov     r8, len
    call    b64_put
endm
xl_build_ei proc frame
    FRAME_PROLOG 48
    lea     rcx, [g_eibuf]
    lea     rdx, [ei_hdr]
    mov     r8, 8
    call    buf_putn
    EIC     ei_c1
    EIB     g_kdSalt, 16
    EIC     ei_c2
    EIB     g_encHK, 64
    EIC     ei_c3
    EIB     g_encHV, 64
    EIC     ei_c4
    EIB     g_pwSalt, 16
    EIC     ei_c5
    EIB     g_encVHI, 16
    EIC     ei_c6
    EIB     g_encVHV, 64
    EIC     ei_c7
    EIB     g_encKV, 32
    EIC     ei_c8
    FRAME_EPILOG
    ret
xl_build_ei endp

; ---- OLE2 / CFB writer ------------------------------------------------------
OP16 macro v
    lea     rcx, [g_olebuf]
    mov     edx, v
    call    buf_pu16
endm
OP32 macro v
    lea     rcx, [g_olebuf]
    mov     edx, v
    call    buf_pu32
endm
OPZ macro n
    lea     rcx, [g_olebuf]
    mov     rdx, n
    call    buf_zero
endm

; ole_hdr() - 512-byte compound-file header
ole_hdr proc frame
    FRAME_PROLOG 48
    lea     rcx, [g_olebuf]
    lea     rdx, [ole_sig]
    mov     r8, 8
    call    buf_putn
    OPZ     16                                   ; CLSID
    OP16    003Eh                                ; minor version
    OP16    0003h                                ; major version (v3)
    OP16    0FFFEh                               ; byte order
    OP16    0009h                                ; sector shift (512)
    OP16    0006h                                ; mini sector shift (64)
    OPZ     6                                    ; reserved
    OP32    0                                    ; num dir sectors (0 for v3)
    OP32    dword ptr [g_F]                      ; num FAT sectors
    OP32    dword ptr [g_dirStart]               ; first dir sector
    OP32    0                                    ; transaction sig
    OP32    00001000h                            ; mini stream cutoff
    OP32    dword ptr [g_mfStart]                ; first MiniFAT sector
    OP32    dword ptr [g_miniFSec]               ; num MiniFAT sectors
    OP32    ENDCHAIN                             ; first DIFAT sector
    OP32    0                                    ; num DIFAT sectors
    ; DIFAT[109]: first F entries are 0..F-1, rest FREESECT
    mov     dword ptr [rbp-24], 0
oh_dl:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, 109
    jae     oh_done
    cmp     eax, dword ptr [g_F]
    jae     oh_free
    OP32    dword ptr [rbp-24]
    jmp     oh_next
oh_free:
    OP32    FREESECT
oh_next:
    inc     dword ptr [rbp-24]
    jmp     oh_dl
oh_done:
    FRAME_EPILOG
    ret
ole_hdr endp

; ole_fat() - the FAT sectors (F * 128 entries)
ole_fat proc frame
    FRAME_PROLOG 64
    mov     eax, dword ptr [g_F]
    shl     eax, 7                               ; F * 128 entries
    mov     dword ptr [rbp-24], eax              ; total entries
    mov     dword ptr [rbp-32], 0                ; i
of_lp:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [rbp-24]
    jae     of_done
    ; default FREESECT
    mov     r10d, FREESECT
    ; FAT sectors themselves
    cmp     eax, dword ptr [g_F]
    jae     of_c_dir
    mov     r10d, FATSECT
    jmp     of_emit
of_c_dir:
    ; directory run [dirStart, dirStart+3)
    mov     ecx, dword ptr [g_dirStart]
    cmp     eax, ecx
    jb      of_c_mf
    mov     edx, ecx
    add     edx, 3
    cmp     eax, edx
    jae     of_c_mf
    call    of_chain
    jmp     of_emit
of_c_mf:
    ; MiniFAT run [mfStart, mfStart+miniFSec)
    mov     ecx, dword ptr [g_mfStart]
    cmp     eax, ecx
    jb      of_c_mc
    mov     edx, ecx
    add     edx, dword ptr [g_miniFSec]
    cmp     eax, edx
    jae     of_c_mc
    call    of_chain
    jmp     of_emit
of_c_mc:
    ; mini container run [mcStart, mcStart+miniCSec)
    mov     ecx, dword ptr [g_mcStart]
    cmp     eax, ecx
    jb      of_c_pkg
    mov     edx, ecx
    add     edx, dword ptr [g_miniCSec]
    cmp     eax, edx
    jae     of_c_pkg
    call    of_chain
    jmp     of_emit
of_c_pkg:
    ; package run [pkgStart, pkgStart+pkgSec)
    mov     ecx, dword ptr [g_pkgStart]
    cmp     eax, ecx
    jb      of_emit
    mov     edx, ecx
    add     edx, dword ptr [g_pkgSec]
    cmp     eax, edx
    jae     of_emit
    call    of_chain
of_emit:
    lea     rcx, [g_olebuf]
    mov     edx, r10d
    call    buf_pu32
    inc     dword ptr [rbp-32]
    jmp     of_lp
of_done:
    FRAME_EPILOG
    ret
ole_fat endp

; of_chain - helper: for sector index eax within a run [ecx, edx), set r10d to
;   the next sector, or ENDCHAIN if it is the last in the run.  Leaf.
of_chain proc
    mov     r10d, eax
    inc     r10d                                 ; next = i+1
    mov     r11d, edx
    dec     r11d                                 ; last = end-1
    cmp     eax, r11d
    jne     ofc_ret
    mov     r10d, ENDCHAIN
ofc_ret:
    ret
of_chain endp

; ole_dirent(rcx=wname, edx=namelenbytes, r8d=objtype, r9d=left) using globals
;   g_de_right / g_de_child / g_de_start / g_de_size
ole_dirent proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [rbp-40], r8d
    mov     dword ptr [rbp-48], r9d
    ; name (64 bytes): wname then zero pad
    lea     rcx, [g_olebuf]
    mov     rdx, qword ptr [rbp-24]
    mov     r8d, dword ptr [rbp-32]
    call    buf_putn
    lea     rcx, [g_olebuf]
    mov     edx, 64
    sub     edx, dword ptr [rbp-32]
    mov     rdx, rdx
    call    buf_zero
    OP16    dword ptr [rbp-32]                   ; name length (bytes incl null)
    lea     rcx, [g_olebuf]                      ; object type
    mov     dl, byte ptr [rbp-40]
    call    buf_putb
    lea     rcx, [g_olebuf]                      ; color flag (red/black)
    mov     dl, byte ptr [g_de_color]
    call    buf_putb
    OP32    dword ptr [rbp-48]                   ; left sibling
    OP32    dword ptr [g_de_right]               ; right sibling
    OP32    dword ptr [g_de_child]               ; child
    OPZ     16                                   ; CLSID
    OP32    0                                    ; state bits
    OPZ     8                                    ; creation time
    OPZ     8                                    ; modified time
    OP32    dword ptr [g_de_start]               ; start sector
    OP32    dword ptr [g_de_size]                ; stream size (low)
    OP32    0                                    ; stream size (high)
    FRAME_EPILOG
    ret
ole_dirent endp

; DENT nm,nl,ty,cl,lf,rt,ch,st,sz - emit one directory entry (start/size are
;   operands loadable with `mov eax,<op>`; sibling links are immediates).
DENT macro nm, nl, ty, cl, lf, rt, ch, st, sz
    mov     dword ptr [g_de_color], cl
    mov     dword ptr [g_de_right], rt
    mov     dword ptr [g_de_child], ch
    mov     eax, st
    mov     dword ptr [g_de_start], eax
    mov     eax, sz
    mov     dword ptr [g_de_size], eax
    lea     rcx, [nm]
    mov     edx, nl
    mov     r8d, ty
    mov     r9d, lf
    call    ole_dirent
endm

; ole_dir() - the full directory: Root + EncryptionInfo + EncryptedPackage plus
;   the mandatory \x06DataSpaces transform tree (11 entries + 1 empty = 3 sectors).
;   Tree links/colors mirror what Office itself writes (Excel validates them).
ole_dir proc frame
    FRAME_PROLOG 48
    DENT w_root,  22, 5, 0, -1, -1, 10, dword ptr [g_mcStart], dword ptr [g_miniCLen]
    DENT w_ep,    34, 2, 0, -1, -1, -1, dword ptr [g_pkgStart], dword ptr [g_EPlen]
    DENT w_ds,    24, 1, 0, -1, -1,  4, 0, 0
    DENT w_ver,   16, 2, 1, -1, -1, -1, 0, 76
    DENT w_dsmap, 26, 2, 1,  3,  5, -1, 2, 112
    DENT w_dsinf, 28, 1, 1, -1,  7,  6, 0, 0
    DENT w_strds, 52, 2, 1, -1, -1, -1, 4, 64
    DENT w_tinf,  28, 1, 0, -1, -1,  8, 0, 0
    DENT w_strtr, 52, 1, 1, -1, -1,  9, 0, 0
    DENT w_prim,  18, 2, 1, -1, -1, -1, 5, 200
    DENT w_ei,    30, 2, 1,  2,  1, -1, 9, dword ptr [g_EIlen]
    OPZ     128                                  ; 12th slot (unused)
    FRAME_EPILOG
    ret
ole_dir endp

; ole_minifat() - MiniFAT: chain the 5 mini streams (9 fixed DataSpaces mini-
;   sectors 0..8 via mf_fixed, then EncryptionInfo starting at mini-sector 9)
ole_minifat proc frame
    FRAME_PROLOG 48
    mov     eax, dword ptr [g_miniFSec]
    shl     eax, 7                               ; total minifat slots
    mov     dword ptr [rbp-24], eax
    mov     dword ptr [rbp-32], 0                ; i
    mov     eax, dword ptr [g_numMini]           ; lastEI = 9 + eiMS - 1
    dec     eax
    mov     dword ptr [rbp-40], eax
omf_lp:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [rbp-24]
    jae     omf_done
    cmp     eax, 9
    jae     omf_ei
    lea     r10, [mf_fixed]                      ; fixed 0..8
    mov     r10d, dword ptr [r10+rax*4]
    jmp     omf_emit
omf_ei:
    cmp     eax, dword ptr [rbp-40]              ; EncryptionInfo run [9, lastEI]
    ja      omf_free
    jne     omf_next
    mov     r10d, ENDCHAIN
    jmp     omf_emit
omf_next:
    mov     r10d, eax
    inc     r10d
    jmp     omf_emit
omf_free:
    mov     r10d, FREESECT
omf_emit:
    lea     rcx, [g_olebuf]
    mov     edx, r10d
    call    buf_pu32
    inc     dword ptr [rbp-32]
    jmp     omf_lp
omf_done:
    FRAME_EPILOG
    ret
ole_minifat endp

; MC1 src,len,pad - append a mini stream padded to its mini-sector multiple
MC1 macro src, len, pad
    lea     rcx, [g_olebuf]
    lea     rdx, [src]
    mov     r8, len
    call    buf_putn
    lea     rcx, [g_olebuf]
    mov     rdx, pad
    call    buf_zero
endm

; ole_minicont() - the mini-stream container: Version, DataSpaceMap,
;   StrongEncryptionDataSpace, \x06Primary, EncryptionInfo (each mini-aligned)
ole_minicont proc frame
    FRAME_PROLOG 48
    MC1     ds_version,   76,  52                 ; -> 128 (2 mini-sectors)
    MC1     ds_dsmap,    112,  16                 ; -> 128
    MC1     ds_strongds,  64,   0                 ; -> 64  (1)
    MC1     ds_primary,  200,  56                 ; -> 256 (4)
    lea     rcx, [g_olebuf]                       ; EncryptionInfo -> eiMS*64
    lea     rdx, [g_ei]
    mov     r8d, dword ptr [g_EIlen]
    call    buf_putn
    lea     rcx, [g_olebuf]
    mov     eax, dword ptr [g_eiMS]
    shl     eax, 6
    sub     eax, dword ptr [g_EIlen]
    mov     edx, eax
    call    buf_zero
    ; pad the whole container to a 512-sector multiple
    lea     rcx, [g_olebuf]
    mov     eax, dword ptr [g_miniCSec]
    shl     eax, 9
    sub     eax, dword ptr [g_miniCLen]
    mov     edx, eax
    call    buf_zero
    FRAME_EPILOG
    ret
ole_minicont endp

; ole_pkg() - the EncryptedPackage stream, padded to a 512-sector multiple
ole_pkg proc frame
    FRAME_PROLOG 48
    lea     r10, [g_encbuf]
    lea     rcx, [g_olebuf]
    mov     rdx, qword ptr [r10]
    mov     r8d, dword ptr [g_EPlen]
    call    buf_putn
    mov     eax, dword ptr [g_pkgSec]
    shl     eax, 9
    sub     eax, dword ptr [g_EPlen]
    lea     rcx, [g_olebuf]
    mov     edx, eax
    mov     rdx, rdx
    call    buf_zero
    FRAME_EPILOG
    ret
ole_pkg endp

; xl_ole_write() - lay out sectors and assemble the compound file into g_olebuf
xl_ole_write proc frame
    FRAME_PROLOG 48
    lea     r10, [g_eibuf]
    mov     eax, dword ptr [r10+8]
    mov     dword ptr [g_EIlen], eax
    lea     r10, [g_encbuf]
    mov     eax, dword ptr [r10+8]
    mov     dword ptr [g_EPlen], eax
    mov     eax, dword ptr [g_EIlen]             ; eiMS = ceil(EIlen/64)
    add     eax, 63
    shr     eax, 6
    mov     dword ptr [g_eiMS], eax
    add     eax, 9                               ; numMini = 9 fixed + eiMS
    mov     dword ptr [g_numMini], eax
    shl     eax, 6                               ; miniCLen = numMini*64
    mov     dword ptr [g_miniCLen], eax
    add     eax, 511                             ; miniCSec = ceil(miniCLen/512)
    shr     eax, 9
    mov     dword ptr [g_miniCSec], eax
    mov     eax, dword ptr [g_EPlen]             ; pkgSec = ceil(EPlen/512)
    add     eax, 511
    shr     eax, 9
    mov     dword ptr [g_pkgSec], eax
    mov     eax, dword ptr [g_numMini]           ; miniFSec = ceil(numMini/128)
    add     eax, 127
    shr     eax, 7
    mov     dword ptr [g_miniFSec], eax
    ; nonFat = 3 (dir) + miniFSec + miniCSec + pkgSec
    mov     ecx, 3
    add     ecx, dword ptr [g_miniFSec]
    add     ecx, dword ptr [g_miniCSec]
    add     ecx, dword ptr [g_pkgSec]
    ; iterate F
    mov     edx, 1
xow_fit:
    mov     eax, edx
    add     eax, ecx
    add     eax, 127
    shr     eax, 7
    cmp     eax, edx
    jbe     xow_fdone
    mov     edx, eax
    jmp     xow_fit
xow_fdone:
    mov     dword ptr [g_F], edx
    mov     eax, edx
    add     eax, ecx
    mov     dword ptr [g_T], eax
    mov     eax, dword ptr [g_F]
    mov     dword ptr [g_dirStart], eax
    add     eax, 3                               ; directory is 3 sectors
    mov     dword ptr [g_mfStart], eax
    add     eax, dword ptr [g_miniFSec]
    mov     dword ptr [g_mcStart], eax
    add     eax, dword ptr [g_miniCSec]
    mov     dword ptr [g_pkgStart], eax
    call    ole_hdr
    call    ole_fat
    call    ole_dir
    call    ole_minifat
    call    ole_minicont
    call    ole_pkg
    FRAME_EPILOG
    ret
xl_ole_write endp

; =============================================================================
; xl_encrypt(rcx = wide password ptr, edx = password length in bytes) -> eax
; =============================================================================
public xl_encrypt
xl_encrypt proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx             ; wpw
    mov     dword ptr [rbp-32], edx             ; wpwlen
    mov     byte ptr [g_xl_err], 0
    ; buffers
    mov     rcx, XL_ECAP
    call    secmem_alloc
    test    rax, rax
    jz      xe_fail
    lea     r10, [g_encbuf]
    mov     qword ptr [r10], rax
    mov     qword ptr [r10+8], 0
    mov     qword ptr [r10+16], XL_ECAP
    mov     rcx, XL_ECAP
    call    secmem_alloc
    test    rax, rax
    jz      xe_fail
    lea     r10, [g_olebuf]
    mov     qword ptr [r10], rax
    mov     qword ptr [r10+8], 0
    mov     qword ptr [r10+16], XL_ECAP
    lea     r10, [g_eibuf]
    lea     rax, [g_ei]
    mov     qword ptr [r10], rax
    mov     qword ptr [r10+8], 0
    mov     qword ptr [r10+16], 8192
    ; random salts + keys
    lea     rcx, [g_pwSalt]
    mov     edx, 16
    call    rng_fill
    lea     rcx, [g_kdSalt]
    mov     edx, 16
    call    rng_fill
    lea     rcx, [g_pkgKey]
    mov     edx, 32
    call    rng_fill
    lea     rcx, [g_vin]
    mov     edx, 16
    call    rng_fill
    lea     rcx, [g_hmKey]
    mov     edx, 64
    call    rng_fill
    ; H = SHA512(pwSalt || wpw)
    lea     rcx, [g_scr]
    lea     rdx, [g_pwSalt]
    mov     r8, 16
    call    xcopy
    lea     rcx, [g_scr+16]
    mov     rdx, qword ptr [rbp-24]
    mov     r8d, dword ptr [rbp-32]
    call    xcopy
    lea     rcx, [g_scr]
    mov     edx, 16
    add     edx, dword ptr [rbp-32]
    lea     r8, [g_H]
    call    sha512_hash
    ; spin: H = SHA512(LE32(i) || H)
    mov     dword ptr [rbp-40], 0
xe_spin:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, SPIN_COUNT
    jae     xe_spun
    mov     dword ptr [g_scr], eax              ; LE32(i)
    lea     rcx, [g_scr+4]
    lea     rdx, [g_H]
    mov     r8, 64
    call    xcopy
    lea     rcx, [g_scr]
    mov     edx, 68
    lea     r8, [g_H]
    call    sha512_hash
    inc     dword ptr [rbp-40]
    jmp     xe_spin
xe_spun:
    ; verifier hash input
    lea     rcx, [bk_vhi]
    call    derive_key
    lea     rcx, [g_encVHI]
    lea     rdx, [g_vin]
    mov     r8, 16
    call    xcopy
    lea     rcx, [g_dk]
    lea     rdx, [g_pwSalt]
    lea     r8, [g_encVHI]
    mov     r9, 16
    call    xl_cbc
    ; verifier hash value = Encrypt(SHA512(vin)).  Derive the key FIRST: derive_key
    ; also writes the shared g_tmp64 scratch, so hashing vin must come after it.
    lea     rcx, [bk_vhv]
    call    derive_key
    lea     rcx, [g_vin]
    mov     rdx, 16
    lea     r8, [g_tmp64]
    call    sha512_hash
    lea     rcx, [g_encVHV]
    lea     rdx, [g_tmp64]
    mov     r8, 64
    call    xcopy
    lea     rcx, [g_dk]
    lea     rdx, [g_pwSalt]
    lea     r8, [g_encVHV]
    mov     r9, 64
    call    xl_cbc
    ; encrypted package key
    lea     rcx, [bk_kv]
    call    derive_key
    lea     rcx, [g_encKV]
    lea     rdx, [g_pkgKey]
    mov     r8, 32
    call    xcopy
    lea     rcx, [g_dk]
    lea     rdx, [g_pwSalt]
    lea     r8, [g_encKV]
    mov     r9, 32
    call    xl_cbc
    ; encrypt the package
    call    xl_enc_package
    ; dataIntegrity: encrypted HMAC key
    lea     rcx, [bk_hk]
    mov     edx, 8
    call    iv_from
    lea     rcx, [g_encHK]
    lea     rdx, [g_hmKey]
    mov     r8, 64
    call    xcopy
    lea     rcx, [g_pkgKey]
    lea     rdx, [g_ivt]
    lea     r8, [g_encHK]
    mov     r9, 64
    call    xl_cbc
    ; encrypted HMAC value: derive the IV FIRST (iv_from writes the shared g_tmp64
    ; scratch), then compute the HMAC into g_tmp64 so it isn't clobbered.
    lea     rcx, [bk_hv]
    mov     edx, 8
    call    iv_from
    lea     rcx, [g_hmKey]
    mov     edx, 64
    lea     r10, [g_encbuf]
    mov     r8, qword ptr [r10]
    mov     r9, qword ptr [r10+8]
    lea     rax, [g_tmp64]
    mov     qword ptr [rsp+32], rax
    call    hmac_sha512
    lea     rcx, [g_encHV]
    lea     rdx, [g_tmp64]
    mov     r8, 64
    call    xcopy
    lea     rcx, [g_pkgKey]
    lea     rdx, [g_ivt]
    lea     r8, [g_encHV]
    mov     r9, 64
    call    xl_cbc
    ; EncryptionInfo + compound file
    call    xl_build_ei
    call    xl_ole_write
    cmp     byte ptr [g_xl_err], 0
    jnz     xe_fail
    lea     r10, [g_olebuf]
    mov     rax, qword ptr [r10]
    mov     qword ptr [g_ole_ptr], rax
    mov     rax, qword ptr [r10+8]
    mov     qword ptr [g_ole_len], rax
    call    xe_wipe
    xor     eax, eax
    FRAME_EPILOG
    ret
xe_fail:
    call    xe_wipe
    call    xl_encrypt_free
    mov     eax, 1
    FRAME_EPILOG
    ret
xl_encrypt endp

; xe_wipe - zero the secret key material (salts/keys/hash state)
xe_wipe proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_pwSalt]
    xor     r8d, r8d
xw_lp:
    mov     byte ptr [rcx+r8], 0
    inc     r8d
    cmp     r8d, 16+16+32+16+64+64+32+256+64+16   ; through g_ivt
    jb      xw_lp
    FRAME_EPILOG
    ret
xe_wipe endp

; xl_encrypt_free() - wipe + release the encryption buffers
public xl_encrypt_free
xl_encrypt_free proc frame
    FRAME_PROLOG 48
    lea     r10, [g_encbuf]
    mov     rcx, qword ptr [r10]
    test    rcx, rcx
    jz      xef_ole
    mov     rdx, XL_ECAP
    call    secmem_free
    lea     r10, [g_encbuf]
    mov     qword ptr [r10], 0
xef_ole:
    lea     r10, [g_olebuf]
    mov     rcx, qword ptr [r10]
    test    rcx, rcx
    jz      xef_done
    mov     rdx, XL_ECAP
    call    secmem_free
    lea     r10, [g_olebuf]
    mov     qword ptr [r10], 0
xef_done:
    mov     qword ptr [g_ole_ptr], 0
    mov     qword ptr [g_ole_len], 0
    FRAME_EPILOG
    ret
xl_encrypt_free endp

end
