; =============================================================================
; inflate.asm - RFC-1951 DEFLATE decompressor (Mark Adler "puff" algorithm),
; used to read real (DEFLATE-compressed) .xlsx / .zip entries.
;
;   inflate(rcx=src, rdx=srclen, r8=dst, r9=dstcap) -> eax = out bytes / -1 error
;
; Single-threaded: bit-reader state + the Huffman tables live in globals.
; =============================================================================

include macros.inc

.const
align 2
inf_lbase dw 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258
inf_lext  db 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
inf_dbase dw 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
inf_dext  db 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13
inf_clord db 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15

.data?
align 8
inf_src     dq ?
inf_end     dq ?
inf_bitbuf  dd ?
inf_bitcnt  dd ?
inf_dst     dq ?
inf_dcap    dq ?
inf_dlen    dq ?
lc_count    dw 16 dup (?)
lc_sym      dw 288 dup (?)
dc_count    dw 16 dup (?)
dc_sym      dw 32 dup (?)
cl_count    dw 16 dup (?)
cl_sym      dw 19 dup (?)
inf_lens    db 320 dup (?)

.code

; inf_bits(ecx=n, 0..16) -> eax = n bits LSB-first.  CF set on input exhaustion.
inf_bits proc
    xor     eax, eax
    xor     r8d, r8d                            ; output shift
ib_lp:
    test    ecx, ecx
    jz      ib_ok
    cmp     dword ptr [inf_bitcnt], 0
    jne     ib_have
    mov     r11, qword ptr [inf_src]
    cmp     r11, qword ptr [inf_end]
    jae     ib_eof
    movzx   r9d, byte ptr [r11]
    inc     r11
    mov     qword ptr [inf_src], r11
    mov     dword ptr [inf_bitbuf], r9d
    mov     dword ptr [inf_bitcnt], 8
ib_have:
    mov     r9d, dword ptr [inf_bitbuf]
    and     r9d, 1
    shr     dword ptr [inf_bitbuf], 1
    dec     dword ptr [inf_bitcnt]
    mov     r10d, ecx                           ; save n (cl needed for the shift)
    mov     ecx, r8d
    shl     r9d, cl
    mov     ecx, r10d
    or      eax, r9d
    inc     r8d
    dec     ecx
    jmp     ib_lp
ib_ok:
    clc
    ret
ib_eof:
    stc
    ret
inf_bits endp

; inf_decode(rcx=count, rdx=symbol) -> eax = symbol.  CF set on error.
inf_decode proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     dword ptr [rbp-36], 0               ; code
    mov     dword ptr [rbp-40], 0               ; first
    mov     dword ptr [rbp-44], 0               ; index
    mov     dword ptr [rbp-48], 1               ; len
id_lp:
    cmp     dword ptr [rbp-48], 15
    ja      id_err
    mov     ecx, 1
    call    inf_bits
    jc      id_err
    or      dword ptr [rbp-36], eax             ; code |= bit
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [rbp-48]
    movzx   r8d, word ptr [r10+rax*2]           ; count = count[len]
    mov     edx, dword ptr [rbp-36]
    sub     edx, r8d                            ; code - count
    cmp     edx, dword ptr [rbp-40]             ; < first ? (signed)
    jl      id_ret
    add     dword ptr [rbp-44], r8d             ; index += count
    add     dword ptr [rbp-40], r8d             ; first += count
    shl     dword ptr [rbp-40], 1               ; first <<= 1
    shl     dword ptr [rbp-36], 1               ; code <<= 1
    inc     dword ptr [rbp-48]
    jmp     id_lp
id_ret:
    mov     eax, dword ptr [rbp-36]
    sub     eax, dword ptr [rbp-40]
    add     eax, dword ptr [rbp-44]             ; index + code - first
    mov     r10, qword ptr [rbp-32]
    movzx   eax, word ptr [r10+rax*2]
    clc
    FRAME_EPILOG
    ret
id_err:
    stc
    FRAME_EPILOG
    ret
inf_decode endp

; inf_construct(rcx=count out, rdx=symbol out, r8=lengths, r9d=n) - build a
;   canonical Huffman decode table.  Leaf (no calls).
inf_construct proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     dword ptr [rbp-48], r9d
    mov     r10, qword ptr [rbp-24]             ; zero count[0..15]
    xor     eax, eax
ic_z:
    cmp     eax, 16
    jae     ic_zd
    mov     word ptr [r10+rax*2], 0
    inc     eax
    jmp     ic_z
ic_zd:
    xor     eax, eax                            ; count lengths
ic_c:
    cmp     eax, dword ptr [rbp-48]
    jae     ic_cd
    mov     r11, qword ptr [rbp-40]
    movzx   ecx, byte ptr [r11+rax]
    mov     r10, qword ptr [rbp-24]
    inc     word ptr [r10+rcx*2]
    inc     eax
    jmp     ic_c
ic_cd:
    lea     r11, [rbp-88]                       ; offs[16] words
    mov     word ptr [r11+2], 0                 ; offs[1] = 0
    mov     ecx, 1
ic_o:
    cmp     ecx, 15
    ja      ic_od
    mov     r10, qword ptr [rbp-24]
    movzx   eax, word ptr [r10+rcx*2]           ; count[len]
    movzx   edx, word ptr [r11+rcx*2]           ; offs[len]
    add     eax, edx
    mov     word ptr [r11+rcx*2+2], ax          ; offs[len+1]
    inc     ecx
    jmp     ic_o
ic_od:
    xor     eax, eax                            ; place symbols
ic_s:
    cmp     eax, dword ptr [rbp-48]
    jae     ic_sd
    mov     r10, qword ptr [rbp-40]
    movzx   ecx, byte ptr [r10+rax]             ; len
    test    ecx, ecx
    jz      ic_sn
    lea     r11, [rbp-88]
    movzx   edx, word ptr [r11+rcx*2]           ; offs[len]
    mov     r10, qword ptr [rbp-32]
    mov     word ptr [r10+rdx*2], ax            ; symbol[offs[len]] = i
    lea     r11, [rbp-88]
    inc     word ptr [r11+rcx*2]
ic_sn:
    inc     eax
    jmp     ic_s
ic_sd:
    FRAME_EPILOG
    ret
inf_construct endp

; inf_codes() -> eax 0/err.  Decode literal/length + distance codes into inf_dst.
inf_codes proc frame
    FRAME_PROLOG 96                             ; locals above the callee shadow region
ico_lp:
    lea     rcx, [lc_count]
    lea     rdx, [lc_sym]
    call    inf_decode
    jc      ico_err
    cmp     eax, 256
    ja      ico_len
    je      ico_done                            ; 256 = end of block
    ; literal
    mov     rcx, qword ptr [inf_dlen]
    cmp     rcx, qword ptr [inf_dcap]
    jae     ico_err
    mov     r10, qword ptr [inf_dst]
    mov     byte ptr [r10+rcx], al
    inc     qword ptr [inf_dlen]
    jmp     ico_lp
ico_len:
    sub     eax, 257
    cmp     eax, 28
    ja      ico_err
    mov     dword ptr [rbp-24], eax             ; length sym
    lea     r10, [inf_lbase]
    movzx   r11d, word ptr [r10+rax*2]
    mov     dword ptr [rbp-28], r11d            ; base length
    lea     r10, [inf_lext]
    movzx   ecx, byte ptr [r10+rax]
    call    inf_bits
    jc      ico_err
    add     eax, dword ptr [rbp-28]
    mov     dword ptr [rbp-32], eax             ; length
    lea     rcx, [dc_count]
    lea     rdx, [dc_sym]
    call    inf_decode
    jc      ico_err
    cmp     eax, 29
    ja      ico_err
    mov     dword ptr [rbp-36], eax             ; dist sym
    lea     r10, [inf_dbase]
    movzx   r11d, word ptr [r10+rax*2]
    mov     dword ptr [rbp-40], r11d
    lea     r10, [inf_dext]
    movzx   ecx, byte ptr [r10+rax]
    call    inf_bits
    jc      ico_err
    add     eax, dword ptr [rbp-40]
    mov     dword ptr [rbp-44], eax             ; distance
    ; copy [length] bytes from (dlen - dist), byte by byte (handles overlap)
    mov     rax, qword ptr [inf_dlen]
    mov     ecx, dword ptr [rbp-44]
    cmp     rax, rcx
    jb      ico_err                             ; distance before start
    mov     r8d, dword ptr [rbp-32]             ; remaining length
ico_cp:
    test    r8d, r8d
    jz      ico_lp
    mov     rax, qword ptr [inf_dlen]
    cmp     rax, qword ptr [inf_dcap]
    jae     ico_err
    mov     r10, qword ptr [inf_dst]
    mov     r11, rax
    mov     ecx, dword ptr [rbp-44]             ; dist (zero-extended)
    sub     r11, rcx                            ; src = dlen - dist
    mov     dl, byte ptr [r10+r11]
    mov     byte ptr [r10+rax], dl
    inc     qword ptr [inf_dlen]
    dec     r8d
    jmp     ico_cp
ico_done:
    xor     eax, eax
    FRAME_EPILOG
    ret
ico_err:
    mov     eax, 1
    FRAME_EPILOG
    ret
inf_codes endp

; inf_fixed() - build the fixed literal/length + distance tables, then inf_codes.
inf_fixed proc frame
    FRAME_PROLOG 32
    lea     r10, [inf_lens]                     ; 0-143:8 144-255:9 256-279:7 280-287:8
    xor     eax, eax
if_l1:
    cmp     eax, 144
    jae     if_l2
    mov     byte ptr [r10+rax], 8
    inc     eax
    jmp     if_l1
if_l2:
    cmp     eax, 256
    jae     if_l3
    mov     byte ptr [r10+rax], 9
    inc     eax
    jmp     if_l2
if_l3:
    cmp     eax, 280
    jae     if_l4
    mov     byte ptr [r10+rax], 7
    inc     eax
    jmp     if_l3
if_l4:
    cmp     eax, 288
    jae     if_ld
    mov     byte ptr [r10+rax], 8
    inc     eax
    jmp     if_l4
if_ld:
    lea     rcx, [lc_count]
    lea     rdx, [lc_sym]
    lea     r8, [inf_lens]
    mov     r9d, 288
    call    inf_construct
    lea     r10, [inf_lens]                     ; distances: all 5
    xor     eax, eax
if_d:
    cmp     eax, 30
    jae     if_dd
    mov     byte ptr [r10+rax], 5
    inc     eax
    jmp     if_d
if_dd:
    lea     rcx, [dc_count]
    lea     rdx, [dc_sym]
    lea     r8, [inf_lens]
    mov     r9d, 30
    call    inf_construct
    call    inf_codes
    FRAME_EPILOG
    ret
inf_fixed endp

; inf_dynamic() -> eax 0/err.
inf_dynamic proc frame
    FRAME_PROLOG 96                             ; locals above the callee shadow region
    mov     ecx, 5
    call    inf_bits
    jc      idy_err
    add     eax, 257
    mov     dword ptr [rbp-24], eax             ; hlit
    mov     ecx, 5
    call    inf_bits
    jc      idy_err
    add     eax, 1
    mov     dword ptr [rbp-28], eax             ; hdist
    mov     ecx, 4
    call    inf_bits
    jc      idy_err
    add     eax, 4
    mov     dword ptr [rbp-32], eax             ; hclen
    ; clear the 19 code-length code lengths
    lea     r10, [inf_lens]
    xor     eax, eax
idy_z:
    cmp     eax, 19
    jae     idy_zd
    mov     byte ptr [r10+rax], 0
    inc     eax
    jmp     idy_z
idy_zd:
    xor     eax, eax                            ; read hclen of them (in clord order)
idy_cl:
    cmp     eax, dword ptr [rbp-32]
    jae     idy_cld
    mov     dword ptr [rbp-36], eax
    mov     ecx, 3
    call    inf_bits
    jc      idy_err
    mov     r10d, eax                           ; the 3-bit value
    lea     r11, [inf_clord]
    mov     eax, dword ptr [rbp-36]
    movzx   edx, byte ptr [r11+rax]             ; clord[i]
    lea     r11, [inf_lens]
    mov     byte ptr [r11+rdx], r10b
    mov     eax, dword ptr [rbp-36]
    inc     eax
    jmp     idy_cl
idy_cld:
    lea     rcx, [cl_count]
    lea     rdx, [cl_sym]
    lea     r8, [inf_lens]
    mov     r9d, 19
    call    inf_construct
    ; decode hlit+hdist code lengths into inf_lens using the cl table
    mov     eax, dword ptr [rbp-24]
    add     eax, dword ptr [rbp-28]
    mov     dword ptr [rbp-40], eax             ; total
    mov     dword ptr [rbp-44], 0               ; index
idy_dec:
    mov     eax, dword ptr [rbp-44]
    cmp     eax, dword ptr [rbp-40]
    jae     idy_build
    lea     rcx, [cl_count]
    lea     rdx, [cl_sym]
    call    inf_decode
    jc      idy_err
    cmp     eax, 16
    jae     idy_rep
    ; literal length symbol
    mov     ecx, dword ptr [rbp-44]
    lea     r11, [inf_lens]
    mov     byte ptr [r11+rcx], al
    inc     dword ptr [rbp-44]
    jmp     idy_dec
idy_rep:
    cmp     eax, 16
    jne     idy_r17
    ; repeat previous, bits(2)+3
    mov     ecx, dword ptr [rbp-44]
    test    ecx, ecx
    jz      idy_err
    lea     r11, [inf_lens]
    movzx   edx, byte ptr [r11+rcx-1]
    mov     dword ptr [rbp-48], edx             ; value to repeat
    mov     ecx, 2
    call    inf_bits
    jc      idy_err
    add     eax, 3
    jmp     idy_fill
idy_r17:
    cmp     eax, 17
    jne     idy_r18
    mov     dword ptr [rbp-48], 0
    mov     ecx, 3
    call    inf_bits
    jc      idy_err
    add     eax, 3
    jmp     idy_fill
idy_r18:
    mov     dword ptr [rbp-48], 0
    mov     ecx, 7
    call    inf_bits
    jc      idy_err
    add     eax, 11
idy_fill:
    mov     dword ptr [rbp-52], eax             ; repeat count
idy_fl:
    cmp     dword ptr [rbp-52], 0
    je      idy_dec
    mov     eax, dword ptr [rbp-44]
    cmp     eax, dword ptr [rbp-40]
    jae     idy_err
    mov     ecx, dword ptr [rbp-44]
    lea     r11, [inf_lens]
    mov     dl, byte ptr [rbp-48]
    mov     byte ptr [r11+rcx], dl
    inc     dword ptr [rbp-44]
    dec     dword ptr [rbp-52]
    jmp     idy_fl
idy_build:
    lea     rcx, [lc_count]
    lea     rdx, [lc_sym]
    lea     r8, [inf_lens]
    mov     r9d, dword ptr [rbp-24]
    call    inf_construct
    lea     rcx, [dc_count]
    lea     rdx, [dc_sym]
    lea     r8, [inf_lens]
    mov     eax, dword ptr [rbp-24]             ; hlit (zero-extended)
    add     r8, rax                             ; lens + hlit
    mov     r9d, dword ptr [rbp-28]
    call    inf_construct
    call    inf_codes
    FRAME_EPILOG
    ret
idy_err:
    mov     eax, 1
    FRAME_EPILOG
    ret
inf_dynamic endp

; =============================================================================
; inflate(rcx=src, rdx=srclen, r8=dst, r9=dstcap) -> eax = out bytes / -1
; =============================================================================
public inflate
inflate proc frame
    FRAME_PROLOG 64                             ; BFINAL local above the callee shadow region
    mov     qword ptr [inf_src], rcx
    add     rcx, rdx
    mov     qword ptr [inf_end], rcx
    mov     dword ptr [inf_bitcnt], 0
    mov     qword ptr [inf_dst], r8
    mov     qword ptr [inf_dcap], r9
    mov     qword ptr [inf_dlen], 0
inf_lp:
    mov     ecx, 1
    call    inf_bits                            ; BFINAL
    jc      inf_err
    mov     dword ptr [rbp-24], eax
    mov     ecx, 2
    call    inf_bits                            ; BTYPE
    jc      inf_err
    cmp     eax, 0
    je      inf_stored
    cmp     eax, 1
    je      inf_do_fixed
    cmp     eax, 2
    je      inf_do_dyn
    jmp     inf_err
inf_do_fixed:
    call    inf_fixed
    test    eax, eax
    jnz     inf_err
    jmp     inf_next
inf_do_dyn:
    call    inf_dynamic
    test    eax, eax
    jnz     inf_err
    jmp     inf_next
inf_stored:
    mov     dword ptr [inf_bitcnt], 0           ; discard bits to the byte boundary
    mov     r11, qword ptr [inf_src]
    mov     rax, r11
    add     rax, 4
    cmp     rax, qword ptr [inf_end]
    ja      inf_err
    movzx   r8d, word ptr [r11]                 ; LEN
    movzx   r9d, word ptr [r11+2]               ; NLEN
    add     r11, 4
    mov     qword ptr [inf_src], r11
    mov     eax, r8d                            ; LEN == ~NLEN & 0xffff ?
    xor     eax, 0FFFFh
    cmp     eax, r9d
    jne     inf_err
    mov     rax, r11
    add     rax, r8
    cmp     rax, qword ptr [inf_end]
    ja      inf_err
    mov     rax, qword ptr [inf_dlen]           ; room?
    add     rax, r8
    cmp     rax, qword ptr [inf_dcap]
    ja      inf_err
    xor     ecx, ecx
inf_scp:
    cmp     ecx, r8d
    jae     inf_scpd
    mov     r10, qword ptr [inf_src]
    mov     dl, byte ptr [r10+rcx]
    mov     r10, qword ptr [inf_dst]
    mov     rax, qword ptr [inf_dlen]
    add     rax, rcx
    mov     byte ptr [r10+rax], dl
    inc     ecx
    jmp     inf_scp
inf_scpd:
    mov     r10d, r8d
    add     qword ptr [inf_dlen], r10
    mov     rax, qword ptr [inf_src]
    add     rax, r10
    mov     qword ptr [inf_src], rax
inf_next:
    cmp     dword ptr [rbp-24], 0               ; BFINAL?
    je      inf_lp
    mov     rax, qword ptr [inf_dlen]
    FRAME_EPILOG
    ret
inf_err:
    mov     eax, -1
    FRAME_EPILOG
    ret
inflate endp

end
