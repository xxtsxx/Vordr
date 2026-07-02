; =============================================================================
; sha512.asm - SHA-512 (scalar 64-bit) + HMAC-SHA512
; -----------------------------------------------------------------------------
;   sha512_init   (rcx = ctx)
;   sha512_update (rcx = ctx, rdx = data, r8 = len)
;   sha512_final  (rcx = ctx, rdx = out64)
;   sha512_hash   (rcx = data, rdx = len, r8 = out64)          one-shot
;   hmac_sha512   (rcx = key, edx = keylen, r8 = msg, r9 = msglen, [rsp+40]=out64)
;
; No SHA-512 hardware acceleration is assumed (SHA512-NI is Arrow-Lake+ only),
; so the compressor is a straight scalar reference implementation.  Only used
; off the hot path (MS-OFFCRYPTO agile encryption for the .xlsx export), so the
; loss vs. a vectorized version does not matter.
; =============================================================================

include macros.inc

extern secure_zero:proc

SHA512_CTX struct
    state   dq 8 dup (?)            ; H0..H7
    buf     db 128 dup (?)          ; partial block
    buflen  dd ?                    ; bytes buffered (0..127)
    pad     dd ?
    total   dq ?                    ; total message length in bytes (< 2^64)
SHA512_CTX ends
public SHA512_CTX_SIZE
SHA512_CTX_SIZE equ sizeof SHA512_CTX

.const
align 16
init_h512 dq 06a09e667f3bcc908h,0bb67ae8584caa73bh,03c6ef372fe94f82bh,0a54ff53a5f1d36f1h
          dq 0510e527fade682d1h,09b05688c2b3e6c1fh,01f83d9abfb41bd6bh,05be0cd19137e2179h
align 16
k512 dq 0428a2f98d728ae22h,07137449123ef65cdh,0b5c0fbcfec4d3b2fh,0e9b5dba58189dbbch
     dq 03956c25bf348b538h,059f111f1b605d019h,0923f82a4af194f9bh,0ab1c5ed5da6d8118h
     dq 0d807aa98a3030242h,012835b0145706fbeh,0243185be4ee4b28ch,0550c7dc3d5ffb4e2h
     dq 072be5d74f27b896fh,080deb1fe3b1696b1h,09bdc06a725c71235h,0c19bf174cf692694h
     dq 0e49b69c19ef14ad2h,0efbe4786384f25e3h,00fc19dc68b8cd5b5h,0240ca1cc77ac9c65h
     dq 02de92c6f592b0275h,04a7484aa6ea6e483h,05cb0a9dcbd41fbd4h,076f988da831153b5h
     dq 0983e5152ee66dfabh,0a831c66d2db43210h,0b00327c898fb213fh,0bf597fc7beef0ee4h
     dq 0c6e00bf33da88fc2h,0d5a79147930aa725h,006ca6351e003826fh,0142929670a0e6e70h
     dq 027b70a8546d22ffch,02e1b21385c26c926h,04d2c6dfc5ac42aedh,053380d139d95b3dfh
     dq 0650a73548baf63deh,0766a0abb3c77b2a8h,081c2c92e47edaee6h,092722c851482353bh
     dq 0a2bfe8a14cf10364h,0a81a664bbc423001h,0c24b8b70d0f89791h,0c76c51a30654be30h
     dq 0d192e819d6ef5218h,0d69906245565a910h,0f40e35855771202ah,0106aa07032bbd1b8h
     dq 019a4c116b8d2d0c8h,01e376c085141ab53h,02748774cdf8eeb99h,034b0bcb5e19b48a8h
     dq 0391c0cb3c5c95a63h,04ed8aa4ae3418acbh,05b9cca4f7763e373h,0682e6ff3d6b2b8a3h
     dq 0748f82ee5defb2fch,078a5636f43172f60h,084c87814a1f0ab72h,08cc702081a6439ech
     dq 090befffa23631e28h,0a4506cebde82bde9h,0bef9a3f7b2c67915h,0c67178f2e372532bh
     dq 0ca273eceea26619ch,0d186b8c721c0c207h,0eada7dd6cde0eb1eh,0f57d4f7fee6ed178h
     dq 006f067aa72176fbah,00a637dc5a2c898a6h,0113f9804bef90daeh,01b710b35131c471bh
     dq 028db77f523047d84h,032caab7b40c72493h,03c9ebe0a15c9bebch,0431d67c49c100d4ch
     dq 04cc5d4becb3e42b6h,0597f299cfc657e2ah,05fcb6fab3ad6faech,06c44198c4a475817h

.code

; =============================================================================
; sha512_init(rcx = ctx)
; =============================================================================
public sha512_init
sha512_init proc
    lea     r10, [init_h512]
    xor     eax, eax
si_lp:
    mov     r11, qword ptr [r10+rax*8]
    mov     qword ptr [rcx+rax*8], r11
    inc     eax
    cmp     eax, 8
    jb      si_lp
    mov     dword ptr [rcx].SHA512_CTX.buflen, 0
    mov     qword ptr [rcx].SHA512_CTX.total, 0
    ret
sha512_init endp

; =============================================================================
; sha512_compress(rcx = state ptr (8 qw), rdx = block ptr, r8 = nblocks)
; Scalar leaf.  Saves all nonvolatile GPRs it uses.
;   layout on the local stack:  [rsp+0..639] = W[80],  [rsp+640..703] = a..h
; =============================================================================
sha512_compress proc
    push    rbx
    push    rsi
    push    rdi
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 640+64+16
    mov     rbx, rcx                        ; state ptr
    mov     rsi, rsp                         ; W base
    lea     rdi, [rsp+640]                   ; a..h base
    mov     qword ptr [rsp+704], rdx         ; block ptr
    mov     qword ptr [rsp+712], r8          ; nblocks
    test    r8, r8
    jz      scz_done
scz_block:
    ; load a..h from state
    xor     eax, eax
scz_ld:
    mov     r9, qword ptr [rbx+rax*8]
    mov     qword ptr [rdi+rax*8], r9
    inc     eax
    cmp     eax, 8
    jb      scz_ld
    ; W[0..15] = big-endian qwords of the block
    mov     r12, qword ptr [rsp+704]
    mov     r13, rsi
    mov     ecx, 16
scz_wl:
    mov     rax, qword ptr [r12]
    bswap   rax
    mov     qword ptr [r13], rax
    add     r12, 8
    add     r13, 8
    dec     ecx
    jnz     scz_wl
    ; W[16..79] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16]
    lea     r12, [rsi + 16*8]
    mov     r13d, 64
scz_sched:
    mov     rax, qword ptr [r12 - 2*8]       ; s1(W[t-2]) = ror19 ^ ror61 ^ shr6
    mov     rcx, rax
    ror     rax, 19
    mov     rdx, rcx
    ror     rdx, 61
    xor     rax, rdx
    shr     rcx, 6
    xor     rax, rcx                          ; rax = s1
    mov     rcx, qword ptr [r12 - 15*8]      ; s0(W[t-15]) = ror1 ^ ror8 ^ shr7
    mov     r8, rcx
    ror     rcx, 1
    mov     rdx, r8
    ror     rdx, 8
    xor     rcx, rdx
    shr     r8, 7
    xor     rcx, r8                           ; rcx = s0
    add     rax, rcx
    add     rax, qword ptr [r12 - 7*8]
    add     rax, qword ptr [r12 - 16*8]
    mov     qword ptr [r12], rax
    add     r12, 8
    dec     r13d
    jnz     scz_sched
    ; 80 rounds; rbp = &K[t], r12 = &W[t], r14 = round counter
    lea     rbp, [k512]
    mov     r12, rsi
    mov     r14d, 80
scz_round:
    ; S1 = ror(e,14) ^ ror(e,18) ^ ror(e,41)
    mov     rax, qword ptr [rdi+32]         ; e
    mov     rcx, rax
    ror     rax, 14
    mov     rdx, rcx
    ror     rdx, 18
    xor     rax, rdx
    mov     rdx, rcx
    ror     rdx, 41
    xor     rax, rdx                          ; rax = S1
    ; ch = (e & f) ^ (~e & g)
    mov     rcx, qword ptr [rdi+32]         ; e
    mov     rdx, qword ptr [rdi+40]         ; f
    and     rdx, rcx
    not     rcx
    mov     r8, qword ptr [rdi+48]          ; g
    and     r8, rcx
    xor     rdx, r8                           ; rdx = ch
    ; temp1 = h + S1 + ch + K[t] + W[t]
    mov     r9, qword ptr [rdi+56]          ; h
    add     r9, rax
    add     r9, rdx
    add     r9, qword ptr [rbp]              ; K[t]
    add     r9, qword ptr [r12]              ; W[t]   -> temp1 in r9
    ; S0 = ror(a,28) ^ ror(a,34) ^ ror(a,39)
    mov     rax, qword ptr [rdi+0]          ; a
    mov     rcx, rax
    ror     rax, 28
    mov     rdx, rcx
    ror     rdx, 34
    xor     rax, rdx
    mov     rdx, rcx
    ror     rdx, 39
    xor     rax, rdx                          ; rax = S0
    ; maj = (a&b) ^ (a&c) ^ (b&c)
    mov     rcx, qword ptr [rdi+0]          ; a
    mov     rdx, qword ptr [rdi+8]          ; b
    mov     r8, rcx
    and     r8, rdx                          ; a&b
    mov     r10, qword ptr [rdi+16]         ; c
    mov     r11, rcx
    and     r11, r10                         ; a&c
    xor     r8, r11
    and     rdx, r10                         ; b&c
    xor     r8, rdx                          ; r8 = maj
    add     rax, r8                          ; temp2 = S0 + maj (rax)
    ; shift the working vars
    mov     r10, qword ptr [rdi+48]         ; g -> h
    mov     qword ptr [rdi+56], r10
    mov     r10, qword ptr [rdi+40]         ; f -> g
    mov     qword ptr [rdi+48], r10
    mov     r10, qword ptr [rdi+32]         ; e -> f
    mov     qword ptr [rdi+40], r10
    mov     r10, qword ptr [rdi+24]         ; d + temp1 -> e
    add     r10, r9
    mov     qword ptr [rdi+32], r10
    mov     r10, qword ptr [rdi+16]         ; c -> d
    mov     qword ptr [rdi+24], r10
    mov     r10, qword ptr [rdi+8]          ; b -> c
    mov     qword ptr [rdi+16], r10
    mov     r10, qword ptr [rdi+0]          ; a -> b
    mov     qword ptr [rdi+8], r10
    add     r9, rax                          ; temp1 + temp2 -> a
    mov     qword ptr [rdi+0], r9
    add     rbp, 8
    add     r12, 8
    dec     r14d
    jnz     scz_round
    ; feed-forward: state[i] += a..h[i]
    xor     eax, eax
scz_ff:
    mov     r9, qword ptr [rbx+rax*8]
    add     r9, qword ptr [rdi+rax*8]
    mov     qword ptr [rbx+rax*8], r9
    inc     eax
    cmp     eax, 8
    jb      scz_ff
    ; next block
    mov     rax, qword ptr [rsp+704]
    add     rax, 128
    mov     qword ptr [rsp+704], rax
    dec     qword ptr [rsp+712]
    jnz     scz_block
scz_done:
    add     rsp, 640+64+16
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rdi
    pop     rsi
    pop     rbx
    ret
sha512_compress endp

; =============================================================================
; sha512_update(rcx = ctx, rdx = data, r8 = len)
; =============================================================================
public sha512_update
sha512_update proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     rax, r8
    add     qword ptr [rcx].SHA512_CTX.total, rax
su5_fill:
    mov     rcx, qword ptr [rbp-24]
    mov     r9d, dword ptr [rcx].SHA512_CTX.buflen
    test    r9d, r9d
    jz      su5_bulk
    cmp     r9d, 128
    je      su5_flush
    cmp     qword ptr [rbp-40], 0
    je      su5_done
    ; append one byte to buf
    mov     rax, qword ptr [rbp-32]
    mov     r10b, byte ptr [rax]
    lea     r11, [rcx].SHA512_CTX.buf
    mov     byte ptr [r11+r9], r10b
    inc     r9d
    mov     dword ptr [rcx].SHA512_CTX.buflen, r9d
    inc     qword ptr [rbp-32]
    dec     qword ptr [rbp-40]
    jmp     su5_fill
su5_flush:
    lea     rdx, [rcx].SHA512_CTX.buf
    lea     rcx, [rcx].SHA512_CTX.state
    mov     r8, 1
    call    sha512_compress
    mov     rcx, qword ptr [rbp-24]
    mov     dword ptr [rcx].SHA512_CTX.buflen, 0
su5_bulk:
    mov     r8, qword ptr [rbp-40]
    shr     r8, 7                            ; whole 128-byte blocks
    test    r8, r8
    jz      su5_tail
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    lea     rcx, [rcx].SHA512_CTX.state
    call    sha512_compress
    mov     r8, qword ptr [rbp-40]
    and     r8, -128
    add     qword ptr [rbp-32], r8
    mov     rax, qword ptr [rbp-40]
    and     rax, 127
    mov     qword ptr [rbp-40], rax
su5_tail:
    mov     rcx, qword ptr [rbp-24]
    mov     r9, qword ptr [rbp-40]
    test    r9, r9
    jz      su5_done
    lea     r11, [rcx].SHA512_CTX.buf
    mov     rax, qword ptr [rbp-32]
    xor     r10d, r10d
su5_copy:
    mov     r8b, byte ptr [rax+r10]
    mov     byte ptr [r11+r10], r8b
    inc     r10
    cmp     r10, r9
    jb      su5_copy
    mov     dword ptr [rcx].SHA512_CTX.buflen, r10d
su5_done:
    FRAME_EPILOG
    ret
sha512_update endp

; =============================================================================
; sha512_final(rcx = ctx, rdx = out64) - pad and emit big-endian digest
; =============================================================================
public sha512_final
sha512_final proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    ; bit length (128-bit big-endian; high 64 = 0 for our message sizes)
    mov     rax, qword ptr [rcx].SHA512_CTX.total
    shl     rax, 3
    bswap   rax
    mov     qword ptr [rbp-40], rax           ; be64 low bits
    ; append 0x80
    mov     r9d, dword ptr [rcx].SHA512_CTX.buflen
    lea     r11, [rcx].SHA512_CTX.buf
    mov     byte ptr [r11+r9], 080h
    inc     r9d
    cmp     r9d, 112
    jbe     sf5_pad
    ; not enough room -> fill to 128, compress, restart
sf5_to128:
    cmp     r9d, 128
    jae     sf5_flush
    mov     byte ptr [r11+r9], 0
    inc     r9d
    jmp     sf5_to128
sf5_flush:
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [rcx].SHA512_CTX.buf
    lea     rcx, [rcx].SHA512_CTX.state
    mov     r8, 1
    call    sha512_compress
    mov     rcx, qword ptr [rbp-24]
    lea     r11, [rcx].SHA512_CTX.buf
    xor     r9d, r9d
sf5_pad:
    mov     rcx, qword ptr [rbp-24]
    lea     r11, [rcx].SHA512_CTX.buf
sf5_zloop:
    cmp     r9d, 120
    jae     sf5_putlen
    mov     byte ptr [r11+r9], 0
    inc     r9d
    jmp     sf5_zloop
sf5_putlen:
    ; bytes 112..119 are the high 64 length bits (zero); 120..127 the low bits
    mov     qword ptr [r11+112], 0
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [r11+120], rax
    lea     rdx, [rcx].SHA512_CTX.buf
    lea     rcx, [rcx].SHA512_CTX.state
    mov     r8, 1
    call    sha512_compress
    ; output 64 bytes, big-endian per qword
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    xor     r8d, r8d
sf5_out:
    mov     rax, qword ptr [rcx+r8*8]
    bswap   rax
    mov     qword ptr [rdx+r8*8], rax
    inc     r8d
    cmp     r8d, 8
    jb      sf5_out
    ; wipe context
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, SHA512_CTX_SIZE
    call    secure_zero
    FRAME_EPILOG
    ret
sha512_final endp

; =============================================================================
; sha512_hash(rcx = data, rdx = len, r8 = out64) - one-shot
; =============================================================================
public sha512_hash
sha512_hash proc frame
    FRAME_PROLOG 64 + SHA512_CTX_SIZE
    mov     qword ptr [rbp-24], rdx          ; len
    mov     qword ptr [rbp-32], r8           ; out
    mov     qword ptr [rbp-40], rcx          ; data
    lea     rcx, [rsp+32]                     ; ctx
    mov     qword ptr [rbp-48], rcx
    call    sha512_init
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-40]
    mov     r8,  qword ptr [rbp-24]
    call    sha512_update
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-32]
    call    sha512_final
    FRAME_EPILOG
    ret
sha512_hash endp

; =============================================================================
; hmac_sha512(rcx = key, edx = keylen, r8 = msg, r9 = msglen, [rsp+40] = out64)
; Block size 128.  Keys here are always <= 128 bytes, but a > 128 key is still
; handled (hashed down first) for correctness.
; =============================================================================
public hmac_sha512
hmac_sha512 proc frame
    FRAME_PROLOG 128 + 128 + 128 + SHA512_CTX_SIZE + 64
    ; locals:
    ;   [rbp-24] key  [rbp-32] keylen  [rbp-40] msg  [rbp-48] msglen  [rbp-56] out
    ;   k0   @ [rsp+32]                (128 bytes, padded key)
    ;   pad  @ [rsp+160]               (128 bytes, i/o pad block)
    ;   ihash@ [rsp+288]               (64 bytes, inner digest)
    ;   ctx  @ [rsp+352]
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9
    mov     rax, qword ptr [rbp+48]            ; 5th arg (out64): ret+shadow above saved rbp
    mov     qword ptr [rbp-56], rax
    ; --- k0 = key padded/truncated to 128 bytes -----------------------------
    lea     rdi, [rsp+32]                     ; k0
    xor     eax, eax
hm_zk:
    mov     byte ptr [rdi+rax], 0
    inc     eax
    cmp     eax, 128
    jb      hm_zk
    mov     eax, dword ptr [rbp-32]
    cmp     eax, 128
    jbe     hm_copykey
    ; key too long: k0 = sha512(key)
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    mov     r8, rdi
    call    sha512_hash
    jmp     hm_havek0
hm_copykey:
    mov     ecx, dword ptr [rbp-32]
    test    ecx, ecx
    jz      hm_havek0
    mov     rsi, qword ptr [rbp-24]
    xor     r10d, r10d
hm_ck:
    mov     r8b, byte ptr [rsi+r10]
    mov     byte ptr [rdi+r10], r8b
    inc     r10d
    cmp     r10d, ecx
    jb      hm_ck
hm_havek0:
    ; --- inner: sha512( (k0^0x36) || msg ) ----------------------------------
    lea     rsi, [rsp+160]                    ; pad block
    lea     rdi, [rsp+32]                     ; k0
    xor     eax, eax
hm_ipad:
    mov     r8b, byte ptr [rdi+rax]
    xor     r8b, 036h
    mov     byte ptr [rsi+rax], r8b
    inc     eax
    cmp     eax, 128
    jb      hm_ipad
    lea     rcx, [rsp+352]                    ; ctx
    call    sha512_init
    lea     rcx, [rsp+352]
    lea     rdx, [rsp+160]
    mov     r8, 128
    call    sha512_update
    lea     rcx, [rsp+352]
    mov     rdx, qword ptr [rbp-40]
    mov     r8, qword ptr [rbp-48]
    call    sha512_update
    lea     rcx, [rsp+352]
    lea     rdx, [rsp+288]                    ; ihash
    call    sha512_final
    ; --- outer: sha512( (k0^0x5c) || ihash ) --------------------------------
    lea     rsi, [rsp+160]
    lea     rdi, [rsp+32]
    xor     eax, eax
hm_opad:
    mov     r8b, byte ptr [rdi+rax]
    xor     r8b, 05ch
    mov     byte ptr [rsi+rax], r8b
    inc     eax
    cmp     eax, 128
    jb      hm_opad
    lea     rcx, [rsp+352]
    call    sha512_init
    lea     rcx, [rsp+352]
    lea     rdx, [rsp+160]
    mov     r8, 128
    call    sha512_update
    lea     rcx, [rsp+352]
    lea     rdx, [rsp+288]
    mov     r8, 64
    call    sha512_update
    lea     rcx, [rsp+352]
    mov     rdx, qword ptr [rbp-56]           ; out
    call    sha512_final
    ; wipe k0 + pad (key-derived)
    lea     rcx, [rsp+32]
    mov     rdx, 128+128
    call    secure_zero
    FRAME_EPILOG
    ret
hmac_sha512 endp

end
