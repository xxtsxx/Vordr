; =============================================================================
; otp.asm - one-time-pad secret sharing (information-theoretic confidentiality)
; -----------------------------------------------------------------------------
; Sharing model (see docs/formats.md):
;   * A pre-shared .vpad holds random pad material both parties possess.  A
;     local high-water mark (consumed_offset) guarantees no region is ever
;     reused - the single invariant on which OTP security rests.
;   * A .vshare carries ciphertext = msg XOR pad[off..], plus a ONE-TIME MAC so
;     tampering is detectable.  Confidentiality is unconditional when the pad is
;     truly random (TRNG); CSPRNG pads are computationally secure.
;
; The one-time MAC is **Poly1305** (RFC 8439) keyed by a fresh 32-byte pad
; slice.  As a one-time authenticator (each key used for exactly one message)
; Poly1305 is information-theoretically secure: forgery probability is bounded
; by ~8*ceil(len/16)/2^106 regardless of adversary power.  The implementation
; is the donna 32-bit-limb construction (5x26-bit limbs, 64-bit accumulators)
; and is validated against the RFC 8439 2.5.2 test vector in selftest.asm.
;
; Implemented (real, self-tested): otp_xor, otp_mac, otp_mac_verify,
; otp_share_seal, otp_share_open.  Stubbed (file-backed, next step): pad
; create/import.
; =============================================================================

include macros.inc

extern ct_memcmp:proc

MASK26      equ 03FFFFFFh

.data?
align 8
poly_h0     dq ?
poly_h1     dq ?
poly_h2     dq ?
poly_h3     dq ?
poly_h4     dq ?
poly_r0     dq ?
poly_r1     dq ?
poly_r2     dq ?
poly_r3     dq ?
poly_r4     dq ?
poly_s1     dq ?
poly_s2     dq ?
poly_s3     dq ?
poly_s4     dq ?
poly_d4     dq ?
poly_blk    db 16 dup (?)            ; staging for a final partial block

.code

; ---------------------------------------------------------------------------
; otp_xor(rcx = dst, rdx = src, r8 = pad, r9 = len)
;   dst[i] = src[i] XOR pad[i].  In-place safe; leaf; constant-time over data.
; ---------------------------------------------------------------------------
public otp_xor
otp_xor proc
    xor     r10, r10
ox_loop:
    cmp     r10, r9
    jae     ox_done
    mov     al, byte ptr [rdx+r10]
    xor     al, byte ptr [r8+r10]
    mov     byte ptr [rcx+r10], al
    inc     r10
    jmp     ox_loop
ox_done:
    ret
otp_xor endp

; ---------------------------------------------------------------------------
; poly_block(rcx = 16-byte block ptr, edx = hibit)  - internal leaf.
;   h = (h + block) * r  mod (2^130 - 5), updating poly_h0..poly_h4.
;   hibit = 1<<24 for a full block, 0 for the padded final block.
;   Clobbers rax/rcx/rdx/r8/r9/r10/r11 only (all volatile).
; ---------------------------------------------------------------------------
poly_block proc
    ; ---- h += block (5 little-endian 26-bit limbs) --------------------------
    mov     eax, dword ptr [rcx]
    and     eax, MASK26
    add     qword ptr [poly_h0], rax
    mov     eax, dword ptr [rcx+3]
    shr     eax, 2
    and     eax, MASK26
    add     qword ptr [poly_h1], rax
    mov     eax, dword ptr [rcx+6]
    shr     eax, 4
    and     eax, MASK26
    add     qword ptr [poly_h2], rax
    mov     eax, dword ptr [rcx+9]
    shr     eax, 6
    and     eax, MASK26
    add     qword ptr [poly_h3], rax
    mov     eax, dword ptr [rcx+12]
    shr     eax, 8
    add     eax, edx                        ; + hibit
    add     qword ptr [poly_h4], rax

    ; ---- d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1 -------------------------
    mov     rax, qword ptr [poly_h0]
    imul    rax, qword ptr [poly_r0]
    mov     r8, rax
    mov     rax, qword ptr [poly_h1]
    imul    rax, qword ptr [poly_s4]
    add     r8, rax
    mov     rax, qword ptr [poly_h2]
    imul    rax, qword ptr [poly_s3]
    add     r8, rax
    mov     rax, qword ptr [poly_h3]
    imul    rax, qword ptr [poly_s2]
    add     r8, rax
    mov     rax, qword ptr [poly_h4]
    imul    rax, qword ptr [poly_s1]
    add     r8, rax                         ; r8 = d0
    ; ---- d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2 ------------------------
    mov     rax, qword ptr [poly_h0]
    imul    rax, qword ptr [poly_r1]
    mov     r9, rax
    mov     rax, qword ptr [poly_h1]
    imul    rax, qword ptr [poly_r0]
    add     r9, rax
    mov     rax, qword ptr [poly_h2]
    imul    rax, qword ptr [poly_s4]
    add     r9, rax
    mov     rax, qword ptr [poly_h3]
    imul    rax, qword ptr [poly_s3]
    add     r9, rax
    mov     rax, qword ptr [poly_h4]
    imul    rax, qword ptr [poly_s2]
    add     r9, rax                         ; r9 = d1
    ; ---- d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3 ------------------------
    mov     rax, qword ptr [poly_h0]
    imul    rax, qword ptr [poly_r2]
    mov     r10, rax
    mov     rax, qword ptr [poly_h1]
    imul    rax, qword ptr [poly_r1]
    add     r10, rax
    mov     rax, qword ptr [poly_h2]
    imul    rax, qword ptr [poly_r0]
    add     r10, rax
    mov     rax, qword ptr [poly_h3]
    imul    rax, qword ptr [poly_s4]
    add     r10, rax
    mov     rax, qword ptr [poly_h4]
    imul    rax, qword ptr [poly_s3]
    add     r10, rax                        ; r10 = d2
    ; ---- d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4 ------------------------
    mov     rax, qword ptr [poly_h0]
    imul    rax, qword ptr [poly_r3]
    mov     r11, rax
    mov     rax, qword ptr [poly_h1]
    imul    rax, qword ptr [poly_r2]
    add     r11, rax
    mov     rax, qword ptr [poly_h2]
    imul    rax, qword ptr [poly_r1]
    add     r11, rax
    mov     rax, qword ptr [poly_h3]
    imul    rax, qword ptr [poly_r0]
    add     r11, rax
    mov     rax, qword ptr [poly_h4]
    imul    rax, qword ptr [poly_s4]
    add     r11, rax                        ; r11 = d3
    ; ---- d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0 -----------------------
    mov     rax, qword ptr [poly_h0]
    imul    rax, qword ptr [poly_r4]
    mov     qword ptr [poly_d4], rax
    mov     rax, qword ptr [poly_h1]
    imul    rax, qword ptr [poly_r3]
    add     qword ptr [poly_d4], rax
    mov     rax, qword ptr [poly_h2]
    imul    rax, qword ptr [poly_r2]
    add     qword ptr [poly_d4], rax
    mov     rax, qword ptr [poly_h3]
    imul    rax, qword ptr [poly_r1]
    add     qword ptr [poly_d4], rax
    mov     rax, qword ptr [poly_h4]
    imul    rax, qword ptr [poly_r0]
    add     qword ptr [poly_d4], rax        ; [poly_d4] = d4

    ; ---- carry chain (partial reduction) -----------------------------------
    mov     rcx, r8
    shr     rcx, 26
    and     r8, MASK26
    mov     qword ptr [poly_h0], r8
    add     r9, rcx
    mov     rcx, r9
    shr     rcx, 26
    and     r9, MASK26
    mov     qword ptr [poly_h1], r9
    add     r10, rcx
    mov     rcx, r10
    shr     rcx, 26
    and     r10, MASK26
    mov     qword ptr [poly_h2], r10
    add     r11, rcx
    mov     rcx, r11
    shr     rcx, 26
    and     r11, MASK26
    mov     qword ptr [poly_h3], r11
    add     qword ptr [poly_d4], rcx
    mov     r8, qword ptr [poly_d4]
    mov     rcx, r8
    shr     rcx, 26
    and     r8, MASK26
    mov     qword ptr [poly_h4], r8
    lea     rax, [rcx + rcx*4]              ; c*5
    add     qword ptr [poly_h0], rax
    mov     rax, qword ptr [poly_h0]
    mov     rcx, rax
    shr     rcx, 26
    and     rax, MASK26
    mov     qword ptr [poly_h0], rax
    add     qword ptr [poly_h1], rcx
    ret
poly_block endp

; ===========================================================================
; otp_mac(rcx = msg, rdx = msglen, r8 = key32, r9 = tagout16)
;   Poly1305 one-shot.  Writes the 16-byte tag to tagout.  Returns eax = 1.
; ===========================================================================
public otp_mac
otp_mac proc frame
    FRAME_PROLOG 96
    ; locals: [rbp-24] msg cursor, [rbp-32] remaining, [rbp-40] key, [rbp-48] tag,
    ;         [rbp-56] scratch (pad-add; used only after the last poly_block call)
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9

    ; ---- clamp r (donna 32-bit limbs) from key[0..16] ----------------------
    mov     eax, dword ptr [r8]
    and     eax, 03FFFFFFh
    mov     qword ptr [poly_r0], rax
    mov     eax, dword ptr [r8+3]
    shr     eax, 2
    and     eax, 03FFFF03h
    mov     qword ptr [poly_r1], rax
    mov     eax, dword ptr [r8+6]
    shr     eax, 4
    and     eax, 03FFC0FFh
    mov     qword ptr [poly_r2], rax
    mov     eax, dword ptr [r8+9]
    shr     eax, 6
    and     eax, 03F03FFFh
    mov     qword ptr [poly_r3], rax
    mov     eax, dword ptr [r8+12]
    shr     eax, 8
    and     eax, 000FFFFFh
    mov     qword ptr [poly_r4], rax

    ; ---- s_i = r_i * 5 (i=1..4) --------------------------------------------
    mov     rax, qword ptr [poly_r1]
    lea     rax, [rax + rax*4]
    mov     qword ptr [poly_s1], rax
    mov     rax, qword ptr [poly_r2]
    lea     rax, [rax + rax*4]
    mov     qword ptr [poly_s2], rax
    mov     rax, qword ptr [poly_r3]
    lea     rax, [rax + rax*4]
    mov     qword ptr [poly_s3], rax
    mov     rax, qword ptr [poly_r4]
    lea     rax, [rax + rax*4]
    mov     qword ptr [poly_s4], rax

    ; ---- h = 0 -------------------------------------------------------------
    mov     qword ptr [poly_h0], 0
    mov     qword ptr [poly_h1], 0
    mov     qword ptr [poly_h2], 0
    mov     qword ptr [poly_h3], 0
    mov     qword ptr [poly_h4], 0

    ; ---- full 16-byte blocks ----------------------------------------------
om_blocks:
    cmp     qword ptr [rbp-32], 16
    jb      om_tail
    mov     rcx, qword ptr [rbp-24]
    mov     edx, 1000000h                   ; hibit = 1<<24
    call    poly_block
    add     qword ptr [rbp-24], 16
    sub     qword ptr [rbp-32], 16
    jmp     om_blocks

om_tail:
    mov     rax, qword ptr [rbp-32]
    test    rax, rax
    jz      om_finish
    ; build a zero-padded final block with the 0x01 marker byte
    lea     rcx, [poly_blk]
    mov     qword ptr [rcx], 0
    mov     qword ptr [rcx+8], 0
    xor     r10d, r10d                       ; index
    mov     r9, qword ptr [rbp-24]           ; src
om_copy:
    cmp     r10, qword ptr [rbp-32]
    jae     om_copydone
    mov     al, byte ptr [r9+r10]
    mov     byte ptr [rcx+r10], al
    inc     r10
    jmp     om_copy
om_copydone:
    mov     byte ptr [rcx+r10], 1            ; 0x01 padding marker
    lea     rcx, [poly_blk]
    xor     edx, edx                         ; hibit = 0 (final block)
    call    poly_block

om_finish:
    ; ---- fully carry h -----------------------------------------------------
    mov     rax, qword ptr [poly_h1]
    shr     rax, 26
    and     qword ptr [poly_h1], MASK26
    add     qword ptr [poly_h2], rax
    mov     rax, qword ptr [poly_h2]
    shr     rax, 26
    and     qword ptr [poly_h2], MASK26
    add     qword ptr [poly_h3], rax
    mov     rax, qword ptr [poly_h3]
    shr     rax, 26
    and     qword ptr [poly_h3], MASK26
    add     qword ptr [poly_h4], rax
    mov     rax, qword ptr [poly_h4]
    shr     rax, 26
    and     qword ptr [poly_h4], MASK26
    lea     rax, [rax + rax*4]               ; c*5
    add     qword ptr [poly_h0], rax
    mov     rax, qword ptr [poly_h0]
    shr     rax, 26
    and     qword ptr [poly_h0], MASK26
    add     qword ptr [poly_h1], rax

    ; ---- compute g = h + 5, fold the 2^130 carry; select h or g ------------
    ; g0..g4 in r8..r11 + (g4 in rax-derived); use registers.
    mov     r8, qword ptr [poly_h0]
    add     r8, 5
    mov     rax, r8
    shr     rax, 26
    and     r8, MASK26                       ; g0
    mov     r9, qword ptr [poly_h1]
    add     r9, rax
    mov     rax, r9
    shr     rax, 26
    and     r9, MASK26                       ; g1
    mov     r10, qword ptr [poly_h2]
    add     r10, rax
    mov     rax, r10
    shr     rax, 26
    and     r10, MASK26                      ; g2
    mov     r11, qword ptr [poly_h3]
    add     r11, rax
    mov     rax, r11
    shr     rax, 26
    and     r11, MASK26                      ; g3
    mov     rdx, qword ptr [poly_h4]
    add     rdx, rax
    sub     rdx, 4000000h                    ; g4 = h4 + c - (1<<26); may underflow
    ; mask = (g4 >> 63) - 1  : 0 if g4<0 (keep h, h<p), all-ones if g4>=0 (use g)
    mov     rax, rdx
    shr     rax, 63
    sub     rax, 1                           ; rax = mask
    ; h_i = (g_i & mask) | (h_i & ~mask)
    and     r8, rax
    and     r9, rax
    and     r10, rax
    and     r11, rax
    and     rdx, rax
    not     rax                              ; ~mask
    mov     rcx, qword ptr [poly_h0]
    and     rcx, rax
    or      r8, rcx
    mov     rcx, qword ptr [poly_h1]
    and     rcx, rax
    or      r9, rcx
    mov     rcx, qword ptr [poly_h2]
    and     rcx, rax
    or      r10, rcx
    mov     rcx, qword ptr [poly_h3]
    and     rcx, rax
    or      r11, rcx
    mov     rcx, qword ptr [poly_h4]
    and     rcx, rax
    or      rdx, rcx
    ; now r8=h0 r9=h1 r10=h2 r11=h3 rdx=h4 (final reduced 26-bit limbs)

    ; ---- serialize to four 32-bit words ------------------------------------
    ; w0 = h0 | h1<<26 ; w1 = h1>>6 | h2<<20 ; w2 = h2>>12 | h3<<14 ; w3 = h3>>18 | h4<<8
    mov     rax, r9
    shl     rax, 26
    or      rax, r8
    mov     r8, rax                          ; r8d = w0 (low 32 bits)
    mov     rax, r10
    shl     rax, 20
    mov     rcx, r9
    shr     rcx, 6
    or      rax, rcx
    mov     r9, rax                          ; r9d = w1
    mov     rax, r11
    shl     rax, 14
    mov     rcx, r10
    shr     rcx, 12
    or      rax, rcx
    mov     r10, rax                         ; r10d = w2
    mov     rax, rdx
    shl     rax, 8
    mov     rcx, r11
    shr     rcx, 18
    or      rax, rcx
    mov     r11, rax                         ; r11d = w3

    ; ---- add pad s = key[16..32] (32-bit limbs) with carry -----------------
    mov     rcx, qword ptr [rbp-40]          ; key ptr
    mov     eax, r8d
    mov     edx, dword ptr [rcx+16]
    add     rax, rdx                         ; 64-bit add captures carry
    mov     qword ptr [rbp-56], rax          ; stash f0 (carry in bits >=32)
    mov     rax, qword ptr [rbp-56]
    shr     rax, 32                          ; carry
    mov     r8d, dword ptr [rbp-56]          ; w0 low 32 = out[0]
    ; f1
    mov     edx, r9d
    add     rax, rdx
    mov     edx, dword ptr [rcx+20]
    add     rax, rdx
    mov     r9d, eax                         ; out[4] low 32
    shr     rax, 32
    ; f2
    mov     edx, r10d
    add     rax, rdx
    mov     edx, dword ptr [rcx+24]
    add     rax, rdx
    mov     r10d, eax
    shr     rax, 32
    ; f3
    mov     edx, r11d
    add     rax, rdx
    mov     edx, dword ptr [rcx+28]
    add     rax, rdx
    mov     r11d, eax

    ; ---- store the 16-byte tag (little-endian) -----------------------------
    mov     rcx, qword ptr [rbp-48]          ; tagout
    mov     dword ptr [rcx], r8d
    mov     dword ptr [rcx+4], r9d
    mov     dword ptr [rcx+8], r10d
    mov     dword ptr [rcx+12], r11d

    mov     eax, 1
    FRAME_EPILOG
    ret
otp_mac endp

; ===========================================================================
; otp_mac_verify(rcx = msg, rdx = msglen, r8 = key32, r9 = tag16)
;   -> eax = 0 if the tag is valid, 1 otherwise (constant-time compare).
; ===========================================================================
public otp_mac_verify
otp_mac_verify proc frame
    FRAME_PROLOG 64
    ; [rbp-24] = computed-tag buffer (16 bytes), [rbp-32] = expected tag ptr
    mov     qword ptr [rbp-32], r9          ; save expected tag ptr
    lea     r9, [rbp-24]                    ; computed-tag buffer
    call    otp_mac                         ; rcx/rdx/r8 still = msg/len/key
    lea     rcx, [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, 16
    call    ct_memcmp                        ; eax = 0 if equal
    FRAME_EPILOG
    ret
otp_mac_verify endp

; ===========================================================================
; otp_share_seal(rcx = pt, rdx = len, r8 = pad, r9 = ctout, [rbp+48] = tagout)
;   pad layout: [len bytes cipher pad][MAC_KEY_LEN bytes one-time MAC key].
;   ct = pt XOR pad[0..len] ; tag = Poly1305(ct, mackey = pad+len).  Returns 1.
; ===========================================================================
public otp_share_seal
otp_share_seal proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx         ; pt
    mov     qword ptr [rbp-32], rdx         ; len
    mov     qword ptr [rbp-40], r8          ; pad
    mov     qword ptr [rbp-48], r9          ; ctout
    ; ct = pt XOR pad[0..len]
    mov     rcx, r9                         ; dst = ctout
    mov     rdx, qword ptr [rbp-24]         ; src = pt
    mov     r8, qword ptr [rbp-40]          ; pad
    mov     r9, qword ptr [rbp-32]          ; len
    call    otp_xor
    ; tag = Poly1305(ct, len, mackey = pad + len)
    mov     rcx, qword ptr [rbp-48]         ; msg = ct
    mov     rdx, qword ptr [rbp-32]         ; len
    mov     r8, qword ptr [rbp-40]
    add     r8, qword ptr [rbp-32]          ; key = pad + len
    mov     r9, qword ptr [rbp+48]          ; tagout (5th arg)
    call    otp_mac
    mov     eax, 1
    FRAME_EPILOG
    ret
otp_share_seal endp

; ===========================================================================
; otp_share_open(rcx = ct, rdx = len, r8 = pad, r9 = ptout, [rbp+48] = tag)
;   Verify the one-time MAC, then pt = ct XOR pad[0..len].
;   -> eax = 0 on success (ptout filled), 1 if authentication fails.
; ===========================================================================
public otp_share_open
otp_share_open proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx         ; ct
    mov     qword ptr [rbp-32], rdx         ; len
    mov     qword ptr [rbp-40], r8          ; pad
    mov     qword ptr [rbp-48], r9          ; ptout
    ; verify tag over ct with mackey = pad + len
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, qword ptr [rbp-40]
    add     r8, qword ptr [rbp-32]
    mov     r9, qword ptr [rbp+48]          ; expected tag
    call    otp_mac_verify
    test    eax, eax
    jnz     oso_bad
    ; pt = ct XOR pad[0..len]
    mov     rcx, qword ptr [rbp-48]         ; dst = ptout
    mov     rdx, qword ptr [rbp-24]         ; src = ct
    mov     r8, qword ptr [rbp-40]
    mov     r9, qword ptr [rbp-32]
    call    otp_xor
    xor     eax, eax
    FRAME_EPILOG
    ret
oso_bad:
    mov     eax, 1
    FRAME_EPILOG
    ret
otp_share_open endp

; ---------------------------------------------------------------------------
; Fail-closed stubs - file-backed pad management arrives in the next step.
; ---------------------------------------------------------------------------
public otp_pad_new
otp_pad_new proc
    xor     eax, eax
    ret
otp_pad_new endp

public otp_pad_import
otp_pad_import proc
    xor     eax, eax
    ret
otp_pad_import endp

end
