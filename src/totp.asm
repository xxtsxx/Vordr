; =============================================================================
; totp.asm - RFC 6238 TOTP (time-based one-time passwords) for vault entries.
; -----------------------------------------------------------------------------
; Standard authenticator codes: HMAC-SHA1 over the 30-second time counter,
; dynamically truncated to a 6-digit code (RFC 4226 HOTP + RFC 6238 TOTP).
; HMAC-SHA1 is the interoperable default and remains secure (HMAC does not rely
; on SHA-1 collision resistance).
;
;   base32_decode(rcx=src, edx=srclen, r8=dst, r9d=cap) -> eax = nbytes (0 = bad)
;   totp_from_b32(rcx=b32 ascii, edx=len, r8=out6) -> eax = 1 ok / 0 invalid
;   totp_secs_left() -> eax = seconds until the current code rolls over
; =============================================================================

include macros.inc

extern hmac_sha1:proc
extern GetSystemTimeAsFileTime:proc
extern secure_zero:proc

TOTP_PERIOD     equ 30
TOTP_KEY_CAP    equ 160
FT_UNIX_EPOCH   equ 116444736000000000     ; 100-ns ticks between 1601 and 1970

.data?
align 16
public g_totp_key                         ; pinned + crash-wiped by secmem.asm
g_totp_key  db TOTP_KEY_CAP dup (?)        ; decoded TOTP secret (wiped after use)

.code

; ===========================================================================
; base32_decode(rcx=src, edx=srclen, r8=dst, r9d=cap) -> eax = decoded bytes.
;   RFC 4648 alphabet (A-Z, 2-7), case-insensitive; spaces / '-' ignored;
;   '=' padding permitted only at the tail.  Data-symbol decoding is branchless
;   (no secret-dependent conditional jumps or lookup tables).  Rejects empty
;   inputs, invalid characters, truncated trailing groups, and non-zero pad bits,
;   scrubbing any partial output bytes written to dst on failure.
; ===========================================================================
public base32_decode
base32_decode proc frame
    FRAME_PROLOG 80
    ; [rbp-24]=dst [rbp-32]=cap [rbp-40]=outcount [rbp-48]=src [rbp-56]=srclen [rbp-64]=seen_pad
    mov     edx, edx                        ; zero-extend 32-bit srclen into rdx
    test    rcx, rcx
    jz      b32_bad_early
    test    r8, r8
    jz      b32_bad_early
    mov     qword ptr [rbp-24], r8
    mov     r8d, r9d
    mov     qword ptr [rbp-32], r8
    mov     qword ptr [rbp-40], 0
    mov     qword ptr [rbp-48], rcx
    mov     qword ptr [rbp-56], rdx
    mov     dword ptr [rbp-64], 0
    xor     r10, r10                        ; acc (bit buffer)
    xor     r11d, r11d                      ; nbits in acc
    xor     r8d, r8d                        ; src index
b32_loop:
    cmp     r8, qword ptr [rbp-56]
    jae     b32_done
    mov     r9, qword ptr [rbp-48]
    movzx   eax, byte ptr [r9+r8]
    inc     r8
    cmp     al, ' '
    je      b32_loop
    cmp     al, 9
    je      b32_loop
    cmp     al, '-'
    je      b32_loop
    cmp     al, '='
    jne     b32_sym
    mov     dword ptr [rbp-64], 1
    jmp     b32_loop
b32_sym:
    cmp     dword ptr [rbp-64], 0           ; data symbol after '=' padding is invalid
    jne     b32_bad
    ; Branchlessly fold 'a'..'z' -> 'A'..'Z'
    mov     ecx, eax
    sub     ecx, 'a'
    cmp     ecx, 26
    sbb     edx, edx                        ; -1 if 'a'..'z', else 0
    and     edx, -32
    add     eax, edx
    ; Branchlessly map 'A'..'Z' -> 0..25 and '2'..'7' -> 26..31
    mov     ecx, eax
    sub     ecx, 'A'
    cmp     ecx, 26
    sbb     edx, edx                        ; -1 if 'A'..'Z', else 0
    mov     r9d, eax
    sub     r9d, '2'
    cmp     r9d, 6
    sbb     eax, eax                        ; -1 if '2'..'7', else 0
    add     r9d, 26
    and     ecx, edx
    and     r9d, eax
    or      edx, eax
    jz      b32_bad                         ; invalid byte (neither A-Z nor 2-7)
    or      ecx, r9d                        ; ecx = 5-bit symbol value (0..31)
    mov     eax, ecx
    and     eax, 1Fh
    shl     r10, 5
    or      r10, rax
    add     r11d, 5
    cmp     r11d, 8
    jb      b32_loop
    ; emit one byte = top 8 of the buffered bits
    sub     r11d, 8
    mov     ecx, r11d
    mov     rax, r10
    shr     rax, cl                         ; rax low byte = the output byte
    mov     rdx, 1
    shl     rdx, cl
    dec     rdx
    and     r10, rdx                        ; keep only the low `nbits` bits
    and     eax, 0FFh
    mov     rdx, qword ptr [rbp-40]
    cmp     rdx, qword ptr [rbp-32]
    jae     b32_bad                         ; over cap: fail (0) rather than silently
                                            ; truncate the secret into a wrong TOTP key
    mov     rcx, qword ptr [rbp-24]
    mov     byte ptr [rcx+rdx], al
    inc     qword ptr [rbp-40]
    jmp     b32_loop
b32_done:
    cmp     qword ptr [rbp-40], 0           ; empty / padding-only input -> invalid
    je      b32_bad
    cmp     r11d, 5                         ; 5..7 leftover bits => truncated group
    jae     b32_bad
    test    r10, r10                        ; RFC 4648: unused low padding bits must be 0
    jnz     b32_bad
    xor     ecx, ecx
    xor     edx, edx
    xor     r10d, r10d
    mov     rax, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
b32_bad:
    xor     r10d, r10d
    mov     rdx, qword ptr [rbp-40]
    test    rdx, rdx
    jz      b32_bad_early
    mov     rcx, qword ptr [rbp-24]
    call    secure_zero
b32_bad_early:
    xor     eax, eax
    FRAME_EPILOG
    ret
base32_decode endp

; ===========================================================================
; totp_unix() -> rax = current Unix time in seconds (clamped to 0 if < 1970).
; ===========================================================================
totp_unix proc frame
    FRAME_PROLOG 48
    lea     rcx, [rbp-24]                   ; FILETIME (8 bytes)
    call    GetSystemTimeAsFileTime
    mov     rax, qword ptr [rbp-24]
    mov     rcx, FT_UNIX_EPOCH
    cmp     rax, rcx
    jb      tu_pre1970
    sub     rax, rcx
    xor     edx, edx
    mov     rcx, 10000000
    div     rcx                             ; rax = seconds since 1970
    FRAME_EPILOG
    ret
tu_pre1970:
    xor     eax, eax
    FRAME_EPILOG
    ret
totp_unix endp

; ===========================================================================
; hotp(rcx=key, edx=keylen, r8=counter, r9=out6) -> eax = 1.
;   RFC 4226: HMAC-SHA1(key, counter_be64), dynamic-truncate, mod 10^6.
; ===========================================================================
public hotp
hotp proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=out  [rbp-40]=counterBE(8)  [rbp-72..rbp-53]=mac(20)
    mov     edx, edx                        ; zero-extend 32-bit keylen into rdx
    mov     qword ptr [rbp-24], r9
    mov     rax, r8
    bswap   rax                             ; counter -> big-endian
    mov     qword ptr [rbp-40], rax
    ; hmac_sha1(key=rcx, keylen=rdx, msg=&counterBE, msglen=8, out=&mac)
    lea     r8, [rbp-40]
    mov     r9, 8
    lea     rax, [rbp-72]
    mov     qword ptr [rsp+32], rax
    call    hmac_sha1
    ; dynamic truncation
    lea     r10, [rbp-72]
    movzx   ecx, byte ptr [r10+19]
    and     ecx, 0Fh                        ; offset 0..15
    movzx   eax, byte ptr [r10+rcx]
    and     eax, 7Fh
    shl     eax, 24
    mov     r9d, eax
    movzx   eax, byte ptr [r10+rcx+1]
    shl     eax, 16
    or      r9d, eax
    movzx   eax, byte ptr [r10+rcx+2]
    shl     eax, 8
    or      r9d, eax
    movzx   eax, byte ptr [r10+rcx+3]
    or      r9d, eax                        ; 31-bit binary code
    mov     eax, r9d
    xor     edx, edx
    mov     ecx, 1000000
    div     ecx                             ; edx = code (0..999999)
    ; format six zero-padded ASCII digits into out
    mov     r8, qword ptr [rbp-24]
    mov     eax, edx
    mov     r9d, 10
    mov     ecx, 6
hotp_fmt:
    dec     ecx
    xor     edx, edx
    div     r9d
    add     dl, '0'
    mov     byte ptr [r8+rcx], dl
    test    ecx, ecx
    jnz     hotp_fmt
    ; wipe mac + counterBE ([rbp-72 .. rbp-32))
    lea     rcx, [rbp-72]
    mov     edx, 40
    call    secure_zero
    mov     eax, 1
    FRAME_EPILOG
    ret
hotp endp

; ===========================================================================
; totp_at(rcx=key, edx=keylen, r8=unix_sec, r9d=period,
;         [rbp+48]=digits, [rbp+56]=out) -> eax = 1 ok / 0 invalid.
;   Parameterized RFC 6238 TOTP (6..9 digits, caller-chosen period/time) used
;   by the RFC 6238 Appendix B KATs and differential test suite.
; ===========================================================================
public totp_at
totp_at proc frame
    FRAME_PROLOG 128
    ; [rbp-24]=key [rbp-32]=keylen [rbp-40]=digits [rbp-48]=out
    ; [rbp-64]=counterBE(8) [rbp-96..rbp-77]=mac(20)
    mov     edx, edx
    test    rcx, rcx
    jz      ta_bad
    test    edx, edx
    jz      ta_bad
    test    r8, r8
    js      ta_bad
    test    r9d, r9d
    jz      ta_bad
    mov     eax, dword ptr [rbp+48]         ; digits
    cmp     eax, 6
    jb      ta_bad
    cmp     eax, 9
    ja      ta_bad
    mov     r10, qword ptr [rbp+56]         ; out
    test    r10, r10
    jz      ta_bad
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     dword ptr [rbp-40], eax
    mov     qword ptr [rbp-48], r10
    ; counter = unix_sec / period
    mov     rax, r8
    xor     edx, edx
    mov     ecx, r9d
    div     rcx
    bswap   rax
    mov     qword ptr [rbp-64], rax
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    lea     r8, [rbp-64]
    mov     r9, 8
    lea     rax, [rbp-96]
    mov     qword ptr [rsp+32], rax
    call    hmac_sha1
    lea     r10, [rbp-96]
    movzx   ecx, byte ptr [r10+19]
    and     ecx, 0Fh
    movzx   eax, byte ptr [r10+rcx]
    and     eax, 7Fh
    shl     eax, 24
    mov     r9d, eax
    movzx   eax, byte ptr [r10+rcx+1]
    shl     eax, 16
    or      r9d, eax
    movzx   eax, byte ptr [r10+rcx+2]
    shl     eax, 8
    or      r9d, eax
    movzx   eax, byte ptr [r10+rcx+3]
    or      r9d, eax                        ; 31-bit binary code
    ; modulus = 10^digits (64-bit so 10^9 fits cleanly)
    mov     r10, 1
    mov     ecx, dword ptr [rbp-40]
ta_pow:
    imul    r10, r10, 10
    dec     ecx
    jnz     ta_pow
    mov     eax, r9d
    xor     edx, edx
    div     r10                             ; rdx = code mod 10^digits
    mov     r8, qword ptr [rbp-48]
    mov     rax, rdx
    mov     r9d, 10
    mov     ecx, dword ptr [rbp-40]
ta_fmt:
    dec     ecx
    xor     edx, edx
    div     r9
    add     dl, '0'
    mov     byte ptr [r8+rcx], dl
    test    ecx, ecx
    jnz     ta_fmt
    lea     rcx, [rbp-96]
    mov     edx, 40
    call    secure_zero
    mov     eax, 1
    FRAME_EPILOG
    ret
ta_bad:
    xor     eax, eax
    FRAME_EPILOG
    ret
totp_at endp

; ===========================================================================
; totp_now(rcx=key, edx=keylen, r8=out6) -> eax = 1.  Current TOTP code.
; ===========================================================================
public totp_now
totp_now proc frame
    FRAME_PROLOG 48
    mov     edx, edx
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], r8
    call    totp_unix
    xor     edx, edx
    mov     rcx, TOTP_PERIOD
    div     rcx                             ; rax = time counter
    mov     r8, rax
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    mov     r9, qword ptr [rbp-40]
    call    hotp
    FRAME_EPILOG
    ret
totp_now endp

; ===========================================================================
; totp_from_b32(rcx=b32 ascii, edx=len, r8=out6) -> eax = 1 ok / 0 invalid.
;   Decodes the base32 secret, computes the current code, wipes the key.
; ===========================================================================
public totp_from_b32
totp_from_b32 proc frame
    FRAME_PROLOG 48
    mov     edx, edx
    mov     qword ptr [rbp-24], r8          ; out
    lea     r8, [g_totp_key]
    mov     r9d, TOTP_KEY_CAP
    call    base32_decode                   ; eax = key length
    test    eax, eax
    jz      tfb_bad
    mov     dword ptr [rbp-32], eax
    lea     rcx, [g_totp_key]
    mov     edx, dword ptr [rbp-32]
    mov     r8, qword ptr [rbp-24]
    call    totp_now
    lea     rcx, [g_totp_key]
    mov     edx, TOTP_KEY_CAP
    call    secure_zero
    mov     eax, 1
    FRAME_EPILOG
    ret
tfb_bad:
    lea     rcx, [g_totp_key]
    mov     edx, TOTP_KEY_CAP
    call    secure_zero
    xor     eax, eax
    FRAME_EPILOG
    ret
totp_from_b32 endp

; ===========================================================================
; totp_secs_left() -> eax = TOTP_PERIOD - (unix mod TOTP_PERIOD).
; ===========================================================================
public totp_secs_left
totp_secs_left proc frame
    FRAME_PROLOG 32
    call    totp_unix
    xor     edx, edx
    mov     rcx, TOTP_PERIOD
    div     rcx
    mov     eax, TOTP_PERIOD
    sub     eax, edx
    FRAME_EPILOG
    ret
totp_secs_left endp

end
