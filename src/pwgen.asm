; =============================================================================
; pwgen.asm - configurable high-quality password generator + password policy
; -----------------------------------------------------------------------------
;   pwgen(rcx = outbuf, edx = len, r8d = classmask) -> eax = 1 ok / 0 fail
;       Fills outbuf with `len` ASCII bytes drawn UNIFORMLY (rejection sampling
;       over the CSPRNG, so there is no modulo bias) from the alphabet selected
;       by classmask (bit 1=upper 2=lower 4=digit 8=symbol - same bits as the
;       policy class mask).  Fails closed if the alphabet is empty, len is out
;       of range, or the CSPRNG fails.
;
;   check_password_policy() -> eax = 0 ok / 1 too short / 2 too few classes
;       (reads g_cfg_pass/g_cfg_passlen and the
;       g_cfg_pwminlen / g_cfg_pwminclasses policy globals.)
;
; TODO (next step): guarantee at least one character from each requested class
; (currently the draw is uniform but does not force class coverage), and add an
; --exclude-ambiguous alphabet variant.
; =============================================================================

include macros.inc

extern rng_fill:proc

externdef g_cfg_pass:byte
externdef g_cfg_passlen:dword
externdef g_cfg_pwminlen:dword
externdef g_cfg_pwminclasses:dword

PWGEN_MIN_LEN       equ 1
PWGEN_MAX_LEN       equ 256

PWCLASS_UPPER       equ 1
PWCLASS_LOWER       equ 2
PWCLASS_DIGIT       equ 4
PWCLASS_SYMBOL      equ 8

.const
; Per-class alphabets (concatenated at run time into a working alphabet).
abc_upper   db "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
abc_upper_n equ $ - abc_upper
abc_lower   db "abcdefghijklmnopqrstuvwxyz"
abc_lower_n equ $ - abc_lower
abc_digit   db "0123456789"
abc_digit_n equ $ - abc_digit
abc_symbol  db "!@#$%^&*()-_=+[]{};:,.?/"
abc_symbol_n equ $ - abc_symbol
abc_hex     db "0123456789abcdef"
abc_hex_n   equ $ - abc_hex
abc_cons    db "bcdfghjkmnpqrstvwxz"           ; pronounceable consonants (no ambiguous)
abc_cons_n  equ $ - abc_cons
abc_vowel   db "aeiou"
abc_vowel_n equ $ - abc_vowel
abc_ambig   db "0O1lI"                          ; ambiguous glyphs dropped by PWO_NOAMBIG
abc_ambig_n equ $ - abc_ambig
include wordlist.inc

.data?
align 16
pw_alpha    db 128 dup (?)         ; assembled alphabet (max 26+26+10+23 = 85)
pw_alpha_n  dd ?                    ; assembled alphabet length
pw_entropy  dd ?                    ; running entropy estimate in millibits

.code

; ---------------------------------------------------------------------------
; pwg_append(rcx = src, edx = count) - append a class alphabet to pw_alpha,
; advancing pw_alpha_n.  Internal; clobbers volatiles only.
; ---------------------------------------------------------------------------
pwg_append proc
    mov     r10d, dword ptr [pw_alpha_n]
    xor     r9d, r9d
pa_loop:
    cmp     r9d, edx
    jae     pa_done
    mov     al, byte ptr [rcx+r9]
    lea     r11, [pw_alpha]
    mov     byte ptr [r11+r10], al
    inc     r10d
    inc     r9d
    jmp     pa_loop
pa_done:
    mov     dword ptr [pw_alpha_n], r10d
    ret
pwg_append endp

public pwgen
pwgen proc frame
    FRAME_PROLOG 96
    ; locals: [rbp-24] outbuf, [rbp-32] len, [rbp-40] classmask,
    ;         [rbp-48] write index, [rbp-56] one random byte, [rbp-64] reject thr
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [rbp-40], r8d

    ; ---- length bounds ------------------------------------------------------
    cmp     edx, PWGEN_MIN_LEN
    jb      pg_fail
    cmp     edx, PWGEN_MAX_LEN
    ja      pg_fail

    ; ---- assemble the alphabet from the requested classes -------------------
    mov     dword ptr [pw_alpha_n], 0
    test    r8d, PWCLASS_UPPER
    jz      @F
    lea     rcx, [abc_upper]
    mov     edx, abc_upper_n
    call    pwg_append
@@: test    dword ptr [rbp-40], PWCLASS_LOWER
    jz      @F
    lea     rcx, [abc_lower]
    mov     edx, abc_lower_n
    call    pwg_append
@@: test    dword ptr [rbp-40], PWCLASS_DIGIT
    jz      @F
    lea     rcx, [abc_digit]
    mov     edx, abc_digit_n
    call    pwg_append
@@: test    dword ptr [rbp-40], PWCLASS_SYMBOL
    jz      @F
    lea     rcx, [abc_symbol]
    mov     edx, abc_symbol_n
    call    pwg_append
@@:
    mov     ecx, dword ptr [pw_alpha_n]
    test    ecx, ecx
    jz      pg_fail                         ; empty alphabet (no classes selected)

    ; ---- rejection-sampling threshold: largest multiple of N that fits 0..255
    ; reject = 256 - (256 mod N); draw < reject, then map byte mod N.
    mov     eax, 256
    xor     edx, edx
    div     ecx                             ; eax = 256/N, edx = 256 mod N
    mov     r10d, 256
    sub     r10d, edx                       ; reject threshold (multiple of N)
    mov     dword ptr [rbp-64], r10d

    mov     qword ptr [rbp-48], 0           ; write index
pg_outer:
    mov     rax, qword ptr [rbp-48]
    cmp     eax, dword ptr [rbp-32]
    jae     pg_ok
pg_draw:
    lea     rcx, [rbp-56]                   ; one random byte
    mov     edx, 1
    call    rng_fill
    test    eax, eax
    jz      pg_fail                         ; CSPRNG failure -> fail closed
    movzx   r10d, byte ptr [rbp-56]
    cmp     r10d, dword ptr [rbp-64]
    jae     pg_draw                         ; in the biased tail: redraw
    mov     eax, r10d
    xor     edx, edx
    mov     ecx, dword ptr [pw_alpha_n]
    div     ecx                             ; edx = byte mod N -> alphabet index
    lea     r11, [pw_alpha]
    mov     al, byte ptr [r11+rdx]
    mov     r10, qword ptr [rbp-24]
    mov     r11, qword ptr [rbp-48]
    mov     byte ptr [r10+r11], al
    inc     qword ptr [rbp-48]
    jmp     pg_outer
pg_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
pg_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
pwgen endp

; ---------------------------------------------------------------------------
; rand_idx(ecx = N, 1..256) -> eax = uniform index 0..N-1, or -1 on CSPRNG fail.
;   Rejection sampling over one CSPRNG byte (no modulo bias).  Leaf-ish.
; ---------------------------------------------------------------------------
rand_idx proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], ecx            ; N
    mov     eax, 256                           ; threshold = 256 - (256 mod N)
    xor     edx, edx
    div     dword ptr [rbp-24]
    mov     r10d, 256
    sub     r10d, edx
    mov     dword ptr [rbp-28], r10d
ri_draw:
    lea     rcx, [rbp-32]
    mov     edx, 1
    call    rng_fill
    test    eax, eax
    jz      ri_fail
    movzx   eax, byte ptr [rbp-32]
    cmp     eax, dword ptr [rbp-28]
    jae     ri_draw
    xor     edx, edx
    div     dword ptr [rbp-24]                 ; edx = byte mod N
    mov     eax, edx
    FRAME_EPILOG
    ret
ri_fail:
    mov     eax, -1
    FRAME_EPILOG
    ret
rand_idx endp

; ---------------------------------------------------------------------------
; log2x1000(ecx = N >= 1) -> eax = round(log2(N) * 1000).
;   floor via BSR + a linear fractional term.  Leaf.
; ---------------------------------------------------------------------------
log2x1000 proc
    push    rbx
    mov     ebx, ecx                           ; N
    bsr     eax, ecx                           ; k = floor(log2 N)
    mov     r10d, eax
    mov     r11d, 1
    mov     ecx, eax
    shl     r11d, cl                           ; 2^k
    mov     eax, ebx
    sub     eax, r11d                          ; N - 2^k
    imul    eax, eax, 1000
    xor     edx, edx
    div     r11d                               ; frac = (N-2^k)*1000 / 2^k
    imul    r10d, r10d, 1000
    add     eax, r10d
    pop     rbx
    ret
log2x1000 endp

; ---------------------------------------------------------------------------
; draw_chars(rcx = dst, edx = n, r8 = alphabet, r9d = alphabet len) -> rax = dst+n
;   (0 on failure).  Appends n uniform chars and adds n*log2(len) to pw_entropy.
; ---------------------------------------------------------------------------
draw_chars proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx            ; dst cursor
    mov     dword ptr [rbp-32], edx            ; n
    mov     qword ptr [rbp-40], r8             ; alphabet
    mov     dword ptr [rbp-48], r9d            ; len
    mov     dword ptr [rbp-52], 0              ; i
    mov     ecx, r9d
    call    log2x1000
    mov     dword ptr [rbp-56], eax            ; bits*1000 per char
dc_loop:
    mov     eax, dword ptr [rbp-52]
    cmp     eax, dword ptr [rbp-32]
    jae     dc_done
    mov     ecx, dword ptr [rbp-48]
    call    rand_idx
    cmp     eax, -1
    je      dc_fail
    mov     r10, qword ptr [rbp-40]
    movzx   eax, byte ptr [r10+rax]
    mov     r11, qword ptr [rbp-24]
    mov     byte ptr [r11], al
    inc     qword ptr [rbp-24]
    mov     eax, dword ptr [rbp-56]
    add     dword ptr [pw_entropy], eax
    inc     dword ptr [rbp-52]
    jmp     dc_loop
dc_done:
    mov     rax, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
dc_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
draw_chars endp

; ---------------------------------------------------------------------------
; filter_ambig() - compact ambiguous glyphs out of pw_alpha (updates pw_alpha_n).
; ---------------------------------------------------------------------------
filter_ambig proc
    lea     r10, [pw_alpha]
    xor     r8d, r8d                            ; read
    xor     r9d, r9d                            ; write
fa_loop:
    cmp     r8d, dword ptr [pw_alpha_n]
    jae     fa_done
    movzx   eax, byte ptr [r10+r8]
    lea     r11, [abc_ambig]
    xor     ecx, ecx
fa_chk:
    cmp     ecx, abc_ambig_n
    jae     fa_keep
    cmp     al, byte ptr [r11+rcx]
    je      fa_skip
    inc     ecx
    jmp     fa_chk
fa_keep:
    mov     byte ptr [r10+r9], al
    inc     r9d
fa_skip:
    inc     r8d
    jmp     fa_loop
fa_done:
    mov     dword ptr [pw_alpha_n], r9d
    ret
filter_ambig endp

; ===========================================================================
; pwgen_ex(rcx = outbuf, edx = n, r8d = style, r9d = opt) -> eax = entropy bits
;   (0 on failure).  Writes the password + a NUL terminator to outbuf.
;   n means char count (RANDOM/PRONOUNCE/PIN/HEX) or word count (PASSPHRASE).
;   opt low nibble = class mask for RANDOM; PWO_* flags in the high bits.
; ===========================================================================
public pwgen_ex
pwgen_ex proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx            ; cursor
    mov     dword ptr [rbp-32], edx            ; n
    mov     dword ptr [rbp-40], r8d            ; style
    mov     dword ptr [rbp-48], r9d            ; opt
    mov     dword ptr [pw_entropy], 0
    cmp     edx, 1
    jb      pex_fail
    cmp     edx, PWGEN_MAX_LEN
    ja      pex_fail
    mov     eax, r8d
    cmp     eax, PWS_PASSPHRASE
    je      pex_phrase
    cmp     eax, PWS_PRONOUNCE
    je      pex_pron
    cmp     eax, PWS_PIN
    je      pex_pin
    cmp     eax, PWS_HEX
    je      pex_hex
; ---- RANDOM: assemble class alphabet (+ optional no-ambiguous) --------------
    mov     dword ptr [pw_alpha_n], 0
    test    dword ptr [rbp-48], PWCLASS_UPPER
    jz      @F
    lea     rcx, [abc_upper]
    mov     edx, abc_upper_n
    call    pwg_append
@@: test    dword ptr [rbp-48], PWCLASS_LOWER
    jz      @F
    lea     rcx, [abc_lower]
    mov     edx, abc_lower_n
    call    pwg_append
@@: test    dword ptr [rbp-48], PWCLASS_DIGIT
    jz      @F
    lea     rcx, [abc_digit]
    mov     edx, abc_digit_n
    call    pwg_append
@@: test    dword ptr [rbp-48], PWCLASS_SYMBOL
    jz      @F
    lea     rcx, [abc_symbol]
    mov     edx, abc_symbol_n
    call    pwg_append
@@: test    dword ptr [rbp-48], PWO_NOAMBIG
    jz      pex_rnd_go
    call    filter_ambig
pex_rnd_go:
    cmp     dword ptr [pw_alpha_n], 0
    je      pex_fail
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    lea     r8, [pw_alpha]
    mov     r9d, dword ptr [pw_alpha_n]
    call    draw_chars
    test    rax, rax
    jz      pex_fail
    mov     qword ptr [rbp-24], rax
    jmp     pex_finish
pex_pin:
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    lea     r8, [abc_digit]
    mov     r9d, abc_digit_n
    call    draw_chars
    test    rax, rax
    jz      pex_fail
    mov     qword ptr [rbp-24], rax
    jmp     pex_finish
pex_hex:
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    lea     r8, [abc_hex]
    mov     r9d, abc_hex_n
    call    draw_chars
    test    rax, rax
    jz      pex_fail
    mov     qword ptr [rbp-24], rax
    jmp     pex_afterdigit                      ; hex already covers digits; skip PWO_DIGIT
; ---- PRONOUNCE: alternate consonant / vowel --------------------------------
pex_pron:
    mov     dword ptr [rbp-56], 0               ; i
pex_pron_lp:
    mov     eax, dword ptr [rbp-56]
    cmp     eax, dword ptr [rbp-32]
    jae     pex_pron_done
    test    eax, 1
    jnz     pex_pron_vow
    lea     r8, [abc_cons]
    mov     r9d, abc_cons_n
    jmp     pex_pron_draw
pex_pron_vow:
    lea     r8, [abc_vowel]
    mov     r9d, abc_vowel_n
pex_pron_draw:
    mov     rcx, qword ptr [rbp-24]
    mov     edx, 1
    call    draw_chars
    test    rax, rax
    jz      pex_fail
    mov     qword ptr [rbp-24], rax
    ; capitalize the first char if requested
    cmp     dword ptr [rbp-56], 0
    jne     pex_pron_next
    test    dword ptr [rbp-48], PWO_CAP
    jz      pex_pron_next
    mov     r10, qword ptr [rbp-24]
    movzx   eax, byte ptr [r10-1]
    cmp     al, 'a'
    jb      pex_pron_next
    cmp     al, 'z'
    ja      pex_pron_next
    sub     al, 20h
    mov     byte ptr [r10-1], al
pex_pron_next:
    inc     dword ptr [rbp-56]
    jmp     pex_pron_lp
pex_pron_done:
    jmp     pex_afterphrase                     ; -> optional trailing digit
; ---- PASSPHRASE: n words from the embedded list ----------------------------
pex_phrase:
    mov     dword ptr [rbp-56], 0               ; word i
pex_phrase_lp:
    mov     eax, dword ptr [rbp-56]
    cmp     eax, dword ptr [rbp-32]
    jae     pex_phrase_done
    ; separator '-' between words
    cmp     eax, 0
    je      pex_phrase_word
    test    dword ptr [rbp-48], PWO_DASH
    jz      pex_phrase_word
    mov     r10, qword ptr [rbp-24]
    mov     byte ptr [r10], '-'
    inc     qword ptr [rbp-24]
pex_phrase_word:
    mov     ecx, WL_COUNT
    call    rand_idx
    cmp     eax, -1
    je      pex_fail
    imul    eax, eax, WL_STRIDE                 ; &wl_words[idx]
    lea     r10, [wl_words]
    add     r10, rax
    mov     dword ptr [rbp-64], 0               ; char j
pex_word_cp:
    mov     eax, dword ptr [rbp-64]
    cmp     eax, WL_STRIDE
    jae     pex_word_done
    movzx   ecx, byte ptr [r10+rax]
    test    ecx, ecx
    jz      pex_word_done
    ; capitalize first letter of each word if requested
    cmp     eax, 0
    jne     pex_word_put
    test    dword ptr [rbp-48], PWO_CAP
    jz      pex_word_put
    cmp     cl, 'a'
    jb      pex_word_put
    cmp     cl, 'z'
    ja      pex_word_put
    sub     cl, 20h
pex_word_put:
    mov     r11, qword ptr [rbp-24]
    mov     byte ptr [r11], cl
    inc     qword ptr [rbp-24]
    inc     dword ptr [rbp-64]
    jmp     pex_word_cp
pex_word_done:
    add     dword ptr [pw_entropy], 8000        ; 256-word list -> 8 bits/word
    inc     dword ptr [rbp-56]
    jmp     pex_phrase_lp
pex_phrase_done:
pex_afterphrase:
    ; optional trailing random digit
    test    dword ptr [rbp-48], PWO_DIGIT
    jz      pex_afterdigit
    mov     ecx, 10
    call    rand_idx
    cmp     eax, -1
    je      pex_fail
    add     eax, '0'
    mov     r10, qword ptr [rbp-24]
    mov     byte ptr [r10], al
    inc     qword ptr [rbp-24]
    add     dword ptr [pw_entropy], 3321        ; log2(10)
pex_afterdigit:
pex_finish:
    mov     rax, qword ptr [rbp-24]
    mov     byte ptr [rax], 0                   ; NUL terminate
    mov     eax, dword ptr [pw_entropy]
    xor     edx, edx
    mov     ecx, 1000
    div     ecx                                 ; -> whole bits
    FRAME_EPILOG
    ret
pex_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
pwgen_ex endp

; =============================================================================
; check_password_policy() -> eax = 0 ok / 1 too short / 2 too few classes
; (counts UTF-8 code points and distinct
; character classes in g_cfg_pass[0..g_cfg_passlen).)
; =============================================================================
public check_password_policy
check_password_policy proc
    lea     r9, [g_cfg_pass]
    mov     ecx, dword ptr [g_cfg_passlen]
    xor     r10d, r10d                  ; code-point count
    xor     r11d, r11d                  ; class mask (1=U 2=L 4=D 8=S)
    xor     r8d, r8d
cpp_loop:
    cmp     r8d, ecx
    jae     cpp_eval
    movzx   eax, byte ptr [r9+r8]
    mov     edx, eax                    ; count code points: (b & 0xC0) != 0x80
    and     edx, 0C0h
    cmp     edx, 80h
    je      cpp_noinc
    inc     r10d
cpp_noinc:
    cmp     eax, 'A'
    jb      cpp_lo
    cmp     eax, 'Z'
    ja      cpp_lo
    or      r11d, 1
    jmp     cpp_next
cpp_lo:
    cmp     eax, 'a'
    jb      cpp_di
    cmp     eax, 'z'
    ja      cpp_di
    or      r11d, 2
    jmp     cpp_next
cpp_di:
    cmp     eax, '0'
    jb      cpp_sy
    cmp     eax, '9'
    ja      cpp_sy
    or      r11d, 4
    jmp     cpp_next
cpp_sy:
    or      r11d, 8
cpp_next:
    inc     r8d
    jmp     cpp_loop
cpp_eval:
    mov     eax, dword ptr [g_cfg_pwminlen]
    cmp     r10d, eax
    jb      cpp_short
    xor     eax, eax                    ; popcount of the 4-bit class mask
    test    r11d, 1
    jz      @F
    inc     eax
@@: test    r11d, 2
    jz      @F
    inc     eax
@@: test    r11d, 4
    jz      @F
    inc     eax
@@: test    r11d, 8
    jz      @F
    inc     eax
@@: cmp     eax, dword ptr [g_cfg_pwminclasses]
    jb      cpp_few
    xor     eax, eax
    ret
cpp_short:
    mov     eax, 1
    ret
cpp_few:
    mov     eax, 2
    ret
check_password_policy endp

; ---------------------------------------------------------------------------
; pw_metrics() -> eax = UTF-8 code-point count, edx = distinct class count (0..4)
;   over g_cfg_pass / g_cfg_passlen.  Same scan as check_password_policy, exposed
;   so the GUI can drive a live password strength / compliance indicator.
; ---------------------------------------------------------------------------
public pw_metrics
pw_metrics proc
    lea     r9, [g_cfg_pass]
    mov     ecx, dword ptr [g_cfg_passlen]
    xor     r10d, r10d                  ; code-point count
    xor     r11d, r11d                  ; class mask (1=U 2=L 4=D 8=S)
    xor     r8d, r8d
pmx_loop:
    cmp     r8d, ecx
    jae     pmx_eval
    movzx   eax, byte ptr [r9+r8]
    mov     edx, eax                    ; code points: (b & 0xC0) != 0x80
    and     edx, 0C0h
    cmp     edx, 80h
    je      pmx_noinc
    inc     r10d
pmx_noinc:
    cmp     eax, 'A'
    jb      pmx_lo
    cmp     eax, 'Z'
    ja      pmx_lo
    or      r11d, 1
    jmp     pmx_next
pmx_lo:
    cmp     eax, 'a'
    jb      pmx_di
    cmp     eax, 'z'
    ja      pmx_di
    or      r11d, 2
    jmp     pmx_next
pmx_di:
    cmp     eax, '0'
    jb      pmx_sy
    cmp     eax, '9'
    ja      pmx_sy
    or      r11d, 4
    jmp     pmx_next
pmx_sy:
    or      r11d, 8
pmx_next:
    inc     r8d
    jmp     pmx_loop
pmx_eval:
    xor     edx, edx                    ; popcount of the 4-bit class mask
    test    r11d, 1
    jz      @F
    inc     edx
@@: test    r11d, 2
    jz      @F
    inc     edx
@@: test    r11d, 4
    jz      @F
    inc     edx
@@: test    r11d, 8
    jz      @F
    inc     edx
@@: mov     eax, r10d
    ret
pw_metrics endp

end
