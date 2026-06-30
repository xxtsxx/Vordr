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

.data?
align 16
pw_alpha    db 128 dup (?)         ; assembled alphabet (max 26+26+10+23 = 85)
pw_alpha_n  dd ?                    ; assembled alphabet length

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
