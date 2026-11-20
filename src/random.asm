; =============================================================================
; random.asm - CSPRNG
; -----------------------------------------------------------------------------
; rng_fill(rcx = buffer, edx = length) -> eax = 1 ok, 0 failure
;
; Primary source : BCryptGenRandom(NULL, buf, len, USE_SYSTEM_PREFERRED_RNG)
; Defense in depth: if the CPU supports RDSEED, every 8-byte lane is XOR-mixed
; with an independent hardware source.  Security relies on the OS CSPRNG; the
; hardware contribution is supplemental and assumes the sources are not
; maliciously correlated.
; Policy        : if the OS RNG fails we FAIL - we never fall back to a
;                 weaker source for key material.
; =============================================================================

include macros.inc

extern BCryptGenRandom:proc
extern secure_zero:proc

BCRYPT_USE_SYSTEM_PREFERRED_RNG equ 2

.code

public rng_fill
rng_fill proc frame
    FRAME_PROLOG 48
    ; locals: [rbp-24] buffer, [rbp-32] length
    test    rcx, rcx
    jz      rf_fail
    test    edx, edx
    jz      rf_ok

    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx

    ; ---- primary: OS CSPRNG -------------------------------------------------
    ; BCryptGenRandom(hAlgorithm=NULL, pbBuffer, cbBuffer, dwFlags)
    WINCALL BCryptGenRandom, 0, rcx, edx, BCRYPT_USE_SYSTEM_PREFERRED_RNG
    test    eax, eax                    ; NTSTATUS: 0 = STATUS_SUCCESS
    jnz     rf_wipe_fail

    ; ---- defense in depth: XOR-mix RDSEED if available ----------------------
    test    dword ptr [g_cpu_features], CPUF_RDSEED
    jz      rf_ok
    mov     r10, qword ptr [rbp-24]     ; cursor
    mov     r11d, dword ptr [rbp-32]    ; remaining bytes
rf_mix_loop:
    cmp     r11d, 8
    jb      rf_tail
    mov     eax, 16                     ; retry budget per lane
rf_retry:
    rdseed  rcx
    jc      rf_have_seed
    pause
    dec     eax
    jnz     rf_retry
    jmp     rf_ok                       ; RDSEED starved: keep OS bytes, still ok
rf_have_seed:
    xor     qword ptr [r10], rcx
    add     r10, 8
    sub     r11d, 8
    jmp     rf_mix_loop

rf_tail:
    test    r11d, r11d
    jz      rf_ok
    mov     eax, 16                     ; draw one hardware qword for 1..7-byte tail
rf_t_retry:
    rdseed  rcx
    jc      rf_t_have
    pause
    dec     eax
    jnz     rf_t_retry
    jmp     rf_ok
rf_t_have:
    xor     byte ptr [r10], cl
    shr     rcx, 8
    inc     r10
    dec     r11d
    jnz     rf_t_have

rf_ok:
    xor     ecx, ecx                    ; scrub last hardware RDSEED qword from rcx
    mov     eax, 1
    jmp     rf_done
rf_wipe_fail:
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    call    secure_zero
rf_fail:
    xor     ecx, ecx
    xor     eax, eax
rf_done:
    FRAME_EPILOG
    ret
rng_fill endp

end
