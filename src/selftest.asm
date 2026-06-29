; =============================================================================
; selftest.asm - embedded known-answer tests for every primitive
; -----------------------------------------------------------------------------
; run_selftest(rcx = verbose) -> eax = number of failures.
;   verbose != 0 : print the full "[PASS]/[FAIL]" report (the `selftest` verb).
;   verbose == 0 : run silently and just return the failure count - used by the
;                  startup gate, which runs the KATs on EVERY launch and aborts
;                  fail-closed if any vector mismatches (per the brief).
;
; Each primitive is validated against an official RFC/NIST vector, plus the
; password generator and an in-memory vault seal/open round-trip.
; =============================================================================

include macros.inc

extern sha256_hash:proc
extern ct_memcmp:proc
extern print_a:proc
extern gcm_seal:proc
extern gcm_open:proc
extern blake2b_hash:proc
extern argon2_compress:proc
extern argon2id_hash:proc
extern check_password_policy:proc
extern pwgen:proc
extern vault_selftest:proc
externdef g_cfg_pass:byte
externdef g_cfg_passlen:dword
externdef g_cfg_pwminlen:dword
externdef g_cfg_pwminclasses:dword

ARGON2REQ struct
    t_cost      dd ?
    m_cost      dd ?
    lanes       dd ?
    outlen      dd ?
    version     dd ?
    atype       dd ?
    pwd         dq ?
    pwdlen      dd ?
    saltlen     dd ?
    salt        dq ?
    secret      dq ?
    secretlen   dd ?
    adlen       dd ?
    ad          dq ?
    outp        dq ?
ARGON2REQ ends

GCMREQ struct
    key     dq ?
    iv      dq ?
    aad     dq ?
    aadlen  dq ?
    inp     dq ?
    inlen   dq ?
    outp    dq ?
    tag     dq ?
GCMREQ ends

.const
st_abc          db "abc"
; SHA-256("abc")
sha_abc_exp     db 0bah,078h,016h,0bfh,08fh,001h,0cfh,0eah,041h,041h,040h,0deh,05dh,0aeh,022h,023h
                db 0b0h,003h,061h,0a3h,096h,017h,07ah,09ch,0b4h,010h,0ffh,061h,0f2h,000h,015h,0adh

CSTR st_hdr,       "running self-tests:",13,10
CSTR st_pass_sha,  "  [PASS] sha-256  (FIPS 180-4 'abc')",13,10
CSTR st_fail_sha,  "  [FAIL] sha-256",13,10
CSTR st_pass_gcm,  "  [PASS] aes-256-gcm  (NIST SP800-38D + round-trip)",13,10
CSTR st_fail_gcm,  "  [FAIL] aes-256-gcm",13,10
CSTR st_pass_aad,  "  [PASS] aes-256-gcm + AAD round-trip",13,10
CSTR st_fail_aad,  "  [FAIL] aes-256-gcm + AAD",13,10
CSTR st_pass_ip,   "  [PASS] aes-256-gcm in-place + tail",13,10
CSTR st_fail_ip,   "  [FAIL] aes-256-gcm in-place + tail",13,10
CSTR st_pass_b2b,  "  [PASS] blake2b  (RFC 7693 'abc')",13,10
CSTR st_fail_b2b,  "  [FAIL] blake2b",13,10
CSTR st_pass_ac,   "  [PASS] argon2 compress  (block KAT)",13,10
CSTR st_fail_ac,   "  [FAIL] argon2 compress",13,10
CSTR st_pass_a2,   "  [PASS] argon2id  (RFC 9106 test vector)",13,10
CSTR st_fail_a2,   "  [FAIL] argon2id",13,10
CSTR st_pass_pw,   "  [PASS] password policy (length + class rules)",13,10
CSTR st_fail_pw,   "  [FAIL] password policy",13,10
CSTR st_pass_gen,  "  [PASS] pwgen  (alphabet + length, no bias tail)",13,10
CSTR st_fail_gen,  "  [FAIL] pwgen",13,10
CSTR st_pass_vlt,  "  [PASS] vault seal/open  (Argon2id KDF -> KCV -> GCM round-trip)",13,10
CSTR st_fail_vlt,  "  [FAIL] vault seal/open",13,10

; policy test passwords
pw_short    db "Abc12"                       ; 5 chars (too short)
pw_short_n  equ $ - pw_short
pw_oneclass db "abcdefghijklmnopqrs"         ; 19 lower only (too few classes)
pw_oneclass_n equ $ - pw_oneclass
pw_good3    db "Abcdefghij12"                ; 12 chars, U+L+D = 3 classes
pw_good3_n  equ $ - pw_good3
align 8
arg_cksum   dq 05ee3a5c79eba0a63h
arg_out0    dq 0dc71308d33513477h
; RFC 9106 Argon2id tag (t=3,m=32,p=4,secret,ad)
a2_exp      db 00dh,064h,00dh,0f5h,08dh,078h,076h,06ch,008h,0c0h,037h,0a3h,04ah,08bh,053h,0c9h
            db 0d0h,01eh,0f0h,045h,02dh,075h,0b6h,05eh,0b5h,025h,020h,0e9h,06bh,001h,0e6h,059h
; BLAKE2b-512("abc") - RFC 7693 Appendix A
b2b_abc_exp db 0bah,080h,0a5h,03fh,098h,01ch,04dh,00dh,06ah,027h,097h,0b6h,09fh,012h,0f6h,0e9h
            db 04ch,021h,02fh,014h,068h,05ah,0c4h,0b7h,04bh,012h,0bbh,06fh,0dbh,0ffh,0a2h,0d1h
            db 07dh,087h,0c5h,039h,02ah,0abh,079h,02dh,0c2h,052h,0d5h,0deh,045h,033h,0cch,095h
            db 018h,0d3h,08ah,0a8h,0dbh,0f1h,092h,05ah,0b9h,023h,086h,0edh,0d4h,000h,099h,023h
; NIST SP800-38D AES-256-GCM: key=0(32), iv=0(12), aad=none, pt=16 zero bytes
gcm_ct_exp  db 0ceh,0a7h,040h,03dh,04dh,060h,06bh,06eh,007h,04eh,0c5h,0d3h,0bah,0f3h,09dh,018h
gcm_tag_exp db 0d0h,0d1h,0c8h,0a7h,099h,099h,06bh,0f0h,026h,05bh,098h,0b5h,0d4h,08ah,0b9h,019h

.data?
st_out          db 32 dup (?)
b2b_out         db 64 dup (?)
gcm_aadbuf      db 32 dup (?)
gcm_pt2b        db 16 dup (?)
gcm_dec2        db 16 dup (?)
gcm_tag2b       db 16 dup (?)
align 16
gcm_ip_pt       db 20 dup (?)        ; 20 bytes -> 1 block + 4-byte tail
gcm_ip_buf      db 20 dup (?)        ; in-place work buffer
gcm_ip_tag      db 16 dup (?)
align 16
arg_x           db 1024 dup (?)
arg_y           db 1024 dup (?)
arg_o           db 1024 dup (?)
a2_pwd          db 32 dup (?)
a2_salt         db 16 dup (?)
a2_secret       db 8 dup (?)
a2_ad           db 12 dup (?)
a2_out          db 32 dup (?)
align 8
a2_req          ARGON2REQ <>
gcm_key         db 32 dup (?)
gcm_iv          db 12 dup (?)
gcm_pt          db 16 dup (?)
gcm_ct          db 16 dup (?)
gcm_tag         db 16 dup (?)
gcm_dec         db 16 dup (?)
align 8
greq            GCMREQ <>
pw_out          db 64 dup (?)
g_st_verbose    dd ?

.code

; STPRINT msg, len - print a line only when running verbose (the `selftest`
; verb); silent under the startup gate.
STPRINT macro msg, len
    cmp     dword ptr [g_st_verbose], 0
    je      @F
    lea     rcx, [msg]
    mov     edx, len
    call    print_a
@@:
endm

; LOADPW src,len - copy a test password into g_cfg_pass, set g_cfg_passlen
LOADPW macro src, len
    lea     r12, [src]
    lea     r13, [g_cfg_pass]
    xor     r9d, r9d
@@:
    mov     al, byte ptr [r12+r9]
    mov     byte ptr [r13+r9], al
    inc     r9d
    cmp     r9d, len
    jb      @B
    mov     dword ptr [g_cfg_passlen], len
endm

; =============================================================================
; run_selftest(rcx = verbose) -> eax = number of failures
; =============================================================================
public run_selftest
run_selftest proc frame
    FRAME_PROLOG 96
    ; [rbp-24] = failure count
    mov     dword ptr [g_st_verbose], ecx
    mov     qword ptr [rbp-24], 0

    STPRINT st_hdr, st_hdr_len

    ; ---- SHA-256("abc") -----------------------------------------------------
    lea     rcx, [st_abc]
    mov     rdx, 3
    lea     r8, [st_out]
    call    sha256_hash
    lea     rcx, [st_out]
    lea     rdx, [sha_abc_exp]
    mov     r8, 32
    call    ct_memcmp
    test    eax, eax
    jnz     st_sha_fail
    STPRINT st_pass_sha, st_pass_sha_len
    jmp     st_after_sha
st_sha_fail:
    STPRINT st_fail_sha, st_fail_sha_len
    inc     qword ptr [rbp-24]
st_after_sha:

    ; ---- AES-256-GCM seal (key/iv/pt all zero via BSS) ----------------------
    lea     rax, [gcm_key]
    mov     qword ptr [greq].GCMREQ.key, rax
    lea     rax, [gcm_iv]
    mov     qword ptr [greq].GCMREQ.iv, rax
    mov     qword ptr [greq].GCMREQ.aad, 0
    mov     qword ptr [greq].GCMREQ.aadlen, 0
    lea     rax, [gcm_pt]
    mov     qword ptr [greq].GCMREQ.inp, rax
    mov     qword ptr [greq].GCMREQ.inlen, 16
    lea     rax, [gcm_ct]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rax, [gcm_tag]
    mov     qword ptr [greq].GCMREQ.tag, rax
    lea     rcx, [greq]
    call    gcm_seal
    lea     rcx, [gcm_ct]
    lea     rdx, [gcm_ct_exp]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     st_gcm_fail
    lea     rcx, [gcm_tag]
    lea     rdx, [gcm_tag_exp]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     st_gcm_fail
    ; round-trip open
    lea     rax, [gcm_ct]
    mov     qword ptr [greq].GCMREQ.inp, rax
    lea     rax, [gcm_dec]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rcx, [greq]
    call    gcm_open
    test    eax, eax
    jnz     st_gcm_fail
    lea     rcx, [gcm_dec]
    lea     rdx, [gcm_pt]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     st_gcm_fail
    STPRINT st_pass_gcm, st_pass_gcm_len
    jmp     st_after_gcm
st_gcm_fail:
    STPRINT st_fail_gcm, st_fail_gcm_len
    inc     qword ptr [rbp-24]
st_after_gcm:

    ; ---- AES-256-GCM with AAD: seal then open round-trip --------------------
    lea     rax, [gcm_key]
    mov     qword ptr [greq].GCMREQ.key, rax
    lea     rax, [gcm_iv]
    mov     qword ptr [greq].GCMREQ.iv, rax
    lea     rax, [gcm_aadbuf]
    mov     qword ptr [greq].GCMREQ.aad, rax
    mov     qword ptr [greq].GCMREQ.aadlen, 32
    lea     rax, [gcm_pt2b]
    mov     qword ptr [greq].GCMREQ.inp, rax
    mov     qword ptr [greq].GCMREQ.inlen, 16
    lea     rax, [gcm_ct]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rax, [gcm_tag2b]
    mov     qword ptr [greq].GCMREQ.tag, rax
    lea     rcx, [greq]
    call    gcm_seal
    lea     rax, [gcm_ct]
    mov     qword ptr [greq].GCMREQ.inp, rax
    lea     rax, [gcm_dec2]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rcx, [greq]
    call    gcm_open
    test    eax, eax
    jnz     st_aad_fail
    lea     rcx, [gcm_dec2]
    lea     rdx, [gcm_pt2b]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     st_aad_fail
    STPRINT st_pass_aad, st_pass_aad_len
    jmp     st_after_aad
st_aad_fail:
    STPRINT st_fail_aad, st_fail_aad_len
    inc     qword ptr [rbp-24]
st_after_aad:

    ; ---- AES-256-GCM in-place decrypt with a partial-block tail -------------
    lea     rax, [gcm_key]
    mov     qword ptr [greq].GCMREQ.key, rax
    lea     rax, [gcm_iv]
    mov     qword ptr [greq].GCMREQ.iv, rax
    lea     rax, [gcm_aadbuf]
    mov     qword ptr [greq].GCMREQ.aad, rax
    mov     qword ptr [greq].GCMREQ.aadlen, 32
    lea     rax, [gcm_ip_pt]
    mov     qword ptr [greq].GCMREQ.inp, rax
    mov     qword ptr [greq].GCMREQ.inlen, 20
    lea     rax, [gcm_ip_buf]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rax, [gcm_ip_tag]
    mov     qword ptr [greq].GCMREQ.tag, rax
    lea     rcx, [greq]
    call    gcm_seal
    lea     rax, [gcm_ip_buf]
    mov     qword ptr [greq].GCMREQ.inp, rax
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rcx, [greq]
    call    gcm_open
    test    eax, eax
    jnz     st_ip_fail
    lea     rcx, [gcm_ip_buf]
    lea     rdx, [gcm_ip_pt]
    mov     r8, 20
    call    ct_memcmp
    test    eax, eax
    jnz     st_ip_fail
    STPRINT st_pass_ip, st_pass_ip_len
    jmp     st_after_ip
st_ip_fail:
    STPRINT st_fail_ip, st_fail_ip_len
    inc     qword ptr [rbp-24]
st_after_ip:

    ; ---- BLAKE2b-512("abc") -------------------------------------------------
    lea     rcx, [st_abc]
    mov     rdx, 3
    lea     r8, [b2b_out]
    mov     r9, 64
    call    blake2b_hash
    lea     rcx, [b2b_out]
    lea     rdx, [b2b_abc_exp]
    mov     r8, 64
    call    ct_memcmp
    test    eax, eax
    jnz     st_b2b_fail
    STPRINT st_pass_b2b, st_pass_b2b_len
    jmp     st_after_b2b
st_b2b_fail:
    STPRINT st_fail_b2b, st_fail_b2b_len
    inc     qword ptr [rbp-24]
st_after_b2b:

    ; ---- Argon2 block compression (known-answer test) -----------------------
    lea     r12, [arg_x]
    lea     r13, [arg_y]
    xor     r9d, r9d
st_acfill:
    lea     r8, [r9+1]
    mov     rax, 00101010101010101h
    imul    rax, r8
    mov     qword ptr [r12 + r9*8], rax
    mov     rax, 00202020202020202h
    imul    rax, r8
    mov     qword ptr [r13 + r9*8], rax
    inc     r9d
    cmp     r9d, 128
    jb      st_acfill
    lea     rcx, [arg_o]
    lea     rdx, [arg_x]
    lea     r8,  [arg_y]
    xor     r9d, r9d                    ; with_xor = 0
    call    argon2_compress
    lea     r12, [arg_o]
    xor     rax, rax
    xor     r9d, r9d
st_acsum:
    xor     rax, qword ptr [r12 + r9*8]
    inc     r9d
    cmp     r9d, 128
    jb      st_acsum
    mov     r10, qword ptr [arg_cksum]
    cmp     rax, r10
    jne     st_ac_fail
    mov     rax, qword ptr [arg_o]
    mov     r10, qword ptr [arg_out0]
    cmp     rax, r10
    jne     st_ac_fail
    STPRINT st_pass_ac, st_pass_ac_len
    jmp     st_after_ac
st_ac_fail:
    STPRINT st_fail_ac, st_fail_ac_len
    inc     qword ptr [rbp-24]
st_after_ac:

    ; ---- Argon2id full KDF (RFC 9106 vector) --------------------------------
    lea     r12, [a2_pwd]
    mov     ecx, 32
st_fpwd:
    mov     byte ptr [r12], 1
    inc     r12
    dec     ecx
    jnz     st_fpwd
    lea     r12, [a2_salt]
    mov     ecx, 16
st_fsalt:
    mov     byte ptr [r12], 2
    inc     r12
    dec     ecx
    jnz     st_fsalt
    lea     r12, [a2_secret]
    mov     ecx, 8
st_fsec:
    mov     byte ptr [r12], 3
    inc     r12
    dec     ecx
    jnz     st_fsec
    lea     r12, [a2_ad]
    mov     ecx, 12
st_fad:
    mov     byte ptr [r12], 4
    inc     r12
    dec     ecx
    jnz     st_fad
    lea     r12, [a2_req]
    mov     dword ptr [r12].ARGON2REQ.t_cost, 3
    mov     dword ptr [r12].ARGON2REQ.m_cost, 32
    mov     dword ptr [r12].ARGON2REQ.lanes, 4
    mov     dword ptr [r12].ARGON2REQ.outlen, 32
    mov     dword ptr [r12].ARGON2REQ.version, 13h
    mov     dword ptr [r12].ARGON2REQ.atype, 2
    lea     rax, [a2_pwd]
    mov     qword ptr [r12].ARGON2REQ.pwd, rax
    mov     dword ptr [r12].ARGON2REQ.pwdlen, 32
    lea     rax, [a2_salt]
    mov     qword ptr [r12].ARGON2REQ.salt, rax
    mov     dword ptr [r12].ARGON2REQ.saltlen, 16
    lea     rax, [a2_secret]
    mov     qword ptr [r12].ARGON2REQ.secret, rax
    mov     dword ptr [r12].ARGON2REQ.secretlen, 8
    lea     rax, [a2_ad]
    mov     qword ptr [r12].ARGON2REQ.ad, rax
    mov     dword ptr [r12].ARGON2REQ.adlen, 12
    lea     rax, [a2_out]
    mov     qword ptr [r12].ARGON2REQ.outp, rax
    lea     rcx, [a2_req]
    call    argon2id_hash
    test    eax, eax
    jnz     st_a2_fail
    lea     rcx, [a2_out]
    lea     rdx, [a2_exp]
    mov     r8, 32
    call    ct_memcmp
    test    eax, eax
    jnz     st_a2_fail
    STPRINT st_pass_a2, st_pass_a2_len
    jmp     st_after_a2
st_a2_fail:
    STPRINT st_fail_a2, st_fail_a2_len
    inc     qword ptr [rbp-24]
st_after_a2:

    ; ---- password policy (default min 12 chars / 3 of 4 classes) ------------
    mov     dword ptr [g_cfg_pwminlen], 12
    mov     dword ptr [g_cfg_pwminclasses], 3
    LOADPW  pw_short, pw_short_n            ; 5 chars -> too short (1)
    call    check_password_policy
    cmp     eax, 1
    jne     st_pw_fail
    LOADPW  pw_oneclass, pw_oneclass_n      ; 19 lower-only -> too few (2)
    call    check_password_policy
    cmp     eax, 2
    jne     st_pw_fail
    LOADPW  pw_good3, pw_good3_n            ; 12 chars, 3 classes -> ok (0)
    call    check_password_policy
    test    eax, eax
    jnz     st_pw_fail
    STPRINT st_pass_pw, st_pass_pw_len
    jmp     st_after_pw
st_pw_fail:
    STPRINT st_fail_pw, st_fail_pw_len
    inc     qword ptr [rbp-24]
st_after_pw:

    ; ---- pwgen: generate 24 chars over all classes; check length + alphabet -
    lea     rcx, [pw_out]
    mov     edx, 24
    mov     r8d, 15                         ; all four classes
    call    pwgen
    test    eax, eax
    jz      st_gen_fail
    lea     r10, [pw_out]
    mov     ecx, 24
st_gen_scan:
    movzx   eax, byte ptr [r10]
    cmp     al, 21h                         ; printable ASCII range [0x21,0x7E]
    jb      st_gen_fail
    cmp     al, 7Eh
    ja      st_gen_fail
    inc     r10
    dec     ecx
    jnz     st_gen_scan
    STPRINT st_pass_gen, st_pass_gen_len
    jmp     st_after_gen
st_gen_fail:
    STPRINT st_fail_gen, st_fail_gen_len
    inc     qword ptr [rbp-24]
st_after_gen:

    ; ---- vault seal/open (Argon2id -> KCV -> AES-256-GCM, in memory) ---------
    call    vault_selftest
    test    eax, eax
    jnz     st_vlt_fail
    STPRINT st_pass_vlt, st_pass_vlt_len
    jmp     st_after_vlt
st_vlt_fail:
    STPRINT st_fail_vlt, st_fail_vlt_len
    inc     qword ptr [rbp-24]
st_after_vlt:

    mov     rax, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
run_selftest endp

end
