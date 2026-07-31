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
extern secure_zero:proc
extern print_a:proc
extern print_hex:proc
extern print_u64:proc
extern CreateThread:proc
extern WaitForMultipleObjects:proc
extern CloseHandle:proc
extern GetSystemInfo:proc
extern InitializeCriticalSection:proc
extern EnterCriticalSection:proc
extern LeaveCriticalSection:proc
extern DeleteCriticalSection:proc
extern gcm_seal:proc
extern gcm_open:proc
extern blake2b_hash:proc
extern argon2_compress:proc
extern argon2id_hash:proc
extern check_password_policy:proc
extern pwgen:proc
extern pwgen_ex:proc
externdef g_pwgen_outcap:dword          ; E16: one-shot pwgen output capacity
extern vault_selftest:proc
extern hmac_sha1:proc
extern base32_decode:proc
extern hotp:proc
extern gui_wstr_eq:proc                  ; constant-time wide-string equality (gui.asm)
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

; one extended Argon2id known-answer vector (t/m/p/outlen + optional keyed
; secret and associated data).  Emphasises single-lane (p=1) and large-segment
; cases - the pass0/slice0 address-index path the lone RFC vector never touched.
A2VEC struct
    v_t         dd ?
    v_m         dd ?
    v_p         dd ?
    v_outlen    dd ?
    v_pwd       dq ?
    v_pwdlen    dd ?
    v_saltlen   dd ?
    v_salt      dq ?
    v_sec       dq ?
    v_seclen    dd ?
    v_adlen     dd ?
    v_ad        dq ?
    v_exp       dq ?
A2VEC ends

.const
st_abc          db "abc"
; SHA-256("abc")
sha_abc_exp     db 0bah,078h,016h,0bfh,08fh,001h,0cfh,0eah,041h,041h,040h,0deh,05dh,0aeh,022h,023h
                db 0b0h,003h,061h,0a3h,096h,017h,07ah,09ch,0b4h,010h,0ffh,061h,0f2h,000h,015h,0adh

CSTR st_hdr,       "running self-tests:",13,10
CSTR pk_ok,        "pkat: PASS (threaded fail-closed KAT gate)",13,10
CSTR pk_bad,       "pkat: FAIL",13,10
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
CSTR st_pass_a2v,  "  [PASS] argon2id conformance vectors (4x, incl. single-lane)",13,10
.data
; mutable: the '#0' digit is patched to the failing vector index before printing
st_fail_a2v      db "  [FAIL] argon2id conformance vector #0",13,10
st_fail_a2v_len  equ $ - st_fail_a2v
.const
CSTR st_pass_pw,   "  [PASS] password policy (length + class rules)",13,10
CSTR st_fail_pw,   "  [FAIL] password policy",13,10
CSTR st_pass_gen,  "  [PASS] pwgen  (alphabet + length, no bias tail)",13,10
CSTR st_fail_gen,  "  [FAIL] pwgen",13,10
CSTR st_pass_gx,   "  [PASS] pwgen_ex  (random/passphrase/pronounce/pin/hex + entropy)",13,10
CSTR st_fail_gx,   "  [FAIL] pwgen_ex",13,10
CSTR st_pass_vlt,  "  [PASS] vault seal/open  (Argon2id KDF -> KCV -> GCM round-trip)",13,10
CSTR st_fail_vlt,  "  [FAIL] vault seal/open",13,10
CSTR st_pass_mac,  "  [PASS] hmac-sha1  (RFC 2202 test case 1)",13,10
CSTR st_fail_mac,  "  [FAIL] hmac-sha1",13,10
CSTR st_pass_b32,  "  [PASS] base32 decode  (RFC 4648)",13,10
CSTR st_fail_b32,  "  [FAIL] base32 decode",13,10
CSTR st_pass_otp,  "  [PASS] totp/hotp  (RFC 4226 vector)",13,10
CSTR st_fail_otp,  "  [FAIL] totp/hotp",13,10
CSTR st_pass_o16,  "  [PASS] base32->hotp path  (16-char key, high bytes)",13,10
CSTR st_fail_o16,  "  [FAIL] base32->hotp path",13,10
CSTR st_pass_mac2, "  [PASS] hmac-sha1 short key  (RFC 2202 case 2)",13,10
CSTR st_fail_mac2, "  [FAIL] hmac-sha1 short key",13,10
CSTR st_pass_ctm,  "  [PASS] constant-time compare  (ct_memcmp + wstr_eq edges)",13,10
CSTR st_fail_ctm,  "  [FAIL] constant-time compare",13,10

; ct_memcmp KAT buffers: b == a; c differs in byte 0; d differs in byte 15
ctm_a       db 010h,020h,030h,040h,050h,060h,070h,080h
            db 090h,0a0h,0b0h,0c0h,0d0h,0e0h,0f0h,0ffh
ctm_b       db 010h,020h,030h,040h,050h,060h,070h,080h
            db 090h,0a0h,0b0h,0c0h,0d0h,0e0h,0f0h,0ffh
ctm_c       db 011h,020h,030h,040h,050h,060h,070h,080h
            db 090h,0a0h,0b0h,0c0h,0d0h,0e0h,0f0h,0ffh
ctm_d       db 010h,020h,030h,040h,050h,060h,070h,080h
            db 090h,0a0h,0b0h,0c0h,0d0h,0e0h,0f0h,0feh
; gui_wstr_eq edges: equal / differ-last / proper prefix (both directions)
align 2
ws_a        dw 'v','o','r','d','r',0
ws_b        dw 'v','o','r','d','r',0
ws_c        dw 'v','o','r','d','R',0
ws_d        dw 'v','o','r',0

; RFC 2202 HMAC-SHA1 test case 1: key = 0x0b x20, data = "Hi There"
hm_key      db 020 dup (0bh)             ; (only first 20 used)
hm_msg      db "Hi There"
hm_exp      db 0b6h,017h,031h,086h,055h,005h,072h,064h,0e2h,08bh,0c0h,0b6h
            db 0fbh,037h,08ch,08eh,0f1h,046h,0beh,000h
; base32("Hello") = "JBSWY3DP" -> 48 65 6C 6C 6F
b32_src     db "JBSWY3DP"
b32_exp     db "Hello"
; RFC 4226 HOTP: secret "12345678901234567890", counter 1 -> "287082"
otp_key     db "12345678901234567890"
otp_exp     db "287082"
; full base32->hotp path: base32("JBSWY3DPEHPK3PXP") = "Hello!"+deadbeef (10 bytes);
; HOTP at counter 1 = 996554 (exercises a short key with high bytes end-to-end)
otp16_b32   db "JBSWY3DPEHPK3PXP"
otp16_dec   db 048h,065h,06ch,06ch,06fh,021h,0deh,0adh,0beh,0efh
otp16_exp   db "996554"
; RFC 2202 HMAC-SHA1 case 2: key="Jefe" (4 bytes), msg="what do ya want for nothing?"
hm2_key     db "Jefe"
hm2_msg     db "what do ya want for nothing?"
hm2_exp     db 0efh,0fch,0dfh,06ah,0e5h,0ebh,02fh,0a2h,0d2h,074h
            db 016h,0d5h,0f1h,084h,0dfh,09ch,025h,09ah,07ch,079h

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
; Argon2id conformance vectors, cross-checked against the argon2 reference
; (argon2.low_level.lib.argon2_ctx, type Argon2id, version 0x13).  k1/k2 are
; single-lane (p=1); k4 is p=4 with a large enough segment to fill during
; pass0/slice0.  All exercise the corrected data-independent address indexing.
k1_pwd  db 063h,06fh,072h,072h,065h,063h,074h,068h,06fh,072h,073h,065h
k1_salt db 073h,061h,06ch,074h,073h,061h,06ch,074h,073h,061h,06ch,074h,031h,032h,033h,034h
k1_sec  db 0aah,0bbh,0cch,0ddh
k1_ad   db 011h,022h,033h
k1_exp  db 08fh,0aah,01dh,01dh,0ebh,0a7h,0a7h,0eeh,0c0h,0a0h,02eh,019h,050h,09eh,021h,098h
        db 088h,05eh,073h,0e6h,062h,05fh,06ch,0cbh,06ch,055h,05ah,07ah,065h,074h,07fh,03ah
k2_pwd  db 005h,005h,005h,005h,005h,005h,005h,005h,005h,005h,005h,005h,005h,005h,005h,005h,005h,005h,005h,005h
k2_salt db 006h,006h,006h,006h,006h,006h,006h,006h,006h,006h,006h,006h,006h,006h,006h,006h
k2_sec  db 007h,007h,007h,007h,007h,007h,007h,007h
k2_ad   db 008h,008h,008h,008h,008h,008h,008h,008h,008h,008h,008h,008h
k2_exp  db 05ah,038h,022h,0f3h,06eh,071h,0e4h,0deh,089h,060h,0ebh,063h,019h,0a8h,05bh,054h
        db 0f6h,036h,053h,085h,0fbh,057h,066h,0c3h,010h,05eh,030h,0bch,036h,0bch,0bch,055h
k3_pwd  db 070h,077h
k3_salt db 030h,031h,032h,033h,034h,035h,036h,037h,038h,039h,061h,062h,063h,064h,065h,066h
k3_sec  db 099h
k3_ad   db 042h,042h
k3_exp  db 04fh,07bh,07ah,06dh,0f4h,0bch,0dah,05ch,083h,0dch,094h,0f1h,047h,0b6h,04fh,06fh
        db 089h,02fh,021h,04dh,06ah,035h,002h,048h,072h,038h,0e0h,0f8h,09ch,087h,00fh,0a7h
        db 0f8h,056h,0b4h,0eah,007h,05fh,0d1h,02bh,0c9h,017h,012h,06ch,0b4h,05dh,053h,036h
        db 03fh,04dh,0cch,04ch,0e4h,074h,02bh,03fh,098h,0bfh,057h,097h,00fh,0c9h,097h,00ah
k4_pwd  db 0a0h,0a1h,0a2h
k4_salt db 04eh,061h,043h,06ch,04eh,061h,043h,06ch,04eh,061h,043h,06ch,04eh,061h,043h,06ch
k4_exp  db 034h,07bh,096h,05eh,068h,072h,091h,0f2h,0d1h,0c8h,09fh,046h,0bch,020h,04eh,0d0h
        db 0dbh,097h,050h,0a0h,0c3h,002h,0c6h,033h,0a6h,005h,047h,03ch,0a4h,06ch,055h,05fh
align 8
a2_vecs label A2VEC
    A2VEC { 3, 32,  1, 32, k1_pwd, 12, 16, k1_salt, k1_sec, 4, 3,  k1_ad, k1_exp }
    A2VEC { 1, 64,  1, 32, k2_pwd, 20, 16, k2_salt, k2_sec, 8, 12, k2_ad, k2_exp }
    A2VEC { 2, 128, 2, 64, k3_pwd,  2, 16, k3_salt, k3_sec, 1, 2,  k3_ad, k3_exp }
    A2VEC { 3, 256, 4, 32, k4_pwd,  3, 16, k4_salt, 0,      0, 0,  0,     k4_exp }
A2VEC_N equ 4
; BLAKE2b-512("abc") - RFC 7693 Appendix A
b2b_abc_exp db 0bah,080h,0a5h,03fh,098h,01ch,04dh,00dh,06ah,027h,097h,0b6h,09fh,012h,0f6h,0e9h
            db 04ch,021h,02fh,014h,068h,05ah,0c4h,0b7h,04bh,012h,0bbh,06fh,0dbh,0ffh,0a2h,0d1h
            db 07dh,087h,0c5h,039h,02ah,0abh,079h,02dh,0c2h,052h,0d5h,0deh,045h,033h,0cch,095h
            db 018h,0d3h,08ah,0a8h,0dbh,0f1h,092h,05ah,0b9h,023h,086h,0edh,0d4h,000h,099h,023h
; NIST SP800-38D AES-256-GCM: key=0(32), iv=0(12), aad=none, pt=16 zero bytes
gcm_ct_exp  db 0ceh,0a7h,040h,03dh,04dh,060h,06bh,06eh,007h,04eh,0c5h,0d3h,0bah,0f3h,09dh,018h
gcm_tag_exp db 0d0h,0d1h,0c8h,0a7h,099h,099h,06bh,0f0h,026h,05bh,098h,0b5h,0d4h,08ah,0b9h,019h

.data?
align 8
g_pkat_cs       db 40 dup (?)        ; CRITICAL_SECTION (x64 = 40 bytes)
g_pkat_res      dd 8 dup (?)         ; per-thread PASS(0)/FAIL(1) slot
g_pkat_h        dq 8 dup (?)         ; worker thread handles
g_pkat_n        dd ?                 ; worker count = min(cores, PKAT_MAX)
g_pkat_si       db 48 dup (?)        ; SYSTEM_INFO (dwNumberOfProcessors at +32)
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
a2_vout         db 64 dup (?)        ; conformance-vector output (up to 64 bytes)
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
hmac_out        db 20 dup (?)
b32_out         db 16 dup (?)
otp_out         db 8 dup (?)
g_st_verbose    dd ?

.code

.data?
align 4
public g_kat_n
g_kat_n         dd ?                 ; known-answer tests passed in the last run
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

; STPASS msg, len - report a PASSED known-answer test.  Prints like STPRINT when
; verbose, and ALWAYS counts, so g_kat_n is the number of KATs this build actually
; ran rather than a figure someone has to remember to update.  The home panel
; shows that count; hardcoding it there would have gone stale the first time a
; vector was added.
STPASS macro msg, len
    inc     dword ptr [g_kat_n]
    STPRINT msg, len
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
    ; preserve callee-saved registers used as scratch below (r12/r13/r15).  These
    ; slots sit above the 32-byte callee shadow and are untouched by any call here.
    mov     qword ptr [rbp-48], r12
    mov     qword ptr [rbp-56], r13
    mov     qword ptr [rbp-64], r15
    ; [rbp-24] = failure count
    mov     dword ptr [g_kat_n], 0
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
    STPASS st_pass_sha, st_pass_sha_len
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
    STPASS st_pass_gcm, st_pass_gcm_len
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
    STPASS st_pass_aad, st_pass_aad_len
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
    STPASS st_pass_ip, st_pass_ip_len
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
    STPASS st_pass_b2b, st_pass_b2b_len
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
    STPASS st_pass_ac, st_pass_ac_len
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
    STPASS st_pass_a2, st_pass_a2_len
    jmp     st_after_a2
st_a2_fail:
    STPRINT st_fail_a2, st_fail_a2_len
    inc     qword ptr [rbp-24]
st_after_a2:

    ; ---- Argon2id conformance vectors (table-driven) ------------------------
    ; cursor + index live in stack locals ([rbp-32]/[rbp-40]) because
    ; argon2id_hash does not preserve r10-r15 across the call.
    lea     rax, [a2_vecs]
    mov     qword ptr [rbp-32], rax
    mov     qword ptr [rbp-40], 0
st_a2v_loop:
    cmp     qword ptr [rbp-40], A2VEC_N
    jae     st_a2v_ok
    mov     r10, qword ptr [rbp-32]
    lea     r11, [a2_req]
    mov     eax, dword ptr [r10].A2VEC.v_t
    mov     dword ptr [r11].ARGON2REQ.t_cost, eax
    mov     eax, dword ptr [r10].A2VEC.v_m
    mov     dword ptr [r11].ARGON2REQ.m_cost, eax
    mov     eax, dword ptr [r10].A2VEC.v_p
    mov     dword ptr [r11].ARGON2REQ.lanes, eax
    mov     eax, dword ptr [r10].A2VEC.v_outlen
    mov     dword ptr [r11].ARGON2REQ.outlen, eax
    mov     dword ptr [r11].ARGON2REQ.version, 13h
    mov     dword ptr [r11].ARGON2REQ.atype, 2
    mov     rax, qword ptr [r10].A2VEC.v_pwd
    mov     qword ptr [r11].ARGON2REQ.pwd, rax
    mov     eax, dword ptr [r10].A2VEC.v_pwdlen
    mov     dword ptr [r11].ARGON2REQ.pwdlen, eax
    mov     rax, qword ptr [r10].A2VEC.v_salt
    mov     qword ptr [r11].ARGON2REQ.salt, rax
    mov     eax, dword ptr [r10].A2VEC.v_saltlen
    mov     dword ptr [r11].ARGON2REQ.saltlen, eax
    mov     rax, qword ptr [r10].A2VEC.v_sec
    mov     qword ptr [r11].ARGON2REQ.secret, rax
    mov     eax, dword ptr [r10].A2VEC.v_seclen
    mov     dword ptr [r11].ARGON2REQ.secretlen, eax
    mov     rax, qword ptr [r10].A2VEC.v_ad
    mov     qword ptr [r11].ARGON2REQ.ad, rax
    mov     eax, dword ptr [r10].A2VEC.v_adlen
    mov     dword ptr [r11].ARGON2REQ.adlen, eax
    lea     rax, [a2_vout]
    mov     qword ptr [r11].ARGON2REQ.outp, rax
    lea     rcx, [a2_req]
    call    argon2id_hash
    test    eax, eax
    jnz     st_a2v_fail
    mov     r10, qword ptr [rbp-32]                 ; reload (argon2 clobbers r10)
    lea     rcx, [a2_vout]
    mov     rdx, qword ptr [r10].A2VEC.v_exp
    mov     r8d, dword ptr [r10].A2VEC.v_outlen
    call    ct_memcmp
    test    eax, eax
    jnz     st_a2v_fail
    add     qword ptr [rbp-32], sizeof A2VEC
    inc     qword ptr [rbp-40]
    jmp     st_a2v_loop
st_a2v_fail:
    mov     eax, dword ptr [rbp-40]                 ; patch the failing index into the message
    add     eax, '0'
    mov     byte ptr [st_fail_a2v + 38], al
    STPRINT st_fail_a2v, st_fail_a2v_len
    inc     qword ptr [rbp-24]
    jmp     st_after_a2v
st_a2v_ok:
    STPASS st_pass_a2v, st_pass_a2v_len
st_after_a2v:

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
    STPASS st_pass_pw, st_pass_pw_len
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
    STPASS st_pass_gen, st_pass_gen_len
    jmp     st_after_gen
st_gen_fail:
    STPRINT st_fail_gen, st_fail_gen_len
    inc     qword ptr [rbp-24]
st_after_gen:

    ; ---- pwgen_ex: each style yields printable output + nonzero entropy ------
    lea     rcx, [pw_out]                       ; RANDOM, all classes, no ambiguous
    mov     edx, 20
    mov     r8d, PWS_RANDOM
    mov     r9d, 15 or PWO_NOAMBIG
    mov     dword ptr [g_pwgen_outcap], 64      ; E16: pw_out capacity
    call    pwgen_ex
    cmp     eax, 90                             ; 20 chars * ~5.9 bits ~= 118, floor >= 90
    jb      st_gx_fail
    lea     rcx, [pw_out]                       ; PASSPHRASE, 4 words, capitalized + dashes
    mov     edx, 4
    mov     r8d, PWS_PASSPHRASE
    mov     r9d, PWO_CAP or PWO_DASH
    mov     dword ptr [g_pwgen_outcap], 64      ; E16: pw_out capacity
    call    pwgen_ex
    cmp     eax, 32                             ; 4 words * 8 bits
    jne     st_gx_fail
    lea     rcx, [pw_out]                       ; PRONOUNCE, 12 chars
    mov     edx, 12
    mov     r8d, PWS_PRONOUNCE
    mov     r9d, PWO_CAP
    mov     dword ptr [g_pwgen_outcap], 64      ; E16: pw_out capacity
    call    pwgen_ex
    test    eax, eax
    jz      st_gx_fail
    lea     rcx, [pw_out]                       ; PIN, 6 digits
    mov     edx, 6
    mov     r8d, PWS_PIN
    xor     r9d, r9d
    mov     dword ptr [g_pwgen_outcap], 64      ; E16: pw_out capacity
    call    pwgen_ex
    cmp     eax, 19                             ; 6 * log2(10) = 19.9 -> 19
    jne     st_gx_fail
    lea     r10, [pw_out]                       ; and all-digits
    mov     ecx, 6
st_gx_pin:
    movzx   eax, byte ptr [r10]
    cmp     al, '0'
    jb      st_gx_fail
    cmp     al, '9'
    ja      st_gx_fail
    inc     r10
    dec     ecx
    jnz     st_gx_pin
    lea     rcx, [pw_out]                       ; HEX, 16 chars
    mov     edx, 16
    mov     r8d, PWS_HEX
    xor     r9d, r9d
    mov     dword ptr [g_pwgen_outcap], 64      ; E16: pw_out capacity
    call    pwgen_ex
    cmp     eax, 64                             ; 16 * 4 bits
    jne     st_gx_fail
    STPASS st_pass_gx, st_pass_gx_len
    jmp     st_after_gx
st_gx_fail:
    STPRINT st_fail_gx, st_fail_gx_len
    inc     qword ptr [rbp-24]
st_after_gx:

    ; ---- vault seal/open (Argon2id -> KCV -> AES-256-GCM, in memory) ---------
    call    vault_selftest
    test    eax, eax
    jnz     st_vlt_fail
    STPASS st_pass_vlt, st_pass_vlt_len
    jmp     st_after_vlt
st_vlt_fail:
    STPRINT st_fail_vlt, st_fail_vlt_len
    inc     qword ptr [rbp-24]
st_after_vlt:

    ; ---- HMAC-SHA1 (RFC 2202 test case 1) -----------------------------------
    WINCALL hmac_sha1, addr hm_key, 20, addr hm_msg, 8, addr hmac_out
    lea     rcx, [hmac_out]
    lea     rdx, [hm_exp]
    mov     r8, 20
    call    ct_memcmp
    test    eax, eax
    jnz     st_mac_fail
    STPASS st_pass_mac, st_pass_mac_len
    jmp     st_after_mac
st_mac_fail:
    STPRINT st_fail_mac, st_fail_mac_len
    inc     qword ptr [rbp-24]
st_after_mac:

    ; ---- base32 decode ("JBSWY3DP" -> "Hello") ------------------------------
    WINCALL base32_decode, addr b32_src, 8, addr b32_out, 16
    cmp     eax, 5
    jne     st_b32_fail
    lea     rcx, [b32_out]
    lea     rdx, [b32_exp]
    mov     r8, 5
    call    ct_memcmp
    test    eax, eax
    jnz     st_b32_fail
    STPASS st_pass_b32, st_pass_b32_len
    jmp     st_after_b32
st_b32_fail:
    STPRINT st_fail_b32, st_fail_b32_len
    inc     qword ptr [rbp-24]
st_after_b32:

    ; ---- HOTP (RFC 4226: secret, counter 1 -> "287082") ---------------------
    WINCALL hotp, addr otp_key, 20, 1, addr otp_out
    lea     rcx, [otp_out]
    lea     rdx, [otp_exp]
    mov     r8, 6
    call    ct_memcmp
    test    eax, eax
    jnz     st_otp_fail
    STPASS st_pass_otp, st_pass_otp_len
    jmp     st_after_otp
st_otp_fail:
    STPRINT st_fail_otp, st_fail_otp_len
    inc     qword ptr [rbp-24]
st_after_otp:

    ; ---- HMAC-SHA1 short key (RFC 2202 case 2, "Jefe" = 4 bytes) -------------
    WINCALL hmac_sha1, addr hm2_key, 4, addr hm2_msg, 28, addr hmac_out
    lea     rcx, [hmac_out]
    lea     rdx, [hm2_exp]
    mov     r8, 20
    call    ct_memcmp
    test    eax, eax
    jnz     st_mac2_fail
    STPASS st_pass_mac2, st_pass_mac2_len
    jmp     st_after_mac2
st_mac2_fail:
    STPRINT st_fail_mac2, st_fail_mac2_len
    inc     qword ptr [rbp-24]
st_after_mac2:

    ; ---- full base32 -> hotp path (16-char base32 -> 10-byte key w/ high bytes,
    ;      fixed counter 1 -> 996554): exercises decode + short-key HMAC end-to-end
    WINCALL base32_decode, addr otp16_b32, 16, addr b32_out, 16
    cmp     eax, 10
    jne     st_o16_fail
    lea     rcx, [b32_out]
    lea     rdx, [otp16_dec]
    mov     r8, 10
    call    ct_memcmp
    test    eax, eax
    jnz     st_o16_fail
    WINCALL hotp, addr b32_out, 10, 1, addr otp_out
    lea     rcx, [otp_out]
    lea     rdx, [otp16_exp]
    mov     r8, 6
    call    ct_memcmp
    test    eax, eax
    jnz     st_o16_fail
    STPASS st_pass_o16, st_pass_o16_len
    jmp     st_after_o16
st_o16_fail:
    STPRINT st_fail_o16, st_fail_o16_len
    inc     qword ptr [rbp-24]
st_after_o16:

    ; ---- constant-time compare primitives -----------------------------------
    ; ct_memcmp: equal, differ-first, differ-last, zero-length
    lea     rcx, [ctm_a]
    lea     rdx, [ctm_b]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     st_ctm_fail                       ; equal buffers must give 0
    lea     rcx, [ctm_a]
    lea     rdx, [ctm_c]
    mov     r8, 16
    call    ct_memcmp
    cmp     eax, 1
    jne     st_ctm_fail                       ; first-byte difference -> exactly 1
    lea     rcx, [ctm_a]
    lea     rdx, [ctm_d]
    mov     r8, 16
    call    ct_memcmp
    cmp     eax, 1
    jne     st_ctm_fail                       ; last-byte difference -> exactly 1
    lea     rcx, [ctm_a]
    lea     rdx, [ctm_c]
    xor     r8d, r8d
    call    ct_memcmp
    test    eax, eax
    jnz     st_ctm_fail                       ; zero length -> equal
    ; gui_wstr_eq: equal, differ-last, prefix (both directions)
    lea     rcx, [ws_a]
    lea     rdx, [ws_b]
    call    gui_wstr_eq
    cmp     eax, 1
    jne     st_ctm_fail
    lea     rcx, [ws_a]
    lea     rdx, [ws_c]
    call    gui_wstr_eq
    test    eax, eax
    jnz     st_ctm_fail
    lea     rcx, [ws_a]
    lea     rdx, [ws_d]
    call    gui_wstr_eq
    test    eax, eax
    jnz     st_ctm_fail                       ; longer vs prefix -> different
    lea     rcx, [ws_d]
    lea     rdx, [ws_a]
    call    gui_wstr_eq
    test    eax, eax
    jnz     st_ctm_fail                       ; prefix vs longer -> different
    STPASS st_pass_ctm, st_pass_ctm_len
    jmp     st_after_ctm
st_ctm_fail:
    STPRINT st_fail_ctm, st_fail_ctm_len
    inc     qword ptr [rbp-24]
st_after_ctm:
    ; scrub the KAT's test-password state.  run_selftest is the startup gate
    ; (wstart runs it on every launch), so it must not leave a stale constant
    ; password + non-zero length in g_cfg_pass for the unlock flow to inherit.
    lea     rcx, [g_cfg_pass]
    mov     edx, MAX_PASSWORD_BYTES+1
    call    secure_zero
    mov     dword ptr [g_cfg_passlen], 0

    mov     rax, qword ptr [rbp-24]
    mov     r12, qword ptr [rbp-48]     ; restore callee-saved registers
    mov     r13, qword ptr [rbp-56]
    mov     r15, qword ptr [rbp-64]
    FRAME_EPILOG
    ret
run_selftest endp

PKAT_MAX    equ 4
PKAT_ITERS  equ 2000

; =============================================================================
; pkat_worker(rcx = slot) - worker thread body for the parallel KAT gate.  Runs
;   a SHA-256 known-answer test PKAT_ITERS times; on all-pass, clears its result
;   slot to 0 (PASS).  A RAW frame (no FRAME_PROLOG) - it must not touch the
;   process-global software shadow stack outside the critical section.  The KAT
;   itself (sha256_hash uses FRAME_PROLOG) runs under g_pkat_cs, so only one
;   thread is ever inside shadow-stack-using code at a time: correct LIFO use,
;   no race.  (True parallel KAT compute awaits a per-thread shadow stack; this
;   is the fail-closed thread-pool gate machinery, verified end to end.)
; =============================================================================
pkat_worker proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96                          ; raw frame: shadow + a 32-byte out buf
    mov     qword ptr [rbp-8], rcx           ; slot
    mov     qword ptr [rbp-16], PKAT_ITERS
pw_loop:
    cmp     qword ptr [rbp-16], 0
    je      pw_pass
    WINCALL EnterCriticalSection, addr g_pkat_cs
    lea     rcx, [st_abc]                    ; sha256("abc") -> [rbp-56]
    mov     rdx, 3
    lea     r8, [rbp-56]
    call    sha256_hash
    WINCALL LeaveCriticalSection, addr g_pkat_cs
    lea     r10, [rbp-56]                    ; compare to the known digest
    lea     r11, [sha_abc_exp]
    xor     r9, r9
pw_cmp:
    mov     al, byte ptr [r10+r9]
    cmp     al, byte ptr [r11+r9]
    jne     pw_done                          ; mismatch -> leave slot FAIL
    inc     r9
    cmp     r9, 32
    jb      pw_cmp
    dec     qword ptr [rbp-16]
    jmp     pw_loop
pw_pass:
    mov     rcx, qword ptr [rbp-8]           ; all iterations passed -> PASS
    lea     r10, [g_pkat_res]
    mov     dword ptr [r10+rcx*4], 0
pw_done:
    xor     eax, eax
    add     rsp, 96
    pop     rbp
    ret
pkat_worker endp

; =============================================================================
; cmd_pkat - parallel KAT gate: spawn min(cores,PKAT_MAX) worker
;   threads, each running a KAT loop; the gate FAILS CLOSED - every result slot
;   starts FAIL and only an all-pass worker clears it, and a watchdog-bounded
;   join (10 s) treats a hung/never-reporting worker as failure.  exit 0 = pass.
; =============================================================================
LANDING_PAD
public cmd_pkat
cmd_pkat proc frame
    FRAME_PROLOG 96
    ; [rbp-24] = loop counter  [rbp-32] = wait result
    WINCALL GetSystemInfo, addr g_pkat_si
    mov     eax, dword ptr [g_pkat_si+32]        ; dwNumberOfProcessors
    test    eax, eax
    jnz     @F
    mov     eax, 1
@@: cmp     eax, PKAT_MAX                        ; clamp to PKAT_MAX
    jbe     @F
    mov     eax, PKAT_MAX
@@: mov     dword ptr [g_pkat_n], eax
    WINCALL InitializeCriticalSection, addr g_pkat_cs
    ; every result slot starts FAIL(1) - fail closed
    mov     qword ptr [rbp-24], 0
pk_init:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_pkat_n]
    jae     pk_spawn
    lea     r10, [g_pkat_res]
    mov     dword ptr [r10+rax*4], 1
    inc     qword ptr [rbp-24]
    jmp     pk_init
pk_spawn:
    mov     qword ptr [rbp-24], 0
pk_spawn_loop:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_pkat_n]
    jae     pk_wait
    WINCALL CreateThread, 0, 0, addr pkat_worker, qword ptr [rbp-24], 0, 0
    mov     r10, qword ptr [rbp-24]
    lea     r11, [g_pkat_h]
    mov     qword ptr [r11+r10*8], rax
    inc     qword ptr [rbp-24]
    jmp     pk_spawn_loop
pk_wait:
    ; watchdog-bounded join: WAIT_ALL, 10 s.  A timeout (or any non-signalled
    ; return) is a failure - a worker that hung never cleared its slot anyway.
    WINCALL WaitForMultipleObjects, dword ptr [g_pkat_n], addr g_pkat_h, 1, 10000
    mov     dword ptr [rbp-32], eax
    mov     qword ptr [rbp-24], 0
pk_close:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_pkat_n]
    jae     pk_eval
    mov     r10, qword ptr [rbp-24]
    lea     r11, [g_pkat_h]
    WINCALL CloseHandle, qword ptr [r11+r10*8]
    inc     qword ptr [rbp-24]
    jmp     pk_close
pk_eval:
    ; only destroy the CS once EVERY worker finished (WAIT_OBJECT_0).  On a timeout
    ; a worker may still be alive and could enter a deleted CS (UB), so leak it -
    ; the process exits (ExitProcess) immediately after pkat returns.
    cmp     dword ptr [rbp-32], 0               ; WAIT_OBJECT_0 = all signalled
    jne     pk_fail                             ; timeout / abandoned -> fail closed
    WINCALL DeleteCriticalSection, addr g_pkat_cs
    mov     qword ptr [rbp-24], 0               ; every slot must be PASS(0)
pk_sum:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_pkat_n]
    jae     pk_ok_ret
    lea     r10, [g_pkat_res]
    cmp     dword ptr [r10+rax*4], 0
    jne     pk_fail
    inc     qword ptr [rbp-24]
    jmp     pk_sum
pk_ok_ret:
    lea     rcx, [pk_ok]
    mov     edx, pk_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
pk_fail:
    lea     rcx, [pk_bad]
    mov     edx, pk_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_pkat endp

; =============================================================================
; cmd_katreport - EXTERNAL-AUDIT crypto proof mode.  Runs a fixed, deterministic
;   battery of the crypto primitives over public/known inputs and prints each
;   result as "<label> [counter] <lowercase-hex>\n".  The inputs are baked in
;   (no vault, password, or real secret ever touches the command line - these are
;   published RFC/NIST test vectors and fixed patterns), so `vordr kat-report`
;   yields byte-identical output on any machine.  tests/verify_crypto.py holds the
;   SAME inputs, recomputes each expected value with an INDEPENDENT reference
;   (Python hashlib/hmac + a self-validating pure-Python AES-256-GCM) and against
;   the official published vectors, then diffs vordr's output.  That makes the
;   crypto correctness externally reproducible - an auditor runs both and checks.
; =============================================================================
.data
; ---- labels (each ends in a space; no CRLF) --------------------------------
CSTR krl_sha_empty,  "sha256/empty "
CSTR krl_sha_abc,    "sha256/abc "
CSTR krl_sha_fips2,  "sha256/fips2 "
CSTR krl_sha_a1k,    "sha256/a1000 "
CSTR krl_sha_a55,    "sha256/a55 "
CSTR krl_sha_a56,    "sha256/a56 "
CSTR krl_sha_a63,    "sha256/a63 "
CSTR krl_sha_a64,    "sha256/a64 "
CSTR krl_sha_a65,    "sha256/a65 "
CSTR krl_sha_a127,   "sha256/a127 "
CSTR krl_sha_a128,   "sha256/a128 "
CSTR krl_b2_a127,    "blake2b512/a127 "
CSTR krl_b2_a128,    "blake2b512/a128 "
CSTR krl_b2_a129,    "blake2b512/a129 "
CSTR krl_b2_empty,   "blake2b512/empty "
CSTR krl_b2_abc,     "blake2b512/abc "
CSTR krl_b2_fox,     "blake2b512/fox "
CSTR krl_hm1,        "hmac-sha1/rfc2202-1 "
CSTR krl_hm2,        "hmac-sha1/rfc2202-2 "
CSTR krl_hmc,        "hmac-sha1/custom "
CSTR krl_gcm_zct,    "gcm256/zero/ct "
CSTR krl_gcm_ztag,   "gcm256/zero/tag "
CSTR krl_gcm_act,    "gcm256/aad/ct "
CSTR krl_gcm_atag,   "gcm256/aad/tag "
CSTR krl_gcm_vct,    "gcm256/vec/ct "
CSTR krl_gcm_vtag,   "gcm256/vec/tag "
CSTR krl_gcm_ept,    "gcm256/emptypt/tag "
CSTR krl_hotp,       "hotp/rfc4226 "
CSTR krl_totp,       "totp/rfc6238 "
CSTR krl_b32h,       "base32/hello "
CSTR krl_b32o,       "base32/otp16 "
CSTR krl_a2,         "argon2id/rfc9106 "
; ---- fixed inputs ----------------------------------------------------------
kr_fips2    db "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
kr_fips2_len equ $ - kr_fips2
kr_fox      db "The quick brown fox jumps over the lazy dog"
kr_fox_len  equ $ - kr_fox
kr_a1k      db 1000 dup('a')
kr_hkey     db "vordr-key"
kr_hkey_len equ $ - kr_hkey
kr_hmsg     db "differential test vector"
kr_hmsg_len equ $ - kr_hmsg
kr_zero32   db 32 dup(0)
kr_zero12   db 12 dup(0)
kr_iota16   db 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
kr_key32    db 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
kr_iv12     db 0,1,2,3,4,5,6,7,8,9,10,11
kr_aad8     db 0a0h,0a1h,0a2h,0a3h,0a4h,0a5h,0a6h,0a7h
kr_pt20     db 10h,11h,12h,13h,14h,15h,16h,17h,18h,19h,1ah,1bh,1ch,1dh,1eh,1fh,20h,21h,22h,23h
align 8
kr_totp_ctrs dq 1, 37037036, 41152263, 66666666   ; T=59,1111111109,1234567890,2000000000 (/30)
kr_sp       db ' '
kr_nl       db 10

.data?
kr_o64      db 64 dup(?)
kr_ct       db 32 dup(?)
kr_tag      db 16 dup(?)
kr_otp      db 8 dup(?)

.code
; KEMIT lbl, buf, blen - print "<lbl><hex(buf[0..blen))>\n"
KEMIT macro lbl, buf, blen
    lea     rcx, [lbl]
    mov     edx, lbl&_len
    call    print_a
    lea     rcx, [buf]
    mov     edx, blen
    call    print_hex
    lea     rcx, [kr_nl]
    mov     edx, 1
    call    print_a
endm

; KSHA_N lbl, n - emit SHA-256 of the first n bytes of kr_a1k ('a'*n)
KSHA_N macro lbl, n
    lea     rcx, [kr_a1k]
    mov     rdx, n
    lea     r8, [kr_o64]
    call    sha256_hash
    KEMIT   lbl, kr_o64, 32
endm

; KB2_N lbl, n - emit BLAKE2b-512 of the first n bytes of kr_a1k ('a'*n)
KB2_N macro lbl, n
    lea     rcx, [kr_a1k]
    mov     rdx, n
    lea     r8, [kr_o64]
    mov     r9, 64
    call    blake2b_hash
    KEMIT   lbl, kr_o64, 64
endm

LANDING_PAD
public cmd_katreport
cmd_katreport proc frame
    FRAME_PROLOG 96
    ; locals: [rbp-32] counter/scratch (q), [rbp-40] loop index (q), [rbp-48] declen (d)

    ; ---- SHA-256 ----
    lea     rcx, [st_abc]
    xor     edx, edx
    lea     r8, [kr_o64]
    call    sha256_hash
    KEMIT   krl_sha_empty, kr_o64, 32
    lea     rcx, [st_abc]
    mov     rdx, 3
    lea     r8, [kr_o64]
    call    sha256_hash
    KEMIT   krl_sha_abc, kr_o64, 32
    lea     rcx, [kr_fips2]
    mov     rdx, kr_fips2_len
    lea     r8, [kr_o64]
    call    sha256_hash
    KEMIT   krl_sha_fips2, kr_o64, 32
    lea     rcx, [kr_a1k]
    mov     rdx, 1000
    lea     r8, [kr_o64]
    call    sha256_hash
    KEMIT   krl_sha_a1k, kr_o64, 32
    ; SHA-256 block-boundary lengths (block = 64; padding edge at 55/56) over 'a'*N
    KSHA_N  krl_sha_a55, 55
    KSHA_N  krl_sha_a56, 56
    KSHA_N  krl_sha_a63, 63
    KSHA_N  krl_sha_a64, 64
    KSHA_N  krl_sha_a65, 65
    KSHA_N  krl_sha_a127, 127
    KSHA_N  krl_sha_a128, 128

    ; ---- BLAKE2b-512 ----
    lea     rcx, [st_abc]
    xor     edx, edx
    lea     r8, [kr_o64]
    mov     r9, 64
    call    blake2b_hash
    KEMIT   krl_b2_empty, kr_o64, 64
    lea     rcx, [st_abc]
    mov     rdx, 3
    lea     r8, [kr_o64]
    mov     r9, 64
    call    blake2b_hash
    KEMIT   krl_b2_abc, kr_o64, 64
    lea     rcx, [kr_fox]
    mov     rdx, kr_fox_len
    lea     r8, [kr_o64]
    mov     r9, 64
    call    blake2b_hash
    KEMIT   krl_b2_fox, kr_o64, 64
    KB2_N   krl_b2_a127, 127                     ; BLAKE2b block = 128 bytes
    KB2_N   krl_b2_a128, 128
    KB2_N   krl_b2_a129, 129

    ; ---- HMAC-SHA1 ----
    WINCALL hmac_sha1, addr hm_key, 20, addr hm_msg, 8, addr kr_o64
    KEMIT   krl_hm1, kr_o64, 20
    WINCALL hmac_sha1, addr hm2_key, 4, addr hm2_msg, 28, addr kr_o64
    KEMIT   krl_hm2, kr_o64, 20
    WINCALL hmac_sha1, addr kr_hkey, kr_hkey_len, addr kr_hmsg, kr_hmsg_len, addr kr_o64
    KEMIT   krl_hmc, kr_o64, 20

    ; ---- AES-256-GCM: zero vector (NIST SP800-38D all-zero) ----
    lea     rax, [kr_zero32]
    mov     qword ptr [greq].GCMREQ.key, rax
    lea     rax, [kr_zero12]
    mov     qword ptr [greq].GCMREQ.iv, rax
    mov     qword ptr [greq].GCMREQ.aad, 0
    mov     qword ptr [greq].GCMREQ.aadlen, 0
    lea     rax, [kr_zero32]
    mov     qword ptr [greq].GCMREQ.inp, rax
    mov     qword ptr [greq].GCMREQ.inlen, 16
    lea     rax, [kr_ct]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rax, [kr_tag]
    mov     qword ptr [greq].GCMREQ.tag, rax
    lea     rcx, [greq]
    call    gcm_seal
    KEMIT   krl_gcm_zct, kr_ct, 16
    KEMIT   krl_gcm_ztag, kr_tag, 16

    ; ---- AES-256-GCM: key0/iv0, aad=iota16, pt=iota16 ----
    lea     rax, [kr_zero32]
    mov     qword ptr [greq].GCMREQ.key, rax
    lea     rax, [kr_zero12]
    mov     qword ptr [greq].GCMREQ.iv, rax
    lea     rax, [kr_iota16]
    mov     qword ptr [greq].GCMREQ.aad, rax
    mov     qword ptr [greq].GCMREQ.aadlen, 16
    lea     rax, [kr_iota16]
    mov     qword ptr [greq].GCMREQ.inp, rax
    mov     qword ptr [greq].GCMREQ.inlen, 16
    lea     rax, [kr_ct]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rax, [kr_tag]
    mov     qword ptr [greq].GCMREQ.tag, rax
    lea     rcx, [greq]
    call    gcm_seal
    KEMIT   krl_gcm_act, kr_ct, 16
    KEMIT   krl_gcm_atag, kr_tag, 16

    ; ---- AES-256-GCM: key=iota32, iv=iota12, aad=8, pt=20 (partial block) ----
    lea     rax, [kr_key32]
    mov     qword ptr [greq].GCMREQ.key, rax
    lea     rax, [kr_iv12]
    mov     qword ptr [greq].GCMREQ.iv, rax
    lea     rax, [kr_aad8]
    mov     qword ptr [greq].GCMREQ.aad, rax
    mov     qword ptr [greq].GCMREQ.aadlen, 8
    lea     rax, [kr_pt20]
    mov     qword ptr [greq].GCMREQ.inp, rax
    mov     qword ptr [greq].GCMREQ.inlen, 20
    lea     rax, [kr_ct]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rax, [kr_tag]
    mov     qword ptr [greq].GCMREQ.tag, rax
    lea     rcx, [greq]
    call    gcm_seal
    KEMIT   krl_gcm_vct, kr_ct, 20
    KEMIT   krl_gcm_vtag, kr_tag, 16

    ; ---- AES-256-GCM: empty plaintext, aad=iota16 (tag over AAD only) ----
    lea     rax, [kr_zero32]
    mov     qword ptr [greq].GCMREQ.key, rax
    lea     rax, [kr_zero12]
    mov     qword ptr [greq].GCMREQ.iv, rax
    lea     rax, [kr_iota16]
    mov     qword ptr [greq].GCMREQ.aad, rax
    mov     qword ptr [greq].GCMREQ.aadlen, 16
    lea     rax, [kr_zero32]
    mov     qword ptr [greq].GCMREQ.inp, rax
    mov     qword ptr [greq].GCMREQ.inlen, 0
    lea     rax, [kr_ct]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rax, [kr_tag]
    mov     qword ptr [greq].GCMREQ.tag, rax
    lea     rcx, [greq]
    call    gcm_seal
    KEMIT   krl_gcm_ept, kr_tag, 16

    ; ---- HOTP (RFC 4226 secret, counters 0..9) ----
    mov     qword ptr [rbp-32], 0
kr_hotp_lp:
    cmp     qword ptr [rbp-32], 10
    jae     kr_hotp_done
    lea     rcx, [krl_hotp]
    mov     edx, krl_hotp_len
    call    print_a
    mov     rcx, qword ptr [rbp-32]
    call    print_u64
    lea     rcx, [kr_sp]
    mov     edx, 1
    call    print_a
    WINCALL hotp, addr otp_key, 20, qword ptr [rbp-32], addr kr_otp
    lea     rcx, [kr_otp]
    mov     edx, 6
    call    print_hex
    lea     rcx, [kr_nl]
    mov     edx, 1
    call    print_a
    inc     qword ptr [rbp-32]
    jmp     kr_hotp_lp
kr_hotp_done:

    ; ---- TOTP (RFC 6238 time-step -> counter; 6-digit HOTP) ----
    mov     qword ptr [rbp-40], 0
kr_totp_lp:
    cmp     qword ptr [rbp-40], 4
    jae     kr_totp_done
    lea     rcx, [krl_totp]
    mov     edx, krl_totp_len
    call    print_a
    lea     r10, [kr_totp_ctrs]
    mov     rax, qword ptr [rbp-40]
    mov     rax, qword ptr [r10+rax*8]
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax
    call    print_u64
    lea     rcx, [kr_sp]
    mov     edx, 1
    call    print_a
    WINCALL hotp, addr otp_key, 20, qword ptr [rbp-32], addr kr_otp
    lea     rcx, [kr_otp]
    mov     edx, 6
    call    print_hex
    lea     rcx, [kr_nl]
    mov     edx, 1
    call    print_a
    inc     qword ptr [rbp-40]
    jmp     kr_totp_lp
kr_totp_done:

    ; ---- base32 decode ----
    WINCALL base32_decode, addr b32_src, 8, addr kr_o64, 64
    mov     dword ptr [rbp-48], eax
    lea     rcx, [krl_b32h]
    mov     edx, krl_b32h_len
    call    print_a
    lea     rcx, [kr_o64]
    mov     edx, dword ptr [rbp-48]
    call    print_hex
    lea     rcx, [kr_nl]
    mov     edx, 1
    call    print_a
    WINCALL base32_decode, addr otp16_b32, 16, addr kr_o64, 64
    mov     dword ptr [rbp-48], eax
    lea     rcx, [krl_b32o]
    mov     edx, krl_b32o_len
    call    print_a
    lea     rcx, [kr_o64]
    mov     edx, dword ptr [rbp-48]
    call    print_hex
    lea     rcx, [kr_nl]
    mov     edx, 1
    call    print_a

    ; ---- Argon2id (RFC 9106 vector: t=3,m=32,p=4,out=32,secret,ad) ----
    lea     r8, [a2_pwd]
    mov     ecx, 32
kr_a2pwd:
    mov     byte ptr [r8], 1
    inc     r8
    dec     ecx
    jnz     kr_a2pwd
    lea     r8, [a2_salt]
    mov     ecx, 16
kr_a2salt:
    mov     byte ptr [r8], 2
    inc     r8
    dec     ecx
    jnz     kr_a2salt
    lea     r8, [a2_secret]
    mov     ecx, 8
kr_a2sec:
    mov     byte ptr [r8], 3
    inc     r8
    dec     ecx
    jnz     kr_a2sec
    lea     r8, [a2_ad]
    mov     ecx, 12
kr_a2ad:
    mov     byte ptr [r8], 4
    inc     r8
    dec     ecx
    jnz     kr_a2ad
    lea     r8, [a2_req]
    mov     dword ptr [r8].ARGON2REQ.t_cost, 3
    mov     dword ptr [r8].ARGON2REQ.m_cost, 32
    mov     dword ptr [r8].ARGON2REQ.lanes, 4
    mov     dword ptr [r8].ARGON2REQ.outlen, 32
    mov     dword ptr [r8].ARGON2REQ.version, 13h
    mov     dword ptr [r8].ARGON2REQ.atype, 2
    lea     rax, [a2_pwd]
    mov     qword ptr [r8].ARGON2REQ.pwd, rax
    mov     dword ptr [r8].ARGON2REQ.pwdlen, 32
    lea     rax, [a2_salt]
    mov     qword ptr [r8].ARGON2REQ.salt, rax
    mov     dword ptr [r8].ARGON2REQ.saltlen, 16
    lea     rax, [a2_secret]
    mov     qword ptr [r8].ARGON2REQ.secret, rax
    mov     dword ptr [r8].ARGON2REQ.secretlen, 8
    lea     rax, [a2_ad]
    mov     qword ptr [r8].ARGON2REQ.ad, rax
    mov     dword ptr [r8].ARGON2REQ.adlen, 12
    lea     rax, [a2_out]
    mov     qword ptr [r8].ARGON2REQ.outp, rax
    lea     rcx, [a2_req]
    call    argon2id_hash
    KEMIT   krl_a2, a2_out, 32

    xor     eax, eax
    FRAME_EPILOG
    ret
cmd_katreport endp

end
