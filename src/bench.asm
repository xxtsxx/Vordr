; =============================================================================
; bench.asm - micro-benchmark of the crypto core (do_bench, the `bench` verb).
; -----------------------------------------------------------------------------
; Reports AES-256-GCM and SHA-256 streaming throughput over a 64 MiB buffer
; (MiB/s) and one Argon2id derivation at the configured memory cost (ms).
; Timed with QueryPerformanceCounter; integer math only (no CRT).
; =============================================================================

include macros.inc

extern QueryPerformanceCounter:proc
extern QueryPerformanceFrequency:proc
extern mem_alloc:proc
extern mem_free:proc
extern gcm_seal:proc
extern sha256_hash:proc
extern argon2id_hash:proc
extern rng_fill:proc
extern print_a:proc
extern print_u64:proc

externdef g_cfg_m:dword
externdef g_cfg_t:dword

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

BENCH_BYTES     equ 67108864         ; 64 MiB

.const
CSTR b_hd,  "benchmarking the crypto core:",13,10
CSTR b_gcm, "  aes-256-gcm : "
CSTR b_sha, "  sha-256     : "
CSTR b_mibs," MiB/s",13,10
CSTR b_arg, "  argon2id    : "
CSTR b_msm, " ms  (m="
CSTR b_mib, " MiB, t="
CSTR b_tend,")",13,10
CSTR b_oom, "bench: out of memory",13,10
bpw         db "benchmark-password"
bpw_n       equ $ - bpw

.data?
align 16
b_key       db 32 dup (?)
b_iv        db 12 dup (?)
b_tag       db 16 dup (?)
b_sha_out   db 32 dup (?)
b_salt      db 16 dup (?)
b_a2out     db 32 dup (?)
align 8
g_greq      GCMREQ <>
g_areq      ARGON2REQ <>
b_buf       dq ?
qpc_a       dq ?
qpc_b       dq ?
qpc_freq    dq ?

.code

; print_mibps(rcx = byte count) - print (bytes>>20)*freq/(qpc_b-qpc_a) in MiB/s.
print_mibps proc frame
    FRAME_PROLOG 32
    mov     rax, qword ptr [qpc_b]
    sub     rax, qword ptr [qpc_a]
    test    rax, rax
    jnz     pm_ok
    mov     rax, 1
pm_ok:
    mov     r9, rax                         ; ticks
    mov     rax, rcx
    shr     rax, 20                         ; MiB
    mov     r8, qword ptr [qpc_freq]
    mul     r8                              ; rdx:rax = MiB * freq
    div     r9                              ; rax = MiB*freq/ticks
    mov     rcx, rax
    call    print_u64
    FRAME_EPILOG
    ret
print_mibps endp

public do_bench
do_bench proc frame
    FRAME_PROLOG 48
    lea     rcx, [b_hd]
    mov     edx, b_hd_len
    call    print_a
    ; allocate the 64 MiB work buffer (zero-backed by VirtualAlloc)
    mov     rcx, BENCH_BYTES
    call    mem_alloc
    test    rax, rax
    jz      b_oomexit
    mov     qword ptr [b_buf], rax
    lea     rcx, [b_key]
    mov     edx, 32
    call    rng_fill
    lea     rcx, [b_iv]
    mov     edx, 12
    call    rng_fill
    lea     rcx, [qpc_freq]
    call    QueryPerformanceFrequency

    ; ---- AES-256-GCM seal, in place over 64 MiB ----------------------------
    lea     r10, [g_greq]
    lea     rax, [b_key]
    mov     qword ptr [r10].GCMREQ.key, rax
    lea     rax, [b_iv]
    mov     qword ptr [r10].GCMREQ.iv, rax
    mov     qword ptr [r10].GCMREQ.aad, 0
    mov     qword ptr [r10].GCMREQ.aadlen, 0
    mov     rax, qword ptr [b_buf]
    mov     qword ptr [r10].GCMREQ.inp, rax
    mov     qword ptr [r10].GCMREQ.inlen, BENCH_BYTES
    mov     rax, qword ptr [b_buf]
    mov     qword ptr [r10].GCMREQ.outp, rax
    lea     rax, [b_tag]
    mov     qword ptr [r10].GCMREQ.tag, rax
    lea     rcx, [qpc_a]
    call    QueryPerformanceCounter
    lea     rcx, [g_greq]
    call    gcm_seal
    lea     rcx, [qpc_b]
    call    QueryPerformanceCounter
    lea     rcx, [b_gcm]
    mov     edx, b_gcm_len
    call    print_a
    mov     rcx, BENCH_BYTES
    call    print_mibps
    lea     rcx, [b_mibs]
    mov     edx, b_mibs_len
    call    print_a

    ; ---- SHA-256 over 64 MiB ----------------------------------------------
    lea     rcx, [qpc_a]
    call    QueryPerformanceCounter
    mov     rcx, qword ptr [b_buf]
    mov     rdx, BENCH_BYTES
    lea     r8, [b_sha_out]
    call    sha256_hash
    lea     rcx, [qpc_b]
    call    QueryPerformanceCounter
    lea     rcx, [b_sha]
    mov     edx, b_sha_len
    call    print_a
    mov     rcx, BENCH_BYTES
    call    print_mibps
    lea     rcx, [b_mibs]
    mov     edx, b_mibs_len
    call    print_a

    ; free the work buffer before Argon2 grabs its arena
    mov     rcx, qword ptr [b_buf]
    mov     rdx, BENCH_BYTES
    call    mem_free
    mov     qword ptr [b_buf], 0

    ; ---- Argon2id one derivation at the configured memory cost ------------
    lea     rcx, [b_salt]
    mov     edx, 16
    call    rng_fill
    lea     r10, [g_areq]
    mov     eax, dword ptr [g_cfg_t]
    mov     dword ptr [r10].ARGON2REQ.t_cost, eax
    mov     eax, dword ptr [g_cfg_m]
    mov     dword ptr [r10].ARGON2REQ.m_cost, eax
    mov     dword ptr [r10].ARGON2REQ.lanes, 1
    mov     dword ptr [r10].ARGON2REQ.outlen, 32
    mov     dword ptr [r10].ARGON2REQ.version, 19
    mov     dword ptr [r10].ARGON2REQ.atype, 2
    lea     rax, [bpw]
    mov     qword ptr [r10].ARGON2REQ.pwd, rax
    mov     dword ptr [r10].ARGON2REQ.pwdlen, bpw_n
    mov     dword ptr [r10].ARGON2REQ.saltlen, 16
    lea     rax, [b_salt]
    mov     qword ptr [r10].ARGON2REQ.salt, rax
    mov     qword ptr [r10].ARGON2REQ.secret, 0
    mov     dword ptr [r10].ARGON2REQ.secretlen, 0
    mov     dword ptr [r10].ARGON2REQ.adlen, 0
    mov     qword ptr [r10].ARGON2REQ.ad, 0
    lea     rax, [b_a2out]
    mov     qword ptr [r10].ARGON2REQ.outp, rax
    lea     rcx, [qpc_a]
    call    QueryPerformanceCounter
    lea     rcx, [g_areq]
    call    argon2id_hash
    lea     rcx, [qpc_b]
    call    QueryPerformanceCounter
    lea     rcx, [b_arg]
    mov     edx, b_arg_len
    call    print_a
    ; ms = (qpc_b - qpc_a) * 1000 / freq
    mov     rax, qword ptr [qpc_b]
    sub     rax, qword ptr [qpc_a]
    imul    rax, rax, 1000
    xor     edx, edx
    div     qword ptr [qpc_freq]
    mov     rcx, rax
    call    print_u64
    ; " ms  (m=" <MiB> " MiB, t=" <t> ")"
    lea     rcx, [b_msm]
    mov     edx, b_msm_len
    call    print_a
    mov     ecx, dword ptr [g_cfg_m]
    shr     ecx, 10                         ; KiB -> MiB
    call    print_u64
    lea     rcx, [b_mib]
    mov     edx, b_mib_len
    call    print_a
    mov     ecx, dword ptr [g_cfg_t]
    call    print_u64
    lea     rcx, [b_tend]
    mov     edx, b_tend_len
    call    print_a
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
b_oomexit:
    lea     rcx, [b_oom]
    mov     edx, b_oom_len
    call    print_a
    mov     eax, EXIT_OOM
    FRAME_EPILOG
    ret
do_bench endp

end
