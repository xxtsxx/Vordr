; =============================================================================
; redteam.asm - in-tool fault injection for measuring the memory-safety controls.
; -----------------------------------------------------------------------------
; The exploitation-hardening controls (stack canary, software shadow stack,
; DLPV forward-edge CFG, integer-overflow checks, bounds checks, struct type
; tags, temporal tagged heap, IAT lockdown) only fire when memory is actually
; corrupted, so they cannot be exercised through the normal CLI.  This module
; adds a hidden `redteam <case>` command that DELIBERATELY commits exactly one
; violation per invocation.  The test harness runs each case as a child process
; and asserts the child died with the expected fastfail / access-violation code,
; proving the control both fires and fails closed.
;
;   myrkr redteam canary     -> FF_STACK_COOKIE (2)
;   myrkr redteam shadow     -> FF_SHADOW_STACK (0xF001)
;   myrkr redteam dlpv       -> FF_GUARD_ICALL  (10)
;   myrkr redteam overflow   -> FF_OVERFLOW     (0xF005)
;   myrkr redteam bounds     -> FF_BOUNDS       (0xF004)
;   myrkr redteam typemagic  -> FF_TYPE_MAGIC   (0xF003)
;   myrkr redteam heaptag    -> FF_HEAP_TAG     (0xF002)
;   myrkr redteam iat        -> access violation (0xC0000005)
;
; If a case RETURNS (the control failed to fire), cmd_redteam exits non-zero so
; the harness records a FAIL.  Compiled only into the instrumented build
; (`build dbg`, which defines DBG_TRACE); the shipping binary never contains it.
; =============================================================================

include macros.inc

ifdef DBG_TRACE

externdef g_cfg_in:qword                ; first positional arg (the case name)
extern wstr_eq:proc                     ; (rcx,rdx) -> eax=1 if equal UTF-16
extern print_a:proc                     ; (rcx=ptr, edx=len)
extern tagged_alloc:proc                ; (rcx=size) -> rax=user ptr
extern tagged_check:proc                ; (rcx=user ptr) fastfails on violation
extern __imp_CloseHandle:qword          ; an IAT slot (RO after iat_lockdown)

.const
WSTR rc_canary,    <canary>
WSTR rc_shadow,    <shadow>
WSTR rc_dlpv,      <dlpv>
WSTR rc_overflow,  <overflow>
WSTR rc_bounds,    <bounds>
WSTR rc_typemagic, <typemagic>
WSTR rc_heaptag,   <heaptag>
WSTR rc_iat,       <iat>
CSTR rt_msg_nofire, "redteam: control did NOT fire - FAIL",13,10
CSTR rt_msg_unkn,   "redteam: unknown case (canary|shadow|dlpv|overflow|bounds|typemagic|heaptag|iat)",13,10

.data?
align 16
rt_buf  db 64 dup (?)                    ; zeroed scratch (no LP/type magic)

.code

; -- dispatch one redteam case ------------------------------------------------
; Matches g_cfg_in against the case names and runs the matching violation.
RTCASE macro target, namestr
    mov     rcx, qword ptr [g_cfg_in]
    lea     rdx, namestr
    call    wstr_eq
    test    eax, eax
    jnz     target
endm

public cmd_redteam
LANDING_PAD                              ; dispatch reaches handlers via CALL_GUARDED
cmd_redteam proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [g_cfg_in]
    test    rcx, rcx
    jz      rt_unknown

    RTCASE  rt_do_canary,    rc_canary
    RTCASE  rt_do_shadow,    rc_shadow
    RTCASE  rt_do_dlpv,      rc_dlpv
    RTCASE  rt_do_overflow,  rc_overflow
    RTCASE  rt_do_bounds,    rc_bounds
    RTCASE  rt_do_type,      rc_typemagic
    RTCASE  rt_do_heap,      rc_heaptag
    RTCASE  rt_do_iat,       rc_iat
    jmp     rt_unknown

rt_do_canary:   call rt_v_canary
    jmp     rt_nofire
rt_do_shadow:   call rt_v_shadow
    jmp     rt_nofire
rt_do_dlpv:     call rt_v_dlpv
    jmp     rt_nofire
rt_do_overflow: call rt_v_overflow
    jmp     rt_nofire
rt_do_bounds:   call rt_v_bounds
    jmp     rt_nofire
rt_do_type:     call rt_v_type
    jmp     rt_nofire
rt_do_heap:     call rt_v_heap
    jmp     rt_nofire
rt_do_iat:      call rt_v_iat
    jmp     rt_nofire

rt_nofire:
    ; the violation returned -> the control under test did NOT catch it
    lea     rcx, rt_msg_nofire
    mov     edx, rt_msg_nofire_len
    call    print_a
    mov     eax, EXIT_SELFTEST          ; non-zero: harness records FAIL
    FRAME_EPILOG
    ret
rt_unknown:
    lea     rcx, rt_msg_unkn
    mov     edx, rt_msg_unkn_len
    call    print_a
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
cmd_redteam endp

; =============================================================================
; Individual violations.  Each is `proc frame` so the canary/shadow-stack
; machinery is active; each should terminate the process before returning.
; =============================================================================

; B1 stack canary: overwrite the canary slot, then run the verifying epilog.
rt_v_canary proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-8], 0DEADBEEFh   ; smash the planted canary
    FRAME_EPILOG                             ; -> FF_STACK_COOKIE
    ret
rt_v_canary endp

; B2 software shadow stack: corrupt the on-stack return address, leave canary.
rt_v_shadow proc frame
    FRAME_PROLOG 32
    mov     rax, 0BADC0DEBADC0DEh
    mov     qword ptr [rbp+8], rax           ; clobber saved return address
    FRAME_EPILOG                             ; canary ok, shadow mismatch -> FF_SHADOW_STACK
    ret
rt_v_shadow endp

; B4 DLPV: guarded indirect call through a pointer with no landing-pad magic.
rt_v_dlpv proc frame
    FRAME_PROLOG 32
    lea     rax, [rt_buf+8]                  ; [rax-8] = rt_buf[0] = 0 != LP_MAGIC
    CALL_GUARDED rax                         ; -> FF_GUARD_ICALL
    FRAME_EPILOG
    ret
rt_v_dlpv endp

; B6 integer overflow: checked add that carries out of 64 bits.
rt_v_overflow proc frame
    FRAME_PROLOG 32
    mov     rax, -1                          ; 0xFFFF...FF
    CHECK_ADD_OVF rax, 2                      ; carry -> FF_OVERFLOW
    FRAME_EPILOG
    ret
rt_v_overflow endp

; B7 bounds: index >= limit.
rt_v_bounds proc frame
    FRAME_PROLOG 32
    mov     rcx, 100
    BOUND_CHECK rcx, 10                       ; 100 >= 10 -> FF_BOUNDS
    FRAME_EPILOG
    ret
rt_v_bounds endp

; B8 type safety: type-check a buffer whose first dword is not the magic.
rt_v_type proc frame
    FRAME_PROLOG 32
    lea     rcx, [rt_buf]                    ; magic dword = 0 != TM_HEAPBLK
    TYPE_CHECK rcx, TM_HEAPBLK                ; -> FF_TYPE_MAGIC
    FRAME_EPILOG
    ret
rt_v_type endp

; B9 tagged heap: smash a live block's rear canary, then validate it.
rt_v_heap proc frame
    FRAME_PROLOG 32
    mov     rcx, 64
    call    tagged_alloc
    test    rax, rax
    jz      rt_heap_done                     ; OOM: can't run the test
    mov     qword ptr [rbp-24], rax          ; save user ptr
    mov     byte ptr [rax+64], 0AAh          ; overflow past user region -> rear canary
    mov     rcx, qword ptr [rbp-24]
    call    tagged_check                     ; rear-canary mismatch -> FF_HEAP_TAG
rt_heap_done:
    FRAME_EPILOG
    ret
rt_v_heap endp

; B5 IAT lockdown: write to a read-only IAT slot -> access violation.
rt_v_iat proc frame
    FRAME_PROLOG 32
    lea     rax, [__imp_CloseHandle]         ; RIP-relative addr of the IAT entry
    mov     qword ptr [rax], 0               ; write to RO page -> 0xC0000005
    FRAME_EPILOG
    ret
rt_v_iat endp

endif ; DBG_TRACE

end
