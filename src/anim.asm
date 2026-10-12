; =============================================================================
; anim.asm - the UI's animation clock.
; -----------------------------------------------------------------------------
; A handful of numeric slots (a thumb's alpha, the selection pill's position,
; hover levels, the cross-fade) each move from where they are toward a target
; over a duration, eased out (cubic).  One WM_TIMER on the vault window drives
; them, and only while one is moving: at rest no timer runs and animation costs
; no CPU at all.  Progress comes from GetTickCount64, not from counting ticks,
; so a late or coalesced timer neither shortens nor stretches an animation - it
; only samples it less often.
;
; Every change of a slot's value calls gui_anim_apply(slot), which knows what to
; repaint for it.  Slot numbers (ANIM_*) are in macros.inc.
;
; Settings > Animations (g_anim_pref) decides whether it runs: Always, Never, or
; - the default - Follow Windows, i.e. Windows' "Animation effects" switch
; (Settings > Accessibility > Visual effects; SPI_GETCLIENTAREAANIMATION).  Off,
; anim_set jumps straight to the target: the end state is identical, only instant.
; =============================================================================

include macros.inc

extern SetTimer:proc
extern KillTimer:proc
extern GetTickCount64:proc
extern SystemParametersInfoW:proc
extern gui_anim_apply:proc
externdef g_vaulthwnd:qword

public anim_set, anim_get, anim_active, anim_tick, anim_reset, anim_settings
public g_anim_on, g_anim_tmr, g_anim, g_anim_force, g_anim_pref

ANIM_MS             equ 15              ; ~60 Hz; USER timers round to the system tick
SPI_GETCLIENTAREAANIMATION equ 1042h

; one slot, 32 bytes
AS_FROM             equ 0               ; value when this run started
AS_TO               equ 4               ; target
AS_CUR              equ 8               ; value now
AS_ACT              equ 12              ; 1 while moving
AS_START            equ 16              ; GetTickCount64 at the start (qword)
AS_DUR              equ 24              ; duration, ms

.data
align 8
g_anim_on   dd 1                        ; Windows' animation switch (anim_settings)
g_anim_tmr  dd 0                        ; ANIM_TIMER is armed on g_vaulthwnd
g_anim_force dd 0                       ; test builds only (VORDR_TEST_ANIM, gui_test_hooks):
                                        ;   1 = on, 2 = off, whatever Windows says
g_anim_pref dd 0                        ; the user's Settings > Animations (ui_anim):
                                        ;   0 = follow Windows, 1 = always, 2 = never
align 8
g_anim      db ANIM_SLOTS*32 dup (0)

.code

; anim_slot(ecx = slot) -> r10 = its record.  Leaf, no frame (no calls).
anim_slot macro
    mov     eax, ecx
    shl     eax, 5
    lea     r10, [g_anim]
    add     r10, rax
endm

; anim_settings - re-read Windows' animation switch.  A failed query (an older
;   Windows without the setting) leaves animation on.
anim_settings proc frame
    FRAME_PROLOG 48
    mov     eax, dword ptr [g_anim_force]
    test    eax, eax
    jz      ast_query
    xor     ecx, ecx
    cmp     eax, 1
    sete    cl
    mov     dword ptr [g_anim_on], ecx
    jmp     ast_ret
ast_query:
    mov     eax, dword ptr [g_anim_pref]         ; the user's own choice, unless it is
    test    eax, eax                             ;   "follow Windows"
    jz      ast_spi
    xor     ecx, ecx
    cmp     eax, 1
    sete    cl
    mov     dword ptr [g_anim_on], ecx
    jmp     ast_ret
ast_spi:
    mov     dword ptr [rbp-24], 1
    WINCALL SystemParametersInfoW, SPI_GETCLIENTAREAANIMATION, 0, addr rbp-24, 0
    test    eax, eax
    jz      ast_ret
    xor     eax, eax
    cmp     dword ptr [rbp-24], 0
    setne   al
    mov     dword ptr [g_anim_on], eax
ast_ret:
    FRAME_EPILOG
    ret
anim_settings endp

; anim_reset - every slot at rest at 0, and the timer considered gone.  For a new
;   vault window: the old one took its timer with it when it was destroyed.
anim_reset proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_anim]
    xor     eax, eax
    mov     edx, ANIM_SLOTS*32/8
ars_lp:
    mov     qword ptr [rcx], rax
    add     rcx, 8
    dec     edx
    jnz     ars_lp
    mov     dword ptr [g_anim_tmr], 0
    FRAME_EPILOG
    ret
anim_reset endp

; anim_get(ecx = slot) -> eax = its value now.
anim_get proc frame
    FRAME_PROLOG 32
    xor     eax, eax
    cmp     ecx, ANIM_SLOTS
    jae     agt_ret
    anim_slot
    mov     eax, dword ptr [r10+AS_CUR]
agt_ret:
    FRAME_EPILOG
    ret
anim_get endp

; anim_active(ecx = slot) -> eax = 1 while it is moving.
anim_active proc frame
    FRAME_PROLOG 32
    xor     eax, eax
    cmp     ecx, ANIM_SLOTS
    jae     aac_ret
    anim_slot
    mov     eax, dword ptr [r10+AS_ACT]
aac_ret:
    FRAME_EPILOG
    ret
anim_active endp

; anim_set(ecx = slot, edx = target, r8d = duration ms) - move toward target from
;   wherever the slot is now (a reversal mid-way starts from the current value,
;   so nothing jumps).  Duration 0, animation switched off, or no vault window:
;   jump there at once.  Either way gui_anim_apply hears about every change.
anim_set proc frame
    FRAME_PROLOG 64
    cmp     ecx, ANIM_SLOTS
    jae     ase_ret
    mov     dword ptr [rbp-24], ecx
    mov     dword ptr [rbp-28], edx
    anim_slot
    mov     qword ptr [rbp-40], r10
    cmp     dword ptr [r10+AS_ACT], 0
    jne     ase_moving
    cmp     edx, dword ptr [r10+AS_CUR]
    je      ase_ret                              ; at rest, already there
    jmp     ase_go
ase_moving:
    cmp     edx, dword ptr [r10+AS_TO]
    jne     ase_go
    test    r8d, r8d                             ; already heading there - unless
    jnz     ase_ret                              ;   asked to arrive now
ase_go:
    test    r8d, r8d
    jle     ase_jump
    cmp     dword ptr [g_anim_on], 0
    je      ase_jump
    cmp     qword ptr [g_vaulthwnd], 0
    je      ase_jump
    mov     dword ptr [rbp-32], r8d
    WINCALL GetTickCount64
    mov     r10, qword ptr [rbp-40]
    mov     qword ptr [r10+AS_START], rax
    mov     eax, dword ptr [r10+AS_CUR]
    mov     dword ptr [r10+AS_FROM], eax
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [r10+AS_TO], eax
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [r10+AS_DUR], eax
    mov     dword ptr [r10+AS_ACT], 1
    cmp     dword ptr [g_anim_tmr], 0
    jne     ase_ret
    WINCALL SetTimer, qword ptr [g_vaulthwnd], ANIM_TIMER, ANIM_MS, 0
    test    rax, rax
    jz      ase_jump                             ; no timer: arrive at once instead
    mov     dword ptr [g_anim_tmr], 1
    jmp     ase_ret
ase_jump:
    mov     r10, qword ptr [rbp-40]
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [r10+AS_CUR], eax
    mov     dword ptr [r10+AS_TO], eax
    mov     dword ptr [r10+AS_ACT], 0
    mov     ecx, dword ptr [rbp-24]
    call    gui_anim_apply
ase_ret:
    FRAME_EPILOG
    ret
anim_set endp

; anim_tick - one ANIM_TIMER tick: advance every moving slot, then stop the timer
;   if nothing moves any more.  A slot started by a gui_anim_apply callback during
;   this tick keeps the timer: the stop decision rescans all slots at the end.
;
;   e = 1 - (1 - t)^3, t and e in 1/1024; value = from + (to - from) * e.
anim_tick proc frame
    FRAME_PROLOG 64
    WINCALL GetTickCount64
    mov     qword ptr [rbp-32], rax              ; now
    mov     dword ptr [rbp-24], 0                ; slot
atk_lp:
    mov     ecx, dword ptr [rbp-24]
    cmp     ecx, ANIM_SLOTS
    jae     atk_scan
    anim_slot
    cmp     dword ptr [r10+AS_ACT], 0
    je      atk_next
    mov     rax, qword ptr [rbp-32]
    sub     rax, qword ptr [r10+AS_START]        ; elapsed ms
    shl     rax, 10
    mov     ecx, dword ptr [r10+AS_DUR]
    xor     edx, edx
    div     rcx                                  ; t, in 1/1024
    cmp     rax, 1024
    jb      atk_ease
    mov     eax, dword ptr [r10+AS_TO]           ; done: land exactly on the target
    mov     dword ptr [r10+AS_CUR], eax
    mov     dword ptr [r10+AS_ACT], 0
    jmp     atk_apply
atk_ease:
    mov     ecx, 1024
    sub     ecx, eax                             ; u = 1 - t
    mov     eax, ecx
    imul    eax, ecx
    shr     eax, 10                              ; u^2
    imul    eax, ecx
    shr     eax, 10                              ; u^3
    mov     ecx, 1024
    sub     ecx, eax                             ; e
    mov     eax, dword ptr [r10+AS_TO]
    sub     eax, dword ptr [r10+AS_FROM]         ; signed distance
    imul    eax, ecx
    sar     eax, 10
    add     eax, dword ptr [r10+AS_FROM]
    cmp     eax, dword ptr [r10+AS_CUR]
    je      atk_next                             ; no visible step this tick
    mov     dword ptr [r10+AS_CUR], eax
atk_apply:
    mov     ecx, dword ptr [rbp-24]
    call    gui_anim_apply
atk_next:
    inc     dword ptr [rbp-24]
    jmp     atk_lp
atk_scan:
    lea     r10, [g_anim]
    mov     ecx, ANIM_SLOTS
atk_scl:
    cmp     dword ptr [r10+AS_ACT], 0
    jne     atk_ret                              ; something still moves
    add     r10, 32
    dec     ecx
    jnz     atk_scl
    cmp     dword ptr [g_anim_tmr], 0
    je      atk_ret
    mov     dword ptr [g_anim_tmr], 0
    WINCALL KillTimer, qword ptr [g_vaulthwnd], ANIM_TIMER
atk_ret:
    FRAME_EPILOG
    ret
anim_tick endp

end
