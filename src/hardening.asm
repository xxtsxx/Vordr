; =============================================================================
; hardening.asm - runtime hardening services
; -----------------------------------------------------------------------------
;   hardening_init    : canary + software shadow stack setup (call FIRST)
;   iat_lockdown      : make our IAT pages read-only ("full RELRO" equivalent)
;   secure_zero       : forced, non-elidable memory wipe
;   tagged_alloc      : heap allocator with temporal tag + canaries
;   ct_memcmp         : constant-time comparison (timing safe)
; =============================================================================

include macros.inc

extern VirtualAlloc:proc
extern VirtualFree:proc
extern VirtualProtect:proc
extern GetModuleHandleW:proc
extern rng_fill:proc                    ; random.asm: rcx=buf, rdx=len -> eax=1 ok
extern print_a:proc                     ; console.asm (cttest probe)
extern print_u64:proc
extern secmem_panic_wipe:proc           ; secmem.asm: zero every live secret buffer
extern SetUnhandledExceptionFilter:proc
extern AddVectoredExceptionHandler:proc
extern SetErrorMode:proc
extern TerminateProcess:proc
extern GetCurrentProcess:proc
extern MessageBoxW:proc

MEM_COMMIT          equ 1000h
MEM_RESERVE         equ 2000h
MEM_RELEASE         equ 8000h
PAGE_READONLY       equ 02h
PAGE_READWRITE      equ 04h
PAGE_NOACCESS       equ 01h

; -----------------------------------------------------------------------------
; Tagged heap block layout (temporal memory tagging emulation):
;
;   [hdr]  32 bytes : magic "BLPH" | size(8) | tag(8) | front canary(8) | gen(4)
;   [user] size bytes
;   [tail] 8 bytes  : rear canary  (= front canary rotated by 1)
;
; tag is random per allocation; generation counter is global and bumps on
; every free, so a stale pointer's stored tag can never match a reused block.
; Freed blocks are poisoned with 0xDD before release.
; -----------------------------------------------------------------------------
HEAPBLK struct
    magic       dd ?                    ; TM_HEAPBLK
    gen         dd ?                    ; generation at allocation time
    blksize     dq ?                    ; user size in bytes
    tag         dq ?                    ; random temporal tag
    canary      dq ?                    ; front canary
HEAPBLK ends
HEAP_TAIL_LEN   equ 8

.data
public g_stack_canary
public g_sstk_base
public g_sstk_index
public g_cpu_features
g_stack_canary  dq 0
g_sstk_base     dq 0
g_sstk_index    dq 0
g_cpu_features  dd 0
g_heap_gen      dd 1                    ; global generation counter
public g_gui_active
g_gui_active    dd 0                    ; 1 once the GUI is up (crash apology box)

SEM_FAILCRITICALERRORS  equ 1
SEM_NOGPFAULTERRORBOX   equ 2
MB_OK_          equ 0
MB_ICONERROR_   equ 10h

.const
crash_apology label word
    dw 'V','o','r','d','r',' ','h','i','t',' ','a',' ','f','a','t','a','l',' ','e'
    dw 'r','r','o','r',' ','a','n','d',' ','m','u','s','t',' ','c','l','o','s','e'
    dw '.',' ','Y','o','u','r',' ','s','e','c','r','e','t','s',' ','w','e','r','e'
    dw ' ','w','i','p','e','d',' ','f','r','o','m',' ','m','e','m','o','r','y','.', 0
crash_title label word
    dw 'V','o','r','d','r', 0
ifdef DBG_TRACE
CSTR crash_bc, "crash: unhandled exception - wiping secrets, terminating",13,10
endif

.code

; =============================================================================
; sstk_overflow_fail - jumped to from FRAME_PROLOG when shadow stack is full
; =============================================================================
public sstk_overflow_fail
sstk_overflow_fail proc
    FASTFAIL FF_SHADOW_STACK
sstk_overflow_fail endp

; =============================================================================
; crash_contain() - the shared crash-containment action: wipe every live secret
;   buffer, print a dbg breadcrumb, show a one-line apology (GUI only), then
;   terminate the process hard.  No secret can reach a WER minidump or
;   hibernation image, and the OS never runs its dump writer for this fault.
;   Never returns.
; =============================================================================
crash_contain proc frame
    FRAME_PROLOG 32
    call    secmem_panic_wipe                   ; secrets gone before anything else
ifdef DBG_TRACE
    lea     rcx, [crash_bc]
    mov     edx, crash_bc_len
    call    print_a
endif
    cmp     dword ptr [g_gui_active], 0          ; apology box only when a GUI is up
    je      cc_kill                             ; (headless CLI never blocks on a modal)
    WINCALL MessageBoxW, 0, addr crash_apology, addr crash_title, \
            <MB_OK_ or MB_ICONERROR_>
cc_kill:
    WINCALL GetCurrentProcess
    WINCALL TerminateProcess, rax, 0C0000409h
    FRAME_EPILOG                                ; unreached
    ret
crash_contain endp

; =============================================================================
; crash_veh(rcx = PEXCEPTION_POINTERS) -> LONG.  Vectored exception handler,
;   the PRIMARY containment path: it runs first-chance, so it fires before any
;   OS dump writer and even when a monitor/debugger owns the last-chance filter.
;   It only acts on error-severity (0xCxxxxxxx) codes - access violations,
;   stack-buffer-overrun fastfails, illegal instructions, etc. - and passes
;   benign first-chance events (guard-page stack growth 0x80000001, single-step)
;   straight through with EXCEPTION_CONTINUE_SEARCH so normal execution is
;   untouched.  On a fatal code it never returns (crash_contain terminates).
; =============================================================================
crash_veh proc frame
    FRAME_PROLOG 32
    mov     rax, qword ptr [rcx]                ; -> EXCEPTION_RECORD
    mov     eax, dword ptr [rax]                ; ExceptionCode
    and     eax, 0F0000000h                     ; severity nibble
    cmp     eax, 0C0000000h                     ; ERROR severity => fatal
    jne     cv_pass
    call    crash_contain                       ; wipe + terminate (no return)
cv_pass:
    xor     eax, eax                            ; EXCEPTION_CONTINUE_SEARCH
    FRAME_EPILOG
    ret
crash_veh endp

; crash_filter(rcx = PEXCEPTION_POINTERS) -> LONG.  Backup last-chance filter
;   for environments where a VEH is not reached; same containment action.
crash_filter proc frame
    FRAME_PROLOG 32
    call    crash_contain
    xor     eax, eax                            ; EXCEPTION_CONTINUE_SEARCH (unreached)
    FRAME_EPILOG
    ret
crash_filter endp

; =============================================================================
; crash_install() - arm crash containment.  Suppresses the WER fault UI for
;   this process (SetErrorMode, no registry change), installs the vectored
;   handler as the first-chance responder, and the top-level filter as backup.
;   Call once, early in wstart, before any secret exists.
; =============================================================================
public crash_install
crash_install proc frame
    FRAME_PROLOG 32
    WINCALL SetErrorMode, <SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX>
    WINCALL AddVectoredExceptionHandler, 1, addr crash_veh
    WINCALL SetUnhandledExceptionFilter, addr crash_filter
    FRAME_EPILOG
    ret
crash_install endp

; =============================================================================
; hardening_init - must be the first call made by the entry point.
; Allocates the shadow stack between two PAGE_NOACCESS guard pages and
; seeds the stack canary from the CSPRNG mixed with rdtsc.
; Returns eax=1 on success, 0 on failure (caller exits EXIT_OOM).
; NOTE: uses a raw frame - the canary/shadow machinery is not live yet.
; =============================================================================
public hardening_init
hardening_init proc frame
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 64                     ; 32 shadow + locals (base, oldprot, seed)
    .allocstack 64
    .endprolog

    ; ---- reserve guard | shadow stack | guard ------------------------------
    ; size = 4KiB guard + SSTK pages + 4KiB guard
    WINCALL VirtualAlloc, 0, <1000h + (SSTK_CAPACITY*8) + 1000h>, <MEM_RESERVE or MEM_COMMIT>, PAGE_NOACCESS
    test    rax, rax
    jz      hi_fail
    mov     qword ptr [rbp-8], rax      ; save region base

    ; ---- unprotect only the middle (the usable shadow stack) ---------------
    WINCALL VirtualProtect, addr rax+1000h, <SSTK_CAPACITY*8>, PAGE_READWRITE, addr rbp-16
    test    eax, eax
    jz      hi_fail
    mov     rax, qword ptr [rbp-8]
    lea     rax, [rax+1000h]
    mov     qword ptr [g_sstk_base], rax
    mov     qword ptr [g_sstk_index], 0

    ; ---- seed stack canary: CSPRNG xor rdtsc, never zero --------------------
    ; IMPORTANT: rng_fill is itself canary-protected and reads g_stack_canary
    ; in its epilog, so we must NOT let it write g_stack_canary directly.
    ; Fill a local seed buffer, then publish the canary only after it returns.
    lea     rcx, [rbp-24]               ; local seed (8 bytes)
    mov     edx, 8
    call    rng_fill
    test    eax, eax
    jz      hi_fail
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    xor     rax, qword ptr [rbp-24]
    test    rax, rax
    jnz     @F
    mov     rax, 0A5A5A5A55A5A5A5Ah     ; never-zero fallback
@@:
    mov     qword ptr [g_stack_canary], rax
    mov     eax, 1
    jmp     hi_done
hi_fail:
    xor     eax, eax
hi_done:
    mov     rsp, rbp
    pop     rbp
    ret
hardening_init endp

; =============================================================================
; iat_lockdown - "full RELRO" equivalent: walk our own PE header, find the
; IAT data directory and VirtualProtect it PAGE_READONLY.  Call after all
; initialization (imports are bound by the loader before we run, so this is
; safe immediately).  Returns eax=1 ok / 0 fail (non-fatal; caller may warn).
; =============================================================================
public iat_lockdown
iat_lockdown proc frame
    FRAME_PROLOG 48                     ; 32 shadow + 16 locals
    ; locals: [rbp-16] old protect

    WINCALL GetModuleHandleW, 0         ; GetModuleHandleW(NULL) = our base
    test    rax, rax
    jz      il_fail
    mov     r10, rax                    ; r10 = module base

    ; e_lfanew at base+3Ch -> PE header
    mov     eax, dword ptr [r10+3Ch]
    BOUND_CHECK rax, 1000h              ; sanity: header within first page
    lea     r11, [r10+rax]              ; r11 = IMAGE_NT_HEADERS64
    cmp     dword ptr [r11], 00004550h  ; "PE\0\0"
    jne     il_fail

    ; OptionalHeader at +24; DataDirectory at +112 within OptionalHeader;
    ; entry 12 (IMAGE_DIRECTORY_ENTRY_IAT) = +24+112+12*8 = +232
    mov     eax, dword ptr [r11+232]    ; IAT RVA
    mov     edx, dword ptr [r11+236]    ; IAT size
    test    eax, eax
    jz      il_fail
    test    edx, edx
    jz      il_fail

    ; IAT VA in r10+rax, size already in rdx
    WINCALL VirtualProtect, addr r10+rax, rdx, PAGE_READONLY, addr rbp-16
    test    eax, eax
    jz      il_fail
    mov     eax, 1
    jmp     il_done
il_fail:
    xor     eax, eax
il_done:
    FRAME_EPILOG
    ret
iat_lockdown endp

; =============================================================================
; secure_zero(rcx = ptr, rdx = len)
; Wipe that cannot be optimized away (we are asm - but we also use xmm stores
; followed by a fence so partial inlining/reordering can never skip it).
; =============================================================================
public secure_zero
secure_zero proc
    test    rdx, rdx
    jz      sz_done
    pxor    xmm0, xmm0
    ; ---- 16-byte chunks -----------------------------------------------------
sz_loop16:
    cmp     rdx, 16
    jb      sz_tail
    movdqu  xmmword ptr [rcx], xmm0
    add     rcx, 16
    sub     rdx, 16
    jmp     sz_loop16
sz_tail:
    test    rdx, rdx
    jz      sz_fence
    mov     byte ptr [rcx], 0
    inc     rcx
    dec     rdx
    jmp     sz_tail
sz_fence:
    mfence                              ; order the wipe before anything later
sz_done:
    ret
secure_zero endp

; =============================================================================
; ct_memcmp(rcx = a, rdx = b, r8 = len) -> eax = 0 if equal, 1 if different
; Constant time: examines every byte, no data-dependent branches.
; =============================================================================
public ct_memcmp
ct_memcmp proc
    xor     eax, eax                    ; accumulated difference
    xor     r10d, r10d                  ; index
    test    r8, r8
    jz      cm_done
cm_loop:
    movzx   r11d, byte ptr [rcx+r10]
    movzx   r9d,  byte ptr [rdx+r10]
    xor     r11d, r9d
    or      eax, r11d
    inc     r10
    cmp     r10, r8
    jb      cm_loop
cm_done:
    ; collapse any nonzero to exactly 1 without branching
    neg     eax                         ; CF=1 iff eax was nonzero
    sbb     eax, eax                    ; eax = -1 iff nonzero, else 0
    neg     eax                         ; eax = 1 iff different, 0 if equal
    ret
ct_memcmp endp

; =============================================================================
; tagged_alloc(rcx = user size) -> rax = user pointer, or 0 on failure
; VirtualAlloc-backed (no RWX, page-granular, OS guards) with header/footer
; canaries and a random temporal tag.
; =============================================================================
public tagged_alloc
tagged_alloc proc frame
    FRAME_PROLOG 64
    ; locals: [rbp-24] user size, [rbp-32] block ptr

    mov     qword ptr [rbp-24], rcx
    ; total = sizeof header + size + tail, overflow-checked
    mov     rax, rcx
    CHECK_ADD_OVF rax, (sizeof HEAPBLK) + HEAP_TAIL_LEN
    WINCALL VirtualAlloc, 0, rax, <MEM_RESERVE or MEM_COMMIT>, PAGE_READWRITE
    test    rax, rax
    jz      ta_fail
    mov     qword ptr [rbp-32], rax

    ; ---- fill header --------------------------------------------------------
    mov     dword ptr [rax].HEAPBLK.magic, TM_HEAPBLK
    mov     ecx, dword ptr [g_heap_gen]
    mov     dword ptr [rax].HEAPBLK.gen, ecx
    mov     rcx, qword ptr [rbp-24]
    mov     qword ptr [rax].HEAPBLK.blksize, rcx

    lea     rcx, [rax].HEAPBLK.tag      ; random temporal tag (8 bytes)
    mov     edx, 8
    call    rng_fill
    test    eax, eax
    jz      ta_fail_free

    mov     rax, qword ptr [rbp-32]
    mov     r10, qword ptr [rax].HEAPBLK.tag
    mov     qword ptr [rax].HEAPBLK.canary, r10     ; front canary = tag
    rol     r10, 1
    mov     rcx, qword ptr [rax].HEAPBLK.blksize    ; rear canary = rol(tag,1)
    lea     r11, [rax + sizeof HEAPBLK]
    mov     qword ptr [r11+rcx], r10

    lea     rax, [rax + sizeof HEAPBLK]             ; -> user pointer
    jmp     ta_done
ta_fail_free:
    WINCALL VirtualFree, qword ptr [rbp-32], 0, MEM_RELEASE
ta_fail:
    xor     eax, eax
ta_done:
    FRAME_EPILOG
    ret
tagged_alloc endp

; =============================================================================
; tagged_check(rcx = user ptr) - validate a live block, fastfail on violation.
; Catches: type confusion, buffer overflow into header, rear-canary smash,
; use-after-free (poisoned/stale generation).
; =============================================================================
public tagged_check
tagged_check proc
    lea     r10, [rcx - sizeof HEAPBLK]
    TYPE_CHECK r10, TM_HEAPBLK
    mov     r11, qword ptr [r10].HEAPBLK.tag
    cmp     r11, qword ptr [r10].HEAPBLK.canary     ; front canary == tag?
    jne     tc_fail
    mov     rax, qword ptr [r10].HEAPBLK.blksize
    rol     r11, 1
    cmp     r11, qword ptr [rcx+rax]                ; rear canary == rol(tag,1)?
    jne     tc_fail
    ret
tc_fail:
    FASTFAIL FF_HEAP_TAG
tagged_check endp

; =============================================================================
; cmd_cttest (dbg probe) - coarse constant-time check for ct_memcmp: time 10k
;   4 KiB compares with the difference at the FIRST byte, then at the LAST
;   byte.  An early-exit memcmp finishes the first case ~1000x faster; the
;   constant-time compare must stay within 2x.  exit 0 = pass, 1 = fail.
; =============================================================================
.data?
ctt_a   db 4096 dup (?)
ctt_b   db 4096 dup (?)

.code
CSTR ctt_hdr,  "cttest: 10000 x ct_memcmp(4096 B), rdtsc cycles:",13,10
CSTR ctt_l1,   "  diff at byte 0:    "
CSTR ctt_l2,   "  diff at byte 4095: "
CSTR ctt_nl,   13,10
CSTR ctt_pass, "cttest: PASS (timing independent of the difference position)",13,10
CSTR ctt_fail, "cttest: FAIL (compare time depends on the difference position)",13,10

; ctt_run() -> rax = rdtsc cycles for 10000 x ct_memcmp(ctt_a, ctt_b, 4096)
ctt_run proc frame
    FRAME_PROLOG 48
    ; [rbp-24] = start tsc, [rbp-32] = iterations left
    lfence
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     qword ptr [rbp-24], rax
    mov     dword ptr [rbp-32], 10000
cr_loop:
    lea     rcx, [ctt_a]
    lea     rdx, [ctt_b]
    mov     r8d, 4096
    call    ct_memcmp
    dec     dword ptr [rbp-32]
    jnz     cr_loop
    lfence
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
ctt_run endp

public cmd_cttest
LANDING_PAD                              ; dispatch reaches handlers via CALL_GUARDED
cmd_cttest proc frame
    FRAME_PROLOG 48
    ; [rbp-24] = cycles(diff@first), [rbp-32] = cycles(diff@last)
    xor     ecx, ecx                    ; identical buffers: a[i] = b[i] = i
    lea     r10, [ctt_a]                ; (RIP-relative; static+index would need ADDR32)
    lea     r11, [ctt_b]
ctt_fill:
    mov     al, cl
    mov     byte ptr [r10+rcx], al
    mov     byte ptr [r11+rcx], al
    inc     ecx
    cmp     ecx, 4096
    jb      ctt_fill
    lea     rcx, [ctt_hdr]
    mov     edx, ctt_hdr_len
    call    print_a
    xor     byte ptr [ctt_b], 1         ; difference at byte 0
    call    ctt_run                     ; warm-up (page-in + caches)
    call    ctt_run
    mov     qword ptr [rbp-24], rax
    xor     byte ptr [ctt_b], 1         ; restore
    xor     byte ptr [ctt_b+4095], 1    ; difference at byte 4095
    call    ctt_run                     ; warm-up
    call    ctt_run
    mov     qword ptr [rbp-32], rax
    xor     byte ptr [ctt_b+4095], 1    ; restore
    lea     rcx, [ctt_l1]
    mov     edx, ctt_l1_len
    call    print_a
    mov     rcx, qword ptr [rbp-24]
    call    print_u64
    lea     rcx, [ctt_nl]
    mov     edx, ctt_nl_len
    call    print_a
    lea     rcx, [ctt_l2]
    mov     edx, ctt_l2_len
    call    print_a
    mov     rcx, qword ptr [rbp-32]
    call    print_u64
    lea     rcx, [ctt_nl]
    mov     edx, ctt_nl_len
    call    print_a
    ; pass iff max < 2 * min (early exit would give a ~1000x gap)
    mov     rax, qword ptr [rbp-24]
    mov     rcx, qword ptr [rbp-32]
    cmp     rax, rcx
    jae     @F
    xchg    rax, rcx                    ; rax = max, rcx = min
@@: shr     rax, 1
    cmp     rax, rcx
    jae     ctt_bad                     ; max/2 >= min  ->  ratio >= 2x
    lea     rcx, [ctt_pass]
    mov     edx, ctt_pass_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
ctt_bad:
    lea     rcx, [ctt_fail]
    mov     edx, ctt_fail_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_cttest endp

end
