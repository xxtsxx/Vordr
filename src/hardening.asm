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
extern TlsAlloc:proc                    ; the per-thread shadow stack's slot
extern TlsSetValue:proc
extern GetModuleHandleW:proc
extern GetModuleFileNameW:proc
extern rng_fill:proc                    ; random.asm: rcx=buf, rdx=len -> eax=1 ok
ifdef DBG_TRACE
extern print_a:proc                     ; console.asm (cttest / crash breadcrumb)
extern print_u64:proc
endif
extern secmem_panic_wipe:proc           ; secmem.asm: zero every live secret buffer
extern SetUnhandledExceptionFilter:proc
extern AddVectoredExceptionHandler:proc
extern SetErrorMode:proc
extern SetDefaultDllDirectories:proc
extern SetProcessMitigationPolicy:proc
extern TerminateProcess:proc
extern GetCurrentProcess:proc
extern GetCurrentThreadId:proc
extern Sleep:proc
extern SwitchDesktop:proc               ; restore the user's desktop before we die
extern OpenDesktopW:proc
extern CloseDesktop:proc
externdef g_secdesk_orig:qword          ; gui.asm: HDESK of the user's own input desktop
extern HeapSetInformation:proc
extern GetProcAddress:proc
extern LoadLibraryExW:proc
extern FreeLibrary:proc
ifdef DBG_TRACE
extern CreateFileW:proc
extern GetFileType:proc
extern GetFileInformationByHandle:proc
extern WriteFile:proc
extern CloseHandle:proc
extern GetTempPathW:proc
endif

MEM_COMMIT          equ 1000h
MEM_RESERVE         equ 2000h
MEM_RELEASE         equ 8000h
PAGE_READONLY       equ 02h
PAGE_READWRITE      equ 04h
PAGE_NOACCESS       equ 01h

; -----------------------------------------------------------------------------
; Tagged heap block layout (guard-page-aligned + header/footer canaries):
;
;   [hdr]  32 bytes : magic "BLPH" | reserved(4) | size(8) | tag(8) | front canary(8)
;   [user] size bytes
;   [tail] 8 bytes  : rear canary  (= front canary rotated by 1)
;   [pad]  0..15 B  : 16-byte alignment slack, flush against a trailing
;                     PAGE_NOACCESS hardware guard page.
; -----------------------------------------------------------------------------
HEAPBLK struct
    magic       dd ?                    ; TM_HEAPBLK
    reserved    dd ?                    ; alignment pad (0)
    blksize     dq ?                    ; user size in bytes
    tag         dq ?                    ; random per-block tag
    canary      dq ?                    ; front canary
HEAPBLK ends
HEAP_TAIL_LEN   equ 8

; Dedicated 4 KiB-aligned write-once startup section locked PAGE_READONLY in iat_lockdown (AUD-09)
_ROINIT SEGMENT PAGE READ WRITE 'ROINIT'
public g_stack_canary
public g_ptr_cookie
public g_sstk_tls
public g_cpu_features
g_roinit_base label byte
g_stack_canary  dq 0
g_ptr_cookie    dq 0
g_sstk_tls      dd 0                    ; TLS index + 1 (0 = not allocated yet)
g_cpu_features  dd 0
g_img_lo        dq 0                    ; this image's [base, base+SizeOfImage):
g_img_hi        dq 0                    ;   crash_veh only acts on faults inside it
ROINIT_LEN      equ $ - g_roinit_base
_ROINIT ENDS

.data
public g_gui_active
g_gui_active    dd 0                    ; 1 once the GUI is up
public g_in_crash
g_in_crash      dd 0                    ; owning crash TID (or 1 in redteam crash_reent)
align 8
g_crash_code    dq 0                    ; last exception code (crash breadcrumb)
g_crash_addr    dq 0                    ; last exception address
ifdef DBG_TRACE
g_crash_base    dq 0                    ; image base at crash time (RVA math)
endif
g_crash_info    dq 2 dup (0)            ; ExceptionInformation[0..1] (op, data addr)
ifdef DBG_TRACE
g_crash_regs    dq 10 dup (0)           ; rax rcx rdx rbx rsp rbp rsi rdi rip r8
g_crash_h       dq 0                    ; breadcrumb file handle
g_crash_nw      dd 0                    ; WriteFile bytes-written out
g_crash_dumped  db 0                    ; reentry guard: dump once
endif
align 2

SEM_FAILCRITICALERRORS  equ 1
SEM_NOGPFAULTERRORBOX   equ 2
GENERIC_WRITE_          equ 40000000h
FILE_FLAG_OPEN_RP       equ 00200000h   ; FILE_FLAG_OPEN_REPARSE_POINT
FILE_TYPE_DISK_         equ 1
ifdef DBG_TRACE
CREATE_NEW_             equ 1
FILE_ATTR_REPARSE_PT    equ 00000400h   ; FILE_ATTRIBUTE_REPARSE_POINT
endif
STATUS_ILLEGAL_INST     equ 0C000001Dh
STATUS_INT_DIV_ZERO     equ 0C0000094h
STATUS_STACK_OVF        equ 0C00000FDh
STATUS_HEAP_CORRUPT     equ 0C0000374h
STATUS_STACK_OVERRUN    equ 0C0000409h
WER_FLAGS_HARDEN        equ 000001E1h   ; A3-09: NOHEAP|NO_UI|NO_HEAP_ON_QUEUE|DISABLE_SNAPSHOT_CRASH|HANG
LOAD_LIB_SYS32          equ 0800h       ; LOAD_LIBRARY_SEARCH_SYSTEM32
MITIG_EXT_DISABLE       equ 7           ; ProcessExtensionPointDisablePolicy
MITIG_IMG_LOAD          equ 10          ; ProcessImageLoadPolicy
IMG_POL_FLAGS           equ 7           ; NoRemoteImages (1) | NoLowMandatoryLabelImages (2) | PreferSystem32Images (4)

.const
WSTR w_k32_dll,   <kernel32.dll>
WSTR w_wer_dll,   <wer.dll>
WSTR w_vordr_exe, <vordr.exe>
WSTR w_def_desk,  <Default>
a_wer_flags       db "WerSetFlags", 0
a_wer_excl        db "WerAddExcludedApplication", 0
ifdef DBG_TRACE
align 2
crash_fname label word
    dw 'v','o','r','d','r','_','c','r','a','s','h','.','b','i','n', 0
CSTR crash_bc, "crash: unhandled exception - wiping secrets, terminating",13,10
endif

.data?
align 2
ci_modbuf       dw 264 dup (?)          ; A3-09: GetModuleFileNameW basename for WerAddExcludedApplication

.code

; =============================================================================
; sstk_thread_init -> eax = 1 ok, 0 failed.  Give the CALLING thread its own
;   software shadow stack and publish it in the TLS slot.  Every thread that runs
;   framed code calls this first; one that does not keeps only the canary.
;
;   One commit: [guard page][16-byte block {index, -}][SSTK_CAPACITY*8][guard
;   page], so a runaway push or pop hits a guard, not someone else's memory.
;
;   RAW frame: it runs before the thread has a shadow stack.  The caller must
;   call it with an aligned stack (thread entries align rsp first).
; =============================================================================
public sstk_thread_init
; The block + entries span SSTK_SPAN bytes, which is not a whole number of pages, so
; the block is placed SSTK_PAD bytes into its first page: the last entry then ends
; exactly where the upper guard page begins, and a runaway push hits the guard
; rather than the page's slack.  sstk_thread_free rounds the block down to its page.
SSTK_SPAN   equ SSTK_HDR + (SSTK_CAPACITY*8)
SSTK_PAGES  equ (SSTK_SPAN + 0FFFh) / 1000h
SSTK_PAD    equ SSTK_PAGES*1000h - SSTK_SPAN
sstk_thread_init proc
    push    rbp
    mov     rbp, rsp
    and     rsp, -16                        ; whatever the caller did
    sub     rsp, 64
    WINCALL VirtualAlloc, 0, <1000h + SSTK_PAGES*1000h + 1000h>, <MEM_RESERVE or MEM_COMMIT>, PAGE_NOACCESS
    test    rax, rax
    jz      sti_fail
    mov     qword ptr [rbp-8], rax          ; region base
    WINCALL VirtualProtect, addr rax+1000h, <SSTK_PAGES*1000h>, PAGE_READWRITE, addr rbp-16
    test    eax, eax
    jz      sti_fail_free
    mov     rax, qword ptr [rbp-8]
    lea     rax, [rax+1000h+SSTK_PAD]       ; -> the block, flush against the upper guard
    mov     qword ptr [rax], 0              ; index = 0
    mov     qword ptr [rbp-24], rax         ; through memory: WINCALL marshals rax first
    mov     eax, dword ptr [g_sstk_tls]
    dec     eax
    mov     dword ptr [rbp-32], eax
    WINCALL TlsSetValue, dword ptr [rbp-32], qword ptr [rbp-24]
    test    eax, eax
    jz      sti_fail_free
    mov     eax, 1
    mov     rsp, rbp
    pop     rbp
    ret
sti_fail_free:
    WINCALL VirtualFree, qword ptr [rbp-8], 0, MEM_RELEASE
sti_fail:
    xor     eax, eax
    mov     rsp, rbp
    pop     rbp
    ret
sstk_thread_init endp

; =============================================================================
; sstk_thread_free - give back the calling thread's block.  MUST be the last
;   thing the thread does: every framed call has returned by then.  The TLS slot
;   is cleared FIRST, so framed code that somehow runs afterwards degrades to
;   canary-only instead of writing into released pages.  RAW frame, for the
;   mirror of sstk_thread_init's reason.
; =============================================================================
public sstk_thread_free
sstk_thread_free proc
    push    rbp
    mov     rbp, rsp
    and     rsp, -16
    sub     rsp, 64
    mov     eax, dword ptr [g_sstk_tls]
    test    eax, eax
    jz      stf_ret
    dec     eax
    mov     dword ptr [rbp-32], eax
    mov     r10d, eax
    mov     r11, gs:[r10*8 + TEB_TLS_SLOTS]
    test    r11, r11
    jz      stf_ret
    and     r11, -1000h                     ; the block's page (it sits SSTK_PAD in) ...
    sub     r11, 1000h                      ;   ... and the region starts one guard page lower
    mov     qword ptr [rbp-24], r11
    WINCALL TlsSetValue, dword ptr [rbp-32], 0
    WINCALL VirtualFree, qword ptr [rbp-24], 0, MEM_RELEASE
stf_ret:
    mov     rsp, rbp
    pop     rbp
    ret
sstk_thread_free endp

; sstk_reset_current - empty the calling thread's shadow stack (ff_trap, which is
;   terminating and needs secmem_panic_wipe's framed prologue to be able to push
;   even when the trap was a FULL shadow stack).  Leaf; clobbers rax, r10.
public sstk_reset_current
sstk_reset_current proc
    mov     eax, dword ptr [g_sstk_tls]
    test    eax, eax
    jz      srcur_ret
    dec     eax
    mov     r10, gs:[rax*8 + TEB_TLS_SLOTS]
    test    r10, r10
    jz      srcur_ret
    mov     qword ptr [r10], 0
srcur_ret:
    ret
sstk_reset_current endp

; =============================================================================
; sstk_overflow_fail - jumped to from FRAME_PROLOG when shadow stack is full
; =============================================================================
public sstk_overflow_fail
sstk_overflow_fail proc
    FASTFAIL FF_SHADOW_STACK
sstk_overflow_fail endp

; =============================================================================
; crash_try_enter() -> eax = 1 if THIS thread acquired the crash latch, 0 if
;   re-entrant on the SAME thread (or pre-armed g_in_crash == 1).  If ANOTHER
;   thread already owns the crash latch, parks this thread in Sleep() so the
;   owning thread finishes secmem_panic_wipe uninterrupted (AUD-10).  RAW frame.
; =============================================================================
public crash_try_enter
crash_try_enter proc
    push    rbp
    mov     rbp, rsp
    and     rsp, -16
    sub     rsp, 48
    WINCALL GetCurrentThreadId
    test    eax, eax
    jnz     @F
    mov     eax, 2
@@: mov     ecx, eax
    xor     eax, eax
    lock cmpxchg dword ptr [g_in_crash], ecx
    je      cte_won
    cmp     eax, ecx                            ; recursive fault on owning crash thread?
    je      cte_reent
    cmp     eax, 1                              ; redteam crash_reent sentinel?
    je      cte_reent
cte_park:
    WINCALL Sleep, 1000                         ; wait for owning thread to finish panic wipe
    jmp     cte_park
cte_reent:
    xor     eax, eax
    mov     rsp, rbp
    pop     rbp
    ret
cte_won:
    mov     eax, 1
    mov     rsp, rbp
    pop     rbp
    ret
crash_try_enter endp

; crash_restore_desktop() - restore input desktop to g_secdesk_orig, retrying and
;   falling back to OpenDesktopW(L"Default") so a crash never strands the session
;   on the private Secure-Unlock desktop (AUD-10).  RAW frame.
public crash_restore_desktop
crash_restore_desktop proc
    push    rbp
    mov     rbp, rsp
    and     rsp, -16
    sub     rsp, 48
    mov     rcx, qword ptr [g_secdesk_orig]
    test    rcx, rcx
    jz      crd_done
    WINCALL SwitchDesktop, rcx
    test    eax, eax
    jnz     crd_done
    WINCALL Sleep, 15
    WINCALL SwitchDesktop, qword ptr [g_secdesk_orig]
    test    eax, eax
    jnz     crd_done
    WINCALL OpenDesktopW, addr w_def_desk, 0, 0, 0100h ; DESKTOP_SWITCHDESKTOP = 0x100
    test    rax, rax
    jz      crd_done
    mov     qword ptr [rbp-16], rax
    WINCALL SwitchDesktop, rax
    WINCALL CloseDesktop, qword ptr [rbp-16]
crd_done:
    mov     rsp, rbp
    pop     rbp
    ret
crash_restore_desktop endp

; =============================================================================
; crash_contain() - the shared crash-containment action: reset shadow stack,
;   wipe every live secret buffer, print a dbg breadcrumb, restore desktop if on
;   the Secure-Unlock private desktop, and terminate immediately without pumping
;   messages or raising UI.  RAW frame so crash containment never depends on the
;   software shadow stack or stack canary being intact.
; =============================================================================
crash_contain proc
    push    rbp
    mov     rbp, rsp
    and     rsp, -16
    sub     rsp, 64
    call    sstk_reset_current
    call    secmem_panic_wipe                   ; 1. secrets gone BEFORE any Win32 / file I/O
    call    crash_restore_desktop               ; 2. restore user's desktop BEFORE any I/O
ifdef DBG_TRACE
    cmp     dword ptr [g_crash_code], STATUS_STACK_OVF
    je      cc_nodump                           ; stack exhausted: skip Win32 file I/O
    call    crash_dump                          ; 3. dbg-only breadcrumb AFTER wipe + desktop
cc_nodump:
    lea     rcx, [crash_bc]
    mov     edx, crash_bc_len
    call    print_a
endif
    WINCALL GetCurrentProcess
    WINCALL TerminateProcess, rax, 0C0000409h
    mov     ecx, 2
    int     29h
    mov     rsp, rbp
    pop     rbp
    ret
crash_contain endp

; =============================================================================
; crash_veh(rcx = PEXCEPTION_POINTERS) -> LONG.  Vectored exception handler,
;   the PRIMARY containment path: raw frame + atomic re-entrancy latch (g_in_crash).
; =============================================================================
crash_veh proc
    push    rbp
    mov     rbp, rsp
    and     rsp, -16
    sub     rsp, 64
    mov     rax, qword ptr [rcx]                ; -> EXCEPTION_RECORD
    mov     edx, dword ptr [rax]                ; ExceptionCode
    mov     r8d, edx
    and     r8d, 0F0000000h                     ; severity nibble
    cmp     r8d, 0C0000000h                     ; ERROR severity => fatal
    jne     cv_pass
    mov     r10, qword ptr [rax+16]             ; ExceptionAddress
    ; Non-SEH-probed fatal faults (heap corruption, stack overflow/overrun, #UD, #DE,
    ; or wild indirect jump to NULL/low page) are contained immediately regardless of
    ; module RIP; ordinary AVs outside our image pass to SEH first so OS DLL __try
    ; probes continue, with crash_filter catching any genuinely unhandled DLL fault.
    cmp     edx, STATUS_HEAP_CORRUPT
    je      cv_catch
    cmp     edx, STATUS_STACK_OVERRUN
    je      cv_catch
    cmp     edx, STATUS_STACK_OVF
    je      cv_catch
    cmp     edx, STATUS_ILLEGAL_INST
    je      cv_catch
    cmp     edx, STATUS_INT_DIV_ZERO
    je      cv_catch
    cmp     r10, 10000h
    jb      cv_catch
    cmp     r10, qword ptr [g_img_lo]
    jb      cv_pass
    cmp     r10, qword ptr [g_img_hi]
    jae     cv_pass
cv_catch:
    ; Preserve rcx/rax/edx/r10 across crash_try_enter
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rax
    mov     dword ptr [rbp-28], edx
    mov     qword ptr [rbp-40], r10
    call    crash_try_enter
    test    eax, eax
    jz      cv_reent
    mov     rcx, qword ptr [rbp-16]
    mov     rax, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-28]
    mov     r10, qword ptr [rbp-40]
    mov     dword ptr [g_crash_code], edx
    mov     qword ptr [g_crash_addr], r10
    cmp     dword ptr [rax+24], 2               ; NumberParameters >= 2?
    jb      cv_noinfo
    mov     r10, qword ptr [rax+32]
    mov     qword ptr [g_crash_info], r10
    mov     r10, qword ptr [rax+40]
    mov     qword ptr [g_crash_info+8], r10
cv_noinfo:
ifdef DBG_TRACE
    mov     rcx, qword ptr [rcx+8]              ; -> CONTEXT
    call    crash_capture_context
endif
    call    crash_contain                       ; wipe + restore desktop + terminate
cv_reent:
    WINCALL GetCurrentProcess
    WINCALL TerminateProcess, rax, 0C0000409h
    mov     ecx, 2
    int     29h
cv_pass:
    xor     eax, eax                            ; EXCEPTION_CONTINUE_SEARCH
    mov     rsp, rbp
    pop     rbp
    ret
crash_veh endp

ifdef DBG_TRACE
; A3-18: isolated CONTEXT register snapshot so ARM64 overrides it cleanly in src/arm64/platform.S
public crash_capture_context, g_crash_regs
crash_capture_context proc
    test    rcx, rcx
    jz      ccc_done
    mov     r10, qword ptr [rcx+78h]
    mov     qword ptr [g_crash_regs+0], r10     ; rax
    mov     r10, qword ptr [rcx+80h]
    mov     qword ptr [g_crash_regs+8], r10     ; rcx
    mov     r10, qword ptr [rcx+88h]
    mov     qword ptr [g_crash_regs+16], r10    ; rdx
    mov     r10, qword ptr [rcx+90h]
    mov     qword ptr [g_crash_regs+24], r10    ; rbx
    mov     r10, qword ptr [rcx+98h]
    mov     qword ptr [g_crash_regs+32], r10    ; rsp
    mov     r10, qword ptr [rcx+0A0h]
    mov     qword ptr [g_crash_regs+40], r10    ; rbp
    mov     r10, qword ptr [rcx+0A8h]
    mov     qword ptr [g_crash_regs+48], r10    ; rsi
    mov     r10, qword ptr [rcx+0B0h]
    mov     qword ptr [g_crash_regs+56], r10    ; rdi
    mov     r10, qword ptr [rcx+0F8h]
    mov     qword ptr [g_crash_regs+64], r10    ; rip
    mov     r10, qword ptr [rcx+0B8h]
    mov     qword ptr [g_crash_regs+72], r10    ; r8
ccc_done:
    ret
crash_capture_context endp
endif

ifdef DBG_TRACE
; crash_dump() - dbg-only crash breadcrumb: %TEMP%\vordr_crash.bin, run AFTER
;   secmem_panic_wipe + SwitchDesktop.  Refuses existing files, reparse points,
;   hardlinks, and non-disk handles.
crash_dump proc
    push    rbp
    mov     rbp, rsp
    and     rsp, -16
    sub     rsp, 128
    ; [rbp-64..-13] = BY_HANDLE_FILE_INFORMATION (52 bytes), clear of [rsp..rsp+31]
    cmp     byte ptr [g_crash_dumped], 0
    jne     cd_ret
    mov     byte ptr [g_crash_dumped], 1
    WINCALL GetTempPathW, MAX_PATH_CHARS-32, addr g_crashpath
    test    eax, eax
    jz      cd_ret
    cmp     eax, MAX_PATH_CHARS-32
    jae     cd_ret
    lea     r10, [g_crashpath]
cd_scan:
    cmp     word ptr [r10], 0
    je      cd_app
    add     r10, 2
    jmp     cd_scan
cd_app:
    lea     r11, [crash_fname]
cd_cp:
    mov     ax, word ptr [r11]
    mov     word ptr [r10], ax
    add     r10, 2
    add     r11, 2
    test    ax, ax
    jnz     cd_cp
    WINCALL CreateFileW, addr g_crashpath, GENERIC_WRITE_, 0, 0, CREATE_NEW_, FILE_FLAG_OPEN_RP, 0
    cmp     rax, -1
    je      cd_ret
    mov     qword ptr [g_crash_h], rax
    WINCALL GetFileType, qword ptr [g_crash_h]
    cmp     eax, FILE_TYPE_DISK_
    jne     cd_close
    WINCALL GetFileInformationByHandle, qword ptr [g_crash_h], addr rbp-64
    test    eax, eax
    jz      cd_close
    test    dword ptr [rbp-64], FILE_ATTR_REPARSE_PT
    jnz     cd_close
    cmp     dword ptr [rbp-64+40], 1            ; nNumberOfLinks <= 1
    ja      cd_close
    WINCALL GetModuleHandleW, 0
    mov     qword ptr [g_crash_base], rax
    WINCALL WriteFile, qword ptr [g_crash_h], addr g_crash_code, 120, addr g_crash_nw, 0
cd_close:
    WINCALL CloseHandle, qword ptr [g_crash_h]
cd_ret:
    mov     rsp, rbp
    pop     rbp
    ret
crash_dump endp
endif

; crash_filter(rcx = PEXCEPTION_POINTERS) -> LONG.  Backup last-chance filter.
crash_filter proc
    push    rbp
    mov     rbp, rsp
    and     rsp, -16
    sub     rsp, 64
    mov     qword ptr [rbp-16], rcx
    call    crash_try_enter
    test    eax, eax
    jz      cf_reent
    mov     rcx, qword ptr [rbp-16]
    mov     rax, qword ptr [rcx]
    mov     r10d, dword ptr [rax]
    mov     dword ptr [g_crash_code], r10d
    mov     r10, qword ptr [rax+16]
    mov     qword ptr [g_crash_addr], r10
    call    crash_contain
cf_reent:
    WINCALL GetCurrentProcess
    WINCALL TerminateProcess, rax, 0C0000409h
    mov     ecx, 2
    int     29h
    xor     eax, eax
    mov     rsp, rbp
    pop     rbp
    ret
crash_filter endp

; =============================================================================
; crash_install() - arm crash containment.  Suppresses WER UI + LocalDumps /
;   crash snapshots for this process, installs the vectored handler as the
;   first-chance responder, and the top-level filter as backup.
;   Call once, early in wstart, before any secret exists.
; =============================================================================
public crash_install
crash_install proc frame
    FRAME_PROLOG 80
    WINCALL GetModuleHandleW, 0                 ; our image range, for crash_veh
    mov     qword ptr [g_img_lo], rax
    mov     r10d, dword ptr [rax+3Ch]           ; e_lfanew
    mov     r10d, dword ptr [rax+r10+50h]       ; OptionalHeader.SizeOfImage
    add     rax, r10
    mov     qword ptr [g_img_hi], rax
    WINCALL SetErrorMode, <SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX>
    ; Best-effort WER snapshot/LocalDumps suppression (kernel32!WerSetFlags +
    ; wer!WerAddExcludedApplication, resolved dynamically from System32).
    WINCALL GetModuleHandleW, addr w_k32_dll
    test    rax, rax
    jz      ci_wer_dll
    WINCALL GetProcAddress, rax, addr a_wer_flags
    test    rax, rax
    jz      ci_wer_dll
    mov     ecx, WER_FLAGS_HARDEN
    call    rax
ci_wer_dll:
    WINCALL LoadLibraryExW, addr w_wer_dll, 0, LOAD_LIB_SYS32
    test    rax, rax
    jz      ci_handlers
    mov     qword ptr [rbp-24], rax
    WINCALL GetProcAddress, rax, addr a_wer_excl
    test    rax, rax
    jz      ci_free_wer
    mov     qword ptr [rbp-32], rax
    ; A3-09: exclude actual running image basename (handles renamed portable executables)
    WINCALL GetModuleFileNameW, 0, addr ci_modbuf, 260
    lea     rcx, [w_vordr_exe]
    test    eax, eax
    jz      ci_call_excl
    cmp     eax, 260
    jae     ci_call_excl
    lea     r10, [ci_modbuf]
    mov     rcx, r10
ci_base_lp:
    movzx   edx, word ptr [r10]
    test    dx, dx
    jz      ci_call_excl
    add     r10, 2
    cmp     dx, 5Ch
    je      ci_base_set
    cmp     dx, '/'
    jne     ci_base_lp
ci_base_set:
    mov     rcx, r10
    jmp     ci_base_lp
ci_call_excl:
    xor     edx, edx
    call    qword ptr [rbp-32]
ci_free_wer:
    WINCALL FreeLibrary, qword ptr [rbp-24]
ci_handlers:
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

    ; ---- lock dynamic DLL search path + process/heap mitigation policies ----
    WINCALL HeapSetInformation, 0, 1, 0, 0      ; HeapEnableTerminationOnCorruption
    test    eax, eax
    jz      hi_fail
    WINCALL SetDefaultDllDirectories, LOAD_LIB_SYS32
    test    eax, eax
    jz      hi_fail
    mov     dword ptr [rbp-24], 1
    WINCALL SetProcessMitigationPolicy, MITIG_EXT_DISABLE, addr rbp-24, 4
    mov     dword ptr [rbp-24], IMG_POL_FLAGS
    WINCALL SetProcessMitigationPolicy, MITIG_IMG_LOAD, addr rbp-24, 4

    ; ---- one TLS index, then THIS thread's own shadow stack ----------------
    call    TlsAlloc                    ; no arguments
    cmp     eax, 63                     ; must be an inline TEB slot: past 63 the
    ja      hi_fail                     ;   value lives in TlsExpansionSlots instead
    inc     eax                         ; stored +1: 0 means "not ready", and TLS
    mov     dword ptr [g_sstk_tls], eax ;   index 0 is a real slot someone may own
    call    sstk_thread_init
    test    eax, eax
    jz      hi_fail

    ; ---- seed stack canary + pointer cookie: CSPRNG xor rdtsc, never zero ---
    ; IMPORTANT: rng_fill is itself canary-protected and reads g_stack_canary
    ; in its epilog, so we must NOT let it write g_stack_canary directly.
    ; Fill a 16-byte local seed buffer, publish g_stack_canary & g_ptr_cookie,
    ; then wipe the stack seed before returning (AUD-09, AUD-26).
    lea     rcx, [rbp-32]               ; local 16-byte seed ([rbp-32..-17])
    mov     edx, 16
    call    rng_fill
    test    eax, eax
    jz      hi_fail
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rcx, rax
    xor     rax, qword ptr [rbp-32]
    test    rax, rax
    jnz     @F
    mov     rax, 0A5A5A5A55A5A5A5Ah     ; never-zero fallback
@@: mov     qword ptr [g_stack_canary], rax
    rol     rcx, 17
    xor     rcx, qword ptr [rbp-24]
    test    rcx, rcx
    jnz     @F
    mov     rcx, 05A5A5A5AA5A5A5A5h
@@: mov     qword ptr [g_ptr_cookie], rcx
    mov     qword ptr [rbp-32], 0
    mov     qword ptr [rbp-24], 0
    mfence
    mov     eax, 1
    jmp     hi_done
hi_fail:
    mov     qword ptr [rbp-32], 0
    mov     qword ptr [rbp-24], 0
    xor     eax, eax
hi_done:
    mov     rsp, rbp
    pop     rbp
    ret
hardening_init endp

; =============================================================================
; iat_lockdown - "full RELRO" equivalent: walk our own PE header, find the
; IAT data directory and VirtualProtect it PAGE_READONLY, and lock the _ROINIT
; startup security globals PAGE_READONLY as well (AUD-09).
; Returns eax=1 ok / 0 fail.
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
    mov     ecx, dword ptr [r11+50h]    ; OptionalHeader.SizeOfImage
    mov     eax, dword ptr [r11+232]    ; IAT RVA
    mov     edx, dword ptr [r11+236]    ; IAT size
    test    eax, eax
    jz      il_fail
    test    edx, edx
    jz      il_fail
    cmp     eax, ecx                    ; IAT_RVA < SizeOfImage
    jae     il_fail
    sub     ecx, eax
    cmp     edx, ecx                    ; IAT_Size <= SizeOfImage - IAT_RVA
    ja      il_fail

    ; IAT VA in r10+rax, size already in rdx
    WINCALL VirtualProtect, addr r10+rax, rdx, PAGE_READONLY, addr rbp-16
    test    eax, eax
    jz      il_fail
    ; Lock write-once _ROINIT page (canary, pointer cookie, shadow-stack TLS, img bounds)
    WINCALL VirtualProtect, addr g_roinit_base, ROINIT_LEN, PAGE_READONLY, addr rbp-16
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
    xor     r11d, r11d                          ; A3-30: scrub last compared byte/XOR residue
    xor     r9d, r9d
    ; collapse any nonzero to exactly 1 without branching
    neg     eax                         ; CF=1 iff eax was nonzero
    sbb     eax, eax                    ; eax = -1 iff nonzero, else 0
    neg     eax                         ; eax = 1 iff different, 0 if equal
    ret
ct_memcmp endp

; =============================================================================
; tagged_alloc(rcx = user size) -> rax = user pointer, or 0 on failure
; VirtualAlloc-backed with header/footer canaries AND placed flush (within 16B
; alignment) against a trailing PAGE_NOACCESS hardware guard page (AUD-22).
; =============================================================================
public tagged_alloc
tagged_alloc proc frame
    FRAME_PROLOG 96
    ; locals: [rbp-24] user size, [rbp-32] region base, [rbp-40] hdr ptr,
    ;         [rbp-48] rw_pages, [rbp-56] oldprot

    mov     qword ptr [rbp-24], rcx
    ; span = (sizeof HEAPBLK + size + HEAP_TAIL_LEN + 15) & -16, overflow-checked
    mov     rax, rcx
    CHECK_ADD_OVF rax, (sizeof HEAPBLK) + HEAP_TAIL_LEN + 15
    and     rax, -16
    mov     r8, rax                             ; r8 = span (multiple of 16, >= 48)
    CHECK_ADD_OVF rax, 0FFFh
    and     rax, -1000h                         ; rw_pages (multiple of 4096, >= span)
    mov     qword ptr [rbp-48], rax
    mov     rdx, rax
    sub     rdx, r8                             ; pad = rw_pages - span (0 <= pad <= 0FF0h)
    mov     qword ptr [rbp-40], rdx             ; temp: pad
    CHECK_ADD_OVF rax, 1000h                    ; + 1 trailing guard page
    WINCALL VirtualAlloc, 0, rax, <MEM_RESERVE or MEM_COMMIT>, PAGE_READWRITE
    test    rax, rax
    jz      ta_fail
    mov     qword ptr [rbp-32], rax             ; region base
    mov     rcx, rax
    add     rcx, qword ptr [rbp-48]             ; guard page VA = base + rw_pages
    WINCALL VirtualProtect, rcx, 1000h, PAGE_NOACCESS, addr rbp-56
    test    eax, eax
    jz      ta_fail_free

    mov     rax, qword ptr [rbp-32]
    add     rax, qword ptr [rbp-40]             ; hdr = region_base + pad (in first page)
    mov     qword ptr [rbp-40], rax

    ; ---- fill header --------------------------------------------------------
    mov     dword ptr [rax].HEAPBLK.magic, TM_HEAPBLK
    mov     dword ptr [rax].HEAPBLK.reserved, 0
    mov     rcx, qword ptr [rbp-24]
    mov     qword ptr [rax].HEAPBLK.blksize, rcx

    lea     rcx, [rax].HEAPBLK.tag              ; random per-block tag (8 bytes)
    mov     edx, 8
    call    rng_fill
    test    eax, eax
    jz      ta_fail_free

    mov     rax, qword ptr [rbp-40]
    mov     r10, qword ptr [rax].HEAPBLK.tag
    mov     qword ptr [rax].HEAPBLK.canary, r10 ; front canary = tag
    rol     r10, 1
    mov     rcx, qword ptr [rax].HEAPBLK.blksize ; rear canary = rol(tag,1)
    lea     r11, [rax + sizeof HEAPBLK]
    mov     qword ptr [r11+rcx], r10

    lea     rax, [rax + sizeof HEAPBLK]         ; -> 16-byte-aligned user pointer
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
; double-free (wiped magic).
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
; tagged_free(rcx = user ptr) - verify header/rear canaries, wipe user + header
;   bytes, and release the underlying VirtualAlloc reservation.  NULL is a no-op.
; =============================================================================
public tagged_free
tagged_free proc frame
    FRAME_PROLOG 48
    test    rcx, rcx
    jz      tf_done
    mov     qword ptr [rbp-24], rcx
    call    tagged_check                        ; traps on overflow/corrupt/double-free
    mov     rcx, qword ptr [rbp-24]
    lea     rax, [rcx - sizeof HEAPBLK]
    mov     qword ptr [rbp-32], rax             ; hdr ptr
    mov     rdx, qword ptr [rax].HEAPBLK.blksize
    add     rdx, HEAP_TAIL_LEN
    call    secure_zero                         ; wipe user bytes + rear canary
    mov     rcx, qword ptr [rbp-32]
    mov     edx, sizeof HEAPBLK
    call    secure_zero                         ; clear TM_HEAPBLK + tags
    mov     rcx, qword ptr [rbp-32]
    and     rcx, -1000h                         ; region_base (0 <= pad <= 0FF0h < 1000h)
    WINCALL VirtualFree, rcx, 0, MEM_RELEASE
tf_done:
    FRAME_EPILOG
    ret
tagged_free endp

ifdef DBG_TRACE
; =============================================================================
; cmd_cttest (dbg probe) - coarse constant-time check for ct_memcmp: time 10k
;   4 KiB compares with the difference at the FIRST byte, then at the LAST
;   byte.  An early-exit memcmp finishes the first case ~1000x faster; the
;   constant-time compare must stay within 2x.  exit 0 = pass, 1 = fail.
; =============================================================================
.data?
align 2
ifdef DBG_TRACE
g_crashpath     dw MAX_PATH_CHARS dup (?)  ; %TEMP%\vordr_crash.bin
endif
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
endif ; DBG_TRACE

end
