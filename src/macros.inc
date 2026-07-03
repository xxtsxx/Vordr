; =============================================================================
; macros.inc - shared constants, structures and hardening macros
; =============================================================================
; Every non-leaf procedure in this project uses the FRAME_PROLOG /
; FRAME_EPILOG pair.  Together they provide, per call:
;   1. a proper SEH unwind frame        (.pushreg / .setframe / .allocstack)
;   2. a stack canary                   (random cookie, checked on exit)
;   3. a software shadow-stack entry    (return address verified on exit)
; Any violation terminates the process immediately via __fastfail (int 29h),
; which the kernel treats as a non-continuable, non-handlable fault.
; =============================================================================

OPTION CASEMAP:NONE

; ---------------------------------------------------------------------------
; Exit codes (see manifest.md section 10)
; ---------------------------------------------------------------------------
EXIT_OK             equ 0
EXIT_USAGE          equ 1
EXIT_IO             equ 2
EXIT_AUTH           equ 3
EXIT_CORRUPT        equ 4
EXIT_OOM            equ 5
EXIT_NOCPU          equ 6
EXIT_SELFTEST       equ 7
EXIT_NOSPACE        equ 8          ; insufficient free disk space (pre-flight)
EXIT_LOCKED         equ 9          ; vault is locked / wrong master password

DISK_MARGIN         equ 100000h    ; 1 MiB slack added to free-space estimates

; ---------------------------------------------------------------------------
; __fastfail codes (int 29h, rcx = code).  2/10 are the documented Windows
; codes for cookie / indirect-call failures; codes >= 0F000h are ours.
; ---------------------------------------------------------------------------
FF_STACK_COOKIE     equ 2          ; FAST_FAIL_STACK_COOKIE_CHECK_FAILURE
FF_GUARD_ICALL      equ 10         ; FAST_FAIL_GUARD_ICALL_CHECK_FAILURE
FF_SHADOW_STACK     equ 0F001h     ; software shadow stack mismatch
FF_HEAP_TAG         equ 0F002h     ; temporal heap tag / canary violation
FF_TYPE_MAGIC       equ 0F003h     ; struct type-magic mismatch
FF_BOUNDS           equ 0F004h     ; bounds check failed
FF_OVERFLOW         equ 0F005h     ; integer overflow in size arithmetic

; ---------------------------------------------------------------------------
; CPU feature flag bits kept in g_cpu_features (set once in cpu_gate)
; ---------------------------------------------------------------------------
CPUF_AESNI          equ 1          ; leaf 1  ecx[25]
CPUF_PCLMUL         equ 2          ; leaf 1  ecx[1]
CPUF_SSE41          equ 4          ; leaf 1  ecx[19]
CPUF_SHANI          equ 8          ; leaf 7  ebx[29]
CPUF_AVX2           equ 16         ; leaf 7  ebx[5]
CPUF_RDSEED         equ 32         ; leaf 7  ebx[18]

; ---------------------------------------------------------------------------
; Limits (input validation)
; ---------------------------------------------------------------------------
MAX_ARGS            equ 256        ; argv[0] + up to 255 file inputs
MAX_PATH_CHARS      equ 8000h      ; 32768 UTF-16 units (Windows extended-length max)
MAX_PASSWORD_BYTES  equ 1024       ; UTF-8 bytes after conversion
MIN_PASSWORD_BYTES  equ 1

ARGON2_MIN_T        equ 1
ARGON2_MAX_T        equ 16
ARGON2_MIN_M_KIB    equ 8192       ; 8 MiB
ARGON2_MAX_M_KIB    equ 4194304    ; 4 GiB
ARGON2_DEF_T        equ 3
ARGON2_DEF_M_KIB    equ 524288     ; 512 MiB (tuned for ~600-700ms with AVX2)

KCV_LEN             equ 16         ; key-check value bytes (SHA-256(key) prefix)

; ===========================================================================
; Vordr vault file format (see docs/formats.md).  A fixed 80-byte header (the
; 64-byte parameter block plus a 16-byte key-check value) is used verbatim as
; the GCM AAD.  The KCV = SHA-256(key)[0..15] lets a wrong master password be
; rejected right after the KDF (and makes the scheme key-committing).  Each
; write uses a fresh CSPRNG salt/nonce and is committed atomically via a temp
; file + MoveFileExW.
; ---------------------------------------------------------------------------
VAULT_MAGIC         equ 52445256h  ; "VRDR" little-endian  - the single vault file
VAULT_VERSION       equ 1

VAULT_HDR struct
    magic       dd ?               ; "VRDR"
    version     dd ?               ; 1
    t_cost      dd ?               ; Argon2id passes
    m_cost_kib  dd ?               ; Argon2id memory (KiB)
    lanes       dd ?               ; Argon2id parallelism (always 1)
    salt        db 32 dup (?)      ; CSPRNG salt
    nonce       db 12 dup (?)      ; GCM nonce
VAULT_HDR ends
VAULT_KCV_OFFSET    equ (sizeof VAULT_HDR)               ; 64
VAULT_HDR_BYTES     equ (sizeof VAULT_HDR) + KCV_LEN     ; 80 (full header = AAD)

; Entry record TLV field type tags (UTF-8 values, every length BOUND_CHECKed)
VF_TITLE            equ 1
VF_USERNAME         equ 2
VF_SECRET           equ 3
VF_URL              equ 4
VF_NOTES            equ 5
VF_TAGS             equ 6
VF_TOTP             equ 7          ; base32 TOTP secret (RFC 6238)
VF_TEXT             equ 8          ; generic single-line text (custom fields)
VF_IMAGE            equ 9          ; raw encoded image bytes (PNG/JPEG/BMP)
VF_FILE             equ 10         ; generic file attachment (any bytes + filename)
VF_FAV              equ 11         ; reserved marker: entry is a favorite (value "1")
VF_ICON             equ 12         ; reserved: custom icon override, value = 12 hex
                                   ;   chars "GGGGCCCCCCCC" (glyph codepoint + COLORREF)
; A stored field type carries the base kind in its low byte; VF_LABELED in the
; high byte marks a field whose value bytes are prefixed with a custom label:
;   labeled: bytes = u16 labellen | label_utf8 | value_utf8
;   plain:   bytes = value_utf8
VF_LABELED          equ 8000h      ; "this field carries a custom label" flag
VF_KINDMASK         equ 00FFh      ; mask to recover the base kind from a type

; Export format selector (consolidated Export dialog / ze_compose)
EXP_EXCEL           equ 0          ; encrypted .xlsx (or plain .xlsx inside the zip)
EXP_CSV             equ 1          ; CSV text (always wrapped in the encrypted zip)
EXP_JSON            equ 2          ; vordr.json (always wrapped in the encrypted zip)

; Password generator styles (pwgen_ex) + options
PWS_RANDOM          equ 0          ; n random chars from the class mask (opt low nibble)
PWS_PASSPHRASE      equ 1          ; n words from the embedded list, 8 bits/word
PWS_PRONOUNCE       equ 2          ; n chars, alternating consonant/vowel (readable)
PWS_PIN             equ 3          ; n decimal digits
PWS_HEX             equ 4          ; n lowercase hex chars
PWO_CAP             equ 100h       ; capitalize each word / first letter
PWO_DIGIT           equ 200h       ; append a random digit
PWO_DASH            equ 400h       ; separate passphrase words with '-'
PWO_NOAMBIG         equ 800h       ; random: drop ambiguous glyphs (0O1lI)
MAX_LABEL_BYTES     equ 128        ; bound on a single field's custom label
; GUI->vault_build_entry descriptor marker (in the g_field_list type qword, never
; stored): the value pointer is a raw binary blob {u32 len, bytes}, not wide text.
VFL_RAW             equ 40000000h
VAULT_ID_LEN        equ 16         ; per-entry random id
MAX_ENTRY_BYTES     equ 65536      ; bound on a single serialized entry
MAX_FIELD_BYTES     equ 16384      ; bound on a single TLV field

; ---------------------------------------------------------------------------
; Struct type magics (TYPE_CHECK targets)
; ---------------------------------------------------------------------------
TM_HEAPBLK          equ 48504C42h  ; "BLPH" heap block header

; ---------------------------------------------------------------------------
; Software shadow stack
; ---------------------------------------------------------------------------
SSTK_CAPACITY       equ 4096       ; max simultaneous frames (entries)

; landing-pad magic for DLPV - emitted in front of every indirect-call target
LP_MAGIC            equ 0D1B7C0DEFACEB00Ch

; =============================================================================
; FRAME_PROLOG localbytes
; -----------------------------------------------------------------------------
; Use immediately after "name PROC FRAME".  localbytes = bytes you need for
; locals INCLUDING the 32-byte shadow space for any calls you make.  The
; macro adds the canary slot and rounds to 16.
;
; Resulting frame layout:
;   [rbp+8]              return address (verified against shadow stack)
;   [rbp]                saved rbp
;   [rbp-8]              stack canary
;   [rbp-16 ... down]    your locals
;   [rsp .. rsp+31]      shadow space for callees (bottom of frame)
;
; Clobbers rax, r10, r11 (all volatile, never argument registers).
; =============================================================================
FRAME_PROLOG macro localbytes
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, ((localbytes + 8 + 15) AND 0FFFFFFF0h)
    .allocstack ((localbytes + 8 + 15) AND 0FFFFFFF0h)
    .endprolog
    ; ---- plant stack canary ------------------------------------------------
    mov     rax, qword ptr [g_stack_canary]
    mov     qword ptr [rbp-8], rax
    ; ---- push return address onto software shadow stack --------------------
    mov     r10, qword ptr [g_sstk_index]
    cmp     r10, SSTK_CAPACITY
    jae     sstk_overflow_fail              ; shared fail stub (hardening.asm)
    mov     r11, qword ptr [g_sstk_base]
    mov     rax, qword ptr [rbp+8]          ; our return address
    mov     qword ptr [r11+r10*8], rax
    inc     r10
    mov     qword ptr [g_sstk_index], r10
endm

; =============================================================================
; FRAME_EPILOG - place immediately before "ret".
; Verifies canary + shadow stack, restores rsp/rbp.
; Preserves rax/rdx/xmm0 (return values).  Clobbers r10, r11.
; =============================================================================
FRAME_EPILOG macro
    local ok1, ok2
    ; ---- verify stack canary ------------------------------------------------
    mov     r10, qword ptr [g_stack_canary]
    cmp     r10, qword ptr [rbp-8]
    je      ok1
    mov     ecx, FF_STACK_COOKIE
    jmp     ff_trap
ok1:
    ; ---- pop + verify software shadow stack --------------------------------
    mov     r10, qword ptr [g_sstk_index]
    test    r10, r10
    jz      @F
    dec     r10
    mov     qword ptr [g_sstk_index], r10
    mov     r11, qword ptr [g_sstk_base]
    mov     r11, qword ptr [r11+r10*8]
    cmp     r11, qword ptr [rbp+8]
    je      ok2
@@:
    mov     ecx, FF_SHADOW_STACK
    jmp     ff_trap
ok2:
    mov     rsp, rbp
    pop     rbp
endm

; =============================================================================
; LANDING_PAD - emit before any label that is the target of an indirect call.
; CALL_GUARDED validates the 8-byte magic at [entry-8] before transferring.
;
; Layout must guarantee the magic sits EXACTLY 8 bytes before the proc entry
; no matter how MASM aligns the following PROC (1..16).  We align to 16, then
; emit 8 bytes of filler + the 8-byte magic, leaving the cursor on a 16-byte
; boundary.  Any proc alignment of <=16 then places the entry right there, so
; [entry-8] is always the magic.
; =============================================================================
LANDING_PAD macro
    align   16
    dq      0CCCCCCCCCCCCCCCCh          ; filler (never executed)
    dq      LP_MAGIC
    align   16
endm

; CALL_GUARDED reg - DLPV-validated indirect call through 'reg'
CALL_GUARDED macro reg
    local ok
    mov     r11, LP_MAGIC
    cmp     r11, qword ptr [reg-8]
    je      ok
    mov     ecx, FF_GUARD_ICALL
    jmp     ff_trap
ok:
    call    reg
endm

; =============================================================================
; Integer-overflow-checked arithmetic on unsigned sizes.  Fail-closed.
; =============================================================================
CHECK_ADD_OVF macro dst, src        ; dst = dst + src, fastfail on carry
    local ok
    add     dst, src
    jnc     ok
    mov     ecx, FF_OVERFLOW
    jmp     ff_trap
ok:
endm

CHECK_SUB_OVF macro dst, src        ; dst = dst - src, fastfail on borrow
    local ok
    sub     dst, src
    jnc     ok
    mov     ecx, FF_OVERFLOW
    jmp     ff_trap
ok:
endm

; rax = rax * src, fastfail if result exceeds 64 bits.  Clobbers rdx.
CHECK_MUL_OVF macro src
    local ok
    mul     src
    jnc     ok
    mov     ecx, FF_OVERFLOW
    jmp     ff_trap
ok:
endm

; =============================================================================
; BOUND_CHECK index, limit - fastfail unless index < limit (unsigned)
; =============================================================================
BOUND_CHECK macro index, limit
    local ok
    cmp     index, limit
    jb      ok
    mov     ecx, FF_BOUNDS
    jmp     ff_trap
ok:
endm

; =============================================================================
; TYPE_CHECK preg, magic32 - verify struct type tag (first dword of struct)
; (parameter must not be named "ptr" - that is a MASM keyword)
; =============================================================================
TYPE_CHECK macro preg, magic32
    local ok
    cmp     dword ptr [preg], magic32
    je      ok
    mov     ecx, FF_TYPE_MAGIC
    jmp     ff_trap
ok:
endm

; =============================================================================
; FASTFAIL code - unconditional immediate termination
; =============================================================================
FASTFAIL macro code
    mov     ecx, code
    jmp     ff_trap
endm

; =============================================================================
; WINCALL fn, arg1, arg2, ...  -- call with the Win64 calling convention.
;
; The first four arguments load into rcx, rdx, r8, r9; the fifth onward land on
; the caller's shadow space at [rsp+32], [rsp+40], ...  An argument written as
; "addr X" passes the ADDRESS of X via lea (required under /highentropyva, where
; a 32-bit absolute "mov reg, offset X" is illegal); any other argument passes
; its value with mov.  An argument already sitting in its destination register
; is skipped.
;
; Register arguments are emitted rcx-LAST (r9, r8, rdx, rcx) so a value arriving
; in rcx can still be used as the source for the later arguments -- e.g.
;   WINCALL VirtualAlloc, 0, rcx, <MEM_RESERVE or MEM_COMMIT>, PAGE_READWRITE
; copies the incoming rcx into rdx before rcx is overwritten with 0.  (Cross
; dependencies among rdx/r8/r9 are not auto-resolved; stage those via r10/r11.)
;
; Clobbers rax (scratch for address / memory stack arguments).
;
; !!! FOOTGUN: because rax is the scratch for `addr X` / 64-bit-memory STACK args
; (5th+), which are emitted BEFORE the register args, DO NOT pass a 1st-4th
; argument that is sourced from rax/eax (e.g. a bare `eax` holding a count) when
; any 5th+ argument is `addr X` or a 64-bit memory value.  The `lea rax,[X]` for
; that stack arg overwrites eax first, so the register arg then loads garbage.
; Stage such a value in a non-rax register (r8d/r9d) and pass THAT instead.  (This
; caused a chaotic, ASLR-dependent cchWideChar bug in ze_compose - 2026-07.)
;
; Ordering: stack arguments (5th+) are stored BEFORE the register arguments are
; loaded.  This is safe unless a register argument's SOURCE is a memory slot that
; a stack-argument DESTINATION overwrites -- which only happens when a proc's
; locals overlap its outgoing-argument area (a small frame passing many args).
; In that rare case (see create_ctl) keep the call hand-written.
; =============================================================================
; load one register argument, matching the destination width to the operand
; (a 32-bit operand zero-extends into the 32-bit dest, exactly like the original
; "mov r8d, edx" hand-code; type()==4 means a 32-bit register or dword memory).
__WREGARG macro op:req, dst:req, dst32:req
    if @InStr(1, <&op&>, <addr >) eq 1
        lea     dst, [@SubStr(<&op&>, 6)]
    elseifidni <&op&>, <&dst&>
        ; already in the destination register -- nothing to do
    elseifidni <&op&>, <&dst32&>
        ; already in the low half of the destination -- nothing to do
    elseif (type (op)) eq 4
        mov     dst32, op
    else
        mov     dst, op
    endif
endm

__WSTKARG macro op:req, off:req
    if @InStr(1, <&op&>, <addr >) eq 1
        lea     rax, [@SubStr(<&op&>, 6)]
        mov     qword ptr [rsp+off], rax
    elseif (opattr (op)) AND 004h          ; absolute constant -> direct store
        mov     qword ptr [rsp+off], op
    elseif (type (op)) eq 4                ; 32-bit reg/mem -> zero-extend via eax
        mov     eax, op
        mov     qword ptr [rsp+off], rax
    elseif (opattr (op)) AND 010h          ; 64-bit register -> direct store
        mov     qword ptr [rsp+off], op
    else                                   ; 64-bit memory value -> via rax
        mov     rax, op
        mov     qword ptr [rsp+off], rax
    endif
endm

WINCALL macro fn:req, args:VARARG
    local n
    n = 0
    for a, <args>
        n = n + 1
        if n eq 1
            __WA1 textequ <a>
        elseif n eq 2
            __WA2 textequ <a>
        elseif n eq 3
            __WA3 textequ <a>
        elseif n eq 4
            __WA4 textequ <a>
        else
            __WSTKARG <a>, %(32 + 8 * (n - 5))
        endif
    endm
    if n ge 4
        __WREGARG %__WA4, r9, r9d
    endif
    if n ge 3
        __WREGARG %__WA3, r8, r8d
    endif
    if n ge 2
        __WREGARG %__WA2, rdx, edx
    endif
    if n ge 1
        __WREGARG %__WA1, rcx, ecx
    endif
    call    fn
endm

; =============================================================================
; Structured conditionals.  ml64 has no high-level .IF/.ELSE/.ENDIF, so these
; build the equivalent from cmp + jcc.  The condition code is given EXPLICITLY
; (e/ne, unsigned a/ae/b/be, signed g/ge/l/le, z/nz/s/ns), which keeps the
; signed-vs-unsigned choice in the author's hands -- no hidden default.
;
;   xIF  rax, e, 0          ; if rax == 0
;       ...
;   xELIF rax, a, 100h      ; else if (unsigned) rax > 0x100
;       ...
;   xELSE
;       ...
;   xENDIF
;
;   xIFT rcx               ; "if rcx != 0" (test rcx,rcx; taken when nonzero)
;   xIFZ rcx               ; "if rcx == 0"
;
; Nesting is supported (a per-depth sequence id is stacked).  The condition is
; the TAKEN condition for the then-block; the macro emits the inverse jump.
; =============================================================================
__cf_seq   = 0
__cf_depth = 0

; map a taken condition code -> the opposite jump mnemonic (to skip the block)
__cf_jinv macro cc, lbl
    ifidni <cc>, <e>
        jne lbl
    elseifidni <cc>, <z>
        jnz lbl
    elseifidni <cc>, <ne>
        je  lbl
    elseifidni <cc>, <nz>
        jz  lbl
    elseifidni <cc>, <a>
        jbe lbl
    elseifidni <cc>, <ae>
        jb  lbl
    elseifidni <cc>, <b>
        jae lbl
    elseifidni <cc>, <be>
        ja  lbl
    elseifidni <cc>, <g>
        jle lbl
    elseifidni <cc>, <ge>
        jl  lbl
    elseifidni <cc>, <l>
        jge lbl
    elseifidni <cc>, <le>
        jg  lbl
    elseifidni <cc>, <s>
        jns lbl
    elseifidni <cc>, <ns>
        js  lbl
    else
        .err <xIF: unknown condition code cc>
    endif
endm

; per-depth state:
;   __cf_chain_<d>   = id of the (stable) end label for this if/elif/else chain
;   __cf_cur_<d>     = id of the CURRENT branch's false label
;   __cf_haselse_<d> = 1 once xELSE has been emitted
xIF macro lhs:req, cc:req, rhs:req
    __cf_seq   = __cf_seq + 1
    __cf_depth = __cf_depth + 1
    @CatStr(<__cf_chain_>, %__cf_depth)   = __cf_seq
    @CatStr(<__cf_cur_>, %__cf_depth)     = __cf_seq
    @CatStr(<__cf_haselse_>, %__cf_depth) = 0
    cmp     lhs, rhs
    __cf_jinv cc, @CatStr(<__cf_false_>, %__cf_seq)
endm

; test-style entry: xIFT reg -> if reg != 0 ; xIFZ reg -> if reg == 0
xIFT macro reg:req
    __cf_seq   = __cf_seq + 1
    __cf_depth = __cf_depth + 1
    @CatStr(<__cf_chain_>, %__cf_depth)   = __cf_seq
    @CatStr(<__cf_cur_>, %__cf_depth)     = __cf_seq
    @CatStr(<__cf_haselse_>, %__cf_depth) = 0
    test    reg, reg
    jz      @CatStr(<__cf_false_>, %__cf_seq)
endm
xIFZ macro reg:req
    __cf_seq   = __cf_seq + 1
    __cf_depth = __cf_depth + 1
    @CatStr(<__cf_chain_>, %__cf_depth)   = __cf_seq
    @CatStr(<__cf_cur_>, %__cf_depth)     = __cf_seq
    @CatStr(<__cf_haselse_>, %__cf_depth) = 0
    test    reg, reg
    jnz     @CatStr(<__cf_false_>, %__cf_seq)
endm

xELSE macro
    __cf_a = @CatStr(<__cf_chain_>, %__cf_depth)
    __cf_b = @CatStr(<__cf_cur_>, %__cf_depth)
    @CatStr(<__cf_haselse_>, %__cf_depth) = 1
    jmp     @CatStr(<__cf_end_>, %__cf_a)
    @CatStr(<__cf_false_>, %__cf_b):
endm

; else-if: close the current then with a jump to end, open a fresh compare
xELIF macro lhs:req, cc:req, rhs:req
    __cf_a = @CatStr(<__cf_chain_>, %__cf_depth)
    __cf_b = @CatStr(<__cf_cur_>, %__cf_depth)
    jmp     @CatStr(<__cf_end_>, %__cf_a)
    @CatStr(<__cf_false_>, %__cf_b):
    __cf_seq = __cf_seq + 1
    @CatStr(<__cf_cur_>, %__cf_depth) = __cf_seq
    cmp     lhs, rhs
    __cf_jinv cc, @CatStr(<__cf_false_>, %__cf_seq)
endm

xENDIF macro
    __cf_a = @CatStr(<__cf_chain_>, %__cf_depth)
    __cf_b = @CatStr(<__cf_cur_>, %__cf_depth)
    if (@CatStr(<__cf_haselse_>, %__cf_depth)) eq 0
        @CatStr(<__cf_false_>, %__cf_b):    ; no else: false target == end
    endif
    @CatStr(<__cf_end_>, %__cf_a):
    __cf_depth = __cf_depth - 1
endm

; =============================================================================
; Structured top-tested loops (ml64 also has no .WHILE).  Same explicit-cc rule.
;
;   xWHILE qword ptr [rbp-40], ne, 0     ; while (remaining != 0)
;       ...
;       xIFZ eax                          ; (xBREAK / xCONTINUE work too)
;           xBREAK
;       xENDIF
;   xENDW
;
;   xWHILET reg   ; while reg != 0   (test reg,reg)
;   xWHILEZ reg   ; while reg == 0
;
; Nesting supported; xBREAK / xCONTINUE target the innermost loop.
; =============================================================================
__lp_seq   = 0
__lp_depth = 0

xWHILE macro lhs:req, cc:req, rhs:req
    __lp_seq   = __lp_seq + 1
    __lp_depth = __lp_depth + 1
    @CatStr(<__lp_id_>, %__lp_depth) = __lp_seq
    @CatStr(<__lp_top_>, %__lp_seq):
    cmp     lhs, rhs
    __cf_jinv cc, @CatStr(<__lp_end_>, %__lp_seq)
endm
xWHILET macro reg:req
    __lp_seq   = __lp_seq + 1
    __lp_depth = __lp_depth + 1
    @CatStr(<__lp_id_>, %__lp_depth) = __lp_seq
    @CatStr(<__lp_top_>, %__lp_seq):
    test    reg, reg
    jz      @CatStr(<__lp_end_>, %__lp_seq)
endm
xWHILEZ macro reg:req
    __lp_seq   = __lp_seq + 1
    __lp_depth = __lp_depth + 1
    @CatStr(<__lp_id_>, %__lp_depth) = __lp_seq
    @CatStr(<__lp_top_>, %__lp_seq):
    test    reg, reg
    jnz     @CatStr(<__lp_end_>, %__lp_seq)
endm
xENDW macro
    __lp_t = @CatStr(<__lp_id_>, %__lp_depth)
    jmp     @CatStr(<__lp_top_>, %__lp_t)
    @CatStr(<__lp_end_>, %__lp_t):
    __lp_depth = __lp_depth - 1
endm
xBREAK macro
    __lp_t = @CatStr(<__lp_id_>, %__lp_depth)
    jmp     @CatStr(<__lp_end_>, %__lp_t)
endm
xCONTINUE macro
    __lp_t = @CatStr(<__lp_id_>, %__lp_depth)
    jmp     @CatStr(<__lp_top_>, %__lp_t)
endm

; =============================================================================
; ASCII string in .const with automatic length constant:
;   CSTR msg_hello, "hello", 13, 10
; defines  msg_hello  and  msg_hello_len
; =============================================================================
CSTR macro name, text:VARARG
    name db text
    name&_len equ $ - name
endm

; UTF-16 string literal:  WSTR cmd_encrypt, <encrypt>
; (text inside <> may not contain commas; use multiple WSTRs or raw dw)
WSTR macro name, text
    name label word
    forc c, <text>
        dw '&c'
    endm
    dw 0
endm

; ---------------------------------------------------------------------------
; Globals owned by hardening.asm, referenced by the frame macros everywhere
; ---------------------------------------------------------------------------
externdef g_stack_canary:qword
externdef g_sstk_base:qword
externdef g_sstk_index:qword
externdef g_cpu_features:dword
externdef sstk_overflow_fail:near
externdef ff_trap:near                  ; central fail handler (main.asm)
