; =============================================================================
; theme.asm - Vordr dark theme + procedurally generated animated background.
;
; Nothing here is an embedded image: the background is a deep "aurora" field
; computed on the fly from a tiny sine LUT (itself computed at startup) using a
; cheap separable model (per-column + per-row + per-diagonal sine bands).  The
; renderer's internal resolution and animation are scaled to the machine via
; theme_detect (CPU cores / AC vs battery), so a strong desktop gets a smooth
; full-resolution animation while a thin laptop falls back to a quiet static
; gradient.  Everything degrades, fail-closed, to a flat dark fill.
;
; All procs touch only volatile registers (rax/rcx/rdx/r8-r11) so they unwind
; cleanly back through the OS dialog callbacks without saving rbx/rsi/rdi/r12-15.
;
; Public surface (called from gui.asm dialog procs):
;   theme_boot                      - one-time: detect caps, build LUT + brushes
;   theme_attach(hwnd, defid)       - per dialog: dark titlebar, bg, anim timer
;   theme_paint(hwnd)  -> 1         - WM_PAINT: blit the background
;   theme_erase        -> 1         - WM_ERASEBKGND: suppress the default erase
;   theme_tick(hwnd)               - WM_TIMER(THEME_TIMER): advance + invalidate
;   theme_ctlcolor(hwnd,msg,hdc,hctl) -> HBRUSH  - WM_CTLCOLOR* dark colours
;   theme_drawitem(lpdis) -> 1      - WM_DRAWITEM: owner-draw buttons/groupboxes
; =============================================================================

include macros.inc

; ---- imports ----------------------------------------------------------------
extern CreateDIBSection:proc
extern CreateCompatibleDC:proc
extern DeleteDC:proc
extern DeleteObject:proc
extern SelectObject:proc
extern StretchBlt:proc
extern SetStretchBltMode:proc
extern CreateSolidBrush:proc
extern CreatePen:proc
extern CreateFontW:proc
extern SetTextColor:proc
extern SetBkColor:proc
extern SetBkMode:proc
extern GetStockObject:proc
extern RoundRect:proc

extern GetClientRect:proc
extern InvalidateRect:proc
extern BeginPaint:proc
extern EndPaint:proc
extern DrawTextW:proc
extern FillRect:proc
extern GetWindowTextW:proc
extern GetClassNameW:proc
extern GetWindowLongPtrW:proc
extern SetWindowLongPtrW:proc
extern SetTimer:proc
extern SendMessageW:proc
extern EnumChildWindows:proc
extern SetWindowTheme:proc
extern SetLayeredWindowAttributes:proc
extern GetWindowRect:proc
extern ScreenToClient:proc
extern IsWindowVisible:proc
extern GetSystemInfo:proc
extern GetSystemPowerStatus:proc
extern DwmSetWindowAttribute:proc
extern CreateDXGIFactory1:proc

; ---- message / api constants ------------------------------------------------
WM_CTLCOLOREDIT     equ 133h
WM_CTLCOLORLISTBOX  equ 134h
WM_CTLCOLORSTATIC   equ 138h
DM_SETDEFID         equ 401h
THEME_TIMER         equ 9
GWL_STYLE           equ -16
GWL_EXSTYLE         equ -20
WS_CLIPCHILDREN     equ 02000000h
WS_EX_LAYERED       equ 00080000h
LWA_ALPHA           equ 2
WIN_ALPHA           equ 250                  ; 98% of 255
DWMWA_DARK          equ 20
BI_RGB              equ 0
DIB_RGB_COLORS      equ 0
SRCCOPY             equ 0CC0020h
HALFTONE            equ 4
NULL_BRUSH          equ 5
PS_SOLID            equ 0
BS_TYPEMASK         equ 0Fh
BS_GROUPBOX         equ 7
ODS_SELECTED        equ 1
ODS_DISABLED        equ 4
ODS_DEFAULT         equ 20h
BKMODE_TRANSP       equ 1
DT_CFLAGS           equ 25h                 ; DT_CENTER|DT_VCENTER|DT_SINGLELINE
DT_LFLAGS           equ 24h                 ; DT_LEFT|DT_VCENTER|DT_SINGLELINE

; ---- flat dark palette (COLORREF 0x00BBGGRR) --------------------------------
COL_BG       equ 001E1F1Fh                  ; main window      #1F1F1E
COL_PANEL    equ 00262626h                  ; input area bg    #262626
COL_FRAME    equ 00373737h                  ; input area frame #373737
COL_BTN      equ 00262626h                  ; button face
COL_BTNSEL   equ 00333333h                  ; button face (pressed)
COL_TEXT     equ 00E9E0DFh                  ; primary text
COL_TEXTDIM  equ 00989898h                  ; secondary text
COL_BORDER   equ 00373737h                  ; hairline border  #373737
COL_ACCENT   equ 00B4D23Ah                  ; teal accent (default button)

; aurora-borealis tuning: vertical curtains rising from the horizon, a star
;   field above, slow drift.  Darker than a flat glow.
CK1 equ 5                                ; curtain streak frequencies (per column)
CK2 equ 9
CK3 equ 2                                ; broad envelope
CSTREAK equ 430                          ; streak emphasis threshold (of 765)
FKY equ 6                                ; fine filament freqs (shimmer texture)
FKX equ 3

; internal-resolution caps per tier
CAP2_W equ 480
CAP2_H equ 320
CAP1_W equ 320
CAP1_H equ 214
CAP0_W equ 208
CAP0_H equ 140
BW_MAX equ 480
BH_MAX equ 320

.data
align 8
; IID_IDXGIFactory1 {770aae78-f26f-4dba-a829-253c83d1b387}
iid_factory1 label byte
    dd      0770aae78h
    dw      0f26fh
    dw      04dbah
    db      0a8h, 029h, 025h, 03ch, 083h, 0d1h, 0b3h, 087h
g_tier      dd 2
g_anim      dd 0
g_overlay   dd 0
g_phase     dd 0
g_bw        dd 0
g_bh        dd 0
g_memdc     dq 0
g_hbm       dq 0
g_bits      dq 0
g_br_bg     dq 0
g_br_panel  dq 0
g_br_frame  dq 0
g_br_btn    dq 0
g_br_btnsel dq 0
g_pen_bd    dq 0
g_pen_acc   dq 0
g_font_big  dq 0                            ; large glyph font for toolbar buttons
g_frame_hdc dq 0                            ; EnumChildWindows frame-draw context
g_frame_par dq 0

td_dark label word                      ; control theme class for dark scrollbars
    dw 'D','a','r','k','M','o','d','e','_','E','x','p','l','o','r','e','r', 0
td_font label word                      ; toolbar glyph font face
    dw 'S','e','g','o','e',' ','U','I',0

.data?
align 16
sin_lut     db 256 dup (?)
glow_x      db BW_MAX dup (?)
glow_y      db BH_MAX dup (?)
glow_d      db (BW_MAX+BH_MAX) dup (?)
g_txtbuf    dw 160 dup (?)
g_clsbuf    dw 16 dup (?)               ; control class name (Static vs Edit)

.code

; =============================================================================
; theme_lut_init - fill sin_lut[256] with a raised parabolic sine (0..255),
;   computed (not embedded) via s = 4p(1-|p|), p in [-1,1).  Leaf, volatiles.
; =============================================================================
theme_lut_init proc
    lea     r10, [sin_lut]
    xor     r8d, r8d                        ; i
tl_loop:
    mov     eax, r8d
    shl     eax, 3
    sub     eax, 1024                        ; P = i*8 - 1024
    mov     r9d, eax                         ; P
    mov     ecx, eax
    sar     ecx, 31
    xor     eax, ecx
    sub     eax, ecx                         ; |P|
    mov     edx, 1024
    sub     edx, eax                         ; t = 1024 - |P|
    mov     eax, r9d
    imul    eax, edx                         ; sq = P * t
    imul    eax, 127
    sar     eax, 18
    add     eax, 128                         ; -> [1,255]
    mov     byte ptr [r10 + r8], al
    inc     r8d
    cmp     r8d, 256
    jb      tl_loop
    ret
theme_lut_init endp

; =============================================================================
; theme_gpu_vram -> eax = dedicated VRAM of the strongest adapter, in MiB
;   (0 if DXGI is unavailable).  Enumerates real (non-software) adapters via
;   DXGI and reports the largest DedicatedVideoMemory - the signal for "is there
;   a discrete graphics card here?".
; =============================================================================
theme_gpu_vram proc frame
    FRAME_PROLOG 416
    ; [rbp-24] factory  [rbp-32] adapter  [rbp-40] index  [rbp-48] maxvram
    ; DXGI_ADAPTER_DESC1 @ [rbp-384]  (VideoMem @ +272, Flags @ +304)
    mov     qword ptr [rbp-48], 0
    mov     qword ptr [rbp-24], 0
    WINCALL CreateDXGIFactory1, addr iid_factory1, addr rbp-24
    test    eax, eax
    jnz     gv_none
    cmp     qword ptr [rbp-24], 0
    je      gv_none
    mov     dword ptr [rbp-40], 0
gv_loop:
    mov     rcx, qword ptr [rbp-24]          ; factory (this)
    mov     r11, qword ptr [rcx]
    mov     edx, dword ptr [rbp-40]          ; adapter index
    lea     r8, [rbp-32]                     ; &adapter
    call    qword ptr [r11+96]               ; IDXGIFactory1::EnumAdapters1
    test    eax, eax
    jnz     gv_endfactory                    ; DXGI_ERROR_NOT_FOUND -> done
    mov     rcx, qword ptr [rbp-32]          ; adapter (this)
    mov     r11, qword ptr [rcx]
    lea     rdx, [rbp-384]                   ; &desc
    call    qword ptr [r11+80]               ; IDXGIAdapter1::GetDesc1
    mov     eax, dword ptr [rbp-384+304]     ; Flags
    test    eax, 2                            ; DXGI_ADAPTER_FLAG_SOFTWARE
    jnz     gv_rel
    mov     rax, qword ptr [rbp-384+272]     ; DedicatedVideoMemory
    cmp     rax, qword ptr [rbp-48]
    jbe     gv_rel
    mov     qword ptr [rbp-48], rax
gv_rel:
    mov     rcx, qword ptr [rbp-32]          ; adapter->Release
    mov     r11, qword ptr [rcx]
    call    qword ptr [r11+16]
    inc     dword ptr [rbp-40]
    cmp     dword ptr [rbp-40], 64
    jb      gv_loop
gv_endfactory:
    mov     rcx, qword ptr [rbp-24]          ; factory->Release
    mov     r11, qword ptr [rcx]
    call    qword ptr [r11+16]
    mov     rax, qword ptr [rbp-48]
    shr     rax, 20                           ; bytes -> MiB
    FRAME_EPILOG
    ret
gv_none:
    xor     eax, eax
    FRAME_EPILOG
    ret
theme_gpu_vram endp

; =============================================================================
; theme_detect - choose g_tier / g_anim from the GPU, CPU cores and power.
;   tier 2 (rich)  : a discrete GPU (>=1.5 GiB VRAM) OR a roomy CPU (>4 cores)
;   tier 1 (modest): otherwise, or on battery
;   tier 0 (static): reserved (very constrained machines fall here via caps)
; =============================================================================
theme_detect proc frame
    FRAME_PROLOG 96
    ; locals: SYSTEM_INFO @ [rbp-56], SYSTEM_POWER_STATUS @ [rbp-72]
    mov     dword ptr [g_tier], 2
    lea     rcx, [rbp-56]
    call    GetSystemInfo
    call    theme_gpu_vram                   ; eax = VRAM MiB (0 if unknown)
    mov     r9d, eax                          ; vram
    mov     r8d, dword ptr [rbp-56+32]        ; dwNumberOfProcessors
    cmp     r9d, 1536                         ; >= 1.5 GiB -> discrete GPU
    jae     td_tier2
    cmp     r8d, 4                            ; or a roomy CPU
    ja      td_tier2
    mov     dword ptr [g_tier], 1
td_tier2:
    lea     rcx, [rbp-72]
    call    GetSystemPowerStatus
    movzx   eax, byte ptr [rbp-72]           ; ACLineStatus (0 = on battery)
    cmp     al, 0
    jne     td_power_ok
    cmp     dword ptr [g_tier], 1
    jbe     td_power_ok
    mov     dword ptr [g_tier], 1
td_power_ok:
    mov     dword ptr [g_anim], 0
    cmp     dword ptr [g_tier], 1
    jb      td_done
    mov     dword ptr [g_anim], 1
td_done:
    FRAME_EPILOG
    ret
theme_detect endp

; =============================================================================
; theme_boot - one-time initialisation.
; =============================================================================
public theme_boot
theme_boot proc frame
    FRAME_PROLOG 112                          ; room for the 14-arg CreateFontW
    WINCALL CreateSolidBrush, COL_BG
    mov     qword ptr [g_br_bg], rax
    WINCALL CreateSolidBrush, COL_PANEL
    mov     qword ptr [g_br_panel], rax
    WINCALL CreateSolidBrush, COL_FRAME
    mov     qword ptr [g_br_frame], rax
    WINCALL CreateSolidBrush, COL_BTN
    mov     qword ptr [g_br_btn], rax
    WINCALL CreateSolidBrush, COL_BTNSEL
    mov     qword ptr [g_br_btnsel], rax
    WINCALL CreatePen, PS_SOLID, 1, COL_BORDER
    mov     qword ptr [g_pen_bd], rax
    WINCALL CreatePen, PS_SOLID, 1, COL_ACCENT
    mov     qword ptr [g_pen_acc], rax
    ; large semibold font for the small toolbar symbol buttons (+ pencil -)
    WINCALL CreateFontW, -18, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, addr td_font
    mov     qword ptr [g_font_big], rax
    FRAME_EPILOG
    ret
theme_boot endp

; =============================================================================
; bg_render - paint the aurora-borealis background into g_bits for g_phase:
;   a star field over a very dark sky, with green->teal->violet curtains rising
;   from the horizon (bottom).  No callees -> volatiles + locals only.
; =============================================================================
bg_render proc frame
    FRAME_PROLOG 160
    ; [rbp-24] rowptr [rbp-32] y    [rbp-40] rise [rbp-48] tintR [rbp-56] tintG
    ; [rbp-64] tintB  [rbp-72] baseR [rbp-80] baseG [rbp-88] baseB
    ; [rbp-96] x      [rbp-104] a    [rbp-112] pixaddr [rbp-120] star [rbp-128] t
    mov     ecx, dword ptr [g_bw]
    test    ecx, ecx
    jz      br_done
    ; ---- per-frame curtain[x] (vertical streak intensity) -> glow_x ----------
    lea     r10, [sin_lut]
    lea     r11, [glow_x]
    xor     r8d, r8d
brx:
    mov     eax, r8d
    imul    eax, CK1
    add     eax, dword ptr [g_phase]
    and     eax, 255
    movzx   ecx, byte ptr [r10 + rax]        ; s1
    mov     eax, r8d
    imul    eax, CK2
    sub     eax, dword ptr [g_phase]
    and     eax, 255
    movzx   r9d, byte ptr [r10 + rax]        ; s2
    add     ecx, r9d
    mov     eax, r8d
    imul    eax, CK3
    and     eax, 255
    movzx   r9d, byte ptr [r10 + rax]        ; s3 (broad envelope)
    add     ecx, r9d                          ; 0..765
    sub     ecx, CSTREAK
    jns     brx_pos
    xor     ecx, ecx
brx_pos:
    imul    ecx, 3
    shr     ecx, 2                            ; *0.75 -> emphasise streaks
    cmp     ecx, 255
    jbe     brx_cap
    mov     ecx, 255
brx_cap:
    mov     byte ptr [r11 + r8], cl
    inc     r8d
    cmp     r8d, dword ptr [g_bw]
    jb      brx
    ; ---- pixels -------------------------------------------------------------
    mov     rax, qword ptr [g_bits]
    mov     qword ptr [rbp-24], rax          ; rowptr
    mov     dword ptr [rbp-32], 0            ; y
    lea     r10, [glow_x]
    lea     r11, [sin_lut]
br_yloop:
    mov     r8d, dword ptr [rbp-32]
    cmp     r8d, dword ptr [g_bh]
    jae     br_done
    ; t = y*256/bh (vertical position 0=top .. 255=horizon)
    mov     eax, r8d
    shl     eax, 8
    cdq
    idiv    dword ptr [g_bh]
    mov     dword ptr [rbp-128], eax          ; t
    ; rise = clamp((t-90)*256/165, 0, 255) - aurora envelope, 0 up top
    sub     eax, 90
    jns     bry_r0
    xor     eax, eax
bry_r0:
    shl     eax, 8
    mov     ecx, 165
    cdq
    idiv    ecx
    cmp     eax, 255
    jbe     bry_r1
    mov     eax, 255
bry_r1:
    mov     dword ptr [rbp-40], eax           ; rise
    ; up = 255 - t  (height above horizon)
    mov     ecx, 255
    sub     ecx, dword ptr [rbp-128]          ; up
    mov     eax, ecx                          ; tintR = 15 + up*70/256
    imul    eax, 70
    shr     eax, 8
    add     eax, 15
    mov     dword ptr [rbp-48], eax
    mov     eax, ecx                          ; tintG = 210 - up*60/256
    imul    eax, 60
    shr     eax, 8
    mov     edx, 210
    sub     edx, eax
    mov     dword ptr [rbp-56], edx
    mov     eax, ecx                          ; tintB = 70 + up*90/256
    imul    eax, 90
    shr     eax, 8
    add     eax, 70
    mov     dword ptr [rbp-64], eax
    ; very dark sky base: B=4+t*14/256 G=2+t*8/256 R=1+t*5/256
    mov     eax, dword ptr [rbp-128]
    imul    eax, 14
    shr     eax, 8
    add     eax, 4
    mov     dword ptr [rbp-88], eax           ; baseB
    mov     eax, dword ptr [rbp-128]
    imul    eax, 8
    shr     eax, 8
    add     eax, 2
    mov     dword ptr [rbp-80], eax           ; baseG
    mov     eax, dword ptr [rbp-128]
    imul    eax, 5
    shr     eax, 8
    add     eax, 1
    mov     dword ptr [rbp-72], eax           ; baseR
    mov     dword ptr [rbp-96], 0            ; x
br_xloop:
    mov     edx, dword ptr [rbp-96]          ; x
    mov     r8d, dword ptr [rbp-32]          ; y
    mov     rcx, qword ptr [rbp-24]
    lea     rax, [rcx + rdx*4]
    mov     qword ptr [rbp-112], rax          ; pixaddr
    ; a = curtain[x] * rise / 256, then modulated by a fine filament
    movzx   eax, byte ptr [r10 + rdx]
    imul    eax, dword ptr [rbp-40]
    shr     eax, 8                            ; 0..255
    mov     ecx, r8d
    imul    ecx, FKY
    mov     r9d, edx
    imul    r9d, FKX
    add     ecx, r9d
    add     ecx, dword ptr [g_phase]
    and     ecx, 255
    movzx   ecx, byte ptr [r11 + rcx]         ; filament 0..255
    shr     ecx, 1
    add     ecx, 150                          ; 150..277
    imul    eax, ecx
    shr     eax, 8
    cmp     eax, 255
    jbe     br_acap
    mov     eax, 255
br_acap:
    mov     dword ptr [rbp-104], eax          ; a
    ; --- star (upper sky only, where the aurora is faint) ---
    mov     dword ptr [rbp-120], 0
    cmp     dword ptr [rbp-40], 130
    jae     br_nostar
    mov     eax, dword ptr [rbp-96]
    imul    eax, 374761393
    mov     ecx, r8d
    imul    ecx, 668265263
    add     eax, ecx
    mov     ecx, eax
    shr     ecx, 13
    xor     eax, ecx
    imul    eax, 1274126177
    mov     ecx, eax
    shr     ecx, 8
    and     ecx, 1023
    jnz     br_nostar                          ; ~1/1024 pixels is a star
    shr     eax, 18
    and     eax, 7Fh
    add     eax, 110
    mov     dword ptr [rbp-120], eax
br_nostar:
    ; --- compose channels (base + aurora tint + star), cap 255 ---
    mov     eax, dword ptr [rbp-104]
    imul    eax, dword ptr [rbp-48]           ; tintR
    shr     eax, 10
    add     eax, dword ptr [rbp-72]
    add     eax, dword ptr [rbp-120]
    cmp     eax, 255
    jbe     br_rok
    mov     eax, 255
br_rok:
    mov     rcx, qword ptr [rbp-112]
    mov     byte ptr [rcx+2], al              ; R
    mov     eax, dword ptr [rbp-104]
    imul    eax, dword ptr [rbp-56]           ; tintG
    shr     eax, 10
    add     eax, dword ptr [rbp-80]
    add     eax, dword ptr [rbp-120]
    cmp     eax, 255
    jbe     br_gok
    mov     eax, 255
br_gok:
    mov     byte ptr [rcx+1], al              ; G
    mov     eax, dword ptr [rbp-104]
    imul    eax, dword ptr [rbp-64]           ; tintB
    shr     eax, 10
    add     eax, dword ptr [rbp-88]
    add     eax, dword ptr [rbp-120]
    cmp     eax, 255
    jbe     br_bok
    mov     eax, 255
br_bok:
    mov     byte ptr [rcx+0], al              ; B
    mov     byte ptr [rcx+3], 0
    inc     dword ptr [rbp-96]
    mov     eax, dword ptr [rbp-96]
    cmp     eax, dword ptr [g_bw]
    jb      br_xloop
    mov     eax, dword ptr [g_bw]
    shl     eax, 2
    add     qword ptr [rbp-24], rax
    inc     dword ptr [rbp-32]
    jmp     br_yloop
br_done:
    FRAME_EPILOG
    ret
bg_render endp

; =============================================================================
; bg_ensure(ecx=w, edx=h) - (re)create the DIB at the internal resolution.
; =============================================================================
bg_ensure proc frame
    FRAME_PROLOG 128
    ; [rbp-24] w  [rbp-32] h  BITMAPINFOHEADER @ [rbp-80] (40)  [rbp-88] bits
    mov     dword ptr [rbp-24], ecx
    mov     dword ptr [rbp-32], edx
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_bw]
    jne     be_make
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [g_bh]
    jne     be_make
    cmp     qword ptr [g_bits], 0
    je      be_make
    jmp     be_render
be_make:
    cmp     qword ptr [g_hbm], 0
    je      be_nofree1
    WINCALL DeleteObject, qword ptr [g_hbm]
    mov     qword ptr [g_hbm], 0
be_nofree1:
    cmp     qword ptr [g_memdc], 0
    je      be_nofree2
    WINCALL DeleteDC, qword ptr [g_memdc]
    mov     qword ptr [g_memdc], 0
be_nofree2:
    ; zero the BITMAPINFOHEADER (10 dwords) then set fields
    xor     eax, eax
    mov     dword ptr [rbp-80], eax
    mov     dword ptr [rbp-76], eax
    mov     dword ptr [rbp-72], eax
    mov     dword ptr [rbp-68], eax
    mov     dword ptr [rbp-64], eax
    mov     dword ptr [rbp-60], eax
    mov     dword ptr [rbp-56], eax
    mov     dword ptr [rbp-52], eax
    mov     dword ptr [rbp-48], eax
    mov     dword ptr [rbp-44], eax
    mov     dword ptr [rbp-80], 40            ; biSize
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [rbp-76], eax           ; biWidth
    mov     eax, dword ptr [rbp-32]
    neg     eax
    mov     dword ptr [rbp-72], eax           ; biHeight (top-down)
    mov     word ptr [rbp-68], 1              ; biPlanes
    mov     word ptr [rbp-66], 32             ; biBitCount
    mov     dword ptr [rbp-64], BI_RGB        ; biCompression
    WINCALL CreateDIBSection, 0, addr rbp-80, DIB_RGB_COLORS, addr rbp-88, 0, 0
    test    rax, rax
    jz      be_fail
    mov     qword ptr [g_hbm], rax
    mov     rax, qword ptr [rbp-88]
    mov     qword ptr [g_bits], rax
    WINCALL CreateCompatibleDC, 0
    test    rax, rax
    jz      be_fail
    mov     qword ptr [g_memdc], rax
    WINCALL SelectObject, qword ptr [g_memdc], qword ptr [g_hbm]
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_bw], eax
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [g_bh], eax
be_render:
    call    bg_render
    mov     eax, 1
    FRAME_EPILOG
    ret
be_fail:
    mov     qword ptr [g_bits], 0
    mov     dword ptr [g_bw], 0
    mov     dword ptr [g_bh], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
bg_ensure endp

; theme_dark_cb(rcx=hwnd, rdx=lparam) -> BOOL - give each control the dark
;   "explorer" theme so its scrollbars/borders render dark.  EnumChildWindows cb.
theme_dark_cb proc
    sub     rsp, 40
    lea     rdx, [td_dark]
    xor     r8, r8
    call    SetWindowTheme
    add     rsp, 40
    mov     eax, 1
    ret
theme_dark_cb endp

; =============================================================================
; theme_attach(rcx=hwnd, edx=defid)
; =============================================================================
public theme_attach
theme_attach proc frame
    FRAME_PROLOG 96
    ; [rbp-24] hwnd  [rbp-32] defid  [rbp-40] dwmflag  RECT @ [rbp-64]
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [rbp-40], 1
    WINCALL DwmSetWindowAttribute, qword ptr [rbp-24], DWMWA_DARK, addr rbp-40, 4
    WINCALL GetWindowLongPtrW, qword ptr [rbp-24], GWL_STYLE
    or      rax, WS_CLIPCHILDREN            ; clip children so the frame ring isn't overpainted
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], GWL_STYLE, rax
    ; translucent window: WS_EX_LAYERED + 92% alpha
    WINCALL GetWindowLongPtrW, qword ptr [rbp-24], GWL_EXSTYLE
    or      rax, WS_EX_LAYERED
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], GWL_EXSTYLE, rax
    WINCALL SetLayeredWindowAttributes, qword ptr [rbp-24], 0, WIN_ALPHA, LWA_ALPHA
    ; dark scrollbars/borders on the standard controls (listbox, multiline edits)
    WINCALL EnumChildWindows, qword ptr [rbp-24], addr theme_dark_cb, 0
    cmp     dword ptr [rbp-32], 0
    je      ta_done
    WINCALL SendMessageW, qword ptr [rbp-24], DM_SETDEFID, qword ptr [rbp-32], 0
ta_done:
    FRAME_EPILOG
    ret
theme_attach endp

; =============================================================================
; theme_tick(rcx=hwnd)
; =============================================================================
public theme_tick
theme_tick proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    cmp     qword ptr [g_bits], 0
    je      tt_done
    inc     dword ptr [g_phase]
    call    bg_render
    WINCALL InvalidateRect, qword ptr [rbp-24], 0, 0
tt_done:
    FRAME_EPILOG
    ret
theme_tick endp

; =============================================================================
; theme_paint(rcx=hwnd) -> 1
; =============================================================================
public theme_paint
theme_paint proc frame
    FRAME_PROLOG 224
    ; [rbp-24] hwnd  [rbp-32] hdc  PAINTSTRUCT @ [rbp-120] (72)  RECT @ [rbp-152]
    mov     qword ptr [rbp-24], rcx
    cmp     qword ptr [g_bits], 0
    je      tp_flat
    WINCALL BeginPaint, qword ptr [rbp-24], addr rbp-120
    mov     qword ptr [rbp-32], rax           ; hdc
    WINCALL GetClientRect, qword ptr [rbp-24], addr rbp-152
    WINCALL SetStretchBltMode, qword ptr [rbp-32], HALFTONE
    WINCALL StretchBlt, qword ptr [rbp-32], 0, 0, dword ptr [rbp-152+8], dword ptr [rbp-152+12], \
            qword ptr [g_memdc], 0, 0, dword ptr [g_bw], dword ptr [g_bh], SRCCOPY
    ; when the settings overlay is open, paint an opaque dark backdrop over the
    ; aurora so the (transparent) menu controls read against a solid page
    cmp     dword ptr [g_overlay], 0
    je      tp_done
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-152, qword ptr [g_br_bg]
tp_done:
    WINCALL EndPaint, qword ptr [rbp-24], addr rbp-120
    mov     eax, 1
    FRAME_EPILOG
    ret
tp_flat:
    xor     eax, eax
    FRAME_EPILOG
    ret
theme_paint endp

; =============================================================================
; theme_overlay(ecx = 0/1) - mark the settings overlay open so theme_paint draws
;   an opaque backdrop.
; =============================================================================
public theme_overlay
theme_overlay proc
    mov     dword ptr [g_overlay], ecx
    ret
theme_overlay endp

; frame_cb(rcx=child, rdx=lparam) -> BOOL - draw a #373737 frame around each
;   visible Edit / ListBox so the input areas are segmented.  EnumChildWindows cb.
frame_cb proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96                          ; [rbp-8] child  RECT @ [rbp-40]
    mov     qword ptr [rbp-8], rcx
    mov     rcx, qword ptr [rbp-8]
    call    IsWindowVisible
    test    eax, eax
    jz      fc_skip
    mov     rcx, qword ptr [rbp-8]
    lea     rdx, [g_clsbuf]
    mov     r8d, 16
    call    GetClassNameW
    movzx   eax, word ptr [g_clsbuf]
    cmp     eax, 'E'                          ; "Edit"
    je      fc_frame
    cmp     eax, 'L'                          ; "ListBox"
    je      fc_frame
    jmp     fc_skip
fc_frame:
    mov     rcx, qword ptr [rbp-8]
    lea     rdx, [rbp-40]
    call    GetWindowRect                     ; screen rect
    mov     rcx, qword ptr [g_frame_par]
    lea     rdx, [rbp-40]                     ; top-left point
    call    ScreenToClient
    mov     rcx, qword ptr [g_frame_par]
    lea     rdx, [rbp-32]                     ; bottom-right point
    call    ScreenToClient
    dec     dword ptr [rbp-40]                ; inflate by 1px
    dec     dword ptr [rbp-36]
    inc     dword ptr [rbp-32]
    inc     dword ptr [rbp-28]
    mov     rcx, qword ptr [g_frame_hdc]
    lea     rdx, [rbp-40]
    mov     r8, qword ptr [g_br_frame]
    call    FillRect
fc_skip:
    mov     eax, 1
    mov     rsp, rbp
    pop     rbp
    ret
frame_cb endp

; =============================================================================
; theme_erase(rcx=hdc, rdx=hwnd) -> 1 - flat #1F1F1E fill + segment input frames.
; =============================================================================
public theme_erase
theme_erase proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx           ; hdc
    mov     qword ptr [rbp-32], rdx           ; hwnd
    WINCALL GetClientRect, qword ptr [rbp-32], addr rbp-72
    WINCALL FillRect, qword ptr [rbp-24], addr rbp-72, qword ptr [g_br_bg]
    mov     eax, 1
    FRAME_EPILOG
    ret
theme_erase endp

; =============================================================================
; theme_backdrop -> HBRUSH - opaque dark brush for the burger-menu backdrop.
; =============================================================================
public theme_backdrop
theme_backdrop proc
    mov     rax, qword ptr [g_br_bg]
    ret
theme_backdrop endp

; =============================================================================
; theme_ctlcolor(rcx=hwnd, rdx=msg, r8=hdc, r9=hctl) -> HBRUSH
; =============================================================================
public theme_ctlcolor
theme_ctlcolor proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], r8            ; hdc
    mov     qword ptr [rbp-32], rdx           ; msg
    mov     qword ptr [rbp-40], r9            ; hctl
    cmp     rdx, WM_CTLCOLORLISTBOX
    je      tc_panel
    cmp     rdx, WM_CTLCOLOREDIT
    je      tc_panel
    cmp     rdx, WM_CTLCOLORSTATIC
    je      tc_static
    ; dialog background / checkbox / radio text -> opaque near-black, light text
    WINCALL SetTextColor, qword ptr [rbp-24], COL_TEXT
    WINCALL SetBkMode, qword ptr [rbp-24], BKMODE_TRANSP
    mov     rax, qword ptr [g_br_bg]
    FRAME_EPILOG
    ret
tc_static:
    ; read-only edits also arrive here -> give them the input colour; real
    ; Static labels blend into the #1F1F1E window.
    WINCALL GetClassNameW, qword ptr [rbp-40], addr g_clsbuf, 16
    movzx   eax, word ptr [g_clsbuf]
    cmp     eax, 'E'
    je      tc_panel
    WINCALL SetTextColor, qword ptr [rbp-24], COL_TEXT
    WINCALL SetBkMode, qword ptr [rbp-24], BKMODE_TRANSP
    mov     rax, qword ptr [g_br_bg]
    FRAME_EPILOG
    ret
tc_panel:
    WINCALL SetTextColor, qword ptr [rbp-24], COL_TEXT
    WINCALL SetBkColor, qword ptr [rbp-24], COL_PANEL
    mov     rax, qword ptr [g_br_panel]
    FRAME_EPILOG
    ret
theme_ctlcolor endp

; =============================================================================
; theme_drawitem(rcx=lpdis) -> 1
; =============================================================================
public theme_drawitem
theme_drawitem proc frame
    FRAME_PROLOG 176
    ; [rbp-24] lpdis [rbp-32] hdc [rbp-40] hwndItem [rbp-48] state [rbp-56] style
    ; rcItem @ [rbp-80] (L,T,R,B)   [rbp-112] frameTop temp
    mov     qword ptr [rbp-24], rcx
    mov     rax, qword ptr [rcx+32]
    mov     qword ptr [rbp-32], rax           ; hDC
    mov     rax, qword ptr [rcx+24]
    mov     qword ptr [rbp-40], rax           ; hwndItem
    mov     eax, dword ptr [rcx+16]
    mov     dword ptr [rbp-48], eax           ; itemState
    mov     eax, dword ptr [rcx+40]
    mov     dword ptr [rbp-80], eax           ; left
    mov     eax, dword ptr [rcx+44]
    mov     dword ptr [rbp-76], eax           ; top
    mov     eax, dword ptr [rcx+48]
    mov     dword ptr [rbp-72], eax           ; right
    mov     eax, dword ptr [rcx+52]
    mov     dword ptr [rbp-68], eax           ; bottom
    ; ODT_STATIC (5) = the burger-overlay backdrop -> opaque dark fill
    mov     eax, dword ptr [rcx]              ; CtlType
    cmp     eax, 5
    jne     tdi_notstatic
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-80, qword ptr [g_br_bg]
    mov     eax, 1
    FRAME_EPILOG
    ret
tdi_notstatic:
    mov     eax, dword ptr [rcx+40]
    mov     dword ptr [rbp-80], eax           ; left
    mov     eax, dword ptr [rcx+44]
    mov     dword ptr [rbp-76], eax           ; top
    mov     eax, dword ptr [rcx+48]
    mov     dword ptr [rbp-72], eax           ; right
    mov     eax, dword ptr [rcx+52]
    mov     dword ptr [rbp-68], eax           ; bottom
    WINCALL GetWindowLongPtrW, qword ptr [rbp-40], GWL_STYLE
    mov     dword ptr [rbp-56], eax
    WINCALL GetWindowTextW, qword ptr [rbp-40], addr g_txtbuf, 159
    WINCALL SetBkMode, qword ptr [rbp-32], BKMODE_TRANSP
    mov     eax, dword ptr [rbp-56]
    and     eax, BS_TYPEMASK
    cmp     eax, BS_GROUPBOX
    je      tdi_group
    ; ---------- push button --------------------------------------------------
    mov     rax, qword ptr [g_br_btn]
    test    dword ptr [rbp-48], ODS_SELECTED
    jz      tdi_face
    mov     rax, qword ptr [g_br_btnsel]
tdi_face:
    WINCALL SelectObject, qword ptr [rbp-32], rax
    mov     rax, qword ptr [g_pen_bd]
    test    dword ptr [rbp-48], ODS_DEFAULT
    jz      tdi_pen
    mov     rax, qword ptr [g_pen_acc]
tdi_pen:
    WINCALL SelectObject, qword ptr [rbp-32], rax
    WINCALL RoundRect, qword ptr [rbp-32], dword ptr [rbp-80], dword ptr [rbp-76], \
            dword ptr [rbp-72], dword ptr [rbp-68], 8, 8
    mov     ecx, COL_TEXT
    test    dword ptr [rbp-48], ODS_DISABLED
    jz      tdi_tcol
    mov     ecx, COL_TEXTDIM
tdi_tcol:
    WINCALL SetTextColor, qword ptr [rbp-32], rcx
    ; small toolbar buttons (narrow) get the large glyph font for clarity
    mov     eax, dword ptr [rbp-72]
    sub     eax, dword ptr [rbp-80]
    cmp     eax, 32
    jge     tdi_dt
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_big]
    mov     qword ptr [rbp-112], rax           ; old font
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_txtbuf, -1, addr rbp-80, DT_CFLAGS
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-112]
    mov     eax, 1
    FRAME_EPILOG
    ret
tdi_dt:
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_txtbuf, -1, addr rbp-80, DT_CFLAGS
    mov     eax, 1
    FRAME_EPILOG
    ret
    ; ---------- group box ----------------------------------------------------
tdi_group:
    WINCALL GetStockObject, NULL_BRUSH
    WINCALL SelectObject, qword ptr [rbp-32], rax
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_pen_bd]
    mov     eax, dword ptr [rbp-76]
    add     eax, 5
    mov     dword ptr [rbp-112], eax          ; frame top below caption
    WINCALL RoundRect, qword ptr [rbp-32], dword ptr [rbp-80], dword ptr [rbp-112], \
            dword ptr [rbp-72], dword ptr [rbp-68], 8, 8
    WINCALL SetTextColor, qword ptr [rbp-32], COL_TEXTDIM
    mov     eax, dword ptr [rbp-80]
    add     eax, 9
    mov     dword ptr [rbp-80], eax           ; caption left indent
    mov     eax, dword ptr [rbp-76]
    add     eax, 12
    mov     dword ptr [rbp-68], eax           ; caption band bottom = top+12
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_txtbuf, -1, addr rbp-80, DT_LFLAGS
    mov     eax, 1
    FRAME_EPILOG
    ret
theme_drawitem endp

end
