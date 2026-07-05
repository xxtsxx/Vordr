; =============================================================================
; theme.asm - Vordr dark theme (flat dark background + owner-drawn controls).
;
; The window background is a solid dark fill: theme_erase paints the dark
; background brush on WM_ERASEBKGND, and theme_paint returns "unhandled" so the
; default paint uses it.  Brushes/pens/fonts are (re)built by theme_rebrush from
; the active colour scheme (theme_set_scheme, cycled by the settings menu).
;
; NOTE: a procedural "aurora" animation path also lives here (bg_render + sin_lut
; into a DIB, driven by a WM_TIMER through theme_tick, blitted by theme_paint).
; It is currently INACTIVE: the DIB is never created (g_bits stays 0), so both
; theme_tick and theme_paint short-circuit to the flat fill.  It is retained,
; guarded and harmless, pending a decision to either wire it up or remove it.
;
; All procs touch only volatile registers (rax/rcx/rdx/r8-r11) so they unwind
; cleanly back through the OS dialog callbacks without saving rbx/rsi/rdi/r12-15.
;
; Public surface (called from gui.asm dialog procs):
;   theme_boot                      - one-time: build the colour scheme + brushes
;   theme_attach(hwnd, defid)       - per dialog: dark titlebar, bg, anim timer
;   theme_paint(hwnd)               - WM_PAINT: flat fill / sidebar card
;   theme_erase        -> 1         - WM_ERASEBKGND: paint the dark background
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
extern GradientFill:proc
extern CreateRoundRectRgn:proc
extern SelectClipRgn:proc
extern Ellipse:proc

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
extern GetDlgItem:proc
extern SetTimer:proc
extern RedrawWindow:proc
extern SendMessageW:proc
extern EnumChildWindows:proc
extern SetWindowTheme:proc
extern SetLayeredWindowAttributes:proc
extern GetWindowRect:proc
extern ScreenToClient:proc
extern GetFocus:proc
extern GetDlgCtrlID:proc
extern MapDialogRect:proc
extern GetParent:proc
extern g_vaulthwnd:qword              ; the DLG_VAULT window (sidebar card only there)
IDC_V_SEARCH_TH equ 232               ; = IDC_V_SEARCH in gui.asm (sidebar search box)
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
GWL_USERDATA        equ -21                  ; 1 = Fluent accent (primary) button
WS_CLIPCHILDREN     equ 02000000h
WS_EX_LAYERED       equ 00080000h
LWA_ALPHA           equ 2
WIN_ALPHA           equ 255                  ; 100% (fully opaque)
DWMWA_DARK          equ 20
DWMWA_CORNER        equ 33                   ; DWMWA_WINDOW_CORNER_PREFERENCE
DWMWCP_ROUND        equ 2                    ; rounded corners (Fluent)
SRCCOPY             equ 0CC0020h
HALFTONE            equ 4
NULL_BRUSH          equ 5
PS_SOLID            equ 0
WHITE_BRUSH         equ 0
NULL_PEN            equ 8
BS_TYPEMASK         equ 0Fh
BS_GROUPBOX         equ 7
ODS_SELECTED        equ 1
ODS_DISABLED        equ 4
BKMODE_TRANSP       equ 1
DT_CFLAGS           equ 25h                 ; DT_CENTER|DT_VCENTER|DT_SINGLELINE
DT_LFLAGS           equ 24h                 ; DT_LEFT|DT_VCENTER|DT_SINGLELINE

; ---- palette (COLORREF 0x00BBGGRR) -----------------------------------------
; The live UI colours are the runtime g_col_* globals (see the schemes[] table
; further down); only text-on-accent stays constant.
COL_ONACC    equ 00000000h                  ; text on accent fill          #000000

; aurora-borealis tuning: vertical curtains rising from the horizon, a star
;   field above, slow drift.  Darker than a flat glow.
CK1 equ 5                                ; curtain streak frequencies (per column)
CK2 equ 9
CK3 equ 2                                ; broad envelope
CSTREAK equ 430                          ; streak emphasis threshold (of 765)
FKY equ 6                                ; fine filament freqs (shimmer texture)
FKX equ 3

; internal-resolution caps per tier
BW_MAX equ 480
BH_MAX equ 320

.data
align 8
; IID_IDXGIFactory1 {770aae78-f26f-4dba-a829-253c83d1b387}
g_overlay   dd 0
g_phase     dd 0
g_bw        dd 0
g_bh        dd 0
g_memdc     dq 0
g_bits      dq 0
; ---- runtime-selectable colour scheme -------------------------------------
; g_col_* are 13 consecutive dwords (order matches each schemes[] row).
public g_scheme, g_col_bg, g_col_panel, g_col_text, g_col_textdim, g_col_frame, g_col_dark
public g_col_side, g_col_accent, g_col_filebadge
g_scheme    dd 0
align 4
g_col_bg    dd 00202020h
g_col_panel dd 002D2D2Dh
g_col_frame dd 003D3D3Dh
g_col_btn   dd 002D2D2Dh
g_col_btnsel dd 002A2A2Ah
g_col_text  dd 00FFFFFFh
g_col_textdim dd 00C8C8C8h
g_col_border dd 003D3D3Dh
g_col_accent dd 00FFC24Ch
g_col_accsel dd 00DBA03Ah
g_col_focus dd 00FFC24Ch
g_col_dark  dd 1
g_col_side  dd 00342A26h                  ; sidebar (list + search) panel colour
g_col_filebadge dd 00544A3Ah              ; attachment/file chip fill (distinct from bg/panel)
SCHEME_DW   equ 14                        ; dwords per scheme row
SCHEME_COUNT equ 9
SCHEME_RAINBOW equ 8                       ; purple base; accent surfaces get a static rainbow gradient
schemes label dword
    ; bg       panel     frame     btn       btnsel    text      textdim   border    accent    accsel    focus     dark  side      filebadge
    dd 00202020h,002D2D2Dh,003D3D3Dh,002D2D2Dh,002A2A2Ah,00FFFFFFh,00C8C8C8h,003D3D3Dh,00FFC24Ch,00DBA03Ah,00FFC24Ch,1,00342A26h,00544A3Ah  ; Dark
    dd 00F3F3F3h,00FFFFFFh,00D2D2D2h,00FFFFFFh,00E6E6E6h,00202020h,00707070h,00D2D2D2h,00C26A00h,00A05800h,00C26A00h,0,00FFFFFFh,00E8DCC8h  ; Light
    dd 001A1410h,00282018h,00403420h,00282018h,00201810h,00FFF0E0h,00C0B0A0h,00403420h,00E0C040h,00B09020h,00E0C040h,1,00170F0Fh,00504028h  ; Midnight
    dd 00000000h,00151515h,00808080h,00202020h,00404040h,00FFFFFFh,00E0E0E0h,00808080h,0000FFFFh,0000C0C0h,0000FFFFh,1,001E0C0Ch,00404040h  ; Contrast
    dd 00E3F6FDh,00D5E8EEh,00A1A193h,00D5E8EEh,00C8DAE0h,00756E58h,00969483h,00A1A193h,00D28B26h,00A86F1Eh,00D28B26h,0,00B0E4EFh,00C8D8C0h  ; Solarized
    dd 00D8ECF4h,00E0F3FBh,00A8C8D8h,00E0F3FBh,00C0DFEAh,002A3B4Bh,00556A7Ah,00A8C8D8h,001D65B5h,00144E90h,001D65B5h,0,00C4D2D6h,00CCDCE4h  ; Sepia
    dd 0040342Eh,0052423Bh,006A564Ch,0052423Bh,005E4C43h,00F4EFECh,00E9DED8h,006A564Ch,00D0C088h,00B0A06Fh,00D0C088h,1,004F4039h,00786858h  ; Nord
    dd 00F3F0FFh,00FFFFFFh,00D0C8F0h,00FFFFFFh,00E4DCFAh,00302A3Ah,00746A8Ah,00D0C8F0h,006C33D6h,005A28B0h,006C33D6h,0,00F8E0E9h,00E0D0F0h  ; Rose
    dd 00181420h,00241E30h,00443A5Ah,00241E30h,00302842h,00FFFFFFh,00C8C8C8h,00443A5Ah,00FF5A96h,00D24678h,00FF5A96h,1,001E1628h,003C3050h  ; Rainbow (purple base, gradient accents)
g_br_bg     dq 0
g_br_side   dq 0                            ; sidebar (list + search) fill
g_br_panel  dq 0
g_br_frame  dq 0
g_br_btn    dq 0
g_br_btnsel dq 0
g_br_accent dq 0                            ; Fluent accent fill (primary button)
g_br_accsel dq 0                            ; Fluent accent fill pressed
g_br_dim    dq 0                            ; #C8C8C8 (toggle off thumb)
g_pen_bd    dq 0
g_pen_acc   dq 0
g_pen_focus dq 0                            ; 2px accent focus underline
g_font_big  dq 0                            ; large glyph font for toolbar buttons
public g_font_icon
g_font_icon dq 0                            ; Segoe Fluent Icons (PUA glyph buttons)
public g_font_totp
g_font_totp dq 0                            ; slightly larger font for the TOTP code
g_frame_hdc dq 0                            ; EnumChildWindows frame-draw context
g_frame_par dq 0
; Optional per-control focus-underline colour override (used by the export
; password dialog to show strength/match in the field's own underline instead
; of a separate bar).  ctl = control id to recolour, br = HBRUSH (0 = default).
public g_uline_ctl, g_uline_br, g_uline_ctl2, g_uline_br2
g_uline_ctl  dd 0
g_uline_br   dq 0
g_uline_ctl2 dd 0
g_uline_br2  dq 0

; 7 rainbow boundary colours (COLOR16 = value<<8) for the Rainbow scheme's
; horizontal gradient fills: red, yellow, green, cyan, blue, magenta, red.
rb_grad label word                      ; [7][3] = R,G,B per stop
    dw 0FF00h,0,0
    dw 0FF00h,0FF00h,0
    dw 0,0FF00h,0
    dw 0,0FF00h,0FF00h
    dw 0,0,0FF00h
    dw 0FF00h,0,0FF00h
    dw 0FF00h,0,0
td_dark label word                      ; control theme class for dark scrollbars
    dw 'D','a','r','k','M','o','d','e','_','E','x','p','l','o','r','e','r', 0
td_light label word                     ; control theme class for light scrollbars
    dw 'E','x','p','l','o','r','e','r', 0
td_font label word                      ; toolbar glyph font face
    dw 'S','e','g','o','e',' ','U','I',0
td_iconfont label word                  ; Fluent icon font (PUA glyphs e.g. trashcan)
    dw 'S','e','g','o','e',' ','F','l','u','e','n','t',' ','I','c','o','n','s',0

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
; theme_boot - one-time initialisation.
; =============================================================================
public theme_boot
theme_boot proc frame
    FRAME_PROLOG 112                          ; room for the 14-arg CreateFontW
    mov     ecx, dword ptr [g_scheme]         ; build brushes/pens from the active scheme
    call    theme_set_scheme
    ; large semibold font for the small toolbar symbol buttons (+ pencil)
    WINCALL CreateFontW, -18, 0, 0, 0, 100, 0, 0, 0, 1, 0, 0, 5, 0, addr td_font
    mov     qword ptr [g_font_big], rax
    ; Fluent icon font for PUA glyph buttons (the trashcan)
    WINCALL CreateFontW, -18, 0, 0, 0, 100, 0, 0, 0, 1, 0, 0, 5, 0, addr td_iconfont
    mov     qword ptr [g_font_icon], rax
    ; slightly larger semibold font for the live TOTP code box
    WINCALL CreateFontW, -16, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, addr td_font
    mov     qword ptr [g_font_totp], rax
    FRAME_EPILOG
    ret
theme_boot endp

; =============================================================================
; theme_del_gdi(rcx = &handle) - DeleteObject the handle if non-zero, then 0 it.
; =============================================================================
theme_del_gdi proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    mov     rcx, qword ptr [rcx]
    test    rcx, rcx
    jz      tdg_done
    call    DeleteObject
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [r10], 0
tdg_done:
    FRAME_EPILOG
    ret
theme_del_gdi endp

; =============================================================================
; theme_rebrush - (re)create the scheme brushes/pens from g_col_*.
; =============================================================================
theme_rebrush proc frame
    FRAME_PROLOG 48
    lea     rcx, [g_br_bg]
    call    theme_del_gdi
    lea     rcx, [g_br_side]
    call    theme_del_gdi
    lea     rcx, [g_br_panel]
    call    theme_del_gdi
    lea     rcx, [g_br_frame]
    call    theme_del_gdi
    lea     rcx, [g_br_btn]
    call    theme_del_gdi
    lea     rcx, [g_br_btnsel]
    call    theme_del_gdi
    lea     rcx, [g_br_accent]
    call    theme_del_gdi
    lea     rcx, [g_br_accsel]
    call    theme_del_gdi
    lea     rcx, [g_br_dim]
    call    theme_del_gdi
    lea     rcx, [g_pen_bd]
    call    theme_del_gdi
    lea     rcx, [g_pen_acc]
    call    theme_del_gdi
    lea     rcx, [g_pen_focus]
    call    theme_del_gdi
    WINCALL CreateSolidBrush, dword ptr [g_col_bg]
    mov     qword ptr [g_br_bg], rax
    WINCALL CreateSolidBrush, dword ptr [g_col_side]
    mov     qword ptr [g_br_side], rax
    WINCALL CreateSolidBrush, dword ptr [g_col_panel]
    mov     qword ptr [g_br_panel], rax
    WINCALL CreateSolidBrush, dword ptr [g_col_frame]
    mov     qword ptr [g_br_frame], rax
    WINCALL CreateSolidBrush, dword ptr [g_col_btn]
    mov     qword ptr [g_br_btn], rax
    WINCALL CreateSolidBrush, dword ptr [g_col_btnsel]
    mov     qword ptr [g_br_btnsel], rax
    WINCALL CreateSolidBrush, dword ptr [g_col_accent]
    mov     qword ptr [g_br_accent], rax
    WINCALL CreateSolidBrush, dword ptr [g_col_accsel]
    mov     qword ptr [g_br_accsel], rax
    WINCALL CreateSolidBrush, dword ptr [g_col_textdim]
    mov     qword ptr [g_br_dim], rax
    WINCALL CreatePen, PS_SOLID, 1, dword ptr [g_col_border]
    mov     qword ptr [g_pen_bd], rax
    WINCALL CreatePen, PS_SOLID, 1, dword ptr [g_col_accent]
    mov     qword ptr [g_pen_acc], rax
    WINCALL CreatePen, PS_SOLID, 2, dword ptr [g_col_focus]
    mov     qword ptr [g_pen_focus], rax
    FRAME_EPILOG
    ret
theme_rebrush endp

; =============================================================================
; theme_set_scheme(ecx = index) - select a colour scheme: copy its colours into
;   g_col_* and rebuild the brushes/pens.  Clamps out-of-range to 0 (Dark).
; =============================================================================
public theme_set_scheme
theme_set_scheme proc frame
    FRAME_PROLOG 48
    cmp     ecx, SCHEME_COUNT
    jb      tss_ok
    xor     ecx, ecx
tss_ok:
    mov     dword ptr [g_scheme], ecx
    mov     eax, ecx
    imul    eax, eax, SCHEME_DW*4
    lea     r10, [schemes]
    add     r10, rax
    lea     r11, [g_col_bg]
    xor     eax, eax
tss_cp:
    cmp     eax, SCHEME_DW
    jae     tss_done
    mov     edx, dword ptr [r10+rax*4]
    mov     dword ptr [r11+rax*4], edx
    inc     eax
    jmp     tss_cp
tss_done:
    call    theme_rebrush
    FRAME_EPILOG
    ret
theme_set_scheme endp

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


; theme_dark_cb(rcx=hwnd, rdx=lparam) -> BOOL - give each control the explorer
;   theme so its scrollbars/borders match the scheme: DarkMode_Explorer for dark
;   schemes, plain Explorer (light) otherwise.  EnumChildWindows callback.
theme_dark_cb proc
    sub     rsp, 40
    lea     rdx, [td_dark]
    cmp     dword ptr [g_col_dark], 0        ; light scheme -> light scrollbars
    jne     tdc_go
    lea     rdx, [td_light]
tdc_go:
    xor     r8, r8
    call    SetWindowTheme
    add     rsp, 40
    mov     eax, 1
    ret
theme_dark_cb endp

; theme_scrollbars(rcx=hwnd) - re-theme every child control's scrollbars to match
;   the current scheme (call after a scheme switch so they follow dark<->light).
public theme_scrollbars
theme_scrollbars proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    WINCALL EnumChildWindows, qword ptr [rbp-24], addr theme_dark_cb, 0
    FRAME_EPILOG
    ret
theme_scrollbars endp

; =============================================================================
; theme_attach(rcx=hwnd, edx=defid)
; =============================================================================
public theme_attach
theme_attach proc frame
    FRAME_PROLOG 96
    ; [rbp-24] hwnd  [rbp-32] defid  [rbp-40] dwmflag  RECT @ [rbp-64]
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     eax, dword ptr [g_col_dark]         ; dark title bar only for dark schemes
    mov     dword ptr [rbp-40], eax
    WINCALL DwmSetWindowAttribute, qword ptr [rbp-24], DWMWA_DARK, addr rbp-40, 4
    mov     dword ptr [rbp-40], DWMWCP_ROUND          ; Fluent rounded window corners
    WINCALL DwmSetWindowAttribute, qword ptr [rbp-24], DWMWA_CORNER, addr rbp-40, 4
    WINCALL GetWindowLongPtrW, qword ptr [rbp-24], GWL_STYLE
    or      rax, WS_CLIPCHILDREN            ; clip children so the frame ring isn't overpainted
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], GWL_STYLE, rax
    ; WS_EX_LAYERED at full (100%) alpha — opaque window
    WINCALL GetWindowLongPtrW, qword ptr [rbp-24], GWL_EXSTYLE
    or      rax, WS_EX_LAYERED
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], GWL_EXSTYLE, rax
    WINCALL SetLayeredWindowAttributes, qword ptr [rbp-24], 0, WIN_ALPHA, LWA_ALPHA
    ; dark scrollbars/borders on the standard controls (listbox, multiline edits)
    WINCALL EnumChildWindows, qword ptr [rbp-24], addr theme_dark_cb, 0
    cmp     dword ptr [rbp-32], 0
    je      ta_done
    WINCALL SendMessageW, qword ptr [rbp-24], DM_SETDEFID, dword ptr [rbp-32], 0
    ; tag the default button so theme_drawitem paints it as the accent primary
    WINCALL GetDlgItem, qword ptr [rbp-24], dword ptr [rbp-32]
    WINCALL SetWindowLongPtrW, rax, GWL_USERDATA, 1
ta_done:
    FRAME_EPILOG
    ret
theme_attach endp

; =============================================================================
; theme_rainbow_fill(rcx=hdc, edx=L, r8d=T, r9d=R, [rbp+48]=B, [rbp+56]=radius) -
;   fill a rounded rect with a static horizontal rainbow gradient (6 segments via
;   GradientFill, clipped to a rounded region).  Used by the Rainbow scheme for
;   the accent surfaces (primary buttons, toggle-on tracks).
; =============================================================================
public theme_rainbow_fill
theme_rainbow_fill proc frame
    FRAME_PROLOG 160
    mov     qword ptr [rbp-24], rcx           ; hdc
    mov     dword ptr [rbp-28], edx           ; L
    mov     dword ptr [rbp-32], r8d           ; T
    mov     dword ptr [rbp-36], r9d           ; R
    mov     eax, dword ptr [rbp+48]
    mov     dword ptr [rbp-40], eax           ; B
    mov     eax, dword ptr [rbp+56]
    mov     dword ptr [rbp-44], eax           ; radius
    mov     eax, dword ptr [rbp-36]           ; w = R - L
    sub     eax, dword ptr [rbp-28]
    mov     dword ptr [rbp-48], eax
    cmp     eax, 0
    jle     trf_done
    WINCALL CreateRoundRectRgn, dword ptr [rbp-28], dword ptr [rbp-32], \
            dword ptr [rbp-36], dword ptr [rbp-40], dword ptr [rbp-44], dword ptr [rbp-44]
    mov     qword ptr [rbp-56], rax
    WINCALL SelectClipRgn, qword ptr [rbp-24], qword ptr [rbp-56]
    lea     r10, [rbp-104]                    ; GRADIENT_RECT {0,1}
    mov     dword ptr [r10], 0
    mov     dword ptr [r10+4], 1
    mov     dword ptr [rbp-60], 0             ; seg
trf_seg:
    cmp     dword ptr [rbp-60], 6
    jae     trf_unclip
    mov     eax, dword ptr [rbp-60]           ; xL = L + seg*w/6
    imul    eax, dword ptr [rbp-48]
    cdq
    mov     ecx, 6
    idiv    ecx
    add     eax, dword ptr [rbp-28]
    mov     r8d, eax                          ; xL
    mov     eax, dword ptr [rbp-60]
    inc     eax
    cmp     eax, 6
    jne     trf_xr
    mov     r9d, dword ptr [rbp-36]           ; last segment -> R exactly
    jmp     trf_verts
trf_xr:
    imul    eax, dword ptr [rbp-48]
    cdq
    mov     ecx, 6
    idiv    ecx
    add     eax, dword ptr [rbp-28]
    mov     r9d, eax                          ; xR
trf_verts:
    lea     r10, [rbp-96]                     ; v0 = { xL, T, rb_grad[seg] }
    mov     dword ptr [r10], r8d
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [r10+4], eax
    mov     eax, dword ptr [rbp-60]
    imul    eax, eax, 6
    lea     r11, [rb_grad]
    add     r11, rax
    movzx   ecx, word ptr [r11]
    mov     word ptr [r10+8], cx
    movzx   ecx, word ptr [r11+2]
    mov     word ptr [r10+10], cx
    movzx   ecx, word ptr [r11+4]
    mov     word ptr [r10+12], cx
    mov     word ptr [r10+14], 0
    lea     r10, [rbp-80]                     ; v1 = { xR, B, rb_grad[seg+1] }
    mov     dword ptr [r10], r9d
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r10+4], eax
    mov     eax, dword ptr [rbp-60]
    inc     eax
    imul    eax, eax, 6
    lea     r11, [rb_grad]
    add     r11, rax
    movzx   ecx, word ptr [r11]
    mov     word ptr [r10+8], cx
    movzx   ecx, word ptr [r11+2]
    mov     word ptr [r10+10], cx
    movzx   ecx, word ptr [r11+4]
    mov     word ptr [r10+12], cx
    mov     word ptr [r10+14], 0
    WINCALL GradientFill, qword ptr [rbp-24], addr rbp-96, 2, addr rbp-104, 1, 0
    inc     dword ptr [rbp-60]
    jmp     trf_seg
trf_unclip:
    WINCALL SelectClipRgn, qword ptr [rbp-24], 0
    WINCALL DeleteObject, qword ptr [rbp-56]
trf_done:
    FRAME_EPILOG
    ret
theme_rainbow_fill endp

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

; col_darken(ecx=col, edx=factor[0..256]) -> eax = per-channel col*factor/256   leaf
col_darken proc
    movzx   eax, cl
    imul    eax, edx
    shr     eax, 8
    mov     r9d, eax
    mov     eax, ecx
    shr     eax, 8
    movzx   eax, al
    imul    eax, edx
    shr     eax, 8
    shl     eax, 8
    or      r9d, eax
    mov     eax, ecx
    shr     eax, 16
    movzx   eax, al
    imul    eax, edx
    shr     eax, 8
    shl     eax, 16
    or      r9d, eax
    mov     eax, r9d
    ret
col_darken endp

; =============================================================================
; theme_sidecard(rcx=hwnd, rdx=hdc) - draw the sidebar as a rounded, 1px-bordered
;   card in the scheme sidebar colour, with a thin drop shadow, sized to the
;   list + search box (they sit inside it and blend via the same fill colour).
; =============================================================================
theme_sidecard proc frame
    FRAME_PROLOG 192
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    ; card bounds in DLU (list+search bbox, outset ~3 DLU so the edge/round shows)
    mov     dword ptr [rbp-64], 27
    mov     dword ptr [rbp-60], 7
    mov     dword ptr [rbp-56], 205
    mov     dword ptr [rbp-52], 308
    WINCALL MapDialogRect, qword ptr [rbp-24], addr rbp-64
    mov     eax, dword ptr [rbp-64]
    mov     dword ptr [rbp-72], eax           ; card L
    mov     eax, dword ptr [rbp-60]
    mov     dword ptr [rbp-68], eax           ; card T
    mov     eax, dword ptr [rbp-56]
    mov     dword ptr [rbp-76], eax           ; card R
    mov     eax, dword ptr [rbp-52]
    mov     dword ptr [rbp-80], eax           ; card B
    ; ---- drop shadow (offset +2,+3), NULL pen ----
    WINCALL GetStockObject, 8                 ; NULL_PEN
    WINCALL SelectObject, qword ptr [rbp-32], rax
    mov     qword ptr [rbp-104], rax          ; old pen
    mov     ecx, dword ptr [g_col_bg]         ; shadow = darkened window bg
    mov     edx, 176
    call    col_darken
    WINCALL CreateSolidBrush, eax
    mov     qword ptr [rbp-88], rax           ; shadow brush
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-88]
    mov     qword ptr [rbp-96], rax           ; old brush
    mov     eax, dword ptr [rbp-72]
    add     eax, 2
    mov     dword ptr [rbp-112], eax          ; shadow L
    mov     eax, dword ptr [rbp-68]
    add     eax, 3
    mov     dword ptr [rbp-116], eax          ; shadow T
    mov     eax, dword ptr [rbp-76]
    add     eax, 2
    mov     dword ptr [rbp-120], eax          ; shadow R
    mov     eax, dword ptr [rbp-80]
    add     eax, 3
    mov     dword ptr [rbp-124], eax          ; shadow B
    WINCALL RoundRect, qword ptr [rbp-32], dword ptr [rbp-112], dword ptr [rbp-116], \
            dword ptr [rbp-120], dword ptr [rbp-124], 14, 14
    ; ---- the card: side fill + 1px border pen ----
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_pen_bd]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_br_side]
    WINCALL RoundRect, qword ptr [rbp-32], dword ptr [rbp-72], dword ptr [rbp-68], \
            dword ptr [rbp-76], dword ptr [rbp-80], 14, 14
    ; restore GDI objects, free the shadow brush
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-104]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-96]
    WINCALL DeleteObject, qword ptr [rbp-88]
    FRAME_EPILOG
    ret
theme_sidecard endp

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
    jne     tp_ovl
    mov     rax, qword ptr [rbp-24]           ; sidebar card only on the vault window
    cmp     rax, qword ptr [g_vaulthwnd]
    jne     tp_done
    mov     rcx, qword ptr [rbp-24]           ; else draw the sidebar card
    mov     rdx, qword ptr [rbp-32]
    call    theme_sidecard
    jmp     tp_done
tp_ovl:
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

; frame_cb(rcx=child, rdx=lparam) -> BOOL - draw a Fluent bottom-border underline
;   under each visible Edit: 1px #3D3D3D at rest, 2px accent when focused.
;   EnumChildWindows callback.  src RECT @ [rbp-40], underline RECT @ [rbp-72].
frame_cb proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 112
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
    cmp     eax, 'E'                          ; only "Edit" controls get the underline
    jne     fc_skip
    mov     rcx, qword ptr [rbp-8]            ; row-card edits (id >= 3000) sit on filled
    call    GetDlgCtrlID                      ;   panels -> no underline (clean cards)
    mov     dword ptr [rbp-80], eax           ; remember this control's id
    cmp     eax, 3000                         ; IDC_DYN_BASE
    jae     fc_skip
    mov     rcx, qword ptr [rbp-8]
    lea     rdx, [rbp-40]
    call    GetWindowRect                     ; screen rect L,T,R,B
    mov     rcx, qword ptr [g_frame_par]
    lea     rdx, [rbp-40]                     ; left/top -> client
    call    ScreenToClient
    mov     rcx, qword ptr [g_frame_par]
    lea     rdx, [rbp-32]                     ; right/bottom -> client
    call    ScreenToClient
    ; underline rect spans the field width, sitting on its bottom edge
    mov     eax, dword ptr [rbp-40]           ; left
    mov     dword ptr [rbp-72], eax
    mov     eax, dword ptr [rbp-32]           ; right
    mov     dword ptr [rbp-64], eax
    mov     eax, dword ptr [rbp-28]           ; bottom (B)
    mov     dword ptr [rbp-68], eax           ; underline top = B
    call    GetFocus
    cmp     rax, qword ptr [rbp-8]
    je      fc_focus
    mov     eax, dword ptr [rbp-28]
    add     eax, 1
    mov     dword ptr [rbp-60], eax           ; 1px
    mov     r8, qword ptr [g_br_frame]
    jmp     fc_fill
fc_focus:
    mov     eax, dword ptr [rbp-28]
    add     eax, 2
    mov     dword ptr [rbp-60], eax           ; 2px
    mov     r8, qword ptr [g_br_accent]       ; default accent
    ; per-control colour override (strength / match underline)?
    mov     ecx, dword ptr [rbp-80]
    cmp     ecx, dword ptr [g_uline_ctl]
    jne     fc_ov2
    cmp     qword ptr [g_uline_br], 0
    je      fc_fill
    mov     r8, qword ptr [g_uline_br]
    jmp     fc_fill
fc_ov2:
    cmp     ecx, dword ptr [g_uline_ctl2]
    jne     fc_fill
    cmp     qword ptr [g_uline_br2], 0
    je      fc_fill
    mov     r8, qword ptr [g_uline_br2]
fc_fill:
    mov     rcx, qword ptr [g_frame_hdc]
    lea     rdx, [rbp-72]
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
    cmp     dword ptr [g_overlay], 0          ; draw the sidebar card (flat path)
    jne     te_noside
    mov     rax, qword ptr [rbp-32]           ; only on the vault window
    cmp     rax, qword ptr [g_vaulthwnd]
    jne     te_noside
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-24]
    call    theme_sidecard
te_noside:
    ; Fluent input underlines: 1px rest / 2px accent-on-focus under each Edit
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [g_frame_hdc], rax
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [g_frame_par], rax
    WINCALL EnumChildWindows, qword ptr [rbp-32], addr frame_cb, 0
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
    je      tc_side
    cmp     rdx, WM_CTLCOLOREDIT
    je      tc_edit
    cmp     rdx, WM_CTLCOLORSTATIC
    je      tc_static
    ; dialog background / checkbox / radio text -> opaque near-black, light text
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_text]
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
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_text]
    WINCALL SetBkMode, qword ptr [rbp-24], BKMODE_TRANSP
    mov     rax, qword ptr [g_br_bg]
    FRAME_EPILOG
    ret
tc_panel:
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_text]
    WINCALL SetBkColor, qword ptr [rbp-24], dword ptr [g_col_panel]
    mov     rax, qword ptr [g_br_panel]
    FRAME_EPILOG
    ret
tc_edit:
    ; the sidebar search box uses the sidebar colour; detail-pane field edits
    ; keep the panel colour
    WINCALL GetDlgCtrlID, qword ptr [rbp-40]
    cmp     eax, IDC_V_SEARCH_TH
    je      tc_side
    jmp     tc_panel
tc_side:
    ; the entry list + search box paint in the sidebar colour so the whole left
    ; panel reads as one tinted region (matches the sidebar background fill)
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_text]
    WINCALL SetBkColor, qword ptr [rbp-24], dword ptr [g_col_side]
    mov     rax, qword ptr [g_br_side]
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
    ; ---------- push button (Fluent: accent primary / neutral standard) ------
    WINCALL GetWindowLongPtrW, qword ptr [rbp-40], GWL_USERDATA
    test    rax, rax
    jnz     tdi_accent
    ; standard button - control fill + hairline stroke + light text
    mov     rax, qword ptr [g_br_btn]
    test    dword ptr [rbp-48], ODS_SELECTED
    jz      @F
    mov     rax, qword ptr [g_br_btnsel]
@@: WINCALL SelectObject, qword ptr [rbp-32], rax
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_pen_bd]
    mov     eax, dword ptr [g_col_text]
    mov     dword ptr [rbp-116], eax
    jmp     tdi_btnshape
tdi_accent:
    test    dword ptr [rbp-48], ODS_DISABLED  ; Fluent disabled accent = muted neutral
    jz      tdi_acc_on
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_br_btn]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_pen_bd]
    mov     eax, dword ptr [g_col_textdim]
    mov     dword ptr [rbp-116], eax
    jmp     tdi_btnshape
tdi_acc_on:
    ; primary button - accent fill + black text
    mov     rax, qword ptr [g_br_accent]
    test    dword ptr [rbp-48], ODS_SELECTED
    jz      @F
    mov     rax, qword ptr [g_br_accsel]
@@: WINCALL SelectObject, qword ptr [rbp-32], rax
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_pen_acc]
    mov     dword ptr [rbp-116], COL_ONACC
tdi_btnshape:
    WINCALL RoundRect, qword ptr [rbp-32], dword ptr [rbp-80], dword ptr [rbp-76], \
            dword ptr [rbp-72], dword ptr [rbp-68], 8, 8
    ; Rainbow scheme: overpaint the accent (primary) button with a rainbow gradient
    cmp     dword ptr [g_scheme], SCHEME_RAINBOW
    jne     tdi_tclr
    WINCALL GetWindowLongPtrW, qword ptr [rbp-40], GWL_USERDATA
    test    rax, rax
    jz      tdi_tclr                          ; standard (non-accent) button -> no gradient
    test    dword ptr [rbp-48], ODS_DISABLED
    jnz     tdi_tclr
    WINCALL theme_rainbow_fill, qword ptr [rbp-32], dword ptr [rbp-80], dword ptr [rbp-76], \
            dword ptr [rbp-72], dword ptr [rbp-68], 8
tdi_tclr:
    mov     ecx, dword ptr [rbp-116]
    test    dword ptr [rbp-48], ODS_DISABLED
    jz      tdi_tcol
    mov     ecx, dword ptr [g_col_textdim]
tdi_tcol:
    WINCALL SetTextColor, qword ptr [rbp-32], rcx
    ; single-glyph buttons get a large glyph font for clarity; multi-char
    ; captions (Reveal/Copy/Lock/accent buttons) keep the default font.  A
    ; private-use glyph (>= U+E000) uses the Fluent icon font (e.g. trashcan).
    cmp     word ptr [g_txtbuf+2], 0          ; >1 char -> a word caption
    jne     tdi_dt
    movzx   eax, word ptr [g_txtbuf]
    test    eax, eax                          ; empty caption -> default
    jz      tdi_dt
    cmp     eax, 0E000h
    jb      tdi_bigfont
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_icon]
    jmp     tdi_drawglyph
tdi_bigfont:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_big]
tdi_drawglyph:
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
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_textdim]
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

; =============================================================================
; theme_toggle(rcx=lpdis, edx=on) -> 1 - draw a Fluent pill toggle switch in the
;   owner-draw button's rect.  on: accent track + white thumb right; off: panel
;   track + hairline border + dim thumb left.
; =============================================================================
public theme_toggle
theme_toggle proc frame
    FRAME_PROLOG 144
    mov     qword ptr [rbp-24], rcx           ; lpdis
    mov     dword ptr [rbp-36], edx           ; on
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax           ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-40], eax           ; L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-44], eax           ; T
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-48], eax           ; R
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-52], eax           ; B
    mov     eax, dword ptr [rbp-52]
    sub     eax, dword ptr [rbp-44]
    mov     dword ptr [rbp-56], eax           ; height = pill diameter
    ; ---- track ----
    mov     r10, qword ptr [rbp-24]           ; ODS_DISABLED (HKLM-locked) -> muted, no accent
    test    dword ptr [r10+16], 4
    jnz     tg_dimtrack
    cmp     dword ptr [rbp-36], 0
    je      tg_off
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_br_accent]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_pen_acc]
    jmp     tg_track
tg_off:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_br_panel]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_pen_bd]
    jmp     tg_track
tg_dimtrack:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_br_dim]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_pen_bd]
tg_track:
    WINCALL RoundRect, qword ptr [rbp-32], dword ptr [rbp-40], dword ptr [rbp-44], \
            dword ptr [rbp-48], dword ptr [rbp-52], dword ptr [rbp-56], dword ptr [rbp-56]
    ; Rainbow scheme: rainbow-gradient the ON track
    cmp     dword ptr [g_scheme], SCHEME_RAINBOW
    jne     tg_thumb
    cmp     dword ptr [rbp-36], 0
    je      tg_thumb
    mov     r10, qword ptr [rbp-24]
    test    dword ptr [r10+16], 4
    jnz     tg_thumb
    WINCALL theme_rainbow_fill, qword ptr [rbp-32], dword ptr [rbp-40], dword ptr [rbp-44], \
            dword ptr [rbp-48], dword ptr [rbp-52], dword ptr [rbp-56]
tg_thumb:
    ; ---- thumb ----
    mov     r10, qword ptr [rbp-24]           ; disabled -> muted thumb (state still shown by pos)
    test    dword ptr [r10+16], 4
    jnz     tg_tb_dim
    cmp     dword ptr [rbp-36], 0
    je      tg_tb_off
    WINCALL GetStockObject, WHITE_BRUSH
    jmp     tg_tb_sel
tg_tb_off:
    mov     rax, qword ptr [g_br_dim]
    jmp     tg_tb_sel
tg_tb_dim:
    mov     rax, qword ptr [g_br_panel]
tg_tb_sel:
    WINCALL SelectObject, qword ptr [rbp-32], rax
    WINCALL GetStockObject, NULL_PEN
    WINCALL SelectObject, qword ptr [rbp-32], rax
    mov     eax, dword ptr [rbp-56]
    sub     eax, 4
    mov     dword ptr [rbp-60], eax           ; thumb diameter (pad 2)
    mov     eax, dword ptr [rbp-44]
    add     eax, 2
    mov     dword ptr [rbp-64], eax           ; y1 = T+2
    mov     eax, dword ptr [rbp-52]
    sub     eax, 2
    mov     dword ptr [rbp-68], eax           ; y2 = B-2
    cmp     dword ptr [rbp-36], 0
    je      tg_tb_left
    mov     eax, dword ptr [rbp-48]
    sub     eax, 2
    mov     dword ptr [rbp-76], eax           ; x2 = R-2
    sub     eax, dword ptr [rbp-60]
    mov     dword ptr [rbp-72], eax           ; x1 = x2 - thumbd
    jmp     tg_tb_draw
tg_tb_left:
    mov     eax, dword ptr [rbp-40]
    add     eax, 2
    mov     dword ptr [rbp-72], eax           ; x1 = L+2
    add     eax, dword ptr [rbp-60]
    mov     dword ptr [rbp-76], eax           ; x2 = x1 + thumbd
tg_tb_draw:
    WINCALL Ellipse, qword ptr [rbp-32], dword ptr [rbp-72], dword ptr [rbp-64], \
            dword ptr [rbp-76], dword ptr [rbp-68]
    mov     eax, 1
    FRAME_EPILOG
    ret
theme_toggle endp

; =============================================================================
; theme_toggle_labeled(rcx=lpdis, edx=on) -> 1 - draw an owner-draw button as a
;   left-aligned caption plus a small Fluent pill toggle (20x8 DLU, matching the
;   settings toggles) vertically centred at the right edge of its rect.  The pill
;   is rendered by theme_toggle after the lpdis rect is temporarily replaced with
;   the pill sub-rect, then restored.
; =============================================================================
public theme_toggle_labeled
theme_toggle_labeled proc frame
    FRAME_PROLOG 176
    mov     qword ptr [rbp-24], rcx           ; lpdis
    mov     dword ptr [rbp-36], edx           ; on
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax           ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-40], eax           ; original left
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-44], eax           ; top
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-48], eax           ; right
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-52], eax           ; bottom
    mov     eax, dword ptr [r10+16]
    mov     dword ptr [rbp-56], eax           ; itemState
    ; ---- pill size = 20x8 DLU -> pixels via the parent dialog ----
    mov     r10, qword ptr [rbp-24]
    mov     rcx, qword ptr [r10+24]           ; hwndItem
    call    GetParent
    mov     qword ptr [rbp-88], rax           ; hDlg
    mov     dword ptr [rbp-104], 0            ; RECT{0,0,20,8}
    mov     dword ptr [rbp-100], 0
    mov     dword ptr [rbp-96], 20
    mov     dword ptr [rbp-92], 8
    WINCALL MapDialogRect, qword ptr [rbp-88], addr rbp-104
    mov     eax, dword ptr [rbp-96]
    mov     dword ptr [rbp-60], eax           ; pill width (px)
    mov     eax, dword ptr [rbp-92]
    mov     dword ptr [rbp-64], eax           ; pill height (px)
    ; pill rect: right edge - 4, vertically centred
    mov     eax, dword ptr [rbp-48]
    sub     eax, 4
    mov     dword ptr [rbp-76], eax           ; pR
    sub     eax, dword ptr [rbp-60]
    mov     dword ptr [rbp-68], eax           ; pL
    mov     eax, dword ptr [rbp-52]           ; pT = T + ((B-T)-h)/2
    sub     eax, dword ptr [rbp-44]
    sub     eax, dword ptr [rbp-64]
    sar     eax, 1
    add     eax, dword ptr [rbp-44]
    mov     dword ptr [rbp-72], eax           ; pT
    add     eax, dword ptr [rbp-64]
    mov     dword ptr [rbp-80], eax           ; pB
    ; ---- caption (left, dim if disabled) ----
    WINCALL SetBkMode, qword ptr [rbp-32], BKMODE_TRANSP
    mov     ecx, dword ptr [g_col_text]
    test    dword ptr [rbp-56], ODS_DISABLED
    jz      @F
    mov     ecx, dword ptr [g_col_textdim]
@@: WINCALL SetTextColor, qword ptr [rbp-32], ecx
    mov     r10, qword ptr [rbp-24]
    mov     rcx, qword ptr [r10+24]           ; hwndItem
    WINCALL GetWindowTextW, rcx, addr g_txtbuf, 159
    mov     eax, dword ptr [rbp-40]
    add     eax, 2
    mov     dword ptr [rbp-120], eax          ; label rect L
    mov     eax, dword ptr [rbp-44]
    mov     dword ptr [rbp-116], eax          ; T
    mov     eax, dword ptr [rbp-68]
    sub     eax, 6
    mov     dword ptr [rbp-112], eax          ; R (before pill)
    mov     eax, dword ptr [rbp-52]
    mov     dword ptr [rbp-108], eax          ; B
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_txtbuf, -1, addr rbp-120, DT_LFLAGS
    ; ---- pill: swap lpdis rect for the pill sub-rect, draw, restore ----
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [rbp-68]
    mov     dword ptr [r10+40], eax           ; left
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [r10+44], eax           ; top
    mov     eax, dword ptr [rbp-76]
    mov     dword ptr [r10+48], eax           ; right
    mov     eax, dword ptr [rbp-80]
    mov     dword ptr [r10+52], eax           ; bottom
    mov     rcx, r10
    mov     edx, dword ptr [rbp-36]
    call    theme_toggle
    mov     r10, qword ptr [rbp-24]           ; restore the original rect
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r10+40], eax
    mov     eax, dword ptr [rbp-44]
    mov     dword ptr [r10+44], eax
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [r10+48], eax
    mov     eax, dword ptr [rbp-52]
    mov     dword ptr [r10+52], eax
    mov     eax, 1
    FRAME_EPILOG
    ret
theme_toggle_labeled endp

; =============================================================================
; theme_progressbar(rcx=lpdis, edx=num, r8d=denom) -> 1 - draw a Fluent progress
;   bar in the owner-draw control's rect: a hairline track with an accent fill of
;   width num/denom from the left.  Used as the TOTP countdown under the code box.
; =============================================================================
public theme_progressbar
theme_progressbar proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-36], edx           ; num (seconds left)
    mov     dword ptr [rbp-40], r8d           ; denom (window seconds)
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax           ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-56], eax           ; rect L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-52], eax           ; rect T
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-48], eax           ; rect R
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-44], eax           ; rect B
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-56, qword ptr [g_br_frame]
    mov     eax, dword ptr [rbp-48]
    sub     eax, dword ptr [rbp-56]
    mov     dword ptr [rbp-60], eax           ; width
    cmp     dword ptr [rbp-40], 0             ; denom 0 -> no fill
    jle     tpb_done
    mov     eax, dword ptr [rbp-36]           ; clamp num to 0..denom
    test    eax, eax
    jns     tpb_lo
    xor     eax, eax
tpb_lo:
    cmp     eax, dword ptr [rbp-40]
    jle     tpb_hi
    mov     eax, dword ptr [rbp-40]
tpb_hi:
    imul    eax, dword ptr [rbp-60]
    xor     edx, edx
    div     dword ptr [rbp-40]                ; eax = fill width
    mov     ecx, dword ptr [rbp-56]
    mov     dword ptr [rbp-76], ecx           ; fill L
    mov     edx, dword ptr [rbp-52]
    mov     dword ptr [rbp-72], edx           ; fill T
    add     ecx, eax
    mov     dword ptr [rbp-68], ecx           ; fill R = L + fill
    mov     edx, dword ptr [rbp-44]
    mov     dword ptr [rbp-64], edx           ; fill B
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-76, qword ptr [g_br_accent]
tpb_done:
    mov     eax, 1
    FRAME_EPILOG
    ret
theme_progressbar endp

end
