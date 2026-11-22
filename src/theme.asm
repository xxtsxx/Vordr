; =============================================================================
; theme.asm - Vordr dark theme (flat dark background + owner-drawn controls).
;
; The window background is a solid dark fill: theme_erase paints the dark
; background brush on WM_ERASEBKGND, and theme_paint returns "unhandled" so the
; default paint uses it.  Brushes/pens/fonts are (re)built by theme_rebrush from
; the active colour scheme (theme_set_scheme, cycled by the settings menu).
;
; All procs touch only volatile registers (rax/rcx/rdx/r8-r11) so they unwind
; cleanly back through the OS dialog callbacks without saving rbx/rsi/rdi/r12-15.
;
; Public surface (called from gui.asm dialog procs):
;   theme_boot                      - one-time: build the colour scheme + brushes
;   theme_attach(hwnd, defid)       - per dialog: dark titlebar + bg
;   theme_paint(hwnd)               - WM_PAINT: flat fill / sidebar card
;   theme_erase        -> 1         - WM_ERASEBKGND: paint the dark background
;   theme_ctlcolor(hwnd,msg,hdc,hctl) -> HBRUSH  - WM_CTLCOLOR* dark colours
;   theme_drawitem(lpdis) -> 1      - WM_DRAWITEM: owner-draw buttons/groupboxes
; =============================================================================

include macros.inc

; ---- imports ----------------------------------------------------------------
extern DeleteObject:proc
extern SelectObject:proc
extern CreateSolidBrush:proc
extern CreatePen:proc
extern CreateCompatibleDC:proc
extern CreateDIBSection:proc
extern GdiFlush:proc
extern AlphaBlend:proc
extern mk_font:proc                     ; gui.asm: font factory (applies g_fontdelta)
extern SetTextColor:proc
extern SetBkColor:proc
extern SetBkMode:proc
extern GetStockObject:proc
extern RoundRect:proc
extern ghost_halo_color:proc             ; gui.asm: a ghost button's (fading) halo colour

extern GetClientRect:proc
extern BeginPaint:proc
extern EndPaint:proc
extern DrawTextW:proc
extern FillRect:proc
extern FrameRect:proc
extern GetWindowTextW:proc
extern GetClassNameW:proc
extern GetWindowLongPtrW:proc
extern SetWindowLongPtrW:proc
extern GetDlgItem:proc
extern RedrawWindow:proc
extern SendMessageW:proc
extern EnumChildWindows:proc
extern SetWindowTheme:proc
extern GetWindowRect:proc
extern ScreenToClient:proc
extern GetFocus:proc
extern GetDlgCtrlID:proc
extern MapDialogRect:proc
extern GetParent:proc
extern g_vaulthwnd:qword              ; the DLG_VAULT window (sidebar card only there)
extern g_settings_hwnd:qword          ; the DLG_SETTINGS child surface
extern sidebar_rect:proc              ; gui.asm: shared sidebar frame geometry
extern gui_draw_brand_hdr:proc        ; gui.asm: Layout B Vordr shield + wordmark header
IDC_V_SEARCH_TH equ 232               ; = IDC_V_SEARCH in gui.asm (sidebar search box)
GLASS_FILL_TAG  equ 66000000h         ; 102 / 255 = 40.0% semi-transparent card fill
extern IsWindowVisible:proc
extern DwmSetWindowAttribute:proc
extern gpu_paint_bg:proc              ; gpu.asm: D3D11 procedural backdrop
extern gpu_fill_child_bg:proc         ; gpu.asm: sub-rect blit behind child controls
extern gpu_sample_child_bg:proc       ; gpu.asm: COLORREF under child center
extern gpu_fill_glass_child:proc      ; gpu.asm: glass g_col_panel over backdrop slice
extern gpu_sample_glass_child:proc    ; gpu.asm: sampled COLORREF under glass card
extern gpu_fill_side_glass_child:proc ; gpu.asm: glass g_col_side over backdrop slice
extern gpu_sample_side_glass_child:proc
extern gpu_is_surface_hwnd:proc       ; gpu.asm: 1 if DLG_VAULT / DLG_SETTINGS + GPU active

; ---- message / api constants ------------------------------------------------
WM_CTLCOLOREDIT     equ 133h
WM_CTLCOLORLISTBOX  equ 134h
WM_CTLCOLORSTATIC   equ 138h
DM_SETDEFID         equ 401h
GWL_STYLE           equ -16
GWL_USERDATA        equ -21                  ; 1 = Fluent accent (primary) button
WS_CLIPCHILDREN     equ 02000000h
DWMWA_DARK          equ 20
DWMWA_CORNER        equ 33                   ; DWMWA_WINDOW_CORNER_PREFERENCE
DWMWCP_ROUND        equ 2                    ; rounded corners (Fluent)
DWMWA_BORDER_COLOR  equ 34                   ; 1px DWM outer border colour (Win11)
DWMWA_CAPTION_COLOR equ 35                   ; title-bar fill (Win11; older: E_INVALIDARG, ignored)
DWMWA_TEXT_COLOR    equ 36                   ; title-bar text
NULL_BRUSH          equ 5
PS_SOLID            equ 0
BS_TYPEMASK         equ 0Fh
BS_GROUPBOX         equ 7
ODS_SELECTED        equ 1
ODS_DISABLED        equ 4
BKMODE_TRANSP       equ 1
DT_CFLAGS           equ 25h                 ; DT_CENTER|DT_VCENTER|DT_SINGLELINE
DT_LFLAGS           equ 24h                 ; DT_LEFT|DT_VCENTER|DT_SINGLELINE

.data
align 8
; ---- runtime-selectable colour scheme -------------------------------------
; g_col_* are 15 consecutive dwords (order matches each schemes[] row).
public g_scheme, g_col_bg, g_col_panel, g_col_text, g_col_textdim, g_col_frame, g_col_dark
public g_col_side, g_col_accent, g_col_accent2, g_col_filebadge, g_col_border
public g_col_onacc, g_col_spec, schemes
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
g_col_accent2 dd 00FFC24Ch                ; secondary accent (two-tone gradient end)
public g_col_hover, g_col_rowhov, g_col_sel
g_col_hover dd 002C2C2Ch                  ; ghost-button hover halo: bg blended ~10% toward text
                                          ;   (computed per scheme in theme_set_scheme, NOT in the
                                          ;   15-dword schemes table above - keep it out of the copy)
g_col_rowhov dd 0                         ; entry-list row under the pointer   (derived, ditto)
g_col_sel   dd 0                          ; entry-list selection pill fill     (derived, ditto)
g_col_onacc dd 00101010h                  ; BT.709 auto-contrasted text on accent buttons (#11)
g_col_spec  dd 00585858h                  ; 1px top-lit specular border highlight (#13)
SCHEME_DW   equ 15
TINT_W      equ 6                         ; accent share of the neutrals, /256
SCHEME_COUNT equ 9
schemes label dword
    ; bg,panel,frame,btn,btnsel,text,textdim,border,accent,accsel,focus,dark,side,filebadge,accent2
    ; ---- Light palettes (0..2) ----
    dd 00F3F3F3h,00FFFFFFh,00D2D2D2h,00FFFFFFh,00E6E6E6h,00202020h,00707070h,00D2D2D2h,00C26A00h,00A05800h,00C26A00h,00000000h,00FFFFFFh,00E8DCC8h,00C26A00h  ; 0: Light
    dd 00D8ECF4h,00E0F3FBh,00A8C8D8h,00E0F3FBh,00C0DFEAh,002A3B4Bh,00556A7Ah,00A8C8D8h,001D65B5h,00144E90h,001D65B5h,00000000h,00C4D2D6h,00CCDCE4h,001D65B5h  ; 1: Sepia
    dd 00E3F6FDh,00F0FBFFh,00A1A193h,00F0FBFFh,00D5E8EEh,00423607h,00756E58h,00B8B8AAh,00D28B26h,00AD701Ch,00D28B26h,00000000h,00D5E8EEh,00C8DFD8h,0098A12Ah  ; 2: Solarized
    ; ---- Dark palettes (3..8) ----
    dd 0040342Eh,0052423Bh,006A564Ch,0052423Bh,005E4C43h,00F4EFECh,00E9DED8h,006A564Ch,00D0C088h,00B0A06Fh,00D0C088h,00000001h,004F4039h,00786858h,00D0C088h  ; 3: Nord
    dd 001A1410h,00282018h,00403420h,00282018h,00201810h,00FFF0E0h,00C0B0A0h,00403420h,00E0C040h,00B09020h,00E0C040h,00000001h,00170F0Fh,00504028h,00E0C040h  ; 4: Midnight
    dd 00220E06h,0038180Ah,008A3A1Ah,0038180Ah,004E2210h,00FFEAE0h,00E0B09Ah,008A3A1Ah,00FF6A2Eh,00D04818h,00FF6A2Eh,00000001h,001A0A04h,00341208h,00FFB08Ah  ; 5: Sapphire
    dd 00282828h,002F3032h,00454950h,002F3032h,0036383Ch,00B2DBEBh,008499A8h,00454950h,001980FEh,001060D0h,001980FEh,00000001h,001F2022h,0034363Ah,0026BBB8h  ; 6: Gruvbox
    dd 002E1E1Eh,00443231h,005A4745h,00443231h,00523D3Bh,00F4D6CDh,00DEC2BAh,005A4745h,00F7A6CBh,00D684B0h,00F7A6CBh,00000001h,00251818h,005A4745h,0087B3FAh  ; 7: Catppuccin
    dd 00000000h,00121010h,00443E3Eh,00161414h,00262222h,00FFFFFFh,00C4C0C0h,004A4444h,00FFE500h,00CCB600h,00FFE500h,00000001h,00080808h,002A2828h,00A3FF00h  ; 8: OLED Black
; scheme_traits[scheme] = radius(byte0) | accent-mode(byte1: 0 solid/1 rainbow/2 two-tone) |
;   flags(byte2: bit0 scanlines)
scheme_traits label dword
    dd 00000008h  ; 0: Light
    dd 00000008h  ; 1: Sepia
    dd 00000208h  ; 2: Solarized
    dd 00000008h  ; 3: Nord
    dd 00000008h  ; 4: Midnight
    dd 00000208h  ; 5: Sapphire
    dd 00000006h  ; 6: Gruvbox
    dd 00000208h  ; 7: Catppuccin
    dd 00000208h  ; 8: OLED Black
public g_br_frame, g_br_panel, g_br_bg, g_br_side
g_br_bg     dq 0
g_br_side   dq 0                            ; sidebar (list + search) fill
g_br_panel  dq 0
g_br_frame  dq 0
g_br_btn    dq 0
g_br_btnsel dq 0
g_br_accent dq 0                            ; Fluent accent fill (primary button)
g_br_accsel dq 0                            ; Fluent accent fill pressed
g_br_dim    dq 0                            ; #C8C8C8 (toggle off thumb)
public g_br_hover, g_pen_bd
g_br_hover  dq 0                            ; ghost-button hover halo fill (g_col_hover)
g_pen_bd    dq 0
g_pen_acc   dq 0
g_pen_focus dq 0                            ; 2px accent focus underline
g_font_big  dq 0                            ; large glyph font for toolbar buttons
public g_font_icon, g_font_icon_pop
g_font_icon     dq 0                        ; Segoe Fluent Icons (PUA glyph buttons)
g_font_icon_pop dq 0                        ; enlarged Fluent icon font for favorite star pop (#18)
public g_font_totp
g_font_totp dq 0                            ; tabular monospace semibold font for TOTP code (#20)
g_font_sym  dq 0                            ; Segoe UI Symbol (recycle ♻ button glyph)
g_frame_hdc dq 0                            ; EnumChildWindows frame-draw context
g_frame_par dq 0
; Optional per-control focus-underline colour override + 4-segment strength meter (#1, #16)
public g_uline_ctl, g_uline_br, g_uline_ctl2, g_uline_br2
public g_uline_anim_hwnd, g_uline_seg_ctl, g_uline_seg_lvl
public g_tog_anim_hwnd, g_copy_btn_hwnd
g_uline_ctl       dd 0
g_uline_br        dq 0
g_uline_ctl2      dd 0
g_uline_br2       dq 0
g_uline_anim_hwnd dq 0                      ; Edit currently animating center-out underline (#1)
g_uline_seg_ctl   dd 0                      ; Control ID using 4-segment strength bar (#16)
g_uline_seg_lvl   dd 0                      ; 0=empty, 1=weak, 2=fair, 3=good, 4=strong
g_tog_anim_hwnd   dq 0                      ; Toggle switch currently sliding (#4)
g_copy_btn_hwnd   dq 0                      ; Copy button flashing green checkmark (#2)

; Persistent 32-bit premultiplied ARGB scratch surface for analytical SDF AA (#15)
align 8
g_aa_hdc    dq 0
g_aa_hbmp   dq 0
g_aa_oldbmp dq 0
g_aa_bits   dq 0
g_aa_capw   dd 0
g_aa_caph   dd 0

align 4
f_half      dd 3F000000h                    ; 0.5f
f_one       dd 3F800000h                    ; 1.0f
f_255       dd 437F0000h                    ; 255.0f
f_256       dd 43800000h                    ; 256.0f
f_neg_half  dd 0BF000000h                   ; -0.5f
f_0_6       dd 3F19999Ah                    ; 0.6f
f_pi_4      dd 3F490FDBh                    ; 0.78539816f (pi/4)
f_atan_k    dd 3E8BC6A8h                    ; 0.273f
f_rad_to_k  dd 4322F983h                    ; 1024.0f / (2*pi) = 162.97466f
f_1024      dd 44800000h                    ; 1024.0f
f_512       dd 44000000h                    ; 512.0f
f_2pi       dd 40C90FDBh                    ; 6.2831853f
f_eight     dd 41000000h                    ; 8.0f
f_two       dd 40000000h                    ; 2.0f
f_seven     dd 40E00000h                    ; 7.0f
f_nine      dd 41100000h                    ; 9.0f
f_inv_nine  dd 3DE38E39h                    ; 1.0f / 9.0f
f_abs_mask  dd 7FFFFFFFh

td_dark label word                      ; control theme class for dark scrollbars
    dw 'D','a','r','k','M','o','d','e','_','E','x','p','l','o','r','e','r', 0
td_light label word                     ; control theme class for light scrollbars
    dw 'E','x','p','l','o','r','e','r', 0
td_font label word                      ; toolbar glyph font face
    dw 'S','e','g','o','e',' ','U','I',0
td_iconfont label word                  ; Fluent icon font (PUA glyphs e.g. trashcan)
    dw 'S','e','g','o','e',' ','F','l','u','e','n','t',' ','I','c','o','n','s',0
td_symfont label word                   ; Segoe UI Symbol (recycle ♻)
    dw 'S','e','g','o','e',' ','U','I',' ','S','y','m','b','o','l',0
td_monofont label word                  ; Tabular monospace font for TOTP codes (#20)
    dw 'C','o','n','s','o','l','a','s',0

.data?
align 16
g_txtbuf    dw 160 dup (?)
g_clsbuf    dw 16 dup (?)               ; control class name (Static vs Edit)

.code




; =============================================================================
; theme_boot - one-time initialisation.
; =============================================================================
public theme_boot
theme_boot proc frame
    FRAME_PROLOG 48
    mov     ecx, dword ptr [g_scheme]         ; build brushes/pens from the active scheme
    call    theme_set_scheme
    ; large semibold font for the small toolbar symbol buttons (+ pencil)
    mov     ecx, -18
    mov     edx, 100
    lea     r8, [td_font]
    call    mk_font                           ; the shared font factory (applies S/M/L)
    mov     qword ptr [g_font_big], rax
    ; Fluent icon font for PUA glyph buttons (the trashcan)
    mov     ecx, -18
    mov     edx, 100
    lea     r8, [td_iconfont]
    call    mk_font
    mov     qword ptr [g_font_icon], rax
    ; Enlarged Fluent icon font for Favorite star pop (#18)
    mov     ecx, -22
    mov     edx, 100
    lea     r8, [td_iconfont]
    call    mk_font
    mov     qword ptr [g_font_icon_pop], rax
    ; Tabular semibold monospace font for the live TOTP code box (#20)
    mov     ecx, -16
    mov     edx, 600
    lea     r8, [td_monofont]
    call    mk_font
    mov     qword ptr [g_font_totp], rax
    ; Segoe UI Symbol for the recycle-button glyph (♻ U+267B); sized to the
    ; small header button so DT_VCENTER lands it centered like the star icon
    mov     ecx, -15
    mov     edx, 400
    lea     r8, [td_symfont]
    call    mk_font
    mov     qword ptr [g_font_sym], rax
    FRAME_EPILOG
    ret
theme_boot endp

; =============================================================================
; theme_del_gdi(rcx = &handle) - DeleteObject the handle if non-zero, then 0 it.
; =============================================================================
theme_del_gdi proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     rcx, qword ptr [rcx]
    test    rcx, rcx
    jz      tdg_done
    call    DeleteObject
    mov     r10, qword ptr [rbp-16]
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
    lea     rcx, [g_br_hover]
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
    WINCALL CreateSolidBrush, dword ptr [g_col_hover]
    mov     qword ptr [g_br_hover], rax
    WINCALL CreatePen, PS_SOLID, 1, dword ptr [g_col_border]
    mov     qword ptr [g_pen_bd], rax
    WINCALL CreatePen, PS_SOLID, 1, dword ptr [g_col_accent]
    mov     qword ptr [g_pen_acc], rax
    WINCALL CreatePen, PS_SOLID, 2, dword ptr [g_col_focus]
    mov     qword ptr [g_pen_focus], rax
    FRAME_EPILOG
    ret
theme_rebrush endp

; col_mix(ecx = a, edx = b, r8d = w 0..256) -> eax = a + (b - a) * w / 256, per
;   channel (COLORREFs).  The one place interaction shades come from, so every
;   scheme derives them the same way from its own seeds.
public col_mix
col_mix proc frame
    FRAME_PROLOG 32
    mov     r9d, ecx
    xor     r10d, r10d                         ; result
    xor     ecx, ecx                           ; channel shift 0, 8, 16
cmx_lp:
    mov     eax, r9d
    shr     eax, cl
    movzx   eax, al                            ; a's channel
    mov     r11d, edx
    shr     r11d, cl
    movzx   r11d, r11b                         ; b's channel
    sub     r11d, eax                          ; b - a, signed
    imul    r11d, r8d
    sar     r11d, 8
    add     eax, r11d
    shl     eax, cl
    or      r10d, eax
    add     ecx, 8
    cmp     ecx, 24
    jb      cmx_lp
    mov     eax, r10d
    FRAME_EPILOG
    ret
col_mix endp

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
    ; The table holds each scheme's seeds; everything an interaction needs is
    ; derived from them here, the same way for every scheme (col_mix):
    ;   - the big neutral areas carry a trace (~2%) of the accent, so the greys
    ;     read as belonging to the scheme rather than as default grey;
    ;   - hover halo = background ~10% toward the text colour (lightens dark
    ;     schemes, darkens light ones);
    ;   - list row hover = sidebar ~8% toward text;
    ;   - selection pill = sidebar ~9% toward text, then ~17% toward the accent.
    ; Keep OLED Black's #000000 background pure pitch-black without neutral tint (#9)
    mov     ecx, dword ptr [g_col_bg]
    test    ecx, ecx
    jz      tss_skip_bgtint
    mov     edx, dword ptr [g_col_accent]
    mov     r8d, TINT_W
    call    col_mix
    mov     dword ptr [g_col_bg], eax
tss_skip_bgtint:
    mov     ecx, dword ptr [g_col_panel]
    mov     edx, dword ptr [g_col_accent]
    mov     r8d, TINT_W
    call    col_mix
    mov     dword ptr [g_col_panel], eax
    mov     ecx, dword ptr [g_col_side]
    mov     edx, dword ptr [g_col_accent]
    mov     r8d, TINT_W
    call    col_mix
    mov     dword ptr [g_col_side], eax
    mov     ecx, dword ptr [g_col_bg]
    mov     edx, dword ptr [g_col_text]
    mov     r8d, 26
    call    col_mix
    mov     dword ptr [g_col_hover], eax
    mov     ecx, dword ptr [g_col_side]
    mov     edx, dword ptr [g_col_text]
    mov     r8d, 20
    call    col_mix
    mov     dword ptr [g_col_rowhov], eax
    mov     ecx, dword ptr [g_col_side]
    mov     edx, dword ptr [g_col_text]
    mov     r8d, 24
    call    col_mix
    mov     ecx, eax
    mov     edx, dword ptr [g_col_accent]
    mov     r8d, 44
    call    col_mix
    mov     dword ptr [g_col_sel], eax
    ; Perceived-luminance BT.709 auto-contrast for g_col_onacc (#11):
    ; midpoint of accent & accent2 -> Y = (54*R + 183*G + 19*B) >> 8
    mov     ecx, dword ptr [g_col_accent]
    mov     edx, dword ptr [g_col_accent2]
    mov     r8d, 128
    call    col_mix
    movzx   ecx, al                             ; R
    imul    ecx, ecx, 54
    mov     edx, eax
    shr     edx, 8
    movzx   edx, dl                             ; G
    imul    edx, edx, 183
    add     ecx, edx
    shr     eax, 16
    movzx   eax, al                             ; B
    imul    eax, eax, 19
    add     ecx, eax
    shr     ecx, 8                              ; Y in 0..255
    mov     eax, 00101010h
    cmp     ecx, 142
    jae     @F
    mov     eax, 00FFFFFFh
@@: mov     dword ptr [g_col_onacc], eax
    ; Top-lit 1px specular border highlight (#13)
    mov     eax, 00FFFFFFh
    cmp     dword ptr [g_col_dark], 0
    je      @F
    mov     ecx, dword ptr [g_col_border]
    mov     edx, 00FFFFFFh
    mov     r8d, 58
    call    col_mix
@@: mov     dword ptr [g_col_spec], eax
    call    theme_rebrush
    FRAME_EPILOG
    ret
theme_set_scheme endp

; theme_dark_cb(rcx=hwnd, rdx=lparam) -> BOOL - give each control the explorer
;   theme so its scrollbars/borders match the scheme: DarkMode_Explorer for dark
;   schemes, plain Explorer (light) otherwise.  EnumChildWindows callback.
;   AUD-18: skip ES_PASSWORD controls (0x20) so uxtheme never attaches buffered-paint scratch.
theme_dark_cb proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     qword ptr [rbp-16], rcx
    WINCALL GetWindowLongPtrW, rcx, GWL_STYLE
    test    eax, 20h                         ; ES_PASSWORD = 0x20
    jnz     tdc_skip
    mov     rcx, qword ptr [rbp-16]
    lea     rdx, [td_dark]
    cmp     dword ptr [g_col_dark], 0        ; light scheme -> light scrollbars
    jne     tdc_go
    lea     rdx, [td_light]
tdc_go:
    xor     r8, r8
    call    SetWindowTheme
tdc_skip:
    mov     eax, 1
    mov     rsp, rbp
    pop     rbp
    ret
theme_dark_cb endp

; theme_scrollbars(rcx=hwnd) - re-theme every child control's scrollbars to match
;   the current scheme (call after a scheme switch so they follow dark<->light).
public theme_scrollbars
theme_scrollbars proc frame
    FRAME_PROLOG 48   ; >= 48: keep locals clear of the callee 32-byte home area
    mov     qword ptr [rbp-24], rcx
    WINCALL EnumChildWindows, qword ptr [rbp-24], addr theme_dark_cb, 0
    FRAME_EPILOG
    ret
theme_scrollbars endp

; =============================================================================
; theme_dwm_apply(rcx=hwnd) - apply every scheme-dependent DWM window attribute:
;   immersive dark mode, rounded corners, title-bar fill/text colours, and
;   Windows 11 Mica backdrop attribute when Backdrop == Mica (#12).
; =============================================================================
public theme_dwm_apply
theme_dwm_apply proc frame
    FRAME_PROLOG 64   ; >= 64: keep locals clear of the callee 32-byte home area
    ; [rbp-24] hwnd  [rbp-40] attribute value cell
    mov     qword ptr [rbp-24], rcx
    mov     eax, dword ptr [g_col_dark]         ; dark title bar only for dark schemes
    mov     dword ptr [rbp-40], eax
    WINCALL DwmSetWindowAttribute, qword ptr [rbp-24], DWMWA_DARK, addr rbp-40, 4
    mov     dword ptr [rbp-40], DWMWCP_ROUND    ; Fluent rounded window corners
    WINCALL DwmSetWindowAttribute, qword ptr [rbp-24], DWMWA_CORNER, addr rbp-40, 4
    mov     eax, dword ptr [g_col_border]       ; 1px Win11 DWM border matches active scheme
    mov     dword ptr [rbp-40], eax
    WINCALL DwmSetWindowAttribute, qword ptr [rbp-24], DWMWA_BORDER_COLOR, addr rbp-40, 4
    mov     eax, dword ptr [g_col_bg]           ; caption painted like the window bg
    mov     dword ptr [rbp-40], eax
    WINCALL DwmSetWindowAttribute, qword ptr [rbp-24], DWMWA_CAPTION_COLOR, addr rbp-40, 4
    mov     eax, dword ptr [g_col_text]         ; caption text follows the scheme
    mov     dword ptr [rbp-40], eax
    WINCALL DwmSetWindowAttribute, qword ptr [rbp-24], DWMWA_TEXT_COLOR, addr rbp-40, 4
    FRAME_EPILOG
    ret
theme_dwm_apply endp

; =============================================================================
; theme_attach(rcx=hwnd, edx=defid)
; =============================================================================
public theme_attach
theme_attach proc frame
    FRAME_PROLOG 96
    ; [rbp-24] hwnd  [rbp-32] defid  [rbp-40] dwmflag  RECT @ [rbp-64]
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     rcx, qword ptr [rbp-24]
    call    theme_dwm_apply                     ; dark/corners/caption colours
    WINCALL GetWindowLongPtrW, qword ptr [rbp-24], GWL_STYLE
    or      rax, WS_CLIPCHILDREN            ; clip children so the frame ring isn't overpainted
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], GWL_STYLE, rax
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

; theme_trait() -> eax = scheme_traits[g_scheme].  Leaf.  (byte0 radius, byte1
;   accent mode 0 solid/2 two-tone, byte2 bit0 = CRT scanlines.)
public theme_trait
theme_trait proc
    mov     eax, dword ptr [g_scheme]
    lea     r10, [scheme_traits]
    mov     eax, dword ptr [r10+rax*4]
    ret
theme_trait endp

; col_darken(ecx=col, edx=factor[0..256]) -> eax = per-channel col*factor/256   leaf
public col_darken
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
; theme_aa_ensure(ecx = w, edx = h) -> eax = 1 if persistent 32-bit ARGB scratch
;   DIB (g_aa_hdc / g_aa_bits) is ready for at least w x h pixels, 0 on failure.
;   Grows monotonically so normal painting creates ZERO GDI handles per frame.
; =============================================================================
theme_aa_ensure proc frame
    FRAME_PROLOG 144
    ; [rbp-16]=reqW  [rbp-20]=reqH  [rbp-72..rbp-33]=BITMAPINFOHEADER(40B)
    cmp     ecx, 1
    jge     @F
    mov     ecx, 1
@@: cmp     edx, 1
    jge     @F
    mov     edx, 1
@@: cmp     ecx, dword ptr [g_aa_capw]
    jg      tae_grow
    cmp     edx, dword ptr [g_aa_caph]
    jg      tae_grow
    cmp     qword ptr [g_aa_bits], 0
    je      tae_grow
    mov     eax, 1
    FRAME_EPILOG
    ret

tae_grow:
    mov     eax, dword ptr [g_aa_capw]
    cmp     eax, 320
    jge     @F
    mov     eax, 320
@@: cmp     ecx, eax
    cmovg   eax, ecx
    mov     dword ptr [rbp-16], eax             ; new capw
    mov     eax, dword ptr [g_aa_caph]
    cmp     eax, 128
    jge     @F
    mov     eax, 128
@@: cmp     edx, eax
    cmovg   eax, edx
    mov     dword ptr [rbp-20], eax             ; new caph

    cmp     qword ptr [g_aa_hdc], 0
    jne     tae_havedc
    WINCALL CreateCompatibleDC, 0
    test    rax, rax
    jz      tae_fail
    mov     qword ptr [g_aa_hdc], rax
tae_havedc:
    cmp     qword ptr [g_aa_hbmp], 0
    je      tae_mkbmp
    WINCALL SelectObject, qword ptr [g_aa_hdc], qword ptr [g_aa_oldbmp]
    mov     qword ptr [g_aa_oldbmp], 0
    WINCALL DeleteObject, qword ptr [g_aa_hbmp]
    mov     qword ptr [g_aa_hbmp], 0
    mov     qword ptr [g_aa_bits], 0
tae_mkbmp:
    lea     r10, [rbp-72]
    xor     eax, eax
    mov     qword ptr [r10+0], rax
    mov     qword ptr [r10+8], rax
    mov     qword ptr [r10+16], rax
    mov     qword ptr [r10+24], rax
    mov     qword ptr [r10+32], rax
    mov     dword ptr [r10+0], 40               ; biSize
    mov     ecx, dword ptr [rbp-16]
    mov     dword ptr [r10+4], ecx              ; biWidth = capw
    mov     edx, dword ptr [rbp-20]
    neg     edx
    mov     dword ptr [r10+8], edx              ; biHeight = -caph (top-down)
    mov     word ptr [r10+12], 1                ; biPlanes = 1
    mov     word ptr [r10+14], 32               ; biBitCount = 32 (BGRA8)
    WINCALL CreateDIBSection, qword ptr [g_aa_hdc], addr rbp-72, 0, addr g_aa_bits, 0, 0
    test    rax, rax
    jz      tae_fail
    mov     qword ptr [g_aa_hbmp], rax
    WINCALL SelectObject, qword ptr [g_aa_hdc], rax
    mov     qword ptr [g_aa_oldbmp], rax
    mov     eax, dword ptr [rbp-16]
    mov     dword ptr [g_aa_capw], eax
    mov     eax, dword ptr [rbp-20]
    mov     dword ptr [g_aa_caph], eax
    mov     eax, 1
    FRAME_EPILOG
    ret
tae_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
theme_aa_ensure endp

; aa_lerp_rgb(ecx = c0, edx = c1, r8d = w[0..256]) -> eax = COLORREF.  Leaf, volatile regs only.
aa_lerp_rgb proc
    movzx   eax, cl
    movzx   r9d, dl
    sub     r9d, eax
    imul    r9d, r8d
    sar     r9d, 8
    add     eax, r9d
    mov     r10d, eax                           ; R
    mov     eax, ecx
    shr     eax, 8
    movzx   eax, al
    mov     r9d, edx
    shr     r9d, 8
    movzx   r9d, r9b
    sub     r9d, eax
    imul    r9d, r8d
    sar     r9d, 8
    add     eax, r9d
    shl     eax, 8
    or      r10d, eax                           ; G
    mov     eax, ecx
    shr     eax, 16
    movzx   eax, al
    mov     r9d, edx
    shr     r9d, 16
    movzx   r9d, r9b
    sub     r9d, eax
    imul    r9d, r8d
    sar     r9d, 8
    add     eax, r9d
    shl     eax, 16
    or      eax, r10d                           ; 0x00BBGGRR
    ret
aa_lerp_rgb endp

; aa_pack_pm(ecx = COLORREF 0x00BBGGRR, edx = alpha 0..255) -> eax = premultiplied BGRA8 0xAARRGGBB.
;   Uses ((ch + 1) * alpha) >> 8 which is bit-exact ch at alpha=255 and 0 at alpha=0!  Leaf.
aa_pack_pm proc
    test    edx, edx
    jz      app_zero
    cmp     edx, 255
    jae     app_opaque
    movzx   eax, cl                             ; R
    inc     eax
    imul    eax, edx
    shr     eax, 8
    shl     eax, 16
    mov     r9d, eax
    mov     eax, ecx
    shr     eax, 8
    movzx   eax, al                             ; G
    inc     eax
    imul    eax, edx
    shr     eax, 8
    shl     eax, 8
    or      r9d, eax
    mov     eax, ecx
    shr     eax, 16
    movzx   eax, al                             ; B
    inc     eax
    imul    eax, edx
    shr     eax, 8
    or      r9d, eax
    mov     eax, edx
    shl     eax, 24
    or      eax, r9d
    ret
app_opaque:
    movzx   eax, cl                             ; R
    shl     eax, 16
    mov     r9d, ecx
    and     r9d, 0000FF00h                      ; G
    or      eax, r9d
    mov     r9d, ecx
    shr     r9d, 16
    and     r9d, 0FFh                           ; B
    or      eax, r9d
    or      eax, 0FF000000h
    ret
app_zero:
    xor     eax, eax
    ret
aa_pack_pm endp

; aa_lerp_pm_cov(ecx = pmA, edx = pmB, r8d = w256, r9d = cov256) -> eax = 0xAARRGGBB.
;   Linearly interpolates two premultiplied BGRA8 pixels by w256 (0..256), then
;   scales all 4 channels by outer coverage cov256 (0..256).  Leaf, volatile regs only.
aa_lerp_pm_cov proc
    test    r9d, r9d
    jle     alpc_zero
    ; Channel B (bits 0..7)
    movzx   eax, cl
    movzx   r10d, dl
    sub     r10d, eax
    imul    r10d, r8d
    sar     r10d, 8
    add     eax, r10d
    imul    eax, r9d
    shr     eax, 8
    mov     r11d, eax
    ; Channel G (bits 8..15)
    mov     eax, ecx
    shr     eax, 8
    movzx   eax, al
    mov     r10d, edx
    shr     r10d, 8
    movzx   r10d, r10b
    sub     r10d, eax
    imul    r10d, r8d
    sar     r10d, 8
    add     eax, r10d
    imul    eax, r9d
    shr     eax, 8
    shl     eax, 8
    or      r11d, eax
    ; Channel R (bits 16..23)
    mov     eax, ecx
    shr     eax, 16
    movzx   eax, al
    mov     r10d, edx
    shr     r10d, 16
    movzx   r10d, r10b
    sub     r10d, eax
    imul    r10d, r8d
    sar     r10d, 8
    add     eax, r10d
    imul    eax, r9d
    shr     eax, 8
    shl     eax, 16
    or      r11d, eax
    ; Channel A (bits 24..31)
    shr     ecx, 24
    shr     edx, 24
    sub     edx, ecx
    imul    edx, r8d
    sar     edx, 8
    add     ecx, edx
    imul    ecx, r9d
    shr     ecx, 8
    shl     ecx, 24
    mov     eax, r11d
    or      eax, ecx
    ret
alpc_zero:
    xor     eax, eax
    ret
aa_lerp_pm_cov endp

; =============================================================================
; theme_aa_rrect(rcx=hdc, edx=L, r8d=T, r9d=R, [rbp+48]=B, [rbp+56]=diam,
;   [rbp+64]=colTop(|alpha<<24), [rbp+72]=colBot(|80000000h horiz),
;   [rbp+80]=borderCol, [rbp+88]=specCol) -> eax = 1
;   Analytical SDF smooth anti-aliased rounded rectangle with optional semi-
;   transparent glass interior (colTop bits 24..31 = 1..254, 0 = 255 opaque),
;   1px border, and top-lit 1px specular highlight (#13, #15, #18).
; =============================================================================
public theme_aa_rrect
theme_aa_rrect proc frame
    FRAME_PROLOG 256
    ; Locals [rbp-16 .. rbp-136], leaving 120B >= 88B for 11-arg AlphaBlend:
    ;   [rbp-16]=hdc [rbp-20]=L [rbp-24]=T [rbp-28]=w [rbp-32]=h
    ;   [rbp-36]=colTop [rbp-40]=colBot [rbp-44]=horizGrad [rbp-48]=borderCol [rbp-52]=specCol
    ;   [rbp-56]=hx [rbp-60]=hy [rbp-64]=bx [rbp-68]=by [rbp-72]=rad
    ;   [rbp-76]=iy [rbp-80]=ix [rbp-84]=gradDenom [rbp-88]=rowCol [rbp-92]=rowBgra
    ;   [rbp-104]=rowPtr [rbp-108]=py_sub [rbp-112]=qy2 [rbp-116]=dist
    ;   [rbp-128]=fillAlpha [rbp-132]=pmFill
    mov     qword ptr [rbp-16], rcx
    mov     dword ptr [rbp-20], edx
    mov     dword ptr [rbp-24], r8d
    sub     r9d, edx
    jle     tar_done
    mov     dword ptr [rbp-28], r9d             ; w = R - L
    mov     eax, dword ptr [rbp+48]
    sub     eax, r8d
    jle     tar_done
    mov     dword ptr [rbp-32], eax             ; h = B - T

    mov     ecx, dword ptr [rbp-28]
    mov     edx, eax
    call    theme_aa_ensure
    test    eax, eax
    jz      tar_done

    mov     eax, dword ptr [rbp+64]
    mov     ecx, eax
    shr     ecx, 24
    test    ecx, ecx
    jnz     tar_chk_gtag
    mov     ecx, 255
    jmp     tar_set_fa
tar_chk_gtag:
    cmp     ecx, 66h                            ; GLASS_FILL_TAG >> 24 -> scheme-aware glass alpha
    jne     tar_set_fa
    mov     dword ptr [rbp-128], eax
    call    theme_glass_alpha
    mov     ecx, eax
    mov     eax, dword ptr [rbp-128]
tar_set_fa:
    mov     dword ptr [rbp-128], ecx            ; fillAlpha (1..255)
    and     eax, 00FFFFFFh
    mov     dword ptr [rbp-36], eax             ; colTop
    mov     ecx, dword ptr [rbp+72]
    xor     edx, edx
    test    ecx, 80000000h
    setnz   dl
    mov     dword ptr [rbp-44], edx             ; horizGrad
    and     ecx, 00FFFFFFh
    mov     dword ptr [rbp-40], ecx             ; colBot
    mov     eax, dword ptr [rbp+80]
    mov     dword ptr [rbp-48], eax             ; borderCol (-1 = none)
    mov     eax, dword ptr [rbp+88]
    mov     dword ptr [rbp-52], eax             ; specCol (-1 = none)

    ; gradDenom = max(1, (horizGrad ? w : h) - 1)
    mov     eax, dword ptr [rbp-32]
    cmp     dword ptr [rbp-44], 0
    je      @F
    mov     eax, dword ptr [rbp-28]
@@: dec     eax
    cmp     eax, 1
    jge     @F
    mov     eax, 1
@@: mov     dword ptr [rbp-84], eax

    ; hx = w * 0.5f, hy = h * 0.5f, rad = clamp(diam * 0.5f, 0, min(hx, hy))
    cvtsi2ss xmm0, dword ptr [rbp-28]
    mulss   xmm0, dword ptr [f_half]
    movss   dword ptr [rbp-56], xmm0            ; hx
    cvtsi2ss xmm1, dword ptr [rbp-32]
    mulss   xmm1, dword ptr [f_half]
    movss   dword ptr [rbp-60], xmm1            ; hy
    movaps  xmm2, xmm0
    minss   xmm2, xmm1                          ; min(hx, hy)
    xorps   xmm3, xmm3
    mov     eax, dword ptr [rbp+56]
    cmp     eax, 0
    jle     @F
    cvtsi2ss xmm3, eax
    mulss   xmm3, dword ptr [f_half]
    minss   xmm3, xmm2
@@: movss   dword ptr [rbp-72], xmm3            ; rad
    subss   xmm0, xmm3
    movss   dword ptr [rbp-64], xmm0            ; bx = hx - rad
    subss   xmm1, xmm3
    movss   dword ptr [rbp-68], xmm1            ; by = hy - rad

    mov     dword ptr [rbp-76], 0               ; iy = 0
tar_ylp:
    mov     eax, dword ptr [rbp-76]
    cmp     eax, dword ptr [rbp-32]
    jge     tar_blit

    ; rowPtr = g_aa_bits + iy * g_aa_capw * 4
    imul    eax, dword ptr [g_aa_capw]
    shl     eax, 2
    mov     rcx, qword ptr [g_aa_bits]
    add     rcx, rax
    mov     qword ptr [rbp-104], rcx

    ; py = abs((iy + 0.5f) - hy), py_sub = py - by, qy2 = max(py_sub, 0)^2
    cvtsi2ss xmm0, dword ptr [rbp-76]
    addss   xmm0, dword ptr [f_half]
    subss   xmm0, dword ptr [rbp-60]
    movd    eax, xmm0
    and     eax, dword ptr [f_abs_mask]
    movd    xmm0, eax                           ; py
    subss   xmm0, dword ptr [rbp-68]            ; py_sub
    movss   dword ptr [rbp-108], xmm0
    xorps   xmm1, xmm1
    maxss   xmm0, xmm1                          ; qy
    mulss   xmm0, xmm0
    movss   dword ptr [rbp-112], xmm0           ; qy * qy

    ; Precompute rowCol & opaque rowBgra when vertical/solid fill
    mov     eax, dword ptr [rbp-36]
    cmp     dword ptr [rbp-44], 0
    jne     tar_rowcol_set
    cmp     eax, dword ptr [rbp-40]
    je      tar_rowcol_set
    mov     eax, dword ptr [rbp-76]
    shl     eax, 8
    cdq
    idiv    dword ptr [rbp-84]
    mov     r8d, eax
    mov     ecx, dword ptr [rbp-36]
    mov     edx, dword ptr [rbp-40]
    call    aa_lerp_rgb
tar_rowcol_set:
    mov     dword ptr [rbp-88], eax
    mov     ecx, eax
    mov     edx, dword ptr [rbp-128]            ; fillAlpha (255 opaque, or e.g. 102 = 40% glass)
    call    aa_pack_pm
    mov     dword ptr [rbp-92], eax

    mov     dword ptr [rbp-80], 0               ; ix = 0
tar_xlp:
    mov     r8d, dword ptr [rbp-80]
    cmp     r8d, dword ptr [rbp-28]
    jge     tar_ynext

    ; px = abs((ix + 0.5f) - hx), px_sub = px - bx
    cvtsi2ss xmm0, r8d
    addss   xmm0, dword ptr [f_half]
    subss   xmm0, dword ptr [rbp-56]
    movd    eax, xmm0
    and     eax, dword ptr [f_abs_mask]
    movd    xmm0, eax
    subss   xmm0, dword ptr [rbp-64]            ; px_sub

    ; qx = max(px_sub, 0), outLen = sqrt(qx^2 + qy^2)
    xorps   xmm2, xmm2
    movaps  xmm1, xmm0
    maxss   xmm1, xmm2
    mulss   xmm1, xmm1
    addss   xmm1, dword ptr [rbp-112]
    sqrtss  xmm1, xmm1

    ; inNeg = min(max(px_sub, py_sub), 0)
    maxss   xmm0, dword ptr [rbp-108]
    minss   xmm0, xmm2
    addss   xmm1, xmm0
    subss   xmm1, dword ptr [rbp-72]            ; xmm1 = dist

    ; Outside check: dist >= 0.5f -> 0
    comiss  xmm1, dword ptr [f_half]
    jb      tar_inside
    mov     r11, qword ptr [rbp-104]
    mov     dword ptr [r11 + r8*4], 0
    inc     dword ptr [rbp-80]
    jmp     tar_xlp

tar_inside:
    ; Fast interior path: dist <= -1.5f, vertical/solid fill, not on top 2px specular row
    mov     eax, dword ptr [f_neg_half]         ; -0.5f; check -1.5f (0BFC00000h)
    mov     ecx, 0BFC00000h                     ; -1.5f
    movd    xmm3, ecx
    comiss  xmm3, xmm1                          ; -1.5f >= dist ?
    jb      tar_edge
    cmp     dword ptr [rbp-44], 0
    jne     tar_edge
    cmp     dword ptr [rbp-52], -1
    je      tar_fast_px
    cmp     dword ptr [rbp-76], 2
    jl      tar_edge
tar_fast_px:
    mov     eax, dword ptr [rbp-92]
    mov     r11, qword ptr [rbp-104]
    mov     ecx, dword ptr [rbp-28]             ; w
    sub     ecx, r8d
    sub     ecx, r8d                            ; symmetric interior span = w - 2*ix
    cmp     ecx, 1
    jg      tar_fast_span
    mov     dword ptr [r11 + r8*4], eax
    inc     dword ptr [rbp-80]
    jmp     tar_xlp
tar_fast_span:
    mov     qword ptr [rbp-144], rdi
    lea     rdi, [r11 + r8*4]
    add     dword ptr [rbp-80], ecx
    rep     stosd
    mov     rdi, qword ptr [rbp-144]
    jmp     tar_xlp

tar_edge:
    movss   dword ptr [rbp-116], xmm1           ; save dist
    ; Fill color for this pixel
    mov     eax, dword ptr [rbp-88]
    cmp     dword ptr [rbp-44], 0
    je      tar_got_fill
    mov     eax, dword ptr [rbp-36]
    cmp     eax, dword ptr [rbp-40]
    je      tar_got_fill
    mov     eax, dword ptr [rbp-80]
    shl     eax, 8
    cdq
    idiv    dword ptr [rbp-84]
    mov     r8d, eax
    mov     ecx, dword ptr [rbp-36]
    mov     edx, dword ptr [rbp-40]
    call    aa_lerp_rgb
tar_got_fill:
    mov     ecx, eax                            ; ecx = fillCol
    cmp     dword ptr [rbp-128], 255
    jb      tar_edge_glass

    ; ---- Opaque interior edge path (fillAlpha == 255) ----
    cmp     dword ptr [rbp-48], -1
    je      tar_inner_spec

    ; inCov256 = clamp((-0.5f - dist) * 256.0f, 0, 256)
    movss   xmm0, dword ptr [f_neg_half]
    subss   xmm0, dword ptr [rbp-116]
    mulss   xmm0, dword ptr [f_256]
    cvttss2si r8d, xmm0
    cmp     r8d, 0
    jge     @F
    xor     r8d, r8d
@@: cmp     r8d, 256
    jge     tar_calc_alpha                      ; wholly inside border -> keep fillCol

    ; Effective border color (top-lit 1px specular on iy <= 1 when specCol != -1)
    mov     edx, dword ptr [rbp-48]             ; borderCol
    cmp     dword ptr [rbp-52], -1
    je      tar_mix_bd
    cmp     dword ptr [rbp-76], 1
    jg      tar_mix_bd
    mov     dword ptr [rbp-120], ecx            ; save fillCol
    mov     dword ptr [rbp-124], r8d            ; save inCov256
    mov     ecx, edx                            ; borderCol
    mov     edx, dword ptr [rbp-52]             ; specCol
    mov     r8d, 240
    cmp     dword ptr [rbp-76], 0
    je      @F
    mov     r8d, 96
@@: call    aa_lerp_rgb
    mov     edx, eax                            ; top-lit borderCol
    mov     ecx, dword ptr [rbp-120]            ; fillCol
    mov     r8d, dword ptr [rbp-124]            ; inCov256
tar_mix_bd:
    ; mix(effBorderCol=edx, fillCol=ecx, inCov256=r8d)
    xchg    ecx, edx
    call    aa_lerp_rgb
    mov     ecx, eax
    jmp     tar_calc_alpha

tar_inner_spec:
    ; Borderless inner glass rim (for monogram tiles #18 when specCol != -1)
    cmp     dword ptr [rbp-52], -1
    je      tar_calc_alpha
    cmp     dword ptr [rbp-76], 2
    jg      tar_calc_alpha
    movss   xmm0, dword ptr [rbp-116]
    mov     eax, 0BFC00000h                     ; -1.5f
    movd    xmm2, eax
    comiss  xmm0, xmm2                          ; dist > -1.5f ?
    jbe     tar_calc_alpha
    mov     edx, dword ptr [rbp-52]
    mov     r8d, 92
    cmp     dword ptr [rbp-76], 0
    je      @F
    mov     r8d, 44
@@: call    aa_lerp_rgb
    mov     ecx, eax

tar_calc_alpha:
    ; alpha = clamp(round((0.5f - dist) * 255.0f), 0, 255)
    movss   xmm0, dword ptr [f_half]
    subss   xmm0, dword ptr [rbp-116]
    mulss   xmm0, dword ptr [f_255]
    addss   xmm0, dword ptr [f_half]
    cvttss2si edx, xmm0
    cmp     edx, 0
    jge     @F
    xor     edx, edx
@@: cmp     edx, 255
    jle     @F
    mov     edx, 255
@@: call    aa_pack_pm
    jmp     tar_store_px

tar_edge_glass:
    ; ---- Semi-transparent glass edge path (fillAlpha < 255) ----
    mov     edx, dword ptr [rbp-128]
    call    aa_pack_pm
    mov     dword ptr [rbp-132], eax            ; pmFill

    ; covOut256 = clamp(round((0.5f - dist) * 256.0f), 0, 256)
    movss   xmm0, dword ptr [f_half]
    subss   xmm0, dword ptr [rbp-116]
    mulss   xmm0, dword ptr [f_256]
    addss   xmm0, dword ptr [f_half]
    cvttss2si r9d, xmm0
    cmp     r9d, 0
    jge     @F
    xor     r9d, r9d
@@: cmp     r9d, 256
    jle     @F
    mov     r9d, 256
@@: cmp     dword ptr [rbp-48], -1
    jne     tar_gl_bd
    mov     ecx, dword ptr [rbp-132]
    mov     edx, ecx
    xor     r8d, r8d
    call    aa_lerp_pm_cov
    jmp     tar_store_px

tar_gl_bd:
    ; inCov256 = clamp((-0.5f - dist) * 256.0f, 0, 256)
    movss   xmm0, dword ptr [f_neg_half]
    subss   xmm0, dword ptr [rbp-116]
    mulss   xmm0, dword ptr [f_256]
    cvttss2si r8d, xmm0
    cmp     r8d, 0
    jge     @F
    xor     r8d, r8d
@@: cmp     r8d, 256
    jle     @F
    mov     r8d, 256
@@: mov     dword ptr [rbp-124], r8d            ; save inCov256
    mov     dword ptr [rbp-120], r9d            ; save covOut256

    mov     ecx, dword ptr [rbp-48]             ; borderCol
    cmp     dword ptr [rbp-52], -1
    je      tar_gl_bdpm
    cmp     dword ptr [rbp-76], 1
    jg      tar_gl_bdpm
    mov     edx, dword ptr [rbp-52]             ; specCol
    mov     r8d, 210
    cmp     dword ptr [rbp-76], 0
    je      @F
    mov     r8d, 80
@@: call    aa_lerp_rgb
    mov     ecx, eax
tar_gl_bdpm:
    mov     edx, 168                            ; crisp, balanced 1px glass rim alpha (66%)
    call    aa_pack_pm                          ; eax = pmBd
    mov     ecx, eax
    mov     edx, dword ptr [rbp-132]            ; pmFill
    mov     r8d, dword ptr [rbp-124]            ; inCov256
    mov     r9d, dword ptr [rbp-120]            ; covOut256
    call    aa_lerp_pm_cov

tar_store_px:
    mov     r8d, dword ptr [rbp-80]
    mov     r11, qword ptr [rbp-104]
    mov     dword ptr [r11 + r8*4], eax
    inc     dword ptr [rbp-80]
    jmp     tar_xlp

tar_ynext:
    inc     dword ptr [rbp-76]
    jmp     tar_ylp

tar_blit:
    WINCALL GdiFlush
    WINCALL AlphaBlend, qword ptr [rbp-16], dword ptr [rbp-20], dword ptr [rbp-24], \
            dword ptr [rbp-28], dword ptr [rbp-32], qword ptr [g_aa_hdc], 0, 0, \
            dword ptr [rbp-28], dword ptr [rbp-32], 01FF0000h
tar_done:
    mov     eax, 1
    FRAME_EPILOG
    ret
theme_aa_rrect endp

; theme_glass_alpha() -> eax = glass card opacity (0..255):
;   Dark schemes:  180 (~70.6% smoked glass — grounded dark panel + clear backdrop glow)
;   Light schemes: 115 (~45.1% frosted glass)
public theme_glass_alpha
theme_glass_alpha proc
    mov     eax, 180
    cmp     dword ptr [g_col_dark], 0
    jne     @F
    mov     eax, 115
@@: ret
theme_glass_alpha endp

; =============================================================================
; theme_glass_tint(rcx=hdc, edx=L, r8d=T, r9d=W, [rbp+48]=H, [rbp+56]=col,
;   [rbp+64]=alpha) -> eax = 1
;   Blends an unstretched WxH premultiplied surface over hdc using the exact
;   same aa_pack_pm + AlphaBlend path as theme_aa_rrect's interior, ensuring
;   0-LSB match between glass cards and child controls inside them.
; =============================================================================
public theme_glass_tint
theme_glass_tint proc frame
    FRAME_PROLOG 224
    mov     qword ptr [rbp-16], rcx             ; hdc
    mov     dword ptr [rbp-20], edx             ; L
    mov     dword ptr [rbp-24], r8d             ; T
    cmp     r9d, 0
    jle     tgt_done
    mov     dword ptr [rbp-28], r9d             ; W
    mov     eax, dword ptr [rbp+48]
    cmp     eax, 0
    jle     tgt_done
    mov     dword ptr [rbp-32], eax             ; H

    mov     ecx, r9d
    mov     edx, eax
    call    theme_aa_ensure
    test    eax, eax
    jz      tgt_done

    mov     ecx, dword ptr [rbp+56]
    and     ecx, 00FFFFFFh
    mov     edx, dword ptr [rbp+64]
    call    aa_pack_pm
    mov     r10d, eax                           ; premultiplied fill pixel

    mov     qword ptr [rbp-40], rdi
    xor     edx, edx                            ; iy = 0
tgt_ylp:
    cmp     edx, dword ptr [rbp-32]
    jge     tgt_ydone
    mov     eax, edx
    imul    eax, dword ptr [g_aa_capw]
    shl     eax, 2
    mov     rdi, qword ptr [g_aa_bits]
    add     rdi, rax
    mov     eax, r10d
    mov     ecx, dword ptr [rbp-28]
    rep     stosd
    inc     edx
    jmp     tgt_ylp
tgt_ydone:
    mov     rdi, qword ptr [rbp-40]

tgt_blit:
    WINCALL GdiFlush
    WINCALL AlphaBlend, qword ptr [rbp-16], dword ptr [rbp-20], dword ptr [rbp-24], \
            dword ptr [rbp-28], dword ptr [rbp-32], qword ptr [g_aa_hdc], 0, 0, \
            dword ptr [rbp-28], dword ptr [rbp-32], 01FF0000h
tgt_done:
    mov     eax, 1
    FRAME_EPILOG
    ret
theme_glass_tint endp

; =============================================================================
; theme_drop_shadow(rcx=hdc, edx=L, r8d=T, r9d=R, [rbp+48]=B, [rbp+56]=diam) -> eax = 1
;   9px soft cast drop-shadow (+3px vertical offset) around elevated cards,
;   masked out inside the card interior so 40% semi-transparent glass cards
;   remain completely clear and unmuddied inside.
; =============================================================================
public theme_drop_shadow
theme_drop_shadow proc frame
    FRAME_PROLOG 256
    ; Shadow rect expands card by (-9, -7, +9, +11): 9px blur around +2px Y offset
    mov     qword ptr [rbp-16], rcx             ; hdc
    mov     eax, edx
    sub     eax, 9
    mov     dword ptr [rbp-20], eax             ; sL = L - 9
    mov     ecx, r8d
    sub     ecx, 7
    mov     dword ptr [rbp-24], ecx             ; sT = T - 7
    mov     r10d, r9d
    add     r10d, 9
    sub     r10d, eax
    jle     tds_done
    mov     dword ptr [rbp-28], r10d            ; sW = cardW + 18
    mov     r11d, dword ptr [rbp+48]
    add     r11d, 11
    sub     r11d, ecx
    jle     tds_done
    mov     dword ptr [rbp-32], r11d            ; sH = cardH + 18
    sub     r9d, edx
    jle     tds_done
    mov     dword ptr [rbp-36], r9d             ; cardW
    mov     eax, dword ptr [rbp+48]
    sub     eax, r8d
    jle     tds_done
    mov     dword ptr [rbp-40], eax             ; cardH

    mov     ecx, dword ptr [rbp-28]
    mov     edx, dword ptr [rbp-32]
    call    theme_aa_ensure
    test    eax, eax
    jz      tds_done

    ; Unshifted card center: cx = sW * 0.5f, cyCard = 7.0f + hy; shifted: cyShad = 9.0f + hy
    cvtsi2ss xmm0, dword ptr [rbp-28]
    mulss   xmm0, dword ptr [f_half]
    movss   dword ptr [rbp-44], xmm0            ; cx
    cvtsi2ss xmm1, dword ptr [rbp-40]
    mulss   xmm1, dword ptr [f_half]
    movaps  xmm4, xmm1                          ; hy = cardH * 0.5f
    addss   xmm1, dword ptr [f_seven]
    movss   dword ptr [rbp-48], xmm1            ; cyCard = hy + 7.0f
    addss   xmm1, dword ptr [f_two]
    movss   dword ptr [rbp-92], xmm1            ; cyShad = hy + 9.0f (+2px Y offset)

    cvtsi2ss xmm2, dword ptr [rbp-36]
    mulss   xmm2, dword ptr [f_half]            ; hx = cardW * 0.5f
    movaps  xmm5, xmm2
    minss   xmm5, xmm4                          ; min(hx, hy)
    xorps   xmm3, xmm3
    mov     eax, dword ptr [rbp+56]
    cmp     eax, 0
    jle     @F
    cvtsi2ss xmm3, eax
    mulss   xmm3, dword ptr [f_half]
    minss   xmm3, xmm5
@@: movss   dword ptr [rbp-52], xmm3            ; rad
    subss   xmm2, xmm3
    movss   dword ptr [rbp-56], xmm2            ; bx = hx - rad
    subss   xmm4, xmm3
    movss   dword ptr [rbp-60], xmm4            ; by = hy - rad

    mov     eax, 36                             ; subtle 9px dark-scheme cast shadow (~14%)
    cmp     dword ptr [g_col_dark], 0
    jne     @F
    mov     eax, 18                             ; feather-light cast shadow on light schemes (~7%)
@@: cvtsi2ss xmm5, eax
    movss   dword ptr [rbp-64], xmm5            ; maxAlpha

    mov     dword ptr [rbp-68], 0               ; iy = 0
tds_ylp:
    mov     eax, dword ptr [rbp-68]
    cmp     eax, dword ptr [rbp-32]
    jge     tds_blit
    imul    eax, dword ptr [g_aa_capw]
    shl     eax, 2
    mov     rcx, qword ptr [g_aa_bits]
    add     rcx, rax
    mov     qword ptr [rbp-80], rcx

    ; Row Y terms for unshifted card (pyCard_sub, qyCard2)
    cvtsi2ss xmm0, dword ptr [rbp-68]
    addss   xmm0, dword ptr [f_half]
    movaps  xmm3, xmm0                          ; y = iy + 0.5f
    subss   xmm0, dword ptr [rbp-48]            ; y - cyCard
    movd    eax, xmm0
    and     eax, dword ptr [f_abs_mask]
    movd    xmm0, eax
    subss   xmm0, dword ptr [rbp-60]
    movss   dword ptr [rbp-84], xmm0            ; pyCard_sub
    xorps   xmm1, xmm1
    maxss   xmm0, xmm1
    mulss   xmm0, xmm0
    movss   dword ptr [rbp-88], xmm0            ; qyCard^2

    ; Row Y terms for +3px shifted shadow (pyShad_sub, qyShad2)
    subss   xmm3, dword ptr [rbp-92]            ; y - cyShad
    movd    eax, xmm3
    and     eax, dword ptr [f_abs_mask]
    movd    xmm3, eax
    subss   xmm3, dword ptr [rbp-60]
    movss   dword ptr [rbp-96], xmm3            ; pyShad_sub
    maxss   xmm3, xmm1
    mulss   xmm3, xmm3
    movss   dword ptr [rbp-100], xmm3           ; qyShad^2

    xor     r8d, r8d                            ; ix = 0
tds_xlp:
    cmp     r8d, dword ptr [rbp-28]
    jge     tds_ynext
    cvtsi2ss xmm0, r8d
    addss   xmm0, dword ptr [f_half]
    subss   xmm0, dword ptr [rbp-44]
    movd    eax, xmm0
    and     eax, dword ptr [f_abs_mask]
    movd    xmm0, eax
    subss   xmm0, dword ptr [rbp-56]            ; xmm0 = px_sub

    xorps   xmm2, xmm2
    movaps  xmm4, xmm0
    maxss   xmm4, xmm2
    mulss   xmm4, xmm4                          ; xmm4 = qx^2

    ; 1) Unshifted card SDF distance (mask interior so glass stays clear)
    movaps  xmm1, xmm4
    addss   xmm1, dword ptr [rbp-88]
    sqrtss  xmm1, xmm1
    movaps  xmm3, xmm0
    maxss   xmm3, dword ptr [rbp-84]
    minss   xmm3, xmm2
    addss   xmm1, xmm3
    subss   xmm1, dword ptr [rbp-52]            ; xmm1 = distCard
    comiss  xmm1, dword ptr [f_neg_half]
    ja      tds_outside
    mov     r11, qword ptr [rbp-80]
    mov     ecx, dword ptr [rbp-28]             ; sW
    sub     ecx, r8d
    sub     ecx, r8d                            ; symmetric interior mask span = sW - 2*ix
    cmp     ecx, 1
    jg      tds_zero_span
    mov     dword ptr [r11 + r8*4], 0
    inc     r8d
    jmp     tds_xlp
tds_zero_span:
    mov     qword ptr [rbp-112], rdi
    lea     rdi, [r11 + r8*4]
    add     r8d, ecx
    xor     eax, eax
    rep     stosd
    mov     rdi, qword ptr [rbp-112]
    jmp     tds_xlp

tds_outside:
    ; covOut = min(distCard + 0.5f, 1.0f) in (0..1]
    addss   xmm1, dword ptr [f_half]
    minss   xmm1, dword ptr [f_one]             ; xmm1 = covOut

    ; 2) Shifted shadow SDF distance
    addss   xmm4, dword ptr [rbp-100]
    sqrtss  xmm4, xmm4
    maxss   xmm0, dword ptr [rbp-96]
    minss   xmm0, xmm2
    addss   xmm4, xmm0
    subss   xmm4, dword ptr [rbp-52]            ; xmm4 = distShad

    ; 9px cubic falloff: t = clamp((9.0f - max(distShad, 0.0f)) / 9.0f, 0, 1)
    maxss   xmm4, xmm2
    movss   xmm0, dword ptr [f_nine]
    subss   xmm0, xmm4
    mulss   xmm0, dword ptr [f_inv_nine]
    maxss   xmm0, xmm2
    minss   xmm0, dword ptr [f_one]
    movaps  xmm3, xmm0
    mulss   xmm0, xmm0
    mulss   xmm0, xmm3                          ; t^3 Gaussian-like feather
    mulss   xmm0, dword ptr [rbp-64]            ; * maxAlpha
    mulss   xmm0, xmm1                          ; * covOut
    cvttss2si eax, xmm0
    shl     eax, 24                             ; premultiplied black 0xAA000000
    mov     r11, qword ptr [rbp-80]
    mov     dword ptr [r11 + r8*4], eax
    inc     r8d
    jmp     tds_xlp
tds_ynext:
    inc     dword ptr [rbp-68]
    jmp     tds_ylp

tds_blit:
    WINCALL GdiFlush
    WINCALL AlphaBlend, qword ptr [rbp-16], dword ptr [rbp-20], dword ptr [rbp-24], \
            dword ptr [rbp-28], dword ptr [rbp-32], qword ptr [g_aa_hdc], 0, 0, \
            dword ptr [rbp-28], dword ptr [rbp-32], 01FF0000h
tds_done:
    mov     eax, 1
    FRAME_EPILOG
    ret
theme_drop_shadow endp

; =============================================================================
; theme_aa_arc(rcx=hdc, edx=L, r8d=T, r9d=size, [rbp+48]=thick,
;   [rbp+56]=start1024, [rbp+64]=end1024, [rbp+72]=col) -> eax = 1
;   Anti-aliased circular arc / donut segment (#3 TOTP ring, #17 Vault Health).
;   Angles run clockwise from 12 o'clock (0..1024).
; =============================================================================
public theme_aa_arc
theme_aa_arc proc frame
    FRAME_PROLOG 240
    mov     qword ptr [rbp-16], rcx             ; hdc
    mov     dword ptr [rbp-20], edx             ; L
    mov     dword ptr [rbp-24], r8d             ; T
    cmp     r9d, 4
    jl      taa_done
    mov     dword ptr [rbp-28], r9d             ; size
    mov     eax, dword ptr [rbp+56]             ; start1024
    mov     ecx, dword ptr [rbp+64]             ; end1024
    cmp     ecx, eax
    jle     taa_done
    mov     dword ptr [rbp-32], eax
    mov     dword ptr [rbp-36], ecx
    mov     eax, dword ptr [rbp+72]
    and     eax, 00FFFFFFh
    mov     dword ptr [rbp-40], eax             ; col

    mov     ecx, r9d
    mov     edx, r9d
    call    theme_aa_ensure
    test    eax, eax
    jz      taa_done

    ; c = size * 0.5f, halfT = thick * 0.5f, midR = c - halfT - 0.5f
    cvtsi2ss xmm0, dword ptr [rbp-28]
    mulss   xmm0, dword ptr [f_half]
    movss   dword ptr [rbp-44], xmm0            ; center
    cvtsi2ss xmm1, dword ptr [rbp+48]
    mulss   xmm1, dword ptr [f_half]
    movss   dword ptr [rbp-48], xmm1            ; halfT
    subss   xmm0, xmm1
    subss   xmm0, dword ptr [f_half]
    movss   dword ptr [rbp-52], xmm0            ; midR

    ; feather1024 = 1024.0f / max(2*pi*midR, 8.0f)
    mulss   xmm0, dword ptr [f_2pi]
    maxss   xmm0, dword ptr [f_eight]
    movss   xmm1, dword ptr [f_1024]
    divss   xmm1, xmm0
    movss   dword ptr [rbp-56], xmm1            ; feather1024
    cvtsi2ss xmm2, dword ptr [rbp-32]
    movss   dword ptr [rbp-60], xmm2            ; fStart
    cvtsi2ss xmm3, dword ptr [rbp-36]
    movss   dword ptr [rbp-64], xmm3            ; fEnd

    mov     dword ptr [rbp-68], 0               ; iy = 0
taa_ylp:
    mov     eax, dword ptr [rbp-68]
    cmp     eax, dword ptr [rbp-28]
    jge     taa_blit
    imul    eax, dword ptr [g_aa_capw]
    shl     eax, 2
    mov     rcx, qword ptr [g_aa_bits]
    add     rcx, rax
    mov     qword ptr [rbp-80], rcx

    cvtsi2ss xmm0, dword ptr [rbp-68]
    addss   xmm0, dword ptr [f_half]
    subss   xmm0, dword ptr [rbp-44]            ; dy
    movss   dword ptr [rbp-84], xmm0

    mov     dword ptr [rbp-72], 0               ; ix = 0
taa_xlp:
    mov     r8d, dword ptr [rbp-72]
    cmp     r8d, dword ptr [rbp-28]
    jge     taa_ynext

    cvtsi2ss xmm0, r8d
    addss   xmm0, dword ptr [f_half]
    subss   xmm0, dword ptr [rbp-44]            ; dx
    movss   xmm1, dword ptr [rbp-84]            ; dy
    movaps  xmm2, xmm0
    mulss   xmm2, xmm2
    movaps  xmm3, xmm1
    mulss   xmm3, xmm3
    addss   xmm2, xmm3
    sqrtss  xmm2, xmm2                          ; r = sqrt(dx^2 + dy^2)
    subss   xmm2, dword ptr [rbp-52]
    movd    eax, xmm2
    and     eax, dword ptr [f_abs_mask]
    movd    xmm2, eax
    subss   xmm2, dword ptr [rbp-48]            ; dRad = abs(r - midR) - halfT

    comiss  xmm2, dword ptr [f_0_6]
    jb      taa_in_rad
taa_px0:
    mov     r11, qword ptr [rbp-80]
    mov     dword ptr [r11 + r8*4], 0
    inc     dword ptr [rbp-72]
    jmp     taa_xlp

taa_in_rad:
    ; covRad = clamp(0.5f - dRad, 0, 1)
    movss   xmm4, dword ptr [f_half]
    subss   xmm4, xmm2
    xorps   xmm5, xmm5
    maxss   xmm4, xmm5
    minss   xmm4, dword ptr [f_one]             ; xmm4 = covRad

    ; Full circle fast path (start <= 0 && end >= 1024)
    cmp     dword ptr [rbp-32], 0
    jg      taa_ang
    cmp     dword ptr [rbp-36], 1024
    jge     taa_pack

taa_ang:
    ; Clockwise angle from 12 o'clock: ux = dx (xmm0), uy = -dy
    xorps   xmm1, xmm1
    subss   xmm1, dword ptr [rbp-84]            ; uy = -dy
    movd    eax, xmm0
    and     eax, dword ptr [f_abs_mask]
    movd    xmm2, eax                           ; ax = |ux|
    movd    ecx, xmm1
    and     ecx, dword ptr [f_abs_mask]
    movd    xmm3, ecx                           ; ay = |uy|

    ; Octant polynomial atan(min/max) in radians -> 0..256 per quadrant -> 0..1024
    comiss  xmm3, xmm2                          ; ay >= ax ?
    jb      taa_oct_x
    ; z = ax / max(ay, 1e-6), base = 0, angle_in_quad = atan(z)
    mov     eax, 358637BDh                      ; 1e-6f
    movd    xmm5, eax
    maxss   xmm3, xmm5
    divss   xmm2, xmm3                          ; z in [0, 1]
    movss   xmm3, dword ptr [f_one]
    subss   xmm3, xmm2
    mulss   xmm3, dword ptr [f_atan_k]
    addss   xmm3, dword ptr [f_pi_4]
    mulss   xmm2, xmm3                          ; rad in [0, pi/4]
    mulss   xmm2, dword ptr [f_rad_to_k]        ; in [0, 128]
    jmp     taa_quad
taa_oct_x:
    ; z = ay / ax, angle_in_quad = 256 - atan(z)*rad_to_k
    divss   xmm3, xmm2                          ; z in [0, 1)
    movss   xmm2, dword ptr [f_one]
    subss   xmm2, xmm3
    mulss   xmm2, dword ptr [f_atan_k]
    addss   xmm2, dword ptr [f_pi_4]
    mulss   xmm3, xmm2
    mulss   xmm3, dword ptr [f_rad_to_k]
    movss   xmm2, dword ptr [f_256]
    subss   xmm2, xmm3                          ; in [128, 256]

taa_quad:
    ; xmm2 = angle from Y-axis inside quadrant [0..256]
    ; Quadrant mapping for clockwise from +uy (12 o'clock):
    ;   ux >= 0, uy >= 0 (TR): ang = xmm2               (0..256)
    ;   ux >= 0, uy <  0 (BR): ang = 512 - xmm2         (256..512)
    ;   ux <  0, uy <  0 (BL): ang = 512 + xmm2         (512..768)
    ;   ux <  0, uy >= 0 (TL): ang = 1024 - xmm2        (768..1024)
    xorps   xmm5, xmm5
    comiss  xmm0, xmm5                          ; ux >= 0 ?
    jb      taa_q_left
    comiss  xmm1, xmm5                          ; uy >= 0 ?
    jae     taa_ang_chk
    movss   xmm3, dword ptr [f_512]
    subss   xmm3, xmm2
    movaps  xmm2, xmm3
    jmp     taa_ang_chk
taa_q_left:
    comiss  xmm1, xmm5                          ; uy >= 0 ?
    jae     taa_q_tl
    addss   xmm2, dword ptr [f_512]
    jmp     taa_ang_chk
taa_q_tl:
    movss   xmm3, dword ptr [f_1024]
    subss   xmm3, xmm2
    movaps  xmm2, xmm3

taa_ang_chk:
    ; Smooth angular coverage at fStart and fEnd using feather1024
    movss   xmm3, dword ptr [rbp-56]            ; feather
    movaps  xmm0, xmm2
    subss   xmm0, dword ptr [rbp-60]            ; ang - fStart
    divss   xmm0, xmm3
    addss   xmm0, dword ptr [f_half]
    xorps   xmm5, xmm5
    maxss   xmm0, xmm5
    minss   xmm0, dword ptr [f_one]

    movss   xmm1, dword ptr [rbp-64]
    subss   xmm1, xmm2                          ; fEnd - ang
    divss   xmm1, xmm3
    addss   xmm1, dword ptr [f_half]
    maxss   xmm1, xmm5
    minss   xmm1, dword ptr [f_one]

    mulss   xmm4, xmm0
    mulss   xmm4, xmm1

taa_pack:
    mulss   xmm4, dword ptr [f_255]
    addss   xmm4, dword ptr [f_half]
    cvttss2si edx, xmm4
    test    edx, edx
    jle     taa_px0
    cmp     edx, 255
    jle     @F
    mov     edx, 255
@@: mov     ecx, dword ptr [rbp-40]
    call    aa_pack_pm
    mov     r8d, dword ptr [rbp-72]
    mov     r11, qword ptr [rbp-80]
    mov     dword ptr [r11 + r8*4], eax
    inc     dword ptr [rbp-72]
    jmp     taa_xlp

taa_ynext:
    inc     dword ptr [rbp-68]
    jmp     taa_ylp

taa_blit:
    WINCALL GdiFlush
    WINCALL AlphaBlend, qword ptr [rbp-16], dword ptr [rbp-20], dword ptr [rbp-24], \
            dword ptr [rbp-28], dword ptr [rbp-28], qword ptr [g_aa_hdc], 0, 0, \
            dword ptr [rbp-28], dword ptr [rbp-28], 01FF0000h
taa_done:
    mov     eax, 1
    FRAME_EPILOG
    ret
theme_aa_arc endp

; =============================================================================
; theme_sidecard(rcx=hwnd, rdx=hdc) - draw the sidebar as an anti-aliased
;   rounded card in the scheme sidebar colour, with a soft translucent drop
;   shadow and 1px top-lit specular border (#13, #15).
; =============================================================================
theme_sidecard proc frame
    FRAME_PROLOG 224
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    lea     rdx, [rbp-128]                    ; rect {L,T,R,B}
    mov     rcx, qword ptr [rbp-24]
    call    sidebar_rect
    WINCALL theme_drop_shadow, qword ptr [rbp-32], dword ptr [rbp-128], dword ptr [rbp-124], \
            dword ptr [rbp-120], dword ptr [rbp-116], 14
    mov     eax, dword ptr [g_col_side]
    or      eax, GLASS_FILL_TAG
    mov     dword ptr [rbp-40], eax
    WINCALL theme_aa_rrect, qword ptr [rbp-32], dword ptr [rbp-128], dword ptr [rbp-124], \
            dword ptr [rbp-120], dword ptr [rbp-116], 7, \
            dword ptr [rbp-40], dword ptr [g_col_side], \
            dword ptr [g_col_border], dword ptr [g_col_spec]
    FRAME_EPILOG
    ret
theme_sidecard endp

; =============================================================================
; theme_paint(rcx=hwnd) -> 0 ("unhandled") - the flat background comes from
;   theme_erase (WM_ERASEBKGND); the default paint pass draws controls over it.
; =============================================================================
public theme_paint
theme_paint proc frame
    FRAME_PROLOG 224
    xor     eax, eax
    FRAME_EPILOG
    ret
theme_paint endp

; frame_cb(rcx=child, rdx=lparam) -> BOOL - draw a Fluent bottom-border underline
;   under each visible Edit: 1px hairline at rest, center-out animated 2px accent
;   bar when focused (#1), or 4-segment strength meter bar (#16).
;   EnumChildWindows callback.  src RECT @ [rbp-40], underline RECT @ [rbp-72].
frame_cb proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 208
    mov     qword ptr [rbp-8], rcx
    WINCALL GetParent, rcx
    cmp     rax, qword ptr [g_frame_par]
    jne     fc_skip
    mov     rcx, qword ptr [rbp-8]
    call    IsWindowVisible
    test    eax, eax
    jz      fc_skip
    mov     rcx, qword ptr [rbp-8]
    lea     rdx, [g_clsbuf]
    mov     r8d, 16
    call    GetClassNameW
    movzx   eax, word ptr [g_clsbuf]
    cmp     eax, 'E'                          ; only "Edit" controls get the underline / glass frame
    jne     fc_skip
    mov     rcx, qword ptr [rbp-8]            ; row-card edits (id >= 3000) sit on filled
    call    GetDlgCtrlID                      ;   panels -> drawn by gui_draw_field_cards
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

    ; Standalone glass Edit boxes on DLG_SETTINGS and IDC_V_TITLE on DLG_VAULT:
    ; draw 9px cast shadow + 40% glass fill + 1px border (accent on focus).
    mov     rax, qword ptr [g_frame_par]
    cmp     rax, qword ptr [g_settings_hwnd]
    je      fc_glass_box
    cmp     rax, qword ptr [g_vaulthwnd]
    jne     fc_chk_seg
    cmp     dword ptr [rbp-80], IDC_V_SEARCH_TH
    je      fc_chk_seg
fc_glass_box:
    mov     eax, dword ptr [rbp-40]
    sub     eax, 3
    mov     dword ptr [rbp-72], eax           ; gL = L - 3
    mov     eax, dword ptr [rbp-36]
    sub     eax, 1
    mov     dword ptr [rbp-68], eax           ; gT = T - 1
    mov     eax, dword ptr [rbp-32]
    add     eax, 3
    mov     dword ptr [rbp-64], eax           ; gR = R + 3
    mov     eax, dword ptr [rbp-28]
    add     eax, 1
    mov     dword ptr [rbp-60], eax           ; gB = B + 1
    WINCALL theme_drop_shadow, qword ptr [g_frame_hdc], dword ptr [rbp-72], dword ptr [rbp-68], \
            dword ptr [rbp-64], dword ptr [rbp-60], 5
    call    GetFocus
    mov     ecx, dword ptr [g_col_border]
    cmp     rax, qword ptr [rbp-8]
    jne     @F
    mov     ecx, dword ptr [g_col_accent]
@@: mov     dword ptr [rbp-96], ecx           ; borderCol
    mov     eax, dword ptr [g_col_panel]
    or      eax, GLASS_FILL_TAG
    mov     dword ptr [rbp-100], eax          ; 40% glass colTop
    WINCALL theme_aa_rrect, qword ptr [g_frame_hdc], dword ptr [rbp-72], dword ptr [rbp-68], \
            dword ptr [rbp-64], dword ptr [rbp-60], 5, \
            dword ptr [rbp-100], dword ptr [g_col_panel], dword ptr [rbp-96], dword ptr [g_col_spec]
    jmp     fc_skip

fc_chk_seg:
    ; 4-segment strength meter bar (#16) when non-empty on g_uline_seg_ctl?
    mov     ecx, dword ptr [rbp-80]
    cmp     ecx, dword ptr [g_uline_seg_ctl]
    jne     fc_not_seg
    cmp     dword ptr [g_uline_seg_lvl], 0
    jle     fc_not_seg
    cmp     qword ptr [g_uline_br], 0
    je      fc_not_seg
    ; Draw 4 segments across [L, R] with 3px gaps, 2px tall
    mov     eax, dword ptr [rbp-32]           ; R
    sub     eax, dword ptr [rbp-40]           ; totalW = R - L
    sub     eax, 9                            ; subtract 3 * 3px gaps
    cmp     eax, 16
    jl      fc_not_seg
    sar     eax, 2                            ; segW = (totalW - 9) / 4
    mov     dword ptr [rbp-88], eax           ; segW
    mov     dword ptr [rbp-92], 0             ; seg i = 0..3
fc_seg_lp:
    mov     ecx, dword ptr [rbp-92]
    cmp     ecx, 4
    jae     fc_skip
    mov     eax, dword ptr [rbp-88]
    add     eax, 3
    imul    eax, ecx
    add     eax, dword ptr [rbp-40]
    mov     dword ptr [rbp-72], eax           ; seg L
    cmp     ecx, 3
    jne     fc_seg_r
    mov     eax, dword ptr [rbp-32]           ; last segment lands flush on R
    jmp     fc_seg_setr
fc_seg_r:
    add     eax, dword ptr [rbp-88]
fc_seg_setr:
    mov     dword ptr [rbp-64], eax           ; seg R
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [rbp-68], eax           ; seg T = B
    add     eax, 2
    mov     dword ptr [rbp-60], eax           ; seg B = B + 2
    mov     r8, qword ptr [g_br_frame]
    mov     ecx, dword ptr [rbp-92]
    cmp     ecx, dword ptr [g_uline_seg_lvl]
    ja      @F
    mov     r8, qword ptr [g_uline_br]
@@: mov     rcx, qword ptr [g_frame_hdc]
    lea     rdx, [rbp-72]
    call    FillRect
    inc     dword ptr [rbp-92]
    jmp     fc_seg_lp

fc_not_seg:
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
    ; unfocused: a strength/match override shows persistently (2px), else 1px hairline
    mov     ecx, dword ptr [rbp-80]
    xor     r9, r9
    cmp     ecx, dword ptr [g_uline_ctl]
    jne     fc_nf_ov2
    mov     r9, qword ptr [g_uline_br]
    jmp     fc_nf_test
fc_nf_ov2:
    cmp     ecx, dword ptr [g_uline_ctl2]
    jne     fc_nf_test
    mov     r9, qword ptr [g_uline_br2]
fc_nf_test:
    test    r9, r9
    jz      fc_nf_hair
    mov     eax, dword ptr [rbp-28]
    add     eax, 2
    mov     dword ptr [rbp-60], eax           ; 2px strength/match bar
    mov     r8, r9
    jmp     fc_fill
fc_nf_hair:
    mov     eax, dword ptr [rbp-28]
    add     eax, 1
    mov     dword ptr [rbp-60], eax           ; 1px hairline
    mov     r8, qword ptr [g_br_frame]
    jmp     fc_fill
fc_focus:
    ; Always paint the 1px base hairline first so outer edges stay grounded during expand (#1)
    mov     eax, dword ptr [rbp-28]
    inc     eax
    mov     dword ptr [rbp-60], eax
    WINCALL FillRect, qword ptr [g_frame_hdc], addr rbp-72, qword ptr [g_br_frame]

    mov     eax, dword ptr [rbp-28]
    add     eax, 2
    mov     dword ptr [rbp-60], eax           ; 2px active underline
    ; Center-out expansion (#1) when this Edit is g_uline_anim_hwnd and ANIM_ULINE is active
    mov     rax, qword ptr [rbp-8]
    cmp     rax, qword ptr [g_uline_anim_hwnd]
    jne     fc_focus_col
    mov     ecx, ANIM_ULINE
    call    anim_active
    test    eax, eax
    jz      fc_focus_col
    mov     ecx, ANIM_ULINE
    call    anim_get                          ; 0..1024
    cmp     eax, 1024
    jge     fc_focus_col
    mov     ecx, dword ptr [rbp-32]           ; R
    sub     ecx, dword ptr [rbp-40]           ; W = R - L
    imul    ecx, eax
    sar     ecx, 11                           ; halfW = W * anim / 2048
    mov     edx, dword ptr [rbp-40]
    add     edx, dword ptr [rbp-32]
    sar     edx, 1                            ; mid = (L + R) / 2
    mov     eax, edx
    sub     eax, ecx
    mov     dword ptr [rbp-72], eax           ; mid - halfW
    add     edx, ecx
    mov     dword ptr [rbp-64], edx           ; mid + halfW

fc_focus_col:
    mov     r8, qword ptr [g_br_accent]       ; default accent
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
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx           ; hdc
    mov     qword ptr [rbp-32], rdx           ; hwnd
    WINCALL GetClientRect, qword ptr [rbp-32], addr rbp-72
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    gpu_paint_bg
    test    eax, eax
    jnz     te_bg_done
    WINCALL FillRect, qword ptr [rbp-24], addr rbp-72, qword ptr [g_br_bg]
te_bg_done:
    ; CRT scanline overlay for schemes flagged with it (dim 1px lines every 3px)
    call    theme_trait
    test    eax, 010000h                      ; flags byte2 bit0
    jz      te_noscan
    mov     eax, dword ptr [g_col_bg]          ; line colour = bg dimmed ~50%
    shr     eax, 1
    and     eax, 007F7F7Fh
    WINCALL CreateSolidBrush, eax
    mov     qword ptr [rbp-40], rax
    mov     eax, dword ptr [rbp-68]           ; y = rect.top
    mov     dword ptr [rbp-48], eax
te_scanlp:
    mov     eax, dword ptr [rbp-48]
    cmp     eax, dword ptr [rbp-60]           ; rect.bottom
    jge     te_scandone
    lea     r10, [rbp-96]                     ; line rect { left, y, right, y+1 }
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [r10], eax
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [r10+4], eax
    mov     eax, dword ptr [rbp-64]
    mov     dword ptr [r10+8], eax
    mov     eax, dword ptr [rbp-48]
    inc     eax
    mov     dword ptr [r10+12], eax
    WINCALL FillRect, qword ptr [rbp-24], addr rbp-96, qword ptr [rbp-40]
    add     dword ptr [rbp-48], 3
    jmp     te_scanlp
te_scandone:
    WINCALL DeleteObject, qword ptr [rbp-40]
te_noscan:
    mov     rax, qword ptr [rbp-32]           ; sidebar card + brand header: vault window only
    cmp     rax, qword ptr [g_vaulthwnd]
    jne     te_noside
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-24]
    call    theme_sidecard
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    gui_draw_brand_hdr
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

; =============================================================================
; theme_ctlcolor(rcx=hwnd, rdx=msg, r8=hdc, r9=hctl) -> HBRUSH
; =============================================================================
public theme_ctlcolor
theme_ctlcolor proc frame
    FRAME_PROLOG 112
    ; [rbp-24]=hdc [rbp-32]=msg [rbp-40]=hctl [rbp-48]=hwnd [rbp-64..rbp-49]=rcStatic
    mov     qword ptr [rbp-48], rcx           ; hwnd (dialog receiving WM_CTLCOLOR*)
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
    ; read-only edits also arrive here -> give them the input/glass colour; real
    ; Static labels pre-blit their GPU/glass backdrop slice before returning NULL_BRUSH
    ; so ClearType never double-accumulates on in-place repaints.
    WINCALL GetClassNameW, qword ptr [rbp-40], addr g_clsbuf, 16
    movzx   eax, word ptr [g_clsbuf]
    cmp     eax, 'E'
    je      tc_panel
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_text]
    WINCALL SetBkMode, qword ptr [rbp-24], BKMODE_TRANSP
    WINCALL GetDlgCtrlID, qword ptr [rbp-40]
    cmp     eax, 3000                         ; DS_TCODE inside a 40% glass field card
    jb      tc_stat_bg
    WINCALL GetClientRect, qword ptr [rbp-40], addr rbp-64
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [rbp-64]
    call    gpu_fill_glass_child
    test    eax, eax
    jz      tc_stat_bg
    WINCALL GetStockObject, NULL_BRUSH
    FRAME_EPILOG
    ret
tc_stat_bg:
    mov     rcx, qword ptr [rbp-48]
    call    gpu_is_surface_hwnd
    test    eax, eax
    jz      tc_stat_flat
    WINCALL GetClientRect, qword ptr [rbp-40], addr rbp-64
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [rbp-64]
    call    gpu_fill_child_bg
    test    eax, eax
    jz      tc_stat_flat
    WINCALL GetStockObject, NULL_BRUSH
    FRAME_EPILOG
    ret
tc_stat_flat:
    mov     rax, qword ptr [g_br_bg]
    FRAME_EPILOG
    ret
tc_panel:
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_text]
    mov     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [g_vaulthwnd]
    je      tc_panel_glass
    cmp     rax, qword ptr [g_settings_hwnd]
    je      tc_panel_glass
    WINCALL SetBkColor, qword ptr [rbp-24], dword ptr [g_col_panel]
    mov     rax, qword ptr [g_br_panel]
    FRAME_EPILOG
    ret
tc_panel_glass:
    WINCALL SetBkMode, qword ptr [rbp-24], BKMODE_TRANSP
    mov     rcx, qword ptr [rbp-40]
    call    gpu_sample_glass_child
    WINCALL SetBkColor, qword ptr [rbp-24], eax
    WINCALL GetClientRect, qword ptr [rbp-40], addr rbp-64
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [rbp-64]
    call    gpu_fill_glass_child
    WINCALL GetStockObject, NULL_BRUSH
    FRAME_EPILOG
    ret
tc_edit:
    ; the sidebar search box uses semi-transparent sidebar glass on DLG_VAULT;
    ; detail-pane field edits keep the panel glass colour
    WINCALL GetDlgCtrlID, qword ptr [rbp-40]
    cmp     eax, IDC_V_SEARCH_TH
    jne     tc_panel
    mov     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [g_vaulthwnd]
    jne     tc_side
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_text]
    WINCALL SetBkMode, qword ptr [rbp-24], BKMODE_TRANSP
    mov     rcx, qword ptr [rbp-40]
    call    gpu_sample_side_glass_child
    WINCALL SetBkColor, qword ptr [rbp-24], eax
    WINCALL GetClientRect, qword ptr [rbp-40], addr rbp-64
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [rbp-64]
    call    gpu_fill_side_glass_child
    WINCALL GetStockObject, NULL_BRUSH
    FRAME_EPILOG
    ret
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
    FRAME_PROLOG 272
    ; [rbp-24] lpdis [rbp-32] hdc [rbp-40] hwndItem [rbp-48] state [rbp-56] style
    ; rcItem @ [rbp-80] (L,T,R,B)   rcText @ [rbp-160] (L,T,R,B)
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
    mov     eax, dword ptr [rcx+4]            ; CtlID: 297 = search-overlay panel -> add a frame
    cmp     eax, 297
    jne     tdi_static_done
    WINCALL FrameRect, qword ptr [rbp-32], addr rbp-80, qword ptr [g_br_frame]
tdi_static_done:
    mov     eax, 1
    FRAME_EPILOG
    ret
tdi_notstatic:
    WINCALL GetWindowLongPtrW, qword ptr [rbp-40], GWL_STYLE
    mov     dword ptr [rbp-56], eax
    WINCALL GetWindowTextW, qword ptr [rbp-40], addr g_txtbuf, 159
    WINCALL SetBkMode, qword ptr [rbp-32], BKMODE_TRANSP
    mov     eax, dword ptr [rbp-56]
    and     eax, BS_TYPEMASK
    cmp     eax, BS_GROUPBOX
    je      tdi_group
    ; ---------- push button (Fluent AA: accent primary / neutral standard) ---
    WINCALL GetWindowLongPtrW, qword ptr [rbp-40], GWL_USERDATA
    mov     qword ptr [rbp-128], rax          ; save userdata (ghost: glyph<<16 | hover<<8 | 2)
    movzx   ecx, al                           ; style byte: 0 standard, 1 accent, 2 ghost, 3 search-pill
    cmp     ecx, 2
    je      tdi_ghost
    cmp     ecx, 3
    je      tdi_searchpill

    ; Pre-clear rounded corner slack (GPU backdrop slice if on vault/settings, else g_br_bg)
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [rbp-80]
    call    gpu_fill_child_bg
    test    eax, eax
    jnz     tdi_bg_ok
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-80, qword ptr [g_br_bg]
tdi_bg_ok:
    call    theme_trait
    mov     ecx, eax
    and     ecx, 0FFh
    mov     dword ptr [rbp-120], ecx          ; diam
    shr     eax, 8
    and     eax, 0FFh
    mov     dword ptr [rbp-124], eax          ; accent mode (2 = two-tone)

    cmp     qword ptr [rbp-128], 0
    jne     tdi_accent

    ; Standard button (#4, #13, #15)
    mov     eax, dword ptr [g_col_btn]
    mov     edx, dword ptr [g_col_spec]
    test    dword ptr [rbp-48], ODS_SELECTED
    jz      @F
    mov     eax, dword ptr [g_col_btnsel]
    mov     edx, -1                           ; pressed: suppress top specular lip
@@: mov     dword ptr [rbp-132], eax          ; colTop
    mov     dword ptr [rbp-136], eax          ; colBot
    mov     ecx, dword ptr [g_col_border]
    mov     dword ptr [rbp-140], ecx          ; borderCol
    mov     dword ptr [rbp-144], edx          ; specCol
    mov     eax, dword ptr [g_col_text]
    mov     dword ptr [rbp-116], eax          ; textCol
    jmp     tdi_btnshape

tdi_accent:
    test    dword ptr [rbp-48], ODS_DISABLED  ; Fluent disabled accent = muted neutral
    jz      tdi_acc_on
    mov     eax, dword ptr [g_col_btn]
    mov     dword ptr [rbp-132], eax
    mov     dword ptr [rbp-136], eax
    mov     eax, dword ptr [g_col_border]
    mov     dword ptr [rbp-140], eax
    mov     dword ptr [rbp-144], -1
    mov     eax, dword ptr [g_col_textdim]
    mov     dword ptr [rbp-116], eax
    jmp     tdi_btnshape

tdi_acc_on:
    ; Primary button: BT.709 auto-contrasted g_col_onacc (#11) + AA two-tone (#15)
    mov     eax, dword ptr [g_col_accent]
    mov     edx, eax
    cmp     dword ptr [rbp-124], 2
    jne     @F
    mov     edx, dword ptr [g_col_accent2]
    or      edx, 80000000h                    ; horizontal two-tone gradient!
@@: mov     ecx, dword ptr [g_col_spec]
    test    dword ptr [rbp-48], ODS_SELECTED
    jz      tdi_acc_set
    mov     eax, dword ptr [g_col_accsel]
    mov     edx, eax
    mov     ecx, -1
tdi_acc_set:
    mov     dword ptr [rbp-132], eax
    mov     dword ptr [rbp-136], edx
    mov     eax, dword ptr [g_col_accent]
    mov     dword ptr [rbp-140], eax
    mov     dword ptr [rbp-144], ecx
    mov     eax, dword ptr [g_col_onacc]
    mov     dword ptr [rbp-116], eax

tdi_btnshape:
    WINCALL theme_aa_rrect, qword ptr [rbp-32], dword ptr [rbp-80], dword ptr [rbp-76], \
            dword ptr [rbp-72], dword ptr [rbp-68], dword ptr [rbp-120], \
            dword ptr [rbp-132], dword ptr [rbp-136], dword ptr [rbp-140], dword ptr [rbp-144]
    mov     ecx, dword ptr [rbp-116]
    test    dword ptr [rbp-48], ODS_DISABLED
    jz      tdi_tcol
    mov     ecx, dword ptr [g_col_textdim]
tdi_tcol:
    WINCALL SetTextColor, qword ptr [rbp-32], rcx
    ; Copy rcItem -> rcText [rbp-160..rbp-148] (no press shift)
    mov     eax, dword ptr [rbp-80]
    mov     dword ptr [rbp-160], eax
    mov     eax, dword ptr [rbp-76]
    mov     dword ptr [rbp-156], eax
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [rbp-152], eax
    mov     eax, dword ptr [rbp-68]
    mov     dword ptr [rbp-148], eax
    cmp     word ptr [g_txtbuf+2], 0          ; >1 char -> a word caption
    jne     tdi_dt
    movzx   eax, word ptr [g_txtbuf]
    test    eax, eax                          ; empty caption -> default
    jz      tdi_dt
    cmp     eax, 267Bh                        ; recycle ♻ -> Segoe UI Symbol
    je      tdi_symfont
    cmp     eax, 0E000h
    jb      tdi_bigfont
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_icon]
    jmp     tdi_drawglyph
tdi_symfont:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_sym]
    jmp     tdi_drawglyph
tdi_bigfont:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_big]
tdi_drawglyph:
    mov     qword ptr [rbp-112], rax           ; old font
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_txtbuf, -1, addr rbp-160, DT_CFLAGS
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-112]
    mov     eax, 1
    FRAME_EPILOG
    ret
tdi_dt:
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_txtbuf, -1, addr rbp-160, DT_CFLAGS
    mov     eax, 1
    FRAME_EPILOG
    ret
    ; ---------- ghost button (frameless glyph; AA hover halo + morphs) --------
tdi_ghost:
    mov     r10, qword ptr [rbp-24]           ; lpdis
    cmp     dword ptr [r10+4], 3000           ; CtlID: >= IDC_DYN_BASE -> a card row button
    jae     tdi_gh_card
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [rbp-80]
    call    gpu_fill_child_bg
    test    eax, eax
    jz      tdi_gh_flat
    mov     rcx, qword ptr [rbp-40]
    call    gpu_sample_child_bg
    cmp     eax, -1
    jne     @F
    mov     eax, dword ptr [g_col_bg]
@@: mov     r8d, eax
    jmp     tdi_gh_halo
tdi_gh_flat:
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-80, qword ptr [g_br_bg]
    mov     r8d, dword ptr [g_col_bg]
    jmp     tdi_gh_halo
tdi_gh_card:
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [rbp-80]
    call    gpu_fill_glass_child
    test    eax, eax
    jz      tdi_gh_card_op
    mov     rcx, qword ptr [rbp-40]
    call    gpu_sample_glass_child
    mov     r8d, eax
    jmp     tdi_gh_halo
tdi_gh_card_op:
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-80, qword ptr [g_br_panel]
    mov     r8d, dword ptr [g_col_panel]
tdi_gh_halo:
    mov     dword ptr [rbp-140], r8d           ; save bgUnder
    ; #2 Copy-to-Clipboard Checkmark Morph halo override
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [g_copy_btn_hwnd]
    jne     tdi_gh_stdhalo
    mov     ecx, r8d
    mov     edx, 005CD65Ch                     ; emerald glow
    mov     r8d, 68
    call    col_mix
    mov     dword ptr [rbp-132], eax
    jmp     tdi_gh_drawhalo
tdi_gh_stdhalo:
    xor     edx, edx
    test    dword ptr [rbp-128], 0FF00h        ; hover bit
    setnz   dl
    mov     rcx, qword ptr [rbp-40]            ; hwndItem
    call    ghost_halo_color
    cmp     eax, -1
    je      tdi_ghost_glyph
    mov     dword ptr [rbp-132], eax
tdi_gh_drawhalo:
    WINCALL theme_aa_rrect, qword ptr [rbp-32], dword ptr [rbp-80], dword ptr [rbp-76], \
            dword ptr [rbp-72], dword ptr [rbp-68], 8, \
            dword ptr [rbp-132], dword ptr [rbp-132], -1, -1
tdi_ghost_glyph:
    ; #2 Copy button checkmark morph (U+E73E CheckMark in emerald)
    mov     rax, qword ptr [rbp-40]
    cmp     rax, qword ptr [g_copy_btn_hwnd]
    jne     tdi_gh_normchar
    mov     eax, 0E73Eh
    mov     word ptr [g_txtbuf], ax
    mov     word ptr [g_txtbuf+2], 0
    mov     dword ptr [rbp-116], eax
    mov     ecx, 005CD65Ch                     ; crisp emerald on dark
    cmp     dword ptr [g_col_dark], 0
    jne     @F
    mov     ecx, 00248F24h                     ; darker emerald on light
@@: WINCALL SetTextColor, qword ptr [rbp-32], ecx
    jmp     tdi_gh_pickfont
tdi_gh_normchar:
    mov     eax, dword ptr [rbp-128]
    shr     eax, 16
    movzx   eax, ax                            ; glyph codepoint (userdata bits 16-31)
    test    eax, eax
    jnz     tdi_ghost_udchar
    movzx   eax, word ptr [g_txtbuf]
    test    eax, eax
    jz      tdi_ghost_done
    jmp     tdi_ghost_havechar
tdi_ghost_udchar:
    mov     word ptr [g_txtbuf], ax
    mov     word ptr [g_txtbuf+2], 0
tdi_ghost_havechar:
    mov     dword ptr [rbp-116], eax           ; save codepoint
    mov     ecx, dword ptr [g_col_text]
    cmp     eax, 0E735h                        ; #18 FavoriteStarFill -> warm gold!
    jne     @F
    mov     ecx, 002EB2F6h
@@: WINCALL SetTextColor, qword ptr [rbp-32], ecx
tdi_gh_pickfont:
    ; Keep ghost glyph stationary on press (no tactile jump)
    mov     eax, dword ptr [rbp-80]
    mov     dword ptr [rbp-160], eax
    mov     eax, dword ptr [rbp-76]
    mov     dword ptr [rbp-156], eax
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [rbp-152], eax
    mov     ecx, dword ptr [rbp-68]
    mov     dword ptr [rbp-148], ecx

    mov     eax, dword ptr [rbp-116]
    cmp     eax, 0E000h                        ; PUA -> Fluent icons, else Segoe UI Symbol
    jb      tdi_ghost_sym
    cmp     eax, 0E735h                        ; #18 FavoriteStarFill pop font while animating!
    jne     tdi_ghost_icnorm
    mov     ecx, ANIM_FAVPOP
    call    anim_active
    test    eax, eax
    jz      tdi_ghost_icnorm
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_icon_pop]
    jmp     tdi_ghost_draw
tdi_ghost_icnorm:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_icon]
    jmp     tdi_ghost_draw
tdi_ghost_sym:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_sym]
tdi_ghost_draw:
    mov     qword ptr [rbp-112], rax           ; old font
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_txtbuf, -1, addr rbp-160, DT_CFLAGS
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-112]
tdi_ghost_done:
    mov     eax, 1
    FRAME_EPILOG
    ret
    ; ---------- title-bar search pill (style 3) ------------------------------
tdi_searchpill:
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [rbp-80]
    call    gpu_fill_child_bg
    test    eax, eax
    jnz     @F
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-80, qword ptr [g_br_bg]
@@: WINCALL theme_aa_rrect, qword ptr [rbp-32], dword ptr [rbp-80], dword ptr [rbp-76], \
            dword ptr [rbp-72], dword ptr [rbp-68], 14, \
            dword ptr [g_col_btn], dword ptr [g_col_btn], \
            dword ptr [g_col_border], dword ptr [g_col_spec]
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_textdim]
    mov     eax, dword ptr [rbp-80]
    add     eax, 27
    mov     dword ptr [rbp-104], eax           ; L
    mov     eax, dword ptr [rbp-76]
    mov     dword ptr [rbp-100], eax           ; T
    mov     eax, dword ptr [rbp-72]
    sub     eax, 6
    mov     dword ptr [rbp-96], eax            ; R
    mov     eax, dword ptr [rbp-68]
    mov     dword ptr [rbp-92], eax            ; B
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_txtbuf, -1, addr rbp-104, 24h
    mov     word ptr [g_txtbuf], 0E721h
    mov     word ptr [g_txtbuf+2], 0
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_icon]
    mov     qword ptr [rbp-112], rax
    mov     eax, dword ptr [rbp-80]
    add     eax, 9
    mov     dword ptr [rbp-104], eax           ; L
    mov     eax, dword ptr [rbp-76]
    mov     dword ptr [rbp-100], eax           ; T
    mov     eax, dword ptr [rbp-80]
    add     eax, 26
    mov     dword ptr [rbp-96], eax            ; R
    mov     eax, dword ptr [rbp-68]
    mov     dword ptr [rbp-92], eax            ; B
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_txtbuf, -1, addr rbp-104, 24h
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-112]
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
; theme_toggle(rcx=lpdis, edx=on) -> 1 - draw an anti-aliased Fluent pill toggle
;   switch with smooth thumb slide & interpolated track color (#4, #15).
; =============================================================================
public theme_toggle
theme_toggle proc frame
    FRAME_PROLOG 256
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
    sub     eax, dword ptr [rbp-44]
    mov     dword ptr [rbp-56], eax           ; height = pill diameter

    ; Pre-clear corner slack (GPU backdrop slice if on vault/settings, else g_br_bg)
    mov     r10, qword ptr [rbp-24]
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+24]
    lea     r8, [r10+40]
    call    gpu_fill_child_bg
    test    eax, eax
    jnz     tg_bg_ok
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [g_br_bg]
tg_bg_ok:
    ; Compute slide position pos in 0..1024 (#4)
    xor     eax, eax
    cmp     dword ptr [rbp-36], 0
    je      @F
    mov     eax, 1024
@@: mov     dword ptr [rbp-80], eax           ; default pos
    mov     r10, qword ptr [rbp-24]
    mov     rax, qword ptr [r10+24]           ; hwndItem
    cmp     rax, qword ptr [g_tog_anim_hwnd]
    jne     tg_pos_done
    mov     ecx, ANIM_TOG
    call    anim_active
    test    eax, eax
    jz      tg_pos_done
    mov     ecx, ANIM_TOG
    call    anim_get
    mov     dword ptr [rbp-80], eax
tg_pos_done:
    mov     r10, qword ptr [rbp-24]
    test    dword ptr [r10+16], 4             ; ODS_DISABLED (HKLM-locked)
    jnz     tg_disabled

    mov     eax, dword ptr [rbp-80]
    shr     eax, 2                            ; w256 in 0..256
    mov     dword ptr [rbp-84], eax

    mov     ecx, dword ptr [g_col_panel]
    mov     edx, dword ptr [g_col_accent]
    mov     r8d, dword ptr [rbp-84]
    call    col_mix
    mov     dword ptr [rbp-88], eax           ; trackTop
    mov     dword ptr [rbp-92], eax           ; trackBot

    call    theme_trait
    shr     eax, 8
    and     eax, 0FFh
    cmp     eax, 2
    jne     tg_bd_mix
    mov     ecx, dword ptr [g_col_panel]
    mov     edx, dword ptr [g_col_accent2]
    mov     r8d, dword ptr [rbp-84]
    call    col_mix
    or      eax, 80000000h                    ; horizontal two-tone track!
    mov     dword ptr [rbp-92], eax

tg_bd_mix:
    mov     ecx, dword ptr [g_col_border]
    mov     edx, dword ptr [g_col_accent]
    mov     r8d, dword ptr [rbp-84]
    call    col_mix
    mov     dword ptr [rbp-96], eax           ; borderCol

    mov     ecx, dword ptr [g_col_textdim]
    mov     edx, 00FFFFFFh
    mov     r8d, dword ptr [rbp-84]
    call    col_mix
    mov     dword ptr [rbp-100], eax          ; thumbCol
    jmp     tg_draw

tg_disabled:
    mov     eax, dword ptr [g_col_textdim]
    mov     dword ptr [rbp-88], eax
    mov     dword ptr [rbp-92], eax
    mov     eax, dword ptr [g_col_border]
    mov     dword ptr [rbp-96], eax
    mov     eax, dword ptr [g_col_panel]
    mov     dword ptr [rbp-100], eax

tg_draw:
    WINCALL theme_aa_rrect, qword ptr [rbp-32], dword ptr [rbp-40], dword ptr [rbp-44], \
            dword ptr [rbp-48], dword ptr [rbp-52], dword ptr [rbp-56], \
            dword ptr [rbp-88], dword ptr [rbp-92], dword ptr [rbp-96], -1

    ; Thumb circle interpolated smoothly across travel = (R - L - 4) - thumbd
    mov     eax, dword ptr [rbp-56]
    sub     eax, 4
    cmp     eax, 4
    jge     @F
    mov     eax, 4
@@: mov     dword ptr [rbp-60], eax           ; thumbd
    mov     ecx, dword ptr [rbp-44]
    add     ecx, 2
    mov     dword ptr [rbp-64], ecx           ; y1 = T + 2
    mov     ecx, dword ptr [rbp-52]
    sub     ecx, 2
    mov     dword ptr [rbp-68], ecx           ; y2 = B - 2

    mov     eax, dword ptr [rbp-48]
    sub     eax, dword ptr [rbp-40]
    sub     eax, 4
    sub     eax, dword ptr [rbp-60]           ; travel
    jns     @F
    xor     eax, eax
@@: imul    eax, dword ptr [rbp-80]           ; travel * pos
    sar     eax, 10
    add     eax, dword ptr [rbp-40]
    add     eax, 2
    mov     dword ptr [rbp-72], eax           ; x1
    add     eax, dword ptr [rbp-60]
    mov     dword ptr [rbp-76], eax           ; x2 = x1 + thumbd

    WINCALL theme_aa_rrect, qword ptr [rbp-32], dword ptr [rbp-72], dword ptr [rbp-64], \
            dword ptr [rbp-76], dword ptr [rbp-68], dword ptr [rbp-60], \
            dword ptr [rbp-100], dword ptr [rbp-100], -1, -1
    mov     eax, 1
    FRAME_EPILOG
    ret
theme_toggle endp

; =============================================================================
; theme_toggle_labeled(rcx=lpdis, edx=on) -> 1 - draw an owner-draw button as a
;   left-aligned caption plus a small Fluent pill toggle (20x8 DLU) on the right.
; =============================================================================
public theme_toggle_labeled
theme_toggle_labeled proc frame
    FRAME_PROLOG 192
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
    ; Pre-clear full labeled toggle surface so bErase=0 animations keep ClearType crisp
    mov     r10, qword ptr [rbp-24]
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+24]
    lea     r8, [r10+40]
    call    gpu_fill_child_bg
    test    eax, eax
    jnz     @F
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [g_br_bg]
@@:
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
; theme_progressbar(rcx=lpdis, edx=num, r8d=denom) -> 1 - draw an anti-aliased
;   TOTP countdown bar: smooth rounded pill bar centred vertically,
;   interpolating color accent -> amber (<25%) -> coral (<10%).
; =============================================================================
public theme_progressbar
theme_progressbar proc frame
    FRAME_PROLOG 256
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-36], edx           ; num
    mov     dword ptr [rbp-40], r8d           ; denom
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

    ; Clear 40% glass card panel background so bErase=0 ticks leave zero artifacts
    mov     r10, qword ptr [rbp-24]
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+24]
    lea     r8, [rbp-56]
    call    gpu_fill_glass_child
    test    eax, eax
    jnz     @F
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-56, qword ptr [g_br_panel]
@@:

    cmp     dword ptr [rbp-40], 0
    jle     tpb_done
    mov     eax, dword ptr [rbp-36]
    test    eax, eax
    jns     @F
    xor     eax, eax
@@: cmp     eax, dword ptr [rbp-40]
    jle     @F
    mov     eax, dword ptr [rbp-40]
@@: shl     eax, 10
    xor     edx, edx
    div     dword ptr [rbp-40]
    mov     dword ptr [rbp-64], eax           ; frac1024 in 0..1024

    ; Urgency color interpolation: >240 -> accent; 102..240 -> accent..amber; <102 -> amber..coral
    mov     ecx, dword ptr [g_col_accent]
    cmp     eax, 240
    jae     tpb_col_done
    cmp     eax, 102
    jb      tpb_coral
    ; w256 = (240 - frac) * 256 / 138
    mov     r8d, 240
    sub     r8d, eax
    shl     r8d, 8
    mov     eax, r8d
    xor     edx, edx
    mov     r9d, 138
    div     r9d
    mov     r8d, eax
    mov     ecx, dword ptr [g_col_accent]
    mov     edx, 002EB2F6h                    ; amber
    call    col_mix
    mov     ecx, eax
    jmp     tpb_col_done
tpb_coral:
    ; w256 = (102 - frac) * 256 / 102
    mov     r8d, 102
    sub     r8d, eax
    shl     r8d, 8
    mov     eax, r8d
    xor     edx, edx
    mov     r9d, 102
    div     r9d
    mov     r8d, eax
    mov     ecx, 002EB2F6h                    ; amber
    mov     edx, 003B3BEFh                    ; coral red
    call    col_mix
    mov     ecx, eax
tpb_col_done:
    mov     dword ptr [rbp-68], ecx           ; activeCol

    mov     eax, dword ptr [rbp-44]
    sub     eax, dword ptr [rbp-52]           ; h = B - T
    mov     ecx, dword ptr [rbp-56]           ; barL = L (full width, bar only)
    cmp     eax, 6
    jl      tpb_bar_full
    sar     eax, 1
    add     eax, dword ptr [rbp-52]
    sub     eax, 2
    mov     dword ptr [rbp-76], eax           ; barT = midY - 2 (4px centred pill)
    add     eax, 4
    mov     dword ptr [rbp-80], eax           ; barB = midY + 2
    jmp     tpb_draw_bar

tpb_bar_full:
    mov     eax, dword ptr [rbp-52]
    mov     dword ptr [rbp-76], eax
    mov     eax, dword ptr [rbp-44]
    mov     dword ptr [rbp-80], eax

tpb_draw_bar:
    mov     dword ptr [rbp-84], ecx           ; barL
    mov     edx, dword ptr [rbp-48]
    sub     edx, ecx                          ; barW = R - barL
    cmp     edx, 6
    jl      tpb_done
    mov     dword ptr [rbp-88], edx
    WINCALL theme_aa_rrect, qword ptr [rbp-32], dword ptr [rbp-84], dword ptr [rbp-76], \
            dword ptr [rbp-48], dword ptr [rbp-80], 4, \
            dword ptr [g_col_frame], dword ptr [g_col_frame], -1, -1
    mov     eax, dword ptr [rbp-88]
    imul    eax, dword ptr [rbp-64]
    sar     eax, 10                           ; fillW = barW * frac1024 / 1024
    cmp     eax, 2
    jl      tpb_done
    add     eax, dword ptr [rbp-84]
    mov     dword ptr [rbp-92], eax
    WINCALL theme_aa_rrect, qword ptr [rbp-32], dword ptr [rbp-84], dword ptr [rbp-76], \
            dword ptr [rbp-92], dword ptr [rbp-80], 4, \
            dword ptr [rbp-68], dword ptr [rbp-68], -1, -1
tpb_done:
    mov     eax, 1
    FRAME_EPILOG
    ret
theme_progressbar endp

end
