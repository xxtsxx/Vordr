; =============================================================================
; gui.asm - hybrid entry point (wstart) + the Win32 vault GUI.
; -----------------------------------------------------------------------------
; The single vordr.exe is linked /subsystem:windows with entry point `wstart`.
; wstart runs the CLI diagnostics when argv[1] is a known verb; otherwise it
; opens the GUI - the only place the vault and secrets are ever handled, so a
; master password or secret never appears on the command line.
;
; The GUI uses twelve dialog-resource templates (vordr.rc): unlock, create,
; vault, message, about, password readout, icon picker, generator, history,
; select/export, export-password and import-password.  The vault is unlocked
; ONCE (key in g_vkey, body in locked memory); the dialogs read entries and
; mutate the in-memory body, then re-seal to disk via the vault session API
; (vault_unlock/reseal/add/remove/...).
;
; Dialog procs are RAW frames (no FRAME_PROLOG): they are OS callbacks, so the
; software shadow stack must not be touched across them.  The helper procs they
; call are ordinary FRAME_PROLOG procedures.
; =============================================================================

include macros.inc
include glyphs.inc

; ---- startup helpers ---------------------------------------------------------
extern cpu_gate:proc
extern SetWindowSubclass:proc
extern DefSubclassProc:proc
extern TrackMouseEvent:proc
extern hardening_init:proc
extern crash_install:proc               ; hardening.asm: arm crash containment
externdef g_gui_active:dword            ; hardening.asm: gate the crash apology box
extern con_init:proc
extern con_attach_parent:proc
extern iat_lockdown:proc
extern parse_cmdline:proc
extern is_cli_command:proc
extern dispatch:proc
extern run_selftest:proc
extern secure_zero:proc
extern secmem_panic_wipe:proc           ; wipe every pinned secret (shutdown/logoff)
extern print_err:proc

; ---- vault session API (vault.asm) + password helper (main.asm) -------------
extern password_to_utf8:proc
extern do_init:proc
extern vault_unlock:proc
extern vault_lock:proc
extern vault_reload:proc                ; C8: refresh from disk (reload-safe conflict)
externdef g_seclock_failed:dword        ; C3: a secret buffer stayed pageable
externdef g_lockerr_vl:dword            ; C3 diag: first VirtualLock Win32 error
externdef g_lockerr_wss:dword           ; C3 diag: SetProcessWorkingSetSize error
extern log_result:proc                  ; C5: audit-log a GUI security event
externdef g_cfg_loglevel:dword          ; C5: audit-log verbosity (from HKCU at GUI start)
extern vault_reseal:proc
extern vault_open_foreign:proc          ; .vordr import: decrypt another vault while this
                                        ;   one stays open (parks/restores every global)
extern fed_merge:proc                   ;   and merge its entries in
extern zi_stage_vault:proc              ;   titles -> the shared selection checklist
extern vault_free_foreign:proc          ;   release the source body (size lives in vault.asm)
externdef g_merge_sel:dword             ;   1 = fed_merge honours g_sel
externdef g_zi_hide:byte                ;   staged rows the checklist must not show
extern vault_export_sel:proc            ; .vordr export: selected entries -> a child file,
                                        ;   master vault left open and untouched
extern vault_ext_changed:proc           ; vault.asm: on-disk file changed since load?
extern vault_remove_at:proc
extern vault_count:proc
extern vault_is_system:proc             ; system items are hidden from every user-facing list
extern vault_last_user:proc             ;   (docs/SYSITEM_DESIGN.md)
extern vault_add_system_item:proc
externdef g_io_err:dword                 ; Win32 reason behind an EXIT_IO
extern vault_preload:proc                ; read the vault image BEFORE the unlock
extern vault_preload_end:proc            ;   dialog, so no file I/O runs on the       ; new vaults get one at creation; old ones lazily
extern vault_is_deleted:proc            ; trashed records are never exported
extern vault_pw_due:proc                ; C9: is the master-password reminder due?
extern vault_pw_check:proc              ;   and does this password open this vault?
extern vault_pwverify_set:proc          ;   stamp it once confirmed
extern vault_health:proc                ; E6: {weak,reused,old,total} analysis
extern vault_title_at:proc
extern vault_field_at:proc
extern vh_pw_weak:proc                  ; E6: weak-password predicate (rcx=bytes,edx=len)
extern vault_entry_stale:proc           ; E6/R6: stale-entry predicate (rcx=index)
extern vault_entry_ptr:proc
extern g_carry_created:qword
extern pwgen_ex:proc
externdef g_pwgen_outcap:dword          ; E16: one-shot pwgen output capacity
extern g_col_bg:dword
extern g_col_panel:dword
extern g_col_frame:dword
extern g_col_text:dword
extern g_col_textdim:dword
extern g_col_accent:dword
extern g_col_dark:dword
extern g_col_side:dword
extern g_col_filebadge:dword
extern DwmSetWindowAttribute:proc
extern g_scheme:dword
extern theme_set_scheme:proc
extern theme_scrollbars:proc
extern theme_dwm_apply:proc
extern cfg_set_dword_hkcu:proc
extern cfg_get_dword:proc
extern vault_field_count:proc
extern vault_field_get:proc
extern vault_build_entry:proc
extern attach_stage:proc
extern attach_open:proc
extern mem_alloc:proc
extern mem_free:proc
extern read_file:proc
extern write_file:proc
extern ze_compose:proc                  ; encrypted-ZIP export composer (zipexport.asm)
extern zi_stage:proc                    ; encrypted-ZIP import: stage titles (zipimport.asm)
extern zi_commit:proc                   ; import the g_sel-selected staged entries
extern zi_abort:proc                    ; discard a staged import
externdef g_zi_titles:qword             ; staged entry titles (wide ptr array)
externdef g_zi_tlens:dword              ; staged entry title lengths (wchars)
externdef g_zi_stg_n:dword              ; staged entry count
externdef g_zi_trunc:dword              ; >0 = the source had more than the list can hold
externdef g_kat_n:dword                 ; known-answer tests run by the launch gate
extern ze_free:proc
externdef g_zbuf:qword
extern ShellExecuteW:proc
extern DragAcceptFiles:proc
extern DragQueryFileW:proc
extern DragFinish:proc
extern GetTempPathW:proc
extern GetClientRect:proc
extern DeleteFileW:proc
extern DeleteObject:proc
externdef g_field_list:qword
externdef g_field_n:dword
extern totp_from_b32:proc
extern totp_secs_left:proc
extern vault_tpm_remember:proc
extern vault_tpm_forget:proc
extern vault_tpm_has:proc
extern tpm_available:proc
extern reg_load_vault:proc
extern reg_save_vault:proc
extern cfg_default_vault:proc
extern cfg_classify_path:proc
extern g_font_icon:qword
extern cfg_get_dword:proc
extern cfg_set_dword_hkcu:proc
extern check_password_policy:proc

externdef g_use_tpm:dword
externdef g_cfg_pwminlen:dword
externdef g_cfg_pwminclasses:dword
externdef g_uline_ctl:dword             ; theme focus-underline colour overrides
externdef g_uline_br:qword
externdef g_uline_ctl2:dword
externdef g_uline_br2:qword
externdef g_cfg_in:qword
externdef g_rollback:dword              ; vault.asm: 1 if the unlocked file is a rollback
externdef g_cfg_pass:byte
externdef g_cfg_passlen:dword
externdef g_cfg_title:qword
externdef g_cfg_user:qword
externdef g_cfg_secret:qword
externdef g_cfg_url:qword
externdef g_cfg_notes:qword
externdef g_cfg_totp:qword

; ---- Win32 -------------------------------------------------------------------
extern GetModuleHandleW:proc
extern ExitProcess:proc
extern CreateMutexW:proc
extern GetLastError:proc
extern FindWindowW:proc
extern MessageBoxW:proc
extern DialogBoxParamW:proc
extern CreateDialogParamW:proc          ; the settings child dialog
; secure-desktop (anti-keylogger) master-password entry
extern CreateDesktopW:proc
extern OpenInputDesktop:proc
extern OpenDesktopW:proc                ; last-resort restore: switch to "Default" by name
extern Sleep:proc
extern SwitchDesktop:proc
extern SetThreadDesktop:proc
extern CloseDesktop:proc
extern CreateThread:proc
extern GetCurrentThreadId:proc
extern WaitForSingleObject:proc
extern CloseHandle:proc
extern EndDialog:proc
extern GetDlgItemTextW:proc
extern SetDlgItemTextW:proc
extern SendDlgItemMessageW:proc
extern GetOpenFileNameW:proc
extern GetSaveFileNameW:proc
extern OpenClipboard:proc
extern EmptyClipboard:proc
extern SetClipboardData:proc
extern CloseClipboard:proc
extern GlobalAlloc:proc
extern RegisterClipboardFormatW:proc
extern GlobalLock:proc
extern GlobalUnlock:proc
extern GetClipboardSequenceNumber:proc
extern SetTimer:proc
extern KillTimer:proc
extern GetLastInputInfo:proc              ; auto-lock: system-wide idle time
extern GetTickCount:proc
extern GetActiveWindow:proc
extern WTSRegisterSessionNotification:proc   ; wtsapi32: Win+L lock events
extern WTSUnRegisterSessionNotification:proc
extern MultiByteToWideChar:proc
extern WideCharToMultiByte:proc
extern EnableWindow:proc
extern GetDlgItem:proc
extern GetFocus:proc
extern CharUpperBuffW:proc
extern SetFocus:proc
extern GetParent:proc
extern SetDlgItemInt:proc
extern GetDlgItemInt:proc
extern GetFileAttributesW:proc
extern GetModuleFileNameW:proc           ; to know where WE live (see gui_path_under)
extern SetFileAttributesW:proc
extern CreateFileW:proc                   ; secure temp-file wipe
extern WriteFile:proc
extern FlushFileBuffers:proc
extern CreateDirectoryW:proc
extern ShowWindow:proc
extern IsZoomed:proc
extern EnumChildWindows:proc
extern MonitorFromWindow:proc
extern GetMonitorInfoW:proc
extern MoveWindow:proc
extern GetWindowRect:proc
extern MapWindowPoints:proc
extern ScreenToClient:proc
extern SetWindowPos:proc
extern DrawTextW:proc
extern FrameRect:proc
extern MapDialogRect:proc
extern SendMessageW:proc
extern PostMessageW:proc
extern SetWindowTextW:proc
extern GetDlgCtrlID:proc
extern GetKeyState:proc
extern SetWindowLongPtrW:proc
extern GetWindowLongPtrW:proc
extern CallWindowProcW:proc
extern LoadCursorW:proc
extern SetCursor:proc
extern HideCaret:proc
extern SetTextColor:proc
extern SetBkMode:proc
extern TextOutW:proc
extern GetTextExtentPoint32W:proc
extern SetBkColor:proc
extern GetSysColorBrush:proc
extern GetStockObject:proc
extern RoundRect:proc
extern SelectObject:proc
extern CreateFontW:proc
extern GetSysColor:proc
extern CreateSolidBrush:proc
extern FillRect:proc
extern InvalidateRect:proc
extern FileTimeToSystemTime:proc
extern GetSystemTimeAsFileTime:proc
extern RedrawWindow:proc
extern InitCommonControlsEx:proc
extern pw_metrics:proc
extern theme_boot:proc
extern theme_attach:proc
extern theme_paint:proc
extern theme_erase:proc
extern theme_ctlcolor:proc
extern theme_drawitem:proc
extern theme_toggle:proc
extern theme_toggle_labeled:proc
extern theme_progressbar:proc
extern g_font_totp:qword
; --- system-tray / message-loop imports ---------------------------------------
extern Shell_NotifyIconW:proc
extern RegisterClassW:proc
extern CreateWindowExW:proc
extern DestroyWindow:proc
extern DefWindowProcW:proc
extern GetMessageW:proc
extern TranslateMessage:proc
extern DispatchMessageW:proc
extern PostQuitMessage:proc
extern LoadIconW:proc
extern LoadImageW:proc
extern CreatePopupMenu:proc
extern AppendMenuW:proc
extern TrackPopupMenu:proc
extern DestroyMenu:proc
extern SetMenuInfo:proc
extern GetCursorPos:proc
extern SetForegroundWindow:proc
extern RegisterHotKey:proc
extern UnregisterHotKey:proc
extern VkKeyScanW:proc
extern GetKeyNameTextW:proc
extern MapVirtualKeyW:proc

; ---- constants ---------------------------------------------------------------
MB_OK               equ 0
MB_ICONERROR        equ 10h
MB_ICONINFORMATION  equ 40h
MB_ICONWARNING      equ 30h
MB_YESNO            equ 4
MB_ICONQUESTION     equ 20h
MB_OKCANCEL         equ 1
MB_DEFBUTTON2       equ 100h
IDYES               equ 6
IDNO                equ 7
IDOK                equ 1
IDCANCEL            equ 2

WM_CLOSE            equ 10h
WM_TIMER            equ 113h
WM_INITDIALOG       equ 110h
WM_SETFONT          equ 30h
WM_MOUSEWHEEL       equ 20Ah
WM_MOUSEMOVE_       equ 200h
WM_MOUSELEAVE_      equ 2A3h
WM_CHAR_            equ 102h
WM_KEYDOWN_         equ 100h
VK_CONTROL_         equ 11h
WM_SIZE_            equ 5
WM_GETMINMAXINFO_   equ 24h
; resize-anchor flags (gui_reflow)
ANCH_STRETCHW       equ 1
ANCH_STRETCHH       equ 2
ANCH_RIGHT          equ 4
ANCH_BOTTOM         equ 8
WM_COMMAND          equ 111h
; ghost buttons (frameless glyph controls: theme_drawitem tdi_ghost path)
GHOST_STYLE_        equ 2               ; GWL_USERDATA style byte
TME_LEAVE_          equ 2
CW_USEDEFAULT_      equ 80000000h
TTS_ALWAYSTIP_      equ 1
TTS_NOPREFIX_       equ 2
TTF_IDISHWND_       equ 1
TTF_SUBCLASS_       equ 10h
TTM_ADDTOOLW_       equ 432h            ; WM_USER+50
TTM_DELTOOLW_       equ 433h            ; WM_USER+51
TTM_SETMAXTIPW_     equ 418h            ; WM_USER+24
WM_PAINT            equ 0Fh
WM_SETCURSOR        equ 20h
WM_ERASEBKGND       equ 14h
WM_DRAWITEM         equ 2Bh
GWLP_WNDPROC        equ -4
IDC_HAND            equ 32649
HTCLIENT            equ 1
; --- custom title-bar frame (redesign A1/A2/A3) -------------------------------
WM_NCHITTEST_       equ 84h
HTCAPTION           equ 2
DWLP_MSGRESULT_     equ 0
SWP_FRAME_          equ 16h              ; SWP_NOMOVE|SWP_NOZORDER|SWP_NOACTIVATE
SWP_NOSIZE_         equ 1h
SWP_NOMOVE_         equ 2h
SWP_NOACTIVATE_     equ 10h
TBAR_H              equ 32               ; custom title-bar strip height (px)
CAPBTN_W            equ 44               ; caption (close) button width
IDC_T_CLOSE         equ 292             ; caption: close
IDC_T_NEW           equ 293             ; dock: new item
IDC_T_GEN           equ 294             ; dock: password generator
IDC_T_SET           equ 295             ; dock: settings
MARGBTN_W           equ 34              ; left-margin glyph button (square: New / Generate /
MARGBTN_GAP         equ 4               ;   Settings live beside the sidebar, not in the strip)
; sidebar card geometry (sidebar_rect / sidebar_layout): the frame + entry list
; scale with the window height at an equal top/bottom gap.  L/R and the gap are
; DLU (DPI-aware); the list is inset inside the frame so it never paints over it.
SIDE_L_DLU          equ 27              ; frame left (DLU)
SIDE_R_DLU          equ 205             ; frame right (DLU)
SIDE_GAP_DLU        equ 5               ; frame gap from strip-bottom / window-bottom (DLU)
SIDE_BORD_X         equ 1               ; list inset L/R inside the frame (px) - selection meets
                                        ;   the border's inner edge (frame stroke is 1px)
SIDE_BORD_Y         equ 5               ; list inset T/B inside the frame (px) - list ends above it
SIDE_SRCH_H         equ 20              ; search box height at the top of the frame (px)
SIDE_SRCH_GAP       equ 6               ; gap between the search box and the list (px)
LINK_BLUE           equ 00E08C3Ch        ; COLORREF (RGB 60,140,224) hyperlink blue
WM_MEASUREITEM      equ 2Ch
WM_COMPAREITEM      equ 39h
WM_CTLCOLOREDIT     equ 133h
WM_CTLCOLORLISTBOX  equ 134h
WM_CTLCOLORBTN      equ 135h
WM_CTLCOLORDLG      equ 136h
WM_CTLCOLORSTATIC   equ 138h
EM_SETCUEBANNER     equ 1501h
; ---- system tray / window-loop -----------------------------------------------
WM_DESTROY          equ 2
WM_ENDSESSION       equ 16h                ; the session is really ending (wParam != 0)
WM_LBUTTONUP        equ 0202h
WM_LBUTTONDBLCLK    equ 0203h
WM_RBUTTONUP        equ 0205h
WM_TRAYICON         equ 8001h            ; WM_APP+1, our tray callback message
NIM_ADD             equ 0
NIM_DELETE          equ 2
NIF_TRAY            equ 7                 ; NIF_MESSAGE | NIF_ICON | NIF_TIP
MF_SEPARATOR        equ 800h
MF_OWNERDRAW        equ 100h
MIM_DARK            equ 80000002h        ; MIM_APPLYTOSUBMENUS | MIM_BACKGROUND
TPM_RIGHTBUTTON     equ 2
TPM_LEFTALIGN       equ 0
TPM_RETURNCMD       equ 0100h
WS_EX_TOOLWINDOW    equ 80h
; ---- global hotkey (Alt + |) - summons the vault from the tray ---------------
WM_HOTKEY           equ 0312h
MOD_ALT             equ 1
MOD_CONTROL         equ 2
MOD_SHIFT           equ 4
MOD_WIN             equ 8
MOD_NOREPEAT        equ 4000h            ; auto-repeat off (Win7+); dropped on failure
HOTKEY_SHOW         equ 1                 ; our hotkey id on the tray-owner window
VK_OEM_5            equ 0DCh              ; the \| key - fallback when '|' isn't mappable
DLG_HOTKEY          equ 790               ; "capture a new summon hotkey" dialog
IDC_HK_CAP          equ 791               ; the capture surface (focused, eats keystrokes)
IDC_HK_HINT         equ 792
IDC_HK_CLEAR        equ 793               ; restore the built-in Alt + | default
IDC_V_MHOTKL        equ 275               ; settings: "Summon hotkey" label
IDC_V_MHOTK         equ 276               ; settings: current combo (click = recapture)
DLGC_WANTALLKEYS    equ 4                 ; WM_GETDLGCODE: give us Tab/Enter/Esc too
MAPVK_VK_TO_VSC     equ 0
WM_GETDLGCODE_      equ 87h
WM_SYSKEYDOWN_      equ 104h              ; Alt+key arrives here, NOT as WM_KEYDOWN
VK_TAB_             equ 9
VK_RETURN_          equ 13
VK_ESCAPE_          equ 27
VK_SHIFT_           equ 10h
VK_CONTROL_         equ 11h
VK_MENU_            equ 12h
VK_LWIN_            equ 5Bh
VK_RWIN_            equ 5Ch
WS_POPUP            equ 80000000h
IDM_ABOUT           equ 1001
IDM_OPEN            equ 1002
IDM_EXIT            equ 1003
; password-strength / match line colours (COLORREF 0x00BBGGRR)
CLR_BAR_RED         equ 004545D6h         ; bad / no password / mismatch
CLR_BAR_AMBER       equ 003CA5E1h         ; weak (meets the policy, minimal) 
CLR_BAR_LGREEN      equ 00169C84h         ; adequate
CLR_BAR_DGREEN      equ 0055AF2Dh         ; strong / match
EN_CHANGE           equ 300h
EN_SETFOCUS         equ 100h
EN_KILLFOCUS        equ 200h
CLIP_TIMER          equ 1                  ; timer id for clipboard auto-clear
TOTP_TIMER          equ 2                  ; timer id for live auth-code refresh
TOTP_MS             equ 1000               ; recompute the code once a second
SEARCH_TIMER        equ 3                  ; timer id for debounced search-as-you-type
SEARCH_MS           equ 300                ; refilter only after 0.3 s of no keystrokes
IDLE_TIMER          equ 4                  ; timer id for the auto-lock idle poll
IDLE_POLL_MS        equ 30000              ; check system idle time every 30 s
WM_WTSSESSION_CHANGE equ 02B1h             ; session notification (Win+L etc.)
WM_DROPFILES         equ 0233h             ; Explorer file drop (drag-and-drop attach)
WTS_SESSION_LOCK    equ 7                  ; wparam: the workstation locked
SEARCH_DEBOUNCE_MIN equ 200               ; ...but only when the list exceeds this many entries
SCORE_CAP           equ 8192              ; entries beyond this index score 0 (ranking cap)
FZ_WORDSTART        equ 16                ; fuzzy bonus: char matched at a word start
FZ_CONTIG           equ 8                 ; fuzzy bonus: char contiguous with the previous match
FZ_BASE             equ 1                 ; fuzzy score per matched char
LBN_SELCHANGE       equ 1
LB_ADDSTRING        equ 180h
LB_RESETCONTENT     equ 184h
LB_INITSTORAGE      equ 1A8h            ; pre-allocate item storage for large lists
LB_SETCURSEL        equ 186h
LB_GETCURSEL        equ 188h
LB_GETCOUNT         equ 18Bh
LB_GETCURSEL        equ 188h
LB_GETITEMRECT      equ 198h            ; item bounding rect (recycle-glyph hit-test)
GWL_USERDATA        equ -21             ; button accent tag (theme_drawitem primary)
GWL_STYLE_          equ -16
LB_GETCOUNT         equ 18Bh
LB_GETITEMDATA      equ 199h
LB_ERR              equ -1
EM_SETSEL           equ 0B1h
EM_SETREADONLY      equ 0CFh

CP_UTF8_            equ 65001
CF_UNICODETEXT      equ 13
GMEM_MOVEABLE       equ 2
GMEM_ZEROINIT       equ 40h

; dialog + control IDs (MUST match vordr.rc)
DLG_UNLOCK   equ 100
IDC_U_PATH   equ 101
IDC_U_OPEN   equ 102
IDC_U_NEW    equ 103
IDC_U_PW     equ 104
IDC_U_UNLOCK equ 105
IDC_U_STATUS equ 106
IDC_U_TPM    equ 107
IDC_U_REMEMBER equ 108
IDC_U_RONLY  equ 109                  ; E9: "Open read-only" - a Fluent pill toggle (R7.3)
IDC_U_RONLYL equ 110                  ; its label
DLG_VAULT    equ 200
IDC_V_LIST   equ 201
IDC_V_TITLE  equ 202
IDC_V_USER   equ 203
IDC_V_SECRET equ 204
IDC_V_URL    equ 205
IDC_V_NOTES  equ 206
IDC_V_REVEAL equ 207
IDC_V_COPY   equ 208
IDC_V_ADD    equ 209
IDC_V_EDIT   equ 210
IDC_V_REMOVE equ 211
IDC_V_LOCK   equ 212
IDC_V_TOTP   equ 213
IDC_V_COPYTOTP equ 214
IDC_V_TOTPBAR equ 215
IDC_V_TOTP_WINDOW equ 30                   ; TOTP step (seconds) - progress denom
IDC_V_TKEY   equ 227
IDC_V_TKEYREVEAL equ 229
EM_SETPASSWORDCHAR equ 0CCh
SECRET_MASK  equ 2022h                ; bullet mask char for the secret field
IDC_V_MTITLE equ 218
IDC_V_MPOLL  equ 219
IDC_V_MLENL  equ 220
IDC_V_MLEN   equ 221
IDC_V_MCLSL  equ 222
IDC_V_MCLS   equ 223
IDC_V_MTPM   equ 224
IDC_V_MTPMINFO equ 226
IDC_V_MTPML  equ 228                  ; "TPM Unlock" label beside the toggle
IDC_V_MNOHISTL equ 250                ; "Do not save history" label
IDC_V_MNOHIST  equ 251                ; "Do not save history" toggle
IDC_V_MNOPHONL equ 252                ; "Disable phonetic reader" label
IDC_V_MNOPHON  equ 253                ; "Disable phonetic reader" toggle
IDC_V_MSECDL   equ 254                ; "Secure password entry" label
IDC_V_MSECD    equ 255                ; "Secure password entry" toggle
IDC_V_MSECINFO equ 256               ; "Secure password entry" info screen
IDC_V_MCLIPL equ 257                  ; "Clipboard clear (seconds)" label
IDC_V_MCLIP  equ 258                  ; clipboard timeout edit
IDC_V_MIDLEL equ 259                  ; "Auto-lock idle (minutes)" label
IDC_V_MIDLE  equ 260                  ; idle-minutes edit
IDC_V_MWLKL  equ 261                  ; "Lock with Windows" label
IDC_V_MWLK   equ 262                  ; lock-with-Windows toggle
IDC_V_MNOPREVL   equ 263              ; "Disable attachment preview" label
IDC_V_MTOUTS equ 266                  ; "Timeouts" section heading
IDC_V_MPWDL  equ 277                  ; C9: "Password reminder (days)" label
IDC_V_MPWD   equ 278                  ; C9: reminder interval edit
IDC_RM_TEXT  equ 279                  ; C9 reminder dialog: explanatory text
IDC_RM_PW    equ 280                  ;   and the password field
IDC_V_MNOPREV    equ 264              ; disable-attachment-preview toggle
IDC_V_MNOPREVINFO equ 265            ; "Disable attachment preview" info (i)
IDC_V_MTHEME equ 240                  ; color-scheme cycle button (settings)
IDC_V_MTHEMEL equ 241                 ; "Color scheme" label
IDC_V_COLORPW equ 244                 ; overlay: colored revealed secret (owner-draw)
IDC_V_MEXPORT equ 245                 ; "Export secrets..." button (.vaultz archive)
IDC_V_MIMPORT equ 246                 ; "Import..." button (Vordr .vaultz archives)
IDC_V_MEXPZIP equ 247                 ; "Export to encrypted ZIP" button (settings)
DLG_ICON      equ 740                 ; icon picker (glyph grid + colour swatches)
IDC_I_PREV    equ 850                 ; icon picker: live preview tile
; RESERVED RANGES - not scalars.  A control id placed inside one of these is invisible
; to idcheck's duplicate check (which compares scalars and skips *_BASE), and icon_proc
; dispatches on them by range.  idcheck now flags any id that lands inside one.
IDC_IG_BASE   equ 800                 ; icon picker: glyph buttons  (GLYPHPAL_N = 30)
IDC_IC_BASE   equ 830                 ; icon picker: colour swatches (GLYPHCOL_N = 12)
DLG_PWGEN     equ 760                 ; password-generator window
IDC_PG_OUT    equ 761
IDC_PG_REGEN  equ 762
IDC_PG_BITS   equ 763
IDC_PG_LENL   equ 764
IDC_PG_LEN    equ 765
IDC_PG_LENVAL equ 766
IDC_PG_STYLE  equ 767
IDC_PG_UP     equ 768
IDC_PG_LO     equ 769
IDC_PG_DI     equ 770
IDC_PG_SY     equ 771
PWCLASS_U     equ 1
PWCLASS_L     equ 2
PWCLASS_D     equ 4
PWCLASS_S     equ 8
TBM_GETPOS    equ 400h
TBM_SETPOS    equ 405h
TBM_SETRANGE  equ 406h
WM_HSCROLL_   equ 114h
DLG_XLPW     equ 720                  ; export-password prompt dialog
IDC_XP_PW    equ 721
IDC_XP_PW2   equ 722
IDC_XP_WARN  equ 723
IDC_XP_PWL   equ 724
IDC_XP_PW2L  equ 725
DLG_IMPPW    equ 730                  ; import-password prompt (single field)
DLG_PWREMIND equ 795                  ; C9 master-password reminder
DLG_SETTINGS equ 796                  ; settings screen: a WS_CHILD dialog over the
                                      ;   vault client area (docs/SETTINGS_DESIGN.md)
DLG_SELECT   equ 750                  ; export/import entry-selection checklist
IDC_SEL_SEARCH equ 751
IDC_SEL_LIST equ 752                  ; SysListView32 checkbox list of entries
IDC_SEL_ALL  equ 753
IDC_SEL_NONE equ 754
MAX_SEL      equ 8192                 ; entries the selection screen can list
; SysListView32 checkbox-list messages / flags
LVM_FIRST                    equ 1000h
LVM_DELETEALLITEMS           equ LVM_FIRST + 9
LVM_INSERTITEMW              equ LVM_FIRST + 77
LVM_SETITEMSTATE             equ LVM_FIRST + 43
LVM_GETITEMW                 equ LVM_FIRST + 75
LVM_GETITEMCOUNT             equ LVM_FIRST + 4
LVM_INSERTCOLUMNW            equ LVM_FIRST + 97
LVM_SETCOLUMNWIDTH           equ LVM_FIRST + 30
LVM_SETBKCOLOR               equ LVM_FIRST + 1
LVM_SETTEXTCOLOR             equ LVM_FIRST + 36
LVM_SETTEXTBKCOLOR           equ LVM_FIRST + 38
LVM_SETEXTENDEDLISTVIEWSTYLE equ LVM_FIRST + 54
LVS_EX_CHECKBOXES            equ 4
LVS_EX_FULLROWSELECT         equ 20h
LVIF_TEXT                    equ 1
LVIF_STATE                   equ 8
LVIF_PARAM                   equ 4
LVIS_STATEIMAGEMASK          equ 0F000h
LVCF_WIDTH                   equ 2
SW_HIDE      equ 0
SW_SHOW      equ 5
DLG_CREATE   equ 400
IDC_C_PW     equ 402
IDC_C_PW2    equ 403
IDC_C_INFO   equ 406                  ; (i) password-requirements callout
IDC_C_LOGO   equ 407                  ; large Vordr icon (welcome screen)
IDC_C_WELCOME equ 408                 ; welcome text
DLG_MSG      equ 600                  ; Fluent message box (replaces MessageBoxW)
IDC_M_TEXT   equ 601
IDC_M_OK     equ 602
IDC_M_NO     equ 603
MB_TYPEMASK  equ 0Fh
DLG_ABOUT    equ 610                  ; About box with the app logo
IDC_A_ICON   equ 611
IDC_A_TEXT   equ 612
IDC_A_OK     equ 613
STM_SETICON  equ 0170h
DLG_PWREAD   equ 700                  ; "read password" popup (class colors + phonetic)
IDC_PR_COLOR equ 701
IDC_PR_LEGEND equ 702
IDC_PR_PHON  equ 703
DT_IMGFLAGS  equ 25h                  ; DT_CENTER|DT_VCENTER|DT_SINGLELINE

OFN_OVERWRITEPROMPT equ 2
OFN_HIDEREADONLY    equ 4
OFN_PATHMUSTEXIST   equ 800h
OFN_FILEMUSTEXIST   equ 1000h
OFN_EXPLORER        equ 80000h

EBUF        equ 4096            ; wide chars per entry-field buffer
EM_LIMITTEXT equ 0C5h           ; hard-stop typing/pasting at CONVW_MAX-1 (macros.inc)

; --- modular field rows (runtime-built detail form) ------------------------
; Per-row descriptor (flat record, stride DESCSZ) in g_fields[].
FD_KIND     equ 0               ; dd  base kind (VF_TEXT/USERNAME/SECRET/URL/NOTES/TOTP)
FD_FLAGS    equ 4               ; dd  bit0 = custom label; bits4-5 = pw-strength grade
FD_Y        equ 8              ; dd  row top in DLU (within the detail pane)
FD_H        equ 12             ; dd  row height in DLU
FD_HANDLES  equ 16             ; q[DYN_SLOTS]  control hwnd per slot (0 = absent)
DESCSZ      equ 480            ; 16 + 16 handles*8 + 328 arf blob + 8 reserved (16-aligned)
; The attachments tile aggregates every VF_FILE/VF_IMAGE field of the open entry
; into one row backed by g_tilefiles (see the tf_* helpers).  Each file entry is
; {AttachRef[68], filename wide (NUL-terminated, <=129 wchars)}.
MAX_TFILES  equ 24             ; <= MAX_FIELDS minus the other fields of an entry
; secure temp-file tracking: every attachment decrypted to %TEMP% is
; recorded here and, on vault lock/exit, overwritten with zeros then deleted.
MAX_TEMPFILES equ 16           ; tracked decrypt-to-temp files per session
TEMP_PATHW    equ 300          ; wide chars reserved per temp path
TEMP_SIZEOFF  equ TEMP_PATHW*2 ; qword plaintext size lives after the path
TEMPREC       equ TEMP_SIZEOFF+8
GENERIC_WRITE_ equ 40000000h
OPEN_EXISTING_ equ 3
FILE_ATTR_NORMAL_ equ 80h
FILE_ATTRIBUTE_TEMPORARY equ 100h
WIPE_CHUNK    equ 65536        ; bytes of zeros written per pass
TFILE_ENTRY equ 328
TFILE_NAME  equ 68             ; filename offset within a tile-file entry
MAX_FIELDS  equ 96             ; g_field_list capacity (matches main.asm): >= MAXROWS + MAX_TFILES + title + markers
; Field history: every value-level event on ANY tile (not just secrets) is
; archived as a reserved VF_PWHIST field, value = raw {u64 FILETIME, label wide,
; old value wide, u32 action} (VFL_RAW).  Loaded into g_pwhist for the open entry;
; g_pworig holds the entry's ORIGINAL field values keyed by (effective) label at
; load, so gui_commit can detect per-tile what changed.  Two kinds of event are
; recorded: CHANGED (a value was overwritten - the archived value is the OLD one)
; and ADDED (a label first came to hold data, so there is no old value to keep).
; ADDED deliberately stores no value: the current one is already in the record,
; and history must not become a second copy of live secrets.  The browser groups
; records into one tab per label.
; MAX_PWHIST / PWHIST_ENTRY / MAX_PWORIG / PWORIG_STRIDE / PWHBLOB_ENTRY live in
; macros.inc - secmem.asm locks and panic-wipes these buffers and must size them
; identically.  The offsets below are gui-side only.
PWHIST_LBL   equ 8             ; label offset within a g_pwhist entry
PWHIST_PW    equ 264           ; value offset (8 + 128*2)
PWHIST_ACT   equ 520           ; action offset (264 + 128*2), in the stride's slack
PWHA_CHANGED equ 0             ; value overwritten -> PWHIST_PW holds the old value
PWHA_ADDED   equ 1             ; label first filled with data -> PWHIST_PW is empty
PWORIG_VAL   equ 256           ; value offset (bytes) within a g_pworig slot
MAXROWS     equ 64
; Commit scratch for custom labels.  Every row can contribute a full 128-wide-char
; label (gg_label reads 128 and gg_lcp copies at most 127 + NUL), so the pool must
; scale with MAXROWS - at 24 rows a fixed 4096 still fit, at 64 it did not.
; gui_gather also range-checks against this, so the two can never drift again.
LBLBLOB_W   equ MAXROWS*128
FDF_LABELED equ 1               ; FD_FLAGS bit0 = carries a custom label
FDF_REVEALED equ 2              ; FD_FLAGS bit1 = value currently unmasked
FDF_PWLVL_MASK equ 30h          ; FD_FLAGS bits4-5 = secret strength grade 0..3
FDF_PWLVL_SHIFT equ 4
; Runtime control ids: IDC_DYN_BASE + row*DYN_SLOTS + slot (DYN_SLOTS = power of 2).
; IDC_DYN_BASE now lives in macros.inc (shared with theme.asm's ghost-fill test).
DYN_SLOTS   equ 16
VDX_DLU     equ 58              ; detail-pane x-shift (DLU): widened sidebar by 50% (116->174)
DYN_SLOTS_LOG2 equ 4
DS_LABEL    equ 0
DS_VALUE    equ 1
DS_REVEAL   equ 2
DS_UP       equ 3
DS_DOWN     equ 4
DS_DEL      equ 5
DS_TCODE    equ 6               ; TOTP live-code display
DS_TBAR     equ 7               ; TOTP drain bar
DS_COPY     equ 8               ; copy-to-clipboard (secret value / TOTP code)
                                ; slots 9 and 11 are unused (were thumbnail/paste)
DS_IMPORT   equ 10              ; attachment: choose a file to attach (edit mode)
DS_SBADGE   equ 14              ; secret: password-strength badge (owner-draw, view mode)
DS_GEN      equ 15              ; secret: generate-password button (edit mode)
TAG_XW      equ 16              ; width (px) of a tag's edit-mode 'x' delete hotspot
DT_NAMEFLAGS equ 8024h          ; DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS
IDC_V_ADDFIELD equ 230          ; "+ Add field" button (edit mode)
IDC_V_SAVE   equ 231          ; "Save" button (edit mode, accent/primary)
IDC_V_SEARCH equ 232          ; search/filter box under the entry list
IDC_V_HEADER equ 233          ; detail-pane header (icon tile + title, view mode)
IDC_V_TITLELBL equ 234        ; "Title" static label (edit mode only)
IDC_V_ICON   equ 249          ; edit-mode icon tile before the title (opens picker)
IDC_V_OVFL   equ 235          ; header overflow (...) menu button
DLG_PWHIST   equ 780          ; password-history browser dialog
IDC_PH_LIST  equ 781          ; owner-draw list of archived passwords
PH_ROW_H     equ 26           ; history row height (px)
PH_PURGE_W   equ 22           ; per-row purge hotspot width (px)
PH_HDRH      equ 22           ; height (px) of the created/modified header atop the list
PH_TABH      equ 28           ; height (px) of the per-tile tab strip below the header
MAX_TABS     equ 16           ; distinct labels (tabs) shown in the history browser
IDC_V_FAV    equ 237          ; header favorite (star) toggle
IDC_V_CANCEL equ 238          ; "Cancel" button (edit mode, discards edits)
IDC_V_DONE   equ 271          ; trash view: "Done" (exit recover mode); accent button
IDC_V_GENERATE equ 273        ; sidebar dock: standalone password generator (retired: hidden, dock replaces)
IDC_V_HDREDIT  equ 274        ; detail-header edit ghost button (D1 command dock; replaces sidebar "e")
IDC_V_PGPREV   equ 267        ; detail pagination: previous page (ghost)
IDC_V_PGIND    equ 268        ; detail pagination: "n / m" indicator (static)
IDC_V_PGNEXT   equ 269        ; detail pagination: next page (ghost)
; (field-area bottom is computed live from the window height by gui_vis_bottom)
; Win32 window styles (gui.asm builds controls at runtime; the RC gets these
; from windows.h, but this module needs the numeric values).
WS_CHILD_       equ 40000000h
WS_VISIBLE_     equ 10000000h
WS_CLIPSIBLINGS_ equ 04000000h    ; a row value edit must not repaint over the
                                  ; overlapping top-right cluster (badge/glyphs/trash)
WS_TABSTOP_     equ 00010000h
ES_AUTOHSCROLL_ equ 0080h
ES_AUTOVSCROLL_ equ 0040h
ES_PASSWORD_    equ 0020h
ES_MULTILINE_   equ 0004h
ES_WANTRETURN_  equ 1000h
BS_OWNERDRAW_   equ 000Bh
SS_OWNERDRAW_   equ 000Dh
SS_LEFTNOWORDWRAP_ equ 000Ch
WM_GETFONT      equ 31h

; OPENFILENAMEW (x64 layout; STRUCT 8 gives the correct natural alignment)
OPENFILENAMEW struct 8
    lStructSize       dd ?
    hwndOwner         dq ?
    hInstance         dq ?
    lpstrFilter       dq ?
    lpstrCustomFilter dq ?
    nMaxCustFilter    dd ?
    nFilterIndex      dd ?
    lpstrFile         dq ?
    nMaxFile          dd ?
    lpstrFileTitle    dq ?
    nMaxFileTitle     dd ?
    lpstrInitialDir   dq ?
    lpstrTitle        dq ?
    Flags             dd ?
    nFileOffset       dw ?
    nFileExtension    dw ?
    lpstrDefExt       dq ?
    lCustData         dq ?
    lpfnHook          dq ?
    lpTemplateName    dq ?
    pvReserved        dq ?
    dwReserved        dd ?
    FlagsEx           dd ?
OPENFILENAMEW ends

.const
; ---- ASCII (console) diagnostics --------------------------------------------
CSTR c_nocpu,   "error: CPU lacks required features (AES-NI/PCLMULQDQ/SSE4.1/SHA-NI)",13,10
CSTR c_stfail,  "SELFTEST FAILURE - refusing to run",13,10
; ---- wide message-box strings (WSTR: no commas) -----------------------------
WSTR t_err,         <Vordr - error>
WSTR m_nocpu,       <This CPU lacks required features (AES-NI / PCLMULQDQ / SSE4.1 / SHA-NI) - cannot run.>
WSTR m_stfail,      <Self-test FAILED - refusing to run. The binary may be corrupt.>
WSTR t_remove,      <Remove this entry?>
WSTR t_trash,       <Move this entry to the trash? It can be restored for 30 days.>
WSTR t_delforever,  <Permanently delete this entry? This cannot be undone.>
WSTR t_notrash,     <There are no deleted items to recover.>
WSTR t_recover_ttl, <Recover items>
WSTR gt_copy,       <Copy>                   ; standalone-pwgen action button (R7.4)
WSTR s_pickvault,   <Select or create a vault file first.>
WSTR s_nopw,        <Enter the master password.>
WSTR s_badpw,       <Password must be 1..1024 UTF-8 bytes.>
WSTR s_wrongpw,     <Wrong master password.>
WSTR s_corrupt,     <Not a Vordr vault or the file is corrupt.>
WSTR s_io,          <Cannot read or write that file.>
WSTR s_rollback,    <This vault is older than the last one saved on this PC. It may be a restored backup or a rollback. Open it anyway?>
WSTR s_rbabort,     <Unlock aborted (older vault).>
WSTR t_rbtitle,     <Vault rollback warning>
WSTR t_exttitle,    <Vault changed on disk>
WSTR s_reloaded,    <This vault was changed by someone else and has been reloaded from disk. Your change was not saved - re-apply it and save again.>
WSTR t_reloaded,    <Vault reloaded>
WSTR s_busy,        <Another user is saving this vault right now. Your change is kept in memory - try saving again in a moment.>
WSTR s_nolock,      <Vordr could not lock all secret buffers into RAM on this system, so decrypted secrets may be written to the pagefile. Consider closing memory-heavy apps.>
WSTR t_nolock,      <Secrets not pinned to RAM>
WSTR s_lkdiag1,     <Diagnostic: VirtualLock error >
WSTR s_lkdiag2,     <, working-set-grow error >
WSTR s_lkdiag3,     <. (VirtualLock is limited by the working-set quota, not by free RAM.)>
; C5: GUI security-event names for the audit log (log_result classifies the code)
WSTR ev_unlock,     <gui-unlock>
WSTR s_createfail_n, <Could not create the vault. Windows error>
WSTR s_nodir_n,      <Could not create the folder for the vault. Check the vault location in Settings. Windows error>
WSTR m_exedir,       <This vault would be created in the folder Vordr itself runs from. Program folders get replaced on update and are often temporary or removable, so the vault could be lost. Create it here anyway?>
WSTR t_exedir,       <Vordr - unusual location>
WSTR h_title,        <Vault health>
WSTR h_secrets,      <secrets>
WSTR h_weak,         <weak>
WSTR h_reused,       <reused>
WSTR h_ageing,       <ageing>
WSTR h_allclear,     <Everything looks healthy.>
WSTR h_attention,    <Some secrets could use attention.>
WSTR h_empty,        <This vault is empty. Press + to add your first secret.>
; The launch gate refuses to start Vordr if any of these fail, so this line can
; only ever be drawn on a passing build.  It therefore does NOT say "passed" - a
; tick that cannot show anything else is decoration.  What it reports is WHAT was
; checked and against which published vectors, which is a fact the reader can go
; and verify.
WSTR h_kat_suf,      < known-answer tests verified at launch>
WSTR h_kat_std,      <FIPS 180-4, SP 800-38D, RFC 9106, RFC 7693, RFC 2202, RFC 4226, RFC 4648>
WSTR s_exedir_no,    <Cancelled. Pick a different location for the vault.>
WSTR ev_save,       <gui-save>
WSTR ev_export,     <gui-export>
WSTR ev_import,     <gui-import>
WSTR g_singleton_name, <VordrSingletonMutex_v1>
WSTR g_vault_title,    <Vordr - Vault>
WSTR g_vault_title_ro, <Vordr - Vault (read-only)>   ; E9: title when opened read-only
WSTR g_unlock_title,   <Vordr - Unlock vault>
WSTR g_create_title,   <Vordr - Set master password>
WSTR s_createfail,  <Could not create the vault (I/O or out of memory).>
WSTR s_notitle,     <An entry needs a title.>
WSTR s_nofieldroom, <This record already has the maximum number of fields.>
WSTR s_resealfail,  <Unable to write to the vault file - it may be read-only or locked by another program. Your changes are kept in memory. Retry saving now?>
WSTR t_overwrite,   <Vordr - vault already exists>
WSTR m_overwrite,   <A vault file already exists at this location. Creating a new vault will PERMANENTLY destroy it and every entry it holds. Overwrite it?>
WSTR s_kept,        <Existing vault kept. Cancel, or use "Create new..." to choose a different file.>
WSTR s_pwmismatch,  <The passwords do not match.>
WSTR s_pwshort,     <Password is too short for the current policy.>
WSTR s_pwclasses,   <Password needs more character types (lowercase / uppercase / number / symbol).>
WSTR t_noprevinfo,  <Disable attachment preview>
WSTR m_noprevinfo,  <Disable preview of attachments so it never opens in another app. Opening would decrypt the file to a temp folder where its plaintext can linger for other software to read, and may be left behind.>
WSTR wtmptest_name, <vordr_tmptest.bin>       ; gui_tmptest scratch (headless probe)
WSTR wt_newentry,   <New entry>
WSTR cue_search,    <Search>
WSTR sel_cap_imp,   <Vordr - Select entries to import>
WSTR sel_ok_imp,    <Import>
WSTR t_tpminfo,     <TPM Unlock>
WSTR m_tpminfo,     <The TPM chip in this computer can unlock the vault automatically on this device. You will not need to type the master password at startup. The password still works everywhere and is never stored.>
WSTR t_msecinfo,    <Secure Unlock>
WSTR m_msecinfo,    <The master password is typed on a private, isolated Windows desktop, like the one used for UAC prompts. Keyloggers and screen-scrapers in your normal session cannot see it. If a private desktop is unavailable, a normal prompt is used.>
WSTR cue_pw,        <Master password>
WSTR cue_pw2,       <Confirm password>
WSTR t_req,         <Password requirements>
WSTR req_p1,        <Your master password must be at least >
WSTR req_p2,        < characters and use at least >
WSTR req_p3,        < of 4 character types - lowercase / uppercase / number / symbol.>
req_p4 label word
    dw 13,10,13,10,84,104,101,32,109,97,115,116,101,114,32,112
    dw 97,115,115,119,111,114,100,32,105,115,32,116,104,101,32,111
    dw 110,108,121,32,107,101,121,32,116,111,32,101,118,101,114,121
    dw 32,97,99,99,111,117,110,116,32,121,111,117,39,118,101,32
    dw 115,97,118,101,100,46,32,84,104,101,114,101,32,105,115,32
    dw 110,111,32,114,101,115,101,116,32,98,117,116,116,111,110,44
    dw 32,110,111,32,34,102,111,114,103,111,116,32,112,97,115,115
    dw 119,111,114,100,34,32,108,105,110,107,44,32,97,110,100,32
    dw 110,111,32,119,97,121,32,116,111,32,114,101,99,111,118,101
    dw 114,32,105,116,32,105,102,32,121,111,117,32,108,111,115,101
    dw 32,105,116,46,32,67,104,111,111,115,101,32,97,32,115,116
    dw 114,111,110,103,32,112,97,115,115,119,111,114,100,32,121,111
    dw 117,39,108,108,32,116,114,117,108,121,32,114,101,109,101,109
    dw 98,101,114,44,32,107,101,101,112,32,105,116,32,115,97,102
    dw 101,44,32,97,110,100,32,110,101,118,101,114,32,115,104,97
    dw 114,101,32,105,116,46,32,80,114,111,116,101,99,116,32,105
    dw 116,32,108,105,107,101,32,116,104,101,32,111,110,108,121,32
    dw 107,101,121,32,116,111,32,121,111,117,114,32,100,105,103,105
    dw 116,97,108,32,104,111,109,101,8212,98,101,99,97,117,115,101
    dw 32,105,102,32,105,116,39,115,32,103,111,110,101,44,32,101
    dw 118,101,114,121,116,104,105,110,103,32,105,115,32,103,111,110
    dw 101,46,0
WSTR wv_clip,       <ClipSeconds>
WSTR wv_pwdays,     <PwVerifyDays>
ifdef DBG_TRACE
WSTR wv_pwnow,      <PwVerifyNow>            ; test builds: force the reminder every unlock
endif
WSTR wv_idlemin,    <IdleLockMin>
WSTR wv_winlock,    <LockOnWinLock>
WSTR wv_nopreview,  <NoPreview>
WSTR wv_pwlen,      <PwMinLen>
WSTR wv_pwcls,      <PwMinClasses>
WSTR wv_nohist,     <NoHistory>
WSTR wv_nophon,     <NoPhonetic>
WSTR wv_secunlock,  <SecureUnlock>
WSTR wv_tpm,        <TpmUnlock>
; --- system tray strings ------------------------------------------------------
WSTR t_about,       <About Vordr>
m_welcome label word
    dw 87,101,108,99,111,109,101,32,116,111,32,86,111,114,100,114
    dw 44,32,116,104,101,32,112,97,115,115,119,111,114,100,32,109
    dw 97,110,97,103,101,114,32,98,117,105,108,116,32,102,111,114
    dw 32,116,111,116,97,108,32,100,105,103,105,116,97,108,32,115
    dw 111,118,101,114,101,105,103,110,116,121,46,13,10,13,10,87
    dw 101,32,112,114,111,116,101,99,116,32,121,111,117,114,32,115
    dw 101,99,114,101,116,115,32,119,105,116,104,32,115,116,97,116
    dw 101,45,111,102,45,116,104,101,45,97,114,116,32,113,117,97
    dw 110,116,117,109,45,114,101,115,105,115,116,97,110,116,32,101
    dw 110,99,114,121,112,116,105,111,110,44,32,101,110,115,117,114
    dw 105,110,103,32,116,104,101,121,32,114,101,109,97,105,110,32
    dw 115,97,102,101,32,97,103,97,105,110,115,116,32,98,111,116
    dw 104,32,99,117,114,114,101,110,116,32,116,104,114,101,97,116
    dw 115,32,97,110,100,32,102,117,116,117,114,101,32,99,111,109
    dw 112,117,116,105,110,103,32,97,100,118,97,110,99,101,115,46
    dw 13,10,13,10,86,111,114,100,114,32,111,112,101,114,97,116
    dw 101,115,32,99,111,109,112,108,101,116,101,108,121,32,111,102
    dw 102,108,105,110,101,32,119,105,116,104,32,122,101,114,111,32
    dw 101,120,116,101,114,110,97,108,32,100,101,112,101,110,100,101
    dw 110,99,105,101,115,46,32,89,111,117,114,32,115,101,99,114
    dw 101,116,115,32,115,116,97,121,32,101,120,97,99,116,108,121
    dw 32,119,104,101,114,101,32,116,104,101,121,32,98,101,108,111
    dw 110,103,58,32,117,110,100,101,114,32,121,111,117,114,32,99
    dw 111,110,116,114,111,108,46,13,10,13,10,83,101,116,32,97
    dw 32,115,101,99,117,114,101,32,109,97,115,116,101,114,32,112
    dw 97,115,115,119,111,114,100,32,116,111,32,103,101,116,32,115
    dw 116,97,114,116,101,100,46,0
m_about label word
    dw 87,105,116,104,32,86,111,114,100,114,44,32,121,111,117,114
    dw 32,115,101,99,114,101,116,115,32,97,114,101,32,112,114,111
    dw 116,101,99,116,101,100,32,98,121,32,115,116,97,116,101,45
    dw 111,102,45,116,104,101,45,97,114,116,44,32,113,117,97,110
    dw 116,117,109,45,114,101,115,105,115,116,97,110,116,32,101,110
    dw 99,114,121,112,116,105,111,110,32,101,110,103,105,110,101,101
    dw 114,101,100,32,116,111,32,114,101,109,97,105,110,32,115,101
    dw 99,117,114,101,32,97,115,32,99,111,109,112,117,116,105,110
    dw 103,32,116,101,99,104,110,111,108,111,103,121,32,97,100,118
    dw 97,110,99,101,115,46,13,10,13,10,86,111,114,100,114,32
    dw 105,115,32,98,117,105,108,116,32,111,110,32,116,104,101,32
    dw 102,111,108,108,111,119,105,110,103,58,13,10,13,10,8212,32
    dw 72,97,114,100,119,97,114,101,32,97,99,99,101,108,101,114
    dw 97,116,101,100,32,65,69,83,45,50,53,54,45,71,67,77
    dw 32,101,110,99,114,121,112,116,105,111,110,13,10,8212,32,65
    dw 114,103,111,110,50,105,100,32,102,111,114,32,98,114,117,116
    dw 101,45,102,111,114,99,101,32,115,101,99,117,114,101,100,32
    dw 107,101,121,115,13,10,8212,32,80,114,111,118,101,110,32,105
    dw 109,112,108,101,109,101,110,116,97,116,105,111,110,44,32,116
    dw 101,115,116,101,100,32,97,103,97,105,110,115,116,32,78,73
    dw 83,84,47,82,70,67,32,118,101,99,116,111,114,115,32,111
    dw 110,32,101,118,101,114,121,32,114,117,110,13,10,13,10,65
    dw 108,108,32,119,114,105,116,116,101,110,32,105,110,32,54,52
    dw 98,105,116,32,97,115,115,101,109,98,108,101,114,32,119,105
    dw 116,104,32,122,101,114,111,32,114,117,110,116,105,109,101,32
    dw 100,101,112,101,110,100,101,110,99,105,101,115,46,0
WSTR mi_open,       <Open>
WSTR mi_exit,       <Exit>
WSTR mb_ok,         <OK>
WSTR mb_yes,        <Yes>
WSTR mb_no,         <No>
align 2                                     ; tray_cls must be even-aligned: the
tray_cls label word                         ;  OS class-name reader faults on odd
    dw 'V','o','r','d','r','T','r','a','y', 0
dbg_static_cls label word                   ; system class for the no-registration fallback
    dw 'S','t','a','t','i','c', 0
tray_wt label word
    dw 'V','o','r','d','r', 0
secdesk_name label word                          ; private desktop for password entry
    dw 'V','o','r','d','r','-','S','e','c','u','r','e', 0
desk_default label word                          ; the normal interactive desktop, by name:
    dw 'D','e','f','a','u','l','t', 0            ;   secdesk_restore's last resort
WSTR cf_hist_name,  <CanIncludeInClipboardHistory>
WSTR cf_cloud_name, <CanUploadToCloudClipboard>
WSTR cf_excl_name,  <ExcludeClipboardContentFromMonitorProcessing>
ifdef DBG_TRACE
WSTR sd_spike_ttl, <Secure desktop>
WSTR sd_spike_txt, <This dialog is running on a private, isolated Vordr desktop. Same-session keyloggers and screen-scrapers cannot see it. Click OK to return to your normal desktop.>
endif
WSTR xp_mm_title,    <Export all secrets>
WSTR imp_xls_wrongpw,<Could not open the workbook - the password was incorrect.>
WSTR imp_g_title,    <Import>
; E6: vault-health summary (Ctrl+H) - labels chained with gui_wstrcpy/gui_u32w
WSTR t_health,       <Vordr - vault health>
WSTR hb_l1,          <Entries: >
WSTR hb_l2,          <Weak passwords: >
WSTR hb_l3,          <Reused passwords: >
WSTR hb_l4,          <Unchanged over a year: >
WSTR hb_locked,      <Unlock a vault first to see its health.>
hb_crlf  dw 13,10,0
WSTR imp_g_pre,      <Imported >
WSTR imp_g_post,     < entries.>
WSTR imp_g_none,     <No importable entries were found. Vordr imports uncompressed (STORED) AES-zip members only - re-create hand-built archives with no compression.>
; The ZIP wording above is meaningless for a .vordr import, and worse, it was shown for
; the ordinary case of re-importing a file this vault already contains - which is not a
; failure at all.  These two say what actually happened.
WSTR imp_v_none,     <That vault has no entries to import. Its records are either already in the trash or carry no title.>
WSTR imp_v_trunc,    <This vault holds more entries than the selection list can show. Only the first 8192 are listed and importable; the rest are not included. Import in stages if you need them all.>
WSTR t_imp_trunc,    <Vordr - partial import>
WSTR imp_v_same,     <Nothing to import - this vault already has every entry you selected, and none of them was newer. Re-importing the same file is always safe.>
WSTR imp_g_bad,      <That file is not a Vordr encrypted export (.zip), or the password was wrong.>
WSTR zip_title,      <Export to encrypted archive>
WSTR zip_defname,    <vordr-export.zip>
; No extension: the save box shows just the stem, so nothing on screen can disagree
; with the file-type dropdown, and the modern dialog appends the selected type's
; extension itself.  gui_fix_ext then settles it from the filter index regardless.
WSTR exp_defname,    <vordr-export>
WSTR exp_title,      <Export>
WSTR w_dotvordr,     <.vordr>
WSTR w_dotzip,       <.zip>
WSTR exp_pw_vordr,   <This writes the selected entries (including passwords and TOTP secrets) into a new encrypted .vordr vault, protected only by the password you choose below. Store it safely and delete it when done.>
WSTR exp_pw_zip,     <This writes the selected entries (including passwords and TOTP secrets) into one .zip archive encrypted with WinZip AE-2, protected only by the password you choose below. Store it safely.>
WSTR exp_zipwarn,    <ZIP is the weaker format - use it only when the export must be read by other software. Attachment names become random ids but keep their extensions, so a holder can see what file types are inside. Continue?>
WSTR exp_done_ok,    <Export complete. Keep the file safe and delete it when you no longer need it.>
WSTR pg_lbl_up,  <Uppercase>
WSTR pg_lbl_lo,  <Lowercase>
WSTR pg_lbl_di,  <Digits>
WSTR pg_lbl_sy,  <Symbols>
WSTR pg_style_pre, <Style: >
WSTR pg_sn0, <Random>
WSTR pg_sn1, <Passphrase>
WSTR pg_sn2, <Pronounceable>
WSTR pg_sn3, <PIN>
WSTR pg_sn4, <Hex>
WSTR pg_bits_suf, < bits of entropy>
align 8
pg_snames dq pg_sn0, pg_sn1, pg_sn2, pg_sn3, pg_sn4
WSTR xp_mm_empty,    <Please enter an export password.>
WSTR xp_mm_mismatch, <The two passwords do not match. Please re-enter them.>
WSTR xp_mm_fail,     <The export could not be completed.>
WSTR cue_xppw,       <Export password>
WSTR cue_rmpw,       <Master password>
WSTR rm_wrong,       <That is not the master password for this vault. Try again, or choose "Not now".>
WSTR rm_title,       <Vordr - Master password check>
WSTR rm_okmsg,       <Confirmed - that is the master password for this vault.>
WSTR cue_xppw2,      <Confirm password>
WSTR cue_ippw,       <Workbook password>
WSTR imp_pw_title,   <Import from Excel>
WSTR imp_pw_empty,   <Please enter the workbook password.>
wb_add label word
    dw 002Bh, 0                                  ; +  (add)
wb_addf label word
    dw 0E710h, 0                                 ; Segoe Fluent Icons: Add (centered glyph)
wb_edit label word
    dw 0E70Fh, 0                                 ; Segoe Fluent Icons: Edit (pencil)
wb_rem label word
    dw 0E74Dh, 0                                 ; Segoe Fluent Icons: Delete (trashcan)
; --- runtime field-row glyphs, window classes, and default labels ---
wb_up label word
    dw 0E70Eh, 0                                 ; ChevronUp (move field up)
wb_down label word
    dw 0E70Dh, 0                                 ; ChevronDown (move field down)
wb_eye label word
    dw 0E7B3h, 0                                 ; RedEye (reveal)
wb_copy label word
    dw 0E8C8h, 0                                 ; Copy (copy to clipboard)
wb_more label word
    dw 0E712h, 0                                 ; More (header overflow menu)
wb_star label word
    dw 0E734h, 0                                 ; FavoriteStar (MSAA name for the fav button)
fav_one label word
    dw '1', 0                                    ; VF_FAV marker value
pht_lbl db 'Password'                            ; gui_phtest scratch (headless probe)
pht_old db 'oldpw'
align 2
pht_ttl dw 'T', 0
pht_new dw 'n','e','w','p','w', 0
pht_loginu  db 'Login'                           ; phtest: a 2nd, different-label field
pht_stayu   db 'stays'
align 2
pht_loginw  dw 'L','o','g','i','n', 0
pht_staysw  dw 's','t','a','y','s', 0
    even                                         ; wb_gen MUST be word-aligned: an odd
wb_gen label word                                ; caption addr fails CreateWindowExW (998)
    dw 0E72Ch, 0                                 ; Refresh (generate password)
sn_light dw 'L','i','g','h','t',0
sn_sepia dw 'S','e','p','i','a',0
sn_nord dw 'N','o','r','d',0
sn_midnight dw 'M','i','d','n','i','g','h','t',0
sn_commodore dw 'C','o','m','m','o','d','o','r','e',0
sn_amethyst dw 'A','m','e','t','h','y','s','t',0
sn_emerald dw 'E','m','e','r','a','l','d',0
sn_sapphire dw 'S','a','p','p','h','i','r','e',0
sn_gruvbox dw 'G','r','u','v','b','o','x',0
align 8
scheme_names dq sn_light,sn_sepia,sn_nord,sn_midnight,sn_commodore,sn_amethyst,sn_emerald,sn_sapphire,sn_gruvbox
GUI_SCHEME_COUNT equ 9
GUI_SCHEME_GRUVBOX equ 8               ; default scheme (index into schemes[])
layout_gaps  dd 7, 3, 14                          ; inter-card gap (DLU) per layout
lay_band     dd 14, 0, 18                         ; label band: card(top) vs 0=flat(left)
lay_itemh    dd 42, 30, 58                         ; list-item pixel height (index 0 used)
pref_scheme dw 'u','i','_','s','c','h','e','m','e',0
pref_loglevel dw 'L','o','g','L','e','v','e','l',0   ; C5: HKCU audit-log verbosity
pref_reqhello dw 'T','p','m','R','e','q','u','i','r','e','H','e','l','l','o',0  ; C4
pref_layout dw 'u','i','_','l','a','y','o','u','t',0
pref_hotkey dw 'u','i','_','h','o','t','k','e','y',0   ; (mods << 16) | vk; 0 = built-in default
WSTR hk_plus, < + >
WSTR hk_shift, <Shift>
WSTR hk_ctrl, <Ctrl>
WSTR hk_alt, <Alt>
WSTR hk_win, <Win>
WSTR hk_none, <(none)>
WSTR hk_press, <Press keys...>
WSTR hk_taken, <That combination is already in use by another program.  Vordr kept its previous hotkey.>
WSTR hk_ttl, <Summon hotkey>
align 8
align 4
; class accent colors (index 0 upper / 2 digit / 3 symbol; lowercase uses g_col_text)
cls_accent_dark  dd 00FFC24Ch, 0, 0060D060h, 003C7DFFh   ; light-blue / green / orange
cls_accent_light dd 00CC6600h, 0, 00008000h, 000055CCh   ; strong-blue / dk-green / dk-orange
f_mono label word
    dw 'C','o','n','s','o','l','a','s', 0
pr_symdef dw 's','y','m','b','o','l', 0
pr_cap  dw 'C','A','P','-', 0                     ; capital-letter marker
lg_upper dw 'A','B','C', 0
lg_lower dw 'a','b','c', 0
lg_digit dw '1','2','3', 0
lg_sym   dw '!','@','#', 0
pr_zero  dw '0', 0
align 8
lg_ptrs  dq lg_upper, lg_lower, lg_digit, lg_sym
include phonetic.inc
cls_edit label word
    dw 'E','d','i','t', 0
cls_button label word
    dw 'B','u','t','t','o','n', 0
cls_static label word
    dw 'S','t','a','t','i','c', 0
cls_tooltip label word
    dw 't','o','o','l','t','i','p','s','_','c','l','a','s','s','3','2', 0
WSTR gt_more, <More>
WSTR gt_fav, <Favorite>
WSTR gt_new, <New item>
WSTR gt_edit, <Edit entry>
WSTR gt_pgprev, <Previous page>
WSTR gt_pgnext, <Next page>
WSTR gt_rem, <Delete entry>
WSTR gt_gen, <Generate password>
WSTR gt_close, <Close>
WSTR gt_settings, <Settings>
; per-field row glyphs (registered per control, dropped again by gui_rows_clear)
WSTR gt_reveal, <Show / hide this value>
WSTR gt_rowcopy, <Copy to clipboard>    ; (gt_copy is the pwgen button's caption)
WSTR gt_rowgen, <Generate a password>
WSTR gt_attach, <Attach a file>
WSTR gt_rowdel, <Delete this field>
WSTR gt_rowup, <Move this field up>
WSTR gt_rowdn, <Move this field down>
kl_user label word
    dw 'U','s','e','r','n','a','m','e', 0
kl_secret label word
    dw 'P','a','s','s','w','o','r','d', 0
kl_url label word
    dw 'U','R','L', 0
kl_notes label word
    dw 'N','o','t','e','s', 0
kl_totp label word
    dw 'A','u','t','h','e','n','t','i','c','a','t','o','r', 0
kl_text label word
    dw 'T','e','x','t', 0
kl_email label word
    dw 'E','m','a','i','l', 0
kl_image label word
    dw 'I','m','a','g','e', 0
kl_file label word
    dw 'F','i','l','e', 0
kl_group label word
    dw 'G','r','o','u','p',' ','h','e','a','d','i','n','g', 0
kl_spacer label word
    dw 'S','p','a','c','e','r', 0
; --- new-entry templates (redesign D4): a pre-built field list per preset ------
WSTR tm_login,  <Login>
WSTR tm_card,   <Credit card>
WSTR tm_ident,  <Identity>
WSTR tm_note,   <Secure note>
WSTR tm_blank,  <Blank>
WSTR lbl_holder,   <Cardholder>
WSTR lbl_cardno,   <Card number>
WSTR lbl_expiry,   <Expiry>
WSTR lbl_cvv,      <CVV>
WSTR lbl_fullname, <Full name>
WSTR lbl_phone,    <Phone>
align 8
tmpl_login label qword                          ; {count; count x (type, label)} after Title
    dq 4
    dq VF_USERNAME, 0
    dq VF_SECRET, 0
    dq VF_URL, 0
    dq VF_NOTES, 0
tmpl_card label qword
    dq 5
    dq VF_TEXT, lbl_holder
    dq VF_TEXT, lbl_cardno
    dq VF_TEXT, lbl_expiry
    dq VF_SECRET, lbl_cvv
    dq VF_NOTES, 0
tmpl_ident label qword
    dq 4
    dq VF_TEXT, lbl_fullname
    dq VF_TEXT, kl_email
    dq VF_TEXT, lbl_phone
    dq VF_NOTES, 0
tmpl_note label qword
    dq 1
    dq VF_NOTES, 0
tmpl_blank label qword
    dq 0                                         ; Title only
tmpl_table label qword
    dq tmpl_login, tmpl_card, tmpl_ident, tmpl_note, tmpl_blank
; resize anchors (redesign 1.3): {control id, anchor flags} for gui_reflow
g_anchor_def label dword
    dd IDC_V_REMOVE,   ANCH_BOTTOM
    dd IDC_V_HEADER,   ANCH_STRETCHW
    dd IDC_V_TITLE,    ANCH_STRETCHW
; the entry list (sidebar_layout) and the command controls (gui_cmd_dock_layout)
; are NOT delta-anchored - they are laid out from the live client rect.
;
; Derived from the table, never hand-counted.  It was hand-counted, and when
; IDC_V_MBACK was deleted from the table the 4 stayed: the reflow then read one
; entry PAST the end, straight into tag_xw, and got {id 215, flags 0x0070006F} -
; IDC_V_TOTPBAR, a real control, stretched in both axes and anchored right+bottom.
; It landed across the title edit.  Two dwords per row.
ANCHOR_N equ ($ - g_anchor_def) / 8
tag_xw label word
    dw 0D7h, 0                             ; multiplication sign, used as the tag 'x'
verb_open label word
    dw 'o','p','e','n', 0
url_https label word                    ; scheme prefix for a bare URL (e.g. "example.com")
    dw 'h','t','t','p','s',':','/','/', 0
gl_cloud    dw 0E753h, 0                 ; Segoe Fluent Icons: Cloud (OneDrive)
gl_doc      dw 0E8A5h, 0                 ; Document (Documents folder)
gl_folder   dw 0E8B7h, 0                 ; Folder (other location)
WSTR st_onedrive,   <OneDrive>
WSTR st_documents,  <Documents>
even
s_stor_sep  dw ' ', 00B7h, ' ', 0            ; " . " separator: <location> . <vault name>
f_iconname label word
    dw 'S','e','g','o','e',' ','F','l','u','e','n','t',' ','I','c','o','n','s', 0
f_symbol label word
    dw 'S','e','g','o','e',' ','U','I',' ','S','y','m','b','o','l', 0
f_segoeui label word
    dw 'S','e','g','o','e',' ','U','I', 0
align 4
g_tilepal label dword                         ; 8 tile colours (COLORREF 0x00BBGGRR)
    dd 000C06020h, 00050A028h, 0001E78E6h, 000C85A96h
    dd 000AAAA1Eh, 0004646D2h, 0009650DCh, 000826450h
; icon picker: 18 curated Segoe Fluent glyphs (codepoints) + 12 tile colours
GLYPHPAL_N equ 30
g_glyphpal label dword
    dd 0E72Eh, 0E774h, 0E77Bh, 0E715h, 0E716h, 0E7BFh   ; lock globe contact mail people shop
    dd 0E7FCh, 0E714h, 0E753h, 0E717h, 0E8D7h, 0E8A5h   ; game media cloud phone key document
    dd 0E734h, 0EB51h, 0E80Fh, 0E713h, 0E8F1h, 0E787h   ; star heart home settings library calendar
    dd 0E70Fh, 0E722h, 0E8C8h, 0E706h, 0E790h, 0E838h   ; edit camera copy brightness colour folder
    dd 0E7C1h, 0E946h, 0E767h, 0E72Ch, 0E8A9h, 0E8B7h   ; flag info volume refresh view tag
GLYPHCOL_N equ 12
g_glyphpal_col label dword
    dd 000C06020h, 00050A028h, 0001E78E6h, 000C85A96h
    dd 000AAAA1Eh, 0004646D2h, 0009650DCh, 000826450h
    dd 0003030D0h, 0002EA02Eh, 000208CE6h, 000909090h  ; red green amber grey
name_default_att label word
    dw 'v','o','r','d','r','_','a','t','t','a','c','h','.','b','i','n', 0
; Executable / script extensions Vordr will never auto-open.  Opening one of these
; attachments prompts a Save As instead, so the USER (not Vordr) decides to run it.
; Lowercase, NUL-separated, double-NUL terminated (see gui_ext_is_exec).
exec_exts label word
    dw 'e','x','e',0,  'c','o','m',0,  's','c','r',0,  'p','i','f',0
    dw 'b','a','t',0,  'c','m','d',0,  'h','t','a',0,  'c','p','l',0
    dw 'm','s','i',0,  'm','s','p',0,  'm','s','c',0,  'j','a','r',0
    dw 'j','s',0,      'j','s','e',0,  'v','b','s',0,  'v','b','e',0
    dw 'w','s','f',0,  'w','s','h',0,  'w','s','c',0,  'p','s','1',0
    dw 'p','s','m','1',0,  'p','s','c','1',0,  'r','e','g',0,  'l','n','k',0
    dw 'u','r','l',0,  'i','n','f',0,  's','c','f',0,  's','c','t',0
    dw 's','h','b',0,  's','h','s',0,  'c','h','m',0,  'h','l','p',0
    dw 'a','d','e',0,  'a','d','p',0,  'm','d','e',0,  'm','d','b',0
    dw 'd','l','l',0,  'o','c','x',0,  's','y','s',0,  'd','r','v',0
    dw 'v','b',0,      'g','a','d','g','e','t',0
    dw 'a','p','p','l','i','c','a','t','i','o','n',0
    dw 'm','s','i','x',0,  'a','p','p','x',0
    dw 'a','p','p','x','b','u','n','d','l','e',0,  'm','s','i','x','b','u','n','d','l','e',0
    dw 'p','s','1','x','m','l',0,  'm','s','h',0,  'w','s',0
    dw 0                                             ; double-NUL terminator
badge_weak label word
    dw 'W','e','a','k', 0
badge_fair label word
    dw 'F','a','i','r', 0
badge_good label word
    dw 'G','o','o','d', 0
badge_strong label word
    dw 'S','t','r','o','n','g', 0
om_copypw label word
    dw 'C','o','p','y',' ','p','a','s','s','w','o','r','d', 0
om_copyuser label word
    dw 'C','o','p','y',' ','u','s','e','r','n','a','m','e', 0
om_delete label word
    dw 'D','e','l','e','t','e',' ','e','n','t','r','y', 0
om_read label word
    dw 'R','e','a','d',' ','p','a','s','s','w','o','r','d', 0
om_history label word
    dw 'S','h','o','w',' ','h','i','s','t','o','r','y', 0
om_recover label word
    dw 'R','e','c','o','v','e','r',' ','i','t','e','m','s', 2026h, 0
om_leavetrash label word
    dw 'R','e','t','u','r','n',' ','t','o',' ','v','a','u','l','t', 0
t_created label word
    dw 'C','r','e','a','t','e','d',' ', 0
t_modified label word
    dw ' ',' ',' ',' ','M','o','d','i','f','i','e','d',' ', 0
pwh_empty label word            ; empty wide string: an ADDED row archives no value
    dw 0
ph_added label word             ; ADDED row marker, shown where an old value would be
    dw '(','a','d','d','e','d',')', 0
g_imgfilter label word          ; "Images\0*.png;*.jpg;*.jpeg;*.bmp;*.gif\0All\0*.*\0\0"
    dw 'I','m','a','g','e','s',0
    dw '*','.','p','n','g',';','*','.','j','p','g',';','*','.','j','p','e','g',';','*','.','b','m','p',';','*','.','g','i','f',0
    dw 'A','l','l',' ','f','i','l','e','s',0
    dw '*','.','*',0,0
g_allfilter label word          ; "All files\0*.*\0\0"
    dw 'A','l','l',' ','f','i','l','e','s',0
    dw '*','.','*',0,0
; Export destination picker.  .vordr is FIRST so it is the default file type: it is
; the stronger format (AES-256-GCM + Argon2id + a full-file MAC, attachments and all).
; ZIP is offered second, for interoperability only, and warns before it is used.
g_expfilter label word          ; "Vordr vault\0*.vordr\0ZIP archive\0*.zip\0\0"
    dw 'V','o','r','d','r',' ','v','a','u','l','t',0
    dw '*','.','v','o','r','d','r',0
    dw 'Z','I','P',' ','a','r','c','h','i','v','e',0
    dw '*','.','z','i','p',0,0
g_vaultfilter label word        ; "Vordr vault\0*.vordr\0All files\0*.*\0\0"
    dw 'V','o','r','d','r',' ','v','a','u','l','t',0
    dw '*','.','v','o','r','d','r',0
    dw 'A','l','l',' ','f','i','l','e','s',0
    dw '*','.','*',0,0
; Import accepts both formats Vordr writes.  The FORMAT is decided by the file's magic,
; not by this filter or the extension - a .vordr renamed to .zip still imports correctly.
g_impfilter label word          ; "Vordr files\0*.vordr;*.zip\0...\0\0"
    dw 'V','o','r','d','r',' ','f','i','l','e','s',0
    dw '*','.','v','o','r','d','r',';','*','.','z','i','p',0
    dw 'V','o','r','d','r',' ','v','a','u','l','t',0
    dw '*','.','v','o','r','d','r',0
    dw 'Z','I','P',' ','a','r','c','h','i','v','e',0
    dw '*','.','z','i','p',0
    dw 'A','l','l',' ','f','i','l','e','s',0
    dw '*','.','*',0,0
g_empty_w label word
    dw 0                                          ; empty wide string (default field value)
; (the settings screen is DLG_SETTINGS, a child window: it hides as ONE hwnd, so the
;  hand-maintained id partition that used to fake that is gone)

; =============================================================================
; The settings table.  One row per control that maps to a dword global; it drives
; populate (gui_settings_populate) and save (gui_settings_store) so that adding a
; setting is ONE row here plus the rc template, instead of edits in seven places.
;
; It also removes a whole class of bug the open-coded version had: those two paths
; were a chain of fallthroughs sharing skip labels, so an early-out in one row
; silently skipped later, unrelated rows.  Two real cases: typing 0 into "Minimum
; character types" jumped past the clipboard, idle, reminder and lock-on-Windows
; saves, and an HKLM lock on that same policy did exactly the same.  A row here
; cannot affect its neighbours - each iteration is independent.
; =============================================================================
SK_NUM equ 0                    ; edit box  <-> dword global; clamped, persisted
SK_TOG equ 1                    ; Fluent toggle: its click handler owns the global,
                                ;   we only gate the control and persist the value
SK_BTN equ 2                    ; button owning its own state (theme): gate only

SF_ZEROOK equ 1                 ; 0 is a legal value ("off").  Without this, a 0
                                ;   read leaves the global untouched.
SF_NEEDHW equ 2                 ; additionally requires g_tpm_present to be enabled

SR_ID    equ 0                  ; dd  control id
SR_KIND  equ 4                  ; dd  SK_*
SR_VAL   equ 8                  ; dq  -> dword holding the value (0 = none)
SR_REG   equ 16                 ; dq  -> HKCU value name  (0 = not persisted here)
SR_LOCK  equ 24                 ; dq  -> dword HKLM lock flag (0 = never locked)
SR_MAX   equ 32                 ; dd  clamp ceiling (SK_NUM)
SR_FLAGS equ 36                 ; dd  SF_*
SR_SIZE  equ 40

align 8
g_setrows label byte
    dd IDC_V_MLEN,    SK_NUM
    dq g_cfg_pwminlen,     wv_pwlen,     g_pol_len_lock
    dd 256,           0
    dd IDC_V_MCLS,    SK_NUM
    dq g_cfg_pwminclasses, wv_pwcls,     g_pol_cls_lock
    dd 4,             0
    dd IDC_V_MCLIP,   SK_NUM
    dq g_clip_secs,        wv_clip,      g_clip_lock
    dd 3600,          SF_ZEROOK
    dd IDC_V_MIDLE,   SK_NUM
    dq g_idle_min,         wv_idlemin,   g_idle_lock
    dd 1440,          SF_ZEROOK
    dd IDC_V_MPWD,    SK_NUM
    dq g_pwdays,           wv_pwdays,    g_pwdays_lock
    dd C9_DAYS_MAX,   SF_ZEROOK
    dd IDC_V_MTPM,    SK_TOG
    dq g_tpm_want,         wv_tpm,       g_tpm_lock
    dd 0,             SF_NEEDHW
    dd IDC_V_MSECD,   SK_TOG
    dq g_secunlock,        wv_secunlock, g_secunlock_lock
    dd 0,             0
    dd IDC_V_MWLK,    SK_TOG
    dq g_winlock,          wv_winlock,   g_winlock_lock
    dd 0,             0
    dd IDC_V_MNOPREV, SK_TOG
    dq g_nopreview,        wv_nopreview, g_nopreview_lock
    dd 0,             0
    dd IDC_V_MNOPHON, SK_TOG
    dq g_no_phonetic,      wv_nophon,    g_nophon_lock
    dd 0,             0
    dd IDC_V_MNOHIST, SK_TOG
    dq g_no_history,       wv_nohist,    g_nohist_lock
    dd 0,             0
    dd IDC_V_MTHEME,  SK_BTN            ; gated by policy; gui_save_prefs persists it
    dq 0,                  0,            g_scheme_lock
    dd 0,             0
g_setrows_end label byte

.data?
align 8
g_hinst     dq ?
g_trayhwnd  dq ?                      ; hidden owner window that hosts the tray icon
g_showing   dd ?                      ; 1 = a modal dialog is currently open (re-entry guard)
g_msg_text  dq ?                      ; Fluent message box: body text / title / flags
g_msg_title dq ?
g_msg_flags dd ?
g_tpm_want  dd ?                      ; Fluent TPM toggle state (1 = enrolled/on)
; ---- secure-desktop password entry (anti-keylogger) -------------------------
g_secunlock      dd ?                 ; setting: 1 = Secure Unlock (master pw on a private desktop)
g_secunlock_lock dd ?                 ; 1 = Secure Unlock forced by HKLM policy (locked)
g_tpm_lock       dd ?                 ; 1 = TPM Unlock forced by HKLM policy (locked)
g_scheme_lock    dd ?                 ; 1 = colour scheme forced by HKLM policy (locked)
g_secdesk_dlg   dd ?                  ; template id marshalled to the worker thread
public g_secdesk_tid
g_secdesk_tid   dd ?                  ; worker thread id while the dialog runs (0 = none).
                                      ;   crash_contain reads it to tell whether the faulting
                                      ;   thread's windows live on the private desktop.
align 8
g_secdesk_proc  dq ?                  ; dialog proc addr for the worker thread
g_secdesk_hd    dq ?                  ; HDESK of the private desktop
public g_secdesk_orig
g_secdesk_orig  dq ?                  ; HDESK of the original input desktop (restore on exit)
g_secdesk_res   dq ?                  ; DialogBox result marshalled back to the caller
g_secdesk_orphan dd ?                 ; 1 = the watchdog gave up on a wedged worker
align 2
g_errbuf    dw 256 dup (?)            ; "<prefix> <number>" built by gui_num_msg
align 4
g_home_stats dd 4 dup (?)             ; vault_health: {weak, reused, old, total}
g_home_valid dd ?                     ; 0 = recompute on the next home paint
g_home_alert dd ?                     ; 1 = this tile's count is a finding, not a total
g_home_numw  dw 16 dup (?)            ; one stat rendered as digits
g_katline    dw 96 dup (?)            ; "<n> known-answer tests verified at launch"
g_exedir    dw 1024 dup (?)           ; folder holding vordr.exe
g_initdir   dw 1024 dup (?)           ; explicit start folder for the vault picker
align 8
; The software shadow stack (g_sstk_base/g_sstk_index) is a process-global, but
; the Secure-Unlock dialog runs on a SEPARATE worker thread (secdesk_thread) that
; executes framed code.  If the worker pushed/popped onto the main thread's shared
; stack it could corrupt the main thread's parked frames -> intermittent
; FF_SHADOW_STACK on the next real return.  The worker gets its OWN shadow stack,
; swapped in for the duration of its run (the main thread is blocked in
; WaitForSingleObject, so touching these globals is race-free).
g_sstk_worker   dq SSTK_CAPACITY dup (?)  ; the worker thread's isolated shadow stack
g_sstk_savebase dq ?                  ; main thread's g_sstk_base, parked during the worker
g_sstk_saveidx  dq ?                  ; main thread's g_sstk_index, parked during the worker
g_nid       db 976 dup (?)           ; NOTIFYICONDATAW (x64 full size)
g_wc        db 80 dup (?)            ; WNDCLASSW (72 used)
g_msg       db 56 dup (?)            ; MSG
g_pt        db 8 dup (?)             ; POINT (cursor for the tray menu)
align 8
g_vpath_set dd ?
g_create    dd ?
g_is_default dd ?                     ; 1 = auto-created default vault (register it)
g_pol_len_lock dd ?                   ; 1 = min-length set by HKLM policy (locked)
g_pol_cls_lock dd ?                   ; 1 = min-classes set by HKLM policy (locked)
g_no_history  dd ?                    ; 1 = "Do not save history" setting on
g_no_phonetic dd ?                    ; 1 = "Disable phonetic reader" setting on
public g_readonly
g_readonly    dd ?                    ; E9: 1 = vault opened read-only (no disk writes)
public g_tpm_reqhello
g_tpm_reqhello dd ?                   ; C4: 1 = require Hello/PIN on TPM unlock (not silent)
g_seclock_warned dd ?                 ; C3: 1 = the "secrets not pinned" warning was shown
g_loglvl_lock   dd ?                  ; C5: 1 = LogLevel forced by HKLM policy
g_reqhello_lock dd ?                  ; C4: 1 = TpmRequireHello forced by HKLM policy
g_nohist_lock dd ?                    ; 1 = NoHistory forced by HKLM policy (locked)
g_nophon_lock dd ?                    ; 1 = NoPhonetic forced by HKLM policy (locked)
g_pw_compliant dd ?                   ; 1 = create-dialog password meets the policy
g_tpm_present dd ?                    ; 1 = a usable platform TPM was detected
g_pw_level  dd ?                      ; 0 bad/none, 1 weak, 2 adequate, 3 strong
g_pw_match  dd ?                      ; 1 = confirm matches a non-empty password
align 8
g_br_red    dq ?                      ; cached strength/match line brushes (0=unbuilt)
g_br_amber  dq ?
g_br_lgreen dq ?
g_br_dgreen dq ?
g_reqbuf    dw 768 dup (?)            ; formatted password-requirements callout text
g_numtmp    db 16 dup (?)             ; scratch for uint-to-decimal
g_vault_lock dd ?                     ; 1 = vault path set by HKLM (locked)
g_menu_open  dd ?                     ; 1 = settings overlay is showing
g_revealed  dd ?
g_clip_seq  dd ?                      ; clipboard sequence number at last copy
g_clip_secs dd ?                      ; auto-clear timeout in seconds (0 = off); HKLM>HKCU>20
g_clip_lock dd ?                      ; 1 = clipboard timeout forced by HKLM policy
public g_pwdays
g_pwdays    dd ?                      ; C9: re-verify the master password every N days
                                      ;   under TPM Unlock (0 = off); HKLM>HKCU>30
g_pwdays_lock dd ?                    ; 1 = PwVerifyDays forced by HKLM policy
ifdef DBG_TRACE
g_pwnow_lock dd ?                     ; cfg_get_dword out-param for the dbg force switch
endif
g_idle_min  dd ?                      ; auto-lock after N idle minutes (0 = off); HKLM>HKCU>10
g_idle_lock dd ?                      ; 1 = idle timeout forced by HKLM policy
g_winlock   dd ?                      ; 1 = lock the vault when Windows locks (Win+L)
g_winlock_lock dd ?                   ; 1 = LockOnWinLock forced by HKLM policy
g_nopreview dd ?                      ; 1 = never open attachments in-place; download only
g_nopreview_lock dd ?                 ; 1 = NoPreview forced by HKLM policy
g_cf_hist   dd ?                      ; registered format: CanIncludeInClipboardHistory
g_cf_cloud  dd ?                      ; registered format: CanUploadToCloudClipboard
g_cf_excl   dd ?                      ; registered format: ExcludeClipboardContentFromMonitorProcessing
g_cur_idx   dd ?                      ; entry currently shown/edited inline (-1=none)
g_dirty     dd ?                      ; 1 = inline fields edited since last load/save
g_loading   dd ?                      ; 1 = programmatically loading fields (ignore EN_CHANGE)
g_editmode  dd ?                      ; 1 = detail fields editable (view/edit toggle)
g_new_pending dd ?                    ; 1 = current entry is a just-added placeholder (delete on Cancel)
align 8
public g_vaulthwnd
g_vaulthwnd dq ?                      ; the open DLG_VAULT window (0 when not shown)
align 2
g_search_w  dw 512 dup (?)            ; current search query (wide, upper-cased)
g_match_w   dw EBUF*2 dup (?)         ; scratch: a field value/label folded for matching
align 4
g_search_len dd ?                     ; active query length in chars (0 = no query -> title sort)
g_entry_score dd SCORE_CAP dup (?)    ; fuzzy score per vault index (for score-descending sort)
public g_vpath, g_is_default, g_vault_lock  ; live vault path / default-loc flag / share lock
g_vpath     dw 1024 dup (?)        ; chosen vault path (wide, NUL-terminated)
g_xlpw      dw 256 dup (?)         ; export password (wide; wiped after use)
g_xlpw2     dw 256 dup (?)         ; export confirm password (wide; wiped)
g_xlpwlen   dd ?                   ; export password length in bytes
public g_pwbuf, g_pw2buf, g_secret_w, g_e_totp, g_totp_b32
g_pwbuf     dw 1024 dup (?)        ; password field (wide; wiped after use)
g_pw2buf    dw 1024 dup (?)        ; confirm-password field (wide; wiped)
g_conv_w    dw CONVW_MAX dup (?)   ; utf8 -> wide display scratch (see CONVW_MAX)
g_secret_w  dw EBUF*2 dup (?)      ; current selected secret (wide) for reveal/copy
g_e_totp    dw 256 dup (?)            ; entry-form base32 TOTP key (wide)
g_totp_on   dd ?                      ; 1 if the selected entry has a TOTP key
g_totp_secs dd ?                      ; seconds left in the current TOTP window
g_totp_b32len dd ?
g_totp_b32  db 256 dup (?)            ; selected entry's base32 key (utf8)
g_totp_code6 db 8 dup (?)            ; computed 6-digit code (ascii)
g_totp_code_w dw 16 dup (?)          ; code as wide, 6 digits no space (for clipboard)
g_totp_disp_w dw 16 dup (?)          ; code grouped "nnn nnn" wide (on-screen only)
g_times_w   dw 128 dup (?)           ; "Created ... Modified ..." line (wide)
g_st        dw 8 dup (?)             ; SYSTEMTIME scratch (FileTimeToSystemTime)
g_genout    db 260 dup (?)           ; generator ASCII output (wiped after use)
g_genout_w  dw 260 dup (?)           ; generator output widened for the edit
g_readpw    dw 260 dup (?)           ; password being read out (wiped on close)
g_phon_w    dw 6144 dup (?)          ; phonetic spelling text (wiped on close)
g_urlbuf    dw 1024 dup (?)          ; URL read from a URL field for click-to-open
g_urlbuf2   dw 1040 dup (?)          ; URL with an https:// scheme prepended if bare
g_menuinfo  db 40 dup (?)            ; MENUINFO scratch for themed popup menus
align 8
g_url_origproc dq ?                  ; original EDIT wndproc (URL fields subclassed for hand cursor)
; --- modular field-row model (runtime detail form) ---
g_fields      db MAXROWS*DESCSZ dup (?)   ; row descriptors
g_field_count dd ?                        ; live row count
g_fav_state   dd ?                         ; current entry is a favorite (0/1)
g_deleted_state dd ?                       ; current entry is soft-deleted / in trash (0/1)
g_trash_view  dd ?                         ; sidebar shows the trash (deleted entries) instead
align 2
g_deleted_ft  dw 20 dup (?)                ; VF_DELETED value: 16 wide hex FILETIME + NUL
g_icon_set    dd ?                         ; current entry has a custom icon override (0/1)
g_icon_glyph  dd ?                         ; override glyph codepoint (when g_icon_set)
g_icon_color  dd ?                         ; override tile COLORREF   (when g_icon_set)
g_ovr_glyph   dd ?                         ; scratch: gui_entry_icon result glyph
g_ovr_color   dd ?                         ; scratch: gui_entry_icon result color
g_icon_valw   dw 20 dup (?)                ; scratch wide "GGGGCCCCCCCC" for saving
g_pick_glyph  dd ?                         ; icon picker working selection (glyph)
g_pick_color  dd ?                         ; icon picker working selection (color)
g_layout      dd ?                         ; UI layout/density index (0 comfortable)
public g_fontdelta
g_fontdelta   dd ?                         ; font-size delta in px (fixed 0 = Medium)
g_colorpw_row dd ?                         ; row whose revealed secret is colored (-1=none)
public g_rowpw_w
g_rowpw_w     dw 512 dup (?)               ; revealed secret text for the color overlay
g_wordtmp     dw 32 dup (?)                ; one resolved phonetic word (scratch)
g_cur_page    dd ?                        ; detail-pane current page (0-based)
g_page_count  dd ?                        ; detail-pane total pages (>=1)
align 2
g_pgbuf       dw 16 dup (?)               ; "n / m" pagination indicator text
g_dlgfont     dq ?                        ; the vault dialog's font (for runtime ctls)
g_tooltip     dq ?                        ; shared tooltip window for ghost buttons (0 = none)
public g_hk_vk
g_hk_vk       dd ?                        ; summon hotkey: virtual-key currently registered
g_hk_mods     dd ?                        ;   and its MOD_* modifiers (0/0 = none registered)
g_hk_cap_vk   dd ?                        ; capture dialog: the combo being offered
g_hk_cap_mods dd ?
g_hk_txt      dw 64 dup (?)               ; formatted combo ("Ctrl + Shift + F2")
g_totp_row    dd ?                        ; row index of the TOTP field (-1 = none)
g_totp_codehwnd dq ?                      ; live-code display control of the TOTP row
g_totp_barhwnd  dq ?                      ; drain-bar control of the TOTP row
align 8
g_iconfont    dq ?                         ; Segoe Fluent Icons for list/tile glyphs
g_welcomefont dq ?                         ; slightly larger body font for the create welcome text
g_cardfont    dq ?                         ; list entry title (semibold)
g_subfont     dq ?                         ; list entry subtitle (regular, dim)
g_titlefont   dq ?                         ; detail-header title (large semibold)
g_chevfont    dq ?                         ; small Fluent icons for flat reorder chevrons
g_monofont    dq ?                         ; monospace font for the colored password readout
g_phonfont    dq ?                         ; small monospace font for the phonetic columns
g_symfont     dq ?                         ; Segoe UI Symbol - the recycle glyph in recover mode
g_sub_w       dw 512 dup (?)               ; subtitle scratch (wide)
g_cmpbuf      db 256 dup (?)               ; title-A copy for WM_COMPAREITEM
align 2
g_imp_msgw    dw 160 dup (?)               ; import result message scratch (wide)
g_health_msgw dw 200 dup (?)               ; E6: vault-health summary scratch (wide)
g_lockmsg     dw 400 dup (?)               ; C3: seclock warning + error-code diagnostic
g_pg_len      dd ?                         ; password-generator: length
g_pg_style    dd ?                         ;   PWS_* style
g_pg_opt      dd ?                         ;   class mask + PWO_* flags
g_pg_target   dd ?                         ;   secret row to fill on "Use" (-1 = none)
g_pg_bits     dd ?                         ;   last entropy estimate
align 2
g_pg_tmpw     dw 128 dup (?)               ;   scratch for composed control text
align 4
g_tilecolor   dd ?                         ; fill color for the next tile draw
align 2
g_glyph_w     dw 2 dup (?)                 ; one glyph char + NUL
align 8
g_imgstageref db 68 dup (?)               ; scratch AttachRef from attach_stage
align 8
g_tilefiles   db MAX_TFILES*TFILE_ENTRY dup (?)  ; the attachments tile's file list
g_tilefile_n  dd ?                               ; number of files in the tile
align 8
g_field_list2 dq 3*MAX_FIELDS dup (?)            ; commit scratch: expanded field list
g_tileblob    db MAX_TFILES*336 dup (?)          ; per-file {u32 len, AttachRef, name}
align 8
public g_sel
g_sel         db MAX_SEL dup (?)                 ; export/import selection mask (1=selected)
g_sel_src     dd ?                               ; checklist source: 0 = vault (export), 1 = staged import
align 8
g_lvi         db 96 dup (?)                      ; LVITEMW/LVCOLUMNW marshalling scratch (modal, non-reentrant)
public g_pwhist, g_pwhblob, g_pworig      ; secmem.asm locks + panic-wipes these
g_pwhist      db MAX_PWHIST*PWHIST_ENTRY dup (?) ; open entry's overwritten values
g_pwhist_n    dd ?                               ; number of history entries
g_pwhblob     db MAX_PWHIST*PWHBLOB_ENTRY dup (?); per-history emit scratch (VFL_RAW)
g_pworig      db MAX_PWORIG*PWORIG_STRIDE dup (?); original {label,value} per field
g_pworig_hd   db MAX_PWORIG dup (?)              ; 1 = that field carried data at load.
                                                 ;   Kept separately because the wide copy
                                                 ;   above caps at 127 chars, so a longer
                                                 ;   value lands empty and would otherwise
                                                 ;   read back as "never had data"
g_pworig_n    dd ?
g_pwh_scroll  dd ?                               ; history browser: first visible row
g_pwh_dirty   dd ?                               ; history browser: a purge happened
align 2
g_phdate      dw 40 dup (?)                      ; history browser: formatted date scratch
g_pwh_tab     dd ?                               ; selected tab (0-based)
g_pwh_ntabs   dd ?                               ; number of distinct-label tabs
g_pwh_tabs    dd MAX_TABS dup (?)                ; each tab -> a representative g_pwhist index
g_pwh_filter  dd MAX_PWHIST dup (?)              ; g_pwhist indices belonging to the current tab
g_pwh_fn      dd ?                               ; number of rows in g_pwh_filter
align 2
g_imgfn_w     dw 200 dup (?)               ; current image's filename (wide) to store
align 8
g_storagelabel dw 300 dup (?)              ; unlock dialog: "<location> . <vault name>"
g_imgbuf      dq ?                         ; imported file bytes (mem_alloc'd)
g_imgbuflen   dq ?
g_pickfilter  dq ?                         ; OPENFILENAME filter for the next pick (0=image)
public g_settings_hwnd
g_settings_hwnd dq ?                       ; the settings child dialog (0 = not created).
                                           ;   One window to show/hide, instead of an id
                                           ;   array (docs/SETTINGS_DESIGN.md)
g_exp_iszip   dd ?                         ; export format the user chose: 0 = .vordr, 1 = .zip
                                           ;   (from the save dialog's filter index)
g_tmpfile     dw 1024 dup (?)              ; temp path for opening an attachment (wide)
align 8
g_tempfiles   db MAX_TEMPFILES*TEMPREC dup (?)  ; tracked decrypt-to-temp paths + sizes
g_tempfile_n  dd ?                         ; number of live tracked temp files
g_wipezeros   db WIPE_CHUNK dup (?)        ; source of zeros for overwriting temp files
align 2
g_imgpath     dw 1024 dup (?)             ; import/export file path (wide)
g_valblob   dw 32768 dup (?)          ; commit scratch: field values, NUL-joined
g_lblblob   dw LBLBLOB_W dup (?)      ; commit scratch: custom labels, NUL-joined
g_rlabel    dw 128 dup (?)            ; per-row label read scratch
g_grouptxt  dw 128 dup (?)            ; group-heading title read scratch (paint)
g_base_cx   dd ?                      ; vault client size recorded at init (resize anchors)
g_base_cy   dd ?
g_base_winw dd ?                      ; vault window size recorded at init (min-track size)
g_base_winh dd ?
g_anchor_rect dd ANCHOR_N*4 dup (?)   ; per-control initial client {x,y,w,h}
g_extw      dw 20 dup (?)             ; scratch: an attachment's extension, lowercased
align 8
g_ofn       OPENFILENAMEW <>

.code

; =============================================================================
; gui_towide(rcx = utf8 src, edx = len, r8 = wide dst, r9d = cap) -> eax = nwide
;   Converts `len` UTF-8 bytes to a NUL-terminated wide string in dst.  A NULL
;   src or zero len yields an empty string.
; =============================================================================
gui_towide proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], r8          ; dst (survives the call)
    test    rcx, rcx
    jz      gt_empty
    test    edx, edx
    jz      gt_empty
    WINCALL MultiByteToWideChar, CP_UTF8_, 0, rcx, edx, r8, r9d
    mov     r10, qword ptr [rbp-24]
    mov     ecx, eax
    mov     word ptr [r10+rcx*2], 0         ; NUL-terminate
    FRAME_EPILOG
    ret
gt_empty:
    mov     r10, qword ptr [rbp-24]
    mov     word ptr [r10], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_towide endp

; =============================================================================
; gui_setfield(rcx = hdlg, edx = id, r8 = utf8 src, r9 = len) - set a dialog
;   edit/static to the converted UTF-8 text (empty if src is NULL).
; =============================================================================
gui_setfield proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx         ; hdlg
    mov     dword ptr [rbp-32], edx         ; id
    ; convert into g_conv_w
    mov     rcx, r8
    mov     edx, r9d
    lea     r8, [g_conv_w]
    mov     r9d, CONVW_MAX-1
    call    gui_towide
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], dword ptr [rbp-32], addr g_conv_w
    FRAME_EPILOG
    ret
gui_setfield endp

; =============================================================================
; gui_status(rcx = hdlg, rdx = wide msg) - set the unlock dialog status line.
; =============================================================================
gui_status proc frame
    FRAME_PROLOG 32
    WINCALL SetDlgItemTextW, rcx, IDC_U_STATUS, rdx
    FRAME_EPILOG
    ret
gui_status endp

; =============================================================================
; gui_unlock(rcx = hdlg) - validate inputs, (create then) unlock the vault.
;   On success EndDialog(hdlg, 1).  On failure show a status message.
; =============================================================================
gui_unlock proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [g_use_tpm], 0        ; password path (not the TPM shortcut)
    ; R7.3: g_readonly is maintained live by the read-only pill toggle (up_ronly) and
    ; the --ro launch flag, so there is no checkbox to read back here.
    cmp     dword ptr [g_vpath_set], 0
    jne     gu_havepath
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [s_pickvault]
    call    gui_status
    jmp     gu_done
gu_havepath:
    ; read the password field
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_U_PW, addr g_pwbuf, 1024
    test    eax, eax
    jnz     gu_havepw
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [s_nopw]
    call    gui_status
    jmp     gu_done
gu_havepw:
    lea     rcx, [g_pwbuf]
    call    password_to_utf8                ; -> g_cfg_pass; wipes g_pwbuf
    test    eax, eax
    jnz     gu_pwok
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [s_badpw]
    call    gui_status
    jmp     gu_done
gu_pwok:
    lea     rax, [g_vpath]
    mov     qword ptr [g_cfg_in], rax
gu_open:
    call    vault_unlock                    ; eax = 0 / EXIT_*
    mov     dword ptr [rbp-32], eax
    lea     rcx, [ev_unlock]                ; C5: audit the unlock outcome
    mov     edx, eax
    call    log_result
    call    gui_wipepw
    cmp     dword ptr [rbp-32], 0
    jne     gu_fail
    ; anti-rollback: this vault is older than the last one saved on this machine
    cmp     dword ptr [g_rollback], 0
    je      gu_norb
    WINCALL gui_msgbox, qword ptr [rbp-24], addr s_rollback, addr t_rbtitle, \
            <MB_YESNO or MB_ICONWARNING>
    cmp     eax, IDYES
    je      gu_norb
    call    vault_lock                      ; user declined -> lock and stay on the dialog
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [s_rbabort]
    call    gui_status
    jmp     gu_done
gu_norb:
    ; first opened the auto-default vault -> record its path in HKCU
    cmp     dword ptr [g_is_default], 0
    je      gu_success
    lea     rcx, [g_vpath]
    call    reg_save_vault
    mov     dword ptr [g_is_default], 0
gu_success:
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_U_PW, 0
    WINCALL EndDialog, qword ptr [rbp-24], 1
    jmp     gu_done
gu_fail:
    mov     eax, dword ptr [rbp-32]
    lea     rdx, [s_io]
    cmp     eax, EXIT_LOCKED
    jne     @F
    lea     rdx, [s_wrongpw]
@@: cmp     eax, EXIT_CORRUPT
    jne     @F
    lea     rdx, [s_corrupt]
@@: mov     rcx, qword ptr [rbp-24]
    call    gui_status
gu_done:
    FRAME_EPILOG
    ret
gui_unlock endp

; gui_wipepw() - scrub the UTF-8 master password buffer.
; gui_num_msg(rcx = wide prefix, edx = number) -> rax = the composed wide string.
;   Appends " <n>" to the prefix in g_errbuf.  There is no wide number formatter
;   anywhere else in the codebase, and log_result deliberately maps codes to fixed
;   text rather than printing them - so a failure that only the user can reproduce
;   had no way to carry its Win32 error back to us.  That is what turned one I/O
;   error into two rounds of guesswork.
; gui_exe_dir(rcx = dst wide, edx = cap chars) -> eax = 1 ok.  The directory the
;   running binary sits in, with the filename stripped.
gui_exe_dir proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    WINCALL GetModuleFileNameW, 0, qword ptr [rbp-24], dword ptr [rbp-32]
    test    eax, eax
    jz      gxd_fail
    mov     r10, qword ptr [rbp-24]
    xor     r8d, r8d
    mov     r9d, -1
gxd_scan:
    movzx   ecx, word ptr [r10+r8*2]
    test    ecx, ecx
    jz      gxd_cut
    cmp     ecx, 5Ch
    jne     @F
    mov     r9d, r8d
@@: inc     r8d
    jmp     gxd_scan
gxd_cut:
    cmp     r9d, 0
    jle     gxd_fail
    movsxd  r11, r9d
    mov     word ptr [r10+r11*2], 0             ; strip "ordr.exe"
    mov     eax, 1
    FRAME_EPILOG
    ret
gxd_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_exe_dir endp

; gui_path_under(rcx = path, rdx = dir) -> eax = 1 if path lies inside dir.
;   Case-folded ASCII, same rule as cfg_wstr_ieq; requires a separator (or the end
;   of the string) right after dir, so "...\VordrData" is not "inside" "...\Vordr".
;   Leaf proc.
gui_path_under proc
gpu_lp:
    movzx   r10d, word ptr [rdx]
    test    r10d, r10d
    jz      gpu_diroff
    movzx   eax, word ptr [rcx]
    test    eax, eax
    jz      gpu_no
    lea     r11d, [rax-'A']
    cmp     r11d, 25
    ja      @F
    add     eax, 32
@@: lea     r11d, [r10-'A']
    cmp     r11d, 25
    ja      @F
    add     r10d, 32
@@: cmp     eax, r10d
    jne     gpu_no
    add     rcx, 2
    add     rdx, 2
    jmp     gpu_lp
gpu_diroff:
    movzx   eax, word ptr [rcx]
    test    eax, eax
    jz      gpu_yes
    cmp     eax, 5Ch
    je      gpu_yes
gpu_no:
    xor     eax, eax
    ret
gpu_yes:
    mov     eax, 1
    ret
gui_path_under endp

; gui_vault_initdir() -> rax = an EXISTING folder for the picker to open in, or 0.
;   Without this the dialog only gets lpstrFile, and Windows silently falls back to
;   the process's current directory when that file's folder is missing - which is how
;   a vault ended up proposed inside the program's own install folder.
gui_vault_initdir proc frame
    FRAME_PROLOG 64
    lea     r10, [g_initdir]                    ; try the configured vault's folder
    lea     r11, [g_vpath]
    xor     r8d, r8d
gvi_cpy:
    mov     ax, word ptr [r11+r8*2]
    mov     word ptr [r10+r8*2], ax
    test    ax, ax
    jz      gvi_cut
    inc     r8d
    cmp     r8d, 1000
    jb      gvi_cpy
gvi_cut:
    lea     r10, [g_initdir]
    mov     r9d, -1
    xor     r8d, r8d
gvi_scan:
    movzx   ecx, word ptr [r10+r8*2]
    test    ecx, ecx
    jz      gvi_trim
    cmp     ecx, 5Ch
    jne     @F
    mov     r9d, r8d
@@: inc     r8d
    jmp     gvi_scan
gvi_trim:
    cmp     r9d, 0
    jle     gvi_default
    movsxd  r11, r9d
    mov     word ptr [r10+r11*2], 0
    WINCALL GetFileAttributesW, addr g_initdir
    cmp     eax, -1
    je      gvi_default
    test    eax, 10h                            ; FILE_ATTRIBUTE_DIRECTORY
    jz      gvi_default
    lea     rax, [g_initdir]
    FRAME_EPILOG
    ret
gvi_default:
    ; no usable folder -> derive the default one (which creates it) and use that
    lea     rcx, [g_initdir]
    call    cfg_default_vault
    test    eax, eax
    jz      gvi_none
    lea     r10, [g_initdir]
    mov     r9d, -1
    xor     r8d, r8d
gvi_scan2:
    movzx   ecx, word ptr [r10+r8*2]
    test    ecx, ecx
    jz      gvi_trim2
    cmp     ecx, 5Ch
    jne     @F
    mov     r9d, r8d
@@: inc     r8d
    jmp     gvi_scan2
gvi_trim2:
    cmp     r9d, 0
    jle     gvi_none
    movsxd  r11, r9d
    mov     word ptr [r10+r11*2], 0
    lea     rax, [g_initdir]
    FRAME_EPILOG
    ret
gvi_none:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_vault_initdir endp

; gui_exe_dir_check() -> eax = 1 to proceed, 0 if the user declined.
;   A vault inside the program's own folder is almost never deliberate: it is what
;   you get when the file picker falls back to the current directory.  On this
;   machine that was a build output folder; elsewhere it is Downloads, a temp
;   extract, or a USB stick.  Warn once, default to No, and let a deliberate
;   portable install through.
gui_exe_dir_check proc frame
    FRAME_PROLOG 48
    lea     rcx, [g_exedir]
    mov     edx, 1000
    call    gui_exe_dir
    test    eax, eax
    jnz     gedc_have
    mov     eax, 1                              ; cannot tell -> do not block
    FRAME_EPILOG
    ret
gedc_have:
    lea     rcx, [g_vpath]
    lea     rdx, [g_exedir]
    call    gui_path_under
    test    eax, eax
    jz      gedc_ok
    WINCALL gui_msgbox, qword ptr [g_vaulthwnd], addr m_exedir, addr t_exedir,             <MB_YESNO or MB_ICONWARNING or MB_DEFBUTTON2>
    cmp     eax, IDYES
    jne     gedc_no
gedc_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
gedc_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_exe_dir_check endp

; =============================================================================
; The home panel - what the detail pane shows when nothing is selected.
;
; Four stat tiles from vault_health {weak, reused, old, total}, then a line of
; plain English.  Painted onto the erased background from vp_terase, alongside the
; field cards, so it picks up the active scheme's colours for free.
;
; vault_health walks every entry and runs a duplicate pass, so the result is
; CACHED: WM_ERASEBKGND fires on every repaint and resize, and rescanning a large
; vault there would make dragging the window crawl.  gui_poplist invalidates it -
; that is the funnel every add / edit / delete / trash change already goes through.
; =============================================================================
HOME_PAD   equ 18                        ; inset from the detail-pane edges (px)
HOME_GAP   equ 12                        ; gap between tiles (px)
HOME_TILEH equ 76                        ; tile height (px)
HOME_R     equ 10                        ; tile corner radius (px)

; home_num(ecx = value) -> rax = g_home_numw as wide decimal.  Leaf, no allocation.
home_num proc frame
    FRAME_PROLOG 64                      ; [rbp-48] = digit scratch (no calls inside)
    mov     dword ptr [rbp-24], ecx
    mov     eax, dword ptr [rbp-24]
    lea     r9, [rbp-48]
    xor     ecx, ecx
    mov     r11d, 10
hn_div:
    xor     edx, edx
    div     r11d
    add     dl, 30h
    mov     byte ptr [r9+rcx], dl
    inc     rcx
    test    eax, eax
    jnz     hn_div
    lea     r10, [g_home_numw]
    xor     r8, r8
hn_emit:
    dec     rcx
    movzx   eax, byte ptr [r9+rcx]
    mov     word ptr [r10+r8*2], ax
    inc     r8
    test    rcx, rcx
    jnz     hn_emit
    mov     word ptr [r10+r8*2], 0
    lea     rax, [g_home_numw]
    FRAME_EPILOG
    ret
home_num endp

; home_tile(rcx=hdc, rdx=*rect{L,T,R,B}, r8d=value, r9=label) - one tile: rounded
;   panel, the count large, the label dimmed beneath it.  A non-zero count is drawn
;   in the accent colour only when g_home_alert is set, so the plain totals never
;   shout and a genuine finding stands out.
home_tile proc frame
    FRAME_PROLOG 192                     ; RoundRect spills 7 args, DrawTextW 5
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     dword ptr [rbp-40], r8d
    mov     qword ptr [rbp-48], r9
    mov     r10, qword ptr [rbp-32]
    mov     eax, dword ptr [r10+0]
    mov     dword ptr [rbp-88], eax
    mov     eax, dword ptr [r10+4]
    mov     dword ptr [rbp-92], eax
    mov     eax, dword ptr [r10+8]
    mov     dword ptr [rbp-96], eax
    mov     eax, dword ptr [r10+12]
    mov     dword ptr [rbp-100], eax
    WINCALL CreateSolidBrush, dword ptr [g_col_panel]
    mov     qword ptr [rbp-56], rax
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-56]
    mov     qword ptr [rbp-64], rax
    WINCALL GetStockObject, 8            ; NULL_PEN
    mov     qword ptr [rbp-72], rax
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-72]
    mov     qword ptr [rbp-80], rax
    WINCALL RoundRect, qword ptr [rbp-24], dword ptr [rbp-88], dword ptr [rbp-92], \
            dword ptr [rbp-96], dword ptr [rbp-100], HOME_R, HOME_R
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-64]
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-80]
    WINCALL DeleteObject, qword ptr [rbp-56]
    WINCALL SetBkMode, qword ptr [rbp-24], 1          ; TRANSPARENT
    mov     eax, dword ptr [g_col_text]
    cmp     dword ptr [g_home_alert], 0
    je      ht_col
    cmp     dword ptr [rbp-40], 0
    je      ht_col
    mov     eax, dword ptr [g_col_accent]
ht_col:
    mov     dword ptr [rbp-132], eax
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [rbp-132]
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [g_titlefont]
    mov     qword ptr [rbp-108], rax                  ; old font
    mov     eax, dword ptr [rbp-88]                   ; number rect, inset in the tile
    add     eax, 14
    mov     dword ptr [rbp-128], eax
    mov     eax, dword ptr [rbp-92]
    add     eax, 10
    mov     dword ptr [rbp-124], eax
    mov     eax, dword ptr [rbp-96]
    sub     eax, 10
    mov     dword ptr [rbp-120], eax
    mov     eax, dword ptr [rbp-124]
    add     eax, 34
    mov     dword ptr [rbp-116], eax
    mov     ecx, dword ptr [rbp-40]
    call    home_num
    mov     qword ptr [rbp-136], rax
    WINCALL DrawTextW, qword ptr [rbp-24], qword ptr [rbp-136], -1, addr rbp-128, \
            DT_NAMEFLAGS
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [g_subfont]
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_textdim]
    mov     eax, dword ptr [rbp-116]                  ; label sits under the number
    mov     dword ptr [rbp-124], eax
    add     eax, 22
    mov     dword ptr [rbp-116], eax
    WINCALL DrawTextW, qword ptr [rbp-24], qword ptr [rbp-48], -1, addr rbp-128, \
            DT_NAMEFLAGS
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-108]
    FRAME_EPILOG
    ret
home_tile endp

; gui_draw_home(rcx = hdc, rdx = hdlg) - the panel.  No-op unless the detail pane
;   is genuinely idle.
public gui_draw_home
gui_draw_home proc frame
    FRAME_PROLOG 288
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    cmp     dword ptr [g_cur_idx], 0             ; an entry is showing -> cards own the pane
    jge     gdh_ret
    cmp     dword ptr [g_menu_open], 0           ; settings covers it
    jne     gdh_ret
    cmp     dword ptr [g_trash_view], 0          ; the trash has its own idea of "empty"
    jne     gdh_ret
    cmp     dword ptr [g_home_valid], 0
    jne     gdh_have
    lea     rcx, [g_home_stats]
    call    vault_health
    mov     dword ptr [g_home_valid], 1
gdh_have:
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [rbp-64]                        ; sidebar frame {L,T,R,B}
    call    sidebar_rect
    WINCALL GetClientRect, qword ptr [rbp-32], addr rbp-96
    mov     eax, dword ptr [rbp-56]              ; pane L = sidebar R + pad
    add     eax, HOME_PAD
    mov     dword ptr [rbp-104], eax
    mov     eax, dword ptr [rbp-60]              ; pane T = sidebar T + pad
    add     eax, HOME_PAD
    mov     dword ptr [rbp-108], eax
    mov     eax, dword ptr [rbp-88]              ; pane R = client right - pad
    sub     eax, HOME_PAD
    mov     dword ptr [rbp-112], eax
    mov     eax, dword ptr [rbp-112]             ; too narrow to lay out -> draw nothing
    sub     eax, dword ptr [rbp-104]
    cmp     eax, 200
    jl      gdh_ret
    WINCALL SetBkMode, qword ptr [rbp-24], 1
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_text]
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [g_titlefont]
    mov     qword ptr [rbp-120], rax
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-160], eax
    mov     eax, dword ptr [rbp-108]
    mov     dword ptr [rbp-156], eax
    mov     eax, dword ptr [rbp-112]
    mov     dword ptr [rbp-152], eax
    mov     eax, dword ptr [rbp-156]
    add     eax, 32
    mov     dword ptr [rbp-148], eax
    WINCALL DrawTextW, qword ptr [rbp-24], addr h_title, -1, addr rbp-160, DT_NAMEFLAGS
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-120]
    mov     eax, dword ptr [rbp-112]             ; tileW = (paneW - gap) / 2
    sub     eax, dword ptr [rbp-104]
    sub     eax, HOME_GAP
    shr     eax, 1
    mov     dword ptr [rbp-144], eax
    mov     eax, dword ptr [rbp-148]             ; first tile row under the heading
    add     eax, 14
    mov     dword ptr [rbp-140], eax
    ; ---- row 1 : total | weak ---------------------------------------------
    mov     dword ptr [g_home_alert], 0
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-192], eax
    mov     eax, dword ptr [rbp-140]
    mov     dword ptr [rbp-188], eax
    mov     eax, dword ptr [rbp-192]
    add     eax, dword ptr [rbp-144]
    mov     dword ptr [rbp-184], eax
    mov     eax, dword ptr [rbp-188]
    add     eax, HOME_TILEH
    mov     dword ptr [rbp-180], eax
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [rbp-192]
    mov     r8d, dword ptr [g_home_stats+12]
    lea     r9, [h_secrets]
    call    home_tile
    mov     dword ptr [g_home_alert], 1
    mov     eax, dword ptr [rbp-184]
    add     eax, HOME_GAP
    mov     dword ptr [rbp-192], eax
    mov     eax, dword ptr [rbp-112]
    mov     dword ptr [rbp-184], eax
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [rbp-192]
    mov     r8d, dword ptr [g_home_stats+0]
    lea     r9, [h_weak]
    call    home_tile
    ; ---- row 2 : reused | ageing ------------------------------------------
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-192], eax
    add     eax, dword ptr [rbp-144]
    mov     dword ptr [rbp-184], eax
    mov     eax, dword ptr [rbp-140]
    add     eax, HOME_TILEH
    add     eax, HOME_GAP
    mov     dword ptr [rbp-188], eax
    add     eax, HOME_TILEH
    mov     dword ptr [rbp-180], eax
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [rbp-192]
    mov     r8d, dword ptr [g_home_stats+4]
    lea     r9, [h_reused]
    call    home_tile
    mov     eax, dword ptr [rbp-184]
    add     eax, HOME_GAP
    mov     dword ptr [rbp-192], eax
    mov     eax, dword ptr [rbp-112]
    mov     dword ptr [rbp-184], eax
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [rbp-192]
    mov     r8d, dword ptr [g_home_stats+8]
    lea     r9, [h_ageing]
    call    home_tile
    mov     dword ptr [g_home_alert], 0
    ; ---- where this vault lives, directly under the tiles ------------------
    ; Same glyph + label as the unlock screen (gui_storage_parts), so the two
    ; screens can never describe the vault's location differently.
    lea     rcx, [rbp-200]                       ; glyph out
    lea     rdx, [rbp-208]                       ; label out
    call    gui_storage_parts
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-160], eax
    mov     eax, dword ptr [rbp-180]             ; bottom of the tile grid
    add     eax, 18
    mov     dword ptr [rbp-156], eax
    mov     eax, dword ptr [rbp-112]
    mov     dword ptr [rbp-152], eax
    mov     eax, dword ptr [rbp-156]
    add     eax, 22
    mov     dword ptr [rbp-148], eax
    mov     eax, dword ptr [rbp-104]             ; label starts right of the glyph
    add     eax, 20
    mov     dword ptr [rbp-216], eax
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_accent]
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [g_font_icon]
    mov     qword ptr [rbp-224], rax             ; old font
    WINCALL DrawTextW, qword ptr [rbp-24], qword ptr [rbp-200], -1, addr rbp-160, \
            DT_NAMEFLAGS
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-224]
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [g_subfont]
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_textdim]
    mov     eax, dword ptr [rbp-216]
    mov     dword ptr [rbp-160], eax
    WINCALL DrawTextW, qword ptr [rbp-24], qword ptr [rbp-208], -1, addr rbp-160, \
            DT_NAMEFLAGS
    ; ---- the verdict, one step louder than everything else -----------------
    ; g_cardfont is -14 semibold against g_subfont's -12 regular: the line that
    ; tells you whether anything needs doing should not be the quietest on the
    ; panel, but it is still a sentence, not a headline.
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-160], eax
    mov     eax, dword ptr [rbp-148]
    add     eax, 14
    mov     dword ptr [rbp-156], eax
    add     eax, 24
    mov     dword ptr [rbp-148], eax
    cmp     dword ptr [g_home_stats+12], 0
    jne     gdh_vpick
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_textdim]
    lea     rax, [h_empty]                       ; empty vault: say how to start
    mov     qword ptr [rbp-168], rax
    jmp     gdh_vdraw
gdh_vpick:
    mov     eax, dword ptr [g_home_stats+0]
    add     eax, dword ptr [g_home_stats+4]
    add     eax, dword ptr [g_home_stats+8]
    test    eax, eax
    jz      gdh_clear
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_accent]
    lea     rax, [h_attention]
    jmp     gdh_vset
gdh_clear:
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_textdim]
    lea     rax, [h_allclear]
gdh_vset:
    mov     qword ptr [rbp-168], rax
gdh_vdraw:
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [g_cardfont]
    mov     qword ptr [rbp-232], rax
    WINCALL DrawTextW, qword ptr [rbp-24], qword ptr [rbp-168], -1, addr rbp-160, \
            DT_NAMEFLAGS
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-232]
    ; ---- what the launch gate verified -------------------------------------
    ; g_kat_n is counted by the gate itself, not written down here, so this stays
    ; true when a vector is added.
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_textdim]
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-160], eax
    mov     eax, dword ptr [rbp-148]
    add     eax, 12
    mov     dword ptr [rbp-156], eax
    add     eax, 20
    mov     dword ptr [rbp-148], eax
    mov     ecx, dword ptr [g_kat_n]
    call    home_num
    mov     qword ptr [rbp-240], rax
    lea     rcx, [g_katline]
    mov     rdx, qword ptr [rbp-240]
    call    gui_wstrcpy
    mov     rcx, rax
    lea     rdx, [h_kat_suf]
    call    gui_wstrcpy
    WINCALL DrawTextW, qword ptr [rbp-24], addr g_katline, -1, addr rbp-160, \
            DT_NAMEFLAGS
    mov     eax, dword ptr [rbp-148]
    mov     dword ptr [rbp-156], eax
    add     eax, 20
    mov     dword ptr [rbp-148], eax
    WINCALL DrawTextW, qword ptr [rbp-24], addr h_kat_std, -1, addr rbp-160, \
            DT_NAMEFLAGS
gdh_font:
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-120]
gdh_ret:
    FRAME_EPILOG
    ret
gui_draw_home endp

gui_num_msg proc frame
    FRAME_PROLOG 96                          ; [rbp-80] = digit scratch (no calls inside)
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    lea     r10, [g_errbuf]
    mov     r11, qword ptr [rbp-24]
    xor     r8, r8
gnm_cpy:
    mov     ax, word ptr [r11+r8*2]
    test    ax, ax
    jz      gnm_sep
    mov     word ptr [r10+r8*2], ax
    inc     r8
    cmp     r8, 200                          ; leave room for the number + NUL
    jb      gnm_cpy
gnm_sep:
    mov     word ptr [r10+r8*2], 20h         ; space
    inc     r8
    mov     eax, dword ptr [rbp-32]          ; decimal digits, least significant first
    lea     r9, [rbp-80]
    xor     ecx, ecx
    mov     r11d, 10
gnm_div:
    xor     edx, edx                         ; EDX:EAX / 10 -> EAX rem EDX
    div     r11d
    add     dl, 30h
    mov     byte ptr [r9+rcx], dl
    inc     rcx
    test    eax, eax
    jnz     gnm_div
gnm_emit:                                    ; ...then reversed into the message
    dec     rcx
    movzx   eax, byte ptr [r9+rcx]
    mov     word ptr [r10+r8*2], ax
    inc     r8
    test    rcx, rcx
    jnz     gnm_emit
    mov     word ptr [r10+r8*2], 0
    lea     rax, [g_errbuf]
    FRAME_EPILOG
    ret
gui_num_msg endp

gui_wipepw proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_cfg_pass]
    mov     edx, MAX_PASSWORD_BYTES+1
    call    secure_zero
    FRAME_EPILOG
    ret
gui_wipepw endp

; gui_set_winicon(rcx=hwnd) - give a top-level window the Vordr shield in its
;   title bar (small 16x16 for the caption, default size for Alt-Tab).
gui_set_winicon proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    WINCALL LoadImageW, qword ptr [g_hinst], 1, 1, 16, 16, 0
    mov     qword ptr [rbp-32], rax
    WINCALL SendMessageW, qword ptr [rbp-24], 80h, 0, qword ptr [rbp-32]   ; WM_SETICON ICON_SMALL
    WINCALL LoadIconW, qword ptr [g_hinst], 1
    mov     qword ptr [rbp-32], rax
    WINCALL SendMessageW, qword ptr [rbp-24], 80h, 1, qword ptr [rbp-32]   ; WM_SETICON ICON_BIG
    FRAME_EPILOG
    ret
gui_set_winicon endp

; =============================================================================
; gui_draw_storage(rcx=lpdis) - paint the unlock dialog's storage-location button
;   as an icon + friendly name: OneDrive / Documents (when the vault lives there)
;   else the full path, drawn in the accent colour to read as a clickable link.
; =============================================================================
; gui_storage_parts(rcx = *out glyph ptr, rdx = *out label ptr) -> eax = class
;   (0 = OneDrive, 1 = Documents, 2 = other).  Where the vault lives, rendered the
;   way the unlock screen renders it: a Fluent glyph plus either "<folder> . <vault
;   file>" for the two friendly locations, or the full path for anywhere else.
;
;   Factored out rather than copied when the home panel needed the same line - two
;   descriptions of where the vault is would eventually disagree, and the one on
;   the unlock screen is the one people check before typing a master password.
public gui_storage_parts
gui_storage_parts proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx           ; *out glyph
    mov     qword ptr [rbp-32], rdx           ; *out label
    lea     rcx, [g_vpath]                    ; classify: 0 OneDrive / 1 Documents / 2 other
    call    cfg_classify_path
    mov     dword ptr [rbp-40], eax
    lea     r8, [gl_cloud]
    lea     r9, [st_onedrive]
    cmp     eax, 0
    je      gsp2_have
    cmp     eax, 1
    jne     gsp2_other
    lea     r8, [gl_doc]
    lea     r9, [st_documents]
    jmp     gsp2_have
gsp2_other:
    lea     r8, [gl_folder]
    lea     r9, [g_vpath]
gsp2_have:
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [r10], r8               ; glyph
    mov     r10, qword ptr [rbp-32]
    mov     qword ptr [r10], r9               ; label (default)
    ; A friendly location names only the folder, so append the vault file name -
    ; otherwise it never says WHICH vault.  'other' is already a full path ending
    ; in the file name.
    cmp     dword ptr [rbp-40], 2
    jae     gsp2_done
    mov     qword ptr [rbp-48], r9            ; survives the wstrcpy calls
    lea     rcx, [g_storagelabel]
    mov     rdx, qword ptr [rbp-48]
    call    gui_wstrcpy
    mov     rcx, rax
    lea     rdx, [s_stor_sep]                 ; " . "
    call    gui_wstrcpy
    mov     qword ptr [rbp-56], rax           ; append point
    lea     r10, [g_vpath]                    ; basename = text after the last \ or /
    mov     r11, r10
gsp2_bn:
    movzx   edx, word ptr [r10]
    test    edx, edx
    jz      gsp2_bn_done
    cmp     edx, '\'
    je      gsp2_bn_sep
    cmp     edx, '/'
    jne     gsp2_bn_next
gsp2_bn_sep:
    lea     r11, [r10+2]
gsp2_bn_next:
    add     r10, 2
    jmp     gsp2_bn
gsp2_bn_done:
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, r11
    call    gui_wstrcpy
    lea     rax, [g_storagelabel]
    mov     r10, qword ptr [rbp-32]
    mov     qword ptr [r10], rax              ; the combined label
gsp2_done:
    mov     eax, dword ptr [rbp-40]
    FRAME_EPILOG
    ret
gui_storage_parts endp

gui_draw_storage proc frame
    FRAME_PROLOG 160
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax           ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-80], eax           ; rc L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-76], eax           ; T
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-72], eax           ; R
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-68], eax           ; B
    WINCALL CreateSolidBrush, dword ptr [g_col_bg]
    mov     qword ptr [rbp-40], rax
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-80, qword ptr [rbp-40]
    WINCALL DeleteObject, qword ptr [rbp-40]
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    lea     rcx, [rbp-48]                     ; glyph out
    lea     rdx, [rbp-56]                     ; label out
    call    gui_storage_parts
    mov     dword ptr [rbp-88], eax           ; keep the classification
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_accent]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_font_icon]
    mov     qword ptr [rbp-64], rax           ; old font
    mov     eax, dword ptr [rbp-80]
    mov     dword ptr [rbp-120], eax          ; glyph rect L
    mov     eax, dword ptr [rbp-76]
    mov     dword ptr [rbp-116], eax
    mov     eax, dword ptr [rbp-80]
    add     eax, 18
    mov     dword ptr [rbp-112], eax
    mov     eax, dword ptr [rbp-68]
    mov     dword ptr [rbp-108], eax
    WINCALL DrawTextW, qword ptr [rbp-32], qword ptr [rbp-48], -1, addr rbp-120, 24h
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-64]   ; restore font
    mov     eax, dword ptr [rbp-80]           ; label rect: [L+20 .. R]
    add     eax, 20
    mov     dword ptr [rbp-120], eax
    mov     eax, dword ptr [rbp-76]
    mov     dword ptr [rbp-116], eax
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [rbp-112], eax
    mov     eax, dword ptr [rbp-68]
    mov     dword ptr [rbp-108], eax
    WINCALL DrawTextW, qword ptr [rbp-32], qword ptr [rbp-56], -1, addr rbp-120, 8024h
    mov     eax, 1
    FRAME_EPILOG
    ret
gui_draw_storage endp

; gui_pick_vault(rcx=hdlg) - browse for a vault file (opening at the current
;   vault's folder); on selection update g_vpath + create/open state and repaint
;   the storage-location button.
gui_pick_vault proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    lea     rcx, [g_ofn]
    mov     edx, sizeof OPENFILENAMEW
    call    secure_zero
    lea     r10, [g_ofn]
    mov     dword ptr [r10].OPENFILENAMEW.lStructSize, sizeof OPENFILENAMEW
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [r10].OPENFILENAMEW.hwndOwner, rax
    lea     rax, [g_vaultfilter]
    mov     qword ptr [r10].OPENFILENAMEW.lpstrFilter, rax
    lea     rax, [g_vpath]                    ; prefilled -> dialog opens at its folder
    mov     qword ptr [r10].OPENFILENAMEW.lpstrFile, rax
    mov     dword ptr [r10].OPENFILENAMEW.nMaxFile, 1024
    mov     dword ptr [r10].OPENFILENAMEW.nFilterIndex, 1
    mov     dword ptr [r10].OPENFILENAMEW.Flags, OFN_PATHMUSTEXIST or OFN_HIDEREADONLY or OFN_EXPLORER
    call    gui_vault_initdir                 ; never let comdlg32 fall back to the CWD
    test    rax, rax                          ;   (= the program folder) when the vault's
    jz      @F                                ;   own folder is missing
    lea     r10, [g_ofn]
    mov     qword ptr [r10].OPENFILENAMEW.lpstrInitialDir, rax
@@: WINCALL GetOpenFileNameW, addr g_ofn
    test    eax, eax
    jz      gpv_done                           ; cancelled -> keep the old path
    mov     dword ptr [g_vpath_set], 1
    lea     rcx, [g_vpath]                     ; file present -> open; absent -> create
    call    gui_file_exists
    mov     dword ptr [rbp-32], eax
    xor     edx, edx
    test    eax, eax
    jnz     @F
    mov     edx, 1
@@: mov     dword ptr [g_create], edx
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_U_PATH
    WINCALL InvalidateRect, rax, 0, 1
gpv_done:
    FRAME_EPILOG
    ret
gui_pick_vault endp

; =============================================================================
; unlock_proc - DLG_UNLOCK dialog procedure (raw frame; OS callback).
; rcx=hdlg rdx=msg r8=wParam r9=lParam -> rax = BOOL handled
; =============================================================================
unlock_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64                         ; [rbp-8]=hdlg + shadow
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      up_init
    cmp     rdx, WM_COMMAND
    je      up_cmd
    cmp     rdx, WM_PAINT
    je      up_tpaint
    cmp     rdx, WM_ERASEBKGND
    je      up_terase
    cmp     rdx, WM_DRAWITEM
    je      up_tdraw
    cmp     rdx, WM_CTLCOLOREDIT
    je      up_tcolor
    cmp     rdx, WM_CTLCOLORLISTBOX
    je      up_tcolor
    cmp     rdx, WM_CTLCOLORBTN
    je      up_tcolor
    cmp     rdx, WM_CTLCOLORDLG
    je      up_tcolor
    cmp     rdx, WM_CTLCOLORSTATIC
    je      up_tcolor
    xor     eax, eax
    jmp     up_ret
up_tcolor:
    call    theme_ctlcolor
    jmp     up_ret
up_tpaint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     up_ret
up_terase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     up_ret
up_tdraw:
    mov     r10, r9
    cmp     dword ptr [r10+4], IDC_U_PATH        ; storage-location button: icon + name
    je      up_tdraw_path
    cmp     dword ptr [r10+4], IDC_U_RONLY       ; R7.3: read-only = Fluent pill toggle
    je      up_tdraw_ronly
    jmp     up_tdraw_def
up_tdraw_path:
    mov     rcx, r9
    call    gui_draw_storage
    mov     eax, 1
    jmp     up_ret
up_tdraw_ronly:
    mov     rcx, r9
    mov     edx, dword ptr [g_readonly]
    call    theme_toggle
    mov     eax, 1
    jmp     up_ret
up_tdraw_def:
    mov     rcx, r9
    call    theme_drawitem
    jmp     up_ret
up_tunh:
    xor     eax, eax
    jmp     up_ret
up_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_U_UNLOCK
    call    theme_attach
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    ; R7.1: the misplaced per-dialog theme cogwheel (id 990) is gone - theme switching
    ; lives in the settings menu (IDC_V_MTHEME) and the title-bar dock (IDC_T_SET).
    ; cue-banner label shown inside the (borderless) password box
    sub     rsp, 48
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_U_PW
    mov     r8d, EM_SETCUEBANNER
    mov     r9d, 1
    lea     rax, [cue_pw]
    mov     qword ptr [rsp+32], rax
    call    SendDlgItemMessageW
    add     rsp, 48
    sub     rsp, 32
    cmp     dword ptr [g_vpath_set], 0
    je      up_init_x
    mov     rcx, qword ptr [rbp-8]           ; show the resolved vault path
    mov     edx, IDC_U_PATH
    lea     r8, [g_vpath]
    call    SetDlgItemTextW
up_init_x:
    add     rsp, 32
    ; R7.3: the read-only pill paints straight from g_readonly (which the --ro launch
    ; flag already set), so there is no checkbox to seed here.
    mov     eax, 1
    jmp     up_ret
up_cmd:
    mov     r10d, r8d
    shr     r10d, 16                        ; HIWORD(wParam) = notification
    cmp     r10d, EN_SETFOCUS               ; redraw Fluent underline on focus change
    je      up_refocus
    cmp     r10d, EN_KILLFOCUS
    je      up_refocus
    movzx   eax, r8w                        ; LOWORD(wParam) = control id
    cmp     eax, IDC_U_UNLOCK
    je      up_unlock
    cmp     eax, IDC_U_PATH                 ; click the storage location -> browse
    je      up_pickvault
    cmp     eax, IDC_U_RONLY               ; R7.3: click the read-only pill -> flip + repaint
    je      up_ronly
    cmp     eax, IDCANCEL
    je      up_cancel
    xor     eax, eax
    jmp     up_ret
up_ronly:
    xor     dword ptr [g_readonly], 1
    sub     rsp, 48
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_U_RONLY
    call    GetDlgItem
    mov     rcx, rax
    xor     edx, edx
    mov     r8d, 1
    call    InvalidateRect
    add     rsp, 48
    mov     eax, 1
    jmp     up_ret
up_pickvault:
    mov     rcx, qword ptr [rbp-8]
    call    gui_pick_vault
    mov     eax, 1
    jmp     up_ret
up_refocus:
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    xor     edx, edx
    mov     r8d, 1
    call    InvalidateRect
    add     rsp, 32
    mov     eax, 1
    jmp     up_ret
up_unlock:
    mov     rcx, qword ptr [rbp-8]
    call    gui_unlock
    mov     eax, 1
    jmp     up_ret
up_cancel:
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    xor     edx, edx
    call    EndDialog
    add     rsp, 32
    mov     eax, 1
up_ret:
    mov     rsp, rbp
    pop     rbp
    ret
unlock_proc endp

; =============================================================================
; gui_poplist(rcx = hdlg) - clear and repopulate the entry list from the vault.
; =============================================================================
gui_poplist proc frame
    mov     dword ptr [g_home_valid], 0   ; the entry set changed -> restat on next paint
    FRAME_PROLOG 32                              ; single-vault: fill IDC_V_LIST from the one
    mov     edx, IDC_V_LIST                      ; open vault, filtered by the sidebar search box
    mov     r8d, IDC_V_SEARCH                    ; (empty box -> shows every entry)
    call    poplist_into
    FRAME_EPILOG
    ret
gui_poplist endp

; poplist_into(rcx=hdlg, edx=listId, r8d=queryEditId) - clear & fuzzy-fill an
;   owner-draw entry list from the vault, reading the query from queryEditId.
;   Backs both the sidebar (IDC_V_LIST/IDC_V_SEARCH) and the search overlay.
poplist_into proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-64], edx              ; listId
    mov     dword ptr [rbp-68], r8d              ; queryId
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], dword ptr [rbp-64], LB_RESETCONTENT, 0, 0
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], dword ptr [rbp-68], addr g_search_w, 255
    mov     dword ptr [rbp-56], eax              ; query length (chars)
    mov     dword ptr [g_search_len], eax        ; publish for the score-aware sort
    test    eax, eax
    jz      pi_nofold
    WINCALL CharUpperBuffW, addr g_search_w, dword ptr [rbp-56]
pi_nofold:
    call    vault_count
    mov     dword ptr [rbp-32], eax              ; count
    ; pre-allocate the listbox's internal item storage so a 5000-entry bulk fill
    ; does not repeatedly reallocate (large-vault sidebar work).  The
    ; owner-draw listbox already virtualizes painting; this just speeds the load.
    mov     r10d, eax
    imul    r10d, r10d, 8                        ; ~8 bytes of storage per item
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], dword ptr [rbp-64], LB_INITSTORAGE, \
            dword ptr [rbp-32], r10
    mov     dword ptr [rbp-40], 0               ; index
pi_loop:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [rbp-32]
    jae     pi_done
    mov     ecx, dword ptr [rbp-40]             ; system items are never user rows.  The bound
    call    vault_is_system                     ;   above stays PHYSICAL and the item data set
    test    eax, eax                            ;   below is the PHYSICAL index, so this is a
    jnz     pi_next                             ;   pure skip - nothing downstream remaps.
    mov     ecx, dword ptr [rbp-40]             ; trash filter: show deleted iff in trash view
    call    gui_entry_is_deleted
    cmp     eax, dword ptr [g_trash_view]
    jne     pi_next
    cmp     dword ptr [rbp-56], 0               ; empty query -> show everything
    je      pi_show
    mov     ecx, dword ptr [rbp-40]
    call    gui_entry_fuzzy                      ; eax = best fuzzy score, or -1
    mov     r10d, dword ptr [rbp-40]             ; cache the score for the sort (idx<CAP)
    cmp     r10d, SCORE_CAP
    jae     pi_scored
    lea     r11, [g_entry_score]
    mov     dword ptr [r11+r10*4], eax
pi_scored:
    test    eax, eax                             ; -1 = no match -> skip
    js      pi_next
pi_show:
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], dword ptr [rbp-64], LB_ADDSTRING, 0, \
            dword ptr [rbp-40]
pi_next:
    inc     dword ptr [rbp-40]
    jmp     pi_loop
pi_done:
    FRAME_EPILOG
    ret
poplist_into endp

; =============================================================================
; Owner-draw entry list: icon-tile cards (glyph + title + subtitle)
; =============================================================================

; gui_make_listfonts() - lazily create the list fonts.
; gui_make_welcomefont() - lazily build the larger body font for the create
;   dialog's welcome text.  Its own frame: the 14-arg CreateFontW needs the room.
gui_make_welcomefont proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_welcomefont], 0
    jne     mwf_done
    mov     ecx, -15
    mov     edx, 400
    lea     r8, [f_segoeui]
    call    mk_font
    mov     qword ptr [g_welcomefont], rax
mwf_done:
    FRAME_EPILOG
    ret
gui_make_welcomefont endp

; gui_center_ok(rcx=hdlg) - centre the message-box OK button (DLU 122,120,56,22)
;   for single-button boxes, so it isn't left where the 2-button pair sits.
gui_center_ok proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    lea     r10, [rbp-72]                    ; RECT {122,170,178,192} in DLU
    mov     dword ptr [r10], 122
    mov     dword ptr [r10+4], 170
    mov     dword ptr [r10+8], 178
    mov     dword ptr [r10+12], 192
    WINCALL MapDialogRect, qword ptr [rbp-24], addr rbp-72
    mov     eax, dword ptr [rbp-64]          ; width = right - left
    sub     eax, dword ptr [rbp-72]
    mov     dword ptr [rbp-44], eax
    mov     eax, dword ptr [rbp-60]          ; height = bottom - top
    sub     eax, dword ptr [rbp-68]
    mov     dword ptr [rbp-48], eax
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_M_OK
    mov     qword ptr [rbp-32], rax
    WINCALL MoveWindow, qword ptr [rbp-32], dword ptr [rbp-72], dword ptr [rbp-68], \
            dword ptr [rbp-44], dword ptr [rbp-48], 1
    FRAME_EPILOG
    ret
gui_center_ok endp

; mk_font(ecx = base pixel height (negative), edx = weight, r8 = facename ptr)
;   -> rax = HFONT.  THE font factory: every CreateFontW routes through here so
;   the S/M/L font-size setting (g_fontdelta) scales the whole UI at once.
;   Heights are negative character heights, so a positive delta grows the font.
public mk_font
mk_font proc frame
    FRAME_PROLOG 160                             ; room for the 14-arg CreateFontW spill
    movsxd  rax, ecx
    sub     eax, dword ptr [g_fontdelta]         ; delta>0 -> more negative -> taller
    mov     dword ptr [rbp-24], eax              ; adjusted height
    mov     dword ptr [rbp-32], edx              ; weight
    mov     qword ptr [rbp-40], r8               ; facename
    WINCALL CreateFontW, dword ptr [rbp-24], 0, 0, 0, dword ptr [rbp-32], \
            0, 0, 0, 1, 0, 0, 5, 0, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
mk_font endp

gui_make_listfonts proc frame
    FRAME_PROLOG 48
    cmp     qword ptr [g_iconfont], 0
    jne     mlf_done
    mov     ecx, -19
    mov     edx, 400
    lea     r8, [f_iconname]
    call    mk_font
    mov     qword ptr [g_iconfont], rax
    mov     ecx, -14
    mov     edx, 600
    lea     r8, [f_segoeui]
    call    mk_font
    mov     qword ptr [g_cardfont], rax
    mov     ecx, -12
    mov     edx, 400
    lea     r8, [f_segoeui]
    call    mk_font
    mov     qword ptr [g_subfont], rax
    mov     ecx, -21
    mov     edx, 600
    lea     r8, [f_segoeui]
    call    mk_font
    mov     qword ptr [g_titlefont], rax
    mov     ecx, -11
    mov     edx, 400
    lea     r8, [f_iconname]
    call    mk_font
    mov     qword ptr [g_chevfont], rax
    mov     ecx, -24
    mov     edx, 600
    lea     r8, [f_mono]
    call    mk_font
    mov     qword ptr [g_monofont], rax
    mov     ecx, -12
    mov     edx, 400
    lea     r8, [f_mono]
    call    mk_font
    mov     qword ptr [g_phonfont], rax
    mov     ecx, -22                            ; Segoe UI Symbol for the recycle glyph (large)
    mov     edx, 400
    lea     r8, [f_symbol]
    call    mk_font
    mov     qword ptr [g_symfont], rax
mlf_done:
    FRAME_EPILOG
    ret
gui_make_listfonts endp

; gtc_score(ecx = entry index) -> eax = cached fuzzy score (0 when idx >= SCORE_CAP).
;   Leaf helper for the score-aware sort.
gtc_score proc
    cmp     ecx, SCORE_CAP
    jae     gts_zero
    lea     rax, [g_entry_score]
    mov     eax, dword ptr [rax+rcx*4]
    ret
gts_zero:
    xor     eax, eax
    ret
gtc_score endp

; gui_title_cmp(ecx=idxA, edx=idxB) -> eax = -1/0/1 (case-insensitive title order).
gui_title_cmp proc frame
    FRAME_PROLOG 96
    mov     dword ptr [rbp-24], ecx
    mov     dword ptr [rbp-28], edx
    ; with an active search query, rank by fuzzy score (descending); ties -> title
    cmp     dword ptr [g_search_len], 0
    je      gtc_favcheck
    mov     ecx, dword ptr [rbp-24]
    call    gtc_score
    mov     r8d, eax                             ; scoreA
    mov     ecx, dword ptr [rbp-28]
    call    gtc_score                            ; eax = scoreB
    cmp     r8d, eax
    jg      gtc_lt                               ; A higher score -> A first
    jl      gtc_gt
    jmp     gtc_bytitle                          ; equal score -> alphabetical
gtc_favcheck:
    ; favorites sort ahead of everything else; ties fall through to the title
    mov     ecx, dword ptr [rbp-24]
    call    gui_entry_is_fav
    mov     dword ptr [rbp-60], eax              ; favA
    mov     ecx, dword ptr [rbp-28]
    call    gui_entry_is_fav                     ; eax = favB
    cmp     dword ptr [rbp-60], eax
    je      gtc_bytitle
    cmp     dword ptr [rbp-60], 0                ; A favorite, B not -> A first
    jne     gtc_lt
    jmp     gtc_gt                               ; B favorite, A not -> A after
gtc_bytitle:
    mov     ecx, dword ptr [rbp-24]
    lea     rdx, [rbp-40]
    call    vault_title_at                      ; rax=ptrA, [rbp-40]=lenA
    mov     r8, qword ptr [rbp-40]
    cmp     r8, 255
    jbe     @F
    mov     r8, 255
@@: mov     dword ptr [rbp-32], r8d              ; lenA (capped)
    lea     r10, [g_cmpbuf]
    mov     r11, rax
    xor     r9d, r9d
gtc_cp:
    cmp     r9d, dword ptr [rbp-32]
    jae     gtc_cpd
    mov     al, byte ptr [r11+r9]
    mov     byte ptr [r10+r9], al
    inc     r9d
    jmp     gtc_cp
gtc_cpd:
    mov     ecx, dword ptr [rbp-28]
    lea     rdx, [rbp-48]
    call    vault_title_at                      ; rax=ptrB, [rbp-48]=lenB
    mov     qword ptr [rbp-56], rax
    xor     r9d, r9d
gtc_lp:
    cmp     r9d, dword ptr [rbp-32]              ; i>=lenA?
    jae     gtc_aend
    mov     r10d, dword ptr [rbp-48]
    cmp     r9d, r10d                            ; i>=lenB?
    jae     gtc_gt
    lea     r10, [g_cmpbuf]
    movzx   eax, byte ptr [r10+r9]
    mov     r11, qword ptr [rbp-56]
    movzx   r8d, byte ptr [r11+r9]
    cmp     eax, 'A'
    jb      gtc_af
    cmp     eax, 'Z'
    ja      gtc_af
    add     eax, 20h
gtc_af:
    cmp     r8d, 'A'
    jb      gtc_bf
    cmp     r8d, 'Z'
    ja      gtc_bf
    add     r8d, 20h
gtc_bf:
    cmp     eax, r8d
    jb      gtc_lt
    ja      gtc_gt
    inc     r9d
    jmp     gtc_lp
gtc_aend:
    mov     r10d, dword ptr [rbp-48]
    cmp     r9d, r10d
    jae     gtc_eq                              ; both exhausted -> equal
gtc_lt:
    mov     eax, -1
    FRAME_EPILOG
    ret
gtc_gt:
    mov     eax, 1
    FRAME_EPILOG
    ret
gtc_eq:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_title_cmp endp

; gui_entry_glyph(ecx=idx) -> eax = a Fluent icon char based on the record's fields.
; geg_contains(rcx=hay, edx=haylen, r8=lowercase-asciiz kw) -> eax = 1/0.
;   case-insensitive byte substring (hay is UTF-8/ASCII title bytes).
geg_contains proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], r8
    xor     r9d, r9d                             ; i
gc_outer:
    mov     r10d, r9d                            ; j
    mov     r11, qword ptr [rbp-40]              ; k
gc_inner:
    movzx   eax, byte ptr [r11]                  ; kw char (already lowercase)
    test    eax, eax
    jz      gc_yes
    cmp     r10d, dword ptr [rbp-32]
    jae     gc_next
    mov     rcx, qword ptr [rbp-24]
    movzx   edx, byte ptr [rcx+r10]              ; hay char
    cmp     edx, 'A'
    jb      gc_cmp
    cmp     edx, 'Z'
    ja      gc_cmp
    add     edx, 20h
gc_cmp:
    cmp     eax, edx
    jne     gc_next
    inc     r10d
    inc     r11
    jmp     gc_inner
gc_next:
    inc     r9d
    cmp     r9d, dword ptr [rbp-32]
    jb      gc_outer
    xor     eax, eax
    FRAME_EPILOG
    ret
gc_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
geg_contains endp

.const
gk_mail db "mail",0
gk_outlook db "outlook",0
gk_proton db "proton",0
gk_yahoo db "yahoo",0
gk_icloud db "icloud",0
gk_facebook db "facebook",0
gk_insta db "insta",0
gk_twitter db "twitter",0
gk_linkedin db "linkedin",0
gk_reddit db "reddit",0
gk_tiktok db "tiktok",0
gk_discord db "discord",0
gk_snap db "snap",0
gk_telegram db "telegram",0
gk_whatsapp db "whatsapp",0
gk_amazon db "amazon",0
gk_ebay db "ebay",0
gk_etsy db "etsy",0
gk_walmart db "walmart",0
gk_target db "target",0
gk_ali db "aliexpress",0
gk_ikea db "ikea",0
gk_paypal db "paypal",0
gk_shop db "shop",0
gk_steam db "steam",0
gk_epic db "epic",0
gk_xbox db "xbox",0
gk_playstation db "playstation",0
gk_nintendo db "nintendo",0
gk_riot db "riot",0
gk_game db "game",0
gk_netflix db "netflix",0
gk_hulu db "hulu",0
gk_disney db "disney",0
gk_spotify db "spotify",0
gk_youtube db "youtube",0
gk_twitch db "twitch",0
gk_video db "video",0
gk_github db "github",0
gk_gitlab db "gitlab",0
gk_aws db "aws",0
gk_azure db "azure",0
gk_cloud db "cloud",0
gk_docker db "docker",0
gk_verizon db "verizon",0
gk_mobile db "mobile",0
align 8
GK macro lbl, gl
    dq lbl
    dd gl
    dd 0
endm
geg_kwtab label qword
    GK gk_mail, 0E715h
    GK gk_outlook, 0E715h
    GK gk_proton, 0E715h
    GK gk_yahoo, 0E715h
    GK gk_icloud, 0E715h
    GK gk_facebook, 0E716h
    GK gk_insta, 0E716h
    GK gk_twitter, 0E716h
    GK gk_linkedin, 0E716h
    GK gk_reddit, 0E716h
    GK gk_tiktok, 0E716h
    GK gk_discord, 0E716h
    GK gk_snap, 0E716h
    GK gk_telegram, 0E716h
    GK gk_whatsapp, 0E716h
    GK gk_amazon, 0E7BFh
    GK gk_ebay, 0E7BFh
    GK gk_etsy, 0E7BFh
    GK gk_walmart, 0E7BFh
    GK gk_target, 0E7BFh
    GK gk_ali, 0E7BFh
    GK gk_ikea, 0E7BFh
    GK gk_paypal, 0E7BFh
    GK gk_shop, 0E7BFh
    GK gk_steam, 0E7FCh
    GK gk_epic, 0E7FCh
    GK gk_xbox, 0E7FCh
    GK gk_playstation, 0E7FCh
    GK gk_nintendo, 0E7FCh
    GK gk_riot, 0E7FCh
    GK gk_game, 0E7FCh
    GK gk_netflix, 0E714h
    GK gk_hulu, 0E714h
    GK gk_disney, 0E714h
    GK gk_spotify, 0E714h
    GK gk_youtube, 0E714h
    GK gk_twitch, 0E714h
    GK gk_video, 0E714h
    GK gk_github, 0E753h
    GK gk_gitlab, 0E753h
    GK gk_aws, 0E753h
    GK gk_azure, 0E753h
    GK gk_cloud, 0E753h
    GK gk_docker, 0E753h
    GK gk_verizon, 0E717h
    GK gk_mobile, 0E717h
    dq 0
    dd 0, 0
.code

; gui_hexparse(rcx=ascii ptr, edx=ndigits) -> eax = value.  Leaf.
gui_hexparse proc
    xor     eax, eax
    xor     r9d, r9d
hxp_lp:
    cmp     r9d, edx
    jae     hxp_done
    movzx   r8d, byte ptr [rcx+r9]
    cmp     r8d, '0'
    jb      hxp_done
    cmp     r8d, '9'
    jbe     hxp_dig
    or      r8d, 20h
    sub     r8d, 'a'-10
    jmp     hxp_add
hxp_dig:
    sub     r8d, '0'
hxp_add:
    shl     eax, 4
    or      eax, r8d
    inc     r9d
    jmp     hxp_lp
hxp_done:
    ret
gui_hexparse endp

; gui_entry_icon(ecx=idx) -> eax = 1 if the entry has a VF_ICON override (sets
;   g_ovr_glyph / g_ovr_color), else 0.
gui_entry_icon proc frame
    FRAME_PROLOG 64
    mov     edx, VF_ICON
    lea     r8, [rbp-24]                        ; &len
    call    vault_field_at                      ; rcx = idx
    test    rax, rax
    jz      gei_no
    mov     qword ptr [rbp-40], rax             ; value ptr (UTF-8 hex)
    cmp     dword ptr [rbp-24], 12
    jb      gei_no
    mov     rcx, rax
    mov     edx, 4
    call    gui_hexparse
    mov     dword ptr [g_ovr_glyph], eax
    mov     rcx, qword ptr [rbp-40]
    add     rcx, 4
    mov     edx, 8
    call    gui_hexparse
    mov     dword ptr [g_ovr_color], eax
    mov     eax, 1
    FRAME_EPILOG
    ret
gei_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_entry_icon endp

; gie_write(eax=value, r11d=ndigits, r10=dst) - append ndigits uppercase hex
;   (MSB first) as wide chars, advance r10.  Clobbers ecx/r8.  Leaf.
gie_write proc
    mov     ecx, r11d
    dec     ecx
    shl     ecx, 2                              ; top-nibble bit offset
gw_lp:
    mov     r8d, eax
    shr     r8d, cl
    and     r8d, 0Fh
    cmp     r8d, 10
    jb      gw_dig
    add     r8d, 'A'-10
    jmp     gw_put
gw_dig:
    add     r8d, '0'
gw_put:
    mov     word ptr [r10], r8w
    add     r10, 2
    sub     ecx, 4
    jns     gw_lp
    ret
gie_write endp

; gui_icon_encode() - render g_icon_glyph + g_icon_color into g_icon_valw as a
;   NUL-terminated wide "GGGGCCCCCCCC" (4 glyph hex + 8 colour hex).
gui_icon_encode proc frame
    FRAME_PROLOG 32
    lea     r10, [g_icon_valw]
    mov     eax, dword ptr [g_icon_glyph]
    mov     r11d, 4
    call    gie_write
    mov     eax, dword ptr [g_icon_color]
    mov     r11d, 8
    call    gie_write
    mov     word ptr [r10], 0
    FRAME_EPILOG
    ret
gui_icon_encode endp

gui_entry_glyph proc frame
    FRAME_PROLOG 112
    mov     dword ptr [rbp-24], ecx
    call    gui_entry_icon                      ; user override wins
    test    eax, eax
    jz      geg_auto
    mov     eax, dword ptr [g_ovr_glyph]
    FRAME_EPILOG
    ret
geg_auto:
    ; brand/keyword match on the title first
    mov     ecx, dword ptr [rbp-24]
    lea     rdx, [rbp-96]
    call    vault_title_at                      ; rax=ptr, [rbp-96]=len
    mov     qword ptr [rbp-56], rax
    mov     eax, dword ptr [rbp-96]
    mov     dword ptr [rbp-60], eax
    lea     r10, [geg_kwtab]
geg_kwlp:
    mov     r8, qword ptr [r10]
    test    r8, r8
    jz      geg_kwdone
    mov     qword ptr [rbp-72], r10
    mov     rcx, qword ptr [rbp-56]
    mov     edx, dword ptr [rbp-60]
    call    geg_contains
    mov     r10, qword ptr [rbp-72]
    test    eax, eax
    jz      geg_kwnext
    mov     eax, dword ptr [r10+8]
    FRAME_EPILOG
    ret
geg_kwnext:
    add     r10, 16
    jmp     geg_kwlp
geg_kwdone:
    mov     dword ptr [rbp-28], 0               ; hasurl
    mov     dword ptr [rbp-32], 0               ; hasuser
    mov     ecx, dword ptr [rbp-24]
    call    vault_field_count
    mov     dword ptr [rbp-36], eax
    mov     dword ptr [rbp-40], 0
geg_lp:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [rbp-36]
    jae     geg_done
    mov     ecx, dword ptr [rbp-24]
    mov     edx, dword ptr [rbp-40]
    lea     r8, [rbp-88]
    call    vault_field_get
    mov     eax, dword ptr [rbp-88]
    cmp     eax, VF_URL
    jne     geg_chkuser
    mov     dword ptr [rbp-28], 1
geg_chkuser:
    cmp     eax, VF_USERNAME
    jne     geg_next
    mov     dword ptr [rbp-32], 1
geg_next:
    inc     dword ptr [rbp-40]
    jmp     geg_lp
geg_done:
    cmp     dword ptr [rbp-28], 0
    je      geg_noturl
    mov     eax, 0E774h                         ; Globe (has URL)
    FRAME_EPILOG
    ret
geg_noturl:
    cmp     dword ptr [rbp-32], 0
    je      geg_deflt
    mov     eax, 0E77Bh                         ; Contact (has username)
    FRAME_EPILOG
    ret
geg_deflt:
    mov     eax, 0E72Eh                         ; Lock (default)
    FRAME_EPILOG
    ret
gui_entry_glyph endp

; gui_entry_color(ecx=idx) -> eax = tile color: the VF_ICON override if set,
;   else a stable colour from the title hash.
gui_entry_color proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-40], ecx             ; save idx across the override probe
    call    gui_entry_icon
    test    eax, eax
    jz      gec_auto
    mov     eax, dword ptr [g_ovr_color]
    FRAME_EPILOG
    ret
gec_auto:
    mov     ecx, dword ptr [rbp-40]
    lea     rdx, [rbp-24]
    call    vault_title_at                      ; rax=ptr, [rbp-24]=len
    mov     r8, qword ptr [rbp-24]
    mov     r10, rax
    xor     r9d, r9d
    xor     eax, eax
gec_lp:
    cmp     r9, r8
    jae     gec_done
    movzx   edx, byte ptr [r10+r9]
    add     eax, edx
    inc     r9
    jmp     gec_lp
gec_done:
    and     eax, 7
    lea     r10, [g_tilepal]
    mov     eax, dword ptr [r10+rax*4]
    FRAME_EPILOG
    ret
gui_entry_color endp

; gui_entry_subtitle(ecx=idx) - fill g_sub_w with the username (or URL) value.
gui_entry_subtitle proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], ecx
    mov     ecx, dword ptr [rbp-24]
    mov     edx, VF_USERNAME
    lea     r8, [rbp-32]
    call    vault_field_at
    test    rax, rax
    jnz     ges_have
    mov     ecx, dword ptr [rbp-24]
    mov     edx, VF_URL
    lea     r8, [rbp-32]
    call    vault_field_at
    test    rax, rax
    jnz     ges_have
    mov     word ptr [g_sub_w], 0
    FRAME_EPILOG
    ret
ges_have:
    mov     rcx, rax
    mov     edx, dword ptr [rbp-32]
    lea     r8, [g_sub_w]
    mov     r9d, 500
    call    gui_towide
    FRAME_EPILOG
    ret
gui_entry_subtitle endp

; gui_draw_tile(rcx=hdc, edx=x, r8d=y, r9d=size) - filled rounded square (g_tilecolor)
;   with the centered glyph in g_glyph_w drawn white.
gui_draw_tile proc frame
    FRAME_PROLOG 160
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [rbp-40], r8d
    mov     dword ptr [rbp-48], r9d
    mov     eax, edx
    add     eax, r9d
    mov     dword ptr [rbp-56], eax             ; x2
    mov     eax, r8d
    add     eax, r9d
    mov     dword ptr [rbp-64], eax             ; y2
    WINCALL CreateSolidBrush, dword ptr [g_tilecolor]
    mov     qword ptr [rbp-72], rax
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-72]
    mov     qword ptr [rbp-80], rax             ; old brush
    WINCALL GetStockObject, 8                   ; NULL_PEN
    WINCALL SelectObject, qword ptr [rbp-24], rax
    mov     qword ptr [rbp-88], rax             ; old pen
    WINCALL RoundRect, qword ptr [rbp-24], dword ptr [rbp-32], dword ptr [rbp-40], \
            dword ptr [rbp-56], dword ptr [rbp-64], 10, 10
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-80]   ; restore brush
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-88]   ; restore pen
    WINCALL DeleteObject, qword ptr [rbp-72]
    ; glyph
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [g_iconfont]
    mov     qword ptr [rbp-80], rax             ; old font
    WINCALL SetTextColor, qword ptr [rbp-24], 00FFFFFFh
    WINCALL SetBkMode, qword ptr [rbp-24], 1
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [rbp-104], eax            ; rect L
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [rbp-100], eax            ; rect T
    mov     eax, dword ptr [rbp-56]
    mov     dword ptr [rbp-96], eax             ; rect R
    mov     eax, dword ptr [rbp-64]
    mov     dword ptr [rbp-92], eax             ; rect B
    WINCALL DrawTextW, qword ptr [rbp-24], addr g_glyph_w, -1, addr rbp-104, DT_IMGFLAGS
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-80]   ; restore font
    FRAME_EPILOG
    ret
gui_draw_tile endp

; gui_draw_listitem(rcx=lpdis) - draw one owner-draw list entry card.
gui_draw_listitem proc frame
    FRAME_PROLOG 192
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     eax, dword ptr [r10+8]              ; itemID
    cmp     eax, -1
    je      gli_done                            ; empty listbox (focus-rect draw)
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax             ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-40], eax             ; L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-48], eax             ; T
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-56], eax             ; R
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-64], eax             ; B
    mov     eax, dword ptr [r10+16]
    mov     dword ptr [rbp-72], eax             ; itemState
    mov     eax, dword ptr [r10+56]
    mov     dword ptr [rbp-80], eax             ; vault idx (itemData)
    ; background (active scheme: sidebar fill, frame color when selected)
    mov     eax, dword ptr [g_col_side]
    test    dword ptr [rbp-72], 1               ; ODS_SELECTED
    jz      @F
    mov     eax, dword ptr [g_col_frame]
@@: mov     dword ptr [rbp-88], eax
    WINCALL CreateSolidBrush, dword ptr [rbp-88]
    mov     qword ptr [rbp-96], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [rbp-96]
    WINCALL DeleteObject, qword ptr [rbp-96]
    ; icon tile (L+5, T+5, 34)
    mov     ecx, dword ptr [rbp-80]
    call    gui_entry_color
    mov     dword ptr [g_tilecolor], eax
    mov     ecx, dword ptr [rbp-80]
    call    gui_entry_glyph
    mov     word ptr [g_glyph_w], ax
    mov     word ptr [g_glyph_w+2], 0
    mov     rcx, qword ptr [rbp-32]
    mov     edx, dword ptr [rbp-40]
    add     edx, 5
    mov     r8d, dword ptr [rbp-48]
    add     r8d, 5
    mov     r9d, 34
    call    gui_draw_tile
    ; title (cardfont, active text colour)
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_cardfont]
    mov     qword ptr [rbp-104], rax           ; old font
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_text]
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    mov     eax, dword ptr [rbp-40]
    add     eax, 46
    mov     dword ptr [rbp-152], eax           ; rect L
    mov     eax, dword ptr [rbp-48]
    add     eax, 4
    mov     dword ptr [rbp-148], eax           ; rect T
    mov     eax, dword ptr [rbp-56]
    sub     eax, 4
    mov     dword ptr [rbp-144], eax           ; rect R
    mov     eax, dword ptr [rbp-48]
    add     eax, 22
    mov     dword ptr [rbp-140], eax           ; rect B (top line)
    cmp     dword ptr [g_layout], 1            ; compact: one line, vertically centered
    jne     @F
    mov     eax, dword ptr [rbp-64]
    sub     eax, 2
    mov     dword ptr [rbp-140], eax
@@: mov     ecx, dword ptr [rbp-80]
    lea     rdx, [rbp-136]
    call    vault_title_at                     ; rax=ptr, [rbp-136]=len
    mov     rcx, rax
    mov     edx, dword ptr [rbp-136]
    lea     r8, [g_conv_w]
    mov     r9d, CONVW_MAX-1
    call    gui_towide
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_conv_w, -1, addr rbp-152, 8024h
    cmp     dword ptr [g_layout], 1            ; compact: no subtitle
    je      gli_subdone
    ; subtitle (subfont, dim)
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_subfont]
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_textdim]
    mov     ecx, dword ptr [rbp-80]
    call    gui_entry_subtitle                 ; -> g_sub_w
    mov     eax, dword ptr [rbp-48]
    add     eax, 22
    mov     dword ptr [rbp-148], eax           ; rect T
    mov     eax, dword ptr [rbp-64]
    sub     eax, 2
    mov     dword ptr [rbp-140], eax           ; rect B
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_sub_w, -1, addr rbp-152, 8024h
gli_subdone:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-104]   ; restore font
    ; E6/R6: health dot on the card's right edge (normal view only).  Reuses the
    ; tested vault_field_at + vh_pw_weak + vault_entry_stale; a single bullet just
    ; left of the star, red when the password is weak, amber when it is stale
    ; (unchanged over a year), absent when healthy.  Colour is stashed in the
    ; now-dead len scratch [rbp-136] so it survives the WINCALLs below.
    cmp     dword ptr [g_trash_view], 0
    jne     gli_weakdone
    mov     ecx, dword ptr [rbp-80]                               ; entry index
    mov     edx, VF_SECRET
    lea     r8, [rbp-136]                                         ; len scratch (free after)
    call    vault_field_at
    test    rax, rax
    jz      gli_weakdone                                          ; no password -> no dot
    mov     rcx, rax
    mov     edx, dword ptr [rbp-136]
    call    vh_pw_weak
    test    eax, eax
    jz      gli_dot_stale
    mov     dword ptr [rbp-136], 03B3BEFh                         ; red = weak
    jmp     gli_dot_draw
gli_dot_stale:
    mov     ecx, dword ptr [rbp-80]
    call    vault_entry_stale
    test    eax, eax
    jz      gli_weakdone                                          ; healthy -> no dot
    mov     dword ptr [rbp-136], 02EB2F6h                         ; amber = stale
gli_dot_draw:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_symfont]
    mov     qword ptr [rbp-104], rax
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [rbp-136]
    mov     word ptr [g_glyph_w], 2022h                           ; bullet
    mov     word ptr [g_glyph_w+2], 0
    mov     eax, dword ptr [rbp-56]
    sub     eax, 38
    mov     dword ptr [rbp-152], eax                              ; L = R-38
    mov     eax, dword ptr [rbp-48]
    add     eax, 4
    mov     dword ptr [rbp-148], eax                              ; T
    mov     eax, dword ptr [rbp-56]
    sub     eax, 22
    mov     dword ptr [rbp-144], eax                              ; R = R-22
    mov     eax, dword ptr [rbp-48]
    add     eax, 22
    mov     dword ptr [rbp-140], eax                              ; B
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_glyph_w, -1, addr rbp-152, 025h
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-104]
gli_weakdone:
    ; trash (recover) view: a recycle glyph on each item's right edge - clicking
    ; it restores that entry (see gui_trash_glyph_hit).  Otherwise, the fav star.
    cmp     dword ptr [g_trash_view], 0
    je      gli_fav
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_symfont]
    mov     qword ptr [rbp-104], rax
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_text]
    mov     word ptr [g_glyph_w], 267Bh                           ; recycle symbol
    mov     word ptr [g_glyph_w+2], 0
    mov     eax, dword ptr [rbp-56]
    sub     eax, 32
    mov     dword ptr [rbp-152], eax                              ; rect L = R-32
    mov     eax, dword ptr [rbp-48]
    add     eax, 4
    mov     dword ptr [rbp-148], eax
    mov     eax, dword ptr [rbp-56]
    sub     eax, 4
    mov     dword ptr [rbp-144], eax                              ; rect R = R-4
    mov     eax, dword ptr [rbp-64]
    sub     eax, 4
    mov     dword ptr [rbp-140], eax                              ; rect B
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_glyph_w, -1, addr rbp-152, 025h
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-104]
    jmp     gli_done
gli_fav:
    ; favorite marker: a small gold star on the card's right edge
    mov     ecx, dword ptr [rbp-80]
    call    gui_entry_is_fav
    test    eax, eax
    jz      gli_done
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_chevfont]
    mov     qword ptr [rbp-104], rax
    WINCALL SetTextColor, qword ptr [rbp-32], 002EB2F6h            ; amber
    mov     word ptr [g_glyph_w], 0E735h                          ; FavoriteStarFill
    mov     word ptr [g_glyph_w+2], 0
    mov     eax, dword ptr [rbp-56]
    sub     eax, 20
    mov     dword ptr [rbp-152], eax                              ; rect L = R-20
    mov     eax, dword ptr [rbp-48]
    add     eax, 4
    mov     dword ptr [rbp-148], eax                              ; rect T
    mov     eax, dword ptr [rbp-56]
    sub     eax, 4
    mov     dword ptr [rbp-144], eax                              ; rect R = R-4
    mov     eax, dword ptr [rbp-48]
    add     eax, 22
    mov     dword ptr [rbp-140], eax                              ; rect B
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_glyph_w, -1, addr rbp-152, 025h
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-104]
gli_done:
    FRAME_EPILOG
    ret
gui_draw_listitem endp

; gui_draw_header(rcx=lpdis) - draw the detail-pane header for the current entry:
;   a large icon tile + title + subtitle (shown in view mode).  Blank when no
;   entry is selected.  Coords are the control's own client rect (0,0-origin).
gui_draw_header proc frame
    FRAME_PROLOG 192
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax            ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-40], eax            ; L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-48], eax            ; T
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-56], eax            ; R
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-64], eax            ; B
    ; background fill (dialog base color #202020)
    WINCALL CreateSolidBrush, dword ptr [g_col_bg]
    mov     qword ptr [rbp-72], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [rbp-72]
    WINCALL DeleteObject, qword ptr [rbp-72]
    ; nothing selected -> leave the header blank
    cmp     dword ptr [g_cur_idx], 0
    jl      gdh_done
    ; icon tile (L, T+2, 38)
    mov     ecx, dword ptr [g_cur_idx]
    call    gui_entry_color
    mov     dword ptr [g_tilecolor], eax
    mov     ecx, dword ptr [g_cur_idx]
    call    gui_entry_glyph
    mov     word ptr [g_glyph_w], ax
    mov     word ptr [g_glyph_w+2], 0
    mov     rcx, qword ptr [rbp-32]
    mov     edx, dword ptr [rbp-40]
    mov     r8d, dword ptr [rbp-48]
    add     r8d, 2
    mov     r9d, 38
    call    gui_draw_tile
    ; title (large semibold, active text colour)
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_titlefont]
    mov     qword ptr [rbp-80], rax            ; old font
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_text]
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    mov     eax, dword ptr [rbp-40]
    add     eax, 48
    mov     dword ptr [rbp-104], eax           ; rect L
    mov     eax, dword ptr [rbp-48]
    add     eax, 1
    mov     dword ptr [rbp-100], eax           ; rect T
    mov     eax, dword ptr [rbp-56]
    sub     eax, 8                              ; small right padding
    mov     dword ptr [rbp-96], eax            ; rect R
    mov     eax, dword ptr [rbp-48]
    add     eax, 40                             ; span the icon height so DT_VCENTER centers it
    mov     dword ptr [rbp-92], eax            ; rect B
    mov     ecx, dword ptr [g_cur_idx]
    lea     rdx, [rbp-112]
    call    vault_title_at                     ; rax=ptr, [rbp-112]=len
    mov     rcx, rax
    mov     edx, dword ptr [rbp-112]
    lea     r8, [g_conv_w]
    mov     r9d, CONVW_MAX-1
    call    gui_towide
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_conv_w, -1, addr rbp-104, 8024h
    ; (the username subtitle was redundant with the Username field below - removed)
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-80]   ; restore font
gdh_done:
    FRAME_EPILOG
    ret
gui_draw_header endp

; gui_draw_iconbtn(rcx=lpdis) - draw the edit-mode icon button as a mini tile
;   showing the current entry's effective glyph + colour (the working override
;   if the user picked one, else the auto-derived icon).
gui_draw_iconbtn proc frame
    FRAME_PROLOG 128                       ; >= 128: the 5-arg DrawTextW below spills
                                           ;   its flags to [rsp+32]; at 96 that landed
                                           ;   exactly on the saved font at [rbp-80]
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-40], rax            ; hdc
    WINCALL CreateSolidBrush, dword ptr [g_col_bg]
    mov     qword ptr [rbp-48], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-40], rdx, qword ptr [rbp-48]
    WINCALL DeleteObject, qword ptr [rbp-48]
    cmp     dword ptr [g_cur_idx], 0
    jl      gib_done
    cmp     dword ptr [g_icon_set], 0
    je      gib_auto
    mov     eax, dword ptr [g_icon_color]
    mov     dword ptr [g_tilecolor], eax
    mov     eax, dword ptr [g_icon_glyph]
    jmp     gib_glyph
gib_auto:
    mov     ecx, dword ptr [g_cur_idx]
    call    gui_entry_color
    mov     dword ptr [g_tilecolor], eax
    mov     ecx, dword ptr [g_cur_idx]
    call    gui_entry_glyph
gib_glyph:
    mov     word ptr [g_glyph_w], ax
    mov     word ptr [g_glyph_w+2], 0
    mov     rcx, qword ptr [rbp-40]
    mov     r10, qword ptr [rbp-24]
    mov     edx, dword ptr [r10+40]            ; L
    mov     r8d, dword ptr [r10+44]            ; T
    mov     r9d, dword ptr [r10+52]
    sub     r9d, dword ptr [r10+44]            ; size = B - T
    call    gui_draw_tile
    ; edit hint: a tiny pencil in the bottom-right corner (this button is edit-mode only)
    mov     word ptr [g_glyph_w], 0E70Fh
    mov     word ptr [g_glyph_w+2], 0
    WINCALL SelectObject, qword ptr [rbp-40], qword ptr [g_chevfont]
    mov     qword ptr [rbp-80], rax            ; old font
    WINCALL SetTextColor, qword ptr [rbp-40], dword ptr [g_col_text]
    WINCALL SetBkMode, qword ptr [rbp-40], 1
    mov     r10, qword ptr [rbp-24]
    mov     r9d, dword ptr [r10+52]
    sub     r9d, dword ptr [r10+44]            ; tile size
    mov     eax, dword ptr [r10+40]           ; pencil rect: bottom-right corner of the tile
    add     eax, r9d
    sub     eax, 9
    mov     dword ptr [rbp-72], eax            ; L
    mov     eax, dword ptr [r10+44]
    add     eax, r9d
    sub     eax, 9
    mov     dword ptr [rbp-68], eax            ; T
    mov     eax, dword ptr [r10+40]
    add     eax, r9d
    mov     dword ptr [rbp-64], eax            ; R
    mov     eax, dword ptr [r10+44]
    add     eax, r9d
    mov     dword ptr [rbp-60], eax            ; B
    WINCALL DrawTextW, qword ptr [rbp-40], addr g_glyph_w, -1, addr rbp-72, 25h
    WINCALL SelectObject, qword ptr [rbp-40], qword ptr [rbp-80]
gib_done:
    FRAME_EPILOG
    ret
gui_draw_iconbtn endp

; gui_pw_grade(rcx=ptr utf8, edx=len) -> eax = strength 0 weak /1 fair /2 good /3 strong.
;   Self-contained: character-class count + length.  Leaf.
gui_pw_grade proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    xor     r8d, r8d                          ; class mask (l/u/d/sym)
    xor     r9d, r9d                          ; i
gpg_lp:
    cmp     r9d, dword ptr [rbp-32]
    jae     gpg_classes
    mov     r10, qword ptr [rbp-24]
    movzx   eax, byte ptr [r10+r9]
    cmp     al, 'a'
    jb      gpg_cku
    cmp     al, 'z'
    ja      gpg_cku
    or      r8d, 1
    jmp     gpg_next
gpg_cku:
    cmp     al, 'A'
    jb      gpg_ckd
    cmp     al, 'Z'
    ja      gpg_ckd
    or      r8d, 2
    jmp     gpg_next
gpg_ckd:
    cmp     al, '0'
    jb      gpg_sym
    cmp     al, '9'
    ja      gpg_sym
    or      r8d, 4
    jmp     gpg_next
gpg_sym:
    or      r8d, 8
gpg_next:
    inc     r9d
    jmp     gpg_lp
gpg_classes:
    xor     ecx, ecx                          ; class count
    test    r8d, 1
    jz      gpg_c2
    inc     ecx
gpg_c2:
    test    r8d, 2
    jz      gpg_c3
    inc     ecx
gpg_c3:
    test    r8d, 4
    jz      gpg_c4
    inc     ecx
gpg_c4:
    test    r8d, 8
    jz      gpg_grade
    inc     ecx
gpg_grade:
    mov     edx, dword ptr [rbp-32]           ; L
    xor     eax, eax                          ; weak
    cmp     edx, 8
    jb      gpg_ret                           ; <8 chars -> weak
    mov     eax, 1                            ; fair
    cmp     edx, 12                           ; good: (L>=12 & c>=2) | (L>=10 & c>=3)
    jb      gpg_g2
    cmp     ecx, 2
    jae     gpg_good
gpg_g2:
    cmp     edx, 10
    jb      gpg_ret
    cmp     ecx, 3
    jb      gpg_ret
gpg_good:
    mov     eax, 2                            ; good
    cmp     edx, 16                           ; strong: (L>=16 & c>=3) | (L>=12 & c==4)
    jb      gpg_s2
    cmp     ecx, 3
    jae     gpg_strong
gpg_s2:
    cmp     edx, 12
    jb      gpg_ret
    cmp     ecx, 4
    jb      gpg_ret
gpg_strong:
    mov     eax, 3                            ; strong
gpg_ret:
    FRAME_EPILOG
    ret
gui_pw_grade endp

; gui_draw_sbadge(rcx=lpdis) - draw a secret row's password-strength badge: a
;   colored rounded pill with Weak/Fair/Good/Strong, keyed off FD_PWLEVEL.
gui_draw_sbadge proc frame
    FRAME_PROLOG 192
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax            ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-40], eax            ; L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-48], eax            ; T
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-56], eax            ; R
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-64], eax            ; B
    ; clear behind the pill to the row's own background so nothing lingers: the
    ; panel colour in card layouts (the badge sits inside a tile), else the dialog bg
    mov     eax, dword ptr [g_col_bg]
    mov     r11d, dword ptr [g_layout]
    lea     r10, [lay_band]
    cmp     dword ptr [r10+r11*4], 0
    je      @F
    mov     eax, dword ptr [g_col_panel]
@@: mov     dword ptr [rbp-80], eax
    WINCALL CreateSolidBrush, dword ptr [rbp-80]
    mov     qword ptr [rbp-72], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [rbp-72]
    WINCALL DeleteObject, qword ptr [rbp-72]
    ; row index from ctl id -> FD_PWLEVEL
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [r10+4]             ; CtlID
    sub     eax, IDC_DYN_BASE
    shr     eax, DYN_SLOTS_LOG2                ; row
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     eax, dword ptr [r10+FD_FLAGS]
    shr     eax, FDF_PWLVL_SHIFT
    and     eax, 3                             ; level 0..3
    ; caption + color by level
    lea     r8, [badge_weak]
    mov     ecx, CLR_BAR_RED
    cmp     eax, 1
    jb      gds_have
    lea     r8, [badge_fair]
    mov     ecx, CLR_BAR_AMBER
    je      gds_have
    lea     r8, [badge_good]
    mov     ecx, CLR_BAR_LGREEN
    cmp     eax, 2
    je      gds_have
    lea     r8, [badge_strong]
    mov     ecx, CLR_BAR_DGREEN
gds_have:
    mov     qword ptr [rbp-88], r8             ; caption ptr
    mov     dword ptr [rbp-96], ecx            ; color
    ; pill
    WINCALL CreateSolidBrush, dword ptr [rbp-96]
    mov     qword ptr [rbp-104], rax
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-104]
    mov     qword ptr [rbp-112], rax           ; old brush
    WINCALL GetStockObject, 8                  ; NULL_PEN
    WINCALL SelectObject, qword ptr [rbp-32], rax
    mov     qword ptr [rbp-120], rax           ; old pen
    WINCALL RoundRect, qword ptr [rbp-32], dword ptr [rbp-40], dword ptr [rbp-48], \
            dword ptr [rbp-56], dword ptr [rbp-64], 8, 8
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-112]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-120]
    WINCALL DeleteObject, qword ptr [rbp-104]
    ; caption (subfont, white, centered)
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_subfont]
    mov     qword ptr [rbp-112], rax           ; old font
    WINCALL SetTextColor, qword ptr [rbp-32], 00FFFFFFh
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [rbp-160], eax           ; rect L
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [rbp-156], eax           ; rect T
    mov     eax, dword ptr [rbp-56]
    mov     dword ptr [rbp-152], eax           ; rect R
    mov     eax, dword ptr [rbp-64]
    mov     dword ptr [rbp-148], eax           ; rect B
    WINCALL DrawTextW, qword ptr [rbp-32], qword ptr [rbp-88], -1, addr rbp-160, DT_IMGFLAGS
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-112]
    FRAME_EPILOG
    ret
gui_draw_sbadge endp

; gui_draw_taglist(rcx=lpdis) - paint the attachments tile: one rounded chip per
;   file in g_tilefiles (filename, left-aligned, ellipsized).  In edit mode each
;   chip shows an 'x' delete hotspot (TAG_XW px) on its right.  Chip height =
;   clientH / count, matching gui_tag_hit's inverse mapping.
gui_draw_taglist proc frame
    FRAME_PROLOG 224
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax            ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-40], eax            ; L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-48], eax            ; T
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-56], eax            ; R
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-64], eax            ; B
    ; clear behind the tile to the row's own background: the panel colour in
    ; card layouts (the tile sits inside a card, like the sbadge/chevron), else
    ; the dialog bg - previously always dialog bg, which left a dark well in cards
    mov     eax, dword ptr [g_col_bg]
    mov     r11d, dword ptr [g_layout]
    lea     r10, [lay_band]
    cmp     dword ptr [r10+r11*4], 0
    je      @F
    mov     eax, dword ptr [g_col_panel]
@@: mov     dword ptr [rbp-160], eax
    WINCALL CreateSolidBrush, dword ptr [rbp-160]
    mov     qword ptr [rbp-112], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [rbp-112]
    WINCALL DeleteObject, qword ptr [rbp-112]
    mov     eax, dword ptr [g_tilefile_n]
    mov     dword ptr [rbp-72], eax
    test    eax, eax
    jz      gtl_done
    mov     eax, dword ptr [rbp-64]            ; chipH = (B - T) / n
    sub     eax, dword ptr [rbp-48]
    cdq
    idiv    dword ptr [rbp-72]
    mov     dword ptr [rbp-88], eax
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_subfont]
    mov     qword ptr [rbp-120], rax           ; old font
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    mov     dword ptr [rbp-80], 0              ; i
gtl_loop:
    mov     eax, dword ptr [rbp-80]
    cmp     eax, dword ptr [rbp-72]
    jae     gtl_restore
    mov     eax, dword ptr [rbp-80]           ; top = T + i*chipH
    imul    eax, dword ptr [rbp-88]
    add     eax, dword ptr [rbp-48]
    mov     dword ptr [rbp-96], eax
    add     eax, dword ptr [rbp-88]           ; bot = top + chipH - 2 (gap)
    sub     eax, 2
    mov     dword ptr [rbp-104], eax
    mov     eax, dword ptr [rbp-56]           ; chip right = R - 2
    sub     eax, 2
    mov     dword ptr [rbp-152], eax
    ; rounded chip fill (dedicated file-badge colour), NULL pen
    WINCALL CreateSolidBrush, dword ptr [g_col_filebadge]
    mov     qword ptr [rbp-128], rax
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-128]
    mov     qword ptr [rbp-136], rax          ; old brush
    WINCALL GetStockObject, 8                 ; NULL_PEN
    WINCALL SelectObject, qword ptr [rbp-32], rax
    mov     qword ptr [rbp-144], rax          ; old pen
    WINCALL RoundRect, qword ptr [rbp-32], dword ptr [rbp-40], dword ptr [rbp-96], \
            dword ptr [rbp-152], dword ptr [rbp-104], 8, 8
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-136]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-144]
    WINCALL DeleteObject, qword ptr [rbp-128]
    ; filename (left, vcenter, ellipsized) padded, leaving room for the x
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_text]
    mov     eax, dword ptr [rbp-40]
    add     eax, 8
    mov     dword ptr [rbp-176], eax          ; rc.left = L + 8
    mov     eax, dword ptr [rbp-96]
    mov     dword ptr [rbp-172], eax          ; rc.top
    mov     eax, dword ptr [rbp-56]
    sub     eax, 2 + TAG_XW
    mov     dword ptr [rbp-168], eax          ; rc.right = R - 2 - TAG_XW
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-164], eax          ; rc.bottom
    mov     ecx, dword ptr [rbp-80]
    call    tf_entry
    add     rax, TFILE_NAME
    WINCALL DrawTextW, qword ptr [rbp-32], rax, -1, addr rbp-176, DT_NAMEFLAGS
    ; edit mode: 'x' delete hotspot on the right
    cmp     dword ptr [g_editmode], 0
    je      gtl_next
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_textdim]
    mov     eax, dword ptr [rbp-56]
    sub     eax, 2 + TAG_XW
    mov     dword ptr [rbp-176], eax          ; rc.left = R - 2 - TAG_XW
    mov     eax, dword ptr [rbp-96]
    mov     dword ptr [rbp-172], eax
    mov     eax, dword ptr [rbp-56]
    sub     eax, 2
    mov     dword ptr [rbp-168], eax          ; rc.right = R - 2
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-164], eax
    WINCALL DrawTextW, qword ptr [rbp-32], addr tag_xw, -1, addr rbp-176, DT_IMGFLAGS
gtl_next:
    inc     dword ptr [rbp-80]
    jmp     gtl_loop
gtl_restore:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-120]
gtl_done:
    FRAME_EPILOG
    ret
gui_draw_taglist endp

; gui_draw_field_cards(rcx=hdc, rdx=hdlg) - fill a COL_PANEL rounded card behind
;   every field row (label+value edits already paint COL_PANEL, so they blend).
gui_draw_field_cards proc frame
    FRAME_PROLOG 208                       ; >= 208: at 160 the GetClientRect output
                                           ;   at [rbp-160] sat in that call's OWN
                                           ;   home space (rsp+16), so user32 homed
                                           ;   nonvolatiles over it and restored them
                                           ;   from the rect.  This also lifts it clear
                                           ;   of the 7-arg RoundRect spill below, so
                                           ;   safety no longer rests on the local
                                           ;   being dead by then.
    mov     qword ptr [rbp-24], rcx            ; hdc
    mov     qword ptr [rbp-32], rdx            ; hdlg
    cmp     dword ptr [g_menu_open], 0         ; SETTINGS.md predicted this guard could go
    jne     gfc_ret                            ;   with the overlay.  It cannot: DLG_VAULT
                                               ;   has no WS_CLIPCHILDREN, so WM_ERASEBKGND
                                               ;   still paints the region the settings
                                               ;   child occupies.  Steady state hides it,
                                               ;   but a drag-resize erases the parent
                                               ;   before the child repaints and the cards
                                               ;   flash through - the tearing class we
                                               ;   already hit on the title strip.  Adding
                                               ;   WS_CLIPCHILDREN would fix it properly and
                                               ;   is too broad a change for a cleanup: any
                                               ;   child relying on the parent's backdrop
                                               ;   showing through would break.
    mov     eax, dword ptr [g_layout]          ; flat (Compact) layout draws no cards
    lea     r10, [lay_band]
    cmp     dword ptr [r10+rax*4], 0
    je      gfc_ret
    WINCALL CreateSolidBrush, dword ptr [g_col_panel]   ; card fill (active scheme)
    mov     qword ptr [rbp-40], rax
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-40]
    mov     qword ptr [rbp-48], rax            ; old brush
    WINCALL GetStockObject, 8                  ; NULL_PEN
    WINCALL SelectObject, qword ptr [rbp-24], rax
    mov     qword ptr [rbp-56], rax            ; old pen
    WINCALL GetClientRect, qword ptr [rbp-32], addr rbp-160   ; elastic: widen cards by dW
    mov     eax, dword ptr [rbp-152]           ; client right = width (left is 0)
    sub     eax, dword ptr [g_base_cx]         ; dW = width - base (matches gui_stretch_rows)
    jns     @F
    xor     eax, eax                           ; narrower than base -> no stretch
@@: mov     dword ptr [rbp-112], eax           ; dW (pixels, >= 0)
    mov     dword ptr [rbp-64], 0              ; row i
gfc_lp:
    mov     eax, dword ptr [rbp-64]
    cmp     eax, dword ptr [g_field_count]
    jae     gfc_done
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     ecx, dword ptr [r10+FD_KIND]
    mov     dword ptr [rbp-100], ecx           ; kind (survives the calls below)
    cmp     ecx, VF_SPACER                     ; a blank gap is the only row with no card;
    je      gfc_next                           ;   a heading gets one like any other tile
    mov     eax, dword ptr [r10+FD_Y]
    mov     dword ptr [rbp-104], eax           ; row top in DLU: r10 is volatile and the
    mov     dword ptr [rbp-84], eax            ;   heading text below is painted after two
    add     eax, dword ptr [r10+FD_H]          ;   WINCALLs have clobbered it
    mov     dword ptr [rbp-76], eax            ; B
    mov     dword ptr [rbp-88], 214            ; L (156 + VDX_DLU)
    mov     dword ptr [rbp-80], 472            ; R (414 + VDX_DLU)
    WINCALL MapDialogRect, qword ptr [rbp-32], addr rbp-88
    mov     eax, dword ptr [rbp-112]           ; stretch the card to the widened pane
    add     dword ptr [rbp-80], eax
    WINCALL RoundRect, qword ptr [rbp-24], dword ptr [rbp-88], dword ptr [rbp-84], \
            dword ptr [rbp-80], dword ptr [rbp-76], 10, 10
    cmp     dword ptr [rbp-100], VF_GROUP      ; a heading also paints its title on the card
    jne     gfc_next
    ; Edit mode shows the title EDIT instead, so painting here would double up with it.
    ; No hairline rule any more either: the card is the separation, and the rule on top
    ; of the edit read as two lines at different heights with the painted one jutting
    ; out past the edit's right edge.
    cmp     dword ptr [g_editmode], 0
    jne     gfc_next
    mov     ecx, dword ptr [rbp-64]            ; the heading's title control
    mov     edx, DS_VALUE
    call    dynid
    WINCALL GetDlgItemTextW, qword ptr [rbp-32], eax, addr g_grouptxt, 128
    WINCALL SetBkMode, qword ptr [rbp-24], 1   ; TRANSPARENT
    WINCALL SetTextColor, qword ptr [rbp-24], dword ptr [g_col_textdim]
    mov     eax, dword ptr [rbp-104]
    add     eax, 3                             ; the label band: identical to where every
    mov     dword ptr [rbp-84], eax            ;   other tile puts its label, and to where
    add     eax, 10                            ;   the title edit sits in edit mode
    mov     dword ptr [rbp-76], eax            ; B
    ; L = the card content column, so the title lines up with the label of every tile
    ; above and below it.  gui_rows_layout passes a bare 176 for those, but move_ctl
    ; adds VDX_DLU itself; this path maps the rect directly, so the shift has to be
    ; written out or the heading lands 58 DLU left - i.e. painted under the sidebar.
    mov     dword ptr [rbp-88], 176 + VDX_DLU  ; L
    mov     dword ptr [rbp-80], 460            ; R
    WINCALL MapDialogRect, qword ptr [rbp-32], addr rbp-88
    mov     eax, dword ptr [rbp-112]           ; stretch heading text room to the widened pane
    add     dword ptr [rbp-80], eax
    WINCALL DrawTextW, qword ptr [rbp-24], addr g_grouptxt, -1, addr rbp-88, DT_NAMEFLAGS
gfc_next:
    inc     dword ptr [rbp-64]
    jmp     gfc_lp
gfc_done:
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-48]   ; restore brush
    WINCALL SelectObject, qword ptr [rbp-24], qword ptr [rbp-56]   ; restore pen
    WINCALL DeleteObject, qword ptr [rbp-40]
gfc_ret:
    FRAME_EPILOG
    ret
gui_draw_field_cards endp

; gui_anchor_init(rcx=hdlg) - record the vault client + window size and each
;   anchored control's initial client rect, so gui_reflow can resize responsively
;   (redesign 1.3).  Called once from vp_init after the layout is settled.
gui_anchor_init proc frame
    FRAME_PROLOG 144
    mov     qword ptr [rbp-24], rcx
    WINCALL GetClientRect, qword ptr [rbp-24], addr rbp-48
    mov     eax, dword ptr [rbp-40]           ; right = client width
    mov     dword ptr [g_base_cx], eax
    mov     eax, dword ptr [rbp-36]           ; bottom = client height
    mov     dword ptr [g_base_cy], eax
    WINCALL GetWindowRect, qword ptr [rbp-24], addr rbp-48
    mov     eax, dword ptr [rbp-40]
    sub     eax, dword ptr [rbp-48]
    mov     dword ptr [g_base_winw], eax
    mov     eax, dword ptr [rbp-36]
    sub     eax, dword ptr [rbp-44]
    mov     dword ptr [g_base_winh], eax
    mov     dword ptr [rbp-52], 0             ; i
gai_lp:
    mov     eax, dword ptr [rbp-52]
    cmp     eax, ANCHOR_N
    jae     gai_done
    imul    eax, eax, 8
    lea     r10, [g_anchor_def]
    mov     eax, dword ptr [r10+rax]          ; id
    mov     dword ptr [rbp-56], eax
    WINCALL GetDlgItem, qword ptr [rbp-24], dword ptr [rbp-56]
    mov     qword ptr [rbp-64], rax
    test    rax, rax
    jz      gai_next
    WINCALL GetWindowRect, qword ptr [rbp-64], addr rbp-96
    WINCALL MapWindowPoints, 0, qword ptr [rbp-24], addr rbp-96, 2
    mov     eax, dword ptr [rbp-52]
    imul    eax, eax, 16
    lea     r11, [g_anchor_rect]
    add     r11, rax
    mov     eax, dword ptr [rbp-96]           ; L -> x
    mov     dword ptr [r11+0], eax
    mov     eax, dword ptr [rbp-92]           ; T -> y
    mov     dword ptr [r11+4], eax
    mov     eax, dword ptr [rbp-88]           ; R - L -> w
    sub     eax, dword ptr [rbp-96]
    mov     dword ptr [r11+8], eax
    mov     eax, dword ptr [rbp-84]           ; B - T -> h
    sub     eax, dword ptr [rbp-92]
    mov     dword ptr [r11+12], eax
gai_next:
    inc     dword ptr [rbp-52]
    jmp     gai_lp
gai_done:
    FRAME_EPILOG
    ret
gui_anchor_init endp

; gui_reflow(rcx=hdlg) - reposition anchored controls for the current client size
;   (WM_SIZE).  Each control moves/stretches by the delta from the recorded base
;   size per its anchor flags.  The detail rows keep their own (fixed) layout.
gui_reflow proc frame
    FRAME_PROLOG 144
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_base_cx], 0          ; not recorded yet -> nothing to do
    je      grf_done
    WINCALL GetClientRect, qword ptr [rbp-24], addr rbp-48
    ; Clamp both deltas at 0, exactly as gui_draw_field_cards does for the cards.
    ; A window narrower than the recorded base gave a NEGATIVE dW, and a STRETCHW
    ; control (IDC_V_HEADER, IDC_V_TITLE) then got width = base + dW - the header
    ; is only 194 DLU wide, so it collapsed and the entry name vanished from the
    ; detail pane.  Latent until the rax fix in 25e49aa made this MoveWindow run
    ; at all.  Below the base size the layout keeps base metrics and clips, which
    ; is also what the cards do - so the two stay in agreement.
    mov     eax, dword ptr [rbp-40]
    sub     eax, dword ptr [g_base_cx]
    jns     @F
    xor     eax, eax
@@: mov     dword ptr [rbp-52], eax           ; dW (>= 0)
    mov     eax, dword ptr [rbp-36]
    sub     eax, dword ptr [g_base_cy]
    jns     @F
    xor     eax, eax
@@: mov     dword ptr [rbp-56], eax           ; dH (>= 0)
    mov     dword ptr [rbp-60], 0             ; i
grf_lp:
    mov     eax, dword ptr [rbp-60]
    cmp     eax, ANCHOR_N
    jae     grf_done
    imul    eax, eax, 8
    lea     r10, [g_anchor_def]
    mov     ecx, dword ptr [r10+rax]          ; id
    mov     dword ptr [rbp-64], ecx
    mov     edx, dword ptr [r10+rax+4]        ; flags
    mov     dword ptr [rbp-68], edx
    mov     eax, dword ptr [rbp-60]
    imul    eax, eax, 16
    lea     r11, [g_anchor_rect]
    add     r11, rax
    mov     eax, dword ptr [r11+0]            ; nx = x (+dW if RIGHT)
    test    dword ptr [rbp-68], ANCH_RIGHT
    jz      @F
    add     eax, dword ptr [rbp-52]
@@: mov     dword ptr [rbp-72], eax
    mov     eax, dword ptr [r11+4]            ; ny = y (+dH if BOTTOM)
    test    dword ptr [rbp-68], ANCH_BOTTOM
    jz      @F
    add     eax, dword ptr [rbp-56]
@@: mov     dword ptr [rbp-76], eax
    mov     eax, dword ptr [r11+8]            ; nw = w (+dW if STRETCHW)
    test    dword ptr [rbp-68], ANCH_STRETCHW
    jz      @F
    add     eax, dword ptr [rbp-52]
@@: mov     dword ptr [rbp-80], eax
    mov     eax, dword ptr [r11+12]           ; nh = h (+dH if STRETCHH)
    test    dword ptr [rbp-68], ANCH_STRETCHH
    jz      @F
    add     eax, dword ptr [rbp-56]
@@: mov     dword ptr [rbp-84], eax
    WINCALL GetDlgItem, qword ptr [rbp-24], dword ptr [rbp-64]
    test    rax, rax
    jz      grf_next
    mov     qword ptr [rbp-88], rax           ; stage the hwnd: WINCALL emits the
                                              ;   32-bit memory stack args FIRST,
                                              ;   via rax - passing rax here made
                                              ;   MoveWindow take nHeight as its
                                              ;   hWnd, so no anchor ever moved
    WINCALL MoveWindow, qword ptr [rbp-88], dword ptr [rbp-72], dword ptr [rbp-76], \
            dword ptr [rbp-80], dword ptr [rbp-84], 1
grf_next:
    inc     dword ptr [rbp-60]
    jmp     grf_lp
grf_done:
    mov     rcx, qword ptr [rbp-24]           ; also stretch the detail value columns
    call    gui_stretch_rows
    mov     rcx, qword ptr [rbp-24]           ; edge-dock the command controls (glyphs/buttons)
    call    gui_cmd_dock_layout
    mov     rcx, qword ptr [rbp-24]           ; fit the entry list inside the sidebar frame
    call    sidebar_layout
    WINCALL InvalidateRect, qword ptr [rbp-24], 0, 1   ; repaint the field cards at the new width
    FRAME_EPILOG
    ret
gui_reflow endp

; gui_stretch_rows(rcx=hdlg) - widen each field row's value control by the window's
;   horizontal growth from the base size, so the modular detail pane's fields grow
;   with the window (redesign responsive detail pane).  Called from gui_reflow and
;   at the end of gui_rows_layout so it survives a relayout.
gui_stretch_rows proc frame
    FRAME_PROLOG 144
    mov     qword ptr [rbp-24], rcx
    jmp     gsr_done                          ; DISABLED (2026-07): value boxes are a fixed
                                              ; width sized to clear the top-right action
                                              ; cluster, so they are no longer stretched to
                                              ; the full window width (they ran under it).
    WINCALL GetClientRect, qword ptr [rbp-24], addr rbp-48
    mov     eax, dword ptr [rbp-40]
    sub     eax, dword ptr [g_base_cx]
    mov     dword ptr [rbp-52], eax           ; dW
    cmp     eax, 0
    jle     gsr_done                          ; narrower/equal -> keep the base widths
    mov     dword ptr [rbp-56], 0             ; row i
gsr_lp:
    mov     eax, dword ptr [rbp-56]
    cmp     eax, dword ptr [g_field_count]
    jae     gsr_done
    mov     ecx, eax
    mov     edx, DS_VALUE
    call    dynid
    mov     dword ptr [rbp-60], eax
    WINCALL GetDlgItem, qword ptr [rbp-24], dword ptr [rbp-60]
    mov     qword ptr [rbp-64], rax
    test    rax, rax
    jz      gsr_next
    WINCALL GetWindowRect, qword ptr [rbp-64], addr rbp-96
    WINCALL MapWindowPoints, 0, qword ptr [rbp-24], addr rbp-96, 2
    mov     eax, dword ptr [rbp-96]           ; nx = L
    mov     dword ptr [rbp-68], eax
    mov     eax, dword ptr [rbp-92]           ; ny = T
    mov     dword ptr [rbp-72], eax
    mov     eax, dword ptr [rbp-88]           ; nw = (R - L) + dW
    sub     eax, dword ptr [rbp-96]
    add     eax, dword ptr [rbp-52]
    mov     dword ptr [rbp-76], eax
    mov     eax, dword ptr [rbp-84]           ; nh = B - T
    sub     eax, dword ptr [rbp-92]
    mov     dword ptr [rbp-80], eax
    WINCALL MoveWindow, qword ptr [rbp-64], dword ptr [rbp-68], dword ptr [rbp-72], \
            dword ptr [rbp-76], dword ptr [rbp-80], 1
gsr_next:
    inc     dword ptr [rbp-56]
    jmp     gsr_lp
gsr_done:
    FRAME_EPILOG
    ret
gui_stretch_rows endp

; dock_rect(rcx=hdlg, edx=id, r8=out{L,T,W,H}) -> rax=hwnd (0 if the control is
;   absent).  Fills the control's rect in CLIENT pixels.
dock_rect proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], r8
    WINCALL GetDlgItem, qword ptr [rbp-24], edx
    test    rax, rax
    jz      dr_null
    mov     qword ptr [rbp-40], rax
    WINCALL GetWindowRect, qword ptr [rbp-40], addr rbp-64      ; L-64 T-60 R-56 B-52
    WINCALL MapWindowPoints, 0, qword ptr [rbp-24], addr rbp-64, 2
    mov     r8, qword ptr [rbp-32]
    mov     eax, dword ptr [rbp-64]
    mov     dword ptr [r8+0], eax             ; L
    mov     eax, dword ptr [rbp-60]
    mov     dword ptr [r8+4], eax             ; T
    mov     eax, dword ptr [rbp-56]
    sub     eax, dword ptr [rbp-64]
    mov     dword ptr [r8+8], eax             ; W
    mov     eax, dword ptr [rbp-52]
    sub     eax, dword ptr [rbp-60]
    mov     dword ptr [r8+12], eax            ; H
    mov     rax, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
dr_null:
    xor     eax, eax
    FRAME_EPILOG
    ret
dock_rect endp

; --- gui_cmd_dock_layout local placement macros (rbp slots defined in the proc) ---
;   -128..-116 = dock_rect out{L,T,W,H}; -136 hwnd; -140 nx; -144 ny;
;   -72 running right edge; -52 cx; -56 cy; -60 marginx; -64 marginy; -68 gap
DOCK_RIGHT macro cid, bottomflag
    local skip
    mov     rcx, qword ptr [rbp-24]
    mov     edx, cid
    lea     r8, [rbp-128]
    call    dock_rect
    test    rax, rax
    jz      skip
    mov     qword ptr [rbp-136], rax
    mov     eax, dword ptr [rbp-72]           ; nx = right - W
    sub     eax, dword ptr [rbp-120]
    mov     dword ptr [rbp-140], eax
IF bottomflag
    mov     eax, dword ptr [rbp-56]           ; ny = cy - marginy - H (bottom-align)
    sub     eax, dword ptr [rbp-64]
    sub     eax, dword ptr [rbp-116]
ELSE
    mov     eax, dword ptr [rbp-124]          ; keep T
ENDIF
    mov     dword ptr [rbp-144], eax
    WINCALL MoveWindow, qword ptr [rbp-136], dword ptr [rbp-140], dword ptr [rbp-144], \
            dword ptr [rbp-120], dword ptr [rbp-116], 1
    mov     eax, dword ptr [rbp-140]          ; advance the right edge leftward past this + gap
    sub     eax, dword ptr [rbp-68]
    mov     dword ptr [rbp-72], eax
skip:
endm

; gui_cmd_dock_layout(rcx=hdlg) - dock the command controls to the window edges so
;   they track a resize: the header glyphs (More / Favorite / Edit) right-align on
;   their row; Save + Cancel right-align on the bottom border; + Add field rides the
;   bottom border but keeps its x.  Called at init and from gui_reflow (WM_SIZE).
gui_cmd_dock_layout proc frame
    FRAME_PROLOG 224
    mov     qword ptr [rbp-24], rcx
    WINCALL GetClientRect, qword ptr [rbp-24], addr rbp-48       ; L-48 T-44 R-40 B-36
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [rbp-52], eax           ; cx
    mov     eax, dword ptr [rbp-36]
    mov     dword ptr [rbp-56], eax           ; cy
    ; margins (12 DLU) -> px via MapDialogRect
    mov     dword ptr [rbp-96], 0
    mov     dword ptr [rbp-92], 0
    mov     dword ptr [rbp-88], 12
    mov     dword ptr [rbp-84], 12
    WINCALL MapDialogRect, qword ptr [rbp-24], addr rbp-96
    mov     eax, dword ptr [rbp-88]
    mov     dword ptr [rbp-60], eax           ; marginx
    mov     eax, dword ptr [rbp-84]
    mov     dword ptr [rbp-64], eax           ; marginy
    ; inter-control gap (4 DLU) -> px
    mov     dword ptr [rbp-96], 0
    mov     dword ptr [rbp-92], 0
    mov     dword ptr [rbp-88], 4
    mov     dword ptr [rbp-84], 0
    WINCALL MapDialogRect, qword ptr [rbp-24], addr rbp-96
    mov     eax, dword ptr [rbp-88]
    mov     dword ptr [rbp-68], eax           ; gap
    ; ---- header glyph row: More, Favorite, Edit (right -> left) ----
    mov     eax, dword ptr [rbp-52]
    sub     eax, dword ptr [rbp-60]
    mov     dword ptr [rbp-72], eax           ; right edge = cx - marginx
    DOCK_RIGHT IDC_V_OVFL, 0
    DOCK_RIGHT IDC_V_FAV, 0
    DOCK_RIGHT IDC_V_HDREDIT, 0
    ; ---- bottom row: Save, Cancel (right-aligned) ----
    mov     eax, dword ptr [rbp-52]
    sub     eax, dword ptr [rbp-60]
    mov     dword ptr [rbp-72], eax
    DOCK_RIGHT IDC_V_SAVE, 1
    DOCK_RIGHT IDC_V_CANCEL, 1
    ; ---- + Add field: keep its x, ride the bottom border ----
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_ADDFIELD
    lea     r8, [rbp-128]
    call    dock_rect
    test    rax, rax
    jz      dk_done
    mov     qword ptr [rbp-136], rax
    mov     eax, dword ptr [rbp-128]          ; keep L
    mov     dword ptr [rbp-140], eax
    mov     eax, dword ptr [rbp-56]           ; ny = cy - marginy - H
    sub     eax, dword ptr [rbp-64]
    sub     eax, dword ptr [rbp-116]
    mov     dword ptr [rbp-144], eax
    WINCALL MoveWindow, qword ptr [rbp-136], dword ptr [rbp-140], dword ptr [rbp-144], \
            dword ptr [rbp-120], dword ptr [rbp-116], 1
    ; ---- pagination bar: on the command-bar row (+Add field's y).  Positioned
    ;      here so it tracks the true bottom exactly when +Add is docked
    ;      (gui_page_bar only shows/hides + sets the text).  Edit mode: centre in
    ;      the free gap between + Add field and Cancel (so it clears the buttons);
    ;      view mode (no bottom buttons): centre on the detail pane. ----
    cmp     dword ptr [g_editmode], 0
    je      dk_pgview
    mov     eax, dword ptr [rbp-140]           ; + Add field right = L + W
    add     eax, dword ptr [rbp-120]
    add     eax, dword ptr [rbp-72]            ; + running right edge (Cancel's left)
    sar     eax, 1                             ; centre of the gap
    mov     dword ptr [rbp-148], eax
    jmp     dk_pghavex
dk_pgview:
    mov     dword ptr [rbp-96], 210            ; detail-pane left edge (DLU) -> px
    mov     dword ptr [rbp-92], 0
    mov     dword ptr [rbp-88], 210
    mov     dword ptr [rbp-84], 0
    WINCALL MapDialogRect, qword ptr [rbp-24], addr rbp-96
    mov     eax, dword ptr [rbp-96]            ; centre x = (detail_left + cx) / 2
    add     eax, dword ptr [rbp-52]
    sar     eax, 1
    mov     dword ptr [rbp-148], eax
dk_pghavex:
    mov     eax, dword ptr [rbp-144]            ; bar y = + Add field's docked top
    mov     dword ptr [rbp-152], eax
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_PGPREV
    mov     qword ptr [rbp-160], rax
    mov     eax, dword ptr [rbp-148]
    sub     eax, 48
    mov     dword ptr [rbp-164], eax
    WINCALL MoveWindow, qword ptr [rbp-160], dword ptr [rbp-164], dword ptr [rbp-152], 20, 20, 1
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_PGIND
    mov     qword ptr [rbp-160], rax
    mov     eax, dword ptr [rbp-148]
    sub     eax, 25
    mov     dword ptr [rbp-164], eax
    WINCALL MoveWindow, qword ptr [rbp-160], dword ptr [rbp-164], dword ptr [rbp-152], 50, 20, 1
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_PGNEXT
    mov     qword ptr [rbp-160], rax
    mov     eax, dword ptr [rbp-148]
    add     eax, 28
    mov     dword ptr [rbp-164], eax
    WINCALL MoveWindow, qword ptr [rbp-160], dword ptr [rbp-164], dword ptr [rbp-152], 20, 20, 1
    ; The centre differs per mode, so an edit<->view switch shifts all three.  A
    ; moved owner-draw/static control bit-blts its pixels and only invalidates the
    ; sliver it uncovers - the area it VACATED keeps its old paint, so a stale
    ; digit can sit where a chevron just landed.  Repaint the whole bar row,
    ; children included, whenever the bar is up.
    cmp     dword ptr [g_page_count], 1
    jle     dk_done
    mov     dword ptr [rbp-184], 0             ; strip {0, y-6, cx, y+30}
    mov     eax, dword ptr [rbp-152]
    sub     eax, 6
    mov     dword ptr [rbp-180], eax
    mov     eax, dword ptr [rbp-52]
    mov     dword ptr [rbp-176], eax
    mov     eax, dword ptr [rbp-152]
    add     eax, 30
    mov     dword ptr [rbp-172], eax
    WINCALL RedrawWindow, qword ptr [rbp-24], addr rbp-184, 0, 85h
dk_done:
    FRAME_EPILOG
    ret
gui_cmd_dock_layout endp

; sidebar_rect(rcx=hdlg, rdx=out{L,T,R,B}) - the sidebar frame rect in client px.
;   L/R + the gap are DLU (DPI-aware); T is a gap below the title strip and B a
;   matching gap above the window bottom, so the card scales with the window.
public sidebar_rect
sidebar_rect proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    WINCALL GetClientRect, qword ptr [rbp-24], addr rbp-64   ; L-64 T-60 R-56 B-52
    mov     dword ptr [rbp-48], SIDE_L_DLU        ; map {L, gap, R, gap} DLU -> px
    mov     dword ptr [rbp-44], SIDE_GAP_DLU      ; (scratch above the outgoing shadow zone)
    mov     dword ptr [rbp-40], SIDE_R_DLU
    mov     dword ptr [rbp-36], SIDE_GAP_DLU
    WINCALL MapDialogRect, qword ptr [rbp-24], addr rbp-48
    mov     r8, qword ptr [rbp-32]
    mov     eax, dword ptr [rbp-48]               ; L
    mov     dword ptr [r8+0], eax
    mov     eax, dword ptr [rbp-44]               ; gap (vertical) -> T = strip + gap
    add     eax, TBAR_H
    mov     dword ptr [r8+4], eax
    mov     eax, dword ptr [rbp-40]               ; R
    mov     dword ptr [r8+8], eax
    mov     eax, dword ptr [rbp-52]               ; B = client height - gap
    sub     eax, dword ptr [rbp-44]
    mov     dword ptr [r8+12], eax
    FRAME_EPILOG
    ret
sidebar_rect endp

; sidebar_layout(rcx=hdlg) - fit the entry list inside the sidebar frame: a thin
;   L/R inset so the selection reaches the border, and a slightly larger T/B inset
;   so the list ends above the frame.  Called at init and on WM_SIZE.
sidebar_layout proc frame
    FRAME_PROLOG 160                              ; MoveWindow's 6-arg spill reaches rbp-128,
                                                  ;   so the margin-button locals (-104/-112)
                                                  ;   have to sit above it
    mov     qword ptr [rbp-24], rcx
    lea     rdx, [rbp-48]                         ; frame rect {L,T,R,B}
    call    sidebar_rect
    mov     eax, dword ptr [rbp-48]               ; inner x = frameL + BORD_X
    add     eax, SIDE_BORD_X
    mov     dword ptr [rbp-64], eax
    mov     eax, dword ptr [rbp-40]               ; inner w = (frameR - frameL) - 2*BORD_X
    sub     eax, dword ptr [rbp-48]
    sub     eax, SIDE_BORD_X*2
    mov     dword ptr [rbp-72], eax
    ; --- search box: across the top of the frame ---
    mov     eax, dword ptr [rbp-44]               ; sy = frameT + BORD_Y
    add     eax, SIDE_BORD_Y
    mov     dword ptr [rbp-68], eax
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_SEARCH
    mov     qword ptr [rbp-88], rax               ; save hwnd: MoveWindow's mem args clobber rax
    WINCALL MoveWindow, qword ptr [rbp-88], dword ptr [rbp-64], dword ptr [rbp-68], \
            dword ptr [rbp-72], SIDE_SRCH_H, 1
    ; --- list: below the search box, down to just above the frame bottom ---
    mov     eax, dword ptr [rbp-68]               ; ly = sy + SRCH_H + SRCH_GAP
    add     eax, SIDE_SRCH_H + SIDE_SRCH_GAP
    mov     dword ptr [rbp-76], eax
    mov     eax, dword ptr [rbp-36]               ; lh = (frameB - BORD_Y) - ly
    sub     eax, SIDE_BORD_Y
    sub     eax, dword ptr [rbp-76]
    mov     dword ptr [rbp-80], eax
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_LIST
    mov     qword ptr [rbp-88], rax               ; save hwnd before the MoveWindow (rax clobber)
    WINCALL MoveWindow, qword ptr [rbp-88], dword ptr [rbp-64], dword ptr [rbp-76], \
            dword ptr [rbp-72], dword ptr [rbp-80], 1
    ; --- left margin: New at the list's top, Generate + Settings at its bottom ---
    ; Placed here rather than in frame_layout because they anchor to the LIST, and
    ; this is the proc that knows where it ended up (and re-runs on every WM_SIZE).
    mov     eax, dword ptr [rbp-48]               ; centre in the margin left of the frame
    sub     eax, MARGBTN_W
    sar     eax, 1
    cmp     eax, 2                                ; never let it slide under the frame edge
    jge     @F
    mov     eax, 2
@@: mov     dword ptr [rbp-96], eax               ; mx
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_T_NEW
    mov     qword ptr [rbp-88], rax
    WINCALL MoveWindow, qword ptr [rbp-88], dword ptr [rbp-96], dword ptr [rbp-76], \
            MARGBTN_W, MARGBTN_W, 1               ; top edge == list top
    mov     eax, dword ptr [rbp-76]               ; settings: bottom edge == list bottom
    add     eax, dword ptr [rbp-80]
    sub     eax, MARGBTN_W
    mov     dword ptr [rbp-104], eax
    mov     eax, dword ptr [rbp-104]              ; generate: stacked directly above it
    sub     eax, MARGBTN_W + MARGBTN_GAP
    mov     dword ptr [rbp-112], eax
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_T_GEN
    mov     qword ptr [rbp-88], rax
    WINCALL MoveWindow, qword ptr [rbp-88], dword ptr [rbp-96], dword ptr [rbp-112], \
            MARGBTN_W, MARGBTN_W, 1
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_T_SET
    mov     qword ptr [rbp-88], rax
    WINCALL MoveWindow, qword ptr [rbp-88], dword ptr [rbp-96], dword ptr [rbp-104], \
            MARGBTN_W, MARGBTN_W, 1
    FRAME_EPILOG
    ret
sidebar_layout endp

; gui_draw_flatchevron(rcx=lpdis) - draw a reorder chevron as a bare dim glyph on
;   the dialog bg (no button chrome).  Up for DS_UP, down otherwise.
gui_draw_flatchevron proc frame
    FRAME_PROLOG 160
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax            ; hdc
    ; chevrons sit inside the tile in card layouts -> blend with the panel;
    ; flat (Compact) has no card -> blend with the dialog background
    mov     eax, dword ptr [g_col_bg]
    mov     r11d, dword ptr [g_layout]
    lea     r10, [lay_band]
    cmp     dword ptr [r10+r11*4], 0
    je      gfv_bgok
    mov     eax, dword ptr [g_col_panel]
gfv_bgok:
    WINCALL CreateSolidBrush, eax
    mov     qword ptr [rbp-40], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [rbp-40]
    WINCALL DeleteObject, qword ptr [rbp-40]
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [r10+4]             ; ctl id -> slot
    sub     eax, IDC_DYN_BASE
    and     eax, DYN_SLOTS-1
    mov     ecx, 0E70Eh                        ; ChevronUp
    cmp     eax, DS_UP
    je      gfv_have
    mov     ecx, 0E70Dh                        ; ChevronDown
gfv_have:
    mov     word ptr [g_glyph_w], cx
    mov     word ptr [g_glyph_w+2], 0
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_chevfont]
    mov     qword ptr [rbp-48], rax            ; old font
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_textdim]
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-104], eax           ; L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-100], eax           ; T
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-96], eax            ; R
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-92], eax            ; B
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_glyph_w, -1, addr rbp-104, DT_IMGFLAGS
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-48]
    FRAME_EPILOG
    ret
gui_draw_flatchevron endp

; gui_entry_matches(ecx = entry index) -> eax = 1 if any non-sensitive field
;   (value or custom label) contains the current g_search_w query, else 0.
;   Secret and TOTP fields are skipped entirely.  Assumes g_search_w is non-empty
;   and already upper-cased.
gui_entry_matches proc frame
    FRAME_PROLOG 112
    mov     dword ptr [rbp-24], ecx              ; idx
    call    vault_field_count                    ; ecx still = idx
    mov     dword ptr [rbp-32], eax              ; n
    mov     dword ptr [rbp-40], 0               ; j
gem_loop:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [rbp-32]
    jae     gem_no
    mov     ecx, dword ptr [rbp-24]
    mov     edx, dword ptr [rbp-40]
    lea     r8, [rbp-88]                         ; out struct: -88 kind, -80 lblptr,
    call    vault_field_get                      ;   -72 lbllen, -64 valptr, -56 vallen
    test    eax, eax
    jz      gem_next
    mov     eax, dword ptr [rbp-88]              ; kind
    cmp     eax, VF_SECRET                       ; sensitive -> never searched
    je      gem_next
    cmp     eax, VF_TOTP
    je      gem_next
    mov     rcx, qword ptr [rbp-64]              ; value ptr
    mov     edx, dword ptr [rbp-56]             ; value len
    call    gem_field
    test    eax, eax
    jnz     gem_yes
    mov     rax, qword ptr [rbp-72]             ; label len
    test    rax, rax
    jz      gem_next
    mov     rcx, qword ptr [rbp-80]             ; label ptr
    mov     edx, dword ptr [rbp-72]
    call    gem_field
    test    eax, eax
    jnz     gem_yes
gem_next:
    inc     dword ptr [rbp-40]
    jmp     gem_loop
gem_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
gem_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_entry_matches endp

; gem_field(rcx = utf8 ptr, edx = byte len) -> eax = 1 if the folded text contains
;   the g_search_w query.  Converts to wide in g_match_w, upper-cases, substring-scans.
gem_field proc frame
    FRAME_PROLOG 32
    test    rcx, rcx
    jz      gf_no
    test    edx, edx
    jz      gf_no
    lea     r8, [g_match_w]
    mov     r9d, EBUF*2-1
    call    gui_towide                           ; eax = wide chars written
    test    eax, eax
    jz      gf_no
    WINCALL CharUpperBuffW, addr g_match_w, eax
    lea     rcx, [g_match_w]
    lea     rdx, [g_search_w]
    call    wide_find
    FRAME_EPILOG
    ret
gf_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gem_field endp

; wide_find(rcx = haystack, rdx = needle) -> eax = 1 if needle is a substring of
;   haystack (both NUL-terminated wide).  Leaf; needle assumed non-empty.
wide_find proc
    mov     r8, rcx                              ; hay cursor
wf_outer:
    cmp     word ptr [r8], 0
    je      wf_no
    mov     r9, r8                               ; hay compare ptr
    mov     r10, rdx                             ; needle ptr
wf_inner:
    mov     ax, word ptr [r10]
    test    ax, ax
    jz      wf_yes                               ; needle exhausted -> match
    mov     r11w, word ptr [r9]
    test    r11w, r11w
    jz      wf_no                                ; hay ended first
    cmp     ax, r11w
    jne     wf_adv
    add     r9, 2
    add     r10, 2
    jmp     wf_inner
wf_adv:
    add     r8, 2
    jmp     wf_outer
wf_yes:
    mov     eax, 1
    ret
wf_no:
    xor     eax, eax
    ret
wide_find endp

; fuzzy_score(rcx = needle wide, rdx = hay wide; both NUL-terminated, pre-folded to
;   upper case) -> eax = match score (>=0), or -1 if the needle does not match.
;   The needle is split on spaces into terms; EVERY term must appear in the hay as
;   an ordered subsequence (terms themselves are order-independent - each is scanned
;   from the start of the hay).  Bonuses: word-start (FZ_WORDSTART), contiguity with
;   the previous matched char (FZ_CONTIG), plus FZ_BASE per char.  Empty needle -> 0.
;   Leaf; clobbers rax/r8/r9/r10/r11.  rcx/rdx preserved conceptually (rcx advances
;   via r10, rdx stays as the hay base).
public fuzzy_score
fuzzy_score proc
    xor     eax, eax                         ; score accumulator
    mov     r10, rcx                         ; needle cursor
    mov     r8, rdx                          ; hay cursor (starts at base)
    mov     r9d, -1                          ; prev matched position (chars) in hay
fz_need:
    movzx   ecx, word ptr [r10]
    test    cx, cx
    jz      fz_ok                            ; needle consumed -> success
    cmp     cx, ' '
    jne     fz_find
    add     r10, 2                           ; term separator: reset hay scan, new term
    mov     r8, rdx
    mov     r9d, -1
    jmp     fz_need
fz_find:
    movzx   r11d, word ptr [r8]
    test    r11w, r11w
    jz      fz_nomatch                       ; hay ended before this term char -> fail
    cmp     r11w, cx
    je      fz_hit
    add     r8, 2
    jmp     fz_find
fz_hit:
    add     eax, FZ_BASE
    mov     r11, r8                          ; pos = (cursor - base) / 2
    sub     r11, rdx
    shr     r11, 1                           ; r11 = matched char position
    test    r11, r11
    jz      fz_ws                            ; position 0 -> word start
    mov     ecx, dword ptr [rdx+r11*2-2]     ; hay[pos-1]
    cmp     cx, ' '
    je      fz_ws
    cmp     cx, '-'
    je      fz_ws
    cmp     cx, '_'
    je      fz_ws
    cmp     cx, '/'
    je      fz_ws
    cmp     cx, '.'
    je      fz_ws
    cmp     cx, ':'
    je      fz_ws
    jmp     fz_ctg
fz_ws:
    add     eax, FZ_WORDSTART
fz_ctg:
    mov     ecx, r9d
    inc     ecx
    cmp     r11d, ecx                        ; pos == prev+1 -> contiguous
    jne     fz_adv
    add     eax, FZ_CONTIG
fz_adv:
    mov     r9d, r11d                        ; prev = pos
    add     r8, 2                            ; advance hay + needle
    add     r10, 2
    jmp     fz_need
fz_ok:
    ret
fz_nomatch:
    mov     eax, -1
    ret
fuzzy_score endp

; gui_entry_fuzzy(ecx = entry index) -> eax = best fuzzy score across the entry's
;   non-sensitive fields (value + custom label), or -1 if nothing matched g_search_w.
;   Mirrors gui_entry_matches but scores instead of boolean-matching.
gui_entry_fuzzy proc frame
    FRAME_PROLOG 112
    mov     dword ptr [rbp-24], ecx              ; idx
    mov     dword ptr [rbp-96], -1               ; best score
    call    vault_field_count                    ; ecx still = idx
    mov     dword ptr [rbp-32], eax              ; n
    mov     dword ptr [rbp-40], 0               ; j
gef_loop:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [rbp-32]
    jae     gef_done
    mov     ecx, dword ptr [rbp-24]
    mov     edx, dword ptr [rbp-40]
    lea     r8, [rbp-88]                         ; out: -88 kind,-80 lblptr,-72 lbllen,
    call    vault_field_get                      ;      -64 valptr,-56 vallen
    test    eax, eax
    jz      gef_next
    mov     eax, dword ptr [rbp-88]              ; kind
    cmp     eax, VF_SECRET                       ; sensitive -> never searched
    je      gef_next
    cmp     eax, VF_TOTP
    je      gef_next
    mov     rcx, qword ptr [rbp-64]              ; value ptr
    mov     edx, dword ptr [rbp-56]             ; value len
    call    gef_field
    cmp     eax, dword ptr [rbp-96]
    jle     gef_trylabel
    mov     dword ptr [rbp-96], eax
gef_trylabel:
    mov     rax, qword ptr [rbp-72]             ; label len
    test    rax, rax
    jz      gef_next
    mov     rcx, qword ptr [rbp-80]             ; label ptr
    mov     edx, dword ptr [rbp-72]
    call    gef_field
    cmp     eax, dword ptr [rbp-96]
    jle     gef_next
    mov     dword ptr [rbp-96], eax
gef_next:
    inc     dword ptr [rbp-40]
    jmp     gef_loop
gef_done:
    mov     eax, dword ptr [rbp-96]
    FRAME_EPILOG
    ret
gui_entry_fuzzy endp

; gef_field(rcx = utf8 ptr, edx = byte len) -> eax = fuzzy score of the folded text
;   against g_search_w, or -1.  Converts to wide in g_match_w, upper-cases, scores.
gef_field proc frame
    FRAME_PROLOG 32
    test    rcx, rcx
    jz      gff_no
    test    edx, edx
    jz      gff_no
    lea     r8, [g_match_w]
    mov     r9d, EBUF*2-1
    call    gui_towide                           ; eax = wide chars written
    test    eax, eax
    jz      gff_no
    WINCALL CharUpperBuffW, addr g_match_w, eax
    lea     rcx, [g_search_w]
    lea     rdx, [g_match_w]
    call    fuzzy_score
    FRAME_EPILOG
    ret
gff_no:
    mov     eax, -1
    FRAME_EPILOG
    ret
gef_field endp

; gui_lb_seldata(rcx = hdlg) -> eax = entry index of the selected row, or -1 if
;   nothing is selected.  The row's item data IS the vault entry index.
gui_lb_seldata proc frame
    FRAME_PROLOG 64                             ; 64 -> alloc 80: the 5th-arg spill slot
                                               ; [rsp+32]=[rbp-48] must clear the live
                                               ; [rbp-32] cursel (arg4 source below).  A
                                               ; smaller frame (48->alloc 64) put arg5 AT
                                               ; [rbp-32], so LB_GETITEMDATA's lParam=0
                                               ; store zeroed the index -> always row 0.
    mov     qword ptr [rbp-24], rcx
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_GETCURSEL, 0, 0
    mov     dword ptr [rbp-32], eax
    cmp     eax, LB_ERR
    je      gls_none
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_GETITEMDATA, \
            dword ptr [rbp-32], 0               ; item data = entry index (single vault)
    mov     dword ptr [rbp-40], eax
    call    vault_count                         ; guard a stale index (pre-repopulate paint)
    cmp     dword ptr [rbp-40], eax
    jae     gls_none
    mov     eax, dword ptr [rbp-40]
    FRAME_EPILOG
    ret
gls_none:
    mov     eax, -1
    FRAME_EPILOG
    ret
gui_lb_seldata endp

; gui_lb_selbydata(rcx = hdlg, edx = entry index) -> eax = selected row, or -1.
;   Reselects the list row whose item data (the entry index) matches - used to
;   restore the selection after a repopulate.
gui_lb_selbydata proc frame
    FRAME_PROLOG 80                              ; 80 -> alloc 96: the 5th-arg spill slot
                                                ; [rsp+32]=[rbp-64] must clear the live
                                                ; [rbp-32] target (held across the whole
                                                ; loop).  A smaller frame put arg5 AT
                                                ; [rbp-32], so every LB_* call's lParam=0
                                                ; store zeroed the target -> matched row 0.
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx              ; target entry index
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_GETCOUNT, 0, 0
    mov     dword ptr [rbp-40], eax              ; row count
    mov     dword ptr [rbp-48], 0               ; i
glb_loop:
    mov     eax, dword ptr [rbp-48]
    cmp     eax, dword ptr [rbp-40]
    jae     glb_none
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_GETITEMDATA, \
            dword ptr [rbp-48], 0               ; item data = entry index
    cmp     eax, dword ptr [rbp-32]
    jne     glb_next
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_SETCURSEL, \
            dword ptr [rbp-48], 0
    mov     eax, dword ptr [rbp-48]
    FRAME_EPILOG
    ret
glb_next:
    inc     dword ptr [rbp-48]
    jmp     glb_loop
glb_none:
    mov     eax, -1
    FRAME_EPILOG
    ret
gui_lb_selbydata endp

; gui_copy_topmost(rcx = hdlg) - copy the first Secret of the top (first) listed
;   record to the clipboard (auto-clear armed).  No-op if the list is empty or the
;   top record has no Secret field.
gui_copy_topmost proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_GETCOUNT, 0, 0
    test    eax, eax
    jz      gct_done                             ; empty list
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_GETITEMDATA, 0, 0
    cmp     eax, 0                               ; topmost entry index (item data)
    jl      gct_done
    mov     dword ptr [rbp-32], eax
    call    vault_count
    cmp     dword ptr [rbp-32], eax
    jae     gct_done
    mov     ecx, dword ptr [rbp-32]              ; topmost entry index
    mov     edx, VF_SECRET
    lea     r8, [rbp-40]                         ; &len
    call    vault_field_at                       ; rax = first secret ptr
    test    rax, rax
    jz      gct_done                             ; no password on that record
    mov     rcx, rax
    mov     edx, dword ptr [rbp-40]
    lea     r8, [g_match_w]
    mov     r9d, EBUF*2-1
    call    gui_towide
    lea     rdx, [g_match_w]
    mov     rcx, qword ptr [rbp-24]
    call    gui_copy
    lea     rcx, [g_match_w]                     ; scrub the staged plaintext
    mov     edx, EBUF*4
    call    secure_zero
gct_done:
    FRAME_EPILOG
    ret
gui_copy_topmost endp

; =============================================================================
; gui_showdetail(rcx = hdlg, edx = index) - fill the detail fields; secret is
;   captured into g_secret_w and shown masked.
; =============================================================================
gui_showdetail proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [g_revealed], 0
    mov     dword ptr [g_cur_idx], edx
    mov     dword ptr [g_dirty], 0
    mov     dword ptr [g_cur_page], 0         ; each entry opens on its first page
    mov     dword ptr [g_new_pending], 0      ; navigating to an entry clears the "just-added" flag
    mov     dword ptr [g_loading], 1          ; suppress EN_CHANGE dirty while loading
    mov     dword ptr [g_totp_on], 0
    mov     dword ptr [g_totp_row], -1
    mov     qword ptr [g_totp_codehwnd], 0
    mov     qword ptr [g_totp_barhwnd], 0
    mov     rcx, qword ptr [rbp-24]           ; drop any revealed-secret color overlay
    call    gui_colorpw_hide
    mov     ecx, dword ptr [rbp-32]           ; favorite state for this entry
    call    gui_entry_is_fav
    mov     dword ptr [g_fav_state], eax
    mov     ecx, dword ptr [rbp-32]           ; soft-delete (trash) state for this entry
    call    gui_entry_is_deleted
    mov     dword ptr [g_deleted_state], eax
    test    eax, eax
    jz      gsd_nodel
    mov     ecx, dword ptr [rbp-32]           ; preserve the original deletion timestamp
    mov     edx, VF_DELETED
    lea     r8, [rbp-48]
    call    vault_field_at
    test    rax, rax
    jz      gsd_nodel
    mov     rcx, rax
    mov     edx, dword ptr [rbp-48]
    lea     r8, [g_deleted_ft]
    mov     r9d, 17
    call    gui_towide
gsd_nodel:
    mov     ecx, dword ptr [rbp-32]           ; custom icon override for this entry
    call    gui_entry_icon
    mov     dword ptr [g_icon_set], eax
    test    eax, eax
    jz      gsd_noicon
    mov     eax, dword ptr [g_ovr_glyph]
    mov     dword ptr [g_icon_glyph], eax
    mov     eax, dword ptr [g_ovr_color]
    mov     dword ptr [g_icon_color], eax
gsd_noicon:
    ; stop any prior live-code timer and tear down old rows
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-24]
    mov     edx, TOTP_TIMER
    call    KillTimer
    add     rsp, 32
    mov     rcx, qword ptr [rbp-24]
    call    gui_rows_clear
    call    tf_reset                             ; start the attachments tile empty
    call    pwh_reset                            ; start password history empty
    ; Title (fixed control)
    mov     ecx, dword ptr [rbp-32]
    mov     edx, VF_TITLE
    lea     r8, [rbp-48]
    call    vault_field_at
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_TITLE
    mov     r8, rax
    mov     r9d, dword ptr [rbp-48]
    call    gui_setfield
    ; walk every field by position; build one row per non-title field
    mov     ecx, dword ptr [rbp-32]
    call    vault_field_count
    mov     dword ptr [rbp-52], eax              ; n
    mov     dword ptr [rbp-40], 0                ; j
gsd_floop:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [rbp-52]
    jae     gsd_fdone
    mov     ecx, dword ptr [rbp-32]
    mov     edx, dword ptr [rbp-40]
    lea     r8, [rbp-96]                         ; out struct (kind/lbl/val)
    call    vault_field_get
    mov     eax, dword ptr [rbp-96]              ; out.kind
    cmp     eax, VF_TITLE
    je      gsd_fnext
    cmp     eax, VF_FAV                          ; reserved favorite marker: not a row
    je      gsd_fnext
    cmp     eax, VF_ICON                         ; reserved icon override: not a row
    je      gsd_fnext
    cmp     eax, VF_PWHIST                       ; archived old password: not a row
    je      gsd_pwhist
    cmp     eax, VF_DELETED                      ; soft-delete marker: not a row
    je      gsd_fnext
    cmp     eax, VF_IMAGE                        ; attachments collapse into one tile
    je      gsd_attach
    cmp     eax, VF_FILE
    je      gsd_attach
    mov     rcx, qword ptr [rbp-24]
    mov     edx, eax
    call    gui_row_add                          ; eax = row (-1 if full)
    cmp     eax, 0
    jl      gsd_fdone
    mov     dword ptr [rbp-44], eax              ; row
    ; custom label (if the field carried one)
    mov     rax, qword ptr [rbp-80]              ; out.labellen
    test    rax, rax
    jz      gsd_setval
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_LABEL
    call    dynid
    mov     rcx, qword ptr [rbp-24]
    mov     edx, eax
    mov     r8, qword ptr [rbp-88]              ; labelptr
    mov     r9d, dword ptr [rbp-80]             ; labellen
    call    gui_setfield
    mov     eax, dword ptr [rbp-44]
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    or      dword ptr [r10+FD_FLAGS], FDF_LABELED
gsd_setval:
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_VALUE
    call    dynid
    mov     rcx, qword ptr [rbp-24]
    mov     edx, eax
    mov     r8, qword ptr [rbp-72]              ; valptr
    mov     r9d, dword ptr [rbp-64]             ; vallen
    call    gui_setfield
    ; remember this field's original (effective label, value) for per-tile history
    mov     edx, dword ptr [rbp-80]             ; labellen
    test    edx, edx
    jnz     gsd_cap_custom
    mov     edx, dword ptr [rbp-96]             ; unlabeled -> the kind's default label
    call    kind_label                          ;   (wide) so both sides key the same way
    mov     rcx, rax
    xor     edx, edx
    jmp     gsd_cap_go
gsd_cap_custom:
    mov     rcx, qword ptr [rbp-88]             ; custom label (utf8, len in edx)
gsd_cap_go:
    mov     r8, qword ptr [rbp-72]              ; value (utf8)
    mov     r9d, dword ptr [rbp-64]
    call    pworig_add
    mov     eax, dword ptr [rbp-96]             ; kind
    cmp     eax, VF_SECRET
    je      gsd_secret
    cmp     eax, VF_TOTP
    je      gsd_mask
    jmp     gsd_fnext
gsd_secret:
    ; grade the password for the strength badge (uses the plaintext value)
    mov     rcx, qword ptr [rbp-72]            ; valptr (utf8)
    mov     edx, dword ptr [rbp-64]            ; vallen
    call    gui_pw_grade                       ; eax = 0..3
    shl     eax, FDF_PWLVL_SHIFT
    mov     ecx, dword ptr [rbp-44]           ; row
    imul    ecx, ecx, DESCSZ
    lea     r10, [g_fields]
    add     r10, rcx
    mov     edx, dword ptr [r10+FD_FLAGS]
    and     edx, NOT FDF_PWLVL_MASK           ; preserve other flag bits
    or      edx, eax
    mov     dword ptr [r10+FD_FLAGS], edx
    jmp     gsd_mask                          ; (original value already captured above)
gsd_mask:
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_VALUE
    call    dynid
    mov     dword ptr [rbp-56], eax
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], dword ptr [rbp-56], \
            EM_SETPASSWORDCHAR, SECRET_MASK, 0
    jmp     gsd_fnext
gsd_attach:
    ; append this file to the attachments tile; create the tile row only once
    mov     eax, dword ptr [rbp-64]             ; vallen
    cmp     eax, 68
    jb      gsd_attach_row                      ; < 68: no valid AttachRef -> skip the file
    mov     rcx, qword ptr [rbp-72]             ; valptr -> AttachRef
    lea     rdx, [g_empty_w]                    ; default: no filename (vallen == 68)
    jbe     @F
    lea     rdx, [rcx+68]                       ; filename wide (at value+68)
@@: call    tf_append
gsd_attach_row:
    call    tf_find_row
    cmp     eax, -1
    jne     gsd_fnext                           ; tile row already created
    mov     rcx, qword ptr [rbp-24]
    mov     edx, VF_FILE
    call    gui_row_add
    jmp     gsd_fnext
gsd_pwhist:
    ; reserved archive {u64 filetime, label wide\0, value wide\0, u32 action} ->
    ; g_pwhist (not a row).  Two older shapes still load: no action word (reads as
    ; PWHA_CHANGED), and no label either - just {u64 filetime, pw wide\0}.
    mov     eax, dword ptr [rbp-64]             ; vallen
    cmp     eax, 10
    jb      gsd_fnext                           ; need the filetime + a NUL
    mov     r10, qword ptr [rbp-72]             ; valptr
    mov     r11, r10                            ; value end = valptr + vallen
    add     r11, rax
    mov     rcx, qword ptr [r10]                ; filetime qword
    lea     r8, [r10+8]                         ; scan string1 to its NUL
    xor     eax, eax
gsd_ph_scan:
    cmp     r8, r11                             ; never scan past the value
    jae     gsd_ph_s1end
    cmp     word ptr [r8], 0
    je      gsd_ph_s1end
    add     r8, 2
    inc     eax
    cmp     eax, 255
    jb      gsd_ph_scan
gsd_ph_s1end:
    add     r8, 2                               ; past string1's NUL
    xor     r9d, r9d                            ; action defaults to PWHA_CHANGED
    cmp     r8, r11
    jb      gsd_ph_new                          ; a second string follows -> labelled format
    lea     rdx, [kl_secret]                    ; oldest format: label = "Password",
    lea     r8, [r10+8]                         ;                pw = value+8
    call    pwh_append
    jmp     gsd_fnext
gsd_ph_new:
    lea     rdx, [r10+8]                        ; label = value+8, value = past its NUL
    mov     rax, r8                             ; scan the value; a u32 action may follow it
gsd_ph_scan2:
    cmp     rax, r11
    jae     gsd_ph_go
    cmp     word ptr [rax], 0
    je      gsd_ph_s2end
    add     rax, 2
    jmp     gsd_ph_scan2
gsd_ph_s2end:
    add     rax, 6                              ; past the NUL + the u32 action
    cmp     rax, r11
    ja      gsd_ph_go                           ; no room -> pre-action record, keep CHANGED
    mov     r9d, dword ptr [rax-4]
    cmp     r9d, PWHA_ADDED                     ; unknown action -> treat as CHANGED
    jbe     gsd_ph_go
    xor     r9d, r9d
gsd_ph_go:
    call    pwh_append
    jmp     gsd_fnext
gsd_fnext:
    inc     dword ptr [rbp-40]
    jmp     gsd_floop
gsd_fdone:
    mov     rcx, qword ptr [rbp-24]
    call    gui_rows_layout
    mov     rcx, qword ptr [rbp-24]           ; hand-cursor subclass on URL value edits
    call    gui_subclass_urls
    mov     rcx, qword ptr [rbp-24]           ; repaint the header tile+title for this entry
    mov     edx, IDC_V_HEADER
    call    GetDlgItem
    WINCALL InvalidateRect, rax, 0, 1
    mov     rcx, qword ptr [rbp-24]           ; favorite star glyph
    call    gui_update_fav_glyph
    mov     rcx, qword ptr [rbp-24]
    call    gui_arm_totp
    mov     dword ptr [g_loading], 0
    mov     dword ptr [g_dirty], 0
    FRAME_EPILOG
    ret
gui_showdetail endp

; gui_totp_refresh(rcx = hdlg) - recompute the live code + countdown and show it.
gui_totp_refresh proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_totp_on], 0
    je      gtr_done
    lea     rcx, [g_totp_b32]
    mov     edx, dword ptr [g_totp_b32len]
    lea     r8, [g_totp_code6]
    call    totp_from_b32
    test    eax, eax
    jz      gtr_bad
    ; code as wide (for the clipboard copy button)
    lea     rcx, [g_totp_code6]
    mov     edx, 6
    lea     r8, [g_totp_code_w]
    mov     r9d, 15
    call    gui_towide
    ; show the code grouped "nnn nnn" (display only; g_totp_code_w stays 6 digits)
    movzx   eax, word ptr [g_totp_code_w]
    mov     word ptr [g_totp_disp_w], ax
    movzx   eax, word ptr [g_totp_code_w+2]
    mov     word ptr [g_totp_disp_w+2], ax
    movzx   eax, word ptr [g_totp_code_w+4]
    mov     word ptr [g_totp_disp_w+4], ax
    mov     word ptr [g_totp_disp_w+6], ' '
    movzx   eax, word ptr [g_totp_code_w+6]
    mov     word ptr [g_totp_disp_w+8], ax
    movzx   eax, word ptr [g_totp_code_w+8]
    mov     word ptr [g_totp_disp_w+10], ax
    movzx   eax, word ptr [g_totp_code_w+10]
    mov     word ptr [g_totp_disp_w+12], ax
    mov     word ptr [g_totp_disp_w+14], 0
    WINCALL SetWindowTextW, qword ptr [g_totp_codehwnd], addr g_totp_disp_w
    call    totp_secs_left                  ; eax = seconds left (1..30)
    mov     dword ptr [g_totp_secs], eax
    WINCALL InvalidateRect, qword ptr [g_totp_barhwnd], 0, 1
    FRAME_EPILOG
    ret
gtr_bad:
    WINCALL SetWindowTextW, qword ptr [g_totp_codehwnd], 0
gtr_done:
    FRAME_EPILOG
    ret
gui_totp_refresh endp

; (gui_reveal / gui_reveal_tkey removed - per-row reveal is gui_row_reveal.)

; gui_copy(rcx = hdlg, rdx = wide NUL-terminated source) - copy to the clipboard
;   and arm a timer to auto-clear it after g_clip_secs seconds (0 = off; only if
;   the copy is still ours).
; gui_clip_markers() - while the clipboard is open, attach the three Windows
;   markers that keep the current content out of clipboard history (Win+V), out
;   of the cloud clipboard, and out of clipboard-monitor processing.  Each
;   marker is its own zero-init HGLOBAL (the clipboard takes ownership).  Idempo-
;   tently registers the formats on first use.  Best-effort - failures are
;   silently ignored (the copy + auto-clear still work).
gui_clip_markers proc frame
    FRAME_PROLOG 32
    cmp     dword ptr [g_cf_hist], 0            ; register the formats once
    jne     cm_have
    WINCALL RegisterClipboardFormatW, addr cf_hist_name
    mov     dword ptr [g_cf_hist], eax
    WINCALL RegisterClipboardFormatW, addr cf_cloud_name
    mov     dword ptr [g_cf_cloud], eax
    WINCALL RegisterClipboardFormatW, addr cf_excl_name
    mov     dword ptr [g_cf_excl], eax
cm_have:
    cmp     dword ptr [g_cf_hist], 0           ; CanIncludeInClipboardHistory = 0
    je      cm_cloud
    WINCALL GlobalAlloc, <GMEM_MOVEABLE or GMEM_ZEROINIT>, 4
    test    rax, rax
    jz      cm_cloud
    WINCALL SetClipboardData, dword ptr [g_cf_hist], rax
cm_cloud:
    cmp     dword ptr [g_cf_cloud], 0          ; CanUploadToCloudClipboard = 0
    je      cm_excl
    WINCALL GlobalAlloc, <GMEM_MOVEABLE or GMEM_ZEROINIT>, 4
    test    rax, rax
    jz      cm_excl
    WINCALL SetClipboardData, dword ptr [g_cf_cloud], rax
cm_excl:
    cmp     dword ptr [g_cf_excl], 0           ; ExcludeClipboardContentFromMonitorProcessing
    je      cm_done
    WINCALL GlobalAlloc, <GMEM_MOVEABLE or GMEM_ZEROINIT>, 4
    test    rax, rax
    jz      cm_done
    WINCALL SetClipboardData, dword ptr [g_cf_excl], rax
cm_done:
    FRAME_EPILOG
    ret
gui_clip_markers endp

gui_copy proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-40], rcx         ; hdlg (for SetTimer)
    mov     qword ptr [rbp-48], rdx         ; source wide ptr
    ; wide length (chars) incl NUL
    mov     r10, rdx
    xor     ecx, ecx
gc_len:
    cmp     word ptr [r10+rcx*2], 0
    je      gc_lend
    inc     ecx
    cmp     ecx, EBUF*2
    jb      gc_len
gc_lend:
    inc     ecx                             ; include NUL
    mov     dword ptr [rbp-32], ecx
    ; bytes = chars*2
    mov     eax, ecx
    shl     eax, 1
    WINCALL GlobalAlloc, GMEM_MOVEABLE, eax
    test    rax, rax
    jz      gc_done
    mov     qword ptr [rbp-24], rax         ; hMem
    WINCALL GlobalLock, rax
    test    rax, rax
    jz      gc_done
    ; copy the source (chars) into the locked block
    mov     r11, rax                        ; dst
    mov     r10, qword ptr [rbp-48]         ; src
    xor     r8d, r8d
gc_cp:
    cmp     r8d, dword ptr [rbp-32]
    jae     gc_cpd
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    inc     r8d
    jmp     gc_cp
gc_cpd:
    WINCALL GlobalUnlock, qword ptr [rbp-24]
    WINCALL OpenClipboard, 0
    test    eax, eax
    jz      gc_done
    WINCALL EmptyClipboard
    WINCALL SetClipboardData, CF_UNICODETEXT, qword ptr [rbp-24]
    call    gui_clip_markers                ; exclude from history / cloud / monitors
    WINCALL CloseClipboard
    ; remember the clipboard state and arm the auto-clear timer
    WINCALL GetClipboardSequenceNumber
    mov     dword ptr [g_clip_seq], eax
    WINCALL KillTimer, qword ptr [rbp-40], CLIP_TIMER     ; cancel any prior
    mov     eax, dword ptr [g_clip_secs]        ; 0 = never auto-clear
    test    eax, eax
    jz      gc_done
    imul    eax, eax, 1000                      ; seconds -> ms
    mov     r10d, eax                           ; stage off the arg regs (r9 is arg4)
    WINCALL SetTimer, qword ptr [rbp-40], CLIP_TIMER, r10d, 0
gc_done:
    FRAME_EPILOG
    ret
gui_copy endp

; gui_clipclear() - if the clipboard still holds the secret we copied (unchanged
;   sequence number), empty it; otherwise leave the user's newer content alone.
gui_clipclear proc frame
    FRAME_PROLOG 32
    cmp     dword ptr [g_clip_seq], 0
    je      gcc_done
    WINCALL GetClipboardSequenceNumber
    cmp     eax, dword ptr [g_clip_seq]
    jne     gcc_keep                        ; changed since our copy -> don't touch
    WINCALL OpenClipboard, 0
    test    eax, eax
    jz      gcc_keep
    WINCALL EmptyClipboard
    WINCALL CloseClipboard
gcc_keep:
    mov     dword ptr [g_clip_seq], 0
gcc_done:
    FRAME_EPILOG
    ret
gui_clipclear endp

; gui_gather(rcx = hdlg) - read Title + every row into the ordered descriptor
;   array g_field_list[] (g_field_n) that vault_build_entry consumes.  Values go
;   into g_valblob, custom labels into g_lblblob; a row whose label still matches
;   its kind default is stored unlabelled.
gui_gather proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx             ; hdlg
    lea     rax, [g_valblob]
    mov     qword ptr [rbp-40], rax             ; vc (value cursor)
    mov     dword ptr [rbp-48], 32768           ; vcap (wide chars left)
    lea     rax, [g_lblblob]
    mov     qword ptr [rbp-56], rax             ; lc (label cursor)
    ; field 0 = Title
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_V_TITLE, qword ptr [rbp-40], dword ptr [rbp-48]
    lea     r10, [g_field_list]
    mov     qword ptr [r10+0], VF_TITLE
    mov     qword ptr [r10+8], 0
    mov     r11, qword ptr [rbp-40]
    mov     qword ptr [r10+16], r11
    inc     eax
    mov     edx, eax
    sub     dword ptr [rbp-48], edx
    jns     @F                                  ; never let the budget go negative: it is
    mov     dword ptr [rbp-48], 0               ;   passed straight to GetDlgItemTextW as
@@:                                             ;   nMaxCount, and -1 reads as 4 billion
    shl     edx, 1
    add     qword ptr [rbp-40], rdx
    mov     dword ptr [rbp-32], 1               ; k = 1
    mov     dword ptr [rbp-28], 0               ; row = 0
gg_row:
    mov     eax, dword ptr [rbp-28]
    cmp     eax, dword ptr [g_field_count]
    jae     gg_done
    ; type = row kind
    mov     eax, dword ptr [rbp-28]
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     r9d, dword ptr [r10+FD_KIND]
    mov     eax, dword ptr [rbp-32]
    imul    eax, eax, 24
    lea     r11, [g_field_list]
    add     r11, rax
    mov     qword ptr [r11+0], r9
    cmp     r9d, VF_IMAGE                        ; image/file rows carry a binary AttachRef
    je      gg_image
    cmp     r9d, VF_FILE
    je      gg_image
    ; read value -> vc
    mov     ecx, dword ptr [rbp-28]
    mov     edx, DS_VALUE
    call    dynid
    mov     dword ptr [rbp-72], eax
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], dword ptr [rbp-72], qword ptr [rbp-40], dword ptr [rbp-48]
    mov     ecx, dword ptr [rbp-32]
    imul    ecx, ecx, 24
    lea     r11, [g_field_list]
    add     r11, rcx
    mov     rdx, qword ptr [rbp-40]
    mov     qword ptr [r11+16], rdx
    mov     qword ptr [r11+8], 0                ; default: unlabelled
    inc     eax
    mov     edx, eax
    sub     dword ptr [rbp-48], edx
    jns     @F                                  ; never let the budget go negative: it is
    mov     dword ptr [rbp-48], 0               ;   passed straight to GetDlgItemTextW as
@@:                                             ;   nMaxCount, and -1 reads as 4 billion
    shl     edx, 1
    add     qword ptr [rbp-40], rdx
gg_label:
    ; read label; if non-empty and != kind default -> custom label
    mov     ecx, dword ptr [rbp-28]
    mov     edx, DS_LABEL
    call    dynid
    mov     dword ptr [rbp-72], eax
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], dword ptr [rbp-72], addr g_rlabel, 128
    cmp     word ptr [g_rlabel], 0
    je      gg_next
    mov     eax, dword ptr [rbp-28]
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     edx, dword ptr [r10+FD_KIND]
    call    kind_label
    lea     rcx, [g_rlabel]
    mov     rdx, rax
    call    gui_wstr_eq
    test    eax, eax
    jnz     gg_next
    ; custom: copy g_rlabel -> lc, point the field's label at it.  The pool is
    ; sized for MAXROWS worst-case labels, but bound the cursor anyway - running
    ; past it would corrupt whatever .data? follows (g_ofn among it).  Out of
    ; room -> leave the row unlabelled ([r11+8] is already 0) rather than spill.
    mov     rax, qword ptr [rbp-56]              ; lc
    lea     r10, [g_lblblob + LBLBLOB_W*2]       ; one past the pool
    sub     r10, rax                             ; bytes left
    cmp     r10, 128*2                           ; room for a worst-case label?
    jb      gg_next
    mov     ecx, dword ptr [rbp-32]
    imul    ecx, ecx, 24
    lea     r11, [g_field_list]
    add     r11, rcx
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [r11+8], rax
    lea     r10, [g_rlabel]
    mov     r11, qword ptr [rbp-56]
    xor     r8d, r8d
gg_lcp:
    mov     ax, word ptr [r10+r8*2]
    mov     word ptr [r11+r8*2], ax
    test    ax, ax
    jz      gg_lcd
    inc     r8d
    cmp     r8d, 127
    jb      gg_lcp
gg_lcd:
    inc     r8d
    mov     eax, r8d
    shl     eax, 1
    add     qword ptr [rbp-56], rax
gg_next:
    inc     dword ptr [rbp-32]
    inc     dword ptr [rbp-28]
    jmp     gg_row
gg_image:
    ; the attachments tile emits ONE placeholder entry (a bare VF_FILE, no VFL_RAW);
    ; its files live in g_tilefiles and gui_commit expands the placeholder into one
    ; VFL_RAW field per file.  An empty tile is dropped (row unchanged -> disappears).
    cmp     dword ptr [g_tilefile_n], 0
    je      gg_imgskip
    mov     ecx, dword ptr [rbp-32]
    imul    ecx, ecx, 24
    lea     rax, [g_field_list]
    add     rax, rcx                             ; &list[k]
    mov     qword ptr [rax+0], VF_FILE           ; base kind = tile marker
    mov     qword ptr [rax+8], 0
    lea     r11, [g_empty_w]
    mov     qword ptr [rax+16], r11
    jmp     gg_next
gg_imgskip:
    inc     dword ptr [rbp-28]                   ; drop the empty tile row (k unchanged)
    jmp     gg_row
gg_done:
    ; append the reserved favorite marker field when set
    cmp     dword ptr [g_fav_state], 0
    je      gg_favdone
    mov     eax, dword ptr [rbp-32]
    imul    eax, eax, 24
    lea     r11, [g_field_list]
    add     r11, rax
    mov     qword ptr [r11+0], VF_FAV
    mov     qword ptr [r11+8], 0                 ; no label
    lea     rax, [fav_one]
    mov     qword ptr [r11+16], rax              ; value "1"
    inc     dword ptr [rbp-32]
gg_favdone:
    ; append the reserved soft-delete marker (trash) when set
    cmp     dword ptr [g_deleted_state], 0
    je      gg_deldone
    mov     eax, dword ptr [rbp-32]
    imul    eax, eax, 24
    lea     r11, [g_field_list]
    add     r11, rax
    mov     qword ptr [r11+0], VF_DELETED
    mov     qword ptr [r11+8], 0                 ; no label
    lea     rax, [g_deleted_ft]
    mov     qword ptr [r11+16], rax              ; value = 16 hex FILETIME
    inc     dword ptr [rbp-32]
gg_deldone:
    ; append the custom icon override when set
    cmp     dword ptr [g_icon_set], 0
    je      gg_icondone
    call    gui_icon_encode
    mov     eax, dword ptr [rbp-32]
    imul    eax, eax, 24
    lea     r11, [g_field_list]
    add     r11, rax
    mov     qword ptr [r11+0], VF_ICON
    mov     qword ptr [r11+8], 0                 ; no label
    lea     rax, [g_icon_valw]
    mov     qword ptr [r11+16], rax
    inc     dword ptr [rbp-32]
gg_icondone:
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [g_field_n], eax
    FRAME_EPILOG
    ret
gui_gather endp

; gui_tile_expand() - replace the single VF_FILE tile placeholder in g_field_list with
;   one VFL_RAW field per file in g_tilefiles (value = {u32 len, AttachRef, filename}
;   built into g_tileblob).  Order is preserved; other fields copy through unchanged.
;   Called by gui_commit only - the reorder path keeps the tile as one placeholder.
gui_tile_expand proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-24], 0               ; src
    mov     dword ptr [rbp-32], 0               ; dst
gte_src:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_field_n]
    jae     gte_finish
    imul    eax, eax, 24
    lea     r10, [g_field_list]
    add     r10, rax
    mov     rcx, qword ptr [r10]                ; entry kind
    cmp     rcx, VF_FILE                        ; the tile placeholder (bare VF_FILE)?
    je      gte_expand
    mov     eax, dword ptr [rbp-32]             ; copy this entry through
    cmp     eax, MAX_FIELDS
    jae     gte_srcnext
    imul    eax, eax, 24
    lea     r11, [g_field_list2]
    add     r11, rax
    mov     rax, qword ptr [r10+0]
    mov     qword ptr [r11+0], rax
    mov     rax, qword ptr [r10+8]
    mov     qword ptr [r11+8], rax
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [r11+16], rax
    inc     dword ptr [rbp-32]
gte_srcnext:
    inc     dword ptr [rbp-24]
    jmp     gte_src
gte_expand:
    mov     dword ptr [rbp-40], 0               ; i
gte_i:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [g_tilefile_n]
    jae     gte_srcnext
    mov     eax, dword ptr [rbp-32]
    cmp     eax, MAX_FIELDS
    jae     gte_srcnext                         ; no field slots left -> stop
    mov     eax, dword ptr [rbp-40]             ; blob = g_tileblob + i*336
    imul    eax, eax, 336
    lea     r11, [g_tileblob]
    add     r11, rax
    mov     qword ptr [rbp-56], r11
    mov     ecx, dword ptr [rbp-40]
    call    tf_entry
    mov     qword ptr [rbp-48], rax             ; entry ptr
    mov     rcx, qword ptr [rbp-56]             ; AttachRef -> blob+4
    add     rcx, 4
    mov     rdx, qword ptr [rbp-48]
    mov     r8, 68
    call    gui_bcpy
    mov     rcx, qword ptr [rbp-56]             ; filename -> blob+4+68
    add     rcx, 4+68
    mov     rdx, qword ptr [rbp-48]
    add     rdx, TFILE_NAME
    call    gui_wcpy_capped                     ; eax = name bytes incl NUL
    add     eax, 68                             ; len = 68 + name bytes
    mov     r10, qword ptr [rbp-56]
    mov     dword ptr [r10], eax                ; u32 len at blob+0
    mov     eax, dword ptr [rbp-32]             ; g_field_list2[dst]
    imul    eax, eax, 24
    lea     r11, [g_field_list2]
    add     r11, rax
    mov     qword ptr [r11+0], VF_FILE or VFL_RAW
    mov     qword ptr [r11+8], 0
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [r11+16], rax
    inc     dword ptr [rbp-32]
    inc     dword ptr [rbp-40]
    jmp     gte_i
gte_finish:
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [g_field_n], eax
    imul    eax, eax, 24
    lea     rcx, [g_field_list]
    lea     rdx, [g_field_list2]
    mov     r8d, eax
    call    gui_bcpy
    FRAME_EPILOG
    ret
gui_tile_expand endp

; gui_pwhist_capture() - record this edit's TILE value events, in two passes over
;   the per-label set difference against g_pworig (the values captured at load):
;     CHANGED - an original (label L, value V) whose L no longer holds V; archives
;               {now, L, V}.  Renaming or removing a tile archives its old value.
;     ADDED   - a new field with data whose label held none before; archives
;               {now, L, ""}.  Covers a brand-new record, a field added in this
;               edit, and an existing-but-empty field filled in for the first time.
gui_pwhist_capture proc frame
    FRAME_PROLOG 96
    mov     dword ptr [rbp-24], 0             ; oi = original index
gpc_orig:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_pworig_n]
    jae     gpc_done
    imul    eax, eax, PWORIG_STRIDE
    lea     r10, [g_pworig]
    add     r10, rax
    mov     qword ptr [rbp-32], r10           ; orig slot (label @ +0, value @ +PWORIG_VAL)
    cmp     word ptr [r10+PWORIG_VAL], 0      ; empty original value -> nothing to archive
    je      gpc_orignext
    mov     dword ptr [rbp-40], 0            ; fi = field index
gpc_field:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [g_field_n]
    jae     gpc_notfound
    imul    eax, eax, 24
    lea     r11, [g_field_list]
    add     r11, rax
    mov     qword ptr [rbp-64], r11           ; field slot (survives the calls below;
    mov     ecx, dword ptr [r11]             ;   volatile regs don't)
    and     ecx, VF_KINDMASK
    cmp     ecx, VF_TITLE                     ; skip non-tile fields (title / reserved /
    je      gpc_fieldnext                     ;   attachment placeholders)
    cmp     ecx, VF_FAV
    je      gpc_fieldnext
    cmp     ecx, VF_ICON
    je      gpc_fieldnext
    cmp     ecx, VF_PWHIST
    je      gpc_fieldnext
    cmp     ecx, VF_FILE
    je      gpc_fieldnext
    cmp     ecx, VF_IMAGE
    je      gpc_fieldnext
    ; effective label of this new field (custom, or the kind default)
    mov     rax, qword ptr [r11+8]
    test    rax, rax
    jnz     gpc_haveEL
    mov     edx, ecx
    call    kind_label
gpc_haveEL:
    mov     qword ptr [rbp-48], rax           ; EL (survives the wstr_eq calls)
    mov     rcx, qword ptr [rbp-32]           ; compare EL to the original's label
    mov     rdx, qword ptr [rbp-48]
    call    gui_wstr_eq
    test    eax, eax
    jz      gpc_fieldnext                     ; different tile -> keep looking
    mov     rcx, qword ptr [rbp-32]           ; same label: compare values
    add     rcx, PWORIG_VAL
    mov     rax, qword ptr [rbp-64]           ; reload the field slot
    mov     rdx, qword ptr [rax+16]
    call    gui_wstr_eq
    test    eax, eax
    jnz     gpc_orignext                      ; same label + value still present -> not overwritten
gpc_fieldnext:
    inc     dword ptr [rbp-40]
    jmp     gpc_field
gpc_notfound:
    lea     rcx, [rbp-56]                      ; now -> FILETIME
    call    GetSystemTimeAsFileTime
    mov     rcx, qword ptr [rbp-56]           ; ft
    mov     rdx, qword ptr [rbp-32]           ; label (slot+0)
    mov     r8, qword ptr [rbp-32]           ; old value (slot+PWORIG_VAL)
    add     r8, PWORIG_VAL
    mov     r9d, PWHA_CHANGED
    call    pwh_append
gpc_orignext:
    inc     dword ptr [rbp-24]
    jmp     gpc_orig
gpc_done:
    ; ---- pass 2: labels that now carry data but carried none at load -> ADDED ----
    mov     dword ptr [rbp-24], 0             ; fi = field index
gpc_add:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_field_n]
    jae     gpc_adddone
    imul    eax, eax, 24
    lea     r11, [g_field_list]
    add     r11, rax
    mov     ecx, dword ptr [r11]
    and     ecx, VF_KINDMASK
    cmp     ecx, VF_TITLE                     ; skip the same non-tile kinds as pass 1
    je      gpc_addnext
    cmp     ecx, VF_FAV
    je      gpc_addnext
    cmp     ecx, VF_ICON
    je      gpc_addnext
    cmp     ecx, VF_PWHIST
    je      gpc_addnext
    cmp     ecx, VF_FILE
    je      gpc_addnext
    cmp     ecx, VF_IMAGE
    je      gpc_addnext
    cmp     ecx, VF_DELETED                   ; the trash marker is re-emitted by
    je      gpc_addnext                       ;   gui_gather but never captured as an
                                              ;   original, so it always looked new
    mov     rax, qword ptr [r11+16]           ; still empty -> nothing was filled in
    test    rax, rax
    jz      gpc_addnext
    cmp     word ptr [rax], 0
    je      gpc_addnext
    mov     rax, qword ptr [r11+8]            ; effective label (custom, or kind default)
    test    rax, rax
    jnz     gpc_addEL
    mov     edx, ecx
    call    kind_label
gpc_addEL:
    mov     qword ptr [rbp-48], rax           ; EL (survives the wstr_eq calls)
    mov     dword ptr [rbp-40], 0            ; oi = original index
gpc_addorig:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [g_pworig_n]
    jae     gpc_addnew                        ; no original held data under EL -> new
    lea     r10, [g_pworig_hd]                ; carried data at load?  Read the recorded
    cmp     byte ptr [r10+rax], 0             ;   flag, not the wide copy - that caps at
    je      gpc_addorignext                   ;   127 chars and reads empty beyond it
    imul    eax, eax, PWORIG_STRIDE
    lea     r10, [g_pworig]
    add     r10, rax
    mov     rcx, r10
    mov     rdx, qword ptr [rbp-48]
    call    gui_wstr_eq
    test    eax, eax
    jnz     gpc_addnext                       ; EL already carried data -> not an add
gpc_addorignext:
    inc     dword ptr [rbp-40]
    jmp     gpc_addorig
gpc_addnew:
    lea     rcx, [rbp-56]                      ; now -> FILETIME
    call    GetSystemTimeAsFileTime
    mov     rcx, qword ptr [rbp-56]           ; ft
    mov     rdx, qword ptr [rbp-48]           ; label
    lea     r8, [pwh_empty]                   ; ADDED archives no value
    mov     r9d, PWHA_ADDED
    call    pwh_append
gpc_addnext:
    inc     dword ptr [rbp-24]
    jmp     gpc_add
gpc_adddone:
    FRAME_EPILOG
    ret
gui_pwhist_capture endp

; gui_phtest() -> eax = g_pwhist_n after a synthetic capture (headless probe).
;   Seeds one original secret ("Password"="oldpw") + a new secret field "newpw",
;   runs gui_pwhist_capture; a working capture returns 1.
public gui_phtest
gui_phtest proc frame
    FRAME_PROLOG 48
    call    pwh_reset
    lea     rcx, [pht_lbl]                    ; original label "Password" (utf8, 8)
    mov     edx, 8
    lea     r8, [pht_old]                     ; original value "oldpw" (utf8, 5)
    mov     r9d, 5
    call    pworig_add
    lea     rcx, [pht_loginu]                 ; 2nd original: "Login" = "stays" (UNCHANGED)
    mov     edx, 5
    lea     r8, [pht_stayu]
    mov     r9d, 5
    call    pworig_add
    cmp     dword ptr [g_pworig_n], 2         ; 10 = pworig_add didn't record both
    jne     pht_e10
    lea     r10, [g_pworig]                   ; 20 = original value not stored
    cmp     word ptr [r10+PWORIG_VAL], 0
    je      pht_e20
    lea     r10, [g_field_list]
    mov     qword ptr [r10+0], VF_TITLE
    mov     qword ptr [r10+8], 0
    lea     rax, [pht_ttl]
    mov     qword ptr [r10+16], rax
    mov     qword ptr [r10+24], VF_SECRET     ; secret changed "oldpw" -> "newpw"
    mov     qword ptr [r10+32], 0
    lea     rax, [pht_new]
    mov     qword ptr [r10+40], rax
    mov     qword ptr [r10+48], VF_USERNAME   ; "Login" tile UNCHANGED ("stays")
    lea     rax, [pht_loginw]
    mov     qword ptr [r10+56], rax
    lea     rax, [pht_staysw]
    mov     qword ptr [r10+64], rax
    mov     dword ptr [g_field_n], 3
    call    gui_pwhist_capture
    cmp     dword ptr [g_pwhist_n], 1         ; 30 = wrong count (Login must NOT archive)
    jne     pht_e30
    lea     r10, [g_pwhist]                   ; verify stored content (pwh_append)
    cmp     word ptr [r10+PWHIST_LBL], 'P'    ; 40 = label not "Password"
    jne     pht_e40
    cmp     word ptr [r10+PWHIST_PW], 'o'     ; 50 = pw not "oldpw"
    jne     pht_e50
    call    gui_pwhist_emit                   ; exercise emit -> VF_PWHIST field
    cmp     dword ptr [g_field_n], 4          ; 60 = emit didn't append a field (3 -> 4)
    jne     pht_e60
    lea     r10, [g_field_list+72]            ; g_field_list[3] (the emitted record)
    mov     rcx, qword ptr [r10]              ; 70 = kind not VF_PWHIST|VFL_RAW
    cmp     rcx, VF_PWHIST or VFL_RAW
    jne     pht_e70
    mov     r10, qword ptr [r10+16]           ; emitted value {u32 len, ft, label\0, pw\0}
    cmp     word ptr [r10+12], 'P'            ; 80 = emitted label wrong
    jne     pht_e80
    mov     eax, 1                            ; all good
    FRAME_EPILOG
    ret
pht_e10:
    mov     eax, 10
    FRAME_EPILOG
    ret
pht_e20:
    mov     eax, 20
    FRAME_EPILOG
    ret
pht_e30:
    mov     eax, 30
    FRAME_EPILOG
    ret
pht_e40:
    mov     eax, 40
    FRAME_EPILOG
    ret
pht_e50:
    mov     eax, 50
    FRAME_EPILOG
    ret
pht_e60:
    mov     eax, 60
    FRAME_EPILOG
    ret
pht_e70:
    mov     eax, 70
    FRAME_EPILOG
    ret
pht_e80:
    mov     eax, 80
    FRAME_EPILOG
    ret
gui_phtest endp


; gui_pwhist_emit() - append every g_pwhist entry to g_field_list as a reserved
;   VF_PWHIST|VFL_RAW field: value = {u32 len, u64 ft, label wide\0, pw wide\0,
;   u32 action} built into g_pwhblob so it survives until vault_build_entry
;   consumes it.  The action trails the strings so records written before it
;   existed still parse (a short record reads back as PWHA_CHANGED).
gui_pwhist_emit proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], 0            ; i
gpe_loop:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_pwhist_n]
    jae     gpe_done
    mov     eax, dword ptr [g_field_n]
    cmp     eax, MAX_FIELDS
    jae     gpe_done                          ; no field slots left
    mov     eax, dword ptr [rbp-24]           ; blob = g_pwhblob + i*PWHBLOB_ENTRY
    imul    eax, eax, PWHBLOB_ENTRY
    lea     r11, [g_pwhblob]
    add     r11, rax
    mov     qword ptr [rbp-32], r11
    mov     ecx, dword ptr [rbp-24]
    call    pwh_entry
    mov     qword ptr [rbp-40], rax
    mov     r10, qword ptr [rax]             ; filetime -> blob+4
    mov     r11, qword ptr [rbp-32]
    mov     qword ptr [r11+4], r10
    mov     rcx, qword ptr [rbp-32]           ; label wide -> blob+12
    add     rcx, 12
    mov     rdx, qword ptr [rbp-40]
    add     rdx, PWHIST_LBL
    call    gui_wcpy_capped                   ; eax = label bytes incl NUL
    mov     dword ptr [rbp-44], eax
    mov     rcx, qword ptr [rbp-32]           ; pw wide -> blob+12+labelbytes
    add     rcx, 12
    add     rcx, rax
    mov     rdx, qword ptr [rbp-40]
    add     rdx, PWHIST_PW
    call    gui_wcpy_capped                   ; eax = pw bytes incl NUL
    add     eax, 8                            ; len = ft(8) + label bytes + pw bytes
    add     eax, dword ptr [rbp-44]
    mov     r11, qword ptr [rbp-32]           ; u32 action trails both strings
    mov     r10, qword ptr [rbp-40]
    mov     r10d, dword ptr [r10+PWHIST_ACT]
    mov     dword ptr [r11+rax+4], r10d       ; blob+4+len (past ft+strings)
    add     eax, 4                            ; len += action
    mov     dword ptr [r11], eax             ; u32 len at blob+0
    mov     eax, dword ptr [g_field_n]        ; g_field_list[g_field_n]
    imul    eax, eax, 24
    lea     r11, [g_field_list]
    add     r11, rax
    mov     qword ptr [r11+0], VF_PWHIST or VFL_RAW
    mov     qword ptr [r11+8], 0
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [r11+16], rax
    inc     dword ptr [g_field_n]
    inc     dword ptr [rbp-24]
    jmp     gpe_loop
gpe_done:
    FRAME_EPILOG
    ret
gui_pwhist_emit endp

; gui_commit(rcx = hdlg) - gather Title + rows into g_field_list and write the
;   record back (remove the old entry, rebuild via vault_build_entry, reseal).
;   Reselects the entry.  Refuses to save an empty title (keeps the old entry).
gui_commit proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_cur_idx], 0
    jl      gco_done                          ; nothing selected
    ; external-change guard: warn before overwriting a file another program or
    ; instance rewrote since we loaded it (checked before touching any state).
    call    vault_ext_changed
    test    eax, eax
    jz      gco_noext
    mov     rcx, qword ptr [rbp-24]           ; C8: reload-safe - the file changed under
    call    gui_reload_safe                   ; us; reload + inform, never clobber
    jmp     gco_done
gco_noext:
    mov     rcx, qword ptr [rbp-24]
    call    gui_gather
    call    gui_tile_expand                   ; tile placeholder -> one field per file
    mov     r10, qword ptr [g_field_list+16]  ; title value ptr
    test    r10, r10
    jz      gco_notitle
    cmp     word ptr [r10], 0                 ; empty title -> keep the old entry
    je      gco_notitle
    cmp     dword ptr [g_no_history], 0        ; "Do not save history" -> neither capture
    jne     gco_nohist                         ;   new overwrites nor re-emit existing ones
    call    gui_pwhist_capture                ; archive any overwritten value, then
    call    gui_pwhist_emit                   ; write history back as VF_PWHIST fields
gco_nohist:
    mov     ecx, dword ptr [g_cur_idx]        ; preserve the original creation date
    call    vault_entry_ptr
    test    rax, rax
    jz      gco_nocarry
    mov     rdx, qword ptr [rax+16]           ; original created FILETIME
    mov     qword ptr [g_carry_created], rdx
gco_nocarry:
    mov     ecx, dword ptr [g_cur_idx]
    call    vault_remove_at
    call    vault_build_entry
    test    eax, eax
    jnz     gco_done
gco_reseal:
    call    vault_reseal
    mov     dword ptr [rbp-32], eax             ; C5: audit the save outcome
    lea     rcx, [ev_save]
    mov     edx, eax
    call    log_result
    mov     eax, dword ptr [rbp-32]
    test    eax, eax
    jnz     gco_resealerr
    mov     rcx, qword ptr [rbp-24]
    call    gui_poplist
    call    vault_last_user                     ; NOT count-1: a vault that gained its system
    cmp     eax, 0                              ;   item on a later save has it appended LAST
    jl      gco_done
    mov     dword ptr [g_cur_idx], eax
    mov     rcx, qword ptr [rbp-24]              ; reselect by vault index (list is sorted)
    mov     edx, dword ptr [g_cur_idx]
    call    gui_lb_selbydata
    jmp     gco_done
gco_notitle:
    WINCALL gui_msgbox, qword ptr [rbp-24], addr s_notitle, addr t_err, <MB_OK or MB_ICONERROR>
    FRAME_EPILOG
    ret
gco_resealerr:
    cmp     eax, EXIT_CHANGED                   ; C8: change caught in the TOCTOU window
    je      gco_reload
    cmp     eax, EXIT_BUSY                       ; C8: another instance holds the write lock
    je      gco_busy
    WINCALL gui_msgbox, qword ptr [rbp-24], addr s_resealfail, addr t_err, \
            <MB_YESNO or MB_ICONWARNING>
    cmp     eax, IDYES                          ; Yes -> retry the write (file may be unlocked now)
    je      gco_reseal
    jmp     gco_done
gco_reload:
    mov     rcx, qword ptr [rbp-24]
    call    gui_reload_safe
    jmp     gco_done
gco_busy:
    WINCALL gui_msgbox, qword ptr [rbp-24], addr s_busy, addr t_exttitle, <MB_OK or MB_ICONWARNING>
gco_done:
    mov     dword ptr [g_dirty], 0
    FRAME_EPILOG
    ret
gui_commit endp

; gui_reload_safe(rcx = hdlg) - C8: the vault changed on disk under us; reload it
;   (vault_reload, existing key - no re-KDF), refresh the list, and tell the user
;   to re-apply their unsaved change.  Never overwrites the other writer's save.
gui_reload_safe proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    call    vault_reload
    mov     rcx, qword ptr [rbp-24]
    call    gui_poplist
    WINCALL gui_msgbox, qword ptr [rbp-24], addr s_reloaded, addr t_reloaded, \
            <MB_OK or MB_ICONINFORMATION>
    FRAME_EPILOG
    ret
gui_reload_safe endp

; gui_check_refresh(rcx = hdlg) - C8.4: if the vault changed on disk and we have
;   no unsaved edit, silently reload it (existing key, no re-KDF) and refresh the
;   list.  Called from the idle poll.  Skips while editing/dirty so the reload-safe
;   save path (gui_commit) owns the conflict then.
gui_check_refresh proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    call    vault_count                       ; 0 = locked/closed -> nothing to do
    test    eax, eax
    jz      gcr2_done
    cmp     dword ptr [g_editmode], 0          ; editing -> don't disturb the user
    jne     gcr2_done
    cmp     dword ptr [g_dirty], 0             ; unsaved change -> defer to the save path
    jne     gcr2_done
    call    vault_ext_changed
    test    eax, eax
    jz      gcr2_done
    call    vault_reload
    test    eax, eax
    jnz     gcr2_done                          ; reload failed -> leave as is
    mov     rcx, qword ptr [rbp-24]
    call    gui_poplist
gcr2_done:
    FRAME_EPILOG
    ret
gui_check_refresh endp

; gui_ro_disable_btns(rcx = hdlg) - E9: grey out the mutation buttons that stay
;   visible in view mode (New / Edit / Delete / Favorite / header-edit) so a
;   read-only vault reads as read-only.  The click handlers are already gated;
;   this is the matching visual state.
gui_ro_disable_btns proc frame
    FRAME_PROLOG 48   ; >= 48: keep locals clear of the callee 32-byte home area
    mov     qword ptr [rbp-24], rcx
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_ADD
    WINCALL EnableWindow, rax, 0
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_EDIT
    WINCALL EnableWindow, rax, 0
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_REMOVE
    WINCALL EnableWindow, rax, 0
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_FAV
    WINCALL EnableWindow, rax, 0
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_HDREDIT
    WINCALL EnableWindow, rax, 0
    FRAME_EPILOG
    ret
gui_ro_disable_btns endp

; gui_set_editmode(rcx=hdlg, edx=on) - 1 = detail fields editable (edit mode),
;   0 = read-only (view).  Toggles EM_SETREADONLY on the six fields and swaps
;   the toolbar pencil glyph for a check mark while editing.
gui_set_editmode proc frame
    FRAME_PROLOG 128
    cmp     dword ptr [g_readonly], 0           ; E9: read-only never enters edit mode -
    je      sem_modeok                          ; force view so the edit UI stays hidden
    xor     edx, edx
sem_modeok:
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [g_editmode], edx
    call    gui_colorpw_hide                    ; a mode change drops the color overlay
    mov     eax, dword ptr [rbp-32]              ; mode (edx was clobbered by the call above)
    xor     eax, 1
    mov     dword ptr [rbp-40], eax              ; readonly = NOT on
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_TITLE, EM_SETREADONLY, dword ptr [rbp-40], 0
    ; each row's value + label edit
    mov     dword ptr [rbp-44], 0                ; row
sem_row:
    mov     eax, dword ptr [rbp-44]
    cmp     eax, dword ptr [g_field_count]
    jae     sem_rowsdone
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_VALUE
    call    dynid
    mov     dword ptr [rbp-48], eax
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], dword ptr [rbp-48], EM_SETREADONLY, \
            dword ptr [rbp-40], 0
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_LABEL
    call    dynid
    mov     dword ptr [rbp-48], eax
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], dword ptr [rbp-48], EM_SETREADONLY, \
            dword ptr [rbp-40], 0
    inc     dword ptr [rbp-44]
    jmp     sem_row
sem_rowsdone:
    ; show/hide the "+ Add field" button + relayout (updates reorder visibility)
    mov     dword ptr [rbp-52], SW_HIDE
    cmp     dword ptr [rbp-32], 0
    je      sem_addcmd
    mov     dword ptr [rbp-52], SW_SHOW
sem_addcmd:
    ; header glyphs (edit / favorite / more) + the header tile show in VIEW mode,
    ; but only when an entry is actually selected - with no secret shown they hide.
    mov     eax, dword ptr [rbp-52]           ; SW_SHOW in edit, SW_HIDE in view
    xor     eax, SW_SHOW                      ; -> SW_SHOW in view, SW_HIDE in edit
    cmp     dword ptr [g_cur_idx], 0
    jge     @F
    xor     eax, eax                          ; no entry selected -> SW_HIDE
@@: mov     dword ptr [rbp-88], eax           ; header-glyph visibility
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_ADDFIELD
    call    GetDlgItem
    mov     rcx, rax
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
    mov     rcx, qword ptr [rbp-24]           ; Save button shares the Add-field visibility
    mov     edx, IDC_V_SAVE
    call    GetDlgItem
    mov     rcx, rax
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
    mov     rcx, qword ptr [rbp-24]           ; Cancel button shares the edit-mode visibility
    mov     edx, IDC_V_CANCEL
    call    GetDlgItem
    mov     rcx, rax
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
    ; header (view) vs. editable Title label+edit (edit): show one, hide the other
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_TITLE
    call    GetDlgItem
    mov     rcx, rax
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
    mov     rcx, qword ptr [rbp-24]           ; edit-mode icon button (before the title)
    mov     edx, IDC_V_ICON
    call    GetDlgItem
    mov     rcx, rax
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_HEADER
    call    GetDlgItem
    mov     qword ptr [rbp-72], rax           ; header hwnd (own 8-byte slot)
    mov     eax, dword ptr [rbp-88]           ; view-mode + entry-selected visibility
    mov     rcx, qword ptr [rbp-72]
    mov     edx, eax
    call    ShowWindow
    WINCALL InvalidateRect, qword ptr [rbp-72], 0, 1   ; repaint header for this entry
    ; overflow (...) button shares the header's view-mode visibility
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_OVFL
    call    GetDlgItem
    mov     qword ptr [rbp-72], rax
    mov     eax, dword ptr [rbp-88]
    mov     rcx, qword ptr [rbp-72]
    mov     edx, eax
    call    ShowWindow
    mov     rcx, qword ptr [rbp-24]           ; favorite star shares the header visibility
    mov     edx, IDC_V_FAV
    call    GetDlgItem
    mov     qword ptr [rbp-72], rax
    mov     eax, dword ptr [rbp-88]
    mov     rcx, qword ptr [rbp-72]
    mov     edx, eax
    call    ShowWindow
    mov     rcx, qword ptr [rbp-24]           ; header edit ghost shares the view-mode visibility
    mov     edx, IDC_V_HDREDIT
    call    GetDlgItem
    mov     qword ptr [rbp-72], rax
    mov     eax, dword ptr [rbp-88]
    mov     rcx, qword ptr [rbp-72]
    mov     edx, eax
    call    ShowWindow
    mov     rcx, qword ptr [rbp-24]           ; re-dock: pagination re-centres for the
    call    gui_cmd_dock_layout               ;   new mode (gap between buttons vs pane)
    mov     rcx, qword ptr [rbp-24]
    call    gui_rows_layout
    ; the pencil button stays a pencil in both modes (Save handles committing)
    FRAME_EPILOG
    ret
gui_set_editmode endp

; =============================================================================
; Settings overlay (burger menu) helpers for DLG_VAULT.
; =============================================================================

; =============================================================================
; Modular field rows - runtime-built, composable detail form.
; =============================================================================

; mk_ctl(rcx=parent, edx=id, r8=classwide, r9=captionwide,
;        [+48]=style [+56]=dlux [+64]=dluy [+72]=dluw [+80]=dluh) -> rax=hwnd
;   Create a themed child control: map the DLU rect to pixels, apply the dialog
;   font.  Geometry can be a placeholder (gui_rows_layout repositions later).
mk_ctl proc frame
    FRAME_PROLOG 224
    mov     qword ptr [rbp-24], rcx
    mov     eax, edx
    mov     qword ptr [rbp-32], rax              ; id (zero-extended)
    mov     qword ptr [rbp-40], r8               ; class
    mov     qword ptr [rbp-48], r9               ; caption
    mov     rax, qword ptr [rbp+48]
    or      rax, WS_CHILD_ or WS_VISIBLE_
    mov     qword ptr [rbp-56], rax              ; style
    mov     eax, dword ptr [rbp+56]              ; DLU rect at [rbp-80]
    mov     dword ptr [rbp-80], eax
    mov     eax, dword ptr [rbp+64]
    mov     dword ptr [rbp-76], eax
    mov     eax, dword ptr [rbp+56]
    add     eax, dword ptr [rbp+72]
    mov     dword ptr [rbp-72], eax
    mov     eax, dword ptr [rbp+64]
    add     eax, dword ptr [rbp+80]
    mov     dword ptr [rbp-68], eax
    WINCALL MapDialogRect, qword ptr [rbp-24], addr rbp-80
    mov     eax, dword ptr [rbp-80]
    mov     qword ptr [rbp-88], rax              ; px
    mov     eax, dword ptr [rbp-76]
    mov     qword ptr [rbp-96], rax              ; py
    mov     eax, dword ptr [rbp-72]
    sub     eax, dword ptr [rbp-80]
    mov     qword ptr [rbp-104], rax             ; pw
    mov     eax, dword ptr [rbp-68]
    sub     eax, dword ptr [rbp-76]
    mov     qword ptr [rbp-112], rax             ; ph
    WINCALL CreateWindowExW, 0, qword ptr [rbp-40], qword ptr [rbp-48], qword ptr [rbp-56], \
            qword ptr [rbp-88], qword ptr [rbp-96], qword ptr [rbp-104], qword ptr [rbp-112], \
            qword ptr [rbp-24], qword ptr [rbp-32], qword ptr [g_hinst], 0
    mov     qword ptr [rbp-16], rax
    WINCALL SendMessageW, qword ptr [rbp-16], WM_SETFONT, qword ptr [g_dlgfont], 1
    mov     rax, qword ptr [rbp-16]
    FRAME_EPILOG
    ret
mk_ctl endp

; row_mk(rcx=hdlg, edx=i, r8d=slot, r9=classwide, [+48]=captionwide, [+56]=style)
;   -> rax=hwnd.  Create one row control with id = IDC_DYN_BASE+i*DYN_SLOTS+slot
;   and store its handle in g_fields[i].handles[slot].
row_mk proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx              ; i
    mov     dword ptr [rbp-40], r8d              ; slot
    mov     qword ptr [rbp-48], r9               ; class
    mov     eax, edx
    imul    eax, eax, DYN_SLOTS
    add     eax, r8d
    add     eax, IDC_DYN_BASE
    mov     dword ptr [rbp-56], eax              ; id
    WINCALL mk_ctl, qword ptr [rbp-24], dword ptr [rbp-56], qword ptr [rbp-48], \
            qword ptr [rbp+48], qword ptr [rbp+56], 0, 0, 1, 1
    mov     qword ptr [rbp-64], rax              ; hwnd
    mov     eax, dword ptr [rbp-32]
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     eax, dword ptr [rbp-40]
    mov     r11, qword ptr [rbp-64]
    mov     qword ptr [r10 + FD_HANDLES + rax*8], r11
    mov     rax, r11
    FRAME_EPILOG
    ret
row_mk endp

; =============================================================================
; Ghost buttons - frameless glyph-only controls (see docs/REDESIGN_PLAN.md 1.2).
; Rendered by theme_drawitem's tdi_ghost path: bare Fluent/Symbol glyph, a subtle
; rounded hover halo, and a tooltip.  Window text stays a readable name (MSAA);
; the glyph + hover state ride in GWL_USERDATA (glyph<<16 | hover<<8 | style 2).
; =============================================================================

; ghost_attach(rcx=parent, rdx=button hwnd, r8d=glyph, r9=name/tooltip wstr).
;   Turn an already-created BS_OWNERDRAW button into a ghost button: set the
;   userdata glyph+style, install the hover subclass, and register a tooltip.
;   Used both by ghost_make and to convert existing (RC) toolbar buttons.
ghost_attach proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx             ; parent
    mov     qword ptr [rbp-32], rdx             ; button hwnd
    mov     dword ptr [rbp-40], r8d             ; glyph
    mov     qword ptr [rbp-48], r9              ; name/tip
    mov     eax, dword ptr [rbp-40]             ; userdata = glyph<<16 | GHOST_STYLE
    shl     eax, 16
    or      eax, GHOST_STYLE_
    mov     edx, eax                            ; zero-extends into rdx
    WINCALL SetWindowLongPtrW, qword ptr [rbp-32], GWL_USERDATA, rdx
    WINCALL SetWindowSubclass, qword ptr [rbp-32], addr ghost_subclass, 0, 0
    mov     rcx, qword ptr [rbp-48]             ; register a tooltip if a name was given
    test    rcx, rcx
    jz      ga_done
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    mov     r8, qword ptr [rbp-48]
    call    ghost_tip_add
ga_done:
    FRAME_EPILOG
    ret
ghost_attach endp

; ghost_set_glyph(rcx=hdlg, edx=ctlid, r8d=glyph) - change a ghost button's glyph
;   (bits 16-31 of userdata), preserving its hover/style bits, and repaint.
ghost_set_glyph proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-28], edx
    mov     dword ptr [rbp-32], r8d
    WINCALL GetDlgItem, qword ptr [rbp-24], dword ptr [rbp-28]
    mov     qword ptr [rbp-40], rax
    test    rax, rax
    jz      gsg_done
    WINCALL GetWindowLongPtrW, qword ptr [rbp-40], GWL_USERDATA
    and     eax, 0FFFFh                         ; keep hover+style, clear glyph
    mov     edx, dword ptr [rbp-32]
    shl     edx, 16
    or      eax, edx                            ; new glyph in bits 16-31
    mov     edx, eax
    WINCALL SetWindowLongPtrW, qword ptr [rbp-40], GWL_USERDATA, rdx
    WINCALL InvalidateRect, qword ptr [rbp-40], 0, 1
gsg_done:
    FRAME_EPILOG
    ret
ghost_set_glyph endp

; ghost_make(rcx=hdlg, edx=id, r8d=glyph, r9=name/tooltip wstr) -> rax=hwnd.
;   Placeholder geometry; the layout pass positions it.
ghost_make proc frame
    FRAME_PROLOG 128                            ; room for the 9-arg mk_ctl WINCALL spill
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-28], edx
    mov     dword ptr [rbp-32], r8d
    mov     qword ptr [rbp-40], r9
    WINCALL mk_ctl, qword ptr [rbp-24], dword ptr [rbp-28], addr cls_button, \
            qword ptr [rbp-40], BS_OWNERDRAW_ or WS_TABSTOP_, 0, 0, 16, 14
    mov     qword ptr [rbp-48], rax             ; hwnd
    mov     rcx, qword ptr [rbp-24]             ; parent
    mov     rdx, qword ptr [rbp-48]             ; button
    mov     r8d, dword ptr [rbp-32]             ; glyph
    mov     r9, qword ptr [rbp-40]              ; name/tip
    call    ghost_attach
    mov     rax, qword ptr [rbp-48]
    FRAME_EPILOG
    ret
ghost_make endp

; ghost_subclass - SUBCLASSPROC: track hover for the halo.  WM_MOUSEMOVE sets the
;   hover bit + arms WM_MOUSELEAVE; WM_MOUSELEAVE clears it; both repaint.
ghost_subclass proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-24], rcx             ; hwnd
    mov     qword ptr [rbp-32], rdx             ; msg
    mov     qword ptr [rbp-40], r8              ; wParam
    mov     qword ptr [rbp-48], r9              ; lParam
    cmp     rdx, WM_MOUSEMOVE_
    je      gsc_move
    cmp     rdx, WM_MOUSELEAVE_
    je      gsc_leave
    cmp     rdx, WM_CHAR_
    je      gsc_char
    cmp     rdx, WM_KEYDOWN_
    je      gsc_key
gsc_def:
    WINCALL DefSubclassProc, qword ptr [rbp-24], qword ptr [rbp-32], qword ptr [rbp-40], \
            qword ptr [rbp-48]
    FRAME_EPILOG
    ret
gsc_key:
    mov     rcx, qword ptr [rbp-24]            ; Ctrl+shortcuts from a focused ghost button
    mov     edx, r8d
    call    vault_ctrl_key
    test    eax, eax
    jz      gsc_def
    xor     eax, eax
    FRAME_EPILOG
    ret
gsc_char:
    ; type-to-search: a printable key while a ghost button has focus jumps to the
    ; sidebar search box (only the vault dialog has one; harmless elsewhere)
    cmp     qword ptr [rbp-40], 20h
    jb      gsc_def
    WINCALL GetParent, qword ptr [rbp-24]
    mov     qword ptr [rbp-56], rax
    WINCALL GetDlgItem, qword ptr [rbp-56], IDC_V_SEARCH   ; focus the sidebar box, type into it
    mov     qword ptr [rbp-64], rax
    test    rax, rax
    jz      gsc_def
    WINCALL SetFocus, qword ptr [rbp-64]
    WINCALL SendMessageW, qword ptr [rbp-64], WM_CHAR_, qword ptr [rbp-40], \
            qword ptr [rbp-48]
    xor     eax, eax
    FRAME_EPILOG
    ret
gsc_move:
    WINCALL GetWindowLongPtrW, qword ptr [rbp-24], GWL_USERDATA
    test    eax, 0FF00h                         ; already hovering -> nothing to do
    jnz     gsc_def
    or      eax, 100h                           ; set hover byte
    mov     edx, eax
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], GWL_USERDATA, rdx
    mov     dword ptr [rbp-80], 24              ; TRACKMOUSEEVENT{cbSize,dwFlags,hwnd,hover}
                                                ; cbSize = sizeof on x64 = 24 (NOT the x86 16:
                                                ; a wrong cbSize makes TrackMouseEvent fail to
                                                ; arm WM_MOUSELEAVE, so the hover halo stuck)
    mov     dword ptr [rbp-76], TME_LEAVE_
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [rbp-72], rax
    mov     dword ptr [rbp-64], 0
    WINCALL TrackMouseEvent, addr rbp-80
    WINCALL InvalidateRect, qword ptr [rbp-24], 0, 0
    jmp     gsc_def
gsc_leave:
    WINCALL GetWindowLongPtrW, qword ptr [rbp-24], GWL_USERDATA
    and     eax, 0FFFF00FFh                     ; clear hover byte
    mov     edx, eax
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], GWL_USERDATA, rdx
    WINCALL InvalidateRect, qword ptr [rbp-24], 0, 0
    jmp     gsc_def
ghost_subclass endp

; ghost_tip_create(rcx=parent) - lazily create the shared tooltip window.
ghost_tip_create proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    cmp     qword ptr [g_tooltip], 0
    jne     gtc_done
    WINCALL CreateWindowExW, 0, addr cls_tooltip, 0, \
            WS_POPUP or TTS_ALWAYSTIP_ or TTS_NOPREFIX_, \
            CW_USEDEFAULT_, CW_USEDEFAULT_, CW_USEDEFAULT_, CW_USEDEFAULT_, \
            qword ptr [rbp-24], 0, qword ptr [g_hinst], 0
    mov     qword ptr [g_tooltip], rax
    WINCALL SendMessageW, qword ptr [g_tooltip], TTM_SETMAXTIPW_, 0, 300
gtc_done:
    FRAME_EPILOG
    ret
ghost_tip_create endp

; ghost_tip_add(rcx=parent, rdx=tool hwnd, r8=text) - register a subclass tooltip.
ghost_tip_add proc frame
    FRAME_PROLOG 144
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     rcx, qword ptr [rbp-24]
    call    ghost_tip_create
    mov     dword ptr [rbp-104], 38h            ; TOOLINFOW cbSize (through lpszText)
    mov     dword ptr [rbp-100], TTF_IDISHWND_ or TTF_SUBCLASS_
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [rbp-96], rax             ; hwnd = parent
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-88], rax             ; uId = tool hwnd
    xor     eax, eax
    mov     dword ptr [rbp-80], eax             ; rect = 0 (ignored for IDISHWND)
    mov     dword ptr [rbp-76], eax
    mov     dword ptr [rbp-72], eax
    mov     dword ptr [rbp-68], eax
    mov     qword ptr [rbp-64], 0               ; hinst = 0
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [rbp-56], rax             ; lpszText
    WINCALL SendMessageW, qword ptr [g_tooltip], TTM_ADDTOOLW_, 0, addr rbp-104
    FRAME_EPILOG
    ret
ghost_tip_add endp

; ghost_tip_del(rcx=parent, rdx=tool hwnd) - drop a tool from the shared tooltip.
;   Tools are keyed by hwnd, so a control that is destroyed without this leaves a
;   dead entry behind.  The row controls are torn down and rebuilt on every
;   selection, which is why they carried no tooltip at all before: without a
;   matching delete the list would grow without bound.
ghost_tip_del proc frame
    FRAME_PROLOG 144
    cmp     qword ptr [g_tooltip], 0
    je      gtd_done                            ; nothing created yet -> nothing to drop
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     dword ptr [rbp-104], 38h            ; TOOLINFOW cbSize (matches ghost_tip_add)
    mov     dword ptr [rbp-100], TTF_IDISHWND_
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [rbp-96], rax             ; hwnd = parent
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-88], rax             ; uId = tool hwnd
    WINCALL SendMessageW, qword ptr [g_tooltip], TTM_DELTOOLW_, 0, addr rbp-104
gtd_done:
    FRAME_EPILOG
    ret
ghost_tip_del endp

; search_type_subclass - SUBCLASSPROC on the sidebar list: type-to-search.  When
;   a printable character is typed while the list has focus (no edit focused),
;   move focus to the search box and forward the character there (redesign A2).
; vault_ctrl_key(rcx=ctl hwnd, edx=vk) -> eax 1 if a Ctrl+shortcut was handled.
;   Ctrl+K focus search, Ctrl+N new, Ctrl+G generate, Ctrl+H health, Ctrl+L lock
;   (redesign A2/E4; Ctrl+H is E6).
vault_ctrl_key proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-28], edx
    WINCALL GetKeyState, VK_CONTROL_
    test    ax, 8000h
    jz      vck_no
    WINCALL GetParent, qword ptr [rbp-24]
    mov     qword ptr [rbp-40], rax
    mov     eax, dword ptr [rbp-28]
    cmp     eax, 4Bh                           ; 'K' -> focus the sidebar search box
    jne     vck_chkn
    WINCALL GetDlgItem, qword ptr [rbp-40], IDC_V_SEARCH
    WINCALL SetFocus, rax
    jmp     vck_yes
vck_chkn:
    cmp     eax, 4Eh                           ; 'N' -> new item
    jne     @F
    mov     dword ptr [rbp-44], IDC_V_ADD
    jmp     vck_post
@@: cmp     eax, 47h                           ; 'G' -> generate
    jne     @F
    mov     dword ptr [rbp-44], IDC_V_GENERATE
    jmp     vck_post
@@: cmp     eax, 48h                           ; 'H' -> vault-health summary (E6)
    jne     @F
    mov     rcx, qword ptr [rbp-40]            ; parent hwnd
    call    gui_show_health
    jmp     vck_yes
@@: cmp     eax, 4Ch                           ; 'L' -> lock
    jne     vck_no
    mov     dword ptr [rbp-44], IDC_V_LOCK
vck_post:
    WINCALL PostMessageW, qword ptr [rbp-40], WM_COMMAND, qword ptr [rbp-44], 0
vck_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
vck_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
vault_ctrl_key endp

search_type_subclass proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx            ; hwnd (list)
    mov     qword ptr [rbp-32], rdx            ; msg
    mov     qword ptr [rbp-40], r8             ; wParam (char)
    mov     qword ptr [rbp-48], r9             ; lParam
    cmp     rdx, WM_KEYDOWN_
    jne     sts_notkey
    mov     rcx, qword ptr [rbp-24]
    mov     edx, r8d
    call    vault_ctrl_key
    test    eax, eax
    jz      sts_def
    xor     eax, eax
    FRAME_EPILOG
    ret
sts_notkey:
    cmp     rdx, WM_CHAR_
    jne     sts_def
    cmp     r8, 20h                            ; printable (space and up)?
    jb      sts_def
    WINCALL GetParent, qword ptr [rbp-24]
    mov     qword ptr [rbp-56], rax
    WINCALL GetDlgItem, qword ptr [rbp-56], IDC_V_SEARCH   ; focus the sidebar search box,
    mov     qword ptr [rbp-64], rax
    test    rax, rax
    jz      sts_def
    WINCALL SetFocus, qword ptr [rbp-64]
    WINCALL SendMessageW, qword ptr [rbp-64], WM_CHAR_, qword ptr [rbp-40], \
            qword ptr [rbp-48]                  ;   then forward the keystroke into it
    xor     eax, eax                           ; consumed
    FRAME_EPILOG
    ret
sts_def:
    WINCALL DefSubclassProc, qword ptr [rbp-24], qword ptr [rbp-32], qword ptr [rbp-40], \
            qword ptr [rbp-48]
    FRAME_EPILOG
    ret
search_type_subclass endp

; kind_label(edx=kind) -> rax = wide default-label ptr.  Leaf.
kind_label proc
    cmp     edx, VF_USERNAME
    jne     @F
    lea     rax, [kl_user]
    ret
@@: cmp     edx, VF_SECRET
    jne     @F
    lea     rax, [kl_secret]
    ret
@@: cmp     edx, VF_URL
    jne     @F
    lea     rax, [kl_url]
    ret
@@: cmp     edx, VF_NOTES
    jne     @F
    lea     rax, [kl_notes]
    ret
@@: cmp     edx, VF_TOTP
    jne     @F
    lea     rax, [kl_totp]
    ret
@@: cmp     edx, VF_IMAGE
    jne     @F
    lea     rax, [kl_image]
    ret
@@: cmp     edx, VF_FILE
    jne     @F
    lea     rax, [kl_file]
    ret
@@: lea     rax, [kl_text]
    ret
kind_label endp

; gui_rows_clear(rcx=hdlg) - destroy every runtime row control; count -> 0.
gui_rows_clear proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-40], rcx              ; hdlg (for the post-clear repaint)
    mov     dword ptr [rbp-24], 0                ; i
grc_row:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_field_count]
    jae     grc_done
    mov     dword ptr [rbp-32], 0                ; slot
grc_slot:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, DYN_SLOTS
    jae     grc_nextrow
    mov     eax, dword ptr [rbp-24]
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     eax, dword ptr [rbp-32]
    lea     r10, [r10 + FD_HANDLES + rax*8]
    mov     rcx, qword ptr [r10]
    test    rcx, rcx
    jz      grc_slotnext
    mov     qword ptr [r10], 0
    mov     qword ptr [rbp-48], rcx              ; drop its tooltip first: tools are keyed
    mov     rdx, rcx                             ;   by hwnd, so destroying the control
    mov     rcx, qword ptr [rbp-40]              ;   without this strands a dead entry and
    call    ghost_tip_del                        ;   the list grows on every selection
    mov     rcx, qword ptr [rbp-48]
    call    DestroyWindow
grc_slotnext:
    inc     dword ptr [rbp-32]
    jmp     grc_slot
grc_nextrow:
    inc     dword ptr [rbp-24]
    jmp     grc_row
grc_done:
    mov     dword ptr [g_field_count], 0
    ; repaint only the detail pane (not the whole window) so the sidebar card's
    ; border/shadow don't flicker on every selection
    mov     rcx, qword ptr [rbp-40]
    call    gui_inval_detail
    FRAME_EPILOG
    ret
gui_rows_clear endp

; gui_inval_detail(rcx = hdlg) - invalidate just the detail pane (x >= 210 DLU),
;   leaving the sidebar card untouched (avoids flicker of its border/shadow).
gui_inval_detail proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    WINCALL GetClientRect, qword ptr [rbp-24], addr rbp-56
    mov     dword ptr [rbp-80], 210              ; DLU x=210 -> px (detail-left)
    mov     dword ptr [rbp-76], 0
    mov     dword ptr [rbp-72], 210
    mov     dword ptr [rbp-68], 8
    WINCALL MapDialogRect, qword ptr [rbp-24], addr rbp-80
    mov     dword ptr [rbp-76], 0                ; rect = {mapped-left, 0, clientW, clientH}
    mov     eax, dword ptr [rbp-48]              ; rc.right = clientW
    mov     dword ptr [rbp-72], eax
    mov     eax, dword ptr [rbp-44]              ; rc.bottom = clientH
    mov     dword ptr [rbp-68], eax
    WINCALL InvalidateRect, qword ptr [rbp-24], addr rbp-80, 1
    FRAME_EPILOG
    ret
gui_inval_detail endp

; GHOSTIFY - turn the row action button just created by row_mk (hwnd in rax) into
;   a frameless ghost: glyph 0 keeps its window-text glyph, so theme_drawitem's
;   ghost path renders it borderless with a hover halo (matching the header glyphs).
;   Row controls are destroyed and rebuilt on every selection, so their tooltips
;   would accumulate as dead entries - gui_rows_clear now calls ghost_tip_del for
;   each handle before destroying it, which is what makes a per-row tip safe.
GHOSTIFY macro tip
    mov     qword ptr [rbp-56], rax
    mov     rcx, qword ptr [rbp-24]              ; parent
    mov     rdx, qword ptr [rbp-56]              ; button hwnd
    xor     r8d, r8d                             ; glyph 0 -> draw the window-text glyph
IFB <tip>
    xor     r9, r9                               ; no tooltip
ELSE
    lea     r9, [tip]
ENDIF
    call    ghost_attach
endm

; ROWTIP - tooltip for a row button that is NOT ghostified (the reorder chevrons
;   paint through gui_draw_flatchevron instead).  hwnd still in rax from row_mk.
ROWTIP macro tip
    mov     qword ptr [rbp-56], rax
    mov     rcx, qword ptr [rbp-24]              ; parent
    mov     rdx, qword ptr [rbp-56]              ; button hwnd
    lea     r8, [tip]
    call    ghost_tip_add
endm

; gui_row_add(rcx=hdlg, edx=kind) -> eax = row index (or -1 if at MAXROWS).
;   Append a descriptor and create the kind-appropriate row controls (geometry
;   is placeholder; call gui_rows_layout afterwards).
gui_row_add proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx              ; kind
    mov     eax, dword ptr [g_field_count]
    cmp     eax, MAXROWS
    jae     gra_full
    mov     dword ptr [rbp-40], eax              ; i
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax                             ; desc
    mov     ecx, DESCSZ/8
gra_zero:
    mov     qword ptr [r10], 0
    add     r10, 8
    dec     ecx
    jnz     gra_zero
    mov     eax, dword ptr [rbp-40]
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [r10+FD_KIND], eax
    cmp     eax, VF_SPACER                       ; layout blocks carry no editable label
    je      gra_spacer
    cmp     eax, VF_GROUP
    je      gra_group
    ; label (editable, kind's default caption)
    mov     edx, dword ptr [rbp-32]
    call    kind_label
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_LABEL, addr cls_edit, rax, ES_AUTOHSCROLL_
    ; value (kind-specific)
    mov     eax, dword ptr [rbp-32]
    cmp     eax, VF_SECRET
    je      gra_secret
    cmp     eax, VF_NOTES
    je      gra_notes
    cmp     eax, VF_TOTP
    je      gra_totp
    cmp     eax, VF_IMAGE                        ; images and files are both plain,
    je      gra_file                            ; download-only attachments now
    cmp     eax, VF_FILE
    je      gra_file
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_edit, 0, \
            ES_AUTOHSCROLL_ or WS_TABSTOP_ or WS_CLIPSIBLINGS_
    jmp     gra_reorder
gra_file:
    ; attachments tile: owner-draw tag list (DS_VALUE, click = open/remove) + a
    ; Choose button pinned top-right.  Up/Down reposition the tile; NO trashcan -
    ; the tile is removed automatically when its last file is deleted.
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_button, 0, \
            BS_OWNERDRAW_ or WS_TABSTOP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_IMPORT, addr cls_button, addr wb_addf, \
            BS_OWNERDRAW_ or WS_TABSTOP_
    GHOSTIFY gt_attach
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_UP, addr cls_button, addr wb_up, \
            BS_OWNERDRAW_
    ROWTIP  gt_rowup
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_DOWN, addr cls_button, addr wb_down, \
            BS_OWNERDRAW_
    ROWTIP  gt_rowdn
    jmp     gra_finish
gra_secret:
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_edit, 0, \
            ES_PASSWORD_ or ES_AUTOHSCROLL_ or WS_TABSTOP_ or WS_CLIPSIBLINGS_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_REVEAL, addr cls_button, addr wb_eye, \
            BS_OWNERDRAW_
    GHOSTIFY gt_reveal
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_COPY, addr cls_button, addr wb_copy, \
            BS_OWNERDRAW_
    GHOSTIFY gt_rowcopy
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_SBADGE, addr cls_static, 0, \
            SS_OWNERDRAW_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_GEN, addr cls_button, addr wb_gen, \
            BS_OWNERDRAW_
    GHOSTIFY gt_rowgen
    jmp     gra_reorder
gra_notes:
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_edit, 0, \
            ES_MULTILINE_ or ES_AUTOVSCROLL_ or ES_WANTRETURN_ or WS_TABSTOP_ or WS_CLIPSIBLINGS_
    jmp     gra_reorder
gra_totp:
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_edit, 0, \
            ES_PASSWORD_ or ES_AUTOHSCROLL_ or WS_TABSTOP_ or WS_CLIPSIBLINGS_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_REVEAL, addr cls_button, addr wb_eye, \
            BS_OWNERDRAW_
    GHOSTIFY gt_reveal
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_TCODE, addr cls_static, 0, \
            SS_LEFTNOWORDWRAP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_TBAR, addr cls_static, 0, \
            SS_OWNERDRAW_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_COPY, addr cls_button, addr wb_copy, \
            BS_OWNERDRAW_
    GHOSTIFY gt_rowcopy
    jmp     gra_reorder
gra_group:
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_edit, 0, \
            ES_AUTOHSCROLL_ or WS_TABSTOP_ or WS_CLIPSIBLINGS_   ; the section title (heading)
    jmp     gra_reorder
gra_spacer:                                      ; a blank gap - no controls, just height
gra_reorder:
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_UP, addr cls_button, addr wb_up, \
            BS_OWNERDRAW_
    ROWTIP  gt_rowup
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_DOWN, addr cls_button, addr wb_down, \
            BS_OWNERDRAW_
    ROWTIP  gt_rowdn
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_DEL, addr cls_button, addr wb_rem, \
            BS_OWNERDRAW_
    GHOSTIFY gt_rowdel
gra_finish:
    ; Hard-stop the value edit at exactly what the display path can render back
    ; (gui_setfield converts with CONVW_MAX-1).  Without this a user could type or
    ; paste a value longer than the buffer, save it, and then find the field blank
    ; on reload - at which point the next save wrote the blank over it.  The limit
    ; is enforced by the edit control, so the text simply stops growing.
    ; Harmless on the attachment tile, whose DS_VALUE is an owner-draw button.
    mov     eax, dword ptr [rbp-40]
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_VALUE*8]
    test    rcx, rcx
    jz      gra_nolimit
    WINCALL SendMessageW, rcx, EM_LIMITTEXT, CONVW_MAX-1, 0
gra_nolimit:
    inc     dword ptr [g_field_count]
    mov     eax, dword ptr [rbp-40]
    FRAME_EPILOG
    ret
gra_full:
    mov     eax, -1
    FRAME_EPILOG
    ret
gui_row_add endp

; =============================================================================
; Attachment field helpers (store/choose/open/save encrypted file blobs)
; =============================================================================

; gui_bcpy(rcx=dst, rdx=src, r8=len) - byte copy.  Leaf.
gui_bcpy proc
    xor     r9, r9
gbc_l:
    cmp     r9, r8
    jae     gbc_d
    mov     al, byte ptr [rdx+r9]
    mov     byte ptr [rcx+r9], al
    inc     r9
    jmp     gbc_l
gbc_d:
    ret
gui_bcpy endp

; gui_desc(ecx=row) -> rax = &g_fields[row].  Leaf.
gui_desc proc
    mov     eax, ecx
    imul    eax, eax, DESCSZ
    lea     rdx, [g_fields]
    add     rax, rdx
    ret
gui_desc endp

; -----------------------------------------------------------------------------
; tf_* - the attachments tile's file list (g_tilefiles / g_tilefile_n).  Each
;   entry is {AttachRef[68], filename wide (NUL-terminated)}.  One tile per entry.
; -----------------------------------------------------------------------------
; tf_reset() - empty the list.  Leaf.
tf_reset proc
    mov     dword ptr [g_tilefile_n], 0
    ret
tf_reset endp

; tf_entry(ecx = index) -> rax = &g_tilefiles[index].  Leaf.
tf_entry proc
    mov     eax, ecx
    imul    eax, eax, TFILE_ENTRY
    lea     rdx, [g_tilefiles]
    add     rax, rdx
    ret
tf_entry endp

; tf_append(rcx = AttachRef[68], rdx = filename wide) -> eax = 0 ok / 1 full.
tf_append proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     eax, dword ptr [g_tilefile_n]
    cmp     eax, MAX_TFILES
    jae     tfa_full
    mov     ecx, eax
    call    tf_entry
    mov     qword ptr [rbp-40], rax             ; dst entry
    mov     rcx, rax                            ; copy the 68-byte AttachRef
    mov     rdx, qword ptr [rbp-24]
    mov     r8, 68
    call    gui_bcpy
    mov     rcx, qword ptr [rbp-40]             ; copy the filename (capped, NUL-term)
    add     rcx, TFILE_NAME
    mov     rdx, qword ptr [rbp-32]
    call    gui_wcpy_capped
    inc     dword ptr [g_tilefile_n]
    xor     eax, eax
    FRAME_EPILOG
    ret
tfa_full:
    mov     eax, 1
    FRAME_EPILOG
    ret
tf_append endp

; tf_remove(ecx = index) - drop entry [index], shifting the tail down.
tf_remove proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], ecx
    cmp     ecx, dword ptr [g_tilefile_n]
    jae     tfr_done                            ; out of range
tfr_shift:
    mov     ecx, dword ptr [rbp-24]
    inc     ecx
    cmp     ecx, dword ptr [g_tilefile_n]
    jae     tfr_dec
    mov     ecx, dword ptr [rbp-24]             ; dst = [i]
    call    tf_entry
    mov     qword ptr [rbp-32], rax
    mov     ecx, dword ptr [rbp-24]             ; src = [i+1]
    inc     ecx
    call    tf_entry
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, rax
    mov     r8, TFILE_ENTRY
    call    gui_bcpy
    inc     dword ptr [rbp-24]
    jmp     tfr_shift
tfr_dec:
    dec     dword ptr [g_tilefile_n]
tfr_done:
    FRAME_EPILOG
    ret
tf_remove endp

; tf_find_row() -> eax = row index of the attachments tile (VF_FILE/VF_IMAGE) or -1.
tf_find_row proc frame
    FRAME_PROLOG 32
    mov     dword ptr [rbp-24], 0
tff_l:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_field_count]
    jae     tff_none
    mov     ecx, eax
    call    gui_desc
    mov     ecx, dword ptr [rax+FD_KIND]
    cmp     ecx, VF_FILE
    je      tff_hit
    cmp     ecx, VF_IMAGE
    je      tff_hit
    inc     dword ptr [rbp-24]
    jmp     tff_l
tff_hit:
    mov     eax, dword ptr [rbp-24]
    FRAME_EPILOG
    ret
tff_none:
    mov     eax, -1
    FRAME_EPILOG
    ret
tf_find_row endp

; -----------------------------------------------------------------------------
; pwh_* / pworig_* - password history for the open entry (g_pwhist) and the
;   original secret values captured at load (g_pworig) used to detect overwrites.
; -----------------------------------------------------------------------------
; pwh_reset() - clear history + originals for a freshly opened entry.  Zeroes the
;   buffers, not just the counts: g_pworig holds the plaintext of EVERY field of
;   the entry (pworig_add runs before the kind check, so secrets included) and
;   g_pwhist holds superseded values.  Dropping only the counts left the previous
;   entry's secrets resident for the life of the process - and gui_towide does not
;   pad, so a shorter value never covered a longer one's tail.
pwh_reset proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_pwhist]
    mov     edx, MAX_PWHIST*PWHIST_ENTRY
    call    secure_zero
    lea     rcx, [g_pworig]
    mov     edx, MAX_PWORIG*PWORIG_STRIDE
    call    secure_zero
    lea     rcx, [g_pwhblob]
    mov     edx, MAX_PWHIST*PWHBLOB_ENTRY
    call    secure_zero
    lea     rcx, [g_pworig_hd]
    mov     edx, MAX_PWORIG
    call    secure_zero
    mov     dword ptr [g_pwhist_n], 0
    mov     dword ptr [g_pworig_n], 0
    FRAME_EPILOG
    ret
pwh_reset endp

; pwh_entry(ecx = index) -> rax = &g_pwhist[index].  Leaf.
pwh_entry proc
    mov     eax, ecx
    imul    eax, eax, PWHIST_ENTRY
    lea     rdx, [g_pwhist]
    add     rax, rdx
    ret
pwh_entry endp

; pwh_append(rcx = FILETIME qword, rdx = wide label, r8 = wide old value,
;            r9d = PWHA_* action) - add a history entry; when full, drop the
;   oldest so the most recent are kept.
pwh_append proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-56], r8
    mov     dword ptr [rbp-64], r9d
    mov     eax, dword ptr [g_pwhist_n]
    cmp     eax, MAX_PWHIST
    jb      pwa_slot
    mov     dword ptr [rbp-40], 0             ; shift [1..n) down over [0..n-1)
pwa_shift:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, MAX_PWHIST-1
    jae     pwa_shifted
    mov     ecx, dword ptr [rbp-40]
    call    pwh_entry
    mov     qword ptr [rbp-48], rax
    mov     ecx, dword ptr [rbp-40]
    inc     ecx
    call    pwh_entry
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, rax
    mov     r8, PWHIST_ENTRY
    call    gui_bcpy
    inc     dword ptr [rbp-40]
    jmp     pwa_shift
pwa_shifted:
    mov     dword ptr [g_pwhist_n], MAX_PWHIST-1
    mov     eax, MAX_PWHIST-1
pwa_slot:
    mov     ecx, eax
    call    pwh_entry
    mov     qword ptr [rbp-48], rax           ; entry ptr
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [rax], r10              ; filetime
    lea     rcx, [rax+PWHIST_LBL]             ; label (capped, NUL-term)
    mov     rdx, qword ptr [rbp-32]
    call    gui_wcpy_capped
    mov     rax, qword ptr [rbp-48]
    lea     rcx, [rax+PWHIST_PW]             ; old value (capped, NUL-term; empty for ADDED)
    mov     rdx, qword ptr [rbp-56]
    call    gui_wcpy_capped
    mov     rax, qword ptr [rbp-48]
    mov     r10d, dword ptr [rbp-64]
    mov     dword ptr [rax+PWHIST_ACT], r10d ; action
    inc     dword ptr [g_pwhist_n]
    FRAME_EPILOG
    ret
pwh_append endp

; pwh_remove(ecx = index) - purge one history entry (shift the tail down).
pwh_remove proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_readonly], 0           ; E9: no history purge in read-only mode
    jne     pwr_done
    mov     dword ptr [rbp-24], ecx
    cmp     ecx, dword ptr [g_pwhist_n]
    jae     pwr_done
pwr_shift:
    mov     ecx, dword ptr [rbp-24]
    inc     ecx
    cmp     ecx, dword ptr [g_pwhist_n]
    jae     pwr_dec
    mov     ecx, dword ptr [rbp-24]
    call    pwh_entry
    mov     qword ptr [rbp-32], rax
    mov     ecx, dword ptr [rbp-24]
    inc     ecx
    call    pwh_entry
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, rax
    mov     r8, PWHIST_ENTRY
    call    gui_bcpy
    inc     dword ptr [rbp-24]
    jmp     pwr_shift
pwr_dec:
    dec     dword ptr [g_pwhist_n]
pwr_done:
    FRAME_EPILOG
    ret
pwh_remove endp

; pworig_add(edx = labellen; rcx = custom label utf8 when labellen>0, else the
;            kind's DEFAULT label wide-ptr; r8 = value utf8, r9d = vallen) -
;   remember an original field's effective label + value (as wide) at load, so
;   gui_commit can detect + attribute a per-tile overwrite.
pworig_add proc frame
    FRAME_PROLOG 80                            ; each local its own 8-byte slot (a dword
    mov     eax, dword ptr [g_pworig_n]        ; under a qword's footprint gets clobbered
    cmp     eax, MAX_PWORIG                     ; when the qword pointer is written)
    jae     poa_done
    mov     qword ptr [rbp-16], rcx           ; label utf8
    mov     dword ptr [rbp-24], edx           ; labellen
    mov     qword ptr [rbp-32], r8            ; value utf8
    mov     dword ptr [rbp-40], r9d           ; vallen
    imul    eax, eax, PWORIG_STRIDE
    lea     r10, [g_pworig]
    add     r10, rax
    mov     qword ptr [rbp-48], r10           ; slot
    cmp     dword ptr [rbp-24], 0
    je      poa_deflbl
    mov     rcx, qword ptr [rbp-16]           ; custom label -> wide
    mov     edx, dword ptr [rbp-24]
    mov     r8, qword ptr [rbp-48]
    mov     r9d, 127
    call    gui_towide
    jmp     poa_val
poa_deflbl:
    mov     rcx, qword ptr [rbp-48]           ; unlabeled -> caller's kind default (wide)
    mov     rdx, qword ptr [rbp-16]
    call    gui_wcpy_capped
poa_val:
    mov     rcx, qword ptr [rbp-32]           ; value -> wide at slot+PWORIG_VAL
    mov     edx, dword ptr [rbp-40]
    mov     r8, qword ptr [rbp-48]
    add     r8, PWORIG_VAL
    mov     r9d, 127
    call    gui_towide
    mov     eax, dword ptr [g_pworig_n]       ; note whether this field carried data,
    lea     r10, [g_pworig_hd]                ;   taken from the SOURCE length: the wide
    xor     ecx, ecx                          ;   copy above caps at 127 chars, so a
    cmp     dword ptr [rbp-40], 0             ;   longer value lands empty and must not
    je      @F                                ;   be mistaken for "never had a value"
    mov     ecx, 1
@@: mov     byte ptr [r10+rax], cl
    inc     dword ptr [g_pworig_n]
poa_done:
    FRAME_EPILOG
    ret
pworig_add endp

; gui_wcpy_capped(rcx=dst, rdx=src wide) -> eax = bytes copied incl NUL.  Leaf.
gui_wcpy_capped proc
    xor     r8d, r8d
gwc_l:
    mov     ax, word ptr [rdx+r8*2]
    mov     word ptr [rcx+r8*2], ax
    test    ax, ax
    jz      gwc_done
    inc     r8d
    cmp     r8d, 120
    jb      gwc_l
    mov     word ptr [rcx+r8*2], 0
gwc_done:
    inc     r8d
    mov     eax, r8d
    shl     eax, 1
    ret
gui_wcpy_capped endp

; img_pick(rcx=hdlg, edx=save?) -> eax = 1 if a path was chosen into g_imgpath.
img_pick proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    lea     rcx, [g_ofn]
    mov     edx, sizeof OPENFILENAMEW
    call    secure_zero
    lea     r10, [g_ofn]
    mov     dword ptr [r10].OPENFILENAMEW.lStructSize, sizeof OPENFILENAMEW
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [r10].OPENFILENAMEW.hwndOwner, rax
    mov     rax, qword ptr [g_pickfilter]
    test    rax, rax
    jnz     @F
    lea     rax, [g_imgfilter]
@@: mov     qword ptr [r10].OPENFILENAMEW.lpstrFilter, rax
    lea     rax, [g_imgpath]
    mov     qword ptr [r10].OPENFILENAMEW.lpstrFile, rax
    mov     dword ptr [r10].OPENFILENAMEW.nMaxFile, 1024
    mov     dword ptr [r10].OPENFILENAMEW.nFilterIndex, 1
    cmp     dword ptr [rbp-32], 0
    jne     ip_save
    mov     word ptr [g_imgpath], 0             ; open: start from an empty pick
    mov     dword ptr [r10].OPENFILENAMEW.Flags, OFN_FILEMUSTEXIST or OFN_PATHMUSTEXIST or OFN_HIDEREADONLY or OFN_EXPLORER
    WINCALL GetOpenFileNameW, addr g_ofn
    FRAME_EPILOG
    ret
ip_save:
    mov     dword ptr [r10].OPENFILENAMEW.Flags, OFN_OVERWRITEPROMPT or OFN_PATHMUSTEXIST or OFN_HIDEREADONLY or OFN_EXPLORER
    WINCALL GetSaveFileNameW, addr g_ofn
    FRAME_EPILOG
    ret
img_pick endp

; gui_basename(rcx=wide path) - copy the file-name part (after the last \ or /)
;   into g_imgfn_w (wide, NUL-terminated, capped).  Leaf.
gui_basename proc
    mov     r10, rcx
    mov     r11, rcx                            ; start of basename
gb_scan:
    mov     ax, word ptr [r10]
    test    ax, ax
    jz      gb_copy
    cmp     ax, '\'
    je      gb_sep
    cmp     ax, '/'
    jne     gb_next
gb_sep:
    lea     r11, [r10+2]
gb_next:
    add     r10, 2
    jmp     gb_scan
gb_copy:
    lea     r10, [g_imgfn_w]
    xor     r8d, r8d
gb_cp:
    mov     ax, word ptr [r11+r8*2]
    mov     word ptr [r10+r8*2], ax
    test    ax, ax
    jz      gb_done
    inc     r8d
    cmp     r8d, 120
    jb      gb_cp
    mov     word ptr [r10+r8*2], 0
gb_done:
    ret
gui_basename endp

; =============================================================================
; Generic file attachments (VF_FILE)
; =============================================================================

; gui_tile_make_temp(ecx = file index) - build g_tmpfile = %TEMP%\<basename>.
;   The stored filename can be attacker-controlled (imported from a zip), so any
;   directory part is stripped (basename after the last '\' or '/') to keep the
;   written+opened file confined to %TEMP% - no "..\" path traversal out of it.
gui_tile_make_temp proc frame
    FRAME_PROLOG 64   ; >= 64: keep locals clear of the callee 32-byte home area
    mov     dword ptr [rbp-24], ecx
    WINCALL GetTempPathW, 512, addr g_tmpfile
    mov     dword ptr [rbp-32], eax                  ; base length incl trailing '\'
    mov     ecx, dword ptr [rbp-24]
    call    tf_entry
    add     rax, TFILE_NAME
    mov     r10, rax                                 ; scan cursor
    mov     r11, rax                                 ; basename start
gtmt_scan:
    mov     dx, word ptr [r10]
    test    dx, dx
    jz      gtmt_scandone
    cmp     dx, '\'
    je      gtmt_sep
    cmp     dx, '/'
    jne     gtmt_next
gtmt_sep:
    lea     r11, [r10+2]                             ; name restarts after the separator
gtmt_next:
    add     r10, 2
    jmp     gtmt_scan
gtmt_scandone:
    mov     qword ptr [rbp-40], r11                  ; sanitized filename ptr (basename)
    mov     eax, dword ptr [rbp-32]
    lea     rcx, [g_tmpfile]
    lea     rcx, [rcx+rax*2]                         ; dst = g_tmpfile + baselen
    mov     rdx, qword ptr [rbp-40]
    movzx   eax, word ptr [rdx]                      ; empty name -> default
    test    eax, eax
    jnz     @F
    lea     rdx, [name_default_att]
@@: call    gui_wcpy_capped
    FRAME_EPILOG
    ret
gui_tile_make_temp endp

; gui_tile_relayout(rcx = hdlg, edx = row) - re-flow the form and repaint the tile's
;   tag-list control after the file count changed.
gui_tile_relayout proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    call    gui_rows_layout                          ; rcx = hdlg (already)
    mov     ecx, dword ptr [rbp-32]
    mov     edx, DS_VALUE
    call    dynid
    mov     rcx, qword ptr [rbp-24]
    mov     edx, eax
    call    GetDlgItem
    WINCALL InvalidateRect, rax, 0, 1
    FRAME_EPILOG
    ret
gui_tile_relayout endp

; gui_tile_choose(rcx = hdlg, edx = row) - pick a file, encrypt+stage it, and
;   append it to the attachments tile's file list; then re-flow.
gui_tile_choose proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    lea     rax, [g_allfilter]
    mov     qword ptr [g_pickfilter], rax
    mov     rcx, qword ptr [rbp-24]
    xor     edx, edx                                 ; open dialog
    call    img_pick
    test    eax, eax
    jz      gtc_done
    lea     rcx, [g_imgpath]
    lea     rdx, [g_imgbuf]
    lea     r8, [g_imgbuflen]
    call    read_file
    test    eax, eax
    jnz     gtc_done
    lea     rcx, [g_imgpath]
    call    gui_basename                             ; -> g_imgfn_w
    mov     rcx, qword ptr [g_imgbuf]                 ; encrypt+stage -> g_imgstageref
    mov     rdx, qword ptr [g_imgbuflen]
    lea     r8, [g_imgstageref]
    call    attach_stage
    test    eax, eax
    jnz     gtc_free
    lea     rcx, [g_imgstageref]                     ; append {ref, filename}
    lea     rdx, [g_imgfn_w]
    call    tf_append
    mov     dword ptr [g_dirty], 1
gtc_free:
    mov     rcx, qword ptr [g_imgbuf]
    mov     rdx, qword ptr [g_imgbuflen]
    call    mem_free
    mov     qword ptr [g_imgbuf], 0
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    call    gui_tile_relayout
gtc_done:
    FRAME_EPILOG
    ret
gui_tile_choose endp

; gui_tag_open(ecx = file index) - decrypt g_tilefiles[i] to a %TEMP% file and open
;   it in the system default app.  The temp path is tracked (gui_temp_track) and
;   securely overwritten + deleted when the vault locks (gui_temp_purge).
gui_tag_open proc frame
    FRAME_PROLOG 96                             ; room for ShellExecuteW's 6-arg spill
    mov     dword ptr [rbp-32], ecx
    cmp     ecx, dword ptr [g_tilefile_n]
    jae     gto_done
    mov     ecx, dword ptr [rbp-32]
    call    tf_entry                                 ; rax = &entry (AttachRef @ +0)
    mov     rcx, rax
    lea     rdx, [rbp-48]                            ; &len
    call    attach_open
    test    rax, rax
    jz      gto_done
    mov     qword ptr [rbp-56], rax                  ; plaintext
    mov     ecx, dword ptr [rbp-32]
    call    gui_tile_make_temp                       ; -> g_tmpfile
    lea     rcx, [g_tmpfile]
    mov     rdx, qword ptr [rbp-56]
    mov     r8, qword ptr [rbp-48]
    call    write_file
    mov     dword ptr [rbp-60], eax                  ; write_file result
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-48]
    call    mem_free
    cmp     dword ptr [rbp-60], 0                     ; only open if the temp was written
    jne     gto_done
    WINCALL SetFileAttributesW, addr g_tmpfile, FILE_ATTRIBUTE_TEMPORARY  ; hint: keep in cache
    lea     rcx, [g_tmpfile]                          ; track for deterministic wipe on lock
    mov     rdx, qword ptr [rbp-48]
    call    gui_temp_track
    WINCALL ShellExecuteW, 0, addr verb_open, addr g_tmpfile, 0, 0, 1
gto_done:
    FRAME_EPILOG
    ret
gui_tag_open endp

; gui_temp_track(rcx = wide path, rdx = plaintext size) - record a decrypt-to-temp
;   file so gui_temp_purge can overwrite + delete it on lock/exit.  If the table is
;   full, purge it first (flushing the older files) then record this one.
gui_temp_track proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     eax, dword ptr [g_tempfile_n]
    cmp     eax, MAX_TEMPFILES
    jb      gtt_have
    call    gui_temp_purge                            ; full -> flush, then start over
    xor     eax, eax
gtt_have:
    imul    eax, eax, TEMPREC                         ; &g_tempfiles[n]
    lea     r10, [g_tempfiles]
    add     r10, rax
    mov     qword ptr [rbp-40], r10
    mov     rcx, qword ptr [rbp-24]                   ; copy the path (capped)
    xor     r8d, r8d
gtt_cp:
    mov     ax, word ptr [rcx+r8*2]
    mov     word ptr [r10+r8*2], ax
    test    ax, ax
    jz      gtt_cpdone
    inc     r8d
    cmp     r8d, TEMP_PATHW-1
    jb      gtt_cp
    mov     word ptr [r10+r8*2], 0                     ; force-terminate an over-long path
gtt_cpdone:
    mov     r10, qword ptr [rbp-40]
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [r10+TEMP_SIZEOFF], rax          ; plaintext size for the wipe
    inc     dword ptr [g_tempfile_n]
    FRAME_EPILOG
    ret
gui_temp_track endp

; gui_temp_purge() -> eax = count of files purged.  For each tracked temp file:
;   open it, overwrite its whole length with zeros, flush to disk, close, delete.
;   Clears the table.  Best-effort per file (a vanished/locked file is skipped).
gui_temp_purge proc frame
    FRAME_PROLOG 96                            ; CreateFileW(7)/WriteFile(5) arg spill below rbp-56
    ; [rbp-24]=i, [rbp-32]=handle, [rbp-40]=remaining, [rbp-48]=&entry, [rbp-56]=purged
    ; [rbp-64] = WriteFile bytes-written (throwaway, in the spill zone)
    mov     dword ptr [rbp-56], 0
    lea     rcx, [g_wipezeros]                        ; ensure the source really is zero
    mov     edx, WIPE_CHUNK
    call    secure_zero
    mov     dword ptr [rbp-24], 0
gtp_loop:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_tempfile_n]
    jae     gtp_clear
    imul    eax, eax, TEMPREC
    lea     r10, [g_tempfiles]
    add     r10, rax
    mov     qword ptr [rbp-48], r10                    ; &entry (path @ +0)
    WINCALL CreateFileW, r10, GENERIC_WRITE_, 0, 0, OPEN_EXISTING_, FILE_ATTR_NORMAL_, 0
    cmp     rax, -1
    je      gtp_del                                    ; can't open -> still try to delete
    mov     qword ptr [rbp-32], rax
    mov     r10, qword ptr [rbp-48]
    mov     rax, qword ptr [r10+TEMP_SIZEOFF]
    mov     qword ptr [rbp-40], rax                    ; remaining bytes to overwrite
gtp_wipe:
    cmp     qword ptr [rbp-40], 0
    je      gtp_flush
    mov     r10, qword ptr [rbp-40]
    cmp     r10, WIPE_CHUNK
    jbe     @F
    mov     r10, WIPE_CHUNK
@@: WINCALL WriteFile, qword ptr [rbp-32], addr g_wipezeros, r10d, addr rbp-64, 0
    test    eax, eax
    jz      gtp_flush                                  ; write error -> stop, still delete
    mov     r10d, dword ptr [rbp-64]
    test    r10d, r10d
    jz      gtp_flush                                  ; wrote 0 -> avoid an infinite loop
    sub     qword ptr [rbp-40], r10
    jmp     gtp_wipe
gtp_flush:
    WINCALL FlushFileBuffers, qword ptr [rbp-32]       ; force the zeros to the platter
    WINCALL CloseHandle, qword ptr [rbp-32]
gtp_del:
    WINCALL DeleteFileW, qword ptr [rbp-48]
    inc     dword ptr [rbp-56]
    inc     dword ptr [rbp-24]
    jmp     gtp_loop
gtp_clear:
    lea     rcx, [g_tempfiles]                         ; scrub the path table itself
    mov     edx, MAX_TEMPFILES*TEMPREC
    call    secure_zero
    mov     dword ptr [g_tempfile_n], 0
    mov     eax, dword ptr [rbp-56]
    FRAME_EPILOG
    ret
gui_temp_purge endp

; gui_tmptest() -> eax = 0 pass / 1 fail (headless probe for the secure temp
;   lifecycle).  Writes a %TEMP% file, tracks it, confirms it exists, purges,
;   then confirms gui_temp_purge overwrote + deleted it.
public gui_tmptest
gui_tmptest proc frame
    FRAME_PROLOG 48
    mov     dword ptr [g_tempfile_n], 0               ; isolated table for the probe
    WINCALL GetTempPathW, 512, addr g_tmpfile         ; g_tmpfile = %TEMP%\
    lea     r10, [g_tmpfile]                          ; append the fixed test name
    lea     r10, [r10+rax*2]
    lea     r11, [wtmptest_name]
    xor     ecx, ecx
gtt2_cp:
    mov     dx, word ptr [r11+rcx*2]
    mov     word ptr [r10+rcx*2], dx
    test    dx, dx
    jz      gtt2_cpd
    inc     ecx
    jmp     gtt2_cp
gtt2_cpd:
    lea     r10, [g_wipezeros]                        ; 4096 bytes of a nonzero pattern
    mov     ecx, 4096
gtt2_fill:
    mov     byte ptr [r10+rcx-1], 0ABh
    dec     ecx
    jnz     gtt2_fill
    lea     rcx, [g_tmpfile]
    lea     rdx, [g_wipezeros]
    mov     r8, 4096
    call    write_file
    test    eax, eax
    jnz     gtt2_fail                                 ; couldn't write the probe file
    lea     rcx, [g_tmpfile]                          ; track it (size 4096)
    mov     rdx, 4096
    call    gui_temp_track
    WINCALL GetFileAttributesW, addr g_tmpfile        ; must exist now
    cmp     eax, -1
    je      gtt2_fail
    call    gui_temp_purge                            ; overwrite + delete
    WINCALL GetFileAttributesW, addr g_tmpfile        ; must be gone now
    cmp     eax, -1
    jne     gtt2_fail_del
    xor     eax, eax
    FRAME_EPILOG
    ret
gtt2_fail_del:
    WINCALL DeleteFileW, addr g_tmpfile               ; don't leak the probe file on failure
gtt2_fail:
    mov     dword ptr [g_tempfile_n], 0
    mov     eax, 1
    FRAME_EPILOG
    ret
gui_tmptest endp

; gui_ext_is_exec(rcx = wide filename) -> eax = 1 if the extension is a known
;   executable/script type (exec_exts denylist).  Extracts the extension of the
;   basename (last '.' after the last '\' or '/'), ignoring trailing dots/spaces
;   that Windows strips, and compares case-insensitively.
gui_ext_is_exec proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx            ; name
    mov     r10, rcx                           ; find the NUL terminator
gxe_end:
    cmp     word ptr [r10], 0
    je      gxe_haveend
    add     r10, 2
    jmp     gxe_end
gxe_haveend:
    ; trim trailing '.' and ' ' (Windows ignores them when resolving a name)
gxe_trim:
    cmp     r10, qword ptr [rbp-24]
    jbe     gxe_noext
    movzx   eax, word ptr [r10-2]
    cmp     eax, '.'
    je      gxe_trimc
    cmp     eax, ' '
    jne     gxe_trimdone
gxe_trimc:
    sub     r10, 2
    jmp     gxe_trim
gxe_trimdone:
    mov     qword ptr [rbp-32], r10            ; end (after trim)
    ; last '.' within the basename (a separator resets it -> new component)
    mov     r11, qword ptr [rbp-24]
    mov     qword ptr [rbp-40], 0             ; dot ptr = none
gxe_scan:
    cmp     r11, qword ptr [rbp-32]
    jae     gxe_scandone
    movzx   eax, word ptr [r11]
    cmp     eax, '\'
    je      gxe_ssep
    cmp     eax, '/'
    je      gxe_ssep
    cmp     eax, '.'
    jne     gxe_snext
    mov     qword ptr [rbp-40], r11
    jmp     gxe_snext
gxe_ssep:
    mov     qword ptr [rbp-40], 0
gxe_snext:
    add     r11, 2
    jmp     gxe_scan
gxe_scandone:
    mov     r11, qword ptr [rbp-40]
    test    r11, r11
    jz      gxe_noext                          ; no '.' in the basename
    add     r11, 2                             ; ext start = after the '.'
    cmp     r11, qword ptr [rbp-32]
    jae     gxe_noext                          ; nothing after the '.'
    ; copy the extension -> g_extw, lowercased, capped at 15 chars
    lea     r8, [g_extw]
    xor     ecx, ecx
gxe_cpy:
    cmp     r11, qword ptr [rbp-32]
    jae     gxe_cpd
    cmp     ecx, 15
    jae     gxe_cpd
    movzx   eax, word ptr [r11]
    cmp     eax, 'A'
    jb      @F
    cmp     eax, 'Z'
    ja      @F
    add     eax, 20h
@@: mov     word ptr [r8+rcx*2], ax
    inc     ecx
    add     r11, 2
    jmp     gxe_cpy
gxe_cpd:
    mov     word ptr [r8+rcx*2], 0             ; NUL-terminate
    lea     r10, [exec_exts]
    mov     qword ptr [rbp-40], r10            ; denylist cursor (survives the call)
gxe_next:
    mov     r10, qword ptr [rbp-40]
    cmp     word ptr [r10], 0
    je      gxe_noext                          ; double-NUL -> not found
    lea     rcx, [g_extw]
    mov     rdx, r10
    call    gui_wstr_eq
    test    eax, eax
    jnz     gxe_yes
    mov     r10, qword ptr [rbp-40]            ; advance past this entry's NUL
gxe_adv:
    cmp     word ptr [r10], 0
    je      gxe_advd
    add     r10, 2
    jmp     gxe_adv
gxe_advd:
    add     r10, 2
    mov     qword ptr [rbp-40], r10
    jmp     gxe_next
gxe_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
gxe_noext:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_ext_is_exec endp

; gui_tag_saveas(rcx = hdlg, edx = file index) - decrypt the attachment and let the
;   user pick where to save it (Save As).  Used for executable/script types instead
;   of opening them: Vordr writes the file but never runs it on the user's behalf.
gui_tag_saveas proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx           ; hdlg
    mov     dword ptr [rbp-32], edx           ; index
    ; prefill the Save As name with the basename of the stored filename
    mov     ecx, edx
    call    tf_entry
    add     rax, TFILE_NAME
    mov     r10, rax
    mov     r11, rax
gts_scan:
    mov     dx, word ptr [r10]
    test    dx, dx
    jz      gts_scandone
    cmp     dx, '\'
    je      gts_sep
    cmp     dx, '/'
    jne     gts_snext
gts_sep:
    lea     r11, [r10+2]
gts_snext:
    add     r10, 2
    jmp     gts_scan
gts_scandone:
    mov     qword ptr [rbp-40], r11
    movzx   eax, word ptr [r11]               ; empty name -> default
    test    eax, eax
    jnz     @F
    lea     r11, [name_default_att]
    mov     qword ptr [rbp-40], r11
@@: lea     rcx, [g_imgpath]
    mov     rdx, qword ptr [rbp-40]
    call    gui_wcpy_capped
    lea     rax, [g_allfilter]
    mov     qword ptr [g_pickfilter], rax
    mov     rcx, qword ptr [rbp-24]
    mov     edx, 1                            ; Save As dialog
    call    img_pick
    test    eax, eax
    jz      gts_done                          ; cancelled
    mov     ecx, dword ptr [rbp-32]
    call    tf_entry                          ; AttachRef @ +0
    mov     rcx, rax
    lea     rdx, [rbp-48]                      ; &len
    call    attach_open
    test    rax, rax
    jz      gts_done
    mov     qword ptr [rbp-56], rax           ; plaintext
    lea     rcx, [g_imgpath]                  ; write to the chosen path (no ShellExecute)
    mov     rdx, rax
    mov     r8, qword ptr [rbp-48]
    call    write_file
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-48]
    call    mem_free
gts_done:
    FRAME_EPILOG
    ret
gui_tag_saveas endp

; gui_tag_click(rcx = hdlg, edx = row) - a tag-list chip was clicked.  Map the cursor
;   to a chip index; in edit mode a hit on the right-side 'x' removes that file (and
;   deletes the whole tile when the last file goes), otherwise the file is opened.
gui_tag_click proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    cmp     dword ptr [g_tilefile_n], 0
    je      gtk_done
    mov     ecx, dword ptr [rbp-32]                  ; tag-list control hwnd
    mov     edx, DS_VALUE
    call    dynid
    mov     rcx, qword ptr [rbp-24]
    mov     edx, eax
    call    GetDlgItem
    mov     qword ptr [rbp-40], rax
    test    rax, rax
    jz      gtk_done
    lea     rcx, [rbp-56]                            ; POINT: x @ -56, y @ -52
    call    GetCursorPos
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [rbp-56]
    call    ScreenToClient
    mov     rcx, qword ptr [rbp-40]                  ; RECT: l -72,t -68,r -64,b -60
    lea     rdx, [rbp-72]
    call    GetClientRect
    mov     eax, dword ptr [rbp-60]                  ; chipH = clientH / n  (matches the
    test    eax, eax                                 ; painter's chip layout exactly)
    jz      gtk_done
    cdq
    idiv    dword ptr [g_tilefile_n]
    test    eax, eax
    jz      gtk_done                                 ; more files than pixels -> bail
    mov     ecx, eax                                 ; ecx = chipH
    mov     eax, dword ptr [rbp-52]                  ; chip = pt.y / chipH
    cdq
    idiv    ecx
    cmp     eax, 0
    jl      gtk_done
    cmp     eax, dword ptr [g_tilefile_n]
    jae     gtk_done                                 ; in the unpainted bottom band -> ignore
    mov     dword ptr [rbp-76], eax                  ; chip index
    cmp     dword ptr [g_editmode], 0                ; x-hotspot only in edit mode
    je      gtk_open
    mov     eax, dword ptr [rbp-64]                  ; clientW - 2 - TAG_XW
    sub     eax, 2 + TAG_XW
    cmp     dword ptr [rbp-56], eax                  ; pt.x
    jl      gtk_open
    mov     ecx, dword ptr [rbp-76]                  ; remove this file
    call    tf_remove
    mov     dword ptr [g_dirty], 1
    cmp     dword ptr [g_tilefile_n], 0              ; last file gone -> drop the tile
    jne     gtk_relayout
    mov     rcx, qword ptr [rbp-24]                  ; gather+rebuild: gg_image skips the
    call    gui_gather                               ; now-empty tile, so it disappears
    mov     rcx, qword ptr [rbp-24]                  ; (gui_row_delete can't be used - the
    call    gui_rebuild_rows                         ;  skipped tile breaks its row->k map)
    jmp     gtk_done
gtk_relayout:
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    call    gui_tile_relayout
    jmp     gtk_done
gtk_open:
    cmp     dword ptr [g_nopreview], 0               ; preview disabled -> download only,
    jne     gtk_saveas                               ;   never decrypt to a temp file
    mov     ecx, dword ptr [rbp-76]                  ; executable/script type?
    call    tf_entry
    lea     rcx, [rax+TFILE_NAME]
    call    gui_ext_is_exec
    test    eax, eax
    jnz     gtk_saveas                               ; yes -> Save As, never run it
    mov     ecx, dword ptr [rbp-76]                  ; otherwise open in the default app
    call    gui_tag_open
    jmp     gtk_done
gtk_saveas:
    mov     rcx, qword ptr [rbp-24]                  ; hdlg
    mov     edx, dword ptr [rbp-76]                  ; index
    call    gui_tag_saveas
gtk_done:
    FRAME_EPILOG
    ret
gui_tag_click endp

; gui_tile_palette_add(rcx = hdlg) - the palette's Image/File tile: pick a file and
;   append it to the attachments tile, creating the tile row on the first file (so an
;   empty tile is never left behind if the user cancels the picker).
gui_tile_palette_add proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    lea     rax, [g_allfilter]
    mov     qword ptr [g_pickfilter], rax
    mov     rcx, qword ptr [rbp-24]
    xor     edx, edx
    call    img_pick
    test    eax, eax
    jz      gtpa_done
    lea     rcx, [g_imgpath]
    lea     rdx, [g_imgbuf]
    lea     r8, [g_imgbuflen]
    call    read_file
    test    eax, eax
    jnz     gtpa_done
    lea     rcx, [g_imgpath]
    call    gui_basename                         ; -> g_imgfn_w
    mov     rcx, qword ptr [g_imgbuf]
    mov     rdx, qword ptr [g_imgbuflen]
    lea     r8, [g_imgstageref]
    call    attach_stage
    test    eax, eax
    jnz     gtpa_free
    lea     rcx, [g_imgstageref]
    lea     rdx, [g_imgfn_w]
    call    tf_append
    mov     dword ptr [g_dirty], 1
gtpa_free:
    mov     rcx, qword ptr [g_imgbuf]
    mov     rdx, qword ptr [g_imgbuflen]
    call    mem_free
    mov     qword ptr [g_imgbuf], 0
    call    tf_find_row                          ; already have a tile?
    cmp     eax, -1
    jne     gtpa_relayout
    cmp     dword ptr [g_tilefile_n], 0          ; nothing added -> no tile
    je      gtpa_done
    mov     rcx, qword ptr [rbp-24]              ; first file: create the tile row
    mov     edx, VF_FILE
    xor     r8d, r8d                             ; no preset label (r8 clobbered above)
    call    gui_addfield_one                     ; enters edit mode + relayouts
    jmp     gtpa_done
gtpa_relayout:
    mov     dword ptr [rbp-32], eax
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    call    gui_tile_relayout
gtpa_done:
    FRAME_EPILOG
    ret
gui_tile_palette_add endp

; gui_tile_add_cur(rcx = hdlg) -> eax = 1 if the file at g_imgpath was read,
;   encrypted+staged, and appended to the attachments tile (0 if read failed,
;   staging failed, or the tile is already full).  Shared by Choose and drop.
gui_tile_add_cur proc frame
    FRAME_PROLOG 48
    lea     rcx, [g_imgpath]
    lea     rdx, [g_imgbuf]
    lea     r8, [g_imgbuflen]
    call    read_file
    test    eax, eax
    jnz     gtac_no
    lea     rcx, [g_imgpath]
    call    gui_basename                            ; -> g_imgfn_w
    mov     rcx, qword ptr [g_imgbuf]
    mov     rdx, qword ptr [g_imgbuflen]
    lea     r8, [g_imgstageref]
    call    attach_stage
    test    eax, eax
    jnz     gtac_free_no
    lea     rcx, [g_imgstageref]
    lea     rdx, [g_imgfn_w]
    call    tf_append                               ; 1 = tile full (MAX_TFILES)
    test    eax, eax
    jnz     gtac_free_no
    mov     dword ptr [g_dirty], 1
    mov     rcx, qword ptr [g_imgbuf]
    mov     rdx, qword ptr [g_imgbuflen]
    call    mem_free
    mov     qword ptr [g_imgbuf], 0
    mov     eax, 1
    FRAME_EPILOG
    ret
gtac_free_no:
    mov     rcx, qword ptr [g_imgbuf]
    mov     rdx, qword ptr [g_imgbuflen]
    call    mem_free
    mov     qword ptr [g_imgbuf], 0
gtac_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_tile_add_cur endp

; gui_drop_files(rcx = hdlg, rdx = HDROP) - attach every dropped file to the
;   attachments tile (edit mode), creating the tile row on the first file.  The
;   MAX_TFILES cap is enforced by tf_append inside gui_tile_add_cur.
gui_drop_files proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=hdlg [rbp-32]=hdrop [rbp-40]=count [rbp-44]=i
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    WINCALL DragQueryFileW, qword ptr [rbp-32], 0FFFFFFFFh, 0, 0
    mov     dword ptr [rbp-40], eax
    mov     dword ptr [rbp-44], 0
gdf_loop:
    mov     eax, dword ptr [rbp-44]
    cmp     eax, dword ptr [rbp-40]
    jae     gdf_finish
    WINCALL DragQueryFileW, qword ptr [rbp-32], dword ptr [rbp-44], \
            addr g_imgpath, MAX_PATH_CHARS
    mov     rcx, qword ptr [rbp-24]
    call    gui_tile_add_cur
    inc     dword ptr [rbp-44]
    jmp     gdf_loop
gdf_finish:
    WINCALL DragFinish, qword ptr [rbp-32]
    call    tf_find_row                             ; existing tile?
    cmp     eax, -1
    jne     gdf_relayout
    cmp     dword ptr [g_tilefile_n], 0
    je      gdf_ret
    mov     rcx, qword ptr [rbp-24]                 ; first file: create the tile row
    mov     edx, VF_FILE
    xor     r8d, r8d
    call    gui_addfield_one
    jmp     gdf_ret
gdf_relayout:
    mov     dword ptr [rbp-48], eax
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-48]
    call    gui_tile_relayout
gdf_ret:
    FRAME_EPILOG
    ret
gui_drop_files endp

; move_ctl(rcx=hdlg, rdx=hwnd, r8d=dlux, r9d=dluy, [+48]=dluw, [+56]=dluh)
;   Map the DLU rect to pixels and MoveWindow the control.  No-op if hwnd=0.
move_ctl proc frame
    FRAME_PROLOG 112
    test    rdx, rdx
    jz      mvc_ret
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    add     r8d, VDX_DLU                         ; shift the whole detail pane right (wider sidebar)
    mov     dword ptr [rbp-48], r8d              ; rc.left = x + dx
    mov     dword ptr [rbp-44], r9d              ; rc.top = y
    mov     eax, r8d
    add     eax, dword ptr [rbp+48]
    mov     dword ptr [rbp-40], eax              ; rc.right = x + dx + w
    mov     eax, r9d
    add     eax, dword ptr [rbp+56]
    mov     dword ptr [rbp-36], eax              ; rc.bottom = y+h
    WINCALL MapDialogRect, qword ptr [rbp-24], addr rbp-48
    mov     eax, dword ptr [rbp-48]
    mov     qword ptr [rbp-56], rax              ; px
    mov     eax, dword ptr [rbp-44]
    mov     qword ptr [rbp-64], rax              ; py
    mov     eax, dword ptr [rbp-40]
    sub     eax, dword ptr [rbp-48]
    mov     qword ptr [rbp-72], rax              ; pw
    mov     eax, dword ptr [rbp-36]
    sub     eax, dword ptr [rbp-44]
    mov     qword ptr [rbp-80], rax              ; ph
    WINCALL MoveWindow, qword ptr [rbp-32], qword ptr [rbp-56], qword ptr [rbp-64], \
            qword ptr [rbp-72], qword ptr [rbp-80], 1
mvc_ret:
    FRAME_EPILOG
    ret
move_ctl endp

; gui_vis_bottom(rcx=hdlg) -> eax = the visible field-area bottom in DLU (the
;   live client height minus a reserve for the docked command bar).  Grows with
;   the window, so the fields scroll within whatever height the user gives them.
gui_vis_bottom proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    WINCALL GetClientRect, qword ptr [rbp-24], addr rbp-48    ; {L-48 T-44 R-40 B-36}
    mov     dword ptr [rbp-80], 0                             ; probe {0,0,4,8} -> base units
    mov     dword ptr [rbp-76], 0
    mov     dword ptr [rbp-72], 4
    mov     dword ptr [rbp-68], 8
    WINCALL MapDialogRect, qword ptr [rbp-24], addr rbp-80    ; [-68] = px per 8 vertical DLU
    mov     eax, dword ptr [rbp-36]              ; client height (px, top = 0)
    imul    eax, 8
    cdq
    idiv    dword ptr [rbp-68]                   ; -> client height in DLU
    sub     eax, 30                              ; reserve the docked command bar
    FRAME_EPILOG
    ret
gui_vis_bottom endp

; pg_putnum(ecx = num 0..99, r8 = dst wide ptr) -> rax = advanced dst.  Leaf.
pg_putnum proc
    mov     eax, ecx
    cmp     eax, 10
    jb      ppn_one
    xor     edx, edx
    mov     r9d, 10
    div     r9d                                  ; eax = tens, edx = ones
    add     eax, '0'
    mov     word ptr [r8], ax
    add     r8, 2
    mov     eax, edx
ppn_one:
    add     eax, '0'
    mov     word ptr [r8], ax
    add     r8, 2
    mov     rax, r8
    ret
pg_putnum endp

; gui_page_bar(rcx = hdlg) - position the "< n / m >" pagination bar at the
;   bottom centre of the window and show it only when there is more than one page.
gui_page_bar proc frame
    FRAME_PROLOG 160
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-28], 0                ; SW_HIDE (single page)
    cmp     dword ptr [g_page_count], 1
    jle     gpb_apply
    mov     dword ptr [rbp-28], SW_SHOW
    ; --- indicator text "n / m" (1-based current, total) ---
    lea     r8, [g_pgbuf]
    mov     ecx, dword ptr [g_cur_page]
    inc     ecx
    call    pg_putnum
    mov     r8, rax
    mov     word ptr [r8], ' '
    mov     word ptr [r8+2], '/'
    mov     word ptr [r8+4], ' '
    add     r8, 6
    mov     ecx, dword ptr [g_page_count]
    call    pg_putnum
    mov     word ptr [rax], 0
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_PGIND, addr g_pgbuf
    ; (positioning is done in gui_cmd_dock_layout, docked to the command-bar row)
gpb_apply:
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_PGPREV
    WINCALL ShowWindow, rax, dword ptr [rbp-28]
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_PGIND
    WINCALL ShowWindow, rax, dword ptr [rbp-28]
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_V_PGNEXT
    WINCALL ShowWindow, rax, dword ptr [rbp-28]
    FRAME_EPILOG
    ret
gui_page_bar endp

; rowh(rcx=desc) -> rax = slot handle helper is inlined; small accessors below.
; gui_rows_layout(rcx=hdlg) - position every row's controls in the detail pane
;   and show/hide the per-row reorder buttons according to g_editmode.
gui_rows_layout proc frame
    FRAME_PROLOG 160
    mov     qword ptr [rbp-24], rcx              ; hdlg
    mov     dword ptr [rbp-36], 0                ; i
    mov     dword ptr [rbp-40], 52               ; y (ROW_TOP - below the detail header)
    mov     dword ptr [rbp-52], 0                ; show cmd (SW_HIDE)
    cmp     dword ptr [g_editmode], 0
    je      grl_havecmd
    mov     dword ptr [rbp-52], SW_SHOW
grl_havecmd:
    mov     eax, dword ptr [g_layout]            ; label band: >0 card(top), 0 flat(left)
    lea     r10, [lay_band]
    mov     eax, dword ptr [r10+rax*4]
    mov     dword ptr [rbp-68], eax
    mov     rcx, qword ptr [rbp-24]              ; pagination: rows are packed into pages
    call    gui_vis_bottom                       ;   sized to the live window height
    mov     dword ptr [rbp-92], eax              ; visible field-area bottom (DLU)
grl_pgrestart:
    mov     dword ptr [rbp-36], 0                ; i
    mov     dword ptr [rbp-84], 52               ; py = per-page virtual cursor (ROW_TOP)
    mov     dword ptr [rbp-88], 0                ; pg = current row's page index
grl_row:
    mov     eax, dword ptr [rbp-36]
    cmp     eax, dword ptr [g_field_count]
    jae     grl_done
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     qword ptr [rbp-32], r10              ; desc
    mov     eax, dword ptr [r10+FD_KIND]
    mov     dword ptr [rbp-44], 27               ; rowH (card = label band 14 + value)
    mov     dword ptr [rbp-48], 11               ; valH
    cmp     eax, VF_NOTES
    jne     grl_chkblock
    mov     dword ptr [rbp-44], 54
    mov     dword ptr [rbp-48], 40
    jmp     grl_setyh
grl_chkblock:
    cmp     eax, VF_SPACER                       ; layout block: a small blank gap
    jne     grl_chkgroup
    mov     dword ptr [rbp-44], 16
    jmp     grl_setyh
grl_chkgroup:
    cmp     eax, VF_GROUP                        ; layout block: a section heading
    jne     grl_chkimg
    mov     dword ptr [rbp-44], 22
    mov     dword ptr [rbp-48], 12
    jmp     grl_setyh
grl_chkimg:
    cmp     eax, VF_IMAGE                        ; attachments tile: height grows with
    je      grl_attach_h                         ; the number of files (tag list)
    cmp     eax, VF_FILE
    jne     grl_chktotp
grl_attach_h:
    mov     eax, dword ptr [g_tilefile_n]
    test    eax, eax
    jnz     @F
    mov     eax, 1                               ; keep a minimum height
@@: imul    eax, eax, 15                         ; per-tag chip height (DLU)
    add     eax, 20                              ; label band + padding (+ is in the band)
    mov     dword ptr [rbp-44], eax
    jmp     grl_setyh
grl_chktotp:
    cmp     eax, VF_TOTP
    jne     grl_setyh
    mov     dword ptr [rbp-44], 39               ; view mode: code + bar + room below the bar
    cmp     dword ptr [g_editmode], 0
    je      grl_setyh
    mov     dword ptr [rbp-44], 55               ; edit mode: key + code + bar + room below
grl_setyh:
    mov     eax, dword ptr [rbp-68]              ; adjust height for the layout band
    sub     eax, 14                              ; (base heights assume a 14-DLU band)
    add     dword ptr [rbp-44], eax
    ; --- pagination: does this row fit on the current page?  If not, open a new
    ;     one.  Rows on g_cur_page get their real y; all others go off-screen. ---
    mov     eax, dword ptr [rbp-84]              ; py
    cmp     eax, 52                              ; first row on a page always fits
    je      grl_pg_disp
    add     eax, dword ptr [rbp-44]              ; py + rowH
    cmp     eax, dword ptr [rbp-92]              ; > visible bottom?
    jle     grl_pg_disp
    inc     dword ptr [rbp-88]                   ; pg++ : this row opens a new page
    mov     dword ptr [rbp-84], 52               ; py = top of the new page
grl_pg_disp:
    mov     eax, dword ptr [rbp-88]              ; on the current page -> real y; else hide
    cmp     eax, dword ptr [g_cur_page]
    jne     grl_pg_hide
    mov     eax, dword ptr [rbp-84]
    jmp     grl_pg_sety
grl_pg_hide:
    mov     eax, 10000                           ; off-screen (far below the window)
grl_pg_sety:
    mov     dword ptr [rbp-40], eax              ; row_top = this row's display y
    mov     r10, qword ptr [rbp-32]
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r10+FD_Y], eax
    mov     eax, dword ptr [rbp-44]
    mov     dword ptr [r10+FD_H], eax
    ; TOTP code/bar vertical offset: under the key field while editing, at the row
    ; top in view mode (where the key field is hidden)
    mov     dword ptr [rbp-56], 0
    mov     r10, qword ptr [rbp-32]
    cmp     dword ptr [r10+FD_KIND], VF_TOTP
    jne     grl_offdone
    cmp     dword ptr [g_editmode], 0
    je      grl_offdone
    mov     dword ptr [rbp-56], 14
grl_offdone:
    mov     eax, dword ptr [rbp-40]              ; content_y = row top + label band
    add     eax, dword ptr [rbp-68]
    mov     dword ptr [rbp-60], eax
    ; label: card layouts put it on top (164, y+3); flat puts it left (158, y)
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_LABEL*8]
    cmp     dword ptr [rbp-68], 0
    je      grl_lbl_flat
    mov     r8d, 176                             ; content column (chevrons live to the left)
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 3
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 120, 10   ; narrow: clears the top-right cluster
    jmp     grl_lbl_done
grl_lbl_flat:
    mov     r8d, 158
    mov     r9d, dword ptr [rbp-40]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 44, 11
grl_lbl_done:
    ; value width: secret rows leave room for the badge+reveal+copy cluster (x>=340)
    mov     r10, qword ptr [rbp-32]
    mov     dword ptr [rbp-76], 196             ; card default
    cmp     dword ptr [rbp-68], 0
    jne     @F
    mov     dword ptr [rbp-76], 150             ; flat default
@@: cmp     dword ptr [r10+FD_KIND], VF_GROUP    ; section title: run the edit out to just
    jne     grl_chksecw                          ;   short of the trash (x=394) so it reads
    mov     dword ptr [rbp-76], 212              ;   as a heading field, not a stub box
    jmp     grl_valpos
grl_chksecw:
    cmp     dword ptr [r10+FD_KIND], VF_SECRET
    jne     grl_chktotpw
    mov     dword ptr [rbp-76], 118             ; card secret: stop before the badge (x=300)
    cmp     dword ptr [rbp-68], 0
    jne     grl_valpos
    mov     dword ptr [rbp-76], 130             ; flat secret
    jmp     grl_valpos
grl_chktotpw:
    cmp     dword ptr [r10+FD_KIND], VF_TOTP     ; totp key edit: stop before the reveal (x=344)
    jne     grl_valpos
    mov     dword ptr [rbp-76], 160
grl_valpos:
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_VALUE*8]
    cmp     dword ptr [rbp-68], 0
    je      grl_val_flat
    cmp     dword ptr [r10+FD_KIND], VF_GROUP    ; a heading's title IS its label, so put it
    jne     grl_val_card                         ;   in the LABEL band: the value band starts
    mov     r8d, 176                             ;   at row_top+14 and a heading row is only
    mov     r9d, dword ptr [rbp-40]              ;   22 tall, so the edit hung out past the
    add     r9d, 3                               ;   bottom of its card and sat lower than
    WINCALL move_ctl, rcx, rdx, r8d, r9d, dword ptr [rbp-76], 10   ; every other tile's label
    jmp     grl_val_done
grl_val_card:
    mov     r8d, 176                             ; content column (shifted for chevrons)
    mov     r9d, dword ptr [rbp-60]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, dword ptr [rbp-76], dword ptr [rbp-48]
    jmp     grl_val_done
grl_val_flat:
    mov     r8d, 206
    mov     r9d, dword ptr [rbp-60]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, dword ptr [rbp-76], dword ptr [rbp-48]
grl_val_done:
    ; a group heading shows its title as a painted section header in view mode;
    ; hide its edit there and reveal it only when editing
    mov     r10, qword ptr [rbp-32]
    cmp     dword ptr [r10+FD_KIND], VF_GROUP
    jne     grl_grphide_done
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_VALUE*8]
    xor     edx, edx                            ; SW_HIDE (view mode)
    cmp     dword ptr [g_editmode], 0
    je      @F
    mov     edx, 5                              ; SW_SHOW (edit mode)
@@: call    ShowWindow
grl_grphide_done:
    ; top-right cluster on the label row: Reveal | Copy | Generate | Trash
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_REVEAL*8]
    mov     r8d, 344
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 4
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 12, 12
    ; copy: secret -> right cluster (352,y); totp -> next to the live code (318,y+14)
    mov     r10, qword ptr [rbp-32]
    cmp     dword ptr [r10+FD_KIND], VF_TOTP
    je      grl_copytotp
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_COPY*8]
    mov     r8d, 360                             ; top-right cluster, right of the reveal
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 4
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 12, 12
    jmp     grl_copydone
grl_copytotp:
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_COPY*8]
    mov     r8d, 360                             ; top-right cluster (token copy)
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 4
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 12, 12
grl_copydone:
    ; totp code (206, y+off, 110, 11) + bar (206, y+off+11, 110, 2)
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_TCODE*8]
    mov     r8d, 176
    mov     r9d, dword ptr [rbp-60]
    add     r9d, dword ptr [rbp-56]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 84, 11
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_TBAR*8]
    mov     r8d, 176
    mov     r9d, dword ptr [rbp-60]
    add     r9d, dword ptr [rbp-56]
    add     r9d, 11
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 84, 3
    ; reorder chevrons: stacked in the left gutter (edit mode), flat glyphs;
    ; delete stays as a button in the card's top-right corner
    mov     eax, dword ptr [rbp-44]              ; card mid = top + H/2
    sar     eax, 1
    add     eax, dword ptr [rbp-40]
    mov     dword ptr [rbp-64], eax
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_UP*8]
    mov     r8d, 158                             ; inside the tile's left edge
    mov     r9d, dword ptr [rbp-64]
    sub     r9d, 9
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 11, 9
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_DOWN*8]
    mov     r8d, 158                             ; inside the tile's left edge
    mov     r9d, dword ptr [rbp-64]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 11, 9
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_DEL*8]
    mov     r8d, 394                             ; trash: far right of the cluster
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 4
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 12, 11
    ; show/hide the reorder cluster per edit mode
    mov     r10, qword ptr [rbp-32]
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_UP*8]
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
    mov     r10, qword ptr [rbp-32]
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_DOWN*8]
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
    mov     r10, qword ptr [rbp-32]
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_DEL*8]
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
    ; secret strength badge: top-right cluster (left of the trash) in view mode
    mov     r10, qword ptr [rbp-32]
    cmp     dword ptr [r10+FD_KIND], VF_SECRET
    jne     grl_sbadge_done
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_SBADGE*8]
    mov     r8d, 300                             ; view mode: left of the reveal/copy cluster
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 4
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 40, 11
    mov     eax, dword ptr [rbp-52]           ; edit=SW_SHOW, view=SW_HIDE
    xor     eax, SW_SHOW                      ; badge shows in view (opposite)
    mov     r10, qword ptr [rbp-32]
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_SBADGE*8]
    mov     edx, eax
    call    ShowWindow
    ; generate button: top-right cluster, just left of the trash (edit mode only)
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_GEN*8]
    mov     r8d, 378
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 4
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 12, 12
    mov     r10, qword ptr [rbp-32]
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_GEN*8]
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
grl_sbadge_done:
    ; TOTP key field + its reveal are edit-mode only (view shows just the live code)
    mov     r10, qword ptr [rbp-32]
    cmp     dword ptr [r10+FD_KIND], VF_TOTP
    jne     grl_totptog_done
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_VALUE*8]
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
    mov     r10, qword ptr [rbp-32]
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_REVEAL*8]
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
grl_totptog_done:
    ; attachments tile: Choose pinned top-right (edit mode only); an owner-draw
    ; tag-list control fills the body beneath it, sized to the file count.
    mov     r10, qword ptr [rbp-32]
    mov     eax, dword ptr [r10+FD_KIND]
    cmp     eax, VF_IMAGE
    je      grl_attach
    cmp     eax, VF_FILE
    je      grl_attach
    jmp     grl_advance
grl_attach:
    mov     r10, qword ptr [rbp-32]                  ; the tile has no editable label
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_LABEL*8]  ; (files ARE the content) - hide
    xor     edx, edx                                 ; it so a stray label can't be typed
    call    ShowWindow                               ; and then silently dropped on save
    mov     rcx, qword ptr [rbp-24]                  ; "+" add button, card top-right
    mov     r10, qword ptr [rbp-32]                  ; corner (where the trash sits on
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_IMPORT*8]  ; other rows)
    mov     r8d, 394
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 4
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 12, 12
    mov     eax, dword ptr [g_tilefile_n]            ; tag-list height = n * chip
    test    eax, eax
    jnz     @F
    mov     eax, 1
@@: imul    eax, eax, 15
    mov     dword ptr [rbp-56], eax
    mov     rcx, qword ptr [rbp-24]                  ; tag list: right of the chevrons (176)
    mov     r10, qword ptr [rbp-32]                  ; and up in the top band (no label here)
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_VALUE*8]
    mov     r8d, 176
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 4
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 134, dword ptr [rbp-56]
    mov     r10, qword ptr [rbp-32]                  ; "+" shows in edit mode only
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_IMPORT*8]
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
grl_advance:
    ; advance the per-page virtual cursor by card height + inter-card gap
    mov     eax, dword ptr [rbp-84]
    add     eax, dword ptr [rbp-44]
    mov     r10d, dword ptr [g_layout]
    lea     r11, [layout_gaps]
    add     eax, dword ptr [r11+r10*4]
    mov     dword ptr [rbp-84], eax
    inc     dword ptr [rbp-36]
    jmp     grl_row
grl_done:
    ; total pages = the last row's page index + 1
    mov     eax, dword ptr [rbp-88]
    inc     eax
    mov     dword ptr [g_page_count], eax
    ; if the current page fell past the end (window shrank / rows removed), clamp
    ; it and re-run the layout once with the corrected page
    mov     eax, dword ptr [g_cur_page]
    cmp     eax, dword ptr [g_page_count]
    jl      grl_pgok
    mov     eax, dword ptr [g_page_count]
    dec     eax
    mov     dword ptr [g_cur_page], eax
    jmp     grl_pgrestart
grl_pgok:
    ; (created/modified now live in the history browser, not under the last row)
    mov     rcx, qword ptr [rbp-24]              ; position + show/hide the pagination bar
    call    gui_page_bar
    mov     rcx, qword ptr [rbp-24]              ; keep value columns elastic after relayout
    call    gui_stretch_rows
    ; repaint just the detail pane (not the whole window) so the sidebar card's
    ; border/shadow don't flicker when rows are laid out
    mov     rcx, qword ptr [rbp-24]
    call    gui_inval_detail
    FRAME_EPILOG
    ret
gui_rows_layout endp

; dynid(ecx=row, edx=slot) -> eax = control id.  Leaf.
dynid proc
    mov     eax, ecx
    imul    eax, eax, DYN_SLOTS
    add     eax, edx
    add     eax, IDC_DYN_BASE
    ret
dynid endp

; gui_url_open(rcx=hdlg, edx=row) - read the URL from the row's value field and
;   open it in the default browser, prepending https:// when the value carries no
;   "://" scheme.  Invoked when a URL field is clicked in view mode.
gui_url_open proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     ecx, edx
    mov     edx, DS_VALUE
    call    dynid
    mov     dword ptr [rbp-40], eax             ; value control id
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], dword ptr [rbp-40], addr g_urlbuf, 1024
    test    eax, eax
    jz      guo_done                            ; empty field
    lea     r10, [g_urlbuf]                     ; scheme present ("://")?
    xor     ecx, ecx
guo_scan:
    movzx   eax, word ptr [r10+rcx*2]
    test    eax, eax
    jz      guo_bare
    cmp     eax, ':'
    jne     guo_next
    movzx   eax, word ptr [r10+rcx*2+2]
    cmp     eax, '/'
    jne     guo_next
    movzx   eax, word ptr [r10+rcx*2+4]
    cmp     eax, '/'
    je      guo_hasscheme
guo_next:
    inc     ecx
    cmp     ecx, 1022
    jb      guo_scan
guo_bare:
    lea     rcx, [g_urlbuf2]                    ; target = "https://" + url
    lea     rdx, [url_https]
    call    gui_wstrcpy
    mov     rcx, rax
    lea     rdx, [g_urlbuf]
    call    gui_wstrcpy
    lea     rax, [g_urlbuf2]
    mov     qword ptr [rbp-48], rax
    jmp     guo_exec
guo_hasscheme:
    ; allowlist: only open http:// and https://.  A stored or imported URL field
    ; could carry file://, a UNC path, javascript:, etc., which ShellExecute would
    ; launch as click-to-execute in the user's context.  ecx = scheme length.
    cmp     ecx, 4
    jb      guo_done
    cmp     ecx, 5
    ja      guo_done
    lea     r10, [g_urlbuf]
    lea     r11, [url_https]                    ; L"https://": [0..ecx) is "http"/"https"
    xor     r9d, r9d
guo_ci_lp:
    movzx   eax, word ptr [r10+r9*2]
    or      eax, 20h                            ; ASCII tolower
    movzx   edx, word ptr [r11+r9*2]
    cmp     eax, edx
    jne     guo_done                            ; scheme not http/https -> do not open
    inc     r9d
    cmp     r9d, ecx
    jb      guo_ci_lp
    lea     rax, [g_urlbuf]
    mov     qword ptr [rbp-48], rax
guo_exec:
    WINCALL ShellExecuteW, 0, addr verb_open, qword ptr [rbp-48], 0, 0, 1
guo_done:
    lea     rcx, [g_urlbuf]                     ; URLs may carry internal hosts / tokens
    mov     edx, 1024*2
    call    secure_zero
    lea     rcx, [g_urlbuf2]
    mov     edx, 1040*2
    call    secure_zero
    FRAME_EPILOG
    ret
gui_url_open endp

; url_editproc(rcx=hwnd, rdx=msg, r8=wParam, r9=lParam) -> rax - subclass proc for
;   a URL field's value edit: in view mode it shows a hand cursor over the client
;   area; everything else defers to the original EDIT window procedure.
url_editproc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx              ; hwnd
    mov     qword ptr [rbp-16], rdx             ; msg
    mov     qword ptr [rbp-24], r8              ; wParam
    mov     qword ptr [rbp-32], r9              ; lParam
    cmp     rdx, WM_SETCURSOR
    jne     uep_pass
    cmp     dword ptr [g_editmode], 0
    jne     uep_pass                            ; edit mode -> normal I-beam
    movzx   eax, word ptr [rbp-32]              ; LOWORD(lParam) = hit-test
    cmp     eax, HTCLIENT
    jne     uep_pass
    WINCALL LoadCursorW, 0, IDC_HAND
    WINCALL SetCursor, rax
    mov     eax, 1                              ; TRUE -> halt default cursor handling
    jmp     uep_ret
uep_pass:
    WINCALL CallWindowProcW, qword ptr [g_url_origproc], qword ptr [rbp-8], \
            qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
uep_ret:
    mov     rsp, rbp
    pop     rbp
    ret
url_editproc endp

; gui_subclass_urls(rcx=hdlg) - subclass every VF_URL row's value edit with
;   url_editproc (freshly-built controls, so idempotent per row rebuild).
gui_subclass_urls proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], 0               ; row
gsu_l:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_field_count]
    jae     gsu_done
    mov     ecx, eax
    call    gui_desc
    cmp     dword ptr [rax+FD_KIND], VF_URL
    jne     gsu_next
    mov     ecx, dword ptr [rbp-24]
    mov     edx, DS_VALUE
    call    gui_row_handle                      ; -> rax = value control hwnd
    test    rax, rax
    jz      gsu_next
    WINCALL SetWindowLongPtrW, rax, GWLP_WNDPROC, addr url_editproc
    mov     qword ptr [g_url_origproc], rax     ; original EDIT proc (same for all)
gsu_next:
    inc     dword ptr [rbp-24]
    jmp     gsu_l
gsu_done:
    FRAME_EPILOG
    ret
gui_subclass_urls endp

; gui_ctlcolor(rcx=hdlg, rdx=msg, r8=hdc, r9=hctl) -> rax=brush - theme_ctlcolor,
;   then paint a view-mode URL value edit's text in link blue.
gui_ctlcolor proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], r8              ; hdc
    mov     qword ptr [rbp-32], r9              ; hctl
    call    theme_ctlcolor                      ; rdx/r8/r9 still valid -> rax = brush
    mov     qword ptr [rbp-40], rax             ; brush
    cmp     dword ptr [g_editmode], 0
    jne     gcc_ret                             ; only recolour in view mode
    WINCALL GetDlgCtrlID, qword ptr [rbp-32]
    cmp     eax, IDC_DYN_BASE
    jb      gcc_ret
    mov     ecx, eax
    sub     ecx, IDC_DYN_BASE
    mov     r10d, ecx
    and     r10d, DYN_SLOTS-1
    cmp     r10d, DS_VALUE
    jne     gcc_ret
    shr     ecx, DYN_SLOTS_LOG2                 ; row
    call    gui_desc
    cmp     dword ptr [rax+FD_KIND], VF_URL
    jne     gcc_ret
    WINCALL SetTextColor, qword ptr [rbp-24], LINK_BLUE
gcc_ret:
    mov     rax, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
gui_ctlcolor endp

; gui_row_handle(ecx=row, edx=slot) -> rax = hwnd (0 if none).  Leaf.
gui_row_handle proc
    mov     eax, ecx
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     eax, edx
    mov     rax, qword ptr [r10 + FD_HANDLES + rax*8]
    ret
gui_row_handle endp

; gui_wstr_eq(rcx=a, rdx=b) -> eax = 1 if the wide NUL-terminated strings match.  Leaf.
public gui_wstr_eq                       ; selftest KATs the constant-time behavior
gui_wstr_eq proc
    ; Constant-time in the CONTENT: differences are OR-accumulated and never
    ; branched on, so timing can't reveal the first differing character.  The
    ; loop still ends at either string's NUL (running to a fixed bound would
    ; read past short allocations), so only min(len_a,len_b) is timing-visible.
    ; Some callers compare secrets (password confirm, pw-history set-diff).
    ; Clobbers rax, r8, r9, r10 only.
    xor     r8d, r8d                    ; index
    xor     r10d, r10d                  ; accumulated difference
wse_l:
    movzx   eax, word ptr [rcx+r8*2]
    movzx   r9d, word ptr [rdx+r8*2]
    xor     r9d, eax                    ; r9d = a xor b
    or      r10d, r9d                   ; covers a length mismatch too: the
    test    eax, eax                    ;   shorter side's NUL xor the longer
    jz      wse_done                    ;   side's char is nonzero
    cmp     r9d, eax                    ; diff == a  <=>  b == 0 -> stop
    je      wse_done                    ;   (a NUL test, not a content test)
    inc     r8d
    cmp     r8d, 4096
    jb      wse_l
wse_done:
    neg     r10d                        ; CF=1 iff any difference accumulated
    sbb     eax, eax                    ; eax = -1 if different, 0 if equal
    inc     eax                         ; eax = 1 if equal, 0 if different
    ret
gui_wstr_eq endp

; gui_row_reveal(rcx=hdlg, edx=row) - toggle the row's value between masked/clear.
gui_row_reveal proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     eax, edx
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     eax, dword ptr [r10+FD_FLAGS]
    test    eax, FDF_REVEALED
    jnz     grr_hide
    or      eax, FDF_REVEALED
    mov     dword ptr [r10+FD_FLAGS], eax
    mov     dword ptr [rbp-40], 0                ; unmask
    jmp     grr_apply
grr_hide:
    and     eax, NOT FDF_REVEALED
    mov     dword ptr [r10+FD_FLAGS], eax
    mov     dword ptr [rbp-40], SECRET_MASK
grr_apply:
    mov     ecx, dword ptr [rbp-32]
    mov     edx, DS_VALUE
    call    dynid
    mov     dword ptr [rbp-48], eax              ; id
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], dword ptr [rbp-48], \
            EM_SETPASSWORDCHAR, dword ptr [rbp-40], 0
    mov     ecx, dword ptr [rbp-32]
    mov     edx, DS_VALUE
    call    gui_row_handle
    WINCALL InvalidateRect, rax, 0, 1
    ; view mode: overlay the class-coloured plaintext when revealed, hide when masked
    cmp     dword ptr [g_editmode], 0
    jne     grr_ret
    cmp     dword ptr [rbp-40], 0             ; 0 = now revealed
    jne     grr_maskhide
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    call    gui_colorpw_show
    jmp     grr_ret
grr_maskhide:
    mov     rcx, qword ptr [rbp-24]
    call    gui_colorpw_hide
grr_ret:
    FRAME_EPILOG
    ret
gui_row_reveal endp

; gui_row_copy(rcx=hdlg, edx=row) - copy the row to the clipboard (TOTP -> live
;   6-digit code; otherwise the value), with the usual auto-clear timer.
gui_row_copy proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     eax, edx
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    cmp     dword ptr [r10+FD_KIND], VF_TOTP
    jne     grc_value
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_totp_code_w]
    call    gui_copy
    jmp     grc_done
grc_value:
    mov     ecx, dword ptr [rbp-32]
    mov     edx, DS_VALUE
    call    dynid
    mov     dword ptr [rbp-40], eax
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], dword ptr [rbp-40], addr g_secret_w, EBUF*2-1
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_secret_w]
    call    gui_copy
grc_done:
    FRAME_EPILOG
    ret
gui_row_copy endp

; gui_arm_totp(rcx=hdlg) - find the (single) TOTP row, latch its code/bar handles
;   and base32 key, and (re)start the live-code timer.  Safe with no TOTP row.
gui_arm_totp proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [g_totp_on], 0
    mov     dword ptr [g_totp_row], -1
    mov     qword ptr [g_totp_codehwnd], 0
    mov     qword ptr [g_totp_barhwnd], 0
    mov     rcx, qword ptr [rbp-24]
    mov     edx, TOTP_TIMER
    call    KillTimer
    mov     dword ptr [rbp-32], 0
gat_loop:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [g_field_count]
    jae     gat_done
    mov     eax, dword ptr [rbp-32]
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    cmp     dword ptr [r10+FD_KIND], VF_TOTP
    jne     gat_next
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [g_totp_row], eax
    mov     ecx, dword ptr [rbp-32]
    mov     edx, DS_TCODE
    call    gui_row_handle
    mov     qword ptr [g_totp_codehwnd], rax
    mov     ecx, dword ptr [rbp-32]
    mov     edx, DS_TBAR
    call    gui_row_handle
    mov     qword ptr [g_totp_barhwnd], rax
    mov     ecx, dword ptr [rbp-32]
    mov     edx, DS_VALUE
    call    dynid
    mov     dword ptr [rbp-36], eax
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], dword ptr [rbp-36], addr g_e_totp, 256
    lea     r10, [g_e_totp]                     ; ascii base32 (wide) -> bytes
    lea     r11, [g_totp_b32]
    xor     r8d, r8d
gat_cp:
    movzx   eax, word ptr [r10+r8*2]
    test    eax, eax
    jz      gat_cpd
    cmp     r8d, 255
    jae     gat_cpd
    mov     byte ptr [r11+r8], al
    inc     r8d
    jmp     gat_cp
gat_cpd:
    mov     dword ptr [g_totp_b32len], r8d
    test    r8d, r8d
    jz      gat_done
    mov     dword ptr [g_totp_on], 1
    jmp     gat_done
gat_next:
    inc     dword ptr [rbp-32]
    jmp     gat_loop
gat_done:
    cmp     dword ptr [g_totp_on], 0
    je      gat_ret
    mov     rcx, qword ptr [rbp-24]
    call    gui_totp_refresh
    WINCALL SetTimer, qword ptr [rbp-24], TOTP_TIMER, TOTP_MS, 0
gat_ret:
    FRAME_EPILOG
    ret
gui_arm_totp endp

; gui_rebuild_rows(rcx=hdlg) - tear down and recreate every row from the wide
;   g_field_list[1..g_field_n) (built by gui_gather).  Used after reorder/delete.
gui_rebuild_rows proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     rcx, qword ptr [rbp-24]
    call    gui_rows_clear
    mov     dword ptr [rbp-32], 1               ; k = 1 (skip title)
grb_loop:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [g_field_n]
    jae     grb_done
    mov     eax, dword ptr [rbp-32]
    imul    eax, eax, 24
    lea     r10, [g_field_list]
    add     r10, rax
    mov     qword ptr [rbp-40], r10             ; &list[k]
    mov     r9d, dword ptr [r10]                ; raw type (may carry VFL_RAW)
    mov     dword ptr [rbp-64], r9d
    mov     eax, r9d
    and     eax, NOT VFL_RAW                    ; clean base kind
    cmp     eax, VF_FAV                         ; reserved favorite marker: not a row
    je      grb_next
    cmp     eax, VF_ICON                        ; reserved icon override: not a row
    je      grb_next
    mov     rcx, qword ptr [rbp-24]
    mov     edx, eax
    call    gui_row_add
    cmp     eax, 0
    jl      grb_done
    mov     dword ptr [rbp-44], eax             ; row
    mov     r10, qword ptr [rbp-40]
    mov     rax, qword ptr [r10+8]              ; label ptr (0=none)
    test    rax, rax
    jz      grb_setval
    mov     qword ptr [rbp-56], rax
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_LABEL
    call    dynid
    mov     dword ptr [rbp-48], eax
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], dword ptr [rbp-48], qword ptr [rbp-56]
    mov     eax, dword ptr [rbp-44]
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    or      dword ptr [r10+FD_FLAGS], FDF_LABELED
grb_setval:
    ; (the attachments tile rebuilds as a bare VF_FILE placeholder; its tags repaint
    ;  from g_tilefiles, so there is no per-value restore here)
    mov     r10, qword ptr [rbp-40]
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [rbp-56], rax
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_VALUE
    call    dynid
    mov     dword ptr [rbp-48], eax
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], dword ptr [rbp-48], qword ptr [rbp-56]
    mov     r10, qword ptr [rbp-40]
    mov     eax, dword ptr [r10]
    cmp     eax, VF_SECRET
    je      grb_mask
    cmp     eax, VF_TOTP
    je      grb_mask
    jmp     grb_next
grb_mask:
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_VALUE
    call    dynid
    mov     dword ptr [rbp-48], eax
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], dword ptr [rbp-48], \
            EM_SETPASSWORDCHAR, SECRET_MASK, 0
    jmp     grb_next
grb_next:
    inc     dword ptr [rbp-32]
    jmp     grb_loop
grb_done:
    mov     rcx, qword ptr [rbp-24]
    call    gui_rows_layout
    mov     rcx, qword ptr [rbp-24]
    call    gui_arm_totp
    FRAME_EPILOG
    ret
gui_rebuild_rows endp

; swap24(rcx=ptr a, rdx=ptr b) - swap two 24-byte field-list descriptors.  Leaf.
swap24 proc
    mov     rax, qword ptr [rcx]
    mov     r8,  qword ptr [rdx]
    mov     qword ptr [rcx], r8
    mov     qword ptr [rdx], rax
    mov     rax, qword ptr [rcx+8]
    mov     r8,  qword ptr [rdx+8]
    mov     qword ptr [rcx+8], r8
    mov     qword ptr [rdx+8], rax
    mov     rax, qword ptr [rcx+16]
    mov     r8,  qword ptr [rdx+16]
    mov     qword ptr [rcx+16], r8
    mov     qword ptr [rdx+16], rax
    ret
swap24 endp

; gui_row_moveup(rcx=hdlg, edx=row) - move dynamic row up one (no-op for row 0).
gui_row_moveup proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    cmp     edx, 0
    jle     grmu_done
    mov     rcx, qword ptr [rbp-24]
    call    gui_gather
    mov     eax, dword ptr [rbp-32]             ; list[row] <-> list[row+1]
    imul    eax, eax, 24
    lea     rcx, [g_field_list]
    add     rcx, rax
    lea     rdx, [rcx+24]
    call    swap24
    mov     rcx, qword ptr [rbp-24]
    call    gui_rebuild_rows
    mov     dword ptr [g_dirty], 1
grmu_done:
    FRAME_EPILOG
    ret
gui_row_moveup endp

; gui_row_movedown(rcx=hdlg, edx=row) - move dynamic row down one.
gui_row_movedown proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     eax, dword ptr [g_field_count]
    dec     eax
    cmp     edx, eax
    jge     grmd_done
    mov     rcx, qword ptr [rbp-24]
    call    gui_gather
    mov     eax, dword ptr [rbp-32]             ; list[row+1] <-> list[row+2]
    inc     eax
    imul    eax, eax, 24
    lea     rcx, [g_field_list]
    add     rcx, rax
    lea     rdx, [rcx+24]
    call    swap24
    mov     rcx, qword ptr [rbp-24]
    call    gui_rebuild_rows
    mov     dword ptr [g_dirty], 1
grmd_done:
    FRAME_EPILOG
    ret
gui_row_movedown endp

; gui_row_delete(rcx=hdlg, edx=row) - remove a dynamic row.
gui_row_delete proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     rcx, qword ptr [rbp-24]
    call    gui_gather
    ; shift list[k+1] -> list[k] for k = row+1 .. g_field_n-2
    mov     eax, dword ptr [rbp-32]
    inc     eax                                 ; k = row+1
    mov     dword ptr [rbp-40], eax
grd_shift:
    mov     eax, dword ptr [g_field_n]
    dec     eax
    cmp     dword ptr [rbp-40], eax
    jge     grd_shifted
    mov     eax, dword ptr [rbp-40]
    imul    eax, eax, 24
    lea     r10, [g_field_list]
    lea     r11, [r10+rax]                      ; &list[k]
    add     r11, 0
    lea     r10, [r11+24]                       ; &list[k+1]
    mov     rax, qword ptr [r10]
    mov     qword ptr [r11], rax
    mov     rax, qword ptr [r10+8]
    mov     qword ptr [r11+8], rax
    mov     rax, qword ptr [r10+16]
    mov     qword ptr [r11+16], rax
    inc     dword ptr [rbp-40]
    jmp     grd_shift
grd_shifted:
    dec     dword ptr [g_field_n]
    mov     rcx, qword ptr [rbp-24]
    call    gui_rebuild_rows
    mov     dword ptr [g_dirty], 1
    FRAME_EPILOG
    ret
gui_row_delete endp

; gui_addfield_one(rcx=hdlg, edx=kind, r8=label wide or 0) - append a field row.
gui_addfield_one proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], r8
    ; refuse a 2nd TOTP (the palette greys it; guard regardless)
    cmp     dword ptr [rbp-32], VF_TOTP
    jne     gao_chkroom
    call    gui_has_totp
    test    eax, eax
    jnz     gao_done
gao_chkroom:
    ; adding always succeeds now - rows past the visible area flow onto further
    ; pages (see gui_rows_layout).  The only hard cap is MAXROWS.
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    call    gui_row_add
    cmp     eax, 0
    jl      gao_full
    mov     dword ptr [rbp-44], eax             ; row
    ; optional preset label
    cmp     qword ptr [rbp-40], 0
    je      gao_mask
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_LABEL
    call    dynid
    mov     dword ptr [rbp-48], eax
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], dword ptr [rbp-48], qword ptr [rbp-40]
gao_mask:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, VF_SECRET
    je      gao_dom
    cmp     eax, VF_TOTP
    je      gao_dom
    jmp     gao_show
gao_dom:
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_VALUE
    call    dynid
    mov     dword ptr [rbp-48], eax
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], dword ptr [rbp-48], \
            EM_SETPASSWORDCHAR, SECRET_MASK, 0
gao_show:
    mov     rcx, qword ptr [rbp-24]             ; (re)enter edit mode + relayout
    mov     edx, 1
    call    gui_set_editmode                   ; relayout -> g_page_count is current
    mov     dword ptr [g_dirty], 1
    ; jump to the last page so the just-appended row is on-screen
    mov     eax, dword ptr [g_page_count]
    dec     eax
    mov     dword ptr [g_cur_page], eax
    mov     rcx, qword ptr [rbp-24]
    call    gui_rows_layout
    ; focus the new field for immediate typing (custom w/o label -> label, else value)
    mov     edx, DS_VALUE
    cmp     dword ptr [rbp-32], VF_TEXT
    jne     gao_focus
    cmp     qword ptr [rbp-40], 0
    jne     gao_focus
    mov     edx, DS_LABEL
gao_focus:
    mov     ecx, dword ptr [rbp-44]
    call    dynid
    mov     rcx, qword ptr [rbp-24]
    mov     edx, eax
    call    GetDlgItem
    mov     rcx, rax
    call    SetFocus
    jmp     gao_done
gao_full:
    ; MAXROWS reached - the only remaining hard cap
    WINCALL gui_msgbox, qword ptr [rbp-24], addr s_nofieldroom, addr t_err, \
            <MB_OK or MB_ICONINFORMATION>
gao_done:
    FRAME_EPILOG
    ret
gui_addfield_one endp

; gui_has_totp() -> eax = 1 if any currently-composed row is a TOTP field.  Leaf.
gui_has_totp proc
    xor     r8d, r8d
ght_loop:
    cmp     r8d, dword ptr [g_field_count]
    jae     ght_no
    mov     eax, r8d
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    cmp     dword ptr [r10+FD_KIND], VF_TOTP
    je      ght_yes
    inc     r8d
    jmp     ght_loop
ght_no:
    xor     eax, eax
    ret
ght_yes:
    mov     eax, 1
    ret
gui_has_totp endp

; gui_palette_add(rcx=hdlg, edx=menu id) - map a palette choice to a new field.
gui_palette_add proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    xor     r8, r8                              ; label = none
    mov     ecx, edx
    cmp     ecx, 1
    jne     @F
    mov     edx, VF_USERNAME
    jmp     gpa_go
@@: cmp     ecx, 2
    jne     @F
    mov     edx, VF_SECRET
    jmp     gpa_go
@@: cmp     ecx, 3
    jne     @F
    mov     edx, VF_URL
    jmp     gpa_go
@@: cmp     ecx, 4
    jne     @F
    mov     edx, VF_TEXT
    lea     r8, [kl_email]
    jmp     gpa_go
@@: cmp     ecx, 5
    jne     @F
    mov     edx, VF_NOTES
    jmp     gpa_go
@@: cmp     ecx, 6
    jne     @F
    mov     edx, VF_TOTP
    jmp     gpa_go
@@: cmp     ecx, 8                              ; Image and File both add to the one
    je      gpa_attach                          ; attachments tile (pick files -> tags)
    cmp     ecx, 9
    je      gpa_attach
    cmp     ecx, 10                             ; group heading (layout block)
    jne     @F
    mov     edx, VF_GROUP
    jmp     gpa_go
@@: cmp     ecx, 11                             ; spacer (layout block)
    jne     @F
    mov     edx, VF_SPACER
    jmp     gpa_go
@@: mov     edx, VF_TEXT                        ; 7 = custom (empty label)
gpa_go:
    mov     rcx, qword ptr [rbp-24]
    call    gui_addfield_one
    FRAME_EPILOG
    ret
gpa_attach:
    mov     rcx, qword ptr [rbp-24]
    call    gui_tile_palette_add
    FRAME_EPILOG
    ret
gui_palette_add endp

; gui_row_of_kind(edx=kind) -> eax = first row index with that FD_KIND, or -1.  Leaf.
gui_row_of_kind proc
    xor     r8d, r8d
grk_lp:
    cmp     r8d, dword ptr [g_field_count]
    jae     grk_none
    mov     eax, r8d
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    cmp     dword ptr [r10+FD_KIND], edx
    je      grk_found
    inc     r8d
    jmp     grk_lp
grk_found:
    mov     eax, r8d
    ret
grk_none:
    mov     eax, -1
    ret
gui_row_of_kind endp

; =============================================================================
; Themed owner-draw popup menus.  Items are appended with MF_OWNERDRAW (their
; text pointer carried as the item data); gui_menu_dark tints the menu window
; background, and vault_proc / tray_wndproc route WM_MEASUREITEM + WM_DRAWITEM
; for ODT_MENU (CtlType 1) here.
; =============================================================================

; gui_menu_dark(rcx=hmenu) -> rax = HBRUSH (delete after TrackPopupMenu returns).
gui_menu_dark proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    WINCALL CreateSolidBrush, dword ptr [g_col_panel]
    mov     qword ptr [rbp-32], rax
    lea     r10, [g_menuinfo]
    mov     dword ptr [r10+0], 40                ; cbSize
    mov     dword ptr [r10+4], MIM_DARK          ; fMask
    mov     dword ptr [r10+8], 0                 ; dwStyle
    mov     dword ptr [r10+12], 0                ; cyMax
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [r10+16], rax              ; hbrBack
    mov     qword ptr [r10+24], 0
    mov     qword ptr [r10+32], 0
    WINCALL SetMenuInfo, qword ptr [rbp-24], addr g_menuinfo
    mov     rax, qword ptr [rbp-32]
    FRAME_EPILOG
    ret
gui_menu_dark endp

; gui_menu_measure(rcx=lpmis) - size an owner-draw menu item to its label.
gui_menu_measure proc frame
    FRAME_PROLOG 32
    mov     r10, rcx
    mov     rax, qword ptr [r10+24]              ; itemData = label ptr
    xor     r8d, r8d
gmm_len:
    cmp     word ptr [rax+r8*2], 0
    je      gmm_done
    inc     r8d
    jmp     gmm_len
gmm_done:
    imul    r8d, r8d, 7                          ; ~7 px/char + padding
    add     r8d, 44
    mov     dword ptr [r10+12], r8d              ; itemWidth
    mov     dword ptr [r10+16], 22               ; itemHeight
    mov     eax, 1
    FRAME_EPILOG
    ret
gui_menu_measure endp

; gui_menu_draw(rcx=lpdis) - paint an owner-draw menu item in the theme colours.
gui_menu_draw proc frame
    FRAME_PROLOG 160
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax              ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-80], eax              ; rc L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-76], eax
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-72], eax
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-68], eax
    mov     ecx, dword ptr [g_col_panel]         ; selected row -> frame highlight
    mov     r11, qword ptr [rbp-24]
    test    dword ptr [r11+16], 1                ; ODS_SELECTED
    jz      @F
    mov     ecx, dword ptr [g_col_frame]
@@: WINCALL CreateSolidBrush, ecx
    mov     qword ptr [rbp-40], rax
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-80, qword ptr [rbp-40]
    WINCALL DeleteObject, qword ptr [rbp-40]
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    mov     ecx, dword ptr [g_col_text]          ; grayed/disabled item -> dim text
    mov     r11, qword ptr [rbp-24]
    test    dword ptr [r11+16], 6                ; ODS_GRAYED | ODS_DISABLED
    jz      @F
    mov     ecx, dword ptr [g_col_textdim]
@@: WINCALL SetTextColor, qword ptr [rbp-32], ecx
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_dlgfont]
    mov     qword ptr [rbp-48], rax              ; old font
    mov     r11, qword ptr [rbp-24]
    mov     rax, qword ptr [r11+56]              ; itemData = label ptr
    mov     qword ptr [rbp-56], rax
    mov     eax, dword ptr [rbp-80]
    add     eax, 12
    mov     dword ptr [rbp-120], eax             ; text rect [L+12 .. R]
    mov     eax, dword ptr [rbp-76]
    mov     dword ptr [rbp-116], eax
    mov     eax, dword ptr [rbp-72]
    mov     dword ptr [rbp-112], eax
    mov     eax, dword ptr [rbp-68]
    mov     dword ptr [rbp-108], eax
    WINCALL DrawTextW, qword ptr [rbp-32], qword ptr [rbp-56], -1, addr rbp-120, 24h
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-48]
    mov     eax, 1
    FRAME_EPILOG
    ret
gui_menu_draw endp

; gui_overflow_menu(rcx=hdlg) - the header "..." menu: copy password/username,
;   delete entry.  Copies reuse gui_row_copy; delete posts IDC_V_REMOVE.
gui_overflow_menu proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    WINCALL CreatePopupMenu
    mov     qword ptr [rbp-32], rax
    test    rax, rax
    jz      gom_done
    cmp     dword ptr [g_trash_view], 0          ; trash view: only "Return to vault"
    je      gom_vault
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 8, addr om_leavetrash
    jmp     gom_track
gom_vault:
    cmp     dword ptr [g_cur_idx], 0             ; entry-scoped items only with a shown entry
    jl      gom_recover
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 1, addr om_copypw
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 2, addr om_copyuser
    cmp     dword ptr [g_no_phonetic], 0         ; "Disable phonetic reader" -> hide it
    jne     @F
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 4, addr om_read
@@: cmp     dword ptr [g_no_history], 0          ; "Do not save history" -> hide the browser
    jne     @F
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 5, addr om_history
@@: WINCALL AppendMenuW, qword ptr [rbp-32], MF_SEPARATOR, 0, 0
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 3, addr om_delete
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_SEPARATOR, 0, 0
gom_recover:
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 7, addr om_recover
gom_track:
    mov     rcx, qword ptr [rbp-32]              ; tint the menu background
    call    gui_menu_dark
    mov     qword ptr [rbp-64], rax              ; bg brush (delete after tracking)
    lea     rcx, [rbp-56]                        ; POINT
    call    GetCursorPos
    WINCALL SetForegroundWindow, qword ptr [rbp-24]
    WINCALL TrackPopupMenu, qword ptr [rbp-32], TPM_RETURNCMD or TPM_LEFTALIGN, \
            dword ptr [rbp-56], dword ptr [rbp-52], 0, qword ptr [rbp-24], 0
    mov     dword ptr [rbp-44], eax              ; chosen id
    WINCALL DestroyMenu, qword ptr [rbp-32]
    WINCALL DeleteObject, qword ptr [rbp-64]
    cmp     dword ptr [rbp-44], 7               ; "Recover items" -> enter trash view
    jne     gom_notrecover
    call    gui_first_deleted
    cmp     eax, 0
    jge     gom_dorecover
    WINCALL gui_msgbox, qword ptr [rbp-24], addr t_notrash, addr t_recover_ttl, \
            MB_OK or MB_ICONINFORMATION
    jmp     gom_done
gom_dorecover:
    mov     rcx, qword ptr [rbp-24]
    call    gui_enter_trash
    jmp     gom_done
gom_notrecover:
    cmp     dword ptr [rbp-44], 8               ; "Return to vault" -> leave trash view
    jne     gom_not8
    mov     rcx, qword ptr [rbp-24]
    call    gui_leave_trash
    jmp     gom_done
gom_not8:
    cmp     dword ptr [rbp-44], 3
    jne     gom_notdel
    WINCALL PostMessageW, qword ptr [rbp-24], WM_COMMAND, IDC_V_REMOVE, 0
    jmp     gom_done
gom_notdel:
    cmp     dword ptr [rbp-44], 4
    jne     gom_notread
    mov     rcx, qword ptr [rbp-24]
    call    gui_read_password
    jmp     gom_done
gom_notread:
    cmp     dword ptr [rbp-44], 5
    jne     gom_nothist
    mov     rcx, qword ptr [rbp-24]
    call    gui_open_pwhist
    jmp     gom_done
gom_nothist:
    cmp     dword ptr [rbp-44], 1
    je      gom_cppw
    cmp     dword ptr [rbp-44], 2
    je      gom_cpuser
    jmp     gom_done
gom_cppw:
    mov     edx, VF_SECRET
    jmp     gom_docopy
gom_cpuser:
    mov     edx, VF_USERNAME
gom_docopy:
    call    gui_row_of_kind                     ; eax = row or -1
    cmp     eax, 0
    jl      gom_done
    mov     edx, eax
    mov     rcx, qword ptr [rbp-24]
    call    gui_row_copy
gom_done:
    FRAME_EPILOG
    ret
gui_overflow_menu endp

; gui_pw_class(ecx = char) -> eax = 0 upper / 1 lower / 2 digit / 3 symbol.  Leaf.
gui_pw_class proc
    cmp     cl, 'A'
    jb      gpc_l
    cmp     cl, 'Z'
    ja      gpc_l
    xor     eax, eax
    ret
gpc_l:
    cmp     cl, 'a'
    jb      gpc_d
    cmp     cl, 'z'
    ja      gpc_d
    mov     eax, 1
    ret
gpc_d:
    cmp     cl, '0'
    jb      gpc_s
    cmp     cl, '9'
    ja      gpc_s
    mov     eax, 2
    ret
gpc_s:
    mov     eax, 3
    ret
gui_pw_class endp

; gui_class_color(ecx = class 0..3) -> eax = a colour that contrasts with the
;   active scheme background (lowercase = primary text; others = light/dark accent).
gui_class_color proc
    cmp     ecx, 1
    jne     gcc_accent
    mov     eax, dword ptr [g_col_text]
    ret
gcc_accent:
    lea     r10, [cls_accent_dark]
    cmp     dword ptr [g_col_dark], 0
    jne     @F
    lea     r10, [cls_accent_light]
@@: mov     eax, dword ptr [r10+rcx*4]
    ret
gui_class_color endp

; gui_wapp_lc(rcx = dst, rdx = src wideZ, r8d = lowercase flag) -> rax = dst end.
;   Appends src to dst (no NUL); lowercases A-Z when r8d != 0.  Leaf.
gui_wapp_lc proc
wal_lp:
    movzx   eax, word ptr [rdx]
    test    eax, eax
    jz      wal_done
    test    r8d, r8d
    jz      wal_put
    cmp     ax, 'A'
    jb      wal_put
    cmp     ax, 'Z'
    ja      wal_put
    add     ax, 20h
wal_put:
    mov     word ptr [rcx], ax
    add     rcx, 2
    add     rdx, 2
    jmp     wal_lp
wal_done:
    mov     rax, rcx
    ret
gui_wapp_lc endp

; gui_phon_word(ecx = char, rdx = dst wide) - write the char's phonetic word
;   (NUL-terminated; "CAP-" prefix for uppercase; digit + symbol names) to dst.
gui_phon_word proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], ecx           ; char
    mov     qword ptr [rbp-32], rdx           ; dst
    cmp     ecx, 'A'
    jb      pw_notU
    cmp     ecx, 'Z'
    ja      pw_notU
    mov     rcx, qword ptr [rbp-32]           ; uppercase -> "CAP-" + Word
    lea     rdx, [pr_cap]
    xor     r8d, r8d
    call    gui_wapp_lc
    mov     qword ptr [rbp-32], rax
    mov     ecx, dword ptr [rbp-24]
    sub     ecx, 'A'
    lea     r10, [nato_ptrs]
    mov     rdx, qword ptr [r10+rcx*8]
    xor     r8d, r8d
    jmp     pw_app
pw_notU:
    cmp     ecx, 'a'
    jb      pw_notL
    cmp     ecx, 'z'
    ja      pw_notL
    sub     ecx, 'a'
    lea     r10, [nato_ptrs]
    mov     rdx, qword ptr [r10+rcx*8]
    mov     r8d, 1
    jmp     pw_app
pw_notL:
    cmp     ecx, '0'
    jb      pw_sym
    cmp     ecx, '9'
    ja      pw_sym
    sub     ecx, '0'
    lea     r10, [digit_ptrs]
    mov     rdx, qword ptr [r10+rcx*8]
    xor     r8d, r8d
    jmp     pw_app
pw_sym:
    lea     r10, [sym_chars]
    xor     r9d, r9d
pw_symf:
    cmp     r9d, SYM_COUNT
    jae     pw_symdef
    movzx   eax, byte ptr [r10+r9]
    cmp     eax, dword ptr [rbp-24]
    je      pw_symhit
    inc     r9d
    jmp     pw_symf
pw_symhit:
    lea     r11, [sym_ptrs]
    mov     rdx, qword ptr [r11+r9*8]
    xor     r8d, r8d
    jmp     pw_app
pw_symdef:
    lea     rdx, [pr_symdef]
    xor     r8d, r8d
pw_app:
    mov     qword ptr [rbp-40], rdx
    mov     dword ptr [rbp-44], r8d
    mov     rcx, qword ptr [rbp-32]
    mov     rdx, qword ptr [rbp-40]
    mov     r8d, dword ptr [rbp-44]
    call    gui_wapp_lc
    mov     word ptr [rax], 0                 ; NUL-terminate
    FRAME_EPILOG
    ret
gui_phon_word endp

; gui_draw_phonlist(rcx = lpdis) - owner-draw the phonetic list, one line per char
;   of g_readpw: the char in its class colour, the spoken word in the text colour.
gui_draw_phonlist proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax           ; hdc
    WINCALL CreateSolidBrush, dword ptr [g_col_bg]
    mov     qword ptr [rbp-40], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [rbp-40]
    WINCALL DeleteObject, qword ptr [rbp-40]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_phonfont]
    mov     qword ptr [rbp-48], rax           ; old font
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    WINCALL GetTextExtentPoint32W, qword ptr [rbp-32], addr pr_zero, 1, addr rbp-88
    mov     eax, dword ptr [rbp-84]           ; line height = cy + 3
    add     eax, 3
    mov     dword ptr [rbp-52], eax
    mov     eax, dword ptr [rbp-88]           ; word x = 4 + 4 cells
    imul    eax, eax, 4
    add     eax, 4
    mov     dword ptr [rbp-56], eax
    mov     dword ptr [rbp-60], 0             ; i
    mov     dword ptr [rbp-64], 2             ; y
dpl_loop:
    mov     eax, dword ptr [rbp-60]
    lea     r10, [g_readpw]
    movzx   ecx, word ptr [r10+rax*2]
    test    ecx, ecx
    jz      dpl_end
    mov     dword ptr [rbp-100], ecx          ; char
    call    gui_pw_class
    mov     ecx, eax
    call    gui_class_color
    WINCALL SetTextColor, qword ptr [rbp-32], eax
    WINCALL TextOutW, qword ptr [rbp-32], 4, dword ptr [rbp-64], addr rbp-100, 1
    mov     ecx, dword ptr [rbp-100]          ; resolve + draw the word (text colour)
    lea     rdx, [g_wordtmp]
    call    gui_phon_word
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_text]
    lea     r10, [g_wordtmp]                  ; word length
    xor     r9d, r9d
dpl_wl:
    cmp     word ptr [r10+r9*2], 0
    je      dpl_wld
    inc     r9d
    cmp     r9d, 30
    jb      dpl_wl
dpl_wld:
    mov     dword ptr [rbp-72], r9d
    WINCALL TextOutW, qword ptr [rbp-32], dword ptr [rbp-56], dword ptr [rbp-64], \
            addr g_wordtmp, dword ptr [rbp-72]
    mov     eax, dword ptr [rbp-52]
    add     dword ptr [rbp-64], eax
    inc     dword ptr [rbp-60]
    cmp     dword ptr [rbp-60], 200
    jb      dpl_loop
dpl_end:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-48]
    FRAME_EPILOG
    ret
gui_draw_phonlist endp

; gui_draw_colorpw(rcx = lpdis) - draw g_readpw in monospace, each char coloured
;   by its character class, wrapping within the control rect.
gui_draw_colorpw proc frame
    FRAME_PROLOG 160
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax           ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-40], eax           ; L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-44], eax           ; T
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-48], eax           ; R
    ; background
    WINCALL CreateSolidBrush, dword ptr [g_col_bg]
    mov     qword ptr [rbp-56], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [rbp-56]
    WINCALL DeleteObject, qword ptr [rbp-56]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_monofont]
    mov     qword ptr [rbp-64], rax           ; old font
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    ; measure the (monospace) cell size from "0"
    WINCALL GetTextExtentPoint32W, qword ptr [rbp-32], addr pr_zero, 1, addr rbp-88
    mov     eax, dword ptr [rbp-88]           ; cell width (cx)
    mov     dword ptr [rbp-72], eax
    mov     eax, dword ptr [rbp-84]           ; cell height (cy)
    add     eax, 2
    mov     dword ptr [rbp-76], eax           ; line height
    mov     eax, dword ptr [rbp-40]
    add     eax, 4
    mov     dword ptr [rbp-92], eax           ; x
    mov     eax, dword ptr [rbp-44]
    add     eax, 2
    mov     dword ptr [rbp-96], eax           ; y
    mov     dword ptr [rbp-100], 0            ; i
gcp_loop:
    mov     eax, dword ptr [rbp-100]
    lea     r10, [g_readpw]
    movzx   ecx, word ptr [r10+rax*2]
    test    ecx, ecx
    jz      gcp_done
    mov     dword ptr [rbp-104], ecx          ; char
    call    gui_pw_class
    mov     ecx, eax
    call    gui_class_color
    WINCALL SetTextColor, qword ptr [rbp-32], eax
    ; wrap if past the right edge
    mov     eax, dword ptr [rbp-92]
    add     eax, dword ptr [rbp-72]
    mov     r10d, dword ptr [rbp-48]
    sub     r10d, 4
    cmp     eax, r10d
    jle     gcp_draw
    mov     eax, dword ptr [rbp-40]
    add     eax, 4
    mov     dword ptr [rbp-92], eax
    mov     eax, dword ptr [rbp-96]
    add     eax, dword ptr [rbp-76]
    mov     dword ptr [rbp-96], eax
gcp_draw:
    lea     rax, [rbp-104]
    WINCALL TextOutW, qword ptr [rbp-32], dword ptr [rbp-92], dword ptr [rbp-96], \
            addr rbp-104, 1
    mov     eax, dword ptr [rbp-72]
    add     dword ptr [rbp-92], eax
    inc     dword ptr [rbp-100]
    cmp     dword ptr [rbp-100], 256
    jb      gcp_loop
gcp_done:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-64]
    FRAME_EPILOG
    ret
gui_draw_colorpw endp

; gui_draw_pwlegend(rcx = lpdis) - draw a small colour key (ABC abc 123 !@#).
gui_draw_pwlegend proc frame
    FRAME_PROLOG 128                          ; TextOutW's 5th arg must clear [rbp-80]
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax           ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-40], eax           ; L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-44], eax           ; T
    WINCALL CreateSolidBrush, dword ptr [g_col_bg]
    mov     qword ptr [rbp-56], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [rbp-56]
    WINCALL DeleteObject, qword ptr [rbp-56]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_subfont]
    mov     qword ptr [rbp-64], rax
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [rbp-72], eax           ; x
    mov     ecx, 0                            ; token index
lg_loop:
    cmp     ecx, 4
    jae     lg_done
    ; NB: keep the loop index at [rbp-68] - it must not share bytes with the
    ; qword token pointer at [rbp-80], whose high half would clobber it.
    mov     dword ptr [rbp-68], ecx           ; token index
    call    gui_class_color                   ; ecx = class
    WINCALL SetTextColor, qword ptr [rbp-32], eax
    mov     ecx, dword ptr [rbp-68]
    lea     r10, [lg_ptrs]
    mov     r8, qword ptr [r10+rcx*8]         ; token text ptr
    mov     qword ptr [rbp-80], r8
    WINCALL TextOutW, qword ptr [rbp-32], dword ptr [rbp-72], dword ptr [rbp-44], \
            qword ptr [rbp-80], 3
    add     dword ptr [rbp-72], 74
    mov     ecx, dword ptr [rbp-68]
    inc     ecx
    jmp     lg_loop
lg_done:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-64]
    FRAME_EPILOG
    ret
gui_draw_pwlegend endp

; gui_draw_rowcolor(rcx = lpdis) - the IDC_V_COLORPW overlay: draw g_colorpw_row's
;   revealed secret in the dialog font with each glyph coloured by character class.
gui_draw_rowcolor proc frame
    FRAME_PROLOG 160
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax           ; hdc
    WINCALL CreateSolidBrush, dword ptr [g_col_panel]
    mov     qword ptr [rbp-40], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [rbp-40]
    WINCALL DeleteObject, qword ptr [rbp-40]
    cmp     dword ptr [g_colorpw_row], 0
    jl      drc_done
    mov     ecx, dword ptr [g_colorpw_row]    ; fetch the plaintext
    mov     edx, DS_VALUE
    call    dynid
    WINCALL GetDlgItemTextW, qword ptr [g_vaulthwnd], eax, addr g_rowpw_w, 256
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_dlgfont]
    mov     qword ptr [rbp-48], rax           ; old font
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    WINCALL GetTextExtentPoint32W, qword ptr [rbp-32], addr pr_zero, 1, addr rbp-88
    mov     r10, qword ptr [rbp-24]           ; y = vertically centered in the rect
    mov     eax, dword ptr [r10+52]
    sub     eax, dword ptr [r10+44]
    sub     eax, dword ptr [rbp-84]
    sar     eax, 1
    mov     dword ptr [rbp-60], eax           ; y
    mov     dword ptr [rbp-56], 1             ; x (edit left inset)
    mov     dword ptr [rbp-64], 0             ; i
drc_loop:
    mov     eax, dword ptr [rbp-64]
    lea     r10, [g_rowpw_w]
    movzx   ecx, word ptr [r10+rax*2]
    test    ecx, ecx
    jz      drc_end
    mov     dword ptr [rbp-100], ecx
    call    gui_pw_class
    mov     ecx, eax
    call    gui_class_color
    WINCALL SetTextColor, qword ptr [rbp-32], eax
    WINCALL GetTextExtentPoint32W, qword ptr [rbp-32], addr rbp-100, 1, addr rbp-88
    WINCALL TextOutW, qword ptr [rbp-32], dword ptr [rbp-56], dword ptr [rbp-60], \
            addr rbp-100, 1
    mov     eax, dword ptr [rbp-88]
    add     dword ptr [rbp-56], eax
    inc     dword ptr [rbp-64]
    cmp     dword ptr [rbp-64], 256
    jb      drc_loop
drc_end:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-48]
drc_done:
    FRAME_EPILOG
    ret
gui_draw_rowcolor endp

; gui_colorpw_hide(rcx=hdlg) - hide the colour overlay + restore the value edit.
gui_colorpw_hide proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_colorpw_row], 0
    jl      cph_ovl
    mov     ecx, dword ptr [g_colorpw_row]    ; re-show the value edit we hid
    mov     edx, DS_VALUE
    call    gui_row_handle
    mov     rcx, rax
    mov     edx, SW_SHOW
    call    ShowWindow
cph_ovl:
    mov     dword ptr [g_colorpw_row], -1
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_COLORPW
    call    GetDlgItem
    mov     rcx, rax
    xor     edx, edx
    call    ShowWindow
    ; wipe the revealed-secret copy so cleartext never lingers past the overlay
    ; (matches the wipe discipline used for every other secret buffer)
    lea     rcx, [g_rowpw_w]
    mov     edx, 512*2
    call    secure_zero
    FRAME_EPILOG
    ret
gui_colorpw_hide endp

; gui_colorpw_show(rcx=hdlg, edx=row) - position the colour overlay over the row's
;   value edit, raise it, and paint (used when a secret is revealed in view mode).
gui_colorpw_show proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [g_colorpw_row], edx     ; row (the only copy we need)
    mov     ecx, edx
    mov     edx, DS_VALUE
    call    gui_row_handle                    ; -> rax = value edit hwnd
    test    rax, rax
    jz      cps_done
    mov     qword ptr [rbp-32], rax
    mov     rcx, rax                           ; screen rect of the edit
    lea     rdx, [rbp-56]
    call    GetWindowRect
    mov     rcx, qword ptr [rbp-24]            ; -> client coords of the dialog
    lea     rdx, [rbp-56]
    call    ScreenToClient
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [rbp-48]
    call    ScreenToClient
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_COLORPW
    call    GetDlgItem
    mov     qword ptr [rbp-64], rax           ; overlay hwnd
    mov     eax, dword ptr [rbp-48]
    sub     eax, dword ptr [rbp-56]
    mov     dword ptr [rbp-68], eax           ; width
    mov     eax, dword ptr [rbp-44]
    sub     eax, dword ptr [rbp-52]
    mov     dword ptr [rbp-72], eax           ; height
    WINCALL MoveWindow, qword ptr [rbp-64], dword ptr [rbp-56], dword ptr [rbp-52], \
            dword ptr [rbp-68], dword ptr [rbp-72], 1
    WINCALL SetWindowPos, qword ptr [rbp-64], 0, 0, 0, 0, 0, 43h  ; TOP|NOMOVE|NOSIZE|SHOW
    WINCALL InvalidateRect, qword ptr [rbp-64], 0, 1
    mov     rcx, qword ptr [rbp-32]            ; hide the plain edit; overlay replaces it
    xor     edx, edx
    call    ShowWindow
cps_done:
    FRAME_EPILOG
    ret
gui_colorpw_show endp

; pwread_proc - DLG_PWREAD dialog procedure (colored password + phonetic).
pwread_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      pr_init
    cmp     rdx, WM_COMMAND
    je      pr_cmd
    cmp     rdx, WM_PAINT
    je      pr_paint
    cmp     rdx, WM_ERASEBKGND
    je      pr_erase
    cmp     rdx, WM_DRAWITEM
    je      pr_draw
    cmp     rdx, WM_CTLCOLOREDIT
    je      pr_color
    cmp     rdx, WM_CTLCOLORBTN
    je      pr_color
    cmp     rdx, WM_CTLCOLORDLG
    je      pr_color
    cmp     rdx, WM_CTLCOLORSTATIC
    je      pr_color
    xor     eax, eax
    jmp     pr_ret
pr_color:
    call    theme_ctlcolor
    jmp     pr_ret
pr_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDOK
    call    theme_attach
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    WINCALL SetForegroundWindow, qword ptr [rbp-8]
    mov     eax, 1
    jmp     pr_ret
pr_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     pr_ret
pr_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     pr_ret
pr_draw:
    mov     r10, r9
    mov     eax, dword ptr [r10+4]
    cmp     eax, IDC_PR_COLOR
    je      pr_drawpw
    cmp     eax, IDC_PR_LEGEND
    je      pr_drawlg
    cmp     eax, IDC_PR_PHON
    je      pr_drawphon
    mov     rcx, r9
    call    theme_drawitem
    jmp     pr_ret
pr_drawphon:
    mov     rcx, r9
    call    gui_draw_phonlist
    mov     eax, 1
    jmp     pr_ret
pr_drawpw:
    mov     rcx, r9
    call    gui_draw_colorpw
    mov     eax, 1
    jmp     pr_ret
pr_drawlg:
    mov     rcx, r9
    call    gui_draw_pwlegend
    mov     eax, 1
    jmp     pr_ret
pr_cmd:
    movzx   eax, r8w
    cmp     eax, IDOK
    je      pr_close
    cmp     eax, IDCANCEL
    je      pr_close
    xor     eax, eax
    jmp     pr_ret
pr_close:
    WINCALL EndDialog, qword ptr [rbp-8], 0
    mov     eax, 1
pr_ret:
    mov     rsp, rbp
    pop     rbp
    ret
pwread_proc endp

; gui_read_password(rcx = hdlg) - read the entry's first secret aloud: copy its
;   plaintext into g_readpw, show DLG_PWREAD, then wipe the scratch buffers.
gui_read_password proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     edx, VF_SECRET
    call    gui_row_of_kind
    cmp     eax, 0
    jl      grp_done
    mov     ecx, eax                          ; row -> DS_VALUE id
    mov     edx, DS_VALUE
    call    dynid
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], eax, addr g_readpw, 256
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_PWREAD, qword ptr [rbp-24], \
            addr pwread_proc, 0
    lea     r10, [g_readpw]                   ; wipe plaintext + phonetic scratch
    xor     ecx, ecx
grp_wipe:
    cmp     ecx, 260
    jae     grp_wiped
    mov     word ptr [r10+rcx*2], 0
    inc     ecx
    jmp     grp_wipe
grp_wiped:
    lea     r10, [g_phon_w]
    xor     ecx, ecx
grp_wipe2:
    cmp     ecx, 6144
    jae     grp_done
    mov     word ptr [r10+rcx*2], 0
    inc     ecx
    jmp     grp_wipe2
grp_done:
    FRAME_EPILOG
    ret
gui_read_password endp

; gui_apply_scheme(rcx=hdlg) - apply g_scheme: rebuild theme brushes, update the
;   settings button caption, and repaint the whole window + children.
gui_apply_scheme proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     ecx, dword ptr [g_scheme]
    call    theme_set_scheme
    mov     eax, dword ptr [g_scheme]
    lea     r10, [scheme_names]
    mov     rax, qword ptr [r10+rax*8]
    mov     qword ptr [rbp-32], rax
    ; the button lives in the settings CHILD, not in rcx's dialog: addressing the vault
    ; here silently found nothing and left the rc template's placeholder caption showing,
    ; so every scheme read "Dark" while the colours themselves cycled correctly.
    WINCALL SetDlgItemTextW, qword ptr [g_settings_hwnd], IDC_V_MTHEME, qword ptr [rbp-32]
    mov     rcx, qword ptr [rbp-24]              ; title bar + backdrop material follow the scheme
    call    theme_dwm_apply
    mov     rcx, qword ptr [rbp-24]              ; re-theme scrollbars to match dark/light
    call    theme_scrollbars
    WINCALL RedrawWindow, qword ptr [rbp-24], 0, 0, 185h
    FRAME_EPILOG
    ret
gui_apply_scheme endp

; gui_apply_layout(rcx=hdlg) - apply g_layout: relayout the current entry, update
;   the settings button caption, repaint.
gui_apply_layout proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [g_layout], 0             ; Comfortable is the only layout
    mov     rcx, qword ptr [rbp-24]              ; re-populate so items re-measure at
    call    gui_poplist                          ;   the new per-layout height
    cmp     dword ptr [g_cur_idx], 0
    jl      @F
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [g_cur_idx]
    call    gui_lb_selbydata
@@: cmp     dword ptr [g_cur_idx], 0             ; rows are covered by the settings child
                                                 ;   now, not hidden - laying them out
                                                 ;   while it is up is simply unseen
    jl      gal_paint
    mov     rcx, qword ptr [rbp-24]
    call    gui_rows_layout
gal_paint:
    WINCALL RedrawWindow, qword ptr [rbp-24], 0, 0, 185h
    FRAME_EPILOG
    ret
gui_apply_layout endp

; gui_save_prefs() - persist the UI scheme + layout to HKCU\Software\Vordr.
gui_save_prefs proc frame
    FRAME_PROLOG 48
    WINCALL cfg_set_dword_hkcu, addr pref_scheme, dword ptr [g_scheme]
    WINCALL cfg_set_dword_hkcu, addr pref_layout, dword ptr [g_layout]
    FRAME_EPILOG
    ret
gui_save_prefs endp

; gui_load_prefs() - load the persisted UI scheme + layout (clamped to range).
gui_load_prefs proc frame
    FRAME_PROLOG 48
    WINCALL cfg_get_dword, addr pref_scheme, GUI_SCHEME_GRUVBOX, addr g_scheme_lock
    cmp     eax, GUI_SCHEME_COUNT               ; clamp out-of-range to the default
    jb      @F
    mov     eax, GUI_SCHEME_GRUVBOX
@@: mov     dword ptr [g_scheme], eax
    mov     dword ptr [g_layout], 0             ; Comfortable is the only layout
    ; C5: audit-log verbosity (HKLM > HKCU > 0/off), so GUI security events are
    ; logged when the operator enables it (0..4; see log.asm LOG_* levels)
    WINCALL cfg_get_dword, addr pref_loglevel, 0, addr g_loglvl_lock
    cmp     eax, 4                              ; clamp to LOG_DEBUG
    jbe     @F
    xor     eax, eax
@@: mov     dword ptr [g_cfg_loglevel], eax
    ; C4: optional "require Hello/PIN on TPM unlock" (HKLM > HKCU > 0/off)
    WINCALL cfg_get_dword, addr pref_reqhello, 0, addr g_reqhello_lock
    test    eax, eax
    jz      @F
    mov     eax, 1
@@: mov     dword ptr [g_tpm_reqhello], eax
    FRAME_EPILOG
    ret
gui_load_prefs endp

; gui_u2pad(rcx=dst wide, edx=val 0..99) -> rax = dst end.  2 digits, zero-padded.
;   Leaf; clobbers eax/edx/r9.
gui_u2pad proc
    mov     eax, edx
    xor     edx, edx
    mov     r9d, 10
    div     r9d                                 ; eax=tens, edx=ones
    add     eax, '0'
    mov     word ptr [rcx], ax
    add     edx, '0'
    mov     word ptr [rcx+2], dx
    lea     rax, [rcx+4]
    ret
gui_u2pad endp

; gui_fmt_datetime(rcx=dst wide, rdx=FILETIME ptr) -> rax = dst end.
;   Writes "YYYY-MM-DD HH:MM" (no NUL).
gui_fmt_datetime proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx             ; dst
    mov     qword ptr [rbp-32], rdx             ; FILETIME ptr (stage: avoids WINCALL rdx dep)
    WINCALL FileTimeToSystemTime, qword ptr [rbp-32], addr g_st
    mov     rcx, qword ptr [rbp-24]
    movzx   edx, word ptr [g_st+0]              ; year
    call    gui_uint_w
    mov     word ptr [rax], '-'
    lea     rcx, [rax+2]
    movzx   edx, word ptr [g_st+2]              ; month
    call    gui_u2pad
    mov     word ptr [rax], '-'
    lea     rcx, [rax+2]
    movzx   edx, word ptr [g_st+6]              ; day
    call    gui_u2pad
    mov     word ptr [rax], ' '
    lea     rcx, [rax+2]
    movzx   edx, word ptr [g_st+8]              ; hour
    call    gui_u2pad
    mov     word ptr [rax], ':'
    lea     rcx, [rax+2]
    movzx   edx, word ptr [g_st+10]             ; minute
    call    gui_u2pad
    FRAME_EPILOG
    ret
gui_fmt_datetime endp

; gui_build_times() - render the open entry's "Created <dt>  Modified <dt>" into
;   g_times_w (NUL-terminated; empty when no entry).  Drawn as the history
;   browser's header - the detail pane no longer carries a timestamps line.
gui_build_times proc frame
    FRAME_PROLOG 64
    mov     word ptr [g_times_w], 0
    cmp     dword ptr [g_cur_idx], 0
    jl      gts_done
    mov     ecx, dword ptr [g_cur_idx]
    call    vault_entry_ptr
    test    rax, rax
    jz      gts_done
    mov     qword ptr [rbp-32], rax             ; entry ptr
    lea     rcx, [g_times_w]
    lea     rdx, [t_created]
    call    gui_w_appendz
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-32]
    add     rdx, 16                             ; created FILETIME
    call    gui_fmt_datetime
    mov     rcx, rax
    lea     rdx, [t_modified]
    call    gui_w_appendz
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-32]
    add     rdx, 24                             ; modified FILETIME
    call    gui_fmt_datetime
    mov     word ptr [rax], 0                   ; NUL-terminate
gts_done:
    FRAME_EPILOG
    ret
gui_build_times endp

; gui_entry_is_fav(ecx=idx) -> eax = 1 if the entry carries a VF_FAV field.
gui_entry_is_fav proc frame
    FRAME_PROLOG 48
    mov     edx, VF_FAV
    lea     r8, [rbp-24]
    call    vault_field_at                      ; rax = ptr or 0
    xor     ecx, ecx
    test    rax, rax
    setnz   cl
    mov     eax, ecx
    FRAME_EPILOG
    ret
gui_entry_is_fav endp

; gui_entry_is_deleted(ecx=idx) -> eax = 1 if the entry carries a VF_DELETED marker
;   (soft-deleted / in the trash).  Leaf-ish wrapper over vault_field_at.
gui_entry_is_deleted proc frame
    FRAME_PROLOG 48
    mov     edx, VF_DELETED
    lea     r8, [rbp-24]
    call    vault_field_at                      ; rax = ptr or 0
    xor     ecx, ecx
    test    rax, rax
    setnz   cl
    mov     eax, ecx
    FRAME_EPILOG
    ret
gui_entry_is_deleted endp

; gui_ft_hex16(rcx = value qword, rdx = dst wide) - format the 64-bit value as 16
;   uppercase hex wide chars (high nibble first) + a NUL.  Leaf.
gui_ft_hex16 proc
    mov     r9, rcx                             ; value (ecx will be clobbered by shift)
    xor     r8d, r8d                            ; i
fh_lp:
    mov     r10d, 15
    sub     r10d, r8d                           ; nibble index high->low
    lea     ecx, [r10*4]                        ; shift amount
    mov     rax, r9
    shr     rax, cl
    and     eax, 0Fh
    cmp     al, 10
    jb      fh_dec
    add     al, 'A'-10
    jmp     fh_emit
fh_dec:
    add     al, '0'
fh_emit:
    movzx   eax, al
    mov     word ptr [rdx+r8*2], ax
    inc     r8d
    cmp     r8d, 16
    jb      fh_lp
    mov     word ptr [rdx+r8*2], 0              ; NUL
    ret
gui_ft_hex16 endp

; gui_hex16_to_ft(rcx = utf8/ascii hex ptr, >= 16 chars) -> rax = parsed 64-bit value.
;   Stops at 16 chars; non-hex bytes contribute 0.  Leaf.
gui_hex16_to_ft proc
    xor     rax, rax
    xor     r8d, r8d
hf_lp:
    movzx   r9d, byte ptr [rcx+r8]
    shl     rax, 4
    cmp     r9b, '0'
    jb      hf_skip
    cmp     r9b, '9'
    ja      hf_alpha
    sub     r9d, '0'
    or      rax, r9
    jmp     hf_skip
hf_alpha:
    or      r9d, 20h                            ; fold to lower
    cmp     r9b, 'a'
    jb      hf_skip
    cmp     r9b, 'f'
    ja      hf_skip
    sub     r9d, 'a'-10
    or      rax, r9
hf_skip:
    inc     r8d
    cmp     r8d, 16
    jb      hf_lp
    ret
gui_hex16_to_ft endp

; gui_set_deleted_now() - stamp g_deleted_ft with the current time (16 wide hex).
gui_set_deleted_now proc frame
    FRAME_PROLOG 48
    lea     rcx, [rbp-40]                       ; FILETIME (8 bytes)
    call    GetSystemTimeAsFileTime
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [g_deleted_ft]
    call    gui_ft_hex16
    FRAME_EPILOG
    ret
gui_set_deleted_now endp

; gui_purge_trash() -> eax = count of entries permanently removed.  Walks the vault
;   high->low, hard-removing any VF_DELETED entry whose timestamp is older than 30
;   days.  Reseals if anything was purged.  Called once at unlock.
gui_purge_trash proc frame
    FRAME_PROLOG 64
    cmp     dword ptr [g_readonly], 0           ; E9: no auto-purge on a read-only open
    je      pt_go
    xor     eax, eax
    FRAME_EPILOG
    ret
pt_go:
    ; [rbp-24] now-ft, [rbp-32] purged count, [rbp-40] index
    lea     rcx, [rbp-56]
    call    GetSystemTimeAsFileTime
    mov     rax, qword ptr [rbp-56]
    mov     qword ptr [rbp-24], rax             ; now (FILETIME)
    mov     dword ptr [rbp-32], 0
    call    vault_count
    mov     dword ptr [rbp-40], eax             ; i = count
pt_loop:
    cmp     dword ptr [rbp-40], 0
    jle     pt_done
    dec     dword ptr [rbp-40]                  ; i-- (walk downward)
    mov     ecx, dword ptr [rbp-40]
    mov     edx, VF_DELETED
    lea     r8, [rbp-64]                        ; &vallen
    call    vault_field_at                      ; rax = value ptr (0 if not deleted)
    test    rax, rax
    jz      pt_loop
    cmp     qword ptr [rbp-64], 16              ; need a full 16-hex timestamp
    jb      pt_loop
    mov     rcx, rax
    call    gui_hex16_to_ft                     ; rax = deletion FILETIME
    mov     r10, qword ptr [rbp-24]
    sub     r10, rax                            ; age in FILETIME units
    mov     rax, 25920000000000                 ; 30 days * 24h * 3600s * 1e7 (100ns)
    cmp     r10, rax
    jbe     pt_loop                             ; younger than 30 days -> keep
    mov     ecx, dword ptr [rbp-40]             ; expired -> hard remove
    call    vault_remove_at
    inc     dword ptr [rbp-32]
    jmp     pt_loop
pt_done:
    cmp     dword ptr [rbp-32], 0
    je      pt_ret
    call    vault_reseal
pt_ret:
    mov     eax, dword ptr [rbp-32]
    FRAME_EPILOG
    ret
gui_purge_trash endp

.const
tr_hex_upper db "0123456789ABCDEF"
tr_hex_lower db "0123456789abcdef"
.code
; gui_trtest() -> eax = 0 pass / 1 fail.  Headless probe for the trash timestamp
;   encode/decode and the 30-day purge threshold (the computational core of the
;   soft-delete lifecycle).
public gui_trtest
gui_trtest proc frame
    FRAME_PROLOG 96
    lea     rcx, [tr_hex_upper]                  ; parse 16 upper hex -> 0x0123456789ABCDEF
    call    gui_hex16_to_ft
    mov     r10, 0123456789ABCDEFh
    cmp     rax, r10
    jne     tr_fail
    lea     rcx, [tr_hex_lower]                  ; lowercase must parse identically
    call    gui_hex16_to_ft
    cmp     rax, r10
    jne     tr_fail
    mov     rcx, 0ABh                            ; format 0xAB -> "00000000000000AB"
    lea     rdx, [rbp-64]
    call    gui_ft_hex16
    cmp     word ptr [rbp-64], '0'               ; first nibble char
    jne     tr_fail
    cmp     word ptr [rbp-64+28], 'A'            ; char[14]
    jne     tr_fail
    cmp     word ptr [rbp-64+30], 'B'            ; char[15]
    jne     tr_fail
    mov     rax, 34560000000000                  ; 40-day age exceeds the 30-day threshold
    mov     r10, 25920000000000
    cmp     rax, r10
    jbe     tr_fail
    mov     rax, 8640000000000                   ; 10-day age is under the threshold
    cmp     rax, r10
    ja      tr_fail
    xor     eax, eax
    FRAME_EPILOG
    ret
tr_fail:
    mov     eax, 1
    FRAME_EPILOG
    ret
gui_trtest endp

; gui_update_fav_glyph(rcx=hdlg) - set the header button glyph.  In recover mode
;   the favorite (star) button becomes a recycle (â™») button that restores the
;   shown entry; otherwise it reflects g_fav_state (outline / filled star).
gui_update_fav_glyph proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_trash_view], 0
    je      guf_star
    mov     r8d, GLY_RECYCLE                      ; recover mode -> recycle glyph (Segoe Symbol)
    jmp     guf_set
guf_star:
    mov     r8d, GLY_FAV_OFF                      ; outline (not favorite)
    cmp     dword ptr [g_fav_state], 0
    je      guf_set
    mov     r8d, GLY_FAV_ON                       ; filled (favorite)
guf_set:
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_FAV
    call    ghost_set_glyph
    FRAME_EPILOG
    ret
gui_update_fav_glyph endp

; gui_first_deleted() -> eax = index of the first trashed entry, or -1 if none.
gui_first_deleted proc frame
    FRAME_PROLOG 48
    call    vault_count
    mov     dword ptr [rbp-24], eax
    mov     dword ptr [rbp-32], 0
gfd_loop:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [rbp-24]
    jae     gfd_none
    mov     ecx, dword ptr [rbp-32]
    call    gui_entry_is_deleted
    test    eax, eax
    jnz     gfd_hit
    inc     dword ptr [rbp-32]
    jmp     gfd_loop
gfd_hit:
    mov     eax, dword ptr [rbp-32]
    FRAME_EPILOG
    ret
gfd_none:
    mov     eax, -1
    FRAME_EPILOG
    ret
gui_first_deleted endp

; gui_enter_trash(rcx = hdlg) - switch the sidebar into the trash (recover) view,
;   auto-showing the first deleted entry so Restore is immediately usable.
gui_enter_trash proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [g_trash_view], 1
    mov     rcx, qword ptr [rbp-24]
    call    gui_poplist
    mov     rcx, qword ptr [rbp-24]
    call    gui_update_done_btn
    call    gui_first_deleted
    cmp     eax, 0
    jl      get_done
    mov     rcx, qword ptr [rbp-24]           ; show the first trashed entry
    mov     edx, eax
    call    gui_showdetail
    mov     rcx, qword ptr [rbp-24]
    xor     edx, edx
    call    gui_set_editmode
get_done:
    FRAME_EPILOG
    ret
gui_enter_trash endp

; gui_leave_trash(rcx = hdlg) - return the sidebar to the normal vault view.
gui_leave_trash proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [g_trash_view], 0
    mov     dword ptr [g_cur_idx], -1
    mov     dword ptr [g_totp_on], 0
    mov     rcx, qword ptr [rbp-24]
    call    gui_rows_clear
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_TITLE, 0
    mov     rcx, qword ptr [rbp-24]
    call    gui_update_done_btn
    mov     rcx, qword ptr [rbp-24]
    call    gui_poplist
    mov     rcx, qword ptr [rbp-24]
    call    gui_update_fav_glyph                ; recycle -> star (g_trash_view=0 now)
    mov     rcx, qword ptr [rbp-24]
    call    gui_detail_clear                    ; empty the detail pane, deselect the list
    FRAME_EPILOG
    ret
gui_leave_trash endp

; gui_detail_clear(rcx = hdlg) - reset the detail pane to the no-entry state:
;   clear the times/title, hide the header tile + fav/recycle button, and clear
;   the list selection.  Caller has already set g_cur_idx = -1.
gui_detail_clear proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_TITLE, 0
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_HEADER
    call    GetDlgItem
    WINCALL ShowWindow, rax, SW_HIDE
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_FAV
    call    GetDlgItem
    WINCALL ShowWindow, rax, SW_HIDE
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_HDREDIT
    call    GetDlgItem
    WINCALL ShowWindow, rax, SW_HIDE
    mov     rcx, qword ptr [rbp-24]           ; the "..." (More) glyph hides with no entry too
    mov     edx, IDC_V_OVFL
    call    GetDlgItem
    WINCALL ShowWindow, rax, SW_HIDE
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_SETCURSEL, \
            -1, 0
    ; The pane is empty now, so the home panel is what belongs there - force the
    ; erase that draws it.  Neither caller repaints, and without this the panel only
    ; appeared the next time something else happened to invalidate the window.
    WINCALL InvalidateRect, qword ptr [rbp-24], 0, 1
    FRAME_EPILOG
    ret
gui_detail_clear endp

; gui_update_done_btn(rcx = hdlg) - show the highlighted "Done" button (exit
;   recover mode) only in trash view, and tag it as the accent/primary button.
gui_update_done_btn proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     edx, IDC_V_DONE
    call    GetDlgItem
    mov     qword ptr [rbp-32], rax             ; Done hwnd
    WINCALL SetWindowLongPtrW, rax, GWL_USERDATA, 1   ; theme_drawitem -> accent primary
    mov     r8d, SW_HIDE
    cmp     dword ptr [g_trash_view], 0
    je      gud_show
    mov     r8d, SW_SHOW
gud_show:
    WINCALL ShowWindow, qword ptr [rbp-32], r8d
    FRAME_EPILOG
    ret
gui_update_done_btn endp

; gui_trash_glyph_hit(rcx = hdlg) -> eax = 1 if the mouse cursor is over the
;   recycle glyph (right ~24 px) of the currently selected list item.  Used to
;   turn a click on that glyph into a per-item restore.
gui_trash_glyph_hit proc frame
    FRAME_PROLOG 96
    ; [rbp-32]=list hwnd  [rbp-40]=sel idx  RECT@[rbp-72]  POINT@[rbp-80]
    mov     qword ptr [rbp-24], rcx
    mov     edx, IDC_V_LIST
    call    GetDlgItem
    mov     qword ptr [rbp-32], rax
    WINCALL SendMessageW, qword ptr [rbp-32], LB_GETCURSEL, 0, 0
    cmp     eax, -1                             ; LB_ERR
    je      gtgh_no
    mov     dword ptr [rbp-40], eax
    WINCALL SendMessageW, qword ptr [rbp-32], LB_GETITEMRECT, dword ptr [rbp-40], addr rbp-72
    WINCALL GetCursorPos, addr rbp-80
    WINCALL ScreenToClient, qword ptr [rbp-32], addr rbp-80
    mov     eax, dword ptr [rbp-64]             ; rc.right
    sub     eax, 24
    cmp     dword ptr [rbp-80], eax             ; pt.x >= rc.right-24 ?
    jl      gtgh_no
    mov     eax, dword ptr [rbp-76]             ; pt.y
    cmp     eax, dword ptr [rbp-68]             ; >= rc.top ?
    jl      gtgh_no
    cmp     eax, dword ptr [rbp-60]             ; < rc.bottom ?
    jge     gtgh_no
    mov     eax, 1
    FRAME_EPILOG
    ret
gtgh_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_trash_glyph_hit endp

; gui_restore_entry(rcx = hdlg, edx = vault index) - restore one trashed entry:
;   load it into the detail, clear its VF_DELETED marker, reseal, then refresh
;   the recover list (staying in recover mode).
gui_restore_entry proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    call    gui_showdetail                      ; load the entry so gui_commit rebuilds it
    mov     dword ptr [g_deleted_state], 0       ; clear the deleted marker + reseal
    mov     rcx, qword ptr [rbp-24]
    call    gui_commit
    mov     dword ptr [g_dirty], 0
    mov     dword ptr [g_cur_idx], -1            ; it left the trash: clear the detail
    mov     rcx, qword ptr [rbp-24]
    call    gui_rows_clear
    mov     rcx, qword ptr [rbp-24]
    call    gui_poplist                          ; refresh the recover list
    mov     rcx, qword ptr [rbp-24]
    call    gui_detail_clear                     ; empty the detail (no stale entry shown)
    FRAME_EPILOG
    ret
gui_restore_entry endp

; gui_pick_template(rcx=hdlg) -> eax = template index (0..3), or -1 if cancelled.
;   Pops the new-entry template menu (redesign D4) at the cursor.
gui_pick_template proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    WINCALL CreatePopupMenu
    mov     qword ptr [rbp-32], rax
    test    rax, rax
    jz      gpt_cancel
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 1, addr tm_login
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 2, addr tm_card
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 3, addr tm_ident
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 4, addr tm_note
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_SEPARATOR, 0, 0
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 5, addr tm_blank
    mov     rcx, qword ptr [rbp-32]
    call    gui_menu_dark
    mov     qword ptr [rbp-64], rax
    lea     rcx, [rbp-56]
    call    GetCursorPos
    WINCALL SetForegroundWindow, qword ptr [rbp-24]
    WINCALL TrackPopupMenu, qword ptr [rbp-32], TPM_RETURNCMD or TPM_LEFTALIGN, \
            dword ptr [rbp-56], dword ptr [rbp-52], 0, qword ptr [rbp-24], 0
    mov     dword ptr [rbp-44], eax
    WINCALL DestroyMenu, qword ptr [rbp-32]
    WINCALL DeleteObject, qword ptr [rbp-64]
    mov     eax, dword ptr [rbp-44]
    test    eax, eax
    jz      gpt_cancel
    dec     eax                                 ; menu id 1..4 -> index 0..3
    FRAME_EPILOG
    ret
gpt_cancel:
    mov     eax, -1
    FRAME_EPILOG
    ret
gui_pick_template endp

; gui_build_template(edx = template index) - fill g_field_list from a template:
;   Title first, then each preset {type, label} with an empty value.  Sets g_field_n.
gui_build_template proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-28], edx
    lea     r10, [g_field_list]                 ; field 0 = Title "New entry"
    mov     qword ptr [r10+0], VF_TITLE
    mov     qword ptr [r10+8], 0
    lea     rax, [wt_newentry]
    mov     qword ptr [r10+16], rax
    mov     eax, dword ptr [rbp-28]
    lea     r11, [tmpl_table]
    mov     r11, qword ptr [r11+rax*8]          ; -> template descriptor
    mov     rcx, qword ptr [r11]                ; extra-field count
    add     r11, 8
    mov     edx, 1                              ; k = 1
gbt_lp:
    test    rcx, rcx
    jz      gbt_done
    mov     eax, edx
    imul    eax, eax, 24
    lea     r9, [g_field_list]
    add     r9, rax                             ; &g_field_list[k]
    mov     rax, qword ptr [r11+0]              ; type
    mov     qword ptr [r9+0], rax
    mov     rax, qword ptr [r11+8]              ; label ptr (0 = default)
    mov     qword ptr [r9+8], rax
    lea     rax, [g_empty_w]                    ; value = empty
    mov     qword ptr [r9+16], rax
    add     r11, 16
    inc     edx
    dec     rcx
    jmp     gbt_lp
gbt_done:
    mov     dword ptr [g_field_n], edx
    FRAME_EPILOG
    ret
gui_build_template endp

; gui_addfield_menu(rcx=hdlg) - popup the field-type palette at the cursor.
gui_addfield_menu proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx
    WINCALL CreatePopupMenu
    mov     qword ptr [rbp-32], rax
    test    rax, rax
    jz      gam_done
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 1, addr kl_user
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 2, addr kl_secret
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 3, addr kl_url
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 4, addr kl_email
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 5, addr kl_notes
    mov     dword ptr [rbp-40], MF_OWNERDRAW    ; enabled owner-draw
    call    gui_has_totp                        ; grey TOTP if one already exists (live rows)
    test    eax, eax
    jz      gam_totp
    mov     dword ptr [rbp-40], MF_OWNERDRAW or 1  ; MF_OWNERDRAW | MF_GRAYED
gam_totp:
    WINCALL AppendMenuW, qword ptr [rbp-32], dword ptr [rbp-40], 6, addr kl_totp
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 9, addr kl_file
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 10, addr kl_group
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, 11, addr kl_spacer
    mov     rcx, qword ptr [rbp-32]              ; tint the menu background
    call    gui_menu_dark
    mov     qword ptr [rbp-64], rax
    lea     rcx, [rbp-56]                        ; POINT
    call    GetCursorPos
    WINCALL SetForegroundWindow, qword ptr [rbp-24]
    WINCALL TrackPopupMenu, qword ptr [rbp-32], TPM_RETURNCMD or TPM_LEFTALIGN, \
            dword ptr [rbp-56], dword ptr [rbp-52], 0, qword ptr [rbp-24], 0
    mov     dword ptr [rbp-44], eax              ; chosen id
    WINCALL DestroyMenu, qword ptr [rbp-32]
    WINCALL DeleteObject, qword ptr [rbp-64]
    cmp     dword ptr [rbp-44], 0
    je      gam_done
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-44]
    call    gui_palette_add
gam_done:
    FRAME_EPILOG
    ret
gui_addfield_menu endp

; gui_menu_open(rcx=hdlg) - hide the vault content, reveal the settings overlay.
; =============================================================================
; The settings screen is a WS_CHILD dialog covering the vault's client area
; (docs/SETTINGS_DESIGN.md).  It used to be ~34 controls living inside DLG_VAULT,
; shown and hidden through a hand-maintained id array - which is what produced the
; recurring bleed-through: a control missing from the array, or a painter that forgot
; to check the flag, and the vault showed through the "overlay".
;
; A real window occludes what is behind it for free.  There is one hwnd to show and
; hide, the settings rows live in their own coordinate space, and no painter needs to
; know settings exists.
;
; settings_proc keeps NO logic of its own: WM_COMMAND / WM_DRAWITEM / WM_MEASUREITEM
; are forwarded to the vault window, so every existing handler works unchanged.
; =============================================================================
settings_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      stp_init
    cmp     rdx, WM_COMMAND
    je      stp_fwd
    cmp     rdx, WM_DRAWITEM                    ; owner-draw settings controls: the parent
    je      stp_fwd                             ;   already knows how to paint every one
    cmp     rdx, WM_MEASUREITEM
    je      stp_fwd
    cmp     rdx, WM_CTLCOLORSTATIC
    je      stp_col
    cmp     rdx, WM_CTLCOLOREDIT
    je      stp_col
    cmp     rdx, WM_CTLCOLORBTN
    je      stp_col
    cmp     rdx, WM_CTLCOLORDLG
    je      stp_col
    cmp     rdx, WM_ERASEBKGND
    je      stp_erase
    cmp     rdx, WM_PAINT
    je      stp_paint
    xor     eax, eax
    jmp     stp_ret
stp_col:
    call    theme_ctlcolor
    jmp     stp_ret
stp_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     stp_ret
stp_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     stp_ret
stp_init:
    mov     eax, 1
    jmp     stp_ret
stp_fwd:
    mov     qword ptr [rbp-16], rdx             ; msg
    mov     qword ptr [rbp-24], r8              ; wParam
    mov     qword ptr [rbp-32], r9              ; lParam
    WINCALL GetParent, qword ptr [rbp-8]
    WINCALL SendMessageW, rax, qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    mov     eax, 1
stp_ret:
    mov     rsp, rbp
    pop     rbp
    ret
settings_proc endp

; gui_clip_cb(rcx = child hwnd, rdx = lparam) -> BOOL - add WS_CLIPSIBLINGS.
;   Z-order alone is not enough.  Without WS_CLIPSIBLINGS a control still paints over the
;   area of a sibling ABOVE it, so the entry list and the search box scribbled straight
;   over the settings child even though the child sat on top.  With it, the window
;   manager excludes the overlapping sibling from their clip region and the overlay holds
;   without anyone hiding anything by hand.
;   DIRECT children of the vault only.  EnumChildWindows recurses, and clipping the
;   SETTINGS child's own controls breaks them: the template overlaps each numeric edit
;   with the label to its left by ~4 DLU, and the label sits above it in z-order, so a
;   clipped edit loses its own left edge ("20" renders as "!0").  Those controls have no
;   overlay to defend against - only the vault's do.
gui_clip_cb proc frame
    FRAME_PROLOG 72                            ; locals clear of the callees' home areas
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx            ; the vault hwnd
    WINCALL GetParent, qword ptr [rbp-24]
    cmp     rax, qword ptr [rbp-32]
    jne     gcc_next                           ; a grandchild: leave it alone
    WINCALL GetWindowLongPtrW, qword ptr [rbp-24], GWL_STYLE_
    or      rax, WS_CLIPSIBLINGS_
    mov     qword ptr [rbp-40], rax
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], GWL_STYLE_, qword ptr [rbp-40]
gcc_next:
    mov     eax, 1
    FRAME_EPILOG
    ret
gui_clip_cb endp

; gui_clip_children(rcx = hdlg) - apply it to the vault's direct children.  Called again
;   whenever settings opens: the left-margin buttons are created at RUNTIME, after the
;   init-time pass, so they would otherwise still paint over the panel.
gui_clip_children proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    WINCALL EnumChildWindows, qword ptr [rbp-24], addr gui_clip_cb, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
gui_clip_children endp

; gui_settings_size(rcx = vault hdlg) - keep the child covering the vault's content.
;   It sits BELOW the custom title strip, so the close button and the strip stay live,
;   and on TOP of its siblings - without that the search box and the margin glyphs paint
;   over it, which is the whole failure mode this refactor exists to remove.
gui_settings_size proc frame
    FRAME_PROLOG 120                          ; locals must clear SetWindowPos's 7-arg area
    cmp     qword ptr [g_settings_hwnd], 0
    je      gss2_done
    mov     qword ptr [rbp-24], rcx
    WINCALL GetClientRect, qword ptr [rbp-24], addr rbp-56
    mov     eax, dword ptr [rbp-44]            ; height below the strip
    sub     eax, TBAR_H
    jns     @F
    xor     eax, eax
@@: mov     dword ptr [rbp-64], eax
    WINCALL MoveWindow, qword ptr [g_settings_hwnd], 0, TBAR_H, \
            dword ptr [rbp-48], dword ptr [rbp-64], 1
    WINCALL SetWindowPos, qword ptr [g_settings_hwnd], 0, 0, 0, 0, 0, \
            <SWP_NOMOVE_ or SWP_NOSIZE_ or SWP_NOACTIVATE_>   ; above every sibling...
    ; ...except the settings cogwheel, which is what CLOSES this panel.  Covering it left
    ; no way out but Escape.  The other two margin glyphs (new item, generator) stay
    ; behind, which is what they should do while settings is up.
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_T_SET
    mov     qword ptr [rbp-72], rax
    test    rax, rax
    jz      gss2_done
    WINCALL SetWindowPos, qword ptr [rbp-72], 0, 0, 0, 0, 0, \
            <SWP_NOMOVE_ or SWP_NOSIZE_ or SWP_NOACTIVATE_>
gss2_done:
    FRAME_EPILOG
    ret
gui_settings_size endp

; gui_settings_populate() - push every table row's live value into its control and
;   gate the control on its HKLM lock.  Targets g_settings_hwnd, never a parameter:
;   these controls exist in exactly one window (see tools/dlgtarget.py).
gui_settings_populate proc frame
    FRAME_PROLOG 96
    lea     rax, [g_setrows]
    mov     qword ptr [rbp-24], rax               ; row cursor
gsp_loop:
    lea     rax, [g_setrows_end]
    cmp     qword ptr [rbp-24], rax
    jae     gsp_done
    mov     r11, qword ptr [rbp-24]
    mov     eax, dword ptr [r11+SR_ID]
    mov     dword ptr [rbp-56], eax               ; id
    mov     eax, 1                                ; enabled unless HKLM says otherwise
    mov     r10, qword ptr [r11+SR_LOCK]
    test    r10, r10
    jz      gsp_hw
    mov     eax, dword ptr [r10]
    xor     eax, 1
    and     eax, 1
gsp_hw:
    test    dword ptr [r11+SR_FLAGS], SF_NEEDHW   ; TPM: also needs the hardware
    jz      gsp_enable
    cmp     dword ptr [g_tpm_present], 0
    jne     gsp_enable
    xor     eax, eax
gsp_enable:
    mov     dword ptr [rbp-40], eax               ; enable
    cmp     dword ptr [r11+SR_KIND], SK_NUM       ; only numerics carry a value
    jne     gsp_gate
    mov     r10, qword ptr [r11+SR_VAL]
    mov     eax, dword ptr [r10]
    mov     dword ptr [rbp-48], eax
    WINCALL SetDlgItemInt, qword ptr [g_settings_hwnd], dword ptr [rbp-56], \
            dword ptr [rbp-48], 0
gsp_gate:
    WINCALL GetDlgItem, qword ptr [g_settings_hwnd], dword ptr [rbp-56]
    mov     qword ptr [rbp-64], rax
    test    rax, rax
    jz      gsp_next
    WINCALL EnableWindow, qword ptr [rbp-64], dword ptr [rbp-40]
gsp_next:
    add     qword ptr [rbp-24], SR_SIZE
    jmp     gsp_loop
gsp_done:
    FRAME_EPILOG
    ret
gui_settings_populate endp

; gui_settings_store() - read every table row back and persist it to HKCU.  A row
;   locked by HKLM is skipped entirely so the policy value is never overwritten.
gui_settings_store proc frame
    FRAME_PROLOG 96
    lea     rax, [g_setrows]
    mov     qword ptr [rbp-24], rax
gss_loop:
    lea     rax, [g_setrows_end]
    cmp     qword ptr [rbp-24], rax
    jae     gss_done
    mov     r11, qword ptr [rbp-24]
    mov     r10, qword ptr [r11+SR_LOCK]          ; HKLM-locked -> leave it alone
    test    r10, r10
    jz      gss_kind
    cmp     dword ptr [r10], 0
    jne     gss_next
gss_kind:
    cmp     dword ptr [r11+SR_KIND], SK_NUM
    jne     gss_persist
    mov     eax, dword ptr [r11+SR_ID]
    mov     dword ptr [rbp-56], eax
    WINCALL GetDlgItemInt, qword ptr [g_settings_hwnd], dword ptr [rbp-56], 0, 0
    mov     dword ptr [rbp-48], eax
    mov     r11, qword ptr [rbp-24]
    test    eax, eax
    jnz     gss_clamp
    test    dword ptr [r11+SR_FLAGS], SF_ZEROOK   ; 0 illegal here -> keep the old
    jz      gss_next                              ;   value rather than store junk
gss_clamp:
    mov     eax, dword ptr [rbp-48]
    cmp     eax, dword ptr [r11+SR_MAX]
    jbe     @F
    mov     eax, dword ptr [r11+SR_MAX]
@@: mov     r10, qword ptr [r11+SR_VAL]
    mov     dword ptr [r10], eax
gss_persist:
    mov     r11, qword ptr [rbp-24]
    mov     r10, qword ptr [r11+SR_REG]           ; no reg name -> nothing to write
    test    r10, r10
    jz      gss_next
    mov     rax, qword ptr [r11+SR_VAL]
    test    rax, rax
    jz      gss_next
    mov     rcx, r10
    mov     edx, dword ptr [rax]
    call    cfg_set_dword_hkcu
gss_next:
    add     qword ptr [rbp-24], SR_SIZE
    jmp     gss_loop
gss_done:
    FRAME_EPILOG
    ret
gui_settings_store endp

gui_menu_open proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx           ; the VAULT window
    mov     rcx, qword ptr [rbp-24]           ; drop the revealed-secret overlay FIRST: it
    call    gui_colorpw_hide                  ;   re-shows the plaintext value edit
    mov     rcx, qword ptr [rbp-24]           ; re-apply: the margin buttons and the detail
    call    gui_clip_children                 ;   rows are created after vp_init's pass
    mov     rcx, qword ptr [rbp-24]
    call    gui_settings_size                 ; cover the client area, then show
    WINCALL ShowWindow, qword ptr [g_settings_hwnd], SW_SHOW
    call    gui_settings_populate             ; every row: value + HKLM gating
    call    gui_hotkey_label                  ; show the live summon combo on its button
    mov     dword ptr [g_menu_open], 1
    WINCALL RedrawWindow, qword ptr [rbp-24], 0, 0, 0185h  ; INVALIDATE|ERASE|ALLCHILDREN|UPDATENOW
    FRAME_EPILOG
    ret
gui_menu_open endp

; gui_menu_close(rcx=hdlg) - apply the settings, then hide the overlay.
gui_menu_close proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    call    gui_menu_save                    ; save all settings on leaving the screen
    WINCALL ShowWindow, qword ptr [g_settings_hwnd], SW_HIDE   ; one hwnd, not 35 ids
    mov     rcx, qword ptr [rbp-24]           ; restore edit-mode state
    mov     edx, dword ptr [g_editmode]
    call    gui_set_editmode
    mov     dword ptr [g_menu_open], 0
    WINCALL RedrawWindow, qword ptr [rbp-24], 0, 0, 0185h
    FRAME_EPILOG
    ret
gui_menu_close endp

; gui_menu_toggle(rcx=hdlg) - open or close the settings overlay.
gui_menu_toggle proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_menu_open], 0
    jne     mtg_close
    mov     rcx, qword ptr [rbp-24]
    call    gui_menu_open
    FRAME_EPILOG
    ret
mtg_close:
    mov     rcx, qword ptr [rbp-24]
    call    gui_menu_close
    FRAME_EPILOG
    ret
gui_menu_toggle endp

; gui_menu_save(rcx=hdlg) - apply the policy fields (HKCU) + the TPM toggle,
;   then close the overlay.  HKLM-locked policy values are left untouched.
gui_menu_save proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx           ; the VAULT window (timers below), NOT the
                                              ;   settings child - a store to
                                              ;   g_settings_hwnd here overwrote the live
                                              ;   child handle with it, and the caller's
                                              ;   ShowWindow(SW_HIDE) then hid the vault.
    call    gui_settings_store                ; every row: clamp, store, persist
    WINCALL KillTimer, qword ptr [rbp-24], IDLE_TIMER   ; re-arm the poll (auto-lock +
    WINCALL SetTimer, qword ptr [rbp-24], IDLE_TIMER, IDLE_POLL_MS, 0   ;   C8.4).
                                              ; Unconditional now: the old chain reached
                                              ;   this only on one path, so a changed
                                              ;   idle timeout often did not take effect
                                              ;   until the next unlock.
    ; TPM is the one row with a side effect beyond the registry - enrolling seals the
    ; vault key to the chip - so the enrol/forget decision stays hand-written here.
    ; Persisting g_tpm_want is the table's job (neither call touches it, so the order
    ; of the two does not matter).
msv_tpm:
    cmp     dword ptr [g_tpm_present], 0
    je      msv_done                        ; no TPM -> nothing to enrol/forget
    mov     eax, dword ptr [g_tpm_want]     ; Fluent toggle state
    mov     dword ptr [rbp-32], eax         ; want enrolled?
    call    vault_tpm_has
    mov     dword ptr [rbp-36], eax         ; currently enrolled?
    cmp     dword ptr [rbp-32], 0
    je      msv_unwant
    cmp     dword ptr [rbp-36], 0
    jne     msv_done                        ; want + have -> already sealed
    call    vault_tpm_remember
    jmp     msv_done
msv_unwant:
    cmp     dword ptr [rbp-36], 0
    je      msv_done                        ; !want + !have
    call    vault_tpm_forget
msv_done:
    FRAME_EPILOG
    ret
gui_menu_save endp

; =============================================================================
; Custom title-bar frame helpers (redesign A1).  The vault window drops
; WS_CAPTION and grows a TBAR_H strip at the top of its client area: existing
; content is shifted down into place at init, and the strip hosts the caption
; buttons (min/max/close) plus the search box and control dock.  Dragging the
; empty strip moves the window (HTCAPTION from frame_hittest); WS_THICKFRAME
; still resizes from the borders.
; =============================================================================

; frame_hittest(rcx=hdlg, r9=lParam screen POINT) -> eax=1 when the cursor is in
;   the empty title strip (DWLP_MSGRESULT set to HTCAPTION), else 0 (default).
frame_hittest proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    movsx   eax, r9w                           ; screen x
    mov     dword ptr [rbp-40], eax
    mov     r10, r9
    sar     r10, 16
    movsx   eax, r10w                          ; screen y
    mov     dword ptr [rbp-36], eax            ; POINT{x=[rbp-40], y=[rbp-36]}
    WINCALL ScreenToClient, qword ptr [rbp-24], addr rbp-40
    WINCALL GetClientRect, qword ptr [rbp-24], addr rbp-64   ; 0 0 R-56 B-52
    ; Anywhere inside the client area that isn't a child control counts as chrome
    ; and drags the window (child controls hit-test themselves; static labels are
    ; HTTRANSPARENT and fall through here).  Clicks outside the client are the NC
    ; sizing border - leave those to DefDlgProc so the window stays resizable.
    mov     eax, dword ptr [rbp-40]            ; x in [0, client width) ?
    cmp     eax, 0
    jl      fht_no
    cmp     eax, dword ptr [rbp-56]
    jge     fht_no
    mov     eax, dword ptr [rbp-36]            ; y in [0, client height) ?
    cmp     eax, 0
    jl      fht_no
    cmp     eax, dword ptr [rbp-52]
    jge     fht_no
    WINCALL SetWindowLongPtrW, qword ptr [rbp-24], DWLP_MSGRESULT_, HTCAPTION
    mov     eax, 1
    FRAME_EPILOG
    ret
fht_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
frame_hittest endp

; frame_shift_cb(rcx=child, rdx=parent) - EnumChildWindows callback: move one
;   child down by TBAR_H so the reclaimed caption space becomes the title strip.
frame_shift_cb proc frame
    FRAME_PROLOG 128                            ; spill area must clear the locals (down to -76)
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    ; DIRECT children only.  EnumChildWindows recurses, so this used to shift the settings
    ; child's own 34 controls down by TBAR_H as well - on top of the child already being
    ; placed at TBAR_H - which is what pushed the whole panel down the screen.  A
    ; grandchild's position is relative to its own parent and must not be touched here.
    WINCALL GetParent, qword ptr [rbp-24]
    cmp     rax, qword ptr [rbp-32]
    jne     fsc_skip
    WINCALL GetWindowRect, qword ptr [rbp-24], addr rbp-64   ; L-64 T-60 R-56 B-52
    WINCALL MapWindowPoints, 0, qword ptr [rbp-32], addr rbp-64, 2
    mov     eax, dword ptr [rbp-56]            ; w = R - L
    sub     eax, dword ptr [rbp-64]
    mov     dword ptr [rbp-68], eax
    mov     eax, dword ptr [rbp-52]            ; h = B - T
    sub     eax, dword ptr [rbp-60]
    mov     dword ptr [rbp-72], eax
    mov     eax, dword ptr [rbp-60]            ; newY = T + TBAR_H
    add     eax, TBAR_H
    mov     dword ptr [rbp-76], eax
    WINCALL MoveWindow, qword ptr [rbp-24], dword ptr [rbp-64], dword ptr [rbp-76], \
            dword ptr [rbp-68], dword ptr [rbp-72], 1
fsc_skip:
    mov     eax, 1                             ; continue enumeration
    FRAME_EPILOG
    ret
frame_shift_cb endp

; frame_shift(rcx=hdlg) - shift every existing child down into place.
frame_shift proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    WINCALL EnumChildWindows, qword ptr [rbp-24], addr frame_shift_cb, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
frame_shift endp

; frame_grow(rcx=hdlg) - grow the window height by TBAR_H so the shifted content
;   keeps its size and the new strip is pure gain at the top.
frame_grow proc frame
    FRAME_PROLOG 128                            ; spill area must clear the locals (down to -56)
    mov     qword ptr [rbp-24], rcx
    WINCALL GetWindowRect, qword ptr [rbp-24], addr rbp-48   ; L-48 T-44 R-40 B-36
    mov     eax, dword ptr [rbp-40]            ; w = R - L
    sub     eax, dword ptr [rbp-48]
    mov     dword ptr [rbp-52], eax
    mov     eax, dword ptr [rbp-36]            ; h = B - T + TBAR_H
    sub     eax, dword ptr [rbp-44]
    add     eax, TBAR_H
    mov     dword ptr [rbp-56], eax
    WINCALL SetWindowPos, qword ptr [rbp-24], 0, 0, 0, dword ptr [rbp-52], \
            dword ptr [rbp-56], SWP_FRAME_
    FRAME_EPILOG
    ret
frame_grow endp

; frame_layout(rcx=hdlg) - right-align the caption buttons in the title strip.
;   Called at build time and on WM_SIZE.
frame_layout proc frame
    FRAME_PROLOG 128                            ; spill area must clear the locals (down to -60)
    mov     qword ptr [rbp-24], rcx
    WINCALL GetClientRect, qword ptr [rbp-24], addr rbp-48   ; R at [rbp-40]
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [rbp-52], eax            ; client width
    mov     eax, dword ptr [rbp-52]            ; xClose = W - CAPBTN_W
    sub     eax, CAPBTN_W
    mov     dword ptr [rbp-56], eax
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_T_CLOSE
    WINCALL MoveWindow, rax, dword ptr [rbp-56], 0, CAPBTN_W, TBAR_H, 1
    ; R7.5 removed min/max; New / Generate / Settings then moved out of the strip
    ; into the left margin beside the sidebar (sidebar_layout places them, since
    ; they anchor to the entry list).  The whole strip is now draggable space.
    FRAME_EPILOG
    ret
frame_layout endp

; frame_maxinfo(rcx=hdlg, rdx=MINMAXINFO*) - constrain the maximized size/position
;   to the monitor work area, so the borderless window does not cover the taskbar.
frame_maxinfo proc frame
    FRAME_PROLOG 112   ; >= 112: keep locals clear of the callee 32-byte home area
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    WINCALL MonitorFromWindow, qword ptr [rbp-24], 2   ; MONITOR_DEFAULTTONEAREST
    mov     qword ptr [rbp-40], rax
    mov     dword ptr [rbp-96], 40             ; MONITORINFO.cbSize
    WINCALL GetMonitorInfoW, qword ptr [rbp-40], addr rbp-96
    ; rcMonitor L-92 T-88 R-84 B-80 ; rcWork L-76 T-72 R-68 B-64
    mov     r10, qword ptr [rbp-32]            ; MINMAXINFO
    mov     eax, dword ptr [rbp-68]            ; ptMaxSize.x = work width
    sub     eax, dword ptr [rbp-76]
    mov     dword ptr [r10+8], eax
    mov     eax, dword ptr [rbp-64]            ; ptMaxSize.y = work height
    sub     eax, dword ptr [rbp-72]
    mov     dword ptr [r10+12], eax
    mov     eax, dword ptr [rbp-76]            ; ptMaxPosition.x = work.L - monitor.L
    sub     eax, dword ptr [rbp-92]
    mov     dword ptr [r10+16], eax
    mov     eax, dword ptr [rbp-72]            ; ptMaxPosition.y = work.T - monitor.T
    sub     eax, dword ptr [rbp-88]
    mov     dword ptr [r10+20], eax
    FRAME_EPILOG
    ret
frame_maxinfo endp

; frame_build(rcx=hdlg) - create the caption ghost buttons, then lay them out.
;   Called from vp_init AFTER frame_shift/frame_grow so they are not shifted.
frame_build proc frame
    FRAME_PROLOG 128                            ; room for the 9-arg mk_ctl spill
    mov     qword ptr [rbp-24], rcx
    ; R7.5: no minimize/maximize caption buttons - only the close glyph remains.
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_T_CLOSE
    mov     r8d, GLY_CLOSE
    lea     r9, [gt_close]
    call    ghost_make
    mov     rcx, qword ptr [rbp-24]             ; dock: New / Generate / Settings
    mov     edx, IDC_T_NEW
    mov     r8d, GLY_NEW
    lea     r9, [gt_new]
    call    ghost_make
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_T_GEN
    mov     r8d, GLY_GENERATE
    lea     r9, [gt_gen]
    call    ghost_make
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_T_SET
    mov     r8d, GLY_SETTINGS
    lea     r9, [gt_settings]
    call    ghost_make
    mov     rcx, qword ptr [rbp-24]
    call    frame_layout
    FRAME_EPILOG
    ret
frame_build endp


; =============================================================================
; vault_proc - DLG_VAULT dialog procedure (raw frame).
; =============================================================================
vault_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96                         ; 96 not 64: at 64 a 5-arg WINCALL's spill
                                            ;   ([rsp+32]) landed on the deepest local
                                            ;   [rbp-32].  Safe only because that slot
                                            ;   is live solely inside vp_t_idle - too
                                            ;   fragile a property for a 1100-line
                                            ;   dispatcher that gains handlers often
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      vp_init
    cmp     rdx, WM_COMMAND
    je      vp_cmd
    cmp     rdx, WM_CLOSE
    je      vp_close
    cmp     rdx, WM_TIMER
    je      vp_timer_clip
    cmp     rdx, WM_WTSSESSION_CHANGE
    je      vp_wts
    cmp     rdx, WM_DROPFILES
    je      vp_drop
    cmp     rdx, WM_PAINT
    je      vp_tpaint
    cmp     rdx, WM_ERASEBKGND
    je      vp_terase
    cmp     rdx, WM_DRAWITEM
    je      vp_tdraw
    cmp     rdx, WM_MEASUREITEM
    je      vp_measure
    cmp     rdx, WM_COMPAREITEM
    je      vp_compare
    cmp     rdx, WM_CTLCOLOREDIT
    je      vp_tcolor
    cmp     rdx, WM_CTLCOLORLISTBOX
    je      vp_tcolor
    cmp     rdx, WM_CTLCOLORBTN
    je      vp_tcolor
    cmp     rdx, WM_CTLCOLORDLG
    je      vp_tcolor
    cmp     rdx, WM_CTLCOLORSTATIC
    je      vp_tcolor
    cmp     rdx, WM_SIZE_
    je      vp_size
    cmp     rdx, WM_GETMINMAXINFO_
    je      vp_minmax
    cmp     rdx, WM_NCHITTEST_
    je      vp_nchit
    xor     eax, eax
    jmp     vp_ret
vp_tcolor:
    call    gui_ctlcolor                     ; theme + link-blue for view-mode URL values
    jmp     vp_ret
vp_nchit:
    mov     rcx, qword ptr [rbp-8]           ; custom frame: drag the empty title strip
    call    frame_hittest                    ;   (r9 already = lParam screen point)
    test    eax, eax
    jz      vp_nchit_def
    mov     eax, 1                           ; handled: DWLP_MSGRESULT = HTCAPTION
    jmp     vp_ret
vp_nchit_def:
    xor     eax, eax                         ; not in strip -> DefDlgProc default hittest
    jmp     vp_ret
vp_size:
    mov     rcx, qword ptr [rbp-8]           ; responsive reflow of anchored controls
    call    gui_reflow
    mov     rcx, qword ptr [rbp-8]           ; the settings child covers the client area,
    call    gui_settings_size                ;   so it resizes with it - one MoveWindow
                                             ;   instead of anchoring 34 controls
    cmp     dword ptr [g_cur_idx], 0         ; re-paginate the detail for the new height
    jl      vp_size_nopag
    mov     rcx, qword ptr [rbp-8]
    call    gui_rows_layout
vp_size_nopag:
    mov     rcx, qword ptr [rbp-8]           ; keep the caption buttons right-aligned
    call    frame_layout
    ; The title-strip dock/caption buttons are owner-draw children that MoveWindow
    ; repositions by bit-blitting their pixels, then only re-invalidating the thin
    ; newly-uncovered sliver.  On a slow multi-step drag that leaves each WM_DRAWITEM
    ; painting only part of the glyph, so the Fluent icons tear into fragments and
    ; the "+" loses its stem.  RDW_ALLCHILDREN forces a full repaint of every child
    ; (whole glyph), not the blit-preserved copy, clearing the trails.
    WINCALL RedrawWindow, qword ptr [rbp-8], 0, 0, 85h   ; INVALIDATE|ERASE|ALLCHILDREN
    xor     eax, eax
    jmp     vp_ret
vp_minmax:
    mov     r10, r9                          ; MINMAXINFO: ptMinTrackSize at +24
    mov     eax, dword ptr [g_base_winw]
    test    eax, eax
    jz      vp_minmax_max                    ; not recorded yet -> leave min default
    mov     dword ptr [r10+24], eax
    mov     eax, dword ptr [g_base_winh]
    mov     dword ptr [r10+28], eax
vp_minmax_max:
    mov     rcx, qword ptr [rbp-8]           ; keep maximize inside the work area
    mov     rdx, r9                          ;   (borderless would cover the taskbar)
    call    frame_maxinfo
    xor     eax, eax
    jmp     vp_ret
vp_drop:
    cmp     dword ptr [g_editmode], 0        ; only accept drops while editing an entry
    je      vp_drop_ret
    mov     rcx, qword ptr [rbp-8]           ; hdlg
    mov     rdx, r8                          ; wParam = HDROP
    call    gui_drop_files
vp_drop_ret:
    xor     eax, eax
    jmp     vp_ret
vp_tdraw_list:
    mov     rcx, r9
    call    gui_draw_listitem
    mov     eax, 1
    jmp     vp_ret
vp_tdraw_menu:
    mov     rcx, r9
    call    gui_menu_draw
    mov     eax, 1
    jmp     vp_ret
vp_measure:
    mov     r10, r9
    cmp     dword ptr [r10+0], 1             ; ODT_MENU -> size to the label
    je      vp_measure_menu
    mov     eax, dword ptr [g_layout]        ; MEASUREITEMSTRUCT.itemHeight per layout
    lea     r11, [lay_itemh]
    mov     eax, dword ptr [r11+rax*4]
    mov     dword ptr [r10+16], eax
    mov     eax, 1
    jmp     vp_ret
vp_measure_menu:
    mov     rcx, r9
    call    gui_menu_measure
    mov     eax, 1
    jmp     vp_ret
vp_compare:
    mov     r10, r9                          ; COMPAREITEMSTRUCT: CtlID +4, item data +24/+40
    mov     ecx, dword ptr [r10+24]          ; IDC_V_LIST entry cards ordered by gui_title_cmp
    mov     edx, dword ptr [r10+40]
    call    gui_title_cmp
    jmp     vp_ret
vp_tpaint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     vp_ret
vp_terase:
    mov     qword ptr [rbp-16], r8            ; hdc
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    mov     rcx, qword ptr [rbp-16]           ; draw the field cards on the erased bg
    mov     rdx, qword ptr [rbp-8]
    call    gui_draw_field_cards
    mov     rcx, qword ptr [rbp-16]           ; ...or the home panel, when the detail
    mov     rdx, qword ptr [rbp-8]            ;   pane has nothing to show
    call    gui_draw_home
    mov     eax, 1
    jmp     vp_ret
vp_tdraw:
    mov     r10, r9
    cmp     dword ptr [r10+0], 1              ; ODT_MENU -> themed owner-draw menu item
    je      vp_tdraw_menu
    mov     eax, dword ptr [r10+4]            ; DRAWITEMSTRUCT.CtlID
    cmp     eax, IDC_V_MTPM                   ; the TPM control = Fluent pill toggle
    je      vp_tdraw_toggle
    cmp     eax, IDC_V_MNOHIST               ; the two privacy pill toggles
    je      vp_tdraw_tnohist
    cmp     eax, IDC_V_MNOPHON
    je      vp_tdraw_tnophon
    cmp     eax, IDC_V_MSECD                  ; secure-desktop entry toggle
    je      vp_tdraw_tsecd
    cmp     eax, IDC_V_MWLK                   ; lock-with-Windows toggle
    je      vp_tdraw_twlk
    cmp     eax, IDC_V_MNOPREV               ; disable-attachment-preview toggle
    je      vp_tdraw_tnoprev
    cmp     eax, IDC_V_LIST                   ; single-vault entry-card painter
    je      vp_tdraw_list
    cmp     eax, IDC_V_HEADER                 ; detail-pane header (tile + title)
    je      vp_tdraw_header
    cmp     eax, IDC_V_ICON                   ; edit-mode icon tile before the title
    je      vp_tdraw_icon
    cmp     eax, IDC_V_COLORPW                ; revealed-secret colour overlay
    je      vp_tdraw_colorpw
    cmp     eax, IDC_DYN_BASE                 ; a runtime row's TOTP drain bar?
    jb      vp_tdraw_def
    mov     edx, eax
    sub     edx, IDC_DYN_BASE
    and     edx, DYN_SLOTS-1                  ; slot = (id-base) mod 8
    cmp     edx, DS_TBAR
    je      vp_tdraw_totp
    cmp     edx, DS_SBADGE
    je      vp_tdraw_sbadge
    cmp     edx, DS_VALUE                    ; attachment tile's owner-draw tag list
    je      vp_tdraw_taglist
    cmp     edx, DS_UP
    je      vp_tdraw_chev
    cmp     edx, DS_DOWN
    je      vp_tdraw_chev
    jmp     vp_tdraw_def
vp_tdraw_header:
    mov     rcx, r9
    call    gui_draw_header
    mov     eax, 1
    jmp     vp_ret
vp_tdraw_icon:
    mov     rcx, r9
    call    gui_draw_iconbtn
    mov     eax, 1
    jmp     vp_ret
vp_tdraw_colorpw:
    mov     rcx, r9
    call    gui_draw_rowcolor
    mov     eax, 1
    jmp     vp_ret
vp_tdraw_sbadge:
    mov     rcx, r9
    call    gui_draw_sbadge
    mov     eax, 1
    jmp     vp_ret
vp_tdraw_taglist:
    mov     rcx, r9
    call    gui_draw_taglist
    mov     eax, 1
    jmp     vp_ret
vp_tdraw_chev:
    mov     rcx, r9
    call    gui_draw_flatchevron
    mov     eax, 1
    jmp     vp_ret
vp_tdraw_toggle:
    mov     rcx, r9
    mov     edx, dword ptr [g_tpm_want]
    call    theme_toggle
    jmp     vp_ret
vp_tdraw_tnohist:
    mov     rcx, r9
    mov     edx, dword ptr [g_no_history]
    call    theme_toggle
    jmp     vp_ret
vp_tdraw_tnophon:
    mov     rcx, r9
    mov     edx, dword ptr [g_no_phonetic]
    call    theme_toggle
    jmp     vp_ret
vp_tdraw_tsecd:
    mov     rcx, r9
    mov     edx, dword ptr [g_secunlock]
    call    theme_toggle
    jmp     vp_ret
vp_tdraw_twlk:
    mov     rcx, r9
    mov     edx, dword ptr [g_winlock]
    call    theme_toggle
    jmp     vp_ret
vp_tdraw_tnoprev:
    mov     rcx, r9
    mov     edx, dword ptr [g_nopreview]
    call    theme_toggle
    jmp     vp_ret
vp_tdraw_totp:
    mov     rcx, r9
    mov     edx, dword ptr [g_totp_secs]
    mov     r8d, IDC_V_TOTP_WINDOW
    call    theme_progressbar
    jmp     vp_ret
vp_tdraw_def:
    mov     rcx, r9
    call    theme_drawitem
    jmp     vp_ret
vp_timer_clip:
    cmp     r8d, CLIP_TIMER
    je      vp_t_clip
    cmp     r8d, TOTP_TIMER
    je      vp_t_totp
    cmp     r8d, SEARCH_TIMER
    je      vp_t_search
    cmp     r8d, IDLE_TIMER
    je      vp_t_idle
    jmp     vp_unhandled
vp_wts:
    cmp     r8d, WTS_SESSION_LOCK             ; only the lock event matters
    jne     vp_handled
    cmp     dword ptr [g_winlock], 0          ; setting off -> ignore
    je      vp_handled
    jmp     vp_lock
vp_t_idle:
    mov     rcx, qword ptr [rbp-8]            ; C8.4: refresh if the vault changed on disk
    call    gui_check_refresh                ;   and we have no unsaved edit (silent)
    cmp     dword ptr [g_idle_min], 0         ; auto-lock: setting turned off since arming
    je      vp_handled
    sub     rsp, 32                           ; one of OUR modal popups active?
    call    GetActiveWindow                   ;   (thread-local; NULL if another app
    add     rsp, 32                           ;    has focus - locking then is fine)
    test    rax, rax
    jz      @F
    cmp     rax, qword ptr [rbp-8]
    jne     vp_handled                        ; modal child up -> skip this tick
@@: mov     dword ptr [rbp-32], 8             ; LASTINPUTINFO { cbSize=8, dwTime }
    sub     rsp, 32
    lea     rcx, [rbp-32]
    call    GetLastInputInfo
    add     rsp, 32
    test    eax, eax
    jz      vp_handled
    sub     rsp, 32
    call    GetTickCount
    add     rsp, 32
    sub     eax, dword ptr [rbp-28]           ; idle ms (wrap-safe unsigned diff)
    mov     ecx, dword ptr [g_idle_min]
    imul    ecx, ecx, 60000                   ; minutes -> ms
    cmp     eax, ecx
    jb      vp_handled
    jmp     vp_lock                           ; idle long enough -> lock the vault
vp_t_clip:
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, CLIP_TIMER
    call    KillTimer
    add     rsp, 32
    call    gui_clipclear
    jmp     vp_handled
vp_t_totp:
    mov     rcx, qword ptr [rbp-8]
    call    gui_totp_refresh
    jmp     vp_handled
vp_t_search:
    sub     rsp, 32                           ; debounce elapsed -> one-shot: stop then refilter
    mov     rcx, qword ptr [rbp-8]
    mov     edx, SEARCH_TIMER
    call    KillTimer
    add     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    call    gui_poplist
    jmp     vp_handled
vp_init:
    mov     rax, qword ptr [rbp-8]            ; remember the window for the tray toggle
    mov     qword ptr [g_vaulthwnd], rax
    WINCALL GetFileAttributesW, addr g_vpath  ; C8.5: a read-only vault FILE forces
    cmp     eax, -1                           ; read-only mode (it can't be written anyway)
    je      @F
    test    eax, 1                            ; FILE_ATTRIBUTE_READONLY
    jz      @F
    mov     dword ptr [g_readonly], 1
@@:
    lea     rax, [g_vault_title]                        ; E9: " (read-only)" title suffix
    cmp     dword ptr [g_readonly], 0
    je      @F
    lea     rax, [g_vault_title_ro]
@@:
    WINCALL SetWindowTextW, qword ptr [rbp-8], rax  ; taskbar/Alt-Tab (FindWindow still keys on g_vault_title)
    cmp     dword ptr [g_seclock_failed], 0   ; C3: one-time "secrets not pinned to RAM" warning
    je      @F
    cmp     dword ptr [g_seclock_warned], 0
    jne     @F
    mov     dword ptr [g_seclock_warned], 1
    mov     rcx, qword ptr [rbp-8]
    call    gui_seclock_warn
@@:
    WINCALL DragAcceptFiles, qword ptr [rbp-8], 1   ; accept Explorer file drops
    mov     rcx, qword ptr [rbp-8]           ; Vordr shield in the title bar
    call    gui_set_winicon
    call    gui_make_listfonts               ; entry-list icon/title/subtitle fonts
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_V_SAVE                   ; Save is the accent/primary (default) button
    call    theme_attach
    WINCALL SendMessageW, qword ptr [rbp-8], WM_GETFONT, 0, 0   ; font for runtime ctls
    mov     qword ptr [g_dlgfont], rax
    mov     dword ptr [g_field_count], 0
    mov     dword ptr [g_menu_open], 0
    WINCALL CreateDialogParamW, qword ptr [g_hinst], DLG_SETTINGS, qword ptr [rbp-8],             addr settings_proc, 0             ; the settings screen, created hidden
    mov     qword ptr [g_settings_hwnd], rax
    mov     rcx, qword ptr [rbp-8]           ; every child must clip its siblings, or they
    call    gui_clip_children                ;   repaint straight over the settings child
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_ADD, addr wb_add
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_EDIT, addr wb_edit
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_REMOVE, addr wb_rem
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_OVFL, addr wb_more
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_FAV, addr wb_star
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_HDREDIT, addr wb_edit
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_V_OVFL   ; header "..." -> frameless ghost
    mov     rcx, qword ptr [rbp-8]
    mov     rdx, rax
    mov     r8d, GLY_MORE
    lea     r9, [gt_more]
    call    ghost_attach
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_V_FAV    ; header favorite -> frameless ghost
    mov     rcx, qword ptr [rbp-8]                       ;   (dynamic glyph via ghost_set_glyph)
    mov     rdx, rax
    mov     r8d, GLY_FAV_OFF
    lea     r9, [gt_fav]
    call    ghost_attach
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_V_HDREDIT ; header edit -> frameless ghost (D1 dock)
    mov     rcx, qword ptr [rbp-8]
    mov     rdx, rax
    mov     r8d, GLY_EDIT
    lea     r9, [gt_edit]
    call    ghost_attach
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_V_PGPREV  ; pagination arrows -> frameless ghosts
    mov     rcx, qword ptr [rbp-8]
    mov     rdx, rax
    mov     r8d, 0E76Bh                                  ; ChevronLeft
    lea     r9, [gt_pgprev]
    call    ghost_attach
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_V_PGNEXT
    mov     rcx, qword ptr [rbp-8]
    mov     rdx, rax
    mov     r8d, 0E76Ch                                  ; ChevronRight
    lea     r9, [gt_pgnext]
    call    ghost_attach
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_V_ADD     ; sidebar toolbar -> frameless ghosts
    mov     rcx, qword ptr [rbp-8]
    mov     rdx, rax
    mov     r8d, GLY_NEW
    lea     r9, [gt_new]
    call    ghost_attach
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_V_EDIT
    mov     rcx, qword ptr [rbp-8]
    mov     rdx, rax
    mov     r8d, GLY_EDIT
    lea     r9, [gt_edit]
    call    ghost_attach
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_V_REMOVE
    mov     rcx, qword ptr [rbp-8]
    mov     rdx, rax
    mov     r8d, GLY_DELETE
    lea     r9, [gt_rem]
    call    ghost_attach
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_V_GENERATE ; sidebar dock: generate -> ghost
    mov     rcx, qword ptr [rbp-8]
    mov     rdx, rax
    mov     r8d, GLY_GENERATE
    lea     r9, [gt_gen]
    call    ghost_attach
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_V_LIST    ; type-to-search: keystrokes on
    WINCALL SetWindowSubclass, rax, addr search_type_subclass, 0, 0   ;  the list -> search box
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_V_SEARCH, EM_SETCUEBANNER, 1, addr cue_search
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_V_TITLE, EM_LIMITTEXT, CONVW_MAX-1, 0
    mov     dword ptr [g_trash_view], 0       ; start in the vault (not the trash) view
    mov     dword ptr [g_deleted_state], 0
    call    gui_purge_trash                   ; drop entries trashed > 30 days ago
    call    gui_load_prefs                    ; apply persisted color scheme + layout
    mov     rcx, qword ptr [rbp-8]
    call    gui_apply_scheme
    mov     rcx, qword ptr [rbp-8]
    call    gui_apply_layout
    mov     dword ptr [g_cur_idx], -1         ; no entry selected yet
    mov     dword ptr [g_colorpw_row], -1
    mov     dword ptr [g_dirty], 0
    mov     dword ptr [g_loading], 0
    mov     rcx, qword ptr [rbp-8]
    call    gui_poplist
    mov     rcx, qword ptr [rbp-8]            ; start in view mode (fields locked)
    xor     edx, edx
    call    gui_set_editmode
    cmp     dword ptr [g_readonly], 0         ; E9: grey out mutation buttons if read-only
    je      @F
    mov     rcx, qword ptr [rbp-8]
    call    gui_ro_disable_btns
@@:
    ; auto-lock: Win+L notifications (gated by g_winlock on receipt) + idle poll
    WINCALL WTSRegisterSessionNotification, qword ptr [rbp-8], 0  ; NOTIFY_FOR_THIS_SESSION
    WINCALL SetTimer, qword ptr [rbp-8], IDLE_TIMER, IDLE_POLL_MS, 0  ; poll: auto-lock + C8.4 refresh
    sub     rsp, 32                          ; foreground the window so keystrokes land
    mov     rcx, qword ptr [rbp-8]            ;   here (launched from the tray, it is
    call    SetForegroundWindow              ;   otherwise visible but not active)
    add     rsp, 32
    mov     rcx, qword ptr [rbp-8]            ; the entry list takes focus on show
    mov     edx, IDC_V_LIST                   ;   (type-to-search opens the overlay)
    call    GetDlgItem
    sub     rsp, 32
    mov     rcx, rax
    call    SetFocus
    add     rsp, 32
    mov     rcx, qword ptr [rbp-8]            ; custom frame: shift content below the strip,
    call    frame_shift                       ;   grow to preserve size, then build the strip
    mov     rcx, qword ptr [rbp-8]
    call    frame_grow
    mov     rcx, qword ptr [rbp-8]
    call    frame_build
    mov     rcx, qword ptr [rbp-8]            ; record control rects for responsive resize
    call    gui_anchor_init
    mov     rcx, qword ptr [rbp-8]            ; edge-dock the glyphs/buttons for the initial size
    call    gui_cmd_dock_layout
    mov     rcx, qword ptr [rbp-8]            ; fit the entry list inside the sidebar frame
    call    sidebar_layout
    xor     eax, eax                          ; we set focus ourselves -> return FALSE
    jmp     vp_ret
vp_cmd:
    movzx   eax, r8w                        ; control id
    mov     r10d, r8d
    shr     r10d, 16                        ; notification code
    cmp     r10d, EN_SETFOCUS               ; focus moved -> redraw Fluent underlines
    je      vp_focusin
    cmp     r10d, EN_KILLFOCUS
    je      vp_refocus
    cmp     r10d, EN_CHANGE                 ; inline edit changed -> mark dirty
    jne     vp_cmd_disp
    cmp     eax, IDC_V_SEARCH                 ; query changed -> re-filter the list
    je      vp_searchchg
    cmp     eax, IDC_V_TITLE
    je      vp_setdirty
    cmp     eax, IDC_DYN_BASE                 ; any runtime row value/label edit
    jae     vp_setdirty
vp_cmd_disp:
    cmp     eax, IDC_DYN_BASE                 ; runtime row control (button OR edit)?
    jb      vp_cmd_fixed
    test    r10d, r10d                        ; act ONLY on a real click (BN/STN_CLICKED=0);
    jnz     vp_handled                        ;   an edit's stray notifs (EN_UPDATE, EN_MAXTEXT,
    jmp     vp_dyn                            ;   ...) must never fire a row button action
vp_cmd_fixed:
    cmp     eax, IDC_T_CLOSE                  ; custom caption button (only Close remains)
    je      vp_close
    cmp     eax, IDC_T_NEW                    ; title-bar control dock
    je      vp_add
    cmp     eax, IDC_T_GEN
    je      vp_gen_standalone
    cmp     eax, IDC_T_SET
    je      vp_menu
    cmp     eax, IDC_V_LIST
    je      vp_list
    cmp     eax, IDC_V_ADDFIELD
    je      vp_addfield
    cmp     eax, IDC_V_PGPREV
    je      vp_pgprev
    cmp     eax, IDC_V_PGNEXT
    je      vp_pgnext
    cmp     eax, IDC_V_ADD
    je      vp_add
    cmp     eax, IDC_V_GENERATE
    je      vp_gen_standalone
    cmp     eax, IDC_V_EDIT
    je      vp_edit
    cmp     eax, IDC_V_HDREDIT                    ; header command-dock edit button
    je      vp_edit
    cmp     eax, IDC_V_SAVE
    je      vp_save
    cmp     eax, IDC_V_CANCEL
    je      ve_save                           ; discard edits, back to view mode
    cmp     eax, IDC_V_REMOVE
    je      vp_remove
    cmp     eax, IDC_V_DONE
    je      vp_done
    cmp     eax, IDC_V_LOCK                   ; no Lock button, but Ctrl+L still posts this
    je      vp_lock
    cmp     eax, IDC_V_MTHEME
    je      vp_theme
    cmp     eax, IDC_V_MHOTK
    je      vp_hotkey
    cmp     eax, IDC_V_MEXPORT
    je      vp_export
    cmp     eax, IDC_V_MIMPORT
    je      vp_import
    cmp     eax, IDC_V_OVFL
    je      vp_ovfl
    cmp     eax, IDC_V_FAV
    je      vp_fav
    cmp     eax, IDC_V_ICON                      ; edit-mode icon button -> picker
    je      vp_iconpick
    cmp     eax, IDC_V_MTPMINFO
    je      vp_tpminfo
    cmp     eax, IDC_V_MTPM
    je      vp_mtpm
    cmp     eax, IDC_V_MNOHIST
    je      vp_mnohist
    cmp     eax, IDC_V_MNOPHON
    je      vp_mnophon
    cmp     eax, IDC_V_MSECD
    je      vp_msecd
    cmp     eax, IDC_V_MSECINFO
    je      vp_msecinfo
    cmp     eax, IDC_V_MWLK
    je      vp_mwlk
    cmp     eax, IDC_V_MNOPREV
    je      vp_mnoprev
    cmp     eax, IDC_V_MNOPREVINFO
    je      vp_mnoprevinfo
    cmp     eax, IDCANCEL
    je      vp_esc
    xor     eax, eax
    jmp     vp_ret
vp_esc:
    cmp     dword ptr [g_new_pending], 0     ; Escape on a just-added placeholder
    jne     ve_discard_new                   ;   discards it rather than locking
    jmp     vp_lock
vp_mtpm:
    cmp     dword ptr [g_tpm_present], 0       ; disabled with no TPM hardware
    je      vp_handled
    cmp     dword ptr [g_tpm_lock], 0          ; HKLM-locked -> ignore the click
    jne     vp_handled
    mov     eax, dword ptr [g_tpm_want]
    xor     eax, 1
    mov     dword ptr [g_tpm_want], eax
    mov     ecx, IDC_V_MTPM                ; repaint the toggle in the settings child
    call    gui_inval_setting
    jmp     vp_handled
vp_mwlk:
    cmp     dword ptr [g_winlock_lock], 0     ; HKLM-locked -> ignore the click
    jne     vp_handled
    mov     eax, dword ptr [g_winlock]
    xor     eax, 1
    mov     dword ptr [g_winlock], eax
    mov     ecx, IDC_V_MWLK                ; repaint the toggle in the settings child
    call    gui_inval_setting
    jmp     vp_handled
vp_mnoprev:
    cmp     dword ptr [g_nopreview_lock], 0   ; HKLM-locked -> ignore the click
    jne     vp_handled
    mov     eax, dword ptr [g_nopreview]
    xor     eax, 1
    mov     dword ptr [g_nopreview], eax
    mov     ecx, IDC_V_MNOPREV                ; repaint the toggle in the settings child
    call    gui_inval_setting
    jmp     vp_handled
vp_mnohist:
    cmp     dword ptr [g_nohist_lock], 0      ; HKLM-locked -> ignore the click
    jne     vp_handled
    mov     eax, dword ptr [g_no_history]
    xor     eax, 1
    mov     dword ptr [g_no_history], eax
    mov     ecx, IDC_V_MNOHIST                ; repaint the toggle in the settings child
    call    gui_inval_setting
    jmp     vp_handled
vp_mnophon:
    cmp     dword ptr [g_nophon_lock], 0
    jne     vp_handled
    mov     eax, dword ptr [g_no_phonetic]
    xor     eax, 1
    mov     dword ptr [g_no_phonetic], eax
    mov     ecx, IDC_V_MNOPHON                ; repaint the toggle in the settings child
    call    gui_inval_setting
    jmp     vp_handled
vp_msecd:
    cmp     dword ptr [g_secunlock_lock], 0    ; HKLM-locked -> ignore the click
    jne     vp_handled
    mov     eax, dword ptr [g_secunlock]
    xor     eax, 1
    mov     dword ptr [g_secunlock], eax
    mov     ecx, IDC_V_MSECD                ; repaint the toggle in the settings child
    call    gui_inval_setting
    jmp     vp_handled
vp_msecinfo:
    WINCALL gui_msgbox, qword ptr [rbp-8], addr m_msecinfo, addr t_msecinfo, \
            <MB_OK or MB_ICONINFORMATION>
    jmp     vp_handled

vp_setdirty:
    cmp     dword ptr [g_loading], 0          ; ignore programmatic field loads
    jne     vp_handled
    mov     dword ptr [g_dirty], 1
    jmp     vp_handled
vp_searchchg:
    call    vault_count                       ; big list -> debounce; small list -> live
    cmp     eax, SEARCH_DEBOUNCE_MIN
    jbe     vp_search_now
    ; (re)arm a one-shot timer; SetTimer with the same id resets the interval, so a
    ; run of fast keystrokes keeps pushing the refilter out until the user pauses 0.3 s.
    WINCALL SetTimer, qword ptr [rbp-8], SEARCH_TIMER, SEARCH_MS, 0
    jmp     vp_handled
vp_search_now:
    mov     rcx, qword ptr [rbp-8]            ; refilter the entry list immediately
    call    gui_poplist
    jmp     vp_handled
vp_focusin:
    cmp     dword ptr [g_editmode], 0
    jne     vp_refocus                          ; edit mode: field is being edited
    ; view mode: suppress the blinking caret on the read-only detail edits (the
    ; search box, id < IDC_DYN_BASE and not the title, keeps its caret)
    mov     dword ptr [rbp-16], eax             ; save ctrl id
    cmp     eax, IDC_DYN_BASE
    jae     vpf_hidecaret
    cmp     eax, IDC_V_TITLE
    jne     vpf_caretdone
vpf_hidecaret:
    WINCALL HideCaret, r9                        ; r9 = focused control
vpf_caretdone:
    mov     eax, dword ptr [rbp-16]
    ; a genuine mouse click on a view-mode URL value opens it in the browser
    cmp     eax, IDC_DYN_BASE
    jb      vp_refocus
    mov     ecx, eax
    sub     ecx, IDC_DYN_BASE
    mov     r10d, ecx
    and     r10d, DYN_SLOTS-1                    ; slot
    cmp     r10d, DS_VALUE
    jne     vp_refocus
    shr     ecx, DYN_SLOTS_LOG2                  ; row
    mov     dword ptr [rbp-16], ecx
    call    gui_desc                             ; ecx=row -> rax=descriptor
    cmp     dword ptr [rax+FD_KIND], VF_URL
    jne     vp_refocus
    WINCALL GetKeyState, 1                        ; VK_LBUTTON: focus from a click, not a tab?
    test    ax, ax
    jns     vp_refocus                          ; high bit clear -> keyboard focus, ignore
    mov     rcx, qword ptr [rbp-8]
    mov     edx, dword ptr [rbp-16]
    call    gui_url_open
vp_refocus:
    WINCALL InvalidateRect, qword ptr [rbp-8], 0, 1
    jmp     vp_handled
vp_menu:
    mov     rcx, qword ptr [rbp-8]
    call    gui_menu_toggle
    jmp     vp_handled
vp_theme:
    mov     eax, dword ptr [g_scheme]            ; cycle color scheme
    inc     eax
    cmp     eax, GUI_SCHEME_COUNT
    jb      @F
    xor     eax, eax
@@: mov     dword ptr [g_scheme], eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_apply_scheme
    call    gui_save_prefs
    jmp     vp_handled
vp_hotkey:
    mov     rcx, qword ptr [rbp-8]               ; capture + rebind the summon hotkey
    call    gui_hotkey_capture
    jmp     vp_handled
vp_export:
    mov     rcx, qword ptr [rbp-8]
    call    gui_export
    jmp     vp_handled
vp_import:
    cmp     dword ptr [g_readonly], 0           ; E9: no import in read-only mode
    jne     vp_handled
    mov     rcx, qword ptr [rbp-8]
    call    gui_import
    jmp     vp_handled
vp_mnoprevinfo:
    WINCALL gui_msgbox, qword ptr [rbp-8], addr m_noprevinfo, addr t_noprevinfo, \
            <MB_OK or MB_ICONINFORMATION>
    jmp     vp_handled
vp_ovfl:                                        ; menu opens even with no entry shown
    mov     rcx, qword ptr [rbp-8]               ; (so "Recover items" stays reachable)
    call    gui_overflow_menu
    jmp     vp_handled
vp_iconpick:
    cmp     dword ptr [g_cur_idx], 0             ; only with an entry shown (edit mode only)
    jl      vp_handled
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_ICON, qword ptr [rbp-8], addr icon_proc, 0
    cmp     eax, 1
    jne     vp_handled
    mov     rcx, qword ptr [rbp-8]               ; repaint the icon button with the new glyph
    mov     edx, IDC_V_ICON
    call    GetDlgItem
    sub     rsp, 32
    mov     rcx, rax
    xor     edx, edx
    mov     r8d, 1
    call    InvalidateRect
    add     rsp, 32
    mov     dword ptr [g_dirty], 1               ; applied on Save
    jmp     vp_handled
vp_fav:
    cmp     dword ptr [g_readonly], 0           ; E9: no favorite/restore in read-only
    jne     vp_handled
    cmp     dword ptr [g_cur_idx], 0             ; only with an entry shown
    jl      vp_handled
    cmp     dword ptr [g_trash_view], 0          ; recover mode: the button restores
    je      vp_fav_toggle
    mov     rcx, qword ptr [rbp-8]
    mov     edx, dword ptr [g_cur_idx]
    call    gui_restore_entry
    jmp     vp_handled
vp_fav_toggle:
    mov     eax, dword ptr [g_fav_state]         ; toggle favorite
    xor     eax, 1
    mov     dword ptr [g_fav_state], eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_update_fav_glyph
    mov     rcx, qword ptr [rbp-8]               ; persist immediately
    call    gui_commit
    jmp     vp_handled
vp_tpminfo:
    WINCALL gui_msgbox, qword ptr [rbp-8], addr m_tpminfo, addr t_tpminfo, \
            <MB_OK or MB_ICONINFORMATION>
    jmp     vp_handled
vp_list:
    cmp     r10d, LBN_SELCHANGE
    jne     vp_unhandled
    mov     rcx, qword ptr [rbp-8]
    call    gui_lb_seldata                   ; B = clicked row's vault index (item data)
    cmp     eax, LB_ERR
    je      vp_handled
    mov     dword ptr [rbp-16], eax          ; B = newly clicked vault index
    ; switching entries discards any unsaved inline edits (edits are only
    ; persisted by an explicit Save)
    mov     dword ptr [g_dirty], 0
    ; recover mode: a click on the row's recycle glyph restores that entry
    cmp     dword ptr [g_trash_view], 0
    je      vl_load
    mov     rcx, qword ptr [rbp-8]
    call    gui_trash_glyph_hit
    test    eax, eax
    jz      vl_load
    mov     rcx, qword ptr [rbp-8]
    mov     edx, dword ptr [rbp-16]
    call    gui_restore_entry
    jmp     vp_handled
vl_load:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, dword ptr [rbp-16]
    call    gui_showdetail
    mov     rcx, qword ptr [rbp-8]            ; viewing another record -> view mode
    xor     edx, edx
    call    gui_set_editmode
    jmp     vp_handled
vp_addfield:
    mov     rcx, qword ptr [rbp-8]
    call    gui_addfield_menu
    jmp     vp_handled
vp_pgprev:
    cmp     dword ptr [g_cur_page], 0
    jle     vp_handled
    dec     dword ptr [g_cur_page]
    mov     rcx, qword ptr [rbp-8]
    call    gui_rows_layout
    jmp     vp_handled
vp_pgnext:
    mov     eax, dword ptr [g_cur_page]
    inc     eax
    cmp     eax, dword ptr [g_page_count]
    jge     vp_handled
    mov     dword ptr [g_cur_page], eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_rows_layout
    jmp     vp_handled
vp_dyn:
    ; eax = control id of a runtime row button; decode row + slot
    sub     eax, IDC_DYN_BASE
    mov     ecx, eax
    and     ecx, DYN_SLOTS-1                  ; slot
    shr     eax, DYN_SLOTS_LOG2               ; row
    cmp     ecx, DS_REVEAL
    je      vpd_reveal
    cmp     ecx, DS_UP
    je      vpd_up
    cmp     ecx, DS_DOWN
    je      vpd_down
    cmp     ecx, DS_DEL
    je      vpd_del
    cmp     ecx, DS_COPY
    je      vpd_copy
    cmp     ecx, DS_IMPORT
    je      vpd_import
    cmp     ecx, DS_VALUE                       ; attachments tile: click a tag
    je      vpd_tagclick
    cmp     ecx, DS_GEN
    je      vpd_gen
    jmp     vp_handled
vpd_import:
    ; Choose: append one or more files to the attachments tile
    mov     edx, eax                            ; row
    mov     rcx, qword ptr [rbp-8]
    call    gui_tile_choose
    jmp     vp_handled
vpd_tagclick:
    ; a tag was clicked: open that file, or (edit mode) remove it via the x
    mov     edx, eax                            ; row
    mov     rcx, qword ptr [rbp-8]
    call    gui_tag_click
    jmp     vp_handled
vpd_copy:
    mov     edx, eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_row_copy
    jmp     vp_handled
vpd_gen:
    mov     dword ptr [g_pg_target], eax        ; clicked secret row
    cmp     dword ptr [g_pg_len], 0              ; first open -> sticky defaults
    jne     @F
    mov     dword ptr [g_pg_len], 16
    mov     dword ptr [g_pg_style], 0
    mov     dword ptr [g_pg_opt], PWCLASS_U or PWCLASS_L or PWCLASS_D
@@: WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_PWGEN, qword ptr [rbp-8], addr pwgen_proc, 0
    jmp     vp_handled
vpd_reveal:
    mov     edx, eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_row_reveal
    jmp     vp_handled
vpd_up:
    mov     edx, eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_row_moveup
    jmp     vp_handled
vpd_down:
    mov     edx, eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_row_movedown
    jmp     vp_handled
vpd_del:
    mov     edx, eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_row_delete
    jmp     vp_handled
vp_gen_standalone:
    ; sidebar dock: open the password generator with no target field (standalone)
    mov     dword ptr [g_pg_target], -1
    cmp     dword ptr [g_pg_len], 0
    jne     @F
    mov     dword ptr [g_pg_len], 16
    mov     dword ptr [g_pg_style], 0
    mov     dword ptr [g_pg_opt], PWCLASS_U or PWCLASS_L or PWCLASS_D
@@: WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_PWGEN, qword ptr [rbp-8], addr pwgen_proc, 0
    jmp     vp_handled
vp_add:
    cmp     dword ptr [g_readonly], 0           ; E9: no new entry in read-only mode
    jne     vp_handled
    ; adding a new entry discards any unsaved inline edits to the current one
    ; (edits are only persisted by an explicit Save)
    mov     dword ptr [g_dirty], 0
    mov     rcx, qword ptr [rbp-8]            ; choose a template (Login/Card/Identity/Note)
    call    gui_pick_template
    cmp     eax, -1
    je      vp_handled                       ; menu cancelled -> no new entry
    mov     edx, eax                         ; build the field list from the template
    call    gui_build_template
va_build:
    call    vault_build_entry
    test    eax, eax
    jnz     vp_handled
    call    vault_reseal
    mov     rcx, qword ptr [rbp-8]
    call    gui_poplist
    call    vault_last_user                   ; NOT count-1 (see gui_commit)
    cmp     eax, 0
    jl      vp_handled
    mov     dword ptr [g_cur_idx], eax
    mov     rcx, qword ptr [rbp-8]            ; reselect by vault index (list is sorted)
    mov     edx, dword ptr [g_cur_idx]
    call    gui_lb_selbydata
    mov     rcx, qword ptr [rbp-8]
    mov     edx, dword ptr [g_cur_idx]
    call    gui_showdetail
    mov     dword ptr [g_new_pending], 1     ; mark as a placeholder: Cancel deletes it
    mov     rcx, qword ptr [rbp-8]            ; new entry opens straight into edit mode
    mov     edx, 1
    call    gui_set_editmode
    mov     rcx, qword ptr [rbp-8]            ; focus the title for quick typing
    mov     edx, IDC_V_TITLE
    call    GetDlgItem
    sub     rsp, 32
    mov     rcx, rax
    call    SetFocus
    add     rsp, 32
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_V_TITLE, EM_SETSEL, 0, -1
    jmp     vp_handled
vp_edit:
    ; pencil toggles edit mode: enter (make fields editable) or discard + leave
    ; (edits are only persisted by an explicit Save)
    cmp     dword ptr [g_editmode], 0
    jne     ve_save
    cmp     dword ptr [g_cur_idx], 0
    jl      vp_handled                       ; nothing selected -> nothing to edit
    mov     rcx, qword ptr [rbp-8]
    mov     edx, 1
    call    gui_set_editmode
    mov     rcx, qword ptr [rbp-8]            ; focus the title for editing
    mov     edx, IDC_V_TITLE
    call    GetDlgItem
    sub     rsp, 32
    mov     rcx, rax
    call    SetFocus
    add     rsp, 32
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_V_TITLE, EM_SETSEL, 0, -1
    jmp     vp_handled
ve_save:
    ; Cancel / pencil-off: discard any unsaved inline edits (edits are only
    ; persisted by an explicit Save) and return to view mode.
    mov     dword ptr [g_dirty], 0
    cmp     dword ptr [g_new_pending], 0     ; cancelling a just-added placeholder?
    jne     ve_discard_new                   ;   -> delete it instead of reloading
    cmp     dword ptr [g_cur_idx], 0
    jl      ve_view
    mov     rcx, qword ptr [rbp-8]           ; reload the entry from the vault (drops edits)
    mov     edx, dword ptr [g_cur_idx]
    call    gui_showdetail
ve_view:
    mov     rcx, qword ptr [rbp-8]           ; ...then apply view-mode read-only + layout
    xor     edx, edx
    call    gui_set_editmode
    jmp     vp_handled
ve_discard_new:
    ; the user cancelled straight out of a freshly-added entry: delete the
    ; "New entry" placeholder rather than leaving an empty record behind.
    mov     dword ptr [g_new_pending], 0
    mov     ecx, dword ptr [g_cur_idx]
    call    vault_remove_at
    call    vault_reseal
    mov     rcx, qword ptr [rbp-8]
    call    gui_poplist
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_TITLE, 0
    mov     rcx, qword ptr [rbp-8]           ; tear down the detail rows
    call    gui_rows_clear
    mov     dword ptr [g_totp_on], 0         ; stop any live auth-code refresh
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, TOTP_TIMER
    call    KillTimer
    add     rsp, 32
    mov     dword ptr [g_cur_idx], -1
    mov     rcx, qword ptr [rbp-8]           ; back to view mode
    xor     edx, edx
    call    gui_set_editmode
    jmp     vp_handled
vp_save:
    ; Enter while typing in the search box (default-button command, focus in
    ; search) copies the top record's first password instead of saving.
    call    GetFocus
    mov     qword ptr [rbp-24], rax
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_V_SEARCH
    call    GetDlgItem
    cmp     rax, qword ptr [rbp-24]
    jne     vp_save_real
    mov     rcx, qword ptr [rbp-8]
    call    gui_copy_topmost
    jmp     vp_handled
vp_save_real:
    ; explicit Save: commit the edits and return to view mode.  No-op outside
    ; edit mode / with nothing selected.
    cmp     dword ptr [g_editmode], 0
    je      vp_handled
    cmp     dword ptr [g_cur_idx], 0
    jl      vp_handled
    mov     dword ptr [g_new_pending], 0     ; an explicit Save keeps the entry
    mov     rcx, qword ptr [rbp-8]
    call    gui_commit
    cmp     dword ptr [g_cur_idx], 0
    jl      vsr_view
    mov     rcx, qword ptr [rbp-8]            ; rebuild the rows first...
    mov     edx, dword ptr [g_cur_idx]
    call    gui_showdetail
vsr_view:
    mov     rcx, qword ptr [rbp-8]            ; ...then apply view-mode read-only + layout
    xor     edx, edx
    call    gui_set_editmode
    jmp     vp_handled
vp_remove:
    cmp     dword ptr [g_readonly], 0           ; E9: no delete in read-only mode
    jne     vp_handled
    cmp     dword ptr [g_cur_idx], 0
    jl      vp_handled
    cmp     dword ptr [g_trash_view], 0
    jne     vpr_forever                      ; already in trash -> permanent delete
    WINCALL gui_msgbox, qword ptr [rbp-8], addr t_trash, addr t_err, <MB_YESNO or MB_ICONQUESTION>
    cmp     eax, IDYES
    jne     vp_handled
    mov     dword ptr [g_deleted_state], 1   ; soft-delete: mark VF_DELETED + reseal
    call    gui_set_deleted_now
    mov     rcx, qword ptr [rbp-8]
    call    gui_commit
    jmp     vpr_teardown
vpr_forever:
    WINCALL gui_msgbox, qword ptr [rbp-8], addr t_delforever, addr t_err, <MB_YESNO or MB_ICONWARNING>
    cmp     eax, IDYES
    jne     vp_handled
    mov     ecx, dword ptr [g_cur_idx]
    call    vault_remove_at
    call    vault_reseal
vpr_teardown:
    mov     rcx, qword ptr [rbp-8]
    call    gui_poplist
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_TITLE, 0
    mov     rcx, qword ptr [rbp-8]            ; tear down the detail rows
    call    gui_rows_clear
    mov     dword ptr [g_totp_on], 0          ; stop the live auth-code refresh
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, TOTP_TIMER
    call    KillTimer
    add     rsp, 32
    mov     dword ptr [g_cur_idx], -1
    mov     dword ptr [g_dirty], 0
    mov     dword ptr [g_deleted_state], 0
    mov     rcx, qword ptr [rbp-8]            ; back to view mode
    xor     edx, edx
    call    gui_set_editmode
    jmp     vp_handled
vp_done:
    mov     rcx, qword ptr [rbp-8]           ; "Done" -> leave recover mode
    call    gui_leave_trash
    jmp     vp_handled
vp_lock:
vp_close:
    cmp     dword ptr [g_menu_open], 0       ; closing while settings open -> save
    je      vp_lock_dirty
    mov     rcx, qword ptr [rbp-8]
    call    gui_menu_save
vp_lock_dirty:
    mov     dword ptr [g_dirty], 0           ; locking discards unsaved inline edits
vp_lock_go:
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, CLIP_TIMER
    call    KillTimer
    mov     rcx, qword ptr [rbp-8]
    mov     edx, TOTP_TIMER
    call    KillTimer
    mov     rcx, qword ptr [rbp-8]
    mov     edx, SEARCH_TIMER               ; drop any pending debounced refilter
    call    KillTimer
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDLE_TIMER                 ; stop the auto-lock poll
    call    KillTimer
    mov     rcx, qword ptr [rbp-8]          ; window is going away
    call    WTSUnRegisterSessionNotification
    add     rsp, 32
    mov     dword ptr [g_totp_on], 0
    call    gui_temp_purge                  ; overwrite + delete any decrypt-to-temp files
    call    gui_clipclear                   ; clear the clipboard if it is still ours
    lea     rcx, [g_secret_w]               ; wipe revealed secret + TOTP material
    mov     edx, EBUF*4
    call    secure_zero
    lea     rcx, [g_totp_b32]
    mov     edx, 256
    call    secure_zero
    lea     rcx, [g_e_totp]
    mov     edx, 512
    call    secure_zero
    lea     rcx, [g_rowpw_w]                 ; revealed-row secret (if overlay was up)
    mov     edx, 512*2
    call    secure_zero
    mov     qword ptr [g_vaulthwnd], 0       ; window going away -> tray reopens it
    WINCALL EndDialog, qword ptr [rbp-8], 0
vp_handled:
    mov     eax, 1
    jmp     vp_ret
vp_unhandled:
    xor     eax, eax
vp_ret:
    mov     rsp, rbp
    pop     rbp
    ret
vault_proc endp

; =============================================================================
; gui_main - GUI front-end: unlock dialog, then the vault dialog, looping back
;   to the unlock screen when the vault is locked.
; =============================================================================
; gui_load_policy() - load the password policy into g_cfg_pwminlen /
;   g_cfg_pwminclasses (HKLM policy wins, then HKCU, then 12 / 3) and record
;   whether each came from HKLM (locked).
gui_load_policy proc frame
    FRAME_PROLOG 32
    lea     rcx, [wv_pwlen]
    mov     edx, 12
    lea     r8, [g_pol_len_lock]
    call    cfg_get_dword
    cmp     eax, 1
    jae     @F
    mov     eax, 12
@@: cmp     eax, 256
    jbe     @F
    mov     eax, 256
@@: mov     dword ptr [g_cfg_pwminlen], eax
    lea     rcx, [wv_pwcls]
    mov     edx, 3
    lea     r8, [g_pol_cls_lock]
    call    cfg_get_dword
    cmp     eax, 1
    jae     @F
    mov     eax, 3
@@: cmp     eax, 4
    jbe     @F
    mov     eax, 4
@@: mov     dword ptr [g_cfg_pwminclasses], eax
    lea     rcx, [wv_nohist]                    ; "Do not save history" (0/1; HKLM locks)
    xor     edx, edx
    lea     r8, [g_nohist_lock]
    call    cfg_get_dword
    test    eax, eax
    jz      @F
    mov     eax, 1
@@: mov     dword ptr [g_no_history], eax
    lea     rcx, [wv_nophon]                    ; "Disable phonetic reader" (0/1)
    xor     edx, edx
    lea     r8, [g_nophon_lock]
    call    cfg_get_dword
    test    eax, eax
    jz      @F
    mov     eax, 1
@@: mov     dword ptr [g_no_phonetic], eax
    lea     rcx, [wv_secunlock]                 ; "Secure unlock" (default ON; HKLM locks)
    mov     edx, 1
    lea     r8, [g_secunlock_lock]
    call    cfg_get_dword
    test    eax, eax
    jz      @F
    mov     eax, 1
@@: mov     dword ptr [g_secunlock], eax
    ; TPM Unlock: HKLM > HKCU > default ON (only meaningful with hardware).  The
    ; loaded value drives both the settings toggle AND the actual auto-unlock /
    ; new-vault enrollment, so an HKLM "TpmUnlock=0" really disables the feature.
    mov     dword ptr [g_tpm_lock], 0
    mov     dword ptr [g_tpm_want], 0
    cmp     dword ptr [g_tpm_present], 0
    je      lp_tpm_done
    WINCALL cfg_get_dword, addr wv_tpm, 1, addr g_tpm_lock
    test    eax, eax
    jz      @F
    mov     eax, 1
@@: mov     dword ptr [g_tpm_want], eax
lp_tpm_done:
    ; clipboard auto-clear timeout (seconds; HKLM > HKCU > default 20; 0 = off)
    WINCALL cfg_get_dword, addr wv_clip, 20, addr g_clip_lock
    cmp     eax, 3600                           ; clamp to [0, 3600]
    jbe     @F
    mov     eax, 3600
@@: mov     dword ptr [g_clip_secs], eax
    ; C9: re-verify the master password every N days under TPM Unlock
    ; (HKLM > HKCU > default 30; 0 = off)
    WINCALL cfg_get_dword, addr wv_pwdays, C9_DAYS_DEFAULT, addr g_pwdays_lock
    cmp     eax, C9_DAYS_MAX
    jbe     @F
    mov     eax, C9_DAYS_MAX
@@: mov     dword ptr [g_pwdays], eax
    ; auto-lock idle timeout (minutes; HKLM > HKCU > default 10; 0 = off)
    WINCALL cfg_get_dword, addr wv_idlemin, 10, addr g_idle_lock
    cmp     eax, 1440                           ; clamp to [0, 24 h]
    jbe     @F
    mov     eax, 1440
@@: mov     dword ptr [g_idle_min], eax
    ; lock the vault when Windows locks (0/1; HKLM > HKCU > default 1)
    WINCALL cfg_get_dword, addr wv_winlock, 1, addr g_winlock_lock
    test    eax, eax
    jz      @F
    mov     eax, 1
@@: mov     dword ptr [g_winlock], eax
    ; disable attachment preview -> download-only (0/1; HKLM > HKCU > default 0)
    WINCALL cfg_get_dword, addr wv_nopreview, 0, addr g_nopreview_lock
    test    eax, eax
    jz      @F
    mov     eax, 1
@@: mov     dword ptr [g_nopreview], eax
    FRAME_EPILOG
    ret
gui_load_policy endp

; gui_pw_match() -> eax = 1 if g_pwbuf == g_pw2buf (wide, NUL-terminated).
;   Tail-calls the constant-time gui_wstr_eq (secret-vs-secret compare).
gui_pw_match proc
    lea     rcx, [g_pwbuf]
    lea     rdx, [g_pw2buf]
    jmp     gui_wstr_eq
gui_pw_match endp

; gui_wipepw_create() - scrub both wide password buffers.
gui_wipepw_create proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_pwbuf]
    mov     edx, 1024*2
    call    secure_zero
    lea     rcx, [g_pw2buf]
    mov     edx, 1024*2
    call    secure_zero
    FRAME_EPILOG
    ret
gui_wipepw_create endp

; gui_file_exists(rcx = wide path) -> eax = 1 if the file exists, else 0.
gui_file_exists proc frame
    FRAME_PROLOG 32
    WINCALL GetFileAttributesW, rcx
    cmp     eax, -1                          ; INVALID_FILE_ATTRIBUTES
    je      gfe_no
    mov     eax, 1
    FRAME_EPILOG
    ret
gfe_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_file_exists endp

; gui_ensure_vault_dir(rcx = wide path) - make sure the directory that will hold
;   the vault exists before we try to write it.  Only cfg_default_vault created
;   the default folder; a path from the registry (or a removed folder) otherwise
;   makes do_init fail with EXIT_IO ("could not create the vault").  Creates the
;   immediate parent directory (ignoring "already exists").
; gui_ensure_vault_dir(rcx = wide path to the vault FILE) -> eax = 1 if its parent
;   directory exists (or was just created), 0 if it could not be made.
;
;   Creates EVERY missing component, and checks the outcome.  The old version made a
;   single CreateDirectoryW for the deepest folder and discarded the result, so a path
;   whose chain was missing more than one level - a vault location carried over from
;   another machine, or a %OneDrive% root that does not exist here - could never be
;   created.  Nothing noticed until the write itself failed, deep inside vault_seal_write,
;   as a bare ERROR_PATH_NOT_FOUND (3) reported as "I/O or out of memory".
gui_ensure_vault_dir proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx          ; path
    mov     r10, rcx
    xor     r8d, r8d                          ; index
    mov     r9d, -1                           ; index of last backslash
ged_scan:
    movzx   eax, word ptr [r10+r8*2]
    test    eax, eax
    jz      ged_split
    cmp     eax, 5Ch                          ; backslash
    jne     @F
    mov     r9d, r8d
@@: inc     r8d
    jmp     ged_scan
ged_split:
    cmp     r9d, 0
    jle     ged_ok                            ; no directory component (or root) -> nothing
    movsxd  r11, r9d
    mov     qword ptr [rbp-32], r11           ; index of the final separator
    ; Skip the root so we never try to create "C:" or a UNC share: start after the
    ; drive colon, or after "\\server\share" for a UNC path.
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [rbp-40], 1             ; default start index
    cmp     word ptr [r10+2], 3Ah             ; ':' at index 1  ...
    jne     @F
    cmp     word ptr [r10+4], 5Ch             ; ... and '\' at index 2 -> "X:\"
    jne     @F
    mov     qword ptr [rbp-40], 3
@@: cmp     word ptr [r10], 5Ch               ; "\\server\share\..."
    jne     ged_walk
    cmp     word ptr [r10+2], 5Ch
    jne     ged_walk
    mov     qword ptr [rbp-40], 2
ged_walk:
    ; create each intermediate directory in turn; per-component failures are ignored
    ; (already-exists is the normal case) - the single check that matters is at the end
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [rbp-48], rax           ; i
ged_loop:
    mov     rax, qword ptr [rbp-48]
    cmp     rax, qword ptr [rbp-32]
    jae     ged_final
    mov     r10, qword ptr [rbp-24]
    cmp     word ptr [r10+rax*2], 5Ch
    jne     ged_next
    mov     word ptr [r10+rax*2], 0           ; terminate at this component
    WINCALL CreateDirectoryW, qword ptr [rbp-24], 0
    mov     r10, qword ptr [rbp-24]
    mov     rax, qword ptr [rbp-48]
    mov     word ptr [r10+rax*2], 5Ch         ; restore
ged_next:
    inc     qword ptr [rbp-48]
    jmp     ged_loop
ged_final:
    mov     r10, qword ptr [rbp-24]
    mov     r11, qword ptr [rbp-32]
    mov     word ptr [r10+r11*2], 0           ; terminate at the parent directory
    WINCALL CreateDirectoryW, qword ptr [rbp-24], 0
    WINCALL GetFileAttributesW, qword ptr [rbp-24]     ; the answer that matters: is it
    mov     dword ptr [rbp-56], eax                    ;   there NOW, however it got there
    mov     r10, qword ptr [rbp-24]
    mov     r11, qword ptr [rbp-32]
    mov     word ptr [r10+r11*2], 5Ch         ; restore the separator
    mov     eax, dword ptr [rbp-56]
    cmp     eax, -1                           ; INVALID_FILE_ATTRIBUTES
    je      ged_fail
    test    eax, 10h                          ; FILE_ATTRIBUTE_DIRECTORY
    jz      ged_fail
ged_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
ged_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_ensure_vault_dir endp

; gui_create_do(rcx = hdlg) -> eax = 1 if the vault was created + unlocked
;   (close the dialog), else 0 (an error message was shown, stay open).
gui_create_do proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx          ; hdlg
    ; read password + confirm
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_C_PW, addr g_pwbuf, 1024
    test    eax, eax
    jnz     cd_havepw
    lea     rax, [s_nopw]
    mov     qword ptr [rbp-56], rax
    jmp     cd_status
cd_havepw:
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_C_PW2, addr g_pw2buf, 1024
    call    gui_pw_match
    test    eax, eax
    jnz     cd_match
    lea     rax, [s_pwmismatch]
    mov     qword ptr [rbp-56], rax
    jmp     cd_status
cd_match:
    ; the policy is fixed here (set in Settings / by HKLM); just enforce it
    lea     rcx, [g_pwbuf]
    call    password_to_utf8
    test    eax, eax
    jnz     cd_pwok
    lea     rax, [s_badpw]
    mov     qword ptr [rbp-56], rax
    jmp     cd_status
cd_pwok:
    call    check_password_policy           ; 0 ok / 1 short / 2 few classes
    cmp     eax, 0
    je      cd_polok
    cmp     eax, 1
    jne     @F
    lea     rax, [s_pwshort]
    mov     qword ptr [rbp-56], rax
    jmp     cd_status
@@: lea     rax, [s_pwclasses]
    mov     qword ptr [rbp-56], rax
    jmp     cd_status
cd_polok:
    call    gui_wipepw_create                ; wide buffers done with; the password now
    mov     eax, 1                           ;   lives in g_cfg_pass for the commit step
    FRAME_EPILOG
    ret
cd_status:
    call    gui_wipepw_create
    WINCALL gui_msgbox, qword ptr [rbp-24], qword ptr [rbp-56], addr t_err, \
            <MB_OK or MB_ICONWARNING>
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_create_do endp

; =============================================================================
; gui_create_commit(rcx = owner hwnd) -> eax = 1 if the vault was created, opened
;   and (where applicable) TPM-enrolled.
;
; This is everything gui_create_do used to do after the password was accepted, and
; it is a separate proc for one reason: it must NOT run on the private desktop.
;
; The private desktop exists to keep keystrokes away from same-session hooks.  It
; does nothing for file I/O - but the desktop is only restored after the dialog
; returns, so every blocking call made from inside it holds the user on a desktop
; with no shell.  Writing the vault into a OneDrive-synced folder does exactly
; that: file_rename retries a sync-tool lock for up to 10s by design, and the
; cloud-files filter can stall CreateFile/WriteFile/FlushFileBuffers with no
; timeout at all.  That stranded users on the private desktop with Ctrl+Alt+Del
; as the only exit, and surfaced as "Could not create the vault" when the retry
; budget ran out instead.
;
; So the dialog now only captures the password (into the VirtualLock'd g_cfg_pass,
; which outlives it), and the caller runs this once the desktop is its own again -
; where a slow disk merely looks slow, and an error box is on a desktop that has a
; shell to show it.
; =============================================================================
gui_create_commit proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-24], rcx          ; owner hwnd (error box parent)
    lea     rax, [g_vpath]
    mov     qword ptr [g_cfg_in], rax
    ; never silently overwrite an existing vault file - confirm first
    lea     rcx, [g_vpath]
    call    gui_file_exists
    test    eax, eax
    jz      ccm_doinit
    WINCALL gui_msgbox, qword ptr [rbp-24], addr m_overwrite, addr t_overwrite, \
            <MB_YESNO or MB_ICONWARNING or MB_DEFBUTTON2>
    cmp     eax, IDYES
    je      ccm_doinit
    lea     rax, [s_kept]                    ; declined -> keep existing vault
    mov     qword ptr [rbp-56], rax
    jmp     ccm_status
ccm_doinit:
    mov     dword ptr [g_readonly], 0        ; E9: a newly created vault is always writable
    call    gui_exe_dir_check                ; not beside the executable, please
    test    eax, eax
    jz      ccm_status_kept
    lea     rcx, [g_vpath]                   ; make sure the target folder exists - and
    call    gui_ensure_vault_dir             ;   say so HERE if it does not, instead of
    test    eax, eax                         ;   letting the write fail later with a bare
    jnz     ccm_dirok                        ;   ERROR_PATH_NOT_FOUND nobody can act on
    call    GetLastError
    mov     qword ptr [rbp-64], rax
    lea     rcx, [s_nodir_n]
    mov     edx, dword ptr [rbp-64]
    call    gui_num_msg
    mov     qword ptr [rbp-56], rax
    jmp     ccm_status
ccm_dirok:
    call    do_init
    test    eax, eax
    jz      ccm_created
    lea     rcx, [s_createfail_n]            ; carry the Win32 error INTO the message: the
    mov     edx, dword ptr [g_io_err]        ;   generic "(I/O or out of memory)" cost two
    call    gui_num_msg                      ;   rounds of guessing on a box with 110 GB free
    mov     qword ptr [rbp-56], rax
    jmp     ccm_status
ccm_created:
    ; Persist the freshly created vault as the startup vault, so it is reopened
    ; next launch.  Always - not only on the auto-default path (g_is_default).
    ; DLG_CREATE only ever makes the MASTER vault; foreign vaults are added via
    ; the M4 screen, which deliberately does NOT touch the startup path.  Without
    ; this, a second create in the same (tray-persistent) process left g_is_default
    ; at 0 and never recorded the new vault.
    lea     rcx, [g_vpath]
    call    reg_save_vault
    mov     dword ptr [g_is_default], 0
ccm_savepol:
    cmp     dword ptr [g_pol_len_lock], 0
    jne     ccm_savecls
    lea     rcx, [wv_pwlen]
    mov     edx, dword ptr [g_cfg_pwminlen]
    call    cfg_set_dword_hkcu
ccm_savecls:
    cmp     dword ptr [g_pol_cls_lock], 0
    jne     ccm_open
    lea     rcx, [wv_pwcls]
    mov     edx, dword ptr [g_cfg_pwminclasses]
    call    cfg_set_dword_hkcu
ccm_open:
    ; unlock the freshly created vault for the vault window
    mov     dword ptr [g_use_tpm], 0
    call    vault_unlock
    test    eax, eax
    jnz     ccm_unlockfail
    ; Give a brand-new vault its system item straight away, so it is entry 0 and every
    ; later record sits after it.  This is the REAL creation path only - do_init and
    ; do_seed stay system-item-free, which is what keeps the probe suite's physical
    ; entry counts unchanged (docs/SYSITEM_DESIGN.md).  An EXISTING vault is never
    ; migrated here: it gains one lazily, the first time there is actually a setting to
    ; store, so opening a vault never rewrites it behind the user's back.
    call    vault_add_system_item
    test    eax, eax
    jz      ccm_sysfail
    ; C9: the master password was typed seconds ago, so start its clock NOW.  Leaving
    ; the stamp at 0 means "never verified", which vault_pw_due reads as due - so a
    ; brand-new vault demanded a Master Password Check on its very first unlock.
    lea     rcx, [rbp-80]
    call    GetSystemTimeAsFileTime
    mov     rcx, qword ptr [rbp-80]
    call    vault_pwverify_set
    call    vault_reseal                     ; persist it now; the vault is empty, so cheap
    test    eax, eax
    jnz     ccm_sysfail
    ; enroll TPM unlock for a new vault when supported AND the setting/policy
    ; allows it (g_tpm_want: HKLM > HKCU > default ON, loaded at startup)
    cmp     dword ptr [g_tpm_present], 0
    je      ccm_done
    cmp     dword ptr [g_tpm_want], 0
    je      ccm_done
    call    vault_tpm_remember
    jmp     ccm_done
ccm_sysfail:
    call    vault_lock                       ; do not hand back a half-built vault
ccm_unlockfail:
    lea     rax, [s_createfail]
    mov     qword ptr [rbp-56], rax
    jmp     ccm_status
ccm_done:
    mov     dword ptr [g_create], 0
    call    gui_wipepw
    call    gui_wipepw_create
    mov     eax, 1
    FRAME_EPILOG
    ret
ccm_status_kept:
    lea     rax, [s_exedir_no]
    mov     qword ptr [rbp-56], rax
ccm_status:
    call    gui_wipepw
    call    gui_wipepw_create
    WINCALL gui_msgbox, qword ptr [rbp-24], qword ptr [rbp-56], addr t_err,             <MB_OK or MB_ICONWARNING>
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_create_commit endp

; gui_pw_strength(rcx = hdlg) - recompute the strength level (g_pw_level) and
;   confirm-match (g_pw_match) from the two password boxes, enable Create only
;   when valid, and repaint the two colour lines.
gui_pw_strength proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx          ; hdlg
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_C_PW, addr g_pwbuf, 1024
    mov     dword ptr [rbp-32], eax          ; password length (chars)
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_C_PW2, addr g_pw2buf, 1024
    mov     dword ptr [rbp-56], 0            ; pw_empty (captured before the buffers are wiped)
    cmp     dword ptr [rbp-32], 0
    jne     @F
    mov     dword ptr [rbp-56], 1
@@: mov     dword ptr [rbp-64], 0            ; pw2_empty
    movzx   eax, word ptr [g_pw2buf]
    test    eax, eax
    jnz     @F
    mov     dword ptr [rbp-64], 1
@@:
    ; ---- confirm matches a non-empty password? -----------------------------
    mov     dword ptr [g_pw_match], 0
    movzx   eax, word ptr [g_pw2buf]
    test    eax, eax
    jz      ps_nomatch
    call    gui_pw_match
    test    eax, eax
    jz      ps_nomatch
    mov     dword ptr [g_pw_match], 1
ps_nomatch:
    ; ---- strength level from the master password ---------------------------
    cmp     dword ptr [rbp-32], 0
    je      ps_bad
    lea     rcx, [g_pwbuf]
    call    password_to_utf8                 ; -> g_cfg_pass; wipes g_pwbuf
    test    eax, eax
    jz      ps_bad
    call    pw_metrics                       ; eax = code points, edx = classes
    mov     dword ptr [rbp-32], eax
    mov     dword ptr [rbp-40], edx
    call    gui_wipepw                       ; scrub the utf-8 copy
    mov     eax, dword ptr [rbp-32]
    mov     edx, dword ptr [rbp-40]
    cmp     eax, dword ptr [g_cfg_pwminlen]
    jb      ps_bad
    cmp     edx, dword ptr [g_cfg_pwminclasses]
    jb      ps_bad
    mov     r8d, dword ptr [g_cfg_pwminlen]
    add     r8d, 8
    cmp     eax, r8d                         ; >= min+8 chars AND all 4 types?
    jb      ps_grade_mid
    cmp     edx, 4
    jne     ps_grade_mid
    mov     dword ptr [g_pw_level], 3         ; strong
    jmp     ps_done
ps_grade_mid:
    mov     r8d, dword ptr [g_cfg_pwminlen]
    add     r8d, 4
    cmp     eax, r8d                         ; >= min+4 chars OR all 4 types?
    jae     ps_grade_good
    cmp     edx, 4
    je      ps_grade_good
    mov     dword ptr [g_pw_level], 2         ; barely compliant -> still green
    jmp     ps_done
ps_grade_good:
    mov     dword ptr [g_pw_level], 2         ; adequate
    jmp     ps_done
ps_bad:
    mov     dword ptr [g_pw_level], 0
ps_done:
    xor     eax, eax
    cmp     dword ptr [g_pw_level], 0
    setne   al
    mov     dword ptr [g_pw_compliant], eax
    call    gui_wipepw_create                 ; scrub both wide buffers
    ; enable Create only when the password is valid AND the confirm matches
    mov     ecx, dword ptr [g_pw_compliant]
    and     ecx, dword ptr [g_pw_match]
    mov     dword ptr [rbp-48], ecx
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDOK
    call    GetDlgItem
    mov     rcx, rax
    mov     edx, dword ptr [rbp-48]
    call    EnableWindow
    ; strength/match integrated into the field underlines (like the export dialog)
    mov     dword ptr [g_uline_ctl], IDC_C_PW
    cmp     dword ptr [rbp-56], 0            ; empty field -> default accent underline
    jne     cs_pwdef
    mov     eax, dword ptr [g_pw_level]      ; contiguous red/amber/lgreen/dgreen
    lea     r10, [g_br_red]
    mov     rax, qword ptr [r10+rax*8]
    mov     qword ptr [g_uline_br], rax
    jmp     cs_confirm
cs_pwdef:
    mov     qword ptr [g_uline_br], 0
cs_confirm:
    mov     dword ptr [g_uline_ctl2], IDC_C_PW2
    cmp     dword ptr [rbp-64], 0
    jne     cs_cfdef
    cmp     dword ptr [g_pw_match], 0
    je      cs_cfbad
    mov     rax, qword ptr [g_br_dgreen]
    mov     qword ptr [g_uline_br2], rax
    jmp     cs_inval
cs_cfbad:
    mov     rax, qword ptr [g_br_red]
    mov     qword ptr [g_uline_br2], rax
    jmp     cs_inval
cs_cfdef:
    mov     qword ptr [g_uline_br2], 0
cs_inval:
    WINCALL InvalidateRect, qword ptr [rbp-24], 0, 1
    FRAME_EPILOG
    ret
gui_pw_strength endp

; gui_pw_level(rcx = wide password ptr) -> eax = strength 0..3 using the SAME
;   thresholds as vault creation: 0 = below the vault policy (min length / char
;   classes), 2 = compliant, 3 = >= min+8 chars AND all four character classes.
;   Consumes the buffer via password_to_utf8 (which wipes it).
gui_pw_level proc frame
    FRAME_PROLOG 48
    call    password_to_utf8                    ; -> g_cfg_pass; wipes the wide src
    test    eax, eax
    jz      gpl_bad
    call    pw_metrics                          ; eax = code points, edx = classes
    mov     dword ptr [rbp-24], eax
    mov     dword ptr [rbp-32], edx
    call    gui_wipepw                          ; scrub the utf-8 copy
    mov     eax, dword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    cmp     eax, dword ptr [g_cfg_pwminlen]
    jb      gpl_bad
    cmp     edx, dword ptr [g_cfg_pwminclasses]
    jb      gpl_bad
    mov     r8d, dword ptr [g_cfg_pwminlen]
    add     r8d, 8
    cmp     eax, r8d                            ; >= min+8 chars AND all 4 types -> strong
    jb      gpl_mid
    cmp     edx, 4
    jne     gpl_mid
    mov     eax, 3
    FRAME_EPILOG
    ret
gpl_mid:
    mov     eax, 2
    FRAME_EPILOG
    ret
gpl_bad:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_pw_level endp

; gui_xlpw_strength(rcx = hdlg) - recompute the export password strength and the
;   confirm match, and colour each field's own focus underline instead of a
;   separate bar: main field red/light-green/deep-green by strength, confirm
;   field deep-green (match) / red (mismatch).  Then repaint the dialog frame.
gui_xlpw_strength proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx             ; hdlg
    call    gui_pwbars_init                     ; make sure the strength brushes exist
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_XP_PW, addr g_pwbuf, 1024
    mov     dword ptr [rbp-32], eax             ; password length (chars)
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_XP_PW2, addr g_pw2buf, 1024
    mov     dword ptr [rbp-36], eax             ; confirm length
    ; ---- confirm match (before password_to_utf8 wipes g_pwbuf) ----
    mov     dword ptr [rbp-40], 0
    cmp     dword ptr [rbp-36], 0
    je      xs_nomatch
    call    gui_pw_match
    test    eax, eax
    jz      xs_nomatch
    mov     dword ptr [rbp-40], 1
xs_nomatch:
    ; ---- strength level of the main password ----
    mov     dword ptr [rbp-44], 0
    cmp     dword ptr [rbp-32], 0
    je      xs_setpw
    lea     rcx, [g_pwbuf]
    call    gui_pw_level                        ; eax = 0..3 (wipes g_pwbuf)
    mov     dword ptr [rbp-44], eax
xs_setpw:
    mov     dword ptr [g_uline_ctl], IDC_XP_PW
    cmp     dword ptr [rbp-32], 0               ; empty field -> default accent underline
    je      xs_pwdef
    mov     eax, dword ptr [rbp-44]
    lea     r10, [g_br_red]                     ; contiguous red/amber/lgreen/dgreen
    mov     rax, qword ptr [r10+rax*8]
    mov     qword ptr [g_uline_br], rax
    jmp     xs_confirm
xs_pwdef:
    mov     qword ptr [g_uline_br], 0
xs_confirm:
    mov     dword ptr [g_uline_ctl2], IDC_XP_PW2
    cmp     dword ptr [rbp-36], 0               ; empty confirm -> default accent
    je      xs_cfdef
    cmp     dword ptr [rbp-40], 0
    je      xs_cfbad
    mov     rax, qword ptr [g_br_dgreen]
    mov     qword ptr [g_uline_br2], rax
    jmp     xs_wipe
xs_cfbad:
    mov     rax, qword ptr [g_br_red]
    mov     qword ptr [g_uline_br2], rax
    jmp     xs_wipe
xs_cfdef:
    mov     qword ptr [g_uline_br2], 0
xs_wipe:
    lea     rcx, [g_pwbuf]                      ; scrub both wide buffers
    mov     edx, 2048
    call    secure_zero
    lea     rcx, [g_pw2buf]
    mov     edx, 2048
    call    secure_zero
    WINCALL InvalidateRect, qword ptr [rbp-24], 0, 1
    FRAME_EPILOG
    ret
gui_xlpw_strength endp

; gui_pwbars_init() - build the four strength/match line brushes once.
gui_pwbars_init proc frame
    FRAME_PROLOG 32
    cmp     qword ptr [g_br_red], 0
    jne     pbi_done
    WINCALL CreateSolidBrush, CLR_BAR_RED
    mov     qword ptr [g_br_red], rax
    WINCALL CreateSolidBrush, CLR_BAR_AMBER
    mov     qword ptr [g_br_amber], rax
    WINCALL CreateSolidBrush, CLR_BAR_LGREEN
    mov     qword ptr [g_br_lgreen], rax
    WINCALL CreateSolidBrush, CLR_BAR_DGREEN
    mov     qword ptr [g_br_dgreen], rax
pbi_done:
    FRAME_EPILOG
    ret
gui_pwbars_init endp

; gui_w_appendz(rcx = dst wide, rdx = src wideZ) -> rax = dst end (no NUL copied).
gui_w_appendz proc
az_loop:
    movzx   eax, word ptr [rdx]
    test    eax, eax
    jz      az_done
    mov     word ptr [rcx], ax
    add     rcx, 2
    add     rdx, 2
    jmp     az_loop
az_done:
    mov     rax, rcx
    ret
gui_w_appendz endp

; gui_uint_w(rcx = dst wide, edx = value) -> rax = dst end.  Wide decimal, no NUL.
gui_uint_w proc
    push    rbx
    mov     rbx, rcx                          ; dst
    mov     eax, edx                          ; value
    lea     r9, [g_numtmp+16]                 ; write digits backwards from here
    mov     r8, r9
    mov     ecx, 10
uw_div:
    xor     edx, edx
    div     ecx                               ; eax/=10, edx=remainder
    add     edx, '0'
    sub     r8, 1
    mov     byte ptr [r8], dl
    test    eax, eax
    jnz     uw_div
uw_cpy:
    cmp     r8, r9
    jae     uw_done
    movzx   eax, byte ptr [r8]
    mov     word ptr [rbx], ax
    add     rbx, 2
    inc     r8
    jmp     uw_cpy
uw_done:
    mov     rax, rbx
    pop     rbx
    ret
gui_uint_w endp

; gui_show_info(rcx = hdlg) - compose the active policy into the (i) callout.
gui_show_info proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    lea     rcx, [g_reqbuf]
    lea     rdx, [req_p1]
    call    gui_w_appendz
    mov     rcx, rax
    mov     edx, dword ptr [g_cfg_pwminlen]
    call    gui_uint_w
    mov     rcx, rax
    lea     rdx, [req_p2]
    call    gui_w_appendz
    mov     rcx, rax
    mov     edx, dword ptr [g_cfg_pwminclasses]
    call    gui_uint_w
    mov     rcx, rax
    lea     rdx, [req_p3]
    call    gui_w_appendz
    mov     rcx, rax                          ; the "there is no reset" warning
    lea     rdx, [req_p4]
    call    gui_w_appendz
    mov     word ptr [rax], 0                 ; terminate
    WINCALL gui_msgbox, qword ptr [rbp-24], addr g_reqbuf, addr t_req, \
            <MB_OK or MB_ICONINFORMATION>
    FRAME_EPILOG
    ret
gui_show_info endp

; =============================================================================
; create_proc - DLG_CREATE dialog procedure (raw frame; OS callback).
;   rcx=hdlg rdx=msg r8=wParam r9=lParam -> rax = BOOL handled
; =============================================================================
create_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      cp_init
    cmp     rdx, WM_COMMAND
    je      cp_cmd
    cmp     rdx, WM_CTLCOLORSTATIC
    je      cp_tcolor
    cmp     rdx, WM_PAINT
    je      cp_tpaint
    cmp     rdx, WM_ERASEBKGND
    je      cp_terase
    cmp     rdx, WM_DRAWITEM
    je      cp_tdraw
    cmp     rdx, WM_CTLCOLOREDIT
    je      cp_tcolor
    cmp     rdx, WM_CTLCOLORLISTBOX
    je      cp_tcolor
    cmp     rdx, WM_CTLCOLORBTN
    je      cp_tcolor
    cmp     rdx, WM_CTLCOLORDLG
    je      cp_tcolor
    xor     eax, eax
    jmp     cp_ret
cp_tcolor:
    call    theme_ctlcolor
    jmp     cp_ret
cp_tpaint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     cp_ret
cp_terase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     cp_ret
cp_tdraw:
    mov     rcx, r9
    call    theme_drawitem
    jmp     cp_ret
cp_tunh:
    xor     eax, eax
    jmp     cp_ret
cp_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDOK
    call    theme_attach
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    call    gui_pwbars_init                  ; build the strength brushes
    WINCALL LoadImageW, qword ptr [g_hinst], 1, 1, 64, 64, 0   ; large Vordr logo
    mov     qword ptr [rbp-16], rax
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_C_LOGO, STM_SETICON, qword ptr [rbp-16], 0
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_C_WELCOME, addr m_welcome
    call    gui_make_welcomefont             ; larger body font (own frame: 14-arg CreateFontW)
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_C_WELCOME, WM_SETFONT, qword ptr [g_welcomefont], 1
    mov     dword ptr [g_uline_ctl], 0       ; start with default (accent) underlines
    mov     dword ptr [g_uline_ctl2], 0
    mov     qword ptr [g_uline_br], 0
    mov     qword ptr [g_uline_br2], 0
    ; placeholder cue text inside the two password boxes
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_C_PW, EM_SETCUEBANNER, 1, addr cue_pw
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_C_PW2, EM_SETCUEBANNER, 1, addr cue_pw2
    mov     rcx, qword ptr [rbp-8]           ; prime the underlines + Create state
    call    gui_pw_strength
    mov     eax, 1
    jmp     cp_ret
cp_cmd:
    movzx   eax, r8w                         ; LOWORD(wParam) = control id
    mov     r10d, r8d
    shr     r10d, 16                         ; HIWORD(wParam) = notification code
    cmp     r10d, EN_SETFOCUS                ; redraw Fluent underline on focus change
    je      cp_refocus
    cmp     r10d, EN_KILLFOCUS
    je      cp_refocus
    cmp     eax, IDC_C_INFO
    je      cp_info
    cmp     eax, IDC_C_PW
    je      cp_pwchg
    cmp     eax, IDC_C_PW2
    je      cp_pwchg
    cmp     eax, IDOK
    je      cp_ok
    cmp     eax, IDCANCEL
    je      cp_cancel
cp_ignore:
    xor     eax, eax
    jmp     cp_ret
cp_refocus:
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    xor     edx, edx
    mov     r8d, 1
    call    InvalidateRect
    add     rsp, 32
    mov     eax, 1
    jmp     cp_ret
cp_pwchg:
    cmp     r10d, EN_CHANGE
    jne     cp_ignore
    mov     rcx, qword ptr [rbp-8]           ; a password box changed -> recompute
    call    gui_pw_strength
    mov     eax, 1
    jmp     cp_ret
cp_info:
    mov     rcx, qword ptr [rbp-8]
    call    gui_show_info
    mov     eax, 1
    jmp     cp_ret
cp_ok:
    mov     rcx, qword ptr [rbp-8]
    call    gui_create_do
    test    eax, eax
    jz      cp_handled                      ; error shown, stay open
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, 1
    call    EndDialog
    add     rsp, 32
cp_handled:
    mov     eax, 1
    jmp     cp_ret
cp_cancel:
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    xor     edx, edx
    call    EndDialog
    add     rsp, 32
    mov     eax, 1
cp_ret:
    mov     rsp, rbp
    pop     rbp
    ret
create_proc endp

; =============================================================================
; =============================================================================
; Entry-selection checklist (DLG_SELECT): an owner-draw list of the vault's
; entries, each with a [ ]/[x] checkbox, a search box, and Select all/none.
; Used by export (pick what to write).  g_sel[e] = 1 selects entry e.
; =============================================================================
; -----------------------------------------------------------------------------
; Checklist source shims: the DLG_SELECT dialog serves both export (g_sel_src=0,
; rows come from the open vault) and import (g_sel_src=1, rows come from the
; staged-title arrays g_zi_titles/g_zi_tlens filled by zi_stage).
; -----------------------------------------------------------------------------

; gui_sel_count() -> eax = number of selectable rows.
gui_sel_count proc frame
    FRAME_PROLOG 32
    cmp     dword ptr [g_sel_src], 0
    jne     gsc_imp
    call    vault_count
    FRAME_EPILOG
    ret
gsc_imp:
    mov     eax, dword ptr [g_zi_stg_n]
    FRAME_EPILOG
    ret
gui_sel_count endp

; gui_sel_title(rcx = index, rdx = *len) -> rax = wide title ptr, [rdx] = wchars.
gui_sel_title proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    cmp     dword ptr [g_sel_src], 0
    jne     gst_imp
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [rbp-32]
    call    vault_title_at
    FRAME_EPILOG
    ret
gst_imp:
    mov     r10, qword ptr [rbp-24]              ; index
    lea     r8, [g_zi_titles]
    mov     rax, qword ptr [r8+r10*8]
    lea     r8, [g_zi_tlens]
    mov     ecx, dword ptr [r8+r10*4]
    mov     r10, qword ptr [rbp-32]
    mov     dword ptr [r10], ecx
    FRAME_EPILOG
    ret
gui_sel_title endp

; gui_sel_exportable(rcx = index) -> eax = 1 if that entry belongs in the export list.
;   Excludes the system item (not a user record at all) and anything in the TRASH - the
;   user deleted it, so offering it for export, and ticking it under "All", is wrong.
;   Applied in PHYSICAL index space alongside the search filter, so rows are only ever
;   skipped and no row->index remapping is needed anywhere.
;   Staged import rows have no vault semantics and always pass.
gui_sel_exportable proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_sel_src], 0
    je      gse_vault
    ; staged import: rows are staged at their SOURCE index so the tick mask lines up, so
    ; the ones that must not be offered are flagged rather than removed.
    cmp     ecx, MAX_SEL
    jae     gse_no
    lea     r10, [g_zi_hide]
    cmp     byte ptr [r10+rcx], 0
    jne     gse_no
    jmp     gse_yes
gse_vault:
    mov     qword ptr [rbp-24], rcx
    call    vault_is_system
    test    eax, eax
    jnz     gse_no
    mov     ecx, dword ptr [rbp-24]
    call    vault_is_deleted
    test    eax, eax
    jnz     gse_no
gse_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
gse_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_sel_exportable endp

; gui_sel_match(rcx = index) -> eax = 1 if the row matches g_search_w, else 0.
;   Vault rows delegate to gui_entry_matches; staged rows fold the title into
;   g_match_w and substring-scan for the (already upper-cased) query.
gui_sel_match proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_sel_src], 0
    jne     gsm_imp
    call    gui_entry_matches                    ; rcx = index
    FRAME_EPILOG
    ret
gsm_imp:
    lea     r8, [g_zi_titles]                    ; src = g_zi_titles[index]
    mov     r8, qword ptr [r8+rcx*8]
    lea     r9, [g_match_w]                      ; copy up to 255 wchars + NUL
    xor     r10d, r10d
gsm_cp:
    cmp     r10d, 255
    jae     gsm_cpend
    mov     ax, word ptr [r8+r10*2]
    mov     word ptr [r9+r10*2], ax
    test    ax, ax
    jz      gsm_upper
    inc     r10d
    jmp     gsm_cp
gsm_cpend:
    mov     word ptr [r9+r10*2], 0
gsm_upper:
    WINCALL CharUpperBuffW, addr g_match_w, r10d
    lea     rcx, [g_match_w]
    lea     rdx, [g_search_w]
    call    wide_find
    FRAME_EPILOG
    ret
gui_sel_match endp

; gui_sel_populate(rcx = hdlg) - (re)fill the SysListView32 with the rows that
;   match the search box, each carrying its source index in lParam and a checkbox
;   reflecting g_sel.  Titles are converted UTF-8 -> wide before insertion.
gui_sel_populate proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx              ; hdlg
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_SEL_LIST
    mov     qword ptr [rbp-32], rax              ; hlist
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_SEL_SEARCH, addr g_search_w, 255
    mov     dword ptr [rbp-36], eax              ; query len
    WINCALL CharUpperBuffW, addr g_search_w, dword ptr [rbp-36]
    WINCALL SendMessageW, qword ptr [rbp-32], LVM_DELETEALLITEMS, 0, 0
    call    gui_sel_count
    mov     dword ptr [rbp-40], eax              ; total
    mov     dword ptr [rbp-44], 0                ; i (source index)
    mov     dword ptr [rbp-48], 0                ; row (inserted index)
gsp_loop:
    mov     eax, dword ptr [rbp-44]
    cmp     eax, dword ptr [rbp-40]
    jae     gsp_done
    cmp     eax, MAX_SEL
    jae     gsp_done
    mov     ecx, dword ptr [rbp-44]             ; system items and trashed records are never
    call    gui_sel_exportable                  ;   offered, whatever the query says
    test    eax, eax
    jz      gsp_next
    cmp     dword ptr [rbp-36], 0               ; empty query -> everything matches
    je      gsp_show
    mov     ecx, dword ptr [rbp-44]
    call    gui_sel_match
    test    eax, eax
    jz      gsp_next
gsp_show:
    mov     ecx, dword ptr [rbp-44]
    lea     rdx, [rbp-56]
    call    gui_sel_title                        ; rax = ptr, [rbp-56] = len
    ; import titles are already wide + NUL-terminated; vault titles are UTF-8 bytes
    cmp     dword ptr [g_sel_src], 0
    jne     gsp_wide
    mov     rcx, rax                             ; vault: UTF-8 -> wide in g_conv_w
    mov     edx, dword ptr [rbp-56]
    lea     r8, [g_conv_w]
    mov     r9d, CONVW_MAX-1
    call    gui_towide
    lea     rax, [g_conv_w]
gsp_wide:
    mov     qword ptr [rbp-64], rax              ; pszText (wide, NUL-terminated)
    lea     r10, [g_lvi]                         ; marshal LVITEMW
    mov     dword ptr [r10+0], LVIF_TEXT or LVIF_PARAM or LVIF_STATE
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [r10+4], eax               ; iItem = row
    mov     dword ptr [r10+8], 0                 ; iSubItem
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [r10+24], rax              ; pszText
    mov     eax, dword ptr [rbp-44]
    mov     qword ptr [r10+40], rax              ; lParam = source index
    mov     dword ptr [r10+16], LVIS_STATEIMAGEMASK
    lea     r11, [g_sel]                         ; state image: checked = 2, unchecked = 1
    mov     eax, dword ptr [rbp-44]
    movzx   eax, byte ptr [r11+rax]
    test    eax, eax
    jz      gsp_unchk
    mov     eax, 2 shl 12
    jmp     gsp_st
gsp_unchk:
    mov     eax, 1 shl 12
gsp_st:
    mov     dword ptr [r10+12], eax              ; state
    WINCALL SendMessageW, qword ptr [rbp-32], LVM_INSERTITEMW, 0, addr g_lvi
    inc     dword ptr [rbp-48]
gsp_next:
    inc     dword ptr [rbp-44]
    jmp     gsp_loop
gsp_done:
    lea     rcx, [rbp-96]                        ; stretch the single column to the client width
    mov     qword ptr [rbp-64], rcx
    WINCALL GetClientRect, qword ptr [rbp-32], qword ptr [rbp-64]
    mov     eax, dword ptr [rbp-88]              ; rect.right
    sub     eax, 2
    WINCALL SendMessageW, qword ptr [rbp-32], LVM_SETCOLUMNWIDTH, 0, rax
    FRAME_EPILOG
    ret
gui_sel_populate endp

; gui_sel_setstate(rcx = hdlg, edx = check 0/1) - check or uncheck every visible row.
gui_sel_setstate proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-52], edx             ; check flag
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_SEL_LIST
    mov     qword ptr [rbp-32], rax             ; hlist
    WINCALL SendMessageW, qword ptr [rbp-32], LVM_GETITEMCOUNT, 0, 0
    mov     dword ptr [rbp-40], eax             ; count
    mov     eax, 1 shl 12                       ; unchecked state image
    cmp     dword ptr [rbp-52], 0
    je      @F
    mov     eax, 2 shl 12                       ; checked
@@: mov     dword ptr [rbp-48], eax
    mov     dword ptr [rbp-44], 0               ; j
sst_loop:
    mov     eax, dword ptr [rbp-44]
    cmp     eax, dword ptr [rbp-40]
    jae     sst_done
    lea     r10, [g_lvi]
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [r10+12], eax             ; state
    mov     dword ptr [r10+16], LVIS_STATEIMAGEMASK
    WINCALL SendMessageW, qword ptr [rbp-32], LVM_SETITEMSTATE, dword ptr [rbp-44], addr g_lvi
    inc     dword ptr [rbp-44]
    jmp     sst_loop
sst_done:
    FRAME_EPILOG
    ret
gui_sel_setstate endp

; gui_sel_readback(rcx = hdlg) - fold every visible row's checkbox back into g_sel
;   (keyed by the source index stored in each item's lParam).  Filtered-out rows
;   keep their prior g_sel state.
gui_sel_readback proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    WINCALL GetDlgItem, qword ptr [rbp-24], IDC_SEL_LIST
    mov     qword ptr [rbp-32], rax             ; hlist
    WINCALL SendMessageW, qword ptr [rbp-32], LVM_GETITEMCOUNT, 0, 0
    mov     dword ptr [rbp-40], eax             ; count
    mov     dword ptr [rbp-44], 0               ; j
grb_loop:
    mov     eax, dword ptr [rbp-44]
    cmp     eax, dword ptr [rbp-40]
    jae     grb_done
    lea     r10, [g_lvi]
    mov     dword ptr [r10+0], LVIF_PARAM or LVIF_STATE
    mov     eax, dword ptr [rbp-44]
    mov     dword ptr [r10+4], eax              ; iItem
    mov     dword ptr [r10+8], 0
    mov     dword ptr [r10+16], LVIS_STATEIMAGEMASK
    WINCALL SendMessageW, qword ptr [rbp-32], LVM_GETITEMW, 0, addr g_lvi
    lea     r10, [g_lvi]
    mov     rcx, qword ptr [r10+40]             ; lParam = source index
    mov     edx, dword ptr [r10+12]             ; state
    shr     edx, 12
    and     edx, 0Fh
    cmp     edx, 2                              ; state image 2 = checked
    sete    al
    movzx   eax, al
    cmp     rcx, MAX_SEL
    jae     grb_next
    lea     r11, [g_sel]
    mov     byte ptr [r11+rcx], al
grb_next:
    inc     dword ptr [rbp-44]
    jmp     grb_loop
grb_done:
    FRAME_EPILOG
    ret
gui_sel_readback endp

; select_proc - DLG_SELECT dialog procedure (themed; native SysListView32 with
;   checkboxes).  Returns 1 (OK) / 0 (Cancel).
select_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      sel_init
    cmp     rdx, WM_COMMAND
    je      sel_cmd
    cmp     rdx, WM_CTLCOLORSTATIC
    je      sel_col
    cmp     rdx, WM_CTLCOLOREDIT
    je      sel_col
    cmp     rdx, WM_CTLCOLORBTN
    je      sel_col
    cmp     rdx, WM_CTLCOLORDLG
    je      sel_col
    cmp     rdx, WM_PAINT
    je      sel_paint
    cmp     rdx, WM_ERASEBKGND
    je      sel_erase
    cmp     rdx, WM_DRAWITEM
    je      sel_draw
    xor     eax, eax
    jmp     sel_ret
sel_col:
    call    theme_ctlcolor
    jmp     sel_ret
sel_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     sel_ret
sel_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    mov     eax, 1
    jmp     sel_ret
sel_draw:
    mov     rcx, r9                              ; owner-draw buttons (All/None/OK/Cancel)
    call    theme_drawitem
    mov     eax, 1
    jmp     sel_ret
sel_unh:
    xor     eax, eax
    jmp     sel_ret
sel_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDOK
    call    theme_attach
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_SEL_LIST
    mov     qword ptr [rbp-16], rax             ; hlist
    ; native checkboxes + full-row selection, themed colours
    WINCALL SendMessageW, qword ptr [rbp-16], LVM_SETEXTENDEDLISTVIEWSTYLE, \
            LVS_EX_CHECKBOXES or LVS_EX_FULLROWSELECT, LVS_EX_CHECKBOXES or LVS_EX_FULLROWSELECT
    WINCALL SendMessageW, qword ptr [rbp-16], LVM_SETBKCOLOR, 0, dword ptr [g_col_bg]
    WINCALL SendMessageW, qword ptr [rbp-16], LVM_SETTEXTBKCOLOR, 0, dword ptr [g_col_bg]
    WINCALL SendMessageW, qword ptr [rbp-16], LVM_SETTEXTCOLOR, 0, dword ptr [g_col_text]
    lea     r10, [g_lvi]                         ; one width-only column
    mov     dword ptr [r10+0], LVCF_WIDTH
    mov     dword ptr [r10+8], 100
    WINCALL SendMessageW, qword ptr [rbp-16], LVM_INSERTCOLUMNW, 0, addr g_lvi
    cmp     dword ptr [g_sel_src], 0            ; import mode: relabel caption + OK button
    je      sel_init_pop
    WINCALL SetWindowTextW, qword ptr [rbp-8], addr sel_cap_imp
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDOK, addr sel_ok_imp
sel_init_pop:
    mov     rcx, qword ptr [rbp-8]
    call    gui_sel_populate
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_SEL_SEARCH, EM_SETCUEBANNER, 1, addr cue_search
    mov     eax, 1
    jmp     sel_ret
sel_cmd:
    movzx   eax, r8w
    mov     r10d, r8d
    shr     r10d, 16                             ; notification
    cmp     r10d, EN_CHANGE
    jne     sel_cmd_disp
    cmp     eax, IDC_SEL_SEARCH
    jne     sel_handled
    mov     rcx, qword ptr [rbp-8]
    call    gui_sel_populate
    jmp     sel_handled
sel_cmd_disp:
    cmp     eax, IDC_SEL_ALL
    je      sel_c_all
    cmp     eax, IDC_SEL_NONE
    je      sel_c_none
    cmp     eax, IDOK
    je      sel_c_ok
    cmp     eax, IDCANCEL
    je      sel_c_cancel
    xor     eax, eax
    jmp     sel_ret
sel_c_all:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, 1
    call    gui_sel_setstate
    jmp     sel_handled
sel_c_none:
    mov     rcx, qword ptr [rbp-8]
    xor     edx, edx
    call    gui_sel_setstate
    jmp     sel_handled
sel_c_ok:
    mov     rcx, qword ptr [rbp-8]
    call    gui_sel_readback
    WINCALL EndDialog, qword ptr [rbp-8], 1
    jmp     sel_handled
sel_c_cancel:
    WINCALL EndDialog, qword ptr [rbp-8], 0
    jmp     sel_handled
sel_handled:
    mov     eax, 1
sel_ret:
    mov     rsp, rbp
    pop     rbp
    ret
select_proc endp

; gui_sel_all(rcx = count) - preselect entries 0..count-1 (capped at MAX_SEL) and
;   clear the rest, so the checklist opens with everything ticked.
gui_sel_all proc frame
    FRAME_PROLOG 48
    ; [rbp-24] = count, [rbp-32] = i.  "All" must tick exactly what the list SHOWS -
    ; ticking a hidden system item or a trashed record would hand it straight to the
    ; exporters, which is the very thing the row filter exists to prevent.
    mov     dword ptr [rbp-24], ecx
    mov     dword ptr [rbp-32], 0
gsa_lp:
    cmp     dword ptr [rbp-32], MAX_SEL
    jae     gsa_done
    mov     eax, dword ptr [rbp-32]
    xor     r8d, r8d
    cmp     eax, dword ptr [rbp-24]
    jae     gsa_put
    mov     ecx, eax
    call    gui_sel_exportable
    mov     r8d, eax
gsa_put:
    lea     r10, [g_sel]
    mov     eax, dword ptr [rbp-32]
    mov     byte ptr [r10+rax], r8b
    inc     dword ptr [rbp-32]
    jmp     gsa_lp
gsa_done:
    FRAME_EPILOG
    ret
gui_sel_all endp

; gui_export(rcx = hdlg) - prompt for a password, ze_compose builds the AES-256
;   encrypted ZIP (vordr.json of all tiles + every attachment, history excluded),
;   then pick a save path and write it.
; =============================================================================
; gfe_tailci(rcx = path, edx = pathlen, r8 = suffix, r9d = suffixlen)
;   -> eax = 1 if path ends with suffix, case-insensitive (ASCII).  Leaf.
gfe_tailci proc
    cmp     edx, r9d
    jb      gtc_no
    sub     edx, r9d                            ; -> start of the tail
    xor     r10d, r10d
gtc_lp:
    cmp     r10d, r9d
    jae     gtc_yes
    mov     eax, edx
    add     eax, r10d
    movzx   eax, word ptr [rcx+rax*2]
    or      eax, 20h                            ; ASCII fold; both sides are literals here
    movzx   r11d, word ptr [r8+r10*2]
    or      r11d, 20h
    cmp     eax, r11d
    jne     gtc_no
    inc     r10d
    jmp     gtc_lp
gtc_yes:
    mov     eax, 1
    ret
gtc_no:
    xor     eax, eax
    ret
gfe_tailci endp

; gui_fix_ext(rcx = wide buffer, edx = capacity in chars, r8d = 1 for .zip / 0 for .vordr)
;   Force the buffer's extension to agree with the chosen format.
;   GetSaveFileName only applies lpstrDefExt when the name has NO extension, so changing
;   the file type never rewrote an existing ".vordr" to ".zip" - pick ZIP and you still
;   got vordr-export.vordr.  The FILTER INDEX is the authority: whatever the type box
;   says, the name is made to match.  Only a trailing ".vordr"/".zip" is stripped, so
;   "notes.2026" keeps its dots and simply gains the right suffix.
gui_fix_ext proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=buf [rbp-32]=cap [rbp-40]=iszip [rbp-48]=len
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [rbp-40], r8d
    mov     r10, rcx
    xor     ecx, ecx
gfe_len:
    cmp     word ptr [r10+rcx*2], 0
    je      gfe_have
    inc     ecx
    mov     eax, dword ptr [rbp-32]
    sub     eax, 8
    cmp     ecx, eax
    jb      gfe_len
gfe_have:
    mov     dword ptr [rbp-48], ecx
    mov     rcx, qword ptr [rbp-24]             ; strip a trailing ".vordr"...
    mov     edx, dword ptr [rbp-48]
    lea     r8, [w_dotvordr]
    mov     r9d, 6
    call    gfe_tailci
    test    eax, eax
    jz      @F
    sub     dword ptr [rbp-48], 6
    jmp     gfe_app
@@: mov     rcx, qword ptr [rbp-24]             ; ...or a trailing ".zip"
    mov     edx, dword ptr [rbp-48]
    lea     r8, [w_dotzip]
    mov     r9d, 4
    call    gfe_tailci
    test    eax, eax
    jz      gfe_app
    sub     dword ptr [rbp-48], 4
gfe_app:
    mov     r10, qword ptr [rbp-24]
    mov     ecx, dword ptr [rbp-48]
    lea     r11, [w_dotvordr]
    cmp     dword ptr [rbp-40], 0
    je      @F
    lea     r11, [w_dotzip]
@@: xor     r8d, r8d
gfe_cp:
    mov     ax, word ptr [r11+r8*2]
    mov     word ptr [r10+rcx*2], ax
    test    ax, ax
    jz      gfe_done
    inc     ecx
    inc     r8d
    mov     eax, dword ptr [rbp-32]
    dec     eax
    cmp     ecx, eax
    jb      gfe_cp
    mov     word ptr [r10+rcx*2], 0
gfe_done:
    FRAME_EPILOG
    ret
gui_fix_ext endp

; NOTE: an OFN_ENABLEHOOK hook handling CDN_TYPECHANGE would let us rewrite the
; file-name edit live when the type changes - but installing ANY hook drops the save
; box off the modern Vista+ dialog and back onto the legacy comdlg32 one.  That is a
; far worse regression than a stale suffix, so the approach was removed.  Instead the
; default name carries NO extension: nothing on screen can then contradict the type
; box, and the extension is settled from the filter index on return (gui_fix_ext).

gui_export proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [g_sel_src], 0             ; checklist draws from the open vault
    call    vault_count                          ; open the checklist with all entries ticked
    mov     ecx, eax
    call    gui_sel_all
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_SELECT, qword ptr [rbp-24], addr select_proc, 0
    cmp     eax, 1
    jne     gx_done
    ; ---- destination FIRST: the chosen file type is the chosen format ------
    lea     rax, [g_expfilter]                   ; .vordr first (default), .zip second
    mov     qword ptr [g_pickfilter], rax
    lea     rcx, [g_imgpath]
    lea     rdx, [exp_defname]
    call    gui_wcpy_capped
    mov     dword ptr [g_exp_iszip], 0           ; .vordr is filter 1 = the default
    mov     rcx, qword ptr [rbp-24]
    mov     edx, 1
    call    img_pick
    test    eax, eax
    jz      gx_done
    lea     r10, [g_ofn]                         ; the TYPE box is the authority, not the
    xor     eax, eax                             ;   text the user was left with: filter 2
    cmp     dword ptr [r10].OPENFILENAMEW.nFilterIndex, 2   ;   = ZIP, anything else = vordr
    jne     @F
    mov     eax, 1
@@: mov     dword ptr [g_exp_iszip], eax
    mov     dword ptr [rbp-40], eax              ; 0 = .vordr, 1 = .zip
    lea     rcx, [g_imgpath]                     ; belt and braces: the hook keeps the shown
    mov     edx, MAX_PATH_CHARS                  ;   name in step, this guarantees the path
    mov     r8d, eax                             ;   actually written matches the format
    call    gui_fix_ext
    cmp     dword ptr [rbp-40], 0
    je      gx_askpw
    ; ZIP is the weaker path and must be a deliberate choice, so say plainly what is
    ; given up - including the extensions kept in member names - and let them back out.
    WINCALL gui_msgbox, qword ptr [rbp-24], addr exp_zipwarn, addr exp_title, \
            <MB_OKCANCEL or MB_ICONWARNING>
    cmp     eax, IDOK
    jne     gx_done
gx_askpw:
    ; The export password is a secret being typed, so it honours the same
    ; secure-desktop setting as the master password rather than being the one
    ; password-entry box that ignores it.
    cmp     dword ptr [g_secunlock], 0
    je      gx_pw_normal
    mov     ecx, DLG_XLPW
    lea     rdx, [xlpw_proc]
    call    gui_secdesk_show
    jmp     gx_pw_res
gx_pw_normal:
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_XLPW, qword ptr [rbp-24], addr xlpw_proc, 0
gx_pw_res:
    cmp     rax, 1
    jne     gx_done
    cmp     dword ptr [rbp-40], 0
    jne     gx_zip
    ; ---- .vordr: seal a child vault; the master stays open throughout -------
    lea     rcx, [g_xlpw]                        ; -> g_cfg_pass (and wipes g_xlpw)
    call    password_to_utf8
    test    eax, eax
    jz      gx_composefail
    lea     rcx, [g_imgpath]
    call    vault_export_sel
    mov     dword ptr [rbp-32], eax
    lea     rcx, [ev_export]                     ; C5: audit the export
    mov     edx, eax
    call    log_result
    lea     rcx, [g_cfg_pass]                    ; the EXPORT password must not be left
    mov     edx, MAX_PASSWORD_BYTES+1            ;   sitting in the master's buffer
    call    secure_zero
    mov     dword ptr [g_cfg_passlen], 0
    call    ges_wipepw
    cmp     dword ptr [rbp-32], 0
    jne     gx_writefail
    WINCALL MessageBoxW, qword ptr [rbp-24], addr exp_done_ok, addr exp_title, 040h
    jmp     gx_done
gx_zip:
    lea     rcx, [g_xlpw]                        ; wide password + length (bytes)
    mov     edx, dword ptr [g_xlpwlen]
    call    ze_compose                           ; -> encrypted zip in g_zbuf (all tiles, no history)
    mov     dword ptr [rbp-32], eax             ; C5: audit the export
    lea     rcx, [ev_export]
    mov     edx, eax
    call    log_result
    mov     eax, dword ptr [rbp-32]
    test    eax, eax
    jnz     gx_composefail
    lea     rcx, [g_imgpath]
    lea     r11, [g_zbuf]
    mov     rdx, qword ptr [r11]
    mov     r8, qword ptr [r11+8]
    call    write_file
    mov     dword ptr [rbp-32], eax
    call    ze_free
    call    ges_wipepw
    cmp     dword ptr [rbp-32], 0
    jne     gx_writefail
    WINCALL MessageBoxW, qword ptr [rbp-24], addr exp_done_ok, addr exp_title, 040h
    jmp     gx_done
gx_composefail:
    call    ze_free
    call    ges_wipepw
    WINCALL MessageBoxW, qword ptr [rbp-24], addr xp_mm_fail, addr xp_mm_title, 010h
    jmp     gx_done
gx_writefail:
    WINCALL MessageBoxW, qword ptr [rbp-24], addr xp_mm_fail, addr xp_mm_title, 010h
gx_done:
    FRAME_EPILOG
    ret
gui_export endp

; =============================================================================
; Password history browser (DLG_PWHIST): a scrollable owner-draw list of the
; open entry's archived passwords (g_pwhist), each showing when it was changed,
; the old password, and a per-row purge 'x'.
; =============================================================================
; pwh_build_tabs() - scan g_pwhist and collect the distinct labels into g_pwh_tabs
;   (each entry = the index of the first record carrying that label).  Clamps the
;   selected tab g_pwh_tab into range.  One tab per tile that has history.
pwh_build_tabs proc frame
    FRAME_PROLOG 64
    mov     dword ptr [g_pwh_ntabs], 0
    mov     dword ptr [rbp-24], 0             ; i = record index
pbt_i:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_pwhist_n]
    jae     pbt_done
    mov     ecx, eax
    call    pwh_entry
    lea     rax, [rax+PWHIST_LBL]
    mov     qword ptr [rbp-32], rax           ; label_i
    mov     dword ptr [rbp-40], 0             ; t = tab index
pbt_t:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [g_pwh_ntabs]
    jae     pbt_add
    lea     r10, [g_pwh_tabs]
    mov     ecx, dword ptr [r10+rax*4]        ; representative record of tab t
    call    pwh_entry
    lea     rdx, [rax+PWHIST_LBL]
    mov     rcx, qword ptr [rbp-32]
    call    gui_wstr_eq
    test    eax, eax
    jnz     pbt_inext                         ; already have a tab for this label
    inc     dword ptr [rbp-40]
    jmp     pbt_t
pbt_add:
    mov     eax, dword ptr [g_pwh_ntabs]
    cmp     eax, MAX_TABS
    jae     pbt_inext
    lea     r10, [g_pwh_tabs]
    mov     ecx, dword ptr [rbp-24]
    mov     dword ptr [r10+rax*4], ecx
    inc     dword ptr [g_pwh_ntabs]
pbt_inext:
    inc     dword ptr [rbp-24]
    jmp     pbt_i
pbt_done:
    mov     eax, dword ptr [g_pwh_tab]        ; clamp selection
    cmp     eax, dword ptr [g_pwh_ntabs]
    jb      pbt_ok
    mov     dword ptr [g_pwh_tab], 0
pbt_ok:
    FRAME_EPILOG
    ret
pwh_build_tabs endp

; pwh_build_filter() - fill g_pwh_filter with the g_pwhist indices whose label matches
;   the selected tab (g_pwh_tab), preserving order.  g_pwh_fn = count.
pwh_build_filter proc frame
    FRAME_PROLOG 64
    mov     dword ptr [g_pwh_fn], 0
    mov     eax, dword ptr [g_pwh_tab]
    cmp     eax, dword ptr [g_pwh_ntabs]
    jae     pbf_done
    lea     r10, [g_pwh_tabs]
    mov     ecx, dword ptr [r10+rax*4]
    call    pwh_entry
    lea     rax, [rax+PWHIST_LBL]
    mov     qword ptr [rbp-24], rax           ; target label
    mov     dword ptr [rbp-32], 0             ; i
pbf_i:
    mov     eax, dword ptr [rbp-32]
    cmp     eax, dword ptr [g_pwhist_n]
    jae     pbf_done
    mov     ecx, eax
    call    pwh_entry
    lea     rdx, [rax+PWHIST_LBL]
    mov     rcx, qword ptr [rbp-24]
    call    gui_wstr_eq
    test    eax, eax
    jz      pbf_inext
    mov     eax, dword ptr [g_pwh_fn]
    lea     r10, [g_pwh_filter]
    mov     ecx, dword ptr [rbp-32]
    mov     dword ptr [r10+rax*4], ecx
    inc     dword ptr [g_pwh_fn]
pbf_inext:
    inc     dword ptr [rbp-32]
    jmp     pbf_i
pbf_done:
    FRAME_EPILOG
    ret
pwh_build_filter endp

; gui_draw_pwhist(rcx = lpdis) - paint the per-tile tab strip, then the visible
;   history rows for the selected tab from g_pwh_scroll (newest on top).
gui_draw_pwhist proc frame
    FRAME_PROLOG 272
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax            ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-40], eax            ; L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-48], eax            ; T
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-56], eax            ; R
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-64], eax            ; B
    WINCALL CreateSolidBrush, dword ptr [g_col_bg]
    mov     qword ptr [rbp-72], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [rbp-72]
    WINCALL DeleteObject, qword ptr [rbp-72]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_subfont]
    mov     qword ptr [rbp-80], rax            ; old font
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    ; --- header: this entry's Created / Modified (dim, across the top) ---
    call    gui_build_times
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_textdim]
    mov     eax, dword ptr [rbp-40]
    add     eax, 10
    mov     dword ptr [rbp-176], eax
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [rbp-172], eax
    mov     eax, dword ptr [rbp-56]
    sub     eax, 2
    mov     dword ptr [rbp-168], eax
    mov     eax, dword ptr [rbp-48]
    add     eax, PH_HDRH
    mov     dword ptr [rbp-164], eax
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_times_w, -1, addr rbp-176, 8024h
    cmp     dword ptr [g_pwhist_n], 0
    je      gdh_restore                        ; no records: the header still shows
    call    pwh_build_tabs
    call    pwh_build_filter
    ; --- per-tile tab strip (splits the width evenly among the labels) ---
    mov     eax, dword ptr [rbp-56]           ; tabW = (R - L) / ntabs
    sub     eax, dword ptr [rbp-40]
    cdq
    idiv    dword ptr [g_pwh_ntabs]
    mov     dword ptr [rbp-188], eax          ; tabW
    mov     dword ptr [rbp-88], 0             ; t
gdh_tab:
    mov     eax, dword ptr [rbp-88]
    cmp     eax, dword ptr [g_pwh_ntabs]
    jae     gdh_tabsdone
    mov     eax, dword ptr [rbp-88]           ; tabX = L + t*tabW
    imul    eax, dword ptr [rbp-188]
    add     eax, dword ptr [rbp-40]
    mov     dword ptr [rbp-192], eax
    mov     eax, dword ptr [g_col_textdim]    ; selected tab = bright text
    mov     ecx, dword ptr [rbp-88]
    cmp     ecx, dword ptr [g_pwh_tab]
    jne     @F
    mov     eax, dword ptr [g_col_text]
@@: WINCALL SetTextColor, qword ptr [rbp-32], eax
    mov     eax, dword ptr [rbp-192]          ; text rect [tabX+4, below the header,
    add     eax, 4                            ;            tabX+tabW-4, +PH_TABH]
    mov     dword ptr [rbp-176], eax
    mov     eax, dword ptr [rbp-48]
    add     eax, PH_HDRH
    mov     dword ptr [rbp-172], eax
    mov     eax, dword ptr [rbp-192]
    add     eax, dword ptr [rbp-188]
    sub     eax, 4
    mov     dword ptr [rbp-168], eax
    mov     eax, dword ptr [rbp-48]
    add     eax, PH_HDRH+PH_TABH
    mov     dword ptr [rbp-164], eax
    mov     ecx, dword ptr [rbp-88]           ; tab label = its representative record's label
    lea     r10, [g_pwh_tabs]
    mov     ecx, dword ptr [r10+rcx*4]
    call    pwh_entry
    add     rax, PWHIST_LBL
    WINCALL DrawTextW, qword ptr [rbp-32], rax, -1, addr rbp-176, 8025h
    mov     eax, dword ptr [rbp-88]           ; selected tab -> accent underline
    cmp     eax, dword ptr [g_pwh_tab]
    jne     gdh_tabnext
    WINCALL CreateSolidBrush, dword ptr [g_col_accent]
    mov     qword ptr [rbp-120], rax
    mov     eax, dword ptr [rbp-192]
    add     eax, 8
    mov     dword ptr [rbp-176], eax
    mov     eax, dword ptr [rbp-48]
    add     eax, PH_HDRH+PH_TABH-3
    mov     dword ptr [rbp-172], eax
    mov     eax, dword ptr [rbp-192]
    add     eax, dword ptr [rbp-188]
    sub     eax, 8
    mov     dword ptr [rbp-168], eax
    mov     eax, dword ptr [rbp-48]
    add     eax, PH_HDRH+PH_TABH-1
    mov     dword ptr [rbp-164], eax
    WINCALL FillRect, qword ptr [rbp-32], addr rbp-176, qword ptr [rbp-120]
    WINCALL DeleteObject, qword ptr [rbp-120]
gdh_tabnext:
    inc     dword ptr [rbp-88]
    jmp     gdh_tab
gdh_tabsdone:
    mov     dword ptr [rbp-88], 0             ; k = visible row within the selected tab
gdh_loop:
    mov     eax, dword ptr [g_pwh_scroll]
    add     eax, dword ptr [rbp-88]           ; fdisp = scroll + k
    cmp     eax, dword ptr [g_pwh_fn]
    jae     gdh_restore
    mov     ecx, dword ptr [g_pwh_fn]         ; fi = (fn-1) - fdisp  (newest on top)
    dec     ecx
    sub     ecx, eax
    lea     r10, [g_pwh_filter]               ; i = filter[fi] = record index
    mov     ecx, dword ptr [r10+rcx*4]
    mov     dword ptr [rbp-96], ecx           ; i = entry index
    mov     eax, dword ptr [rbp-88]
    imul    eax, eax, PH_ROW_H
    add     eax, dword ptr [rbp-48]
    add     eax, PH_HDRH+PH_TABH
    mov     dword ptr [rbp-104], eax          ; rowTop (below the header + tab strip)
    mov     ecx, eax
    add     ecx, PH_ROW_H
    cmp     ecx, dword ptr [rbp-64]
    jg      gdh_restore                        ; next row would overflow the control
    sub     ecx, 2
    mov     dword ptr [rbp-112], ecx          ; rowBot
    ; row panel (rounded)
    WINCALL CreateSolidBrush, dword ptr [g_col_panel]
    mov     qword ptr [rbp-120], rax
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-120]
    mov     qword ptr [rbp-128], rax
    WINCALL GetStockObject, 8                  ; NULL_PEN
    WINCALL SelectObject, qword ptr [rbp-32], rax
    mov     qword ptr [rbp-136], rax
    mov     eax, dword ptr [rbp-56]
    sub     eax, 2
    mov     dword ptr [rbp-144], eax           ; right = R-2
    WINCALL RoundRect, qword ptr [rbp-32], dword ptr [rbp-40], dword ptr [rbp-104], \
            dword ptr [rbp-144], dword ptr [rbp-112], 6, 6
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-128]
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-136]
    WINCALL DeleteObject, qword ptr [rbp-120]
    ; entry ptr + formatted change date
    mov     ecx, dword ptr [rbp-96]
    call    pwh_entry
    mov     qword ptr [rbp-152], rax           ; entry ptr (filetime @ +0)
    lea     rcx, [g_phdate]
    mov     rdx, rax
    call    gui_fmt_datetime
    mov     eax, dword ptr [rbp-56]            ; dateLeft = R-2-PURGE-100 (right column)
    sub     eax, 2 + PH_PURGE_W + 100
    mov     dword ptr [rbp-144], eax
    ; tile name / label (dim, left column)
    mov     eax, dword ptr [rbp-40]
    add     eax, 110                           ; labelRight = L+10+100
    mov     dword ptr [rbp-184], eax
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_textdim]
    mov     eax, dword ptr [rbp-40]
    add     eax, 10
    mov     dword ptr [rbp-176], eax
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-172], eax
    mov     eax, dword ptr [rbp-184]
    mov     dword ptr [rbp-168], eax
    mov     eax, dword ptr [rbp-112]
    mov     dword ptr [rbp-164], eax
    mov     rax, qword ptr [rbp-152]
    add     rax, PWHIST_LBL
    WINCALL DrawTextW, qword ptr [rbp-32], rax, -1, addr rbp-176, 8024h
    ; middle column (ellipsized): the old value for CHANGED, else a dim "(added)"
    ; marker - an ADDED record keeps no value to show
    mov     rax, qword ptr [rbp-152]
    lea     r10, [rax+PWHIST_PW]
    mov     r11d, dword ptr [g_col_text]
    cmp     dword ptr [rax+PWHIST_ACT], PWHA_CHANGED
    je      @F
    lea     r10, [ph_added]
    mov     r11d, dword ptr [g_col_textdim]
@@: mov     qword ptr [rbp-200], r10          ; text ptr + color in their own slots:
    mov     dword ptr [rbp-208], r11d         ;   WINCALL's arg stores clobber registers
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [rbp-208]
    mov     eax, dword ptr [rbp-184]
    add     eax, 8
    mov     dword ptr [rbp-176], eax
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-172], eax
    mov     eax, dword ptr [rbp-144]
    sub     eax, 6
    mov     dword ptr [rbp-168], eax
    mov     eax, dword ptr [rbp-112]
    mov     dword ptr [rbp-164], eax
    WINCALL DrawTextW, qword ptr [rbp-32], qword ptr [rbp-200], -1, addr rbp-176, 8024h
    ; change date (dim, right-aligned column)
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_textdim]
    mov     eax, dword ptr [rbp-144]
    mov     dword ptr [rbp-176], eax
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-172], eax
    mov     eax, dword ptr [rbp-56]
    sub     eax, 2 + PH_PURGE_W
    mov     dword ptr [rbp-168], eax
    mov     eax, dword ptr [rbp-112]
    mov     dword ptr [rbp-164], eax
    WINCALL DrawTextW, qword ptr [rbp-32], addr g_phdate, -1, addr rbp-176, 26h
    ; purge 'x' (far right)
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_textdim]
    mov     eax, dword ptr [rbp-56]
    sub     eax, 2 + PH_PURGE_W
    mov     dword ptr [rbp-176], eax
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-172], eax
    mov     eax, dword ptr [rbp-56]
    sub     eax, 2
    mov     dword ptr [rbp-168], eax
    mov     eax, dword ptr [rbp-112]
    mov     dword ptr [rbp-164], eax
    WINCALL DrawTextW, qword ptr [rbp-32], addr tag_xw, -1, addr rbp-176, DT_IMGFLAGS
    inc     dword ptr [rbp-88]
    jmp     gdh_loop
gdh_restore:
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [rbp-80]
gdh_done:
    FRAME_EPILOG
    ret
gui_draw_pwhist endp

; gui_pwhist_click(rcx = hdlg) - a history row was clicked; if the click landed on
;   the right-hand purge 'x', remove that archived password (marks the entry dirty).
gui_pwhist_click proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_pwhist_n], 0
    je      gpk_done
    call    pwh_build_tabs
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_PH_LIST
    call    GetDlgItem
    mov     qword ptr [rbp-32], rax
    test    rax, rax
    jz      gpk_done
    lea     rcx, [rbp-48]                      ; POINT x@-48 y@-44
    call    GetCursorPos
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [rbp-48]
    call    ScreenToClient
    mov     rcx, qword ptr [rbp-32]
    lea     rdx, [rbp-64]                      ; RECT l-64 t-60 r-56 b-52
    call    GetClientRect
    ; --- click in the header band? (above the tabs) -> nothing to do ---
    cmp     dword ptr [rbp-44], PH_HDRH
    jl      gpk_done
    ; --- click in the tab strip? -> switch tab ---
    cmp     dword ptr [rbp-44], PH_HDRH+PH_TABH
    jge     gpk_row
    mov     eax, dword ptr [rbp-56]           ; tabW = clientW / ntabs
    cdq
    idiv    dword ptr [g_pwh_ntabs]
    test    eax, eax
    jz      gpk_done
    mov     ecx, eax                          ; tabW
    mov     eax, dword ptr [rbp-48]           ; tab = pt.x / tabW
    cdq
    idiv    ecx
    cmp     eax, dword ptr [g_pwh_ntabs]      ; clamp to last tab
    jb      @F
    mov     eax, dword ptr [g_pwh_ntabs]
    dec     eax
@@: mov     dword ptr [g_pwh_tab], eax
    mov     dword ptr [g_pwh_scroll], 0
    jmp     gpk_repaint
gpk_row:
    call    pwh_build_filter
    mov     eax, dword ptr [rbp-44]           ; disp = scroll + (pt.y-tabsBot)/PH_ROW_H
    sub     eax, PH_HDRH+PH_TABH
    cdq
    mov     ecx, PH_ROW_H
    idiv    ecx
    add     eax, dword ptr [g_pwh_scroll]
    cmp     eax, 0
    jl      gpk_done
    cmp     eax, dword ptr [g_pwh_fn]
    jae     gpk_done
    mov     ecx, dword ptr [g_pwh_fn]         ; fi = (fn-1) - disp (reversed)
    dec     ecx
    sub     ecx, eax
    lea     r10, [g_pwh_filter]               ; record index = filter[fi]
    mov     ecx, dword ptr [r10+rcx*4]
    mov     dword ptr [rbp-68], ecx
    mov     eax, dword ptr [rbp-56]           ; purge region: pt.x >= clientW-2-PURGE
    sub     eax, 2 + PH_PURGE_W
    cmp     dword ptr [rbp-48], eax
    jl      gpk_done
    mov     ecx, dword ptr [rbp-68]
    call    pwh_remove
    mov     dword ptr [g_dirty], 1
    mov     dword ptr [g_pwh_dirty], 1        ; persist on close (view mode has no Save)
    call    pwh_build_tabs                    ; a purge may have emptied a tab
    call    pwh_build_filter
    mov     eax, dword ptr [g_pwh_scroll]     ; keep scroll in range
    cmp     eax, dword ptr [g_pwh_fn]
    jb      gpk_repaint
    mov     dword ptr [g_pwh_scroll], 0
gpk_repaint:
    WINCALL InvalidateRect, qword ptr [rbp-32], 0, 1
gpk_done:
    FRAME_EPILOG
    ret
gui_pwhist_click endp

; pwhist_proc - DLG_PWHIST procedure (themed).
pwhist_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      ph_init
    cmp     rdx, WM_COMMAND
    je      ph_cmd
    cmp     rdx, WM_CTLCOLORSTATIC
    je      ph_col
    cmp     rdx, WM_CTLCOLORBTN
    je      ph_col
    cmp     rdx, WM_CTLCOLORDLG
    je      ph_col
    cmp     rdx, WM_PAINT
    je      ph_paint
    cmp     rdx, WM_ERASEBKGND
    je      ph_erase
    cmp     rdx, WM_DRAWITEM
    je      ph_draw
    cmp     rdx, WM_MOUSEWHEEL
    je      ph_wheel
    xor     eax, eax
    jmp     ph_ret
ph_col:
    call    theme_ctlcolor
    jmp     ph_ret
ph_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     ph_ret
ph_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     ph_ret
ph_draw:
    mov     r10, r9
    mov     eax, dword ptr [r10+4]
    cmp     eax, IDC_PH_LIST
    jne     ph_draw_def
    mov     rcx, r9
    call    gui_draw_pwhist
    mov     eax, 1
    jmp     ph_ret
ph_draw_def:
    mov     rcx, r9
    call    theme_drawitem
    mov     eax, 1
    jmp     ph_ret
ph_wheel:
    mov     eax, r8d                           ; wParam hi word = wheel delta (signed)
    sar     eax, 16
    test    eax, eax
    jz      ph_wheel_done
    jle     ph_wheel_down
    mov     eax, dword ptr [g_pwh_scroll]     ; up
    dec     eax
    jns     ph_wheel_set
    xor     eax, eax
    jmp     ph_wheel_set
ph_wheel_down:
    mov     eax, dword ptr [g_pwh_fn]         ; rows in the selected tab
    dec     eax                               ; max scroll = fn-1
    mov     ecx, dword ptr [g_pwh_scroll]
    inc     ecx
    cmp     ecx, eax
    jle     @F
    mov     ecx, eax
@@: mov     eax, ecx
    cmp     eax, 0
    jns     ph_wheel_set
    xor     eax, eax
ph_wheel_set:
    mov     dword ptr [g_pwh_scroll], eax
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_PH_LIST
    WINCALL InvalidateRect, rax, 0, 1
ph_wheel_done:
    mov     eax, 1
    jmp     ph_ret
ph_unh:
    xor     eax, eax
    jmp     ph_ret
ph_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDOK
    call    theme_attach
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    mov     dword ptr [g_pwh_scroll], 0
    mov     dword ptr [g_pwh_tab], 0          ; start on the first tile's tab
    mov     eax, 1
    jmp     ph_ret
ph_cmd:
    movzx   eax, r8w
    cmp     eax, IDC_PH_LIST
    je      ph_list
    cmp     eax, IDOK
    je      ph_close
    cmp     eax, IDCANCEL
    je      ph_close
    xor     eax, eax
    jmp     ph_ret
ph_list:
    mov     rcx, qword ptr [rbp-8]
    call    gui_pwhist_click
    mov     eax, 1
    jmp     ph_ret
ph_close:
    WINCALL EndDialog, qword ptr [rbp-8], 0
    mov     eax, 1
ph_ret:
    mov     rsp, rbp
    pop     rbp
    ret
pwhist_proc endp

; gui_open_pwhist(rcx = hdlg) - open the password-history browser (modal).
gui_open_pwhist proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [g_pwh_dirty], 0
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_PWHIST, qword ptr [rbp-24], \
            addr pwhist_proc, 0
    cmp     dword ptr [g_pwh_dirty], 0        ; a purge -> re-save the entry so it sticks
    je      gop_done
    mov     rcx, qword ptr [rbp-24]
    call    gui_commit
gop_done:
    FRAME_EPILOG
    ret
gui_open_pwhist endp

; gui_wstrcpy(rcx=dst, rdx=src wide) -> rax = ptr to the terminating NUL in dst.  Leaf.
gui_wstrcpy proc
    xor     r8d, r8d
gwsc_l:
    movzx   eax, word ptr [rdx+r8*2]
    mov     word ptr [rcx+r8*2], ax
    test    eax, eax
    jz      gwsc_d
    inc     r8d
    jmp     gwsc_l
gwsc_d:
    lea     rax, [rcx+r8*2]
    ret
gui_wstrcpy endp

; gui_u32w(ecx=val, rdx=dst) -> rax = ptr past the written decimal (NUL-terminated).
gui_u32w proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rdx             ; dst
    mov     eax, ecx
    lea     r10, [rbp-40]                        ; reversed-digit scratch
    xor     r8d, r8d
    mov     r9d, 10
gu32_dl:
    xor     edx, edx
    div     r9d
    add     dl, '0'
    mov     byte ptr [r10+r8], dl
    inc     r8d
    test    eax, eax
    jnz     gu32_dl
    mov     rcx, qword ptr [rbp-24]
    xor     r11d, r11d
gu32_wl:
    dec     r8d
    movzx   eax, byte ptr [r10+r8]
    mov     word ptr [rcx+r11*2], ax
    inc     r11d
    test    r8d, r8d
    jnz     gu32_wl
    mov     word ptr [rcx+r11*2], 0
    lea     rax, [rcx+r11*2]
    FRAME_EPILOG
    ret
gui_u32w endp

; ===========================================================================
; gui_show_health(rcx = parent hwnd) - E6 dashboard: run vault_health on the
;   open vault and show a summary message box (weak / reused / stale counts).
;   Bound to Ctrl+H.  With no vault open it explains that instead.
; ===========================================================================
public gui_show_health
gui_show_health proc frame
    FRAME_PROLOG 64
    ; [rbp-24]=parent  [rbp-48]=weak [rbp-44]=reused [rbp-40]=old [rbp-36]=total
    mov     qword ptr [rbp-24], rcx
    lea     rcx, [rbp-48]
    call    vault_health
    cmp     dword ptr [rbp-36], 0
    jne     gsh_build
    WINCALL gui_msgbox, qword ptr [rbp-24], addr hb_locked, addr t_health, \
            <MB_OK or MB_ICONINFORMATION>
    FRAME_EPILOG
    ret
gsh_build:
    lea     rcx, [g_health_msgw]
    lea     rdx, [hb_l1]
    call    gui_wstrcpy                         ; "Entries: "
    mov     ecx, dword ptr [rbp-36]             ; total
    mov     rdx, rax
    call    gui_u32w
    mov     rcx, rax
    lea     rdx, [hb_crlf]
    call    gui_wstrcpy
    mov     rcx, rax
    lea     rdx, [hb_l2]
    call    gui_wstrcpy                         ; "Weak passwords: "
    mov     ecx, dword ptr [rbp-48]             ; weak
    mov     rdx, rax
    call    gui_u32w
    mov     rcx, rax
    lea     rdx, [hb_crlf]
    call    gui_wstrcpy
    mov     rcx, rax
    lea     rdx, [hb_l3]
    call    gui_wstrcpy                         ; "Reused passwords: "
    mov     ecx, dword ptr [rbp-44]             ; reused
    mov     rdx, rax
    call    gui_u32w
    mov     rcx, rax
    lea     rdx, [hb_crlf]
    call    gui_wstrcpy
    mov     rcx, rax
    lea     rdx, [hb_l4]
    call    gui_wstrcpy                         ; "Unchanged over a year: "
    mov     ecx, dword ptr [rbp-40]             ; old
    mov     rdx, rax
    call    gui_u32w
    WINCALL gui_msgbox, qword ptr [rbp-24], addr g_health_msgw, addr t_health, \
            <MB_OK or MB_ICONINFORMATION>
    FRAME_EPILOG
    ret
gui_show_health endp

; ===========================================================================
; gui_seclock_warn(rcx = hdlg) - C3: show the "Secrets not pinned to RAM"
;   warning with the actual Win32 error codes appended (VirtualLock + the
;   working-set-grow), so a constrained environment can be diagnosed.
; ===========================================================================
public gui_seclock_warn
gui_seclock_warn proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    lea     rcx, [g_lockmsg]
    lea     rdx, [s_nolock]
    call    gui_wstrcpy
    mov     rcx, rax
    lea     rdx, [hb_crlf]
    call    gui_wstrcpy
    mov     rcx, rax
    lea     rdx, [hb_crlf]
    call    gui_wstrcpy                         ; blank line
    mov     rcx, rax
    lea     rdx, [s_lkdiag1]                    ; "Diagnostic - VirtualLock error "
    call    gui_wstrcpy
    mov     ecx, dword ptr [g_lockerr_vl]
    mov     rdx, rax
    call    gui_u32w
    mov     rcx, rax
    lea     rdx, [s_lkdiag2]                    ; ", working-set-grow error "
    call    gui_wstrcpy
    mov     ecx, dword ptr [g_lockerr_wss]
    mov     rdx, rax
    call    gui_u32w
    mov     rcx, rax
    lea     rdx, [s_lkdiag3]                    ; ". (VirtualLock is limited by ...)"
    call    gui_wstrcpy
    WINCALL gui_msgbox, qword ptr [rbp-24], addr g_lockmsg, addr t_nolock, \
            <MB_OK or MB_ICONWARNING>
    FRAME_EPILOG
    ret
gui_seclock_warn endp

; =============================================================================
; gui_import(rcx = hdlg) -> eax = entries imported.  Pick a .vaultz file: the
;   only accepted format is a Vordr WinZip-AES archive (PK + method 99); the
;   password is prompted via DLG_IMPPW, then zi_stage decrypts vordr.json and
;   the entries are appended, resealed and refreshed.
; =============================================================================
public gui_import
gui_import proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx             ; hdlg
    mov     dword ptr [rbp-64], 0               ; imported count
    mov     qword ptr [rbp-32], 0               ; raw ptr (0 = not allocated)
    mov     qword ptr [rbp-56], 0               ; foreign body ptr (.vordr path)
    lea     rax, [g_impfilter]
    mov     qword ptr [g_pickfilter], rax
    mov     rcx, qword ptr [rbp-24]
    xor     edx, edx
    call    img_pick
    test    eax, eax
    jz      gim_done
    lea     rcx, [g_imgpath]
    lea     rdx, [rbp-32]                       ; *raw
    lea     r8, [rbp-40]                        ; *rawlen
    call    read_file
    test    eax, eax
    jz      gim_read_ok
    WINCALL gui_msgbox, qword ptr [rbp-24], addr imp_g_bad, addr imp_g_title, 030h
    jmp     gim_done
gim_read_ok:
    ; ---- a .vordr vault?  decided by MAGIC, never by the extension --------------
    mov     r10, qword ptr [rbp-32]
    cmp     dword ptr [rbp-40], 8
    jb      gim_notvordr
    cmp     dword ptr [r10], VAULT_MAGIC
    je      gim_vault
    ; ---- else require a Vordr encrypted zip (PK + WinZip-AES method 99) ----
    mov     r10, qword ptr [rbp-32]             ; raw
    cmp     dword ptr [rbp-40], 10
    jb      gim_notvordr
    cmp     byte ptr [r10], 'P'
    jne     gim_notvordr
    cmp     byte ptr [r10+1], 'K'
    jne     gim_notvordr
    cmp     word ptr [r10+8], 99                ; method 99 = WinZip AES
    jne     gim_notvordr
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_IMPPW, qword ptr [rbp-24], addr imppw_proc, 0
    cmp     eax, 1
    jne     gim_done
    ; ---- stage: decrypt vordr.json + collect entry titles (raw stays mapped) ----
    mov     rcx, qword ptr [rbp-32]             ; raw zip
    mov     edx, dword ptr [rbp-40]
    lea     r8, [g_xlpw]                        ; UTF-16 archive password
    mov     r9d, dword ptr [g_xlpwlen]
    call    zi_stage
    mov     dword ptr [rbp-64], eax
    lea     rcx, [g_xlpw]                       ; wipe the wide pw (zi_stage kept a UTF-8 copy)
    mov     edx, 512
    call    secure_zero
    mov     dword ptr [g_xlpwlen], 0
    cmp     dword ptr [rbp-64], -3
    je      gim_wrongpw                         ; zi_stage already freed the arena + wiped pw
    cmp     dword ptr [rbp-64], 0
    jl      gim_bad
    jg      gim_sel
    call    zi_abort                            ; staged 0 entries
    WINCALL gui_msgbox, qword ptr [rbp-24], addr imp_g_none, addr imp_g_title, 030h
    jmp     gim_done
gim_notvordr:
    WINCALL gui_msgbox, qword ptr [rbp-24], addr imp_g_bad, addr imp_g_title, 030h
    jmp     gim_done
    ; ---- .vordr: decrypt the foreign vault, then reuse the same checklist ------
gim_vault:
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_IMPPW, qword ptr [rbp-24], addr imppw_proc, 0
    cmp     eax, 1
    jne     gim_done
    lea     rcx, [g_xlpw]                       ; -> g_cfg_pass, wiping g_xlpw at the source
    call    password_to_utf8
    mov     dword ptr [g_xlpwlen], 0
    test    eax, eax
    jz      gim_bad
    ; vault_open_foreign parks and restores every live global, so the open vault is
    ; untouched by this - and it wipes the password we hand it.
    lea     rcx, [g_imgpath]
    lea     rdx, [g_cfg_pass]
    mov     r8d, dword ptr [g_cfg_passlen]
    lea     r9, [rbp-56]                        ; -> foreign body
    call    vault_open_foreign
    mov     dword ptr [rbp-72], eax
    test    eax, eax
    jnz     gim_vwrongpw
    mov     rcx, qword ptr [rbp-56]
    call    zi_stage_vault                      ; titles into the shared staging arrays
    mov     dword ptr [rbp-64], eax
    test    eax, eax
    jz      gim_vempty
    cmp     dword ptr [g_zi_trunc], 0           ; say so BEFORE the checklist: importing a
    je      @F                                  ;   silent subset of someone's vault is
    WINCALL gui_msgbox, qword ptr [rbp-24], addr imp_v_trunc, addr t_imp_trunc,             <MB_OK or MB_ICONWARNING>           ;   exactly the surprise to avoid
@@: mov     dword ptr [g_sel_src], 1
    mov     ecx, dword ptr [rbp-64]
    call    gui_sel_all
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_SELECT, qword ptr [rbp-24], addr select_proc, 0
    cmp     eax, 1
    jne     gim_vfree                           ; cancelled -> nothing merged
    mov     dword ptr [g_merge_sel], 1          ; honour the ticks
    mov     rcx, qword ptr [rbp-56]
    call    fed_merge
    mov     dword ptr [g_merge_sel], 0
    mov     dword ptr [rbp-64], eax
    test    eax, eax
    jz      gim_vsame                           ; dedup by entry id: all already present
    mov     rcx, qword ptr [rbp-56]             ; done with the source body
    call    vault_free_foreign
    mov     qword ptr [rbp-56], 0
    mov     eax, dword ptr [rbp-64]
    jmp     gim_ok                              ; reseal + audit + "Imported N entries."
gim_vempty:
    WINCALL gui_msgbox, qword ptr [rbp-24], addr imp_v_none, addr imp_g_title, 030h
    jmp     gim_vfree
gim_vsame:
    ; Not a failure: the merge dedups by entry id, so re-importing a file this vault
    ; already holds correctly changes nothing.  Say that, with an information icon.
    WINCALL gui_msgbox, qword ptr [rbp-24], addr imp_v_same, addr imp_g_title, 040h
    jmp     gim_vfree
gim_vwrongpw:
    WINCALL gui_msgbox, qword ptr [rbp-24], addr imp_xls_wrongpw, addr imp_g_title, 030h
gim_vfree:
    mov     rcx, qword ptr [rbp-56]
    call    vault_free_foreign
    mov     qword ptr [rbp-56], 0
    jmp     gim_done
gim_sel:
    ; ---- selection screen (all entries pre-checked; import adds them as new) ----
    mov     dword ptr [g_sel_src], 1
    mov     ecx, dword ptr [rbp-64]             ; staged count
    call    gui_sel_all
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_SELECT, qword ptr [rbp-24], addr select_proc, 0
    cmp     eax, 1
    je      gim_commit
    call    zi_abort                            ; user cancelled the selection
    jmp     gim_done
gim_commit:
    call    zi_commit                           ; -> eax = entries imported
    mov     dword ptr [rbp-64], eax
    test    eax, eax
    jnz     gim_ok
    WINCALL gui_msgbox, qword ptr [rbp-24], addr imp_g_none, addr imp_g_title, 030h
    jmp     gim_done
gim_ok:
    mov     dword ptr [rbp-64], eax             ; both paths arrive with the count in eax
    call    vault_reseal
    lea     rcx, [ev_import]                    ; C5: audit the import
    mov     edx, dword ptr [rbp-64]
    call    log_result
    mov     rcx, qword ptr [rbp-24]
    call    gui_poplist
    lea     rcx, [g_imp_msgw]                   ; "Imported N entries."
    lea     rdx, [imp_g_pre]
    call    gui_wstrcpy
    mov     ecx, dword ptr [rbp-64]
    mov     rdx, rax
    call    gui_u32w
    mov     rcx, rax
    lea     rdx, [imp_g_post]
    call    gui_wstrcpy
    WINCALL gui_msgbox, qword ptr [rbp-24], addr g_imp_msgw, addr imp_g_title, 040h
    jmp     gim_done
gim_wrongpw:
    WINCALL gui_msgbox, qword ptr [rbp-24], addr imp_xls_wrongpw, addr imp_g_title, 030h
    jmp     gim_done
gim_bad:
    WINCALL gui_msgbox, qword ptr [rbp-24], addr imp_g_bad, addr imp_g_title, 030h
gim_done:
    mov     rcx, qword ptr [rbp-32]             ; free raw if still allocated (cancel path)
    test    rcx, rcx
    jz      gim_ret
    mov     rdx, qword ptr [rbp-40]
    call    mem_free
gim_ret:
    mov     eax, dword ptr [rbp-64]
    FRAME_EPILOG
    ret
gui_import endp

; gui_pg_toggle_text(rcx=hdlg, edx=ctlid, r8d=state, r9=base wide) - set a toggle
;   button's caption to "[x] "/"[ ] " + base.
; gui_pg_toggle_text(rcx=hdlg, edx=ctrlID, r8d=on(unused), r9=label) - set the
;   option control's caption to the plain label; the on/off state is rendered as
;   a Fluent pill by theme_toggle_labeled (which reads g_pg_opt), and the
;   SetDlgItemTextW here invalidates the owner-draw control so it repaints.
gui_pg_toggle_text proc frame
    FRAME_PROLOG 64   ; >= 64: keep locals clear of the callee 32-byte home area
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-28], edx
    mov     qword ptr [rbp-40], r9
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], dword ptr [rbp-28], qword ptr [rbp-40]
    FRAME_EPILOG
    ret
gui_pg_toggle_text endp

; gui_pg_sync(rcx=hdlg) - refresh all toggle captions, the style button and the
;   length readout from g_pg_opt / g_pg_style / g_pg_len.
gui_pg_sync proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    xor     r8d, r8d
    test    dword ptr [g_pg_opt], PWCLASS_U
    setnz   r8b
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_PG_UP
    lea     r9, [pg_lbl_up]
    call    gui_pg_toggle_text
    xor     r8d, r8d
    test    dword ptr [g_pg_opt], PWCLASS_L
    setnz   r8b
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_PG_LO
    lea     r9, [pg_lbl_lo]
    call    gui_pg_toggle_text
    xor     r8d, r8d
    test    dword ptr [g_pg_opt], PWCLASS_D
    setnz   r8b
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_PG_DI
    lea     r9, [pg_lbl_di]
    call    gui_pg_toggle_text
    xor     r8d, r8d
    test    dword ptr [g_pg_opt], PWCLASS_S
    setnz   r8b
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_PG_SY
    lea     r9, [pg_lbl_sy]
    call    gui_pg_toggle_text
    ; style button
    lea     rcx, [g_pg_tmpw]
    lea     rdx, [pg_style_pre]
    call    gui_wstrcpy
    mov     rcx, rax
    mov     eax, dword ptr [g_pg_style]
    lea     r10, [pg_snames]
    mov     rdx, qword ptr [r10+rax*8]
    call    gui_wstrcpy
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_PG_STYLE, addr g_pg_tmpw
    ; length readout
    mov     ecx, dword ptr [g_pg_len]
    lea     rdx, [g_pg_tmpw]
    call    gui_u32w
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_PG_LENVAL, addr g_pg_tmpw
    FRAME_EPILOG
    ret
gui_pg_sync endp

; gui_pg_regen(rcx=hdlg) - generate a fresh password into g_genout/g_genout_w and
;   show it + the entropy estimate.
gui_pg_regen proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    lea     rcx, [g_genout]
    mov     edx, dword ptr [g_pg_len]
    mov     r8d, dword ptr [g_pg_style]
    mov     r9d, dword ptr [g_pg_opt]
    mov     dword ptr [g_pwgen_outcap], 260     ; E16: g_genout capacity
    call    pwgen_ex
    mov     dword ptr [g_pg_bits], eax
    test    eax, eax
    jnz     pgr_ok
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_PG_OUT, 0
    jmp     pgr_bits
pgr_ok:
    lea     r10, [g_genout]
    xor     ecx, ecx
pgr_sl:
    cmp     byte ptr [r10+rcx], 0
    je      pgr_sld
    inc     ecx
    cmp     ecx, 258
    jb      pgr_sl
pgr_sld:
    mov     dword ptr [rbp-28], ecx
    lea     rcx, [g_genout]
    mov     edx, dword ptr [rbp-28]
    lea     r8, [g_genout_w]
    mov     r9d, 258
    call    gui_towide
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_PG_OUT, addr g_genout_w
pgr_bits:
    mov     ecx, dword ptr [g_pg_bits]
    lea     rdx, [g_pg_tmpw]
    call    gui_u32w
    mov     rcx, rax
    lea     rdx, [pg_bits_suf]
    call    gui_wstrcpy
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_PG_BITS, addr g_pg_tmpw
    FRAME_EPILOG
    ret
gui_pg_regen endp

; gui_pg_apply() - write the current password into the target secret row on the
;   main vault window (g_vaulthwnd), grade it and mark dirty.
gui_pg_apply proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [g_pg_target], 0
    jl      pga_done
    ; write to the row whose Generate was clicked (g_pg_target).  The pwgen dialog
    ; is modal so rows can't change under us; DO NOT re-resolve to "the first
    ; secret" - that would send every tile's generated password to the same field.
pga_have:
    lea     r10, [g_genout]
    xor     ecx, ecx
pga_sl:
    cmp     byte ptr [r10+rcx], 0
    je      pga_sld
    inc     ecx
    cmp     ecx, 258
    jb      pga_sl
pga_sld:
    mov     dword ptr [rbp-28], ecx
    lea     rcx, [g_genout]
    mov     edx, dword ptr [rbp-28]
    call    gui_pw_grade
    shl     eax, FDF_PWLVL_SHIFT
    mov     ecx, dword ptr [g_pg_target]
    imul    ecx, ecx, DESCSZ
    lea     r11, [g_fields]
    add     r11, rcx
    mov     edx, dword ptr [r11+FD_FLAGS]
    and     edx, NOT FDF_PWLVL_MASK
    or      edx, eax
    mov     dword ptr [r11+FD_FLAGS], edx
    mov     ecx, dword ptr [g_pg_target]
    mov     edx, DS_VALUE
    call    dynid
    WINCALL SetDlgItemTextW, qword ptr [g_vaulthwnd], eax, addr g_genout_w
    mov     dword ptr [g_dirty], 1
    mov     ecx, dword ptr [g_pg_target]         ; repaint the strength badge
    mov     edx, DS_SBADGE
    call    dynid
    mov     rcx, qword ptr [g_vaulthwnd]
    mov     edx, eax
    call    GetDlgItem
    WINCALL InvalidateRect, rax, 0, 1
pga_done:
    FRAME_EPILOG
    ret
gui_pg_apply endp

; =============================================================================
; pwgen_proc - DLG_PWGEN dialog procedure (password generator window).
; =============================================================================
pwgen_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      pp_init
    cmp     rdx, WM_COMMAND
    je      pp_cmd
    cmp     rdx, WM_HSCROLL_
    je      pp_hscroll
    cmp     rdx, WM_CTLCOLORSTATIC
    je      pp_col
    cmp     rdx, WM_CTLCOLOREDIT
    je      pp_col
    cmp     rdx, WM_CTLCOLORBTN
    je      pp_col
    cmp     rdx, WM_CTLCOLORDLG
    je      pp_col
    cmp     rdx, WM_PAINT
    je      pp_paint
    cmp     rdx, WM_ERASEBKGND
    je      pp_erase
    cmp     rdx, WM_DRAWITEM
    je      pp_draw
    xor     eax, eax
    jmp     pp_ret
pp_col:
    call    theme_ctlcolor
    jmp     pp_ret
pp_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     pp_ret
pp_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     pp_ret
pp_draw:
    mov     r10, r9
    mov     eax, dword ptr [r10+4]             ; DRAWITEMSTRUCT.CtlID
    cmp     eax, IDC_PG_UP
    je      pp_d_up
    cmp     eax, IDC_PG_LO
    je      pp_d_lo
    cmp     eax, IDC_PG_DI
    je      pp_d_di
    cmp     eax, IDC_PG_SY
    je      pp_d_sy
    mov     rcx, r9
    call    theme_drawitem
    jmp     pp_ret
pp_d_up:
    mov     edx, PWCLASS_U
    jmp     pp_d_tog
pp_d_lo:
    mov     edx, PWCLASS_L
    jmp     pp_d_tog
pp_d_di:
    mov     edx, PWCLASS_D
    jmp     pp_d_tog
pp_d_sy:
    mov     edx, PWCLASS_S
pp_d_tog:
    and     edx, dword ptr [g_pg_opt]          ; state = option bit (nonzero = on)
    mov     rcx, r9
    call    theme_toggle_labeled
    jmp     pp_ret
pp_unh:
    xor     eax, eax
    jmp     pp_ret
pp_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDOK
    call    theme_attach
    cmp     dword ptr [g_pg_target], 0          ; R7.4: dock-launched (target = -1) copies to
    jge     pp_init_lbl                          ;   the clipboard, so the button says "Copy";
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDOK, addr gt_copy  ; field-launched keeps "Use"
pp_init_lbl:
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_PG_LEN, TBM_SETRANGE, 1, 400006h
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_PG_LEN, TBM_SETPOS, 1, dword ptr [g_pg_len]
    mov     rcx, qword ptr [rbp-8]
    call    gui_pg_sync
    mov     rcx, qword ptr [rbp-8]
    call    gui_pg_regen
    mov     eax, 1
    jmp     pp_ret
pp_hscroll:
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_PG_LEN, TBM_GETPOS, 0, 0
    mov     dword ptr [g_pg_len], eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_pg_sync
    mov     rcx, qword ptr [rbp-8]
    call    gui_pg_regen
    mov     eax, 1
    jmp     pp_ret
pp_cmd:
    movzx   eax, r8w
    cmp     eax, IDOK
    je      pp_use
    cmp     eax, IDCANCEL
    je      pp_cancel
    cmp     eax, IDC_PG_REGEN
    je      pp_regen
    cmp     eax, IDC_PG_STYLE
    je      pp_style
    cmp     eax, IDC_PG_UP
    je      pp_tup
    cmp     eax, IDC_PG_LO
    je      pp_tlo
    cmp     eax, IDC_PG_DI
    je      pp_tdi
    cmp     eax, IDC_PG_SY
    je      pp_tsy
    xor     eax, eax
    jmp     pp_ret
pp_regen:
    mov     rcx, qword ptr [rbp-8]
    call    gui_pg_regen
    mov     eax, 1
    jmp     pp_ret
pp_style:
    mov     eax, dword ptr [g_pg_style]
    inc     eax
    cmp     eax, 5
    jb      @F
    xor     eax, eax
@@: mov     dword ptr [g_pg_style], eax
    jmp     pp_syncgen
pp_tup:
    xor     dword ptr [g_pg_opt], PWCLASS_U
    jmp     pp_syncgen
pp_tlo:
    xor     dword ptr [g_pg_opt], PWCLASS_L
    jmp     pp_syncgen
pp_tdi:
    xor     dword ptr [g_pg_opt], PWCLASS_D
    jmp     pp_syncgen
pp_tsy:
    xor     dword ptr [g_pg_opt], PWCLASS_S
pp_syncgen:
    mov     rcx, qword ptr [rbp-8]
    call    gui_pg_sync
    mov     rcx, qword ptr [rbp-8]
    call    gui_pg_regen
    mov     eax, 1
    jmp     pp_ret
pp_use:
    cmp     dword ptr [g_pg_target], 0           ; R7.4: dock-launched -> clipboard (auto-clear),
    jl      pp_use_copy                          ;   field-launched -> write the secret row
    call    gui_pg_apply
    jmp     pp_use_wipe
pp_use_copy:
    mov     rcx, qword ptr [rbp-8]               ; hdlg (arms the clip auto-clear timer)
    lea     rdx, [g_genout_w]                    ; the generated password (wide)
    call    gui_copy
pp_use_wipe:
    lea     rcx, [g_genout]                      ; wipe plaintext scratch
    mov     edx, 260
    call    secure_zero
    lea     rcx, [g_genout_w]
    mov     edx, 520
    call    secure_zero
    WINCALL EndDialog, qword ptr [rbp-8], 1
    mov     eax, 1
    jmp     pp_ret
pp_cancel:
    lea     rcx, [g_genout]
    mov     edx, 260
    call    secure_zero
    lea     rcx, [g_genout_w]
    mov     edx, 520
    call    secure_zero
    WINCALL EndDialog, qword ptr [rbp-8], 0
    mov     eax, 1
pp_ret:
    mov     rsp, rbp
    pop     rbp
    ret
pwgen_proc endp

; ges_wipepw - zero the export password buffers
ges_wipepw proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_xlpw]
    mov     edx, 512
    call    secure_zero
    lea     rcx, [g_xlpw2]
    mov     edx, 512
    call    secure_zero
    mov     dword ptr [g_xlpwlen], 0
    FRAME_EPILOG
    ret
ges_wipepw endp

; =============================================================================
; gui_xlpw_policy() -> eax = 0 ok / 1 too short / 2 too few classes.
;   Scans the wide (UTF-16) export password in g_xlpw against the active
;   g_cfg_pwminlen / g_cfg_pwminclasses policy - the same rule the master
;   password must satisfy.  Leaf proc: deliberately does NOT go through
;   password_to_utf8 / g_cfg_pass (that buffer holds the live master password
;   used to reseal the vault, and password_to_utf8 wipes its input).
; =============================================================================
gui_xlpw_policy proc
    lea     r9, [g_xlpw]
    xor     r8d, r8d                     ; unit index
    xor     r10d, r10d                  ; code-point count
    xor     r11d, r11d                  ; class mask (1=U 2=L 4=D 8=S)
xpol_loop:
    movzx   eax, word ptr [r9+r8*2]
    test    eax, eax
    jz      xpol_eval
    inc     r8d
    mov     edx, eax                    ; low surrogate (DC00-DFFF): tail of a
    and     edx, 0FC00h                 ;   pair -> not a new code point
    cmp     edx, 0DC00h
    je      xpol_symonly
    inc     r10d                        ; new code point
    cmp     eax, 'A'
    jb      xpol_lo
    cmp     eax, 'Z'
    ja      xpol_lo
    or      r11d, 1
    jmp     xpol_loop
xpol_lo:
    cmp     eax, 'a'
    jb      xpol_di
    cmp     eax, 'z'
    ja      xpol_di
    or      r11d, 2
    jmp     xpol_loop
xpol_di:
    cmp     eax, '0'
    jb      xpol_sym
    cmp     eax, '9'
    ja      xpol_sym
    or      r11d, 4
    jmp     xpol_loop
xpol_sym:
    or      r11d, 8                     ; non-alnum (incl. non-ASCII) -> symbol
    jmp     xpol_loop
xpol_symonly:
    or      r11d, 8
    jmp     xpol_loop
xpol_eval:
    mov     eax, dword ptr [g_cfg_pwminlen]
    cmp     r10d, eax
    jb      xpol_short
    xor     eax, eax                    ; popcount of the class mask
    test    r11d, 1
    jz      @F
    inc     eax
@@: test    r11d, 2
    jz      @F
    inc     eax
@@: test    r11d, 4
    jz      @F
    inc     eax
@@: test    r11d, 8
    jz      @F
    inc     eax
@@: cmp     eax, dword ptr [g_cfg_pwminclasses]
    jb      xpol_few
    xor     eax, eax
    ret
xpol_short:
    mov     eax, 1
    ret
xpol_few:
    mov     eax, 2
    ret
gui_xlpw_policy endp

; =============================================================================
; xlpw_proc - DLG_XLPW dialog procedure (export password + confirm).  Raw frame.
; =============================================================================
xlpw_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      xpp_init
    cmp     rdx, WM_COMMAND
    je      xpp_cmd
    cmp     rdx, WM_CTLCOLORSTATIC
    je      xpp_col
    cmp     rdx, WM_CTLCOLOREDIT
    je      xpp_col
    cmp     rdx, WM_CTLCOLORBTN
    je      xpp_col
    cmp     rdx, WM_CTLCOLORDLG
    je      xpp_col
    cmp     rdx, WM_PAINT
    je      xpp_paint
    cmp     rdx, WM_ERASEBKGND
    je      xpp_erase
    cmp     rdx, WM_DRAWITEM
    je      xpp_draw
    xor     eax, eax
    jmp     xpp_ret
xpp_col:
    call    theme_ctlcolor
    jmp     xpp_ret
xpp_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     xpp_ret
xpp_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     xpp_ret
xpp_draw:
    mov     rcx, r9
    call    theme_drawitem
    jmp     xpp_ret
xpp_unh:
    xor     eax, eax
    jmp     xpp_ret
xpp_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDOK
    call    theme_attach
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    lea     rax, [exp_pw_vordr]                 ; the blurb must describe the format the
    cmp     dword ptr [g_exp_iszip], 0          ;   user actually picked, not whatever the
    je      @F                                  ;   .rc happened to say when ZIP was the
    lea     rax, [exp_pw_zip]                   ;   only option
@@: WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_XP_WARN, rax
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_XP_PW, EM_SETCUEBANNER, 1, addr cue_xppw
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_XP_PW2, EM_SETCUEBANNER, 1, addr cue_xppw2
    mov     dword ptr [g_uline_ctl], 0          ; start with default (accent) underlines
    mov     dword ptr [g_uline_ctl2], 0
    mov     qword ptr [g_uline_br], 0
    mov     qword ptr [g_uline_br2], 0
    mov     eax, 1
    jmp     xpp_ret
xpp_cmd:
    movzx   eax, r8w
    mov     r10d, r8d
    shr     r10d, 16                            ; HIWORD(wParam) = notification code
    cmp     r10d, EN_SETFOCUS                   ; focus moved -> repaint underlines
    je      xpp_refocus
    cmp     r10d, EN_KILLFOCUS
    je      xpp_refocus
    cmp     eax, IDOK
    je      xpp_ok
    cmp     eax, IDCANCEL
    je      xpp_cancel
    cmp     eax, IDC_XP_PW
    je      xpp_pwchg
    cmp     eax, IDC_XP_PW2
    je      xpp_pwchg
    xor     eax, eax
    jmp     xpp_ret
xpp_refocus:
    WINCALL InvalidateRect, qword ptr [rbp-8], 0, 1
    mov     eax, 1
    jmp     xpp_ret
xpp_pwchg:
    cmp     r10d, EN_CHANGE
    jne     xpp_unh
    mov     rcx, qword ptr [rbp-8]              ; a password box changed -> recolour
    call    gui_xlpw_strength
    mov     eax, 1
    jmp     xpp_ret
xpp_ok:
    WINCALL GetDlgItemTextW, qword ptr [rbp-8], IDC_XP_PW, addr g_xlpw, 255
    mov     dword ptr [rbp-16], eax             ; length in chars
    WINCALL GetDlgItemTextW, qword ptr [rbp-8], IDC_XP_PW2, addr g_xlpw2, 255
    cmp     dword ptr [rbp-16], 0
    je      xpp_empty
    lea     rcx, [g_xlpw]
    lea     rdx, [g_xlpw2]
    call    gui_wstr_eq
    test    eax, eax
    jz      xpp_mismatch
    call    gui_xlpw_policy                      ; enforce the vault password policy
    test    eax, eax
    jz      xpp_polok
    cmp     eax, 1
    jne     xpp_polfew
    WINCALL MessageBoxW, qword ptr [rbp-8], addr s_pwshort, addr xp_mm_title, 030h
    mov     eax, 1
    jmp     xpp_ret
xpp_polfew:
    WINCALL MessageBoxW, qword ptr [rbp-8], addr s_pwclasses, addr xp_mm_title, 030h
    mov     eax, 1
    jmp     xpp_ret
xpp_polok:
    mov     eax, dword ptr [rbp-16]
    shl     eax, 1                               ; bytes = chars * 2
    mov     dword ptr [g_xlpwlen], eax
    lea     rcx, [g_xlpw2]                       ; wipe the confirm copy
    mov     edx, 512
    call    secure_zero
    mov     dword ptr [g_uline_ctl], 0           ; drop the underline overrides
    mov     dword ptr [g_uline_ctl2], 0
    mov     qword ptr [g_uline_br], 0
    mov     qword ptr [g_uline_br2], 0
    WINCALL EndDialog, qword ptr [rbp-8], 1
    mov     eax, 1
    jmp     xpp_ret
xpp_empty:
    WINCALL MessageBoxW, qword ptr [rbp-8], addr xp_mm_empty, addr xp_mm_title, 030h
    mov     eax, 1
    jmp     xpp_ret
xpp_mismatch:
    WINCALL MessageBoxW, qword ptr [rbp-8], addr xp_mm_mismatch, addr xp_mm_title, 030h
    mov     eax, 1
    jmp     xpp_ret
xpp_cancel:
    lea     rcx, [g_xlpw]
    mov     edx, 512
    call    secure_zero
    lea     rcx, [g_xlpw2]
    mov     edx, 512
    call    secure_zero
    mov     dword ptr [g_uline_ctl], 0           ; drop the underline overrides
    mov     dword ptr [g_uline_ctl2], 0
    mov     qword ptr [g_uline_br], 0
    mov     qword ptr [g_uline_br2], 0
    WINCALL EndDialog, qword ptr [rbp-8], 0
    mov     eax, 1
xpp_ret:
    mov     rsp, rbp
    pop     rbp
    ret
xlpw_proc endp

; =============================================================================
; imppw_proc - DLG_IMPPW dialog procedure: prompt for the archive password
;   (single field, no confirm, no policy check) to open a Vordr WinZip-AES
;   .vaultz for import.  Fills g_xlpw / g_xlpwlen.  Raw frame.
; =============================================================================
; =============================================================================
; C9 - master-password reminder (docs/SYSITEM_DESIGN.md).
;   Under TPM Unlock the password is never typed, so it rots.  After PwVerifyDays we
;   ask for it once per unlock.  This is a REMINDER: "Not now" always works, nothing is
;   withheld, and TPM enrolment is never revoked - if the password really has been
;   forgotten, the vault is open right now and the useful advice is to export while
;   that is still true.  The dialog says exactly that.
; =============================================================================
; pwremind_proc - returns 1 from EndDialog once the password has been confirmed.
pwremind_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      rmp_init
    cmp     rdx, WM_COMMAND
    je      rmp_cmd
    cmp     rdx, WM_CTLCOLORSTATIC
    je      rmp_col
    cmp     rdx, WM_CTLCOLOREDIT
    je      rmp_col
    cmp     rdx, WM_CTLCOLORBTN
    je      rmp_col
    cmp     rdx, WM_CTLCOLORDLG
    je      rmp_col
    cmp     rdx, WM_PAINT
    je      rmp_paint
    cmp     rdx, WM_ERASEBKGND
    je      rmp_erase
    cmp     rdx, WM_DRAWITEM
    je      rmp_draw
    xor     eax, eax
    jmp     rmp_ret
rmp_col:
    call    theme_ctlcolor
    jmp     rmp_ret
rmp_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     rmp_ret
rmp_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     rmp_ret
rmp_draw:
    mov     rcx, r9
    call    theme_drawitem
    jmp     rmp_ret
rmp_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDOK
    call    theme_attach
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_RM_PW, EM_SETCUEBANNER, 1, addr cue_rmpw
    mov     eax, 1
    jmp     rmp_ret
rmp_cmd:
    movzx   eax, r8w
    cmp     eax, IDOK
    je      rmp_ok
    cmp     eax, IDCANCEL
    je      rmp_cancel
    xor     eax, eax
    jmp     rmp_ret
rmp_ok:
    WINCALL GetDlgItemTextW, qword ptr [rbp-8], IDC_RM_PW, addr g_pwbuf, 1023
    test    eax, eax
    jz      rmp_again                            ; empty -> just ask again
    lea     rcx, [g_pwbuf]
    call    password_to_utf8                     ; -> g_cfg_pass; wipes g_pwbuf
    test    eax, eax
    jz      rmp_again
    lea     rcx, [g_cfg_pass]                    ; vault_pw_check wipes g_cfg_pass itself,
    mov     edx, dword ptr [g_cfg_passlen]       ;   whichever way the comparison goes
    call    vault_pw_check
    test    eax, eax
    jz      rmp_bad
    WINCALL EndDialog, qword ptr [rbp-8], 1
    mov     eax, 1
    jmp     rmp_ret
rmp_bad:
    WINCALL gui_msgbox, qword ptr [rbp-8], addr rm_wrong, addr rm_title, \
            <MB_OK or MB_ICONWARNING>
rmp_again:
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_RM_PW, 0
    mov     eax, 1
    jmp     rmp_ret
rmp_cancel:
    WINCALL EndDialog, qword ptr [rbp-8], 0      ; "Not now" is always available
    mov     eax, 1
rmp_ret:
    mov     rsp, rbp
    pop     rbp
    ret
pwremind_proc endp

; gui_pwremind() - ask for the master password if the reminder is due.  Called after a
;   successful TPM auto-unlock only: a normal password unlock has just proved the user
;   knows it, and stamps the vault itself.
gui_pwremind proc frame
    FRAME_PROLOG 72                              ; 72 -> 80 bytes: the FILETIME slot must
                                                 ;   clear DialogBoxParamW's home area
    ; [rbp-24] = now, [rbp-32] = its FILETIME landing slot
    lea     rcx, [rbp-32]
    call    GetSystemTimeAsFileTime
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [rbp-24], rax
ifdef DBG_TRACE
    ; Test builds only: HKCU ...\Vordr\PwVerifyNow = 1 fires the reminder on EVERY
    ; unlock, so the dialog can be seen without waiting out the interval or hand-editing
    ; a stamp.  It bypasses the interval entirely, including 0 = off.  Never compiled
    ; into a release build - a release must not have a registry switch that changes when
    ; a master password is asked for.
    WINCALL cfg_get_dword, addr wv_pwnow, 0, addr g_pwnow_lock
    test    eax, eax
    jnz     gpr_show
endif
    cmp     dword ptr [g_pwdays], 0
    je      gpr_done                             ; reminder switched off
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [g_pwdays]
    call    vault_pw_due
    test    eax, eax
    jz      gpr_done
gpr_show:
    ; A master password is being typed, so honour the secure-desktop setting exactly as
    ; the unlock and export prompts do.
    cmp     dword ptr [g_secunlock], 0
    je      gpr_normal
    mov     ecx, DLG_PWREMIND
    lea     rdx, [pwremind_proc]
    call    gui_secdesk_show
    jmp     gpr_res
gpr_normal:
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_PWREMIND, qword ptr [g_vaulthwnd], \
            addr pwremind_proc, 0
gpr_res:
    cmp     rax, 1
    jne     gpr_done                             ; dismissed - ask again next unlock
    mov     rcx, qword ptr [rbp-24]              ; confirmed: restart the clock
    call    vault_pwverify_set
    test    eax, eax
    jz      gpr_done
    call    vault_reseal                         ; on a read-only vault this is a no-op and
                                                 ;   the reminder simply returns next time
gpr_done:
    call    gui_wipepw
    FRAME_EPILOG
    ret
gui_pwremind endp

imppw_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      ipp_init
    cmp     rdx, WM_COMMAND
    je      ipp_cmd
    cmp     rdx, WM_CTLCOLORSTATIC
    je      ipp_col
    cmp     rdx, WM_CTLCOLOREDIT
    je      ipp_col
    cmp     rdx, WM_CTLCOLORBTN
    je      ipp_col
    cmp     rdx, WM_CTLCOLORDLG
    je      ipp_col
    cmp     rdx, WM_PAINT
    je      ipp_paint
    cmp     rdx, WM_ERASEBKGND
    je      ipp_erase
    cmp     rdx, WM_DRAWITEM
    je      ipp_draw
    xor     eax, eax
    jmp     ipp_ret
ipp_col:
    call    theme_ctlcolor
    jmp     ipp_ret
ipp_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     ipp_ret
ipp_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     ipp_ret
ipp_draw:
    mov     rcx, r9
    call    theme_drawitem
    jmp     ipp_ret
ipp_unh:
    xor     eax, eax
    jmp     ipp_ret
ipp_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDOK
    call    theme_attach
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_XP_PW, EM_SETCUEBANNER, 1, addr cue_ippw
    mov     eax, 1
    jmp     ipp_ret
ipp_cmd:
    movzx   eax, r8w
    cmp     eax, IDOK
    je      ipp_ok
    cmp     eax, IDCANCEL
    je      ipp_cancel
    xor     eax, eax
    jmp     ipp_ret
ipp_ok:
    WINCALL GetDlgItemTextW, qword ptr [rbp-8], IDC_XP_PW, addr g_xlpw, 255
    test    eax, eax
    jz      ipp_empty
    shl     eax, 1                               ; bytes = chars * 2
    mov     dword ptr [g_xlpwlen], eax
    WINCALL EndDialog, qword ptr [rbp-8], 1
    mov     eax, 1
    jmp     ipp_ret
ipp_empty:
    WINCALL MessageBoxW, qword ptr [rbp-8], addr imp_pw_empty, addr imp_pw_title, 030h
    mov     eax, 1
    jmp     ipp_ret
ipp_cancel:
    lea     rcx, [g_xlpw]                        ; wipe on cancel
    mov     edx, 512
    call    secure_zero
    WINCALL EndDialog, qword ptr [rbp-8], 0
    mov     eax, 1
ipp_ret:
    mov     rsp, rbp
    pop     rbp
    ret
imppw_proc endp

; =============================================================================
; Icon picker (DLG_ICON): a glyph grid + colour swatches + live preview.  On OK
; it writes the chosen glyph/colour into g_icon_glyph / g_icon_color and sets
; g_icon_set; the caller persists via gui_commit.
; =============================================================================
; ic_glyph_btn(rcx=DRAWITEMSTRUCT, r8d=index) - draw one glyph palette button.
ic_glyph_btn proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], r8d
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-40], rax            ; hdc
    WINCALL CreateSolidBrush, dword ptr [g_col_panel]
    mov     qword ptr [rbp-48], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-40], rdx, qword ptr [rbp-48]
    WINCALL DeleteObject, qword ptr [rbp-48]
    mov     eax, dword ptr [rbp-32]
    lea     r10, [g_glyphpal]
    mov     eax, dword ptr [r10+rax*4]
    cmp     eax, dword ptr [g_pick_glyph]
    jne     igb_noborder
    WINCALL CreateSolidBrush, dword ptr [g_col_text]
    mov     qword ptr [rbp-48], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FrameRect, qword ptr [rbp-40], rdx, qword ptr [rbp-48]
    WINCALL DeleteObject, qword ptr [rbp-48]
igb_noborder:
    mov     eax, dword ptr [rbp-32]            ; reload the glyph (avoid a stack slot)
    lea     r10, [g_glyphpal]
    mov     eax, dword ptr [r10+rax*4]
    mov     word ptr [g_glyph_w], ax
    mov     word ptr [g_glyph_w+2], 0
    WINCALL SelectObject, qword ptr [rbp-40], qword ptr [g_iconfont]
    mov     qword ptr [rbp-56], rax
    WINCALL SetTextColor, qword ptr [rbp-40], dword ptr [g_col_text]
    WINCALL SetBkMode, qword ptr [rbp-40], 1
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-72], eax
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-68], eax
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-64], eax
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-60], eax
    WINCALL DrawTextW, qword ptr [rbp-40], addr g_glyph_w, -1, addr rbp-72, 25h
    WINCALL SelectObject, qword ptr [rbp-40], qword ptr [rbp-56]
    FRAME_EPILOG
    ret
ic_glyph_btn endp

; ic_color_btn(rcx=DRAWITEMSTRUCT, r8d=index) - draw one colour swatch button.
ic_color_btn proc frame
    FRAME_PROLOG 80   ; >= 80: keep locals clear of the callee 32-byte home area
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], r8d
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-40], rax            ; hdc
    mov     eax, dword ptr [rbp-32]
    lea     r10, [g_glyphpal_col]
    mov     eax, dword ptr [r10+rax*4]
    mov     dword ptr [rbp-48], eax            ; this colour
    WINCALL CreateSolidBrush, dword ptr [rbp-48]
    mov     qword ptr [rbp-56], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-40], rdx, qword ptr [rbp-56]
    WINCALL DeleteObject, qword ptr [rbp-56]
    mov     eax, dword ptr [rbp-48]
    cmp     eax, dword ptr [g_pick_color]
    jne     icb_done
    WINCALL CreateSolidBrush, dword ptr [g_col_text]
    mov     qword ptr [rbp-56], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FrameRect, qword ptr [rbp-40], rdx, qword ptr [rbp-56]
    WINCALL DeleteObject, qword ptr [rbp-56]
icb_done:
    FRAME_EPILOG
    ret
ic_color_btn endp

; ic_prev_btn(rcx=DRAWITEMSTRUCT) - draw the live preview tile.
ic_prev_btn proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-40], rax            ; hdc
    WINCALL CreateSolidBrush, dword ptr [g_col_bg]
    mov     qword ptr [rbp-48], rax
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-40], rdx, qword ptr [rbp-48]
    WINCALL DeleteObject, qword ptr [rbp-48]
    mov     eax, dword ptr [g_pick_color]
    mov     dword ptr [g_tilecolor], eax
    mov     eax, dword ptr [g_pick_glyph]
    mov     word ptr [g_glyph_w], ax
    mov     word ptr [g_glyph_w+2], 0
    mov     rcx, qword ptr [rbp-40]
    mov     r10, qword ptr [rbp-24]
    mov     edx, dword ptr [r10+40]            ; L
    mov     r8d, dword ptr [r10+44]            ; T
    mov     r9d, dword ptr [r10+52]
    sub     r9d, dword ptr [r10+44]            ; size = B - T
    call    gui_draw_tile
    FRAME_EPILOG
    ret
ic_prev_btn endp

; ic_refresh(rcx=hwnd) - repaint the whole picker (grid highlights + preview).
ic_refresh proc
    sub     rsp, 40
    xor     edx, edx
    xor     r8, r8
    mov     r9d, 85h                            ; RDW_INVALIDATE|RDW_ERASE|RDW_ALLCHILDREN
    call    RedrawWindow
    add     rsp, 40
    ret
ic_refresh endp

icon_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      ic_init
    cmp     rdx, WM_COMMAND
    je      ic_cmd
    cmp     rdx, WM_DRAWITEM
    je      ic_draw
    cmp     rdx, WM_CTLCOLORSTATIC
    je      ic_col
    cmp     rdx, WM_CTLCOLOREDIT
    je      ic_col
    cmp     rdx, WM_CTLCOLORBTN
    je      ic_col
    cmp     rdx, WM_CTLCOLORDLG
    je      ic_col
    cmp     rdx, WM_PAINT
    je      ic_paint
    cmp     rdx, WM_ERASEBKGND
    je      ic_erase
    xor     eax, eax
    jmp     ic_ret
ic_col:
    call    theme_ctlcolor
    jmp     ic_ret
ic_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     ic_ret
ic_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     ic_ret
ic_unh:
    xor     eax, eax
    jmp     ic_ret
ic_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDOK
    call    theme_attach
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    cmp     dword ptr [g_icon_set], 0           ; seed the working selection
    je      ic_initdef
    mov     eax, dword ptr [g_icon_glyph]
    mov     dword ptr [g_pick_glyph], eax
    mov     eax, dword ptr [g_icon_color]
    mov     dword ptr [g_pick_color], eax
    mov     eax, 1
    jmp     ic_ret
ic_initdef:
    mov     eax, dword ptr [g_glyphpal]
    mov     dword ptr [g_pick_glyph], eax
    mov     eax, dword ptr [g_glyphpal_col]
    mov     dword ptr [g_pick_color], eax
    mov     eax, 1
    jmp     ic_ret
ic_draw:
    mov     eax, r8d                            ; ctl id
    cmp     eax, IDC_I_PREV
    je      ic_dprev
    cmp     eax, IDC_IG_BASE
    jb      ic_dtheme
    cmp     eax, IDC_IG_BASE + GLYPHPAL_N
    jb      ic_dglyph
    cmp     eax, IDC_IC_BASE
    jb      ic_dtheme
    cmp     eax, IDC_IC_BASE + GLYPHCOL_N
    jb      ic_dcolor
ic_dtheme:
    mov     rcx, r9
    call    theme_drawitem
    mov     eax, 1
    jmp     ic_ret
ic_dglyph:
    sub     r8d, IDC_IG_BASE
    mov     rcx, r9
    call    ic_glyph_btn
    mov     eax, 1
    jmp     ic_ret
ic_dcolor:
    sub     r8d, IDC_IC_BASE
    mov     rcx, r9
    call    ic_color_btn
    mov     eax, 1
    jmp     ic_ret
ic_dprev:
    mov     rcx, r9
    call    ic_prev_btn
    mov     eax, 1
    jmp     ic_ret
ic_cmd:
    movzx   eax, r8w
    cmp     eax, IDOK
    je      ic_ok
    cmp     eax, IDCANCEL
    je      ic_cancel
    cmp     eax, IDC_IG_BASE
    jb      ic_unh
    cmp     eax, IDC_IG_BASE + GLYPHPAL_N
    jb      ic_pickg
    cmp     eax, IDC_IC_BASE
    jb      ic_unh
    cmp     eax, IDC_IC_BASE + GLYPHCOL_N
    jb      ic_pickc
    xor     eax, eax
    jmp     ic_ret
ic_pickg:
    sub     eax, IDC_IG_BASE
    lea     r10, [g_glyphpal]
    mov     eax, dword ptr [r10+rax*4]
    mov     dword ptr [g_pick_glyph], eax
    mov     rcx, qword ptr [rbp-8]
    call    ic_refresh
    mov     eax, 1
    jmp     ic_ret
ic_pickc:
    sub     eax, IDC_IC_BASE
    lea     r10, [g_glyphpal_col]
    mov     eax, dword ptr [r10+rax*4]
    mov     dword ptr [g_pick_color], eax
    mov     rcx, qword ptr [rbp-8]
    call    ic_refresh
    mov     eax, 1
    jmp     ic_ret
ic_ok:
    mov     eax, dword ptr [g_pick_glyph]
    mov     dword ptr [g_icon_glyph], eax
    mov     eax, dword ptr [g_pick_color]
    mov     dword ptr [g_icon_color], eax
    mov     dword ptr [g_icon_set], 1
    WINCALL EndDialog, qword ptr [rbp-8], 1
    mov     eax, 1
    jmp     ic_ret
ic_cancel:
    WINCALL EndDialog, qword ptr [rbp-8], 0
    mov     eax, 1
ic_ret:
    mov     rsp, rbp
    pop     rbp
    ret
icon_proc endp

; gui_resolve_vault() - decide which vault to mount at startup.
;   Path:  HKLM (if set) > HKCU (if set) > default Documents\vault.vordr.
;   Mode:  no file at that path -> create (g_create=1); file present -> open.
;   Sets g_vpath / g_vpath_set / g_create / g_is_default / g_vault_lock.
gui_resolve_vault proc frame
    FRAME_PROLOG 32
    mov     dword ptr [g_is_default], 0
    mov     dword ptr [g_vault_lock], 0
    lea     rcx, [g_vpath]
    mov     edx, 1024
    lea     r8, [g_vault_lock]
    call    reg_load_vault                  ; HKLM>HKCU registered path, if any
    test    eax, eax
    jnz     grv_havepath
    ; nothing in the registry -> fall back to the default Documents\vault.vordr
    lea     rcx, [g_vpath]
    call    cfg_default_vault
    test    eax, eax
    jz      grv_none
    mov     dword ptr [g_is_default], 1     ; first run registers this path in HKCU
    lea     rcx, [g_vpath]                  ; make the folder we are about to OFFER real,
    call    gui_ensure_vault_dir            ;   so the picker prefill resolves to it
grv_havepath:
    mov     dword ptr [g_vpath_set], 1
    ; create vs open is decided purely by whether a file exists at the path
    lea     rcx, [g_vpath]
    call    gui_file_exists
    test    eax, eax
    jz      grv_create
    mov     dword ptr [g_create], 0          ; file present -> TPM / password unlock
    FRAME_EPILOG
    ret
grv_create:
    mov     dword ptr [g_create], 1          ; no file -> create + set-password
    FRAME_EPILOG
    ret
grv_none:
    mov     dword ptr [g_vpath_set], 0
    mov     dword ptr [g_create], 0
    FRAME_EPILOG
    ret
gui_resolve_vault endp

; gui_try_tpm_auto() -> eax = 1 if the registered vault was unlocked via TPM.
gui_try_tpm_auto proc frame
    FRAME_PROLOG 32
    cmp     dword ptr [g_tpm_want], 0        ; TPM Unlock off (setting/HKLM) -> ask for password
    je      gta_no
    lea     rax, [g_vpath]
    mov     qword ptr [g_cfg_in], rax
    call    vault_tpm_has
    test    eax, eax
    jz      gta_no
    mov     dword ptr [g_use_tpm], 1
    call    vault_unlock
    mov     dword ptr [g_use_tpm], 0
    test    eax, eax
    jnz     gta_no
    mov     eax, 1
    FRAME_EPILOG
    ret
gta_no:
    mov     dword ptr [g_use_tpm], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_try_tpm_auto endp

; =============================================================================
; Secure-desktop master-password entry (anti-keylogger).
;
; A password-entry dialog shown on a private Windows desktop is invisible to
; same-session input hooks (WH_KEYBOARD_LL, WH_GETMESSAGE, ...) and to
; screen-scrapers, because those are bound to the desktop that installed them.
; SetThreadDesktop only works on a thread that owns no windows/hooks yet, so
; the dialog runs on a freshly spawned worker thread; the entered password
; lands directly in the process-shared (and VirtualLock'd) g_cfg_pass buffer -
; no clipboard, no window messages cross the boundary.  If the desktop or
; thread cannot be created (limited token, Win7, etc.) it degrades gracefully
; to a normal on-desktop dialog so the user is never locked out.
; =============================================================================
DESKTOP_MAXALLOWED equ 02000000h                 ; MAXIMUM_ALLOWED access
                                                 ; (no INFINITE here any more - see the
                                                 ;  watchdog in gui_secdesk_show)

; secdesk_restore() -> eax = 1 if the user is back on their own desktop, else 0.
;   SwitchDesktop FAILS BY RETURNING FALSE, not by raising - and it genuinely can, when
;   another process holds the input desktop, during a secure-attention sequence, or under
;   policy.  Both restores used to ignore that, so one transient failure at exactly the
;   wrong moment left the user stranded on the private desktop with the app still running
;   happily: box accepted and dismissed, desktop never comes back, no crash to explain it.
;   So: retry, and if the remembered handle stays unusable, fall back to switching to
;   "Default" by name - that is the normal interactive desktop, and reaching it is far
;   better than leaving someone on a desktop with no shell.
SECDESK_TRIES equ 6
SECDESK_WAIT  equ 40                                 ; ms between attempts
SECDESK_SLICE_MS equ 500                             ; watchdog poll interval
SECDESK_MAX_MS   equ 600000                          ; 10 min: longer than any real
                                                     ;   password entry, short enough
                                                     ;   that a wedge is not forever
secdesk_restore proc frame
    FRAME_PROLOG 72                                  ; 72 -> 80 bytes: [rbp-40] holds the
                                                     ;   SwitchDesktop result ACROSS the
                                                     ;   CloseDesktop below, so it must sit
                                                     ;   clear of that call's home area
    mov     dword ptr [rbp-24], 0
sdr_loop:
    cmp     qword ptr [g_secdesk_orig], 0
    je      sdr_byname
    WINCALL SwitchDesktop, qword ptr [g_secdesk_orig]
    test    eax, eax
    jnz     sdr_ok
    inc     dword ptr [rbp-24]
    cmp     dword ptr [rbp-24], SECDESK_TRIES
    jae     sdr_byname
    WINCALL Sleep, SECDESK_WAIT
    jmp     sdr_loop
sdr_byname:
    WINCALL OpenDesktopW, addr desk_default, 0, 0, DESKTOP_MAXALLOWED
    test    rax, rax
    jz      sdr_fail
    mov     qword ptr [rbp-32], rax
    WINCALL SwitchDesktop, qword ptr [rbp-32]
    mov     dword ptr [rbp-40], eax
    WINCALL CloseDesktop, qword ptr [rbp-32]
    cmp     dword ptr [rbp-40], 0
    je      sdr_fail
sdr_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
sdr_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
secdesk_restore endp

; secdesk_switch(rcx = hdesk) -> eax = 1 if that desktop now receives input.
;   The FORWARD switch can fail exactly as the restore can (another process owns the
;   input desktop, a secure-attention sequence, policy) - secdesk_restore learned that
;   the hard way and this path never did.  Ignoring the result is worse here than
;   anywhere else: SetThreadDesktop has already bound this thread to the private
;   desktop, so the dialog is created THERE while input stays on the user's desktop.
;   Nothing is visible, the main thread is parked in the wait, and the app is wedged
;   with no window to close.
secdesk_switch proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], 0
sds_loop:
    WINCALL SwitchDesktop, qword ptr [rbp-24]
    test    eax, eax
    jnz     sds_ok
    inc     dword ptr [rbp-32]
    cmp     dword ptr [rbp-32], SECDESK_TRIES
    jae     sds_fail
    WINCALL Sleep, SECDESK_WAIT
    jmp     sds_loop
sds_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
sds_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
secdesk_switch endp

; secdesk_thread(rcx = unused) - worker: bind to the private desktop, make it
;   the visible input desktop, run the dialog, then switch back.  eax = 0.
secdesk_body proc frame
    FRAME_PROLOG 48
    WINCALL SetThreadDesktop, qword ptr [g_secdesk_hd]
    test    eax, eax
    jz      sdt_run                              ; couldn't bind -> show on current desktop
    mov     rcx, qword ptr [g_secdesk_hd]
    call    secdesk_switch
    test    eax, eax
    jnz     sdt_run
    ; It could not be made the input desktop.  Unbind (safe: this thread owns no
    ; windows yet) and show the dialog on the desktop the user is actually looking
    ; at, rather than on an invisible one.
    WINCALL SetThreadDesktop, qword ptr [g_secdesk_orig]
sdt_run:
    WINCALL DialogBoxParamW, qword ptr [g_hinst], dword ptr [g_secdesk_dlg], 0, \
            qword ptr [g_secdesk_proc], 0
    mov     qword ptr [g_secdesk_res], rax       ; marshal the result back to the caller
    cmp     dword ptr [g_secdesk_orphan], 0      ; the watchdog already restored the user's
    jne     sdt_done                             ;   desktop and released these handles
    call    secdesk_restore                      ; checked + retried, never fire-and-forget
sdt_done:
    xor     eax, eax
    FRAME_EPILOG
    ret
secdesk_body endp

; secdesk_thread(rcx = unused) - the CreateThread entry.  It swaps in this worker
;   thread's OWN shadow stack for the duration of the dialog, so the framed code it
;   runs (secdesk_body -> the create/unlock dialog) can never push or pop the main
;   thread's shared shadow stack.  The main thread is parked in WaitForSingleObject
;   throughout, so mutating g_sstk_* here is race-free.  RAW proc by design: it must
;   NOT frame itself (that would push to the stack it is about to swap out).
secdesk_thread proc
    push    rbp                                  ; robust raw frame: force 16-byte alignment
    mov     rbp, rsp                             ; regardless of the OS thread-entry rsp
    and     rsp, -16                             ; (a bad assumption here misaligned the crypto
    sub     rsp, 32                              ;  in secdesk_body -> corruption/faults)
    call    GetCurrentThreadId                   ; publish before the desktop switch: a fault
    mov     dword ptr [g_secdesk_tid], eax       ;   from here on is on the private desktop
    mov     rax, qword ptr [g_sstk_base]         ; park the main thread's shadow stack
    mov     qword ptr [g_sstk_savebase], rax
    mov     rax, qword ptr [g_sstk_index]
    mov     qword ptr [g_sstk_saveidx], rax
    lea     rax, [g_sstk_worker]                 ; install this thread's own, empty stack
    mov     qword ptr [g_sstk_base], rax
    mov     qword ptr [g_sstk_index], 0
    call    secdesk_body
    mov     dword ptr [g_secdesk_tid], 0         ; back on the caller's desktop from here
    mov     rax, qword ptr [g_sstk_savebase]     ; restore the main thread's shadow stack
    mov     qword ptr [g_sstk_base], rax
    mov     rax, qword ptr [g_sstk_saveidx]
    mov     qword ptr [g_sstk_index], rax
    mov     rsp, rbp
    pop     rbp
    xor     eax, eax
    ret
secdesk_thread endp

; gui_secdesk_show(ecx = dialog template id, rdx = dialog proc) -> rax = result.
;   Runs the given dialog on a private desktop via secdesk_thread and blocks
;   until it closes.  Falls back to a normal modal dialog on any failure.
public gui_secdesk_show
gui_secdesk_show proc frame
    FRAME_PROLOG 64                              ; room for 6-arg WINCALL spill above [rbp-24]
    mov     dword ptr [g_secdesk_dlg], ecx
    mov     qword ptr [g_secdesk_proc], rdx
    mov     qword ptr [g_secdesk_res], 0
    mov     qword ptr [g_secdesk_hd], 0
    mov     dword ptr [g_secdesk_orphan], 0
    ; Remember the desktop currently receiving input, to restore afterwards.  If this
    ; fails there is NO handle to switch back to, and both restore paths (secdesk_body
    ; and gss_cleanup) are guarded on it being non-null - so switching away anyway would
    ; leave the user on a shell-less desktop with no code able to return them, silently
    ; and without a crash.  Never switch away from a desktop you cannot get back to:
    ; degrade to the plain modal instead.
    WINCALL OpenInputDesktop, 0, 0, DESKTOP_MAXALLOWED
    mov     qword ptr [g_secdesk_orig], rax
    test    rax, rax
    jz      gss_fallback
    ; create the private desktop the dialog will live on
    WINCALL CreateDesktopW, addr secdesk_name, 0, 0, 0, DESKTOP_MAXALLOWED, 0
    mov     qword ptr [g_secdesk_hd], rax
    test    rax, rax
    jz      gss_fallback                         ; no desktop -> plain dialog
    WINCALL CreateThread, 0, 0, addr secdesk_thread, 0, 0, 0
    mov     qword ptr [rbp-24], rax              ; worker thread handle
    test    rax, rax
    jz      gss_fallback                         ; no thread -> plain dialog
    ; Bounded wait, not INFINITE.  The desktop restore lives at the END of the
    ; worker's dialog, so ANYTHING that blocks inside that dialog leaves the user on
    ; a shell-less desktop with no way back but Ctrl+Alt+Del - which is exactly what
    ; a blocking write into a OneDrive-synced folder did.  The password entry itself
    ; is unbounded by nature, so the ceiling is generous; it exists only to break a
    ; genuine wedge, never to interrupt someone typing.
    mov     dword ptr [rbp-32], 0                ; elapsed ms
gss_wait:
    WINCALL WaitForSingleObject, qword ptr [rbp-24], SECDESK_SLICE_MS
    test    eax, eax                             ; WAIT_OBJECT_0 -> the worker finished
    jz      gss_worker_done
    add     dword ptr [rbp-32], SECDESK_SLICE_MS
    cmp     dword ptr [rbp-32], SECDESK_MAX_MS
    jb      gss_wait
    ; Wedged.  Hand the user their desktop back and abandon the worker.  Deliberately
    ; leak the desktop and thread handles: the worker is still inside the dialog and
    ; would use them, and two leaked handles cost far less than a stranded user.
    mov     dword ptr [g_secdesk_orphan], 1
    call    secdesk_restore
    mov     qword ptr [g_secdesk_res], 0         ; treat as cancelled
    mov     qword ptr [g_secdesk_hd], 0          ; skip the closes in gss_cleanup
    mov     qword ptr [g_secdesk_orig], 0
    jmp     gss_ret
gss_worker_done:
    ; secdesk_thread restores these itself on the normal path; repeat it here so a
    ; worker that died mid-dialog cannot leave the main thread running on the
    ; worker's shadow stack.  Same saved values, so the normal path is a no-op.
    mov     rax, qword ptr [g_sstk_savebase]
    test    rax, rax
    jz      @F
    mov     qword ptr [g_sstk_base], rax
    mov     rax, qword ptr [g_sstk_saveidx]
    mov     qword ptr [g_sstk_index], rax
@@: WINCALL CloseHandle, qword ptr [rbp-24]
    jmp     gss_cleanup
gss_fallback:
    ; degrade to a normal on-desktop modal dialog (never lock the user out)
    WINCALL DialogBoxParamW, qword ptr [g_hinst], dword ptr [g_secdesk_dlg], 0, \
            qword ptr [g_secdesk_proc], 0
    mov     qword ptr [g_secdesk_res], rax
gss_cleanup:
    ; belt-and-braces: secdesk_body restores itself on the normal path, but a worker that
    ; died mid-dialog never reached that line.  Switching to the desktop that is already
    ; current is a harmless no-op, and it MUST precede CloseDesktop (the desktop currently
    ; receiving input cannot be closed).
    cmp     qword ptr [g_secdesk_orig], 0
    je      gss_closehd
    call    secdesk_restore
gss_closehd:
    cmp     qword ptr [g_secdesk_hd], 0
    je      gss_orig
    WINCALL CloseDesktop, qword ptr [g_secdesk_hd]
    mov     qword ptr [g_secdesk_hd], 0
gss_orig:
    cmp     qword ptr [g_secdesk_orig], 0
    je      gss_ret
    WINCALL CloseDesktop, qword ptr [g_secdesk_orig]
    mov     qword ptr [g_secdesk_orig], 0
gss_ret:
    mov     rax, qword ptr [g_secdesk_res]
    FRAME_EPILOG
    ret
gui_secdesk_show endp

ifdef DBG_TRACE
; cmd_securedesk - private-desktop spike dialog (dbg builds only): brings up a
;   themed dialog on the isolated desktop to eyeball the switch mechanism.
public cmd_securedesk
LANDING_PAD
cmd_securedesk proc frame
    FRAME_PROLOG 48
    WINCALL GetModuleHandleW, 0
    mov     qword ptr [g_hinst], rax
    call    theme_boot                           ; brushes/fonts for the themed dialog
    lea     rax, [sd_spike_txt]
    mov     qword ptr [g_msg_text], rax
    lea     rax, [sd_spike_ttl]
    mov     qword ptr [g_msg_title], rax
    mov     dword ptr [g_msg_flags], 0           ; MB_OK
    mov     ecx, DLG_MSG
    lea     rdx, [msg_proc]
    call    gui_secdesk_show
    xor     eax, eax
    FRAME_EPILOG
    ret
cmd_securedesk endp
endif

; =============================================================================
; gui_open(rcx = owner hwnd) - run the create/unlock -> vault flow, then lock and
;   return to the tray.  Guarded against re-entry while a dialog is already open.
;   On leaving the vault (Lock / close) the data is wiped and we drop back to the
;   tray WITHOUT showing the unlock screen.
; =============================================================================
gui_open proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_showing], 0
    jne     go_done
    mov     dword ptr [g_showing], 1
    cmp     dword ptr [g_create], 0
    jne     go_create
    call    gui_try_tpm_auto                ; silent unlock if this device is enrolled
    test    eax, eax
    jz      go_askpw
    call    gui_pwremind                    ; C9: the password was NOT typed just now, so
    jmp     go_vault                        ;   remind if it has gone stale
go_askpw:
    ; Read the vault image here, on the caller's desktop.  vault_unlock then works
    ; from memory, so a slow or stalled OneDrive read can no longer happen while the
    ; user is parked on the private desktop with no shell and no way back.
    cmp     dword ptr [g_vpath_set], 0
    je      go_nopreload
    lea     rax, [g_vpath]
    mov     qword ptr [g_cfg_in], rax
    call    vault_preload
go_nopreload:
    cmp     dword ptr [g_secunlock], 0     ; enter the master password on a private desktop?
    je      go_unlock_normal
    mov     ecx, DLG_UNLOCK
    lea     rdx, [unlock_proc]
    call    gui_secdesk_show
    jmp     go_unlock_res
go_unlock_normal:
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_UNLOCK, qword ptr [rbp-24], addr unlock_proc, 0
go_unlock_res:
    mov     qword ptr [rbp-32], rax        ; preload claim ends either way: on success the
    xor     ecx, ecx                       ;   image is the live vault's, otherwise nobody
    cmp     qword ptr [rbp-32], 1          ;   owns it and it must be released
    jne     @F
    mov     ecx, 1
@@: call    vault_preload_end
    cmp     qword ptr [rbp-32], 1
    jne     go_reset
    jmp     go_vault
go_create:
    cmp     dword ptr [g_secunlock], 0     ; set the master password on a private desktop?
    je      go_create_normal
    mov     ecx, DLG_CREATE
    lea     rdx, [create_proc]
    call    gui_secdesk_show
    jmp     go_create_res
go_create_normal:
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_CREATE, qword ptr [rbp-24], addr create_proc, 0
go_create_res:
    cmp     rax, 1
    jne     go_reset
    mov     rcx, qword ptr [rbp-24]         ; create the vault HERE, not in the dialog:
    call    gui_create_commit               ;   on the secure-unlock path the private
    test    eax, eax                        ;   desktop is gone by now, so blocking I/O
    jz      go_reset                        ;   can no longer strand the user on it
go_vault:
    ; single-vault: vault_unlock / TPM already set the live globals (g_body_ptr/g_hdr/
    ; g_vkey) - there is no context to register and nothing to fan out.
    ; Drop the previous window's anchor base BEFORE this one exists.  Windows sends
    ; WM_SIZE while the dialog is being created - i.e. BEFORE WM_INITDIALOG, so before
    ; gui_anchor_init has recorded anything - and gui_reflow only skips when the base
    ; is 0.  Locking destroys the vault window but left g_base_* set, so the second and
    ; every later unlock in one process reflowed the fresh controls against the DEAD
    ; window's rects: the entry-name edit moved before it was ever measured, and
    ; gui_anchor_init then recorded that wrong position as the new base.  Always fine
    ; on the first unlock, wrong on some of the ones after - which is exactly how it
    ; presented.  ([[vordr-vaultwindow-state-reset]]: state outliving the window.)
    mov     dword ptr [g_base_cx], 0
    mov     dword ptr [g_base_cy], 0
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_VAULT, qword ptr [rbp-24], addr vault_proc, 0
    call    vault_lock                      ; wipe body + key, minimise to tray
    call    gui_clipclear
    call    gui_resolve_vault               ; refresh create/open state for next time
go_reset:
    mov     dword ptr [g_showing], 0
go_done:
    FRAME_EPILOG
    ret
gui_open endp

; gui_tray_add(rcx = hwnd) - install the notification-area icon.
gui_tray_add proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    lea     rcx, [g_nid]
    mov     edx, 976
    call    secure_zero
    lea     r10, [g_nid]
    mov     dword ptr [r10+0], 976
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [r10+8], rax           ; hWnd
    mov     dword ptr [r10+16], 1            ; uID
    mov     dword ptr [r10+20], NIF_TRAY     ; uFlags
    mov     dword ptr [r10+24], WM_TRAYICON  ; uCallbackMessage
    WINCALL LoadIconW, qword ptr [g_hinst], 1
    lea     r10, [g_nid]
    mov     qword ptr [r10+32], rax          ; hIcon
    lea     r10, [g_nid+40]                  ; szTip
    lea     r11, [tray_wt]
    xor     ecx, ecx
ga_tip:
    mov     ax, word ptr [r11+rcx*2]
    mov     word ptr [r10+rcx*2], ax
    test    ax, ax
    jz      ga_tipd
    inc     ecx
    jmp     ga_tip
ga_tipd:
    WINCALL Shell_NotifyIconW, NIM_ADD, addr g_nid
    FRAME_EPILOG
    ret
gui_tray_add endp

; gui_tray_del() - remove the notification-area icon.
gui_tray_del proc frame
    FRAME_PROLOG 32
    WINCALL Shell_NotifyIconW, NIM_DELETE, addr g_nid
    FRAME_EPILOG
    ret
gui_tray_del endp

; gui_hotkey_add(rcx = hwnd) - register the system-wide "summon" hotkey, Alt + |,
;   on the tray-owner window (it outlives the vault window, which is destroyed on
;   close).  RegisterHotKey is a plain user32 call - no hook and no separate DLL.
;   The key carrying '|' differs per layout (unshifted left of 1 on Nordic, Shift
;   + \ on US), so ask the ACTIVE layout for it via VkKeyScanW rather than hard-
;   coding a scan code, and fold the shift state that '|' needs into the
;   modifiers.  Silent on failure: another process may already own the combo, and
;   a startup error box would be worse than a missing accelerator.
;   The user can rebind it from Settings; ui_hotkey holds (mods << 16) | vk and 0
;   means "use the built-in default".
gui_hotkey_add proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx              ; hwnd
    lea     rcx, [rbp-32]                        ; start from the built-in default
    lea     rdx, [rbp-40]
    call    gui_hotkey_default
    WINCALL cfg_get_dword, addr pref_hotkey, 0, 0    ; a saved rebind overrides it
    test    eax, eax
    jz      gha_reg
    mov     r10d, eax
    and     r10d, 0FFh                           ; vk
    jz      gha_reg                              ; malformed -> keep the default
    mov     dword ptr [rbp-32], r10d
    shr     eax, 16
    and     eax, 0Fh                             ; MOD_ALT|CONTROL|SHIFT|WIN only
    mov     dword ptr [rbp-40], eax
gha_reg:
    mov     eax, dword ptr [rbp-32]              ; publish before registering: a refused
    mov     dword ptr [g_hk_vk], eax             ;   rebind restores THIS pair
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [g_hk_mods], eax
    mov     eax, dword ptr [rbp-40]
    or      eax, MOD_NOREPEAT
    mov     dword ptr [rbp-48], eax
    WINCALL RegisterHotKey, qword ptr [rbp-24], HOTKEY_SHOW, dword ptr [rbp-48], \
            dword ptr [rbp-32]
    test    eax, eax
    jnz     gha_done
    WINCALL RegisterHotKey, qword ptr [rbp-24], HOTKEY_SHOW, dword ptr [rbp-40], \
            dword ptr [rbp-32]                   ; retry without MOD_NOREPEAT (pre-Win7)
gha_done:
    FRAME_EPILOG
    ret
gui_hotkey_add endp

; gui_hotkey_del(rcx = hwnd) - release the summon hotkey.
gui_hotkey_del proc frame
    FRAME_PROLOG 32
    WINCALL UnregisterHotKey, rcx, HOTKEY_SHOW
    FRAME_EPILOG
    ret
gui_hotkey_del endp

; hk_fmt(ecx = vk, edx = MOD_* mods) - render the combo into g_hk_txt as
;   "Ctrl + Shift + F2".  The key's own name comes from GetKeyNameTextW off a scan
;   code, so it is whatever the ACTIVE layout calls that key - localised, and
;   correct for OEM keys like '|' that have no fixed name.
hk_fmt proc frame
    FRAME_PROLOG 96
    mov     dword ptr [rbp-24], ecx             ; vk
    mov     dword ptr [rbp-32], edx             ; mods
    mov     word ptr [g_hk_txt], 0
    cmp     dword ptr [rbp-24], 0
    jne     hkf_mods
    lea     rcx, [g_hk_txt]                     ; no key -> "(none)"
    lea     rdx, [hk_none]
    call    gui_w_appendz
    mov     word ptr [rax], 0
    jmp     hkf_done
hkf_mods:
    lea     rax, [g_hk_txt]
    mov     qword ptr [rbp-40], rax             ; cursor
    test    dword ptr [rbp-32], MOD_CONTROL     ; fixed order, not capture order, so the
    jz      hkf_alt                             ;   same combo always reads the same way
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [hk_ctrl]
    call    gui_w_appendz
    mov     rcx, rax
    lea     rdx, [hk_plus]
    call    gui_w_appendz
    mov     qword ptr [rbp-40], rax
hkf_alt:
    test    dword ptr [rbp-32], MOD_ALT
    jz      hkf_shift
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [hk_alt]
    call    gui_w_appendz
    mov     rcx, rax
    lea     rdx, [hk_plus]
    call    gui_w_appendz
    mov     qword ptr [rbp-40], rax
hkf_shift:
    test    dword ptr [rbp-32], MOD_SHIFT
    jz      hkf_win
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [hk_shift]
    call    gui_w_appendz
    mov     rcx, rax
    lea     rdx, [hk_plus]
    call    gui_w_appendz
    mov     qword ptr [rbp-40], rax
hkf_win:
    test    dword ptr [rbp-32], MOD_WIN
    jz      hkf_key
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [hk_win]
    call    gui_w_appendz
    mov     rcx, rax
    lea     rdx, [hk_plus]
    call    gui_w_appendz
    mov     qword ptr [rbp-40], rax
hkf_key:
    ; key name: vk -> scan code -> the lParam form GetKeyNameTextW wants (scan << 16)
    WINCALL MapVirtualKeyW, dword ptr [rbp-24], MAPVK_VK_TO_VSC
    shl     eax, 16
    mov     dword ptr [rbp-48], eax
    mov     rax, qword ptr [rbp-40]             ; wide chars still free in g_hk_txt
    lea     r10, [g_hk_txt]
    sub     rax, r10
    sar     rax, 1
    mov     ecx, 63
    sub     ecx, eax
    mov     dword ptr [rbp-56], ecx
    WINCALL GetKeyNameTextW, dword ptr [rbp-48], qword ptr [rbp-40], dword ptr [rbp-56]
    test    eax, eax                            ; unnamed key -> show the vk number, so a
    jnz     hkf_done                            ;   row is never mysteriously blank
    mov     rcx, qword ptr [rbp-40]
    mov     edx, dword ptr [rbp-24]
    call    gui_uint_w
    mov     word ptr [rax], 0
hkf_done:
    FRAME_EPILOG
    ret
hk_fmt endp

; gui_hotkey_default(rcx = *vk out, rdx = *mods out) - the built-in Alt + | combo,
;   resolved against the ACTIVE layout (the key carrying '|' moves per layout).
gui_hotkey_default proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     dword ptr [rbp-40], VK_OEM_5        ; fallback: the \| key
    mov     dword ptr [rbp-48], MOD_ALT
    WINCALL VkKeyScanW, 7Ch                     ; '|' -> lo = vk, hi = shift state
    movsx   eax, ax
    cmp     eax, -1
    je      hkd_out
    movzx   r10d, al
    test    r10d, r10d
    jz      hkd_out
    mov     dword ptr [rbp-40], r10d
    movzx   eax, ah                             ; 1 Shift, 2 Ctrl, 4 Alt (NOT the MOD_ bits)
    test    eax, 1
    jz      @F
    or      dword ptr [rbp-48], MOD_SHIFT
@@: test    eax, 2
    jz      @F
    or      dword ptr [rbp-48], MOD_CONTROL
@@:
hkd_out:
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [r10], eax
    mov     r10, qword ptr [rbp-32]
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [r10], eax
    FRAME_EPILOG
    ret
gui_hotkey_default endp

; gui_hotkey_apply(ecx = vk, edx = mods) -> eax = 1 registered / 0 refused.
;   Swap the live summon hotkey.  The old one is released first; if the new combo
;   is owned by another process the old one is put back, so a refused rebind never
;   leaves the app with no hotkey at all.
public gui_hotkey_apply
gui_hotkey_apply proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-24], ecx             ; vk
    mov     dword ptr [rbp-32], edx             ; mods
    cmp     qword ptr [g_trayhwnd], 0
    je      hka_no
    WINCALL UnregisterHotKey, qword ptr [g_trayhwnd], HOTKEY_SHOW
    mov     eax, dword ptr [rbp-32]
    or      eax, MOD_NOREPEAT
    mov     dword ptr [rbp-40], eax
    WINCALL RegisterHotKey, qword ptr [g_trayhwnd], HOTKEY_SHOW, dword ptr [rbp-40], \
            dword ptr [rbp-24]
    test    eax, eax
    jnz     hka_ok
    WINCALL RegisterHotKey, qword ptr [g_trayhwnd], HOTKEY_SHOW, dword ptr [rbp-32], \
            dword ptr [rbp-24]                  ; retry without MOD_NOREPEAT (pre-Win7)
    test    eax, eax
    jnz     hka_ok
    mov     eax, dword ptr [g_hk_mods]          ; refused -> put the previous one back
    or      eax, MOD_NOREPEAT
    mov     dword ptr [rbp-40], eax
    WINCALL RegisterHotKey, qword ptr [g_trayhwnd], HOTKEY_SHOW, dword ptr [rbp-40], \
            dword ptr [g_hk_vk]
hka_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
hka_ok:
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [g_hk_vk], eax
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [g_hk_mods], eax
    mov     eax, 1
    FRAME_EPILOG
    ret
gui_hotkey_apply endp

; hk_cap_subclass - SUBCLASSPROC on the capture surface.  It answers WM_GETDLGCODE
;   with WANTALLKEYS so the dialog manager stops eating keystrokes, and takes both
;   WM_KEYDOWN and WM_SYSKEYDOWN - Alt combinations only ever arrive as the latter,
;   which is the usual reason a hand-rolled capture misses exactly the combo the
;   user is trying to set.
hk_cap_subclass proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx             ; hwnd
    mov     qword ptr [rbp-32], rdx             ; msg
    mov     qword ptr [rbp-40], r8              ; wParam = vk
    mov     qword ptr [rbp-48], r9              ; lParam
    cmp     rdx, WM_GETDLGCODE_
    je      hkc_wantall
    cmp     rdx, WM_KEYDOWN_
    je      hkc_key
    cmp     rdx, WM_SYSKEYDOWN_
    je      hkc_key
    jmp     hkc_def
hkc_wantall:
    mov     eax, DLGC_WANTALLKEYS
    FRAME_EPILOG
    ret
hkc_key:
    mov     eax, dword ptr [rbp-40]             ; a bare modifier is not a hotkey by itself
    cmp     eax, VK_SHIFT_
    je      hkc_eat
    cmp     eax, VK_CONTROL_
    je      hkc_eat
    cmp     eax, VK_MENU_
    je      hkc_eat
    cmp     eax, VK_LWIN_
    je      hkc_eat
    cmp     eax, VK_RWIN_
    je      hkc_eat
    ; gather the modifiers actually held down
    xor     r11d, r11d
    mov     dword ptr [rbp-56], r11d
    WINCALL GetKeyState, VK_CONTROL_
    test    ax, 8000h
    jz      @F
    or      dword ptr [rbp-56], MOD_CONTROL
@@: WINCALL GetKeyState, VK_MENU_
    test    ax, 8000h
    jz      @F
    or      dword ptr [rbp-56], MOD_ALT
@@: WINCALL GetKeyState, VK_SHIFT_
    test    ax, 8000h
    jz      @F
    or      dword ptr [rbp-56], MOD_SHIFT
@@: WINCALL GetKeyState, VK_LWIN_
    test    ax, 8000h
    jnz     hkc_win
    WINCALL GetKeyState, VK_RWIN_
    test    ax, 8000h
    jz      hkc_nowin
hkc_win:
    or      dword ptr [rbp-56], MOD_WIN
hkc_nowin:
    ; Tab / Enter / Esc UNMODIFIED still belong to the dialog, or there would be no
    ; way to move focus or leave.  With a modifier they are fair game.
    cmp     dword ptr [rbp-56], 0
    jne     hkc_take
    mov     eax, dword ptr [rbp-40]
    cmp     eax, VK_TAB_
    je      hkc_def
    cmp     eax, VK_RETURN_
    je      hkc_def
    cmp     eax, VK_ESCAPE_
    je      hkc_def
hkc_take:
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [g_hk_cap_vk], eax
    mov     eax, dword ptr [rbp-56]
    mov     dword ptr [g_hk_cap_mods], eax
    mov     ecx, dword ptr [g_hk_cap_vk]
    mov     edx, dword ptr [g_hk_cap_mods]
    call    hk_fmt
    WINCALL SetWindowTextW, qword ptr [rbp-24], addr g_hk_txt
    WINCALL InvalidateRect, qword ptr [rbp-24], 0, 1
hkc_eat:
    xor     eax, eax                            ; consumed
    FRAME_EPILOG
    ret
hkc_def:
    WINCALL DefSubclassProc, qword ptr [rbp-24], qword ptr [rbp-32], qword ptr [rbp-40], \
            qword ptr [rbp-48]
    FRAME_EPILOG
    ret
hk_cap_subclass endp

; hotkey_proc - DLG_HOTKEY procedure (themed).
hotkey_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 96
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      hk_init
    cmp     rdx, WM_COMMAND
    je      hk_cmd
    cmp     rdx, WM_CTLCOLORSTATIC
    je      hk_col
    cmp     rdx, WM_CTLCOLORBTN
    je      hk_col
    cmp     rdx, WM_CTLCOLORDLG
    je      hk_col
    cmp     rdx, WM_PAINT
    je      hk_paint
    cmp     rdx, WM_ERASEBKGND
    je      hk_erase
    cmp     rdx, WM_DRAWITEM
    je      hk_draw
    xor     eax, eax
    jmp     hk_ret
hk_col:
    call    theme_ctlcolor
    jmp     hk_ret
hk_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     hk_ret
hk_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     hk_ret
hk_draw:
    mov     rcx, r9                             ; lpdis - NOT the dialog hwnd still in rcx
    call    theme_drawitem
    mov     eax, 1
    jmp     hk_ret
hk_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDOK
    call    theme_attach
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDCANCEL
    call    theme_attach
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_HK_CLEAR
    call    theme_attach
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    mov     eax, dword ptr [g_hk_vk]            ; start from the live combo
    mov     dword ptr [g_hk_cap_vk], eax
    mov     eax, dword ptr [g_hk_mods]
    mov     dword ptr [g_hk_cap_mods], eax
    mov     ecx, dword ptr [g_hk_cap_vk]
    mov     edx, dword ptr [g_hk_cap_mods]
    call    hk_fmt
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_HK_CAP, addr g_hk_txt
    WINCALL GetDlgItem, qword ptr [rbp-8], IDC_HK_CAP
    mov     qword ptr [rbp-16], rax
    WINCALL SetWindowSubclass, qword ptr [rbp-16], addr hk_cap_subclass, 0, 0
    WINCALL SetFocus, qword ptr [rbp-16]
    xor     eax, eax                            ; we set focus ourselves -> FALSE
    jmp     hk_ret
hk_cmd:
    movzx   eax, r8w
    cmp     eax, IDOK
    je      hk_ok
    cmp     eax, IDCANCEL
    je      hk_cancel
    cmp     eax, IDC_HK_CLEAR
    je      hk_clear
    xor     eax, eax
    jmp     hk_ret
hk_clear:
    lea     rcx, [g_hk_cap_vk]                  ; back to the built-in Alt + |
    lea     rdx, [g_hk_cap_mods]
    call    gui_hotkey_default
    mov     ecx, dword ptr [g_hk_cap_vk]
    mov     edx, dword ptr [g_hk_cap_mods]
    call    hk_fmt
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_HK_CAP, addr g_hk_txt
    mov     eax, 1
    jmp     hk_ret
hk_ok:
    WINCALL EndDialog, qword ptr [rbp-8], 1
    mov     eax, 1
    jmp     hk_ret
hk_cancel:
    WINCALL EndDialog, qword ptr [rbp-8], 0
    mov     eax, 1
hk_ret:
    mov     rsp, rbp
    pop     rbp
    ret
hotkey_proc endp

; gui_hotkey_capture(rcx = hdlg) - run the capture dialog; on Set, rebind and
;   persist.  A combo another process already owns is reported and nothing
;   changes - gui_hotkey_apply has already put the previous one back.
gui_hotkey_capture proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_HOTKEY, qword ptr [rbp-24], \
            addr hotkey_proc, 0
    cmp     rax, 1
    jne     ghc_done
    cmp     dword ptr [g_hk_cap_vk], 0
    je      ghc_done
    mov     ecx, dword ptr [g_hk_cap_vk]
    mov     edx, dword ptr [g_hk_cap_mods]
    call    gui_hotkey_apply
    test    eax, eax
    jz      ghc_taken
    mov     eax, dword ptr [g_hk_mods]          ; persist as (mods << 16) | vk
    shl     eax, 16
    or      eax, dword ptr [g_hk_vk]
    mov     dword ptr [rbp-32], eax
    WINCALL cfg_set_dword_hkcu, addr pref_hotkey, dword ptr [rbp-32]
    jmp     ghc_refresh
ghc_taken:
    WINCALL gui_msgbox, qword ptr [rbp-24], addr hk_taken, addr hk_ttl, 030h
ghc_refresh:
    call    gui_hotkey_label                    ; repaint the settings row either way
ghc_done:
    FRAME_EPILOG
    ret
gui_hotkey_capture endp

; gui_hotkey_label(rcx = hdlg) - show the live combo on the settings button.
; gui_hotkey_label() - no argument on purpose.  IDC_V_MHOTK exists in exactly one
;   window, the settings child, so taking an hwnd only creates the opportunity to pass
;   the wrong one: gui_hotkey_capture passed the vault, the write went nowhere, and the
;   new hotkey did not appear on the button until settings was closed and reopened.
gui_hotkey_label proc frame
    FRAME_PROLOG 48
    mov     ecx, dword ptr [g_hk_vk]
    mov     edx, dword ptr [g_hk_mods]
    call    hk_fmt
    WINCALL SetDlgItemTextW, qword ptr [g_settings_hwnd], IDC_V_MHOTK, addr g_hk_txt
    FRAME_EPILOG
    ret
gui_hotkey_label endp

; gui_inval_setting(ecx = control id) - repaint one owner-draw control in the settings
;   child after the global behind it changed.
;   Six toggle handlers did this inline against the VAULT window.  GetDlgItem returned
;   NULL there, and InvalidateRect(NULL, ...) does not no-op: it invalidates EVERY
;   window on the desktop.  The toggle did repaint - as collateral damage of a
;   system-wide repaint - which is exactly why the miss was invisible on screen.
gui_inval_setting proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-24], ecx
    WINCALL GetDlgItem, qword ptr [g_settings_hwnd], dword ptr [rbp-24]
    mov     qword ptr [rbp-32], rax
    test    rax, rax                          ; never hand NULL to InvalidateRect
    jz      gis_done
    WINCALL InvalidateRect, qword ptr [rbp-32], 0, 1
gis_done:
    FRAME_EPILOG
    ret
gui_inval_setting endp

; gui_tray_menu(rcx = hwnd) - the right-click context menu (About / Open / Exit).
gui_tray_menu proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    WINCALL CreatePopupMenu
    mov     qword ptr [rbp-32], rax
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, IDM_ABOUT, addr t_about
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, IDM_OPEN, addr mi_open
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_SEPARATOR, 0, 0
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_OWNERDRAW, IDM_EXIT, addr mi_exit
    mov     rcx, qword ptr [rbp-32]              ; tint the menu background
    call    gui_menu_dark
    mov     qword ptr [rbp-40], rax
    WINCALL GetCursorPos, addr g_pt
    WINCALL SetForegroundWindow, qword ptr [rbp-24]
    WINCALL TrackPopupMenu, qword ptr [rbp-32], TPM_RIGHTBUTTON, dword ptr [g_pt], \
            dword ptr [g_pt+4], 0, qword ptr [rbp-24], 0
    WINCALL DestroyMenu, qword ptr [rbp-32]
    WINCALL DeleteObject, qword ptr [rbp-40]
    FRAME_EPILOG
    ret
gui_tray_menu endp

; =============================================================================
; tray_wndproc - window proc for the hidden tray-owner window.  rax = LRESULT.
; =============================================================================
tray_wndproc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx           ; hwnd
    mov     qword ptr [rbp-16], rdx          ; msg
    mov     qword ptr [rbp-24], r8           ; wParam
    mov     qword ptr [rbp-32], r9           ; lParam
    cmp     rdx, WM_TRAYICON
    je      twp_tray
    cmp     rdx, WM_HOTKEY
    je      twp_hotkey
    cmp     rdx, WM_COMMAND
    je      twp_cmd
    cmp     rdx, WM_DESTROY
    je      twp_destroy
    cmp     rdx, WM_ENDSESSION                  ; shutdown/logoff: wipe before we are killed
    je      twp_endsession
    cmp     rdx, WM_MEASUREITEM                 ; themed owner-draw tray menu
    je      twp_measure
    cmp     rdx, WM_DRAWITEM
    je      twp_draw
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
    jmp     twp_ret
twp_measure:
    mov     rcx, qword ptr [rbp-32]
    call    gui_menu_measure
    mov     eax, 1
    jmp     twp_ret
twp_draw:
    mov     rcx, qword ptr [rbp-32]
    call    gui_menu_draw
    mov     eax, 1
    jmp     twp_ret
twp_tray:
    movzx   eax, word ptr [rbp-32]           ; LOWORD(lParam) = mouse message
    cmp     eax, WM_LBUTTONUP
    je      twp_toggle
    cmp     eax, WM_LBUTTONDBLCLK
    je      twp_toggle
    cmp     eax, WM_RBUTTONUP
    je      twp_menu
    xor     eax, eax
    jmp     twp_ret
twp_toggle:
    ; left-click toggles: if the vault window is up, close it (back to tray);
    ; otherwise open the unlock/vault flow.
    cmp     qword ptr [g_vaulthwnd], 0
    je      twp_open
    WINCALL PostMessageW, qword ptr [g_vaulthwnd], WM_COMMAND, IDCANCEL, 0
    xor     eax, eax
    jmp     twp_ret
twp_hotkey:
    ; The summon hotkey from anywhere: closed -> open (unlock flow), open -> LOCK.
    ; Serving a hotkey grants this process the right to take the foreground, so
    ; SetForegroundWindow is allowed to succeed on the way up.
    ;
    ; The lock half posts IDC_V_LOCK, the same command Ctrl+L uses, so it runs the
    ; one real lock path: wipe secrets, purge decrypt-to-temp files, clear the
    ; clipboard, drop to the tray.  Deliberately NOT IDCANCEL (what the tray
    ; left-click posts) - that goes via vp_esc, which diverts to discarding a
    ; just-added placeholder row instead of locking.  A key you press to secure the
    ; screen has to lock every time, not sometimes discard a field.
    cmp     qword ptr [g_vaulthwnd], 0
    je      twp_open                         ; not up -> the usual unlock/open flow
    WINCALL PostMessageW, qword ptr [g_vaulthwnd], WM_COMMAND, IDC_V_LOCK, 0
    xor     eax, eax
    jmp     twp_ret
twp_cmd:
    movzx   eax, word ptr [rbp-24]           ; LOWORD(wParam) = menu id
    cmp     eax, IDM_ABOUT
    je      twp_about
    cmp     eax, IDM_OPEN
    je      twp_open
    cmp     eax, IDM_EXIT
    je      twp_exit
    xor     eax, eax
    jmp     twp_ret
twp_open:
    mov     rcx, qword ptr [rbp-8]
    call    gui_open
    xor     eax, eax
    jmp     twp_ret
twp_menu:
    mov     rcx, qword ptr [rbp-8]
    call    gui_tray_menu
    xor     eax, eax
    jmp     twp_ret
twp_about:
    mov     rcx, qword ptr [rbp-8]
    call    gui_about
    xor     eax, eax
    jmp     twp_ret
twp_exit:
    WINCALL DestroyWindow, qword ptr [rbp-8]
    xor     eax, eax
    jmp     twp_ret
twp_endsession:
    ; Windows is ending the session and will terminate us shortly - no auto-lock timer
    ; will fire, and nothing else runs.  Drop the copied secret and wipe every pinned
    ; buffer now.  wParam = 0 means the shutdown was cancelled, so do nothing then.
    cmp     qword ptr [rbp-24], 0
    je      twp_endsession_ret
    call    gui_clipclear
    call    secmem_panic_wipe
twp_endsession_ret:
    xor     eax, eax
    jmp     twp_ret
twp_destroy:
    mov     rcx, qword ptr [rbp-8]
    call    gui_hotkey_del
    call    gui_tray_del
    WINCALL PostQuitMessage, 0
    xor     eax, eax
twp_ret:
    mov     rsp, rbp
    pop     rbp
    ret
tray_wndproc endp

; =============================================================================
; gui_msgbox(rcx=parent, rdx=text, r8=title, r9d=flags) -> eax = IDOK/IDYES/
;   IDNO/IDCANCEL.  Fluent dark replacement for MessageBoxW (same arg order);
;   flags low nibble == MB_YESNO gives Yes/No, otherwise a single OK button.
; =============================================================================
gui_msgbox proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [g_msg_text], rdx
    mov     qword ptr [g_msg_title], r8
    mov     dword ptr [g_msg_flags], r9d
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_MSG, qword ptr [rbp-24], addr msg_proc, 0
    FRAME_EPILOG
    ret
gui_msgbox endp

; msg_proc - DLG_MSG dialog procedure (Fluent message box).  rax = BOOL.
msg_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      mp_init
    cmp     rdx, WM_COMMAND
    je      mp_cmd
    cmp     rdx, WM_CLOSE
    je      mp_close
    cmp     rdx, WM_DRAWITEM
    je      mp_draw
    cmp     rdx, WM_ERASEBKGND
    je      mp_erase
    cmp     rdx, WM_PAINT
    je      mp_paint
    cmp     rdx, WM_CTLCOLOREDIT
    je      mp_color
    cmp     rdx, WM_CTLCOLORSTATIC
    je      mp_color
    cmp     rdx, WM_CTLCOLORBTN
    je      mp_color
    cmp     rdx, WM_CTLCOLORDLG
    je      mp_color
    xor     eax, eax
    jmp     mp_ret
mp_color:
    call    theme_ctlcolor
    jmp     mp_ret
mp_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     mp_ret
mp_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     mp_ret
mp_draw:
    mov     rcx, r9
    call    theme_drawitem
    jmp     mp_ret
mp_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_M_OK
    call    theme_attach                     ; OK / Yes = accent primary
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     rdx, qword ptr [g_msg_title]
    call    SetWindowTextW
    add     rsp, 32
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_M_TEXT
    mov     r8, qword ptr [g_msg_text]
    call    SetDlgItemTextW
    add     rsp, 32
    call    gui_make_welcomefont              ; larger body font for the message text
    sub     rsp, 48
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_M_TEXT
    mov     r8d, WM_SETFONT
    mov     r9, qword ptr [g_welcomefont]
    mov     qword ptr [rsp+32], 1
    call    SendDlgItemMessageW
    add     rsp, 48
    mov     eax, dword ptr [g_msg_flags]
    and     eax, MB_TYPEMASK
    cmp     eax, MB_YESNO
    je      mp_yesno
    sub     rsp, 32                           ; single OK button
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_M_OK
    lea     r8, [mb_ok]
    call    SetDlgItemTextW
    add     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_M_NO
    call    GetDlgItem
    sub     rsp, 32
    mov     rcx, rax
    xor     edx, edx                          ; SW_HIDE
    call    ShowWindow
    add     rsp, 32
    mov     rcx, qword ptr [rbp-8]            ; centre the lone OK button
    call    gui_center_ok
    jmp     mp_initdone
mp_yesno:
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_M_OK
    lea     r8, [mb_yes]
    call    SetDlgItemTextW
    add     rsp, 32
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_M_NO
    lea     r8, [mb_no]
    call    SetDlgItemTextW
    add     rsp, 32
mp_initdone:
    mov     eax, 1
    jmp     mp_ret
mp_cmd:
    movzx   eax, r8w
    cmp     eax, IDC_M_OK
    je      mp_ok
    cmp     eax, IDC_M_NO
    je      mp_no
    cmp     eax, IDCANCEL
    je      mp_no
    xor     eax, eax
    jmp     mp_ret
mp_ok:
    mov     eax, dword ptr [g_msg_flags]
    and     eax, MB_TYPEMASK
    cmp     eax, MB_YESNO
    je      mp_ok_yes
    mov     edx, IDOK
    jmp     mp_end
mp_ok_yes:
    mov     edx, IDYES
    jmp     mp_end
mp_no:
mp_close:
    mov     eax, dword ptr [g_msg_flags]
    and     eax, MB_TYPEMASK
    cmp     eax, MB_YESNO
    je      mp_no_n
    mov     edx, IDCANCEL
    jmp     mp_end
mp_no_n:
    mov     edx, IDNO
mp_end:
    mov     rcx, qword ptr [rbp-8]
    sub     rsp, 32
    call    EndDialog
    add     rsp, 32
    mov     eax, 1
mp_ret:
    mov     rsp, rbp
    pop     rbp
    ret
msg_proc endp

; gui_about(rcx = parent) - the About box, showing the Vordr logo (app icon).
gui_about proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_ABOUT, qword ptr [rbp-24], addr about_proc, 0
    FRAME_EPILOG
    ret
gui_about endp

; about_proc - DLG_ABOUT dialog procedure (logo + text + OK).  rax = BOOL.
about_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      ap_init
    cmp     rdx, WM_COMMAND
    je      ap_cmd
    cmp     rdx, WM_CLOSE
    je      ap_close
    cmp     rdx, WM_DRAWITEM
    je      ap_draw
    cmp     rdx, WM_ERASEBKGND
    je      ap_erase
    cmp     rdx, WM_PAINT
    je      ap_paint
    cmp     rdx, WM_CTLCOLOREDIT
    je      ap_color
    cmp     rdx, WM_CTLCOLORSTATIC
    je      ap_color
    cmp     rdx, WM_CTLCOLORBTN
    je      ap_color
    cmp     rdx, WM_CTLCOLORDLG
    je      ap_color
    xor     eax, eax
    jmp     ap_ret
ap_color:
    call    theme_ctlcolor
    jmp     ap_ret
ap_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     ap_ret
ap_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     ap_ret
ap_draw:
    mov     rcx, r9
    call    theme_drawitem
    jmp     ap_ret
ap_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_A_OK
    call    theme_attach                     ; OK = accent primary
    mov     rcx, qword ptr [rbp-8]
    call    gui_set_winicon
    sub     rsp, 48                           ; load the app icon (the logo) at 72px
    mov     rcx, qword ptr [g_hinst]
    mov     edx, 1
    mov     r8d, 1                            ; IMAGE_ICON
    mov     r9d, 72
    mov     qword ptr [rsp+32], 72
    mov     qword ptr [rsp+40], 0             ; LR_DEFAULTCOLOR
    call    LoadImageW
    add     rsp, 48
    mov     qword ptr [rbp-16], rax           ; hIcon
    sub     rsp, 48                           ; STM_SETICON on the icon static
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_A_ICON
    mov     r8d, STM_SETICON
    mov     r9, qword ptr [rbp-16]
    mov     qword ptr [rsp+32], 0
    call    SendDlgItemMessageW
    add     rsp, 48
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_A_TEXT
    lea     r8, [m_about]
    call    SetDlgItemTextW
    add     rsp, 32
    mov     eax, 1
    jmp     ap_ret
ap_cmd:
    movzx   eax, r8w
    cmp     eax, IDC_A_OK
    je      ap_ok
    cmp     eax, IDCANCEL
    je      ap_ok
    xor     eax, eax
    jmp     ap_ret
ap_ok:
ap_close:
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, 1
    call    EndDialog
    add     rsp, 32
    mov     eax, 1
ap_ret:
    mov     rsp, rbp
    pop     rbp
    ret
about_proc endp

; =============================================================================
; gui_main - create the hidden tray-owner window, install the tray icon, and run
;   the message loop.  The app starts minimised to the tray (no window shown);
;   the user opens the vault by left-clicking the icon or via the menu.
; =============================================================================
gui_main proc frame
    FRAME_PROLOG 112
    WINCALL GetModuleHandleW, 0
    mov     qword ptr [g_hinst], rax
    mov     dword ptr [rbp-24], 8           ; INITCOMMONCONTROLSEX.dwSize
    mov     dword ptr [rbp-20], 4005h       ; ICC_STANDARD | ICC_BAR (trackbar) | ICC_LISTVIEW_CLASSES
    WINCALL InitCommonControlsEx, addr rbp-24
    call    gui_load_prefs                  ; load the saved scheme BEFORE theme_boot so the
    call    theme_boot                      ;   create/unlock dialogs use it too, not the default
    call    tpm_available
    mov     dword ptr [g_tpm_present], eax
    call    gui_load_policy
ifdef DBG_SHOW
    mov     dword ptr [g_secunlock], 0      ; debug: use the normal desktop so the GUI is inspectable
endif
    call    gui_resolve_vault
    ; ---- register + create the hidden tray-owner window --------------------
    lea     rcx, [g_wc]
    mov     edx, 80
    call    secure_zero
    lea     r10, [g_wc]
    lea     rax, [tray_wndproc]
    mov     qword ptr [r10+8], rax           ; lpfnWndProc
    mov     rax, qword ptr [g_hinst]
    mov     qword ptr [r10+24], rax          ; hInstance
    lea     rax, [tray_cls]
    mov     qword ptr [r10+64], rax          ; lpszClassName
    WINCALL RegisterClassW, addr g_wc
    test    eax, eax
    jnz     gm_clsok
    ; RegisterClassW can still fail on exotic machines (error 998); fall back to
    ; a system class + WNDPROC subclass, which needs no registration at all.
    WINCALL CreateWindowExW, WS_EX_TOOLWINDOW, addr dbg_static_cls, addr tray_wt, WS_POPUP, \
            0, 0, 0, 0, 0, 0, qword ptr [g_hinst], 0
    test    rax, rax
    jz      gm_trayhwnd                       ; still 0 -> the tray icon just won't show
    WINCALL SetWindowLongPtrW, rax, GWLP_WNDPROC, addr tray_wndproc
    jmp     gm_trayhwnd
gm_clsok:
    WINCALL CreateWindowExW, WS_EX_TOOLWINDOW, addr tray_cls, addr tray_wt, WS_POPUP, \
            0, 0, 0, 0, 0, 0, qword ptr [g_hinst], 0
gm_trayhwnd:
    mov     qword ptr [g_trayhwnd], rax
    mov     rcx, rax
    call    gui_tray_add
    mov     rcx, qword ptr [g_trayhwnd]       ; Alt + | summons the vault from anywhere
    call    gui_hotkey_add
ifdef DBG_SHOW
    WINCALL PostMessageW, qword ptr [g_trayhwnd], WM_TRAYICON, 0, WM_LBUTTONUP  ; auto-open the vault
endif
    ; ---- message loop (start minimised to the tray) -----------------------
gm_msg:
    WINCALL GetMessageW, addr g_msg, 0, 0, 0
    test    eax, eax
    jle     gm_quit                          ; 0 = WM_QUIT, -1 = error
    WINCALL TranslateMessage, addr g_msg
    WINCALL DispatchMessageW, addr g_msg
    jmp     gm_msg
gm_quit:
    call    gui_clipclear                    ; never leave a copied secret behind
    FRAME_EPILOG
    ret
gui_main endp

; =============================================================================
; wstart - process entry point (linker /entry:wstart).  Raw frame.
; =============================================================================
public wstart
wstart proc
    sub     rsp, 56
    call    cpu_gate
    mov     dword ptr [rsp+48], eax
    call    hardening_init
    test    eax, eax
    jz      ws_oom
    call    crash_install                   ; arm crash containment before any secrets exist
    call    parse_cmdline
    call    is_cli_command
    test    eax, eax
    jz      ws_gui

    ; ========================= CLI MODE =====================================
    call    con_attach_parent
    call    con_init
    cmp     dword ptr [rsp+48], 0
    je      ws_nocpu_cli
    call    iat_lockdown
    xor     ecx, ecx
    call    run_selftest
    test    eax, eax
    jnz     ws_stfail_cli
    call    dispatch
    mov     dword ptr [rsp+52], eax
    lea     rcx, [g_cfg_pass]
    mov     edx, MAX_PASSWORD_BYTES+1
    call    secure_zero
    WINCALL ExitProcess, dword ptr [rsp+52]
ws_stfail_cli:
    lea     rcx, [c_stfail]
    mov     edx, c_stfail_len
    call    print_err
    WINCALL ExitProcess, EXIT_SELFTEST
ws_nocpu_cli:
    lea     rcx, [c_nocpu]
    mov     edx, c_nocpu_len
    call    print_err
    WINCALL ExitProcess, EXIT_NOCPU

    ; ========================= GUI MODE =====================================
ws_gui:
    call    con_init
    cmp     dword ptr [rsp+48], 0
    je      ws_nocpu
    call    iat_lockdown
    xor     ecx, ecx
    call    run_selftest
    test    eax, eax
    jnz     ws_stfail_gui
    ; single-instance guard: two GUIs on one vault would clobber each other's
    ; saves.  If the named mutex already exists, surface the running instance
    ; (focus its open dialog, or ask its tray window to open the flow), then exit.
    WINCALL CreateMutexW, 0, 1, addr g_singleton_name
    call    GetLastError
    cmp     eax, 183                        ; ERROR_ALREADY_EXISTS
    jne     ws_gui_go
    WINCALL FindWindowW, 0, addr g_vault_title
    test    rax, rax
    jnz     ws_gui_focus
    WINCALL FindWindowW, 0, addr g_unlock_title
    test    rax, rax
    jnz     ws_gui_focus
    WINCALL FindWindowW, 0, addr g_create_title
    test    rax, rax
    jnz     ws_gui_focus
    ; no dialog is up: the running instance is sitting in the tray - post it an
    ; Open command so IT shows the unlock/create flow, instead of dying silently
    WINCALL FindWindowW, addr tray_cls, 0
    test    rax, rax
    jz      ws_gui_exit
    WINCALL PostMessageW, rax, WM_COMMAND, IDM_OPEN, 0
    jmp     ws_gui_exit
ws_gui_focus:
    WINCALL SetForegroundWindow, rax
ws_gui_exit:
    WINCALL ExitProcess, 0
ws_gui_go:
    mov     dword ptr [g_gui_active], 1      ; enable the crash-time apology box
    call    gui_main
    WINCALL ExitProcess, 0
ws_stfail_gui:
    WINCALL MessageBoxW, 0, addr m_stfail, addr t_err, <MB_OK or MB_ICONERROR>
    WINCALL ExitProcess, EXIT_SELFTEST
ws_nocpu:
    WINCALL MessageBoxW, 0, addr m_nocpu, addr t_err, <MB_OK or MB_ICONERROR>
    WINCALL ExitProcess, EXIT_NOCPU
ws_oom:
    WINCALL ExitProcess, EXIT_OOM
wstart endp

end
