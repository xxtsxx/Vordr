; =============================================================================
; gui.asm - hybrid entry point (wstart) + the Win32 vault GUI.
; -----------------------------------------------------------------------------
; The single vordr.exe is linked /subsystem:windows with entry point `wstart`.
; wstart runs the CLI diagnostics when argv[1] is a known verb; otherwise it
; opens the GUI - the only place the vault and secrets are ever handled, so a
; master password or secret never appears on the command line.
;
; The GUI uses three dialog-resource templates (DLG_UNLOCK / DLG_VAULT /
; DLG_ENTRY in vordr.rc).  The vault is unlocked ONCE (key in g_vkey, body in
; locked memory); the dialogs read entries and mutate the in-memory body, then
; re-seal to disk via the vault session API (vault_unlock/reseal/add/remove/...).
;
; Dialog procs are RAW frames (no FRAME_PROLOG): they are OS callbacks, so the
; software shadow stack must not be touched across them.  The helper procs they
; call are ordinary FRAME_PROLOG procedures.
; =============================================================================

include macros.inc

; ---- startup helpers ---------------------------------------------------------
extern cpu_gate:proc
extern hardening_init:proc
extern con_init:proc
extern con_attach_parent:proc
extern iat_lockdown:proc
extern parse_cmdline:proc
extern is_cli_command:proc
extern dispatch:proc
extern run_selftest:proc
extern secure_zero:proc
extern print_err:proc

; ---- vault session API (vault.asm) + password helper (main.asm) -------------
extern password_to_utf8:proc
extern do_init:proc
extern vault_unlock:proc
extern vault_lock:proc
extern vault_reseal:proc
extern vault_add_entry:proc
extern vault_remove_at:proc
extern vault_count:proc
extern vault_title_at:proc
extern vault_field_at:proc
extern vault_entry_ptr:proc
extern g_carry_created:qword
extern pwgen_ex:proc
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
extern ze_free:proc
externdef g_zbuf:qword
extern ShellExecuteW:proc
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
externdef g_cfg_pass:byte
externdef g_cfg_title:qword
externdef g_cfg_user:qword
externdef g_cfg_secret:qword
externdef g_cfg_url:qword
externdef g_cfg_notes:qword
externdef g_cfg_totp:qword

; ---- Win32 -------------------------------------------------------------------
extern GetModuleHandleW:proc
extern ExitProcess:proc
extern MessageBoxW:proc
extern DialogBoxParamW:proc
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
extern GlobalLock:proc
extern GlobalUnlock:proc
extern GetClipboardSequenceNumber:proc
extern SetTimer:proc
extern KillTimer:proc
extern MultiByteToWideChar:proc
extern WideCharToMultiByte:proc
extern IsDlgButtonChecked:proc
extern EnableWindow:proc
extern GetDlgItem:proc
extern GetFocus:proc
extern CharUpperBuffW:proc
extern SetFocus:proc
extern SetDlgItemInt:proc
extern GetDlgItemInt:proc
extern GetFileAttributesW:proc
extern CreateDirectoryW:proc
extern ShowWindow:proc
extern MoveWindow:proc
extern GetWindowRect:proc
extern ScreenToClient:proc
extern SetWindowPos:proc
extern DrawTextW:proc
extern FrameRect:proc
extern MapDialogRect:proc
extern SendMessageW:proc
extern PostMessageW:proc
extern SetWindowTextW:proc
extern CheckDlgButton:proc
extern GetDlgCtrlID:proc
extern GetKeyState:proc
extern SetWindowLongPtrW:proc
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
extern theme_tick:proc
extern theme_paint:proc
extern theme_erase:proc
extern theme_ctlcolor:proc
extern theme_drawitem:proc
extern theme_toggle:proc
extern theme_toggle_labeled:proc
extern theme_progressbar:proc
extern g_font_totp:qword
extern theme_backdrop:proc
extern theme_overlay:proc
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

; ---- constants ---------------------------------------------------------------
MB_OK               equ 0
MB_ICONERROR        equ 10h
MB_ICONINFORMATION  equ 40h
MB_ICONWARNING      equ 30h
MB_YESNO            equ 4
MB_ICONQUESTION     equ 20h
MB_DEFBUTTON2       equ 100h
IDYES               equ 6
IDNO                equ 7
IDOK                equ 1
IDCANCEL            equ 2
DS_CENTER           equ 0800h

WM_CLOSE            equ 10h
WM_TIMER            equ 113h
WM_INITDIALOG       equ 110h
WM_SETFONT          equ 30h
WM_MOUSEWHEEL       equ 20Ah
WM_COMMAND          equ 111h
WM_PAINT            equ 0Fh
WM_SETCURSOR        equ 20h
WM_ERASEBKGND       equ 14h
WM_DRAWITEM         equ 2Bh
GWLP_WNDPROC        equ -4
IDC_HAND            equ 32649
HTCLIENT            equ 1
LINK_BLUE           equ 00E08C3Ch        ; COLORREF (RGB 60,140,224) hyperlink blue
WM_MEASUREITEM      equ 2Ch
WM_COMPAREITEM      equ 39h
WM_CTLCOLOREDIT     equ 133h
WM_CTLCOLORLISTBOX  equ 134h
WM_CTLCOLORBTN      equ 135h
WM_CTLCOLORDLG      equ 136h
WM_CTLCOLORSTATIC   equ 138h
THEME_TIMER         equ 9
EM_SETCUEBANNER     equ 1501h
; ---- system tray / window-loop -----------------------------------------------
WM_DESTROY          equ 2
WM_LBUTTONUP        equ 0202h
WM_LBUTTONDBLCLK    equ 0203h
WM_RBUTTONUP        equ 0205h
WM_TRAYICON         equ 8001h            ; WM_APP+1, our tray callback message
NIM_ADD             equ 0
NIM_DELETE          equ 2
NIF_TRAY            equ 7                 ; NIF_MESSAGE | NIF_ICON | NIF_TIP
MF_STRING           equ 0
MF_SEPARATOR        equ 800h
MF_OWNERDRAW        equ 100h
MIM_DARK            equ 80000002h        ; MIM_APPLYTOSUBMENUS | MIM_BACKGROUND
TPM_RIGHTBUTTON     equ 2
TPM_LEFTALIGN       equ 0
TPM_RETURNCMD       equ 0100h
WS_EX_TOOLWINDOW    equ 80h
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
CLIP_MS             equ 20000              ; clear a copied secret after 20 s
TOTP_TIMER          equ 2                  ; timer id for live auth-code refresh
TOTP_MS             equ 1000               ; recompute the code once a second
SEARCH_TIMER        equ 3                  ; timer id for debounced search-as-you-type
SEARCH_MS           equ 300                ; refilter only after 0.3 s of no keystrokes
SEARCH_DEBOUNCE_MIN equ 200               ; ...but only when the list exceeds this many entries
LBN_SELCHANGE       equ 1
LB_ADDSTRING        equ 180h
LB_RESETCONTENT     equ 184h
LB_SETCURSEL        equ 186h
LB_GETCURSEL        equ 188h
LB_GETCOUNT         equ 18Bh
LB_GETITEMDATA      equ 199h
LB_ERR              equ -1
EM_SETSEL           equ 0B1h
EM_SETREADONLY      equ 0CFh

CP_UTF8_            equ 65001
CF_UNICODETEXT      equ 13
GMEM_MOVEABLE       equ 2

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
IDC_V_MENU   equ 216
EM_SETPASSWORDCHAR equ 0CCh
SECRET_MASK  equ 2022h                ; bullet mask char for the secret field
IDC_V_MBACK  equ 217
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
IDC_V_MTHEME equ 240                  ; color-scheme cycle button (settings)
IDC_V_MTHEMEL equ 241                 ; "Color scheme" label
IDC_V_COLORPW equ 244                 ; overlay: colored revealed secret (owner-draw)
IDC_V_MEXPORT equ 245                 ; "Export all secrets to Excel" button (settings)
IDC_V_MIMPORT equ 246                 ; "Import..." button (auto-detects CSV / xlsx)
IDC_V_MEXPZIP equ 247                 ; "Export to encrypted ZIP" button (settings)
DLG_ICON      equ 740                 ; icon picker (glyph grid + colour swatches)
IDC_I_PREV    equ 850                 ; icon picker: live preview tile
IDC_IG_BASE   equ 800                 ; icon picker: glyph buttons (18)
IDC_IC_BASE   equ 830                 ; icon picker: colour swatches (12)
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
LVM_GETITEMSTATE             equ LVM_FIRST + 44
LVM_GETITEMW                 equ LVM_FIRST + 75
LVM_GETITEMCOUNT             equ LVM_FIRST + 4
LVM_INSERTCOLUMNW            equ LVM_FIRST + 97
LVM_SETCOLUMNWIDTH           equ LVM_FIRST + 30
LVM_SETBKCOLOR               equ LVM_FIRST + 1
LVM_SETTEXTCOLOR             equ LVM_FIRST + 36
LVM_SETTEXTBKCOLOR           equ LVM_FIRST + 38
LVM_SETEXTENDEDLISTVIEWSTYLE equ LVM_FIRST + 54
LVSIL_STATE                  equ 2
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
IDC_C_PWBAR  equ 404                  ; strength line under the master-password box
IDC_C_PW2BAR equ 405                  ; match line under the confirm box
IDC_C_INFO   equ 406                  ; (i) password-requirements callout
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

; --- modular field rows (runtime-built detail form) ------------------------
; Per-row descriptor (flat record, stride DESCSZ) in g_fields[].
FD_KIND     equ 0               ; dd  base kind (VF_TEXT/USERNAME/SECRET/URL/NOTES/TOTP)
FD_FLAGS    equ 4               ; dd  bit0 = custom label; bits4-5 = pw-strength grade
FD_Y        equ 8              ; dd  row top in DLU (within the detail pane)
FD_H        equ 12             ; dd  row height in DLU
FD_HANDLES  equ 16             ; q[DYN_SLOTS]  control hwnd per slot (0 = absent)
FD_ARF      equ 144            ; {u32 len, AttachRef[68], filename wide}  attachment value blob
FD_RSVD     equ 472            ; q  reserved (kept for 16-byte DESCSZ alignment)
ARFBLOB     equ 328            ; size of the {u32 len,AttachRef,filename} attachment blob
DESCSZ      equ 480            ; 16 + 16 handles*8 + 328 arf blob + 8 reserved (16-aligned)
; The attachments tile aggregates every VF_FILE/VF_IMAGE field of the open entry
; into one row backed by g_tilefiles (see the tf_* helpers).  Each file entry is
; {AttachRef[68], filename wide (NUL-terminated, <=129 wchars)}.
MAX_TFILES  equ 24             ; <= MAX_FIELDS minus the other fields of an entry
TFILE_ENTRY equ 328
TFILE_NAME  equ 68             ; filename offset within a tile-file entry
MAX_FIELDS  equ 56             ; g_field_list capacity (matches main.asm)
; Field history: each overwritten field value (ANY tile, not just secrets) is
; archived as a reserved VF_PWHIST field, value = raw {u64 FILETIME, label wide,
; old value wide} (VFL_RAW).  Loaded into g_pwhist for the open entry; g_pworig
; holds the entry's ORIGINAL field values keyed by (effective) label at load, so
; gui_commit can detect per-tile which values were overwritten.  The browser
; groups records into one tab per label.
MAX_PWHIST   equ 64
PWHIST_ENTRY equ 528           ; {u64 filetime, label wide[128], value wide[128]}
PWHIST_LBL   equ 8             ; label offset within a g_pwhist entry
PWHIST_PW    equ 264           ; value offset (8 + 128*2)
PWHBLOB_ENTRY equ 512          ; emit scratch {u32 len, u64 ft, label wide, value wide}
MAX_PWORIG   equ 24            ; up to MAXROWS value fields captured per entry
PWORIG_STRIDE equ 512          ; original field {label wide[128], value wide[128]}
PWORIG_VAL   equ 256           ; value offset (bytes) within a g_pworig slot
MAXROWS     equ 24
FDF_LABELED equ 1               ; FD_FLAGS bit0 = carries a custom label
FDF_REVEALED equ 2              ; FD_FLAGS bit1 = value currently unmasked
FDF_HASIMG  equ 4               ; FD_FLAGS bit2 = attachment row has a blob in FD_ARF
FDF_PWLVL_MASK equ 30h          ; FD_FLAGS bits4-5 = secret strength grade 0..3
FDF_PWLVL_SHIFT equ 4
; Runtime control ids: IDC_DYN_BASE + row*DYN_SLOTS + slot (DYN_SLOTS = power of 2).
IDC_DYN_BASE equ 3000
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
DS_EXPORT   equ 12              ; attachment: save the file to disk
DS_OPEN     equ 13              ; attachment: open the file in the default app
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
PH_TABH      equ 28           ; height (px) of the per-tile tab strip atop the list
MAX_TABS     equ 16           ; distinct labels (tabs) shown in the history browser
IDC_V_TIMES  equ 236          ; created/modified timestamps line (below the last row)
IDC_V_FAV    equ 237          ; header favorite (star) toggle
IDC_V_CANCEL equ 238          ; "Cancel" button (edit mode, discards edits)
FIELD_AREA_BOTTOM equ 292        ; rows may not grow past here (DLU; Add-field is at 296)
; Win32 window styles (gui.asm builds controls at runtime; the RC gets these
; from windows.h, but this module needs the numeric values).
WS_CHILD_       equ 40000000h
WS_VISIBLE_     equ 10000000h
WS_TABSTOP_     equ 00010000h
ES_AUTOHSCROLL_ equ 0080h
ES_AUTOVSCROLL_ equ 0040h
ES_PASSWORD_    equ 0020h
ES_MULTILINE_   equ 0004h
ES_READONLY_    equ 0800h
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
CSTR c_nocpu,   "error: CPU lacks required features (AES-NI/PCLMULQDQ/SSE4.1)",13,10
CSTR c_stfail,  "SELFTEST FAILURE - refusing to run",13,10
; ---- wide message-box strings (WSTR: no commas) -----------------------------
WSTR t_err,         <Vordr - error>
WSTR m_nocpu,       <This CPU lacks required features (AES-NI / PCLMULQDQ / SSE4.1) - cannot run.>
WSTR m_stfail,      <Self-test FAILED - refusing to run. The binary may be corrupt.>
WSTR t_open,        <Open vault>
WSTR t_remove,      <Remove this entry?>
WSTR s_pickvault,   <Select or create a vault file first.>
WSTR s_nopw,        <Enter the master password.>
WSTR s_badpw,       <Password must be 1..1024 UTF-8 bytes.>
WSTR s_wrongpw,     <Wrong master password.>
WSTR s_corrupt,     <Not a Vordr vault or the file is corrupt.>
WSTR s_io,          <Cannot read or write that file.>
WSTR s_createfail,  <Could not create the vault (I/O or out of memory).>
WSTR s_notitle,     <An entry needs a title.>
WSTR s_nofieldroom, <No room for more fields on this record - remove one first.>
WSTR s_resealfail,  <Saved in memory but writing to disk failed.>
WSTR t_overwrite,   <Vordr - vault already exists>
WSTR m_overwrite,   <A vault file already exists at this location. Creating a new vault will PERMANENTLY destroy it and every entry it holds. Overwrite it?>
WSTR s_kept,        <Existing vault kept. Cancel, or use "Create new..." to choose a different file.>
WSTR s_pwmismatch,  <The passwords do not match.>
WSTR s_pwshort,     <Password is too short for the current policy.>
WSTR s_pwclasses,   <Password needs more character types (lowercase / uppercase / number / symbol).>
WSTR wt_newentry,   <New entry>
WSTR cue_search,    <Search>
WSTR sel_cap_imp,   <Vordr - Select entries to import>
WSTR sel_ok_imp,    <Import>
WSTR t_tpminfo,     <TPM Unlock>
WSTR m_tpminfo,     <The TPM chip in this computer can unlock the vault automatically on this device. You will not need to type the master password at startup. The password still works everywhere and is never stored.>
WSTR cue_pw,        <Master password>
WSTR cue_pw2,       <Confirm password>
WSTR t_req,         <Password requirements>
WSTR req_p1,        <Your master password must be at least >
WSTR req_p2,        < characters and use at least >
WSTR req_p3,        < of 4 character types - lowercase / uppercase / number / symbol.>
WSTR wv_pwlen,      <PwMinLen>
WSTR wv_pwcls,      <PwMinClasses>
WSTR wv_nohist,     <NoHistory>
WSTR wv_nophon,     <NoPhonetic>
; --- system tray strings ------------------------------------------------------
WSTR t_about,       <About Vordr>
WSTR m_about,       <Vordr - a hardened password manager. AES-256-GCM with Argon2id key derivation. Fail-closed and self-tested on every launch. Written in x64 assembly with no runtime dependencies.>
WSTR mi_open,       <Open>
WSTR mi_exit,       <Exit>
WSTR mb_ok,         <OK>
WSTR mb_yes,        <Yes>
WSTR mb_no,         <No>
tray_cls label word
    dw 'V','o','r','d','r','T','r','a','y', 0
tray_wt label word
    dw 'V','o','r','d','r', 0
; OPENFILENAMEW filter: "Vordr vault\0*.vordr\0All files\0*.*\0\0"
align 2
xlsx_filter label word
    dw 'E','x','c','e','l',' ','W','o','r','k','b','o','o','k',0
    dw '*','.','x','l','s','x',0
    dw 0
xlsx_defext label word
    dw 'x','l','s','x',0
WSTR xp_mm_title,    <Export all secrets>
WSTR imp_xls_wrongpw,<Could not open the workbook - the password was incorrect.>
WSTR imp_g_title,    <Import>
WSTR imp_g_pre,      <Imported >
WSTR imp_g_post,     < entries.>
WSTR imp_g_none,     <No importable entries were found in that file.>
WSTR imp_g_bad,      <That file is not a Vordr encrypted export (.zip), or the password was wrong.>
WSTR zip_title,      <Export to encrypted archive>
WSTR zip_defname,    <vordr-export.zip>
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
WSTR cue_xppw2,      <Confirm password>
WSTR cue_ippw,       <Workbook password>
WSTR imp_pw_title,   <Import from Excel>
WSTR imp_pw_empty,   <Please enter the workbook password.>
; burger / close glyphs for the settings button (wide)
wb_menu label word
    dw 2630h, 0                                  ; trigram for heaven (hamburger)
wb_close label word
    dw 2715h, 0                                  ; multiplication X
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
    dw 0E734h, 0                                 ; FavoriteStar (outline = not favorite)
wb_starf label word
    dw 0E735h, 0                                 ; FavoriteStarFill (favorited)
fav_one label word
    dw '1', 0                                    ; VF_FAV marker value
pht_lbl db 'Password'                            ; gui_phtest scratch (headless probe)
pht_old db 'oldpw'
pht_ttl dw 'T', 0
pht_new dw 'n','e','w','p','w', 0
pht_loginu  db 'Login'                           ; phtest: a 2nd, different-label field
pht_stayu   db 'stays'
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
layout_gaps  dd 7, 3, 14                          ; inter-card gap (DLU) per layout
lay_band     dd 14, 0, 18                         ; label band: card(top) vs 0=flat(left)
lay_itemh    dd 42, 30, 58                         ; list-item pixel height (index 0 used)
pref_scheme dw 'u','i','_','s','c','h','e','m','e',0
pref_layout dw 'u','i','_','l','a','y','o','u','t',0
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
f_iconname label word
    dw 'S','e','g','o','e',' ','F','l','u','e','n','t',' ','I','c','o','n','s', 0
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
t_created label word
    dw 'C','r','e','a','t','e','d',' ', 0
t_modified label word
    dw ' ',' ',' ',' ','M','o','d','i','f','i','e','d',' ', 0
cap_noimg label word
    dw '(','n','o',' ','i','m','a','g','e',')', 0
suffix_dotpng label word
    dw '.','p','n','g', 0
g_imgfilter label word          ; "Images\0*.png;*.jpg;*.jpeg;*.bmp;*.gif\0All\0*.*\0\0"
    dw 'I','m','a','g','e','s',0
    dw '*','.','p','n','g',';','*','.','j','p','g',';','*','.','j','p','e','g',';','*','.','b','m','p',';','*','.','g','i','f',0
    dw 'A','l','l',' ','f','i','l','e','s',0
    dw '*','.','*',0,0
g_allfilter label word          ; "All files\0*.*\0\0"
    dw 'A','l','l',' ','f','i','l','e','s',0
    dw '*','.','*',0,0
g_zipfilter label word          ; "ZIP archive\0*.zip\0\0"
    dw 'Z','I','P',' ','a','r','c','h','i','v','e',0
    dw '*','.','z','i','p',0,0
g_vaultfilter label word        ; "Vordr vault\0*.vordr\0All files\0*.*\0\0"
    dw 'V','o','r','d','r',' ','v','a','u','l','t',0
    dw '*','.','v','o','r','d','r',0
    dw 'A','l','l',' ','f','i','l','e','s',0
    dw '*','.','*',0,0
g_impfilter label word          ; "Vordr export\0*.zip\0All files\0*.*\0\0"
    dw 'V','o','r','d','r',' ','e','x','p','o','r','t',0
    dw '*','.','z','i','p',0
    dw 'A','l','l',' ','f','i','l','e','s',0
    dw '*','.','*',0,0
g_empty_w label word
    dw 0                                          ; empty wide string (default field value)
; control-id groups toggled when the settings overlay opens/closes
align 4
g_vault_ids label dword
    dd IDC_V_LIST, IDC_V_ADD, IDC_V_EDIT, IDC_V_REMOVE, IDC_V_TITLE
    dd IDC_V_ADDFIELD, IDC_V_SAVE, IDC_V_LOCK, IDC_V_SEARCH
VAULT_ID_COUNT equ 9
g_menu_ids label dword
    dd IDC_V_MBACK, IDC_V_MTITLE, IDC_V_MPOLL, IDC_V_MLENL, IDC_V_MLEN
    dd IDC_V_MCLSL, IDC_V_MCLS, IDC_V_MTPM, IDC_V_MTPML, IDC_V_MTPMINFO
    dd IDC_V_MTHEMEL, IDC_V_MTHEME, IDC_V_MEXPORT
    dd IDC_V_MIMPORT
    dd IDC_V_MNOHISTL, IDC_V_MNOHIST, IDC_V_MNOPHONL, IDC_V_MNOPHON
MENU_ID_COUNT equ 18

.data?
align 8
g_hinst     dq ?
g_trayhwnd  dq ?                      ; hidden owner window that hosts the tray icon
g_showing   dd ?                      ; 1 = a modal dialog is currently open (re-entry guard)
g_msg_text  dq ?                      ; Fluent message box: body text / title / flags
g_msg_title dq ?
g_msg_flags dd ?
g_tpm_want  dd ?                      ; Fluent TPM toggle state (1 = enrolled/on)
align 8
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
g_reqbuf    dw 512 dup (?)            ; formatted password-requirements callout text
g_numtmp    db 16 dup (?)             ; scratch for uint-to-decimal
g_vault_lock dd ?                     ; 1 = vault path set by HKLM (locked)
g_menu_open  dd ?                     ; 1 = settings overlay is showing
g_revealed  dd ?
g_clip_seq  dd ?                      ; clipboard sequence number at last copy
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
g_vpath     dw 1024 dup (?)        ; chosen vault path (wide, NUL-terminated)
g_xlpw      dw 256 dup (?)         ; export password (wide; wiped after use)
g_xlpw2     dw 256 dup (?)         ; export confirm password (wide; wiped)
g_xlpwlen   dd ?                   ; export password length in bytes
g_pwbuf     dw 1024 dup (?)        ; password field (wide; wiped after use)
g_pw2buf    dw 1024 dup (?)        ; confirm-password field (wide; wiped)
g_conv_w    dw EBUF*2 dup (?)      ; utf8 -> wide display scratch
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
g_icon_set    dd ?                         ; current entry has a custom icon override (0/1)
g_icon_glyph  dd ?                         ; override glyph codepoint (when g_icon_set)
g_icon_color  dd ?                         ; override tile COLORREF   (when g_icon_set)
g_ovr_glyph   dd ?                         ; scratch: gui_entry_icon result glyph
g_ovr_color   dd ?                         ; scratch: gui_entry_icon result color
g_icon_valw   dw 20 dup (?)                ; scratch wide "GGGGCCCCCCCC" for saving
g_pick_glyph  dd ?                         ; icon picker working selection (glyph)
g_pick_color  dd ?                         ; icon picker working selection (color)
g_layout      dd ?                         ; UI layout/density index (0 comfortable)
g_colorpw_row dd ?                         ; row whose revealed secret is colored (-1=none)
g_rowpw_w     dw 512 dup (?)               ; revealed secret text for the color overlay
g_wordtmp     dw 32 dup (?)                ; one resolved phonetic word (scratch)
g_content_h   dd ?                        ; field-form content bottom (DLU) after layout
g_dlgfont     dq ?                        ; the vault dialog's font (for runtime ctls)
g_totp_row    dd ?                        ; row index of the TOTP field (-1 = none)
g_totp_codehwnd dq ?                      ; live-code display control of the TOTP row
g_totp_barhwnd  dq ?                      ; drain-bar control of the TOTP row
align 8
g_iconfont    dq ?                         ; Segoe Fluent Icons for list/tile glyphs
g_cardfont    dq ?                         ; list entry title (semibold)
g_subfont     dq ?                         ; list entry subtitle (regular, dim)
g_titlefont   dq ?                         ; detail-header title (large semibold)
g_chevfont    dq ?                         ; small Fluent icons for flat reorder chevrons
g_monofont    dq ?                         ; monospace font for the colored password readout
g_phonfont    dq ?                         ; small monospace font for the phonetic columns
g_sub_w       dw 512 dup (?)               ; subtitle scratch (wide)
g_cmpbuf      db 256 dup (?)               ; title-A copy for WM_COMPAREITEM
g_imp_msgw    dw 160 dup (?)               ; CSV-import result message scratch (wide)
g_pg_len      dd ?                         ; password-generator: length
g_pg_style    dd ?                         ;   PWS_* style
g_pg_opt      dd ?                         ;   class mask + PWO_* flags
g_pg_target   dd ?                         ;   secret row to fill on "Use" (-1 = none)
g_pg_bits     dd ?                         ;   last entropy estimate
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
g_pwhist      db MAX_PWHIST*PWHIST_ENTRY dup (?) ; open entry's overwritten passwords
g_pwhist_n    dd ?                               ; number of history entries
g_pwhblob     db MAX_PWHIST*PWHBLOB_ENTRY dup (?); per-history emit scratch (VFL_RAW)
g_pworig      db MAX_PWORIG*PWORIG_STRIDE dup (?); original {label,value} per secret
g_pworig_n    dd ?
g_pwh_scroll  dd ?                               ; history browser: first visible row
g_pwh_dirty   dd ?                               ; history browser: a purge happened
g_phdate      dw 40 dup (?)                      ; history browser: formatted date scratch
g_pwh_tab     dd ?                               ; selected tab (0-based)
g_pwh_ntabs   dd ?                               ; number of distinct-label tabs
g_pwh_tabs    dd MAX_TABS dup (?)                ; each tab -> a representative g_pwhist index
g_pwh_filter  dd MAX_PWHIST dup (?)              ; g_pwhist indices belonging to the current tab
g_pwh_fn      dd ?                               ; number of rows in g_pwh_filter
align 2
g_imgfn_w     dw 200 dup (?)               ; current image's filename (wide) to store
g_imgbuf      dq ?                         ; imported file bytes (mem_alloc'd)
g_imgbuflen   dq ?
g_pickfilter  dq ?                         ; OPENFILENAME filter for the next pick (0=image)
g_tmpfile     dw 1024 dup (?)              ; temp path for opening an attachment (wide)
align 2
g_imgpath     dw 1024 dup (?)             ; import/export file path (wide)
g_valblob   dw 32768 dup (?)          ; commit scratch: field values, NUL-joined
g_lblblob   dw 4096 dup (?)           ; commit scratch: custom labels, NUL-joined
g_rlabel    dw 128 dup (?)            ; per-row label read scratch
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
    mov     r9d, EBUF*2-1
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
    call    gui_wipepw
    cmp     dword ptr [rbp-32], 0
    jne     gu_fail
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
    lea     rcx, [g_vpath]                    ; classify: 0 OneDrive / 1 Documents / 2 other
    call    cfg_classify_path
    lea     r8, [gl_cloud]
    lea     r9, [st_onedrive]
    cmp     eax, 0
    je      gds_have
    cmp     eax, 1
    jne     gds_other
    lea     r8, [gl_doc]
    lea     r9, [st_documents]
    jmp     gds_have
gds_other:
    lea     r8, [gl_folder]
    lea     r9, [g_vpath]
gds_have:
    mov     qword ptr [rbp-48], r8            ; glyph ptr
    mov     qword ptr [rbp-56], r9            ; label ptr
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
    WINCALL GetOpenFileNameW, addr g_ofn
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
    cmp     rdx, WM_TIMER
    je      up_ttimer
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
    jne     up_tdraw_def
    mov     rcx, r9
    call    gui_draw_storage
    mov     eax, 1
    jmp     up_ret
up_tdraw_def:
    mov     rcx, r9
    call    theme_drawitem
    jmp     up_ret
up_ttimer:
    cmp     r8d, THEME_TIMER
    jne     up_tunh
    mov     rcx, qword ptr [rbp-8]
    call    theme_tick
    mov     eax, 1
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
    cmp     eax, IDCANCEL
    je      up_cancel
    xor     eax, eax
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
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_RESETCONTENT, 0, 0
    ; read the search query and upper-case it for case-insensitive matching
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_V_SEARCH, addr g_search_w, 255
    mov     dword ptr [rbp-56], eax              ; query length (chars)
    test    eax, eax
    jz      gp_nofold
    WINCALL CharUpperBuffW, addr g_search_w, dword ptr [rbp-56]
gp_nofold:
    call    vault_count
    mov     dword ptr [rbp-32], eax              ; count
    mov     dword ptr [rbp-40], 0               ; index
gp_loop:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [rbp-32]
    jae     gp_done
    cmp     dword ptr [rbp-56], 0               ; empty query -> show everything
    je      gp_show
    mov     ecx, dword ptr [rbp-40]
    call    gui_entry_matches
    test    eax, eax
    jz      gp_next
gp_show:
    ; owner-draw list: the item data IS the vault index; WM_COMPAREITEM sorts by
    ; title, WM_DRAWITEM renders the icon card.  Pass the index as a DWORD so the
    ; 64-bit LPARAM is zero-extended (the slot is a dword; a qword read would take
    ; the uninitialized 4 bytes above it into the stored item data).
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_ADDSTRING, 0, \
            dword ptr [rbp-40]
gp_next:
    inc     dword ptr [rbp-40]
    jmp     gp_loop
gp_done:
    FRAME_EPILOG
    ret
gui_poplist endp

; =============================================================================
; Owner-draw entry list: icon-tile cards (glyph + title + subtitle)
; =============================================================================

; gui_make_listfonts() - lazily create the list fonts.
gui_make_listfonts proc frame
    FRAME_PROLOG 112
    cmp     qword ptr [g_iconfont], 0
    jne     mlf_done
    WINCALL CreateFontW, -19, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, addr f_iconname
    mov     qword ptr [g_iconfont], rax
    WINCALL CreateFontW, -14, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, addr f_segoeui
    mov     qword ptr [g_cardfont], rax
    WINCALL CreateFontW, -12, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, addr f_segoeui
    mov     qword ptr [g_subfont], rax
    WINCALL CreateFontW, -21, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, addr f_segoeui
    mov     qword ptr [g_titlefont], rax
    WINCALL CreateFontW, -11, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, addr f_iconname
    mov     qword ptr [g_chevfont], rax
    WINCALL CreateFontW, -24, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, addr f_mono
    mov     qword ptr [g_monofont], rax
    WINCALL CreateFontW, -12, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, addr f_mono
    mov     qword ptr [g_phonfont], rax
mlf_done:
    FRAME_EPILOG
    ret
gui_make_listfonts endp

; gui_title_cmp(ecx=idxA, edx=idxB) -> eax = -1/0/1 (case-insensitive title order).
gui_title_cmp proc frame
    FRAME_PROLOG 96
    mov     dword ptr [rbp-24], ecx
    mov     dword ptr [rbp-28], edx
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
    mov     r9d, EBUF*2-1
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
    mov     r9d, EBUF*2-1
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
    FRAME_PROLOG 96
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
    ; clear to dialog base so nothing lingers behind the pill
    WINCALL CreateSolidBrush, dword ptr [g_col_bg]
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
    ; clear the whole item rect to the dialog base
    WINCALL CreateSolidBrush, dword ptr [g_col_bg]
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
    FRAME_PROLOG 160
    mov     qword ptr [rbp-24], rcx            ; hdc
    mov     qword ptr [rbp-32], rdx            ; hdlg
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
    mov     dword ptr [rbp-64], 0              ; row i
gfc_lp:
    mov     eax, dword ptr [rbp-64]
    cmp     eax, dword ptr [g_field_count]
    jae     gfc_done
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     eax, dword ptr [r10+FD_Y]
    mov     dword ptr [rbp-84], eax            ; T
    add     eax, dword ptr [r10+FD_H]
    mov     dword ptr [rbp-76], eax            ; B
    mov     dword ptr [rbp-88], 214            ; L (156 + VDX_DLU)
    mov     dword ptr [rbp-80], 472            ; R (414 + VDX_DLU)
    WINCALL MapDialogRect, qword ptr [rbp-32], addr rbp-88
    WINCALL RoundRect, qword ptr [rbp-24], dword ptr [rbp-88], dword ptr [rbp-84], \
            dword ptr [rbp-80], dword ptr [rbp-76], 10, 10
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

; gui_lb_seldata(rcx = hdlg) -> eax = vault index of the selected row (its item
;   data), or -1 if nothing is selected.
gui_lb_seldata proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_GETCURSEL, 0, 0
    mov     dword ptr [rbp-32], eax
    cmp     eax, LB_ERR
    je      gls_none
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_GETITEMDATA, \
            dword ptr [rbp-32], 0
    FRAME_EPILOG
    ret
gls_none:
    mov     eax, -1
    FRAME_EPILOG
    ret
gui_lb_seldata endp

; gui_lb_selbydata(rcx = hdlg, edx = vault index) -> eax = selected row, or -1.
;   Finds the row whose item data == the vault index and selects it.
gui_lb_selbydata proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx              ; target vault index
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_GETCOUNT, 0, 0
    mov     dword ptr [rbp-40], eax              ; row count
    mov     dword ptr [rbp-48], 0               ; i
glb_loop:
    mov     eax, dword ptr [rbp-48]
    cmp     eax, dword ptr [rbp-40]
    jae     glb_none
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_GETITEMDATA, \
            dword ptr [rbp-48], 0
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
    mov     dword ptr [rbp-32], eax              ; topmost vault index
    cmp     eax, 0
    jl      gct_done
    mov     ecx, dword ptr [rbp-32]
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
    ; reserved archive {u64 filetime, label wide\0, pw wide\0} -> g_pwhist (not a row).
    ; Back-compat: an older record is just {u64 filetime, pw wide\0} (no label).
    mov     eax, dword ptr [rbp-64]             ; vallen
    cmp     eax, 10
    jb      gsd_fnext                           ; need the filetime + a NUL
    mov     r10, qword ptr [rbp-72]             ; valptr
    mov     rcx, qword ptr [r10]                ; filetime qword
    lea     r8, [r10+8]                         ; scan string1 to its NUL
    xor     r9d, r9d
gsd_ph_scan:
    cmp     word ptr [r8], 0
    je      gsd_ph_s1end
    add     r8, 2
    inc     r9d
    cmp     r9d, 255
    jb      gsd_ph_scan
gsd_ph_s1end:
    add     r8, 2                               ; past string1's NUL
    mov     r11, r10                            ; value end = valptr + vallen
    mov     eax, dword ptr [rbp-64]
    add     r11, rax
    cmp     r8, r11
    jb      gsd_ph_new                          ; a second string follows -> new format
    lea     rdx, [kl_secret]                    ; old format: label = "Password",
    lea     r8, [r10+8]                         ;             pw = value+8
    call    pwh_append
    jmp     gsd_fnext
gsd_ph_new:
    lea     rdx, [r10+8]                        ; new: label = value+8, pw = past its NUL
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
    mov     rcx, qword ptr [rbp-24]           ; created/modified line
    call    gui_show_times
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
;   and arm a timer to auto-clear it after CLIP_MS (only if still ours).
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
    WINCALL CloseClipboard
    ; remember the clipboard state and arm the auto-clear timer
    WINCALL GetClipboardSequenceNumber
    mov     dword ptr [g_clip_seq], eax
    WINCALL KillTimer, qword ptr [rbp-40], CLIP_TIMER     ; cancel any prior
    WINCALL SetTimer, qword ptr [rbp-40], CLIP_TIMER, CLIP_MS, 0
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
    ; custom: copy g_rlabel -> lc, point the field's label at it
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

; gui_pwhist_capture() - archive any TILE value that was overwritten in this edit.
;   Per-label set difference: for each original field (label L, value V) captured
;   at load in g_pworig, if no NEW field with the same effective label L still holds
;   value V, append {now, L, V} to g_pwhist.  This attributes each overwrite to its
;   own tile (label); renaming/removing a tile also archives its old value.
gui_pwhist_capture proc frame
    FRAME_PROLOG 80
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
    mov     ecx, dword ptr [r11]             ; kind (low byte)
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
    mov     rdx, qword ptr [r11+16]
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
    call    pwh_append
gpc_orignext:
    inc     dword ptr [rbp-24]
    jmp     gpc_orig
gpc_done:
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
;   VF_PWHIST|VFL_RAW field: value = {u32 len, u64 ft, label wide\0, pw wide\0} built
;   into g_pwhblob so it survives until vault_build_entry consumes it.
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
    mov     r11, qword ptr [rbp-32]
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
    call    vault_reseal
    test    eax, eax
    jnz     gco_resealerr
    mov     rcx, qword ptr [rbp-24]
    call    gui_poplist
    call    vault_count
    test    eax, eax
    jz      gco_done
    dec     eax
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
    WINCALL gui_msgbox, qword ptr [rbp-24], addr s_resealfail, addr t_err, <MB_OK or MB_ICONERROR>
gco_done:
    mov     dword ptr [g_dirty], 0
    FRAME_EPILOG
    ret
gui_commit endp

; gui_set_editmode(rcx=hdlg, edx=on) - 1 = detail fields editable (edit mode),
;   0 = read-only (view).  Toggles EM_SETREADONLY on the six fields and swaps
;   the toolbar pencil glyph for a check mark while editing.
gui_set_editmode proc frame
    FRAME_PROLOG 128
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
    mov     eax, dword ptr [rbp-52]           ; SW_SHOW in edit, SW_HIDE in view
    xor     eax, SW_SHOW                      ; opposite: SW_SHOW in view
    mov     rcx, qword ptr [rbp-72]
    mov     edx, eax
    call    ShowWindow
    WINCALL InvalidateRect, qword ptr [rbp-72], 0, 1   ; repaint header for this entry
    ; overflow (...) button shares the header's view-mode visibility
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_OVFL
    call    GetDlgItem
    mov     qword ptr [rbp-72], rax
    mov     eax, dword ptr [rbp-52]
    xor     eax, SW_SHOW
    mov     rcx, qword ptr [rbp-72]
    mov     edx, eax
    call    ShowWindow
    mov     rcx, qword ptr [rbp-24]           ; favorite star shares the header visibility
    mov     edx, IDC_V_FAV
    call    GetDlgItem
    mov     qword ptr [rbp-72], rax
    mov     eax, dword ptr [rbp-52]
    xor     eax, SW_SHOW
    mov     rcx, qword ptr [rbp-72]
    mov     edx, eax
    call    ShowWindow
    mov     rcx, qword ptr [rbp-24]
    call    gui_rows_layout
    ; the pencil button stays a pencil in both modes (Save handles committing)
    FRAME_EPILOG
    ret
gui_set_editmode endp

; =============================================================================
; Settings overlay (burger menu) helpers for DLG_VAULT.
; =============================================================================

; gui_show_ids(rcx=hdlg, rdx=*id array, r8d=count, r9d=SW_* cmd) - ShowWindow
;   each listed control.
gui_show_ids proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     dword ptr [rbp-40], r8d
    mov     dword ptr [rbp-44], r9d
    mov     dword ptr [rbp-48], 0           ; index
gsi_loop:
    mov     eax, dword ptr [rbp-48]
    cmp     eax, dword ptr [rbp-40]
    jae     gsi_done
    mov     r11, qword ptr [rbp-32]
    mov     eax, dword ptr [r11+rax*4]      ; ids[i]
    mov     dword ptr [rbp-52], eax
    WINCALL GetDlgItem, qword ptr [rbp-24], dword ptr [rbp-52]
    WINCALL ShowWindow, rax, dword ptr [rbp-44]
    inc     dword ptr [rbp-48]
    jmp     gsi_loop
gsi_done:
    FRAME_EPILOG
    ret
gui_show_ids endp

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
            ES_AUTOHSCROLL_ or WS_TABSTOP_
    jmp     gra_reorder
gra_file:
    ; attachments tile: owner-draw tag list (DS_VALUE, click = open/remove) + a
    ; Choose button pinned top-right.  Up/Down reposition the tile; NO trashcan -
    ; the tile is removed automatically when its last file is deleted.
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_button, 0, \
            BS_OWNERDRAW_ or WS_TABSTOP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_IMPORT, addr cls_button, addr wb_addf, \
            BS_OWNERDRAW_ or WS_TABSTOP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_UP, addr cls_button, addr wb_up, \
            BS_OWNERDRAW_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_DOWN, addr cls_button, addr wb_down, \
            BS_OWNERDRAW_
    jmp     gra_finish
gra_secret:
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_edit, 0, \
            ES_PASSWORD_ or ES_AUTOHSCROLL_ or WS_TABSTOP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_REVEAL, addr cls_button, addr wb_eye, \
            BS_OWNERDRAW_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_COPY, addr cls_button, addr wb_copy, \
            BS_OWNERDRAW_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_SBADGE, addr cls_static, 0, \
            SS_OWNERDRAW_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_GEN, addr cls_button, addr wb_gen, \
            BS_OWNERDRAW_
    jmp     gra_reorder
gra_notes:
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_edit, 0, \
            ES_MULTILINE_ or ES_AUTOVSCROLL_ or ES_WANTRETURN_ or WS_TABSTOP_
    jmp     gra_reorder
gra_totp:
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_edit, 0, \
            ES_PASSWORD_ or ES_AUTOHSCROLL_ or WS_TABSTOP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_REVEAL, addr cls_button, addr wb_eye, \
            BS_OWNERDRAW_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_TCODE, addr cls_static, 0, \
            SS_LEFTNOWORDWRAP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_TBAR, addr cls_static, 0, \
            SS_OWNERDRAW_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_COPY, addr cls_button, addr wb_copy, \
            BS_OWNERDRAW_
gra_reorder:
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_UP, addr cls_button, addr wb_up, \
            BS_OWNERDRAW_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_DOWN, addr cls_button, addr wb_down, \
            BS_OWNERDRAW_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_DEL, addr cls_button, addr wb_rem, \
            BS_OWNERDRAW_
gra_finish:
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
; pwh_reset() - clear history + originals for a freshly opened entry.  Leaf.
pwh_reset proc
    mov     dword ptr [g_pwhist_n], 0
    mov     dword ptr [g_pworig_n], 0
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

; pwh_append(rcx = FILETIME qword, rdx = wide label, r8 = wide old-password) - add a
;   history entry; when full, drop the oldest so the most recent are kept.
pwh_append proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-56], r8
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
    lea     rcx, [rax+PWHIST_PW]             ; old password (capped, NUL-term)
    mov     rdx, qword ptr [rbp-56]
    call    gui_wcpy_capped
    inc     dword ptr [g_pwhist_n]
    FRAME_EPILOG
    ret
pwh_append endp

; pwh_remove(ecx = index) - purge one history entry (shift the tail down).
pwh_remove proc frame
    FRAME_PROLOG 48
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
    FRAME_PROLOG 48
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
;   it in the system default app (plaintext lingers in %TEMP% until the OS cleans it).
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
    WINCALL ShellExecuteW, 0, addr verb_open, addr g_tmpfile, 0, 0, 1
gto_done:
    FRAME_EPILOG
    ret
gui_tag_open endp

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

; rowh(rcx=desc) -> rax = slot handle helper is inlined; small accessors below.
; gui_rows_layout(rcx=hdlg) - position every row's controls in the detail pane
;   and show/hide the per-row reorder buttons according to g_editmode.
gui_rows_layout proc frame
    FRAME_PROLOG 128
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
    jne     grl_chkimg
    mov     dword ptr [rbp-44], 54
    mov     dword ptr [rbp-48], 40
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
@@: cmp     dword ptr [r10+FD_KIND], VF_SECRET
    jne     grl_valpos
    mov     dword ptr [rbp-76], 196             ; card secret (controls are on the top row)
    cmp     dword ptr [rbp-68], 0
    jne     grl_valpos
    mov     dword ptr [rbp-76], 130             ; flat secret
grl_valpos:
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_VALUE*8]
    cmp     dword ptr [rbp-68], 0
    je      grl_val_flat
    mov     r8d, 176                             ; content column (shifted for chevrons)
    mov     r9d, dword ptr [rbp-60]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, dword ptr [rbp-76], dword ptr [rbp-48]
    jmp     grl_val_done
grl_val_flat:
    mov     r8d, 206
    mov     r9d, dword ptr [rbp-60]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, dword ptr [rbp-76], dword ptr [rbp-48]
grl_val_done:
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
    ; advance y by the card height + the layout's inter-card gap
    mov     eax, dword ptr [rbp-40]
    add     eax, dword ptr [rbp-44]
    mov     r10d, dword ptr [g_layout]
    lea     r11, [layout_gaps]
    add     eax, dword ptr [r11+r10*4]
    mov     dword ptr [rbp-40], eax
    inc     dword ptr [rbp-36]
    jmp     grl_row
grl_done:
    ; place the created/modified line just below the last record, flowing with
    ; the field rows (x=176 matches the row content column)
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_TIMES
    call    GetDlgItem
    mov     qword ptr [rbp-32], rax
    WINCALL move_ctl, qword ptr [rbp-24], qword ptr [rbp-32], 176, dword ptr [rbp-40], 244, 10
    mov     eax, dword ptr [rbp-40]              ; content bottom incl. the timestamps line
    add     eax, 12
    mov     dword ptr [g_content_h], eax
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
    lea     rax, [g_urlbuf]
    mov     qword ptr [rbp-48], rax
guo_exec:
    WINCALL ShellExecuteW, 0, addr verb_open, qword ptr [rbp-48], 0, 0, 1
guo_done:
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
gui_wstr_eq proc
    xor     r8d, r8d
wse_l:
    movzx   eax, word ptr [rcx+r8*2]
    movzx   r9d, word ptr [rdx+r8*2]
    cmp     eax, r9d
    jne     wse_ne
    test    eax, eax
    jz      wse_eq
    inc     r8d
    cmp     r8d, 4096
    jb      wse_l
wse_ne:
    xor     eax, eax
    ret
wse_eq:
    mov     eax, 1
    ret
gui_wstr_eq endp

; gui_rows_show(rcx=hdlg, edx=cmd) - ShowWindow every runtime row control.
gui_rows_show proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [rbp-24], 0
grs_row:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [g_field_count]
    jae     grs_done
    mov     dword ptr [rbp-40], 0
grs_slot:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, DYN_SLOTS
    jae     grs_nextrow
    mov     ecx, dword ptr [rbp-24]
    mov     edx, dword ptr [rbp-40]
    call    gui_row_handle
    test    rax, rax
    jz      grs_slotnext
    mov     rcx, rax
    mov     edx, dword ptr [rbp-32]
    call    ShowWindow
grs_slotnext:
    inc     dword ptr [rbp-40]
    jmp     grs_slot
grs_nextrow:
    inc     dword ptr [rbp-24]
    jmp     grs_row
grs_done:
    FRAME_EPILOG
    ret
gui_rows_show endp

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
    FRAME_PROLOG 96
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
    ; refuse if the new row wouldn't fit the field area
    mov     eax, dword ptr [rbp-32]              ; kind -> row height (incl gap)
    mov     r9d, 18
    cmp     eax, VF_NOTES
    jne     gao_h1
    mov     r9d, 46
gao_h1:
    cmp     eax, VF_TOTP
    jne     gao_h2
    mov     r9d, 34
gao_h2:
    mov     eax, dword ptr [g_content_h]
    add     eax, r9d
    cmp     eax, FIELD_AREA_BOTTOM
    jle     gao_addit
    WINCALL gui_msgbox, qword ptr [rbp-24], addr s_nofieldroom, addr t_err, \
            <MB_OK or MB_ICONINFORMATION>
    jmp     gao_done
gao_addit:
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    call    gui_row_add
    cmp     eax, 0
    jl      gao_done
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
    call    gui_set_editmode
    mov     dword ptr [g_dirty], 1
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
    mov     edx, VF_TEXT                        ; 7 = custom (empty label)
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
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_MTHEME, qword ptr [rbp-32]
    mov     eax, dword ptr [g_col_dark]          ; match the title bar to the scheme
    mov     dword ptr [rbp-40], eax
    WINCALL DwmSetWindowAttribute, qword ptr [rbp-24], 20, addr rbp-40, 4
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
@@: cmp     dword ptr [g_menu_open], 0           ; settings open: rows are hidden, don't
    jne     gal_paint                            ;   re-show them (re-lays out on close)
    cmp     dword ptr [g_cur_idx], 0
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
    WINCALL cfg_get_dword, addr pref_scheme, 0, 0
    cmp     eax, GUI_SCHEME_COUNT
    jae     glp_layout
    mov     dword ptr [g_scheme], eax
glp_layout:
    mov     dword ptr [g_layout], 0             ; Comfortable is the only layout
glp_done:
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

; gui_show_times(rcx=hdlg) - fill IDC_V_TIMES with the current entry's
;   "Created <dt>  Modified <dt>" (blank when no entry).
gui_show_times proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_cur_idx], 0
    jl      gts_clear
    mov     ecx, dword ptr [g_cur_idx]
    call    vault_entry_ptr
    test    rax, rax
    jz      gts_clear
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
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_TIMES, addr g_times_w
    FRAME_EPILOG
    ret
gts_clear:
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_TIMES, 0
    FRAME_EPILOG
    ret
gui_show_times endp

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

; gui_update_fav_glyph(rcx=hdlg) - set the star button glyph from g_fav_state.
gui_update_fav_glyph proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    lea     rax, [wb_star]                       ; outline (not favorite)
    cmp     dword ptr [g_fav_state], 0
    je      guf_set
    lea     rax, [wb_starf]                      ; filled (favorite)
guf_set:
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_FAV, rax
    FRAME_EPILOG
    ret
gui_update_fav_glyph endp

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
gui_menu_open proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_vault_ids]
    mov     r8d, VAULT_ID_COUNT
    mov     r9d, SW_HIDE
    call    gui_show_ids
    mov     rcx, qword ptr [rbp-24]           ; drop the revealed-secret overlay FIRST: it
    call    gui_colorpw_hide                  ;   re-shows the plaintext value edit, which the
    mov     rcx, qword ptr [rbp-24]           ;   row-hide below then hides (else it would show
    mov     edx, SW_HIDE                      ;   through the settings overlay)
    call    gui_rows_show
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_menu_ids]
    mov     r8d, MENU_ID_COUNT
    mov     r9d, SW_SHOW
    call    gui_show_ids
    ; prefill the policy fields
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_MLEN
    mov     r8d, dword ptr [g_cfg_pwminlen]
    xor     r9d, r9d
    call    SetDlgItemInt
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_MCLS
    mov     r8d, dword ptr [g_cfg_pwminclasses]
    xor     r9d, r9d
    call    SetDlgItemInt
    ; disable policy fields locked by HKLM
    cmp     dword ptr [g_pol_len_lock], 0
    je      mo_len_ok
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_MLEN
    call    GetDlgItem
    mov     rcx, rax
    xor     edx, edx
    call    EnableWindow
mo_len_ok:
    cmp     dword ptr [g_pol_cls_lock], 0
    je      mo_cls_ok
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_MCLS
    call    GetDlgItem
    mov     rcx, rax
    xor     edx, edx
    call    EnableWindow
mo_cls_ok:
    ; TPM toggle: only meaningful with hardware -> check it iff enrolled, and
    ; enable the checkbox only when the platform TPM is present.
    mov     dword ptr [rbp-32], 0
    cmp     dword ptr [g_tpm_present], 0
    je      mo_tpm_set
    call    vault_tpm_has
    mov     dword ptr [rbp-32], eax
mo_tpm_set:
    mov     eax, dword ptr [rbp-32]           ; prime the Fluent toggle state
    mov     dword ptr [g_tpm_want], eax
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_MTPM
    call    GetDlgItem
    mov     rcx, rax
    mov     edx, dword ptr [g_tpm_present]    ; enable iff hardware present
    call    EnableWindow
    ; the two privacy toggles: disable them when HKLM policy locks the value
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_MNOHIST
    call    GetDlgItem
    mov     rcx, rax
    mov     eax, dword ptr [g_nohist_lock]
    xor     eax, 1                            ; enable = NOT locked
    mov     edx, eax
    call    EnableWindow
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_MNOPHON
    call    GetDlgItem
    mov     rcx, rax
    mov     eax, dword ptr [g_nophon_lock]
    xor     eax, 1
    mov     edx, eax
    call    EnableWindow
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_MENU, addr wb_close
    mov     dword ptr [g_menu_open], 1
    mov     ecx, 1                            ; opaque backdrop in theme_paint
    call    theme_overlay
    WINCALL RedrawWindow, qword ptr [rbp-24], 0, 0, 0185h  ; INVALIDATE|ERASE|ALLCHILDREN|UPDATENOW
    FRAME_EPILOG
    ret
gui_menu_open endp

; gui_menu_close(rcx=hdlg) - apply the settings, then hide the overlay.
gui_menu_close proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    call    gui_menu_save                    ; save all settings on leaving the screen
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_vault_ids]
    mov     r8d, VAULT_ID_COUNT
    mov     r9d, SW_SHOW
    call    gui_show_ids
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_menu_ids]
    mov     r8d, MENU_ID_COUNT
    mov     r9d, SW_HIDE
    call    gui_show_ids
    mov     rcx, qword ptr [rbp-24]           ; restore field rows + edit-mode state
    mov     edx, SW_SHOW
    call    gui_rows_show
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [g_editmode]
    call    gui_set_editmode
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_MENU, addr wb_menu
    mov     dword ptr [g_menu_open], 0
    xor     ecx, ecx
    call    theme_overlay
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
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_pol_len_lock], 0
    jne     msv_cls
    WINCALL GetDlgItemInt, qword ptr [rbp-24], IDC_V_MLEN, 0, 0
    test    eax, eax
    jz      msv_cls
    cmp     eax, 256
    jbe     @F
    mov     eax, 256
@@: mov     dword ptr [g_cfg_pwminlen], eax
    lea     rcx, [wv_pwlen]
    mov     edx, dword ptr [g_cfg_pwminlen]
    call    cfg_set_dword_hkcu
msv_cls:
    cmp     dword ptr [g_pol_cls_lock], 0
    jne     msv_tpm
    WINCALL GetDlgItemInt, qword ptr [rbp-24], IDC_V_MCLS, 0, 0
    test    eax, eax
    jz      msv_tpm
    cmp     eax, 4
    jbe     @F
    mov     eax, 4
@@: mov     dword ptr [g_cfg_pwminclasses], eax
    lea     rcx, [wv_pwcls]
    mov     edx, dword ptr [g_cfg_pwminclasses]
    call    cfg_set_dword_hkcu
msv_tpm:
    cmp     dword ptr [g_tpm_present], 0
    je      msv_apply_close                 ; no TPM -> nothing to enrol/forget
    mov     eax, dword ptr [g_tpm_want]     ; Fluent toggle state
    mov     dword ptr [rbp-32], eax         ; want enrolled?
    call    vault_tpm_has
    mov     dword ptr [rbp-36], eax         ; currently enrolled?
    cmp     dword ptr [rbp-32], 0
    je      msv_unwant
    cmp     dword ptr [rbp-36], 0
    jne     msv_apply_close                 ; want + have -> nothing
    call    vault_tpm_remember
    jmp     msv_apply_close
msv_unwant:
    cmp     dword ptr [rbp-36], 0
    je      msv_apply_close                 ; !want + !have -> nothing
    call    vault_tpm_forget
msv_apply_close:
    cmp     dword ptr [g_nohist_lock], 0    ; persist the privacy toggles (HKCU) unless
    jne     msv_phon                        ;   HKLM policy locks them
    lea     rcx, [wv_nohist]
    mov     edx, dword ptr [g_no_history]
    call    cfg_set_dword_hkcu
msv_phon:
    cmp     dword ptr [g_nophon_lock], 0
    jne     msv_done
    lea     rcx, [wv_nophon]
    mov     edx, dword ptr [g_no_phonetic]
    call    cfg_set_dword_hkcu
msv_done:
    FRAME_EPILOG
    ret
gui_menu_save endp

; =============================================================================
; vault_proc - DLG_VAULT dialog procedure (raw frame).
; =============================================================================
vault_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      vp_init
    cmp     rdx, WM_COMMAND
    je      vp_cmd
    cmp     rdx, WM_CLOSE
    je      vp_close
    cmp     rdx, WM_TIMER
    je      vp_timer
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
    xor     eax, eax
    jmp     vp_ret
vp_tcolor:
    call    gui_ctlcolor                     ; theme + link-blue for view-mode URL values
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
    mov     r10, r9                          ; COMPAREITEMSTRUCT: idx at +24/+40
    mov     ecx, dword ptr [r10+24]
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
    cmp     eax, IDC_V_LIST                   ; the entry list = icon cards
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
vp_timer:
    cmp     r8d, THEME_TIMER
    jne     vp_timer_clip
    mov     rcx, qword ptr [rbp-8]
    call    theme_tick
    jmp     vp_handled
vp_timer_clip:
    cmp     r8d, CLIP_TIMER
    je      vp_t_clip
    cmp     r8d, TOTP_TIMER
    je      vp_t_totp
    cmp     r8d, SEARCH_TIMER
    je      vp_t_search
    jmp     vp_unhandled
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
    mov     rcx, qword ptr [rbp-8]           ; keep the settings overlay hidden
    lea     rdx, [g_menu_ids]
    mov     r8d, MENU_ID_COUNT
    mov     r9d, SW_HIDE
    call    gui_show_ids
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_MENU, addr wb_menu
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_ADD, addr wb_add
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_EDIT, addr wb_edit
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_REMOVE, addr wb_rem
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_OVFL, addr wb_more
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_FAV, addr wb_star
    call    gui_load_prefs                    ; apply persisted color scheme + layout
    mov     rcx, qword ptr [rbp-8]
    call    gui_apply_scheme
    mov     rcx, qword ptr [rbp-8]
    call    gui_apply_layout
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_V_SEARCH, EM_SETCUEBANNER, 1, addr cue_search
    mov     dword ptr [g_cur_idx], -1         ; no entry selected yet
    mov     dword ptr [g_colorpw_row], -1
    mov     dword ptr [g_dirty], 0
    mov     dword ptr [g_loading], 0
    mov     rcx, qword ptr [rbp-8]
    call    gui_poplist
    mov     rcx, qword ptr [rbp-8]            ; start in view mode (fields locked)
    xor     edx, edx
    call    gui_set_editmode
    sub     rsp, 32                          ; foreground the window so keystrokes land
    mov     rcx, qword ptr [rbp-8]            ;   here (launched from the tray, it is
    call    SetForegroundWindow              ;   otherwise visible but not active)
    add     rsp, 32
    mov     rcx, qword ptr [rbp-8]            ; the search box takes focus on show
    mov     edx, IDC_V_SEARCH
    call    GetDlgItem
    sub     rsp, 32
    mov     rcx, rax
    call    SetFocus
    add     rsp, 32
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
    cmp     eax, IDC_V_LIST
    je      vp_list
    cmp     eax, IDC_V_ADDFIELD
    je      vp_addfield
    cmp     eax, IDC_V_ADD
    je      vp_add
    cmp     eax, IDC_V_EDIT
    je      vp_edit
    cmp     eax, IDC_V_SAVE
    je      vp_save
    cmp     eax, IDC_V_CANCEL
    je      ve_save                           ; discard edits, back to view mode
    cmp     eax, IDC_V_REMOVE
    je      vp_remove
    cmp     eax, IDC_V_LOCK
    je      vp_lock
    cmp     eax, IDC_V_MENU
    je      vp_menu
    cmp     eax, IDC_V_MTHEME
    je      vp_theme
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
    mov     eax, dword ptr [g_tpm_want]
    xor     eax, 1
    mov     dword ptr [g_tpm_want], eax
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_V_MTPM
    call    GetDlgItem
    sub     rsp, 32
    mov     rcx, rax
    xor     edx, edx
    mov     r8d, 1
    call    InvalidateRect
    add     rsp, 32
    jmp     vp_handled
vp_mnohist:
    cmp     dword ptr [g_nohist_lock], 0      ; HKLM-locked -> ignore the click
    jne     vp_handled
    mov     eax, dword ptr [g_no_history]
    xor     eax, 1
    mov     dword ptr [g_no_history], eax
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_V_MNOHIST
    call    GetDlgItem
    sub     rsp, 32
    mov     rcx, rax
    xor     edx, edx
    mov     r8d, 1
    call    InvalidateRect
    add     rsp, 32
    jmp     vp_handled
vp_mnophon:
    cmp     dword ptr [g_nophon_lock], 0
    jne     vp_handled
    mov     eax, dword ptr [g_no_phonetic]
    xor     eax, 1
    mov     dword ptr [g_no_phonetic], eax
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_V_MNOPHON
    call    GetDlgItem
    sub     rsp, 32
    mov     rcx, rax
    xor     edx, edx
    mov     r8d, 1
    call    InvalidateRect
    add     rsp, 32
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
vp_export:
    mov     rcx, qword ptr [rbp-8]
    call    gui_export
    jmp     vp_handled
vp_import:
    mov     rcx, qword ptr [rbp-8]
    call    gui_import
    jmp     vp_handled
vp_ovfl:
    cmp     dword ptr [g_cur_idx], 0             ; only with an entry shown
    jl      vp_handled
    mov     rcx, qword ptr [rbp-8]
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
    cmp     dword ptr [g_cur_idx], 0             ; only with an entry shown
    jl      vp_handled
    mov     eax, dword ptr [g_fav_state]         ; toggle favorite
    xor     eax, 1
    mov     dword ptr [g_fav_state], eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_update_fav_glyph
    mov     rcx, qword ptr [rbp-8]               ; persist immediately
    call    gui_commit
    mov     rcx, qword ptr [rbp-8]               ; refresh Modified (commit bumped it)
    call    gui_show_times
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
vp_add:
    ; adding a new entry discards any unsaved inline edits to the current one
    ; (edits are only persisted by an explicit Save)
    mov     dword ptr [g_dirty], 0
va_build:
    ; new record = Title "New entry" + empty Username + Password + Notes (last)
    lea     r10, [g_field_list]
    mov     qword ptr [r10+0], VF_TITLE
    mov     qword ptr [r10+8], 0
    lea     rax, [wt_newentry]
    mov     qword ptr [r10+16], rax
    mov     qword ptr [r10+24], VF_USERNAME
    mov     qword ptr [r10+32], 0
    lea     rax, [g_empty_w]
    mov     qword ptr [r10+40], rax
    mov     qword ptr [r10+48], VF_SECRET
    mov     qword ptr [r10+56], 0
    lea     rax, [g_empty_w]
    mov     qword ptr [r10+64], rax
    mov     qword ptr [r10+72], VF_NOTES
    mov     qword ptr [r10+80], 0
    lea     rax, [g_empty_w]
    mov     qword ptr [r10+88], rax
    mov     dword ptr [g_field_n], 4
    call    vault_build_entry
    test    eax, eax
    jnz     vp_handled
    call    vault_reseal
    mov     rcx, qword ptr [rbp-8]
    call    gui_poplist
    call    vault_count
    test    eax, eax
    jz      vp_handled
    dec     eax
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
    cmp     dword ptr [g_cur_idx], 0
    jl      vp_handled
    WINCALL gui_msgbox, qword ptr [rbp-8], addr t_remove, addr t_err, <MB_YESNO or MB_ICONQUESTION>
    cmp     eax, IDYES
    jne     vp_handled
    mov     ecx, dword ptr [g_cur_idx]
    call    vault_remove_at
    call    vault_reseal
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
    mov     rcx, qword ptr [rbp-8]            ; back to view mode
    xor     edx, edx
    call    gui_set_editmode
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
    add     rsp, 32
    mov     dword ptr [g_totp_on], 0
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
    FRAME_EPILOG
    ret
gui_load_policy endp

; gui_pw_match() -> eax = 1 if g_pwbuf == g_pw2buf (wide, NUL-terminated).
gui_pw_match proc
    lea     r10, [g_pwbuf]
    lea     r11, [g_pw2buf]
    xor     ecx, ecx
pm_loop:
    movzx   eax, word ptr [r10+rcx*2]
    movzx   edx, word ptr [r11+rcx*2]
    cmp     eax, edx
    jne     pm_no
    test    eax, eax
    jz      pm_yes
    inc     ecx
    jmp     pm_loop
pm_no:
    xor     eax, eax
    ret
pm_yes:
    mov     eax, 1
    ret
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
gui_ensure_vault_dir proc frame
    FRAME_PROLOG 64
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
    jl      ged_done                          ; no directory component
    movsxd  r11, r9d
    mov     qword ptr [rbp-32], r11           ; remember the backslash position
    mov     r10, qword ptr [rbp-24]
    mov     word ptr [r10+r11*2], 0           ; terminate at the parent directory
    WINCALL CreateDirectoryW, qword ptr [rbp-24], 0
    mov     r10, qword ptr [rbp-24]
    mov     r11, qword ptr [rbp-32]
    mov     word ptr [r10+r11*2], 5Ch         ; restore the separator
ged_done:
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
    lea     rax, [g_vpath]
    mov     qword ptr [g_cfg_in], rax
    ; never silently overwrite an existing vault file - confirm first
    lea     rcx, [g_vpath]
    call    gui_file_exists
    test    eax, eax
    jz      cd_doinit
    WINCALL gui_msgbox, qword ptr [rbp-24], addr m_overwrite, addr t_overwrite, \
            <MB_YESNO or MB_ICONWARNING or MB_DEFBUTTON2>
    cmp     eax, IDYES
    je      cd_doinit
    lea     rax, [s_kept]                    ; declined -> keep existing vault
    mov     qword ptr [rbp-56], rax
    jmp     cd_status
cd_doinit:
    lea     rcx, [g_vpath]                   ; make sure the target folder exists
    call    gui_ensure_vault_dir
    call    do_init
    test    eax, eax
    jz      cd_created
    lea     rax, [s_createfail]
    mov     qword ptr [rbp-56], rax
    jmp     cd_status
cd_created:
    ; persist the default vault path, and any editable policy values, to HKCU
    cmp     dword ptr [g_is_default], 0
    je      cd_savepol
    lea     rcx, [g_vpath]
    call    reg_save_vault
    mov     dword ptr [g_is_default], 0
cd_savepol:
    cmp     dword ptr [g_pol_len_lock], 0
    jne     cd_savecls
    lea     rcx, [wv_pwlen]
    mov     edx, dword ptr [g_cfg_pwminlen]
    call    cfg_set_dword_hkcu
cd_savecls:
    cmp     dword ptr [g_pol_cls_lock], 0
    jne     cd_open
    lea     rcx, [wv_pwcls]
    mov     edx, dword ptr [g_cfg_pwminclasses]
    call    cfg_set_dword_hkcu
cd_open:
    ; unlock the freshly created vault for the vault window
    mov     dword ptr [g_use_tpm], 0
    call    vault_unlock
    test    eax, eax
    jnz     cd_unlockfail
    ; TPM unlock is on by default for a new vault when the hardware supports it
    cmp     dword ptr [g_tpm_present], 0
    je      cd_done
    call    vault_tpm_remember
    jmp     cd_done
cd_unlockfail:
    lea     rax, [s_createfail]
    mov     qword ptr [rbp-56], rax
    jmp     cd_status
cd_done:
    mov     dword ptr [g_create], 0
    call    gui_wipepw
    call    gui_wipepw_create
    mov     eax, 1
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

; gui_pw_strength(rcx = hdlg) - recompute the strength level (g_pw_level) and
;   confirm-match (g_pw_match) from the two password boxes, enable Create only
;   when valid, and repaint the two colour lines.
gui_pw_strength proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx          ; hdlg
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_C_PW, addr g_pwbuf, 1024
    mov     dword ptr [rbp-32], eax          ; password length (chars)
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_C_PW2, addr g_pw2buf, 1024
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
    ; repaint the two colour lines
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_C_PWBAR
    call    GetDlgItem
    WINCALL InvalidateRect, rax, 0, 1
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_C_PW2BAR
    call    GetDlgItem
    WINCALL InvalidateRect, rax, 0, 1
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

; gui_drawbar(rcx = lpdrawitem, edx = 0 strength / 1 match) - fill the colour
;   line: strength uses red/amber/light-green/deep-green by g_pw_level; match
;   uses red (mismatch) / deep-green (match).
gui_drawbar proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx          ; lpdis
    cmp     edx, 0
    jne     db_match
    ; strength: pick by g_pw_level
    mov     eax, dword ptr [g_pw_level]
    lea     r10, [g_br_red]
    mov     rax, qword ptr [r10+rax*8]        ; brushes are contiguous red/amber/lg/dg
    jmp     db_fill
db_match:
    mov     rax, qword ptr [g_br_red]
    cmp     dword ptr [g_pw_match], 0
    je      db_fill_have
    mov     rax, qword ptr [g_br_dgreen]
db_fill_have:
db_fill:
    mov     qword ptr [rbp-32], rax           ; brush
    mov     rcx, qword ptr [rbp-24]
    mov     rax, qword ptr [rcx+32]           ; hDC
    mov     qword ptr [rbp-40], rax
    ; FillRect(hDC, &rcItem, brush)
    mov     rcx, qword ptr [rbp-40]
    mov     rax, qword ptr [rbp-24]
    lea     rdx, [rax+40]                     ; &rcItem
    mov     r8, qword ptr [rbp-32]
    call    FillRect
    mov     eax, 1
    FRAME_EPILOG
    ret
gui_drawbar endp

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
    cmp     rdx, WM_TIMER
    je      cp_ttimer
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
    ; the two colour lines are owner-draw statics; everything else is themed
    mov     eax, dword ptr [r9+4]            ; DRAWITEMSTRUCT.CtlID
    cmp     eax, IDC_C_PWBAR
    je      cp_drawbar_pw
    cmp     eax, IDC_C_PW2BAR
    je      cp_drawbar_pw2
    mov     rcx, r9
    call    theme_drawitem
    jmp     cp_ret
cp_drawbar_pw:
    mov     rcx, r9
    xor     edx, edx                         ; strength
    call    gui_drawbar
    jmp     cp_ret
cp_drawbar_pw2:
    mov     rcx, r9
    mov     edx, 1                           ; match
    call    gui_drawbar
    jmp     cp_ret
cp_ttimer:
    cmp     r8d, THEME_TIMER
    jne     cp_tunh
    mov     rcx, qword ptr [rbp-8]
    call    theme_tick
    mov     eax, 1
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
    call    gui_pwbars_init                  ; build the colour-line brushes
    ; placeholder cue text inside the two password boxes
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_C_PW, EM_SETCUEBANNER, 1, addr cue_pw
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_C_PW2, EM_SETCUEBANNER, 1, addr cue_pw2
    mov     rcx, qword ptr [rbp-8]           ; prime the colour lines + Create state
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
    mov     r9d, EBUF*2-1
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
    cmp     rdx, WM_TIMER
    je      sel_timer
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
sel_timer:
    cmp     r8d, THEME_TIMER
    jne     sel_unh
    mov     rcx, qword ptr [rbp-8]
    call    theme_tick
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
    FRAME_PROLOG 32
    lea     r10, [g_sel]
    xor     r11d, r11d
gsa_lp:
    cmp     r11d, MAX_SEL
    jae     gsa_done
    xor     eax, eax
    cmp     r11d, ecx
    jae     @F
    mov     eax, 1
@@: mov     byte ptr [r10+r11], al
    inc     r11d
    jmp     gsa_lp
gsa_done:
    FRAME_EPILOG
    ret
gui_sel_all endp

; gui_export(rcx = hdlg) - prompt for a password, ze_compose builds the AES-256
;   encrypted ZIP (vordr.json of all tiles + every attachment, history excluded),
;   then pick a save path and write it.
; =============================================================================
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
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_XLPW, qword ptr [rbp-24], addr xlpw_proc, 0
    cmp     eax, 1
    jne     gx_done
    lea     rcx, [g_xlpw]                        ; wide password + length (bytes)
    mov     edx, dword ptr [g_xlpwlen]
    call    ze_compose                           ; -> encrypted zip in g_zbuf (all tiles, no history)
    test    eax, eax
    jnz     gx_composefail
    lea     rax, [g_zipfilter]                   ; pick a .zip save path
    mov     qword ptr [g_pickfilter], rax
    lea     rcx, [g_imgpath]
    lea     rdx, [zip_defname]
    call    gui_wcpy_capped
    mov     rcx, qword ptr [rbp-24]
    mov     edx, 1
    call    img_pick
    test    eax, eax
    jz      gx_zip_cancel
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
    WINCALL MessageBoxW, qword ptr [rbp-24], addr exp_done_ok, addr zip_title, 040h
    jmp     gx_done
gx_zip_cancel:
    call    ze_free
    call    ges_wipepw
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
    cmp     dword ptr [g_pwhist_n], 0
    je      gdh_done
    WINCALL SelectObject, qword ptr [rbp-32], qword ptr [g_subfont]
    mov     qword ptr [rbp-80], rax            ; old font
    WINCALL SetBkMode, qword ptr [rbp-32], 1
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
    mov     eax, dword ptr [rbp-192]          ; text rect [tabX+4, T, tabX+tabW-4, T+PH_TABH]
    add     eax, 4
    mov     dword ptr [rbp-176], eax
    mov     eax, dword ptr [rbp-48]
    mov     dword ptr [rbp-172], eax
    mov     eax, dword ptr [rbp-192]
    add     eax, dword ptr [rbp-188]
    sub     eax, 4
    mov     dword ptr [rbp-168], eax
    mov     eax, dword ptr [rbp-48]
    add     eax, PH_TABH
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
    add     eax, PH_TABH-3
    mov     dword ptr [rbp-172], eax
    mov     eax, dword ptr [rbp-192]
    add     eax, dword ptr [rbp-188]
    sub     eax, 8
    mov     dword ptr [rbp-168], eax
    mov     eax, dword ptr [rbp-48]
    add     eax, PH_TABH-1
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
    add     eax, PH_TABH
    mov     dword ptr [rbp-104], eax          ; rowTop (below the tab strip)
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
    ; old password (normal, middle column, ellipsized)
    WINCALL SetTextColor, qword ptr [rbp-32], dword ptr [g_col_text]
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
    mov     rax, qword ptr [rbp-152]
    add     rax, PWHIST_PW
    WINCALL DrawTextW, qword ptr [rbp-32], rax, -1, addr rbp-176, 8024h
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
    ; --- click in the tab strip? (pt.y < PH_TABH) -> switch tab ---
    cmp     dword ptr [rbp-44], PH_TABH
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
    mov     eax, dword ptr [rbp-44]           ; disp = scroll + (pt.y-PH_TABH)/PH_ROW_H
    sub     eax, PH_TABH
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
    cmp     rdx, WM_TIMER
    je      ph_timer
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
ph_timer:
    cmp     r8d, THEME_TIMER
    jne     ph_unh
    mov     rcx, qword ptr [rbp-8]
    call    theme_tick
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

; =============================================================================
; gui_import(rcx = hdlg) -> eax = entries imported.  Pick any supported file and
;   auto-detect its format from the leading bytes: "PK" -> unencrypted .xlsx;
;   OLE2 magic (D0 CF 11 E0) -> encrypted .xlsx (prompt for the workbook
;   password); otherwise CSV (delimiter auto-detected).  Appends every row/entry,
;   reseals and refreshes.
; =============================================================================
public gui_import
gui_import proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx             ; hdlg
    mov     dword ptr [rbp-64], 0               ; imported count
    mov     qword ptr [rbp-32], 0               ; raw ptr (0 = not allocated)
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
    ; ---- require a Vordr encrypted zip (PK + WinZip-AES method 99) ----
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
    call    vault_reseal
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
    FRAME_PROLOG 48
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
    cmp     rdx, WM_TIMER
    je      pp_timer
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
pp_timer:
    cmp     r8d, THEME_TIMER
    jne     pp_unh
    mov     rcx, qword ptr [rbp-8]
    call    theme_tick
    mov     eax, 1
    jmp     pp_ret
pp_unh:
    xor     eax, eax
    jmp     pp_ret
pp_init:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDOK
    call    theme_attach
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
    call    gui_pg_apply
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
    cmp     rdx, WM_TIMER
    je      xpp_timer
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
xpp_timer:
    cmp     r8d, THEME_TIMER
    jne     xpp_unh
    mov     rcx, qword ptr [rbp-8]
    call    theme_tick
    mov     eax, 1
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
; imppw_proc - DLG_IMPPW dialog procedure: prompt for an existing workbook
;   password (single field, no confirm, no policy check) to open an encrypted
;   .xlsx for import.  Fills g_xlpw / g_xlpwlen.  Raw frame.
; =============================================================================
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
    cmp     rdx, WM_TIMER
    je      ipp_timer
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
ipp_timer:
    cmp     r8d, THEME_TIMER
    jne     ipp_unh
    mov     rcx, qword ptr [rbp-8]
    call    theme_tick
    mov     eax, 1
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
    FRAME_PROLOG 64
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
    cmp     rdx, WM_TIMER
    je      ic_timer
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
ic_timer:
    cmp     r8d, THEME_TIMER
    jne     ic_unh
    mov     rcx, qword ptr [rbp-8]
    call    theme_tick
    mov     eax, 1
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
    jnz     go_vault
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_UNLOCK, qword ptr [rbp-24], addr unlock_proc, 0
    cmp     rax, 1
    jne     go_reset
    jmp     go_vault
go_create:
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_CREATE, qword ptr [rbp-24], addr create_proc, 0
    cmp     rax, 1
    jne     go_reset
go_vault:
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
    cmp     rdx, WM_COMMAND
    je      twp_cmd
    cmp     rdx, WM_DESTROY
    je      twp_destroy
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
twp_destroy:
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
    call    theme_boot
    call    tpm_available
    mov     dword ptr [g_tpm_present], eax
    call    gui_load_policy
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
    WINCALL CreateWindowExW, WS_EX_TOOLWINDOW, addr tray_cls, addr tray_wt, WS_POPUP, \
            0, 0, 0, 0, 0, 0, qword ptr [g_hinst], 0
    mov     qword ptr [g_trayhwnd], rax
    mov     rcx, rax
    call    gui_tray_add
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
