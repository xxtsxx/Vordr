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
extern vault_field_count:proc
extern vault_field_get:proc
extern vault_build_entry:proc
extern attach_stage:proc
extern attach_open:proc
extern img_load:proc
extern img_free:proc
extern img_dims:proc
extern img_draw:proc
extern img_encode_hbitmap:proc
extern mem_alloc:proc
extern mem_free:proc
extern read_file:proc
extern write_file:proc
extern GetClipboardData:proc
extern IsClipboardFormatAvailable:proc
extern ShellExecuteW:proc
extern GetTempPathW:proc
extern shell_thumb:proc
extern img_from_hbitmap:proc
extern preview_open:proc
extern preview_show:proc
extern preview_setrect:proc
extern preview_close:proc
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
extern cfg_get_dword:proc
extern cfg_set_dword_hkcu:proc
extern check_password_policy:proc

externdef g_use_tpm:dword
externdef g_cfg_pwminlen:dword
externdef g_cfg_pwminclasses:dword
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
extern DrawTextW:proc
extern FrameRect:proc
extern MapDialogRect:proc
extern SendMessageW:proc
extern PostMessageW:proc
extern SetWindowTextW:proc
extern CheckDlgButton:proc
extern GetDlgCtrlID:proc
extern SetTextColor:proc
extern SetBkMode:proc
extern SetBkColor:proc
extern GetSysColorBrush:proc
extern GetStockObject:proc
extern CreateSolidBrush:proc
extern FillRect:proc
extern InvalidateRect:proc
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
WM_COMMAND          equ 111h
WM_PAINT            equ 0Fh
WM_ERASEBKGND       equ 14h
WM_DRAWITEM         equ 2Bh
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
COLOR_BTNFACE       equ 0Fh
BKMODE_TRANSPARENT  equ 1
CLR_STRENGTH_OK     equ 0055AF2Dh           ; green  - meets the policy
CLR_STRENGTH_BAD    equ 000000C8h           ; red    - does not meet the policy
CLIP_TIMER          equ 1                  ; timer id for clipboard auto-clear
CLIP_MS             equ 20000              ; clear a copied secret after 20 s
TOTP_TIMER          equ 2                  ; timer id for live auth-code refresh
TOTP_MS             equ 1000               ; recompute the code once a second
LBN_SELCHANGE       equ 1
LB_ADDSTRING        equ 180h
LB_RESETCONTENT     equ 184h
LB_SETCURSEL        equ 186h
LB_GETCURSEL        equ 188h
LB_GETCOUNT         equ 18Bh
LB_GETITEMDATA      equ 199h
LB_SETITEMDATA      equ 19Ah
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
DLG_IMGVIEW  equ 620                  ; enlarge/export image viewer
IDC_IV_PIC   equ 621
IDC_IV_EXPORT equ 622
CF_BITMAP    equ 2
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
FD_FLAGS    equ 4               ; dd  bit0 = field carries a custom label
FD_Y        equ 8              ; dd  row top in DLU (within the detail pane)
FD_H        equ 12             ; dd  row height in DLU
FD_HANDLES  equ 16             ; q[DYN_SLOTS]  control hwnd per slot (0 = absent)
FD_ARF      equ 144            ; {u32 len, AttachRef[68], filename wide}  image value blob
IMG_BLOBCAP equ 328            ; 4 + 68 + up to 256 bytes of wide filename
FD_IMG      equ 472            ; q  decoded image handle (img_load) for the thumbnail
DESCSZ      equ 480            ; 16 + 16 handles*8 + 328 arf blob + 8 img (16-aligned)
MAXROWS     equ 24
FDF_LABELED equ 1               ; FD_FLAGS bit0 = carries a custom label
FDF_REVEALED equ 2              ; FD_FLAGS bit1 = value currently unmasked
FDF_HASIMG  equ 4               ; FD_FLAGS bit2 = image row has data in FD_ARF/FD_IMG
; Runtime control ids: IDC_DYN_BASE + row*DYN_SLOTS + slot (DYN_SLOTS = power of 2).
IDC_DYN_BASE equ 3000
DYN_SLOTS   equ 16
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
DS_THUMB    equ 9               ; image/file thumbnail (owner-draw; click to enlarge)
DS_IMPORT   equ 10              ; image/file: import/choose from file (edit mode)
DS_PASTE    equ 11              ; image: paste from clipboard (edit mode)
DS_EXPORT   equ 12              ; file: save attachment to disk
DS_OPEN     equ 13              ; file: open attachment in the default app
IDC_V_ADDFIELD equ 230          ; "+ Add field" button (edit mode)
IDC_V_SAVE   equ 231          ; "Save" button (edit mode, accent/primary)
IDC_V_SEARCH equ 232          ; search/filter box under the entry list
FIELD_AREA_BOTTOM equ 292        ; rows may not grow past here (DLU; Add-field is at 296)
; Win32 window styles (gui.asm builds controls at runtime; the RC gets these
; from windows.h, but this module needs the numeric values).
WS_CHILD_       equ 40000000h
WS_VISIBLE_     equ 10000000h
WS_TABSTOP_     equ 00010000h
WS_VSCROLL_     equ 00200000h
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
WSTR t_new,         <Create new vault>
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
WSTR s_full,        <Vault is full.>
WSTR s_resealfail,  <Saved in memory but writing to disk failed.>
WSTR s_firstrun,    <No vault yet - set a master password to create your default vault.>
WSTR t_overwrite,   <Vordr - vault already exists>
WSTR m_overwrite,   <A vault file already exists at this location. Creating a new vault will PERMANENTLY destroy it and every entry it holds. Overwrite it?>
WSTR s_kept,        <Existing vault kept. Cancel, or use "Create new..." to choose a different file.>
WSTR s_pwmismatch,  <The passwords do not match.>
WSTR s_pwshort,     <Password is too short for the current policy.>
WSTR s_pwclasses,   <Password needs more character types (lowercase / uppercase / number / symbol).>
WSTR s_pollocked,   <Password policy is set by your administrator and cannot be changed here.>
WSTR s_str_short,   <Too short for the policy.>
WSTR s_str_few,     <Needs more character types for the policy.>
WSTR s_str_fair,    <Fair - meets the policy.>
WSTR s_str_good,    <Good - meets the policy.>
WSTR s_str_strong,  <Strong - meets the policy.>
WSTR wt_newentry,   <New entry>
WSTR cue_search,    <Search>
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
WSTR s_tpmnone,     <No Windows Hello / TPM unlock saved for this vault on this PC.>
WSTR s_tpmfail,     <Windows Hello / TPM unlock failed - use your master password.>
WSTR s_tpmsaved,    <This device can now unlock the vault with Windows Hello / TPM.>
WSTR s_tpmsavefail, <Could not register this device with the TPM.>
WSTR t_tpm,         <Windows Hello / TPM>
WSTR m_forgotten,   <Windows Hello / TPM quick-unlock was removed for this device.>
WSTR m_forget_q,    <Remove Windows Hello / TPM quick-unlock for this vault on this PC? The master password will still work.>
WSTR t_forget,      <Forget this device>
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
g_filter label word
    dw 'V','o','r','d','r',' ','v','a','u','l','t',0
    dw '*','.','v','o','r','d','r',0
    dw 'A','l','l',' ','f','i','l','e','s',0
    dw '*','.','*',0
    dw 0
g_defext label word
    dw 'v','o','r','d','r',0
; burger / close glyphs for the settings button (wide)
wb_menu label word
    dw 2630h, 0                                  ; trigram for heaven (hamburger)
wb_close label word
    dw 2715h, 0                                  ; multiplication X
wb_add label word
    dw 002Bh, 0                                  ; +  (add)
wb_edit label word
    dw 270Eh, 0                                  ; pencil (edit)
wb_save label word
    dw 2713h, 0                                  ; check mark (save / leave edit mode)
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
cap_import label word
    dw 'I','m','p','o','r','t', 0
cap_choose label word
    dw 'C','h','o','o','s','e', 0
cap_open label word
    dw 'O','p','e','n', 0
cap_save label word
    dw 'S','a','v','e', 0
cap_nofile label word
    dw '(','f','i','l','e',')', 0
verb_open label word
    dw 'o','p','e','n', 0
name_default_att label word
    dw 'v','o','r','d','r','_','a','t','t','a','c','h','.','b','i','n', 0
cap_paste label word
    dw 'P','a','s','t','e', 0
cap_export label word
    dw 'E','x','p','o','r','t', 0
cap_noimg label word
    dw '(','n','o',' ','i','m','a','g','e',')', 0
suffix_imgpng label word
    dw '_','i','m','a','g','e','.','p','n','g', 0
suffix_dotpng label word
    dw '.','p','n','g', 0
sep_underscore label word
    dw '_', 0
g_imgfilter label word          ; "Images\0*.png;*.jpg;*.jpeg;*.bmp;*.gif\0All\0*.*\0\0"
    dw 'I','m','a','g','e','s',0
    dw '*','.','p','n','g',';','*','.','j','p','g',';','*','.','j','p','e','g',';','*','.','b','m','p',';','*','.','g','i','f',0
    dw 'A','l','l',' ','f','i','l','e','s',0
    dw '*','.','*',0,0
g_allfilter label word          ; "All files\0*.*\0\0"
    dw 'A','l','l',' ','f','i','l','e','s',0
    dw '*','.','*',0,0
g_empty_w label word
    dw 0                                          ; empty wide string (default field value)
pm_custom label word
    dw 'C','u','s','t','o','m',' ','f','i','e','l','d', 0
; control-id groups toggled when the settings overlay opens/closes
align 4
g_vault_ids label dword
    dd IDC_V_LIST, IDC_V_ADD, IDC_V_EDIT, IDC_V_REMOVE, IDC_V_TITLE
    dd IDC_V_ADDFIELD, IDC_V_SAVE, IDC_V_LOCK
VAULT_ID_COUNT equ 8
g_menu_ids label dword
    dd IDC_V_MBACK, IDC_V_MTITLE, IDC_V_MPOLL, IDC_V_MLENL, IDC_V_MLEN
    dd IDC_V_MCLSL, IDC_V_MCLS, IDC_V_MTPM, IDC_V_MTPML, IDC_V_MTPMINFO
MENU_ID_COUNT equ 10

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
g_tkey_revealed dd ?                  ; 1 if the TOTP key field is unmasked
g_clip_seq  dd ?                      ; clipboard sequence number at last copy
g_cur_idx   dd ?                      ; entry currently shown/edited inline (-1=none)
g_dirty     dd ?                      ; 1 = inline fields edited since last load/save
g_loading   dd ?                      ; 1 = programmatically loading fields (ignore EN_CHANGE)
g_editmode  dd ?                      ; 1 = detail fields editable (view/edit toggle)
align 8
g_vaulthwnd dq ?                      ; the open DLG_VAULT window (0 when not shown)
align 2
g_search_w  dw 512 dup (?)            ; current search query (wide, upper-cased)
g_match_w   dw EBUF*2 dup (?)         ; scratch: a field value/label folded for matching
g_vpath     dw 1024 dup (?)        ; chosen vault path (wide, NUL-terminated)
g_pwbuf     dw 1024 dup (?)        ; password field (wide; wiped after use)
g_pw2buf    dw 1024 dup (?)        ; confirm-password field (wide; wiped)
g_conv_w    dw EBUF*2 dup (?)      ; utf8 -> wide display scratch
g_secret_w  dw EBUF*2 dup (?)      ; current selected secret (wide) for reveal/copy
g_e_title   dw 1024 dup (?)
g_e_user    dw 1024 dup (?)
g_e_secret  dw EBUF dup (?)
g_e_url     dw 1024 dup (?)
g_e_notes   dw EBUF dup (?)
g_e_totp    dw 256 dup (?)            ; entry-form base32 TOTP key (wide)
g_totp_on   dd ?                      ; 1 if the selected entry has a TOTP key
g_totp_secs dd ?                      ; seconds left in the current TOTP window
g_totp_b32len dd ?
g_totp_b32  db 256 dup (?)            ; selected entry's base32 key (utf8)
g_totp_code6 db 8 dup (?)            ; computed 6-digit code (ascii)
g_totp_code_w dw 16 dup (?)          ; code as wide, 6 digits no space (for clipboard)
g_totp_disp_w dw 16 dup (?)          ; code grouped "nnn nnn" wide (on-screen only)
g_disp_a    db 32 dup (?)            ; "287082  (17s)" display, ascii
align 8
; --- modular field-row model (runtime detail form) ---
g_fields      db MAXROWS*DESCSZ dup (?)   ; row descriptors
g_field_count dd ?                        ; live row count
g_content_h   dd ?                        ; field-form content bottom (DLU) after layout
g_rowkind     dd ?                        ; scratch: kind for a pending add
g_dlgfont     dq ?                        ; the vault dialog's font (for runtime ctls)
g_totp_row    dd ?                        ; row index of the TOTP field (-1 = none)
g_totp_codehwnd dq ?                      ; live-code display control of the TOTP row
g_totp_barhwnd  dq ?                      ; drain-bar control of the TOTP row
align 8
g_imgstageref db 68 dup (?)               ; scratch AttachRef from attach_stage
g_imgblob     db IMG_BLOBCAP dup (?)       ; scratch {AttachRef, filename wide} value blob
align 2
g_imgfn_w     dw 200 dup (?)               ; current image's filename (wide) to store
g_imgbuf      dq ?                         ; imported file bytes (mem_alloc'd)
g_imgbuflen   dq ?
g_iv_img      dq ?                         ; image handle shown in the enlarge dialog
g_iv_ref      dq ?                         ; AttachRef ptr for the enlarge dialog's Export
g_iv_isfile   dd ?                         ; 1 = enlarge target is a VF_FILE (try preview)
g_iv_preview  dq ?                         ; hosted preview handle in the viewer (0=none)
g_pickfilter  dq ?                         ; OPENFILENAME filter for the next pick (0=image)
g_tmpfile     dw 1024 dup (?)              ; temp path for file open/preview (wide)
align 2
g_imgpath     dw 1024 dup (?)             ; import/export file path (wide)
g_valblob   dw 32768 dup (?)          ; commit scratch: field values, NUL-joined
g_lblblob   dw 4096 dup (?)           ; commit scratch: custom labels, NUL-joined
g_rlabel    dw 128 dup (?)            ; per-row label read scratch
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
; gui_browse(rcx = hdlg, edx = save?) - run the open/save file dialog; on OK
;   store the path in g_vpath, set g_vpath_set, and show it in IDC_U_PATH.
; =============================================================================
gui_browse proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx         ; hdlg
    mov     dword ptr [rbp-32], edx         ; save flag
    ; zero the OPENFILENAMEW
    lea     rcx, [g_ofn]
    mov     edx, sizeof OPENFILENAMEW
    call    secure_zero
    lea     r10, [g_ofn]
    mov     dword ptr [r10].OPENFILENAMEW.lStructSize, sizeof OPENFILENAMEW
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [r10].OPENFILENAMEW.hwndOwner, rax
    lea     rax, [g_filter]
    mov     qword ptr [r10].OPENFILENAMEW.lpstrFilter, rax
    lea     rax, [g_vpath]
    mov     qword ptr [r10].OPENFILENAMEW.lpstrFile, rax
    mov     dword ptr [r10].OPENFILENAMEW.nMaxFile, 1024
    lea     rax, [g_defext]
    mov     qword ptr [r10].OPENFILENAMEW.lpstrDefExt, rax
    mov     dword ptr [r10].OPENFILENAMEW.nFilterIndex, 1
    ; the dialog overwrites g_vpath; start it empty so a fresh pick is clean
    mov     word ptr [g_vpath], 0
    cmp     dword ptr [rbp-32], 0
    jne     gb_save
    lea     rax, [t_open]
    mov     qword ptr [r10].OPENFILENAMEW.lpstrTitle, rax
    mov     dword ptr [r10].OPENFILENAMEW.Flags, OFN_FILEMUSTEXIST or OFN_PATHMUSTEXIST or OFN_HIDEREADONLY or OFN_EXPLORER
    WINCALL GetOpenFileNameW, addr g_ofn
    jmp     gb_check
gb_save:
    lea     rax, [t_new]
    mov     qword ptr [r10].OPENFILENAMEW.lpstrTitle, rax
    mov     dword ptr [r10].OPENFILENAMEW.Flags, OFN_OVERWRITEPROMPT or OFN_PATHMUSTEXIST or OFN_HIDEREADONLY or OFN_EXPLORER
    WINCALL GetSaveFileNameW, addr g_ofn
gb_check:
    test    eax, eax
    jz      gb_done                         ; cancelled
    mov     dword ptr [g_vpath_set], 1
    mov     eax, dword ptr [rbp-32]         ; save mode == create-new mode
    mov     dword ptr [g_create], eax
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_U_PATH, addr g_vpath
gb_done:
    FRAME_EPILOG
    ret
gui_browse endp

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
    cmp     eax, IDCANCEL
    je      up_cancel
    xor     eax, eax
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
    mov     ecx, dword ptr [rbp-40]
    lea     rdx, [rbp-48]                       ; &len
    call    vault_title_at                      ; rax = title ptr, [rbp-48] = len
    mov     rcx, rax
    mov     edx, dword ptr [rbp-48]
    lea     r8, [g_conv_w]
    mov     r9d, EBUF*2-1
    call    gui_towide
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_ADDSTRING, 0, addr g_conv_w
    mov     dword ptr [rbp-64], eax             ; sorted insert position
    cmp     eax, 0
    jl      gp_next
    ; tag the new row with the real vault index (sorting/filtering scrambles order)
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_SETITEMDATA, \
            dword ptr [rbp-64], qword ptr [rbp-40]
gp_next:
    inc     dword ptr [rbp-40]
    jmp     gp_loop
gp_done:
    FRAME_EPILOG
    ret
gui_poplist endp

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
    mov     dword ptr [g_loading], 1          ; suppress EN_CHANGE dirty while loading
    mov     dword ptr [g_totp_on], 0
    mov     dword ptr [g_totp_row], -1
    mov     qword ptr [g_totp_codehwnd], 0
    mov     qword ptr [g_totp_barhwnd], 0
    ; stop any prior live-code timer and tear down old rows
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-24]
    mov     edx, TOTP_TIMER
    call    KillTimer
    add     rsp, 32
    mov     rcx, qword ptr [rbp-24]
    call    gui_rows_clear
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
    ; image/file field: value is {AttachRef, filename} -> load ref + preview
    cmp     dword ptr [rbp-96], VF_IMAGE
    je      gsd_imgload
    cmp     dword ptr [rbp-96], VF_FILE
    je      gsd_fileload
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_VALUE
    call    dynid
    mov     rcx, qword ptr [rbp-24]
    mov     edx, eax
    mov     r8, qword ptr [rbp-72]              ; valptr
    mov     r9d, dword ptr [rbp-64]             ; vallen
    call    gui_setfield
    mov     eax, dword ptr [rbp-96]             ; kind
    cmp     eax, VF_SECRET
    je      gsd_mask
    cmp     eax, VF_TOTP
    je      gsd_mask
    jmp     gsd_fnext
gsd_mask:
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_VALUE
    call    dynid
    mov     dword ptr [rbp-56], eax
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], dword ptr [rbp-56], \
            EM_SETPASSWORDCHAR, SECRET_MASK, 0
    jmp     gsd_fnext
gsd_imgload:
    mov     ecx, dword ptr [rbp-44]
    mov     rdx, qword ptr [rbp-72]             ; out.valptr = {AttachRef, filename}
    mov     r8d, dword ptr [rbp-64]             ; out.vallen
    call    gui_img_setblob
    mov     ecx, dword ptr [rbp-44]
    call    gui_img_decode
    jmp     gsd_fnext
gsd_fileload:
    mov     ecx, dword ptr [rbp-44]
    mov     rdx, qword ptr [rbp-72]             ; {AttachRef, filename}
    mov     r8d, dword ptr [rbp-64]
    call    gui_img_setblob
    ; show the filename in the read-only DS_VALUE edit
    mov     eax, dword ptr [rbp-64]
    cmp     eax, 68
    jbe     gsd_filethumb
    mov     ecx, dword ptr [rbp-44]
    mov     edx, DS_VALUE
    call    dynid
    mov     r8, qword ptr [rbp-72]
    add     r8, 68                             ; filename (wide)
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], eax, r8
gsd_filethumb:
    mov     ecx, dword ptr [rbp-44]
    call    gui_file_preview                   ; shell thumbnail (PDF page / icon)
gsd_fnext:
    inc     dword ptr [rbp-40]
    jmp     gsd_floop
gsd_fdone:
    mov     rcx, qword ptr [rbp-24]
    call    gui_rows_layout
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

; gui_lbsel(rcx = hdlg) -> eax = selected index, or -1 if none.
gui_lbsel proc frame
    FRAME_PROLOG 32
    WINCALL SendDlgItemMessageW, rcx, IDC_V_LIST, LB_GETCURSEL, 0, 0
    FRAME_EPILOG
    ret
gui_lbsel endp

; gui_setcfg() - point g_cfg_title/user/secret/url/notes at the g_e_* buffers,
;   using 0 for empty fields (so va_field skips them).
gui_setcfg proc frame
    FRAME_PROLOG 32
    lea     rax, [g_e_title]
    cmp     word ptr [g_e_title], 0
    jne     @F
    xor     eax, eax
@@: mov     qword ptr [g_cfg_title], rax
    lea     rax, [g_e_user]
    cmp     word ptr [g_e_user], 0
    jne     @F
    xor     eax, eax
@@: mov     qword ptr [g_cfg_user], rax
    lea     rax, [g_e_secret]
    cmp     word ptr [g_e_secret], 0
    jne     @F
    xor     eax, eax
@@: mov     qword ptr [g_cfg_secret], rax
    lea     rax, [g_e_url]
    cmp     word ptr [g_e_url], 0
    jne     @F
    xor     eax, eax
@@: mov     qword ptr [g_cfg_url], rax
    lea     rax, [g_e_notes]
    cmp     word ptr [g_e_notes], 0
    jne     @F
    xor     eax, eax
@@: mov     qword ptr [g_cfg_notes], rax
    lea     rax, [g_e_totp]
    cmp     word ptr [g_e_totp], 0
    jne     @F
    xor     eax, eax
@@: mov     qword ptr [g_cfg_totp], rax
    FRAME_EPILOG
    ret
gui_setcfg endp

; gui_clearcfg() - clear the g_cfg_* field pointers + wipe the g_e_* buffers.
gui_clearcfg proc frame
    FRAME_PROLOG 32
    mov     qword ptr [g_cfg_title], 0
    mov     qword ptr [g_cfg_user], 0
    mov     qword ptr [g_cfg_secret], 0
    mov     qword ptr [g_cfg_url], 0
    mov     qword ptr [g_cfg_notes], 0
    mov     qword ptr [g_cfg_totp], 0
    lea     rcx, [g_e_secret]
    mov     edx, EBUF*2
    call    secure_zero
    lea     rcx, [g_e_totp]
    mov     edx, 512
    call    secure_zero
    FRAME_EPILOG
    ret
gui_clearcfg endp

; gui_addsave(rcx = hdlg) - commit the g_e_* fields as a new entry + reseal.
gui_addsave proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    call    gui_setcfg
    call    vault_add_entry                 ; eax = 0 / EXIT_*
    mov     dword ptr [rbp-32], eax
    call    gui_clearcfg
    cmp     dword ptr [rbp-32], 0
    jne     gas_err
    call    vault_reseal
    test    eax, eax
    jnz     gas_resealerr
    mov     rcx, qword ptr [rbp-24]
    call    gui_poplist
    jmp     gas_done
gas_err:
    cmp     dword ptr [rbp-32], EXIT_NOSPACE
    jne     @F
    WINCALL gui_msgbox, qword ptr [rbp-24], addr s_full, addr t_err, <MB_OK or MB_ICONERROR>
    jmp     gas_done
@@: WINCALL gui_msgbox, qword ptr [rbp-24], addr s_notitle, addr t_err, <MB_OK or MB_ICONERROR>
    jmp     gas_done
gas_resealerr:
    WINCALL gui_msgbox, qword ptr [rbp-24], addr s_resealfail, addr t_err, <MB_OK or MB_ICONERROR>
gas_done:
    FRAME_EPILOG
    ret
gui_addsave endp

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
    ; image/file row: emit the AttachRef as a VFL_RAW binary value (skip if empty)
    mov     eax, dword ptr [rbp-28]
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    test    dword ptr [r10+FD_FLAGS], FDF_HASIMG
    jz      gg_imgskip
    mov     ecx, dword ptr [rbp-32]
    imul    ecx, ecx, 24
    lea     r11, [g_field_list]
    add     r11, rcx
    mov     eax, dword ptr [r10+FD_KIND]         ; VF_IMAGE or VF_FILE
    or      eax, VFL_RAW
    mov     qword ptr [r11+0], rax
    mov     rax, r10
    add     rax, FD_ARF                          ; {u32 len, AttachRef, filename}
    mov     qword ptr [r11+16], rax
    mov     qword ptr [r11+8], 0
    jmp     gg_label
gg_imgskip:
    inc     dword ptr [rbp-28]                   ; drop empty image rows (k unchanged)
    jmp     gg_row
gg_done:
    mov     eax, dword ptr [rbp-32]
    mov     dword ptr [g_field_n], eax
    FRAME_EPILOG
    ret
gui_gather endp

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
    mov     r10, qword ptr [g_field_list+16]  ; title value ptr
    test    r10, r10
    jz      gco_notitle
    cmp     word ptr [r10], 0                 ; empty title -> keep the old entry
    je      gco_notitle
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
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [g_editmode], edx
    mov     eax, edx
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
    ; free any decoded image handle for this row
    mov     eax, dword ptr [rbp-24]
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     rcx, qword ptr [r10+FD_IMG]
    test    rcx, rcx
    jz      grc_noimg
    mov     qword ptr [r10+FD_IMG], 0
    call    img_free
grc_noimg:
    inc     dword ptr [rbp-24]
    jmp     grc_row
grc_done:
    mov     dword ptr [g_field_count], 0
    ; repaint the dialog bg so destroyed edits leave no ghost focus-underline
    WINCALL InvalidateRect, qword ptr [rbp-40], 0, 1
    FRAME_EPILOG
    ret
gui_rows_clear endp

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
    cmp     eax, VF_IMAGE
    je      gra_image
    cmp     eax, VF_FILE
    je      gra_file
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_edit, 0, \
            ES_AUTOHSCROLL_ or WS_TABSTOP_
    jmp     gra_reorder
gra_file:
    ; thumbnail (owner-draw preview) + read-only filename + Choose/Paste/Open/Save
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_THUMB, addr cls_button, 0, \
            BS_OWNERDRAW_ or WS_TABSTOP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_edit, 0, \
            ES_AUTOHSCROLL_ or ES_READONLY_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_IMPORT, addr cls_button, addr cap_choose, \
            BS_OWNERDRAW_ or WS_TABSTOP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_PASTE, addr cls_button, addr cap_paste, \
            BS_OWNERDRAW_ or WS_TABSTOP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_OPEN, addr cls_button, addr cap_open, \
            BS_OWNERDRAW_ or WS_TABSTOP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_EXPORT, addr cls_button, addr cap_save, \
            BS_OWNERDRAW_ or WS_TABSTOP_
    jmp     gra_reorder
gra_image:
    ; owner-draw thumbnail (also the click-to-enlarge button) + import/paste
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_THUMB, addr cls_button, 0, \
            BS_OWNERDRAW_ or WS_TABSTOP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_IMPORT, addr cls_button, addr cap_import, \
            BS_OWNERDRAW_ or WS_TABSTOP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_PASTE, addr cls_button, addr cap_paste, \
            BS_OWNERDRAW_ or WS_TABSTOP_
    jmp     gra_reorder
gra_secret:
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_VALUE, addr cls_edit, 0, \
            ES_PASSWORD_ or ES_AUTOHSCROLL_ or WS_TABSTOP_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_REVEAL, addr cls_button, addr wb_eye, \
            BS_OWNERDRAW_
    WINCALL row_mk, qword ptr [rbp-24], dword ptr [rbp-40], DS_COPY, addr cls_button, addr wb_copy, \
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
; Image field helpers (attachments + GDI+ thumbnails)
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

; gui_img_setblob(ecx=row, rdx=blob ptr, r8d=blob len) - copy the image value blob
;   ({AttachRef[68], filename wide}) into FD_ARF (length-prefixed for VFL_RAW),
;   mark FDF_HASIMG, drop any old decoded image.
gui_img_setblob proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-24], ecx
    mov     qword ptr [rbp-32], rdx
    cmp     r8d, IMG_BLOBCAP-4
    jbe     @F
    mov     r8d, IMG_BLOBCAP-4
@@: mov     dword ptr [rbp-44], r8d
    call    gui_desc
    mov     qword ptr [rbp-40], rax
    mov     rcx, qword ptr [rax+FD_IMG]
    test    rcx, rcx
    jz      gis_copy
    mov     qword ptr [rax+FD_IMG], 0
    call    img_free
gis_copy:
    mov     r10, qword ptr [rbp-40]
    mov     eax, dword ptr [rbp-44]
    mov     dword ptr [r10+FD_ARF], eax
    lea     rcx, [r10+FD_ARF+4]
    mov     rdx, qword ptr [rbp-32]
    mov     r8d, dword ptr [rbp-44]
    call    gui_bcpy
    mov     r10, qword ptr [rbp-40]
    or      dword ptr [r10+FD_FLAGS], FDF_HASIMG
    FRAME_EPILOG
    ret
gui_img_setblob endp

; gui_img_decode(ecx=row) - decrypt the row's attachment and img_load a handle
;   into FD_IMG (freeing any prior).  No-op unless FDF_HASIMG.
gui_img_decode proc frame
    FRAME_PROLOG 48
    call    gui_desc
    mov     qword ptr [rbp-24], rax
    test    dword ptr [rax+FD_FLAGS], FDF_HASIMG
    jz      gid_done
    mov     rcx, qword ptr [rax+FD_IMG]
    test    rcx, rcx
    jz      gid_open
    mov     qword ptr [rax+FD_IMG], 0
    call    img_free
gid_open:
    mov     r10, qword ptr [rbp-24]
    lea     rcx, [r10+FD_ARF+4]
    lea     rdx, [rbp-32]                       ; &ptlen
    call    attach_open
    test    rax, rax
    jz      gid_done
    mov     qword ptr [rbp-40], rax             ; plaintext
    mov     rcx, rax
    mov     rdx, qword ptr [rbp-32]
    call    img_load
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [r10+FD_IMG], rax
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
gid_done:
    FRAME_EPILOG
    ret
gui_img_decode endp

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

; gui_img_setbytes(rcx=hdlg, edx=row, r8=bytes, r9=len) - stage the encoded bytes
;   as a new attachment (filename in g_imgfn_w), load the thumbnail, mark dirty,
;   repaint the thumbnail.
gui_img_setbytes proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-40], r8
    mov     qword ptr [rbp-48], r9
    mov     rcx, r8
    mov     rdx, r9
    lea     r8, [g_imgstageref]
    call    attach_stage
    test    eax, eax
    jnz     gsb_done
    ; build g_imgblob = AttachRef(68) | filename wide
    lea     rcx, [g_imgblob]
    lea     rdx, [g_imgstageref]
    mov     r8, 68
    call    gui_bcpy
    lea     rcx, [g_imgblob+68]
    lea     rdx, [g_imgfn_w]
    call    gui_wcpy_capped
    add     eax, 68
    mov     dword ptr [rbp-56], eax             ; blob len
    mov     ecx, dword ptr [rbp-32]
    lea     rdx, [g_imgblob]
    mov     r8d, dword ptr [rbp-56]
    call    gui_img_setblob
    mov     ecx, dword ptr [rbp-32]
    call    gui_img_refresh
    mov     dword ptr [g_dirty], 1
    ; repaint the thumbnail control
    mov     ecx, dword ptr [rbp-32]
    mov     edx, DS_THUMB
    call    dynid
    mov     dword ptr [rbp-64], eax
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-64]
    call    GetDlgItem
    sub     rsp, 32
    mov     rcx, rax
    xor     edx, edx
    mov     r8d, 1
    call    InvalidateRect
    add     rsp, 32
gsb_done:
    FRAME_EPILOG
    ret
gui_img_setbytes endp

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

; gui_img_import(rcx=hdlg, edx=row) - pick a file, read its bytes, store them.
gui_img_import proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [g_pickfilter], 0         ; image filter
    xor     edx, edx                            ; open
    call    img_pick
    test    eax, eax
    jz      gii_done
    lea     rcx, [g_imgpath]
    lea     rdx, [g_imgbuf]
    lea     r8, [g_imgbuflen]
    call    read_file
    test    eax, eax
    jnz     gii_done
    lea     rcx, [g_imgpath]                    ; remember the original file name
    call    gui_basename
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    mov     r8, qword ptr [g_imgbuf]
    mov     r9, qword ptr [g_imgbuflen]
    call    gui_img_setbytes
    mov     rcx, qword ptr [g_imgbuf]
    mov     rdx, qword ptr [g_imgbuflen]
    call    mem_free
    mov     qword ptr [g_imgbuf], 0
gii_done:
    FRAME_EPILOG
    ret
gui_img_import endp

; gui_img_paste(rcx=hdlg, edx=row) - if the clipboard holds a bitmap, encode it
;   to PNG and store it.
gui_img_paste proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     qword ptr [rbp-56], 0               ; png bytes
    WINCALL IsClipboardFormatAvailable, CF_BITMAP
    test    eax, eax
    jz      gip_done
    WINCALL OpenClipboard, qword ptr [rbp-24]
    test    eax, eax
    jz      gip_done
    WINCALL GetClipboardData, CF_BITMAP
    mov     qword ptr [rbp-40], rax
    test    rax, rax
    jz      gip_close
    mov     rcx, rax
    lea     rdx, [rbp-48]                       ; &pnglen
    call    img_encode_hbitmap
    mov     qword ptr [rbp-56], rax
gip_close:
    WINCALL CloseClipboard
    cmp     qword ptr [rbp-56], 0
    je      gip_done
    ; default filename = <image field label>_<record title>.png
    mov     ecx, dword ptr [rbp-32]             ; this row's label control
    mov     edx, DS_LABEL
    call    dynid
    mov     dword ptr [rbp-64], eax
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], dword ptr [rbp-64], addr g_imgfn_w, 60
    mov     dword ptr [rbp-72], eax             ; pos = label length
    lea     r10, [g_imgfn_w]                    ; append '_'
    mov     eax, dword ptr [rbp-72]
    mov     word ptr [r10+rax*2], '_'
    inc     dword ptr [rbp-72]
    lea     r10, [g_imgfn_w]                    ; append record title at pos
    mov     eax, dword ptr [rbp-72]
    lea     rdx, [r10+rax*2]
    mov     qword ptr [rbp-80], rdx
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_V_TITLE, qword ptr [rbp-80], 60
    add     dword ptr [rbp-72], eax             ; pos += title length
    lea     r10, [g_imgfn_w]                    ; append ".png"
    mov     eax, dword ptr [rbp-72]
    lea     r10, [r10+rax*2]
    lea     r11, [suffix_dotpng]
    xor     r9d, r9d
gpn_l:
    mov     ax, word ptr [r11+r9*2]
    mov     word ptr [r10+r9*2], ax
    test    ax, ax
    jz      gpn_done
    inc     r9d
    jmp     gpn_l
gpn_done:
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    mov     r8, qword ptr [rbp-56]
    mov     r9, qword ptr [rbp-48]
    call    gui_img_setbytes
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-48]
    call    mem_free
gip_done:
    FRAME_EPILOG
    ret
gui_img_paste endp

; gui_img_paint(rcx=lpdis, rdx=img handle) - fill the owner-draw rect and draw the
;   image aspect-fit (or a "(no image)" placeholder).
gui_img_paint proc frame
    FRAME_PROLOG 192                            ; each local its own 8-byte slot (no
    mov     qword ptr [rbp-24], rcx             ;   qword/dword overlap) + 6-arg call
    mov     qword ptr [rbp-48], rdx             ; img
    mov     r10, rcx
    mov     rax, qword ptr [r10+32]
    mov     qword ptr [rbp-32], rax             ; hdc
    mov     eax, dword ptr [r10+40]
    mov     dword ptr [rbp-56], eax             ; L
    mov     eax, dword ptr [r10+44]
    mov     dword ptr [rbp-64], eax             ; T
    mov     eax, dword ptr [r10+48]
    mov     dword ptr [rbp-72], eax             ; R
    mov     eax, dword ptr [r10+52]
    mov     dword ptr [rbp-80], eax             ; B
    WINCALL GetStockObject, 3                   ; DKGRAY_BRUSH
    mov     qword ptr [rbp-40], rax             ; brush
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL FillRect, qword ptr [rbp-32], rdx, qword ptr [rbp-40]
    cmp     qword ptr [rbp-48], 0
    je      gpt_noimg
    mov     rcx, qword ptr [rbp-48]
    lea     rdx, [rbp-88]                       ; &iw
    lea     r8, [rbp-96]                        ; &ih
    call    img_dims
    mov     eax, dword ptr [rbp-88]
    test    eax, eax
    jz      gpt_noimg
    mov     eax, dword ptr [rbp-96]
    test    eax, eax
    jz      gpt_noimg
    mov     eax, dword ptr [rbp-72]             ; R
    sub     eax, dword ptr [rbp-56]             ; -L
    sub     eax, 4
    mov     dword ptr [rbp-104], eax            ; availw
    mov     eax, dword ptr [rbp-80]             ; B
    sub     eax, dword ptr [rbp-64]             ; -T
    sub     eax, 4
    mov     dword ptr [rbp-112], eax            ; availh
    mov     eax, dword ptr [rbp-96]             ; ih
    imul    eax, dword ptr [rbp-104]            ; ih*availw
    cdq
    idiv    dword ptr [rbp-88]                  ; /iw
    mov     dword ptr [rbp-120], eax            ; fh
    mov     eax, dword ptr [rbp-104]
    mov     dword ptr [rbp-128], eax            ; fw = availw
    mov     eax, dword ptr [rbp-120]
    cmp     eax, dword ptr [rbp-112]
    jle     gpt_have
    mov     eax, dword ptr [rbp-112]
    mov     dword ptr [rbp-120], eax            ; fh = availh
    mov     eax, dword ptr [rbp-88]             ; iw
    imul    eax, dword ptr [rbp-112]            ; iw*availh
    cdq
    idiv    dword ptr [rbp-96]                  ; /ih
    mov     dword ptr [rbp-128], eax            ; fw
gpt_have:
    mov     eax, dword ptr [rbp-72]             ; R
    sub     eax, dword ptr [rbp-56]             ; w = R-L
    sub     eax, dword ptr [rbp-128]            ; -fw
    sar     eax, 1
    add     eax, dword ptr [rbp-56]             ; +L
    mov     dword ptr [rbp-136], eax            ; x
    mov     eax, dword ptr [rbp-80]             ; B
    sub     eax, dword ptr [rbp-64]             ; h = B-T
    sub     eax, dword ptr [rbp-120]            ; -fh
    sar     eax, 1
    add     eax, dword ptr [rbp-64]             ; +T
    mov     dword ptr [rbp-144], eax            ; y
    WINCALL img_draw, qword ptr [rbp-48], qword ptr [rbp-32], dword ptr [rbp-136], \
            dword ptr [rbp-144], dword ptr [rbp-128], dword ptr [rbp-120]
    FRAME_EPILOG
    ret
gpt_noimg:
    WINCALL SetBkMode, qword ptr [rbp-32], 1
    WINCALL SetTextColor, qword ptr [rbp-32], 00C8C8C8h
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+40]
    WINCALL DrawTextW, qword ptr [rbp-32], addr cap_noimg, -1, rdx, DT_IMGFLAGS
    FRAME_EPILOG
    ret
gui_img_paint endp

; gui_img_drawthumb(rcx=lpdis) - draw a row's thumbnail (decodes row from CtlID).
gui_img_drawthumb proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     r10, rcx
    mov     ecx, dword ptr [r10+4]              ; CtlID
    sub     ecx, IDC_DYN_BASE
    shr     ecx, DYN_SLOTS_LOG2                 ; row
    call    gui_desc
    mov     rdx, qword ptr [rax+FD_IMG]
    mov     rcx, qword ptr [rbp-24]
    call    gui_img_paint
    FRAME_EPILOG
    ret
gui_img_drawthumb endp

; gui_img_enlarge(rcx=hdlg, edx=row) - open the viewer for the row's image.
gui_img_enlarge proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     ecx, edx
    call    gui_desc
    mov     qword ptr [rbp-32], rax             ; desc
    test    dword ptr [rax+FD_FLAGS], FDF_HASIMG
    jz      gie_done                            ; nothing attached
    mov     r10, qword ptr [rax+FD_IMG]
    mov     qword ptr [g_iv_img], r10           ; thumbnail (may be 0 for files)
    lea     rdx, [rax+FD_ARF+4]
    mov     qword ptr [g_iv_ref], rdx
    xor     eax, eax
    mov     r10, qword ptr [rbp-32]
    cmp     dword ptr [r10+FD_KIND], VF_FILE    ; files try a live preview handler
    jne     @F
    mov     eax, 1
@@: mov     dword ptr [g_iv_isfile], eax
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_IMGVIEW, qword ptr [rbp-24], addr imgview_proc, 0
gie_done:
    FRAME_EPILOG
    ret
gui_img_enlarge endp

; gui_img_export(rcx=hdlg) - decode the viewer's attachment and save it to a file.
gui_img_export proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    ; prefill the save dialog with the stored filename (blob len is at ref-4)
    mov     r10, qword ptr [g_iv_ref]
    mov     eax, dword ptr [r10-4]
    cmp     eax, 68
    jbe     gxe_nofn
    lea     rcx, [g_imgpath]
    lea     rdx, [r10+68]
    call    gui_wcpy_capped
    jmp     gxe_pick
gxe_nofn:
    mov     word ptr [g_imgpath], 0
gxe_pick:
    mov     rcx, qword ptr [rbp-24]
    mov     edx, 1                              ; save dialog
    call    img_pick
    test    eax, eax
    jz      gxe_done
    mov     rcx, qword ptr [g_iv_ref]
    lea     rdx, [rbp-32]                       ; &len
    call    attach_open
    test    rax, rax
    jz      gxe_done
    mov     qword ptr [rbp-40], rax             ; bytes
    lea     rcx, [g_imgpath]
    mov     rdx, rax
    mov     r8, qword ptr [rbp-32]
    call    write_file
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
gxe_done:
    FRAME_EPILOG
    ret
gui_img_export endp

; =============================================================================
; Generic file attachments (VF_FILE)
; =============================================================================

; gui_img_refresh(ecx=row) - re-render the row's preview: GDI+ decode for images,
;   shell thumbnail for files.
gui_img_refresh proc frame
    FRAME_PROLOG 32
    mov     dword ptr [rbp-24], ecx
    call    gui_desc
    cmp     dword ptr [rax+FD_KIND], VF_FILE
    je      gir_file
    mov     ecx, dword ptr [rbp-24]
    call    gui_img_decode
    FRAME_EPILOG
    ret
gir_file:
    mov     ecx, dword ptr [rbp-24]
    call    gui_file_preview
    FRAME_EPILOG
    ret
gui_img_refresh endp

; gui_make_temp_path(rcx=desc) - build g_tmpfile = %TEMP%\<stored filename>.
gui_make_temp_path proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    WINCALL GetTempPathW, 512, addr g_tmpfile
    mov     dword ptr [rbp-32], eax                  ; length incl trailing '\'
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [r10+FD_ARF]
    cmp     eax, 68
    jbe     gmt_default
    mov     eax, dword ptr [rbp-32]
    lea     rcx, [g_tmpfile]
    lea     rcx, [rcx+rax*2]
    mov     r10, qword ptr [rbp-24]
    lea     rdx, [r10+FD_ARF+4+68]
    call    gui_wcpy_capped
    FRAME_EPILOG
    ret
gmt_default:
    mov     eax, dword ptr [rbp-32]
    lea     rcx, [g_tmpfile]
    lea     rcx, [rcx+rax*2]
    lea     rdx, [name_default_att]
    call    gui_wcpy_capped
    FRAME_EPILOG
    ret
gui_make_temp_path endp

; gui_file_preview(ecx=row) - decrypt the file to a short-lived temp, ask the shell
;   for its thumbnail (PDF first page / doc preview / icon), wrap it as an image
;   handle in FD_IMG, then delete the temp.  No-op if nothing decodes.
gui_file_preview proc frame
    FRAME_PROLOG 64
    mov     dword ptr [rbp-32], ecx
    call    gui_desc
    mov     qword ptr [rbp-24], rax                  ; desc
    ; free any prior handle
    mov     rcx, qword ptr [rax+FD_IMG]
    test    rcx, rcx
    jz      gfp_open
    mov     qword ptr [rax+FD_IMG], 0
    call    img_free
gfp_open:
    mov     r10, qword ptr [rbp-24]
    test    dword ptr [r10+FD_FLAGS], FDF_HASIMG
    jz      gfp_done
    lea     rcx, [r10+FD_ARF+4]                      ; AttachRef
    lea     rdx, [rbp-40]                            ; &len
    call    attach_open
    test    rax, rax
    jz      gfp_done
    mov     qword ptr [rbp-48], rax                  ; plaintext
    mov     rcx, qword ptr [rbp-24]
    call    gui_make_temp_path
    lea     rcx, [g_tmpfile]
    mov     rdx, qword ptr [rbp-48]
    mov     r8, qword ptr [rbp-40]
    call    write_file
    ; scrub + free the plaintext promptly
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-40]
    call    mem_free
    ; shell thumbnail (256x256 px) -> HBITMAP
    lea     rcx, [g_tmpfile]
    mov     edx, 256
    mov     r8d, 256
    call    shell_thumb
    mov     qword ptr [rbp-56], rax                  ; hbitmap (0 if none)
    WINCALL DeleteFileW, addr g_tmpfile             ; remove the temp asap
    cmp     qword ptr [rbp-56], 0
    je      gfp_done
    mov     rcx, qword ptr [rbp-56]                  ; wrap HBITMAP as an img handle
    call    img_from_hbitmap
    mov     r10, qword ptr [rbp-24]
    mov     qword ptr [r10+FD_IMG], rax
    WINCALL DeleteObject, qword ptr [rbp-56]
gfp_done:
    FRAME_EPILOG
    ret
gui_file_preview endp

; gui_file_import(rcx=hdlg, edx=row) - pick any file and store it as an attachment.
gui_file_import proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    lea     rax, [g_allfilter]
    mov     qword ptr [g_pickfilter], rax
    mov     rcx, qword ptr [rbp-24]
    xor     edx, edx
    call    img_pick
    test    eax, eax
    jz      gfi_done
    lea     rcx, [g_imgpath]
    lea     rdx, [g_imgbuf]
    lea     r8, [g_imgbuflen]
    call    read_file
    test    eax, eax
    jnz     gfi_done
    lea     rcx, [g_imgpath]
    call    gui_basename                             ; -> g_imgfn_w
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-32]
    mov     r8, qword ptr [g_imgbuf]
    mov     r9, qword ptr [g_imgbuflen]
    call    gui_img_setbytes
    mov     rcx, qword ptr [g_imgbuf]
    mov     rdx, qword ptr [g_imgbuflen]
    call    mem_free
    mov     qword ptr [g_imgbuf], 0
    ; show the filename in the read-only edit
    mov     ecx, dword ptr [rbp-32]
    mov     edx, DS_VALUE
    call    dynid
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], eax, addr g_imgfn_w
gfi_done:
    FRAME_EPILOG
    ret
gui_file_import endp

; gui_file_export(rcx=hdlg, edx=row) - save the attachment to a chosen file.
gui_file_export proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     ecx, edx
    call    gui_desc
    test    dword ptr [rax+FD_FLAGS], FDF_HASIMG
    jz      gfe2_done
    mov     qword ptr [rbp-40], rax
    mov     eax, dword ptr [rax+FD_ARF]
    cmp     eax, 68
    jbe     gfe2_nofn
    mov     r10, qword ptr [rbp-40]
    lea     rcx, [g_imgpath]
    lea     rdx, [r10+FD_ARF+4+68]
    call    gui_wcpy_capped
    jmp     gfe2_pick
gfe2_nofn:
    mov     word ptr [g_imgpath], 0
gfe2_pick:
    lea     rax, [g_allfilter]
    mov     qword ptr [g_pickfilter], rax
    mov     rcx, qword ptr [rbp-24]
    mov     edx, 1
    call    img_pick
    test    eax, eax
    jz      gfe2_done
    mov     r10, qword ptr [rbp-40]
    lea     rcx, [r10+FD_ARF+4]
    lea     rdx, [rbp-48]
    call    attach_open
    test    rax, rax
    jz      gfe2_done
    mov     qword ptr [rbp-56], rax
    lea     rcx, [g_imgpath]
    mov     rdx, rax
    mov     r8, qword ptr [rbp-48]
    call    write_file
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-48]
    call    mem_free
gfe2_done:
    FRAME_EPILOG
    ret
gui_file_export endp

; gui_file_open(rcx=hdlg, edx=row) - decrypt to a temp file and open it in the
;   system default app (the temp holds plaintext until the OS cleans %TEMP%).
gui_file_open proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     ecx, edx
    call    gui_desc
    test    dword ptr [rax+FD_FLAGS], FDF_HASIMG
    jz      gfo_done
    mov     qword ptr [rbp-40], rax
    lea     rcx, [rax+FD_ARF+4]
    lea     rdx, [rbp-48]
    call    attach_open
    test    rax, rax
    jz      gfo_done
    mov     qword ptr [rbp-56], rax
    mov     rcx, qword ptr [rbp-40]
    call    gui_make_temp_path
    lea     rcx, [g_tmpfile]
    mov     rdx, qword ptr [rbp-56]
    mov     r8, qword ptr [rbp-48]
    call    write_file
    mov     rcx, qword ptr [rbp-56]
    mov     rdx, qword ptr [rbp-48]
    call    mem_free
    WINCALL ShellExecuteW, 0, addr verb_open, addr g_tmpfile, 0, 0, 1
gfo_done:
    FRAME_EPILOG
    ret
gui_file_open endp

; gui_ext_of(rcx=wide filename) -> rax = ptr to the last '.' (incl.), or 0.  Leaf.
gui_ext_of proc
    mov     r10, rcx
    xor     rax, rax
geo_l:
    mov     dx, word ptr [r10]
    test    dx, dx
    jz      geo_done
    cmp     dx, '.'
    jne     @F
    mov     rax, r10
@@: add     r10, 2
    jmp     geo_l
geo_done:
    ret
gui_ext_of endp

; gui_iv_preview_setup(rcx=hdlg) -> eax = 1 if a live preview handler was hosted in
;   IDC_IV_PIC (renders the actual page content), else 0 (fall back to thumbnail).
gui_iv_preview_setup proc frame
    FRAME_PROLOG 128
    ; [rbp-24]=hdlg [rbp-32]=len [rbp-40]=bytes [rbp-48]=ext [rbp-56]=templen
    ; [rbp-64]=ph [rbp-72]=pichwnd  RECT @ [rbp-96]
    mov     qword ptr [rbp-24], rcx
    mov     rcx, qword ptr [g_iv_ref]
    lea     rdx, [rbp-32]
    call    attach_open
    test    rax, rax
    jz      gps_fail
    mov     qword ptr [rbp-40], rax
    mov     rcx, qword ptr [g_iv_ref]
    add     rcx, 68                             ; filename (wide)
    call    gui_ext_of
    test    rax, rax
    jz      gps_freebytes
    mov     qword ptr [rbp-48], rax
    ; temp path = %TEMP%\<filename>
    WINCALL GetTempPathW, 500, addr g_tmpfile
    mov     qword ptr [rbp-56], rax
    lea     rcx, [g_tmpfile]
    mov     r10, qword ptr [rbp-56]
    lea     rcx, [rcx+r10*2]
    mov     rdx, qword ptr [g_iv_ref]
    add     rdx, 68
    call    gui_wcpy_capped
    ; preview_open(ext, bytes, len, temp)
    mov     rcx, qword ptr [rbp-48]
    mov     rdx, qword ptr [rbp-40]
    mov     r8, qword ptr [rbp-32]
    lea     r9, [g_tmpfile]
    call    preview_open
    mov     qword ptr [rbp-64], rax
    mov     rcx, qword ptr [rbp-40]             ; free the decrypted bytes now
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
    cmp     qword ptr [rbp-64], 0
    je      gps_fail
    mov     rax, qword ptr [rbp-64]
    mov     qword ptr [g_iv_preview], rax
    ; host it in IDC_IV_PIC at its full client rect
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_IV_PIC
    call    GetDlgItem
    mov     qword ptr [rbp-72], rax
    mov     rcx, rax
    lea     rdx, [rbp-96]
    call    GetClientRect
    mov     rcx, qword ptr [g_iv_preview]
    mov     rdx, qword ptr [rbp-72]
    lea     r8, [rbp-96]
    call    preview_show
    mov     eax, 1
    FRAME_EPILOG
    ret
gps_freebytes:
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, qword ptr [rbp-32]
    call    mem_free
gps_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
gui_iv_preview_setup endp

; imgview_proc - DLG_IMGVIEW procedure (themed; shows g_iv_img, Export/Close).
imgview_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx
    cmp     rdx, WM_INITDIALOG
    je      iv_init
    cmp     rdx, WM_COMMAND
    je      iv_cmd
    cmp     rdx, WM_PAINT
    je      iv_paint
    cmp     rdx, WM_ERASEBKGND
    je      iv_erase
    cmp     rdx, WM_DRAWITEM
    je      iv_draw
    cmp     rdx, WM_CTLCOLORBTN
    je      iv_color
    cmp     rdx, WM_CTLCOLORDLG
    je      iv_color
    cmp     rdx, WM_CTLCOLORSTATIC
    je      iv_color
    xor     eax, eax
    jmp     iv_ret
iv_color:
    call    theme_ctlcolor
    jmp     iv_ret
iv_init:
    mov     qword ptr [g_iv_preview], 0
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_IV_EXPORT
    call    theme_attach
    cmp     dword ptr [g_iv_isfile], 0
    je      iv_init_done
    mov     rcx, qword ptr [rbp-8]
    call    gui_iv_preview_setup
iv_init_done:
    mov     eax, 1
    jmp     iv_ret
iv_paint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     iv_ret
iv_erase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     iv_ret
iv_draw:
    ; r9 = lpdis; if it is the picture, draw the image, else theme the button
    mov     r10, r9
    mov     eax, dword ptr [r10+4]              ; CtlID
    cmp     eax, IDC_IV_PIC
    jne     iv_drawbtn
    cmp     qword ptr [g_iv_preview], 0         ; hosted preview covers the pic -> skip
    jne     iv_pic_done
    mov     rcx, r9
    mov     rdx, qword ptr [g_iv_img]
    call    gui_img_paint
iv_pic_done:
    mov     eax, 1
    jmp     iv_ret
iv_drawbtn:
    mov     rcx, r9
    call    theme_drawitem
    jmp     iv_ret
iv_cmd:
    movzx   eax, r8w
    cmp     eax, IDC_IV_EXPORT
    je      iv_export
    cmp     eax, IDOK
    je      iv_close
    cmp     eax, IDCANCEL
    je      iv_close
    xor     eax, eax
    jmp     iv_ret
iv_export:
    mov     rcx, qword ptr [rbp-8]
    call    gui_img_export
    mov     eax, 1
    jmp     iv_ret
iv_close:
    cmp     qword ptr [g_iv_preview], 0
    je      iv_close_end
    mov     rcx, qword ptr [g_iv_preview]
    call    preview_close
    mov     qword ptr [g_iv_preview], 0
iv_close_end:
    WINCALL EndDialog, qword ptr [rbp-8], 0
    mov     eax, 1
iv_ret:
    mov     rsp, rbp
    pop     rbp
    ret
imgview_proc endp

; move_ctl(rcx=hdlg, rdx=hwnd, r8d=dlux, r9d=dluy, [+48]=dluw, [+56]=dluh)
;   Map the DLU rect to pixels and MoveWindow the control.  No-op if hwnd=0.
move_ctl proc frame
    FRAME_PROLOG 112
    test    rdx, rdx
    jz      mvc_ret
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     dword ptr [rbp-48], r8d              ; rc.left = x
    mov     dword ptr [rbp-44], r9d              ; rc.top = y
    mov     eax, r8d
    add     eax, dword ptr [rbp+48]
    mov     dword ptr [rbp-40], eax              ; rc.right = x+w
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
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx              ; hdlg
    mov     dword ptr [rbp-36], 0                ; i
    mov     dword ptr [rbp-40], 30               ; y (ROW_TOP)
    mov     dword ptr [rbp-52], 0                ; show cmd (SW_HIDE)
    cmp     dword ptr [g_editmode], 0
    je      grl_havecmd
    mov     dword ptr [rbp-52], SW_SHOW
grl_havecmd:
grl_row:
    mov     eax, dword ptr [rbp-36]
    cmp     eax, dword ptr [g_field_count]
    jae     grl_done
    imul    eax, eax, DESCSZ
    lea     r10, [g_fields]
    add     r10, rax
    mov     qword ptr [rbp-32], r10              ; desc
    mov     eax, dword ptr [r10+FD_KIND]
    mov     dword ptr [rbp-44], 12               ; rowH
    mov     dword ptr [rbp-48], 11               ; valH
    cmp     eax, VF_NOTES
    jne     grl_chkimg
    mov     dword ptr [rbp-44], 40
    mov     dword ptr [rbp-48], 40
    jmp     grl_setyh
grl_chkimg:
    cmp     eax, VF_IMAGE
    jne     grl_chkfile
    mov     dword ptr [rbp-44], 60               ; image: thumbnail row
    jmp     grl_setyh
grl_chkfile:
    cmp     eax, VF_FILE
    jne     grl_chktotp
    mov     dword ptr [rbp-44], 74               ; file: thumbnail + name + buttons
    jmp     grl_setyh
grl_chktotp:
    cmp     eax, VF_TOTP
    jne     grl_setyh
    mov     dword ptr [rbp-44], 12               ; view mode: code + bar only (short)
    cmp     dword ptr [g_editmode], 0
    je      grl_setyh
    mov     dword ptr [rbp-44], 28               ; edit mode: key + code + bar (tall)
grl_setyh:
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
    ; label  (158, y, 44, 11)
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_LABEL*8]
    mov     r8d, 158
    mov     r9d, dword ptr [rbp-40]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 44, 11
    ; value  (206, y, 128, valH)
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_VALUE*8]
    mov     r8d, 206
    mov     r9d, dword ptr [rbp-40]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 128, dword ptr [rbp-48]
    ; reveal (338, y, 12, 12)
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_REVEAL*8]
    mov     r8d, 338
    mov     r9d, dword ptr [rbp-40]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 12, 12
    ; copy: secret -> right cluster (352,y); totp -> next to the live code (318,y+14)
    mov     r10, qword ptr [rbp-32]
    cmp     dword ptr [r10+FD_KIND], VF_TOTP
    je      grl_copytotp
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_COPY*8]
    mov     r8d, 352
    mov     r9d, dword ptr [rbp-40]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 12, 12
    jmp     grl_copydone
grl_copytotp:
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_COPY*8]
    mov     r8d, 318
    mov     r9d, dword ptr [rbp-40]
    add     r9d, dword ptr [rbp-56]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 16, 11
grl_copydone:
    ; totp code (206, y+off, 110, 11) + bar (206, y+off+11, 110, 2)
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_TCODE*8]
    mov     r8d, 206
    mov     r9d, dword ptr [rbp-40]
    add     r9d, dword ptr [rbp-56]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 110, 11
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_TBAR*8]
    mov     r8d, 206
    mov     r9d, dword ptr [rbp-40]
    add     r9d, dword ptr [rbp-56]
    add     r9d, 11
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 110, 2
    ; up/down/del  (368/382/396, y, 12, 11)
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_UP*8]
    mov     r8d, 368
    mov     r9d, dword ptr [rbp-40]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 12, 11
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_DOWN*8]
    mov     r8d, 382
    mov     r9d, dword ptr [rbp-40]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 12, 11
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_DEL*8]
    mov     r8d, 396
    mov     r9d, dword ptr [rbp-40]
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
    ; image row: thumbnail (206,y,120,58) + Import/Paste buttons (edit mode only)
    mov     r10, qword ptr [rbp-32]
    cmp     dword ptr [r10+FD_KIND], VF_IMAGE
    jne     grl_filelayout
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_THUMB*8]
    mov     r8d, 206
    mov     r9d, dword ptr [rbp-40]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 120, 58
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_IMPORT*8]
    mov     r8d, 330
    mov     r9d, dword ptr [rbp-40]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 34, 14
    mov     rcx, qword ptr [rbp-24]
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_PASTE*8]
    mov     r8d, 330
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 18
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 34, 14
    ; Import/Paste show only in edit mode
    mov     r10, qword ptr [rbp-32]
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_IMPORT*8]
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
    mov     r10, qword ptr [rbp-32]
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_PASTE*8]
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
    jmp     grl_advance
grl_filelayout:
    mov     r10, qword ptr [rbp-32]
    cmp     dword ptr [r10+FD_KIND], VF_FILE
    jne     grl_advance
    mov     rcx, qword ptr [rbp-24]                  ; thumbnail (206,y,100,58)
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_THUMB*8]
    mov     r8d, 206
    mov     r9d, dword ptr [rbp-40]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 100, 58
    mov     rcx, qword ptr [rbp-24]                  ; filename (206,y+60,100,11)
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_VALUE*8]
    mov     r8d, 206
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 60
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 100, 11
    mov     rcx, qword ptr [rbp-24]                  ; Choose (312,y,40,14)
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_IMPORT*8]
    mov     r8d, 312
    mov     r9d, dword ptr [rbp-40]
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 40, 14
    mov     rcx, qword ptr [rbp-24]                  ; Paste (312,y+16,40,14)
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_PASTE*8]
    mov     r8d, 312
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 16
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 40, 14
    mov     rcx, qword ptr [rbp-24]                  ; Open (312,y+32,40,14)
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_OPEN*8]
    mov     r8d, 312
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 32
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 40, 14
    mov     rcx, qword ptr [rbp-24]                  ; Save (312,y+48,40,14)
    mov     r10, qword ptr [rbp-32]
    mov     rdx, qword ptr [r10+FD_HANDLES+DS_EXPORT*8]
    mov     r8d, 312
    mov     r9d, dword ptr [rbp-40]
    add     r9d, 48
    WINCALL move_ctl, rcx, rdx, r8d, r9d, 40, 14
    ; Choose + Paste show only in edit mode
    mov     r10, qword ptr [rbp-32]
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_IMPORT*8]
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
    mov     r10, qword ptr [rbp-32]
    mov     rcx, qword ptr [r10+FD_HANDLES+DS_PASTE*8]
    mov     edx, dword ptr [rbp-52]
    call    ShowWindow
grl_advance:
    ; advance y
    mov     eax, dword ptr [rbp-40]
    add     eax, dword ptr [rbp-44]
    add     eax, 6
    mov     dword ptr [rbp-40], eax
    inc     dword ptr [rbp-36]
    jmp     grl_row
grl_done:
    mov     eax, dword ptr [rbp-40]              ; content bottom (DLU) for overflow checks
    mov     dword ptr [g_content_h], eax
    ; repaint the dialog bg so controls just hidden (e.g. the TOTP key in view
    ; mode) leave no ghost pixels behind
    WINCALL InvalidateRect, qword ptr [rbp-24], 0, 1
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
    mov     r9d, dword ptr [r10]                ; type
    mov     rcx, qword ptr [rbp-24]
    mov     edx, r9d
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
@@: cmp     ecx, 8
    jne     @F
    mov     edx, VF_IMAGE
    jmp     gpa_go
@@: cmp     ecx, 9
    jne     @F
    mov     edx, VF_FILE
    jmp     gpa_go
@@: mov     edx, VF_TEXT                        ; 7 = custom (empty label)
gpa_go:
    mov     rcx, qword ptr [rbp-24]
    call    gui_addfield_one
    FRAME_EPILOG
    ret
gui_palette_add endp

; gui_addfield_menu(rcx=hdlg) - popup the field-type palette at the cursor.
gui_addfield_menu proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    WINCALL CreatePopupMenu
    mov     qword ptr [rbp-32], rax
    test    rax, rax
    jz      gam_done
    WINCALL AppendMenuW, qword ptr [rbp-32], 0, 1, addr kl_user
    WINCALL AppendMenuW, qword ptr [rbp-32], 0, 2, addr kl_secret
    WINCALL AppendMenuW, qword ptr [rbp-32], 0, 3, addr kl_url
    WINCALL AppendMenuW, qword ptr [rbp-32], 0, 4, addr kl_email
    WINCALL AppendMenuW, qword ptr [rbp-32], 0, 5, addr kl_notes
    mov     dword ptr [rbp-40], 0               ; MF_STRING|MF_ENABLED
    call    gui_has_totp                        ; grey TOTP if one already exists (live rows)
    test    eax, eax
    jz      gam_totp
    mov     dword ptr [rbp-40], 1               ; MF_GRAYED
gam_totp:
    WINCALL AppendMenuW, qword ptr [rbp-32], dword ptr [rbp-40], 6, addr kl_totp
    WINCALL AppendMenuW, qword ptr [rbp-32], 0, 9, addr kl_file
    WINCALL AppendMenuW, qword ptr [rbp-32], 0, 7, addr pm_custom
    lea     rcx, [rbp-56]                        ; POINT
    call    GetCursorPos
    WINCALL SetForegroundWindow, qword ptr [rbp-24]
    WINCALL TrackPopupMenu, qword ptr [rbp-32], TPM_RETURNCMD or TPM_LEFTALIGN, \
            dword ptr [rbp-56], dword ptr [rbp-52], 0, qword ptr [rbp-24], 0
    mov     dword ptr [rbp-44], eax              ; chosen id
    WINCALL DestroyMenu, qword ptr [rbp-32]
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
    mov     rcx, qword ptr [rbp-24]           ; hide the runtime field rows too
    mov     edx, SW_HIDE
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
    call    theme_ctlcolor
    jmp     vp_ret
vp_tpaint:
    mov     rcx, qword ptr [rbp-8]
    call    theme_paint
    jmp     vp_ret
vp_terase:
    mov     rcx, r8
    mov     rdx, qword ptr [rbp-8]
    call    theme_erase
    jmp     vp_ret
vp_tdraw:
    mov     r10, r9
    mov     eax, dword ptr [r10+4]            ; DRAWITEMSTRUCT.CtlID
    cmp     eax, IDC_V_MTPM                   ; the TPM control = Fluent pill toggle
    je      vp_tdraw_toggle
    cmp     eax, IDC_DYN_BASE                 ; a runtime row's TOTP drain bar?
    jb      vp_tdraw_def
    mov     edx, eax
    sub     edx, IDC_DYN_BASE
    and     edx, DYN_SLOTS-1                  ; slot = (id-base) mod 8
    cmp     edx, DS_TBAR
    je      vp_tdraw_totp
    cmp     edx, DS_THUMB
    je      vp_tdraw_thumb
    jmp     vp_tdraw_def
vp_tdraw_thumb:
    mov     rcx, r9
    call    gui_img_drawthumb
    mov     eax, 1
    jmp     vp_ret
vp_tdraw_toggle:
    mov     rcx, r9
    mov     edx, dword ptr [g_tpm_want]
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
vp_init:
    mov     rax, qword ptr [rbp-8]            ; remember the window for the tray toggle
    mov     qword ptr [g_vaulthwnd], rax
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
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_V_SEARCH, EM_SETCUEBANNER, 1, addr cue_search
    mov     dword ptr [g_cur_idx], -1         ; no entry selected yet
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
    je      vp_refocus
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
    cmp     eax, IDC_DYN_BASE                 ; runtime row button (reveal/up/down/del)?
    jae     vp_dyn
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
    cmp     eax, IDC_V_REMOVE
    je      vp_remove
    cmp     eax, IDC_V_LOCK
    je      vp_lock
    cmp     eax, IDC_V_MENU
    je      vp_menu
    cmp     eax, IDC_V_MTPMINFO
    je      vp_tpminfo
    cmp     eax, IDC_V_MTPM
    je      vp_mtpm
    cmp     eax, IDCANCEL
    je      vp_lock
    xor     eax, eax
    jmp     vp_ret
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
vp_setdirty:
    cmp     dword ptr [g_loading], 0          ; ignore programmatic field loads
    jne     vp_handled
    mov     dword ptr [g_dirty], 1
    jmp     vp_handled
vp_searchchg:
    mov     rcx, qword ptr [rbp-8]            ; refilter the entry list on each keystroke
    call    gui_poplist
    jmp     vp_handled
vp_refocus:
    WINCALL InvalidateRect, qword ptr [rbp-8], 0, 1
    jmp     vp_handled
vp_menu:
    mov     rcx, qword ptr [rbp-8]
    call    gui_menu_toggle
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
    ; if editing the current entry with unsaved changes, save it first
    cmp     dword ptr [g_editmode], 0
    je      vl_load
    cmp     dword ptr [g_dirty], 0
    je      vl_load
    mov     eax, dword ptr [g_cur_idx]
    mov     dword ptr [rbp-24], eax          ; A = entry being edited
    mov     rcx, qword ptr [rbp-8]
    call    gui_commit                       ; removes A, appends -> A at end
    ; commit shifted indices: entries after A move down by one
    mov     eax, dword ptr [rbp-16]
    cmp     eax, dword ptr [rbp-24]
    jle     vl_resel
    dec     eax
    mov     dword ptr [rbp-16], eax
vl_resel:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, dword ptr [rbp-16]
    call    gui_lb_selbydata
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
    cmp     ecx, DS_PASTE
    je      vpd_paste
    cmp     ecx, DS_THUMB
    je      vpd_thumb
    cmp     ecx, DS_OPEN
    je      vpd_open
    cmp     ecx, DS_EXPORT
    je      vpd_export
    jmp     vp_handled
vpd_import:
    ; file rows choose any file; image rows use the image picker
    mov     dword ptr [rbp-16], eax             ; row
    mov     ecx, eax
    call    gui_desc
    cmp     dword ptr [rax+FD_KIND], VF_FILE
    jne     vpd_imgimp
    mov     edx, dword ptr [rbp-16]
    mov     rcx, qword ptr [rbp-8]
    call    gui_file_import
    jmp     vp_handled
vpd_imgimp:
    mov     edx, dword ptr [rbp-16]
    mov     rcx, qword ptr [rbp-8]
    call    gui_img_import
    jmp     vp_handled
vpd_open:
    mov     edx, eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_file_open
    jmp     vp_handled
vpd_export:
    mov     edx, eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_file_export
    jmp     vp_handled
vpd_paste:
    mov     edx, eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_img_paste
    jmp     vp_handled
vpd_thumb:
    mov     edx, eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_img_enlarge
    jmp     vp_handled
vpd_copy:
    mov     edx, eax
    mov     rcx, qword ptr [rbp-8]
    call    gui_row_copy
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
    ; save any unsaved edits to the current entry before adding a new one
    cmp     dword ptr [g_editmode], 0
    je      va_build
    cmp     dword ptr [g_dirty], 0
    je      va_build
    mov     rcx, qword ptr [rbp-8]
    call    gui_commit
va_build:
    ; new record = Title "New entry" + empty Username + empty Password
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
    mov     dword ptr [g_field_n], 3
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
    ; pencil toggles edit mode: enter (make fields editable) or save + leave
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
    cmp     dword ptr [g_dirty], 0
    je      ve_off
    mov     rcx, qword ptr [rbp-8]
    call    gui_commit
ve_off:
    mov     rcx, qword ptr [rbp-8]
    xor     edx, edx
    call    gui_set_editmode
    cmp     dword ptr [g_cur_idx], 0
    jl      vp_handled
    mov     rcx, qword ptr [rbp-8]
    mov     edx, dword ptr [g_cur_idx]
    call    gui_showdetail
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
    mov     rcx, qword ptr [rbp-8]
    call    gui_commit
    mov     rcx, qword ptr [rbp-8]            ; leave edit mode (hides the TOTP key etc.)
    xor     edx, edx
    call    gui_set_editmode
    cmp     dword ptr [g_cur_idx], 0
    jl      vp_handled
    mov     rcx, qword ptr [rbp-8]
    mov     edx, dword ptr [g_cur_idx]
    call    gui_showdetail
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
    cmp     dword ptr [g_dirty], 0           ; unsaved inline edits -> commit
    je      vp_lock_go
    mov     rcx, qword ptr [rbp-8]
    call    gui_commit
vp_lock_go:
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, CLIP_TIMER
    call    KillTimer
    mov     rcx, qword ptr [rbp-8]
    mov     edx, TOTP_TIMER
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

; gui_clrwbuf(rcx = wide buf, edx = count) - zero `count` wide chars.
gui_clrwbuf proc frame
    FRAME_PROLOG 32
    mov     eax, edx
    shl     eax, 1
    mov     edx, eax
    call    secure_zero
    FRAME_EPILOG
    ret
gui_clrwbuf endp

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
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_STRING, IDM_ABOUT, addr t_about
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_STRING, IDM_OPEN, addr mi_open
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_SEPARATOR, 0, 0
    WINCALL AppendMenuW, qword ptr [rbp-32], MF_STRING, IDM_EXIT, addr mi_exit
    WINCALL GetCursorPos, addr g_pt
    WINCALL SetForegroundWindow, qword ptr [rbp-24]
    WINCALL TrackPopupMenu, qword ptr [rbp-32], TPM_RIGHTBUTTON, dword ptr [g_pt], \
            dword ptr [g_pt+4], 0, qword ptr [rbp-24], 0
    WINCALL DestroyMenu, qword ptr [rbp-32]
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
    WINCALL DefWindowProcW, qword ptr [rbp-8], qword ptr [rbp-16], qword ptr [rbp-24], qword ptr [rbp-32]
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
    mov     dword ptr [rbp-20], 4000h       ; ICC_STANDARD_CLASSES (edit cue banners)
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
