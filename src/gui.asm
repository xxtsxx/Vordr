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
extern SetFocus:proc
extern SetDlgItemInt:proc
extern GetDlgItemInt:proc
extern GetFileAttributesW:proc
extern CreateDirectoryW:proc
extern ShowWindow:proc
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

OFN_OVERWRITEPROMPT equ 2
OFN_HIDEREADONLY    equ 4
OFN_PATHMUSTEXIST   equ 800h
OFN_FILEMUSTEXIST   equ 1000h
OFN_EXPLORER        equ 80000h

EBUF        equ 4096            ; wide chars per entry-field buffer

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
; control-id groups toggled when the settings overlay opens/closes
align 4
g_vault_ids label dword
    dd IDC_V_LIST, IDC_V_ADD, IDC_V_EDIT, IDC_V_REMOVE, IDC_V_TITLE
    dd IDC_V_USER, IDC_V_SECRET, IDC_V_REVEAL, IDC_V_COPY, IDC_V_URL
    dd IDC_V_NOTES, IDC_V_TKEY, IDC_V_TOTP, IDC_V_COPYTOTP, IDC_V_LOCK
    dd IDC_V_TOTPBAR, IDC_V_TKEYREVEAL
VAULT_ID_COUNT equ 17
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
align 2
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
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    WINCALL SendDlgItemMessageW, rcx, IDC_V_LIST, LB_RESETCONTENT, 0, 0
    call    vault_count
    mov     dword ptr [rbp-32], eax         ; count
    mov     qword ptr [rbp-40], 0           ; index
gp_loop:
    mov     rax, qword ptr [rbp-40]
    cmp     eax, dword ptr [rbp-32]
    jae     gp_done
    mov     rcx, rax
    lea     rdx, [rbp-48]                   ; &len
    call    vault_title_at                  ; rax = title ptr, [rbp-48] = len
    mov     rcx, rax
    mov     edx, dword ptr [rbp-48]
    lea     r8, [g_conv_w]
    mov     r9d, EBUF*2-1
    call    gui_towide
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_ADDSTRING, 0, addr g_conv_w
    inc     qword ptr [rbp-40]
    jmp     gp_loop
gp_done:
    FRAME_EPILOG
    ret
gui_poplist endp

; =============================================================================
; gui_showdetail(rcx = hdlg, edx = index) - fill the detail fields; secret is
;   captured into g_secret_w and shown masked.
; =============================================================================
gui_showdetail proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [g_revealed], 0
    mov     dword ptr [g_tkey_revealed], 0
    mov     eax, dword ptr [rbp-32]           ; track the entry being edited inline
    mov     dword ptr [g_cur_idx], eax
    mov     dword ptr [g_dirty], 0
    mov     dword ptr [g_loading], 1          ; suppress EN_CHANGE dirty while loading
    ; title / user / url / notes
    mov     rcx, qword ptr [rbp-32]
    mov     edx, VF_TITLE
    lea     r8, [rbp-48]
    call    vault_field_at
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_TITLE
    mov     r8, rax
    mov     r9d, dword ptr [rbp-48]
    call    gui_setfield
    mov     rcx, qword ptr [rbp-32]
    mov     edx, VF_USERNAME
    lea     r8, [rbp-48]
    call    vault_field_at
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_USER
    mov     r8, rax
    mov     r9d, dword ptr [rbp-48]
    call    gui_setfield
    mov     rcx, qword ptr [rbp-32]
    mov     edx, VF_URL
    lea     r8, [rbp-48]
    call    vault_field_at
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_URL
    mov     r8, rax
    mov     r9d, dword ptr [rbp-48]
    call    gui_setfield
    mov     rcx, qword ptr [rbp-32]
    mov     edx, VF_NOTES
    lea     r8, [rbp-48]
    call    vault_field_at
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_NOTES
    mov     r8, rax
    mov     r9d, dword ptr [rbp-48]
    call    gui_setfield
    ; secret -> editable password field (masked); keep g_secret_w for Copy
    mov     rcx, qword ptr [rbp-32]
    mov     edx, VF_SECRET
    lea     r8, [rbp-48]
    call    vault_field_at
    mov     rcx, rax
    mov     edx, dword ptr [rbp-48]
    lea     r8, [g_secret_w]
    mov     r9d, EBUF*2-1
    call    gui_towide
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_SECRET, addr g_secret_w
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_SECRET, EM_SETPASSWORDCHAR, SECRET_MASK, 0
    ; TOTP key -> editable field + arm the live code
    mov     rcx, qword ptr [rbp-32]
    mov     edx, VF_TOTP
    lea     r8, [rbp-48]
    call    vault_field_at
    mov     qword ptr [rbp-56], rax           ; key ptr (or NULL)
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_TKEY
    mov     r8, rax
    mov     r9d, dword ptr [rbp-48]
    call    gui_setfield
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_TKEY, EM_SETPASSWORDCHAR, SECRET_MASK, 0
    mov     rax, qword ptr [rbp-56]
    test    rax, rax
    jz      gsd_nototp
    mov     ecx, dword ptr [rbp-48]
    cmp     ecx, 256
    ja      gsd_nototp
    mov     dword ptr [g_totp_b32len], ecx
    mov     r11, rax                        ; src
    lea     r10, [g_totp_b32]               ; dst
    xor     r8d, r8d
gsd_b32cp:
    cmp     r8d, dword ptr [g_totp_b32len]
    jae     gsd_b32d
    mov     al, byte ptr [r11+r8]
    mov     byte ptr [r10+r8], al
    inc     r8d
    jmp     gsd_b32cp
gsd_b32d:
    mov     dword ptr [g_totp_on], 1
    mov     rcx, qword ptr [rbp-24]
    call    gui_totp_refresh
    WINCALL SetTimer, qword ptr [rbp-24], TOTP_TIMER, TOTP_MS, 0
    mov     dword ptr [g_loading], 0
    mov     dword ptr [g_dirty], 0
    FRAME_EPILOG
    ret
gsd_nototp:
    mov     dword ptr [g_totp_on], 0
    mov     dword ptr [g_totp_secs], 0
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-24]
    mov     edx, TOTP_TIMER
    call    KillTimer
    add     rsp, 32
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_TOTP, 0
    sub     rsp, 32                           ; redraw the (now empty) progress bar
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_TOTPBAR
    call    GetDlgItem
    add     rsp, 32
    WINCALL InvalidateRect, rax, 0, 1
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
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_TOTP, addr g_totp_disp_w
    call    totp_secs_left                  ; eax = seconds left (1..30)
    mov     dword ptr [g_totp_secs], eax
    mov     rcx, qword ptr [rbp-24]          ; redraw the progress bar
    mov     edx, IDC_V_TOTPBAR
    call    GetDlgItem
    WINCALL InvalidateRect, rax, 0, 1
    FRAME_EPILOG
    ret
gtr_bad:
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_TOTP, 0
gtr_done:
    FRAME_EPILOG
    ret
gui_totp_refresh endp

; gui_reveal(rcx = hdlg) - toggle the secret field between masked and revealed.
gui_reveal proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_revealed], 0
    jne     gr_hide
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_SECRET, EM_SETPASSWORDCHAR, 0, 0
    mov     dword ptr [g_revealed], 1
    jmp     gr_redraw
gr_hide:
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_SECRET, EM_SETPASSWORDCHAR, SECRET_MASK, 0
    mov     dword ptr [g_revealed], 0
gr_redraw:
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_SECRET
    call    GetDlgItem
    WINCALL InvalidateRect, rax, 0, 1
    FRAME_EPILOG
    ret
gui_reveal endp

; gui_reveal_tkey(rcx = hdlg) - toggle the TOTP key field between masked/revealed.
gui_reveal_tkey proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_tkey_revealed], 0
    jne     grt_hide
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_TKEY, EM_SETPASSWORDCHAR, 0, 0
    mov     dword ptr [g_tkey_revealed], 1
    jmp     grt_redraw
grt_hide:
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_TKEY, EM_SETPASSWORDCHAR, SECRET_MASK, 0
    mov     dword ptr [g_tkey_revealed], 0
grt_redraw:
    mov     rcx, qword ptr [rbp-24]
    mov     edx, IDC_V_TKEY
    call    GetDlgItem
    WINCALL InvalidateRect, rax, 0, 1
    FRAME_EPILOG
    ret
gui_reveal_tkey endp

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

; gui_readfields(rcx = hdlg) - read the inline detail edits into the g_e_* buffers.
gui_readfields proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_V_TITLE, addr g_e_title, 1024
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_V_USER, addr g_e_user, 1024
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_V_SECRET, addr g_e_secret, EBUF
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_V_URL, addr g_e_url, 1024
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_V_NOTES, addr g_e_notes, EBUF
    WINCALL GetDlgItemTextW, qword ptr [rbp-24], IDC_V_TKEY, addr g_e_totp, 256
    FRAME_EPILOG
    ret
gui_readfields endp

; gui_commit(rcx = hdlg) - write the inline edits back to the current entry
;   (replace in place by remove + append) and persist.  Reselects the entry.
gui_commit proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_cur_idx], 0
    jl      gco_done                          ; nothing selected
    mov     rcx, qword ptr [rbp-24]
    call    gui_readfields
    mov     ecx, dword ptr [g_cur_idx]
    call    vault_remove_at
    mov     rcx, qword ptr [rbp-24]
    call    gui_addsave                       ; append + reseal + repopulate
    call    vault_count
    test    eax, eax
    jz      gco_done
    dec     eax
    mov     dword ptr [g_cur_idx], eax
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_LIST, LB_SETCURSEL, \
            dword ptr [g_cur_idx], 0
gco_done:
    mov     dword ptr [g_dirty], 0
    FRAME_EPILOG
    ret
gui_commit endp

; gui_set_editmode(rcx=hdlg, edx=on) - 1 = detail fields editable (edit mode),
;   0 = read-only (view).  Toggles EM_SETREADONLY on the six fields and swaps
;   the toolbar pencil glyph for a check mark while editing.
gui_set_editmode proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [g_editmode], edx
    mov     eax, edx
    xor     eax, 1
    mov     dword ptr [rbp-40], eax           ; readonly = NOT on
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_TITLE,  EM_SETREADONLY, dword ptr [rbp-40], 0
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_USER,   EM_SETREADONLY, dword ptr [rbp-40], 0
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_SECRET, EM_SETREADONLY, dword ptr [rbp-40], 0
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_URL,    EM_SETREADONLY, dword ptr [rbp-40], 0
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_NOTES,  EM_SETREADONLY, dword ptr [rbp-40], 0
    WINCALL SendDlgItemMessageW, qword ptr [rbp-24], IDC_V_TKEY,   EM_SETREADONLY, dword ptr [rbp-40], 0
    lea     rax, [wb_edit]
    cmp     dword ptr [rbp-32], 0
    je      sem_glyph
    lea     rax, [wb_save]
sem_glyph:
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_EDIT, rax
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

; gui_menu_open(rcx=hdlg) - hide the vault content, reveal the settings overlay.
gui_menu_open proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_vault_ids]
    mov     r8d, VAULT_ID_COUNT
    mov     r9d, SW_HIDE
    call    gui_show_ids
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
    cmp     eax, IDC_V_TOTPBAR                ; the TOTP countdown = progress bar
    je      vp_tdraw_totp
    jmp     vp_tdraw_def
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
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_V_LOCK
    call    theme_attach
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_V_TOTP, WM_SETFONT, qword ptr [g_font_totp], 1
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
    mov     dword ptr [g_cur_idx], -1         ; no entry selected yet
    mov     dword ptr [g_dirty], 0
    mov     dword ptr [g_loading], 0
    mov     rcx, qword ptr [rbp-8]
    call    gui_poplist
    mov     rcx, qword ptr [rbp-8]            ; start in view mode (fields locked)
    xor     edx, edx
    call    gui_set_editmode
    mov     eax, 1
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
    cmp     eax, IDC_V_TITLE
    je      vp_setdirty
    cmp     eax, IDC_V_USER
    je      vp_setdirty
    cmp     eax, IDC_V_SECRET
    je      vp_setdirty
    cmp     eax, IDC_V_URL
    je      vp_setdirty
    cmp     eax, IDC_V_NOTES
    je      vp_setdirty
    cmp     eax, IDC_V_TKEY
    je      vp_setdirty
vp_cmd_disp:
    cmp     eax, IDC_V_LIST
    je      vp_list
    cmp     eax, IDC_V_REVEAL
    je      vp_reveal
    cmp     eax, IDC_V_TKEYREVEAL
    je      vp_reveal_tkey
    cmp     eax, IDC_V_COPY
    je      vp_copy
    cmp     eax, IDC_V_COPYTOTP
    je      vp_copytotp
    cmp     eax, IDC_V_ADD
    je      vp_add
    cmp     eax, IDC_V_EDIT
    je      vp_edit
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
    call    gui_lbsel
    cmp     eax, LB_ERR
    je      vp_handled
    mov     dword ptr [rbp-16], eax          ; B = newly clicked index
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
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_V_LIST, LB_SETCURSEL, dword ptr [rbp-16], 0
vl_load:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, dword ptr [rbp-16]
    call    gui_showdetail
    mov     rcx, qword ptr [rbp-8]            ; viewing another record -> view mode
    xor     edx, edx
    call    gui_set_editmode
    jmp     vp_handled
vp_reveal:
    mov     rcx, qword ptr [rbp-8]
    call    gui_reveal
    jmp     vp_handled
vp_reveal_tkey:
    mov     rcx, qword ptr [rbp-8]
    call    gui_reveal_tkey
    jmp     vp_handled
vp_copy:
    mov     rcx, qword ptr [rbp-8]
    lea     rdx, [g_secret_w]
    call    gui_copy
    jmp     vp_handled
vp_copytotp:
    mov     rcx, qword ptr [rbp-8]
    lea     rdx, [g_totp_code_w]
    call    gui_copy
    jmp     vp_handled
vp_add:
    ; save any unsaved edits to the current entry before adding a new one
    cmp     dword ptr [g_editmode], 0
    je      va_clear
    cmp     dword ptr [g_dirty], 0
    je      va_clear
    mov     rcx, qword ptr [rbp-8]
    call    gui_commit
va_clear:
    ; create a new entry (placeholder title) and edit it inline
    lea     rcx, [g_e_title]
    mov     edx, 1024
    call    gui_clrwbuf
    lea     rcx, [g_e_user]
    mov     edx, 1024
    call    gui_clrwbuf
    lea     rcx, [g_e_secret]
    mov     edx, EBUF
    call    gui_clrwbuf
    lea     rcx, [g_e_url]
    mov     edx, 1024
    call    gui_clrwbuf
    lea     rcx, [g_e_notes]
    mov     edx, EBUF
    call    gui_clrwbuf
    lea     rcx, [g_e_totp]
    mov     edx, 256
    call    gui_clrwbuf
    lea     r10, [wt_newentry]
    lea     r11, [g_e_title]
    xor     ecx, ecx
vpa_cp:
    mov     ax, word ptr [r10+rcx*2]
    mov     word ptr [r11+rcx*2], ax
    test    ax, ax
    jz      vpa_cpd
    inc     ecx
    jmp     vpa_cp
vpa_cpd:
    mov     rcx, qword ptr [rbp-8]
    call    gui_addsave
    call    vault_count
    test    eax, eax
    jz      vp_handled
    dec     eax
    mov     dword ptr [g_cur_idx], eax
    WINCALL SendDlgItemMessageW, qword ptr [rbp-8], IDC_V_LIST, LB_SETCURSEL, dword ptr [g_cur_idx], 0
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
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_USER, 0
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_SECRET, 0
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_URL, 0
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_NOTES, 0
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_TKEY, 0
    mov     dword ptr [g_totp_on], 0          ; stop the live auth-code refresh
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, TOTP_TIMER
    call    KillTimer
    add     rsp, 32
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_TOTP, 0
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
    je      twp_open
    cmp     eax, WM_LBUTTONDBLCLK
    je      twp_open
    cmp     eax, WM_RBUTTONUP
    je      twp_menu
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
