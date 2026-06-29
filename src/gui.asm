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

externdef g_cfg_in:qword
externdef g_cfg_pass:byte
externdef g_cfg_title:qword
externdef g_cfg_user:qword
externdef g_cfg_secret:qword
externdef g_cfg_url:qword
externdef g_cfg_notes:qword

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
extern MultiByteToWideChar:proc

; ---- constants ---------------------------------------------------------------
MB_OK               equ 0
MB_ICONERROR        equ 10h
MB_ICONINFORMATION  equ 40h
MB_YESNO            equ 4
MB_ICONQUESTION     equ 20h
IDYES               equ 6
IDOK                equ 1
IDCANCEL            equ 2

WM_CLOSE            equ 10h
WM_INITDIALOG       equ 110h
WM_COMMAND          equ 111h
LBN_SELCHANGE       equ 1
LB_ADDSTRING        equ 180h
LB_RESETCONTENT     equ 184h
LB_GETCURSEL        equ 188h
LB_ERR              equ -1

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
DLG_ENTRY    equ 300
IDC_E_TITLE  equ 301
IDC_E_USER   equ 302
IDC_E_SECRET equ 303
IDC_E_URL    equ 304
IDC_E_NOTES  equ 305

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
g_mask label word
    dw 2022h,2022h,2022h,2022h,2022h,2022h,2022h,2022h,0    ; eight bullets

.data?
align 8
g_hinst     dq ?
g_vpath_set dd ?
g_create    dd ?
g_revealed  dd ?
g_e_edit    dd ?
g_e_idx     dd ?
align 2
g_vpath     dw 1024 dup (?)        ; chosen vault path (wide, NUL-terminated)
g_pwbuf     dw 1024 dup (?)        ; password field (wide; wiped after use)
g_conv_w    dw EBUF*2 dup (?)      ; utf8 -> wide display scratch
g_secret_w  dw EBUF*2 dup (?)      ; current selected secret (wide) for reveal/copy
g_e_title   dw 1024 dup (?)
g_e_user    dw 1024 dup (?)
g_e_secret  dw EBUF dup (?)
g_e_url     dw 1024 dup (?)
g_e_notes   dw EBUF dup (?)
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
    ; create mode: build a fresh empty vault first
    cmp     dword ptr [g_create], 0
    je      gu_open
    call    do_init
    test    eax, eax
    jz      gu_open
    call    gui_wipepw
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [s_createfail]
    call    gui_status
    jmp     gu_done
gu_open:
    call    vault_unlock                    ; eax = 0 / EXIT_*
    mov     dword ptr [rbp-32], eax
    call    gui_wipepw
    cmp     dword ptr [rbp-32], 0
    jne     gu_fail
    ; success
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
    xor     eax, eax
    jmp     up_ret
up_init:
    mov     dword ptr [g_vpath_set], 0
    mov     dword ptr [g_create], 0
    mov     eax, 1
    jmp     up_ret
up_cmd:
    movzx   eax, r8w                        ; LOWORD(wParam) = control id
    cmp     eax, IDC_U_OPEN
    je      up_open
    cmp     eax, IDC_U_NEW
    je      up_new
    cmp     eax, IDC_U_UNLOCK
    je      up_unlock
    cmp     eax, IDCANCEL
    je      up_cancel
    xor     eax, eax
    jmp     up_ret
up_open:
    mov     rcx, qword ptr [rbp-8]
    xor     edx, edx
    call    gui_browse
    mov     eax, 1
    jmp     up_ret
up_new:
    mov     rcx, qword ptr [rbp-8]
    mov     edx, 1
    call    gui_browse
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
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx
    mov     dword ptr [g_revealed], 0
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
    ; secret -> g_secret_w (kept), display masked
    mov     rcx, qword ptr [rbp-32]
    mov     edx, VF_SECRET
    lea     r8, [rbp-48]
    call    vault_field_at
    mov     rcx, rax
    mov     edx, dword ptr [rbp-48]
    lea     r8, [g_secret_w]
    mov     r9d, EBUF*2-1
    call    gui_towide
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_SECRET, addr g_mask
    FRAME_EPILOG
    ret
gui_showdetail endp

; gui_reveal(rcx = hdlg) - toggle the secret field between masked and revealed.
gui_reveal proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    cmp     dword ptr [g_revealed], 0
    jne     gr_hide
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_SECRET, addr g_secret_w
    mov     dword ptr [g_revealed], 1
    jmp     gr_done
gr_hide:
    WINCALL SetDlgItemTextW, qword ptr [rbp-24], IDC_V_SECRET, addr g_mask
    mov     dword ptr [g_revealed], 0
gr_done:
    FRAME_EPILOG
    ret
gui_reveal endp

; gui_copy() - copy g_secret_w (NUL-terminated wide) to the clipboard.
gui_copy proc frame
    FRAME_PROLOG 64
    ; wide length (chars) incl NUL
    lea     r10, [g_secret_w]
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
    ; copy g_secret_w (chars) into the locked block
    mov     r11, rax                        ; dst
    lea     r10, [g_secret_w]               ; src
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
gc_done:
    FRAME_EPILOG
    ret
gui_copy endp

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
    lea     rcx, [g_e_secret]
    mov     edx, EBUF*2
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
    WINCALL MessageBoxW, qword ptr [rbp-24], addr s_full, addr t_err, <MB_OK or MB_ICONERROR>
    jmp     gas_done
@@: WINCALL MessageBoxW, qword ptr [rbp-24], addr s_notitle, addr t_err, <MB_OK or MB_ICONERROR>
    jmp     gas_done
gas_resealerr:
    WINCALL MessageBoxW, qword ptr [rbp-24], addr s_resealfail, addr t_err, <MB_OK or MB_ICONERROR>
gas_done:
    FRAME_EPILOG
    ret
gui_addsave endp

; gui_loadentry(rcx = hdlg, edx = index) - fill g_e_* from an existing entry
;   (for editing).
gui_loadentry proc frame
    FRAME_PROLOG 48
    mov     dword ptr [rbp-32], edx
    LOADF macro vftype, dstbuf
    mov     rcx, qword ptr [rbp-32]
    mov     edx, vftype
    lea     r8, [rbp-40]
    call    vault_field_at
    mov     rcx, rax
    mov     edx, dword ptr [rbp-40]
    lea     r8, [dstbuf]
    mov     r9d, lengthof dstbuf - 1
    call    gui_towide
    endm
    LOADF VF_TITLE,    g_e_title
    LOADF VF_USERNAME, g_e_user
    LOADF VF_SECRET,   g_e_secret
    LOADF VF_URL,      g_e_url
    LOADF VF_NOTES,    g_e_notes
    FRAME_EPILOG
    ret
gui_loadentry endp

; =============================================================================
; entry_proc - DLG_ENTRY (add/edit form).  Pre-fills from g_e_* on edit; on OK
;   reads the fields back into g_e_*.  rax = BOOL.
; =============================================================================
entry_proc proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    mov     qword ptr [rbp-8], rcx          ; hdlg
    cmp     rdx, WM_INITDIALOG
    je      ep_init
    cmp     rdx, WM_COMMAND
    je      ep_cmd
    xor     eax, eax
    jmp     ep_ret
ep_init:
    ; pre-fill the edit controls from g_e_* (empty buffers for "add")
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_E_TITLE
    lea     r8, [g_e_title]
    call    SetDlgItemTextW
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_E_USER
    lea     r8, [g_e_user]
    call    SetDlgItemTextW
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_E_SECRET
    lea     r8, [g_e_secret]
    call    SetDlgItemTextW
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_E_URL
    lea     r8, [g_e_url]
    call    SetDlgItemTextW
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDC_E_NOTES
    lea     r8, [g_e_notes]
    call    SetDlgItemTextW
    add     rsp, 32
    mov     eax, 1
    jmp     ep_ret
ep_cmd:
    movzx   eax, r8w
    cmp     eax, IDOK
    je      ep_ok
    cmp     eax, IDCANCEL
    je      ep_cancel
    xor     eax, eax
    jmp     ep_ret
ep_ok:
    ; read fields back into g_e_*
    GETF macro id, dstbuf, cap
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, id
    lea     r8, [dstbuf]
    mov     r9d, cap
    call    GetDlgItemTextW
    add     rsp, 32
    endm
    GETF IDC_E_TITLE,  g_e_title,  1024
    GETF IDC_E_USER,   g_e_user,   1024
    GETF IDC_E_SECRET, g_e_secret, EBUF
    GETF IDC_E_URL,    g_e_url,    1024
    GETF IDC_E_NOTES,  g_e_notes,  EBUF
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDOK
    call    EndDialog
    add     rsp, 32
    mov     eax, 1
    jmp     ep_ret
ep_cancel:
    sub     rsp, 32
    mov     rcx, qword ptr [rbp-8]
    mov     edx, IDCANCEL
    call    EndDialog
    add     rsp, 32
    mov     eax, 1
ep_ret:
    mov     rsp, rbp
    pop     rbp
    ret
entry_proc endp

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
    xor     eax, eax
    jmp     vp_ret
vp_init:
    mov     rcx, qword ptr [rbp-8]
    call    gui_poplist
    mov     eax, 1
    jmp     vp_ret
vp_cmd:
    movzx   eax, r8w                        ; control id
    mov     r10d, r8d
    shr     r10d, 16                        ; notification code
    cmp     eax, IDC_V_LIST
    je      vp_list
    cmp     eax, IDC_V_REVEAL
    je      vp_reveal
    cmp     eax, IDC_V_COPY
    je      vp_copy
    cmp     eax, IDC_V_ADD
    je      vp_add
    cmp     eax, IDC_V_EDIT
    je      vp_edit
    cmp     eax, IDC_V_REMOVE
    je      vp_remove
    cmp     eax, IDC_V_LOCK
    je      vp_lock
    cmp     eax, IDCANCEL
    je      vp_lock
    xor     eax, eax
    jmp     vp_ret
vp_list:
    cmp     r10d, LBN_SELCHANGE
    jne     vp_unhandled
    mov     rcx, qword ptr [rbp-8]
    call    gui_lbsel
    cmp     eax, LB_ERR
    je      vp_handled
    mov     rcx, qword ptr [rbp-8]
    mov     edx, eax
    call    gui_showdetail
    jmp     vp_handled
vp_reveal:
    mov     rcx, qword ptr [rbp-8]
    call    gui_reveal
    jmp     vp_handled
vp_copy:
    call    gui_copy
    jmp     vp_handled
vp_add:
    lea     rcx, [g_e_title]                ; clear the form buffers
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
    mov     dword ptr [g_e_edit], 0
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_ENTRY, qword ptr [rbp-8], addr entry_proc, 0
    cmp     rax, IDOK
    jne     vp_handled
    mov     rcx, qword ptr [rbp-8]
    call    gui_addsave
    jmp     vp_handled
vp_edit:
    mov     rcx, qword ptr [rbp-8]
    call    gui_lbsel
    cmp     eax, LB_ERR
    je      vp_handled
    mov     dword ptr [g_e_idx], eax
    mov     rcx, qword ptr [rbp-8]
    mov     edx, eax
    call    gui_loadentry
    mov     dword ptr [g_e_edit], 1
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_ENTRY, qword ptr [rbp-8], addr entry_proc, 0
    cmp     rax, IDOK
    jne     vp_handled
    mov     ecx, dword ptr [g_e_idx]        ; remove the old, append the edited
    call    vault_remove_at
    mov     rcx, qword ptr [rbp-8]
    call    gui_addsave
    jmp     vp_handled
vp_remove:
    mov     rcx, qword ptr [rbp-8]
    call    gui_lbsel
    cmp     eax, LB_ERR
    je      vp_handled
    mov     dword ptr [g_e_idx], eax
    WINCALL MessageBoxW, qword ptr [rbp-8], addr t_remove, addr t_err, <MB_YESNO or MB_ICONQUESTION>
    cmp     eax, IDYES
    jne     vp_handled
    mov     ecx, dword ptr [g_e_idx]
    call    vault_remove_at
    call    vault_reseal
    mov     rcx, qword ptr [rbp-8]
    call    gui_poplist
    ; clear detail (no selection)
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_TITLE, 0
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_USER, 0
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_SECRET, 0
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_URL, 0
    WINCALL SetDlgItemTextW, qword ptr [rbp-8], IDC_V_NOTES, 0
    jmp     vp_handled
vp_lock:
vp_close:
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
gui_main proc frame
    FRAME_PROLOG 32
    WINCALL GetModuleHandleW, 0
    mov     qword ptr [g_hinst], rax
gm_loop:
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_UNLOCK, 0, addr unlock_proc, 0
    cmp     rax, 1
    jne     gm_done                         ; cancelled -> exit
    WINCALL DialogBoxParamW, qword ptr [g_hinst], DLG_VAULT, 0, addr vault_proc, 0
    call    vault_lock                      ; wipe body + key on close
    jmp     gm_loop
gm_done:
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
