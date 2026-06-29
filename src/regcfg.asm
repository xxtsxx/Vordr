; =============================================================================
; regcfg.asm - per-machine / per-user vault location in the registry.
; -----------------------------------------------------------------------------
; The vault path is read from HKLM\SOFTWARE\Vordr  value "vault" first, then
; HKCU\SOFTWARE\Vordr  value "vault" (HKLM wins).  On a fresh install neither
; exists, so the GUI creates a default vault in the user's Documents folder and
; records its path under HKCU (which is user-writable, no elevation needed).
;
;   reg_load_vault(rcx=dst wide, edx=cap chars) -> eax = 1 if a path was found
;   reg_save_vault(rcx=wide path) -> eax = 1/0   (writes HKCU\SOFTWARE\Vordr)
;   cfg_default_vault(rcx=dst wide) -> eax = 1/0  (Documents\vault.vordr)
; =============================================================================

include macros.inc

extern RegGetValueW:proc
extern RegCreateKeyExW:proc
extern RegSetValueExW:proc
extern RegCloseKey:proc
extern SHGetFolderPathW:proc

RRF_RT_REG_SZ   equ 2
REG_SZ          equ 1
KEY_WRITE       equ 20006h
CSIDL_PERSONAL  equ 5

.data
align 2
; key/value names + filename suffix as raw UTF-16 (backslash = 5Ch)
cfg_subkey label word
    dw 'S','O','F','T','W','A','R','E', 5Ch, 'V','o','r','d','r', 0
cfg_value label word
    dw 'v','a','u','l','t', 0
cfg_fname label word
    dw 5Ch,'v','a','u','l','t','.','v','o','r','d','r', 0
align 8
g_hklm  dq 080000002h            ; HKEY_LOCAL_MACHINE (as a clean 64-bit value)
g_hkcu  dq 080000001h            ; HKEY_CURRENT_USER

.data?
g_cfg_cb    dd ?                 ; RegGetValue/Set byte count
g_cfg_khan  dq ?                 ; open key handle

.code

; ===========================================================================
; reg_load_vault(rcx=dst wide, edx=cap chars) -> eax = 1 if found (HKLM>HKCU).
; ===========================================================================
public reg_load_vault
reg_load_vault proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx          ; dst
    mov     dword ptr [rbp-32], edx          ; cap (chars)
    ; --- HKLM ---
    mov     eax, dword ptr [rbp-32]
    shl     eax, 1                           ; bytes
    mov     dword ptr [g_cfg_cb], eax
    WINCALL RegGetValueW, qword ptr [g_hklm], addr cfg_subkey, addr cfg_value, \
            RRF_RT_REG_SZ, 0, qword ptr [rbp-24], addr g_cfg_cb
    test    eax, eax
    jz      rlv_yes
    ; --- HKCU ---
    mov     eax, dword ptr [rbp-32]
    shl     eax, 1
    mov     dword ptr [g_cfg_cb], eax
    WINCALL RegGetValueW, qword ptr [g_hkcu], addr cfg_subkey, addr cfg_value, \
            RRF_RT_REG_SZ, 0, qword ptr [rbp-24], addr g_cfg_cb
    test    eax, eax
    jz      rlv_yes
    xor     eax, eax
    FRAME_EPILOG
    ret
rlv_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
reg_load_vault endp

; ===========================================================================
; reg_save_vault(rcx=wide path) -> eax = 1/0.  Writes HKCU\SOFTWARE\Vordr:vault.
; ===========================================================================
public reg_save_vault
reg_save_vault proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx          ; path
    WINCALL RegCreateKeyExW, qword ptr [g_hkcu], addr cfg_subkey, 0, 0, 0, \
            KEY_WRITE, 0, addr g_cfg_khan, 0
    test    eax, eax
    jnz     rsv_fail
    ; byte length incl NUL
    mov     r11, qword ptr [rbp-24]
    xor     r8d, r8d
rsv_len:
    cmp     word ptr [r11+r8*2], 0
    je      rsv_lend
    inc     r8d
    jmp     rsv_len
rsv_lend:
    inc     r8d
    shl     r8d, 1
    mov     dword ptr [g_cfg_cb], r8d
    WINCALL RegSetValueExW, qword ptr [g_cfg_khan], addr cfg_value, 0, REG_SZ, \
            qword ptr [rbp-24], dword ptr [g_cfg_cb]
    mov     dword ptr [rbp-32], eax
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
    cmp     dword ptr [rbp-32], 0
    jne     rsv_fail
    mov     eax, 1
    FRAME_EPILOG
    ret
rsv_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
reg_save_vault endp

; ===========================================================================
; cfg_default_vault(rcx=dst wide) -> eax = 1/0.  dst = "<Documents>\vault.vordr".
; ===========================================================================
public cfg_default_vault
cfg_default_vault proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    WINCALL SHGetFolderPathW, 0, CSIDL_PERSONAL, 0, 0, qword ptr [rbp-24]
    test    eax, eax                         ; S_OK = 0
    jnz     cdv_fail
    ; find the terminating NUL, then append "\vault.vordr"
    mov     r11, qword ptr [rbp-24]
    xor     r8d, r8d
cdv_end:
    cmp     word ptr [r11+r8*2], 0
    je      cdv_app
    inc     r8d
    jmp     cdv_end
cdv_app:
    lea     r10, [r11+r8*2]
    lea     r9, [cfg_fname]
    xor     ecx, ecx
cdv_cpy:
    movzx   eax, word ptr [r9+rcx*2]
    mov     word ptr [r10+rcx*2], ax
    test    eax, eax
    jz      cdv_done
    inc     ecx
    jmp     cdv_cpy
cdv_done:
    mov     eax, 1
    FRAME_EPILOG
    ret
cdv_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
cfg_default_vault endp

end
