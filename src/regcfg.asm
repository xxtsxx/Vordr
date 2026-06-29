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

extern RegOpenKeyExW:proc
extern RegQueryValueExW:proc
extern RegCreateKeyExW:proc
extern RegSetValueExW:proc
extern RegCloseKey:proc
extern SHGetFolderPathW:proc

REG_SZ          equ 1
REG_DWORD       equ 4
KEY_READ        equ 20019h
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
g_cfg_dw    dd ?                 ; REG_DWORD value scratch
g_cfg_khan  dq ?                 ; open key handle

.code

; ===========================================================================
; reg_query_sz(rcx=hkey, rdx=value name, r8=dst, r9d=cap bytes) -> eax = 1 if
;   the SOFTWARE\Vordr value was read into dst, else 0.  Opens + queries +
;   closes the key (RegOpenKeyExW fails cleanly when the key is absent).
; ===========================================================================
reg_query_sz proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rcx          ; hkey
    mov     qword ptr [rbp-24], rdx          ; value name
    mov     qword ptr [rbp-32], r8           ; dst
    mov     dword ptr [rbp-40], r9d          ; cap bytes
    WINCALL RegOpenKeyExW, qword ptr [rbp-16], addr cfg_subkey, 0, KEY_READ, addr g_cfg_khan
    test    eax, eax
    jnz     qsz_no
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [g_cfg_cb], eax
    WINCALL RegQueryValueExW, qword ptr [g_cfg_khan], qword ptr [rbp-24], 0, 0, \
            qword ptr [rbp-32], addr g_cfg_cb
    mov     dword ptr [rbp-48], eax
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
    cmp     dword ptr [rbp-48], 0
    jne     qsz_no
    mov     eax, 1
    FRAME_EPILOG
    ret
qsz_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
reg_query_sz endp

; ===========================================================================
; reg_query_dw(rcx=hkey, rdx=value name, r8=*out dword) -> eax = 1 if read.
; ===========================================================================
reg_query_dw proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rcx          ; hkey
    mov     qword ptr [rbp-24], rdx          ; value name
    mov     qword ptr [rbp-32], r8           ; *out
    WINCALL RegOpenKeyExW, qword ptr [rbp-16], addr cfg_subkey, 0, KEY_READ, addr g_cfg_khan
    test    eax, eax
    jnz     qdw_no
    mov     dword ptr [g_cfg_cb], 4
    WINCALL RegQueryValueExW, qword ptr [g_cfg_khan], qword ptr [rbp-24], 0, 0, \
            addr g_cfg_dw, addr g_cfg_cb
    mov     dword ptr [rbp-40], eax
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
    cmp     dword ptr [rbp-40], 0
    jne     qdw_no
    mov     rax, qword ptr [rbp-32]
    mov     ecx, dword ptr [g_cfg_dw]
    mov     dword ptr [rax], ecx
    mov     eax, 1
    FRAME_EPILOG
    ret
qdw_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
reg_query_dw endp

; ===========================================================================
; cfg_get_dword(rcx=value name, edx=default, r8=*locked) -> eax = value.
;   HKLM wins (and sets *locked=1, since it is admin policy); else HKCU
;   (*locked=0); else the supplied default (*locked=0).  *locked may be 0/NULL.
; ===========================================================================
public cfg_get_dword
cfg_get_dword proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx          ; value name
    mov     dword ptr [rbp-32], edx          ; default
    mov     qword ptr [rbp-40], r8           ; *locked
    ; --- HKLM (policy) ---
    mov     rcx, qword ptr [g_hklm]
    mov     rdx, qword ptr [rbp-24]
    lea     r8, [g_cfg_dw]
    call    reg_query_dw
    test    eax, eax
    jz      cgd_hkcu
    mov     rax, qword ptr [rbp-40]
    test    rax, rax
    jz      cgd_hklm_val
    mov     dword ptr [rax], 1               ; locked = 1
cgd_hklm_val:
    mov     eax, dword ptr [g_cfg_dw]
    FRAME_EPILOG
    ret
cgd_hkcu:
    mov     rax, qword ptr [rbp-40]
    test    rax, rax
    jz      cgd_hkcu_q
    mov     dword ptr [rax], 0               ; not locked
cgd_hkcu_q:
    mov     rcx, qword ptr [g_hkcu]
    mov     rdx, qword ptr [rbp-24]
    lea     r8, [g_cfg_dw]
    call    reg_query_dw
    test    eax, eax
    jz      cgd_def
    mov     eax, dword ptr [g_cfg_dw]
    FRAME_EPILOG
    ret
cgd_def:
    mov     eax, dword ptr [rbp-32]
    FRAME_EPILOG
    ret
cfg_get_dword endp

; ===========================================================================
; cfg_set_dword_hkcu(rcx=value name, edx=value) -> eax = 1/0.
; ===========================================================================
public cfg_set_dword_hkcu
cfg_set_dword_hkcu proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     eax, edx
    mov     dword ptr [g_cfg_dw], eax
    WINCALL RegCreateKeyExW, qword ptr [g_hkcu], addr cfg_subkey, 0, 0, 0, \
            KEY_WRITE, 0, addr g_cfg_khan, 0
    test    eax, eax
    jnz     csd_fail
    WINCALL RegSetValueExW, qword ptr [g_cfg_khan], qword ptr [rbp-24], 0, \
            REG_DWORD, addr g_cfg_dw, 4
    mov     dword ptr [rbp-32], eax
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
    cmp     dword ptr [rbp-32], 0
    jne     csd_fail
    mov     eax, 1
    FRAME_EPILOG
    ret
csd_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
cfg_set_dword_hkcu endp

; ===========================================================================
; reg_load_vault(rcx=dst wide, edx=cap chars) -> eax = 1 if found (HKLM>HKCU).
; ===========================================================================
public reg_load_vault
reg_load_vault proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx          ; dst
    mov     dword ptr [rbp-32], edx          ; cap (chars)
    ; --- HKLM ---
    mov     rcx, qword ptr [g_hklm]
    lea     rdx, [cfg_value]
    mov     r8, qword ptr [rbp-24]
    mov     r9d, dword ptr [rbp-32]
    shl     r9d, 1
    call    reg_query_sz
    test    eax, eax
    jnz     rlv_done
    ; --- HKCU ---
    mov     rcx, qword ptr [g_hkcu]
    lea     rdx, [cfg_value]
    mov     r8, qword ptr [rbp-24]
    mov     r9d, dword ptr [rbp-32]
    shl     r9d, 1
    call    reg_query_sz
rlv_done:
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
