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
extern RegDeleteValueW:proc
extern RegCloseKey:proc
extern SHGetFolderPathW:proc
extern GetEnvironmentVariableW:proc
extern CreateDirectoryW:proc

REG_SZ          equ 1
REG_BINARY      equ 3
REG_DWORD       equ 4
KEY_READ        equ 20019h
KEY_WRITE       equ 20006h
CSIDL_PERSONAL  equ 5

.data
align 2
; key/value names + filename suffix as raw UTF-16 (backslash = 5Ch)
cfg_subkey label word
    dw 'S','O','F','T','W','A','R','E', 5Ch, 'V','o','r','d','r', 0
tpm_subkey label word
    dw 'S','O','F','T','W','A','R','E', 5Ch, 'V','o','r','d','r', 5Ch
    dw 'T','P','M','-','U','n','l','o','c','k', 0
cfg_value label word
    dw 'v','a','u','l','t', 0
cfg_fname label word
    dw 5Ch,'v','a','u','l','t','.','v','o','r','d','r', 0
env_onedrive label word
    dw 'O','n','e','D','r','i','v','e', 0
onedrive_sub label word
    dw 5Ch,'V','o','r','d','r', 0
align 8
g_hklm  dq 080000002h            ; HKEY_LOCAL_MACHINE (as a clean 64-bit value)
g_hkcu  dq 080000001h            ; HKEY_CURRENT_USER

.data?
g_cfg_cb    dd ?                 ; RegGetValue/Set byte count
g_cfg_dw    dd ?                 ; REG_DWORD value scratch
g_cfg_khan  dq ?                 ; open key handle
align 2
cc_od       dw 1024 dup (?)      ; %OneDrive% root (cfg_classify_path scratch)
cc_docs     dw 1024 dup (?)      ; Documents root (cfg_classify_path scratch)

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
; reg_load_vault(rcx=dst wide, edx=cap chars, r8=*locked) -> eax = 1 if found
;   (HKLM>HKCU).  *locked = 1 when the path came from HKLM (admin policy), else
;   0.  *locked may be 0/NULL.
; ===========================================================================
public reg_load_vault
reg_load_vault proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx          ; dst
    mov     dword ptr [rbp-32], edx          ; cap (chars)
    mov     qword ptr [rbp-40], r8           ; *locked
    ; --- HKLM (policy) ---
    mov     rcx, qword ptr [g_hklm]
    lea     rdx, [cfg_value]
    mov     r8, qword ptr [rbp-24]
    mov     r9d, dword ptr [rbp-32]
    shl     r9d, 1
    call    reg_query_sz
    test    eax, eax
    jz      rlv_hkcu
    mov     rax, qword ptr [rbp-40]
    test    rax, rax
    jz      rlv_yes
    mov     dword ptr [rax], 1               ; HKLM -> locked
rlv_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
rlv_hkcu:
    mov     rax, qword ptr [rbp-40]
    test    rax, rax
    jz      rlv_hkcu_q
    mov     dword ptr [rax], 0               ; not locked
rlv_hkcu_q:
    mov     rcx, qword ptr [g_hkcu]
    lea     rdx, [cfg_value]
    mov     r8, qword ptr [rbp-24]
    mov     r9d, dword ptr [rbp-32]
    shl     r9d, 1
    call    reg_query_sz
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
; cfg_default_vault(rcx=dst wide) -> eax = 1/0.  Prefers a OneDrive-synced
;   location ("%OneDrive%\Vordr\vault.vordr", creating the Vordr folder) when
;   OneDrive is in use; otherwise falls back to "<Documents>\vault.vordr".
; ===========================================================================
public cfg_default_vault
cfg_default_vault proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    ; ---- prefer OneDrive if the %OneDrive% folder is configured -------------
    WINCALL GetEnvironmentVariableW, addr env_onedrive, qword ptr [rbp-24], 980
    test    eax, eax                         ; 0 = not set / error
    jz      cdv_docs
    cmp     eax, 980                          ; too long to fit -> use Documents
    jae     cdv_docs
    ; dst = "%OneDrive%"; append "\Vordr"
    mov     r8d, eax                          ; char count (zero-extended)
    mov     r11, qword ptr [rbp-24]
    lea     r10, [r11+r8*2]                   ; end (GetEnv returned char count)
    lea     r9, [onedrive_sub]
    xor     ecx, ecx
cdv_od_cpy:
    movzx   eax, word ptr [r9+rcx*2]
    mov     word ptr [r10+rcx*2], ax
    test    eax, eax
    jz      cdv_od_dir
    inc     ecx
    jmp     cdv_od_cpy
cdv_od_dir:
    WINCALL CreateDirectoryW, qword ptr [rbp-24], 0   ; ignore "already exists"
    mov     rcx, qword ptr [rbp-24]
    jmp     cdv_app                           ; append "\vault.vordr" to it
cdv_docs:
    WINCALL SHGetFolderPathW, 0, CSIDL_PERSONAL, 0, 0, qword ptr [rbp-24]
    test    eax, eax                         ; S_OK = 0
    jnz     cdv_fail
    mov     rcx, qword ptr [rbp-24]
cdv_app:
    ; find the terminating NUL of dst, then append "\vault.vordr"
    mov     r11, rcx
    xor     r8d, r8d
cdv_end:
    cmp     word ptr [r11+r8*2], 0
    je      cdv_app2
    inc     r8d
    jmp     cdv_end
cdv_app2:
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

; ===========================================================================
; cfg_path_prefix(rcx=path, rdx=prefix) -> eax = 1 if the wide path starts with
;   prefix (ASCII case-insensitive), else 0.  Leaf.
; ===========================================================================
cfg_path_prefix proc
    xor     r8d, r8d
cpp_l:
    movzx   eax, word ptr [rdx+r8*2]          ; prefix[i]
    test    eax, eax
    jz      cpp_yes                            ; prefix exhausted -> match
    movzx   r9d, word ptr [rcx+r8*2]          ; path[i]
    cmp     eax, 'A'                           ; fold prefix char
    jb      cpp_p2
    cmp     eax, 'Z'
    ja      cpp_p2
    add     eax, 32
cpp_p2:
    cmp     r9d, 'A'                           ; fold path char
    jb      cpp_cmp
    cmp     r9d, 'Z'
    ja      cpp_cmp
    add     r9d, 32
cpp_cmp:
    cmp     eax, r9d
    jne     cpp_no
    inc     r8d
    cmp     r8d, 1024
    jb      cpp_l
cpp_yes:
    mov     eax, 1
    ret
cpp_no:
    xor     eax, eax
    ret
cfg_path_prefix endp

; ===========================================================================
; cfg_classify_path(rcx=path wide) -> eax = 0 OneDrive / 1 Documents / 2 other.
;   Resolves the %OneDrive% and Documents roots and prefix-matches the path
;   (OneDrive wins when Documents is itself OneDrive-backed).
; ===========================================================================
public cfg_classify_path
cfg_classify_path proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx
    WINCALL GetEnvironmentVariableW, addr env_onedrive, addr cc_od, 1024
    test    eax, eax
    jz      ccp_docs
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [cc_od]
    call    cfg_path_prefix
    test    eax, eax
    jz      ccp_docs
    xor     eax, eax                           ; OneDrive
    FRAME_EPILOG
    ret
ccp_docs:
    WINCALL SHGetFolderPathW, 0, CSIDL_PERSONAL, 0, 0, addr cc_docs
    test    eax, eax
    jnz     ccp_other
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [cc_docs]
    call    cfg_path_prefix
    test    eax, eax
    jz      ccp_other
    mov     eax, 1                             ; Documents
    FRAME_EPILOG
    ret
ccp_other:
    mov     eax, 2
    FRAME_EPILOG
    ret
cfg_classify_path endp

; ===========================================================================
; TPM convenience-unlock blobs live under HKCU\SOFTWARE\Vordr\TPM-Unlock, one
; REG_BINARY value per vault (value name = the wide vault path, so existence can
; be checked before the vault header is read).  Replaces the old .tpm sidecars.
;
;   reg_tpm_set(rcx=value name, rdx=data, r8d=len) -> eax = 1/0
;   reg_tpm_get(rcx=value name, rdx=outbuf, r8d=cap) -> eax = bytes read (0=none)
;   reg_tpm_del(rcx=value name) -> eax = 1
; ===========================================================================
public reg_tpm_set
reg_tpm_set proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-24], rcx          ; value name
    mov     qword ptr [rbp-32], rdx          ; data
    mov     dword ptr [rbp-40], r8d          ; len
    WINCALL RegCreateKeyExW, qword ptr [g_hkcu], addr tpm_subkey, 0, 0, 0, \
            KEY_WRITE, 0, addr g_cfg_khan, 0
    test    eax, eax
    jnz     rts_fail
    WINCALL RegSetValueExW, qword ptr [g_cfg_khan], qword ptr [rbp-24], 0, \
            REG_BINARY, qword ptr [rbp-32], dword ptr [rbp-40]
    mov     dword ptr [rbp-48], eax
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
    cmp     dword ptr [rbp-48], 0
    jne     rts_fail
    mov     eax, 1
    FRAME_EPILOG
    ret
rts_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
reg_tpm_set endp

public reg_tpm_get
reg_tpm_get proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx          ; value name
    mov     qword ptr [rbp-32], rdx          ; outbuf
    mov     dword ptr [rbp-40], r8d          ; cap
    WINCALL RegOpenKeyExW, qword ptr [g_hkcu], addr tpm_subkey, 0, KEY_READ, \
            addr g_cfg_khan
    test    eax, eax
    jnz     rtg_no
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [g_cfg_cb], eax        ; cb in = cap
    WINCALL RegQueryValueExW, qword ptr [g_cfg_khan], qword ptr [rbp-24], 0, 0, \
            qword ptr [rbp-32], addr g_cfg_cb
    mov     dword ptr [rbp-48], eax
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
    cmp     dword ptr [rbp-48], 0
    jne     rtg_no
    mov     eax, dword ptr [g_cfg_cb]        ; bytes actually read
    FRAME_EPILOG
    ret
rtg_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
reg_tpm_get endp

public reg_tpm_del
reg_tpm_del proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx          ; value name
    WINCALL RegOpenKeyExW, qword ptr [g_hkcu], addr tpm_subkey, 0, KEY_WRITE, \
            addr g_cfg_khan
    test    eax, eax
    jnz     rtd_done
    WINCALL RegDeleteValueW, qword ptr [g_cfg_khan], qword ptr [rbp-24]
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
rtd_done:
    mov     eax, 1
    FRAME_EPILOG
    ret
reg_tpm_del endp

end
