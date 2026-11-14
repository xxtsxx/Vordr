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
;   cfg_default_vault(rcx=dst wide, edx=cap chars) -> eax = 1/0 (Documents\vault.vordr)
; =============================================================================

include macros.inc

extern RegOpenKeyExW:proc
extern RegQueryValueExW:proc
extern RegCreateKeyExW:proc
extern RegSetValueExW:proc
extern RegDeleteValueW:proc
extern RegCloseKey:proc
extern RegEnumKeyExW:proc
extern RegEnumValueW:proc               ; C6: enumerate values to prune legacy names
extern sha256_hash:proc                 ; C6: hash the per-vault value name
extern SHGetFolderPathW:proc
extern GetEnvironmentVariableW:proc
extern ExpandEnvironmentStringsW:proc   ; REG_EXPAND_SZ means expand it, not accept it
extern CreateDirectoryW:proc
extern CreateFileW:proc
extern CloseHandle:proc
extern OpenProcessToken:proc
extern GetUserProfileDirectoryW:proc
extern GetFinalPathNameByHandleW:proc
extern GetFullPathNameW:proc            ; reg_hash_name: one key per FILE, not per spelling
extern CharUpperBuffW:proc
extern path_longify:proc

REG_SZ          equ 1
REG_EXPAND_SZ   equ 2
REG_BINARY      equ 3
REG_DWORD       equ 4
KEY_READ        equ 20019h
KEY_WRITE       equ 20006h
KEY_RW          equ 2001Fh          ; KEY_READ or KEY_WRITE (enumerate + delete values)
CSIDL_PERSONAL  equ 5
OPEN_EXISTING   equ 3
FILE_SHARE_RWD      equ 7
FILE_FLAG_BACKUP_SEM equ 02000000h
; "\Vordr" (6) + "\vault.vordr" (12) + NUL, and the filename tail on its own.
; Both appends are bounded against the caller's capacity using these.
CDV_MIN_CHARS   equ 280        ; MAX_PATH (260) + the tail + slack
CDV_TAIL_CHARS  equ 19
CDV_FNAME_CHARS equ 13
CFG_EXPAND_CCH  equ 1024        ; expansion scratch, in wide chars incl. the NUL

.data
align 2
; key/value names + filename suffix as raw UTF-16 (backslash = 5Ch)
cfg_subkey label word
    dw 'S','O','F','T','W','A','R','E', 5Ch, 'V','o','r','d','r', 0
tpm_subkey label word
    dw 'S','O','F','T','W','A','R','E', 5Ch, 'V','o','r','d','r', 5Ch
    dw 'T','P','M','-','U','n','l','o','c','k', 0
ctr_subkey label word
    dw 'S','O','F','T','W','A','R','E', 5Ch, 'V','o','r','d','r', 5Ch
    dw 'R','o','l','l','b','a','c','k', 0
cfg_value label word
    dw 'v','a','u','l','t', 0
cfg_fname label word
    dw 5Ch,'v','a','u','l','t','.','v','o','r','d','r', 0
env_onedrive label word
    dw 'O','n','e','D','r','i','v','e', 0
onedrive_sub label word
    dw 5Ch,'V','o','r','d','r', 0
od_accounts label word
    dw 'S','O','F','T','W','A','R','E', 5Ch, 'M','i','c','r','o','s','o','f','t'
    dw 5Ch, 'O','n','e','D','r','i','v','e', 5Ch, 'A','c','c','o','u','n','t','s', 0
od_userfolder label word
    dw 'U','s','e','r','F','o','l','d','e','r', 0
pfx_hklm_up label word
    dw '%','U','S','E','R','P','R','O','F','I','L','E','%', 5Ch, 0
pfx_hklm_la label word
    dw '%','L','O','C','A','L','A','P','P','D','A','T','A','%', 5Ch, 0
pfx_hklm_ad label word
    dw '%','A','P','P','D','A','T','A','%', 5Ch, 0
sfx_hklm_la label word
    dw 5Ch,'A','p','p','D','a','t','a',5Ch,'L','o','c','a','l', 0
sfx_hklm_ad label word
    dw 5Ch,'A','p','p','D','a','t','a',5Ch,'R','o','a','m','i','n','g', 0
align 8
public g_hklm
g_hklm  dq 080000002h            ; HKEY_LOCAL_MACHINE (as a clean 64-bit value)
public g_hkcu                    ; gui_test_hooks (probeio/dbg) points it at a scratch key
g_hkcu  dq 080000001h            ; HKEY_CURRENT_USER

.data?
public g_allow_unc
g_allow_unc         dd ?         ; HKLM-only AllowUncVault policy (0 = block UNC/SMB)
public g_allow_screencap
g_allow_screencap   dd ?         ; AllowScreenCapture policy (0 = WDA_EXCLUDEFROMCAPTURE)
g_cfg_cb    dd ?                 ; RegGetValue/Set byte count
g_cfg_type  dd ?                 ; RegQueryValueExW value type (REG_SZ check)
g_cfg_dw    dd ?                 ; REG_DWORD value scratch
g_cfg_khan  dq ?                 ; open key handle
g_reg_hdig  db 32 dup (?)        ; C6: SHA-256(vault path), input to the name hash
align 2
g_reg_hname dw 33 dup (?)        ; C6: hashed reg value name = 32 hex chars + NUL
align 2
REG_NORM_CCH equ MAX_PATH_CHARS + 16
g_reg_lpath dw REG_NORM_CCH dup (?) ; path_longify scratch for reg_hash_name
g_reg_tmp   dw REG_NORM_CCH dup (?) ; reg_hash_name: the path with any \\?\ prefix removed
g_reg_norm  dw REG_NORM_CCH dup (?) ;   and then made absolute and upper-cased
align 2
g_prune_name dw 512 dup (?)      ; C6: RegEnumValueW value-name scratch (legacy prune)
align 2
g_cfg_expand dw CFG_EXPAND_CCH dup (?) ; REG_EXPAND_SZ expansion scratch (see reg_query_sz)
align 2
cc_od       dw 1024 dup (?)      ; %OneDrive% root (cfg_classify_path scratch)
cc_docs     dw 1024 dup (?)      ; Documents root (cfg_classify_path scratch)
; One name for the UserFolder buffer's size, so the cbData handed to the registry and
; the in-bounds NUL offset can never drift apart (they were two separate literals).
OD_UFBUF_CH    equ 1024
OD_UFBUF_BYTES equ OD_UFBUF_CH * 2
od_namebuf  dw 256 dup (?)       ; account subkey name (cfg_od_linked)
od_ufbuf    dw OD_UFBUF_CH dup (?) ; UserFolder value (cfg_od_linked)

.code

; ===========================================================================
; reg_hash_name(rcx = wide value name) -> rax = ptr to the hashed name (wide,
;   32 hex chars + NUL, in g_reg_hname).  The rollback mirror and TPM blob are
;   keyed per-vault; using the raw vault PATH as the value name leaks where the
;   user's vaults live.  Hashing it keeps a stable, fixed-length, non-identifying
;   name (SHA-256 of the path's UTF-16 bytes, first 128 bits, hex).  Get/set/del
;   all hash the same path, so they still agree.  (C6. Registry location leak.)
;   Clobbers volatiles; reads/writes g_reg_hdig / g_reg_hname.
; ===========================================================================
reg_hash_legacy proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-24], rcx             ; name ptr
    xor     r11d, r11d                          ; wcslen(name)
rhn_len:
    cmp     word ptr [rcx+r11*2], 0
    je      rhn_lend
    inc     r11d
    jmp     rhn_len
rhn_lend:
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [r11+r11]                      ; byte length = chars * 2
    lea     r8, [g_reg_hdig]
    call    sha256_hash
    ; hex-encode the first 16 digest bytes into g_reg_hname (wide)
    lea     r10, [g_reg_hdig]
    lea     r11, [g_reg_hname]
    xor     ecx, ecx
rhn_hex:
    movzx   eax, byte ptr [r10+rcx]
    mov     edx, eax                            ; high nibble
    shr     edx, 4
    cmp     edx, 10
    jb      rhn_hh
    add     edx, 'a'-10
    jmp     rhn_hp
rhn_hh:
    add     edx, '0'
rhn_hp:
    mov     word ptr [r11+rcx*4], dx
    mov     edx, eax                            ; low nibble
    and     edx, 0Fh
    cmp     edx, 10
    jb      rhn_lh
    add     edx, 'a'-10
    jmp     rhn_lp
rhn_lh:
    add     edx, '0'
rhn_lp:
    mov     word ptr [r11+rcx*4+2], dx
    inc     ecx
    cmp     ecx, 16
    jb      rhn_hex
    mov     word ptr [r11+64], 0                ; wide NUL after 32 hex chars
    lea     rax, [g_reg_hname]
    FRAME_EPILOG
    ret
reg_hash_legacy endp

; ===========================================================================
; reg_hash_name(rcx = vault path) -> rax = hashed value name for that FILE.
;   The rollback mirror and the TPM blob are looked up by this name, and it used to
;   hash the path exactly as spelled.  The same vault is spelled many ways - case,
;   "\\?\" once it passes 248 chars (cfg_in_set adds it), a relative name, a UNC
;   form - and each spelling had its own counter: the rollback tripwire was
;   bypassed by opening the file under another name, and a long path lost its TPM
;   enrolment.  Normalise first: strip the extended-length prefix, make it
;   absolute, upper-case it.  (Short 8.3 names and junctions still differ; the
;   mirror is a tripwire, not an access control.)  Readers fall back to the legacy
;   hash so existing entries keep working.
; ===========================================================================
; rhn_strip_prefix(rcx = wide src, rdx = wide dst) -> eax = chars written.
;   Strips leading "\\?\" or "\\.\" (and case-insensitive "\\?\UNC\" / "\\.\UNC\" -> "\\")
;   into dst, bounded by REG_NORM_CCH - 2.  Leaf.
rhn_strip_prefix proc
    mov     r11, rdx
    xor     r8d, r8d
    cmp     word ptr [rcx], 5Ch
    jne     rsp_copy
    cmp     word ptr [rcx+2], 5Ch
    jne     rsp_copy
    movzx   eax, word ptr [rcx+4]
    cmp     eax, '?'
    je      rsp_pfx4
    cmp     eax, '.'
    jne     rsp_copy
rsp_pfx4:
    cmp     word ptr [rcx+6], 5Ch
    jne     rsp_copy
    mov     r8d, 4                              ; "\\?\X:\..." or "\\.\X:\..." -> "X:\..."
    movzx   eax, word ptr [rcx+8]
    or      eax, 20h
    cmp     eax, 'u'
    jne     rsp_copy
    movzx   eax, word ptr [rcx+10]
    or      eax, 20h
    cmp     eax, 'n'
    jne     rsp_copy
    movzx   eax, word ptr [rcx+12]
    or      eax, 20h
    cmp     eax, 'c'
    jne     rsp_copy
    cmp     word ptr [rcx+14], 5Ch
    jne     rsp_copy
    mov     word ptr [r11], 5Ch                 ; "\\?\UNC\srv" -> "\\srv"
    add     r11, 2
    mov     r8d, 7
rsp_copy:
    xor     r9d, r9d
rsp_cl:
    mov     ax, word ptr [rcx+r8*2]
    mov     word ptr [r11+r9*2], ax
    test    ax, ax
    jz      rsp_done
    inc     r8d
    inc     r9d
    cmp     r9d, REG_NORM_CCH - 2
    jb      rsp_cl
    mov     word ptr [r11+r9*2], 0
rsp_done:
    lea     rax, [r11+r9*2]
    sub     rax, rdx
    shr     rax, 1
    ret
rhn_strip_prefix endp

public reg_hash_name
reg_hash_name proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    ; 1) Try handle-based canonicalisation (GetFinalPathNameByHandleW) so 8.3 short
    ;    names, directory junctions, symlinks, "\\.\", and case variants all map to
    ;    the exact same registry hash when the file exists.
    lea     rdx, [g_reg_lpath]
    mov     r8d, REG_NORM_CCH
    call    path_longify
    WINCALL CreateFileW, rax, 0, FILE_SHARE_RWD, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEM, 0
    cmp     rax, -1
    je      rhn2_lex
    mov     qword ptr [rbp-40], rax
    WINCALL GetFinalPathNameByHandleW, rax, addr g_reg_tmp, REG_NORM_CCH, 0
    mov     dword ptr [rbp-48], eax
    WINCALL CloseHandle, qword ptr [rbp-40]
    mov     eax, dword ptr [rbp-48]
    test    eax, eax
    jz      rhn2_lex
    cmp     eax, REG_NORM_CCH
    jae     rhn2_lex
    lea     rcx, [g_reg_tmp]
    lea     rdx, [g_reg_norm]
    call    rhn_strip_prefix
    test    eax, eax
    jz      rhn2_lex
    jmp     rhn2_upper
rhn2_lex:
    ; 2) File does not exist yet: strip "\\?\" / "\\.\" / "UNC\" and normalise lexically.
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [g_reg_tmp]
    call    rhn_strip_prefix
    WINCALL GetFullPathNameW, addr g_reg_tmp, REG_NORM_CCH, addr g_reg_norm, 0
    test    eax, eax
    jz      rhn2_asis
    cmp     eax, REG_NORM_CCH
    jb      rhn2_upper
rhn2_asis:                                      ; could not resolve: hash it as written
    mov     rcx, qword ptr [rbp-24]
    call    reg_hash_legacy
    FRAME_EPILOG
    ret
rhn2_upper:
    mov     dword ptr [rbp-32], eax
    WINCALL CharUpperBuffW, addr g_reg_norm, dword ptr [rbp-32]
    lea     rcx, [g_reg_norm]
    call    reg_hash_legacy
    FRAME_EPILOG
    ret
reg_hash_name endp

; reg_get_bin(rcx = subkey, rdx = value name, r8 = outbuf, r9d = cap) -> eax = bytes
;   read from HKCU\<subkey>, 0 if absent.
reg_get_bin proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    mov     dword ptr [rbp-40], r9d
    WINCALL RegOpenKeyExW, qword ptr [g_hkcu], rcx, 0, KEY_READ, addr g_cfg_khan
    test    eax, eax
    jnz     rgb_no
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [g_cfg_cb], eax
    WINCALL RegQueryValueExW, qword ptr [g_cfg_khan], qword ptr [rbp-24], 0, 0, \
            qword ptr [rbp-32], addr g_cfg_cb
    mov     dword ptr [rbp-48], eax
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
    cmp     dword ptr [rbp-48], 0
    jne     rgb_no
    mov     eax, dword ptr [g_cfg_cb]
    FRAME_EPILOG
    ret
rgb_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
reg_get_bin endp

; reg_get_either(rcx = subkey, rdx = vault path, r8 = outbuf, r9d = cap) -> eax =
;   bytes: under the normalised name, else under the legacy (as-spelled) one.
reg_get_either proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     dword ptr [rbp-48], r9d
    mov     rcx, rdx
    call    reg_hash_name
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, rax
    mov     r8, qword ptr [rbp-40]
    mov     r9d, dword ptr [rbp-48]
    call    reg_get_bin
    test    eax, eax
    jnz     rge_done
    mov     rcx, qword ptr [rbp-32]
    call    reg_hash_legacy
    mov     rcx, qword ptr [rbp-24]
    mov     rdx, rax
    mov     r8, qword ptr [rbp-40]
    mov     r9d, dword ptr [rbp-48]
    call    reg_get_bin
rge_done:
    FRAME_EPILOG
    ret
reg_get_either endp

; ===========================================================================
; reg_is_hashed(rcx = wide name) -> eax = 1 iff the name is exactly 32 lowercase
;   hex chars (the current value-name format), else 0.  Lets the prune below tell
;   a current hashed value name from a legacy raw-vault-path one.  Leaf.
; ===========================================================================
reg_is_hashed proc
    xor     r10d, r10d
rih_lp:
    movzx   eax, word ptr [rcx+r10*2]
    test    eax, eax
    je      rih_end
    cmp     eax, '0'
    jb      rih_no
    cmp     eax, '9'
    jbe     rih_next
    cmp     eax, 'a'
    jb      rih_no
    cmp     eax, 'f'
    ja      rih_no
rih_next:
    inc     r10d
    cmp     r10d, 33
    jb      rih_lp
    jmp     rih_no                              ; > 32 chars -> not our format
rih_end:
    cmp     r10d, 32
    jne     rih_no
    mov     eax, 1
    ret
rih_no:
    xor     eax, eax
    ret
reg_is_hashed endp

; ===========================================================================
; reg_prune_legacy(rcx = subkey label) - under HKCU\SOFTWARE\Vordr\<subkey>,
;   delete every value whose name is NOT the current 32-hex hashed form - i.e. a
;   legacy raw-vault-path value name from before C6, which leaks the vault
;   location.  Best-effort.  Enumerate at a moving index: on a kept (hashed)
;   value advance the index; on a deleted value the entries above shift down so
;   the same index now points at the next one - both cases make progress.
; ===========================================================================
reg_prune_legacy proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx             ; subkey label
    WINCALL RegOpenKeyExW, qword ptr [g_hkcu], qword ptr [rbp-24], 0, KEY_RW, addr g_cfg_khan
    test    eax, eax
    jnz     rpl_done                            ; absent -> nothing to prune
    mov     dword ptr [rbp-32], 0               ; enumeration index
rpl_loop:
    mov     dword ptr [g_cfg_cb], 512           ; cchName capacity (chars, incl NUL)
    WINCALL RegEnumValueW, qword ptr [g_cfg_khan], dword ptr [rbp-32], addr g_prune_name, \
            addr g_cfg_cb, 0, 0, 0, 0
    test    eax, eax
    jnz     rpl_close                           ; ERROR_NO_MORE_ITEMS / error -> stop
    lea     rcx, [g_prune_name]
    call    reg_is_hashed
    test    eax, eax
    jz      rpl_del
    inc     dword ptr [rbp-32]                  ; hashed -> keep, advance the index
    jmp     rpl_loop
rpl_del:
    WINCALL RegDeleteValueW, qword ptr [g_cfg_khan], addr g_prune_name
    jmp     rpl_loop                            ; deleted -> same index = next value
rpl_close:
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
rpl_done:
    FRAME_EPILOG
    ret
reg_prune_legacy endp

; ===========================================================================
; reg_prune_all() - prune legacy path-named values from both per-vault subkeys
;   (rollback mirror + TPM blob).  Called once per unlock so an install that
;   predates C6 has its leaked vault paths removed on first use.  (C6.)
; ===========================================================================
public reg_prune_all
reg_prune_all proc frame
    FRAME_PROLOG 32
    lea     rcx, [ctr_subkey]
    call    reg_prune_legacy
    lea     rcx, [tpm_subkey]
    call    reg_prune_legacy
    FRAME_EPILOG
    ret
reg_prune_all endp

; cfg_profile_dir(rcx = wide dst, edx = cap chars) -> eax = chars written (0 = error).
;   Resolves the current process token's profile root directly via
;   GetUserProfileDirectoryW (backed by HKLM\...\ProfileList\<SID>\ProfileImagePath),
;   so user-writable HKCU\...\User Shell Folders and %USERPROFILE% cannot redirect it.
cfg_profile_dir proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx             ; dst
    mov     dword ptr [rbp-24], edx             ; cap chars
    cmp     edx, 4
    jb      cpd_bad
    mov     qword ptr [rbp-32], 0               ; hTok
    WINCALL OpenProcessToken, -1, 8, addr rbp-32 ; GetCurrentProcess()=-1, TOKEN_QUERY=8
    test    eax, eax
    jz      cpd_bad
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [rbp-40], eax
    WINCALL GetUserProfileDirectoryW, qword ptr [rbp-32], qword ptr [rbp-16], addr rbp-40
    mov     dword ptr [rbp-44], eax
    WINCALL CloseHandle, qword ptr [rbp-32]
    cmp     dword ptr [rbp-44], 0
    je      cpd_bad
    mov     r10, qword ptr [rbp-16]
    mov     ecx, dword ptr [rbp-24]
    xor     r8d, r8d
cpd_len:
    cmp     word ptr [r10+r8*2], 0
    je      cpd_have
    inc     r8d
    cmp     r8d, ecx
    jb      cpd_len
    jmp     cpd_bad
cpd_have:
    test    r8d, r8d
    jz      cpd_bad
    cmp     r8d, 3
    jbe     cpd_ret
    cmp     word ptr [r10+r8*2-2], 5Ch
    jne     cpd_ret
    dec     r8d
    mov     word ptr [r10+r8*2], 0
cpd_ret:
    mov     eax, r8d
    FRAME_EPILOG
    ret
cpd_bad:
    xor     eax, eax
    FRAME_EPILOG
    ret
cfg_profile_dir endp

; cfg_expand_hklm(rcx = wide in/out dst, edx = cap chars) -> eax = 1 ok / 0 invalid.
;   Expands HKLM REG_EXPAND_SZ templates WITHOUT calling ExpandEnvironmentStringsW
;   (process env) or SHGetFolderPathW (HKCU User Shell Folders).  Only a single
;   leading "%USERPROFILE%\", "%LOCALAPPDATA%\", or "%APPDATA%\" token is permitted
;   and is anchored strictly to GetUserProfileDirectoryW (HKLM ProfileList\<SID>).
cfg_expand_hklm proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx             ; dst
    mov     dword ptr [rbp-32], edx             ; cap chars
    ; Check if any '%' exists at all; if none, accept literal path unchanged.
    xor     r8d, r8d
ceh_scan:
    movzx   eax, word ptr [rcx+r8*2]
    test    eax, eax
    jz      ceh_nopct
    cmp     eax, '%'
    je      ceh_match
    inc     r8d
    jmp     ceh_scan
ceh_nopct:
    mov     eax, 1
    FRAME_EPILOG
    ret
ceh_match:
    ; '%' appeared: must be at index 0 and match one of the 3 known folder prefixes
    test    r8d, r8d
    jnz     ceh_bad
    mov     qword ptr [rbp-56], 0               ; optional subfolder suffix ptr
    mov     dword ptr [rbp-60], 0               ; optional subfolder suffix chars
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [pfx_hklm_up]
    call    cfg_path_prefix
    test    eax, eax
    jz      ceh_try_la
    mov     dword ptr [rbp-44], 13              ; offset of trailing '\' in "%USERPROFILE%\"
    jmp     ceh_have_pfx
ceh_try_la:
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [pfx_hklm_la]
    call    cfg_path_prefix
    test    eax, eax
    jz      ceh_try_ad
    lea     rax, [sfx_hklm_la]
    mov     qword ptr [rbp-56], rax
    mov     dword ptr [rbp-60], 14              ; "\AppData\Local"
    mov     dword ptr [rbp-44], 14              ; offset of trailing '\' in "%LOCALAPPDATA%\"
    jmp     ceh_have_pfx
ceh_try_ad:
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [pfx_hklm_ad]
    call    cfg_path_prefix
    test    eax, eax
    jz      ceh_bad
    lea     rax, [sfx_hklm_ad]
    mov     qword ptr [rbp-56], rax
    mov     dword ptr [rbp-60], 16              ; "\AppData\Roaming"
    mov     dword ptr [rbp-44], 9               ; offset of trailing '\' in "%APPDATA%\"
ceh_have_pfx:
    ; Verify no remaining '%' exists in the tail after the prefix
    mov     rcx, qword ptr [rbp-24]
    mov     r8d, dword ptr [rbp-44]
    xor     r9d, r9d                            ; tail length (incl leading '\')
ceh_tail_chk:
    movzx   eax, word ptr [rcx+r8*2]
    test    eax, eax
    jz      ceh_resolve
    cmp     eax, '%'
    je      ceh_bad
    inc     r8d
    inc     r9d
    jmp     ceh_tail_chk
ceh_resolve:
    mov     dword ptr [rbp-48], r9d             ; tail chars (excl NUL)
    lea     rcx, [g_cfg_expand]
    mov     edx, CFG_EXPAND_CCH
    call    cfg_profile_dir
    test    eax, eax
    jz      ceh_bad
    mov     r8d, eax                            ; profile root chars (no trailing '\')
    add     eax, dword ptr [rbp-60]             ; + "\AppData\..." suffix chars
    add     eax, dword ptr [rbp-48]             ; + "\..." tail chars
    inc     eax                                 ; + NUL
    cmp     eax, CFG_EXPAND_CCH
    ja      ceh_bad
    cmp     eax, dword ptr [rbp-32]             ; <= caller cap chars?
    ja      ceh_bad
    ; Append optional subfolder suffix ("\AppData\Local" or "\AppData\Roaming")
    lea     r10, [g_cfg_expand]
    lea     r10, [r10+r8*2]
    mov     r11, qword ptr [rbp-56]
    test    r11, r11
    jz      ceh_app_tail
ceh_sfx:
    mov     ax, word ptr [r11]
    test    ax, ax
    jz      ceh_app_tail
    mov     word ptr [r10], ax
    add     r11, 2
    add     r10, 2
    jmp     ceh_sfx
ceh_app_tail:
    ; Append tail (from '\') onto g_cfg_expand cursor r10
    mov     r11, qword ptr [rbp-24]
    mov     ecx, dword ptr [rbp-44]
    lea     r11, [r11+rcx*2]
ceh_app:
    mov     ax, word ptr [r11]
    mov     word ptr [r10], ax
    add     r11, 2
    add     r10, 2
    test    ax, ax
    jnz     ceh_app
    ; Copy g_cfg_expand -> dst
    mov     r10, qword ptr [rbp-24]
    lea     r11, [g_cfg_expand]
    xor     r8d, r8d
ceh_out:
    mov     ax, word ptr [r11+r8*2]
    mov     word ptr [r10+r8*2], ax
    test    ax, ax
    jz      ceh_ok
    inc     r8d
    jmp     ceh_out
ceh_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
ceh_bad:
    mov     r10, qword ptr [rbp-24]
    mov     word ptr [r10], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
cfg_expand_hklm endp

; ===========================================================================
; reg_query_sz(rcx=hkey, rdx=value name, r8=dst, r9d=cap bytes) -> eax:
;   1  = valid non-empty string read into dst
;   0  = key or value absent (ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND)
;  -1  = value exists (or open failed abnormally) with invalid type/size/template
; ===========================================================================
reg_query_sz proc frame
    FRAME_PROLOG 112
    mov     qword ptr [rbp-16], rcx          ; hkey
    mov     qword ptr [rbp-24], rdx          ; value name
    mov     qword ptr [rbp-32], r8           ; dst
    mov     dword ptr [rbp-40], r9d          ; cap bytes
    cmp     r9d, 4                           ; need at least 1 wchar + NUL
    jb      qsz_bad
    WINCALL RegOpenKeyExW, qword ptr [rbp-16], addr cfg_subkey, 0, KEY_READ, addr g_cfg_khan
    test    eax, eax
    jz      qsz_opened
    cmp     eax, 2                           ; ERROR_FILE_NOT_FOUND
    je      qsz_absent
    cmp     eax, 3                           ; ERROR_PATH_NOT_FOUND
    je      qsz_absent
    jmp     qsz_bad
qsz_opened:
    mov     eax, dword ptr [rbp-40]
    mov     dword ptr [g_cfg_cb], eax
    WINCALL RegQueryValueExW, qword ptr [g_cfg_khan], qword ptr [rbp-24], 0, addr g_cfg_type, \
            qword ptr [rbp-32], addr g_cfg_cb
    mov     dword ptr [rbp-48], eax
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
    mov     eax, dword ptr [rbp-48]
    test    eax, eax
    jz      qsz_chktype
    cmp     eax, 2                           ; ERROR_FILE_NOT_FOUND -> value absent
    je      qsz_absent
    jmp     qsz_bad                          ; ERROR_MORE_DATA (234) etc. -> fail closed
qsz_chktype:
    cmp     dword ptr [g_cfg_type], REG_SZ
    je      qsz_term
    cmp     dword ptr [g_cfg_type], REG_EXPAND_SZ
    jne     qsz_bad
qsz_term:
    mov     ecx, dword ptr [rbp-40]             ; cap bytes
    mov     eax, dword ptr [g_cfg_cb]           ; bytes returned
    test    eax, 1                              ; odd byte count in UTF-16 -> reject
    jnz     qsz_bad
    cmp     eax, ecx
    ja      qsz_bad
    mov     r10, qword ptr [rbp-32]             ; dst
    je      qsz_exact_cap                       ; filled entire buffer: must already end in NUL
    mov     word ptr [r10+rax], 0               ; room for NUL at [rax] -> terminate cleanly
    jmp     qsz_chk_nonempty
qsz_exact_cap:
    cmp     word ptr [r10+rcx-2], 0             ; no room to append NUL: require trailing NUL
    jne     qsz_bad                             ;   (otherwise value would truncate!)
qsz_chk_nonempty:
    cmp     word ptr [r10], 0                   ; empty "" string -> invalid path
    je      qsz_bad
    cmp     dword ptr [g_cfg_type], REG_EXPAND_SZ
    jne     qsz_ok
    mov     ecx, dword ptr [rbp-40]
    shr     ecx, 1
    mov     dword ptr [rbp-56], ecx             ; dst capacity, chars
    ; HKLM policy strings MUST NOT expand user-controlled environment variables!
    mov     rax, qword ptr [rbp-16]
    cmp     rax, qword ptr [g_hklm]
    jne     qsz_exp_hkcu
    mov     rcx, qword ptr [rbp-32]
    mov     edx, dword ptr [rbp-56]
    call    cfg_expand_hklm
    test    eax, eax
    jz      qsz_bad
    jmp     qsz_ok
qsz_exp_hkcu:
    WINCALL ExpandEnvironmentStringsW, qword ptr [rbp-32], addr g_cfg_expand, CFG_EXPAND_CCH
    test    eax, eax
    jz      qsz_bad
    cmp     eax, CFG_EXPAND_CCH
    ja      qsz_bad
    cmp     eax, dword ptr [rbp-56]
    ja      qsz_bad
    mov     r10, qword ptr [rbp-32]
    lea     r11, [g_cfg_expand]
    xor     r8d, r8d
qsz_cpy:
    mov     cx, word ptr [r11+r8*2]
    mov     word ptr [r10+r8*2], cx
    test    cx, cx
    jz      qsz_ok
    inc     r8d
    cmp     r8d, dword ptr [rbp-56]
    jb      qsz_cpy
    jmp     qsz_bad
qsz_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
qsz_bad:
    cmp     dword ptr [rbp-40], 2
    jb      @F
    mov     r10, qword ptr [rbp-32]
    mov     word ptr [r10], 0
@@: mov     eax, -1
    FRAME_EPILOG
    ret
qsz_absent:
    xor     eax, eax
    FRAME_EPILOG
    ret
reg_query_sz endp

; ===========================================================================
; reg_query_dw(rcx=hkey, rdx=value name, r8=*out dword) -> eax:
;   1 = valid REG_DWORD, 0 = absent, -1 = present with invalid type/size.
; ===========================================================================
reg_query_dw proc frame
    FRAME_PROLOG 80
    mov     qword ptr [rbp-16], rcx          ; hkey
    mov     qword ptr [rbp-24], rdx          ; value name
    mov     qword ptr [rbp-32], r8           ; *out
    WINCALL RegOpenKeyExW, qword ptr [rbp-16], addr cfg_subkey, 0, KEY_READ, addr g_cfg_khan
    test    eax, eax
    jz      qdw_opened
    cmp     eax, 2                           ; ERROR_FILE_NOT_FOUND
    je      qdw_absent
    cmp     eax, 3                           ; ERROR_PATH_NOT_FOUND
    je      qdw_absent
    jmp     qdw_bad
qdw_opened:
    mov     dword ptr [g_cfg_cb], 4
    mov     dword ptr [g_cfg_type], 0
    WINCALL RegQueryValueExW, qword ptr [g_cfg_khan], qword ptr [rbp-24], 0, addr g_cfg_type, \
            addr g_cfg_dw, addr g_cfg_cb
    mov     dword ptr [rbp-40], eax
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
    mov     eax, dword ptr [rbp-40]
    test    eax, eax
    jz      qdw_chk
    cmp     eax, 2                           ; ERROR_FILE_NOT_FOUND
    je      qdw_absent
    jmp     qdw_bad
qdw_chk:
    cmp     dword ptr [g_cfg_type], REG_DWORD
    jne     qdw_bad
    cmp     dword ptr [g_cfg_cb], 4
    jne     qdw_bad
    mov     rax, qword ptr [rbp-32]
    mov     ecx, dword ptr [g_cfg_dw]
    mov     dword ptr [rax], ecx
    mov     eax, 1
    FRAME_EPILOG
    ret
qdw_bad:
    mov     eax, -1
    FRAME_EPILOG
    ret
qdw_absent:
    xor     eax, eax
    FRAME_EPILOG
    ret
reg_query_dw endp

; ===========================================================================
; cfg_get_dword(rcx=value name, edx=default, r8=*locked) -> eax = value.
;   HKLM wins (*locked=1); if HKLM has an invalid/corrupt policy value (-1),
;   fail closed (*locked=1, return safe default, NEVER consult HKCU).
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
    cmp     eax, -1
    je      cgd_hklm_bad
    mov     rax, qword ptr [rbp-40]
    test    rax, rax
    jz      cgd_hklm_val
    mov     dword ptr [rax], 1               ; locked = 1
cgd_hklm_val:
    mov     eax, dword ptr [g_cfg_dw]
    FRAME_EPILOG
    ret
cgd_hklm_bad:
    mov     rax, qword ptr [rbp-40]
    test    rax, rax
    jz      cgd_def
    mov     dword ptr [rax], 1               ; locked = 1 (do NOT fall back to HKCU)
    jmp     cgd_def
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
    cmp     eax, 1
    jne     cgd_def
    mov     eax, dword ptr [g_cfg_dw]
    FRAME_EPILOG
    ret
cgd_def:
    mov     eax, dword ptr [rbp-32]
    FRAME_EPILOG
    ret
cfg_get_dword endp

; ===========================================================================
; cfg_get_dword_hklm(rcx=value name, edx=default) -> eax = value.
;   Strictly machine-policy only: queries HKLM\SOFTWARE\Vordr and NEVER
;   consults HKCU (prevents user-hive escalation on policies like AllowUncVault).
; ===========================================================================
public cfg_get_dword_hklm
cfg_get_dword_hklm proc frame
    FRAME_PROLOG 32
    mov     dword ptr [rbp-16], edx          ; default
    mov     rdx, rcx                         ; value name
    mov     rcx, qword ptr [g_hklm]
    lea     r8, [g_cfg_dw]
    call    reg_query_dw
    cmp     eax, 1
    jne     cgdh_def
    mov     eax, dword ptr [g_cfg_dw]
    FRAME_EPILOG
    ret
cgdh_def:
    mov     eax, dword ptr [rbp-16]
    FRAME_EPILOG
    ret
cfg_get_dword_hklm endp

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
    cmp     eax, -1
    je      rlv_hklm_bad                     ; invalid HKLM policy: lock & refuse HKCU
    mov     rax, qword ptr [rbp-40]
    test    rax, rax
    jz      rlv_yes
    mov     dword ptr [rax], 1               ; HKLM -> locked
rlv_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
rlv_hklm_bad:
    mov     rax, qword ptr [rbp-40]
    test    rax, rax
    jz      rlv_no
    mov     dword ptr [rax], 1               ; HKLM policy present -> locked
    jmp     rlv_no
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
    cmp     eax, 1
    je      rlv_yes
rlv_no:
    cmp     dword ptr [rbp-32], 1
    jb      @F
    mov     r10, qword ptr [rbp-24]
    mov     word ptr [r10], 0
@@: xor     eax, eax
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

; cfg_wstr_ieq(rcx = a wide, rdx = b wide) -> eax = 1 if equal, case-folded
;   (ASCII A-Z only, enough for filesystem paths).  Leaf proc.
cfg_wstr_ieq proc
cieq_lp:
    movzx   eax, word ptr [rcx]
    movzx   r10d, word ptr [rdx]
    lea     r11d, [rax-'A']
    cmp     r11d, 25
    ja      @F
    add     eax, 32
@@: lea     r11d, [r10-'A']
    cmp     r11d, 25
    ja      @F
    add     r10d, 32
@@: cmp     eax, r10d
    jne     cieq_ne
    test    eax, eax
    jz      cieq_eq
    add     rcx, 2
    add     rdx, 2
    jmp     cieq_lp
cieq_eq:
    mov     eax, 1
    ret
cieq_ne:
    xor     eax, eax
    ret
cfg_wstr_ieq endp

; ===========================================================================
; cfg_od_linked(rcx = %OneDrive% root wide) -> eax = 1 if OneDrive is actually
;   IN USE here, else 0.  "In use" = some account under
;   HKCU\SOFTWARE\Microsoft\OneDrive\Accounts carries a UserFolder value that
;   matches the env-var root.  A dormant OneDrive (the env var exists on every
;   Win11 box, but the sync client was never linked) leaves only stub account
;   keys with no UserFolder value - and writing into such a folder can wake the
;   sync client (logon prompts, placeholder weirdness), so it must not be
;   trusted with the vault.
; ===========================================================================
cfg_od_linked proc frame
    FRAME_PROLOG 144                         ; locals to -80 + spill room for the
                                           ;  8-arg RegEnumKeyExW (args 5+ land at
                                           ;  [rbp-alloc+32..] - must not overlap
                                           ;  the live in-out params)
    mov     qword ptr [rbp-24], rcx              ; candidate root
    mov     dword ptr [rbp-32], 0                ; enum index
    WINCALL RegOpenKeyExW, qword ptr [g_hkcu], addr od_accounts, 0, KEY_READ, addr g_cfg_khan
    test    eax, eax
    jnz     col_no                               ; no Accounts key -> not in use
col_enum:
    mov     dword ptr [rbp-48], 255              ; cch name (in chars, in/out)
    WINCALL RegEnumKeyExW, qword ptr [g_cfg_khan], dword ptr [rbp-32], addr od_namebuf, \
            addr rbp-48, 0, 0, 0, 0
    test    eax, eax
    jnz     col_close                            ; no more accounts
    WINCALL RegOpenKeyExW, qword ptr [g_cfg_khan], addr od_namebuf, 0, KEY_READ, addr rbp-56
    test    eax, eax
    jnz     col_next
    mov     dword ptr [rbp-72], OD_UFBUF_BYTES   ; cbData = the whole buffer
    WINCALL RegQueryValueExW, qword ptr [rbp-56], addr od_userfolder, 0, addr rbp-64, \
            addr od_ufbuf, addr rbp-72
    mov     dword ptr [rbp-80], eax
    WINCALL RegCloseKey, qword ptr [rbp-56]
    cmp     dword ptr [rbp-80], 0
    jne     col_next                             ; stub account: no UserFolder
    ; Same two guards cfg_get_str applies, and for the same reasons - this path had
    ; neither, then handed the buffer straight to cfg_wstr_ieq, which scans to a NUL
    ; with no bound.
    ; 1) the value must be a string type: other types carry bytes that are not wide-Z.
    mov     eax, dword ptr [rbp-64]              ; value type
    cmp     eax, REG_SZ
    je      col_term
    cmp     eax, REG_EXPAND_SZ
    jne     col_next
col_term:
    ; 2) RegQueryValueExW does not guarantee a terminating NUL, and none fits when the
    ;    value exactly fills the buffer - which is precisely the 1024-wchar case here.
    mov     eax, dword ptr [rbp-72]              ; bytes returned
    cmp     eax, OD_UFBUF_BYTES-2
    jbe     @F
    mov     eax, OD_UFBUF_BYTES-2                ; last in-bounds wide-NUL offset
@@: and     eax, 0FFFFFFFEh                      ; align to a wchar boundary
    lea     r10, [od_ufbuf]
    mov     word ptr [r10+rax], 0
    lea     rcx, [od_ufbuf]
    mov     rdx, qword ptr [rbp-24]
    call    cfg_wstr_ieq
    test    eax, eax
    jz      col_next
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]  ; linked account for this root
    mov     eax, 1
    FRAME_EPILOG
    ret
col_next:
    inc     dword ptr [rbp-32]
    jmp     col_enum
col_close:
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
col_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
cfg_od_linked endp

; ===========================================================================
; cfg_default_vault(rcx=dst wide) -> eax = 1/0.  Prefers a OneDrive-synced
;   location ("%OneDrive%\Vordr\vault.vordr", creating the Vordr folder) when
;   OneDrive is actually linked on this machine (cfg_od_linked); otherwise
;   falls back to "<Documents>\Vordr\vault.vordr".
; ===========================================================================
public cfg_default_vault
; The capacity used to be implicit: the proc appended "\Vordr" and
; "\vault.vordr" to whatever it had built and trusted the caller to have passed
; something big enough.  Both callers do pass 1024 chars, so nothing was wrong -
; but the contract lived only in the callers' heads, and a third caller with a
; smaller buffer would have overflowed silently.  It is now a parameter, every
; append is bounded by it, and a buffer too small to hold a path is refused
; rather than half-filled.
cfg_default_vault proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rcx
    mov     dword ptr [rbp-32], edx           ; capacity, wide chars incl. the NUL
    cmp     edx, CDV_MIN_CHARS                ; SHGetFolderPathW below writes up to
    jb      cdv_no                            ;   MAX_PATH regardless of what we
                                              ;   want, so a buffer that cannot
                                              ;   hold MAX_PATH + the tail is
                                              ;   refused before anything writes
    ; ---- prefer OneDrive if the %OneDrive% folder is configured -------------
    ; leave room for the longest tail this proc appends: "\Vordr" + "\vault.vordr"
    mov     eax, dword ptr [rbp-32]
    sub     eax, CDV_TAIL_CHARS
    mov     dword ptr [rbp-40], eax           ; the most the env var may occupy
    WINCALL GetEnvironmentVariableW, addr env_onedrive, qword ptr [rbp-24], dword ptr [rbp-40]
    test    eax, eax                         ; 0 = not set / error
    jz      cdv_docs
    cmp     eax, dword ptr [rbp-40]           ; too long to fit -> use Documents
    jae     cdv_docs
    ; the env var alone is not enough: require a linked sync account too,
    ; otherwise a dormant OneDrive would capture the vault
    mov     rcx, qword ptr [rbp-24]
    call    cfg_od_linked
    test    eax, eax
    jz      cdv_docs
    ; dst = "%OneDrive%"; append "\Vordr" + the filename through the shared tail.
    ;
    ; This used to take the append offset from eax, commented "char count" - but eax
    ; here holds cfg_od_linked's 1/0 result, NOT the length GetEnvironmentVariableW
    ; returned.  So "\Vordr" was written at character index 1 and
    ; "C:\Users\<user>\OneDrive" became "C\Vordr" - a RELATIVE path, which then
    ; resolved against the process's current directory.  The vault appeared next to
    ; vordr.exe and followed it when the exe was moved, the stray "C" folder being the
    ; first character of "C:\".  Only machines where OneDrive is actually linked ever
    ; reach this line, which is why it reproduced on one box and not another.
    ;
    ; The length is not needed at all: the shared tail scans for the NUL, exactly as
    ; the Documents and %USERPROFILE% paths do.
    mov     r11, qword ptr [rbp-24]
    xor     r8d, r8d
    jmp     cdv_docs_end
cdv_docs:
    WINCALL SHGetFolderPathW, 0, CSIDL_PERSONAL, 0, 0, qword ptr [rbp-24]
    test    eax, eax                         ; S_OK = 0
    jnz     cdv_profile                      ; no Documents -> %USERPROFILE%, never nothing
    ; dst = "<Documents>"; append "\Vordr" and create it, mirroring OneDrive
    mov     r11, qword ptr [rbp-24]
    xor     r8d, r8d
cdv_docs_end:
    cmp     word ptr [r11+r8*2], 0
    je      cdv_docs_sub
    inc     r8d
    jmp     cdv_docs_end
cdv_docs_sub:
    mov     eax, dword ptr [rbp-32]           ; room left after the prefix?
    sub     eax, CDV_TAIL_CHARS
    cmp     r8d, eax
    jae     cdv_no
    lea     r10, [r11+r8*2]
    lea     r9, [onedrive_sub]                ; "\Vordr"
    xor     ecx, ecx
cdv_docs_cpy:
    movzx   eax, word ptr [r9+rcx*2]
    mov     word ptr [r10+rcx*2], ax
    test    eax, eax
    jz      cdv_docs_dir
    inc     ecx
    jmp     cdv_docs_cpy
cdv_docs_dir:
    WINCALL CreateDirectoryW, qword ptr [rbp-24], 0   ; ignore "already exists"
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
    mov     eax, dword ptr [rbp-32]
    sub     eax, CDV_FNAME_CHARS
    cmp     r8d, eax
    jae     cdv_no
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
cdv_no:
    mov     r10, qword ptr [rbp-24]           ; never hand back a half-built path
    mov     word ptr [r10], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
cdv_profile:
    ; Last resort, so this can never come back empty-handed.  Resolve the token's
    ; HKLM ProfileList directory rather than %USERPROFILE% from the environment.
    mov     rcx, qword ptr [rbp-24]
    mov     edx, dword ptr [rbp-40]
    call    cfg_profile_dir
    test    eax, eax
    jz      cdv_fail
    mov     r11, qword ptr [rbp-24]
    xor     r8d, r8d
    jmp     cdv_docs_end                     ; shared subfolder + filename tail
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
    cmp     eax, 1024
    jae     ccp_docs
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
    mov     qword ptr [rbp-32], rdx          ; data (saved before reg_hash_name)
    mov     dword ptr [rbp-40], r8d          ; len
    call    reg_hash_name                    ; rcx=path -> rax=hashed value name (C6)
    mov     qword ptr [rbp-24], rax
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
    FRAME_PROLOG 32
    mov     r9d, r8d                         ; cap
    mov     r8, rdx                          ; outbuf
    mov     rdx, rcx                         ; vault path
    lea     rcx, [tpm_subkey]
    call    reg_get_either
    FRAME_EPILOG
    ret
reg_tpm_get endp

public reg_tpm_del
reg_tpm_del proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-32], rcx          ; vault path
    call    reg_hash_name                    ; normalised name
    mov     rdx, rax
    call    rtd_one
    mov     rcx, qword ptr [rbp-32]          ; and the legacy (as-spelled) one, so
    call    reg_hash_legacy                  ;   "forget this device" really forgets
    mov     rdx, rax
    call    rtd_one
    mov     eax, 1
    FRAME_EPILOG
    ret
reg_tpm_del endp

; rtd_one(rdx = hashed value name) - delete it under HKCU\..\TPM-Unlock.
rtd_one proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rdx
    WINCALL RegOpenKeyExW, qword ptr [g_hkcu], addr tpm_subkey, 0, KEY_WRITE, \
            addr g_cfg_khan
    test    eax, eax
    jnz     rto_done
    WINCALL RegDeleteValueW, qword ptr [g_cfg_khan], qword ptr [rbp-24]
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
rto_done:
    FRAME_EPILOG
    ret
rtd_one endp

; ===========================================================================
; Anti-rollback counter mirror: last-seen save_counter per vault path,
; under HKCU\...\Vordr\Rollback.  A user-writable mirror is only a tripwire (an
; attacker who can restore an old vault can usually also clear this), but it
; reliably catches accidental restores and sync mishaps.
;   reg_ctr_set(rcx = value name, rdx = data ptr, r8d = len) -> eax = 1/0
;   reg_ctr_get(rcx = value name, rdx = outbuf, r8d = cap)   -> eax = bytes read
; ===========================================================================
public reg_ctr_set
reg_ctr_set proc frame
    FRAME_PROLOG 144
    mov     qword ptr [rbp-56], rcx             ; raw path
    mov     qword ptr [rbp-32], rdx             ; data (saved before reg_hash_name)
    mov     dword ptr [rbp-40], r8d             ; len
    ; Enforce monotonicity: never overwrite an existing 8-byte counter with a smaller one
    cmp     r8d, 8
    jne     rcs_write
    mov     qword ptr [rbp-64], 0
    lea     rcx, [ctr_subkey]
    mov     rdx, qword ptr [rbp-56]
    lea     r8, [rbp-64]
    mov     r9d, 8
    call    reg_get_either
    cmp     eax, 8
    jne     rcs_write
    mov     rax, qword ptr [rbp-32]
    mov     rcx, qword ptr [rax]                ; new counter
    cmp     rcx, qword ptr [rbp-64]             ; < existing stored counter?
    jb      rcs_keep                            ; keep the higher high-water mark
rcs_write:
    mov     rcx, qword ptr [rbp-56]
    call    reg_hash_name                       ; rcx=path -> rax=hashed value name (C6)
    mov     qword ptr [rbp-24], rax
    WINCALL RegCreateKeyExW, qword ptr [g_hkcu], addr ctr_subkey, 0, 0, 0, \
            KEY_WRITE, 0, addr g_cfg_khan, 0
    test    eax, eax
    jnz     rcs_fail
    WINCALL RegSetValueExW, qword ptr [g_cfg_khan], qword ptr [rbp-24], 0, \
            REG_BINARY, qword ptr [rbp-32], dword ptr [rbp-40]
    mov     dword ptr [rbp-48], eax
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
    cmp     dword ptr [rbp-48], 0
    jne     rcs_fail
rcs_keep:
    mov     eax, 1
    FRAME_EPILOG
    ret
rcs_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
reg_ctr_set endp

public reg_ctr_get
reg_ctr_get proc frame
    FRAME_PROLOG 32
    mov     r9d, r8d
    mov     r8, rdx
    mov     rdx, rcx
    lea     rcx, [ctr_subkey]
    call    reg_get_either
    FRAME_EPILOG
    ret
reg_ctr_get endp

public reg_ctr_del
reg_ctr_del proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-32], rcx
    call    reg_hash_name
    mov     rdx, rax
    call    rcd_one
    mov     rcx, qword ptr [rbp-32]
    call    reg_hash_legacy
    mov     rdx, rax
    call    rcd_one
    mov     eax, 1
    FRAME_EPILOG
    ret
reg_ctr_del endp

rcd_one proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-24], rdx
    WINCALL RegOpenKeyExW, qword ptr [g_hkcu], addr ctr_subkey, 0, KEY_WRITE, \
            addr g_cfg_khan
    test    eax, eax
    jnz     rco_done
    WINCALL RegDeleteValueW, qword ptr [g_cfg_khan], qword ptr [rbp-24]
    WINCALL RegCloseKey, qword ptr [g_cfg_khan]
rco_done:
    FRAME_EPILOG
    ret
rcd_one endp

; ===========================================================================
; cmd_polkat - VDR-09 + VDR-23 registry policy & cfg_in_set ABI KAT.
;   Runs entirely inside the isolated scratch HKCU hive installed by
;   gui_test_hooks (g_hkcu), mounting a subkey "PolHklm" as g_hklm so zero
;   machine or user registry state is touched.  Verifies:
;     1) HKLM REG_EXPAND_SZ "%APPDATA%\Vordr\corp.vordr" resolves via
;        SHGetFolderPathW with *locked == 1.
;     2) HKLM REG_EXPAND_SZ "%ATTACKER_ENV%\evil.vordr" fails closed
;        (eax == 0, *locked == 1, dst[0] == 0) and NEVER falls back to HKCU!
;     3) HKLM wrong-type REG_SZ on DWORD policy "ClipSeconds" returns safe
;        default (15) with *locked == 1 and NEVER consults HKCU (99)!
;     4) cfg_in_set preserves caller's r8 across path normalisation (VDR-23).
; ===========================================================================
extern cfg_in_set:proc
extern print_a:proc

.data
CSTR plk_ok,  "polkat: PASS (HKLM folder-template allowlist, fail-closed lock, cfg_in_set r8)",13,10
CSTR plk_bad, "polkat: FAIL",13,10
WSTR plk_subm, <PolHklm>
align 2
plk_good label word
    dw '%','A','P','P','D','A','T','A','%',5Ch,'V','o','r','d','r',5Ch,'c','o','r','p','.','v','o','r','d','r',0
PLK_GOOD_CB equ ($ - plk_good)
plk_evil label word
    dw '%','A','T','T','A','C','K','E','R','_','E','N','V','%',5Ch,'e','v','i','l','.','v','o','r','d','r',0
PLK_EVIL_CB equ ($ - plk_evil)
WSTR plk_usrv, <C:\UserVault\user.vordr>
PLK_USRV_CB equ (23 + 1) * 2
WSTR plk_clip, <ClipSeconds>
WSTR plk_unc,  <AllowUncVault>
WSTR plk_zero, <0>
PLK_ZERO_CB equ 4
align 4
plk_dw99    dd 99
plk_dw1     dd 1
.data?
align 2
plk_out     dw 512 dup (?)
align 4
plk_locked  dd ?
.code
LANDING_PAD
public cmd_polkat
cmd_polkat proc frame
    FRAME_PROLOG 128
    ; [rbp-16]=saved g_hklm, [rbp-24]=hFakeHklm, [rbp-32]=hPolKey, [rbp-40]=hUsrKey,
    ; [rbp-48]=saved g_cfg_in
    mov     rax, qword ptr [g_hklm]
    mov     qword ptr [rbp-16], rax
    mov     qword ptr [rbp-24], 0
    mov     qword ptr [rbp-32], 0
    mov     qword ptr [rbp-40], 0
    WINCALL RegCreateKeyExW, qword ptr [g_hkcu], addr plk_subm, 0, 0, 0, \
            KEY_RW, 0, addr rbp-24, 0
    test    eax, eax
    jnz     plk_fail
    mov     rax, qword ptr [rbp-24]
    mov     qword ptr [g_hklm], rax
    WINCALL RegCreateKeyExW, qword ptr [g_hklm], addr cfg_subkey, 0, 0, 0, \
            KEY_RW, 0, addr rbp-32, 0
    test    eax, eax
    jnz     plk_clean
    WINCALL RegCreateKeyExW, qword ptr [g_hkcu], addr cfg_subkey, 0, 0, 0, \
            KEY_RW, 0, addr rbp-40, 0
    test    eax, eax
    jnz     plk_clean
    ; Seed HKCU fallback values that MUST NOT be reached when HKLM policy is set/corrupt
    WINCALL RegSetValueExW, qword ptr [rbp-40], addr cfg_value, 0, REG_SZ, \
            addr plk_usrv, PLK_USRV_CB
    test    eax, eax
    jnz     plk_clean
    WINCALL RegSetValueExW, qword ptr [rbp-40], addr plk_clip, 0, REG_DWORD, \
            addr plk_dw99, 4
    test    eax, eax
    jnz     plk_clean

    ; 1) Valid HKLM REG_EXPAND_SZ "%APPDATA%\Vordr\corp.vordr" -> expands, *locked = 1
    WINCALL RegSetValueExW, qword ptr [rbp-32], addr cfg_value, 0, REG_EXPAND_SZ, \
            addr plk_good, PLK_GOOD_CB
    test    eax, eax
    jnz     plk_clean
    mov     dword ptr [plk_locked], 0
    lea     rcx, [plk_out]
    mov     edx, 512
    lea     r8, [plk_locked]
    call    reg_load_vault
    cmp     eax, 1
    jne     plk_clean
    cmp     dword ptr [plk_locked], 1
    jne     plk_clean
    cmp     word ptr [plk_out], 0
    je      plk_clean
    cmp     word ptr [plk_out], '%'
    je      plk_clean

    ; 2) Disallowed HKLM "%ATTACKER_ENV%\evil.vordr" -> fail closed, *locked = 1, NO HKCU fallback
    WINCALL RegSetValueExW, qword ptr [rbp-32], addr cfg_value, 0, REG_EXPAND_SZ, \
            addr plk_evil, PLK_EVIL_CB
    test    eax, eax
    jnz     plk_clean
    mov     dword ptr [plk_locked], 0
    lea     rcx, [plk_out]
    mov     edx, 512
    lea     r8, [plk_locked]
    call    reg_load_vault
    test    eax, eax
    jnz     plk_clean
    cmp     dword ptr [plk_locked], 1
    jne     plk_clean
    cmp     word ptr [plk_out], 0
    jne     plk_clean

    ; 3) Wrong-type REG_SZ on HKLM DWORD policy -> default (15), *locked = 1, NO HKCU (99)
    WINCALL RegSetValueExW, qword ptr [rbp-32], addr plk_clip, 0, REG_SZ, \
            addr plk_zero, PLK_ZERO_CB
    test    eax, eax
    jnz     plk_clean
    mov     dword ptr [plk_locked], 0
    lea     rcx, [plk_clip]
    mov     edx, 15
    lea     r8, [plk_locked]
    call    cfg_get_dword
    cmp     eax, 15
    jne     plk_clean
    cmp     dword ptr [plk_locked], 1
    jne     plk_clean

    ; 4) cfg_in_set preserves r8 (VDR-23 raw frame ABI check)
    lea     rcx, [plk_usrv]
    mov     r8, 0CAFEBABE12345678h
    call    cfg_in_set
    mov     rcx, 0CAFEBABE12345678h
    cmp     r8, rcx
    jne     plk_clean

    ; 5) VDR2-11: HKLM-only policy (AllowUncVault) ignores HKCU and honours HKLM
    WINCALL RegSetValueExW, qword ptr [rbp-40], addr plk_unc, 0, REG_DWORD, \
            addr plk_dw1, 4
    test    eax, eax
    jnz     plk_clean
    lea     rcx, [plk_unc]
    xor     edx, edx
    call    cfg_get_dword_hklm
    test    eax, eax
    jnz     plk_clean                        ; HKCU AllowUncVault=1 MUST be ignored!
    WINCALL RegSetValueExW, qword ptr [rbp-32], addr plk_unc, 0, REG_DWORD, \
            addr plk_dw1, 4
    test    eax, eax
    jnz     plk_clean
    lea     rcx, [plk_unc]
    xor     edx, edx
    call    cfg_get_dword_hklm
    cmp     eax, 1
    jne     plk_clean

    ; Clean up values + handles and restore g_hklm
    WINCALL RegDeleteValueW, qword ptr [rbp-32], addr cfg_value
    WINCALL RegDeleteValueW, qword ptr [rbp-32], addr plk_clip
    WINCALL RegDeleteValueW, qword ptr [rbp-32], addr plk_unc
    WINCALL RegDeleteValueW, qword ptr [rbp-40], addr cfg_value
    WINCALL RegDeleteValueW, qword ptr [rbp-40], addr plk_clip
    WINCALL RegDeleteValueW, qword ptr [rbp-40], addr plk_unc
    WINCALL RegCloseKey, qword ptr [rbp-40]
    WINCALL RegCloseKey, qword ptr [rbp-32]
    WINCALL RegCloseKey, qword ptr [rbp-24]
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [g_hklm], rax
    lea     rcx, [plk_ok]
    mov     edx, plk_ok_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret

plk_clean:
    cmp     qword ptr [rbp-40], 0
    je      @F
    WINCALL RegDeleteValueW, qword ptr [rbp-40], addr cfg_value
    WINCALL RegDeleteValueW, qword ptr [rbp-40], addr plk_clip
    WINCALL RegDeleteValueW, qword ptr [rbp-40], addr plk_unc
    WINCALL RegCloseKey, qword ptr [rbp-40]
@@: cmp     qword ptr [rbp-32], 0
    je      @F
    WINCALL RegDeleteValueW, qword ptr [rbp-32], addr cfg_value
    WINCALL RegDeleteValueW, qword ptr [rbp-32], addr plk_clip
    WINCALL RegDeleteValueW, qword ptr [rbp-32], addr plk_unc
    WINCALL RegCloseKey, qword ptr [rbp-32]
@@: cmp     qword ptr [rbp-24], 0
    je      @F
    WINCALL RegCloseKey, qword ptr [rbp-24]
@@: mov     rax, qword ptr [rbp-16]
    mov     qword ptr [g_hklm], rax
plk_fail:
    lea     rcx, [plk_bad]
    mov     edx, plk_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_polkat endp

end
