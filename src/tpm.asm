; =============================================================================
; tpm.asm - optional convenience unlock backed by the platform TPM.
; -----------------------------------------------------------------------------
; Wraps the vault's 32-byte master key to a TPM-resident RSA key (CNG
; "Microsoft Platform Crypto Provider") so it can be released again only on THIS
; machine.  The wrapped blob lives in the registry (HKCU\SOFTWARE\Vordr\
; TPM-Unlock, one value per vault path); the master password
; still opens the vault on any machine, so this is pure convenience (OR mode) and
; never the sole factor - losing the TPM only costs the fast-unlock shortcut.
;
;   tpm_available() -> eax = 1 if the platform provider is present
;   tpm_seal(rcx=keyname, rdx=in32, r8=outblob, r9d=cap) -> eax = blob len (0=fail)
;   tpm_unseal(rcx=keyname, rdx=blob, r8d=bloblen, r9=out32) -> eax = 1 / 0
;   tpm_delete(rcx=keyname) -> eax = 1 / 0          ("forget this device")
;
; Keys are per-user, RSA-2048, OAEP(SHA-256); all calls are NCRYPT_SILENT (no
; gesture) - a Hello PIN can be added later via a UI policy on key creation.
; The provider/key handles live in module globals (single-threaded use).
; =============================================================================

include macros.inc

extern NCryptOpenStorageProvider:proc
extern NCryptOpenKey:proc
extern NCryptCreatePersistedKey:proc
extern NCryptSetProperty:proc
extern NCryptFinalizeKey:proc
extern NCryptEncrypt:proc
extern NCryptDecrypt:proc
extern NCryptDeleteKey:proc
extern NCryptFreeObject:proc
extern sha256_init:proc
extern sha256_update:proc
extern sha256_final:proc
extern secure_zero:proc
extern ct_memcmp:proc

NCRYPT_SILENT_FLAG        equ 040h
NCRYPT_OVERWRITE_KEY_FLAG equ 080h
NCRYPT_OAEP_SILENT        equ 044h      ; NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG
NCRYPT_PAD_OAEP           equ 004h      ; C4: OAEP without SILENT (lets the OS prompt)
NCRYPT_UI_PROTECT_KEY     equ 1         ; NCRYPT_UI_POLICY dwFlags: prompt on each use
VH_SALT                   equ 20        ; VAULT_HDR.salt byte offset (mirrors vault.asm)

externdef g_tpm_reqhello:dword          ; C4: require Hello/PIN on TPM unlock (gui.asm)
externdef g_hdr:byte                    ; live vault header (vault.asm)
externdef g_secdesk_hwnd:qword          ; active secure-desktop dialog HWND (gui.asm)
externdef g_vaulthwnd:qword             ; main vault HWND (gui.asm)

.data
; CNG provider / algorithm names as UTF-16 (no commas -> WSTR)
WSTR tpm_prov, <Microsoft Platform Crypto Provider>
WSTR tpm_alg,  <RSA>
WSTR tpm_sha,  <SHA256>
WSTR tpm_lenprop, <Length>              ; NCRYPT_LENGTH_PROPERTY
WSTR hwnd_prop,   <HWND Handle>         ; NCRYPT_HWND_PROPERTY
tpm_keylen  dd 2048                     ; force RSA-2048 (never the provider default)
; C4: UI policy stamped on the key when g_tpm_reqhello is set (opt-in).
WSTR ui_policy_prop, <UI Policy>        ; NCRYPT_UI_POLICY_PROPERTY
WSTR ui_friendly,    <Vordr>
WSTR ui_desc,        <Unlock your Vordr vault>
CSTR tpm_lbl_dom, "Vordr-TPM-v2"
align 8
g_ui_policy label byte                  ; NCRYPT_UI_POLICY (32 bytes, x64)
    dd  1                               ; dwVersion
    dd  NCRYPT_UI_PROTECT_KEY           ; dwFlags
    dq  0                               ; pszCreationTitle
    dq  ui_friendly                     ; pszFriendlyName
    dq  ui_desc                         ; pszDescription

.data?
g_tpm_prov  dq ?                ; NCRYPT_PROV_HANDLE
g_tpm_key   dq ?                ; NCRYPT_KEY_HANDLE
g_tpm_cbres dd ?                ; bytes produced by encrypt/decrypt
align 8
public g_tpm_oaep, g_tpm_label
g_tpm_oaep    db 24 dup (?)     ; BCRYPT_OAEP_PADDING_INFO
g_tpm_label   db 32 dup (?)     ; SHA-256("Vordr-TPM-v2" || vault_salt || reqhello)
g_tpm_sha_ctx db 128 dup (?)    ; SHA256_CTX scratch (108 bytes used)

.code

; tpm_build_oaep(ecx = use_v2) - fill g_tpm_oaep.
;   use_v2 != 0: pbLabel = SHA-256("Vordr-TPM-v2" || g_hdr[VH_SALT..+32] || LE32(reqhello!=0))
;   use_v2 == 0: legacy empty OAEP label { pszAlgId="SHA256", 0, 0 } (silent-only compat)
public tpm_build_oaep
tpm_build_oaep proc frame
    FRAME_PROLOG 48
    test    ecx, ecx
    jz      tbo_legacy
    lea     rcx, [g_tpm_sha_ctx]
    call    sha256_init
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [tpm_lbl_dom]
    mov     r8d, tpm_lbl_dom_len
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [g_hdr + VH_SALT]
    mov     r8d, 32
    call    sha256_update
    xor     eax, eax
    cmp     dword ptr [g_tpm_reqhello], 0
    setne   al
    mov     dword ptr [rbp-24], eax
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [rbp-24]
    mov     r8d, 4
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [g_tpm_label]
    call    sha256_final
    lea     rax, [tpm_sha]
    mov     qword ptr [g_tpm_oaep], rax
    lea     rax, [g_tpm_label]
    mov     qword ptr [g_tpm_oaep+8], rax
    mov     dword ptr [g_tpm_oaep+16], 32
    FRAME_EPILOG
    ret
tbo_legacy:
    lea     rax, [tpm_sha]
    mov     qword ptr [g_tpm_oaep], rax
    mov     qword ptr [g_tpm_oaep+8], 0
    mov     dword ptr [g_tpm_oaep+16], 0
    FRAME_EPILOG
    ret
tpm_build_oaep endp

; tpm_attach_hwnd(rcx = hKey) - best-effort attach parent HWND for Windows Hello UI.
tpm_attach_hwnd proc frame
    FRAME_PROLOG 64
    mov     rax, qword ptr [g_secdesk_hwnd]
    test    rax, rax
    jnz     tah_set
    mov     rax, qword ptr [g_vaulthwnd]
    test    rax, rax
    jz      tah_done
tah_set:
    mov     qword ptr [rbp-24], rax
    WINCALL NCryptSetProperty, rcx, addr hwnd_prop, addr rbp-24, 8, 0
tah_done:
    FRAME_EPILOG
    ret
tpm_attach_hwnd endp

; ===========================================================================
; tpm_available() -> eax = 1 if the platform crypto provider opens, else 0.
; ===========================================================================
public tpm_available
tpm_available proc frame
    FRAME_PROLOG 64
    mov     qword ptr [g_tpm_prov], 0
    WINCALL NCryptOpenStorageProvider, addr g_tpm_prov, addr tpm_prov, 0
    test    eax, eax
    jnz     ta_no
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
    mov     eax, 1
    FRAME_EPILOG
    ret
ta_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_available endp

; ===========================================================================
; tpm_seal(rcx=keyname, rdx=in32, r8=outblob, r9d=cap) -> eax = blob len (0=fail).
;   Opens (or creates) the named TPM RSA key, encrypts the 32-byte input with
;   RSA-OAEP(SHA-256).  RSA-2048 -> a 256-byte blob.
; ===========================================================================
public tpm_seal
tpm_seal proc frame
    FRAME_PROLOG 192
    ; [rbp-24]=keyname [rbp-32]=in32 [rbp-40]=outblob [rbp-48]=cap [rbp-52]=ncrypt rc
    ; [rbp-56]=finalize flags [rbp-64]=encrypt flags [rbp-128..-65]=pt64 (key32 || bind32)
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     dword ptr [rbp-48], r9d
    mov     qword ptr [g_tpm_prov], 0
    mov     qword ptr [g_tpm_key], 0
    mov     dword ptr [g_tpm_cbres], 0
    WINCALL NCryptOpenStorageProvider, addr g_tpm_prov, addr tpm_prov, 0
    test    eax, eax
    jnz     ts_fail
    ; Always recreate the persisted key (NCRYPT_OVERWRITE_KEY_FLAG) so changing
    ; g_tpm_reqhello (0 -> 1) immediately enforces NCRYPT_UI_POLICY instead of
    ; reusing an older silent key.
    WINCALL NCryptCreatePersistedKey, qword ptr [g_tpm_prov], addr g_tpm_key, \
            addr tpm_alg, qword ptr [rbp-24], 0, NCRYPT_OVERWRITE_KEY_FLAG
    test    eax, eax
    jnz     ts_freeprov
    ; Enforce RSA-2048 modulus size (fail closed if provider rejects Length)
    WINCALL NCryptSetProperty, qword ptr [g_tpm_key], addr tpm_lenprop, \
            addr tpm_keylen, 4, 0
    test    eax, eax
    jnz     ts_freekey
    mov     dword ptr [rbp-56], NCRYPT_SILENT_FLAG
    mov     dword ptr [rbp-64], NCRYPT_OAEP_SILENT
    cmp     dword ptr [g_tpm_reqhello], 0
    je      ts_finalize
    ; Require Windows Hello / PIN: attach parent HWND, enforce UI Policy (fail
    ; closed if rejected!), and omit NCRYPT_SILENT_FLAG on finalize + encrypt.
    mov     rcx, qword ptr [g_tpm_key]
    call    tpm_attach_hwnd
    WINCALL NCryptSetProperty, qword ptr [g_tpm_key], addr ui_policy_prop, \
            addr g_ui_policy, 32, 0
    test    eax, eax
    jnz     ts_freekey
    mov     dword ptr [rbp-56], 0
    mov     dword ptr [rbp-64], NCRYPT_PAD_OAEP
ts_finalize:
    WINCALL NCryptFinalizeKey, qword ptr [g_tpm_key], dword ptr [rbp-56]
    test    eax, eax
    jnz     ts_freekey
    ; Bind key32 to vault_salt + reqhello inside a 64-byte OAEP payload:
    ;   pt64 = key32 || SHA-256(key32 || g_tpm_label)
    ; Windows PCPKSP.dll silently ignores BCRYPT_OAEP_PADDING_INFO.pbLabel on
    ; TPM 2.0 RSA keys, so binding inside the encrypted OAEP block guarantees
    ; cross-vault / policy-downgrade rejection on every provider while keeping
    ; the 256-byte RSA-2048 ciphertext size unchanged.
    mov     ecx, 1
    call    tpm_build_oaep
    xor     ecx, ecx
    call    tpm_build_oaep
    mov     r10, qword ptr [rbp-32]
    lea     r11, [rbp-128]
    xor     ecx, ecx
ts_cpk:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      ts_cpk
    lea     rcx, [g_tpm_sha_ctx]
    call    sha256_init
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [rbp-128]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [g_tpm_label]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [rbp-96]
    call    sha256_final
    lea     r10, [rbp-128]
    WINCALL NCryptEncrypt, qword ptr [g_tpm_key], r10, 64, \
            addr g_tpm_oaep, qword ptr [rbp-40], dword ptr [rbp-48], \
            addr g_tpm_cbres, dword ptr [rbp-64]
    mov     dword ptr [rbp-52], eax
    lea     rcx, [rbp-128]
    mov     edx, 64
    call    secure_zero
    lea     rcx, [g_tpm_sha_ctx]
    mov     edx, 128
    call    secure_zero
    lea     rcx, [g_tpm_label]
    mov     edx, 32
    call    secure_zero
    cmp     dword ptr [rbp-52], 0
    jne     ts_freekey
    mov     eax, dword ptr [g_tpm_cbres]
    test    eax, eax
    jz      ts_freekey
    cmp     eax, dword ptr [rbp-48]
    ja      ts_freekey
    WINCALL NCryptFreeObject, qword ptr [g_tpm_key]
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
    mov     eax, dword ptr [g_tpm_cbres]
    FRAME_EPILOG
    ret
ts_freekey:
    WINCALL NCryptFreeObject, qword ptr [g_tpm_key]
ts_freeprov:
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
ts_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_seal endp

; ===========================================================================
; tpm_unseal(rcx=keyname, rdx=blob, r8d=bloblen, r9=out32) -> eax = 1 / 0.
;   Decrypts the wrapped blob with the TPM key back into the 32-byte buffer.
;   Verifies the v2 64-byte context-binding tag in constant time, and wipes
;   scratch + out32 on ANY failure path so partial output never lingers.
; ===========================================================================
public tpm_unseal
tpm_unseal proc frame
    FRAME_PROLOG 224
    ; [rbp-24]=keyname [rbp-32]=blob [rbp-40]=bloblen [rbp-48]=out32
    ; [rbp-56]=OpenKey flag [rbp-64]=Decrypt flag
    ; [rbp-128..-65]=pt64  [rbp-160..-129]=exp_tag
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     dword ptr [rbp-40], r8d
    mov     qword ptr [rbp-48], r9
    mov     qword ptr [g_tpm_prov], 0
    mov     qword ptr [g_tpm_key], 0
    mov     dword ptr [g_tpm_cbres], 0
    lea     rcx, [rbp-160]
    mov     edx, 96
    call    secure_zero
    WINCALL NCryptOpenStorageProvider, addr g_tpm_prov, addr tpm_prov, 0
    test    eax, eax
    jnz     tu_fail
    mov     eax, NCRYPT_SILENT_FLAG
    mov     edx, NCRYPT_OAEP_SILENT
    cmp     dword ptr [g_tpm_reqhello], 0
    je      tu_flags
    xor     eax, eax
    mov     edx, NCRYPT_PAD_OAEP
tu_flags:
    mov     dword ptr [rbp-56], eax
    mov     dword ptr [rbp-64], edx
    WINCALL NCryptOpenKey, qword ptr [g_tpm_prov], addr g_tpm_key, \
            qword ptr [rbp-24], 0, dword ptr [rbp-56]
    test    eax, eax
    jnz     tu_freeprov
    cmp     dword ptr [g_tpm_reqhello], 0
    je      tu_dec
    mov     rcx, qword ptr [g_tpm_key]
    call    tpm_attach_hwnd
tu_dec:
    mov     ecx, 1
    call    tpm_build_oaep
    xor     ecx, ecx
    call    tpm_build_oaep
    lea     r10, [rbp-128]
    WINCALL NCryptDecrypt, qword ptr [g_tpm_key], qword ptr [rbp-32], dword ptr [rbp-40], \
            addr g_tpm_oaep, r10, 64, \
            addr g_tpm_cbres, dword ptr [rbp-64]
    test    eax, eax
    jnz     tu_freekey
    cmp     dword ptr [g_tpm_cbres], 64
    je      tu_v2_chk
    ; Legacy pre-v2 32-byte blob: accepted ONLY when silent unlock (reqhello == 0).
    cmp     dword ptr [g_tpm_cbres], 32
    jne     tu_freekey
    cmp     dword ptr [g_tpm_reqhello], 0
    jne     tu_freekey
    jmp     tu_emit
tu_v2_chk:
    lea     rcx, [g_tpm_sha_ctx]
    call    sha256_init
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [rbp-128]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [g_tpm_label]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [rbp-160]
    call    sha256_final
    lea     rcx, [rbp-160]
    lea     rdx, [rbp-96]
    mov     r8d, 32
    call    ct_memcmp
    test    eax, eax
    jnz     tu_freekey
tu_emit:
    mov     r11, qword ptr [rbp-48]
    test    r11, r11
    jz      tu_freekey
    lea     r10, [rbp-128]
    xor     ecx, ecx
tu_cpout:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      tu_cpout
    lea     rcx, [rbp-160]
    mov     edx, 96
    call    secure_zero
    lea     rcx, [g_tpm_sha_ctx]
    mov     edx, 128
    call    secure_zero
    lea     rcx, [g_tpm_label]
    mov     edx, 32
    call    secure_zero
    WINCALL NCryptFreeObject, qword ptr [g_tpm_key]
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
    mov     eax, 1
    FRAME_EPILOG
    ret
tu_freekey:
    WINCALL NCryptFreeObject, qword ptr [g_tpm_key]
tu_freeprov:
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
tu_fail:
    lea     rcx, [rbp-160]
    mov     edx, 96
    call    secure_zero
    lea     rcx, [g_tpm_sha_ctx]
    mov     edx, 128
    call    secure_zero
    lea     rcx, [g_tpm_label]
    mov     edx, 32
    call    secure_zero
    mov     rcx, qword ptr [rbp-48]
    test    rcx, rcx
    jz      @F
    mov     edx, 32
    call    secure_zero
@@: xor     eax, eax
    FRAME_EPILOG
    ret
tpm_unseal endp

; ===========================================================================
; tpm_delete(rcx=keyname) -> eax = 1 / 0.  Removes the device's wrapping key.
; ===========================================================================
public tpm_delete
tpm_delete proc frame
    FRAME_PROLOG 96
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [g_tpm_prov], 0
    mov     qword ptr [g_tpm_key], 0
    WINCALL NCryptOpenStorageProvider, addr g_tpm_prov, addr tpm_prov, 0
    test    eax, eax
    jnz     td_fail
    mov     eax, NCRYPT_SILENT_FLAG
    cmp     dword ptr [g_tpm_reqhello], 0
    je      @F
    xor     eax, eax
@@: mov     dword ptr [rbp-32], eax
    WINCALL NCryptOpenKey, qword ptr [g_tpm_prov], addr g_tpm_key, \
            qword ptr [rbp-24], 0, dword ptr [rbp-32]
    test    eax, eax
    jnz     td_freeprov
    cmp     dword ptr [g_tpm_reqhello], 0
    je      @F
    mov     rcx, qword ptr [g_tpm_key]
    call    tpm_attach_hwnd
@@: ; NCryptDeleteKey frees the key handle as well
    WINCALL NCryptDeleteKey, qword ptr [g_tpm_key], dword ptr [rbp-32]
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
    mov     eax, 1
    FRAME_EPILOG
    ret
td_freeprov:
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
td_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_delete endp

; ===========================================================================
; cmd_tpmkat - VDR-10 OAEP v2 label domain/salt/reqhello binding KAT +
;   optional live Platform Crypto Provider cross-vault transplant refusal.
; ===========================================================================
extern print_a:proc

.data
WSTR tpk_key, <VordrTpmKatKey>
CSTR tpk_ok_live, "tpmkat: PASS (OAEP v2 label + live TPM cross-vault transplant refused)",13,10
CSTR tpk_ok_sw,   "tpmkat: PASS (OAEP v2 label binding ok; no writable PCP TPM on host)",13,10
CSTR tpk_bad,     "tpmkat: FAIL",13,10
.data?
tpk_in      db 32 dup (?)
tpk_out     db 32 dup (?)
tpk_zero    db 32 dup (?)
tpk_lbl0    db 32 dup (?)
tpk_saltbk  db 32 dup (?)
tpk_blob    db 512 dup (?)
align 4
tpk_reqbk   dd ?
.code
tpk_restore proc
    lea     r10, [g_hdr + VH_SALT]
    lea     r11, [tpk_saltbk]
    xor     ecx, ecx
tpk_rs:
    mov     al, byte ptr [r11+rcx]
    mov     byte ptr [r10+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      tpk_rs
    mov     eax, dword ptr [tpk_reqbk]
    mov     dword ptr [g_tpm_reqhello], eax
    ret
tpk_restore endp

LANDING_PAD
public cmd_tpmkat
cmd_tpmkat proc frame
    FRAME_PROLOG 64
    ; Save g_hdr[VH_SALT..+32] and g_tpm_reqhello
    mov     eax, dword ptr [g_tpm_reqhello]
    mov     dword ptr [tpk_reqbk], eax
    lea     r10, [g_hdr + VH_SALT]
    lea     r11, [tpk_saltbk]
    xor     ecx, ecx
tpk_sv:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    mov     byte ptr [r10+rcx], 0AAh
    lea     r8, [tpk_in]
    mov     byte ptr [r8+rcx], cl
    lea     r8, [tpk_zero]
    mov     byte ptr [r8+rcx], 0
    inc     ecx
    cmp     ecx, 32
    jb      tpk_sv

    ; 1) use_v2=1, reqhello=0 -> 32-byte label
    mov     dword ptr [g_tpm_reqhello], 0
    mov     ecx, 1
    call    tpm_build_oaep
    cmp     dword ptr [g_tpm_oaep+16], 32
    jne     tpk_fail
    lea     rax, [g_tpm_label]
    cmp     qword ptr [g_tpm_oaep+8], rax
    jne     tpk_fail
    lea     r10, [g_tpm_label]
    lea     r11, [tpk_lbl0]
    xor     ecx, ecx
tpk_cp0:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      tpk_cp0

    ; 2) reqhello=1 changes OAEP label; reqhello=7 canonicalises identically to 1
    mov     dword ptr [g_tpm_reqhello], 1
    mov     ecx, 1
    call    tpm_build_oaep
    lea     rcx, [g_tpm_label]
    lea     rdx, [tpk_lbl0]
    mov     r8d, 32
    call    ct_memcmp
    test    eax, eax
    jz      tpk_fail
    lea     r10, [g_tpm_label]
    lea     r11, [tpk_out]
    xor     ecx, ecx
tpk_cp1:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      tpk_cp1
    mov     dword ptr [g_tpm_reqhello], 7
    mov     ecx, 1
    call    tpm_build_oaep
    lea     rcx, [g_tpm_label]
    lea     rdx, [tpk_out]
    mov     r8d, 32
    call    ct_memcmp
    test    eax, eax
    jnz     tpk_fail

    ; 3) use_v2=0 -> empty OAEP label (legacy silent fallback shape)
    mov     dword ptr [g_tpm_reqhello], 0
    xor     ecx, ecx
    call    tpm_build_oaep
    cmp     qword ptr [g_tpm_oaep+8], 0
    jne     tpk_fail
    cmp     dword ptr [g_tpm_oaep+16], 0
    jne     tpk_fail

    ; 4) Optional live PCP check when silent TPM key creation succeeds on this host
    call    tpm_available
    test    eax, eax
    jz      tpk_sw_ok
    lea     rcx, [tpk_key]
    lea     rdx, [tpk_in]
    lea     r8, [tpk_blob]
    mov     r9d, 512
    call    tpm_seal
    test    eax, eax
    jz      tpk_sw_ok                           ; PCP present, silent persisted key unavailable
    mov     dword ptr [rbp-28], eax             ; bloblen
    ; Flip 1 salt bit -> tpm_unseal MUST reject (both v2 label and legacy empty label fail)
    xor     byte ptr [g_hdr + VH_SALT], 1
    lea     rcx, [tpk_out]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [tpk_key]
    lea     rdx, [tpk_blob]
    mov     r8d, dword ptr [rbp-28]
    lea     r9, [tpk_out]
    call    tpm_unseal
    test    eax, eax
    jnz     tpk_del_fail
    lea     rcx, [tpk_out]                      ; out32 must stay wiped on failure
    lea     rdx, [tpk_zero]
    mov     r8d, 32
    call    ct_memcmp
    test    eax, eax
    jnz     tpk_del_fail
    ; Restore exact salt -> tpm_unseal MUST succeed and recover tpk_in
    xor     byte ptr [g_hdr + VH_SALT], 1
    lea     rcx, [tpk_key]
    lea     rdx, [tpk_blob]
    mov     r8d, dword ptr [rbp-28]
    lea     r9, [tpk_out]
    call    tpm_unseal
    cmp     eax, 1
    jne     tpk_del_fail
    lea     rcx, [tpk_out]
    lea     rdx, [tpk_in]
    mov     r8d, 32
    call    ct_memcmp
    test    eax, eax
    jnz     tpk_del_fail
    lea     rcx, [tpk_key]
    call    tpm_delete
    lea     rcx, [tpk_out]
    mov     edx, 32
    call    secure_zero
    call    tpk_restore
    lea     rcx, [tpk_ok_live]
    mov     edx, tpk_ok_live_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret

tpk_sw_ok:
    call    tpk_restore
    lea     rcx, [tpk_ok_sw]
    mov     edx, tpk_ok_sw_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret

tpk_del_fail:
    lea     rcx, [tpk_key]
    call    tpm_delete
tpk_fail:
    call    tpk_restore
    lea     rcx, [tpk_bad]
    mov     edx, tpk_bad_len
    call    print_a
    mov     eax, 1
    FRAME_EPILOG
    ret
cmd_tpmkat endp

; ===========================================================================
; cmd_tpmtest (dbg builds only) - headless seal/unseal round-trip on this
;   machine's TPM, so the platform-crypto path can be validated without the GUI.
; ===========================================================================
ifdef DBG_TRACE
extern rng_fill:proc

.data
WSTR tpm_testkey, <VordrSelfTestKey>
CSTR tt_pass, "  [PASS] tpm seal/unseal round-trip",13,10
CSTR tt_fail, "  [FAIL] tpm seal/unseal (no TPM, or provider error)",13,10
.data?
tt_in   db 32 dup (?)
tt_blob db 512 dup (?)
tt_out  db 32 dup (?)
.code

public cmd_tpmtest
LANDING_PAD
cmd_tpmtest proc frame
    FRAME_PROLOG 48
    lea     rcx, [tt_in]
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      tt_bad
    lea     rcx, [tpm_testkey]
    lea     rdx, [tt_in]
    lea     r8, [tt_blob]
    mov     r9d, 512
    call    tpm_seal
    test    eax, eax
    jz      tt_bad
    mov     dword ptr [rbp-32], eax         ; blob length
    lea     rcx, [tpm_testkey]
    lea     rdx, [tt_blob]
    mov     r8d, dword ptr [rbp-32]
    lea     r9, [tt_out]
    call    tpm_unseal
    test    eax, eax
    jz      tt_bad
    lea     rcx, [tt_in]
    lea     rdx, [tt_out]
    mov     r8, 32
    call    ct_memcmp
    test    eax, eax
    jnz     tt_bad
    lea     rcx, [tpm_testkey]
    call    tpm_delete
    lea     rcx, [tt_pass]
    mov     edx, tt_pass_len
    call    print_a
    xor     eax, eax
    FRAME_EPILOG
    ret
tt_bad:
    lea     rcx, [tpm_testkey]
    call    tpm_delete
    lea     rcx, [tt_fail]
    mov     edx, tt_fail_len
    call    print_a
    mov     eax, EXIT_SELFTEST
    FRAME_EPILOG
    ret
cmd_tpmtest endp
endif

end
