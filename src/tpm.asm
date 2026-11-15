; =============================================================================
; tpm.asm - optional convenience unlock backed by the platform TPM & Windows Hello.
; -----------------------------------------------------------------------------
; Wraps vault unlock material to non-exportable TPM-resident RSA-2048 keys (CNG
; "Microsoft Platform Crypto Provider") and, in Mode 3 (TPM + Windows Hello),
; combines the machine PCP secret with a live user-verifying Windows Hello FIDO2
; PRF ("hmac-secret") assertion via webauthn.dll (unpackaged Win32 compatible).
;
;   tpm_available() -> eax = 1 if the platform provider is present
;   tpm_seal(rcx=keyname, rdx=in32, r8=outblob, r9d=cap) -> eax = blob len (0=fail)
;   tpm_unseal(rcx=keyname, rdx=blob, r8d=bloblen, r9=out32) -> eax = 1 / 0
;   tpm_delete(rcx=keyname) -> eax = 1 / 0          ("forget this device")
;   tpm_hello_available() -> eax = 1 if Windows Hello platform authenticator ready
;   tpm_hello_seal(rcx=out_sec32, rdx=outblob, r8d=cap) -> eax = blob len (0=fail)
;   tpm_hello_unseal(rcx=blob, edx=bloblen, r8=out32) -> eax = 1 / 0
;   tpm_hello_delete(rcx=blob, edx=bloblen) -> eax = 1 / 0
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
extern LoadLibraryExW:proc
extern GetProcAddress:proc
extern GetForegroundWindow:proc
extern GetDesktopWindow:proc
extern RegOpenKeyExW:proc
extern RegQueryValueExW:proc
extern RegCloseKey:proc
extern OpenProcessToken:proc
extern GetTokenInformation:proc
extern CloseHandle:proc
extern GetSystemTimeAsFileTime:proc
extern FileTimeToLocalFileTime:proc
extern FileTimeToSystemTime:proc
extern sha256_init:proc
extern sha256_update:proc
extern sha256_final:proc
extern rng_fill:proc
extern secure_zero:proc
extern ct_memcmp:proc
ifdef PROBE_IO
extern vault_tpm_pin_kat:proc
endif

NCRYPT_SILENT_FLAG        equ 040h
NCRYPT_OVERWRITE_KEY_FLAG equ 080h
NCRYPT_OAEP_SILENT        equ 044h      ; NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG
NCRYPT_PAD_OAEP           equ 004h      ; C4: OAEP without SILENT (lets the OS prompt)
NCRYPT_UI_PROTECT_KEY     equ 1         ; NCRYPT_UI_POLICY dwFlags: prompt on each use
LOAD_LIB_SYS32            equ 0800h     ; LOAD_LIBRARY_SEARCH_SYSTEM32
VH_SALT                   equ 20        ; VAULT_HDR.salt byte offset (mirrors vault.asm)
VH_KCV                    equ 64        ; VAULT_HDR+KCV offset (mirrors vault.asm)
WHLO_MAGIC                equ 4F4C4857h ; "WHLO" little-endian
WHLO_VER                  equ 1
WHLO_HDR_LEN              equ 64
WHLO_MAX_CRED             equ 400
REG_BINARY                equ 3
REG_DWORD                 equ 4
KEY_READ                  equ 20019h
FT_PER_MIN                equ 600000000 ; 60 * 10,000,000 (100-ns ticks per minute)

externdef g_tpm_reqhello:dword          ; C4: require Hello/PIN on TPM unlock (gui.asm)
externdef g_hklm:qword                  ; HKEY_LOCAL_MACHINE (regcfg.asm)
externdef g_hdr:byte                    ; live vault header (vault.asm)
externdef g_secdesk_hwnd:qword          ; active secure-desktop dialog HWND (gui.asm)
externdef g_vaulthwnd:qword             ; main vault HWND (gui.asm)
externdef g_trayhwnd:qword              ; persistent hidden owner HWND (gui.asm)

.data
; CNG / WebAuthn wide strings (no commas -> WSTR)
align 2
WSTR tpm_prov,        <Microsoft Platform Crypto Provider>
WSTR tpm_alg,         <RSA>
WSTR tpm_sha,         <SHA256>
WSTR tpm_lenprop,     <Length>          ; NCRYPT_LENGTH_PROPERTY
WSTR key_usage_prop,  <Key Usage>       ; NCRYPT_KEY_USAGE_PROPERTY
WSTR export_pol_prop, <Export Policy>   ; NCRYPT_EXPORT_POLICY_PROPERTY
WSTR hwnd_prop,       <HWND Handle>     ; NCRYPT_HWND_PROPERTY
WSTR ui_policy_prop,  <UI Policy>       ; NCRYPT_UI_POLICY_PROPERTY
WSTR ui_friendly,     <Vordr>
WSTR ui_desc,         <Unlock your Vordr vault>
WSTR wa_dll_w,        <webauthn.dll>
WSTR wa_rpid_w,       <vordr.local>
WSTR wa_rpname_w,     <Vordr>
WSTR wa_uname_w,      <vordr-vault>
WSTR wa_udisp_w,      <Vordr Vault Unlock>
WSTR wa_hashalg_w,    <SHA-256>
WSTR wa_credtype_w,   <public-key>
WSTR wa_ext_hmac_w,   <hmac-secret>
WSTR tbs_dll_w,       <tbs.dll>
WSTR rk_tpm_pol,      <SOFTWARE\Policies\Microsoft\TPM>
WSTR rv_su_dur,       <StandardUserAuthorizationFailureDuration>
WSTR rv_su_ind,       <StandardUserAuthorizationFailureIndividualThreshold>
WSTR rv_su_tot,       <StandardUserAuthorizationFailureTotalThreshold>
WSTR rk_tpm_af,       <SYSTEM\CurrentControlSet\Services\TPM\AuthorizationFailure>
WSTR rk_af_all,       <ALLSTANDARDUSERS>
WSTR rv_af_hist,      <History>

CSTR tpm_lbl_dom,     "Vordr-TPM-v2"
CSTR tbs_n_create,    "Tbsi_Context_Create"
CSTR tbs_n_submit,    "Tbsip_Submit_Command"
CSTR tbs_n_close,     "Tbsip_Context_Close"
CSTR wa_key_dom,      "Vordr-Hello-Key-v1"
CSTR wa_tag_dom,      "Vordr-Hello-Tag-v1"
CSTR wa_cjson_make,   '{"type":"webauthn.create","challenge":"Vm9yZHJIZWxsb0Vucm9sbA","origin":"https://vordr.local"}'
CSTR wa_cjson_get,    '{"type":"webauthn.get","challenge":"Vm9yZHJIZWxsb1VubG9jaw","origin":"https://vordr.local"}'
CSTR wa_n_ver,        "WebAuthNGetApiVersionNumber"
CSTR wa_n_avail,      "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable"
CSTR wa_n_make,       "WebAuthNAuthenticatorMakeCredential"
CSTR wa_n_get,        "WebAuthNAuthenticatorGetAssertion"
CSTR wa_n_freeatt,    "WebAuthNFreeCredentialAttestation"
CSTR wa_n_freeass,    "WebAuthNFreeAssertion"
CSTR wa_n_delcred,    "WebAuthNDeletePlatformCredential"
CSTR wa_n_getlist,    "WebAuthNGetAuthenticatorList"
CSTR wa_n_freelist,   "WebAuthNFreeAuthenticatorList"

; Windows Hello platform authenticator AAGUID: 08987058-cadc-4b81-b6e1-30de50dcbe96
wa_wh_aaguid db 08h,98h,70h,58h,0CAh,0DCh,4Bh,81h,0B6h,0E1h,30h,0DEh,50h,0DCh,0BEh,96h

; TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES=6, property=0x020E, count=3) - 22 bytes
tbs_getcap_cmd db 80h,01h, 00h,00h,00h,16h, 00h,00h,01h,7Ah, 00h,00h,00h,06h, 00h,00h,02h,0Eh, 00h,00h,00h,03h

align 4
public g_tpm_last_err
g_tpm_last_err dd 0                     ; last nonzero NCrypt / WebAuthN HRESULT
tpm_keylen     dd 2048                  ; force RSA-2048 (never the provider default)
tpm_keyusage   dd 1                     ; NCRYPT_ALLOW_DECRYPT_FLAG (decryption ONLY)
tpm_exppol     dd 0                     ; non-exportable
wa_bool_true   dd 1
ifdef PROBE_IO
g_tpm_mock_mode dd 0                    ; 1 only inside cmd_tpmkat software fallback
endif

align 8
g_ui_policy label byte                  ; NCRYPT_UI_POLICY (32 bytes, x64)
    dd  1                               ; dwVersion
    dd  NCRYPT_UI_PROTECT_KEY           ; dwFlags
    dq  0                               ; pszCreationTitle
    dq  ui_friendly                     ; pszFriendlyName
    dq  ui_desc                         ; pszDescription

align 8
wa_cose_arr label byte                  ; 2 x WEBAUTHN_COSE_CREDENTIAL_PARAMETER (48 bytes)
    dd  1, 0                            ; [0] dwVersion = 1 + pad
    dq  wa_credtype_w                   ;     pwszCredentialType = L"public-key"
    dd  -7, 0                           ;     lAlg = COSE ES256 (-7) + pad
    dd  1, 0                            ; [1] dwVersion = 1 + pad
    dq  wa_credtype_w                   ;     pwszCredentialType = L"public-key"
    dd  -257, 0                         ;     lAlg = COSE RS256 (-257) + pad

align 8
wa_cose_params label byte               ; WEBAUTHN_COSE_CREDENTIAL_PARAMETERS (16 bytes)
    dd  2, 0                            ; cCredentialParameters = 2
    dq  wa_cose_arr                     ; pCredentialParameters

align 8
wa_ext_arr label byte                   ; WEBAUTHN_EXTENSION (24 bytes)
    dq  wa_ext_hmac_w                   ; pwszExtensionIdentifier = L"hmac-secret"
    dd  4, 0                            ; cbExtension = sizeof(BOOL)
    dq  wa_bool_true                    ; pvExtension = &TRUE

.data?
align 8
g_tpm_prov  dq ?                        ; NCRYPT_PROV_HANDLE
g_tpm_key   dq ?                        ; NCRYPT_KEY_HANDLE
g_tpm_cbres dd ?                        ; bytes produced by encrypt/decrypt
align 8
public g_tpm_oaep, g_tpm_label, g_tpm_sha_ctx
g_tpm_oaep    db 24 dup (?)             ; BCRYPT_OAEP_PADDING_INFO
g_tpm_label   db 32 dup (?)             ; SHA-256("Vordr-TPM-v2" || vault_salt || reqhello)
g_tpm_sha_ctx db 128 dup (?)            ; SHA256_CTX scratch (108 bytes used)

; Cached webauthn.dll module + resolved entry points (process lifetime)
align 8
wa_hmod         dq ?
wa_fn_ver       dq ?
wa_fn_avail     dq ?
wa_fn_makecred  dq ?
wa_fn_getass    dq ?
wa_fn_freeatt   dq ?
wa_fn_freeass   dq ?
wa_fn_delcred   dq ?
wa_fn_getlist   dq ?
wa_fn_freelist  dq ?
wa_api_ver      dd ?
wa_init_done    dd ?

align 8
tbs_hmod        dq ?
tbs_fn_create   dq ?
tbs_fn_submit   dq ?
tbs_fn_close    dq ?
tbs_init_done   dd ?

; Non-secret WebAuthn request option structs (zeroed before and after every call)
align 8
g_wa_rp         db 32 dup (?)           ; WEBAUTHN_RP_ENTITY_INFORMATION
g_wa_user       db 40 dup (?)           ; WEBAUTHN_USER_ENTITY_INFORMATION
g_wa_cdata      db 24 dup (?)           ; WEBAUTHN_CLIENT_DATA
g_wa_hsalt      db 32 dup (?)           ; WEBAUTHN_HMAC_SECRET_SALT
g_wa_saltvals   db 24 dup (?)           ; WEBAUTHN_HMAC_SECRET_SALT_VALUES
g_wa_credex     db 32 dup (?)           ; WEBAUTHN_CREDENTIAL_EX
g_wa_pcredex    dq ?                    ; PWEBAUTHN_CREDENTIAL_EX[1]
g_wa_credlist   db 16 dup (?)           ; WEBAUTHN_CREDENTIAL_LIST
g_wa_makeopts   db 208 dup (?)          ; WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS (200B)
g_wa_getopts    db 208 dup (?)          ; WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS (200B)

ifdef PROBE_IO
; 4-slot software TPM simulator used ONLY inside cmd_tpmkat when hardware PCP is
; absent or in Windows TBS anti-hammering cooldown (0x80290409).
MOCK_SLOT_SZ    equ 232                 ; name[128] + pt64[64] + tag32[32] + used[4] + pad[4]
MOCK_SLOTS      equ 4
align 8
g_tpm_mock_slots db (MOCK_SLOT_SZ * MOCK_SLOTS) dup (?)
endif

.code

; tpm_compute_label() - compute g_tpm_label = SHA-256("Vordr-TPM-v2" || salt || LE32(reqhello!=0)).
tpm_compute_label proc frame
    FRAME_PROLOG 48
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
    FRAME_EPILOG
    ret
tpm_compute_label endp

; tpm_build_oaep(ecx = use_v2) - fill g_tpm_oaep.
;   use_v2 != 0: pbLabel = SHA-256("Vordr-TPM-v2" || g_hdr[VH_SALT..+32] || LE32(reqhello!=0))
;   use_v2 == 0: empty OAEP label { pszAlgId="SHA256", 0, 0 } (PCPKSP wire format)
public tpm_build_oaep
tpm_build_oaep proc frame
    FRAME_PROLOG 32
    test    ecx, ecx
    jz      tbo_legacy
    call    tpm_compute_label
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

; tpm_get_hwnd() -> rax = best non-NULL owner HWND for Windows Security / Hello UI.
tpm_get_hwnd proc frame
    FRAME_PROLOG 32
    mov     rax, qword ptr [g_secdesk_hwnd]
    test    rax, rax
    jnz     tgh_done
    mov     rax, qword ptr [g_vaulthwnd]
    test    rax, rax
    jnz     tgh_done
    call    GetForegroundWindow
    test    rax, rax
    jnz     tgh_done
    mov     rax, qword ptr [g_trayhwnd]
    test    rax, rax
    jnz     tgh_done
    call    GetDesktopWindow
tgh_done:
    FRAME_EPILOG
    ret
tpm_get_hwnd endp

; tpm_attach_hwnd(rcx = hKey) - best-effort attach parent HWND for Windows Hello UI.
tpm_attach_hwnd proc frame
    FRAME_PROLOG 64
    mov     qword ptr [rbp-16], rcx
    call    tpm_get_hwnd
    test    rax, rax
    jz      tah_done
    mov     qword ptr [rbp-24], rax
    WINCALL NCryptSetProperty, qword ptr [rbp-16], addr hwnd_prop, addr rbp-24, 8, 0
tah_done:
    FRAME_EPILOG
    ret
tpm_attach_hwnd endp

ifdef PROBE_IO
; tpm_wname_eq(rcx = w1, rdx = w2) -> eax = 1 equal / 0 different.
tpm_wname_eq proc
    xor     r8d, r8d
twe_lp:
    mov     ax, word ptr [rcx+r8*2]
    cmp     ax, word ptr [rdx+r8*2]
    jne     twe_no
    test    ax, ax
    jz      twe_yes
    inc     r8d
    cmp     r8d, 63
    jb      twe_lp
twe_yes:
    mov     eax, 1
    ret
twe_no:
    xor     eax, eax
    ret
tpm_wname_eq endp

; tpm_mock_seal(rcx=keyname, rdx=in32, r8=outblob, r9d=cap) -> eax = 256 / 0.
tpm_mock_seal proc frame
    FRAME_PROLOG 64
    cmp     r9d, 256
    jb      tms_fail
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    ; Find existing slot with matching keyname or first free slot
    lea     r10, [g_tpm_mock_slots]
    mov     dword ptr [rbp-36], -1              ; free_idx
    xor     r11d, r11d
tms_find:
    imul    eax, r11d, MOCK_SLOT_SZ
    lea     rdx, [r10+rax]
    cmp     dword ptr [rdx+224], 0
    jne     tms_chkname
    cmp     dword ptr [rbp-36], -1
    jne     tms_next
    mov     dword ptr [rbp-36], r11d
    jmp     tms_next
tms_chkname:
    mov     rcx, qword ptr [rbp-16]
    mov     qword ptr [rbp-48], r11
    call    tpm_wname_eq
    mov     r11, qword ptr [rbp-48]
    lea     r10, [g_tpm_mock_slots]
    test    eax, eax
    jnz     tms_found
tms_next:
    inc     r11d
    cmp     r11d, MOCK_SLOTS
    jb      tms_find
    mov     r11d, dword ptr [rbp-36]
    cmp     r11d, -1
    jne     tms_found
    xor     r11d, r11d
tms_found:
    imul    eax, r11d, MOCK_SLOT_SZ
    lea     r10, [g_tpm_mock_slots]
    add     r10, rax
    mov     qword ptr [rbp-48], r10             ; slot ptr
    ; Copy keyname (up to 63 wide chars + NUL)
    mov     rcx, qword ptr [rbp-16]
    xor     r8d, r8d
tms_cpn:
    mov     ax, word ptr [rcx+r8*2]
    mov     word ptr [r10+r8*2], ax
    test    ax, ax
    jz      tms_cpnd
    inc     r8d
    cmp     r8d, 63
    jb      tms_cpn
    mov     word ptr [r10+126], 0
tms_cpnd:
    ; Build pt64 = in32 || SHA-256(in32 || g_tpm_label) at slot+128
    call    tpm_compute_label
    mov     r10, qword ptr [rbp-48]
    mov     r11, qword ptr [rbp-24]
    xor     ecx, ecx
tms_cpk:
    mov     al, byte ptr [r11+rcx]
    mov     byte ptr [r10+128+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      tms_cpk
    lea     rcx, [g_tpm_sha_ctx]
    call    sha256_init
    mov     r10, qword ptr [rbp-48]
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [r10+128]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [g_tpm_label]
    mov     r8d, 32
    call    sha256_update
    mov     r10, qword ptr [rbp-48]
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [r10+160]
    call    sha256_final
    ; Generate fresh 256-byte mock ciphertext in outblob and store SHA-256(ct256) in slot+192
    mov     rcx, qword ptr [rbp-32]
    mov     edx, 256
    call    rng_fill
    test    eax, eax
    jz      tms_fail
    lea     rcx, [g_tpm_sha_ctx]
    call    sha256_init
    lea     rcx, [g_tpm_sha_ctx]
    mov     rdx, qword ptr [rbp-32]
    mov     r8d, 256
    call    sha256_update
    mov     r10, qword ptr [rbp-48]
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [r10+192]
    call    sha256_final
    mov     r10, qword ptr [rbp-48]
    mov     dword ptr [r10+224], 1
    lea     rcx, [g_tpm_sha_ctx]
    mov     edx, 128
    call    secure_zero
    lea     rcx, [g_tpm_label]
    mov     edx, 32
    call    secure_zero
    mov     eax, 256
    FRAME_EPILOG
    ret
tms_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_mock_seal endp

; tpm_mock_unseal(rcx=keyname, rdx=blob, r8d=bloblen, r9=out32) -> eax = 1 / 0.
tpm_mock_unseal proc frame
    FRAME_PROLOG 128
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     dword ptr [rbp-32], r8d
    mov     qword ptr [rbp-40], r9
    cmp     r8d, 256
    jne     tmu_fail
    test    r9, r9
    jz      tmu_fail
    xor     r11d, r11d
tmu_find:
    imul    eax, r11d, MOCK_SLOT_SZ
    lea     r10, [g_tpm_mock_slots]
    add     r10, rax
    cmp     dword ptr [r10+224], 0
    je      tmu_next
    mov     qword ptr [rbp-48], r10
    mov     qword ptr [rbp-56], r11
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, r10
    call    tpm_wname_eq
    mov     r11, qword ptr [rbp-56]
    test    eax, eax
    jnz     tmu_got
tmu_next:
    inc     r11d
    cmp     r11d, MOCK_SLOTS
    jb      tmu_find
    jmp     tmu_fail
tmu_got:
    ; Verify SHA-256(blob[256]) == slot.tag32
    lea     rcx, [g_tpm_sha_ctx]
    call    sha256_init
    lea     rcx, [g_tpm_sha_ctx]
    mov     rdx, qword ptr [rbp-24]
    mov     r8d, 256
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [rbp-96]
    call    sha256_final
    mov     r10, qword ptr [rbp-48]
    lea     rcx, [rbp-96]
    lea     rdx, [r10+192]
    mov     r8d, 32
    call    ct_memcmp
    test    eax, eax
    jnz     tmu_fail
    ; Verify context label SHA-256(pt64[0..31] || g_tpm_label) == pt64[32..63]
    call    tpm_compute_label
    lea     rcx, [g_tpm_sha_ctx]
    call    sha256_init
    mov     r10, qword ptr [rbp-48]
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [r10+128]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [g_tpm_label]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [rbp-96]
    call    sha256_final
    mov     r10, qword ptr [rbp-48]
    lea     rcx, [rbp-96]
    lea     rdx, [r10+160]
    mov     r8d, 32
    call    ct_memcmp
    test    eax, eax
    jnz     tmu_fail
    mov     r10, qword ptr [rbp-48]
    mov     r11, qword ptr [rbp-40]
    xor     ecx, ecx
tmu_cp:
    mov     al, byte ptr [r10+128+rcx]
    mov     byte ptr [r11+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      tmu_cp
    lea     rcx, [rbp-96]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_tpm_sha_ctx]
    mov     edx, 128
    call    secure_zero
    lea     rcx, [g_tpm_label]
    mov     edx, 32
    call    secure_zero
    mov     eax, 1
    FRAME_EPILOG
    ret
tmu_fail:
    lea     rcx, [rbp-96]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_tpm_sha_ctx]
    mov     edx, 128
    call    secure_zero
    lea     rcx, [g_tpm_label]
    mov     edx, 32
    call    secure_zero
    mov     rcx, qword ptr [rbp-40]
    test    rcx, rcx
    jz      @F
    mov     edx, 32
    call    secure_zero
@@: xor     eax, eax
    FRAME_EPILOG
    ret
tpm_mock_unseal endp

; tpm_mock_delete(rcx = keyname) -> eax = 1 / 0.
tpm_mock_delete proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    xor     r11d, r11d
tmd_lp:
    imul    eax, r11d, MOCK_SLOT_SZ
    lea     r10, [g_tpm_mock_slots]
    add     r10, rax
    cmp     dword ptr [r10+224], 0
    je      tmd_nx
    mov     qword ptr [rbp-24], r10
    mov     qword ptr [rbp-32], r11
    mov     rcx, qword ptr [rbp-16]
    mov     rdx, r10
    call    tpm_wname_eq
    mov     r11, qword ptr [rbp-32]
    test    eax, eax
    jz      tmd_nx
    mov     rcx, qword ptr [rbp-24]
    mov     edx, MOCK_SLOT_SZ
    call    secure_zero
    mov     eax, 1
    FRAME_EPILOG
    ret
tmd_nx:
    inc     r11d
    cmp     r11d, MOCK_SLOTS
    jb      tmd_lp
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_mock_delete endp
endif

; ===========================================================================
; tpm_available() -> eax = 1 if the platform crypto provider opens, else 0.
; ===========================================================================
public tpm_available
tpm_available proc frame
    FRAME_PROLOG 64
ifdef PROBE_IO
    cmp     dword ptr [g_tpm_mock_mode], 0
    je      @F
    mov     eax, 1
    FRAME_EPILOG
    ret
@@:
endif
    mov     qword ptr [g_tpm_prov], 0
    WINCALL NCryptOpenStorageProvider, addr g_tpm_prov, addr tpm_prov, 0
    test    eax, eax
    jnz     ta_no
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
    mov     qword ptr [g_tpm_prov], 0
    mov     eax, 1
    FRAME_EPILOG
    ret
ta_no:
    mov     qword ptr [g_tpm_prov], 0
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
    mov     dword ptr [g_tpm_last_err], 0
ifdef PROBE_IO
    cmp     dword ptr [g_tpm_mock_mode], 0
    je      @F
    call    tpm_mock_seal
    FRAME_EPILOG
    ret
@@:
endif
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     dword ptr [rbp-48], r9d
    mov     qword ptr [g_tpm_prov], 0
    mov     qword ptr [g_tpm_key], 0
    mov     dword ptr [g_tpm_cbres], 0
    WINCALL NCryptOpenStorageProvider, addr g_tpm_prov, addr tpm_prov, 0
    test    eax, eax
    jnz     ts_rec_fail
    WINCALL NCryptCreatePersistedKey, qword ptr [g_tpm_prov], addr g_tpm_key, \
            addr tpm_alg, qword ptr [rbp-24], 0, NCRYPT_OVERWRITE_KEY_FLAG
    test    eax, eax
    jnz     ts_rec_freeprov
    WINCALL NCryptSetProperty, qword ptr [g_tpm_key], addr tpm_lenprop, \
            addr tpm_keylen, 4, 0
    test    eax, eax
    jnz     ts_rec_delkey
    WINCALL NCryptSetProperty, qword ptr [g_tpm_key], addr key_usage_prop, \
            addr tpm_keyusage, 4, 0
    test    eax, eax
    jz      ts_chk_exp
    cmp     eax, 80090029h              ; NTE_NOT_SUPPORTED on fixed-usage PCP providers
    jne     ts_rec_delkey
ts_chk_exp:
    WINCALL NCryptSetProperty, qword ptr [g_tpm_key], addr export_pol_prop, \
            addr tpm_exppol, 4, 0
    test    eax, eax
    jz      ts_pol_ok
    cmp     eax, 80090029h              ; NTE_NOT_SUPPORTED when TPM hardware fixes export=0
    jne     ts_rec_delkey
ts_pol_ok:
    mov     dword ptr [rbp-56], NCRYPT_SILENT_FLAG
    mov     dword ptr [rbp-64], NCRYPT_OAEP_SILENT
    cmp     dword ptr [g_tpm_reqhello], 0
    je      ts_finalize
    mov     rcx, qword ptr [g_tpm_key]
    call    tpm_attach_hwnd
    WINCALL NCryptSetProperty, qword ptr [g_tpm_key], addr ui_policy_prop, \
            addr g_ui_policy, 32, 0
    test    eax, eax
    jnz     ts_rec_delkey
    mov     dword ptr [rbp-56], 0
    mov     dword ptr [rbp-64], NCRYPT_PAD_OAEP
ts_finalize:
    WINCALL NCryptFinalizeKey, qword ptr [g_tpm_key], dword ptr [rbp-56]
    test    eax, eax
    jnz     ts_rec_delkey
    call    tpm_compute_label
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
    test    eax, eax
    jz      @F
    mov     dword ptr [g_tpm_last_err], eax
@@: lea     rcx, [rbp-128]
    mov     edx, 64
    call    secure_zero
    lea     rcx, [g_tpm_sha_ctx]
    mov     edx, 128
    call    secure_zero
    lea     rcx, [g_tpm_label]
    mov     edx, 32
    call    secure_zero
    cmp     dword ptr [rbp-52], 0
    jne     ts_delkey
    mov     eax, dword ptr [g_tpm_cbres]
    test    eax, eax
    jz      ts_delkey
    cmp     eax, dword ptr [rbp-48]
    ja      ts_delkey
    WINCALL NCryptFreeObject, qword ptr [g_tpm_key]
    mov     qword ptr [g_tpm_key], 0
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
    mov     qword ptr [g_tpm_prov], 0
    mov     eax, dword ptr [g_tpm_cbres]
    FRAME_EPILOG
    ret
ts_rec_delkey:
    mov     dword ptr [g_tpm_last_err], eax
ts_delkey:
    WINCALL NCryptDeleteKey, qword ptr [g_tpm_key], 0
    test    eax, eax
    jz      ts_keygone
    WINCALL NCryptFreeObject, qword ptr [g_tpm_key]
ts_keygone:
    mov     qword ptr [g_tpm_key], 0
    jmp     ts_freeprov
ts_rec_freeprov:
    mov     dword ptr [g_tpm_last_err], eax
ts_freeprov:
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
    mov     qword ptr [g_tpm_prov], 0
    jmp     ts_fail
ts_rec_fail:
    mov     dword ptr [g_tpm_last_err], eax
ts_fail:
    mov     qword ptr [g_tpm_prov], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_seal endp

; ===========================================================================
; tpm_unseal(rcx=keyname, rdx=blob, r8d=bloblen, r9=out32) -> eax = 1 / 0.
; ===========================================================================
public tpm_unseal
tpm_unseal proc frame
    FRAME_PROLOG 224
    ; [rbp-24]=keyname [rbp-32]=blob [rbp-40]=bloblen [rbp-48]=out32
    ; [rbp-56]=OpenKey flag [rbp-64]=Decrypt flag
    ; [rbp-128..-65]=pt64  [rbp-160..-129]=exp_tag
    mov     dword ptr [g_tpm_last_err], 0
ifdef PROBE_IO
    cmp     dword ptr [g_tpm_mock_mode], 0
    je      @F
    call    tpm_mock_unseal
    FRAME_EPILOG
    ret
@@:
endif
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
    jnz     tu_rec_fail
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
    jnz     tu_rec_freeprov
    cmp     dword ptr [g_tpm_reqhello], 0
    je      tu_dec
    mov     rcx, qword ptr [g_tpm_key]
    call    tpm_attach_hwnd
tu_dec:
    call    tpm_compute_label
    xor     ecx, ecx
    call    tpm_build_oaep
    lea     r10, [rbp-128]
    WINCALL NCryptDecrypt, qword ptr [g_tpm_key], qword ptr [rbp-32], dword ptr [rbp-40], \
            addr g_tpm_oaep, r10, 64, \
            addr g_tpm_cbres, dword ptr [rbp-64]
    test    eax, eax
    jnz     tu_rec_freekey
    cmp     dword ptr [g_tpm_cbres], 64
    jne     tu_freekey
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
    mov     qword ptr [g_tpm_key], 0
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
    mov     qword ptr [g_tpm_prov], 0
    mov     eax, 1
    FRAME_EPILOG
    ret
tu_rec_freekey:
    mov     dword ptr [g_tpm_last_err], eax
tu_freekey:
    WINCALL NCryptFreeObject, qword ptr [g_tpm_key]
    mov     qword ptr [g_tpm_key], 0
    jmp     tu_freeprov
tu_rec_freeprov:
    mov     dword ptr [g_tpm_last_err], eax
tu_freeprov:
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
    mov     qword ptr [g_tpm_prov], 0
    jmp     tu_fail
tu_rec_fail:
    mov     dword ptr [g_tpm_last_err], eax
tu_fail:
    mov     qword ptr [g_tpm_prov], 0
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
ifdef PROBE_IO
    cmp     dword ptr [g_tpm_mock_mode], 0
    je      @F
    call    tpm_mock_delete
    FRAME_EPILOG
    ret
@@:
endif
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
@@: WINCALL NCryptDeleteKey, qword ptr [g_tpm_key], 0
    mov     dword ptr [rbp-40], eax
    test    eax, eax
    jz      td_deleted
    WINCALL NCryptFreeObject, qword ptr [g_tpm_key]
td_deleted:
    mov     qword ptr [g_tpm_key], 0
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
    mov     qword ptr [g_tpm_prov], 0
    xor     eax, eax
    cmp     dword ptr [rbp-40], 0
    sete    al
    FRAME_EPILOG
    ret
td_freeprov:
    mov     qword ptr [g_tpm_key], 0
    WINCALL NCryptFreeObject, qword ptr [g_tpm_prov]
    mov     qword ptr [g_tpm_prov], 0
td_fail:
    mov     qword ptr [g_tpm_prov], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_delete endp

; ===========================================================================
; Windows Hello FIDO2 PRF ("hmac-secret") via webauthn.dll (unpackaged Win32)
; ---------------------------------------------------------------------------
; Works natively in standalone Win32 builds (no MSIX identity required) and
; prompts Windows Hello Face, Fingerprint, or Windows Hello PIN via Windows
; Security while keeping the credential non-exportable inside the platform
; authenticator.
;
; WHLO blob wire format (64 + cred_len bytes, 1 <= cred_len <= 400):
;   +0  u32  "WHLO" (4F4C4857h)
;   +4  u16  version = 1
;   +6  u16  cred_len
;   +8  u8   prf_salt[32]
;   +40 u8   verify_tag[24] = SHA-256("Vordr-Hello-Tag-v1" || prf_out || g_tpm_label)[0..23]
;   +64 u8   cred_id[cred_len]
; ===========================================================================

; wa_load() -> eax = 1 if webauthn.dll (API >= 4) loaded, else 0.
wa_load proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [wa_init_done], 0
    je      wal_do
    xor     eax, eax
    cmp     dword ptr [wa_api_ver], 4
    setae   al
    FRAME_EPILOG
    ret
wal_do:
    mov     dword ptr [wa_init_done], 1
    mov     dword ptr [wa_api_ver], 0
    WINCALL LoadLibraryExW, addr wa_dll_w, 0, LOAD_LIB_SYS32
    test    rax, rax
    jz      wal_no
    mov     qword ptr [wa_hmod], rax
    WINCALL GetProcAddress, qword ptr [wa_hmod], addr wa_n_ver
    test    rax, rax
    jz      wal_no
    mov     qword ptr [wa_fn_ver], rax
    WINCALL GetProcAddress, qword ptr [wa_hmod], addr wa_n_avail
    test    rax, rax
    jz      wal_no
    mov     qword ptr [wa_fn_avail], rax
    WINCALL GetProcAddress, qword ptr [wa_hmod], addr wa_n_make
    test    rax, rax
    jz      wal_no
    mov     qword ptr [wa_fn_makecred], rax
    WINCALL GetProcAddress, qword ptr [wa_hmod], addr wa_n_get
    test    rax, rax
    jz      wal_no
    mov     qword ptr [wa_fn_getass], rax
    WINCALL GetProcAddress, qword ptr [wa_hmod], addr wa_n_freeatt
    test    rax, rax
    jz      wal_no
    mov     qword ptr [wa_fn_freeatt], rax
    WINCALL GetProcAddress, qword ptr [wa_hmod], addr wa_n_freeass
    test    rax, rax
    jz      wal_no
    mov     qword ptr [wa_fn_freeass], rax
    WINCALL GetProcAddress, qword ptr [wa_hmod], addr wa_n_delcred
    mov     qword ptr [wa_fn_delcred], rax
    WINCALL GetProcAddress, qword ptr [wa_hmod], addr wa_n_getlist
    mov     qword ptr [wa_fn_getlist], rax
    WINCALL GetProcAddress, qword ptr [wa_hmod], addr wa_n_freelist
    mov     qword ptr [wa_fn_freelist], rax
    mov     rax, qword ptr [wa_fn_ver]
    call    rax
    mov     dword ptr [wa_api_ver], eax
    cmp     eax, 4
    jb      wal_no
    mov     eax, 1
    FRAME_EPILOG
    ret
wal_no:
    mov     dword ptr [wa_api_ver], 0
    xor     eax, eax
    FRAME_EPILOG
    ret
wa_load endp

; wa_probe_winhello_aaguid() -> eax = 1 found WH AAGUID / 0 enumerated without WH / -1 N/A.
wa_probe_winhello_aaguid proc frame
    FRAME_PROLOG 64
    cmp     dword ptr [wa_api_ver], 9
    jb      wpa_na
    cmp     qword ptr [wa_fn_getlist], 0
    je      wpa_na
    cmp     qword ptr [wa_fn_freelist], 0
    je      wpa_na
    mov     qword ptr [rbp-16], 0               ; pAuthList
    xor     ecx, ecx                            ; pGetAuthenticatorListOptions = NULL
    lea     rdx, [rbp-16]
    mov     rax, qword ptr [wa_fn_getlist]
    call    rax
    test    eax, eax
    jnz     wpa_na
    mov     r10, qword ptr [rbp-16]
    test    r10, r10
    jz      wpa_na
    mov     ecx, dword ptr [r10+0]              ; cAuthenticatorDetails
    mov     r11, qword ptr [r10+8]              ; ppAuthenticatorDetails
    test    ecx, ecx
    jz      wpa_free_na
    test    r11, r11
    jz      wpa_free_na
    mov     dword ptr [rbp-20], ecx
    mov     qword ptr [rbp-32], r11
    mov     dword ptr [rbp-24], 0               ; idx
wpa_lp:
    mov     eax, dword ptr [rbp-24]
    cmp     eax, dword ptr [rbp-20]
    jae     wpa_notfound
    mov     r11, qword ptr [rbp-32]
    mov     r10, qword ptr [r11+rax*8]          ; PWEBAUTHN_AUTHENTICATOR_DETAILS
    test    r10, r10
    jz      wpa_nx
    cmp     dword ptr [r10+4], 16               ; cbAuthenticatorId == 16
    jne     wpa_nx
    mov     rcx, qword ptr [r10+8]              ; pbAuthenticatorId
    test    rcx, rcx
    jz      wpa_nx
    lea     rdx, [wa_wh_aaguid]
    mov     r8d, 16
    call    ct_memcmp
    test    eax, eax
    jz      wpa_found
wpa_nx:
    inc     dword ptr [rbp-24]
    jmp     wpa_lp
wpa_found:
    mov     rcx, qword ptr [rbp-16]
    mov     rax, qword ptr [wa_fn_freelist]
    call    rax
    mov     eax, 1
    FRAME_EPILOG
    ret
wpa_notfound:
    mov     rcx, qword ptr [rbp-16]
    mov     rax, qword ptr [wa_fn_freelist]
    call    rax
    xor     eax, eax
    FRAME_EPILOG
    ret
wpa_free_na:
    mov     rcx, qword ptr [rbp-16]
    mov     rax, qword ptr [wa_fn_freelist]
    call    rax
wpa_na:
    mov     eax, -1
    FRAME_EPILOG
    ret
wa_probe_winhello_aaguid endp

; tpm_hello_available() -> eax = 1 iff Windows Hello platform authenticator is provisioned.
public tpm_hello_available
tpm_hello_available proc frame
    FRAME_PROLOG 48
    call    wa_load
    test    eax, eax
    jz      tha_no
    mov     dword ptr [rbp-16], 0               ; bAvailable
    lea     rcx, [rbp-16]
    mov     rax, qword ptr [wa_fn_avail]
    call    rax
    test    eax, eax
    jnz     tha_no
    cmp     dword ptr [rbp-16], 0
    je      tha_no
    call    wa_probe_winhello_aaguid
    test    eax, eax                            ; 0 = enumerated list had only 3rd-party passkeys
    jz      tha_no
    mov     eax, 1
    FRAME_EPILOG
    ret
tha_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_hello_available endp

; wa_compute_hmac_in(rcx = prf_salt32, rdx = out_hmac_in32)
;   Computes SHA-256(prf_salt[32] || g_tpm_label[32]) using current vault salt (mode=0).
wa_compute_hmac_in proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     eax, dword ptr [g_tpm_reqhello]
    mov     dword ptr [rbp-28], eax
    mov     dword ptr [g_tpm_reqhello], 0
    call    tpm_compute_label
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [g_tpm_reqhello], eax
    lea     rcx, [g_tpm_sha_ctx]
    call    sha256_init
    lea     rcx, [g_tpm_sha_ctx]
    mov     rdx, qword ptr [rbp-16]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [g_tpm_label]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    mov     rdx, qword ptr [rbp-24]
    call    sha256_final
    FRAME_EPILOG
    ret
wa_compute_hmac_in endp

; wa_derive_hello_mats(rcx = prf_out32, rdx = out_key32, r8 = out_tag32)
;   Derives domain-separated hello_secret[32] and tag[32] from prf_out || g_tpm_label.
wa_derive_hello_mats proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     qword ptr [rbp-32], r8
    ; out_key32 = SHA-256("Vordr-Hello-Key-v1" || prf_out[32] || g_tpm_label[32])
    lea     rcx, [g_tpm_sha_ctx]
    call    sha256_init
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [wa_key_dom]
    mov     r8d, wa_key_dom_len
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    mov     rdx, qword ptr [rbp-16]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [g_tpm_label]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    mov     rdx, qword ptr [rbp-24]
    call    sha256_final
    ; out_tag32 = SHA-256("Vordr-Hello-Tag-v1" || prf_out[32] || g_tpm_label[32])
    lea     rcx, [g_tpm_sha_ctx]
    call    sha256_init
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [wa_tag_dom]
    mov     r8d, wa_tag_dom_len
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    mov     rdx, qword ptr [rbp-16]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    lea     rdx, [g_tpm_label]
    mov     r8d, 32
    call    sha256_update
    lea     rcx, [g_tpm_sha_ctx]
    mov     rdx, qword ptr [rbp-32]
    call    sha256_final
    FRAME_EPILOG
    ret
wa_derive_hello_mats endp

; wa_wipe_structs() - scrub WebAuthn transient option buffers + label/sha scratch.
wa_wipe_structs proc frame
    FRAME_PROLOG 32
    lea     rcx, [g_wa_makeopts]
    mov     edx, 208
    call    secure_zero
    lea     rcx, [g_wa_getopts]
    mov     edx, 208
    call    secure_zero
    lea     rcx, [g_wa_hsalt]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_wa_saltvals]
    mov     edx, 24
    call    secure_zero
    lea     rcx, [g_wa_credex]
    mov     edx, 32
    call    secure_zero
    lea     rcx, [g_tpm_sha_ctx]
    mov     edx, 128
    call    secure_zero
    lea     rcx, [g_tpm_label]
    mov     edx, 32
    call    secure_zero
    FRAME_EPILOG
    ret
wa_wipe_structs endp

; wa_get_prf_assertion(rcx = cred_ptr, edx = cred_len, r8 = hmac_in32, r9 = out_prf32)
;   -> eax = 1 ok / 0 fail.
wa_get_prf_assertion proc frame
    FRAME_PROLOG 96
    ; [rbp-16]=cred_ptr [rbp-20]=cred_len [rbp-32]=hmac_in32 [rbp-40]=out_prf32
    ; [rbp-48]=pAssertion [rbp-52]=has_wh
    mov     qword ptr [rbp-16], rcx
    mov     dword ptr [rbp-20], edx
    mov     qword ptr [rbp-32], r8
    mov     qword ptr [rbp-40], r9
    mov     qword ptr [rbp-48], 0
    call    wa_probe_winhello_aaguid
    mov     dword ptr [rbp-52], eax

    lea     rcx, [g_wa_getopts]
    mov     edx, 208
    call    secure_zero

    ; ClientData (webauthn.get)
    lea     r10, [g_wa_cdata]
    mov     dword ptr [r10+0], 1
    mov     dword ptr [r10+4], wa_cjson_get_len
    lea     rax, [wa_cjson_get]
    mov     qword ptr [r10+8], rax
    lea     rax, [wa_hashalg_w]
    mov     qword ptr [r10+16], rax

    ; AllowCredentialList (exact enrolled credential, internal platform transport)
    lea     r10, [g_wa_credex]
    mov     dword ptr [r10+0], 1
    mov     eax, dword ptr [rbp-20]
    mov     dword ptr [r10+4], eax
    mov     rax, qword ptr [rbp-16]
    mov     qword ptr [r10+8], rax
    lea     rax, [wa_credtype_w]
    mov     qword ptr [r10+16], rax
    mov     dword ptr [r10+24], 10h             ; WEBAUTHN_CTAP_TRANSPORT_INTERNAL
    mov     dword ptr [r10+28], 0
    mov     qword ptr [g_wa_pcredex], r10
    lea     r10, [g_wa_credlist]
    mov     dword ptr [r10+0], 1
    mov     dword ptr [r10+4], 0
    lea     rax, [g_wa_pcredex]
    mov     qword ptr [r10+8], rax

    ; HmacSecretSalt + Values
    lea     r10, [g_wa_hsalt]
    mov     dword ptr [r10+0], 32
    mov     dword ptr [r10+4], 0
    mov     rax, qword ptr [rbp-32]
    mov     qword ptr [r10+8], rax
    mov     qword ptr [r10+16], 0
    mov     qword ptr [r10+24], 0
    lea     r11, [g_wa_saltvals]
    mov     qword ptr [r11+0], r10              ; pGlobalHmacSalt
    mov     qword ptr [r11+8], 0
    mov     qword ptr [r11+16], 0

    ; WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
    lea     r10, [g_wa_getopts]
    mov     dword ptr [r10+0], 6                ; VERSION_6 (supports pHmacSecretSaltValues)
    mov     dword ptr [r10+4], 60000            ; 60s timeout
    mov     dword ptr [r10+40], 1               ; PLATFORM attachment
    mov     dword ptr [r10+44], 1               ; USER_VERIFICATION_REQUIRED
    lea     rax, [g_wa_credlist]
    mov     qword ptr [r10+80], rax             ; pAllowCredentialList
    lea     rax, [g_wa_saltvals]
    mov     qword ptr [r10+104], rax            ; pHmacSecretSaltValues
    cmp     dword ptr [rbp-52], 1
    jne     wgpa_call
    mov     dword ptr [r10+0], 9                ; VERSION_9: pin to Windows Hello AAGUID
    mov     dword ptr [r10+184], 16
    lea     rax, [wa_wh_aaguid]
    mov     qword ptr [r10+192], rax

wgpa_call:
    call    tpm_get_hwnd
    mov     rcx, rax
    lea     rdx, [wa_rpid_w]
    lea     r8, [g_wa_cdata]
    lea     r9, [g_wa_getopts]
    lea     rax, [rbp-48]
    mov     qword ptr [rsp+32], rax
    mov     rax, qword ptr [wa_fn_getass]
    call    rax
    test    eax, eax
    jz      wgpa_got
    mov     dword ptr [g_tpm_last_err], eax
    jmp     wgpa_fail

wgpa_got:
    mov     r10, qword ptr [rbp-48]             ; PWEBAUTHN_ASSERTION
    test    r10, r10
    jz      wgpa_fail
    cmp     dword ptr [r10+0], 3                ; WEBAUTHN_ASSERTION_VERSION_3+
    jb      wgpa_free_fail
    mov     r11, qword ptr [r10+112]            ; pHmacSecret
    test    r11, r11
    jz      wgpa_free_fail
    cmp     dword ptr [r11+0], 32               ; cbFirst == 32
    jne     wgpa_free_fail
    mov     r10, qword ptr [r11+8]              ; pbFirst
    test    r10, r10
    jz      wgpa_free_fail
    mov     r11, qword ptr [rbp-40]
    xor     ecx, ecx
wgpa_cp:
    mov     al, byte ptr [r10+rcx]
    mov     byte ptr [r11+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      wgpa_cp
    mov     rcx, qword ptr [rbp-48]
    mov     rax, qword ptr [wa_fn_freeass]
    call    rax
    mov     eax, 1
    FRAME_EPILOG
    ret

wgpa_free_fail:
    mov     rcx, qword ptr [rbp-48]
    mov     rax, qword ptr [wa_fn_freeass]
    call    rax
wgpa_fail:
    xor     eax, eax
    FRAME_EPILOG
    ret
wa_get_prf_assertion endp

; tpm_hello_seal(rcx=out_sec32, rdx=outblob, r8d=cap) -> eax = blob len (0=fail/cancelled).
;   Creates a Windows Hello FIDO2 platform credential with PRF ("hmac-secret"),
;   derives out_sec32[32] from the live 32-byte PRF output, and writes the WHLO
;   envelope into outblob[0..64+cred_len-1].
public tpm_hello_seal
tpm_hello_seal proc frame
    FRAME_PROLOG 256
    ; [rbp-16]=out_sec32 [rbp-24]=outblob [rbp-32]=cap [rbp-36]=cred_len
    ; [rbp-48]=pAttestation [rbp-52]=has_wh
    ; [rbp-96..-65]=prf_salt[32]  [rbp-128..-97]=hmac_in[32]
    ; [rbp-160..-129]=prf_out[32] [rbp-192..-161]=tag_tmp[32]
    mov     dword ptr [g_tpm_last_err], 0
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    mov     dword ptr [rbp-32], r8d
    mov     qword ptr [rbp-48], 0
    lea     rcx, [rbp-192]
    mov     edx, 128
    call    secure_zero
    cmp     dword ptr [rbp-32], WHLO_HDR_LEN + 1
    jb      ths_fail
    call    tpm_hello_available
    test    eax, eax
    jz      ths_fail
    call    wa_probe_winhello_aaguid
    mov     dword ptr [rbp-52], eax

    ; 1) Generate random prf_salt[32] and compute hmac_in[32]
    lea     rcx, [rbp-96]
    mov     edx, 32
    call    rng_fill
    test    eax, eax
    jz      ths_fail
    lea     rcx, [rbp-96]
    lea     rdx, [rbp-128]
    call    wa_compute_hmac_in

    ; 2) Populate MakeCredential structs
    lea     rcx, [g_wa_makeopts]
    mov     edx, 208
    call    secure_zero

    lea     r10, [g_wa_rp]
    mov     dword ptr [r10+0], 1
    mov     dword ptr [r10+4], 0
    lea     rax, [wa_rpid_w]
    mov     qword ptr [r10+8], rax
    lea     rax, [wa_rpname_w]
    mov     qword ptr [r10+16], rax
    mov     qword ptr [r10+24], 0

    lea     r10, [g_wa_user]
    mov     dword ptr [r10+0], 1
    mov     dword ptr [r10+4], 16
    lea     rax, [g_hdr + VH_KCV]
    mov     qword ptr [r10+8], rax
    lea     rax, [wa_uname_w]
    mov     qword ptr [r10+16], rax
    mov     qword ptr [r10+24], 0
    lea     rax, [wa_udisp_w]
    mov     qword ptr [r10+32], rax

    lea     r10, [g_wa_cdata]
    mov     dword ptr [r10+0], 1
    mov     dword ptr [r10+4], wa_cjson_make_len
    lea     rax, [wa_cjson_make]
    mov     qword ptr [r10+8], rax
    lea     rax, [wa_hashalg_w]
    mov     qword ptr [r10+16], rax

    lea     r10, [g_wa_hsalt]
    mov     dword ptr [r10+0], 32
    mov     dword ptr [r10+4], 0
    lea     rax, [rbp-128]
    mov     qword ptr [r10+8], rax
    mov     qword ptr [r10+16], 0
    mov     qword ptr [r10+24], 0

    lea     r10, [g_wa_makeopts]
    ; Select highest supported MakeCredential version (5 on API 4..5, 6 on 6..7, 8 on >=8, 9 with WH AAGUID)
    mov     eax, dword ptr [wa_api_ver]
    mov     ecx, 5
    cmp     eax, 6
    jb      ths_setver
    mov     ecx, 6
    cmp     eax, 8
    jb      ths_setver
    mov     ecx, 8
    cmp     dword ptr [rbp-52], 1
    jne     ths_setver
    mov     ecx, 9
    mov     dword ptr [r10+184], 16
    lea     rdx, [wa_wh_aaguid]
    mov     qword ptr [r10+192], rdx
ths_setver:
    mov     dword ptr [r10+0], ecx
    mov     dword ptr [r10+4], 60000            ; 60s timeout
    mov     dword ptr [r10+24], 1               ; Extensions.cExtensions = 1
    lea     rax, [wa_ext_arr]
    mov     qword ptr [r10+32], rax             ; Extensions.pExtensions
    mov     dword ptr [r10+40], 1               ; PLATFORM attachment
    mov     dword ptr [r10+44], 1               ; bRequireResidentKey = TRUE (discoverable Hello passkey)
    mov     dword ptr [r10+48], 1               ; USER_VERIFICATION_REQUIRED
    mov     dword ptr [r10+52], 1               ; ATTESTATION_CONVEYANCE_PREFERENCE_NONE
    mov     dword ptr [r10+88], 1               ; bPreferResidentKey = TRUE
    mov     dword ptr [r10+96], 1               ; bEnablePrf = TRUE
    lea     rax, [g_wa_hsalt]
    mov     qword ptr [r10+128], rax            ; pPRFGlobalEval (v8+)

    ; 3) Invoke WebAuthNAuthenticatorMakeCredential (7 args)
    call    tpm_get_hwnd
    mov     rcx, rax
    lea     rdx, [g_wa_rp]
    lea     r8, [g_wa_user]
    lea     r9, [wa_cose_params]
    lea     rax, [g_wa_cdata]
    mov     qword ptr [rsp+32], rax
    lea     rax, [g_wa_makeopts]
    mov     qword ptr [rsp+40], rax
    lea     rax, [rbp-48]
    mov     qword ptr [rsp+48], rax
    mov     rax, qword ptr [wa_fn_makecred]
    call    rax
    test    eax, eax
    jz      ths_made
    mov     dword ptr [g_tpm_last_err], eax
    jmp     ths_fail

ths_made:
    mov     r10, qword ptr [rbp-48]             ; PWEBAUTHN_CREDENTIAL_ATTESTATION
    test    r10, r10
    jz      ths_fail
    mov     eax, dword ptr [r10+80]             ; cbCredentialId
    cmp     eax, 1
    jb      ths_free_fail
    cmp     eax, WHLO_MAX_CRED
    ja      ths_free_fail
    lea     ecx, [rax + WHLO_HDR_LEN]
    cmp     ecx, dword ptr [rbp-32]
    ja      ths_free_fail
    cmp     qword ptr [r10+88], 0               ; pbCredentialId
    je      ths_free_fail
    mov     dword ptr [rbp-36], eax             ; cred_len

    ; Copy cred_id into outblob + 64 now
    mov     r11, qword ptr [rbp-24]
    add     r11, WHLO_HDR_LEN
    mov     rdx, qword ptr [r10+88]
    xor     ecx, ecx
ths_cpcred:
    mov     r8b, byte ptr [rdx+rcx]
    mov     byte ptr [r11+rcx], r8b
    inc     ecx
    cmp     ecx, eax
    jb      ths_cpcred

    ; Did MakeCredential return inline pPRFGlobalEval output at pAtt->pHmacSecret (+144)?
    cmp     dword ptr [r10+0], 7                ; WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_7
    jb      ths_need_assert
    mov     r11, qword ptr [r10+144]            ; pHmacSecret
    test    r11, r11
    jz      ths_need_assert
    cmp     dword ptr [r11+0], 32               ; cbFirst == 32
    jne     ths_need_assert
    mov     rdx, qword ptr [r11+8]              ; pbFirst
    test    rdx, rdx
    jz      ths_need_assert
    lea     r8, [rbp-160]
    xor     ecx, ecx
ths_cpprf:
    mov     al, byte ptr [rdx+rcx]
    mov     byte ptr [r8+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      ths_cpprf
    mov     rcx, qword ptr [rbp-48]
    mov     rax, qword ptr [wa_fn_freeatt]
    call    rax
    mov     qword ptr [rbp-48], 0
    jmp     ths_have_prf

ths_need_assert:
    ; Free attestation, then evaluate PRF via WebAuthNAuthenticatorGetAssertion
    mov     rcx, qword ptr [rbp-48]
    mov     rax, qword ptr [wa_fn_freeatt]
    call    rax
    mov     qword ptr [rbp-48], 0
    mov     rcx, qword ptr [rbp-24]
    add     rcx, WHLO_HDR_LEN
    mov     edx, dword ptr [rbp-36]
    lea     r8, [rbp-128]
    lea     r9, [rbp-160]
    call    wa_get_prf_assertion
    test    eax, eax
    jnz     ths_have_prf
    ; Clean up newly created platform credential on fallback failure / cancel
    cmp     qword ptr [wa_fn_delcred], 0
    je      ths_fail
    mov     ecx, dword ptr [rbp-36]
    mov     rdx, qword ptr [rbp-24]
    add     rdx, WHLO_HDR_LEN
    mov     rax, qword ptr [wa_fn_delcred]
    call    rax
    jmp     ths_fail

ths_have_prf:
    ; Recompute g_tpm_label cleanly, derive out_sec32 + verify_tag[24], and seal WHLO header
    lea     rcx, [rbp-96]
    lea     rdx, [rbp-128]
    call    wa_compute_hmac_in
    lea     rcx, [rbp-160]
    mov     rdx, qword ptr [rbp-16]
    lea     r8, [rbp-192]
    call    wa_derive_hello_mats

    mov     r10, qword ptr [rbp-24]
    mov     dword ptr [r10+0], WHLO_MAGIC
    mov     word ptr  [r10+4], WHLO_VER
    mov     eax, dword ptr [rbp-36]
    mov     word ptr  [r10+6], ax
    xor     ecx, ecx
ths_cpsalt:
    mov     al, byte ptr [rbp-96+rcx]
    mov     byte ptr [r10+8+rcx], al
    inc     ecx
    cmp     ecx, 32
    jb      ths_cpsalt
    xor     ecx, ecx
ths_cptag:
    mov     al, byte ptr [rbp-192+rcx]
    mov     byte ptr [r10+40+rcx], al
    inc     ecx
    cmp     ecx, 24
    jb      ths_cptag

    call    wa_wipe_structs
    lea     rcx, [rbp-192]
    mov     edx, 128
    call    secure_zero
    mov     eax, dword ptr [rbp-36]
    add     eax, WHLO_HDR_LEN
    FRAME_EPILOG
    ret

ths_free_fail:
    mov     rcx, qword ptr [rbp-48]
    mov     rax, qword ptr [wa_fn_freeatt]
    call    rax
ths_fail:
    call    wa_wipe_structs
    lea     rcx, [rbp-192]
    mov     edx, 128
    call    secure_zero
    mov     rcx, qword ptr [rbp-16]
    test    rcx, rcx
    jz      @F
    mov     edx, 32
    call    secure_zero
@@: xor     eax, eax
    FRAME_EPILOG
    ret
tpm_hello_seal endp

; tpm_hello_unseal(rcx=blob, edx=bloblen, r8=out32) -> eax = 1 / 0.
;   Prompts Windows Hello (Face / Fingerprint / Windows Hello PIN) via webauthn.dll
;   and recovers the 32-byte hello_secret if and only if the PRF tag matches.
public tpm_hello_unseal
tpm_hello_unseal proc frame
    FRAME_PROLOG 224
    ; [rbp-16]=blob [rbp-24]=bloblen [rbp-28]=cred_len [rbp-40]=out32
    ; [rbp-96..-65]=hmac_in[32] [rbp-128..-97]=prf_out[32] [rbp-160..-129]=tag_tmp[32]
    mov     dword ptr [g_tpm_last_err], 0
    mov     qword ptr [rbp-16], rcx
    mov     dword ptr [rbp-24], edx
    mov     qword ptr [rbp-40], r8
    lea     rcx, [rbp-160]
    mov     edx, 96
    call    secure_zero
    cmp     qword ptr [rbp-40], 0
    je      thu_fail
    mov     r10, qword ptr [rbp-16]
    test    r10, r10
    jz      thu_fail
    mov     edx, dword ptr [rbp-24]
    cmp     edx, WHLO_HDR_LEN + 1
    jb      thu_fail
    cmp     edx, WHLO_HDR_LEN + WHLO_MAX_CRED
    ja      thu_fail
    cmp     dword ptr [r10+0], WHLO_MAGIC
    jne     thu_fail
    cmp     word ptr [r10+4], WHLO_VER
    jne     thu_fail
    movzx   ecx, word ptr [r10+6]
    cmp     ecx, 1
    jb      thu_fail
    cmp     ecx, WHLO_MAX_CRED
    ja      thu_fail
    lea     eax, [rcx + WHLO_HDR_LEN]
    cmp     eax, edx
    jne     thu_fail
    mov     dword ptr [rbp-28], ecx

    call    wa_load
    test    eax, eax
    jz      thu_fail

    mov     r10, qword ptr [rbp-16]
    lea     rcx, [r10+8]                        ; prf_salt[32]
    lea     rdx, [rbp-96]                       ; hmac_in[32]
    call    wa_compute_hmac_in

    mov     rcx, qword ptr [rbp-16]
    add     rcx, WHLO_HDR_LEN                   ; cred_id
    mov     edx, dword ptr [rbp-28]             ; cred_len
    lea     r8, [rbp-96]                        ; hmac_in[32]
    lea     r9, [rbp-128]                       ; prf_out[32]
    call    wa_get_prf_assertion
    test    eax, eax
    jz      thu_fail

    ; Recompute g_tpm_label and derive candidate out32 + verify_tag[24]
    mov     r10, qword ptr [rbp-16]
    lea     rcx, [r10+8]
    lea     rdx, [rbp-96]
    call    wa_compute_hmac_in
    lea     rcx, [rbp-128]
    mov     rdx, qword ptr [rbp-40]
    lea     r8, [rbp-160]
    call    wa_derive_hello_mats

    mov     r10, qword ptr [rbp-16]
    lea     rcx, [rbp-160]
    lea     rdx, [r10+40]
    mov     r8d, 24
    call    ct_memcmp
    test    eax, eax
    jnz     thu_fail

    call    wa_wipe_structs
    lea     rcx, [rbp-160]
    mov     edx, 96
    call    secure_zero
    mov     eax, 1
    FRAME_EPILOG
    ret

thu_fail:
    call    wa_wipe_structs
    lea     rcx, [rbp-160]
    mov     edx, 96
    call    secure_zero
    mov     rcx, qword ptr [rbp-40]
    test    rcx, rcx
    jz      @F
    mov     edx, 32
    call    secure_zero
@@: xor     eax, eax
    FRAME_EPILOG
    ret
tpm_hello_unseal endp

; tpm_hello_delete(rcx = blob, edx = bloblen) -> eax = 1 / 0.
;   Best-effort removes an enrolled WHLO platform credential from Windows Hello.
public tpm_hello_delete
tpm_hello_delete proc frame
    FRAME_PROLOG 48
    mov     qword ptr [rbp-16], rcx
    mov     dword ptr [rbp-24], edx
    test    rcx, rcx
    jz      thd_no
    cmp     edx, WHLO_HDR_LEN + 1
    jb      thd_no
    cmp     edx, WHLO_HDR_LEN + WHLO_MAX_CRED
    ja      thd_no
    cmp     dword ptr [rcx+0], WHLO_MAGIC
    jne     thd_no
    cmp     word ptr [rcx+4], WHLO_VER
    jne     thd_no
    movzx   eax, word ptr [rcx+6]
    lea     r8d, [rax + WHLO_HDR_LEN]
    cmp     r8d, edx
    jne     thd_no
    mov     dword ptr [rbp-28], eax
    call    wa_load
    test    eax, eax
    jz      thd_no
    cmp     qword ptr [wa_fn_delcred], 0
    je      thd_no
    mov     ecx, dword ptr [rbp-28]
    mov     rdx, qword ptr [rbp-16]
    add     rdx, WHLO_HDR_LEN
    mov     rax, qword ptr [wa_fn_delcred]
    call    rax
    xor     ecx, ecx
    test    eax, eax
    sete    cl
    mov     eax, ecx
    FRAME_EPILOG
    ret
thd_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_hello_delete endp

; ===========================================================================
; TPM Anti-Hammering / Lockout Cooldown Diagnostics
; ===========================================================================

; tpm_u64_to_w(rcx = dst, rdx = dst_end, r8 = val_u64) -> rax = new dst (or 0 on overflow).
tpm_u64_to_w proc frame
    FRAME_PROLOG 64
    ; [rbp-40 .. rbp-17] = reversed ASCII digits (24 bytes)
    mov     r10, rcx                            ; dst
    mov     r11, rdx                            ; dst_end
    mov     rax, r8                             ; val
    lea     r9, [rbp-16]                        ; end of scratch
    mov     rcx, r9
    mov     r8d, 10
tuw_div:
    xor     edx, edx
    div     r8                                  ; rax /= 10, rdx = rem
    add     edx, '0'
    dec     rcx
    mov     byte ptr [rcx], dl
    test    rax, rax
    jnz     tuw_div
tuw_emit:
    cmp     rcx, r9
    jae     tuw_ok
    cmp     r10, r11
    jae     tuw_ovf
    movzx   eax, byte ptr [rcx]
    mov     word ptr [r10], ax
    add     r10, 2
    inc     rcx
    jmp     tuw_emit
tuw_ok:
    mov     rax, r10
    FRAME_EPILOG
    ret
tuw_ovf:
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_u64_to_w endp

; tpm_format_sid_w(rcx = psid, rdx = dst_w, r8d = cap_wchars) -> eax = 1 / 0.
;   Formats a binary Win32 SID into L"S-<rev>-<auth>-<sub0>-..." without Heap/LocalAlloc.
tpm_format_sid_w proc frame
    FRAME_PROLOG 96
    ; [rbp-16]=psid [rbp-24]=cur [rbp-32]=end [rbp-36]=subcnt [rbp-40]=idx [rbp-48]=auth64
    test    rcx, rcx
    jz      tfs_bad
    test    rdx, rdx
    jz      tfs_bad
    cmp     r8d, 16
    jb      tfs_bad
    mov     qword ptr [rbp-16], rcx
    mov     qword ptr [rbp-24], rdx
    dec     r8d
    lea     rax, [rdx + r8*2]
    mov     qword ptr [rbp-32], rax             ; last NUL-safe slot

    movzx   eax, byte ptr [rcx+0]               ; Revision (1..15)
    test    eax, eax
    jz      tfs_bad
    cmp     eax, 15
    ja      tfs_bad
    mov     dword ptr [rbp-40], eax             ; temp save rev

    movzx   eax, byte ptr [rcx+1]               ; SubAuthorityCount (1..15)
    test    eax, eax
    jz      tfs_bad
    cmp     eax, 15
    ja      tfs_bad
    mov     dword ptr [rbp-36], eax

    ; 48-bit big-endian IdentifierAuthority at [psid + 2..7]
    xor     r9, r9
    mov     r10d, 2
tfs_auth:
    shl     r9, 8
    movzx   eax, byte ptr [rcx + r10]
    or      r9, rax
    inc     r10d
    cmp     r10d, 8
    jb      tfs_auth
    mov     qword ptr [rbp-48], r9

    ; Emit "S-"
    mov     r10, qword ptr [rbp-24]
    mov     r11, qword ptr [rbp-32]
    lea     rax, [r10 + 4]
    cmp     rax, r11
    jae     tfs_bad
    mov     word ptr [r10], 'S'
    mov     word ptr [r10+2], '-'
    add     r10, 4

    ; Emit Revision
    mov     rcx, r10
    mov     rdx, r11
    mov     r8d, dword ptr [rbp-40]
    call    tpm_u64_to_w
    test    rax, rax
    jz      tfs_bad
    mov     r10, rax
    mov     r11, qword ptr [rbp-32]
    cmp     r10, r11
    jae     tfs_bad
    mov     word ptr [r10], '-'
    add     r10, 2

    ; Emit IdentifierAuthority
    mov     rcx, r10
    mov     rdx, r11
    mov     r8, qword ptr [rbp-48]
    call    tpm_u64_to_w
    test    rax, rax
    jz      tfs_bad
    mov     qword ptr [rbp-24], rax

    ; Emit SubAuthorities[0 .. subcnt-1]
    mov     dword ptr [rbp-40], 0
tfs_sub_lp:
    mov     eax, dword ptr [rbp-40]
    cmp     eax, dword ptr [rbp-36]
    jae     tfs_done
    mov     r10, qword ptr [rbp-24]
    mov     r11, qword ptr [rbp-32]
    cmp     r10, r11
    jae     tfs_bad
    mov     word ptr [r10], '-'
    add     r10, 2
    mov     r9, qword ptr [rbp-16]
    mov     r8d, dword ptr [r9 + rax*4 + 8]     ; zero-extended uint32 SubAuthority
    mov     rcx, r10
    mov     rdx, r11
    call    tpm_u64_to_w
    test    rax, rax
    jz      tfs_bad
    mov     qword ptr [rbp-24], rax
    inc     dword ptr [rbp-40]
    jmp     tfs_sub_lp

tfs_done:
    mov     rax, qword ptr [rbp-24]
    mov     word ptr [rax], 0
    mov     eax, 1
    FRAME_EPILOG
    ret
tfs_bad:
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_format_sid_w endp

; tpm_calc_window_rem(rcx = hist_ptr, edx = hist_bytes, r8 = now_ft, r9 = (thresh<<32)|dur_mins)
;   -> rax = unlock_ft (0 if active count < thresh or thresh == 0), edx = active_cnt.
tpm_calc_window_rem proc frame
    FRAME_PROLOG 608
    ; [rbp-16]=hist_ptr [rbp-20]=n_entries [rbp-24]=dur_mins [rbp-28]=thresh
    ; [rbp-40]=now_ft [rbp-48]=win_ft [rbp-56]=m_active [rbp-576 .. rbp-65]=active_ft[64]
    test    rcx, rcx
    jz      tcwr_zero
    mov     qword ptr [rbp-16], rcx
    cmp     edx, 512
    jbe     @F
    mov     edx, 512
@@: shr     edx, 3                              ; n_entries = min(hist_bytes, 512) / 8
    mov     dword ptr [rbp-20], edx
    mov     qword ptr [rbp-40], r8
    mov     eax, r9d                            ; dur_mins
    test    eax, eax
    jz      tcwr_zero
    mov     dword ptr [rbp-24], eax
    shr     r9, 32
    mov     dword ptr [rbp-28], r9d             ; thresh
    mov     ecx, FT_PER_MIN
    imul    rax, rcx                            ; win_ft = dur_mins * 600,000,000
    mov     qword ptr [rbp-48], rax

    xor     r10d, r10d                          ; i = 0
    xor     r11d, r11d                          ; m_active = 0
tcwr_scan:
    cmp     r10d, dword ptr [rbp-20]
    jae     tcwr_eval
    mov     rcx, qword ptr [rbp-16]
    mov     rax, qword ptr [rcx + r10*8]        ; ft
    test    rax, rax
    jz      tcwr_next
    mov     rdx, qword ptr [rbp-40]             ; now_ft
    cmp     rax, rdx
    ja      tcwr_next                           ; future timestamp -> ignore
    sub     rdx, rax                            ; age = now_ft - ft
    cmp     rdx, qword ptr [rbp-48]
    jae     tcwr_next                           ; expired (>= win_ft)

    ; Insertion-sort ft (rax) into active_ft[0..r11d-1] at [rbp-576]
    mov     ecx, r11d                           ; j = m_active
tcwr_ins:
    test    ecx, ecx
    jz      tcwr_put
    mov     edx, ecx
    dec     edx
    mov     r8, qword ptr [rbp - 576 + rdx*8]
    cmp     r8, rax
    jbe     tcwr_put
    mov     qword ptr [rbp - 576 + rcx*8], r8
    dec     ecx
    jmp     tcwr_ins
tcwr_put:
    mov     qword ptr [rbp - 576 + rcx*8], rax
    inc     r11d
tcwr_next:
    inc     r10d
    jmp     tcwr_scan

tcwr_eval:
    mov     edx, r11d                           ; edx = active_cnt
    mov     ecx, dword ptr [rbp-28]             ; thresh
    test    ecx, ecx
    jz      tcwr_not_locked
    cmp     r11d, ecx
    jb      tcwr_not_locked
    mov     eax, r11d
    sub     eax, ecx                            ; idx = m_active - thresh
    mov     rax, qword ptr [rbp - 576 + rax*8]
    add     rax, qword ptr [rbp-48]             ; unlock_ft = active_ft[idx] + win_ft
    FRAME_EPILOG
    ret
tcwr_not_locked:
    xor     eax, eax
    FRAME_EPILOG
    ret
tcwr_zero:
    xor     eax, eax
    xor     edx, edx
    FRAME_EPILOG
    ret
tpm_calc_window_rem endp

; tpm_pol_dword(rcx = hkey, rdx = valname_w, r8d = def_val) -> eax = val (or def_val).
tpm_pol_dword proc frame
    FRAME_PROLOG 80
    ; [rbp-16]=def [rbp-24]=type [rbp-28]=cb [rbp-32]=val
    mov     dword ptr [rbp-16], r8d
    test    rcx, rcx
    jz      tpd_def
    mov     dword ptr [rbp-28], 4
    WINCALL RegQueryValueExW, rcx, rdx, 0, addr rbp-24, addr rbp-32, addr rbp-28
    test    eax, eax
    jnz     tpd_def
    cmp     dword ptr [rbp-24], REG_DWORD
    jne     tpd_def
    cmp     dword ptr [rbp-28], 4
    jne     tpd_def
    mov     eax, dword ptr [rbp-32]
    FRAME_EPILOG
    ret
tpd_def:
    mov     eax, dword ptr [rbp-16]
    FRAME_EPILOG
    ret
tpm_pol_dword endp

; tpm_af_check_sub(rcx = hAfRoot, rdx = subkey_w, r8 = now_ft, r9 = (thresh<<32)|dur_mins)
;   -> rax = unlock_ft (0 if not locked), edx = active_cnt.
tpm_af_check_sub proc frame
    FRAME_PROLOG 640
    ; [rbp-16]=hSub [rbp-24]=now_ft [rbp-32]=packed [rbp-36]=type [rbp-40]=cb [rbp-560..rbp-49]=hist[512]
    mov     qword ptr [rbp-16], 0
    mov     qword ptr [rbp-24], r8
    mov     qword ptr [rbp-32], r9
    WINCALL RegOpenKeyExW, rcx, rdx, 0, KEY_READ, addr rbp-16
    test    eax, eax
    jnz     tacs_none
    mov     dword ptr [rbp-40], 512
    WINCALL RegQueryValueExW, qword ptr [rbp-16], addr rv_af_hist, 0, addr rbp-36, addr rbp-560, addr rbp-40
    mov     dword ptr [rbp-44], eax
    WINCALL RegCloseKey, qword ptr [rbp-16]
    cmp     dword ptr [rbp-44], 0
    jne     tacs_none
    cmp     dword ptr [rbp-36], REG_BINARY
    jne     tacs_none
    lea     rcx, [rbp-560]
    mov     edx, dword ptr [rbp-40]
    mov     r8, qword ptr [rbp-24]
    mov     r9, qword ptr [rbp-32]
    call    tpm_calc_window_rem
    FRAME_EPILOG
    ret
tacs_none:
    xor     eax, eax
    xor     edx, edx
    FRAME_EPILOG
    ret
tpm_af_check_sub endp

; tbs_load() -> eax = 1 if tbs.dll entry points resolved, 0 otherwise.
tbs_load proc frame
    FRAME_PROLOG 48
    cmp     dword ptr [tbs_init_done], 1
    je      tbsl_ok
    cmp     dword ptr [tbs_init_done], -1
    je      tbsl_no
    WINCALL LoadLibraryExW, addr tbs_dll_w, 0, LOAD_LIB_SYS32
    test    rax, rax
    jz      tbsl_fail
    mov     qword ptr [tbs_hmod], rax
    WINCALL GetProcAddress, qword ptr [tbs_hmod], addr tbs_n_create
    test    rax, rax
    jz      tbsl_fail
    mov     qword ptr [tbs_fn_create], rax
    WINCALL GetProcAddress, qword ptr [tbs_hmod], addr tbs_n_submit
    test    rax, rax
    jz      tbsl_fail
    mov     qword ptr [tbs_fn_submit], rax
    WINCALL GetProcAddress, qword ptr [tbs_hmod], addr tbs_n_close
    test    rax, rax
    jz      tbsl_fail
    mov     qword ptr [tbs_fn_close], rax
    mov     dword ptr [tbs_init_done], 1
tbsl_ok:
    mov     eax, 1
    FRAME_EPILOG
    ret
tbsl_fail:
    mov     dword ptr [tbs_init_done], -1
tbsl_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
tbs_load endp

; tpm_cooldown_query(rcx = out_info_32) -> eax = kind:
;   0 = g_tpm_last_err is not an anti-hammering / DA lockout HRESULT
;   1 = Windows OS / TBS standard-user anti-hammering active (live countdown populated)
;   2 = Hardware TPM 2.0 dictionary-attack lockout active (live counter & heal interval populated)
;   3 = Anti-hammering HRESULT active (policy/default summary populated, exact timer unavailable)
;   out_info_32 layout:
;     [+0]  dd err_hr        [+4]  dd win_mins     [+8]  dd rem_mins
;     [+12] dd cur_fails     [+16] dd max_fails    [+20] dd local_hm ((hour<<16)|min, or -1)
;     [+24] dq unlock_ft
public tpm_cooldown_query
tpm_cooldown_query proc frame
    FRAME_PROLOG 640
    ; [rbp-16]=out_ptr    [rbp-20]=err_hr     [rbp-24]=dur_mins   [rbp-28]=ind_thr
    ; [rbp-32]=tot_thr    [rbp-40]=hKey       [rbp-48]=now_ft     [rbp-56]=best_ft
    ; [rbp-60]=best_cur   [rbp-64]=best_max   [rbp-72]=loc_ft     [rbp-96..rbp-81]=SYSTEMTIME(16)
    ; [rbp-104]=hTok      [rbp-108]=tok_ret   [rbp-240..rbp-113]=tok_buf(128)
    ; [rbp-448..rbp-257]=sid_w(96 wchars = 192B)
    ; [rbp-456]=tbs_h     [rbp-464]=tbs_prm   [rbp-468]=rsp_len   [rbp-560..rbp-481]=tbs_rsp(80B)
    test    rcx, rcx
    jz      tcq_not
    mov     qword ptr [rbp-16], rcx
    mov     eax, dword ptr [g_tpm_last_err]
    cmp     eax, 80290409h                      ; TPM_E_PCP_AUTHENTICATION_IGNORED
    je      tcq_go
    cmp     eax, 80280921h                      ; TPM_20_E_LOCKOUT
    je      tcq_go
    cmp     eax, 80280803h                      ; TPM_E_DEFEND_LOCK_RUNNING
    je      tcq_go
    jmp     tcq_not

tcq_go:
    mov     dword ptr [rbp-20], eax
    ; Zero output struct and initialize defaults
    mov     qword ptr [rcx+0], 0
    mov     qword ptr [rcx+8], 0
    mov     qword ptr [rcx+16], 0
    mov     qword ptr [rcx+24], 0
    mov     dword ptr [rcx+0], eax
    mov     dword ptr [rcx+20], 0FFFFFFFFh      ; local_hm = unavailable

    ; 1) Read optional Windows TPM Group Policy thresholds (defaults: 480m, 4 indiv, 9 total)
    mov     dword ptr [rbp-24], 480
    mov     dword ptr [rbp-28], 4
    mov     dword ptr [rbp-32], 9
    mov     qword ptr [rbp-40], 0
    WINCALL RegOpenKeyExW, qword ptr [g_hklm], addr rk_tpm_pol, 0, KEY_READ, addr rbp-40
    test    eax, eax
    jnz     tcq_pol_done
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [rv_su_dur]
    mov     r8d, 480
    call    tpm_pol_dword
    test    eax, eax
    jnz     @F
    mov     eax, 480
@@: cmp     eax, 10000
    jbe     @F
    mov     eax, 10000
@@: mov     dword ptr [rbp-24], eax

    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [rv_su_ind]
    mov     r8d, 4
    call    tpm_pol_dword
    cmp     eax, 1000
    jbe     @F
    mov     eax, 1000
@@: mov     dword ptr [rbp-28], eax

    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [rv_su_tot]
    mov     r8d, 9
    call    tpm_pol_dword
    cmp     eax, 1000
    jbe     @F
    mov     eax, 1000
@@: mov     dword ptr [rbp-32], eax
    WINCALL RegCloseKey, qword ptr [rbp-40]

tcq_pol_done:
    ; 2) Check Windows TBS Standard-User AuthorizationFailure History (<UserSID> and ALLSTANDARDUSERS)
    WINCALL GetSystemTimeAsFileTime, addr rbp-48
    mov     qword ptr [rbp-56], 0               ; best_ft
    mov     dword ptr [rbp-60], 0               ; best_cur
    mov     dword ptr [rbp-64], 0               ; best_max
    mov     qword ptr [rbp-40], 0
    WINCALL RegOpenKeyExW, qword ptr [g_hklm], addr rk_tpm_af, 0, KEY_READ, addr rbp-40
    test    eax, eax
    jnz     tcq_try_hw

    ; Resolve current user's SID string for per-user threshold check
    mov     qword ptr [rbp-104], 0
    WINCALL OpenProcessToken, -1, 8, addr rbp-104
    test    eax, eax
    jz      tcq_af_all
    mov     dword ptr [rbp-108], 0
    WINCALL GetTokenInformation, qword ptr [rbp-104], 1, addr rbp-240, 128, addr rbp-108
    mov     dword ptr [rbp-112], eax
    WINCALL CloseHandle, qword ptr [rbp-104]
    cmp     dword ptr [rbp-112], 0
    je      tcq_af_all
    mov     rcx, qword ptr [rbp-240]            ; TOKEN_USER.User.Sid
    lea     rdx, [rbp-448]
    mov     r8d, 96
    call    tpm_format_sid_w
    test    eax, eax
    jz      tcq_af_all

    mov     eax, dword ptr [rbp-28]             ; ind_thr
    shl     rax, 32
    mov     ecx, dword ptr [rbp-24]             ; dur_mins
    or      rax, rcx
    mov     r9, rax
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [rbp-448]
    mov     r8, qword ptr [rbp-48]
    call    tpm_af_check_sub
    cmp     rax, qword ptr [rbp-48]
    jbe     tcq_af_all
    mov     qword ptr [rbp-56], rax
    mov     dword ptr [rbp-60], edx
    mov     ecx, dword ptr [rbp-28]
    mov     dword ptr [rbp-64], ecx

tcq_af_all:
    mov     eax, dword ptr [rbp-32]             ; tot_thr
    shl     rax, 32
    mov     ecx, dword ptr [rbp-24]             ; dur_mins
    or      rax, rcx
    mov     r9, rax
    mov     rcx, qword ptr [rbp-40]
    lea     rdx, [rk_af_all]
    mov     r8, qword ptr [rbp-48]
    call    tpm_af_check_sub
    mov     r8, rax
    mov     r9d, edx
    WINCALL RegCloseKey, qword ptr [rbp-40]
    cmp     r8, qword ptr [rbp-48]
    jbe     tcq_af_eval
    cmp     r8, qword ptr [rbp-56]
    jbe     tcq_af_eval
    mov     qword ptr [rbp-56], r8
    mov     dword ptr [rbp-60], r9d
    mov     ecx, dword ptr [rbp-32]
    mov     dword ptr [rbp-64], ecx

tcq_af_eval:
    mov     rax, qword ptr [rbp-56]
    cmp     rax, qword ptr [rbp-48]
    jbe     tcq_try_hw
    ; Found live TBS standard-user cooldown!
    mov     r10, qword ptr [rbp-16]
    mov     ecx, dword ptr [rbp-24]
    mov     dword ptr [r10+4], ecx              ; win_mins
    mov     ecx, dword ptr [rbp-60]
    mov     dword ptr [r10+12], ecx             ; cur_fails
    mov     ecx, dword ptr [rbp-64]
    mov     dword ptr [r10+16], ecx             ; max_fails
    mov     qword ptr [r10+24], rax             ; unlock_ft
    sub     rax, qword ptr [rbp-48]             ; rem_ft
    mov     ecx, FT_PER_MIN - 1
    add     rax, rcx
    xor     edx, edx
    mov     ecx, FT_PER_MIN
    div     rcx                                 ; ceil(rem_ft / FT_PER_MIN)
    test    eax, eax
    jnz     @F
    mov     eax, 1
@@: mov     r10, qword ptr [rbp-16]
    mov     dword ptr [r10+8], eax              ; rem_mins

    ; Convert unlock_ft -> local HH:MM
    WINCALL FileTimeToLocalFileTime, addr rbp-56, addr rbp-72
    test    eax, eax
    jz      tcq_ret1
    WINCALL FileTimeToSystemTime, addr rbp-72, addr rbp-96
    test    eax, eax
    jz      tcq_ret1
    movzx   eax, word ptr [rbp-96 + 8]          ; wHour
    shl     eax, 16
    movzx   ecx, word ptr [rbp-96 + 10]         ; wMinute
    or      eax, ecx
    mov     r10, qword ptr [rbp-16]
    mov     dword ptr [r10+20], eax
tcq_ret1:
    mov     eax, 1
    FRAME_EPILOG
    ret

tcq_try_hw:
    ; 3) Query Hardware TPM 2.0 DA Lockout properties via tbs.dll (unprivileged TPM2_GetCapability)
    call    tbs_load
    test    eax, eax
    jz      tcq_fallback
    mov     qword ptr [rbp-456], 0              ; tbs_h
    mov     dword ptr [rbp-464], 2              ; TBS_CONTEXT_VERSION_TWO
    mov     dword ptr [rbp-460], 4              ; includeTpm20 = 1 (bit 2)
    lea     rcx, [rbp-464]
    lea     rdx, [rbp-456]
    mov     rax, qword ptr [tbs_fn_create]
    sub     rsp, 32
    call    rax
    add     rsp, 32
    test    eax, eax
    jnz     tcq_fallback
    mov     dword ptr [rbp-468], 80             ; rsp_len
    sub     rsp, 64
    mov     rcx, qword ptr [rbp-456]
    xor     edx, edx                            ; TBS_COMMAND_LOCALITY_ZERO
    mov     r8d, 200                            ; TBS_COMMAND_PRIORITY_NORMAL
    lea     r9, [tbs_getcap_cmd]
    mov     dword ptr [rsp+32], 22
    lea     rax, [rbp-560]
    mov     qword ptr [rsp+40], rax
    lea     rax, [rbp-468]
    mov     qword ptr [rsp+48], rax
    mov     rax, qword ptr [tbs_fn_submit]
    call    rax
    add     rsp, 64
    mov     dword ptr [rbp-108], eax            ; save submit rc
    mov     rcx, qword ptr [rbp-456]
    mov     rax, qword ptr [tbs_fn_close]
    sub     rsp, 32
    call    rax
    add     rsp, 32
    cmp     dword ptr [rbp-108], 0
    jne     tcq_fallback
    mov     ecx, dword ptr [rbp-468]
    cmp     ecx, 19
    jb      tcq_fallback
    mov     eax, dword ptr [rbp-560 + 6]        ; responseCode (0 = TPM_RC_SUCCESS)
    test    eax, eax
    jnz     tcq_fallback
    mov     eax, dword ptr [rbp-560 + 15]       ; count (big-endian)
    bswap   eax
    cmp     eax, 8
    jbe     @F
    mov     eax, 8
@@: mov     dword ptr [rbp-60], 0FFFFFFFFh      ; lockout_counter
    mov     dword ptr [rbp-64], 0               ; max_auth_fail
    mov     dword ptr [rbp-112], 0              ; lockout_interval_sec
    xor     r8d, r8d                            ; i = 0
tcq_hw_lp:
    cmp     r8d, eax
    jae     tcq_hw_eval
    lea     r9d, [r8*8 + 19]
    lea     r10d, [r9 + 8]
    cmp     r10d, ecx
    ja      tcq_hw_eval
    mov     edx, dword ptr [rbp-560 + r9]
    bswap   edx                                 ; property ID
    mov     r11d, dword ptr [rbp-560 + r9 + 4]
    bswap   r11d                                ; property value
    cmp     edx, 020Eh                          ; TPM_PT_LOCKOUT_COUNTER
    jne     @F
    mov     dword ptr [rbp-60], r11d
    jmp     tcq_hw_nx
@@: cmp     edx, 020Fh                          ; TPM_PT_MAX_AUTH_FAIL
    jne     @F
    mov     dword ptr [rbp-64], r11d
    jmp     tcq_hw_nx
@@: cmp     edx, 0210h                          ; TPM_PT_LOCKOUT_INTERVAL (seconds)
    jne     tcq_hw_nx
    mov     dword ptr [rbp-112], r11d
tcq_hw_nx:
    inc     r8d
    jmp     tcq_hw_lp

tcq_hw_eval:
    mov     eax, dword ptr [rbp-64]             ; max_auth_fail
    test    eax, eax
    jz      tcq_fallback
    mov     ecx, dword ptr [rbp-60]             ; lockout_counter
    cmp     ecx, 0FFFFFFFFh
    je      tcq_fallback
    cmp     ecx, eax
    jb      tcq_fallback
    ; Hardware TPM 2.0 DA Lockout is active!
    mov     r10, qword ptr [rbp-16]
    mov     dword ptr [r10+12], ecx             ; cur_fails
    mov     dword ptr [r10+16], eax             ; max_fails
    sub     ecx, eax
    inc     ecx                                 ; steps = counter - max + 1
    mov     r8d, dword ptr [rbp-112]            ; interval_sec
    test    r8d, r8d
    jnz     @F
    mov     r8d, 600                            ; 10m default if firmware reports 0
@@: lea     eax, [r8 + 59]
    xor     edx, edx
    mov     r9d, 60
    div     r9d
    test    eax, eax
    jnz     @F
    mov     eax, 1
@@: mov     dword ptr [r10+4], eax              ; win_mins (per-decrement heal interval)
    mov     eax, ecx
    imul    rax, r8                             ; total_sec = steps * interval_sec
    add     rax, 59
    xor     edx, edx
    mov     r9d, 60
    div     r9
    test    eax, eax
    jnz     @F
    mov     eax, 1
@@: mov     dword ptr [r10+8], eax              ; rem_mins
    mov     eax, 2
    FRAME_EPILOG
    ret

tcq_fallback:
    mov     r10, qword ptr [rbp-16]
    mov     eax, dword ptr [rbp-24]
    mov     dword ptr [r10+4], eax              ; win_mins (policy/default TBS window)
    mov     eax, dword ptr [rbp-28]
    mov     dword ptr [r10+16], eax             ; max_fails (policy/default indiv threshold)
    mov     eax, 3
    FRAME_EPILOG
    ret

tcq_not:
    xor     eax, eax
    FRAME_EPILOG
    ret
tpm_cooldown_query endp

; ===========================================================================
; cmd_tpmkat - VDR-10 OAEP v2 label domain/salt/reqhello binding KAT +
;   live PCP / mock-PCP Mode 2 anti-replay, 3-strike revocation & reseal KAT.
; ===========================================================================
extern print_a:proc

.data
align 2
WSTR tpk_key, <VordrTpmKatKey>
WSTR tpk_sid_exp, <S-1-5-21-100-200-1002>
tpk_sid_bin db 1, 4, 0,0,0,0,0,5
            dd 21, 100, 200, 1002
CSTR tpk_ok_live, "tpmkat: PASS (OAEP v2 + S0/S1 anti-replay + 3-strike revoke + reseal + cooldown + Hello probe)",13,10
CSTR tpk_ok_sw,   "tpmkat: PASS (OAEP v2 + mock-PCP S0/S1 anti-replay + 3-strike revoke + reseal + cooldown)",13,10
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

    ; 3) use_v2=0 -> empty OAEP label
    mov     dword ptr [g_tpm_reqhello], 0
    xor     ecx, ecx
    call    tpm_build_oaep
    cmp     qword ptr [g_tpm_oaep+8], 0
    jne     tpk_fail
    cmp     dword ptr [g_tpm_oaep+16], 0
    jne     tpk_fail

    ; 4) Silent Windows Hello WebAuthn availability probe must return 0 or 1 cleanly
    call    tpm_hello_available
    cmp     eax, 1
    ja      tpk_fail

    ; 4b) Cooldown SID formatter + TBS rolling-window remaining-time math KAT
    lea     rcx, [tpk_sid_bin]
    lea     rdx, [tpk_blob]
    mov     r8d, 96
    call    tpm_format_sid_w
    cmp     eax, 1
    jne     tpk_fail
    lea     rcx, [tpk_blob]
    lea     rdx, [tpk_sid_exp]
    mov     r8d, 44                             ; 21 chars + NUL = 22 words = 44 bytes
    call    ct_memcmp
    test    eax, eax
    jnz     tpk_fail

    ; Synthetic History: 1 expired (t=100m) + 4 active unsorted (t=680m, 678m, 682m, 679m), now=1000m, win=480m
    lea     r10, [tpk_blob]
    mov     ecx, FT_PER_MIN
    mov     eax, 100
    imul    rax, rcx
    mov     qword ptr [r10+0], rax
    mov     eax, 680
    imul    rax, rcx
    mov     qword ptr [r10+8], rax
    mov     eax, 678
    imul    rax, rcx
    mov     qword ptr [r10+16], rax
    mov     eax, 682
    imul    rax, rcx
    mov     qword ptr [r10+24], rax
    mov     eax, 679
    imul    rax, rcx
    mov     qword ptr [r10+32], rax
    ; With thresh=4 -> 4 active, oldest active is 678m -> unlock_ft = (678+480)*600M = 1158m -> 158m left
    mov     eax, 1000
    imul    rax, rcx
    mov     r8, rax                             ; now_ft
    mov     r9, (4 shl 32) or 480               ; thresh=4, dur=480
    lea     rcx, [tpk_blob]
    mov     edx, 40                             ; 5 QWORDs
    call    tpm_calc_window_rem
    cmp     edx, 4
    jne     tpk_fail
    mov     ecx, FT_PER_MIN
    mov     r8d, 1158
    imul    r8, rcx
    cmp     rax, r8
    jne     tpk_fail
    ; With thresh=5 -> 4 active < 5 -> not locked (rax == 0, edx == 4)
    mov     eax, 1000
    imul    rax, rcx
    mov     r8, rax
    mov     r9, (5 shl 32) or 480
    lea     rcx, [tpk_blob]
    mov     edx, 40
    call    tpm_calc_window_rem
    test    rax, rax
    jnz     tpk_fail
    cmp     edx, 4
    jne     tpk_fail
    ; With non-cooldown g_tpm_last_err=0 -> tpm_cooldown_query returns 0
    mov     dword ptr [g_tpm_last_err], 0
    lea     rcx, [tpk_blob]
    call    tpm_cooldown_query
    test    eax, eax
    jnz     tpk_fail

    ; 5) Live PCP check when silent TPM key creation succeeds on this host
    call    tpm_available
    test    eax, eax
    jz      tpk_sw_ok
    lea     rcx, [tpk_key]
    lea     rdx, [tpk_in]
    lea     r8, [tpk_blob]
    mov     r9d, 512
    call    tpm_seal
    test    eax, eax
    jz      tpk_sw_ok                           ; PCP unavailable or in OS cooldown -> run mock KAT
    mov     dword ptr [rbp-28], eax             ; bloblen
    ; Flip 1 salt bit -> tpm_unseal MUST reject and wipe out32
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
    lea     rcx, [tpk_out]
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
    cmp     eax, 1
    jne     tpk_fail
    lea     rcx, [tpk_key]
    lea     rdx, [tpk_blob]
    mov     r8d, dword ptr [rbp-28]
    lea     r9, [tpk_out]
    call    tpm_unseal
    test    eax, eax
    jnz     tpk_fail

ifdef PROBE_IO
    ; 6) Full TPM+PIN envelope + disk reseal + 3-strike revocation + 2-vault KAT on live PCP
    call    vault_tpm_pin_kat
    test    eax, eax
    jnz     tpk_fail
endif

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
ifdef PROBE_IO
    ; Exercise the full Mode 2 envelope + disk reseal + 3-strike revocation KAT against mock PCP
    mov     dword ptr [g_tpm_mock_mode], 1
    call    vault_tpm_pin_kat
    mov     dword ptr [rbp-32], eax
    mov     dword ptr [g_tpm_mock_mode], 0
    lea     rcx, [g_tpm_mock_slots]
    mov     edx, MOCK_SLOT_SZ * MOCK_SLOTS
    call    secure_zero
    cmp     dword ptr [rbp-32], 0
    jne     tpk_fail
endif
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

.data
align 2
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
