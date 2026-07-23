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

NCRYPT_SILENT_FLAG      equ 040h
NCRYPT_OAEP_SILENT      equ 044h        ; NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG
NCRYPT_PAD_OAEP         equ 004h        ; C4: OAEP without SILENT (lets the OS prompt)
NCRYPT_UI_PROTECT_KEY   equ 1           ; NCRYPT_UI_POLICY dwFlags: prompt on each use

externdef g_tpm_reqhello:dword          ; C4: require Hello/PIN on TPM unlock (gui.asm)

.data
; CNG provider / algorithm names as UTF-16 (no commas -> WSTR)
WSTR tpm_prov, <Microsoft Platform Crypto Provider>
WSTR tpm_alg,  <RSA>
WSTR tpm_sha,  <SHA256>
WSTR tpm_lenprop, <Length>              ; NCRYPT_LENGTH_PROPERTY
tpm_keylen  dd 2048                     ; force RSA-2048 (never the provider default)
; C4: UI policy stamped on the key when g_tpm_reqhello is set (opt-in).
WSTR ui_policy_prop, <UI Policy>        ; NCRYPT_UI_POLICY_PROPERTY
WSTR ui_friendly,    <Vordr>
WSTR ui_desc,        <Unlock your Vordr vault>
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
g_tpm_oaep  db 24 dup (?)       ; BCRYPT_OAEP_PADDING_INFO

.code

; build_oaep() - fill g_tpm_oaep: { pszAlgId="SHA256"; pbLabel=0; cbLabel=0 }.
build_oaep proc
    lea     rax, [tpm_sha]
    mov     qword ptr [g_tpm_oaep], rax
    mov     qword ptr [g_tpm_oaep+8], 0
    mov     dword ptr [g_tpm_oaep+16], 0
    ret
build_oaep endp

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
    FRAME_PROLOG 128
    ; [rbp-24]=keyname [rbp-32]=in32 [rbp-40]=outblob [rbp-48]=cap
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     qword ptr [rbp-40], r8
    mov     dword ptr [rbp-48], r9d
    mov     qword ptr [g_tpm_prov], 0
    mov     qword ptr [g_tpm_key], 0
    WINCALL NCryptOpenStorageProvider, addr g_tpm_prov, addr tpm_prov, 0
    test    eax, eax
    jnz     ts_fail
    ; reuse the key if it already exists, else create it
    WINCALL NCryptOpenKey, qword ptr [g_tpm_prov], addr g_tpm_key, \
            qword ptr [rbp-24], 0, NCRYPT_SILENT_FLAG
    test    eax, eax
    jz      ts_haskey
    WINCALL NCryptCreatePersistedKey, qword ptr [g_tpm_prov], addr g_tpm_key, \
            addr tpm_alg, qword ptr [rbp-24], 0, 0
    test    eax, eax
    jnz     ts_freeprov
    ; set the modulus size explicitly BEFORE finalize - the PCP default is
    ; unspecified and could be weaker than the RSA-2048 the header promises.
    ; Best-effort: a provider that rejects the property just uses its default.
    WINCALL NCryptSetProperty, qword ptr [g_tpm_key], addr tpm_lenprop, \
            addr tpm_keylen, 4, NCRYPT_SILENT_FLAG
    ; C4 (opt-in): stamp a UI policy so every future use of this key prompts
    ; for Windows Hello / PIN.  Best-effort - a provider that rejects it just
    ; leaves the key silent.  Default (g_tpm_reqhello=0) keeps today's behavior.
    cmp     dword ptr [g_tpm_reqhello], 0
    je      ts_nohello
    WINCALL NCryptSetProperty, qword ptr [g_tpm_key], addr ui_policy_prop, \
            addr g_ui_policy, 32, 0
ts_nohello:
    WINCALL NCryptFinalizeKey, qword ptr [g_tpm_key], NCRYPT_SILENT_FLAG
    test    eax, eax
    jnz     ts_freekey
ts_haskey:
    call    build_oaep
    WINCALL NCryptEncrypt, qword ptr [g_tpm_key], qword ptr [rbp-32], 32, \
            addr g_tpm_oaep, qword ptr [rbp-40], dword ptr [rbp-48], \
            addr g_tpm_cbres, NCRYPT_OAEP_SILENT
    test    eax, eax
    jnz     ts_freekey
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
; ===========================================================================
public tpm_unseal
tpm_unseal proc frame
    FRAME_PROLOG 128
    ; [rbp-24]=keyname [rbp-32]=blob [rbp-40]=bloblen [rbp-48]=out32
    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], rdx
    mov     dword ptr [rbp-40], r8d
    mov     qword ptr [rbp-48], r9
    mov     qword ptr [g_tpm_prov], 0
    mov     qword ptr [g_tpm_key], 0
    WINCALL NCryptOpenStorageProvider, addr g_tpm_prov, addr tpm_prov, 0
    test    eax, eax
    jnz     tu_fail
    ; C4: pick the flags.  Default = silent (unchanged).  With g_tpm_reqhello,
    ; drop SILENT so the OS is allowed to surface a Hello/PIN prompt.
    ; [rbp-56]=OpenKey flag  [rbp-64]=Decrypt flag
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
    call    build_oaep
    WINCALL NCryptDecrypt, qword ptr [g_tpm_key], qword ptr [rbp-32], dword ptr [rbp-40], \
            addr g_tpm_oaep, qword ptr [rbp-48], 32, \
            addr g_tpm_cbres, dword ptr [rbp-64]
    test    eax, eax
    jnz     tu_freekey
    cmp     dword ptr [g_tpm_cbres], 32
    jne     tu_freekey
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
    xor     eax, eax
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
    WINCALL NCryptOpenKey, qword ptr [g_tpm_prov], addr g_tpm_key, \
            qword ptr [rbp-24], 0, NCRYPT_SILENT_FLAG
    test    eax, eax
    jnz     td_freeprov
    ; NCryptDeleteKey frees the key handle as well
    WINCALL NCryptDeleteKey, qword ptr [g_tpm_key], NCRYPT_SILENT_FLAG
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
; cmd_tpmtest (dbg builds only) - headless seal/unseal round-trip on this
;   machine's TPM, so the platform-crypto path can be validated without the GUI.
; ===========================================================================
ifdef DBG_TRACE
extern rng_fill:proc
extern ct_memcmp:proc
extern print_a:proc

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
