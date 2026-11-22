# Vault file format

[Documentation](README.md) · [Architecture](ARCHITECTURE.md)

This is a reference for the current version-2 reader and writer.
Constants are in `src/macros.inc` and `src/vault.asm`; serialization is in
`src/vault.asm`. Integer fields are little-endian unless a field explicitly
uses textual hexadecimal. Offsets below are bytes from the beginning of the file.

## Container layout

```text
┌──────────────────────────────┐
│ Header + KCV          80 B   │ ← complete GCM associated data
├──────────────────────────────┤
│ Encrypted record body       │
│ Body GCM tag          16 B   │
├──────────────────────────────┤
│ Attachment records          │ optional
│ VATT footer           12 B  │ present with attachment records
├──────────────────────────────┤
│ Save counter           8 B  │
│ File MAC              32 B  │
│ VMAC marker            4 B  │
└──────────────────────────────┘
```

The file MAC covers all bytes preceding it, including the counter.
The final `VMAC` marker is checked separately. The attachment section is
authenticated before its lengths are used to locate the body.

## Header

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 | magic | ASCII `VRDR` |
| 4 | 4 | version | 2; other versions are rejected |
| 8 | 4 | t_cost | Argon2id passes; default 3 |
| 12 | 4 | m_cost_kib | Argon2id memory in KiB; default 524288 |
| 16 | 4 | lanes | 1 for native vaults |
| 20 | 32 | salt | Random password-derivation salt |
| 52 | 12 | nonce | Random body GCM nonce, refreshed on each reseal |
| 64 | 16 | KCV | First 16 bytes of SHA-256 of the vault key |
| 80 | variable | body ciphertext | Followed by a 16-byte GCM tag |

`VAULT_HDR` is the first 64 bytes; `VH_TOTAL` includes the KCV and is 80.
**All 80 bytes are passed as GCM AAD**, not just the parameter structure.

```text
key = Argon2id(UTF-8 password, salt, t_cost, m_cost_kib, lanes)  // 32 bytes
KCV = SHA-256(key)[0:16]
```

The salt and derived key normally remain unchanged across saves. Native exports
create their own header salt and key. The save counter is not used as a nonce.

Before derivation, `vk_params_ok` accepts t_cost from 1 through 16, a
memory cost from 8 KiB (the RFC 9106 floor) up to 4194304 KiB (4 GiB), and a lane count of exactly 1
(any other value is refused as unsupported rather than tried and reported as a
wrong password). These caps bound resource use but still permit
expensive files. Do not confuse the reader's accepted minimum with the production
default. Small diagnostic vaults deliberately use cheaper parameters.

## Record body

Plaintext is limited to `VAULT_BODY_MAX` (16 MiB). Attachments are stored outside
this body.

```text
u32 entry_count
repeat entry_count:
    byte[16] entry_id
    u64 created_FILETIME
    u64 modified_FILETIME
    u32 field_count
    repeat field_count:
        u16 type
        u32 length
        byte[length] value
```

A field's base kind is `type & 0x00ff`. The `0x8000` flag (`VF_LABELED`)
means the value starts with a custom label:

```text
u16 label_length_in_bytes | UTF-8 label | remaining value bytes
```

Text fields use UTF-8. Raw fields such as attachment references and history
have their own encodings. Lengths are checked against the containing record/body.
Skipping an unknown field during interpretation is not permission to discard it
when rewriting metadata.

### Field kinds

| Tag | Symbol | Value |
|---|---|---|
| 1 | `VF_TITLE` | Title |
| 2 | `VF_USERNAME` | Username |
| 3 | `VF_SECRET` | Secret |
| 4 | `VF_URL` | URL |
| 5 | `VF_NOTES` | Notes |
| 7 | `VF_TOTP` | Base32 TOTP key |
| 8 | `VF_TEXT` | Generic single-line text |
| 9, 10 | `VF_IMAGE`, `VF_FILE` | Attachment reference |
| 11 | `VF_FAV` | Favorite marker, text `1` |
| 12 | `VF_ICON` | 12 hex (`GGGGCCCCCCCC`) for a BMP glyph, 16 hex (`GGGGGGGGCCCCCCCC`) for a supplementary Unicode scalar (e.g. emoji), or 24 hex (`GGGGGGGGCCCCCCCCFFFFFFFF`) adding an explicit icon/accent color (`00000000` auto, `02BBGGRR` solid RGB, or `01000001`–`01000008` animated palette) alongside the 32-bit tile background color (`00BBGGRR` solid RGB or `01000001`–`01000008` animated palette) |
| 13 | `VF_PWHIST` | Raw field-history event |
| 14 | `VF_DELETED` | Trash timestamp, 16 hexadecimal FILETIME characters |
| 15 | `VF_GROUP` | Section-heading text |
| 16 | `VF_SPACER` | Blank layout gap |
| 17 | `VF_SYSTEM` | Unlabelled first-field (`field[0]`) system marker; one-byte schema version (at most one system entry per vault) |
| 18 | `VF_SYS_PWVERIFY` | Unlabelled u64 reminder FILETIME (valid only inside the `VF_SYSTEM` entry) |
| 19 | Retired | Earlier grace-period field; do not reuse |
| 20 | `VF_PIN` | PIN / passcode secret (UTF-8; evaluated by `pin_eval` rather than password class rules) |

The writer limits labels to `MAX_LABEL_BYTES` (384 bytes). The reader checks
a label against the containing field rather than imposing that writer limit.
GUI field values are limited to `CONVW_MAX - 1` wide characters (16383);
the UTF-8 conversion capacity must accommodate them. The `convcap` probe guards
against silently writing an overlong conversion as an empty field.

### History

A current raw `VF_PWHIST` event is:

```text
u64 FILETIME | UTF-16 label + NUL | UTF-16 old value + NUL | u32 action
```

Action 0 means CHANGED; action 1 means ADDED and has an empty old value.
`vault_body_validate` enforces even byte alignment and valid UTF-16LE NUL termination on
every `VF_PWHIST` payload before exposing the unlocked body. The reader also accepts
older shapes without the action (CHANGED) and without a label (attributed to the default
Password field). History is excluded from native and ZIP exports.

### System items

A system item is an ordinary entry whose first field is `VF_SYSTEM`.
Its physical index remains part of the body even though user lists hide it.
Native/ZIP exchange excludes the source system metadata.

See [System items](SYSITEM_DESIGN.md) for creation, preservation, filtering,
and the distinction between physical indexes and user-visible counts.

## Attachments

A `VF_IMAGE` or `VF_FILE` value contains a 68-byte reference:

```text
byte[16] id | byte[32] key | byte[12] nonce | u64 plaintext_length
```

Each attachment has its own AES-256-GCM key and nonce, with a per-attachment cap of
`ATT_FILE_MAX` (`256 MiB`, `0x10000000`) and a total attachment-section cap of
`ATT_TOTAL_MAX` (`3,840 MiB`, `0xF0000000`), enforced with overflow-checked 64-bit
arithmetic in both `vault_body_validate` and `attach_build` (`attovfkat`). The reference
lives inside the encrypted body; its ciphertext lives in the optional trailing section:

```text
repeat for attachment records:
    byte[16] id | u64 ciphertext_length | ciphertext | byte[16] GCM_tag
u32 "VATT" | u64 total_attachment_record_bytes
```

Attachment GCM AAD is the 24-byte record prefix (ID and length).
GCM ciphertext length equals plaintext length. The `VATT` footer is omitted
when there are no attachments; if a zero-attachment vault's body GCM `tag[4..7]`
coincidentally equals `"VATT"`, `vault_seal_write` draws a fresh 12-byte body nonce and
reseals (`vattcolkat`), while `vault_unlock` falls back cleanly to `g_att_total = 0` if
an unparsed legacy collision occurs. The mandatory version-2 `VMAC` trailer always
remains.

New content is staged with fresh random key/nonce metadata. Unchanged
attachments can be copied as ciphertext during a save or native export.
Keeping an attachment key/nonce is safe only for the unchanged message and AAD;
do not mutate staged plaintext under retained metadata.

## File authentication trailer

The final 44 bytes are:

```text
u64 save_counter | byte[32] MAC | u32 "VMAC"
```

`vault_file_mac` initializes BLAKE2b with a 32-byte digest length and feeds:

```text
MAC = BLAKE2b-256(
    ASCII("vordr-file-mac-v1") || vault_key ||
    file_bytes_before_counter || little_endian_u64(save_counter)
)
```

The 17-byte domain string has no NUL terminator in the hash. This is a
prefix-keyed construction, **not** the native keyed-BLAKE2 parameter mode,
and not a truncated BLAKE2b-512 digest. Matching the digest-length parameter
matters for interoperability.

A version-2 image must have a valid file MAC. Version 1, which could omit the
trailer, is not accepted. The KCV and GCM tag use constant-time comparisons;
the full-file MAC is also verified before record data is exposed.

The counter is mirrored per vault under `HKCU\SOFTWARE\Vordr\Rollback`, named by the
32-character lowercase hex `SHA-256` prefix (`[:16]`) of the upper-cased canonicalized
handle path (`GetFinalPathNameByHandleW`) so alternate path spellings, junctions, and
casing share one high-water mark (`rbtest`). `reg_ctr_set` enforces monotonicity—never
overwriting a stored 8-byte counter with a smaller value—and `vault_seal_write` refuses
to wrap `u64` `-1`. An older file counter raises a rollback warning on both password and
TPM unlock. Because the mirror resides in user-writable local registry state rather than
hardware monotonic storage, restoring both the vault and `HKCU` (or opening an older copy
on a fresh machine) cannot be detected locally.

## Writes and concurrency

`vault_reseal` takes a short advisory `<vault>.lock` file lock, checks for
external changes, refreshes the body nonce, and calls the sealing writer.
The writer flushes a temporary image before replacement and rotates nearby
`.bak1`–`.bak3` generations. A failed flush must not be reported as a successful
save.

Multiple readers are allowed. A save refuses an externally changed image
instead of blindly overwriting it. A clean GUI can reload through
`vault_reload` using the existing key. These mechanisms rely on cooperating
writers and filesystem semantics; they are not a distributed merge protocol.

For the transaction and failure flow, see [Architecture](ARCHITECTURE.md#save-and-retry).

## TPM-Unlock registry envelopes

When TPM convenience unlock is enrolled, `HKCU\SOFTWARE\Vordr\TPM-Unlock` stores a
`REG_BINARY` envelope named by the 32-character lowercase hex `SHA-256` prefix (`[:16]`)
of the upper-cased canonical vault path (`TPM_BLOB_CAP = 1024` bytes; pre-C6 raw-path
value names are pruned automatically). Active envelopes start with magic `VTPM`
(`0x4D505456` LE) and `version = 1`; legacy raw RSA-OAEP blobs (`256..512` bytes, no
`VTPM` prefix) are accepted only when the effective `TpmUnlockMode` is `1`
(`TPM_MODE_ALONE`). If the stored envelope's `mode` differs from the effective policy
mode or violates `blob_mode >= g_tpm_want`, Vordr skips unsealing and prompts for the
master password.

- **Mode 1 — TPM Alone (`272` bytes)**:
  `u32 "VTPM" | u16 ver=1 | u8 mode=1 | u8 rsv=0 | u32 rsv2=0 | u32 total_len=272 | byte[256] tpm_ct`
  (`tpm_ct` seals `g_vkey[32]` concatenated with `SHA-256(g_vkey || "Vordr-TPM-v2" || vault_salt || LE32(req_hello))` under `Vordr-<KCV>`; legacy `256`-byte raw RSA-OAEP blobs without the `16`-byte `VTPM` prefix remain readable in Mode 1 only.)
- **Mode 2 — TPM + PIN (`680` bytes outer, `380` bytes inner)**:
  Outer header (`680` B): `u32 "VTPM" | u16 ver=1 | u8 mode=2 | u8 active_slot (0/1) | u32 rsv=0 | u32 total_len=680 | byte[256] state_tpm_ct | byte[12] state_iv | byte[380] enc_state | byte[16] state_tag`
  (`state_tpm_ct` seals random `state_key[32]` under rotating PCP key `Vordr-<KCV>-S{active_slot}`; `enc_state` is encrypted under `AES-256-GCM(key = state_key, AAD = outer[0..15] || inv_hdr[68])`, where `inv_hdr[68] = g_hdr[0..51] || g_hdr[64..79]` excludes the per-save mutable `VH_NONCE`.)
  Inner plaintext (`380` B): `u64 gen | u32 fails | u32 max_tries | u64 last_ft | byte[32] pin_salt | u16 ct_len=256 | u16 rsv=0 | byte[256] main_tpm_ct | byte[12] wrap_iv | byte[32] enc_vkey | byte[16] wrap_tag`
  (`main_tpm_ct` silently seals `tpm_secret[32]` under machine PCP key `Vordr-<KCV>`; `Argon2id(pin, pin_salt, t=2, m=65536 KiB, p=1)` yields `k_wrap[32..63]` so `wrap_key = BLAKE2b-256(tpm_secret || k_wrap)` decrypts `enc_vkey` with `AAD = inv_hdr[68]` without tripping OS-wide TPM dictionary-attack lockout.)
- **Mode 3 — TPM + Windows Hello (`336 + ct_hello_len` bytes, `ct_hello_len` in `65..512`)**:
  `u32 "VTPM" | u16 ver=1 | u8 mode=3 | u8 rsv=0 | u32 rsv2=0 | u32 total_len | u16 ct_tpm_len=256 | u16 ct_hello_len | byte[256] tpm_ct | byte[ct_hello_len] hello_ct | byte[12] gcm_iv | byte[32] enc_vkey | byte[16] gcm_tag`
  (`tpm_ct` seals `tpm_secret[32]` under PCP `Vordr-<KCV>`; `hello_ct` is a `WHLO` v1 envelope (`u32 "WHLO" | u16 ver=1 | u16 cred_len | byte[24] prf_salt | byte[32] masked_secret | byte[cred_len] cred_id`) backed by a Windows Hello platform FIDO2 `PRF` (`hmac-secret`) credential via `webauthn.dll`, verifying `UP|UV` authenticator flags and credential ID on both seal and unseal, scrubbing `pbFirst`, and deleting replaced or orphaned platform credentials via `WebAuthNDeletePlatformCredential`; `wrap_key = BLAKE2b-256(tpm_secret || hello_secret)` decrypts `enc_vkey` with `AAD = blob[0..19] || inv_hdr[68]`.)
