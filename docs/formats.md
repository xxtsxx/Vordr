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

Before derivation, `vk_params_ok` accepts t_cost from 1 through 16 and a nonzero
memory cost no greater than 4194304 KiB (4 GiB); the reader separately checks
the supported lane count. These caps bound resource use but still permit
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
| 12 | `VF_ICON` | 12 hex characters: glyph and COLORREF (`GGGGCCCCCCCC`) |
| 13 | `VF_PWHIST` | Raw field-history event |
| 14 | `VF_DELETED` | Trash timestamp, 16 hexadecimal FILETIME characters |
| 15 | `VF_GROUP` | Section-heading text |
| 16 | `VF_SPACER` | Blank layout gap |
| 17 | `VF_SYSTEM` | First-field system marker; one-byte schema version |
| 18 | `VF_SYS_PWVERIFY` | u64 reminder FILETIME |
| 19 | Retired | Earlier grace-period field; do not reuse |

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
The reader also accepts older shapes without the action (CHANGED), and
without a label (attributed to the default Password field). History is excluded
from native and ZIP exports.

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

Each attachment has its own AES-256-GCM key and nonce. The reference is inside
the encrypted body. Its ciphertext lives in the optional trailing section:

```text
repeat for attachment records:
    byte[16] id | u64 ciphertext_length | ciphertext | byte[16] GCM_tag
u32 "VATT" | u64 total_attachment_record_bytes
```

Attachment GCM AAD is the 24-byte record prefix (ID and length).
GCM ciphertext length equals plaintext length. The VATT footer is omitted
when there are no attachments; the mandatory version-2 VMAC trailer remains.

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

The counter is mirrored per vault path under
`HKCU\SOFTWARE\Vordr\Rollback`. An older counter sets a rollback warning.
The mirror is user-writable local evidence, not a hardware monotonic counter.
It cannot detect rollback of both copies or establish history on a fresh machine.

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
