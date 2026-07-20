# Vordr — file format and security model

This document specifies the on-disk vault format and states the security
guarantees (and their limits) honestly. Constants live in `src/macros.inc`;
the encoder/decoder is `src/vault.asm`.

The format follows a strict container discipline:

- a fixed **80-byte header** (the 64-byte `VAULT_HDR` parameter block plus the
  16-byte KCV) fed **verbatim as the GCM AAD**, so header tampering breaks
  authentication;
- a **key-check value** `KCV = SHA-256(key)[0..15]`, so a wrong master password
  is rejected immediately after the KDF (and the construction is
  key-committing);
- a 32-byte **CSPRNG salt generated once at vault creation** (it stays fixed
  for the life of the file) and a 12-byte GCM **nonce refreshed from the
  CSPRNG on every save** (`rng_fill` = OS CSPRNG ⊕ RDSEED);
- a **full-file keyed MAC + monotonic save counter** trailer, so any rewrite
  of any byte fails authentication and a stale copy of the file is flagged;
- **atomic writes** via a temp file + `MoveFileExW`, with the previous
  generation rotated into `.bak1`..`.bak3` before the replace.

---

## Vault file `.vordr` (magic `"VRDR"`, v2)

One encrypted file holds the entire vault. On unlock it is decrypted into
`secmem` (VirtualLock'd) memory; on change it is re-sealed and atomically
replaced.

```
[80-byte header][body ciphertext][GCM tag 16][attachment section][file trailer]

header (80 bytes, = GCM AAD):
    magic       dd    "VRDR"
    version     dd    2                      ; v2 = FMAC trailer mandatory
    t_cost      dd    Argon2id passes        (default 3)
    m_cost_kib  dd    Argon2id memory KiB    (default 524288 = 512 MiB)
    lanes       dd    Argon2id parallelism   (1)
    salt        db 32 CSPRNG salt            (fixed at creation)
    nonce       db 12 GCM nonce              (refreshed per save)
KCV             db 16 SHA-256(key)[0..15]
body                AES-256-GCM( serialized entry stream )   ; ≤ 16 MiB plaintext
tag             db 16 GCM tag
```

Key: `Argon2id(master password, salt, t, m, p=1) → 32-byte AES-256 key`.

### Body plaintext (TLV record stream — no JSON/CRT parser)

```
u32 entry_count
entry* :  id db16 | created u64 (FILETIME) | modified u64 (FILETIME) |
          u32 field_count |
          field* { u16 type, u32 len, bytes }
```

Field type tags (`VF_*` in `macros.inc`): `VF_TITLE`=1, `VF_USERNAME`=2,
`VF_SECRET`=3, `VF_URL`=4, `VF_NOTES`=5, `VF_TOTP`=7 (base32 TOTP secret,
RFC 6238), `VF_TEXT`=8 (generic single-line text), `VF_IMAGE`=9 /
`VF_FILE`=10 (attachments — the value is an AttachRef, see below),
`VF_FAV`=11 (favorite marker, value `"1"`), `VF_ICON`=12 (custom icon
override, 12 hex chars `"GGGGCCCCCCCC"`), `VF_PWHIST`=13 (one overwritten
password + when it was changed: 16 hex FILETIME chars + old password),
`VF_DELETED`=14 (trash marker: 16 hex FILETIME chars of when it was deleted).

A stored field type carries the base kind in its low byte
(`VF_KINDMASK = 00FFh`); `VF_LABELED = 8000h` in the high byte marks a field
whose value bytes are prefixed with a custom label:

```
labeled:  bytes = u16 labellen | label_utf8 | value_utf8
plain:    bytes = value_utf8
```

Every length is bounds-checked against the remaining body and the 16 MiB
plaintext cap (`VAULT_BODY_MAX`, record fields only); a custom label is
capped at `MAX_LABEL_BYTES` (128). Unknown `VF_*` tags are skipped, so old
readers tolerate newer files (that is how FAV/ICON/PWHIST/DELETED were
added without a version bump).

### Attachment section (`VATT`)

Large blobs stay out of the record body: a `VF_IMAGE`/`VF_FILE` field's value
is a 68-byte **AttachRef** `{id16 | key32 | nonce12 | u64 ptlen}`, and the
bytes themselves live in a trailing section, each attachment individually
AES-256-GCM'd under its own random key/nonce — which is therefore stored
encrypted, inside the body:

```
( [id16][u64 ctlen][ct][tag16] )*   [u32 "VATT"][u64 entries_len]
```

The 12-byte `"VATT"` trailer is present only when at least one attachment
exists, so an attachment-free vault is byte-identical to the pre-attachment
format.

### File trailer (full-file MAC + anti-rollback counter)

Appended after everything else (44 bytes):

```
[u64 save_counter][32-byte keyed BLAKE2b MAC][u32 "VMAC"]
```

`MAC = BLAKE2b("vordr-file-mac-v1" || vault_key || image || save_counter)` —
BLAKE2b is not length-extendable, so prefix-keying with a domain-separation
string is a sound MAC (`vault_file_mac`). It covers the whole file image up
to and including the counter: header, body ciphertext, GCM tag, and the
attachment section. The counter increments on every save and is mirrored
per-vault under `HKCU\SOFTWARE\Vordr\Rollback` (value name = vault path); on
unlock, a file whose counter is *older* than the mirror sets `g_rollback`
and the GUI warns — a served-stale-copy / accidental-restore tripwire (a
user-writable mirror is not a hard boundary, and is documented as such in
`regcfg.asm`). **The trailer is mandatory in v2:** `vault_unlock` rejects any
file whose header version is not the current `VAULT_VERSION`, and independently
rejects a v2 image that lacks a valid FMAC trailer (`EXIT_AUTH`). This closes a
downgrade where an attacker stripped the trailer to splice unauthenticated bytes
into the attachment section (which GCM does not cover). Every save writes the
trailer, so a well-formed v2 vault always has it; the v1 format (which tolerated
a missing trailer) is no longer accepted.

---

## Security model — guarantees and limits

### Confidentiality / integrity
- **At rest:** AES-256-GCM (AEAD) + Argon2id. Quantum-hardened by construction —
  Grover only halves symmetric strength (→ ~128-bit) and Argon2id's
  memory-hardness is unaffected by Shor. There is no public-key crypto anywhere,
  so nothing is exposed to Shor's algorithm.
- A wrong master password is caught by the KCV right after the KDF
  (`EXIT_LOCKED`); any tampering with the file fails GCM authentication or the
  full-file MAC (`EXIT_AUTH`); a whole-file rollback is flagged via the save
  counter (above).

### Hostile-OS resistance is best-effort in user mode
Vordr raises the cost of compromise — VirtualLock keeps decrypted secrets out
of the pagefile, the IAT is locked read-only, W^X / ASLR / DEP / NX / CET +
software shadow stack / stack canaries / DLPV / tagged heap are all on, and all
key material is `secure_zero`'d. But against a **fully compromised kernel** (or a
DMA-capable attacker), user-mode defenses cannot be absolute. We state this
plainly rather than overclaiming.

### Not yet addressed
- No multi-process / cross-host file locking (single-writer assumption; a
  best-effort external-change tripwire — `vault_ext_changed`, a size + header
  hash snapshot taken at load/save — warns before overwriting a file that
  changed under us).
- No external security review.
