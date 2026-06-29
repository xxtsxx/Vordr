# Vordr — file format and security model

This document specifies the on-disk vault format and states the security
guarantees (and their limits) honestly. Constants live in `src/macros.inc`.

The format reuses Myrkr's proven container discipline:

- a fixed header used **verbatim as the GCM AAD**, so header tampering breaks
  authentication;
- a **key-check value** `KCV = SHA-256(key)[0..15]`, so a wrong master password
  is rejected immediately after the KDF (and the construction is
  key-committing);
- fresh **CSPRNG** salt/nonce per write (`rng_fill` = OS CSPRNG ⊕ RDSEED);
- **atomic writes** via a temp file + `MoveFileExW`.

---

## Vault file `.vordr` (magic `"VRDR"`, v1)

One encrypted file holds the entire vault. On unlock it is decrypted into
`secmem` (VirtualLock'd) memory; on change it is re-sealed and atomically
replaced.

```
VAULT_HDR (64 bytes, = GCM AAD):
    magic       dd   "VRDR"
    version     dd   1
    t_cost      dd   Argon2id passes        (default 3)
    m_cost_kib  dd   Argon2id memory KiB     (default 524288 = 512 MiB)
    lanes       dd   Argon2id parallelism    (1)
    salt        db32 CSPRNG salt
    nonce       db12 GCM nonce
KCV             db16  SHA-256(key)[0..15]
body            AES-256-GCM( serialized entry stream )
tag             db16  GCM tag
```

**Body plaintext** is a length-prefixed record stream (no JSON/CRT parser):
`u32 entry_count` followed by entries. Each entry is a 16-byte random id +
created/modified `FILETIME` + `u32 field_count` + TLV fields
`{u16 type, u32 len, bytes}` for title / username / secret / url / notes
(`VF_*` in `macros.inc`). Every length is `BOUND_CHECK`ed against
`MAX_FIELD_BYTES` / `MAX_ENTRY_BYTES`.

Key: `Argon2id(master password, salt, t, m, p=1) → 32-byte AES-256 key`.

---

## Security model — guarantees and limits

### Confidentiality / integrity
- **At rest:** AES-256-GCM (AEAD) + Argon2id. Quantum-hardened by construction —
  Grover only halves symmetric strength (→ ~128-bit) and Argon2id's
  memory-hardness is unaffected by Shor. There is no public-key crypto anywhere,
  so nothing is exposed to Shor's algorithm.
- A wrong master password is caught by the KCV right after the KDF
  (`EXIT_LOCKED`); any tampering with the file fails GCM authentication
  (`EXIT_AUTH`).

### Hostile-OS resistance is best-effort in user mode
Vordr raises the cost of compromise — VirtualLock keeps decrypted secrets out
of the pagefile, the IAT is locked read-only, W^X / ASLR / DEP / NX / CET +
software shadow stack / stack canaries / DLPV / tagged heap are all on, and all
key material is `secure_zero`d. But against a **fully compromised kernel** (or a
DMA-capable attacker), user-mode defenses cannot be absolute. We state this
plainly rather than overclaiming.

### Not yet addressed
- No multi-process / cross-host file locking (single-writer assumption).
- No external security review.
