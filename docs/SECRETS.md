# Vordr — secret-buffer audit

Every buffer that can hold a master password, a derived key, or a plaintext
secret, with its lock status (VirtualLock → non-pageable, so it can't leak
through the pagefile / a hibernation image) and its wipe site.

`sec_lock_statics` (src/secmem.asm) VirtualLock's every fixed static secret
buffer once at startup (called from `start` in main.asm, after `hardening_init`);
`sec_lock` grows the process working set and retries if a lock is refused.
Heap secrets go through `secmem_alloc`, which VirtualLock's on allocation.

| Buffer | Location | Size | Holds | Locked by | Wiped at |
|---|---|---|---|---|---|
| `g_cfg_pass` | main.asm:118 | 1025 B | master password (UTF-8) | `sec_lock_statics` | main.asm:812, main.asm:1205 (`secure_zero`) |
| `g_vkey` | vault.asm:169 | 32 B | derived vault key | `sec_lock_statics` | vault.asm:778 (`vault_lock`) |
| `g_pwbuf` | gui.asm:1051 | 2048 B | unlock/create password field (wide) | `sec_lock_statics` | gui.asm:8728 (+ 1240/8340/8423/8551/8698) |
| `g_pw2buf` | gui.asm:1052 | 2048 B | confirm-password field (wide) | `sec_lock_statics` | gui.asm:8728 |
| `g_secret_w` | gui.asm:1054 | 16384 B | revealed secret for reveal/copy (wide) | `sec_lock_statics` | gui.asm:8221 (`vp_close`) |
| `g_e_totp` | gui.asm:1055 | 512 B | entry-form TOTP key (wide) | `sec_lock_statics` | gui.asm:8227 |
| `g_totp_b32` | gui.asm:1059 | 256 B | selected entry TOTP key (UTF-8) | `sec_lock_statics` | gui.asm:8224, gui.asm:3255 |
| vault body | `secmem_alloc` (vault.asm:683 et al.) | ≤ `VAULT_BODY_MAX` | decrypted entries (all field plaintext, incl. archived pw-history) | `secmem_alloc` (VirtualLock) | `secmem_free` (`secure_zero` before release) |

## Accepted exceptions (documented, intentionally not locked)

- **Argon2 KDF arena** (`g_arena`, argon2.asm) — `VirtualAlloc`'d at
  `m_cost` KiB, which defaults to **512 MiB** (`ARGON2_DEF_M_KIB`). Pinning
  hundreds of MB non-pageable is impractical and would create real memory
  pressure, so it is not locked. It holds intermediate Argon2 mixing blocks
  (not the password or key directly), and is `secure_zero`'d then `VirtualFree`d
  at the end of every `argon2id_hash` call.
- **Export scratch** (zipexport.asm) — the plaintext CSV/JSON assembled during
  "Export all secrets" is transient and wiped after the archive is encrypted;
  it exists only for the duration of an explicit export.
- **`g_conv_w`** (gui.asm) — transient UTF-8→wide display scratch, overwritten
  on each use; never the sole copy of a secret at rest.

No "unknown" rows: every secret buffer above is either locked or listed as an
accepted exception with its rationale.
