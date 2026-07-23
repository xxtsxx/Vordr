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
| `g_cfg_pass` | main.asm (`.data?`) | 1025 B | master password (UTF-8) | `sec_lock_statics` | `gui_wipepw` (gui.asm, after each unlock/create attempt), `start` / `wstart` (process exit) — all `secure_zero` |
| `g_vkey` | vault.asm (`.data?`) | 32 B | derived vault key | `sec_lock_statics` | `vault_lock` (vault.asm) |
| `g_pwbuf` | gui.asm (`.data?`) | 2048 B | unlock/create password field (wide) | `sec_lock_statics` | `password_to_utf8` (main.asm, wipes the wide source after conversion), `gui_wipepw_create`, `gui_xlpw_strength` (gui.asm) |
| `g_pw2buf` | gui.asm (`.data?`) | 2048 B | confirm-password field (wide) | `sec_lock_statics` | `gui_wipepw_create`, `gui_xlpw_strength` (gui.asm) |
| `g_secret_w` | gui.asm (`.data?`) | 16384 B | revealed secret for reveal/copy (wide) | `sec_lock_statics` | `vault_proc` close/lock path (gui.asm) |
| `g_rowpw_w` | gui.asm (`.data?`) | 1024 B | reveal-overlay secret copy (wide) | `sec_lock_statics` | `gui_colorpw_hide` + `vault_proc` close/lock (gui.asm) |
| `g_e_totp` | gui.asm (`.data?`) | 512 B | entry-form TOTP key (wide) | `sec_lock_statics` | `vault_proc` close/lock path (gui.asm) |
| `g_totp_b32` | gui.asm (`.data?`) | 256 B | selected entry TOTP key (UTF-8) | `sec_lock_statics` | `vault_proc` close/lock path (gui.asm) |
| vault body | `secmem_alloc` (called from `vault_unlock` / `do_init`, vault.asm) | ≤ `VAULT_BODY_MAX` | decrypted entries (all field plaintext, incl. archived pw-history) | `secmem_alloc` (VirtualLock) | `secmem_free` (`secure_zero` before release) |

Every static buffer above is additionally wiped on the crash-containment path
by `secmem_panic_wipe` (secmem.asm), which the VEH runs before terminating.

## Accepted exceptions (documented, intentionally not locked)

- **Argon2 KDF arena** (`g_arena`, argon2.asm) — `VirtualAlloc`'d at
  `m_cost` KiB, which defaults to **512 MiB** (`ARGON2_DEF_M_KIB`). Pinning
  hundreds of MB non-pageable is impractical and would create real memory
  pressure, so it is not locked. It holds intermediate Argon2 mixing blocks
  (not the password or key directly), and is `secure_zero`'d then `VirtualFree`d
  at the end of every `argon2id_hash` call. **`g_hbuf`** (argon2.asm, 80 B) holds
  the key-equivalent H0 pre-hash for the same call; it is `.data?`, not locked
  (transient, one KDF call), and `secure_zero`'d on every exit of `argon2id_hash`.
- **`g_conv` / `g_convlabel`** (vault.asm) — UTF-8 scratch for a field value /
  label while an entry is serialized (`conv_w2u` in `va_field_*`). Not locked
  (transient, overwritten per field); `secure_zero`'d in `vault_lock`.
- **`g_urlbuf` / `g_urlbuf2`** (gui.asm) — a clicked URL field (not a
  password-class secret, but may carry internal hosts/tokens); `secure_zero`'d
  after the `ShellExecute` in `gui_url_open`.
- **Export scratch** (zipexport.asm) — the plaintext `vordr.json` assembled
  during "Export all secrets" is transient: `ze_compose` releases it with
  `mem_free` (which `secure_zero`s before `VirtualFree`), the archive buffer
  and AES key material are wiped in `ze_free`, and the UTF-8 export-password
  copy is wiped in `ze_compose`. It exists only for the duration of an
  explicit export.
- **`g_conv_w`** (gui.asm) — transient UTF-8→wide display scratch, overwritten
  on each use; never the sole copy of a secret at rest.
- **Attachment decrypt-to-temp** (gui.asm `gui_tag_open`) — opening an attachment
  writes its plaintext to `%TEMP%` so the OS default app can read it (unavoidable
  for the ShellExecute hand-off). This is *not* left to the OS: every such path is
  tracked in `g_tempfiles` and, on vault lock/exit, `gui_temp_purge` overwrites
  the file's whole length with zeros, `FlushFileBuffers`, then `DeleteFileW`
  (secure temp-file tracking; regression-tested by the `tmptest` verb). The
  **Disable attachment preview** setting (`NoPreview`) suppresses the temp file
  entirely — attachments are then download-only, so no plaintext copy is ever
  written outside the vault.

No "unknown" rows: every secret buffer above is either locked or listed as an
accepted exception with its rationale.

## Comparison audit (constant-time discipline)

Every memory-vs-memory comparison in `src/*.asm`, classified. The primitive is
`ct_memcmp` (hardening.asm): OR-accumulated differences, no data-dependent
branches, branchless collapse to 0/1 — KAT'd in selftest (equal / differ-first /
differ-last / zero-length). `gui_wstr_eq` (gui.asm) is the constant-time wide
NUL-terminated equality: content differences are accumulated, never branched
on; only min(len_a, len_b) is timing-visible (a fixed-bound scan would read
past short allocations). KAT'd in selftest (equal / differ-last / prefix both
ways).

### Secret-touching (all constant-time)

| Site | Compares | Via |
|---|---|---|
| vault unlock KCV | recomputed KCV vs stored (`vk_kcv_ok`, vault.asm) | `ct_memcmp` |
| AES-GCM tag check | computed vs stored tag (`gcm_open`, aesgcm.asm) | `ct_memcmp` |
| TPM-unsealed vault key | recomputed KCV vs stored after unseal — the TPM path reuses the same `vk_kcv_ok` check in vault.asm (the only `ct_memcmp` inside tpm.asm itself is the dbg-only `cmd_tpmtest` probe) | `ct_memcmp` |
| vault/attach self-test KATs | decrypted output vs expected (`vault_selftest`, `vault_field_selftest`, `attach_selftest`, vault.asm) | `ct_memcmp` |
| .vaultz import pw verifier | PBKDF2-derived 2 bytes vs stored (zipimport.asm `zi_decrypt`) | `ct_memcmp` |
| .vaultz import HMAC tag | HMAC-SHA1[:10] vs stored (zipimport.asm `zi_decrypt`) | `ct_memcmp` |
| create/change password confirm | `g_pwbuf` vs `g_pw2buf` (gui.asm `gui_pw_match`) | `gui_wstr_eq` |
| export password confirm | `g_xlpw` vs `g_xlpw2` (gui.asm `xlpw_proc`) | `gui_wstr_eq` |
| pw-history set-diff | old secret value vs new on save (gui.asm `gui_pwhist_capture`) | `gui_wstr_eq` |

### Not secret-dependent (early-exit is fine)

- **Heap canary checks** (hardening.asm) — per-boot random tag; a mismatch
  fail-fasts immediately, timing tells an attacker nothing they don't learn
  from the crash.
- **zip member-name / JSON literal matching** (zipimport.asm `zi_find`,
  `zj_lit`) — public archive structure and format keywords.
- **Attachment-ID lookup** (vault.asm `attach_find`) — random 16-byte IDs used
  as table keys, not key material; in-process lookup on already-decrypted data.
- **GUI sort/search/labels** (gui.asm `gui_title_cmp`, `wide_find`, pwhist
  label routing) — entry titles/labels for local display; no oracle exposed.
- **pwgen alphabet filter** (pwgen.asm `filter_ambig`) — compares the public
  alphabet against the public ambiguous-character list, before any secret
  exists.
- **secscan sentinel scan** (secmem.asm) — diagnostic probe.
