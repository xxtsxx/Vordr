# Vordr — Improvement Plans

Rewritten 2026-07-18 against the source tree. The previous version had drifted
(it referenced `tests\redteam.py`, `docs/FORMAT.md`, `inflate.asm`, and CLI verbs
that no longer exist) and was deleted. Every plan below was verified absent or
partial in the code before being listed here.

**Status note (2026-07-18):** `origin/audit-cleanup` was merged into master
(merge commit 8e893a0). Fifteen plans it implemented were removed from this
file: anti-rollback save counter, full-file MAC, save durability + backup
rotation, crash containment, single-instance + external-change detection,
fuzzy sidebar search, trash/undo-delete, drag-and-drop attachments, central
font factory (the S/M/L size setting was added then deliberately dropped in
1b562dc), parser fuzzer, zip-import fuzzer, dead-code detector, reproducible
builds, parallel fail-closed KAT gate (`pkat`, after measurement showed the
KATs cost ~0 ms), and sidebar virtualization (closed with an engineering
verdict: the owner-draw listbox already paints on demand).

**Scope cut (2026-07-18):** E1 (otpauth import), E3 (tags), E4 (templates),
E5 (expiry), E10 (emergency sheet), E12 (clip verb), E13 (breach check),
E14 (auto-type), F3 (DPI), F5 (screen-reader) and F7 (localization) were
removed as out of project scope; recover them from git history if ever wanted.

**Done 2026-07-19:** A1 (cpu_gate now requires SHA-NI; refusal text updated,
refusal path verified with the bit masked) and A2 (framecheck evaluates
symbolic frame sizes — `equ` chains and `sizeof` — and reports unresolvable
frames instead of silently skipping; 11 symbolic-size procs now scanned.
Note: FP findings are warn-by-design, so detection was verified at warn level
with a seeded case, not a strict-build failure). Both removed from this file.

**Done 2026-07-19 (D-group):** D1 (aurora path, `securedesk` spike → dbg-only,
CSV corpse — plus `deadcode.py` no longer counts `public`/`extern` as
references and now scans `macros.inc`; the improved tool found and led to the
removal of `aes_ecb_decrypt`, `theme_backdrop`, `vault_add_entry`,
`ze_export_all`, `va_field`, `SHA1_CTX_SIZE` and six dead CLI field buffers),
D2 (formats.md rewritten, SECRETS.md re-cited by proc, README TPM/density/
BLAKE2b/rollback/MAC claims corrected, stale comments/strings everywhere,
`.gitignore` pruned, committed log/reg artifacts deleted), D3 (`.inc` files
now documented as canonical), D4 (`tools/idcheck.py` gates rc↔asm ID sync in
strict builds), D5 (SDK version resolved at build time). All removed from
this file.

**Done 2026-07-19 (redesign merge, 2c9f744):** the `Vordr_ALT` redesign branch
(36 commits) was merged and the fork deleted. Landed: custom borderless frame
with title-bar search control + command dock, ghost buttons, resizable window
with anchor reflow, read-only-by-default opens + save retry with error dialog,
per-vault availability state machine, `VAULTCTX`/VSLOT multi-vault contexts
with a tab strip and cross-vault search, modular details pane (heading dock,
VF_GROUP/VF_SPACER blocks, entry templates), Ctrl+K/N/G/L shortcuts, and the
mvtest/mvswitch/avtest gate probes. E8 (multi-vault) and F2 (resizable window)
removed from this file as done; the remaining redesign items are group R.
The reverted virtual-scroll commits were secured on branch `recovered-scroll`
before the fork was deleted.

**Done 2026-07-20 (security audit → PR #2, branch `audit-fixes`):** a full-tree
security + stability audit. Landed: the ZIP import parser is fully bounded (the
attacker-controlled overflows in `zj_str`, the field loop, `zi_u2w`/
`zi_stage_title`/`zi_addattach`, and the staged-entry count are all closed);
opaque attachment ZIP member names (entry titles no longer leak in cleartext);
overflow-safe `attach_index_build` bounds + an `attach_open` ctlen/ptlen cross-
check; **the FMAC trailer is now mandatory, with `VAULT_VERSION` bumped to 2**
(see the Format note); a passphrase-length bound in `pwgen_ex`; secret-wipe gaps
closed (`g_hbuf`, `g_rowpw_w`, `g_conv`/`g_convlabel`, `g_urlbuf`, and `g_cfg_pass`
after the startup KAT gate); `argon2id_hash`/`run_selftest` preserve r12/r13/r15;
`gcm_open` scrubs `outp` on tag mismatch; `reg_query_sz` gets a REG_SZ type-check +
NUL-termination; an http/https URL allowlist; `base32_decode` fails instead of
truncating; `write_file`/`log_open` guards; TPM RSA-2048 set explicitly; the
`pkat` CS-teardown race; dead empty `crc32.asm` removed. Follow-ups the audit
surfaced are new below: C7, D6, E16, G8 (the deferred CI SHA-pin is G7.3).

**Done 2026-07-20 (C6, registry location-leak hygiene → PR #2):** the per-vault
HKCU value names — the rollback mirror (`reg_ctr_set`/`reg_ctr_get`) and the TPM
blob (`reg_tpm_set`/`get`/`del`), both previously keyed by the **raw vault path**
— are now SHA-256-hashed to a fixed 32-hex name by `reg_hash_name`, so the vault
location no longer leaks; `reg_prune_all` (called from `vault_unlock`) deletes any
surviving legacy path-named value. Runtime-verified: after a run the Rollback key
holds only hashed names, zero path-leaking. This also closes C4.2 (the TPM value-
name leak), so C4 keeps only the Hello-PIN item. Remaining nicety (not a leak): a
hashed orphan left by a *moved* vault is opaque but not pruned — a touch-timestamp
+ expiry could add that later if wanted.

**Done 2026-07-21 (C8, concurrent shared-drive access → PR #2):** vaults open
read-only with full share (they already did); a save takes a brief advisory
`<vault>.lock` (`CREATE_NEW` + `FILE_FLAG_DELETE_ON_CLOSE`) and, under it, refuses
to overwrite a vault another writer changed since load (`EXIT_CHANGED`) - the GUI
reloads via `vault_reload` (re-decrypt with the existing key, no re-KDF) instead
of clobbering. A held lock -> `EXIT_BUSY` "try again"; the idle poll silently
refreshes a clean vault; a read-only vault file auto-enters E9 read-only mode.
Probes `reload` + `cowrite` gated in RUNALL; `formats.md` updated. The full
"stash + precise re-apply of the pending edit" and an `AVSLOT`-backed retry with
backoff are possible refinements (the current reload-safe flow already prevents
lost updates).

House rules:

- Plan IDs are stable: `C4` stays `C4` when other plans are completed or added.
  Completed plans are removed from this file in the commit that ships them.
  Code comments must cite plan titles, never bare IDs (IDs outlive rewrites).
- Update this file in the same commit as any behavior change.
- Cite proc/file names, not line numbers (line numbers rot).

## Conventions

- **BUILD** = `build.cmd` completes with `BUILD OK: bin\vordr.exe` (kill any
  running `vordr.exe` first; a locked exe fails LNK1104). Run from an "x64
  Native Tools Command Prompt for VS".
- **STRICT** = `build.cmd strict` — `tools/framecheck.py` FATAL findings fail
  the build.
- **RELEASE** = `build.cmd release` — reproducible build (`/Brepro`,
  `/pdbaltpath`); prints the SHA-256 to publish in `docs/RELEASES.md`.
- **SELFTEST** = `bin\vordr.exe selftest` prints `all self-tests passed`.
- **RUNALL** = `tests\run_all.cmd` — the one-command gate and the entire CI
  pipeline: stage 1 redteam (dbg build; 8 fault-injection cases each exit with
  `0xFADE<code>` in the high word, `iat` dies with `0xC0000005`), stage 2
  strict build, stage 3 selftest, stage 4 probes: `seedtest` → `atgen` →
  `zitest` → `phtest` → `secscan` → `tmptest` → `fztest` → `trtest` →
  `vfuzz` → `fuzzzip` → `bktest` → `mactest` → `rbtest` → `xctest` → `pkat`.
  `--quick` skips stage 1.
- **FRAMES** = no >4-arg `WINCALL` directly inside a raw `sub rsp,64` dialog
  proc (`create_proc`, `unlock_proc`, `vault_proc`, `msg_proc`, `about_proc`,
  …); wide calls go in a `FRAME_PROLOG N` helper. This is the BEX64/offset-0
  crash class.
- **PROBE** = the CLI is diagnostics-only by design: no vault path, password,
  or secret on the command line, and no add/get/list verbs. Scripted vault
  scenarios mean `seedtest`, an existing probe verb, or a new dbg-only probe
  verb.

## Sequencing

- **Format note:** the audit-cleanup merge added the FMAC trailer (a trailing
  `[u64 save_counter][keyed BLAKE2b MAC][magic]` block after the VATT trailer)
  plus a reserved `VF_DELETED` tag as **v1** additions that old readers ignored.
  The 2026-07-20 audit made the FMAC trailer **mandatory** and bumped the header
  to **v2**: `vault_unlock` now rejects any image whose version != `VAULT_VERSION`
  and any v2 image lacking a valid FMAC (`EXIT_AUTH`), so the attachment section
  is always authenticated. In-body **field** additions still follow the tolerant
  pattern — a new reserved `VF_*` tag old readers skip (verify the unknown-tag
  skip path first) — but any change to authentication or container layout must
  bump `VAULT_VERSION`, not ride on tag-skipping.

---

## C. Hardening & platform

### C3. VirtualLock failure policy
`secmem_alloc` ignores a failed `sec_lock` — the secret stays pageable,
silently.

1. Decide fail-closed (refuse unlock) vs loud one-time warning; implement.
   *Test:* a forced-failure dbg hook exercises the chosen path; SELFTEST
   unaffected.

### C4. TPM unlock hardening
All ncrypt calls are `NCRYPT_SILENT` — any same-user process can unwrap the
vault key.

1. Optional Hello PIN / UI policy on key creation (setting; default
   unchanged). *Test:* with the policy set, unseal prompts; without, silent as
   today.

(The former blob-hygiene item — the TPM registry value name was the full vault
path — is fixed by C6: the name is now hashed and legacy path-named values are
pruned at unlock.)

### C5. Audit-log honesty
The "audit log" only records CLI diagnostic verbs; GUI unlock/save/export log
nothing.

1. Log GUI security events (unlock/lock/save/export/import, success and
   failure) or stop billing it as an audit log. Fix the stale header examples
   (`add/get/list`) and the "Event Log" comment in `main.asm`. *Test:* a GUI
   session produces the expected lines; no planted secret appears in any line.

### C7. Temp-file exclusive create (atomic-save hardening)
`write_file` (fileio.asm) creates `<vault>.tmp` with `CREATE_ALWAYS` and no
exclusive-create / reparse-point check. In a writable shared directory a
pre-planted `<vault>.tmp` symlink could redirect the save. The vault dir is
normally user-owned (hence low), but the atomic-write guarantee in `formats.md`
should hold regardless.

1. Create the temp with `CREATE_NEW` (retry with a fresh unpredictable suffix on
   collision) and reject a pre-existing reparse point. *Test:* a pre-planted
   `<vault>.tmp` (plain + symlink) is not followed; `bktest`/`tmptest` stay green.

---

## D. Docs & tooling

### D6. SECRETS.md buffer-table sync
The 2026-07-20 audit added wipes for `g_hbuf` (Argon2 H0 pre-hash), `g_rowpw_w`
(reveal-overlay secret), `g_conv`/`g_convlabel` (field value/label scratch) and
`g_urlbuf`. None appear in `SECRETS.md`'s buffer table or accepted-exceptions
list, so its "no unknown rows" invariant no longer holds.

1. Add the four buffers with lock status + wipe site. Confirm each one's
   VirtualLock status — in particular whether `g_rowpw_w` (a revealed plaintext
   secret) is in `sec_lock_statics`; if it is not, either lock it or list it as a
   justified transient exception (and, if unlocked, file a C-group lock task).
   *Test:* every secret buffer in `src/*.asm` maps to a table row or a documented
   exception (grep audit passes).

---

## E. Features (all verified absent)

### E6. Vault health dashboard
(The redesign's cheap precursor — weak/reused dot indicators inline on sidebar
tiles — can ship first and shares the same analysis pass.)

1. Analysis pass: strength buckets (existing `gui_pw_strength` core),
   exact-duplicates via BLAKE2b, age via pw-history timestamps; dbg `health`
   verb prints counts for a scripted 10-entry vault — exact match.
2. Dashboard dialog; clicking a row jumps to the entry. *Test:* navigation
   highlights the right tile.
3. Sidebar badge with the worst-bucket count. *Test:* fix one weak password →
   badge decrements after save.

### E9. Read-only mode
(The redesign's B1 landed read-only-by-default opens with full share masks, so
this is now nearly free.)

**Landed (PR #2, 2026-07-20):** `g_readonly` (gui.asm); the `--ro` launch flag
(main.asm `is_cli_command` exemption — verified via cdb: `--ro` → `g_readonly=1`,
else 0) and the unlock-dialog "Open read-only" checkbox (`IDC_U_RONLY`, read in
`gui_unlock`, mirrored from `--ro` in `up_init`); an airtight write block
(`vault_reseal` no-ops when RO — RUNALL stays green because the CLI/probes never
set the flag); `gui_set_editmode` forced to view; New/Delete/Favorite/Import and
the auto-purge (`gui_purge_trash`) gated; the create path forces RW; and a
`g_vault_title_ro` "(read-only)" window title.

**Remaining:**
1. Grey out (disable) the still-visible mutation buttons — New / Edit / Delete /
   Favorite / Import — in `vp_init` when RO (the *actions* are already gated, so
   this is UX polish, not a hole). Theme the plain `AUTOCHECKBOX` to match the
   custom-painted dialog. *Test:* RO open shows the buttons disabled.
2. Gate the password-history purge (`gui_pwhist_click`) at the in-memory level
   too (the `vault_reseal` backstop already blocks its persistence).
3. Visual/interactive verification: confirm the "(read-only)" title suffix renders
   and that a full RO UI walk leaves the file mtime unchanged. *Test:* both modes.

### E15. DEFLATE in zipimport (or a documented limitation)
Imports accept only Vordr's own STORE-inside-AES exports today; 7-Zip/WinRAR
AES zips are rejected. There is no inflate in this repo — sibling project
`myrkr` has a proven puff-style decoder with KATs to port.

1. Decide: port inflate (recommended) or document "imports Vordr exports
   only" in README + the import dialog. *Test:* the choice is written down.
2. If porting: `inflate.asm` + KAT selftests; the import path dispatches
   method 8 vs 0. *Test:* a 7-Zip-produced deflated AE-2 zip imports
   correctly; RUNALL (incl. the `fuzzzip` stage) green.

### E16. pwgen output-capacity parameter
The 2026-07-20 audit bounded the passphrase word count (`PWGEN_PP_MAXWORDS`) to
stop `pwgen_ex` overflowing a caller buffer (the GUI's 260-byte `g_genout`). That
is a stopgap: `pwgen_ex` still takes no explicit output-capacity argument, so a
future caller with a small buffer and a large `n` could overflow for a
non-passphrase style too.

1. Add an `outcap` argument to `pwgen_ex` (and `pwgen`); bound every write; drop
   the `PWGEN_PP_MAXWORDS` special case. Update all call sites (~12) and their
   frame sizes. *Test:* a dbg probe requests each style into a deliberately-tiny
   buffer and gets a clean truncation/refusal, never an overwrite; SELFTEST +
   `atgen` green.

---

## R. Redesign remainder

Folded in from `docs/REDESIGN_PLAN.md` (the standalone doc was merged into
this file and deleted). The redesign landed with merge 2c9f744: custom frame +
title-bar search & dock, ghost buttons, resizable reflow, the B1–B3 IO
contract, multi-vault contexts/tabs/cross-vault search, modular details pane
(groups/spacers/templates), and Ctrl+K/N/G/L shortcuts. What remains:

### R1. Detail-pane virtual scroll
The scroll resurrection did not land with the merge. The reverted work is
secured in-repo on branch `recovered-scroll` (18c747e virtual-scroll field
list, b47fd3b drop the room cap); anchor reflow + elastic widths did land.

1. Cherry-pick the two commits and adapt them to the anchor-reflow layout;
   pixel viewport from the detail rect. *Test:* a 25-field entry on a 350-px
   window scrolls cleanly with no paint over the header/dock; RUNALL.
2. Precision wheel accumulation + PgUp/PgDn/Home/End when the pane has focus.

### R2. Command palette (Ctrl+Shift+P)
The landed title-bar overlay in command mode (`>` prefix): Lock, Switch
vault, New item, Export, Import, Settings, theme switching, Trash view.
*Test:* every command fires; fuzzy ranks correctly; Esc closes.

### R3. DPI audit
Revived by the redesign (supersedes the 2026-07-18 scope cut of the old F3).
The layout engine already scales; sweep painters for hardcoded px through a
`dpi_scale` (MulDiv) helper; recreate fonts on WM_DPICHANGED. *Test:* 100% vs
200% screenshots — chips, underlines, icons all scale.

### R4. Sidebar niceties
Per-vault entry counts on tabs; tag chips row under search results; alphabet
fast-scroll on >200 entries. *Test:* 5k vault fast-scrolls to the right letter.

### R5. Session restore
Reopen the same tab set (paths from MRU) at next unlock, each tab showing a
locked placeholder until its password is supplied (click → secure unlock for
that vault). *Test:* two vaults open, lock, unlock → two placeholders; one
unlocks inline.

---

## G. Infrastructure & performance

### G7. CI hardening
1. Nightly scheduled workflow that runs the `vfuzz`/`fuzzzip` fuzz stages with
   random logged seeds.
2. dbg + release build matrix (incl. `build release`).
3. SHA-pin `ilammy/msvc-dev-cmd` (currently tag-pinned).
4. Fix the stage-list comments in `run_all.cmd` + `build.yml` (they omit
   secscan/tmptest and the newer probes).

*Test:* the workflow runs green on schedule; a seeded fuzz failure reproduces
from its logged seed.

### G8. Attachment-section + FMAC fuzzer
The 2026-07-20 audit added `attach_index_build` per-entry bounds and made the
FMAC trailer mandatory; `vfuzz` mutates the record body, but nothing fuzzes the
attachment section or the trailer specifically.

1. A dbg probe (`attfuzz`) that seals a vault, then mutates the attachment
   section (crafted `ctlen`/id, truncation, junk entries) and the FMAC trailer
   (stripped, bit-flipped) under logged random seeds, asserting `vault_unlock`
   rejects or safely skips — never crashes or reads OOB. *Test:* add to RUNALL
   stage 4; a seeded failure reproduces from its seed. Pairs with G7.1.

---

*Completed plans are removed from this file in the commit that ships them.
Plans verified against master (post-merge 8e893a0) on 2026-07-18; if something
here is already done, delete it — the file was wrong, not the code.*
