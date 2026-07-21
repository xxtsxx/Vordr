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

**Done 2026-07-21 (plan-completion sweep → PR #2):** the remaining
headlessly-verifiable backlog was cleared. **C4** (opt-in `TpmRequireHello`:
`tpm_seal` stamps `NCRYPT_UI_POLICY`, `tpm_unseal` drops the SILENT flags when
set; default off = silent unlock behaviorally unchanged; prompting path can't be
verified without a TPM+Hello, so it is gated off). **E15** (DEFLATE-in-zipimport
resolved as a documented STORED-only limitation in README + the GUI no-entries
message; porting inflate deferred rather than add a fuzzed pre-auth path).
**G7.1** (`vfuzz`/`fuzzzip`/`attfuzz` draw a random seed each run, log it, and
accept `--seed N` to reproduce; shared `fuzz_seed` helper). **E6** (vault-health:
`vault_health` computes {weak, reused, old, total}; `healthkat` KAT gates it in
RUNALL; Ctrl+H shows a summary box; sidebar tiles show a weak-password dot — the
richer modeless dialog + reused/stale badges are folded to **R6**). An
adversarial re-audit of the sweep caught and fixed one real bug: `vault_health`
freed its password-digest scratch without a wipe length, which could leak
BLAKE2b fingerprints or drive an OOB `secure_zero`; it now wipes `n*HSTRIDE`
bytes. C4/E6/E15/G7 sections removed from this file; the visual-only remainder
is group R.

**Done 2026-07-21 (R safe-subset → PR #2):** the headlessly-verifiable slices of
group R that carry negligible visual risk. **R6-lite** — the E6 sidebar dot is
now colour-coded red=weak / amber=stale via `vault_entry_stale` (same >365-day
rule as `vault_health`, KAT'd in `healthkat`). **R5-lite** — the last vault the
user opens is persisted (`reg_save_vault`) so startup reopens it. The pure-layout
/ cross-entry-cache remainder (R1 virtual scroll, R2 command palette, R3 DPI
retrofit, R4 tab decorations, R5 multi-vault tab-set, R6 reused dot + modeless
dialog) stays deferred — its acceptance tests are visual and need a display.

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
  `zitest` → `phtest` → `secscan` → `lktest` → `tmptest` → `fztest` → `trtest`
  → `vfuzz` → `fuzzzip` → `bktest` → `mactest` → `rbtest` → `xctest` → `reload`
  → `cowrite` → `attfuzz` → `healthkat` → `pkat` → `mvtest` → `mvswitch` →
  `avtest`. `--quick` skips stage 1.
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

## M. Master-vault federation (multi-vault redesign) — new headline effort (2026-07-21)

**Why.** The tab-based multi-vault model (VSLOT/`g_vaults` contexts + `IDC_V_TABS`
strip + cross-vault search) is a dead end: every open vault demands its own
password on every unlock, TPM convenience-unlock is per-vault and awkward, and
the tab strip fragments what should be one list of secrets. The redesign makes
**one master vault the single authentication gate**; other vaults ("foreign"
vaults) are *federated* — the master holds a keyring that caches their keys, so
unlocking the master (password **or** TPM) transparently opens them all, and all
their secrets merge into one list.

**Shape.** The existing multi-vault machinery is *reused, not thrown away*: the
VSLOT/`vault_ctx_*` contexts stay as the per-vault live-state holders, and the
cross-vault XR enumeration (`search_overlay_xfill`) is promoted from a search-only
cache to **the primary list builder**. What goes away is the user-facing tab strip
and per-vault password prompting. This supersedes the tab-oriented parts of the R
backlog: **R4**'s "per-vault entry counts on tabs" and **R5**'s "reopen the whole
tab set" are rewritten below (M3/M4); delete those clauses from R when M lands.

**Security posture (state it plainly).** The keyring means *master compromise =
compromise of every federated vault* — the master's encrypted body becomes the
one place that concentrates key material. That is the deliberate trade: a single
strong gate (Argon2id + KCV + optional TPM) instead of N weak habits (password
reuse, sticky notes). Cached keys live **only** inside the master's AES-256-GCM
body, never in the registry, never on disk in the clear, and are `secure_zero`'d
on lock like every other secret. Foreign vaults each keep their own independent
key on disk — the cache is a convenience copy, not a new root of trust beyond the
master. Two levers bound the blast radius: (1) a per-vault **`LINK_PROMPT`
opt-out** — a high-value vault can be flagged to always demand its own password
even inside the federation (no cached key stored for it); and (2) **lock is
all-or-nothing** — locking or auto-lock-timing-out the master wipes *every*
federated body from secmem, so the federation is never "half open."

**Decisions locked (2026-07-21, with the user).** (1) Keyring stores the
**cached derived 32-byte key** (reference model): foreign vaults stay
independent and portable, fan-out is instant, no plaintext password, staleness
is KCV-detectable. Adoption/re-keying and password-caching were rejected — the
first destroys portability (contradicting M6), the second stores reusable
plaintext and pays Argon2 N times. (2) Vault ID is an **explicit random 16-byte
ID pinned in the v3 body meta at creation**, immutable across password/salt
rotation; salt-derivation is only the display fallback for not-yet-upgraded v2
foreign vaults. (3) Foreign vaults **auto-open** from cached keys on master
unlock, with the per-vault `LINK_PROMPT` opt-out above. (4) "Export to `.vordr`"
produces a **child vault with its own new password** (portable/shareable), with
an optional "and link it" step (M6).

### M1. Vault identity — stable ID + user name
1. **Vault ID (pinned, immutable):** generate a random 16-byte `vault_id` once at
   creation (`rng_fill`) and store it in the v3 body meta (M1.2). It is identity,
   not a crypto parameter, so it survives a password change *or* a future salt
   rotation — which matters because it is the key the links table references, and
   a link must never dangle because the crypto was rotated. **Fallback for v2**
   (not-yet-upgraded) foreign vaults: derive a transitional display ID
   `SHA-256(salt)[0..15]` until first save pins a real one. Add `vault_id_of()`
   (returns the pinned meta ID, else the salt-derived fallback). *Test:* KAT — a
   pinned ID round-trips through reseal unchanged; a v2 image reports the
   salt-derived fallback, then a pinned ID after upgrade.
2. **User-editable name + v3 body preamble:** store the name in the **body**
   (authenticated + encrypted), not the header. Bump `VAULT_VERSION` → **3** and
   define a body preamble: after the entry stream's `u32 entry_count`, a
   version-gated `u16 meta_len | meta_TLV` block carrying `VMETA_ID` (the pinned
   16-byte ID), `VMETA_NAME` (the display name), and reserved room for future
   vault-level settings. v2 bodies have no preamble → name defaults to the file
   basename and the ID is the salt-derived fallback; first save upgrades to v3.
   Editing the name reseals the vault. *Test:* set a name, reseal, reload → name
   and ID round-trip; a v2 image opens with basename+fallback then upgrades.

### M2. The keyring / links table (core)
1. Define the **links table**, a v3 master-body meta section: `link* {
   vault_id16 | foreign_KCV16 | cached_key32 | flags u32 | display_name |
   locator }`, where `locator` is the foreign vault path (wide, capped). Caching
   the **derived 32-byte key** — not the password — means no plaintext password at
   rest and **no Argon2 re-run** per foreign vault (fast fan-out unlock). `flags`:
   `LINK_STALE` (KCV mismatch), `LINK_MISSING` (file gone), and **`LINK_PROMPT`**
   (opt-out: *no* `cached_key` is stored; the vault always demands its own password
   even in the federation — the high-value-vault escape hatch).
2. **Fan-out unlock:** after the master decrypts, walk the links table; for each
   link (skipping `LINK_PROMPT`), load the foreign file and unlock it with
   `cached_key` **directly** (`vault_unlock` variant that skips the KDF when a key
   is supplied), verifying against the foreign file's own KCV. KCV mismatch
   (foreign password was changed) → set `LINK_STALE`, skip, surface in M4; file
   absent → `LINK_MISSING`. **Lock is all-or-nothing:** `vault_lock` (and the
   auto-lock timeout) must wipe *every* federated body from secmem, not just the
   master — the federation is never left half-open. **Memory is bounded:** all
   bodies are VirtualLock'd at once, so a federation is capped by `MAX_VAULTS`
   (8) × 16 MiB against the 256 MiB working-set ceiling (the dynamic `sec_ws_grow`
   sizing already covers this; keep `MAX_VAULTS` as the federation cap).
3. **Re-key on demand:** re-authenticating a stale link (M4) runs the foreign KDF
   once, refreshes `cached_key` + `foreign_KCV`, reseals the master.
4. Keep each foreign vault's own on-disk crypto untouched — the cache is additive.
   *Test:* `keyringkat` (headless) — build a master with N links, seal, reload,
   assert every cached key round-trips and KCV-validates; flip one foreign KCV and
   assert `LINK_STALE` is detected; a `LINK_PROMPT` link stores no key bytes.

### M3. Unified secret list (drop the tab strip)
1. Remove `IDC_V_TABS`, `gui_draw_tabs`, `gui_tab_click`, `gui_switch_vault`, and
   the tab-strip geometry (`PH_TABH`); the list shows the **union** of all open
   vaults' entries. Promote the XR enumeration (`search_overlay_xfill` → a general
   `list_fill_all`) to build the default list, each row tagged `(vault_id, entry)`.
   Vault provenance shows as the existing dim right-aligned name (kept from the
   cross-vault card) or an optional group header — no tabs.
2. Edit/save routes to the **owning** vault: `vault_ctx_front(owner)` then
   `vault_reseal`. New-item **target** = the vault of the currently-selected entry,
   else the master (predictable, no modal nag; a small target picker only when the
   user wants to override). Health/search/sort already operate on the merged XR set
   — reuse.
   *Test:* extends `mvname`/`federatetest` — the merged list is the union with
   correct owner attribution; editing an entry reseals only its owner.

### M4. Foreign-vault management screen
1. A dedicated modeless dialog (replaces the tab strip's add/close/switch): rows
   of linked vaults with **name, path, status** (open / locked / stale / missing)
   and entry count. Actions: **add link** (pick `.vordr` → unlock once → cache
   key), rename, remove link (drop cached key + reseal master), **set master**,
   **re-authenticate** a stale link, open/close.
2. "Add link" is the federation entry point; "set master" re-points the registry +
   TPM (M5) and folds the old master into the new master's links table.
   *Test (needs a display):* add → row appears, secrets merge into the list;
   remove → they vanish and the cached key is gone from the resealed master.

### M5. Scope TPM + registry to the master only
1. Registry persists **only** the master path (`reg_save_vault`); only the master
   gets a TPM sidecar (`reg_tpm_set`/`gui_try_tpm_auto`). Foreign paths + keys move
   **out** of the registry and **into** the master's links table — a net privacy
   win (fewer plaintext vault paths in `HKCU`, extends the C6 hygiene work).
2. The per-vault rollback mirror can key by `vault_id` instead of path (less
   leakage). Foreign vaults no longer get their own registry/TPM entries.
   *Test:* `migratetest` (headless) — after migration, `HKCU\SOFTWARE\Vordr`
   TPM-Unlock/rollback hold master-only entries; foreign sidecars are deleted.

### M6. Vault as the default export/import format
1. **Export default → `.vordr` (child vault, own password):** "export selected
   entries" seals them into a fresh standalone vault with its **own new salt +
   password** (portable/shareable — never a copy of the current key), reusing the
   `gcm_seal` + attachment path, and offers an **"and link it"** checkbox so export
   doubles as "create a new federated vault" (M2). The encrypted-ZIP export
   (`ze_compose`) stays as the alternate ("winzip flexibility") behind a format
   choice.
2. **Import default → `.vordr`:** two modes — **link** (federate the file via M2,
   the common case) or **merge** (copy its entries into the current vault, **dedup
   by the 16-byte entry id — newer `modified` wins** — so re-merges don't
   duplicate). ZIP import (`zi_stage`/`zi_commit`) stays for external data. The
   vault is already the superior container (AEAD + Argon2 + full-file MAC +
   attachments), so export = "spin off a child vault" that round-trips losslessly.
   *Test:* `vaultexportkat` (headless) — export N entries + an attachment to a new
   vault, reopen, assert entries and attachment bytes match; re-merge is idempotent.

### M7. Migration & back-compat
1. `VAULT_VERSION` → 3 for the body preamble (ID + name + links meta). **v2 vaults
   still open** (read path tolerates a missing preamble; name = basename; ID = the
   salt-derived fallback); first save upgrades in place and pins a random ID. A
   foreign vault may remain v2 — only the *master* needs v3 for its links table.
2. On first launch after upgrade, if the old multi-vault registry/tab-set
   remembered several vaults, **prompt to pick a master (never auto-elect one)** and
   fold the rest into its links table (unlock each once to cache its key), then
   delete their individual registry/TPM sidecars. Folding is non-destructive to the
   foreign files themselves.
3. Update `docs/formats.md` (v3 preamble + links-table layout) and the Sequencing
   Format note; bump the format table. Any container/auth change bumps the version
   — the links table is a container change, so v3 is mandatory, not tag-skip.

### M8. Test/probe strategy (headless-first, per PROBE convention)
Grounded in the existing probes (`mvtest`/`mvswitch`/`mvname`). Add, wired into
`tests\run_all.cmd`:
- **`keyringkat`** — links-table seal/reload + cached-key round-trip + stale-KCV
  detection (M2).
- **`federatetest`** — master + N foreign contexts, fan-out unlock from cached
  keys, unified enumeration = the union with correct owner attribution (M2/M3).
- **`vaultexportkat`** — entries + attachment export to a new `.vordr`, reopen,
  byte-exact round-trip (M6).
- **`migratetest`** — v2 + legacy multi-vault registry → v3 master + links; assert
  foreign registry/TPM sidecars are gone (M5/M7).
The keyring/format/migration logic must be provable headlessly; only the M4 screen
and the list chrome (M3 painters) need a display.

**Sequencing.** M1 (identity) → M2 (keyring + fan-out, headless, the core) →
M7 (migration + version bump, alongside M2) → M6 (vault export/import, reuses the
seal path) → M3 (unified list, removes tabs) → M4 (management screen) → M5 (registry/
TPM scoping, folds in with M4). M1/M2/M6/M7/M8 are headlessly verifiable and should
land build-green with KATs before the M3/M4 display work.

**Resolved secondary calls (2026-07-21).** (a) **No master nesting** — a foreign
vault cannot itself be a master (flat federation in v1); enforce and test. (b) Body
16 MiB cap is per-vault and unaffected (the links table is tiny). (c) Per-vault save
locking (`.lock`, `vault_ext_changed`) is unchanged — a save touches only the owning
vault; the master reseals only when the links table changes. (d) **"Set master"
migrates the already-in-memory cached keys** (no re-prompt — they are already
trusted). (e) **New-item target** = selected entry's vault, else master (M3). (f)
**Merge-import dedups by entry id**, newer `modified` wins (M6). (g) Migration
**never auto-elects a master** (M7).

---

## R. Redesign remainder — the current active backlog (2026-07-21)

With the C/E/G backlog cleared, group R is what's left. Every R item is
**painter/interaction work whose acceptance test is visual** ("100% vs 200%
screenshots", "scrolls with no paint over the header", "fast-scrolls to the
right letter"), so each needs a real display to verify — they were deliberately
left for an environment where the window can be seen, rather than shipped
build-green-but-unverified. The headlessly-safe slices are already done (R5-lite
last-vault restore, R6-lite weak/stale tile dot — see the Done log). Sequence
suggestion for the visual remainder: R3 (DPI, touches every painter — do it
before adding more) → R1 (scroll) → R6/R4 (tile decorations, shared
analysis/enumeration) → R2 (palette) → R5 (multi-vault tab-set restore).

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

### R5. Session restore — partially done
*Done (single-vault, 2026-07-21):* `gui_open_additional` persists the last
successfully-opened vault via `reg_save_vault`, so startup's `gui_resolve_vault`
(HKLM>HKCU) reopens it. *Remaining (needs a display):* reopen the whole tab set
(the multi-vault context list), each tab a locked placeholder until its password
is supplied (click → secure unlock). *Test:* two vaults open, lock, unlock → two
placeholders; one unlocks inline.

### R6. Vault-health dashboard, richer (from E6) — partially done
E6 shipped the analysis pass (`vault_health` + `healthkat`), a Ctrl+H summary
box, and a tile dot now colour-coded red=weak / amber=stale (`vault_entry_stale`,
KAT'd). *Remaining (needs a display + a cache):* a modeless health dialog whose
rows jump to the offending entry, a **reused**-password tile indicator, and a
worst-bucket count badge. These need a per-entry classification cached at
`gui_poplist` and invalidated on edit/save (the reused check is O(n²), too heavy
to recompute per paint). *Test:* fix one weak password → badge decrements after
save; clicking a row highlights its tile.

---

*Completed plans are removed from this file in the commit that ships them.
Plans verified against master (post-merge 8e893a0) on 2026-07-18; if something
here is already done, delete it — the file was wrong, not the code.*
