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
  `mvname` → `avtest`. `--quick` skips stage 1.
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

**Pre-v1.0 clean slate (2026-07-21).** Until v1.0 ships, all pre-existing vaults
and Vordr builds are treated as discarded — **no migration, no back-compat
burden**. The format is defined fresh: every vault is created by the new code with
its system items (ID + name) from the start, so there are no fallbacks, no
in-place upgrades, and no old-reader concerns. This removed a whole tier of the
plan (legacy-registry migration, salt-derived ID fallback, first-save-upgrade
paths, the old-build caveat).

**Why.** The tab-based multi-vault model (VSLOT/`g_vaults` contexts + `IDC_V_TABS`
strip + cross-vault search) is a dead end: every open vault demands its own
password on every unlock, TPM convenience-unlock is per-vault and awkward, and
the tab strip fragments what should be one list of secrets. The redesign makes
**one master vault the single authentication gate**; other vaults ("foreign"
vaults) are *federated* through a **machine-local keyring** that caches their
keys, so unlocking the master (password **or** TPM) transparently opens them all
and their secrets merge into one list. **The keyring belongs to the machine, not
to any vault** — it is never written into a vault file and is not exportable, so a
master vault stays an ordinary, portable, shareable file.

**Shape.** The existing multi-vault machinery is *reused, not thrown away*: the
VSLOT/`vault_ctx_*` contexts stay as the per-vault live-state holders, and the
cross-vault XR enumeration (`search_overlay_xfill`) is promoted from a search-only
cache to **the primary list builder**. What goes away: the user-facing tab strip,
per-vault password prompting, and *any in-vault links table* — the entire
federation state (which vaults, their keys, names, locators) lives in a
machine-local, encrypted **registry** blob. The only vault-file change is additive
— system items (ID + name) carried inside the existing container (M1); pre-v1.0
the format is simply defined fresh, no migration. This supersedes the tab-oriented parts of the R
backlog: **R4**'s "per-vault entry counts on tabs" and **R5**'s "reopen the whole
tab set" are rewritten below (M3/M4/M5); delete those clauses from R when M lands.

**Security posture (state it plainly).** A machine-local, master-bound, and
machine-bound keyring means opening the federation needs **four factors**: the
master file + the master password/TPM + this machine's keyring blob + this
machine (via TPM binding). **Stealing the master file alone yields nothing** —
foreign keys are not in it. This is strictly better than an in-vault keyring
(which concentrated every key in one stealable file) and gives *membership
privacy*: a shared or exported master reveals nothing about what else you
federate. The residual concentration — whoever holds the *unlocked* master on
*this* machine holds the federation — is bounded by two levers: a per-vault
**`LINK_PROMPT` opt-out** (a high-value vault is never cached; it always demands
its own password), and **all-or-nothing lock** (locking / auto-lock-timeout wipes
*every* federated body from secmem — never half-open). Cached keys sit AES-256-GCM
at rest under a key derived from the master key **and** a TPM machine secret, and
are `secure_zero`'d on lock like every other secret. Note two *separate* TPM roles:
**binding** (make the keyring un-copyable — default, no-PIN, since TPM is a W11
given) versus **unlock** (skip the master password — opt-in, PIN/Hello-gated per
C4). Declining TPM-unlock does not forfeit TPM-binding. On a no-TPM device the
keyring degrades to master-key-only (copyable) with a visible warning.

**Decisions locked (2026-07-21, with the user).** (1) **Fully machine-local
federation:** the entire keyring — foreign links (`vault_id` + cached derived key
+ KCV + name + locator + flags) — lives in a machine-local **registry** blob,
*never* in a vault file, non-exportable. Caching the derived key (not the
password) keeps fan-out instant with no plaintext password and no Argon2 re-run.
In-vault keyring rejected: it leaked keys + membership on share and broke path
portability. (2) **At-rest crypto:** AES-256-GCM under `KEK = BLAKE2b(master_key ‖
tpm_secret)`. Two *separate* TPM uses: **TPM-binding** (a no-PIN per-machine
NCrypt key supplying `tpm_secret`) is the default/expected path since TPM 2.0 is
guaranteed on W11+; **TPM-unlock** (unsealing the master key to skip the password,
C4 PIN/Hello-gated) stays opt-in. On the rare no-TPM device the keyring falls back
to **master-key-only** (still encrypted, still master-gated, but copyable — the
UI warns it is not machine-bound). (3) **Vault ID = explicit random 16-byte ID
pinned in a system item** at creation (immutable across password/salt rotation).
(4) **Vault name = a permanent in-vault system item** (travels with the file); the
federation record caches a display copy for locked/missing rows. (5) Foreign
vaults **auto-open** on master unlock, with the `LINK_PROMPT` opt-out. (6) "Export
to `.vordr`" = a **child vault with its own new password** (an ordinary vault),
optional "and link it". (7) **System items** — hidden entries (a reserved
`VF_SYSTEM` marker) that carry the vault's *own* metadata (ID, name, future
per-vault settings), excluded from the user list. A general, format-stable
extension mechanism — **still no `VAULT_VERSION` bump**. Boundary: system items
hold what *should* travel with the vault; the federation keyring (other vaults'
keys, locators, membership) stays machine-local and never becomes a system item.

### M1. System items + vault identity/naming
1. **System items (the mechanism):** define a hidden entry class — an ordinary body
   entry carrying a reserved **`VF_SYSTEM`** marker field — that the list builder
   **excludes from the user list** and interprets as vault-level data. It is
   authenticated + encrypted like any entry, so it fits the existing container with
   no new parser. Our read/write path round-trips system items intact (forward-
   compat for `VF_SYS*` fields a later build doesn't yet know). This is the general
   extension slot for future per-vault settings (auto-lock, icon/colour, read-only
   default…), each a `VF_SYS*` field.
2. **Vault ID (pinned):** at creation, generate a random 16-byte `vault_id`
   (`rng_fill`) and store it in the system item — immutable across password *or*
   salt rotation, which matters because the machine-local store keys foreign vaults
   by it. `vault_id_of()` returns the pinned ID (every vault is created with one).
   *Test:* KAT — a pinned ID round-trips through reseal unchanged; two vaults differ.
3. **Vault name (permanent, in-vault):** the user-editable name is a system-item
   field — it **travels with the file**, so the vault knows its own name on any
   machine. Falls back to the basename only when unset. The federation record (M2)
   caches a display copy for showing *locked/missing* foreign rows (whose in-vault
   name can't be read without opening them). *Test:* set a name, reseal, reload →
   name + ID round-trip; the cached copy matches when the vault is open.

### M2. The machine-local keyring (core)
1. **Federation record** (one per master, machine-local): `{ master_vault_id,
   record* }`, each `record = { vault_id16 | foreign_KCV16 | cached_key32 |
   flags u32 | name | locator }` (`name`/`locator` u16-length-prefixed; `name` is a
   *cached display copy* of the foreign vault's own system-item name, for rendering
   locked/missing rows — source of truth is the vault itself, M1.3). `flags`:
   `LINK_STALE` (KCV mismatch), `LINK_MISSING` (file gone), `LINK_PROMPT` (opt-out:
   *no* `cached_key`; always demands its own password — the high-value escape
   hatch). Caching the **derived key** — not the password — means no plaintext
   password at rest and **no Argon2 re-run** per foreign vault (instant fan-out).
2. **At-rest crypto + storage:** serialize → AES-256-GCM under `KEK =
   BLAKE2b(master_key ‖ tpm_secret)` → store as `REG_BINARY` under
   `HKCU\SOFTWARE\Vordr\Federation` (value name = hashed master `vault_id` via
   `reg_hash_name`, reusing the `reg_tpm_*` infrastructure). `tpm_secret` = a
   32-byte machine secret sealed by `tpm_seal`/`tpm_unseal` (tpm.asm) under a
   **dedicated no-PIN binding key** — created transparently, distinct from the
   opt-in PIN/Hello-gated TPM-*unlock* key (C4), so keyring decrypt never prompts.
   TPM 2.0 is a W11+ given, so this is the expected path; when `tpm_available` = 0,
   fall back to master-key-only and **warn in the UI** that the keyring is
   password-bound but not machine-bound (copyable). The blob decrypts only with the
   master unlocked **and** (normally) on this machine. `KEK` reuses the
   keyed-BLAKE2b already shipped for the file MAC — no new primitive.
3. **Fan-out unlock:** master unlocks → derive `master_key` → unseal `tpm_secret`
   → derive `KEK` → decrypt the record → for each entry (skipping `LINK_PROMPT`),
   load the foreign file and unlock with `cached_key` **directly** (a `vault_unlock`
   variant that skips the KDF when a key is supplied), verifying the foreign KCV.
   Mismatch → `LINK_STALE`; file gone → `LINK_MISSING`. **Lock is all-or-nothing:**
   `vault_lock` / auto-lock wipes *every* federated body from secmem. **Memory
   bounded:** all bodies VirtualLock'd at once → capped by `MAX_VAULTS` (8) × 16 MiB
   under the 256 MiB WS ceiling (`sec_ws_grow` already sizes it; keep `MAX_VAULTS`
   as the federation cap).
4. **Re-key on demand:** re-auth a stale link (M4) runs the foreign KDF once,
   refreshes `cached_key` + `foreign_KCV`, re-encrypts + rewrites the record.
5. **Master-password change** → `master_key` changes → **re-wrap** the federation
   record under the new `KEK`, and re-seal the master's TPM unlock sidecar (its key
   name is KCV-derived, so a password change moves it).
6. *Test:* `keyringkat` (headless, hermetic — synthetic keys, no real registry
   writes, never emits key bytes): serialize→encrypt→decrypt→deserialize
   round-trips N records; a wrong `tpm_secret` fails decryption (machine binding);
   a flipped foreign KCV yields `LINK_STALE`; a `LINK_PROMPT` record stores no key.

### M3. Unified secret list (drop the tab strip)
1. Remove `IDC_V_TABS`, `gui_draw_tabs`, `gui_tab_click`, `gui_switch_vault`, and
   the tab-strip geometry (`PH_TABH`); the list shows the **union** of all open
   vaults' entries. Promote the XR enumeration (`search_overlay_xfill` → a general
   `list_fill_all`) to build the default list, each row tagged `(vault_id, entry)`.
   Vault provenance shows as the existing dim right-aligned name (kept from the
   cross-vault card) or an optional group header — no tabs.
2. Edit/save **and attachment-open** route to the **owning** vault: the attachment
   index (`g_att_*`) is per-live-vault, so a row's edit, save (`vault_ctx_front(owner)`
   → `vault_reseal`) *and* an attachment click must front its owner first. Track the
   master as `g_master_idx`. Opening a `.vordr` standalone that is already federated
   fronts the existing context (no double-load). New-item **target** = the
   currently-selected entry's vault, else the master (no modal nag; a small picker
   only to override). Health/search/sort already run on the merged XR set — reuse.
   *Test:* extends `mvname`/`federatetest` — merged list = union with correct owner
   attribution; edits and attachment-opens hit the right owner.

### M4. Foreign-vault management screen
1. A dedicated modeless dialog (replaces the tab strip's add/close/switch): rows
   of linked vaults with **name, path, status** (open / locked / stale / missing)
   and entry count. Actions: **add link** (pick `.vordr` → unlock once → cache
   key), rename (edits the vault's own system-item name, M1.3 — resealing it; the
   record's cached copy refreshes), remove link (drop cached key + rewrite the
   record), **set master**, **re-authenticate** a stale link, **relocate** a missing
   link (its file moved → re-point the locator), open/close.
2. "Add link" is the federation entry point; "set master" re-points the registry +
   TPM (M5) and **migrates the in-memory cached keys** into the new master's record.
   *Test (needs a display):* add → row appears, secrets merge into the list;
   remove → they vanish and the cached key is gone from the rewritten record.

### M5. Scope TPM + registry to the master (the federation record replaces per-vault entries)
1. Registry persists **only** the master path (`reg_save_vault`); only the master
   gets a TPM unlock sidecar (`reg_tpm_*`/`gui_try_tpm_auto`) **and** the TPM
   machine secret that binds the keyring (M2). Foreign vault paths + keys live only
   in the master's machine-local federation record — **no per-foreign registry/TPM
   entries at all** (a privacy win; extends the C6 hygiene work).
2. The per-vault rollback mirror keys by `vault_id` instead of path (less leakage).
   *Test:* `federatetest` asserts the runtime invariant — add/remove of a foreign
   link touches only the master's `Federation` blob; no per-foreign registry/TPM
   value is ever created.

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

### M7. Format definition (no migration — pre-v1.0 clean slate)
1. **No migration, no back-compat.** Per the clean-slate note, pre-existing vaults
   and any old multi-vault registry/tab-set are discarded, not migrated — there is
   no legacy-import path and no in-place upgrade. Any stale `HKCU\SOFTWARE\Vordr`
   values a current dev build left behind are simply abandoned (a one-shot wipe of
   the old per-vault TPM-Unlock/Rollback subkeys on first run is optional tidiness,
   not correctness).
2. **Define the format fresh.** Every vault is created with its system items (ID +
   name) from the start. The container is otherwise unchanged; a `VAULT_VERSION`
   bump is *available* if we want a clean-break marker that rejects any stray old
   vault, but not required — decide when M1 lands.
3. **Single vault = zero ceremony:** no federation record, no master concept
   surfaced; the common single-vault case is unchanged.
4. Update `docs/formats.md`: document **system items** (`VF_SYSTEM` marker, the
   ID/name/settings they carry, the "excluded from the user list" + round-trip
   rules) and a "federation state is machine-local (registry), never in the file"
   note.

### M8. Test/probe strategy (headless-first, per PROBE convention)
Grounded in the existing probes (`mvtest`/`mvswitch`/`mvname`). Add, wired into
`tests\run_all.cmd`:
- **`keyringkat`** — federation-record encrypt/decrypt round-trip + machine-binding
  (wrong `tpm_secret` fails) + stale-KCV + `LINK_PROMPT` (M2); hermetic, synthetic
  keys, no real registry writes, never emits key bytes.
- **`federatetest`** — master + N foreign contexts, fan-out unlock from cached
  keys, unified enumeration = the union with correct owner attribution + system-item
  names (and a system-item ID/name reseal round-trip) (M1/M2/M3).
- **`vaultexportkat`** — entries + attachment export to a new `.vordr`, reopen,
  byte-exact round-trip; re-merge is idempotent (M6).
(No `migratetest` — there is no migration path pre-v1.0.) The keyring logic must be
provable headlessly; only the M4 screen and the list chrome (M3 painters) need a
display.

**Sequencing.** M1 (system items + pinned ID/name) → M2 (machine-local keyring +
fan-out, the headless core) → M6 (vault export/import, reuses the seal path) → M3
(unified list, removes tabs) → M4 (management screen) → M5 (scoping, folds in with
M4). M7 is just the format-definition + docs that ride along with M1. M1/M2/M6/M8
are headlessly verifiable and should land build-green with KATs before the M3/M4
display work. **Cross-group
dependency:** M3 rewrites the list builder (`gui_poplist` → the merged XR fill) that
**R1** (scroll), **R4** (sidebar niceties) and **R6** (health cache) all paint on —
do M3 before investing in those R items, or they get built twice.

**Resolved secondary calls (2026-07-21).** (a) **No master nesting** — a foreign
vault cannot itself be a master (flat federation in v1); enforce and test. (b) Body
16 MiB cap is per-vault and unaffected. (c) Per-vault save locking (`.lock`,
`vault_ext_changed`) is unchanged — a save touches only the owning vault; the
machine-local record is rewritten only when the keyring changes. (d) **"Set master"
migrates the already-in-memory cached keys** (no re-prompt — they are already
trusted). (e) **New-item target** = selected entry's vault, else master (M3). (f)
**Merge-import dedups by entry id**, newer `modified` wins (M6). (g) The app
**never auto-designates a master** — the user picks (M4); pre-v1.0 there is no
migration that would need to (M7). (h) **Names are a permanent vault property**
via an in-vault system item (M1.3) — they travel with the file; the federation
record only caches a display copy. (i) **Two TPM
roles** — no-PIN *binding* (default, since TPM is a W11 given) vs opt-in PIN/Hello
*unlock* (C4); a no-TPM device degrades to a copyable master-key-only keyring with
a UI warning.

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

### R7. Title-bar & dialog UI polish (2026-07-21)
Small visual/interaction fixes; all need a display to verify, so they ride with
the R group. Each is independent and can ship together in one session.

1. **Remove the misplaced per-dialog theme cogwheel.** The id-990 `GLY_SETTINGS`
   "ghost-button foundation demo" that cycles the colour scheme (`unlock_proc`
   `up_init` → `up_cyclescheme`; check `create_proc`/`about_proc` for siblings) is
   out of place. Drop it — theme switching stays in the settings menu
   (`IDC_V_MTHEME`) and the title-bar dock settings button (`IDC_T_SET`). *Test:* no
   cogwheel on the unlock/create/about dialogs; theme still switchable from settings.
2. **Ghost buttons must dim again on mouse-leave.** They currently keep the hover
   halo after the cursor leaves. Fix in `ghost_subclass` — the hover byte in
   `GWL_USERDATA` set by `gsc_move` should be cleared + repainted by the
   `WM_MOUSELEAVE` (`gsc_leave`) path; verify the `TrackMouseEvent`/`TME_LEAVE`
   arm actually fires and re-arms (check `TRACKMOUSEEVENT.cbSize`/struct and the
   "already hovering → skip" guard so a missed leave can't stick). *Test:* hover
   then leave every ghost button (dock + converted toolbar) → halo fades.
3. **Read-only checkbox → Fluent toggle.** Convert the unlock dialog's `IDC_U_RONLY`
   "Open read-only" checkbox to a Fluent pill toggle matching the existing
   `IDC_V_MTPM` toggle (`vp_tdraw_toggle` painter), for style consistency. *Test:*
   the toggle reads/writes `g_readonly`; looks like the TPM pill.
4. **Standalone pwgen: "Use" → "Copy".** When the generator is opened standalone
   from the title-bar dock (`vp_gen_standalone`, `g_pg_target == -1`) rather than
   from a secret's field (`vpd_gen`), the action button should read **Copy** and put
   the generated password on the clipboard (existing clip path + auto-clear timer)
   instead of writing to `g_pg_target`. *Test:* dock-launched pwgen shows Copy →
   clipboard gets the password; field-launched still shows Use → writes the field.
5. **Remove the minimize / maximize / lock / burger buttons.** Drop:
   - the `IDC_T_MIN` and `IDC_T_MAX` caption buttons (+ `gt_min`/`gt_max` strings,
     anchors, handlers) — no need to minimise/maximise;
   - the `IDC_V_LOCK` button — redundant because `vp_close` (the `IDC_T_CLOSE`
     "X"), `vp_esc` (Escape), and the idle-timeout all already fall through to
     `vp_lock`, which wipes and hides to tray; so the X and Escape lock to tray;
   - the **hamburger menu** `IDC_V_MENU` (`GLY_MORE`, `wb_menu`/`wb_close` toggle)
     — redundant now that the title-bar dock settings glyph `IDC_T_SET` opens the
     same overlay (both route to `vp_menu` → `gui_menu_toggle`). Keep `IDC_T_SET`
     as the toggle; the overlay still closes via re-click / Esc.
   Reflow the caption/toolbar to drop the removed slots. *Test:* only the close
   glyph in the caption and the dock's New/Generate/Settings/search remain; Esc and
   X lock (wipe) + hide to tray; the settings glyph opens/closes the overlay.

---

*Completed plans are removed from this file in the commit that ships them.
Plans verified against master (post-merge 8e893a0) on 2026-07-18; if something
here is already done, delete it — the file was wrong, not the code.*
