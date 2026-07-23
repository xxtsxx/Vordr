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
/ cross-entry-cache remainder (R2 command palette, R3 DPI retrofit, R4 tab
decorations, R5 multi-vault tab-set, R6 reused dot + modeless dialog) stays
deferred — its acceptance tests are visual and need a display.

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
  `mvname` → `idkat` → `kekkat` → `keyringkat` → `fedkat` → `fedregkat` →
  `fmskat` → `fedapikat` → `fedfanout` → `avtest`. `--quick` skips stage 1.
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

**Landed so far (2026-07-22) — the headless keyring core, gate-verified:**
- **M1 identity:** `vault_id_of()` = `SHA-256(salt)[0..15]` (vault.asm). Probe: `idkat`.
- **M2 KEK:** `keyring_kek()` = `BLAKE2b("vordr-federation-kek-v1" ‖ master_key ‖
  tpm_secret)`. Probe: `kekkat` (deterministic + sensitive to both inputs).
- **M2 blob crypto:** `keyring_seal`/`keyring_open` — AES-256-GCM the record under
  the KEK, blob = `[nonce12][ct][tag16]`, federation domain as AAD. Probe:
  `keyringkat` (byte-exact round-trip + wrong-`tpm_secret` fails = machine binding).
- **M2 record:** `FEDLINK`/`FEDREC` fixed-layout link table + `fed_reset`/`fed_slot`/
  `fed_find`/`fed_add`; flag bits `LINK_STALE`/`MISSING`/`PROMPT`. Probe: `fedkat`
  (add/lookup + seal→wipe→open round-trip incl. keys + flags).
- **M2 persistence:** `fed_store`/`fed_load` seal→`REG_BINARY` under
  `HKCU\SOFTWARE\Vordr\Federation` (`reg_fed_set`/`get`/`del` in regcfg.asm),
  machine-local + non-exportable; `fed_load` returns none on absent/auth-fail.
  Probe: `fedregkat` (store→wipe→load→delete→confirm-none; self-cleaning).
- **M2 machine binding:** `fed_machine_secret` get-or-creates the per-machine
  `tpm_secret` (`tpm_seal`/`unseal`; no-TPM → 0 = master-key-only). Probe: `fmskat`
  (provision→retrieve→match, self-cleaning test names).
- **M2 master-key API:** `fed_save_all`/`fed_unlock_all` — master key in → derive
  secret+KEK → store/load the record; working keys `secure_zero`'d. Probe:
  `fedapikat` (save→wipe→unlock round-trip under a master key).
- **M2 wired into unlock:** `gui_open` calls `fed_unlock_master` (loads the record
  under `g_vkey`) then `fed_fanout` on the first (master) vault unlock. A
  provisioning guard peeks for a record first, so non-federating users get no
  TPM key.
- **M2 fan-out:** `fed_fanout` opens each foreign vault into a VSLOT context with
  its cached key (the `g_reuse_key`/`vu_havekey` KDF-skip path); marks
  `LINK_MISSING`/`STALE` and rolls back on failure. Probe: `fedfanout` (seed a
  real vault → link → open as 2nd ctx; corrupt key → STALE + rollback).

**M2 is now functional end to end and gate-verified** (8 probes:
`idkat`/`kekkat`/`keyringkat`/`fedkat`/`fedregkat`/`fmskat`/`fedapikat`/`fedfanout`):
master unlock → load the machine-local, TPM-bound, non-exportable record → open
every foreign vault with its cached key.

*Remaining M — needs the display or format review:* **M3**/**M4** landed (see their
notes); **M5** (registry/TPM scoping — mostly done via the keyring; the rollback-
mirror-by-`vault_id` refinement rides with M1's pinned id), **M1** system items
(vault-body ID+name — a core on-disk-format change, **do with review**; see the M1
note), and the **M8 `federatetest`** union-enumeration probe (needs M1's system
items to stand up). **M6 export/merge landed v1 headless** (see its note; the
"and link it" + import UI and attachment carry are the follow-ups). Net: the M6
headless core is the fully-automatable slice that landed; M1/M5/`federatetest`
are the review-and-display-gated remainder.

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

**NOT autonomously landable — needs review + a display (noted 2026-07-23).** A
system item is an ordinary body entry, so adding one changes **`vault_count` for
every vault** — which ripples through every count-based probe *and* would surface a
phantom entry in the on-screen list unless the list builder excludes it. That
"excluded from the user list" acceptance is **display-gated** (not headlessly
verifiable), the pinned-ID change re-points `vault_id_of` (rippling into the landed
M2 keyring / `idkat` / `vault_ctx_is_dup` / `fed_remember_open`), and the plan
itself flags this "a core on-disk-format change, do with review." So it is deferred
for a review pass rather than dropped into an automated run. The headlessly-provable
slice when it is done: a `VF_SYSTEM`/`VF_SYS_NAME` entry whose 16-byte entry id is
the pinned `vault_id`, round-tripping through reseal (extend `idkat`), plus a
`vault_user_count()` that excludes it (KAT the predicate).

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

**LANDED (2026-07-22).** The unified list is live and gate-green:
- New store `g_lxr`/`g_lxr_n` (separate from the overlay's `g_xr` so the browse
  list and search overlay never alias). `search_overlay_xfill` refactored into
  parameterized **`xfill_into(hdlg, queryEditId, xrbase, &count)`** (honours
  `g_trash_view`); thin wrappers `search_overlay_xfill` (→`g_xr`) and
  **`list_fill_all`** (→`g_lxr`, no query = full union). `MAX_XR` 200→4096 (the
  union of 8 vaults, not one search). `gui_poplist` now fills `IDC_V_LIST` with
  `g_lxr` indices; `gui_draw_xresult` + the `WM_COMPAREITEM` path self-select
  `g_lxr` vs `g_xr` by CtlID (main-list order = vault ASC, then title). Provenance
  = the dim right-aligned vault name (no group headers).
- **Selection chokepoint:** `gui_lb_seldata` decodes the row's xr index →
  `vault_ctx_front(owner)` → returns the entry index, so detail/save/edit/
  attachment-open all hit the right owner unchanged. `gui_lb_selbydata` reselects
  by `(fronted vault, entry)`; `search_overlay_activate` fronts owner + reselects
  (no `gui_switch_vault`); new-item target = selected row's vault else master (0).
- **Tab strip removed:** `gui_draw_tabs`, `gui_tab_click`, `IDC_V_TABS`, `TAB_W`
  and all dispatch/layout gone (the strip lived in the caption, so the list
  geometry was untouched). `gui_switch_vault`/`gui_open_additional`/
  `gui_close_vault` are **kept but unwired** (allowlisted in `tools/deadcode.py`)
  for M4 to re-wire as "add/remove link". Per user (2026-07-22) there is **no
  interim open/close affordance** — foreign vaults arrive via the fan-out only
  until M4.
- Corrections to the plan text above: `PH_TABH` is the *password-history* browser's
  strip, unrelated — not touched. `g_master_idx` not introduced yet (master = slot
  0, as elsewhere); fold it in with M4. **`federatetest` still pending** — the
  mv-probe harness plants synthetic scalars and does not stand up multiple
  decrypted vaults with real entry bodies, which the union enumeration needs;
  deferred rather than faked. **GUI wiring not yet screen-verified** — headless
  build + gate green; awaiting Thomas's visual check.

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

**LANDED — v1 (2026-07-22).** The management screen exists and closes the M3 open/
close gap. Build + gate green.
- New modal dialog `DLG_FEDMGR` (`fedmgr_proc`) reached via a **"Manage vaults…"**
  button (`IDC_V_MMANAGE`) added to the settings overlay (in `g_menu_ids`,
  `MENU_ID_COUNT` 31→32, dispatched at `vp_mmanage`→`gui_open_fedmgr`). Modal, like
  every other secondary dialog (no modeless pump exists).
- An owner-draw listbox (`IDC_FM_LIST`) shows one row per **open** vault slot:
  glyph tile + name (`s_name`) + dim path (`s_vpath`, via new
  `vault_ctx_pathptr`) + right-aligned **"Master (N)"/"Open (N)"** with the entry
  count (`gui_draw_fmrow`; counts cached in `g_fm_count` at populate).
- **Add vault…** and **Remove** re-wire the parked procs: `gui_open_additional`
  (now decoupled from the main window — no `gui_switch_vault`) and `gui_close_vault`
  (rewritten: front master → `vault_ctx_close` → `fed_remember_open`; the old
  last-vault/WM_CLOSE + neighbour-switch logic is gone). `gui_switch_vault` is
  **deleted** (fully obsolete); both procs are off the deadcode allowlist. On
  dialog close, `gui_open_fedmgr` rebuilds the unified list + reselects row 0.
- **Deferred to M4 v2:** set-master (needs M5's registry/TPM re-point + key
  migration), rename (needs M1.3 system-item name), re-authenticate a stale link,
  relocate a missing link, and showing record links that **failed** to fan out
  (stale/missing) — v1 lists only currently-open slots. **Not screen-verified** —
  headless build + gate green; awaiting Thomas's visual check.

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

**LANDED — v1 (2026-07-23), headless core, gate-green.** The engine is in vault.asm:
- **`fed_export(rcx = source body)`** builds a fresh standalone `.vordr` from every
  entry in the source body under a NEW salt + the password in `g_cfg_pass`, written
  to `g_cfg_in` (mirrors `do_seed`'s header/`vk_derive`/`vk_kcv`/`vault_seal_write`).
- **`fed_merge(rcx = source body)`** copies source entries into the live body,
  deduped by the 16-byte **entry** id (`fed_find_by_id`), newer `modified` winning;
  idempotent (a re-merge of the same body changes nothing). Caller reseals.
- **`entry_copy_filtered`** does a raw-ish entry copy that **preserves
  id16/created/modified** (not `vault_build_entry`, which mints new ones and would
  break dedup).
- Probe **`vaultexportkat`** (gated): seed 3 → export under a *different* password →
  reopen → the 3 entry ids round-trip → merge back → 0 changes.
- **Attachment carry (LANDED 2026-07-23).** `fed_export(rcx, edx = carry)`: `carry=1`
  copies entries verbatim (`entry_copy_full`) and keeps the source's attachment
  context (`g_attidx`/`g_filebuf`) live through the seal, so `vault_seal_write` copies
  every referenced blob into the child file — ct verbatim, keyed by the AttachRef's
  own per-attachment key (which travels in the entry), so it still decrypts under the
  child's new master password. Probe **`vaultexpattkat`** (gated): build a vault with
  two attachments (`do_attgen`), export with `carry=1` under a different password,
  reopen the child, `attach_open` both blobs and assert the plaintext matches
  byte-for-byte. (`carry=0` stays the text-only path.) Audited attachment probes
  (`attfuzz`/`zexcap`/`atgen`/`zitest`) unregressed.
- **Follow-ups (still open):** (1) **"and link it"** on export and the **link/merge
  import UI** are GUI wiring (display-gated). (2) selected-subset export (the headless
  API exports all entries; the GUI picks the subset). (3) merge-import attachment
  carry (v1 `fed_merge` still filters; export is the primary attachment case).

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
**R4** (sidebar niceties) and **R6** (health cache) paint on — do M3 before
investing in those R items, or they get built twice.

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

## P. Passkey (WebAuthn) support — new headline effort (2026-07-23)

**Status: PARKED (2026-07-23).** Captured for a future release; no implementation
work is in progress. Left here in full so it can be picked up later — resume at
P1 (the ECDSA P-256 primitive) once the Decision-1 invocation-bridge choice is
made with the user.

Make Vordr a **passkey provider**: generate, store, and use FIDO2/WebAuthn
discoverable credentials (passkeys) so it can stand in for a website's password
with a phishing-resistant public-key login. A passkey is a per-relying-party key
pair — the private key is a first-class secret (vault-resident, `secmem`-wiped on
lock, never on the CLI per PROBE), the public key + a credential id go to the site.

**Why.** Passkeys are the industry's password replacement; a password manager that
cannot hold them is increasingly incomplete. Vordr already has the hard parts of
the *storage* side (AEAD vault, Argon2 gate, attachments, `secmem` hygiene,
machine-bound federation); what it lacks is (a) an **asymmetric signing
primitive** and (b) a **way for a browser/OS to invoke it**. This effort is
deliberately split so the whole cryptographic core lands **headlessly, KAT-gated**
(the strong part) before the OS/browser integration (the display-gated part).

**The gating fact.** Vordr today has **no software asymmetric crypto** — only the
TPM/NCrypt RSA sealing in `tpm.asm` (platform, not a primitive we control). WebAuthn's
mandatory algorithm is **ES256 = ECDSA over NIST P-256 with SHA-256** (COSE alg
`-7`). So **P1 (a P-256 + ECDSA implementation) is the critical path**; nothing else
in this group can be tested until it exists. It is a large but self-contained,
KAT-friendly primitive — exactly the kind the new differential crypto harness
(`docs/ASSURANCE.md`, `tests/verify_crypto.py`) was built to prove.

**Decisions to make with the user before P4 (flagged, not assumed):**
1. **Invocation bridge.** How a browser reaches Vordr — the real integration lift:
   - **(a) Windows 11 passkey *plugin authenticator* / credential-manager API**
     (23H2+, 2024): third-party providers register so the native OS passkey UI
     offers them. Best UX, no extension, Windows-only, substantial COM surface and
     app-identity/registration requirements. **Recommended strategic target.**
   - **(b) Browser extension + native-messaging host:** an extension shims
     `navigator.credentials.create/get` and talks to a Vordr helper over
     stdin/stdout JSON. Cross-browser, how 1Password/Bitwarden shipped first, more
     moving parts — and it needs a **new non-GUI process mode** (Vordr is a
     GUI-subsystem exe with a diagnostics-only CLI; a native-messaging host breaks
     the PROBE "no real I/O verbs" shape and must be a separate, explicitly-scoped
     entry point).
   - (c) Full CTAP2 authenticator over hybrid/virtual-HID — heaviest; out of scope
     for v1.
2. **Attestation:** `none` (privacy-preserving, no provider fingerprint —
   **recommended for v1**) vs self/`packed`.
3. **Discoverable (resident) vs server-side credentials:** resident (usernameless,
   the modern default) is primary; also support server-side (credential id carries
   the wrapped private key, zero storage) — decide whether v1 does both.
4. **Signature counter policy:** return **0** (sync-friendly across machines/the M
   federation — recommended) vs a monotonic per-credential counter (single-device
   clone-detection, but clobbers on multi-device sync).
5. **Algorithms:** ES256 is mandatory and sufficient for v1; EdDSA (`-8`, Ed25519)
   and RS256 (`-257`) are optional later additions (each a new primitive).

**Security posture (state it plainly).** A passkey private key is the crown jewel:
it is generated with `rng_fill`, stored **only** AES-256-GCM at rest inside the
vault body like every other secret, `VirtualLock`'d + `secure_zero`'d on lock, and
**never** printed, exported in the clear, or accepted/emitted on the command line
(PROBE). Every assertion (login) requires the vault unlocked **and** an explicit
per-use consent gesture bound to the shown relying party — Vordr must **never sign
silently**; the anti-phishing guarantee is that the signature is bound to
`rpIdHash = SHA-256(rpId)` and the origin from `clientDataJSON`, so a look-alike
site gets a different (useless) credential. Deterministic ECDSA (RFC 6979) is used
for signing so a bad RNG can never leak the key through nonce reuse — and it makes
signatures exact-match testable.

### P1. ECDSA over P-256 (ES256) — the new asymmetric primitive (critical path)
1. NIST P-256 field + group arithmetic (256-bit modular over the curve prime and
   order), constant-time scalar multiplication, key generation (`rng_fill` scalar →
   public point), and **deterministic ECDSA** signing (RFC 6979 with SHA-256; Vordr
   already has `sha256_hash`/`hmac`). A verify path too, for self-checking. New file
   `p256.asm`; treat it with the same care as `argon2.asm`/`aesgcm.asm` (frames,
   `secmem` for the private scalar, no secret-dependent branches/indexing).
2. *Test:* `p256kat` (headless, gated in RUNALL) — **NIST CAVP P-256** key/sign
   vectors + the **RFC 6979 Appendix A.2.5** deterministic (r,s) vectors (exact
   bytes), plus a sign→verify round-trip and a tampered-message reject. **Extend the
   differential harness:** add a `katreport` line emitting a deterministic signature
   for a fixed key/message and have `verify_crypto.py` check it against the RFC 6979
   vector and validate it with a small self-contained pure-Python P-256 verify (the
   same "self-validating independent reference" pattern already used for AES-GCM).

### P2. COSE / CBOR + the WebAuthn data objects
1. A minimal canonical **CTAP2 CBOR** encoder (and just-enough decoder), a
   **COSE_Key** EC2 encoder for the public key (`{1:2, 3:-7, -1:1, -2:x, -3:y}`),
   and the WebAuthn structures: **authenticatorData** (`rpIdHash(32) ‖ flags(1) ‖
   signCount(4) ‖ attestedCredentialData ‖ extensions`), the registration
   **attestation object** (`CBOR{fmt:"none", authData, attStmt:{}}`), and the
   assertion signature input (`authData ‖ SHA-256(clientDataJSON)`).
2. *Test:* `webauthnkat` (headless) — byte-exact COSE_Key and
   attestation-object encodings for fixed inputs; the assertion signature over a
   known `authData ‖ clientDataHash` **verifies** against the stored public key
   (chains P1). Canonical-CBOR ordering asserted (deterministic encoding).

### P3. Credential store (vault-resident passkeys)
1. A passkey record = `{ credentialId | rpId | rpIdHash | userHandle | userName |
   private_scalar | publicKey | signCount | created }`. Store as a **new hidden
   entry class** built on M1's system-item mechanism (a reserved **`VF_PASSKEY`**
   marker) so it rides the existing authenticated+encrypted container with no new
   parser and round-trips forward-compatibly; the list builder shows passkeys in a
   dedicated view, not mixed into password rows. Server-side (non-discoverable)
   mode: `credentialId` = the AES-256-GCM-wrapped private key (self-contained, no
   stored record). **Format discipline:** a new `VF_*` tag old readers skip is the
   tolerant pattern, but passkey *semantics* need the new reader — decide with M
   whether this rides a `VAULT_VERSION` bump or stays additive (per the Format note,
   anything touching container/auth layout bumps the version; a new tag alone does
   not).
2. **Federation (M) interaction:** passkeys are vault entries, so they federate
   like any secret — but the **counter policy (Decision 4)** must be sync-safe
   (returning 0 sidesteps multi-machine clobber). A high-value passkey vault can use
   the existing `LINK_PROMPT` opt-out. *Test:* `passkeykat` (headless) — create a
   credential, seal → wipe → reload, produce an assertion, assert it verifies
   against the stored public key; **per-RP isolation** (an assertion for `rpId` A
   never validates against B's credential); server-side wrap/unwrap round-trips.

### P4. The invocation bridge (Decision 1 — OS/browser integration, not headless)
1. Implement the chosen path from Decision 1 — recommended: the **Win11 passkey
   plugin authenticator** COM server (register the provider; implement create/get so
   the OS passkey UI lists Vordr; route to P1–P3 + the P5 consent). The
   extension+native-messaging fallback needs the new non-GUI helper process mode
   noted above.
2. *Test (needs a display + a real relying party):* register a passkey on a live
   WebAuthn test site (e.g. `webauthn.io`) via Vordr, then sign in with it; the RP
   accepts the assertion. Not gate-automatable — verified interactively, like the R
   group.

### P5. Consent + user-verification UI (not headless)
1. A per-ceremony consent surface: show the **relying party** and the **account**,
   require an explicit approve gesture, and treat the unlocked vault (password /
   TPM / Hello per C4) as user-verification (UV). Never sign without it; offer
   "this site is asking to sign in as <user> — approve?" with the origin shown for
   anti-phishing. Rate-limit / re-auth for high-value credentials.
2. *Test (needs a display):* a create and a get ceremony each show the RP + account
   and block until approved; declining aborts with no signature emitted.

### P6. Test/probe strategy (headless-first, per PROBE)
The entire crypto core is provable headlessly and must land KAT-gated before P4/P5:
`p256kat` (P1, CAVP + RFC 6979), `webauthnkat` (P2, byte-exact COSE/attestation +
assertion verify), `passkeykat` (P3, create→seal→reload→assert→verify + per-RP
isolation + server-side wrap). All hermetic, synthetic keys, **never emit a private
scalar**, wired into `tests\run_all.cmd`, and the P1 signature cross-checked by the
independent `verify_crypto.py` reference. Only P4 (OS/browser) and P5 (consent UI)
need a live environment — mirror the R-group "verified interactively" stance.

**Sequencing.** P1 (P-256/ECDSA — the gating primitive, KAT-gated) → P2 (COSE/CBOR
+ WebAuthn objects) → P3 (`VF_PASSKEY` store, decide the M/`VAULT_VERSION`
interaction) → **decision point** (P4 invocation bridge — pick (a) or (b) with the
user) → P4 → P5 (consent UI). P6 KATs land alongside P1–P3. Do **not** start P4
before P1–P3 are green — the integration is worthless without a proven, testable
signing core, and P1 is a multi-week primitive on its own. Depends on M1's
system-item mechanism for P3's storage; otherwise independent of the M federation
work.

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
before adding more) → R6/R4 (tile decorations, shared analysis/enumeration) →
R2 (palette) → R5 (multi-vault tab-set restore).

Folded in from `docs/REDESIGN_PLAN.md` (the standalone doc was merged into
this file and deleted). The redesign landed with merge 2c9f744: custom frame +
title-bar search & dock, ghost buttons, resizable reflow, the B1–B3 IO
contract, multi-vault contexts/tabs/cross-vault search, modular details pane
(groups/spacers/templates), and Ctrl+K/N/G/L shortcuts. What remains:

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

**LANDED (2026-07-23) — build-clean + gate-green, AWAITING an on-screen pass.** All
five implemented (strict build 0 fatal / 0 dead; full gate green - the changes are
GUI-only, so no headless probe covers them):
- **R7.1** unlock-dialog theme cogwheel (id 990) removed (`unlock_proc`: the
  `ghost_make`, the dispatch, `up_cyclescheme`, the orphaned `gl_t_theme`).
- **R7.2** ghost-button hover fixed: `TRACKMOUSEEVENT.cbSize` was 16 (x86); on x64
  it must be 24, so `TrackMouseEvent` had failed to arm `WM_MOUSELEAVE` and the halo
  stuck. Root-cause fix.
- **R7.3** unlock "Open read-only" `AUTOCHECKBOX` -> Fluent pill toggle matching the
  TPM pill (`.rc` LTEXT + `BS_OWNERDRAW`; `theme_toggle(g_readonly)`; `up_ronly`
  flips + repaints; `gui_unlock` no longer reads a checkbox).
- **R7.4** standalone (dock-launched) pwgen action button reads **Copy** and copies to
  the clipboard with auto-clear; field-launched keeps **Use**.
- **R7.5** minimize/maximize/`IDC_V_LOCK`/hamburger `IDC_V_MENU` buttons removed; the
  caption keeps only Close (dock reflows left of it); Ctrl+L still locks (id/dispatch
  kept), X/Esc/idle lock to tray, and `IDC_T_SET` opens the settings overlay.

The clauses below are the original spec (kept for the on-screen review checklist).

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

### R8. Search overhaul — one title-bar search (2026-07-21, in progress)
Consolidate to a single search driven from the title bar; the sidebar filter box
is gone. Built on the existing `search_overlay_*` (panel/edit/list) infrastructure.
1. **[done, stage 1]** Remove the redundant sidebar box (`IDC_V_SEARCH`); the list
   reflows to fill it. Ctrl+K, list type-to-search (`search_type_subclass`) and
   ghost-button type-to-search (`gsc_char`) now open the overlay and forward the
   keystroke into `IDC_SO_EDIT`. *Verify on screen:* list fills the space; typing
   anywhere with no field focused opens the overlay and starts the query.
2. **Type-anywhere focus:** ensure *every* no-field-focused keypress reaches the
   overlay (extend beyond the list/ghost subclasses if any control swallows it).
3. **Edit painted over the pill:** position `IDC_SO_EDIT` over the `IDC_T_SEARCH`
   rect (not below) so activating looks like the pill becomes the field.
4. **Floating results window:** promote the results panel from a child control to a
   top-level layered popup (`WS_POPUP` + drop-shadow / `WS_EX_NOACTIVATE`) that
   floats over the window with a border + shadow. Subsumes the edit-over-pill
   positioning (3) and dynamic sizing (6).
5. **Linger until selection:** keep the results open until Enter/click/Esc (already
   the behaviour — confirm no close-on-blur once it is a popup).
6. **[done, stage 2]** Scale with hits: `search_overlay_resize` sizes the list +
   backdrop to `clamp(rows × itemHeight, one row, SO_LISTH)` after every populate,
   so the dropdown shrinks live as the query filters. Carries over to the popup.
*Sequence:* stages 1–2 done → 2b (type-anywhere completeness) → 4+3 (the
floating-popup rebuild, reuses the stage-2 sizing) → 5 (confirm). All visual —
each increment verified by screenshot.

---

*Completed plans are removed from this file in the commit that ships them.
Plans verified against master (post-merge 8e893a0) on 2026-07-18; if something
here is already done, delete it — the file was wrong, not the code.*
