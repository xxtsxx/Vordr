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
(**The multi-vault contexts / tab strip / cross-vault search / availability
machinery and their probes were later ripped out — 2026-07-23, single-vault only;
see group M.**)
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
deferred — its acceptance tests are visual and need a display. (The R5
multi-vault tab-set item is **cancelled** — single-vault only since 2026-07-23.)

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

## M. Master-vault federation (multi-vault redesign) — WITHDRAWN (2026-07-23)

**Withdrawn / ripped out (2026-07-23).** Per the user, multi-vault support "only
causes problems for us" — Vordr is now **single-vault**: exactly one vault open at a
time. The federation/multi-vault machinery (VSLOT/ctx array, availability retry state
machine, the machine-local keyring + `FEDLINK`/`FEDREC` + `fed_*`/`keyring_*` +
`reg_fed_*`, `vault_id_of`, the M4 management screen, the M3 unified list, and all
their probes) was removed in commit `4bb6210` (~-3.8k lines). M1-M5, M7, and M8
(`federatetest`) are cancelled — do not implement them.

**M6 — vault as export/import format — LANDED (headless core, gate-green).** The one
surviving deliverable, reframed for single-vault: import from / export to a foreign
`.vordr`, nothing federated. Engine in vault.asm:
- **`fed_export(rcx = source body, edx = carry)`** builds a fresh standalone `.vordr`
  from the source body under a NEW salt + the password in `g_cfg_pass`, written to
  `g_cfg_in` (mirrors `do_seed`'s header / `vk_derive` / `vk_kcv` / `vault_seal_write`).
  `carry=1` copies entries verbatim (`entry_copy_full`) and keeps the source's
  attachment context live through the seal so `vault_seal_write` copies every
  referenced blob into the child (ct verbatim, keyed by the AttachRef's own key, so it
  decrypts under the child's new password); `carry=0` is the text-only path.
- **`fed_merge(rcx = source body)`** copies source entries into the live body, deduped
  by the 16-byte **entry** id (`fed_find_by_id`), newer `modified` winning; idempotent.
  Caller reseals.
- **`entry_copy_filtered`/`entry_copy_full`** preserve id16/created/modified (not
  `vault_build_entry`, which would mint new ids and break dedup).
- Probes **`vaultexportkat`** (export under a different password -> ids round-trip ->
  re-merge is a no-op) and **`vaultexpattkat`** (two attachments carried; blobs decrypt
  byte-for-byte in the child) gate it. The search overlay keeps its ranked `g_xr`
  painter, now single-vault.
- **Follow-ups (open, GUI-gated):** selected-subset export (headless API exports all
  entries; the GUI picks the subset); merge-import attachment carry (v1 `fed_merge`
  still filters — export is the primary attachment case).

---

## P. Passkey (WebAuthn) support — WITHDRAWN (2026-07-24)

**Withdrawn — not building this.** A full WebAuthn/FIDO2 provider needs a
constant-time P-256 / ECDSA primitive (a multi-week crown-jewel crypto module),
CBOR/COSE + WebAuthn object encoders, a new `VF_PASSKEY` credential store, and —
the unavoidable part — an OS/browser invocation bridge (a Win11 plugin
authenticator or a browser extension + native-messaging host) plus a consent UI.
The headless crypto/storage core was prototyped and proven, but the integration
half is high-complexity, browser/display-bound, and hard to keep testable, while
the user-facing value over the existing password + TOTP flows is low. **Complexity
too high, value too low — off the roadmap.** The design notes and the prototype
(branch `passkey`, P1–P3) survive in git history if it is ever revived.

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
R2 (palette). (R5's multi-vault tab-set restore is cancelled — see below.)

Folded in from `docs/REDESIGN_PLAN.md` (the standalone doc was merged into
this file and deleted). The redesign landed with merge 2c9f744: custom frame +
title-bar search & dock, ghost buttons, resizable reflow, the B1–B3 IO
contract, multi-vault contexts/tabs/cross-vault search (**since removed —
single-vault only, 2026-07-23**), modular details pane (groups/spacers/templates),
and Ctrl+K/N/G/L shortcuts. What remains:

### R2. Command palette (Ctrl+Shift+P)
The landed title-bar overlay in command mode (`>` prefix): Lock, New item,
Export, Import, Settings, theme switching, Trash view. *Test:* every command
fires; fuzzy ranks correctly; Esc closes.

### R3. DPI audit — step 1 done (GDI Scaling)
**Landed (2026-07-23):** the manifest declares `gdiScaling=true` (SMI/2017). The
app stays DPI-unaware (fixed 96-DPI pixel layout), but Windows now renders the GDI
owner-draw content (DrawTextW glyphs, FillRect cards, RoundRect) at physical
resolution on a >100% display instead of bitmap-stretching a 96-DPI frame — so text
and Fluent icons stay crisp with zero layout rewrite. No-op at 100%; verified the
element embeds in the exe manifest. **Needs an on-screen pass at 125/150/200% to
confirm crispness** (headless gate can't test it).
*Remaining (optional, only if GDI Scaling proves insufficient — e.g. blurry
StretchBlt'd bitmaps or a per-monitor-DPI requirement):* the full retrofit — a
`dpi_scale` (MulDiv) helper through the painters + recreate fonts on WM_DPICHANGED
(per-monitor-v2), which is a much larger change and conflicts with gdiScaling.
*Test:* 100% vs 200% screenshots — chips, underlines, icons all crisp.

### R4. Sidebar niceties
Tag chips row under search results; alphabet fast-scroll on >200 entries.
*Test:* 5k vault fast-scrolls to the right letter.

### R5. Session restore — DONE (single-vault)
The last successfully-opened vault is persisted via `reg_save_vault`, so startup's
`gui_resolve_vault` (HKLM>HKCU) reopens it. The multi-vault "reopen the whole tab
set as locked placeholders" remainder is **cancelled** with the single-vault
rip-out (2026-07-23) — there is no tab set. Nothing left here.

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
