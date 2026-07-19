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

- **Format note:** the audit-cleanup merge shipped its format work without a
  header version bump — a trailing `[u64 save_counter][keyed BLAKE2b MAC]
  [magic]` block after the VATT trailer, plus a reserved `VF_DELETED` tag; old
  readers ignore the additions. Any future format addition should follow the
  same pattern: a new reserved `VF_*` tag that old readers skip (verify the
  unknown-tag skip path first).

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
2. Blob hygiene: the registry value name is the full vault path (location
   leak; orphans when the vault moves). Hash the name + prune orphans at
   unlock. *Test:* move the vault → the old value is gone after the next
   unlock.

### C5. Audit-log honesty
The "audit log" only records CLI diagnostic verbs; GUI unlock/save/export log
nothing.

1. Log GUI security events (unlock/lock/save/export/import, success and
   failure) or stop billing it as an audit log. Fix the stale header examples
   (`add/get/list`) and the "Event Log" comment in `main.asm`. *Test:* a GUI
   session produces the expected lines; no planted secret appears in any line.

---

## E. Features (all verified absent)

### E6. Vault health dashboard
1. Analysis pass: strength buckets (existing `gui_pw_strength` core),
   exact-duplicates via BLAKE2b, age via pw-history timestamps; dbg `health`
   verb prints counts for a scripted 10-entry vault — exact match.
2. Dashboard dialog; clicking a row jumps to the entry. *Test:* navigation
   highlights the right tile.
3. Sidebar badge with the worst-bucket count. *Test:* fix one weak password →
   badge decrements after save.

### E8. Multiple vaults / switcher
1. HKCU MRU (max 5, paths only — no secrets). *Test:* open two vaults in
   sequence → MRU shows both in order.
2. "Switch vault…" → full lock+wipe → file picker or MRU → unlock dialog.
   *Test:* A→B→A shows the right entries; a dbg memory scan after lock finds
   no residue of the previous master key.
3. Dirty-guard: refuse switching with unsaved edits (Save/Discard/Cancel).
   *Test:* Cancel keeps state intact.

### E9. Read-only mode
1. `--ro` flag + an unlock-dialog checkbox set `g_readonly`. *Test:* dbg trace
   shows the flag.
2. Gate every mutation entry point (save, add, delete, import, history purge);
   hide/disable the buttons. *Test:* a full UI walk in RO mode leaves the file
   mtime unchanged.
3. Title-bar suffix "(read-only)". *Test:* both modes.

### E15. DEFLATE in zipimport (or a documented limitation)
Imports accept only Vordr's own STORE-inside-AES exports today; 7-Zip/WinRAR
AES zips are rejected. There is no inflate in this repo — sibling project
`myrkr` has a proven puff-style decoder with KATs to port.

1. Decide: port inflate (recommended) or document "imports Vordr exports
   only" in README + the import dialog. *Test:* the choice is written down.
2. If porting: `inflate.asm` + KAT selftests; the import path dispatches
   method 8 vs 0. *Test:* a 7-Zip-produced deflated AE-2 zip imports
   correctly; RUNALL (incl. the `fuzzzip` stage) green.

---

## F. GUI / UX

### F1. Toast notifications
(The tray NIF flags are MESSAGE|ICON|TIP only — no balloon/toast exists.)

1. Layered, rounded toast child window, auto-fade via timer, theme brushes;
   dbg `toast <text>` verb. *Test:* no focus steal (caret stays in an edit).
2. Wire copy/save/lock events; queue max 3. *Test:* 5 rapid copies → ≤3
   stacked, all fade; GDI handle count stable over 100 toasts.
3. Settings toggle. *Test:* off → old behavior only.

### F2. Resizable main window
1. WS_THICKFRAME + WM_GETMINMAXINFO (min = current 484×350 layout). *Test:*
   resizes; can't shrink below the old layout.
2. Reflow in WM_SIZE: sidebar fixed width, detail pane fills. *Test:* no
   clipped/overlapping controls from 800×600 to 2560×1440.
3. Persist WINDOWPLACEMENT in HKCU, restored clamped to a live monitor.
   *Test:* restart restores position; saved off-screen coords still yield an
   on-screen window.

### F4. Mnemonics & keyboard audit
Tab order/Enter/Esc largely come free from the dialog manager; zero `&`
mnemonics exist anywhere.

1. Per-dialog audit table (tab order, default button, Esc). *Test:* the table
   has no unreachable-control rows after fixes.
2. `&`-accelerators where owner-draw painters can render underscores. *Test:*
   Alt+letter activates each marked control.

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

---

*Completed plans are removed from this file in the commit that ships them.
Plans verified against master (post-merge 8e893a0) on 2026-07-18; if something
here is already done, delete it — the file was wrong, not the code.*
