# Vordr — 39 Improvement Plans

Each plan is broken into small, independently buildable steps. Every step lists a
concrete verification test. Global conventions used below:

- **BUILD** = `build.cmd` completes with `BUILD OK: bin\vordr.exe` (kill any running
  `vordr.exe` first; a locked exe fails LNK1104).
- **SELFTEST** = `bin\vordr.exe selftest` prints `all self-tests passed`.
- **REDTEAM** = `build.cmd dbg` then `python tests\redteam.py` passes (fault-injection gate).
- **FRAMES** = no >4-arg `WINCALL` added directly inside a raw `sub rsp,64` dialog proc
  (`create_proc`, `unlock_proc`, `vault_proc`, `msg_proc`, `about_proc`, …); wide calls go
  in a `FRAME_PROLOG N` helper. This is the crash class that produced BEX64/offset-0.
- **ROUNDTRIP** = create temp vault via CLI, `add` entries, export `.vaultz`, re-import,
  diff plaintexts.
- **RUNALL** = `tests\run_all.cmd` (build + framecheck + selftest + roundtrip; `--quick` skips
  the dbg redteam stage). This is the one-command gate; use it in place of the individual
  BUILD/SELFTEST/ROUNDTRIP steps where convenient.

> **Already delivered (removed from this list):** secure-desktop ("Secure Unlock") master-
> password entry; DWM dark/immersive title-bar theming (a Mica/Acrylic client-area glass
> variant was tried and reverted); `framecheck.py` v2 raw-proc scanner; the GitHub Actions
> CI pipeline; and the consolidated `tests\run_all.cmd` runner.

---

## A. Security & Crypto (Plans 1–8)

### 1. VirtualLock audit for secret buffers
**Goal:** Every buffer that ever holds a master password, derived key, or plaintext secret is
VirtualLock'd (non-pageable) and wiped.
**Steps:**
1. Inventory: grep `secmem.asm` callers; list every static/heap secret buffer in a table in
   `docs/SECRETS.md` (name, size, lock status, wipe site).
   *Test:* the table has no "unknown" rows; each wipe site cited as file:line.
2. Add `sec_lock`/`sec_unlock` wrappers (VirtualLock + working-set growth fallback) in `secmem.asm`.
   *Test:* `dbg` trace prints lock success for each region at startup; BUILD + SELFTEST.
3. Apply to any unlocked buffers found in step 1.
   *Test:* re-run inventory — zero unlocked rows; SELFTEST + REDTEAM.
4. Add a redteam check: after `lock` (GUI lock or CLI exit path), scan the process's own
   committed pages for a known sentinel password — must not be found.
   *Test:* `dbg` build: plant sentinel, lock, scan verb reports 0 hits; then disable one wipe
   → scan must report a hit (proves the scanner works).
**Status: IMPLEMENTED** — sec_lock/sec_lock_statics in secmem.asm (VirtualLock + working-set-grow fallback) pin g_cfg_pass/g_vkey/g_pwbuf/g_pw2buf/g_secret_w/g_e_totp/g_totp_b32 at startup; docs/SECRETS.md audits every secret buffer + exceptions; `secscan` probe (in run_all) proves no post-wipe residue.


### 2. Clipboard hygiene: auto-clear + history exclusion
**Goal:** Copied secrets clear after N seconds and never enter Windows clipboard history / cloud sync.
**Steps:**
1. On every secret copy, also set the `ExcludeClipboardContentFromMonitorProcessing`,
   `CanIncludeInClipboardHistory`=0 and `CanUploadToCloudClipboard`=0 formats.
   *Test:* copy a password, press Win+V — the entry must not appear in history.
2. Start a 30 s timer (`SetTimer` on the vault window); on fire, clear the clipboard only if
   its sequence number (`GetClipboardSequenceNumber`) is unchanged since our copy.
   *Test:* copy → wait 31 s → paste is empty; copy → user copies other text → wait → user's
   text survives (sequence check proved).
3. Settings row: timeout seconds (0 = off), persisted in HKCU.
   *Test:* set 5 s, verify clears at ~5 s; set 0, verify never clears; SELFTEST.

### 3. Vault anti-rollback counter
**Goal:** Detect an attacker restoring an older vault file (e.g. to resurrect a purged password).
**Steps:**
1. Add a monotonically increasing `save_counter` to the authenticated vault header.
   *Test:* hexdump two consecutive saves; counter increments; SELFTEST + ROUNDTRIP.
2. Mirror the last-seen counter in HKCU (and optionally TPM NV if `tpm.asm` reports one).
   *Test:* save vault, read the registry value, matches header.
3. On unlock: if header counter < mirror, show a loud warning dialog ("vault is older than
   the last one this machine saved") with explicit continue/abort.
   *Test:* save, copy vault aside, save again, restore the old copy → warning appears;
   normal unlock → no warning. REDTEAM still passes.

### 4. Full-file HMAC / header hardening pass
**Goal:** One authenticated digest covers everything (header fields, all records, trailer) so
truncation or record-splicing is always caught, not just per-record.
**Steps:**
1. Document the current authentication coverage (what AES-GCM AAD covers today) in `docs/FORMAT.md`.
   *Test:* review doc vs `vault.asm` source; every field accounted for.
2. Add a final BLAKE2b-keyed MAC record over the whole preceding file, key derived from the
   master key with a distinct info string.
   *Test:* SELFTEST; truncate a vault by 1 record with a Python script → unlock must fail with
   the tamper error, not a partial load.
3. Fuzz splice test: Python script swaps two encrypted records → unlock must fail.
   *Test:* scripted 100 random splices/truncations — 100/100 rejected; ROUNDTRIP still passes.

### 5. Argon2id RFC 9106 full vector coverage
**Goal:** Selftest covers all published Argon2id vectors, not just one.
**Steps:**
1. Encode the RFC 9106 §5 test vectors (and the reference-repo extended vectors) as data in
   `selftest.asm`.
   *Test:* cross-check each vector against `argon2_cffi` in Python before committing
   (validate the reference itself, per the byte-shift lesson).
2. Loop the KAT over all vectors; report which index failed.
   *Test:* SELFTEST passes; corrupt vector #3's expected output → selftest names index 3.
3. Time it: keep added startup cost < 100 ms (drop the highest-memory vector if needed).
   *Test:* `bench` verb before/after; delta under budget.

### 6. Constant-time comparison audit
**Goal:** No secret-dependent early-exit comparisons anywhere.
**Steps:**
1. Grep for byte-compare loops (`repe cmpsb`, `jne` inside compare loops) across `src/*.asm`;
   classify each as secret-touching or not in `docs/SECRETS.md`.
   *Test:* table complete; each secret-touching site names its fix or why it's safe.
2. Add `sec_memeq` (fixed-time OR-accumulate compare) to `secmem.asm` with a selftest KAT.
   *Test:* SELFTEST includes equal/unequal/length-edge cases.
3. Replace secret-touching sites (GCM tag check, password verify, HOTP compare).
   *Test:* SELFTEST + REDTEAM + ROUNDTRIP all pass; `dbg` timing probe shows compare time
   independent of first-differing-byte position (coarse check, 10k iterations).

### 7. Auto-lock on idle and on workstation lock
**Goal:** Vault locks itself after configurable idle time and immediately when Windows locks.
**Steps:**
1. Register for `WM_WTSSESSION_CHANGE` (WTSRegisterSessionNotification) on the vault window;
   on `WTS_SESSION_LOCK` call the existing lock path.
   *Test:* unlock vault, press Win+L, unlock Windows → Vordr shows its unlock dialog.
2. Idle timer: `GetLastInputInfo` polled by a 30 s `SetTimer`; lock after N minutes idle.
   *Test:* set 1 min, leave machine untouched 70 s → locked; move mouse at 50 s → not locked.
3. Settings: idle minutes (0=off) + "lock when Windows locks" checkbox, persisted (HKLM>HKCU>default).
   *Test:* persistence across restart; SELFTEST; FRAMES (the new handlers stay in helpers).

### 8. Secure temp-file lifecycle for attachment "Open"
**Goal:** Decrypt-to-temp files (from `gui_file_open`) are overwritten and deleted deterministically.
**Steps:**
1. Track every temp path created this session in a small table; on lock/exit, overwrite with
   zeros (existing `secmem` wipe pattern via `write_file`) then delete.
   *Test:* open an attachment, note the temp path, exit Vordr → file gone; recreate the file
   name and check content is not recoverable via a hex viewer of the disk sectors (best-effort:
   verify the overwrite write happened via `dbg` trace).
2. Create temp files with `FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE` where the
   viewer app tolerates it; fall back to the tracked-wipe path otherwise.
   *Test:* .txt attachment opens in Notepad successfully both modes.
3. Add a "purge temp now" action to Settings.
   *Test:* click purges immediately while the app stays open.

---

## B. Features (Plans 9–20)

### 9. otpauth:// URI import for TOTP
**Goal:** Paste an `otpauth://totp/...` URI to fill secret/digits/period/algorithm automatically.
**Steps:**
1. Parser proc `otp_parse_uri` (percent-decode, extract secret/issuer/digits/period/algo)
   with strict bounds; unit-test verb `otptest <uri>`.
   *Test:* 10 crafted URIs incl. hostile ones (overlong, bad base32, missing secret) — good
   ones parse, bad ones rejected; compare against `pyotp.parse_uri` output.
2. GUI: "Paste URI" button next to the TOTP field; fills the row fields.
   *Test:* paste a Google-format URI → 6-digit code matches `oathtool --totp -b <secret>`.
3. SELFTEST vector: fixed URI → fixed parsed tuple.
   *Test:* SELFTEST; corrupt expected digits → fail.

### 10. Offline breach check (HIBP bloom filter)
**Goal:** Flag vault passwords found in public breach corpora — fully offline.
**Steps:**
1. Build-side tool `tools/mkbloom.py`: from the HIBP SHA-1 ordered file, build a bloom filter
   (target ≤64 MiB, FPR ≤0.1%) written as a flat file.
   *Test:* Python: 1000 known-breached hashes all hit; 10k random hashes FPR ≤ 0.1%.
2. `bloom.asm`: mmap the file, k hash probes using existing SHA-1.
   *Test:* CLI `breach <password>` verb agrees with the Python checker on 100 samples.
3. GUI: shield icon on the password row (grey=no db, green=clean, red=breached), checked on
   entry display only (never network).
   *Test:* entry with "password123" shows red; random 20-char shows green; remove the db file
   → grey and no crash.

### 11. Global auto-type hotkey
**Goal:** Ctrl+Alt+V types username{TAB}password{ENTER} into the previously focused window.
**Steps:**
1. `RegisterHotKey` on the tray window; on fire, capture `GetForegroundWindow` BEFORE showing
   the picker.
   *Test:* `dbg` trace logs the captured HWND title.
2. Entry picker popup (reuse the select-dialog pattern; remember the tray-foreground fix:
   DS_SETFOREGROUND + SetForegroundWindow).
   *Test:* picker appears focused with a live caret (the known tray gotcha).
3. `SendInput` typer with per-char `VkKeyScanW` + Unicode fallback (KEYEVENTF_UNICODE); wipes
   its buffer after.
   *Test:* auto-type into Notepad: exact string, incl. symbols and 'æøå'; verify buffer wipe
   via `dbg` scan.
4. Safety: refuse to type into elevated windows / consoles unless confirmed.
   *Test:* target an admin cmd → confirmation dialog appears first.

### 12. Fuzzy search in the sidebar
**Goal:** `gmail wrk` matches "Work – Gmail account" (subsequence scoring), not just prefix.
**Steps:**
1. `fuzzy_score` proc: case-folded subsequence match with contiguity + word-start bonuses;
   returns score or -1.
   *Test:* CLI `fztest` verb over a fixed table of (needle, hay, expected-rank) — 20 cases.
2. Filter path: score all entries, sort descending, keep >0 (replace the current substring test).
   *Test:* GUI: type `gmwk`; the Gmail-Work entry ranks above plain "Gmail".
3. Highlight matched characters in the tile painter (existing owner-draw text run).
   *Test:* visual check: matched letters render in accent color; no clipping at 9 pt.

### 13. Entry templates
**Goal:** New-entry menu offers Login / Credit card / Identity / Server / Note presets that
pre-create the right modular field rows.
**Steps:**
1. Template table in `.const`: list of (VF type, label) rows per template.
   *Test:* assembles; table dumped by a `dbg` verb matches spec.
2. Replace the "+" button action with a small popup menu (reuse `CreatePopupMenu` pattern from
   the tray) listing templates.
   *Test:* each template creates its rows in order; Save + reopen preserves labels (TLV labeled
   fields already support this).
3. "Save current entry as template" (stored in HKCU as a label list).
   *Test:* custom template round-trips app restart.

### 14. Tag-based sidebar filtering
**Goal:** Entries can carry tags; sidebar gets a tag strip; clicking a tag filters the list.
**Steps:**
1. Reserved `VF_TAGS` field (VFL_RAW, comma-separated) per entry; editor row in edit mode.
   *Test:* save entry with tags, reopen, tags intact; ROUNDTRIP preserves them.
2. Collect distinct tags at vault load into a sorted table.
   *Test:* `dbg` verb prints the tag table; matches entries.
3. Tag chips above the list (reuse the attachment tag-chip painter); click toggles filter,
   second click clears.
   *Test:* two tags AND-combine; empty result shows a friendly "no matches" state; FRAMES.

### 15. Vault health dashboard
**Goal:** One screen: weak / reused / old / breached password counts with drill-down lists.
**Steps:**
1. Analysis pass proc: iterate decrypted entries, bucket by (strength level via existing
   `gui_pw_strength` core, exact-duplicate hash via BLAKE2b, age via the pw-history timestamps).
   *Test:* CLI `health` verb prints the four counts on a synthetic 10-entry vault built by a
   script with known expected counts — exact match.
2. Dashboard dialog listing the buckets; clicking a row jumps to the entry.
   *Test:* click navigates and highlights the correct tile.
3. Sidebar badge showing the worst-bucket count.
   *Test:* fix one weak password → badge decrements after save.

### 16. Password expiry reminders
**Goal:** Optional per-entry "rotate every N days"; overdue entries get a badge + tray balloon.
**Steps:**
1. Reserved `VF_EXPIRY` field storing N days; edit-mode row (0=never).
   *Test:* save/reload round-trip; export/import preserves it.
2. Overdue = last password-change time (from pw-history capture or entry mtime) + N < now;
   compute at load.
   *Test:* synthetic vault with back-dated change time → flagged; fresh entry → not flagged.
3. Amber clock badge on overdue tiles + one tray balloon per unlock session.
   *Test:* visual check; balloon appears once, not repeatedly.

### 17. Multiple vaults / vault switcher
**Goal:** File → recent-vaults list; switching locks the current vault first.
**Steps:**
1. Track the open vault path (already known) + an HKCU MRU (max 5, paths only — no secrets).
   *Test:* open two different vault files in sequence; MRU shows both in order.
2. Tray/menu "Switch vault…" → lock current (full wipe path) → file picker or MRU → unlock dialog.
   *Test:* switch A→B→A; entries correct each time; `dbg` scan after lock shows no residue of
   the previous vault's master key.
3. Guard: refuse switch with unsaved edits (prompt Save/Discard/Cancel).
   *Test:* dirty entry + switch → prompt appears; Cancel keeps state intact.

### 18. Read-only mode
**Goal:** Open a vault without write intent — all mutating UI disabled; good for USB/backup review.
**Steps:**
1. `--ro` CLI flag and a checkbox on the unlock dialog set `g_readonly`.
   *Test:* flag reaches the global (dbg trace).
2. Gate every mutation entry point (save, add, delete, import, history purge) on the flag;
   hide/disable their buttons.
   *Test:* click-audit in RO mode: no control mutates the file (file mtime unchanged after a
   full UI walk); CLI `add` with `--ro` refuses.
3. Title bar suffix "(read-only)".
   *Test:* visual check both modes.

### 19. Printable emergency sheet
**Goal:** Settings → "Emergency sheet": renders vault location, key-slot info, and OWNER-FILLED
blanks (never the password) to a printable page.
**Steps:**
1. Compose fixed text + vault path + creation date into a buffer (no secrets).
   *Test:* string inspection — grep the buffer for any g_pw residue in `dbg`; zero hits.
2. Print via `ShellExecuteW print` of a generated .txt (or direct `StartDoc`/`TextOut` if
   nicer layout wanted).
   *Test:* Microsoft Print to PDF produces the sheet; content matches spec.
3. Confirmation dialog first (this leaves a paper trail — user must acknowledge).
   *Test:* Cancel produces nothing.

### 20. CLI `clip` verb
**Goal:** `vordr clip <entry> [field]` prompts for the master password (console, no echo),
copies the secret to clipboard with the auto-clear timer, prints nothing secret.
**Steps:**
1. Console hidden-input already exists for other verbs — reuse; resolve entry by fuzzy name.
   *Test:* correct secret lands on clipboard (paste in Notepad); stdout contains no secret.
2. Apply the same clipboard-history-exclusion formats as Plan 2 and spawn the clear timer via
   a detached sleeper thread that outlives the CLI (or message-only window + timer).
   *Test:* Win+V shows nothing; clipboard empty after timeout even though the process exited.
3. Non-zero exit codes for not-found/ambiguous names.
   *Test:* scripted: `clip nosuch` → exit 2; ambiguous prefix → exit 3 + candidate list.

---

## C. GUI / UX (Plans 21–29)

### 21. Full keyboard navigation audit
**Goal:** Every dialog usable without a mouse: logical tab order, accelerators, Enter/Esc correct.
**Steps:**
1. Audit table: for each dialog in `vordr.rc`, walk with Tab and note dead ends (owner-draw
   buttons missing WS_TABSTOP, wrong control order in the .rc).
   *Test:* the table lists every control with its tab index; no "unreachable" rows remain after fixes.
2. Fix .rc ordering + add WS_TABSTOP; ensure DM_SETDEFID default buttons are right (remember
   the dword-vs-qword LPARAM bug class here).
   *Test:* per dialog: Tab cycles all controls; Enter fires the intended default; Esc cancels.
3. Add `&`-accelerators to labels/buttons where the owner-draw painter can render underscores.
   *Test:* Alt+letter activates each marked control.

### 22. Per-monitor-v2 DPI audit
**Goal:** Crisp rendering at 100/150/200% and when dragging between mixed-DPI monitors.
**Steps:**
1. Confirm the manifest declares PerMonitorV2 (`vordr.manifest`); log `GetDpiForWindow` in `dbg`.
   *Test:* value changes when the window moves to a 150% monitor.
2. Sweep hardcoded pixel metrics in painters (`theme.asm`, tile/row painters): route through a
   `dpi_scale` helper (MulDiv by current DPI).
   *Test:* screenshot at 100% vs 200%: chip heights, underline thicknesses, icon sizes all scale
   (no 1-px hairlines vanishing at 200%).
3. Recreate fonts on `WM_DPICHANGED` (g_welcomefont, list fonts, icon font).
   *Test:* drag between monitors — text reflows without restart; no GDI handle leak
   (`dbg`: GetGuiResources GDI count stable over 20 drags).

### 23. Screen-reader accessibility for owner-draw controls
**Goal:** Narrator/NVDA announce owner-draw buttons and tiles meaningfully.
**Steps:**
1. Ensure every owner-draw BUTTON keeps a real window text (SetWindowTextW even though the
   painter draws it) — that's what MSAA reads.
   *Test:* NVDA reads each button name on the create/unlock/vault dialogs.
2. Tiles/list: name via `SetWindowTextW` per tile child, or implement `WM_GETOBJECT` returning
   entry titles.
   *Test:* NVDA walks the sidebar and reads entry names in order.
3. Verify contrast of `textdim` on `panel` in all 9 schemes ≥ 4.5:1 (compute in Python from
   the schemes table).
   *Test:* script prints per-scheme ratios; fix any failing pair; visual regression screenshots.

### 24. Resizable main window
**Goal:** The vault window resizes with a sensible reflow; size/position persisted.
**Steps:**
1. Add `WS_THICKFRAME` + WM_GETMINMAXINFO (min = current fixed size).
   *Test:* window resizes; can't shrink below the old layout.
2. Reflow in `WM_SIZE`: sidebar fixed width, detail pane fills; the existing row/tile layout
   already computes from client width — re-run it.
   *Test:* maximize: detail rows widen, no clipped/overlapping controls at 800×600 → 2560×1440.
3. Persist placement (WINDOWPLACEMENT) in HKCU; restore clamped to a live monitor.
   *Test:* resize+move, restart → same place; unplug-monitor simulation (save coords off-screen
   manually in registry) → window still appears on-screen.

### 25. In-app toast notifications
**Goal:** Non-blocking "Copied", "Saved", "Locked in 4:59…" toasts instead of/alongside cue text.
**Steps:**
1. Toast child window: layered, rounded, auto-fade via timer, painter reuses theme brushes.
   *Test:* `dbg` verb `toast <text>` shows/fades it; no focus steal (caret stays in an edit).
2. Wire copy/save/lock events to toasts; queue max 3.
   *Test:* rapid 5 copies → max 3 stacked, all fade; no GDI leak over 100 toasts (handle count stable).
3. Settings toggle.
   *Test:* off → old behavior only.

### 26. Trash / undo-delete for entries
**Goal:** Deleted entries go to a Trash section for 30 days instead of vanishing.
**Steps:**
1. Reserved `VF_DELETED` timestamp field; delete = set it (entry stays in the file, encrypted
   as always).
   *Test:* delete → entry gone from sidebar; hexdump: record still present; ROUNDTRIP keeps it.
2. Trash view (sidebar footer button) lists deleted entries with Restore / Delete-forever.
   *Test:* restore returns the entry intact incl. attachments + history; delete-forever removes
   the record on next save (hexdump confirms gone).
3. Auto-purge >30 days at unlock (count shown once).
   *Test:* back-date a deletion timestamp via a `dbg` verb → purged at next unlock.

### 27. Drag-and-drop attachment add
**Goal:** Drop files from Explorer onto an entry's attachment tile (edit mode) to attach them.
**Steps:**
1. `DragAcceptFiles` on the vault window; handle `WM_DROPFILES` → `DragQueryFileW` loop.
   *Test:* `dbg` trace lists dropped paths.
2. Route each path through the existing Choose flow (`attach_stage` + g_tilefiles append),
   respecting MAX_TFILES; require edit mode + an attachments tile target (hit-test drop point).
   *Test:* drop 3 files → 3 chips appear; drop in view mode → gently refused (toast);
   drop 40 files → capped with a message.
3. Save + reopen round-trip.
   *Test:* all dropped files download back byte-identical (fc.exe compare).

### 28. Localization scaffolding
**Goal:** All user-visible strings live in one table so a second language is a data-only change.
**Steps:**
1. Script `tools/strings_audit.py`: find WSTR/dw-string data in `gui.asm`/`theme.asm` and emit
   a catalog CSV (id, english).
   *Test:* catalog count matches a manual sample; no secret-bearing buffers listed.
2. Introduce `str_get(id)` indirection backed by a language block chosen at startup (default en).
   Migrate one dialog (About) fully as the pilot.
   *Test:* BUILD; About renders identically (screenshot diff ≈ pixel-equal).
3. Add a `no` (Norwegian) block for the pilot dialog behind a registry setting.
   *Test:* toggle setting → About renders in Norwegian; all other dialogs unaffected.
4. Migrate remaining dialogs incrementally (one commit each).
   *Test:* per-dialog visual check + SELFTEST each commit.

### 29. Font-size / density unification
**Goal:** The existing layout-density setting also scales fonts (S/M/L) consistently everywhere.
**Steps:**
1. Central font factory: all CreateFontW calls route through one FRAME_PROLOG helper taking a
   role enum (body, title, mono, welcome) + density.
   *Test:* grep: no raw CreateFontW outside the factory; BUILD + visual check at M.
2. Scale table per density (S=-1pt, L=+2pt roles).
   *Test:* switch density → all dialogs change together; no clipped rows at L (walk every
   dialog; heights come from MapDialogRect so DLU-based ones need +margin where flagged).
3. Persist + live-apply on setting change (WM_SETFONT broadcast + relayout).
   *Test:* change takes effect without restart; GDI handle count stable after 10 switches.

---

## D. Code quality, build & test infrastructure (Plans 30–33)

### 30. In-proc fuzzer for the vault parser
**Goal:** Coverage-light structural fuzzing of `vault.asm`'s record parser to shake out
malformed-input crashes before an attacker does.
**Steps:**
1. `fuzz <seed> <iters>` verb (dbg builds): loads a fixture vault image into memory, applies
   deterministic xorshift mutations (bit flips, length-field tweaks, truncations), calls the
   parse path with the correct key, expects clean-reject or clean-parse — never AV.
   *Test:* 100k iterations complete with 0 crashes; the iteration count + rejection stats print.
2. Structure-aware mutations: target TLV length fields and record counts specifically.
   *Test:* rejection rate rises (proves it's hitting parse logic); still 0 crashes at 1M iters.
3. Run 1M iterations in CI nightly (scheduled workflow) with a random seed, logging the seed
   for reproduction.
   *Test:* nightly green; deliberately re-run a failed seed reproduces identically (determinism).

### 31. Fuzz the zip/inflate import path
**Goal:** Same treatment for `zipimport.asm` + `inflate.asm` (they parse attacker-supplied files).
**Steps:**
1. `fuzzzip <seed> <iters>` verb mutating a fixture `.vaultz` in memory, running the stage
   path (zi_stage) with abort-after-parse.
   *Test:* 100k iters, 0 AV; every failure is a clean error return.
2. Inflate-specific corpus: hand-craft stored/fixed/dynamic-huffman members incl. the classic
   evil cases (oversubscribed trees, distance-too-far, 0-length codes).
   *Test:* each evil case rejected with the right error code (table of expected codes).
3. Memory-bomb guard: assert decompressed-size cap enforced before allocation.
   *Test:* member claiming 4 GiB output rejected before any large alloc (peak WS < 100 MiB
   during the test, watched via `Get-Process`).

### 32. Automated dead-code detector
**Goal:** Repeatable tool replacing the manual dead-symbol sweeps done in the audit.
**Steps:**
1. `tools/deadcode.py`: parse `obj/*.lst` listings for defined symbols, cross-reference call/
   lea references across all listings, report never-referenced procs/data (allowlist for
   entry points, exports, rc-referenced IDs).
   *Test:* run on HEAD: the report matches "known clean" (empty or allowlisted only); re-add a
   known-dead proc from git history → detected.
2. Same for equ constants via source grep.
   *Test:* seed an unused equ → detected; HEAD clean.
3. Hook into `build strict`.
   *Test:* strict build fails on the seeded case, passes on HEAD.

### 33. Reproducible release builds
**Goal:** Two clean builds of the same commit produce byte-identical exes (auditability).
**Steps:**
1. Identify nondeterminism: link `/Brepro`, strip PDB path (`/pdbaltpath`), fix the rc
   timestamp fields.
   *Test:* build twice into different dirs; `fc /b` the exes → identical (except allowed
   sections, ideally none).
2. `build release` target applying these flags (keep /debug builds as default dev flow).
   *Test:* release exe passes SELFTEST + REDTEAM; mitigation flags (CET, DEP, ASLR) still
   present per dumpbin.
3. Publish the SHA-256 of releases in the repo.
   *Test:* documented hash matches a fresh clean build by a second checkout.

---

## E. Performance & robustness (Plans 34–39)

### 34. Faster unlock: parallel KAT gate
**Goal:** Run the startup self-test KATs across worker threads to cut launch latency.
**Steps:**
1. Measure: `dbg` timestamps per KAT; identify the top 3 (Argon2id will dominate).
   *Test:* a table of per-test ms is printed; numbers reproducible ±10%.
2. Thread pool (CreateThread ×N, N=min(cores,4)) executing independent KATs; the gate still
   fails closed if ANY thread reports failure or doesn't report at all (watchdog timeout).
   *Test:* SELFTEST wall time drops ≥40%; corrupt one vector → still fails closed; suspend a
   worker artificially (dbg hook) → watchdog trips.
3. Keep single-threaded order for tests with shared state (audit for statics first).
   *Test:* 1000 repeated selftest runs in a loop, zero flakes.

### 35. Sidebar virtualization for large vaults
**Goal:** 5,000-entry vault scrolls smoothly; tiles are drawn, not created, per row.
**Steps:**
1. Generate a 5k-entry synthetic vault via a script (CLI `add` loop); profile current load
   and scroll (GetGuiResources, paint time via `dbg` QPC probes).
   *Test:* baseline numbers recorded in the plan's commit message.
2. Convert the sidebar to a single owner-draw scrolled surface: paint only visible tile rows
   from `g_entries` (painters already exist), hit-test by y-offset; kill per-entry child windows.
   *Test:* GDI handle count independent of entry count; scroll paint < 5 ms/frame at 5k entries.
3. Keep keyboard selection + accessibility names (Plan 23) working.
   *Test:* arrow keys walk entries; NVDA still reads them.

### 36. Crash containment without secret leakage
**Goal:** On any unhandled exception: wipe secrets, show a minimal apology box, and ensure NO
minidump/WER report containing key material leaves the machine.
**Steps:**
1. `SetUnhandledExceptionFilter` handler: call the existing global wipe (secmem), then
   fail-fast. Register early in wstart.
   *Test:* `dbg` verb `crashme` (deliberate AV) → wipe trace prints, process exits, no WER
   dialog with "send" appears.
2. Disable WER dumps for the process (WerAddExcludedApplication / registry DumpType=0 doc note).
   *Test:* after crashme, `%LOCALAPPDATA%\CrashDumps` has no new vordr dump.
3. Optional local-only breadcrumb: last 32 dbg trace lines to a ring buffer flushed to a text
   file (no secrets by construction — trace lines are static strings + codes).
   *Test:* crashme produces the breadcrumb file; grep for planted sentinel password → absent.

### 37. Atomic saves + backup generations
**Goal:** A crash/power-cut mid-save can never lose the vault; keep N rotated backups.
**Steps:**
1. Audit the current save: ensure write-to-temp → FlushFileBuffers → ReplaceFileW/MoveFileEx
   ordering; fix if it writes in place.
   *Test:* kill -9 the process mid-save in a loop (script injects a dbg stall between write
   and rename, then TerminateProcess): after 50 kills, the vault always opens (either old or
   new state, never corrupt).
2. Rotation: before replace, copy current to `vault.bak1..N` (N=3 default, setting).
   *Test:* 5 saves → bak1..3 exist and are each openable with the master password.
3. "Restore from backup…" picker on the unlock dialog's error path.
   *Test:* corrupt the main file → unlock offers backups → restore succeeds.

### 38. External-change detection
**Goal:** If the vault file changes on disk while open (sync tools, second instance), warn
before overwriting.
**Steps:**
1. Snapshot (size, mtime, BLAKE2b of header) at load; re-check before every save.
   *Test:* touch the file externally → next save shows the conflict dialog.
2. Conflict dialog: Reload / Overwrite / Save-As, with the anti-rollback counter (Plan 3)
   shown for both versions.
   *Test:* each button does what it says; Reload preserves unsaved-edit warning first.
3. Single-instance guard: named mutex; second launch focuses the first window instead.
   *Test:* launch twice → one window, first instance foregrounded (tray-foreground pattern).

### 39. Startup breadcrumb + first-run experience
**Goal:** Cold-start problems become diagnosable and the very first launch is welcoming.
**Steps:**
1. Promote the dbg breadcrumb trace to release (static strings only) behind `--trace <file>`.
   *Test:* run with the flag → ordered milestones (selftest gate, TPM probe, prefs load,
   dialog up) in the file; without flag → no file.
2. First-run detection (no HKCU prefs): after vault creation, show a one-time 3-step tour
   overlay (add entry → generator → lock) using the toast/overlay machinery (Plan 25).
   *Test:* delete the HKCU key → tour appears once, never again after completion.
3. Measure cold start (process create → dialog visible) before/after all this; budget ≤ 1.5 s
   with the parallel KAT gate (Plan 34).
   *Test:* scripted 10-run average printed; within budget.

---

## Suggested sequencing

- **High user value / low risk:** 2, 7, 12, 20, 26.
- **Format-touching plans (3, 4, 14, 16, 26)** each bump/extend the header — batch
  compatibly and always ship with ROUNDTRIP + a version-gate test (old vault still opens).
- **Big rocks:** 35 (sidebar virtualization) deserves its own branch.
