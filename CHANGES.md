# Changes

All notable changes to **Vordr** are logged here, newest first. Dates are
ISO-8601. This file is kept by hand alongside every change: each entry says
what changed and why, not a raw commit list. Releases before 0.2.4 are recorded
in [docs/RELEASES.md](docs/RELEASES.md).

## [Unreleased]

## [0.2.4] - 2026-11-15

### Added

- **PIN secret type (`VF_PIN = 20`).** Dedicated masked secret rows for numeric or alphanumeric PIN codes with separate length policy (`PinMinLen`, default `6`), trivial-pattern detection (repeated digits, `+1`/`-1` runs, `2`/`3`-period cycles, palindromes) and optional save-time rejection (`PinRejectTrivial`), PIN-first random generator redraw, history archiving (`VF_PWHIST`), search exclusion, and domain-separated vault-health auditing (`pinkat`, `healthkat`).
- **Strengthened TPM Unlock modes (`VTPM` v1).** Configurable per-vault TPM unlock in Settings (`Off`, `TPM only`, `TPM + PIN`, `TPM + Hello`) with administrator minimum-mode floor (`TpmMinMode`):
  - **`TPM + PIN`:** Argon2id-stretched PIN combined with dual-slot (`S0`/`S1`) pre-commit rotating TPM 2.0 state keys (`Microsoft Platform Crypto Provider`) so replaying or rolling back the `HKCU` registry blob fails `AES-256-GCM` authentication, revoking the TPM shortcut after `TpmPinMaxAttempts` (default `3`) failed attempts without touching OS-wide TPM authorization counters (`tpmkat`).
  - **`TPM + Windows Hello`:** Dual-key unwrap combining TPM 2.0 RSA-2048 OAEP with unpackaged Win32 Windows Hello FIDO2 `PRF` (`hmac-secret` via `webauthn.dll`, `WHLO` v1) requiring live biometric or Hello PIN verification.
- **Live TPM anti-hammering cooldown diagnostics.** When Windows OS standard-user anti-hammering (`0x80290409`) or hardware TPM 2.0 dictionary-attack lockout (`0x80280921` / `0x80280803`) blocks a TPM call, Vordr queries the active Windows `AuthorizationFailure` rolling-window history or unprivileged `TPM2_GetCapability` lockout properties via `tbs.dll` and reports the active mechanism, configured window/threshold, remaining cooldown duration, local expiry clock time, and sleep/reboot behavior.

### Security

- **Second-pass security audit remediation (`VDR2-01`–`VDR2-26`).** Hardened private-desktop DACLs (`SetUserObjectSecurity` pointer fix and restricted SIDs), screen-capture exclusion (`WDA_EXCLUDEFROMCAPTURE` default with `AllowScreenCapture` policy), UNC vault blocking (`AllowUncVault`), strict parser/clipboard/temp-cleanup bounds, and invariant `VH_INV_AAD` binding across `VTPM` v1 envelopes.
- **Comprehensive security hardening (`VDR-01`–`VDR-28`).**
  - **Container, ZIP, and JSON parsers:** Bounded `zj_str` destination capacity (enforced statically in `wstrcheck.py`) with strict `\uXXXX`, surrogate-pair, and `\u0000` validation; enforced `256 MiB` per-attachment (`ATT_FILE_MAX`) and `3,840 MiB` section (`ATT_TOTAL_MAX`) caps with checked 64-bit arithmetic (`attovfkat`); honored per-entry selection masks (`g_sel[]`) on AES-ZIP attachment export (`zexselkat`); validated UTF-16LE tails on `VF_PWHIST`; added automatic nonce retry on `VATT` footer tag collisions (`vattcolkat`); switched `zi_scan` to EOCD Central Directory parsing and made `zi_decrypt` non-destructive across duplicate attachment references.
  - **Attachment preview, IPC, clipboard, and private desktop:** Replaced preview blocklisting with a strict eight-extension safe-preview allowlist (`.txt`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.webp`, `.pdf`), filename sanitization (`gui_sanitize_attname`), owner-only temp directory DACLs, and fail-closed `Zone.Identifier` (`ZoneId=3`) writes (`tmptest`); wiped `g_vkey`, arenas, and static buffers immediately inside `vp_lock` when locking over open modals (`guitest.ps1`); rejected UNC/device paths and modal-active hand-offs in `WM_COPYDATA`; bound `CLIP_TIMER` to `g_trayhwnd` so clipboard auto-clear survives dialog closure; made `HKLM`-locked `SecureUnlock=1` fail closed and added explicit user confirmation before normal-desktop fallback (`secdeskkat`); filtered whitespace/quotes/control bytes in URL launches.
  - **Loader, crash containment, policy, file I/O, and TPM:** Enabled PE `LOAD_CONFIG.DependentLoadFlags = 0x0800` (`System32`-only static import loading, verified by `pe_normalise.py` and `dllhijack`) plus early `SetDefaultDllDirectories` and process mitigation policies; replaced `HKLM` environment expansion with a fail-closed `SHGetFolderPathW` prefix allowlist (`%USERPROFILE%\`, `%LOCALAPPDATA%\`, `%APPDATA%\`) that locks invalid `HKLM` values without `HKCU` fallback (`polkat`); bound TPM RSA-2048 OAEP blobs via a 64-byte `key32 || SHA-256(key32 || label32)` payload verified in constant time (`tpmkat`); made crash handling atomic/reentrant-safe (`crash_reent`) with `{base, size}` secret-region wipes; hardened atomic saves via `ReplaceFileW` and reparse-point/disk-type checks; canonicalized rollback counters via `GetFinalPathNameByHandleW` with monotonic high-water enforcement (`rbtest`); backed `mem_alloc`/`mem_free` with canary-tagged heap blocks (`heaptag`, `heapmagic`) and enforced raw frames on OS callbacks (`framecheck.py`).
  - **Cryptography, CPU gate, and supply chain:** Replaced table S-boxes in `aes_expand_key` with hardware `aeskeygenassist`; scrubbed Argon2/SHA-1/BLAKE2b/TOTP stack frames and volatile `xmm`/`ymm` registers; enforced the SP 800-38D GCM plaintext length bound ($2^{36}-32$ bytes); verified `OSXSAVE` and `XGETBV(0)` before enabling AVX2; mixed `RDSEED` into `1..7`-byte RNG tails; pinned GitHub Actions by commit SHA, required Python fail-closed in `build.cmd strict`, and added MSI downgrade blocking (`NEWERVERSIONDETECTED`) and SDDL `LockPermissions` (`verify_msi.ps1`).
- **Static secret buffers pinned from `wstart`.** `sec_lock_statics` now runs at GUI startup via the unified `sec_regions` table driving startup `VirtualLock`, lock-time zeroing, and panic wipes; `lktest` verifies physical working-set residency (`QueryWorkingSetEx`).
- **Native `.vordr` import preserves active vault attachments.** Foreign imports park and restore the full attachment index table (`vimpattkat`).
- **Per-thread TLS software shadow stack.** Each thread initializes its own guard-paged shadow-stack arena via TLS (`pkat`), eliminating cross-thread races during parallel KATs and private-desktop prompts; `FRAME_EPILOG` verifies top-of-stack and ancestor integrity (`shadow_anc`).

### Fixed

- **A partly-shown entry could be saved, dropping the part not shown** (more
  fields than rows, an over-long value, an attachment past the tile's limit). It
  opens read-only with an explanation; save, favourite, trash, edit and add-field
  all refuse it.
- **A failed reload emptied the vault window** and the next save dereferenced
  nothing. The open vault is kept; the user is told; an older file swapped in by
  a reload is warned about.
- **An unanswered dialog kept the vault unlocked for good**: the idle lock skipped
  every tick while one was open. A lock now closes Vordr's dialogs first.
- **TPM auto-unlock opened an older (rolled-back) vault without asking.**
- **Export could overwrite the open vault.** Refused, by file identity.
- **Input cut short without a word**: an export password longer than 254
  characters sealed the archive with its first 254; long labels, read-aloud and
  click-to-open URLs were shortened; dropped files past the tile's limit, or
  locked ones, vanished. Edits now stop at their buffer's size, and the rest say
  what did not fit.
- An encrypted ZIP Vordr cannot read is named as such, not as a wrong password.
- Save failures say why (vault full, failed integrity check) instead of offering
  a retry that cannot work.
- Flushing a file on a volume that does not support it no longer fails every save.

### Changed

- **Drawn scrollbars**, after Myrkr: the entry list and the export/import
  checklist have a translucent thumb that appears when you point at the right
  edge, instead of the native bar. Drag it, click above or below it to page, or
  use the wheel. The lists paint double-buffered, so the thumb no longer
  flickers while dragged or leaves a stub behind when the pointer leaves, and
  the checklist lost a white strip its hidden horizontal scrollbar still
  reserved.
- **The detail pane scrolls instead of paging.** An entry with more fields than
  fit used to split into pages behind a "< n / m >" bar; it now scrolls a whole
  card at a time with the same drawn thumb (wheel, drag, page-click), and tabbing
  to a field off screen brings it into view; a field you were typing in that
  scrolls away hands the focus to the top card, so keys never edit something
  hidden. No card is ever partly shown, so nothing can overlap the header or the
  command bar. Touchpad scrolling adds up small movements instead of jumping a
  whole card (or three list rows) for each.
- **A visual uplift.** One animation clock (`src/anim.asm`) eases a few values
  over time with a single timer that runs only while something moves - at rest
  it costs nothing. **Settings > Animations** picks *Follow Windows* (the
  default: Windows' "Animation effects" switch), *Always* or *Never*; without
  animation every change is instant. On it:
  - the selection is a Fluent pill with an accent bar that **slides** between
    entries;
  - the detail pane **cross-fades** from one entry to the next;
  - list rows and the frameless header/row buttons **fade** their hover tint in
    and out, and the scrollbar thumbs fade instead of popping.
  Hover, selection and the neutral backgrounds are derived from each scheme's
  own colours the same way for all nine (`col_mix`), with a trace of the accent
  in the greys. Entry tiles show the title's first letter (a monogram) instead
  of the same globe or padlock on every row; brand icons and icons you picked
  stay. The vault window's background is composed off screen and put up in one
  blit, and the hot paint paths use the DC's own brush instead of creating one
  per row.
- **Faster, steadier painting** (measured on a 5,000-entry vault):
  - showing an entry rebuilds its rows with the window's painting suspended and
    repaints the pane once - it used to repaint the window background 38 times
    (78 for a 40-field entry), once per control created, moved or destroyed:
    42 ms -> 20 ms per switch, 299 ms -> 125 ms for 40 fields, and no flicker;
  - a search refill takes 0.3 s instead of 3.5 s: looking an entry up by index
    walked the vault from its first entry, and sorting does ~60,000 lookups. Bulk
    reads (a refill, a list paint, an entry rebuild) now use a one-pass index
    that lives only for that read;
  - a list repaint costs ~1.1 ms instead of ~6.8 ms; icon tiles come from a
    cache of pre-rendered bitmaps (emptied at lock), pixel-identical to drawing
    them;
  - the edit boxes are left out of the background paint (they paint every pixel
    themselves), so a full repaint no longer shows them empty for a frame;
  - moving the keyboard focus repaints the underline strips, not the whole
    window and every control in it;
  - the sliding selection repaints only the rows it crosses.
- **Topmost elevation, foreground revival, focus priority, and full-surface Settings dragging.** All 16 top-level dialogs carry `WS_EX_TOPMOST` and `DS_SETFOREGROUND` with deferred `WM_VORDR_RAISE` foreground restoration across tray/hotkey/`WM_COPYDATA` revivals, automatic focus into password/PIN inputs on credential dialogs and `IDC_V_SEARCH` on the main vault window, and full-surface window dragging across `DLG_SETTINGS`.
- **Smooth zero-flicker detail switching and fast reproducible builds.** Buffered `WS_EX_COMPOSITED` child tearing/creation during entry switches, single-process lint caching + multi-core `ml64` compilation in `tools\build_fast.py`, precompiled regexes in `tools\nvcheck.py`, and auto-discovered MSI target in `tools\verify_msi.ps1`.
- **Reproducible release builds.** Two builds of one commit differed (ml64 stamps
  every object, so `/Brepro` hashed different inputs each time).
  `tools\pe_normalise.py` zeroes the build stamps after the link, `build.cmd
  release` writes `bin\SHA256SUMS.txt`, and `tools\verify_repro.ps1` proves two
  clean builds are byte-identical with every mitigation intact.

### Tests and tooling

- `tests\verify_vault.py`: an independent reader of the vault format, with its
  own RFC 9106 Argon2id, that decrypts real vault files from `docs/formats.md`
  alone, tamper-checks every region and checks nonces differ per save.
- `tests\compattest.py` with frozen v0.2.3 vaults in `tests\fixtures`.
- `tests\guitest.ps1` and `tests\lib\gui.psm1`: an isolated Vordr instance (HKCU
  remapped to a scratch key) driven from outside its process; `-Slow` adds the
  real idle lock and one real mouse press on the detail pane's thumb.
- `tools\prune_rollback.py`: lists (and with `--delete`, after a .reg backup,
  removes) rollback-mirror values that are not this machine's registered vault -
  the test probes used to leave one per temporary path in the real HKCU.
- `tests\redteam.py`: each fault-injection case must end with its own fail-fast
  code; a new `crash` case checks containment and the breadcrumb.
- `guardkat` inside `layoutkat`; `katreport` adds the Argon2 reference vector
  that crosses the 128-block address boundary.
- `tools\nvcheck.py` (callee-saved registers), framecheck v3 (raw epilogue
  mismatch, `--strict` in strict builds), aligncheck v2 (resolved sizes),
  `verify_msi.ps1` payload checks, `tools\compare.ps1`.
- From Myrkr: the TLS shadow stack, the drawn scrollbar, the GUI harness, the
  reproducibility tools, the independent reader's Argon2id and most of the above
  checkers. Vordr gave Myrkr its crash containment, flush-before-rename and
  secure-desktop handling in turn.
