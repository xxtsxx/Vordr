# Changes

All notable changes to **Vordr** are logged here, newest first. Dates are
ISO-8601. This file is kept by hand alongside every change: each entry says
what changed and why, not a raw commit list. Releases before 0.2.4 are recorded
in [docs/RELEASES.md](docs/RELEASES.md).

## [Unreleased]

### Security

- **Static secret buffers were never locked into RAM.** `sec_lock_statics` ran
  only from an entry point the executable no longer uses (`start`; the real one
  is `wstart`), so the master password, the vault key, password history and the
  display scratch could be paged out, and the "secrets not pinned" warning could
  never fire for them. The lock list is now one table (`sec_regions`) driving the
  startup lock, the wipe on lock and the panic wipe; `lktest` checks every listed
  buffer is actually resident-locked.
- **Importing a `.vordr` file could destroy the open vault's attachments.** The
  foreign vault's attachment index overwrote the open vault's; the next save wrote
  those attachments away as empty ciphertext. Merging a newer copy of an entry
  also dropped its attachments. Both fixed; `vimpattkat` covers them.
- **A ZIP import took field types verbatim**, so a crafted archive could make the
  vault unreadable at its next unlock or drive an out-of-bounds read. Types are
  sanitised; `jfuzz` checks every case.
- **ZIP export could write past its buffer** when an attachment did not fit.
  Buffers now grow; `zexcap` covers it.
- **The rollback warning could be bypassed by opening the vault under another
  spelling of its path**, and a long path lost its TPM enrolment: both were keyed
  by the path as typed. They are keyed by the normalised path now, with the old
  keys still read.
- **The computed GCM tag was left on the stack** after every authenticated
  decrypt - after a forgery attempt, a valid tag for the attacker's ciphertext.
- **A lock left decrypted data in static buffers** (history, originals, display
  and commit scratch, attachment keys). The whole secret table is wiped on lock.
- **Every first-chance exception in any DLL killed Vordr**, including ones shell
  extensions in the file dialogs raise and handle themselves. The vectored
  handler acts only on faults inside Vordr's own image; others still reach the
  unhandled-exception filter.
- **The software shadow stack was one process-wide global**, raced by any thread
  running framed code, and the secure-desktop watchdog left the main thread
  verifying against the worker's stack - a fastfail instead of a cancelled
  prompt. It is per thread now (TLS), from Myrkr; `pkat` runs its workers truly
  in parallel to prove it.
- Mark of the Web on every file written out of an attachment; more executable
  types (disk images, search/library connectors, appref-ms, theme files, Python)
  are download-only; the secure-desktop name is random per use; the Argon2 final
  block is pinned while the KDF runs; HMAC-SHA1, BLAKE2b and AES-CTR wipe their
  stack state; the header's lane count is checked (the format said it was).

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
