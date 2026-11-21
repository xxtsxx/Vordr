# Changes

All notable changes to **Vordr** are logged here, newest first. Dates are
ISO-8601. This file is kept by hand alongside every change: each entry says
what changed and why, not a raw commit list. Releases before 0.2.4 are recorded
in [docs/RELEASES.md](docs/RELEASES.md).

## [Unreleased]

## [1.0.0] - 2026-11-21

First public `1.0.0` release, consolidating the native ARM64 port, DirectCompute glass UI and compositor, PIN secret type, strengthened TPM unlock modes, and Pass 1–9 security audit remediations (`0.2.4`–`0.8.2`) with a polished interactive universal MSI installer and refreshed documentation.

### Added in 1.0.0

- **Interactive universal MSI setup wizard (`tools/make_msi.ps1`, `tools/verify_msi.ps1`).** Pure declarative Windows Installer 5.0 wizard (zero custom actions, zero third-party tools) featuring custom Vordr-styled graphics (`BmpSide`, `BmpTop`, `vordr.ico` Add/Remove icon, and 16×16 supersampled padlock icons), four guided screens (Welcome, Installation Folder & integration options, master-detail Settings & Policy editor, and Ready to Install), a modeless progress dialog, and maintenance/uninstall handling.
- **Start with Windows installer option (`VORDR_AUTOSTART=1`).** Opt-in checkbox on the Installation Folder screen and secure public MSI property writing `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Vordr = "[INSTALLDIR]vordr.exe"` (starting minimized to the notification area, cleanly removed on uninstall).
- **User-overridable `HKCU` defaults alongside `HKLM` policy locks (`VORDR_USER_*` + top-right `Lock` toggle).** All 16 settings in the MSI wizard are directly editable: editing any of the 14 `HKCU`-capable settings without ticking the top-right `Lock` checkbox seeds a `Permanent` `HKCU\SOFTWARE\Vordr` user default (changeable inside Vordr Settings and preserved across uninstall), while ticking `Lock` enforces and locks the value in `HKLM\SOFTWARE\Vordr`. `AllowUncVault` and `AllowScreenCapture` remain strictly `HKLM`-only. Silent `/qn` installs continue to write zero policy or preference rows unless explicitly supplied.
- **Documentation visual refresh and post-quantum section (`README.md`, `logo/vordr.svg`, `docs/screenshots/*.png`, `docs/DEPLOYMENT.md`, `docs/TRUST.md`).** Added the Vordr vector shield logo, synthetic-vault screenshots, a plain-language post-quantum resistance section covering AES-256-GCM, Argon2id/BLAKE2b, SHA-256, and RSA-2048/FIDO2 TPM/Hello unlock wrappers, an encryption implementation trustworthiness discussion in `docs/TRUST.md`, and full alignment across all 20 documentation files.

### Changed in 1.0.0

- **Simplified TOTP countdown timer (`src/theme.asm`).** Removed the redundant circular ring beside the TOTP countdown bar so each authenticator row renders only the clean horizontal progress pill.

## [0.8.2] - 2026-11-21

### Added in 0.8.2

- **Native Windows on ARM (ARM64) executable (`bin/vordr-arm64.exe`, [docs/ARM64.md](docs/ARM64.md)).** Pure AArch64 assembly build (zero C, zero CRT) combining hand-written ARMv8 Cryptography Extensions (`AESE`/`AESMC`, `PMULL`/`PMULL2`, `SHA256*`, `SHA1*`), NEON (`BLAKE2b`, `Argon2id`), `BCryptGenRandom` + ARMv8.5 `RNDRRS` entropy mixing, ARM64 `cpu_gate` / `ff_trap` (`BRK #0xF003`), pointer authentication (`PACIBSP`/`AUTIBSP`), and `LOAD_CONFIG.DependentLoadFlags = 0x0800` in `src/arm64/*.S` with deterministic COFF-to-AArch64 translation (`tools/a64/xlat.py`, `build_arm64.cmd`) so application logic stays single-source with x64. Verified byte-reproducible (`tools/verify_repro.ps1`) and end-to-end under ARM64 emulation (`tests/arm64/test_*.py`), including cross-architecture `.vordr` vault interoperability with x64 fixtures and `tests/verify_vault.py`.
- **Universal x64 + ARM64 MSI (`tools/make_msi.ps1`, `tools/verify_msi.ps1`).** Single per-machine MSI embedding both `vordr.exe` (`0x8664`) and `vordr-arm64.exe` (`0xAA64`) and automatically deploying the local system's native executable to `%ProgramFiles%\Vordr\vordr.exe` with zero custom actions via `AppSearch` + `RegLocator` (`HOST_NATIVE_ARCH`).

### Fixed in 0.8.2

- **Latent x64 flag-liveness and stack-alignment hazards (`src/gpu.asm`, `src/gui.asm`, `src/theme.asm`).** Surfaced by `tools/a64/xlat.py` static analysis: added explicit `test` instructions before conditional jumps following multi-bit shifts (`src/gui.asm`) and `imul` (`src/gpu.asm`), and removed an 8-byte stack misalignment around `theme_glass_alpha` (`src/theme.asm`).

### Security in 0.8.2

- **Pass 3 full-application & ARM64 security audit remediation (`A3-01`–`A3-31`).**
  - **Path canonicalization, ACLs, and file I/O (`src/fileio.asm`, `src/log.asm`, `src/vault.asm`, `src/regcfg.asm`, `src/gui.asm`):** Blocked `\\?\` prefix bypasses, forward slashes, `..` traversal, and NTFS ADS streams outside drive colons; forced `file_path_allowed` canonicalization even when `AllowUncVault != 0`; gated default vault candidates via `file_path_allowed`; made DACL creation fail closed across `file_write`, `log_open`, `vault_copy_dacl` (handle-based `GetSecurityInfo`/`SetSecurityInfo`), and `gui_secdesk_show` (atomic `SECURITY_ATTRIBUTES` at `CreateDesktopW`); added inside-retry reparse checks on `file_rename`, backup rotation, and stale temp sweeps (`FILE_FLAG_OPEN_RP` + `file_validate_handle`).
  - **IPC, clipboard, settings, and secure-desktop hardening (`src/gui.asm`):** Replaced legacy `WM_COPYDATA` (now unconditionally rejected) with a kernel-authenticated per-SID named pipe (`\\.\pipe\VordrIPC-<16hex>`, `PIPE_REJECT_REMOTE_CLIENTS`, `GetNamedPipeClientProcessId` / `GetNamedPipeServerProcessId` + `gui_pid_is_self`); routed `WM_COPY`/`WM_CUT` in password/edit controls through `gui_copy` (clipboard history/cloud exclusion + auto-clear timer); removed unsaved-settings auto-commit on `vp_lock`; isolated `gui_secdesk_show` per-invocation state (`g_sd_slots` + atomic `g_secdesk_busy`/`g_secdesk_orphans`) with 200 ms orphan cancellation polling across all private-desktop dialogs; fixed `g_comp_bits` UAF window and `PatBlt` scrollbar-buffer wipe.
  - **Policy, TPM, WebAuthn, vault, ZIP, and secret-memory hardening (`src/gui.asm`, `src/vault.asm`, `src/tpm.asm`, `src/secmem.asm`, `src/pwgen.asm`, `src/zipimport.asm`, `src/hardening.asm`, `src/gpu.asm`, `src/main.asm`):** Made `TpmMinMode`, `TpmUnlockMode`, and `VaultPath` fail closed on corrupt `HKLM` values; enforced `blob_mode >= g_tpm_want` on TPM unlock and rolled back orphan PCP keys on `vault_tpm_remember` write failure; ran `tpm_hello_unseal` before `tpm_unseal` for Mode 3; validated WebAuthn `authenticatorData` (`UP|UV` flags + credential ID) and TBS `TPM2_GetCapability` response headers; moved `sec_regions` and TPM constants into `.const`, added trailing `PAGE_NOACCESS` guard pages and `SRWLOCK` serialization to `secmem_alloc`/`secmem_free`, capped `secmem_panic_wipe` lengths, tracked/wiped `g_foreign_body`, scoped `VF_SYSTEM`/`VF_SYS_PWVERIFY` to `field[0]`, stripped system/history fields on copy, hardened `zi_commit` error handling and AE-2/JSON strictness, removed branch/cache timing leaks in `pwgen`/`draw_chars`, hardened `WER` flags (`0x1E1`) and `ct_memcmp` register scrub, and handled D3D11 buffer/UAV allocation failures via WARP fallback.
  - **ARM64 translator, hand-written assembly, PE, MSI, and CI hardening (`tools/a64/xlat.py`, `tools/a64/build_arm64.py`, `tools/a64/coff.py`, `src/arm64/*.S`, `tools/pe_normalise.py`, `tools/make_msi.ps1`, `tools/verify_msi.ps1`, `build.cmd`, `.github/workflows/build.yml`):** Eliminated stack-canary leaks on indirect Win32 API calls via exact `api_arity` and CFG-clamped argument walks; fixed `cmpxchg`/`xchg` barrier & comparison width, `gs:` -> `x18`, divide/overflow traps, `cl == 0` shifts, and `comiss` NaN handling; added `frame.inc` stack canary + TLS shadow-stack guards and `.seh_startepilogue`/`.seh_endepilogue` unwind info to hand-written ARM64 framed procedures; enumerated all `CentralProcessor\<N>` cores for `FEAT_RNG`; extracted `ARM64_NT_CONTEXT` `crash_capture_context`; removed dead `br x15` gadget in `loadcfg.S`; hardened `pe_normalise.py` and `make_msi.ps1` (`MsiLockPermissionsEx` SDDL ACLs, case-insensitive `~><` + range `LaunchCondition` guards, CET payload bit + `DependentLoadFlags` + W^X checks); added ARM64 + universal MSI build/verification and `persist-credentials: false` to CI.

- **Pass 4 focused security audit remediation (`A4-01`–`A4-25`).**
  - **Universal MSI & PE verification (`tools/make_msi.ps1`, `tools/verify_msi.ps1`, `tools/pe_normalise.py`):** Fixed `MsiLockPermissionsEx` to the full 5-column Windows Installer 5.0 schema (`MsiLockPermissionsEx` PK + `Condition`) and verified it against `msi.dll`'s exact runtime SQL query; fixed `Assert-ReleasePe` `IMAGE_FILE_HEADER.Characteristics` offset (`peOff + 22`), CET mapped-RVA / read-only / non-zero checks, `LaunchCondition` `S255` (`ICE03`) compliance, and `_ROINIT` page-isolation checks.
  - **Named-pipe IPC, temp sweep & secure desktop (`src/gui.asm`, `src/vault.asm`):** Upgraded named-pipe IPC to bounded overlapped duplex I/O (`PIPE_ACCESS_DUPLEX`, 250 ms `ReadFile`/`WriteFile` + `CancelIo`, explicit `SetEvent` on `ERROR_PIPE_CONNECTED`, 1-byte server liveness ACK closing PID-reuse TOCTOU, and `IPC_POLL_TIMER` servicing during modal `DLG_VAULT`); hardened `gui_temp_sweep_stale` against NTFS hardlinks (`nNumberOfLinks > 1`), directory-junction escapes (canonical `%TEMP%\VordrPreview-` prefix verification), and path-based `SetFileAttributesW`/`DeleteFileW` TOCTOU (`SetFileInformationByHandle` `FileBasicInfo` & `FileDispositionInfo`); converted Secure Desktop timeout/exit ownership to a 3-state atomic CAS (`0`/`1`/`2`), handled pre-`WM_INITDIALOG` cancellation and nested child popups, and gated `gui_open` / `vault_preload` against live orphans.
  - **File I/O, ZIP, WebAuthn & ARM64 (`src/fileio.asm`, `src/zipimport.asm`, `src/tpm.asm`, `src/hardening.asm`, `src/arm64/platform.S`, `src/arm64/frame.inc`, `tools/a64/xlat.py`, `tools/a64/emu.py`):** Reset `g_wf_inherit_acl` before `file_path_allowed`, checked `SetSecurityInfo` on `CREATE_ALWAYS`, checked both endpoints for reparse points in `file_rename`, prevented `path_longify` >4096-wchar truncation, included 28-byte AE-2 framing in `zi_scan` overlap checks, added `UP|UV` and `pbFirst` scrub parity to `tpm_hello_seal`, spilled `RegQueryValueExW` status across `RegCloseKey` in ARM64 `cpu_gate` (+ volatile `x1..x17` poisoning in `emu.py`), aligned `A64_SSTK_CAPACITY = 4096` with ±128 MiB `BRANCH26`, fixed `xlat.py` `cl == 0` flag preservation (`and`/`cbz` instead of `tst`) and `i_cmpxchg`/`i_idiv`/`rdx_known_zero` soundness, and sized `ci_modbuf` to `MAX_PATH_CHARS`.
- **Pass 5–8 verification-loop remediation (`A5-01`–`A5-15`, `A6-01`–`A6-07`, `A7-01`–`A7-03`, `A8-01`).** Added a bounded 250 ms multi-read overlapped drain loop before `DisconnectNamedPipe` (draining unread client messages on early-NACK while preserving `g_ipc_buf` on ACK and recording pre-cancel bytes for wipe), `g_ipc_armed` auto-recovery across timers, and `g_secdesk_busy` / `g_in_import` / `g_tray_modal` gating (`IPC_POLL_TIMER` active on tray modals while ignoring `g_vaulthwnd` in `GetWindow(g_trayhwnd, GW_ENABLEDPOPUP)`); reordered `secdesk_restore` strictly before CAS `0 -> 2` desktop ownership transfer, wiped vaulted/preloaded/password/PIN material across all orphaned dialogs including `DLG_PWREMIND` (with `g_body_ptr == 0` guards in `go_tpm_ok` and `vault_pw_check`, post-`vault_pw_check` orphan exit in `pwremind_proc`, and consumer `lfence` / ARM64 `dmb ish` acquire barriers on every `g_secdesk_orphans == 0` fallthrough), gated all 8 normal-desktop password sites via `gui_normal_dlg_ready`, returned `0` on pre-switch cancellation, and CAS-cleared `g_secdesk_tid` before releasing `g_secdesk_orphans`; fixed PowerShell signed `0xA0000000L` W^X comparison and `LOAD_CONFIG` alignment/span checks in `make_msi.ps1`, duplicate `_ROINIT` rejection in `pe_normalise.py`, subdir `\` separator validation in `gui_sweep_handle_ok`, orphan Hello passkey deletion in `tpm_hello_seal`, `path_longify` cap-boundary OOB guard, and variable-shift `dv == x0` / flag-liveness handling in `xlat.py`.

## [0.8.1] - 2026-11-20

### Added in 0.8.1

- **DirectCompute procedural backdrop engine (`src/gpu.asm`, `cs_5_0`).** Hardware-accelerated D3D11 DirectCompute shader dispatch (`WARP` fallback when no hardware adapter is available) rendering seven curated procedural backdrops (`Cut planes`, `Ambient glow`, `Stained mosaic`, `Brushed alloy`, `Paper grain`, `Neon horizon`, `Topo contours`) plus `Flat`, backed by an SSE2 360-degree palette hue/luminance color-cycling pass (`gpu_color_cycle`) that re-tints pre-rendered backdrop caches in under `5 ms` (`gpukat`).
- **Expanded palette library and glass surface UI (`src/theme.asm`, `src/gui.asm`).** Fourteen curated color palettes (`0..13`, `Gruvbox` default) plus `Follow Windows` (`14`), paired with semi-transparent glass entry/detail cards, sidebar selection panels, soft ambient drop shadows, a gold-shield title bar header covering the full `0px` top client surface, TOTP radial countdown rings, character-class syntax highlighting in the password generator, and compact single-button scheme/backdrop selectors in Settings.
- **Unified off-screen window compositor (`gui_present_composite`).** Top-level dialogs composite their backdrop, glass cards, owner-drawn controls, and Win32 child edit/list/combo windows into a single off-screen `DIBSection` via `WM_PRINTCLIENT` and present the completed frame atomically in a single `BitBlt`, eliminating multi-pass GDI tearing and flicker across Settings, Vault, and modal dialogs (`guitest.ps1`).

### Security in 0.8.1

- **Full-application security audit remediation (`AUD-01`–`AUD-30`).**
  - **Read-only post-init globals and pointer encoding (`src/hardening.asm`, `src/secmem.asm`, `src/gpu.asm`):** Moved startup-resolved system DLL pointers (`webauthn.dll`, `tbs.dll`, `d3d11.dll`, `SetProcessMitigationPolicy`, `RtlGenRandom`) and secret-heap metadata (`sec_base`, `sec_cursor`, `g_ptr_cookie`, `g_tls_sstack`, `g_heap_cookie`) into a dedicated page-aligned `_ROINIT` PE section sealed `PAGE_READONLY` via `VirtualProtect` after startup (`hardening_seal_roinit`), and XOR-encoded dynamic function pointers with a hardware-seeded cookie (`ENCODE_PTR` / `DECODE_PTR`).
  - **Fail-closed `TPM + PIN` state rotation (`src/tpm.asm`):** Checked `NCryptDeleteKey` (`tpm_delete`) return status on the consumed TPM state slot during Mode 2 (`TPM + PIN`) pre-commit rotation and aborted unlock if key deletion fails, preventing stale-slot rollback if PCP key storage refuses deletion.
  - **Compositor and GDI secret-pixel hygiene (`src/gui.asm`, `src/hardening.asm`):** Registered `g_comp_bits` for zero-wiping across `vp_lock`, dialog switch/close (`gui_comp_wipe` / `gui_comp_free`), and crash panic (`crash_wipe_comp`), and replaced unguarded screen-DC reads with internal off-screen buffer sampling.
  - **Parser, vault, and file-I/O hardening (`src/vault.asm`, `src/zipimport.asm`, `src/zipexport.asm`, `src/fileio.asm`, `src/regcfg.asm`, `src/main.asm`, `src/totp.asm`):** Checked 64-bit size arithmetic across vault serialization and ZIP export/import, enforced strict `FILE_TYPE_DISK` / reparse-point checks and canonicalized path bounds across file operations, rejected embedded NULs in `REG_SZ` registry reads, scrubbed temporary buffers on all error exits, and gated CLI `seedtest` / diagnostic probes out of normal operation.
  - **Build, PE, and static-analysis gates (`tools/framecheck.py`, `tools/deadcode.py`, `tools/pe_normalise.py`, `build.cmd`):** Verified non-overlapping 32-byte x64 shadow home space across all 731 `FRAME_PROLOG` procedures (`framecheck.py --strict`), zero dead symbols in release (`deadcode.py`), and `_ROINIT` section flags in `pe_normalise.py`.

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
