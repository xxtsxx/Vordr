# Vordr

An offline password manager for Windows x64, written in 64-bit MASM assembly.
The name comes from Old Norse *vörðr*: watchman or guardian.

Vordr stores passwords, TOTP keys, notes, custom fields, and encrypted file attachments in a single authenticated `.vordr` container. It ships as one native executable with **zero network stack, zero telemetry, zero automatic updater, and zero third-party runtime libraries**—linking exclusively against `System32` Windows DLLs without a C runtime, .NET, or Electron.

## Why trust is earned by design

Security software earns trust through verifiable engineering choices, explicit boundaries, and repeatable proof rather than promises:

| Architectural choice | Why it is designed this way | How it is verified |
|---|---|---|
| **Zero-dependency native binary** | Eliminates transitive package supply-chain exposure, runtime JIT/GC copies of secrets, and background network egress; keeps the entire codebase small enough to audit line by line. | [`pe_normalise.py`](tools/pe_normalise.py) enforces `LOAD_CONFIG.DependentLoadFlags = 0x0800` (`System32`-only DLL loading); [`verify_repro.ps1`](tools/verify_repro.ps1) proves two clean builds produce byte-identical SHA-256 outputs. |
| **Key-committing AEAD + full-file MAC** | Derives a 256-bit key via Argon2id (RFC 9106; default `512 MiB`, `t=3`, `p=1`), encrypts the record body and each attachment with AES-256-GCM under fresh 96-bit random nonces, and authenticates the entire file image plus a 64-bit monotonic save counter with BLAKE2b-256. | [`verify_vault.py`](tests/verify_vault.py) decrypts and tamper-tests real `.vordr` files using a standalone Python RFC 9106 + AES-256-GCM reader built strictly from [`docs/formats.md`](docs/formats.md), sharing zero code with Vordr. |
| **Fail-closed startup & differential crypto** | Every launch runs a mandatory 23-suite known-answer self-test gate before opening any window or file; any primitive mismatch terminates immediately. | [`verify_crypto.py`](tests/verify_crypto.py) cross-checks 58 outputs against independent reference implementations and 25 published FIPS/NIST/RFC vectors. |
| **Defense-in-depth memory & OS isolation** | Pins static secret buffers (`VirtualLock`) and decrypted arenas (`secmem_alloc`), enforces per-thread shadow stacks, stack/heap canaries, CET compatibility, read-only IAT, isolated private-desktop password entry, and a strict safe-preview allowlist with owner-only temp ACLs and Mark of the Web. | 10 static assembly/ABI/resource analyzers gated by [`floors.py`](tools/floors.py), 12 fault-injection & containment cases ([`redteam.py`](tests/redteam.py)), 35+ binary fuzz/round-trip probes, and an 86-check isolated Win32 GUI suite ([`guitest.ps1`](tests/guitest.ps1)). |

## Start here

Install the published MSI through WinGet (requires administrator approval; WinGet downloads the installer while Vordr itself remains offline):

```powershell
winget install --id ThomasSmistad.Vordr --exact --source winget
```

1. Install via WinGet, or download the portable `vordr.exe` or MSI from [Releases](https://github.com/xxtsxx/Vordr/releases).
2. [Verify the executable SHA-256](docs/RELEASES.md#verify-a-download) before first launch.
3. Launch `vordr.exe`, open Vordr from the Windows notification area, and create a vault.
4. Choose a high-entropy master password and keep a secure offline record—Vordr has no password-reset or escrow service.
5. Store an independent encrypted backup of your `.vordr` file and verify that it opens cleanly.

Update an installed copy manually when a new release is published:

```powershell
winget upgrade --id ThomasSmistad.Vordr --exact --source winget
```

See [update instructions](docs/USER_GUIDE.md#updates) for backups, portable copies, and policy-managed deployments, and [antivirus verification](docs/ANTIVIRUS.md) if SmartScreen or an endpoint scanner flags an unsigned binary.

## Capabilities

- **Structured records**: usernames, secrets, URLs, notes, RFC 6238 TOTP codes, custom-labeled fields, custom icons, favorites, encrypted field history, and Trash.
- **Encrypted attachments**: up to 24 files (`256 MiB` each) per entry, each sealed under its own random AES-256-GCM key and nonce; preview is restricted to a strict allowlist (`.txt`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.webp`, `.pdf`) inside owner-only temp folders with fail-closed Mark of the Web (`ZoneId=3`).
- **Password generator**: random character sets, EFF-style passphrases, pronounceable strings, PINs, and hex tokens (`BCryptGenRandom` + optional `RDSEED` mixing).
- **Session & desktop protection**: sequence-checked clipboard auto-clear (persisting across dialog/window close via the tray), idle auto-lock (closing open modals first), lock on Windows session lock, optional isolated private-desktop password entry, and optional RSA-2048 TPM convenience unlock bound to the vault salt and policy state.
- **Interoperability & enterprise policy**: selective `.vordr` export/merge, WinZip AE-2 encrypted `.zip` import/export, and fail-closed `HKLM\SOFTWARE\Vordr` administrator policy precedence.

## Explicit security boundaries

Earned trust requires stating exact boundaries alongside protections. Vordr is verified by deterministic tests, fuzzers, and independent reference readers, though no external third-party audit is recorded in this repository:

- **Master password entropy**: Argon2id raises the cost of each guess (`512 MiB`, `3` passes by default), but an attacker holding a copy of the vault file can still brute-force a weak password offline.
- **Hostile local OS or hardware**: While unlocked, decrypted data resides in user-mode memory. `VirtualLock`, lock-time zeroing, and private-desktop prompts reduce exposure to paging and unprivileged hooks, but cannot defend against a compromised kernel, local administrator, DMA/cold-boot attack, or hibernation file (`hiberfil.sys` without full-disk encryption).
- **Plaintext egress**: Copying to the clipboard, revealing on screen, or opening/saving an attachment deliberately hands plaintext to Windows or another application whose own caches Vordr does not control.
- **TPM convenience unlock**: Wraps the vault key in hardware as a local convenience shortcut—not a second factor or a substitute for retaining the master password.
- **Anti-rollback mirror**: The `HKCU\SOFTWARE\Vordr\Rollback` high-water counter reliably flags accidental cloud-sync rollbacks on the same machine, whereas restoring both the vault and registry state (or opening an older copy on a fresh machine) has no prior counter to compare against.

See [security boundaries](docs/ARCHITECTURE.md#security-boundaries), [secret memory](docs/SECRETS.md), and the [security policy](SECURITY.md) for full details.

## Build and verify from source

Requires Windows x64 with Visual Studio Build Tools (`ml64.exe`, `link.exe`), the Windows 10/11 SDK (`rc.exe`), and Python 3 on `PATH`. From an **x64 Native Tools Command Prompt**:

```bat
build.cmd release strict
bin\vordr.exe selftest
python tests\verify_crypto.py --exe bin\vordr.exe
```

CPU requirements: AES-NI, PCLMULQDQ, SSE4.1, and SHA-NI (checked fail-closed at startup); AVX2 (gated on `OSXSAVE` + `XCR0`) and `RDSEED` are optional. Read the [development guide](docs/DEVELOPMENT.md#full-test-gate-read-before-running) before running `tests\run_all.cmd`, which terminates running `vordr.exe` instances and overwrites `bin\`.

## Documentation

| Goal | Reference |
|---|---|
| Create vaults, manage entries, and protect backups | [User guide](docs/USER_GUIDE.md) |
| Deploy MSI packages or enforce `HKLM` policy | [Deployment & policy](docs/DEPLOYMENT.md) |
| Inspect module design, data flow, and trust boundaries | [Architecture](docs/ARCHITECTURE.md) · [File format](docs/formats.md) |
| Audit secret lifetimes, `VirtualLock`, and wipe paths | [Secret memory](docs/SECRETS.md) |
| Review automated gates, KATs, fuzzers, and limits | [Assurance](docs/ASSURANCE.md) · [Visual map](docs/assurance.html) |
| Build, modify, or reproduce binaries byte-for-byte | [Development](docs/DEVELOPMENT.md) · [Release hashes](docs/RELEASES.md) · [Checklist](docs/RELEASE_CHECKLIST.md) |
| Browse all technical and design references | [Documentation index](docs/README.md) |

## Report a problem

- **Bugs**: [Open a GitHub issue](https://github.com/xxtsxx/Vordr/issues) using synthetic data and redacted logs/screenshots.
- **Security vulnerabilities**: Submit privately via [GitHub Security Advisories](https://github.com/xxtsxx/Vordr/security/advisories/new)—never in a public issue, and never attach a real vault or password.

## License

[MIT](LICENSE.txt).
