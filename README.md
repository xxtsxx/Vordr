# Vordr

An offline password manager for Windows x64, written in 64-bit assembly.
The name comes from Old Norse *vörðr*: watchman or guardian.

Vordr stores passwords, notes, TOTP keys, custom fields, and attachments in a
single encrypted `.vordr` file. The application has no network client, telemetry,
or automatic updater. It runs as one executable, using Windows system DLLs
without a C runtime, .NET, or bundled third-party libraries. An optional MSI
provides installation, a Start Menu shortcut, and file association.

## Start here

1. Download a build from [Releases](https://github.com/xxtsxx/Vordr/releases).
2. [Verify the executable](docs/RELEASES.md#verify-a-download) before using it.
3. Run `vordr.exe`, open Vordr from the notification area, and create a vault.
4. Choose a strong, unique master password and keep a secure record of it.
   Vordr has no password-reset or recovery service.
5. Back up the encrypted vault and confirm you can open the backup.

Read the [user guide](docs/USER_GUIDE.md) for everyday use, backups, TPM unlock,
and import/export. If antivirus software flags a download, follow the
[verification and reporting guide](docs/ANTIVIRUS.md); do not disable protection
or add a blanket exclusion.

## What it does

- Flexible entries with passwords, TOTP codes, notes, custom labels, and files.
- Search, favorites, custom icons, password history, and a trash view.
- A password generator with random, passphrase, pronounceable, PIN, and hex styles.
- Clipboard clearing, idle locking, and locking with the Windows session.
- Optional private-desktop password entry and TPM convenience unlock.
- Selective `.vordr` export and encrypted ZIP import/export.
- Registry-based user preferences and administrator policy.

Vordr uses AES-256-GCM for vault encryption and Argon2id for password-based key
derivation (default: 512 MiB, three passes, one lane). Each save uses a fresh
random body nonce. The [architecture guide](docs/ARCHITECTURE.md) explains the
data flow; the [format reference](docs/formats.md) defines the bytes on disk.

<a id="security-limits"></a>

## Risk assessment

The [complete risk assessment](docs/RISK_ASSESSMENT.md) is the starting point
for security review. It brings the threat model, implemented protections,
residual risks, evidence gaps, and deployment decisions together in one place.
The main conclusions are summarized below.

Vordr implements standard cryptographic algorithms itself. Its tests check
known vectors, selected failure paths, and persistence behavior; they are not a
proof that the application is free of vulnerabilities. No independent external
security review is recorded in this repository.

The main limits are important before entrusting it with secrets:

- A weak master password remains vulnerable to offline guessing.
- An unlocked vault is exposed to someone who controls the computer. Vordr does
  not protect against a hostile kernel, administrator, or hardware attacker.
- Copying, revealing, downloading, or previewing a secret exposes plaintext
  outside the encrypted file. Cleanup is best-effort, particularly after a crash.
- TPM unlock is a local convenience, not a second factor or a portable recovery
  method. Keep the master password even if you rarely type it.
- Rollback warnings depend on this machine's registry history. Restoring both
  the vault and that history, or opening an old copy on a new machine, can evade them.
- Sync and rotating backups do not replace an independent, tested backup.

See [security boundaries](docs/ARCHITECTURE.md#security-boundaries),
[memory handling](docs/SECRETS.md), and the [security policy](SECURITY.md).

## Build and test

Use Windows x64 with Visual Studio's MASM/linker, a Windows SDK, and Python 3.
From an **x64 Native Tools Command Prompt** in the repository:

```bat
build.cmd release strict
```

The executable requires AES-NI, PCLMULQDQ, SSE4.1, and SHA-NI. AVX2 and RDSEED
are optional. Password-based unlock also needs memory for the Argon2 arena.

The [development guide](docs/DEVELOPMENT.md) covers build variants and tests.
Read its test-safety warning before running `tests\run_all.cmd`: the full gate
terminates running Vordr processes and replaces build outputs.

## Documentation

| I want to… | Read |
|---|---|
| Use Vordr and protect my backups | [User guide](docs/USER_GUIDE.md) |
| Install or enforce policy across machines | [Deployment](docs/DEPLOYMENT.md) |
| Understand the implementation | [Architecture](docs/ARCHITECTURE.md) |
| Assess security risks and deployment suitability | [Risk assessment](docs/RISK_ASSESSMENT.md) |
| Build, change, or test the code | [Development](docs/DEVELOPMENT.md) |
| Evaluate the evidence and limitations | [Assurance](docs/ASSURANCE.md) |
| Verify a release or prepare a new one | [Release hashes](docs/RELEASES.md) · [Checklist](docs/RELEASE_CHECKLIST.md) |
| Find a reference or design decision | [Documentation index](docs/README.md) |

## Report a problem

For ordinary bugs, [open an issue](https://github.com/xxtsxx/Vordr/issues).
Use synthetic data and redact screenshots and logs.

For vulnerabilities, use the
[private reporting form](https://github.com/xxtsxx/Vordr/security/advisories/new),
not a public issue. Never send a real vault or master password.

## License

[MIT](LICENSE.txt).
