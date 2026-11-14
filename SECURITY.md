# Security policy

Report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/xxtsxx/Vordr/security/advisories/new),
never in a public issue. Never attach a real vault, master password, or unredacted
screenshot or memory dump.

## What to include

- Concrete security impact and the preconditions/access an attacker requires.
- Minimal reproduction steps using a synthetic vault or archive.
- Tested release tag or commit hash, plus Windows and toolchain versions.
- Redacted diagnostic output or proof-of-concept script, if applicable.
- Contact details for coordinated follow-up.

Reports must be reviewed and submitted by a human operator; raw unverified automated
scanner output is not accepted.

## Response and coordinated disclosure

Vordr is a single-maintainer, pre-1.0 project:

- **Target acknowledgement**: within 7 days, followed by reproduction and severity triage.
  Vulnerabilities reachable without prior code execution on the host take top priority.
- **Recognition**: there is no paid bug bounty; reporter credit is published in the
  advisory and release notes unless anonymity is requested.
- **Disclosure window**: advisories publish when a fixed release ships or **90 days**
  after submission, whichever comes first, unless a longer window is mutually agreed.
  Reporters retain full freedom to publish after 90 days.

## Scope and trust model

This policy covers the Vordr executable, cryptographic and container implementations,
ZIP/JSON parsers, registry policy resolution, and build/MSI packaging scripts in this
repository.

Protected assets include master passwords, derived vault and attachment keys, decrypted
records, TOTP secrets, field history, and attached files. Vordr treats vault files,
native/ZIP imports, attachment filenames, registry values, `WM_COPYDATA` IPC payloads,
and command-line arguments as untrusted inputs. Clipboard copies and preview/downloaded
files intentionally cross into external OS/application boundaries; optional TPM unlock
additionally relies on local Windows Platform Crypto Provider and TPM 2.0 state.

### In scope

- Recovering vault plaintext or key material without the master password through an unintended path.
- Forging, splicing, or modifying a vault body, attachment section, save counter, or export without detection.
- Cryptographic or RNG implementation flaws, parameter-validation bypasses, or observable timing leaks on secret comparisons/key schedules.
- Memory-safety or Win64 ABI violations reachable via files, archives, attachments, IPC, registry data, or CLI arguments.
- Secret residue persisting past lock/close in application buffers, temporary preview files, clipboard timers, or crash handlers.
- Bypasses of documented policy controls (`HKLM\SOFTWARE\Vordr` fail-closed locks, read-only mode, `SecureUnlock` policy enforcement, modal auto-lock, or DLL search-order lockdown).
- Build or installer defects that break reproducibility, silently skip strict verification gates, or permit MSI downgrades/ACL weaknesses.

Evaluate findings against documented prerequisites: deliberate TPM convenience unlock
is an alternative local key-unwrapping path rather than a password bypass, whereas
transplanting a TPM blob across vaults or bypassing a locked `TpmRequireHello` /
`SecureUnlock` policy **is** in scope.

### Out of scope (architectural boundaries)

The following lie outside the protection boundary of a user-mode offline application:

- Kernel-mode compromise, or same-user/administrator code execution while the vault is unlocked.
- Physical hardware attacks (DMA, firmware implants, cold-boot RAM extraction) or unencrypted OS hibernation files (`hiberfil.sys`).
- Actions performed by someone physically operating an already-unlocked session or holding the master password.
- Simultaneous rollback of both the `.vordr` file and `HKCU\SOFTWARE\Vordr\Rollback`, or opening an older intact vault on a machine with no prior counter history.
- Offline brute-force guessing of a low-entropy master password.

Hardening improvements that raise attacker cost near these boundaries remain welcome.

## Supported versions and advisory process

Only the **latest published release** is supported; fixes are shipped forward rather
than backported. Check [Releases](https://github.com/xxtsxx/Vordr/releases) and
[RELEASES.md](docs/RELEASES.md) for current hashes and status.

When any defect in a published release exposes secrets, weakens cryptography, or risks
silent data loss—whether discovered externally or internally—the project:

1. Publishes a GitHub Security Advisory naming affected and fixed versions.
2. Requests a CVE when the flaw is exploitable by someone other than the vault owner.
3. Marks affected hashes directly in [RELEASES.md](docs/RELEASES.md) while retaining historical git tags for binary identification.
4. Ships a verified replacement release and submits updated artifacts per the [release checklist](docs/RELEASE_CHECKLIST.md).

Because Vordr contains no network updater or telemetry, users apply updates manually
(or via enterprise MSI / WinGet management).

## Verification and earned assurance

Every download can be checked against its published SHA-256 in [RELEASES.md](docs/RELEASES.md)
and rebuilt byte-for-byte from its git tag (`tools\verify_repro.ps1`). The repository
enforces a six-stage automated gate (`tests\run_all.cmd`): 12 fault-injection and
containment checks, 10 static source/ABI/resource/doc analyzers plus PE `LOAD_CONFIG`
verification, 23 startup known-answer suites, 35+ fuzz/round-trip/policy/TPM/GUI probes
with an independent zero-shared-code vault reader, 83 differential + published crypto
vectors, and MSI table/costing/downgrade verification.

See [TRUST.md](TRUST.md), [ARCHITECTURE.md](docs/ARCHITECTURE.md), [SECRETS.md](docs/SECRETS.md),
and [ASSURANCE.md](docs/ASSURANCE.md) for exact coverage and limits. No external third-party
audit is recorded in this repository, and passing test suites bound known failure
classes rather than proving the absence of all defects.
