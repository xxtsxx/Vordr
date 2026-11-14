# Documentation

[Project overview](../README.md)

Technical and operational references for the current source tree. Published release
hashes in [RELEASES.md](RELEASES.md) are immutable historical records matched to their
exact git tags.

## Trust, architecture, and assurance

- [Why Vordr earns trust](TRUST.md): architectural rationale, lifecycle trust boundaries, defense-in-depth controls, runnable verification proof, and honest limits.
- [Architecture](ARCHITECTURE.md): module design, why each trust boundary is structured this way, unlock/save state machines, cryptography, and runtime hardening.
- [Assurance and verification](ASSURANCE.md): the six-stage automated gate, independent vault and crypto verifiers, 10 static analyzers, fuzz/regression probes, and explicit test limits.
- [Visual verification map](assurance.html): self-contained offline HTML overview of how the six verification stages and trust boundaries fit together.
- [Secret memory](SECRETS.md): `VirtualLock` static/dynamic buffer inventory, zeroing lifecycles, clipboard/preview containment, and constant-time comparison paths.
- [Vault file format](formats.md): complete version-2 wire specification—header AAD, Argon2id/AES-256-GCM parameters, record encoding, per-attachment AEAD, and BLAKE2b-256 trailer.
- [Security policy](../SECURITY.md): threat model, in-scope vs OS/hardware boundaries, private vulnerability reporting, and 90-day disclosure policy.

## Operation and enterprise deployment

- [User guide](USER_GUIDE.md): installation, vault creation, entries, TOTP, safe attachment previews, backups, and native/ZIP import-export.
- [Deployment and policy](DEPLOYMENT.md): per-machine MSI properties, fail-closed `HKLM\SOFTWARE\Vordr` policy precedence, folder-template path pinning, upgrades, and downgrade protection.
- [Antivirus warnings](ANTIVIRUS.md): cryptographic hash verification, SmartScreen vs malware verdicts, and vendor false-positive submission.
- [Release hashes](RELEASES.md): published SHA-256 records, WinGet provenance, and byte-for-byte reproducible rebuild instructions.

## Engineering and release maintenance

- [Development](DEVELOPMENT.md): x64 toolchain, build modes, isolated test harnesses (`HKCU` remapping), and change discipline.
- [Settings screen design](SETTINGS_DESIGN.md): `DLG_SETTINGS` window ownership and table-driven policy/preference persistence.
- [System items](SYSITEM_DESIGN.md): encrypted in-body vault metadata and physical-vs-visible index invariants.
- [Release checklist](RELEASE_CHECKLIST.md): gate execution, `verify_repro.ps1`, MSI costing/VM checks, WinGet manifests, and vendor submissions.

Keep configuration defaults canonical in [DEPLOYMENT.md](DEPLOYMENT.md#properties) and
wire-level constants canonical in [formats.md](formats.md); update code, tests, and
documentation together in the same change.
