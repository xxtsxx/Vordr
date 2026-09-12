# Security policy

Report suspected vulnerabilities through
[GitHub's private reporting form](https://github.com/xxtsxx/Vordr/security/advisories/new),
not a public issue. Never include a real vault, master password, or unredacted
secret-bearing screenshot or dump.

## What to include

- The impact and the access an attacker already needs.
- Reproduction steps using a synthetic vault.
- The tested release or commit and relevant Windows/toolchain details.
- Redacted diagnostic output, if useful.
- A way to contact you.

The maintainer currently accepts reports from humans. If an AI-assisted review
finds a significant issue, its human operator should submit the report.

## Response and disclosure

Vordr is a one-person, pre-1.0 project. The target is an acknowledgement within
about a week, followed by an initial severity and scope assessment after
reproduction. Critical issues reachable without already controlling the machine
take priority; lower-severity issues may wait.

There is no paid bug bounty. Reporter credit is offered in the advisory and
release notes unless anonymity is preferred.

Publication occurs when a fix ships or 90 days after the report, whichever comes
first. Any longer coordination period is negotiated with the reporter.
Reporters remain free to publish after 90 days.

## System and scope

The policy covers this repository's application, parsers, cryptographic
implementations, configuration handling, and build/package tooling.

Vordr is an offline Windows password manager. Its sensitive assets include
master passwords, derived keys, decrypted entries, TOTP material, history, and
attachments. Files, imports, registry values, and command-line arguments can
be attacker-controlled. Clipboard copies and preview files cross into other
applications; optional TPM unlock also depends on local Windows/TPM state.

The [architecture](docs/ARCHITECTURE.md) and
[memory reference](docs/SECRETS.md) describe implementation controls and known
limits. They are evidence for review, not proof that a report is safe to ignore.

## In scope

- Recovering vault contents or key material without the master password through
  an unintended path.
- Forging or tampering with a vault, export, or attachment without detection.
- Weaknesses in the cryptographic implementations or random generation,
  including timing side channels in comparisons or key handling.
- Memory-safety faults reachable through parsed files, attachments, registry
  values, or command-line input.
- Secrets persisting beyond their intended lifetime or leaking through memory,
  paging, hibernation, temporary files, the clipboard, or crash artifacts.
- Bypasses of documented policy controls, including HKLM settings, read-only
  mode, private-desktop behavior, and auto-lock.
- Supply-chain defects that cause the intended build to differ from its source.

Report impact with its actual prerequisites. Deliberate TPM convenience unlock
is not itself a password bypass; a flaw that exposes its wrapped key or bypasses
an intended control is a separate question. Similarly, a documented fallback
must not be represented as a control stronger than the implementation provides.

## Existing exclusions and limits

The following remain outside the project's protection model:

- A compromised kernel, or administrator-level code while the vault is unlocked.
- Hardware attacks such as DMA, firmware implants, and cold boot.
- Access available to someone physically using the unlocked vault or already
  holding the master password.
- Rolling back both the vault and its HKCU save-counter mirror, or restoring an
  older vault on a machine without matching history.
- Offline guessing of a weak master password.

Suggestions that raise the cost of those attacks are welcome as hardening
improvements. These exclusions do not dismiss an independently reachable parser,
cryptographic, or policy-control defect.

## Supported versions

Only the newest release is supported. There are no backported fixes to older
versions. Use the [release page](https://github.com/xxtsxx/Vordr/releases) to
identify the newest published version and the [release records](docs/RELEASES.md)
to check its hash and known status.

## Disclosure of defects in released versions

When a defect in a published version exposes vault contents, weakens encryption,
or loses data, the project follows the same disclosure process whether the
maintainer or an outside reporter found it:

1. Publish a GitHub Security Advisory naming affected and fixed versions.
2. Request a CVE through the advisory when someone other than the vault owner
   can exploit the issue.
3. Mark affected builds in [RELEASES.md](docs/RELEASES.md), beside their hashes.
4. Ship a new release; retain old tags so existing binaries remain identifiable.

Vordr has no automatic updater or telemetry. Users must obtain updates
themselves. Package-manager or enterprise inventory coverage depends on how a
copy was installed and on those services; it is not a promise that every user
will receive a warning. The MSI provides an installed-product identity that a
portable copy does not.

Release preparation also includes antivirus-vendor submissions. See the
[release checklist](docs/RELEASE_CHECKLIST.md).

## Verification and assurance

Compare a download with its published executable hash and, where possible,
rebuild the exact tag with a matching toolchain. A mismatch requires
investigation; it does not by itself identify the cause or prove maliciousness.

The repository includes startup known-answer tests, a Python crypto
cross-check, fault injection, static source checkers, and persistence tests.
Their coverage and skip conditions are described in
[ASSURANCE.md](docs/ASSURANCE.md).

No independent external security review is recorded in this repository.
Passing tests and reproducible builds do not establish the absence of
vulnerabilities.
