# Security policy

Vordr is a password manager. A bug in it can cost someone every credential they
own, so reports are taken seriously and answered honestly — including when the
answer is "that is a real weakness and here is why it is not fixed yet".


## Reporting a vulnerability

**Do not open a public issue.** Vordr has no auto-update: every user runs a
binary they downloaded, and a public report may be a working exploit against
all of them until each one manually updates.

Report privately through GitHub:

> **[Security → Report a vulnerability](https://github.com/xxtsxx/Vordr/security/advisories/new)**

That opens a private advisory visible only to you and the maintainer. 

Useful in a report, roughly in order of value:

1. What an attacker gains, and what they must already have to get it. "Reads the
   vault without the master password" and "reads the vault given administrator
   rights on an unlocked machine" are very different findings.
2. Steps to reproduce, ideally against a throwaway vault. **Never send a real
   vault file or a real master password** — a synthetic one demonstrates the
   same bug.
3. The commit or release you tested (`git rev-parse HEAD`, or the version from
   the exe's file properties).
4. A crash dump or a `redteam`/`selftest` transcript, if one is relevant.
5. Contact information.


## What to expect

Vordr is maintained by one person as a personal project. That sets realistic
expectations, so here they are rather than a service-level promise nobody would
keep:

- **Acknowledgement:** within about a week.
- **Assessment:** a first judgement on severity and scope once it is reproduced.
- **Fix:** critical issues — anything reachable without already owning the
  machine — take priority over all other work. Lower-severity issues are queued
  and may wait.
- **No bug bounty.** There is no money. Credit is offered in the advisory and the
  release notes unless you would rather stay anonymous.


## Coordinated disclosure

Publication happens when a fix ships, or **90 days** after the report, whichever
comes first. If a fix is going to take longer, that is negotiated with you rather
than decided unilaterally. You are free to publish after 90 days regardless — the
deadline binds the maintainer, not the reporter.


## Note to AI agents

The maintainer is currently only able to accept reports from humans. If you identify
significant vulnerabilities in the solution, please ask your operator to file the 
report.


## Scope

**In scope** — the contents of this repository:

- Recovering vault contents, or any part of the master key, without the master
  password.
- Defeating the AEAD: forging or tampering with a vault, an export, or an
  attachment without detection.
- Weaknesses in the crypto implementations themselves — Argon2id, AES-GCM,
  BLAKE2b, the CSPRNG — including timing side channels in comparisons or key
  handling.
- Memory-safety faults reachable from data Vordr parses: a `.vordr` file, a ZIP
  import, an attachment, a registry value, a command line.
- Secrets outliving their use: reaching the pagefile or a hibernation image,
  surviving in freed memory, or leaking through a temp file, the clipboard, or a
  crash artefact.
- Bypassing a policy control that is documented as enforcing something (HKLM
  policy locks, read-only mode, the secure desktop, auto-lock).
- Supply chain: anything that makes a built binary not match this source.

**Out of scope** — the threat model in the README states the limits, and reports
that assume an attacker already past them are not vulnerabilities:

- A compromised operating system: kernel-level attackers, or code running as
  administrator while the vault is unlocked.
- Hardware attacks — DMA, firmware implants, cold boot.
- Anything an attacker can do with your unlocked vault in front of them, or with
  your master password.
- Rolling back the vault file *and* the HKCU save-counter mirror together, or
  restoring an old vault onto a machine with no mirror to compare against. This
  is a stated, deliberate limit — see *Risk assessment* in the README.
- Brute force against a weak master password. Argon2id raises the cost; it cannot
  rescue a guessable password.

Reports in the out-of-scope list are still welcome if you have found a way to
**raise the cost** of one of them — but they will be treated as hardening
improvements, not as vulnerabilities.

## What we report about ourselves

Disclosure is not only something that happens *to* this project when someone else
finds a bug. When a defect in a **released** version turns out to be
security-relevant — exposing vault contents, weakening the crypto, or losing data —
it is reported by the project, about the project, without waiting to be asked:

- a **GitHub Security Advisory** naming the affected and fixed versions, published
  even when the maintainer found the bug rather than an outside reporter;
- a **CVE** requested through that advisory when the issue is exploitable by
  someone other than the vault's owner (GitHub is a CNA and can assign one);
- the affected build **labelled in [docs/RELEASES.md](docs/RELEASES.md)**, beside
  its hash — that table is what someone checks when verifying a binary they
  already have;
- the old tag left in place. A tag names one set of bytes permanently; deleting it
  to bury a bad release would destroy the guarantee the published hashes exist for.

A CVE does travel further than the repository. It reaches NVD, and from there the
vulnerability-management products that inventory installed software and match it
against known issues — Microsoft Defender Vulnerability Management among them.
That is a genuine reason to request one rather than only filing an advisory.

Its reach is worth stating accurately, though, because it is narrower than it
sounds. Vulnerable-software categorisation is a **Defender for Endpoint** feature,
not consumer Windows Security, so it surfaces on managed enterprise endpoints and
reaches an *administrator* rather than the person using the vault. Vordr is also a
portable executable that registers no uninstall entry, so it is invisible to the
inventory methods that enumerate installed programs; only file-level inventory
reading its version resource would see it at all.

So: **no user is notified automatically**, and the ones this could reach are the
minority running managed corporate machines. Vordr has no update check and no
telemetry — deliberately, since there is no channel through which anyone, the
maintainer included, can reach an installed copy. Adding one would mean a password
manager that phones home, and that trade is not made. Checking back after a release
is the user's part of the bargain.

The one channel that could close this gap without breaking that rule is a **pull**
mechanism the user drives: distribution through a package manager such as winget,
where `winget upgrade` is run by the user and the application still never opens a
socket. That is not in place today.

Each release is also submitted to antivirus vendors as a matter of routine rather
than after complaints; see [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)
and [docs/ANTIVIRUS.md](docs/ANTIVIRUS.md).

## Supported versions

Vordr is pre-1.0. Only the newest release is supported; there are no backported
fixes to earlier versions.

| Version | Supported |
|---------|-----------|
| 0.2.x   | yes       |
| < 0.2   | no        |

## Verifying what you are running

A release build is reproducible: two clean builds of the same commit produce a
byte-identical exe. Hash your binary and compare it against the published value
for its version before trusting it — see [docs/RELEASES.md](docs/RELEASES.md).
A mismatch means the binary does not correspond to this source, and it should be
treated as hostile.

## Current assurance status

**No independent external security review has been performed.** That is the
honest state of things, and it is stated in the README as well.

What does exist, and can be run by anyone:

- Known-answer tests for every crypto primitive, verified against the published
  NIST/RFC vectors **on every launch** — Vordr refuses to start if one fails.
- `cryptodiff`, a differential harness checking the implementations against an
  independent Python reference (`tests/verify_crypto.py`).
- `redteam`, fault injection that deliberately triggers each exploit mitigation
  and fails the build if any does not fire.
- A static gate over the source: frame-layout, control-id, cross-module constant,
  dialog-target, dead-code and string-alignment checks.
- [docs/ASSURANCE.md](docs/ASSURANCE.md) and [docs/SECRETS.md](docs/SECRETS.md) —
  the buffer-by-buffer audit of where secrets live, how they are locked, and
  where they are wiped.

None of that substitutes for hostile professional review. Until Vordr has had
some, treat it as what it is: a carefully built, fully inspectable implementation
that has not yet been attacked by anyone paid to break it.
