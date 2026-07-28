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
