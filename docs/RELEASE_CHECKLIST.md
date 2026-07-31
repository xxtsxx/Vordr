# Release checklist

Every release runs through this list in order. It exists because two of the steps
are easy to skip and expensive to skip: telling antivirus vendors about a new
binary, and telling users when a version they already have turns out to be unsafe.

Vordr has **no auto-update and no telemetry**. Nothing reaches out to a user after
they download a build. That is a deliberate property — there is no channel for
anyone, including us, to push code to them — and it means these notification steps
are very nearly the only notification there will be. A CVE is the one signal that
travels on its own, and only as far as §4 describes.

## 1. Before tagging

- [ ] `tests\run_all.cmd` — all five stages pass.
- [ ] `build.cmd release` twice from a clean tree (`obj\` and `bin\` removed
      between), hashes compared, byte-identical.
- [ ] `selftest` passes on the exact binary being published.
- [ ] The version resource in `vordr.rc` matches the tag being cut. A binary whose
      properties disagree with its tag defeats the published-hash scheme.
- [ ] Anything fixed since the last release that affected a *published* version is
      recorded in §4 below.

## 2. Tag and publish

- [ ] Annotated tag on the built commit (`git tag -a vX.Y.Z <commit>`).
- [ ] Row added to [RELEASES.md](RELEASES.md): version, commit, SHA-256.
- [ ] Previous release marked superseded there if it carries known defects.

## 3. Self-report the build to antivirus vendors

**Do this at every release, before or immediately after publishing the binary —
not after a user complains.**

Vordr is unsigned, has near-zero prevalence, and (being a password manager)
registers a global hotkey, switches desktops and uses the clipboard. Machine
learning classifiers score that as malware; Defender has flagged a release as
`Trojan:Win32/Wacatac.B!ml` already. See [ANTIVIRUS.md](ANTIVIRUS.md).

**A clearance applies to one hash only.** Every release is a new binary and starts
from scratch, which is exactly why this is a per-release step and not a one-off.

- [ ] **Microsoft** — <https://www.microsoft.com/en-us/wdsi/filesubmission>,
      submitting as *software developer*. This is the one that matters most:
      Defender and SmartScreen are what most Windows users meet. Typical
      turnaround is one to three days.
- [ ] **Upload to VirusTotal.** Not a vendor, but the sample is distributed to the
      engines that participate, so it seeds many vendors at once and gives a public
      record of the scan for the published hash.
- [ ] **Any vendor that has flagged a previous release** — most run a
      false-positive submission form or a `samples@` address; check the vendor's
      current page rather than trusting a URL cached here, as these move.
- [ ] Record the date and outcome in the release notes so the next person can see
      which vendors have already cleared the project.

If a vendor rejects the submission or does not respond, say so publicly in the
release notes rather than quietly leaving users with a scary warning.

## 4. When a released version turns out to be vulnerable

If a defect in a **published** version is security-relevant — anything that could
expose vault contents, weaken the crypto, or lose data — it gets reported by the
project, about the project, without waiting for anyone to ask.

- [ ] **Publish a GitHub Security Advisory** on the repository, naming the exact
      affected versions and the fixed version. Do this even when the finding came
      from the maintainer rather than an outside reporter: an advisory is how a
      version already in someone's hands gets flagged, and it is the only
      machine-readable signal this project emits.
- [ ] **Request a CVE** through the advisory when the issue is exploitable by
      someone other than the vault's owner. GitHub is a CNA and can assign one
      directly from the advisory, at no cost. This is the step that travels beyond
      the repository: a CVE reaches NVD and from there the vulnerability-management
      products that match installed software against known issues. Keep the product
      naming in `vordr.rc` (`ProductName`, `ProductVersion`, `CompanyName`) stable
      across releases — that version resource is what file-level inventory matches
      on, and a portable exe with no uninstall entry has nothing else to be
      recognised by. Do not expect it to reach consumers: that categorisation is a
      Defender for Endpoint feature and surfaces to enterprise administrators.
- [ ] **Mark the version in [RELEASES.md](RELEASES.md)** — the hash table is what
      someone checks when verifying a binary they already downloaded, so a
      vulnerable build must be labelled *there*, next to its hash, not only in an
      advisory they may never see.
- [ ] **Ship the fix as a new release** and mark the old one superseded.
- [ ] Do **not** silently delete or repoint the old tag. A tag names one set of
      bytes permanently; removing it to hide a bad release destroys the very
      guarantee the published hashes exist to provide, and leaves anyone holding
      that binary unable to find out what is wrong with it.

The honest limit: users who never revisit the repository will not learn any of
this. A CVE does travel further — into NVD, and from there into the
vulnerability-management tools that inventory installed software — but that path
surfaces to enterprise administrators running Defender for Endpoint, not to the
individual who downloaded a portable exe. Consumer Windows Security has no
software inventory and will never raise it.

Without an update check there is no way to reach the rest, and adding one would
mean a password manager that phones home — a trade this project does not make.
The one channel that would close the gap without breaking that rule is a **pull**
mechanism the user drives, such as distribution through winget, where
`winget upgrade` is run by the user and Vordr still never opens a socket. Not in
place today; worth considering, and it would help the prevalence problem in §3 at
the same time.

Saying all of this plainly is part of the disclosure, not a footnote to it.
