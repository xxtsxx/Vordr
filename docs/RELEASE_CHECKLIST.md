# Release checklist

Every release runs through this list in order. It exists because two of the steps
are easy to skip and expensive to skip: telling antivirus vendors about a new
binary, and telling users when a version they already have turns out to be unsafe.

Vordr has **no auto-update and no telemetry**. Nothing reaches out to a user after
they download a build. That is a deliberate property — there is no channel for
anyone, including us, to push code to them — and it means these notification steps
are very nearly the only notification there will be. A CVE is the one signal that
travels on its own, and only as far as §5 describes.

## 1. Before tagging

- [ ] `tests\run_all.cmd` — all six stages pass (the sixth builds and verifies
      the installer; see §2).
- [ ] `build.cmd release` twice from a clean tree (`obj\` and `bin\` removed
      between), hashes compared, byte-identical.
- [ ] `selftest` passes on the exact binary being published.
- [ ] The version resource in `vordr.rc` matches the tag being cut. A binary whose
      properties disagree with its tag defeats the published-hash scheme.
- [ ] Anything fixed since the last release that affected a *published* version is
      recorded in §5 below.

## 2. Build and check the installer

The MSI is optional to ship but not optional to check: it is the only artefact
that writes to HKLM and to the shell's class registry, and the only one whose
mistakes are invisible until someone installs it. See
[DEPLOYMENT.md](DEPLOYMENT.md) for what it registers and why.

**The first two boxes below are now the gate's sixth stage** — `run_all.cmd`
builds the package from the restored release binary and runs the verifier on
every push. Tick them by reading the gate output rather than by repeating the
commands. The rest of this section is what the gate *cannot* do: it will not
install anything, so the upgrade and uninstall checks stay manual and stay the
ones that matter.

- [ ] Build it from the **exact** binary being published, not a rebuilt one.
      `make_msi.ps1` takes the version from the exe's own resource, so a stale
      `bin\vordr.exe` yields a package correctly labelled vX.Y.Z and wrapped
      around the wrong bytes.

      ```
      powershell -ExecutionPolicy Bypass -File tools\make_msi.ps1
      ```

- [ ] `tools\verify_msi.ps1 -Msi bin\vordr-X.Y.Z.msi` exits 0. It runs the
      package's costing through Windows Installer rather than only reading rows
      back, so it catches the silent ones: a property that never reaches the elevated half of
      the install, a component that writes into `WOW6432Node` where the 64-bit
      exe never looks, a policy value written with no condition, an unquoted `%1`
      in the open command.
- [ ] **Install over the previous release**, not onto a clean machine, and
      confirm exactly one entry remains in Add/Remove Programs.

      This is the step that earns its place. Two upgrade faults have shipped past
      inspection here — `Upgrade.Attributes` using `0x1` where the Inclusive bits
      are `0x100`/`0x200`, and `FindRelatedProducts` missing from
      `InstallUISequence` so the server skipped it as *"already done on client
      side"* and it ran nowhere. Both produced logs that read as success, both
      left two products registered, and `msiexec /a` cannot see either. Only a
      real install found them.

- [ ] Uninstall and confirm what is gone and what is not: the exe, the shortcut,
      the `.vordr` class and the policy values go; **the vault and `HKCU` stay**.
      That half of the check matters most — an installer that tidies away a
      password manager's data on removal destroys the user's secrets, and MSI
      makes it a one-row mistake.
- [ ] Confirm the installed `%ProgramFiles%\Vordr\vordr.exe` hashes to the
      SHA-256 being published. The cab is built from a copy; this proves the copy
      is the same file.
- [ ] Record the ProductCode in the release notes. The **UpgradeCode never
      changes** — it is the only thing that lets a future package recognise this
      one instead of installing beside it.

Two notes on running these by hand. Installing needs elevation, and `/qn`
suppresses the UI that a UAC prompt would appear in, so a silent install from a
normal shell fails with error 1925 and prints nothing at all — drop `/qn` and
msiexec prompts. And a per-user association in `HKCU\Software\Classes` shadows
the per-machine one, so clear any test association before judging the shell
behaviour.

## 3. Tag and publish

- [ ] Annotated tag on the built commit (`git tag -a vX.Y.Z <commit>`).
- [ ] Row added to [RELEASES.md](RELEASES.md): version, commit, SHA-256.
- [ ] Previous release marked superseded there if it carries known defects.
- [ ] If the MSI is published alongside the exe, its hash is listed as *this
      file*, never as something to check a rebuild against. The exe is
      reproducible; the MSI deliberately is not — ProductCode and PackageCode are
      fresh GUIDs on every build, so two packages of the same commit differ by
      design. The reproducible-build guarantee covers the exe, and the MSI's hash
      only tells someone their download arrived intact.
- [ ] **winget manifest**, once the release assets are uploaded and their URLs
      are final:

      ```
      powershell -ExecutionPolicy Bypass -File tools\make_winget.ps1 -Url <asset URL>
      winget validate --manifest bin\winget\<version>
      ```

      then a PR to `microsoft/winget-pkgs`. Every release needs a new manifest —
      version, URL, hash and ProductCode all change together, and the ProductCode
      is what winget matches an installed copy on, so a stale one means "not
      installed" forever.

      This is the one distribution channel that fits the project's constraints.
      It earns the prevalence that §4 exists to work around, and `winget upgrade`
      gives users a way to *pull* a fix — the gap §5 admits to — without Vordr
      ever opening a socket.

## 4. Self-report the build to antivirus vendors

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
- [ ] **Submit the MSI too, if one is published.** It is a separate binary with
      its own hash and the same near-zero prevalence, and clearing the exe does
      nothing for it. An installer that writes to HKLM and registers a file type
      is, if anything, the more suspicious-looking of the two.
- [ ] **Any vendor that has flagged a previous release** — most run a
      false-positive submission form or a `samples@` address; check the vendor's
      current page rather than trusting a URL cached here, as these move.
- [ ] Record the date and outcome in the release notes so the next person can see
      which vendors have already cleared the project.

If a vendor rejects the submission or does not respond, say so publicly in the
release notes rather than quietly leaving users with a scary warning.

## 5. When a released version turns out to be vulnerable

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
      on, and a portable exe unzipped into a folder has nothing else to be
      recognised by. An MSI install is the exception worth knowing about: it
      registers ProductName and ProductVersion in Add/Remove Programs, which is
      the entry software inventory reads first, so machines installed that way are
      the ones a CVE can actually reach. Do not expect it to reach consumers
      either way: that categorisation is a Defender for Endpoint feature and
      surfaces to enterprise administrators.
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
The one channel that closes the gap without breaking that rule is a **pull**
mechanism the user drives: distribution through winget, where `winget upgrade` is
run by the user and Vordr still never opens a socket. `tools\make_winget.ps1`
generates the manifests and §3 carries the step; what remains is a published
release to point them at and a PR to `microsoft/winget-pkgs`. Until that is
merged, this section describes the whole of the reach a fix has.

Saying all of this plainly is part of the disclosure, not a footnote to it.
