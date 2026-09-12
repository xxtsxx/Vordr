# Antivirus warnings

[Documentation](README.md) · [Verify a release](RELEASES.md)

Vordr's release records include Microsoft Defender detections named
`Trojan:Win32/Wacatac.B!ml` and `Trojan:Win32/Wacatac.C!ml`.
The project treated these as suspected false positives. A historical report
does not establish that a different file or a new warning is harmless.

## If your download is flagged

1. Keep antivirus protection enabled. Do not add a blanket exclusion.
2. Confirm the file came from the project's release page.
3. Compare the executable's SHA-256 with the [published record](RELEASES.md).
   Treat the MSI as a separate file with its own hash.
4. If the bytes match, review the source or reproduce the tagged build with
   a matching toolchain. A match identifies the file; it does not prove safety.
5. Submit the flagged public release to the vendor for analysis. Never upload
   a vault, export, attachment containing secrets, or secret-bearing dump.

If you cannot establish what the file is, do not run it.

## Why warnings may differ

Unsigned or uncommon applications can encounter reputation warnings. Vordr
also uses APIs for clipboard access, hotkeys, encryption, registry settings,
and private desktops. Those uses are documented, but the API list alone neither
proves maliciousness nor explains a particular vendor's decision.

Do not equate a SmartScreen reputation warning with a Defender malware verdict.
A clean scan from another service also does not guarantee that a local or
cloud-assisted scanner will agree.

Code signing identifies a publisher and can help establish reputation, but it
does not guarantee the absence of warnings. In particular, Microsoft says EV
certificates no longer receive automatic positive SmartScreen reputation.
See [Microsoft's developer guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation).

## Submit a suspected false positive

Use [Microsoft's file submission portal](https://www.microsoft.com/en-us/wdsi/filesubmission)
or the detecting vendor's current submission process. Maintainers should identify
the exact release, filename, SHA-256, detection name, and reproduction details.
Response times and verdicts are controlled by the vendor; do not promise a
turnaround or assume a previous result applies to a rebuilt file.

Public multi-engine scan services can provide additional observations, but their
results are not interchangeable with a user's local protection settings.
Treat a public upload as publication of the entire submitted file.

## Historical submission record

This is the previously recorded observation, not a current vendor-status check.

| Version | Recorded date | Observation | Last recorded outcome |
|---|---|---|---|
| v0.2.3 | 2026-08-02 | WDSI: `Trojan:Win32/Wacatac.C!ml`; VirusTotal reported no detections | Awaiting response |

A maintainer should add dated vendor responses rather than silently changing
this historical observation.

## Maintainer practice

The [release checklist](RELEASE_CHECKLIST.md) includes submitting new public
release artifacts to vendors and recording outcomes. Preserve inspectable
binaries and reproducible build information. Do not pack, obfuscate, hide imports,
or weaken security features to evade a scanner. Do not ask users to disable
their protection.
