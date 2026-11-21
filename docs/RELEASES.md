# Release verification and hashes

[Documentation](README.md) · [Release checklist](RELEASE_CHECKLIST.md)

A matching hash identifies a particular file. Reproducing that hash from a
reviewed tag provides evidence that the executable corresponds to the source
built with that toolchain. Neither comparison proves that the source is safe.

## Verify a download

Hash the downloaded executable in PowerShell:

```powershell
Get-FileHash .\vordr.exe -Algorithm SHA256
```

Compare it with the row for that exact version below. A mismatch means the
files differ: do not use the download until you have checked the version, source,
and transfer. Do not compare an MSI's hash with the executable hash.

## Published executable hashes

These are historical release records, retained unchanged. The supported-version
policy is in [SECURITY.md](../SECURITY.md); an old hash does not imply support.

| Version | Commit | SHA-256 of `vordr.exe` (x64) | SHA-256 of `vordr-arm64.exe` (ARM64) |
|---|---|---|---|
| v0.2.0 | `48cc1df` | `811b5cd6f56845daf747bc8e4d18f89f35a7bb815463611a1f090009a8279faa` | — |
| v0.2.1 | `1ba8413` | `01baa66ff49e1869dc6b68b4c4528c5cb534282b54f98745222e0f628898e664` | — |
| v0.2.2 | `4482251` | `eaa45139c4941e6516c17ebf880c5fb78dee0bd0c5db88024e99b51833ad914d` | — |
| v0.2.3 | `378c28e` | `197e5ef014c8be0093ed7a0e7960358cdeb2b118c4dbb5680a949dcf55c2d343` | — |
| v1.0.0 | `d8aaf5f` | `8241198fb48d592302ffb20f8b9df3766bc4d396913e18e641003986c2456526` | `ccf95b48cc5f4a324af5805c83f0868dc080f78e440ff4f001d48e2df26f7e6b` |

`v1.0.0` (`d8aaf5f`) build metadata:
- Toolchain: MSVC `ml64` / `link` `14.44.35230.0`, Windows SDK `10.0.28000.0`, LLVM `clang` `23.1.5` (`build.cmd release strict` and `build_arm64.cmd release`, verified byte-reproducible via `tools\verify_repro.ps1` and a second clean checkout).
- Universal MSI (`vordr-1.0.0.msi`, `647,168` bytes): SHA-256 `53bc66a111180c2912dc2d9c46869f9b62d595ccef80f5477a64a57c9621d803`, `ProductCode` `{94A9DB29-A12F-434E-A73F-1CB8C9D6EE33}`, `UpgradeCode` `{6A1D0C7E-9E2F-4F1B-9C2A-7E5B0D3A8F41}`.

A row may have been added after the tag it describes. Rebuild the tag, not
the current `master` branch, when checking a published hash.

## WinGet publication

Vordr **0.2.3** was approved, merged, and published to the WinGet community source
on **2026-09-14** through
[PR #411202](https://github.com/microsoft/winget-pkgs/pull/411202).
All ten validation stages passed, and publication was confirmed by querying
`ThomasSmistad.Vordr` through WinGet. This is a historical publication record,
not a claim that 0.2.3 will always be the latest version.

The listing uses the existing GitHub release MSI, with SHA-256:

```text
683202773f1307952f7c9d6705c1cc09c082bdd28570625aa5ba1a2640d894e6
```

This is the **MSI hash**, not the executable hash in the table above.
Publication did not rebuild or change the release. Query the live listing with:

```powershell
winget show --id ThomasSmistad.Vordr --exact --source winget
```

See [installation and updates](USER_GUIDE.md#updates) for everyday use.
Each future release needs a separate manifest update and successful publication;
uploading a GitHub release alone does not update WinGet.

## Reproduce an executable

Use a separate clean checkout and the matching MSVC/SDK (and LLVM for ARM64) versions.
Build flags remove common sources of variation but do not make different toolchains
interchangeable.

```bat
git clone --branch v0.2.3 --depth 1 https://github.com/xxtsxx/Vordr.git vordr-v0.2.3-check
cd vordr-v0.2.3-check
build.cmd release strict
build_arm64.cmd release
certutil -hashfile bin\vordr.exe SHA256
certutil -hashfile bin\vordr-arm64.exe SHA256
```

The tag is an example; choose the version being verified (`v0.2.3` pre-dates the ARM64
port; `build_arm64.cmd` applies to `0.8.2` and later). Both `build.cmd release` and
`build_arm64.cmd release` merge their SHA-256 digests into `bin\SHA256SUMS.txt`. To
check that one machine builds identical bytes twice for both architectures, run
`powershell -NoProfile -ExecutionPolicy Bypass -File tools\verify_repro.ps1`.

| Step | Purpose |
|---|---|
| `/Brepro` | Uses deterministic content-derived build metadata |
| `/pdbaltpath:vordr.pdb` *(or `vordr-arm64.pdb`)* | Avoids embedding a machine-specific absolute PDB path |
| `tools\pe_normalise.py` | Verifies `LOAD_CONFIG.DependentLoadFlags == 0x0800` (`LOAD_LIBRARY_SEARCH_SYSTEM32`), 4 KiB-isolated `_ROINIT`, `W^X`, and x64 CET flags; zeroes COFF/export/load-config/debug timestamps while preserving `IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS` (CET). |

Releases built before normalisation was added (v0.2.3 and earlier) carry those
stamps, so their published hash cannot be matched by a rebuild directly. Compare
them by normalising both files first; `pe_normalise.py` changes nothing else:

```bat
copy vordr.exe published.exe
python tools\pe_normalise.py published.exe bin\vordr.exe
certutil -hashfile published.exe SHA256
certutil -hashfile bin\vordr.exe SHA256
```

ASLR, DEP/NX, high-entropy VA, and (on x64) CET compatibility flags remain enabled.
Record tool versions alongside hashes when preparing a release.

## MSI payloads

The universal MSI is a per-machine wrapper carrying both native x64 (`vordr.exe`) and
native ARM64 (`vordr-arm64.exe`) executables. It installs the host's native binary into
`%ProgramFiles%\Vordr\vordr.exe` with zero custom actions (`AppSearch` + `RegLocator`),
applies `MsiLockPermissionsEx` SDDL rules, registers an installed-product identity, and
can add a shortcut, `.vordr` file association, and administrator-selected policy values.
Uninstall does not remove vaults or HKCU user data.

The MSI gets new product/package identifiers when built, so its hash can change
even when its executable payload does not. Publish a separate MSI hash and
ProductCode. Verify its extracted executable against the table above.

An administrative extraction can be used to inspect the payload:

```bat
msiexec /a "C:\Downloads\vordr-0.2.3.msi" /qn TARGETDIR="C:\Temp\vordr-extracted"
```

Use an empty, task-owned destination and inspect the extracted tree for
`vordr.exe`. Extraction does not test installation policy, upgrades, or uninstall;
see [Deployment](DEPLOYMENT.md).

## Historical known issues

**v0.2.0 is superseded and should not be used.** The existing release record
notes an incorrect default vault location on OneDrive-linked machines, a
first-unlock private-desktop problem, and an import-selection bounds issue
above 8192 entries. Use the newest supported release, not an old version simply
because its hash is listed.

The previous release documentation contained no advisory entries. This page is
not a live advisory feed; check
[GitHub security advisories](https://github.com/xxtsxx/Vordr/security/advisories)
and current release notes before deployment. Add affected/fixed versions here
when publishing an advisory, without deleting or repointing old tags.
