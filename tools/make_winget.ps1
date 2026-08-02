<#
    make_winget.ps1 - generate the winget manifests for a published release.

    WHY winget at all.  Two problems have one answer.  Antivirus engines flag
    Vordr largely because it has near-zero prevalence (see ANTIVIRUS.md), and a
    package repository is how prevalence is earned.  Separately, Vordr has no
    update channel by design - no auto-update, no telemetry, nothing that phones
    home - which means a user holding a vulnerable build has no way to be told.
    `winget upgrade` closes that gap from the other end: the USER pulls, on their
    schedule, and Vordr still never opens a socket.  It is the only distribution
    mechanism found so far that does not trade the no-callback property away.

    WHAT THIS DOES NOT DO.  It does not publish anything.  It writes three YAML
    files to disk and prints what to do with them.  Submitting them is a pull
    request to microsoft/winget-pkgs, against a release that must already exist
    with a stable download URL - both of which are decisions for a person.

    Run it AFTER the release assets are uploaded, because the installer hash and
    URL in the manifest have to match the file the world will actually download.

    Usage:
        powershell -ExecutionPolicy Bypass -File tools\make_winget.ps1 `
                   -Url https://github.com/xxtsxx/Vordr/releases/download/v0.2.2/vordr-0.2.2.msi
                   [-Msi bin\vordr-0.2.2.msi] [-OutDir bin\winget]
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Url,
    [string]$Msi    = "",
    [string]$OutDir = "bin\winget",
    [string]$ReleaseDate = ""
)

$ErrorActionPreference = "Stop"

# PackageIdentifier is forever.  winget matches upgrades on it, so a later change
# orphans every install that came before - it is not a display name and must not
# be tidied later.
$PackageId  = "ThomasSmistad.Vordr"
$Publisher  = "Thomas Smistad"
$RepoUrl    = "https://github.com/xxtsxx/Vordr"
$ManifestVer = "1.6.0"


# winget-pkgs validation requires CRLF and rejects a manifest without it
# (Validation-Line-Endings-Error).  A here-string carries whatever line endings
# the SCRIPT FILE has, and this one is stored LF - so the first submission went
# up as LF and failed.  Normalise on write rather than depending on how this file
# happens to be saved, which is not a property anyone checks when editing it.
function Write-Manifest([string]$Path, [string]$Text) {
    $crlf = ($Text -replace "`r`n", "`n") -replace "`n", "`r`n"
    $utf8bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($Path, $crlf + "`r`n", $utf8bom)
}

if (-not $Msi) {
    $found = Get-ChildItem "bin\vordr-*.msi" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $found) { throw "no bin\vordr-*.msi - run tools\make_msi.ps1 first" }
    $Msi = $found.FullName
}
$Msi = (Resolve-Path $Msi).Path

# Version and ProductCode come out of the package itself.  Typing either by hand
# is how a manifest ends up describing a build that was never shipped, and the
# ProductCode in particular is regenerated on every build - winget uses it to
# recognise the installed product, so a stale one means "not installed" forever.
$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.OpenDatabase($Msi, 0)
function Prop([string]$name) {
    $v = $db.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property``='$name'")
    $null = $v.Execute()
    $r = $v.Fetch()
    $out = if ($r) { $r.StringData(1) } else { $null }
    $null = $v.Close()
    $out
}
$version     = Prop "ProductVersion"
$productCode = Prop "ProductCode"
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
if (-not $version)     { throw "$Msi has no ProductVersion" }
if (-not $productCode) { throw "$Msi has no ProductCode" }

$sha = (Get-FileHash $Msi -Algorithm SHA256).Hash
if (-not $ReleaseDate) { $ReleaseDate = (Get-Date).ToString("yyyy-MM-dd") }

# Sanity: the URL should name this version.  A copied-and-not-edited URL pointing
# at the previous release is silent - winget installs the old build under the new
# version number and every hash check still passes, because the hash was taken
# from the file the URL names.
if ($Url -notmatch [regex]::Escape($version)) {
    Write-Warning "the URL does not mention $version - is it pointing at the right release asset?"
}

$dir = Join-Path (Join-Path (Get-Location) $OutDir) $version
New-Item -ItemType Directory -Path $dir -Force | Out-Null

$header = "# Created for Vordr $version by tools\make_winget.ps1 - do not hand-edit."

@"
$header
PackageIdentifier: $PackageId
PackageVersion: $version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: $ManifestVer
"@ | ForEach-Object { Write-Manifest (Join-Path $dir "$PackageId.yaml") $_ }

# Scope machine + /qn: the package is per-machine and a silent install from an
# unelevated shell fails with 1925, so winget must run it elevated - which it
# does for a machine-scope installer.
@"
$header
PackageIdentifier: $PackageId
PackageVersion: $version
MinimumOSVersion: 10.0.17763.0
InstallerType: msi
Scope: machine
InstallModes:
- interactive
- silent
- silentWithProgress
InstallerSwitches:
  Silent: /qn
  SilentWithProgress: /qb
UpgradeBehavior: install
ReleaseDate: $ReleaseDate
ProductCode: '$productCode'
Installers:
- Architecture: x64
  InstallerUrl: $Url
  InstallerSha256: $sha
ManifestType: installer
ManifestVersion: $ManifestVer
"@ | ForEach-Object { Write-Manifest (Join-Path $dir "$PackageId.installer.yaml") $_ }

@"
$header
PackageIdentifier: $PackageId
PackageVersion: $version
PackageLocale: en-US
Publisher: $Publisher
PublisherUrl: $RepoUrl
PublisherSupportUrl: $RepoUrl/issues
PackageName: Vordr
PackageUrl: $RepoUrl
License: MIT
LicenseUrl: $RepoUrl/blob/master/LICENSE.txt
ShortDescription: A hardened offline password manager written entirely in x64 assembly.
Description: |-
  Vordr is a single Windows executable with no installer runtime, no C runtime,
  no .NET and no third-party code. The vault is a local encrypted file; nothing
  is sent anywhere, and the program never opens a network socket.
  Releases are reproducible and their SHA-256 is published.
Moniker: vordr
Tags:
- password
- password-manager
- security
- offline
- assembly
ReleaseNotesUrl: $RepoUrl/releases/tag/v$version
ManifestType: defaultLocale
ManifestVersion: $ManifestVer
"@ | ForEach-Object { Write-Manifest (Join-Path $dir "$PackageId.locale.en-US.yaml") $_ }

Write-Host ""
Write-Host "  manifests   : $dir"
Write-Host "  version     : $version"
Write-Host "  ProductCode : $productCode   (regenerated per build - winget matches installs on it)"
Write-Host "  SHA-256     : $sha"
Write-Host "  URL         : $Url"
Write-Host ""
Write-Host "  Nothing has been published.  To take it further, by hand:"
Write-Host "    1. winget validate --manifest `"$dir`""
Write-Host "    2. winget install --manifest `"$dir`"      (installs it locally, for real)"
Write-Host "    3. open a PR against microsoft/winget-pkgs adding"
Write-Host "       manifests/t/$($PackageId -replace '\.','/')/$version/"
Write-Host ""
Write-Host "  Every release needs a new manifest: the version, the URL, the hash and"
Write-Host "  the ProductCode all change together."
