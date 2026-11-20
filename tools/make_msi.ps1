<#
    make_msi.ps1 - build a per-machine universal MSI (x64 + ARM64) around
                   bin\vordr.exe and bin\vordr-arm64.exe.

    No third-party toolchain: the MSI database is authored directly through the
    WindowsInstaller COM automation, and the payload is packed with makecab.
    Requiring WiX to cut a release would undercut "no third-party code".

    WHAT IT INSTALLS, and just as importantly what it does not:

      * one file, vordr.exe, into %ProgramFiles%\Vordr
      * a Start Menu shortcut
      * an Add/Remove Programs entry carrying ProductName + ProductVersion
      * HKLM policy values - ONLY those the installing admin asks for by name
      * the .vordr file association (VORDR_NOASSOC=1 to skip it)

    It owns NOTHING else.  No vault, no HKCU settings.  That is deliberate:
    uninstall removes only what MSI installed, so a user who uninstalls Vordr
    keeps their vault and their configuration.  An installer that "cleans up" a
    password manager's data on removal would destroy the user's secrets, and MSI
    makes that mistake easy - one RemoveFile row aimed at the wrong directory is
    all it takes.  There are none here, and there must never be.

    POLICY (see $Policies below).  Each HKLM value Vordr honours is exposed as a
    public MSI property, so a deployment can set it from the command line:

        msiexec /i vordr-0.2.2.msi /qn VORDR_SECUREUNLOCK=1 VORDR_PWMINLEN=16

    Each value lives in its own component, conditioned on its property being
    set, so a property that is not named is not written.  That matters more than
    it looks: in Vordr, the PRESENCE of an HKLM value is what locks the setting
    against the user (regcfg.asm cfg_get_dword returns locked=1 for anything it
    finds in HKLM).  An installer that helpfully wrote every default would hand
    the admin a machine where the user can change nothing.

    Values are not validated here - they cannot be, they arrive at install time,
    not build time.  Vordr clamps every one of them on read (gui_load_policy), so
    a typo degrades to the clamp rather than to undefined behaviour.

    CAVEAT, and it is a real one: MSI does not remember properties.  An upgrade
    that does not repeat them installs without those components, and the old
    product's values go away with it - so policy must be passed on EVERY install,
    including upgrades, or it is silently dropped.  Deployment tooling normally
    does exactly that.  Making it survive instead would need AppSearch to read
    the current values back plus a type-51 action per value to reconcile them
    with the command line, which is a lot of untestable machinery to add blind.

    PER-MACHINE: installs into Program Files, so installing and uninstalling need
    elevation.  That is deliberate.  It is the only scope in which HKLM policy
    defaults and .vordr file associations can be registered, and Program Files is
    read-only to standard users - a password manager binary that any non-admin
    process could overwrite would be a poor idea.

    This does not contradict vordr.manifest's asInvoker: that governs how the
    program RUNS (never elevated), not how it is installed.

    The version is read from the exe's own version resource, so vordr.rc stays
    the single source of truth - the MSI cannot drift from the binary it wraps.

    Usage:  powershell -ExecutionPolicy Bypass -File tools\make_msi.ps1
            [-Exe bin\vordr.exe] [-Arm64Exe bin\vordr-arm64.exe] [-OutDir bin]
#>
[CmdletBinding()]
param(
    [string]$Exe      = "bin\vordr.exe",
    [string]$Arm64Exe = "bin\vordr-arm64.exe",
    [string]$OutDir   = "bin"
)

$ErrorActionPreference = "Stop"

# Stable identity.  UpgradeCode must NEVER change - it is what lets a new MSI
# recognise and replace an older install instead of sitting beside it.
# ProductCode is regenerated per build, which is what tells Windows the payload
# differs (required for RemoveExistingProducts to do its job).
$UpgradeCode        = "{6A1D0C7E-9E2F-4F1B-9C2A-7E5B0D3A8F41}"
$ComponentGuid      = "{2F8B5A31-4C6D-4E7A-8B90-1D3E5F7A9C24}"
$Arm64ComponentGuid = "{8E4C7D29-61B3-4F0A-9A5E-3C1B8D4F2E71}"
$Manufacturer = "Thomas Smistad"
$ProductName  = "Vordr"
$InstallDir   = "Vordr"
$PolicyKey    = "SOFTWARE\Vordr"       # regcfg.asm cfg_subkey - HKLM wins over HKCU

# The HKLM policy surface, one row per value Vordr reads.  Name/Default/Range
# mirror gui_load_policy + gui_load_prefs; keep them in step, since this table is
# what an administrator reads before deploying.
#
# Guid is the COMPONENT id and must never change: it is what lets an upgrade
# recognise the value it already owns instead of orphaning it.
$Policies = @(
    @{ Prop="VORDR_PWMINLEN";        Value="PwMinLen";        Comp="PolPwMinLen";     Guid="{D19F5EA9-D38C-4D8F-AB7D-7FA755005F6A}"; Range="1-256";   Default="12";  Doc="minimum master-password length" }
    @{ Prop="VORDR_PWMINCLASSES";    Value="PwMinClasses";    Comp="PolPwMinCls";     Guid="{A00BACFE-4D80-4660-9838-6CDACB2B4FD0}"; Range="1-4";     Default="3";   Doc="character classes a master password must mix" }
    @{ Prop="VORDR_SECUREUNLOCK";    Value="SecureUnlock";    Comp="PolSecUnlock";    Guid="{71D60D6C-C613-4D0E-BA73-4DB5FE8BD552}"; Range="0/1";     Default="1";   Doc="type the master password on an isolated desktop" }
    @{ Prop="VORDR_TPMUNLOCK";       Value="TpmUnlock";       Comp="PolTpmUnlock";    Guid="{E644B890-A962-45CA-923D-B1C721BBAF5A}"; Range="0/1";     Default="1";   Doc="allow TPM convenience unlock" }
    @{ Prop="VORDR_TPMREQUIREHELLO"; Value="TpmRequireHello"; Comp="PolTpmHello";     Guid="{DABA9DC0-F726-41CE-9291-45D3ED06D498}"; Range="0/1";     Default="0";   Doc="require Hello/PIN for TPM unlock" }
    @{ Prop="VORDR_CLIPSECONDS";     Value="ClipSeconds";     Comp="PolClipSecs";     Guid="{0E7CC768-6CA6-492F-8283-A22866EDDADE}"; Range="0-3600";  Default="20";  Doc="clipboard auto-clear delay, 0 = never copy-and-forget" }
    @{ Prop="VORDR_IDLELOCKMIN";     Value="IdleLockMin";     Comp="PolIdleLock";     Guid="{065AAA8F-F053-4F6D-83EE-2F6CC73F6A2E}"; Range="0-1440";  Default="10";  Doc="idle minutes before auto-lock, 0 = off" }
    @{ Prop="VORDR_LOCKONWINLOCK";   Value="LockOnWinLock";   Comp="PolWinLock";      Guid="{7DCACD47-C2DD-4E02-BA29-5BFA6C1B5258}"; Range="0/1";     Default="1";   Doc="lock the vault when Windows locks" }
    @{ Prop="VORDR_PWVERIFYDAYS";    Value="PwVerifyDays";    Comp="PolPwDays";       Guid="{558B9574-C9E7-4A05-99B2-6792F0850BFB}"; Range="0-3650";  Default="30";  Doc="re-verify the master password every N days under TPM unlock" }
    @{ Prop="VORDR_NOHISTORY";       Value="NoHistory";       Comp="PolNoHistory";    Guid="{835B8733-0B32-4DFF-AE70-3DDB1F261FA6}"; Range="0/1";     Default="0";   Doc="do not keep per-entry history" }
    @{ Prop="VORDR_NOPHONETIC";      Value="NoPhonetic";      Comp="PolNoPhonetic";   Guid="{2C20D1F4-69BF-44A1-B131-44DFBE4DB6F3}"; Range="0/1";     Default="0";   Doc="disable the phonetic secret reader" }
    @{ Prop="VORDR_NOPREVIEW";       Value="NoPreview";       Comp="PolNoPreview";    Guid="{7887784C-D701-466E-B920-14E2DD01FB71}"; Range="0/1";     Default="0";   Doc="attachments download only, never preview via another app" }
    @{ Prop="VORDR_ALLOWUNCVAULT";       Value="AllowUncVault";       Comp="PolAllowUnc";     Guid="{C4829E51-3D74-4A8B-9162-5E1B0F47A3C9}"; Range="0/1";     Default="0";   Doc="allow opening vault files over UNC/network shares (HKLM-only)" }
    @{ Prop="VORDR_ALLOWSCREENCAPTURE";  Value="AllowScreenCapture";  Comp="PolAllowCap";     Guid="{6D3A14B8-79E2-4F55-8A1C-34B8E92D71F0}"; Range="0/1";     Default="0";   Doc="allow screen capture of Vordr windows (0 = WDA_EXCLUDEFROMCAPTURE)" }
    @{ Prop="VORDR_LOGLEVEL";            Value="LogLevel";            Comp="PolLogLevel";     Guid="{A3BD3F2C-326F-4749-A57E-A78D1EC4AC0E}"; Range="0-4";     Default="0";   Doc="audit-log verbosity, 0 = off" }
    @{ Prop="VORDR_UISCHEME";            Value="ui_scheme";           Comp="PolUiScheme";     Guid="{9B70EE1D-7B67-44A0-8C02-06B7BD8F982F}"; Range="0-14";    Default="8";   Doc="force a colour scheme (8 = Gruvbox default, 14 = Follow Windows)" }
)
# NOT exposed via MSI property: HKLM "vault".  Administrators who configure a
# per-machine vault path via Group Policy can use safe per-user prefixes
# (%APPDATA%\, %LOCALAPPDATA%\, %USERPROFILE%\) resolved via GetUserProfileDirectoryW
# in regcfg.asm, whereas an unparameterized MSI property could easily point every
# user on a shared machine at one literal path by mistake.

# --- .vordr file association -------------------------------------------------
# Registered per-machine under HKLM\SOFTWARE\Classes (which is what HKCR resolves
# to for an ALLUSERS install).  Double-clicking a .vordr opens it as an IMPORT
# source - never as the vault Vordr opens from then on; gui.asm enforces that,
# not the installer.
$AssocComp = "FileAssoc"
$AssocGuid = "{4B1E86D2-95AF-4C33-9F0E-2A6D74C1B5E8}"
$AssocProp = "VORDR_NOASSOC"            # set to anything to skip the registration
$ProgId    = "Vordr.Vault"
$ClassesKey= "SOFTWARE\Classes"

function Resolve-Full([string]$p) {
    if ([System.IO.Path]::IsPathRooted($p)) { $p } else { Join-Path (Get-Location) $p }
}

$exePath   = Resolve-Full $Exe
$arm64Path = Resolve-Full $Arm64Exe
if (-not (Test-Path $exePath))   { throw "not found: $exePath  (build first: build.cmd release)" }
if (-not (Test-Path $arm64Path)) { throw "not found: $arm64Path  (build first: build_arm64.cmd release)" }

# --- refuse to wrap anything but normalised release binaries -----------------
# The gate's roundtrip stage leaves a PROBE_IO build in bin\, and that build
# exposes the path-taking diagnostic verbs.  Shipping one inside an installer
# would hand every user a binary that takes a vault path on the command line.
# Nothing about the file says which build it is - same name, same version
# resource - so ask the x64 binary directly, and statically inspect both PEs.
$probe = Join-Path $env:TEMP ("vordrguard_" + [guid]::NewGuid().ToString("N") + ".vault")
$run = Start-Process -FilePath $exePath -ArgumentList @("seedtest", $probe) `
                     -Wait -PassThru -WindowStyle Hidden
$tookIt = $run.ExitCode -eq 0
if (Test-Path $probe) { Remove-Item $probe -Force; $tookIt = $true }
if ($tookIt) {
    throw "$exePath accepts path-taking verbs - that is a PROBE_IO build, not a release. Run build.cmd release (or strict) and package that."
}

function Assert-ReleasePe([string]$Path, [uint16]$ExpectMachine, [bool]$RequireCet) {
    $peBytes = [System.IO.File]::ReadAllBytes($Path)
    $sentinel = [System.Text.Encoding]::ASCII.GetBytes("VORDR_NON_RELEASE_BUILD")
    $si = 0
    $maxSi = $peBytes.Length - $sentinel.Length
    while (($si = [Array]::IndexOf($peBytes, $sentinel[0], $si)) -ge 0 -and $si -le $maxSi) {
        $match = $true
        for ($sj = 1; $sj -lt $sentinel.Length; $sj++) {
            if ($peBytes[$si + $sj] -ne $sentinel[$sj]) { $match = $false; break }
        }
        if ($match) {
            throw "$Path contains VORDR_NON_RELEASE_BUILD (dbg/probeio/guishow build) - never package non-release builds."
        }
        $si++
    }
    $peOff   = [BitConverter]::ToInt32($peBytes, 0x3C)
    $machine = [BitConverter]::ToUInt16($peBytes, $peOff + 4)
    if ($machine -ne $ExpectMachine) {
        throw ("{0} has PE Machine 0x{1:X4}, expected 0x{2:X4}" -f $Path, $machine, $ExpectMachine)
    }
    $coffTs  = [BitConverter]::ToInt32($peBytes, $peOff + 8)
    if ($coffTs -ne 0) {
        throw "$Path has non-zero COFF TimeDateStamp (0x$($coffTs.ToString('X8'))) - not a normalised release binary."
    }
    $nSect   = [BitConverter]::ToUInt16($peBytes, $peOff + 6)
    $optSize = [BitConverter]::ToUInt16($peBytes, $peOff + 20)
    $optOff  = $peOff + 24
    $dllChar = [BitConverter]::ToUInt16($peBytes, $optOff + 70)
    if (($dllChar -band 0x0160) -ne 0x0160) {
        throw ("{0} DllCharacteristics 0x{1:X4} lacks HIGH_ENTROPY_VA|DYNAMIC_BASE|NX_COMPAT" -f $Path, $dllChar)
    }
    $ddOff   = $optOff + 112                  # PE32+ DataDirectory[0]
    $sectOff = $optOff + $optSize
    $dbgRva  = [BitConverter]::ToInt32($peBytes, $ddOff + 6 * 8)
    $dbgSz   = [BitConverter]::ToInt32($peBytes, $ddOff + 6 * 8 + 4)
    $hasCet  = $false
    if ($dbgRva -ne 0 -and $dbgSz -ge 28) {
        $dbgFileOff = -1
        for ($si = 0; $si -lt $nSect; $si++) {
            $s = $sectOff + $si * 40
            $va = [BitConverter]::ToUInt32($peBytes, $s + 12)
            $vsz = [BitConverter]::ToUInt32($peBytes, $s + 8)
            $raw = [BitConverter]::ToUInt32($peBytes, $s + 20)
            $rsz = [BitConverter]::ToUInt32($peBytes, $s + 16)
            $span = if ($vsz -gt 0 -and $vsz -lt $rsz) { $vsz } else { $rsz }
            if ($dbgRva -ge $va -and $dbgRva -lt ($va + $span)) {
                $dbgFileOff = [int]($raw + ($dbgRva - $va))
                break
            }
        }
        if ($dbgFileOff -ge 0) {
            for ($di = 0; $di -lt [int]($dbgSz / 28); $di++) {
                $de = $dbgFileOff + $di * 28
                $dtype = [BitConverter]::ToUInt32($peBytes, $de + 12)
                if ($dtype -eq 20) { $hasCet = $true }
            }
        }
    }
    if ($RequireCet -and -not $hasCet) {
        throw "$Path lacks IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS (/CETCOMPAT) - never package a 'nohw' build."
    }
}

Assert-ReleasePe -Path $exePath   -ExpectMachine 0x8664 -RequireCet $true
Assert-ReleasePe -Path $arm64Path -ExpectMachine 0xAA64 -RequireCet $false

# --- version comes from the binaries, never typed twice ----------------------
$vi    = (Get-Item $exePath).VersionInfo
$viArm = (Get-Item $arm64Path).VersionInfo
$fv    = $vi.FileVersion
if (-not $fv) { throw "$exePath has no version resource" }
if ($viArm.FileVersion -ne $fv) {
    throw ("version mismatch: x64 is {0}, arm64 is {1} - rebuild both from the same commit" -f $fv, $viArm.FileVersion)
}
$parts = ($fv -split '[.,]') | ForEach-Object { [int]$_ }
# MSI ProductVersion is max three fields; the 4th is ignored by Windows Installer
$productVersion = "{0}.{1}.{2}" -f $parts[0], $parts[1], $parts[2]
Write-Host ("  x64 exe        : {0}" -f $exePath)
Write-Host ("  arm64 exe      : {0}" -f $arm64Path)
Write-Host ("  FileVersion    : {0}  ->  MSI ProductVersion {1} (universal x64 + ARM64)" -f $fv, $productVersion)

$outMsi = Join-Path (Resolve-Full $OutDir) ("vordr-{0}.msi" -f $productVersion)
if (Test-Path $outMsi) { Remove-Item $outMsi -Force }

# --- pack both payloads into a single cab ------------------------------------
# MSI stores files in a cabinet; each File table key matches its cab member.
# Both components install to [INSTALLDIR]vordr.exe under mutually exclusive
# conditions driven by HOST_NATIVE_ARCH (AppSearch + RegLocator).
$work = Join-Path $env:TEMP ("vordrmsi_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Copy-Item $exePath   (Join-Path $work "vordr_x64.exe")
    Copy-Item $arm64Path (Join-Path $work "vordr_arm64.exe")
    $ddf = Join-Path $work "make.ddf"
@"
.OPTION EXPLICIT
.Set CabinetNameTemplate=vordr.cab
.Set DiskDirectory1=$work
.Set Cabinet=on
.Set Compress=on
.Set CompressionType=MSZIP
.Set MaxDiskSize=0
.Set ReservePerCabinetSize=0
.Set InfFileName=$work\setup.inf
.Set RptFileName=$work\setup.rpt
"$work\vordr_x64.exe" vordr_x64.exe
"$work\vordr_arm64.exe" vordr_arm64.exe
"@ | Out-File -FilePath $ddf -Encoding ascii
    # makecab drops setup.inf / setup.rpt in the CURRENT directory unless told
    # otherwise - that put build litter in the repo root.  Both are redirected
    # into the scratch dir above, and it runs from there as well.
    Push-Location $work
    $cabLog = & makecab.exe /F $ddf 2>&1
    Pop-Location
    $cab = Join-Path $work "vordr.cab"
    if (-not (Test-Path $cab)) { throw "makecab failed:`n$cabLog" }
    Write-Host ("  cab            : {0} bytes" -f (Get-Item $cab).Length)

    # --- author the database -------------------------------------------------
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.OpenDatabase($outMsi, 3)      # msiOpenDatabaseModeCreate

    function Exec([string]$sql) {
        try {
            $view = $db.OpenView($sql)
            $view.Execute()
            $view.Close()
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view)
        } catch {
            # MSI reports every SQL failure as the same opaque "Execute,Params",
            # so the statement has to be surfaced here or the error is unusable.
            throw ("MSI SQL failed:`n  {0}`n  -> {1}" -f $sql, $_.Exception.Message)
        }
    }

    # schema
    Exec "CREATE TABLE ``Property`` (``Property`` CHAR(72) NOT NULL, ``Value`` CHAR(255) NOT NULL PRIMARY KEY ``Property``)"
    Exec "CREATE TABLE ``Directory`` (``Directory`` CHAR(72) NOT NULL, ``Directory_Parent`` CHAR(72), ``DefaultDir`` CHAR(255) NOT NULL PRIMARY KEY ``Directory``)"
    Exec "CREATE TABLE ``Component`` (``Component`` CHAR(72) NOT NULL, ``ComponentId`` CHAR(38), ``Directory_`` CHAR(72) NOT NULL, ``Attributes`` SHORT NOT NULL, ``Condition`` CHAR(255), ``KeyPath`` CHAR(72) PRIMARY KEY ``Component``)"
    Exec "CREATE TABLE ``Feature`` (``Feature`` CHAR(38) NOT NULL, ``Feature_Parent`` CHAR(38), ``Title`` CHAR(64), ``Description`` CHAR(255), ``Display`` SHORT, ``Level`` SHORT NOT NULL, ``Directory_`` CHAR(72), ``Attributes`` SHORT NOT NULL PRIMARY KEY ``Feature``)"
    Exec "CREATE TABLE ``FeatureComponents`` (``Feature_`` CHAR(38) NOT NULL, ``Component_`` CHAR(72) NOT NULL PRIMARY KEY ``Feature_``, ``Component_``)"
    Exec "CREATE TABLE ``File`` (``File`` CHAR(72) NOT NULL, ``Component_`` CHAR(72) NOT NULL, ``FileName`` CHAR(255) NOT NULL, ``FileSize`` LONG NOT NULL, ``Version`` CHAR(72), ``Language`` CHAR(20), ``Attributes`` SHORT, ``Sequence`` SHORT NOT NULL PRIMARY KEY ``File``)"
    Exec "CREATE TABLE ``Media`` (``DiskId`` SHORT NOT NULL, ``LastSequence`` SHORT NOT NULL, ``DiskPrompt`` CHAR(64), ``Cabinet`` CHAR(255), ``VolumeLabel`` CHAR(32), ``Source`` CHAR(72) PRIMARY KEY ``DiskId``)"
    Exec "CREATE TABLE ``InstallExecuteSequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
    Exec "CREATE TABLE ``InstallUISequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
    Exec "CREATE TABLE ``AdminExecuteSequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
    Exec "CREATE TABLE ``AdvtExecuteSequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
    Exec "CREATE TABLE ``Upgrade`` (``UpgradeCode`` CHAR(38) NOT NULL, ``VersionMin`` CHAR(20), ``VersionMax`` CHAR(20), ``Language`` CHAR(255), ``Attributes`` LONG NOT NULL, ``Remove`` CHAR(255), ``ActionProperty`` CHAR(72) NOT NULL PRIMARY KEY ``UpgradeCode``, ``VersionMin``, ``VersionMax``, ``Language``, ``Attributes``)"
    Exec "CREATE TABLE ``LaunchCondition`` (``Condition`` CHAR(255) NOT NULL, ``Description`` CHAR(255) NOT NULL PRIMARY KEY ``Condition``)"
    Exec "CREATE TABLE ``Shortcut`` (``Shortcut`` CHAR(72) NOT NULL, ``Directory_`` CHAR(72) NOT NULL, ``Name`` CHAR(128) NOT NULL, ``Component_`` CHAR(72) NOT NULL, ``Target`` CHAR(72) NOT NULL, ``Arguments`` CHAR(255), ``Description`` CHAR(255), ``Hotkey`` SHORT, ``Icon_`` CHAR(72), ``IconIndex`` SHORT, ``ShowCmd`` SHORT, ``WkDir`` CHAR(72) PRIMARY KEY ``Shortcut``)"
    Exec "CREATE TABLE ``Registry`` (``Registry`` CHAR(72) NOT NULL, ``Root`` SHORT NOT NULL, ``Key`` CHAR(255) NOT NULL, ``Name`` CHAR(255), ``Value`` CHAR(0), ``Component_`` CHAR(72) NOT NULL PRIMARY KEY ``Registry``)"
    Exec "CREATE TABLE ``AppSearch`` (``Property`` CHAR(72) NOT NULL, ``Signature_`` CHAR(72) NOT NULL PRIMARY KEY ``Property``, ``Signature_``)"
    Exec "CREATE TABLE ``RegLocator`` (``Signature_`` CHAR(72) NOT NULL, ``Root`` SHORT NOT NULL, ``Key`` CHAR(255) NOT NULL, ``Name`` CHAR(255), ``Type`` SHORT PRIMARY KEY ``Signature_``)"
    # AppSearch always queries the Signature table even for raw RegLocator lookups;
    # omitting this empty table fails real installs with MSI error 2228.
    Exec "CREATE TABLE ``Signature`` (``Signature`` CHAR(72) NOT NULL, ``FileName`` CHAR(255) NOT NULL, ``MinVersion`` CHAR(20), ``MaxVersion`` CHAR(20), ``MinSize`` LONG, ``MaxSize`` LONG, ``MinDate`` LONG, ``MaxDate`` LONG, ``Languages`` CHAR(255) PRIMARY KEY ``Signature``)"
    # NO RemoveFile table.  MSI removes a component's own files on uninstall
    # automatically; RemoveFile exists to delete things the installer did NOT
    # install, which for a password manager is how you would delete someone's
    # vault.  Its absence is the safeguard - do not add it.

    $productCode = "{" + [guid]::NewGuid().ToString().ToUpper() + "}"
    $props = @{
        "ProductCode"        = $productCode
        "ProductName"        = $ProductName
        "ProductVersion"     = $productVersion
        "Manufacturer"       = $Manufacturer
        "UpgradeCode"        = $UpgradeCode
        "ProductLanguage"    = "1033"
        # PER-MACHINE.  This began as a per-user package but still demanded
        # elevation - the worst of both: admin required, yet the exe landing in one
        # user's LocalAppData where nobody else can see it.  Per-machine is what it
        # actually wants: the only scope in which HKLM policy defaults and .vordr
        # file associations can be registered, and Program Files is read-only to
        # standard users, so the binary cannot be replaced by anything running
        # without admin.
        "ALLUSERS"           = "1"
        "ARPNOMODIFY"        = "1"
        "ARPNOREPAIR"        = "1"
        "ARPURLINFOABOUT"    = "https://github.com/xxtsxx/Vordr"
        "ARPHELPLINK"        = "https://github.com/xxtsxx/Vordr/blob/master/SECURITY.md"
        # Public properties reach the elevated half of a per-machine install only
        # if they are listed here.  Miss one and it silently has no effect - the
        # property is set, the component condition still evaluates false.
        "SecureCustomProperties" = (@("OLDERVERSIONBEINGUPGRADED", "NEWERVERSIONDETECTED", "HOST_NATIVE_ARCH", $AssocProp) + ($Policies | ForEach-Object { $_.Prop })) -join ";"
    }
    foreach ($k in $props.Keys) {
        $v = $props[$k] -replace "'", "''"
        Exec "INSERT INTO ``Property`` (``Property``,``Value``) VALUES ('$k','$v')"
    }

    # --- native architecture detection (zero custom actions) -----------------
    # Reads HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\
    # PROCESSOR_ARCHITECTURE (64-bit view, raw value: Type = 18 = 2|16).  That
    # value has no WOW64 redirection and is "ARM64" on Windows on ARM vs "AMD64"
    # on x64 Windows.  VordrExe and VordrExeArm64 are mutually exclusive under
    # HOST_NATIVE_ARCH so every machine receives its native binary at
    # %ProgramFiles%\Vordr\vordr.exe.
    Exec "INSERT INTO ``RegLocator`` (``Signature_``,``Root``,``Key``,``Name``,``Type``) VALUES ('SigHostArch',2,'SYSTEM\CurrentControlSet\Control\Session Manager\Environment','PROCESSOR_ARCHITECTURE',18)"
    Exec "INSERT INTO ``AppSearch`` (``Property``,``Signature_``) VALUES ('HOST_NATIVE_ARCH','SigHostArch')"

    Exec "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('TARGETDIR','','SourceDir')"
    Exec "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('ProgramFiles64Folder','TARGETDIR','.')"
    Exec "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('INSTALLDIR','ProgramFiles64Folder','$InstallDir')"
    Exec "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('ProgramMenuFolder','TARGETDIR','.')"

    # Component attributes 256 = msidbComponentAttributes64bit; bit 4
    # (RegistryKeyPath) is clear so each component's exe File row is its key path.
    # Mutually exclusive conditions ensure only one binary lands at
    # [INSTALLDIR]vordr.exe (x64 default when HOST_NATIVE_ARCH is unset/AMD64,
    # ARM64 when HOST_NATIVE_ARCH is "ARM64").
    Exec "INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('VordrExe','$ComponentGuid','INSTALLDIR',256,'NOT (HOST_NATIVE_ARCH ~= `"ARM64`")','vordr_x64.exe')"
    Exec "INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('VordrExeArm64','$Arm64ComponentGuid','INSTALLDIR',256,'HOST_NATIVE_ARCH ~= `"ARM64`"','vordr_arm64.exe')"
    Exec "INSERT INTO ``Feature`` (``Feature``,``Feature_Parent``,``Title``,``Description``,``Display``,``Level``,``Directory_``,``Attributes``) VALUES ('Main','','Vordr','Vordr password manager',1,1,'INSTALLDIR',0)"
    Exec "INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','VordrExe')"
    Exec "INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','VordrExeArm64')"

    # --- one component per policy value --------------------------------------
    # Attributes 4 = the registry row is the key path; 256 = write to the 64-bit
    # view.  Without 256 an x64 package puts these under WOW6432Node, where the
    # 64-bit vordr.exe would never look - the install would appear to succeed and
    # the policy would simply not take effect.
    # Condition is the bare property name: true when it is set to anything,
    # false when the admin left it out.
    foreach ($p in $Policies) {
        $defVal = 0
        if (-not [int]::TryParse($p.Default, [ref]$defVal)) {
            throw ("policy {0} Default '{1}' is not an integer" -f $p.Prop, $p.Default)
        }
        if ($p.Range -eq "0/1") {
            if ($defVal -lt 0 -or $defVal -gt 1) { throw ("policy {0} Default {1} outside 0/1" -f $p.Prop, $defVal) }
            $cond = "(NOT {0}) OR ({0} = `"0`") OR ({0} = `"1`")" -f $p.Prop
        } elseif ($p.Range -match '^(\d+)-(\d+)$') {
            $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
            if ($defVal -lt $lo -or $defVal -gt $hi) { throw ("policy {0} Default {1} outside {2}" -f $p.Prop, $defVal, $p.Range) }
            if (($hi - $lo) -le 8) {
                $terms = @("NOT $($p.Prop)") + ($lo..$hi | ForEach-Object { "($($p.Prop) = `"$_`")" })
                $cond = $terms -join " OR "
            } else {
                # Reject signs, spaces, '#', 'x'/'X' (#x -> REG_BINARY), '%' (#% -> REG_EXPAND_SZ),
                # and ASCII letters so #[PROP] can never coerce into a non-REG_DWORD registry type.
                $badSub = @("-","+"," ","#","%","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z") |
                          ForEach-Object { "(NOT ({0} >< `"{1}`"))" -f $p.Prop, $_ }
                $cond = "(NOT {0}) OR ({1})" -f $p.Prop, ($badSub -join " AND ")
            }
        } else {
            throw ("policy {0} has unrecognised Range '{1}'" -f $p.Prop, $p.Range)
        }
        $desc = ("{0} must be a valid integer in {1}." -f $p.Prop, $p.Range) -replace "'", "''"
        $condSql = $cond -replace "'", "''"
        Exec ("INSERT INTO ``LaunchCondition`` (``Condition``,``Description``) VALUES ('{0}','{1}')" -f $condSql, $desc)

        $reg = "Reg" + $p.Comp
        Exec ("INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('{0}','{1}','INSTALLDIR',260,'{2}','{3}')" -f $p.Comp, $p.Guid, $p.Prop, $reg)
        Exec ("INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','{0}')" -f $p.Comp)
        # "#" makes it a REG_DWORD; the property supplies the decimal digits.
        Exec ("INSERT INTO ``Registry`` (``Registry``,``Root``,``Key``,``Name``,``Value``,``Component_``) VALUES ('{0}',2,'{1}','{2}','#[{3}]','{4}')" -f $reg, $PolicyKey, $p.Value, $p.Prop, $p.Comp)
    }
    Write-Host ("  policy values  : {0} exposed as properties" -f $Policies.Count)

    # --- .vordr association ---------------------------------------------------
    # On by default, because a file type nobody can open is not much of a file
    # type; VORDR_NOASSOC=1 skips it for deployments that manage associations
    # centrally.
    Exec ("INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('{0}','{1}','INSTALLDIR',260,'NOT {2}','RegAssocExt')" -f $AssocComp, $AssocGuid, $AssocProp)
    Exec ("INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','{0}')" -f $AssocComp)

    # A null Name column is how the Registry table writes a key's DEFAULT value,
    # so these INSERTs leave Name out entirely rather than passing an empty
    # string - an empty Name would create a value literally called "".
    function RegDefault([string]$key, [string]$path, [string]$value, [string]$comp) {
        Exec ("INSERT INTO ``Registry`` (``Registry``,``Root``,``Key``,``Value``,``Component_``) VALUES ('{0}',2,'{1}','{2}','{3}')" -f $key, $path, $value, $comp)
    }
    RegDefault "RegAssocExt"    "$ClassesKey\.vordr"                       $ProgId                      $AssocComp
    RegDefault "RegAssocProgId" "$ClassesKey\$ProgId"                      "Vordr vault"                $AssocComp
    RegDefault "RegAssocIcon"   "$ClassesKey\$ProgId\DefaultIcon"          "[INSTALLDIR]vordr.exe,0"    $AssocComp
    # "%1" is literal here - MSI's Formatted syntax reserves [] and {}, not %.
    # The quotes matter: without them a vault path containing a space arrives as
    # several arguments and gui_shell_arg sees only the first fragment.
    RegDefault "RegAssocCmd"    "$ClassesKey\$ProgId\shell\open\command"   '"[INSTALLDIR]vordr.exe" "%1"' $AssocComp
    # Name "-" deletes the key and everything under it on uninstall.  Aimed at
    # the ProgId we created and nothing else: removing only the VALUES would
    # leave .vordr pointing at an empty class, which Explorer renders as a file
    # type that exists and cannot be opened.  Deliberately NOT aimed at the
    # .vordr key itself, which other applications may have added themselves to.
    Exec ("INSERT INTO ``Registry`` (``Registry``,``Root``,``Key``,``Name``,``Component_``) VALUES ('RegAssocClean',2,'{0}\{1}','-','{2}')" -f $ClassesKey, $ProgId, $AssocComp)
    Write-Host ("  file assoc     : .vordr -> {0} (skip with {1}=1)" -f $ProgId, $AssocProp)

    $sizeX64   = (Get-Item $exePath).Length
    $sizeArm64 = (Get-Item $arm64Path).Length
    Exec "INSERT INTO ``File`` (``File``,``Component_``,``FileName``,``FileSize``,``Version``,``Language``,``Attributes``,``Sequence``) VALUES ('vordr_x64.exe','VordrExe','vordr.exe',$sizeX64,'$fv','1033',512,1)"
    Exec "INSERT INTO ``File`` (``File``,``Component_``,``FileName``,``FileSize``,``Version``,``Language``,``Attributes``,``Sequence``) VALUES ('vordr_arm64.exe','VordrExeArm64','vordr.exe',$sizeArm64,'$fv','1033',512,2)"
    Exec "INSERT INTO ``Media`` (``DiskId``,``LastSequence``,``DiskPrompt``,``Cabinet``,``VolumeLabel``,``Source``) VALUES (1,2,'','#vordr.cab','','')"

    Exec "INSERT INTO ``Shortcut`` (``Shortcut``,``Directory_``,``Name``,``Component_``,``Target``,``Arguments``,``Description``,``ShowCmd``,``WkDir``) VALUES ('VordrSC','ProgramMenuFolder','Vordr','VordrExe','[INSTALLDIR]vordr.exe','','Vordr password manager',1,'INSTALLDIR')"
    Exec "INSERT INTO ``Shortcut`` (``Shortcut``,``Directory_``,``Name``,``Component_``,``Target``,``Arguments``,``Description``,``ShowCmd``,``WkDir``) VALUES ('VordrSCArm64','ProgramMenuFolder','Vordr','VordrExeArm64','[INSTALLDIR]vordr.exe','','Vordr password manager',1,'INSTALLDIR')"

    # Upgrade: replace an existing install rather than sitting beside it, and
    # refuse to downgrade when a strictly newer version is already installed.
    #
    # Attributes is a bitfield and the two Inclusive bits are easy to get wrong,
    # because they are NOT 1 and 2:
    #     0x001 MigrateFeatures        0x100 VersionMinInclusive
    #     0x002 OnlyDetect             0x200 VersionMaxInclusive
    #     0x004 IgnoreRemoveFailure    0x400 LanguagesExclusive
    # This was 257 (0x101) - MigrateFeatures + VersionMin*Inclusive* - which left
    # VersionMax EXCLUSIVE.  Every version below this one was replaced correctly,
    # so it looked right, but installing 0.2.2 over an existing 0.2.2 detected
    # nothing and registered a SECOND product: two Add/Remove entries, two
    # ProductCodes, one set of files.  That is not a hypothetical - every build
    # gets a fresh ProductCode, so any test of the same version hits it.
    #
    # 768 = VersionMinInclusive | VersionMaxInclusive: replace anything from
    # 0.0.0 up to and including this version.  FindRelatedProducts always skips
    # our own ProductCode, so "including this version" can only ever match a
    # DIFFERENT build of it - exactly the case that was broken.
    #
    # 2 = OnlyDetect (WITHOUT VersionMinInclusive): detect any installed version
    # strictly greater than $productVersion into NEWERVERSIONDETECTED, then halt
    # in LaunchConditions before modifying the machine.
    $UPG_ATTR = 768
    $DOWNGRADE_ATTR = 2
    Exec "INSERT INTO ``Upgrade`` (``UpgradeCode``,``VersionMin``,``VersionMax``,``Language``,``Attributes``,``Remove``,``ActionProperty``) VALUES ('$UpgradeCode','0.0.0','$productVersion','',$UPG_ATTR,'','OLDERVERSIONBEINGUPGRADED')"
    Exec "INSERT INTO ``Upgrade`` (``UpgradeCode``,``VersionMin``,``VersionMax``,``Language``,``Attributes``,``Remove``,``ActionProperty``) VALUES ('$UpgradeCode','$productVersion','','',$DOWNGRADE_ATTR,'','NEWERVERSIONDETECTED')"
    Exec "INSERT INTO ``LaunchCondition`` (``Condition``,``Description``) VALUES ('NOT NEWERVERSIONDETECTED','A newer version of Vordr is already installed.')"

    # Standard sequence.  RemoveExistingProducts runs immediately after
    # InstallInitialize (before InstallFiles) so same-version rebuilds replace
    # the old binary instead of hitting MSI's equal-version skip rule; MSI
    # rollback restores the previous product if the install aborts mid-way.
    # Actions that establish properties for later actions run in the CLIENT
    # process.  Once the client's sequence finishes, the installer marks them
    # done - so if one is missing from InstallUISequence, the server-side pass
    # logs "Skipping <action>: already done on client side" and returns 0 without
    # running it.  It never ran anywhere, and nothing says so above verbose level.
    # FindRelatedProducts MUST precede LaunchConditions so NEWERVERSIONDETECTED
    # is populated before the downgrade guard evaluates.
    $clientSide = @(
        @("AppSearch",             "",   50),
        @("FindRelatedProducts",   "",  100),
        @("LaunchConditions",      "",  200)
    )
    $seq = $clientSide + @(
        @("CostInitialize",        "",  800),
        @("FileCost",              "",  900),
        @("CostFinalize",          "", 1000),
        @("InstallValidate",       "", 1400),
        @("InstallInitialize",     "", 1500),
        # RemoveExistingProducts EARLY - immediately after InstallInitialize, one
        # of the five positions Windows Installer accepts (anywhere else fails at
        # install time with error 2613, which msiexec /a never catches).
        #
        # Sequencing it after InstallFinalize silently breaks same-version
        # rebuilds: MSI only overwrites a versioned file when the incoming
        # FileVersion is strictly higher, so InstallFiles logs
        #     "Won't Overwrite; Existing file is of an equal version"
        # and leaves the old vordr.exe on disk while reporting success.  Removing
        # the old product before InstallFiles guarantees the new binary lands;
        # default MSI rollback restores the old product if installation fails.
        @("RemoveExistingProducts","", 1550),
        @("ProcessComponents",     "", 1600),
        @("UnpublishFeatures",     "", 1800),
        # Policy values are put back by WriteRegistryValues on every install, so
        # removing them first is what makes a re-run with different properties
        # actually change the machine instead of merging into the old state.
        @("RemoveRegistryValues",  "", 2600),
        @("RemoveShortcuts",       "", 3200),
        @("RemoveFiles",           "", 3500),
        @("InstallFiles",          "", 4000),
        @("CreateShortcuts",       "", 4500),
        @("WriteRegistryValues",   "", 5000),
        @("RegisterUser",          "", 6000),
        @("RegisterProduct",       "", 6100),
        @("PublishFeatures",       "", 6300),
        @("PublishProduct",        "", 6400),
        @("InstallFinalize",       "", 6600)
    )
    foreach ($s in $seq) {
        Exec ("INSERT INTO ``InstallExecuteSequence`` (``Action``,``Condition``,``Sequence``) VALUES ('{0}','{1}',{2})" -f $s[0], $s[1], $s[2])
    }
    # ,@(...) - without the leading comma ForEach-Object unrolls each pair into
    # the pipeline and the list becomes a flat run of strings, so $a[0] indexes
    # into "LaunchConditions" and inserts the single character 'L'.
    $uiSeq = @($clientSide | ForEach-Object { ,@($_[0], $_[2]) }) +
             @(@("CostInitialize",800),@("FileCost",900),@("CostFinalize",1000),@("ExecuteAction",1300))
    foreach ($a in $uiSeq) {
        Exec ("INSERT INTO ``InstallUISequence`` (``Action``,``Condition``,``Sequence``) VALUES ('{0}','',{1})" -f $a[0], $a[1])
    }
    foreach ($a in @(@("CostInitialize",800),@("FileCost",900),@("CostFinalize",1000),@("InstallValidate",1400),@("InstallInitialize",1500),@("InstallAdminPackage",3900),@("InstallFiles",4000),@("InstallFinalize",6600))) {
        Exec ("INSERT INTO ``AdminExecuteSequence`` (``Action``,``Condition``,``Sequence``) VALUES ('{0}','',{1})" -f $a[0], $a[1])
    }

    # --- self-check the one thing /a cannot catch ----------------------------
    # An administrative install does not run the upgrade logic, so a badly placed
    # RemoveExistingProducts sails through msiexec /a and then fails a REAL install
    # with error 2613.  It is only legal immediately after one of these anchors.
    $ordered  = $seq | Sort-Object { $_[2] }
    $names    = @($ordered | ForEach-Object { $_[0] })
    $idx      = [array]::IndexOf($names, "RemoveExistingProducts")
    $ifIdx    = [array]::IndexOf($names, "InstallFiles")
    $anchors  = @("InstallValidate","InstallInitialize","InstallExecute",
                  "InstallExecuteAgain","InstallFinalize")
    if ($idx -lt 1) { throw "RemoveExistingProducts is missing from InstallExecuteSequence" }
    $prev = $names[$idx-1]
    if ($anchors -notcontains $prev) {
        # -f binds tighter than +, so build the whole string first or the format
        # placeholders in the leading fragment are never substituted.
        $fmt = "RemoveExistingProducts follows '{0}' - Windows Installer only accepts it immediately after {1}. A real install would fail with error 2613."
        throw ($fmt -f $prev, ($anchors -join ", "))
    }
    if ($ifIdx -lt 0 -or $idx -ge $ifIdx) {
        throw "RemoveExistingProducts must precede InstallFiles so same-version rebuilds overwrite vordr.exe"
    }
    Write-Host ("  sequence check : RemoveExistingProducts follows {0} (< InstallFiles) - legal" -f $prev)

    # --- self-check the policy wiring ----------------------------------------
    # Every one of these is a silent failure in the field: the install succeeds,
    # the property is accepted, and nothing is written.  None of them shows up in
    # msiexec /a either, so they have to be caught here.
    $secure = $props["SecureCustomProperties"] -split ";"
    foreach ($p in $Policies) {
        if ($secure -notcontains $p.Prop) {
            throw ("{0} is missing from SecureCustomProperties - it would be dropped on the way to the elevated half of the install and silently do nothing" -f $p.Prop)
        }
        if ($p.Prop -cne $p.Prop.ToUpper()) {
            throw ("{0} is not all-uppercase, so MSI treats it as private and the command line cannot set it" -f $p.Prop)
        }
    }
    if ($secure -notcontains $AssocProp) { throw "$AssocProp is missing from SecureCustomProperties - the opt-out would be ignored" }
    if ($secure -notcontains "HOST_NATIVE_ARCH") { throw "HOST_NATIVE_ARCH is missing from SecureCustomProperties - ARM64 selection would be dropped on elevation" }
    $allGuids = @($ComponentGuid, $Arm64ComponentGuid, $AssocGuid) + @($Policies | ForEach-Object { $_.Guid })
    $dupAll = $allGuids | Group-Object | Where-Object { $_.Count -gt 1 }
    if ($dupAll) { throw ("component GUID reused: " + ($dupAll[0].Name)) }
    $dupComp = $Policies | Group-Object { $_.Comp } | Where-Object { $_.Count -gt 1 }
    if ($dupComp) { throw ("component name reused: " + $dupComp[0].Name) }
    foreach ($a in @("WriteRegistryValues","RemoveRegistryValues")) {
        if ($names -notcontains $a) { throw "$a is missing - the Registry table would never be processed" }
    }
    Write-Host ("  policy check   : {0} properties secure, unique and sequenced" -f $Policies.Count)

    $uiNames = @($uiSeq | ForEach-Object { $_[0] })
    foreach ($a in $clientSide) {
        if ($uiNames -notcontains $a[0]) {
            throw ("{0} is in InstallExecuteSequence but not InstallUISequence - the server would skip it as 'already done on client side' and it would never run at all" -f $a[0])
        }
    }
    Write-Host ("  client-side    : {0} present in both sequences" -f (($clientSide | ForEach-Object { $_[0] }) -join ", "))

    if (-not ($UPG_ATTR -band 512)) {
        throw "Upgrade.Attributes lacks VersionMaxInclusive (0x200) - a rebuild of $productVersion would install ALONGSIDE the existing one instead of replacing it"
    }
    Write-Host ("  upgrade check  : replaces 0.0.0 .. {0} inclusive" -f $productVersion)

    # --- summary information (required, and x64 must be declared) ------------
    # SummaryInformation(update-count) - Property is a PARAMETERISED property, which
    # PowerShell cannot assign directly, so this one genuinely needs InvokeMember.
    $si = $db.SummaryInformation(20)
    function SetSI([int]$id, $val) {
        $si.GetType().InvokeMember("Property","SetProperty",$null,$si,@($id,$val))
    }
    SetSI 1  1252                                   # codepage
    SetSI 2  "Vordr"                                # title
    SetSI 3  "Vordr password manager"               # subject
    SetSI 4  $Manufacturer                          # author
    SetSI 5  "Installer,MSI,Database"               # keywords
    SetSI 6  "Per-machine universal (x64 + ARM64) install of Vordr $productVersion"
    SetSI 7  "x64;1033"                             # template: 64-bit package (runs natively on x64 and Windows 11 on ARM)
    SetSI 9  ("{" + [guid]::NewGuid().ToString().ToUpper() + "}")   # package code
    SetSI 14 200                                    # min installer version
    SetSI 15 2                                      # word count: source is compressed
    $si.Persist()
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($si)

    $db.Commit()

    # --- embed the cab as a stream ------------------------------------------
    # _Streams is an implicit MSI table - it always exists and CREATE TABLE on it
    # fails.  Insert straight into it.
    $view = $db.OpenView("INSERT INTO ``_Streams`` (``Name``,``Data``) VALUES ('vordr.cab', ?)")
    $rec  = $installer.CreateRecord(1)
    $rec.SetStream(1, $cab)
    $view.Execute($rec)
    $view.Close()
    $db.Commit()
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($rec)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
    # the database keeps the .msi open until the COM objects are actually gone
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()

    Write-Host ""
    Write-Host ("  MSI            : {0}" -f $outMsi)
    Write-Host ("  size           : {0} bytes" -f (Get-Item $outMsi).Length)
    Write-Host ("  ProductCode    : {0}" -f $productCode)
    Write-Host ("  UpgradeCode    : {0}  (never change this)" -f $UpgradeCode)
    Write-Host ""
    Write-Host "  installs   %ProgramFiles%\$InstallDir\vordr.exe (native x64 or ARM64) + all-users Start Menu shortcut"
    Write-Host "  arch       auto-selected via AppSearch/RegLocator on HKLM\...\Environment\PROCESSOR_ARCHITECTURE"
    Write-Host "  scope      per-machine: elevation required, binary read-only to standard users"
    Write-Host "  owns       that file, the shortcut, and any policy value named below"
    Write-Host "  uninstall  removes exactly those; the vault and HKCU settings are untouched"
    Write-Host ""
    Write-Host ("  HKLM\{0}  - set only what you name; an unnamed value is not written," -f $PolicyKey)
    Write-Host "  and in Vordr a value's PRESENCE is what locks it against the user."
    Write-Host ""
    Write-Host ("    {0,-24} {1,-18} {2,-8} {3}" -f "PROPERTY", "VALUE", "RANGE", "MEANING (default)")
    foreach ($p in $Policies) {
        Write-Host ("    {0,-24} {1,-18} {2,-8} {3} ({4})" -f $p.Prop, $p.Value, $p.Range, $p.Doc, $p.Default)
    }
    Write-Host ""
    Write-Host "    msiexec /i `"$outMsi`" /qn VORDR_SECUREUNLOCK=1 VORDR_PWMINLEN=16"
    Write-Host ""
    Write-Host "  MSI does not remember properties: repeat them on upgrades too, or the"
    Write-Host "  old product's policy values are removed along with it."
    Write-Host ""
    Write-Host ("  .vordr        -> {0}, opened as an IMPORT source by [INSTALLDIR]vordr.exe" -f $ProgId)
    Write-Host ("                   registered by default; {0}=1 to leave associations alone" -f $AssocProp)
}
finally {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}
