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

    LaunchCondition rows validate every public policy property at install time
    (rejecting out-of-range, signed, or non-decimal values that could coerce
    #[PROP] away from REG_DWORD), and Vordr also clamps every value on read
    (gui_load_policy) as defense-in-depth for direct registry edits.

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
    @{ Prop="VORDR_PWMINLEN";        UserProp="VORDR_USER_PWMINLEN";        Value="PwMinLen";        Comp="PolPwMinLen";     UserComp="DefPwMinLen";     Guid="{D19F5EA9-D38C-4D8F-AB7D-7FA755005F6A}"; UserGuid="{1A4E8C10-5B2F-4D91-9E3A-6F8B1C2D4E01}"; Range="1-256";   Default="12";  Doc="minimum master-password length" }
    @{ Prop="VORDR_PWMINCLASSES";    UserProp="VORDR_USER_PWMINCLASSES";    Value="PwMinClasses";    Comp="PolPwMinCls";     UserComp="DefPwMinCls";     Guid="{A00BACFE-4D80-4660-9838-6CDACB2B4FD0}"; UserGuid="{2B5F9D21-6C30-4EA2-AF4B-709C2D3E5F02}"; Range="1-4";     Default="3";   Doc="character classes a master password must mix" }
    @{ Prop="VORDR_SECUREUNLOCK";    UserProp="VORDR_USER_SECUREUNLOCK";    Value="SecureUnlock";    Comp="PolSecUnlock";    UserComp="DefSecUnlock";    Guid="{71D60D6C-C613-4D0E-BA73-4DB5FE8BD552}"; UserGuid="{3C60AE32-7D41-4FB3-B05C-81AD3E4F6003}"; Range="0/1";     Default="1";   Doc="type the master password on an isolated desktop" }
    @{ Prop="VORDR_TPMUNLOCK";       UserProp="VORDR_USER_TPMUNLOCK";       Value="TpmUnlock";       Comp="PolTpmUnlock";    UserComp="DefTpmUnlock";    Guid="{E644B890-A962-45CA-923D-B1C721BBAF5A}"; UserGuid="{4D71BF43-8E52-40C4-816D-92BE4F507104}"; Range="0/1";     Default="1";   Doc="allow TPM convenience unlock" }
    @{ Prop="VORDR_TPMREQUIREHELLO"; UserProp="VORDR_USER_TPMREQUIREHELLO"; Value="TpmRequireHello"; Comp="PolTpmHello";     UserComp="DefTpmHello";     Guid="{DABA9DC0-F726-41CE-9291-45D3ED06D498}"; UserGuid="{5E82C054-9F63-41D5-927E-A3CF50618205}"; Range="0/1";     Default="0";   Doc="require Hello/PIN for TPM unlock" }
    @{ Prop="VORDR_CLIPSECONDS";     UserProp="VORDR_USER_CLIPSECONDS";     Value="ClipSeconds";     Comp="PolClipSecs";     UserComp="DefClipSecs";     Guid="{0E7CC768-6CA6-492F-8283-A22866EDDADE}"; UserGuid="{6F93D165-A074-42E6-A38F-B4D061729306}"; Range="0-3600";  Default="20";  Doc="clipboard auto-clear delay, 0 = never copy-and-forget" }
    @{ Prop="VORDR_IDLELOCKMIN";     UserProp="VORDR_USER_IDLELOCKMIN";     Value="IdleLockMin";     Comp="PolIdleLock";     UserComp="DefIdleLock";     Guid="{065AAA8F-F053-4F6D-83EE-2F6CC73F6A2E}"; UserGuid="{70A4E276-B185-43F7-B490-C5E17283A407}"; Range="0-1440";  Default="10";  Doc="idle minutes before auto-lock, 0 = off" }
    @{ Prop="VORDR_LOCKONWINLOCK";   UserProp="VORDR_USER_LOCKONWINLOCK";   Value="LockOnWinLock";   Comp="PolWinLock";      UserComp="DefWinLock";      Guid="{7DCACD47-C2DD-4E02-BA29-5BFA6C1B5258}"; UserGuid="{81B5F387-C296-4408-85A1-D6F28394B508}"; Range="0/1";     Default="1";   Doc="lock the vault when Windows locks" }
    @{ Prop="VORDR_PWVERIFYDAYS";    UserProp="VORDR_USER_PWVERIFYDAYS";    Value="PwVerifyDays";    Comp="PolPwDays";       UserComp="DefPwDays";       Guid="{558B9574-C9E7-4A05-99B2-6792F0850BFB}"; UserGuid="{92C60498-D3A7-4519-96B2-E70394A5C609}"; Range="0-3650";  Default="30";  Doc="re-verify the master password every N days under TPM unlock" }
    @{ Prop="VORDR_NOHISTORY";       UserProp="VORDR_USER_NOHISTORY";       Value="NoHistory";       Comp="PolNoHistory";    UserComp="DefNoHistory";    Guid="{835B8733-0B32-4DFF-AE70-3DDB1F261FA6}"; UserGuid="{A3D715A9-E4B8-462A-A7C3-F814A5B6D70A}"; Range="0/1";     Default="0";   Doc="do not keep per-entry history" }
    @{ Prop="VORDR_NOPHONETIC";      UserProp="VORDR_USER_NOPHONETIC";      Value="NoPhonetic";      Comp="PolNoPhonetic";   UserComp="DefNoPhonetic";   Guid="{2C20D1F4-69BF-44A1-B131-44DFBE4DB6F3}"; UserGuid="{B4E826BA-F5C9-473B-B8D4-0925B6C7E80B}"; Range="0/1";     Default="0";   Doc="disable the phonetic secret reader" }
    @{ Prop="VORDR_NOPREVIEW";       UserProp="VORDR_USER_NOPREVIEW";       Value="NoPreview";       Comp="PolNoPreview";    UserComp="DefNoPreview";    Guid="{7887784C-D701-466E-B920-14E2DD01FB71}"; UserGuid="{C5F937CB-06DA-484C-89E5-1A36C7D8F90C}"; Range="0/1";     Default="0";   Doc="attachments download only, never preview via another app" }
    @{ Prop="VORDR_ALLOWUNCVAULT";       Value="AllowUncVault";       Comp="PolAllowUnc";     Guid="{C4829E51-3D74-4A8B-9162-5E1B0F47A3C9}"; HklmOnly=$true; Range="0/1";     Default="0";   Doc="allow opening vault files over UNC/network shares (HKLM-only)" }
    @{ Prop="VORDR_ALLOWSCREENCAPTURE";  Value="AllowScreenCapture";  Comp="PolAllowCap";     Guid="{6D3A14B8-79E2-4F55-8A1C-34B8E92D71F0}"; HklmOnly=$true; Range="0/1";     Default="0";   Doc="allow screen capture of Vordr windows (0 = WDA_EXCLUDEFROMCAPTURE)" }
    @{ Prop="VORDR_LOGLEVEL";            UserProp="VORDR_USER_LOGLEVEL";        Value="LogLevel";            Comp="PolLogLevel";     UserComp="DefLogLevel";     Guid="{A3BD3F2C-326F-4749-A57E-A78D1EC4AC0E}"; UserGuid="{D60A48DC-17EB-495D-9AF6-2B47D8E90A0D}"; Range="0-4";     Default="0";   Doc="audit-log verbosity, 0 = off" }
    @{ Prop="VORDR_UISCHEME";            UserProp="VORDR_USER_UISCHEME";        Value="ui_scheme";           Comp="PolUiScheme";     UserComp="DefUiScheme";     Guid="{9B70EE1D-7B67-44A0-8C02-06B7BD8F982F}"; UserGuid="{E71B59ED-28FC-4A6E-AB07-3C58E9FA1B0E}"; Range="0-9";     Default="6";   Doc="colour scheme (6 = Gruvbox default, 9 = Follow Windows)" }
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
$AssocComp     = "FileAssoc"
$AssocGuid     = "{4B1E86D2-95AF-4C33-9F0E-2A6D74C1B5E8}"
$AssocProp     = "VORDR_NOASSOC"            # set to anything to skip the registration
$ProgId        = "Vordr.Vault"
$ClassesKey    = "SOFTWARE\Classes"
# --- Start with Windows (HKLM Run, minimized to notification area; on by default) --
$AutoStartComp = "VordrAutoStart"
$AutoStartGuid = "{3D9A6F21-7E4B-4C80-B2D1-9F4C6A3E8B15}"
$AutoStartProp = "VORDR_AUTOSTART"          # 1 by default; set to 0 to skip HKLM\...\Run\Vordr
$RunKey        = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

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
    if ($peBytes.Length -lt 0x100 -or [BitConverter]::ToUInt16($peBytes, 0) -ne 0x5A4D) {
        throw "$Path is not a valid MZ/PE executable."
    }
    $peOff    = [BitConverter]::ToInt32($peBytes, 0x3C)
    if ($peOff -lt 0x40 -or ($peOff + 24 + 216) -gt $peBytes.Length -or [BitConverter]::ToUInt32($peBytes, $peOff) -ne 0x00004550) {
        throw "$Path has an invalid PE header offset or signature."
    }
    $machine  = [BitConverter]::ToUInt16($peBytes, $peOff + 4)
    if ($machine -ne $ExpectMachine) {
        throw ("{0} has PE Machine 0x{1:X4}, expected 0x{2:X4}" -f $Path, $machine, $ExpectMachine)
    }
    $coffTs   = [BitConverter]::ToInt32($peBytes, $peOff + 8)
    if ($coffTs -ne 0) {
        throw "$Path has non-zero COFF TimeDateStamp (0x$($coffTs.ToString('X8'))) - not a normalised release binary."
    }
    $fileChar = [BitConverter]::ToUInt16($peBytes, $peOff + 22)
    if ($fileChar -band 0x0001) {
        throw "$Path has IMAGE_FILE_RELOCS_STRIPPED set - ASLR relocations missing."
    }
    $nSect    = [BitConverter]::ToUInt16($peBytes, $peOff + 6)
    $optSize  = [BitConverter]::ToUInt16($peBytes, $peOff + 20)
    $optOff   = $peOff + 24
    if ($optSize -lt 216 -or ($optOff + $optSize + $nSect * 40) -gt $peBytes.Length) {
        throw "$Path has truncated OptionalHeader or section table."
    }
    $optMagic = [BitConverter]::ToUInt16($peBytes, $optOff)
    if ($optMagic -ne 0x020B) {
        throw ("{0} OptionalHeader Magic 0x{1:X4} != 0x020B (PE32+)" -f $Path, $optMagic)
    }
    $dllChar  = [BitConverter]::ToUInt16($peBytes, $optOff + 70)
    if (($dllChar -band 0x0160) -ne 0x0160) {
        throw ("{0} DllCharacteristics 0x{1:X4} lacks HIGH_ENTROPY_VA|DYNAMIC_BASE|NX_COMPAT" -f $Path, $dllChar)
    }
    $ddOff    = $optOff + 112                  # PE32+ DataDirectory[0]
    $nDdir    = [BitConverter]::ToUInt32($peBytes, $ddOff - 4)
    if ($nDdir -le 12) {
        throw "$Path OptionalHeader has only $nDdir DataDirectories (expected > 12)."
    }
    $sectOff  = $optOff + $optSize
    $sects    = @()
    for ($si = 0; $si -lt $nSect; $si++) {
        $s   = $sectOff + $si * 40
        $va  = [BitConverter]::ToUInt32($peBytes, $s + 12)
        $vsz = [BitConverter]::ToUInt32($peBytes, $s + 8)
        $raw = [BitConverter]::ToUInt32($peBytes, $s + 20)
        $rsz = [BitConverter]::ToUInt32($peBytes, $s + 16)
        $ch  = [BitConverter]::ToUInt32($peBytes, $s + 36)
        if (([int64]$raw + [int64]$rsz) -gt $peBytes.Length) {
            throw ("{0} section #{1} raw range runs past EOF" -f $Path, $si)
        }
        if (($ch -band 0xA0000000L) -eq 0xA0000000L) {
            throw ("{0} section #{1} is both WRITABLE and EXECUTABLE (0x{2:X8})" -f $Path, $si, $ch)
        }
        $span = if ($vsz -gt 0 -and $vsz -lt $rsz) { $vsz } else { $rsz }
        $sects += ,@{ Va=$va; Span=$span; Raw=$raw; Rsz=$rsz; Ch=$ch }
    }
    $resolveRva = {
        param([uint32]$rva)
        foreach ($sc in $sects) {
            if ($rva -ge $sc.Va -and $rva -lt ($sc.Va + $sc.Span)) {
                $delta = [int64]($rva - $sc.Va)
                return @{ Off = [int]($sc.Raw + $delta); Ch = $sc.Ch; Rem = [int64]($sc.Span - $delta) }
            }
        }
        return $null
    }
    # LOAD_CONFIG (DataDirectory[10]): must be 8-byte aligned, full-span, read-only, DependentLoadFlags == 0x0800
    $lcRva = [BitConverter]::ToUInt32($peBytes, $ddOff + 10 * 8)
    $lcSz  = [BitConverter]::ToUInt32($peBytes, $ddOff + 10 * 8 + 4)
    if ($lcRva -eq 0 -or $lcSz -lt 0x50 -or (($lcRva -band 7) -ne 0)) {
        throw ("{0} missing, truncated, or misaligned LOAD_CONFIG directory (rva=0x{1:X}, size={2})" -f $Path, $lcRva, $lcSz)
    }
    $lcLoc = & $resolveRva $lcRva
    if ($null -eq $lcLoc -or $lcLoc.Rem -lt $lcSz -or ($lcLoc.Off + $lcSz) -gt $peBytes.Length) {
        throw "$Path LOAD_CONFIG RVA does not map to a valid PE section span."
    }
    if (($lcLoc.Ch -band 0x80000000L) -ne 0) { throw "$Path LOAD_CONFIG resides in a writable section." }
    $lcStructSz = [BitConverter]::ToUInt32($peBytes, $lcLoc.Off)
    $depFlags   = [BitConverter]::ToUInt16($peBytes, $lcLoc.Off + 0x4E)
    if ($lcStructSz -lt 0x50 -or $depFlags -ne 0x0800) {
        throw ("{0} LOAD_CONFIG DependentLoadFlags=0x{1:X4} (size=0x{2:X}), expected 0x0800" -f $Path, $depFlags, $lcStructSz)
    }
    $dbgRva  = [BitConverter]::ToUInt32($peBytes, $ddOff + 6 * 8)
    $dbgSz   = [BitConverter]::ToUInt32($peBytes, $ddOff + 6 * 8 + 4)
    $hasCet  = $false
    if ($dbgRva -ne 0 -and $dbgSz -ge 28) {
        $dbgLoc = & $resolveRva $dbgRva
        if ($null -ne $dbgLoc -and $dbgLoc.Rem -ge $dbgSz -and ($dbgLoc.Off + $dbgSz) -le $peBytes.Length) {
            $dbgCount = [int][Math]::Floor($dbgSz / 28)
            for ($di = 0; $di -lt $dbgCount; $di++) {
                $de    = $dbgLoc.Off + $di * 28
                $dtype = [BitConverter]::ToUInt32($peBytes, $de + 12)
                if ($dtype -eq 20) {
                    $dsz   = [BitConverter]::ToUInt32($peBytes, $de + 16)
                    $drva  = [BitConverter]::ToUInt32($peBytes, $de + 20)
                    $dptr  = [BitConverter]::ToUInt32($peBytes, $de + 24)
                    # A4-17: require mapped non-zero RVA & PointerToRawData in a read-only section
                    if ($drva -ne 0 -and $dptr -ne 0 -and $dsz -ge 4 -and ($dptr + 4) -le $peBytes.Length) {
                        $cetLoc = & $resolveRva $drva
                        if ($null -ne $cetLoc -and $cetLoc.Off -eq $dptr -and $cetLoc.Rem -ge 4 -and
                            (($cetLoc.Ch -band 0x80000000L) -eq 0) -and
                            (([BitConverter]::ToUInt32($peBytes, $dptr) -band 0x0001) -eq 0x0001)) {
                            $hasCet = $true
                        }
                    }
                }
            }
        }
    }
    if ($RequireCet -and -not $hasCet) {
        throw "$Path lacks valid IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS (/CETCOMPAT bit 0x1) - never package a 'nohw' build."
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
    function ExecParams([string]$sql, [object[]]$vals) {
        try {
            $view = $db.OpenView($sql)
            $rec  = $installer.CreateRecord($vals.Count)
            for ($i = 0; $i -lt $vals.Count; $i++) {
                if ($vals[$i] -is [int]) { $rec.IntegerData($i + 1) = $vals[$i] }
                else                     { $rec.StringData($i + 1)  = [string]$vals[$i] }
            }
            $view.Execute($rec)
            $view.Close()
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($rec)
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view)
        } catch {
            throw ("MSI SQL failed:`n  {0}`n  vals={1}`n  -> {2}" -f $sql, ($vals -join " | "), $_.Exception.Message)
        }
    }

    # schema
    Exec "CREATE TABLE ``Property`` (``Property`` CHAR(72) NOT NULL, ``Value`` CHAR(0) NOT NULL PRIMARY KEY ``Property``)"
    Exec "CREATE TABLE ``Directory`` (``Directory`` CHAR(72) NOT NULL, ``Directory_Parent`` CHAR(72), ``DefaultDir`` CHAR(255) NOT NULL PRIMARY KEY ``Directory``)"
    Exec "CREATE TABLE ``Component`` (``Component`` CHAR(72) NOT NULL, ``ComponentId`` CHAR(38), ``Directory_`` CHAR(72) NOT NULL, ``Attributes`` SHORT NOT NULL, ``Condition`` CHAR(255), ``KeyPath`` CHAR(72) PRIMARY KEY ``Component``)"
    Exec "CREATE TABLE ``Feature`` (``Feature`` CHAR(38) NOT NULL, ``Feature_Parent`` CHAR(38), ``Title`` CHAR(64), ``Description`` CHAR(255), ``Display`` SHORT, ``Level`` SHORT NOT NULL, ``Directory_`` CHAR(72), ``Attributes`` SHORT NOT NULL PRIMARY KEY ``Feature``)"
    Exec "CREATE TABLE ``FeatureComponents`` (``Feature_`` CHAR(38) NOT NULL, ``Component_`` CHAR(72) NOT NULL PRIMARY KEY ``Feature_``, ``Component_``)"
    Exec "CREATE TABLE ``File`` (``File`` CHAR(72) NOT NULL, ``Component_`` CHAR(72) NOT NULL, ``FileName`` CHAR(255) NOT NULL, ``FileSize`` LONG NOT NULL, ``Version`` CHAR(72), ``Language`` CHAR(20), ``Attributes`` SHORT, ``Sequence`` SHORT NOT NULL PRIMARY KEY ``File``)"
    Exec "CREATE TABLE ``Media`` (``DiskId`` SHORT NOT NULL, ``LastSequence`` SHORT NOT NULL, ``DiskPrompt`` CHAR(64), ``Cabinet`` CHAR(255), ``VolumeLabel`` CHAR(32), ``Source`` CHAR(72) PRIMARY KEY ``DiskId``)"
    Exec "CREATE TABLE ``InstallExecuteSequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
    Exec "CREATE TABLE ``InstallUISequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
    # AdminExecuteSequence is intentionally omitted: a universal MSI carries both
    # x64 and ARM64 payloads named vordr.exe in INSTALLDIR, and msiexec /a ignores
    # component conditions so an administrative unpack would overwrite one with the other.
    Exec "CREATE TABLE ``AdvtExecuteSequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
    Exec "CREATE TABLE ``Upgrade`` (``UpgradeCode`` CHAR(38) NOT NULL, ``VersionMin`` CHAR(20), ``VersionMax`` CHAR(20), ``Language`` CHAR(255), ``Attributes`` LONG NOT NULL, ``Remove`` CHAR(255), ``ActionProperty`` CHAR(72) NOT NULL PRIMARY KEY ``UpgradeCode``, ``VersionMin``, ``VersionMax``, ``Language``, ``Attributes``)"
    Exec "CREATE TABLE ``LaunchCondition`` (``Condition`` CHAR(255) NOT NULL, ``Description`` CHAR(255) NOT NULL PRIMARY KEY ``Condition``)"
    Exec "CREATE TABLE ``CreateFolder`` (``Directory_`` CHAR(72) NOT NULL, ``Component_`` CHAR(72) NOT NULL PRIMARY KEY ``Directory_``, ``Component_``)"
    # Windows Installer 5.0 requires all 5 columns (MsiLockPermissionsEx PK, LockObject, Table, SDDLText, Condition);
    # omitting Condition fails real msiexec /i installs with MSI Error 2235 (A4-01).
    Exec "CREATE TABLE ``MsiLockPermissionsEx`` (``MsiLockPermissionsEx`` CHAR(72) NOT NULL, ``LockObject`` CHAR(72) NOT NULL, ``Table`` CHAR(32) NOT NULL, ``SDDLText`` CHAR(0) NOT NULL, ``Condition`` CHAR(255) PRIMARY KEY ``MsiLockPermissionsEx``)"
    Exec "CREATE TABLE ``Shortcut`` (``Shortcut`` CHAR(72) NOT NULL, ``Directory_`` CHAR(72) NOT NULL, ``Name`` CHAR(128) NOT NULL, ``Component_`` CHAR(72) NOT NULL, ``Target`` CHAR(72) NOT NULL, ``Arguments`` CHAR(255), ``Description`` CHAR(255), ``Hotkey`` SHORT, ``Icon_`` CHAR(72), ``IconIndex`` SHORT, ``ShowCmd`` SHORT, ``WkDir`` CHAR(72) PRIMARY KEY ``Shortcut``)"
    Exec "CREATE TABLE ``Registry`` (``Registry`` CHAR(72) NOT NULL, ``Root`` SHORT NOT NULL, ``Key`` CHAR(255) NOT NULL, ``Name`` CHAR(255), ``Value`` CHAR(0), ``Component_`` CHAR(72) NOT NULL PRIMARY KEY ``Registry``)"
    Exec "CREATE TABLE ``AppSearch`` (``Property`` CHAR(72) NOT NULL, ``Signature_`` CHAR(72) NOT NULL PRIMARY KEY ``Property``, ``Signature_``)"
    Exec "CREATE TABLE ``RegLocator`` (``Signature_`` CHAR(72) NOT NULL, ``Root`` SHORT NOT NULL, ``Key`` CHAR(255) NOT NULL, ``Name`` CHAR(255), ``Type`` SHORT PRIMARY KEY ``Signature_``)"
    # AppSearch always queries the Signature table even for raw RegLocator lookups;
    # omitting this empty table fails real installs with MSI error 2228.
    Exec "CREATE TABLE ``Signature`` (``Signature`` CHAR(72) NOT NULL, ``FileName`` CHAR(255) NOT NULL, ``MinVersion`` CHAR(20), ``MaxVersion`` CHAR(20), ``MinSize`` LONG, ``MaxSize`` LONG, ``MinDate`` LONG, ``MaxDate`` LONG, ``Languages`` CHAR(255) PRIMARY KEY ``Signature``)"
    # UI tables (pure declarative Windows Installer 5.0 wizard, zero custom actions)
    Exec "CREATE TABLE ``Binary`` (``Name`` CHAR(72) NOT NULL, ``Data`` OBJECT NOT NULL PRIMARY KEY ``Name``)"
    Exec "CREATE TABLE ``Icon`` (``Name`` CHAR(72) NOT NULL, ``Data`` OBJECT NOT NULL PRIMARY KEY ``Name``)"
    Exec "CREATE TABLE ``TextStyle`` (``TextStyle`` CHAR(72) NOT NULL, ``FaceName`` CHAR(32) NOT NULL, ``Size`` SHORT NOT NULL, ``Color`` LONG, ``StyleBits`` SHORT PRIMARY KEY ``TextStyle``)"
    Exec "CREATE TABLE ``Dialog`` (``Dialog`` CHAR(72) NOT NULL, ``HCentering`` SHORT NOT NULL, ``VCentering`` SHORT NOT NULL, ``Width`` SHORT NOT NULL, ``Height`` SHORT NOT NULL, ``Attributes`` LONG, ``Title`` CHAR(128), ``Control_First`` CHAR(50) NOT NULL, ``Control_Default`` CHAR(50), ``Control_Cancel`` CHAR(50) PRIMARY KEY ``Dialog``)"
    Exec "CREATE TABLE ``Control`` (``Dialog_`` CHAR(72) NOT NULL, ``Control`` CHAR(50) NOT NULL, ``Type`` CHAR(20) NOT NULL, ``X`` SHORT NOT NULL, ``Y`` SHORT NOT NULL, ``Width`` SHORT NOT NULL, ``Height`` SHORT NOT NULL, ``Attributes`` LONG, ``Property`` CHAR(50), ``Text`` CHAR(0), ``Control_Next`` CHAR(50), ``Help`` CHAR(50) PRIMARY KEY ``Dialog_``, ``Control``)"
    Exec "CREATE TABLE ``ControlEvent`` (``Dialog_`` CHAR(72) NOT NULL, ``Control_`` CHAR(50) NOT NULL, ``Event`` CHAR(50) NOT NULL, ``Argument`` CHAR(255) NOT NULL, ``Condition`` CHAR(255) NOT NULL, ``Ordering`` SHORT PRIMARY KEY ``Dialog_``, ``Control_``, ``Event``, ``Argument``, ``Condition``)"
    Exec "CREATE TABLE ``ControlCondition`` (``Dialog_`` CHAR(72) NOT NULL, ``Control_`` CHAR(50) NOT NULL, ``Action`` CHAR(50) NOT NULL, ``Condition`` CHAR(255) NOT NULL PRIMARY KEY ``Dialog_``, ``Control_``, ``Action``, ``Condition``)"
    Exec "CREATE TABLE ``EventMapping`` (``Dialog_`` CHAR(72) NOT NULL, ``Control_`` CHAR(50) NOT NULL, ``Event`` CHAR(50) NOT NULL, ``Attribute`` CHAR(50) NOT NULL PRIMARY KEY ``Dialog_``, ``Control_``, ``Event``)"
    Exec "CREATE TABLE ``RadioButton`` (``Property`` CHAR(72) NOT NULL, ``Order`` SHORT NOT NULL, ``Value`` CHAR(64) NOT NULL, ``X`` SHORT NOT NULL, ``Y`` SHORT NOT NULL, ``Width`` SHORT NOT NULL, ``Height`` SHORT NOT NULL, ``Text`` CHAR(64), ``Help`` CHAR(50) PRIMARY KEY ``Property``, ``Order``)"
    Exec "CREATE TABLE ``ListBox`` (``Property`` CHAR(72) NOT NULL, ``Order`` SHORT NOT NULL, ``Value`` CHAR(64) NOT NULL, ``Text`` CHAR(64) PRIMARY KEY ``Property``, ``Order``)"
    Exec "CREATE TABLE ``ComboBox`` (``Property`` CHAR(72) NOT NULL, ``Order`` SHORT NOT NULL, ``Value`` CHAR(64) NOT NULL, ``Text`` CHAR(64) PRIMARY KEY ``Property``, ``Order``)"
    Exec "CREATE TABLE ``CheckBox`` (``Property`` CHAR(72) NOT NULL, ``Value`` CHAR(64) PRIMARY KEY ``Property``)"
    Exec "CREATE TABLE ``ActionText`` (``Action`` CHAR(72) NOT NULL, ``Description`` CHAR(0), ``Template`` CHAR(0) PRIMARY KEY ``Action``)"
    Exec "CREATE TABLE ``UIText`` (``Key`` CHAR(72) NOT NULL, ``Text`` CHAR(255) PRIMARY KEY ``Key``)"
    Exec "CREATE TABLE ``Error`` (``Error`` SHORT NOT NULL, ``Message`` CHAR(0) PRIMARY KEY ``Error``)"
    # NO RemoveFile table.  MSI removes a component's own files on uninstall
    # automatically; RemoveFile exists to delete things the installer did NOT
    # install, which for a password manager is how you would delete someone's
    # vault.  Its absence is the safeguard - do not add it.

    # --- interactive UI metadata for all 16 HKLM policies --------------------
    # Driven by a master-detail ListBox + right-side inspector (enforce/lock
    # checkbox + typed value control).  None of the VORDR_* properties receive
    # defaults in the Property table, so silent /qn installs write zero policy
    # rows unless explicitly passed on the command line.
    $UiPolicyMeta = @{
        "PwMinLen"           = @{ Title="Minimum password length";    Kind="int";  Min=1; Max=256 }
        "PwMinClasses"       = @{ Title="Password character classes"; Kind="enum"; Items=@(@("1","1 — Any characters"),@("2","2 — Two classes"),@("3","3 — Three classes (default)"),@("4","4 — All four classes")) }
        "SecureUnlock"       = @{ Title="Secure Unlock desktop";      Kind="bool" }
        "TpmUnlock"          = @{ Title="TPM convenience unlock";     Kind="bool" }
        "TpmRequireHello"    = @{ Title="Windows Hello for TPM";      Kind="bool" }
        "ClipSeconds"        = @{ Title="Clipboard auto-clear (sec)"; Kind="int";  Min=0; Max=3600 }
        "IdleLockMin"        = @{ Title="Idle auto-lock (min)";       Kind="int";  Min=0; Max=1440 }
        "LockOnWinLock"      = @{ Title="Lock on Windows lock";       Kind="bool" }
        "PwVerifyDays"       = @{ Title="Password reminder (days)";   Kind="int";  Min=0; Max=3650 }
        "NoHistory"          = @{ Title="Disable entry history";      Kind="bool" }
        "NoPhonetic"         = @{ Title="Disable phonetic reader";    Kind="bool" }
        "NoPreview"          = @{ Title="Disable attachment preview"; Kind="bool" }
        "AllowUncVault"      = @{ Title="Allow UNC / network vaults"; Kind="bool" }
        "AllowScreenCapture" = @{ Title="Allow screen capture";       Kind="bool" }
        "LogLevel"           = @{ Title="Audit log verbosity";        Kind="enum"; Items=@(@("0","0 — Off (default)"),@("1","1 — Errors"),@("2","2 — Warnings"),@("3","3 — Info"),@("4","4 — Debug")) }
        "ui_scheme"          = @{ Title="Colour scheme";              Kind="enum"; Items=@(
            @("0","0 — Light"),@("1","1 — Sepia"),@("2","2 — Solarized"),
            @("3","3 — Nord"),@("4","4 — Midnight"),@("5","5 — Sapphire"),
            @("6","6 — Gruvbox (default)"),@("7","7 — Catppuccin"),@("8","8 — OLED Black"),
            @("9","9 — Follow Windows")) }
    }

    $productCode = "{" + [guid]::NewGuid().ToString().ToUpper() + "}"
    $userPolicyProps = @($Policies | Where-Object { $_.UserProp } | ForEach-Object { $_.UserProp })
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
        "ARPPRODUCTICON"     = "VordrIcon.exe"
        "ARPURLINFOABOUT"    = "https://github.com/xxtsxx/Vordr"
        "ARPHELPLINK"        = "https://github.com/xxtsxx/Vordr/blob/master/SECURITY.md"
        # Standard Windows Installer UI wiring properties
        "DefaultUIFont"      = "VordrFontBody"
        "ErrorDialog"        = "ErrorDlg"
        "_BrowseProperty"    = "INSTALLDIR"
        "UI_ASSOC"           = "1"
        "UI_AUTOSTART"       = "1"
        "VORDR_AUTOSTART"    = "1"
        "UI_LOCKED"          = "1"
        "UI_SEL_POL"         = $Policies[0].Value
        # Public properties reach the elevated half of a per-machine install only
        # if they are listed here.  Miss one and it silently has no effect - the
        # property is set, the component condition still evaluates false.
        "SecureCustomProperties" = (@("INSTALLDIR", "OLDERVERSIONBEINGUPGRADED", "NEWERVERSIONDETECTED", "HOST_NATIVE_ARCH", $AssocProp, $AutoStartProp) + ($Policies | ForEach-Object { $_.Prop }) + $userPolicyProps) -join ";"
    }
    for ($pi = 0; $pi -lt $Policies.Count; $pi++) {
        $props["UV_$pi"] = $Policies[$pi].Default
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
    # Explicit SDDL ACLs (Windows Installer 5.0 MsiLockPermissionsEx): protected
    # DACL granting SYSTEM & Administrators full control, Built-in Users read+execute.
    $dirSddl  = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
    $fileSddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
    Exec "INSERT INTO ``CreateFolder`` (``Directory_``,``Component_``) VALUES ('INSTALLDIR','VordrExe')"
    Exec "INSERT INTO ``CreateFolder`` (``Directory_``,``Component_``) VALUES ('INSTALLDIR','VordrExeArm64')"
    Exec "INSERT INTO ``MsiLockPermissionsEx`` (``MsiLockPermissionsEx``,``LockObject``,``Table``,``SDDLText``) VALUES ('LockInstallDir','INSTALLDIR','CreateFolder','$dirSddl')"
    Exec "INSERT INTO ``MsiLockPermissionsEx`` (``MsiLockPermissionsEx``,``LockObject``,``Table``,``SDDLText``) VALUES ('LockVordrX64','vordr_x64.exe','File','$fileSddl')"
    Exec "INSERT INTO ``MsiLockPermissionsEx`` (``MsiLockPermissionsEx``,``LockObject``,``Table``,``SDDLText``) VALUES ('LockVordrArm64','vordr_arm64.exe','File','$fileSddl')"
    Exec "INSERT INTO ``Feature`` (``Feature``,``Feature_Parent``,``Title``,``Description``,``Display``,``Level``,``Directory_``,``Attributes``) VALUES ('Main','','Vordr','Vordr password manager',1,1,'INSTALLDIR',0)"
    Exec "INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','VordrExe')"
    Exec "INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','VordrExeArm64')"

    # --- one component per HKLM policy + one permanent HKCU default component -
    # Attributes 4 = the registry row is the key path; 256 = write to the 64-bit
    # view.  Without 256 an x64 package puts these under WOW6432Node, where the
    # 64-bit vordr.exe would never look - the install would appear to succeed and
    # the policy would simply not take effect.
    # For HKCU user defaults (Def*), add Permanent (16 -> 276) so uninstalling
    # Vordr NEVER deletes user-editable HKCU preferences.
    function Add-PolicyLaunchGuards([string]$propName, [string]$range, [int]$defVal) {
        $desc = "{0} must be a valid integer in {1}." -f $propName, $range
        $condList = @()
        if ($range -eq "0/1") {
            if ($defVal -lt 0 -or $defVal -gt 1) { throw ("policy {0} Default {1} outside 0/1" -f $propName, $defVal) }
            $condList += ("(NOT {0}) OR ({0} = `"0`") OR ({0} = `"1`")" -f $propName)
        } elseif ($range -match '^(\d+)-(\d+)$') {
            $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
            if ($defVal -lt $lo -or $defVal -gt $hi) { throw ("policy {0} Default {1} outside {2}" -f $propName, $defVal, $range) }
            if (($hi - $lo) -le 5) {
                $terms = @("NOT $propName") + ($lo..$hi | ForEach-Object { "($propName = `"$_`")" })
                $condList += ($terms -join " OR ")
            } else {
                # Reject signs, whitespace, punctuation, and ASCII letters case-insensitively (~><)
                # so #[PROP] can never coerce into REG_BINARY (#x/#X) or REG_EXPAND_SZ (#%), and
                # enforce numeric range bounds [lo, hi].  Chunk by 4 chars so every LaunchCondition
                # row stays strictly <= 255 chars (MSI standard S255 / ICE03 compliance, A4-23).
                $condList += ("(NOT {0}) OR (({0} >= {1}) AND ({0} <= {2}))" -f $propName, $lo, $hi)
                $badChars = @('-','+',' ',"`t",'#','%','.',',','$','/','\',':',';','=','!','@','^','&','*','(',')','[',']','{','}','|','?','<','>','~','`','_',"'") +
                            @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
                for ($ci = 0; $ci -lt $badChars.Count; $ci += 4) {
                    $end = [Math]::Min($ci + 3, $badChars.Count - 1)
                    $chunk = $badChars[$ci..$end] | ForEach-Object { "(NOT ({0} ~>< `"{1}`"))" -f $propName, $_ }
                    $condList += ("(NOT {0}) OR ({1})" -f $propName, ($chunk -join " AND "))
                }
            }
        } else {
            throw ("policy {0} has unrecognised Range '{1}'" -f $propName, $range)
        }
        foreach ($cond in $condList) {
            if ($cond.Length -gt 255) {
                throw ("LaunchCondition row for {0} exceeds 255 chars ({1}): {2}" -f $propName, $cond.Length, $cond)
            }
            ExecParams "INSERT INTO ``LaunchCondition`` (``Condition``,``Description``) VALUES (?,?)" @($cond, $desc)
        }
    }

    $hkcuCount = 0
    foreach ($p in $Policies) {
        $defVal = 0
        if (-not [int]::TryParse($p.Default, [ref]$defVal)) {
            throw ("policy {0} Default '{1}' is not an integer" -f $p.Prop, $p.Default)
        }
        Add-PolicyLaunchGuards $p.Prop $p.Range $defVal

        $reg = "Reg" + $p.Comp
        Exec ("INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('{0}','{1}','INSTALLDIR',260,'{2}','{3}')" -f $p.Comp, $p.Guid, $p.Prop, $reg)
        Exec ("INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','{0}')" -f $p.Comp)
        # "#" makes it a REG_DWORD; the property supplies the decimal digits.
        Exec ("INSERT INTO ``Registry`` (``Registry``,``Root``,``Key``,``Name``,``Value``,``Component_``) VALUES ('{0}',2,'{1}','{2}','#[{3}]','{4}')" -f $reg, $PolicyKey, $p.Value, $p.Prop, $p.Comp)

        if ($p.UserProp) {
            Add-PolicyLaunchGuards $p.UserProp $p.Range $defVal
            $ureg = "Reg" + $p.UserComp
            # Attributes 276 = 64-bit (256) | RegistryKeyPath (4) | Permanent (16)
            Exec ("INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('{0}','{1}','INSTALLDIR',276,'{2} AND NOT {3}','{4}')" -f $p.UserComp, $p.UserGuid, $p.UserProp, $p.Prop, $ureg)
            Exec ("INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','{0}')" -f $p.UserComp)
            Exec ("INSERT INTO ``Registry`` (``Registry``,``Root``,``Key``,``Name``,``Value``,``Component_``) VALUES ('{0}',1,'{1}','{2}','#[{3}]','{4}')" -f $ureg, $PolicyKey, $p.Value, $p.UserProp, $p.UserComp)
            $hkcuCount++
        }
    }
    Write-Host ("  policy values  : {0} HKLM enforced + {1} HKCU user-default properties" -f $Policies.Count, $hkcuCount)

    # --- Start with Windows (HKLM\...\Run, minimized to tray; on by default) -
    Add-PolicyLaunchGuards $AutoStartProp "0/1" 1
    Exec ("INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('{0}','{1}','INSTALLDIR',260,'{2} = `"1`"','RegAutoStart')" -f $AutoStartComp, $AutoStartGuid, $AutoStartProp)
    Exec ("INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','{0}')" -f $AutoStartComp)
    Exec ("INSERT INTO ``Registry`` (``Registry``,``Root``,``Key``,``Name``,``Value``,``Component_``) VALUES ('RegAutoStart',2,'{0}','Vordr','`"[INSTALLDIR]vordr.exe`"','{1}')" -f $RunKey, $AutoStartComp)
    Write-Host ("  autostart      : HKLM\{0}\Vordr (enabled by default; {1}=0 skips)" -f $RunKey, $AutoStartProp)

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

    Exec "INSERT INTO ``Shortcut`` (``Shortcut``,``Directory_``,``Name``,``Component_``,``Target``,``Arguments``,``Description``,``Icon_``,``IconIndex``,``ShowCmd``,``WkDir``) VALUES ('VordrSC','ProgramMenuFolder','Vordr','VordrExe','[INSTALLDIR]vordr.exe','','Vordr password manager','VordrIcon.exe',0,1,'INSTALLDIR')"
    Exec "INSERT INTO ``Shortcut`` (``Shortcut``,``Directory_``,``Name``,``Component_``,``Target``,``Arguments``,``Description``,``Icon_``,``IconIndex``,``ShowCmd``,``WkDir``) VALUES ('VordrSCArm64','ProgramMenuFolder','Vordr','VordrExeArm64','[INSTALLDIR]vordr.exe','','Vordr password manager','VordrIcon.exe',0,1,'INSTALLDIR')"

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
        @("RemoveFolders",         "", 3600),
        @("CreateFolders",         "", 3700),
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
    $uiSeq = @($clientSide | ForEach-Object { ,@($_[0], "", $_[2]) }) + @(
        @("CostInitialize", "",                                        800),
        @("FileCost",       "",                                        900),
        @("CostFinalize",   "",                                       1000),
        @("WelcomeDlg",     "NOT Installed",                          1200),
        @("MaintenanceDlg", "Installed AND NOT RESUME AND NOT Preselected", 1205),
        @("ProgressDlg",    "",                                       1290),
        @("ExecuteAction",  "",                                       1300),
        @("ExitDlg",        "",                                         -1),
        @("UserExitDlg",    "",                                         -2),
        @("FatalErrorDlg",  "",                                         -3)
    )
    foreach ($a in $uiSeq) {
        ExecParams "INSERT INTO ``InstallUISequence`` (``Action``,``Condition``,``Sequence``) VALUES (?,?,?)" @($a[0], $a[1], [int]$a[2])
    }

    # --- Vordr-styled MSI graphics (pure .NET GDI+, zero external tools) -----
    Add-Type -AssemblyName System.Drawing
    function Draw-VordrShield([System.Drawing.Graphics]$g, [float]$cx, [float]$cy, [float]$scale, [System.Drawing.Color]$holeColor) {
        # Exact amber-gold guardian shield cubic Bezier path from logo/vordr.svg
        # (centered around (256, 262) in SVG coordinate space).
        $st = $g.Save()
        $g.TranslateTransform($cx, $cy)
        $g.ScaleTransform($scale, $scale)
        $g.TranslateTransform(-256.0, -262.0)

        # Warm amber ambient glow behind the shield
        $glowPath = New-Object System.Drawing.Drawing2D.GraphicsPath
        $glowPath.AddEllipse(86.0, 92.0, 340.0, 340.0)
        $glowBrush = New-Object System.Drawing.Drawing2D.PathGradientBrush($glowPath)
        $glowBrush.CenterColor = [System.Drawing.Color]::FromArgb(72, 246, 178, 46)
        $glowBrush.SurroundColors = @([System.Drawing.Color]::FromArgb(0, 246, 178, 46))
        $g.FillPath($glowBrush, $glowPath)
        $glowBrush.Dispose(); $glowPath.Dispose()

        $shield = New-Object System.Drawing.Drawing2D.GraphicsPath
        # Quadratic Q148,140 -> 166,136 converted to exact cubic
        $shield.AddBezier(148.0, 158.0, 148.0, 146.0, 154.0, 138.67, 166.0, 136.0)
        $shield.AddBezier(166.0, 136.0, 210.0, 124.0, 302.0, 124.0, 346.0, 136.0)
        $shield.AddBezier(346.0, 136.0, 358.0, 138.67, 364.0, 146.0, 364.0, 158.0)
        $shield.AddLine(364.0, 158.0, 364.0, 250.0)
        $shield.AddBezier(364.0, 250.0, 364.0, 318.0, 322.0, 364.0, 256.0, 398.0)
        $shield.AddBezier(256.0, 398.0, 190.0, 364.0, 148.0, 318.0, 148.0, 250.0)
        $shield.CloseFigure()

        $rect = [System.Drawing.RectangleF]::new(146.0, 124.0, 220.0, 276.0)
        $sBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
            $rect,
            [System.Drawing.Color]::FromArgb(255, 255, 217, 107),
            [System.Drawing.Color]::FromArgb(255, 232, 146, 10),
            90.0
        )
        $cb = New-Object System.Drawing.Drawing2D.ColorBlend 3
        $cb.Colors = @(
            [System.Drawing.Color]::FromArgb(255, 255, 217, 107),
            [System.Drawing.Color]::FromArgb(255, 246, 178, 46),
            [System.Drawing.Color]::FromArgb(255, 232, 146, 10)
        )
        $cb.Positions = @(0.0, 0.55, 1.0)
        $sBrush.InterpolationColors = $cb
        $g.FillPath($sBrush, $shield)
        $sBrush.Dispose()

        # Soft top sheen highlight
        $sheen = New-Object System.Drawing.Drawing2D.GraphicsPath
        $sheen.AddBezier(166.0, 136.0, 210.0, 124.0, 302.0, 124.0, 346.0, 136.0)
        $sheen.AddBezier(346.0, 136.0, 355.3, 138.67, 360.0, 145.3, 360.0, 156.0)
        $sheen.AddBezier(360.0, 156.0, 300.0, 142.0, 212.0, 142.0, 152.0, 156.0)
        $sheen.AddBezier(152.0, 156.0, 152.0, 145.3, 156.7, 138.67, 166.0, 136.0)
        $sheen.CloseFigure()
        $sheenBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(46, 255, 255, 255))
        $g.FillPath($sheenBrush, $sheen)
        $sheenBrush.Dispose(); $sheen.Dispose()

        # Subtle crisp rim highlight
        $rimPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(95, 255, 244, 200), 3.0)
        $g.DrawPath($rimPen, $shield)
        $rimPen.Dispose(); $shield.Dispose()

        # Recessed keyhole cutout
        $holeBrush = New-Object System.Drawing.SolidBrush($holeColor)
        $g.FillEllipse($holeBrush, 223.0, 198.0, 66.0, 66.0)
        $trap = [System.Drawing.PointF[]]@(
            [System.Drawing.PointF]::new(239.0, 255.0),
            [System.Drawing.PointF]::new(273.0, 255.0),
            [System.Drawing.PointF]::new(288.0, 324.0),
            [System.Drawing.PointF]::new(224.0, 324.0)
        )
        $g.FillPolygon($holeBrush, $trap)
        $holeBrush.Dispose()

        $g.Restore($st)
    }

    function Save-Jpeg94([System.Drawing.Bitmap]$bmp, [string]$path) {
        $codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' } | Select-Object -First 1
        $ep = New-Object System.Drawing.Imaging.EncoderParameters 1
        $ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, 94L)
        $bmp.Save($path, $codec, $ep)
        $ep.Dispose()
    }

    # 1) BmpSide (390x702 for WelcomeDlg / ExitDlg left panel, 130x234 DLU)
    $sidePath = Join-Path $work "vordr_side.jpg"
    $bmpS = New-Object System.Drawing.Bitmap(390, 702, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $gS = [System.Drawing.Graphics]::FromImage($bmpS)
    $gS.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $gS.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $bgS = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        [System.Drawing.Rectangle]::new(0, 0, 390, 702),
        [System.Drawing.Color]::FromArgb(255, 11, 18, 34),
        [System.Drawing.Color]::FromArgb(255, 8, 13, 25),
        125.0
    )
    $gS.FillRectangle($bgS, 0, 0, 390, 702)
    $bgS.Dispose()
    # Cut-Planes geometric facets (matching Vordr's signature Midnight backdrop)
    $facetsS = @(
        @{ C=[System.Drawing.Color]::FromArgb(92, 29, 55, 108);  P=@(@(0,0),@(390,0),@(265,245),@(0,175)) }
        @{ C=[System.Drawing.Color]::FromArgb(72, 22, 42, 86);   P=@(@(390,0),@(390,340),@(190,260),@(270,115)) }
        @{ C=[System.Drawing.Color]::FromArgb(76, 36, 66, 124);  P=@(@(0,395),@(245,280),@(390,460),@(390,702),@(0,702)) }
        @{ C=[System.Drawing.Color]::FromArgb(62, 16, 28, 56);   P=@(@(0,515),@(390,375),@(390,702),@(0,702)) }
        @{ C=[System.Drawing.Color]::FromArgb(46, 56, 86, 152);  P=@(@(0,220),@(185,290),@(88,520),@(0,480)) }
        @{ C=[System.Drawing.Color]::FromArgb(32, 246, 178, 46); P=@(@(215,435),@(390,345),@(390,515)) }
    )
    foreach ($f in $facetsS) {
        $pts = [System.Drawing.PointF[]]@($f.P | ForEach-Object { [System.Drawing.PointF]::new([float]$_[0], [float]$_[1]) })
        $br = New-Object System.Drawing.SolidBrush($f.C)
        $gS.FillPolygon($br, $pts)
        $br.Dispose()
    }
    # Subtle cut-plane specular seams
    $seam1 = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(48, 130, 178, 255), 1.5)
    $seam2 = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(36, 246, 198, 96), 1.2)
    $gS.DrawLine($seam1, 0, 175, 390, 295)
    $gS.DrawLine($seam1, 265, 0, 88, 520)
    $gS.DrawLine($seam2, 0, 515, 390, 375)
    $seam1.Dispose(); $seam2.Dispose()

    Draw-VordrShield $gS 195.0 262.0 0.76 ([System.Drawing.Color]::FromArgb(255, 13, 21, 40))

    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $fWord = New-Object System.Drawing.Font("Segoe UI", 28, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $fSub  = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
    $bIvory = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 244, 247, 252))
    $bMuted = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 206, 220, 242))
    $gS.DrawString("V O R D R", $fWord, $bIvory, [System.Drawing.RectangleF]::new(16, 400, 358, 40), $sfC)
    $gS.DrawString("Offline Password Vault", $fSub, $bMuted, [System.Drawing.RectangleF]::new(16, 446, 358, 26), $sfC)

    # Crisp gold accent rule along right edge
    $goldEdge = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 238, 166, 32))
    $gS.FillRectangle($goldEdge, 387, 0, 3, 702)
    $goldEdge.Dispose(); $bIvory.Dispose(); $bMuted.Dispose()
    $fWord.Dispose(); $fSub.Dispose(); $sfC.Dispose()
    $gS.Dispose()
    Save-Jpeg94 $bmpS $sidePath
    $bmpS.Dispose()

    # 2) BmpTop (1110x132 for inner dialog top banner, 370x44 DLU)
    $topPath = Join-Path $work "vordr_top.jpg"
    $bmpT = New-Object System.Drawing.Bitmap(1110, 132, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $gT = [System.Drawing.Graphics]::FromImage($bmpT)
    $gT.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $bgT = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        [System.Drawing.Rectangle]::new(0, 0, 1110, 132),
        [System.Drawing.Color]::FromArgb(255, 11, 18, 34),
        [System.Drawing.Color]::FromArgb(255, 19, 34, 66),
        12.0
    )
    $gT.FillRectangle($bgT, 0, 0, 1110, 132)
    $bgT.Dispose()
    # Geometric Cut-Planes sweeping across the right half (keeping left calm for text)
    $facetsT = @(
        @{ C=[System.Drawing.Color]::FromArgb(85, 30, 56, 110);  P=@(@(640,0),@(1110,0),@(1110,132),@(760,132)) }
        @{ C=[System.Drawing.Color]::FromArgb(65, 42, 74, 138);  P=@(@(790,0),@(1010,0),@(920,132),@(680,132)) }
        @{ C=[System.Drawing.Color]::FromArgb(40, 246, 178, 46); P=@(@(965,0),@(1110,0),@(1110,95)) }
    )
    foreach ($f in $facetsT) {
        $pts = [System.Drawing.PointF[]]@($f.P | ForEach-Object { [System.Drawing.PointF]::new([float]$_[0], [float]$_[1]) })
        $br = New-Object System.Drawing.SolidBrush($f.C)
        $gT.FillPolygon($br, $pts)
        $br.Dispose()
    }
    $seamT = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(52, 136, 184, 255), 1.4)
    $gT.DrawLine($seamT, 640, 0, 760, 132)
    $gT.DrawLine($seamT, 790, 0, 680, 132)
    $seamT.Dispose()

    Draw-VordrShield $gT 1038.0 64.0 0.30 ([System.Drawing.Color]::FromArgb(255, 18, 31, 60))

    $goldBot = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 238, 166, 32))
    $gT.FillRectangle($goldBot, 0, 128, 1110, 4)
    $goldBot.Dispose()
    $gT.Dispose()
    Save-Jpeg94 $bmpT $topPath
    $bmpT.Dispose()

    # 3) Padlock icons (16x16 supersampled 32bpp BGRA DIB .ico) for PolicyDlg lock toggle
    function Save-Icon32([System.Drawing.Bitmap]$bmp16, [string]$path) {
        $w = $bmp16.Width; $h = $bmp16.Height
        $xorBytes = $w * $h * 4
        $andStride = [int](([Math]::Ceiling($w / 32.0)) * 4)
        $andBytes = $andStride * $h
        $imgBytes = 40 + $xorBytes + $andBytes
        $ms = New-Object System.IO.MemoryStream
        $bw = New-Object System.IO.BinaryWriter($ms)
        # ICONDIR (6 bytes)
        $bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]1)
        # ICONDIRENTRY (16 bytes)
        $bw.Write([byte]$w); $bw.Write([byte]$h); $bw.Write([byte]0); $bw.Write([byte]0)
        $bw.Write([uint16]1); $bw.Write([uint16]32)
        $bw.Write([uint32]$imgBytes); $bw.Write([uint32]22)
        # BITMAPINFOHEADER (40 bytes; biHeight = 2*h for XOR+AND)
        $bw.Write([uint32]40); $bw.Write([int32]$w); $bw.Write([int32]($h * 2))
        $bw.Write([uint16]1); $bw.Write([uint16]32); $bw.Write([uint32]0)
        $bw.Write([uint32]($xorBytes + $andBytes))
        $bw.Write([int32]0); $bw.Write([int32]0); $bw.Write([uint32]0); $bw.Write([uint32]0)
        # XOR mask (bottom-up BGRA)
        for ($yy = $h - 1; $yy -ge 0; $yy--) {
            for ($xx = 0; $xx -lt $w; $xx++) {
                $px = $bmp16.GetPixel($xx, $yy)
                $bw.Write([byte]$px.B); $bw.Write([byte]$px.G); $bw.Write([byte]$px.R); $bw.Write([byte]$px.A)
            }
        }
        # AND mask (bottom-up 1bpp, 1 = transparent)
        for ($yy = $h - 1; $yy -ge 0; $yy--) {
            $row = New-Object byte[] $andStride
            for ($xx = 0; $xx -lt $w; $xx++) {
                if ($bmp16.GetPixel($xx, $yy).A -eq 0) {
                    $row[[int][Math]::Floor($xx / 8)] = $row[[int][Math]::Floor($xx / 8)] -bor (0x80 -shr ($xx % 8))
                }
            }
            $bw.Write($row)
        }
        $bw.Flush()
        [System.IO.File]::WriteAllBytes($path, $ms.ToArray())
        $bw.Dispose(); $ms.Dispose()
    }
    function New-RoundedRectPath([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
        $gp = New-Object System.Drawing.Drawing2D.GraphicsPath
        $d = $r * 2.0
        $gp.AddArc($x, $y, $d, $d, 180, 90)
        $gp.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
        $gp.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
        $gp.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
        $gp.CloseFigure()
        return $gp
    }
    function Build-PadlockIcon([bool]$locked, [string]$outPath) {
        $hi = New-Object System.Drawing.Bitmap(64, 64, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g = [System.Drawing.Graphics]::FromImage($hi)
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $g.Clear([System.Drawing.Color]::Transparent)
        if ($locked) {
            # Closed amber-gold Vordr padlock
            $shPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 194, 126, 16), 6.5)
            $shPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
            $shPen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
            $shPath = New-Object System.Drawing.Drawing2D.GraphicsPath
            $shPath.AddLine(19.0, 30.0, 19.0, 20.0)
            $shPath.AddArc(19.0, 7.0, 26.0, 26.0, 180, 180)
            $shPath.AddLine(45.0, 20.0, 45.0, 30.0)
            $g.DrawPath($shPen, $shPath)
            $shPen.Dispose(); $shPath.Dispose()

            $body = New-RoundedRectPath 10.0 27.0 44.0 31.0 6.5
            $br = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
                [System.Drawing.RectangleF]::new(10.0, 27.0, 44.0, 31.0),
                [System.Drawing.Color]::FromArgb(255, 255, 218, 108),
                [System.Drawing.Color]::FromArgb(255, 230, 142, 10),
                90.0
            )
            $g.FillPath($br, $body)
            $rim = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 178, 108, 8), 2.5)
            $g.DrawPath($rim, $body)
            $br.Dispose(); $rim.Dispose(); $body.Dispose()

            $kh = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 19, 30, 56))
            $g.FillEllipse($kh, 26.5, 34.5, 11.0, 11.0)
            $g.FillPolygon($kh, [System.Drawing.PointF[]]@(
                [System.Drawing.PointF]::new(29.0, 43.0),
                [System.Drawing.PointF]::new(35.0, 43.0),
                [System.Drawing.PointF]::new(37.0, 52.0),
                [System.Drawing.PointF]::new(27.0, 52.0)
            ))
            $kh.Dispose()
        } else {
            # Open muted-slate padlock
            $shPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 104, 118, 138), 6.0)
            $shPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
            $shPen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
            $shPath = New-Object System.Drawing.Drawing2D.GraphicsPath
            $shPath.AddLine(33.0, 20.0, 33.0, 17.0)
            $shPath.AddArc(33.0, 6.0, 24.0, 22.0, 180, 180)
            $shPath.AddLine(57.0, 17.0, 57.0, 22.0)
            # Keep shackle anchored on left side of body and swung open right
            $shPath.Reset()
            $shPath.AddLine(18.0, 30.0, 18.0, 18.0)
            $shPath.AddArc(18.0, 6.0, 26.0, 24.0, 180, 155)
            $g.DrawPath($shPen, $shPath)
            $shPen.Dispose(); $shPath.Dispose()

            $body = New-RoundedRectPath 10.0 28.0 44.0 30.0 6.5
            $br = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
                [System.Drawing.RectangleF]::new(10.0, 28.0, 44.0, 30.0),
                [System.Drawing.Color]::FromArgb(255, 226, 232, 240),
                [System.Drawing.Color]::FromArgb(255, 188, 198, 212),
                90.0
            )
            $g.FillPath($br, $body)
            $rim = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 104, 118, 138), 2.8)
            $g.DrawPath($rim, $body)
            $br.Dispose(); $rim.Dispose(); $body.Dispose()

            $kh = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 86, 100, 120))
            $g.FillEllipse($kh, 27.0, 36.0, 10.0, 10.0)
            $g.FillPolygon($kh, [System.Drawing.PointF[]]@(
                [System.Drawing.PointF]::new(29.5, 44.0),
                [System.Drawing.PointF]::new(34.5, 44.0),
                [System.Drawing.PointF]::new(36.0, 52.0),
                [System.Drawing.PointF]::new(28.0, 52.0)
            ))
            $kh.Dispose()
        }
        $g.Dispose()
        $lo = New-Object System.Drawing.Bitmap(16, 16, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $gLo = [System.Drawing.Graphics]::FromImage($lo)
        $gLo.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $gLo.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $gLo.DrawImage($hi, 0, 0, 16, 16)
        $gLo.Dispose()
        $hi.Dispose()
        Save-Icon32 $lo $outPath
        $lo.Dispose()
    }
    $lockOpenPath = Join-Path $work "lock_open.ico"
    $lockShutPath = Join-Path $work "lock_shut.ico"
    Build-PadlockIcon $false $lockOpenPath
    Build-PadlockIcon $true  $lockShutPath

    function Insert-Stream([string]$table, [string]$name, [string]$filePath) {
        $v = $db.OpenView("INSERT INTO ``$table`` (``Name``,``Data``) VALUES (?,?)")
        $r = $installer.CreateRecord(2)
        $r.StringData(1) = $name
        $r.SetStream(2, $filePath)
        $v.Execute($r)
        $v.Close()
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($r)
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($v)
    }
    Insert-Stream "Binary" "BmpSide"     $sidePath
    Insert-Stream "Binary" "BmpTop"      $topPath
    Insert-Stream "Binary" "IcoLockOpen" $lockOpenPath
    Insert-Stream "Binary" "IcoLockShut" $lockShutPath
    $icoPath = Join-Path (Split-Path -Parent $PSScriptRoot) "vordr.ico"
    if (-not (Test-Path $icoPath)) { throw "not found: $icoPath" }
    Insert-Stream "Icon" "VordrIcon.exe" $icoPath

    # --- UI TextStyle, Dialogs, Controls, Events & Conditions ----------------
    # TextStyle.Color is 0x00BBGGRR (Win32 COLORREF).
    # Note: msi.dll clamps near-white text over transparent controls back to
    # COLOR_WINDOWTEXT (black), so banner styles use high-contrast gold & cool silver.
    $textStyles = @(
        @("VordrFontBody",      "Segoe UI",  9,  1579032, 0), # #181818 charcoal
        @("VordrFontBold",      "Segoe UI",  9,  1579032, 1), # #181818 bold
        @("VordrFontSmall",     "Segoe UI",  8,  6316128, 0), # #606060 muted
        @("VordrFontError",     "Segoe UI",  8,  2237128, 1), # #C82222 validation red bold
        @("VordrFontTitle",     "Segoe UI", 13,  3810587, 1), # #1B253A deep navy bold
        @("VordrFontBanner",    "Segoe UI", 11,  7067391, 1), # #FFD66B bright Vordr amber-gold bold
        @("VordrFontBannerSub", "Segoe UI",  8, 15252377, 0)  # #99BBE8 soft cool silver-blue
    )
    foreach ($ts in $textStyles) {
        Exec ("INSERT INTO ``TextStyle`` (``TextStyle``,``FaceName``,``Size``,``Color``,``StyleBits``) VALUES ('{0}','{1}',{2},{3},{4})" -f $ts[0], $ts[1], $ts[2], $ts[3], $ts[4])
    }

    function Add-Dialog([string]$name, [int]$w, [int]$h, [int]$attr, [string]$title, [string]$first, [string]$def, [string]$cancel) {
        ExecParams "INSERT INTO ``Dialog`` (``Dialog``,``HCentering``,``VCentering``,``Width``,``Height``,``Attributes``,``Title``,``Control_First``,``Control_Default``,``Control_Cancel``) VALUES (?,50,50,?,?,?,?,?,?,?)" `
            @($name, $w, $h, $attr, $title, $first, $def, $cancel)
    }
    function Add-Ctrl([string]$dlg, [string]$id, [string]$type, [int]$x, [int]$y, [int]$w, [int]$h, [int]$attr, [string]$prop, [string]$text, [string]$next) {
        ExecParams "INSERT INTO ``Control`` (``Dialog_``,``Control``,``Type``,``X``,``Y``,``Width``,``Height``,``Attributes``,``Property``,``Text``,``Control_Next``) VALUES (?,?,?,?,?,?,?,?,?,?,?)" `
            @($dlg, $id, $type, $x, $y, $w, $h, $attr, $prop, $text, $next)
    }
    function Add-Evt([string]$dlg, [string]$ctrl, [string]$evt, [string]$arg, [string]$cond, [int]$ord) {
        ExecParams "INSERT INTO ``ControlEvent`` (``Dialog_``,``Control_``,``Event``,``Argument``,``Condition``,``Ordering``) VALUES (?,?,?,?,?,?)" `
            @($dlg, $ctrl, $evt, $arg, $cond, $ord)
    }
    function Add-Cond([string]$dlg, [string]$ctrl, [string]$act, [string]$cond) {
        ExecParams "INSERT INTO ``ControlCondition`` (``Dialog_``,``Control_``,``Action``,``Condition``) VALUES (?,?,?,?)" `
            @($dlg, $ctrl, $act, $cond)
    }
    function Add-Map([string]$dlg, [string]$ctrl, [string]$evt, [string]$attr) {
        ExecParams "INSERT INTO ``EventMapping`` (``Dialog_``,``Control_``,``Event``,``Attribute``) VALUES (?,?,?,?)" `
            @($dlg, $ctrl, $evt, $attr)
    }

    $DLG_MODAL    = 7          # Visible (1) | Modal (2) | Minimize (4)
    $DLG_POPUP    = 19         # Visible (1) | Modal (2) | KeepModeless (16) — keeps ProgressDlg alive if Cancel->No
    $DLG_MODELESS = 5          # Visible (1) | Minimize (4) — MUST omit Modal (2) so ExecuteAction runs!
    $DLG_ERROR    = 65555      # Visible | Modal | KeepModeless | Error (0x10013)
    $TXT_TRANS    = 196611     # Visible | Enabled | Transparent | NoPrefix (0x30003)
    $TXT_NOPFX    = 131075     # Visible | Enabled | NoPrefix (0x20003)
    $RADIO_PUSH   = 131075     # Visible | Enabled | PushLike (0x20003)
    $LIST_SORTED  = 65543      # Visible | Enabled | Sunken | Sorted-by-Order (0x10007)
    $COMBO_LIST   = 196611     # Visible | Enabled | Sorted-by-Order | ComboList (0x30003)
    $EDIT_INT     = 23         # Visible | Enabled | Sunken | Integer (0x17)
    $ICO_16       = 3145729    # Visible (1) | FixedSize (0x100000) | IconSize16 (0x200000)
    $BTN_SHIELD   = 8388611    # Visible | Enabled | ElevationShield (0x800003)
    $DLG_TITLE    = "Vordr Setup (v$productVersion)"

    Exec "INSERT INTO ``CheckBox`` (``Property``,``Value``) VALUES ('UI_ASSOC','1')"
    Exec "INSERT INTO ``CheckBox`` (``Property``,``Value``) VALUES ('UI_AUTOSTART','1')"
    Exec "INSERT INTO ``CheckBox`` (``Property``,``Value``) VALUES ('UI_LOCKED','1')"
    for ($pi = 0; $pi -lt $Policies.Count; $pi++) {
        Exec "INSERT INTO ``CheckBox`` (``Property``,``Value``) VALUES ('UL_$pi','1')"
    }

    # 1) WelcomeDlg
    Add-Dialog "WelcomeDlg" 370 270 $DLG_MODAL $DLG_TITLE "Next" "Next" "Cancel"
    Add-Ctrl "WelcomeDlg" "SideArt"    "Bitmap"     0   0   130 234 1          "" "BmpSide" ""
    Add-Ctrl "WelcomeDlg" "Title"      "Text"       142 16  216 24  $TXT_TRANS "" "{\VordrFontTitle}Welcome to Vordr Setup" ""
    Add-Ctrl "WelcomeDlg" "Intro"      "Text"       142 44  216 62  $TXT_NOPFX "" "Vordr is a quiet, completely offline password manager for Windows x64 and ARM64. Your logins, 2FA codes, PINs, notes, and files stay inside one encrypted .vordr vault—with no accounts, cloud sync, or third-party libraries." ""
    Add-Ctrl "WelcomeDlg" "WhatHdr"    "Text"       142 112 216 13  $TXT_NOPFX "" "{\VordrFontBold}This installer sets up:" ""
    Add-Ctrl "WelcomeDlg" "What1"      "Text"       146 128 212 13  $TXT_NOPFX "" "• Native x64 or ARM64 binary (auto-detected)" ""
    Add-Ctrl "WelcomeDlg" "What2"      "Text"       146 143 212 13  $TXT_NOPFX "" "• Start Menu shortcut, .vordr link & startup" ""
    Add-Ctrl "WelcomeDlg" "What3"      "Text"       146 158 212 13  $TXT_NOPFX "" "• Optional user defaults & HKLM policy locks" ""
    Add-Ctrl "WelcomeDlg" "KeepNote"   "Text"       142 184 216 42  $TXT_NOPFX "" "{\VordrFontSmall}Uninstalling removes only program files—your vaults and personal settings are never deleted. Click Next to choose the install folder, startup option, and optional settings." ""
    Add-Ctrl "WelcomeDlg" "BottomLine" "Line"       0   234 370 0   1          "" "" ""
    Add-Ctrl "WelcomeDlg" "Next"       "PushButton" 240 243 56  17  3          "" "&Next >" "Cancel"
    Add-Ctrl "WelcomeDlg" "Cancel"     "PushButton" 302 243 56  17  3          "" "Cancel"  "Next"

    # Sync UI helper properties from any CLI-provided VORDR_* / VORDR_USER_* properties
    $ord = 1
    Add-Evt "WelcomeDlg" "Next" "[UI_ASSOC]"     "{}" "VORDR_NOASSOC"                ($ord++)
    Add-Evt "WelcomeDlg" "Next" "[UI_ASSOC]"     "1"  "NOT VORDR_NOASSOC"            ($ord++)
    Add-Evt "WelcomeDlg" "Next" "[UI_AUTOSTART]" "1"  "VORDR_AUTOSTART = `"1`""      ($ord++)
    Add-Evt "WelcomeDlg" "Next" "[UI_AUTOSTART]" "{}" "NOT (VORDR_AUTOSTART = `"1`")" ($ord++)
    for ($pi = 0; $pi -lt $Policies.Count; $pi++) {
        $pol = $Policies[$pi]; $p = $pol.Prop; $dv = $pol.Default
        if ($pol.UserProp) {
            $up = $pol.UserProp
            Add-Evt "WelcomeDlg" "Next" "[UL_$pi]" "{}"    "NOT $p"               ($ord++)
            Add-Evt "WelcomeDlg" "Next" "[UV_$pi]" $dv     "NOT $p AND NOT $up"   ($ord++)
            Add-Evt "WelcomeDlg" "Next" "[UV_$pi]" "[$up]" "NOT $p AND $up"       ($ord++)
            Add-Evt "WelcomeDlg" "Next" "[UL_$pi]" "1"     "$p"                   ($ord++)
            Add-Evt "WelcomeDlg" "Next" "[UV_$pi]" "[$p]"  "$p"                   ($ord++)
        } else {
            Add-Evt "WelcomeDlg" "Next" "[UL_$pi]" "{}"    "NOT $p"               ($ord++)
            Add-Evt "WelcomeDlg" "Next" "[UV_$pi]" $dv     "NOT $p"               ($ord++)
            Add-Evt "WelcomeDlg" "Next" "[UL_$pi]" "1"     "$p"                   ($ord++)
            Add-Evt "WelcomeDlg" "Next" "[UV_$pi]" "[$p]"  "$p"                   ($ord++)
        }
    }
    Add-Evt "WelcomeDlg" "Next"   "NewDialog"   "InstallDirDlg" "1" ($ord++)
    Add-Evt "WelcomeDlg" "Cancel" "SpawnDialog" "CancelDlg"     "1" 1

    # 2) InstallDirDlg (destination folder, .vordr association & optional Start with Windows)
    Add-Dialog "InstallDirDlg" 370 270 $DLG_MODAL $DLG_TITLE "FolderEdit" "Next" "Cancel"
    Add-Ctrl "InstallDirDlg" "TopArt"       "Bitmap"     0   0   370 44  1          ""             "BmpTop" ""
    Add-Ctrl "InstallDirDlg" "BannerTitle"  "Text"       16  7   290 16  $TXT_TRANS ""             "{\VordrFontBanner}Installation Folder" ""
    Add-Ctrl "InstallDirDlg" "BannerSub"    "Text"       16  24  290 14  $TXT_TRANS ""             "{\VordrFontBannerSub}Choose where Vordr will be installed and how it integrates with Windows." ""
    Add-Ctrl "InstallDirDlg" "DirIntro"     "Text"       18  54  334 24  3          ""             "Vordr installs per-machine into a read-only folder protected for standard users. Your encrypted vaults stay in your own folder." ""
    Add-Ctrl "InstallDirDlg" "FolderLbl"    "Text"       18  84  260 12  3          ""             "{\VordrFontBold}Destination folder:" ""
    Add-Ctrl "InstallDirDlg" "FolderEdit"   "PathEdit"   18  98  268 16  3          "INSTALLDIR"   "" "Browse"
    Add-Ctrl "InstallDirDlg" "Browse"       "PushButton" 292 98  60  17  3          ""             "&Browse..." "AssocChk"
    Add-Ctrl "InstallDirDlg" "OptsHdr"      "Text"       18  124 334 12  3          ""             "{\VordrFontBold}Integration options:" ""
    Add-Ctrl "InstallDirDlg" "AssocChk"     "CheckBox"   18  138 334 15  3          "UI_ASSOC"     "Register .vordr file association (double-clicking opens the import workflow)" "AutoStartChk"
    Add-Ctrl "InstallDirDlg" "AutoStartChk" "CheckBox"   18  156 334 15  3          "UI_AUTOSTART" "Start Vordr automatically with Windows (minimized to the notification area)" "Back"
    Add-Ctrl "InstallDirDlg" "ArchNote"     "Text"       18  184 334 32  3          ""             "{\VordrFontSmall}Detected host architecture: [HOST_NATIVE_ARCH]. This universal installer automatically deploys the matching native vordr.exe binary." ""
    Add-Ctrl "InstallDirDlg" "BottomLine"   "Line"       0   234 370 0   1          ""             "" ""
    Add-Ctrl "InstallDirDlg" "Back"         "PushButton" 180 243 56  17  3          ""             "< &Back" "Next"
    Add-Ctrl "InstallDirDlg" "Next"         "PushButton" 240 243 56  17  3          ""             "&Next >" "Cancel"
    Add-Ctrl "InstallDirDlg" "Cancel"       "PushButton" 302 243 56  17  3          ""             "Cancel"  "FolderEdit"

    Add-Evt "InstallDirDlg" "Browse" "[_BrowseProperty]" "INSTALLDIR" "1" 1
    Add-Evt "InstallDirDlg" "Browse" "SpawnDialog"       "BrowseDlg"  "1" 2
    Add-Evt "InstallDirDlg" "Back"   "NewDialog"         "WelcomeDlg" "1" 1
    Add-Evt "InstallDirDlg" "Next"   "SetTargetPath"     "INSTALLDIR" "1" 1
    Add-Evt "InstallDirDlg" "Next"   "[VORDR_NOASSOC]"   "{}"         "UI_ASSOC = `"1`""         2
    Add-Evt "InstallDirDlg" "Next"   "[VORDR_NOASSOC]"   "1"          "NOT (UI_ASSOC = `"1`")"   3
    Add-Evt "InstallDirDlg" "Next"   "[VORDR_AUTOSTART]" "1"          "UI_AUTOSTART = `"1`""     4
    Add-Evt "InstallDirDlg" "Next"   "[VORDR_AUTOSTART]" "0"          "NOT (UI_AUTOSTART = `"1`")" 5
    Add-Evt "InstallDirDlg" "Next"   "NewDialog"         "PolicyDlg"  "1" 6
    Add-Evt "InstallDirDlg" "Cancel" "SpawnDialog"       "CancelDlg"  "1" 1

    # 3) BrowseDlg (bit 0x8 Indirect required on controls bound to _BrowseProperty)
    Add-Dialog "BrowseDlg" 370 270 $DLG_MODAL $DLG_TITLE "PathEdit" "OK" "Cancel"
    Add-Ctrl "BrowseDlg" "TopArt"      "Bitmap"         0   0   370 44  1       ""                "BmpTop" ""
    Add-Ctrl "BrowseDlg" "BannerTitle" "Text"           16  7   290 16  $TXT_TRANS ""             "{\VordrFontBanner}Change Destination Folder" ""
    Add-Ctrl "BrowseDlg" "BannerSub"   "Text"           16  24  290 14  $TXT_TRANS ""             "{\VordrFontBannerSub}Select a local folder where Vordr will be installed." ""
    Add-Ctrl "BrowseDlg" "ComboLbl"    "Text"           18  56  48  13  3       ""                "&Look in:" ""
    Add-Ctrl "BrowseDlg" "Combo"       "DirectoryCombo" 68  54  180 80  196619  "_BrowseProperty" "" "Up"
    Add-Ctrl "BrowseDlg" "Up"          "PushButton"     254 54  36  16  3       ""                "&Up" "NewFolder"
    Add-Ctrl "BrowseDlg" "NewFolder"   "PushButton"     294 54  58  16  3       ""                "New &Folder" "List"
    Add-Ctrl "BrowseDlg" "List"        "DirectoryList"  18  76  334 114 15      "_BrowseProperty" "" "PathEdit"
    Add-Ctrl "BrowseDlg" "PathLbl"     "Text"           18  198 62  13  3       ""                "&Folder name:" ""
    Add-Ctrl "BrowseDlg" "PathEdit"    "PathEdit"       82  196 270 16  11      "_BrowseProperty" "" "OK"
    Add-Ctrl "BrowseDlg" "BottomLine"  "Line"           0   234 370 0   1       ""                "" ""
    Add-Ctrl "BrowseDlg" "OK"          "PushButton"     240 243 56  17  3       ""                "OK" "Cancel"
    Add-Ctrl "BrowseDlg" "Cancel"      "PushButton"     302 243 56  17  3       ""                "Cancel" "Combo"

    Add-Evt "BrowseDlg" "Up"        "DirectoryListUp"  "0"                 "1" 1
    Add-Evt "BrowseDlg" "NewFolder" "DirectoryListNew" "0"                 "1" 1
    Add-Evt "BrowseDlg" "OK"        "SetTargetPath"    "[_BrowseProperty]" "1" 1
    Add-Evt "BrowseDlg" "OK"        "EndDialog"        "Return"            "1" 2
    Add-Evt "BrowseDlg" "Cancel"    "EndDialog"        "Return"            "1" 1

    # 4) PolicyDlg (master-detail ListBox for all 16 settings: edit user default in HKCU or Lock in HKLM)
    Add-Dialog "PolicyDlg" 370 270 $DLG_MODAL $DLG_TITLE "PolList" "Next" "Cancel"
    Add-Ctrl "PolicyDlg" "TopArt"      "Bitmap"   0   0   370 44  1          ""           "BmpTop" ""
    Add-Ctrl "PolicyDlg" "BannerTitle" "Text"     16  7   290 16  $TXT_TRANS ""           "{\VordrFontBanner}Settings & Policy (Optional)" ""
    Add-Ctrl "PolicyDlg" "BannerSub"   "Text"     16  24  290 14  $TXT_TRANS ""           "{\VordrFontBannerSub}Adjust user defaults (HKCU) or tick Lock in the corner to enforce in HKLM." ""
    Add-Ctrl "PolicyDlg" "ListLbl"     "Text"     14  50  148 12  $TXT_NOPFX ""           "{\VordrFontBold}Settings:" ""
    Add-Ctrl "PolicyDlg" "PolList"     "ListBox"  14  64  148 150 $LIST_SORTED "UI_SEL_POL" "" "ResetAll"
    Add-Ctrl "PolicyDlg" "DetailBox"   "GroupBox" 170 52  186 162 1          ""           "Selected setting" ""

    $intChecks = @()
    for ($pi = 0; $pi -lt $Policies.Count; $pi++) {
        $pol  = $Policies[$pi]
        $meta = $UiPolicyMeta[$pol.Value]
        $dv   = $pol.Default
        $selCond    = "UI_SEL_POL = `"$($pol.Value)`""
        $notSelCond = "UI_SEL_POL <> `"$($pol.Value)`""

        # Add item to left-side ListBox
        ExecParams "INSERT INTO ``ListBox`` (``Property``,``Order``,``Value``,``Text``) VALUES ('UI_SEL_POL',?,?,?)" @([int]($pi + 1), $pol.Value, $meta.Title)

        # Right-side setting view with consistent top-right Lock checkbox + padlock icon
        $docCap  = $pol.Doc.Substring(0, 1).ToUpper() + $pol.Doc.Substring(1)
        $docLine = if ($pol.Doc -match 'default') { "$docCap." } else { "$docCap. Default: $dv." }
        Add-Ctrl "PolicyDlg" "PTit$pi" "Text"     178 63  122 13 $TXT_NOPFX "" "{\VordrFontBold}$($meta.Title)" ""
        Add-Ctrl "PolicyDlg" "PLck$pi" "CheckBox" 303 62  31  13 3          "UL_$pi" "Lock" ""
        Add-Ctrl "PolicyDlg" "PIcO$pi" "Icon"     336 61  12  12 $ICO_16    "" "IcoLockOpen" ""
        Add-Ctrl "PolicyDlg" "PIcL$pi" "Icon"     336 61  12  12 $ICO_16    "" "IcoLockShut" ""
        Add-Ctrl "PolicyDlg" "PKey$pi" "Text"     178 76  170 11 $TXT_NOPFX "" "{\VordrFontSmall}$PolicyKey\$($pol.Value)" ""
        Add-Ctrl "PolicyDlg" "PDsc$pi" "Text"     178 88  170 35 $TXT_NOPFX "" $docLine ""
        Add-Ctrl "PolicyDlg" "PVLb$pi" "Text"     178 125 170 12 $TXT_NOPFX "" "{\VordrFontBold}Value:" ""

        Add-Cond "PolicyDlg" "PTit$pi" "Show" $selCond; Add-Cond "PolicyDlg" "PTit$pi" "Hide" $notSelCond
        Add-Cond "PolicyDlg" "PKey$pi" "Show" $selCond; Add-Cond "PolicyDlg" "PKey$pi" "Hide" $notSelCond
        Add-Cond "PolicyDlg" "PDsc$pi" "Show" $selCond; Add-Cond "PolicyDlg" "PDsc$pi" "Hide" $notSelCond
        Add-Cond "PolicyDlg" "PVLb$pi" "Show" $selCond; Add-Cond "PolicyDlg" "PVLb$pi" "Hide" $notSelCond

        if ($pol.HklmOnly) {
            # HKLM-only security policy: enabling (1) always enforces in HKLM (checked+disabled Lock + gold padlock)
            Add-Ctrl "PolicyDlg" "PLckF$pi" "CheckBox" 303 62 31 13 1 "UI_LOCKED" "Lock" ""
            Add-Cond "PolicyDlg" "PLck$pi"  "Show"    "$selCond AND UV_$pi = `"0`""
            Add-Cond "PolicyDlg" "PLck$pi"  "Hide"    "NOT ($selCond AND UV_$pi = `"0`")"
            Add-Cond "PolicyDlg" "PLckF$pi" "Show"    "$selCond AND UV_$pi <> `"0`""
            Add-Cond "PolicyDlg" "PLckF$pi" "Hide"    "NOT ($selCond AND UV_$pi <> `"0`")"
            Add-Cond "PolicyDlg" "PLckF$pi" "Disable" "1"
            Add-Cond "PolicyDlg" "PIcO$pi"  "Show"    "$selCond AND NOT UL_$pi AND UV_$pi = `"0`""
            Add-Cond "PolicyDlg" "PIcO$pi"  "Hide"    "NOT ($selCond AND NOT UL_$pi AND UV_$pi = `"0`")"
            Add-Cond "PolicyDlg" "PIcL$pi"  "Show"    "$selCond AND (UL_$pi OR UV_$pi <> `"0`")"
            Add-Cond "PolicyDlg" "PIcL$pi"  "Hide"    "NOT ($selCond AND (UL_$pi OR UV_$pi <> `"0`"))"
        } else {
            Add-Cond "PolicyDlg" "PLck$pi" "Show" $selCond; Add-Cond "PolicyDlg" "PLck$pi" "Hide" $notSelCond
            Add-Cond "PolicyDlg" "PIcO$pi" "Show" "$selCond AND NOT UL_$pi"
            Add-Cond "PolicyDlg" "PIcO$pi" "Hide" "NOT ($selCond AND NOT UL_$pi)"
            Add-Cond "PolicyDlg" "PIcL$pi" "Show" "$selCond AND UL_$pi"
            Add-Cond "PolicyDlg" "PIcL$pi" "Hide" "NOT ($selCond AND UL_$pi)"
        }

        if ($meta.Kind -eq "bool") {
            Add-Ctrl "PolicyDlg" "PVal$pi" "RadioButtonGroup" 178 138 170 16 $RADIO_PUSH "UV_$pi" "" ""
            ExecParams "INSERT INTO ``RadioButton`` (``Property``,``Order``,``Value``,``X``,``Y``,``Width``,``Height``,``Text``) VALUES (?,1,'0',0,0,82,15,'Disabled (0)')" @("UV_$pi")
            ExecParams "INSERT INTO ``RadioButton`` (``Property``,``Order``,``Value``,``X``,``Y``,``Width``,``Height``,``Text``) VALUES (?,2,'1',86,0,82,15,'Enabled (1)')"  @("UV_$pi")
            Add-Cond "PolicyDlg" "PVal$pi" "Show" $selCond; Add-Cond "PolicyDlg" "PVal$pi" "Hide" $notSelCond
        } elseif ($meta.Kind -eq "enum") {
            Add-Ctrl "PolicyDlg" "PVal$pi" "ComboBox" 178 138 170 80 $COMBO_LIST "UV_$pi" "" ""
            for ($ei = 0; $ei -lt $meta.Items.Count; $ei++) {
                ExecParams "INSERT INTO ``ComboBox`` (``Property``,``Order``,``Value``,``Text``) VALUES (?,?,?,?)" @("UV_$pi", [int]($ei + 1), $meta.Items[$ei][0], $meta.Items[$ei][1])
            }
            Add-Cond "PolicyDlg" "PVal$pi" "Show" $selCond; Add-Cond "PolicyDlg" "PVal$pi" "Hide" $notSelCond
        } else {
            Add-Ctrl "PolicyDlg" "PVal$pi" "Edit" 178 138 68 16 $EDIT_INT   "UV_$pi" "{4}" ""
            Add-Ctrl "PolicyDlg" "PRng$pi" "Text" 252 140 96 13 $TXT_NOPFX  ""       "Range: $($meta.Min)-$($meta.Max)" ""
            $badCond = "NOT UV_$pi OR UV_$pi < $($meta.Min) OR UV_$pi > $($meta.Max)"
            Add-Ctrl "PolicyDlg" "PErr$pi" "Text" 178 157 170 12 $TXT_NOPFX ""       "{\VordrFontError}Enter an integer in $($meta.Min)-$($meta.Max)." ""
            Add-Cond "PolicyDlg" "PVal$pi" "Show" $selCond; Add-Cond "PolicyDlg" "PVal$pi" "Hide" $notSelCond
            Add-Cond "PolicyDlg" "PRng$pi" "Show" $selCond; Add-Cond "PolicyDlg" "PRng$pi" "Hide" $notSelCond
            Add-Cond "PolicyDlg" "PErr$pi" "Show" "$selCond AND ($badCond)"
            Add-Cond "PolicyDlg" "PErr$pi" "Hide" "NOT ($selCond AND ($badCond))"
            $intChecks += "(UV_$pi AND UV_$pi>=$($meta.Min) AND UV_$pi<=$($meta.Max))"
        }

        if ($pol.HklmOnly) {
            Add-Ctrl "PolicyDlg" "PSt0_$pi" "Text" 178 174 170 34 $TXT_NOPFX "" "{\VordrFontSmall}Default (0, not written). HKLM-only security policy—users cannot change this in Vordr." ""
            Add-Ctrl "PolicyDlg" "PSt2_$pi" "Text" 178 174 170 34 $TXT_NOPFX "" "{\VordrFontSmall}Locked policy: writes HKLM\$PolicyKey\$($pol.Value). HKLM-only security policy." ""
            Add-Cond "PolicyDlg" "PSt0_$pi" "Show" "$selCond AND NOT UL_$pi AND UV_$pi = `"0`""
            Add-Cond "PolicyDlg" "PSt0_$pi" "Hide" "NOT ($selCond AND NOT UL_$pi AND UV_$pi = `"0`")"
            Add-Cond "PolicyDlg" "PSt2_$pi" "Show" "$selCond AND (UL_$pi OR UV_$pi <> `"0`")"
            Add-Cond "PolicyDlg" "PSt2_$pi" "Hide" "NOT ($selCond AND (UL_$pi OR UV_$pi <> `"0`"))"
        } else {
            Add-Ctrl "PolicyDlg" "PSt0_$pi" "Text" 178 174 170 34 $TXT_NOPFX "" "{\VordrFontSmall}Default (not written). Change value to set an HKCU user default, or tick Lock to enforce in HKLM." ""
            Add-Ctrl "PolicyDlg" "PSt1_$pi" "Text" 178 174 170 34 $TXT_NOPFX "" "{\VordrFontSmall}User default: writes HKCU\$PolicyKey\$($pol.Value). Users can override this in Vordr Settings." ""
            Add-Ctrl "PolicyDlg" "PSt2_$pi" "Text" 178 174 170 34 $TXT_NOPFX "" "{\VordrFontSmall}Locked policy: writes HKLM\$PolicyKey\$($pol.Value). Users cannot change this in Vordr Settings." ""
            Add-Cond "PolicyDlg" "PSt0_$pi" "Show" "$selCond AND NOT UL_$pi AND UV_$pi = `"$dv`""
            Add-Cond "PolicyDlg" "PSt0_$pi" "Hide" "NOT ($selCond AND NOT UL_$pi AND UV_$pi = `"$dv`")"
            Add-Cond "PolicyDlg" "PSt1_$pi" "Show" "$selCond AND NOT UL_$pi AND UV_$pi <> `"$dv`""
            Add-Cond "PolicyDlg" "PSt1_$pi" "Hide" "NOT ($selCond AND NOT UL_$pi AND UV_$pi <> `"$dv`")"
            Add-Cond "PolicyDlg" "PSt2_$pi" "Show" "$selCond AND UL_$pi"
            Add-Cond "PolicyDlg" "PSt2_$pi" "Hide" "NOT ($selCond AND UL_$pi)"
        }
    }

    Add-Ctrl "PolicyDlg" "FootNote"   "Text"       14  219 342 12  $TXT_NOPFX "" "{\VordrFontSmall}Unchanged values are not written. Edited values seed HKCU; Lock enforces HKLM." ""
    Add-Ctrl "PolicyDlg" "BottomLine" "Line"       0   234 370 0   1 "" "" ""
    Add-Ctrl "PolicyDlg" "ResetAll"   "PushButton" 14  243 68  17  3 "" "&Reset all" "Back"
    Add-Ctrl "PolicyDlg" "Back"       "PushButton" 180 243 56  17  3 "" "< &Back"    "Next"
    Add-Ctrl "PolicyDlg" "Next"       "PushButton" 240 243 56  17  3 "" "&Next >"    "Cancel"
    Add-Ctrl "PolicyDlg" "Cancel"     "PushButton" 302 243 56  17  3 "" "Cancel"     "PolList"

    # Disable Next live while any numeric Edit box is empty or out of range
    $allIntOk  = $intChecks -join " AND "
    $anyIntBad = "NOT ($allIntOk)"
    if ($anyIntBad.Length -gt 255) { throw "PolicyDlg numeric validation condition exceeds 255 chars ($($anyIntBad.Length))" }
    Add-Cond "PolicyDlg" "Next" "Enable"  $allIntOk
    Add-Cond "PolicyDlg" "Next" "Disable" $anyIntBad

    $rOrd = 1
    for ($pi = 0; $pi -lt $Policies.Count; $pi++) {
        Add-Evt "PolicyDlg" "ResetAll" "[UL_$pi]" "{}"                   "1" ($rOrd++)
        Add-Evt "PolicyDlg" "ResetAll" "[UV_$pi]" $Policies[$pi].Default "1" ($rOrd++)
    }
    Add-Evt "PolicyDlg" "Back" "NewDialog" "InstallDirDlg" "1" 1
    $nOrd = 1
    Add-Evt "PolicyDlg" "Next" "[UI_ANY_HKLM]" "{}" "1" ($nOrd++)
    Add-Evt "PolicyDlg" "Next" "[UI_ANY_HKCU]" "{}" "1" ($nOrd++)
    for ($pi = 0; $pi -lt $Policies.Count; $pi++) {
        $pol = $Policies[$pi]; $p = $pol.Prop; $dv = $pol.Default
        if ($pol.UserProp) {
            $up = $pol.UserProp
            Add-Evt "PolicyDlg" "Next" "[$p]"          "[UV_$pi]" "UL_$pi"                           ($nOrd++)
            Add-Evt "PolicyDlg" "Next" "[$up]"         "{}"       "UL_$pi"                           ($nOrd++)
            Add-Evt "PolicyDlg" "Next" "[UI_ANY_HKLM]" "1"        "UL_$pi"                           ($nOrd++)
            Add-Evt "PolicyDlg" "Next" "[$p]"          "{}"       "NOT UL_$pi"                       ($nOrd++)
            Add-Evt "PolicyDlg" "Next" "[$up]"         "[UV_$pi]" "NOT UL_$pi AND UV_$pi <> `"$dv`"" ($nOrd++)
            Add-Evt "PolicyDlg" "Next" "[UI_ANY_HKCU]" "1"        "NOT UL_$pi AND UV_$pi <> `"$dv`"" ($nOrd++)
            Add-Evt "PolicyDlg" "Next" "[$up]"         "{}"       "NOT UL_$pi AND UV_$pi = `"$dv`""  ($nOrd++)
        } else {
            Add-Evt "PolicyDlg" "Next" "[$p]"          "[UV_$pi]" "UL_$pi OR UV_$pi <> `"0`""        ($nOrd++)
            Add-Evt "PolicyDlg" "Next" "[UI_ANY_HKLM]" "1"        "UL_$pi OR UV_$pi <> `"0`""        ($nOrd++)
            Add-Evt "PolicyDlg" "Next" "[$p]"          "{}"       "NOT UL_$pi AND UV_$pi = `"0`""    ($nOrd++)
        }
    }
    Add-Evt "PolicyDlg" "Next"   "NewDialog"   "VerifyReadyDlg" $allIntOk ($nOrd++)
    Add-Evt "PolicyDlg" "Cancel" "SpawnDialog" "CancelDlg"      "1" 1

    # 5) VerifyReadyDlg
    Add-Dialog "VerifyReadyDlg" 370 270 $DLG_MODAL $DLG_TITLE "Install" "Install" "Cancel"
    Add-Ctrl "VerifyReadyDlg" "TopArt"      "Bitmap"     0   0   370 44  1          "" "BmpTop" ""
    Add-Ctrl "VerifyReadyDlg" "BannerTitle" "Text"       16  7   290 16  $TXT_TRANS "" "{\VordrFontBanner}Ready to Install Vordr" ""
    Add-Ctrl "VerifyReadyDlg" "BannerSub"   "Text"       16  24  290 14  $TXT_TRANS "" "{\VordrFontBannerSub}Review your installation settings and click Install to begin." ""
    Add-Ctrl "VerifyReadyDlg" "SumDirLbl"   "Text"       18  56  88  13  3          "" "{\VordrFontBold}Install folder:" ""
    Add-Ctrl "VerifyReadyDlg" "SumDirVal"   "Text"       108 56  244 20  $TXT_NOPFX "" "[INSTALLDIR]" ""
    Add-Ctrl "VerifyReadyDlg" "SumArchLbl"  "Text"       18  79  88  13  3          "" "{\VordrFontBold}Target binary:" ""
    Add-Ctrl "VerifyReadyDlg" "SumArchVal"  "Text"       108 79  244 13  3          "" "Native [HOST_NATIVE_ARCH] vordr.exe (v[ProductVersion])" ""
    Add-Ctrl "VerifyReadyDlg" "SumAssocLbl" "Text"       18  97  88  13  3          "" "{\VordrFontBold}.vordr files:" ""
    Add-Ctrl "VerifyReadyDlg" "SumAssocOn"  "Text"       108 97  244 13  3          "" "Registered (double-clicking opens import workflow)" ""
    Add-Ctrl "VerifyReadyDlg" "SumAssocOff" "Text"       108 97  244 13  3          "" "Not registered (skipped)" ""
    Add-Ctrl "VerifyReadyDlg" "SumAutoLbl"  "Text"       18  115 88  13  3          "" "{\VordrFontBold}Windows startup:" ""
    Add-Ctrl "VerifyReadyDlg" "SumAutoOn"   "Text"       108 115 244 13  3          "" "Starts automatically with Windows (notification area)" ""
    Add-Ctrl "VerifyReadyDlg" "SumAutoOff"  "Text"       108 115 244 13  3          "" "Manual start (Start Menu)" ""
    Add-Ctrl "VerifyReadyDlg" "SumPolLbl"   "Text"       18  133 88  13  3          "" "{\VordrFontBold}Settings / policy:" ""
    Add-Ctrl "VerifyReadyDlg" "SumPolNone"  "Text"       108 133 244 36  3          "" "Built-in defaults—nothing written to HKCU or HKLM." ""
    Add-Ctrl "VerifyReadyDlg" "SumPolHkcu"  "Text"       108 133 244 40  3          "" "Custom user defaults will be written to HKCU\SOFTWARE\Vordr (changeable in Settings)." ""
    Add-Ctrl "VerifyReadyDlg" "SumPolHklm"  "Text"       108 133 244 42  3          "" "Locked machine policies will be written to HKLM\SOFTWARE\Vordr. Repeat choices on future upgrades." ""
    Add-Ctrl "VerifyReadyDlg" "SumPolBoth"  "Text"       108 133 244 44  3          "" "Custom HKCU defaults and locked HKLM machine policies will be applied. Repeat HKLM locks on upgrades." ""
    Add-Ctrl "VerifyReadyDlg" "UacNote"     "Text"       18  190 336 32  3          "" "{\VordrFontSmall}Click Install to continue. Windows will ask for administrator approval to install into Program Files and apply any machine settings." ""
    Add-Ctrl "VerifyReadyDlg" "BottomLine"  "Line"       0   234 370 0   1          "" "" ""
    Add-Ctrl "VerifyReadyDlg" "Back"        "PushButton" 180 243 56  17  3          "" "< &Back" "Install"
    Add-Ctrl "VerifyReadyDlg" "Install"     "PushButton" 240 243 56  17  $BTN_SHIELD "" "&Install" "Cancel"
    Add-Ctrl "VerifyReadyDlg" "Cancel"      "PushButton" 302 243 56  17  3          "" "Cancel"   "Back"

    Add-Cond "VerifyReadyDlg" "SumAssocOn"  "Hide" "VORDR_NOASSOC"
    Add-Cond "VerifyReadyDlg" "SumAssocOn"  "Show" "NOT VORDR_NOASSOC"
    Add-Cond "VerifyReadyDlg" "SumAssocOff" "Hide" "NOT VORDR_NOASSOC"
    Add-Cond "VerifyReadyDlg" "SumAssocOff" "Show" "VORDR_NOASSOC"
    Add-Cond "VerifyReadyDlg" "SumAutoOn"   "Show" "VORDR_AUTOSTART = `"1`""
    Add-Cond "VerifyReadyDlg" "SumAutoOn"   "Hide" "NOT (VORDR_AUTOSTART = `"1`")"
    Add-Cond "VerifyReadyDlg" "SumAutoOff"  "Show" "NOT (VORDR_AUTOSTART = `"1`")"
    Add-Cond "VerifyReadyDlg" "SumAutoOff"  "Hide" "VORDR_AUTOSTART = `"1`""
    Add-Cond "VerifyReadyDlg" "SumPolNone"  "Show" "NOT UI_ANY_HKCU AND NOT UI_ANY_HKLM"
    Add-Cond "VerifyReadyDlg" "SumPolNone"  "Hide" "UI_ANY_HKCU OR UI_ANY_HKLM"
    Add-Cond "VerifyReadyDlg" "SumPolHkcu"  "Show" "UI_ANY_HKCU AND NOT UI_ANY_HKLM"
    Add-Cond "VerifyReadyDlg" "SumPolHkcu"  "Hide" "NOT (UI_ANY_HKCU AND NOT UI_ANY_HKLM)"
    Add-Cond "VerifyReadyDlg" "SumPolHklm"  "Show" "UI_ANY_HKLM AND NOT UI_ANY_HKCU"
    Add-Cond "VerifyReadyDlg" "SumPolHklm"  "Hide" "NOT (UI_ANY_HKLM AND NOT UI_ANY_HKCU)"
    Add-Cond "VerifyReadyDlg" "SumPolBoth"  "Show" "UI_ANY_HKCU AND UI_ANY_HKLM"
    Add-Cond "VerifyReadyDlg" "SumPolBoth"  "Hide" "NOT (UI_ANY_HKCU AND UI_ANY_HKLM)"

    Add-Evt "VerifyReadyDlg" "Back"    "NewDialog"   "PolicyDlg" "1" 1
    Add-Evt "VerifyReadyDlg" "Install" "EndDialog"   "Return"    "1" 1
    Add-Evt "VerifyReadyDlg" "Cancel"  "SpawnDialog" "CancelDlg" "1" 1

    # 6) ProgressDlg (MODELESS: Attributes = 5 = Visible|Minimize, NO Modal bit!)
    Add-Dialog "ProgressDlg" 370 270 $DLG_MODELESS $DLG_TITLE "Cancel" "Cancel" "Cancel"
    Add-Ctrl "ProgressDlg" "TopArt"      "Bitmap"      0   0   370 44  1          "" "BmpTop" ""
    Add-Ctrl "ProgressDlg" "BannerTitle" "Text"        16  7   290 16  $TXT_TRANS "" "{\VordrFontBanner}Installing Vordr" ""
    Add-Ctrl "ProgressDlg" "BannerSub"   "Text"        16  24  290 14  $TXT_TRANS "" "{\VordrFontBannerSub}Please wait while Windows Installer configures Vordr." ""
    Add-Ctrl "ProgressDlg" "StatusLbl"   "Text"        18  74  46  13  3          "" "{\VordrFontBold}Status:" ""
    Add-Ctrl "ProgressDlg" "ActionText"  "Text"        68  74  284 14  $TXT_NOPFX "" "Preparing installation..." ""
    Add-Ctrl "ProgressDlg" "ActionData"  "Text"        68  92  284 14  $TXT_NOPFX "" "{\VordrFontSmall}" ""
    Add-Ctrl "ProgressDlg" "ProgressBar" "ProgressBar" 18  114 334 12  65537      "" "Progress" ""
    Add-Ctrl "ProgressDlg" "BottomLine"  "Line"        0   234 370 0   1          "" "" ""
    Add-Ctrl "ProgressDlg" "Cancel"      "PushButton"  302 243 56  17  3          "" "Cancel" "Cancel"
    Add-Map "ProgressDlg" "ActionText"  "ActionText"  "Text"
    Add-Map "ProgressDlg" "ActionData"  "ActionData"  "Text"
    Add-Map "ProgressDlg" "ProgressBar" "SetProgress" "Progress"
    Add-Evt "ProgressDlg" "Cancel" "SpawnDialog" "CancelDlg" "1" 1

    # 7) ExitDlg / UserExitDlg / FatalErrorDlg
    Add-Dialog "ExitDlg" 370 270 $DLG_MODAL $DLG_TITLE "Finish" "Finish" "Finish"
    Add-Ctrl "ExitDlg" "SideArt"    "Bitmap"     0   0   130 234 1          "" "BmpSide" ""
    Add-Ctrl "ExitDlg" "Title"      "Text"       144 18  212 24  $TXT_TRANS "" "{\VordrFontTitle}Vordr Setup Complete" ""
    Add-Ctrl "ExitDlg" "Desc"       "Text"       144 52  212 56  3          "" "Vordr has been installed to your computer and added to the Start Menu. Open Vordr from the Start Menu or notification area to create or unlock your vault." ""
    Add-Ctrl "ExitDlg" "Hint"       "Text"       144 118 212 46  3          "" "{\VordrFontSmall}Remember to keep an independent backup copy of your .vordr file and a physically safe copy of your master password." ""
    Add-Ctrl "ExitDlg" "BottomLine" "Line"       0   234 370 0   1          "" "" ""
    Add-Ctrl "ExitDlg" "Finish"     "PushButton" 302 243 56  17  3          "" "&Finish" "Finish"
    Add-Evt "ExitDlg" "Finish" "EndDialog" "Return" "1" 1

    Add-Dialog "UserExitDlg" 370 270 $DLG_MODAL $DLG_TITLE "Finish" "Finish" "Finish"
    Add-Ctrl "UserExitDlg" "SideArt"    "Bitmap"     0   0   130 234 1          "" "BmpSide" ""
    Add-Ctrl "UserExitDlg" "Title"      "Text"       144 18  212 24  $TXT_TRANS "" "{\VordrFontTitle}Vordr Setup Interrupted" ""
    Add-Ctrl "UserExitDlg" "Desc"       "Text"       144 52  212 60  3          "" "Vordr setup was cancelled before completion. Your system has not been modified. Run the installer again at any time to complete installation." ""
    Add-Ctrl "UserExitDlg" "BottomLine" "Line"       0   234 370 0   1          "" "" ""
    Add-Ctrl "UserExitDlg" "Finish"     "PushButton" 302 243 56  17  3          "" "&Finish" "Finish"
    Add-Evt "UserExitDlg" "Finish" "EndDialog" "Exit" "1" 1

    Add-Dialog "FatalErrorDlg" 370 270 $DLG_MODAL $DLG_TITLE "Finish" "Finish" "Finish"
    Add-Ctrl "FatalErrorDlg" "SideArt"    "Bitmap"     0   0   130 234 1          "" "BmpSide" ""
    Add-Ctrl "FatalErrorDlg" "Title"      "Text"       144 18  212 24  $TXT_TRANS "" "{\VordrFontTitle}Vordr Setup Ended Early" ""
    Add-Ctrl "FatalErrorDlg" "Desc"       "Text"       144 52  212 64  3          "" "Vordr setup ended prematurely because of an error or blocked launch condition. Your system has not been modified." ""
    Add-Ctrl "FatalErrorDlg" "BottomLine" "Line"       0   234 370 0   1          "" "" ""
    Add-Ctrl "FatalErrorDlg" "Finish"     "PushButton" 302 243 56  17  3          "" "&Finish" "Finish"
    Add-Evt "FatalErrorDlg" "Finish" "EndDialog" "Exit" "1" 1

    # 8) MaintenanceDlg (when MSI is re-run on an already-installed matching ProductCode)
    Add-Dialog "MaintenanceDlg" 370 270 $DLG_MODAL $DLG_TITLE "Remove" "Cancel" "Cancel"
    Add-Ctrl "MaintenanceDlg" "TopArt"      "Bitmap"     0   0   370 44  1          "" "BmpTop" ""
    Add-Ctrl "MaintenanceDlg" "BannerTitle" "Text"       16  7   290 16  $TXT_TRANS "" "{\VordrFontBanner}Vordr Maintenance" ""
    Add-Ctrl "MaintenanceDlg" "BannerSub"   "Text"       16  24  290 14  $TXT_TRANS "" "{\VordrFontBannerSub}This version of Vordr is already installed." ""
    Add-Ctrl "MaintenanceDlg" "Desc"        "Text"       18  60  334 48  3          "" "Click Remove to uninstall Vordr from this computer. Uninstalling removes only the Vordr executable, Start Menu shortcut, file association, and MSI-owned HKLM policy values—your vaults and HKCU settings remain untouched." ""
    Add-Ctrl "MaintenanceDlg" "BottomLine"  "Line"       0   234 370 0   1          "" "" ""
    Add-Ctrl "MaintenanceDlg" "Remove"      "PushButton" 240 243 56  17  $BTN_SHIELD "" "&Remove" "Cancel"
    Add-Ctrl "MaintenanceDlg" "Cancel"      "PushButton" 302 243 56  17  3          "" "Cancel"   "Remove"
    Add-Evt "MaintenanceDlg" "Remove" "[REMOVE]"  "ALL"    "1" 1
    Add-Evt "MaintenanceDlg" "Remove" "EndDialog" "Return" "1" 2
    Add-Evt "MaintenanceDlg" "Cancel" "EndDialog" "Exit"   "1" 1

    # 9) CancelDlg & ErrorDlg
    Add-Dialog "CancelDlg" 260 85 $DLG_POPUP "Cancel Vordr Setup" "No" "No" "No"
    Add-Ctrl "CancelDlg" "Text" "Text"       18  14 224 30 3 "" "Are you sure you want to cancel Vordr installation?" ""
    Add-Ctrl "CancelDlg" "Yes"  "PushButton" 132 56 56  17 3 "" "&Yes" "No"
    Add-Ctrl "CancelDlg" "No"   "PushButton" 194 56 56  17 3 "" "&No"  "Yes"
    Add-Evt "CancelDlg" "Yes" "EndDialog" "Exit"   "1" 1
    Add-Evt "CancelDlg" "No"  "EndDialog" "Return" "1" 1

    Add-Dialog "ErrorDlg" 270 105 $DLG_ERROR "Vordr Setup" "ErrorText" "" ""
    Add-Ctrl "ErrorDlg" "ErrorText" "Text"       18  14 234 52 3 "" "Information text" ""
    Add-Ctrl "ErrorDlg" "Y"         "PushButton" 100 78 56  17 3 "" "&Yes"    ""
    Add-Ctrl "ErrorDlg" "N"         "PushButton" 160 78 56  17 3 "" "&No"     ""
    Add-Ctrl "ErrorDlg" "A"         "PushButton" 100 78 56  17 3 "" "&Abort"  ""
    Add-Ctrl "ErrorDlg" "C"         "PushButton" 160 78 56  17 3 "" "&Cancel" ""
    Add-Ctrl "ErrorDlg" "I"         "PushButton" 100 78 56  17 3 "" "&Ignore" ""
    Add-Ctrl "ErrorDlg" "O"         "PushButton" 107 78 56  17 3 "" "&OK"     ""
    Add-Ctrl "ErrorDlg" "R"         "PushButton" 160 78 56  17 3 "" "&Retry"  ""
    Add-Evt "ErrorDlg" "Y" "EndDialog" "ErrorYes"    "1" 1
    Add-Evt "ErrorDlg" "N" "EndDialog" "ErrorNo"     "1" 1
    Add-Evt "ErrorDlg" "A" "EndDialog" "ErrorAbort"  "1" 1
    Add-Evt "ErrorDlg" "C" "EndDialog" "ErrorCancel" "1" 1
    Add-Evt "ErrorDlg" "I" "EndDialog" "ErrorIgnore" "1" 1
    Add-Evt "ErrorDlg" "O" "EndDialog" "ErrorOk"     "1" 1
    Add-Evt "ErrorDlg" "R" "EndDialog" "ErrorRetry"  "1" 1

    # Standard ActionText, UIText, and Error templates for crisp progress & error messages
    $actionTexts = @(
        @("AppSearch",              "Detecting system architecture",                "Property: [1]"),
        @("FindRelatedProducts",    "Checking for existing Vordr installations",    "Found: [1]"),
        @("LaunchConditions",       "Evaluating launch conditions",                 ""),
        @("CostInitialize",         "Computing space requirements",                 ""),
        @("FileCost",               "Computing space requirements",                 ""),
        @("CostFinalize",           "Computing space requirements",                 ""),
        @("InstallValidate",        "Validating installation",                      ""),
        @("InstallInitialize",      "Preparing installation",                       ""),
        @("RemoveExistingProducts", "Removing previous Vordr installation",         "Application: [1]"),
        @("CreateFolders",          "Creating installation folder",                 "Folder: [1]"),
        @("InstallFiles",           "Copying Vordr files",                          "File: [1]"),
        @("CreateShortcuts",        "Creating Start Menu shortcut",                 "Shortcut: [1]"),
        @("WriteRegistryValues",    "Writing registry configuration",               "Key: [1], Name: [2]"),
        @("RemoveFiles",            "Removing files",                               "File: [1]"),
        @("RemoveRegistryValues",   "Removing registry values",                     "Key: [1], Name: [2]"),
        @("RemoveShortcuts",        "Removing shortcuts",                           "Shortcut: [1]"),
        @("PublishProduct",         "Registering Vordr",                            "")
    )
    foreach ($at in $actionTexts) {
        ExecParams "INSERT INTO ``ActionText`` (``Action``,``Description``,``Template``) VALUES (?,?,?)" $at
    }
    $uiTexts = @(
        @("NewFolder", "New Folder"),
        @("bytes",     "bytes"),
        @("KB",        "KB"),
        @("MB",        "MB"),
        @("GB",        "GB")
    )
    foreach ($ut in $uiTexts) {
        ExecParams "INSERT INTO ``UIText`` (``Key``,``Text``) VALUES (?,?)" $ut
    }
    $errors = @(
        @(0,    "{{Fatal error: }}"),
        @(1,    "{{Error [1]. }}"),
        @(2,    "Warning [1]. "),
        @(4,    "Info [1]. "),
        @(5,    "The installer has encountered an unexpected error installing this package. Error code: [1]."),
        @(1301, "Cannot create the file '[2]'. A directory with this name already exists."),
        @(1303, "The installer has insufficient privileges to access this directory: [2]."),
        @(1314, "The specified path '[2]' is unavailable."),
        @(1324, "The folder path '[2]' contains an invalid character."),
        @(1325, "'[2]' is not a valid short file name."),
        @(1327, "Invalid Drive: [2]"),
        @(1602, "Are you sure you want to cancel?"),
        @(1603, "The file [2][3] is being held in use. Close that application and retry."),
        @(1707, "Installation completed successfully."),
        @(1708, "Installation failed."),
        @(1709, "Product: [2] -- [3]"),
        @(1925, "You do not have sufficient privileges to complete this installation for all users of the machine. Log on as administrator and then retry this installation.")
    )
    foreach ($er in $errors) {
        ExecParams "INSERT INTO ``Error`` (``Error``,``Message``) VALUES (?,?)" @([int]$er[0], $er[1])
    }
    Write-Host ("  ui wizard      : 4 screens (Welcome, Folder + startup, {0}-setting ListBox + lock editor, Ready) + Vordr graphics" -f $Policies.Count)

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
        if ($p.UserProp) {
            if ($secure -notcontains $p.UserProp) {
                throw ("{0} is missing from SecureCustomProperties - HKCU user default would be dropped" -f $p.UserProp)
            }
            if ($p.UserProp -cne $p.UserProp.ToUpper()) {
                throw ("{0} is not all-uppercase" -f $p.UserProp)
            }
        }
    }
    if ($secure -notcontains $AssocProp)     { throw "$AssocProp is missing from SecureCustomProperties - the opt-out would be ignored" }
    if ($secure -notcontains $AutoStartProp) { throw "$AutoStartProp is missing from SecureCustomProperties - autostart opt-in would be ignored" }
    if ($secure -notcontains "HOST_NATIVE_ARCH") { throw "HOST_NATIVE_ARCH is missing from SecureCustomProperties - ARM64 selection would be dropped on elevation" }
    $allGuids = @($ComponentGuid, $Arm64ComponentGuid, $AssocGuid, $AutoStartGuid) +
                @($Policies | ForEach-Object { $_.Guid }) +
                @($Policies | Where-Object { $_.UserGuid } | ForEach-Object { $_.UserGuid })
    $dupAll = $allGuids | Group-Object | Where-Object { $_.Count -gt 1 }
    if ($dupAll) { throw ("component GUID reused: " + ($dupAll[0].Name)) }
    $allCompNames = @($Policies | ForEach-Object { $_.Comp }) + @($Policies | Where-Object { $_.UserComp } | ForEach-Object { $_.UserComp })
    $dupComp = $allCompNames | Group-Object | Where-Object { $_.Count -gt 1 }
    if ($dupComp) { throw ("component name reused: " + $dupComp[0].Name) }
    foreach ($a in @("WriteRegistryValues","RemoveRegistryValues")) {
        if ($names -notcontains $a) { throw "$a is missing - the Registry table would never be processed" }
    }
    Write-Host ("  policy check   : {0} HKLM + {1} HKCU + autostart properties secure, unique and sequenced" -f $Policies.Count, $hkcuCount)

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
    SetSI 14 500                                    # min installer version (5.0 for MsiLockPermissionsEx)
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
    Write-Host ("  autostart     -> HKLM\{0}\Vordr (opt-in with {1}=1)" -f $RunKey, $AutoStartProp)
    Write-Host ("  HKCU defaults -> VORDR_USER_<NAME>=<val> seeds unlocked user-editable HKCU\{0} (Permanent on uninstall)" -f $PolicyKey)
}
finally {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}
