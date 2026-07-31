<#
    make_msi.ps1 - build a per-user MSI around bin\vordr.exe.

    No third-party toolchain: the MSI database is authored directly through the
    WindowsInstaller COM automation, and the payload is packed with makecab.
    Requiring WiX to cut a release would undercut "no third-party code".

    WHAT IT INSTALLS, and just as importantly what it does not:

      * one file, vordr.exe, into %LOCALAPPDATA%\Vordr
      * a Start Menu shortcut
      * an Add/Remove Programs entry carrying ProductName + ProductVersion

    It owns NOTHING else.  No vault, no HKCU settings, no registry values.  That
    is deliberate: uninstall removes only what MSI installed, so a user who
    uninstalls Vordr keeps their vault and their configuration.  An installer
    that "cleans up" a password manager's data on removal would destroy the
    user's secrets, and MSI makes that mistake easy - one RemoveFile row aimed at
    the wrong directory is all it takes.  There are none here, and there must
    never be.

    PER-USER on purpose: installs to LocalAppData with no elevation, matching the
    asInvoker execution level vordr.manifest declares.  A per-machine MSI would
    contradict it and would need admin rights to install a program that never
    needs them.

    The version is read from the exe's own version resource, so vordr.rc stays
    the single source of truth - the MSI cannot drift from the binary it wraps.

    Usage:  powershell -ExecutionPolicy Bypass -File tools\make_msi.ps1
            [-Exe bin\vordr.exe] [-OutDir bin]
#>
[CmdletBinding()]
param(
    [string]$Exe    = "bin\vordr.exe",
    [string]$OutDir = "bin"
)

$ErrorActionPreference = "Stop"

# Stable identity.  UpgradeCode must NEVER change - it is what lets a new MSI
# recognise and replace an older install instead of sitting beside it.
# ProductCode is regenerated per build, which is what tells Windows the payload
# differs (required for RemoveExistingProducts to do its job).
$UpgradeCode  = "{6A1D0C7E-9E2F-4F1B-9C2A-7E5B0D3A8F41}"
$ComponentGuid= "{2F8B5A31-4C6D-4E7A-8B90-1D3E5F7A9C24}"
$Manufacturer = "Thomas Smistad"
$ProductName  = "Vordr"
$InstallDir   = "Vordr"

function Resolve-Full([string]$p) {
    if ([System.IO.Path]::IsPathRooted($p)) { $p } else { Join-Path (Get-Location) $p }
}

$exePath = Resolve-Full $Exe
if (-not (Test-Path $exePath)) { throw "not found: $exePath  (build first: build.cmd release)" }

# --- version comes from the binary, never typed twice ------------------------
$vi = (Get-Item $exePath).VersionInfo
$fv = $vi.FileVersion
if (-not $fv) { throw "$exePath has no version resource" }
$parts = ($fv -split '[.,]') | ForEach-Object { [int]$_ }
# MSI ProductVersion is max three fields; the 4th is ignored by Windows Installer
$productVersion = "{0}.{1}.{2}" -f $parts[0], $parts[1], $parts[2]
Write-Host ("  exe            : {0}" -f $exePath)
Write-Host ("  FileVersion    : {0}  ->  MSI ProductVersion {1}" -f $fv, $productVersion)

$outMsi = Join-Path (Resolve-Full $OutDir) ("vordr-{0}.msi" -f $productVersion)
if (Test-Path $outMsi) { Remove-Item $outMsi -Force }

# --- pack the payload into a cab --------------------------------------------
# MSI stores files in a cabinet; the File table's key must match the cab member.
$work = Join-Path $env:TEMP ("vordrmsi_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Copy-Item $exePath (Join-Path $work "vordr.exe")
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
"$work\vordr.exe" vordr.exe
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
    Exec "CREATE TABLE ``Shortcut`` (``Shortcut`` CHAR(72) NOT NULL, ``Directory_`` CHAR(72) NOT NULL, ``Name`` CHAR(128) NOT NULL, ``Component_`` CHAR(72) NOT NULL, ``Target`` CHAR(72) NOT NULL, ``Arguments`` CHAR(255), ``Description`` CHAR(255), ``Hotkey`` SHORT, ``Icon_`` CHAR(72), ``IconIndex`` SHORT, ``ShowCmd`` SHORT, ``WkDir`` CHAR(72) PRIMARY KEY ``Shortcut``)"
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
        # per-user, no elevation: matches the asInvoker manifest
        "MSIINSTALLPERUSER"  = "1"      # ALLUSERS deliberately ABSENT = per-user
        "ARPNOMODIFY"        = "1"
        "ARPNOREPAIR"        = "1"
        "ARPURLINFOABOUT"    = "https://github.com/xxtsxx/Vordr"
        "ARPHELPLINK"        = "https://github.com/xxtsxx/Vordr/blob/master/SECURITY.md"
        "InstallScope"       = "perUser"
        "SecureCustomProperties" = "OLDERVERSIONBEINGUPGRADED"
    }
    foreach ($k in $props.Keys) {
        $v = $props[$k] -replace "'", "''"
        Exec "INSERT INTO ``Property`` (``Property``,``Value``) VALUES ('$k','$v')"
    }

    Exec "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('TARGETDIR','','SourceDir')"
    Exec "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('LocalAppDataFolder','TARGETDIR','.')"
    Exec "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('INSTALLDIR','LocalAppDataFolder','$InstallDir')"
    Exec "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('ProgramMenuFolder','TARGETDIR','.')"

    # Component attributes 0 = per-machine-style file component; msidbComponentAttributes
    # 4 (RegistryKeyPath) is NOT used - the exe itself is the key path.
    Exec "INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('VordrExe','$ComponentGuid','INSTALLDIR',0,'','vordr.exe')"
    Exec "INSERT INTO ``Feature`` (``Feature``,``Feature_Parent``,``Title``,``Description``,``Display``,``Level``,``Directory_``,``Attributes``) VALUES ('Main','','Vordr','Vordr password manager',1,1,'INSTALLDIR',0)"
    Exec "INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','VordrExe')"

    $size = (Get-Item $exePath).Length
    Exec "INSERT INTO ``File`` (``File``,``Component_``,``FileName``,``FileSize``,``Version``,``Language``,``Attributes``,``Sequence``) VALUES ('vordr.exe','VordrExe','vordr.exe',$size,'$fv','1033',512,1)"
    Exec "INSERT INTO ``Media`` (``DiskId``,``LastSequence``,``DiskPrompt``,``Cabinet``,``VolumeLabel``,``Source``) VALUES (1,1,'','#vordr.cab','','')"

    Exec "INSERT INTO ``Shortcut`` (``Shortcut``,``Directory_``,``Name``,``Component_``,``Target``,``Arguments``,``Description``,``ShowCmd``,``WkDir``) VALUES ('VordrSC','ProgramMenuFolder','Vordr','VordrExe','[INSTALLDIR]vordr.exe','','Vordr password manager',1,'INSTALLDIR')"

    # upgrade: replace an older install rather than sitting beside it
    Exec "INSERT INTO ``Upgrade`` (``UpgradeCode``,``VersionMin``,``VersionMax``,``Language``,``Attributes``,``Remove``,``ActionProperty``) VALUES ('$UpgradeCode','0.0.0','$productVersion','',257,'','OLDERVERSIONBEINGUPGRADED')"

    # Standard sequence.  RemoveExistingProducts runs after InstallFiles so an
    # upgrade never leaves the user without the exe if it fails mid-way.
    $seq = @(
        @("FindRelatedProducts",   "",  25),
        @("LaunchConditions",      "",  100),
        @("CostInitialize",        "",  800),
        @("FileCost",              "",  900),
        @("CostFinalize",          "", 1000),
        @("InstallValidate",       "", 1400),
        @("InstallInitialize",     "", 1500),
        @("ProcessComponents",     "", 1600),
        @("UnpublishFeatures",     "", 1800),
        @("RemoveShortcuts",       "", 3200),
        @("RemoveFiles",           "", 3500),
        @("InstallFiles",          "", 4000),
        @("CreateShortcuts",       "", 4500),
        @("RemoveExistingProducts","", 5000),
        @("RegisterUser",          "", 6000),
        @("RegisterProduct",       "", 6100),
        @("PublishFeatures",       "", 6300),
        @("PublishProduct",        "", 6400),
        @("InstallFinalize",       "", 6600)
    )
    foreach ($s in $seq) {
        Exec ("INSERT INTO ``InstallExecuteSequence`` (``Action``,``Condition``,``Sequence``) VALUES ('{0}','{1}',{2})" -f $s[0], $s[1], $s[2])
    }
    foreach ($a in @(@("CostInitialize",800),@("FileCost",900),@("CostFinalize",1000),@("ExecuteAction",1300))) {
        Exec ("INSERT INTO ``InstallUISequence`` (``Action``,``Condition``,``Sequence``) VALUES ('{0}','',{1})" -f $a[0], $a[1])
    }
    foreach ($a in @(@("CostInitialize",800),@("FileCost",900),@("CostFinalize",1000),@("InstallValidate",1400),@("InstallInitialize",1500),@("InstallAdminPackage",3900),@("InstallFiles",4000),@("InstallFinalize",6600))) {
        Exec ("INSERT INTO ``AdminExecuteSequence`` (``Action``,``Condition``,``Sequence``) VALUES ('{0}','',{1})" -f $a[0], $a[1])
    }

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
    SetSI 6  "Per-user install of Vordr $productVersion"
    SetSI 7  "x64;1033"                             # template: 64-bit package
    SetSI 9  ("{" + [guid]::NewGuid().ToString().ToUpper() + "}")   # package code
    SetSI 14 200                                    # min installer version
    SetSI 15 2                                      # word count: compressed, no admin
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
    Write-Host "  installs   %LOCALAPPDATA%\$InstallDir\vordr.exe + a Start Menu shortcut"
    Write-Host "  owns       that file only - no vault, no HKCU settings, nothing else"
    Write-Host "  uninstall  removes the exe and the shortcut; the vault is untouched"
}
finally {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}
