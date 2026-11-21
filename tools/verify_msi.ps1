<#
    verify_msi.ps1 - prove a built MSI's policy wiring without installing it.

    Every failure this looks for is SILENT in the field: the install succeeds,
    the property is accepted, and either nothing is written or something is
    written that nobody asked for.  None of them shows up in `msiexec /a`
    either - an administrative install just unpacks the payload, it does not
    evaluate component conditions or the Registry table.  (That is how a badly
    sequenced RemoveExistingProducts once sailed through /a and then failed a
    real install with error 2613.)

    Two halves:

      1. Read the tables back - Registry, Component, SecureCustomProperties.
         This proves the rows were written as intended.

      2. COST the package with properties set and ask Windows Installer which
         components it would install.  This proves the component CONDITIONS
         work, which reading rows cannot.  Costing touches nothing: the package
         is opened with "ignore machine state", no install is performed, and
         no elevation is needed.

    Usage:  powershell -ExecutionPolicy Bypass -File tools\verify_msi.ps1 `
                       [-Msi bin\vordr-0.8.2.msi]
    Exit code 0 = all checks passed.
#>
[CmdletBinding()]
param([string]$Msi = "")

$ErrorActionPreference = "Stop"

# Auto-discover bin\vordr-*.msi when -Msi is omitted so a bare invocation never
# blocks indefinitely on an interactive PowerShell parameter prompt.
if ([string]::IsNullOrWhiteSpace($Msi)) {
    $repoBin = Join-Path (Split-Path -Parent $PSScriptRoot) "bin"
    $cands   = @(Get-ChildItem -Path (Join-Path $repoBin "vordr-*.msi") -File -ErrorAction SilentlyContinue)
    if ($cands.Count -eq 0) {
        throw "No MSI found matching $repoBin\vordr-*.msi (run tools\make_msi.ps1 first, or pass -Msi <path>)."
    }
    if ($cands.Count -gt 1) {
        throw ("Multiple MSIs found in $repoBin ({0}); pass -Msi <path> explicitly." -f (($cands | ForEach-Object { $_.Name }) -join ", "))
    }
    $Msi = $cands[0].FullName
}

# OpenPackage needs a rooted path - given a relative one it fails with the
# generic "OpenPackage,PackagePath,Options" COM error, while OpenDatabase
# accepts it, so the failure looks like a corrupt package rather than a path.
$Msi = (Resolve-Path $Msi).Path
Write-Host ("msi package     : {0}" -f $Msi)
$installer = New-Object -ComObject WindowsInstaller.Installer
$installer.UILevel = 2                          # msiUILevelNone: never block on modal error UI
$db = $installer.OpenDatabase($Msi, 0)          # msiOpenDatabaseModeReadOnly

function Rows([string]$sql, [int]$cols) {
    # $v.Execute() and $v.Close() each return $null, and an uncaptured $null is
    # still pipeline OUTPUT - it lands in the result as a phantom row.  Hence
    # the $null = on both, and @() so a single-column query still yields rows
    # rather than bare strings.
    $v = $db.OpenView($sql)
    $null = $v.Execute()
    $out = @()
    while ($true) {
        $r = $v.Fetch()
        if ($null -eq $r) { break }
        $out += ,@(1..$cols | ForEach-Object { $r.StringData($_) })
    }
    $null = $v.Close()
    ,$out
}

$fail = 0
function Bad([string]$msg) { Write-Host "  FAIL: $msg"; $script:fail++ }

# --- 1. the rows ------------------------------------------------------------
$reg  = Rows "SELECT ``Registry``,``Root``,``Key``,``Name``,``Value``,``Component_`` FROM ``Registry``" 6
$comp = Rows "SELECT ``Component``,``ComponentId``,``Attributes``,``Condition``,``KeyPath`` FROM ``Component``" 5
$fc   = Rows "SELECT ``Feature_``,``Component_`` FROM ``FeatureComponents``" 2
$scp  = Rows "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='SecureCustomProperties'" 1
$secure = if ($scp.Count) { $scp[0][0] -split ";" } else { @() }
$byName = @{}; foreach ($c in $comp) { $byName[$c[0]] = $c }
$inFeature = @{}; foreach ($f in $fc) { $inFeature[$f[1]] = $true }

# Policy rows and file-association rows are checked differently, so split them
# by the component they belong to rather than guessing from the key.
$polRows   = @($reg | Where-Object { $_[5] -like "Pol*" })
$assocRows = @($reg | Where-Object { $_[5] -eq "FileAssoc" })
$other     = @($reg | Where-Object { $_[5] -notlike "Pol*" -and $_[5] -ne "FileAssoc" })
foreach ($r in $other) { Bad "$($r[0]) belongs to $($r[5]), which this script knows nothing about - add a rule for it rather than leaving it unchecked" }

function CommonChecks($r) {
    $rk, $root, $key, $name, $value, $cname = $r
    $c = $byName[$cname]
    if (-not $c) { Bad "$rk names component $cname, which does not exist"; return $null }
    if ([int]$root -ne 2)               { Bad "$rk writes to root $root, not HKLM (2)" }
    # 256 = write to the 64-bit view.  Without it, an x64 package silently
    # redirects into WOW6432Node, where the 64-bit vordr.exe never looks: the
    # install succeeds and the entry simply has no effect.
    if (-not ([int]$c[2] -band 256))    { Bad "$cname is not marked 64-bit; the value would land in WOW6432Node" }
    if (-not ([int]$c[2] -band 4))      { Bad "$cname does not use a registry row as the key path" }
    if (-not $inFeature[$cname])        { Bad "$cname is in no feature, so it is never installed" }
    if ([string]::IsNullOrEmpty($c[3])) { Bad "$cname has no condition" }
    else {
        $prop = ($c[3] -replace '^NOT\s+', '')
        if ($prop -cne $prop.ToUpper()) { Bad "$cname's condition '$($c[3])' is not a public (uppercase) property" }
        if ($secure -notcontains $prop) { Bad "$prop is missing from SecureCustomProperties - dropped before the elevated half of the install" }
    }
    $c
}

Write-Host ("policy values   : {0}" -f $polRows.Count)
if ($polRows.Count -ne 16) { Bad "expected 16 policy Registry rows, found $($polRows.Count)" }
$polNames = @($polRows | ForEach-Object { $_[3] })
foreach ($reqPol in @("AllowUncVault", "AllowScreenCapture")) {
    if ($polNames -notcontains $reqPol) { Bad "policy row '$reqPol' is missing from Registry table" }
}
foreach ($r in $polRows) {
    Write-Host ("  HKLM\{0}\{1} = {2}   [{3}]" -f $r[2], $r[3], $r[4], $r[5])
    $c = CommonChecks $r
    if (-not $c) { continue }
    if ($r[4] -notmatch '^#\[[A-Z0-9_]+\]$') { Bad "$($r[0]) value '$($r[4])' is not '#[PROPERTY]' - it would not be a REG_DWORD driven by a property" }
    if ($c[3] -match '^NOT\s')               { Bad "$($r[5]) is conditioned on the ABSENCE of its property - it would be written when nobody asked" }
}

Write-Host ""
Write-Host ("file assoc      : {0} rows" -f $assocRows.Count)
foreach ($r in $assocRows) {
    Write-Host ("  HKLM\{0}  {1} = {2}" -f $r[2], $(if ($r[3]) { $r[3] } else { "(default)" }), $r[4])
    $null = CommonChecks $r
    if ($r[2] -notlike "SOFTWARE\Classes\*") { Bad "$($r[0]) writes outside SOFTWARE\Classes" }
}
if ($assocRows.Count) {
    $ext = $assocRows | Where-Object { $_[2] -eq "SOFTWARE\Classes\.vordr" }
    $cmd = $assocRows | Where-Object { $_[2] -like "*\shell\open\command" }
    $ico = $assocRows | Where-Object { $_[2] -like "*\DefaultIcon" }
    $del = $assocRows | Where-Object { $_[3] -eq "-" }
    if (-not $ext) { Bad "nothing associates the .vordr extension with the ProgId" }
    elseif ($ext[3]) { Bad "the .vordr row sets a named value, not the key's default - the extension would stay unassociated" }
    if (-not $cmd) { Bad "no shell\open\command - double-clicking a .vordr would do nothing" }
    else {
        if ($cmd[4] -notlike '*[[]INSTALLDIR]vordr.exe*') { Bad "the open command does not run [INSTALLDIR]vordr.exe: $($cmd[4])" }
        if ($cmd[4] -notlike '*"%1"*') { Bad "the open command does not pass a QUOTED %1 - a vault path containing a space would arrive split into fragments: $($cmd[4])" }
    }
    if (-not $ico) { Bad "no DefaultIcon - .vordr files would show a blank document icon" }
    if (-not $del) { Bad "nothing removes the ProgId key on uninstall - .vordr would keep pointing at a class that no longer opens" }
    elseif ($del[2] -eq "SOFTWARE\Classes\.vordr") { Bad "the '-' row deletes the .vordr key itself, taking any other application's OpenWithProgids with it" }
}

$dup = $comp | Group-Object { $_[1] } | Where-Object { $_.Count -gt 1 -and $_.Name }
foreach ($d in $dup) { Bad ("component GUID {0} is shared by {1}" -f $d.Name, (($d.Group | ForEach-Object { $_[0] }) -join ", ")) }

# --- 2. does the condition actually gate the component? ---------------------
function Cost([hashtable]$set) {
    $s = $installer.OpenPackage($Msi, 1)        # 1 = ignore machine state
    foreach ($k in $set.Keys) { $s.Property($k) = $set[$k] }
    $null = $s.DoAction("CostInitialize")
    $null = $s.DoAction("FileCost")
    $null = $s.DoAction("CostFinalize")
    # Select the feature, then re-cost: component states follow the feature.
    $s.GetType().InvokeMember("FeatureRequestState","SetProperty",$null,$s,@("Main",3)) | Out-Null
    $null = $s.DoAction("CostFinalize")
    $out = @{}
    foreach ($c in $comp) {
        $out[$c[0]] = $s.GetType().InvokeMember("ComponentRequestState","GetProperty",$null,$s,@($c[0]))
    }
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($s)
    $out
}

# INSTALLSTATE_LOCAL = 3.  Anything else means "not going to be written".
$LOCAL = 3
$before = $fail
$none = Cost @{}
Write-Host ""
Write-Host "costing with no properties set:"
foreach ($r in $polRows) {
    if ($none[$r[5]] -eq $LOCAL) { Bad "$($r[5]) installs with no property set - $($r[3]) would be written, and its PRESENCE locks the setting against the user" }
}
if ($assocRows.Count -and $none["FileAssoc"] -ne $LOCAL) {
    Bad "the file association is not registered by default - a plain install would leave .vordr unopenable"
}
if ($fail -eq $before) { Write-Host "  no policy value written; the association registered - ok" }

$before = $fail
Write-Host ""
Write-Host "costing each property individually:"
foreach ($r in $polRows) {
    $prop = $byName[$r[5]][3]
    $one  = Cost @{ $prop = "1" }
    if ($one[$r[5]] -ne $LOCAL) { Bad "$prop=1 does not install $($r[5]) - the property would be accepted and do nothing" }
    foreach ($o in $polRows) {
        if ($o[5] -ne $r[5] -and $one[$o[5]] -eq $LOCAL) { Bad "$prop=1 also writes $($o[3]) - properties are not independent" }
    }
}
if ($fail -eq $before) { Write-Host ("  each of the {0} properties writes exactly its own value - ok" -f $polRows.Count) }

if ($assocRows.Count) {
    $before = $fail
    Write-Host ""
    Write-Host "costing the association opt-out:"
    $off = Cost @{ "VORDR_NOASSOC" = "1" }
    if ($off["FileAssoc"] -eq $LOCAL) { Bad "VORDR_NOASSOC=1 still registers the association" }
    if ($off["VordrExe"] -ne $LOCAL)  { Bad "VORDR_NOASSOC=1 also suppresses the x64 exe" }
    $offArm = Cost @{ "VORDR_NOASSOC" = "1"; "HOST_NATIVE_ARCH" = "ARM64" }
    if ($offArm["FileAssoc"] -eq $LOCAL)     { Bad "VORDR_NOASSOC=1 on ARM64 still registers the association" }
    if ($offArm["VordrExeArm64"] -ne $LOCAL) { Bad "VORDR_NOASSOC=1 on ARM64 also suppresses the ARM64 exe" }
    if ($fail -eq $before) { Write-Host "  VORDR_NOASSOC=1 drops the association and nothing else (x64 + ARM64) - ok" }
}

# --- 2a. universal x64 + ARM64 architecture selection -----------------------
Write-Host ""
$before = $fail
Write-Host "universal architecture selection (x64 + ARM64):"
if ($secure -notcontains "HOST_NATIVE_ARCH") {
    Bad "HOST_NATIVE_ARCH is missing from SecureCustomProperties - ARM64 selection would be dropped on elevation"
}
$appSearch = Rows "SELECT ``Property``,``Signature_`` FROM ``AppSearch``" 2
$regLoc    = Rows "SELECT ``Signature_``,``Root``,``Key``,``Name``,``Type`` FROM ``RegLocator``" 5
$asMatch   = @($appSearch | Where-Object { $_[0] -eq "HOST_NATIVE_ARCH" -and $_[1] -eq "SigHostArch" })
if ($asMatch.Count -ne 1) { Bad "AppSearch lacks HOST_NATIVE_ARCH -> SigHostArch" }
$rlMatch   = @($regLoc | Where-Object { $_[0] -eq "SigHostArch" })
if ($rlMatch.Count -ne 1) { Bad "RegLocator lacks SigHostArch" }
else {
    $rl = $rlMatch[0]
    if ([int]$rl[1] -ne 2) { Bad "SigHostArch Root is $($rl[1]), expected 2 (HKLM)" }
    if ($rl[2] -ne "SYSTEM\CurrentControlSet\Control\Session Manager\Environment") { Bad "SigHostArch Key is '$($rl[2])'" }
    if ($rl[3] -ne "PROCESSOR_ARCHITECTURE") { Bad "SigHostArch Name is '$($rl[3])'" }
    if ([int]$rl[4] -ne 18) { Bad "SigHostArch Type is $($rl[4]), expected 18 (raw+64bit)" }
}
foreach ($exeComp in @("VordrExe", "VordrExeArm64")) {
    $ec = $byName[$exeComp]
    if (-not $ec) { Bad "missing executable component $exeComp" }
    else {
        if (-not ([int]$ec[2] -band 256)) { Bad "$exeComp is not marked 64-bit (Attributes=$($ec[2]))" }
        if ([int]$ec[2] -band 4)          { Bad "$exeComp has RegistryKeyPath set instead of File KeyPath" }
        if (-not $inFeature[$exeComp])    { Bad "$exeComp is not in any feature" }
    }
}
$cDef   = Cost @{}
$cAmd64 = Cost @{ "HOST_NATIVE_ARCH" = "AMD64" }
$cArm64 = Cost @{ "HOST_NATIVE_ARCH" = "ARM64" }
$cArmLo = Cost @{ "HOST_NATIVE_ARCH" = "arm64" }
if ($cDef["VordrExe"] -ne $LOCAL -or $cDef["VordrExeArm64"] -eq $LOCAL) {
    Bad "default (unset HOST_NATIVE_ARCH) did not exclusively select VordrExe"
}
if ($cAmd64["VordrExe"] -ne $LOCAL -or $cAmd64["VordrExeArm64"] -eq $LOCAL) {
    Bad "HOST_NATIVE_ARCH=AMD64 did not exclusively select VordrExe"
}
if ($cArm64["VordrExeArm64"] -ne $LOCAL -or $cArm64["VordrExe"] -eq $LOCAL) {
    Bad "HOST_NATIVE_ARCH=ARM64 did not exclusively select VordrExeArm64"
}
if ($cArmLo["VordrExeArm64"] -ne $LOCAL -or $cArmLo["VordrExe"] -eq $LOCAL) {
    Bad "HOST_NATIVE_ARCH=arm64 (lowercase) did not exclusively select VordrExeArm64"
}
if ($fail -eq $before) { Write-Host "  AppSearch/RegLocator + mutually exclusive x64/ARM64 costing - ok" }

# --- 2b. payload structure (ported from Myrkr's verifier) --------------------
# Each of these produces a package that builds, verifies its policy wiring, and
# then fails or misbehaves only when somebody installs it.
Write-Host ""
$before = $fail
$pvAll  = Rows "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='ProductVersion'" 1
$pvNow  = $pvAll[0][0]
$files  = Rows "SELECT ``File``,``Component_``,``Version``,``Sequence``,``FileName`` FROM ``File``" 5
$regKeys  = @($reg   | ForEach-Object { $_[0] })
$fileKeys = @($files | ForEach-Object { $_[0] })
if ($files.Count -ne 2) { Bad "expected 2 File rows (x64 + ARM64), found $($files.Count)" }
foreach ($f in $files) {
    if ($f[4] -ne "vordr.exe") { Bad "File $($f[0]) installs as '$($f[4])', expected 'vordr.exe'" }
}
# KeyPath names the row Windows Installer uses to decide whether the component is
# installed.  With RegistryKeyPath (0x4) it must be a Registry row, otherwise a
# File row; a dangling one fails the install with error 2715.  The 0x4 bit alone
# (checked above) says nothing about whether the row it points at exists.
foreach ($c in $comp) {
    if ([string]::IsNullOrEmpty($c[4])) { continue }
    if ([int]$c[2] -band 4) {
        if ($regKeys -notcontains $c[4]) { Bad "component $($c[0]) KeyPath '$($c[4])' names no Registry row (error 2715 at install)" }
    } elseif ($fileKeys -notcontains $c[4]) {
        Bad "component $($c[0]) KeyPath '$($c[4])' names no File row (error 2715 at install)"
    }
}
# The exe's version resource is the source of truth; the File row must agree with
# the package or an installed copy cannot be identified from a support call.
foreach ($f in $files) {
    if (-not $f[2].StartsWith($pvNow)) { Bad "File $($f[0]) Version $($f[2]) does not match ProductVersion $pvNow" }
}
# Media.LastSequence below the highest File.Sequence leaves a payload unextracted.
$media = Rows "SELECT ``Cabinet``,``LastSequence`` FROM ``Media``" 2
$maxSeq = ($files | ForEach-Object { [int]$_[3] } | Measure-Object -Maximum).Maximum
if ($media.Count -ne 1) { Bad "expected one Media row, found $($media.Count)" }
else {
    if ([int]$media[0][1] -lt $maxSeq) { Bad "Media.LastSequence $($media[0][1]) does not cover File.Sequence $maxSeq" }
    # '#name' = the cabinet is a stream INSIDE the package.  Without the stream the
    # MSI asks for an external vordr.cab that was never shipped.
    $cabName = $media[0][0]
    if (-not $cabName.StartsWith("#")) { Bad "Media names an external cabinet '$cabName' - the MSI would need a separate file" }
    else {
        $streams = Rows "SELECT ``Name`` FROM ``_Streams``" 1
        $snames  = @($streams | ForEach-Object { $_[0] })
        $streamKey = $cabName.Substring(1)
        if ($snames -notcontains $streamKey) { Bad "cabinet stream '$streamKey' is not embedded in the package" }
        else {
            # Extract embedded CAB and verify PE Machine of both embedded payloads.
            $tmpCabDir = Join-Path $env:TEMP ("vordrmsiverify_" + [guid]::NewGuid().ToString("N"))
            New-Item -ItemType Directory -Path $tmpCabDir | Out-Null
            try {
                $cabOut = Join-Path $tmpCabDir $streamKey
                $sv = $db.OpenView("SELECT ``Data`` FROM ``_Streams`` WHERE ``Name``='$streamKey'")
                $null = $sv.Execute()
                $sr = $sv.Fetch()
                $sz = $sr.DataSize(1)
                $fs = [System.IO.File]::Create($cabOut)
                try {
                    $rem = $sz
                    while ($rem -gt 0) {
                        $chunk = [Math]::Min($rem, 65536)
                        $str = $sr.ReadStream(1, $chunk, 1)  # msiReadStreamBytes (raw 0x00..0xFF per char)
                        $bytes = [System.Text.Encoding]::GetEncoding(28591).GetBytes($str)
                        $fs.Write($bytes, 0, $bytes.Length)
                        $rem -= $bytes.Length
                    }
                } finally { $fs.Close() }
                $null = $sv.Close()
                $null = & expand.exe $cabOut -F:* $tmpCabDir 2>&1
                foreach ($pair in @(@("vordr_x64.exe", 0x8664), @("vordr_arm64.exe", 0xAA64))) {
                    $ep = Join-Path $tmpCabDir $pair[0]
                    if (-not (Test-Path $ep)) { Bad "cab is missing $($pair[0])" }
                    else {
                        $b = [System.IO.File]::ReadAllBytes($ep)
                        $pe = [BitConverter]::ToInt32($b, 0x3C)
                        $mach = [BitConverter]::ToUInt16($b, $pe + 4)
                        if ($mach -ne $pair[1]) {
                            Bad ("cab member {0} has PE Machine 0x{1:X4}, expected 0x{2:X4}" -f $pair[0], $mach, $pair[1])
                        }
                    }
                }
            } finally {
                Remove-Item $tmpCabDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
if ($fail -eq $before) { Write-Host ("payload         : {0} file(s) (0x8664 + 0xAA64), KeyPaths resolve, versions match {1}, cab embedded - ok" -f $files.Count, $pvNow) }

# --- 3. the upgrade rows + downgrade block ----------------------------------
# Attributes is a bitfield whose Inclusive bits are 0x100/0x200, not 0x1/0x2.
# Two Upgrade rows are required:
#   1. OLDERVERSIONBEINGUPGRADED: 0.0.0 .. $pv inclusive (0x300) for replacement.
#   2. NEWERVERSIONDETECTED: > $pv exclusive (0x002 = OnlyDetect, NO 0x100) + a
#      LaunchCondition `NOT NEWERVERSIONDETECTED` sequenced AFTER FindRelatedProducts
#      so an older MSI cannot downgrade a newer installed version.
Write-Host ""
$upg   = Rows "SELECT ``VersionMin``,``VersionMax``,``Attributes``,``ActionProperty`` FROM ``Upgrade``" 4
$lcRows= Rows "SELECT ``Condition``,``Description`` FROM ``LaunchCondition``" 2
$pvRow = Rows "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='ProductVersion'" 1
$pv    = $pvRow[0][0]
$seqRows = Rows "SELECT ``Action``,``Sequence`` FROM ``InstallExecuteSequence``" 2
$names   = @($seqRows | ForEach-Object { $_[0] })
$seqMap  = @{}; foreach ($sr in $seqRows) { $seqMap[$sr[0]] = [int]$sr[1] }

$upgOld   = @($upg | Where-Object { $_[3] -eq "OLDERVERSIONBEINGUPGRADED" })
$upgNew   = @($upg | Where-Object { $_[3] -eq "NEWERVERSIONDETECTED" })
$upgOther = @($upg | Where-Object { $_[3] -ne "OLDERVERSIONBEINGUPGRADED" -and $_[3] -ne "NEWERVERSIONDETECTED" })
foreach ($uo in $upgOther) { Bad "unexpected Upgrade row targeting $($uo[3])" }

if ($upgOld.Count -ne 1) { Bad "expected 1 OLDERVERSIONBEINGUPGRADED Upgrade row, found $($upgOld.Count)" }
else {
    $u = $upgOld[0]; $attr = [int]$u[2]
    Write-Host ("upgrade         : {0} .. {1}  attr=0x{2:X}  -> {3}" -f $u[0], $u[1], $attr, $u[3])
    if (-not ($attr -band 512)) { Bad "VersionMaxInclusive (0x200) is not set - a rebuild of $pv would install ALONGSIDE the existing one" }
    if ($u[1] -ne $pv)          { Bad "VersionMax is $($u[1]) but ProductVersion is $pv - the range does not reach this build" }
    if ($attr -band 2)          { Bad "OnlyDetect (0x2) is set on OLDERVERSIONBEINGUPGRADED - related products are found and then left installed" }
    if (($attr -band 1) -and ($names -notcontains "MigrateFeatureStates")) {
        Bad "MigrateFeatures (0x1) is set but MigrateFeatureStates is not sequenced"
    }
}

if ($upgNew.Count -ne 1) { Bad "expected 1 NEWERVERSIONDETECTED Upgrade row (downgrade block), found $($upgNew.Count)" }
else {
    $u = $upgNew[0]; $attr = [int]$u[2]
    Write-Host ("downgrade guard : > {0}       attr=0x{1:X}  -> {2}" -f $u[0], $attr, $u[3])
    if ($u[0] -ne $pv)          { Bad "NEWERVERSIONDETECTED VersionMin is $($u[0]), expected $pv" }
    if (-not [string]::IsNullOrEmpty($u[1])) { Bad "NEWERVERSIONDETECTED VersionMax is '$($u[1])', expected unbounded" }
    if (-not ($attr -band 2))   { Bad "NEWERVERSIONDETECTED lacks OnlyDetect (0x2) - a downgrade attempt would remove the newer version!" }
    if ($attr -band 256)        { Bad "NEWERVERSIONDETECTED sets VersionMinInclusive (0x100) - same-version rebuilds of $pv would block themselves as a downgrade" }
}
if ($secure -notcontains "NEWERVERSIONDETECTED") {
    Bad "NEWERVERSIONDETECTED is missing from SecureCustomProperties"
}
$lcConds = @($lcRows | ForEach-Object { $_[0] })
if ($lcConds -notcontains "NOT NEWERVERSIONDETECTED") {
    Bad "LaunchCondition lacks 'NOT NEWERVERSIONDETECTED' - NEWERVERSIONDETECTED is detected and then ignored"
}
if ($lcRows.Count -lt 17) {
    Bad "LaunchCondition has $($lcRows.Count) row(s); expected NOT NEWERVERSIONDETECTED + 16 numeric-property guards"
}
if (($seqMap.ContainsKey("FindRelatedProducts")) -and ($seqMap.ContainsKey("LaunchConditions"))) {
    if ($seqMap["FindRelatedProducts"] -ge $seqMap["LaunchConditions"]) {
        Bad "InstallExecuteSequence runs LaunchConditions ($($seqMap['LaunchConditions'])) before FindRelatedProducts ($($seqMap['FindRelatedProducts'])) - NEWERVERSIONDETECTED is not set yet when checked"
    }
} else {
    Bad "InstallExecuteSequence must contain both FindRelatedProducts and LaunchConditions"
}
if (-not $seqMap.ContainsKey("RemoveExistingProducts")) {
    Bad "RemoveExistingProducts is not sequenced - detection would happen and nothing would be removed"
} else {
    $before  = $seqMap.GetEnumerator() | Where-Object { $_.Value -lt $seqMap["RemoveExistingProducts"] } |
               Sort-Object Value | Select-Object -Last 1
    $anchors = @("InstallValidate","InstallInitialize","InstallExecute","InstallExecuteAgain","InstallFinalize")
    if ((-not $before) -or ($anchors -notcontains $before.Key)) {
        Bad "RemoveExistingProducts does not immediately follow a legal anchor ($($anchors -join ', ')) - install fails with error 2613"
    }
    if ($seqMap.ContainsKey("InstallFiles") -and ($seqMap["RemoveExistingProducts"] -ge $seqMap["InstallFiles"])) {
        Bad "RemoveExistingProducts ($($seqMap['RemoveExistingProducts'])) runs after InstallFiles ($($seqMap['InstallFiles'])) - same-version upgrades skip overwriting vordr.exe"
    }
}

# Property-establishing actions run in the CLIENT process.  When the client's
# sequence completes, the installer marks them done; a server-side pass then logs
# "Skipping <action>: already done on client side" and returns 0.  So an action
# present only in InstallExecuteSequence never runs AT ALL on a UI install - the
# install succeeds, the property is empty, and whatever depended on it silently
# does nothing.  That is exactly how RemoveExistingProducts came to run against
# an empty OLDERVERSIONBEINGUPGRADED and report success.
$uiRows   = Rows "SELECT ``Action``,``Sequence`` FROM ``InstallUISequence``" 2
$uiNames  = @($uiRows | ForEach-Object { $_[0] })
$uiMap    = @{}; foreach ($ur in $uiRows) { $uiMap[$ur[0]] = [int]$ur[1] }
if (-not $seqMap.ContainsKey("AppSearch") -or -not $uiMap.ContainsKey("AppSearch")) {
    Bad "AppSearch must be sequenced in both InstallExecuteSequence and InstallUISequence for HOST_NATIVE_ARCH detection"
} else {
    if ($seqMap["AppSearch"] -ge $seqMap["CostInitialize"]) {
        Bad "InstallExecuteSequence runs AppSearch ($($seqMap['AppSearch'])) after CostInitialize ($($seqMap['CostInitialize']))"
    }
    if ($uiMap["AppSearch"] -ge $uiMap["CostInitialize"]) {
        Bad "InstallUISequence runs AppSearch ($($uiMap['AppSearch'])) after CostInitialize ($($uiMap['CostInitialize']))"
    }
}
foreach ($a in @("FindRelatedProducts","AppSearch","LaunchConditions","CCPSearch","RMCCPSearch")) {
    if (($names -contains $a) -and ($uiNames -notcontains $a)) {
        Bad "$a is in InstallExecuteSequence but not InstallUISequence - the server skips it as 'already done on client side', so it never runs on a UI install"
    }
}
if (($uiMap.ContainsKey("FindRelatedProducts")) -and ($uiMap.ContainsKey("LaunchConditions"))) {
    if ($uiMap["FindRelatedProducts"] -ge $uiMap["LaunchConditions"]) {
        Bad "InstallUISequence runs LaunchConditions ($($uiMap['LaunchConditions'])) before FindRelatedProducts ($($uiMap['FindRelatedProducts']))"
    }
}

# What this package would actually displace and select on THIS machine.
$probe = $installer.OpenPackage($Msi, 1)
$appRc = $probe.DoAction("AppSearch")
$hostArch = $probe.Property("HOST_NATIVE_ARCH")
$frpRc = $probe.DoAction("FindRelatedProducts")
$found = $probe.Property("OLDERVERSIONBEINGUPGRADED")
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($probe)
if ($appRc -ne 1) { Bad "AppSearch failed on this machine (return value $appRc - check Signature/RegLocator tables)" }
elseif ([string]::IsNullOrEmpty($hostArch)) { Bad "AppSearch did not populate HOST_NATIVE_ARCH on this machine" }
else { Write-Host ("  host arch     : {0} (live AppSearch -> {1})" -f $hostArch, $(if ($hostArch -ieq "ARM64") { "VordrExeArm64" } else { "VordrExe" })) }
if ($frpRc -ne 1) { Bad "FindRelatedProducts failed on this machine (return value $frpRc)" }
if ($found) { Write-Host ("  would replace : {0}" -f $found) }
else        { Write-Host  "  would replace : nothing currently installed matches" }

# --- 4. MsiLockPermissionsEx SDDL ACLs + CreateFolder sequencing ------------
Write-Host ""
$before = $fail
Write-Host "permissions     : checking MsiLockPermissionsEx & CreateFolder"
$cfRows = Rows "SELECT ``Directory_``,``Component_`` FROM ``CreateFolder``" 2
$cfPairs = @($cfRows | ForEach-Object { "$($_[0])/$($_[1])" })
foreach ($reqCf in @("INSTALLDIR/VordrExe", "INSTALLDIR/VordrExeArm64")) {
    if ($cfPairs -notcontains $reqCf) { Bad "CreateFolder missing required row $reqCf" }
}
if (-not $seqMap.ContainsKey("CreateFolders") -or -not $seqMap.ContainsKey("RemoveFolders")) {
    Bad "InstallExecuteSequence must contain CreateFolders and RemoveFolders for MsiLockPermissionsEx"
} elseif ($seqMap["CreateFolders"] -ge $seqMap["InstallFiles"] -or $seqMap["RemoveFolders"] -le $seqMap["RemoveFiles"]) {
    Bad "CreateFolders/RemoveFolders out of order relative to RemoveFiles/InstallFiles"
}
# A4-01: verify all 5 Windows Installer 5.0 MsiLockPermissionsEx columns AND execute
# msi.dll's exact runtime filtered query (catches MSI Error 2235 schema drift).
$lpRows = Rows "SELECT ``MsiLockPermissionsEx``,``LockObject``,``Table``,``SDDLText``,``Condition`` FROM ``MsiLockPermissionsEx``" 5
$lpMap = @{}; foreach ($lr in $lpRows) { $lpMap["$($lr[2]):$($lr[1])"] = $lr[3] }
foreach ($reqLp in @("CreateFolder:INSTALLDIR", "File:vordr_x64.exe", "File:vordr_arm64.exe")) {
    if (-not $lpMap.ContainsKey($reqLp)) { Bad "MsiLockPermissionsEx missing row for $reqLp"; continue }
    $parts = $reqLp -split ":", 2
    $qRows = Rows ("SELECT ``LockObject``,``Table``,``SDDLText``,``Condition`` FROM ``MsiLockPermissionsEx`` WHERE ``Table``='{0}' AND ``LockObject``='{1}' ORDER BY ``Condition``" -f $parts[0], $parts[1]) 4
    if ($qRows.Count -ne 1) { Bad "msi.dll runtime query for $reqLp returned $($qRows.Count) row(s), expected 1" }
    elseif (-not [string]::IsNullOrEmpty($qRows[0][3])) { Bad "MsiLockPermissionsEx $reqLp has unexpected Condition '$($qRows[0][3])'" }
    $sddl = $lpMap[$reqLp]
    if (-not $sddl.StartsWith("D:P")) { Bad "MsiLockPermissionsEx $reqLp SDDL '$sddl' is not protected (missing D:P)" }
    if ($sddl -notmatch 'FA;;;SY\)' -or $sddl -notmatch 'FA;;;BA\)' -or $sddl -notmatch '0x1200a9;;;BU\)') {
        Bad "MsiLockPermissionsEx $reqLp SDDL '$sddl' lacks expected SY:FA / BA:FA / BU:0x1200a9 ACEs"
    }
    try {
        if ($reqLp.StartsWith("CreateFolder:")) {
            $sd = New-Object System.Security.AccessControl.DirectorySecurity
            $sd.SetSecurityDescriptorSddlForm($sddl)
        } else {
            $sd = New-Object System.Security.AccessControl.FileSecurity
            $sd.SetSecurityDescriptorSddlForm($sddl)
        }
    } catch {
        Bad "MsiLockPermissionsEx $reqLp SDDL '$sddl' failed .NET SDDL parse: $($_.Exception.Message)"
    }
}
if ($fail -eq $before) { Write-Host ("  MsiLockPermissionsEx: {0} protected SDDL rule(s) + 5-col msi.dll SQL validated - ok" -f $lpRows.Count) }

# --- 5. live LaunchConditions numeric/case-insensitive guard evaluation -----
Write-Host ""
$before = $fail
Write-Host "launch guards   : live LaunchConditions evaluation"
foreach ($lcr in $lcRows) {
    if ($lcr[0].Length -gt 255) { Bad "LaunchCondition exceeds standard S255 (ICE03): length $($lcr[0].Length)" }
}
function Test-Launch([hashtable]$props) {
    $s = $installer.OpenPackage($Msi, 1)
    foreach ($k in $props.Keys) { $s.Property($k) = $props[$k] }
    $rc = $s.DoAction("LaunchConditions")
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($s)
    $rc
}
$validCases = @(
    @{},
    @{ "VORDR_PWMINLEN" = "1" },
    @{ "VORDR_PWMINLEN" = "16" },
    @{ "VORDR_PWMINLEN" = "256" },
    @{ "VORDR_UISCHEME" = "0" },
    @{ "VORDR_UISCHEME" = "14" },
    @{ "VORDR_CLIPSECONDS" = "0" },
    @{ "VORDR_CLIPSECONDS" = "3600" },
    @{ "VORDR_IDLELOCKMIN" = "0" },
    @{ "VORDR_IDLELOCKMIN" = "1440" },
    @{ "VORDR_PWVERIFYDAYS" = "0" },
    @{ "VORDR_PWVERIFYDAYS" = "3650" }
)
foreach ($vc in $validCases) {
    $rc = Test-Launch $vc
    if ($rc -ne 1) {
        $desc = ($vc.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " "
        Bad "LaunchConditions rejected valid property set '$desc' (rc=$rc)"
    }
}
$badCases = @(
    @{ "VORDR_PWMINLEN" = "X01" },
    @{ "VORDR_PWMINLEN" = "x01" },
    @{ "VORDR_PWMINLEN" = "ABC" },
    @{ "VORDR_PWMINLEN" = "12.5" },
    @{ "VORDR_PWMINLEN" = "0" },
    @{ "VORDR_PWMINLEN" = "257" },
    @{ "VORDR_PWMINLEN" = "-1" },
    @{ "VORDR_PWMINLEN" = "%TEMP%" },
    @{ "VORDR_UISCHEME" = "15" },
    @{ "VORDR_UISCHEME" = "X01" },
    @{ "VORDR_UISCHEME" = "-0" },
    @{ "VORDR_PWMINLEN" = '1"6' },
    @{ "VORDR_PWMINLEN" = "2147483648" },
    @{ "VORDR_PWMINLEN" = [string][char]0xFF11 + [string][char]0xFF16 },
    @{ "VORDR_CLIPSECONDS" = "3601" },
    @{ "VORDR_CLIPSECONDS" = "12 34" }
)
foreach ($bc in $badCases) {
    $rc = Test-Launch $bc
    if ($rc -eq 1) {
        $desc = ($bc.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " "
        Bad "LaunchConditions ACCEPTED invalid property set '$desc' (expected rejection)"
    }
}
if ($fail -eq $before) {
    Write-Host ("  LaunchConditions: {0} valid passed, {1} invalid/coercion cases rejected - ok" -f $validCases.Count, $badCases.Count)
}

[void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)

Write-Host ""
if ($fail) { Write-Host "MSI VERIFY: $fail failure(s)"; exit 1 }
Write-Host "MSI VERIFY: OK"
exit 0
