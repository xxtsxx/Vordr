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
                       -Msi bin\vordr-0.2.2.msi
    Exit code 0 = all checks passed.
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Msi)

$ErrorActionPreference = "Stop"

# OpenPackage needs a rooted path - given a relative one it fails with the
# generic "OpenPackage,PackagePath,Options" COM error, while OpenDatabase
# accepts it, so the failure looks like a corrupt package rather than a path.
$Msi = (Resolve-Path $Msi).Path
$installer = New-Object -ComObject WindowsInstaller.Installer
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
    if ($off["VordrExe"] -ne $LOCAL)  { Bad "VORDR_NOASSOC=1 also suppresses the exe" }
    if ($fail -eq $before) { Write-Host "  VORDR_NOASSOC=1 drops the association and nothing else - ok" }
}

# --- 3. the upgrade row -----------------------------------------------------
# Attributes is a bitfield whose Inclusive bits are 0x100/0x200, not 0x1/0x2.
# With VersionMax exclusive every OLDER version is still replaced, so the mistake
# hides until someone installs a rebuild of the SAME version - and then quietly
# registers a second product with the same files.
Write-Host ""
$upg   = Rows "SELECT ``VersionMin``,``VersionMax``,``Attributes``,``ActionProperty`` FROM ``Upgrade``" 4
$pvRow = Rows "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='ProductVersion'" 1
$pv    = $pvRow[0][0]
# Assign first, THEN pipe.  Rows returns ,$out to stop the array unrolling; that
# wrapper is removed by assignment but NOT by piping, so "Rows ... | ForEach"
# hands the loop the whole table as one object and quietly yields a single row.
$seqRows = Rows "SELECT ``Action`` FROM ``InstallExecuteSequence``" 1
$names   = @($seqRows | ForEach-Object { $_[0] })
if (-not $upg.Count) { Bad "no Upgrade row - every install would sit beside the last one" }
foreach ($u in $upg) {
    $attr = [int]$u[2]
    Write-Host ("upgrade         : {0} .. {1}  attr=0x{2:X}  -> {3}" -f $u[0], $u[1], $attr, $u[3])
    if (-not ($attr -band 512)) { Bad "VersionMaxInclusive (0x200) is not set - a rebuild of $pv would install ALONGSIDE the existing one" }
    if ($u[1] -ne $pv)          { Bad "VersionMax is $($u[1]) but ProductVersion is $pv - the range does not reach this build" }
    if ($attr -band 2)          { Bad "OnlyDetect (0x2) is set - related products are found and then left installed" }
    if (($attr -band 1) -and ($names -notcontains "MigrateFeatureStates")) {
        Bad "MigrateFeatures (0x1) is set but MigrateFeatureStates is not sequenced"
    }
}
if ($names -notcontains "RemoveExistingProducts") { Bad "RemoveExistingProducts is not sequenced - detection would happen and nothing would be removed" }

# What this package would actually displace on THIS machine.  Informational -
# it depends on machine state, not on the package - but it is the check that
# would have caught the bug above the moment it was tested twice.
$probe = $installer.OpenPackage($Msi, 1)
$null  = $probe.DoAction("FindRelatedProducts")
$found = $probe.Property("OLDERVERSIONBEINGUPGRADED")
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($probe)
if ($found) { Write-Host ("  would replace : {0}" -f $found) }
else        { Write-Host  "  would replace : nothing currently installed matches" }

[void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)

Write-Host ""
if ($fail) { Write-Host "MSI VERIFY: $fail failure(s)"; exit 1 }
Write-Host "MSI VERIFY: OK"
exit 0
