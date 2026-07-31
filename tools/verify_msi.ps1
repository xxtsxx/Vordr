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

Write-Host ("registry values : {0}" -f $reg.Count)
foreach ($r in $reg) {
    $rk, $root, $key, $name, $value, $cname = $r
    $c = $byName[$cname]
    if (-not $c) { Bad "$rk names component $cname, which does not exist"; continue }
    Write-Host ("  HKLM\{0}\{1} = {2}   [{3}]" -f $key, $name, $value, $cname)

    if ([int]$root -ne 2)                  { Bad "$rk writes to root $root, not HKLM (2)" }
    # 256 = write to the 64-bit view.  Without it, an x64 package silently
    # redirects into WOW6432Node, where the 64-bit vordr.exe never looks: the
    # install succeeds and the policy simply has no effect.
    if (-not ([int]$c[2] -band 256))       { Bad "$cname is not marked 64-bit; the value would land in WOW6432Node" }
    if (-not ([int]$c[2] -band 4))         { Bad "$cname does not use its registry row as the key path" }
    if ([string]::IsNullOrEmpty($c[3]))    { Bad "$cname has no condition - it would be written unconditionally" }
    if (-not $inFeature[$cname])           { Bad "$cname is in no feature, so it is never installed" }
    if ($value -notmatch '^#\[[A-Z0-9_]+\]$') { Bad "$rk value '$value' is not '#[PROPERTY]' - it would not be a REG_DWORD driven by a property" }
    if ($c[3] -cne $c[3].ToUpper())        { Bad "$cname's condition '$($c[3])' is not a public (uppercase) property" }
    if ($secure -notcontains $c[3])        { Bad "$($c[3]) is missing from SecureCustomProperties - dropped before the elevated half of the install" }
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
$none = Cost @{}
Write-Host ""
Write-Host "costing with no properties set:"
foreach ($r in $reg) {
    if ($none[$r[5]] -eq $LOCAL) { Bad "$($r[5]) installs with no property set - $($r[3]) would be written, and its presence LOCKS the setting against the user" }
}
if (-not $fail) { Write-Host "  no policy value is written unless asked for - ok" }

Write-Host ""
Write-Host "costing each property individually:"
foreach ($r in $reg) {
    $prop = $byName[$r[5]][3]
    $one  = Cost @{ $prop = "1" }
    if ($one[$r[5]] -ne $LOCAL) { Bad "$prop=1 does not install $($r[5]) - the property would be accepted and do nothing" }
    foreach ($other in $reg) {
        if ($other[5] -ne $r[5] -and $one[$other[5]] -eq $LOCAL) {
            Bad "$prop=1 also writes $($other[3]) - properties are not independent"
        }
    }
}
if (-not $fail) { Write-Host ("  each of the {0} properties writes exactly its own value - ok" -f $reg.Count) }

[void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)

Write-Host ""
if ($fail) { Write-Host "MSI VERIFY: $fail failure(s)"; exit 1 }
Write-Host "MSI VERIFY: OK"
exit 0
