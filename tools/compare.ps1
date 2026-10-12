# compare.ps1 - does a test actually catch the change?  Runs ONE test, as it is in
# the working tree now, against a build of an older commit and against a build of
# the working tree, and says whether the verdicts differ.
#
#   powershell -File tools\compare.ps1 tests\redteam.py -Ref HEAD -Variant "dbg strict"
#   powershell -File tools\compare.ps1 tests\verify_vault.py -Ref <commit>
# (A test that needs something the old commit lacks - guitest needs the GUI test
#  hooks - cannot run there; the verdict says "inconclusive", not "catches".)
#
# A regression test that passes against the code it was written to catch is not a
# test; this is the check.  (Ported from Myrkr, where it caught a tamper offset that
# hit an index instead of an entry, so the "damaged entry" cases passed against the
# broken build.)  The in-binary probes travel WITH the code they test, so for those
# use a sabotage build instead; this is for the tests that live outside the binary:
# tests\*.py and tests\*.ps1.
#
#   -Ref      the old commit (default HEAD - "does my uncommitted change make a
#             difference to this test").
#   -Variant  build arguments for BOTH sides (default "probeio strict": what the
#             path-taking probes and the GUI harness need).
#   -TestArgs extra arguments.  A .py test gets the exe path first, then these; a
#             .ps1 test gets -Exe <path>, then these.
#
# The current tests\ directory is copied over the old checkout, so a new test and
# its fixtures run unchanged against the old code.  bin\ is rebuilt as a release
# build on every exit.  Exit 0 only when the old build FAILS the test and the
# working tree PASSES it.
param(
    [Parameter(Mandatory, Position = 0)][string]$Test,
    [string]$Ref = 'HEAD',
    [string]$Variant = 'probeio strict',
    [string[]]$TestArgs = @(),
    [switch]$KeepWorktree
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'tests\lib\gui.psm1') -Force

$testFull = (Resolve-Path -LiteralPath (Join-Path $root $Test) -ErrorAction SilentlyContinue)
if (-not $testFull) { $testFull = Resolve-Path -LiteralPath $Test }
$testRel = $testFull.Path.Substring($root.Length).TrimStart('\')
if (-not $testRel.StartsWith('tests\')) { throw "the test must live under tests\: $testRel" }

$sha = (git -C $root rev-parse --short $Ref).Trim()
if ($LASTEXITCODE) { throw "unknown ref: $Ref" }
$wt   = Join-Path ([IO.Path]::GetTempPath()) ('vordr-cmp-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$logs = "$wt-logs"      # outside the worktree, so they survive its removal
New-Item -ItemType Directory $logs | Out-Null

# git writes progress to stderr, and Windows PowerShell 5.1 turns a redirected
# native stderr line into a terminating error under ErrorAction Stop.
function Git-Quiet {
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & git -C $root @args 2>&1 | Out-Null } finally { $ErrorActionPreference = $eap }
}

function Run-Test([string]$tree, [string]$log) {
    $file = Join-Path $tree $testRel
    $exe  = Join-Path $tree 'bin\vordr.exe'
    Push-Location $tree
    # The test is EXPECTED to fail on the old side, and a failing child writes to
    # stderr - which, redirected under ErrorAction Stop, Windows PowerShell 5.1 turns
    # into a terminating error that kills this script before it gives a verdict.
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        if ($file -like '*.py') { & python $file $exe @TestArgs *> $log }
        else { & powershell -NoProfile -ExecutionPolicy Bypass -File $file -Exe $exe @TestArgs *> $log }
        return $LASTEXITCODE
    } finally { $ErrorActionPreference = $eap; Pop-Location }
}

$old = $null; $new = $null
try {
    Write-Host "=== old: $Ref ($sha) in $wt ==="
    Git-Quiet worktree add --detach $wt $sha
    if ($LASTEXITCODE) { throw "git worktree add failed" }
    Copy-Item -Recurse -Force (Join-Path $root 'tests\*') (Join-Path $wt 'tests')
    Invoke-VordrBuild -Variant $Variant -Root $wt
    $old = Run-Test $wt (Join-Path $logs 'old.txt')
    Write-Host "    exit $old"

    Write-Host "=== new: working tree ==="
    Invoke-VordrBuild -Variant $Variant -Root $root
    $new = Run-Test $root (Join-Path $logs 'new.txt')
    Write-Host "    exit $new"
} finally {
    Write-Host "=== restore: release build in bin ==="
    try { Invoke-VordrBuild -Variant 'release strict' -Root $root; Write-Host '    ok' }
    catch { Write-Host "    FAIL: $($_.Exception.Message)" }
    if (-not $KeepWorktree) { Git-Quiet worktree remove --force $wt }
}

# The lines that differ, failures first - the reason for the verdict.
$pat = '\bFAIL|\bPASS\b|^\s*ok\b|error|Traceback'
foreach ($side in 'old', 'new') {
    $f = Join-Path $logs "$side.txt"
    $hits  = @(Select-String -LiteralPath $f -Pattern $pat | ForEach-Object { $_.Line.TrimEnd() })
    $fails = @($hits | Where-Object { $_ -cmatch '\bFAIL|Traceback|\berror:' })
    Write-Host ("`n--- {0}: {1} result lines, {2} failing ---" -f $side, $hits.Count, $fails.Count)
    $fails | Select-Object -First 25 | ForEach-Object { Write-Host "  $_" }
}
Write-Host "`nlogs: $logs"

Write-Host ''
# "Old failed" counts only if a CHECK failed there.  A test that could not run at
# all on the old build (no hook it needs, a harness refusal, a crash before the
# first check) also exits nonzero, and calling that a catch would be vacuous.
$oldChecks = @(Select-String -LiteralPath (Join-Path $logs 'old.txt') -Pattern '^\s*FAIL\s' -CaseSensitive)
if ($old -ne 0 -and $new -eq 0 -and -not $oldChecks.Count) {
    Write-Host "VERDICT: inconclusive - the old build failed before any check ran (see old.txt); the test cannot run there"; exit 1
}
if ($old -ne 0 -and $new -eq 0) { Write-Host "VERDICT: the test CATCHES the change (old $old, new 0)"; exit 0 }
if ($old -eq 0 -and $new -eq 0) { Write-Host "VERDICT: the test does NOT tell $sha from the working tree - both pass"; exit 1 }
if ($new -ne 0)                 { Write-Host "VERDICT: the working tree FAILS the test (old $old, new $new)"; exit 1 }
Write-Host "VERDICT: inconclusive (old $old, new $new)"; exit 1
