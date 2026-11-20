# Prove the release build reproduces: build it twice, from scratch, and compare.
#
# docs/RELEASES.md publishes the release executable's SHA-256 and tells users to
# rebuild the tag and compare.  That only works if two builds of one commit are
# byte-identical, and they were not: ml64 stamps every .obj it writes, build.cmd
# reassembles everything on every run, so /Brepro hashed different inputs each
# time.  build.cmd release now runs tools\pe_normalise.py before hashing; this
# script is the proof, and the only place the comparison is actually performed.
# (Ported from Myrkr, where the same defect was found and measured.)
#
# Why it builds TWICE rather than relinking: the variation was in the objects, so
# relinking the same objects reproduces perfectly while a real rebuild does not.
#
# Not part of build.cmd on purpose - it takes two release builds, and the
# property matters when something is about to be published (RELEASE_CHECKLIST §2).
param([switch]$AllowNoDumpbin, [switch]$SkipArm64)
$root = Split-Path -Parent $PSScriptRoot
$fail = 0
Push-Location $root

function ExeHash([string]$p = "bin\vordr.exe") { (Get-FileHash $p -Algorithm SHA256).Hash }

# Both builds start from nothing: a dbg or probeio run leaves its own objects in
# obj\, and comparing a build that inherited them against a clean one reports the
# difference as a reproducibility failure - a harness bug that looks exactly like
# the defect under test.
Remove-Item "obj\*.obj","obj\.lint_cache" -Force -EA SilentlyContinue
"verify_repro: building x64 release (1 of 2), from clean objects..."
$o1 = cmd /c "$root\build.cmd release strict" 2>&1
if (($o1 -join "`n") -notmatch "BUILD OK") { "FAIL first x64 build"; $o1 | Select-Object -Last 15; Pop-Location; exit 1 }
$h1 = ExeHash "bin\vordr.exe"
"  vordr.exe $h1"

Remove-Item "obj\*.obj" -Force -EA SilentlyContinue
"verify_repro: building x64 release (2 of 2), from clean objects..."
$o2 = cmd /c "$root\build.cmd release strict" 2>&1
if (($o2 -join "`n") -notmatch "BUILD OK") { "FAIL second x64 build"; $o2 | Select-Object -Last 15; Pop-Location; exit 1 }
$h2 = ExeHash "bin\vordr.exe"
"  vordr.exe $h2"
""
if ($h1 -eq $h2) { "  ok   vordr.exe reproduces" } else { "  FAIL vordr.exe differs between builds"; $fail++ }

# Normalisation must not cost a mitigation: CET compatibility is advertised by a
# debug-directory record whose payload IS the flags, and the first version of
# Myrkr's normaliser cleared it.  Assert every flag survives.
$h = & dumpbin /headers "bin\vordr.exe" 2>$null
if (-not $h) {
  if ($AllowNoDumpbin) { "  (dumpbin unavailable - mitigation check skipped by -AllowNoDumpbin)" }
  else { "  FAIL dumpbin is not on PATH, so the mitigations were not checked (-AllowNoDumpbin to accept)"; $fail++ }
}
else {
  foreach ($flag in @("Dynamic base", "NX compatible", "High Entropy", "CET compatible")) {
    if (($h -join "`n") -notmatch [regex]::Escape($flag)) { "  FAIL vordr.exe lost '$flag'"; $fail++ }
  }
  if ($fail -eq 0) { "  ok   x64 mitigations survive normalisation (ASLR, DEP, HEVA, CET)" }
}

if (-not $SkipArm64) {
  ""
  Remove-Item "obj\arm64" -Recurse -Force -EA SilentlyContinue
  "verify_repro: building ARM64 release (1 of 2), from clean objects..."
  $a1 = cmd /c "$root\build_arm64.cmd release clean" 2>&1
  if (($a1 -join "`n") -notmatch "BUILD OK") { "FAIL first arm64 build"; $a1 | Select-Object -Last 15; Pop-Location; exit 1 }
  $ah1 = ExeHash "bin\vordr-arm64.exe"
  "  vordr-arm64.exe $ah1"

  Remove-Item "obj\arm64" -Recurse -Force -EA SilentlyContinue
  "verify_repro: building ARM64 release (2 of 2), from clean objects..."
  $a2 = cmd /c "$root\build_arm64.cmd release clean" 2>&1
  if (($a2 -join "`n") -notmatch "BUILD OK") { "FAIL second arm64 build"; $a2 | Select-Object -Last 15; Pop-Location; exit 1 }
  $ah2 = ExeHash "bin\vordr-arm64.exe"
  "  vordr-arm64.exe $ah2"
  ""
  if ($ah1 -eq $ah2) { "  ok   vordr-arm64.exe reproduces" } else { "  FAIL vordr-arm64.exe differs between builds"; $fail++ }

  if ($h) {
    $ha = & dumpbin /headers "bin\vordr-arm64.exe" 2>$null
    foreach ($flag in @("ARM64", "Dynamic base", "NX compatible", "High Entropy")) {
      if (($ha -join "`n") -notmatch [regex]::Escape($flag)) { "  FAIL vordr-arm64.exe lost '$flag'"; $fail++ }
    }
    if ($fail -eq 0) { "  ok   ARM64 mitigations survive normalisation (ARM64, ASLR, DEP, HEVA)" }
  }
}

# ...and the recorded hashes have to match what was actually built.
$sums = Get-Content "bin\SHA256SUMS.txt" -EA SilentlyContinue
if (-not $sums) { "  FAIL bin\SHA256SUMS.txt was not written"; $fail++ }
else {
  if (($sums -join ' ') -notmatch $h2) { "  FAIL SHA256SUMS.txt does not match vordr.exe"; $fail++ }
  if ((-not $SkipArm64) -and (($sums -join ' ') -notmatch $ah2)) { "  FAIL SHA256SUMS.txt does not match vordr-arm64.exe"; $fail++ }
  if ($fail -eq 0) { "  ok   SHA256SUMS.txt matches what was built" }
}

""
if ($fail -eq 0) { "ALL PASS" } else { "$fail FAILURE(S)" }
Pop-Location
exit $(if ($fail -eq 0) { 0 } else { 1 })
