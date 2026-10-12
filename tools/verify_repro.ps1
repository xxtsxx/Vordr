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
param([switch]$AllowNoDumpbin)
$root = Split-Path -Parent $PSScriptRoot
$fail = 0
Push-Location $root

function ExeHash { (Get-FileHash "bin\vordr.exe" -Algorithm SHA256).Hash }

# Both builds start from nothing: a dbg or probeio run leaves its own objects in
# obj\, and comparing a build that inherited them against a clean one reports the
# difference as a reproducibility failure - a harness bug that looks exactly like
# the defect under test.
Remove-Item "obj\*.obj" -Force -EA SilentlyContinue
"verify_repro: building release (1 of 2), from clean objects..."
$o1 = cmd /c "$root\build.cmd release strict" 2>&1
if (($o1 -join "`n") -notmatch "BUILD OK") { "FAIL first build"; $o1 | Select-Object -Last 15; Pop-Location; exit 1 }
$h1 = ExeHash
"  vordr.exe $h1"

Remove-Item "obj\*.obj" -Force -EA SilentlyContinue
"verify_repro: building release (2 of 2), from clean objects..."
$o2 = cmd /c "$root\build.cmd release strict" 2>&1
if (($o2 -join "`n") -notmatch "BUILD OK") { "FAIL second build"; $o2 | Select-Object -Last 15; Pop-Location; exit 1 }
$h2 = ExeHash
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
  if ($fail -eq 0) { "  ok   mitigations survive normalisation (ASLR, DEP, HEVA, CET)" }
}

# ...and the recorded hash has to be the one actually built.
$sums = Get-Content "bin\SHA256SUMS.txt" -EA SilentlyContinue
if (-not $sums) { "  FAIL bin\SHA256SUMS.txt was not written"; $fail++ }
elseif (($sums -join ' ') -notmatch $h2) { "  FAIL SHA256SUMS.txt does not match the binary beside it"; $fail++ }
else { "  ok   SHA256SUMS.txt matches what was built" }

""
if ($fail -eq 0) { "ALL PASS" } else { "$fail FAILURE(S)" }
Pop-Location
exit $(if ($fail -eq 0) { 0 } else { 1 })
