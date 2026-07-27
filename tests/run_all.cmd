@echo off
rem ===========================================================================
rem run_all.cmd - the consolidated Vordr test gate.
rem
rem Stages:
rem   redteam    build dbg, then run every fault-injection case; each must kill
rem              the process with a 0xFADExx fail-fast code (iat: raw AV).
rem              Skipped with --quick.
rem   build      release build via build.cmd strict (framecheck FATALs gate it)
rem   selftest   bin\vordr.exe selftest must print "all self-tests passed"
rem   roundtrip  builds a PROBE_IO binary (a plain release refuses the path-taking
rem              verbs), then runs the headless probes: seedtest -> atgen -> zitest
rem              -> phtest -> secscan -> secfreedup -> lktest -> tmptest -> fztest ->
rem              trtest -> vfuzz -> fuzzzip -> jfuzz -> bktest -> mactest -> rbtest ->
rem              xctest -> reload -> cowrite -> attfuzz -> zexcap -> healthkat ->
rem              pkat -> kdfparam -> vaultexportkat -> vaultexpattkat
rem
rem Usage: tests\run_all.cmd [--quick]
rem Exit:  0 = all stages passed, 1 = at least one FAIL (see the summary table).
rem Run from a VS x64 tools prompt (ml64/link on PATH), like build.cmd.
rem ===========================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0.."

set QUICK=0
if /i "%1"=="--quick" set QUICK=1

set R_REDTEAM=skip
set R_BUILD=FAIL
set R_SELFTEST=FAIL
set R_ROUNDTRIP=FAIL
set T_REDTEAM=-
set T_BUILD=-
set T_SELFTEST=-
set T_ROUNDTRIP=-

set WORK=%TEMP%\vordr_runall
if exist "%WORK%" rd /s /q "%WORK%"
mkdir "%WORK%"

taskkill /im vordr.exe /f >nul 2>nul

rem ---------------------------------------------------------------- redteam --
if "%QUICK%"=="1" goto :s_build
call :now T0
echo === stage: redteam (dbg build + fault injection) ===
call .\build.cmd dbg strict > "%WORK%\build_dbg.log" 2>&1
if errorlevel 1 (
    echo   dbg build FAILED - see %WORK%\build_dbg.log
    set R_REDTEAM=FAIL
    goto :s_build
)
set R_REDTEAM=PASS
for %%c in (canary shadow dlpv overflow bounds typemagic heaptag iat) do (
    bin\vordr.exe redteam %%c > "%WORK%\rt_%%c.log" 2>&1
    set /a RC=!errorlevel!
    set /a HI="(!RC! >> 16) & 0xFFFF"
    set OK=0
    if !HI! equ 64222 set OK=1
    rem iat corrupts the (locked) IAT -> the call faults with a raw AV, which the
    rem crash-containment VEH now catches, wipes secrets, and terminates with
    rem 0xC0000409 (-1073740791).  The control still fired; the fault is contained.
    if "%%c"=="iat" if !RC! equ -1073740791 set OK=1
    if !OK!==1 (
        echo   redteam %%c: fired ^(exit !RC!^) - ok
    ) else (
        echo   redteam %%c: control did NOT fire ^(exit !RC!^) - FAIL
        set R_REDTEAM=FAIL
    )
)
call :now T1
set /a T_REDTEAM=!T1!-!T0!

rem ------------------------------------------------------------------ build --
:s_build
call :now T0
echo === stage: build (release, strict framecheck) ===
call .\build.cmd strict > "%WORK%\build_rel.log" 2>&1
if errorlevel 1 (
    echo   release build FAILED - see %WORK%\build_rel.log
    goto :summary
)
set R_BUILD=PASS
call :now T1
set /a T_BUILD=!T1!-!T0!

rem --------------------------------------------------------------- selftest --
call :now T0
echo === stage: selftest ===
bin\vordr.exe selftest > "%WORK%\selftest.log" 2>&1
if errorlevel 1 (
    echo   selftest FAILED - see %WORK%\selftest.log
    goto :roundtrip_done
)
findstr /c:"all self-tests passed" "%WORK%\selftest.log" >nul || (
    echo   selftest output missing the pass banner - FAIL
    goto :roundtrip_done
)
set R_SELFTEST=PASS
call :now T1
set /a T_SELFTEST=!T1!-!T0!

rem -------------------------------------------------------------- roundtrip --
call :now T0
echo === stage: roundtrip (seedtest / atgen / zitest / phtest / secscan / secfreedup / tmptest / fztest / trtest / vfuzz / fuzzzip / jfuzz / bktest / mactest / rbtest / sysitemkat / vexselkat / c9kat / xctest / reload / attfuzz / zexcap / zexname / convcap / healthkat / pkat / kdfparam / vaultexportkat / vaultexpattkat) ===
set RT=PASS

rem --- data-loss guard: the RELEASE binary (still in bin\ from the build stage)
rem     must REFUSE any path-taking diagnostic and touch no file on disk ---------
del "%WORK%\guard.vault" >nul 2>nul
bin\vordr.exe seedtest "%WORK%\guard.vault" > "%WORK%\guard.log" 2>&1
if not errorlevel 1 ( echo   release-guard: FAIL ^(release accepted a path verb^) & set RT=FAIL )
if exist "%WORK%\guard.vault" ( echo   release-guard: FAIL ^(path verb created a file^) & set RT=FAIL )
if "!RT!"=="PASS" echo   release-guard: path-taking verbs refused in release - ok

rem --- the path-taking probes are diagnostics-only; build a PROBE_IO binary to
rem     exercise them (a plain release build refuses them, verified above) --------
call .\build.cmd probeio strict > "%WORK%\build_probeio.log" 2>&1
if errorlevel 1 ( echo   probeio build FAILED - see %WORK%\build_probeio.log & set RT=FAIL & goto :roundtrip_publish )

bin\vordr.exe seedtest "%WORK%\rt.vault" > "%WORK%\seedtest.log" 2>&1
if errorlevel 1 ( echo   seedtest: FAIL ^(exit !errorlevel!^) & set RT=FAIL )

bin\vordr.exe atgen "%WORK%\rt.zip" > "%WORK%\atgen.log" 2>&1
if errorlevel 1 ( echo   atgen: FAIL ^(exit !errorlevel!^) & set RT=FAIL )

if "!RT!"=="PASS" (
    bin\vordr.exe zitest "%WORK%\rt.vault" "%WORK%\rt.zip" > "%WORK%\zitest.log" 2>&1
    set /a ZN=!errorlevel!
    if !ZN! geq 1 if !ZN! lss 57344 (
        echo   zitest: imported !ZN! entries - ok
    ) else (
        echo   zitest: FAIL ^(exit !ZN!^)
        set RT=FAIL
    )
)

bin\vordr.exe phtest > "%WORK%\phtest.log" 2>&1
if not "!errorlevel!"=="1" ( echo   phtest: FAIL ^(exit !errorlevel!, expected 1^) & set RT=FAIL )

bin\vordr.exe secscan > "%WORK%\secscan.log" 2>&1
if not "!errorlevel!"=="0" ( echo   secscan: FAIL ^(exit !errorlevel!, secret residue after wipe^) & set RT=FAIL )

bin\vordr.exe secfreedup > "%WORK%\secfreedup.log" 2>&1
if not "!errorlevel!"=="0" ( echo   secfreedup: FAIL ^(exit !errorlevel!, secmem_free not double-free-safe^) & set RT=FAIL )

bin\vordr.exe lktest > "%WORK%\lktest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   lktest: FAIL ^(exit !errorlevel!, VirtualLock failure detection^) & set RT=FAIL )

bin\vordr.exe tmptest > "%WORK%\tmptest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   tmptest: FAIL ^(exit !errorlevel!, temp file not wiped+deleted^) & set RT=FAIL )

bin\vordr.exe fztest > "%WORK%\fztest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   fztest: FAIL ^(exit !errorlevel!, fuzzy scoring KAT^) & set RT=FAIL )

bin\vordr.exe trtest > "%WORK%\trtest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   trtest: FAIL ^(exit !errorlevel!, trash timestamp/threshold KAT^) & set RT=FAIL )

bin\vordr.exe vfuzz > "%WORK%\vfuzz.log" 2>&1
if not "!errorlevel!"=="0" ( echo   vfuzz: FAIL ^(exit !errorlevel!, vault parser fuzzer crashed^) & set RT=FAIL )

bin\vordr.exe fuzzzip > "%WORK%\fuzzzip.log" 2>&1
if not "!errorlevel!"=="0" ( echo   fuzzzip: FAIL ^(exit !errorlevel!, zip-import parser fuzzer crashed^) & set RT=FAIL )

bin\vordr.exe jfuzz > "%WORK%\jfuzz.log" 2>&1
if not "!errorlevel!"=="0" ( echo   jfuzz: FAIL ^(exit !errorlevel!, decrypted-json parser fuzzer crashed/hung^) & set RT=FAIL )

bin\vordr.exe bktest "%WORK%\bk.vault" > "%WORK%\bktest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   bktest: FAIL ^(exit !errorlevel!, atomic-save/backup rotation^) & set RT=FAIL )

bin\vordr.exe mactest "%WORK%\mac.vault" > "%WORK%\mactest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   mactest: FAIL ^(exit !errorlevel!, full-file MAC tamper detection^) & set RT=FAIL )

bin\vordr.exe rbtest "%WORK%\rb.vault" > "%WORK%\rbtest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   rbtest: FAIL ^(exit !errorlevel!, anti-rollback detection^) & set RT=FAIL )

bin\vordr.exe sysitemkat "%WORK%\si.vault" > "%WORK%\sysitemkat.log" 2>&1
if not "!errorlevel!"=="0" ( echo   sysitemkat: FAIL ^(exit !errorlevel!, system item hidden/round-trip^) & set RT=FAIL )

bin\vordr.exe vexselkat "%WORK%\vs.vault" > "%WORK%\vexselkat.log" 2>&1
if not "!errorlevel!"=="0" ( echo   vexselkat: FAIL ^(exit !errorlevel!, .vordr export selection / master untouched^) & set RT=FAIL )

bin\vordr.exe c9kat "%WORK%\c9.vault" > "%WORK%\c9kat.log" 2>&1
if not "!errorlevel!"=="0" ( echo   c9kat: FAIL ^(exit !errorlevel!, C9 re-verify interval/grace/escalation^) & set RT=FAIL )

bin\vordr.exe xctest "%WORK%\xc.vault" > "%WORK%\xctest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   xctest: FAIL ^(exit !errorlevel!, external-change detection^) & set RT=FAIL )

bin\vordr.exe reload "%WORK%\rl.vault" > "%WORK%\reload.log" 2>&1
if not "!errorlevel!"=="0" ( echo   reload: FAIL ^(exit !errorlevel!, vault_reload refresh^) & set RT=FAIL )

bin\vordr.exe cowrite "%WORK%\cw.vault" > "%WORK%\cowrite.log" 2>&1
if not "!errorlevel!"=="0" ( echo   cowrite: FAIL ^(exit !errorlevel!, write-lock exclusivity^) & set RT=FAIL )

bin\vordr.exe attfuzz > "%WORK%\attfuzz.log" 2>&1
if not "!errorlevel!"=="0" ( echo   attfuzz: FAIL ^(exit !errorlevel!, attach_index_build fuzz^) & set RT=FAIL )

bin\vordr.exe zexcap > "%WORK%\zexcap.log" 2>&1
if not "!errorlevel!"=="0" ( echo   zexcap: FAIL ^(exit !errorlevel!, zip-export central-dir cap OOB^) & set RT=FAIL )

bin\vordr.exe zexname > "%WORK%\zexname.log" 2>&1
if not "!errorlevel!"=="0" ( echo   zexname: FAIL ^(exit !errorlevel!, attachment filename leaked into a cleartext ZIP member name^) & set RT=FAIL )

bin\vordr.exe convcap > "%WORK%\convcap.log" 2>&1
if not "!errorlevel!"=="0" ( echo   convcap: FAIL ^(exit !errorlevel!, an over-long field value would be stored EMPTY^) & set RT=FAIL )

bin\vordr.exe healthkat > "%WORK%\healthkat.log" 2>&1
if not "!errorlevel!"=="0" ( echo   healthkat: FAIL ^(exit !errorlevel!, vault-health analysis counts^) & set RT=FAIL )

bin\vordr.exe pkat > "%WORK%\pkat.log" 2>&1
if not "!errorlevel!"=="0" ( echo   pkat: FAIL ^(exit !errorlevel!, parallel fail-closed KAT gate^) & set RT=FAIL )








bin\vordr.exe kdfparam > "%WORK%\kdfparam.log" 2>&1
if not "!errorlevel!"=="0" ( echo   kdfparam: FAIL ^(exit !errorlevel!, pre-auth KDF-param DoS guard^) & set RT=FAIL )










bin\vordr.exe vaultexportkat "%WORK%\ve.vault" > "%WORK%\vaultexportkat.log" 2>&1
if not "!errorlevel!"=="0" ( echo   vaultexportkat: FAIL ^(exit !errorlevel!, M6 vault export/merge round-trip^) & set RT=FAIL )

bin\vordr.exe vaultexpattkat "%WORK%\vea.vault" > "%WORK%\vaultexpattkat.log" 2>&1
if not "!errorlevel!"=="0" ( echo   vaultexpattkat: FAIL ^(exit !errorlevel!, M6 attachment carry^) & set RT=FAIL )

:roundtrip_publish
set R_ROUNDTRIP=!RT!
call :now T1
set /a T_ROUNDTRIP=!T1!-!T0!
:roundtrip_done

rem ------------------------------------------------------- cryptodiff (python) --
rem Independent, external verification of the crypto primitives: recompute every
rem primitive with Python stdlib + a self-validating pure-Python AES-GCM and
rem against the published FIPS/RFC/NIST vectors, then diff vordr's kat-report.
rem Skipped (not failed) if python is unavailable, so the gate still runs without it.
call :now T0
echo === stage: cryptodiff (independent python reference) ===
where python >nul 2>&1
if errorlevel 1 (
    echo   cryptodiff: SKIP ^(python not found on PATH^)
    set R_CRYPTODIFF=skip
) else (
    python tests\verify_crypto.py --exe bin\vordr.exe > "%WORK%\cryptodiff.log" 2>&1
    if errorlevel 1 (
        echo   cryptodiff: FAIL - see %WORK%\cryptodiff.log
        set R_CRYPTODIFF=FAIL
    ) else (
        for /f "tokens=*" %%l in ('findstr /c:"RESULT:" "%WORK%\cryptodiff.log"') do echo   %%l
        set R_CRYPTODIFF=PASS
    )
)
call :now T1
set /a T_CRYPTODIFF=!T1!-!T0!

rem --- restore a clean RELEASE binary in bin\ (roundtrip left a PROBE_IO build,
rem     which exposes the path-taking verbs - never leave that as the artifact) --
if "%R_BUILD%"=="PASS" call .\build.cmd strict > "%WORK%\build_restore.log" 2>&1

rem ---------------------------------------------------------------- summary --
:summary
echo.
echo ============ run_all summary ============
echo   stage        result   seconds
echo   redteam      %R_REDTEAM%     %T_REDTEAM%
echo   build        %R_BUILD%     %T_BUILD%
echo   selftest     %R_SELFTEST%     %T_SELFTEST%
echo   roundtrip    %R_ROUNDTRIP%     %T_ROUNDTRIP%
echo   cryptodiff   %R_CRYPTODIFF%     %T_CRYPTODIFF%
echo =========================================

set EXITC=0
if not "%R_BUILD%"=="PASS" set EXITC=1
if not "%R_SELFTEST%"=="PASS" set EXITC=1
if not "%R_ROUNDTRIP%"=="PASS" set EXITC=1
if not "%R_REDTEAM%"=="PASS" if not "%R_REDTEAM%"=="skip" set EXITC=1
if not "%R_CRYPTODIFF%"=="PASS" if not "%R_CRYPTODIFF%"=="skip" set EXITC=1
if "%EXITC%"=="0" ( echo ALL STAGES PASSED ) else ( echo RUN FAILED )
exit /b %EXITC%

rem :now <var> - unix-epoch seconds into %1 (one powershell spawn per call)
:now
for /f %%t in ('powershell -noprofile -command "[DateTimeOffset]::Now.ToUnixTimeSeconds()"') do set %1=%%t
goto :eof
