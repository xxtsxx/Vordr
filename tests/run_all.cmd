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
rem   roundtrip  headless probes: seedtest -> atgen -> zitest -> phtest ->
rem              secscan -> tmptest -> fztest -> trtest -> vfuzz -> fuzzzip ->
rem              bktest -> mactest -> rbtest -> xctest -> pkat
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
echo === stage: roundtrip (seedtest / atgen / zitest / phtest / secscan / tmptest / fztest / trtest / vfuzz / fuzzzip / bktest / mactest / rbtest / xctest / reload / pkat / mvtest / mvswitch / avtest) ===
set RT=PASS

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

bin\vordr.exe bktest "%WORK%\bk.vault" > "%WORK%\bktest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   bktest: FAIL ^(exit !errorlevel!, atomic-save/backup rotation^) & set RT=FAIL )

bin\vordr.exe mactest "%WORK%\mac.vault" > "%WORK%\mactest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   mactest: FAIL ^(exit !errorlevel!, full-file MAC tamper detection^) & set RT=FAIL )

bin\vordr.exe rbtest "%WORK%\rb.vault" > "%WORK%\rbtest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   rbtest: FAIL ^(exit !errorlevel!, anti-rollback detection^) & set RT=FAIL )

bin\vordr.exe xctest "%WORK%\xc.vault" > "%WORK%\xctest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   xctest: FAIL ^(exit !errorlevel!, external-change detection^) & set RT=FAIL )

bin\vordr.exe reload "%WORK%\rl.vault" > "%WORK%\reload.log" 2>&1
if not "!errorlevel!"=="0" ( echo   reload: FAIL ^(exit !errorlevel!, vault_reload refresh^) & set RT=FAIL )

bin\vordr.exe pkat > "%WORK%\pkat.log" 2>&1
if not "!errorlevel!"=="0" ( echo   pkat: FAIL ^(exit !errorlevel!, parallel fail-closed KAT gate^) & set RT=FAIL )

bin\vordr.exe mvtest > "%WORK%\mvtest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   mvtest: FAIL ^(exit !errorlevel!, multi-vault snapshot/restore^) & set RT=FAIL )

bin\vordr.exe mvswitch > "%WORK%\mvswitch.log" 2>&1
if not "!errorlevel!"=="0" ( echo   mvswitch: FAIL ^(exit !errorlevel!, multi-vault context switch^) & set RT=FAIL )

bin\vordr.exe avtest > "%WORK%\avtest.log" 2>&1
if not "!errorlevel!"=="0" ( echo   avtest: FAIL ^(exit !errorlevel!, availability retry state machine^) & set RT=FAIL )

set R_ROUNDTRIP=!RT!
call :now T1
set /a T_ROUNDTRIP=!T1!-!T0!
:roundtrip_done

rem ---------------------------------------------------------------- summary --
:summary
echo.
echo ============ run_all summary ============
echo   stage        result   seconds
echo   redteam      %R_REDTEAM%     %T_REDTEAM%
echo   build        %R_BUILD%     %T_BUILD%
echo   selftest     %R_SELFTEST%     %T_SELFTEST%
echo   roundtrip    %R_ROUNDTRIP%     %T_ROUNDTRIP%
echo =========================================

set EXITC=0
if not "%R_BUILD%"=="PASS" set EXITC=1
if not "%R_SELFTEST%"=="PASS" set EXITC=1
if not "%R_ROUNDTRIP%"=="PASS" set EXITC=1
if not "%R_REDTEAM%"=="PASS" if not "%R_REDTEAM%"=="skip" set EXITC=1
if "%EXITC%"=="0" ( echo ALL STAGES PASSED ) else ( echo RUN FAILED )
exit /b %EXITC%

rem :now <var> - unix-epoch seconds into %1 (one powershell spawn per call)
:now
for /f %%t in ('powershell -noprofile -command "[DateTimeOffset]::Now.ToUnixTimeSeconds()"') do set %1=%%t
goto :eof
