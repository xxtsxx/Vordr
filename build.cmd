@echo off
rem ===========================================================================
rem build.cmd - assemble and link the single hybrid vordr.exe (password mgr).
rem
rem ONE executable serves both roles: it is linked /subsystem:windows with the
rem GUI entry point (wstart), but wstart runs the full CLI when argv[1] is a
rem known verb (init/add/get/list/edit/remove/gen/padnew/padimport/share/open/
rem selftest/bench).  Otherwise it opens the windowed front-end.  Every launch
rem runs the self-test gate first and fails closed.  See src\gui.asm:wstart.
rem
rem Reuses the proven Myrkr crypto + hardening core verbatim.  Run from a
rem "x64 Native Tools Command Prompt for VS" (ml64/link on PATH).
rem ===========================================================================
setlocal
cd /d "%~dp0"

if not exist obj mkdir obj
if not exist bin mkdir bin

rem ---------------------------------------------------------------------------
rem Mitigations: CET hardware shadow stack plus the always-on software set
rem (DLPV, software shadow stack, stack canaries, ASLR/DEP/NX).
rem
rem NOTE: /guard:cf (Control Flow Guard) is intentionally NOT used.  CFG needs
rem per-function metadata that hand-written MASM cannot emit, and a GUI image
rem hands the OS callback pointers (window proc, thread proc) that CFG-
rem instrumented OS code validates against this image's (absent) CFG table,
rem which fast-fails at load.  Since this one binary also runs the GUI, CFG must
rem stay off; CET and the software mitigations remain.
rem
rem Optional args (combinable):
rem   build nohw   link WITHOUT /CETCOMPAT (software mitigations only)
rem   build dbg    add startup breadcrumb trace + per-primitive debug dumps,
rem                the `redteam` fault-injection self-test, and FF-code-in-exit
rem                (0xFADE<code>) for the security test harness (tests/redteam.py)
rem ---------------------------------------------------------------------------
set GUARDFLAGS=/CETCOMPAT
set ASMEXTRA=
:argloop
if "%1"=="" goto :doneargs
if /i "%1"=="nohw" set GUARDFLAGS=
if /i "%1"=="dbg" set ASMEXTRA=%ASMEXTRA% /DDBG_TRACE
shift
goto :argloop
:doneargs

set ASMFLAGS=/c /nologo /W3 /Zi %ASMEXTRA%
set SOURCES=main console hardening random loadcfg sha256 aesgcm blake2b argon2 fileio secmem vault pad pwgen otp log selftest redteam gui

echo === assembling ===
for %%f in (%SOURCES%) do (
    ml64 %ASMFLAGS% /Foobj\%%f.obj /Flobj\%%f.lst /I src src\%%f.asm
    if errorlevel 1 goto :failed
)

rem SDK import libraries (adjust version here if the SDK is updated)
set SDKLIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64
rem SDK bin (for mt.exe, used by /manifest:embed) - prepend to PATH if present
set SDKBIN=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64
if exist "%SDKBIN%\mt.exe" set PATH=%SDKBIN%;%PATH%

echo === resource (VERSIONINFO) ===
rc /nologo /fo obj\vordr.res vordr.rc
if errorlevel 1 goto :failed

echo === linking vordr.exe (%GUARDFLAGS%) ===
link /nologo /subsystem:windows /entry:wstart /nodefaultlib /incremental:no ^
     /dynamicbase /highentropyva /nxcompat /largeaddressaware ^
     %GUARDFLAGS% /debug /pdb:bin\vordr.pdb ^
     /manifest:embed /manifestinput:vordr.manifest /manifestuac:no ^
     /libpath:"%SDKLIB%" ^
     /out:bin\vordr.exe obj\main.obj obj\console.obj obj\hardening.obj obj\random.obj obj\loadcfg.obj obj\sha256.obj obj\aesgcm.obj obj\blake2b.obj obj\argon2.obj obj\fileio.obj obj\secmem.obj obj\vault.obj obj\pad.obj obj\pwgen.obj obj\otp.obj obj\log.obj obj\selftest.obj obj\redteam.obj obj\gui.obj obj\vordr.res ^
     kernel32.lib bcrypt.lib user32.lib advapi32.lib
if errorlevel 1 goto :failed

echo === mitigation check (optional, needs dumpbin) ===
dumpbin /headers bin\vordr.exe | findstr /i "Dynamic NX Guard CET High" 2>nul

echo.
echo BUILD OK: bin\vordr.exe
exit /b 0

:failed
echo.
echo BUILD FAILED
exit /b 1
