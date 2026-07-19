@echo off
rem ===========================================================================
rem build.cmd - assemble and link the single hybrid vordr.exe (password mgr).
rem
rem ONE executable serves both roles: it is linked /subsystem:windows with the
rem GUI entry point (wstart), but wstart runs the full CLI when argv[1] is a
rem known verb (selftest/bench/genpw/seedtest/... - diagnostics only; never a
rem vault path, password, or secret).  Otherwise it opens the windowed
rem front-end.  Every launch runs the self-test gate first and
rem fails closed.  See src\gui.asm:wstart.
rem
rem Run from a
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
rem                (0xFADE<code>) for the security test harness (tests\run_all.cmd)
rem ---------------------------------------------------------------------------
set GUARDFLAGS=/CETCOMPAT
set ASMEXTRA=
set STRICT=0
set REPRO=0
:argloop
if "%1"=="" goto :doneargs
if /i "%1"=="nohw" set GUARDFLAGS=
if /i "%1"=="dbg" set ASMEXTRA=%ASMEXTRA% /DDBG_TRACE
if /i "%1"=="strict" set STRICT=1
if /i "%1"=="release" set REPRO=1
shift
goto :argloop
:doneargs

rem ---------------------------------------------------------------------------
rem Reproducible release build ("build release"): two clean builds of the same
rem commit must produce a byte-identical exe (auditability - a user can rebuild
rem and match the published SHA-256).  The nondeterminism sources in a plain
rem link are (a) the PE header TimeDateStamp and (b) the absolute PDB path plus
rem its content GUID embedded in the debug directory.
rem   /Brepro           - replace every timestamp with a deterministic content
rem                       hash (PE header + debug directory + the PDB signature)
rem   /pdbaltpath:vordr.pdb - embed just the bare PDB name, never the machine's
rem                       absolute build path, so the exe is location-independent
rem The security mitigations (CET, DEP, ASLR, highentropyVA) are orthogonal
rem link flags and stay on in release builds.
rem ---------------------------------------------------------------------------
set REPROFLAGS=
if "%REPRO%"=="1" set REPROFLAGS=/Brepro /pdbaltpath:vordr.pdb

rem ---------------------------------------------------------------------------
rem framecheck: static scan for WINCALL stack-arg spills that overflow a proc's
rem frame (the raw-dialog-proc return-address-smash class, see
rem tools\framecheck.py).  Advisory by default; "build strict" makes a FATAL
rem finding fail the build.  Skipped silently when python is not on PATH.
rem idcheck (tools\idcheck.py) and deadcode (tools\deadcode.py) gate the same
rem way: rc/asm control-ID mismatches / dead symbols fail a strict build.
rem ---------------------------------------------------------------------------
where python >nul 2>nul
if errorlevel 1 goto :nofc
echo === framecheck ===
python tools\framecheck.py
if errorlevel 1 (
    if "%STRICT%"=="1" (
        echo framecheck: FATAL frame bug - failing strict build
        goto :failed
    )
    echo framecheck: WARNING - fatal findings above; build continues. Use "build strict" to gate.
)
echo === idcheck ===
python tools\idcheck.py
if errorlevel 1 (
    if "%STRICT%"=="1" (
        echo idcheck: rc/asm ID mismatch - failing strict build
        goto :failed
    )
    echo idcheck: WARNING - ID mismatches above; build continues. Use "build strict" to gate.
)
echo === deadcode ===
python tools\deadcode.py
if errorlevel 1 (
    if "%STRICT%"=="1" (
        echo deadcode: dead proc/data/equ - failing strict build
        goto :failed
    )
    echo deadcode: WARNING - dead symbols above; build continues. Use "build strict" to gate.
)
:nofc

set ASMFLAGS=/c /nologo /W3 /Zi %ASMEXTRA%
set SOURCES=main console hardening random loadcfg sha256 sha1 aesgcm blake2b argon2 fileio secmem vault totp tpm regcfg pwgen bench log selftest redteam theme zipexport zipimport gui

echo === assembling ===
for %%f in (%SOURCES%) do (
    ml64 %ASMFLAGS% /Foobj\%%f.obj /Flobj\%%f.lst /I src src\%%f.asm
    if errorlevel 1 goto :failed
)

rem ---------------------------------------------------------------------------
rem Windows SDK paths.  The version is resolved at build time: the newest 10.*
rem dir under the SDK's Lib (dir /o-n = newest name first) wins, with the
rem pinned version as fallback if the enumeration finds nothing.  The tools
rem (ml64/rc/link) must be on PATH; passing the SDK include dirs to rc.exe
rem explicitly means this script builds from a plain prompt too, not only from an
rem "x64 Native Tools Command Prompt" that pre-sets the INCLUDE variable.
rem ---------------------------------------------------------------------------
set SDKROOT=C:\Program Files (x86)\Windows Kits\10
set SDKVER=10.0.26100.0
for /f %%v in ('dir /b /ad /o-n "%SDKROOT%\Lib\10.*" 2^>nul') do (
    set SDKVER=%%v
    goto :sdkver_done
)
:sdkver_done
set SDKLIB=%SDKROOT%\Lib\%SDKVER%\um\x64
set SDKBIN=%SDKROOT%\bin\%SDKVER%\x64
set SDKINC=%SDKROOT%\Include\%SDKVER%
if exist "%SDKBIN%\mt.exe" set PATH=%SDKBIN%;%PATH%

echo === resource (VERSIONINFO) ===
rc /nologo /I "%SDKINC%\um" /I "%SDKINC%\shared" /I "%SDKINC%\ucrt" /fo obj\vordr.res vordr.rc
if errorlevel 1 goto :failed

echo === linking vordr.exe (%GUARDFLAGS%) ===
link /nologo /subsystem:windows /entry:wstart /nodefaultlib /incremental:no ^
     /dynamicbase /highentropyva /nxcompat /largeaddressaware ^
     %GUARDFLAGS% %REPROFLAGS% /debug /pdb:bin\vordr.pdb ^
     /manifest:embed /manifestinput:vordr.manifest /manifestuac:no ^
     /libpath:"%SDKLIB%" ^
     /out:bin\vordr.exe obj\main.obj obj\console.obj obj\hardening.obj obj\random.obj obj\loadcfg.obj obj\sha256.obj obj\sha1.obj obj\aesgcm.obj obj\blake2b.obj obj\argon2.obj obj\fileio.obj obj\secmem.obj obj\vault.obj obj\totp.obj obj\tpm.obj obj\regcfg.obj obj\pwgen.obj obj\bench.obj obj\log.obj obj\selftest.obj obj\redteam.obj obj\theme.obj obj\zipexport.obj obj\zipimport.obj obj\gui.obj obj\vordr.res ^
     kernel32.lib bcrypt.lib user32.lib gdi32.lib msimg32.lib dwmapi.lib dxgi.lib comctl32.lib uxtheme.lib advapi32.lib comdlg32.lib ncrypt.lib shell32.lib wtsapi32.lib
if errorlevel 1 goto :failed

echo === mitigation check (optional, needs dumpbin) ===
dumpbin /headers bin\vordr.exe | findstr /i "Dynamic NX Guard CET High" 2>nul

if "%REPRO%"=="1" (
    echo === release SHA-256 ^(publish + verify against a fresh rebuild^) ===
    certutil -hashfile bin\vordr.exe SHA256 | findstr /r "^[0-9a-f]"
)

echo.
echo BUILD OK: bin\vordr.exe
exit /b 0

:failed
echo.
echo BUILD FAILED
exit /b 1
