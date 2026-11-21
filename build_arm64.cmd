@echo off
rem ===========================================================================
rem build_arm64.cmd - build the native Windows on ARM (ARM64) binary
rem                   bin\vordr-arm64.exe from the same x64 MASM sources +
rem                   hand-written AArch64 crypto/SIMD/platform routines in
rem                   src\arm64\*.S (see docs\ARM64.md).
rem
rem Requires: ml64, link, rc (VS / MSVC tools), clang, llvm-lib (LLVM), python.
rem
rem Optional args (combinable, matching build.cmd):
rem   build_arm64 release   reproducible normalised release build (implies strict)
rem   build_arm64 strict    fail on any static-checker finding
rem   build_arm64 dbg       debug trace + redteam + probeio
rem   build_arm64 probeio   expose path-taking diagnostic KAT verbs
rem   build_arm64 guishow   debug-only: auto-open vault window
rem   build_arm64 clean     wipe obj\arm64 before building
rem ===========================================================================
setlocal
cd /d "%~dp0"

set PYARGS=
:argloop
if "%1"=="" goto :doneargs
if /i "%1"=="release" (set PYARGS=%PYARGS% --release& shift & goto :argloop)
if /i "%1"=="strict"  (set PYARGS=%PYARGS% --strict& shift & goto :argloop)
if /i "%1"=="dbg"     (set PYARGS=%PYARGS% --dbg& shift & goto :argloop)
if /i "%1"=="probeio" (set PYARGS=%PYARGS% --probeio& shift & goto :argloop)
if /i "%1"=="guishow" (set PYARGS=%PYARGS% --guishow& shift & goto :argloop)
if /i "%1"=="nohw"    (set PYARGS=%PYARGS% --nohw& shift & goto :argloop)
if /i "%1"=="clean"   (set PYARGS=%PYARGS% --clean& shift & goto :argloop)
echo build_arm64: unknown argument "%1"
exit /b 1
:doneargs

where python >nul 2>nul
if errorlevel 1 (
    echo build_arm64: python not found on PATH
    exit /b 1
)

python tools\a64\build_arm64.py %PYARGS%
if errorlevel 1 exit /b 1
exit /b 0
