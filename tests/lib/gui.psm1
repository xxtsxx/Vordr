# Shared helpers for Vordr's external GUI tests: start an ISOLATED test instance,
# find its windows, drive them, read their controls and globals from outside.
#
#   Import-Module (Join-Path $PSScriptRoot 'lib\gui.psm1') -Force
#
# Ported from Myrkr's tests\lib\gui.psm1.  The in-process probes (layoutkat,
# guardkat) cover what can be measured from inside; this covers what only the
# real message flow shows - a modal that does or does not close, a window that
# does or does not appear, the limit an edit actually enforces.
#
# ISOLATION.  Needs a probeio or dbg build.  Start-VordrTest sets VORDR_TEST_HKCU,
# which makes the instance remap HKEY_CURRENT_USER onto
# HKCU\Software\VordrGuiTest\<name> for its whole process (gui_test_hooks in
# gui.asm): the user's settings, registered vault, rollback counters and TPM
# blobs are never read or written, the user's running Vordr is not handed off to,
# the global hotkey is not taken, the TPM is not used, and prompts stay on the
# normal desktop.  Stop-VordrTest kills the instance and deletes that key.
#
# Conventions: window handles are [IntPtr], [IntPtr]::Zero = not found; processes
# are [Diagnostics.Process]; screen coordinates are absolute.

if (-not ('VordrGui.Native' -as [type])) {
Add-Type @'
using System; using System.Text; using System.Runtime.InteropServices;
namespace VordrGui {
public struct RECT { public int L, T, R, B; }
public static class Native {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetWindow(IntPtr h, uint cmd);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")] public static extern IntPtr SendText(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")] public static extern IntPtr SendBuf(IntPtr h, uint m, IntPtr w, StringBuilder l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref long pt);
  [DllImport("user32.dll")] public static extern bool RedrawWindow(IntPtr h, IntPtr r, IntPtr g, uint f);
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr dc);
  [DllImport("gdi32.dll")]  public static extern uint GetPixel(IntPtr dc, int x, int y);
  [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, IntPtr n, out IntPtr r);
  [DllImport("user32.dll")] public static extern IntPtr OpenInputDesktop(uint f, bool inherit, uint access);
  [DllImport("user32.dll")] public static extern bool CloseDesktop(IntPtr h);
  // Visible top-level windows of a process, as "class: title" - for failure reports.
  public static string[] VisibleOf(uint pid) {
    var list = new System.Collections.Generic.List<string>();
    EnumWindows(delegate(IntPtr h, IntPtr u) {
      uint o; GetWindowThreadProcessId(h, out o);
      if (o == pid && IsWindowVisible(h)) list.Add(ClassOf(h) + ": " + TitleOf(h));
      return true; }, IntPtr.Zero);
    return list.ToArray();
  }

  // EnumWindows + compare, never FindWindow: it would find the USER's Vordr too.
  public static IntPtr Find(uint pid, string cls, string title, bool visibleOnly) {
    IntPtr found = IntPtr.Zero;
    EnumWindows(delegate(IntPtr h, IntPtr u) {
      uint o; GetWindowThreadProcessId(h, out o);
      if (o != pid) return true;
      if (visibleOnly && !IsWindowVisible(h)) return true;
      if (!string.IsNullOrEmpty(cls)) { var s = new StringBuilder(256); GetClassNameW(h, s, 256); if (s.ToString() != cls) return true; }
      if (!string.IsNullOrEmpty(title)) { var t = new StringBuilder(512); GetWindowTextW(h, t, 512); if (t.ToString() != title) return true; }
      found = h; return false; }, IntPtr.Zero);
    return found;
  }
  // Top-level windows of the process whose OWNER is `owner` (modal dialogs).
  public static IntPtr[] Owned(uint pid, IntPtr owner) {
    var list = new System.Collections.Generic.List<IntPtr>();
    EnumWindows(delegate(IntPtr h, IntPtr u) {
      uint o; GetWindowThreadProcessId(h, out o);
      if (o == pid && IsWindowVisible(h) && GetWindow(h, 4) == owner) list.Add(h);
      return true; }, IntPtr.Zero);
    return list.ToArray();
  }
  // By control id at any depth; GetDlgItem only sees direct children.
  public static IntPtr Child(IntPtr top, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(top, delegate(IntPtr h, IntPtr u) {
      if (GetDlgCtrlID(h) == id) { found = h; return false; }
      return true; }, IntPtr.Zero);
    return found;
  }
  public static string ClassOf(IntPtr h) { var s = new StringBuilder(256); GetClassNameW(h, s, 256); return s.ToString(); }
  public static string TitleOf(IntPtr h) { var s = new StringBuilder(1024); GetWindowTextW(h, s, 1024); return s.ToString(); }
}
}
'@
}

$script:WM_SETTEXT      = 0x000C
$script:WM_GETTEXT      = 0x000D
$script:WM_CLOSE        = 0x0010
$script:WM_COMMAND      = 0x0111
$script:WM_MOUSEWHEEL   = 0x020A
$script:EM_GETLIMITTEXT = 0x00D5

$script:TestRoot = 'HKCU:\Software\VordrGuiTest'

# ---------------------------------------------------------------- processes ---

function Stop-Vordr {
    param($Process)
    if ($Process) { try { if (-not $Process.HasExited) { $Process.Kill(); $Process.WaitForExit(3000) | Out-Null } } catch {} }
}

# Starts an isolated test instance on -Vault.  Returns the process.  The exe must
# be a probeio/dbg build: a release build has no gui_test_hooks, so it would run
# against the user's own HKCU - Start-VordrTest refuses one (it checks the map).
function Start-VordrTest {
    param([Parameter(Mandatory)][string]$Exe, [Parameter(Mandatory)][string]$Vault,
          [Parameter(Mandatory)][string]$Name, [hashtable]$Prefs = @{})
    $map = [IO.Path]::ChangeExtension($Exe, '.map')
    if (-not (Select-String -LiteralPath $map -Pattern '\sg_testmode\s' -Quiet)) {
        throw "$Exe has no gui_test_hooks (not a probeio/dbg build) - refusing to run it against the real HKCU"
    }
    Remove-VordrTestKey $Name
    # -Prefs @{ ui_scheme = 0 } seeds DWORD settings into the SCRATCH profile the
    # instance will read (HKCU\Software\VordrGuiTest\<name>\SOFTWARE\Vordr).
    if ($Prefs.Count) {
        $k = Join-Path (Join-Path $script:TestRoot $Name) 'SOFTWARE\Vordr'
        New-Item -Path $k -Force | Out-Null
        foreach ($n in $Prefs.Keys) { New-ItemProperty -Path $k -Name $n -Value ([int]$Prefs[$n]) -PropertyType DWord -Force | Out-Null }
    }
    $psi = New-Object Diagnostics.ProcessStartInfo $Exe
    $psi.UseShellExecute = $false
    $psi.EnvironmentVariables['VORDR_TEST_HKCU'] = $Name
    $psi.EnvironmentVariables['VORDR_TEST_VAULT'] = $Vault
    return [Diagnostics.Process]::Start($psi)
}

function Remove-VordrTestKey { param([Parameter(Mandatory)][string]$Name)
    $k = Join-Path $script:TestRoot $Name
    if (Test-Path $k) { Remove-Item $k -Recurse -Force }
}

function Stop-VordrTest { param($Process, [string]$Name)
    Stop-Vordr $Process
    if ($Name) { Remove-VordrTestKey $Name }
    # the parent goes too once nothing else is under it (the gate's probes use "cli")
    if ((Test-Path $script:TestRoot) -and -not (Get-ChildItem $script:TestRoot)) { Remove-Item $script:TestRoot -Force }
}

# Isolation must be ENGAGED before anything is typed or pressed: the instance
# remapped HKCU (g_testmode = 1), or it refused to run (exit 0xE0F7).  Throws
# otherwise - a harness driving an un-isolated Vordr would be driving the user's.
function Assert-VordrIsolated {
    param([Parameter(Mandatory)]$Process, [Parameter(Mandatory)][string]$Map, [int]$TimeoutMs = 15000)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    do {
        if ($Process.HasExited) {
            throw ("the test instance exited (0x{0:X}){1}" -f $Process.ExitCode,
                   $(if (($Process.ExitCode -band 0xFFFF) -eq 0xE0F7) { ' - it could not isolate itself and refused to run' } else { '' }))
        }
        $tray = [VordrGui.Native]::Find([uint32]$Process.Id, 'VordrTray', $null, $false)
        if ($tray -ne [IntPtr]::Zero) {
            if ((Read-VordrGlobal -Process $Process -Map $Map -Symbol 'g_testmode') -ne 1) {
                throw 'the test instance is running WITHOUT isolation (g_testmode != 1) - stopping before any interaction'
            }
            return $tray
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'the test instance never created its tray window'
}

# $true when this session has an input desktop a test window can appear on.
function Test-VordrDesktop {
    if (-not [Environment]::UserInteractive) { return $false }
    $d = [VordrGui.Native]::OpenInputDesktop(0, $false, 1)
    if ($d -eq [IntPtr]::Zero) { return $false }
    [void][VordrGui.Native]::CloseDesktop($d); return $true
}

function Get-VordrVisible { param([Parameter(Mandatory)]$Process) [VordrGui.Native]::VisibleOf([uint32]$Process.Id) }

# Starts the CLI half (seedtest etc.) hidden and waits; returns the exit code.
function Invoke-VordrCli {
    param([Parameter(Mandatory)][string]$Exe, [Parameter(Mandatory)][string[]]$Arguments)
    $q = foreach ($a in $Arguments) { if ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' } else { $a } }
    $p = Start-Process -WindowStyle Hidden -FilePath $Exe -ArgumentList $q -Wait -PassThru
    return $p.ExitCode
}

# ------------------------------------------------------------------ windows ---

function Wait-VordrWindow {
    param([Parameter(Mandatory)]$Process, [string]$Class, [string]$Title,
          [int]$TimeoutMs = 10000, [switch]$IncludeHidden)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    do {
        $h = [VordrGui.Native]::Find([uint32]$Process.Id, $Class, $Title, -not $IncludeHidden)
        if ($h -ne [IntPtr]::Zero) { return $h }
        if ($Process.HasExited) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return [IntPtr]::Zero
}

# Waits until -Hwnd is gone (destroyed or hidden).  $true if it went.
function Wait-VordrGone {
    param([Parameter(Mandatory)][IntPtr]$Hwnd, [int]$TimeoutMs = 5000)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    do {
        if (-not [VordrGui.Native]::IsWindow($Hwnd) -or -not [VordrGui.Native]::IsWindowVisible($Hwnd)) { return $true }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return $false
}

# The dialogs a window currently owns (a modal message box, a picker, ...).
function Get-VordrOwned {
    param([Parameter(Mandatory)]$Process, [Parameter(Mandatory)][IntPtr]$Owner)
    return ,([VordrGui.Native]::Owned([uint32]$Process.Id, $Owner))
}

function Wait-VordrOwned {
    param([Parameter(Mandatory)]$Process, [Parameter(Mandatory)][IntPtr]$Owner, [int]$TimeoutMs = 5000)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    do {
        $o = [VordrGui.Native]::Owned([uint32]$Process.Id, $Owner)
        if ($o.Count) { return $o[0] }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return [IntPtr]::Zero
}

function Get-VordrControl {
    param([Parameter(Mandatory)][IntPtr]$Window, [Parameter(Mandatory)][int]$Id)
    return [VordrGui.Native]::Child($Window, $Id)
}

function Get-VordrTitle { param([Parameter(Mandatory)][IntPtr]$Hwnd) [VordrGui.Native]::TitleOf($Hwnd) }

# Text of a control in another process (GetWindowTextW does not read a
# cross-process EDIT; WM_GETTEXT does).
function Get-VordrText {
    param([Parameter(Mandatory)][IntPtr]$Hwnd)
    $sb = New-Object Text.StringBuilder 4096
    [void][VordrGui.Native]::SendBuf($Hwnd, $WM_GETTEXT, [IntPtr]4096, $sb)
    return $sb.ToString()
}

function Set-VordrText {
    param([Parameter(Mandatory)][IntPtr]$Hwnd, [Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    [void][VordrGui.Native]::SendText($Hwnd, $WM_SETTEXT, [IntPtr]::Zero, $Text)
}

# The limit an edit enforces on typing and pasting (EM_GETLIMITTEXT).
function Get-VordrEditLimit {
    param([Parameter(Mandatory)][IntPtr]$Hwnd)
    return [int][VordrGui.Native]::SendMessageW($Hwnd, $EM_GETLIMITTEXT, [IntPtr]::Zero, [IntPtr]::Zero)
}

# WM_COMMAND with a control id - a button press.  Posted by default: the handler
# may open a modal loop, and a Send would block until it closes.
function Send-VordrCommand {
    param([Parameter(Mandatory)][IntPtr]$Window, [Parameter(Mandatory)][int]$Id,
          [int]$Notify = 0, [IntPtr]$LParam = [IntPtr]::Zero, [switch]$Sync)
    $w = [IntPtr](([int64]$Notify -shl 16) -bor ($Id -band 0xFFFF))
    if ($Sync) { [void][VordrGui.Native]::SendMessageW($Window, $WM_COMMAND, $w, $LParam) }
    else       { [void][VordrGui.Native]::PostMessageW($Window, $WM_COMMAND, $w, $LParam) }
}

function Send-VordrMessage {
    param([Parameter(Mandatory)][IntPtr]$Hwnd, [Parameter(Mandatory)][uint32]$Msg,
          [IntPtr]$W = [IntPtr]::Zero, [IntPtr]$L = [IntPtr]::Zero)
    return [VordrGui.Native]::SendMessageW($Hwnd, $Msg, $W, $L)
}

function Get-VordrRect {
    param([Parameter(Mandatory)][IntPtr]$Hwnd, [switch]$Client)
    $r = New-Object VordrGui.RECT
    if ($Client) { [void][VordrGui.Native]::GetClientRect($Hwnd, [ref]$r) }
    else         { [void][VordrGui.Native]::GetWindowRect($Hwnd, [ref]$r) }
    return $r
}

# The screen position of a window's client origin.  NOT the window rect plus a
# guessed border: on Windows 11 a resizable window's rect includes an invisible
# resize border (7px here), so "left + 1" missed the thumb by six pixels.
function Get-VordrClientOrigin {
    param([Parameter(Mandatory)][IntPtr]$Hwnd)
    $pt = [int64]0
    [void][VordrGui.Native]::ClientToScreen($Hwnd, [ref]$pt)
    return [pscustomobject]@{ X = [int]($pt -band [int64]4294967295); Y = [int]($pt -shr 32) }
}

# ------------------------------------------------------- process memory (map) ---

# The RVA of a symbol (public or static) from bin\vordr.map (base 0x140000000).
# The map must come from the SAME build as the running exe.
function Get-VordrRva {
    param([Parameter(Mandatory)][string]$Map, [Parameter(Mandatory)][string]$Symbol)
    $l = Select-String -LiteralPath $Map -Pattern ("\s" + [regex]::Escape($Symbol) + "\s") | Select-Object -First 1
    if (-not $l) { return $null }
    return [int64]([Convert]::ToUInt64((($l.Line.Trim() -split '\s+')[2]), 16) - 0x140000000)
}

# Reads a global: 4 bytes as Int32, 8 as Int64, anything else as byte[].  $null
# when the symbol is not in the map - which is NOT a value; a caller that treats
# it as 0 passes vacuously.
function Read-VordrGlobal {
    param([Parameter(Mandatory)]$Process, [Parameter(Mandatory)][string]$Map,
          [Parameter(Mandatory)][string]$Symbol, [int]$Size = 4)
    $rva = Get-VordrRva -Map $Map -Symbol $Symbol
    if ($null -eq $rva) { return $null }
    $b = New-Object byte[] $Size; $got = [IntPtr]::Zero
    $addr = [IntPtr]([int64]$Process.MainModule.BaseAddress + $rva)
    if (-not [VordrGui.Native]::ReadProcessMemory($Process.Handle, $addr, $b, [IntPtr]$Size, [ref]$got)) { return $null }
    switch ($Size) { 4 { return [BitConverter]::ToInt32($b, 0) } 8 { return [BitConverter]::ToInt64($b, 0) } default { return ,$b } }
}

# ------------------------------------------------------------------- builds ---

# Builds a variant in -Root (default: this repo).  Throws on failure, with the
# tail of the log - a test that carries on against the previous binary reports
# that binary's behaviour as its own.  ml64/link/rc must be on PATH.
function Invoke-VordrBuild {
    param([string]$Variant = 'release strict', [string]$Root = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent))
    Push-Location $Root
    try { $log = cmd /c ".\build.cmd $Variant" 2>&1 } finally { Pop-Location }
    if (($log -join "`n") -notmatch 'BUILD OK') { throw "build '$Variant' failed:`n" + (($log | Select-Object -Last 15) -join "`n") }
}

Export-ModuleMember -Function *-Vordr*, Stop-Vordr
