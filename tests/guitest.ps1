# guitest.ps1 - external GUI regression tests: a real, ISOLATED Vordr instance
# driven through its own windows.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\guitest.ps1 [-Exe bin\vordr.exe] [-Slow]
#
# -Slow adds the real idle lock with a dialog open (IdleLockMin = 1, about 70 s)
# and one real mouse press on the detail pane's thumb (it moves the cursor and clicks).
# Idle time is system-wide, so it reports SKIP if anyone uses the machine meanwhile.
#
# Needs a probeio or dbg build (bin\vordr.exe + bin\vordr.map from the same
# build).  The instance runs with HKCU remapped to a scratch key and on a seeded
# test vault (see tests\lib\gui.psm1): the user's own Vordr, settings and vault are
# never touched.  The test password is the seeded vaults' fixed one.
#
# Exit 0 = every check passed.  A missing interactive desktop is a SKIP (exit 0
# with a SKIP line), never a silent pass.
param([string]$Exe = "", [switch]$Slow)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $PSScriptRoot 'lib\gui.psm1') -Force
if (-not $Exe) { $Exe = Join-Path $root 'bin\vordr.exe' }
$Exe = (Resolve-Path $Exe).Path
$map = [IO.Path]::ChangeExtension($Exe, '.map')

$work = Join-Path ([IO.Path]::GetTempPath()) ('vordr-guitest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory $work | Out-Null
$vault = Join-Path $work 'gt.vault'
$name  = 'gt' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$pw    = 'vordrtest'                                    # the seeded vaults' fixed test password

# control and command ids (vordr.rc / gui.asm)
$IDM_OPEN = 1002; $IDC_U_PW = 104; $IDC_U_UNLOCK = 105
$IDC_V_LIST = 201; $IDC_V_REMOVE = 211; $IDC_V_LOCK = 212; $IDC_V_SEARCH = 232
$IDC_M_TEXT = 601; $IDC_M_OK = 602
$T_VAULT = 'Vordr - Vault'; $T_UNLOCK = 'Vordr - Unlock vault'

$script:fails = 0; $script:oks = 0
function Check([bool]$c, [string]$m) {
    if ($c) { $script:oks++; Write-Host "  ok   $m" } else { $script:fails++; Write-Host "  FAIL $m" }
}

# Dismiss anything the vault window owns that this test did not ask for (a one-off
# notice), so it cannot be mistaken for - or block - what the test drives.
function Clear-Notices($p, [IntPtr]$owner) {
    for ($k = 0; $k -lt 5; $k++) {
        $o = Get-VordrOwned -Process $p -Owner $owner
        if (-not $o.Count) { return }
        Write-Host ("  (dismissing notice: {0})" -f (Get-VordrText (Get-VordrControl -Window $o[0] -Id $IDC_M_TEXT)))
        Send-VordrCommand -Window $o[0] -Id $IDC_M_OK
        Start-Sleep -Milliseconds 400
    }
}

function Open-Unlock($p) {
    $tray = Assert-VordrIsolated -Process $p -Map $map                # before ANY interaction
    Send-VordrCommand -Window $tray -Id $IDM_OPEN
    $u = Wait-VordrWindow -Process $p -Title $T_UNLOCK -TimeoutMs 15000
    return $u
}

function Unlock($p, [IntPtr]$u) {
    $ed = Get-VordrControl -Window $u -Id $IDC_U_PW
    Set-VordrText -Hwnd $ed -Text $pw
    Send-VordrCommand -Window $u -Id $IDC_U_UNLOCK
    $v = Wait-VordrWindow -Process $p -Title $T_VAULT -TimeoutMs 60000
    if ($v -ne [IntPtr]::Zero) { Start-Sleep -Milliseconds 800; Clear-Notices $p $v }
    return $v
}

$p = $null
try {
    Write-Host "seeding $vault"
    $rc = Invoke-VordrCli -Exe $Exe -Arguments @('seedtest', $vault)
    if ($rc -ne 0) { throw "seedtest failed ($rc) - is this a probeio/dbg build?" }

    $p = Start-VordrTest -Exe $Exe -Vault $vault -Name $name
    Write-Host "instance pid $($p.Id), HKCU -> Software\VordrGuiTest\$name"

    # ---- isolation actually engaged -------------------------------------------
    if (-not (Test-VordrDesktop)) {
        Write-Host "SKIP: this session has no interactive input desktop, so no window can appear"
        exit 0
    }
    $u = Open-Unlock $p
    if ($null -eq $u -or $u -eq [IntPtr]::Zero) {
        # There IS a desktop: a missing window is a failure, never a skip - a startup
        # message box, a hang or the wrong dialog would otherwise pass the gate.
        throw ("no unlock window appeared; the instance shows: " + ((Get-VordrVisible $p) -join ' | '))
    }
    Check ((Read-VordrGlobal -Process $p -Map $map -Symbol 'g_testmode') -eq 1) 'test isolation engaged (g_testmode = 1: HKCU remapped)'
    Check (Test-Path "HKCU:\Software\VordrGuiTest\$name") 'the scratch HKCU key exists'

    # ---- input limits match the buffers they are read into --------------------
    $ed = Get-VordrControl -Window $u -Id $IDC_U_PW
    Check ((Get-VordrEditLimit $ed) -eq 1023) ("unlock password box stops at 1023 characters (got {0})" -f (Get-VordrEditLimit $ed))

    $v = Unlock $p $u
    Check ($v -ne [IntPtr]::Zero) 'unlock with the test password opens the vault window'
    if ($v -eq [IntPtr]::Zero) { throw 'no vault window' }
    $se = Get-VordrControl -Window $v -Id $IDC_V_SEARCH
    Check ((Get-VordrEditLimit $se) -eq 254) ("search box stops at 254 characters (got {0})" -f (Get-VordrEditLimit $se))

    # select the first entry
    $lb = Get-VordrControl -Window $v -Id $IDC_V_LIST
    [void](Send-VordrMessage -Hwnd $lb -Msg 0x186 -W ([IntPtr]0))                     # LB_SETCURSEL 0
    Send-VordrCommand -Window $v -Id $IDC_V_LIST -Notify 1 -LParam $lb -Sync          # LBN_SELCHANGE
    Start-Sleep -Milliseconds 500
    Check ((Read-VordrGlobal -Process $p -Map $map -Symbol 'g_cur_idx') -ge 0) 'an entry is shown'
    Check ((Read-VordrGlobal -Process $p -Map $map -Symbol 'g_cur_trunc') -eq 0) 'a seeded entry loads complete (g_cur_trunc = 0)'

    # ---- the entry list's drawn scrollbar ---------------------------------------
    $G = { param($s) Read-VordrGlobal -Process $p -Map $map -Symbol $s }
    $style = [int](Send-VordrMessage -Hwnd $lb -Msg 0 -W ([IntPtr]0))                    # (keep $lb warm)
    $gwl = Add-Type -PassThru -Name GwlS -Namespace VordrT -MemberDefinition '[DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int i);'
    Check ((([VordrT.GwlS]::GetWindowLongW($lb, -16)) -band 0x00200000) -eq 0) 'the list has no native scrollbar (WS_VSCROLL off)'
    $top = { [int](Send-VordrMessage -Hwnd $lb -Msg 0x18E) }                            # LB_GETTOPINDEX
    [void](Send-VordrMessage -Hwnd $lb -Msg 0x197 -W ([IntPtr]0))                       # LB_SETTOPINDEX 0
    [void](Send-VordrMessage -Hwnd $lb -Msg 0x000F)                                     # (drain a paint)
    Start-Sleep -Milliseconds 300
    [VordrGui.Native]::PostMessageW($lb, 0x000F, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    $thh = & $G 'g_lbsb_thh'
    Check ($thh -ge 28) ("5000 entries overflow the list: a thumb of {0}px (min 28)" -f $thh)
    $t0 = & $top; $y0 = & $G 'g_lbsb_thy'
    $wheelDown = [IntPtr]([int64](0xFF88) -shl 16)                                     # delta -120: toward the user
    [void](Send-VordrMessage -Hwnd $lb -Msg 0x020A -W $wheelDown)
    $t1 = & $top
    Check ($t1 -eq $t0 + 3) ("one wheel notch scrolls 3 cards ({0} -> {1})" -f $t0, $t1)
    [void](Send-VordrMessage -Hwnd $lb -Msg 0x197 -W ([IntPtr]2500))                    # middle of the list
    Start-Sleep -Milliseconds 300
    $null = & $G 'g_lbsb_thy'
    $cr = Get-VordrRect $lb -Client
    $wr = Get-VordrRect $lb
    # make the subclass recompute (it does on every paint) and read the geometry back
    [void](Send-VordrMessage -Hwnd $lb -Msg 0x020A -W ([IntPtr]0))
    $vis = & $G 'g_lbsb_vis'; $thy = & $G 'g_lbsb_thy'; $thh = & $G 'g_lbsb_thh'
    Check ($thy -gt $y0) ("the thumb moved down with the list ({0} -> {1})" -f $y0, $thy)
    # page-click below the thumb (client coordinates, inside the hot strip)
    $tb = & $top
    $x = $cr.R - 5; $yb = [Math]::Min($cr.B - 2, $thy + $thh + 10)
    $lp = [IntPtr]([int64]((($yb -band 0xFFFF) -shl 16) -bor ($x -band 0xFFFF)))
    [void](Send-VordrMessage -Hwnd $lb -Msg 0x0201 -W ([IntPtr]1) -L $lp)
    [void](Send-VordrMessage -Hwnd $lb -Msg 0x0202 -L $lp)
    $ta = & $top
    Check ($ta -eq $tb + $vis) ("a click below the thumb pages down one view ({0} -> {1}, {2} per page)" -f $tb, $ta, $vis)
    Check ((& $G 'g_cur_idx') -ge 0 -and (& $G 'g_lbsb_track') -eq 0) 'the click went to the bar, not a card drag'
    # drag the thumb 60px down (real cursor: the drag reads GetCursorPos)
    Add-Type -AssemblyName System.Windows.Forms
    $saved = [Windows.Forms.Cursor]::Position
    try {
        [void](Send-VordrMessage -Hwnd $lb -Msg 0x020A -W ([IntPtr]0))
        $thy = & $G 'g_lbsb_thy'; $thh = & $G 'g_lbsb_thh'
        $cy = $thy + [int]($thh / 2)
        [void][VordrGui.Native]::SetCursorPos($wr.L + $x, $wr.T + $cy)
        $lp = [IntPtr]([int64]((($cy -band 0xFFFF) -shl 16) -bor ($x -band 0xFFFF)))
        $td = & $top
        [void](Send-VordrMessage -Hwnd $lb -Msg 0x0201 -W ([IntPtr]1) -L $lp)
        Check ((& $G 'g_lbsb_track') -eq 1) 'pressing on the thumb starts a drag'
        [void][VordrGui.Native]::SetCursorPos($wr.L + $x, $wr.T + $cy + 60)
        [void](Send-VordrMessage -Hwnd $lb -Msg 0x0200 -W ([IntPtr]1) -L $lp)
        $tm = & $top
        Check ($tm -gt $td) ("dragging the thumb down scrolls the list ({0} -> {1})" -f $td, $tm)
        [void](Send-VordrMessage -Hwnd $lb -Msg 0x0202 -L $lp)
        Check ((& $G 'g_lbsb_track') -eq 0) 'releasing ends the drag'
        # hovering the strip widens the thumb; leaving narrows it
        [void][VordrGui.Native]::SetCursorPos($wr.L + $x, $wr.T + 20)
        [void](Send-VordrMessage -Hwnd $lb -Msg 0x0200 -L ([IntPtr](20 * 65536 + $x)))
        Check ((& $G 'g_lbsb_hover') -eq 1) 'the pointer over the strip marks it hovered'
        [void][VordrGui.Native]::SetCursorPos($wr.L + 30, $wr.T + 20)
        [void](Send-VordrMessage -Hwnd $lb -Msg 0x0200 -L ([IntPtr](20 * 65536 + 30)))
        Check ((& $G 'g_lbsb_hover') -eq 0) 'moving off the strip clears the hover'
    } finally { [Windows.Forms.Cursor]::Position = $saved }
    # the thumb actually reaches the screen: a pixel inside it differs from the same
    # column outside it (drawing can be silently discarded - Myrkr measured exactly that)
    [void](Send-VordrMessage -Hwnd $lb -Msg 0x197 -W ([IntPtr]0))
    Start-Sleep -Milliseconds 400
    [void](Send-VordrMessage -Hwnd $lb -Msg 0x020A -W ([IntPtr]0))
    $thy = & $G 'g_lbsb_thy'; $thh = & $G 'g_lbsb_thh'
    $px = $cr.R - 3 - 2                                     # inside the 3px idle thumb
    $dc = [VordrGui.Native]::GetDC($lb)
    $in  = [VordrGui.Native]::GetPixel($dc, $px, $thy + [int]($thh / 2))
    $out = [VordrGui.Native]::GetPixel($dc, $px, [Math]::Min($cr.B - 4, $thy + $thh + 40))
    [void][VordrGui.Native]::ReleaseDC($lb, $dc)
    if ($in -eq 0xFFFFFFFF -or $out -eq 0xFFFFFFFF) { Write-Host '  (thumb pixel check skipped: the window is not on screen)' }
    else { Check ($in -ne $out) ("the thumb is drawn on screen (0x{0:X6} inside vs 0x{1:X6} below)" -f $in, $out) }

    # ---- no GDI/USER handle leak from the thumb (a region + a DC every paint) -----
    Add-Type -Name Gr -Namespace VordrT -MemberDefinition '[DllImport("user32.dll")] public static extern uint GetGuiResources(IntPtr p, uint f);'
    [void](Send-VordrMessage -Hwnd $lb -Msg 0x197 -W ([IntPtr]100))
    Start-Sleep -Milliseconds 300
    $gdi0 = [VordrT.Gr]::GetGuiResources($p.Handle, 0); $usr0 = [VordrT.Gr]::GetGuiResources($p.Handle, 1)
    for ($k = 0; $k -lt 300; $k++) {
        $d = if ($k % 2) { 0x78 } else { 0xFF88 }                                        # up / down
        [void](Send-VordrMessage -Hwnd $lb -Msg 0x020A -W ([IntPtr]([int64]$d -shl 16)))
        [void][VordrGui.Native]::RedrawWindow($lb, [IntPtr]::Zero, [IntPtr]::Zero, 0x0101)  # INVALIDATE|UPDATENOW
    }
    Start-Sleep -Milliseconds 300
    $gdi1 = [VordrT.Gr]::GetGuiResources($p.Handle, 0); $usr1 = [VordrT.Gr]::GetGuiResources($p.Handle, 1)
    Check (($gdi1 - $gdi0) -le 4 -and ($usr1 - $usr0) -le 4) ("300 scroll+paint cycles leak no GDI/USER objects (GDI {0} -> {1}, USER {2} -> {3})" -f $gdi0, $gdi1, $usr0, $usr1)

    # ---- the export checklist (a report ListView) has the same drawn bar --------
    Send-VordrCommand -Window $v -Id 245                                                # IDC_V_MEXPORT
    $sel = Wait-VordrOwned -Process $p -Owner $v -TimeoutMs 8000
    Check ($sel -ne [IntPtr]::Zero) 'the export checklist opens'
    if ($sel -ne [IntPtr]::Zero) {
        $lv = Get-VordrControl -Window $sel -Id 752
        Start-Sleep -Milliseconds 500
        Check ((([VordrT.GwlS]::GetWindowLongW($lv, -16)) -band 0x00200000) -eq 0) 'the checklist has no native scrollbar'
        $lt0 = [int](Send-VordrMessage -Hwnd $lv -Msg 0x1027)                          # LVM_GETTOPINDEX
        [void](Send-VordrMessage -Hwnd $lv -Msg 0x020A -W ([IntPtr]([int64](0xFF88) -shl 16)))
        $lt1 = [int](Send-VordrMessage -Hwnd $lv -Msg 0x1027)
        Check ($lt1 -eq $lt0 + 3) ("one wheel notch scrolls the checklist 3 rows ({0} -> {1})" -f $lt0, $lt1)
        Check ((& $G 'g_lbsb_thh') -ge 28 -and (& $G 'g_lbsb_kind') -eq 1) 'the checklist has a thumb (ListView mode)'
        if ($env:VORDR_GUITEST_SHOTS) {
            Add-Type -AssemblyName System.Drawing
            $r = Get-VordrRect $sel; $bmp = New-Object Drawing.Bitmap ($r.R - $r.L), ($r.B - $r.T)
            $gr = [Drawing.Graphics]::FromImage($bmp); $gr.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
            $bmp.Save((Join-Path $env:VORDR_GUITEST_SHOTS 'checklist.png')); $gr.Dispose(); $bmp.Dispose()
        }
        Send-VordrCommand -Window $sel -Id 2                                            # IDCANCEL
        Check (Wait-VordrGone -Hwnd $sel -TimeoutMs 5000) 'cancelling closes the checklist'
        Start-Sleep -Milliseconds 300
    }

    # ---- a lock while a Vordr modal is open closes the modal, then locks -------
    $before = (Get-Item $vault).LastWriteTimeUtc
    Send-VordrCommand -Window $v -Id $IDC_V_REMOVE                                     # "move to trash?" box
    $box = Wait-VordrOwned -Process $p -Owner $v -TimeoutMs 5000
    Check ($box -ne [IntPtr]::Zero) 'the trash confirmation box is up'
    Send-VordrCommand -Window $v -Id $IDC_V_LOCK                                       # Ctrl+L / hotkey path
    Check (Wait-VordrGone -Hwnd $box -TimeoutMs 5000) 'locking closed the open confirmation box'
    Check (Wait-VordrGone -Hwnd $v -TimeoutMs 5000) 'and the vault window locked'
    Check (-not $p.HasExited) 'the process is still running (no crash on lock-with-modal)'
    Start-Sleep -Milliseconds 500
    Check ((Get-Item $vault).LastWriteTimeUtc -eq $before) 'the cancelled confirmation trashed nothing (vault file unchanged)'

    # ---- what lock leaves behind ---------------------------------------------
    foreach ($sym in @('g_pworig', 'g_conv_w', 'g_valblob', 'g_tilefiles', 'g_secret_w')) {
        $b = Read-VordrGlobal -Process $p -Map $map -Symbol $sym -Size 256
        Check ($null -ne $b -and -not ($b | Where-Object { $_ -ne 0 })) "$sym is zero after lock"
    }
    Check ((Read-VordrGlobal -Process $p -Map $map -Symbol 'g_body_ptr' -Size 8) -eq 0) 'no decrypted body after lock'

    # ---- and it unlocks again cleanly ------------------------------------------
    $u2 = Open-Unlock $p
    Check ($null -ne $u2 -and $u2 -ne [IntPtr]::Zero) 'the unlock window comes back after a lock'
    if ($u2) {
        $v2 = Unlock $p $u2
        Check ($v2 -ne [IntPtr]::Zero) 'a second unlock opens the vault again'
        Check ((Read-VordrGlobal -Process $p -Map $map -Symbol 'g_lock_tries') -eq 0) 'the lock retry counter was reset'
        if ($v2 -ne [IntPtr]::Zero) { Send-VordrCommand -Window $v2 -Id $IDC_V_LOCK; [void](Wait-VordrGone -Hwnd $v2) }
    }
    Stop-VordrTest -Process $p -Name $name; $p = $null

    # ---- the detail pane scrolls a card at a time, with the same drawn thumb ------
    $big = Join-Path $work 'big.vault'
    $rc = Invoke-VordrCli -Exe $Exe -Arguments @('seedbig', $big)
    Check ($rc -eq 0) 'seedbig wrote a vault with one 40-field entry'
    $p = Start-VordrTest -Exe $Exe -Vault $big -Name $name
    $ub = Open-Unlock $p
    $vb = if ($ub) { Unlock $p $ub } else { [IntPtr]::Zero }
    Check ($vb -ne [IntPtr]::Zero) 'the 40-field vault opens'
    if ($vb -ne [IntPtr]::Zero) {
        $G = { param($s) Read-VordrGlobal -Process $p -Map $map -Symbol $s }
        $lbb = Get-VordrControl -Window $vb -Id $IDC_V_LIST
        [void](Send-VordrMessage -Hwnd $lbb -Msg 0x186 -W ([IntPtr]0))
        Send-VordrCommand -Window $vb -Id $IDC_V_LIST -Notify 1 -LParam $lbb -Sync
        Start-Sleep -Milliseconds 500
        $tops = & $G 'g_page_count'; $last0 = & $G 'g_dsb_lastvis'
        Check ((& $G 'g_cur_page') -eq 0 -and $tops -gt 1 -and $last0 -ge 0 -and $last0 -lt 39) ("40 cards do not fit: rows 0..{0} show, {1} top positions" -f $last0, $tops)
        Check ((& $G 'g_dsb_thh') -ge 28) 'the pane has a thumb'
        $wr = Get-VordrRect $vb
        $sp = { param($x, $y) [IntPtr]([int64]((($y -band 0xFFFF) -shl 16) -bor ($x -band 0xFFFF))) }
        $pane = & $sp ($wr.L + 600) ($wr.T + 300)                                       # a screen point over the pane
        $down1 = [IntPtr]([int64](0xFF88) -shl 16)
        [void](Send-VordrMessage -Hwnd $vb -Msg 0x020A -W $down1 -L $pane)
        Check ((& $G 'g_cur_page') -eq 1) 'one wheel notch over the pane scrolls one card'
        $side = & $sp ($wr.L + 150) ($wr.T + 300)                                       # over the sidebar
        [void](Send-VordrMessage -Hwnd $vb -Msg 0x020A -W $down1 -L $side)
        Check ((& $G 'g_cur_page') -eq 1) 'the wheel over the sidebar does not scroll the pane'
        # a real mouse reaches the strip only if the window's hit test calls it CLIENT
        # (the custom frame calls every other empty pixel caption, for dragging) -
        # sending WM_LBUTTONDOWN straight to the window skips that, so ask it directly
        $cr = & $G 'g_dsb_cardr'; $thy = & $G 'g_dsb_thy'
        $ht = [int](Send-VordrMessage -Hwnd $vb -Msg 0x0084 -L (& $sp ($wr.L + 1 + $cr + 8) ($wr.T + 1 + $thy + 5)))
        Check ($ht -eq 1) ("the thumb strip hit-tests as client, so a real press reaches it (got {0})" -f $ht)
        $ht2 = [int](Send-VordrMessage -Hwnd $vb -Msg 0x0084 -L (& $sp ($wr.L + 1 + $cr + 8) ($wr.T + 12)))
        Check ($ht2 -eq 2) ("empty space above it still drags the window (caption, got {0})" -f $ht2)
        # a touchpad's small deltas add up to a card, not a card each
        $t0 = & $G 'g_cur_page'
        $small = [IntPtr]([int64](0xFFD8) -shl 16)                                      # -40
        [void](Send-VordrMessage -Hwnd $vb -Msg 0x020A -W $small -L $pane)
        [void](Send-VordrMessage -Hwnd $vb -Msg 0x020A -W $small -L $pane)
        $t1 = & $G 'g_cur_page'
        [void](Send-VordrMessage -Hwnd $vb -Msg 0x020A -W $small -L $pane)
        $t2 = & $G 'g_cur_page'
        Check ($t1 -eq $t0 -and $t2 -eq $t0 + 1) ("three 40-unit wheel deltas make one card ({0} -> {1} -> {2})" -f $t0, $t1, $t2)
        # page down: a click in the strip below the thumb
        $cr = & $G 'g_dsb_cardr'; $thy = & $G 'g_dsb_thy'; $thh = & $G 'g_dsb_thh'; $lv = & $G 'g_dsb_lastvis'
        $click = & $sp ($cr + 8) ($thy + $thh + 12)
        [void](Send-VordrMessage -Hwnd $vb -Msg 0x0201 -W ([IntPtr]1) -L $click)
        [void](Send-VordrMessage -Hwnd $vb -Msg 0x0202 -L $click)
        $tpd = & $G 'g_cur_page'
        Check ($tpd -eq $lv + 1) ("a click below the thumb pages to the first card that was off screen (top {0})" -f $tpd)
        # page up: a click above the thumb moves back by the cards on screen now
        $thy = & $G 'g_dsb_thy'; $lv2 = & $G 'g_dsb_lastvis'
        $want = [Math]::Max(0, $tpd - ($lv2 - $tpd + 1))
        $click = & $sp ($cr + 8) ([Math]::Max((& $G 'g_dsb_t') + 1, $thy - 4))
        [void](Send-VordrMessage -Hwnd $vb -Msg 0x0201 -W ([IntPtr]1) -L $click)
        [void](Send-VordrMessage -Hwnd $vb -Msg 0x0202 -L $click)
        Check ((& $G 'g_cur_page') -eq $want) ("a click above the thumb pages back by a screen of cards ({0} -> {1}, want {2})" -f $tpd, (& $G 'g_cur_page'), $want)
        # drag the thumb 60px down (real cursor; restored)
        Add-Type -AssemblyName System.Windows.Forms
        $saved = [Windows.Forms.Cursor]::Position
        try {
            $thy = & $G 'g_dsb_thy'; $thh = & $G 'g_dsb_thh'; $t0 = & $G 'g_cur_page'
            $cy = $thy + [int]($thh / 2); $cx = $cr + 8
            [void][VordrGui.Native]::SetCursorPos($wr.L + 1 + $cx, $wr.T + 1 + $cy)
            [void](Send-VordrMessage -Hwnd $vb -Msg 0x0201 -W ([IntPtr]1) -L (& $sp $cx $cy))
            Check ((& $G 'g_dsb_track') -eq 1) 'pressing the pane thumb starts a drag'
            [void][VordrGui.Native]::SetCursorPos($wr.L + 1 + $cx, $wr.T + 1 + $cy + 60)
            [void](Send-VordrMessage -Hwnd $vb -Msg 0x0200 -W ([IntPtr]1) -L (& $sp $cx ($cy + 60)))
            Check ((& $G 'g_cur_page') -gt $t0) ("dragging it scrolls the pane ({0} -> {1})" -f $t0, (& $G 'g_cur_page'))
            [void](Send-VordrMessage -Hwnd $vb -Msg 0x0202 -L (& $sp $cx ($cy + 60)))
            Check ((& $G 'g_dsb_track') -eq 0) 'releasing ends the drag'
            # -Slow: a REAL press, through the window's own hit test (the messages above
            # skip it - that is how a strip the frame called caption went unnoticed)
            if ($Slow) {
                if (-not ('VordrT.Mi' -as [type])) {
                    Add-Type -Name Mi -Namespace VordrT -MemberDefinition @'
[DllImport("user32.dll")] public static extern void mouse_event(uint f, int dx, int dy, uint d, IntPtr e);
[DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(long pt);
'@
                }
                $thy = & $G 'g_dsb_thy'; $thh = & $G 'g_dsb_thh'
                $sx = $wr.L + 1 + $cx; $sy = $wr.T + 1 + $thy + [int]($thh / 2)
                [void][VordrGui.Native]::SetCursorPos($sx, $sy); Start-Sleep -Milliseconds 150
                $under = [VordrT.Mi]::WindowFromPoint(([int64]$sy -shl 32) -bor [uint32]$sx)
                if ($under -ne $vb) { Write-Host '  (real-mouse thumb press skipped: another window covers it)' }
                else {
                    [VordrT.Mi]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero); Start-Sleep -Milliseconds 200
                    $tr = & $G 'g_dsb_track'
                    [VordrT.Mi]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero); Start-Sleep -Milliseconds 200
                    Check ($tr -eq 1) 'a real mouse press on the pane thumb starts a drag (not a window move)'
                    Check ((& $G 'g_dsb_track') -eq 0) 'and the real release ends it'
                }
            }
        } finally { [Windows.Forms.Cursor]::Position = $saved }
        # Tab into a card above the screen brings it back (EN_SETFOCUS from row 0)
        $id0 = 3000 + 0 * 16 + 1                                                        # IDC_DYN_BASE + row*DYN_SLOTS + DS_VALUE
        $ed0 = Get-VordrControl -Window $vb -Id $id0
        Send-VordrCommand -Window $vb -Id $id0 -Notify 0x100 -LParam $ed0 -Sync
        Check ((& $G 'g_cur_page') -eq 0) 'focus moving to a card above the screen scrolls it into view'
        # to the end: the last card shows, and the thumb is drawn on screen
        $gdi0 = [VordrT.Gr]::GetGuiResources($p.Handle, 0)
        for ($k = 0; $k -lt 80; $k++) { [void](Send-VordrMessage -Hwnd $vb -Msg 0x020A -W $down1 -L $pane) }
        Start-Sleep -Milliseconds 300
        Check ((& $G 'g_cur_page') -eq $tops - 1 -and (& $G 'g_dsb_lastvis') -eq 39) 'scrolled to the end, the last card (40th) is on screen'
        $gdi1 = [VordrT.Gr]::GetGuiResources($p.Handle, 0)
        Check (($gdi1 - $gdi0) -le 4) ("80 pane scrolls leak no GDI objects ({0} -> {1})" -f $gdi0, $gdi1)
        [void][VordrGui.Native]::RedrawWindow($vb, [IntPtr]::Zero, [IntPtr]::Zero, 0x0185)
        Start-Sleep -Milliseconds 300
        $thy = & $G 'g_dsb_thy'; $thh = & $G 'g_dsb_thh'
        $dc = [VordrGui.Native]::GetDC($vb)
        $in  = [VordrGui.Native]::GetPixel($dc, $cr + 7, $thy + [int]($thh / 2))
        $out = [VordrGui.Native]::GetPixel($dc, $cr + 7, [Math]::Max((& $G 'g_dsb_t') + 2, $thy - 20))
        [void][VordrGui.Native]::ReleaseDC($vb, $dc)
        if ($in -eq 0xFFFFFFFF -or $out -eq 0xFFFFFFFF) { Write-Host '  (pane thumb pixel check skipped: the window is not on screen)' }
        else { Check ($in -ne $out) ("the pane thumb is drawn on screen (0x{0:X6} inside vs 0x{1:X6} above)" -f $in, $out) }
        $pgbar = @(267, 268, 269) | ForEach-Object { Get-VordrControl -Window $vb -Id $_ } | Where-Object { $_ -ne [IntPtr]::Zero }
        Check ($pgbar.Count -eq 3 -and -not ($pgbar | Where-Object { [VordrGui.Native]::IsWindowVisible($_) })) 'the "< n / m >" page bar stays hidden: the pane scrolls instead'
    }
    Stop-VordrTest -Process $p -Name $name; $p = $null

    # ---- -Slow: the IDLE lock with a dialog open (the original bug's path) -----
    if ($Slow) {
        Add-Type -Name Lii -Namespace VordrT -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)] public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
[DllImport("user32.dll")] public static extern bool GetLastInputInfo(ref LASTINPUTINFO l);
public static uint Last() { var l = new LASTINPUTINFO(); l.cbSize = 8; GetLastInputInfo(ref l); return l.dwTime; }
'@
        $p = Start-VordrTest -Exe $Exe -Vault $vault -Name $name -Prefs @{ IdleLockMin = 1 }
        $u3 = Open-Unlock $p
        $v3 = if ($u3) { Unlock $p $u3 } else { [IntPtr]::Zero }
        if ($v3 -eq [IntPtr]::Zero) { Check $false 'slow: the vault opens with IdleLockMin = 1' }
        else {
            $lb3 = Get-VordrControl -Window $v3 -Id $IDC_V_LIST                       # Remove needs an entry
            [void](Send-VordrMessage -Hwnd $lb3 -Msg 0x186 -W ([IntPtr]0))
            Send-VordrCommand -Window $v3 -Id $IDC_V_LIST -Notify 1 -LParam $lb3 -Sync
            Start-Sleep -Milliseconds 400
            Send-VordrCommand -Window $v3 -Id $IDC_V_REMOVE
            $box3 = Wait-VordrOwned -Process $p -Owner $v3 -TimeoutMs 5000
            Check ($box3 -ne [IntPtr]::Zero) 'slow: a confirmation box is up'
            if ($box3 -eq [IntPtr]::Zero) { throw 'slow: no box to lock over - the rest would prove nothing' }
            $in0 = [VordrT.Lii]::Last()
            Write-Host '  (waiting up to 100 s for the idle lock - do not touch the keyboard or mouse)'
            $gone = Wait-VordrGone -Hwnd $v3 -TimeoutMs 100000
            if ([VordrT.Lii]::Last() -ne $in0 -and -not $gone) {
                Write-Host '  SKIP slow: someone used the machine while it waited, so it never went idle'
            } else {
                Check $gone 'slow: the idle lock fired with the box open (it used to skip every tick)'
                Check (Wait-VordrGone -Hwnd $box3 -TimeoutMs 2000) 'slow: and closed the box'
            }
        }
    }
}
finally {
    Stop-VordrTest -Process $p -Name $name
    Remove-Item -Recurse -Force $work -EA SilentlyContinue
}

Write-Host ""
if ($script:fails -eq 0) { Write-Host "guitest: PASS ($($script:oks) checks)"; exit 0 }
Write-Host "guitest: $($script:fails) FAILURE(S) of $($script:oks + $script:fails)"
exit 1
