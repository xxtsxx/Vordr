#!/usr/bin/env python3
"""dlgtarget - does every dialog-item call name the window its control lives in?

Win32's per-id APIs fail SILENTLY when the id is not in the window handed to them:
SetDlgItemTextW returns FALSE, GetDlgItemInt returns 0, GetDlgItem returns NULL.
Nothing in the assembler, the linker or the other gates notices, and the symptom
surfaces later as "the label never updates" or "the setting doesn't stick".

That became acute when the settings screen moved out of DLG_VAULT into a WS_CHILD
DLG_SETTINGS: 34 controls changed window, and every call still aimed at the vault
kept building cleanly.  Ten such bugs were found by hand or by this script; the
worst was InvalidateRect(GetDlgItem(vault, <settings id>), ...), because
InvalidateRect(NULL) does not no-op - it repaints EVERY window on the desktop, so
the control refreshed anyway and the miss was invisible on screen.

Method: the rc says which dialog each IDC_* belongs to; gui.asm says which hwnd each
call targets.  Where both are statically known, they must agree.

Two call shapes are recognised:
    WINCALL SetDlgItemTextW, <hwnd>, IDC_FOO, ...
    mov rcx, <hwnd> / mov edx, IDC_FOO / call GetDlgItem

Only hwnd expressions naming a known global (g_settings_hwnd, g_vaulthwnd) can be
attributed.  A settings-only id reached through an unattributable hwnd (a local such
as [rbp-8]) is reported separately: it is not provably wrong, but it is exactly the
shape all ten bugs had, so it is worth a human look.

Exit code: number of mismatches (so "build strict" can gate on it).
Usage: python tools/dlgtarget.py [--rc PATH] [--asm PATH] [--strict-unknown]
"""
import re, os, sys, argparse, collections

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_RC  = os.path.normpath(os.path.join(HERE, "..", "vordr.rc"))
DEF_ASM = os.path.normpath(os.path.join(HERE, "..", "src", "gui.asm"))

# hwnd globals we can attribute to a dialog.  Anything else is "unknown".
HWND_GLOBALS = [("g_settings_hwnd", "DLG_SETTINGS"), ("g_vaulthwnd", "DLG_VAULT")]

DLG_API = re.compile(r'^(SetDlgItemTextW|SetDlgItemInt|GetDlgItemTextW|GetDlgItemInt|'
                     r'GetDlgItem|CheckDlgButton|IsDlgButtonChecked|SendDlgItemMessageW)$')


def parse_rc(path):
    """-> {IDC_name: {DLG_name, ...}} from the dialog templates."""
    owner = collections.defaultdict(set)
    cur, depth = None, 0
    for line in open(path, encoding="latin-1"):
        s = line.strip()
        m = re.match(r'^(DLG_\w+)\s+DIALOGEX', s)
        if m:
            cur, depth = m.group(1), 0
            continue
        if cur is None:
            continue
        if s in ("{", "BEGIN"):
            depth += 1
            continue
        if s in ("}", "END"):
            depth -= 1
            if depth <= 0:
                cur = None
            continue
        if depth > 0:
            for idc in re.findall(r'\bIDC_\w+', s):
                owner[idc].add(cur)
    return owner


def classify_hwnd(expr):
    for name, dlg in HWND_GLOBALS:
        if name in expr:
            return dlg
    return None


def split_args(s):
    """comma-split at depth 0; <>, [] and () are MASM grouping."""
    out, buf, d = [], "", 0
    for c in s:
        if c in "<[(":
            d += 1
        elif c in ">])":
            d -= 1
        if c == "," and d == 0:
            out.append(buf)
            buf = ""
        else:
            buf += c
    out.append(buf)
    return [a.strip() for a in out if a.strip()]


def logical_lines(path):
    """Join MASM backslash continuations so one call is one line.  Comments stripped."""
    out, buf, start = [], "", 0
    for i, l in enumerate(open(path, encoding="latin-1").read().split("\n"), 1):
        code = l.split(";")[0].rstrip()
        if not buf:
            start = i
        if code.endswith("\\"):
            buf += code[:-1] + " "
            continue
        out.append((start, buf + code))
        buf = ""
    return out


# Any write to the register that is not the literal we are tracking invalidates it.
# Without this, `mov edx, eax` (a runtime id from dynid) leaves an IDC_* name from
# further up still "live" and the next GetDlgItem is judged against the wrong id -
# which is precisely the false positive this check reported on gui_pg_apply.
W_RDX = re.compile(r'^\s*\w+\s+(?:e|r)dx\s*,')
W_RCX = re.compile(r'^\s*\w+\s+(?:e|r)cx\s*,')
IS_CALL = re.compile(r'^\s*call\s+')


def parse_asm(path):
    """-> [(lineno, api, hwnd_expr, idc, text)] for every dialog-item call."""
    hits = []
    last_rcx = last_edx = None
    for ln, l in logical_lines(path):
        m_id = re.match(r'^\s*mov\s+edx\s*,\s*(IDC_\w+)\s*$', l)
        m_cx = re.match(r'^\s*mov\s+rcx\s*,\s*(.+?)\s*$', l)
        if m_id:
            last_edx = m_id.group(1)
        elif W_RDX.match(l):
            last_edx = None                      # edx now holds something else
        if m_cx:
            last_rcx = m_cx.group(1)
        elif W_RCX.match(l):
            last_rcx = None

        m = re.search(r'\bWINCALL\s+(\w+)\s*,(.*)$', l)
        if m and DLG_API.match(m.group(1)):
            args = split_args(m.group(2))
            if len(args) >= 2:
                ids = re.findall(r'\bIDC_\w+', args[1])
                if ids:
                    hits.append((ln, m.group(1), args[0], ids[0], l.strip()))
            continue
        m = re.match(r'^\s*call\s+(\w+)\s*$', l)
        if m and DLG_API.match(m.group(1)) and last_rcx and last_edx:
            hits.append((ln, m.group(1), last_rcx, last_edx, l.strip()))
        if IS_CALL.match(l):
            last_edx = last_rcx = None           # rcx/rdx are volatile across a call
    return hits


def check_table(path, owner, asmname):
    """The settings table (g_setrows) drives populate/save through ONE pair of calls, so
    per-call checking cannot see its ids - they arrive as data.  Check the data instead:
    every row must name a control that really is in DLG_SETTINGS, and no id twice.
    Without this, table-driving the calls would have silently blinded this gate."""
    src = open(path, encoding="latin-1").read()
    try:
        body = src[src.index("g_setrows label byte"):src.index("g_setrows_end")]
    except ValueError:
        return 0, 0
    rows = re.findall(r'^\s*dd\s+(IDC_\w+)\s*,\s*(SK_\w+)', body, re.M)
    bad, seen = 0, {}
    for idc, kind in rows:
        dlgs = owner.get(idc)
        if dlgs and "DLG_SETTINGS" not in dlgs:
            bad += 1
            print(f"[MISMATCH] {asmname}: g_setrows row {idc} ({kind}) - that control is "
                  f"in {'/'.join(sorted(dlgs))}, not DLG_SETTINGS; the settings loops "
                  f"would never find it")
        elif not dlgs:
            bad += 1
            print(f"[MISMATCH] {asmname}: g_setrows row {idc} ({kind}) - no such control "
                  f"in any dialog template")
        if idc in seen:
            bad += 1
            print(f"[MISMATCH] {asmname}: g_setrows lists {idc} twice")
        seen[idc] = kind
    return bad, len(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rc", default=DEF_RC)
    ap.add_argument("--asm", default=DEF_ASM, dest="asm")
    ap.add_argument("--strict-unknown", action="store_true",
                    help="also fail on settings-only ids reached via an unattributable hwnd")
    args = ap.parse_args()

    owner = parse_rc(args.rc)
    hits = parse_asm(args.asm)
    rcname = os.path.basename(args.rc)
    asmname = os.path.basename(args.asm)

    bad = unknown = ok = skipped = 0
    for ln, api, hwnd, idc, text in hits:
        dlgs = owner.get(idc)
        if not dlgs or len(dlgs) > 1:
            skipped += 1                          # asm-only id, or shared across dialogs
            continue
        want = next(iter(dlgs))
        got = classify_hwnd(hwnd)
        if got is None:
            if want == "DLG_SETTINGS":
                unknown += 1
                print(f"[?] {asmname}:{ln} {api}({hwnd}, {idc}) - {idc} lives only in "
                      f"{want}, but this hwnd is not statically known")
            else:
                skipped += 1
            continue
        if got != want:
            bad += 1
            print(f"[MISMATCH] {asmname}:{ln} {api}(<{got}>, {idc}) - {rcname} puts "
                  f"{idc} in {want}; this call targets the wrong window and will "
                  f"fail silently")
            print(f"           {text[:110]}")
        else:
            ok += 1

    tbad, trows = check_table(args.asm, owner, asmname)
    bad += tbad
    if args.strict_unknown:
        bad += unknown
    print(f"dlgtarget: {bad} mismatch(es), {unknown} unattributable, {ok} verified, "
          f"{skipped} not applicable across {len(hits)} dialog-item call(s); "
          f"{trows} settings-table row(s) checked "
          f"({'clean' if bad == 0 else 'WRONG-WINDOW CALL PRESENT'})")
    sys.exit(min(bad, 255))


if __name__ == "__main__":
    main()
