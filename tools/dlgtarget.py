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

Attribution used to require the hwnd to name a known global (g_settings_hwnd,
g_vaulthwnd).  Almost nothing does: a dialog proc gets its hwnd in rcx and saves it
to a local, and helpers take it as a parameter.  That left 122 of 135 calls
unattributable and only 2 actually verified - a gate in name only.  Two inferences
fix that without a hand-maintained list:

  * A DLGPROC's rcx IS its dialog's hwnd, and which proc serves which template is
    already written down in the DialogBoxParamW / CreateDialogParamW call sites.
    Reading the map off those calls means it cannot drift from the code.
  * A helper's hwnd parameter is whatever its callers pass.  Where EVERY call site
    passes an already-attributed hwnd and they all agree, the parameter inherits
    that dialog; disagreement or one unknown caller leaves it unattributed.

Both are conservative: they only ever add attribution where it is provable, and an
attribution that is wrong shows up as a loud mismatch, not as silence.

A settings-only id reached through a still-unattributable hwnd is reported
separately: it is not provably wrong, but it is exactly the shape all ten bugs
had, so it is worth a human look.

Exit code: number of mismatches (so "build strict" can gate on it).
Usage: python tools/dlgtarget.py [--rc PATH] [--asm PATH] [--strict-unknown]
"""
import re, os, sys, argparse, collections
import floors                            # coverage floors: see tools/floors.py

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


PROC_OPEN  = re.compile(r'^(\w+)\s+proc\b')
PROC_CLOSE = re.compile(r'^(\w+)\s+endp\b')
# the standard first-argument save at the top of a frame proc
ENTRY_SAVE = re.compile(r'^\s*mov\s+qword ptr \[(rbp-\d+)\]\s*,\s*rcx\s*$')
SLOT       = re.compile(r'\b(rbp-\d+)\b')
DLG_CREATE = re.compile(r'\bWINCALL\s+(?:DialogBoxParamW|CreateDialogParamW)\s*,(.*)$')


def dlgproc_map(lines):
    """{dlgproc name: DLG_*} read off the DialogBoxParamW/CreateDialogParamW sites.

    Derived, never hand-written: a new dialog is attributed the moment it is
    created, and renaming a proc cannot leave a stale entry behind.  A proc used
    for two templates is dropped rather than guessed at."""
    seen = collections.defaultdict(set)
    for ln, l in lines:
        m = DLG_CREATE.search(l)
        if not m:
            continue
        args = split_args(m.group(1))
        if len(args) < 4:
            continue
        tmpl = re.search(r'\bDLG_\w+', args[1])
        proc = re.search(r'addr\s+(\w+)', args[3])
        if tmpl and proc:
            seen[proc.group(1)].add(tmpl.group(0))
    return {p: next(iter(d)) for p, d in seen.items() if len(d) == 1}


def entry_slots(lines):
    """{proc: 'rbp-N'} - where each proc saves its first argument."""
    out, cur = {}, None
    for ln, l in lines:
        t = l.strip()
        m = PROC_OPEN.match(t)
        if m:
            cur = m.group(1)
            continue
        if PROC_CLOSE.match(t):
            cur = None
            continue
        if cur and cur not in out:
            m = ENTRY_SAVE.match(l)
            if m:
                out[cur] = m.group(1)
    return out


def call_sites(lines):
    """[(caller, callee, rcx expression at the call)] for plain `call foo`."""
    out, cur, last_rcx = [], None, None
    for ln, l in lines:
        t = l.strip()
        m = PROC_OPEN.match(t)
        if m:
            cur, last_rcx = m.group(1), None
            continue
        if PROC_CLOSE.match(t):
            cur = None
            continue
        m_cx = re.match(r'^\s*mov\s+rcx\s*,\s*(.+?)\s*$', l)
        if m_cx:
            last_rcx = m_cx.group(1)
        elif W_RCX.match(l):
            last_rcx = None
        m = re.match(r'^\s*call\s+(\w+)\s*$', t)
        if m:
            out.append((cur, m.group(1), last_rcx))
            last_rcx = None                      # rcx is volatile across the call
    return out


def attribute(lines):
    """{proc: {'rbp-N': DLG_*}} - which local, in which proc, holds which dialog.

    Seeded from the dialog procs, then propagated to helpers whose every caller
    agrees.  Iterated to a fixed point; four rounds is far more than the call
    graph is deep, and the loop stops early when nothing changes."""
    slots = entry_slots(lines)
    known = {}
    for proc, dlg in dlgproc_map(lines).items():
        if proc in slots:
            known[proc] = {slots[proc]: dlg}
    sites = call_sites(lines)
    for _ in range(4):
        grew = False
        implied = collections.defaultdict(set)
        for caller, callee, rcx in sites:
            if callee in known or callee not in slots:
                continue                          # already known, or takes no first arg
            if rcx is None:
                implied[callee].add(None)         # a caller we cannot read poisons it
                continue
            dlg = classify_hwnd(rcx)
            if dlg is None:
                m = SLOT.search(rcx)
                dlg = known.get(caller, {}).get(m.group(1)) if m else None
            implied[callee].add(dlg)
        for callee, dlgs in implied.items():
            if len(dlgs) == 1 and None not in dlgs:
                known[callee] = {slots[callee]: next(iter(dlgs))}
                grew = True
        if not grew:
            break
    return known


def classify_hwnd(expr, proc=None, known=None):
    for name, dlg in HWND_GLOBALS:
        if name in expr:
            return dlg
    if proc and known:
        m = SLOT.search(expr)
        if m:
            return known.get(proc, {}).get(m.group(1))
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


def parse_asm(path, lines=None):
    """-> [(lineno, api, hwnd_expr, idc, text, proc)] for every dialog-item call."""
    hits = []
    last_rcx = last_edx = None
    cur = None
    for ln, l in (lines if lines is not None else logical_lines(path)):
        t = l.strip()
        if PROC_OPEN.match(t):
            cur = PROC_OPEN.match(t).group(1)
        elif PROC_CLOSE.match(t):
            cur = None
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
                    hits.append((ln, m.group(1), args[0], ids[0], l.strip(), cur))
            continue
        m = re.match(r'^\s*call\s+(\w+)\s*$', l)
        if m and DLG_API.match(m.group(1)) and last_rcx and last_edx:
            hits.append((ln, m.group(1), last_rcx, last_edx, l.strip(), cur))
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
    lines = logical_lines(args.asm)
    known = attribute(lines)
    hits = parse_asm(args.asm, lines)
    rcname = os.path.basename(args.rc)
    asmname = os.path.basename(args.asm)

    bad = unknown = ok = skipped = 0
    for ln, api, hwnd, idc, text, proc in hits:
        dlgs = owner.get(idc)
        if not dlgs or len(dlgs) > 1:
            skipped += 1                          # asm-only id, or shared across dialogs
            continue
        want = next(iter(dlgs))
        got = classify_hwnd(hwnd, proc, known)
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
          f"{trows} settings-table row(s) checked; {len(known)} proc(s) attributed "
          f"({'clean' if bad == 0 else 'WRONG-WINDOW CALL PRESENT'})")
    bad += floors.check("dlgtarget", {"calls": len(hits), "verified": ok,
                                      "settings_rows": trows})
    sys.exit(min(bad, 255))


if __name__ == "__main__":
    main()
