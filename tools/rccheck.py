#!/usr/bin/env python3
"""rccheck - dialog-template geometry: overlaps, escapes and collapses.

The bugs this project keeps finding by eye are layout bugs, and they are found by
eye because nothing else looks: a header static sized so it covered the first
field row (the "dip"), a control left on top of another after a redesign, a
control moved without its old pixels being repainted.  Every one of those starts
as numbers in vordr.rc.

So: read the DIALOGEX templates and check the arithmetic.

  * a control that overlaps a sibling, unless the sibling is a declared container
    (GROUPBOX, or an id listed in CONTAINERS below - the owner-draw backdrops
    that are *supposed* to sit behind things)
  * a control that is not fully inside its dialog
  * a control with a zero or negative dimension - invisible, and usually a typo
  * two controls at exactly the same position and size, which is nearly always a
    copy-paste that never got moved

What it cannot see: anything computed at runtime.  MoveWindow, the anchor reflow
and the dock layout all happen later, and a template that is correct here can
still end up wrong on screen.  That is the other half of the job, and it belongs
to a runtime probe, not to this.

Exit code: number of findings (so "build strict" can gate on it).
Usage: python tools/rccheck.py [--rc PATH]
"""
import re, os, sys, argparse, collections
import floors                            # coverage floors: see tools/floors.py

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_RC = os.path.normpath(os.path.join(HERE, "..", "vordr.rc"))

# Controls that legitimately sit behind others: backdrops and strips, not widgets.
# Add to this only with a reason - every entry is a place the check stops looking,
# which is exactly how a gate goes quiet.
CONTAINERS = {
    "IDC_V_HEADER",      # the top strip the title/icon sit on
    "IDC_PR_PHON",       # owner-draw phonetic panel; IDOK is created later, so on top
}

# Pairs that overlap on purpose, each with the reason it is not a bug.  A pair
# here is EXACT: any new overlap, including a new pairing of these same ids with
# anything else, still fails.
#
# The DLG_VAULT entries are a different case from the rest and worth stating
# plainly: those controls are placed by gui_cmd_dock_layout at runtime, so their
# template coordinates are placeholders and their overlap here means nothing.
# That is also the limit of this tool - it can only check the numbers in the
# file, and for a dock-laid-out dialog those are not the numbers on screen.
ALLOW = {
    ("DLG_VAULT", "IDC_V_HDREDIT", "IDC_V_TITLE"),     # docked at runtime
    ("DLG_VAULT", "IDC_V_FAV",     "IDC_V_TITLE"),     # docked at runtime
    ("DLG_VAULT", "IDC_V_OVFL",    "IDC_V_TITLE"),     # docked at runtime
    # A settings label box is wider than its text so the info dot can sit just
    # after the words; the dot is inside the label's rect but never under glyphs.
    ("DLG_SETTINGS", "IDC_V_MTPML",    "IDC_V_MTPMINFO"),
    ("DLG_SETTINGS", "IDC_V_MSECDL",   "IDC_V_MSECINFO"),
    ("DLG_SETTINGS", "IDC_V_MNOPREVL", "IDC_V_MNOPREVINFO"),
    # Label box overhangs its edit by 4 units.  Cosmetic slack, not a collision:
    # the text is right-trimmed well before the edit begins.
    ("DLG_SETTINGS", "IDC_V_MCLIPL", "IDC_V_MCLIP"),
    ("DLG_SETTINGS", "IDC_V_MIDLEL", "IDC_V_MIDLE"),
    ("DLG_SETTINGS", "IDC_V_MPWDL",  "IDC_V_MPWD"),
}

# Statement forms.  Where the rect starts differs per keyword, so the keyword
# decides - taking "the first four integers" instead would mis-read a CONTROL
# whose style field happens to be numeric.
TEXT_ID_RECT = {"LTEXT", "RTEXT", "CTEXT", "PUSHBUTTON", "DEFPUSHBUTTON",
                "CHECKBOX", "RADIOBUTTON", "GROUPBOX", "ICON", "AUTOCHECKBOX",
                "AUTORADIOBUTTON", "AUTO3STATE", "STATE3"}
ID_RECT      = {"EDITTEXT", "LISTBOX", "COMBOBOX", "SCROLLBAR"}

DLG_HDR = re.compile(r'^(\w+)\s+DIALOGEX\s+(-?\d+)\s*,\s*(-?\d+)\s*,\s*(\d+)\s*,\s*(\d+)')


def split_args(s):
    out, buf, d = [], "", 0
    for c in s:
        if c in "([":
            d += 1
        elif c in ")]":
            d -= 1
        if c == "," and d == 0:
            out.append(buf.strip())
            buf = ""
        else:
            buf += c
    out.append(buf.strip())
    return out


def as_int(tok):
    tok = tok.strip()
    return int(tok) if re.fullmatch(r'-?\d+', tok) else None


def parse(path):
    """-> [(dlg, cx, cy, [(id, kind, x, y, w, h, line)])]"""
    dlgs, cur, controls, depth = [], None, [], 0
    pend = ""
    for ln, raw in enumerate(open(path, encoding="latin-1"), 1):
        line = raw.split("//")[0].rstrip()
        s = line.strip()
        if not s:
            continue
        m = DLG_HDR.match(s)
        if m:
            if cur:
                dlgs.append((cur[0], cur[1], cur[2], controls))
            cur = (m.group(1), int(m.group(4)), int(m.group(5)))
            controls, depth, pend = [], 0, ""
            continue
        if cur is None:
            continue
        if s in ("BEGIN", "{"):
            depth += 1
            continue
        if s in ("END", "}"):
            depth -= 1
            if depth <= 0:
                dlgs.append((cur[0], cur[1], cur[2], controls))
                cur, controls = None, []
            continue
        if depth <= 0:
            continue
        # a statement may be continued across lines with a trailing comma
        pend = (pend + " " + s).strip() if pend else s
        if pend.endswith(","):
            continue
        stmt, pend = pend, ""
        kw = stmt.split(None, 1)[0].upper()
        rest = stmt[len(kw):].strip()
        args = split_args(rest)
        if kw == "CONTROL":
            idx = 4                       # text, id, class, style, x, y, w, h
            idpos = 1
        elif kw in TEXT_ID_RECT:
            idx = 2                       # text, id, x, y, w, h
            idpos = 1
        elif kw in ID_RECT:
            idx = 1                       # id, x, y, w, h
            idpos = 0
        else:
            continue
        if len(args) < idx + 4:
            continue
        rect = [as_int(a) for a in args[idx:idx + 4]]
        if any(v is None for v in rect):
            continue
        cid = args[idpos].strip() if len(args) > idpos else "?"
        controls.append((cid, kw, rect[0], rect[1], rect[2], rect[3], ln))
    if cur:
        dlgs.append((cur[0], cur[1], cur[2], controls))
    return dlgs


def overlap(a, b):
    ax, ay, aw, ah = a[2], a[3], a[4], a[5]
    bx, by, bw, bh = b[2], b[3], b[4], b[5]
    ox = max(0, min(ax + aw, bx + bw) - max(ax, bx))
    oy = max(0, min(ay + ah, by + bh) - max(ay, by))
    return ox * oy


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rc", default=DEF_RC)
    ap.add_argument("--list-overlaps", action="store_true",
                    help="report every overlap, including containers (for curating CONTAINERS)")
    args = ap.parse_args()
    rcname = os.path.basename(args.rc)

    bad = 0
    n_dlg = n_ctl = 0
    for dlg, dcx, dcy, controls in parse(args.rc):
        n_dlg += 1
        n_ctl += len(controls)
        seen_rect = {}
        for c in controls:
            cid, kw, x, y, w, h, ln = c
            if w <= 0 or h <= 0:
                bad += 1
                print(f"[COLLAPSED] {rcname}:{ln} {dlg}/{cid} is {w}x{h} - invisible on screen")
            if x < 0 or y < 0 or x + w > dcx or y + h > dcy:
                bad += 1
                print(f"[ESCAPES] {rcname}:{ln} {dlg}/{cid} at ({x},{y}) {w}x{h} is outside "
                      f"the {dcx}x{dcy} dialog - the part past the edge is not drawn")
            key = (x, y, w, h)
            if key in seen_rect and kw != "GROUPBOX":
                bad += 1
                print(f"[DUPLICATE] {rcname}:{ln} {dlg}/{cid} sits exactly on "
                      f"{seen_rect[key]} - one of them was copied and never moved")
            seen_rect.setdefault(key, cid)

        for i, a in enumerate(controls):
            for b in controls[i + 1:]:
                if not overlap(a, b):
                    continue
                container = (a[1] == "GROUPBOX" or b[1] == "GROUPBOX"
                             or a[0] in CONTAINERS or b[0] in CONTAINERS
                             or (dlg, a[0], b[0]) in ALLOW
                             or (dlg, b[0], a[0]) in ALLOW)
                if container and not args.list_overlaps:
                    continue
                tag = "[overlap-ok]" if container else "[OVERLAP]"
                if not container:
                    bad += 1
                print(f"{tag} {rcname}:{b[6]} {dlg}/{a[0]} ({a[2]},{a[3]} {a[4]}x{a[5]}) and "
                      f"{dlg}/{b[0]} ({b[2]},{b[3]} {b[4]}x{b[5]}) overlap by "
                      f"{overlap(a, b)} dialog units")

    print(f"rccheck: {bad} finding(s) across {n_dlg} dialog(s), {n_ctl} control(s) "
          f"({'clean' if bad == 0 else 'LAYOUT PROBLEM PRESENT'})")
    bad += floors.check("rccheck", {"dialogs": n_dlg, "controls": n_ctl})
    sys.exit(min(bad, 255))


if __name__ == "__main__":
    main()
