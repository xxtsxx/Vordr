#!/usr/bin/env python3
"""idcheck - rc <-> asm control-ID sync gate for Vordr.

vordr.rc's header says its #define control IDs "MUST match the equ values in
src/gui.asm" - the dialog templates are compiled by rc.exe against the
#defines, while the window procs dispatch on hand-mirrored `equ`s, so a drift
between the two silently breaks a dialog.  This script parses both sides and
diffs them:

  - vordr.rc:      #define NAME value        (decimal or 0x.. hex)
  - src/gui.asm:   NAME equ value            (decimal, 0x.., or MASM ..h hex)

Only names present in BOTH files are gated: a value difference is a mismatch.
Names found on only one side are reported as informational (the rc side may
legitimately carry defines only the resource compiler references, and gui.asm
carries asm-only IDs such as IDC_DYN_BASE).  To keep that informational list
useful, only the mirrored ID families (DLG_*/IDC_*) are considered on the asm
side.

Exit code: number of mismatches (so "build strict" can gate on it).
Usage: python tools/idcheck.py [--rc PATH] [--asm PATH]
"""
import re, os, sys, argparse
import floors                            # coverage floors: see tools/floors.py

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_RC  = os.path.normpath(os.path.join(HERE, "..", "vordr.rc"))
DEF_ASM = os.path.normpath(os.path.join(HERE, "..", "src", "gui.asm"))

RE_DEFINE = re.compile(r'^\s*#define\s+([A-Za-z_]\w*)\s+(\S+)')
RE_EQU    = re.compile(r'^\s*([\w$]+)\s+equ\s+(.+?)\s*$', re.I)
RE_IDFAM  = re.compile(r'^(DLG_|IDC_)')

def strip_asm_comment(l):
    q = None; out = []
    for c in l:
        if q:
            out.append(c)
            if c == q: q = None
        elif c in "'\"":
            q = c; out.append(c)
        elif c == ';':
            break
        else:
            out.append(c)
    return ''.join(out)

def parse_int(tok):
    """Integer literal -> int or None: decimal, 0x.., or trailing-h hex (0FFh)."""
    t = tok.strip()
    if re.fullmatch(r'\d+', t): return int(t)
    if re.fullmatch(r'0[xX][0-9A-Fa-f]+', t): return int(t, 16)
    if re.fullmatch(r'[0-9][0-9A-Fa-f]*[hH]', t): return int(t[:-1], 16)
    return None

def parse_rc(path):
    ids = {}
    for ln, l in enumerate(open(path, encoding='latin-1'), 1):
        m = RE_DEFINE.match(l)
        if not m: continue
        v = parse_int(m.group(2))
        if v is None:
            print(f"[info] {os.path.basename(path)}:{ln} {m.group(1)}: "
                  f"unparseable value {m.group(2)!r} - skipped")
            continue
        ids.setdefault(m.group(1), v)
    return ids

def parse_asm(path, all_equs=None):
    """-> {IDC_*/DLG_*: value}.  If `all_equs` is given, every literal equ is also
    collected there - the range-span constants (GLYPHPAL_N, ...) are not ID names but
    are needed to know how wide a *_BASE range is."""
    ids = {}
    for l in open(path, encoding='latin-1'):
        m = RE_EQU.match(strip_asm_comment(l.rstrip('\n')))
        if not m: continue
        v = parse_int(m.group(2))
        if v is None: continue          # non-literal equ (expression) - skip
        if all_equs is not None:
            all_equs.setdefault(m.group(1), v)
        if RE_IDFAM.match(m.group(1)):
            ids.setdefault(m.group(1), v)
    return ids

# Control-id ranges carved out for runtime-created controls.  (base, span-constant);
# a span of None means open-ended (everything from base upward).  A scalar id landing
# inside one of these is the IDC_RM_TEXT=810-inside-IDC_IG_BASE(800..829) mistake:
# harmless while the two live in different dialogs, and silently wrong the moment they
# do not, because icon_proc dispatches these by RANGE rather than by name.
RESERVED_RANGES = [
    ("IDC_IG_BASE",  "GLYPHPAL_N"),
    ("IDC_IC_BASE",  "GLYPHCOL_N"),
    ("IDC_DYN_BASE", None),
]

def check_ranges(ids, equs):
    """-> number of ids that fall inside a reserved range."""
    bad = 0
    for base_name, span_name in RESERVED_RANGES:
        base = ids.get(base_name, equs.get(base_name))
        if base is None:
            continue
        span = None
        if span_name is not None:
            span = equs.get(span_name)
            if span is None:
                print(f"[info] {base_name}: span {span_name} unresolved - range not checked")
                continue
        hi = None if span is None else base + span - 1
        for name, v in sorted(ids.items()):
            if name == base_name or name.endswith("_BASE"):
                continue
            if v < base or (hi is not None and v > hi):
                continue
            where = f"{base}..{hi}" if hi is not None else f"{base}+"
            print(f"[IN-RANGE] {name} = {v} lies inside {base_name}'s reserved "
                  f"range ({where}) - that range is dispatched by value, not by name")
            bad += 1
    return bad

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rc",  default=DEF_RC)
    ap.add_argument("--asm", default=DEF_ASM, dest="asm")
    args = ap.parse_args()
    rc_ids  = parse_rc(args.rc)
    asm_equs = {}
    asm_ids = parse_asm(args.asm, asm_equs)

    mismatches = 0
    shared = 0
    for name in sorted(set(rc_ids) & set(asm_ids)):
        shared += 1
        if rc_ids[name] != asm_ids[name]:
            mismatches += 1
            print(f"[MISMATCH] {name}: {os.path.basename(args.rc)}={rc_ids[name]} "
                  f"vs {os.path.basename(args.asm)}={asm_ids[name]}")

    # --- two IDC_* names sharing one value --------------------------------------
    # Agreement between rc and asm is not enough: within a dialog, GetDlgItem(id)
    # returns only the FIRST control carrying that id, so a duplicate silently
    # half-works - one control responds and its twin can never be found, shown or
    # hidden.  IDC_V_MPWDL was given 267, already IDC_V_PGPREV's, and the settings
    # row it named could not be hidden and bled onto the main screen.
    # DLG_* are dialog-template ids and live in their own namespace, so only IDC_*
    # is gated here.  A few IDC_*_BASE values are deliberate range anchors.
    BASE_OK = re.compile(r'_BASE$')
    byval = {}
    for name, v in rc_ids.items():
        if not name.startswith("IDC_") or BASE_OK.search(name):
            continue
        byval.setdefault(v, []).append(name)
    dups = 0
    for v, names in sorted(byval.items()):
        if len(names) > 1:
            dups += 1
            mismatches += 1
            print(f"[DUPLICATE] id {v} used by {', '.join(sorted(names))} - "
                  f"GetDlgItem can only ever find the first of them")
    # ...and an id sitting inside a range reserved for runtime-created controls
    ranged = check_ranges({**rc_ids, **asm_ids}, asm_equs)
    mismatches += ranged

    rc_only  = sorted(set(rc_ids) - set(asm_ids))
    asm_only = sorted(set(asm_ids) - set(rc_ids))
    for name in rc_only:
        print(f"[info] {name}: only in {os.path.basename(args.rc)} "
              f"(= {rc_ids[name]}; resource-compiler-side, not gated)")
    for name in asm_only:
        print(f"[info] {name}: only in {os.path.basename(args.asm)} "
              f"(= {asm_ids[name]}; asm-side, not gated)")
    print(f"idcheck: {mismatches} mismatches across {shared} shared IDs "
          f"({'clean' if mismatches == 0 else 'ID DRIFT PRESENT'}); "
          f"{dups} duplicate id(s); {ranged} in reserved range(s); "
          f"{len(rc_only)} rc-only, {len(asm_only)} asm-only (informational)")
    mismatches += floors.check("idcheck", {"shared_ids": shared})
    sys.exit(min(mismatches, 255))

if __name__ == "__main__":
    main()
