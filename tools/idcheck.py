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

def parse_asm(path):
    ids = {}
    for l in open(path, encoding='latin-1'):
        m = RE_EQU.match(strip_asm_comment(l.rstrip('\n')))
        if not m or not RE_IDFAM.match(m.group(1)): continue
        v = parse_int(m.group(2))
        if v is None: continue          # non-literal equ (expression) - skip
        ids.setdefault(m.group(1), v)
    return ids

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rc",  default=DEF_RC)
    ap.add_argument("--asm", default=DEF_ASM, dest="asm")
    args = ap.parse_args()
    rc_ids  = parse_rc(args.rc)
    asm_ids = parse_asm(args.asm)

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
          f"{dups} duplicate id(s); "
          f"{len(rc_only)} rc-only, {len(asm_only)} asm-only (informational)")
    sys.exit(min(mismatches, 255))

if __name__ == "__main__":
    main()
