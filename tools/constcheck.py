#!/usr/bin/env python3
"""constcheck - cross-module constant agreement gate for Vordr.

Some `equ` constants are deliberately mirrored in more than one module: Win32
values each file needs, and a few sizes that MUST match the module which actually
allocates the array.  Nothing enforced the second kind, and it drifted:

    main.asm     MAX_FIELDS equ 96      <- allocates g_field_list (dq 3*MAX_FIELDS)
    gui.asm      MAX_FIELDS equ 96
    zipimport.asm MAX_FIELDS equ 56     <- comment claimed "matches main.asm"

Imported entries silently lost every field past the 56th while the array had room
for 96.  Too small only loses data; too LARGE would have overrun the array.

So: any constant defined in more than one file must agree everywhere.  A name is
gated only when at least two files give it a literal value - a definition this
script cannot evaluate is skipped rather than guessed at, so a `equ` built from an
expression never produces a false conflict.

Values are parsed as decimal, 0x.. hex, or MASM trailing-h hex.  Simple integer
expressions over names already resolved IN THE SAME FILE are folded too (that is
how sizes like `8 + FMAC_MACLEN + 4` become comparable); anything else is left
unresolved and ignored.

Exit code: number of conflicting names, so `build strict` can gate on it.
Usage: python tools/constcheck.py [--src DIR]
"""
import re, os, sys, glob, argparse, collections

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_SRC = os.path.normpath(os.path.join(HERE, "..", "src"))

RE_EQU  = re.compile(r'^\s*([A-Za-z_][\w$]*)\s+equ\s+(.+?)\s*$', re.I)
# Only fold expressions built from names, integer literals, whitespace, the four
# operators and parens.  Anything with a register, string, or MASM operator in it is
# left alone rather than guessed at.
RE_SAFE = re.compile(r'^[\w\s$+\-*/()]+$')

def strip_comment(line):
    q = None; out = []
    for c in line:
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
    t = tok.strip()
    if re.fullmatch(r'\d+', t):                    return int(t)
    if re.fullmatch(r'0[xX][0-9A-Fa-f]+', t):      return int(t, 16)
    if re.fullmatch(r'[0-9][0-9A-Fa-f]*[hH]', t):  return int(t[:-1], 16)
    return None

def fold(expr, known):
    """Integer value of `expr` using same-file names in `known`, or None."""
    v = parse_int(expr)
    if v is not None:
        return v
    if not RE_SAFE.match(expr):
        return None
    # substitute known names; bail if any bare identifier is still unresolved
    def sub(m):
        return str(known[m.group(0)]) if m.group(0) in known else m.group(0)
    e = re.sub(r'[A-Za-z_][\w$]*', sub, expr)
    if re.search(r'[A-Za-z_$]', e):
        return None
    try:
        val = eval(e, {"__builtins__": {}}, {})       # digits and + - * / ( ) only
        return int(val) if isinstance(val, (int, float)) else None
    except Exception:
        return None

def parse_file(path):
    """-> {name: value} for every equ in `path` we can evaluate."""
    known, pending = {}, []
    for line in open(path, encoding='latin-1'):
        m = RE_EQU.match(strip_comment(line.rstrip('\n')))
        if not m: continue
        name, expr = m.group(1), m.group(2)
        v = fold(expr, known)
        if v is None:
            pending.append((name, expr))
        else:
            known.setdefault(name, v)
    # a couple of extra passes: definitions that referenced a later name
    for _ in range(3):
        if not pending: break
        again = []
        for name, expr in pending:
            v = fold(expr, known)
            if v is None: again.append((name, expr))
            else:         known.setdefault(name, v)
        if len(again) == len(pending): break
        pending = again
    return known

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=DEF_SRC)
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.src, "*.asm")) +
                   glob.glob(os.path.join(args.src, "*.inc")))
    if not files:
        print(f"constcheck: no sources under {args.src}")
        sys.exit(0)

    defs = collections.defaultdict(dict)
    for f in files:
        for name, v in parse_file(f).items():
            defs[name].setdefault(os.path.basename(f), v)

    shared    = {n: d for n, d in defs.items() if len(d) > 1}
    conflicts = {n: d for n, d in shared.items() if len(set(d.values())) > 1}

    for name in sorted(conflicts):
        where = ", ".join(f"{f}={v}" for f, v in sorted(conflicts[name].items()))
        print(f"[CONFLICT] {name} disagrees across modules: {where}")
    for name in sorted(shared):
        if name in conflicts: continue
        v = next(iter(shared[name].values()))
        print(f"[info] {name} = {v} mirrored in {', '.join(sorted(shared[name]))}")

    print(f"constcheck: {len(conflicts)} conflicting constant(s) across "
          f"{len(files)} files, {len(shared)} mirrored "
          f"({'clean' if not conflicts else 'CROSS-MODULE DRIFT'})")
    sys.exit(min(len(conflicts), 255))

if __name__ == "__main__":
    main()
