#!/usr/bin/env python3
"""wstrcheck - every bounded-copy call site actually passes its bound.

gui_wstrcpy copies a wide string until the source's NUL.  It takes the limit in
r8: the address of the last writable wide char in the destination.  A call site
that forgets to set r8 does not fail to build and does not fail visibly - it
copies against whatever r8 happened to hold, which is either a limit far too
small (silent truncation) or far too large (no bound at all, which is where this
function started).

That is a register contract, and register contracts are exactly what nothing
else in this build checks.  So: every call must set r8 within the few
instructions before it.

The same rule covers cfg_default_vault, whose destination capacity arrives in
edx.  It writes a path built from the environment and had no capacity parameter
at all; both of its callers passed a 1024-char buffer and the proc simply
trusted that.

Exit code: number of call sites missing their bound (so "build strict" gates).
Usage: python tools/wstrcheck.py
"""
import re, os, sys, glob
import floors                            # coverage floors: see tools/floors.py

HERE = os.path.dirname(os.path.abspath(__file__))
SRC  = os.path.normpath(os.path.join(HERE, "..", "src"))

# callee -> (register that carries the bound, how many lines back to look)
CONTRACTS = {
    "gui_wstrcpy":       ("r8",  6),
    "cfg_default_vault": ("edx", 4),
}

SETS = {
    "r8":  re.compile(r'^\s*(lea|mov|xor)\s+r8d?\s*,'),
    "edx": re.compile(r'^\s*(lea|mov|xor)\s+(e|r)dx\s*,'),
}


# g_cfg_in names the vault every file operation derives from - the vault itself,
# its .tmp, its .lock, its .bak<n>.  It is set through cfg_in_set so that the
# conversion to a Win32-usable path happens in exactly one place; a direct
# assignment silently reintroduces the raw form for whichever flow does it.
SOLE_SETTER = ("g_cfg_in", "cfg_in_set")
ASSIGN = re.compile(r'^\s*mov\s+qword ptr \[' + SOLE_SETTER[0] + r'\]\s*,')


def sole_setter_check():
    bad = 0
    for path in sorted(glob.glob(os.path.join(SRC, "*.asm"))):
        base = os.path.basename(path)
        cur = None
        for i, raw in enumerate(open(path, encoding="latin-1").read().split("\n"), 1):
            l = raw.split(";")[0]
            m = re.match(r'^(\w+)\s+proc\b', l.strip())
            if m:
                cur = m.group(1)
            elif re.match(r'^\w+\s+endp\b', l.strip()):
                cur = None
            if ASSIGN.match(l) and cur != SOLE_SETTER[1]:
                bad += 1
                print(f"[DIRECT SET] {base}:{i} assigns {SOLE_SETTER[0]} outside "
                      f"{SOLE_SETTER[1]} - the path conversion would be skipped for "
                      f"whatever flow reaches this line")
    return bad


def main():
    bad = total = 0
    for path in sorted(glob.glob(os.path.join(SRC, "*.asm"))):
        base = os.path.basename(path)
        lines = [l.split(";")[0] for l in open(path, encoding="latin-1").read().split("\n")]
        for i, l in enumerate(lines):
            m = re.match(r'^\s*call\s+(\w+)\s*$', l.rstrip())
            if not m or m.group(1) not in CONTRACTS:
                continue
            reg, back = CONTRACTS[m.group(1)]
            total += 1
            window = lines[max(0, i - back):i]
            if not any(SETS[reg].match(w) for w in window):
                bad += 1
                print(f"[NO BOUND] {base}:{i+1} call {m.group(1)} without setting {reg} "
                      f"in the {back} lines before it - the copy would run against whatever "
                      f"{reg} happened to hold")
    print(f"wstrcheck: {bad} unbounded call site(s) across {total} bounded-copy call(s) "
          f"({'clean' if bad == 0 else 'UNBOUNDED COPY PRESENT'})")
    bad += sole_setter_check()
    bad += floors.check("wstrcheck", {"calls": total})
    sys.exit(min(bad, 255))


if __name__ == "__main__":
    main()
