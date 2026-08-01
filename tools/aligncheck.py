#!/usr/bin/env python3
"""aligncheck.py - data-alignment auditor for Vordr's MASM sources.

The tray_cls incident (2026-07): a `dw` class-name string landed at an ODD
address because an odd-length `db` string earlier in the section shifted it.
The OS class-name reader took an aligned (SSE) path, raised
STATUS_DATATYPE_MISALIGNMENT, and RegisterClassW failed with ERROR_NOACCESS.

This tool tracks the running byte offset of every data label in each source
file and reports labels that cannot be naturally aligned for their access
width:
  - dw / word / WSTR   -> must be 2-aligned
  - dd / dword         -> must be 4-aligned
  - dq / qword         -> must be 8-aligned

Sections are page-aligned by the linker, so per-file offset tracking is
sufficient.  STRUCT/UNION bodies are skipped (layout alignment is explicit),
and align/even directives reset the running offset.

Not every odd `dw` is a bug: most APIs read wide strings byte-wise.  But as a
CONTROL the rule is: any wide string or array that an OS API or an SSE code
path might touch must be naturally aligned.  Flagged sites are fixed with an
explicit `align` (documenting intent) or allowlisted here with a reason.

Exit code = number of misaligned labels (so "build strict" can gate on it).
Usage: python tools\\aligncheck.py [--src DIR]
"""
import re, glob, os, sys, argparse
import floors                            # coverage floors: see tools/floors.py

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_SRC = os.path.normpath(os.path.join(HERE, "..", "src"))

# Sites reviewed and accepted as harmless (name only - the data is consumed
# byte-wise and is never handed to an OS API or an SSE load).
ALLOWLIST = {
}

DIRECTIVE_SIZE = {"db": 1, "dw": 2, "dd": 4, "dq": 8, "dt": 10,
                  "byte": 1, "word": 2, "dword": 4, "qword": 8}
LABEL_ALIGN   = {"db": 1, "dw": 2, "dd": 4, "dq": 8, "dt": 4,
                 "byte": 1, "word": 2, "dword": 4, "qword": 8}

RE_SECTION = re.compile(r'^\s*\.(data\??|const|code)\b', re.I)
RE_STRUCT  = re.compile(r'^\s*[\w$]+\s+(struct|union)\b', re.I)
RE_ENDS    = re.compile(r'^\s*[\w$]+\s+ends\b', re.I)
RE_ALIGN   = re.compile(r'^\s*(align|even)\b\s*(\d+)?', re.I)
RE_LABEL   = re.compile(r'^\s*([\w$]+)\s+(label)\s+(\w+)\b', re.I)
RE_DEF     = re.compile(r'^\s*(?:([\w$]+)\s+)?(db|dw|dd|dq|dt)\b(.*)$', re.I)
RE_DUP     = re.compile(r'(\d+)\s+dup\s*\((.*)\)', re.I)
RE_WSTR    = re.compile(r'^\s*WSTR\s+([\w$]+)\s*,\s*<(.*)>\s*$', re.I)
RE_CSTR    = re.compile(r'^\s*CSTR\s+([\w$]+)\s*,\s*"(.*)"\s*$', re.I)

def strip_line(l):
    """Drop ; comment, keep quoted strings intact (we need their lengths)."""
    out = []
    q = None
    for c in l:
        if q:
            if c == q: q = None
            out.append(c)
        elif c in "'\"":
            q = c; out.append(c)
        elif c == ';':
            break
        else:
            out.append(c)
    return ''.join(out)

def split_items(s):
    """Split a MASM operand list on commas at depth 0, respecting quotes/parens."""
    parts, depth, q, cur = [], 0, None, []
    for c in s:
        if q:
            cur.append(c)
            if c == q: q = None
        elif c in "'\"": q = c; cur.append(c)
        elif c in '([{': depth += 1; cur.append(c)
        elif c in ')]}': depth -= 1; cur.append(c)
        elif c == ',' and depth == 0:
            parts.append(''.join(cur).strip()); cur = []
        else:
            cur.append(c)
    parts.append(''.join(cur).strip())
    return [p for p in parts if p]

def item_bytes(tok, dirsize):
    """Byte count of one MASM data item (numbers, chars, strings, ?, expressions)."""
    tok = tok.strip()
    if not tok: return 0
    if tok == '?': return dirsize
    if tok.startswith('"') and tok.endswith('"') and len(tok) >= 2:
        return len(tok) - 2
    if tok.startswith("'"):
        # char literal(s): 'A' -> 1 per char of content (single quotes hold 1-2)
        inner = tok[1:-1] if tok.endswith("'") else tok[1:]
        return len(inner) if dirsize == 1 else dirsize
    return dirsize

def operand_bytes(rest, dirsize):
    total = 0
    for part in split_items(rest):
        m = RE_DUP.match(part)
        if m:
            n = int(m.group(1))
            inner = split_items(m.group(2))
            sub = sum(item_bytes(t, dirsize) for t in inner)
            total += n * max(sub, dirsize if inner else 0)
        else:
            total += item_bytes(part, dirsize)
    return total

def scan_file(path, results):
    fname = os.path.basename(path)
    section = None
    offsets = {}          # section -> running byte offset
    in_struct = False
    for n, raw in enumerate(open(path, encoding='latin-1'), 1):
        s = strip_line(raw.rstrip('\n')).strip()
        if not s: continue
        m = RE_SECTION.match(s)
        if m:
            section = m.group(1).lower()
            offsets.setdefault(section, 0)
            continue
        if section not in ('data', 'data?', 'const'):
            continue
        if in_struct:
            if RE_ENDS.match(s): in_struct = False
            continue
        if RE_STRUCT.match(s):
            in_struct = True
            continue
        m = RE_ALIGN.match(s)
        if m:
            a = int(m.group(2)) if m.group(2) else 2
            if s.lower().startswith('even'): a = 2
            if a > 0:
                offsets[section] = (offsets[section] + a - 1) & ~(a - 1)
            continue
        # WSTR name, <text>  -> `even` + label + dw text + dw 0.  The WSTR macro
        # now emits `even` first (macros.inc), so every wide string self-aligns
        # regardless of a drifted/odd running offset.  Model that here: snap to
        # even before counting.  (This also keeps the running offset honest
        # through WSTR blocks even if an earlier directive was mis-parsed - the
        # per-file-offset heuristic that let the original m_tpminfo odd address
        # slip past this tool.)
        m = RE_WSTR.match(s)
        if m:
            name, text = m.group(1), m.group(2)
            off = (offsets[section] + 1) & ~1          # WSTR macro's `even`
            offsets[section] = off + 2 * (len(text) + 1)
            continue
        # CSTR name, "text"  -> db text + db 0
        m = RE_CSTR.match(s)
        if m:
            offsets[section] += len(m.group(2)) + 1
            continue
        # name label word|dword|qword|byte
        m = RE_LABEL.match(s)
        if m:
            name, kind = m.group(1), m.group(3).lower()
            need = LABEL_ALIGN.get(kind, 1)
            off = offsets[section]
            if need > 1 and off % need:
                cat = "string" if need == 2 else "scalar"
                results.append((cat, fname, n, name, kind, off,
                    f"{kind} label at offset {off} (not {need}-aligned) - can land "
                    f"unaligned for an aligned-width read"))
            continue
        # [name] db/dw/dd/dq/dt items
        m = RE_DEF.match(s)
        if m:
            name, directive, rest = m.group(1), m.group(2).lower(), m.group(3)
            need = LABEL_ALIGN[directive]
            off = offsets[section]
            if name and need > 1 and off % need:
                cat = "string" if need == 2 else "scalar"
                results.append((cat, fname, n, name, directive, off,
                    f"{directive} label at offset {off} (not {need}-aligned) - can land "
                    f"unaligned for an aligned-width read"))
            offsets[section] = off + operand_bytes(rest, DIRECTIVE_SIZE[directive])
            continue

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=DEF_SRC)
    ap.add_argument("--scalars", action="store_true",
                    help="also report misaligned dq/dd scalar globals (review list)")
    args = ap.parse_args()
    results = []
    for f in sorted(glob.glob(os.path.join(args.src, "*.asm"))) + \
             sorted(glob.glob(os.path.join(args.src, "*.inc"))):
        scan_file(f, results)
    n_str = 0
    n_scalar = 0
    for cat, fname, line, name, kind, off, msg in results:
        if name in ALLOWLIST: continue
        if cat == "scalar" and not args.scalars:
            n_scalar += 1
            continue
        if cat == "string": n_str += 1
        else: n_scalar += 1
        print(f"[{cat}] {fname}:{line} {name}: {msg}")
    print(f"aligncheck: {n_str} misaligned strings"
          + (f", {n_scalar} scalars (review)" if n_scalar else "")
          + f" ({'clean' if n_str == 0 else 'MISALIGNMENT PRESENT'})")
    n_str += floors.check("aligncheck", {"scalars": n_scalar})
    sys.exit(min(n_str, 255))

if __name__ == "__main__":
    main()
