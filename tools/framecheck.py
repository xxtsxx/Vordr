#!/usr/bin/env python3
"""framecheck v2 - static stack-frame safety scanner for Vordr's MASM sources.

Two proc shapes are scanned:

1. FRAME_PROLOG procs (the v1 check): flag procs where the stack-arg spill of
   the widest WINCALL (args 5+ go to [rsp+32], [rsp+40], ...) could overlap the
   proc's deepest [rbp-N] local.  This is a HEURISTIC: per the project's frame
   convention a spill slot may legally share bytes with a local that is DEAD at
   that call, so these are reported as "warn" and a curated allowlist silences
   the historically verified-safe sites.  The frame size may be a plain number
   or any constant MASM expression ("FRAME_PROLOG 96 + BLAKE2B_CTX_SIZE");
   equ names and sizeof STRUCT are evaluated from the sources, and a frame
   whose size cannot be resolved is reported as warn (never silently skipped).

2. Raw procs ("push rbp / mov rbp,rsp / sub rsp,N", no FRAME_PROLOG - i.e. the
   dialog/window procs): these are the dangerous ones that v1 never saw.
   - FATAL: a WINCALL (or explicit [rsp+K] arg store) whose spill area extends
     PAST the N-byte frame, clobbering the saved rbp / return address.  This is
     the exact class that crashed create_proc (14-arg CreateFontW in a
     sub rsp,64 frame -> ret to 0 -> BEX64 c0000005 fault offset 0).
   - WARN:  the spill stays inside the frame but reaches into the proc's
     deepest [rbp-N] local region (possible silent corruption).
   Manual "sub rsp,K ... call ... add rsp,K" extensions and push/pop are
   tracked, so about_proc-style widened call sites are judged with K included.

Exit code: number of FATALs (so "build strict" can gate on it); warns are
informational.  Usage: python tools\\framecheck.py [--src DIR] [--fatal-only]
"""
import re, glob, os, sys, argparse
import floors                            # coverage floors: see tools/floors.py

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_SRC = os.path.normpath(os.path.join(HERE, "..", "src"))

# FRAME_PROLOG heuristic findings verified safe in the 2026-07 audit (proc names).
# read_file/write_file DELIBERATELY overlap ReadFile/WriteFile's out-param slot
# with the lpOverlapped=NULL stack-arg slot (exact-sized frames, documented).
# gui_temp_purge documents the same pattern: its deepest live local is rbp-56
# and [rbp-64] is a throwaway bytes-written slot that intentionally sits in
# the CreateFileW(7)/WriteFile(5) spill zone.
ALLOW_FP = {
    "gui_draw_sbadge", "read_file", "write_file", "gui_temp_purge",
}

# Home-space findings that are safe by inspection rather than by frame size.
# read_file DELIBERATELY aliases ReadFile's lpNumberOfBytesRead with the
# lpOverlapped=NULL slot; write_file/gui_temp_purge document the same pattern.
ALLOW_HOME = {
    "read_file", "write_file", "gui_temp_purge",
}

# Raw-proc warn findings verified safe: url_editproc's 5-arg CallWindowProcW
# spills [rbp-32] onto [rsp+32] which IS [rbp-32] in its 64-byte frame - the
# local is overwritten with its own value and is dead after the call.
ALLOW_RAW_WARN = {
    "url_editproc",
}

def strip_comment(l):
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

def join_continuations(lines):
    """Merge trailing-backslash continuation lines; keep original line numbers."""
    out = []
    i = 0
    while i < len(lines):
        ln = i; s = lines[i]
        while s.rstrip().endswith('\\') and i + 1 < len(lines):
            i += 1
            s = s.rstrip()[:-1] + ' ' + lines[i].lstrip()
        out.append((ln, s))
        i += 1
    return out

def wincall_parts(s):
    """(callee, [args]) for a WINCALL line, or (None, []) if not a WINCALL."""
    m = re.search(r'\bWINCALL\s+([\w$]+)\s*(,(.*))?$', s)
    if not m: return (None, [])
    if not m.group(3): return (m.group(1), [])
    depth = 0; cur = ''; args = []
    for c in m.group(3):
        if c in '[(': depth += 1
        elif c in '])': depth -= 1
        if c == ',' and depth == 0:
            args.append(cur.strip()); cur = ''
        else:
            cur += c
    args.append(cur.strip())
    return (m.group(1), args)

def wincall_args(s):
    """Number of args of a WINCALL line (0 if not a WINCALL)."""
    callee, args = wincall_parts(s)
    return len(args) if callee else 0

def clobbers_rax(arg):
    """True if __WSTKARG routes this stack arg through rax."""
    a = arg.strip()
    if a.lower().startswith('addr '): return True       # lea rax, [X]
    if a.lower() in REG64: return False                 # direct store
    if RE_SAFEARG.match(a) and '[' not in a and ' ' not in a:
        return False                                    # absolute constant / equ
    return True                                         # 32-bit or memory -> via rax

RE_PROC   = re.compile(r'^\s*([\w$]+)\s+proc\b', re.I)
RE_ENDP   = re.compile(r'^\s*[\w$]+\s+endp\b', re.I)
RE_FP     = re.compile(r'\bFRAME_PROLOG\s+(.+?)\s*$')
RE_SUBRSP = re.compile(r'^\s*sub\s+rsp\s*,\s*([0-9*+ ]+?)\s*$', re.I)
RE_ADDRSP = re.compile(r'^\s*add\s+rsp\s*,\s*([0-9*+ ]+?)\s*$', re.I)
RE_PUSH   = re.compile(r'^\s*push\s+\w+', re.I)
RE_POP    = re.compile(r'^\s*pop\s+\w+', re.I)
# A local is referenced either as [rbp-N] or, when its ADDRESS is handed to an
# API, as "addr rbp-N".  Missing the second form is how the GetClientRect output
# buffer in gui_draw_field_cards hid inside that call's own home space.
RE_LOCAL  = re.compile(r'(?:\[rbp\s*-\s*(\d+)\]|\baddr\s+rbp\s*-\s*(\d+)\b)', re.I)
RE_EXTERN = re.compile(r'^\s*extern\s+([\w$]+)\s*:\s*proc', re.I)
# __WSTKARG stores an absolute constant or a 64-bit register straight to [rsp+K];
# everything else (addr X, any 32-bit operand, 64-bit memory) round-trips via rax.
RE_SAFEARG = re.compile(r'^(?:[0-9][0-9a-fx]*h?|r[a-z0-9]+|'
                        r'[A-Z_][A-Z0-9_]*)$', re.I)
REG64 = {'rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
         'r8','r9','r10','r11','r12','r13','r14','r15'}
RE_EQU    = re.compile(r'^\s*([\w$]+)\s+equ\s+(.+?)\s*$', re.I)
RE_STRUCT = re.compile(r'^\s*([\w$]+)\s+struct\b', re.I)
RE_SENDS  = re.compile(r'^\s*[\w$]+\s+ends\b', re.I)
RE_FIELD  = re.compile(r'^\s*(?:[\w$]+\s+)?(db|dw|dd|dq|dt)\b\s*(.*)$', re.I)
FSIZE     = {'db': 1, 'dw': 2, 'dd': 4, 'dq': 8, 'dt': 10}
# a WRITE to [rsp+K]: mov/lea/movdq* with the [rsp+K] as the FIRST operand
RE_RSPST  = re.compile(
    r'^\s*(mov|movdqu|movdqa|movups|movaps|lea)\s+'
    r'(?:(qword|dword|word|byte|xmmword)\s+ptr\s+)?\[rsp\s*\+\s*(\d+)\]\s*,', re.I)
ST_SIZE = {'qword': 8, 'dword': 4, 'word': 2, 'byte': 1, 'xmmword': 16}
RE_MOVRSPBASE = re.compile(r'^\s*mov\s+rsp\s*,\s*rbp', re.I)

EQUS = {}
STRUCTS = {}
EXTERNS = set()          # `extern X:proc` - a Win32 callee, free to use its home space
STATS = {'fp': 0, 'sym': 0}

def masm_int(tok):
    """MASM integer literal -> int or None: decimal, 0x.., or trailing-h hex (0FFh)."""
    t = tok.strip()
    if re.fullmatch(r'\d+', t): return int(t)
    if re.fullmatch(r'0[xX][0-9A-Fa-f]+', t): return int(t, 16)
    if re.fullmatch(r'[0-9][0-9A-Fa-f]*[hH]', t): return int(t[:-1], 16)
    return None

def eval_size(expr, depth=0):
    """Evaluate a MASM size expression: literals, equ names, sizeof STRUCT, + - * / ( ).
    Raises ValueError when anything is unresolvable (caller must surface it)."""
    if depth > 16: raise ValueError("equ cycle")
    expr = expr.strip()
    v = masm_int(expr)
    if v is not None: return v
    m = re.fullmatch(r'sizeof\s+([\w$]+)', expr, re.I)
    if m:
        if m.group(1) not in STRUCTS: raise ValueError(f"unknown struct {m.group(1)}")
        return STRUCTS[m.group(1)]
    out = []
    for t in re.findall(r'[\w$]+|[()+*/-]', expr):
        n = masm_int(t)
        if n is not None:
            out.append(str(n))
        elif re.fullmatch(r'[\w$]+', t):
            if t.lower() == 'sizeof': raise ValueError("sizeof needs a name")
            if t not in EQUS: raise ValueError(f"unknown equ {t}")
            out.append(str(eval_size(EQUS[t], depth + 1)))
        elif t in '()+*/-':
            out.append(t)
        else:
            raise ValueError(f"unresolvable token {t!r}")
    pyexpr = ' '.join(out)
    if not re.fullmatch(r'[0-9()+*/ \-]+', pyexpr): raise ValueError("unsafe expr")
    return int(eval(pyexpr, {'__builtins__': {}}))

def build_tables(files):
    """Collect `NAME equ EXPR` and `NAME struct .. ends` sizes from every source."""
    for path in files:
        raw = [strip_comment(l.rstrip('\n')) for l in open(path, encoding='latin-1')]
        cur = None; size = 0
        for s in raw:
            xm = RE_EXTERN.match(s)
            if xm: EXTERNS.add(xm.group(1))
            em = RE_EQU.match(s)
            if em and not cur: EQUS[em.group(1)] = em.group(2)
            sm = RE_STRUCT.match(s)
            if sm and not cur: cur = sm.group(1); size = 0; continue
            if cur:
                if RE_SENDS.match(s): STRUCTS[cur] = size; cur = None; continue
                fm = RE_FIELD.match(s)
                if fm:
                    cnt = 1
                    dm = re.match(r'(\d+)\s+dup\b', fm.group(2))
                    if dm: cnt = int(dm.group(1))
                    size += cnt * FSIZE[fm.group(1).lower()]

def scan_file(path, results):
    raw = [strip_comment(l.rstrip('\n')) for l in open(path, encoding='latin-1')]
    fname = os.path.basename(path)
    i = 0
    while i < len(raw):
        m = RE_PROC.match(raw[i])
        if not m:
            i += 1; continue
        name = m.group(1); start = i
        end = next((x for x in range(i + 1, len(raw)) if RE_ENDP.match(raw[x])), len(raw) - 1)
        body = raw[start:end + 1]
        merged = join_continuations(body)

        fp = next((RE_FP.search(s) for _, s in merged if 'FRAME_PROLOG' in s), None)
        maxloc = 0
        for _, s in merged:
            for mm in RE_LOCAL.finditer(s):
                maxloc = max(maxloc, int(mm.group(1) or mm.group(2)))

        if fp:
            # ---- v1 heuristic on FRAME_PROLOG procs -------------------------
            try:
                N = eval_size(fp.group(1))
            except ValueError as e:
                results.append(("warn", fname, start + 1, name,
                    f"FRAME_PROLOG {fp.group(1).strip()!r} frame size unresolvable ({e}) "
                    f"- proc NOT CHECKED"))
                i = end + 1; continue
            STATS['fp'] += 1
            if masm_int(fp.group(1)) is None: STATS['sym'] += 1
            alloc = ((N + 8 + 15) & ~15)
            maxargs = 0; at = start
            for ln, s in merged:
                n = wincall_args(s)
                if n > maxargs: maxargs = n; at = start + ln
            need = maxloc + 32 + max(0, maxargs - 4) * 8
            if maxargs > 4 and alloc < need and name not in ALLOW_FP:
                results.append(("warn", fname, at + 1, name,
                    f"FRAME_PROLOG {fp.group(1).strip()} (alloc {alloc}) < heuristic need {need} "
                    f"(deepest local -{maxloc}, {maxargs}-arg WINCALL) - "
                    f"verify the overlapped local is dead at that call"))
            # ---- home-space overlap on Win32 callees ------------------------
            # The 32-byte home area belongs to the CALLEE for any arg count, and
            # a Win32 callee really does save nonvolatiles there (GetClientRect
            # homes four on its first instruction).  Internal procs never touch a
            # caller's home space - an unwritten invariant this whole codebase
            # relies on - so only extern callees are judged here.
            worst = 0; wat = start; wcallee = None
            for ln, s in merged:
                callee, args = wincall_parts(s)
                if not callee or callee not in EXTERNS: continue
                span = 32 + max(0, len(args) - 4) * 8
                if span > worst: worst, wat, wcallee = span, start + ln, callee
                # ---- WINCALL rax-clobber ----------------------------------
                # __WSTKARG emits the stack args BEFORE the register args, and
                # every form except an absolute constant or a 64-bit register
                # goes out through rax.  Passing rax itself as arg 1-4 then
                # loads the wrong value (this silently broke gui_reflow).
                if len(args) > 4 and any(a.strip().lower() in ('rax', 'eax')
                                         for a in args[:4]) \
                   and any(clobbers_rax(a) for a in args[4:]):
                    results.append(("FATAL", fname, start + ln + 1, name,
                        f"WINCALL {callee} passes rax as a register arg while a "
                        f"later stack arg routes through rax - the register arg "
                        f"receives the WRONG value; stage the handle in a local"))
            if worst and alloc - maxloc < worst and maxloc \
               and name not in ALLOW_FP and name not in ALLOW_HOME:
                results.append(("warn", fname, wat + 1, name,
                    f"FRAME_PROLOG {fp.group(1).strip()} (alloc {alloc}): local "
                    f"-{maxloc} lies in {wcallee}'s home/arg area (rsp..rsp+{worst}) "
                    f"- a Win32 callee may save registers over it"))
        else:
            # ---- v2: raw proc ----------------------------------------------
            # find the raw prologue: sub rsp,N within the first few lines
            N = None; pidx = None
            for idx, (ln, s) in enumerate(merged[:6]):
                sm = RE_SUBRSP.match(s)
                if sm: N = eval(sm.group(1)); pidx = idx; break
            if N is None:
                i = end + 1; continue   # leaf/trampoline without a frame
            extra = 0                    # manual sub/add rsp + push/pop tracking
            for ln, s in merged[pidx + 1:]:
                if RE_MOVRSPBASE.match(s):
                    extra = 0; continue  # epilogue "mov rsp, rbp"
                sm = RE_SUBRSP.match(s)
                if sm:
                    extra += eval(sm.group(1)); continue
                am = RE_ADDRSP.match(s)
                if am: extra -= eval(am.group(1)); continue
                if RE_PUSH.match(s): extra += 8; continue
                if RE_POP.match(s):  extra -= 8; continue

                spill_end = 0; desc = None
                n = wincall_args(s)
                if n > 4:
                    spill_end = 32 + 8 * (n - 4)
                    desc = f"{n}-arg WINCALL"
                else:
                    # explicit write to [rsp+K] (outgoing arg or xmm save)
                    mm = RE_RSPST.match(s)
                    if mm:
                        op = mm.group(1).lower()
                        sz = 16 if op.startswith('movdq') or op in ('movups', 'movaps') \
                             else ST_SIZE.get((mm.group(2) or 'qword').lower(), 8)
                        k = int(mm.group(3))
                        if k + sz > spill_end:
                            spill_end = k + sz; desc = f"{sz}-byte store to [rsp+{k}]"
                if not spill_end: continue

                frame = N + extra
                if spill_end > frame:
                    results.append(("FATAL", fname, start + ln + 1, name,
                        f"{desc} spills to rsp+{spill_end - 8} but the raw frame is "
                        f"only {frame} bytes (sub rsp,{N}{f' +{extra} manual' if extra else ''}) "
                        f"- saved rbp/return address clobbered (BEX64 class)"))
                elif spill_end > frame - maxloc and maxloc and name not in ALLOW_RAW_WARN:
                    results.append(("warn", fname, start + ln + 1, name,
                        f"{desc} spill (to rsp+{spill_end - 8}) reaches the local region "
                        f"(frame {frame}, deepest local -{maxloc}) - verify liveness"))
        i = end + 1

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=DEF_SRC)
    ap.add_argument("--fatal-only", action="store_true")
    args = ap.parse_args()
    files = sorted(glob.glob(os.path.join(args.src, "*.asm")))
    inc = os.path.join(args.src, "macros.inc")
    build_tables(files + ([inc] if os.path.exists(inc) else []))
    results = []
    for f in files:
        scan_file(f, results)
    fatals = 0
    for sev, fname, line, name, msg in results:
        if sev == "FATAL": fatals += 1
        if args.fatal_only and sev != "FATAL": continue
        print(f"[{sev}] {fname}:{line} {name}: {msg}")
    n_warn = sum(1 for r in results if r[0] == 'warn')
    print(f"framecheck: {fatals} fatal, {n_warn} warn "
          f"({'clean' if fatals == 0 else 'FRAME BUGS PRESENT'}); "
          f"{STATS['fp']} FRAME_PROLOG procs checked ({STATS['sym']} symbolic-size)")
    fatals += floors.check("framecheck", {"procs": STATS['fp']})
    sys.exit(min(fatals, 255))

if __name__ == "__main__":
    main()
