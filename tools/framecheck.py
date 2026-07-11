#!/usr/bin/env python3
"""framecheck v2 - static stack-frame safety scanner for Vordr's MASM sources.

Two proc shapes are scanned:

1. FRAME_PROLOG procs (the v1 check): flag procs where the stack-arg spill of
   the widest WINCALL (args 5+ go to [rsp+32], [rsp+40], ...) could overlap the
   proc's deepest [rbp-N] local.  This is a HEURISTIC: per the project's frame
   convention a spill slot may legally share bytes with a local that is DEAD at
   that call, so these are reported as "warn" and a curated allowlist silences
   the historically verified-safe sites.

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

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_SRC = os.path.normpath(os.path.join(HERE, "..", "src"))

# FRAME_PROLOG heuristic findings verified safe in the 2026-07 audit (proc names).
# read_file/write_file DELIBERATELY overlap ReadFile/WriteFile's out-param slot
# with the lpOverlapped=NULL stack-arg slot (exact-sized frames, documented).
ALLOW_FP = {
    "gui_draw_iconbtn", "gui_draw_sbadge", "read_file", "write_file",
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

def wincall_args(s):
    """Number of args of a WINCALL line (0 if not a WINCALL)."""
    m = re.search(r'\bWINCALL\s+[\w$]+\s*(,(.*))?$', s)
    if not m: return 0
    if not m.group(2): return 0
    depth = 0; n = 1
    for c in m.group(2):
        if c == '[' or c == '(': depth += 1
        elif c == ']' or c == ')': depth -= 1
        elif c == ',' and depth == 0: n += 1
    return n

RE_PROC   = re.compile(r'^\s*([\w$]+)\s+proc\b', re.I)
RE_ENDP   = re.compile(r'^\s*[\w$]+\s+endp\b', re.I)
RE_FP     = re.compile(r'\bFRAME_PROLOG\s+([0-9+ ]+?)\s*$')
RE_SUBRSP = re.compile(r'^\s*sub\s+rsp\s*,\s*([0-9*+ ]+?)\s*$', re.I)
RE_ADDRSP = re.compile(r'^\s*add\s+rsp\s*,\s*([0-9*+ ]+?)\s*$', re.I)
RE_PUSH   = re.compile(r'^\s*push\s+\w+', re.I)
RE_POP    = re.compile(r'^\s*pop\s+\w+', re.I)
RE_LOCAL  = re.compile(r'\[rbp\s*-\s*(\d+)\]')
# a WRITE to [rsp+K]: mov/lea/movdq* with the [rsp+K] as the FIRST operand
RE_RSPST  = re.compile(
    r'^\s*(mov|movdqu|movdqa|movups|movaps|lea)\s+'
    r'(?:(qword|dword|word|byte|xmmword)\s+ptr\s+)?\[rsp\s*\+\s*(\d+)\]\s*,', re.I)
ST_SIZE = {'qword': 8, 'dword': 4, 'word': 2, 'byte': 1, 'xmmword': 16}
RE_MOVRSPBASE = re.compile(r'^\s*mov\s+rsp\s*,\s*rbp', re.I)

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
                maxloc = max(maxloc, int(mm.group(1)))

        if fp:
            # ---- v1 heuristic on FRAME_PROLOG procs -------------------------
            N = eval(fp.group(1)); alloc = ((N + 8 + 15) & ~15)
            maxargs = 0; at = start
            for ln, s in merged:
                n = wincall_args(s)
                if n > maxargs: maxargs = n; at = start + ln
            need = maxloc + 32 + max(0, maxargs - 4) * 8
            if maxargs > 4 and alloc < need and name not in ALLOW_FP:
                results.append(("warn", fname, at + 1, name,
                    f"FRAME_PROLOG {N} (alloc {alloc}) < heuristic need {need} "
                    f"(deepest local -{maxloc}, {maxargs}-arg WINCALL) - "
                    f"verify the overlapped local is dead at that call"))
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
    results = []
    for f in sorted(glob.glob(os.path.join(args.src, "*.asm"))):
        scan_file(f, results)
    fatals = 0
    for sev, fname, line, name, msg in results:
        if sev == "FATAL": fatals += 1
        if args.fatal_only and sev != "FATAL": continue
        print(f"[{sev}] {fname}:{line} {name}: {msg}")
    n_warn = sum(1 for r in results if r[0] == 'warn')
    print(f"framecheck: {fatals} fatal, {n_warn} warn "
          f"({'clean' if fatals == 0 else 'FRAME BUGS PRESENT'})")
    sys.exit(min(fatals, 255))

if __name__ == "__main__":
    main()
