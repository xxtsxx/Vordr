#!/usr/bin/env python3
"""build_fast.py - single-process linter driver and parallel MASM assembler.

Invoked by build.cmd when Python is available on PATH:
  1. `lint [--strict] [--no-cache]` runs all 10 static analysers in one Python
     process (instead of 10 separate interpreter startups), caching clean
     results in `obj\\.lint_cache` keyed by the SHA-256 of all watched source,
     resource, documentation, and tool inputs (plus repo file paths so missing
     doc-link targets invalidate the cache).
  2. `asm <sources...> -- <asmflags...>` assembles all 26 MASM translation units
     concurrently across CPU cores while preserving deterministic output order
     and per-module `/Foobj\\<m>.obj` + `/Flobj\\<m>.lst` outputs.
  3. `build [--strict] [--no-cache] <sources...> -- <asmflags...>` runs `lint`
     followed immediately by `asm` inside a single Python process.

Each individual checker in tools/ remains directly runnable standalone.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib
import os
from pathlib import Path
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
CACHE_FILE = os.path.join(ROOT, "obj", ".lint_cache")
if HERE not in sys.path:
    sys.path.insert(0, HERE)

CHECKS = [
    ("framecheck", True,
     "framecheck: FATAL frame bug - failing strict build",
     'framecheck: WARNING - fatal findings above; build continues. Use "build strict" to gate.'),
    ("nvcheck", False,
     "nvcheck: a callee-saved register is not preserved - failing strict build",
     'nvcheck: WARNING - unsaved non-volatile registers above; build continues. Use "build strict" to gate.'),
    ("idcheck", False,
     "idcheck: rc/asm ID mismatch - failing strict build",
     'idcheck: WARNING - ID mismatches above; build continues. Use "build strict" to gate.'),
    ("constcheck", False,
     "constcheck: a constant disagrees across modules - failing strict build",
     'constcheck: WARNING - cross-module drift above; build continues. Use "build strict" to gate.'),
    ("dlgtarget", False,
     "dlgtarget: dialog-item call targets the wrong window - failing strict build",
     'dlgtarget: WARNING - wrong-window calls above; build continues. Use "build strict" to gate.'),
    ("deadcode", False,
     "deadcode: dead proc/data/equ - failing strict build",
     'deadcode: WARNING - dead symbols above; build continues. Use "build strict" to gate.'),
    ("rccheck", False,
     "rccheck: dialog geometry - failing strict build",
     'rccheck: WARNING - layout findings above; build continues. Use "build strict" to gate.'),
    ("wstrcheck", False,
     "wstrcheck: a bounded copy called without its bound - failing strict build",
     'wstrcheck: WARNING - unbounded call sites above; build continues. Use "build strict" to gate.'),
    ("aligncheck", False,
     "aligncheck: misaligned wide-string labels - failing strict build",
     'aligncheck: WARNING - misaligned labels above; build continues. Use "build strict" to gate.'),
    ("check_docs", False,
     "check_docs: documentation link/anchor error - failing strict build",
     'check_docs: WARNING - documentation errors above; build continues. Use "build strict" to gate.'),
]

HASH_EXTS = {".asm", ".inc", ".rc", ".manifest", ".py", ".md", ".html"}
SKIP_DIRS = {".git", "bin", "obj", "__pycache__", ".agents"}


def _lint_digest(strict: bool) -> str:
    h = hashlib.sha256()
    h.update(b"strict=1\n" if strict else b"strict=0\n")
    root_path = Path(ROOT)
    entries = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        rel_dir = os.path.relpath(dirpath, ROOT)
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = fn if rel_dir == "." else os.path.join(rel_dir, fn)
            entries.append((rel.replace("\\", "/"), full, os.path.splitext(fn)[1].lower()))
    for rel, full, ext in entries:
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        if ext in HASH_EXTS:
            with open(full, "rb") as fp:
                data = fp.read()
            h.update(len(data).to_bytes(8, "little"))
            h.update(data)
    return h.hexdigest()


def run_lint(strict: bool, use_cache: bool = True) -> int:
    os.chdir(ROOT)
    digest = _lint_digest(True if strict else False)
    strict_digest = _lint_digest(True)
    if use_cache and os.path.isfile(CACHE_FILE):
        try:
            cached = Path(CACHE_FILE).read_text(encoding="ascii").strip()
        except OSError:
            cached = ""
        if cached in (f"strict:{strict_digest}", f"mode:{digest}"):
            print(f"=== static checks: clean (cached sha256:{cached.split(':', 1)[1][:12]}) ===", flush=True)
            return 0

    saved_argv = sys.argv[:]
    all_clean = True
    try:
        for mod_name, pass_strict, fail_msg, warn_msg in CHECKS:
            print(f"=== {mod_name} ===", flush=True)
            argv = [f"{mod_name}.py"]
            if pass_strict and strict:
                argv.append("--strict")
            sys.argv = argv
            mod = importlib.import_module(mod_name)
            code = 0
            try:
                ret = mod.main()
                if isinstance(ret, int):
                    code = ret
            except SystemExit as exc:
                if exc.code is None:
                    code = 0
                elif isinstance(exc.code, int):
                    code = exc.code
                else:
                    code = 1
            if code != 0:
                all_clean = False
                if strict:
                    print(fail_msg, flush=True)
                    return 1
                print(warn_msg, flush=True)
    finally:
        sys.argv = saved_argv

    if all_clean:
        try:
            os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
            tag = f"strict:{strict_digest}" if strict else f"mode:{digest}"
            Path(CACHE_FILE).write_text(tag + "\n", encoding="ascii")
        except OSError:
            pass
    return 0


def _assemble_one(args):
    src_name, asm_flags = args
    cmd = (
        ["ml64"]
        + asm_flags
        + [
            f"/Foobj\\{src_name}.obj",
            f"/Flobj\\{src_name}.lst",
            "/I", "src",
            f"src\\{src_name}.asm",
        ]
    )
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="latin-1",
    )
    return src_name, proc.returncode, proc.stdout


def run_asm(sources, asm_flags) -> int:
    print("=== assembling ===", flush=True)
    workers = min(len(sources), max(2, min(8, os.cpu_count() or 4)))
    tasks = [(s, asm_flags) for s in sources]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(_assemble_one, tasks))
    failed = False
    for _, rc, out in results:
        if out:
            sys.stdout.write(out)
        if rc != 0:
            failed = True
    sys.stdout.flush()
    return 1 if failed else 0


def _split_sources_flags(args):
    if "--" in args:
        sep = args.index("--")
        return args[:sep], args[sep + 1:]
    return args, []


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: build_fast.py [lint|asm|build] ...", file=sys.stderr)
        return 2
    mode = sys.argv[1]
    rest = sys.argv[2:]
    if mode == "lint":
        strict = "--strict" in rest
        use_cache = "--no-cache" not in rest
        return run_lint(strict, use_cache=use_cache)
    if mode == "asm":
        sources, asm_flags = _split_sources_flags(rest)
        return run_asm(sources, asm_flags)
    if mode == "build":
        strict = False
        use_cache = True
        filtered = []
        after_sep = False
        for tok in rest:
            if tok == "--":
                after_sep = True
                filtered.append(tok)
            elif not after_sep and tok == "--strict":
                strict = True
            elif not after_sep and tok == "--no-cache":
                use_cache = False
            else:
                filtered.append(tok)
        sources, asm_flags = _split_sources_flags(filtered)
        rc = run_lint(strict, use_cache=use_cache)
        if rc != 0:
            return rc
        return run_asm(sources, asm_flags)
    print(f"unknown mode: {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
