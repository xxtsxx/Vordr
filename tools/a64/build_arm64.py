"""build_arm64.py - assemble, translate and link native Windows ARM64 vordr-arm64.exe.

Architecture:
  1. Assembles the 24 shared logic modules with ml64 into obj/arm64/x64/*.obj
     (or reuses them when unchanged) so x64 obj/ and bin/vordr.exe are untouched.
  2. Translates each x64 COFF object into obj/arm64/gen/*.S via tools/a64/xlat.py.
  3. Assembles obj/arm64/gen/*.S and the 5 hand-written ISA modules in
     src/arm64/*.S (aesgcm, sha, blake2b_argon2, platform, loadcfg) with
     clang --target=aarch64-pc-windows-msvc -march=armv8.2-a+crypto.
  4. Generates ARM64 import libraries from tools/arm64_defs/*.def via llvm-lib
     (or uses Windows SDK Lib/<ver>/um/arm64 when present).
  5. Links bin/vordr-arm64.exe with MSVC link.exe /machine:arm64 and normalises
     in release mode via tools/pe_normalise.py.
"""
import argparse
import concurrent.futures
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "a64"))
from coff import CoffObject  # noqa: E402

# Modules whose logic is translated from x64 COFF objects (aesgcm, random, loadcfg
# are replaced in full by hand-written src/arm64/*.S).
XLAT_SOURCES = [
    "main", "console", "hardening", "sha256", "sha1", "blake2b", "argon2",
    "fileio", "secmem", "vault", "totp", "tpm", "regcfg", "pwgen", "bench",
    "log", "selftest", "redteam", "theme", "anim", "gpu", "zipexport",
    "zipimport", "gui",
]
HAND_SOURCES = ["aesgcm", "sha", "blake2b_argon2", "platform", "loadcfg"]


def find_llvm(tool):
    p = shutil.which(tool)
    if p:
        return p
    cand = Path(r"C:\Program Files\LLVM\bin") / tool
    if cand.exists():
        return str(cand)
    raise FileNotFoundError(f"LLVM tool not found: {tool} (install LLVM or add to PATH)")


def run_cmd(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        msg = (r.stdout or "") + (r.stderr or "")
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(cmd)}\n{msg.strip()}")
    return r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dbg", action="store_true")
    ap.add_argument("--probeio", action="store_true")
    ap.add_argument("--guishow", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--release", action="store_true")
    ap.add_argument("--nohw", action="store_true")
    ap.add_argument("--clean", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "bin" / "vordr-arm64.exe"))
    args = ap.parse_args()

    if args.release:
        if args.dbg or args.probeio or args.guishow:
            print("build_arm64: 'release' cannot be combined with dbg/probeio/guishow", file=sys.stderr)
            return 1
        args.strict = True

    clang = find_llvm("clang.exe")
    llvm_lib = find_llvm("llvm-lib.exe")
    ml64 = shutil.which("ml64.exe")
    link = shutil.which("link.exe")
    rc = shutil.which("rc.exe")
    if not (ml64 and link and rc):
        print("build_arm64: ml64.exe, link.exe, and rc.exe must be on PATH", file=sys.stderr)
        return 1

    work = ROOT / "obj" / "arm64"
    if args.clean and work.exists():
        shutil.rmtree(work)
    x64_dir = work / "x64"
    gen_dir = work / "gen"
    obj_dir = work / "obj"
    lib_dir = work / "lib"
    for d in (x64_dir, gen_dir, obj_dir, lib_dir, Path(args.out).parent):
        d.mkdir(parents=True, exist_ok=True)

    # Flags
    ml_defs = []
    cl_defs = []
    if args.dbg:
        ml_defs += ["/DDBG_TRACE", "/DPROBE_IO"]
        cl_defs += ["-DDBG_TRACE", "-DPROBE_IO"]
    elif args.probeio:
        ml_defs += ["/DPROBE_IO"]
        cl_defs += ["-DPROBE_IO"]
    if args.guishow:
        ml_defs += ["/DDBG_SHOW"]
        cl_defs += ["-DDBG_SHOW"]

    workers = min(8, max(2, (os.cpu_count() or 4)))

    # 1. Assemble x64 source objects into obj/arm64/x64/
    print(f"=== [arm64 1/5] assembling {len(XLAT_SOURCES)} x64 input objects ===")
    def asm_x64(mod):
        src = ROOT / "src" / f"{mod}.asm"
        obj = x64_dir / f"{mod}.obj"
        cmd = [ml64, "/c", "/nologo", "/W3", "/Zi", *ml_defs,
               f"/Fo{obj}", "/I", str(ROOT / "src"), str(src)]
        run_cmd(cmd, cwd=ROOT)
        return mod, obj

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        x64_objs = dict(ex.map(asm_x64, XLAT_SOURCES))

    # 2. Build global internal symbol table (x64 objs + hand-written public symbols)
    symtab = {}
    for mod, p in x64_objs.items():
        o = CoffObject(str(p))
        for s in o.symbols.values():
            if s.is_external and s.secnum > 0:
                symtab[s.name] = "internal"
    # Hand-written globals from aesgcm.S, sha.S, blake2b_argon2.S, platform.S, loadcfg.S
    for s in ("aes256_expand", "gcm_init", "gcm_aad", "gcm_crypt", "gcm_final",
              "gcm_seal", "gcm_open", "aes_expand_key", "aes_ecb_block", "aes_ctr_xor",
              "sha256_compress", "sha1_block", "blake2b_compress", "argon2_compress",
              "cpu_gate", "rng_fill", "ff_trap", "__security_cookie", "_load_config_used"):
        symtab[s] = "internal"
    symtab_path = work / "symtab.json"
    symtab_path.write_text(json.dumps(symtab, indent=2, sort_keys=True), encoding="utf-8")

    # 3. Translate x64 COFF objects -> AArch64 .S
    print(f"=== [arm64 2/5] translating {len(XLAT_SOURCES)} modules to AArch64 ===")
    cfg_path = ROOT / "tools" / "a64" / "config.json"
    notes_dir = work / "notes"
    notes_dir.mkdir(exist_ok=True)

    def xlat_one(mod):
        obj = x64_objs[mod]
        out_s = gen_dir / f"{mod}.S"
        nfile = notes_dir / f"{mod}.txt"
        cmd = [sys.executable, str(ROOT / "tools" / "a64" / "xlat.py"),
               "--obj", str(obj), "--out", str(out_s),
               "--config", str(cfg_path), "--symtab", str(symtab_path),
               "--notes", str(nfile)]
        run_cmd(cmd, cwd=ROOT)
        return mod, out_s

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        gen_s = dict(ex.map(xlat_one, XLAT_SOURCES))

    # Collate callback thunk report
    cb_lines = []
    for mod in XLAT_SOURCES:
        nf = notes_dir / f"{mod}.txt"
        if nf.exists():
            txt = nf.read_text(encoding="utf-8").strip()
            if txt:
                cb_lines.append(txt)
    (work / "callbacks.txt").write_text("\n".join(cb_lines) + "\n", encoding="utf-8")
    print(f"    generated {sum(len(x.splitlines()) for x in cb_lines)} Windows callback thunks (see obj/arm64/callbacks.txt)")

    # 4. Assemble all AArch64 .S -> ARM64 COFF .obj + generate ARM64 import .libs
    all_s = [(mod, gen_s[mod], obj_dir / f"{mod}.obj") for mod in XLAT_SOURCES]
    all_s += [(mod, ROOT / "src" / "arm64" / f"{mod}.S", obj_dir / f"a64_{mod}.obj") for mod in HAND_SOURCES]
    print(f"=== [arm64 3/5] assembling {len(all_s)} AArch64 objects (clang -march=armv8.2-a+crypto) ===")

    def asm_a64(item):
        mod, src, dst = item
        cmd = [clang, "--target=aarch64-pc-windows-msvc", "-march=armv8.2-a+crypto",
               "-c", *cl_defs, str(src), "-o", str(dst)]
        run_cmd(cmd, cwd=ROOT)
        return dst

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        arm_objs = list(ex.map(asm_a64, all_s))

    # Import libraries from tools/arm64_defs/*.def
    def_files = sorted((ROOT / "tools" / "arm64_defs").glob("*.def"))
    print(f"=== [arm64 4/5] generating {len(def_files)} ARM64 import libraries ===")
    def mk_lib(df):
        out_lib = lib_dir / (df.stem + ".lib")
        if not out_lib.exists() or out_lib.stat().st_mtime < df.stat().st_mtime:
            run_cmd([llvm_lib, f"/def:{df}", "/machine:arm64", f"/out:{out_lib}"], cwd=ROOT)
        return out_lib

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        arm_libs = list(ex.map(mk_lib, def_files))

    # Compile resource file (VERSIONINFO + dialogs + icons)
    res_out = work / "vordr.res"
    rc_cmd = [rc, "/nologo", f"/fo{res_out}", str(ROOT / "vordr.rc")]
    run_cmd(rc_cmd, cwd=ROOT)

    # 5. Link native ARM64 PE
    out_exe = Path(args.out)
    pdb_out = out_exe.with_suffix(".pdb")
    map_out = out_exe.with_suffix(".map")
    repro_flags = ["/Brepro", f"/pdbaltpath:{pdb_out.name}", "/OPT:REF"] if args.release else []
    print(f"=== [arm64 5/5] linking {out_exe} (/machine:arm64) ===")
    link_cmd = [
        link, "/nologo", "/machine:arm64", "/subsystem:windows",
        "/entry:wstart", "/nodefaultlib", "/incremental:no",
        "/dynamicbase", "/highentropyva", "/nxcompat", "/largeaddressaware",
        *repro_flags,
        "/debug", f"/pdb:{pdb_out}", f"/map:{map_out}",
        "/manifest:embed", f"/manifestinput:{ROOT / 'vordr.manifest'}", "/manifestuac:no",
        f"/out:{out_exe}",
        *[str(o) for o in arm_objs],
        str(res_out),
        *[str(l) for l in arm_libs],
    ]
    run_cmd(link_cmd, cwd=ROOT)

    if args.release:
        print("=== [arm64] release normalisation + SHA-256 (bin\\SHA256SUMS.txt) ===")
        run_cmd([sys.executable, str(ROOT / "tools" / "pe_normalise.py"), str(out_exe)], cwd=ROOT)
        digest = hashlib.sha256(out_exe.read_bytes()).hexdigest()
        sums_path = out_exe.parent / "SHA256SUMS.txt"
        entries = {}
        if sums_path.exists():
            lines = [ln.strip() for ln in sums_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            i = 0
            while i + 1 < len(lines):
                if lines[i].lower().endswith(".exe"):
                    entries[lines[i]] = lines[i + 1]
                    i += 2
                else:
                    i += 1
        entries[out_exe.name] = digest
        ordered = []
        for k in ("vordr.exe", "vordr-arm64.exe"):
            if k in entries:
                ordered.append(f"{k}\n{entries.pop(k)}")
        for k, v in sorted(entries.items()):
            ordered.append(f"{k}\n{v}")
        sums_path.write_text("\n".join(ordered) + "\n", encoding="utf-8")
        print(f"{out_exe.name}\n{digest}")

    print(f"BUILD OK: {out_exe} ({out_exe.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"BUILD FAILED:\n{e}", file=sys.stderr)
        sys.exit(1)
