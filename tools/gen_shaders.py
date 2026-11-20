#!/usr/bin/env python3
"""gen_shaders.py - compile HLSL compute shaders into MASM .inc byte tables.

Uses the Windows SDK fxc.exe with /O3 /Gis /Qstrip_reflect /Qstrip_debug
/Qstrip_priv so the emitted DXBC contains zero machine-specific paths or
timestamps and reproduces byte-for-byte across machines.
"""
import ctypes
import math
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def find_fxc() -> str | None:
    w = shutil.which("fxc") or shutil.which("fxc.exe")
    if w:
        return w
    sdk = Path(r"C:\Program Files (x86)\Windows Kits\10\bin")
    if sdk.is_dir():
        for cand in sorted(sdk.glob("10.*/x64/fxc.exe"), reverse=True):
            return str(cand)
    return None


def _blob_bytes_and_release(blob_ptr: ctypes.c_void_p) -> bytes:
    vtbl = ctypes.cast(
        ctypes.cast(blob_ptr, ctypes.POINTER(ctypes.c_void_p))[0],
        ctypes.POINTER(ctypes.c_void_p),
    )
    get_ptr = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(vtbl[3])
    get_sz = ctypes.WINFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p)(vtbl[4])
    release = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vtbl[2])
    ptr = get_ptr(blob_ptr)
    sz = get_sz(blob_ptr)
    data = ctypes.string_at(ptr, sz)
    release(blob_ptr)
    return data


def compile_hlsl_dll(hlsl_path: Path, profile: str, entry: str) -> bytes:
    dll = ctypes.WinDLL("D3DCompiler_47.dll")
    src_bytes = hlsl_path.read_bytes()
    code_blob = ctypes.c_void_p()
    err_blob = ctypes.c_void_p()
    # D3DCOMPILE_IEEE_STRICTNESS (0x2000) | D3DCOMPILE_OPTIMIZATION_LEVEL3 (0x8000)
    flags1 = 0x2000 | 0x8000
    d3d_compile = dll.D3DCompile
    d3d_compile.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
        ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
    ]
    d3d_compile.restype = ctypes.c_long
    hr = d3d_compile(
        src_bytes, len(src_bytes), None, None, None,
        entry.encode("ascii"), profile.encode("ascii"),
        flags1, 0, ctypes.byref(code_blob), ctypes.byref(err_blob),
    )
    if hr < 0:
        msg = _blob_bytes_and_release(err_blob).decode("utf-8", "replace") if err_blob else f"HRESULT 0x{hr & 0xFFFFFFFF:08X}"
        sys.stderr.write(msg)
        raise SystemExit(1)
    if err_blob:
        _blob_bytes_and_release(err_blob)
    raw_dxbc = _blob_bytes_and_release(code_blob)

    stripped_blob = ctypes.c_void_p()
    d3d_strip = dll.D3DStripShader
    d3d_strip.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    d3d_strip.restype = ctypes.c_long
    # STRIP_REFLECTION_DATA (1) | STRIP_DEBUG_INFO (2) | STRIP_PRIVATE_DATA (8)
    hr2 = d3d_strip(raw_dxbc, len(raw_dxbc), 1 | 2 | 8, ctypes.byref(stripped_blob))
    if hr2 < 0 or not stripped_blob:
        return raw_dxbc
    return _blob_bytes_and_release(stripped_blob)


def compile_hlsl(fxc: str | None, hlsl_path: Path, profile: str, entry: str) -> bytes:
    if not fxc:
        return compile_hlsl_dll(hlsl_path, profile, entry)
    out_bin = ROOT / "obj" / (hlsl_path.stem + ".dxbc")
    out_bin.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        fxc, "/nologo",
        "/T", profile,
        "/E", entry,
        "/O3", "/Gis",
        "/Qstrip_reflect", "/Qstrip_debug", "/Qstrip_priv",
        "/Fo", str(out_bin),
        str(hlsl_path),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stdout + res.stderr)
        raise SystemExit(res.returncode)
    data = out_bin.read_bytes()
    out_bin.unlink(missing_ok=True)
    return data


def emit_masm_inc(label: str, data: bytes, src_rel: str, dst_path: Path) -> None:
    lines = [
        f"; Auto-generated from {src_rel} by tools/gen_shaders.py - DO NOT EDIT BY HAND.",
        f"; DXBC size: {len(data)} bytes (cs_5_0, stripped of debug/reflect/priv).",
        "align 4",
        f"{label} label byte",
    ]
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexes = ",".join(f"0{b:02X}h" for b in chunk)
        lines.append(f"    db {hexes}")
    lines.append(f"{label}_len equ {len(data)}")
    lines.append("")
    lines.append("; Exact Q14 Rodrigues hue-rotation trig LUTs (256 steps over 0..2*pi)")
    lines.append("align 4")
    lines.append("gpu_ca_lut label dword")
    ca_vals = [int(round(math.cos(2.0 * math.pi * i / 256.0) * (16384.0 / 3.0))) for i in range(256)]
    for off in range(0, 256, 8):
        lines.append("    dd " + ",".join(str(v) for v in ca_vals[off:off + 8]))
    lines.append("gpu_sa_lut label dword")
    sa_vals = [int(round(math.sin(2.0 * math.pi * i / 256.0) * (16384.0 / math.sqrt(3.0)))) for i in range(256)]
    for off in range(0, 256, 8):
        lines.append("    dd " + ",".join(str(v) for v in sa_vals[off:off + 8]))
    lines.append("")
    dst_path.write_text("\r\n".join(lines), encoding="ascii", newline="")


def main() -> int:
    fxc = find_fxc()
    src = HERE / "backdrops.hlsl"
    dxbc = compile_hlsl(fxc, src, "cs_5_0", "CSMain")
    dst = ROOT / "src" / "gpu_backdrops.inc"
    emit_masm_inc("gpu_cs_backdrops", dxbc, "tools/backdrops.hlsl", dst)
    print(f"gen_shaders: {src.name} -> {dst.relative_to(ROOT)} ({len(dxbc)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
