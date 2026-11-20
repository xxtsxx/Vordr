#!/usr/bin/env python3
"""test_arm64_e2e.py - end-to-end verification of native ARM64 Vordr binaries.

Runs real linked ARM64 PE binaries (`bin/vordr-arm64.exe` and optional
`obj/arm64/vordr-arm64-probeio.exe`) from `wstart` to `ExitProcess` under
`tools/a64/emu.py` (Unicorn ARM64 CPU + MMU protection enforcement):

  1. Release `selftest` (all 23 startup + CLI KATs, IAT & _ROINIT sealed RO)
  2. Release `selftest` with FEAT_RNG disabled (CP 4030 = 0, BCryptGenRandom-only)
  3. Release `cpu_gate` fail-closed check (PF_ARM_V8_CRYPTO=0 -> EXIT_NOCPU=6)
  4. Release `genpw` output sanity
  5. Release path-verb refusal (`seedtest` refused, no file written)
  6. Probeio KAT suite (if `obj/arm64/vordr-arm64-probeio.exe` exists):
     `pinkat`, `healthkat`, `sysitemkat`, `attovfkat`, `vattcolkat`,
     `zexselkat`, `vimpattkat`, `katreport`, and cross-architecture
     `seedtest` vault verification with `tests/verify_vault.py`.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "a64"))
from emu import Arm64PeEmu  # noqa: E402


def run_arm64(exe, args, feat_rng=True, crypto_ok=True):
    emu = Arm64PeEmu(str(exe), [str(exe), *args], feat_rng=feat_rng)
    if not crypto_ok:
        emu.api_IsProcessorFeaturePresent = lambda: 0
    try:
        rc = emu.run()
        out = emu.stdout.decode("utf-8", "replace")
        err = emu.stderr.decode("utf-8", "replace")
        return rc, out, err, emu.iat_locked, emu.roinit_locked, emu.api_calls
    finally:
        emu.close()


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def main():
    rel = ROOT / "bin" / "vordr-arm64.exe"
    check(rel.exists(), f"missing {rel} - run build_arm64.cmd first")

    print("[1] release selftest (FEAT_RNG=1, IAT+ROINIT RO)")
    rc, out, err, iat_ro, ro_ro, calls = run_arm64(rel, ["selftest"], feat_rng=True)
    check(rc == 0, f"selftest rc={rc}\n{out}\n{err}")
    check("all self-tests passed" in out, f"missing pass banner:\n{out}")
    check(out.count("[PASS]") >= 23, f"expected >=23 [PASS], got {out.count('[PASS]')}")
    check(iat_ro and ro_ro, f"hardening lock missing: iat_ro={iat_ro} roinit_ro={ro_ro}")
    print(f"    PASS ({out.count('[PASS]')} KATs, {calls} Win32 calls, iat_ro={iat_ro}, roinit_ro={ro_ro})")

    print("[2] release selftest (FEAT_RNG=0, BCryptGenRandom-only)")
    rc, out, err, _, _, _ = run_arm64(rel, ["selftest"], feat_rng=False)
    check(rc == 0 and "all self-tests passed" in out, f"selftest(no-rng) rc={rc}\n{out}\n{err}")
    print("    PASS")

    print("[3] release cpu_gate fail-closed (PF_ARM_V8_CRYPTO=0 -> EXIT_NOCPU=6)")
    rc, out, err, _, _, _ = run_arm64(rel, ["selftest"], crypto_ok=False)
    check(rc == 6, f"expected EXIT_NOCPU(6), got rc={rc}\n{out}\n{err}")
    print("    PASS (rc=6)")

    print("[4] release katreport (byte-identical to x64 bin\\vordr.exe katreport)")
    rc, out, err, _, _, _ = run_arm64(rel, ["katreport"])
    check(rc == 0 and len(out.strip().splitlines()) >= 10, f"katreport failed: rc={rc}\n{out}\n{err}")
    x64_exe = ROOT / "bin" / "vordr.exe"
    if x64_exe.exists():
        xr = subprocess.run([str(x64_exe), "katreport"], capture_output=True, text=True, check=True)
        check(out.replace("\r\n", "\n") == xr.stdout.replace("\r\n", "\n"),
              f"ARM64 katreport differs from x64!\n--- ARM64 ---\n{out}\n--- x64 ---\n{xr.stdout}")
        print(f"    PASS ({len(out.strip().splitlines())} lines, byte-identical to x64)")
    else:
        print(f"    PASS ({len(out.strip().splitlines())} lines)")

    print("[5] release refuses path-taking verb (seedtest)")
    with tempfile.TemporaryDirectory(prefix="vordr_a64_rel_") as td:
        probe = Path(td) / "refused.vordr"
        rc, out, err, _, _, _ = run_arm64(rel, ["seedtest", str(probe)])
        check(rc != 0 and not probe.exists(), f"release accepted seedtest! rc={rc}")
    print(f"    PASS (refused rc={rc})")

    probe_exe = ROOT / "obj" / "arm64" / "vordr-arm64-probeio.exe"
    if probe_exe.exists():
        zero_arg = (
            "genpw", "pinkat", "healthkat", "attovfkat", "zexselkat",
            "kdfparam", "fztest", "zexcap", "zexname", "convcap",
            "secfreedup", "trtest", "vfuzz", "fuzzzip", "jfuzz", "attfuzz",
        )
        print(f"[6] probeio 0-arg KATs & fuzzers ({len(zero_arg)} verbs)")
        for verb in zero_arg:
            rc, out, err, _, _, _ = run_arm64(probe_exe, [verb])
            check(rc == 0, f"{verb} failed: rc={rc}\n{out}\n{err}")
            tail = out.strip().splitlines()[-1] if out.strip() else "ok"
            print(f"    [PASS] {verb:<12} ({tail[:72]})")

        one_arg = ("sysitemkat", "vattcolkat", "vexselkat", "vimpkat", "vimpattkat", "mactest")
        print(f"[7] probeio file/vault KATs ({len(one_arg)} verbs)")
        with tempfile.TemporaryDirectory(prefix="vordr_a64_kats_") as td:
            for verb in one_arg:
                fp = Path(td) / f"{verb}.vordr"
                rc, out, err, _, _, _ = run_arm64(probe_exe, [verb, str(fp)])
                check(rc == 0, f"{verb} failed: rc={rc}\n{out}\n{err}")
                tail = out.strip().splitlines()[-1] if out.strip() else "ok"
                print(f"    [PASS] {verb:<12} ({tail[:72]})")

            print("[8] cross-architecture vault: ARM64 vattgen -> Python verify_vault.py + ARM64 vopen on frozen x64 fixture")
            vpath = Path(td) / "arm64_vattgen.vordr"
            rc, out, err, _, _, _ = run_arm64(probe_exe, ["vattgen", str(vpath)])
            check(rc == 0 and vpath.exists(), f"vattgen failed: rc={rc}\n{out}\n{err}")
            raw = vpath.read_bytes()
            check(raw[:4] == b"VRDR", f"bad vault magic: {raw[:4]!r}")
            # Verify with independent pure-Python reader tests/verify_vault.py
            sys.path.insert(0, str(ROOT / "tests"))
            import verify_vault as vv  # noqa: E402
            parsed = vv.parse(raw, b"vordrtest")
            check(len(parsed["entries"]) == 1 and len(parsed["attachments"]) == 2 and parsed["counter"] == 4,
                  f"unexpected parsed vault: {parsed}")
            print(f"    [PASS] ARM64 vattgen ({len(raw)} B, 1 entry, 2 attachments, ctr=4) verified by independent Python reader")
            # Open frozen v0.2.3 x64 fixture vaults with ARM64 vopen (password "vordrtest")
            fix = ROOT / "tests" / "fixtures"
            for name, expect_rc in (
                ("v023-attachments.vordr", 0),
                ("v023-m8mib.vordr", 0),
                ("v023-export.vordr", 9),  # encrypted with "exportpw2", must fail auth
            ):
                fx = fix / name
                if fx.exists():
                    rc, out, err, _, _, _ = run_arm64(probe_exe, ["vopen", str(fx)])
                    check(rc == expect_rc, f"ARM64 vopen on x64 fixture {name}: got rc={rc}, expected {expect_rc}\n{out}\n{err}")
                    desc = "decrypted" if expect_rc == 0 else "rejected wrong-password"
                    print(f"    [PASS] ARM64 vopen {desc} x64 fixture {name} (rc={rc})")
    else:
        print("[6-8] skipped (obj/arm64/vordr-arm64-probeio.exe not built)")

    print("ALL ARM64 E2E TESTS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
