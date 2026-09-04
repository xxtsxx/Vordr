"""Regression gate for preview cleanup and long-path vault context restoration.

Requires a PROBE_IO build. All files are synthetic and confined to a fresh temp
directory; no running Vordr instance is stopped and no user vault is opened.
The GUI save-failure/retry regression runs as part of layoutkat in run_all.cmd.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    args = parser.parse_args()
    exe = str(Path(args.exe).resolve())
    root = Path(tempfile.mkdtemp(prefix="vordr-persistence-"))
    # Python itself may lack longPathAware; prefix filesystem operations while
    # deliberately passing ordinary, unprefixed paths to Vordr.
    owned_root = Path("\\\\?\\" + str(root)) if os.name == "nt" else root
    try:
        deep = root / ("a" * 90) / ("b" * 90) / ("c" * 60)
        (owned_root / deep.relative_to(root)).mkdir(parents=True)
        env = os.environ.copy()
        env["TEMP"] = env["TMP"] = str(root)
        cases = [("preview cleanup", ["tmptest"])]
        for label, directory in (("short", root), ("long", deep)):
            for command in ("vexselkat", "vimpkat"):
                path = directory / (command + ".vordr")
                if label == "long":
                    assert len(str(path)) > 260
                cases.append((label + " " + command, [command, str(path)]))
        for label, command in cases:
            result = subprocess.run(
                [exe, *command], env=env, capture_output=True, text=True, timeout=60
            )
            if result.returncode:
                raise RuntimeError(
                    f"{label}: exit {result.returncode}\n{result.stdout}{result.stderr}"
                )
            print(f"PASS: {label}", flush=True)
        print("Persistence regressions: PASS", flush=True)
    finally:
        shutil.rmtree(owned_root)


if __name__ == "__main__":
    main()
