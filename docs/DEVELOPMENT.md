# Development

[Documentation](README.md) · [Architecture](ARCHITECTURE.md) · [Assurance](ASSURANCE.md)

## Toolchain

Use Windows x64 and an **x64 Native Tools Command Prompt** with:

- Visual Studio Build Tools: `ml64.exe` and `link.exe`.
- A Windows 10 SDK: `rc.exe`, headers, and import libraries.
- Python 3 on PATH for static checks and differential/regression tests.
- Windows PowerShell, Windows Installer, and `makecab.exe` for MSI checks.

The application has no third-party runtime packages. The build still trusts
the assembler, linker, SDK, Windows, and hardware; assembly does not eliminate
that toolchain trust. The checked-in CI workflow also uses GitHub Actions.

The build locates a Windows SDK under the standard Windows Kits directory.
Inspect `build.cmd` if your toolchain uses a nonstandard installation.

## Build variants

Run these from the repository root:

| Command | Output and intended use |
|---|---|
| `build.cmd` | Normal executable; static checker failures are advisory |
| `build.cmd strict` | Normal executable; checker nonzero exits fail the build |
| `build.cmd release strict` | Reproducible-link flags plus strict checks; use for release preparation |
| `build.cmd probeio strict` | File-writing diagnostic verbs for synthetic tests |
| `build.cmd dbg strict` | Debug traces and fault injection; includes probe I/O |
| `build.cmd nohw strict` | Omits CET compatibility; keeps software checks |
| `build.cmd dbg guishow` | Development-only GUI startup shortcut; never ship |

Arguments are combinable. All variants overwrite `bin\vordr.exe` and write
intermediates under `obj\`. `release` selects deterministic linker flags;
it is not a prohibition on adding diagnostic flags. Never combine shipping
builds with `dbg`, `probeio`, or `guishow`.

Python is required for meaningful strict verification: the current build skips
its Python checkers if Python is missing, even with `strict`.

## Run diagnostics

A normal build exposes `selftest` and `katreport`. Other diagnostic verbs
are gated to test/debug builds. No master password or secret is accepted on
the command line.

```bat
bin\vordr.exe selftest
python tests\verify_crypto.py --exe bin\vordr.exe
```

The GUI-subsystem executable may not wait or display output like a console
program in every shell. The Python verifier captures its child process output.
Use the supplied test driver for the complete suite.

A `.vordr` path passed to the normal GUI is an import source, not a command-line
unlock or a request to replace the configured vault.

## Full test gate: read before running

**Run the full gate on a development machine or disposable VM with no real vault
open.** `tests\run_all.cmd` forcibly stops processes named `vordr.exe`,
recreates `%TEMP%\vordr_runall`, overwrites build outputs, and replaces matching
MSI outputs in `bin\`. Do not run it during an editing or preview session.

```bat
tests\run_all.cmd
```

The six stages are fault injection, strict build, self-tests, round-trip probes,
crypto differential checks, and MSI build/verification. `--quick` skips fault
injection. A successful summary can still include skips: Python-dependent
checks, installer checks, and desktop-dependent geometry checks have documented
skip paths. Check the actual log, not just the final banner.

Logs are under `%TEMP%\vordr_runall`. The script rebuilds a normal executable
after the probe stage; release preparation must separately build the exact
reproducible artifact intended for publication.

For a narrower persistence test with an existing probe build:

```bat
python tests\verify_persistence.py --exe bin\vordr.exe
```

That harness uses fresh synthetic temporary files and does not stop a running
Vordr instance. It exercises preview cleanup and short/long-path native
export/import. It is not a replacement for the full GUI or release tests.

## Change workflow

1. Use a separate checkout when working with release tags or destructive tests.
2. Read the relevant module and its guide; preserve the Win64 calling convention
   and the shared frame/guard macros.
3. Add a regression for the failure mode, preferably with a negative control.
4. Run the relevant static checkers and a strict build with Python present.
5. Exercise the affected feature using a synthetic vault.
6. For GUI changes, check resize, DPI, focus, keyboard navigation, lock/unlock,
   and policy-disabled controls. Geometry checks alone do not establish usability.
7. Update documentation and record which tests ran or were skipped.

Use [settings design](SETTINGS_DESIGN.md) when adding a setting, and
[system items](SYSITEM_DESIGN.md) when adding per-vault metadata.
Do not publish test vaults, real screenshots, clipboard contents, or crash dumps
that may contain secrets.

## CI and releases

[The build workflow](../.github/workflows/build.yml) runs on pushes, pull requests,
manual dispatch, and a nightly schedule. It runs the gate, creates a separate
reproducible executable, and uploads the executable and crypto-check output.
Stage logs are uploaded on failure.

A CI artifact is not automatically a tagged release. Follow the
[release checklist](RELEASE_CHECKLIST.md), including testing the exact MSI
payload and preserving published hashes.

## Documentation checks

Run `python tools\check_docs.py` to check local Markdown/HTML links, Markdown
anchors, duplicate headings, code fences, and unexpected control characters.
The checker does not fetch external links, execute examples, or validate
security claims. Review those against their source separately.

Its regression tests run without the application or Windows build tools:

```bat
python -m unittest discover -s tests -p test_docs.py
```
