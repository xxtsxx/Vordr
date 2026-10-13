# Assurance and verification

[Documentation](README.md) · [Visual guide](assurance.html) · [Secret memory](SECRETS.md)

This guide maps claims to tests and explains their limits. It is not a
certification, a live CI dashboard, or a claim that every possible input is safe.
No independent external security review is recorded in the repository.

## Reproduce the checks

Use Windows with the x64 MSVC/SDK toolchain and Python 3 on PATH. Read the
[test-safety warning](DEVELOPMENT.md#full-test-gate-read-before-running) first:
the full driver stops running Vordr processes and replaces build outputs.

```bat
tests\run_all.cmd
```

For crypto checks against an existing executable:

```bat
python tests\verify_crypto.py --exe bin\vordr.exe
```

For the vault format and compatibility (a `probeio` or `dbg` build), the
external GUI tests, and proof that a release reproduces:

```bat
python tests\verify_vault.py bin\vordr.exe
python tests\compattest.py bin\vordr.exe
powershell -NoProfile -ExecutionPolicy Bypass -File tests\guitest.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tools\verify_repro.ps1
```

Record the commit, toolchain, command, exit status, and complete logs. Do not copy
an old count of passing tests into a claim about a new revision.

## The six-stage gate

```mermaid
flowchart LR
    A["1. Fault injection"] --> B["2. Strict build"]
    B --> C["3. Self-tests"]
    C --> D["4. Round-trip probes"]
    D --> E["5. Crypto cross-check"]
    E --> F["Restore normal build"]
    F --> G["6. MSI verification"]
```

| Stage | Evidence produced | Important limit |
|---|---|---|
| Fault injection | Deliberate canary, shadow-stack, indirect-call, arithmetic, bounds, type, heap-tag, and IAT violations each end the process with that control's own fail-fast code (`tests/redteam.py`); an ordinary access violation is contained (0xC0000409, no crash dialog) with a breadcrumb naming the fault | Checks termination behavior, not all paths; the IAT case shows the slot is read-only at the write, not that `iat_lockdown` alone made it so |
| Strict build | Nine Python source checkers plus assembly/resource/link success; framecheck warnings gate too | Python absence skips source checks; pattern-based checkers have blind spots |
| Self-tests | Known-answer checks pass; normal release rejects diagnostic file-writing verbs in the following stage | Fixed vectors exercise selected cases |
| Round-trip | Serialization, imports/exports, attachments, policy, locking, parsers, preview cleanup, and persistence probes; an independent reader of the vault format; frozen v0.2.3 vaults; a real, isolated GUI instance driven from outside | Synthetic and bounded input space; geometry and GUI tests skip without a desktop |
| Crypto differential | Output compared with independent Python calculations and published vectors | Functional output checks, not a side-channel proof |
| Installer | MSI tables and component costing checked | Does not install, upgrade, or uninstall the program |

`--quick` skips fault injection. Missing Python can skip crypto/persistence
checks; missing `makecab` can skip the installer stage. The final banner treats
allowed skips as success. A release review must explicitly inspect them.

## Cryptographic checks

`katreport` emits deterministic outputs for public inputs. The verifier uses
Python's `hashlib`, `hmac`, and base32 support, plus an in-file AES-GCM
reference that first checks itself against a fixed GCM vector.

| Primitive | Independent comparison or vector source |
|---|---|
| SHA-256 | Python hashlib; published “abc” digest and block-boundary inputs |
| BLAKE2b | Python hashlib; RFC 7693 digest and block-boundary inputs |
| HMAC-SHA1 | Python hmac; RFC 2202 cases |
| AES-256-GCM | In-file Python implementation; fixed GCM vectors, AAD, partial and empty plaintext |
| Argon2id | RFC 9106 §5.3 vector, and the reference implementation's `test.c` vector (t=2, 64 MiB, p=1), which - unlike the RFC's two-block segments - regenerates the address block past 128 blocks as every real vault does |
| HOTP/TOTP | HMAC-based recomputation; RFC 4226 HOTP values and time-step inputs |
| Base32 | Python base64 implementation |

`tests/verify_vault.py` carries a second, independent Argon2id, written from
RFC 9106 and checked against the RFC's vector before it is trusted. It decrypts
real vault files - header, KCV, body, every attachment, the file MAC - using only
`docs/formats.md`, the Python standard library and the self-checked pure-Python
AES-GCM of `verify_crypto.py` (no third-party package), including a vault whose KDF
segments are 2048 blocks long. A writer and reader that share a mistake agree
with each other; this reader shares nothing, so a drift between Vordr and its
published format fails here whichever side moved. The same test flips a byte in
every region of the file and requires both Vordr (`vopen`) and the independent
reader to refuse it, and checks that each save uses a fresh body nonce under the
unchanged key.

A correct output on these inputs does not establish general correctness or
constant-time behavior. `cttest` is a debug timing probe, not a gate-level
side-channel guarantee. For negative controls, use a disposable checkout to
alter an expected result and confirm the verifier reports a mismatch; it does
not expose a command-line option for reading an edited report file.

## Static checks

| Checker under `tools/` | Detects |
|---|---|
| `framecheck.py` | Stack/frame and call-argument layout problems, including a raw epilogue that gives back a different size than its prologue took |
| `nvcheck.py` | A procedure that writes a callee-saved register (rbx, rsi, rdi, r12-r15, xmm6-15) without saving and restoring it |
| `idcheck.py` | Resource/assembly control-ID drift and collisions |
| `constcheck.py` | Inconsistent constants between modules |
| `dlgtarget.py` | Controls addressed through the wrong known dialog, including settings-table ownership |
| `deadcode.py` | Apparently unreferenced symbols |
| `rccheck.py` | Resource-template geometry problems |
| `wstrcheck.py` | Bounded string-copy calls missing their bound |
| `aligncheck.py` | Misaligned wide-string declarations (sizes written as names or expressions are resolved, not guessed) |

These are source-pattern checks, not a complete compiler or program proof.
A refactor can reduce what a checker recognizes without introducing a reported
failure. Inspect coverage and unknown cases when changing the patterns it scans.

## Regression map

The executable commands and their arguments are defined by
[the test driver](../tests/run_all.cmd); some intentionally return a count
rather than the conventional zero-on-success result.

| Area | Relevant probes |
|---|---|
| Secret cleanup and allocation | `secscan`, `secfreedup`, `lktest`, `tmptest` |
| Input parsing and bounds | `vfuzz`, `fuzzzip`, `jfuzz`, `attfuzz`, `kdfparam`, `convcap` |
| Save integrity and concurrency | `bktest`, `mactest`, `rbtest`, `xctest`, `reload`, `cowrite` |
| Native exchange and metadata | `sysitemkat`, `vexselkat`, `c9kat`, `vimpkat`, `vaultexportkat`, `vaultexpattkat` |
| ZIP export | `atgen`, `zitest`, `zexcap`, `zexname` |
| GUI geometry and failed-edit retry | `layoutkat` (with `savefail` and `guardkat` in the same window) |
| GUI behaviour from outside | `tests/guitest.ps1`: input limits, the drawn scrollbars (entry list, checklist, detail pane), lock while a dialog is open, what a lock wipes, GDI leaks |
| Vault format, tamper and nonce reuse | `tests/verify_vault.py` |
| Opening vaults written by a release | `tests/compattest.py` (frozen `tests/fixtures/v023-*.vordr`) |
| Long-path context restoration | `tests/verify_persistence.py` |

`secscan` checks its planted sentinel after a selected wipe path. It does not
inventory every possible plaintext copy, prove pagefile/hibernation exclusion,
or guarantee cleanup after arbitrary process termination.

The secure allocator tracks currently live base addresses. This prevents
repeated frees of an address that is no longer registered; it is not a general
solution to stale pointers if an address has since been reused.

## Historical regression context

Earlier documentation described the following bugs and their regression tests.
This list preserves that engineering context; it does not establish affected
release ranges or replace a security advisory.

| Prior failure mode | Regression or control |
|---|---|
| ZIP central-directory array overflow | `zexcap` capacity guard |
| Unbounded pre-authentication KDF costs | `vk_params_ok`, `kdfparam` |
| JSON parse cursor not advancing | Forward-progress checks, `jfuzz` |
| Unbounded attachment-filename conversion | Bounded conversion and export tests |
| Attachment-length arithmetic wrap | Validate before arithmetic in vault open |
| Repeated secure-buffer free during context teardown | Live allocation registry, `secfreedup` |
| Failed GUI save losing the editable transaction | Original-body/history restoration, `layoutkat` |
| Preview cleanup forgotten while a viewer held the file | Retained cleanup tracking, `tmptest` |
| Long vault paths truncated during temporary context switches | `verify_persistence.py` |

## Does a test catch what it was written for?

A regression test that passes against the code it was written to catch proves
nothing. For the tests that live outside the binary, `tools\compare.ps1 <test>
-Ref <commit>` builds the older commit in a temporary worktree, runs today's test
against it and against the working tree, and succeeds only if the old build fails
and the new one passes. For the in-binary probes, which travel with the code they
test, the equivalent is a sabotage build: revert the fix, rebuild, and confirm the
probe fails.

Use [release records](RELEASES.md) and [the security policy](../SECURITY.md)
for release-specific disclosure. Neither this table nor a passing test suite
should be interpreted as a “clean bill of security.”

## Checks that still require a person

- Inspect GUI layout, focus, keyboard operation, private-desktop fallback, and
  lock/unlock transitions on supported machines.
- Test real MSI upgrade and uninstall behavior in an isolated environment.
- Verify backup restoration and conflict behavior on the intended storage.
- Evaluate attacker reachability, crypto composition, and side channels.
- Rebuild the exact release with a matching toolchain and compare its bytes.
