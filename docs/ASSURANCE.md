# Vordr Assurance Report

> A one-page visual summary of this report is in [`assurance.html`](assurance.html)
> (open it in a browser) — the gate stages, crypto-check counts, memory-safety
> controls, findings, and the vault export/import round-trips at a glance.

**Scope:** how Vordr's quality and security claims are *proven*, and how an
independent auditor reproduces every proof from a clean checkout. Nothing here
asks you to trust the authors — each claim below names the mechanism, the test
that exercises it, and the command that reproduces it. Where a claim rests on
cryptographic correctness, the proof is cross-checked against an *independent*
implementation and the *official published* test vectors, not Vordr's own word.

Vordr is a password manager written from scratch in x64 MASM assembly (Windows,
GUI subsystem). It implements its own SHA-256, SHA-1, BLAKE2b, HMAC, AES-256-GCM,
Argon2id and HOTP/TOTP; its own vault-file format, ZIP import/export, and
registry/config handling; and a set of runtime memory-safety controls.

---

## 0. One-command reproduction

From a clean checkout on Windows with the x64 MSVC toolchain (`ml64`, `link`,
`rc`) and Python 3 on `PATH`:

```
tests\run_all.cmd
```

This is the single gate. It runs, in order: the redteam fault-injection suite,
the strict release build, the startup self-tests, the headless roundtrip probes,
and the independent crypto differential check. Exit code `0` iff every stage
passes. The same gate runs in CI on every push (`.github/workflows/build.yml`).

The most externally-meaningful single check — crypto correctness against public
vectors — can be run on its own against a prebuilt binary:

```
python tests\verify_crypto.py --exe bin\vordr.exe
```

---

## 1. Cryptographic correctness — proven against independent + published references

**Claim:** Vordr's hand-written assembly crypto produces bit-exact, standards-
correct output.

**Why you can believe it without trusting Vordr:** the proof is *differential*.

- `vordr katreport` (source: `src/selftest.asm`, `cmd_katreport`) runs a fixed,
  deterministic battery of every primitive over public inputs and prints each
  result as `<label> [counter] <hex>`. The inputs are baked into the binary
  (published RFC/NIST vectors + fixed patterns); no secret ever crosses the
  command line, and output is byte-identical on any machine.
- `tests/verify_crypto.py` is a **dependency-free** (Python 3 stdlib only)
  independent reference. It:
  1. recomputes every primitive with `hashlib`/`hmac` and a **self-contained
     pure-Python AES-256-GCM** that first validates *itself* against the NIST
     SP800-38D all-zero vector before it is trusted to judge anything;
  2. checks the **official published** FIPS/RFC/NIST vectors, each cited in-file;
  3. diffs Vordr's `katreport` output against both.

**Result (this revision):** `33 differential / 0 fail` and `17 published / 0 fail`.

**Not rubber-stamping — negative control:** feeding the verifier a single tampered
output line makes it exit non-zero and print the exact mismatch. The check has
teeth; a wrong implementation would be caught.

### Vector provenance

| Primitive | Independent recompute | Published vector cited |
|---|---|---|
| SHA-256 | `hashlib.sha256` (empty, "abc", FIPS 2-block, 1000×'a') | FIPS 180-4 App. B.1 ("abc") |
| BLAKE2b-512 | `hashlib.blake2b` (empty, "abc", fox) | RFC 7693 App. A ("abc") |
| HMAC-SHA1 | `hmac`+`hashlib.sha1` (2 RFC cases + custom) | RFC 2202 cases 1 & 2 |
| AES-256-GCM | pure-Python AES-GCM (zero, AAD, 20-byte partial, empty-pt) | NIST SP800-38D Test Case 14 |
| Argon2id | (no stdlib ref) | RFC 9106 §5.3 |
| HOTP | `hmac` HOTP, counters 0–9 | RFC 4226 App. D (all 10) |
| TOTP | `hmac` HOTP at RFC-6238 time-step counters | RFC 6238 time-step derivation |
| base32 | `base64.b32decode` | RFC 4648 alphabet |

Vordr additionally re-runs its embedded KATs at **every launch** as a fail-closed
startup gate (`run_selftest`, `src/selftest.asm`) and in a threaded fail-closed
KAT gate (`cmd_pkat`). The differential harness proves those embedded expected
values are themselves correct.

---

## 2. Runtime memory-safety controls — proven by fault injection

**Claim:** Vordr carries defense-in-depth runtime controls, and each one actually
*fires* on the violation it targets (a control that never triggers is worthless).

Each control is proven by a **redteam** case that deliberately commits exactly one
violation; the process must die by the matching fail-fast, verified by exit code.
Source: `src/redteam.asm` (a DBG-trace build); driver: `tests\run_all.cmd` stage 1.

| Control | Violation injected | Must fire → |
|---|---|---|
| Stack canary | overwrite the frame cookie | `FF_STACK_COOKIE` (2) |
| Software shadow stack | clobber a parked return address | `FF_SHADOW_STACK` (0xF001) |
| CFI landing-pad (guarded icall) | indirect-call a non-landing-pad target | `FF_GUARD_ICALL` (10) |
| Checked arithmetic | force a 64-bit add carry | `FF_OVERFLOW` (0xF005) |
| Bounds check | index ≥ limit | `FF_BOUNDS` (0xF004) |
| Type-tag check | struct magic mismatch | `FF_TYPE_MAGIC` (0xF003) |
| Heap temporal tag | use-after-free tag mismatch | `FF_HEAP_TAG` (0xF002) |
| IAT lock | write to the locked import table | AV, VEH-contained to `0xC0000409` |

**Result (this revision):** all 8 cases fire as required.

The shadow stack and landing-pad guards are not decorative: the differential
harness above was itself caught by `FF_GUARD_ICALL` during development when its
dispatch entry lacked a landing pad — the control fired on real, unintended code.

---

## 3. Secret hygiene — wiped, pinned, and double-free-safe

- **Wiped before release.** Secret buffers are `secure_zero`'d before free. Proven
  by `secscan`: it plants a random sentinel, confirms the scanner finds it in
  committed pages, wipes, and confirms zero residue.
- **Kept out of the pagefile.** Secret arenas are `VirtualLock`'d; the working-set
  quota is grown so the lock actually holds. Failure to pin is detected and
  surfaced (`lktest`).
- **Double-free-safe allocator.** `secmem_free` `secure_zero`s *before*
  `VirtualFree`, so a second/stale free would write released pages → crash. A
  live-allocation registry now makes `secmem_free` idempotent: it only wipes and
  releases a base that is currently registered, so a double / stale / foreign /
  null free is an inert no-op. Proven by `secfreedup` (free once → wipes; free the
  same pointer twice more + a foreign + a null free → all no-op, no fault). This
  structurally closed a recurring multi-vault teardown crash class.

---

## 4. Untrusted-input parsers — fuzzed for crash-safety

Vordr parses fully attacker-controllable input: `.vordr` vault files, imported
`.zip` archives, and the attachment section. Structural fuzzers assert the parsers
never crash on malformed input:

- `vfuzz` — vault record-parser structural fuzzer.
- `fuzzzip` — ZIP-import (pre-crypto) parser structural fuzzer.
- `jfuzz` — decrypted-`vordr.json` parser structural fuzzer (added this pass; it
  immediately found and we fixed an infinite-loop DoS — see §6a).
- `attfuzz` — attachment-index builder fuzz with random blobs.

Authenticity/anti-tamper of the vault file is separately proven: `mactest`
(full-file MAC catches trailer tamper), `rbtest` (anti-rollback counter),
`xctest` (external-change detection).

---

## 5. Build integrity

Every strict build runs two static gates that fail the build:

- **framecheck** — validates every `FRAME_PROLOG` frame size against its stack
  usage (ABI/stack-safety). This revision: **0 fatal**.
- **deadcode** — flags unreferenced code/symbols. This revision: **0 dead** of
  2239 symbols.

The release build is reproducible (`build.cmd release`, `/Brepro` + pinned PDB
path) and its SHA-256 is printed in CI, so a third party can rebuild and compare.

---

## 6. The gate, in full

`tests\run_all.cmd` aggregates the following stages; overall exit is `0` only if
all non-skipped stages pass:

| Stage | What it proves | This revision |
|---|---|---|
| redteam | all 8 memory-safety controls fire | PASS |
| build | strict release builds; framecheck/deadcode clean | PASS |
| selftest | embedded crypto/policy KATs pass at startup | PASS |
| roundtrip | 37 headless probes (crypto hygiene, parsers, vault format, multi-vault, federation) | PASS |
| cryptodiff | independent + published-vector crypto cross-check | PASS |

The 37 roundtrip probes and 8 redteam cases are enumerated with their source
locations in this repository's test map; each is a self-contained assertion with
an exit-code pass/fail signal.

---

## 6a. Findings from the current audit pass

Independent reviews of the untrusted-input paths — the `.vordr` vault parser, the
imported `.zip` parser, the AES-ZIP exporter, the registry config reader, and the
base32/TOTP code — were performed this pass. The `.vordr` parser, `regcfg`, and
`totp` earned a **clean bill on attacker-reachable memory corruption**; the prior
"attachment section processed before full authentication" concern was confirmed
**fixed** (the mandatory full-file MAC is verified before any attachment length is
used). The exporter had one **critical out-of-bounds write**. Every item below was
fixed, each with a regression test:

| Item | Severity | Fix | Test |
|---|---|---|---|
| **ZIP-export central directory unbounded:** a vault with ≥ 512 attachment fields drove `ze_add_file`'s record write past its array into adjacent **AES key-material globals** — an OOB write of attacker-influenced bytes | **Critical (OOB write)** | capacity guard refuses the write and fails the export closed | `zexcap` (gated) |
| KDF cost params (`t_cost`/`m_cost`) read from the unauthenticated header and run through Argon2id *before* the file MAC can be checked → a crafted file drives a giant allocation on open, no password needed | DoS (pre-auth, no key) | `vk_params_ok` rejects out-of-range params as corrupt before the KDF | `kdfparam` (gated) |
| Post-decryption `vordr.json` parser could **infinite-loop** on malformed input (a stuck parse cursor never advanced) → hang/DoS on a crafted or corrupted file | DoS | forward-progress guards on both `zi_walk` parse loops | `jfuzz` (gated) — the fuzzer that found it |
| Export filename converted with `WideCharToMultiByte(-1)` on an attachment filename not verified NUL-terminated → OOB read past the value buffer | OOB read | bounded wide-length scan capped at the available region | export roundtrip |
| Attachment `entries_len + 112` could integer-wrap past a plausibility check (post-auth; a downstream cap caught it, but fragile) | latent | reject `entries_len ≥ effective_end` before the add | vault-open probes |

The recurring multi-vault teardown crash class was also structurally closed this
pass by making `secmem_free` double-free-safe (§3, `secfreedup`). Two of these were
found by tools built this pass — the JSON infinite-loop by the new `jfuzz` fuzzer,
and the export ABI-clobber in the *first* filename-fix attempt by the build's own
`framecheck` stage — evidence the proof machinery itself catches real defects.

## 7. Honest limitations (what is NOT claimed)

- The differential harness proves **functional correctness** of the crypto output,
  not **side-channel** resistance. Constant-time behavior of `ct_memcmp` is checked
  for correctness (`selftest`) and has a manual timing probe (`cttest`), but timing
  is not asserted in the gate.
- Argon2id has no Python-stdlib reference, so it is checked against the published
  RFC 9106 vector only (not a second independent implementation).
- The fuzzers are **structural** (bounded, deterministic seeds), not coverage-
  guided; they demonstrate crash-safety on the exercised space, not exhaustive
  proof of its absence everywhere.
- Proofs run on the Windows/MSVC target. Behavior is not claimed for other
  toolchains.

---

## 8. Reproduction checklist for an external auditor

1. `git clone <repo> && cd vordr`
2. Open an **x64 Native Tools** prompt (puts `ml64`/`link`/`rc` on `PATH`); ensure
   `python` is on `PATH`.
3. `tests\run_all.cmd` → expect `ALL STAGES PASSED`.
4. Independently re-check crypto: `python tests\verify_crypto.py --exe bin\vordr.exe`
   → expect `RESULT: PASS`. Read `tests/verify_crypto.py` — it is short and
   dependency-free — and confirm the published vectors it hardcodes match the
   FIPS/RFC/NIST documents cited beside them.
5. Prove the check has teeth: edit any one line of `vordr katreport` output and
   feed it in — the verifier must report the mismatch and exit non-zero.
6. Rebuild reproducibly (`build.cmd release`) and compare the printed SHA-256 with
   the CI artifact.
