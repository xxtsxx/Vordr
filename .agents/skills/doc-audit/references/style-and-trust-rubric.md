# Style, Scientific Accuracy & Earned-Trust Rubric

Reference rubric for `doc-audit`. Apply these standards when auditing and rewriting documentation.

---

## 1. The Earned-Trust Pattern (Mechanism -> Rationale -> Proof)

Whenever a document makes a security, safety, or reliability claim, structure it around verifiable engineering facts rather than adjectives:

| Weak / Unsubstantiated | Positive, Concrete, Scientifically Accurate |
| :--- | :--- |
| *"We take security very seriously and use military-grade encryption to keep your data completely safe."* | *"Encrypts the vault body with AES-256-GCM under an Argon2id-derived key (RFC 9106) and authenticates the full file image—including attachments and the 64-bit monotonic save counter—with keyed BLAKE2b-256. `tests/verify_vault.py` independently re-derives and verifies every region without sharing code with the binary."* |
| *"We added a check here because previously a bad path could crash or overwrite the wrong file."* | *"Resolves open file handles via `GetFinalPathNameByHandleW` and compares NTFS volume serial + 64-bit file index before any export write, preventing self-overwrite across symlinks, junctions, and alternate path spellings (`guardkat`)."* |
| *"It isn't really possible to stop admins or malware, so don't rely on this if your machine is hacked."* | *"Protects vault confidentiality and integrity against offline storage compromise, sync rollbacks, and untrusted archive/attachment inputs. Same-user or kernel-level code execution while the vault is unlocked lies outside any user-mode process boundary; auto-lock, `VirtualLock` arenas, and immediate lock-time zeroing bound the exposure window."* |

---

## 2. Tone & Condensation Rules

1. **Affirmative framing**:
   - Lead with the invariant the system maintains (*"Loads system DLLs exclusively from `System32` via `LOAD_CONFIG.DependentLoadFlags = 0x0800` before user code runs"*).
   - State limitations with calm precision (*"Registry rollback mirrors act as an integrity tripwire against accidental cloud-sync restores; an attacker with local HKCU write access can clear the mirror, while the in-file MAC still prevents unauthenticated tampering"*).
2. **Scientific precision**:
   - Cite exact standards where applicable (RFC 9106, NIST SP 800-38D, FIPS 180-4, FIPS 197, RFC 6238, RFC 7693).
   - Distinguish **confidentiality** vs **integrity/authenticity**, **constant-time** vs **data-dependent**, **cryptographic enforcement** vs **OS ACL/policy enforcement**, and **deterministic guarantee** vs **probabilistic bound** (e.g., 96-bit random GCM nonces or tag-collision retry bounds).
   - Quote exact caps and units (`256 MiB` per attachment, `16 MiB` decrypted body arena, `80-byte` header AAD).
3. **Condensation**:
   - Replace multi-sentence prose lists of parameters or gates with a compact Markdown table.
   - Cut filler phrases: *"It should be noted that"*, *"In order to ensure that"*, *"Basically"*, *"Obviously"*, *"As mentioned above"*.
   - Keep `README.md` scannable in under two minutes while linking deep dives (`ARCHITECTURE.md`, `SECURITY.md`, `ASSURANCE.md`, `formats.md`) for full technical detail.

---

## 3. Document-Role Checklist

| Document Role | Primary Question Answered | Must Include |
| :--- | :--- | :--- |
| **`README.md`** | *What is this, why trust its design, and how do I use/verify it?* | Crisp value proposition; architectural why (e.g., zero external runtime dependencies, auditable footprint); front-and-center Trust & Verification summary with runnable commands; quickstart & links to deep docs. |
| **`SECURITY.md`** | *What is the threat model, what is protected vs out of scope, and how are issues reported?* | Explicit in-scope guarantees vs honest OS/hardware boundaries; defense-in-depth layers; vulnerability reporting path; current hardening summary matching live code. |
| **`ARCHITECTURE.md`** | *Why is the system structured this way and how do modules interact?* | Module map matching every file in `src/`; data/key flow; rationale for key design decisions (memory model, threading/desktop model, parser boundaries, loader hardening). |
| **`ASSURANCE.md` / `assurance.html`** | *What objective evidence proves the code matches its claims?* | Complete, accurate inventory of static gates, startup KATs, differential crypto checks, fuzzers, fault-injection cases, GUI/persistence regressions, and reproducible-build verification. |
| **`formats.md` / Specs** | *Can an independent engineer implement a compatible reader/verifier from this doc alone?* | Exact byte offsets, endianness, field types, size caps, KDF/AEAD/MAC constructions, and backward-compatibility invariants. |
| **`DEPLOYMENT.md` / `USER_GUIDE.md`** | *How do operators and users run, configure, and lock down the software safely?* | Accurate UI/CLI behavior, enterprise policy keys (`HKLM` vs `HKCU` precedence and fail-closed behavior), backup/export safety, and installer properties. |
| **`DEVELOPMENT.md` / `RELEASES.md`** | *How do I build, statically check, test, and reproduce the release binary byte-for-byte?* | Exact toolchain prerequisites, build modes, static gate list, test gate stages, and deterministic PE normalization / SHA-256 verification. |
