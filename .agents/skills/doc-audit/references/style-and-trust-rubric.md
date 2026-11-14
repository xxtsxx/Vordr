# Style, Clarity, Scientific Accuracy & Earned-Trust Rubric

Reference rubric for `doc-audit`. Apply these standards when auditing and rewriting documentation.

---

## 1. Two-Tier Entry Pattern: Plain-Language `README.md` vs Technical `docs/TRUST.md`

`README.md` and `docs/TRUST.md` serve distinct audiences and reinforce each other:

| Dimension | `README.md` (First Impression) | `docs/TRUST.md` (Earned-Trust Proof) |
| :--- | :--- | :--- |
| **Target reader** | Anyone discovering the project—users, evaluators, and contributors deciding whether the project aligns with their needs. | Security-conscious users, engineers, auditors, and maintainers inspecting *how* and *why* trust is earned. |
| **Language** | Plain, clear, everyday words. Zero unexplained acronyms or internal symbol names. | Precise engineering prose citing exact algorithms, standards (RFC/FIPS/NIST), caps, OS primitives, and test scripts. |
| **Focus** | What the project is, why its approach is valuable, how daily use works, how to start in minutes, where to read more, and transparent AI development attribution. | Why the architecture was designed this way, what failure classes it eliminates, how automated checks verify it, and honest limits. |
| **Visuals** | Simple `mermaid` workflow and "how it works" diagrams + clean feature/navigation tables. | Trust-boundary diagrams, verification-pipeline flowcharts, and *Choice -> Rationale -> Proof* matrices. |

### Example: Same Fact in `README.md` vs `docs/TRUST.md`

- **Too heavy for `README.md`**:
  > *"Ships as a zero-CRT Win64 PE with `LOAD_CONFIG.DependentLoadFlags = 0x0800`, sealing records via AES-256-GCM under RFC 9106 Argon2id (`m=524288`, `t=3`, `p=1`) and prefix-keyed BLAKE2b-256 over `u64` `save_counter`."*
- **Right for `README.md` (clear, positive, human)**:
  > *"Vordr runs as a single small app on your PC with no internet connection, no account to sign up for, and no third-party software bundled inside. Your passwords, two-factor codes, and attached files live in one encrypted file that stays where you put it—and every release can be independently rebuilt and verified ([see how Vordr earns trust](docs/TRUST.md))."*
- **Right for `docs/TRUST.md` (concrete, condensed, scientifically accurate)**:
  > *"Links exclusively against Windows `System32` DLLs (`LOAD_CONFIG.DependentLoadFlags = 0x0800`, verified by `tools/pe_normalise.py` and `dllhijack`) with zero CRT or third-party libraries. Derives a 256-bit key via Argon2id (RFC 9106; default `512 MiB`, `t=3`, `p=1`), encrypts the body and each attachment with AES-256-GCM under fresh 96-bit random nonces, and authenticates the full image plus 64-bit monotonic save counter with BLAKE2b-256—independently verified by `tests/verify_vault.py` without sharing code with Vordr."*

---

## 2. Visual Elements & Diagrams

Use `mermaid` diagrams and structured tables to replace walls of text where relationships, lifecycles, or workflows are easier to see than read:

- **Supported Mermaid types**: `flowchart LR`, `flowchart TD`, `sequenceDiagram`, `stateDiagram-v2`.
- **Syntax safety**: Always quote node labels containing parentheses, slashes, colons, or punctuation—for example `A["Unlock vault (master password)"]` rather than `A[Unlock vault (master password)]`—and avoid raw HTML tags or literal `\n` escapes inside labels (GitHub's Mermaid renderer prints `\n` literally).
- **High-value diagram placements**:
  1. **`README.md`**: A simple system boundary diagram (*what stays on your device vs what never happens*) and/or a 4–5 step user workflow diagram (*Install -> Create vault -> Use daily -> Auto-lock & back up*).
  2. **`docs/TRUST.md`**: An architectural boundary diagram (*Encrypted file -> Unlocked memory -> External OS boundary*) and a verification pipeline diagram (*Static gates -> Self-tests -> Independent readers -> Reproducible build*).

---

## 3. The Earned-Trust Pattern (Mechanism -> Rationale -> Proof)

In `docs/TRUST.md` and technical references, never assert trust by superlative; establish it through verifiable facts:

| Weak / Unsubstantiated | Positive, Concrete, Scientifically Accurate |
| :--- | :--- |
| *"We take security very seriously and use military-grade encryption to keep your data completely safe."* | *"Encrypts the vault body with AES-256-GCM under an Argon2id-derived key (RFC 9106) and authenticates the full file image—including attachments and the 64-bit monotonic save counter—with BLAKE2b-256. `tests/verify_vault.py` independently re-derives and verifies every region without sharing code with the binary."* |
| *"We added a check here because previously a bad path could overwrite the wrong file."* | *"Resolves open file handles via `GetFinalPathNameByHandleW` and compares NTFS volume serial + 64-bit file index before any export write, preventing self-overwrite across symlinks, junctions, and alternate path spellings (`guardkat`)."* |
| *"It isn't really possible to stop admins or malware, so don't rely on this if your machine is hacked."* | *"Protects vault confidentiality and integrity against offline storage compromise, sync rollbacks, and untrusted archive/attachment inputs. Same-user or kernel-level code execution while the vault is unlocked lies outside any user-mode process boundary; auto-lock, `VirtualLock` arenas, and immediate lock-time zeroing bound the exposure window."* |

---

## 4. Tone & Condensation Rules

1. **Affirmative framing**: Lead with what the system guarantees and why; state boundaries with calm precision rather than alarmism or apology.
2. **Scientific precision**: Cite exact standards (RFC 9106, NIST SP 800-38D, FIPS 180-4, FIPS 197, RFC 6238, RFC 7693), exact units (`256 MiB`, `80-byte` AAD), and distinguish confidentiality vs integrity, cryptographic guarantees vs OS ACLs/tripwires, and deterministic checks vs probabilistic bounds.
3. **Condensation**: Cut filler phrases (*"It should be noted that"*, *"In order to ensure that"*, *"Basically"*), prefer compact tables over repetitive prose lists, and link canonical references rather than duplicating spec tables across five documents.

---

## 5. Transparent AI Attribution at the End of `README.md`

For AI-developed projects, end `README.md` with a short, factual attribution paragraph naming the models that contributed to code, quality, and security, paired with how verification gates validate all changes:

> *"This project is developed using AI. Anthropic Opus 4.8-5.5, Fable 5-5.1, Moonshot Kimi K3, ChatGPT 6 Astra, and Google Gemini 4 Carbon have all contributed to the code, quality, and security—backed by deterministic builds, independent reference verifiers, and automated test gates on every change."*

*(Adapt the model list if the user or repository specifies a different roster.)*

---

## 6. Document-Role Checklist

| Document Role | Primary Question Answered | Must Include |
| :--- | :--- | :--- |
| **`README.md`** | *What is this, why would I want it, and how do I start?* | Plain-language overview; clear value proposition; visual `mermaid` workflow/boundary diagram(s); 2-minute quickstart; everyday capabilities; plain-English trust summary linking to `docs/TRUST.md`; doc navigation map; concise AI development attribution at the end. |
| **`docs/TRUST.md`** | *Why can I trust this solution, why was it built this way, and how is that trust verified?* | Architectural rationale (what failure classes the design eliminates); cryptographic, memory, and OS protection layers; automated verification pipeline with runnable commands; honest, explicit security boundaries. |
| **`SECURITY.md`** | *How are vulnerabilities reported and handled, and what is in scope?* | Private reporting instructions; response/disclosure timeline; in-scope vs out-of-scope threat boundaries; supported versions and advisory protocol. |
| **`ARCHITECTURE.md`** | *How is the codebase structured internally and how do modules interact?* | Module map matching `src/`; unlock/save state machines; internal invariants, threading/desktop rules, and runtime hardening mechanics. |
| **`ASSURANCE.md` / `assurance.html`** | *What exact tests and static analyzers exist, and what are their limits?* | Stage-by-stage gate breakdown, static checker coverage, KAT/differential vector tables, probe regression map, and manual review checklist. |
| **`formats.md` / Specs** | *Can an independent engineer implement a compatible reader from this spec alone?* | Exact byte offsets, endianness, field tags, size caps, KDF/AEAD/MAC constructions, and compatibility invariants. |
| **`DEPLOYMENT.md` / `USER_GUIDE.md`** | *How do users and administrators operate and configure it safely?* | Everyday workflows, backup discipline, installer properties, and `HKLM` vs `HKCU` policy precedence. |
| **`DEVELOPMENT.md` / `RELEASES.md`** | *How do contributors build, test, and reproduce published binaries?* | Toolchain prerequisites, build modes, isolated test harnesses, published SHA-256 hashes, and byte-reproducible build steps. |
