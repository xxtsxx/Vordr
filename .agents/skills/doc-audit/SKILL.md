---
name: doc-audit
description: >-
  Audits, verifies, and updates project documentation for clear non-technical
  onboarding in README.md, dedicated earned-trust engineering depth in TRUST.md,
  scientific accuracy, and positive condensed prose. Use this skill when the
  user asks to review, audit, refresh, or align repository documentation against
  the live codebase.
---

# Documentation Trust, Clarity & Accuracy Audit

Use this skill to audit all documentation in a project against its live source code, build pipeline, and verification suite, and to update every document so it combines **an approachable, visual `README.md`**, **front-and-center earned trust & safety (via a dedicated `TRUST.md`)**, **positive concrete/condensed prose**, and **scientific accuracy**.

## Core Pillars

### 1. Clear Separation of Audience: Approachable `README.md` + Deep `TRUST.md`
1. **`README.md` is the welcoming first impression (plain, non-technical language)**:
   - Write for a smart reader meeting the project for the first time—not someone already steeped in its source code.
   - Use **simple, everyday language** to explain *what the project is*, *what problem it solves*, and *why it is valuable* to anyone aligned with its outcome. Keep low-level flags, byte sizes, API names, and cryptographic jargon out of `README.md`.
   - Use **visual elements**—clean `mermaid` workflow diagrams, boundary/architecture illustrations, and compact comparison/navigation tables—to paint an immediate, memorable picture of how the solution works and how a user interacts with it.
   - Summarize trust in plain, human terms (what stays under the user's control, why the design is dependable, and practical user responsibilities), then link prominently to **`TRUST.md`** for full technical and verification depth.
2. **`TRUST.md` puts earned trust & safety front and center (rigorous & verifiable)**:
   - Create or maintain a dedicated `TRUST.md` at the repository root (linked from `README.md` and the docs index) that answers three questions with complete scientific precision:
     - **Why the solution can be trusted**: Exact guarantees, fail-closed invariants, cryptographic/isolation controls, and honest trust boundaries (distinguishing mathematical guarantees, OS-enforced boundaries, tripwires, and out-of-scope threats).
     - **Why the architecture was designed this way**: First-principles engineering rationale behind structural choices (dependency footprint, memory model, process/desktop isolation, wire formats, privilege boundaries) and the entire failure classes those choices eliminate by construction.
     - **What concrete measures earn and verify that trust**: Automated proof—startup self-tests, known-answer tests (KATs), independent reference/differential verifiers, fuzzers, fault-injection suites, static analyzers, and reproducible-build checks—with visual pipeline diagrams and exact commands anyone can run.

### 2. Positive, Concrete, Condensed Voice & Scientific Accuracy
- **Positive & constructive**: State what the system achieves, enforces, and verifies in active, affirmative prose. Avoid defensive, apologetic, or alarmist phrasing, and keep historical bug-fix archaeology in changelogs rather than reference docs (cite past failure modes only when explaining *why* a permanent architectural invariant exists).
- **Concrete & condensed**: Cut throat-clearing intros, filler phrases, and repetition across files. In `README.md`, be concrete through everyday outcomes and clear visuals; in `TRUST.md` and technical docs, be concrete through exact mechanisms, byte lengths, standards (FIPS/RFC/NIST), caps, and compact tables.
- **Scientifically accurate**: Zero marketing superlatives (*"unbreakable"*, *"military-grade"*, *"bulletproof"*, *"100% hack-proof"*). Every constant, path, flag, wire-format offset, algorithm parameter, and test/gate count must match the current source tree.

Consult [references/style-and-trust-rubric.md](./references/style-and-trust-rubric.md) for rewrite examples, visual diagram patterns, and per-document checklists.

---

## Audit & Update Workflow

### Step 1: Inventory Docs & Run Structural Baseline
1. Run the bundled zero-dependency scanner on the repository root:
   ```bash
   python .agents/skills/doc-audit/scripts/doc_inventory.py --root . --lint-style
   ```
   *(If running from the global skill install, invoke `~/.gemini/config/skills/doc-audit/scripts/doc_inventory.py`.)*
2. Review every discovered `.md` / `.html` document, its length, link/anchor health, and flagged hype/filler hotspots.
3. Locate any project-native documentation or static gates (e.g., `tools/check_docs.py`, build scripts, CI workflows, `floors.py`) so updates satisfy all repository checks.

### Step 2: Extract Codebase Ground Truth
Verify live codebase facts before trusting existing prose:
- **Architecture & entry points**: Module list, dependency surface, build targets/flags, binary/artifact outputs, installer/packaging rules.
- **Security & safety invariants**: Cryptographic primitives and parameters, secret-memory lifecycle, OS mitigations, parser caps, policy precedence, and fail-closed error paths.
- **Verification & assurance**: Exact count and scope of static analyzers, self-tests, KAT vectors, differential verifiers, fuzzers, GUI/integration tests, fault-injection cases, and reproducible-build steps.

### Step 3: Audit Every Document Against Role, Tone & Ground Truth
1. **Check `README.md` weight & accessibility**: Is `README.md` overloaded with low-level jargon, assembly/API identifiers, or dense spec tables? If so, move deep technical proof into `TRUST.md` (and `ARCHITECTURE.md` / `ASSURANCE.md`) and reshape `README.md` around plain language, user value, and clear `mermaid` diagrams.
2. **Check `TRUST.md` completeness**: Ensure `TRUST.md` exists (or create it when appropriate for the project) and thoroughly connects **architectural rationale -> threat boundary -> automated verification proof**.
3. **Check factual drift across all technical & user docs**: Flag outdated counts, caps, CLI flags, policy behaviors, or superseded mechanisms, and check for duplicated prose or negative/defensive tone.

### Step 4: Update & Harmonize Documentation
- Rewrite or refine `README.md` for clarity, warmth, visual flow (`mermaid` flowcharts/diagrams using supported syntax and quoted labels), and scannability.
- Create or update `TRUST.md` and align `SECURITY.md`, `ARCHITECTURE.md`, `ASSURANCE.md`, specs, and user/deployment guides so facts, counts, and cross-links agree everywhere.
- Preserve all inbound heading anchors referenced across the repository, and keep historical release records/changelogs intact for shipped versions.

### Step 5: Verify All Gates
1. Re-run the bundled scanner and confirm zero link, anchor, duplicate-heading, or code-fence errors and zero style warnings:
   ```bash
   python .agents/skills/doc-audit/scripts/doc_inventory.py --root . --lint-style
   ```
2. Run all repository-native doc tests and strict build checks (e.g., `python tools/check_docs.py`, unit tests, `build.cmd strict`) and confirm zero errors.
