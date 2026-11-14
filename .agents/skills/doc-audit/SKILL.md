---
name: doc-audit
description: >-
  Audits, verifies, and updates project documentation for scientific accuracy,
  positive and condensed technical prose, and earned trust and safety. Use this
  skill when the user asks to review, audit, refresh, or align repository
  documentation, README files, architecture guides, security policies, or
  assurance documents against the live codebase.
---

# Documentation Trust, Safety & Accuracy Audit

Use this skill to audit all documentation in a project against its live source code, build pipeline, and verification suite, and to update every document so it is **scientifically accurate**, **positive and concrete/condensed**, and places **earned trust and safety front and center**.

## Core Pillars

### 1. Earned Trust & Safety Front and Center
Trust is never asserted by adjective; it is earned through transparent design, explicit boundaries, and independent verification. Across the project's entry-point and technical docs, surface three answers clearly:
1. **Why the solution can be trusted**: State the exact guarantees, fail-closed invariants, cryptographic or isolation primitives, and honest trust boundaries (distinguishing mathematical/cryptographic guarantees, OS-enforced boundaries, best-effort tripwires, and out-of-scope threats).
2. **Why the architecture was designed this way**: Explain the first-principles engineering rationale behind key structural choices (dependency surface, memory model, process/desktop isolation, file formats, privilege boundaries) and what classes of failure those choices eliminate by construction.
3. **What concrete measures verify that trust**: Point directly to the automated proof—startup self-tests, known-answer tests (KATs), independent reference/differential verifiers, fuzzers, fault-injection suites, static analyzers, and reproducible-build checks—with exact commands a skeptical reader can run themselves.

### 2. Positive, Concrete, Condensed Voice
- **Positive & constructive**: State what the system enforces, guarantees, and verifies in active, affirmative prose (*"Validates every field bound before allocation and wipes key material on lock"*). Avoid defensive, apologetic, or alarmist phrasing, and avoid burying current behavior under historical bug-fix archaeology (keep history in changelogs; retain past failure modes in reference docs only when explaining *why* a permanent architectural invariant exists).
- **Concrete & condensed**: Maximize signal per word. Replace vague qualifiers (*"very secure"*, *"robust"*, *"fast"*, *"carefully handled"*) with exact mechanisms, byte lengths, algorithm standards (FIPS/RFC/NIST), caps, and compact tables. Cut throat-clearing intros and redundant summaries.
- **Scientifically accurate**: Zero marketing superlatives (*"unbreakable"*, *"military-grade"*, *"bulletproof"*, *"100% hack-proof"*). Every constant, path, flag, wire-format offset, algorithm parameter, and test/gate count in documentation must match the current source tree.

Consult [references/style-and-trust-rubric.md](./references/style-and-trust-rubric.md) for concrete rewrite patterns and per-document audit checklists.

---

## Audit & Update Workflow

### Step 1: Inventory Docs & Run Structural Baseline
1. Run the bundled zero-dependency scanner on the repository root:
   ```bash
   python .agents/skills/doc-audit/scripts/doc_inventory.py --root . --lint-style
   ```
   *(If running from the global skill install, invoke `~/.gemini/config/skills/doc-audit/scripts/doc_inventory.py`.)*
2. Review every discovered `.md` / `.html` document, its size, link/anchor health, and flagged hype/weasel-word hotspots.
3. Also locate any project-native documentation or static gates (e.g., `tools/check_docs.py`, build scripts, CI workflows, `floors.py`) so updates obey all repository invariants.

### Step 2: Extract Codebase Ground Truth
Before trusting any claim in prose, verify the live codebase facts:
- **Architecture & entry points**: Module list, dependency surface, build targets/flags, binary/artifact outputs, installer/packaging rules.
- **Security & safety invariants**: Cryptographic primitives and parameters (key/nonce/tag sizes, KDF bounds, AAD/MAC coverage), secret-memory lifecycle, OS mitigations (ASLR, DEP, CET, DLL search lockdown, ACLs, MOTW, policy keys), parser caps, and fail-closed error paths.
- **Verification & assurance**: Exact count and scope of static analyzers, self-tests, KAT vectors, differential verifiers, fuzzers, GUI/integration tests, fault-injection cases, and reproducible-build steps.

### Step 3: Audit Every Document Against Code & the Trust Triad
Read every documentation file in full and check for:
1. **Factual drift**: Outdated module counts, test/analyzer counts, buffer/file caps, CLI verbs, registry keys, CI steps, or superseded behavior after recent commits.
2. **Missing trust & architectural rationale**:
   - Does `README.md` immediately establish *what the project is*, *why its architecture is trustworthy*, and *how anyone can independently verify it*?
   - Do architecture, security, and assurance docs clearly connect **design choice -> eliminated threat class -> automated verification gate**?
   - Are non-goals and OS/hardware boundaries stated honestly and constructively (earning credibility rather than overclaiming)?
3. **Tone & density issues**: Verbose paragraphs, passive hedging, marketing fluff, duplicated sections across files, or informal commit-diary narration inside reference specifications.

### Step 4: Update & Harmonize Documentation
Edit each file needing factual updates or prose tightening:
- Keep cross-document numbers, terminology, and cross-links consistent (prefer linking to the canonical spec/table rather than duplicating brittle lists across five files).
- Preserve frozen historical entries in `CHANGELOG.md` / `CHANGES.md` for released versions unless fixing broken links or adding an unreleased/current summary where appropriate.
- Maintain existing HTML/CSS structure when updating `.html` assurance or documentation pages while syncing their technical claims with `.md` counterparts.

### Step 5: Verify All Gates
1. Re-run the bundled scanner and confirm zero link/anchor/fence errors and clean style output:
   ```bash
   python .agents/skills/doc-audit/scripts/doc_inventory.py --root . --lint-style
   ```
2. Run the repository's own documentation and static verification gates (e.g., `python tools/check_docs.py`, strict build checks) and confirm zero errors before finishing.
