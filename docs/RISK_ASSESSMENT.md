# Vordr risk assessment and treatment register

[Project overview](../README.md) · [Documentation](README.md) · [Test evidence](ASSURANCE.md)

## Executive assessment

Vordr has credible controls for protecting a native vault against offline
guessing and unauthorized modification: Argon2id, AES-256-GCM, full-file
authentication, fresh random body nonces, and authentication before attachment
parsing. These controls materially change an attacker's task from reading or
editing a file to defeating a password, a cryptographic boundary, or its
implementation. They deserve credit within that boundary.

They do not make an unlocked endpoint trustworthy. TPM convenience unlock,
clipboard access, attachment viewers, retained exports, and recovery practices
create separate ways to lose confidentiality or availability. Some are deliberate
product trade-offs, some are incomplete controls, and some are assurance gaps.
We must not collapse these into either “secure” or “insecure.”

The most important assurance gap is the absence of a recorded independent
external review of the custom cryptographic composition, assembly implementation,
and secret lifecycle. Existing tests are useful evidence, but do not quantify
the chance of an undiscovered defect. Unknown exploitability is recorded as
unknown below, with an investigation priority rather than a fabricated score.

This register separates **25 individually treatable scenarios**. Ratings are
provisional technical judgments for the stated reference deployment, not claims
about every installation. No risk has been accepted on an organization's behalf,
and none of the additional mitigations is claimed to be implemented.

Read [the rating method](#assessment-method) before comparing the
[register](#risk-register). Each detailed record explains exploitation,
control strength, remaining exposure, possible mitigation, and an observable
treatment target. [Treatment governance](#treatment-governance) explains how to
turn those targets into owned, dated decisions without mistaking proposals for results.

## Scope and evidence

Assessment date: **2026-09-12**. Source baseline:
**`ee1dbae63ce03c6550cbc63490ee49859da14813`**.
This revision rewrites the earlier twelve risk families; lettered IDs split
those families without reassigning their meaning. It is a source-based assessment,
not a new exhaustive audit, penetration test, or execution of the full security
test gate. It is not a release-specific vulnerability advisory.

The evidence consists of the source functions linked in each record, the
existing regression harnesses, and the documented format and deployment behavior.
Source inspection establishes control behavior, not measured effectiveness in a
particular organization. A named test means that a probe exists; it does not mean
that it ran successfully during this assessment. Historical defects and their
regressions remain in [Assurance](ASSURANCE.md#historical-regression-context).

Assets include the master password, vault and attachment keys, records, TOTP
seeds, attachments, history, the freshness of those records, and continued access
to them. Metadata and copies outside the main file are included. Confidentiality
loss can persist after a password change if an attacker retained an older copy.

The reference deployment is one person using a standard Windows account on a
maintained Windows x64 machine, with genuine Vordr binaries and production-created
vaults. Ordinary imports, clipboard use, previews, and encrypted file sync are
possible. Compiled defaults apply unless stated: 20-second clipboard clearing,
10-minute idle lock, Windows-session locking and private-desktop unlock enabled;
TPM unlock allowed, provider prompting not required, and previews/history allowed.
No credit is assumed for independently verified backups, enterprise monitoring,
mandatory endpoint controls, or an organizational update SLA.

Passwords, TPM enrollment, storage, and sensitive-data concentration vary by
deployment; records give important rating changes where those variations matter.
Active compromise and physical attack scenarios are assessed explicitly, rather
than silently assuming them away. The application's protection exclusions and
reporting commitments remain governed by [SECURITY.md](../SECURITY.md).
This document neither broadens those exclusions nor changes disclosure terms.

## Assessment method

### Impact, likelihood, and uncertainty

The method separates threat events, controls, likelihood, impact, and uncertainty,
consistent with the approach in [NIST SP 800-30 Rev. 1](https://csrc.nist.gov/pubs/sp/800/30/r1/final).
The scales and thresholds below are **project-defined**, not NIST certification,
CVSS scores, incident statistics, or probabilities. The planning horizon is the
next twelve months unless a record explicitly uses the lifetime of a secret.

| Value | Impact if the scenario succeeds | Qualitative likelihood under the stated conditions |
|---|---|---|
| 1 | Negligible disclosure or interruption; no usable secret lost | Exceptional: no practical route under the stated assumptions without an exceptional failure or advance |
| 2 | Limited metadata/privacy loss or easily recovered inconvenience | Uncommon: requires an unusual failure, exposure, or combination of conditions |
| 3 | Limited record loss/disclosure or significant but recoverable disruption | Plausible: realistic exposure and a feasible sequence, but not an expected outcome of ordinary use |
| 4 | Serious account compromise, substantial loss, or prolonged disruption | Likely under the stated exposed configuration: few effective barriers remain |
| 5 | Whole-vault/key compromise, multiple critical credentials, or irrecoverable loss | Expected once the stated adverse condition exists; no effective product boundary blocks it |
| U | Not used for impact; select a consequence and explain its uncertainty | Unknown: evidence does not support a likelihood judgment, particularly for an unvalidated exploit hypothesis |

Likelihood includes the prerequisites stated in the record. **Conditional**
ratings, such as compromise of an already-hostile endpoint, must not be reported
as the likelihood that a clean endpoint becomes compromised. Deployment owners
must separately assess how often those prerequisites can occur. A twelve-month
rating must not be applied to decades of ciphertext retention.

For known L, the triage score is **I × L**: 1–4 Low, 5–9 Moderate, 10–14 High,
15–19 Very high, 20–25 Critical. Multiplying ordinal categories is a sorting aid,
not a measurement of expected loss. With L=U the score and class are **Unrated**;
high-impact unknowns receive investigation priority, not a zero or a comforting
“Low.” Do not add scores across related risks.

Each record states the risk **after current controls**. We do not subtract a
control percentage from an invented inherent score. Proposed treatments do not
lower the current rating; rescoring requires implementation and verification.
Impact assumes the stated asset set, so a vault containing infrastructure-root
credentials may warrant a higher organizational consequence than one holding
replaceable personal notes.

### Control strength and evidence confidence

Strength is assessed for the named objective, not for the entire application:

| Grade | Meaning |
|---|---|
| Strong within boundary | Direct preventive enforcement, defined coverage, and rejection on relevant failure; still depends on correct implementation and stated trust assumptions |
| Partial | Meaningful prevention, detection, or exposure reduction, but limited coverage, best-effort behavior, bypassable ownership, or unverified deployment dependence |
| None for this scenario | No implemented control prevents this consequence; another control may protect a different asset or stage |
| Unestablished | The desired assurance is not demonstrated by the available evidence; this is not itself proof of an exploitable flaw |

Controls are judged on their mechanism, coverage, failure behavior, and evidence.
Confidence is **High** for directly visible behavior and its immediate consequence,
**Medium** where outcome depends on untested platform/user conditions, and **Low**
where exploitability or effectiveness needs specialist or dynamic investigation.
High confidence is not low risk. A reliable observation that a control is absent
can support high confidence in a serious conditional risk.

### Treatment priority

- **P1:** decision or investigation before high-consequence deployment; make the
  applicable validation a release gate before claiming the stronger property.
- **P2:** put a treatment or explicit acceptance decision into the next maintenance
  planning cycle; proposed decision deadline is 30 days after owner assignment.
- **P3:** monitor and review at least quarterly or when assumptions change.

These are proposed planning rules, not maintainer response promises. Critical
exposure needs containment before continued affected use. Every record starts
**Open — proposed**, with owner assignment and due date still required.

## Risk register

The table is an index, not a substitute for the conditions and reasoning below.
Confidence concerns the assessment, not independent certification. “Conditional”
is deliberately visible where the score assumes an adverse condition already exists.

| ID | Individual risk | I | L | Score / residual class | Confidence | Priority |
|---|---|---|---|---|---|---|
| [R1](#r1--offline-master-password-guessing) | Offline master-password guessing | 5 | 2 | 10 / High | Medium | P1 |
| [R2a](#r2a--cryptographic-implementation-or-authentication-defect) | Crypto implementation/authentication defect | 5 | U | — / Unrated | Low | P1 |
| [R2b](#r2b--nonce-collision-or-keynonce-lifecycle-regression) | Nonce collision/lifecycle regression | 5 | 1 | 5 / Moderate | Medium | P2 |
| [R2c](#r2c--secret-dependent-timing-or-other-side-channels) | Side-channel disclosure | 5 | U | — / Unrated | Low | P1 |
| [R3a](#r3a--malicious-input-triggering-memory-corruption) | Parser memory corruption | 5 | U | — / Unrated | Low | P1 |
| [R3b](#r3b--pre-authentication-resource-exhaustion) | Pre-authentication resource exhaustion | 3 | 3 | 9 / Moderate | Medium | P2 |
| [R4a](#r4a--compromised-or-unattended-unlocked-endpoint) | Unlocked endpoint compromise | 5 | 5 | 25 / Critical, conditional | High | P1 |
| [R4b](#r4b--password-observation-during-desktop-fallback) | Password observation during fallback | 5 | 2 | 10 / High | Medium | P1 |
| [R4c](#r4c--orphaned-private-desktop-worker) | Orphaned desktop-worker state interference | 4 | U | — / Unrated | Low | P1 |
| [R5](#r5--unintended-access-through-tpm-convenience-unlock) | TPM alternative-route access | 5 | 4 | 20 / Critical, conditional | Medium | P1 |
| [R6](#r6--plaintext-or-keys-surviving-in-memory-artifacts) | Memory/page/dump residue | 5 | 2 | 10 / High | Medium | P1 |
| [R7a](#r7a--clipboard-or-visible-secret-capture) | Clipboard/reveal capture | 4 | 3 | 12 / High | High | P1 |
| [R7b](#r7b--plaintext-attachment-files-and-external-viewers) | Preview/download exposure | 4 | 3 | 12 / High | High | P1 |
| [R7c](#r7c--offline-guessing-of-zip-exports) | ZIP-export password guessing | 5 | 3 | 15 / Very high | Medium | P1 |
| [R7d](#r7d--superseded-secrets-retained-in-copies) | Historical-copy disclosure | 4 | 3 | 12 / High | High | P2 |
| [R7e](#r7e--metadata-disclosure-without-decryption) | Unencrypted metadata disclosure | 2 | 5 | 10 / High, conditional | High | P2 |
| [R7f](#r7f--password-and-totp-seed-compromised-together) | Password/TOTP co-compromise | 5 | 5 | 25 / Critical, conditional | High | P1 |
| [R8a](#r8a--replay-of-an-older-authentic-vault) | Authentic-file rollback | 4 | 3 | 12 / High | High | P1 |
| [R8b](#r8b--concurrent-or-synchronized-write-conflicts) | Concurrent/sync lost updates | 3 | 3 | 9 / Moderate | Medium | P2 |
| [R9a](#r9a--loss-of-the-only-recoverable-vault-copy) | Irrecoverable storage loss | 5 | 2 | 10 / High | Medium | P1 |
| [R9b](#r9b--loss-of-password-and-tpm-access) | Loss of all unlock routes | 5 | 2 | 10 / High | Medium | P1 |
| [R10](#r10--deployment-policy-not-actually-enforced) | Policy enforcement drift | 4 | 3 | 12 / High | Medium | P1 |
| [R11a](#r11a--substituted-source-toolchain-or-release) | Supply-chain substitution | 5 | 2 | 10 / High | Medium | P1 |
| [R11b](#r11b--vulnerable-builds-persisting-after-disclosure) | Missed fixes/maintenance interruption | 5 | 3 | 15 / Very high, conditional | Medium | P1 |
| [R12](#r12--long-term-cryptanalysis-and-tpm-rsa-exposure) | Future cryptanalysis of retained material | 5 | U | — / Unrated, long-term | Low | P1 |

## Individual assessments

### R1 — Offline master-password guessing

**Scenario and exploitation.** An attacker copies a vault from storage, sync,
or a backup and tests candidate passwords without contacting Vordr. Deriving a
candidate key and comparing its public key-check value provides an offline oracle.
There is no online lockout to evade. Success exposes all data protected by that key.

**Controls and strength.** Argon2id at production defaults (512 MiB, three passes,
one lane) is **Strong within boundary** at imposing work per guess; random salt
prevents simple cross-vault precomputation. AES-256-GCM is strong against direct
reading of ciphertext, subject to R2a. Password length/class checks are **Partial**:
they do not establish entropy. The reader accepts costs below the production
default, so acceptance of a file does not establish equivalent guessing resistance.

**Residual assessment.** I=5, L=2, **High (10), Medium confidence** assumes a
unique, non-obvious master password and a production-cost native file. L=2 is
a conservative human-password judgment, not a measured cracking rate. A reused
or predictable password raises L to 4–5; a demonstrably randomly generated,
sufficient-entropy password can justify L=1. Already stolen old copies retain
their old password and KDF exposure. KCV checking does not remove this risk.

**Further mitigation.** Use a generated unique passphrase, verify actual vault
costs, and consider a minimum-KDF policy on normal imports. Stronger KDF costs
increase unlock time and memory pressure; a strict minimum needs an explicit
compatibility path for older files. Rotate exposed service credentials as well
as the vault password: password rotation alone cannot revoke captured ciphertext.

**Treatment and measurement.** Proposed owner: deployment owner with maintainer;
P1. Inventory KDF parameters for 100% of managed current vaults and retained
backups; record exceptions. Demonstrate the password-generation process without
recording passwords. Measure unlock latency on the slowest supported machine
before setting a KDF floor. Target: no unreviewed weak-cost file or reused master
password in the managed scope; reassess L from that evidence, not password length.

**Evidence.** [vault.asm](../src/vault.asm): `vk_params_ok`, `vk_kcv_ok`,
`vault_unlock`; [format](formats.md#header); `kdfparam` and crypto-vector tests.

### R2a — Cryptographic implementation or authentication defect

**Scenario and exploitation.** An attacker controlling ciphertext would need
an implementation or composition flaw to recover plaintext or make modified
records pass authentication without a key. No such working bypass is established
by this assessment. A bad length, tag, key-selection, or authentication-order
path is a review hypothesis, not a confirmed vulnerability.

**Controls and strength.** Full-file authentication before attachment parsing,
GCM authentication of the body and 80-byte header, and per-attachment tags are
**Strong within their intended boundaries**. Startup vectors and differential
checks are **Partial assurance** over selected inputs. Whole-composition assurance
is **Unestablished**: the same vault key serves body encryption, KCV, and a
domain-prefixed BLAKE2b file-MAC construction that is not native keyed BLAKE2.
That merits review but does not by itself demonstrate a break.

**Residual assessment.** I=5, L=U, **Unrated, Low confidence in exploitability**.
The control design strongly resists ordinary bit flips and splicing; undiscovered
implementation/composition failure cannot honestly be assigned a measured likelihood
from passing vectors. Treat this as a high-impact assurance obligation, not a
claim that cryptography is currently broken.

**Further mitigation.** Commission independent review of composition and key
separation, broaden independent primitive comparisons, and evaluate a reviewed
crypto backend. A backend or format redesign adds dependencies, compatibility
work, and migration risk; it is not automatically safer until integrated and tested.

**Treatment and measurement.** Proposed owner: maintainer and independent crypto
reviewer; P1. Target: a review covering every key derivation/use, authentication
boundary, and format version, with all findings fixed or explicitly dispositioned;
mutation tests must reject header/body/attachment/counter tampering on every
supported reader. Record independent-vector coverage and unresolved findings.
Close the review task, not the possibility of future cryptographic defects.

**Evidence.** [vault.asm](../src/vault.asm): `vault_file_mac`, `vault_unlock`;
[aesgcm.asm](../src/aesgcm.asm); [verify_crypto.py](../tests/verify_crypto.py);
`mactest`. Argon2's verifier uses published vectors, not a second full implementation.

### R2b — Nonce collision or key/nonce lifecycle regression

**Scenario and exploitation.** An attacker who obtains two encryptions of
different plaintext under the same GCM key and nonce can exploit the repeated
keystream; GCM authentication is also endangered. An RNG failure, accidental
reuse across retry/edit paths, or a random collision could enable this condition.
Copying an unchanged attachment ciphertext is not a new encryption of changed data.

**Controls and strength.** `vault_reseal` obtains a new random 96-bit body nonce
for each reseal; OS RNG failure aborts. New attachments get random keys/nonces;
write retries use an already-built image. These are **Strong within the inspected
paths**. Whole-lifecycle enforcement is **Partial** because preserving the invariant
across callers and future edits still depends on program structure and review.
RDSEED is supplementary, not a replacement for a failed OS RNG.

**Residual assessment.** I=5, L=1, **Moderate (5), Medium confidence** under a
trustworthy RNG and the inspected lifecycle. This is not a claim of a current
reuse bug. For q independent uniform 96-bit nonces under one key, the birthday
approximation is q(q−1)/2^97; one million draws gives about 6.3×10^-18. This is
only a collision calculation, not a probability of implementation failure or a
complete GCM security bound. See [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).

**Further mitigation.** Centralize sealing ownership and add deterministic
failure-injection tests. Consider a per-key usage budget or misuse-resistant
format only after compatibility and crypto review; replacing randomness with a
counter requires durable uniqueness across rollback, copies, and machines.

**Treatment and measurement.** Proposed owner: maintainer; P2. Target: instrument
all encryption call sites in test builds and require zero changed-plaintext reuse
of a key/nonce in create, edit, retry, import/export, and attachment-replacement
cases. Inject OS RNG failures and require zero new encrypted images. Document
the per-key invocation/size budget and count all writers; sampling alone does
not prove collision freedom.

**Evidence.** [vault.asm](../src/vault.asm): `vault_reseal`, `vault_seal_write`,
`attach_stage`, `attach_emit_one`; [random.asm](../src/random.asm): `rng_fill`.

### R2c — Secret-dependent timing or other side channels

**Scenario and exploitation.** An attacker needs an observable timing, cache,
or other signal correlated with secret values, repeated measurements, and a
method that converts that signal into useful information. No end-to-end key
recovery through such a signal is demonstrated here; a file alone does not give
an interactive network timing oracle because Vordr has no network service.

**Controls and strength.** Fixed-length secret comparisons accumulate differences
instead of returning at the first mismatch: **Strong for that narrow content-
comparison property**. Whole-program side-channel resistance is **Unestablished**.
GUI comparisons expose string length, and comparison discipline does not prove
the timing behavior of derivation, parsing, memory access, or provider calls.

**Residual assessment.** I=5 for potential key recovery, L=U, **Unrated, Low
confidence in exploitability**. A length-only signal has a smaller impact and
must not be reported as full key recovery without a demonstrated attack chain.

**Further mitigation.** Review secret-dependent branches/accesses and run
controlled timing experiments on supported CPU paths. A vetted implementation
can reduce review burden but still needs integration analysis. Process isolation
may reduce observations but adds IPC and lifecycle complexity.

**Treatment and measurement.** Proposed owner: crypto reviewer; P1. Target: every
secret comparison and cryptographic CPU path mapped, with an explicit observation
model; retain sample counts, noise controls, effect sizes, and negative controls
for timing tests. No unexplained reproducible secret-dependent signal may remain
without an owner and impact analysis. A nonsignificant timing test is not proof
of constant-time behavior.

**Evidence.** [hardening.asm](../src/hardening.asm): `ct_memcmp`;
[gui.asm](../src/gui.asm): `gui_wstr_eq`; `cttest`; [memory reference](SECRETS.md).

### R3a — Malicious input triggering memory corruption

**Scenario and exploitation.** A sender supplies a crafted vault, ZIP, JSON
record, or attachment. The user must reach the relevant import/open path.
Pre-authentication structures need no valid password; post-authentication content
can be attacker-authored under a password the sender knows. Exploitation requires
a parser or arithmetic defect and, for code execution, a usable corruption
primitive. No new working memory-corruption exploit is asserted here.

**Controls and strength.** Authentication-before-use is **Strong** for covered
native contents. Length/capacity guards, frame checks, canaries, software shadow
stack, guarded calls, heap tags, ASLR and DEP are **Partial defense in depth**:
they cover particular patterns, not every load/store or stale alias. Software
landing-pad checks are not Windows CFG; assembly is not memory-safe. Structural
fuzzers provide **Partial evidence**, not exhaustive coverage.

**Residual assessment.** I=5 for potential process compromise, L=U, **Unrated,
Low confidence in exploitability**. Past parser defects justify focused review
and regression work, not a claim that the present parser is exploitable or clean.

**Further mitigation.** Add coverage-guided fuzzing and strengthen bounded parser
interfaces. Isolating import parsing could contain crashes/authority, but adds
IPC and secret-transfer complexity; any such change needs a separate design review.

**Treatment and measurement.** Proposed owner: maintainer/security reviewer; P1.
Target: inventory 100% of external parser entry points; retain corpus, seed,
execution count, coverage, timeouts, and unique crashes for each. Triage every
crash/hang and gate releases on zero unresolved security-relevant findings in
that campaign. Coverage and duration must be reported; “no crashes” alone is
not an adequate success metric.

**Evidence.** [vault.asm](../src/vault.asm), [zipimport.asm](../src/zipimport.asm),
[zipexport.asm](../src/zipexport.asm), [macros.inc](../src/macros.inc),
[redteam.asm](../src/redteam.asm); `vfuzz`, `fuzzzip`, `jfuzz`, `attfuzz`, `zexcap`.

### R3b — Pre-authentication resource exhaustion

**Scenario and exploitation.** A crafted native header requests expensive KDF
parameters. If the user attempts password-based unlock/import, derivation runs
before authentication can reject the file. The attacker does not need the real
password. This is user-triggered local resource consumption, not unauthenticated
remote execution or an always-on denial-of-service endpoint.

**Controls and strength.** Parameter bounds reject out-of-range costs before
derivation: **Strong against unbounded parameter values**. They are **Partial
against practical exhaustion** because accepted limits reach 4 GiB and 16 passes.
Low-memory failure may abort rather than consume the maximum, but that does not
establish a responsiveness guarantee on supported hardware.

**Residual assessment.** I=3, L=3, **Moderate (9), Medium confidence**: enticing
an import is plausible and allowed work can be expensive; actual latency/memory
pressure has not been benchmarked in this review. Raise impact for an endpoint
whose temporary unavailability interrupts a critical operation.

**Further mitigation.** Add a configurable pre-auth work budget, explicit consent
for high costs, and cancellation. This may reject legitimate high-cost vaults;
an override should be deliberate and should not silently weaken their KDF.

**Treatment and measurement.** Proposed owner: maintainer; P2. Target: reject
above-budget headers before allocation and measure peak committed memory and
95th-percentile unlock/cancel latency on the lowest-spec supported machine.
Approve numerical budgets before implementation; they are currently **not
established**, not assumed met. Include boundary and repeated-attempt tests.

**Evidence.** [vault.asm](../src/vault.asm): `vk_params_ok`, `vault_unlock`;
[macros.inc](../src/macros.inc): Argon2 limits; `kdfparam`.

### R4a — Compromised or unattended unlocked endpoint

**Scenario and exploitation.** Malware able to access the unlocked process or
its outputs reads records/keys, or someone physically using the unlocked UI
reveals or exports data. A privileged attacker can bypass more OS boundaries.
These paths do not require cracking the encrypted file. Establishing that
access on a clean endpoint is a separate prerequisite, not demonstrated here.

**Controls and strength.** Idle/session locking is **Partial**, reducing time
at risk. Memory locking/wiping is **None against a live authorized read**; private
desktop protects an input stage, not the unlocked record body. There is no
general product boundary against a hostile kernel, unlocked administrator access,
hardware attacks, or a person already operating the unlocked vault.

**Residual assessment.** I=5, L=5, **Critical (25), High confidence, conditional
on that access**. This is not a prediction that every normal installation will
be compromised. Accepting Vordr for secrets means accepting its dependency on
endpoint security; mitigation within the same compromised process cannot close it.

**Further mitigation.** Use managed/dedicated endpoints, restrict software and
physical access, and minimize unlock duration. These operational measures add
cost and friction and must be verified by the operator. Separate high-value
credentials or hardware-backed service authentication reduces blast radius.

**Treatment and measurement.** Proposed owner: endpoint/data owner; P1. Target:
100% of in-scope endpoints enrolled in the chosen controls; verify session/idle
locking on each supported configuration and record exceptions. Document which
credentials may be stored and the containment/rotation procedure after endpoint
compromise. The conditional product risk remains Critical; report reduced
endpoint exposure separately rather than claiming Vordr now resists a hostile OS.

**Evidence.** [gui.asm](../src/gui.asm): lock/session handlers;
[vault.asm](../src/vault.asm): `vault_lock`; [security policy](../SECURITY.md).

### R4b — Password observation during desktop fallback

**Scenario and exploitation.** A password observer on the normal desktop benefits
if private-desktop setup fails and the user types into the fallback dialog.
Both observation capability and fallback/user entry are needed. A successful
private-desktop demonstration does not test this failure path.

**Controls and strength.** Private-desktop entry is **Partial** protection against
ordinary desktop hooks/screensharing, not the privileged UAC consent boundary.
`gui_secdesk_show` deliberately falls back when input-desktop, desktop creation,
or worker creation fails: **None for mandatory private-desktop enforcement**.

**Residual assessment.** I=5, L=2, **High (10), Medium confidence** because the
sequence needs both an observer and failure. A deployment requiring isolation
on every password entry does not meet that requirement even if failures are rare.

**Further mitigation.** Offer an enforced fail-closed mode, with an explicit
warning for optional fallback. Availability suffers when Windows cannot create
the desktop; recovery needs a documented trusted-machine route, not silent bypass.

**Treatment and measurement.** Proposed owner: maintainer/deployment owner; P1.
Target for strict mode: inject every setup failure and observe zero password
prompts on the normal desktop. Test restoration, cancellation, and accessibility
on supported environments; retain failures/attempts. Until then, document the
fallback exception rather than marking `SecureUnlock=1` as mandatory isolation.

**Evidence.** [gui.asm](../src/gui.asm): `gui_secdesk_show`, `gss_fallback`;
[deployment](DEPLOYMENT.md).

### R4c — Orphaned private-desktop worker

**Scenario and exploitation.** A desktop worker remains blocked past the
ten-minute watchdog, the main thread resumes, and the worker later continues
while application state is reused. Slow or blocked I/O could create the condition;
attacker control of its timing and a resulting integrity/confidentiality failure
have not been reproduced. This is a source-supported concurrency concern, not
a demonstrated race exploit.

**Controls and strength.** The watchdog and desktop restoration are **Partial
availability controls**: they return the user's desktop. The orphan flag avoids
some restoration work, but exclusive ownership of shared vault/crypto/file-I/O
state after timeout is **Unestablished**. Returning control is not cancellation
of the worker or proof that it cannot later mutate shared state.

**Residual assessment.** I=4 for plausible state corruption or data loss, L=U,
**Unrated, Low confidence in exploitability**. A proven path to key disclosure
would raise impact to 5. Treat lifecycle validation as a P1 task rather than
dismissing it as only a leaked handle.

**Further mitigation.** Quarantine vault operations until completion or give
workers isolated state and generation-checked result publication. Quarantine
reduces availability; isolation requires careful ownership changes. Forcibly
killing a thread is not a safe substitute for cleanup design.

**Treatment and measurement.** Proposed owner: maintainer; P1. Target: a controlled
blocked-worker test covering timeout, a second operation, and late completion;
zero stale-worker state writes, unexpected unlocks, or saves after cancellation.
Record schedules tested and object ownership. This treatment first needs a
reproducer; do not claim the risk fixed solely from adding a flag check.

**Evidence.** [gui.asm](../src/gui.asm): `gui_secdesk_show`, `gss_wait`,
`secdesk_thread`, `g_secdesk_orphan`; shared-state warning beside watchdog recovery.

### R5 — Unintended access through TPM convenience unlock

**Scenario and exploitation.** Code or a person with access to the enrolled
user's provider key and wrapped vault-key blob invokes the alternative unlock
route. Knowledge of the master password is unnecessary. This is materially
different from a remote attacker holding only the encrypted vault file.

**Controls and strength.** Platform-provider wrapping is **Strong within its
hardware/key-access boundary**, subject to provider behavior. It is **None as
a password-plus-TPM requirement**: Vordr uses password **or** TPM. Requested
RSA-2048 length and provider UI policy are **Partial**: property failures are
not enforced as fatal, existing keys are reused, and allowing UI is not proof
of mandatory Hello/PIN confirmation. Provider behavior is not tested here.

**Residual assessment.** I=5, L=4, **Critical (20), Medium confidence, conditional
on enrolled-user key/blob access**. Default silent convenience leaves few
application barriers at that point. Without enrollment this route is inactive;
that does not reduce R4a. Merely copying a blob to another ordinary machine
does not establish that it can be decrypted there.

**Further mitigation.** Disable and remove unwanted enrollment, or implement
fail-closed property verification and mandatory confirmation where supported.
Require fresh enrollment when policy changes. Stricter policy may break provider
compatibility and adds interaction; it still is not two-factor vault derivation.

**Treatment and measurement.** Proposed owner: maintainer/endpoint owner; P1.
Target: inventory enrollment on 100% of scoped endpoints; verify absence when
disabled. For an enforced-confirmation mode, test new/reused keys, property
rejection, cancellation, and unavailable UI: zero successful unwraps without
the required confirmation. Record actual key length and provider per test.
Keep residual access under R4a explicit even after this target is met.

**Evidence.** [tpm.asm](../src/tpm.asm): `tpm_seal`, `tpm_unseal`;
[vault.asm](../src/vault.asm): TPM key recovery; [deployment](DEPLOYMENT.md).

### R6 — Plaintext or keys surviving in memory artifacts

**Scenario and exploitation.** An attacker obtains a pagefile, crash/hibernation
artifact, or recoverable process memory containing sensitive data after its
intended lifetime. The attacker needs access to such an artifact and a useful
copy; this is distinct from reading an already-unlocked process in R4a.

**Controls and strength.** Dynamic secure allocation fails if pinning fails and
wipes registered allocations before free: **Strong for those owned buffers**.
Static locking, ordinary scratch/attachment/Argon2 allocations, and panic cleanup
provide **Partial overall coverage**. Static failures can warn without stopping;
forced termination can skip cleanup. [VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock)
excludes locked pages from ordinary paging while locked, not every sensitive
copy or every system artifact. The free registry is not generation-aware pointer safety.

**Residual assessment.** I=5, L=2, **High (10), Medium confidence**: useful residue
plus artifact access is a narrower condition than live compromise, but uncovered
memory and abnormal exits prevent a universal non-persistence claim. Which
artifacts contain recoverable secrets remains unmeasured on target machines.

**Further mitigation.** Complete the sensitive-allocation inventory, consolidate
ownership, shorten lifetimes, and consider strict static-lock failure handling.
Operator controls for disks/dumps/hibernation add protection outside Vordr;
pinning a large Argon2 arena can cause memory pressure and needs measurement.

**Treatment and measurement.** Proposed owner: maintainer/endpoint owner; P1.
Target: every identified secret-bearing allocation has owner, capacity, lock
policy, and cleanup paths. With synthetic sentinels test success, cancel, lock,
failure, and abnormal exit; record recoveries by buffer/artifact and zero unexplained
residue on promised normal-wipe paths. Record untestable artifacts as exceptions,
not passes. Forced-exit physical erasure is not an achievable product guarantee.

**Evidence.** [secmem.asm](../src/secmem.asm), [argon2.asm](../src/argon2.asm),
[buffer inventory](SECRETS.md); `secscan`, `secfreedup`, `lktest`.

### R7a — Clipboard or visible secret capture

**Scenario and exploitation.** A clipboard reader copies a secret before the
timer expires, or an observer captures a reveal, phonetic presentation, or screen.
The receiving application may retain or transmit the value. Clearing later
does not revoke a copy already made.

**Controls and strength.** Twenty-second default clearing, sequence ownership
checks, history/cloud exclusion formats, and hiding revealed values are
**Partial exposure reduction**. There is **None against a contemporaneous reader
authorized by the OS**; exclusion flags request cooperation, not access control.

**Residual assessment.** I=4, L=3, **High (12), High confidence in the exposure
mechanism**. Likelihood assumes ordinary copying plus an unwanted observer/reader,
not automatic transmission of every copy. Impact becomes 5 if the copied value
itself unlocks all critical assets; an active clipboard reader makes the outcome
likely even with a shorter timeout.

**Further mitigation.** Minimize reveal/copy, restrict clipboard consumers and
screen-sharing, or develop a narrower transfer mechanism. Shorter timers trade
usability for duration, not resistance to fast capture. A new integration creates
its own trust boundary and is not presumed safe.

**Treatment and measurement.** Proposed owner: deployment owner; P1. Target:
verify clearing at the configured deadline within an approved timer tolerance,
including lock and ownership changes, on every supported Windows configuration.
Document applications allowed to receive secrets and audit exception use without
logging secret contents. Accept explicitly that zero clipboard reads cannot be
guaranteed by Vordr while clipboard use remains enabled.

**Evidence.** [gui.asm](../src/gui.asm): clipboard/reveal/lock paths;
[plaintext reference](SECRETS.md#clipboard-and-previews).

### R7b — Plaintext attachment files and external viewers

**Scenario and exploitation.** A preview or download writes plaintext. An
attacker reads the temporary/destination file, a viewer retains it, or termination
leaves it behind. A malicious attachment can also attack the chosen viewer;
Vordr's encryption does not sanitize the document or constrain the viewer's network use.

**Controls and strength.** Exclusive creation in random directories, tracked
overwrite/flush/delete attempts, and retry of viewer-held files are **Partial**:
they improve ownership and cleanup but not secure erasure or viewer isolation.
`NoPreview` is **Strong for disabling automatic hand-off**, not for preventing
explicit plaintext downloads. There is no control over independent viewer caches.

**Residual assessment.** I=4, L=3, **High (12), High confidence in copy creation**.
Actual malicious access depends on permissions, viewer behavior, and lifecycle.
Impact can reach 5 for key-bearing attachments or a successful viewer exploit
that compromises the endpoint; that exploit is not established here.

**Further mitigation.** Prefer download-only policy where previews are unnecessary,
use constrained viewers, and make plaintext retention visible. Strict cleanup
requirements may require avoiding previews entirely; encrypted storage cannot
protect a file from the live viewer intentionally given its plaintext.

**Treatment and measurement.** Proposed owner: deployment owner/maintainer; P1.
Target: zero preview launches under `NoPreview`; exercise close, lock, blocked
viewer, retry, forced stop, and reboot with synthetic files. Count residual paths
and viewer-created copies separately. Establish a cleanup SLA for managed
destinations; explicitly retain forced-stop and physical-erasure exceptions.

**Evidence.** [gui.asm](../src/gui.asm): `gui_temp_purge` and preview/download paths;
`tmptest`; [secret memory](SECRETS.md).

### R7c — Offline guessing of ZIP exports

**Scenario and exploitation.** An attacker acquires an encrypted ZIP export
and tests candidate export passwords offline. A complete-vault export can make
all included secrets available through a cheaper password-derivation path than
the native vault, even when the original vault remains intact.

**Controls and strength.** WinZip AE-2 AES encryption and authentication are
**Strong against direct plaintext reading under an unknown strong key**, subject
to implementation correctness. PBKDF2-HMAC-SHA1 at 1,000 iterations is **Partial
against guessing** and provides materially less work per guess than native
Argon2 defaults. Calling both files “encrypted” obscures this difference.

**Residual assessment.** I=5, L=3, **Very high (15), Medium confidence** assumes
an exposed full export protected by a human-chosen password. A unique randomly
generated high-entropy export password can justify L=1; a small selective export
reduces impact. There is no measured cracking-time claim here.

**Further mitigation.** Prefer native format for native backups; use strong
independent export passwords, selective data, and short retention for required ZIP
exchange. Raising the ZIP KDF unilaterally would break interoperability rather
than silently improve a standard AE-2 archive.

**Treatment and measurement.** Proposed owner: data owner/maintainer; P1. Target:
100% of managed exports have an approved purpose, format, recipient, expiration,
and password-generation process; zero untracked full-vault ZIP backups. Test
wrong-password/tamper rejection and a supported recipient round-trip. Restrict
inventory to metadata; do not centralize export passwords in the tracker.

**Evidence.** [zipexport.asm](../src/zipexport.asm): `PBKDF2_ITERS`, `ze_compose`;
[zipimport.asm](../src/zipimport.asm): `zi_decrypt`; ZIP regression probes.

### R7d — Superseded secrets retained in copies

**Scenario and exploitation.** Someone later opens history, trash, an older
backup, or a retained export and recovers a value the user believed removed.
An attacker who already copied an old vault can continue attacking its old
password. Deleting today's entry or rotating today's vault password does not
modify those independent copies.

**Controls and strength.** Encryption is **Strong for the confidentiality of
each still-protected native copy**. History suppression and export filtering are
**Partial retention controls**; native/ZIP exports omit history, but existing
backups and copied files are not retroactively cleaned. There is **None for
revoking an attacker's existing ciphertext or plaintext**.

**Residual assessment.** I=4, L=3, **High (12), High confidence in the retention
boundary**. Disclosure still requires access to usable plaintext or a way to
unlock the retained copy. Impact falls if the underlying service credential has
actually been revoked; deleting it from Vordr alone does not accomplish that.

**Further mitigation.** Define retention and revoke superseded credentials at
their source. Use `NoHistory` when retention is unnecessary, and reconcile backup
retention with recovery obligations. Shorter retention reduces recovery options;
no cleanup policy can guarantee erasure of copies outside its control.

**Treatment and measurement.** Proposed owner: data owner; P2. Target: a retention
period and owner for every managed copy class, periodic expiry checks, and a
tested service-credential revocation checklist. Measure overdue copies and
unrevoked superseded credentials; target zero in managed scope. Record external
copies as unrevocable exposure, not deleted simply because a cleanup task ran.

**Evidence.** [vault.asm](../src/vault.asm): exchange/filtering and history records;
[gui.asm](../src/gui.asm): history/trash settings; [format](formats.md#history).

### R7e — Metadata disclosure without decryption

**Scenario and exploitation.** A file or storage observer reads public header
values, sizes, attachment record identifiers/lengths, counter changes, paths,
and timestamps. Comparing snapshots can reveal activity or association without
recovering passwords. The significance depends on whose activity is sensitive.

**Controls and strength.** Encryption is **Strong for record contents**, and
authentication protects included metadata against undetected modification.
Neither is a confidentiality control for intentionally public metadata: **None
for hiding file size or all storage-side activity**. Hashed/local identifiers do
not conceal every path or relationship visible to Windows and the storage layer.

**Residual assessment.** I=2, L=5, **High (10), High confidence, conditional on
file/storage visibility**. “High” here results from reliable limited disclosure;
it is not equivalent to whole-vault compromise. Raise impact for surveillance-
sensitive contexts, or accept it explicitly for ordinary storage use.

**Further mitigation.** Minimize identifying filenames and storage exposure;
evaluate padding or metadata-encryption changes only if required. Padding adds
storage/traffic and does not hide all timing; format changes require migration.

**Treatment and measurement.** Proposed owner: data owner; P2. Target: a byte-level
inventory of every public field and a metadata-acceptance decision for each
storage channel. Compare synthetic snapshots and list what remains inferable.
Do not claim metadata confidentiality from a test that checks only encrypted
record contents.

**Evidence.** [format](formats.md#container-layout), [vault.asm](../src/vault.asm),
[registry inventory](DEPLOYMENT.md#registry-inventory).

### R7f — Password and TOTP seed compromised together

**Scenario and exploitation.** An attacker who unlocks a vault containing both
an account password and its TOTP seed can generate that account's codes as well
as use the password. The prerequisite is compromise of the shared store, not a
break in HOTP/TOTP itself. Co-location increases the consequence of other risks.

**Controls and strength.** Vault encryption protects both secrets **Strongly
within the file boundary**. There is **None for independence of these factors
against vault compromise**. Code expiration limits the life of an observed code,
not an extracted seed that can generate future codes.

**Residual assessment.** I=5, L=5, **Critical (25), High confidence, conditional
on co-location and vault compromise**. This is a consequence multiplier, not an
independent annual event to add to R1/R4a/R5. No co-location means this scenario
does not apply; the password-only risks remain.

**Further mitigation.** Keep high-value second factors in a separate trust
domain, preferably a service-supported hardware-backed factor. This adds hardware,
recovery, and user-workflow requirements; a second file on the same compromised
endpoint may not provide meaningful separation.

**Treatment and measurement.** Proposed owner: identity/data owner; P1. Target:
classify privileged accounts, count password/seed co-location, and require zero
co-located independent factors for accounts whose policy requires separation.
Test recovery and revoke migrated seeds. Record accepted convenience exceptions
without labeling them independent protection against vault compromise.

**Evidence.** [totp.asm](../src/totp.asm); [format](formats.md#field-kinds);
the common decrypted record body in [vault.asm](../src/vault.asm).

### R8a — Replay of an older authentic vault

**Scenario and exploitation.** A storage attacker returns an older valid image.
The attacker does not forge its MAC. If the matching local registry history is
absent or also rolled back, freshness evidence is lost and old credentials/data
can appear current. On a new machine there may be no local history to compare.

**Controls and strength.** The full-file MAC and included counter are **Strong
against undetected counter editing without a key**. Comparing the counter with
HKCU history is **Partial detection**, with best-effort mirror persistence and
no independent trusted monotonic state. Authenticity is not freshness.

**Residual assessment.** I=4, L=3, **High (12), High confidence in the limitation**
for storage replay combined with missing/untrusted local history. A file-only
attacker facing intact newer history should trigger a warning; rolling back both
is not defeated. Risk depends on whether stale secrets cause consequential actions.

**Further mitigation.** Keep independently protected version history, verify
freshness before recovery, or design a trusted monotonic-state mechanism.
Hardware counters constrain portability; remote witnesses change the offline
architecture and availability model. Neither is an approved redesign here.

**Treatment and measurement.** Proposed owner: data/storage owner; P1. Target:
replay tests with intact, absent, failed-write, and rolled-back mirrors, plus a
fresh-machine restore. Require detection in every configuration claimed protected;
list the others as explicit acceptance conditions. Do not use passing MAC tests
as the freshness metric.

**Evidence.** [vault.asm](../src/vault.asm): `vault_unlock` counter comparison;
[regcfg.asm](../src/regcfg.asm): counter storage; `rbtest`, `mactest`.

### R8b — Concurrent or synchronized write conflicts

**Scenario and exploitation.** Two users/processes edit different snapshots or
a sync client replaces an image between operations. A non-cooperating writer
ignores the application's lock. Lost or stale changes can occur without an
attacker; intentional storage interference can provoke the same sequence.

**Controls and strength.** Advisory locks, changed-image checks, temporary writes,
and failed-edit restoration are **Partial** overall. They protect important local
sequences but do not implement a distributed transaction, merge protocol, or
lock honored by every filesystem/sync actor.

**Residual assessment.** I=3, L=3, **Moderate (9), Medium confidence** for shared/
synced editing. A single local writer lowers exposure; a deployment using routine
multi-machine simultaneous edits should raise L. Copies that preserve both edits
reduce loss, but still require a trustworthy conflict-resolution procedure.

**Further mitigation.** Enforce a single-writer workflow and use tested conflict
recovery. Stronger compare-and-swap or versioned synchronization would require
storage-specific design and compatibility work; retries alone are not resolution.

**Treatment and measurement.** Proposed owner: storage owner/maintainer; P2.
Target: run concurrent-save, external-replace, offline/reconnect, and conflict-copy
tests on every supported storage configuration; zero silent lost updates within
the claimed supported workflow. Record unsupported configurations and conflict
frequency. Preserve originals during recovery, and measure time to resolve a
synthetic conflict rather than assuming automatic merging exists.

**Evidence.** [vault.asm](../src/vault.asm): `vault_lock_acquire`,
`vault_ext_changed`, `vault_reseal`; `xctest`, `cowrite`, `layoutkat`.

### R9a — Loss of the only recoverable vault copy

**Scenario and exploitation.** Disk failure, ransomware, deletion, or interrupted
storage operations remove/corrupt all usable copies. An attacker able to delete
files needs no decryption key. Nearby rotating backups may fail with the same
disk, permissions, or sync account as the live file.

**Controls and strength.** Temporary-image writes, flushing, replacement, and
rotation are **Partial availability controls**, not universal power-loss durability.
Encryption is **None against deletion**. Independent tested backup is an operator
control, and no effective deployment-specific backup is evidenced in this assessment.

**Residual assessment.** I=5, L=2, **High (10), Medium confidence** when no
independent recovery has been demonstrated. Loss is uncommon but potentially
permanent. Active destructive access with no independent backup raises L to 5;
verified independent restoration can reduce the consequence from permanent loss.

**Further mitigation.** Use independent versioned/offline or suitably protected
backups and test restoration. Additional copies increase confidentiality/retention
exposure (R1/R7d); recovery design must protect their passwords and integrity too.

**Treatment and measurement.** Proposed owner: backup/data owner; P1. Target:
approve numerical recovery-point and recovery-time objectives before reliance;
restore a synthetic/current test copy on another suitable machine at least
quarterly and after backup changes. Record last successful restore, backup age,
recovered data version, and elapsed time. Until objectives are assigned and met,
the risk remains Open, not “mitigated by backups.”

**Evidence.** [vault.asm](../src/vault.asm), [fileio.asm](../src/fileio.asm);
`bktest`, [verify_persistence.py](../tests/verify_persistence.py).

### R9b — Loss of password and TPM access

**Scenario and exploitation.** A user forgets the master password after relying
on TPM convenience, then loses the enrolled device/key through replacement,
clearing, or reinstall. An attacker can remove local enrollment to deny the
shortcut, but permanent loss additionally requires no usable password/recovery record.

**Controls and strength.** Password unlock remains a **Strong independent route
from the original TPM** when the password is known. Reverification reminders are
**Partial human controls**. There is **None for resetting an unknown master
password**; deliberately adding a recovery party would add another secret-access path.

**Residual assessment.** I=5, L=2, **High (10), Medium confidence** where password
recovery is untested. A verified protected record lowers likelihood; it introduces
its own access/coercion exposure and must not be stored solely inside this vault.

**Further mitigation.** Keep an independently protected password record and
practice password-based unlock. Organizational escrow may improve availability
but transfers confidentiality trust to escrow administrators and their process.

**Treatment and measurement.** Proposed owner: vault owner; P1. Target: demonstrate
password-based restoration without the original TPM, with an authorized person
able to locate the protected record. Retest at least quarterly and after password/
device changes. Record success/date only, not the password. Never clear the only
enrolled TPM merely to test recovery before verifying the alternative route.

**Evidence.** [tpm.asm](../src/tpm.asm), [vault.asm](../src/vault.asm): unlock routes;
[user guide](USER_GUIDE.md); `PwVerifyDays` in [deployment](DEPLOYMENT.md).

### R10 — Deployment policy not actually enforced

**Scenario and exploitation.** An administrator assumes a policy is enforced,
but writes an unsupported/wrong-typed value, uses the wrong registry view, or
upgrades without repeating MSI properties. The application then uses user/default
values. A user may exercise the resulting permissions without bypassing valid
HKLM policy; this is not evidence that any standard user can edit HKLM.

**Controls and strength.** Valid supported HKLM precedence and locked settings
are **Strong within their defined configuration paths**. Type fallback, installer
property lifecycle, UI differences, and no proof of deployment readback make
end-to-end enforcement **Partial**. Private desktop/TPM exceptions are R4b/R5;
read-only and `NoPreview` do not constitute comprehensive data-loss prevention.

**Residual assessment.** I=4, L=3, **High (12), Medium confidence** without
configuration verification. The impact follows the specific missing policy;
a color setting is not a security incident. Policy on a valid supported path
should receive credit; assume neither universal bypass nor universal enforcement.

**Further mitigation.** Keep policy as versioned deployment configuration,
repeat it on upgrade, and verify effective values and behavior. A future strict
policy mode could reject malformed security policy rather than falling through,
but would need a safe repair path for accidental misconfiguration.

**Treatment and measurement.** Proposed owner: deployment administrator; P1.
Target: 100% of intended security values and their effective behavior verified
after install/upgrade; zero unexplained drift. Test wrong type/view, absent value,
HKCU conflict, upgrade with/without properties, and non-admin access. Retain MSI
and behavior results; settings-screen appearance alone is insufficient evidence.

**Evidence.** [regcfg.asm](../src/regcfg.asm), [gui.asm](../src/gui.asm),
[make_msi.ps1](../tools/make_msi.ps1), [verify_msi.ps1](../tools/verify_msi.ps1);
[deployment](DEPLOYMENT.md).

### R11a — Substituted source, toolchain, or release

**Scenario and exploitation.** An attacker compromises a release account,
distribution route, build inputs/toolchain, or the local executable. A substituted
program captures secrets at unlock. Changing both a download and its same-channel
hash can defeat a naive hash-only verification process.

**Controls and strength.** Published hashes and reproducible-build support are
**Strong for byte comparison under trusted reference inputs**, but **Partial
for provenance**. Open source and no bundled runtime reduce some hidden inputs,
not Windows, SDK, assembler, CPU, build-account, or distribution trust. Offline
application behavior does not constrain a malicious replacement executable.

**Residual assessment.** I=5, L=2, **High (10), Medium confidence** assuming
genuine current inputs but no independently verified provenance chain. A known
account/binary compromise changes the scenario to urgent containment, not another
routine verification attempt. Matching bytes do not prove benign source.

**Further mitigation.** Protect release credentials, record build provenance,
independently rebuild exact tags, and evaluate signing/attestation. Signing adds
key-management costs and authenticates an issuer; it does not certify code safety.

**Treatment and measurement.** Proposed owner: release maintainer/deployment owner;
P1. Target: every released/deployed binary linked to an exact source revision,
toolchain identity, and retained hash; zero unexplained rebuild mismatches.
Independently verify release-channel/key access and test response to a mismatched
binary. Track verification coverage and exceptions, not merely whether a hash
file was published beside the installer.

**Evidence.** [build.cmd](../build.cmd), [release records](RELEASES.md),
[release checklist](RELEASE_CHECKLIST.md), [build workflow](../.github/workflows/build.yml).

### R11b — Vulnerable builds persisting after disclosure

**Scenario and exploitation.** After a real vulnerability becomes known, an
attacker targets users who retain an affected copy. No automatic update reaches
them, or maintainer capacity delays a fix. This scenario requires an applicable
vulnerability; it does not assert that every currently published build is exploitable.

**Controls and strength.** Private reporting, newest-release support, advisories,
and release records are **Partial response controls**. They do not ensure discovery,
remediation within a fixed time, or adoption. MSI/package inventory can help;
portable copies and one-person maintenance leave important coverage/continuity gaps.

**Residual assessment.** I=5 for a key-disclosing defect, L=3, **Very high (15),
Medium confidence, conditional on such a disclosure** in an unmanaged population.
A lower-impact vulnerability needs its own impact score. Fleet update latency
and maintainer response performance are not measured here.

**Further mitigation.** Assign update monitoring, inventory deployed copies,
and prepare a supported migration route. An automatic updater would add signing,
network, and rollback trust requirements; it is not assumed present or approved.

**Treatment and measurement.** Proposed owner: deployment owner/release maintainer;
P1. Target: inventory 100% of managed executable versions including portable
copies; define critical-fix deployment and unsupported-build retirement deadlines.
Measure time from advisory to triage, fix availability, and verified adoption
separately. Exercise a migration/credential-rotation plan if no fix is available.
No numeric SLA is claimed until owners approve and measure it.

**Evidence.** [security policy](../SECURITY.md), [release records](RELEASES.md),
[release checklist](RELEASE_CHECKLIST.md).

### R12 — Long-term cryptanalysis and TPM RSA exposure

**Scenario and exploitation.** An adversary retains encrypted vaults and,
where available, a TPM-wrapped vault key with its corresponding RSA public key.
A sufficiently capable future quantum computer could attack RSA mathematically;
physical possession of the original TPM would not then be necessary. Availability
of that material and future capability are prerequisites, not demonstrated here.

**Controls and strength.** AES-256 gives a **Strong symmetric-algorithm margin**
against known generic search, conditional on implementation and password entropy.
TPM non-exportability is a classical key-protection control, **None against a
future mathematical RSA break**. No whole-format post-quantum assurance or migration
guarantee is established. NIST distinguishes symmetric search costs from the
quantum vulnerability of RSA; see its [FAQ](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/faqs)
and [overview](https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography).

**Residual assessment.** I=5, L=U, **Unrated, Low confidence over the secret's
lifetime**. This is not a prediction of practical RSA-breaking within twelve
months, nor a claim that Argon2's economics are unaffected by quantum computing.
For long-lived high-value secrets, unknown timing warrants a decision now because
later migration cannot retract ciphertext or wrapped keys already harvested.

**Further mitigation.** Avoid unnecessary RSA-wrapped copies for such assets,
minimize retention, and plan reviewed cryptographic agility. Removing current
enrollment cannot invalidate a previously captured wrapping. Re-encrypting new
data does not revoke older service credentials unless those credentials are rotated.

**Treatment and measurement.** Proposed owner: cryptographic/data owner; P1 for
long-lived secrets, otherwise P3. Target: 100% of high-value secret classes have
a confidentiality lifetime, wrapping/dependency inventory, and migration trigger.
Review standards and retained-material exposure at least annually and after
material cryptanalytic changes. Validate any migration with old/new recovery and
interoperability tests; do not mark this risk closed merely by disabling TPM today.

**Evidence.** [tpm.asm](../src/tpm.asm): RSA-OAEP wrapping;
[format](formats.md); NIST algorithm guidance above. The attack consequence is
an inference from that design, not a successful experiment against a TPM.

## Treatment governance

### Turn a target into an accountable decision

All targets above are **proposed acceptance criteria**, not achieved measurements
or project commitments. Current operational metric baselines are **not collected**.
Zero known incidents, an empty finding list, or a test that was skipped is not
evidence of zero risk. This document is the canonical readable register; do not
scatter acceptance decisions into unrelated guides.

For every applicable ID, record the following in the organization's tracking
system, or in an appended decision record here:

| Field | Required content |
|---|---|
| Scope | Exact release/commit, assets, endpoints/storage, relevant settings, and assessment horizon |
| Accountable owner | Named person who can authorize treatment or acceptance; role suggestions above are not assignments |
| Current rating | I, L (or U), class, confidence, prerequisite assumptions, and evidence date |
| Decision | Mitigate, avoid, transfer/shared responsibility, accept, or investigate; reason and approving authority |
| Work and deadline | Specific control/change, ticket, named implementer, and calendar due date |
| Measurement | Metric numerator/denominator or duration, test conditions, baseline, numerical target where applicable, and evidence location |
| Remaining exception | What the treatment cannot prevent, who bears the consequence, and compensating controls actually verified |
| Post-treatment rating | New reasoning and evidence; never copy a hoped-for target into the current-risk field |
| Review trigger | Expiry date plus source/configuration, incident, dependency, or threat changes that reopen the decision |

Use the lifecycle **Open → Assigned → Treatment implemented → Verification →
Accepted/Monitoring**, or **Avoided** if the scoped capability is demonstrably
removed. A failed verification returns the record to treatment. An investigation
may establish L or split a risk; it must not quietly mark an unresolved hypothesis
as false. Acceptance requires an accountable approver, scope, and expiry date.
“Out of product scope” alone is not acceptance of the deployment risk.

### Minimum measurable review dashboard

Keep measurements separate from ordinal scores. Proposed targets are:

| Measure | How to measure | Initial target |
|---|---|---|
| Ownership coverage | Applicable IDs with named owner and deadline / all applicable IDs | 100% before deployment approval |
| P1 disposition | P1 IDs with verified treatment, approved avoidance, or time-limited acceptance / applicable P1 IDs | 100%; unknowns require an explicit investigation/acceptance decision |
| Evidence freshness | Active decisions reviewed against the deployed revision/configuration / active decisions | 100% after a relevant release or configuration change |
| Verification completion | Passed required cases / planned required cases; show failures and skips separately | All required cases executed and passed; no unexplained skips |
| Exception debt | Count and age of overdue treatments and expired acceptances | Zero overdue items without renewed accountable approval |
| Recovery readiness | Last successful restore age, measured recovery time, and recovered-version age | Within approved RTO/RPO and test cadence; no assumed values |
| Update exposure | Affected deployed copies and days past the approved adoption deadline | Zero past deadline without containment/approved exception |

Do not average Critical endpoint exposure away with Low scores elsewhere, or
double-count R7f as an independent event on top of the vault compromise that
enables it. Storage/backup changes can reduce R9a while increasing R1/R7d;
disabling TPM can reduce R5 while increasing recovery burden in R9b. Reassess
both sides of a treatment rather than reporting only its intended benefit.

### Evidence required for release and reassessment

The [assurance guide](ASSURANCE.md) describes source checks, fault injection,
crypto vectors, parser/persistence probes, and their limitations. Before running
`tests\run_all.cmd`, read the [test-safety warning](DEVELOPMENT.md#full-test-gate-read-before-running):
it stops running Vordr processes and replaces build outputs. Record the commit,
toolchain, full logs, failed cases, and skipped stages. `--quick`, missing Python,
or missing packaging tools can leave checks unexecuted despite a success banner.

Reassess affected IDs whenever key/nonce ownership, cryptography, parser entry
points, memory ownership, desktop lifecycle, TPM policy, storage, deployment,
or release procedures change. Independently reviewing code and executing a
bounded test campaign can improve confidence; neither establishes absence of
all future vulnerabilities. Trust rests on the traceable reasoning, observed
control behavior, and explicit treatment of what remains.
