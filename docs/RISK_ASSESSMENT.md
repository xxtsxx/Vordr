# Vordr risk assessment

[Project overview](../README.md) · [Documentation](README.md) · [Test evidence](ASSURANCE.md)

Reading guide: [overall assessment](#overall-assessment),
[scope](#scope-and-basis), [risk register](#risk-register),
[cryptography](#cryptography-and-stolen-file-protection),
[endpoint and plaintext](#input-endpoint-and-plaintext-exposure),
[recovery and maintenance](#integrity-recovery-deployment-and-maintenance),
[assurance gaps](#assurance-strengths-and-remaining-gaps),
and [acceptance decisions](#decisions-required-before-relying-on-vordr).

## Overall assessment

Vordr's main security purpose is to protect the confidentiality and integrity
of a stolen or modified vault file. It combines password-based key derivation,
authenticated encryption, full-file authentication, and local runtime hardening.
Its offline design removes a built-in network service and vendor-hosted vault
store from the application architecture. Those are useful protections, not a
guarantee that the solution as a whole is secure.

The largest unresolved assurance concern is the amount of security-critical
code implemented within the project: cryptographic primitives and their
composition, assembly memory management, file parsers, and GUI secret lifetimes.
No independent external security review is recorded in the repository. Tests
provide meaningful evidence on selected paths, but do not establish how likely
an undiscovered vulnerability is.

The practical protection boundary is equally important. An unlocked vault,
an authorized TPM unlock, a clipboard copy, or an attachment preview can expose
secrets without breaking the file encryption. Strong passwords do not compensate
for a compromised endpoint. Encryption does not prevent deletion, loss of the
master password, or restoration of an older authentic file.

For a security-sensitive deployment, treat Vordr as a pre-1.0 implementation
requiring explicit risk acceptance, not as an independently audited security
product. A deployment requiring assured endpoint isolation, guaranteed second
factor enforcement, global rollback prevention, or independently validated
cryptographic implementation cannot establish those properties from the
current repository evidence.

## Scope and basis

This assessment was consolidated on **2026-09-12** against source revision
**`d9b7663`**. It draws on the implementation, test harnesses, existing technical
documentation, and the earlier README risk assessment. Relevant source paths
and probe names are provided below so a reviewer can check the reasoning.

This is a source-based design and residual-risk assessment, not a new penetration
test, exhaustive vulnerability scan, certification, or fresh execution of the
full test gate. It does not assign affected release ranges to historical bugs.
Review the exact release tag and binary before applying it to a deployed copy.

The assessment is intended to be readable on its own. Linked references supply
byte-level details, buffer inventories, and reproduction instructions; they
are not required to find the principal risks. [SECURITY.md](../SECURITY.md)
remains the authority for reporting, support, disclosure, and report scope.
Describing a residual risk here does not create a new policy exclusion.

### Assets and trust assumptions

The protected assets are master passwords, vault and attachment keys, passwords
and notes, TOTP seeds, previous values in history, attachments, and the integrity
and availability of those records. Paths, file sizes, update timing, registry
state, and exported copies also matter even when they are not plaintext secrets.

Protection depends on a trustworthy Windows installation, user session, CPU,
system random generator, build environment, and executable. TPM convenience
unlock additionally depends on the platform provider, its key-access controls,
and the local enrollment state. Users must keep a strong master password and
independent recoverable backups. Another application receiving plaintext becomes
part of the confidentiality boundary for that copy.

Relevant adversaries include someone holding a vault or backup; a storage or
sync operator able to replace, replay, or delete files; a sender of a malicious
import; code running in the user's session; a privileged or physical attacker;
and an attacker able to substitute a build or release. Accidental corruption,
interrupted saves, forgotten passwords, and delayed updates are risks too.

## Risk register

These are risk scenarios, not a list of confirmed exploitable vulnerabilities.
Impact describes a plausible consequence if the scenario succeeds. No numeric
likelihood or overall score is assigned: deployment exposure and independent
assurance evidence are insufficient to justify one. The final column states
what remains after the implemented controls, not merely whether a control exists.

| ID | Scenario and prerequisite | Potential impact | Residual risk / acceptance condition |
|---|---|---|---|
| R1 | Attacker obtains a native vault or backup | Disclosure of all contents through offline guessing | Argon2id raises the cost per guess; weak passwords and cheaper historical copies remain exposed. Accept only with a strong, unique master password and controlled copies. |
| R2 | Cryptographic implementation, composition, or randomness fails | Loss of confidentiality or undetected modification | Known-answer tests and random nonces reduce specific risks; no independent composition or side-channel assessment is recorded. Specialist review remains necessary. |
| R3 | Crafted vault, archive, JSON, or attachment reaches a parser | Resource exhaustion; a parser defect could expose memory or permit code execution | Authentication and bounds checks narrow exposure but do not make input safe. Structural fuzzing is bounded, and expensive work precedes authentication. |
| R4 | Malicious code or an observer can access the active user environment | Capture of password entry, decrypted records, or copied secrets | Private desktop, timers, and memory hardening are partial protections, not a general same-user malware boundary. Privileged and hardware compromise are not defended. |
| R5 | Attacker can use the enrolled user's TPM key and wrapped vault key | Vault access without typing the master password | TPM unlock is an alternative access route. Provider prompting is best-effort, not guaranteed second-factor enforcement. |
| R6 | Sensitive memory is paged, dumped, copied, or left after an abnormal exit | Recovery of plaintext or key material | Not all sensitive memory is locked; some lock failures only warn. Wiping covers owned paths, not every copy or termination mode. |
| R7 | Secrets are copied, revealed, exported, previewed, or retained in history | Disclosure outside the intended lifetime or recipient set | Clipboard flags and cleanup cannot revoke another application's copy. ZIP has a cheaper KDF; old vaults, history, and backups retain previous data. |
| R8 | Storage serves an older authentic file or concurrent writers diverge | Undetected stale data, lost changes, or use of obsolete credentials | Local rollback history and advisory locks are not trusted global state or a distributed synchronization protocol. |
| R9 | Device/storage fails, files are deleted, or unlock credentials are lost | Permanent loss of access or records | Atomic replacement and nearby backups reduce some failures but do not replace independent tested recovery. TPM is not portable recovery. |
| R10 | Deployment relies on a setting stronger than its implementation | Silent loss of an expected organizational control | HKLM enforcement has type/precedence requirements; upgrades must repeat MSI policy properties. Private-desktop and TPM prompting have fallback behavior. |
| R11 | Release/build is substituted, maintenance stalls, or updates are missed | Malicious executable or continued use of a vulnerable build | Hashes, source, and rebuilds support verification, not automatic trust. One-person maintenance and no automatic updater leave response and adoption gaps. |
| R12 | Long-lived ciphertext and TPM material are retained for future cryptanalysis | Later disclosure of historically protected secrets | AES-256 and password entropy must be distinguished from RSA-based TPM wrapping. No whole-product post-quantum guarantee is established. |

## Cryptography and stolen-file protection

### Password guessing and authentication — R1

Native vaults use AES-256-GCM and Argon2id, with production defaults of 512 MiB,
three passes, and one lane. The password and a random 32-byte salt derive the
32-byte vault key. The visible key-check value is the first 16 bytes of
SHA-256 of that key. A file holder can test password guesses offline; there is
no server-side lockout or rate limit. The KCV is a key check, not a defense
against offline guessing or proof that every key-commitment property holds.

The reader accepts KDF costs below the production defaults as well as higher
ones. Assess the actual file, including old backups, rather than assuming every
accepted vault uses 512 MiB. Password length/class policy is not an entropy
measurement. Changing the current password does not re-encrypt an attacker's
previously captured copies.

The complete 80-byte header is GCM associated data. A mandatory full-file MAC
authenticates the image through its save counter before attachment lengths are
used to locate the encrypted body. Attachments have individual GCM tags, with
their keys held in the encrypted body. These mechanisms are intended to reject
tampering; they neither conceal all metadata nor prevent replay of an intact
older file. File size, public header fields, attachment record sizes/identifiers,
and the public counter can expose structure or changes over time.

Evidence: [vault implementation](../src/vault.asm), particularly `vault_unlock`,
`vk_params_ok`, and `vk_kcv_ok`; [file format](formats.md); `mactest` and `kdfparam`.

### Custom implementation and nonce lifecycle — R2

Published algorithms are implemented in handwritten assembly inside this
repository. This removes bundled library dependencies and makes instruction
choices explicit, but also places implementation, integration, and maintenance
responsibility on this project. It is not inherently safer than a reviewed
cryptographic library or a memory-safe implementation.

The file MAC is BLAKE2b-256 over a domain prefix, the vault key, and the file
image through the counter. It is **not BLAKE2's native keyed mode**. The vault
key is also used for body encryption and the KCV. Review that composition and
its domain separation as a whole; primitive test vectors alone cannot validate
it. The presence of a custom composition is a review obligation, not by itself
evidence of an exploit.

`vault_reseal` draws a fresh 96-bit body nonce before building a new encrypted
image, including on a later retry after failure. Internal write retries use
the already-built ciphertext. The save counter is not the nonce. New attachments
receive random keys and nonces; existing ciphertext may be copied unchanged,
and pending attachment encryption uses the staged bytes. Copying an unchanged
ciphertext is different from encrypting changed plaintext with a reused key/nonce.
Preserving that distinction across edits, retries, imports, and exports is a
security-critical invariant.

Random nonces have a nonzero collision probability. Randomness comes primarily
from `BCryptGenRandom`; failure is reported rather than replaced with a weaker
generator. Optional RDSEED mixing is supplementary. Neither mechanism protects
against a hostile OS. Do not read “fresh random nonce” as a deterministic
uniqueness guarantee or a complete GCM usage-limit analysis.

Fixed-length secret comparisons use `ct_memcmp`; GUI wide-string comparisons
still expose length. Crypto cross-checks establish agreement on tested inputs,
not side-channel resistance across the complete application.

Evidence: [vault writer](../src/vault.asm) (`vault_reseal`, `vault_seal_write`,
`attach_stage`, `attach_emit_one`), [RNG](../src/random.asm),
[GCM](../src/aesgcm.asm), [hardening](../src/hardening.asm), and
[crypto verifier](../tests/verify_crypto.py).

### Long-term and quantum exposure — R12

The native vault's encryption is symmetric; the optional TPM wrapping path uses
RSA. These have different quantum attack models. NIST describes substantial
remaining margins for AES-192/256 against known quantum search methods, while
large-scale quantum computers would threaten RSA. That is algorithm-level
guidance, not validation of Vordr's implementation or password strength.
See [NIST's PQC FAQ](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/faqs)
and [PQC overview](https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography).

Do not claim that Argon2id's cost is unaffected by quantum attacks, that the
whole solution provides a fixed number of post-quantum security bits, or that
a TPM makes RSA post-quantum. An attacker who retains an RSA-wrapped vault key
and the corresponding public key could, given a sufficiently capable future
quantum computer, attack RSA mathematically without using the original TPM.
This is an inference from the implemented wrapping design and RSA's vulnerability,
not a claim that such an attack is currently practical.

Long-term confidentiality review must include registry/TPM material as well as
vault copies. Disabling future TPM use does not retract material already copied
by an attacker. No complete post-quantum migration or historical-copy revocation
guarantee is established here.

## Input, endpoint, and plaintext exposure

### Parsers and runtime hardening — R3

The application must inspect unauthenticated headers before deriving a key.
KDF caps allow up to 16 passes and 4 GiB of memory: bounded is not inexpensive.
An attacker-controlled file can therefore impose significant unlock cost before
authentication rejects it. ZIP import also parses archive structures before
password verification; authenticated content still needs bounds and semantic
validation, since a malicious sender can create content under a known password.

Stack canaries, a software shadow stack, guarded indirect calls, checked
arithmetic, bounds/type checks, heap tags, and a read-only import table provide
defense in depth. ASLR, DEP/NX, and CET compatibility are build-level measures.
They detect selected failure patterns; they do not make assembly memory-safe.
The software indirect-call guard is not Windows CFG, which is not enabled.

Evidence: [vault](../src/vault.asm), [ZIP import](../src/zipimport.asm),
[ZIP export](../src/zipexport.asm), [shared macros](../src/macros.inc),
[hardening](../src/hardening.asm), and [fault injection](../src/redteam.asm).
Probes include `vfuzz`, `fuzzzip`, `jfuzz`, `attfuzz`, and `zexcap`.

### Local access, password entry, and TPM — R4 and R5

The unlocked record body and usable keys exist in process memory. No general
defense against same-user malware is established merely by locking that memory
or moving password entry to another desktop. Auto-lock and Windows-session
locking reduce the exposure window, but do not revoke a secret already read.
Kernel, administrator-level unlocked access, and hardware attacks are outside
the protection model; coercion and access to an already unlocked UI are not
solved by cryptography either.

Secure Unlock uses a private Windows desktop for password entry, reducing
ordinary desktop observation. It is not the privileged Windows UAC consent
boundary, does not protect subsequent unlocked use, and falls back to a normal
dialog if setup fails. Timeout recovery and the lifetime of the desktop worker
also deserve targeted failure/concurrency testing, not just a successful demo.

TPM unlock wraps the vault key through Microsoft Platform Crypto Provider.
It is password **or** TPM access, not password **and** TPM. Code able to use the
enrolled user's provider key and wrapped blob may follow that alternative route
without knowing the password. This is a material trust decision even when the
private RSA key cannot be exported.

The implementation requests RSA-2048 with OAEP-SHA256. The key-length property
request is best-effort, and an existing key is reused without checking its length.
`TpmRequireHello` also requests provider UI policy on a best-effort basis; removing
silent-call flags permits a prompt but does not establish mandatory independent
user verification. Do not deploy either setting as a guarantee stronger than
the provider behavior actually verified on the target machine.

Evidence: [GUI](../src/gui.asm) (`gui_secdesk_show` and desktop recovery),
[TPM](../src/tpm.asm) (`tpm_seal`, `tpm_unseal`), and
[deployment settings](DEPLOYMENT.md). Real desktop/provider behavior needs
environment-specific testing; crypto vectors do not cover it.

### Memory, clipboard, viewers, and retained copies — R6 and R7

Dynamic `secmem_alloc` arenas fail allocation if locking fails, and live arenas
are wiped before release. Selected static secret buffers are also locked, but
a static-lock failure warns rather than universally stopping startup. The
Argon2 arena, some conversion scratch, attachment buffers, and OS-owned copies
are not all covered by that lock list. Successful page locking is not a guarantee
against hibernation, system dumps, or privileged memory access.

Normal locking and exit wipe selected owned buffers. A handled fatal exception
attempts a limited panic wipe; forced termination and OS failure may bypass
cleanup. The live-allocation registry prevents repeated frees of unregistered
addresses, but does not distinguish an old pointer from a new allocation later
placed at the same address. A successful sentinel wipe test is not an inventory
of every secret-bearing copy.

Clipboard history/cloud exclusion flags are requests to cooperating features,
not access control. The clear timer cannot remove copies another application
already saved. Attachment previews write plaintext files and invoke external
viewers. Tracked overwrite/flush/delete cleanup retries blocked files while the
process remains alive, but cannot promise physical erasure, cleanup after forced
exit, or removal from viewer caches. Downloads intentionally persist plaintext.
The application has no network client; a launched browser/viewer or other local
software may nevertheless transmit data.

Encrypted ZIP exchange uses WinZip AE-2 with PBKDF2-HMAC-SHA1 at 1,000 iterations,
far cheaper to guess against than the native vault defaults. It is not an
equivalent password-protected backup. Password history, trash, old vault images,
and external copies also extend retention; removing a current entry is not a
promise of erasure from all of them. Keeping a password and its TOTP seed in
one vault means compromise of that vault can disclose both credentials.

Evidence: [secure memory](../src/secmem.asm), [Argon2](../src/argon2.asm),
[GUI cleanup](../src/gui.asm), and [ZIP export](../src/zipexport.asm).
`secscan`, `secfreedup`, `lktest`, and `tmptest` exercise selected paths;
the [buffer inventory](SECRETS.md) describes their ownership limits.

## Integrity, recovery, deployment, and maintenance

### Rollback, concurrent writes, and availability — R8 and R9

The authenticated save counter is compared with a per-vault HKCU mirror.
An older file can trigger a warning when trustworthy local history exists.
Rolling back both file and registry, losing that history, or moving the old file
to a new machine can evade the warning. Registry mirror updates are best-effort.
Authentication establishes that a file is intact, not that it is the newest one.

Advisory write locks and changed-image checks reduce accidental overwrites by
cooperating instances. Sync services and other writers need not honor those
locks. Temporary-image writes, flushing, replacement, and rotating backups
reduce partial-write exposure, but do not provide transactional guarantees across
arbitrary storage or sync systems. Failed-edit restoration preserves retryable
GUI state on the exercised paths; it does not establish universal crash durability.

A storage attacker can delete or withhold ciphertext without decrypting it.
Independent backups and tested restoration remain necessary. There is no
password-reset service. A cleared TPM, replacement motherboard, reinstall, or
move to a new machine can remove convenience access. Keep a secure record of
the master password and test password-based recovery; a reminder to type it is
not a recovery mechanism.

Evidence: [vault persistence](../src/vault.asm), [file I/O](../src/fileio.asm),
[registry state](../src/regcfg.asm), `bktest`, `rbtest`, `xctest`, `cowrite`,
`layoutkat`, and [persistence harness](../tests/verify_persistence.py).

### Policy, distribution, and project continuity — R10 and R11

Supported valid HKLM settings take precedence over HKCU preferences and compiled
defaults. Wrong types or absent values do not establish the intended policy.
MSI properties are not remembered deployment configuration: upgrades must repeat
them, or installer-owned policy values can disappear. `NoPreview` stops the
automatic viewer hand-off, not user-selected plaintext downloads. Read-only mode
is not a general data-loss-prevention boundary against someone able to read data.

The application does not request elevation on launch, but it still depends on
Windows DLLs, APIs, the assembler/linker/SDK, CPU behavior, packaging, and release
account security. Absence of bundled dependencies or networking does not remove
those trust relationships. A published hash identifies bytes; if binary and hash
are substituted together, comparison alone does not authenticate their origin.
A matching rebuild strengthens source-to-binary confidence but cannot establish
that the source, toolchain, or underlying platform is benign.

This is a one-person project supporting only the newest release, without
automatic updating or telemetry. Users and administrators must discover and
deploy fixes. Package-manager inventory can help, but portable or unmanaged
copies may remain vulnerable. There is no demonstrated organizational guarantee
of maintenance continuity or remediation time beyond the response targets in
the security policy. Antivirus results are evidence to investigate, not proof
of maliciousness or safety; broad exclusions create additional endpoint risk.

Evidence: [registry implementation](../src/regcfg.asm),
[build script](../build.cmd), [MSI generator](../tools/make_msi.ps1),
[deployment guide](DEPLOYMENT.md), [release verification](RELEASES.md), and
[security policy](../SECURITY.md).

## Assurance strengths and remaining gaps

| Evidence available | What it supports | What it does not establish |
|---|---|---|
| Startup known-answer tests and Python crypto cross-check | Agreement with fixed vectors and selected independent calculations | Complete crypto correctness, composition security, or side-channel resistance; Argon2 uses a published vector, not a second full Python implementation |
| Fault injection and source checkers | Selected runtime guards fire; recognized source patterns satisfy checks | Complete memory safety or full guard coverage; most fault cases accept a fail-fast code family, not an exact reason |
| Structural fuzzers and parser probes | Tested malformed inputs are handled as expected | Coverage-guided exploration or absence of untested parser faults |
| Wipe, preview, transaction, and persistence probes | Selected cleanup and failure/retry paths behave as tested | Every secret copy, arbitrary termination, power-loss durability, or all desktop/provider races |
| MSI table verification and reproducible build support | Package structure and a way to compare rebuilt executables | Actual install/upgrade/uninstall behavior, publisher authenticity, or a trustworthy toolchain |

Earlier reviews found ZIP-export bounds errors, excessive pre-authentication
KDF costs, JSON forward-progress failures, attachment conversion/arithmetic
problems, repeated-free teardown errors, failed-edit state loss, preview-cleanup
tracking gaps, and long-path restoration errors. Their regression map is in
[Assurance](ASSURANCE.md#historical-regression-context). That history demonstrates
that the checks have found real defects, and that subtle failure paths need
continued review. It is not a basis for calling the remaining code clean or
assigning affected/fixed release ranges without further evidence.

For reproduction, read the [full-gate safety warning](DEVELOPMENT.md#full-test-gate-read-before-running)
before running `tests\run_all.cmd`: it stops running Vordr processes and replaces
build outputs. Record commit, toolchain, logs, exit status, and **every skipped
stage**. Missing dependencies and `--quick` can skip checks; the success banner
does not mean all stages executed. This assessment does not attach an undated
PASS label to a revision whose complete gate was not run for this review.

## Decisions required before relying on Vordr

A reviewer should record these decisions with an owner and review date rather
than treating documentation as automatic acceptance:

1. **Assurance threshold:** decide whether the sensitivity warrants independent
   cryptographic/composition review, sustained parser fuzzing, and endpoint
   lifecycle testing before deployment. These are gaps to close, not completed work.
2. **Endpoint and unlock model:** decide whether same-user compromise is tolerable
   and whether an alternative TPM route is acceptable. If a strict private-desktop
   or second-factor guarantee is required, current fallback behavior does not meet it.
3. **Copy and retention policy:** account for clipboard recipients, downloads,
   viewers, ZIP exchange, history, TOTP co-location, old backups, and local TPM
   material. Verify the chosen controls without assuming they revoke existing copies.
4. **Recovery and freshness:** demonstrate restoration with the master password
   on another suitable machine; test storage conflicts and decide whether local-only
   rollback detection meets the deployment's integrity requirements.
5. **Release and response:** verify the exact binary, repeat policy through an
   actual upgrade, assign update ownership, and have a migration plan if maintenance
   or a required fix is unavailable.

Revisit this assessment when cryptography, nonce/key ownership, parsing, secret
lifetimes, TPM access, policy fallbacks, persistence, or release procedures change.
New evidence should strengthen or weaken the assessment explicitly; it should
not be replaced with broader claims of safety merely because tests pass.
