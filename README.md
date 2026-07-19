# Vordr — hardened password manager (MASM64)

> Old Norse *vörðr*, "watchman / guardian."

## What Vordr is

Vordr is a self-contained password manager for Windows x64, written entirely in
64-bit assembly. It keeps all of your secrets — passwords, TOTP keys, notes,
custom fields, and file attachments — in **one encrypted file** (`.vordr`),
sealed with **AES-256-GCM** under a key derived from your master password with
**Argon2id** (512 MiB memory-hard). It is a single small executable with **no
installer, no C runtime, no .NET, and no third-party code**; the only
dependencies are DLLs that ship inside Windows itself.

Vordr is built around one principle: **trust is the product**. Every design
decision below follows from that — including the honest description of what it
*cannot* do.

## What Vordr can't protect against

A password manager's guarantees are only meaningful when its limits are stated
plainly:

- **A fully compromised operating system.** If an attacker runs code in your
  kernel, or as administrator while the vault is unlocked, they can ultimately
  read anything you can. Vordr's hardening (below) raises the cost — secrets
  never touch the pagefile, are wiped after use, and the unlock prompt can run
  on an isolated desktop — but user-mode software cannot defeat a hostile
  kernel. We state this rather than overclaim.
- **Hardware attackers.** DMA devices, firmware implants, and cold-boot attacks
  are out of scope.
- **You, while the vault is open.** A revealed secret is on your screen; a
  copied secret is in the clipboard until cleared; a previewed attachment is
  handed in plaintext to another program. Vordr minimizes each window (auto-
  clear, clipboard-history exclusion, temp-file wiping, an option to disable
  previews entirely) but cannot remove them.
- **Rollback of the whole file.** Any tampering *inside* the file breaks
  authentication, and an attacker who replaces the vault with an older, intact
  copy is flagged too: every save bumps a counter whose last-seen value is
  mirrored on this machine (HKCU), so an out-of-date vault triggers a loud
  warning at unlock. The mirror is per-machine — a vault restored onto a fresh
  machine has nothing to compare against, and an attacker who rolls back both
  the file *and* the registry mirror stays invisible (see *Risk assessment*).

### Importance of a strong master password

Every guarantee reduces to the master password. Argon2id with 512 MiB of
memory per guess makes offline guessing expensive — each attempt costs real
time and its own 512 MiB, which is painful to parallelize on GPU rigs — but no
KDF can save a guessable password. Passphrases of five or more random words,
or 16+ random characters, put brute force out of reach; a pet's name does not.
Vordr's generator (five styles, with a live entropy estimate) exists so you
never have to invent one yourself.

### No recovery for the master password

**There is no recovery mechanism, by design.** No recovery questions, no escrow,
no vendor backdoor — anything that could recover your vault without the
password would be an attack surface that defeats the point. If you forget the
master password, the vault contents are cryptographically gone. Write the
password down and store it somewhere physically secure, or accept the risk.
(See also *TPM unlock and the risk of forgetting the master password* below —
convenience unlocks make it easier to forget the password you rarely type.)

## Trust

Why should you trust a password manager written by strangers? You shouldn't —
you should be able to **verify** it:

- **Every line is here.** The entire program is hand-written assembly in this
  repository. There is no compiler output to trust, no vendored library, no
  package manager, no build step that downloads anything.
- **Nothing is home-rolled in the crypto core.** Every primitive is a published,
  standardized algorithm (see *Cryptographic design*), implemented against its
  specification and validated against the official test vectors **on every
  launch** — Vordr refuses to run if any known-answer test fails.
- **No network code exists.** Not disabled — absent. There is no socket, no
  HTTP, no telemetry, no update check anywhere in the binary. Your secrets
  cannot phone home because there is nothing to phone with.
- **The threat model is stated honestly**, including the gaps (no external
  audit yet, single-writer file assumption).
- **The hardening is proven, not asserted.** A fault-injection test suite
  (`redteam`) deliberately triggers each exploit-mitigation control and fails
  the build if any of them does not fire.

The one thing we cannot give you yet is an **independent external security
review** — none has been performed. Until one is, treat Vordr as what it is:
a carefully built, fully inspectable implementation that has not had hostile
professional eyes on it.

## Design philosophy

### Runtime dependencies

The import table is the whole dependency list — OS-inbox DLLs only:
`kernel32`, `user32`, `gdi32`, `advapi32`, `shell32`, `comctl32`, `comdlg32`,
`uxtheme`, `dwmapi`, `dxgi`, `msimg32`, `wtsapi32`, `bcrypt` (OS CSPRNG), and
`ncrypt` (TPM provider, only used if you enable TPM unlock). There is no C
runtime and no static library. What Windows ships is what Vordr uses.

### Proven crypto primitives

Nothing novel guards your secrets. AES-256-GCM (NIST SP 800-38D), Argon2id
(RFC 9106), SHA-256 (FIPS 180-4), BLAKE2b (RFC 7693), HMAC (RFC 2104/2202) —
each implemented from its specification and checked against the published
vectors at startup, every time. Hardware instructions (AES-NI, PCLMULQDQ,
SHA-NI, AVX2) are used where the CPU has them; a CPU without the required
features is refused rather than served a software fallback of untested
constant-timeness.

### Defense in depth

No single mechanism is trusted to hold. The vault format authenticates its
header; the KDF is memory-hard; decrypted secrets live in non-pageable memory;
buffers are wiped after use; the process hardens itself against exploitation
(see *Hardening*); and the GUI minimizes exposure windows (clipboard auto-clear,
auto-lock, secure desktop entry). An attacker must defeat several independent
layers, not one.

### Fail closed

Every failure path denies rather than degrades: a failed self-test aborts the
program; a failed RNG aborts the operation (never a weak fallback); a wrong
password or a tampered file refuses to load (never a partial parse); a
corrupted heap block or smashed stack canary terminates the process
immediately via fail-fast, with the secrets wiped.

### Verifiable implementation

Assembly removes the trust gap between source and binary: what you read is
what executes, instruction for instruction. There is no undefined behavior, no
optimizer re-arranging your constant-time compare, no CRT startup code you
didn't write. Static tooling (`tools/framecheck.py`) mechanically scans every
procedure for the one systematic mistake hand-written Win64 code invites
(stack-argument spills past the frame), and the strict build gates on it.

### No communication

Vordr never opens a network connection, reads no URLs, checks for no updates,
and sends no telemetry. The only "sync" is whatever your file system does with
the encrypted vault file itself (see *OneDrive storage*), which by design only
ever sees ciphertext.

## Cryptographic design

### Crypto primitives and algorithms

| Purpose | Algorithm | Reference |
|---|---|---|
| Vault sealing (AEAD) | AES-256-GCM (AES-NI + PCLMULQDQ GHASH) | NIST SP 800-38D |
| Key derivation | Argon2id, t=3, m=512 MiB, p=1 | RFC 9106 |
| Argon2 core hash | BLAKE2b (scalar 64-bit; AVX2 is used only inside Argon2's compressor) | RFC 7693 |
| Key-check value / hashing | SHA-256 (SHA-NI) | FIPS 180-4 |
| TOTP codes | HOTP/TOTP over HMAC-SHA-1, base32 keys | RFC 4226 / 6238 / 4648 |
| `.vaultz` export/import | WinZip AE-2: PBKDF2-HMAC-SHA1, AES-256-CTR, HMAC-SHA1 | interop standard |
| Constant-time compare | `ct_memcmp` (OR-accumulate, branch-free) | — |

Two honest notes on that table. SHA-1 appears **only** where interop standards
demand it (TOTP per RFC 6238, and the WinZip AE-2 archive format) — never for
vault integrity, which is GCM's job. And the export format is deliberately
weaker than the vault (PBKDF2 at 1000 iterations vs Argon2id): that is the
price of producing archives that 7-Zip and Windows can open. Give exports a
strong password and treat them as live secrets.

All secret-dependent comparisons (GCM tag, key-check value, TPM check value,
import verifiers, password-confirm fields) are constant-time; the audit of
every memory-compare in the codebase is in [docs/SECRETS.md](docs/SECRETS.md),
and a debug-build probe (`cttest`) measures that compare time is independent of
where the difference lies.

### Key derivation

```
key = Argon2id(UTF-8 master password, 32-byte CSPRNG salt, t=3, m=512 MiB, p=1)
KCV = SHA-256(key)[0..15]
```

The parameters are stored in the (authenticated) vault header, so they can be
raised in future versions without breaking old files. 512 MiB per guess is the
core defense against GPU/ASIC cracking rigs: memory is the one resource that
does not parallelize cheaply. The KCV lets a wrong password be rejected
immediately after the KDF and makes the construction key-committing; it reveals
nothing useful about the key (16 bytes of SHA-256 output are no easier to
invert than the password is to guess).

### Randomness

Every salt, nonce, entry id, attachment key, and generated password comes from
`rng_fill`: the OS CSPRNG (`BCryptGenRandom`) **XORed with `RDSEED`** hardware
entropy. Either source alone would be adequate; XORing them means both would
have to fail simultaneously and identically to weaken the output. If the OS
RNG reports failure, the operation aborts — there is no fallback to time-based
or predictable entropy, ever.

## Hardening

The process assumes it will be attacked and arranges to die loudly rather than
be exploited quietly:

- **CET shadow stack** (`/CETCOMPAT`) on supporting CPUs, **plus** a software
  shadow stack that validates every return address independently.
- **Stack canaries** on every frame, from a per-boot random value.
- **DLPV** (indirect-call landing-pad validation): every indirect call target
  must carry a magic prologue marker, or the process fail-fasts.
- **Tagged heap**: every allocation carries a random temporal tag and front/rear
  canaries; frees poison the block; stale or forged pointers are caught on use.
- **Bounds checks** on every length field parsed from disk (`BOUND_CHECK`),
  with hard caps per field/entry/file.
- **IAT lockdown**: after startup the import table is made read-only
  (full-RELRO equivalent), blocking import-address patching.
- **W^X, ASLR (high-entropy), DEP/NX** — verified in the build by a dumpbin
  mitigation check.
- **VirtualLock'd secret memory**: every buffer that ever holds the master
  password, the derived key, or a plaintext secret is pinned (never paged to
  disk) and `secure_zero`'d after use — audited buffer-by-buffer in
  [docs/SECRETS.md](docs/SECRETS.md), and proven by a scanner (`secscan`) that
  plants a sentinel, wipes, and sweeps all process memory for residue.
- **Deterministic temp-file destruction**: attachments previewed via an
  external app are tracked, overwritten with zeros, flushed, and deleted on
  every lock (proven by `tmptest`) — or never written at all (see *Attachment
  preview*).

None of this is taken on faith: the `redteam` suite injects each fault class —
canary smash, shadow-stack mismatch, DLPV bypass, buffer overflow, bounds
violation, type confusion, heap-tag forgery, IAT patch — and requires the
corresponding control to kill the process with the expected fail-fast code.

## Features and functionality

Entries are composable: username, secret, URL, notes, TOTP key, and any number
of custom-labeled fields, plus encrypted file attachments shown as a tag list.
Secrets get strength badges, color-coded reveal, a phonetic read-out popup, and
a generator (random / passphrase / pronounceable / PIN / hex) with a live
entropy estimate. The UI has nine color schemes, search-as-you-type,
favorites, per-entry icons, and a tray icon; it locks to the tray.

### Password policy

Minimum length (default **12**) and minimum character classes (default **3**
of lower/upper/digit/symbol) are enforced when creating or changing the master
password and surfaced in the generator. Registry values `PwMinLen`,
`PwMinClasses`.

### TPM unlock

Optional fast unlock (default **on** when a TPM is present; `TpmUnlock`): the
vault key is wrapped to an RSA-2048-OAEP key that lives inside this machine's
TPM (Microsoft Platform Crypto Provider), and the wrapped blob is stored in
the registry under `HKCU\SOFTWARE\Vordr\TPM-Unlock` (one value per vault,
named by the vault's path). The blob is useless on any other machine — the
private key never leaves the TPM. This is strictly **OR-mode convenience**:
the master password always works everywhere, and deleting the TPM key or the
registry value only costs the shortcut. See *Risk assessment* for the
trade-offs.

### Secure unlock

With Secure Unlock (default **on**; `SecureUnlock`), the master password is
typed on a **private, isolated Windows desktop** — the same mechanism UAC
prompts use. Keyloggers and screen scrapers running in your normal session
cannot observe that desktop. If a private desktop cannot be created, Vordr
falls back to a normal prompt rather than failing to unlock.

### Attachment preview

Opening an attachment in its default app requires writing its plaintext to a
temp file (that is how the ShellExecute hand-off works). Vordr tracks every
such file and overwrites-then-deletes it on lock. If you prefer that the
plaintext **never** leaves the vault unrequested, enable **"Disable attachment
preview"** (`NoPreview`, default off): attachments then become download-only —
you explicitly choose where the plaintext copy goes, exactly as executable
attachments are always handled (they are never auto-opened, regardless of this
setting).

### History

Overwriting any field value archives the old value with a timestamp inside the
vault (encrypted like everything else). A History browser shows the archive per
field, with per-row purge. **"Do not save history"** (`NoHistory`, default off)
disables the capture entirely for the privacy-conscious.

### Timeouts

- **Clipboard clear** (`ClipSeconds`, default **20 s**, 0 = off, max 3600):
  a copied secret is cleared after the timeout — but only if the clipboard
  still holds *our* copy (sequence-number check), so your later copies survive.
  Every copy is also flagged with the Windows exclusion formats so it never
  enters clipboard history (Win+V), the cloud clipboard, or clipboard-monitor
  processing.
- **Auto-lock on idle** (`IdleLockMin`, default **10 min**, 0 = off, max 24 h):
  the vault locks itself after system-wide inactivity.
- **Lock with Windows** (`LockOnWinLock`, default **on**): pressing Win+L (or
  any session lock) locks the vault immediately.

Locking always wipes the decrypted vault, revealed secrets, and TOTP material,
clears the clipboard if it is still ours, and destroys tracked temp files.

### Import and export

Export produces a **`.vaultz`** file: a standard WinZip AES-256 (AE-2) archive
containing `vordr.json` plus the attachments, openable with 7-Zip or any
AES-zip tool — your guaranteed exit path from Vordr, with no proprietary
lock-in. Export is selective (pick which entries), always under a password
that must satisfy the vault's policy. Import stages a `.vaultz`, lets you pick
entries, and appends them (never overwrites). Password history is deliberately
not exported.

### OneDrive storage

On first run Vordr proposes `%OneDrive%\Vordr\vault.vordr` as the default
location, but only when OneDrive is actually in use — a linked sync account
with a matching `UserFolder` exists. The `%OneDrive%` variable alone is not
enough: on a machine where the sync client was never linked, Vordr falls back
to `Documents\Vordr\vault.vordr` rather than wake the dormant client. The
unlock dialog shows where the vault lives. This is a deliberate availability
trade-off: the synced file gives you an off-machine backup for free, and the
provider only ever sees ciphertext — confidentiality and integrity are
enforced by the format, not the transport. What a sync provider *could* do is
withhold updates or serve you an older version of the file (see the rollback
note under *Risk assessment*). You can keep the vault anywhere; the location
is just a path.

## Policy enforcement

### Defaults

Compiled-in defaults are chosen to be safe without configuration: policy
12 chars / 3 classes, clipboard clear 20 s, idle lock 10 min, lock-with-Windows
on, Secure Unlock on, TPM unlock on (if present), history on, previews on.

### HKLM vs HKCU

Every setting reads with the priority **HKLM > HKCU > default**
(`HKLM\SOFTWARE\Vordr` / `HKCU\SOFTWARE\Vordr`). A value set in HKLM is
**policy**: it wins over the user's preference and the corresponding Settings
control is disabled in the UI, so an administrator can mandate (for example) a
minimum password length, a short clipboard timeout, or download-only
attachments machine-wide. HKCU holds the user's own choices, written by the
Settings screen. The vault *path* follows the same rule (HKLM pins it; HKCU
remembers the last one used).

## Testing and verification

Four independent gates, all runnable with one command (`tests\run_all.cmd`)
and enforced in CI on every push:

1. **Known-answer self-tests — on every launch, not just in CI.** SHA-256
   (FIPS 180-4), AES-256-GCM seal/open/AAD/in-place (SP 800-38D), BLAKE2b
   (RFC 7693), the Argon2 compression function, Argon2id against RFC 9106 plus
   four cross-checked conformance vectors (including the single-lane
   configuration the vault actually uses), HMAC-SHA1 (RFC 2202), base32
   (RFC 4648), HOTP (RFC 4226), the password policy, generator entropy, a full
   vault seal/open round-trip, field serialization, and the constant-time
   compare primitives. Any mismatch → the program refuses to run.
2. **Red-team fault injection** (debug build): each hardening control is
   deliberately attacked and must fire.
3. **Strict static analysis**: `framecheck.py` scans every procedure's stack
   discipline; findings fail the build.
4. **Headless round-trip probes**: seed 5000 entries, export, re-import,
   verify (`seedtest`/`atgen`/`zitest`); capture password history (`phtest`);
   scan process memory for post-wipe secret residue (`secscan`); verify
   temp-file destruction (`tmptest`).

## Risk assessment

### Threat model

**Defended:**

| Threat | Defense |
|---|---|
| Vault file stolen (laptop theft, cloud breach, backup leak) | AES-256-GCM + Argon2id 512 MiB; nothing readable without the master password |
| Vault file tampered (bit flips, splicing, header edits) | Header is GCM AAD; body is one authenticated blob; attachments individually AEAD-sealed with keys stored inside the body |
| Wrong-password oracle abuse | Key-committing KCV; constant-time checks |
| Casual local malware (user-mode, non-admin) | Locked memory, wiped buffers, exploit mitigations, clipboard exclusion, secure-desktop unlock, auto-lock |
| Shoulder-surfing / screen scraping at unlock | Secure Unlock private desktop |
| Secrets in swap/hibernation | VirtualLock on every secret buffer |
| Secrets lingering after lock | `secure_zero` on every path, `secscan`-verified |

**Explicitly not defended:** kernel-level or admin-level compromise while
unlocked, DMA/firmware/hardware attackers, coercion, and a weak master
password. Whole-file rollback detection (a monotonic save counter mirrored on
this machine, warned on at unlock) and a single full-file MAC over everything
including the attachment trailer (a keyed BLAKE2b trailer, so truncation or
record-splicing fails the unlock) are both implemented — the remaining caveat
is that rollback evidence lives per-machine, not in the vault. No external
audit has been performed.

### Analysis of quantum resistance

The **vault format contains no public-key cryptography**, which is where
quantum computers actually break things (Shor's algorithm). What remains is
symmetric crypto, where the best known quantum attack (Grover) only halves
effective key strength: AES-256 degrades to ~128-bit security — still far
beyond reach — and Argon2id's memory-hardness is untouched because the cost
per guess is memory bandwidth, not key search. The vault at rest is therefore
quantum-hardened by construction, not by patching.

The one asterisk is **TPM unlock**, which wraps the vault key with RSA-2048 —
a Shor-vulnerable algorithm. Perspective matters: the wrapped blob is a local
registry value bound to one machine's TPM, not something transmitted or
published, and an attacker with a future quantum computer *and* a copy of that
registry value still learns nothing without the TPM it was wrapped to. If your
threat model includes harvest-now-decrypt-later adversaries collecting your
local data, disable TPM unlock; the vault itself remains safe either way.

### TPM unlock and the risk of forgetting the master password

TPM unlock creates a human risk precisely because it works well: if the TPM
opens your vault every day, you may not type the master password for months —
and unused passwords are forgotten. The TPM cannot save you then: a dead
motherboard, a cleared TPM, a Windows reinstall, or simply moving to a new
machine all invalidate the stored blob, and the master password becomes the
only way in. **There is no recovery** (see above). If you enable TPM unlock,
write the master password down and store it physically securely, or schedule
yourself to type it periodically. This trade-off is the reason TPM unlock is
convenience-only and never the sole factor.

## How to assemble

### Toolchain and build

Requirements: Visual Studio Build Tools (MASM `ml64.exe`, `link.exe`) and a
Windows SDK (`rc.exe`). No other tool, no package, no download. From an **x64
Native Tools Command Prompt**:

```
build            release build  ->  bin\vordr.exe
build strict     release + fail the build on any framecheck static finding
build dbg        debug build: startup breadcrumbs + redteam/tpmtest/cttest verbs
build nohw       software mitigations only (no /CETCOMPAT)
tests\run_all    the full gate: redteam + strict build + selftest + round-trip
```

The output is a single hybrid executable — GUI when launched without
arguments, diagnostics CLI otherwise (`selftest`, `bench`, and headless test
probes). **No vault path, master password, or secret is ever accepted on the
command line**, where it would leak into shell history and process listings.

### Module map

| Source | Role |
|---|---|
| `macros.inc` | Shared constants, structs, hardening + readability macros (`FRAME_PROLOG`, `WINCALL`, `BOUND_CHECK`…) |
| `main.asm` | Hybrid entry point, CLI dispatch (guarded indirect calls), self-test gate |
| `hardening.asm`, `loadcfg.asm` | Canary, software shadow stack, tagged heap, `ct_memcmp`, IAT lockdown, load-config |
| `random.asm` | CSPRNG (`BCryptGenRandom` ⊕ `RDSEED`), fails closed |
| `sha256.asm`, `sha1.asm`, `aesgcm.asm`, `blake2b.asm`, `argon2.asm` | Crypto core |
| `secmem.asm` | VirtualLock'd secret memory + `secscan` residue probe |
| `vault.asm` | Vault format: seal/open, entry/field serialization, attachments |
| `totp.asm` | base32 + HOTP/TOTP |
| `tpm.asm` | Optional TPM-wrapped fast unlock (ncrypt) |
| `regcfg.asm` | Registry settings (HKLM > HKCU > default), vault path, OneDrive detection |
| `pwgen.asm` | Password generator (5 styles) + policy checks |
| `zipexport.asm`, `zipimport.asm` | `.vaultz` (WinZip AE-2) export / staged import |
| `gui.asm` | All windows: unlock/create, vault, settings, generator, history (owner-drawn) |
| `theme.asm` | Color schemes, owner-draw painters, DWM dark title bar |
| `fileio.asm`, `console.asm`, `log.asm` | Atomic file I/O, console, audit log |
| `selftest.asm`, `redteam.asm`, `bench.asm` | KAT driver, fault injection, benchmarks |

### File format

Full specification in [docs/formats.md](docs/formats.md). In brief — `.vordr`
(magic `VRDR`, v1):

```
VAULT_HDR (64 B, used verbatim as the GCM AAD):
    magic, version, t_cost, m_cost_kib, lanes,
    salt[32]  (CSPRNG),  nonce[12]  (CSPRNG, fresh per write)
KCV[16]  = SHA-256(key)[0..15]
body     = AES-256-GCM(entry stream)      ; tag[16] appended
[VATT trailer: per-attachment AES-256-GCM blobs; their keys live inside body]
```

The body is a length-prefixed TLV record stream — no JSON/XML parser in the
trust path, every length bounds-checked. Because the header is the AAD,
changing even the KDF parameters breaks authentication. Writes go to a temp
file and are atomically renamed over the vault, so a crash mid-save can never
destroy the previous good state.

## Why 64-bit assembler

Because the trust argument requires it. In any higher-level language you trust
the compiler (and its optimizer's right to remove your "dead" security-
critical stores), the runtime library, and the package ecosystem. Vordr's
audit surface is exactly the ~30k lines in `src/` — what you read is
byte-for-byte what executes:

- **No compiler-injected code**, no CRT startup, no hidden allocations, no
  optimizer silently un-doing a `secure_zero` or short-circuiting a
  constant-time loop.
- **Direct control of security-relevant machinery**: CPU crypto instructions,
  memory locking, wipe ordering with fences, stack layout, and every fail-fast
  path are explicit instructions, not intrinsics you hope translate well.
- **A minimal, inspectable TCB**: one binary, a dozen OS DLLs, nothing else.

The honest costs: assembly is slower to write, unforgiving of frame-discipline
mistakes, and x64-Windows-only. Those risks are managed structurally — shared
macros for the error-prone patterns, a static frame checker gating the build,
fault-injection tests proving the hardening, and known-answer tests proving
the crypto — rather than by hoping for careful reading alone.

## License

See [LICENSE.txt](LICENSE.txt).
