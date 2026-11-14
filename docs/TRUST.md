# Why Vordr Earns Trust

[Project overview](../README.md) · [Documentation](README.md) · [Architecture](ARCHITECTURE.md) · [Assurance](ASSURANCE.md) · [File format](formats.md) · [Security policy](../SECURITY.md)

Trust in a password manager cannot rest on promises—it must be earned through an architecture that eliminates entire classes of risk by construction, transparent boundaries, and automated proof anyone can reproduce offline.

---

## 1. Why the architecture was designed this way

Most password managers pull in hundreds of third-party packages, run inside browser engines or managed runtimes, and maintain persistent cloud connections. Each layer adds attack surface that no single person can audit.

Vordr takes the opposite engineering path:

| Architectural decision | Failure classes eliminated by construction | Where enforced |
|---|---|---|
| **Zero-network, offline-only binary** | Remote server breaches, credential-sync interception, silent telemetry, and compromised auto-update channels. Vordr links zero networking APIs (`ws2_32`, `winhttp`, `wininet` are absent). | Import table & [`src/`](ARCHITECTURE.md#source-map) |
| **Zero third-party libraries or runtime** | Transitive dependency supply-chain attacks, garbage-collector copies of plaintext in RAM, and JIT/runtime vulnerabilities. One native x64 executable (~26 assembly modules) links exclusively against Windows `System32` DLLs. | [`loadcfg.asm`](ARCHITECTURE.md#runtime-hardening) (`DependentLoadFlags = 0x0800`), [`pe_normalise.py`](../tools/pe_normalise.py) |
| **Single authenticated container (`.vordr`)** | Unauthenticated metadata tampering, attachment splicing, and undetected cloud-sync rollbacks. Every byte on disk—header, encrypted body, encrypted attachments, and the 64-bit monotonic save counter—is covered by cryptographic authentication before any record is parsed. | [`vault.asm`](formats.md), [`verify_vault.py`](../tests/verify_vault.py) |
| **Byte-for-byte reproducible builds** | Unverifiable release binaries. Two clean builds of the same git tag with the documented MSVC/SDK toolchain produce identical SHA-256 executables with ASLR, DEP/NX, high-entropy VA, and CET shadow-stack flags intact. | [`build.cmd`](RELEASES.md#reproduce-an-executable), [`verify_repro.ps1`](../tools/verify_repro.ps1) |

---

## 2. How secrets are protected across their lifecycle

```mermaid
flowchart LR
    subgraph Disk["1. At Rest (.vordr file)"]
        A["Argon2id KDF (512 MiB, t=3, p=1 default)"] --> B["AES-256-GCM Body + Per-Attachment Keys"]
        B --> C["Full-File BLAKE2b-256 MAC + 64-bit Counter"]
    end
    subgraph Memory["2. Unlocked in RAM (vordr.exe)"]
        D["VirtualLock Static Table & secmem Arenas"] --> E["Private-Desktop Prompt & Modal Auto-Lock"]
        E --> F["Stack / XMM Scrubbing & Immediate Lock Wipe"]
    end
    subgraph OS["3. Deliberate Plaintext Handoff"]
        G["Sequence-Checked Clipboard (Tray Auto-Clear)"]
        H["8-Extension Preview Allowlist + ACL + MOTW"]
    end
    Disk -->|"Authenticated before parse"| Memory
    Memory -->|"Only on explicit user action"| OS
```

### Cryptographic & container guarantees
- **Memory-hard key derivation**: Master passwords pass through **Argon2id** (RFC 9106; default `512 MiB` RAM, `3` passes, `1` lane; reader enforces `1..16` passes and `8 KiB..4 GiB` bounds before allocation). A 16-byte SHA-256 key-check value (`KCV`) rejects wrong passwords in constant time (`ct_memcmp`).
- **Authenticated encryption with fresh nonces**: The decrypted record body (`<= 16 MiB`) is sealed with **AES-256-GCM** using the full 80-byte header as associated data (`AAD`) and a fresh 96-bit random nonce (`BCryptGenRandom` supplemented with hardware `RDSEED` across 8-byte lanes and `1..7`-byte tails) on every save.
- **Independent attachment encryption**: Each attached file (`<= 256 MiB`, section `<= 3,840 MiB`, checked with overflow-safe 64-bit arithmetic) receives its own random 256-bit AES-GCM key and 96-bit nonce, bound via 24-byte `AAD` (`id || length`).
- **Mandatory full-file MAC & anti-rollback counter**: A domain-separated **BLAKE2b-256** trailer (`"vordr-file-mac-v1" || vault_key || image || save_counter`) authenticates the entire file before record parsing. The 64-bit save counter is mirrored monotonically under `HKCU\SOFTWARE\Vordr\Rollback` keyed by canonical NTFS handle path (`GetFinalPathNameByHandleW`), flagging older restored files regardless of path casing or junctions.
- **Hardware-bound convenience unlock (optional)**: When TPM unlock is enabled, Vordr generates a `>= 2048`-bit RSA key in the Microsoft Platform Crypto Provider and seals a 64-byte context-bound payload `key32 || SHA-256(key32 || label32)` (where `label32` hashes `"Vordr-TPM-v2" || vault_salt || LE32(TpmRequireHello)`). Because Windows `PCPKSP.dll` ignores `BCRYPT_OAEP_PADDING_INFO.pbLabel`, verifying this inner SHA-256 tag in constant time prevents cross-vault or downgraded-policy blob transplants (`tpmkat`).

### Process, desktop & OS defense-in-depth
- **Startup self-test & CPU gate**: Every launch verifies AES-NI, PCLMULQDQ, SSE4.1, and SHA-NI (plus `OSXSAVE` + `XCR0` before enabling AVX2) and runs **23 known-answer test suites** fail-closed before creating any window or opening any file.
- **Pinned secret memory & scrubbing**: `sec_regions` (`secmem.asm`) pins static secret buffers with `VirtualLock` at startup (`lktest` verifies physical working-set residency via `QueryWorkingSetEx`), while `secmem_alloc` pins dynamic plaintext arenas and wipes on free, lock, and handled fatal exceptions. AES key expansion uses hardware `aeskeygenassist` (no RAM S-box tables), and Argon2, SHA-256, SHA-1, BLAKE2b, and TOTP scrub stack frames and volatile `xmm`/`ymm` registers on return.
- **Assembly control-flow & heap hardening**: Hardware CET shadow-stack compatibility (`/CETCOMPAT`) is paired with a per-thread TLS software shadow stack (`FRAME_PROLOG`/`FRAME_EPILOG` verifying top-of-stack and ancestor integrity), stack canaries, landing-pad indirect-call guards, canary-tagged heap allocations (`tagged_alloc`/`tagged_free`), and read-only import tables after startup.
- **Safe desktop, clipboard & preview boundaries**:
  - **Private desktop**: `SecureUnlock` prompts on an isolated Windows desktop (`CreateDesktopW`); when locked by `HKLM` policy, Vordr refuses normal-desktop fallback (`secdeskkat`).
  - **Modal-safe auto-lock & tray clipboard clear**: Auto-lock dismisses open Vordr modals (`Cancel`) and immediately wipes `g_vkey` and decrypted buffers (`guitest.ps1`); clipboard auto-clear checks `GetClipboardSequenceNumber` and runs on the persistent tray window (`g_trayhwnd`) even after standalone dialogs close.
  - **Allowlisted attachment previews**: Automatic preview permits only `.txt`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.webp`, and `.pdf`, sanitized of path/ADS tricks, written inside an owner-only ACL'd temp directory, and stamped fail-closed with Mark of the Web (`ZoneId=3`). All other file types route strictly to **Save As**.
  - **Fail-closed enterprise policy**: `HKLM\SOFTWARE\Vordr` locks settings (`*locked = 1`) without falling back to `HKCU` on wrong registry types, and resolves `HKLM` `REG_EXPAND_SZ` vault paths exclusively through `SHGetFolderPathW` (`%USERPROFILE%\`, `%LOCALAPPDATA%\`, `%APPDATA%\`) rather than user-writable environment variables (`polkat`).

---

## 3. How trust is verified (run it yourself)

Every invariant above is continuously enforced by a six-stage offline verification gate (`tests\run_all.cmd`) and independent Python stdlib verifiers that share **zero code** with Vordr:

```mermaid
flowchart LR
    S1["1. Fault Injection (12 redteam cases)"] --> S2["2. Strict Build (10 static analyzers + PE check)"]
    S2 --> S3["3. Startup KATs (23 FIPS / NIST / RFC suites)"]
    S3 --> S4["4. Round-Trip & Fuzz (35+ probes + 86 GUI checks)"]
    S4 --> S5["5. Crypto Diff (58 differential + 25 std vectors)"]
    S5 --> S6["6. MSI Verifier (14 policy rows, SDDL, upgrade)"]
```

| Verification layer | What it proves | Command to reproduce |
|---|---|---|
| **Independent vault reader** | A standalone Python reader (with its own RFC 9106 Argon2id and pure-Python AES-256-GCM, written solely from [`docs/formats.md`](formats.md)) decrypts real `.vordr` vaults, rejects byte flips across every file region, and confirms fresh nonces per save. | `python tests\verify_vault.py bin\vordr.exe` |
| **Differential & standard crypto vectors** | Cross-checks 58 primitive outputs against Python `hashlib`/`hmac`/AES-GCM and 25 published FIPS 180-4, FIPS 197, SP 800-38A/D, RFC 2202, RFC 4226, RFC 6238, RFC 7693, and RFC 9106 vectors (including multi-segment 64 MiB Argon2id). | `python tests\verify_crypto.py --exe bin\vordr.exe` |
| **10 static source/ABI/PE analyzers** | Verifies Win64 stack frames and raw OS callbacks (`framecheck`), callee-saved GP/XMM registers (`nvcheck`), control IDs (`idcheck`, `dlgtarget`, `rccheck`), cross-module constants (`constcheck`), string bounds (`wstrcheck`), wide alignment (`aligncheck`), dead symbols (`deadcode`), docs (`check_docs`), and `System32` PE load flags (`pe_normalise`)—all guarded against silent coverage drops by [`floors.py`](../tools/floors.py). | `build.cmd release strict` |
| **Fault injection & crash containment** | Deliberately triggers stack canary, TLS shadow-stack, landing-pad, heap-tag, bounds, overflow, crash-reentrancy, `System32` DLL load, and read-only IAT faults, asserting each exact fail-fast exit code (`0xFADExxxx`). | `python tests\redteam.py bin\vordr.exe` *(on a `dbg` build)* |
| **Isolated GUI & parser fuzzing** | Exercises `vfuzz`, `fuzzzip`, `jfuzz`, `attfuzz`, attachment/overflow/policy/TPM/private-desktop KATs, `v0.2.3` backward compatibility (`compattest.py`), and 86 live Win32 checks in an `HKCU`-isolated process (`guitest.ps1`). | `tests\run_all.cmd` *(in a test checkout/VM)* |
| **Byte-for-byte reproducibility** | Builds `release strict` twice from clean state and verifies identical SHA-256 hashes and PE mitigation flags. | `powershell -NoProfile -ExecutionPolicy Bypass -File tools\verify_repro.ps1` |

---

## 4. Honest boundaries (what no offline user-mode app can claim)

Credible security engineering states its boundaries as clearly as its protections:

- **No external third-party audit recorded**: All verification tools in this repository are open and reproducible, but they do not substitute for an independent external audit or formal proof over all inputs.
- **Master password strength**: Argon2id makes each password guess expensive (`512 MiB` RAM by default), yet a weak or reused master password remains vulnerable to offline guessing if a `.vordr` file is stolen.
- **Compromised OS, administrator, or hardware**: User-mode `VirtualLock`, zeroing, and private-desktop prompts cannot protect an unlocked vault against a malicious kernel driver, same-user/admin debugger, physical DMA/cold-boot attack, or unencrypted OS hibernation (`hiberfil.sys` without BitLocker/full-disk encryption).
- **Deliberate plaintext handoff**: Copying a secret to the clipboard, revealing it on screen, or opening/downloading an attachment places plaintext into Windows or a viewer application whose own memory and disk caches Vordr cannot erase.
- **Local rollback history & TPM scope**: The `HKCU` save-counter mirror catches accidental sync rollbacks on the same PC, not an attacker who restores both the vault and registry (or opens an old copy on a fresh PC). TPM unlock is a local convenience wrapper, never a replacement for keeping your master password backed up.

For deep module internals see [Architecture](ARCHITECTURE.md), [Secret memory](SECRETS.md), and [Assurance](ASSURANCE.md). To report a vulnerability privately, follow [SECURITY.md](../SECURITY.md).
