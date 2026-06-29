# Vordr — hardened password manager (MASM64)

> Old Norse *vörðr*, "watchman / guardian."

A self-contained Windows x64 password manager written entirely in 64-bit
assembly, built around one principle: **trust is the product.** It uses only
market-leading, standards-defined cryptography — **AES-256-GCM** for the vault
and an **Argon2id** KDF, over a **CSPRNG seeded from RDSEED** — and is
hardware-accelerated throughout (AES-NI, PCLMULQDQ, SHA-NI, AVX2). There is
**no C runtime, no .NET, and no third-party code**: the only dependencies are
the OS-inbox DLLs `kernel32`, `bcrypt`, and `user32`. Every cryptographic
primitive is validated against an official RFC/NIST test vector on **every
launch**, and the program **fails closed** on any violation.

> **Status: v0.1 — GUI-first; CLI is diagnostics only.** By design, **no master
> password or secret is ever passed on the command line** (where it would leak
> into shell history and process listings) — the vault and the password
> generator are reached only through the GUI. The vault crypto and operations
> (create / add / list / get / edit / remove, single-file, atomic writes), the
> generator, and the per-launch self-test gate (10 known-answer tests) are all
> implemented and self-tested; the command line exposes only `selftest` and
> `bench`. **Caveat:** the GUI vault front-end is still in progress (today the
> window is an About box), so there is not yet an interactive way to drive the
> vault. No external review; single-process file locking only.

## Design goals

- **Trust is fundamental** — only market-leading primitives, nothing
  home-rolled in the crypto core, and every primitive self-tested at runtime.
- **AES-256-GCM** for the vault, **Argon2id** (t=3, m=512 MiB, p=1) for key
  derivation.
- **CPU primitives** (AES-NI / PCLMULQDQ / SHA-NI) and a **CSPRNG mixed with
  RDSEED**; fails closed if the OS RNG fails.
- **Self-test on every run** (FIPS 180-4, NIST SP 800-38D, RFC 7693, RFC 9106).
- **Quantum-hardened by construction.** At rest, AES-256 keeps ~128-bit
  strength under Grover and memory-hard Argon2id is unaffected by Shor. There is
  no public-key crypto anywhere, so nothing is exposed to Shor's algorithm.
- **Hostile-OS resistance** — decrypted secrets live in **VirtualLock**ed memory
  (no pagefile leak), imports are locked read-only (RELRO-equivalent), W^X,
  ASLR/DEP/NX, CET + software shadow stack, stack canaries, DLPV, tagged heap,
  and `secure_zero` of all key material. (Best-effort in user mode — see the
  threat-model notes in [docs/formats.md](docs/formats.md).)

## Build

From an **x64 Native Tools Command Prompt for VS** (so `ml64`/`link`/`rc` are on
PATH):

```
build
```

Produces a single `bin\vordr.exe` (CLI + GUI hybrid). Variants: `build nohw`
(software mitigations only, no `/CETCOMPAT`), `build dbg` (startup breadcrumbs,
per-primitive debug, and the `redteam` fault-injection self-test). The Windows
SDK lib path is set near the top of `build.cmd`.

## Usage

`vordr.exe` opens the **GUI** when launched with no arguments. The vault and the
password generator are reached **only** through that window — so that a master
password or a secret is never placed in `argv`, where it would persist in shell
history and be visible to any process that can read the process list.

The **command line is deliberately limited to non-sensitive diagnostics**:

```
  vordr selftest             run all known-answer self-tests
  vordr bench [-m MIB] [-t N] benchmark the crypto core
```

It accepts no vault path, no master password, and no secret. Every launch (GUI
or CLI) runs the self-test gate first and aborts (`EXIT_SELFTEST`) if any
known-answer test mismatches.

## Module map

| Source | Role |
|---|---|
| `macros.inc` | Shared constants, structs, and the hardening / readability macros |
| `hardening.asm`, `loadcfg.asm` | Runtime hardening: canary, shadow stack, tagged heap, IAT lockdown, load-config |
| `random.asm` | CSPRNG (`BCryptGenRandom` ⊕ RDSEED), fails closed |
| `sha256.asm`, `aesgcm.asm`, `blake2b.asm`, `argon2.asm` | Crypto core (SHA-256, AES-256-GCM, BLAKE2b, Argon2id) |
| `fileio.asm`, `console.asm`, `log.asm` | File I/O, console output, audit log |
| `secmem.asm` | VirtualLock'd secret memory |
| `vault.asm` | Single-file vault lifecycle + commands (init/add/list/get/edit/remove) |
| `pwgen.asm` | Password generator + policy |
| `bench.asm` | Crypto-core micro-benchmark |
| `selftest.asm` | Known-answer-test driver (the per-launch gate) |
| `main.asm`, `gui.asm` | CLI tokenizer/dispatch + hybrid entry (`wstart`) and window shell |

## License

See [LICENSE.txt](LICENSE.txt).
