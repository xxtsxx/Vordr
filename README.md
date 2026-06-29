# Vordr — hardened password manager (MASM64)

> Old Norse *vörðr*, "watchman / guardian."

A self-contained Windows x64 password manager built on the same trust-first
principles (and the same proven crypto + hardening core) as
[Myrkr](../Encrypt): **AES-256-GCM** with an **Argon2id** KDF, a **CSPRNG
seeded from RDSEED**, hardware-accelerated throughout (AES-NI, PCLMULQDQ,
SHA-NI, AVX2 BLAMKA), with **no CRT / no .NET / no external dependencies**
beyond OS-inbox DLLs (`kernel32`, `bcrypt`, `user32`). Every cryptographic
primitive is validated against an official RFC/NIST vector on **every launch**,
and the program **fails closed** on any violation.

> **Status: early (v0.1).** Working today: the vault (`init`/`add`/`list`/`get`,
> single-file, atomic writes), the `gen` password generator, and **one-time-pad
> sharing** end-to-end (`padnew`/`padimport`/`share`/`open` with Poly1305
> one-time MAC and never-reuse offset tracking), plus the per-launch self-test
> gate (13 known-answer tests). Still stubbed: `edit`, `remove`, `bench`. See
> [docs/formats.md](docs/formats.md) for the on-disk formats and security model.

## Design goals

- **Trust is fundamental** — market-leading primitives only; nothing home-rolled
  in the crypto core (it is copied verbatim from Myrkr).
- **AES-256-GCM** for the vault, **Argon2id** (t=3, m=512 MiB, p=1) for key
  derivation.
- **CPU primitives** (AES-NI/PCLMULQDQ/SHA-NI) and a **CSPRNG mixed with
  RDSEED**; fails closed if the OS RNG fails.
- **Self-test on every run** (FIPS 180-4, NIST SP 800-38D, RFC 7693, RFC 9106).
- **Quantum-hardened by construction.** At rest, AES-256 keeps ~128-bit
  strength under Grover and memory-hard Argon2id is unaffected by Shor. For
  **sharing**, Vordr uses a **one-time pad** (information-theoretic
  confidentiality) plus a **one-time MAC** (information-theoretic integrity) —
  there is no classical public-key crypto anywhere, so there is nothing for
  Shor to break.
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

`vordr.exe` is one executable that runs as a **CLI** when the first argument is
a known verb (or begins with `-`), and otherwise opens the **GUI**.

```
  vault:   vordr init | add | get | list | edit | remove
  pwgen:   vordr gen
  share:   vordr padnew | padimport | share | open
  diag:    vordr selftest | bench
```

Every launch runs the self-test gate first and aborts (`EXIT_SELFTEST`) if any
known-answer test mismatches.

## Module map (this scaffold)

| Source | Role |
|---|---|
| `macros.inc`, `hardening.asm`, `loadcfg.asm` | Hardening macros + runtime (copied from Myrkr) |
| `random.asm`, `sha256.asm`, `aesgcm.asm`, `blake2b.asm`, `argon2.asm` | Crypto core (copied verbatim) |
| `fileio.asm`, `console.asm`, `log.asm` | I/O, console, audit log (copied) |
| `secmem.asm` | **New** — VirtualLock'd secret memory |
| `vault.asm` | **New** — single-file vault lifecycle (stubs) |
| `pwgen.asm` | **New** — password generator + policy (live) |
| `otp.asm` | **New** — one-time-pad sharing; `otp_xor` live, rest stubbed |
| `selftest.asm` | KAT driver, with a verbose flag for the per-run gate |
| `main.asm`, `gui.asm` | CLI dispatch + hybrid entry (`wstart`) and About shell |

## License

See [LICENSE.txt](LICENSE.txt).
