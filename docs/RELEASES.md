# Reproducible release builds

A password manager asks for a lot of trust, so a Vordr release must be
*auditable*: anyone with the toolchain can rebuild the exact commit and get a
**byte-identical** `bin\vordr.exe`, then confirm its SHA-256 matches the
published hash. If they match, the published binary provably corresponds to the
public source — no hidden changes slipped in between source and binary.

## Building a release

```
build.cmd release
```

This adds two linker flags on top of the normal security/mitigation flags:

| flag | why it is needed for reproducibility |
|------|--------------------------------------|
| `/Brepro` | Replaces every embedded timestamp (the PE header `TimeDateStamp`, the debug-directory entry, and the PDB signature GUID) with a deterministic hash of the binary content, instead of the wall-clock time of the build. |
| `/pdbaltpath:vordr.pdb` | Embeds only the bare PDB filename in the exe, never the machine's absolute build path — so two people building in different directories still get identical bytes. |

The security mitigations are orthogonal and stay on in release builds:
CET shadow stack (`/CETCOMPAT`), DEP/NX (`/nxcompat`), ASLR
(`/dynamicbase` + `/highentropyva`). `build.cmd` prints the mitigation summary
and the release SHA-256 at the end.

## Verifying a release

Two independent clean builds of the same commit must produce the same hash:

```
build.cmd release
certutil -hashfile bin\vordr.exe SHA256

rmdir /s /q obj bin        &  rem force a full rebuild
build.cmd release
certutil -hashfile bin\vordr.exe SHA256      rem must match the first hash
```

Determinism was verified this way: two clean release builds (with `obj\` wiped
between them, so the assemble + resource-compile + link pipeline is fully
re-run) yield the identical exe.

## Published hashes

Release hashes are recorded per tagged version. When a version is tagged, the
CI release job runs `build.cmd release` and records the resulting SHA-256 here:

| version | commit | SHA-256 (`bin\vordr.exe`) |
|---------|--------|---------------------------|
| _(unreleased)_ | — | — |

To check a downloaded binary, hash it and compare against the row for its
version. A mismatch means the binary does **not** correspond to this source at
that commit — do not trust it.
