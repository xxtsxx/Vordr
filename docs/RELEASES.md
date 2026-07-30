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

Release hashes are recorded per tagged version. There is no automated release
job yet: at tag time `build.cmd release` is run twice from a clean tree, the two
hashes are compared, and the result is recorded here by hand.

| version | commit | SHA-256 (`bin\vordr.exe`) |
|---------|--------|---------------------------|
| v0.2.0 | `48cc1df` | `811b5cd6f56845daf747bc8e4d18f89f35a7bb815463611a1f090009a8279faa` |
| v0.2.1 | `1ba8413` | `01baa66ff49e1869dc6b68b4c4528c5cb534282b54f98745222e0f628898e664` |

The row records the hash of a build of the **tagged** commit. This file is
updated immediately after tagging, so the commit that adds a row is not itself
the commit that row describes — check out the tag, not `master`, when
reproducing a hash:

```
git checkout v0.2.0
build.cmd release
certutil -hashfile bin\vordr.exe SHA256
```

> **v0.2.0 is superseded and should not be used.** It creates the vault beside the
> executable on any machine with a linked OneDrive, can strand the user on the
> secure desktop at first unlock, and reads past the import selection mask on a
> vault with more than 8192 entries. Use v0.2.1.

To check a downloaded binary, hash it and compare against the row for its
version. A mismatch means the binary does **not** correspond to this source at
that commit — do not trust it.
