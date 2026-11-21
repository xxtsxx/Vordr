#!/usr/bin/env python3
"""pe_normalise - zero the build timestamps in a PE image.

A release build claims to be reproducible: same commit, same bytes, and a
published SHA-256 anyone can check (docs/RELEASES.md).  It was not.  Two
`build.cmd release strict` runs of one unchanged Vordr tree produced different
hashes.  (Ported from Myrkr, which found and measured the cause: there, two
builds 36 minutes apart differed in 73 bytes of 301,056.)

Every differing byte was a timestamp:

  * the COFF header's TimeDateStamp, and
  * the TimeDateStamp in each IMAGE_DEBUG_DIRECTORY entry (28 bytes apiece,
    which is what made the diff show up on a 28-byte stride).

`/Brepro` is supposed to prevent exactly this by replacing timestamps with a
hash of the linker's inputs.  It does - but ml64 stamps each .obj it writes,
build.cmd reassembles every source on every run, so the inputs it hashes are
themselves different each time.  The determinism has to be restored after the
link, not asked for during it.

Zeroing is safe: Windows does not validate either field, and neither is load-
bearing for a binary that is not signed or served from a symbol server.  What
is lost is "when was this built", which is what the version resource and the
commit are for.

Idempotent, so running it twice is not an error - and re-running it on a
shipped binary is how you check one.

Usage: python tools\\pe_normalise.py <image> [<image> ...]
Exit code: 0 if every image was normalised, 1 on any parse failure.
"""
import struct
import sys


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _save(path, b, changed):
    """Write back only if something moved, and report how much."""
    if changed:
        with open(path, "wb") as f:
            f.write(b)
    return changed


def normalise(path):
    """Zero the build timestamps in `path`.  Returns how many were non-zero."""
    with open(path, "rb") as f:
        b = bytearray(f.read())

    if b[:2] != b"MZ":
        raise ValueError("not a PE image (no MZ)")
    pe = _u32(b, 0x3C)
    if b[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image (no PE signature at e_lfanew)")

    changed = 0

    # --- COFF header Machine & TimeDateStamp --------------------------------
    machine = _u16(b, pe + 4)
    if machine not in (0x8664, 0xAA64):
        raise ValueError("unsupported PE machine 0x%04X (expected AMD64 0x8664 or ARM64 0xAA64)" % machine)
    if _u32(b, pe + 8) != 0:
        struct.pack_into("<I", b, pe + 8, 0)
        changed += 1

    # --- the debug directory, reached through the data directories ---------
    nsections = _u16(b, pe + 6)
    optsize = _u16(b, pe + 20)
    coff_chars = _u16(b, pe + 22)
    opt = pe + 24
    magic = _u16(b, opt)
    if magic != 0x20B:            # A3-30: require PE32+ only (never accept PE32)
        raise ValueError("unsupported optional header magic 0x%X (expected PE32+ 0x20B)" % magic)
    ddir = opt + 112
    nddir = _u32(b, ddir - 4)
    sect = opt + optsize

    # --- PE hardening invariants (AUD-08 / AUD-23 / A3-18 / A3-30) ----------
    if coff_chars & 0x0001:       # IMAGE_FILE_RELOCS_STRIPPED
        raise ValueError("PE COFF Characteristics has IMAGE_FILE_RELOCS_STRIPPED (breaks ASLR)")
    dll_chars = _u16(b, opt + 70)
    if (dll_chars & 0x0160) != 0x0160:
        raise ValueError("PE DllCharacteristics 0x%04X missing HIGH_ENTROPY_VA|DYNAMIC_BASE|NX_COMPAT (0x0160)"
                         % dll_chars)
    roinit_found = False
    sec_list = []
    for i in range(nsections):
        s = sect + i * 40
        sname = bytes(b[s:s + 8]).rstrip(b"\0").decode("ascii", "replace")
        vsz, va, rawsz, raw, schars = (
            _u32(b, s + 8), _u32(b, s + 12), _u32(b, s + 16), _u32(b, s + 20), _u32(b, s + 36)
        )
        sec_list.append((sname, va, vsz, raw, rawsz, schars))
        if (schars & 0xA0000000) == 0xA0000000:
            raise ValueError("W^X violation: section %r is both writable and executable (0x%08X)"
                             % (sname, schars))
        if sname == "_ROINIT":
            if (va & 0xFFF) != 0:
                raise ValueError("_ROINIT section RVA 0x%X is not 4 KiB-aligned" % va)
            if schars & 0x20000000:
                raise ValueError("_ROINIT section must not be executable (0x%08X)" % schars)
            if (schars & 0x80000000) == 0:
                raise ValueError("_ROINIT section must be writable before iat_lockdown (0x%08X)" % schars)
            roinit_found = True
    if not roinit_found:
        raise ValueError("missing dedicated _ROINIT section for startup security globals")
    if b"VORDR_NON_RELEASE_BUILD" in b:
        raise ValueError("VORDR_NON_RELEASE_BUILD sentinel found in release PE image")

    def rva_to_sec(rva):
        for item in sec_list:
            sname, va, vsz, raw, rawsz, schars = item
            span = min(vsz, rawsz) if vsz else rawsz
            if va <= rva < va + span:
                return item, raw + (rva - va), span - (rva - va)
        return None, None, 0

    def rva_to_off(rva):
        _, off_v, _ = rva_to_sec(rva)
        return off_v

    # Verify non-empty BASERELOC (dir 5) and IAT (dir 12, read-only section)
    if nddir <= 12:
        raise ValueError("PE optional header lacks BASERELOC / IAT data directories")
    reloc_rva, reloc_sz = _u32(b, ddir + 5 * 8), _u32(b, ddir + 5 * 8 + 4)
    if reloc_rva == 0 or reloc_sz == 0:
        raise ValueError("missing or empty IMAGE_DIRECTORY_ENTRY_BASERELOC (breaks ASLR)")
    iat_rva, iat_sz = _u32(b, ddir + 12 * 8), _u32(b, ddir + 12 * 8 + 4)
    if iat_rva == 0 or iat_sz == 0:
        raise ValueError("missing or empty IMAGE_DIRECTORY_ENTRY_IAT")
    iat_sec, _, iat_rem = rva_to_sec(iat_rva)
    if iat_sec is None or iat_sz > iat_rem:
        raise ValueError("IAT directory RVA 0x%X (+0x%X) outside mapped section" % (iat_rva, iat_sz))
    if iat_sec[5] & 0x80000000:
        raise ValueError("IAT lies in writable section %r (0x%08X)" % (iat_sec[0], iat_sec[5]))

    # On ARM64 (and x64), verify non-empty EXCEPTION directory (dir 3, .pdata)
    exc_rva, exc_sz = _u32(b, ddir + 3 * 8), _u32(b, ddir + 3 * 8 + 4)
    if exc_rva == 0 or exc_sz == 0:
        raise ValueError("missing or empty IMAGE_DIRECTORY_ENTRY_EXCEPTION (.pdata)")

    # --- the EXPORT directory's own TimeDateStamp --------------------------
    if nddir > 0:
        exp_rva, exp_size = _u32(b, ddir), _u32(b, ddir + 4)
        if exp_rva and exp_size:
            eo = rva_to_off(exp_rva)
            if eo is not None and _u32(b, eo + 4) != 0:
                struct.pack_into("<I", b, eo + 4, 0)
                changed += 1

    # --- the LOAD_CONFIG directory: verify DependentLoadFlags = 0x0800 ------
    lcfg_rva, lcfg_size = _u32(b, ddir + 10 * 8), _u32(b, ddir + 10 * 8 + 4)
    if lcfg_rva == 0 or lcfg_size < 0x50:
        raise ValueError("missing or truncated LOAD_CONFIG directory (rva=0x%X, size=0x%X)"
                         % (lcfg_rva, lcfg_size))
    if (lcfg_rva & 7) != 0:
        raise ValueError("LOAD_CONFIG RVA 0x%X is not 8-byte aligned (AUD-23)" % lcfg_rva)
    lcfg_sec, lcfg_off, lcfg_rem = rva_to_sec(lcfg_rva)
    if lcfg_sec is None or lcfg_size > lcfg_rem or lcfg_off + lcfg_size > len(b):
        raise ValueError("LOAD_CONFIG RVA 0x%X (+0x%X) is outside mapped section" % (lcfg_rva, lcfg_size))
    if lcfg_sec[5] & 0x80000000:
        raise ValueError("LOAD_CONFIG lies in writable section %r (0x%08X)" % (lcfg_sec[0], lcfg_sec[5]))
    if _u32(b, lcfg_off) < 0x50:
        raise ValueError("LOAD_CONFIG.Size 0x%X does not cover DependentLoadFlags"
                         % _u32(b, lcfg_off))
    dep_flags = _u16(b, lcfg_off + 0x4E)
    if dep_flags != 0x0800:
        raise ValueError("LOAD_CONFIG.DependentLoadFlags is 0x%04X, expected 0x0800 "
                         "(LOAD_LIBRARY_SEARCH_SYSTEM32)" % dep_flags)
    if _u32(b, lcfg_off + 4) != 0:
        struct.pack_into("<I", b, lcfg_off + 4, 0)
        changed += 1

    # --- the DEBUG directory (A3-18: NEVER bypass CETCOMPAT check on x64!) ---
    EX_DLLCHARACTERISTICS = 20
    cet_ok = False
    dbg_rva = _u32(b, ddir + 6 * 8) if nddir > 6 else 0
    dbg_size = _u32(b, ddir + 6 * 8 + 4) if nddir > 6 else 0
    if dbg_rva and dbg_size:
        off = rva_to_off(dbg_rva)
        if off is None:
            raise ValueError("debug directory RVA 0x%X is in no section" % dbg_rva)
        for i in range(dbg_size // 28):
            e = off + i * 28
            if e + 28 > len(b):
                raise ValueError("debug directory runs past the end of the file")
            if _u32(b, e + 4) != 0:
                struct.pack_into("<I", b, e + 4, 0)
                changed += 1
            if _u32(b, e + 12) == EX_DLLCHARACTERISTICS:
                cet_sz, cet_rva, cet_ptr = _u32(b, e + 16), _u32(b, e + 20), _u32(b, e + 24)
                if cet_ptr and cet_sz >= 4 and cet_ptr + 4 <= len(b):
                    if cet_rva and rva_to_off(cet_rva) != cet_ptr:
                        raise ValueError("CET debug entry RVA 0x%X disagrees with PointerToRawData 0x%X"
                                         % (cet_rva, cet_ptr))
                    if (_u32(b, cet_ptr) & 0x0001) != 0:
                        cet_ok = True
                continue
            raw_sz, raw_rva, raw_ptr = _u32(b, e + 16), _u32(b, e + 20), _u32(b, e + 24)
            if raw_ptr and raw_sz:
                if raw_ptr + raw_sz > len(b):
                    raise ValueError("debug payload runs past the end of the file")
                if b[raw_ptr:raw_ptr + raw_sz] != bytearray(raw_sz):
                    b[raw_ptr:raw_ptr + raw_sz] = bytearray(raw_sz)
                    changed += 1
            if raw_sz != 0 or raw_rva != 0 or raw_ptr != 0:
                struct.pack_into("<III", b, e + 16, 0, 0, 0)
                changed += 1

    if machine == 0x8664 and not cet_ok:
        raise ValueError("missing or disabled CETCOMPAT in IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS")

    # Zero OptionalHeader.CheckSum if non-zero after normalisation edits
    if changed and _u32(b, opt + 64) != 0:
        struct.pack_into("<I", b, opt + 64, 0)

    return _save(path, b, changed)


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip())
        return 1
    rc = 0
    for path in argv[1:]:
        try:
            n = normalise(path)
            print("pe_normalise: %-24s %s" %
                  (path, "already normalised" if n == 0 else "zeroed %d timestamp(s)" % n))
        except Exception as e:                                   # noqa: BLE001
            print("pe_normalise: %s: %s" % (path, e))
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
