"""coff.py - minimal x64 COFF object reader for the ARM64 translator.

Reads sections, symbols, relocations and the CodeView (.debug$S) records that
MASM emits with /Zi: procedure ranges (S_GPROC32/S_LPROC32) and line tables
(DEBUG_S_LINES) so translated code can be annotated with source lines.
"""
import struct

IMAGE_SCN_CNT_CODE = 0x20
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80
IMAGE_SCN_LNK_INFO = 0x200
IMAGE_SCN_LNK_REMOVE = 0x800
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

REL_AMD64 = {
    0x0000: "ABSOLUTE", 0x0001: "ADDR64", 0x0002: "ADDR32", 0x0003: "ADDR32NB",
    0x0004: "REL32", 0x0005: "REL32_1", 0x0006: "REL32_2", 0x0007: "REL32_3",
    0x0008: "REL32_4", 0x0009: "REL32_5", 0x000A: "SECTION", 0x000B: "SECREL",
}

SYM_CLASS_EXTERNAL = 2
SYM_CLASS_STATIC = 3
SYM_CLASS_LABEL = 6


class Section:
    def __init__(self, idx, name, data, chars, vsize):
        self.idx = idx            # 1-based
        self.name = name
        self.data = data
        self.chars = chars
        self.size = len(data) if data is not None else vsize
        self.relocs = []          # (offset, type_name, symbol_index)

    @property
    def is_code(self):
        return bool(self.chars & IMAGE_SCN_CNT_CODE)

    @property
    def is_bss(self):
        return bool(self.chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA)

    @property
    def align(self):
        a = (self.chars >> 20) & 0xF
        return 1 << (a - 1) if a else 16

    @property
    def writable(self):
        return bool(self.chars & IMAGE_SCN_MEM_WRITE)


class Symbol:
    def __init__(self, idx, name, value, secnum, typ, cls, naux):
        self.idx = idx
        self.name = name
        self.value = value
        self.secnum = secnum
        self.type = typ
        self.cls = cls
        self.naux = naux

    @property
    def is_function(self):
        return (self.type >> 4) == 2

    @property
    def is_external(self):
        return self.cls == SYM_CLASS_EXTERNAL

    @property
    def is_undefined(self):
        return self.cls == SYM_CLASS_EXTERNAL and self.secnum == 0

    def __repr__(self):
        return f"<Sym {self.name} sec={self.secnum} val={self.value:#x} cls={self.cls}>"


class CoffObject:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            raw = f.read()
        self.raw = raw
        machine, nsec, _ts, symptr, nsym, optsz, _ch = struct.unpack_from("<HHIIIHH", raw, 0)
        if machine != 0x8664:
            raise ValueError(f"{path}: not an x64 COFF object (machine {machine:#x})")
        strtab_off = symptr + nsym * 18
        self.strtab = raw[strtab_off:]

        def sname(b):
            if b[:4] == b"\0\0\0\0":
                off = struct.unpack_from("<I", b, 4)[0]
                end = self.strtab.index(b"\0", off)
                return self.strtab[off:end].decode("latin-1")
            return b.rstrip(b"\0").decode("latin-1")

        self.sections = []
        off = 20 + optsz
        for i in range(nsec):
            hdr = raw[off:off + 40]
            name = hdr[:8]
            if name[:1] == b"/":
                so = int(name[1:].rstrip(b"\0"))
                end = self.strtab.index(b"\0", so)
                nm = self.strtab[so:end].decode("latin-1")
            else:
                nm = name.rstrip(b"\0").decode("latin-1")
            vsize, vaddr, rawsz, rawptr, relptr, _lnptr, nrel, _nln, chars = struct.unpack_from(
                "<IIIIIIHHI", hdr, 8)
            if chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
                data = None
                size = rawsz or vsize
            else:
                data = raw[rawptr:rawptr + rawsz]
                size = rawsz
            s = Section(i + 1, nm, data, chars, size)
            # A3-31: handle IMAGE_SCN_LNK_NRELOC_OVFL (0x01000000) when nrel == 0xFFFF
            if (chars & 0x01000000) and nrel == 0xFFFF:
                real_nrel = struct.unpack_from("<I", raw, relptr)[0]
                r_start = 1
            else:
                real_nrel = nrel
                r_start = 0
            for r in range(r_start, real_nrel):
                ro, si, rt = struct.unpack_from("<IIH", raw, relptr + r * 10)
                s.relocs.append((ro, REL_AMD64.get(rt, f"T{rt}"), si))
            s.relocs.sort()
            self.sections.append(s)
            off += 40

        self.symbols = {}
        i = 0
        while i < nsym:
            e = raw[symptr + i * 18: symptr + (i + 1) * 18]
            name = sname(e[:8])
            value, secnum, typ, cls, naux = struct.unpack_from("<IhHBB", e, 8)
            self.symbols[i] = Symbol(i, name, value, secnum, typ, cls, naux)
            i += 1 + naux

        self.procs = []           # (section_idx, start, length, name)
        self.lines = {}           # section_idx -> sorted [(offset, line, file)]
        self._parse_codeview()

    # ---------------------------------------------------------------------
    def section(self, idx):
        return self.sections[idx - 1]

    def reloc_map(self, sec):
        return {ro: (rt, si) for ro, rt, si in sec.relocs}

    def _parse_codeview(self):
        for sec in self.sections:
            if sec.name != ".debug$S" or sec.data is None:
                continue
            rmap = {}
            for ro, rt, si in sec.relocs:
                rmap.setdefault(ro, []).append((rt, si))
            d = sec.data
            if struct.unpack_from("<I", d, 0)[0] != 4:
                continue
            pos = 4
            files = {}
            strtab = b""
            pending_lines = []
            while pos + 8 <= len(d):
                stype, slen = struct.unpack_from("<II", d, pos)
                body = pos + 8
                end = body + slen
                if stype == 0xF1:
                    p = body
                    while p + 4 <= end:
                        rlen, rkind = struct.unpack_from("<HH", d, p)
                        if rlen < 2:
                            break
                        if rkind in (0x1110, 0x110F, 0x1146, 0x1147):
                            plen = struct.unpack_from("<I", d, p + 16)[0]
                            off_field = p + 32
                            name_off = p + 39
                            nend = d.index(b"\0", name_off)
                            name = d[name_off:nend].decode("latin-1")
                            tgt = self._secrel_target(rmap, off_field, d)
                            if tgt:
                                self.procs.append((tgt[0], tgt[1], plen, name))
                        p += 2 + rlen
                elif stype == 0xF2:
                    pending_lines.append((body, end))
                elif stype == 0xF3:
                    strtab = d[body:end]
                elif stype == 0xF4:
                    p = body
                    while p + 6 <= end:
                        fid = p - body
                        name_off, cbsum, _kind = struct.unpack_from("<IBB", d, p)
                        files[fid] = name_off
                        p += 6 + cbsum
                        p = (p + 3) & ~3
                pos = (end + 3) & ~3
            for body, end in pending_lines:
                tgt = self._secrel_target(rmap, body, d)
                if not tgt:
                    continue
                sidx, base = tgt
                _flags, _cb = struct.unpack_from("<HI", d, body + 6)
                p = body + 12
                lst = self.lines.setdefault(sidx, [])
                while p + 12 <= end:
                    fid, nlines, cbblock = struct.unpack_from("<III", d, p)
                    fname = ""
                    if fid in files and strtab:
                        so = files[fid]
                        fe = strtab.index(b"\0", so)
                        fname = strtab[so:fe].decode("latin-1")
                        fname = fname.replace("\\", "/").split("/")[-1]
                    q = p + 12
                    for k in range(nlines):
                        loff, lflags = struct.unpack_from("<II", d, q + 8 * k)
                        lst.append((base + loff, lflags & 0xFFFFFF, fname))
                    p += cbblock
            for v in self.lines.values():
                v.sort()

    def _secrel_target(self, rmap, field_off, d):
        rs = rmap.get(field_off)
        if not rs:
            return None
        for rt, si in rs:
            if rt == "SECREL":
                sym = self.symbols.get(si)
                if sym is None or sym.secnum <= 0:
                    return None
                addend = struct.unpack_from("<I", d, field_off)[0]
                return (sym.secnum, sym.value + addend)
        return None
