"""xlat.py - translate Vordr's assembled x64 COFF objects into AArch64 assembly.

    python tools/a64/xlat.py --obj obj/x64/gui.obj --out obj/arm64/gui.S \
        --symtab obj/arm64/symtab.json [--override name ...] [--drop name ...]

The input is the x64 object ml64 produced from src/<mod>.asm: every MASM macro
is expanded, every expression resolved, every symbol and relocation explicit.
Each x64 instruction becomes a short AArch64 sequence that keeps x64 register
semantics on fixed ARM64 registers (docs/ARM64.md).  The output is annotated
with the x64 source line of every instruction.

Design summary
  * registers  rax=x8 rcx=x0 rdx=x1 r8=x2 r9=x3 r10=x9 r11=x10 rbx=x19 rsi=x20
               rdi=x21 r12..r15=x22..x25 rbp=x29 rsp=sp; scratch x11..x17, v16..v31
  * flags      a backward liveness pass decides which x64 flag producers must set
               NZCV; a forward pass records the producer kind (sub / add / logic /
               incdec / fcmp / mulovf / bt / zero) so each consumer maps its x64
               condition to the right ARM condition (carry polarity differs).
  * stack      identity layout: an x64 stack address is the same ARM address.  The
               x64 depth d (bytes below the caller's sp, return slot included) is
               tracked per instruction; ARM sp is kept at align16(d) once the
               return address has been stored in the x64 return slot ([A-8]).
  * calls      internal: bl.  Windows APIs / COM / GetProcAddress pointers: load
               x4-x7 from the x64 stack-arg slots, move args 9+ down to [sp], bl,
               then x8 <- x0.  Procedures whose address is handed to Windows get a
               callback thunk (ARM64 ABI in, internal ABI out).
"""
import argparse
import json
import os
import re
import struct
import sys

import capstone
from capstone import x86 as X86

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from coff import CoffObject  # noqa: E402

LP_MAGIC = 0xD1B7C0DEFACEB00C


class XlatError(Exception):
    pass


# ---------------------------------------------------------------------------
# register model
# ---------------------------------------------------------------------------
FAM = {
    "rax": 8, "rcx": 0, "rdx": 1, "rbx": 19, "rsp": "sp", "rbp": 29, "rsi": 20,
    "rdi": 21, "r8": 2, "r9": 3, "r10": 9, "r11": 10, "r12": 22, "r13": 23,
    "r14": 24, "r15": 25,
}
SUBREG = {}
for f, l32, l16, l8, h8 in [
    ("rax", "eax", "ax", "al", "ah"), ("rcx", "ecx", "cx", "cl", "ch"),
    ("rdx", "edx", "dx", "dl", "dh"), ("rbx", "ebx", "bx", "bl", "bh"),
    ("rsp", "esp", "sp", "spl", None), ("rbp", "ebp", "bp", "bpl", None),
    ("rsi", "esi", "si", "sil", None), ("rdi", "edi", "di", "dil", None)]:
    SUBREG[f] = (f, 8, False)
    SUBREG[l32] = (f, 4, False)
    SUBREG[l16] = (f, 2, False)
    SUBREG[l8] = (f, 1, False)
    if h8:
        SUBREG[h8] = (f, 1, True)
for n in range(8, 16):
    f = f"r{n}"
    SUBREG[f] = (f, 8, False)
    SUBREG[f + "d"] = (f, 4, False)
    SUBREG[f + "w"] = (f, 2, False)
    SUBREG[f + "b"] = (f, 1, False)

XMM = {f"xmm{i}": i for i in range(6)}
XMM.update({f"xmm{i}": i + 2 for i in range(6, 14)})
XMM.update({"xmm14": 6, "xmm15": 7})
XMM.update({f"ymm{i}": v for i, v in [(k, XMM[f'xmm{k}']) for k in range(16)]})

COND_SUB = {"e": "eq", "z": "eq", "ne": "ne", "nz": "ne", "b": "lo", "c": "lo",
            "nae": "lo", "ae": "hs", "nb": "hs", "nc": "hs", "be": "ls", "na": "ls",
            "a": "hi", "nbe": "hi", "l": "lt", "nge": "lt", "ge": "ge", "nl": "ge",
            "le": "le", "ng": "le", "g": "gt", "nle": "gt", "s": "mi", "ns": "pl",
            "o": "vs", "no": "vc"}
CANON = {"z": "e", "nz": "ne", "c": "b", "nae": "b", "nb": "ae", "nc": "ae",
         "na": "be", "nbe": "a", "nge": "l", "nl": "ge", "ng": "le", "nle": "g",
         "pe": "p", "po": "np"}
INV_ARM = {"eq": "ne", "ne": "eq", "hs": "lo", "lo": "hs", "mi": "pl", "pl": "mi",
           "vs": "vc", "vc": "vs", "hi": "ls", "ls": "hi", "ge": "lt", "lt": "ge",
           "gt": "le", "le": "gt"}


def canon_cc(cc):
    return CANON.get(cc, cc)


def arm_cond(cc, kind):
    """x64 condition (canonical) + producer kind -> ARM cond, 'always',
    'never', or ('or', c1, c2) / ('and', c1, c2)."""
    cc = canon_cc(cc)
    if kind == "sub":
        return COND_SUB[cc]
    if kind == "add":
        if cc == "b":
            return "hs"
        if cc == "ae":
            return "lo"
        if cc == "a":
            return ("and", "lo", "ne")
        if cc == "be":
            return ("or", "hs", "eq")
        return COND_SUB[cc]
    if kind in ("logic", "zero"):
        m = {"b": "never", "ae": "always", "be": "eq", "a": "ne", "o": "never",
             "no": "always"}
        if cc in m:
            return m[cc]
        if kind == "zero" and cc in ("l", "ge", "le", "g"):
            raise XlatError(f"signed condition {cc} after a result-only flag producer")
        return COND_SUB[cc]
    if kind == "incdec":
        if cc in ("b", "ae", "a", "be"):
            raise XlatError(f"carry condition {cc} after inc/dec (CF not modelled)")
        return COND_SUB[cc]
    if kind == "fcmp":
        m = {"b": "lt", "ae": "ge", "a": "gt", "be": "le", "e": "eq", "ne": "ne",
             "p": "vs", "np": "vc"}
        if cc not in m:
            raise XlatError(f"condition {cc} after comiss")
        return m[cc]
    if kind in ("mulovf", "bt"):
        m = {"b": "ne", "o": "ne", "ae": "eq", "no": "eq"}
        if cc not in m:
            raise XlatError(f"condition {cc} after {kind} producer")
        return m[cc]
    raise XlatError(f"unknown flag kind {kind}")


# ---------------------------------------------------------------------------
# immediates
# ---------------------------------------------------------------------------
def is_bitmask_imm(v, width):
    mask = (1 << width) - 1
    v &= mask
    if v == 0 or v == mask:
        return False
    size = width
    while size > 2:
        half = size // 2
        hm = (1 << half) - 1
        if (v & hm) != ((v >> half) & hm):
            break
        size = half
    em = (1 << size) - 1
    e = v & em
    # element must be a rotated run of ones
    for r in range(size):
        rot = ((e >> r) | (e << (size - r))) & em
        # rot should be 0..01..1
        if rot & (rot + 1) == 0 and rot != 0:
            return True
    return False


def fits_addsub(v):
    return 0 <= v <= 0xFFF or (v & 0xFFF == 0 and 0 <= v <= 0xFFF000)


def s64(v):
    v &= 0xFFFFFFFFFFFFFFFF
    return v - (1 << 64) if v >> 63 else v


class Op:
    """Normalised x64 operand."""
    __slots__ = ("k", "reg", "size", "imm", "base", "index", "scale", "disp", "seg",
                 "sym", "high", "fam", "xmm")

    def __init__(self, k, **kw):
        self.k = k
        self.reg = self.base = self.index = self.seg = self.sym = self.fam = None
        self.xmm = None
        self.size = 0
        self.imm = 0
        self.scale = 1
        self.disp = 0
        self.high = False
        for a, b in kw.items():
            setattr(self, a, b)

    def __repr__(self):
        return f"Op({self.k},{self.reg},{self.size},{self.imm},{self.base},{self.index},{self.disp},{self.sym})"


# ---------------------------------------------------------------------------
# instruction wrapper
# ---------------------------------------------------------------------------
class Ins:
    def __init__(self, cs, off, relocs, tr):
        self.cs = cs
        self.off = off
        self.size = cs.size
        self.mn = cs.mnemonic
        self.prefix = cs.prefix
        self.ops = []
        self.target = None       # ('local', off) | ('sym', name, addend) for branches
        self.relocs = relocs
        self.tr = tr
        rep = X86.X86_PREFIX_REP in cs.prefix or X86.X86_PREFIX_REPE in cs.prefix
        self.rep = rep
        self.lock = X86.X86_PREFIX_LOCK in cs.prefix
        if self.mn.startswith(("rep ", "repe ", "repz ")):
            self.rep = True
            self.mn = self.mn.split(" ", 1)[1]
        elif self.mn.startswith("lock "):
            self.lock = True
            self.mn = self.mn.split(" ", 1)[1]
        for o in cs.operands:
            self.ops.append(self._op(o))
        if self.mn in ("call", "jmp") or (self.mn.startswith("j") and self.mn != "jmp"):
            if self.ops and self.ops[0].k == "imm":
                r = self._reloc_at(cs.imm_offset) if cs.imm_offset else None
                if r is not None:
                    self.target = tr.reloc_target(r, cs.bytes, cs.imm_offset)
                else:
                    self.target = ("local", self.ops[0].imm)

    def _reloc_at(self, field):
        for ro, rt, si in self.relocs:
            if ro - self.off == field:
                return (ro, rt, si)
        return None

    def _op(self, o):
        cs = self.cs
        if o.type == X86.X86_OP_REG:
            name = cs.reg_name(o.reg)
            if name in SUBREG:
                fam, sz, hi = SUBREG[name]
                return Op("reg", reg=name, fam=fam, size=sz, high=hi)
            if name in XMM:
                return Op("xmm", reg=name, xmm=XMM[name], size=o.size)
            raise XlatError(f"unsupported register {name}")
        if o.type == X86.X86_OP_IMM:
            op = Op("imm", imm=o.imm, size=o.size)
            if cs.imm_offset:
                r = self._reloc_at(cs.imm_offset)
                if r is not None:
                    op.sym = self.tr.reloc_target(r, cs.bytes, cs.imm_offset)
            return op
        if o.type == X86.X86_OP_MEM:
            m = o.mem
            base = cs.reg_name(m.base) if m.base else None
            index = cs.reg_name(m.index) if m.index else None
            seg = cs.reg_name(m.segment) if m.segment else None
            op = Op("mem", base=base, index=index, scale=m.scale, disp=m.disp,
                    size=o.size, seg=seg)
            if base == "rip":
                r = self._reloc_at(cs.disp_offset) if cs.disp_offset else None
                if r is not None:
                    op.sym = self.tr.reloc_target(r, cs.bytes, cs.disp_offset,
                                                  rip_end=self.off + self.size)
                else:
                    op.sym = ("local", self.off + self.size + m.disp)
                op.base = None
                op.disp = 0
            elif cs.disp_offset:
                r = self._reloc_at(cs.disp_offset)
                if r is not None:
                    raise XlatError("absolute-address memory operand with relocation")
            return op
        raise XlatError(f"operand type {o.type}")


# ---------------------------------------------------------------------------
# flags metadata
# ---------------------------------------------------------------------------
FLAG_WRITERS = {
    "add": "add", "adc": "add", "sub": "sub", "sbb": "sub", "cmp": "sub", "neg": "sub",
    "and": "logic", "or": "logic", "xor": "logic", "test": "logic",
    "inc": "incdec", "dec": "incdec",
    "shl": "zero", "sal": "zero", "shr": "zero", "sar": "zero",
    "rol": "rot", "ror": "rot",
    "imul": "mulovf", "mul": "mulovf",
    "bt": "bt", "bts": "bt", "bsr": "zero", "bsf": "zero",
    "comiss": "fcmp", "ucomiss": "fcmp", "cmpxchg": "sub",
    "div": "undef", "idiv": "undef",
}


def flag_reader(mn):
    if mn.startswith("j") and mn not in ("jmp", "jrcxz", "jecxz"):
        return True
    if mn.startswith("set") or mn.startswith("cmov"):
        return True
    return mn in ("adc", "sbb")


def cond_of(mn):
    if mn.startswith("cmov"):
        return mn[4:]
    if mn.startswith("set"):
        return mn[3:]
    if mn.startswith("j"):
        return mn[1:]
    return "b"  # adc / sbb read CF


# ---------------------------------------------------------------------------
# the translator
# ---------------------------------------------------------------------------
class Translator:
    def __init__(self, obj, modname, symtab, overrides, drops, api_arity, notes):
        self.o = obj
        self.mod = modname
        self.symtab = symtab              # global: name -> 'internal'
        self.overrides = set(overrides)
        self.drops = set(drops)
        self.api_arity = api_arity
        self.notes = notes
        self.out = []
        self.errors = []
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self.callbacks = set()            # (secidx, off) of procs needing a thunk
        self.code_labels = {}             # (secidx, off) -> needed
        self.lp_procs = set()
        self.label_seq = 0

    # ---- symbol plumbing ---------------------------------------------------
    def reloc_target(self, r, insn_bytes, field_off, rip_end=None):
        ro, rt, si = r
        sym = self.o.symbols[si]
        if rt in ("REL32", "REL32_1", "REL32_2", "REL32_3", "REL32_4", "REL32_5",
                  "ADDR32NB"):
            addend = struct.unpack_from("<i", insn_bytes, field_off)[0]
        elif rt == "ADDR64":
            addend = struct.unpack_from("<q", insn_bytes, field_off)[0]
        else:
            raise XlatError(f"relocation {rt} in code")
        return self.symref(sym, addend)

    def symref(self, sym, addend):
        if sym.secnum > 0:
            sec = self.o.section(sym.secnum)
            if sym.is_external:
                return ("sym", sym.name, addend, (sym.secnum, sym.value))
            return ("loc", sym.secnum, sym.value + addend)
        if sym.secnum == 0:
            return ("sym", sym.name, addend, None)
        raise XlatError(f"absolute/debug symbol reference {sym.name}")

    def ref_text(self, ref, for_call=False):
        """assembler expression for a reference"""
        if ref[0] == "sym":
            name, addend = ref[1], ref[2]
            if ref[3] is not None and ref[3] in self.callbacks and not for_call and addend == 0:
                name = self.cb_name(ref[3])
            return name + (f"+{addend}" if addend > 0 else (f"-{-addend}" if addend < 0 else ""))
        if ref[0] == "loc":
            secnum, off = ref[1], ref[2]
            sec = self.o.section(secnum)
            if sec.is_code:
                key = (secnum, off)
                if key in self.callbacks and not for_call:
                    return self.cb_name(key)
                ov = self.override_at.get(key)
                if ov:
                    return ov
                self.code_labels[key] = True
                return self.clabel(off)
            return f".Ls{secnum}" + (f"+{off}" if off else "")
        if ref[0] == "local":  # same-section code offset (current code section)
            key = (self.cur_sec, ref[1])
            if key in self.callbacks and not for_call:
                return self.cb_name(key)
            ov = self.override_at.get(key)
            if ov:
                return ov
            self.code_labels[key] = True
            return self.clabel(ref[1])
        raise XlatError(f"bad ref {ref}")

    def clabel(self, off):
        return f".Lc{self.cur_sec}_{off:x}"

    def cb_name(self, key):
        pub = self.public_at.get(key)
        if pub:
            return pub + "__a64cb"
        return f".Lcb{key[0]}_{key[1]:x}"

    # ---- emission helpers --------------------------------------------------
    def e(self, s):
        self.out.append("    " + s)

    def lab(self, s):
        self.out.append(s + ":")

    def newlab(self):
        self.label_seq += 1
        return f".Lt{self.label_seq}"

    def err(self, ins, msg):
        loc = self.srcline(ins.off) if ins else ""
        self.errors.append(f"{self.mod}+{ins.off:#x} {loc} `{ins.mn} {ins.cs.op_str}`: {msg}"
                           if ins else msg)
        self.e(f"brk #0xF00E    // XLAT ERROR: {msg}")

    def srcline(self, off):
        lst = self.o.lines.get(self.cur_sec)
        if not lst:
            return ""
        lo, hi = 0, len(lst) - 1
        best = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if lst[mid][0] <= off:
                best = lst[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return f"{best[2]}:{best[1]}" if best else ""

    # immediates -------------------------------------------------------------
    def movimm(self, dst, v, width=64):
        """materialise v into register dst (x or w name according to width)"""
        mask = (1 << width) - 1
        v &= mask
        r = dst
        if v == 0:
            self.e(f"mov {r}, #0")
            return
        if v == mask:
            self.e(f"movn {r}, #0")
            return
        chunks = [(v >> (16 * i)) & 0xFFFF for i in range(width // 16)]
        nz = [i for i, c in enumerate(chunks) if c]
        if len(nz) == 1:
            self.e(f"movz {r}, #{chunks[nz[0]]:#x}, lsl #{16 * nz[0]}")
            return
        inv = [(~c) & 0xFFFF for c in chunks]
        nzi = [i for i, c in enumerate(inv) if c]
        if len(nzi) == 1:
            self.e(f"movn {r}, #{inv[nzi[0]]:#x}, lsl #{16 * nzi[0]}")
            return
        if is_bitmask_imm(v, width):
            self.e(f"orr {r}, {'xzr' if width == 64 else 'wzr'}, #{v:#x}")
            return
        if len(nzi) < len(nz):
            first = True
            for i, c in enumerate(inv):
                if first and c:
                    self.e(f"movn {r}, #{c:#x}, lsl #{16 * i}")
                    first = False
            for i, c in enumerate(chunks):
                if c != 0xFFFF and not (i == nzi[0]):
                    self.e(f"movk {r}, #{c:#x}, lsl #{16 * i}")
            return
        first = True
        for i, c in enumerate(chunks):
            if c:
                if first:
                    self.e(f"movz {r}, #{c:#x}, lsl #{16 * i}")
                    first = False
                else:
                    self.e(f"movk {r}, #{c:#x}, lsl #{16 * i}")

    # scratch registers -------------------------------------------------------
    def scratch(self):
        r = self._scr[self._scri]
        self._scri += 1
        if self._scri > len(self._scr):
            raise XlatError("out of scratch registers")
        return r

    @staticmethod
    def W(n):
        return "wsp" if n == "sp" else f"w{n}"

    @staticmethod
    def Xn(n):
        return "sp" if n == "sp" else f"x{n}"

    # ---- addressing ------------------------------------------------------------
    def addr(self, op, access):
        """return an ARM memory operand string '[...]' for an x64 memory operand.
        access = byte size of the access (1,2,4,8,16)."""
        if op.seg == "gs":
            if op.base or op.index:
                # gs:[reg*8 + disp] etc.
                t = "x16"
                self._ea_into(op, t, extra_base="x18")
                return f"[{t}]"
            return self._imm_off("x18", op.disp, access)
        if op.seg not in (None, "ds", "ss"):
            raise XlatError(f"segment {op.seg}")
        if op.sym is not None:
            t = "x16"
            self.e(f"adrp {t}, {self.ref_text(op.sym)}")
            self.e(f"add {t}, {t}, :lo12:{self.ref_text(op.sym)}")
            if op.index:
                self._add_index(t, op)
            return f"[{t}]"
        base = op.base
        disp = op.disp
        if base in ("rsp", "esp"):
            disp += self.sp_adjust()
            breg = "sp"
        elif base:
            fam = SUBREG[base][0]
            if SUBREG[base][1] != 8:
                raise XlatError("32-bit address register")
            breg = self.Xn(FAM[fam])
        else:
            breg = None
        if op.index:
            t = "x16"
            if breg is None:
                self.movimm(t, 0)
                breg = t
            idx = SUBREG[op.index]
            if idx[1] != 8:
                raise XlatError("32-bit index register")
            sh = {1: 0, 2: 1, 4: 2, 8: 3}[op.scale]
            self.e(f"add {t}, {breg}, {self.Xn(FAM[idx[0]])}, lsl #{sh}")
            breg = t
        if breg is None:
            raise XlatError("absolute memory operand")
        return self._imm_off(breg, disp, access)

    def _add_index(self, t, op):
        idx = SUBREG[op.index]
        sh = {1: 0, 2: 1, 4: 2, 8: 3}[op.scale]
        self.e(f"add {t}, {t}, {self.Xn(FAM[idx[0]])}, lsl #{sh}")

    def _ea_into(self, op, t, extra_base=None):
        """effective address of a non-rip memory operand into register t"""
        parts = []
        if op.base:
            if op.base in ("rsp", "esp"):
                self.e(f"add {t}, sp, #{0}")
                base = t
                disp_adj = self.sp_adjust()
            else:
                base = self.Xn(FAM[SUBREG[op.base][0]])
                disp_adj = 0
        else:
            base = None
            disp_adj = 0
        disp = op.disp + disp_adj
        if extra_base:
            if base:
                self.e(f"add {t}, {base}, {extra_base}")
            else:
                self.e(f"mov {t}, {extra_base}")
            base = t
        if op.index:
            idx = SUBREG[op.index]
            sh = {1: 0, 2: 1, 4: 2, 8: 3}[op.scale]
            if base:
                self.e(f"add {t}, {base}, {self.Xn(FAM[idx[0]])}, lsl #{sh}")
            else:
                self.e(f"lsl {t}, {self.Xn(FAM[idx[0]])}, #{sh}")
            base = t
        if base is None:
            self.movimm(t, disp)
            return
        self.add_imm(t, base, disp)

    def add_imm(self, dst, src, v):
        if v == 0:
            if dst != src:
                self.e(f"mov {dst}, {src}")
            return
        op, a = ("add", v) if v > 0 else ("sub", -v)
        if fits_addsub(a):
            self.e(f"{op} {dst}, {src}, #{a:#x}")
        elif a <= 0xFFFFFF:
            self.e(f"{op} {dst}, {src}, #{a & 0xFFF000:#x}")
            if a & 0xFFF:
                self.e(f"{op} {dst}, {dst}, #{a & 0xFFF:#x}")
        else:
            self.movimm("x17", v)
            self.e(f"add {dst}, {src}, x17")

    def _imm_off(self, breg, disp, access):
        if disp == 0:
            return f"[{breg}]"
        if access in (1, 2, 4, 8, 16) and disp > 0 and disp % access == 0 and disp // access <= 4095:
            return f"[{breg}, #{disp}]"
        if -256 <= disp <= 255:
            return f"[{breg}, #{disp}]"     # assembler picks ldur/stur
        self.movimm("x17", disp)
        return f"[{breg}, x17]"

    # ---- stack model -----------------------------------------------------------
    def sp_adjust(self):
        """ARM address of x64 [rsp+0] relative to ARM sp: x64_rsp - arm_sp = s - d"""
        st = self.st
        return st["s"] - st["d"]

    @staticmethod
    def a16(d):
        return (d + 15) & ~15

    # ---- operand access ----------------------------------------------------------
    def rd(self, op, size=None, sx=False):
        """value of op -> register name (w for <=4 bytes, x for 8)"""
        size = size or op.size
        if op.k == "reg":
            n = FAM[op.fam]
            if n == "sp":
                t = self.scratch()
                self.e(f"add x{t}, sp, #{0}" if self.sp_adjust() == 0 else f"add x{t}, sp, #{self.sp_adjust()}")
                return f"x{t}" if size == 8 else f"w{t}"
            if op.high:
                t = self.scratch()
                self.e(f"{'sbfx' if sx else 'ubfx'} w{t}, w{n}, #8, #8")
                return f"w{t}"
            if op.size == 8:
                return f"x{n}" if size == 8 else f"w{n}"
            if op.size == 4:
                if size == 8:
                    t = self.scratch()
                    self.e(f"{'sxtw' if sx else 'mov'} {'x' if sx else 'w'}{t}, w{n}")
                    return f"x{t}"
                return f"w{n}"
            t = self.scratch()
            ext = {1: "b", 2: "h"}[op.size]
            if sx:
                self.e(f"sxt{ext} {'x' if size == 8 else 'w'}{t}, w{n}")
            else:
                self.e(f"uxt{ext} w{t}, w{n}")
            return (f"x{t}" if size == 8 else f"w{t}")
        if op.k == "imm":
            t = self.scratch()
            if op.sym is not None:
                self.e(f"adrp x{t}, {self.ref_text(op.sym)}")
                self.e(f"add x{t}, x{t}, :lo12:{self.ref_text(op.sym)}")
                return f"x{t}"
            v = op.imm
            if size == 8:
                self.movimm(f"x{t}", v, 64)
                return f"x{t}"
            self.movimm(f"w{t}", v & ((1 << (8 * min(size, 4))) - 1), 32)
            return f"w{t}"
        if op.k == "mem":
            t = self.scratch()
            a = self.addr(op, op.size)
            msz = op.size
            if msz == 8:
                self.e(f"ldr x{t}, {a}")
                return f"x{t}" if size == 8 else f"w{t}"
            if msz == 4:
                if sx and size == 8:
                    self.e(f"ldrsw x{t}, {a}")
                    return f"x{t}"
                self.e(f"ldr w{t}, {a}")
                return f"x{t}" if size == 8 else f"w{t}"
            ins = {1: "b", 2: "h"}[msz]
            if sx:
                self.e(f"ldrs{ins} {'x' if size == 8 else 'w'}{t}, {a}")
            else:
                self.e(f"ldr{ins} w{t}, {a}")
            return f"x{t}" if size == 8 else f"w{t}"
        raise XlatError(f"cannot read operand {op}")

    def wr(self, op, src, size=None):
        """write register src (w or x name) into op"""
        size = size or op.size
        if op.k == "reg":
            n = FAM[op.fam]
            if n == "sp":
                raise XlatError("direct write to rsp")
            if op.high:
                self.e(f"bfi x{n}, x{src[1:]}, #8, #8")
                return
            if op.size == 8:
                if src != f"x{n}":
                    self.e(f"mov x{n}, x{src[1:]}")
                return
            if op.size == 4:
                if src != f"w{n}" or True:
                    self.e(f"mov w{n}, w{src[1:]}")
                return
            self.e(f"bfi x{n}, x{src[1:]}, #0, #{8 * op.size}")
            return
        if op.k == "mem":
            r = src[1:]
            if r in ("16", "17"):
                self.e(f"mov x15, x{r}")
                r = "15"
            a = self.addr(op, op.size)
            st = {1: f"strb w{r}", 2: f"strh w{r}", 4: f"str w{r}", 8: f"str x{r}"}[op.size]
            self.e(f"{st}, {a}")
            return
        raise XlatError(f"cannot write operand {op}")

    def regname(self, op, size=None):
        """ARM register directly holding a 32/64-bit x64 register operand"""
        n = FAM[op.fam]
        size = size or op.size
        return f"x{n}" if size == 8 else f"w{n}"

    def direct(self, op):
        return op.k == "reg" and op.size in (4, 8) and not op.high and FAM[op.fam] != "sp"

    # ---- main per-module driver ------------------------------------------------------
    def run(self):
        o = self.o
        self.public_at = {}
        self.sym_at = {}
        for s in o.symbols.values():
            if s.secnum > 0:
                if s.is_external:
                    self.public_at[(s.secnum, s.value)] = s.name
                self.sym_at.setdefault((s.secnum, s.value), []).append(s.name)
        self.procs = sorted(o.procs)
        self.override_at = {(p[0], p[1]): p[3] for p in self.procs if p[3] in self.overrides}
        self.find_callbacks()
        hdr = [f"// generated by tools/a64/xlat.py from {os.path.basename(o.path)} - do not edit",
               f"// source module: {self.mod}.asm (x64 MASM); see docs/ARM64.md", ""]
        for sec in o.sections:
            if sec.is_code:
                self.translate_code(sec)
        body = self.out
        self.out = []
        for sec in o.sections:
            if not sec.is_code:
                self.emit_data(sec)
        data = self.out
        self.out = hdr + body + data
        return self.out

    # ---- callback detection ------------------------------------------------------------
    def find_callbacks(self):
        """procs whose address is taken by something other than a direct call/jump
        (lea, mov imm64, data pointer) and that are not DLPV landing-pad targets."""
        o = self.o
        procstart = {(p[0], p[1]): p[3] for p in self.procs}
        for sec in o.sections:
            if sec.is_code and sec.data:
                for (s, st), nm in procstart.items():
                    if s == sec.idx and st >= 16:
                        if sec.data[st - 16:st] == b"\xcc" * 8 + struct.pack("<Q", LP_MAGIC):
                            self.lp_procs.add((s, st))
        taken = set()
        for sec in o.sections:
            if sec.name.startswith(".debug") or sec.name in (".pdata", ".xdata"):
                continue
            for ro, rt, si in sec.relocs:
                sym = o.symbols[si]
                if sym.secnum <= 0:
                    continue
                tsec = o.section(sym.secnum)
                if not tsec.is_code:
                    continue
                if sec.is_code:
                    # is this reloc the target of a call/jmp?  peek at the opcode byte
                    b = sec.data[ro - 1] if ro >= 1 else 0
                    if rt == "REL32" and b in (0xE8, 0xE9):
                        continue
                    if rt == "REL32" and ro >= 2 and sec.data[ro - 2] == 0x0F and 0x80 <= b <= 0x8F:
                        continue
                if rt == "ADDR32NB":
                    continue      # imagerel (gfids / load config): keep the real entry
                if rt in ("REL32", "REL32_1", "REL32_2", "REL32_3", "REL32_4", "REL32_5"):
                    addend = struct.unpack_from("<i", sec.data, ro)[0]
                elif rt == "ADDR64":
                    addend = struct.unpack_from("<q", sec.data, ro)[0] if sec.data else 0
                else:
                    continue
                key = (sym.secnum, sym.value + addend)
                taken.add(key)
        for key in taken:
            if key in procstart and key not in self.lp_procs:
                nm = procstart[key]
                if nm in self.overrides or nm in self.drops:
                    continue
                self.callbacks.add(key)
        for key in sorted(self.callbacks):
            self.notes.append(f"{self.mod}: callback thunk for {procstart[key]}")

    # ---- code ----------------------------------------------------------------------------
    def translate_code(self, sec):
        self.cur_sec = sec.idx
        o = self.o
        procs = [p for p in self.procs if p[0] == sec.idx]
        self.e(".text")
        queue = list(procs)
        seen_starts = {p[1] for p in procs}
        covered = []
        for (_s, st, ln, _nm) in procs:
            lo = st - 16 if (sec.idx, st) in self.lp_procs else st
            covered.append((lo, st + ln))
        self._sub_queue = []
        while queue:
            (_s, start, length, name) = queue.pop(0)
            if name in self.drops:
                self.out.append(f"// {name}: dropped (x86-only variant, replaced by src/arm64)")
                continue
            if name in self.overrides:
                self.out.append(f"// {name}: provided by hand-written src/arm64 code")
                continue
            self._sub_queue = []
            try:
                self.translate_proc(sec, start, length, name)
            except XlatError as ex:
                self.errors.append(f"{self.mod}:{name}: {ex}")
            for sub in self._sub_queue:
                if sub[1] not in seen_starts:
                    seen_starts.add(sub[1])
                    queue.append(sub)
        # Emit any read-only data (CSTR/WSTR) placed inside .code between PROCs
        covered.sort()
        gaps = []
        cur = 0
        for lo, hi in covered:
            if lo > cur:
                gaps.append((cur, lo))
            cur = max(cur, hi)
        if cur < sec.size:
            gaps.append((cur, sec.size))
        ref_offs = {off for (sidx, off) in self.code_labels if sidx == sec.idx}
        for (sidx, off) in self.public_at:
            if sidx == sec.idx:
                ref_offs.add(off)
        for glo, ghi in gaps:
            hits = sorted(o for o in ref_offs if glo <= o < ghi)
            if not hits:
                continue
            self.out.append("")
            self.out.append(f"// ---- read-only data emitted inside .code ({glo:#x}..{ghi:#x})")
            self.e('.section .rdata,"dr"')
            self.e(".p2align 4")
            if glo & 15:
                self.e(f".zero {glo & 15}")
            data = sec.data
            pos = glo
            run = []
            hit_set = set(hits)
            def flush_gap():
                if run:
                    for i in range(0, len(run), 16):
                        self.e(".byte " + ", ".join(f"{b:#04x}" for b in run[i:i + 16]))
                    run.clear()
            while pos < ghi:
                if pos in hit_set:
                    flush_gap()
                    pub = self.public_at.get((sec.idx, pos))
                    if pub:
                        self.e(f".globl {pub}")
                        self.lab(pub)
                    self.lab(self.clabel(pos))
                run.append(data[pos])
                pos += 1
            flush_gap()
            self.e(".text")

    def disasm_proc(self, sec, start, length, name=""):
        """recursive traversal from the proc entry; returns {off: Ins}"""
        end = start + length
        data = sec.data
        relocs = sec.relocs
        insns = {}
        work = [start]
        while work:
            off = work.pop()
            while start <= off < end and off not in insns:
                chunk = data[off:off + 16]
                it = self.md.disasm(chunk, off, 1)
                cs = next(it, None)
                if cs is None:
                    raise XlatError(f"undecodable bytes at {off:#x}")
                rel = [r for r in relocs if off <= r[0] < off + cs.size]
                ins = Ins(cs, off, rel, self)
                insns[off] = ins
                mn = ins.mn
                if ins.target and ins.target[0] == "local":
                    t = ins.target[1]
                    if start <= t < end:
                        if mn != "call":
                            work.append(t)
                        elif t > start:
                            self._sub_queue.append((sec.idx, t, end - t, f"{name}__{t:x}"))
                if mn in ("ret", "jmp", "int3") or (mn == "int" and ins.ops and ins.ops[0].imm == 0x29):
                    if mn == "jmp" or mn == "ret" or mn == "int":
                        break
                    if mn == "int3":
                        break
                off += cs.size
        # also follow code-label relocations inside the proc (lea of a local label)
        return insns

    def translate_proc(self, sec, start, length, name):
        insns = self.disasm_proc(sec, start, length, name)
        order = sorted(insns)
        self.insns = insns
        self.order = order
        # successors -------------------------------------------------------------------
        succ = {}
        for i, off in enumerate(order):
            ins = insns[off]
            nxt = order[i + 1] if i + 1 < len(order) and order[i + 1] == off + ins.size else None
            mn = ins.mn
            s = []
            if mn == "ret" or mn == "int3" or (mn == "int"):
                pass
            elif mn == "jmp":
                if ins.target and ins.target[0] == "local" and ins.target[1] in insns:
                    s.append(ins.target[1])
            elif mn.startswith("j"):
                if ins.target and ins.target[0] == "local" and ins.target[1] in insns:
                    s.append(ins.target[1])
                if nxt is not None:
                    s.append(nxt)
            else:
                if nxt is not None:
                    s.append(nxt)
            succ[off] = s
        self.succ = succ
        preds = {off: [] for off in order}
        for a, ss in succ.items():
            for b in ss:
                preds[b].append(a)
        self.preds = preds
        self.flag_analysis(order, insns, succ, preds)
        self.stack_analysis(name, start, order, insns, succ)
        # emit -----------------------------------------------------------------------------
        key = (sec.idx, start)
        pub = self.public_at.get(key)
        self.out.append("")
        self.out.append(f"// ---- proc {name} ({self.srcline(start)})")
        if key in self.lp_procs:
            self.e(".p2align 4")
            self.e(f".quad 0xCCCCCCCCCCCCCCCC")
            self.e(f".quad {LP_MAGIC:#x}    // LP_MAGIC: DLPV landing pad")
        self.e(".p2align 2")
        has_seh = self.prologue_end is not None
        if pub:
            self.e(f".globl {pub}")
        if has_seh:
            self.e(f".seh_proc {pub or self.clabel(start)}")
        if pub:
            self.lab(pub)
        self.lab(self.clabel(start))
        self.in_prologue = has_seh
        lastline = None
        for off in order:
            ins = insns[off]
            self.st = dict(self.stin[off])
            if off != start and (preds[off] and (len(preds[off]) > 1 or preds[off][0] + insns[preds[off][0]].size != off)) or (sec.idx, off) in self.code_labels or off in self.branch_targets:
                if off != start:
                    self.lab(self.clabel(off))
            elif off != start:
                # label for every instruction start that may be referenced later
                self.lab(self.clabel(off))
            ln = self.srcline(off)
            self.out.append(f"    // {ln:<16} {ins.mn} {ins.cs.op_str}" if ln != lastline or True else "")
            lastline = ln
            self._scr = [11, 12, 13, 14, 15]
            self._scri = 0
            try:
                self.translate_ins(ins)
            except XlatError as ex:
                self.err(ins, str(ex))
            if self.in_prologue and off == self.prologue_end:
                self.e(".seh_endprologue")
                self.in_prologue = False
        if has_seh:
            if self.in_prologue:
                self.e(".seh_endprologue")
            self.e(".seh_endproc")
        if key in self.callbacks:
            self.emit_thunk(key, name)

    def emit_thunk(self, key, name):
        nm = self.cb_name(key)
        self.out.append(f"// ---- Windows callback entry for {name}: ARM64 ABI -> internal ABI")
        self.e(".p2align 2")
        if not nm.startswith(".L"):
            self.e(f".globl {nm}")
        self.e(f".seh_proc {nm}")
        self.lab(nm)
        self.e("pacibsp")
        self.e(".seh_pac_sign_lr")
        self.e("stp x29, x30, [sp, #-16]!")
        self.e(".seh_save_fplr_x 16")
        self.e("mov x29, sp")
        self.e(".seh_set_fp")
        self.e("sub sp, sp, #64")
        self.e(".seh_stackalloc 64")
        self.e(".seh_endprologue")
        self.e("stp x4, x5, [sp, #32]     // x64 stack args 5..8 at [rsp+32..]")
        self.e("stp x6, x7, [sp, #48]")
        self.e(f"bl {self.clabel(key[1])}")
        self.e("mov x0, x8")
        self.e("mov sp, x29")
        self.e("ldp x29, x30, [sp], #16")
        self.e("autibsp")
        self.e("ret")
        self.e(".seh_endproc")

    # ---- flags dataflow -------------------------------------------------------------------
    def ins_flags(self, ins):
        mn = ins.mn
        reads = flag_reader(mn)
        writes = mn in FLAG_WRITERS or mn == "call"
        if mn in ("shl", "sal", "shr", "sar", "rol", "ror"):
            # shift by cl with count 0 leaves flags; treat as write anyway
            writes = True
        return reads, writes

    def flag_analysis(self, order, insns, succ, preds):
        live_in = {off: False for off in order}
        live_out = {off: False for off in order}
        changed = True
        rw = {off: self.ins_flags(insns[off]) for off in order}
        while changed:
            changed = False
            for off in reversed(order):
                lo = any(live_in[s] for s in succ[off])
                r, w = rw[off]
                li = r or (lo and not w)
                if lo != live_out[off] or li != live_in[off]:
                    live_out[off] = lo
                    live_in[off] = li
                    changed = True
        self.flags_live = live_out
        # producer kinds (forward)
        kin = {off: None for off in order}
        kout = {}
        changed = True
        iters = 0
        while changed and iters < 50:
            iters += 1
            changed = False
            for off in order:
                ps = preds[off]
                ks = set()
                for p in ps:
                    if p in kout and kout[p] is not None:
                        ks |= kout[p]
                new_in = ks or None
                ins = insns[off]
                r, w = rw[off]
                if w:
                    k = self.producer_kind(ins)
                    out = {k}
                else:
                    out = new_in
                if kin[off] != new_in or kout.get(off) != out:
                    kin[off] = new_in
                    kout[off] = out
                    changed = True
        self.kind_in = kin

    def producer_kind(self, ins):
        mn = ins.mn
        k = FLAG_WRITERS.get(mn)
        if mn == "call":
            return "undef"
        if mn == "neg":
            return "sub"
        return k

    def cur_kind(self, ins):
        ks = self.kind_in.get(ins.off)
        if not ks:
            raise XlatError("flag consumer without a known producer")
        if len(ks) != 1:
            raise XlatError(f"flag consumer reached by different producer kinds {ks}")
        k = next(iter(ks))
        if k in ("undef", "rot"):
            raise XlatError(f"flags consumed after a {k} producer")
        return k

    # ---- stack dataflow ----------------------------------------------------------------------
    def stack_effect(self, ins, st):
        """returns new state dict; raises on unsupported rsp manipulation"""
        st = dict(st)
        mn = ins.mn
        ops = ins.ops

        def lower(nd):
            st["d"] = nd
            if st["mode"] == 0:
                st["mode"] = 1
            st["s"] = self.a16(nd) if st["mode"] == 1 else 0

        def raise_(nd):
            st["d"] = nd
            st["s"] = self.a16(nd) if st["mode"] == 1 else 0
            if st["mode"] == 0 and nd != 8:
                raise XlatError("rsp above entry without frame")

        if mn == "push":
            lower(st["d"] + 8)
        elif mn == "pop":
            if ops[0].k == "reg" and ops[0].fam == "rsp":
                raise XlatError("pop rsp")
            raise_(st["d"] - 8)
            if ops[0].k == "reg" and ops[0].fam == "rbp":
                st["rbp"] = None
        elif mn in ("sub", "add") and ops[0].k == "reg" and ops[0].fam == "rsp":
            if ops[1].k != "imm":
                raise XlatError("rsp adjusted by a register")
            v = ops[1].imm if mn == "sub" else -ops[1].imm
            if v >= 0:
                lower(st["d"] + v)
            else:
                raise_(st["d"] + v)
        elif mn == "mov" and ops[0].k == "reg" and ops[0].fam == "rsp":
            if ops[1].k == "reg" and ops[1].fam == "rbp" and st["rbp"] is not None:
                raise_(st["rbp"]) if st["rbp"] <= st["d"] else lower(st["rbp"])
            else:
                raise XlatError("unsupported mov rsp")
        elif mn == "lea" and ops[0].k == "reg" and ops[0].fam == "rsp":
            m = ops[1]
            if m.base == "rbp" and not m.index and st["rbp"] is not None:
                nd = st["rbp"] - m.disp
                raise_(nd) if nd <= st["d"] else lower(nd)
            elif m.base == "rsp" and not m.index:
                nd = st["d"] - m.disp
                raise_(nd) if nd <= st["d"] else lower(nd)
            else:
                raise XlatError("unsupported lea rsp")
        elif mn == "leave":
            if st["rbp"] is None:
                raise XlatError("leave without known rbp")
            st["d"] = st["rbp"]
            raise_(st["d"] - 8)
            st["rbp"] = None
        elif mn == "and" and ops[0].k == "reg" and ops[0].fam == "rsp":
            if ops[1].k == "imm" and (ops[1].imm & 0xFFFFFFFFFFFFFFFF) == 0xFFFFFFFFFFFFFFF0 and st["d"] % 16 == 0:
                pass  # ARM64 sp is already 16-byte aligned at d % 16 == 0
            else:
                raise XlatError("dynamic rsp alignment")
        # rbp tracking
        if ops and ops[0].k == "reg" and ops[0].fam == "rbp" and mn not in ("push", "cmp", "test"):
            if mn == "mov" and ops[1].k == "reg" and ops[1].fam == "rsp" and ops[0].size == 8:
                st["rbp"] = st["d"]
            elif mn == "lea" and ops[1].k == "mem" and ops[1].base == "rsp" and not ops[1].index:
                st["rbp"] = st["d"] - ops[1].disp
            elif mn != "pop":
                st["rbp"] = None
        if mn in ("xchg",) and any(o.k == "reg" and o.fam in ("rsp",) for o in ops):
            raise XlatError("xchg rsp")
        for o in ops[:1]:
            if o.k == "reg" and o.fam == "rsp" and mn not in ("push", "pop", "sub", "add", "and", "mov", "lea", "cmp", "test"):
                raise XlatError(f"unsupported rsp write via {mn}")
        return st

    def stack_analysis(self, name, start, order, insns, succ):
        stin = {start: {"mode": 0, "d": 8, "s": 0, "rbp": None}}
        work = [start]
        self.branch_targets = set()
        for off in order:
            ins = insns[off]
            if ins.target and ins.target[0] == "local":
                self.branch_targets.add(ins.target[1])
        visited = set()
        while work:
            off = work.pop()
            ins = insns[off]
            try:
                out = self.stack_effect(ins, stin[off])
            except XlatError as ex:
                raise XlatError(f"{ex} at +{off:#x} ({self.srcline(off)})")
            for s in succ[off]:
                if s in stin:
                    if stin[s] != out:
                        a, b = stin[s], out
                        if a["d"] == b["d"] and a["mode"] == b["mode"] and a["s"] == b["s"]:
                            if a["rbp"] != b["rbp"]:
                                m = dict(a)
                                m["rbp"] = None
                                if m != a:
                                    stin[s] = m
                                    work.append(s)
                            continue
                        raise XlatError(f"stack state mismatch at +{s:#x} ({self.srcline(s)}): {a} vs {b}")
                else:
                    stin[s] = out
                    work.append(s)
        # unreachable (by traversal) instructions: give them the entry state
        for off in order:
            if off not in stin:
                stin[off] = {"mode": 0, "d": 8, "s": 0, "rbp": None}
        self.stin = stin
        # prologue: from the entry, the run of frame-setup instructions
        self.prologue_end = None
        off = start
        seen_setup = False
        while off in insns:
            ins = insns[off]
            mn = ins.mn
            o0 = ins.ops[0] if ins.ops else None
            is_setup = (mn == "push" and o0.k == "reg") or \
                (mn == "sub" and o0.k == "reg" and o0.fam == "rsp" and ins.ops[1].k == "imm") or \
                (mn == "mov" and o0.k == "reg" and o0.fam == "rbp" and ins.ops[1].k == "reg" and ins.ops[1].fam == "rsp") or \
                (mn == "lea" and o0.k == "reg" and o0.fam == "rbp" and ins.ops[1].base == "rsp")
            if not is_setup:
                break
            seen_setup = True
            self.prologue_end = off
            off += ins.size
        if not seen_setup:
            self.prologue_end = None

    # ---- data sections ---------------------------------------------------------------------
    def emit_data(self, sec):
        o = self.o
        nm = sec.name
        if nm.startswith(".debug") or nm in (".pdata", ".xdata", ".drectve") or sec.chars & 0x800:
            return
        if sec.size == 0:
            return
        base = nm.split("$")[0]
        if sec.is_bss:
            self.out.append("")
            self.e(f'.section {base},"bw"' if base != ".bss" else ".bss")
        elif sec.writable:
            self.out.append("")
            self.e(f'.section {base},"dw"' if base != ".data" else ".data")
        else:
            self.out.append("")
            self.e(f'.section {base},"dr"')
        al = sec.align
        self.e(f".p2align {al.bit_length() - 1}")
        self.lab(f".Ls{sec.idx}")
        pubs = {}
        for (s, v), name in self.public_at.items():
            if s == sec.idx:
                pubs.setdefault(v, []).append(name)
        names = {}
        for (s, v), lst in self.sym_at.items():
            if s == sec.idx:
                names[v] = lst
        if sec.is_bss:
            cur = 0
            for v in sorted(set(list(pubs) + list(names))):
                if v > cur:
                    self.e(f".zero {v - cur}")
                    cur = v
                for p in pubs.get(v, []):
                    self.e(f".globl {p}")
                    self.lab(p)
                if v not in pubs and v in names:
                    self.out.append(f"    // {', '.join(names[v])}")
            if sec.size > cur:
                self.e(f".zero {sec.size - cur}")
            return
        data = sec.data
        rel = {ro: (rt, si) for ro, rt, si in sec.relocs}
        cur = 0
        run = []

        def flush():
            if run:
                for i in range(0, len(run), 16):
                    self.e(".byte " + ", ".join(f"{b:#04x}" for b in run[i:i + 16]))
                run.clear()

        n = len(data)
        while cur < n:
            if cur in pubs or cur in names:
                flush()
                for p in pubs.get(cur, []):
                    self.e(f".globl {p}")
                    self.lab(p)
                if cur not in pubs:
                    self.out.append(f"    // {', '.join(names[cur])}")
            if cur in rel:
                flush()
                rt, si = rel[cur]
                sym = o.symbols[si]
                if rt == "ADDR64":
                    addend = struct.unpack_from("<q", data, cur)[0]
                    self.e(f".quad {self.ref_text(self.symref(sym, addend))}")
                    cur += 8
                    continue
                if rt == "ADDR32NB":
                    addend = struct.unpack_from("<i", data, cur)[0]
                    ref = self.symref(sym, addend)
                    if ref[0] == "loc" and self.o.section(ref[1]).is_code:
                        txt = self.ref_text(ref, for_call=True)
                    else:
                        txt = self.ref_text(ref)
                    self.e(f".rva {txt}")
                    cur += 4
                    continue
                raise XlatError(f"data relocation {rt} in {nm}")
            run.append(data[cur])
            cur += 1
        flush()

    # =====================================================================================
    # instruction translation
    # =====================================================================================
    def translate_ins(self, ins):
        mn = ins.mn
        fn = getattr(self, "i_" + mn, None)
        if fn is None:
            if mn.startswith("cmov"):
                return self.i_cmov(ins)
            if mn.startswith("set"):
                return self.i_set(ins)
            if mn.startswith("j") and mn != "jmp":
                return self.i_jcc(ins)
            raise XlatError(f"unsupported instruction {mn}")
        return fn(ins)

    # -- flags helpers ----------------------------------------------------------------------
    def live(self, ins):
        return self.flags_live.get(ins.off, False)

    def small_shift(self, size):
        return 32 - 8 * size

    # -- data movement ------------------------------------------------------------------------
    def i_nop(self, ins):
        self.e("nop")

    def i_mov(self, ins):
        d, s = ins.ops
        if d.k == "reg" and d.fam == "rsp":
            return self.stack_mov_rsp(ins)
        if d.k == "reg" and d.fam == "rbp" and s.k == "reg" and s.fam == "rsp":
            st = self.st
            self.add_imm("x29", "sp", st["s"] - st["d"])
            if self.in_prologue:
                if st["s"] - st["d"] == 0:
                    self.e(".seh_set_fp")
                else:
                    self.e(f".seh_add_fp {st['s'] - st['d']}")
            return
        if d.k == "xmm" or s.k == "xmm":
            return self.i_movq_like(ins)
        if self.direct(d):
            if s.k == "imm" and s.sym is None:
                v = s.imm
                if d.size == 4:
                    self.movimm(self.regname(d), v & 0xFFFFFFFF, 32)
                else:
                    self.movimm(self.regname(d), v, 64)
                return
            if self.direct(s):
                if d.size == 8:
                    self.e(f"mov {self.regname(d)}, {self.regname(s)}")
                else:
                    self.e(f"mov {self.regname(d)}, {self.regname(s, 4)}")
                return
            if s.k == "mem":
                a = self.addr(s, s.size)
                self.e(f"ldr {self.regname(d)}, {a}")
                return
        if d.k == "mem" and s.k == "imm" and s.sym is None and (s.imm & ((1 << (8 * d.size)) - 1)) == 0:
            a = self.addr(d, d.size)
            st = {1: "strb wzr", 2: "strh wzr", 4: "str wzr", 8: "str xzr"}[d.size]
            self.e(f"{st}, {a}")
            return
        if d.k == "mem" and self.direct(s):
            a = self.addr(d, d.size)
            n = s.size
            r = self.regname(s, 8 if d.size == 8 else 4)
            st = {1: "strb", 2: "strh", 4: "str", 8: "str"}[d.size]
            self.e(f"{st} {r}, {a}")
            return
        v = self.rd(s, d.size if d.size >= 4 else 4)
        self.wr(d, v)

    def i_movabs(self, ins):
        return self.i_mov(ins)

    def i_movzx(self, ins):
        d, s = ins.ops
        if s.k == "mem":
            a = self.addr(s, s.size)
            ld = {1: "ldrb", 2: "ldrh"}[s.size]
            if d.size >= 4:
                self.e(f"{ld} {self.regname(d, 4)}, {a}")
                return
            t = self.scratch()
            self.e(f"{ld} w{t}, {a}")
            self.wr(d, f"w{t}")
            return
        v = self.rd(s, 4)
        if d.size >= 4:
            self.e(f"mov {self.regname(d, 4)}, {v}")
        else:
            self.wr(d, v)

    def i_movsx(self, ins):
        d, s = ins.ops
        v = self.rd(s, 8 if d.size == 8 else 4, sx=True)
        if d.size >= 4:
            self.e(f"mov {self.regname(d)}, {v if d.size == 8 else 'w' + v[1:]}")
        else:
            self.wr(d, v)

    def i_movsxd(self, ins):
        d, s = ins.ops
        if s.k == "mem":
            a = self.addr(s, 4)
            self.e(f"ldrsw {self.regname(d)}, {a}")
        else:
            self.e(f"sxtw {self.regname(d)}, {self.regname(s, 4)}")

    def i_lea(self, ins):
        d, m = ins.ops
        if d.fam == "rsp":
            return self.stack_lea_rsp(ins)
        if d.fam == "rbp" and m.base == "rsp" and not m.index:
            st = self.st
            v = m.disp + st["s"] - st["d"]
            self.add_imm("x29", "sp", v)
            if self.in_prologue:
                self.e(".seh_set_fp" if v == 0 else f".seh_add_fp {v}")
            return
        dst = self.regname(d, 8)
        if m.sym is not None:
            self.e(f"adrp {dst}, {self.ref_text(m.sym)}")
            self.e(f"add {dst}, {dst}, :lo12:{self.ref_text(m.sym)}")
            if m.index:
                self._add_index(dst, m)
        else:
            t = "x16"
            self._ea_into(m, t)
            self.e(f"mov {dst}, {t}")
        if d.size == 4:
            self.e(f"mov {self.regname(d, 4)}, {self.regname(d, 4)}")
        elif d.size == 2:
            raise XlatError("16-bit lea")

    def i_xchg(self, ins):
        a, b = ins.ops
        if a.k == "mem" or b.k == "mem":
            m, r = (a, b) if a.k == "mem" else (b, a)
            t = "x16"
            self._ea_mem(m, t)
            l1 = self.newlab()
            sz = m.size
            sfx = {1: "b", 2: "h", 4: "", 8: ""}[sz]
            rr = self.rd(r, 8 if sz == 8 else 4)
            regw = "x" if sz == 8 else "w"
            self.lab(l1)
            self.e(f"ldaxr{sfx} {regw}17, [{t}]")
            self.e(f"stlxr{sfx} w15, {regw}{rr[1:]}, [{t}]")
            self.e(f"cbnz w15, {l1}")
            self.wr(r, f"{regw}17")
            return
        if a.size == 8 and self.direct(a) and self.direct(b):
            self.e(f"mov x16, {self.regname(a)}")
            self.e(f"mov {self.regname(a)}, {self.regname(b)}")
            self.e(f"mov {self.regname(b)}, x16")
            return
        va = self.rd(a, 4 if a.size <= 4 else 8)
        vb = self.rd(b, 4 if b.size <= 4 else 8)
        # copy to fresh scratch because rd() may return the live register itself
        self.e(f"mov x16, x{va[1:]}")
        self.e(f"mov x17, x{vb[1:]}")
        self.wr(a, ("x" if a.size == 8 else "w") + "17")
        self.wr(b, ("x" if b.size == 8 else "w") + "16")

    def _ea_mem(self, m, t):
        if m.sym is not None:
            self.e(f"adrp {t}, {self.ref_text(m.sym)}")
            self.e(f"add {t}, {t}, :lo12:{self.ref_text(m.sym)}")
            if m.index:
                self._add_index(t, m)
        else:
            self._ea_into(m, t)

    # -- stack ops ---------------------------------------------------------------------------
    def i_push(self, ins):
        st0 = self.st
        st1 = self.stack_effect(ins, st0)
        src = ins.ops[0]
        prol = self.in_prologue
        if st0["mode"] == 0:
            # first lowering: sign lr, store it in the x64 return slot [A-8]
            self.e("pacibsp")
            if prol:
                self.e(".seh_pac_sign_lr")
            if src.k == "reg" and src.fam == "rbp" and st1["d"] == 16:
                self.e("stp x29, x30, [sp, #-16]!")
                if prol:
                    self.e(".seh_save_fplr_x 16")
                self.st = st1
                return
            self.e("sub sp, sp, #16")
            if prol:
                self.e(".seh_stackalloc 16")
            self.e("str x30, [sp, #8]")
            if prol:
                self.e(".seh_save_reg x30, 8")
            self.push_store(src, 0, prol and src.k == "reg")
            self.st = st1
            return
        grow = st1["s"] - st0["s"]
        if grow:
            self.e(f"sub sp, sp, #{grow}")
            if prol:
                self.e(f".seh_stackalloc {grow}")
        self.st = st1
        self.push_store(src, st1["s"] - st1["d"], prol and src.k == "reg")

    def push_store(self, src, off, seh):
        if src.k == "reg" and src.size == 8:
            n = FAM[src.fam]
            if n == "sp":
                raise XlatError("push rsp")
            self.e(f"str x{n}, [sp, #{off}]")
            if seh:
                if n in (19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29):
                    self.e(f".seh_save_reg x{n}, {off}")
                else:
                    self.e(".seh_nop")
            return
        v = self.rd(src, 8, sx=True)
        self.e(f"str {v}, [sp, #{off}]")

    def i_pop(self, ins):
        st0 = self.st
        st1 = self.stack_effect(ins, st0)
        d = ins.ops[0]
        off = st0["s"] - st0["d"]
        if d.k == "reg" and d.size == 8:
            self.e(f"ldr x{FAM[d.fam]}, [sp, #{off}]")
        else:
            self.e(f"ldr x16, [sp, #{off}]")
            self.wr(d, "x16")
        shrink = st0["s"] - st1["s"]
        if shrink:
            self.e(f"add sp, sp, #{shrink}")
        self.st = st1

    def stack_sub_add(self, ins):
        st0 = self.st
        st1 = self.stack_effect(ins, st0)
        prol = self.in_prologue
        if st0["mode"] == 0 and st1["mode"] == 1:
            self.e("pacibsp")
            if prol:
                self.e(".seh_pac_sign_lr")
            first = 16
            self.e("sub sp, sp, #16")
            if prol:
                self.e(".seh_stackalloc 16")
            self.e("str x30, [sp, #8]")
            if prol:
                self.e(".seh_save_reg x30, 8")
            delta = st1["s"] - 16
        else:
            delta = st1["s"] - st0["s"]
        self.sp_delta(delta, prol)
        self.st = st1

    def sp_delta(self, delta, prol):
        if delta > 0:
            rem = delta
            while rem:
                if rem > 0xFFF:
                    chunk = min(rem & ~0xFFF, 0xFFF000)
                else:
                    chunk = rem
                self.e(f"sub sp, sp, #{chunk:#x}")
                if prol:
                    self.e(f".seh_stackalloc {chunk}")
                rem -= chunk
        elif delta < 0:
            rem = -delta
            while rem:
                chunk = min(rem & ~0xFFF, 0xFFF000) if rem > 0xFFF else rem
                self.e(f"add sp, sp, #{chunk:#x}")
                rem -= chunk

    def stack_mov_rsp(self, ins):
        st0 = self.st
        st1 = self.stack_effect(ins, st0)
        # sp = x29 - (s1 - rbp_d)
        v = st1["s"] - st0["rbp"]
        if v == 0:
            self.e("mov sp, x29")
        else:
            self.e(f"sub sp, x29, #{v}")
        self.st = st1

    def stack_lea_rsp(self, ins):
        st0 = self.st
        st1 = self.stack_effect(ins, st0)
        m = ins.ops[1]
        if m.base == "rbp":
            v = st1["s"] - st0["rbp"]
            if v >= 0:
                self.e(f"sub sp, x29, #{v}")
            else:
                self.e(f"add sp, x29, #{-v}")
        else:
            self.sp_delta(st1["s"] - st0["s"], False)
        self.st = st1

    def i_leave(self, ins):
        st0 = self.st
        st1 = self.stack_effect(ins, st0)
        self.e("mov sp, x29")
        # rbp_d corresponds to s = a16(rbp_d)
        mid_s = self.a16(st0["rbp"])
        if mid_s != st0["rbp"]:
            self.e(f"sub sp, x29, #{mid_s - st0['rbp']}")
        self.e(f"ldr x29, [sp, #{mid_s - st0['rbp']}]")
        sh = mid_s - st1["s"]
        if sh:
            self.e(f"add sp, sp, #{sh}")
        self.st = st1

    def i_ret(self, ins):
        st = self.st
        if ins.ops:
            raise XlatError("ret imm")
        if st["d"] != 8:
            raise XlatError(f"ret with stack depth {st['d']}")
        self.emit_unwind_to_entry(st)
        self.e("ret")

    def emit_unwind_to_entry(self, st):
        if st["mode"] == 1:
            s = st["s"]
            self.e(f"ldr x30, [sp, #{s - 8}]")
            self.sp_delta(-s, False)
            self.e("autibsp")

    # -- calls --------------------------------------------------------------------------------------
    def call_kind(self, ins):
        """'internal' | 'api' and the ARM target text / register"""
        t = ins.target
        op = ins.ops[0]
        if t is not None:
            if t[0] == "local":
                return "internal", self.ref_text(("local", t[1]), for_call=True)
            if t[0] == "loc":
                return "internal", self.ref_text(t, for_call=True)
            name = t[1]
            if t[3] is not None or self.symtab.get(name) == "internal":
                return "internal", name + (f"+{t[2]}" if t[2] else "")
            return "api", name
        # indirect
        if op.k == "mem" and op.sym is not None and op.base is None and not op.index:
            ref = op.sym
            if ref[0] == "sym" and ref[3] is None and self.symtab.get(ref[1]) != "internal":
                # call [__imp_X] style
                nm = ref[1]
                if nm.startswith("__imp_"):
                    return "api", nm[6:]
        if self.is_guarded_call(ins):
            return "internal-ind", None
        return "api-ind", None

    def is_guarded_call(self, ins):
        """CALL_GUARDED pattern: mov r11, LP_MAGIC; cmp r11,[reg-8]; je ok; ...; ok: call reg"""
        op = ins.ops[0]
        if op.k != "reg":
            return False
        # look back through predecessors (the je target)
        for p in self.preds.get(ins.off, []):
            pi = self.insns[p]
            if pi.mn == "je":
                pp = [q for q in self.preds.get(p, [])]
                for q in pp:
                    qi = self.insns[q]
                    if qi.mn == "cmp" and qi.ops[1].k == "mem" and qi.ops[1].disp == -8 and \
                            qi.ops[1].base == op.fam:
                        return True
        return False

    def api_args(self, ins, name):
        """number of arguments for an API call site"""
        n = self.api_arity.get(name) if name else None
        # scan back in the block for stores to [rsp+32+8k]
        k_max = -1
        off = ins.off
        idx = self.order.index(off)
        for j in range(idx - 1, max(-1, idx - 60), -1):
            pi = self.insns[self.order[j]]
            if pi.mn == "call":
                break
            if pi.ops and pi.ops[0].k == "mem" and pi.ops[0].base == "rsp" and not pi.ops[0].index \
                    and pi.mn in ("mov", "movsd", "movq"):
                dsp = pi.ops[0].disp
                if dsp >= 32 and (dsp - 32) % 8 == 0:
                    k_max = max(k_max, (dsp - 32) // 8)
        site = 4 + k_max + 1 if k_max >= 0 else 0
        return max(n or 0, site)

    def sync_call(self):
        st = self.st
        if st["d"] % 16 != 0:
            raise XlatError(f"call with misaligned x64 stack (depth {st['d']})")
        if st["s"] != st["d"]:
            raise XlatError("internal: sp not synced at call")

    def i_call(self, ins):
        kind, tgt = self.call_kind(ins)
        self.sync_call()
        op = ins.ops[0]
        if kind == "internal":
            self.e(f"bl {tgt}")
            return
        if kind == "internal-ind":
            self.e(f"blr x{FAM[op.fam]}")
            return
        # API (direct or indirect)
        if kind == "api-ind":
            if op.k == "reg":
                treg = f"x{FAM[op.fam]}"
                if treg in ("x4", "x5", "x6", "x7"):
                    raise XlatError("call target clash")
            else:
                treg = "x17"
                v = self.rd(op, 8)
                self.e(f"mov x17, {v}")
            name = None
        else:
            treg = None
            name = tgt
        nargs = self.api_args(ins, name)
        if nargs == 0 and name is None:
            nargs = 8  # unknown indirect API: load all four register slots
        for i in range(4, min(nargs, 8)):
            pass
        if nargs > 4:
            regs = [4, 5, 6, 7][:max(0, min(nargs, 8) - 4)]
            i = 0
            while i < len(regs):
                if i + 1 < len(regs):
                    self.e(f"ldp x{regs[i]}, x{regs[i + 1]}, [sp, #{32 + 8 * i}]")
                    i += 2
                else:
                    self.e(f"ldr x{regs[i]}, [sp, #{32 + 8 * i}]")
                    i += 1
            for k in range(8, nargs):
                self.e(f"ldr x16, [sp, #{32 + 8 * (k - 4)}]")
                self.e(f"str x16, [sp, #{8 * (k - 8)}]")
        if treg:
            self.e(f"blr {treg}")
        else:
            self.e(f"bl {name}")
        self.e("mov x8, x0")

    def trap_target(self, t):
        if t is None:
            return None
        if t[0] == "sym" and t[1] in ("ff_trap", "sstk_overflow_fail") and t[2] == 0:
            return t[1]
        if t[0] == "local":
            nm = self.public_at.get((self.cur_sec, t[1]))
            if nm in ("ff_trap", "sstk_overflow_fail"):
                return nm
        return None

    def i_jmp(self, ins):
        t = ins.target
        st = self.st
        if t is not None and t[0] == "local" and t[1] in self.insns:
            self.e(f"b {self.clabel(t[1])}")
            return
        # noreturn trap jump (ff_trap, sstk_overflow_fail) may enter with any stack depth
        trap = self.trap_target(t)
        if trap:
            self.e(f"b {trap}")
            return
        # tail jump out of this proc
        if st["d"] != 8:
            raise XlatError("tail jump with stack depth != 8")
        op = ins.ops[0]
        if t is not None:
            kind, tgt = self.call_kind(ins)
            if kind != "internal":
                raise XlatError("tail jump to a Windows API")
            self.emit_unwind_to_entry(st)
            self.e(f"b {tgt}")
            return
        if op.k == "reg":
            r = f"x{FAM[op.fam]}"
            self.emit_unwind_to_entry(st)
            self.e(f"br {r}")
            return
        raise XlatError("indirect memory jump")

    # -- conditionals ---------------------------------------------------------------------------------
    def cond(self, ins, cc):
        k = self.cur_kind(ins)
        return arm_cond(cc, k)

    def i_jcc(self, ins):
        cc = cond_of(ins.mn)
        if cc in ("rcxz", "ecxz"):
            raise XlatError("jrcxz")
        c = self.cond(ins, cc)
        t = ins.target
        trap = self.trap_target(t)
        if trap:
            # external/intra-section noreturn trap: unconditional ±128 MiB `b` guarded by inverse `b.cond`
            tgt = trap
            if c == "never":
                return
            if c == "always":
                self.e(f"b {tgt}")
                return
            skip = self.newlab()
            if isinstance(c, tuple):
                how, c1, c2 = c
                go = self.newlab()
                if how == "or":
                    self.e(f"b.{c1} {go}")
                    self.e(f"b.{c2} {go}")
                    self.e(f"b {skip}")
                else:
                    self.e(f"b.{INV_ARM[c1]} {skip}")
                    self.e(f"b.{INV_ARM[c2]} {skip}")
                self.lab(go)
                self.e(f"b {tgt}")
                self.lab(skip)
            else:
                self.e(f"b.{INV_ARM[c]} {skip}")
                self.e(f"b {tgt}")
                self.lab(skip)
            return
        if t is None or t[0] != "local" or t[1] not in self.insns:
            raise XlatError("conditional jump out of proc")
        lab = self.clabel(t[1])
        if c == "never":
            return
        if c == "always":
            self.e(f"b {lab}")
            return
        if isinstance(c, tuple):
            how, c1, c2 = c
            if how == "or":
                self.e(f"b.{c1} {lab}")
                self.e(f"b.{c2} {lab}")
            else:  # and: taken iff c1 and c2
                skip = self.newlab()
                self.e(f"b.{INV_ARM[c1]} {skip}")
                self.e(f"b.{c2} {lab}")
                self.lab(skip)
            return
        self.e(f"b.{c} {lab}")

    def cset(self, ins, cc, reg):
        c = self.cond(ins, cc)
        if c == "never":
            self.e(f"mov {reg}, #0")
        elif c == "always":
            self.e(f"mov {reg}, #1")
        elif isinstance(c, tuple):
            how, c1, c2 = c
            self.e(f"cset {reg}, {c1}")
            self.e(f"cset w17, {c2}")
            self.e(f"{'orr' if how == 'or' else 'and'} {reg}, {reg}, w17")
        else:
            self.e(f"cset {reg}, {c}")

    def i_set(self, ins):
        cc = cond_of(ins.mn)
        self.cset(ins, cc, "w16")
        self.wr(ins.ops[0], "w16")

    def i_cmov(self, ins):
        cc = cond_of(ins.mn)
        d, s = ins.ops
        sz = d.size
        v = self.rd(s, sz)
        c = self.cond(ins, cc)
        dn = self.regname(d)
        if c == "always":
            self.e(f"mov {dn}, {v}")
            return
        if c == "never":
            if sz == 4:
                self.e(f"mov {dn}, {dn}")
            return
        if isinstance(c, tuple):
            self.cset(ins, cc, "w16")
            self.e("cmp w16, #0")   # NB: clobbers flags (only if not live afterwards)
            if self.live(ins):
                raise XlatError("compound cmov with live flags")
            c = "ne"
        self.e(f"csel {dn}, {v}, {dn}, {c}")

    # -- ALU -----------------------------------------------------------------------------------------------
    def alu_operands(self, ins):
        d, s = ins.ops[0], ins.ops[1]
        return d, s

    def imm_operand(self, s, size, kind):
        """returns '#imm' text if usable directly, else None"""
        if s.k != "imm" or s.sym is not None:
            return None
        v = s.imm & ((1 << (8 * size)) - 1)
        if kind == "addsub":
            if fits_addsub(v):
                return f"#{v:#x}"
            return None
        if kind == "logic":
            if is_bitmask_imm(v, 64 if size == 8 else 32):
                return f"#{v:#x}"
            return None
        return None

    def binop(self, ins, op_name, flag_op, kind):
        """generic dst = dst OP src with optional flags.
        op_name: add/sub/and/orr/eor ; flag_op: adds/subs/ands/None"""
        d, s = self.alu_operands(ins)
        sz = d.size
        live = self.live(ins)
        if sz >= 4:
            w = "x" if sz == 8 else "w"
            if self.direct(d):
                dn = self.regname(d)
                src_reg = dn
            else:
                src_reg = self.rd(d, sz)
                dn = src_reg
            ikind = "addsub" if op_name in ("add", "sub") else "logic"
            imm = self.imm_operand(s, sz, ikind)
            # negative immediates for add/sub
            if imm is None and s.k == "imm" and s.sym is None and op_name in ("add", "sub"):
                v = s64(s.imm) if sz == 8 else ((s.imm & 0xFFFFFFFF) - (1 << 32) if s.imm & 0x80000000 else s.imm & 0xFFFFFFFF)
                if v < 0 and fits_addsub(-v) and not live:
                    op_name = "sub" if op_name == "add" else "add"
                    imm = f"#{-v:#x}"
                    flag_op = None
            sv = imm if imm is not None else self.rd(s, sz)
            if s.k == "reg" and s.size < 4 and imm is None:
                pass
            use = flag_op if (live and flag_op) else op_name
            if sv.startswith("w") or sv.startswith("x"):
                sv = w + sv[1:]
            self.e(f"{use} {dn}, {src_reg}, {sv}")
            if live and not flag_op:
                self.e(f"tst {dn}, {dn}")
            if not self.direct(d):
                self.wr(d, dn)
            return
        # 8/16-bit
        a = self.rd(d, 4)
        b = self.rd(s, 4)
        if live and flag_op:
            sh = self.small_shift(sz)
            self.e(f"lsl w16, {a}, #{sh}")
            self.e(f"{flag_op} w16, w16, {b}, lsl #{sh}")
            self.e(f"lsr w16, w16, #{sh}")
        else:
            self.e(f"{op_name} w16, {a}, {b}")
            if live:
                sh = self.small_shift(sz)
                self.e(f"tst w16, #{((1 << (8 * sz)) - 1) << 0:#x}")
                # N must be the operand's sign bit: redo with the value shifted up
                self.e(f"lsl w17, w16, #{sh}")
                self.e("tst w17, w17")
        self.wr(d, "x16")

    def i_add(self, ins):
        if ins.ops[0].k == "reg" and ins.ops[0].fam == "rsp":
            return self.stack_sub_add(ins)
        self.binop(ins, "add", "adds", "add")

    def i_sub(self, ins):
        if ins.ops[0].k == "reg" and ins.ops[0].fam == "rsp":
            return self.stack_sub_add(ins)
        d, s = ins.ops
        if d.k == "reg" and s.k == "reg" and d.reg == s.reg and not self.live(ins):
            self.wr(d, "wzr" if d.size <= 4 else "xzr") if False else None
        self.binop(ins, "sub", "subs", "sub")

    def i_and(self, ins):
        if ins.ops[0].k == "reg" and ins.ops[0].fam == "rsp":
            # ARM64 sp is always 16-byte aligned (and st.d % 16 == 0 verified in stack_effect)
            return
        self.binop(ins, "and", "ands", "logic")

    def i_or(self, ins):
        self.binop(ins, "orr", None, "logic")

    def i_xor(self, ins):
        d, s = ins.ops
        if d.k == "reg" and s.k == "reg" and d.reg == s.reg:
            if d.size >= 4:
                self.e(f"mov {self.regname(d, 4)}, #0")
                if self.live(ins):
                    self.e(f"tst {self.regname(d, 4)}, {self.regname(d, 4)}")
                return
        if d.k == "xmm":
            return self.i_pxor(ins)
        self.binop(ins, "eor", None, "logic")

    def i_cmp(self, ins):
        d, s = ins.ops
        sz = d.size
        if not self.live(ins):
            return  # flags never read
        if sz >= 4:
            w = "x" if sz == 8 else "w"
            a = self.regname(d) if self.direct(d) else self.rd(d, sz)
            imm = self.imm_operand(s, sz, "addsub")
            if imm is not None:
                self.e(f"cmp {a}, {imm}")
                return
            if s.k == "imm" and s.sym is None:
                v = s64(s.imm) if sz == 8 else ((s.imm & 0xFFFFFFFF) - (1 << 32) if s.imm & 0x80000000 else s.imm)
                if v < 0 and fits_addsub(-v):
                    self.e(f"cmn {a}, #{-v:#x}")
                    return
            b = self.rd(s, sz)
            b = w + b[1:]
            self.e(f"cmp {a}, {b}")
            return
        a = self.rd(d, 4)
        b = self.rd(s, 4)
        sh = self.small_shift(sz)
        self.e(f"lsl w16, {a}, #{sh}")
        self.e(f"cmp w16, {b}, lsl #{sh}")

    def i_test(self, ins):
        d, s = ins.ops
        sz = d.size
        if not self.live(ins):
            return
        if sz >= 4:
            w = "x" if sz == 8 else "w"
            a = self.regname(d) if self.direct(d) else self.rd(d, sz)
            imm = self.imm_operand(s, sz, "logic")
            if imm is not None:
                self.e(f"tst {a}, {imm}")
                return
            if s.k == "reg" and d.k == "reg" and s.reg == d.reg:
                self.e(f"tst {a}, {a}")
                return
            b = self.rd(s, sz)
            self.e(f"tst {a}, {w}{b[1:]}")
            return
        a = self.rd(d, 4)
        if s.k == "reg" and d.k == "reg" and s.reg == d.reg:
            b = a
        else:
            b = self.rd(s, 4)
        sh = self.small_shift(sz)
        self.e(f"lsl w16, {a}, #{sh}")
        self.e(f"tst w16, {b}, lsl #{sh}")

    def i_inc(self, ins):
        self.incdec(ins, "add")

    def i_dec(self, ins):
        self.incdec(ins, "sub")

    def incdec(self, ins, op):
        d = ins.ops[0]
        live = self.live(ins)
        sz = d.size
        if sz >= 4:
            if self.direct(d):
                r = self.regname(d)
                self.e(f"{op}{'s' if live else ''} {r}, {r}, #1")
                return
            v = self.rd(d, sz)
            self.e(f"{op}{'s' if live else ''} {v}, {v}, #1")
            self.wr(d, v)
            return
        a = self.rd(d, 4)
        if live:
            sh = self.small_shift(sz)
            self.e(f"lsl w16, {a}, #{sh}")
            self.e(f"movz w17, #1, lsl #{sh}" if sh in (16,) else f"mov w17, #{1 << sh:#x}")
            self.e(f"{op}s w16, w16, w17")
            self.e(f"lsr w16, w16, #{sh}")
        else:
            self.e(f"{op} w16, {a}, #1")
        self.wr(d, "x16")

    def i_neg(self, ins):
        d = ins.ops[0]
        sz = d.size
        live = self.live(ins)
        if sz < 4:
            raise XlatError("8/16-bit neg")
        v = self.regname(d) if self.direct(d) else self.rd(d, sz)
        self.e(f"neg{'s' if live else ''} {v}, {v}")
        if not self.direct(d):
            self.wr(d, v)

    def i_not(self, ins):
        d = ins.ops[0]
        sz = d.size
        if sz >= 4:
            v = self.regname(d) if self.direct(d) else self.rd(d, sz)
            self.e(f"mvn {v}, {v}")
            if not self.direct(d):
                self.wr(d, v)
            return
        a = self.rd(d, 4)
        self.e(f"mvn w16, {a}")
        self.wr(d, "x16")

    def carry_to_add_polarity(self, ins):
        k = self.cur_kind(ins)
        if k == "add":
            return
        if k == "sub":
            self.e("cset w16, lo")
            self.e("cmp w16, #1")
            return
        if k == "logic":
            self.e("cmp wzr, #1")   # C = 0
            return
        raise XlatError(f"adc after {k}")

    def carry_to_sub_polarity(self, ins):
        k = self.cur_kind(ins)
        if k == "sub":
            return
        if k == "add":
            self.e("cset w16, hs")
            self.e("eor w16, w16, #1")
            self.e("cmp w16, #1")
            return
        if k == "logic":
            self.e("cmp wzr, #0")   # C = 1 (no borrow)
            return
        raise XlatError(f"sbb after {k}")

    def i_adc(self, ins):
        d, s = ins.ops
        sz = d.size
        if sz < 4:
            raise XlatError("8/16-bit adc")
        self.carry_to_add_polarity(ins)
        w = "x" if sz == 8 else "w"
        dv = self.regname(d) if self.direct(d) else self.rd(d, sz)
        if s.k == "imm" and s.sym is None and s.imm == 0:
            sv = f"{w}zr"
        else:
            sv = self.rd(s, sz)
            sv = w + sv[1:]
        self.e(f"adc{'s' if self.live(ins) else ''} {dv}, {dv}, {sv}")
        if not self.direct(d):
            self.wr(d, dv)

    def i_sbb(self, ins):
        d, s = ins.ops
        sz = d.size
        if sz < 4:
            raise XlatError("8/16-bit sbb")
        self.carry_to_sub_polarity(ins)
        w = "x" if sz == 8 else "w"
        dv = self.regname(d) if self.direct(d) else self.rd(d, sz)
        if s.k == "imm" and s.sym is None and s.imm == 0:
            sv = f"{w}zr"
        elif s.k == "reg" and d.k == "reg" and s.reg == d.reg:
            sv = dv
        else:
            sv = self.rd(s, sz)
            sv = w + sv[1:]
        self.e(f"sbc{'s' if self.live(ins) else ''} {dv}, {dv}, {sv}")
        if not self.direct(d):
            self.wr(d, dv)

    # shifts ---------------------------------------------------------------------------------------------
    def shift(self, ins, armop):
        d = ins.ops[0]
        cnt = ins.ops[1] if len(ins.ops) > 1 else Op("imm", imm=1, size=1)
        sz = d.size
        live = self.live(ins)
        if live:
            k = None
            # make sure nobody needs CF from a shift
            for off2 in self.flag_consumers(ins):
                c = canon_cc(cond_of(self.insns[off2].mn))
                if c not in ("e", "ne", "s", "ns"):
                    raise XlatError(f"flag {c} consumed after shift")
        if sz < 4:
            if armop in ("ror", "rol"):
                raise XlatError("8/16-bit rotate")
            a = self.rd(d, 4, sx=(armop == "asr"))
            if cnt.k == "imm":
                n = cnt.imm & 31
                self.e(f"{armop} w16, {a}, #{n}" if n else f"mov w16, {a}")
            else:
                self.e(f"and w17, w0, #31")
                self.e(f"{armop}v w16, {a}, w17")
            if live:
                self.e(f"lsl w17, w16, #{self.small_shift(sz)}")
                self.e("tst w17, w17")
            self.wr(d, "x16")
            return
        w = "x" if sz == 8 else "w"
        bits = 64 if sz == 8 else 32
        dv = self.regname(d) if self.direct(d) else self.rd(d, sz)
        if cnt.k == "imm":
            n = cnt.imm & (bits - 1)
            if n == 0:
                return
            if armop == "rol":
                self.e(f"ror {dv}, {dv}, #{bits - n}")
            else:
                self.e(f"{armop} {dv}, {dv}, #{n}")
        else:
            if armop == "rol":
                self.e("neg w17, w0")
                self.e(f"ror {dv}, {dv}, {w}17")
            else:
                self.e(f"{armop} {dv}, {dv}, {w}0")
        if live:
            self.e(f"tst {dv}, {dv}")
        if not self.direct(d):
            self.wr(d, dv)

    def flag_consumers(self, ins):
        res = []
        seen = set()
        work = list(self.succ[ins.off])
        while work:
            o = work.pop()
            if o in seen:
                continue
            seen.add(o)
            i2 = self.insns[o]
            r, w = self.ins_flags(i2)
            if r:
                res.append(o)
            if w:
                continue
            work.extend(self.succ[o])
        return res

    def i_shl(self, ins):
        self.shift(ins, "lsl")

    i_sal = i_shl

    def i_shr(self, ins):
        self.shift(ins, "lsr")

    def i_sar(self, ins):
        self.shift(ins, "asr")

    def i_ror(self, ins):
        if self.live(ins):
            raise XlatError("flags after ror")
        self.shift(ins, "ror")

    def i_rol(self, ins):
        if self.live(ins):
            raise XlatError("flags after rol")
        self.shift(ins, "rol")

    def i_bswap(self, ins):
        d = ins.ops[0]
        r = self.regname(d)
        self.e(f"rev {r}, {r}")

    def i_bsr(self, ins):
        d, s = ins.ops
        sz = d.size
        v = self.rd(s, sz)
        bits = 64 if sz == 8 else 32
        w = "x" if sz == 8 else "w"
        if self.live(ins):
            self.e(f"cmp {v}, #0")
        lab = self.newlab()
        # x64 leaves the destination unchanged when the source is zero
        self.e(f"cbz {v}, {lab}")
        self.e(f"clz {w}16, {v}")
        self.e(f"mov {w}17, #{bits - 1}")
        self.e(f"sub {w}16, {w}17, {w}16")
        self.wr(d, f"{w}16")
        self.lab(lab)

    def i_bt(self, ins):
        d, s = ins.ops
        if s.k != "imm":
            raise XlatError("bt with register bit index")
        sz = d.size
        v = self.rd(d, 8 if sz == 8 else 4)
        self.e(f"tst {v}, #{1 << (s.imm & (8 * sz - 1)):#x}")

    def i_bts(self, ins):
        d, s = ins.ops
        if s.k != "imm":
            raise XlatError("bts with register bit index")
        sz = d.size
        bit = s.imm & (8 * max(sz, 4) - 1)
        v = self.rd(d, 8 if sz == 8 else 4)
        if self.live(ins):
            self.e(f"tst {v}, #{1 << bit:#x}")
        self.e(f"orr {v}, {v}, #{1 << bit:#x}")
        self.wr(d, v)

    # multiply / divide ------------------------------------------------------------------------------------
    def i_imul(self, ins):
        ops = ins.ops
        live = self.live(ins)
        if len(ops) == 1:
            s = ops[0]
            sz = s.size
            v = self.rd(s, sz)
            if sz == 8:
                self.e(f"smulh x16, x8, {v}")
                self.e(f"mul x8, x8, {v}")
                self.e("mov x1, x16")
                if live:
                    self.e("cmp x1, x8, asr #63")
            elif sz == 4:
                self.e(f"smull x16, w8, {v}")
                self.e("mov w8, w16")
                self.e("lsr x1, x16, #32")
                self.e("mov w1, w1")
                if live:
                    self.e("cmp x16, w16, sxtw")
            else:
                raise XlatError("8/16-bit imul")
            return
        if len(ops) == 2:
            d, a, b = ops[0], ops[0], ops[1]
        else:
            d, a, b = ops
        sz = d.size
        if sz < 4:
            raise XlatError("16-bit imul")
        va = self.rd(a, sz)
        vb = self.rd(b, sz)
        if sz == 8:
            if live:
                self.e(f"smulh x16, {va}, {vb}")
                self.e(f"mul x17, {va}, {vb}")
                self.e("cmp x16, x17, asr #63")
                self.wr(d, "x17")
            else:
                self.e(f"mul x17, {va}, {vb}")
                self.wr(d, "x17")
        else:
            self.e(f"smull x16, {va}, {vb}")
            if live:
                self.e("cmp x16, w16, sxtw")
            self.wr(d, "w16")

    def i_mul(self, ins):
        s = ins.ops[0]
        sz = s.size
        v = self.rd(s, sz)
        if sz == 8:
            self.e(f"umulh x16, x8, {v}")
            self.e(f"mul x8, x8, {v}")
            self.e("mov x1, x16")
        elif sz == 4:
            self.e(f"umull x16, w8, {v}")
            self.e("mov w8, w16")
            self.e("lsr x1, x16, #32")
        else:
            raise XlatError("8/16-bit mul")
        if self.live(ins):
            self.e("cmp x1, #0")

    def rdx_known_zero(self, ins):
        idx = self.order.index(ins.off)
        for j in range(idx - 1, max(-1, idx - 40), -1):
            pi = self.insns[self.order[j]]
            if self.preds.get(self.order[j + 1]) and len(self.preds[self.order[j + 1]]) > 1:
                return False
            if pi.mn == "xor" and pi.ops[0].k == "reg" and pi.ops[0].fam == "rdx" and \
                    pi.ops[1].k == "reg" and pi.ops[1].fam == "rdx":
                return True
            if pi.mn == "mov" and pi.ops[0].k == "reg" and pi.ops[0].fam == "rdx" and \
                    pi.ops[1].k == "imm" and pi.ops[1].imm == 0 and pi.ops[0].size >= 4:
                return True
            if any(o.k == "reg" and o.fam == "rdx" for o in pi.ops[:1]) or pi.mn in ("call", "cqo", "cdq", "mul", "imul", "div", "idiv"):
                return False
        return False

    def i_div(self, ins):
        s = ins.ops[0]
        sz = s.size
        v = self.rd(s, sz)
        if sz == 8:
            if self.rdx_known_zero(ins):
                self.e(f"udiv x16, x8, {v}")
                self.e(f"msub x1, x16, {v}, x8")
                self.e("mov x8, x16")
                return
            # Full 128-by-64 unsigned division (x1:x8) / v -> x8=quot, x1=rem
            self.e(f"mov x16, {v}")
            l_slow, l_loop, l_sub, l_next, l_done = (self.newlab() for _ in range(5))
            self.e(f"cbnz x1, {l_slow}")
            self.e("udiv x15, x8, x16")
            self.e("msub x1, x15, x16, x8")
            self.e("mov x8, x15")
            self.e(f"b {l_done}")
            self.lab(l_slow)
            self.e("mov x11, x1")       # rem
            self.e("mov x12, x8")       # quot shift reg
            self.e("mov w13, #64")
            self.lab(l_loop)
            self.e("lsr x15, x11, #63")
            self.e("lsl x11, x11, #1")
            self.e("orr x11, x11, x12, lsr #63")
            self.e("lsl x12, x12, #1")
            self.e(f"cbnz x15, {l_sub}")
            self.e("cmp x11, x16")
            self.e(f"b.lo {l_next}")
            self.lab(l_sub)
            self.e("sub x11, x11, x16")
            self.e("orr x12, x12, #1")
            self.lab(l_next)
            self.e("subs w13, w13, #1")
            self.e(f"b.ne {l_loop}")
            self.e("mov x8, x12")
            self.e("mov x1, x11")
            self.lab(l_done)
            return
        if sz == 4:
            self.e("mov w16, w8")
            self.e("bfi x16, x1, #32, #32")
            self.e(f"mov w17, {v}")
            self.e("udiv x15, x16, x17")
            self.e("msub x16, x15, x17, x16")
            self.e("mov w8, w15")
            self.e("mov w1, w16")
            return
        raise XlatError("8/16-bit div")

    def i_idiv(self, ins):
        s = ins.ops[0]
        sz = s.size
        v = self.rd(s, sz)
        if sz == 8:
            idx = self.order.index(ins.off)
            prev = self.insns[self.order[idx - 1]] if idx else None
            if not prev or prev.mn != "cqo":
                raise XlatError("128/64-bit idiv without cqo")
            self.e(f"sdiv x16, x8, {v}")
            self.e(f"msub x1, x16, {v}, x8")
            self.e("mov x8, x16")
            return
        if sz == 4:
            self.e("mov w16, w8")
            self.e("bfi x16, x1, #32, #32")
            self.e(f"sxtw x17, {v}")
            self.e("sdiv x15, x16, x17")
            self.e("msub x16, x15, x17, x16")
            self.e("mov w8, w15")
            self.e("mov w1, w16")
            return
        raise XlatError("8/16-bit idiv")

    def i_cdq(self, ins):
        self.e("asr w1, w8, #31")

    def i_cqo(self, ins):
        self.e("asr x1, x8, #63")

    def i_cdqe(self, ins):
        self.e("sxtw x8, w8")

    def i_cwde(self, ins):
        self.e("sxth w8, w8")

    # misc --------------------------------------------------------------------------------------------------
    def i_int3(self, ins):
        self.e("brk #0xF000")

    def i_int(self, ins):
        if ins.ops[0].imm == 0x29:
            self.e("brk #0xF003            // __fastfail(x0)")
            return
        raise XlatError(f"int {ins.ops[0].imm:#x}")

    def i_pause(self, ins):
        self.e("yield")

    def i_mfence(self, ins):
        self.e("dmb ish")

    i_lfence = i_mfence
    i_sfence = i_mfence

    def i_rdtsc(self, ins):
        self.e("isb")
        self.e("mrs x16, cntvct_el0")
        self.e("mov w8, w16")
        self.e("lsr x1, x16, #32")

    def i_cmpxchg(self, ins):
        m, r = ins.ops
        if m.k != "mem":
            raise XlatError("cmpxchg reg")
        sz = m.size
        w = "x" if sz == 8 else "w"
        if sz not in (4, 8):
            raise XlatError("8/16-bit cmpxchg")
        t = "x16"
        self._ea_mem(m, t)
        rv = self.regname(r)
        l1, l2, l3 = self.newlab(), self.newlab(), self.newlab()
        self.lab(l1)
        self.e(f"ldaxr {w}17, [{t}]")
        self.e(f"cmp {w}17, {w}8")
        self.e(f"b.ne {l2}")
        self.e(f"stlxr w15, {rv}, [{t}]")
        self.e(f"cbnz w15, {l1}")
        self.e(f"b {l3}")
        self.lab(l2)
        self.e("clrex")
        self.e(f"mov {w}8, {w}17")
        self.lab(l3)

    def i_stosb(self, ins):
        self.rep_string(ins, "stos", 1)

    def i_stosd(self, ins):
        self.rep_string(ins, "stos", 4)

    def i_stosq(self, ins):
        self.rep_string(ins, "stos", 8)

    def i_movsb(self, ins):
        if ins.ops and ins.ops[0].k == "xmm":
            raise XlatError("movsb?")
        self.rep_string(ins, "movs", 1)

    def i_movsd(self, ins):
        if ins.ops and ins.ops[0].k in ("xmm",) or (len(ins.ops) == 2 and ins.ops[1].k == "xmm"):
            raise XlatError("SSE2 movsd")
        self.rep_string(ins, "movs", 4)

    def i_movsq(self, ins):
        self.rep_string(ins, "movs", 8)

    def rep_string(self, ins, kind, sz):
        sfx = {1: "b", 2: "h", 4: "", 8: ""}[sz]
        reg = {1: "w", 2: "w", 4: "w", 8: "x"}[sz]
        if not ins.rep:
            if kind == "stos":
                self.e(f"str{sfx} {reg}8, [x21], #{sz}")
            else:
                self.e(f"ldr{sfx} {reg}16, [x20], #{sz}")
                self.e(f"str{sfx} {reg}16, [x21], #{sz}")
            return
        top, done = self.newlab(), self.newlab()
        self.lab(top)
        self.e(f"cbz x0, {done}")
        if kind == "stos":
            self.e(f"str{sfx} {reg}8, [x21], #{sz}")
        else:
            self.e(f"ldr{sfx} {reg}16, [x20], #{sz}")
            self.e(f"str{sfx} {reg}16, [x21], #{sz}")
        self.e("sub x0, x0, #1")
        self.e(f"b {top}")
        self.lab(done)

    # -- SSE --------------------------------------------------------------------------------------------------
    def V(self, op):
        return f"v{op.xmm}"

    def vload(self, op, size, into=None):
        """load an xmm/m operand into a vector register; returns 'vN'"""
        if op.k == "xmm":
            return self.V(op)
        if op.k == "mem":
            r = into or "v16"
            pre = {4: "s", 8: "d", 16: "q"}[size]
            a = self.addr(op, size)
            self.e(f"ldr {pre}{r[1:]}, {a}")
            return r
        raise XlatError("bad vector operand")

    def vstore(self, op, vreg, size):
        pre = {4: "s", 8: "d", 16: "q"}[size]
        a = self.addr(op, size)
        self.e(f"str {pre}{vreg[1:]}, {a}")

    def i_movdqu(self, ins):
        d, s = ins.ops
        if d.k == "xmm" and s.k == "xmm":
            self.e(f"mov {self.V(d)}.16b, {self.V(s)}.16b")
        elif d.k == "xmm":
            self.vload(s, 16, into=self.V(d))
        else:
            self.vstore(d, self.V(s), 16)

    i_movdqa = i_movdqu
    i_movups = i_movdqu
    i_movaps = i_movdqu

    def i_pxor(self, ins):
        d, s = ins.ops
        if s.k == "xmm" and s.xmm == d.xmm:
            self.e(f"movi {self.V(d)}.2d, #0")
            return
        v = self.vload(s, 16)
        self.e(f"eor {self.V(d)}.16b, {self.V(d)}.16b, {v}.16b")

    i_xorps = i_pxor

    def i_por(self, ins):
        d, s = ins.ops
        v = self.vload(s, 16)
        self.e(f"orr {self.V(d)}.16b, {self.V(d)}.16b, {v}.16b")

    def i_movd(self, ins):
        d, s = ins.ops
        if d.k == "xmm":
            if s.k == "reg":
                self.e(f"fmov s{d.xmm}, {self.regname(s, 4)}")
            else:
                self.vload(s, 4, into=self.V(d))
        else:
            if d.k == "reg":
                self.e(f"fmov {self.regname(d, 4)}, s{s.xmm}")
            else:
                self.vstore(d, self.V(s), 4)

    def i_movq(self, ins):
        d, s = ins.ops
        if d.k == "xmm":
            if s.k == "reg":
                self.e(f"fmov d{d.xmm}, {self.regname(s, 8)}")
            elif s.k == "xmm":
                self.e(f"mov d{d.xmm}, {self.V(s)}.d[0]")
                self.e(f"fmov d{d.xmm}, d{d.xmm}")
            else:
                self.vload(s, 8, into=self.V(d))
        else:
            if d.k == "reg":
                self.e(f"fmov {self.regname(d, 8)}, d{s.xmm}")
            else:
                self.vstore(d, self.V(s), 8)

    def i_movq_like(self, ins):
        d, s = ins.ops
        raise XlatError("mov with xmm operand")

    def i_movss(self, ins):
        d, s = ins.ops
        if d.k == "xmm" and s.k == "xmm":
            self.e(f"mov {self.V(d)}.s[0], {self.V(s)}.s[0]")
        elif d.k == "xmm":
            self.vload(s, 4, into=self.V(d))
        else:
            self.vstore(d, self.V(s), 4)

    def fscalar(self, ins, op):
        d, s = ins.ops
        v = self.vload(s, 4)
        self.e(f"{op} s16, s{d.xmm}, s{v[1:]}")
        self.e(f"mov {self.V(d)}.s[0], v16.s[0]")

    def i_addss(self, ins):
        self.fscalar(ins, "fadd")

    def i_subss(self, ins):
        self.fscalar(ins, "fsub")

    def i_mulss(self, ins):
        self.fscalar(ins, "fmul")

    def i_divss(self, ins):
        self.fscalar(ins, "fdiv")

    def i_maxss(self, ins):
        self.fscalar(ins, "fmax")

    def i_minss(self, ins):
        self.fscalar(ins, "fmin")

    def i_sqrtss(self, ins):
        d, s = ins.ops
        v = self.vload(s, 4)
        self.e(f"fsqrt s16, s{v[1:]}")
        self.e(f"mov {self.V(d)}.s[0], v16.s[0]")

    def i_cvtsi2ss(self, ins):
        d, s = ins.ops
        v = self.rd(s, s.size)
        self.e(f"scvtf s16, {v}")
        self.e(f"mov {self.V(d)}.s[0], v16.s[0]")

    def i_cvttss2si(self, ins):
        d, s = ins.ops
        v = self.vload(s, 4)
        self.e(f"fcvtzs {self.regname(d)}, s{v[1:]}")

    def i_cvtss2si(self, ins):
        d, s = ins.ops
        v = self.vload(s, 4)
        self.e(f"fcvtns {self.regname(d)}, s{v[1:]}")

    def i_comiss(self, ins):
        d, s = ins.ops
        if not self.live(ins):
            return
        v = self.vload(s, 4)
        self.e(f"fcmp s{d.xmm}, s{v[1:]}")

    i_ucomiss = i_comiss

    def i_paddd(self, ins):
        d, s = ins.ops
        v = self.vload(s, 16)
        self.e(f"add {self.V(d)}.4s, {self.V(d)}.4s, {v}.4s")

    def i_paddusb(self, ins):
        d, s = ins.ops
        v = self.vload(s, 16)
        self.e(f"uqadd {self.V(d)}.16b, {self.V(d)}.16b, {v}.16b")

    def i_psrld(self, ins):
        d, s = ins.ops
        if s.k != "imm":
            raise XlatError("psrld by register")
        n = s.imm
        if n >= 32:
            self.e(f"movi {self.V(d)}.2d, #0")
        elif n:
            self.e(f"ushr {self.V(d)}.4s, {self.V(d)}.4s, #{n}")

    def i_pslld(self, ins):
        d, s = ins.ops
        if s.k != "imm":
            raise XlatError("pslld by register")
        n = s.imm
        if n >= 32:
            self.e(f"movi {self.V(d)}.2d, #0")
        elif n:
            self.e(f"shl {self.V(d)}.4s, {self.V(d)}.4s, #{n}")

    def i_pshufd(self, ins):
        d, s, im = ins.ops
        v = self.vload(s, 16, into="v17")
        if v != "v17":
            self.e(f"mov v17.16b, {v}.16b")
        for i in range(4):
            j = (im.imm >> (2 * i)) & 3
            self.e(f"mov {self.V(d)}.s[{i}], v17.s[{j}]")

    def i_pshufb(self, ins):
        d, s = ins.ops
        v = self.vload(s, 16)
        D = self.V(d)
        self.e("movi v18.16b, #0x8f")
        self.e(f"and v18.16b, {v}.16b, v18.16b")
        self.e(f"tbl {D}.16b, {{{D}.16b}}, v18.16b")

    def i_pmaddwd(self, ins):
        d, s = ins.ops
        v = self.vload(s, 16)
        D = self.V(d)
        self.e(f"smull v18.4s, {D}.4h, {v}.4h")
        self.e(f"smull2 v19.4s, {D}.8h, {v}.8h")
        self.e(f"addp {D}.4s, v18.4s, v19.4s")

    def i_packssdw(self, ins):
        d, s = ins.ops
        v = self.vload(s, 16)
        D = self.V(d)
        self.e(f"sqxtn v18.4h, {D}.4s")
        self.e(f"sqxtn2 v18.8h, {v}.4s")
        self.e(f"mov {D}.16b, v18.16b")

    def i_packuswb(self, ins):
        d, s = ins.ops
        v = self.vload(s, 16)
        D = self.V(d)
        self.e(f"sqxtun v18.8b, {D}.8h")
        self.e(f"sqxtun2 v18.16b, {v}.8h")
        self.e(f"mov {D}.16b, v18.16b")

    def i_punpcklbw(self, ins):
        d, s = ins.ops
        v = self.vload(s, 16)
        D = self.V(d)
        self.e(f"zip1 {D}.16b, {D}.16b, {v}.16b")

    def i_punpcklwd(self, ins):
        d, s = ins.ops
        v = self.vload(s, 16)
        D = self.V(d)
        self.e(f"zip1 {D}.8h, {D}.8h, {v}.8h")


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--obj", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--config", required=True, help="tools/a64/config.json")
    ap.add_argument("--symtab", required=True, help="json: all internal symbol names")
    ap.add_argument("--notes", default=None)
    a = ap.parse_args()
    mod = os.path.splitext(os.path.basename(a.obj))[0]
    with open(a.config) as f:
        cfg = json.load(f)
    with open(a.symtab) as f:
        symtab = json.load(f)
    obj = CoffObject(a.obj)
    mcfg = cfg.get("modules", {}).get(mod, {})
    notes = []
    tr = Translator(obj, mod, symtab, mcfg.get("override", []), mcfg.get("drop", []),
                    cfg.get("api_arity", {}), notes)
    lines = tr.run()
    with open(a.out, "w", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    if a.notes:
        with open(a.notes, "w") as f:
            f.write("\n".join(notes) + "\n")
    if tr.errors:
        for e in tr.errors:
            print("xlat:", e, file=sys.stderr)
        print(f"xlat: {mod}: {len(tr.errors)} error(s)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
