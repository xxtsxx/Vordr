"""unit.py - call individual AArch64 routines under emulation (unicorn).

Used to test hand-written src/arm64/*.S routines in isolation, against the
Vordr internal ARM64 calling convention (docs/ARM64.md): x64 register meaning on
fixed ARM64 registers, args 1-4 in x0-x3, args 5+ at [sp+32+8*(n-5)], result in
x8.  Checks callee-saved registers (x19-x29, v8-v15 full 128 bits) and that the
routine never touches x18.

Workflow:
    clang --target=aarch64-pc-windows-msvc -march=armv8.2-a+crypto+sha3 -c f.S -o f.obj
    link /nologo /dll /noentry /machine:arm64 /nodefaultlib /export:sym ... /out:f.dll f.obj
    python:
        from unit import A64Unit
        u = A64Unit("f.dll")
        buf = u.alloc(64); u.write(buf, b"...")
        rax = u.call("sym", buf, 3)            # ints / addresses
        out = u.read(buf, 32)

The image is mapped at its preferred base (no base relocations needed).
"""
import struct
import pefile
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.arm64_const import *

PAGE = 0x1000
STACK_BASE = 0x7FF000000000
STACK_SIZE = 0x200000
HEAP_BASE = 0x7FE000000000
HEAP_SIZE = 0x08000000
RET_MAGIC = 0x7FFFFFFF0000

X = [UC_ARM64_REG_X0 + i for i in range(29)]  # x0..x28 are contiguous in unicorn
V = [UC_ARM64_REG_V0 + i for i in range(32)]


def _rup(n, a=PAGE):
    return (n + a - 1) & ~(a - 1)


class A64Unit:
    def __init__(self, dll_path, heap_size=HEAP_SIZE):
        self.pe = pefile.PE(dll_path)
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        try:  # "max" CPU: all ARMv8.x features (crypto, sha3, rng, pauth, lse)
            self.uc.ctl_set_cpu_model(UC_CPU_ARM64_MAX)
        except Exception:
            pass
        base = self.pe.OPTIONAL_HEADER.ImageBase
        size = _rup(self.pe.OPTIONAL_HEADER.SizeOfImage)
        self.base = base
        self.uc.mem_map(base, size)
        self.uc.mem_write(base, self.pe.get_memory_mapped_image()[:size])
        self.exports = {}
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for e in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if e.name:
                    self.exports[e.name.decode()] = base + e.address
        self.uc.mem_map(STACK_BASE, STACK_SIZE)
        self.uc.mem_map(HEAP_BASE, heap_size)
        self.uc.mem_map(RET_MAGIC, PAGE)
        self.heap_cur = HEAP_BASE
        self.heap_end = HEAP_BASE + heap_size
        # x18 = fake TEB pointer page (must not be modified by the routine)
        self.teb = self.alloc(0x2000)
        self.insn_count = 0

    # ---- memory helpers ---------------------------------------------------
    def alloc(self, n, align=64):
        p = (self.heap_cur + align - 1) & ~(align - 1)
        if p + n > self.heap_end:
            raise MemoryError("unit heap exhausted")
        self.heap_cur = p + n
        self.uc.mem_write(p, b"\0" * n)
        return p

    def write(self, addr, data):
        self.uc.mem_write(addr, bytes(data))

    def read(self, addr, n):
        return bytes(self.uc.mem_read(addr, n))

    def buf(self, data, extra=0):
        p = self.alloc(len(data) + extra)
        self.write(p, data)
        return p

    def sym(self, name):
        return self.exports[name]

    # ---- call -------------------------------------------------------------
    def call(self, fn, *args, check_abi=True, max_insn=0, fill=0x5A5A5A5A5A5A5A5A,
             vin=None):
        """Call fn (export name or address) with integer args; return x8 (rax).
        vin: optional dict {vreg_index: 16-byte value} preloaded before the call."""
        uc = self.uc
        addr = self.exports[fn] if isinstance(fn, str) else fn
        sp = STACK_BASE + STACK_SIZE - 0x1000
        nstack = max(0, len(args) - 4)
        frame = _rup(32 + 8 * nstack, 16)
        sp -= frame
        uc.mem_write(sp, b"\xCC" * frame)
        for i, a in enumerate(args[4:]):
            uc.mem_write(sp + 32 + 8 * i, struct.pack("<Q", a & 0xFFFFFFFFFFFFFFFF))
        # poison every GPR, set callee-saved sentinels
        sentinels = {}
        for i in range(29):
            uc.reg_write(X[i], fill ^ (i * 0x0101010101010101))
        for i in range(19, 29):
            sentinels[i] = 0x1900000000000000 | (i << 8) | i
            uc.reg_write(X[i], sentinels[i])
        uc.reg_write(UC_ARM64_REG_X18, self.teb)
        uc.reg_write(UC_ARM64_REG_X29, sentinels.get(29, 0x1D1D1D1D1D1D1D1D))
        vsent = {}
        for i in range(32):
            val = (0xA5 ^ i) * 0x01010101010101010101010101010101
            uc.reg_write(V[i], val)
            if 8 <= i <= 15:
                vsent[i] = val
        if vin:
            for k, val in vin.items():
                uc.reg_write(V[k], int.from_bytes(val, "little"))
        for i, a in enumerate(args[:4]):
            uc.reg_write(X[i], a & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(UC_ARM64_REG_SP, sp)
        uc.reg_write(UC_ARM64_REG_X30, RET_MAGIC)
        # enable FP/SIMD (CPACR_EL1.FPEN)
        try:
            uc.reg_write(UC_ARM64_REG_CPACR_EL1, 0x300000)
        except Exception:
            pass
        try:
            uc.emu_start(addr, RET_MAGIC, count=max_insn)
        except UcError as e:
            pc = uc.reg_read(UC_ARM64_REG_PC)
            raise RuntimeError(f"emulation fault {e} at pc={pc:#x} (rva {pc - self.base:#x})")
        pc = uc.reg_read(UC_ARM64_REG_PC)
        if pc != RET_MAGIC:
            raise RuntimeError(f"did not return (pc={pc:#x}); instruction cap hit?")
        if check_abi:
            if uc.reg_read(UC_ARM64_REG_SP) != sp:
                raise RuntimeError("sp not restored")
            if uc.reg_read(UC_ARM64_REG_X18) != self.teb:
                raise RuntimeError("x18 modified")
            for i, s in sentinels.items():
                got = uc.reg_read(X[i]) if i < 29 else uc.reg_read(UC_ARM64_REG_X29)
                if got != s:
                    raise RuntimeError(f"callee-saved x{i} clobbered ({got:#x})")
            for i, s in vsent.items():
                if uc.reg_read(V[i]) != s:
                    raise RuntimeError(f"callee-saved v{i} clobbered")
        return uc.reg_read(UC_ARM64_REG_X8)

    def vreg(self, i):
        return uc_to_bytes(self.uc.reg_read(V[i]))


def uc_to_bytes(v):
    return int(v).to_bytes(16, "little")
