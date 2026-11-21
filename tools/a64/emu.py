"""emu.py - user-mode Windows ARM64 PE emulator for verifying bin/vordr-arm64.exe.

Maps a real linked ARM64 PE image at its preferred ImageBase with real section
permissions (including VirtualProtect RW->RO enforcement for IAT and _ROINIT),
sets up an ARM64 TEB in x18 (TlsSlots at +0x1480), intercepts IAT thunks to
emulate the Win32 CLI/file/crypto/registry APIs, and runs the binary from its
real entry point (`wstart`) through `ExitProcess`.

Usage:
    python tools/a64/emu.py bin/vordr-arm64.exe selftest
    python tools/a64/emu.py bin/vordr-arm64.exe genpw 24
"""
import ctypes
import os
import shlex
import struct
import sys
import time
from pathlib import Path

import pefile
from unicorn import (
    Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM,
    UC_HOOK_CODE, UC_PROT_NONE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
)
from unicorn.arm64_const import *

PAGE = 0x1000
STUB_BASE = 0x7FFE00000000
STUB_SIZE = 0x10000
STACK_BASE = 0x7FF000000000
STACK_SIZE = 0x400000
TEB_BASE = 0x7FFD00000000
TEB_SIZE = 0x4000
VM_BASE = 0x0000020000000000


def _rup(n, a=PAGE):
    return (n + a - 1) & ~(a - 1)


def _prot_from_win(fl):
    fl &= 0xFF
    if fl == 0x01:  # PAGE_NOACCESS
        return UC_PROT_NONE
    if fl == 0x02:  # PAGE_READONLY
        return UC_PROT_READ
    if fl in (0x04, 0x08):  # PAGE_READWRITE / WRITECOPY
        return UC_PROT_READ | UC_PROT_WRITE
    if fl == 0x20:  # PAGE_EXECUTE_READ
        return UC_PROT_READ | UC_PROT_EXEC
    if fl in (0x40, 0x80):
        return UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC
    return UC_PROT_READ | UC_PROT_WRITE


class Arm64PeEmu:
    def __init__(self, exe_path, argv, trace_api=False, feat_rng=True):
        self.exe_path = str(Path(exe_path).resolve())
        self.argv = list(argv)
        self.trace_api = trace_api
        self.feat_rng = feat_rng
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.exit_code = None
        self.terminated = False
        self.last_error = 0
        self.tls_next = 0
        self.vm_next = VM_BASE
        self.vm_allocs = {}          # base -> size
        self.local_allocs = {}
        self.handles = {}            # handle -> dict
        self.next_handle = 0x1000
        self.reg_keys = {}           # hkey -> path
        self.next_hkey = 0x2000
        self.api_calls = 0
        self.iat_locked = False
        self.roinit_locked = False

        self.pe = pefile.PE(self.exe_path)
        if self.pe.FILE_HEADER.Machine != 0xAA64:
            raise ValueError(f"{exe_path}: expected ARM64 (0xAA64), got {self.pe.FILE_HEADER.Machine:#x}")

        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        try:
            self.uc.ctl_set_cpu_model(UC_CPU_ARM64_MAX)
        except Exception:
            pass
        try:
            self.uc.reg_write(UC_ARM64_REG_CPACR_EL1, 0x300000)
        except Exception:
            pass

        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        img_sz = _rup(self.pe.OPTIONAL_HEADER.SizeOfImage)
        self.img_size = img_sz
        self.uc.mem_map(self.base, img_sz, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        raw_img = self.pe.get_memory_mapped_image()
        self.uc.mem_write(self.base, raw_img[:img_sz])

        # Apply strict section protections (headers R, .text RX, .rdata R, .data/_ROINIT RW)
        self.uc.mem_protect(self.base, PAGE, UC_PROT_READ)
        self.roinit_va = None
        for s in self.pe.sections:
            va = self.base + s.VirtualAddress
            sz = _rup(max(s.Misc_VirtualSize, s.SizeOfRawData))
            ch = s.Characteristics
            prot = 0
            if ch & 0x40000000:
                prot |= UC_PROT_READ
            if ch & 0x80000000:
                prot |= UC_PROT_WRITE
            if ch & 0x20000000:
                prot |= UC_PROT_EXEC
            self.uc.mem_protect(va, sz, prot)
            nm = s.Name.rstrip(b"\0").decode("ascii", "replace")
            if nm == "_ROINIT":
                self.roinit_va = va

        # Map stub page, stack, TEB
        self.uc.mem_map(STUB_BASE, STUB_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_write(STUB_BASE, b"\xc0\x03\x5f\xd6" * (STUB_SIZE // 4))  # ret
        self.uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_map(TEB_BASE, TEB_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        # Populate IAT with stub addresses
        self.stub_map = {}  # stub_addr -> (dll, name)
        idx = 0
        iat_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[12]
        self.iat_va = self.base + iat_dir.VirtualAddress if iat_dir.VirtualAddress else 0
        self.iat_sz = iat_dir.Size
        # Make IAT temporarily writable to bind imports (loader does this before entry)
        if self.iat_va and self.iat_sz:
            p0 = self.iat_va & ~(PAGE - 1)
            p1 = _rup(self.iat_va + self.iat_sz)
            self.uc.mem_protect(p0, p1 - p0, UC_PROT_READ | UC_PROT_WRITE)

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin-1")
            for imp in entry.imports:
                nm = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
                if dll.upper() == "COMCTL32.DLL":
                    if imp.ordinal == 410:
                        nm = "SetWindowSubclass"
                    elif imp.ordinal == 413:
                        nm = "DefSubclassProc"
                sa = STUB_BASE + idx * 4
                idx += 1
                self.stub_map[sa] = (dll, nm)
                self.uc.mem_write(imp.address, struct.pack("<Q", sa))

        # Pre-allocate command line UTF-16LE buffer
        cmdline = " ".join(f'"{a}"' if (" " in a or not a) else a for a in self.argv)
        self.cmdline_va = self._vm_alloc(len(cmdline) * 2 + 16, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_write(self.cmdline_va, (cmdline + "\0").encode("utf-16le"))

        self.uc.hook_add(UC_HOOK_CODE, self._on_stub, begin=STUB_BASE, end=STUB_BASE + STUB_SIZE - 1)

    def close(self):
        for h in list(self.handles.values()):
            if "fp" in h and h["fp"]:
                try:
                    h["fp"].close()
                except Exception:
                    pass
        self.handles.clear()
        self.pe.close()

    # ---- memory helpers ----------------------------------------------------
    def _vm_alloc(self, size, prot=UC_PROT_READ | UC_PROT_WRITE):
        sz = _rup(max(size, 1))
        addr = self.vm_next
        # leave a 64 KiB gap between allocations so overflows fault immediately
        self.vm_next = _rup(addr + sz + 0x10000, 0x10000)
        self.uc.mem_map(addr, sz, prot)
        self.vm_allocs[addr] = sz
        return addr

    def _read_wstr(self, addr, max_chars=32768):
        if not addr:
            return None
        out = bytearray()
        for off in range(0, max_chars * 2, 2):
            c = self.uc.mem_read(addr + off, 2)
            if c == b"\0\0":
                break
            out.extend(c)
        return out.decode("utf-16le", "surrogatepass")

    def _read_astr(self, addr, max_bytes=4096):
        if not addr:
            return None
        out = bytearray()
        for off in range(max_bytes):
            c = self.uc.mem_read(addr + off, 1)
            if c == b"\0":
                break
            out.extend(c)
        return out.decode("latin-1")

    def _r(self, i):
        return self.uc.reg_read(UC_ARM64_REG_X0 + i)

    def _w(self, i, val):
        self.uc.reg_write(UC_ARM64_REG_X0 + i, val & 0xFFFFFFFFFFFFFFFF)

    def _arg(self, idx):
        if idx < 8:
            return self._r(idx)
        sp = self.uc.reg_read(UC_ARM64_REG_SP)
        return struct.unpack("<Q", self.uc.mem_read(sp + 8 * (idx - 8), 8))[0]

    # ---- run ---------------------------------------------------------------
    def run(self, max_insn=0):
        entry = self.base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        sp = STACK_BASE + STACK_SIZE - 0x1000
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_X18, TEB_BASE)
        self.uc.reg_write(UC_ARM64_REG_X30, STUB_BASE + STUB_SIZE - 4)
        try:
            self.uc.emu_start(entry, STUB_BASE + STUB_SIZE - 4, count=max_insn)
        except UcError as e:
            if not self.terminated:
                pc = self.uc.reg_read(UC_ARM64_REG_PC)
                sp_now = self.uc.reg_read(UC_ARM64_REG_SP)
                x0 = self.uc.reg_read(UC_ARM64_REG_X0)
                x8 = self.uc.reg_read(UC_ARM64_REG_X8)
                lr = self.uc.reg_read(UC_ARM64_REG_X30)
                raise RuntimeError(
                    f"ARM64 fault: {e} at pc={pc:#x} (rva={pc-self.base:#x}), "
                    f"lr={lr:#x} (rva={lr-self.base:#x}), sp={sp_now:#x}, x0={x0:#x}, x8={x8:#x}"
                ) from e
        return self.exit_code

    # ---- Win32 API dispatcher ----------------------------------------------
    def _on_stub(self, uc, address, size, user_data):
        info = self.stub_map.get(address)
        if not info:
            self.terminated = True
            uc.emu_stop()
            return
        dll, name = info
        self.api_calls += 1
        sp = uc.reg_read(UC_ARM64_REG_SP)
        if sp & 15:
            raise RuntimeError(f"Unaligned sp={sp:#x} calling {dll}!{name}")
        if uc.reg_read(UC_ARM64_REG_X18) != TEB_BASE:
            raise RuntimeError(f"x18 corrupted before {dll}!{name}")
        if self.trace_api:
            print(f"  [API] {dll}!{name}({self._r(0):#x}, {self._r(1):#x}, {self._r(2):#x}, {self._r(3):#x})")

        fn = getattr(self, "api_" + name, None)
        if fn is None:
            raise NotImplementedError(f"Unimplemented Win32 API in emu.py: {dll}!{name}")
        ret = fn()
        if ret is not None:
            self._w(0, ret)

    # ---- Win32 implementations ---------------------------------------------
    def api_IsProcessorFeaturePresent(self):
        feat = self._r(0) & 0xFFFFFFFF
        return 1 if feat == 30 else 0  # PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE

    def api_RegOpenKeyExW(self):
        hkey = self._r(0)
        sub = self._read_wstr(self._r(1)) or ""
        phk = self._arg(4)
        su = sub.upper()
        if hkey == 0xFFFFFFFF80000002 and su in (
            r"HARDWARE\DESCRIPTION\SYSTEM\CENTRALPROCESSOR",
            r"HARDWARE\DESCRIPTION\SYSTEM\CENTRALPROCESSOR\0",
        ):
            hk = self.next_hkey
            self.next_hkey += 4
            self.reg_keys[hk] = "CENTRALPROCESSOR" if su.endswith("CENTRALPROCESSOR") else "CPU:0"
            self.uc.mem_write(phk, struct.pack("<Q", hk))
            return 0
        if self.reg_keys.get(hkey) == "CENTRALPROCESSOR" and su.isdigit():
            hk = self.next_hkey
            self.next_hkey += 4
            self.reg_keys[hk] = f"CPU:{su}"
            self.uc.mem_write(phk, struct.pack("<Q", hk))
            return 0
        return 2  # ERROR_FILE_NOT_FOUND

    def api_RegQueryValueExW(self):
        hk = self._r(0)
        val = self._read_wstr(self._r(1)) or ""
        ptype = self._r(3)
        pdata = self._arg(4)
        pcb = self._arg(5)
        if self.reg_keys.get(hk, "").startswith("CPU:") and val == "CP 4030":
            q = (1 << 60) if self.feat_rng else 0
            if ptype:
                self.uc.mem_write(ptype, struct.pack("<I", 11))  # REG_QWORD
            if pdata:
                self.uc.mem_write(pdata, struct.pack("<Q", q))
            if pcb:
                self.uc.mem_write(pcb, struct.pack("<I", 8))
            return 0
        return 2

    def api_RegCloseKey(self):
        self.reg_keys.pop(self._r(0), None)
        return 0

    def api_RegCreateKeyExW(self):
        phk = self._arg(7)
        hk = self.next_hkey
        self.next_hkey += 4
        self.reg_keys[hk] = "TEMP"
        if phk:
            self.uc.mem_write(phk, struct.pack("<Q", hk))
        return 0

    def api_RegSetValueExW(self):
        return 0

    def api_RegDeleteValueW(self):
        return 0

    def api_RegOverridePredefKey(self):
        return 0

    def api_CreateDirectoryW(self):
        p = self._read_wstr(self._r(0))
        try:
            os.makedirs(p, exist_ok=True)
            return 1
        except OSError:
            return 0

    def api_RemoveDirectoryW(self):
        p = self._read_wstr(self._r(0))
        try:
            os.rmdir(p)
            return 1
        except OSError:
            return 0

    def api_GetCurrentProcessId(self):
        return 4242

    def api_GetEnvironmentVariableW(self):
        self.last_error = 203  # ERROR_ENVVAR_NOT_FOUND
        return 0

    def api_GetTempPathW(self):
        cch = self._r(0) & 0xFFFFFFFF
        buf = self._r(1)
        p = os.environ.get("TEMP", r"C:\Windows\Temp")
        if not p.endswith("\\"):
            p += "\\"
        if len(p) + 1 > cch:
            return len(p) + 1
        self.uc.mem_write(buf, (p + "\0").encode("utf-16le"))
        return len(p)

    def api_SetFilePointerEx(self):
        h = self._r(0)
        dist = self._r(1)
        if dist >= (1 << 63):
            dist -= (1 << 64)
        pnew = self._r(2)
        meth = self._r(3) & 0xFFFFFFFF
        if h not in self.handles:
            return 0
        fp = self.handles[h]["fp"]
        fp.seek(dist, meth)
        if pnew:
            self.uc.mem_write(pnew, struct.pack("<Q", fp.tell()))
        return 1

    def api_BCryptGenRandom(self):
        buf = self._r(1)
        cb = self._r(2) & 0xFFFFFFFF
        if cb:
            self.uc.mem_write(buf, os.urandom(cb))
        return 0  # STATUS_SUCCESS

    def api_HeapSetInformation(self):
        return 1

    def api_SetDefaultDllDirectories(self):
        return 1

    def api_SetProcessMitigationPolicy(self):
        return 1

    def api_SetErrorMode(self):
        return 0

    def api_AddVectoredExceptionHandler(self):
        return 0xCAFE0001

    def api_SetUnhandledExceptionFilter(self):
        return 0

    def api_LoadLibraryExW(self):
        return 0  # optional DLLs (wer.dll etc.) safely absent

    def api_GetProcAddress(self):
        return 0

    def api_FreeLibrary(self):
        return 1

    def api_GetModuleHandleW(self):
        if self._r(0) == 0:
            return self.base
        return 0

    def api_TlsAlloc(self):
        idx = self.tls_next
        self.tls_next += 1
        return idx

    def api_TlsSetValue(self):
        idx = self._r(0) & 0xFFFFFFFF
        val = self._r(1)
        if idx >= 64:
            return 0
        self.uc.mem_write(TEB_BASE + 0x1480 + idx * 8, struct.pack("<Q", val))
        return 1

    def api_VirtualAlloc(self):
        addr = self._r(0)
        size = self._r(1)
        fl = self._r(3) & 0xFFFFFFFF
        if addr != 0:
            return addr
        return self._vm_alloc(size, _prot_from_win(fl))

    def api_VirtualFree(self):
        addr = self._r(0)
        sz = self.vm_allocs.pop(addr, None)
        if sz:
            self.uc.mem_unmap(addr, sz)
        return 1

    def api_VirtualProtect(self):
        addr = self._r(0)
        size = self._r(1)
        fl = self._r(2) & 0xFFFFFFFF
        pold = self._r(3)
        p0 = addr & ~(PAGE - 1)
        p1 = _rup(addr + max(size, 1))
        self.uc.mem_protect(p0, p1 - p0, _prot_from_win(fl))
        if pold:
            self.uc.mem_write(pold, struct.pack("<I", 0x04))
        if fl == 0x02:
            if self.iat_va and p0 <= self.iat_va < p1:
                self.iat_locked = True
            if self.roinit_va and p0 <= self.roinit_va < p1:
                self.roinit_locked = True
        return 1

    def api_VirtualLock(self):
        return 1

    def api_VirtualUnlock(self):
        return 1

    def api_GetCurrentProcess(self):
        return 0xFFFFFFFFFFFFFFFF

    def api_GetCurrentThreadId(self):
        return 4242

    def api_SetProcessWorkingSetSize(self):
        return 1

    def api_SetProcessWorkingSetSizeEx(self):
        return 1

    def api_GetProcessWorkingSetSizeEx(self):
        pmin, pmax, pflags = self._r(1), self._r(2), self._r(3)
        if pmin:
            self.uc.mem_write(pmin, struct.pack("<Q", 64 * 1024 * 1024))
        if pmax:
            self.uc.mem_write(pmax, struct.pack("<Q", 256 * 1024 * 1024))
        if pflags:
            self.uc.mem_write(pflags, struct.pack("<I", 0))
        return 1

    def api_GetCommandLineW(self):
        return self.cmdline_va

    def api_CommandLineToArgvW(self):
        pargc = self._r(1)
        n = len(self.argv)
        self.uc.mem_write(pargc, struct.pack("<i", n))
        # Pack pointer table + UTF-16 strings into one LocalAlloc block
        str_bytes = [(a + "\0").encode("utf-16le") for a in self.argv]
        total = n * 8 + sum(len(b) for b in str_bytes)
        va = self._vm_alloc(total, UC_PROT_READ | UC_PROT_WRITE)
        self.local_allocs[va] = total
        cur = va + n * 8
        for i, b in enumerate(str_bytes):
            self.uc.mem_write(va + i * 8, struct.pack("<Q", cur))
            self.uc.mem_write(cur, b)
            cur += len(b)
        return va

    def api_LocalFree(self):
        va = self._r(0)
        if va in self.local_allocs:
            self.local_allocs.pop(va)
            sz = self.vm_allocs.pop(va, None)
            if sz:
                self.uc.mem_unmap(va, sz)
        return 0

    def api_AttachConsole(self):
        return 1

    def api_GetStdHandle(self):
        h = self._r(0) & 0xFFFFFFFF
        if h == 0xFFFFFFF5:  # STD_OUTPUT_HANDLE (-11)
            return 0x10
        if h == 0xFFFFFFF4:  # STD_ERROR_HANDLE (-12)
            return 0x11
        if h == 0xFFFFFFF6:  # STD_INPUT_HANDLE (-10)
            return 0x12
        return 0xFFFFFFFFFFFFFFFF

    def api_GetConsoleMode(self):
        return 0  # redirected pipe -> WriteFile

    def api_SetConsoleOutputCP(self):
        return 1

    def api_SetConsoleCP(self):
        return 1

    def api_WriteFile(self):
        h = self._r(0)
        buf = self._r(1)
        n = self._r(2) & 0xFFFFFFFF
        pnw = self._r(3)
        data = bytes(self.uc.mem_read(buf, n)) if n else b""
        if h == 0x10:
            self.stdout.extend(data)
        elif h == 0x11:
            self.stderr.extend(data)
        elif h in self.handles:
            self.handles[h]["fp"].write(data)
        else:
            return 0
        if pnw:
            self.uc.mem_write(pnw, struct.pack("<I", len(data)))
        return 1

    def api_ReadFile(self):
        h = self._r(0)
        buf = self._r(1)
        n = self._r(2) & 0xFFFFFFFF
        pnr = self._r(3)
        if h not in self.handles:
            return 0
        data = self.handles[h]["fp"].read(n)
        if data:
            self.uc.mem_write(buf, data)
        if pnr:
            self.uc.mem_write(pnr, struct.pack("<I", len(data)))
        return 1

    def api_CreateFileW(self):
        path = self._read_wstr(self._r(0))
        access = self._r(1) & 0xFFFFFFFF
        disp = self._arg(4) & 0xFFFFFFFF
        mode = None
        if disp == 1:  # CREATE_NEW
            if os.path.exists(path):
                self.last_error = 80
                return 0xFFFFFFFFFFFFFFFF
            mode = "w+b"
        elif disp == 2:  # CREATE_ALWAYS
            mode = "w+b"
        elif disp == 3:  # OPEN_EXISTING
            if not os.path.exists(path):
                self.last_error = 2
                return 0xFFFFFFFFFFFFFFFF
            mode = "r+b" if (access & 0x40000000) else "rb"
        elif disp == 4:  # OPEN_ALWAYS
            mode = "r+b" if os.path.exists(path) else "w+b"
        else:
            return 0xFFFFFFFFFFFFFFFF
        try:
            fp = open(path, mode)
        except OSError:
            self.last_error = 5
            return 0xFFFFFFFFFFFFFFFF
        h = self.next_handle
        self.next_handle += 4
        self.handles[h] = {"fp": fp, "path": os.path.abspath(path)}
        return h

    def api_CloseHandle(self):
        h = self._r(0)
        ent = self.handles.pop(h, None)
        if ent and ent.get("fp"):
            ent["fp"].close()
        return 1

    def api_GetFileSizeEx(self):
        h = self._r(0)
        pout = self._r(1)
        if h not in self.handles:
            return 0
        fp = self.handles[h]["fp"]
        cur = fp.tell()
        fp.seek(0, 2)
        sz = fp.tell()
        fp.seek(cur)
        self.uc.mem_write(pout, struct.pack("<Q", sz))
        return 1

    def api_GetFileType(self):
        return 1  # FILE_TYPE_DISK

    def api_GetFileInformationByHandle(self):
        h = self._r(0)
        pinfo = self._r(1)
        if h not in self.handles:
            return 0
        st = os.stat(self.handles[h]["path"])
        buf = bytearray(52)
        struct.pack_into("<I", buf, 0, 0x20)  # FILE_ATTRIBUTE_ARCHIVE (not reparse)
        struct.pack_into("<I", buf, 32, st.st_size >> 32)
        struct.pack_into("<I", buf, 36, st.st_size & 0xFFFFFFFF)
        struct.pack_into("<I", buf, 40, 1)    # nNumberOfLinks = 1
        self.uc.mem_write(pinfo, bytes(buf))
        return 1

    def api_GetFinalPathNameByHandleW(self):
        h = self._r(0)
        buf = self._r(1)
        cch = self._r(2) & 0xFFFFFFFF
        if h not in self.handles:
            return 0
        p = "\\\\?\\" + self.handles[h]["path"]
        if len(p) + 1 > cch:
            return len(p) + 1
        self.uc.mem_write(buf, (p + "\0").encode("utf-16le"))
        return len(p)

    def api_FlushFileBuffers(self):
        h = self._r(0)
        if h in self.handles:
            self.handles[h]["fp"].flush()
        return 1

    def api_DeleteFileW(self):
        p = self._read_wstr(self._r(0))
        try:
            os.remove(p)
            return 1
        except OSError:
            return 0

    def api_MoveFileExW(self):
        src = self._read_wstr(self._r(0))
        dst = self._read_wstr(self._r(1))
        try:
            os.replace(src, dst)
            return 1
        except OSError:
            return 0

    def api_ReplaceFileW(self):
        dst = self._read_wstr(self._r(0))
        src = self._read_wstr(self._r(1))
        try:
            os.replace(src, dst)
            return 1
        except OSError:
            return 0

    def api_GetFileAttributesW(self):
        p = self._read_wstr(self._r(0))
        if not os.path.exists(p):
            return 0xFFFFFFFF
        return 0x10 if os.path.isdir(p) else 0x20

    def api_GetFullPathNameW(self):
        p = os.path.abspath(self._read_wstr(self._r(0)) or "")
        cch = self._r(1) & 0xFFFFFFFF
        buf = self._r(2)
        if len(p) + 1 > cch:
            return len(p) + 1
        self.uc.mem_write(buf, (p + "\0").encode("utf-16le"))
        return len(p)

    def api_GetDiskFreeSpaceExW(self):
        pfree = self._r(1)
        if pfree:
            self.uc.mem_write(pfree, struct.pack("<Q", 64 * 1024 * 1024 * 1024))
        return 1

    def api_GetDriveTypeW(self):
        return 3  # DRIVE_FIXED

    def api_SetEndOfFile(self):
        h = self._r(0)
        if h not in self.handles:
            return 0
        fp = self.handles[h]["fp"]
        fp.truncate()
        return 1

    def api_SetFileAttributesW(self):
        return 1

    def api_GetLastError(self):
        return self.last_error

    def api_GetSystemTimeAsFileTime(self):
        p = self._r(0)
        ft = int((time.time() + 11644473600) * 10_000_000)
        self.uc.mem_write(p, struct.pack("<Q", ft))
        return 0

    def api_QueryPerformanceCounter(self):
        self.uc.mem_write(self._r(0), struct.pack("<Q", time.perf_counter_ns()))
        return 1

    def api_QueryPerformanceFrequency(self):
        self.uc.mem_write(self._r(0), struct.pack("<Q", 1_000_000_000))
        return 1

    def api_GetTickCount(self):
        return int(time.monotonic() * 1000) & 0xFFFFFFFF

    def api_WideCharToMultiByte(self):
        wptr = self._r(2)
        wlen = self._r(3) & 0xFFFFFFFF
        mbptr = self._arg(4)
        mbcap = self._arg(5) & 0xFFFFFFFF
        if wlen == 0xFFFFFFFF:
            s = self._read_wstr(wptr) + "\0"
        else:
            s = bytes(self.uc.mem_read(wptr, wlen * 2)).decode("utf-16le", "strict")
        try:
            enc = s.encode("utf-8")
        except UnicodeEncodeError:
            self.last_error = 1113
            return 0
        if mbcap == 0:
            return len(enc)
        if len(enc) > mbcap:
            self.last_error = 122
            return 0
        self.uc.mem_write(mbptr, enc)
        return len(enc)

    def api_MultiByteToWideChar(self):
        mbptr = self._r(2)
        mblen = self._r(3) & 0xFFFFFFFF
        wptr = self._arg(4)
        wcap = self._arg(5) & 0xFFFFFFFF
        if mblen == 0xFFFFFFFF:
            raw = self._read_astr(mbptr).encode("latin-1") + b"\0"
        else:
            raw = bytes(self.uc.mem_read(mbptr, mblen))
        try:
            s = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            self.last_error = 1113
            return 0
        enc = s.encode("utf-16le")
        nchars = len(enc) // 2
        if wcap == 0:
            return nchars
        if nchars > wcap:
            self.last_error = 122
            return 0
        self.uc.mem_write(wptr, enc)
        return nchars

    def api_ExitProcess(self):
        self.exit_code = self._r(0) & 0xFFFFFFFF
        self.terminated = True
        self.uc.emu_stop()
        return 0

    def api_TerminateProcess(self):
        self.exit_code = self._r(1) & 0xFFFFFFFF
        self.terminated = True
        self.uc.emu_stop()
        return 1

    def api_Sleep(self):
        return 0

    def api_CharUpperBuffW(self):
        ptr = self._r(0)
        cch = self._r(1) & 0xFFFFFFFF
        if not ptr or cch == 0:
            return 0
        raw = bytearray(self.uc.mem_read(ptr, cch * 2))
        for i in range(cch):
            u = struct.unpack_from("<H", raw, i * 2)[0]
            up = chr(u).upper()
            if len(up) == 1 and ord(up) <= 0xFFFF:
                struct.pack_into("<H", raw, i * 2, ord(up))
        self.uc.mem_write(ptr, bytes(raw))
        return cch

    def api_CharLowerBuffW(self):
        ptr = self._r(0)
        cch = self._r(1) & 0xFFFFFFFF
        if not ptr or cch == 0:
            return 0
        raw = bytearray(self.uc.mem_read(ptr, cch * 2))
        for i in range(cch):
            u = struct.unpack_from("<H", raw, i * 2)[0]
            lo = chr(u).lower()
            if len(lo) == 1 and ord(lo) <= 0xFFFF:
                struct.pack_into("<H", raw, i * 2, ord(lo))
        self.uc.mem_write(ptr, bytes(raw))
        return cch

    def api_OpenProcessToken(self):
        phtok = self._r(2)
        if phtok:
            self.uc.mem_write(phtok, struct.pack("<Q", 0x5000))
        return 1

    def api_GetTokenInformation(self):
        pbuf = self._r(2)
        pret = self._arg(4)
        if pbuf:
            # TOKEN_USER: { PSID Sid; DWORD Attributes; } followed by dummy SID
            self.uc.mem_write(pbuf, struct.pack("<QII", pbuf + 16, 0, 0) + b"\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00")
        if pret:
            self.uc.mem_write(pret, struct.pack("<I", 28))
        return 1

    def api_InitializeAcl(self):
        return 1

    def api_AddAccessAllowedAceEx(self):
        return 1

    def api_InitializeSecurityDescriptor(self):
        return 1

    def api_SetSecurityDescriptorDacl(self):
        return 1

    def api_SetSecurityDescriptorControl(self):
        return 1

    def api_AddMandatoryAce(self):
        return 1

    def api_SetSecurityDescriptorSacl(self):
        return 1

    def api_CopyFileW(self):
        import shutil
        src = self._read_wstr(self._r(0))
        dst = self._read_wstr(self._r(1))
        fail_exists = self._r(2) & 0xFFFFFFFF
        if fail_exists and os.path.exists(dst):
            self.last_error = 80
            return 0
        try:
            shutil.copyfile(src, dst)
            return 1
        except OSError:
            self.last_error = 5
            return 0

    def api_GetNamedSecurityInfoW(self):
        ppdacl = self._arg(5)
        ppsd = self._arg(7)
        sd_va = self._vm_alloc(64, UC_PROT_READ | UC_PROT_WRITE)
        self.local_allocs[sd_va] = 64
        if ppdacl:
            self.uc.mem_write(ppdacl, struct.pack("<Q", sd_va + 32))
        if ppsd:
            self.uc.mem_write(ppsd, struct.pack("<Q", sd_va))
        return 0  # ERROR_SUCCESS

    def api_GetSecurityDescriptorControl(self):
        pctrl = self._r(1)
        prev = self._r(2)
        if pctrl:
            self.uc.mem_write(pctrl, struct.pack("<H", 0x1004))  # SE_DACL_PROTECTED | SE_DACL_PRESENT
        if prev:
            self.uc.mem_write(prev, struct.pack("<I", 1))
        return 1

    def api_SetNamedSecurityInfoW(self):
        return 0  # ERROR_SUCCESS

    def api_GetSecurityInfo(self):
        ppdacl = self._arg(5)
        ppsd = self._arg(7)
        sd_va = self._vm_alloc(64, UC_PROT_READ | UC_PROT_WRITE)
        self.local_allocs[sd_va] = 64
        if ppdacl:
            self.uc.mem_write(ppdacl, struct.pack("<Q", sd_va + 32))
        if ppsd:
            self.uc.mem_write(ppsd, struct.pack("<Q", sd_va))
        return 0  # ERROR_SUCCESS

    def api_SetSecurityInfo(self):
        return 0  # ERROR_SUCCESS

    def api_AcquireSRWLockExclusive(self):
        return 0

    def api_ReleaseSRWLockExclusive(self):
        return 0

    def api_GetModuleFileNameW(self):
        buf = self._r(1)
        cch = self._r(2) & 0xFFFFFFFF
        name = os.path.abspath(self.pe_path)
        if cch == 0:
            return 0
        out = name[:cch - 1]
        self.uc.mem_write(buf, (out + "\0").encode("utf-16le"))
        return len(out)

    def api_GetCurrentDirectoryW(self):
        cch = self._r(0) & 0xFFFFFFFF
        buf = self._r(1)
        p = os.getcwd()
        if len(p) + 1 > cch:
            return len(p) + 1
        self.uc.mem_write(buf, (p + "\0").encode("utf-16le"))
        return len(p)

    def api_RegEnumValueW(self):
        return 259  # ERROR_NO_MORE_ITEMS

    def api_RegEnumKeyExW(self):
        hk = self._r(0)
        idx = self._r(1) & 0xFFFFFFFF
        lpname = self._r(2)
        lpcch = self._r(3)
        if self.reg_keys.get(hk) == "CENTRALPROCESSOR" and idx in (0, 1):
            nm = str(idx)
            cap = struct.unpack("<I", self.uc.mem_read(lpcch, 4))[0] if lpcch else 0
            if cap <= len(nm):
                return 234  # ERROR_MORE_DATA
            self.uc.mem_write(lpname, (nm + "\0").encode("utf-16le"))
            self.uc.mem_write(lpcch, struct.pack("<I", len(nm)))
            return 0
        return 259  # ERROR_NO_MORE_ITEMS

    def api_ExpandEnvironmentStringsW(self):
        src = self._read_wstr(self._r(0)) or ""
        dst = self._r(1)
        cch = self._r(2) & 0xFFFFFFFF
        exp = os.path.expandvars(src)
        if len(exp) + 1 > cch:
            return len(exp) + 1
        self.uc.mem_write(dst, (exp + "\0").encode("utf-16le"))
        return len(exp) + 1


def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/a64/emu.py [--trace] <arm64.exe> [args...]")
        return 2
    args = sys.argv[1:]
    trace = False
    if args[0] == "--trace":
        trace = True
        args = args[1:]
    exe = args[0]
    emu = Arm64PeEmu(exe, args, trace_api=trace)
    try:
        rc = emu.run()
        out = emu.stdout.decode("utf-8", "replace")
        err = emu.stderr.decode("utf-8", "replace")
        if out:
            sys.stdout.write(out)
        if err:
            sys.stderr.write(err)
        print(f"[emu] exit={rc} api_calls={emu.api_calls} iat_ro={emu.iat_locked} roinit_ro={emu.roinit_locked}")
        return rc if rc is not None else 1
    finally:
        emu.close()


if __name__ == "__main__":
    sys.exit(main())
