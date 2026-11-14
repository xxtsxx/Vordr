#!/usr/bin/env python3
"""Fault injection: every memory-safety control fires with ITS OWN code, and a
plain fault is contained.

`vordr redteam <case>` (dbg builds only) commits exactly one violation.  Each case
must end the process with the exact fail-fast code of the control it targets.
The gate used to accept any 0xFADExxxx code - so "canary" would have passed if a
different control had caught it - and judged `iat` by 0xC0000409, which every
contained fault and every genuine fastfail also produce.

`crash` raises an ordinary access violation inside the image.  It must be
contained: the process ends by itself with 0xC0000409 (crash_contain's
TerminateProcess - a Windows Error Reporting dialog would hold it open), and
%TEMP%\\vordr_crash.bin names the fault: code 0xC0000005 at an address inside the
image.  The wipe itself cannot be seen from outside (the memory is gone with the
process); crash_dump writes the breadcrumb immediately before crash_contain wipes.

    python tests/redteam.py <dbg vordr.exe>        exit 0 = every case passed
"""
import ctypes, os, shutil, struct, subprocess, sys, tempfile

CASES = {                      # case -> exact exit code
    'canary':     0xFADE0002,  # FF_STACK_COOKIE
    'shadow':     0xFADEF001,  # FF_SHADOW_STACK
    'shadow_anc': 0xFADEF001,  # FF_SHADOW_STACK (ancestor-frame skip blocked)
    'dlpv':       0xFADE000A,  # FF_GUARD_ICALL
    'overflow':   0xFADEF005,  # FF_OVERFLOW
    'bounds':     0xFADEF004,  # FF_BOUNDS
    'typemagic':  0xFADEF003,  # FF_TYPE_MAGIC
    'heaptag':    0xFADEF002,  # FF_HEAP_TAG (via mem_alloc / mem_free)
    'heapmagic':  0xFADEF003,  # FF_TYPE_MAGIC (corrupt HEAPBLK.magic -> mem_free)
    'iat':        0xFADE1A70,  # FF_IAT_RO (rt_iat_veh)
}


def run(exe, case, timeout=30):
    try:
        p = subprocess.run([exe, 'redteam', case], capture_output=True, timeout=timeout)
        return p.returncode & 0xFFFFFFFF
    except subprocess.TimeoutExpired:
        return None


def main():
    exe = os.path.abspath(sys.argv[1])
    fails = []

    def check(ok, what):
        print('  %s %s' % ('ok  ' if ok else 'FAIL', what), flush=True)
        if not ok:
            fails.append(what)

    for case, want in CASES.items():
        # heaptag's canary is random; run the flaky-looking cases more than once
        reps = 3 if case in ('heaptag', 'iat') else 1
        for _ in range(reps):
            rc = run(exe, case)
            if rc != want:
                break
        check(rc == want, 'redteam %-11s -> %s (want 0x%08X)'
              % (case, 'timeout' if rc is None else '0x%08X' % rc, want))

    # where crash_dump writes it: GetTempPathW (TMP first), not tempfile's TEMP-first
    buf = ctypes.create_unicode_buffer(32768)
    ctypes.windll.kernel32.GetTempPathW(32768, buf)
    crumb = os.path.join(buf.value, 'vordr_crash.bin')
    if os.path.exists(crumb):
        os.remove(crumb)
    rc = run(exe, 'crash')
    check(rc is not None, 'redteam crash       -> ended by itself (no crash dialog held it open)')
    check(rc == 0xC0000409, 'redteam crash       -> 0x%08X (want 0xC0000409 from crash_contain)'
          % (rc or 0))
    check(os.path.exists(crumb), 'breadcrumb %s written' % crumb)
    if os.path.exists(crumb):
        b = open(crumb, 'rb').read()
        # release writes {code, addr, base} = 24 bytes; dbg (the only build with
        # `redteam`) appends ExceptionInformation[0..1] and 10 registers = 120
        check(len(b) in (24, 120), 'breadcrumb is 24 (release) or 120 (dbg) bytes (got %d)' % len(b))
        if len(b) >= 24:
            code, _pad, addr, base = struct.unpack('<IIQQ', b[:24])
            check(code == 0xC0000005, 'it names an access violation (0x%08X)' % code)
            check(base != 0 and base <= addr < base + 0x10000000,
                  'at an address inside the image (0x%X, base 0x%X)' % (addr, base))
        os.remove(crumb)

    # crash_reent: simulate a secondary fault while already inside crash handling;
    # must terminate immediately with 0xC0000409 (< 2s) and write no new breadcrumb.
    rc_re = run(exe, 'crash_reent', timeout=2)
    check(rc_re == 0xC0000409,
          'redteam crash_reent -> %s (want immediate 0xC0000409, no recursion)'
          % ('timeout' if rc_re is None else '0x%08X' % rc_re))
    check(not os.path.exists(crumb), 'crash_reent skipped crash_dump cleanly')
    if os.path.exists(crumb):
        os.remove(crumb)

    # dllhijack: place a corrupt wtsapi32.dll beside a temp copy of vordr.exe;
    # DependentLoadFlags = 0x0800 (LOAD_LIBRARY_SEARCH_SYSTEM32) must make the OS
    # loader resolve System32\wtsapi32.dll and ignore the application directory.
    tdir = tempfile.mkdtemp(prefix='vordr_dllgate_')
    try:
        texe = os.path.join(tdir, 'vordr.exe')
        shutil.copy2(exe, texe)
        with open(os.path.join(tdir, 'wtsapi32.dll'), 'wb') as f:
            f.write(b'NOT_A_VALID_PE_IMAGE_CANARY')
        p = subprocess.run([texe, 'selftest'], cwd=tdir, capture_output=True, timeout=30)
        check(p.returncode == 0,
              'dllhijack System32 load-config -> rc=%d (app-dir wtsapi32.dll ignored)'
              % p.returncode)
    finally:
        shutil.rmtree(tdir, ignore_errors=True)

    print('redteam: %s' % ('PASS (%d cases + crash/reent + dllhijack)' % len(CASES)
                           if not fails else '%d FAILURE(S)' % len(fails)))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
