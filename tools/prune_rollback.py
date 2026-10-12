#!/usr/bin/env python3
"""List (and, only when asked, remove) rollback-mirror entries that do not belong
to this machine's registered vault.

HKCU\\SOFTWARE\\Vordr\\Rollback holds one value per vault path Vordr has saved,
named by a hash of that path.  Until 2026-10-12 the test probes (seedtest, bktest,
rbtest ...) ran against the real HKCU and left one value per temporary test path
there, every run.  They are harmless counters, not secrets, but they accumulate.

This tool recomputes the names Vordr uses for YOUR vault - the registered path
(HKLM or HKCU "vault", environment variables expanded) and every default location
cfg_default_vault can pick (%OneDrive%\\Vordr, <Documents>\\Vordr, and the older
<Documents>\\vault.vordr) - in both forms
(the normalised name and the legacy as-typed one, see reg_hash_name in
src/regcfg.asm), and sorts every value into "yours" and "other".  "Other" also
covers any vault you deliberately opened at another path; removing its value only
means Vordr has no rollback history for that path until it is saved again.

    python tools\\prune_rollback.py            list only (changes nothing)
    python tools\\prune_rollback.py --delete   export a .reg backup, then remove
                                               the "other" values
"""
import ctypes, hashlib, os, subprocess, sys, tempfile, time, winreg
from ctypes import wintypes

KEY = r'SOFTWARE\Vordr\Rollback'


def name_for(path):
    """Vordr's value name for a path: SHA-256 of the UTF-16LE text, first 16 bytes, hex."""
    return hashlib.sha256(path.encode('utf-16-le')).digest()[:16].hex()


_k32 = ctypes.WinDLL('kernel32', use_last_error=True)
_u32 = ctypes.WinDLL('user32', use_last_error=True)
_k32.GetFullPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPWSTR, ctypes.c_void_p]
_u32.CharUpperBuffW.argtypes = [wintypes.LPWSTR, wintypes.DWORD]


def normalised(path):
    r"""reg_hash_name's normalisation, with the same Win32 calls: drop \\?\ (or
    \\?\UNC\), GetFullPathNameW, CharUpperBuffW (not str.upper, which folds some
    characters differently from the OS)."""
    p = path
    if p.startswith('\\\\?\\UNC\\'):
        p = '\\' + p[7:]
    elif p.startswith('\\\\?\\'):
        p = p[4:]
    buf = ctypes.create_unicode_buffer(32768)
    n = _k32.GetFullPathNameW(p, len(buf), buf, None)
    if n == 0 or n >= len(buf):
        return path                                   # Vordr hashes it as written then
    _u32.CharUpperBuffW(buf, n)
    return buf.value


def documents():
    r"""The real Documents folder (SHGetFolderPathW, CSIDL_PERSONAL) - it may be
    redirected, e.g. into OneDrive, so ~\Documents is not enough."""
    buf = ctypes.create_unicode_buffer(260)
    if ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf) == 0:
        return buf.value
    return os.path.join(os.path.expanduser('~'), 'Documents')


def registered_paths():
    out = []
    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(root, r'SOFTWARE\Vordr') as k:
                v, t = winreg.QueryValueEx(k, 'vault')
                if v and t == winreg.REG_EXPAND_SZ:
                    v = winreg.ExpandEnvironmentStrings(v)
                if v:
                    out.append(v)
        except OSError:
            pass
    # every default cfg_default_vault can choose, whichever this machine used
    od = os.environ.get('OneDrive')
    if od:
        out.append(os.path.join(od, 'Vordr', 'vault.vordr'))
    docs = documents()
    out.append(os.path.join(docs, 'Vordr', 'vault.vordr'))
    out.append(os.path.join(docs, 'vault.vordr'))
    return list(dict.fromkeys(out))


def main():
    delete = '--delete' in sys.argv[1:]
    mine = set()
    for p in registered_paths():
        mine.add(name_for(p))
        mine.add(name_for(normalised(p)))
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE)
    except OSError:
        print('no %s - nothing to do' % KEY)
        return 0
    names, i = [], 0
    while True:
        try:
            names.append(winreg.EnumValue(k, i)[0]); i += 1
        except OSError:
            break
    yours = [n for n in names if n.lower() in mine]
    other = [n for n in names if n.lower() not in mine]
    print('registered vault path(s): %s' % ', '.join(registered_paths()))
    print('%d value(s) under HKCU\\%s: %d yours, %d other' % (len(names), KEY, len(yours), len(other)))
    if not delete:
        print('list only - nothing changed.  Run with --delete to remove the "other" values '
              '(a .reg backup is written first).')
        return 0
    backup = os.path.join(tempfile.gettempdir(),
                          'vordr-rollback-backup-%s.reg' % time.strftime('%Y%m%d-%H%M%S'))
    subprocess.run(['reg', 'export', 'HKCU\\' + KEY, backup, '/y'], check=True, capture_output=True)
    print('backup: %s' % backup)
    for n in other:
        winreg.DeleteValue(k, n)
    print('removed %d value(s); kept %d' % (len(other), len(yours)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
