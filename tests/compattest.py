#!/usr/bin/env python3
"""Vaults written by a RELEASED Vordr still open, with the same contents.

tests/fixtures/v023-*.vordr were written by v0.2.3 (the WinGet release) and are
FROZEN: they are never regenerated, because a fixture rebuilt by today's code
proves only that today's writer agrees with today's reader.  Each one is pinned
here by its SHA-256 and by what it contains, and checked two ways on every run:

  * with Vordr's own reader (`vopen`, probeio/dbg build) - the users' existing
    vaults must keep opening, whatever the current code does to the format;
  * with the independent reader in tests/verify_vault.py - so a change that
    breaks both readers the same way is still noticed.

How they were made (do not redo it - add a NEW fixture for a new release):
  git worktree add --detach <tmp> v0.2.3; build.cmd probeio strict there, then
    vordr vaultexpattkat <dir>\\v023-att.vault  -> v023-attachments.vordr
                                                 (and its .ec child -> v023-export.vordr)
    vordr bktest <dir>\\v023-bk.vault           -> v023-m8mib.vordr
Passwords are the probes' fixed test passwords.

    python tests/compattest.py <vordr.exe>        exit 0 = every fixture checks out
"""
import hashlib, os, shutil, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_vault as vv

HERE = os.path.dirname(os.path.abspath(__file__))

# name: (sha256 of the file, password, vordr-opens, t, m, entries, titles, attachment sha256[:16]s)
FIXTURES = {
    'v023-attachments.vordr': (
        'dde7874e03ebae0b0a7485d0aecd24c8c67cab8bcdaa67c92b3a546c42d7688c', b'vordrtest', True,
        1, 8, 1, ['AttachTest'], ['90d4fc858a27b3b8', 'bb38863fb1ffb121']),
    'v023-export.vordr': (       # a native export: its own salt and key, password "exportpw2"
        'f78552a4935818e73a279e7e86ca9850ab603efda0a539fd3cdf4fb138fa9a11', b'exportpw2', False,
        1, 8, 1, ['AttachTest'], ['90d4fc858a27b3b8', 'bb38863fb1ffb121']),
    'v023-m8mib.vordr': (        # 8 MiB KDF memory: 2048-block segments
        '49515102dc59c3898fe4e3e182e5cbce372d954e38795f266e6dd79e4f47f977', b'vordrtest', True,
        1, 8192, 0, [], []),
}


def main():
    exe = os.path.abspath(sys.argv[1])
    work = tempfile.mkdtemp(prefix='vordr-compat-')
    fails = []

    def check(ok, what):
        print('  %s %s' % ('ok  ' if ok else 'FAIL', what), flush=True)
        if not ok:
            fails.append(what)

    try:
        for name, (sha, pw, vordr_opens, t, m, n, titles, atts) in FIXTURES.items():
            path = os.path.join(HERE, 'fixtures', name)
            data = open(path, 'rb').read()
            check(hashlib.sha256(data).hexdigest() == sha, '%s is the frozen file (sha256 pinned)' % name)
            try:
                v = vv.parse(data, pw)
                got_titles = [f[2].decode('utf-8', 'replace') for e in v['entries']
                              for f in e[1] if (f[0] & 0xFF) == 1]
                got_atts = sorted(hashlib.sha256(x).hexdigest()[:16] for x in v['attachments'].values())
                check((v['t'], v['m'], len(v['entries']), got_titles, got_atts) == (t, m, n, titles, atts),
                      '%s: independent reader - %d entr%s, %d attachment(s), as written by v0.2.3'
                      % (name, len(v['entries']), 'y' if len(v['entries']) == 1 else 'ies', len(got_atts)))
            except vv.Refused as e:
                check(False, '%s: independent reader refused it (%s)' % (name, e))
            if vordr_opens:
                copy = os.path.join(work, name)          # never let a probe touch the fixture
                shutil.copyfile(path, copy)
                p = subprocess.run([exe, 'vopen', copy], capture_output=True, timeout=120, cwd=work)
                out = p.stdout.decode('latin-1').strip()
                check(p.returncode == 0 and out.endswith('entries %d' % n),
                      '%s: today\'s Vordr opens it (%s)' % (name, out))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print('compattest: %s' % ('PASS (%d frozen v0.2.3 vaults)' % len(FIXTURES)
                              if not fails else '%d FAILURE(S)' % len(fails)))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
