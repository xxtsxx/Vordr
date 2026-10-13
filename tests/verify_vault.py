#!/usr/bin/env python3
"""Decrypt Vordr vault files with an implementation that shares nothing with Vordr.

Every other vault test reads a file back with Vordr's own reader, and a writer
and a reader that make the same mistake agree perfectly - a round trip cannot see
it.  This one cannot share a mistake: Argon2id is written here from RFC 9106 (and
checked against the RFC's own vector before it is trusted), AES-GCM is
verify_crypto.py's pure-Python one (checked against NIST's vector the same way),
BLAKE2b is hashlib, and the layout is taken from docs/formats.md
and nothing else.  If Vordr and its published format part company - the AAD, the
KCV, the body/attachment split, the attachment AAD, the file MAC's inputs - this
fails, whichever side moved.  It is also the proof that a user can get their data
out of a .vordr file without Vordr.  (Ported from Myrkr's indepdecrypttest.py; on
its first run there it found that Myrkr's Argon2id was not RFC 9106.)

Checked, against fixtures the probe build writes (`vattgen`, `bktest`):
  * an 8 KiB-memory vault with two attachments: header, KCV, body, every
    attachment, the file MAC, the save counter (1 after the first write);
  * its .bak1..3 (earlier saves): same salt and key, a DIFFERENT body nonce on
    every save - GCM must never see one key with one nonce twice;
  * an 8 MiB-memory vault (2048-block segments): the address-block regeneration
    past i = 128 that every real vault uses, through the KCV;
  * the wrong password is refused (KCV), here and by Vordr;
  * a byte flipped in each region of the file - header fields, salt, nonce, KCV,
    body, body tag, an attachment's id/length/ciphertext/tag, the VATT footer, the
    counter, the MAC, the VMAC marker - is refused by Vordr's own reader (`vopen`)
    AND by this one.

Needs a probeio or dbg build (`vattgen`, `bktest` and `vopen` are test verbs).

    python tests/verify_vault.py <vordr.exe>        exit 0 = every check passed
"""
import hashlib, hmac, os, shutil, struct, subprocess, sys, tempfile

# AES-256-GCM from tests/verify_crypto.py: pure Python, standard library only, and
# validated against the published NIST vector before it judges anything.  This
# reader used to need pycryptodomex - installed on the developer's machine, absent
# on the CI runner, where the test exited "needs pycryptodomex" and failed every
# run while passing locally.  The gate's tests take no third-party package.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_crypto as _vc
_vc.gcm_selftest()

# ============================================================== Argon2id ====
M64 = (1 << 64) - 1

def _le32(x): return struct.pack('<I', x)
def _h(data, n): return hashlib.blake2b(data, digest_size=n).digest()

def hprime(x, t):                                       # H', RFC 9106 3.3
    if t <= 64:
        return _h(_le32(t) + x, t)
    r = -(-t // 32) - 2
    v = _h(_le32(t) + x, 64); out = v[:32]
    for _ in range(r - 1):
        v = _h(v, 64); out += v[:32]
    return out + _h(v, t - 32 * r)

def _gb(v, a, b, c, d):
    va, vb, vc, vd = v[a], v[b], v[c], v[d]
    va = (va + vb + 2 * (va & 0xFFFFFFFF) * (vb & 0xFFFFFFFF)) & M64
    vd ^= va; vd = ((vd >> 32) | (vd << 32)) & M64
    vc = (vc + vd + 2 * (vc & 0xFFFFFFFF) * (vd & 0xFFFFFFFF)) & M64
    vb ^= vc; vb = ((vb >> 24) | (vb << 40)) & M64
    va = (va + vb + 2 * (va & 0xFFFFFFFF) * (vb & 0xFFFFFFFF)) & M64
    vd ^= va; vd = ((vd >> 16) | (vd << 48)) & M64
    vc = (vc + vd + 2 * (vc & 0xFFFFFFFF) * (vd & 0xFFFFFFFF)) & M64
    vb ^= vc; vb = ((vb >> 63) | (vb << 1)) & M64
    v[a], v[b], v[c], v[d] = va, vb, vc, vd

def _p(v):
    _gb(v, 0, 4, 8, 12); _gb(v, 1, 5, 9, 13); _gb(v, 2, 6, 10, 14); _gb(v, 3, 7, 11, 15)
    _gb(v, 0, 5, 10, 15); _gb(v, 1, 6, 11, 12); _gb(v, 2, 7, 8, 13); _gb(v, 3, 4, 9, 14)

_COLS = [[16 * r + 2 * i + k for r in range(8) for k in (0, 1)] for i in range(8)]

def _g(x, y):                                           # compression G, 3.5
    r = [a ^ b for a, b in zip(x, y)]; q = r[:]
    for i in range(8):
        row = q[16 * i:16 * i + 16]; _p(row); q[16 * i:16 * i + 16] = row
    for cols in _COLS:
        col = [q[k] for k in cols]; _p(col)
        for k, val in zip(cols, col): q[k] = val
    return [a ^ b for a, b in zip(q, r)]

def argon2id(pwd, salt, t, m, p, tag_len, secret=b'', ad=b''):
    """RFC 9106 Argon2id, version 0x13.  The data-independent address block is
    indexed by the block's position i % 128 (3.4.1.1), regenerated at 0 and 128."""
    y = 2
    h0 = _h(_le32(p) + _le32(tag_len) + _le32(m) + _le32(t) + _le32(0x13) + _le32(y)
            + _le32(len(pwd)) + pwd + _le32(len(salt)) + salt
            + _le32(len(secret)) + secret + _le32(len(ad)) + ad, 64)
    mp = 4 * p * (m // (4 * p)); q = mp // p; sl = q // 4
    B = [[None] * q for _ in range(p)]
    for l in range(p):
        B[l][0] = list(struct.unpack('<128Q', hprime(h0 + _le32(0) + _le32(l), 1024)))
        B[l][1] = list(struct.unpack('<128Q', hprime(h0 + _le32(1) + _le32(l), 1024)))
    zero = [0] * 128
    for r in range(t):
        for s in range(4):
            for l in range(p):
                indep = r == 0 and s < 2
                start = 2 if (r == 0 and s == 0) else 0
                addr, ctr = None, 0
                def next_block():
                    nonlocal ctr
                    ctr += 1
                    return _g(zero, _g(zero, [r, l, s, mp, t, y, ctr] + [0] * 121))
                if indep and start:
                    addr = next_block()                 # i = 2 uses the first block
                for i in range(start, sl):
                    col = s * sl + i
                    prev = col - 1 if col else q - 1
                    if indep:
                        if i % 128 == 0:
                            addr = next_block()
                        rnd = addr[i % 128]
                    else:
                        rnd = B[l][prev][0]
                    j1, j2 = rnd & 0xFFFFFFFF, rnd >> 32
                    rl = l if (r == 0 and s == 0) else j2 % p
                    if r == 0:
                        w = s * sl + i - 1 if rl == l else s * sl - (1 if i == 0 else 0)
                    else:
                        w = q - sl + i - 1 if rl == l else q - sl - (1 if i == 0 else 0)
                    rel = w - 1 - ((w * ((j1 * j1) >> 32)) >> 32)
                    st = 0 if (r == 0 or s == 3) else (s + 1) * sl
                    new = _g(B[l][prev], B[rl][(st + rel) % q])
                    B[l][col] = new if r == 0 else [a ^ b for a, b in zip(new, B[l][col])]
    c = B[0][q - 1]
    for l in range(1, p):
        c = [a ^ b for a, b in zip(c, B[l][q - 1])]
    return hprime(struct.pack('<128Q', *c), tag_len)

# =============================================== the format (docs/formats.md) ====
HDR, TAG, TRAILER, VATT_FOOTER, REF = 80, 16, 44, 12, 68
VF_IMAGE, VF_FILE, VF_LABELED = 9, 10, 0x8000

class Refused(Exception):
    pass

def gcm_open(key, nonce, aad, ct, tag):
    """AES-256-GCM decrypt-and-verify (96-bit nonce, 16-byte tag): the tag is
    checked over aad || ct BEFORE anything is decrypted.  Raises Refused."""
    if len(key) != 32 or len(nonce) != 12 or len(tag) != 16:
        raise Refused('GCM parameters')
    rk = _vc._key_expansion_256(key)
    h_int = int.from_bytes(_vc._aes256_encrypt_block(b'\x00' * 16, rk), 'big')
    j0 = nonce + b'\x00\x00\x00\x01'
    pad16 = lambda b: b + b'\x00' * ((16 - len(b) % 16) % 16)
    s = _vc._ghash(h_int, pad16(aad) + pad16(ct) + struct.pack('>QQ', len(aad) * 8, len(ct) * 8))
    want = (s ^ int.from_bytes(_vc._aes256_encrypt_block(j0, rk), 'big')).to_bytes(16, 'big')
    if not hmac.compare_digest(want, tag):
        raise Refused('GCM tag')
    pt = bytearray()
    ctr = int.from_bytes(j0, 'big')
    for i in range(0, len(ct), 16):
        ctr = (ctr & ~0xFFFFFFFF) | ((ctr + 1) & 0xFFFFFFFF)
        ks = _vc._aes256_encrypt_block(ctr.to_bytes(16, 'big'), rk)
        pt += bytes(a ^ b for a, b in zip(ct[i:i + 16], ks))
    return bytes(pt)

def parse(data, password, key=None):
    """-> dict.  Raises Refused for anything the format says must be refused."""
    if len(data) < HDR + TAG + TRAILER:
        raise Refused('short')
    magic, ver, t, m, lanes = struct.unpack_from('<4sIIII', data, 0)
    if magic != b'VRDR' or ver != 2:
        raise Refused('magic/version')
    if not (1 <= t <= 16) or not (8 <= m <= 4194304) or lanes != 1:
        raise Refused('KDF parameters')
    salt, nonce, kcv = data[20:52], data[52:64], data[64:80]
    # trailer: u64 counter | 32-byte MAC | "VMAC"
    if data[-4:] != b'VMAC':
        raise Refused('VMAC marker')
    counter, = struct.unpack_from('<Q', data, len(data) - TRAILER)
    mac = data[len(data) - 36:len(data) - 4]
    if key is None:
        key = argon2id(password, salt, t, m, lanes, 32)
    if hashlib.sha256(key).digest()[:16] != kcv:
        raise Refused('KCV (wrong password or tampered)')
    want = hashlib.blake2b(b'vordr-file-mac-v1' + key + data[:len(data) - TRAILER + 8],
                           digest_size=32).digest()
    if want != mac:
        raise Refused('file MAC')
    rest = data[:len(data) - TRAILER]
    # an optional attachment section: records, then "VATT" | u64 total record bytes
    atts, att_region = {}, b''
    if len(rest) >= VATT_FOOTER and rest[-VATT_FOOTER:-8] == b'VATT':
        total, = struct.unpack_from('<Q', rest, len(rest) - 8)
        end = len(rest) - VATT_FOOTER
        if total > end - HDR - TAG:
            raise Refused('VATT length')
        att_region = rest[end - total:end]
        rest = rest[:end - total]
        i = 0
        while i < len(att_region):
            aid = att_region[i:i + 16]
            ln, = struct.unpack_from('<Q', att_region, i + 16)
            if i + 24 + ln + TAG > len(att_region):
                raise Refused('attachment record length')
            atts[aid] = (att_region[i:i + 24], att_region[i + 24:i + 24 + ln],
                         att_region[i + 24 + ln:i + 24 + ln + TAG])
            i += 24 + ln + TAG
    body = gcm_open(key, nonce, data[:HDR], rest[HDR:-TAG], rest[-TAG:])
    # records
    n, = struct.unpack_from('<I', body, 0); o = 4
    entries, refs = [], []
    for _ in range(n):
        eid = body[o:o + 16]; created, modified, fc = struct.unpack_from('<QQI', body, o + 16); o += 36
        fields = []
        for _ in range(fc):
            typ, ln = struct.unpack_from('<HI', body, o); o += 6
            val = body[o:o + ln]; o += ln
            label = None
            if typ & VF_LABELED:
                ll, = struct.unpack_from('<H', val, 0)
                label, val = val[2:2 + ll], val[2 + ll:]
            kind = typ & 0xFF
            if kind in (VF_IMAGE, VF_FILE) and len(val) >= REF:
                refs.append(val[:REF])
            fields.append((typ, label, val))
        entries.append((eid, fields))
    if o != len(body):
        raise Refused('body has trailing bytes')
    plain = {}
    for ref in refs:
        aid, akey, anonce = ref[:16], ref[16:48], ref[48:60]
        ptlen, = struct.unpack_from('<Q', ref, 60)
        if aid not in atts:
            raise Refused('attachment missing')
        aad, ct, tag = atts[aid]
        pt = gcm_open(akey, anonce, aad, ct, tag)
        if len(pt) != ptlen:
            raise Refused('attachment length')
        plain[aid] = pt
    return dict(t=t, m=m, salt=salt, nonce=nonce, kcv=kcv, counter=counter, key=key,
                entries=entries, attachments=plain, att_records=len(atts),
                att_region_at=len(rest), att_region_len=len(att_region))

# ================================================================ the tests ====
def main():
    exe = os.path.abspath(sys.argv[1])
    work = tempfile.mkdtemp(prefix='vordr-vv-')
    fails = []

    def check(ok, what):
        print('  %s %s' % ('ok  ' if ok else 'FAIL', what), flush=True)
        if not ok:
            fails.append(what)

    def vordr(*args):
        p = subprocess.run([exe] + list(args), capture_output=True, timeout=120, cwd=work)
        return p.returncode & 0xFFFFFFFF, p.stdout.decode('latin-1')

    pw = b'vordrtest'
    try:
        # 0. this Argon2id is trusted only after it reproduces RFC 9106's vector
        tag = argon2id(b'\x01' * 32, b'\x02' * 16, 3, 32, 4, 32, secret=b'\x03' * 8, ad=b'\x04' * 12)
        check(tag.hex() == '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
              'this file\'s Argon2id reproduces the RFC 9106 sec.5.3 vector')

        # 1. a small vault with two attachments, saved four times
        a = os.path.join(work, 'a.vault')
        rc, out = vordr('vattgen', a)
        check(rc == 0, 'vattgen wrote the fixture (%s)' % out.strip())
        data = open(a, 'rb').read()
        try:
            v = parse(data, pw)
            check(True, 'the vault decrypts independently (t=%d m=%d KiB)' % (v['t'], v['m']))
            check(len(v['entries']) == 1, 'one entry')
            check(len(v['attachments']) == 2 and v['att_records'] == 2,
                  'both attachments decrypt with their own key and nonce (%s bytes)'
                  % '/'.join(str(len(x)) for x in v['attachments'].values()))
            check(v['counter'] == 4, 'save counter is 4 after four saves (got %d)' % v['counter'])
            titles = [f[2] for e in v['entries'] for f in e[1] if (f[0] & 0xFF) == 1]
            check(bool(titles) and all(t for t in titles), 'the entry has a title: %r' % (titles[0][:40] if titles else None))
        except Refused as e:
            check(False, 'the vault decrypts independently (%s)' % e)
            raise SystemExit(1)

        # 2. earlier saves: same salt/key, a fresh nonce every time
        gens = [a] + [a + '.bak%d' % k for k in (1, 2, 3)]
        parsed = []
        for g in gens:
            try:
                parsed.append(parse(open(g, 'rb').read(), pw, key=v['key']))
            except Refused as e:
                check(False, '%s decrypts (%s)' % (os.path.basename(g), e))
        if len(parsed) == 4:
            check([x['counter'] for x in parsed] == [4, 3, 2, 1],
                  'counters run 4,3,2,1 down the backup generations (got %s)' % [x['counter'] for x in parsed])
            check(len({x['salt'] for x in parsed}) == 1 and len({x['kcv'] for x in parsed}) == 1,
                  'salt and key unchanged across saves')
            check(len({x['nonce'] for x in parsed}) == 4,
                  'a different body nonce on every save (no GCM nonce reuse under the one key)')

        # 3. the wrong password is refused - by both readers
        try:
            parse(data, b'vordrtess')
            check(False, 'a wrong password is refused here')
        except Refused as e:
            check('KCV' in str(e), 'a wrong password is refused here (%s)' % e)

        # 4. every region of the file is authenticated
        L = len(data); vstart = v['att_region_at']; vlen = v['att_region_len']
        regions = [
            ('magic', 0), ('version', 4), ('t_cost', 8), ('m_cost', 12), ('lanes', 16),
            ('salt', 30), ('nonce', 58), ('KCV', 70),
            ('body ciphertext', HDR + 5), ('body tag', vstart - 3),
            ('attachment id', vstart + 2), ('attachment length', vstart + 17),
            ('attachment ciphertext', vstart + 26), ('attachment tag', vstart + vlen - 2),
            ('VATT magic', vstart + vlen + 1), ('VATT length', vstart + vlen + 5),
            ('save counter', L - TRAILER + 1), ('file MAC', L - 20), ('VMAC marker', L - 2),
        ]
        t_path = os.path.join(work, 't.vault')
        for name, off in regions:
            b = bytearray(data); b[off] ^= 0x01
            open(t_path, 'wb').write(b)
            for ext in ('.bak1', '.bak2', '.bak3', '.lock'):
                if os.path.exists(t_path + ext):
                    os.remove(t_path + ext)
            rc, out = vordr('vopen', t_path)
            try:
                parse(bytes(b), pw); mine = 'ACCEPTED'
            except Refused as e:
                mine = str(e)
            check(rc != 0 and mine != 'ACCEPTED',
                  'flip in %-22s -> Vordr exit %d, independent: %s' % (name, rc, mine))
        # 5. ...but every flip above is caught by the file MAC first, so none of them
        #    ever reached a GCM tag check.  Re-sign the file after the flip (the MAC
        #    needs the key, which this test has): now only the GCM tags stand in the
        #    way.  The body must be refused by both readers; an attachment by this
        #    one (Vordr verifies an attachment when it is opened, not at unlock).
        for name, off, both in (('body ciphertext', HDR + 5, True),
                                ('attachment ciphertext', vstart + 26, False)):
            b = bytearray(data); b[off] ^= 0x01
            b[L - 36:L - 4] = hashlib.blake2b(b'vordr-file-mac-v1' + v['key'] + bytes(b[:L - TRAILER + 8]),
                                              digest_size=32).digest()
            open(t_path, 'wb').write(b)
            for ext in ('.bak1', '.bak2', '.bak3', '.lock'):
                if os.path.exists(t_path + ext):
                    os.remove(t_path + ext)
            rc, out = vordr('vopen', t_path)
            try:
                parse(bytes(b), pw, key=v['key']); mine = 'ACCEPTED'
            except Refused as e:
                mine = str(e)
            check(mine.startswith('GCM') and (rc != 0 or not both),
                  'flip in %-22s under a valid file MAC -> Vordr exit %d, independent: %s' % (name, rc, mine))
        rc, out = vordr('vopen', a)
        check(rc == 0, 'the untouched file still opens with Vordr (control)')

        # 5. a vault whose segments are past 128 blocks (m = 8 MiB, 2048-block segments)
        bk = os.path.join(work, 'bk.vault')
        rc, out = vordr('bktest', bk)
        check(rc == 0, 'bktest wrote an 8 MiB-memory vault')
        try:
            vb = parse(open(bk, 'rb').read(), pw)
            check(vb['m'] >= 8192, 'it decrypts independently: the address block past i = 128 matches RFC 9106 (m=%d KiB)' % vb['m'])
        except Refused as e:
            check(False, 'the 8 MiB vault decrypts independently (%s)' % e)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print('verify_vault: %s' % ('PASS (%s)' % 'independent reader agrees with Vordr and docs/formats.md'
                                if not fails else '%d FAILURE(S)' % len(fails)))
    return 1 if fails else 0

if __name__ == '__main__':
    sys.exit(main())
