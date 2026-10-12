import os
import struct
import hashlib

FW = r'firmware'
BASE = 0x200
STEP = 0x5C


def load(fn):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        return None, None
    d = open(p, 'rb').read()
    n = len(d)
    pm = {}
    for i in range(200):
        o = 0x2DC + i * STEP
        if o + STEP > n:
            break
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
            break
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        if flg not in (2, 3):
            break
        pm[nm] = dict(real=BASE + off, size=sz, flg=flg, sha=d[o + 0x2C:o + 0x2C + 32])
    return d, pm


for fn in ('S1H__V28.bin', 'S5___V29.bin', 'S1___V24.bin', 'S5m2XV27.bin'):
    d, pm = load(fn)
    if not d:
        continue
    print(f'===== {fn} =====')
    zero = []
    for nm, a in pm.items():
        if a['size'] == 0 or a['real'] + a['size'] > len(d):
            continue
        if hashlib.sha256(bytes(a['size'])).digest() == a['sha']:
            blob = d[a['real']:a['real'] + a['size']]
            nz = sum(1 for x in blob if x)
            zero.append((nm, a['size'], nz))
    if zero:
        print('  ★ 明文全零的分区(密文即 keystream):')
        for nm, sz, nz in zero:
            print(f'     {nm:14} size={sz:>10,}  镜像非零={nz:,}')
    else:
        print('  无明文全零分区')
    # 也列出"明文非全零"的分区数
    tot = len([1 for nm, a in pm.items() if a['size'] > 0])
    print(f'  分区总数(非空)={tot}, 其中明文全零={len(zero)}')
    print()
