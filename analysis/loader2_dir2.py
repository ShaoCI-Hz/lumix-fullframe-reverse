import os
import struct
import hashlib

FW = r'firmware'
BASE = 0x200
STEP = 0x5C
START = 0x04


def parts_of(path):
    d = open(path, 'rb').read()
    n = len(d)
    out = {}
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
        out[nm] = dict(real=BASE + off, size=sz, flg=flg, sha=d[o + 0x2C:o + 0x2C + 32])
    return d, out


for fn in ('S1H__V28.bin', 'S5___V29.bin', 'S1___V24.bin'):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        continue
    d, pm = parts_of(p)
    print(f'===== {fn} =====')
    for lname in ('loader2',):
        real, sz = pm[lname]['real'], pm[lname]['size']
        blob = d[real:real + sz]
        print(f'--- {lname} size={sz:,}  澶?瀛楄妭={blob[:4].hex()} ---')
        items = []
        off = START
        while off + STEP <= sz:
            raw = blob[off:off + STEP]
            nm = raw[0:12].split(b'\x00')[0].decode('ascii', 'replace')
            if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
                break
            a = struct.unpack_from('<I', raw, 0x0C)[0]
            size = struct.unpack_from('<I', raw, 0x10)[0]
            b = struct.unpack_from('<I', raw, 0x14)[0]
            flg = struct.unpack_from('<I', raw, 0x18)[0]
            h = raw[0x1C:0x3C]
            items.append(dict(off=off, name=nm, a=a, size=size, b=b, flg=flg, h=h))
            off += STEP
        print(f'  瑙ｆ瀽鍑?{len(items)} 椤?)
        print('  #   name          A           size        B           flg  hash[:8]')
        for i, it in enumerate(items):
            print(f'  {i:>3} {it["name"]:<13} 0x{it["a"]:08X} {it["size"]:>11,} 0x{it["b"]:08X} {it["flg"]:>4}  {it["h"][:8].hex()}')
        # 楠岃瘉
        ok = sum(1 for it in items if it['name'] in pm and pm[it['name']]['size'] == it['size'])
        hs = sum(1 for it in items if it['name'] in pm and pm[it['name']]['sha'] == it['h'])
        print(f'  size 鍖归厤: {ok}   hash 鍖归厤: {hs}')
        # 瑕嗙洊浜嗗摢浜涘垎鍖?        names = [it['name'] for it in items]
        missing = [k for k in pm if k not in names]
        print(f'  鍒嗗尯琛ㄦ湁 {len(pm)} 涓垎鍖? 鐩綍瑕嗙洊 {len([k for k in pm if k in names])} 涓? 缂哄皯: {missing}')
        print()
    print()
