import os
import struct
import math
from collections import Counter

FW = r'firmware'
BASE = 0x200


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def load(fn):
    d = open(os.path.join(FW, fn), 'rb').read()
    n = len(d)
    STEP = 0x5C
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
        pm[nm] = dict(real=BASE + off, size=sz)
    return d, pm


print('=' * 72)
print('loader1 鍒嗘缁撴瀯鍒嗘瀽(鎵?鏄庢枃娈?涓?瀵嗘枃娈?杈圭晫)')
print('=' * 72)
for fn in ('S5m2XV27.bin', 'S1H__V28.bin'):
    d, pm = load(fn)
    real, sz = pm['loader1']['real'], pm['loader1']['size']
    b = d[real:real + sz]
    print(f'--- {fn}: loader1 real=0x{real:X} size={sz:,} ---')
    print(f'  閫?4KB 绐楀彛鐔?闆剁巼:')
    W = 4096
    for off in range(0, sz, W):
        seg = b[off:off + W]
        e = ent(seg)
        z = seg.count(0)
        tag = ''
        if e < 7.5:
            tag = '  <<< 浣庣喌(鏄庢枃/缁撴瀯)'
        elif e < 7.95:
            tag = '  <- 鐣ヤ綆浜庡姞瀵?
        print(f'    +0x{off:06X}  鐔?{e:6.3f}  闆?{z:>6,}({z/len(seg):6.2%}){tag}')

    # 鎵炬槑鏂囨(杩炵画浣庣喌鍖?
    print(f'  鏄庢枃/缁撴瀯鍖哄畾浣?')
    runs = []
    cur = None
    for off in range(0, sz, 0x100):
        seg = b[off:off + 0x100]
        e = ent(seg)
        low = e < 6.5
        if low:
            if cur is None:
                cur = off
        else:
            if cur is not None:
                if off - cur >= 0x100:
                    runs.append((cur, off))
                cur = None
    if cur is not None:
        runs.append((cur, sz))
    for a, c in runs:
        seg = b[a:c]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg[:64])
        print(f'    [0x{a:06X}..0x{c:06X}] len={c-a:,} 鐔?{ent(seg):.3f}')
        print(f'      {seg[:48].hex(" ")}')
        print(f'      |{asc}|')
    print()
