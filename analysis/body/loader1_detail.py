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


d, pm = load('S5m2XV27.bin')
L1 = d[pm['loader1']['real']:pm['loader1']['real'] + pm['loader1']['size']]
PROG = d[pm['program']['real']:pm['program']['real'] + min(pm['program']['size'], 1 << 20)]

print('=== 对比:loader1[0x1600:] vs program(已知加密)===')
segA = L1[0x1600:]
segB = PROG
for tag, b in (('loader1[0x1600:]', segA), ('program', segB)):
    c = Counter(b)
    e = ent(b)
    exp = len(b) / 256
    chi = sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))
    print(f'  {tag:18} len={len(b):>9,} 熵={e:.5f} 卡方={chi:>8.1f} 零={b.count(0)}')
    # 熵的"来源":看分布是否双峰
    arr = sorted(c.items())
    mx = max(c.values())
    mn = min(c.values())
    print(f'      最多字节={mx} (@{c.most_common(1)[0][0]:#x})  最少={mn}  max/min={mx/mn:.3f}  期望={exp:.1f}')

print()
print('=== bit 层面偏斜(找弱加密特征)===')
for tag, b in (('loader1[0x1600:]', segA), ('program', segB)):
    ones = sum(bin(x).count('1') for x in b)
    total = len(b) * 8
    print(f'  {tag:18} 1 的比例 = {ones/total:.6f} (理想 0.5)')
    # 每 bit 位置(0-7)的 1 比例
    per = []
    for bit in range(8):
        o = sum((x >> bit) & 1 for x in b)
        per.append(o / len(b))
    print(f'      bit0..7 的 1 比例: {[f"{p:.5f}" for p in per]}')

print()
print('=== 字节分布尾部差异(7.95 熵的最可能来源)===')
for tag, b in (('loader1[0x1600:]', segA), ('program', segB)):
    c = Counter(b)
    exp = len(b) / 256
    dev = sorted(((abs(c.get(i, 0) - exp) / exp, i) for i in range(256)), reverse=True)
    print(f'  {tag:18} 偏差最大的 6 个字节值:')
    for d_, i in dev[:6]:
        print(f'       {i:#04x}: count={c.get(i,0)} 期望={exp:.1f} 偏差={d_:.3f}')

print()
print('=== 16 位/32 位对齐检查(是否为结构化数据而非加密)===')
for tag, b in (('loader1[0x1600:]', segA), ('program', segB)):
    u16 = struct.unpack_from('<%dH' % (len(b) // 2), b)
    u16z = sum(1 for v in u16 if v == 0)
    u32 = struct.unpack_from('<%dI' % (len(b) // 4), b)
    u32z = sum(1 for v in u32 if v == 0)
    # 高字节分布
    hi = Counter((v >> 8) & 0xFF for v in u16)
    lo = Counter(v & 0xFF for v in u16)
    print(f'  {tag:18} 零u16={u16z}/{len(u16)} 零u32={u32z}/{len(u32)}  高字节种类={len(hi)} 低字节种类={len(lo)}')

print()
print('=== loader1 明文段完整内容(0x0..0x1600, 首 512B)===')
for k in range(0, 512, 32):
    seg = L1[k:k + 32]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:04x}  {seg.hex(" ")}  |{asc}|')
