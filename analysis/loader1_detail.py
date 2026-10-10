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

print('=== 瀵规瘮:loader1[0x1600:] vs program(宸茬煡鍔犲瘑)===')
segA = L1[0x1600:]
segB = PROG
for tag, b in (('loader1[0x1600:]', segA), ('program', segB)):
    c = Counter(b)
    e = ent(b)
    exp = len(b) / 256
    chi = sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))
    print(f'  {tag:18} len={len(b):>9,} 鐔?{e:.5f} 鍗℃柟={chi:>8.1f} 闆?{b.count(0)}')
    # 鐔电殑"鏉ユ簮":鐪嬪垎甯冩槸鍚﹀弻宄?    arr = sorted(c.items())
    mx = max(c.values())
    mn = min(c.values())
    print(f'      鏈€澶氬瓧鑺?{mx} (@{c.most_common(1)[0][0]:#x})  鏈€灏?{mn}  max/min={mx/mn:.3f}  鏈熸湜={exp:.1f}')

print()
print('=== bit 灞傞潰鍋忔枩(鎵惧急鍔犲瘑鐗瑰緛)===')
for tag, b in (('loader1[0x1600:]', segA), ('program', segB)):
    ones = sum(bin(x).count('1') for x in b)
    total = len(b) * 8
    print(f'  {tag:18} 1 鐨勬瘮渚?= {ones/total:.6f} (鐞嗘兂 0.5)')
    # 姣?bit 浣嶇疆(0-7)鐨?1 姣斾緥
    per = []
    for bit in range(8):
        o = sum((x >> bit) & 1 for x in b)
        per.append(o / len(b))
    print(f'      bit0..7 鐨?1 姣斾緥: {[f"{p:.5f}" for p in per]}')

print()
print('=== 瀛楄妭鍒嗗竷灏鹃儴宸紓(7.95 鐔电殑鏈€鍙兘鏉ユ簮)===')
for tag, b in (('loader1[0x1600:]', segA), ('program', segB)):
    c = Counter(b)
    exp = len(b) / 256
    dev = sorted(((abs(c.get(i, 0) - exp) / exp, i) for i in range(256)), reverse=True)
    print(f'  {tag:18} 鍋忓樊鏈€澶х殑 6 涓瓧鑺傚€?')
    for d_, i in dev[:6]:
        print(f'       {i:#04x}: count={c.get(i,0)} 鏈熸湜={exp:.1f} 鍋忓樊={d_:.3f}')

print()
print('=== 16 浣?32 浣嶅榻愭鏌?鏄惁涓虹粨鏋勫寲鏁版嵁鑰岄潪鍔犲瘑)===')
for tag, b in (('loader1[0x1600:]', segA), ('program', segB)):
    u16 = struct.unpack_from('<%dH' % (len(b) // 2), b)
    u16z = sum(1 for v in u16 if v == 0)
    u32 = struct.unpack_from('<%dI' % (len(b) // 4), b)
    u32z = sum(1 for v in u32 if v == 0)
    # 楂樺瓧鑺傚垎甯?    hi = Counter((v >> 8) & 0xFF for v in u16)
    lo = Counter(v & 0xFF for v in u16)
    print(f'  {tag:18} 闆秛16={u16z}/{len(u16)} 闆秛32={u32z}/{len(u32)}  楂樺瓧鑺傜绫?{len(hi)} 浣庡瓧鑺傜绫?{len(lo)}')

print()
print('=== loader1 鏄庢枃娈靛畬鏁村唴瀹?0x0..0x1600, 棣?512B)===')
for k in range(0, 512, 32):
    seg = L1[k:k + 32]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:04x}  {seg.hex(" ")}  |{asc}|')
