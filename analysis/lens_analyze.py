import os
import struct
import math
import re
from collections import Counter

FW = r'firmware'
p = os.path.join(FW, '4001V020.plf')
d = open(p, 'rb').read()
n = len(d)


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    m = len(b)
    return -sum((v / m) * math.log2(v / m) for v in c.values())


print(f'=== 4001V020.plf  ({n:,} B) 鐔?{ent(d):.4f} ===')
print()
print('=== 澶撮儴 256 瀛楄妭 hexdump ===')
for k in range(0, 256, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:04x}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 鎵炬墍鏈?"LENS-UPDATE" 鏍囪鍙婂叾鍋忕Щ ===')
for m in re.finditer(rb'LENS-UPDATE-FILE-[A-Z]+:?', d):
    print(f'  0x{m.start():06X}  {m.group().decode()}')

print()
print('=== 鏂囦欢灏?256 瀛楄妭 ===')
for k in range(max(0, n - 256), n, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:04X}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 缁撴瀯鍒嗘(鎸?4KB 绐楀彛鐔?===')
W = 4096
segs = []
for off in range(0, n, W):
    seg = d[off:off + W]
    e = ent(seg)
    z = seg.count(0)
    segs.append((off, e, z))
# 鍚堝苟鐩稿悓鐗瑰緛
prev = None
for off, e, z in segs:
    kind = '鏄庢枃/浣庣喌' if e < 7.5 else ('娣峰悎' if e < 7.95 else '楂樼喌')
    if prev != kind:
        print(f'  @0x{off:06X}  鐔?{e:.3f} 闆?{z:>5,}  -> {kind}')
        prev = kind

print()
print('=== 鎵€鏈夊彲鎵撳嵃瀛楃涓?鍓?80 涓?鍘婚噸)===')
ss = [m.group().decode('ascii', 'replace') for m in re.finditer(rb'[\x20-\x7e]{6,60}', d)]
uniq = list(dict.fromkeys(ss))
print(f'  鍏?{len(ss)} 涓? 鍞竴 {len(uniq)}')
for s in uniq[:80]:
    print(f'    {s}')

print()
print('=== 鏄惁涓?ELF / 宸茬煡 MCU 鏍煎紡? ===')
for mg, tag in ((b'\x7fELF', 'ELF'), (b'\x55\x50\x44\x00', 'UPD'), (b'\x1f\x8b\x08', 'gzip'),
                (b'\xfd7zXZ\x00', 'xz'), (b'\x28\xb5\x2f\xfd', 'zstd'), (b'hsqs', 'squashfs'),
                (b'LENS', 'LENS鏍囪')):
    pp = d.find(mg)
    print(f'  {tag:10}: {"@0x%06X" % pp if pp >= 0 else "鏃?}')
