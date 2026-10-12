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


print(f'=== 4001V020.plf  ({n:,} B) 熵={ent(d):.4f} ===')
print()
print('=== 头部 256 字节 hexdump ===')
for k in range(0, 256, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:04x}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 找所有 "LENS-UPDATE" 标记及其偏移 ===')
for m in re.finditer(rb'LENS-UPDATE-FILE-[A-Z]+:?', d):
    print(f'  0x{m.start():06X}  {m.group().decode()}')

print()
print('=== 文件尾 256 字节 ===')
for k in range(max(0, n - 256), n, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:04X}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 结构分段(按 4KB 窗口熵)===')
W = 4096
segs = []
for off in range(0, n, W):
    seg = d[off:off + W]
    e = ent(seg)
    z = seg.count(0)
    segs.append((off, e, z))
# 合并相同特征
prev = None
for off, e, z in segs:
    kind = '明文/低熵' if e < 7.5 else ('混合' if e < 7.95 else '高熵')
    if prev != kind:
        print(f'  @0x{off:06X}  熵={e:.3f} 零={z:>5,}  -> {kind}')
        prev = kind

print()
print('=== 所有可打印字符串(前 80 个,去重)===')
ss = [m.group().decode('ascii', 'replace') for m in re.finditer(rb'[\x20-\x7e]{6,60}', d)]
uniq = list(dict.fromkeys(ss))
print(f'  共 {len(ss)} 个, 唯一 {len(uniq)}')
for s in uniq[:80]:
    print(f'    {s}')

print()
print('=== 是否为 ELF / 已知 MCU 格式? ===')
for mg, tag in ((b'\x7fELF', 'ELF'), (b'\x55\x50\x44\x00', 'UPD'), (b'\x1f\x8b\x08', 'gzip'),
                (b'\xfd7zXZ\x00', 'xz'), (b'\x28\xb5\x2f\xfd', 'zstd'), (b'hsqs', 'squashfs'),
                (b'LENS', 'LENS标记')):
    pp = d.find(mg)
    print(f'  {tag:10}: {"@0x%06X" % pp if pp >= 0 else "无"}')
