import os
import struct
import math
import re
from collections import Counter

FW = r'firmware'


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


for fn in ('S1H__V28.bin', 'S1___V24.bin', 'S5___V29.bin', 'S5m2XV27.bin'):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    n = len(d)
    print(f'===== {fn} ({n:,} B) =====')

    # 解析分区表,找间隙
    parts = []
    for i in range(200):
        o = 0x2DC + i * 0x5C
        if o + 0x5C > n:
            break
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
            break
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        if flg not in (2, 3):
            break
        if sz:
            parts.append((0x200 + off, 0x200 + off + sz, nm, sz))

    parts.sort()
    print('  前几个分区(文件偏移):')
    for a, b, nm, sz in parts[:6]:
        print(f'    {nm:12} [{a:>10,} .. {b:>10,}]  size={sz:,}')

    # 找间隙(两个相邻分区之间 > 0x1000 的空洞)
    print('  间隙(>4KB):')
    prev_end = 0x200
    for a, b, nm, sz in parts:
        if a > prev_end + 0x1000:
            print(f'    gap [0x{prev_end:X} .. 0x{a:X}]  size={a-prev_end:,}  (前一分区后 → {nm} 前)')
            # 检查间隙内容
            seg = d[prev_end:a]
            e = ent(seg[:min(len(seg), 1 << 20)])
            strs = [m.group().decode('ascii', 'replace') for m in re.finditer(rb'[\x20-\x7e]{4,40}', seg)]
            print(f'         熵={e:.3f}  字符串数={len(strs)}  唯一前12={list(dict.fromkeys(strs))[:12]}')
        prev_end = max(prev_end, b)

    # 特别看 loader 区域内的明文结构(loader1..loader3 覆盖 0x200..0x16A00)
    print()
    print('  === loader 区域(0x200..0x16A00)明文结构 ===')
    seg = d[0x200:0x16A00]
    strs = [m.group().decode('ascii', 'replace') for m in re.finditer(rb'[\x20-\x7e]{3,40}', seg)]
    uniq = list(dict.fromkeys(strs))
    print(f'    字符串({len(strs)} 个, 唯一 {len(uniq)}):')
    for s in uniq[:60]:
        print(f'      {s}')
    print()
