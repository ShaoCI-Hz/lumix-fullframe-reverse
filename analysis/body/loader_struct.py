import os
import struct
import math
import re
from collections import Counter

FW = r'firmware'
BASE = 0x200
STEP = 0x5C


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def parts_of(fn):
    p = os.path.join(FW, fn)
    d = open(p, 'rb').read()
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
        out[nm] = dict(real=BASE + off, size=sz)
    return d, out


d, pm = parts_of('S1H__V28.bin')
l2 = d[pm['loader2']['real']:pm['loader2']['real'] + pm['loader2']['size']]
# loader2 剩余区(目录后)
rest = l2[0x3F8:]
print(f'=== loader2 剩余区 ({len(rest):,} B) 结构分析 ===')
print(f'  熵={ent(rest):.4f}')
c = Counter(rest)
print(f'  字节种类={len(c)}/256')
print(f'  最多: {[(hex(k), v) for k, v in c.most_common(8)]}')
print(f'  最少: {[(hex(k), v) for k, v in c.most_common()[-4:]]}')
# 均匀性:完美随机时每种约 len/256
exp = len(rest) / 256
chi = sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))
print(f'  卡方={chi:.1f} (随机≈255; 偏离越大越不均匀)')

# 零字节比例(结构化数据常有大量零)
zeros = rest.count(0)
print(f'  零字节={zeros} ({zeros/len(rest):.4%})')

# 4 字节对齐:是否有大量零的 u32?
u32 = [struct.unpack_from('<I', rest, i)[0] for i in range(0, len(rest) - 4, 4)]
zero_u32 = sum(1 for v in u32 if v == 0)
print(f'  4字节对齐: 零 u32 = {zero_u32}/{len(u32)} ({zero_u32/len(u32):.2%})')

# ASCII 字符串
strs = [m.group().decode('ascii', 'replace') for m in re.finditer(rb'[\x20-\x7e]{5,60}', rest)]
uniq = list(dict.fromkeys(strs))
print(f'  ASCII 字符串: {len(strs)} 个, 唯一 {len(uniq)}')
for s in uniq[:30]:
    print(f'    {s}')

# 高16位/低16位分布(判断是16位数据?)
hi = Counter((v >> 8) & 0xFF for v in [struct.unpack_from('<H', rest, i)[0] for i in range(0, len(rest) - 2, 2)])
print(f'  16位对齐: 高字节种类={len(hi)}')

# 是否是"位打包"(如每个字节只有低位有信息)
low_nibble = Counter(x & 0xF for x in rest)
high_nibble = Counter(x >> 4 for x in rest)
print(f'  低4位分布种类={len(low_nibble)}  高4位分布种类={len(high_nibble)}')
print(f'  低4位最大偏差: {max(low_nibble.values())/ (len(rest)/16):.2f}x')

# 相邻字节相关性
same_adj = sum(1 for i in range(len(rest) - 1) if rest[i] == rest[i + 1])
print(f'  相邻字节相同: {same_adj}/{len(rest)-1} ({same_adj/(len(rest)-1):.4%}, 随机≈0.39%)')

print()
print('=== 对比:分区数据(加密)的同类指标 ===')
enc = d[pm['program']['real']:pm['program']['real'] + 65536]
ce = Counter(enc)
print(f'  program 熵={ent(enc):.4f} 卡方={sum((ce.get(i,0)-256)**2/256 for i in range(256)):.1f} 零={enc.count(0)}')
print(f'  相邻相同={sum(1 for i in range(len(enc)-1) if enc[i]==enc[i+1])}/{len(enc)-1}')
