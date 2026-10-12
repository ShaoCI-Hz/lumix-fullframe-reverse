import os
import re
import struct
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

# 收集变量名
vars_ = {}
for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{5,40}', d):
    s = m.group().decode()
    if re.search(r'[A-Z]', s) and re.search(r'[a-z]', s):
        if 0x4000 <= m.start() <= 0x9000:
            vars_[m.start()] = s
print(f'变量名: {len(vars_)} 个')

print()
print('=== 1) 名字附近的 4 字节值分布(看是否像 RAM 地址 0x2000xxxx)===')
vals_after = Counter()
vals_before = Counter()
for pos in vars_:
    e = pos + len(vars_[pos])
    if e + 4 <= n:
        v = struct.unpack_from('<I', d, e)[0]
        vals_after[v] += 1
    if pos >= 4:
        v = struct.unpack_from('<I', d, pos - 4)[0]
        vals_before[v] += 1

print('  名字后 4 字节 Top 12:')
for v, c in vals_after.most_common(12):
    tag = ''
    if 0x20000000 <= v < 0x20020000:
        tag = '  <-- RAM!'
    if v < n:
        tag = '  (文件内偏移)'
    print(f'    0x{v:08X}  x{c}{tag}')

print()
print('  名字前 4 字节 Top 12:')
for v, c in vals_before.most_common(12):
    tag = ''
    if 0x20000000 <= v < 0x20020000:
        tag = '  <-- RAM!'
    if v < n:
        tag = '  (文件内偏移)'
    print(f'    0x{v:08X}  x{c}{tag}')

print()
print('=== 2) 全文件中的 RAM 地址引用(0x20000000 段)===')
ram_refs = Counter()
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if 0x20000000 <= v < 0x20040000:
        ram_refs[v & 0xFFFFFC00] += 1        # 按 1KB 块聚合
print(f'  RAM 引用(按 1KB 块): {len(ram_refs)} 个块')
for v, c in ram_refs.most_common(15):
    print(f'    0x{v:08X}  x{c}')

print()
print('=== 3) 变量名字符串的地址本身是否被引用(检查 literal 池)===')
# 变量名地址(可能整体以一个"表基址"被引用)
base_candidates = Counter()
for pos in vars_:
    base_candidates[pos & ~0xFF] += 1
print('  变量名地址按 256 对齐后的分布(前 10):')
for v, c in base_candidates.most_common(10):
    print(f'    0x{v:06X}  含 {c} 个变量名')

print()
print('=== 4) 检查变量表区域的头部(表头可能有起始地址/数量)===')
for k in range(0x3F00, 0x4020, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:06X}  {seg.hex(" ")}  |{asc}|')
print('  ...')
# 第一个变量名的位置之前
first = min(vars_)
print(f'  第一个变量名 @0x{first:06X}: {vars_[first]}')
for k in range(first - 0x40, first + 16, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:06X}  {seg.hex(" ")}  |{asc}|')
