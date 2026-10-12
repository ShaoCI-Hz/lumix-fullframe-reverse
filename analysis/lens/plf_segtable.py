import os
import struct

FW = r'firmware'
NAMES = ['4001V020.plf', '4002V020.plf', '4006V020.plf']
S = {}
for f in NAMES:
    p = os.path.join(FW, f)
    if os.path.exists(p):
        S[f] = open(p, 'rb').read()
print('=== 样本 ===')
for f, d in S.items():
    print(f'  {f}: {len(d):,} B  (0x{len(d):X})')

lens = {f: len(d) for f, d in S.items()}

print()
print('=== 1) 头部逐 4 字节跨样本对比(只列"不同"的偏移)===')
print(f'  {"off":>6}  ' + '  '.join(f'{f[:8]:>12}' for f in S) + '   ')
diff_slots = []
for k in range(0, 0x200, 4):
    vals = []
    for f, d in S.items():
        vals.append(struct.unpack_from('<I', d, k)[0] if k + 4 <= len(d) else None)
    if len(set(vals)) > 1:
        diff_slots.append(k)
        print(f'  {k:04X}   ' + '  '.join(f'{v:12d}' for v in vals))
print(f'  → 头部 0..0x200 中可变槽位: {len(diff_slots)} 个 (总 {0x200//4})')

print()
print('=== 2) 可变槽位是否等于各样本的文件大小? ===')
for k in diff_slots:
    vals = [struct.unpack_from('<I', d, k)[0] for d in S.values()]
    sizes = [lens[f] for f in S]
    if vals == sizes:
        print(f'  ★ 0x{k:04X} 精确等于文件大小!')
    # 也检查常见换算
    for label, fn in (('file_size', lambda s: s), ('file_size/512', lambda s: s // 512),
                      ('file_size/0x200', lambda s: s // 0x200), ('file_size*2', lambda s: s * 2)):
        exp = [fn(s) for s in sizes]
        if vals == exp:
            print(f'  ★ 0x{k:04X} == {label}(file_size)')

print()
print('=== 3) 在整个头部(0..0x400)找"等于文件大小"或"等于某固定比例"的字段 ===')
for k in range(0, 0x400, 2):
    try:
        vals = [struct.unpack_from('<I', d, k)[0] for d in S.values()]
    except Exception:
        continue
    sizes = [lens[f] for f in S]
    if vals == sizes:
        print(f'  ★ u32 @0x{k:04X} == file_size  {vals}')
    for div in (0x200, 0x1000, 0x10000):
        if vals == [s // div for s in sizes] and vals[0] > 0:
            print(f'  ★ u32 @0x{k:04X} == file_size/{div}  {vals}')

print()
print('=== 4) 关键:表项地址序列是否"覆盖 [0xB0, EOF)"且随文件增长 ===')
BASE = 0x100
for f, d in S.items():
    n = len(d)
    print(f'--- {f} (size=0x{n:X}) ---')
    seq = []
    for k in range(BASE, 0x400, 2):
        v = struct.unpack_from('<H', d, k)[0]
        if 0x1000 <= v < n:
            seq.append((k, v))
    print(f'    候选地址(u16 ∈ [0x1000, size)): {len(seq)} 个')
    for k, v in seq[:14]:
        print(f'      0x{k:04X} -> 0x{v:06X} ({v})')
    # 检查是否递增
    vs = [v for _, v in seq]
    inc = sum(1 for i in range(len(vs) - 1) if vs[i + 1] > vs[i])
    print(f'    递增对: {inc}/{max(len(vs)-1,1)}')

print()
print('=== 5) 用 32 位读法再试(4 字节对齐)===')
for f, d in S.items():
    n = len(d)
    print(f'--- {f} ---')
    seq = []
    for k in range(BASE, 0x300, 4):
        v = struct.unpack_from('<I', d, k)[0]
        if 0x1000 <= v < n:
            seq.append((k, v))
    for k, v in seq[:12]:
        print(f'      0x{k:04X} -> 0x{v:06X} ({v})')
    vs = [v for _, v in seq]
    if len(vs) > 1:
        inc = sum(1 for i in range(len(vs) - 1) if vs[i + 1] > vs[i])
        print(f'    递增对: {inc}/{len(vs)-1}')
