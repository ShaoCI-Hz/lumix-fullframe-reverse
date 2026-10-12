import os
import struct

FW = r'firmware'
files = ['4001V020.plf', '4006V020.plf', '4002V020.plf']
data = {}
for f in files:
    p = os.path.join(FW, f)
    if os.path.exists(p):
        data[f] = open(p, 'rb').read()
print('=== 0) 样本 ===')
for f, d in data.items():
    print(f'  {f}: {len(d):,} B')

print()
print('=== 1) 头部完整 hex(0x00..0x120)===')
d = data['4001V020.plf']
for k in range(0, 0x140, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:04X}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 2) 头部字段解析(逐个 u16/u32,标注可疑值)===')
print('  offset  u16    u32         说明')
for k in range(0x00, 0x100, 4):
    u16 = struct.unpack_from('<H', d, k)[0]
    u32 = struct.unpack_from('<I', d, k)[0]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in d[k:k + 4])
    note = ''
    if 0x1000 <= u32 <= 0x100000:
        note = 'SIZE?'
    if u32 == 0x200:
        note = '512'
    print(f'  {k:04X}    {u16:5}  {u32:10}  |{asc}|  {note}')

print()
print('=== 3) 跨样本头部对比(找"可变字段" vs "固定字段")===')
names = list(data.keys())
ref = data[names[0]]
print(f'  {"off":>5}  ' + '  '.join(f'{n[:8]:>12}' for n in names) + '   一致?')
for k in range(0, 0xC0, 4):
    vals = []
    for n in names:
        dd = data[n]
        vals.append(struct.unpack_from('<I', dd, k)[0] if k + 4 <= len(dd) else 0)
    same = len(set(vals)) == 1
    print(f'  {k:04X}   ' + '  '.join(f'{v:12d}' for v in vals) + f'   {"==" if same else "!! 不同"}')

print()
print('=== 4) 搜索段表特征:连续的 (offset,size) 对,offset 递增且 < 文件大小 ===')


def find_pairs(d, start, end):
    out = []
    for k in range(start, min(end, len(d) - 16), 4):
        a = struct.unpack_from('<I', d, k)[0]
        b = struct.unpack_from('<I', d, k + 4)[0]
        c = struct.unpack_from('<I', d, k + 8)[0]
        # 模式: (addr, size, off) 或 (off, size, addr)
        if 0 < b <= len(d) and (0x1000 <= a <= 0x1000000 or 0x1000 <= c <= 0x1000000):
            out.append((k, a, b, c))
    return out


for label, s, e in (('头部 0x80..0x200', 0x80, 0x200), ('段标记后 0xB0..0x400', 0xB0, 0x400)):
    hits = find_pairs(d, s, e)
    print(f'  [{label}] 候选 {len(hits)} 个')
    for k, a, b, c in hits[:12]:
        print(f'    0x{k:04X}: a=0x{a:08X}({a}) b={b} c=0x{c:08X}({c})')
