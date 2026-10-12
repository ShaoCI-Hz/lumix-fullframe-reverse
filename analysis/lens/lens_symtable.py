import os
import re
import struct

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

print('=== 1) 符号集中区 0x5400..0x5480 原始字节(看名字之间有什么)===')
for k in range(0x5400, 0x5480, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:06X}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 2) 逐个符号:名字 + 前后各 8 字节(找地址字段)===')
# 收集所有"像符号名"的字符串及其位置
syms = []
for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{5,40}', d):
    s = m.group().decode()
    if re.search(r'[A-Z]', s) and re.search(r'[a-z]', s):
        syms.append((m.start(), m.end(), s))
print(f'  候选符号 {len(syms)} 个')

# 只看名字密集区(每 256 字节内有 >=2 个名字的区域)
def dense(off):
    cnt = 0
    for s, e, _ in syms:
        if off <= s < off + 256:
            cnt += 1
    return cnt

regions = []
cur = None
for s, e, name in syms:
    if dense(s) >= 2:
        regions.append((s, e, name))
print(f'  密集区符号 {len(regions)} 个')

print()
print('  前 25 个(带前后字节):')
for s, e, name in regions[:25]:
    pre = d[max(0, s - 8):s]
    post = d[e:e + 8]
    print(f'    0x{s:06X}  {name:28}  pre={pre.hex(" ")}  post={post.hex(" ")}')

print()
print('=== 3) 假设:名字后的 4 字节是地址?检查是否落在代码区 ===')
hits = 0
samples = []
for s, e, name in regions:
    for off in (e, e + 1, e + 2):        # 尝试几种对齐
        if off + 4 > n:
            continue
        v = struct.unpack_from('<I', d, off)[0]
        if 0x1000 <= (v & ~1) < n and (v & 1):
            hits += 1
            if len(samples) < 12:
                samples.append((name, off - e, v))
            break
print(f'  名字后 4 字节像 Thumb 地址的: {hits}/{len(regions)}')
for name, extra, v in samples:
    print(f'    {name:28} +{extra} -> 0x{v:08X}')

print()
print('=== 4) 假设:名字前的 4 字节是地址? ===')
hits2 = 0
samples2 = []
for s, e, name in regions:
    for off in (s - 4, s - 5):
        if off < 0 or off + 4 > n:
            continue
        v = struct.unpack_from('<I', d, off)[0]
        if 0x1000 <= (v & ~1) < n and (v & 1):
            hits2 += 1
            if len(samples2) < 12:
                samples2.append((name, s - off, v))
            break
print(f'  名字前 4 字节像 Thumb 地址的: {hits2}/{len(regions)}')
for name, extra, v in samples2:
    print(f'    {name:28} -{extra} -> 0x{v:08X}')
