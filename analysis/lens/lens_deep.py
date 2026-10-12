import os
import re
import struct
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

print('=== 1. 全部 ASCII 字符串中"像标识/命令/路径"的(排除指令码乱码)===')
# 过滤:含字母且有大写/小写混合,或含冒号/下划线/点的
cand = []
for m in re.finditer(rb'[\x20-\x7e]{5,80}', d):
    s = m.group().decode('ascii', 'replace')
    if re.match(r'^[A-Za-z][A-Za-z0-9_\-\. :/]{4,}$', s) and not re.match(r'^[|@\[\]\\{}<>~`#$%^&*+=]', s):
        cand.append((m.start(), s))
uniq = {}
for off, s in cand:
    uniq.setdefault(s, off)
print(f'  候选(去重){len(uniq)} 个:')
for s, off in sorted(uniq.items(), key=lambda x: x[1])[:60]:
    print(f'    0x{off:06X}  {s}')

print()
print('=== 2. 关键字搜索 ===')
for kw in (b'CABRIOLET', b'LENS', b'UPDATE', b'VER', b'VERSION', b'PANASONIC', b'PANA',
           b'ERROR', b'BOOT', b'FLASH', b'CHECK', b'CRC', b'SUM', b'KEY', b'AES', b'MCU',
           b'UPD', b'FW', b'SOF', b'EOH', b'$', b'DATE'):
    ps = [m.start() for m in re.finditer(re.escape(kw), d)]
    if ps:
        print(f'  {kw.decode():12} x{len(ps):>4}  首: {[hex(p) for p in ps[:4]]}')

print()
print('=== 3. CABRIOLET 附近上下文 ===')
i = d.find(b'CABRIOLET')
if i >= 0:
    seg = d[max(0, i - 96):i + 128]
    for k in range(0, len(seg), 16):
        s = seg[k:k + 16]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in s)
        print(f'    0x{i-96+k:06X}  {s.hex(" ")}  |{asc}|')

print()
print('=== 4. 头部区域(0x00-0x60)字段解读 ===')
hdr = d[:0x60]
print(f'  原始: {hdr.hex(" ")}')
print(f'  SOF 标记后(0x13)起:')
p = 0x13
print(f'    +0x{p:02X}: {d[p:p+16].hex(" ")}')

print()
print('=== 5. 数据区结构(熵分布 + 零区 + 0xFF 区)===')
W = 4096
prev = None
for off in range(0, n, W):
    seg = d[off:off + W]
    z = seg.count(0)
    ff = seg.count(0xFF)
    c = Counter(seg)
    e = -sum((v / len(seg)) * (v and 1) * __import__('math').log2(v / len(seg)) for v in c.values())
    kind = '全零' if z == len(seg) else ('全FF' if ff == len(seg) else ('低熵' if e < 6.5 else '数据'))
    if kind != prev:
        print(f'    @0x{off:06X}  {kind}  (熵={e:.2f} 零={z} FF={ff})')
        prev = kind

print()
print('=== 6. 是否含可执行代码特征(MCU 指令跳转表)===')
# 大量 0xFF 通常是未用 flash;数据区可能是 MCU 代码
# 检查 0x79700 附近(CABRIOLET 之后的"表")
for base in (0x79736,):
    for k in range(0, 128, 16):
        s = d[base + k:base + k + 16]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in s)
        print(f'    0x{base+k:06X}  {s.hex(" ")}  |{asc}|')
