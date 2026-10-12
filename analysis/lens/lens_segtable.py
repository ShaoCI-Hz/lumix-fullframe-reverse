import os
import struct
import re
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

print('=== 1) 头部段标记区的完整字节视图 (0x6D..0x110) ===')
for k in range(0x6D, 0x110, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:04x}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 2) 段标记字符串(所有 >=4 的 alpha 序列,头部 0x400 内)===')
for m in re.finditer(rb'[A-Z]{4,}', d[:0x400]):
    print(f'  0x{m.start():04X}  {m.group().decode()}')

print()
print('=== 3) 改进的向量表搜索:word0 像栈指针,word1..N 像 Thumb 地址 ===')
hits = []
for off in range(0, n - 64, 4):
    w0, w1 = struct.unpack_from('<II', d, off)
    # 栈指针:通常 0x20000000 段(RAM),或至少 0x10000 以上且 4 对齐
    if not (0x10000 <= w0 <= 0x40000000 and (w0 & 3) == 0):
        continue
    if not (w1 & 1):
        continue
    # 后续 6 个 word 也要像 Thumb handler
    ok = 0
    for k in range(2, 10):
        v = struct.unpack_from('<I', d, off + k * 4)[0]
        if v & 1 and 0x1000 <= (v & ~1) <= 0x08000000:
            ok += 1
    if ok >= 6:
        hits.append((off, w0, w1))
print(f'  命中 {len(hits)} 个候选:')
for off, w0, w1 in hits[:10]:
    print(f'    @0x{off:06X}  SP=0x{w0:08X}  Reset=0x{w1:08X}')

print()
print('=== 4) 代码段边界附近的字节(找段头)===')
for b in (0x02D000, 0x031000, 0x03B000, 0x045000, 0x04E000, 0x062000):
    print(f'--- 段 @0x{b:06X} 前 0x40 ---')
    for k in range(-0x40, 0x10, 16):
        seg = d[b + k:b + k + 16]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
        print(f'  {b+k:06X}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 5) 全文件的 512 对齐块头模式(找"块索引/地址表")===')
# 检查是否存在每 512 字节重复的结构
cnt = 0
for off in range(0, min(n, 0x4000), 512):
    seg = d[off:off + 16]
    if seg != bytes(16):
        print(f'  @0x{off:06X}: {seg.hex(" ")}')
        cnt += 1
print(f'  非零 512-块头: {cnt}')
