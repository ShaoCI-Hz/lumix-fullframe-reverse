import os
import re
import struct

FW = r'firmware'
p = os.path.join(FW, '4001V020.plf')
d = open(p, 'rb').read()
n = len(d)

print('=== 解析 .plf 头部结构(找段表 / 加载地址)===')
print(f'  "LENS-UPDATE-FILE-SOF:"  @0x0  (21 字节)')
print(f'  头部区 0x15..0x60 逐字段:')
for k in range(0x15, 0x60, 1):
    if k % 8 == 0x15 % 8:
        pass
# 按不同宽度尝试解析
print()
print('--- 字节视图 ---')
for k in range(0x15, 0x60, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:04x}  {seg.hex(" ")}  |{asc}|')

print()
print('--- 按 U16LE 解析 0x15..0x60 ---')
for k in range(0x15, 0x60, 2):
    v = struct.unpack_from('<H', d + bytes(2), k)[0]
    print(f'  +0x{k:02X}: 0x{v:04X} ({v})')

print()
print('=== 找"段表"候选:连续 (offset,size) 或 (addr,size) 对 ===')
# 段表通常在头部,值是递增的地址或 offset
hdr = d[:0x200]
print('  头部 0x60..0x200 中的 u32(非零):')
for k in range(0x60, 0x200, 4):
    v = struct.unpack_from('<I', d, k)[0]
    if v:
        print(f'    +0x{k:03X}: 0x{v:08X} = {v:,}')

print()
print('=== 文件尾部结构(尾部表)===')
tail = d[n - 0x400:]
print('  尾部 0x300 处起 32 行:')
for k in range(0, 0x200, 16):
    seg = tail[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    off = n - 0x400 + k
    print(f'  {off:06X}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 全部 LENS-UPDATE / 已知标记出现位置 ===')
for pat in (b'LENS-UPDATE-FILE-SOF:', b'LENS-UPDATE-FILE-EOH:', b'HDFLSPPSLFDI',
            b'IDFLSPPSLF', b'CABRIOLET', b'PSLFDH'):
    ps = [m.start() for m in re.finditer(re.escape(pat), d)]
    print(f'  {pat.decode():26} {[hex(x) for x in ps[:6]]}')
