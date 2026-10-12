import os
import struct

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True

print('=== 1) 头部 0xF0..0x200 反汇编(Thumb)===')
for off in (0x0F0, 0x0F4, 0x0F6, 0x0F8, 0x0FA):
    print(f'--- 试对齐 0x{off:03X} ---')
    ok = 0
    for i, ins in enumerate(md.disasm(d[off:off + 0x40], off)):
        if i >= 10:
            break
        ok += 1
        print(f'   0x{ins.address:04X}  {ins.bytes.hex():<10} {ins.mnemonic:8} {ins.op_str}')
    print()

print('=== 2) 验证 "00 70 XX YY" 模式是否为地址表 ===')
pat = []
for k in range(0x00, 0x400 - 4, 1):
    if d[k] == 0x00 and d[k + 1] == 0x70:
        pat.append(k)
print(f'  出现位置: {[hex(x) for x in pat[:20]]}')
print(f'  间隔: {[pat[i+1]-pat[i] for i in range(min(12, len(pat)-1))]}')

print()
print('=== 3) 若按 3 字节大端/小端解读 ===')
for k in pat[:10]:
    b3 = d[k + 2:k + 5]
    be = (b3[0] << 16) | (b3[1] << 8) | b3[2]
    le = b3[0] | (b3[1] << 8) | (b3[2] << 16)
    print(f'  @0x{k:03X}: bytes={b3.hex(" ")}  BE=0x{be:06X}({be})  LE=0x{le:06X}({le})  文件内={be < n}')

print()
print('=== 4) 检查头部是否含"递减的地址序列"(段表典型特征)===')
print('  头部 0xB0..0x400 中落在文件内的 u32 值:')
cnt = 0
for k in range(0xB0, 0x400, 4):
    v = struct.unpack_from('<I', d, k)[0]
    if 0x1000 <= v < n:
        print(f'    0x{k:04X}: 0x{v:06X} ({v})')
        cnt += 1
print(f'  合计 {cnt} 个')

print()
print('=== 5) 对比三个样本的头部 0x84..0x120(找可变字段)===')
samples = {}
for f in ('4001V020.plf', '4006V020.plf', '4002V020.plf'):
    p = os.path.join(FW, f)
    if os.path.exists(p):
        samples[f] = open(p, 'rb').read()
print(f'  {"off":>5}  ' + '  '.join(f'{k[:8]:>26}' for k in samples))
for k in range(0x84, 0x110, 8):
    row = []
    for fn, dd in samples.items():
        seg = dd[k:k + 8]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
        row.append(f'{seg.hex(" ")}|{asc}|')
    allsame = len(set(dd[k:k + 8] for dd in samples.values())) == 1
    print(f'  {k:04X}  ' + '  '.join(row) + ('  ==' if allsame else '  !!'))
