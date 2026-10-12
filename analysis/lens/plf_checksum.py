import os
import struct
import zlib
import hashlib

FW = r'firmware'
F = {}
for rel in ('4001V020.plf', '4006V020.plf', '4003V020.plf',
            'sigma/S02D0120_sigma_14F14_art.plf', 'sigma/A0040140_sigma_30F14_cont.plf',
            'sigma/S02A0130_sigma_50F2_cont.plf'):
    p = os.path.join(FW, rel)
    if os.path.exists(p):
        F[os.path.basename(rel)] = open(p, 'rb').read()

print('=== 目标:破解 EOH 前的 4 字节(疑似校验和)===')
print()
for name, d in F.items():
    eoh = d.find(b'LENS-UPDATE-FILE-EOH:')
    val = struct.unpack_from('<I', d, 0x40)[0]
    val2 = struct.unpack_from('<I', d, 0x40)[0]
    print(f'--- {name}  EOH@0x{eoh:02X}  @0x40 = 0x{val:08X} ---')

    # 1) 各种范围的 sum/xor
    rngs = {
        'd[0x15:0x40]': d[0x15:0x40], 'd[0x15:eoh]': d[0x15:eoh],
        'd[0x15:0x3C]': d[0x15:0x3C], 'd[0:0x40]': d[0:0x40],
        'd[0x21:0x3C]': d[0x21:0x3C], 'd[0x21:0x3B]': d[0x21:0x3B],
        'd[eoh+21:]': d[eoh + 21:], 'd[0x200:]': d[0x200:],
        'd[0x15:0x3F]': d[0x15:0x3F],
    }
    found = []
    for lbl, r in rngs.items():
        if not r:
            continue
        s = sum(r) & 0xFFFFFFFF
        x = 0
        for b in r:
            x ^= b
        if s == val:
            found.append(f'sum8({lbl})')
        # sum16
        s16 = sum(struct.unpack('<%dH' % (len(r) // 2), r[:len(r) // 2 * 2])) & 0xFFFFFFFF if len(r) >= 2 else 0
        if s16 == val:
            found.append(f'sum16({lbl})')
        # crc32 变种(不同 init/xorout)
        c = zlib.crc32(r) & 0xFFFFFFFF
        if c == val:
            found.append(f'crc32({lbl})')
        if (c ^ 0xFFFFFFFF) == val:
            found.append(f'crc32xor({lbl})')
        # adler
        if zlib.adler32(r) & 0xFFFFFFFF == val:
            found.append(f'adler({lbl})')
        # 字节累加后取反
        if ((~s) & 0xFFFFFFFF) == val:
            found.append(f'~sum8({lbl})')
    if found:
        print('    命中:', found)
    else:
        print('    无命中(sum/xor/crc32/adler)')

print()
print('=== 二:比较 Sigma 与 Panasonic 的 ID 编码(0x21-0x24)===')
print('  样本            byte0 byte1 byte2 byte3   推断')
for name, d in F.items():
    b = d[0x21:0x25]
    print(f'  {name:<22} 0x{b[0]:02X}  0x{b[1]:02X}   0x{b[2]:02X}   0x{b[3]:02X}')

print()
print('=== 三:0x34 处的重复值(前缀 1 字节不同)===')
for name, d in F.items():
    a = d[0x21:0x25]
    b = d[0x34:0x38]
    same = a[1:] == b[1:]
    print(f'  {name:<22} 0x21={a.hex(" ")}  0x34={b.hex(" ")}  后3字节相同={same}')

print()
print('=== 四:Sigma 头部完整结构(30mm 为例)===')
d = F['A0040140_sigma_30F14_cont.plf']
for k in range(0, 0x80, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:04X}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 五:Sigma 30mm 的代码区(数据起点 0x200)===')
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
# 找第一个非 FF/非 00 的连续区域
o = 0x100
while o < len(d) - 0x200:
    if any(x != 0xFF and x != 0x00 for x in d[o:o + 0x40]):
        break
    o += 0x40
print(f'  首个非填充区 @0x{o:06X}')
print(f'  该处 64 字节:')
seg = d[o:o + 0x40]
print('   ', seg.hex(' '))
print(f'  反汇编:')
for i, ins in enumerate(md.disasm(d[o:o + 0x60], o)):
    if i >= 16:
        break
    print(f'    0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')

print()
print('=== 六:Sigma vs Panasonic 字符串对比(变量字典?)===')
import re
for name, dd in F.items():
    strs = set()
    for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{5,40}', dd[:0x20000]):
        t = m.group().decode()
        if any(c.isupper() for c in t) and any(c.islower() for c in t):
            strs.add(t)
    print(f'  {name:<22} 变量名/字符串 {len(strs)} 个')
