import os
import struct
import math
from collections import Counter

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

FILES = [
    ('4001V020.plf', 'Panasonic S-R24105 (zoom)'),
    ('4006V020.plf', 'Panasonic S-E2470 (zoom)'),
    ('4003V020.plf', 'Panasonic S-X50 (prime)'),
    ('sigma/S02D0120_sigma_14F14_art.plf', 'Sigma 14mm F1.4 Art'),
    ('sigma/A0040140_sigma_30F14_cont.plf', 'Sigma 30mm F1.4 C'),
    ('sigma/S02A0130_sigma_50F2_cont.plf', 'Sigma 50mm F2 C'),
]


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


print('=== 1) 头部字段对比(SOF..EOH 区域)===')
rows = []
for rel, name in FILES:
    p = os.path.join(FW, rel)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    sof = d.find(b'LENS-UPDATE-FILE-SOF:')
    eoh = d.find(b'LENS-UPDATE-FILE-EOH:')
    hdr = d[sof:eoh + 21]
    # 版本字段
    ver = struct.unpack_from('<H', d, 0x15)[0]
    ymd = d[0x17:0x1B]
    # 4 字节 ID 候选:0x21 起
    id4 = d[0x21:0x25].hex(' ')
    id4b = d[0x34:0x38].hex(' ') if eoh > 0x38 else ''
    # 12 字节 FF 区
    ff12 = d[0x25:0x31]
    nff = sum(1 for x in ff12 if x == 0xFF)
    # EOH 后第一段
    after = d[eoh + 21:eoh + 21 + 32].hex(' ')
    rows.append((name, ver, ymd.hex(' '), id4, id4b, nff, eoh, len(d), after))

print(f'  {"样本":<26} {"ver":>4} {"日期":>10} {"ID@0x21":>14} {"ID@0x34":>14} {"FF12":>5} {"EOH@":>5} {"大小":>9}')
for name, ver, ymd, id4, id4b, nff, eoh, sz, after in rows:
    print(f'  {name:<26} {ver:>4} {ymd:>10} {id4:>14} {id4b:>14} {nff:>5} 0x{eoh:02X} {sz:>9,}')

print()
print('=== 2) EOH 后 32 字节(段描述表起点)===')
for name, ver, ymd, id4, id4b, nff, eoh, sz, after in rows:
    print(f'  {name:<26} {after}')

print()
print('=== 3) ★ 假设:0x21 的 4 字节 = 厂商/型号 ID ===')
print('   前 1 字节: 厂商/系列? (Panasonic=0x40, Sigma=0x50/0x60)')
print('   后 3 字节: 型号/版本?')
for name, ver, ymd, id4, id4b, nff, eoh, sz, after in rows:
    b = bytes.fromhex(id4.replace(' ', ''))
    print(f'  {name:<26} 0x{b[0]:02X} | {b[1]:02X} {b[2]:02X} {b[3]:02X}   (LE u32 = 0x{int.from_bytes(b,"little"):08X})')

print()
print('=== 4) CRC32 猜测:0x40 处的 4 字节(EOH 前)===')
import zlib
for rel, name in FILES:
    p = os.path.join(FW, rel)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    eoh = d.find(b'LENS-UPDATE-FILE-EOH:')
    # Sigma EOH@0x44,0x40 处 4 字节;Panasonic EOH@0x58,0x40 处 4 字节
    if eoh == 0x44:
        val = struct.unpack_from('<I', d, 0x40)[0]
    else:
        val = struct.unpack_from('<I', d, 0x40)[0]
    # 尝试多种 CRC 计算
    cands = {}
    for lbl, rng in (('d[0x15:eoh]', d[0x15:eoh]), ('d[0:eoh]', d[0:eoh]),
                     ('d[0x15:]', d[0x15:]), ('d[0:]', d), ('d[0x200:]', d[0x200:])):
        cands[lbl] = zlib.crc32(rng) & 0xFFFFFFFF
    hit = [k for k, v in cands.items() if v == val]
    print(f'  {name:<26} @0x40=0x{val:08X}  匹配: {hit if hit else "无"}')
    if not hit:
        for k, v in cands.items():
            print(f'      {k:14} crc32=0x{v:08X}')

print()
print('=== 5) 熵与代码特征对比 ===')
print(f'  {"样本":<26} {"大小":>9} {"整体熵":>7} {"BXLR":>6} {"PUSH":>6} {"数据区熵":>8}')
for rel, name in FILES:
    p = os.path.join(FW, rel)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    n = len(d)
    bx = d.count(b'\x70\x47')
    pu = sum(1 for o in range(0, n - 2, 2) if d[o + 1] == 0xB5)
    # 数据区熵(0x1000 起 64KB)
    de = ent(d[0x1000:0x11000]) if n > 0x11000 else 0
    print(f'  {name:<26} {n:>9,} {ent(d):>7.3f} {bx:>6,} {pu:>6,} {de:>8.3f}')
