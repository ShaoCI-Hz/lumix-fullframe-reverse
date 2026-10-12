import os
import struct
import zlib
import hashlib
from collections import Counter

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

FILES = [
    ('4001V020.plf', 'Pana S-R24105'),
    ('4006V020.plf', 'Pana S-E2470'),
    ('4003V020.plf', 'Pana S-X50'),
    ('sigma/S02D0120_sigma_14F14_art.plf', 'Sig 14F1.4'),
    ('sigma/A0040140_sigma_30F14_cont.plf', 'Sig 30F1.4'),
    ('sigma/S02A0130_sigma_50F2_cont.plf', 'Sig 50F2'),
]
D = {}
for rel, name in FILES:
    p = os.path.join(FW, rel)
    if os.path.exists(p):
        D[name] = open(p, 'rb').read()

# ---------- 1) FF 填充分析 ----------
print('=== 1) 0xFF 填充 / 数据起始位置 ===')
for name, d in D.items():
    n = len(d)
    nff = d.count(b'\xff')
    # 找第一个"非 0xFF 且非 0x00"的连续块之后
    # 从尾部向前找最后一个非 FF
    last = n - 1
    while last > 0 and d[last] == 0xFF:
        last -= 1
    # 从 0x200 向后找第一个 FF 块(填充区起点)
    first_ff = None
    o = 0x200
    while o < n - 0x100:
        if all(x == 0xFF for x in d[o:o + 0x100]):
            first_ff = o
            break
        o += 0x10
    print(f'  {name:<16} 大小 {n:>9,}  FF占比 {nff/n:>6.1%}  尾部非FF @0x{last:06X}  首个FF块 @0x{first_ff if first_ff else 0:X}')

# ---------- 2) Sigma 段表(EOH 后) ----------
print()
print('=== 2) EOH 后段表(逐 4 字节,前 48 字节)===')
for name, d in D.items():
    eoh = d.find(b'LENS-UPDATE-FILE-EOH:')
    off = eoh + 21
    print(f'--- {name}  (EOH@0x{eoh:02X}, 段表@0x{off:02X}) ---')
    for k in range(off, off + 48, 4):
        v = struct.unpack_from('<I', d, k)[0]
        v16 = struct.unpack_from('<H', d, k)[0]
        print(f'    0x{k:03X}: u32=0x{v:08X} ({v:>12,})  u16lo=0x{v16:04X} ({v16:>6,})')
    print()

# ---------- 3) 更多哈希尝试(0x40 的 4 字节)----------
print('=== 3) 0x40 处 4 字节的哈希匹配(扩展尝试)===')
for name, d in D.items():
    eoh = d.find(b'LENS-UPDATE-FILE-EOH:')
    val = struct.unpack_from('<I', d, 0x40)[0]
    # 各种范围
    rngs = {
        'd[0x15:eoh]': d[0x15:eoh], 'd[0:eoh]': d[0:eoh],
        'd[0x15:]': d[0x15:], 'd[eoh+21:]': d[eoh + 21:],
        'd[0x58:]': d[0x58:] if eoh > 0x58 else b'',
    }
    hits = []
    for lbl, rng in rngs.items():
        if not rng:
            continue
        if (zlib.crc32(rng) & 0xFFFFFFFF) == val:
            hits.append(f'crc32({lbl})')
        # CRC32C (Castagnoli) 用 binascii 不可得,跳过
        # Adler32
        if zlib.adler32(rng) & 0xFFFFFFFF == val:
            hits.append(f'adler32({lbl})')
        # SHA/MD5 前 4 字节
        for h in ('md5', 'sha1', 'sha256'):
            dg = hashlib.new(h, rng).digest()
            for en in ('little', 'big'):
                if int.from_bytes(dg[:4], en) == val:
                    hits.append(f'{h}[{lbl}][:4]{en}')
    print(f'  {name:<16} @0x40=0x{val:08X}  匹配: {hits if hits else "无"}')

# ---------- 4) 版本字段含义验证 ----------
print()
print('=== 4) 版本字段 @0x15 与 EOH 偏移关系 ===')
for name, d in D.items():
    ver = struct.unpack_from('<H', d, 0x15)[0]
    eoh = d.find(b'LENS-UPDATE-FILE-EOH:')
    b0 = d[0x21]
    print(f'  {name:<16} ver=0x{ver:03X}({ver})  EOH@0x{eoh:02X}  头长={eoh+21}  byte0@0x21=0x{b0:02X}')
print('  → 若 ver 与头长/byte0 有规律,则 ver 是格式版本')

# ---------- 5) Sigma 代码区定位 ----------
print()
print('=== 5) Sigma 30mm(无大量FF)的代码特征 ===')
d = D['Sig 30F1.4']
n = len(d)
print(f'  大小 {n:,}')
# 熵逐 4KB
import math


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    m = len(b)
    return -sum((v / m) * math.log2(v / m) for v in c.values())


print('  逐 4KB 熵:')
for off in range(0, min(n, 0x40000), 0x1000):
    print(f'    0x{off:06X}  H={ent(d[off:off + 0x1000]):5.2f}')
print()
print('  前 32 字节 @0x200(数据起点候选):')
b = d[0x200:0x220]
print('   ', b.hex(' '))
print('  反汇编 @0x200:')
for i, ins in enumerate(md.disasm(d[0x200:0x240], 0x200)):
    if i >= 12:
        break
    print(f'    0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
