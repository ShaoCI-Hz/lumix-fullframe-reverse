import os
import struct
import math
import zlib
from collections import Counter

FW = r'firmware'


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


print('=' * 70)
print('验证 1:各分区熵精算(找非 8.000 异常,尤其 loader1)')
print('=' * 70)
for fn in ('S5m2XV27.bin', 'S1H__V28.bin', 'S5___V29.bin'):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    n = len(d)
    STEP = 0x5C
    print(f'--- {fn} ---')
    for i in range(200):
        o = 0x2DC + i * STEP
        if o + STEP > n:
            break
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
            break
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        if sz == 0 or 0x200 + off + sz > n:
            continue
        b = d[0x200 + off:0x200 + off + sz]
        e = ent(b)
        # 只报异常(非 8.000 附近的)
        if e < 7.99:
            nz = sum(1 for x in b if x)
            zeros = b.count(0)
            print(f'  异常 {nm:14} size={sz:>9,} 熵={e:.4f} 零={zeros:,}({zeros/sz:.2%}) 非零={nz:,}')
            # 找低熵前缀
            for w in (256, 1024, 4096):
                if sz >= w:
                    pre = b[:w]
                    ep = ent(pre)
                    if ep < 7.9:
                        print(f'      前缀{w}B 熵={ep:.3f}  head={pre[:32].hex()}')
                        break

print()
print('=' * 70)
print('验证 2:CRC32 覆盖范围 —— 机型 ID 是否裸奔')
print('=' * 70)
for fn in ('S5m2XV27.bin', 'S1H__V28.bin'):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    want = struct.unpack_from('<I', d, 0x40)[0]
    print(f'--- {fn} ---')
    print(f'  头部记录 CRC32 = 0x{want:08X}')
    for a, b2, tag in ((0x200, len(d), 'CRC32(d[0x200:])'),
                       (0, len(d), 'CRC32(d[0:])'),
                       (0x40, len(d), 'CRC32(d[0x40:])'),
                       (0x2A0, len(d), 'CRC32(d[0x2A0:])')):
        v = zlib.crc32(d[a:b2]) & 0xffffffff
        print(f'  {tag:22} = 0x{v:08X}  {"<== MATCH" if v == want else ""}')
    # 关键:改机型 ID 后 CRC 是否仍成立(证明 ID 无 CRC 保护)
    e = bytearray(d)
    e[0x0C:0x1C] = b'MC8223\0' + b'\0' * 9
    v2 = zlib.crc32(bytes(e[0x200:])) & 0xffffffff
    print(f'  改机型ID后 CRC32(d[0x200:]) = 0x{v2:08X}  -> 仍等于原CRC: {v2 == want}')
    print(f'     => 机型 ID(0x0C){"不在" if v2 == want else "在"} CRC32 保护范围内')
