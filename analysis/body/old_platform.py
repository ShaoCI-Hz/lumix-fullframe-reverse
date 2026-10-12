import os
import struct
import math
from collections import Counter

FW = r'firmware'
BASE = 0x200


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


MAGICS = [
    (b'\x1f\x8b\x08', 'gzip'),
    (b'BZh', 'bzip2'),
    (b'\xfd7zXZ\x00', 'xz'),
    (b'\x28\xb5\x2f\xfd', 'zstd'),
    (b'\x04\x22\x4d\x18', 'lz4'),
    (b'\x5d\x00\x00', 'lzma'),
    (b'hsqs', 'squashfs-le'),
    (b'sqsh', 'squashfs-be'),
    (b'\x45\x3d\xcd\x28', 'cramfs'),
    (b'-rom1fs-', 'romfs'),
    (b'070701', 'cpio-newc'),
    (b'070702', 'cpio-crc'),
    (b'\x31\x18\x10\x06', 'ubifs'),
    (b'\x85\x19', 'jffs2'),
    (b'\xd0\x0d\xfe\xed', 'dtb'),
    (b'\x7fELF', 'elf'),
    (b'\x27\x05\x19\x56', 'uimage'),
    (b'ANDROID!', 'android-boot'),
    (b'\x1f\x9d', 'compress-lzw'),
    (b'\x89LZO\x00', 'lzo'),
    (b'UBI#', 'ubi'),
    (b'\x01\x00\x00\x00\x00\x00\x00\x00', 'ext-like'),
]


def parse(path):
    d = open(path, 'rb').read()
    n = len(d)
    if d[:4] != b'UPD\x00':
        return None
    model = d[0x0C:0x1C].split(b'\x00')[0].decode('ascii', 'replace')
    parts = []
    for i in range(200):
        o = 0x2DC + i * 0x5C
        if o + 0x5C > n:
            break
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
            break
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        if flg not in (2, 3):
            break
        parts.append(dict(idx=i, name=nm, size=sz, off=off, flg=flg))
    return dict(model=model, size=n, data=d, parts=parts)


def look(d, real, sz):
    """返回(熵, 命中的magic列表, 首个非零偏移, head16)"""
    if real + sz > len(d):
        return None
    b = d[real:real + sz]
    e = ent(b[:min(len(b), 1 << 20)])
    nz = next((k for k, x in enumerate(b) if x), None)
    hits = []
    for mg, name in MAGICS:
        p = b.find(mg)
        if p >= 0:
            hits.append(f'{name}@0x{p:X}')
    # zImage 检测(0x016f2818 LE/BE)
    for off in (0, None):
        pass
    for pat in (b'\x18\x28\x6f\x01', b'\x01\x6f\x28\x18'):
        p = b.find(pat)
        if p >= 0:
            hits.append(f'zImage@0x{p:X}')
    return e, hits, nz, b[:16].hex()


for fn in ('S1H__V28.bin', 'S1___V24.bin', 'S5___V29.bin'):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        continue
    r = parse(p)
    print(f'===== {fn}  model={r["model"]}  size={r["size"]:,} =====')
    print(f'{"分区":14} {"real":>11} {"size":>10} {"flg":>3} {"熵":>6}  首个非零      识别')
    for pt in r['parts']:
        if pt['size'] == 0:
            print(f'{pt["name"]:14} {BASE+pt["off"]:>11,} {0:>10} {pt["flg"]:>3}  (空)')
            continue
        real = BASE + pt['off']
        res = look(r['data'], real, pt['size'])
        if not res:
            print(f'{pt["name"]:14} {real:>11,} {pt["size"]:>10,} {pt["flg"]:>3}  越界')
            continue
        e, hits, nz, head = res
        nzs = f'0x{nz:X}' if nz is not None else 'all-zero'
        mark = ' '.join(hits) if hits else ''
        flag = '★未加密?' if e < 7.5 else ''
        print(f'{pt["name"]:14} {real:>11,} {pt["size"]:>10,} {pt["flg"]:>3} {e:>6.3f}  {nzs:>12}  {mark} {flag}')
        if head and hits:
            print(f'                 head16={head}')
    print()
