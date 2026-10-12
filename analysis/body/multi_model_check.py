import os
import struct
import zipfile
import hashlib
import math
from collections import Counter

FW = r'firmware'


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


# 解压所有 zip
for f in sorted(os.listdir(FW)):
    if f.lower().endswith('.zip'):
        z = os.path.join(FW, f)
        try:
            with zipfile.ZipFile(z) as zf:
                for i in zf.infolist():
                    print(f'  {f:18} -> {i.filename:20} unpack={i.file_size:>12,}')
                # 解压到 firmware/
                zf.extractall(FW)
        except Exception as e:
            print(f'  {f}: 解压失败 {e}')

print()
print('=== 各机型镜像头部与整体特征 ===')
for f in sorted(os.listdir(FW)):
    if not f.lower().endswith('.bin'):
        continue
    p = os.path.join(FW, f)
    d = open(p, 'rb').read()
    n = len(d)
    head = d[:64]
    magic_ascii = ''.join(chr(x) if 32 <= x < 127 else '.' for x in head[:16])
    # 整体熵(采样)
    sample = d[:min(n, 4 << 20)]
    e = ent(sample)
    print(f'--- {f} ({n:,} B) ---')
    print(f'    head16: {head[:16].hex(" ")}  |{magic_ascii}|')
    print(f'    熵(前4MB)={e:.3f}  是否 UPD magic: {head[:4] == b"UPD\x00"}')
    # 如果有 UPD magic,解析
    if head[:4] == b'UPD\x00':
        block = struct.unpack_from('<I', d, 4)[0]
        model = d[0x0C:0x1C].split(b'\x00')[0].decode('ascii', 'replace')
        ver = struct.unpack_from('<I', d, 0x24)[0]
        imgsz = struct.unpack_from('<I', d, 0x3C)[0]
        crc = struct.unpack_from('<I', d, 0x40)[0]
        print(f'    UPD: block={block} model={model!r} ver_field=0x{ver:08X} img_size={imgsz:,} crc=0x{crc:08X}')
        # 检查签名区
        sig = d[0x220:0x260]
        print(f'    0x220 签名区: {sig[:16].hex()} ... (非零={sum(1 for x in sig if x)})')
        # 分区表
        parts = 0
        for i in range(200):
            o = 0x2DC + i * 0x5C
            if o + 0x5C > n:
                break
            nm = d[o + 16:o + 32].split(b'\x00')[0]
            if not nm or not all(32 <= c < 127 for c in nm):
                break
            flg = struct.unpack_from('<I', d, o + 0x28)[0]
            if flg not in (2, 3):
                break
            parts += 1
        print(f'    分区数(计数)={parts}')
    else:
        # 非 UPD:检查是否有明文/结构
        print(f'    非 UPD 格式,前 256B:')
        for k in range(0, 256, 32):
            seg = d[k:k + 32]
            asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
            print(f'      {k:04x}  {seg.hex(" ")}  |{asc}|')
    print()
