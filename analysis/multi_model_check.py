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


# 瑙ｅ帇鎵€鏈?zip
for f in sorted(os.listdir(FW)):
    if f.lower().endswith('.zip'):
        z = os.path.join(FW, f)
        try:
            with zipfile.ZipFile(z) as zf:
                for i in zf.infolist():
                    print(f'  {f:18} -> {i.filename:20} unpack={i.file_size:>12,}')
                # 瑙ｅ帇鍒?firmware/
                zf.extractall(FW)
        except Exception as e:
            print(f'  {f}: 瑙ｅ帇澶辫触 {e}')

print()
print('=== 鍚勬満鍨嬮暅鍍忓ご閮ㄤ笌鏁翠綋鐗瑰緛 ===')
for f in sorted(os.listdir(FW)):
    if not f.lower().endswith('.bin'):
        continue
    p = os.path.join(FW, f)
    d = open(p, 'rb').read()
    n = len(d)
    head = d[:64]
    magic_ascii = ''.join(chr(x) if 32 <= x < 127 else '.' for x in head[:16])
    # 鏁翠綋鐔?閲囨牱)
    sample = d[:min(n, 4 << 20)]
    e = ent(sample)
    print(f'--- {f} ({n:,} B) ---')
    print(f'    head16: {head[:16].hex(" ")}  |{magic_ascii}|')
    print(f'    鐔?鍓?MB)={e:.3f}  鏄惁 UPD magic: {head[:4] == b"UPD\x00"}')
    # 濡傛灉鏈?UPD magic,瑙ｆ瀽
    if head[:4] == b'UPD\x00':
        block = struct.unpack_from('<I', d, 4)[0]
        model = d[0x0C:0x1C].split(b'\x00')[0].decode('ascii', 'replace')
        ver = struct.unpack_from('<I', d, 0x24)[0]
        imgsz = struct.unpack_from('<I', d, 0x3C)[0]
        crc = struct.unpack_from('<I', d, 0x40)[0]
        print(f'    UPD: block={block} model={model!r} ver_field=0x{ver:08X} img_size={imgsz:,} crc=0x{crc:08X}')
        # 妫€鏌ョ鍚嶅尯
        sig = d[0x220:0x260]
        print(f'    0x220 绛惧悕鍖? {sig[:16].hex()} ... (闈為浂={sum(1 for x in sig if x)})')
        # 鍒嗗尯琛?        parts = 0
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
        print(f'    鍒嗗尯鏁?璁℃暟)={parts}')
    else:
        # 闈?UPD:妫€鏌ユ槸鍚︽湁鏄庢枃/缁撴瀯
        print(f'    闈?UPD 鏍煎紡,鍓?256B:')
        for k in range(0, 256, 32):
            seg = d[k:k + 32]
            asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
            print(f'      {k:04x}  {seg.hex(" ")}  |{asc}|')
    print()
