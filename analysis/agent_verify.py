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
print('楠岃瘉 1:鍚勫垎鍖虹喌绮剧畻(鎵鹃潪 8.000 寮傚父,灏ゅ叾 loader1)')
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
        # 鍙姤寮傚父(闈?8.000 闄勮繎鐨?
        if e < 7.99:
            nz = sum(1 for x in b if x)
            zeros = b.count(0)
            print(f'  寮傚父 {nm:14} size={sz:>9,} 鐔?{e:.4f} 闆?{zeros:,}({zeros/sz:.2%}) 闈為浂={nz:,}')
            # 鎵句綆鐔靛墠缂€
            for w in (256, 1024, 4096):
                if sz >= w:
                    pre = b[:w]
                    ep = ent(pre)
                    if ep < 7.9:
                        print(f'      鍓嶇紑{w}B 鐔?{ep:.3f}  head={pre[:32].hex()}')
                        break

print()
print('=' * 70)
print('楠岃瘉 2:CRC32 瑕嗙洊鑼冨洿 鈥斺€?鏈哄瀷 ID 鏄惁瑁稿')
print('=' * 70)
for fn in ('S5m2XV27.bin', 'S1H__V28.bin'):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    want = struct.unpack_from('<I', d, 0x40)[0]
    print(f'--- {fn} ---')
    print(f'  澶撮儴璁板綍 CRC32 = 0x{want:08X}')
    for a, b2, tag in ((0x200, len(d), 'CRC32(d[0x200:])'),
                       (0, len(d), 'CRC32(d[0:])'),
                       (0x40, len(d), 'CRC32(d[0x40:])'),
                       (0x2A0, len(d), 'CRC32(d[0x2A0:])')):
        v = zlib.crc32(d[a:b2]) & 0xffffffff
        print(f'  {tag:22} = 0x{v:08X}  {"<== MATCH" if v == want else ""}')
    # 鍏抽敭:鏀规満鍨?ID 鍚?CRC 鏄惁浠嶆垚绔?璇佹槑 ID 鏃?CRC 淇濇姢)
    e = bytearray(d)
    e[0x0C:0x1C] = b'MC8223\0' + b'\0' * 9
    v2 = zlib.crc32(bytes(e[0x200:])) & 0xffffffff
    print(f'  鏀规満鍨婭D鍚?CRC32(d[0x200:]) = 0x{v2:08X}  -> 浠嶇瓑浜庡師CRC: {v2 == want}')
    print(f'     => 鏈哄瀷 ID(0x0C){"涓嶅湪" if v2 == want else "鍦?} CRC32 淇濇姢鑼冨洿鍐?)
