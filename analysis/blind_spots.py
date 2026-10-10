import os
import struct
import math
import hashlib
from collections import Counter

FW = r'firmware'
BASE = 0x200
STEP = 0x5C


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def parts_of(fn):
    p = os.path.join(FW, fn)
    d = open(p, 'rb').read()
    n = len(d)
    out = {}
    for i in range(200):
        o = 0x2DC + i * STEP
        if o + STEP > n:
            break
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
            break
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        if flg not in (2, 3):
            break
        out[nm] = dict(real=BASE + off, size=sz, flg=flg, item_off=o,
                       sha=d[o + 0x2C:o + 0x2C + 32])
    return d, out


d, pm = parts_of('S1H__V28.bin')
print('=== 鐩茬偣1:鍒嗗尯椤?+0x00..+0x10 鐨?16 瀛楄妭鐪熺殑鍏ㄩ浂鍚? ===')
nonzero_items = 0
for nm, a in pm.items():
    o = a['item_off']
    seg = d[o:o + 0x10]
    if seg != bytes(16):
        nonzero_items += 1
        print(f'  {nm:14} +0x00..0x10 = {seg.hex(" ")}')
print(f'  闈為浂鐨勫垎鍖洪」: {nonzero_items}/{len(pm)}')

print()
print('=== 鐩茬偣2:loader2 瀹屾暣瑙ｅ墫 (size=38912) ===')
for lname in ('loader2', 'loader3'):
    real, sz = pm[lname]['real'], pm[lname]['size']
    blob = d[real:real + sz]
    print(f'--- {lname} real=0x{real:X} size={sz:,} ---')
    # 鐩綍琛ㄥ崰鐢ㄥ灏?    off = 0x04
    n_items = 0
    while off + STEP <= sz:
        raw = blob[off:off + STEP]
        nm2 = raw[0:12].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm2 or not all(32 <= c < 127 for c in nm2.encode('ascii', 'replace')):
            break
        n_items += 1
        off += STEP
    dir_end = off
    print(f'    鐩綍椤规暟={n_items}, 鐩綍缁撴潫浜?0x{dir_end:X} ({dir_end} B)')
    print(f'    鍓╀綑 {sz - dir_end:,} B (0x{dir_end:X}..0x{sz:X})')
    rest = blob[dir_end:]
    print(f'    鍓╀綑鍐呭: 鐔?{ent(rest[:min(len(rest),65536)]):.3f}  闈為浂={sum(1 for x in rest if x):,}')
    # 鍓╀綑鍐呭鍒嗘
    for k in range(0, min(len(rest), 0x2000), 0x100):
        seg = rest[k:k + 0x100]
        e = ent(seg)
        if e < 7.5 or k == 0:
            asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg[:48])
            print(f'      +0x{k:04X} 鐔?{e:5.2f}  {seg[:24].hex(" ")}  |{asc}|')
    # 鏄惁鏈夋槑鏂囨枃浠跺ご
    for mg, tag in ((b'\x1f\x8b\x08', 'gzip'), (b'\xfd7zXZ\x00', 'xz'), (b'\x28\xb5\x2f\xfd', 'zstd'),
                    (b'hsqs', 'squashfs'), (b'070701', 'cpio'), (b'\xd0\x0d\xfe\xed', 'dtb')):
        pp = rest.find(mg)
        if pp >= 0:
            print(f'    鈽?鍓╀綑鍖哄惈 {tag} @0x{pp:X}')
    print()

print('=== 鐩茬偣3:UPD 澶村瓧娈垫槸鍚﹀惈瀵嗛挜鏉愭枡 ===')
hdr = d[0:0x80]
for k in range(0, 0x80, 4):
    v = struct.unpack_from('<I', d, k)[0]
    print(f'  +0x{k:02X} = 0x{v:08X}')
