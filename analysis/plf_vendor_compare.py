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


print('=== 1) 澶撮儴瀛楁瀵规瘮(SOF..EOH 鍖哄煙)===')
rows = []
for rel, name in FILES:
    p = os.path.join(FW, rel)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    sof = d.find(b'LENS-UPDATE-FILE-SOF:')
    eoh = d.find(b'LENS-UPDATE-FILE-EOH:')
    hdr = d[sof:eoh + 21]
    # 鐗堟湰瀛楁
    ver = struct.unpack_from('<H', d, 0x15)[0]
    ymd = d[0x17:0x1B]
    # 4 瀛楄妭 ID 鍊欓€?0x21 璧?    id4 = d[0x21:0x25].hex(' ')
    id4b = d[0x34:0x38].hex(' ') if eoh > 0x38 else ''
    # 12 瀛楄妭 FF 鍖?    ff12 = d[0x25:0x31]
    nff = sum(1 for x in ff12 if x == 0xFF)
    # EOH 鍚庣涓€娈?    after = d[eoh + 21:eoh + 21 + 32].hex(' ')
    rows.append((name, ver, ymd.hex(' '), id4, id4b, nff, eoh, len(d), after))

print(f'  {"鏍锋湰":<26} {"ver":>4} {"鏃ユ湡":>10} {"ID@0x21":>14} {"ID@0x34":>14} {"FF12":>5} {"EOH@":>5} {"澶у皬":>9}')
for name, ver, ymd, id4, id4b, nff, eoh, sz, after in rows:
    print(f'  {name:<26} {ver:>4} {ymd:>10} {id4:>14} {id4b:>14} {nff:>5} 0x{eoh:02X} {sz:>9,}')

print()
print('=== 2) EOH 鍚?32 瀛楄妭(娈垫弿杩拌〃璧风偣)===')
for name, ver, ymd, id4, id4b, nff, eoh, sz, after in rows:
    print(f'  {name:<26} {after}')

print()
print('=== 3) 鈽?鍋囪:0x21 鐨?4 瀛楄妭 = 鍘傚晢/鍨嬪彿 ID ===')
print('   鍓?1 瀛楄妭: 鍘傚晢/绯诲垪? (Panasonic=0x40, Sigma=0x50/0x60)')
print('   鍚?3 瀛楄妭: 鍨嬪彿/鐗堟湰?')
for name, ver, ymd, id4, id4b, nff, eoh, sz, after in rows:
    b = bytes.fromhex(id4.replace(' ', ''))
    print(f'  {name:<26} 0x{b[0]:02X} | {b[1]:02X} {b[2]:02X} {b[3]:02X}   (LE u32 = 0x{int.from_bytes(b,"little"):08X})')

print()
print('=== 4) CRC32 鐚滄祴:0x40 澶勭殑 4 瀛楄妭(EOH 鍓?===')
import zlib
for rel, name in FILES:
    p = os.path.join(FW, rel)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    eoh = d.find(b'LENS-UPDATE-FILE-EOH:')
    # Sigma EOH@0x44,0x40 澶?4 瀛楄妭;Panasonic EOH@0x58,0x40 澶?4 瀛楄妭
    if eoh == 0x44:
        val = struct.unpack_from('<I', d, 0x40)[0]
    else:
        val = struct.unpack_from('<I', d, 0x40)[0]
    # 灏濊瘯澶氱 CRC 璁＄畻
    cands = {}
    for lbl, rng in (('d[0x15:eoh]', d[0x15:eoh]), ('d[0:eoh]', d[0:eoh]),
                     ('d[0x15:]', d[0x15:]), ('d[0:]', d), ('d[0x200:]', d[0x200:])):
        cands[lbl] = zlib.crc32(rng) & 0xFFFFFFFF
    hit = [k for k, v in cands.items() if v == val]
    print(f'  {name:<26} @0x40=0x{val:08X}  鍖归厤: {hit if hit else "鏃?}')
    if not hit:
        for k, v in cands.items():
            print(f'      {k:14} crc32=0x{v:08X}')

print()
print('=== 5) 鐔典笌浠ｇ爜鐗瑰緛瀵规瘮 ===')
print(f'  {"鏍锋湰":<26} {"澶у皬":>9} {"鏁翠綋鐔?:>7} {"BXLR":>6} {"PUSH":>6} {"鏁版嵁鍖虹喌":>8}')
for rel, name in FILES:
    p = os.path.join(FW, rel)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    n = len(d)
    bx = d.count(b'\x70\x47')
    pu = sum(1 for o in range(0, n - 2, 2) if d[o + 1] == 0xB5)
    # 鏁版嵁鍖虹喌(0x1000 璧?64KB)
    de = ent(d[0x1000:0x11000]) if n > 0x11000 else 0
    print(f'  {name:<26} {n:>9,} {ent(d):>7.3f} {bx:>6,} {pu:>6,} {de:>8.3f}')
