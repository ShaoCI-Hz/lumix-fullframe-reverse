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

print('=== 鐩爣:鐮磋В EOH 鍓嶇殑 4 瀛楄妭(鐤戜技鏍￠獙鍜?===')
print()
for name, d in F.items():
    eoh = d.find(b'LENS-UPDATE-FILE-EOH:')
    val = struct.unpack_from('<I', d, 0x40)[0]
    val2 = struct.unpack_from('<I', d, 0x40)[0]
    print(f'--- {name}  EOH@0x{eoh:02X}  @0x40 = 0x{val:08X} ---')

    # 1) 鍚勭鑼冨洿鐨?sum/xor
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
        # crc32 鍙樼(涓嶅悓 init/xorout)
        c = zlib.crc32(r) & 0xFFFFFFFF
        if c == val:
            found.append(f'crc32({lbl})')
        if (c ^ 0xFFFFFFFF) == val:
            found.append(f'crc32xor({lbl})')
        # adler
        if zlib.adler32(r) & 0xFFFFFFFF == val:
            found.append(f'adler({lbl})')
        # 瀛楄妭绱姞鍚庡彇鍙?        if ((~s) & 0xFFFFFFFF) == val:
            found.append(f'~sum8({lbl})')
    if found:
        print('    鍛戒腑:', found)
    else:
        print('    鏃犲懡涓?sum/xor/crc32/adler)')

print()
print('=== 浜?姣旇緝 Sigma 涓?Panasonic 鐨?ID 缂栫爜(0x21-0x24)===')
print('  鏍锋湰            byte0 byte1 byte2 byte3   鎺ㄦ柇')
for name, d in F.items():
    b = d[0x21:0x25]
    print(f'  {name:<22} 0x{b[0]:02X}  0x{b[1]:02X}   0x{b[2]:02X}   0x{b[3]:02X}')

print()
print('=== 涓?0x34 澶勭殑閲嶅鍊?鍓嶇紑 1 瀛楄妭涓嶅悓)===')
for name, d in F.items():
    a = d[0x21:0x25]
    b = d[0x34:0x38]
    same = a[1:] == b[1:]
    print(f'  {name:<22} 0x21={a.hex(" ")}  0x34={b.hex(" ")}  鍚?瀛楄妭鐩稿悓={same}')

print()
print('=== 鍥?Sigma 澶撮儴瀹屾暣缁撴瀯(30mm 涓轰緥)===')
d = F['A0040140_sigma_30F14_cont.plf']
for k in range(0, 0x80, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:04X}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 浜?Sigma 30mm 鐨勪唬鐮佸尯(鏁版嵁璧风偣 0x200)===')
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
# 鎵剧涓€涓潪 FF/闈?00 鐨勮繛缁尯鍩?o = 0x100
while o < len(d) - 0x200:
    if any(x != 0xFF and x != 0x00 for x in d[o:o + 0x40]):
        break
    o += 0x40
print(f'  棣栦釜闈炲～鍏呭尯 @0x{o:06X}')
print(f'  璇ュ 64 瀛楄妭:')
seg = d[o:o + 0x40]
print('   ', seg.hex(' '))
print(f'  鍙嶆眹缂?')
for i, ins in enumerate(md.disasm(d[o:o + 0x60], o)):
    if i >= 16:
        break
    print(f'    0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')

print()
print('=== 鍏?Sigma vs Panasonic 瀛楃涓插姣?鍙橀噺瀛楀吀?)===')
import re
for name, dd in F.items():
    strs = set()
    for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{5,40}', dd[:0x20000]):
        t = m.group().decode()
        if any(c.isupper() for c in t) and any(c.islower() for c in t):
            strs.add(t)
    print(f'  {name:<22} 鍙橀噺鍚?瀛楃涓?{len(strs)} 涓?)
