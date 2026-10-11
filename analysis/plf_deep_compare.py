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

# ---------- 1) FF 濉厖鍒嗘瀽 ----------
print('=== 1) 0xFF 濉厖 / 鏁版嵁璧峰浣嶇疆 ===')
for name, d in D.items():
    n = len(d)
    nff = d.count(b'\xff')
    # 鎵剧涓€涓?闈?0xFF 涓旈潪 0x00"鐨勮繛缁潡涔嬪悗
    # 浠庡熬閮ㄥ悜鍓嶆壘鏈€鍚庝竴涓潪 FF
    last = n - 1
    while last > 0 and d[last] == 0xFF:
        last -= 1
    # 浠?0x200 鍚戝悗鎵剧涓€涓?FF 鍧?濉厖鍖鸿捣鐐?
    first_ff = None
    o = 0x200
    while o < n - 0x100:
        if all(x == 0xFF for x in d[o:o + 0x100]):
            first_ff = o
            break
        o += 0x10
    print(f'  {name:<16} 澶у皬 {n:>9,}  FF鍗犳瘮 {nff/n:>6.1%}  灏鹃儴闈濬F @0x{last:06X}  棣栦釜FF鍧?@0x{first_ff if first_ff else 0:X}')

# ---------- 2) Sigma 娈佃〃(EOH 鍚? ----------
print()
print('=== 2) EOH 鍚庢琛?閫?4 瀛楄妭,鍓?48 瀛楄妭)===')
for name, d in D.items():
    eoh = d.find(b'LENS-UPDATE-FILE-EOH:')
    off = eoh + 21
    print(f'--- {name}  (EOH@0x{eoh:02X}, 娈佃〃@0x{off:02X}) ---')
    for k in range(off, off + 48, 4):
        v = struct.unpack_from('<I', d, k)[0]
        v16 = struct.unpack_from('<H', d, k)[0]
        print(f'    0x{k:03X}: u32=0x{v:08X} ({v:>12,})  u16lo=0x{v16:04X} ({v16:>6,})')
    print()

# ---------- 3) 鏇村鍝堝笇灏濊瘯(0x40 鐨?4 瀛楄妭)----------
print('=== 3) 0x40 澶?4 瀛楄妭鐨勫搱甯屽尮閰?鎵╁睍灏濊瘯)===')
for name, d in D.items():
    eoh = d.find(b'LENS-UPDATE-FILE-EOH:')
    val = struct.unpack_from('<I', d, 0x40)[0]
    # 鍚勭鑼冨洿
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
        # CRC32C (Castagnoli) 鐢?binascii 涓嶅彲寰?璺宠繃
        # Adler32
        if zlib.adler32(rng) & 0xFFFFFFFF == val:
            hits.append(f'adler32({lbl})')
        # SHA/MD5 鍓?4 瀛楄妭
        for h in ('md5', 'sha1', 'sha256'):
            dg = hashlib.new(h, rng).digest()
            for en in ('little', 'big'):
                if int.from_bytes(dg[:4], en) == val:
                    hits.append(f'{h}[{lbl}][:4]{en}')
    print(f'  {name:<16} @0x40=0x{val:08X}  鍖归厤: {hits if hits else "鏃?}')

# ---------- 4) 鐗堟湰瀛楁鍚箟楠岃瘉 ----------
print()
print('=== 4) 鐗堟湰瀛楁 @0x15 涓?EOH 鍋忕Щ鍏崇郴 ===')
for name, d in D.items():
    ver = struct.unpack_from('<H', d, 0x15)[0]
    eoh = d.find(b'LENS-UPDATE-FILE-EOH:')
    b0 = d[0x21]
    print(f'  {name:<16} ver=0x{ver:03X}({ver})  EOH@0x{eoh:02X}  澶撮暱={eoh+21}  byte0@0x21=0x{b0:02X}')
print('  鈫?鑻?ver 涓庡ご闀?byte0 鏈夎寰?鍒?ver 鏄牸寮忕増鏈?)

# ---------- 5) Sigma 浠ｇ爜鍖哄畾浣?----------
print()
print('=== 5) Sigma 30mm(鏃犲ぇ閲廎F)鐨勪唬鐮佺壒寰?===')
d = D['Sig 30F1.4']
n = len(d)
print(f'  澶у皬 {n:,}')
# 鐔甸€?4KB
import math


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    m = len(b)
    return -sum((v / m) * math.log2(v / m) for v in c.values())


print('  閫?4KB 鐔?')
for off in range(0, min(n, 0x40000), 0x1000):
    print(f'    0x{off:06X}  H={ent(d[off:off + 0x1000]):5.2f}')
print()
print('  鍓?32 瀛楄妭 @0x200(鏁版嵁璧风偣鍊欓€?:')
b = d[0x200:0x220]
print('   ', b.hex(' '))
print('  鍙嶆眹缂?@0x200:')
for i, ins in enumerate(md.disasm(d[0x200:0x240], 0x200)):
    if i >= 12:
        break
    print(f'    0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
