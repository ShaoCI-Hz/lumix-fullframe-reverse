import os
import struct
from collections import Counter, defaultdict

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
print(f'4001V020.plf: {n:,} B')

# Cortex-M 甯歌澶栬鍦板潃娈?PERIPH = [
    (0x40000000, 0x400FFFFF, 'APB/AHB 澶栬'),
    (0xE0000000, 0xE00FFFFF, 'Cortex-M 绯荤粺鎺у埗 (SCS)'),
    (0x20000000, 0x200FFFFF, 'SRAM'),
    (0x08000000, 0x08FFFFFF, 'Flash'),
    (0x00000000, 0x000FFFFF, '浣庡湴鍧€/鍒悕'),
]

print()
print('=== 1) 鍏ㄦ枃浠?4 瀛楄妭鍊艰惤鍦ㄥ悇鍦板潃娈电殑鏁伴噺 ===')
cnt = Counter()
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    for lo, hi, name in PERIPH:
        if lo <= v < hi:
            cnt[name] += 1
            break
for lo, hi, name in PERIPH:
    print(f'  {name:28} 0x{lo:08X}-0x{hi:08X}: {cnt[name]}')

print()
print('=== 2) 澶栬瀵勫瓨鍣ㄥ湴鍧€鏄庣粏(0x40000000 娈?鎸夊湴鍧€鑱氬悎)===')
per = Counter()
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if 0x40000000 <= v < 0x40100000:
        per[v & 0xFFFFFF00] += 1        # 鎸?256B 澶栬鍧楄仛鍚?print(f'  璇ユ鍐呬笉鍚?256B 鍧? {len(per)}')
for v, c in sorted(per.items())[:30]:
    print(f'    0x{v:08X}  x{c}')

print()
print('=== 3) SCS 娈?0xE000E000 闄勮繎)= NVIC/SysTick,璇佹槑鏄?Cortex-M ===')
scs = Counter()
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if 0xE0000000 <= v < 0xE0100000:
        scs[v] += 1
for v, c in sorted(scs.items()):
    tag = ''
    if v == 0xE000E100:
        tag = '  鈫?NVIC_ISER (涓柇浣胯兘)'
    elif v == 0xE000E200:
        tag = '  鈫?NVIC_ICPR (涓柇娓呴櫎)'
    elif v == 0xE000ED00:
        tag = '  鈫?SCB (CPU ID)'
    elif v == 0xE000ED08:
        tag = '  鈫?SCB->VTOR (鍚戦噺琛ㄥ亸绉诲瘎瀛樺櫒)'
    elif v == 0xE000E010:
        tag = '  鈫?SysTick'
    print(f'    0x{v:08X}  x{c}{tag}')

print()
print('=== 4) 寮曠敤杩欎簺澶栬鍦板潃鐨勪唬鐮佷綅缃?鍗?璁块棶澶栬鐨勫嚱鏁?)===')
# literal 姹? 4 瀛楄妭瀵归綈
hits = defaultdict(list)
for off in range(0, n - 4, 4):
    v = struct.unpack_from('<I', d, off)[0]
    if 0x40000000 <= v < 0x40100000 or 0xE0000000 <= v < 0xE0100000:
        hits[off].append(v)
print(f'  literal 姹犱腑澶栬鍦板潃鏉＄洰: {len(hits)}')
# 鎵炬渶杩戠殑鍑芥暟搴忚█(璋佸湪鐢?
seeds = sorted(o for o in range(0, n - 2, 2) if d[o + 1] == 0xB5)
import bisect


def owner(a):
    i = bisect.bisect_right(seeds, a) - 1
    return seeds[i] if i >= 0 else None


owner_cnt = Counter()
for off, vs in list(hits.items())[:4000]:
    o = owner(off)
    if o is not None:
        owner_cnt[o] += len(vs)
print()
print('  璁块棶澶栬鏈€澶氱殑鍑芥暟(搴忚█鍋忕Щ,鎸夊璁惧紩鐢ㄦ暟):')
for o, c in owner_cnt.most_common(15):
    vs = []
    for h, vv in hits.items():
        if owner(h) == o:
            vs += vv
    uniq = sorted(set(vs))[:4]
    print(f'    0x{o:06X}  {c} 澶? 澶栬: {", ".join(f"0x{v:08X}" for v in uniq)}')
