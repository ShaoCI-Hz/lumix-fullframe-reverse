import os
import struct
from collections import Counter, defaultdict

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
print(f'4001V020.plf: {n:,} B')

# Cortex-M 常见外设地址段
PERIPH = [
    (0x40000000, 0x400FFFFF, 'APB/AHB 外设'),
    (0xE0000000, 0xE00FFFFF, 'Cortex-M 系统控制 (SCS)'),
    (0x20000000, 0x200FFFFF, 'SRAM'),
    (0x08000000, 0x08FFFFFF, 'Flash'),
    (0x00000000, 0x000FFFFF, '低地址/别名'),
]

print()
print('=== 1) 全文件 4 字节值落在各地址段的数量 ===')
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
print('=== 2) 外设寄存器地址明细(0x40000000 段,按地址聚合)===')
per = Counter()
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if 0x40000000 <= v < 0x40100000:
        per[v & 0xFFFFFF00] += 1        # 按 256B 外设块聚合
print(f'  该段内不同 256B 块: {len(per)}')
for v, c in sorted(per.items())[:30]:
    print(f'    0x{v:08X}  x{c}')

print()
print('=== 3) SCS 段(0xE000E000 附近)= NVIC/SysTick,证明是 Cortex-M ===')
scs = Counter()
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if 0xE0000000 <= v < 0xE0100000:
        scs[v] += 1
for v, c in sorted(scs.items()):
    tag = ''
    if v == 0xE000E100:
        tag = '  ← NVIC_ISER (中断使能)'
    elif v == 0xE000E200:
        tag = '  ← NVIC_ICPR (中断清除)'
    elif v == 0xE000ED00:
        tag = '  ← SCB (CPU ID)'
    elif v == 0xE000ED08:
        tag = '  ← SCB->VTOR (向量表偏移寄存器)'
    elif v == 0xE000E010:
        tag = '  ← SysTick'
    print(f'    0x{v:08X}  x{c}{tag}')

print()
print('=== 4) 引用这些外设地址的代码位置(即"访问外设的函数")===')
# literal 池: 4 字节对齐
hits = defaultdict(list)
for off in range(0, n - 4, 4):
    v = struct.unpack_from('<I', d, off)[0]
    if 0x40000000 <= v < 0x40100000 or 0xE0000000 <= v < 0xE0100000:
        hits[off].append(v)
print(f'  literal 池中外设地址条目: {len(hits)}')
# 找最近的函数序言(谁在用)
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
print('  访问外设最多的函数(序言偏移,按外设引用数):')
for o, c in owner_cnt.most_common(15):
    vs = []
    for h, vv in hits.items():
        if owner(h) == o:
            vs += vv
    uniq = sorted(set(vs))[:4]
    print(f'    0x{o:06X}  {c} 处  外设: {", ".join(f"0x{v:08X}" for v in uniq)}')
