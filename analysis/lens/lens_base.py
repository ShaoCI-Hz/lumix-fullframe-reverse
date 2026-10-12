import os
import struct
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

# 序言种子
seeds = set()
for o in range(0, n - 2, 2):
    if d[o + 1] == 0xB5:
        seeds.add(o)
for o in range(0, n - 4, 2):
    if d[o:o + 2] == b'\x2d\xe9':
        m2 = struct.unpack_from('<H', d, o + 2)[0]
        if m2 & 0x4000:
            seeds.add(o)
print(f'序言种子: {len(seeds)}')


def disasm_func(start, limit=1200):
    insns = []
    targets = []
    addr = start
    ok = False
    while addr < n - 4 and len(insns) < limit:
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            insns.append(ins)
            if ins.mnemonic in ('bl', 'b', 'blx') and ins.op_str.startswith('#'):
                try:
                    targets.append((ins.address, int(ins.op_str[1:], 16)))
                except Exception:
                    pass
            if (ins.mnemonic == 'pop' and 'pc' in ins.op_str) or (ins.mnemonic == 'bx' and 'lr' in ins.op_str):
                ok = True
                addr += ins.size
                return insns, targets, True
            addr += ins.size
            break
        if not got:
            break
    return insns, targets, False


funcs = {}
for s in sorted(seeds):
    insns, tgts, ok = disasm_func(s)
    if ok and len(insns) >= 3:
        funcs[s] = (len(insns), tgts)

print(f'可信函数: {len(funcs)}')
entry_set = set(funcs.keys())

# 收集所有 BL 目标
bl_t = []
for s, (ni, tgts) in funcs.items():
    for src, t in tgts:
        bl_t.append((src, t))
print(f'BL 指令总数(可信函数内): {len(bl_t)}')

# 命中率
hit = sum(1 for _, t in bl_t if (t & ~1) in entry_set)
print(f'直接命中函数入口: {hit}/{len(bl_t)} ({hit/max(len(bl_t),1):.1%})')

# 关键:计算 "目标 - 最近函数入口" 的差值分布
print()
print('=== 目标到"最近函数入口"的差值分布(找常数偏移)===')
sorted_entries = sorted(entry_set)
import bisect


def nearest_entry(t):
    i = bisect.bisect_left(sorted_entries, t)
    best = None
    for j in (i - 1, i, i + 1):
        if 0 <= j < len(sorted_entries):
            dd = t - sorted_entries[j]
            if best is None or abs(dd) < abs(best):
                best = dd
    return best


diffs = Counter()
absdiffs = Counter()
for _, t in bl_t:
    dd = nearest_entry(t)
    if dd is not None:
        diffs[dd] += 1
        absdiffs[abs(dd)] += 1

print('  绝对差值 Top 10:')
for v, c in absdiffs.most_common(10):
    print(f'    |diff| = {v:>6}  出现 {c} 次')

print()
print('  带符号差值 Top 15:')
for v, c in diffs.most_common(15):
    print(f'    diff = {v:>8}  出现 {c} 次')

# 检查:是否有明显的常数偏移(如 +0x08000000 之类)
print()
print('=== 检查特定基址偏移 ===')
for base in (0, 0x08000000, 0x1000, 0x2000, 0x8000, 0x10000, 0x20000, -0x1000):
    cnt = 0
    for src, t in bl_t:
        if (t + base) & ~1 in entry_set:
            cnt += 1
    if cnt > 0:
        print(f'  base=0x{base:X} (或 {base}) -> 命中 {cnt} ({cnt/max(len(bl_t),1):.1%})')

# 另一路:BL 目标是否落在"可信函数覆盖的区间"内(不要求是入口)
print()
print('=== BL 目标是否落在任意函数体的区间内 ===')
# 近似:用入口 + 下一入口作为区间
ranges = []
se = sorted(entry_set)
for i, s in enumerate(se):
    e = se[i + 1] if i + 1 < len(se) else n
    ranges.append((s, e))
in_body = 0
for _, t in bl_t:
    t2 = t & ~1
    for a, b in ranges:
        if a <= t2 < b:
            in_body += 1
            break
print(f'  落在函数区间内: {in_body}/{len(bl_t)} ({in_body/max(len(bl_t),1):.1%})')
