import os
import struct
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

# 第一轮:序言种子 -> 收集 BL 目标
seeds = set()
for o in range(0, n - 2, 2):
    if d[o + 1] == 0xB5:
        seeds.add(o)
for o in range(0, n - 4, 2):
    if d[o:o + 2] == b'\x2d\xe9':
        m2 = struct.unpack_from('<H', d, o + 2)[0]
        if m2 & 0x4000:
            seeds.add(o)


def walk(start, limit=800):
    insns = []
    tgts = []
    addr = start
    while addr < n - 4 and len(insns) < limit:
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            insns.append(ins)
            if ins.mnemonic in ('bl', 'b', 'blx') and ins.op_str.startswith('#'):
                try:
                    tgts.append(int(ins.op_str[1:], 16) & ~1)
                except Exception:
                    pass
            if (ins.mnemonic == 'pop' and 'pc' in ins.op_str) or (ins.mnemonic == 'bx' and 'lr' in ins.op_str):
                addr += ins.size
                return insns, tgts, True
            addr += ins.size
            break
        if not got:
            break
    return insns, tgts, False


seed_tgts = Counter()
for s in sorted(seeds):
    _, tgts, ok = walk(s)
    if ok:
        for t in tgts:
            seed_tgts[t] += 1

print(f'一轮: 序言种子 {len(seeds)}, 收集到 BL 目标 {len(seed_tgts)}')

# 第二轮:用 BL 目标当入口,反汇编,看质量
print()
print('=== 用 BL 目标作入口的反汇编质量 ===')
cands = [t for t, c in seed_tgts.items() if 0 <= t < n - 4]
ok_cnt = 0
tot = 0
good = []
for t in cands[:3000]:
    insns, tgts, ok = walk(t)
    tot += 1
    if ok and len(insns) >= 3:
        ok_cnt += 1
        good.append((t, len(insns), insns))
print(f'  BL 目标入口能正常反汇编的比例: {ok_cnt}/{tot} ({ok_cnt/max(tot,1):.1%})')

# 与"序言种子入口"对比
ok2 = 0
tot2 = 0
for s in sorted(seeds)[:3000]:
    insns, tgts, ok = walk(s)
    tot2 += 1
    if ok and len(insns) >= 3:
        ok2 += 1
print(f'  序言种子入口能正常反汇编的比例: {ok2}/{tot2} ({ok2/max(tot2,1):.1%})')

print()
print('=== 对比:BL 目标入口的前 8 条指令(看是否有序言)===')
shown = 0
for t, ni, insns in good:
    print(f'--- 入口 0x{t:06X} ({ni} insn) ---')
    for ins in insns[:8]:
        print(f'    0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
    shown += 1
    if shown >= 8:
        break

print()
print('=== 统计:BL 目标入口的首指令分布(是否为序言)===')
first_kind = Counter()
for t, ni, insns in good:
    ins = insns[0]
    b = ins.bytes
    if len(b) >= 2 and b[1] in (0xB4, 0xB5):
        first_kind['push{r0-r7,lr}'] += 1
    elif b[:2] == b'\x2d\xe9':
        first_kind['push.w'] += 1
    elif ins.mnemonic in ('mov', 'movs'):
        first_kind['mov'] += 1
    elif ins.mnemonic.startswith('ldr') or ins.mnemonic.startswith('str'):
        first_kind['ldr/str'] += 1
    else:
        first_kind[ins.mnemonic] += 1
for k, v in first_kind.most_common(10):
    print(f'    {k:20} {v}')
