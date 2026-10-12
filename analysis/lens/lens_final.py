import os
import struct
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
OUTLIST = r'.\analysis\lens\lens_functions_seeds.txt'
OUTDIS = r'.\work\lens_disasm_sample.txt'

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)


def walk(start, limit=1200):
    insns, tgts = [], []
    addr, ok = start, False
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
                ok = True
                addr += ins.size
                return insns, tgts, True
            addr += ins.size
            break
        if not got:
            break
    return insns, tgts, False


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

# 第一轮:从种子收集 BL 目标
tg = Counter()
seed_funcs = {}
for s in sorted(seeds):
    insns, tgts, ok = walk(s)
    if ok and len(insns) >= 3:
        seed_funcs[s] = len(insns)
        for t in tgts:
            tg[t] += 1

# 高置信入口 = BL 目标 且 自身有序言
hi = []
for t, c in tg.items():
    if not (0 <= t < n - 4):
        continue
    if t in seeds:
        insns, _, ok = walk(t)
        if ok and len(insns) >= 3:
            hi.append((t, c, len(insns)))

lines = []
lines.append('# 4001V020.plf 函数分析结果')
lines.append('')
lines.append(f'# 序言种子(PUSH {{r0-r7,lr}} 0xB5xx / PUSH.W e92d..): {len(seeds)}')
lines.append(f'# 其中可完整反汇编的: {len(seed_funcs)}')
lines.append(f'# BL 目标(被调用点): {len(tg)}')
lines.append(f'# 高置信函数入口(BL 目标 且 有序言): {len(hi)}')
lines.append('')
lines.append('# 高置信函数入口列表(按被调用次数)')
lines.append(f'# {"入口":>10} {"被调用":>7} {"指令数":>7}')
for t, c, ni in sorted(hi, key=lambda x: -x[1]):
    lines.append(f'  0x{t:06X} {c:>7} {ni:>7}')

with open(OUTLIST, 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(lines))

print(f'序言种子 {len(seeds)}, 可反汇编 {len(seed_funcs)}')
print(f'BL 目标 {len(tg)}')
print(f'高置信函数入口(BL目标∩序言) {len(hi)}')
print()
print('=== 高置信函数入口 Top 20 ===')
for t, c, ni in sorted(hi, key=lambda x: -x[1])[:20]:
    print(f'  0x{t:06X}  被调用 x{c:<4}  {ni} insn')

# 反汇编几个高置信函数完整输出
dl = []
for t, c, ni in sorted(hi, key=lambda x: -x[1])[:5]:
    dl.append(f'--- func 0x{t:06X} (x{c}, {ni} insn) ---')
    insns, _, _ = walk(t, limit=300)
    for ins in insns[:80]:
        dl.append(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
    dl.append('')
with open(OUTDIS, 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(dl))
print(f'\n[已写 {OUTLIST} 和 {OUTDIS}]')
