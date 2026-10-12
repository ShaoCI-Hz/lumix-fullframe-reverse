import os
import struct
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
OUT = r'.\analysis\lens\lens_functions.txt'

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)


# --- 1) 收集函数序言种子:Thumb "PUSH {r0-r7, lr}" = 0xB5xx (字节序 xx b5) ---
seeds = []
for o in range(0, n - 2, 2):
    if d[o + 1] == 0xB5:
        seeds.append(o)
print(f'=== 1) 函数序言种子 (PUSH {{r0-r7,lr}} = 0xB5xx): {len(seeds)} 个 ===')

# 也收集 PUSH.W {.., lr} = e92d xxxx
seeds_w = []
for o in range(0, n - 4, 2):
    if d[o:o + 2] == b'\x2d\xe9':
        mask = struct.unpack_from('<H', d, o + 2)[0]
        if mask & 0x4000:      # LR bit
            seeds_w.append(o)
print(f'    PUSH.W 序言 (e92d ..): {len(seeds_w)} 个')


# --- 2) 递归下降:从种子出发,跟随 BL/B 目标,判定代码可达性 ---
def follow_targets(start, limit=200000):
    """从 start 反汇编,收集 BL/B 目标,返回(指令数, 目标集, 是否正常结束)"""
    insns = 0
    targets = set()
    addr = start
    ended_ok = False
    while addr < n - 4 and insns < limit:
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            insns += 1
            m = ins.mnemonic
            if m in ('bl', 'b', 'blx', 'bx') and ins.op_str.startswith('#'):
                try:
                    t = int(ins.op_str[1:], 16)
                    if 0 <= t < n:
                        targets.add(t)
                except Exception:
                    pass
            # 函数结束标志
            if m == 'pop' and 'pc' in ins.op_str:
                ended_ok = True
                return insns, targets, True
            if m == 'bx' and 'lr' in ins.op_str:
                ended_ok = True
                return insns, targets, True
            addr += ins.size
            break
        if not got:
            break
    return insns, targets, ended_ok


all_seeds = sorted(set(seeds) | set(seeds_w))
print()
print('=== 2) 种子判定(是否反汇编到函数结尾)===')
ok_funcs = []
for s in all_seeds:
    cnt, tgts, ok = follow_targets(s, limit=2000)
    if ok and cnt >= 3:
        ok_funcs.append((s, cnt))
print(f'  能正常反汇编到结尾的种子: {len(ok_funcs)} / {len(all_seeds)} ({len(ok_funcs)/max(len(all_seeds),1):.1%})')

# --- 3) 用 BL 目标交叉验证:被引用的入口 ---
print()
print('=== 3) BL 目标 vs 序言种子 交叉验证 ===')
# 收集所有(来自"可信函数内")的 BL 目标
trusted_targets = Counter()
trusted_set = set(s for s, _ in ok_funcs)
for s, _ in ok_funcs[:4000]:
    _, tgts, _ = follow_targets(s, limit=2000)
    for t in tgts:
        trusted_targets[t & ~1] += 1
print(f'  可信 BL 目标数: {len(trusted_targets)}')
with_seed = sum(1 for t in trusted_targets if t in trusted_set)
print(f'  其中也带函数序言的: {with_seed} ({with_seed/max(len(trusted_targets),1):.1%})')

# 被引用最多的目标(最可能是真函数)
print()
print('  被引用最多的 20 个目标:')
for t, c in trusted_targets.most_common(20):
    has = 'SEED' if t in trusted_set else '    '
    print(f'    0x{t:06X}  x{c:<5} {has}')

# --- 4) 反汇编一个高置信函数 ---
print()
print('=== 4) 高置信函数反汇编示例 ===')
lines = []
for t, c in trusted_targets.most_common(6):
    lines.append(f'--- func 0x{t:06X} (被引用 {c} 次) ---')
    cnt = 0
    for ins in md.disasm(d[t:t + 0x100], t):
        lines.append(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
        cnt += 1
        if cnt >= 30:
            break
    lines.append('')
for l in lines[:70]:
    print(l)

with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(lines))
print(f'[已写入 {OUT}]')
