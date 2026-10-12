import os
import struct
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
OUT = r'.\analysis\lens\lens_functions.txt'
OUT2 = r'.\work\lens_func_list.txt'

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

# 1) 序言种子
seeds = set()
for o in range(0, n - 2, 2):
    if d[o + 1] == 0xB5:
        seeds.add(o)
for o in range(0, n - 4, 2):
    if d[o:o + 2] == b'\x2d\xe9':
        mask = struct.unpack_from('<H', d, o + 2)[0]
        if mask & 0x4000:
            seeds.add(o)


def disasm_func(start, limit=4000):
    """从 start 反汇编到函数结尾,返回 (指令列表, 目标集合, 是否正常结束, 字节数)"""
    insns = []
    targets = set()
    addr = start
    ok = False
    while addr < n - 4 and len(insns) < limit:
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            insns.append(ins)
            m = ins.mnemonic
            if m in ('bl', 'b', 'blx') and ins.op_str.startswith('#'):
                try:
                    t = int(ins.op_str[1:], 16)
                    if 0 <= t < n:
                        targets.add(t & ~1)
                except Exception:
                    pass
            if (m == 'pop' and 'pc' in ins.op_str) or (m == 'bx' and 'lr' in ins.op_str):
                ok = True
                addr += ins.size
                return insns, targets, True, addr - start
            addr += ins.size
            break
        if not got:
            break
    return insns, targets, ok, addr - start


# 2) 判定所有种子
funcs = []
for s in sorted(seeds):
    insns, tgts, ok, size = disasm_func(s, limit=1500)
    if ok and len(insns) >= 3:
        funcs.append(dict(addr=s, size=size, ninstr=len(insns), targets=tgts))

print(f'=== 可信函数: {len(funcs)} / {len(seeds)} 个序言种子 ===')

# 3) 被引用次数(哪个函数被调用最多 = 核心工具函数)
refcnt = Counter()
for f in funcs:
    for t in f['targets']:
        refcnt[t] += 1

# 4) 关键:把 BL 目标匹配到已知函数入口
entry_set = set(f['addr'] for f in funcs)
matched = sum(1 for t in refcnt if t in entry_set)
print(f'  函数间调用关系: {len(refcnt)} 个目标,其中命中函数入口 {matched} ({matched/max(len(refcnt),1):.1%})')

# 5) 输出函数列表(按被引用次数排序)
lines = []
lines.append(f'# 4001V020.plf 可信函数列表(序言种子 + 递归下降)')
lines.append(f'# 共 {len(funcs)} 个函数')
lines.append(f'# 格式: 入口地址  大小  指令数  被调用次数')
lines.append('')
for f in sorted(funcs, key=lambda x: -refcnt.get(x['addr'], 0)):
    cnt = refcnt.get(f['addr'], 0)
    lines.append(f'  0x{f["addr"]:06X}  {f["size"]:>5} B  {f["ninstr"]:>4} insn  x{cnt}')

# 6) 反汇编 top 8 核心函数
lines.append('')
lines.append('#' + '=' * 66)
lines.append(f'# 核心函数反汇编(被调用最多的 8 个)')
lines.append('#' + '=' * 66)
top = sorted(funcs, key=lambda x: -refcnt.get(x['addr'], 0))[:8]
for f in top:
    cnt = refcnt.get(f['addr'], 0)
    lines.append('')
    lines.append(f'--- func 0x{f["addr"]:06X}  ({f["size"]} B, {f["ninstr"]} insn, 被调用 {cnt} 次) ---')
    insns, _, _, _ = disasm_func(f['addr'], limit=200)
    for ins in insns[:60]:
        lines.append(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')

with open(OUT, 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(lines))
with open(OUT2, 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(lines[:len(funcs) + 5]))

print(f'  已写 {OUT}')
print()
print('=== 被调用最多的 15 个函数 ===')
print(f'  {"入口":>10} {"大小":>7} {"指令":>6} {"调用次数":>8}')
for f in top[:15]:
    cnt = refcnt.get(f['addr'], 0)
    print(f'  0x{f["addr"]:06X} {f["size"]:>6} B {f["ninstr"]:>6} x{cnt}')
print()
print('=== 指令总数统计 ===')
print(f'  可信函数覆盖指令: {sum(f["ninstr"] for f in funcs):,}')
print(f'  可信函数覆盖字节: {sum(f["size"] for f in funcs):,} / {n:,} ({sum(f["size"] for f in funcs)/n:.1%})')
