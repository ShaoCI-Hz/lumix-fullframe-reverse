import os
import re
import struct
from collections import Counter, defaultdict

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
OUT = r'.\analysis\lens\lens_var_xref.txt'

# 1) 收集变量名 + 文件偏移
vars_ = {}
for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{5,40}', d):
    s = m.group().decode()
    if re.search(r'[A-Z]', s) and re.search(r'[a-z]', s):
        # 只保留名字区(0x5000..0x8000 附近的变量表)
        if 0x4000 <= m.start() <= 0x9000:
            vars_[m.start()] = s
print(f'=== 变量名(0x4000-0x9000 区): {len(vars_)} 个 ===')

# 2) 在文件中搜索"等于变量名字符串地址"的 4 字节值(literal 池引用)
by_ref = defaultdict(list)
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if v in vars_:
        by_ref[v].append(off)

print(f'=== 被代码引用(literal 池)的变量: {len(by_ref)} / {len(vars_)} ===')
print()
print('=== 被引用最多的 15 个变量 ===')
order = sorted(by_ref.items(), key=lambda kv: -len(kv[1]))
for va, refs in order[:15]:
    print(f'  {vars_[va]:28} @0x{va:05X}  被引用 {len(refs)} 次')

# 3) 对每个引用的 literal 位置,找"哪个函数包含它"
#    用序言种子建立的函数区间
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)


def walk(start, limit=1500):
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


seeds = set()
for o in range(0, n - 2, 2):
    if d[o + 1] == 0xB5:
        seeds.add(o)
for o in range(0, n - 4, 2):
    if d[o:o + 2] == b'\x2d\xe9':
        m2 = struct.unpack_from('<H', d, o + 2)[0]
        if m2 & 0x4000:
            seeds.add(o)

funcs = {}
for s in sorted(seeds):
    insns, tgts, ok = walk(s)
    if ok and len(insns) >= 3:
        funcs[s] = (len(insns), tgts)
entries = sorted(funcs.keys())
import bisect


def owner(addr):
    """返回包含 addr 的函数入口(最近的 <= addr 的入口)"""
    i = bisect.bisect_right(entries, addr) - 1
    return entries[i] if i >= 0 else None


print()
print('=== 变量 → 函数映射(被引用变量 Top 15)===')
lines = []
lines.append('# 变量 → 引用点 → 函数入口 映射')
lines.append(f'# 变量名 {len(vars_)} 个,被 literal 池引用 {len(by_ref)} 个')
lines.append('')
mapped = 0
for va, refs in order[:60]:
    name = vars_[va]
    owners = Counter()
    for r in refs:
        o = owner(r)
        if o is not None:
            owners[o] += 1
    if owners:
        mapped += 1
    ost = ', '.join(f'0x{o:06X}(x{c})' for o, c in owners.most_common(4))
    lines.append(f'{name:30} @0x{va:05X}  refs={len(refs):<4} funcs: {ost}')

print()
for l in lines[3:18]:
    print('  ' + l)

print()
print(f'=== 能映射到函数的变量: {mapped} ===')

with open(OUT, 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(lines))
print(f'[已写 {OUT}]')
