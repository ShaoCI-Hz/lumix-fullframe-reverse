import os
import hashlib
import re
from collections import defaultdict

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)


def load(n):
    p = os.path.join(FW, n)
    return open(p, 'rb').read() if os.path.exists(p) else None


D = {k: load(k + 'V020.plf') for k in ('4001', '4002', '4006', '4003')}
D = {k: v for k, v in D.items() if v}


def walk(d, start, limit=2000):
    insns = []
    addr = start
    while addr < len(d) - 4 and len(insns) < limit:
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            insns.append(ins)
            if (ins.mnemonic == 'pop' and 'pc' in ins.op_str) or (ins.mnemonic == 'bx' and 'lr' in ins.op_str):
                return insns, True
            addr += ins.size
            break
        if not got:
            break
    return insns, False


def fingerprint(insns):
    """地址无关指纹:保留助记符 + 操作数结构,抹掉立即数/目标地址的具体值"""
    parts = []
    for ins in insns:
        op = ins.op_str
        # 抹掉 #0x.... / 具体数值
        op = re.sub(r'#-?0x[0-9a-f]+', '#I', op)
        op = re.sub(r'#-?\d+', '#I', op)
        # 抹掉寄存器中的具体位移
        op = re.sub(r'0x[0-9a-f]+', 'D', op)
        parts.append(f'{ins.mnemonic} {op}')
    return hashlib.sha1(';'.join(parts).encode()).hexdigest()[:16], len(insns)


def funcs_of(d, minlen=6):
    seeds = set()
    for o in range(0, len(d) - 4, 2):
        if d[o + 1] == 0xB5:
            seeds.add(o)
        elif d[o:o + 2] == b'\x2d\xe9':
            seeds.add(o)
    out = {}
    for s in sorted(seeds):
        insns, ok = walk(d, s)
        if ok and len(insns) >= minlen:
            fp, n = fingerprint(insns)
            out.setdefault(fp, []).append((s, n))
    return out


print('=== 提取各样本的函数指纹 ===')
F = {}
for k, d in D.items():
    F[k] = funcs_of(d)
    total = sum(len(v) for v in F[k].values())
    print(f'  {k}: {total} 个函数,{len(F[k])} 个唯一指纹')

print()
print('=== 跨样本共享指纹 ===')
zoom = [k for k in ('4001', '4002', '4006') if k in F]
prime = [k for k in ('4003',) if k in F]

# 变焦组共享
if len(zoom) >= 2:
    common_z = set(F[zoom[0]])
    for k in zoom[1:]:
        common_z &= set(F[k])
    print(f'  变焦组({"+".join(zoom)})共享指纹: {len(common_z)} 个')
    # 这些指纹在各自样本中对应的函数
    print()
    print('  前 12 个共享指纹(及其在各样本的偏移/长度):')
    for fp in sorted(common_z)[:12]:
        locs = '  '.join(f'{k}:0x{F[k][fp][0][0]:06X}({F[k][fp][0][1]})' for k in zoom if fp in F[k])
        print(f'    {fp}  {locs}')

# 变焦 vs 定焦
if zoom and prime:
    allz = set.union(*[set(F[k]) for k in zoom])
    allp = set.union(*[set(F[k]) for k in prime])
    cross = allz & allp
    print()
    print(f'  变焦全体 ∪ 指纹 {len(allz)},定焦 {len(allp)},交集 {len(cross)}')
    print(f'  → 跨家族共享指纹比例: {len(cross)/max(len(allz),1):.3f}')
    if cross:
        print('  交集样本:')
        for fp in sorted(cross)[:8]:
            locs = '  '.join(f'{k}:0x{F[k][fp][0][0]:06X}' for k in list(zoom) + list(prime) if fp in F[k])
            print(f'    {fp}  {locs}')

print()
print('=== 变焦组共享指纹的长度分布(看共享的是大函数还是小函数)===')
if len(zoom) >= 2:
    lens = sorted(F[zoom[0]][fp][0][1] for fp in common_z)
    from collections import Counter
    c = Counter()
    for L in lens:
        c[(L // 20) * 20] += 1
    for b in sorted(c):
        print(f'    {b:>4}-{b+19:<4} 指令: {c[b]} 个')
