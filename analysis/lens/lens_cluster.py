import os
import re
import hashlib
from collections import defaultdict, Counter

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

MODELS = {
    '4001': 'S-R24105 (zoom)',
    '4002': 'S-R70200 (zoom)',
    '4003': 'S-X50    (prime)',
    '4006': 'S-E2470  (zoom)',
    '400C': 'S-S85    (prime)',
    '400E': 'S-S50    (prime)',
}
D = {}
for k in MODELS:
    p = os.path.join(FW, k + 'V020.plf')
    if os.path.exists(p):
        D[k] = open(p, 'rb').read()
print(f'样本: {len(D)} 个 -> {", ".join(D)}')


def walk(d, start, limit=3000):
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


def norm(insns):
    parts = []
    for ins in insns:
        op = ins.op_str
        op = re.sub(r'#-?0x[0-9a-f]+', '#I', op)
        op = re.sub(r'#-?\d+', '#I', op)
        op = re.sub(r'0x[0-9a-f]+', 'D', op)
        parts.append(f'{ins.mnemonic} {op}')
    return ';'.join(parts)


def fp(s):
    return hashlib.sha1(s.encode()).hexdigest()[:16]


# 1) 每个型号提取函数指纹
FP = {}
for k, d in D.items():
    seeds = set()
    for o in range(0, len(d) - 4, 2):
        if d[o + 1] == 0xB5:
            seeds.add(o)
        elif d[o:o + 2] == b'\x2d\xe9':
            seeds.add(o)
    f = {}
    for s in sorted(seeds):
        insns, ok = walk(d, s)
        if ok and len(insns) >= 6:
            h = fp(norm(insns))
            if h not in f:
                f[h] = (s, len(insns), insns)
    FP[k] = f
    print(f'  {k}: {len(f)} 个唯一函数指纹')

# 2) 聚类:每个指纹出现在哪些型号
print()
print('=== 指纹聚类(跨型号出现次数)===')
cluster = defaultdict(dict)
for k, f in FP.items():
    for h, (off, n, _) in f.items():
        cluster[h][k] = (off, n)

dist = Counter(len(v) for v in cluster.values())
print(f'  唯一指纹总数: {len(cluster)}')
for c in sorted(dist, reverse=True):
    print(f'    出现在 {c} 个型号的指纹: {dist[c]} 个')

# 3) 全 6 型号共享
all6 = {h: v for h, v in cluster.items() if len(v) == len(D)}
print()
print(f'=== 全部 {len(D)} 个型号共享的函数: {len(all6)} 个 ===')

# 输出统一函数编号表
OUT = r'.\analysis\lens\lens_function_ids.txt'
rows = []
for i, (h, v) in enumerate(sorted(all6.items(), key=lambda kv: -max(x[1] for x in kv[1].values())), 1):
    n = max(x[1] for x in v.values())
    locs = ' '.join(f'{k}:0x{v[k][0]:06X}' for k in D if k in v)
    rows.append(f'FN{i:04d}  {h}  {n:>4} insn  {locs}')

lines = []
lines.append('# L 卡口镜头固件:跨型号通用函数编号表')
lines.append(f'# 由 6 个型号的地址无关函数指纹聚类得出')
lines.append(f'# 全部 6 型号共享:{len(all6)} 个函数')
lines.append('#')
lines.append('# 格式:编号  指纹  指令数  各型号文件偏移')
lines.append('')
lines.extend(rows)
with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(lines))
print(f'  已写 {OUT}')

print()
print('=== 全部 6 型号共享函数 Top 12(按规模)===')
print(f'  {"编号":>7}  {"指纹":>16}  {"指令":>5}  位置示例')
for i, (h, v) in enumerate(sorted(all6.items(), key=lambda kv: -max(x[1] for x in kv[1].values()))[:12], 1):
    n = max(x[1] for x in v.values())
    first = next(iter(v))
    print(f'  FN{i:04d}  {h}  {n:>5}  {first}:0x{v[first][0]:06X}')

# 4) 反汇编最大的共享函数
print()
print('=== 最大的共享函数反汇编(前 60 条)===')
best = max(all6.items(), key=lambda kv: max(x[1] for x in kv[1].values()))
h, v = best
k0 = next(iter(v))
off, n, insns = FP[k0][h]
print(f'  指纹 {h},{n} 指令,样本 {k0} @0x{off:06X},出现在 {len(v)} 个型号')
for ins in insns[:60]:
    print(f'    0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')

with open(r'.\analysis\lens\lens_shared_biggest.asm',
          'w', encoding='utf-8', newline='\n') as f:
    f.write(f'# 最大共享函数 指纹={h} {n} insn 样本={k0} @0x{off:06X}\n')
    f.write(f'# 出现在 {len(v)}/{len(D)} 个型号: ' + ', '.join(f'{k}@0x{v[k][0]:06X}' for k in D if k in v) + '\n\n')
    for ins in insns:
        f.write(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}\n')
print()
print('[已写 analysis/lens/lens_shared_biggest.asm]')
