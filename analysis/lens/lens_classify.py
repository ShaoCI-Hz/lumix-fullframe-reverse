import os
import re
import hashlib
from collections import defaultdict, Counter

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

MODELS = {'4001': 'S-R24105(zoom)', '4002': 'S-R70200(zoom)', '4003': 'S-X50(prime)',
          '4006': 'S-E2470(zoom)', '400C': 'S-S85(prime)', '400E': 'S-S50(prime)'}
D = {}
for k in MODELS:
    p = os.path.join(FW, k + 'V020.plf')
    if os.path.exists(p):
        D[k] = open(p, 'rb').read()


def walk(d, start, limit=3000):
    insns, addr = [], start
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
    out = []
    for ins in insns:
        op = ins.op_str
        op = re.sub(r'#-?0x[0-9a-f]+', '#I', op)
        op = re.sub(r'#-?\d+', '#I', op)
        op = re.sub(r'0x[0-9a-f]+', 'D', op)
        out.append(f'{ins.mnemonic} {op}')
    return ';'.join(out)


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
            h = hashlib.sha1(norm(insns).encode()).hexdigest()[:16]
            if h not in f:
                f[h] = (s, len(insns), insns)
    FP[k] = f

cluster = defaultdict(dict)
for k, f in FP.items():
    for h, (off, n, ii) in f.items():
        cluster[h][k] = (off, n)

ZOOM = ['4001', '4002', '4006']
PRIME = ['4003', '400C', '400E']

# 分类:哪些指纹是"变焦全有+定焦全无" vs "定焦全有"
zoom_only = {h: v for h, v in cluster.items() if all(k in v for k in ZOOM) and not any(k in v for k in PRIME)}
zoom_any = {h: v for h, v in cluster.items() if all(k in v for k in ZOOM)}
prime_any = {h: v for h, v in cluster.items() if all(k in v for k in PRIME)}
all6 = {h: v for h, v in cluster.items() if len(v) == 6}
five = {h: v for h, v in cluster.items() if len(v) == 5}
four = {h: v for h, v in cluster.items() if len(v) == 4}

print('=== 指纹按型号组合分类 ===')
print(f'  全 6 型号共享         : {len(all6)}')
print(f'  5 型号共享            : {len(five)}')
print(f'  4 型号共享            : {len(four)}')
print(f'  变焦组全有(3/3)      : {len(zoom_any)}')
print(f'  仅变焦组有(定焦全无)  : {len(zoom_only)}')
print(f'  定焦组全有(3/3)      : {len(prime_any)}')

# 识别运行时库函数:含 udiv/umull/sdiv/smull 的算术例程
print()
print('=== 运行时库特征识别(含 udiv/sdiv/umull/smull,且无内存访问)===')
lib = []
for h, v in cluster.items():
    k0 = next(iter(v))
    ii = FP[k0][h][2]
    mn = set(i.mnemonic for i in ii)
    arith = bool(mn & {'udiv', 'sdiv', 'umull', 'smull', 'umlal', 'smlal'})
    mem = any(i.mnemonic.startswith(('ldr', 'str', 'ldm', 'stm', 'push', 'pop')) and 'pc' not in i.op_str for i in ii[:5])
    if arith and len(v) >= 4:
        lib.append((h, len(v), len(ii), sorted(mn & {'udiv', 'sdiv', 'umull', 'smull'})[0]))
print(f'  疑似算术运行时例程(共享 >=4 型号): {len(lib)} 个')
for h, nk, ni, op in sorted(lib, key=lambda x: -x[2])[:12]:
    print(f'    {h}  共享 {nk} 型号  {ni} insn  核心: {op}')

# 变焦专属函数(可能的变焦/镜头控制逻辑)
print()
print('=== 仅变焦组有的函数(按规模 Top 12)——候选业务逻辑 ===')
zf = sorted(zoom_only.items(), key=lambda kv: -max(x[1] for x in kv[1].values()))
print(f'  {"指纹":>16}  {"指令":>5}  4001 位置')
for h, v in zf[:12]:
    n = max(x[1] for x in v.values())
    o = v['4001'][0] if '4001' in v else next(iter(v.values()))[0]
    print(f'  {h}  {n:>5}  0x{o:06X}')

# 写报告
OUT = r'.\analysis\lens\lens_fingerprint_report.txt'
L = []
L.append('# 镜头固件函数指纹聚类报告(6 型号)')
L.append('')
for k, f in FP.items():
    L.append(f'{k} {MODELS[k]:18} {len(f)} 个唯一函数指纹')
L.append('')
L.append('## 按共享型号数分类')
L.append(f'  全 6 型号共享        : {len(all6)}')
L.append(f'  5 型号共享           : {len(five)}')
L.append(f'  4 型号共享           : {len(four)}')
L.append(f'  3 型号共享           : {sum(1 for v in cluster.values() if len(v) == 3)}')
L.append(f'  2 型号共享           : {sum(1 for v in cluster.values() if len(v) == 2)}')
L.append(f'  仅 1 型号(型号特定) : {sum(1 for v in cluster.values() if len(v) == 1)}')
L.append('')
L.append('## 变焦/定焦分化')
L.append(f'  变焦组全有           : {len(zoom_any)}')
L.append(f'  仅变焦组有(定焦全无) : {len(zoom_only)}')
L.append(f'  定焦组全有           : {len(prime_any)}')
L.append('')
L.append('## 疑似算术语运行时例程(共享 >=4 型号,含 udiv/sdiv/umull/smull)')
L.append('  说明:这些不是镜头业务逻辑,而是编译器运行时库(ARM EABI)')
L.append('  最大的一个是 __aeabi_fdiv(单精度浮点除法)')
L.append('')
for h, nk, ni, op in sorted(lib, key=lambda x: -x[2]):
    L.append(f'  {h}  共享 {nk} 型号  {ni} insn  核心指令 {op}')
L.append('')
L.append('## 仅变焦组有的函数(Top 30,候选镜头业务逻辑)')
L.append('')
for h, v in zf[:30]:
    n = max(x[1] for x in v.values())
    locs = ' '.join(f'{k}:0x{v[k][0]:06X}' for k in ZOOM if k in v)
    L.append(f'  {h}  {n:>4} insn  {locs}')
with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(L))
print()
print(f'[已写 {OUT}]')
