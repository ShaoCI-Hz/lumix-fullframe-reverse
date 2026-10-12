import os
import struct
from collections import Counter, defaultdict

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

BASE = 0x08000000
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
print(f'4001V020.plf: {n:,} B (0x{n:X}),基址 0x{BASE:08X}')


def is_prologue(off):
    if off + 2 > n:
        return False
    if d[off + 1] == 0xB5:
        return True
    if d[off:off + 2] == b'\x2d\xe9' and off + 4 <= n:
        return bool(struct.unpack_from('<H', d, off + 2)[0] & 0x4000)
    return False


def branches(ins):
    """返回 (直接目标, 是否调用)"""
    m, op = ins.mnemonic, ins.op_str
    if m in ('bl', 'blx'):
        if op.startswith('#'):
            try:
                return int(op[1:], 16) & ~1, True
            except Exception:
                pass
        return None, True
    if m.startswith('b'):
        if op.startswith('#'):
            try:
                return int(op[1:], 16) & ~1, False
            except Exception:
                pass
        if m in ('cbz', 'cbnz'):
            parts = op.split(',')
            if len(parts) >= 2 and parts[1].strip().startswith('#'):
                try:
                    return int(parts[1].strip()[1:], 16) & ~1, False
                except Exception:
                    pass
    return None, False


# ---------- §22 的 133 个严格种子 ----------
allbl = set()
a = 0
while a < n - 4:
    got = False
    for ins in md.disasm(d[a:a + 4], a):
        got = True
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                t = int(ins.op_str[1:], 16) & ~1
                if 0 <= t < n:
                    allbl.add(t)
            except Exception:
                pass
        break
    a += 2
seeds = sorted(t for t in allbl if is_prologue(t))
print(f'严格种子: {len(seeds)}')

# ---------- ★ 正确方法 ----------
# 阶段 A:不可达代码不进入入口集 —— 从种子出发,只在"代码流"中收集 BL 目标
# 阶段 B:每次调用独立处理(不把调用者的分支集带过去),用返回栈判定边界
print()
print('=== 阶段 A+B:代码流内收集入口 + 返回栈定边界 ===')

code_addr = set()        # 已确认为代码的地址
entries = set(seeds)
func_info = {}
deferred = list(seeds)   # 待分析的函数入口
MAXF = 3000


def analyze_func(entry):
    """独立分析一个函数:分支集独立,遇返回且分支集空 => 结束"""
    cov = {}
    work = [entry]
    bls = []
    steps = 0
    progressed = True
    while work and steps < MAXF and progressed:
        progressed = False
        addr = work.pop()
        if addr in cov or addr < 0 or addr + 2 > n:
            continue
        cur = addr
        while cur < n - 4 and steps < MAXF:
            steps += 1
            got = False
            for ins in md.disasm(d[cur:cur + 4], cur):
                got = True
                cov[cur] = ins
                t, iscall = branches(ins)
                m, op = ins.mnemonic, ins.op_str
                if iscall:
                    if t is not None:
                        bls.append(t)
                    cur += ins.size
                elif m.startswith('b') and t is not None:
                    work.append(t)          # 函数内分支
                    cur += ins.size
                elif (m == 'pop' and 'pc' in op) or (m == 'bx' and 'lr' in op):
                    # 函数结束点之一;若还有未走的分支目标,继续
                    if work:
                        progressed = True
                        break
                    steps = MAXF
                    break
                else:
                    cur += ins.size
                break
            if not got:
                break
            if steps >= MAXF:
                break
    return cov, bls


# 迭代:分析 -> 遇到新的"有序言"BL 目标就加入待分析
processed = set()
queue = list(seeds)
rounds = 0
while queue and rounds < 100:
    rounds += 1
    nq = []
    for e in queue:
        if e in processed:
            continue
        processed.add(e)
        cov, bls = analyze_func(e)
        if len(cov) < 3:
            continue
        func_info[e] = (cov, bls)
        code_addr |= set(cov.keys())
        for t in set(bls):
            if t not in processed and t not in nq:
                # ★ 关键:只接受"有序言"的目标为新函数入口(避免数据区伪目标)
                if is_prologue(t):
                    entries.add(t)
                    nq.append(t)
    queue = nq
    if rounds <= 5:
        print(f'  第 {rounds} 轮: 新增待分析 {len(nq)} (累计函数 {len(func_info)})')

print(f'  函数数: {len(func_info)}')
print(f'  代码地址(并集): {len(code_addr):,}')

# 质量指标
sizes = sorted(len(v[0]) for v in func_info.values())
print()
print('=== 质量指标 ===')
print(f'  规模中位数: {sizes[len(sizes)//2]}')
print(f'  规模均值  : {sum(sizes)/len(sizes):.1f}')
print(f'  规模最大  : {sizes[-1]}')
print(f'  覆盖字节  : {len(code_addr)*2:,} / {n:,} = {len(code_addr)*2/n:.1%}')

# 重叠
ov = Counter()
for cov, _ in func_info.values():
    for ad in cov:
        ov[ad] += 1
multi = sum(1 for v in ov.values() if v > 1)
print(f'  重叠率    : {multi}/{len(ov)} = {multi/max(len(ov),1):.1%}')

# 自洽性:BL 目标命中"有序言"入口集
es = set(func_info.keys())
tot, hit = 0, 0
for e, (cov, bls) in func_info.items():
    for t in bls:
        tot += 1
        if t in es:
            hit += 1
print(f'  BL 命中有序言入口: {hit}/{tot} = {hit/max(tot,1):.1%}')
# 另一个更有意义的指标:BL 目标是否落在"已确认代码"内
incode = sum(1 for e, (cov, bls) in func_info.items() for t in bls if t in code_addr)
print(f'  BL 目标落在代码内: {incode}/{tot} = {incode/max(tot,1):.1%}  ← 更客观')

print()
print('=== Top 8 最长 ===')
for e, (cov, bls) in sorted(func_info.items(), key=lambda kv: -len(kv[1][0]))[:8]:
    print(f'    0x{e:06X}  {len(cov):>5} 指令  (0x{BASE+e:08X})')

print()
print('=== 规模分布 ===')
b = Counter()
for sz in sizes:
    if sz < 16:
        b['0-15'] += 1
    elif sz < 32:
        b['16-31'] += 1
    elif sz < 64:
        b['32-63'] += 1
    elif sz < 128:
        b['64-127'] += 1
    elif sz < 256:
        b['128-255'] += 1
    else:
        b['256+'] += 1
for k in ('0-15', '16-31', '32-63', '64-127', '128-255', '256+'):
    if b[k]:
        print(f'    {k:>8}: {b[k]:>4}')

with open(r'.\analysis\lens\lens_correct_method.txt',
          'w', encoding='utf-8', newline='\n') as f:
    f.write('# 正确方法:代码流内收集入口 + 返回栈定边界\n')
    f.write(f'# 函数数 {len(func_info)},代码地址 {len(code_addr):,} = {len(code_addr)*2/n:.1%} 文件\n')
    f.write(f'# 重叠率 {multi/max(len(ov),1):.1%},BL 落代码内 {incode/max(tot,1):.1%}\n\n')
    f.write(f'# {"入口":>10} {"运行地址":>12} {"规模":>6} {"BL数":>6}\n')
    for e, (cov, bls) in sorted(func_info.items(), key=lambda kv: -len(kv[1][0])):
        f.write(f'  0x{e:06X}  0x{BASE+e:08X}  {len(cov):>6} {len(bls):>6}\n')
print()
print('[已写 analysis/lens/lens_correct_method.txt]')
