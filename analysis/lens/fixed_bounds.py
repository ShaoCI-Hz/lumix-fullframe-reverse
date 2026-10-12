import os
import struct
from collections import Counter

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

BASE = 0x08000000
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
print(f'4001V020.plf: {n:,} B,基址 0x{BASE:08X}')


def is_prologue(off):
    if off + 2 > n:
        return False
    if d[off + 1] == 0xB5:
        return True
    if d[off:off + 2] == b'\x2d\xe9' and off + 4 <= n:
        return bool(struct.unpack_from('<H', d, off + 2)[0] & 0x4000)
    return False


def get_branch_target(ins):
    """返回分支/调用目标(文件偏移),无则 None"""
    m, op = ins.mnemonic, ins.op_str
    if m in ('bl', 'blx', 'b') or m.startswith('b'):
        if op.startswith('#'):
            try:
                return int(op[1:], 16) & ~1
            except Exception:
                return None
    if m in ('cbz', 'cbnz'):
        parts = op.split(',')
        if len(parts) >= 2 and parts[1].strip().startswith('#'):
            try:
                return int(parts[1].strip()[1:], 16) & ~1
            except Exception:
                return None
    return None


# ---------- 1) 种子:BL 目标 ∩ 序言(同 §22)----------
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
print(f'种子(BL 目标 ∩ 序言): {len(seeds)}')

# ---------- 2) ★ 修正版:函数内扫描(B 分支不重新开函数)----------
print()
print('=== 修正版:函数内控制流(分支目标只在同一函数内跟随)===')
FUNC_MAX = 0x2000     # 单函数最大范围 8KB(合理上限)
funcs = {}


def scan_function(entry):
    """从 entry 扫描,分支目标只在本函数范围内跟随;返回 (覆盖地址集, 规模, BL目标)"""
    covered = {}
    work = [entry]
    bls = []
    lo, hi = entry, entry
    steps = 0
    while work and steps < 20000:
        addr = work.pop()
        if addr in covered:
            continue
        if addr < 0 or addr + 2 > n:
            continue
        # 边界守卫: 不得偏离入口超过 FUNC_MAX
        if abs(addr - entry) > FUNC_MAX:
            continue
        cur = addr
        while cur < n - 4 and steps < 20000:
            steps += 1
            got = False
            for ins in md.disasm(d[cur:cur + 4], cur):
                got = True
                covered[cur] = ins
                lo = min(lo, cur)
                hi = max(hi, cur)
                m, op = ins.mnemonic, ins.op_str
                if m in ('bl', 'blx'):
                    t = get_branch_target(ins)
                    if t is not None:
                        bls.append(t)          # 记录调用,但不去扫描目标
                    # 调用返回后继续
                elif m.startswith('b'):
                    t = get_branch_target(ins)
                    if t is not None and abs(t - entry) <= FUNC_MAX:
                        work.append(t)         # 分支目标:同一函数内
                    cur += ins.size
                    break                      # 无条件分支后串行继续无意义
                if (m == 'pop' and 'pc' in op) or (m == 'bx' and 'lr' in op):
                    steps = 20000
                    break
                cur += ins.size
                break
            if not got:
                break
            if steps >= 20000:
                break
    return covered, len(covered), bls


tot_instr = 0
bad = 0
for s in seeds:
    cov, cnt, bls = scan_function(s)
    if cnt < 3:
        bad += 1
        continue
    funcs[s] = (cov, cnt, bls)
    tot_instr += cnt

print(f'  函数数(≥3 指令): {len(funcs)}  (丢弃过短 {bad})')
print(f'  合计指令(含重叠): {tot_instr:,}')
sizes = sorted(v[1] for v in funcs.values())
print(f'  规模中位数: {sizes[len(sizes)//2]}   均值: {tot_instr/max(len(funcs),1):.1f}')
print(f'  最大规模  : {sizes[-1]}   最小: {sizes[0]}')

print()
print('=== 规模分布(修正后,对比 §23 的 2469 指令异常)===')
buckets = Counter()
for sz in sizes:
    if sz < 16:
        buckets['0-15'] += 1
    elif sz < 32:
        buckets['16-31'] += 1
    elif sz < 64:
        buckets['32-63'] += 1
    elif sz < 128:
        buckets['64-127'] += 1
    elif sz < 256:
        buckets['128-255'] += 1
    elif sz < 512:
        buckets['256-511'] += 1
    else:
        buckets['512+'] += 1
for b in ('0-15', '16-31', '32-63', '64-127', '128-255', '256-511', '512+'):
    if buckets[b]:
        print(f'    {b:>8} 指令: {buckets[b]:>4} 个')

print()
print('=== Top 8 最长函数(修正后)===')
for s, (cov, cnt, bls) in sorted(funcs.items(), key=lambda kv: -kv[1][1])[:8]:
    print(f'    0x{s:06X}  {cnt:>5} 指令  (运行地址 0x{BASE+s:08X})')

print()
print('=== 无重叠的覆盖集(所有函数合起来)===')
union = set()
for cov, cnt, bls in funcs.values():
    union |= set(cov.keys())
print(f'  唯一覆盖地址: {len(union):,} 条指令')
print(f'  占文件字节  : {len(union)*2:,} / {n:,} = {len(union)*2/n:.1%}')
print(f'  (对比 §23 可达性集 71,507 条)')

print()
print('=== 调用图:BL 目标命中函数入口 ===')
entry_set = set(funcs.keys())
tot, hit = 0, 0
for s, (cov, cnt, bls) in funcs.items():
    for t in bls:
        tot += 1
        if t in entry_set:
            hit += 1
print(f'  {hit}/{tot} = {hit/max(tot,1):.1%}')

with open(r'.\analysis\lens\lens_fixed_bounds.txt',
          'w', encoding='utf-8', newline='\n') as f:
    f.write('# 修正后的函数边界(函数内控制流,分支不跨函数)\n')
    f.write(f'# 函数数 {len(funcs)},唯一覆盖 {len(union):,} 指令 = {len(union)*2/n:.1%} 文件\n\n')
    f.write(f'# {"入口":>10} {"运行地址":>12} {"规模":>6} {"BL数":>6}\n')
    for s, (cov, cnt, bls) in sorted(funcs.items(), key=lambda kv: -kv[1][1]):
        f.write(f'  0x{s:06X}  0x{BASE+s:08X}  {cnt:>6} {len(bls):>6}\n')
print()
print('[已写 analysis/lens/lens_fixed_bounds.txt]')
