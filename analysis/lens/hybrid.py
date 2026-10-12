import os
import struct
from collections import Counter, defaultdict

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


def target_of(ins):
    m, op = ins.mnemonic, ins.op_str
    if m.startswith('b'):
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


# ---------- 1) 全局收集 BL 目标(作为入口候选)----------
print()
print('=== 1) 收集全部 BL/BLX 目标(作为函数入口候选)===')
allbl = Counter()
a = 0
while a < n - 4:
    got = False
    for ins in md.disasm(d[a:a + 4], a):
        got = True
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                t = int(ins.op_str[1:], 16) & ~1
                if 0 <= t < n:
                    allbl[t] += 1
            except Exception:
                pass
        break
    a += 2
entries = sorted(allbl)
print(f'  BL 目标入口候选: {len(entries)}')
print(f'  其中自身有序言的: {sum(1 for t in entries if is_prologue(t))}')

# ---------- 2) 从每个入口做函数内扫描(分支不跨函数)----------
print()
print('=== 2) 函数内扫描(每个 BL 目标都当作入口)===')
MAXSPAN = 0x400     # 分支偏离入口超过 1KB 就不跟随(收紧,防跨界)
funcs = {}


def scan(entry):
    covered = {}
    work = [entry]
    bls = []
    steps = 0
    while work and steps < 8000:
        addr = work.pop()
        if addr in covered or addr < 0 or addr + 2 > n:
            continue
        if abs(addr - entry) > MAXSPAN:
            continue
        cur = addr
        while cur < n - 4 and steps < 8000:
            steps += 1
            got = False
            for ins in md.disasm(d[cur:cur + 4], cur):
                got = True
                covered[cur] = ins
                m, op = ins.mnemonic, ins.op_str
                if m in ('bl', 'blx'):
                    t = target_of(ins)
                    if t is not None:
                        bls.append(t)
                    cur += ins.size
                elif m.startswith('b'):
                    t = target_of(ins)
                    if t is not None and abs(t - entry) <= MAXSPAN:
                        work.append(t)
                    cur += ins.size
                elif m == 'pop' and 'pc' in op:
                    steps = 8000
                elif m == 'bx' and 'lr' in op:
                    steps = 8000
                else:
                    cur += ins.size
                break
            if not got:
                break
            if steps >= 8000:
                break
    return covered, bls


for e in entries:
    cov, bls = scan(e)
    if len(cov) >= 3:
        funcs[e] = (cov, bls)

print(f'  有效函数(≥3 指令): {len(funcs)}')

union = set()
overlap = Counter()
for cov, _ in funcs.values():
    for ad in cov:
        union.add(ad)
        overlap[ad] += 1

sizes = sorted(len(v[0]) for v in funcs.values())
print()
print('=== 3) 结果 ===')
print(f'  函数数        : {len(funcs)}')
print(f'  唯一覆盖指令  : {len(union):,}')
print(f'  占文件字节    : {len(union)*2:,} / {n:,} = {len(union)*2/n:.1%}')
print(f'  规模中位数    : {sizes[len(sizes)//2]}')
print(f'  规模均值      : {sum(sizes)/len(sizes):.1f}')
print(f'  规模最大      : {sizes[-1]}')

print()
print('  规模分布:')
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
        print(f'    {k:>8}: {b[k]:>4} 个')

# 重叠分析:同一地址被几个函数覆盖
multi = sum(1 for ad, c in overlap.items() if c > 1)
print()
print(f'  被多个函数覆盖的地址: {multi:,} / {len(union):,} = {multi/len(union):.1%}')
print(f'  (重叠率高说明入口集中/有伪入口)')

print()
print('=== 4) 调用图自洽性 ===')
es = set(funcs.keys())
tot, hit = 0, 0
for e, (cov, bls) in funcs.items():
    for t in bls:
        tot += 1
        if t in es:
            hit += 1
print(f'  BL 目标命中入口集: {hit}/{tot} = {hit/max(tot,1):.1%}')
print(f'  (对比 §22 严格 6.9% / §23 可达 98.9%[部分自证])')

print()
print('=== 5) Top 8 最长函数 ===')
for e, (cov, bls) in sorted(funcs.items(), key=lambda kv: -len(kv[1][0]))[:8]:
    print(f'    0x{e:06X}  {len(cov):>5} 指令  运行地址 0x{BASE+e:08X}')

with open(r'.\analysis\lens\lens_hybrid_funcs.txt',
          'w', encoding='utf-8', newline='\n') as f:
    f.write('# 融合方法:全部 BL 目标作入口 + 函数内扫描(分支不跨函数)\n')
    f.write(f'# 函数数 {len(funcs)},唯一覆盖 {len(union):,} 指令 = {len(union)*2/n:.1%} 文件\n\n')
    f.write(f'# {"入口":>10} {"运行地址":>12} {"规模":>6} {"BL数":>6}\n')
    for e, (cov, bls) in sorted(funcs.items(), key=lambda kv: -len(kv[1][0])):
        f.write(f'  0x{e:06X}  0x{BASE+e:08X}  {len(cov):>6} {len(bls):>6}\n')
print()
print('[已写 analysis/lens/lens_hybrid_funcs.txt]')
