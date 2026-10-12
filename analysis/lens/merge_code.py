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


def is_pro(off):
    return (off + 2 <= n and d[off + 1] == 0xB5) or (off + 4 <= n and d[off:off + 2] == b'\x2d\xe9'
            and struct.unpack_from('<H', d, off + 2)[0] & 0x4000)


def tgt(ins):
    m, op = ins.mnemonic, ins.op_str
    if m in ('bl', 'blx', 'b') or m.startswith('b'):
        if op.startswith('#'):
            try:
                return int(op[1:], 16) & ~1, m in ('bl', 'blx')
            except Exception:
                return None, False
        if m in ('cbz', 'cbnz'):
            p = op.split(',')
            if len(p) >= 2 and p[1].strip().startswith('#'):
                try:
                    return int(p[1].strip()[1:], 16) & ~1, False
                except Exception:
                    return None, False
    return None, False


# ---------- 方法 A:可达性(§23 复现,精简)----------
def method_A():
    allbl = set()
    a = 0
    while a < n - 4:
        for ins in md.disasm(d[a:a + 4], a):
            if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
                try:
                    t = int(ins.op_str[1:], 16) & ~1
                    if 0 <= t < n:
                        allbl.add(t)
                except Exception:
                    pass
            break
        a += 2
    seeds = [t for t in allbl if is_pro(t)]
    code, work, seen = set(), list(seeds), set()
    while work:
        s = work.pop()
        if s in seen:
            continue
        seen.add(s)
        cur = s
        steps = 0
        while cur < n - 4 and steps < 4000:
            steps += 1
            got = False
            for ins in md.disasm(d[cur:cur + 4], cur):
                got = True
                code.add(cur)
                t, iscall = tgt(ins)
                m, op = ins.mnemonic, ins.op_str
                if t is not None:
                    if iscall:
                        if t not in seen and is_pro(t):
                            work.append(t)
                    else:
                        if t not in seen:
                            work.append(t)
                if (m == 'pop' and 'pc' in op) or (m == 'bx' and 'lr' in op):
                    steps = 4000
                    break
                cur += ins.size
                break
            if not got or steps >= 4000:
                break
    return code


# ---------- 方法 B:结束点切段(§26 复现)----------
def method_B():
    ends = []
    for off in range(0, n - 4, 2):
        got = None
        for ins in md.disasm(d[off:off + 4], off):
            got = ins
            break
        if got and ((got.mnemonic == 'bx' and 'lr' in got.op_str) or
                    (got.mnemonic in ('pop', 'pop.w') and 'pc' in got.op_str)):
            ends.append(off + got.size)
    ends = sorted(set(ends))
    code = set()
    for i in range(1, len(ends)):
        s, e = ends[i - 1], ends[i]
        if e <= s or (e - s) > 0x2000:
            continue
        cur, ok = s, False
        while cur < e:
            got = False
            for ins in md.disasm(d[cur:cur + 4], cur):
                got = True
                cur += ins.size
                if cur == e:
                    ok = True
                break
            if not got or cur > e:
                break
            if ok:
                break
        if ok:
            code.update(range(s, e, 2))
    return code


print()
print('=== 运行两种方法 ===')
A = method_A()
print(f'  A 可达性(种子+控制流)  : {len(A):,} 指令 = {len(A)*2/n:.1%}')
B = method_B()
print(f'  B 结束点切段(无种子)    : {len(B):,} 指令 = {len(B)*2/n:.1%}')

inter = A & B
union = A | B
print()
print('=== 重合度分析 ===')
print(f'  A∩B : {len(inter):,}')
print(f'  A∪B : {len(union):,}  = {len(union)*2/n:.1%} 文件')
print(f'  A 独有: {len(A - B):,}')
print(f'  B 独有: {len(B - A):,}')
print(f'  Jaccard = {len(inter)/len(union):.3f}')

print()
print('=== ★ 合并集(最大可信代码区域)===')
print(f'  指令数: {len(union):,}')
print(f'  字节数: {len(union)*2:,} / {n:,} = {len(union)*2/n:.1%}')
print(f'  对比 §23 单独: 71,507 / 36.6%')
print(f'  提升: +{len(union)-71507:,} 指令')

# 合并集中的函数入口(B 方法给出去掉的序言约束后的入口)
ents = Counter()
for s in union:
    if is_pro(s):
        ents[s] += 1
print()
print(f'  合并集中的"有序言位置": {len(ents):,}')
print(f'  → 这些是最可靠的函数入口候选(不经 BL 验证)')

# 分布:代码区在文件中的位置
print()
print('=== 代码区在文件中的分布(每 32KB)===')
for base in range(0, n, 0x8000):
    c = sum(1 for a in union if base <= a < base + 0x8000)
    tot = min(0x8000, n - base) // 2
    bar = '#' * int(c / max(tot, 1) * 40)
    print(f'    0x{base:06X}  {c:>6}/{tot:<6} {c/max(tot,1):>5.1%}  {bar}')

with open(r'.\analysis\lens\lens_merged_code.txt',
          'w', encoding='utf-8', newline='\n') as f:
    f.write('# 合并代码区域(A 可达性 ∪ B 结束点切段)\n')
    f.write(f'# 指令 {len(union):,} = {len(union)*2/n:.1%} 文件\n')
    f.write(f'# A(可达) {len(A):,}  B(切段) {len(B):,}  交集 {len(inter):,}  Jaccard {len(inter)/len(union):.3f}\n\n')
    f.write('# 连续区间列表(起止,含方法来源)\n')
    srt = sorted(union)
    st = srt[0]
    pv = srt[0]
    for a in srt[1:] + [None]:
        if a is None or a != pv + 2:
            f.write(f'  0x{st:06X}..0x{pv+2:06X}  {(pv+2-st)//2:>6} 指令\n')
            st = a
        pv = a if a is not None else pv
print()
print('[已写 analysis/lens/lens_merged_code.txt]')
