import os
import struct

FW = r'firmware'
NAMES = ['4001V020.plf', '4002V020.plf', '4003V020.plf', '4006V020.plf',
         '400CV020.plf', '400EV020.plf']
S = {}
for f in NAMES:
    p = os.path.join(FW, f)
    if os.path.exists(p):
        S[f] = open(p, 'rb').read()
print('=== 可用样本 ===')
for f, d in S.items():
    print(f'  {f}: {len(d):,} B')
print()

# 1) 每个样本的函数序言集合
def prologues(d):
    ps = set()
    for o in range(0, len(d) - 4, 2):
        if d[o + 1] == 0xB5:
            ps.add(o)
        elif d[o:o + 2] == b'\x2d\xe9':
            ps.add(o)
    return ps


P = {f: prologues(d) for f, d in S.items()}
print('=== 1) 各样本序言数量 ===')
for f, ps in P.items():
    print(f'  {f}: {len(ps)} 个序言')

# 2) 共同序言偏移(同一偏移处都有序言 = 共享代码)
print()
print('=== 2) 共同序言偏移(交集)===')
common = set.intersection(*P.values()) if len(P) > 1 else set()
print(f'  全部 {len(P)} 个样本共同拥有的序言偏移: {len(common)} 个')
if common:
    cs = sorted(common)[:20]
    print(f'  前 20 个: {[hex(x) for x in cs]}')

# 3) 两两交集比例
print()
print('=== 3) 两两交集(Jaccard 相似度)===')
keys = list(P.keys())
print(f'  {"A":>12} {"B":>12} {"|A∩B|":>8} {"|A∪B|":>8} {"Jaccard":>8}')
import itertools
for a, b in itertools.combinations(keys, 2):
    inter = len(P[a] & P[b])
    union = len(P[a] | P[b])
    print(f'  {a[:12]:>12} {b[:12]:>12} {inter:>8} {union:>8} {inter/union:>8.3f}')

# 4) 用 512 对齐检查:共同序言是否落在"同一 512 块"里(块级共享)
print()
print('=== 4) 块级共享(512 字节对齐,看有多少块在 3+ 样本中都有序言)===')
from collections import Counter
blk_cnt = Counter()
for f, ps in P.items():
    for o in ps:
        blk_cnt[o // 512] += 1
multi = {b: c for b, c in blk_cnt.items() if c >= 3}
print(f'  在 >=3 个样本中都有序言的 512 块: {len(multi)} 个 (总 {len(blk_cnt)} 块)')
print(f'  占比: {len(multi)/max(len(blk_cnt),1):.1%}')

# 5) 头部字符串(变量名)共享比例 —— 与代码共享对比
print()
print('=== 5) 变量名(字符串)共享比例,用于与代码共享对比 ===')
import re


def varnames(d):
    s = set()
    for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{5,40}', d[:0x20000]):
        t = m.group().decode()
        if re.search(r'[A-Z]', t) and re.search(r'[a-z]', t):
            s.add(t)
    return s


V = {f: varnames(d) for f, d in S.items()}
for f, vs in V.items():
    print(f'  {f}: {len(vs)} 个变量名')
vcommon = set.intersection(*V.values()) if len(V) > 1 else set()
print(f'  全部样本共同拥有: {len(vcommon)} 个')
print(f'  → 变量名 Jaccard: {len(vcommon)/len(set.union(*V.values())):.3f}')
