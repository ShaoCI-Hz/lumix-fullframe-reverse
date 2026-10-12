import os
import re

FW = r'firmware'
N = {'4001': 'S-R24105(变焦)', '4002': 'S-R70200(变焦)', '4006': 'S-E2470(变焦)',
     '4003': 'S-X50(定焦)', '400C': 'S-S85(定焦)', '400E': 'S-S50(定焦)'}
S = {}
for k in N:
    p = os.path.join(FW, k + 'V020.plf')
    if os.path.exists(p):
        S[k] = open(p, 'rb').read()


def varnames(d):
    s = set()
    for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{5,40}', d[:0x40000]):
        t = m.group().decode()
        if re.search(r'[A-Z]', t) and re.search(r'[a-z]', t):
            s.add(t)
    return s


V = {k: varnames(d) for k, d in S.items()}
print('=== 变量名数量 ===')
for k, v in V.items():
    print(f'  {k} {N[k]:22} {len(v):>4} 个')

zoom = ['4001', '4002', '4006']
prime = ['4003', '400C', '400E']
print()
print('=== 变焦组(4001/4002/4006)的交集 ===')
zi = set.intersection(*[V[k] for k in zoom if k in V])
zu = set.union(*[V[k] for k in zoom if k in V])
print(f'  交集 {len(zi)} 个,Jaccard = {len(zi)/len(zu):.3f}')

print()
print('=== 定焦组(4003/400C/400E)的交集 ===')
pi = set.intersection(*[V[k] for k in prime if k in V])
pu = set.union(*[V[k] for k in prime if k in V])
print(f'  交集 {len(pi)} 个,Jaccard = {len(pi)/max(len(pu),1):.3f}')

print()
print('=== 变焦 vs 定焦 ===')
allp = set.union(*[V[k] for k in prime if k in V])
cross = zi & allp
print(f'  变焦共同 ∩ 定焦全体 = {len(cross)} 个')
if cross:
    print(f'  样本: {sorted(cross)[:15]}')

print()
print('=== 变焦组共同变量名的前 30 个 ===')
for x in sorted(zi)[:30]:
    print(f'    {x}')
print(f'  ... 共 {len(zi)} 个')

# 变焦组共同变量名的前缀/模块分布
from collections import Counter
pref = Counter()
for x in zi:
    for pfx in ('OIS', 'Ois', 'Irs', 'Foc', 'Zm', 'Mtr', 'Trk', 'Dbg', 'Log', 'Err', 'Chk', 'Drv', 'Pos', 'Adj', 'Rest', 'Move', 'Tar', 'Ind'):
        if x.startswith(pfx):
            pref[pfx] += 1
            break
    else:
        pref['(其他)'] += 1
print()
print('=== 变焦共同变量名的模块前缀分布 ===')
for p, c in pref.most_common(20):
    print(f'    {p:10} {c}')
