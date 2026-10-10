import os
import re

FW = r'firmware'
N = {'4001': 'S-R24105(鍙樼劍)', '4002': 'S-R70200(鍙樼劍)', '4006': 'S-E2470(鍙樼劍)',
     '4003': 'S-X50(瀹氱劍)', '400C': 'S-S85(瀹氱劍)', '400E': 'S-S50(瀹氱劍)'}
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
print('=== 鍙橀噺鍚嶆暟閲?===')
for k, v in V.items():
    print(f'  {k} {N[k]:22} {len(v):>4} 涓?)

zoom = ['4001', '4002', '4006']
prime = ['4003', '400C', '400E']
print()
print('=== 鍙樼劍缁?4001/4002/4006)鐨勪氦闆?===')
zi = set.intersection(*[V[k] for k in zoom if k in V])
zu = set.union(*[V[k] for k in zoom if k in V])
print(f'  浜ら泦 {len(zi)} 涓?Jaccard = {len(zi)/len(zu):.3f}')

print()
print('=== 瀹氱劍缁?4003/400C/400E)鐨勪氦闆?===')
pi = set.intersection(*[V[k] for k in prime if k in V])
pu = set.union(*[V[k] for k in prime if k in V])
print(f'  浜ら泦 {len(pi)} 涓?Jaccard = {len(pi)/max(len(pu),1):.3f}')

print()
print('=== 鍙樼劍 vs 瀹氱劍 ===')
allp = set.union(*[V[k] for k in prime if k in V])
cross = zi & allp
print(f'  鍙樼劍鍏卞悓 鈭?瀹氱劍鍏ㄤ綋 = {len(cross)} 涓?)
if cross:
    print(f'  鏍锋湰: {sorted(cross)[:15]}')

print()
print('=== 鍙樼劍缁勫叡鍚屽彉閲忓悕鐨勫墠 30 涓?===')
for x in sorted(zi)[:30]:
    print(f'    {x}')
print(f'  ... 鍏?{len(zi)} 涓?)

# 鍙樼劍缁勫叡鍚屽彉閲忓悕鐨勫墠缂€/妯″潡鍒嗗竷
from collections import Counter
pref = Counter()
for x in zi:
    for pfx in ('OIS', 'Ois', 'Irs', 'Foc', 'Zm', 'Mtr', 'Trk', 'Dbg', 'Log', 'Err', 'Chk', 'Drv', 'Pos', 'Adj', 'Rest', 'Move', 'Tar', 'Ind'):
        if x.startswith(pfx):
            pref[pfx] += 1
            break
    else:
        pref['(鍏朵粬)'] += 1
print()
print('=== 鍙樼劍鍏卞悓鍙橀噺鍚嶇殑妯″潡鍓嶇紑鍒嗗竷 ===')
for p, c in pref.most_common(20):
    print(f'    {p:10} {c}')
