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
print('=== 鍙敤鏍锋湰 ===')
for f, d in S.items():
    print(f'  {f}: {len(d):,} B')
print()

# 1) 姣忎釜鏍锋湰鐨勫嚱鏁板簭瑷€闆嗗悎
def prologues(d):
    ps = set()
    for o in range(0, len(d) - 4, 2):
        if d[o + 1] == 0xB5:
            ps.add(o)
        elif d[o:o + 2] == b'\x2d\xe9':
            ps.add(o)
    return ps


P = {f: prologues(d) for f, d in S.items()}
print('=== 1) 鍚勬牱鏈簭瑷€鏁伴噺 ===')
for f, ps in P.items():
    print(f'  {f}: {len(ps)} 涓簭瑷€')

# 2) 鍏卞悓搴忚█鍋忕Щ(鍚屼竴鍋忕Щ澶勯兘鏈夊簭瑷€ = 鍏变韩浠ｇ爜)
print()
print('=== 2) 鍏卞悓搴忚█鍋忕Щ(浜ら泦)===')
common = set.intersection(*P.values()) if len(P) > 1 else set()
print(f'  鍏ㄩ儴 {len(P)} 涓牱鏈叡鍚屾嫢鏈夌殑搴忚█鍋忕Щ: {len(common)} 涓?)
if common:
    cs = sorted(common)[:20]
    print(f'  鍓?20 涓? {[hex(x) for x in cs]}')

# 3) 涓や袱浜ら泦姣斾緥
print()
print('=== 3) 涓や袱浜ら泦(Jaccard 鐩镐技搴?===')
keys = list(P.keys())
print(f'  {"A":>12} {"B":>12} {"|A鈭〣|":>8} {"|A鈭狟|":>8} {"Jaccard":>8}')
import itertools
for a, b in itertools.combinations(keys, 2):
    inter = len(P[a] & P[b])
    union = len(P[a] | P[b])
    print(f'  {a[:12]:>12} {b[:12]:>12} {inter:>8} {union:>8} {inter/union:>8.3f}')

# 4) 鐢?512 瀵归綈妫€鏌?鍏卞悓搴忚█鏄惁钀藉湪"鍚屼竴 512 鍧?閲?鍧楃骇鍏变韩)
print()
print('=== 4) 鍧楃骇鍏变韩(512 瀛楄妭瀵归綈,鐪嬫湁澶氬皯鍧楀湪 3+ 鏍锋湰涓兘鏈夊簭瑷€)===')
from collections import Counter
blk_cnt = Counter()
for f, ps in P.items():
    for o in ps:
        blk_cnt[o // 512] += 1
multi = {b: c for b, c in blk_cnt.items() if c >= 3}
print(f'  鍦?>=3 涓牱鏈腑閮芥湁搴忚█鐨?512 鍧? {len(multi)} 涓?(鎬?{len(blk_cnt)} 鍧?')
print(f'  鍗犳瘮: {len(multi)/max(len(blk_cnt),1):.1%}')

# 5) 澶撮儴瀛楃涓?鍙橀噺鍚?鍏变韩姣斾緥 鈥斺€?涓庝唬鐮佸叡浜姣?print()
print('=== 5) 鍙橀噺鍚?瀛楃涓?鍏变韩姣斾緥,鐢ㄤ簬涓庝唬鐮佸叡浜姣?===')
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
    print(f'  {f}: {len(vs)} 涓彉閲忓悕')
vcommon = set.intersection(*V.values()) if len(V) > 1 else set()
print(f'  鍏ㄩ儴鏍锋湰鍏卞悓鎷ユ湁: {len(vcommon)} 涓?)
print(f'  鈫?鍙橀噺鍚?Jaccard: {len(vcommon)/len(set.union(*V.values())):.3f}')
