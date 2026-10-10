import os
import struct
import hashlib
from collections import Counter

FW = r'firmware'
BASE = 0x200
STEP = 0x5C
MODELS = ['S1H__V28.bin', 'S5___V29.bin', 'S1___V24.bin']


def load(fn):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        return None, None
    d = open(p, 'rb').read()
    n = len(d)
    pm = {}
    for i in range(200):
        o = 0x2DC + i * STEP
        if o + STEP > n:
            break
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
            break
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        if flg not in (2, 3):
            break
        pm[nm] = dict(real=BASE + off, size=sz, flg=flg, sha=d[o + 0x2C:o + 0x2C + 32],
                      nonce=d[o + 0x4C:o + 0x4C + 12])
    return d, pm


data = {}
for fn in MODELS:
    d, pm = load(fn)
    if d:
        data[fn] = (d, pm)

# 鏀堕泦鍚勬満鍨嬬殑"鏄庢枃鍏ㄩ浂涓旀湁瀵嗘枃"鍒嗗尯
ks = {}  # (model, name) -> (blob, size, nonce)
for fn, (d, pm) in data.items():
    ks[fn] = {}
    for nm, a in pm.items():
        if a['size'] == 0 or a['real'] + a['size'] > len(d):
            continue
        if hashlib.sha256(bytes(a['size'])).digest() == a['sha']:
            blob = d[a['real']:a['real'] + a['size']]
            if sum(1 for x in blob if x) > 0:
                ks[fn][nm] = (blob, a['size'], a['nonce'])

print('=== 鍚勬満鍨嬪叏闆舵槑鏂囧垎鍖?===')
for fn in ks:
    print(f'  {fn}: {list(ks[fn].keys())}')

print()
print('=== 璺ㄦ満鍨嬪悓 size 鍒嗗尯鐨勫瘑鏂囨瘮杈?keystream 鏄惁鐩稿悓?)===')
# 鎸?size 鍒嗙粍
byname = {}
for fn in ks:
    for nm, (blob, size, nonce) in ks[fn].items():
        byname.setdefault(nm, []).append((fn, blob, size, nonce))

for nm, lst in byname.items():
    if len(lst) < 2:
        continue
    print(f'--- {nm} (鍑虹幇鍦?{len(lst)} 涓満鍨? ---')
    for i in range(len(lst)):
        for j in range(i + 1, len(lst)):
            f1, b1, s1, n1 = lst[i]
            f2, b2, s2, n2 = lst[j]
            m = min(len(b1), len(b2))
            same_len = s1 == s2
            # 鐩哥瓑瀛楄妭姣斾緥
            eq = sum(1 for x, y in zip(b1[:m], b2[:m]) if x == y)
            same_all = b1[:m] == b2[:m]
            print(f'    {f1} vs {f2}: size {s1}vs{s2}({same_len}) nonce {n1.hex()[:8]}vs{n2.hex()[:8]}')
            print(f'        瀵嗘枃瀹屽叏鐩稿悓: {same_all}   鐩哥瓑瀛楄妭 {eq}/{m} ({eq/m:.4f})')
            if not same_all and m >= 32:
                print(f'        b1[:16]={b1[:16].hex()}')
                print(f'        b2[:16]={b2[:16].hex()}')
                xor = bytes(x ^ y for x, y in zip(b1[:min(m, 4096)], b2[:min(m, 4096)]))
                c = Counter(xor)
                print(f'        XOR 涓嶅悓鍊?{len(c)}/256 (1=鐩稿悓)')
    print()

print('=== 鍚屾満鍨嬪唴涓嶅悓鍒嗗尯鐨?keystream 鏄惁鐩稿悓? ===')
for fn in ks:
    names = list(ks[fn].keys())
    print(f'--- {fn} ---')
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            b1 = ks[fn][names[i]][0]
            b2 = ks[fn][names[j]][0]
            m = min(len(b1), len(b2))
            if m < 16:
                continue
            xor = bytes(x ^ y for x, y in zip(b1[:m], b2[:m]))
            c = Counter(xor)
            tag = '  鈽呪槄鈽?鐩稿悓!' if len(c) == 1 else ''
            print(f'    {names[i]} vs {names[j]}: XOR 涓嶅悓鍊?{len(c)}/256{tag}')
