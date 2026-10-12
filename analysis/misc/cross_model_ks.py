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

# 收集各机型的"明文全零且有密文"分区
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

print('=== 各机型全零明文分区 ===')
for fn in ks:
    print(f'  {fn}: {list(ks[fn].keys())}')

print()
print('=== 跨机型同 size 分区的密文比较(keystream 是否相同?)===')
# 按 size 分组
byname = {}
for fn in ks:
    for nm, (blob, size, nonce) in ks[fn].items():
        byname.setdefault(nm, []).append((fn, blob, size, nonce))

for nm, lst in byname.items():
    if len(lst) < 2:
        continue
    print(f'--- {nm} (出现在 {len(lst)} 个机型) ---')
    for i in range(len(lst)):
        for j in range(i + 1, len(lst)):
            f1, b1, s1, n1 = lst[i]
            f2, b2, s2, n2 = lst[j]
            m = min(len(b1), len(b2))
            same_len = s1 == s2
            # 相等字节比例
            eq = sum(1 for x, y in zip(b1[:m], b2[:m]) if x == y)
            same_all = b1[:m] == b2[:m]
            print(f'    {f1} vs {f2}: size {s1}vs{s2}({same_len}) nonce {n1.hex()[:8]}vs{n2.hex()[:8]}')
            print(f'        密文完全相同: {same_all}   相等字节 {eq}/{m} ({eq/m:.4f})')
            if not same_all and m >= 32:
                print(f'        b1[:16]={b1[:16].hex()}')
                print(f'        b2[:16]={b2[:16].hex()}')
                xor = bytes(x ^ y for x, y in zip(b1[:min(m, 4096)], b2[:min(m, 4096)]))
                c = Counter(xor)
                print(f'        XOR 不同值={len(c)}/256 (1=相同)')
    print()

print('=== 同机型内不同分区的 keystream 是否相同? ===')
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
            tag = '  ★★★ 相同!' if len(c) == 1 else ''
            print(f'    {names[i]} vs {names[j]}: XOR 不同值={len(c)}/256{tag}')
