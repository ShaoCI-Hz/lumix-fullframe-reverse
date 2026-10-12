import os
import zipfile
import hashlib
import math
import re
from collections import Counter

FW = r'firmware'


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


# 解压所有镜头 zip
print('=== 解压镜头固件 ===')
plfs = {}
for f in sorted(os.listdir(FW)):
    if not f.upper().endswith('.ZIP'):
        continue
    z = os.path.join(FW, f)
    try:
        with zipfile.ZipFile(z) as zf:
            for i in zf.infolist():
                print(f'  {f:18} -> {i.filename:18} {i.file_size:>9,} B')
            zf.extractall(FW)
    except Exception as e:
        print(f'  {f}: {e}')

for f in sorted(os.listdir(FW)):
    if f.lower().endswith(('.plf', '.lin')):
        p = os.path.join(FW, f)
        d = open(p, 'rb').read()
        plfs[f] = d

print()
print('=== 各镜头固件概览 ===')
print(f'{"file":18} {"size":>10} {"熵":>7} {"零%":>7}  head')
for f, d in plfs.items():
    print(f'{f:18} {len(d):>10,} {ent(d):>7.3f} {d.count(0)/len(d):>6.1%}  {d[:24].hex(" ")}')
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in d[:32])
    print(f'{"":18} {"":10} {"":7} {"":7}  |{asc}|')

print()
print('=== 结构差分:各固件头部字段对比(前 0x60)===')
for f, d in plfs.items():
    print(f'--- {f} ---')
    for k in range(0, 0x60, 16):
        seg = d[k:k + 16]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
        print(f'  {k:04x}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 符号表对比:各固件的符号数 + 交集 ===')
sym_sets = {}
for f, d in plfs.items():
    sy = set()
    for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{4,40}', d):
        s = m.group().decode()
        if re.search(r'[A-Z]', s) and re.search(r'[a-z]', s) and len(s) >= 6:
            sy.add(s)
    sym_sets[f] = sy
    print(f'  {f:18} 符号数={len(sy):>5}')

names = list(sym_sets.keys())
if len(names) >= 2:
    common = set.intersection(*sym_sets.values())
    print(f'  全部共有符号 = {len(common)}')
    # 两两共有
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            c = len(sym_sets[names[i]] & sym_sets[names[j]])
            print(f'    {names[i]} ∩ {names[j]} = {c}')
    print(f'  共有符号样例(前 40):')
    for s in sorted(common)[:40]:
        print(f'     {s}')
