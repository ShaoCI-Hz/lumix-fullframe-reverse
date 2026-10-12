import os
import math
from collections import Counter

FW = r'firmware'
NAMES = ['4001V020.plf', '4002V020.plf', '4006V020.plf']


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


print('=== 1) 逐 4KB 块的熵(前 0x20000,找数据起始)===')
for f in NAMES:
    p = os.path.join(FW, f)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    print(f'--- {f}  (size=0x{len(d):X}) ---')
    prev = None
    for off in range(0, 0x20000, 0x1000):
        e = ent(d[off:off + 0x1000])
        tag = ''
        if e > 7.5:
            tag = 'HIGH'
        elif e < 2:
            tag = 'low'
        if prev is not None and abs(e - prev) > 3:
            tag += '  <<< 突变'
        print(f'  0x{off:06X}  H={e:5.2f}  {tag}')
        prev = e
    print()

print()
print('=== 2) 找"最后一段低熵区"的结束位置 = 数据起始候选 ===')
for f in NAMES:
    p = os.path.join(FW, f)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    n = len(d)
    # 从头开始,找第一个"高熵块"(H>7.5)且其后持续高熵
    start = None
    for off in range(0, min(n - 0x4000, 0x80000), 0x1000):
        if ent(d[off:off + 0x1000]) > 7.5:
            # 确认后续 3 块也高熵
            if all(ent(d[off + i * 0x1000:off + (i + 1) * 0x1000]) > 7.0 for i in range(1, 4)):
                start = off
                break
    print(f'  {f}: size=0x{n:X}  首个持续高熵块 @0x{start if start is not None else 0:X}')
    if start:
        print(f'         数据区 ≈ [{start:,}, {n:,})  = {n - start:,} 字节 = 0x{n - start:X}')
        # 与头部字段对比
        for k in (0x18, 0x1C, 0x20, 0xB4, 0xB8):
            v = int.from_bytes(d[k:k + 4], 'little')
            mark = '  ★匹配数据大小' if v == n - start else ''
            mark2 = '  ★匹配起始偏移' if v == start else ''
            print(f'         0x{k:02X} = {v:>12,}{mark}{mark2}')

print()
print('=== 3) 头部 0x18 字段的三个值是否与任何"文件大小换算"吻合 ===')
sizes = {}
for f in NAMES:
    p = os.path.join(FW, f)
    if os.path.exists(p):
        dd = open(p, 'rb').read()
        sizes[f] = len(dd)
        v18 = int.from_bytes(dd[0x18:0x1C], 'little')
        print(f'  {f}: size={len(dd):>10,}  0x18={v18:>10,}  diff={len(dd)-v18:>10,}  ratio={v18/len(dd):.4f}')

print()
print('=== 4) 全文件 4KB 熵曲线(每 64KB 采样,看整体结构)===')
for f in NAMES[:1]:
    d = open(os.path.join(FW, f), 'rb').read()
    n = len(d)
    print(f'--- {f} ---')
    for off in range(0, n - 0x4000, 0x10000):
        print(f'  0x{off:06X}  H={ent(d[off:off + 0x4000]):5.2f}')
