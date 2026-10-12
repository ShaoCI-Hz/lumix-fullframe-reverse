import os
import struct
from collections import Counter

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

BASE = 0x08000000
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

# ---------- 1) 真实结束点 ----------
real_ends = []
for off in range(0, n - 4, 2):
    got = None
    for ins in md.disasm(d[off:off + 4], off):
        got = ins
        break
    if got and ((got.mnemonic == 'bx' and 'lr' in got.op_str) or
                (got.mnemonic in ('pop', 'pop.w') and 'pc' in got.op_str)):
        real_ends.append(off + got.size)
real_ends = sorted(set(real_ends))
print(f'真实函数结束点(结束地址): {len(real_ends):,}')

# ---------- 2) ★ 相邻结束点之间:验证能否连续反汇编 ----------
print()
print('=== ★ 相邻结束点之间的连续反汇编验证 ===')
print('  思路: 若 [prev_end, this_end) 能从 prev_end 连续解码到 this_end,')
print('        则该区间是"一段可执行代码"(独立于任何种子/序言判据)')

GAP_MAX = 0x2000     # 超过 8KB 的间隔视为跨数据区
verified = []        # (start, end, ninstr)
failed = 0
for i in range(1, len(real_ends)):
    s = real_ends[i - 1]
    e = real_ends[i]
    if e <= s or (e - s) > GAP_MAX:
        continue
    cur = s
    cnt = 0
    ok = False
    while cur < e:
        got = False
        for ins in md.disasm(d[cur:cur + 4], cur):
            got = True
            cnt += 1
            cur += ins.size
            if cur == e:
                ok = True
            break
        if not got or cur > e:
            break
        if ok:
            break
    if ok and cnt >= 2:
        verified.append((s, e, cnt))
    else:
        failed += 1

print(f'  验证成功的区间: {len(verified):,}')
print(f'  验证失败(跨数据/错位): {failed:,}')

cov = set()
for s, e, c in verified:
    cov.update(range(s, e, 2))
print(f'  覆盖地址: {len(cov):,} 指令')
print(f'  覆盖字节: {len(cov)*2:,} / {n:,} = {len(cov)*2/n:.1%}')

# ---------- 3) 区间规模分布 ----------
sizes = sorted((e - s) // 2 for s, e, c in verified)
print()
print('=== 区间规模分布(指令数)===')
b = Counter()
for sz in sizes:
    if sz < 4:
        b['1-3'] += 1
    elif sz < 8:
        b['4-7'] += 1
    elif sz < 16:
        b['8-15'] += 1
    elif sz < 32:
        b['16-31'] += 1
    elif sz < 64:
        b['32-63'] += 1
    else:
        b['64+'] += 1
for k in ('1-3', '4-7', '8-15', '16-31', '32-63', '64+'):
    if b[k]:
        print(f'    {k:>6} 指令: {b[k]:>5}')

print()
print('=== 最少见的大区间(Top 8 最大)===')
for s, e, c in sorted(verified, key=lambda x: -(x[1] - x[0]))[:8]:
    pro = 'PUSH' if (s + 1 < n and d[s + 1] == 0xB5) else ('PUSH.W' if d[s:s + 2] == b'\x2d\xe9' else '无序言')
    print(f'    0x{s:06X}..0x{e:06X}  {(e-s)//2:>5} 指令  {pro}')

# ---------- 4) 与 §23/§25 对比 ----------
print()
print('=== 4) 与既有方法对比 ===')
print(f'  §25 正确方法(种子出发)  :  10,203 指令 /  4.1%')
print(f'  §23 可达性(种子+控制流) :  71,507 指令 / 36.6%')
print(f'  §26 结束点切段(无种子)  : {len(cov):,} 指令 / {len(cov)*2/n:.1%}')

# ---------- 5) 无序言区间的占比(叶子函数证据)----------
noPro = 0
for s, e, c in verified:
    if not (d[s + 1] == 0xB5 or d[s:s + 2] == b'\x2d\xe9'):
        noPro += 1
print()
print('=== 5) 叶子函数证据 ===')
print(f'  区间起点有序言的: {len(verified)-noPro:,}')
print(f'  区间起点无序言的: {noPro:,}  ({noPro/max(len(verified),1):.1%})')
print(f'  → 这些"无序言"区间正是被 §22/§25 的序言判据漏掉的函数')

with open(r'.\analysis\lens\lens_endpoint_segments.txt',
          'w', encoding='utf-8', newline='\n') as f:
    f.write('# 结束点切段法:相邻函数结束点之间验证连续反汇编\n')
    f.write(f'# 区间 {len(verified):,} 个,覆盖 {len(cov):,} 指令 = {len(cov)*2/n:.1%} 文件\n')
    f.write(f'# 无序言区间 {noPro:,} 个 ({noPro/max(len(verified),1):.1%}) = 叶子函数证据\n\n')
    f.write(f'# {"起点":>10} {"结束":>10} {"指令":>6} {"序言":>8}\n')
    for s, e, c in sorted(verified, key=lambda x: -x[2])[:3000]:
        pro = 'push' if d[s + 1] == 0xB5 else ('pushw' if d[s:s + 2] == b'\x2d\xe9' else '-')
        f.write(f'  0x{s:06X}  0x{e:06X}  {c:>6}  {pro:>8}\n')
print()
print('[已写 analysis/lens/lens_endpoint_segments.txt]')
