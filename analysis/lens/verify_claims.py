import os
import struct
import bisect

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

# 复现我在 lens_base.py 里的"函数区间"构造
seeds = set()
for o in range(0, n - 2, 2):
    if d[o + 1] == 0xB5:
        seeds.add(o)
for o in range(0, n - 4, 2):
    if d[o:o + 2] == b'\x2d\xe9':
        m2 = struct.unpack_from('<H', d, o + 2)[0]
        if m2 & 0x4000:
            seeds.add(o)

entries = sorted(seeds)
print(f'=== 指控 1:函数区间的并集覆盖率 ===')
print(f'  文件大小: {n:,} 字节')
print(f'  种子数: {len(entries)}')
ranges = []
for i, s in enumerate(entries):
    e = entries[i + 1] if i + 1 < len(entries) else n
    ranges.append((s, e))
total = sum(e - s for s, e in ranges)
print(f'  区间并集总长: {total:,} 字节 = {total/n:.2%} 的文件')
print(f'  区间起点范围: 0x{entries[0]:06X} .. 0x{entries[-1]:06X}')
print(f'  区间并集 = [0x{entries[0]:06X}, 0x{n:06X})  ← 覆盖从第一个种子到文件末尾')
print()
print('  => 只要 BL 目标 > 0x%06X,就"落在函数区间内"' % entries[0])
print(f'     ({entries[0]:,} / {n:,} = 前 {entries[0]/n:.1%} 的文件被排除)')

# 指控 2:BL 目标收集包含了普通 B 分支
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
print()
print('=== 指控 2:"BL 目标"实际混入了普通 B 分支 ===')
bl_only = []
b_only = []
addr = 0
while addr < n - 4:
    got = False
    for ins in md.disasm(d[addr:addr + 4], addr):
        got = True
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                bl_only.append(int(ins.op_str[1:], 16) & ~1)
            except Exception:
                pass
        elif ins.mnemonic == 'b' and ins.op_str.startswith('#'):
            try:
                b_only.append(int(ins.op_str[1:], 16) & ~1)
            except Exception:
                pass
        break
    addr += 2
print(f'  纯 BL/BLX 目标: {len(bl_only):,}')
print(f'  普通 B  目标: {len(b_only):,}')
print(f'  我的代码收集的 = BL + B = {len(bl_only) + len(b_only):,}')
print()

# 关键:普通 B 目标有多少落在"同一个函数区间"内(即近距离跳转)?
import bisect


def owner_range(a):
    i = bisect.bisect_right(entries, a) - 1
    if i < 0:
        return None
    s = entries[i]
    return (s, ranges[i][1])


near = 0
far = 0
for t in b_only[:5000]:
    r = owner_range(t)
    if r is None:
        continue
    # B 目标与它所属区间起点的距离
    if t - r[0] < 0x400:
        near += 1
    else:
        far += 1
print(f'  B 目标中,距其区间起点 < 0x400 的近跳转: {near}/{near+far} ({near/max(near+far,1):.1%})')
print('  => 普通 B 多为区间内近跳转,计入后必然推高"落在区间内"的命中率')

# 指控 3:用严格标准(仅 BL,且要求落在"高密度代码块")重新测量
print()
print('=== 指控 3:用严格标准重新测量 ===')


def density(off, size=0x1000):
    cnt = 0
    for _ in md.disasm(d[off:off + size], off):
        cnt += 1
    return cnt / (size / 2)


code_blocks = set()
for blk in range(0, n // 0x1000):
    off = blk * 0x1000
    if density(off) > 0.5:
        code_blocks.add(blk)
print(f'  高密度代码块: {len(code_blocks)} 个')

for label, tg in (('仅 BL/BLX', bl_only), ('BL+B(我原来的)', bl_only + b_only)):
    in_code = sum(1 for t in tg if (t >> 12) in code_blocks)
    print(f'  {label:18} 落在高密度代码块: {in_code:>6}/{len(tg):>6} ({in_code/max(len(tg),1):.1%})')
