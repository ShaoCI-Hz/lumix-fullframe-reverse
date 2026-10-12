import os
import re
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True

# 1) 用线性扫描收集所有 BL/BLX 目标
print('=== 1) 线性扫描 BL 目标分布 ===')
bl_targets = []
addr = 0
while addr < n - 4:
    for ins in md.disasm(d[addr:addr + 4], addr):
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                tgt = int(ins.op_str[1:], 16)
                bl_targets.append((addr, tgt))
            except Exception:
                pass
        break
    addr += 2

print(f'  找到 BL/BLX 指令 {len(bl_targets)} 条')
tgts = [t for _, t in bl_targets]
in_file = [t for t in tgts if 0 <= t < n]
print(f'  目标落在文件内: {len(in_file)}/{len(tgts)} ({len(in_file)/max(len(tgts),1):.1%})')

# 2) 目标分布直方图(按 0x1000)
print()
print('=== 2) BL 目标地址分布(按 0x1000 聚合,Top 20)===')
hist = Counter(t >> 12 for t in in_file)
for blk, cnt in hist.most_common(20):
    print(f'    0x{blk << 12:06X}  {cnt} 次')

# 3) 关键:检查 BL 目标是否集中在"代码区"
print()
print('=== 3) 代码区 vs 非代码区(按 Thumb 密度)===')


def density(off, size=0x1000):
    cnt = 0
    for _ in md.disasm(d[off:off + size], off):
        cnt += 1
    return cnt / (size / 2)


codeset = set()
for blk in range(0, n // 0x1000):
    off = blk * 0x1000
    if density(off) > 0.5:
        codeset.add(blk)
print(f'  代码块数(>0.5 密度): {len(codeset)} / {n // 0x1000}')

in_code = sum(1 for t in in_file if (t >> 12) in codeset)
print(f'  BL 目标落在代码块的: {in_code}/{len(in_file)} ({in_code/max(len(in_file),1):.1%})')
print(f'  => 若比例高,说明"文件偏移 == 加载地址"(或线性偏移)')

# 4) 反汇编一个函数(从看到 BL 的调用者开始)
print()
print('=== 4) 完整函数反汇编示例:调用者 @0x00FD00 附近 ===')
start = 0x00FD00
for i, ins in enumerate(md.disasm(d[start:start + 0x120], start)):
    print(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
    if i > 50:
        break
