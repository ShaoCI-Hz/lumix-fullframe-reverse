import os
import re
import struct
from collections import Counter

FW = r'firmware'
p = os.path.join(FW, '4001V020.plf')
d = open(p, 'rb').read()
n = len(d)
OUT = r'.\analysis\lens\lens_disasm.txt'

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

lines = []
def out(s=''):
    print(s)
    lines.append(s)

out(f'=== 4001V020.plf 反汇编分析 ({n:,} B) ===')

# 1) 找 ARM Cortex-M 向量表:连续 word 中,若干指向"代码区且 bit0=1"(Thumb 入口)
out()
out('=== 1) Cortex-M 向量表候选(连续 4 字节,值落在文件内且 bit0=1)===')
cand = []
for off in range(0, n - 64, 4):
    vals = struct.unpack_from('<16I', d, off)
    # 向量表特征:第 2 个起多为奇数(Thumb),且都在范围内
    odd = sum(1 for v in vals[1:8] if v & 1 and 0x1000 <= (v & ~1) < n)
    if odd >= 6:
        cand.append((off, vals[:8], odd))
for off, vals, odd in cand[:5]:
    out(f'  @0x{off:06X} (odd={odd}): ' + ' '.join(f'0x{v:08X}' for v in vals))
if not cand:
    out('  (未找到典型向量表 —— 可能代码不是从文件偏移 0 加载)')

# 2) 统计代码区(有效 Thumb 指令密度),输出分区
out()
out('=== 2) 代码/数据分区(0x1000 窗口:有效指令比)===')
W = 0x1000
prev = None
segs = []
for off in range(0, n, W):
    seg = d[off:off + W]
    cnt = 0
    for _ in md.disasm(seg, off):
        cnt += 1
    ratio = cnt / (W / 2)
    kind = 'code' if ratio > 0.5 else ('mixed' if ratio > 0.2 else 'data')
    segs.append((off, kind, ratio))
    if kind != prev:
        out(f'  @0x{off:06X}  {kind}  (instr_ratio={ratio:.2f})')
        prev = kind

# 3) 找字符串引用:LDR literal 指向 ASCII 区
out()
out('=== 3) 代码中的 PC 相对加载(LDR literal,可能引用字符串/表)===')
lit_hits = []
addr = 0
while addr < n - 4:
    ins_iter = list(md.disasm(d[addr:addr + 4], addr))
    if ins_iter:
        ins = ins_iter[0]
        if ins.mnemonic in ('ldr.w', 'ldr') and '[pc,' in ins.op_str:
            m = re.search(r'#(0x[0-9a-f]+)', ins.op_str)
            if m:
                target = ins.address + 4 + int(m.group(1), 16)
                if target < n:
                    lit_hits.append((addr, target))
    addr += 2
out(f'  LDR literal 引用数: {len(lit_hits)}')
# 检查这些引用目标是否为 ASCII
ascii_refs = 0
samples = []
for src, tgt in lit_hits[:4000]:
    seg = d[tgt:tgt + 16]
    if sum(1 for x in seg if 32 <= x < 127) >= 10:
        ascii_refs += 1
        if len(samples) < 12:
            s = ''.join(chr(x) if 32 <= x < 127 else '.' for x in d[tgt:tgt + 32])
            samples.append((src, tgt, s))
out(f'  指向 ASCII 的引用: {ascii_refs}')
for src, tgt, s in samples:
    out(f'    0x{src:06X} -> 0x{tgt:06X}  |{s}|')

# 4) 反汇编一段代码区,存文件
out()
out('=== 4) 代码区 0x039800 反汇编(前 80 条)===')
top = 0x039800
for i, ins in enumerate(md.disasm(d[top:top + 0x300], top)):
    if i >= 80:
        break
    out(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:8} {ins.op_str}')

with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(lines))
print(f'\n[已写入 {OUT}, {len(lines)} 行]')
