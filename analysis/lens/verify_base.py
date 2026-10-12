import os
import struct
from collections import Counter, defaultdict

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
print(f'4001V020.plf: {n:,} B (0x{n:X})')
BASE = 0x08000000

# 收集所有落在 Flash 段的引用值及其位置
flash_refs = []
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if BASE <= v < BASE + 0x00100000:
        flash_refs.append((off, v))
print(f'Flash 段(0x08000000+)引用: {len(flash_refs)} 条')
uniq = sorted(set(v for _, v in flash_refs))
print(f'其中不同地址值: {len(uniq)}')
print(f'地址范围: 0x{uniq[0]:08X} .. 0x{uniq[-1]:08X}')
offs = [v - BASE for v in uniq]
print(f'减去基址后的"文件偏移"范围: 0x{min(offs):06X} .. 0x{max(offs):06X}')
print(f'文件大小 0x{n:X}  →  {"全部落在文件内 ✓" if max(offs) < n else "有超出 ✗"}')
print()
print('最接近文件末尾的 5 个:')
for v in uniq[-5:]:
    print(f'  0x{v:08X} -> 偏移 0x{v-BASE:06X}  (文件内={"是" if v-BASE < n else "否"})')

# 关键验证:这些"偏移"处是否是有意义的数据?
print()
print('=== 验证:引用目标的偏移处内容(取 12 个样本)===')
import random
random.seed(1)
for v in uniq[:6] + uniq[-6:]:
    off = v - BASE
    if off + 16 <= n:
        seg = d[off:off + 16]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
        print(f'  0x{v:08X} -> 0x{off:06X}: {seg.hex(" ")}  |{asc}|')

# 关键验证 B: 用指令语义验证 —— 找 LDR literal 指令,看它加载的值是否 0x08000000+
print()
print('=== 验证 B:LDR literal 加载 Flash 段地址的模式(这是"取数据地址")===')
found = 0
for off in range(0, n - 4, 2):
    cnt = 0
    for ins in md.disasm(d[off:off + 4], off):
        cnt += 1
        op = ins.op_str
        if ins.mnemonic in ('ldr', 'ldr.w') and '[pc,' in op:
            import re
            m = re.search(r'#(0x[0-9a-f]+)', op)
            if m:
                tgt = ins.address + 4 + int(m.group(1), 16)
                if tgt + 4 <= n:
                    lit = struct.unpack_from('<I', d, tgt)[0]
                    if BASE <= lit < BASE + 0x00100000:
                        if found < 8:
                            print(f'  0x{off:06X}: {ins.mnemonic} {op}')
                            print(f'      literal @0x{tgt:06X} = 0x{lit:08X} -> 偏移 0x{lit-BASE:06X}')
                        found += 1
        break
print(f'  共 {found} 条 LDR literal 加载 Flash 段地址')

# 统计:这些地址的最低字节分布(代码地址 bit0=1 是 Thumb;数据地址 bit0 常为 0)
print()
print('=== 验证 C:地址 bit0 分布(Thumb 函数指针 vs 数据指针)===')
odd = sum(1 for v in uniq if v & 1)
even = len(uniq) - odd
print(f'  奇数(bit0=1,Thumb 代码指针): {odd}')
print(f'  偶数(bit0=0,数据指针)      : {even}')
print(f'  → 若偶数占多数,说明这些多是"数据地址"而非"函数指针"')
