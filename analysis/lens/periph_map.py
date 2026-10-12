import os
import struct
from collections import Counter, defaultdict

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

BASE = 0x08000000
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

# 1) 外设地址明细(0x40000000 段,按 16 字节对齐聚合 = 寄存器粒度)
print('=== 1) 外设寄存器地址(0x40000000 段,16B 粒度)===')
reg = Counter()
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if 0x40000000 <= v < 0x40100000:
        reg[v & 0xFFFFFFF0] += 1
print(f'  不同寄存器: {len(reg)}  引用总数: {sum(reg.values())}')
print('  引用最多的 25 个寄存器:')
for v, c in reg.most_common(25):
    print(f'    0x{v:08X}  x{c}')

# 2) 按外设块(256B)聚合,看有多少个外设
blk = Counter()
for v, c in reg.items():
    blk[v >> 8] += c
print()
print(f'  不同 256B 外设块: {len(blk)}')
print('  引用最多的 15 个外设块:')
for b, c in blk.most_common(15):
    print(f'    0x{b<<8:08X}  x{c}')

# 3) 函数 <-> RAM/外设地址 关系图
print()
print('=== 3) 函数 ↔ 地址 关系图(建 literal 池索引)===')


def walk(start, limit=1500):
    insns, addr = [], start
    while addr < n - 4 and len(insns) < limit:
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            insns.append(ins)
            if (ins.mnemonic == 'pop' and 'pc' in ins.op_str) or (ins.mnemonic == 'bx' and 'lr' in ins.op_str):
                return insns, True
            addr += ins.size
            break
        if not got:
            break
    return insns, False


seeds = sorted(o for o in range(0, n - 2, 2) if d[o + 1] == 0xB5)
print(f'  序言种子: {len(seeds)}')

import re
func_addrs = defaultdict(set)     # 函数入口 -> 该函数引用的地址集合
addr_users = defaultdict(set)     # 地址 -> 使用它的函数集合
for s in seeds:
    insns, ok = walk(s)
    if not ok or len(insns) < 6:
        continue
    for ins in insns:
        op = ins.op_str
        if '[pc,' in op:
            m = re.search(r'#(0x[0-9a-f]+)', op)
            if not m:
                continue
            tgt = ins.address + 4 + int(m.group(1), 16)
            if tgt + 4 > n:
                continue
            val = struct.unpack_from('<I', d, tgt)[0]
            if (0x20000000 <= val < 0x20040000 or 0x40000000 <= val < 0x40100000
                    or BASE <= val < BASE + 0x100000):
                func_addrs[s].add(val)
                addr_users[val].add(s)

print(f'  有地址引用的函数: {len(func_addrs)}')
print(f'  被引用的地址: {len(addr_users)}')
print()
print('  被最多"不同函数"共享的地址(前 15)= 全局变量/SFR:')
print(f'    {"地址":>12} {"使用函数数":>10}  类型')
for v, users in sorted(addr_users.items(), key=lambda kv: -len(kv[1]))[:15]:
    if 0x20000000 <= v < 0x20040000:
        t = 'SRAM 全局变量'
    elif 0x40000000 <= v < 0x40100000:
        t = '外设寄存器'
    else:
        t = 'Flash 常量/表'
    print(f'    0x{v:08X} {len(users):>10}  {t}')

# 4) 输出报告
OUT = r'.\analysis\lens\lens_periph_map.txt'
L = []
L.append('# 镜头固件外设寄存器与全局地址映射(4001V020.plf)')
L.append(f'# 加载基址 0x{BASE:08X}')
L.append('')
L.append(f'## 外设寄存器(0x40000000 段),共 {len(reg)} 个不同寄存器 / {sum(reg.values())} 次引用')
L.append('')
for v, c in reg.most_common(60):
    L.append(f'  0x{v:08X}  x{c}')
L.append('')
L.append(f'## 外设块(256B),共 {len(blk)} 个')
L.append('')
for b, c in blk.most_common(40):
    L.append(f'  0x{b<<8:08X}  x{c}')
L.append('')
L.append('## 被多个函数共享的地址(全局变量 / SFR)')
L.append('')
L.append(f'  {"地址":>12} {"函数数":>8}  类型')
for v, users in sorted(addr_users.items(), key=lambda kv: -len(kv[1]))[:120]:
    t = 'SRAM' if 0x20000000 <= v < 0x20040000 else ('PERIPH' if 0x40000000 <= v < 0x40100000 else 'FLASH')
    L.append(f'  0x{v:08X} {len(users):>8}  {t}')
with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(L))
print()
print(f'[已写 {OUT}]')
