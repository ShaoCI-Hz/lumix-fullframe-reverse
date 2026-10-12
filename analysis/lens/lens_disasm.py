import os
import re
from collections import Counter

FW = r'firmware'
p = os.path.join(FW, '4001V020.plf')
d = open(p, 'rb').read()
n = len(d)
print(f'=== 4001V020.plf  {n:,} B ===')

# 用 capstone 探测代码区:逐窗口尝试 Thumb 反汇编,统计有效指令比例
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = False


def thumb_score(chunk):
    """返回 (有效指令比例, 指令数)"""
    ok = 0
    tot = 0
    for ins in md.disasm(chunk, 0):
        tot += 1
        ok += 1
        if tot >= 200:
            break
    return ok, tot


W = 0x800
print()
print('=== 代码区探测(Thumb 指令密度)===')
regions = []
for off in range(0, n - W, W):
    seg = d[off:off + W]
    # 简单启发:Thumb 常见 2 字节指令,检查 push/pop/bl 模式
    push = len(re.findall(rb'[\x00-\xff][\xb4\xb5]', seg))          # PUSH {..}
    bl = len(re.findall(rb'[\xf0-\xf7][\xf8-\xff]', seg))           # BL
    bx = seg.count(b'\x70\x47')                                     # BX LR
    pop = len(re.findall(rb'[\x00-\xff][\xbd]', seg))               # POP {..,PC}
    sc = push * 3 + bl * 2 + bx * 5 + pop * 2
    regions.append((off, sc, push, bl, bx, pop))

regions.sort(key=lambda x: -x[1])
print('  代码密度最高的 15 个窗口:')
print(f'    {"off":>10} {"score":>7} {"push":>6} {"bl":>6} {"bx":>5} {"pop":>6}')
for off, sc, pu, bl, bx, po in regions[:15]:
    print(f'    0x{off:06X} {sc:>7} {pu:>6} {bl:>6} {bx:>5} {po:>6}')

# 打印最高密度区的反汇编
top = regions[0][0]
print()
print(f'=== 最高密度区 0x{top:06X} 反汇编(前 60 条)===')
for i, ins in enumerate(md.disasm(d[top:top + 0x200], top)):
    if i >= 60:
        break
    print(f'  0x{ins.address:06X}  {ins.mnemonic:8} {ins.op_str}')

# 全局统计
print()
print('=== 全局 Thumb 特征统计 ===')
allpush = len(re.findall(rb'[\x00-\xff][\xb4\xb5]', d))
allbx = d.count(b'\x70\x47')
allbl = len(re.findall(rb'[\xf0-\xf7][\xf8-\xff]', d))
print(f'  PUSH 模式: {allpush}')
print(f'  BX LR (0x4770): {allbx}')
print(f'  BL 模式: {allbl}')
