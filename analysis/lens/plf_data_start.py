import os

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

for f in ('4001V020.plf', '4006V020.plf'):
    p = os.path.join(FW, f)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    n = len(d)
    print(f'=== {f} (size=0x{n:X}) ===')
    print()
    print('  0x8000..0x8100 原始字节:')
    for k in range(0x8000, 0x8080, 16):
        seg = d[k:k + 16]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
        print(f'    {k:06X}  {seg.hex(" ")}  |{asc}|')
    print()
    print('  0x9000 起的反汇编(试对齐 0x9000 / 0x9002):')
    for base in (0x9000, 0x9002):
        good = 0
        print(f'  --- base=0x{base:X} ---')
        for i, ins in enumerate(md.disasm(d[base:base + 0x40], base)):
            if i >= 8:
                break
            good += 1
            print(f'    0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
        print()
    # 找 0x9000 附近第一个"合法序言"
    print('  0x8800..0x9200 内寻找函数序言 (0xB5xx / e92d):')
    found = []
    for o in range(0x8800, 0x9200, 2):
        if d[o + 1] == 0xB5:
            found.append((o, 'PUSH{r0-r7,lr}'))
        elif d[o:o + 2] == b'\x2d\xe9':
            found.append((o, 'PUSH.W'))
    for o, k in found[:10]:
        print(f'    @0x{o:06X}  {k}')
    if not found:
        print('    (无)')
    print()
    print('  → 数据区第一个序言之前的头部长度:')
    if found:
        print(f'    第一个序言 @0x{found[0][0]:06X} ({found[0][0]:,})')
    print()
    print('=' * 60)
