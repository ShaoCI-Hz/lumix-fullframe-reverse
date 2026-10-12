import os
import re
import hashlib

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

TARGETS = [
    ('9f87c20b6e3a5642', 0x03E3DC, 147, 'zoom-only, largest'),
    ('8c3b7813e9f73380', 0x03E244, 76, 'zoom-only'),
    ('0b5c9767c9ea7872', 0x05F4EC, 76, 'zoom-only'),
]
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()

OUT = r'.\analysis\lens\lens_zoom_only_funcs.asm'
L = []
L.append('# 变焦组专属函数(定焦型号中完全不存在)')
L.append('# 这些是最可能的"变焦/镜头特定业务逻辑",而非编译器运行时库')
L.append('')

for fp16, off, n, tag in TARGETS:
    L.append('')
    L.append(f'# {"="*66}')
    L.append(f'# 指纹 {fp16}  ({n} 指令)  {tag}')
    L.append(f'# 位置: 4001 @0x{off:06X}')
    L.append(f'# {"="*66}')
    print(f'=== {fp16} @0x{off:06X} ({tag}) ===')
    cnt = 0
    for ins in md.disasm(d[off:off + n * 4 + 32], off):
        L.append(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
        if cnt < 45:
            print(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
        cnt += 1
        if cnt >= n:
            break
    print()

# 统计这 20 个 zoom-only 函数的规模与位置,做成清单
L.append('')
L.append('# 20 个"仅变焦组有"的函数清单(按规模)')
zoomonly = [
    ('9f87c20b6e3a5642', 147), ('8c3b7813e9f73380', 76), ('0b5c9767c9ea7872', 76),
    ('3eccb866cefcf4ad', 64), ('7e2df981dde770cd', 63), ('a35d9176b69ddac3', 57),
    ('36a33adb8b8bcfd4', 57), ('2bb0271244c92c0c', 52), ('547c5da2a87ac849', 51),
    ('371873aef844b6bb', 43), ('b61112411f2a1273', 34), ('547b7972269b142a', 32),
]
for h, n in zoomonly:
    L.append(f'  {h}  {n:>4} insn')

with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(L))
print(f'[已写 {OUT}, {len(L)} 行]')
