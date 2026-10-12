import os
import struct

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

SRAM_LO, SRAM_HI = 0x20000000, 0x20080000


def find_vt(d, name):
    n = len(d)
    print(f'--- {name}  (size=0x{n:X}) ---')
    hits = []
    for off in range(0, min(n, 0x10000), 2):
        if off + 8 > n:
            break
        w0, w1 = struct.unpack_from('<II', d, off)
        if not (SRAM_LO <= w0 < SRAM_HI and (w0 & 3) == 0):
            continue
        if not (w1 & 1):
            continue
        # 后续 4 个 word 也要像 handler(小整数或带 bit0)
        ok = 0
        for k in range(2, 8):
            if off + (k + 1) * 4 > n:
                break
            v = struct.unpack_from('<I', d, off + k * 4)[0]
            if v == 0 or (v & 1) or v < 0x20000:
                ok += 1
        if ok >= 4:
            hits.append((off, w0, w1, ok))
    if not hits:
        print('    无向量表')
        return
    for off, w0, w1, ok in hits[:5]:
        print(f'    ★ @0x{off:04X}  SP=0x{w0:08X}  Reset=0x{w1:08X}  (ok={ok})')
    off, sp, rst, _ = hits[0]
    print(f'    解析 @0x{off:04X}:')
    for k in range(0, 24):
        v = struct.unpack_from('<I', d, off + k * 4)[0]
        lbl = ('SP' if k == 0 else 'Reset' if k == 1 else f'IRQ{k-2}')
        print(f'      [{k:2}] {lbl:8} = 0x{v:08X}')
    # ★ 推断加载基址:向量表在文件中位于 off,而在内存中应位于 image 起点
    # 复位向量指向 rst&~1,若该地址落在"文件内偏移"则 base = off - 0
    rst_rel = rst & ~1
    print(f'    → 复位向量相对偏移 0x{rst_rel:06X}')
    print(f'    → 若向量表位于 image 基址,则 image 起始 = 文件偏移 0x{off:04X}')
    print(f'    → 验证:文件偏移 0x{off + rst_rel:06X} 处应是复位代码')
    p = off + rst_rel
    if p + 16 <= n:
        seg = d[p:p + 16]
        print(f'       该处字节: {seg.hex(" ")}')
        for i, ins in enumerate(md.disasm(d[p:p + 0x40], p)):
            if i >= 8:
                break
            print(f'         0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
    # 也试: image 基址 = 0x200 / 0x400 等
    for base in (0x200, 0x400, 0x458, 0x45A, off):
        q = base + rst_rel
        if q + 4 <= n:
            ok2 = None
            for ins in md.disasm(d[q:q + 4], q):
                ok2 = ins.mnemonic
                break
            tag = ' ← 合法首指令' if ok2 and ok2 not in ('movs',) else ''
            print(f'       base=0x{base:04X} → 文件 0x{q:06X} 首指令={ok2}{tag}')
    return off, sp, rst


for rel in ('sigma/A0040140_sigma_30F14_cont.plf', 'sigma/S02D0120_sigma_14F14_art.plf',
            'sigma/S02A0130_sigma_50F2_cont.plf', '4001V020.plf'):
    p = os.path.join(FW, rel)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    find_vt(d, os.path.basename(rel))
    print()
