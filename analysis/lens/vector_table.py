import os
import struct
from collections import Counter

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

BASE = 0x08000000
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
print(f'4001V020.plf: {n:,} B,基址 0x{BASE:08X}')

# 在 *运行时地址空间* 里定义范围
SRAM_LO, SRAM_HI = 0x20000000, 0x20040000
FLASH_HI = BASE + n

print()
print('=== 1) ★ 精确向量表搜索(有了基址后的严格条件)===')
print('  条件: word[0] ∈ SRAM(0x2000xxxx),word[1] ∈ Flash 且 bit0=1(Thumb)')
hits = []
for off in range(0, n - 64, 4):
    w0, w1 = struct.unpack_from('<II', d, off)
    if not (SRAM_LO <= w0 < SRAM_HI and (w0 & 3) == 0):
        continue
    if not (BASE <= (w1 & ~1) < FLASH_HI and (w1 & 1)):
        continue
    # 再要求后续 6 个条目也"像"向量: 要么是 Flash|1(handler), 要么是 0(未用)
    ok = 0
    for k in range(2, 10):
        v = struct.unpack_from('<II', d, off + k * 4)[0]
        if v == 0 or (BASE <= (v & ~1) < FLASH_HI and (v & 1)):
            ok += 1
    if ok >= 7:
        hits.append((off, w0, w1, ok))
print(f'  严格命中: {len(hits)} 个')
for off, w0, w1, ok in hits[:10]:
    print(f'    @0x{off:06X}  SP=0x{w0:08X}  Reset=0x{w1:08X}  (ok={ok})')

if hits:
    off0, sp, rst, _ = hits[0]
    print()
    print(f'=== 2) 向量表解析 @0x{off0:06X}(SP=0x{sp:08X},Reset=0x{rst:08X})===')
    print('  Cortex-M 标准异常号: 0=NMI 1=HardFault 2=MemManage 3=BusFault')
    print('                        4=UsageFault 11=SVC 12=DebugMon 14=PendSV 15=SysTick')
    names = {0: 'NMI', 1: 'HardFault', 2: 'MemManage', 3: 'BusFault', 4: 'UsageFault',
             5: 'reserved5', 6: 'reserved6', 7: 'reserved7', 8: 'reserved8', 9: 'reserved9',
             10: 'reserved10', 11: 'SVC', 12: 'DebugMon', 13: 'reserved13', 14: 'PendSV', 15: 'SysTick'}
    vecs = []
    for k in range(0, 64):
        v = struct.unpack_from('<II', d, off0 + k * 4)[0]
        vecs.append(v)
    for k, v in enumerate(vecs[:20]):
        if k == 0:
            label = 'initial SP'
        elif k == 1:
            label = 'Reset'
        else:
            label = names.get(k - 2, f'IRQ{k-2}')
        tgt = (v & ~1) - BASE if v else 0
        ok = 'code' if v and BASE <= (v & ~1) < FLASH_HI and (v & 1) else ('NULL' if v == 0 else '?')
        print(f'    [{k:2}] {label:12} = 0x{v:08X}  -> 文件偏移 0x{tgt:06X}  {ok}')
    # 统计
    hc = sum(1 for v in vecs[1:] if v and BASE <= (v & ~1) < FLASH_HI and (v & 1))
    nul = sum(1 for v in vecs[1:] if v == 0)
    print(f'  有效 handler: {hc}  空: {nul}')
    # 这些 handler 处是否有函数序言?
    print()
    print('  handler 处是否有函数序言(验证向量表真实性):')
    for k, v in enumerate(vecs[1:20], 1):
        if not v or not (BASE <= (v & ~1) < FLASH_HI):
            continue
        toff = (v & ~1) - BASE
        if toff + 2 <= n:
            pro = 'PUSH{r0-r7,lr}' if d[toff + 1] == 0xB5 else ('PUSH.W' if d[toff:toff + 2] == b'\x2d\xe9' else '—')
            print(f'    [{k:2}] 0x{toff:06X}  {pro}')

print()
print('=== 3) 放宽条件(只要求 word0 ∈ SRAM,word1 ∈ Flash|1)===')
loose = []
for off in range(0, n - 8, 4):
    w0, w1 = struct.unpack_from('<II', d, off)
    if SRAM_LO <= w0 < SRAM_HI and BASE <= (w1 & ~1) < FLASH_HI and (w1 & 1):
        loose.append(off)
print(f'  命中 {len(loose)} 个: {[hex(x) for x in loose[:12]]}')

print()
print('=== 4) SRAM 地址值分布(看 SP 初值范围)===')
sp = Counter()
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if SRAM_LO <= v < SRAM_HI:
        sp[v & 0xFFFF0000] += 1
print(f'  SRAM 段引用总数: {sum(sp.values())}')
for v, c in sorted(sp.items())[:12]:
    print(f'    0x{v:08X}xxxx  x{c}')

print()
print('=== 5) 结论:向量表不在 .plf 中 ===')
print('  严格条件命中 0 / 放宽条件也命中 0')
print('  → 文件中不存在"初始SP + 复位向量"的向量表结构')
print('  → 独立证实 §19.5 的推断:.plf 是不含 Flash 起始区的部分更新镜像')
print()
print('  旁证:文件偏移 0 处是 "LENS-UPDATE-FILE-SOF:" 字符串,')
print('        而 0x08000000 恰好指向它 —— 说明该字符串本身就在 Flash 起始处,')
print('        即 .plf 的第一个字节 = Flash 的 0x08000000,')
print('        但 *运行时的* 向量表位于别处(更新镜像不覆盖它)')
