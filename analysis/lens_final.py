import os
import struct
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
OUTLIST = r'.\analysis\lens_functions_seeds.txt'
OUTDIS = r'.\work\lens_disasm_sample.txt'

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)


def walk(start, limit=1200):
    insns, tgts = [], []
    addr, ok = start, False
    while addr < n - 4 and len(insns) < limit:
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            insns.append(ins)
            if ins.mnemonic in ('bl', 'b', 'blx') and ins.op_str.startswith('#'):
                try:
                    tgts.append(int(ins.op_str[1:], 16) & ~1)
                except Exception:
                    pass
            if (ins.mnemonic == 'pop' and 'pc' in ins.op_str) or (ins.mnemonic == 'bx' and 'lr' in ins.op_str):
                ok = True
                addr += ins.size
                return insns, tgts, True
            addr += ins.size
            break
        if not got:
            break
    return insns, tgts, False


# 搴忚█绉嶅瓙
seeds = set()
for o in range(0, n - 2, 2):
    if d[o + 1] == 0xB5:
        seeds.add(o)
for o in range(0, n - 4, 2):
    if d[o:o + 2] == b'\x2d\xe9':
        m2 = struct.unpack_from('<H', d, o + 2)[0]
        if m2 & 0x4000:
            seeds.add(o)

# 绗竴杞?浠庣瀛愭敹闆?BL 鐩爣
tg = Counter()
seed_funcs = {}
for s in sorted(seeds):
    insns, tgts, ok = walk(s)
    if ok and len(insns) >= 3:
        seed_funcs[s] = len(insns)
        for t in tgts:
            tg[t] += 1

# 楂樼疆淇″叆鍙?= BL 鐩爣 涓?鑷韩鏈夊簭瑷€
hi = []
for t, c in tg.items():
    if not (0 <= t < n - 4):
        continue
    if t in seeds:
        insns, _, ok = walk(t)
        if ok and len(insns) >= 3:
            hi.append((t, c, len(insns)))

lines = []
lines.append('# 4001V020.plf 鍑芥暟鍒嗘瀽缁撴灉')
lines.append('')
lines.append(f'# 搴忚█绉嶅瓙(PUSH {{r0-r7,lr}} 0xB5xx / PUSH.W e92d..): {len(seeds)}')
lines.append(f'# 鍏朵腑鍙畬鏁村弽姹囩紪鐨? {len(seed_funcs)}')
lines.append(f'# BL 鐩爣(琚皟鐢ㄧ偣): {len(tg)}')
lines.append(f'# 楂樼疆淇″嚱鏁板叆鍙?BL 鐩爣 涓?鏈夊簭瑷€): {len(hi)}')
lines.append('')
lines.append('# 楂樼疆淇″嚱鏁板叆鍙ｅ垪琛?鎸夎璋冪敤娆℃暟)')
lines.append(f'# {"鍏ュ彛":>10} {"琚皟鐢?:>7} {"鎸囦护鏁?:>7}')
for t, c, ni in sorted(hi, key=lambda x: -x[1]):
    lines.append(f'  0x{t:06X} {c:>7} {ni:>7}')

with open(OUTLIST, 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(lines))

print(f'搴忚█绉嶅瓙 {len(seeds)}, 鍙弽姹囩紪 {len(seed_funcs)}')
print(f'BL 鐩爣 {len(tg)}')
print(f'楂樼疆淇″嚱鏁板叆鍙?BL鐩爣鈭╁簭瑷€) {len(hi)}')
print()
print('=== 楂樼疆淇″嚱鏁板叆鍙?Top 20 ===')
for t, c, ni in sorted(hi, key=lambda x: -x[1])[:20]:
    print(f'  0x{t:06X}  琚皟鐢?x{c:<4}  {ni} insn')

# 鍙嶆眹缂栧嚑涓珮缃俊鍑芥暟瀹屾暣杈撳嚭
dl = []
for t, c, ni in sorted(hi, key=lambda x: -x[1])[:5]:
    dl.append(f'--- func 0x{t:06X} (x{c}, {ni} insn) ---')
    insns, _, _ = walk(t, limit=300)
    for ins in insns[:80]:
        dl.append(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
    dl.append('')
with open(OUTDIS, 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(dl))
print(f'\n[宸插啓 {OUTLIST} 鍜?{OUTDIS}]')
