import os
import re
import struct
from collections import Counter, defaultdict

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
OUT = r'.\analysis\lens_var_xref.txt'

# 1) 鏀堕泦鍙橀噺鍚?+ 鏂囦欢鍋忕Щ
vars_ = {}
for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{5,40}', d):
    s = m.group().decode()
    if re.search(r'[A-Z]', s) and re.search(r'[a-z]', s):
        # 鍙繚鐣欏悕瀛楀尯(0x5000..0x8000 闄勮繎鐨勫彉閲忚〃)
        if 0x4000 <= m.start() <= 0x9000:
            vars_[m.start()] = s
print(f'=== 鍙橀噺鍚?0x4000-0x9000 鍖?: {len(vars_)} 涓?===')

# 2) 鍦ㄦ枃浠朵腑鎼滅储"绛変簬鍙橀噺鍚嶅瓧绗︿覆鍦板潃"鐨?4 瀛楄妭鍊?literal 姹犲紩鐢?
by_ref = defaultdict(list)
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if v in vars_:
        by_ref[v].append(off)

print(f'=== 琚唬鐮佸紩鐢?literal 姹?鐨勫彉閲? {len(by_ref)} / {len(vars_)} ===')
print()
print('=== 琚紩鐢ㄦ渶澶氱殑 15 涓彉閲?===')
order = sorted(by_ref.items(), key=lambda kv: -len(kv[1]))
for va, refs in order[:15]:
    print(f'  {vars_[va]:28} @0x{va:05X}  琚紩鐢?{len(refs)} 娆?)

# 3) 瀵规瘡涓紩鐢ㄧ殑 literal 浣嶇疆,鎵?鍝釜鍑芥暟鍖呭惈瀹?
#    鐢ㄥ簭瑷€绉嶅瓙寤虹珛鐨勫嚱鏁板尯闂?from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)


def walk(start, limit=1500):
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


seeds = set()
for o in range(0, n - 2, 2):
    if d[o + 1] == 0xB5:
        seeds.add(o)
for o in range(0, n - 4, 2):
    if d[o:o + 2] == b'\x2d\xe9':
        m2 = struct.unpack_from('<H', d, o + 2)[0]
        if m2 & 0x4000:
            seeds.add(o)

funcs = {}
for s in sorted(seeds):
    insns, tgts, ok = walk(s)
    if ok and len(insns) >= 3:
        funcs[s] = (len(insns), tgts)
entries = sorted(funcs.keys())
import bisect


def owner(addr):
    """杩斿洖鍖呭惈 addr 鐨勫嚱鏁板叆鍙?鏈€杩戠殑 <= addr 鐨勫叆鍙?"""
    i = bisect.bisect_right(entries, addr) - 1
    return entries[i] if i >= 0 else None


print()
print('=== 鍙橀噺 鈫?鍑芥暟鏄犲皠(琚紩鐢ㄥ彉閲?Top 15)===')
lines = []
lines.append('# 鍙橀噺 鈫?寮曠敤鐐?鈫?鍑芥暟鍏ュ彛 鏄犲皠')
lines.append(f'# 鍙橀噺鍚?{len(vars_)} 涓?琚?literal 姹犲紩鐢?{len(by_ref)} 涓?)
lines.append('')
mapped = 0
for va, refs in order[:60]:
    name = vars_[va]
    owners = Counter()
    for r in refs:
        o = owner(r)
        if o is not None:
            owners[o] += 1
    if owners:
        mapped += 1
    ost = ', '.join(f'0x{o:06X}(x{c})' for o, c in owners.most_common(4))
    lines.append(f'{name:30} @0x{va:05X}  refs={len(refs):<4} funcs: {ost}')

print()
for l in lines[3:18]:
    print('  ' + l)

print()
print(f'=== 鑳芥槧灏勫埌鍑芥暟鐨勫彉閲? {mapped} ===')

with open(OUT, 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(lines))
print(f'[宸插啓 {OUT}]')
