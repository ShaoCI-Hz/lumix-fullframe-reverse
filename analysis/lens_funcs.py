import os
import struct
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
OUT = r'.\work\lens_functions.txt'
OUT2 = r'.\work\lens_func_list.txt'

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

# 1) 搴忚█绉嶅瓙
seeds = set()
for o in range(0, n - 2, 2):
    if d[o + 1] == 0xB5:
        seeds.add(o)
for o in range(0, n - 4, 2):
    if d[o:o + 2] == b'\x2d\xe9':
        mask = struct.unpack_from('<H', d, o + 2)[0]
        if mask & 0x4000:
            seeds.add(o)


def disasm_func(start, limit=4000):
    """浠?start 鍙嶆眹缂栧埌鍑芥暟缁撳熬,杩斿洖 (鎸囦护鍒楄〃, 鐩爣闆嗗悎, 鏄惁姝ｅ父缁撴潫, 瀛楄妭鏁?"""
    insns = []
    targets = set()
    addr = start
    ok = False
    while addr < n - 4 and len(insns) < limit:
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            insns.append(ins)
            m = ins.mnemonic
            if m in ('bl', 'b', 'blx') and ins.op_str.startswith('#'):
                try:
                    t = int(ins.op_str[1:], 16)
                    if 0 <= t < n:
                        targets.add(t & ~1)
                except Exception:
                    pass
            if (m == 'pop' and 'pc' in ins.op_str) or (m == 'bx' and 'lr' in ins.op_str):
                ok = True
                addr += ins.size
                return insns, targets, True, addr - start
            addr += ins.size
            break
        if not got:
            break
    return insns, targets, ok, addr - start


# 2) 鍒ゅ畾鎵€鏈夌瀛?funcs = []
for s in sorted(seeds):
    insns, tgts, ok, size = disasm_func(s, limit=1500)
    if ok and len(insns) >= 3:
        funcs.append(dict(addr=s, size=size, ninstr=len(insns), targets=tgts))

print(f'=== 鍙俊鍑芥暟: {len(funcs)} / {len(seeds)} 涓簭瑷€绉嶅瓙 ===')

# 3) 琚紩鐢ㄦ鏁?鍝釜鍑芥暟琚皟鐢ㄦ渶澶?= 鏍稿績宸ュ叿鍑芥暟)
refcnt = Counter()
for f in funcs:
    for t in f['targets']:
        refcnt[t] += 1

# 4) 鍏抽敭:鎶?BL 鐩爣鍖归厤鍒板凡鐭ュ嚱鏁板叆鍙?entry_set = set(f['addr'] for f in funcs)
matched = sum(1 for t in refcnt if t in entry_set)
print(f'  鍑芥暟闂磋皟鐢ㄥ叧绯? {len(refcnt)} 涓洰鏍?鍏朵腑鍛戒腑鍑芥暟鍏ュ彛 {matched} ({matched/max(len(refcnt),1):.1%})')

# 5) 杈撳嚭鍑芥暟鍒楄〃(鎸夎寮曠敤娆℃暟鎺掑簭)
lines = []
lines.append(f'# 4001V020.plf 鍙俊鍑芥暟鍒楄〃(搴忚█绉嶅瓙 + 閫掑綊涓嬮檷)')
lines.append(f'# 鍏?{len(funcs)} 涓嚱鏁?)
lines.append(f'# 鏍煎紡: 鍏ュ彛鍦板潃  澶у皬  鎸囦护鏁? 琚皟鐢ㄦ鏁?)
lines.append('')
for f in sorted(funcs, key=lambda x: -refcnt.get(x['addr'], 0)):
    cnt = refcnt.get(f['addr'], 0)
    lines.append(f'  0x{f["addr"]:06X}  {f["size"]:>5} B  {f["ninstr"]:>4} insn  x{cnt}')

# 6) 鍙嶆眹缂?top 8 鏍稿績鍑芥暟
lines.append('')
lines.append('#' + '=' * 66)
lines.append(f'# 鏍稿績鍑芥暟鍙嶆眹缂?琚皟鐢ㄦ渶澶氱殑 8 涓?')
lines.append('#' + '=' * 66)
top = sorted(funcs, key=lambda x: -refcnt.get(x['addr'], 0))[:8]
for f in top:
    cnt = refcnt.get(f['addr'], 0)
    lines.append('')
    lines.append(f'--- func 0x{f["addr"]:06X}  ({f["size"]} B, {f["ninstr"]} insn, 琚皟鐢?{cnt} 娆? ---')
    insns, _, _, _ = disasm_func(f['addr'], limit=200)
    for ins in insns[:60]:
        lines.append(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')

with open(OUT, 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(lines))
with open(OUT2, 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(lines[:len(funcs) + 5]))

print(f'  宸插啓 {OUT}')
print()
print('=== 琚皟鐢ㄦ渶澶氱殑 15 涓嚱鏁?===')
print(f'  {"鍏ュ彛":>10} {"澶у皬":>7} {"鎸囦护":>6} {"璋冪敤娆℃暟":>8}')
for f in top[:15]:
    cnt = refcnt.get(f['addr'], 0)
    print(f'  0x{f["addr"]:06X} {f["size"]:>6} B {f["ninstr"]:>6} x{cnt}')
print()
print('=== 鎸囦护鎬绘暟缁熻 ===')
print(f'  鍙俊鍑芥暟瑕嗙洊鎸囦护: {sum(f["ninstr"] for f in funcs):,}')
print(f'  鍙俊鍑芥暟瑕嗙洊瀛楄妭: {sum(f["size"] for f in funcs):,} / {n:,} ({sum(f["size"] for f in funcs)/n:.1%})')
