import os
import re
import hashlib
from collections import defaultdict, Counter

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

MODELS = {
    '4001': 'S-R24105 (zoom)',
    '4002': 'S-R70200 (zoom)',
    '4003': 'S-X50    (prime)',
    '4006': 'S-E2470  (zoom)',
    '400C': 'S-S85    (prime)',
    '400E': 'S-S50    (prime)',
}
D = {}
for k in MODELS:
    p = os.path.join(FW, k + 'V020.plf')
    if os.path.exists(p):
        D[k] = open(p, 'rb').read()
print(f'鏍锋湰: {len(D)} 涓?-> {", ".join(D)}')


def walk(d, start, limit=3000):
    insns = []
    addr = start
    while addr < len(d) - 4 and len(insns) < limit:
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


def norm(insns):
    parts = []
    for ins in insns:
        op = ins.op_str
        op = re.sub(r'#-?0x[0-9a-f]+', '#I', op)
        op = re.sub(r'#-?\d+', '#I', op)
        op = re.sub(r'0x[0-9a-f]+', 'D', op)
        parts.append(f'{ins.mnemonic} {op}')
    return ';'.join(parts)


def fp(s):
    return hashlib.sha1(s.encode()).hexdigest()[:16]


# 1) 姣忎釜鍨嬪彿鎻愬彇鍑芥暟鎸囩汗
FP = {}
for k, d in D.items():
    seeds = set()
    for o in range(0, len(d) - 4, 2):
        if d[o + 1] == 0xB5:
            seeds.add(o)
        elif d[o:o + 2] == b'\x2d\xe9':
            seeds.add(o)
    f = {}
    for s in sorted(seeds):
        insns, ok = walk(d, s)
        if ok and len(insns) >= 6:
            h = fp(norm(insns))
            if h not in f:
                f[h] = (s, len(insns), insns)
    FP[k] = f
    print(f'  {k}: {len(f)} 涓敮涓€鍑芥暟鎸囩汗')

# 2) 鑱氱被:姣忎釜鎸囩汗鍑虹幇鍦ㄥ摢浜涘瀷鍙?print()
print('=== 鎸囩汗鑱氱被(璺ㄥ瀷鍙峰嚭鐜版鏁?===')
cluster = defaultdict(dict)
for k, f in FP.items():
    for h, (off, n, _) in f.items():
        cluster[h][k] = (off, n)

dist = Counter(len(v) for v in cluster.values())
print(f'  鍞竴鎸囩汗鎬绘暟: {len(cluster)}')
for c in sorted(dist, reverse=True):
    print(f'    鍑虹幇鍦?{c} 涓瀷鍙风殑鎸囩汗: {dist[c]} 涓?)

# 3) 鍏?6 鍨嬪彿鍏变韩
all6 = {h: v for h, v in cluster.items() if len(v) == len(D)}
print()
print(f'=== 鍏ㄩ儴 {len(D)} 涓瀷鍙峰叡浜殑鍑芥暟: {len(all6)} 涓?===')

# 杈撳嚭缁熶竴鍑芥暟缂栧彿琛?OUT = r'.\analysis\lens_function_ids.txt'
rows = []
for i, (h, v) in enumerate(sorted(all6.items(), key=lambda kv: -max(x[1] for x in kv[1].values())), 1):
    n = max(x[1] for x in v.values())
    locs = ' '.join(f'{k}:0x{v[k][0]:06X}' for k in D if k in v)
    rows.append(f'FN{i:04d}  {h}  {n:>4} insn  {locs}')

lines = []
lines.append('# L 鍗″彛闀滃ご鍥轰欢:璺ㄥ瀷鍙烽€氱敤鍑芥暟缂栧彿琛?)
lines.append(f'# 鐢?6 涓瀷鍙风殑鍦板潃鏃犲叧鍑芥暟鎸囩汗鑱氱被寰楀嚭')
lines.append(f'# 鍏ㄩ儴 6 鍨嬪彿鍏变韩:{len(all6)} 涓嚱鏁?)
lines.append('#')
lines.append('# 鏍煎紡:缂栧彿  鎸囩汗  鎸囦护鏁? 鍚勫瀷鍙锋枃浠跺亸绉?)
lines.append('')
lines.extend(rows)
with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(lines))
print(f'  宸插啓 {OUT}')

print()
print('=== 鍏ㄩ儴 6 鍨嬪彿鍏变韩鍑芥暟 Top 12(鎸夎妯?===')
print(f'  {"缂栧彿":>7}  {"鎸囩汗":>16}  {"鎸囦护":>5}  浣嶇疆绀轰緥')
for i, (h, v) in enumerate(sorted(all6.items(), key=lambda kv: -max(x[1] for x in kv[1].values()))[:12], 1):
    n = max(x[1] for x in v.values())
    first = next(iter(v))
    print(f'  FN{i:04d}  {h}  {n:>5}  {first}:0x{v[first][0]:06X}')

# 4) 鍙嶆眹缂栨渶澶х殑鍏变韩鍑芥暟
print()
print('=== 鏈€澶х殑鍏变韩鍑芥暟鍙嶆眹缂?鍓?60 鏉?===')
best = max(all6.items(), key=lambda kv: max(x[1] for x in kv[1].values()))
h, v = best
k0 = next(iter(v))
off, n, insns = FP[k0][h]
print(f'  鎸囩汗 {h},{n} 鎸囦护,鏍锋湰 {k0} @0x{off:06X},鍑虹幇鍦?{len(v)} 涓瀷鍙?)
for ins in insns[:60]:
    print(f'    0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')

with open(r'.\analysis\lens_shared_biggest.asm',
          'w', encoding='utf-8', newline='\n') as f:
    f.write(f'# 鏈€澶у叡浜嚱鏁?鎸囩汗={h} {n} insn 鏍锋湰={k0} @0x{off:06X}\n')
    f.write(f'# 鍑虹幇鍦?{len(v)}/{len(D)} 涓瀷鍙? ' + ', '.join(f'{k}@0x{v[k][0]:06X}' for k in D if k in v) + '\n\n')
    for ins in insns:
        f.write(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}\n')
print()
print('[宸插啓 analysis/lens_shared_biggest.asm]')
