import os
import re
import hashlib
from collections import defaultdict, Counter

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

MODELS = {'4001': 'S-R24105(zoom)', '4002': 'S-R70200(zoom)', '4003': 'S-X50(prime)',
          '4006': 'S-E2470(zoom)', '400C': 'S-S85(prime)', '400E': 'S-S50(prime)'}
D = {}
for k in MODELS:
    p = os.path.join(FW, k + 'V020.plf')
    if os.path.exists(p):
        D[k] = open(p, 'rb').read()


def walk(d, start, limit=3000):
    insns, addr = [], start
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
    out = []
    for ins in insns:
        op = ins.op_str
        op = re.sub(r'#-?0x[0-9a-f]+', '#I', op)
        op = re.sub(r'#-?\d+', '#I', op)
        op = re.sub(r'0x[0-9a-f]+', 'D', op)
        out.append(f'{ins.mnemonic} {op}')
    return ';'.join(out)


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
            h = hashlib.sha1(norm(insns).encode()).hexdigest()[:16]
            if h not in f:
                f[h] = (s, len(insns), insns)
    FP[k] = f

cluster = defaultdict(dict)
for k, f in FP.items():
    for h, (off, n, ii) in f.items():
        cluster[h][k] = (off, n)

ZOOM = ['4001', '4002', '4006']
PRIME = ['4003', '400C', '400E']

# 鍒嗙被:鍝簺鎸囩汗鏄?鍙樼劍鍏ㄦ湁+瀹氱劍鍏ㄦ棤" vs "瀹氱劍鍏ㄦ湁"
zoom_only = {h: v for h, v in cluster.items() if all(k in v for k in ZOOM) and not any(k in v for k in PRIME)}
zoom_any = {h: v for h, v in cluster.items() if all(k in v for k in ZOOM)}
prime_any = {h: v for h, v in cluster.items() if all(k in v for k in PRIME)}
all6 = {h: v for h, v in cluster.items() if len(v) == 6}
five = {h: v for h, v in cluster.items() if len(v) == 5}
four = {h: v for h, v in cluster.items() if len(v) == 4}

print('=== 鎸囩汗鎸夊瀷鍙风粍鍚堝垎绫?===')
print(f'  鍏?6 鍨嬪彿鍏变韩         : {len(all6)}')
print(f'  5 鍨嬪彿鍏变韩            : {len(five)}')
print(f'  4 鍨嬪彿鍏变韩            : {len(four)}')
print(f'  鍙樼劍缁勫叏鏈?3/3)      : {len(zoom_any)}')
print(f'  浠呭彉鐒︾粍鏈?瀹氱劍鍏ㄦ棤)  : {len(zoom_only)}')
print(f'  瀹氱劍缁勫叏鏈?3/3)      : {len(prime_any)}')

# 璇嗗埆杩愯鏃跺簱鍑芥暟:鍚?udiv/umull/sdiv/smull 鐨勭畻鏈緥绋?print()
print('=== 杩愯鏃跺簱鐗瑰緛璇嗗埆(鍚?udiv/sdiv/umull/smull,涓旀棤鍐呭瓨璁块棶)===')
lib = []
for h, v in cluster.items():
    k0 = next(iter(v))
    ii = FP[k0][h][2]
    mn = set(i.mnemonic for i in ii)
    arith = bool(mn & {'udiv', 'sdiv', 'umull', 'smull', 'umlal', 'smlal'})
    mem = any(i.mnemonic.startswith(('ldr', 'str', 'ldm', 'stm', 'push', 'pop')) and 'pc' not in i.op_str for i in ii[:5])
    if arith and len(v) >= 4:
        lib.append((h, len(v), len(ii), sorted(mn & {'udiv', 'sdiv', 'umull', 'smull'})[0]))
print(f'  鐤戜技绠楁湳杩愯鏃朵緥绋?鍏变韩 >=4 鍨嬪彿): {len(lib)} 涓?)
for h, nk, ni, op in sorted(lib, key=lambda x: -x[2])[:12]:
    print(f'    {h}  鍏变韩 {nk} 鍨嬪彿  {ni} insn  鏍稿績: {op}')

# 鍙樼劍涓撳睘鍑芥暟(鍙兘鐨勫彉鐒?闀滃ご鎺у埗閫昏緫)
print()
print('=== 浠呭彉鐒︾粍鏈夌殑鍑芥暟(鎸夎妯?Top 12)鈥斺€斿€欓€変笟鍔￠€昏緫 ===')
zf = sorted(zoom_only.items(), key=lambda kv: -max(x[1] for x in kv[1].values()))
print(f'  {"鎸囩汗":>16}  {"鎸囦护":>5}  4001 浣嶇疆')
for h, v in zf[:12]:
    n = max(x[1] for x in v.values())
    o = v['4001'][0] if '4001' in v else next(iter(v.values()))[0]
    print(f'  {h}  {n:>5}  0x{o:06X}')

# 鍐欐姤鍛?OUT = r'.\analysis\lens_fingerprint_report.txt'
L = []
L.append('# 闀滃ご鍥轰欢鍑芥暟鎸囩汗鑱氱被鎶ュ憡(6 鍨嬪彿)')
L.append('')
for k, f in FP.items():
    L.append(f'{k} {MODELS[k]:18} {len(f)} 涓敮涓€鍑芥暟鎸囩汗')
L.append('')
L.append('## 鎸夊叡浜瀷鍙锋暟鍒嗙被')
L.append(f'  鍏?6 鍨嬪彿鍏变韩        : {len(all6)}')
L.append(f'  5 鍨嬪彿鍏变韩           : {len(five)}')
L.append(f'  4 鍨嬪彿鍏变韩           : {len(four)}')
L.append(f'  3 鍨嬪彿鍏变韩           : {sum(1 for v in cluster.values() if len(v) == 3)}')
L.append(f'  2 鍨嬪彿鍏变韩           : {sum(1 for v in cluster.values() if len(v) == 2)}')
L.append(f'  浠?1 鍨嬪彿(鍨嬪彿鐗瑰畾) : {sum(1 for v in cluster.values() if len(v) == 1)}')
L.append('')
L.append('## 鍙樼劍/瀹氱劍鍒嗗寲')
L.append(f'  鍙樼劍缁勫叏鏈?          : {len(zoom_any)}')
L.append(f'  浠呭彉鐒︾粍鏈?瀹氱劍鍏ㄦ棤) : {len(zoom_only)}')
L.append(f'  瀹氱劍缁勫叏鏈?          : {len(prime_any)}')
L.append('')
L.append('## 鐤戜技绠楁湳璇繍琛屾椂渚嬬▼(鍏变韩 >=4 鍨嬪彿,鍚?udiv/sdiv/umull/smull)')
L.append('  璇存槑:杩欎簺涓嶆槸闀滃ご涓氬姟閫昏緫,鑰屾槸缂栬瘧鍣ㄨ繍琛屾椂搴?ARM EABI)')
L.append('  鏈€澶х殑涓€涓槸 __aeabi_fdiv(鍗曠簿搴︽诞鐐归櫎娉?')
L.append('')
for h, nk, ni, op in sorted(lib, key=lambda x: -x[2]):
    L.append(f'  {h}  鍏变韩 {nk} 鍨嬪彿  {ni} insn  鏍稿績鎸囦护 {op}')
L.append('')
L.append('## 浠呭彉鐒︾粍鏈夌殑鍑芥暟(Top 30,鍊欓€夐暅澶翠笟鍔￠€昏緫)')
L.append('')
for h, v in zf[:30]:
    n = max(x[1] for x in v.values())
    locs = ' '.join(f'{k}:0x{v[k][0]:06X}' for k in ZOOM if k in v)
    L.append(f'  {h}  {n:>4} insn  {locs}')
with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(L))
print()
print(f'[宸插啓 {OUT}]')
