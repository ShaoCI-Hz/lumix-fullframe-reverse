import os
import hashlib
import re
from collections import defaultdict

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)


def load(n):
    p = os.path.join(FW, n)
    return open(p, 'rb').read() if os.path.exists(p) else None


D = {k: load(k + 'V020.plf') for k in ('4001', '4002', '4006', '4003')}
D = {k: v for k, v in D.items() if v}


def walk(d, start, limit=2000):
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


def fingerprint(insns):
    """鍦板潃鏃犲叧鎸囩汗:淇濈暀鍔╄绗?+ 鎿嶄綔鏁扮粨鏋?鎶规帀绔嬪嵆鏁?鐩爣鍦板潃鐨勫叿浣撳€?""
    parts = []
    for ins in insns:
        op = ins.op_str
        # 鎶规帀 #0x.... / 鍏蜂綋鏁板€?        op = re.sub(r'#-?0x[0-9a-f]+', '#I', op)
        op = re.sub(r'#-?\d+', '#I', op)
        # 鎶规帀瀵勫瓨鍣ㄤ腑鐨勫叿浣撲綅绉?        op = re.sub(r'0x[0-9a-f]+', 'D', op)
        parts.append(f'{ins.mnemonic} {op}')
    return hashlib.sha1(';'.join(parts).encode()).hexdigest()[:16], len(insns)


def funcs_of(d, minlen=6):
    seeds = set()
    for o in range(0, len(d) - 4, 2):
        if d[o + 1] == 0xB5:
            seeds.add(o)
        elif d[o:o + 2] == b'\x2d\xe9':
            seeds.add(o)
    out = {}
    for s in sorted(seeds):
        insns, ok = walk(d, s)
        if ok and len(insns) >= minlen:
            fp, n = fingerprint(insns)
            out.setdefault(fp, []).append((s, n))
    return out


print('=== 鎻愬彇鍚勬牱鏈殑鍑芥暟鎸囩汗 ===')
F = {}
for k, d in D.items():
    F[k] = funcs_of(d)
    total = sum(len(v) for v in F[k].values())
    print(f'  {k}: {total} 涓嚱鏁?{len(F[k])} 涓敮涓€鎸囩汗')

print()
print('=== 璺ㄦ牱鏈叡浜寚绾?===')
zoom = [k for k in ('4001', '4002', '4006') if k in F]
prime = [k for k in ('4003',) if k in F]

# 鍙樼劍缁勫叡浜?if len(zoom) >= 2:
    common_z = set(F[zoom[0]])
    for k in zoom[1:]:
        common_z &= set(F[k])
    print(f'  鍙樼劍缁?{"+".join(zoom)})鍏变韩鎸囩汗: {len(common_z)} 涓?)
    # 杩欎簺鎸囩汗鍦ㄥ悇鑷牱鏈腑瀵瑰簲鐨勫嚱鏁?    print()
    print('  鍓?12 涓叡浜寚绾?鍙婂叾鍦ㄥ悇鏍锋湰鐨勫亸绉?闀垮害):')
    for fp in sorted(common_z)[:12]:
        locs = '  '.join(f'{k}:0x{F[k][fp][0][0]:06X}({F[k][fp][0][1]})' for k in zoom if fp in F[k])
        print(f'    {fp}  {locs}')

# 鍙樼劍 vs 瀹氱劍
if zoom and prime:
    allz = set.union(*[set(F[k]) for k in zoom])
    allp = set.union(*[set(F[k]) for k in prime])
    cross = allz & allp
    print()
    print(f'  鍙樼劍鍏ㄤ綋 鈭?鎸囩汗 {len(allz)},瀹氱劍 {len(allp)},浜ら泦 {len(cross)}')
    print(f'  鈫?璺ㄥ鏃忓叡浜寚绾规瘮渚? {len(cross)/max(len(allz),1):.3f}')
    if cross:
        print('  浜ら泦鏍锋湰:')
        for fp in sorted(cross)[:8]:
            locs = '  '.join(f'{k}:0x{F[k][fp][0][0]:06X}' for k in list(zoom) + list(prime) if fp in F[k])
            print(f'    {fp}  {locs}')

print()
print('=== 鍙樼劍缁勫叡浜寚绾圭殑闀垮害鍒嗗竷(鐪嬪叡浜殑鏄ぇ鍑芥暟杩樻槸灏忓嚱鏁?===')
if len(zoom) >= 2:
    lens = sorted(F[zoom[0]][fp][0][1] for fp in common_z)
    from collections import Counter
    c = Counter()
    for L in lens:
        c[(L // 20) * 20] += 1
    for b in sorted(c):
        print(f'    {b:>4}-{b+19:<4} 鎸囦护: {c[b]} 涓?)
