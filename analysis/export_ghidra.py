import os
import re
import struct

FW = r'firmware'
OUTDIR = r'.\analysis'

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

BASE = 0x08000000
MODELS = {'4001': 'S-R24105(zoom)', '4002': 'S-R70200(zoom)', '4006': 'S-E2470(zoom)',
          '4003': 'S-X50(prime)', '400C': 'S-S85(prime)', '400E': 'S-S50(prime)'}


def load(k):
    p = os.path.join(FW, k + 'V020.plf')
    return open(p, 'rb').read() if os.path.exists(p) else None


def entry_set(d):
    """涓ユ牸闆?BL/BLX 鐩爣 涓?鑷韩鏄簭瑷€,鍐嶅仛鐪熼€掑綊涓嬮檷闂悎"""
    n = len(d)

    def is_pro(off):
        if off + 2 > n:
            return False
        if d[off + 1] == 0xB5:
            return True
        if d[off:off + 2] == b'\x2d\xe9' and off + 4 <= n:
            return bool(struct.unpack_from('<H', d, off + 2)[0] & 0x4000)
        return False

    def walk(start, limit=2000):
        insns, bls, addr = [], [], start
        while addr < n - 4 and len(insns) < limit:
            got = False
            for ins in md.disasm(d[addr:addr + 4], addr):
                got = True
                insns.append(ins)
                if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
                    try:
                        t = int(ins.op_str[1:], 16) & ~1
                        if 0 <= t < n:
                            bls.append(t)
                    except Exception:
                        pass
                if (ins.mnemonic == 'pop' and 'pc' in ins.op_str) or (ins.mnemonic == 'bx' and 'lr' in ins.op_str):
                    addr += ins.size
                    return insns, bls, True
                addr += ins.size
                break
            if not got:
                break
        return insns, bls, False

    allbl = set()
    a = 0
    while a < n - 4:
        got = False
        for ins in md.disasm(d[a:a + 4], a):
            got = True
            if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
                try:
                    t = int(ins.op_str[1:], 16) & ~1
                    if 0 <= t < n:
                        allbl.add(t)
                except Exception:
                    pass
            break
        a += 2
    seeds = [t for t in allbl if is_pro(t)]
    funcs, work = {}, sorted(seeds)
    while work:
        nxt = []
        for s in work:
            if s in funcs:
                continue
            insns, bls, ok = walk(s)
            if not ok or len(insns) < 3:
                funcs[s] = (len(insns), [])
                continue
            funcs[s] = (len(insns), bls)
            for t in set(bls):
                if t not in funcs and t not in nxt and is_pro(t):
                    nxt.append(t)
        work = nxt
    return funcs


# 涓烘瘡涓瀷鍙风敓鎴愬叆鍙ｈ〃
report = ['# 涓ユ牸楠岃瘉鐨勫嚱鏁板叆鍙?BL 鐩爣 鈭?搴忚█ + 閫掑綊涓嬮檷闂悎)',
          f'# 杩愯鏃跺湴鍧€ = 鏂囦欢鍋忕Щ + 0x{BASE:08X}',
          '']
per_model = {}
for k, name in MODELS.items():
    d = load(k)
    if d is None:
        continue
    f = entry_set(d)
    per_model[k] = f
    report.append(f'## {k} {name}: {len(f)} 涓叆鍙?)
    report.append('')
    for s in sorted(f):
        report.append(f'  鏂囦欢鍋忕Щ 0x{s:06X}   杩愯鍦板潃 0x{BASE + s:08X}   {f[s][0]} 鎸囦护')
    report.append('')

with open(os.path.join(OUTDIR, 'lens_ghidra_entries.txt'), 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(report))

# 鐢熸垚 Ghidra 鑴氭湰(鐢?4001 鐨勫叆鍙ｄ綔绉嶅瓙)
f401 = per_model.get('4001', {})
script = []
script.append('# Ghidra 鑴氭湰:杞藉叆 S-R24105 闀滃ご鍥轰欢骞舵寚瀹氬凡楠岃瘉鍏ュ彛')
script.append('# 鐢ㄦ硶:')
script.append('#   1) File > Import File... 閫夋嫨 4001V020.plf')
script.append('#      璇█閫?ARM:LE:32:Cortex (Thumb),鍩哄潃濉?0x08000000')
script.append('#   2) 鎵撳紑 Script Manager,杩愯鏈剼鏈?)
script.append('')
script.append('#@category LUMIX')
script.append('')
script.append('from ghidra.program.model.address import AddressSet')
script.append('')
script.append('BASE = 0x%08X' % BASE)
script.append('ENTRIES = [')
for s in sorted(f401):
    script.append('    0x%08X,   # 鏂囦欢鍋忕Щ 0x%06X, %d 鎸囦护' % (BASE + s, s, f401[s][0]))
script.append(']')
script.append('')
script.append('fm = currentProgram.getFunctionManager()')
script.append('af = currentProgram.getAddressFactory()')
script.append('space = af.getDefaultAddressSpace()')
script.append('made = 0')
script.append('for a in ENTRIES:')
script.append('    addr = space.getAddress(a)')
script.append('    if fm.getFunctionAt(addr) is None:')
script.append('        createFunction(addr, None)')
script.append('        made += 1')
script.append('print("LUMIX lens: created %%d functions from %%d verified entries" %% (made, len(ENTRIES)))')
script.append('# 涔嬪悗鍙啀杩愯 Analysis > Auto Analyze 璁?Ghidra 閫掑綊鎵╁睍')

with open(os.path.join(OUTDIR, 'ghidra_lens_entries.py'), 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(script))

print('=== 鍚勫瀷鍙蜂弗鏍煎叆鍙ｆ暟 ===')
for k in MODELS:
    if k in per_model:
        print(f'  {k} {MODELS[k]:20} {len(per_model[k]):>4} 涓叆鍙?)
print()
print('[宸插啓 analysis/lens_ghidra_entries.txt]')
print('[宸插啓 analysis/ghidra_lens_entries.py]')
print(f'  (Ghidra 鑴氭湰鍚?{len(f401)} 涓叆鍙?鍩哄潃 0x{BASE:08X})')
