import os
import re
import struct

FW = r'firmware'
OUTDIR = r'.\analysis\lens'

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

BASE = 0x08000000
MODELS = {'4001': 'S-R24105(zoom)', '4002': 'S-R70200(zoom)', '4006': 'S-E2470(zoom)',
          '4003': 'S-X50(prime)', '400C': 'S-S85(prime)', '400E': 'S-S50(prime)'}


def load(k):
    p = os.path.join(FW, k + 'V020.plf')
    return open(p, 'rb').read() if os.path.exists(p) else None


def entry_set(d):
    """严格集:BL/BLX 目标 且 自身是序言,再做真递归下降闭合"""
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


# 为每个型号生成入口表
report = ['# 严格验证的函数入口(BL 目标 ∩ 序言 + 递归下降闭合)',
          f'# 运行时地址 = 文件偏移 + 0x{BASE:08X}',
          '']
per_model = {}
for k, name in MODELS.items():
    d = load(k)
    if d is None:
        continue
    f = entry_set(d)
    per_model[k] = f
    report.append(f'## {k} {name}: {len(f)} 个入口')
    report.append('')
    for s in sorted(f):
        report.append(f'  文件偏移 0x{s:06X}   运行地址 0x{BASE + s:08X}   {f[s][0]} 指令')
    report.append('')

with open(os.path.join(OUTDIR, 'lens_ghidra_entries.txt'), 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(report))

# 生成 Ghidra 脚本(用 4001 的入口作种子)
f401 = per_model.get('4001', {})
script = []
script.append('# Ghidra 脚本:载入 S-R24105 镜头固件并指定已验证入口')
script.append('# 用法:')
script.append('#   1) File > Import File... 选择 4001V020.plf')
script.append('#      语言选 ARM:LE:32:Cortex (Thumb),基址填 0x08000000')
script.append('#   2) 打开 Script Manager,运行本脚本')
script.append('')
script.append('#@category LUMIX')
script.append('')
script.append('from ghidra.program.model.address import AddressSet')
script.append('')
script.append('BASE = 0x%08X' % BASE)
script.append('ENTRIES = [')
for s in sorted(f401):
    script.append('    0x%08X,   # 文件偏移 0x%06X, %d 指令' % (BASE + s, s, f401[s][0]))
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
script.append('print("LUMIX lens: created %d functions from %d verified entries" % (made, len(ENTRIES)))')
script.append('# 之后可再运行 Analysis > Auto Analyze 让 Ghidra 递归扩展')

with open(os.path.join(OUTDIR, 'ghidra_lens_entries.py'), 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(script))

print('=== 各型号严格入口数 ===')
for k in MODELS:
    if k in per_model:
        print(f'  {k} {MODELS[k]:20} {len(per_model[k]):>4} 个入口')
print()
print('[已写 analysis/lens/lens_ghidra_entries.txt]')
print('[已写 analysis/lens/ghidra_lens_entries.py]')
print(f'  (Ghidra 脚本含 {len(f401)} 个入口,基址 0x{BASE:08X})')
