"""用 Ghidra 交叉验证并扩展 §22 的入口集

背景
----
§22 用"函数序言"判据得到 133 个双重验证的入口,但该判据对**叶子函数**
(编译器不为无调用函数生成 push 序言)结构性失效。Ghidra 使用递归下降 +
调用图,与此互补。

本脚本把 133 个入口当作**种子**喂给 Ghidra,并量化双向收益:
  - Ghidra 单独能找到多少(基线)
  - 加入我们的种子后能到多少(扩展)

前置
----
1. 安装 Ghidra 12.1.x(需 JDK 21)
2. pip install pyghidra
3. 先把目标二进制导入一个 Ghidra 工程:
     analyzeHeadless <projDir> <projName> -import <firmware.plf> \
        -processor ARM:LE:32:Cortex -loader BinaryLoader \
        -loader-baseAddr 0x08000000
   注意 .plf 是裸二进制,必须显式给基址,否则地址全部错位。

用法
----
  set GHIDRA_INSTALL_DIR=<ghidra dir>
  set JAVA_HOME=<jdk21>
  python ghidra_crosscheck.py --project-dir <dir> --project-name <name> \
        --program /4001V020.plf --outdir <out dir>
"""

import argparse
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ENTRIES = os.path.join(HERE, 'ghidra_lens_entries.py')

# 此前确立的代码区分布(相对镜像基址 0x08000000)
IMAGE_BASE = 0x08000000
CODE_LO = IMAGE_BASE + 0x028000
CODE_HI = IMAGE_BASE + 0x068000


def region_of(addr):
    if addr < CODE_LO:
        return 'header-meta'
    if addr < CODE_HI:
        return 'main-code'
    return 'tail-data'


def load_entries(path):
    """从既有脚本解析已验证入口地址(0x........ 形式)。"""
    addrs = []
    pat = re.compile(r'\s*(0x[0-9A-Fa-f]{6,10})\s*,')
    with open(path, encoding='utf-8') as fp:
        for line in fp:
            m = pat.match(line)
            if m:
                addrs.append(int(m.group(1), 16))
    return addrs


def inventory(program):
    """{entry_offset: body_size}"""
    fm = program.getFunctionManager()
    out = {}
    for f in fm.getFunctions(True):
        try:
            out[f.getEntryPoint().getOffset()] = int(f.getBody().getNumAddresses())
        except Exception:
            out[f.getEntryPoint().getOffset()] = 0
    return out


def quality(program, entry_off):
    """返回 (has_push_prologue, has_return, has_suspicious_insn)"""
    af = program.getAddressFactory().getDefaultAddressSpace()
    a = af.getAddress(entry_off)
    fm = program.getFunctionManager()
    listing = program.getListing()
    f = fm.getFunctionAt(a)
    if f is None:
        return (False, False, True)

    body = f.getBody()
    has_push = False
    has_ret = False
    susp = False

    it = listing.getInstructions(body, True)
    n = 0
    while it.hasNext():
        i = it.next()
        m = i.getMnemonicString().lower()
        s = i.toString().replace(' ', '').lower()
        if n < 4 and m.startswith('push'):
            has_push = True
        if s.startswith('bxlr') or (m.startswith('pop') and 'pc' in s):
            has_ret = True
        # 数据被当成代码的典型迹象:NEON / VFP / 系统指令
        if m.startswith('v') and m not in ('vpush', 'vpop'):
            susp = True
        elif m in ('svc', 'udf', 'cdp', 'mcr', 'ldc'):
            susp = True
        n += 1
        if n > 4000:
            break
    return (has_push, has_ret, susp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--project-dir', required=True)
    ap.add_argument('--project-name', required=True)
    ap.add_argument('--program', required=True, help='e.g. /4001V020.plf')
    ap.add_argument('--entries', default=DEFAULT_ENTRIES)
    ap.add_argument('--outdir', default='.')
    args = ap.parse_args()

    import pyghidra
    pyghidra.start()
    from pyghidra import analyze, open_project, program_context, transaction
    from ghidra.app.cmd.disassemble import ArmDisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd

    if not os.path.isdir(args.outdir):
        os.makedirs(args.outdir)

    entries = load_entries(args.entries)
    print('verified entries loaded: %d' % len(entries))

    proj = open_project(args.project_dir, args.project_name)
    with program_context(proj, args.program) as program:
        print('program: %s' % program.getName())
        for b in program.getMemory().getBlocks():
            print('  block %-10s %s  size=0x%X' % (b.getName(), b.getStart(), b.getSize()))

        base = inventory(program)
        print('baseline (Ghidra automatic analysis): %d functions' % len(base))

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()

        # 反汇编限制在已确立的代码区内(0x028000..0x068000),
        # 避免 followFlow 递归下降越界进入头部元数据区而产生误报。
        from ghidra.program.model.address import AddressSet
        code_span = AddressSet(af.getAddress(CODE_LO), af.getAddress(CODE_HI - 1))

        already = created = failed = 0
        with transaction(program):
            for off in entries:
                a = af.getAddress(off)
                if fm.getFunctionAt(a) is not None:
                    already += 1
                    continue
                # followFlow=True:从该入口跟随控制流反汇编(这是 Ghidra 的标准做法),
                # 但用 code_span 限制在代码区内。
                ArmDisassembleCommand(a, code_span, True).applyTo(program)
                if CreateFunctionCmd(a).applyTo(program):
                    created += 1
                else:
                    failed += 1

        print('entries: already_known=%d newly_created=%d failed=%d'
              % (already, created, failed))
        analyze(program)

        final = inventory(program)
        program.save('cross-check with verified entry seeds', None)

        new = sorted(set(final) - set(base))
        cn = Counter(region_of(x) for x in new)
        ca = Counter(region_of(x) for x in final)
        cb = Counter(region_of(x) for x in base)

        hit = [e for e in entries if e in base]
        miss = [e for e in entries if e not in base]

        print()
        print('=' * 68)
        print('  baseline (Ghidra only)        : %5d  %s' % (len(base), dict(cb)))
        print('  with our seeds                : %5d  %s' % (len(final), dict(ca)))
        print('  delta                         : %+5d  %s' % (len(final) - len(base), dict(cn)))
        print()
        print('  of our %d entries, Ghidra found on its own : %d (%.1f%%)'
              % (len(entries), len(hit), 100.0 * len(hit) / max(1, len(entries))))
        print('  entries only we provide (blind spot)        : %d (%.1f%%)'
              % (len(miss), 100.0 * len(miss) / max(1, len(entries))))
        print('=' * 68)

        # 质量分层
        stat = {}
        for reg in ('header-meta', 'main-code', 'tail-data'):
            sub = [x for x in final if region_of(x) == reg]
            if not sub:
                continue
            hp = hr = hs = 0
            for x in sub:
                p, r, s = quality(program, x)
                hp += p
                hr += r
                hs += s
            stat[reg] = (len(sub), hp, hr, hs)
            print('  %-12s n=%5d  push=%5d(%5.1f%%)  ret=%5d(%5.1f%%)  susp=%5d(%5.1f%%)'
                  % (reg, len(sub), hp, 100.0 * hp / len(sub), hr, 100.0 * hr / len(sub),
                     hs, 100.0 * hs / len(sub)))

        # 叶子函数(结构性盲区)
        new_main = [x for x in new if region_of(x) == 'main-code']
        leaf = 0
        for x in new_main:
            p, r, s = quality(program, x)
            if (not p) and r and (not s):
                leaf += 1
        print()
        print('  new funcs in main code      : %d' % len(new_main))
        print('  of which leaf funcs (no push prologue but has return, no susp): %d' % leaf)
        print('     ^ structurally invisible to a prologue-based scanner')

        # 导出
        p1 = os.path.join(args.outdir, 'functions_baseline.tsv')
        with open(p1, 'w', encoding='utf-8') as fp:
            fp.write('# offset\tsize\n')
            for x in sorted(base):
                fp.write('%d\t%d\n' % (x, base[x]))

        p2 = os.path.join(args.outdir, 'functions_with_seeds.tsv')
        with open(p2, 'w', encoding='utf-8') as fp:
            fp.write('# offset\tsize\tregion\n')
            for x in sorted(final):
                fp.write('%d\t%d\t%s\n' % (x, final[x], region_of(x)))

        print()
        print('wrote %s' % p1)
        print('wrote %s' % p2)


if __name__ == '__main__':
    sys.exit(main())
