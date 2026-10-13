"""函数重要度地图 —— 客观分层,替代不可用的符号标注

背景(见 docs/zh/07-镜头固件.md §29):
  本 .plf 里的符号/字符串是**惰性的调试元数据** —— 代码零引用它们
  (变量字典窗口 0x4000-0x9000 的引用数为 0)。
  因此无法用符号名标注函数,只能改用客观指标分层。

指标:
  入度(in-degree)  —— 被调用次数:库函数/hub 的特征
  出度(out-degree) —— 调用了几个函数
  函数体大小
  所在区域(header / main-code / tail)

用法:
  set GHIDRA_INSTALL_DIR=<ghidra dir>
  set JAVA_HOME=<jdk21>
  python function_map.py --project-dir <dir> --project-name <name> \
        --program /4001V020.plf --outdir out
"""

import argparse
import os
import sys
from collections import Counter

IMG_LO = 0x08000000
CODE_LO = IMG_LO + 0x028000
CODE_HI = IMG_LO + 0x068000


def region_of(a):
    if a < CODE_LO:
        return 'header'
    if a < CODE_HI:
        return 'main-code'
    return 'tail'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--project-dir', required=True)
    ap.add_argument('--project-name', required=True)
    ap.add_argument('--program', required=True, help='e.g. /4001V020.plf')
    ap.add_argument('--outdir', default='.')
    args = ap.parse_args()

    import pyghidra
    pyghidra.start()
    from pyghidra import open_project, program_context

    if not os.path.isdir(args.outdir):
        os.makedirs(args.outdir)

    proj = open_project(args.project_dir, args.project_name)
    with program_context(proj, args.program) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        indeg = Counter()
        rows = []

        for f in fm.getFunctions(True):
            fa = f.getEntryPoint().getOffset()
            out_targets = set()
            it = f.getBody().getAddresses(True)
            while it.hasNext():
                ins = listing.getInstructionContaining(it.next())
                if ins is None:
                    continue
                for r in ins.getReferencesFrom():
                    if r.getReferenceType().isCall():
                        t = r.getToAddress()
                        if t is not None:
                            out_targets.add(t.getOffset())
                            indeg[t.getOffset()] += 1
            rows.append((fa, f.getName(), int(f.getBody().getNumAddresses()),
                         region_of(fa), len(out_targets)))

        # 分层
        hub = [r for r in rows if indeg.get(r[0], 0) >= 20]
        mid = [r for r in rows if 3 <= indeg.get(r[0], 0) < 20]
        leaf = [r for r in rows if indeg.get(r[0], 0) < 3]

        print('total functions: %d' % len(rows))
        print('  hub  (called >=20) : %4d' % len(hub))
        print('  mid  (called 3-19) : %4d' % len(mid))
        print('  leaf (called 0-2)  : %4d' % len(leaf))
        print()

        print('=== region census ===')
        for rg in ('header', 'main-code', 'tail'):
            sub = [r for r in rows if r[3] == rg]
            if not sub:
                continue
            tot = sum(r[2] for r in sub)
            print('  %-10s funcs=%5d  bytes=%7d  avg=%6.1f'
                  % (rg, len(sub), tot, tot / float(len(sub))))
        print()

        print('=== hub functions (called >= 20) ===')
        for r in sorted(hub, key=lambda x: -indeg[x[0]]):
            print('  0x%08X %-18s size=%5d outdeg=%3d indeg=%d'
                  % (r[0], r[1], r[2], r[4], indeg[r[0]]))
        print()

        print('=== candidate top-level dispatchers (indeg==0, outdeg>=10) ===')
        top = [r for r in rows if indeg.get(r[0], 0) == 0 and r[4] >= 10]
        for r in sorted(top, key=lambda x: -x[4]):
            print('  0x%08X size=%5d outdeg=%3d' % (r[0], r[2], r[4]))

        p = os.path.join(args.outdir, 'function_map.tsv')
        with open(p, 'w', encoding='utf-8') as fp:
            fp.write('# offset\tname\tsize\tregion\toutdeg\tindeg\tclass\n')
            for fa, nm, size, rg, od in sorted(rows):
                ind = indeg.get(fa, 0)
                cls = 'hub' if ind >= 20 else ('mid' if ind >= 3 else 'leaf')
                fp.write('%d\t%s\t%d\t%s\t%d\t%d\t%s\n' % (fa, nm, size, rg, od, ind, cls))
        print()
        print('wrote %s' % p)
    return 0


if __name__ == '__main__':
    sys.exit(main())
