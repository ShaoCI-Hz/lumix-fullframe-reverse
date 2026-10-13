"""引用普查 —— 确认镜头的符号/字符串是否为惰性调试元数据

结论(见 docs/zh/07-镜头固件.md §29.2):
  变量字典窗口 0x4000-0x9000 的引用数为 **0**,来自 0 个函数。
  故符号名不能用来定位使用该符号的代码。

本脚本同时给出:
  - 全镜像中所有数据引用按地址区间的分布
  - 引用头部元数据区的函数及其目标
  - 调用图 hub(被调用最多的函数)

用法:
  python ref_census.py --project-dir <dir> --project-name <name> --program /4001V020.plf
"""

import argparse
import os
import sys
from collections import Counter

IMG_LO = 0x08000000
IMG_HI = IMG_LO + 0x100000
VAR_LO = IMG_LO + 0x4000      # 变量字典窗口
VAR_HI = IMG_LO + 0x9000


def bucket(w):
    if w is None:
        return 'none'
    if IMG_LO <= w < IMG_LO + 0x028000:
        return 'image:header'
    if IMG_LO + 0x028000 <= w < IMG_LO + 0x068000:
        return 'image:code'
    if IMG_LO + 0x068000 <= w < IMG_HI:
        return 'image:tail'
    if 0x10000000 <= w < 0x11000000:
        return '0x10xxxxxx'
    if 0x20000000 <= w < 0x21000000:
        return '0x20xxxxxx'
    if 0x40000000 <= w < 0x50000000:
        return '0x4xxxxxxx'
    if w >= 0xE0000000:
        return 'system'
    return 'other'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--project-dir', required=True)
    ap.add_argument('--project-name', required=True)
    ap.add_argument('--program', required=True)
    ap.add_argument('--top-hubs', type=int, default=30)
    args = ap.parse_args()

    import pyghidra
    pyghidra.start()
    from pyghidra import open_project, program_context

    proj = open_project(args.project_dir, args.project_name)
    with program_context(proj, args.program) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        funcs_per_bucket = Counter()
        varrefs = []
        header_refs = []
        incall = Counter()
        nfuncs = 0

        for f in fm.getFunctions(True):
            nfuncs += 1
            fa = f.getEntryPoint().getOffset()
            seen = set()
            it = f.getBody().getAddresses(True)
            while it.hasNext():
                ins = listing.getInstructionContaining(it.next())
                if ins is None:
                    continue
                for r in ins.getReferencesFrom():
                    t = r.getToAddress()
                    w = t.getOffset() if t is not None else None
                    if r.getReferenceType().isCall():
                        if w is not None:
                            incall[w] += 1
                        continue
                    if not r.getReferenceType().isData():
                        continue
                    b = bucket(w)
                    if b not in seen:
                        seen.add(b)
                        funcs_per_bucket[b] += 1
                    if w is not None and VAR_LO <= w < VAR_HI:
                        varrefs.append((fa, w))
                    if b == 'image:header':
                        header_refs.append((fa, w))

        print('functions: %d' % nfuncs)
        print()
        print('=== data-reference buckets (functions touching each) ===')
        for b, n in funcs_per_bucket.most_common():
            print('  %-22s %5d functions' % (b, n))
        print()
        print('=== references into the variable-dictionary window 0x4000-0x9000 ===')
        print('  references: %d   from %d distinct functions'
              % (len(varrefs), len(set(x[0] for x in varrefs))))
        for fa, w in varrefs[:20]:
            print('    func 0x%08X -> %08x' % (fa, w))
        print()
        print('=== references into the header region (targets are code, not tables) ===')
        uniq = sorted(set(header_refs))
        print('  distinct (func,target) pairs: %d' % len(uniq))
        for fa, w in uniq[:30]:
            print('    0x%08X -> %08x' % (fa, w))
        print()
        print('=== call-graph hubs (most called) ===')
        print('  functions called at least once: %d' % len(incall))
        af = program.getAddressFactory().getDefaultAddressSpace()
        for w, cnt in incall.most_common(args.top_hubs):
            f = fm.getFunctionAt(af.getAddress(w))
            print('    %08x  called %4d times  %s' % (w, cnt, f.getName() if f else '-'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
