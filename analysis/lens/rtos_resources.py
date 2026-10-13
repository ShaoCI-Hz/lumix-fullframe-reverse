"""从镜头固件中提取 RTOS 资源表与子系统符号分布

发现:4 支镜头(4001/4002/4003/4006)内嵌一张定长 12 字节表项的
RTOS 资源表(任务 / 信号量 / 标志 / 消息队列 / 周期),
而 400C/400E 完全没有 —— 且连 OIS/Iris/Zoom/Focus 符号也全部归零。

这张表不在已知的 578 项"变量字典"(位于头部 0x4000-0x9000)之内,
是**第二张独立表**,位于各固件的代码区。

用法:
    python rtos_resources.py [firmware_dir]
"""

import glob
import os
import re
import sys
from collections import OrderedDict

KINDS = OrderedDict([
    ('TSK', 'task'),
    ('SEM', 'semaphore'),
    ('FLG', 'flag'),
    ('DTQ', 'data queue'),
    ('CYC', 'cycle'),
])

# 资源名:NAME_TSK / NAME_FLG / NAME_DTQ / NAME_CYC;信号量: SEM_NAME
RE_RES = re.compile(rb'[A-Z][A-Z0-9_]{2,10}_(?:TSK|FLG|DTQ|CYC)\x00')
RE_SEM = re.compile(rb'SEM_[A-Z0-9_]{2,12}\x00')

# 子系统符号前缀
SUBSYS = OrderedDict([
    ('OIS', re.compile(rb'OIS[A-Za-z0-9_]{2,16}\x00')),
    ('Iris', re.compile(rb'Irs[A-Za-z0-9_]{2,16}\x00')),
    ('Zoom', re.compile(rb'Zm[A-Za-z0-9_]{2,16}\x00')),
    ('Focus', re.compile(rb'Foc[A-Za-z0-9_]{2,16}\x00')),
    ('Motor', re.compile(rb'Mtr[A-Za-z0-9_]{2,16}\x00')),
    ('Gyro', re.compile(rb'Gy[A-Za-z0-9_]{2,16}\x00')),
])


def analyse(path):
    data = open(path, 'rb').read()
    res = sorted(set(m.group(0)[:-1].decode('latin-1') for m in RE_RES.finditer(data)))
    sem = sorted(set(m.group(0)[:-1].decode('latin-1') for m in RE_SEM.finditer(data)))
    offs = [m.start() for m in RE_RES.finditer(data)]
    span = (min(offs), max(offs)) if offs else None
    subsys = {}
    for k, rx in SUBSYS.items():
        subsys[k] = len(set(rx.findall(data)))
    return {
        'size': len(data),
        'res': res,
        'sem': sem,
        'span': span,
        'subsys': subsys,
    }


def main():
    fwdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'firmware')
    files = sorted(glob.glob(os.path.join(fwdir, '*.plf')))
    if not files:
        print('no .plf found in %s' % fwdir)
        return 1

    print('=== RTOS resource table ===')
    print('%-16s %6s %5s %5s %-22s %s' % ('file', 'size', 'res', 'sem', 'table span', 'tasks'))
    print('-' * 118)
    results = {}
    for p in files:
        r = analyse(p)
        results[os.path.basename(p)] = r
        sp = '0x%X-0x%X' % r['span'] if r['span'] else '-'
        tasks = ','.join(x for x in r['res'] if x.endswith('_TSK'))
        print('%-16s %6d %5d %5d %-22s %s' % (os.path.basename(p), r['size'],
                                              len(r['res']), len(r['sem']), sp, tasks))

    print()
    print('=== subsystem symbol counts ===')
    print('%-16s %s' % ('file', '  '.join('%6s' % k for k in SUBSYS)))
    print('-' * 90)
    for name, r in results.items():
        print('%-16s %s' % (name, '  '.join('%6d' % r['subsys'][k] for k in SUBSYS)))

    # 有/无资源表的二分
    with_tbl = [n for n, r in results.items() if r['res']]
    without = [n for n, r in results.items() if not r['res']]
    print()
    print('=== platform split ===')
    print('  with RTOS table    : %s' % ', '.join(with_tbl))
    print('  without any symbols: %s' % ', '.join(without))

    if len(with_tbl) > 1:
        sets = [set(results[n]['res']) for n in with_tbl]
        common = set.intersection(*sets)
        print('  resource names shared by all %d: %d' % (len(with_tbl), len(common)))
        print('  %s' % ', '.join(sorted(common)))

        semsets = [set(results[n]['sem']) for n in with_tbl]
        cs = set.intersection(*semsets) if semsets else set()
        print('  semaphores shared by all %d: %s' % (len(with_tbl), ', '.join(sorted(cs))))

    print()
    print('=== full resource list (from the largest one) ===')
    biggest = max(with_tbl, key=lambda n: results[n]['size']) if with_tbl else None
    if biggest:
        r = results[biggest]
        for x in r['res']:
            kind = x.rsplit('_', 1)[-1]
            print('  %-18s %s' % (x, KINDS.get(kind, '?')))
        for x in r['sem']:
            print('  %-18s semaphore' % x)

    return 0


if __name__ == '__main__':
    sys.exit(main())
