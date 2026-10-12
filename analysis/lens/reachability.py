import os
import struct
from collections import Counter, defaultdict

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

BASE = 0x08000000
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
print(f'4001V020.plf: {n:,} B (0x{n:X}),基址 0x{BASE:08X}')


def is_prologue(off):
    if off + 2 > n:
        return False
    if d[off + 1] == 0xB5:
        return True
    if d[off:off + 2] == b'\x2d\xe9' and off + 4 <= n:
        return bool(struct.unpack_from('<H', d, off + 2)[0] & 0x4000)
    return False


# ---------- 第 1 步:取得 133 个双重验证入口(除 §22 外不变)----------
print()
print('=== 1) 建立已验证入口集(同 §22)===')


def bl_targets(dd, start, limit=4000):
    """从 start 线性收集 BL/BLX 目标(仅用于找种子)"""
    out = []
    addr = start
    cnt = 0
    while addr < len(dd) - 4 and cnt < limit:
        got = False
        for ins in md.disasm(dd[addr:addr + 4], addr):
            got = True
            cnt += 1
            if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
                try:
                    t = int(ins.op_str[1:], 16) & ~1
                    if 0 <= t < len(dd):
                        out.append(t)
                except Exception:
                    pass
            if (ins.mnemonic == 'pop' and 'pc' in ins.op_str) or (ins.mnemonic == 'bx' and 'lr' in ins.op_str):
                return out
            addr += ins.size
            break
        if not got:
            break
    return out


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
seeds = sorted(t for t in allbl if is_prologue(t))
print(f'  BL/BLX 目标 {len(allbl)},其中有序言 {len(seeds)}')

# ---------- 第 2 步:★ 可达性驱动的递归下降(不依赖序言)----------
print()
print('=== 2) ★ 可达性递归下降(模拟 Ghidra:跟随所有控制流,按可达性判定)===')
print('  规则: 从种子出发,只要反汇编有效就继续;遇 BL/BLX/B/Bcc 就加入目标')

code = {}          # addr -> (size, mnemonic, op_str, bytes)
func_entries = set(seeds)
work = list(seeds)
visited_start = set()
MAX_ITER = 4_000_000


def valid_at(addr):
    """判定 addr 是否是合理的代码起点:反汇编成功 + 后续一小段也有效"""
    if addr < 0 or addr + 2 > n or (addr & 1):
        return None
    cnt = 0
    cur = addr
    first = None
    while cur < n - 2 and cnt < 6:
        got = False
        for ins in md.disasm(d[cur:cur + 4], cur):
            got = True
            if first is None:
                first = ins
            cnt += 1
            cur += ins.size
            # 遇到明显结束/分支就停
            if ins.mnemonic in ('pop', 'bx', 'b', 'bl', 'blx') or ins.mnemonic.startswith('b'):
                return first
            break
        if not got:
            return None
    return first if cnt >= 3 else None


branches = Counter()
steps = 0
while work and steps < MAX_ITER:
    start = work.pop()
    if start in visited_start:
        continue
    visited_start.add(start)
    if valid_at(start) is None:
        continue
    addr = start
    local = 0
    while addr < n - 4 and local < 4000:
        steps += 1
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            code[addr] = (ins.size, ins.mnemonic, ins.op_str, ins.bytes)
            m = ins.mnemonic
            # 跟随控制流: BL/BLX(调用)与 B/Bcc(分支)
            if m == 'bl' or m == 'blx':
                if ins.op_str.startswith('#'):
                    try:
                        t = int(ins.op_str[1:], 16) & ~1
                        if 0 <= t < n:
                            branches['call'] += 1
                            if t not in visited_start:
                                func_entries.add(t)
                                work.append(t)
                    except Exception:
                        pass
            elif m.startswith('b'):
                if ins.op_str.startswith('#'):
                    try:
                        t = int(ins.op_str[1:], 16) & ~1
                        if 0 <= t < n:
                            branches['branch'] += 1
                            work.append(t)      # 分支目标也要覆盖(同一函数内)
                    except Exception:
                        pass
            elif m == 'cbz' or m == 'cbnz':
                # cbz rX, #target
                parts = ins.op_str.split(',')
                if len(parts) >= 2 and parts[1].strip().startswith('#'):
                    try:
                        t = int(parts[1].strip()[1:], 16) & ~1
                        if 0 <= t < n:
                            branches['branch'] += 1
                            work.append(t)
                    except Exception:
                        pass
            elif m in ('pop',) and 'pc' in ins.op_str:
                local = 4000
                break
            elif m == 'bx' and 'lr' in ins.op_str:
                local = 4000
                break
            addr += ins.size
            local += 1
            break
        if not got:
            break
        if local >= 4000:
            break

print(f'  迭代步数: {steps:,}')
print(f'  可达代码地址: {len(code):,}')
print(f'  函数入口数  : {len(func_entries):,}  (种子 {len(seeds)} → 扩展后)')
print(f'  控制流边    : call={branches["call"]:,}  branch={branches["branch"]:,}')

# ---------- 第 3 步:覆盖率 ----------
print()
print('=== 3) 覆盖率 ===')
print(f'  可达指令数: {len(code):,}')
print(f'  可达字节数: {sum(v[0] for v in code.values()):,} / {n:,} = {sum(v[0] for v in code.values())/n:.1%}')
print(f'  对比 §22 严格集: 133 函数 / 11,255 指令')
print(f'  → 指令数增长 {len(code)/max(11255,1):.1f} 倍')

# ---------- 第 4 步:自洽性(用新入口集重测)----------
print()
print('=== 4) ★ 调用图自洽性重测 ===')
tot, hit = 0, 0
for s in func_entries:
    for t in bl_targets(d, s):
        tot += 1
        if t in func_entries:
            hit += 1
print(f'  BL 目标命中函数入口: {hit}/{tot} = {hit/max(tot,1):.1%}')
print(f'  (对比: §22 严格集 6.9%, §11.5 宽松集 3.0%)')

# ---------- 第 5 步:函数规模分布 ----------
print()
print('=== 5) 函数规模(Top 10 最长)===')
lens = []
for s in func_entries:
    # 粗略:从 s 走到 return
    addr, cnt = s, 0
    while addr in code and cnt < 5000:
        sz, m, op, _ = code[addr]
        cnt += 1
        if (m == 'pop' and 'pc' in op) or (m == 'bx' and 'lr' in op):
            break
        addr += sz
    lens.append((cnt, s))
lens.sort(reverse=True)
for cnt, s in lens[:10]:
    print(f'    0x{s:06X}  {cnt} 指令  运行地址 0x{BASE+s:08X}')

with open(r'.\analysis\lens\lens_reachability.txt',
          'w', encoding='utf-8', newline='\n') as f:
    f.write('# 可达性递归下降结果(4001V020.plf)\n')
    f.write(f'# 可达指令 {len(code):,},函数入口 {len(func_entries):,}\n')
    f.write(f'# 控制流边 call={branches["call"]:,} branch={branches["branch"]:,}\n\n')
    f.write(f'# {"入口偏移":>10} {"运行地址":>12} {"规模":>6}\n')
    for cnt, s in sorted(lens, key=lambda x: x[1]):
        f.write(f'  0x{s:06X}  0x{BASE+s:08X}  {cnt:>6}\n')
print()
print('[已写 analysis/lens/lens_reachability.txt]')
