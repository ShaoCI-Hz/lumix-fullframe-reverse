import os
import re
import struct
from collections import Counter, defaultdict

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

BASE = 0x08000000
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
print(f'4001V020.plf: {n:,} B,基址 0x{BASE:08X}')


def is_prologue(off):
    """严格序言判定: PUSH{r0-r7,lr}=0xB5xx 或 PUSH.W(0xe92d,含LR位)"""
    if off + 2 > n:
        return None
    if d[off + 1] == 0xB5:
        return 'push16'
    if d[off:off + 2] == b'\x2d\xe9' and off + 4 <= n:
        mask = struct.unpack_from('<H', d, off + 2)[0]
        if mask & 0x4000:
            return 'pushw'
    return None


def walk(start, limit=2000):
    """前向解码到函数结尾;返回 (指令列表, BL目标列表, 是否正常结束)"""
    insns, bls = [], []
    addr = start
    while addr < n - 4 and len(insns) < limit:
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            insns.append(ins)
            # 只收集 BL/BLX(不含普通 B)
            if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
                try:
                    t = int(ins.op_str[1:], 16) & ~1
                    if 0 <= t < n:
                        bls.append(t)
                except Exception:
                    pass
            if (ins.mnemonic == 'pop' and 'pc' in ins.op_str) or (ins.mnemonic == 'bx' and 'lr' in ins.op_str):
                ok = True
                addr += ins.size
                return insns, bls, True
            addr += ins.size
            break
        if not got:
            break
    return insns, bls, False


# ---------- 第 1 步:收集全部 BL 目标(先做一遍宽松扫描,只为拿目标集) ----------
print()
print('=== 1) 收集所有 BL/BLX 目标(无初始种子,先全扫)===')
all_bl = Counter()
addr = 0
while addr < n - 4:
    got = False
    for ins in md.disasm(d[addr:addr + 4], addr):
        got = True
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                t = int(ins.op_str[1:], 16) & ~1
                if 0 <= t < n:
                    all_bl[t] += 1
            except Exception:
                pass
        break
    addr += 2
print(f'  不同 BL 目标: {len(all_bl)}')

# ---------- 第 2 步:严格种子 = BL 目标 且 是序言 ----------
seeds = {t for t in all_bl if is_prologue(t)}
print(f'  其中"是函数序言"的(严格种子): {len(seeds)}')
print(f'  → 相比 §11.5 的 915 个宽松种子,本次种子有双重验证')

# ---------- 第 3 步:真正的递归下降(迭代扩展) ----------
print()
print('=== 3) 真正的递归下降:迭代扩展 ===')
funcs = {}
work = sorted(seeds)
rounds = 0
while work:
    rounds += 1
    nxt = []
    for s in work:
        if s in funcs:
            continue
        insns, bls, ok = walk(s)
        if not ok or len(insns) < 3:
            funcs[s] = (len(insns), [], False, is_prologue(s))
            continue
        funcs[s] = (len(insns), bls, True, is_prologue(s))
        # 跟随 BL 目标:仅当目标是有效序言时纳入
        for t in set(bls):
            if t not in funcs and t not in nxt and is_prologue(t):
                nxt.append(t)
    if rounds <= 6 or not nxt:
        print(f'  第 {rounds} 轮: 新纳入 {len(nxt)} 个  (累计 {len(funcs)})')
    work = nxt
    if rounds > 200:
        print('  (达到轮次上限)')
        break
print(f'  收敛:共 {len(funcs)} 个函数(全部由 BL 目标 + 序言双重验证)')
good = [s for s, v in funcs.items() if v[2]]
bad = [s for s, v in funcs.items() if not v[2]]
print(f'  可完整反汇编到 return 的: {len(good)} ({len(good)/len(funcs):.1%})')
print(f'  未能到 return 的        : {len(bad)}')

# ---------- 第 4 步:调用图自洽性检验(关键质量指标) ----------
print()
print('=== 4) ★ 调用图自洽性(严格标准的收益)===')


def evaluate(entry_set, label):
    """统计所有函数的 BL 目标中,命中 entry_set 的比例"""
    tot, hit = 0, 0
    for s in entry_set:
        v = funcs.get(s)
        if not v:
            continue
        for t in v[1]:
            tot += 1
            if t in entry_set:
                hit += 1
    print(f'  [{label}] BL 目标命中函数入口: {hit}/{tot} = {hit/max(tot,1):.1%}')
    return hit / max(tot, 1)


r_strict = evaluate(set(good), '严格集(仅序言入口)')

# 对比:宽松集(§11.5 的做法,"有引用的序言")
loose = set()
for s in range(0, n - 2, 2):
    if d[s + 1] == 0xB5:
        loose.add(s)
print(f'  (宽松序言集大小 {len(loose)},对比用)')
tot, hit = 0, 0
for s in list(loose)[:2000]:
    insns, bls, ok = walk(s)
    if not ok:
        continue
    for t in bls:
        tot += 1
        if t in loose:
            hit += 1
print(f'  [宽松集] BL 目标命中函数入口: {hit}/{tot} = {hit/max(tot,1):.1%}')

# ---------- 第 5 步:覆盖的指令数 ----------
cov = sum(v[0] for v in funcs.values())
print()
print('=== 5) 覆盖统计 ===')
print(f'  严格集函数数  : {len(funcs)}')
print(f'  覆盖指令数    : {cov:,}')
print(f'  平均函数长度  : {cov/max(len(funcs),1):.1f} 指令')
lens = sorted(v[0] for v in funcs.values())
if lens:
    print(f'  长度中位数    : {lens[len(lens)//2]}')

# ---------- 第 6 步:用严格集重做 函数↔地址图 ----------
print()
print('=== 6) 用严格集重做 函数↔地址 关系图 ===')
func_addrs = defaultdict(set)
addr_users = defaultdict(set)
for s in good:
    insns, _, _ = walk(s)
    for ins in insns:
        op = ins.op_str
        if '[pc,' in op:
            m = re.search(r'#(0x[0-9a-f]+)', op)
            if not m:
                continue
            tgt = ins.address + 4 + int(m.group(1), 16)
            if tgt + 4 > n:
                continue
            val = struct.unpack_from('<I', d, tgt)[0]
            if 0x20000000 <= val < 0x20040000 or 0x40000000 <= val < 0x40100000 or BASE <= val < BASE + 0x100000:
                func_addrs[s].add(val)
                addr_users[val].add(s)
print(f'  有地址引用的函数: {len(func_addrs)}')
print(f'  被引用的地址    : {len(addr_users)}')
print()
print('  被最多函数共享的地址(前 12):')
for v, users in sorted(addr_users.items(), key=lambda kv: -len(kv[1]))[:12]:
    t = 'SRAM' if 0x20000000 <= v < 0x20040000 else ('PERIPH' if 0x40000000 <= v < 0x40100000 else 'FLASH')
    print(f'    0x{v:08X} {len(users):>5} 个函数  {t}')

# 输出
OUT = r'.\analysis\lens\lens_strict_funcs.txt'
L = ['# 严格递归下降重建的函数集(4001V020.plf)',
     f'# 标准:函数入口必须同时满足 (a) 是某条 BL/BLX 的目标 (b) 自身以函数序言开始',
     f'# 函数数: {len(funcs)}  可完整反汇编: {len(good)}  覆盖指令: {cov:,}',
     '',
     f'# {"入口":>10} {"指令":>6} {"BL数":>6} {"完成":>5} {"序言":>8}']
for s in sorted(funcs):
    ni, bls, ok, pro = funcs[s]
    L.append(f'  0x{s:06X} {ni:>6} {len(bls):>6} {"Y" if ok else "N":>5} {str(pro):>8}')
with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(L))
print()
print(f'[已写 {OUT}]')
