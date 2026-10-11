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
print(f'4001V020.plf: {n:,} B,鍩哄潃 0x{BASE:08X}')


def is_prologue(off):
    """涓ユ牸搴忚█鍒ゅ畾: PUSH{r0-r7,lr}=0xB5xx 鎴?PUSH.W(0xe92d,鍚獿R浣?"""
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
    """鍓嶅悜瑙ｇ爜鍒板嚱鏁扮粨灏?杩斿洖 (鎸囦护鍒楄〃, BL鐩爣鍒楄〃, 鏄惁姝ｅ父缁撴潫)"""
    insns, bls = [], []
    addr = start
    while addr < n - 4 and len(insns) < limit:
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            insns.append(ins)
            # 鍙敹闆?BL/BLX(涓嶅惈鏅€?B)
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


# ---------- 绗?1 姝?鏀堕泦鍏ㄩ儴 BL 鐩爣(鍏堝仛涓€閬嶅鏉炬壂鎻?鍙负鎷跨洰鏍囬泦) ----------
print()
print('=== 1) 鏀堕泦鎵€鏈?BL/BLX 鐩爣(鏃犲垵濮嬬瀛?鍏堝叏鎵?===')
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
print(f'  涓嶅悓 BL 鐩爣: {len(all_bl)}')

# ---------- 绗?2 姝?涓ユ牸绉嶅瓙 = BL 鐩爣 涓?鏄簭瑷€ ----------
seeds = {t for t in all_bl if is_prologue(t)}
print(f'  鍏朵腑"鏄嚱鏁板簭瑷€"鐨?涓ユ牸绉嶅瓙): {len(seeds)}')
print(f'  鈫?鐩告瘮 搂11.5 鐨?915 涓鏉剧瀛?鏈绉嶅瓙鏈夊弻閲嶉獙璇?)

# ---------- 绗?3 姝?鐪熸鐨勯€掑綊涓嬮檷(杩唬鎵╁睍) ----------
print()
print('=== 3) 鐪熸鐨勯€掑綊涓嬮檷:杩唬鎵╁睍 ===')
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
        # 璺熼殢 BL 鐩爣:浠呭綋鐩爣鏄湁鏁堝簭瑷€鏃剁撼鍏?        for t in set(bls):
            if t not in funcs and t not in nxt and is_prologue(t):
                nxt.append(t)
    if rounds <= 6 or not nxt:
        print(f'  绗?{rounds} 杞? 鏂扮撼鍏?{len(nxt)} 涓? (绱 {len(funcs)})')
    work = nxt
    if rounds > 200:
        print('  (杈惧埌杞涓婇檺)')
        break
print(f'  鏀舵暃:鍏?{len(funcs)} 涓嚱鏁?鍏ㄩ儴鐢?BL 鐩爣 + 搴忚█鍙岄噸楠岃瘉)')
good = [s for s, v in funcs.items() if v[2]]
bad = [s for s, v in funcs.items() if not v[2]]
print(f'  鍙畬鏁村弽姹囩紪鍒?return 鐨? {len(good)} ({len(good)/len(funcs):.1%})')
print(f'  鏈兘鍒?return 鐨?       : {len(bad)}')

# ---------- 绗?4 姝?璋冪敤鍥捐嚜娲芥€ф楠?鍏抽敭璐ㄩ噺鎸囨爣) ----------
print()
print('=== 4) 鈽?璋冪敤鍥捐嚜娲芥€?涓ユ牸鏍囧噯鐨勬敹鐩?===')


def evaluate(entry_set, label):
    """缁熻鎵€鏈夊嚱鏁扮殑 BL 鐩爣涓?鍛戒腑 entry_set 鐨勬瘮渚?""
    tot, hit = 0, 0
    for s in entry_set:
        v = funcs.get(s)
        if not v:
            continue
        for t in v[1]:
            tot += 1
            if t in entry_set:
                hit += 1
    print(f'  [{label}] BL 鐩爣鍛戒腑鍑芥暟鍏ュ彛: {hit}/{tot} = {hit/max(tot,1):.1%}')
    return hit / max(tot, 1)


r_strict = evaluate(set(good), '涓ユ牸闆?浠呭簭瑷€鍏ュ彛)')

# 瀵规瘮:瀹芥澗闆?搂11.5 鐨勫仛娉?"鏈夊紩鐢ㄧ殑搴忚█")
loose = set()
for s in range(0, n - 2, 2):
    if d[s + 1] == 0xB5:
        loose.add(s)
print(f'  (瀹芥澗搴忚█闆嗗ぇ灏?{len(loose)},瀵规瘮鐢?')
tot, hit = 0, 0
for s in list(loose)[:2000]:
    insns, bls, ok = walk(s)
    if not ok:
        continue
    for t in bls:
        tot += 1
        if t in loose:
            hit += 1
print(f'  [瀹芥澗闆哴 BL 鐩爣鍛戒腑鍑芥暟鍏ュ彛: {hit}/{tot} = {hit/max(tot,1):.1%}')

# ---------- 绗?5 姝?瑕嗙洊鐨勬寚浠ゆ暟 ----------
cov = sum(v[0] for v in funcs.values())
print()
print('=== 5) 瑕嗙洊缁熻 ===')
print(f'  涓ユ牸闆嗗嚱鏁版暟  : {len(funcs)}')
print(f'  瑕嗙洊鎸囦护鏁?   : {cov:,}')
print(f'  骞冲潎鍑芥暟闀垮害  : {cov/max(len(funcs),1):.1f} 鎸囦护')
lens = sorted(v[0] for v in funcs.values())
if lens:
    print(f'  闀垮害涓綅鏁?   : {lens[len(lens)//2]}')

# ---------- 绗?6 姝?鐢ㄤ弗鏍奸泦閲嶅仛 鍑芥暟鈫斿湴鍧€鍥?----------
print()
print('=== 6) 鐢ㄤ弗鏍奸泦閲嶅仛 鍑芥暟鈫斿湴鍧€ 鍏崇郴鍥?===')
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
print(f'  鏈夊湴鍧€寮曠敤鐨勫嚱鏁? {len(func_addrs)}')
print(f'  琚紩鐢ㄧ殑鍦板潃    : {len(addr_users)}')
print()
print('  琚渶澶氬嚱鏁板叡浜殑鍦板潃(鍓?12):')
for v, users in sorted(addr_users.items(), key=lambda kv: -len(kv[1]))[:12]:
    t = 'SRAM' if 0x20000000 <= v < 0x20040000 else ('PERIPH' if 0x40000000 <= v < 0x40100000 else 'FLASH')
    print(f'    0x{v:08X} {len(users):>5} 涓嚱鏁? {t}')

# 杈撳嚭
OUT = r'.\analysis\lens_strict_funcs.txt'
L = ['# 涓ユ牸閫掑綊涓嬮檷閲嶅缓鐨勫嚱鏁伴泦(4001V020.plf)',
     f'# 鏍囧噯:鍑芥暟鍏ュ彛蹇呴』鍚屾椂婊¤冻 (a) 鏄煇鏉?BL/BLX 鐨勭洰鏍?(b) 鑷韩浠ュ嚱鏁板簭瑷€寮€濮?,
     f'# 鍑芥暟鏁? {len(funcs)}  鍙畬鏁村弽姹囩紪: {len(good)}  瑕嗙洊鎸囦护: {cov:,}',
     '',
     f'# {"鍏ュ彛":>10} {"鎸囦护":>6} {"BL鏁?:>6} {"瀹屾垚":>5} {"搴忚█":>8}']
for s in sorted(funcs):
    ni, bls, ok, pro = funcs[s]
    L.append(f'  0x{s:06X} {ni:>6} {len(bls):>6} {"Y" if ok else "N":>5} {str(pro):>8}')
with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(L))
print()
print(f'[宸插啓 {OUT}]')
