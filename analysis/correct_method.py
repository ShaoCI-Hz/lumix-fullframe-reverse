import os
import struct
from collections import Counter, defaultdict

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

BASE = 0x08000000
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
print(f'4001V020.plf: {n:,} B (0x{n:X}),鍩哄潃 0x{BASE:08X}')


def is_prologue(off):
    if off + 2 > n:
        return False
    if d[off + 1] == 0xB5:
        return True
    if d[off:off + 2] == b'\x2d\xe9' and off + 4 <= n:
        return bool(struct.unpack_from('<H', d, off + 2)[0] & 0x4000)
    return False


def branches(ins):
    """杩斿洖 (鐩存帴鐩爣, 鏄惁璋冪敤)"""
    m, op = ins.mnemonic, ins.op_str
    if m in ('bl', 'blx'):
        if op.startswith('#'):
            try:
                return int(op[1:], 16) & ~1, True
            except Exception:
                pass
        return None, True
    if m.startswith('b'):
        if op.startswith('#'):
            try:
                return int(op[1:], 16) & ~1, False
            except Exception:
                pass
        if m in ('cbz', 'cbnz'):
            parts = op.split(',')
            if len(parts) >= 2 and parts[1].strip().startswith('#'):
                try:
                    return int(parts[1].strip()[1:], 16) & ~1, False
                except Exception:
                    pass
    return None, False


# ---------- 搂22 鐨?133 涓弗鏍肩瀛?----------
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
print(f'涓ユ牸绉嶅瓙: {len(seeds)}')

# ---------- 鈽?姝ｇ‘鏂规硶 ----------
# 闃舵 A:涓嶅彲杈句唬鐮佷笉杩涘叆鍏ュ彛闆?鈥斺€?浠庣瀛愬嚭鍙?鍙湪"浠ｇ爜娴?涓敹闆?BL 鐩爣
# 闃舵 B:姣忔璋冪敤鐙珛澶勭悊(涓嶆妸璋冪敤鑰呯殑鍒嗘敮闆嗗甫杩囧幓),鐢ㄨ繑鍥炴爤鍒ゅ畾杈圭晫
print()
print('=== 闃舵 A+B:浠ｇ爜娴佸唴鏀堕泦鍏ュ彛 + 杩斿洖鏍堝畾杈圭晫 ===')

code_addr = set()        # 宸茬‘璁や负浠ｇ爜鐨勫湴鍧€
entries = set(seeds)
func_info = {}
deferred = list(seeds)   # 寰呭垎鏋愮殑鍑芥暟鍏ュ彛
MAXF = 3000


def analyze_func(entry):
    """鐙珛鍒嗘瀽涓€涓嚱鏁?鍒嗘敮闆嗙嫭绔?閬囪繑鍥炰笖鍒嗘敮闆嗙┖ => 缁撴潫"""
    cov = {}
    work = [entry]
    bls = []
    steps = 0
    progressed = True
    while work and steps < MAXF and progressed:
        progressed = False
        addr = work.pop()
        if addr in cov or addr < 0 or addr + 2 > n:
            continue
        cur = addr
        while cur < n - 4 and steps < MAXF:
            steps += 1
            got = False
            for ins in md.disasm(d[cur:cur + 4], cur):
                got = True
                cov[cur] = ins
                t, iscall = branches(ins)
                m, op = ins.mnemonic, ins.op_str
                if iscall:
                    if t is not None:
                        bls.append(t)
                    cur += ins.size
                elif m.startswith('b') and t is not None:
                    work.append(t)          # 鍑芥暟鍐呭垎鏀?                    cur += ins.size
                elif (m == 'pop' and 'pc' in op) or (m == 'bx' and 'lr' in op):
                    # 鍑芥暟缁撴潫鐐逛箣涓€;鑻ヨ繕鏈夋湭璧扮殑鍒嗘敮鐩爣,缁х画
                    if work:
                        progressed = True
                        break
                    steps = MAXF
                    break
                else:
                    cur += ins.size
                break
            if not got:
                break
            if steps >= MAXF:
                break
    return cov, bls


# 杩唬:鍒嗘瀽 -> 閬囧埌鏂扮殑"鏈夊簭瑷€"BL 鐩爣灏卞姞鍏ュ緟鍒嗘瀽
processed = set()
queue = list(seeds)
rounds = 0
while queue and rounds < 100:
    rounds += 1
    nq = []
    for e in queue:
        if e in processed:
            continue
        processed.add(e)
        cov, bls = analyze_func(e)
        if len(cov) < 3:
            continue
        func_info[e] = (cov, bls)
        code_addr |= set(cov.keys())
        for t in set(bls):
            if t not in processed and t not in nq:
                # 鈽?鍏抽敭:鍙帴鍙?鏈夊簭瑷€"鐨勭洰鏍囦负鏂板嚱鏁板叆鍙?閬垮厤鏁版嵁鍖轰吉鐩爣)
                if is_prologue(t):
                    entries.add(t)
                    nq.append(t)
    queue = nq
    if rounds <= 5:
        print(f'  绗?{rounds} 杞? 鏂板寰呭垎鏋?{len(nq)} (绱鍑芥暟 {len(func_info)})')

print(f'  鍑芥暟鏁? {len(func_info)}')
print(f'  浠ｇ爜鍦板潃(骞堕泦): {len(code_addr):,}')

# 璐ㄩ噺鎸囨爣
sizes = sorted(len(v[0]) for v in func_info.values())
print()
print('=== 璐ㄩ噺鎸囨爣 ===')
print(f'  瑙勬ā涓綅鏁? {sizes[len(sizes)//2]}')
print(f'  瑙勬ā鍧囧€? : {sum(sizes)/len(sizes):.1f}')
print(f'  瑙勬ā鏈€澶? : {sizes[-1]}')
print(f'  瑕嗙洊瀛楄妭  : {len(code_addr)*2:,} / {n:,} = {len(code_addr)*2/n:.1%}')

# 閲嶅彔
ov = Counter()
for cov, _ in func_info.values():
    for ad in cov:
        ov[ad] += 1
multi = sum(1 for v in ov.values() if v > 1)
print(f'  閲嶅彔鐜?   : {multi}/{len(ov)} = {multi/max(len(ov),1):.1%}')

# 鑷唇鎬?BL 鐩爣鍛戒腑"鏈夊簭瑷€"鍏ュ彛闆?es = set(func_info.keys())
tot, hit = 0, 0
for e, (cov, bls) in func_info.items():
    for t in bls:
        tot += 1
        if t in es:
            hit += 1
print(f'  BL 鍛戒腑鏈夊簭瑷€鍏ュ彛: {hit}/{tot} = {hit/max(tot,1):.1%}')
# 鍙︿竴涓洿鏈夋剰涔夌殑鎸囨爣:BL 鐩爣鏄惁钀藉湪"宸茬‘璁や唬鐮?鍐?incode = sum(1 for e, (cov, bls) in func_info.items() for t in bls if t in code_addr)
print(f'  BL 鐩爣钀藉湪浠ｇ爜鍐? {incode}/{tot} = {incode/max(tot,1):.1%}  鈫?鏇村瑙?)

print()
print('=== Top 8 鏈€闀?===')
for e, (cov, bls) in sorted(func_info.items(), key=lambda kv: -len(kv[1][0]))[:8]:
    print(f'    0x{e:06X}  {len(cov):>5} 鎸囦护  (0x{BASE+e:08X})')

print()
print('=== 瑙勬ā鍒嗗竷 ===')
b = Counter()
for sz in sizes:
    if sz < 16:
        b['0-15'] += 1
    elif sz < 32:
        b['16-31'] += 1
    elif sz < 64:
        b['32-63'] += 1
    elif sz < 128:
        b['64-127'] += 1
    elif sz < 256:
        b['128-255'] += 1
    else:
        b['256+'] += 1
for k in ('0-15', '16-31', '32-63', '64-127', '128-255', '256+'):
    if b[k]:
        print(f'    {k:>8}: {b[k]:>4}')

with open(r'.\analysis\lens_correct_method.txt',
          'w', encoding='utf-8', newline='\n') as f:
    f.write('# 姝ｇ‘鏂规硶:浠ｇ爜娴佸唴鏀堕泦鍏ュ彛 + 杩斿洖鏍堝畾杈圭晫\n')
    f.write(f'# 鍑芥暟鏁?{len(func_info)},浠ｇ爜鍦板潃 {len(code_addr):,} = {len(code_addr)*2/n:.1%} 鏂囦欢\n')
    f.write(f'# 閲嶅彔鐜?{multi/max(len(ov),1):.1%},BL 钀戒唬鐮佸唴 {incode/max(tot,1):.1%}\n\n')
    f.write(f'# {"鍏ュ彛":>10} {"杩愯鍦板潃":>12} {"瑙勬ā":>6} {"BL鏁?:>6}\n')
    for e, (cov, bls) in sorted(func_info.items(), key=lambda kv: -len(kv[1][0])):
        f.write(f'  0x{e:06X}  0x{BASE+e:08X}  {len(cov):>6} {len(bls):>6}\n')
print()
print('[宸插啓 analysis/lens_correct_method.txt]')
