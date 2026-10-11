import os
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
    if off + 2 > n:
        return False
    if d[off + 1] == 0xB5:
        return True
    if d[off:off + 2] == b'\x2d\xe9' and off + 4 <= n:
        return bool(struct.unpack_from('<H', d, off + 2)[0] & 0x4000)
    return False


def target_of(ins):
    m, op = ins.mnemonic, ins.op_str
    if m.startswith('b'):
        if op.startswith('#'):
            try:
                return int(op[1:], 16) & ~1
            except Exception:
                return None
        if m in ('cbz', 'cbnz'):
            parts = op.split(',')
            if len(parts) >= 2 and parts[1].strip().startswith('#'):
                try:
                    return int(parts[1].strip()[1:], 16) & ~1
                except Exception:
                    return None
    return None


# ---------- 1) 鍏ㄥ眬鏀堕泦 BL 鐩爣(浣滀负鍏ュ彛鍊欓€?----------
print()
print('=== 1) 鏀堕泦鍏ㄩ儴 BL/BLX 鐩爣(浣滀负鍑芥暟鍏ュ彛鍊欓€?===')
allbl = Counter()
a = 0
while a < n - 4:
    got = False
    for ins in md.disasm(d[a:a + 4], a):
        got = True
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                t = int(ins.op_str[1:], 16) & ~1
                if 0 <= t < n:
                    allbl[t] += 1
            except Exception:
                pass
        break
    a += 2
entries = sorted(allbl)
print(f'  BL 鐩爣鍏ュ彛鍊欓€? {len(entries)}')
print(f'  鍏朵腑鑷韩鏈夊簭瑷€鐨? {sum(1 for t in entries if is_prologue(t))}')

# ---------- 2) 浠庢瘡涓叆鍙ｅ仛鍑芥暟鍐呮壂鎻?鍒嗘敮涓嶈法鍑芥暟)----------
print()
print('=== 2) 鍑芥暟鍐呮壂鎻?姣忎釜 BL 鐩爣閮藉綋浣滃叆鍙?===')
MAXSPAN = 0x400     # 鍒嗘敮鍋忕鍏ュ彛瓒呰繃 1KB 灏变笉璺熼殢(鏀剁揣,闃茶法鐣?
funcs = {}


def scan(entry):
    covered = {}
    work = [entry]
    bls = []
    steps = 0
    while work and steps < 8000:
        addr = work.pop()
        if addr in covered or addr < 0 or addr + 2 > n:
            continue
        if abs(addr - entry) > MAXSPAN:
            continue
        cur = addr
        while cur < n - 4 and steps < 8000:
            steps += 1
            got = False
            for ins in md.disasm(d[cur:cur + 4], cur):
                got = True
                covered[cur] = ins
                m, op = ins.mnemonic, ins.op_str
                if m in ('bl', 'blx'):
                    t = target_of(ins)
                    if t is not None:
                        bls.append(t)
                    cur += ins.size
                elif m.startswith('b'):
                    t = target_of(ins)
                    if t is not None and abs(t - entry) <= MAXSPAN:
                        work.append(t)
                    cur += ins.size
                elif m == 'pop' and 'pc' in op:
                    steps = 8000
                elif m == 'bx' and 'lr' in op:
                    steps = 8000
                else:
                    cur += ins.size
                break
            if not got:
                break
            if steps >= 8000:
                break
    return covered, bls


for e in entries:
    cov, bls = scan(e)
    if len(cov) >= 3:
        funcs[e] = (cov, bls)

print(f'  鏈夋晥鍑芥暟(鈮? 鎸囦护): {len(funcs)}')

union = set()
overlap = Counter()
for cov, _ in funcs.values():
    for ad in cov:
        union.add(ad)
        overlap[ad] += 1

sizes = sorted(len(v[0]) for v in funcs.values())
print()
print('=== 3) 缁撴灉 ===')
print(f'  鍑芥暟鏁?       : {len(funcs)}')
print(f'  鍞竴瑕嗙洊鎸囦护  : {len(union):,}')
print(f'  鍗犳枃浠跺瓧鑺?   : {len(union)*2:,} / {n:,} = {len(union)*2/n:.1%}')
print(f'  瑙勬ā涓綅鏁?   : {sizes[len(sizes)//2]}')
print(f'  瑙勬ā鍧囧€?     : {sum(sizes)/len(sizes):.1f}')
print(f'  瑙勬ā鏈€澶?     : {sizes[-1]}')

print()
print('  瑙勬ā鍒嗗竷:')
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
        print(f'    {k:>8}: {b[k]:>4} 涓?)

# 閲嶅彔鍒嗘瀽:鍚屼竴鍦板潃琚嚑涓嚱鏁拌鐩?multi = sum(1 for ad, c in overlap.items() if c > 1)
print()
print(f'  琚涓嚱鏁拌鐩栫殑鍦板潃: {multi:,} / {len(union):,} = {multi/len(union):.1%}')
print(f'  (閲嶅彔鐜囬珮璇存槑鍏ュ彛闆嗕腑/鏈変吉鍏ュ彛)')

print()
print('=== 4) 璋冪敤鍥捐嚜娲芥€?===')
es = set(funcs.keys())
tot, hit = 0, 0
for e, (cov, bls) in funcs.items():
    for t in bls:
        tot += 1
        if t in es:
            hit += 1
print(f'  BL 鐩爣鍛戒腑鍏ュ彛闆? {hit}/{tot} = {hit/max(tot,1):.1%}')
print(f'  (瀵规瘮 搂22 涓ユ牸 6.9% / 搂23 鍙揪 98.9%[閮ㄥ垎鑷瘉])')

print()
print('=== 5) Top 8 鏈€闀垮嚱鏁?===')
for e, (cov, bls) in sorted(funcs.items(), key=lambda kv: -len(kv[1][0]))[:8]:
    print(f'    0x{e:06X}  {len(cov):>5} 鎸囦护  杩愯鍦板潃 0x{BASE+e:08X}')

with open(r'.\analysis\lens_hybrid_funcs.txt',
          'w', encoding='utf-8', newline='\n') as f:
    f.write('# 铻嶅悎鏂规硶:鍏ㄩ儴 BL 鐩爣浣滃叆鍙?+ 鍑芥暟鍐呮壂鎻?鍒嗘敮涓嶈法鍑芥暟)\n')
    f.write(f'# 鍑芥暟鏁?{len(funcs)},鍞竴瑕嗙洊 {len(union):,} 鎸囦护 = {len(union)*2/n:.1%} 鏂囦欢\n\n')
    f.write(f'# {"鍏ュ彛":>10} {"杩愯鍦板潃":>12} {"瑙勬ā":>6} {"BL鏁?:>6}\n')
    for e, (cov, bls) in sorted(funcs.items(), key=lambda kv: -len(kv[1][0])):
        f.write(f'  0x{e:06X}  0x{BASE+e:08X}  {len(cov):>6} {len(bls):>6}\n')
print()
print('[宸插啓 analysis/lens_hybrid_funcs.txt]')
