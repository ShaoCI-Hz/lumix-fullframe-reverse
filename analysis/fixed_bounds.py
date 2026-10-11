import os
import struct
from collections import Counter

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


def get_branch_target(ins):
    """杩斿洖鍒嗘敮/璋冪敤鐩爣(鏂囦欢鍋忕Щ),鏃犲垯 None"""
    m, op = ins.mnemonic, ins.op_str
    if m in ('bl', 'blx', 'b') or m.startswith('b'):
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


# ---------- 1) 绉嶅瓙:BL 鐩爣 鈭?搴忚█(鍚?搂22)----------
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
print(f'绉嶅瓙(BL 鐩爣 鈭?搴忚█): {len(seeds)}')

# ---------- 2) 鈽?淇鐗?鍑芥暟鍐呮壂鎻?B 鍒嗘敮涓嶉噸鏂板紑鍑芥暟)----------
print()
print('=== 淇鐗?鍑芥暟鍐呮帶鍒舵祦(鍒嗘敮鐩爣鍙湪鍚屼竴鍑芥暟鍐呰窡闅?===')
FUNC_MAX = 0x2000     # 鍗曞嚱鏁版渶澶ц寖鍥?8KB(鍚堢悊涓婇檺)
funcs = {}


def scan_function(entry):
    """浠?entry 鎵弿,鍒嗘敮鐩爣鍙湪鏈嚱鏁拌寖鍥村唴璺熼殢;杩斿洖 (瑕嗙洊鍦板潃闆? 瑙勬ā, BL鐩爣)"""
    covered = {}
    work = [entry]
    bls = []
    lo, hi = entry, entry
    steps = 0
    while work and steps < 20000:
        addr = work.pop()
        if addr in covered:
            continue
        if addr < 0 or addr + 2 > n:
            continue
        # 杈圭晫瀹堝崼: 涓嶅緱鍋忕鍏ュ彛瓒呰繃 FUNC_MAX
        if abs(addr - entry) > FUNC_MAX:
            continue
        cur = addr
        while cur < n - 4 and steps < 20000:
            steps += 1
            got = False
            for ins in md.disasm(d[cur:cur + 4], cur):
                got = True
                covered[cur] = ins
                lo = min(lo, cur)
                hi = max(hi, cur)
                m, op = ins.mnemonic, ins.op_str
                if m in ('bl', 'blx'):
                    t = get_branch_target(ins)
                    if t is not None:
                        bls.append(t)          # 璁板綍璋冪敤,浣嗕笉鍘绘壂鎻忕洰鏍?                    # 璋冪敤杩斿洖鍚庣户缁?                elif m.startswith('b'):
                    t = get_branch_target(ins)
                    if t is not None and abs(t - entry) <= FUNC_MAX:
                        work.append(t)         # 鍒嗘敮鐩爣:鍚屼竴鍑芥暟鍐?                    cur += ins.size
                    break                      # 鏃犳潯浠跺垎鏀悗涓茶缁х画鏃犳剰涔?                if (m == 'pop' and 'pc' in op) or (m == 'bx' and 'lr' in op):
                    steps = 20000
                    break
                cur += ins.size
                break
            if not got:
                break
            if steps >= 20000:
                break
    return covered, len(covered), bls


tot_instr = 0
bad = 0
for s in seeds:
    cov, cnt, bls = scan_function(s)
    if cnt < 3:
        bad += 1
        continue
    funcs[s] = (cov, cnt, bls)
    tot_instr += cnt

print(f'  鍑芥暟鏁?鈮? 鎸囦护): {len(funcs)}  (涓㈠純杩囩煭 {bad})')
print(f'  鍚堣鎸囦护(鍚噸鍙?: {tot_instr:,}')
sizes = sorted(v[1] for v in funcs.values())
print(f'  瑙勬ā涓綅鏁? {sizes[len(sizes)//2]}   鍧囧€? {tot_instr/max(len(funcs),1):.1f}')
print(f'  鏈€澶ц妯? : {sizes[-1]}   鏈€灏? {sizes[0]}')

print()
print('=== 瑙勬ā鍒嗗竷(淇鍚?瀵规瘮 搂23 鐨?2469 鎸囦护寮傚父)===')
buckets = Counter()
for sz in sizes:
    if sz < 16:
        buckets['0-15'] += 1
    elif sz < 32:
        buckets['16-31'] += 1
    elif sz < 64:
        buckets['32-63'] += 1
    elif sz < 128:
        buckets['64-127'] += 1
    elif sz < 256:
        buckets['128-255'] += 1
    elif sz < 512:
        buckets['256-511'] += 1
    else:
        buckets['512+'] += 1
for b in ('0-15', '16-31', '32-63', '64-127', '128-255', '256-511', '512+'):
    if buckets[b]:
        print(f'    {b:>8} 鎸囦护: {buckets[b]:>4} 涓?)

print()
print('=== Top 8 鏈€闀垮嚱鏁?淇鍚?===')
for s, (cov, cnt, bls) in sorted(funcs.items(), key=lambda kv: -kv[1][1])[:8]:
    print(f'    0x{s:06X}  {cnt:>5} 鎸囦护  (杩愯鍦板潃 0x{BASE+s:08X})')

print()
print('=== 鏃犻噸鍙犵殑瑕嗙洊闆?鎵€鏈夊嚱鏁板悎璧锋潵)===')
union = set()
for cov, cnt, bls in funcs.values():
    union |= set(cov.keys())
print(f'  鍞竴瑕嗙洊鍦板潃: {len(union):,} 鏉℃寚浠?)
print(f'  鍗犳枃浠跺瓧鑺? : {len(union)*2:,} / {n:,} = {len(union)*2/n:.1%}')
print(f'  (瀵规瘮 搂23 鍙揪鎬ч泦 71,507 鏉?')

print()
print('=== 璋冪敤鍥?BL 鐩爣鍛戒腑鍑芥暟鍏ュ彛 ===')
entry_set = set(funcs.keys())
tot, hit = 0, 0
for s, (cov, cnt, bls) in funcs.items():
    for t in bls:
        tot += 1
        if t in entry_set:
            hit += 1
print(f'  {hit}/{tot} = {hit/max(tot,1):.1%}')

with open(r'.\analysis\lens_fixed_bounds.txt',
          'w', encoding='utf-8', newline='\n') as f:
    f.write('# 淇鍚庣殑鍑芥暟杈圭晫(鍑芥暟鍐呮帶鍒舵祦,鍒嗘敮涓嶈法鍑芥暟)\n')
    f.write(f'# 鍑芥暟鏁?{len(funcs)},鍞竴瑕嗙洊 {len(union):,} 鎸囦护 = {len(union)*2/n:.1%} 鏂囦欢\n\n')
    f.write(f'# {"鍏ュ彛":>10} {"杩愯鍦板潃":>12} {"瑙勬ā":>6} {"BL鏁?:>6}\n')
    for s, (cov, cnt, bls) in sorted(funcs.items(), key=lambda kv: -kv[1][1]):
        f.write(f'  0x{s:06X}  0x{BASE+s:08X}  {cnt:>6} {len(bls):>6}\n')
print()
print('[宸插啓 analysis/lens_fixed_bounds.txt]')
