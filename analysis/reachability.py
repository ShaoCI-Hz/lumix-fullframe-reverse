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


# ---------- 绗?1 姝?鍙栧緱 133 涓弻閲嶉獙璇佸叆鍙?闄?搂22 澶栦笉鍙?----------
print()
print('=== 1) 寤虹珛宸查獙璇佸叆鍙ｉ泦(鍚?搂22)===')


def bl_targets(dd, start, limit=4000):
    """浠?start 绾挎€ф敹闆?BL/BLX 鐩爣(浠呯敤浜庢壘绉嶅瓙)"""
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
print(f'  BL/BLX 鐩爣 {len(allbl)},鍏朵腑鏈夊簭瑷€ {len(seeds)}')

# ---------- 绗?2 姝?鈽?鍙揪鎬ч┍鍔ㄧ殑閫掑綊涓嬮檷(涓嶄緷璧栧簭瑷€)----------
print()
print('=== 2) 鈽?鍙揪鎬ч€掑綊涓嬮檷(妯℃嫙 Ghidra:璺熼殢鎵€鏈夋帶鍒舵祦,鎸夊彲杈炬€у垽瀹?===')
print('  瑙勫垯: 浠庣瀛愬嚭鍙?鍙鍙嶆眹缂栨湁鏁堝氨缁х画;閬?BL/BLX/B/Bcc 灏卞姞鍏ョ洰鏍?)

code = {}          # addr -> (size, mnemonic, op_str, bytes)
func_entries = set(seeds)
work = list(seeds)
visited_start = set()
MAX_ITER = 4_000_000


def valid_at(addr):
    """鍒ゅ畾 addr 鏄惁鏄悎鐞嗙殑浠ｇ爜璧风偣:鍙嶆眹缂栨垚鍔?+ 鍚庣画涓€灏忔涔熸湁鏁?""
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
            # 閬囧埌鏄庢樉缁撴潫/鍒嗘敮灏卞仠
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
            # 璺熼殢鎺у埗娴? BL/BLX(璋冪敤)涓?B/Bcc(鍒嗘敮)
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
                            work.append(t)      # 鍒嗘敮鐩爣涔熻瑕嗙洊(鍚屼竴鍑芥暟鍐?
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

print(f'  杩唬姝ユ暟: {steps:,}')
print(f'  鍙揪浠ｇ爜鍦板潃: {len(code):,}')
print(f'  鍑芥暟鍏ュ彛鏁? : {len(func_entries):,}  (绉嶅瓙 {len(seeds)} 鈫?鎵╁睍鍚?')
print(f'  鎺у埗娴佽竟    : call={branches["call"]:,}  branch={branches["branch"]:,}')

# ---------- 绗?3 姝?瑕嗙洊鐜?----------
print()
print('=== 3) 瑕嗙洊鐜?===')
print(f'  鍙揪鎸囦护鏁? {len(code):,}')
print(f'  鍙揪瀛楄妭鏁? {sum(v[0] for v in code.values()):,} / {n:,} = {sum(v[0] for v in code.values())/n:.1%}')
print(f'  瀵规瘮 搂22 涓ユ牸闆? 133 鍑芥暟 / 11,255 鎸囦护')
print(f'  鈫?鎸囦护鏁板闀?{len(code)/max(11255,1):.1f} 鍊?)

# ---------- 绗?4 姝?鑷唇鎬?鐢ㄦ柊鍏ュ彛闆嗛噸娴?----------
print()
print('=== 4) 鈽?璋冪敤鍥捐嚜娲芥€ч噸娴?===')
tot, hit = 0, 0
for s in func_entries:
    for t in bl_targets(d, s):
        tot += 1
        if t in func_entries:
            hit += 1
print(f'  BL 鐩爣鍛戒腑鍑芥暟鍏ュ彛: {hit}/{tot} = {hit/max(tot,1):.1%}')
print(f'  (瀵规瘮: 搂22 涓ユ牸闆?6.9%, 搂11.5 瀹芥澗闆?3.0%)')

# ---------- 绗?5 姝?鍑芥暟瑙勬ā鍒嗗竷 ----------
print()
print('=== 5) 鍑芥暟瑙勬ā(Top 10 鏈€闀?===')
lens = []
for s in func_entries:
    # 绮楃暐:浠?s 璧板埌 return
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
    print(f'    0x{s:06X}  {cnt} 鎸囦护  杩愯鍦板潃 0x{BASE+s:08X}')

with open(r'.\analysis\lens_reachability.txt',
          'w', encoding='utf-8', newline='\n') as f:
    f.write('# 鍙揪鎬ч€掑綊涓嬮檷缁撴灉(4001V020.plf)\n')
    f.write(f'# 鍙揪鎸囦护 {len(code):,},鍑芥暟鍏ュ彛 {len(func_entries):,}\n')
    f.write(f'# 鎺у埗娴佽竟 call={branches["call"]:,} branch={branches["branch"]:,}\n\n')
    f.write(f'# {"鍏ュ彛鍋忕Щ":>10} {"杩愯鍦板潃":>12} {"瑙勬ā":>6}\n')
    for cnt, s in sorted(lens, key=lambda x: x[1]):
        f.write(f'  0x{s:06X}  0x{BASE+s:08X}  {cnt:>6}\n')
print()
print('[宸插啓 analysis/lens_reachability.txt]')
