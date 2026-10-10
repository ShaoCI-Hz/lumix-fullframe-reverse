import os
import struct
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
OUT = r'.\work\lens_functions.txt'

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)


# --- 1) 鏀堕泦鍑芥暟搴忚█绉嶅瓙:Thumb "PUSH {r0-r7, lr}" = 0xB5xx (瀛楄妭搴?xx b5) ---
seeds = []
for o in range(0, n - 2, 2):
    if d[o + 1] == 0xB5:
        seeds.append(o)
print(f'=== 1) 鍑芥暟搴忚█绉嶅瓙 (PUSH {{r0-r7,lr}} = 0xB5xx): {len(seeds)} 涓?===')

# 涔熸敹闆?PUSH.W {.., lr} = e92d xxxx
seeds_w = []
for o in range(0, n - 4, 2):
    if d[o:o + 2] == b'\x2d\xe9':
        mask = struct.unpack_from('<H', d, o + 2)[0]
        if mask & 0x4000:      # LR bit
            seeds_w.append(o)
print(f'    PUSH.W 搴忚█ (e92d ..): {len(seeds_w)} 涓?)


# --- 2) 閫掑綊涓嬮檷:浠庣瀛愬嚭鍙?璺熼殢 BL/B 鐩爣,鍒ゅ畾浠ｇ爜鍙揪鎬?---
def follow_targets(start, limit=200000):
    """浠?start 鍙嶆眹缂?鏀堕泦 BL/B 鐩爣,杩斿洖(鎸囦护鏁? 鐩爣闆? 鏄惁姝ｅ父缁撴潫)"""
    insns = 0
    targets = set()
    addr = start
    ended_ok = False
    while addr < n - 4 and insns < limit:
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            insns += 1
            m = ins.mnemonic
            if m in ('bl', 'b', 'blx', 'bx') and ins.op_str.startswith('#'):
                try:
                    t = int(ins.op_str[1:], 16)
                    if 0 <= t < n:
                        targets.add(t)
                except Exception:
                    pass
            # 鍑芥暟缁撴潫鏍囧織
            if m == 'pop' and 'pc' in ins.op_str:
                ended_ok = True
                return insns, targets, True
            if m == 'bx' and 'lr' in ins.op_str:
                ended_ok = True
                return insns, targets, True
            addr += ins.size
            break
        if not got:
            break
    return insns, targets, ended_ok


all_seeds = sorted(set(seeds) | set(seeds_w))
print()
print('=== 2) 绉嶅瓙鍒ゅ畾(鏄惁鍙嶆眹缂栧埌鍑芥暟缁撳熬)===')
ok_funcs = []
for s in all_seeds:
    cnt, tgts, ok = follow_targets(s, limit=2000)
    if ok and cnt >= 3:
        ok_funcs.append((s, cnt))
print(f'  鑳芥甯稿弽姹囩紪鍒扮粨灏剧殑绉嶅瓙: {len(ok_funcs)} / {len(all_seeds)} ({len(ok_funcs)/max(len(all_seeds),1):.1%})')

# --- 3) 鐢?BL 鐩爣浜ゅ弶楠岃瘉:琚紩鐢ㄧ殑鍏ュ彛 ---
print()
print('=== 3) BL 鐩爣 vs 搴忚█绉嶅瓙 浜ゅ弶楠岃瘉 ===')
# 鏀堕泦鎵€鏈?鏉ヨ嚜"鍙俊鍑芥暟鍐?)鐨?BL 鐩爣
trusted_targets = Counter()
trusted_set = set(s for s, _ in ok_funcs)
for s, _ in ok_funcs[:4000]:
    _, tgts, _ = follow_targets(s, limit=2000)
    for t in tgts:
        trusted_targets[t & ~1] += 1
print(f'  鍙俊 BL 鐩爣鏁? {len(trusted_targets)}')
with_seed = sum(1 for t in trusted_targets if t in trusted_set)
print(f'  鍏朵腑涔熷甫鍑芥暟搴忚█鐨? {with_seed} ({with_seed/max(len(trusted_targets),1):.1%})')

# 琚紩鐢ㄦ渶澶氱殑鐩爣(鏈€鍙兘鏄湡鍑芥暟)
print()
print('  琚紩鐢ㄦ渶澶氱殑 20 涓洰鏍?')
for t, c in trusted_targets.most_common(20):
    has = 'SEED' if t in trusted_set else '    '
    print(f'    0x{t:06X}  x{c:<5} {has}')

# --- 4) 鍙嶆眹缂栦竴涓珮缃俊鍑芥暟 ---
print()
print('=== 4) 楂樼疆淇″嚱鏁板弽姹囩紪绀轰緥 ===')
lines = []
for t, c in trusted_targets.most_common(6):
    lines.append(f'--- func 0x{t:06X} (琚紩鐢?{c} 娆? ---')
    cnt = 0
    for ins in md.disasm(d[t:t + 0x100], t):
        lines.append(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
        cnt += 1
        if cnt >= 30:
            break
    lines.append('')
for l in lines[:70]:
    print(l)

with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(lines))
print(f'[宸插啓鍏?{OUT}]')
