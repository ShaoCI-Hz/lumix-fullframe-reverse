import os
import struct
from collections import Counter, defaultdict

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

BASE = 0x08000000
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

# 1) 澶栬鍦板潃鏄庣粏(0x40000000 娈?鎸?16 瀛楄妭瀵归綈鑱氬悎 = 瀵勫瓨鍣ㄧ矑搴?
print('=== 1) 澶栬瀵勫瓨鍣ㄥ湴鍧€(0x40000000 娈?16B 绮掑害)===')
reg = Counter()
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if 0x40000000 <= v < 0x40100000:
        reg[v & 0xFFFFFFF0] += 1
print(f'  涓嶅悓瀵勫瓨鍣? {len(reg)}  寮曠敤鎬绘暟: {sum(reg.values())}')
print('  寮曠敤鏈€澶氱殑 25 涓瘎瀛樺櫒:')
for v, c in reg.most_common(25):
    print(f'    0x{v:08X}  x{c}')

# 2) 鎸夊璁惧潡(256B)鑱氬悎,鐪嬫湁澶氬皯涓璁?blk = Counter()
for v, c in reg.items():
    blk[v >> 8] += c
print()
print(f'  涓嶅悓 256B 澶栬鍧? {len(blk)}')
print('  寮曠敤鏈€澶氱殑 15 涓璁惧潡:')
for b, c in blk.most_common(15):
    print(f'    0x{b<<8:08X}  x{c}')

# 3) 鍑芥暟 <-> RAM/澶栬鍦板潃 鍏崇郴鍥?print()
print('=== 3) 鍑芥暟 鈫?鍦板潃 鍏崇郴鍥?寤?literal 姹犵储寮?===')


def walk(start, limit=1500):
    insns, addr = [], start
    while addr < n - 4 and len(insns) < limit:
        got = False
        for ins in md.disasm(d[addr:addr + 4], addr):
            got = True
            insns.append(ins)
            if (ins.mnemonic == 'pop' and 'pc' in ins.op_str) or (ins.mnemonic == 'bx' and 'lr' in ins.op_str):
                return insns, True
            addr += ins.size
            break
        if not got:
            break
    return insns, False


seeds = sorted(o for o in range(0, n - 2, 2) if d[o + 1] == 0xB5)
print(f'  搴忚█绉嶅瓙: {len(seeds)}')

import re
func_addrs = defaultdict(set)     # 鍑芥暟鍏ュ彛 -> 璇ュ嚱鏁板紩鐢ㄧ殑鍦板潃闆嗗悎
addr_users = defaultdict(set)     # 鍦板潃 -> 浣跨敤瀹冪殑鍑芥暟闆嗗悎
for s in seeds:
    insns, ok = walk(s)
    if not ok or len(insns) < 6:
        continue
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
            if (0x20000000 <= val < 0x20040000 or 0x40000000 <= val < 0x40100000
                    or BASE <= val < BASE + 0x100000):
                func_addrs[s].add(val)
                addr_users[val].add(s)

print(f'  鏈夊湴鍧€寮曠敤鐨勫嚱鏁? {len(func_addrs)}')
print(f'  琚紩鐢ㄧ殑鍦板潃: {len(addr_users)}')
print()
print('  琚渶澶?涓嶅悓鍑芥暟"鍏变韩鐨勫湴鍧€(鍓?15)= 鍏ㄥ眬鍙橀噺/SFR:')
print(f'    {"鍦板潃":>12} {"浣跨敤鍑芥暟鏁?:>10}  绫诲瀷')
for v, users in sorted(addr_users.items(), key=lambda kv: -len(kv[1]))[:15]:
    if 0x20000000 <= v < 0x20040000:
        t = 'SRAM 鍏ㄥ眬鍙橀噺'
    elif 0x40000000 <= v < 0x40100000:
        t = '澶栬瀵勫瓨鍣?
    else:
        t = 'Flash 甯搁噺/琛?
    print(f'    0x{v:08X} {len(users):>10}  {t}')

# 4) 杈撳嚭鎶ュ憡
OUT = r'.\analysis\lens_periph_map.txt'
L = []
L.append('# 闀滃ご鍥轰欢澶栬瀵勫瓨鍣ㄤ笌鍏ㄥ眬鍦板潃鏄犲皠(4001V020.plf)')
L.append(f'# 鍔犺浇鍩哄潃 0x{BASE:08X}')
L.append('')
L.append(f'## 澶栬瀵勫瓨鍣?0x40000000 娈?,鍏?{len(reg)} 涓笉鍚屽瘎瀛樺櫒 / {sum(reg.values())} 娆″紩鐢?)
L.append('')
for v, c in reg.most_common(60):
    L.append(f'  0x{v:08X}  x{c}')
L.append('')
L.append(f'## 澶栬鍧?256B),鍏?{len(blk)} 涓?)
L.append('')
for b, c in blk.most_common(40):
    L.append(f'  0x{b<<8:08X}  x{c}')
L.append('')
L.append('## 琚涓嚱鏁板叡浜殑鍦板潃(鍏ㄥ眬鍙橀噺 / SFR)')
L.append('')
L.append(f'  {"鍦板潃":>12} {"鍑芥暟鏁?:>8}  绫诲瀷')
for v, users in sorted(addr_users.items(), key=lambda kv: -len(kv[1]))[:120]:
    t = 'SRAM' if 0x20000000 <= v < 0x20040000 else ('PERIPH' if 0x40000000 <= v < 0x40100000 else 'FLASH')
    L.append(f'  0x{v:08X} {len(users):>8}  {t}')
with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(L))
print()
print(f'[宸插啓 {OUT}]')
