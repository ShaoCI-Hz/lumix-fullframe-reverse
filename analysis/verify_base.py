import os
import struct
from collections import Counter, defaultdict

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
print(f'4001V020.plf: {n:,} B (0x{n:X})')
BASE = 0x08000000

# 鏀堕泦鎵€鏈夎惤鍦?Flash 娈电殑寮曠敤鍊煎強鍏朵綅缃?flash_refs = []
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if BASE <= v < BASE + 0x00100000:
        flash_refs.append((off, v))
print(f'Flash 娈?0x08000000+)寮曠敤: {len(flash_refs)} 鏉?)
uniq = sorted(set(v for _, v in flash_refs))
print(f'鍏朵腑涓嶅悓鍦板潃鍊? {len(uniq)}')
print(f'鍦板潃鑼冨洿: 0x{uniq[0]:08X} .. 0x{uniq[-1]:08X}')
offs = [v - BASE for v in uniq]
print(f'鍑忓幓鍩哄潃鍚庣殑"鏂囦欢鍋忕Щ"鑼冨洿: 0x{min(offs):06X} .. 0x{max(offs):06X}')
print(f'鏂囦欢澶у皬 0x{n:X}  鈫? {"鍏ㄩ儴钀藉湪鏂囦欢鍐?鉁? if max(offs) < n else "鏈夎秴鍑?鉁?}')
print()
print('鏈€鎺ヨ繎鏂囦欢鏈熬鐨?5 涓?')
for v in uniq[-5:]:
    print(f'  0x{v:08X} -> 鍋忕Щ 0x{v-BASE:06X}  (鏂囦欢鍐?{"鏄? if v-BASE < n else "鍚?})')

# 鍏抽敭楠岃瘉:杩欎簺"鍋忕Щ"澶勬槸鍚︽槸鏈夋剰涔夌殑鏁版嵁?
print()
print('=== 楠岃瘉:寮曠敤鐩爣鐨勫亸绉诲鍐呭(鍙?12 涓牱鏈?===')
import random
random.seed(1)
for v in uniq[:6] + uniq[-6:]:
    off = v - BASE
    if off + 16 <= n:
        seg = d[off:off + 16]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
        print(f'  0x{v:08X} -> 0x{off:06X}: {seg.hex(" ")}  |{asc}|')

# 鍏抽敭楠岃瘉 B: 鐢ㄦ寚浠よ涔夐獙璇?鈥斺€?鎵?LDR literal 鎸囦护,鐪嬪畠鍔犺浇鐨勫€兼槸鍚?0x08000000+
print()
print('=== 楠岃瘉 B:LDR literal 鍔犺浇 Flash 娈靛湴鍧€鐨勬ā寮?杩欐槸"鍙栨暟鎹湴鍧€")===')
found = 0
for off in range(0, n - 4, 2):
    cnt = 0
    for ins in md.disasm(d[off:off + 4], off):
        cnt += 1
        op = ins.op_str
        if ins.mnemonic in ('ldr', 'ldr.w') and '[pc,' in op:
            import re
            m = re.search(r'#(0x[0-9a-f]+)', op)
            if m:
                tgt = ins.address + 4 + int(m.group(1), 16)
                if tgt + 4 <= n:
                    lit = struct.unpack_from('<I', d, tgt)[0]
                    if BASE <= lit < BASE + 0x00100000:
                        if found < 8:
                            print(f'  0x{off:06X}: {ins.mnemonic} {op}')
                            print(f'      literal @0x{tgt:06X} = 0x{lit:08X} -> 鍋忕Щ 0x{lit-BASE:06X}')
                        found += 1
        break
print(f'  鍏?{found} 鏉?LDR literal 鍔犺浇 Flash 娈靛湴鍧€')

# 缁熻:杩欎簺鍦板潃鐨勬渶浣庡瓧鑺傚垎甯?浠ｇ爜鍦板潃 bit0=1 鏄?Thumb;鏁版嵁鍦板潃 bit0 甯镐负 0)
print()
print('=== 楠岃瘉 C:鍦板潃 bit0 鍒嗗竷(Thumb 鍑芥暟鎸囬拡 vs 鏁版嵁鎸囬拡)===')
odd = sum(1 for v in uniq if v & 1)
even = len(uniq) - odd
print(f'  濂囨暟(bit0=1,Thumb 浠ｇ爜鎸囬拡): {odd}')
print(f'  鍋舵暟(bit0=0,鏁版嵁鎸囬拡)      : {even}')
print(f'  鈫?鑻ュ伓鏁板崰澶氭暟,璇存槑杩欎簺澶氭槸"鏁版嵁鍦板潃"鑰岄潪"鍑芥暟鎸囬拡"')
