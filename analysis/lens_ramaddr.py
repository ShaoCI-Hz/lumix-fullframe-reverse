import os
import re
import struct
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

# 鏀堕泦鍙橀噺鍚?vars_ = {}
for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{5,40}', d):
    s = m.group().decode()
    if re.search(r'[A-Z]', s) and re.search(r'[a-z]', s):
        if 0x4000 <= m.start() <= 0x9000:
            vars_[m.start()] = s
print(f'鍙橀噺鍚? {len(vars_)} 涓?)

print()
print('=== 1) 鍚嶅瓧闄勮繎鐨?4 瀛楄妭鍊煎垎甯?鐪嬫槸鍚﹀儚 RAM 鍦板潃 0x2000xxxx)===')
vals_after = Counter()
vals_before = Counter()
for pos in vars_:
    e = pos + len(vars_[pos])
    if e + 4 <= n:
        v = struct.unpack_from('<I', d, e)[0]
        vals_after[v] += 1
    if pos >= 4:
        v = struct.unpack_from('<I', d, pos - 4)[0]
        vals_before[v] += 1

print('  鍚嶅瓧鍚?4 瀛楄妭 Top 12:')
for v, c in vals_after.most_common(12):
    tag = ''
    if 0x20000000 <= v < 0x20020000:
        tag = '  <-- RAM!'
    if v < n:
        tag = '  (鏂囦欢鍐呭亸绉?'
    print(f'    0x{v:08X}  x{c}{tag}')

print()
print('  鍚嶅瓧鍓?4 瀛楄妭 Top 12:')
for v, c in vals_before.most_common(12):
    tag = ''
    if 0x20000000 <= v < 0x20020000:
        tag = '  <-- RAM!'
    if v < n:
        tag = '  (鏂囦欢鍐呭亸绉?'
    print(f'    0x{v:08X}  x{c}{tag}')

print()
print('=== 2) 鍏ㄦ枃浠朵腑鐨?RAM 鍦板潃寮曠敤(0x20000000 娈?===')
ram_refs = Counter()
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if 0x20000000 <= v < 0x20040000:
        ram_refs[v & 0xFFFFFC00] += 1        # 鎸?1KB 鍧楄仛鍚?print(f'  RAM 寮曠敤(鎸?1KB 鍧?: {len(ram_refs)} 涓潡')
for v, c in ram_refs.most_common(15):
    print(f'    0x{v:08X}  x{c}')

print()
print('=== 3) 鍙橀噺鍚嶅瓧绗︿覆鐨勫湴鍧€鏈韩鏄惁琚紩鐢?妫€鏌?literal 姹?===')
# 鍙橀噺鍚嶅湴鍧€(鍙兘鏁翠綋浠ヤ竴涓?琛ㄥ熀鍧€"琚紩鐢?
base_candidates = Counter()
for pos in vars_:
    base_candidates[pos & ~0xFF] += 1
print('  鍙橀噺鍚嶅湴鍧€鎸?256 瀵归綈鍚庣殑鍒嗗竷(鍓?10):')
for v, c in base_candidates.most_common(10):
    print(f'    0x{v:06X}  鍚?{c} 涓彉閲忓悕')

print()
print('=== 4) 妫€鏌ュ彉閲忚〃鍖哄煙鐨勫ご閮?琛ㄥご鍙兘鏈夎捣濮嬪湴鍧€/鏁伴噺)===')
for k in range(0x3F00, 0x4020, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:06X}  {seg.hex(" ")}  |{asc}|')
print('  ...')
# 绗竴涓彉閲忓悕鐨勪綅缃箣鍓?first = min(vars_)
print(f'  绗竴涓彉閲忓悕 @0x{first:06X}: {vars_[first]}')
for k in range(first - 0x40, first + 16, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:06X}  {seg.hex(" ")}  |{asc}|')
