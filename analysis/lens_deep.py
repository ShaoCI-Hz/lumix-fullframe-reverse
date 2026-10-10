import os
import re
import struct
from collections import Counter

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

print('=== 1. 鍏ㄩ儴 ASCII 瀛楃涓蹭腑"鍍忔爣璇?鍛戒护/璺緞"鐨?鎺掗櫎鎸囦护鐮佷贡鐮?===')
# 杩囨护:鍚瓧姣嶄笖鏈夊ぇ鍐?灏忓啓娣峰悎,鎴栧惈鍐掑彿/涓嬪垝绾?鐐圭殑
cand = []
for m in re.finditer(rb'[\x20-\x7e]{5,80}', d):
    s = m.group().decode('ascii', 'replace')
    if re.match(r'^[A-Za-z][A-Za-z0-9_\-\. :/]{4,}$', s) and not re.match(r'^[|@\[\]\\{}<>~`#$%^&*+=]', s):
        cand.append((m.start(), s))
uniq = {}
for off, s in cand:
    uniq.setdefault(s, off)
print(f'  鍊欓€?鍘婚噸){len(uniq)} 涓?')
for s, off in sorted(uniq.items(), key=lambda x: x[1])[:60]:
    print(f'    0x{off:06X}  {s}')

print()
print('=== 2. 鍏抽敭瀛楁悳绱?===')
for kw in (b'CABRIOLET', b'LENS', b'UPDATE', b'VER', b'VERSION', b'PANASONIC', b'PANA',
           b'ERROR', b'BOOT', b'FLASH', b'CHECK', b'CRC', b'SUM', b'KEY', b'AES', b'MCU',
           b'UPD', b'FW', b'SOF', b'EOH', b'$', b'DATE'):
    ps = [m.start() for m in re.finditer(re.escape(kw), d)]
    if ps:
        print(f'  {kw.decode():12} x{len(ps):>4}  棣? {[hex(p) for p in ps[:4]]}')

print()
print('=== 3. CABRIOLET 闄勮繎涓婁笅鏂?===')
i = d.find(b'CABRIOLET')
if i >= 0:
    seg = d[max(0, i - 96):i + 128]
    for k in range(0, len(seg), 16):
        s = seg[k:k + 16]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in s)
        print(f'    0x{i-96+k:06X}  {s.hex(" ")}  |{asc}|')

print()
print('=== 4. 澶撮儴鍖哄煙(0x00-0x60)瀛楁瑙ｈ ===')
hdr = d[:0x60]
print(f'  鍘熷: {hdr.hex(" ")}')
print(f'  SOF 鏍囪鍚?0x13)璧?')
p = 0x13
print(f'    +0x{p:02X}: {d[p:p+16].hex(" ")}')

print()
print('=== 5. 鏁版嵁鍖虹粨鏋?鐔靛垎甯?+ 闆跺尯 + 0xFF 鍖?===')
W = 4096
prev = None
for off in range(0, n, W):
    seg = d[off:off + W]
    z = seg.count(0)
    ff = seg.count(0xFF)
    c = Counter(seg)
    e = -sum((v / len(seg)) * (v and 1) * __import__('math').log2(v / len(seg)) for v in c.values())
    kind = '鍏ㄩ浂' if z == len(seg) else ('鍏‵F' if ff == len(seg) else ('浣庣喌' if e < 6.5 else '鏁版嵁'))
    if kind != prev:
        print(f'    @0x{off:06X}  {kind}  (鐔?{e:.2f} 闆?{z} FF={ff})')
        prev = kind

print()
print('=== 6. 鏄惁鍚彲鎵ц浠ｇ爜鐗瑰緛(MCU 鎸囦护璺宠浆琛?===')
# 澶ч噺 0xFF 閫氬父鏄湭鐢?flash;鏁版嵁鍖哄彲鑳芥槸 MCU 浠ｇ爜
# 妫€鏌?0x79700 闄勮繎(CABRIOLET 涔嬪悗鐨?琛?)
for base in (0x79736,):
    for k in range(0, 128, 16):
        s = d[base + k:base + k + 16]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in s)
        print(f'    0x{base+k:06X}  {s.hex(" ")}  |{asc}|')
