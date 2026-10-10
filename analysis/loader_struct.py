import os
import struct
import math
import re
from collections import Counter

FW = r'firmware'
BASE = 0x200
STEP = 0x5C


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def parts_of(fn):
    p = os.path.join(FW, fn)
    d = open(p, 'rb').read()
    n = len(d)
    out = {}
    for i in range(200):
        o = 0x2DC + i * STEP
        if o + STEP > n:
            break
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
            break
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        if flg not in (2, 3):
            break
        out[nm] = dict(real=BASE + off, size=sz)
    return d, out


d, pm = parts_of('S1H__V28.bin')
l2 = d[pm['loader2']['real']:pm['loader2']['real'] + pm['loader2']['size']]
# loader2 鍓╀綑鍖?鐩綍鍚?
rest = l2[0x3F8:]
print(f'=== loader2 鍓╀綑鍖?({len(rest):,} B) 缁撴瀯鍒嗘瀽 ===')
print(f'  鐔?{ent(rest):.4f}')
c = Counter(rest)
print(f'  瀛楄妭绉嶇被={len(c)}/256')
print(f'  鏈€澶? {[(hex(k), v) for k, v in c.most_common(8)]}')
print(f'  鏈€灏? {[(hex(k), v) for k, v in c.most_common()[-4:]]}')
# 鍧囧寑鎬?瀹岀編闅忔満鏃舵瘡绉嶇害 len/256
exp = len(rest) / 256
chi = sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))
print(f'  鍗℃柟={chi:.1f} (闅忔満鈮?55; 鍋忕瓒婂ぇ瓒婁笉鍧囧寑)')

# 闆跺瓧鑺傛瘮渚?缁撴瀯鍖栨暟鎹父鏈夊ぇ閲忛浂)
zeros = rest.count(0)
print(f'  闆跺瓧鑺?{zeros} ({zeros/len(rest):.4%})')

# 4 瀛楄妭瀵归綈:鏄惁鏈夊ぇ閲忛浂鐨?u32?
u32 = [struct.unpack_from('<I', rest, i)[0] for i in range(0, len(rest) - 4, 4)]
zero_u32 = sum(1 for v in u32 if v == 0)
print(f'  4瀛楄妭瀵归綈: 闆?u32 = {zero_u32}/{len(u32)} ({zero_u32/len(u32):.2%})')

# ASCII 瀛楃涓?strs = [m.group().decode('ascii', 'replace') for m in re.finditer(rb'[\x20-\x7e]{5,60}', rest)]
uniq = list(dict.fromkeys(strs))
print(f'  ASCII 瀛楃涓? {len(strs)} 涓? 鍞竴 {len(uniq)}')
for s in uniq[:30]:
    print(f'    {s}')

# 楂?6浣?浣?6浣嶅垎甯?鍒ゆ柇鏄?6浣嶆暟鎹?)
hi = Counter((v >> 8) & 0xFF for v in [struct.unpack_from('<H', rest, i)[0] for i in range(0, len(rest) - 2, 2)])
print(f'  16浣嶅榻? 楂樺瓧鑺傜绫?{len(hi)}')

# 鏄惁鏄?浣嶆墦鍖?(濡傛瘡涓瓧鑺傚彧鏈変綆浣嶆湁淇℃伅)
low_nibble = Counter(x & 0xF for x in rest)
high_nibble = Counter(x >> 4 for x in rest)
print(f'  浣?浣嶅垎甯冪绫?{len(low_nibble)}  楂?浣嶅垎甯冪绫?{len(high_nibble)}')
print(f'  浣?浣嶆渶澶у亸宸? {max(low_nibble.values())/ (len(rest)/16):.2f}x')

# 鐩搁偦瀛楄妭鐩稿叧鎬?same_adj = sum(1 for i in range(len(rest) - 1) if rest[i] == rest[i + 1])
print(f'  鐩搁偦瀛楄妭鐩稿悓: {same_adj}/{len(rest)-1} ({same_adj/(len(rest)-1):.4%}, 闅忔満鈮?.39%)')

print()
print('=== 瀵规瘮:鍒嗗尯鏁版嵁(鍔犲瘑)鐨勫悓绫绘寚鏍?===')
enc = d[pm['program']['real']:pm['program']['real'] + 65536]
ce = Counter(enc)
print(f'  program 鐔?{ent(enc):.4f} 鍗℃柟={sum((ce.get(i,0)-256)**2/256 for i in range(256)):.1f} 闆?{enc.count(0)}')
print(f'  鐩搁偦鐩稿悓={sum(1 for i in range(len(enc)-1) if enc[i]==enc[i+1])}/{len(enc)-1}')
