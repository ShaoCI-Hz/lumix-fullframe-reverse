import os
import re
import struct

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

print('=== 1) 绗﹀彿闆嗕腑鍖?0x5400..0x5480 鍘熷瀛楄妭(鐪嬪悕瀛椾箣闂存湁浠€涔?===')
for k in range(0x5400, 0x5480, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:06X}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 2) 閫愪釜绗﹀彿:鍚嶅瓧 + 鍓嶅悗鍚?8 瀛楄妭(鎵惧湴鍧€瀛楁)===')
# 鏀堕泦鎵€鏈?鍍忕鍙峰悕"鐨勫瓧绗︿覆鍙婂叾浣嶇疆
syms = []
for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{5,40}', d):
    s = m.group().decode()
    if re.search(r'[A-Z]', s) and re.search(r'[a-z]', s):
        syms.append((m.start(), m.end(), s))
print(f'  鍊欓€夌鍙?{len(syms)} 涓?)

# 鍙湅鍚嶅瓧瀵嗛泦鍖?姣?256 瀛楄妭鍐呮湁 >=2 涓悕瀛楃殑鍖哄煙)
def dense(off):
    cnt = 0
    for s, e, _ in syms:
        if off <= s < off + 256:
            cnt += 1
    return cnt

regions = []
cur = None
for s, e, name in syms:
    if dense(s) >= 2:
        regions.append((s, e, name))
print(f'  瀵嗛泦鍖虹鍙?{len(regions)} 涓?)

print()
print('  鍓?25 涓?甯﹀墠鍚庡瓧鑺?:')
for s, e, name in regions[:25]:
    pre = d[max(0, s - 8):s]
    post = d[e:e + 8]
    print(f'    0x{s:06X}  {name:28}  pre={pre.hex(" ")}  post={post.hex(" ")}')

print()
print('=== 3) 鍋囪:鍚嶅瓧鍚庣殑 4 瀛楄妭鏄湴鍧€?妫€鏌ユ槸鍚﹁惤鍦ㄤ唬鐮佸尯 ===')
hits = 0
samples = []
for s, e, name in regions:
    for off in (e, e + 1, e + 2):        # 灏濊瘯鍑犵瀵归綈
        if off + 4 > n:
            continue
        v = struct.unpack_from('<I', d, off)[0]
        if 0x1000 <= (v & ~1) < n and (v & 1):
            hits += 1
            if len(samples) < 12:
                samples.append((name, off - e, v))
            break
print(f'  鍚嶅瓧鍚?4 瀛楄妭鍍?Thumb 鍦板潃鐨? {hits}/{len(regions)}')
for name, extra, v in samples:
    print(f'    {name:28} +{extra} -> 0x{v:08X}')

print()
print('=== 4) 鍋囪:鍚嶅瓧鍓嶇殑 4 瀛楄妭鏄湴鍧€? ===')
hits2 = 0
samples2 = []
for s, e, name in regions:
    for off in (s - 4, s - 5):
        if off < 0 or off + 4 > n:
            continue
        v = struct.unpack_from('<I', d, off)[0]
        if 0x1000 <= (v & ~1) < n and (v & 1):
            hits2 += 1
            if len(samples2) < 12:
                samples2.append((name, s - off, v))
            break
print(f'  鍚嶅瓧鍓?4 瀛楄妭鍍?Thumb 鍦板潃鐨? {hits2}/{len(regions)}')
for name, extra, v in samples2:
    print(f'    {name:28} -{extra} -> 0x{v:08X}')
