import os
import math
from collections import Counter

FW = r'firmware'
NAMES = ['4001V020.plf', '4002V020.plf', '4006V020.plf']


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


print('=== 1) 閫?4KB 鍧楃殑鐔?鍓?0x20000,鎵炬暟鎹捣濮?===')
for f in NAMES:
    p = os.path.join(FW, f)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    print(f'--- {f}  (size=0x{len(d):X}) ---')
    prev = None
    for off in range(0, 0x20000, 0x1000):
        e = ent(d[off:off + 0x1000])
        tag = ''
        if e > 7.5:
            tag = 'HIGH'
        elif e < 2:
            tag = 'low'
        if prev is not None and abs(e - prev) > 3:
            tag += '  <<< 绐佸彉'
        print(f'  0x{off:06X}  H={e:5.2f}  {tag}')
        prev = e
    print()

print()
print('=== 2) 鎵?鏈€鍚庝竴娈典綆鐔靛尯"鐨勭粨鏉熶綅缃?= 鏁版嵁璧峰鍊欓€?===')
for f in NAMES:
    p = os.path.join(FW, f)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    n = len(d)
    # 浠庡ご寮€濮?鎵剧涓€涓?楂樼喌鍧?(H>7.5)涓斿叾鍚庢寔缁珮鐔?    start = None
    for off in range(0, min(n - 0x4000, 0x80000), 0x1000):
        if ent(d[off:off + 0x1000]) > 7.5:
            # 纭鍚庣画 3 鍧椾篃楂樼喌
            if all(ent(d[off + i * 0x1000:off + (i + 1) * 0x1000]) > 7.0 for i in range(1, 4)):
                start = off
                break
    print(f'  {f}: size=0x{n:X}  棣栦釜鎸佺画楂樼喌鍧?@0x{start if start is not None else 0:X}')
    if start:
        print(f'         鏁版嵁鍖?鈮?[{start:,}, {n:,})  = {n - start:,} 瀛楄妭 = 0x{n - start:X}')
        # 涓庡ご閮ㄥ瓧娈靛姣?        for k in (0x18, 0x1C, 0x20, 0xB4, 0xB8):
            v = int.from_bytes(d[k:k + 4], 'little')
            mark = '  鈽呭尮閰嶆暟鎹ぇ灏? if v == n - start else ''
            mark2 = '  鈽呭尮閰嶈捣濮嬪亸绉? if v == start else ''
            print(f'         0x{k:02X} = {v:>12,}{mark}{mark2}')

print()
print('=== 3) 澶撮儴 0x18 瀛楁鐨勪笁涓€兼槸鍚︿笌浠讳綍"鏂囦欢澶у皬鎹㈢畻"鍚诲悎 ===')
sizes = {}
for f in NAMES:
    p = os.path.join(FW, f)
    if os.path.exists(p):
        dd = open(p, 'rb').read()
        sizes[f] = len(dd)
        v18 = int.from_bytes(dd[0x18:0x1C], 'little')
        print(f'  {f}: size={len(dd):>10,}  0x18={v18:>10,}  diff={len(dd)-v18:>10,}  ratio={v18/len(dd):.4f}')

print()
print('=== 4) 鍏ㄦ枃浠?4KB 鐔垫洸绾?姣?64KB 閲囨牱,鐪嬫暣浣撶粨鏋?===')
for f in NAMES[:1]:
    d = open(os.path.join(FW, f), 'rb').read()
    n = len(d)
    print(f'--- {f} ---')
    for off in range(0, n - 0x4000, 0x10000):
        print(f'  0x{off:06X}  H={ent(d[off:off + 0x4000]):5.2f}')
