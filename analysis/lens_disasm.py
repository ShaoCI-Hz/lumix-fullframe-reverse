import os
import re
from collections import Counter

FW = r'firmware'
p = os.path.join(FW, '4001V020.plf')
d = open(p, 'rb').read()
n = len(d)
print(f'=== 4001V020.plf  {n:,} B ===')

# 鐢?capstone 鎺㈡祴浠ｇ爜鍖?閫愮獥鍙ｅ皾璇?Thumb 鍙嶆眹缂?缁熻鏈夋晥鎸囦护姣斾緥
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = False


def thumb_score(chunk):
    """杩斿洖 (鏈夋晥鎸囦护姣斾緥, 鎸囦护鏁?"""
    ok = 0
    tot = 0
    for ins in md.disasm(chunk, 0):
        tot += 1
        ok += 1
        if tot >= 200:
            break
    return ok, tot


W = 0x800
print()
print('=== 浠ｇ爜鍖烘帰娴?Thumb 鎸囦护瀵嗗害)===')
regions = []
for off in range(0, n - W, W):
    seg = d[off:off + W]
    # 绠€鍗曞惎鍙?Thumb 甯歌 2 瀛楄妭鎸囦护,妫€鏌?push/pop/bl 妯″紡
    push = len(re.findall(rb'[\x00-\xff][\xb4\xb5]', seg))          # PUSH {..}
    bl = len(re.findall(rb'[\xf0-\xf7][\xf8-\xff]', seg))           # BL
    bx = seg.count(b'\x70\x47')                                     # BX LR
    pop = len(re.findall(rb'[\x00-\xff][\xbd]', seg))               # POP {..,PC}
    sc = push * 3 + bl * 2 + bx * 5 + pop * 2
    regions.append((off, sc, push, bl, bx, pop))

regions.sort(key=lambda x: -x[1])
print('  浠ｇ爜瀵嗗害鏈€楂樼殑 15 涓獥鍙?')
print(f'    {"off":>10} {"score":>7} {"push":>6} {"bl":>6} {"bx":>5} {"pop":>6}')
for off, sc, pu, bl, bx, po in regions[:15]:
    print(f'    0x{off:06X} {sc:>7} {pu:>6} {bl:>6} {bx:>5} {po:>6}')

# 鎵撳嵃鏈€楂樺瘑搴﹀尯鐨勫弽姹囩紪
top = regions[0][0]
print()
print(f'=== 鏈€楂樺瘑搴﹀尯 0x{top:06X} 鍙嶆眹缂?鍓?60 鏉?===')
for i, ins in enumerate(md.disasm(d[top:top + 0x200], top)):
    if i >= 60:
        break
    print(f'  0x{ins.address:06X}  {ins.mnemonic:8} {ins.op_str}')

# 鍏ㄥ眬缁熻
print()
print('=== 鍏ㄥ眬 Thumb 鐗瑰緛缁熻 ===')
allpush = len(re.findall(rb'[\x00-\xff][\xb4\xb5]', d))
allbx = d.count(b'\x70\x47')
allbl = len(re.findall(rb'[\xf0-\xf7][\xf8-\xff]', d))
print(f'  PUSH 妯″紡: {allpush}')
print(f'  BX LR (0x4770): {allbx}')
print(f'  BL 妯″紡: {allbl}')
