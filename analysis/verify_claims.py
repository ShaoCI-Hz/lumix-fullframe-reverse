import os
import struct
import bisect

FW = r'firmware'
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)

# 澶嶇幇鎴戝湪 lens_base.py 閲岀殑"鍑芥暟鍖洪棿"鏋勯€?seeds = set()
for o in range(0, n - 2, 2):
    if d[o + 1] == 0xB5:
        seeds.add(o)
for o in range(0, n - 4, 2):
    if d[o:o + 2] == b'\x2d\xe9':
        m2 = struct.unpack_from('<H', d, o + 2)[0]
        if m2 & 0x4000:
            seeds.add(o)

entries = sorted(seeds)
print(f'=== 鎸囨帶 1:鍑芥暟鍖洪棿鐨勫苟闆嗚鐩栫巼 ===')
print(f'  鏂囦欢澶у皬: {n:,} 瀛楄妭')
print(f'  绉嶅瓙鏁? {len(entries)}')
ranges = []
for i, s in enumerate(entries):
    e = entries[i + 1] if i + 1 < len(entries) else n
    ranges.append((s, e))
total = sum(e - s for s, e in ranges)
print(f'  鍖洪棿骞堕泦鎬婚暱: {total:,} 瀛楄妭 = {total/n:.2%} 鐨勬枃浠?)
print(f'  鍖洪棿璧风偣鑼冨洿: 0x{entries[0]:06X} .. 0x{entries[-1]:06X}')
print(f'  鍖洪棿骞堕泦 = [0x{entries[0]:06X}, 0x{n:06X})  鈫?瑕嗙洊浠庣涓€涓瀛愬埌鏂囦欢鏈熬')
print()
print('  => 鍙 BL 鐩爣 > 0x%06X,灏?钀藉湪鍑芥暟鍖洪棿鍐?' % entries[0])
print(f'     ({entries[0]:,} / {n:,} = 鍓?{entries[0]/n:.1%} 鐨勬枃浠惰鎺掗櫎)')

# 鎸囨帶 2:BL 鐩爣鏀堕泦鍖呭惈浜嗘櫘閫?B 鍒嗘敮
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
print()
print('=== 鎸囨帶 2:"BL 鐩爣"瀹為檯娣峰叆浜嗘櫘閫?B 鍒嗘敮 ===')
bl_only = []
b_only = []
addr = 0
while addr < n - 4:
    got = False
    for ins in md.disasm(d[addr:addr + 4], addr):
        got = True
        if ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            try:
                bl_only.append(int(ins.op_str[1:], 16) & ~1)
            except Exception:
                pass
        elif ins.mnemonic == 'b' and ins.op_str.startswith('#'):
            try:
                b_only.append(int(ins.op_str[1:], 16) & ~1)
            except Exception:
                pass
        break
    addr += 2
print(f'  绾?BL/BLX 鐩爣: {len(bl_only):,}')
print(f'  鏅€?B  鐩爣: {len(b_only):,}')
print(f'  鎴戠殑浠ｇ爜鏀堕泦鐨?= BL + B = {len(bl_only) + len(b_only):,}')
print()

# 鍏抽敭:鏅€?B 鐩爣鏈夊灏戣惤鍦?鍚屼竴涓嚱鏁板尯闂?鍐?鍗宠繎璺濈璺宠浆)?
import bisect


def owner_range(a):
    i = bisect.bisect_right(entries, a) - 1
    if i < 0:
        return None
    s = entries[i]
    return (s, ranges[i][1])


near = 0
far = 0
for t in b_only[:5000]:
    r = owner_range(t)
    if r is None:
        continue
    # B 鐩爣涓庡畠鎵€灞炲尯闂磋捣鐐圭殑璺濈
    if t - r[0] < 0x400:
        near += 1
    else:
        far += 1
print(f'  B 鐩爣涓?璺濆叾鍖洪棿璧风偣 < 0x400 鐨勮繎璺宠浆: {near}/{near+far} ({near/max(near+far,1):.1%})')
print('  => 鏅€?B 澶氫负鍖洪棿鍐呰繎璺宠浆,璁″叆鍚庡繀鐒舵帹楂?钀藉湪鍖洪棿鍐?鐨勫懡涓巼')

# 鎸囨帶 3:鐢ㄤ弗鏍兼爣鍑?浠?BL,涓旇姹傝惤鍦?楂樺瘑搴︿唬鐮佸潡")閲嶆柊娴嬮噺
print()
print('=== 鎸囨帶 3:鐢ㄤ弗鏍兼爣鍑嗛噸鏂版祴閲?===')


def density(off, size=0x1000):
    cnt = 0
    for _ in md.disasm(d[off:off + size], off):
        cnt += 1
    return cnt / (size / 2)


code_blocks = set()
for blk in range(0, n // 0x1000):
    off = blk * 0x1000
    if density(off) > 0.5:
        code_blocks.add(blk)
print(f'  楂樺瘑搴︿唬鐮佸潡: {len(code_blocks)} 涓?)

for label, tg in (('浠?BL/BLX', bl_only), ('BL+B(鎴戝師鏉ョ殑)', bl_only + b_only)):
    in_code = sum(1 for t in tg if (t >> 12) in code_blocks)
    print(f'  {label:18} 钀藉湪楂樺瘑搴︿唬鐮佸潡: {in_code:>6}/{len(tg):>6} ({in_code/max(len(tg),1):.1%})')
