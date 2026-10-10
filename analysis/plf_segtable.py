import os
import struct

FW = r'firmware'
NAMES = ['4001V020.plf', '4002V020.plf', '4006V020.plf']
S = {}
for f in NAMES:
    p = os.path.join(FW, f)
    if os.path.exists(p):
        S[f] = open(p, 'rb').read()
print('=== 鏍锋湰 ===')
for f, d in S.items():
    print(f'  {f}: {len(d):,} B  (0x{len(d):X})')

lens = {f: len(d) for f, d in S.items()}

print()
print('=== 1) 澶撮儴閫?4 瀛楄妭璺ㄦ牱鏈姣?鍙垪"涓嶅悓"鐨勫亸绉?===')
print(f'  {"off":>6}  ' + '  '.join(f'{f[:8]:>12}' for f in S) + '   ')
diff_slots = []
for k in range(0, 0x200, 4):
    vals = []
    for f, d in S.items():
        vals.append(struct.unpack_from('<I', d, k)[0] if k + 4 <= len(d) else None)
    if len(set(vals)) > 1:
        diff_slots.append(k)
        print(f'  {k:04X}   ' + '  '.join(f'{v:12d}' for v in vals))
print(f'  鈫?澶撮儴 0..0x200 涓彲鍙樻Ы浣? {len(diff_slots)} 涓?(鎬?{0x200//4})')

print()
print('=== 2) 鍙彉妲戒綅鏄惁绛変簬鍚勬牱鏈殑鏂囦欢澶у皬? ===')
for k in diff_slots:
    vals = [struct.unpack_from('<I', d, k)[0] for d in S.values()]
    sizes = [lens[f] for f in S]
    if vals == sizes:
        print(f'  鈽?0x{k:04X} 绮剧‘绛変簬鏂囦欢澶у皬!')
    # 涔熸鏌ュ父瑙佹崲绠?    for label, fn in (('file_size', lambda s: s), ('file_size/512', lambda s: s // 512),
                      ('file_size/0x200', lambda s: s // 0x200), ('file_size*2', lambda s: s * 2)):
        exp = [fn(s) for s in sizes]
        if vals == exp:
            print(f'  鈽?0x{k:04X} == {label}(file_size)')

print()
print('=== 3) 鍦ㄦ暣涓ご閮?0..0x400)鎵?绛変簬鏂囦欢澶у皬"鎴?绛変簬鏌愬浐瀹氭瘮渚?鐨勫瓧娈?===')
for k in range(0, 0x400, 2):
    try:
        vals = [struct.unpack_from('<I', d, k)[0] for d in S.values()]
    except Exception:
        continue
    sizes = [lens[f] for f in S]
    if vals == sizes:
        print(f'  鈽?u32 @0x{k:04X} == file_size  {vals}')
    for div in (0x200, 0x1000, 0x10000):
        if vals == [s // div for s in sizes] and vals[0] > 0:
            print(f'  鈽?u32 @0x{k:04X} == file_size/{div}  {vals}')

print()
print('=== 4) 鍏抽敭:琛ㄩ」鍦板潃搴忓垪鏄惁"瑕嗙洊 [0xB0, EOF)"涓旈殢鏂囦欢澧為暱 ===')
BASE = 0x100
for f, d in S.items():
    n = len(d)
    print(f'--- {f} (size=0x{n:X}) ---')
    seq = []
    for k in range(BASE, 0x400, 2):
        v = struct.unpack_from('<H', d, k)[0]
        if 0x1000 <= v < n:
            seq.append((k, v))
    print(f'    鍊欓€夊湴鍧€(u16 鈭?[0x1000, size)): {len(seq)} 涓?)
    for k, v in seq[:14]:
        print(f'      0x{k:04X} -> 0x{v:06X} ({v})')
    # 妫€鏌ユ槸鍚﹂€掑
    vs = [v for _, v in seq]
    inc = sum(1 for i in range(len(vs) - 1) if vs[i + 1] > vs[i])
    print(f'    閫掑瀵? {inc}/{max(len(vs)-1,1)}')

print()
print('=== 5) 鐢?32 浣嶈娉曞啀璇?4 瀛楄妭瀵归綈)===')
for f, d in S.items():
    n = len(d)
    print(f'--- {f} ---')
    seq = []
    for k in range(BASE, 0x300, 4):
        v = struct.unpack_from('<I', d, k)[0]
        if 0x1000 <= v < n:
            seq.append((k, v))
    for k, v in seq[:12]:
        print(f'      0x{k:04X} -> 0x{v:06X} ({v})')
    vs = [v for _, v in seq]
    if len(vs) > 1:
        inc = sum(1 for i in range(len(vs) - 1) if vs[i + 1] > vs[i])
        print(f'    閫掑瀵? {inc}/{len(vs)-1}')
