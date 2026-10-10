import os

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

for f in ('4001V020.plf', '4006V020.plf'):
    p = os.path.join(FW, f)
    if not os.path.exists(p):
        continue
    d = open(p, 'rb').read()
    n = len(d)
    print(f'=== {f} (size=0x{n:X}) ===')
    print()
    print('  0x8000..0x8100 鍘熷瀛楄妭:')
    for k in range(0x8000, 0x8080, 16):
        seg = d[k:k + 16]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
        print(f'    {k:06X}  {seg.hex(" ")}  |{asc}|')
    print()
    print('  0x9000 璧风殑鍙嶆眹缂?璇曞榻?0x9000 / 0x9002):')
    for base in (0x9000, 0x9002):
        good = 0
        print(f'  --- base=0x{base:X} ---')
        for i, ins in enumerate(md.disasm(d[base:base + 0x40], base)):
            if i >= 8:
                break
            good += 1
            print(f'    0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:9} {ins.op_str}')
        print()
    # 鎵?0x9000 闄勮繎绗竴涓?鍚堟硶搴忚█"
    print('  0x8800..0x9200 鍐呭鎵惧嚱鏁板簭瑷€ (0xB5xx / e92d):')
    found = []
    for o in range(0x8800, 0x9200, 2):
        if d[o + 1] == 0xB5:
            found.append((o, 'PUSH{r0-r7,lr}'))
        elif d[o:o + 2] == b'\x2d\xe9':
            found.append((o, 'PUSH.W'))
    for o, k in found[:10]:
        print(f'    @0x{o:06X}  {k}')
    if not found:
        print('    (鏃?')
    print()
    print('  鈫?鏁版嵁鍖虹涓€涓簭瑷€涔嬪墠鐨勫ご閮ㄩ暱搴?')
    if found:
        print(f'    绗竴涓簭瑷€ @0x{found[0][0]:06X} ({found[0][0]:,})')
    print()
    print('=' * 60)
