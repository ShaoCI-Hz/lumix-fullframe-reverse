import os
import re
import struct

FW = r'firmware'

PLF = ['4001V020.plf', '4002V020.plf', '4006V020.plf']
datas = {}
for f in PLF:
    p = os.path.join(FW, f)
    if os.path.exists(p):
        datas[f] = open(p, 'rb').read()

print('=== 澶撮儴瀛楁瀵归綈(6 涓暅澶?===') 
allp = [f for f in os.listdir(FW) if f.lower().endswith('.plf')]
print(f'{"file":16} {"+0x13":>10} {"+0x16":>10} {"+0x1C":>10} {"+0x20(code)":>12} {"+0x24":>12} {"+0x2C":>12}')
for f in sorted(allp):
    d = open(os.path.join(FW, f), 'rb').read()
    a = d[0x13:0x17].hex()
    b = d[0x17:0x1B].hex()
    c = d[0x1C:0x20].hex()
    code = d[0x22:0x24].hex()
    e = d[0x24:0x28].hex()
    g = d[0x2C:0x30].hex()
    print(f'{f:16} {a:>10} {b:>10} {c:>10} {code:>12} {e:>12} {g:>12}')

print()
print('=== 4001V020 澶撮儴 0x13..0x60 閫愬瓧娈?===')
d = datas.get('4001V020.plf')
if d:
    for k in range(0x13, 0x60, 4):
        v32 = struct.unpack_from('<I', d + bytes(4), k)[0]
        seg = d[k:k + 4]
        print(f'  +0x{k:02X}: {seg.hex(" ")}  LE32=0x{v32:08X} ({v32:,})')

print()
print('=== 鍙樼劍闀滃ご鍏变韩绗﹀彿(340+)鎸夊姛鑳藉垎绫绘娊鏍?===')
sets = {}
for f, d in datas.items():
    sy = set()
    for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{4,40}', d):
        s = m.group().decode()
        if re.search(r'[A-Z]', s) and re.search(r'[a-z]', s) and len(s) >= 6:
            sy.add(s)
    sets[f] = sy
common = set.intersection(*sets.values())
print(f'  涓夋鍙樼劍闀滃ご鍏辨湁绗﹀彿 {len(common)} 涓?)

# 鎸夊叧閿瘝鍒嗙被
groups = {
    '閫氫俊/鍗″彛': r'Com|Uart|Serial|Spi|I2c|Bus|Msg|Cmd|Rx|Tx|Frame|Packet|Lens|Mount|Comm',
    'OIS/闃叉姈': r'Ois|Wob|Gyro|Stab|Blur|Shake',
    '瀵圭劍': r'Foc|Af|Dist|Lens|Drive|Mtr',
    '鍏夊湀': r'Irs|Apert|Iris|Ape',
    '鍙樼劍': r'Zm|Zoom',
    '鐢垫満/椹卞姩': r'Mtr|Motor|Drv|Pwm|Coil|Cur|Hall',
    '缂栫爜鍣?浣嶇疆': r'Pos|Enc|Ad|Cnt|Cntr|Pls',
    '鎺у埗/妯″紡': r'Mode|Set|Ctrl|Ctl|Cmd|Seq|State|Init',
    '璋冭瘯': r'Dbg|Dbug|Test|Err|Log',
}
for g, pat in groups.items():
    hits = sorted(s for s in common if re.search(pat, s, re.I))
    if hits:
        print(f'  [{g}] {len(hits)} 涓?')
        print(f'      {", ".join(hits[:18])}')
