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

print('=== 头部字段对齐(6 个镜头)===') 
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
print('=== 4001V020 头部 0x13..0x60 逐字段 ===')
d = datas.get('4001V020.plf')
if d:
    for k in range(0x13, 0x60, 4):
        v32 = struct.unpack_from('<I', d + bytes(4), k)[0]
        seg = d[k:k + 4]
        print(f'  +0x{k:02X}: {seg.hex(" ")}  LE32=0x{v32:08X} ({v32:,})')

print()
print('=== 变焦镜头共享符号(340+)按功能分类抽样 ===')
sets = {}
for f, d in datas.items():
    sy = set()
    for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{4,40}', d):
        s = m.group().decode()
        if re.search(r'[A-Z]', s) and re.search(r'[a-z]', s) and len(s) >= 6:
            sy.add(s)
    sets[f] = sy
common = set.intersection(*sets.values())
print(f'  三款变焦镜头共有符号 {len(common)} 个')

# 按关键词分类
groups = {
    '通信/卡口': r'Com|Uart|Serial|Spi|I2c|Bus|Msg|Cmd|Rx|Tx|Frame|Packet|Lens|Mount|Comm',
    'OIS/防抖': r'Ois|Wob|Gyro|Stab|Blur|Shake',
    '对焦': r'Foc|Af|Dist|Lens|Drive|Mtr',
    '光圈': r'Irs|Apert|Iris|Ape',
    '变焦': r'Zm|Zoom',
    '电机/驱动': r'Mtr|Motor|Drv|Pwm|Coil|Cur|Hall',
    '编码器/位置': r'Pos|Enc|Ad|Cnt|Cntr|Pls',
    '控制/模式': r'Mode|Set|Ctrl|Ctl|Cmd|Seq|State|Init',
    '调试': r'Dbg|Dbug|Test|Err|Log',
}
for g, pat in groups.items():
    hits = sorted(s for s in common if re.search(pat, s, re.I))
    if hits:
        print(f'  [{g}] {len(hits)} 个:')
        print(f'      {", ".join(hits[:18])}')
