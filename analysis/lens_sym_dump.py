import os
import re

FW = r'firmware'
OUT = r'.\analysis\lens_symbols_all.txt'

PLFS = ['4001V020.plf', '4002V020.plf', '4006V020.plf', '4003V020.plf',
        '400CV020.plf', '400EV020.plf']
MODEL = {'4001': 'S-R24105', '4002': 'S-R70200', '4003': 'S-X50',
         '4006': 'S-E2470', '400C': 'S-S85', '400E': 'S-S50'}

datas = {}
for f in PLFS:
    p = os.path.join(FW, f)
    if os.path.exists(p):
        datas[f] = open(p, 'rb').read()

sets = {}
lines = []
for f, d in sorted(datas.items()):
    code = f[:4]
    mn = MODEL.get(code.upper(), '?')
    sy = {}
    for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{4,40}', d):
        s = m.group().decode()
        if re.search(r'[A-Z]', s) and re.search(r'[a-z]', s) and len(s) >= 6:
            sy.setdefault(s, m.start())
    sets[f] = set(sy.keys())
    lines.append(f'# {f}  ({mn})  绗﹀彿 {len(sy)} 涓?)
    for s, o in sorted(sy.items(), key=lambda x: x[1]):
        lines.append(f'  0x{o:06X}  {s}')
    lines.append('')

# 鍙樼劍闀滃ご鍏变韩
zoom = [f for f in datas if f[:4].upper() in ('4001', '4002', '4006')]
if len(zoom) >= 2:
    common = set.intersection(*[sets[f] for f in zoom])
    lines.append(f'# 鍙樼劍闀滃ご(4001/4002/4006)鍏辨湁绗﹀彿 {len(common)} 涓?')
    for s in sorted(common):
        lines.append(f'  {s}')

with open(OUT, 'w', encoding='utf-8', newline='\n') as fp:
    fp.write('\n'.join(lines))

print(f'宸插啓 {OUT}')
print(f'  鎬昏鏁? {len(lines)}')
for f in sorted(datas):
    print(f'  {f} ({MODEL.get(f[:4].upper(),"?")}): {len(sets[f])} 绗﹀彿')
if zoom:
    print(f'  鍙樼劍鍏变韩: {len(set.intersection(*[sets[f] for f in zoom]))}')
