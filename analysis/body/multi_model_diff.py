import os
import struct
import sys

FW = r'firmware'

MODELS = [
    ('S1___V24.bin', 'DC-S1'),
    ('S1H__V28.bin', 'DC-S1H'),
    ('S5___V29.bin', 'DC-S5'),
    ('S5m2_V37.bin', 'DC-S5M2'),
    ('S5m2XV27.bin', 'DC-S5M2X'),
    ('S9___V20.bin', 'DC-S9'),
]


def parse(path):
    d = open(path, 'rb').read()
    n = len(d)
    if d[:4] != b'UPD\x00':
        return None
    model = d[0x0C:0x1C].split(b'\x00')[0].decode('ascii', 'replace')
    verf = struct.unpack_from('<I', d, 0x24)[0]
    parts = []
    for i in range(200):
        o = 0x2DC + i * 0x5C
        if o + 0x5C > n:
            break
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
            break
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        flg_f = flg
        if flg_f not in (2, 3):
            break
        sha = d[o + 0x2C:o + 0x2C + 32]
        parts.append(dict(idx=i, name=nm, size=sz, off=off, flg=flg_f, sha=sha))
    return dict(model=model, verf=verf, size=n, parts=parts)


def ts(v):
    """把 +0x24 字段按 BCD 尝试解码为日期/时间"""
    s = f'{v:08X}'
    try:
        b = bytes.fromhex(s)
        pairs = [f'{b[i]:02X}' for i in range(4)]
        return f'{pairs[0]}/{pairs[1]} {pairs[2]}:{pairs[3]}'
    except Exception:
        return '?'


try:
    data = {}
    for fn, label in MODELS:
        p = os.path.join(FW, fn)
        if not os.path.exists(p):
            continue
        r = parse(p)
        if r:
            data[label] = r

    print('=== 机型概览 ===')
    print(f'{"机型":10} {"平台代号":10} {"镜像大小":>14} {"分区数":>6} {"+0x24 字段":>12}  BCD?')
    for label, r in data.items():
        print(f'{label:10} {r["model"]:10} {r["size"]:>14,} {len(r["parts"]):>6} 0x{r["verf"]:08X}  {ts(r["verf"])}')

    print()
    print('=== 分区名 × 机型 矩阵(X=存在,尺寸KB)===')
    allnames = []
    for label, r in data.items():
        for p in r['parts']:
            if p['name'] not in allnames:
                allnames.append(p['name'])
    labels = list(data.keys())
    # 表头
    hdr = f'{"分区名":16}'
    for lb in labels:
        hdr += f'{lb.replace("DC-", ""):>10}'
    print(hdr)
    for nm in allnames:
        row = f'{nm:16}'
        cnt = 0
        for lb in labels:
            hit = next((p for p in data[lb]['parts'] if p['name'] == nm), None)
            if hit:
                row += f'{hit["size"]//1024:>10}'
                cnt += 1
            else:
                row += f'{"-":>10}'
        mark = '  ← 特有' if cnt == 1 else ('  ← 共有' if cnt == len(labels) else '')
        print(row + mark)

    print()
    print('=== 机型特有分区(可能对应功能差异)===')
    for nm in allnames:
        present = [lb for lb in labels if any(p['name'] == nm for p in data[lb]['parts'])]
        if len(present) < len(labels):
            missing = [lb for lb in labels if lb not in present]
            print(f'  {nm:16} 有={present}  缺={missing}')

    print()
    print('=== 共有分区中"大小不同"的(格式/内容演进)===')
    for nm in allnames:
        sizes = {}
        for lb in labels:
            hit = next((p for p in data[lb]['parts'] if p['name'] == nm), None)
            if hit:
                sizes[lb] = hit['size']
        if len(set(sizes.values())) > 1 and len(sizes) == len(labels):
            print(f'  {nm:16} ' + '  '.join(f'{k.replace("DC-","")}={v//1024}K' for k, v in sizes.items()))

except Exception:
    import traceback
    traceback.print_exc()
    sys.exit(1)
