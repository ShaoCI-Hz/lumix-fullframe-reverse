import os
import struct
import hashlib

FW = r'firmware'
BASE = 0x200


def parts_of(path):
    d = open(path, 'rb').read()
    n = len(d)
    out = {}
    for i in range(200):
        o = 0x2DC + i * 0x5C
        if o + 0x5C > n:
            break
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
            break
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        if flg not in (2, 3):
            break
        out[nm] = dict(real=BASE + off, size=sz, flg=flg,
                       sha=d[o + 0x2C:o + 0x2C + 32])
    return d, out


def parse_dir(blob, step=0x60, name_off=0x04, name_len=12):
    """解析明文目录表"""
    items = []
    off = 0
    while off + step <= len(blob):
        raw = blob[off:off + step]
        name = raw[name_off:name_off + name_len].split(b'\x00')[0].decode('ascii', 'replace')
        if not name or not all(32 <= c < 127 for c in name.encode('ascii', 'replace')):
            break
        f10 = struct.unpack_from('<I', raw, 0x10)[0]
        f14 = struct.unpack_from('<I', raw, 0x14)[0]
        f18 = struct.unpack_from('<I', raw, 0x18)[0]
        f1c = struct.unpack_from('<I', raw, 0x1C)[0]
        h20 = raw[0x20:0x40]
        h40 = raw[0x40:0x60]
        items.append(dict(off=off, name=name, f10=f10, f14=f14, f18=f18, f1c=f1c,
                          h20=h20, h40=h40))
        off += step
    return items


for fn in ('S1H__V28.bin', 'S5___V29.bin', 'S1___V24.bin'):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        continue
    d, pm = parts_of(p)
    print(f'===== {fn} =====')
    for lname in ('loader2', 'loader3'):
        if lname not in pm:
            continue
        real, sz = pm[lname]['real'], pm[lname]['size']
        blob = d[real:real + sz]
        items = parse_dir(blob)
        print(f'--- {lname} (size={sz:,}) : {len(items)} 个目录项 ---')
        if not items:
            continue
        print('  #  name            f10          f14(size)        f18   f1c  h20[:8]')
        for i, it in enumerate(items[:30]):
            h40zero = 'zero' if it['h40'] == bytes(32) else 'nonzero'
            print(f'{i:>3} {it["name"]:12} 0x{it["f10"]:08X} {it["f14"]:>11,} 0x{it["f18"]:08X} {it["f1c"]:>4}  {it["h20"][:8].hex()}  {h40zero}')
        if len(items) > 30:
            print(f'    ... 还有 {len(items)-30} 项')

        # 关键验证:f14 == 分区表中该分区的 size?
        print(f'  === 与分区表 size 交叉验证 ===')
        ok = 0
        for it in items:
            if it['name'] in pm:
                if pm[it['name']]['size'] == it['f14']:
                    ok += 1
                else:
                    print(f'    {it["name"]}: 目录={it["f14"]:,} 分区表={pm[it["name"]]["size"]:,}')
        print(f'    size 一致: {ok}/{len([x for x in items if x["name"] in pm])}')

        # 关键:h20 是否 = 分区表的 SHA-256?
        print(f'  === h20 与分区表 SHA-256 对比 ===')
        same = 0
        diff = []
        for it in items:
            if it['name'] in pm:
                if it['h20'] == pm[it['name']]['sha']:
                    same += 1
                else:
                    diff.append(it['name'])
        print(f'    相同: {same}, 不同: {len(diff)}  {diff[:8]}')
        # h20 是否 = SHA-256(全零 size)?
        print(f'  === h20 是否 = SHA-256(全零 f14 字节)? ===')
        zo = []
        for it in items:
            if it['f14'] and hashlib.sha256(bytes(it['f14'])).digest() == it['h20']:
                zo.append(it['name'])
        print(f'    命中: {len(zo)}  {zo[:10]}')
        # h20 是否 = SHA-256(镜像中该分区数据)?
        im = []
        for it in items:
            if it['name'] in pm:
                a = pm[it['name']]
                b = d[a['real']:a['real'] + a['size']]
                if hashlib.sha256(b).digest() == it['h20']:
                    im.append(it['name'])
        print(f'    = SHA256(镜像数据): {len(im)}  {im[:10]}')
        # h40 是否也是哈希?
        print()
    print()
