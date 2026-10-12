import os
import struct

FW = r'firmware'
BASE = 0x200
STEP = 0x5C


def parts_of(path):
    d = open(path, 'rb').read()
    n = len(d)
    out = {}
    order = []
    for i in range(200):
        o = 0x2DC + i * STEP
        if o + STEP > n:
            break
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
            break
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        if flg not in (2, 3):
            break
        out[nm] = dict(real=BASE + off, size=sz, off=off)
        order.append(nm)
    return d, out, order


def l2_table(d, real, sz):
    blob = d[real:real + sz]
    items = {}
    off = 0x04
    while off + STEP <= sz:
        raw = blob[off:off + STEP]
        nm = raw[0:12].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
            break
        A = struct.unpack_from('<I', raw, 0x0C)[0]
        size = struct.unpack_from('<I', raw, 0x10)[0]
        B = struct.unpack_from('<I', raw, 0x14)[0]
        items[nm] = dict(A=A, B=B, size=size)
        off += STEP
    return items


for fn in ('S1H__V28.bin', 'S5___V29.bin'):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        continue
    d, pm, order = parts_of(p)
    l2 = l2_table(d, pm['loader2']['real'], pm['loader2']['size'])
    print(f'===== {fn} =====')
    print('  partition      off(闀滃儚)      A(loader2琛?   real-A         size')
    diffs = []
    for nm, it in l2.items():
        if nm not in pm:
            continue
        real = pm[nm]['real']
        diff = real - it['A']
        diffs.append(diff)
        print(f'  {nm:<13} 0x{pm[nm]["off"]:08X}  0x{it["A"]:08X}  0x{diff:08X} ({diff:>10,})  {it["size"]:>10,}')
    print(f'  real-A 鏄惁鎭掑畾: {len(set(diffs))==1}  (鍊?{sorted(set(diffs))})')
    print()

    # 鍏抽敭:妫€鏌ラ暅鍍忎腑鍒嗗尯鐨?鐗╃悊椤哄簭" vs "loader2 琛ㄩ『搴?
    print('  === 闀滃儚涓垎鍖洪『搴?鎸?real 鎺掑簭)===')
    seq = sorted([(pm[n]['real'], n, pm[n]['off']) for n in order if pm[n]['size']])
    for real, n, off in seq[:20]:
        print(f'    real=0x{real:08X} off=0x{off:08X}  {n}')

    # 妫€鏌?off 鏄惁涓ユ牸閫掑(闀滃儚鏄惁杩炵画鎺掑垪)
    offs = [o for _, _, o in seq]
    print(f'  off 涓ユ牸閫掑(闀滃儚鎸夊垎鍖鸿〃椤哄簭杩炵画): {offs == sorted(offs)}')

    # flash 鍦板潃 A 椤哄簭
    print()
    print('  === loader2 琛ㄨ鐩栫殑鍒嗗尯鍦ㄩ暅鍍忎腑鐨?off ===')
    for nm, it in l2.items():
        if nm in pm:
            print(f'    {nm:<13} loader2_A=0x{it["A"]:08X}  闀滃儚off=0x{pm[nm]["off"]:08X}  宸?0x{pm[nm]["off"]-it["A"]:X}')
    print()
