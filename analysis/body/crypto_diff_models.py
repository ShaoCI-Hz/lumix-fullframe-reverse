import struct, hashlib, sys, traceback
from collections import Counter

BASE = 0x200


def load(p):
    d = open(p, 'rb').read()
    parts = {}
    for i in range(58):
        o = 0x2DC + i * 0x5C
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm:
            continue
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        want = d[o + 0x2C:o + 0x2C + 32]
        nonce = d[o + 0x4C:o + 0x4C + 12]
        parts[nm] = dict(off=BASE + off, sz=sz, flg=flg, want=want, nonce=nonce)
    return d, parts


dx, px = load('firmware/S5m2XV27.bin')   # S5M2X
dm, pm = load('firmware/S5m2_V37.bin')   # S5M2 (姊妹)

try:
    print('=== 明文全零分区的 keystream(S5M2X vs S5M2)差分 ===')
    for nm in ['lens_hist', 'vkizu_data', 'lut2_data', 'grid_data']:
        if nm not in px or nm not in pm:
            continue
        a, b = px[nm], pm[nm]
        ksx = dx[a['off']:a['off'] + a['sz']]
        ksm = dm[b['off']:b['off'] + b['sz']]
        print(f'--- {nm} (size={a["sz"]:,}) ---')
        print(f'   X[:32]={ksx[:32].hex()}')
        print(f'   M[:32]={ksm[:32].hex()}')
        if a['nonce'] == b['nonce']:
            print(f'   nonce 相同 = {a["nonce"].hex()}')
        else:
            print(f'   nonce 不同: X={a["nonce"].hex()} M={b["nonce"].hex()}')
        # XOR 差分
        n = min(len(ksx), len(ksm))
        xor = bytes(x ^ y for x, y in zip(ksx[:n], ksm[:n]))
        c = Counter(xor)
        print(f'   XOR 差分: 不同字节值={len(c)}/256 (256=随机) 最常见={c.most_common(3)}')
        # 差分是否有零段(相同区域)
        # 找最长公共子串(采样)
        common = 0
        for k in range(0, n - 64, 0x1000):
            if ksx[k:k + 64] == ksm[k:k + 64]:
                common += 1
        print(f'   相同 64B 块(采样)={common}')

    print()
    print('=== S5M2X 内部:各分区 keystream 两两 XOR(找 key 复用线索)===')
    znames = [nm for nm in ['lens_hist', 'vkizu_data', 'lut2_data', 'grid_data']
              if hashlib.sha256(bytes(px[nm]['sz'])).digest() == px[nm]['want']]
    print(f'   参与分区: {znames}')
    for i in range(len(znames)):
        for j in range(i + 1, len(znames)):
            na, nb = znames[i], znames[j]
            a, b = px[na], px[nb]
            va = dx[a['off']:a['off'] + a['sz']]
            vb = dx[b['off']:b['off'] + b['sz']]
            n = min(len(va), len(vb), 65536)
            xor = bytes(x ^ y for x, y in zip(va[:n], vb[:n]))
            c = Counter(xor)
            print(f'   {na} XOR {nb}: 不同值={len(c)}/256 最常见={c.most_common(2)}')

    print()
    print('=== 关键:同机型内,是否存在相同密文块(跨分区 CBC 链复用)===')
    # 建立 S5M2X 全部加密分区前 4MB 的 16 字节块索引
    seen = {}
    dups = 0
    for nm, a in px.items():
        blob = dx[a['off']:a['off'] + min(a['sz'], 4 << 20)]
        for k in range(0, len(blob) - 16, 16):
            blk = blob[k:k + 16]
            if blk == bytes(16):
                continue
            if blk in seen:
                if seen[blk][0] != nm:
                    dups += 1
                    if dups <= 5:
                        print(f'   跨分区重复块! {seen[blk][0]}@{seen[blk][1]:X} == {nm}@{k:X} : {blk.hex()}')
            else:
                seen[blk] = (nm, k)
    print(f'   跨分区重复 16B 块数 = {dups}')

except Exception:
    traceback.print_exc()
    sys.exit(1)
