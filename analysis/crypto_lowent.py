import struct, hashlib, math, re, sys, traceback
from collections import Counter

d = open('firmware/S5m2XV27.bin', 'rb').read()
N = len(d)
BASE = 0x200


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def get(nm):
    for i in range(58):
        o = 0x2DC + i * 0x5C
        n = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if n == nm:
            sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
            want = d[o + 0x2C:o + 0x2C + 32]
            return BASE + off, sz, want, flg, d[o + 0x4C:o + 0x4C + 12]
    return None


try:
    for nm in ['eep_fix', 'hr_d_prog', 'osddata', 'grid_data']:
        r = get(nm)
        if not r:
            continue
        real, sz, want, flg, nonce = r
        b = d[real:real + sz]
        print(f'===== {nm}  off={real:,} size={sz:,} flg={flg} nonce={nonce.hex()} =====')
        print(f'  entropy={ent(b):.3f} nonzero={sum(1 for x in b if x):,}')
        print(f'  want_sha={want.hex()}')
        print(f'  sha(raw)      ={hashlib.sha256(b).hexdigest()}')
        print(f'  sha(rstrip00) ={hashlib.sha256(b.rstrip(b"\x00")).hexdigest()}')
        # 找第一个非零
        first = next((k for k, x in enumerate(b) if x), None)
        print(f'  first nonzero @+0x{first:X}' if first is not None else '  all zero')
        if first is not None:
            print(f'  data head: {b[first:first+64].hex(" ")}')
            txt = ''.join(chr(x) if 32 <= x < 127 else '.' for x in b[first:first+64])
            print(f'  ascii     : {txt}')
        # ASCII strings in this partition
        ss = [m.group().decode('ascii', 'replace') for m in re.finditer(rb'[\x20-\x7e]{5,}', b)]
        if ss:
            uniq = list(dict.fromkeys(ss))[:25]
            print(f'  strings({len(ss)}): {uniq}')
        # 非零字节的偏移分布(判断结构)
        nz_offsets = [k for k, x in enumerate(b) if x]
        if nz_offsets:
            print(f'  nonzero range: [0x{nz_offsets[0]:X} .. 0x{nz_offsets[-1]:X}] count={len(nz_offsets)}')
        print()

    # 专门: eep_fix 全部非零字节内容 dump
    print('===== eep_fix 非零内容完整 dump =====')
    r = get('eep_fix')
    real, sz, want, flg, nonce = r
    b = d[real:real + sz]
    nz = [(k, x) for k, x in enumerate(b) if x]
    print(f'  total nonzero={len(nz)}')
    # 采样输出
    for k, x in nz[:80]:
        pass
    # 输出非零段
    runs = []
    st = None
    prev = None
    for k, x in nz:
        if st is None:
            st = k
        elif k != prev + 1:
            runs.append((st, prev))
            st = k
        prev = k
    if st is not None:
        runs.append((st, prev))
    print(f'  连续非零段数={len(runs)}')
    for a, bb in runs[:10]:
        seg = b[a:bb + 1]
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg[:80])
        print(f'    [0x{a:06X}..0x{bb:06X}] len={bb-a+1:5} {seg[:40].hex(" ")} |{asc}|')

except Exception:
    traceback.print_exc()
    sys.exit(1)
