import struct, hashlib, math, sys, traceback
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
            nonce = d[o + 0x4C:o + 0x4C + 12]
            return BASE + off, sz, want, flg, nonce
    return None


try:
    print('=== 排除零填充后,非零部分的真实熵(判定是否密文) ===')
    print(f'{"name":12} {"full_ent":>9} {"nonzero_ent":>12} {"nz/size":>9}  判定')
    for nm in ['eep_fix', 'hr_d_prog', 'osddata', 'grid_data',
               'lens_hist', 'vkizu_data', 'lut2_data', 'history',
               'music', 'osdover', 'hm_c_ddr']:
        r = get(nm)
        if not r:
            continue
        real, sz, want, flg, nonce = r
        if real + sz > N:
            continue
        b = d[real:real + sz]
        nz = bytes(x for x in b if x != 0)
        ratio = len(nz) / sz if sz else 0
        e_full = ent(b)
        e_nz = ent(nz)
        # 全零明文?
        is_zero_plain = hashlib.sha256(bytes(sz)).digest() == want
        verdict = '密文(高熵)' if e_nz >= 7.5 else ('低熵-可疑' if e_nz < 6.0 else '中等')
        if is_zero_plain:
            verdict += ' / 明文=全零'
        print(f'{nm:12} {e_full:>9.3f} {e_nz:>12.3f} {ratio:>9.2%}  {verdict}')

    print()
    print('=== 4 个"明文全零"分区:密文分布特征(加密起止)===')
    for nm in ['grid_data', 'vkizu_data', 'lut2_data', 'lens_hist']:
        r = get(nm)
        real, sz, want, flg, nonce = r
        b = d[real:real + sz]
        nz = [k for k, x in enumerate(b) if x]
        if not nz:
            print(f'  {nm:12} 全零')
            continue
        first, last = nz[0], nz[-1]
        # 分块统计(每 64KB)
        print(f'  {nm:12} size={sz:>9,} nonce={nonce.hex()}')
        print(f'       nonzero=[0x{first:X}..0x{last:X}] total={len(nz):,}')
        step = 65536
        blocks = []
        for off in range(0, sz, step):
            seg = b[off:off + step]
            n = sum(1 for x in seg if x)
            blocks.append((off, n, ent(seg)))
        # 打印非全零块
        for off, n, e in blocks:
            if n > 0:
                flag = '密文' if e >= 7.5 else '低熵'
                print(f'       block +0x{off:07X}: nz={n:>6,}/{step} ent={e:5.3f} {flag}')

except Exception:
    traceback.print_exc()
    sys.exit(1)
