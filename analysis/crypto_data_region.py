import struct, hashlib, sys, traceback
from collections import Counter

d = open('firmware/S5m2XV27.bin', 'rb').read()
N = len(d)
BASE = 0x200


def parts():
    out = {}
    for i in range(58):
        o = 0x2DC + i * 0x5C
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm:
            continue
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        want = d[o + 0x2C:o + 0x2C + 32]
        out[nm] = dict(off=BASE + off, sz=sz, flg=flg, want=want,
                       nonce=d[o + 0x4C:o + 0x4C + 12])
    return out


P = parts()


def data_region(nm):
    """返回(分区内数据起始, 数据 blob)"""
    a = P[nm]
    blob = d[a['off']:a['off'] + a['sz']]
    nz = [k for k, x in enumerate(blob) if x]
    if not nz:
        return None, None
    return nz[0], blob


try:
    print('=== 三个"明文全零"分区的数据区对比 ===')
    regions = {}
    for nm in ['vkizu_data', 'lut2_data', 'grid_data', 'lens_hist']:
        st, blob = data_region(nm)
        if blob is None:
            continue
        data = blob[st:]
        regions[nm] = (st, data)
        # 数据区前若干块的熵
        e0 = Counter(data[:65536])
        print(f'  {nm:12} 分区内数据起始=0x{st:X} ({st%0x10000:#x} mod 64K)  数据长={len(data):,}')
        print(f'       data[:32]={data[:32].hex()}')
        print(f'       data[0x7A00-0x0处?] ...')

    print()
    print('=== 关键:比较数据区(对齐到块内 0x7A00 偏移) ===')
    names = list(regions.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            na, nb = names[i], names[j]
            da = regions[na][1]
            db = regions[nb][1]
            n = min(len(da), len(db), 1 << 20)  # 前 1MB
            # 直接对齐比较
            same_prefix = 0
            for k in range(0, n, 16):
                if da[k:k + 16] == db[k:k + 16]:
                    same_prefix += 1
            # XOR 统计
            xor = bytes(x ^ y for x, y in zip(da[:min(n, 65536)], db[:min(n, 65536)]))
            c = Counter(xor)
            print(f'  {na} vs {nb}: XOR 不同值={len(c)}/256 (1=完全相同)  相同16B块={same_prefix}/{n//16}')
            if len(c) == 1:
                print(f'      !!!!! 数据区密文完全相同 !!!!!')
            print(f'      da[:16]={da[:16].hex()}  db[:16]={db[:16].hex()}')

    print()
    print('=== 探针搜索:数据区密文片段是否在其他分区出现 ===')
    for na in names:
        st, da = regions[na]
        probe = da[:64]
        print(f'  {na} 探针 data[:64]={probe[:16].hex()}')
        for nb in names:
            if nb == na:
                continue
            st2, db = regions[nb]
            idx = db.find(probe)
            if idx >= 0:
                print(f'     !!! 在 {nb} 数据区偏移 0x{idx:X} 找到相同 64B!')
        # 全固件搜索
        pos = d.find(probe)
        cnt = 0
        while pos >= 0 and cnt < 4:
            print(f'      固件命中 @0x{pos:X}')
            pos = d.find(probe, pos + 1)
            cnt += 1

    print()
    print('=== 数据区 64KB 块边界分析(块内偏移对齐) ===')
    for nm in names:
        st, da = regions[nm]
        print(f'  {nm:12} 数据起始 mod 64K = 0x{st % 0x10000:X}')
        # 数据长度是否是 64KB 整数倍
        print(f'       数据长度 = {len(da):,} = 0x{len(da):X}  (mod 64K = 0x{len(da) % 0x10000:X})')

except Exception:
    traceback.print_exc()
    sys.exit(1)
