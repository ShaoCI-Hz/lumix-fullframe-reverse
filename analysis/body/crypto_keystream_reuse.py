import struct, hashlib, sys, traceback

d = open('firmware/S5m2XV27.bin', 'rb').read()
N = len(d)
BASE = 0x200


def parts():
    out = []
    for i in range(58):
        o = 0x2DC + i * 0x5C
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm:
            continue
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        want = d[o + 0x2C:o + 0x2C + 32]
        nonce = d[o + 0x4C:o + 0x4C + 12]
        if nm == 'boot' and sz == 0:
            sz = struct.unpack_from('<I', d, o + 0x04)[0]
            off = struct.unpack_from('<I', d, o + 0x08)[0]
        out.append((i, nm, BASE + off, sz, flg, nonce, want))
    return out


P = parts()
# 明文已知为全零的分区(密文 = keystream,若为流密码)
zero_plain = []
for i, nm, real, sz, flg, nonce, want in P:
    if sz and real + sz <= N and hashlib.sha256(bytes(sz)).digest() == want:
        blob = d[real:real + sz]
        nz = sum(1 for x in blob if x)
        if nz > 0:
            zero_plain.append((nm, real, sz, nonce.hex(), blob))

print('=== 明文全零且有密文的分区(密文即 keystream)===')
for nm, real, sz, nhex, blob in zero_plain:
    print(f'  {nm:12} off={real:>11,} size={sz:>9,} nonce={nhex}')
    # 找实际数据区(排除零填充)
    nz = [k for k, x in enumerate(blob) if x]
    if nz:
        print(f'       数据区(分区内)=[0x{nz[0]:X}..0x{nz[-1]:X}]')

print()
print('=== 关键实验:keystream 复用搜索 ===')
print('  原理:若 keystream 按全局偏移生成,不同分区在相同偏移处应有相同字节')
# 对每个 zero_plain 分区,取其数据区的前若干 64 字节片段,在其他分区密文中搜索
for nm, real, sz, nhex, blob in zero_plain:
    nz = [k for k, x in enumerate(blob) if x]
    if not nz:
        continue
    start = nz[0]
    probes = []
    for off in (start, start + 0x1000, start + 0x10000, sz // 2):
        if off + 64 <= sz and any(blob[off:off + 64]):
            probes.append((off, blob[off:off + 64]))
    print(f'--- {nm} ---')
    for poff, probe in probes[:3]:
        print(f'   探针 @分区内0x{poff:X} = {probe[:16].hex()}')
        # 在其他 zero_plain 分区中搜索
        for nm2, real2, sz2, nhex2, blob2 in zero_plain:
            if nm2 == nm:
                continue
            idx = blob2.find(probe)
            if idx >= 0:
                print(f'      !!! 在 {nm2} 分区内偏移 0x{idx:X} 找到相同 64 字节!')
            # 也在整个固件其他位置搜
        idx_all = d.find(probe, 0)
        cnt = 0
        pos = 0
        while cnt < 3:
            pos = d.find(probe, pos)
            if pos < 0:
                break
            print(f'      (全固件 @0x{pos:X})')
            pos += 1
            cnt += 1

print()
print('=== 另:检查同尺寸分区密文是否相同(keystream+明文同 => 密文同)===')
from collections import defaultdict
by_size = defaultdict(list)
for nm, real, sz, nhex, blob in zero_plain:
    by_size[sz].append((nm, nhex, blob))
for sz, items in by_size.items():
    if len(items) > 1:
        print(f'  size={sz:,}: {[x[0] for x in items]}')
        for a in items:
            for b in items:
                if a[0] < b[0]:
                    same = a[2] == b[2]
                    print(f'    {a[0]} vs {b[0]}: 密文完全相同={same}')

