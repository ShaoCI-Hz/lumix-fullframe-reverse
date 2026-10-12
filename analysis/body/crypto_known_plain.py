import struct, hashlib, sys, traceback

d = open('firmware/S5m2XV27.bin', 'rb').read()
N = len(d)
BASE = 0x200

# 逻辑内容已知为"全零"的分区(摘要 == SHA-256(全零N))
known_zero = []
all_parts = []
for i in range(58):
    o = 0x2DC + i * 0x5C
    nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
    if not nm:
        continue
    sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
    want = d[o + 0x2C:o + 0x2C + 32]
    iv = d[o + 0x4C:o + 0x4C + 12]
    if nm == 'boot' and sz == 0:
        sz = struct.unpack_from('<I', d, o + 0x04)[0]
        off = struct.unpack_from('<I', d, o + 0x08)[0]
    real = BASE + off
    all_parts.append((i, nm, real, sz, flg, iv.hex(), want.hex()))
    if sz and real + sz <= N:
        if hashlib.sha256(bytes(sz)).digest() == want:
            known_zero.append((i, nm, real, sz, flg, iv.hex(), d[real:real + sz]))

print('=== 已知明文(全零)的分区 ===')
for i, nm, real, sz, flg, ivhex, blob in known_zero:
    nz = sum(1 for x in blob if x)
    print(f'  [{i:2}] {nm:12} off={real:>11,} size={sz:>10,} flg={flg} nonce={ivhex} nonzero={nz:,}')
    print(f'        head16={blob[:16].hex()}')

print()
print('=== 关键:相同 nonce => 相同 keystream => 密文前缀应相同 ===')
# 按 nonce 分组
from collections import defaultdict
by_iv = defaultdict(list)
for i, nm, real, sz, flg, ivhex, blob in known_zero:
    by_iv[ivhex].append((nm, real, sz, blob))
for ivhex, items in by_iv.items():
    print(f'  nonce={ivhex}: {len(items)} 个分区 {[x[0] for x in items]}')
    if len(items) > 1:
        # 比较密文前缀
        base_nm, _, _, base = items[0]
        for nm, real, sz, blob in items[1:]:
            m = min(len(base), len(blob))
            # 找到最长公共前缀
            lcp = 0
            for k in range(m):
                if base[k] == blob[k]:
                    lcp += 1
                else:
                    break
            print(f'     {base_nm} vs {nm}: 公共密文前缀 = {lcp} bytes')
            print(f'        {base_nm}[:8]={base[:8].hex()}  {nm}[:8]={blob[:8].hex()}')

print()
print('=== 所有分区 nonce 唯一性 ===')
seen = defaultdict(list)
for i, nm, real, sz, flg, ivhex, want in all_parts:
    if ivhex != '00' * 12:
        seen[ivhex].append(nm)
dups = {k: v for k, v in seen.items() if len(v) > 1}
print(f'  非零 nonce 分区数={sum(len(v) for v in seen.values())}, 重复 nonce 组={len(dups)}')
for k, v in dups.items():
    print(f'    nonce={k} -> {v}')

print()
print('=== 验证:不同分区(相同大小)的全零明文密文对比 ===')
# 找相同 size 的 known_zero
by_size = defaultdict(list)
for i, nm, real, sz, flg, ivhex, blob in known_zero:
    by_size[sz].append((nm, ivhex, blob))
for sz, items in by_size.items():
    if len(items) > 1:
        print(f'  size={sz:,}: {[x[0] for x in items]}')
        a = items[0]
        for b in items[1:]:
            same = a[2] == b[2]
            print(f'    {a[0]} vs {b[0]}: 密文完全相同={same}  nonce同={a[1]==b[1]}')
