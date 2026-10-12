import struct, hashlib, sys, traceback
from Crypto.Cipher import AES

d = open('firmware/S5m2XV27.bin', 'rb').read()
BASE = 0x200

# lens_hist: 明文全零 => 密文就是 keystream
info = {}
for i in range(58):
    o = 0x2DC + i * 0x5C
    nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
    if not nm:
        continue
    sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
    info[nm] = (BASE + off, sz, flg, bytes(d[o + 0x4C:o + 0x4C + 12]))


def ks(nm, n=32):
    real, sz, flg, nonce = info[nm]
    return d[real:real + n]


targets = {nm: ks(nm, 32) for nm in ['lens_hist', 'vkizu_data', 'lut2_data', 'grid_data']}
model = b'MC8223X'
model2 = b'MC8223'

print('=== 目标 keystream(明文全零,密文即可)===')
for nm, t in targets.items():
    print(f'  {nm:12} {t[:16].hex()}')

print()
print('=== 尝试:key 从分区名派生 ===')
found = []
names = ['lens_hist', 'vkizu_data', 'lut2_data', 'grid_data']

# 生成候选 key
def candidates(name):
    nb = name.encode()
    outs = []
    for base in (nb, nb.upper(), nb.lower()):
        outs.append(('sha256(name)', hashlib.sha256(base).digest()))
        outs.append(('sha1(name)', hashlib.sha1(base).digest()))
        outs.append(('md5(name)', hashlib.md5(base).digest()))
        outs.append(('sha256(model+name)', hashlib.sha256(model + base).digest()))
        outs.append(('sha256(name+model)', hashlib.sha256(base + model).digest()))
        outs.append(('sha256(model2+name)', hashlib.sha256(model2 + base).digest()))
        outs.append(('sha256(name+model2)', hashlib.sha256(base + model2).digest()))
        outs.append(('sha256(name+name)', hashlib.sha256(base + base).digest()))
        outs.append(('pad32(name)', (base + b'\x00' * 32)[:32]))
        outs.append(('pad16(name)', (base + b'\x00' * 16)[:16]))
        # 去掉下划线
        nb2 = base.replace(b'_', b'')
        outs.append(('sha256(noname_us)', hashlib.sha256(nb2).digest()))
        outs.append(('sha256(model+noname_us)', hashlib.sha256(model + nb2).digest()))
    return outs


def ctr_keystream(key, nonce, blocks=2, endian='>'):
    """CTR: keystream_i = AES_enc(key, nonce || counter_i) 或 counter || nonce"""
    out = b''
    for i in range(blocks):
        for layout in ('nonce12_ctr4', 'ctr4_nonce12', 'ctr16', 'nonce8_ctr8'):
            if layout == 'nonce12_ctr4':
                pt = nonce + i.to_bytes(4, endian)
            elif layout == 'ctr4_nonce12':
                pt = i.to_bytes(4, endian) + nonce
            elif layout == 'ctr16':
                pt = (i).to_bytes(16, endian)
            else:
                pt = nonce[:8] + i.to_bytes(8, endian)
            out += AES.new(key, AES.MODE_ECB).encrypt(pt)[:16]
    return out


for nm in names:
    tgt = targets[nm][:32]
    nonce = info[nm][3]
    for cname, key in candidates(nm):
        for kl in (16, 24, 32):
            if len(key) < kl:
                continue
            k = key[:kl]
            for endian in ('>', '<'):
                for wbits in (128,):
                    try:
                        # 试各种 counter 布局
                        for layout in ('nonce12_ctr4', 'ctr4_nonce12', 'ctr16', 'nonce8_ctr8'):
                            got = b''
                            for i in range(2):
                                if layout == 'nonce12_ctr4':
                                    pt = (nonce + i.to_bytes(4, endian))
                                elif layout == 'ctr4_nonce12':
                                    pt = (i.to_bytes(4, endian) + nonce)
                                elif layout == 'ctr16':
                                    pt = i.to_bytes(16, endian)
                                else:
                                    pt = nonce[:8] + i.to_bytes(8, endian)
                                got += AES.new(k, AES.MODE_ECB).encrypt(pt)
                            if got[:16] == tgt[:16]:
                                msg = f'!!!!! MATCH {nm} cname={cname} kl={kl} endian={endian} layout={layout} key={k.hex()}'
                                print(msg)
                                found.append(msg)
                    except Exception:
                        pass

print()
if found:
    print(f'!!! 找到 {len(found)} 个匹配 !!!')
else:
    print('分区名派生未匹配。')

# 再试:用"分区名"作为 AES 输入对固定 key 加密(即 keystream = E(key, name))
print()
print('=== 尝试:keystream = E(key, 分区名||counter),用常见/派生 key ===')
common_keys = [
    hashlib.sha256(model).digest(),
    hashlib.sha256(model2).digest(),
    hashlib.sha256(b'panasonic').digest(),
    hashlib.sha256(b'LUMIX').digest(),
    hashlib.sha256(b'').digest(),
    b'\x00' * 32, b'\x00' * 16,
    bytes(range(32)), bytes(range(16)),
]
for nm in names:
    tgt = targets[nm][:16]
    nb = nm.encode()
    for ki, k in enumerate(common_keys):
        for kl in (16, 24, 32):
            if len(k) < kl:
                continue
            kk = k[:kl]
            for payload in (nb, nb + b'\x00' * 16, nb.ljust(16, b'\x00'), nb.ljust(32, b'\x00')):
                try:
                    if len(payload) not in (16, 32, 48, 64):
                        continue
                    got = AES.new(kk, AES.MODE_ECB).encrypt(payload[:16])
                    if got == tgt:
                        print(f'!!!!! MATCH(common key) {nm} keyidx={ki} kl={kl}')
                except Exception:
                    pass
print('done')
