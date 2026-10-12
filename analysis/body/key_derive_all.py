import os
import struct
import hashlib
import itertools
from Crypto.Cipher import AES

FW = r'firmware'
BASE = 0x200
STEP = 0x5C

# 机型 -> 文件名
MODELS = {
    'MC892': 'S1___V24.bin',
    'MC893': 'S1H__V28.bin',
    'MC801': 'S5___V29.bin',
    'MC8223': 'S5m2_V37.bin',
    'MC8223X': 'S5m2XV27.bin',
    'MC8259': 'S9___V20.bin',
}


def get_keystreams(fn):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        return []
    d = open(p, 'rb').read()
    n = len(d)
    out = []
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
        if sz == 0 or BASE + off + sz > n:
            continue
        sha = d[o + 0x2C:o + 0x2C + 32]
        nonce = d[o + 0x4C:o + 0x4C + 12]
        if hashlib.sha256(bytes(sz)).digest() == sha:
            blob = d[BASE + off:BASE + off + sz]
            if sum(1 for x in blob if x) > 0:
                out.append((nm, blob[:16], nonce, sz))
    return out


print('=== 各机型 keystream 样本 ===')
ks_by_model = {}
for mid, fn in MODELS.items():
    ks = get_keystreams(fn)
    ks_by_model[mid] = ks
    print(f'  {mid:8} ({fn}): {len(ks)} 个样本')
    for nm, k16, nonce, sz in ks[:3]:
        print(f'      {nm:12} ks[:16]={k16.hex()}  nonce={nonce.hex()}')

print()
print('=== key 派生验证:keystream[0:16] == AES(key, nonce||0)? ===')


def derive_candidates(mid, nm, nonce):
    mb = mid.encode()
    nb = nm.encode()
    outs = {}
    seeds = {
        'model': mb,
        'model_lower': mb.lower(),
        'name': nb,
        'model+name': mb + nb,
        'name+model': nb + mb,
        'model+0': mb + b'\x00',
        'pad_model16': mb.ljust(16, b'\x00'),
        'pad_model32': mb.ljust(32, b'\x00'),
        'model+name+0': mb + nb + b'\x00',
    }
    for sn, s in seeds.items():
        outs[f'sha256({sn})'] = hashlib.sha256(s).digest()
        outs[f'sha1({sn})'] = hashlib.sha1(s).digest() + bytes(12)
        outs[f'md5({sn})'] = hashlib.md5(s).digest() * 2
    return outs


def ctr(key, nonce, blocks=2, layout='n12c4', endian='>'):
    out = b''
    for i in range(blocks):
        if layout == 'n12c4':
            pt = (nonce + i.to_bytes(4, endian))[:16]
        elif layout == 'c4n12':
            pt = (i.to_bytes(4, endian) + nonce)[:16]
        elif layout == 'c16':
            pt = i.to_bytes(16, endian)
        else:
            pt = nonce[:8] + i.to_bytes(8, endian)
        pt = (pt + bytes(16))[:16]
        out += AES.new(key, AES.MODE_ECB).encrypt(pt)
    return out


hit = []
tried = 0
for mid, ks in ks_by_model.items():
    for nm, k16, nonce, sz in ks:
        for kn, key in derive_candidates(mid, nm, nonce).items():
            for kl in (16, 24, 32):
                if len(key) < kl:
                    continue
                kk = key[:kl]
                for layout in ('n12c4', 'c4n12', 'c16', 'n8c8'):
                    for endian in ('>', '<'):
                        tried += 1
                        try:
                            if ctr(kk, nonce[:12], 1, layout, endian)[:16] == k16:
                                m = f'!!! MATCH {mid}/{nm} key={kn} kl={kl} layout={layout} e={endian}'
                                print(m)
                                hit.append(m)
                        except Exception:
                            pass
print(f'尝试 {tried:,} 组合')
if not hit:
    print('未命中')
