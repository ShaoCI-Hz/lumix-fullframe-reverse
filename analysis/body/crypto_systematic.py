import struct, hashlib, sys, traceback
from Crypto.Cipher import AES

d = open('firmware/S5m2XV27.bin', 'rb').read()
N = len(d)
BASE = 0x200
STEP = 0x5C
MODEL = b'MC8223X'

# 收集分区项全部字段
recs = {}
for i in range(58):
    o = 0x2DC + i * STEP
    nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
    if not nm:
        continue
    sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
    want = d[o + 0x2C:o + 0x2C + 32]
    tail3 = d[o + 0x1D:o + 0x20]       # name 后 3 字节
    f4c = d[o + 0x4C:o + 0x4C + 12]
    f58 = struct.unpack_from('<I', d, o + 0x58)[0]
    recs[nm] = dict(idx=i, real=BASE + off, sz=sz, flg=flg, want=want,
                    tail3=tail3, f4c=f4c, f58=f58, off=off)


def keystream(nm, n=32):
    a = recs[nm]
    blob = d[a['real']:a['real'] + a['sz']]
    nz = [k for k, x in enumerate(blob) if x]
    if not nz:
        return None, None
    st = nz[0]
    return blob[st:st + n], st


try:
    print('=== 目标:4 个已知明文(全零)分区的 keystream ===')
    tg = {}
    for nm in ['lens_hist', 'vkizu_data', 'lut2_data', 'grid_data']:
        ks, st = keystream(nm, 16)
        tg[nm] = ks
        print(f'  {nm:12} tail3={recs[nm]["tail3"].hex()} ks[:16]={ks.hex()}')

    print()
    print('=== 派生 nonce/key:用各种字段组合 ===')

    def nonces(nm):
        a = recs[nm]
        nb = nm.encode()
        out = {}
        out['tail3_pad12'] = a['tail3'] + bytes(9)
        out['tail3_pad16'] = a['tail3'] + bytes(13)
        out['tail3_lo4'] = a['tail3'] + bytes(1)
        out['tail3hi3'] = bytes(1) + a['tail3']
        out['f4c'] = a['f4c']
        out['idx_le4'] = struct.pack('<I', a['idx'])
        out['idx_be4'] = struct.pack('>I', a['idx'])
        out['st_le4'] = struct.pack('<I', a.get('_st', 0))
        out['sz_le4'] = struct.pack('<I', a['sz'])
        out['sha256(name)[:12]'] = hashlib.sha256(nb).digest()[:12]
        out['sha256(model+name)[:12]'] = hashlib.sha256(MODEL + nb).digest()[:12]
        out['zero'] = bytes(12)
        return out

    def keys(nm):
        a = recs[nm]
        nb = nm.encode()
        out = {}
        out['sha256(name)'] = hashlib.sha256(nb).digest()
        out['sha256(model)'] = hashlib.sha256(MODEL).digest()
        out['sha256(model+name)'] = hashlib.sha256(MODEL + nb).digest()
        out['sha256(name+model)'] = hashlib.sha256(nb + MODEL).digest()
        out['sha256(name+tail3)'] = hashlib.sha256(nb + a['tail3']).digest()
        out['sha256(tail3+name)'] = hashlib.sha256(a['tail3'] + nb).digest()
        out['md5(model)'] = hashlib.md5(MODEL).digest() * 2
        out['pad(model,32)'] = MODEL.ljust(32, b'\x00')
        out['pad(model,16)'] = MODEL.ljust(16, b'\x00')
        out['zeros32'] = bytes(32)
        return out

    hit = []
    for nm in ['lens_hist', 'vkizu_data', 'lut2_data', 'grid_data']:
        a = recs[nm]
        blob = d[a['real']:a['real'] + a['sz']]
        nz = [k for k, x in enumerate(blob) if x]
        a['_st'] = nz[0]
    for nm, target in tg.items():
        for kn, k in keys(nm).items():
            for kl in (16, 24, 32):
                if len(k) < kl:
                    continue
                kk = k[:kl]
                for nn, nc in nonces(nm).items():
                    for ncl in (8, 12, 16):
                        n = (nc + bytes(16))[:ncl]
                        for endian in ('<', '>'):
                            # CTR 变体
                            for method in ('nonce+c', 'c+nonce', 'full16'):
                                try:
                                    got = b''
                                    for i in range(2):
                                        if method == 'nonce+c':
                                            blk = (n + i.to_bytes(max(16 - len(n), 1), endian))[:16]
                                        elif method == 'c+nonce':
                                            blk = (i.to_bytes(max(16 - len(n), 1), endian) + n)[:16]
                                        else:
                                            blk = (n + i.to_bytes(16, endian))[:16]
                                        if len(blk) != 16:
                                            blk = (blk + bytes(16))[:16]
                                        got += AES.new(kk, AES.MODE_ECB).encrypt(blk)
                                    if got[:16] == target:
                                        m = f'!!!!! MATCH {nm} key={kn} nonce={nn} ncl={ncl} endian={endian} method={method} kl={kl}'
                                        print(m)
                                        hit.append(m)
                                except Exception:
                                    pass
    print()
    if hit:
        print(f'*** 成功 {len(hit)} 个 ***')
    else:
        print('未匹配')

    print()
    print('=== 备用:直接搜索固件中是否有"密钥表"(32/16字节高熵连续块)===')
    # 检查 UPD 头附近、分区表区域是否有未被识别的字段
    print('  分区表区域 0x2DC..0x2100 中,非零且未被解析的字节:')
    # 分区项字段已知:name(16) size(4) off(4) flg(4) sha256(32) f4c(12) f58(4) + tail3(3)
    # 检查 name 字段中是否有非 ASCII 且看起来像 key 的部分
    for nm, a in recs.items():
        if a['tail3'] and any(x > 0x20 for x in a['tail3'][:3]):
            pass
    # 列出所有 tail3
    print('  所有分区 tail3( name 后 3 字节 ):')
    seen = {}
    for nm, a in recs.items():
        seen.setdefault(a['tail3'].hex(), []).append(nm)
    for k, v in sorted(seen.items()):
        print(f'    {k} -> {v[:6]}{"..." if len(v) > 6 else ""}')

except Exception:
    traceback.print_exc()
    sys.exit(1)
