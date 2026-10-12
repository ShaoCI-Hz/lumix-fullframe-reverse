import struct, hashlib, re, sys, traceback
from Crypto.Cipher import AES

d = open('firmware/S5m2XV27.bin', 'rb').read()
N = len(d)
BASE = 0x200

# 目标:lens_hist keystream(明文全零,nonce=0)
KS = bytes.fromhex('1f2466f650b013e7e5f22c08224d96a1')
KS2 = bytes.fromhex('b286d712e883444cb05d89220e1dfb3e')  # 第2块

try:
    # 1) 提取固件中所有 ASCII 字符串(收敛:长度 4-24、字母数字为主)
    strs = set()
    for m in re.finditer(rb'[\x20-\x7e]{4,64}', d):
        s = m.group()
        if not (4 <= len(s) <= 24):
            continue
        # 只保留看起来像 token/key 的(字母数字下划线横线)
        if re.fullmatch(rb'[A-Za-z0-9_\-]{4,24}', s):
            strs.add(s)
    extra = [b'MC8223X', b'MC8223', b'Panasonic', b'panasonic', b'PANASONIC',
             b'LUMIX', b'Lumix', b'S5M2X', b'DC-S5M2X', b'lens_hist',
             b'V-Log', b'DMW-SFU2', b'UPD']
    for e in extra:
        strs.add(e)
    strs = list(strs)[:20000]
    print(f'候选字符串数: {len(strs):,}')

    # 2) 生成 key 候选
    def make_keys(s):
        out = []
        out.append((f'SHA256({s[:12]!r})', hashlib.sha256(s).digest()))
        out.append((f'MD5({s[:12]!r})', hashlib.md5(s).digest() * 2))
        out.append((f'SHA1({s[:12]!r})', hashlib.sha1(s).digest() + bytes(12)))
        if 16 <= len(s) <= 32:
            out.append((f'raw({s[:12]!r})', (s + bytes(32))[:32]))
        # 加上机型
        out.append((f'SHA256(MC8223X+{s[:10]!r})', hashlib.sha256(b'MC8223X' + s).digest()))
        out.append((f'SHA256({s[:10]!r}+MC8223X)', hashlib.sha256(s + b'MC8223X').digest()))
        return out

    # 3) CTR keystream 生成函数
    def ctr_first_block(key, nonce, layout, endian):
        if layout == 'n12c4':
            pt = nonce[:12] + (0).to_bytes(4, endian)
        elif layout == 'c4n12':
            pt = (0).to_bytes(4, endian) + nonce[:12]
        elif layout == 'c16':
            pt = (0).to_bytes(16, endian)
        elif layout == 'n8c8':
            pt = nonce[:8] + (0).to_bytes(8, endian)
        else:
            return None
        return AES.new(key, AES.MODE_ECB).encrypt(pt)

    found = []
    zero_nonce = bytes(12)
    cnt = 0
    for s in strs:
        for kn, k in make_keys(s):
            for kl in (16, 24, 32):
                if len(k) < kl:
                    continue
                kk = k[:kl]
                for layout in ('n12c4', 'c4n12', 'c16', 'n8c8'):
                    for endian in ('>', '<'):
                        try:
                            got = ctr_first_block(kk, zero_nonce, layout, endian)
                            if got == KS:
                                msg = f'!!!!! MATCH key={kn} kl={kl} layout={layout} endian={endian}'
                                print(msg)
                                found.append(msg)
                        except Exception:
                            pass
            cnt += 1
        if cnt % 2000 == 0:
            print(f'  ...已试 {cnt:,}')

    print()
    if found:
        print(f'*** 命中 {len(found)} ***')
    else:
        print('字典攻击未命中')

    # 4) 另一路:假设 keystream = SHA-256 派生流(非 AES)
    print()
    print('=== 检查 keystream 是否等于某个哈希流的片段 ===')
    # 若 keystream = SHA256(seed) 或 SHA256(seed||counter) 拼接
    for s in list(strs)[:0]:
        pass
    # 对已知的 keystream,反查:是否有 s 使 sha256(s) 前 16 字节 == KS?
    for s in strs:
        for cand in (hashlib.sha256(s).digest(), hashlib.sha256(b'MC8223X' + s).digest(),
                     hashlib.sha256(s + b'MC8223X').digest()):
            if cand[:16] == KS:
                print(f'!!!!! keystream == SHA256 输出! s={s!r}')
    print('done')

except Exception:
    traceback.print_exc()
    sys.exit(1)
