import struct, hashlib, sys, traceback, itertools
from Crypto.Cipher import AES

dx = open('firmware/S5m2XV27.bin', 'rb').read()
dm = open('firmware/S5m2_V37.bin', 'rb').read()

try:
    print('=== 两个 UPD 记录完整字段对比 ===')
    for off in (0x0, 0x2A0):
        print(f'--- UPD 记录 @0x{off:X} ---')
        for k in range(0, 0x40, 4):
            v = struct.unpack_from('<I', dx, off + k)[0]
            print(f'  +0x{k:02X} = 0x{v:08X} ({v:,})')
        print(f'  +0x0C id = {dx[off+0x0C:off+0x1C]!r}')
        print()

    print('=== 0x220 的 64 字节:结构分析 ===')
    blk_x = dx[0x220:0x260]
    blk_m = dm[0x220:0x260]
    print(f'  X: {blk_x.hex()}')
    print(f'  M: {blk_m.hex()}')
    print(f'  X 前32: {blk_x[:32].hex()}')
    print(f'  X 后32: {blk_x[32:].hex()}')
    # 是否为"加密的随机"或结构化
    print(f'  X 字节范围: min={min(blk_x)} max={max(blk_x)}')
    # 检查是否是 2x 32 字节(两个 256-bit 值,如 ECDSA r||s)
    for name, b in (('X', blk_x), ('M', blk_m)):
        r = int.from_bytes(b[:32], 'big')
        s = int.from_bytes(b[32:], 'big')
        print(f'  {name}: r bitlen={r.bit_length()} s bitlen={s.bit_length()}')

    print()
    print('=== 全面 key 验证:lens_hist keystream ===')
    KS = dx[0x6360200:0x6360210]
    KS2 = dx[0x6360210:0x6360220]
    print(f'  目标 keystream[0:16]={KS.hex()}')
    print(f'  目标 keystream[16:32]={KS2.hex()}')

    def aes_ctr_stream(key, nonce12, blocks, layout, endian):
        out = b''
        for i in range(blocks):
            if layout == 'n12c4':
                pt = nonce12 + i.to_bytes(4, endian)
            elif layout == 'c4n12':
                pt = i.to_bytes(4, endian) + nonce12
            elif layout == 'c16':
                pt = i.to_bytes(16, endian)
            elif layout == 'n8c8':
                pt = nonce12[:8] + i.to_bytes(8, endian)
            elif layout == 'n12c4_be1':  # counter 从 1 开始
                pt = nonce12 + (i + 1).to_bytes(4, endian)
            out += AES.new(key, AES.MODE_ECB).encrypt(pt)
        return out

    found = []
    for tag, blk in (('X', blk_x), ('M', blk_m)):
        # key 候选
        keycands = {}
        keycands['blk[:32]'] = blk[:32]
        keycands['blk[32:]'] = blk[32:]
        keycands['blk[:16]'] = blk[:16]
        keycands['blk[16:32]'] = blk[16:32]
        keycands['sha256(blk)'] = hashlib.sha256(blk).digest()
        keycands['sha256(blk[:32])'] = hashlib.sha256(blk[:32]).digest()
        keycands['md5(blk)'] = hashlib.md5(blk).digest() * 2
        noncecands = {}
        noncecands['zero'] = bytes(12)
        noncecands['blk[:12]'] = blk[:12]
        noncecands['blk[32:44]'] = blk[32:44]
        noncecands['sha256(blk)[:12]'] = hashlib.sha256(blk).digest()[:12]
        for kn, k in keycands.items():
            for kl in (16, 24, 32):
                if len(k) < kl:
                    continue
                kk = k[:kl]
                for nn, nc in noncecands.items():
                    for layout in ('n12c4', 'c4n12', 'c16', 'n8c8', 'n12c4_be1'):
                        for endian in ('>', '<'):
                            for nb in (1, 2):
                                try:
                                    got = aes_ctr_stream(kk, nc, nb, layout, endian)
                                    if got[:16] == KS:
                                        m = f'!!!!! MATCH {tag} key={kn} nonce={nn} layout={layout} endian={endian} kl={kl} counter_start={nb}'
                                        print(m)
                                        found.append(m)
                                except Exception:
                                    pass

    print()
    if found:
        print(f'*** 命中 {len(found)} ***')
    else:
        print('未命中')

    print()
    print('=== 另一路:该 64B 是否 = SHA256/AES 相关值 ===')
    for tag, blk in (('X', blk_x), ('M', blk_m)):
        print(f'  {tag}:')
        print(f'    sha256(blk)      = {hashlib.sha256(blk).hexdigest()}')
        print(f'    sha256(fr 0x200) = {hashlib.sha256((dx if tag=="X" else dm)[0x200:0x2A0]).hexdigest()}')
        # 是否 = 某段的 sha256
        for src, dd in (('UPD头0x0:0x40', (dx if tag == 'X' else dm)[0:0x40]),):
            print(f'    sha256({src}) = {hashlib.sha256(dd).hexdigest()}')

    print()
    print('=== 检查 0x220 块是否可能是"被加密的密钥"(用固件内其他数据解)===')
    # 若 blk = AES_ECB(somekey, realkey),试着用常见 key 解
    for tag, blk in (('X', blk_x), ('M', blk_m)):
        for kn, k in (('zeros', bytes(16)), ('zeros32', bytes(32)),
                      ('panasonic', b'panasonic'.ljust(16, b'\x00')),
                      ('MC8223X', b'MC8223X'.ljust(16, b'\x00'))):
            try:
                dec = AES.new(k, AES.MODE_ECB).decrypt(blk[:16])
                # 解密后是否有意义?
                printable = sum(1 for x in dec if 32 <= x < 127 or x == 0)
                if printable >= 14:
                    print(f'  {tag} AES_ECB_dec({kn}) -> {dec.hex()} (printable={printable})')
            except Exception:
                pass
    print('  (无输出=无意义)')

except Exception:
    traceback.print_exc()
    sys.exit(1)
