import struct, hashlib, sys, traceback
from Crypto.Cipher import AES

dx = open('firmware/S5m2XV27.bin', 'rb').read()
dm = open('firmware/S5m2_V37.bin', 'rb').read()

try:
    print('=== 0x200..0x2DC 区域完整 hexdump(两台机型)===')
    for tag, d in (('S5M2X', dx), ('S5M2 ', dm)):
        print(f'--- {tag} ---')
        for off in range(0x200, 0x2E0, 16):
            seg = d[off:off + 16]
            asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
            print(f'  {off:04x}  {seg.hex(" ")}  |{asc}|')
        print()

    # 定位高熵块
    print('=== 高熵块定位 ===')
    def find_entropy_blocks(d, start=0x200, end=0x2E0):
        blocks = []
        cur = None
        for off in range(start, end):
            x = d[off]
            if x != 0:
                if cur is None:
                    cur = off
            else:
                if cur is not None:
                    if off - cur >= 16:
                        blocks.append((cur, off))
                    cur = None
        if cur is not None and end - cur >= 16:
            blocks.append((cur, end))
        return blocks

    for tag, d in (('S5M2X', dx), ('S5M2 ', dm)):
        blks = find_entropy_blocks(d)
        print(f'  {tag}: {[(hex(a),hex(b),b-a) for a,b in blks]}')
        for a, b in blks:
            data = d[a:b]
            print(f'     @0x{a:X} len={b-a}')
            print(f'       {data.hex()}')

    print()
    print('=== 关键:两机型该区域是否相同? ===')
    a1 = dx[0x200:0x2E0]
    a2 = dm[0x200:0x2E0]
    same = a1 == a2
    print(f'  0x200..0x2E0 完全相同: {same}')
    if not same:
        for k in range(0, 0xE0):
            if a1[k] != a2[k]:
                print(f'    首次不同 @0x{0x200+k:X}: X={a1[k]:02x} M={a2[k]:02x}')

    print()
    print('=== 用该 64 字节块尝试作为 key/nonce 验证 lens_hist keystream ===')
    KS = dx[0x6360200:0x6360210]

    def extract(d, off, n):
        return d[off:off + n]

    for tag, d in (('S5M2X', dx), ('S5M2 ', dm)):
        # 找该机型的高熵块
        blks = find_entropy_blocks(d)
        if not blks:
            continue
        a, b = blks[0]
        blk = d[a:b]
        print(f'  --- {tag} 块 @0x{a:X} len={b-a} ---')
        print(f'       {blk.hex()}')
        # 各种用法
        cands = {
            'blk[:16]': blk[:16],
            'blk[:32]': blk[:32],
            'sha256(blk)': hashlib.sha256(blk).digest(),
            'md5(blk)': hashlib.md5(blk).digest(),
        }
        if b - a >= 32:
            cands['blk[16:32]'] = blk[16:32]
            cands['blk[32:48]'] = blk[32:48]
        nonces = {
            'blk12': blk[:12], 'blk16': blk[:16],
            'hash12': hashlib.sha256(blk).digest()[:12],
            'zero': bytes(12),
        }
        for kn, k in cands.items():
            for kl in (16, 24, 32):
                if len(k) < kl:
                    continue
                kk = k[:kl]
                for nn, nc in nonces.items():
                    for layout in ('n12c4', 'c4n12', 'c16', 'n8c8'):
                        for endian in ('>', '<'):
                            try:
                                if layout == 'n12c4':
                                    pt = (nc + bytes(4))[:16]
                                elif layout == 'c4n12':
                                    pt = (bytes(4) + nc)[:16]
                                elif layout == 'c16':
                                    pt = bytes(16)
                                else:
                                    pt = (nc[:8] + bytes(8))[:16]
                                pt = (pt + bytes(16))[:16]
                                got = AES.new(kk, AES.MODE_ECB).encrypt(pt)
                                if got == KS:
                                    print(f'     !!!!! MATCH key={kn} nonce={nn} layout={layout} endian={endian} kl={kl}')
                            except Exception:
                                pass
    print('  (若无 MATCH 则未命中)')

except Exception:
    traceback.print_exc()
    sys.exit(1)
