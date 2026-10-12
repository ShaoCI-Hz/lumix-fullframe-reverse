import struct, hashlib, sys, traceback
from Crypto.Cipher import AES

d = open('firmware/S5m2XV27.bin', 'rb').read()
N = len(d)
BASE = 0x200
STEP = 0x5C

print('=== 分区项 92 字节完整结构(lens_hist 与 program)===')
for want in ('lens_hist', 'program', 'vkizu_data'):
    for i in range(58):
        o = 0x2DC + i * STEP
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if nm != want:
            continue
        print(f'--- [{i}] {nm}  项@0x{o:X} ---')
        for k in range(0, STEP, 16):
            seg = d[o + k:o + k + 16]
            print(f'  +0x{k:02X}  {seg.hex(" ")}')
        print()

# 提取各分区的"数据区起始"及其 keystream(明文全零 => 密文=keystream)
print('=== 各分区数据区起始 keystream(明文全零)===')
zero_parts = []
for i in range(58):
    o = 0x2DC + i * STEP
    nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
    if not nm:
        continue
    sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
    want = d[o + 0x2C:o + 0x2C + 32]
    f4c = d[o + 0x4C:o + 0x4C + 12]
    f58 = struct.unpack_from('<I', d, o + 0x58)[0]
    real = BASE + off
    if nm == 'boot' and sz == 0:
        sz = struct.unpack_from('<I', d, o + 0x04)[0]
        real = BASE + struct.unpack_from('<I', d, o + 0x08)[0]
    if sz and real + sz <= N and hashlib.sha256(bytes(sz)).digest() == want:
        blob = d[real:real + sz]
        nz = [k for k, x in enumerate(blob) if x]
        if nz:
            st = nz[0]
            zero_parts.append((nm, real, sz, st, f4c, f58, blob))
            print(f'  {nm:12} real=0x{real:X} sz={sz:>9,} 数据起始(分区内)=0x{st:06X} (mod64K=0x{st%0x10000:X})')
            print(f'       +0x4C={f4c.hex()}  +0x58=0x{f58:08X}')
            print(f'       keystream[:32]={blob[st:st+32].hex()}')

print()
print('=== 关键:数据区起始 keystream 与"+0x4C/+0x58"的关系 ===')
# 假设 keystream = AES(key, nonce) 且 nonce 来自分区项字段
# 收集所有候选 nonce
for nm, real, sz, st, f4c, f58, blob in zero_parts:
    ks = blob[st:st + 16]
    cands = {
        'f4c(12B)': f4c,
        'f58(4B)': struct.pack('<I', f58),
        'f58_be': struct.pack('>I', f58),
        'real(addr4)': struct.pack('<I', real & 0xffffffff),
        'st(off3)': struct.pack('<I', st)[:3],
        'sz(4B)': struct.pack('<I', sz),
        'zero': bytes(16),
        'idx': None,
    }
    print(f'  {nm}: keystream[:16]={ks.hex()}')
    for k, v in cands.items():
        if v:
            print(f'     {k:12} = {v.hex()}')

print()
print('=== 用 Crypto 尝试:若 keystream_i = AES_ECB(key, X) 且 X 已知,穷举常见 key ===')
# 对 lens_hist,keystream[0:16] = AES(key, block)  其中 block 未知(可能是 0 或 nonce)
tgt = zero_parts[[x[0] for x in zero_parts].index('lens_hist')][6]
tgt = tgt[0:16]
print(f'  lens_hist keystream[0:16] = {tgt.hex()}')
keys = {
    'zeros16': b'\x00' * 16, 'zeros32': b'\x00' * 32,
    'ff16': b'\xff' * 16, 'ff32': b'\xff' * 32,
    'sha256(MC8223X)': hashlib.sha256(b'MC8223X').digest(),
    'sha256(MC8223)': hashlib.sha256(b'MC8223').digest(),
    'sha256(panasonic)': hashlib.sha256(b'panasonic').digest(),
    'sha256(lens_hist)': hashlib.sha256(b'lens_hist').digest(),
    'sha256(MC8223X+lens_hist)': hashlib.sha256(b'MC8223X' + b'lens_hist').digest(),
    'sha256(lens_hist+MC8223X)': hashlib.sha256(b'lens_hist' + b'MC8223X').digest(),
    'md5(MC8223X)': hashlib.md5(b'MC8223X').digest(),
    'sha1(MC8223X)': hashlib.sha1(b'MC8223X').digest(),
    'ascii_MC8223Xpad': b'MC8223X'.ljust(16, b'\x00'),
    'ascii_MC8223Xpad32': b'MC8223X'.ljust(32, b'\x00'),
    'UPD header first16': d[:16],
    'UPD 0x0C:0x1C': d[0x0C:0x1C],
    'UPD 0x1C:0x2C': d[0x1C:0x2C],
    'UPD 0x2C:0x3C': d[0x2C:0x3C],
}
blocks = {
    'zeros': bytes(16), 'zeros32': bytes(32),
    'MC8223Xpad16': b'MC8223X'.ljust(16, b'\x00'),
    'lens_histpad16': b'lens_hist'.ljust(16, b'\x00'),
}
for kn, k in keys.items():
    for kl in (16, 24, 32):
        if len(k) < kl:
            continue
        kk = k[:kl]
        for bn, blk in blocks.items():
            try:
                if AES.new(kk, AES.MODE_ECB).encrypt(blk[:16]) == tgt:
                    print(f'  !!!!! MATCH key={kn} blk={bn}')
            except Exception:
                pass
print('  (无输出=未匹配)')
