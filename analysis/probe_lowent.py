import struct, hashlib, math, sys, traceback
from collections import Counter

d = open('firmware/S5m2XV27.bin', 'rb').read()
N = len(d)
BASE = 0x200


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def sha(b):
    return hashlib.sha256(b).digest()


targets = ['vkizu_data', 'lut2_data', 'grid_data', 'eep_fix',
           'hr_d_prog', 'osddata', 'lens_hist', 'menu_save', 'lut_data']

try:
    print(f'{"name":12} {"off(real)":>11} {"size":>9} {"entropy":>7} {"nonzero":>9}  match')
    info = {}
    for i in range(58):
        o = 0x2DC + i * 0x5C
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if nm not in targets:
            continue
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        want = d[o + 0x2C:o + 0x2C + 32]
        real = BASE + off
        if real + sz > N:
            print(f'{nm:12} out-of-range (real=0x{real:X})')
            continue
        b = d[real:real + sz]
        if sha(b) == want:
            match = 'raw'
        elif sha(b.rstrip(b'\xff')) == want:
            match = 'stripFF'
        elif sha(b.rstrip(b'\x00')) == want:
            match = 'strip00'
        else:
            match = 'NO'
        nz = sum(1 for x in b if x)
        print(f'{nm:12} {real:>11,} {sz:>9,} {ent(b):>7.3f} {nz:>9,}  {match}')
        info[nm] = (real, sz, want.hex(), b)
    print()
    print('=== head 48 bytes (correct offset) ===')
    for nm in ['vkizu_data', 'lut2_data', 'grid_data', 'eep_fix', 'hr_d_prog']:
        if nm in info:
            real, sz, want, b = info[nm]
            print(f'{nm}: {b[:48].hex(" ")}')
    print()
    print('=== 摘要是否 = SHA-256(全零N) (即逻辑内容为空) ===')
    for nm, (real, sz, want, b) in info.items():
        z = sha(bytes(sz))
        print(f'  {nm:12} want={want[:16]}...  sha256(zeros)={z.hex()[:16]}...  {"MATCH=空内容" if z==want else ""}')
except Exception:
    traceback.print_exc()
    sys.exit(1)
