import os
import re
import struct

FW = r'firmware'
p = os.path.join(FW, '4001V020.plf')
d = open(p, 'rb').read()
n = len(d)

print('=== 瑙ｆ瀽 .plf 澶撮儴缁撴瀯(鎵炬琛?/ 鍔犺浇鍦板潃)===')
print(f'  "LENS-UPDATE-FILE-SOF:"  @0x0  (21 瀛楄妭)')
print(f'  澶撮儴鍖?0x15..0x60 閫愬瓧娈?')
for k in range(0x15, 0x60, 1):
    if k % 8 == 0x15 % 8:
        pass
# 鎸変笉鍚屽搴﹀皾璇曡В鏋?print()
print('--- 瀛楄妭瑙嗗浘 ---')
for k in range(0x15, 0x60, 16):
    seg = d[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    print(f'  {k:04x}  {seg.hex(" ")}  |{asc}|')

print()
print('--- 鎸?U16LE 瑙ｆ瀽 0x15..0x60 ---')
for k in range(0x15, 0x60, 2):
    v = struct.unpack_from('<H', d + bytes(2), k)[0]
    print(f'  +0x{k:02X}: 0x{v:04X} ({v})')

print()
print('=== 鎵?娈佃〃"鍊欓€?杩炵画 (offset,size) 鎴?(addr,size) 瀵?===')
# 娈佃〃閫氬父鍦ㄥご閮?鍊兼槸閫掑鐨勫湴鍧€鎴?offset
hdr = d[:0x200]
print('  澶撮儴 0x60..0x200 涓殑 u32(闈為浂):')
for k in range(0x60, 0x200, 4):
    v = struct.unpack_from('<I', d, k)[0]
    if v:
        print(f'    +0x{k:03X}: 0x{v:08X} = {v:,}')

print()
print('=== 鏂囦欢灏鹃儴缁撴瀯(灏鹃儴琛?===')
tail = d[n - 0x400:]
print('  灏鹃儴 0x300 澶勮捣 32 琛?')
for k in range(0, 0x200, 16):
    seg = tail[k:k + 16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
    off = n - 0x400 + k
    print(f'  {off:06X}  {seg.hex(" ")}  |{asc}|')

print()
print('=== 鍏ㄩ儴 LENS-UPDATE / 宸茬煡鏍囪鍑虹幇浣嶇疆 ===')
for pat in (b'LENS-UPDATE-FILE-SOF:', b'LENS-UPDATE-FILE-EOH:', b'HDFLSPPSLFDI',
            b'IDFLSPPSLF', b'CABRIOLET', b'PSLFDH'):
    ps = [m.start() for m in re.finditer(re.escape(pat), d)]
    print(f'  {pat.decode():26} {[hex(x) for x in ps[:6]]}')
