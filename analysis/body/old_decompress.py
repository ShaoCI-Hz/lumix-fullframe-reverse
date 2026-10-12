import os
import struct
import zlib
import lzma
import bz2
import sys

FW = r'firmware'
BASE = 0x200


def parts_of(path):
    d = open(path, 'rb').read()
    n = len(d)
    out = []
    for i in range(200):
        o = 0x2DC + i * 0x5C
        if o + 0x5C > n:
            break
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if not nm or not all(32 <= c < 127 for c in nm.encode('ascii', 'replace')):
            break
        sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
        if flg not in (2, 3):
            break
        out.append((nm, BASE + off, sz, flg))
    return d, out


TARGETS = ['zimage', 'rootfs1', 'rootfs2', 'dtb', 'zboot', 'loader2', 'loader3',
           'hm_d_nw', 'hm_d_nw_sng', 'apu0_code_i', 'ipu_code', 'program']

for fn in ('S1H__V28.bin', 'S5___V29.bin'):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        continue
    d, parts = parts_of(p)
    pm = {nm: (real, sz, flg) for nm, real, sz, flg in parts}
    print(f'===== {fn} =====')
    for t in TARGETS:
        if t not in pm:
            continue
        real, sz, flg = pm[t]
        if real + sz > len(d):
            print(f'  {t:12} 越界'); continue
        b = d[real:real + sz]
        print(f'--- {t} (real=0x{real:X} size={sz:,} flg={flg}) ---')
        print(f'    head32: {b[:32].hex()}')
        if t in ('loader2', 'loader3', 'dtb', 'zboot'):
            # dump 明文结构
            for k in range(0, min(160, len(b)), 32):
                seg = b[k:k + 32]
                asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in seg)
                print(f'      +0x{k:04X}  {seg.hex(" ")}  |{asc}|')
        # 解压测试
        done = False
        for wb, tag in ((31, 'gzip'), (15, 'zlib'), (-15, 'raw-deflate'), (47, 'gzip-auto')):
            try:
                out = zlib.decompressobj(wb).decompress(b, 64 << 20)
                if len(out) > 1024:
                    print(f'    !!! {tag} 解压成功 -> {len(out):,} B')
                    print(f'        {out[:32].hex()}')
                    done = True
                    break
            except Exception:
                pass
        if not done:
            for fmt, filters, tag in [
                (lzma.FORMAT_AUTO, None, 'lzma-auto'),
                (lzma.FORMAT_XZ, None, 'xz'),
                (lzma.FORMAT_ALONE, None, 'lzma-alone'),
                (lzma.FORMAT_RAW, [{'id': lzma.FILTER_LZMA1, 'dict_size': 1 << 23}], 'lzma1-raw'),
                (lzma.FORMAT_RAW, [{'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 23}], 'lzma2-raw'),
            ]:
                try:
                    out = lzma.decompress(b, format=fmt, filters=filters, max_length=64 << 20)
                    if len(out) > 1024:
                        print(f'    !!! {tag} 解压成功 -> {len(out):,} B')
                        done = True
                        break
                except Exception:
                    pass
        if not done:
            try:
                out = bz2.decompress(b)
                if len(out) > 1024:
                    print(f'    !!! bz2 解压成功 -> {len(out):,} B')
                    done = True
            except Exception:
                pass
        if not done:
            print(f'    (无可识别压缩格式)')
        # zImage ARM 头检测
        for pat, tag in ((b'\x18\x28\x6f\x01', 'ARM zImage(LE)'), (b'\x01\x6f\x28\x18', 'ARM zImage(BE)')):
            pp = b.find(pat)
            if pp >= 0:
                print(f'    ★ {tag} @0x{pp:X}')
        # squashfs / ext / cpio
        for mg, tag in ((b'hsqs', 'squashfs'), (b'070701', 'cpio'), (b'\x53\xef', 'ext-magic')):
            pp = b.find(mg)
            if pp >= 0:
                print(f'    ★ {tag} @0x{pp:X}')
        print()
    print()
