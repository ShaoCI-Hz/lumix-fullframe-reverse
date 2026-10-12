import os
import struct
import zlib
import lzma
import bz2
import zstandard as zstd

FW = r'firmware'
BASE = 0x200
STEP = 0x5C


def parts_of(fn):
    p = os.path.join(FW, fn)
    d = open(p, 'rb').read()
    n = len(d)
    out = {}
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
        out[nm] = dict(real=BASE + off, size=sz)
    return d, out


def try_all(blob, tag):
    """对 blob 尝试各种解压"""
    ok = False
    # zlib/gzip 各 wbits
    for wb, nm in ((15, 'zlib'), (-15, 'raw-deflate'), (31, 'gzip'), (47, 'gzip-auto')):
        try:
            out = zlib.decompressobj(wb).decompress(blob, 256 << 20)
            if len(out) > 512:
                print(f'    !!! [{tag}] {nm} 解压成功 -> {len(out):,} B')
                print(f'        {out[:48].hex()}')
                # 输出可能的明文
                asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in out[:80])
                print(f'        |{asc}|')
                ok = True
        except Exception:
            pass
    for fmt, flt, nm in [
        (lzma.FORMAT_AUTO, None, 'lzma-auto'),
        (lzma.FORMAT_XZ, None, 'xz'),
        (lzma.FORMAT_ALONE, None, 'lzma-alone'),
        (lzma.FORMAT_RAW, [{'id': lzma.FILTER_LZMA1, 'dict_size': 1 << 23}], 'lzma1'),
        (lzma.FORMAT_RAW, [{'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 23}], 'lzma2'),
        (lzma.FORMAT_RAW, [{'id': lzma.FILTER_LZMA1, 'dict_size': 1 << 16, 'lc': 0, 'lp': 0, 'pb': 0}], 'lzma1-alt'),
    ]:
        try:
            out = lzma.decompress(blob, format=fmt, filters=flt, max_length=256 << 20)
            if len(out) > 512:
                print(f'    !!! [{tag}] {nm} 解压成功 -> {len(out):,} B')
                print(f'        {out[:48].hex()}')
                ok = True
        except Exception:
            pass
    try:
        out = bz2.decompress(blob)
        if len(out) > 512:
            print(f'    !!! [{tag}] bz2 解压成功 -> {len(out):,} B')
            ok = True
    except Exception:
        pass
    try:
        out = zstd.ZstdDecompressor().decompress(blob, max_output_size=256 << 20)
        if len(out) > 512:
            print(f'    !!! [{tag}] zstd 解压成功 -> {len(out):,} B')
            ok = True
    except Exception:
        pass
    if not ok:
        print(f'    [{tag}] 无标准压缩格式匹配')


for fn in ('S1H__V28.bin', 'S5___V29.bin', 'S1___V24.bin', 'S5m2XV27.bin'):
    p = os.path.join(FW, fn)
    if not os.path.exists(p):
        continue
    d, pm = parts_of(fn)
    print(f'########## {fn} ##########')
    for lname in ('loader1', 'loader2', 'loader3'):
        if lname not in pm:
            continue
        real, sz = pm[lname]['real'], pm[lname]['size']
        blob = d[real:real + sz]
        print(f'--- {lname} ({sz:,} B) ---')
        # 尝试多个起点
        for start in (0, 0x04, 0x3F8, 0x400, 0x1000):
            if start >= sz:
                continue
            try_all(blob[start:], f'{lname}@{start:#x}')
        # 也试镜像中 loader2/loader3 前后相邻区域
    print()
