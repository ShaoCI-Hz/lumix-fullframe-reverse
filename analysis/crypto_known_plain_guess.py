import struct, hashlib, sys, traceback

d = open('firmware/S5m2XV27.bin', 'rb').read()
N = len(d)
BASE = 0x200
STEP = 0x5C

recs = {}
for i in range(58):
    o = 0x2DC + i * STEP
    nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
    if not nm:
        continue
    sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
    want = d[o + 0x2C:o + 0x2C + 32]
    recs[nm] = dict(idx=i, off=BASE + off, sz=sz, flg=flg, want=want)


def gen_patterns(n):
    """生成常见明文候选模式"""
    pats = {}
    pats['zeros'] = bytes(n)
    pats['ones'] = b'\xff' * n
    pats['inc'] = bytes(i & 0xFF for i in range(n))
    pats['dec'] = bytes((0xFF - i) & 0xFF for i in range(n))
    pats['seq16le'] = b''.join((i & 0xFFFF).to_bytes(2, 'little') for i in range(n // 2))
    pats['seq16be'] = b''.join((i & 0xFFFF).to_bytes(2, 'big') for i in range(n // 2))
    pats['seq32le'] = b''.join((i & 0xFFFFFFFF).to_bytes(4, 'little') for i in range(n // 4))
    pats['seq32be'] = b''.join((i & 0xFFFFFFFF).to_bytes(4, 'big') for i in range(n // 4))
    pats['space'] = b' ' * n
    pats['ascii0'] = b'0' * n
    pats['nul_ff_alt'] = (b'\x00\xff' * (n // 2))
    pats['ff00_alt'] = (b'\xff\x00' * (n // 2))
    return pats


try:
    print('=== 用摘要验证猜测的明文(已知明文攻击)===')
    print(f'{"partition":13} {"size":>10} {"flg":>3}  摘要匹配的明文模式')
    any_hit = False
    for nm, a in recs.items():
        sz, want = a['sz'], a['want']
        if sz == 0 or a['off'] + sz > N:
            continue
        pats = gen_patterns(sz)
        hits = []
        for pname, pdata in pats.items():
            if len(pdata) != sz:
                continue
            if hashlib.sha256(pdata).digest() == want:
                hits.append(pname)
        # 也测"非零前缀 + 零填充"(常见:数据 + 填充)
        # 以及"重复块"
        if not hits:
            # 测 4/64 字节重复模式
            for unit in (4, 8, 16, 64, 512):
                for fill in (b'\x00', b'\xff'):
                    pat = (fill * unit) * (sz // unit)
                    if len(pat) == sz and hashlib.sha256(pat).digest() == want:
                        hits.append(f'rep{unit}x{fill.hex()}')
        if hits:
            any_hit = True
            print(f'{nm:13} {sz:>10,} {a["flg"]:>3}  !!! {hits}')

    print()
    print('=== 特殊:按"数据区起始 + 零填充"结构测(前缀区全零)===')
    # 对每个分区:镜像中数据区前的部分是零(plaintext 零),后面是密文
    # 若明文 = "零 + X",而镜像是"零 + 密文",则 X 的 SHA 未知
    # 但若明文全零(整个分区),摘要 = sha256(zeros)
    for nm, a in recs.items():
        sz, want = a['sz'], a['want']
        if sz == 0 or a['off'] + sz > N:
            continue
        z = hashlib.sha256(bytes(sz)).digest()
        if z == want:
            print(f'  {nm:13} 明文=全零 (摘要=sha256(zeros))')

    print()
    if not any_hit:
        print('常见明文模式未命中。')
    print()
    print('=== 反向思考:检查 UPD 头/分区表自身是否被"加密分区"覆盖 ===')
    print('  分区表中记录的 offset 是否可能不是文件偏移?')
    # 用 boot 的已知位置验证
    for nm in ['boot', 'program', 'loader1']:
        a = recs[nm]
        print(f'  {nm:10} off={a["off"]:>11,} sz={a["sz"]:>10,} 末端={a["off"]+a["sz"]:>11,}  (N={N:,})')
    print()
    print('  boot 末端 vs 文件末尾:')
    b = recs['boot']
    print(f'    BASE+off+sz = 0x{b["off"]+b["sz"]:X} = {b["off"]+b["sz"]:,}')
    print(f'    N           = 0x{N:X} = {N:,}')
    print(f'    diff        = {N - (b["off"]+b["sz"]):,}')
    print('  若 diff=0 => 基准 BASE=0x200 正确(boot 紧贴末尾)')
    # 试 BASE=0
    o = 0x2DC + recs['boot']['idx'] * STEP
    bsz, boff = struct.unpack_from('<II', d, o + 0x04)
    print(f'  (boot 项 +0x04={bsz} +0x08={boff})')
    print(f'    BASE=0   : 0x{boff}+0x{bsz} = 0x{boff+bsz:X}  diff_N = {N-(boff+bsz):,}')
    print(f'    BASE=0x200: 0x{0x200+boff}+0x{bsz} = 0x{0x200+boff+bsz:X}  diff_N = {N-(0x200+boff+bsz):,}')

except Exception:
    traceback.print_exc()
    sys.exit(1)
