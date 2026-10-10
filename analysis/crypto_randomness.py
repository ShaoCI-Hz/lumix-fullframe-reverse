import struct, hashlib, math, sys, traceback
from collections import Counter

d = open('firmware/S5m2XV27.bin', 'rb').read()
N = len(d)
BASE = 0x200

# lens_hist keystream(明文全零)
KS = d[0x6360200:0x6360200 + 393216]

try:
    print('=== 1) keystream 随机性检测(判定强加密 vs 弱 PRNG)===')
    n = len(KS)
    c = Counter(KS)
    e = -sum((v / n) * math.log2(v / n) for v in c.values())
    print(f'  长度={n:,}  熵={e:.6f}  (8.0=完美随机)')
    print(f'  字节值种类={len(c)}/256  最少={c.most_common()[-1]}  最多={c.most_common(1)[0]}')

    # 卡方检验
    exp = n / 256
    chi = sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))
    print(f'  卡方={chi:.1f}  (期望≈255, 接受区间约 200~310)')

    # 自相关(找周期)
    def autocorr(data, max_lag=4096, step=1):
        res = []
        n_ = len(data)
        sample = data[:min(n_, 65536)]
        for lag in range(1, max_lag + 1, step):
            a = sample[:-lag]
            b = sample[lag:]
            if not a:
                break
            # 快速估计:比较字节相等的比例
            eq = sum(1 for x, y in zip(a, b) if x == y)
            if eq > len(a) * 0.01:
                res.append((lag, eq / len(a)))
        return res

    hits = autocorr(KS, 512)
    print(f'  自相关(相等率>1%的 lag)= {hits[:10] if hits else "无"}')
    print(f'  (相等率≈0.39% 为随机;若某 lag 明显高 => 存在周期)')

    # 块重复
    blocks16 = [KS[i * 16:(i + 1) * 16] for i in range(n // 16)]
    dup = len(blocks16) - len(set(blocks16))
    print(f'  16B 块: 总={len(blocks16):,} 重复={dup}')

    print()
    print('=== 2) 相邻块 XOR 汉明重量(强加密应集中在 64)===')
    hw = Counter()
    for i in range(0, 2000):
        if (i + 1) * 16 + 16 > n:
            break
        a = KS[i * 16:(i + 1) * 16]
        b = KS[(i + 1) * 16:(i + 2) * 16]
        x = bytes(p ^ q for p, q in zip(a, b))
        hw[bin(int.from_bytes(x, 'big')).count('1')] += 1
    tot = sum(hw.values())
    mean = sum(k * v for k, v in hw.items()) / tot
    print(f'  平均汉明重量={mean:.2f} (128位随机理论值=64)')
    print(f'  分布={dict(sorted(hw.items()))}')

    print()
    print('=== 3) loader1 区域(第一个加载代码)===')
    # loader1: 记录 off,判断真实数据位置
    for i in range(58):
        o = 0x2DC + i * 0x5C
        nm = d[o + 16:o + 32].split(b'\x00')[0].decode('ascii', 'replace')
        if nm in ('loader1', 'loader2', 'loader3', 'storage'):
            sz, off, flg = struct.unpack_from('<III', d, o + 0x20)
            print(f'  {nm:10} raw_off=0x{off:X}({off:,}) size={sz:,} flg={flg} real=0x{BASE+off:X}')
    print()
    print('  0x200..0x2100 (UPD头+分区表):')
    print(f'    0x200 "panasonic"?: {d[0x200:0x210].hex()}')
    print('  0x2100 起(密文起点):')
    for off in (0x2100, 0x4000, 0x20000, 0x80000):
        e2 = Counter(d[off:off + 4096])
        ee = -sum((v / 4096) * math.log2(v / 4096) for v in e2.values())
        print(f'    0x{off:06X} ent(4K)={ee:.3f} head={d[off:off+16].hex()}')

    print()
    print('=== 4) 关键:0x200..0x2100 是否有未解析的非零数据(可能含密钥)===')
    region = d[0x200:0x2200]
    # 分区表已知区域 0x2DC..0x2100
    # 0x200..0x2DC 是 "panasonic"+填充, 检查
    print(f'  0x200..0x2DC: {d[0x200:0x2DC].hex(" ")}')
    nonz = [(k + 0x200, x) for k, x in enumerate(d[0x200:0x2200]) if x]
    print(f'  非零字节数={len(nonz)}')

except Exception:
    traceback.print_exc()
    sys.exit(1)
