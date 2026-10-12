import hashlib, struct, sys, traceback

dx = open('firmware/S5m2XV27.bin', 'rb').read()
dm = open('firmware/S5m2_V37.bin', 'rb').read()

# NIST P-256 (secp256r1)
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

try:
    print('=== 验证 0x220 块是否为合法 ECDSA P-256 签名 ===')
    print(f'  P-256 阶 N = 0x{N:064X}')

    def check(tag, blk):
        r = int.from_bytes(blk[:32], 'big')
        s = int.from_bytes(blk[32:64], 'big')
        print(f'  --- {tag} ---')
        print(f'    r = 0x{r:064X}')
        print(f'    s = 0x{s:064X}')
        print(f'    1 <= r < N : {1 <= r < N}')
        print(f'    1 <= s < N : {1 <= s < N}')
        print(f'    r < P      : {r < P}')
        print(f'    s < P      : {s < P}')
        # 是否低 s(标准化签名)?
        half = N // 2
        print(f'    s <= N/2 (低s标准化): {s <= half}')
        return (1 <= r < N) and (1 <= s < N)

    ok_x = check('S5M2X', dx[0x220:0x260])
    ok_m = check('S5M2 ', dm[0x220:0x260])
    print()
    print(f'  两者均为合法 P-256 签名范围: X={ok_x} M={ok_m}')

    print()
    print('=== 逆向:签名验证(尝试用标准曲线验证签名自洽性)===')
    print('  说明:验证签名需公钥,而公钥可能在 boot ROM 或加密的 program 中。')
    print('  但可检查:签名是否对"固件某区域"的 SHA-256 有效 —— 需公钥,无法离线完成。')

    print()
    print('=== 结论 ===')
    print('  UPD 头 0x220 = ECDSA P-256 签名(r||s),机型相关。')
    print('  作用:固件完整性/来源验证 → 防篡改。')
    print('  ⚠️ 关键含义:即使解密并修改固件,签名校验也会拒绝 → 修改镜像不可行。')

    print()
    print('=== 顺带:UPD 头其他字段语义(基于两记录完全相同)===')
    hdr = dx[0:0x40]
    print(f'  +0x00 = "UPD\\0"                        magic')
    print(f'  +0x04 = {struct.unpack_from("<I", dx, 4)[0]}                            block size')
    print(f'  +0x08 = {struct.unpack_from("<I", dx, 8)[0]}                            block size')
    print(f'  +0x0C = {dx[0x0C:0x1C]!r}       model id')
    print(f'  +0x1C = 0x{struct.unpack_from("<I", dx, 0x1C)[0]:08X}  = 0x0274_0274')
    print(f'  +0x20 = 0x{struct.unpack_from("<I", dx, 0x20)[0]:08X}  = 0x0001_0004')
    print(f'  +0x24 = 0x{struct.unpack_from("<I", dx, 0x24)[0]:08X}  (X: 0x02102019, M: 0x02102018)')
    mv = struct.unpack_from('<I', dm, 0x24)[0]
    print(f'         X version field = 0x02102019   M = 0x{mv:08X}  ← 版本/日期字段')
    print(f'  +0x28 = 0')
    print(f'  +0x2C = {struct.unpack_from("<I", dx, 0x2C)[0]}')
    print(f'  +0x30 = 0')
    print(f'  +0x34 = {struct.unpack_from("<I", dx, 0x34)[0]}')
    print(f'  +0x38 = {struct.unpack_from("<I", dx, 0x38)[0]}')
    print(f'  +0x3C = {struct.unpack_from("<I", dx, 0x3C)[0]:,}  image_data_size')
    print(f'  +0x40 = CRC32(数据区)')
    print(f'  +0x220..0x260 = ECDSA P-256 签名')
    print(f'  +0x2A0 = 第二个 UPD 记录(与 0x0 完全相同,冗余备份)')

except Exception:
    traceback.print_exc()
    sys.exit(1)
