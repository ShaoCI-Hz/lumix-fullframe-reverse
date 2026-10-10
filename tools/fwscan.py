#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fwscan.py - 固件侦察工具 (Panasonic LUMIX S5M2X 逆向工程)

对一个二进制文件做无侵入侦察,产出可用于逆向的结构化情报:
  1. 基本信息与哈希
  2. 文件头 hexdump
  3. magic / 已知格式签名扫描
  4. 滑动窗口熵分析 + 自动区域分段
  5. 压缩流探测 (zlib/gzip/lzma/bz2/lz4/zstd)
  6. 文件系统签名探测
  7. ARM 向量表 / ELF / PE 探测
  8. 可选:字符串提取、按区域导出

用法:
  python tools/fwscan.py <firmware.bin>
  python tools/fwscan.py <firmware.bin> --window 2048 --json report.json
  python tools/fwscan.py <firmware.bin> --strings --extract-dir work/extracted
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Optional

# --------------------------------------------------------------------------
# 签名表
# --------------------------------------------------------------------------

# (名称, 偏移或 None 表示任意, bytes/magic, 说明)
# 文件系统签名:(名称, magic, 说明, 验证函数名或 None)
# 短 magic 必须配上下文验证,否则在高熵数据中误报会淹没真信号。
FILESYSTEM_SIGNATURES = [
    ("squashfs", b"hsqs", "SquashFS (小端)", None),
    ("squashfs", b"sqsh", "SquashFS (大端)", None),
    ("cramfs", b"\x45\x3d\xcd\x28", "cRAMFS", None),
    ("romfs", b"-rom1fs-", "romfs", None),
    ("jffs2", b"\x85\x19", "JFFS2 (0x1985)", "verify_jffs2"),
    ("ubifs", b"\x31\x18\x10\x06", "UBIFS", None),
    ("ext2/3/4", b"\x53\xef", "ext superblock @0x438", "verify_ext"),
    ("erofs", b"\xe0\xf5\xe1\xe2", "EROFS", None),
    ("fat", b"\x55\xaa", "FAT boot sector 尾标记", "verify_fat"),
    ("cpio", b"070701", "ASCII cpio (newc)", "verify_cpio_newc"),
    ("cpio", b"\xc7\x71", "binary cpio", "verify_cpio_bin"),
]

COMPRESSION_SIGNATURES = [
    ("gzip", b"\x1f\x8b\x08", None),
    ("bzip2", b"BZh", None),
    ("xz", b"\xfd7zXZ\x00", None),
    ("lz4", b"\x04\x22\x4d\x18", None),
    ("zstd", b"\x28\xb5\x2f\xfd", None),
    ("lzo", b"\x89LZO\x00", None),
    ("snappy", b"\xff\x06\x00\x00sNaPpY", None),
    ("sevenzip", b"7z\xbc\xaf\x27\x1c", None),
    ("zip", b"PK\x03\x04", None),
    ("rar", b"Rar!\x1a\x07", None),
]

FORMAT_SIGNATURES = [
    ("ELF", b"\x7fELF", "可执行/可链接格式 (Linux 固件常见)", None),
    ("PE/COFF", b"MZ", "Windows PE (符号工具/服务模式)", "verify_pe"),
    ("uImage", b"\x27\x05\x19\x56", "U-Boot uImage", None),
    ("DTB", b"\xd0\x0d\xfe\xed", "Flattened Device Tree Blob", None),
    ("Java class", b"\xca\xfe\xba\xbe", "Java class (App 资源)", None),
    ("PNG", b"\x89PNG\r\n\x1a\n", "PNG 图像", None),
    ("JPEG", b"\xff\xd8\xff", "JPEG 图像", None),
    ("RIFF", b"RIFF", "RIFF 容器", None),
    ("SQLite", b"SQLite format 3\x00", "SQLite 库", None),
    ("pax/GNU tar", b"ustar", "TAR 归档", None),
]

# Panasonic 相关 magic(初步;拿到样本后按实际格式补充)
PANASONIC_SIGNATURES = [
    ("PANA ascii", b"PANA", "'PANA' ASCII", None),
    ("LUMIX", b"LUMIX", "'LUMIX' ASCII", None),
    ("Panasonic", b"Panasonic", "'Panasonic' ASCII", None),
    ("DC-S5", b"DC-S5", "机型标识", None),
    ("DMC", b"DMC-", "机型标识 (LUMIX 旧款)", None),
]


# --------------------------------------------------------------------------
# 上下文验证(压制短 magic 误报)
# --------------------------------------------------------------------------

def verify_jffs2(data: bytes, off: int) -> bool:
    """JFFS2 node header: magic(2) nodetype(2) totlen(4) hdr_crc(4)"""
    if off + 12 > len(data):
        return False
    nodetype = struct.unpack_from("<H", data, off + 2)[0]
    totlen = struct.unpack_from("<I", data, off + 4)[0]
    # nodetype 高字节通常为 0x00(目录)/0x20(inode)/0x40(clean)/0x60(dirent)/0xe0(xattr)
    if (nodetype & 0xE000) not in (0x0000, 0x2000, 0x4000, 0x6000, 0xE000):
        return False
    return 12 <= totlen <= 1024 * 1024


def verify_ext(data: bytes, off: int) -> bool:
    """ext superblock magic 须在 0x438,且 block size 字段合理"""
    if off != 0x438:
        return False
    base = off - 56           # s_magic 在 superblock 内偏移 0x38
    if base < 0:
        return False
    log_block_size = struct.unpack_from("<I", data, base + 24)[0]
    return log_block_size <= 6


def verify_fat(data: bytes, off: int) -> bool:
    """0x55AA 须在扇区末尾,且引导扇区前 32 字节为零(JMP 指令后为厂商字符串区)"""
    if off % 512 != 510 or off < 32:
        return False
    return data[off - 32:off] == b"\x00" * 32


def verify_cpio_bin(data: bytes, off: int) -> bool:
    """binary cpio header: magic(2)=0x71c7 ... namesize(2) filesize(4)"""
    if off + 26 > len(data):
        return False
    namesize = struct.unpack_from("<H", data, off + 20)[0]
    filesize = struct.unpack_from("<I", data, off + 22)[0]
    return 1 <= namesize <= 255 and filesize <= 256 * 1024 * 1024


def verify_cpio_newc(data: bytes, off: int) -> bool:
    """newc header: '070701' 后 13 个 8 位八进制字段"""
    if off + 6 + 13 * 8 > len(data):
        return False
    for k in range(13):
        seg = data[off + 6 + k * 8: off + 6 + (k + 1) * 8]
        if not all(48 <= b <= 55 for b in seg):    # '0'..'7'
            return False
    return True


def verify_pe(data: bytes, off: int) -> bool:
    """MZ 头的 e_lfanew 必须指向 'PE\\0\\0'"""
    if off + 0x40 > len(data):
        return False
    e_lfanew = struct.unpack_from("<I", data, off + 0x3C)[0]
    if e_lfanew == 0 or e_lfanew > 1024 or off + e_lfanew + 4 > len(data):
        return False
    return data[off + e_lfanew:off + e_lfanew + 4] == b"PE\x00\x00"


VERIFY_FUNCS = {
    "verify_jffs2": verify_jffs2,
    "verify_ext": verify_ext,
    "verify_fat": verify_fat,
    "verify_cpio_newc": verify_cpio_newc,
    "verify_cpio_bin": verify_cpio_bin,
    "verify_pe": verify_pe,
}


# --------------------------------------------------------------------------
# 工具函数
# --------------------------------------------------------------------------

def entropy(data: bytes) -> float:
    """香农熵 (bits/byte), 0..8"""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {base + off:08x}  {hexpart:<{width * 3}}  |{asciipart}|")
    return "\n".join(lines)


def find_all(hay: bytes, needle: bytes, limit: int = 20):
    out = []
    start = 0
    while len(out) < limit:
        i = hay.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


# --------------------------------------------------------------------------
# 结果结构
# --------------------------------------------------------------------------

@dataclass
class Region:
    offset: int
    length: int
    avg_entropy: float
    kind: str            # 'entropy_high' / 'entropy_low' / 'zero' / 'mixed'
    note: str = ""


@dataclass
class ScanReport:
    path: str
    size: int
    md5: str
    sha256: str
    head_hex: str = ""
    signatures: list = field(default_factory=list)
    compressed: list = field(default_factory=list)
    filesystems: list = field(default_factory=list)
    arm_vector_tables: list = field(default_factory=list)
    regions: list = field(default_factory=list)
    overall_entropy: float = 0.0
    strings_sample: list = field(default_factory=list)


# --------------------------------------------------------------------------
# 各项扫描
# --------------------------------------------------------------------------

def scan_signatures(data: bytes, report: ScanReport):
    """扫描固定 magic,短 magic 需通过上下文验证"""
    hits = []
    # COMPRESSION_SIGNATURES 由 scan_compression 专门处理,此处不扫
    tables = [("PANASONIC", PANASONIC_SIGNATURES),
              ("FORMAT", FORMAT_SIGNATURES),
              ("FILESYSTEM", FILESYSTEM_SIGNATURES)]
    for group, table in tables:
        for name, magic, desc, verifier in table:
            if not magic:
                continue
            for off in find_all(data, magic, limit=8):
                if verifier and not VERIFY_FUNCS[verifier](data, off):
                    continue
                hits.append({
                    "group": group, "name": name, "offset": off,
                    "offset_hex": f"0x{off:x}", "desc": desc,
                })
    hits.sort(key=lambda h: h["offset"])
    report.signatures = hits


def scan_compression(data: bytes, report: ScanReport, verify=True):
    """探测并验证压缩流,估算解压后大小"""
    import zlib

    found = []
    for name, magic, verifier in COMPRESSION_SIGNATURES:
        if not magic:
            continue
        for off in find_all(data, magic, limit=10):
            entry = {"name": name, "offset": off, "offset_hex": f"0x{off:x}",
                     "declared_size": None, "verified": False}
            if verify:
                try:
                    if name == "gzip":
                        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                        out = d.decompress(data[off:off + min(len(data) - off, 16 * 1024 * 1024)])
                        entry["declared_size"] = len(out)
                        entry["verified"] = True
                    elif name == "zstd":
                        import zstandard
                        out = zstandard.ZstdDecompressor().decompress(
                            data[off:off + min(len(data) - off, 64 * 1024 * 1024)],
                            max_output_size=64 * 1024 * 1024)
                        entry["declared_size"] = len(out)
                        entry["verified"] = True
                    elif name == "xz":
                        import lzma
                        out = lzma.decompress(data[off:off + min(len(data) - off, 64 * 1024 * 1024)])
                        entry["declared_size"] = len(out)
                        entry["verified"] = True
                    elif name == "bzip2":
                        import bz2
                        d = bz2.BZ2Decompressor()
                        out = d.decompress(data[off:off + min(len(data) - off, 64 * 1024 * 1024)])
                        entry["declared_size"] = len(out)
                        entry["verified"] = True
                except Exception:
                    pass
            found.append(entry)

    # 逐字节尝试 zlib 头 (CMF/FLG 校验),避免误报
    zlib_hits = []
    i = 0
    while i < len(data) - 2 and len(zlib_hits) < 20:
        cmf, flg = data[i], data[i + 1]
        if (cmf & 0x0F) == 8 and (cmf >> 4) <= 7 and ((cmf << 8) + flg) % 31 == 0:
            wbits = (cmf >> 4) + 8
            try:
                out = zlib.decompressobj(-wbits).decompress(
                    data[i:i + min(len(data) - i, 16 * 1024 * 1024)])
                if len(out) > 256:
                    zlib_hits.append({"name": "zlib", "offset": i,
                                      "offset_hex": f"0x{i:x}",
                                      "declared_size": len(out), "verified": True})
                    i += max(1, len(out) // 64)   # 跳过一段,避免海量重复
                    continue
            except Exception:
                pass
        i += 1
    found.extend(zlib_hits)
    found.sort(key=lambda e: e["offset"])
    report.compressed = found


def scan_arm_vector_tables(data: bytes, report: ScanReport):
    """
    ARM Cortex-M 向量表启发式探测:
      word0 = 初始 MSP,应落在 RAM 区 (0x20000000-0x20040000 / 0x10000000 等)
      word1 = Reset handler,Thumb 位为 1,应落在 flash 区
    这是识别松下 MCU 固件入口的关键线索。
    """
    hits = []
    RAM_RANGES = [(0x10000000, 0x10100000), (0x20000000, 0x20100000),
                  (0x08000000, 0x09000000), (0x38000000, 0x38100000),
                  (0x00200000, 0x00300000)]
    FLASH_RANGES = [(0x00000000, 0x02000000), (0x08000000, 0x0C000000),
                    (0x10000000, 0x14000000), (0x20000000, 0x24000000),
                    (0x00100000, 0x00400000)]

    def in_range(v, ranges):
        return any(a <= v < b for a, b in ranges)

    # 以 4 字节对齐扫描前 4MB 和后 4MB
    scan_regions = [(0, min(len(data), 4 * 1024 * 1024)),
                    (max(0, len(data) - 4 * 1024 * 1024), len(data))]
    seen = set()
    for start, end in scan_regions:
        for off in range(start, end - 32, 4):
            if off in seen:
                continue
            msp, reset = struct.unpack_from("<II", data, off)
            if reset & 1 == 0:
                continue
            # 栈指针要求 8 字节对齐(ARM AAPCS)
            if msp & 0x7:
                continue
            if not in_range(msp, RAM_RANGES):
                continue
            if not in_range(reset & ~1, FLASH_RANGES):
                continue
            # 进一步:看后续向量是否也像 handler,要求至少 3 个可信
            ok = 0
            for k in range(2, 16):
                if off + 4 * (k + 1) > len(data):
                    break
                v = struct.unpack_from("<I", data, off + 4 * k)[0]
                if v == 0 or v == 0xFFFFFFFF:
                    continue
                if v & 1 and in_range(v & ~1, FLASH_RANGES):
                    ok += 1
            if ok >= 3:
                seen.add(off)
                hits.append({"offset": off, "offset_hex": f"0x{off:x}",
                             "initial_sp": f"0x{msp:08x}",
                             "reset_handler": f"0x{reset:08x}",
                             "handlers_plausible": ok})
            if len(hits) >= 12:
                break
        if len(hits) >= 12:
            break
    report.arm_vector_tables = hits


def analyze_regions(data: bytes, report: ScanReport, window: int):
    """滑动窗口熵分析 + 自动分段"""
    n = len(data)
    points = []
    for off in range(0, n, window):
        chunk = data[off:off + window]
        points.append((off, entropy(chunk)))

    if not points:
        return

    # 自动分段:按熵水平聚类成连续区域
    regions = []
    cur_start, cur_vals = points[0][0], [points[0][1]]

    def classify(avg):
        if avg < 0.5:
            return "zero", "填充/空白"
        if avg < 3.0:
            return "entropy_low", "明文/结构化数据(常量、表、文件系统元数据)"
        if avg < 6.0:
            return "entropy_mid", "代码或混合数据"
        return "entropy_high", "压缩/加密/高随机数据"

    prev_class = classify(cur_vals[0])[0]
    for off, e in points[1:]:
        cls, _ = classify(e)
        if cls != prev_class:
            avg = sum(cur_vals) / len(cur_vals)
            kind, note = classify(avg)
            regions.append(Region(cur_start, off - cur_start, round(avg, 3), kind, note))
            cur_start, cur_vals = off, [e]
            prev_class = cls
        else:
            cur_vals.append(e)

    avg = sum(cur_vals) / len(cur_vals)
    kind, note = classify(avg)
    regions.append(Region(cur_start, n - cur_start, round(avg, 3), kind, note))

    # 合并过小片段
    merged = []
    for r in regions:
        if merged and r.length < window * 2 and merged[-1].kind == r.kind:
            merged[-1].length += r.length
        else:
            merged.append(r)
    report.regions = [asdict(r) for r in merged]
    report.overall_entropy = round(entropy(data), 4)


def extract_strings(data: bytes, report: ScanReport, min_len=6, limit=30):
    """提取 ASCII/UTF-16 字符串样本(优先含关键字的)"""
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    keywords = (b"firmware", b"version", b"update", b"error", b"debug",
                b"panasonic", b"lumix", b"V-Log", b"menu", b"function",
                b"serial", b"model", b"DMC", b"DC-S5", b"boot", b"flash")
    hits = []
    for m in pat.finditer(data):
        s = m.group()
        if any(k.lower() in s.lower() for k in keywords):
            hits.append((m.start(), s.decode("ascii", "replace")))
        if len(hits) >= limit:
            break
    report.strings_sample = [{"offset": o, "offset_hex": f"0x{o:x}", "s": s}
                             for o, s in hits]


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def scan(path: str, window: int, do_strings: bool, extract_dir: Optional[str]) -> ScanReport:
    with open(path, "rb") as f:
        data = f.read()

    report = ScanReport(
        path=os.path.abspath(path),
        size=len(data),
        md5=hashlib.md5(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        head_hex=hexdump(data[:256]),
    )

    print(f"[*] 文件: {report.path}")
    print(f"[*] 大小: {report.size:,} bytes ({report.size / 1024 / 1024:.2f} MiB)")
    print(f"[*] MD5   : {report.md5}")
    print(f"[*] SHA256: {report.sha256}")
    print(f"\n[*] 文件头:\n{report.head_hex}\n")

    scan_signatures(data, report)
    scan_compression(data, report)
    scan_arm_vector_tables(data, report)
    analyze_regions(data, report, window)
    if do_strings:
        extract_strings(data, report)

    # 打印
    print(f"[*] 整体熵: {report.overall_entropy} bits/byte")

    print("\n=== 签名命中 ===")
    if not report.signatures:
        print("  (无)")
    for h in report.signatures:
        print(f"  [{h['group']:10}] {h['name']:16} @ {h['offset_hex']:>12}  {h['desc']}")

    print("\n=== 压缩流 ===")
    if not report.compressed:
        print("  (无)")
    for c in report.compressed:
        v = "已验证" if c.get("verified") else "未验证"
        size = c.get("declared_size")
        print(f"  {c['name']:8} @ {c['offset_hex']:>12}  解压后 {size if size is not None else '?':>12} bytes  {v}")

    print("\n=== ARM 向量表候选 ===")
    if not report.arm_vector_tables:
        print("  (无)")
    for a in report.arm_vector_tables:
        print(f"  @ {a['offset_hex']:>12}  SP={a['initial_sp']}  Reset={a['reset_handler']}  可信handler={a['handlers_plausible']}")

    print(f"\n=== 熵分布分段 (窗口 {window} B) ===")
    print(f"  {'起始偏移':>12} {'长度':>12} {'熵':>7}  类型")
    for r in report.regions:
        print(f"  {r['offset']:>12x} {r['length']:>12x} {r['avg_entropy']:>7}  {r['kind']:14} {r['note']}")

    if report.strings_sample:
        print("\n=== 关键字符串样本 ===")
        for s in report.strings_sample[:20]:
            print(f"  {s['offset_hex']:>12}  {s['s'][:100]}")

    if extract_dir:
        os.makedirs(extract_dir, exist_ok=True)
        # 按分段导出
        for i, r in enumerate(report.regions):
            if r["length"] <= 0:
                continue
            blob = data[r["offset"]:r["offset"] + r["length"]]
            out = os.path.join(extract_dir, f"region_{i:03d}_{r['kind']}_{r['offset']:08x}.bin")
            with open(out, "wb") as f:
                f.write(blob)
        # 导出已验证的压缩流
        for i, c in enumerate(report.compressed):
            if not c.get("verified"):
                continue
            out = os.path.join(extract_dir, f"stream_{i:03d}_{c['name']}_{c['offset']:08x}.bin")
            try:
                with open(path, "rb") as f:
                    f.seek(c["offset"])
                    raw = f.read()
                import zlib
                if c["name"] == "gzip":
                    blob = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw)
                elif c["name"] == "zlib":
                    blob = zlib.decompress(raw)
                elif c["name"] == "zstd":
                    import zstandard
                    blob = zstandard.ZstdDecompressor().decompress(raw, max_output_size=512 * 1024 * 1024)
                elif c["name"] == "xz":
                    import lzma
                    blob = lzma.decompress(raw)
                elif c["name"] == "bzip2":
                    import bz2
                    blob = bz2.decompress(raw)
                else:
                    continue
                with open(out, "wb") as f:
                    f.write(blob)
            except Exception:
                pass
        print(f"\n[*] 已导出区域/流到 {extract_dir}")

    return report


def main():
    ap = argparse.ArgumentParser(description="固件侦察工具")
    ap.add_argument("file", help="固件文件路径")
    ap.add_argument("--window", type=int, default=4096, help="熵分析窗口大小 (默认 4096)")
    ap.add_argument("--json", help="输出 JSON 报告路径")
    ap.add_argument("--strings", action="store_true", help="提取关键字符串")
    ap.add_argument("--extract-dir", help="导出区域与已验证压缩流")
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] 文件不存在: {args.file}", file=sys.stderr)
        sys.exit(1)

    report = scan(args.file, args.window, args.strings, args.extract_dir)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, ensure_ascii=False, indent=2)
        print(f"\n[*] JSON 报告已写入 {args.json}")


if __name__ == "__main__":
    main()
