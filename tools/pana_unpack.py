#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pana_unpack.py - Panasonic LUMIX UPD 固件镜像解包工具 (DC-S5M2X)

针对 S5m2XV27.bin 等 Panasonic "UPD" 格式固件镜像:
  - 解析 UPD 文件头与机型标识
  - 解析 92 字节定长分区表
  - 列出 / 提取各分区
  - 输出 JSON 布局
  - 分区熵分析(判断是否加密)

用法:
  python tools/pana_unpack.py firmware/S5m2XV27.bin --list
  python tools/pana_unpack.py firmware/S5m2XV27.bin --extract program --out-dir work/parts
  python tools/pana_unpack.py firmware/S5m2XV27.bin --extract-all --out-dir work/parts
  python tools/pana_unpack.py firmware/S5m2XV27.bin --json work/layout.json

镜像布局(已验证):
  0x0000  UPD 文件头 (magic "UPD\\0")
  0x0200  "panasonic" 标识
  0x02DC  分区表,每项 92 (0x5C) 字节,名字在项内 +0x10
          项内字段:
            +0x00  镜像总数据大小 (所有项相同)
            +0x04  boot 分区大小 (仅 boot 项有效)
            +0x08  boot 分区偏移 (仅 boot 项有效)
            +0x0C  校验类型
            +0x10  name[16]
            +0x20  分区大小
            +0x24  分区偏移
            +0x28  标志 (2=明文/空, 3=加密)
            +0x2C  32 字节摘要 (MD5/SHA)
  0x080000  数据分区起始 (program)

注:flags=3 的分区熵恒为 8.00,即**数据区加密**,提取出的是密文。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import struct
import sys
from collections import Counter
from dataclasses import dataclass, asdict

MAGIC = b"UPD\x00"
TABLE_BASE = 0x2DC
ENTRY_SIZE = 0x5C
NAME_OFF = 0x10
NAME_LEN = 16


@dataclass
class Partition:
    index: int
    name: str
    offset: int
    size: int
    flags: int
    check_type: int
    digest_hex: str
    entropy: float = 0.0
    encrypted_hint: bool = False


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


class UpdImage:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        with open(path, "rb") as f:
            self.data = f.read()
        self.size = len(self.data)
        self.parts: list[Partition] = []
        self._parse()

    # ------------------------------------------------------------------
    def _parse(self):
        d = self.data
        if d[:4] != MAGIC:
            raise ValueError(f"不是 UPD 镜像 (magic={d[:4]!r}, 期望 {MAGIC!r})")
        self.block_size = struct.unpack_from("<I", d, 4)[0]
        self.block_size2 = struct.unpack_from("<I", d, 8)[0]
        self.model_id = d[0x0C:0x1C].split(b"\x00")[0].decode("ascii", "replace")

        # 文件头 +0x3C 记录镜像总数据大小
        self.image_data_size = struct.unpack_from("<I", d, 0x3C)[0]
        self.header_checksum = struct.unpack_from("<I", d, 0x40)[0]

        # 分区表:有效项的 flags 仅为 2 或 3,且偏移/大小落在镜像内。
        # 越过表尾后会读到数据区,必须在此终止,否则会把密文误当成分区项。
        for i in range(512):
            o = TABLE_BASE + i * ENTRY_SIZE
            if o + ENTRY_SIZE > self.size:
                break
            raw = d[o + NAME_OFF:o + NAME_OFF + NAME_LEN]
            name = raw.split(b"\x00")[0].decode("ascii", "replace")
            if not name or not all(32 <= c < 127 for c in name.encode("ascii", "replace")):
                break

            check_type = struct.unpack_from("<I", d, o + 0x0C)[0]
            p_size, p_off, flags = struct.unpack_from("<III", d, o + 0x20)
            digest = d[o + 0x2C:o + 0x4C]

            # boot 项用 +0x04/+0x08 记录位置
            if name == "boot" and p_size == 0:
                p_size = struct.unpack_from("<I", d, o + 0x04)[0]
                p_off = struct.unpack_from("<I", d, o + 0x08)[0]

            # 表尾判定:flags 只允许 2/3。越界项是合法的(数据未包含在镜像内),
            # 予以保留但标记;只有 flags 非法才代表读到了数据区。
            if flags not in (2, 3):
                break

            self.parts.append(Partition(
                index=i, name=name, offset=p_off, size=p_size,
                flags=flags, check_type=check_type,
                digest_hex=digest.hex(),
            ))

    # ------------------------------------------------------------------
    def analyze(self, deep=False):
        """为各分区计算熵,标记疑似加密"""
        for p in self.parts:
            if p.size == 0 or p.offset + p.size > self.size:
                continue
            blob = self.data[p.offset:p.offset + p.size]
            if deep or p.size <= 8 * 1024 * 1024:
                p.entropy = round(entropy(blob), 3)
            else:
                # 大分区只采样头/中/尾各 1MB
                samples = (blob[:1024 * 1024],
                           blob[len(blob) // 2: len(blob) // 2 + 1024 * 1024],
                           blob[-1024 * 1024:])
                p.entropy = round(entropy(b"".join(samples)), 3)
            p.encrypted_hint = p.entropy >= 7.5

    def get(self, name: str) -> Partition | None:
        for p in self.parts:
            if p.name == name:
                return p
        return None

    def extract(self, p: Partition, out_dir: str) -> str:
        os.makedirs(out_dir, exist_ok=True)
        blob = self.data[p.offset:p.offset + p.size]
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in p.name)
        out = os.path.join(out_dir, f"{p.index:03d}_{safe}_{p.offset:08x}.bin")
        with open(out, "wb") as f:
            f.write(blob)
        return out


# ----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Panasonic UPD 固件解包工具")
    ap.add_argument("image", help="UPD 镜像路径 (.bin)")
    ap.add_argument("--list", action="store_true", help="列出分区")
    ap.add_argument("--extract", metavar="NAME", help="提取指定分区")
    ap.add_argument("--extract-all", action="store_true", help="提取全部分区")
    ap.add_argument("--out-dir", default="work/parts", help="输出目录")
    ap.add_argument("--json", help="输出 JSON 布局")
    ap.add_argument("--deep", action="store_true", help="对大分区也做完整熵分析(慢)")
    args = ap.parse_args()

    if not os.path.isfile(args.image):
        print(f"[!] 文件不存在: {args.image}", file=sys.stderr)
        sys.exit(1)

    img = UpdImage(args.image)

    print(f"[*] 镜像: {img.path}")
    print(f"[*] 大小: {img.size:,} B ({img.size / 1024 / 1024:.2f} MiB)")
    print(f"[*] magic: {MAGIC!r}   block_size={img.block_size} / {img.block_size2}")
    print(f"[*] 机型标识: {img.model_id!r}")
    print(f"[*] 镜像数据大小: {img.image_data_size:,} B (0x{img.image_data_size:X})")
    print(f"[*] 头部校验值: 0x{img.header_checksum:08X}")
    print(f"[*] 分区数: {len(img.parts)}")
    print()

    img.analyze(deep=args.deep)

    if args.list or not (args.extract or args.extract_all or args.json):
        print(f"{'#':>3} {'name':14} {'offset':>12} {'size':>12} {'end':>12} {'flg':>4} {'熵':>6}  {'':2}")
        for p in img.parts:
            flag = ""
            if p.size and p.offset + p.size > img.size:
                flag = "越界"
            elif p.encrypted_hint:
                flag = "加密?"
            elif p.size == 0:
                flag = "空"
            print(f"{p.index:>3} {p.name:14} {p.offset:>12,} {p.size:>12,} "
                  f"{p.offset + p.size:>12,} {p.flags:>4} {p.entropy:>6.2f}  {flag}")
        print()

    if args.extract:
        p = img.get(args.extract)
        if not p:
            print(f"[!] 未找到分区: {args.extract}", file=sys.stderr)
            sys.exit(1)
        out = img.extract(p, args.out_dir)
        print(f"[+] 已提取 {p.name} -> {out}  ({p.size:,} B, sha256={hashlib.sha256(open(out,'rb').read()).hexdigest()[:24]}...)")

    if args.extract_all:
        for p in img.parts:
            if p.size and p.offset + p.size <= img.size:
                out = img.extract(p, args.out_dir)
                print(f"[+] {p.name:14} -> {os.path.basename(out)}  ({p.size:,} B)")

    if args.json:
        payload = {
            "image": img.path,
            "image_size": img.size,
            "model_id": img.model_id,
            "block_size": img.block_size,
            "image_data_size": img.image_data_size,
            "header_checksum": f"0x{img.header_checksum:08X}",
            "partitions": [asdict(p) for p in img.parts],
        }
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"[*] JSON 布局已写入 {args.json}")


if __name__ == "__main__":
    main()
