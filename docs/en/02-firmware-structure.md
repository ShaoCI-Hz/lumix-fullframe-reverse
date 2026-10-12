# DC-S5M2X Firmware Structure — Reverse-Engineering the UPD Image Format

Sample: `firmware/S5m2XV27.bin` (Ver.2.7, 179,207,168 B)
Tool: `tools/pana_unpack.py`

---

## 1. Summary

| Item | Finding |
|---|---|
| Image format | Panasonic **UPD** (`magic = "UPD\0"`), model ID `MC8223X` |
| Layout | file header + partition table + data partitions |
| Partition table | starts at `0x2DC`, **92 bytes (`0x5C`) per entry**, **58 entries** |
| Data area | starts at `0x080000` |
| **Encryption state** | **major partitions are encrypted (entropy flat at 8.00)** |
| Partition contiguity | ✅ verified — adjacent partitions abut exactly |

---

## 2. File header

```
offset     field
0x00  u32  magic        = 0x00445055  "UPD\0"
0x04  u32  block_size   = 512
0x08  u32  block_size2  = 512
0x0C  16B  model_id     = "MC8223X" + \0 padding
0x200      "panasonic" marker
0x3C  u32  image_data_size = 179,206,656 (0x0AAE7A00)  total image data size
0x40  u32  checksum     = 0x752E308D                  header checksum
0x2DC      partition table start
0x80000    data partition start
```

**Verification**: `image_data_size = 179,206,656`; the `boot` partition sits at
`179,201,024` with size `5,632`, ending exactly at `179,206,656` — a perfect
match, showing this field and the partition table are self-consistent.

---

## 3. Partition table entry structure (92 bytes)

```
offset   field
+0x00  u32   total image data size (same in every entry)
+0x04  u32   boot partition size   (valid only in the boot entry)
+0x08  u32   boot partition offset (valid only in the boot entry)
+0x0C  u32   checksum type
+0x10  16B   name (ASCII, \0 padded, truncated past 16 bytes, e.g. "compress_pr")
+0x20  u32   partition size
+0x24  u32   partition offset
+0x28  u32   flags: 2 = plaintext/empty, 3 = encrypted
+0x2C  32B   digest (MD5/SHA-256)
```

**End-of-table rule**: `flags` may only be `2` or `3`; the first other value
means the data area has begun and parsing must stop. (Otherwise ciphertext is
misread as partition entries, producing hundreds of junk records.)

**Field-relationship check**:
```
program       off 0x00080000 + size 0x02CC0000 = 0x02D40000
compress_pr   off 0x02D40000                  <- abuts exactly ✓
```
All 58 entries pass the contiguity check with `gap = 0` between neighbours.

---

## 4. Partition inventory

| # | Name | Offset | Size | flags | Entropy | Notes |
|---|---|---|---|---|---|---|
| 0 | `boot` | 179,201,024 | 5,632 | 2 | 0.00 | boot block, plaintext, at the end of the image |
| 1 | `loader1` | 0 | 131,072 | 3 | 7.97 | loader |
| 2-4 | `loader2/3` `storage` | — | 0 | 2 | 0 | empty placeholders |
| 5 | **`program`** | 524,288 | **46,923,776** | 3 | 8.00 | **main program** |
| 6 | `compress_pr` | 47,448,064 | 16,777,216 | 3 | 8.00 | compressed program segment |
| 7-14 | `postboot1_r`~`5_r` | — | 6.5M/8.2M… | 3 | 8.00 | post-boot modules (two groups) |
| 15-22 | `eep_ow_*` `eep_adj` `eep_fix` `eep_act_*` `eep_exp_*` | — | 512B~128K | 3 | 0~8 | EEPROM partitions |
| 23-24 | `history` `lens_hist` | — | 256K/384K | 3/2 | 8.00 | usage history |
| 25 | `music` | 104,595,456 | 3,538,944 | 3 | 8.00 | notification sounds |
| 26-27 | `osdover` `osddata` | — | 16M/18M | 3 | 8.00/6.81 | **UI resources** |
| 28-29 | `wifi_info` `wifi2_info` | — | 128K/256K | 2 | 0 | wireless module (empty) |
| 30 | **`menu_save`** | 143,392,768 | 262,144 | 2 | **0.00** | **menu settings (all zero)** |
| 31-32 | `kizu_data` `vkizu_data` | — | 512K/6M | 2 | 0/1.71 | blemish/correction data |
| 33-38 | `usbcharge` `hm_*` `hr_*` | — | — | 3 | 8.00 | USB / host modules |
| 39-40 | `pzm_data` `xtk` | — | 64K/128K | 3/2 | 0 | |
| 41-42 | **`lut_data`** `lut2_data` | — | 2.1M/8.4M | 2 | **0/1.54** | **LUT data (all zero)** |
| 43-48 | `dsp_*` `raw_kizu_*` | — | 64K×6 | 3 | 0 | DSP correction |
| 49 | `grid_data` | 167,641,088 | 2,359,296 | 2 | 4.42 | grid lines |
| 50-55 | `hm_d_nw_1st`~`6th` | — | 1,441,792×6 | 3 | 8.00 | network modules |
| 56-57 | `hm_d_nw_7th` `mbr_dummy_d` | — | — | 3/2 | — | entries valid but **data not included in the image** |

---

## 5. Encryption — the current core obstacle

| flags | Partitions | Mean entropy | Verdict |
|---|---|---|---|
| `3` | 32 | 5.94 | **encrypted** (`program` `compress_pr` `postboot*` `osd*` `music`, …) |
| `2` | 9 | 1.15 | plaintext/empty (`menu_save` `lut_data` `wifi_info` all zero) |

Basis for the judgement: **entropy sits flat at exactly 8.00**. Compression
algorithms (even maximal zlib/lzma/zstd) typically plateau at 7.6–7.9 and cannot
hold 8.000 steadily across tens of kilobytes. That is the signature of
**encryption**.

Plaintext / low-entropy partitions that remain analysable:
- `eep_fix` (2.73), `hr_d_prog` (3.37), `grid_data` (4.42), `vkizu_data` (1.71), `lut2_data` (1.54)
- `boot` (plaintext, 5,632 B) — **the decryption logic may live here**

---

## 6. Observations on the configuration structure

### How feature configuration is stored

`menu_save` is **all zero** inside the firmware package — meaning menu and
feature switches are written at **runtime**, and the firmware image itself
carries no configuration data. The logic that decides those states lives in
`program`, which is ciphertext, so it is not visible under static analysis.

`lut_data` is all zero and `lut2_data` is low-entropy — paid LUT data is stored
separately and is not part of the firmware package.

### Comparing analysis paths

| Path | Feasibility | Notes |
|---|---|---|
| A. Obtain `program` plaintext | Medium | requires first locating the decryption algorithm and key in `boot`/`loader1` |
| B. **Protocol-layer (PTP) observation** | **High** | no firmware decryption involved; the camera is already in tether mode, PID `2382` |
| C. Modify the image | Very low | constrained by the signature check (`+0x2C`, 32-byte digest) |

**Path B is preferred** — it involves neither keys nor decryption and directly
observes device behaviour; A proceeds in parallel as a deeper line. C is
recorded only for completeness and is limited by the signature guarantee.

---

## 7. Checksum mechanism — `+0x2C` is SHA-256 (solved)

Reverse-engineered from the plaintext partitions, the 32-byte digest at `+0x2C`
is confirmed to be **SHA-256**:

| Partition | Stored digest | Verification | Result |
|---|---|---|---|
| `lut_data` | `7b15c3f99be0c5f9…` | `SHA-256(raw image bytes)` | ✅ **exact match** |
| `boot` | `e3b0c44298fc1c14…` | `SHA-256(strip trailing 0xFF)` = `SHA-256(empty)` | ✅ **match** |
| `menu_save` | `3b874d3ba46c638f…` | all-zero 262,144 B; no candidate algorithm matches | ⚠️ |
| `eep_act_a` | `3bdcb4d0d03318c6…` | all-zero 512 B; no candidate algorithm matches | ⚠️ |

Candidates ruled out: MD5 / SHA-1 / CRC32 / `SHA-256(raw)` / `rstrip(0x00)` /
concatenation of non-zero bytes.

### Key inference (a yardstick for decryption correctness)

When `boot` is entirely `0xFF` (flash-erased state) the digest degenerates to
`SHA-256(empty)` — showing the digest is computed over the **effective content**,
not over the raw bytes in the image.

It follows that **an encrypted partition's digest = `SHA-256(decrypted content)`**.

> This means that after any decryption attempt, computing SHA-256 and comparing
> it against `+0x2C` in the partition table **deterministically verifies whether
> the decryption was correct** — no guessing, a clear pass/fail criterion.
> This is the core tool for the decryption analysis work that follows.

The digests of `menu_save` / `eep_act_a` match no plaintext candidate; they are
presumed to be hashes of factory-default or decrypted content, still to be
confirmed.

---

## 8. Open questions

1. Encryption algorithm and key source: `boot` (5,632 B) and `loader1` (flags=3, entropy 7.97) are the primary targets
2. What input the `menu_save` / `eep_act_a` digests are computed over
3. The meaning of the checksum-type values at `+0x0C`
4. Whether `loader1` is an encrypted second-stage loader
