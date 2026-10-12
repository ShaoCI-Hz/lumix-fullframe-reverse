# Cross-Model Firmware Comparison

A side-by-side comparison of six LUMIX full-frame models' firmware, to
understand platform evolution and model differences.

---

## 1. Sample list

| Model | Platform code | Image size | Partitions | Build timestamp (`+0x24`) |
|---|---|---|---|---|
| DC-S1 | `MC892` | 90,226,176 | 53 | `0x12161150` → 12/16 11:50 |
| DC-S1H | `MC893` | 91,012,608 | 53 | `0x02140907` → 02/14 09:07 |
| DC-S5 | `MC801` | 90,238,464 | 48 | `0x07101450` → 07/10 14:50 |
| DC-S5M2 | `MC8223` | 179,207,168 | 58 | `0x02102018` → 02/10 20:18 |
| DC-S5M2X | `MC8223X` | 179,207,168 | 58 | `0x02102019` → 02/10 20:19 |
| DC-S9 | `MC8259` | 172,915,712 | 55 | `0x05132030` → 05/13 20:30 |

**All models**:
- use the UPD container format
- have fully encrypted image data (entropy 8.000)
- carry a 64-byte ECDSA P-256 signature (`+0x220`)

---

## 2. `+0x24` is a BCD build timestamp

The field decodes as BCD into `MM/DD HH:MM`:

```
DC-S5M2   0x02102018 → 02/10 20:18
DC-S5M2X  0x02102019 → 02/10 20:19
```

**S5M2X is only one minute later than S5M2** → they come from the **same build
batch**, with functionality differentiated by the model ID
(`MC8223` vs `MC8223X`). This is direct evidence that models are distinguished
through the firmware itself.

---

## 3. Platform architecture: a full rebuild between two generations

| Feature | Old platform (S1/S1H/S5) | New platform (S5M2/S5M2X/S9) |
|---|---|---|
| Image size | ~90 MB | ~180 MB |
| `zboot` / `dtb` | ✅ present | ❌ absent |
| **`zimage` (Linux kernel)** | ✅ 2.5 MB | ❌ absent |
| **`rootfs1` / `rootfs2`** | ✅ 12 MB + 4 MB | ❌ absent |
| System nature | **embedded Linux** | **RTOS / in-house** |
| `program` | 14–16 MB | **45 MB** |
| `compress_pr` | ❌ | ✅ 16 MB |
| Boot partitions | `postboot1-5`, `dram_sleep` | `boot`, `postboot1_r-5_r` |
| Networking | `hm_d_nw` (one) | `hm_d_nw_1st`~`7th` (seven shards) |
| Image processing | `ipu_*`, `rc_*`, `nr_*` | `dsp_kizu_*`, `raw_kizu_*`, `dsp_eisldc_*` |
| Co-processor | `apu0_code/data_i/e` | ❌ |
| New data areas | — | `kizu_data` `vkizu_data` `lut_data` `lut2_data` `grid_data` `xtk` `pzm_data` |

> The old platform (S1/S1H/S5) runs **Linux**; the S5M2 generation moved to a
> **completely different processing architecture**. That explains the doubling
> from ~90 MB to ~180 MB.

---

## 4. Model-specific partitions (structural clues to feature differences)

| Partition | Models | Probable meaning |
|---|---|---|
| **`mult_fpga`** | **DC-S1H only** | **multi-function FPGA configuration** |
| `lns_fpga` | DC-S1 only | lens FPGA |
| `dsh_adj` | DC-S9 only | model-specific calibration |
| `apu0_*` | S1, S1H | APU co-processor |
| `avchd_info` | S1, S1H | AVCHD recording metadata |
| `wifi2_info` | S5M2, S5M2X | dual wireless modules |
| `lut2_data` | S5M2, S5M2X | second LUT group |
| `grid_data` | S5M2, S5M2X | grid-line data |
| `music` | all except S9 | notification sounds |

### Key observation: **DC-S1H is the only model carrying `mult_fpga`**

`DC-S1H` sits at the top of the LUMIX full-frame range and **uniquely owns the
`mult_fpga` partition**, which neither the S5M2 series nor the S9 has.

> **Inference**: this partition corresponds to an S1H-class FPGA / image
> processing hardware configuration — a **hardware-spec difference** between
> models reflected in the firmware layout.

---

## 5. Partition differences across models

| Partition | S5M2/S5M2X | S9 | Notes |
|---|---|---|---|
| `lut_data` | 2,176 KB | **8,576 KB** | S9 carries 4× the LUT data |
| `lut2_data` | 8,576 KB | ❌ absent | S9 does not use a second LUT group |
| `vkizu_data` | 6,144 KB | **9,216 KB** | larger on S9 |
| `grid_data` | 2,304 KB | ❌ absent | |
| `wifi_info` | 128 KB | **256 KB** | |
| `music` | present | ❌ absent | |

> The S9 merges both LUT areas into a single large partition
> (`lut_data` 8576 KB) and drops partitions such as the notification sounds.
> Note that `lut_data` / `lut2_data` are **logically all zero** in the image
> (see `03-crypto-analysis.md`), meaning LUTs are generated at runtime and the
> firmware contains no actual LUT data.

---

## 6. Reproduction

```bash
# Obtain each model's firmware (see 01-firmware-acquisition.md) into firmware/
python tools/pana_unpack.py firmware/S1H__V28.bin --list
# or use the comparison script
python analysis/body/multi_model_diff.py
```

Analysis focal points:
- `+0x0C` model ID (platform code)
- `+0x24` build timestamp (BCD)
- `+0x220` ECDSA signature
- partition table from `0x2DC` (92 bytes per entry)

---

## 7. Further work

1. Add **DC-S1R / DC-BS1H / DC-S1M2 / DC-S1RM2** samples to complete the full-frame map
2. With historical versions available, run a **same-model version diff** (missing: only the current version is officially offered)
3. The old platform contains `zimage` / `rootfs` — an unencrypted old version would be a useful opening (all current samples are encrypted)
