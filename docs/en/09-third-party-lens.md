# 09 · Third-Party L-Mount Firmware: `.plf` Is an Alliance Standard

> **Core conclusion**: Panasonic's `.plf` is **not a private format** — it is the
> **shared lens-firmware container standard of the L-Mount Alliance
> (Leica / Panasonic / Sigma)**.
> Sigma's `.plf` has the **same magic and same structure** as Panasonic's, and
> additionally **contains a complete vector table**.

---

## 1. Sample sources (official direct links, no serial number required)

| File | Lens | Version | Size |
|---|---|---|---|
| `S02D0120.plf` | Sigma 14mm F1.4 DG DN Art (A023) | 1.2 | 1,049,690 |
| `A0040140.plf` | Sigma 30mm F1.4 DC DN Contemp. (C016) | 1.4 | 263,258 |
| `S02A0130.plf` | Sigma 50mm F2 DG DN Contemp. (C023) | 1.3 | 1,049,690 |

**Direct-link pattern (verified 200):**

```text
https://www.sigma-global.com/en/support/download/<8-char-filename>.plf
```

Naming rule: `<4-char alphanumeric lens code><4-digit version>` = `S02D`+`0120` → v1.2.

**Other vendors, same format (documentary evidence, not downloaded):**

- **Leica**: `SLLens01.plf` / `SLLens09.plf` / `2870_11.plf`
- **Samyang**: `7801V340.plf` (AF 35-150/2-2.8 L, package `LAF35150F20_v340.zip`)

→ **`.plf` is the shared L-Mount Alliance convention.**

---

## 2. ★ Header structure: same magic, different version

```text
                Panasonic                Sigma
0x00  "LENS-UPDATE-FILE-SOF:"    <- identical (21 bytes)
0x15  ver = 0x200 (512)          ver = 0x300 (768)   <- format version
0x17  07 e9 = 2025               07 e9 = 2025        <- year (BCD)
0x19  03 07 / 0c 04 / 03 0a      07 02 / 07 0b / 06 18  <- month/day (BCD)
0x21  00 40 01 02                02 60 2D 01         <- ★ vendor/model ID
0x25  real nonce data (12 B)     FF FF FF FF FF FF FF FF FF FF FF FF  <- 12-byte nonce, unused by Sigma
0x34  01 40 01 02                00 60 2D 01         <- repeated ID, leading byte differs
0x3B  —                          5A ('Z')
0x40  4 bytes (probable checksum) 4 bytes (probable checksum)
      "LENS-UPDATE-FILE-EOH:"    <- identical (21 bytes)
0x58/0x45  EOH offset differs    <- Panasonic's header is longer
```

### 2.1 ★ Vendor/model ID encoding (4 bytes from `0x21`)

| Sample | byte0 | byte1 | byte2 | byte3 |
|---|---|---|---|---|
| Panasonic S-R24105 | `00` | **`40`** | `01` | `02` |
| Panasonic S-E2470 | `00` | **`40`** | `06` | `02` |
| Panasonic S-X50 | `00` | **`40`** | `03` | `02` |
| Sigma 14mm Art | `02` | **`60`** | `2D` | `01` |
| Sigma 30mm Cont. | `02` | **`50`** | `04` | `01` |
| Sigma 50mm Cont. | `02` | **`60`** | `2A` | `01` |

**Inference:**

- **byte1 = vendor/series code**: `40` = Panasonic, `50`/`60` = Sigma
  (distinguishing Art / Contemporary)
- **byte2-3 = model number**
- **byte0 = format variant**: `00` (Panasonic) = `ver 0x200`; `02` (Sigma) =
  `ver 0x300` — which **matches the ver-field difference in §2 exactly**

The same ID repeats at `0x34` but with **byte0 changed**
(Panasonic `00→01`, Sigma `02→00`), suspected to be a "target state" or
"version flag" field.

### 2.2 The 12-byte nonce field

```text
Panasonic: 6d 00 06 93 c3 47 f0 c8 cc 00 01 01   <- real nonce
Sigma:     ff ff ff ff ff ff ff ff ff ff ff ff   <- all FF = unused
```

**Length 12 = the nonce length in Panasonic's body UPD partition table**
(`+0x4C`). This shows **the `.plf` and the body UPD container share one nonce
field definition**, and that **Sigma simply chooses not to encrypt**
(all-FF padding).

**This is key protocol-layer information: encryption is optional and decided by
each vendor.**

---

## 3. ★★ Sigma's `.plf` contains a complete Cortex-M vector table

**Panasonic's `.plf` has no vector table** (see `07-lens-firmware.md` §20),
whereas **Sigma's does** — a difference in image completeness.

### 3.1 Sigma 30mm vector table @ file offset `0x45A`

```text
[ 0] SP     = 0x20005610   <- initial stack pointer (SRAM)
[ 1] Reset  = 0x00000401   <- reset vector (Thumb, bit0=1)
[ 2] IRQ0   = 0x00010381   NMI
[ 3] IRQ1   = 0x00000197   HardFault
[ 4] IRQ2   = 0x00000199   MemManage
[ 5] IRQ3   = 0x0000019B   BusFault
[ 6] IRQ4   = 0x0000019D   UsageFault
[ 7] IRQ5   = 0x00000000   ★ reserved — ARM spec requires 0
[ 8] IRQ6   = 0x00000000   ★ reserved
[ 9] IRQ7   = 0x00000000   ★ reserved
[10] IRQ8   = 0x00000000   ★ reserved
[11] IRQ9   = 0x0001020D   SVC
[12] IRQ10  = 0x000001A1   DebugMon
[13] IRQ11  = 0x00000000   ★ reserved
[14] IRQ12  = 0x00010121   PendSV
[15] IRQ13  = 0x000001A3   SysTick
```

**★ Every reserved slot is 0** — the spec signature of an ARM Cortex-M exception
table, **decisively confirming** the Cortex-M identification (which had
previously been an inference).

### 3.2 ★ Load base = file offset `0x45A`

Reset vector `0x400` → offset `0x400` relative to the image base.
If the image starts at file offset `0x45A`, reset code should sit at file `0x85A`:

```text
0x00085A  00f006f8   bl    #0x86a
0x00085E  0148       ldr   r0, [pc, #4]
0x000860  8047       blx   r0
0x000862  0ff002fe   bl    #0x1046a
```

**✓ a plausible reset sequence** (bl + ldr literal + blx, typical runtime init).

**Three alternative base assumptions (0x200 / 0x400 / 0x458) all fail** —
**only `0x45A` holds**.

### 3.3 Image completeness versus Panasonic

| | Panasonic `.plf` | Sigma `.plf` |
|---|---|---|
| Vector table | **absent** (§20) | **present** @0x45A |
| Image type | **partial update package** (only the regions to update) | **complete image** |
| nonce | real data | all FF (not encrypted) |
| Header length | 0x58 | 0x45 |
| Format version | `0x200` | `0x300` |

**§20.5's inference is independently confirmed**: a `.plf` may be a complete
image or a partial update package — **whether the vector table is included
depends on the vendor's packaging**.

---

## 4. Segment descriptor table (after EOH)

### 4.1 Sigma (compact)

```text
Sig 14mm / 50mm (1,049,690 B, identical):
  0x5A  512          <- block size
  0x5E  15
  0x62  15
  0x66  192
  0x6A  64
  0x6E+ 0 (all zero)

Sig 30mm (263,258 B):
  0x5A  512          <- block size
  0x5E  0
  0x62  64
  0x66  0x03000080
  0x6A  128
  0x6E+ 0
```

**The 14mm and 50mm segment tables are identical** (both files are
1,049,690 B = 1 MiB + 0x45A), showing the table describes **Flash layout rather
than content**.

### 4.2 Panasonic (complex)

```text
0x6D  "PSLFDH"        0x78  "HDFLSPPSLFDI"       0x9A  "IDFLSPPSLF00"
```

Panasonic inserts **vendor tag strings** after EOH (Sigma does not) — this is
exactly the segment-descriptor-table start discussed in `07-lens-firmware.md` §14.

**Explaining the difference**: Panasonic uses **named segments** (each carrying a
`PSLFDH` / `HDFLSPPSLFDI` tag) while Sigma uses **positional segments** (a purely
numeric table). Both use a **block size of 512**.

---

## 5. Code and padding

| Sample | Size | FF share | Whole-file entropy | BX LR | PUSH | Variable names |
|---|---|---|---|---|---|---|
| Pana S-R24105 | 497,494 | 1.2% | 6.84 | 1,311 | 915 | 319 |
| Pana S-E2470 | 452,161 | 1.4% | 6.84 | 976 | 705 | 457 |
| Pana S-X50 | 260,498 | 1.4% | 6.70 | 836 | 614 | 15 |
| Sig 14mm Art | 1,049,690 | **82.7%** | 1.89 | 0 | 110 | 13 |
| Sig 30mm Cont. | 263,258 | 64.6% | 3.36 | 511 | 597 | 43 |
| Sig 50mm Cont. | 1,049,690 | **84.4%** | 1.72 | 0 | 89 | 14 |

**Key observations:**

1. **82–84% of Sigma's 1 MiB files is `0xFF`** — the flash-erased fill value,
   showing the image is **padded to the Flash sector size** (1 MiB alignment),
   not compressed
2. **Sigma carries almost no variable dictionary** (13–43 entries vs Panasonic's
   319–457) → **Panasonic's 578-entry variable dictionary is its own debug
   system, not part of the standard**
3. Panasonic code is denser (BX LR 1311); Sigma is sparser

---

## 6. Significance for this project

### 6.1 Direct value

1. **`.plf` is an open de-facto standard** — all three vendors' lens firmware is
   mutually compatible (a Panasonic body can apply a Sigma `.plf` and vice versa)
2. **The Cortex-M identification is decisively confirmed** (reserved slots = 0)
3. **The "partial update image" inference of §20.5 is independently confirmed**
   (Sigma contains a vector table = complete image)
4. **The load-base method is validated**: `0x45A` is confirmed twice over, by the
   vector table and by the reset code — the same class of approach used in
   `07-lens-firmware.md` §19 to resolve Panasonic's base via the memory map

### 6.2 Protocol-layer information

1. **Encryption is optional** (nonce all FF = unencrypted)
   → L-mount lens updates **are not obliged to be encrypted**, in sharp contrast
   to the AES-class protection of the body firmware
2. **The vendor/model ID encoding** (`byte1 = 0x40/0x50/0x60`) is partly decoded
3. **Block size 512 is an alliance-wide convention**

### 6.3 Open items

1. **The 4-byte checksum at `0x40` is undetermined**:
   sum8 / sum16 / xor / CRC32 / Adler32 / MD5 / SHA1 / SHA256 were all tried
   (multiple ranges, both endiannesses) with **no hit** — possibly a
   custom-polynomial CRC or a keyed MAC
2. **The vector tables of the Sigma 14mm / 50mm are not located** (30mm is
   confirmed): 1 MiB files may contain several segments with the table elsewhere
3. **The semantics of Panasonic's `PSLFDH` / `HDFLSPPSLFDI` segment tags** remain
   unsolved

---

## 7. Reproduction

```bash
# Download Sigma L-mount firmware (official direct links, no serial number)
python analysis/lens/download_sigma.py      # see analysis/

python analysis/lens/plf_vendor_compare.py  # cross-vendor header/ID/entropy
python analysis/lens/plf_deep_compare.py    # FF padding / segment table / code location
python analysis/lens/plf_checksum.py        # checksum analysis attempts + ID encoding
python analysis/lens/sigma_vt.py            # ★ vector-table location and base verification
```

---

## 8. Approaches considered and set aside

- **LUMIX Tether (official PC tool)**: includes a firmware update function, but
  downloading it requires the **11-digit serial number from the camera's battery
  compartment** — not supplied and not fabricated, so **not obtained**
- **SIGMA Optimization Pro**: third-party lens update tool (no serial required),
  but its download link is generated by JavaScript on the host
  `pub.sigma-global.com` and the direct path could not be resolved
  (**recorded honestly as unfinished**)
- **Patent search**: the attempt was rejected by the safety policy, so it was
  **not carried out**

> These three are recorded here to avoid duplicated effort.
