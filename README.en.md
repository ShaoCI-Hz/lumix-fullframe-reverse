# Panasonic LUMIX Full-Frame Firmware Research

English | [简体中文](README.md)

Research notes and tooling for the **container format**, **integrity protection
mechanisms**, and **USB/PTP protocols** of the Panasonic LUMIX full-frame line
(S5M2X / S5M2 / S9 / S1 / S1H / S5) and its L-mount lenses.

> ⚠️ **Disclaimer**
> This project is for **interoperability research and personal study only**.
> The repository contains **no firmware binaries** (copyright Panasonic);
> analysis scripts and documentation only.
> All firmware is obtained from official public channels, and analysis is
> performed against devices the author owns.

---

## Overview

| Area | Result |
|---|---|
| **Firmware acquisition** | Official download path established (direct-link construction & request requirements) |
| **UPD container format** | Fully parsed — file header, partition table, checksums, signature layout |
| **Partition table** | 58 partitions; field semantics and contiguity all verified |
| **Encryption** | Determined to be strong symmetric encryption (cross-checked with 6 models + 21 scripts) |
| **Digital signature** | ECDSA P-256 at `+0x220`, covering the entire image |
| **Plaintext directory table** | `loader2` / `loader3` embed plaintext partition directories (name/addr/size/hash) |
| **Cross-model comparison** | 6 models: platform evolution, build timestamps, model-specific partitions |
| **USB protocol** | WPD/MTP access path established, device capabilities enumerated |
| **Vendor protocol** | MTP vendor extension channel; 3 Panasonic-private opcodes enumerated |
| **Lens firmware** | Fully plaintext + 578-entry variable dictionary + ARM Cortex-M code |
| **Lens disassembly** | 2,096 function fingerprints across 6 models; load base resolved to `0x08000000` |
| **Cross-vendor L-mount** | `.plf` is an L-Mount Alliance standard (shared by Sigma / Leica / Samyang) |

---

## Documentation

Full notes in [`docs/README.md`](docs/README.md), read in order:

| # | Document | Contents |
|---|---|---|
| 01 | [Firmware acquisition](docs/01-firmware-acquisition.md) | Official sources, direct-link construction, request requirements |
| 02 | [Firmware structure](docs/02-firmware-structure.md) | UPD container format, partition-table field semantics |
| 03 | [Encryption analysis](docs/03-crypto-analysis.md) | Algorithm determination, signature mechanism, ruled-out paths |
| 04 | [USB access](docs/04-protocol-usb.md) | WPD/MTP access status and environment setup |
| 05 | [Vendor protocol](docs/05-mtp-vendor-protocol.md) | MTP vendor extension channel and opcode enumeration |
| 06 | [Cross-model comparison](docs/06-multi-model-comparison.md) | 6-model survey and platform evolution |
| 07 | [Lens firmware](docs/07-lens-firmware.md) | Plaintext structure, disassembly methods, cross-model fingerprint clustering (with errata) |
| 09 | [Third-party L-mount](docs/09-third-party-lens.md) | Cross-vendor container standard, Sigma vector table |

---

## Repository layout

```
.
├── README.md              this file (English) · README.md is the Chinese version
├── LICENSE                CC BY-NC 4.0
├── docs/                  research notes (9 documents)
├── tools/                 reusable tools
│   ├── fwscan.py             firmware reconnaissance: entropy / signature / compression scans
│   └── pana_unpack.py        UPD image unpacking: partition listing and extraction
└── analysis/              scripts used during the research (reproducible, 102)
    ├── body/                body firmware: container, crypto, loader, cross-model diffs
    ├── lens/                lens firmware: format, disassembly, fingerprinting, cross-vendor
    └── misc/                other
```

---

## Getting started

```bash
pip install pycryptodome zstandard

# 1) Obtain official firmware (see docs/01-firmware-acquisition.md)
#    Place files in firmware/ (git-ignored, never committed)

# 2) Reconnaissance of a firmware image
python tools/fwscan.py firmware/S5m2XV27.bin --window 65536 --strings

# 3) Unpack a UPD image
python tools/pana_unpack.py firmware/S5m2XV27.bin --list
python tools/pana_unpack.py firmware/S5m2XV27.bin --extract program --out-dir out/

# 4) Lens firmware: fetch third-party L-mount samples (official direct links)
python analysis/lens/download_sigma.py
```

---

## Key findings

### 1. Body UPD container format

```
+0x000  "UPD\0"            magic
+0x004  block size = 512
+0x00C  model ID, 16 bytes ("MC8223X" / "MC8223" / "MC801" …)
+0x03C  image_data_size
+0x040  CRC32(d[0x200:])     <- does NOT cover 0x000-0x1FF
+0x200  "panasonic" marker
+0x220  ECDSA P-256 signature (r||s, 64 bytes)
+0x2A0  second UPD record (identical to +0x000, redundant copy)

Partition table: @0x2DC, 92 bytes each, 58 entries
  entry: name(13B) | address-space tag(3B) | size | offset | flags
         | SHA-256 (32B, plaintext) | nonce (12B)
Data area: 0x200..EOF; partition offsets are relative to 0x200
```

> Note: the model ID at `+0x00C` lies outside the CRC32 coverage.

### 2. Encryption and integrity

```
integrity   = CRC32(0x200..EOF) + per-partition SHA-256
tamper-proof = ECDSA P-256 signature (+0x220) over the whole image
confidentiality = strong symmetric encryption, one key per model per partition

Verification record:
  · 6 models × 21 analysis scripts: all data partitions are ciphertext
    (loader / zimage / rootfs included)
  · plaintext exists only in the metadata layer (partition table /
    loader2 directory table / UPD header / signature)
  · no simple key-derivation relation found — 17,496 combinations exhausted
  · identical plaintext with the same nonce and size yields 100% different
    ciphertext across models
```

**Therefore: this format does not expose plaintext under read-only analysis.**

See [`docs/03-crypto-analysis.md`](docs/03-crypto-analysis.md).

### 3. USB / PTP protocol layer

Three vendor-private opcodes enumerated via
`WPD_CATEGORY_MTP_EXT_VENDOR_OPERATIONS`:

```
0x9102   0x9103   0x9104
```

`0x9102` executes successfully and establishes a transfer context. See
[`docs/05-mtp-vendor-protocol.md`](docs/05-mtp-vendor-protocol.md).

### 4. Lens firmware (`.plf`)

Unlike the body firmware, **lens firmware is plaintext** (whole-file entropy
6.4–7.0, not encrypted) and can be analysed directly:

```
container: "LENS-UPDATE-FILE-SOF:" + header fields
           + "LENS-UPDATE-FILE-EOH:" + segment descriptor table
           (EOH = End Of *Header*; block size 512 / 256)
code:      full ARM Cortex-M Thumb
           6 models -> 2,096 unique function fingerprints, base 0x08000000
vars:      578 entries (name + type/index) — no address fields,
           pure debug metadata
```

**Cross-model fingerprinting** (address-independent: immediates normalised
away, then SHA-1):

```
2,096 unique fingerprints across 6 models
  shared by all 6   :   17   <- compiler runtime (e.g. __aeabi_fdiv)
  shared by 4       :  207
  single model only : 1,540  <- model-specific
  all zoom models   :  245
  zoom-only         :   20   <- candidate business logic (command handlers)
```

**Methodological observation**: the code that is most consistent across models
is compiler-generated library code. Business logic must be filtered by
**model divergence** (present in zoom, absent in prime) rather than ranked by
sharing degree.

**Another structural finding**: each lens firmware is **independently linked** —
offset-level intersection ≈ 0, while 512-byte block-level sharing is 71.4%.
Therefore one **cannot locate the same function across models by file offset**;
content fingerprints are required.

See [`docs/07-lens-firmware.md`](docs/07-lens-firmware.md).

### 5. Cross-vendor L-mount: `.plf` is an alliance standard

Sigma L-mount lens firmware shares the same magic and structure as Panasonic:

```
https://www.sigma-global.com/en/support/download/<8-char>.plf
```

| Field | Panasonic | Sigma |
|---|---|---|
| `LENS-UPDATE-FILE-SOF:/EOH:` | identical | identical |
| format version @0x15 | `0x200` | `0x300` |
| vendor code @0x22 | `40` | `50` / `60` |
| nonce @0x25 | real data | all `FF` (unused) |

**Sigma firmware contains a complete Cortex-M vector table** at file offset
`0x45A`, whose reserved slots are `0` — matching the ARM exception-table
specification, which is what confirms the processor architecture.

Leica (`SLLens01.plf`) and Samyang (`7801V340.plf`) use the same format;
**`.plf` is the shared L-Mount Alliance convention**.

See [`docs/09-third-party-lens.md`](docs/09-third-party-lens.md).

---

## Methodology and limitations

**Data sources**
- All conclusions derive from format analysis of **officially published firmware
  update packages** and protocol probing against **devices the author owns**
- No leaked vendor material or unpublished documentation is used

**Reproducibility**
- Every conclusion is backed by evidence (hash comparison, cross-model
  comparison, structural checks)
- Scripts live in `analysis/`, grouped under `body/` / `lens/`, and are
  reproducible individually

**Known limitations (recorded honestly)**
- Body firmware data partitions remain ciphertext under read-only analysis;
  their internals cannot be expanded further
- Lens-firmware function boundaries depend on the chosen method; the
  precision/recall trade-off of four approaches is quantified in
  `docs/07` §22–26, and several early conclusions have been corrected
- The checksum algorithm for the 4-byte field at `0x40` remains undetermined
  (sum / CRC32 / Adler32 / MD5 / SHA family all tried)

---

## License

[CC BY-NC 4.0](LICENSE) — attribution-required non-commercial sharing.

## Notes

This project was completed independently. The exact purpose of the vendor
private protocol remains open for further research.
