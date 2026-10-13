# Research Notes Index

[Chinese index](../zh/README.md) | English index below

This directory records the reverse-engineering process and technical findings
for the firmware format, integrity-protection mechanisms, and protocol layers.
Reading in order is recommended.

| # | Document | Contents |
|---|---|---|
| 01 | [Firmware acquisition](01-firmware-acquisition.md) | Official sources, direct-link construction, request requirements |
| 02 | [Firmware structure](02-firmware-structure.md) | UPD container format, partition table, field semantics |
| 03 | [Encryption analysis](03-crypto-analysis.md) | Algorithm determination, signature mechanism, ruled-out paths |
| 04 | [USB access](04-protocol-usb.md) | WPD/MTP access status, interface definitions, environment setup |
| 05 | [Vendor private protocol](05-mtp-vendor-protocol.md) | MTP vendor extension channel, private opcode enumeration |
| 06 | [Cross-model comparison](06-multi-model-comparison.md) | Six models side by side, platform evolution, model-specific partitions |
| 07 | [Lens firmware](07-lens-firmware.md) | Plaintext structure, disassembly methods, cross-model fingerprint clustering, RTOS resource table, Ghidra cross-check (with errata) |
| 09 | [Third-party L-mount](09-third-party-lens.md) | Cross-vendor container standard, Sigma vector table |

---

## Research path

```text
Obtain public firmware update packages
      ↓
Parse the UPD container format (02)
      └─→ file header / partition table (58 entries) / checksums / signature layout
      ↓
Analyse encryption and integrity protection (03)
      ├─→ data partitions: strong symmetric encryption, one key per model per partition
      ├─→ integrity: CRC32 + per-partition SHA-256 + ECDSA P-256
      └─→ no plaintext is exposed under read-only analysis
      ↓
Move to the USB / PTP protocol layer (04 → 05)
      ├─→ WPD/MTP access path established
      └─→ three vendor-private opcodes enumerated (0x9102 / 0x9103 / 0x9104)
      ↓
Cross-model diffing (06)
      ├─→ platform evolution, build-timestamp decoding, model-specific partitions
      └─→ mult_fpga partition unique to S1H (reflects a hardware-spec difference)
      ↓
Lens firmware (.plf) analysis (07)
      ├─→ plaintext ARM Cortex-M, load base 0x08000000
      ├─→ header = segment descriptor table; 578-entry variable table = debug metadata
      ├─→ each model is independently linked → cross-model work needs content fingerprints
      └─→ address-independent fingerprint clustering: 2,096 fingerprints across 6 models
            ├─ 17 shared by all models = compiler runtime library
            └─ 20 zoom-only           = candidate business logic (command handlers)
      ↓
Cross-vendor L-mount (09)
      ├─→ .plf is an L-Mount Alliance standard (Sigma / Leica / Samyang, same format)
      └─→ Sigma ships a complete Cortex-M vector table, base 0x45A
```

---

## ⚠️ Errata

**Regarding `07-lens-firmware.md`:** an early version of §11.3 claimed that
"load address equals file offset". **That inference has been disproven and
withdrawn** — the interval test covered 98.59% of the file and was therefore
nearly vacuous, and plain `B` branches were miscounted as function calls.
Section 19 later re-derived the load base as `0x08000000` from the standard
Cortex-M memory map. See §11.3, §11.5, §13.7 and §19 of that document;
the reproducing script is `../../analysis/lens/verify_claims.py`.

**Regarding method choice:** function boundaries in the lens firmware depend on
the analysis method used. The precision/recall trade-off of four approaches is
quantified in `07-lens-firmware.md` §22–26 (strict set / reachability / hybrid /
endpoint segmentation), and some earlier statistics were revised accordingly.

**Regarding where function identification converges:** the self-built methods
above were preparation for the final answer, not the answer itself. Handing the
133 doubly-verified entries of §22 to Ghidra's recursive descent as **seeds**
raised the function count from 1,095 to **1,824** (+66.6%) and recovered 226
**leaf functions that a prologue criterion structurally cannot enumerate**.
See §27 of that document.

---

## Methodology notes

- All findings come from format analysis of **publicly released firmware
  update packages** and protocol probing against **hardware the author owns**
- No leaked vendor material or non-public documentation was used
- Every finding carries its supporting evidence (hash comparison, cross-model
  comparison, structural checks)
- Analysis scripts live in `../../analysis/`, organised under `body/` and
  `lens/`, and each is individually reproducible

---

## Firmware sample requirements

Analysis requires official firmware update packages. The repository **does not
contain firmware images** (copyright reasons); see
[01-firmware-acquisition.md](01-firmware-acquisition.md) for how to obtain them.

It is recommended to also prepare a **sister model** firmware for differential
comparison:

| Model | Filename | Purpose |
|---|---|---|
| DC-S5M2X | `S5m2XV27.bin` | Primary sample |
| DC-S5M2 | `S5m2_V37.bin` | Cross-model diff (same hardware lineage, matching layout) |

> The two firmwares are byte-identical in size (179,207,168 bytes) and their
> partition tables correspond one-to-one, making them a high-value differential
> sample for locating model-specific code.

Third-party L-mount lens firmware can be downloaded directly (official links):

```bash
python ../../analysis/lens/download_sigma.py
```
