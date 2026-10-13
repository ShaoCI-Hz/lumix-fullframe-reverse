# Lens Firmware — Fully Plaintext, Symbols Included (major finding)

> **Core finding**: Panasonic **lens firmware is not encrypted** and retains a
> complete function/variable symbol table. This contrasts sharply with the body
> firmware (strong encryption + ECDSA signature) and makes it the **most
> information-rich resource** along the entire reverse-engineering path.

---

## 1. Sample

| Item | Value |
|---|---|
| Download | `https://panasonic.jp/support/share2/eww/com/dsc/ff/zip/S-R24105V020.zip` |
| ZIP contents | `4001V020.plf` |
| Compressed / extracted | 301,572 B / **497,494 B** |
| Entropy | **6.84** (plaintext, not encrypted) |
| Zero bytes | 70,625 (14.20%) |

**Comparison: the body firmware is 90–180 MB and fully encrypted; the lens
firmware is only ~0.5 MB and completely plaintext.**

---

## 2. File format

```text
0x000000  "LENS-UPDATE-FILE-SOF:"     <- Start of File marker
0x000013  ...header fields...
0x000058  "LENS-UPDATE-FILE-EOH:"     <- end-of-header marker
0x000078  "HDFLSPPSLFDI"              <- segment marker
          ...data (ARM code + symbol table)...
0x069038  "CABRIOLET\0\x01A"          <- internal project codename
0x079743  "CABRIOLET"                 <- second occurrence
end       large amount of 0xFF (flash-erased state) + structured tables
```

**Known markers**: `LENS-UPDATE-FILE-SOF:` / `LENS-UPDATE-FILE-EOH:` (each
appears once in the file)

---

## 3. ★ Embedded symbol table (578 symbols)

The firmware **retains its debug symbols**, directly exposing the lens control
logic. Grouped by function:

### OIS (stabilisation)

```text
OISPwAdjAdjSet        0x005413
OisDVL                0x0055DB
WstOL / WstOL2 / WstFL / WstFL2
```

### Iris

```text
IrsSetCrVel2x16       0x0054EF
IrsAct / IrsJmp / IrsPos
```

### Focus

```text
FocDrv                0x005793
FocJmp / FocPos / Foc_FreqActSet
Dist5mm               0x00579B
```

### Zoom / motor

```text
ZmPosAD               0x00581B
ZmPos256ZmMinPlsZmPosAD2ZmPosTrk
MtrMode / DrvActGr / DrvVel / ActSet
```

### Control state

```text
DbgMode / DrvMode / MoveMode / TarMode / RestMode
TrgtPos / NowPos / PICnt / Result
```

### Signal processing

```text
IntFreq / DifAmpP / DifAmpS / AmpPrev / AmpShiftPhShift
ObsGain / Phase
```

> The full list is in `analysis/lens/lens_symbols.txt` (578 entries with offsets).

---

## 4. ★ It is ARM Cortex-M code

Around `CABRIOLET` there are **standard ARM Thumb instructions**:

```text
0x068FD8  e1 ee 10 0a | 70 47         <- 70 47 = BX LR (function return)
0x068FE8  ff f7 d4 ff | af f3 00 80   <- ff f7 = BL (function call)
0x069018  80 b5 ... 02 bd             <- 80 b5 = PUSH {R7,LR}; 02 bd = POP {R7,PC}
0x069038  43 41 42 52 49 4f 4c 45 54  <- "CABRIOLET\0\x01A"
```

**Verdict: the lens MCU is an ARM Cortex-M and the firmware can be disassembled
directly (IDAPython/Ghidra, Thumb mode).**

---

## 5. Significance and actionable directions

### 5.1 Direct value: the lens control protocol can be fully reverse-engineered

Symbol table + ARM code = the complete OIS / iris / focus / zoom control
algorithms and register definitions can be reconstructed.

### 5.2 Strategic value: Panasonic does not encrypt everything

Body firmware = **AES strong encryption + ECDSA signature**; lens firmware =
**fully plaintext with symbols retained**. Encryption is therefore a
**deliberate choice applied to the body**, and the lens "update file" format is
**a separate system**.

### 5.3 ★ A structural observation: the camera must be able to handle plaintext firmware

For the camera to push a `.plf` through the mount to the lens, the camera's
firmware-processing logic **must contain a branch that handles the plaintext
format**.

The technical points this yields:
1. The camera's firmware updater supports more than one container format
   (`UPD` encrypted / `LENS-UPDATE-FILE` plaintext)
2. The camera's firmware-processing path therefore contains a branch that
   handles the plaintext format
3. `.plf` traffic on the L-mount bus is plaintext and can be recorded with a
   logic analyser

### 5.4 Other samples

All L-mount lenses can be downloaded; the naming pattern is:
```text
https://panasonic.jp/support/share2/eww/com/dsc/ff/zip/<model>V<version>.zip
e.g. S-R24105V020.zip / S-E2470V010.zip / S-S85V010.zip ...
internal filename such as 4001V020.plf (4001 = internal lens model code)
```
Differential comparison across lens firmwares locates the "shared template"
versus "model patches", covering the whole lens line quickly.

---

## 7. Multi-lens differential (completed)

Six L-mount lens firmwares were downloaded and compared:

| Firmware | Internal model | Lens | Size | Entropy | Symbols |
|---|---|---|---|---|---|
| `4001V020.plf` | 4001 | S-R24105 | 497,494 | 6.843 | **431** |
| `4002V020.plf` | 4002 | S-R70200 | 673,252 | 7.005 | **538** |
| `4006V020.plf` | 4006 | S-E2470 | 452,161 | 6.840 | **539** |
| `4003V020.plf` | 4003 | S-X50 | 260,498 | 6.699 | 30 |
| `400CV020.plf` | 400C | S-S85 | 296,988 | 6.429 | 41 |
| `400EV020.plf` | 400E | S-S50 | 293,006 | 6.461 | 37 |

**All six are fully plaintext** (entropy < 7.01).

### 7.1 Header structure (identical across all)

```text
+0x00  "LENS-UPDATE-FILE-SOF:"
+0x13  46 3a 00 02        <- fixed magic (same for all lenses)
+0x17  07 e9 XX XX        <- first two bytes fixed, last two vary by model
+0x1C  01 00 03 00        <- fixed
+0x20  40 XX              <- internal model code (4001 = S-R24105 ...)
+0x24  02 00 00 00        <- fixed
+0x2C  XX XX XX XX        <- varies by model (probable checksum/hash)
+0x58  "LENS-UPDATE-FILE-EOH:"  <- end of header
```

### 7.2 ★ Shared symbol stack (329 symbols common to the zoom lenses)

**The zoom lenses (4001 / 4002 / 4006) share 329 symbols** — i.e. the common
L-mount control stack. Prime lenses have very few symbols (30–41), showing that
the bulk is shared zoom/focus/stabilisation logic.

| Function | Symbols (excerpt) |
|---|---|
| **OIS stabilisation** (19) | `ChkGyro` `ChkOISAj` `ChkOISTYmode` `GyroDCAjAdjSet` `OISAngleData` `OisDVL` `OISDrv` `ItunOIS_Gain_tbl` |
| **Focus** (19) | `FocDrv` `FocJmp` `FocPos` `Dist5mm` `TrkDistance` `AFAdjData` `LAFArea` `MtrMode` |
| **Iris** (12) | `IrsAct` `IrsDrvStep` `IrsPos` `IrsJmp` `IrsSetCrVel2x16` `IrsAv2ApNo` |
| **Zoom** (5) | `ZmPosAD` `ZmHysAD2ZomAD3` `ZmPos256ZmMinPlsZmPosAD2ZmPosTrk` |
| **Motor/drive** (24) | `Current` `DrvActGr` `DrvVel` `PitDrv1~3` `FMtrPos` |
| **Encoder/position** (76) | `ChkCnt` `CntPulse` `AllAdjAdrsData` `DiffPls` … |
| **Control/mode** (49) | `ActSet` `AdjSet` `DrvMode` `MoveMode` `TarMode` |
| **Debug/error** (16) | `DbgMode` `ErrLSB` `ErrMSB` `LockErr` `StopErr` `LogData1~8` |

> Full listing: `analysis/lens/lens_symbols_all.txt` (1958 lines, per-symbol
> offsets plus the 329 zoom-shared symbols).

### 7.3 Conclusion

**The complete L-mount lens control protocol is exposed as plaintext symbols**:
the camera→lens delivery mechanism (OIS / iris / focus / zoom / motor), the
internal model-code scheme (4001–400E), and the unified update container
(`LENS-UPDATE-FILE-SOF/EOH`). This is the project's most direct white-box sample
of "firmware processing logic".

---

## 8. To do

1. Disassemble the `CABRIOLET` region with Ghidra/IDA (Thumb) to recover the lens control functions → **done with capstone, see §9**
2. Capture the L-mount bus to verify the plaintext format the camera sends
3. Investigate whether the camera firmware updater accepts a lens-format payload (requires the camera online)

---

## 9. ARM Cortex-M disassembly analysis (capstone)

### 9.1 Container-structure correction: `EOH` = End Of **Header** (not End Of File)

```text
0x000000  "LENS-UPDATE-FILE-SOF:"      <- Start Of File
0x000015  header fields  (00 02 | 07 e9 | 03 07 00 01 | 00 03 ...)
0x000058  "LENS-UPDATE-FILE-EOH:"      <- End Of HEADER
0x000070  "HDFLSPPSLFDI" / "IDFLSPPSLF00"   <- segment markers
0x000084  0x00000200 = 512             <- block size
+0x29     00 6D + 8 bytes of high-entropy data   <- probable checksum/signature
```

**So `.plf` = SOF header + segment table + data segments**, with the data
segments having their own layout — which explains why disassembling from an
arbitrary offset misaligns.

### 9.2 Confirmed a complete ARM Cortex-M program (capstone statistics)

| Feature | Count |
|---|---|
| `PUSH` prologue patterns | **2,490** |
| `BX LR` (`70 47`, function return) | **1,311** |
| `BL` call patterns (`f0-f7 f8-ff`) | **1,078** |

Disassembly sample (`0x049800`, correctly aligned):

```asm
0x04980E  push   {r2, r3, r4, lr}     ; prologue
0x049810  mov    r4, r0
0x049816  cmp    r4, #0
0x049818  beq    #0x49828
0x049820  bl     #0x60bd8             ; call
0x049828  pop    {r0, r1, r4, pc}     ; epilogue
```

### 9.3 Code-segment distribution (by instruction density)

```text
0x02D000(0.56)  0x031000(0.73)  0x03B000(0.71)  0x040000(0.51)
0x042000(0.58)  0x045000(0.79)  0x04E000(0.81)  0x057000(0.71)  0x062000(0.79)
```

The code is split into several segments interleaved with data segments — a
typical segmented link layout.

### 9.4 No typical vector table found

No Cortex-M reset vector table was found inside the file (all candidates fall in
data regions), showing **the file offset of the code is not its load address**
and that `.plf` is a **packaged container**: the segment table must be parsed
first (moving segments to their load addresses) before full disassembly is possible.

### 9.5 Reproduction

```bash
python analysis/lens/lens_disasm.py         # locate code regions (Thumb feature density)
python analysis/lens/lens_disasm2.py        # vector table / code partition / string refs
python analysis/lens/lens_header_struct.py  # header and segment structure
# full disassembly output: analysis/lens/lens_disasm_output.txt
```

### 9.6 Conclusion

The lens firmware is a **complete, disassemblable ARM Cortex-M program**, with a
symbol table and located code segments.

**The only remaining step was to parse the segment table** (mapping segments to
load addresses) to enable full function-level recovery with Ghidra/IDA. It is
the most analysable sample of all the camera firmwares.

---

## 10. Segment-table attempts (conclusion: the segment layout must be solved first)

### 10.1 Vendor markers inside the container

```text
0x006D  "PSLFDH"          <- marker after the header fields
0x0078  "HDFLSPPSLFDI"     <- segment marker 1
0x009A  "IDFLSPPSLF"       <- segment marker 2 (followed by "00")
0x00CF  "QIPL"
0x02D7  "PHUL"
```

There are also values such as `0x84: 512` (block size) and `0xB4: 0x2000`; the
header contains 8 bytes of high-entropy data (`+0x2B..+0x33`), a probable
checksum or signature.

### 10.2 No usable vector table found

An improved search (requiring word0 to look like a stack pointer and word1..N to
look like Thumb addresses) produced 49 candidates, but **all fall in data
regions** (e.g. `SP=0x00404040`) — none is a real reset vector table.

**Inference**: the file offset of the code **≠** its load address, `.plf` is a
**packaged container**, and the segment layout must be parsed to rebuild a
loadable image.

### 10.3 Linear sweep is unreliable (measured)

```text
BL/BLX instructions     5,688
targets inside the file 89.1%      <- looks plausible
targets in a dense code block 25.1%  <- actually very low
```

Linear disassembly from an arbitrary offset produces many false positives (data
segments misread as instructions) — for example the "disassembly" at `0x00FD00`
shows `svc #0xb2` and implausible `ldm` sequences.

**Therefore code segments must be separated from data segments before any
trustworthy function-level disassembly can be obtained.**

### 10.4 Reproduction

```bash
python analysis/lens/lens_segtable.py   # segment markers / vector table / boundaries
python analysis/lens/lens_bl_verify.py  # BL target distribution and load-address check
```

### 10.5 Next steps

1. **Solve the segment layout**: locate the segment table after
   `PSLFDH`/`HDFLSPPSLFDI` (possibly an (address, size, offset) triple, or encoded)
2. Use the recovered segment mapping for **accurate function-level disassembly**
3. Use the 578 symbol names to annotate function semantics (OIS / iris / focus / zoom)

> Note: this section is an **honestly recorded open item**. The segment table has
> not been solved, and it is a prerequisite for accurate disassembly — recorded
> here to avoid duplicated effort.

---

## 11. ★ An alternative to the segment table: seeds + forward sweep (succeeded)

**Key insight: this method does not depend on the segment table.** Using function
prologues as seeds plus forward decoding yields a trustworthy function set.

### 11.1 Method

Linear sweep is unreliable (data regions misread as instructions), so instead:

1. **Prologue seeds**: Thumb `PUSH {r0-r7,lr}` (`0xB5xx`) and `PUSH.W` (`e92d ..`) —
   such byte sequences almost never occur naturally in data
2. Decode **from each seed to the function end** (`pop {..,pc}` or `bx lr`)
3. Collect **BL targets** as candidate function entries
4. **Cross-validate**: `BL target ∩ prologue` = high-confidence entry

### 11.2 Measured results

```text
prologue seeds              1,147
  fully disassemblable        694  (60.2%)
BL targets (call sites)     2,532
  disassembly success rate   81.5%   <- higher than prologue seeds
high-confidence entries       101   <- BL target ∩ prologue (double-validated)
trusted-function coverage    31.2% of file (155,366 / 497,494 bytes)
```

### 11.3 ⚠️ Retracted: "load address = file offset" (**not proven**)

> **Erratum (added after an independent sub-agent review)**
>
> An early version of this section claimed "99.9% of BL targets fall inside
> function intervals ⇒ load address = file offset".
> **The inference does not hold and is hereby withdrawn.**

**Reasons for withdrawal (reproduced and verified in code):**

1. **The union of "function intervals" covers 98.59% of the file**

```text
   file size          497,494 bytes
   interval union     490,476 bytes = 98.59%
   interval union = [0x001B6A, 0x079756)   <- spans from the first seed to EOF
```

   Because the intervals are built as `[(se[i], se[i+1]) ... (se[-1], n)]`,
   **any target above 0x001B6A "falls inside an interval"** — the test has almost
   no discriminating power.

2. **Plain `B` branches were mixed into the "BL targets"**

   The collection code used `ins.mnemonic in ('bl', 'b', 'blx')`, **including `b`**:

```text
   pure BL/BLX targets : 5,688
   plain B targets     : 5,116   <- 47%, should not count as "function calls"
   total               : 10,804
```

   `B` is an intra-function jump: **77% of B targets are within 0x400 of their
   interval start**, so including them necessarily inflates the hit rate — a
   self-fulfilling measurement.

3. **The real numbers under a strict standard**

   | Standard | Landing in a dense code block |
   |---|---|
   | BL/BLX only | **22.4%** |
   | BL+B (the original usage) | 17.1% |
   | the honest measurement of §10.3 | 25.1% |

   **§10.3's 25.1% was the valid number; §11.3 "upgraded" the conclusion using a
   weaker test, which is not new evidence.**

4. **The base test itself is not decisive**: base=0 matches only 2.3% of targets
   exactly, which is close to what an incomplete seed set would give —
   **not enough to confirm load==offset**.

**Corrected statement:**

> **Whether the load address equals the file offset remains undetermined.** It has
> been neither proven nor disproven. Resolving it requires parsing the segment
> table (§10) or an intra-segment address-consistency check.

**This directly affects usability**: §11.6 previously said the file "can be
loaded into Ghidra/IDA" — until the load address is settled, **that must be
downgraded to "a base address has to be tried in Ghidra first".**

### 11.4 Call-chain verification (self-consistent)

```text
0x02C2D0  push {r4,r5,r6,lr}     <- prologue
0x02C2DA  bl   #0x2C3CC          <- call
0x02C3CC  push {r4,lr}           <- indeed a prologue ✓
0x02C3D2  bl   #0x2C388          <- another call
```

Most-called functions (core utilities):

| Entry | Times called | Instructions |
|---|---|---|
| `0x0459C2` | 7 | 30 |
| `0x04E70E` | 6 | 41 |
| **`0x05AE26`** | 4 | **455** (largest function) |
| `0x03E3DC` | 3 | 147 |
| `0x02C3CC` | 2 | 13 |

> Note: "times called" is likewise based on the target set that includes `B`,
> so the numbers are inflated — **for relative ranking only**.

### 11.5 ⚠️ Naming erratum: this is not "recursive descent"

> An early version of this section called the method "recursive-descent
> disassembly" — **that name is inaccurate**.
>
> The actual implementation (`follow_targets()` in
> `analysis/lens/lens_recursive.py`) is: **decode forward linearly from each seed
> to the first return, and "collect" the jump targets encountered** — it **never
> descends into them**. The correct name is
> **"seed-based linear sweep"**, not recursive descent.
>
> Also: the seed test `d[o+1] == 0xB5` is a ~1/256 byte predicate.
> Over ~248K even offsets it would be expected to hit about **970** times by
> chance — the measured count was **1,147**. The two are close, **so a
> substantial fraction of these 1,147 seeds may be data coincidences**, and the
> original statement that such sequences "almost never occur naturally in data"
> was **too optimistic**. No 0xB5 frequency baseline (null model) was computed —
> a known weakness of the method.

### 11.6 Reproduction

```bash
python analysis/lens/lens_recursive.py  # seeds + forward sweep (note: not recursive descent)
python analysis/lens/lens_base.py       # ⚠️ its "function interval" test is disproven, do not cite
python analysis/lens/lens_entry2.py     # target-entry quality comparison
python analysis/lens/lens_final.py      # high-confidence entry list
python analysis/lens/verify_claims.py   # ★ reproducible falsification of the claims above
```

### 11.7 Next steps

1. Rebuild the function set using a **strict standard**: only BL/BLX targets,
   and only those landing in a dense code block
2. **Prioritise the load-address question** (segment table, or an intra-segment
   consistency check)
3. Cross-validate the statistics on a **second lens file** (4002/4006) for repeatability
4. Only annotate symbols/functions after the above is confirmed

---

## 12. Nature of the symbol region: a "variable-name table", not a "function symbol table"

The 578 symbols mentioned in §3 were dissected structurally; **the conclusion is
revised**:

### 12.1 Actual structure

```hex
005410  03 00 00 4f 49 53 50 77 41 64 6a 41 64 6a 53 65  |...OISPwAdjAdjSe|
005420  74 00 00 00 00 00 00 00 ...                        |t...............|

0x5413  "OISPwAdjAdjSet"
```

**The names are consecutive null-terminated strings**, each preceded by a small
structure:

```text
before OisDVL:  00 00 00 00 | 01 06 | 00 00
before IrsAct:  00 00 00 00 | 05 01 | 00 00
before FocDrv:  00 00 00 00 | 05 03 | 00 00
                             ↑type  ↑index/number
```

### 12.2 Basis for the judgement: the table **contains no address field**

| Assumption | Hit rate |
|---|---|
| 4 bytes after the name are a Thumb address | **5 / 575** |
| 4 bytes before the name are a Thumb address | 67 / 575 (all cross-string-boundary false positives) |

→ **the table carries no addresses**, so it **cannot** be mapped directly to
function entries. It is a **variable dictionary** (variable name + type/number),
likely metadata retained from the debug build.

### 12.3 But it is still valuable: feature semantics are readable

Variable names appear in module groups, directly exposing the subsystem split:

```text
OIS group     OISPwAdjAdjSet / OisDVL / OisFcharActSet / OISAngleData
Iris group    IrsSetCrVel2x16 / IrsAct / IrsJmp / IrsPos / IrsDrvStep
Focus group   FocDrv / FocJmp / FocPos / Dist5mm / TrkDistance / AFAdjData
Zoom group    ZmPosAD / ZmHysAD2ZomAD3 / ZmPos256...
Drive group   MtrMode / DrvActGr / DrvVel / Current / Vel2x16
Mode group    DbgMode / DrvMode / MoveMode / RestMode / TarMode
```

**These names can be used to "tag" functions** — a function that frequently reads
and writes `Irs*` variables is an iris-control function.

### 12.4 Revised mapping approach

Since the variable table has no addresses, an **indirect mapping** is used:

1. Locate the **file address of the variable-name string** (known; see
   `analysis/lens/lens_symbols_all.txt`)
2. Search the code for **instructions referencing that address** (the literal
   pool of Thumb `LDR Rd, [PC, #imm]`)
3. A function referencing a variable ⇒ that variable's user

```bash
python analysis/lens/lens_symtable.py   # symbol-region structure analysis
python analysis/lens/lens_symbols_all.txt  # per-symbol file offsets (published)
```

### 12.5 Current progress

| Item | Status |
|---|---|
| Lens firmware plaintext | ✅ |
| Cortex-M confirmed | ✅ |
| load address = file offset | ❌ **retracted, not proven** (see §11.3) |
| Function set (694 disassemblable) | ⚠️ contains data coincidences, see §11.5 |
| High-confidence entries (101) | ⚠️ same |
| Variable dictionary (578 entries, with types) | ✅ |
| Container table structure (segment descriptors) | ✅ see §14 |
| Variable → function mapping | ⏸ needs the indirect method of §12.4 |

---

## 13. ★ Indirect-mapping test: the variable table is "pure debug metadata"

Two rounds of testing followed the §12.4 approach, and **the result was more
valuable than expected**.

### 13.1 Variable names have no code references at all

```text
variable names (0x4000-0x9000 region)   388
referenced from literal pools              1   <- the single hit is a string-fragment false positive
```

### 13.2 A methodological error was corrected

Previously, testing whether the 4 bytes next to a name looked like an address
required *address < file size* — which is **wrong**: variables live in **RAM**,
so their addresses belong to the `0x2000xxxx` range and **are never inside the
file**.

Re-testing with the RAM address range:

```text
top 4 bytes after a name: 0x00000000 x106, the rest are string fragments — no address field
top 4 bytes before a name: 0x00000000 x78, the rest are string fragments — no address field
```

### 13.3 But the code does reference RAM heavily

```text
whole-file RAM address references (aggregated per 1KB block): 166 blocks
  0x20002000 x458   0x20004400 x273   0x2000D000 x189
  0x20000000 x177   0x2001D000 x170   0x2000F800 x122
  ...
```

**The code only operates on RAM addresses and never references the variable-name
strings.**

### 13.4 Conclusion: the variable table serves a "runtime debug channel"

The table **contains no addresses and is not referenced by code**, yet retains
complete variable names and types — **the only reasonable explanation is that it
is used by a debug interface that accesses variables by name**.

Supporting evidence (the table indeed contains debug-class variables):

```text
DbgMode        DrvMode       LogData1..8       ErrLSB
LockErr        ChkGyro       Adj_Pos           AvMaxVlF
```

**This is a meaningful finding for the project:**

1. **The lens MCU has runtime debug capability** — internal variables can be read
   and written by name
2. The presence of `DbgMode` suggests **a debug mode can be entered externally**
3. If that debug channel remains **available during normal use**, it offers an
   entry point for observing the lens's internal state
4. This path **sidesteps the static-analysis difficulty of the lens firmware** and
   moves directly to dynamic observation

### 13.5 Reproduction

```bash
python analysis/lens/lens_ramaddr.py   # address-field detection + RAM reference statistics
python analysis/lens/lens_xref.py      # variable → reference → function mapping attempt
# output: analysis/lens/lens_var_xref.txt
```

### 13.6 Next steps (direction is clear)

| Priority | Task | Requires |
|---|---|---|
| **1** | **Probe the lens debug channel** (`DbgMode` / variable-name interface) | camera + logic analyser |
| 2 | Infer the **protocol format** for accessing variables by name | the debug handler in the firmware |
| 3 | Locate in the firmware the **function handling variable-name requests** (search the logic around strings such as `DbgMode`) | local |

> Note: the "1 reference" of §13.1 was reviewed and found to be a
> string-fragment false positive, **i.e. the variable table has 0 references**.

### 13.7 ⚠️ Erratum and self-correction (added after an independent review)

> An independent review raised **reasonable doubts** about this section's reading,
> recorded as follows.

**The doubt: "rounding 1 reference straight down to 0, then building a
'debug metadata' narrative on that"** carries a risk of **motivated reasoning** —
since "a debug channel exists" is the more interesting conclusion.

The more careful wording would be:

| Original | Revised |
|---|---|
| "zero references" | "**no** references detected in literal pools; the single hit was manually judged to be a string fragment, **and that judgement itself was not more strongly verified**" |
| "serves a debug channel" | "**a reasonable hypothesis**; not yet confirmed by any direct evidence" |

**Stronger checks suggested by the review (not yet done):**

1. Dump the **context bytes** at that one reference site to confirm it really is a fragment
2. Search for the table's **base pointer** (a pointer into the `0x5400` area)
   rather than per-name offsets — the table is likely indexed as a whole
3. Check whether the `[type][index]` fields are **consumed by any code path**

**Until those checks are done, the "debug channel" conclusion of §13.4 should be
treated as a hypothesis, not a finding.**

### 13.8 Falsification risk for "the variable table serves debugging"

It should also be noted: if the §13 hypothesis held, a dispatcher that works
**by name** **ought to leave references behind**. Zero references were measured,
which **both** supports "the table is host-side/offline metadata"
**and** weakens the idea of "an in-firmware debug handler dispatching by name".

**So do not treat §13 as evidence of "a usable debug entry point".**

### 13.9 Reproduction

```bash
python analysis/lens/lens_ramaddr.py   # address-field detection + RAM reference statistics
python analysis/lens/lens_xref.py      # variable → reference → function mapping attempt
python analysis/lens/verify_claims.py  # ★ reproducible falsification of the §11.3 conclusion
```

---

## 14. Container header structure: a segment/block descriptor table (not code)

Continuing the `.plf` header dissection, confirming it is a **table structure**
rather than executable code.

### 14.1 Header layout

```text
0x0000  "LENS-UPDATE-FILE-SOF:"              (21 B)
0x0015  header fields 00 02 | 07 e9 | 03 07 00 01 | 00 03 ...
0x0058  "LENS-UPDATE-FILE-EOH:"              (21 B) <- End Of HEADER
0x006D  "PSLFDH" + 01
0x0074  02 00 02 05
0x0078  "HDFLSPPSLFDI"
0x0084  0x00000200 = 512                     <- block size
0x009A  "IDFLSPPSLF00"
0x00B4  0x00002000 = 8192
0x00B8  0x00000200 = 512
0x00B0+ segment/block descriptor table starts
```

### 14.2 Basis for judging it a "table" rather than "code"

**(a) Disassembly produces implausible instruction streams.** Trying Thumb
decoding at several alignments from `0x00F0` yields strings of meaningless
instructions:

```text
0x00F0  4811  asrs r0, r1, #5
0x00F2  4901  lsls r1, r1, #5
0x00F4  540c  lsrs r4, r2, #0x11
0x00F8  4901  lsls r1, r1, #5
0x010A  70be  bkpt  #0x70        <- a hallmark of "data being read as code"
```

**(b) The `00 00 70 XX` pattern recurs at a 4-byte stride:**

```text
stride sequence: [4, 4, 4, 4, 14, 6, 4, 4, 4, 4, 10, 4]
```

Read as u16 LE from `0x10E`, this yields addresses that are **strictly increasing
and all inside the file**:

| Offset | Bytes | u16 LE | Value |
|---|---|---|---|
| 0x10E | `70 72` | 0x7270 | 29,296 |
| 0x112 | `70 90` | 0x9070 | 36,976 |
| 0x116 | `70 a2` | 0xa270 | 41,584 |
| 0x11A | `70 b0` | 0xb070 | 45,168 |

**(c) `0xB0..0x400` also contains addresses near the end of the file:**

```text
0x0128  0x007070 =  28,784
0x014C  0x057270 = 356,976
0x0150  0x05EC70 = 388,208
0x016C  0x073270 = 471,664     <- file size 0x79716 = 497,494
0x029C  0x025E70 = 155,248
```

### 14.3 Meaning of the two values 512 / 8192

```text
0x0084 = 512    <- matches the "block size" of §9.1
0x00B4 = 8192
0x00B8 = 512
```

**512 recurs**, the same as the UPD container (body firmware) block size —
showing that Panasonic's firmware containers **share one block-layout convention
across the body and the lens**.

### 14.4 Still unsolved

**The item structure of this table has not been fully solved** — whether it is
(address, size) or an (address, size, type) triple, and whether `0x70` is a flag,
still require:

1. **Cross-sample alignment**: compare entries at the same offset across the
   three differently-sized files (4001/4002/4006 at 497K/673K/452K) to find the
   field that varies with file size (= the segment boundary)
2. **Verify monotonicity**: the entry address sequence should cover `[0xB0, EOF)`
   without overlap

```bash
python analysis/lens/plf_struct.py    # header fields / cross-sample comparison / pair search
python analysis/lens/plf_head2.py     # header disassembly test + 0x70 pattern analysis
```

**The value of this section**: it settles the open question "is the header code
or a table?" in favour of **a table**, thereby **narrowing the segment-table
problem of §10 to "solve this table's item structure"**.

---

## 15. Segment-table attempts: two negative results (methodology record)

Two independent methods were used to locate the data-region start / segment
boundaries — **neither succeeded**, but both negative results are worth recording.

### 15.1 Cross-sample alignment (4001/4002/4006)

Three differently-sized samples were compared to find header fields that vary
with file size:

```text
     off    4001V020(497,494)  4002V020(673,252)  4006V020(452,161)
  0x0018          459,753           1,379,305            265,449
  0x0084              512                 512                256
  0x00B4            8,192               8,192             40,960
```

**A striking coincidence:**

```text
4001:  37,741 + 459,753 = 497,494 = file size  ✓
```

**But 4002 immediately refutes it**: `0x18 = 1,379,305 > 673,252 = file size` ✗

**Conclusion: `0x18` is not a "data size"**; the match on one sample was
coincidence. Also note `0x84` is **256**, not 512, on 4006 — the block size is
**not a global constant**.

### 15.2 Entropy scan (a more direct method, also failed)

Computing entropy per 4 KB block **does show a clear stratification**:

```text
0x000000 - 0x008000   H = 3.15 - 5.04    <- low entropy
0x009000 onward        H = 6.28 - 6.89    <- medium-high, stable

and the three samples agree closely over 0x2000-0x8000:
  3.79, 4.06, 3.93, 3.33, 3.15   <- fixed header
```

At first this looks like a clean "header + data region" split.
**But content inspection refutes it:**

| Offset | Actual content | Code? |
|---|---|---|
| `0x8000` (4001) | `02 0a 02 0a 02 0a ...` repeating pattern | ❌ data table |
| `0x9000` (4006) | `72 6b 46 53 74 6f 70 70 65 72` = `"rkFStopper"` | ❌ string |
| `0x8800..0x9200` | count of function prologues (`0xB5xx` / `e92d`) | **zero** |

**The decisive counter-evidence:**

> `0x02C2D0` and `0x02C3CC`, **already verified as real functions**, fall in the
> entropy band **3.9–4.9, the "low-entropy" region**.

**Therefore: entropy cannot reliably separate code from data.**
String tables and constant tables also reach 6.5+, while real code can sit in a
low-entropy region. **The intuition "high entropy = code" is wrong here.**

### 15.3 Methodology lesson (echoing the existing rule in §3)

Repository `docs/03` §12.2 already established the rule: **entropy alone is not a
basis for format judgement**. This section is that rule's **second confirmation**,
now on the lens firmware:

| Case | Misuse | Consequence |
|---|---|---|
| `docs/03` (body) | small-window (256B/4KB) entropy → "compressed not encrypted" | misjudgement, corrected with ≥64KB |
| **this section (lens)** | medium-entropy region → "data/code start" inference | **misjudgement, corrected by content inspection** |

**The right approach**: entropy is for **coarse screening** only (ruling out
global strong encryption); determining code/data boundaries requires **content
features** (valid-Thumb decode rate, prologue density, strings).

### 15.4 Reproduction

```bash
python analysis/lens/plf_segtable.py    # cross-sample header field comparison
python analysis/lens/plf_entropy.py     # per-block entropy curve + data-start inference
python analysis/lens/plf_data_start.py  # content inspection (refutes the entropy conclusion)
```

### 15.5 Unsolved / next steps

The segment-table item structure **remains unsolved**. Already ruled out:

- ❌ header fields directly equal to file size / data size
- ❌ entropy stratification to locate the data region
- ❌ the function-interval test (§11.3, retracted)

**Still worth trying:**

1. **Block-index view**: since `512`/`256` is the block size, try a
   "one descriptor per block" structure
2. **Work backwards from known functions**: take verified real functions (such as
   `0x02C2D0`) and their BL targets and check whether their addresses satisfy some
   **piecewise-linear mapping** (rather than identity)
3. **Compare with the body UPD container**: the body container's block layout is
   fully parsed (`docs/02`); the lens container may reuse the same descriptor format

---

## 16. Cross-lens comparison: independent linking + two architectures (zoom vs prime)

### 16.1 ★ Key finding: each lens firmware is independently linked

Six lens firmwares were compared by the **file offsets of their function prologues**:

```text
prologue counts: 4001:1149  4002:1380  4003:849  4006:952  400C:529  400E:543
```

| Level of comparison | Result |
|---|---|
| **Offset-level** pairwise Jaccard | **≈ 0.002** |
| **Offset-level** prologues common to all six | **0** |
| **Block-level** (512-aligned, prologue in ≥3 samples) | **705 / 988 = 71.4%** |

**Offset-level intersection ≈ 0 while block-level sharing is 71.4%** — strongly indicating:

> **Each lens firmware is "independently linked" from the same source base**
> (different link layouts → completely different function offsets; but shared
> content → high block-level overlap)

**Inference**: shared functions cannot be found across models by "identical file
offset"; **content comparison is required** (binary diff / function fingerprints /
strings).

### 16.2 ★ Zoom vs prime lenses: two entirely different firmwares

Comparing each sample's **set of variable names** (strict match: ≥6 characters,
mixed case):

```text
4001 S-R24105 (zoom)    332
4002 S-R70200 (zoom)    381
4006 S-E2470  (zoom)    478
4003 S-X50    (prime)    30
400C S-S85    (prime)    20
400E S-S50    (prime)    23
```

| Group | Intersection | Jaccard |
|---|---|---|
| **Zoom group** (4001/4002/4006) | **291** | **0.507** |
| **Prime group** (4003/400C/400E) | 5 | 0.102 |
| zoom-common ∩ all primes | **3** (all junk strings such as `PPbbbbbbfp` / `eForce` / `pGpGpG`) | ≈ 0 |

**Conclusion:**

1. **Zoom lenses share 291 variable names (Jaccard 0.507)** — a **common control stack** exists
2. **Prime lenses have only 20–30 variable names** — a **heavily reduced firmware** (no zoom mechanism, simplified OIS)
3. **The two groups share almost nothing at this level** — **not one codebase trimmed down, but two independent firmware families**

### 16.3 Module composition of the shared zoom control stack (291 names)

```text
Prefix     Count  Meaning
Irs         10    iris
Chk         10    self-test / verification
OIS          9    optical stabilisation
Foc          8    focus
Adj          8    calibration / adjustment
Pos          8    position
Err          7    error codes
Zm           5    zoom
Move         4    motion control
Drv          4    drive
Trk          2    tracking
Ois          2    (a second naming style)
Tar          2    target
Log/Dbg/Rest/Mtr  1 each
(other)    208    unclassified (mostly internal abbreviations)
```

**Representative variable names** (all readable plaintext):

```text
AFAdjData        AllAdjAdrsData    AdjStat     AdjSpd
AtnTracking      AvMaxVlF          AveSmpC     BAmpGain
ChkGyro          ChkOISAj          ChkPos      ChkLin
BtnTrkFStopper   AmpShiftPhShift   Apvel2Imode ...
```

**This corroborates the "329 shared symbols" of §7** — this round used a
**stricter matching rule** (≥6 characters, mixed case) and got **291**; the lower
count comes from dropping short names and fragments, but **the conclusion is the
same: the zoom lenses share one unified control-algorithm stack**.

### 16.4 Reproduction

```bash
python analysis/lens/lens_cross.py       # cross-sample prologue/block/variable-name sharing
python analysis/lens/lens_zoom_prime.py  # zoom vs prime group comparison
```

### 16.5 Methodology correction (important)

The result of §16.1 **corrects an implicit assumption this project had been
making** — namely that "the same file offset can locate the same function across
models".

**That assumption is false.** Cross-model work must use content comparison.
This also explains part of the §11 puzzle where only 2.3% of BL targets hit a
known function entry: offsets are simply not comparable across models.

---

## 17. ★ Cross-model function fingerprinting (succeeded)

Since offsets do not work across models (§16.1), **address-independent function
fingerprints** were used instead.

### 17.1 Method

1. Extract functions from prologue seeds, decode forward to the return (as in §11)
2. **Normalise** every instruction: strip all immediates and displacements
   (`#0x1f4` → `#I`, `[pc, #0x44]` → `[pc, D]`), **keeping only mnemonic and
   operand shape**
3. SHA-1 over the normalised instruction sequence

This **normalises away PC-relative targets, absolute addresses and literal-pool
positions**, so functions compiled from the same source — even when linked at
different offsets — produce the **same fingerprint**.

### 17.2 Result: the zoom group shares 245 functions

```text
4001: 646 functions / 615 unique fingerprints
4002: 691 functions / 660 unique fingerprints
4006: 603 functions / 572 unique fingerprints
4003: 669 functions / 637 unique fingerprints

fingerprints common to all three zoom samples: 245
```

**The same fingerprint appears at completely different offsets across the three
models, with strictly identical instruction counts:**

| Fingerprint | 4001 | 4002 | 4006 | Instructions |
|---|---|---|---|---|
| `0131b7e9776bdda5` | 0x030C80 | 0x034AD8 | 0x02035C | 26 |
| `01c4c9e6cb536931` | 0x031056 | 0x034EAE | 0x020732 | 41 |
| `082e9cb9ef4678dc` | 0x02E7F4 | 0x03264C | 0x01DC20 | **93** |
| `0b5c9767c9ea7872` | 0x05F4EC | 0x06A9D8 | 0x056AAE | 76 |
| `06837485a2619dda` | 0x0651E6 | 0x070702 | 0x05B3FA | 45 |

**This directly confirms the "independent linking" conclusion of §16.1** and
**establishes a cross-model function correspondence** — something previously
considered impossible.

### 17.3 ★ Correction: zoom and prime share 358 functions at the code level

§16.2 concluded from variable names that the two groups "share almost nothing
(3 entries, all junk strings)". **Code fingerprints give a different answer:**

```text
zoom union: 1,225 fingerprints
prime union:  637 fingerprints
intersection: 358   -> 29.2% cross-family sharing
```

Cross sample (`4003` is a prime model other than the S-X50):

```text
0131b7e9776bdda5   4001:0x030C80  4002:0x034AD8  4006:0x02035C  4003:0x0052A0
082e9cb9ef4678dc   4001:0x02E7F4  4002:0x03264C  4006:0x01DC20  4003:0x002E14
```

**The corrected picture:**

| Level | Zoom ↔ prime sharing |
|---|---|
| Variable names (debug metadata) | ≈ 0 (primes have essentially no variable table) |
| **Machine code (functions)** | **358 functions, 29.2%** |

**So the two lens classes share substantial core control code; the difference is
that prime lenses drop the variable table and the zoom-related logic** — rather
than being "two unrelated firmwares".

### 17.4 Size distribution of shared functions

```text
 0- 19 instructions: 126
20- 39 instructions:  65
40- 59 instructions:  23
60- 79 instructions:  21
80- 99 instructions:   6
100+ instructions :    4 (longest 180+)
```

**Sharing is concentrated in small and medium functions** (utilities, protocol,
math routines), while large functions (most likely lens-specific algorithms) do
not cross models — as expected.

### 17.5 Significance

1. **A cross-model common function set has been found** (245 zoom-shared /
   358 cross-family) — this is **the skeleton of the L-mount control stack**
2. **Annotations can accumulate across models**: a function identified on one
   model can be ported to others
3. **It provides the right tool for cross-model diffing**: different versions of
   the same fingerprint = model-specific changes

### 17.6 Reproduction

```bash
python analysis/lens/lens_fingerprint.py   # address-independent fingerprints + cross-model matching
```

### 17.7 Next steps

1. **Associate** the 578 variable names of §7 with these 245 shared functions
   (which functions read and write which variables)
2. Disassemble the **largest shared function** (180+ instructions) in detail —
   likely core control logic
3. **Cluster** the six models' functions by fingerprint to produce a unified
   "L-mount function index"

---

## 18. ★ Six-model fingerprint clustering: separating runtime library from business logic

All three items from §17.7 are complete.

### 18.1 Clustering overview (six models)

```text
4001: 618 unique fingerprints   4002: 665   4003: 638
4006: 572                       400C: 382   400E: 380
total unique fingerprints: 2,096

distribution by number of models sharing:
  all 6 models :   17
  5 models     :    6
  4 models     :  207
  3 models     :  103
  2 models     :  223
  single model : 1,540     <- model-specific logic
```

Zoom/prime divergence:

```text
zoom group (4001/4002/4006) all have : 245
zoom-only, absent from all primes    :  20   ★ candidate business logic
prime group (4003/400C/400E) all have:  22
```

### 18.2 ★ Important finding: what "all 6 models share" is the compiler runtime library

The initial assumption was "shared by all models = core business logic";
**disassembly refuted it**.

The largest fully-shared function `FN0001` (`5ba6c9099252ca2c`, 93 instructions):

```asm
0x0328BA  movw  r5, #0x7ff           ; IEEE754 exponent mask (11 bits)
0x0328BE  eor.w ip, r1, r3           ; sign-bit XOR
0x0328C2  and   ip, ip, #0x80000000  ; extract sign bit
0x0328C6  ands.w r4, r5, r1, lsr #20 ; extract exponent (>>20)
0x0328D0  cmp   r4, r5               ; compare exponents
0x0328FA  udiv  r6, r1, r3           ; division
0x032902  umull r7, r5, r2, r6
```

**This is `__aeabi_fdiv` (single-precision software float division)** — **a routine
from the ARM EABI compiler runtime library**, not lens business logic.

Ten such arithmetic runtime routines were auto-identified (containing
`udiv`/`sdiv`/`umull`/`smull`):

| Fingerprint | Models sharing | Instructions | Core instruction |
|---|---|---|---|
| `5ba6c9099252ca2c` | 6 | 93 | `udiv` |
| `7eeeb71eac111543` | 4 | 55 | `sdiv` |
| `c0da11e2be5031c4` | 6 | 46 | `umull` |
| `5f1c24b20b22dda1` | 4 | 35 | `udiv` |
| `4a84d1f291a1e089` | 4 | 30 | `udiv` |
| ... (10 in total) | | | |

**Conclusion: high sharing ≠ high business value.** What is most consistent
across models is compiler-generated library code.
**To find lens logic you must look at the functions showing "zoom/prime
divergence".**

### 18.3 ★ The 20 "zoom-group only" functions = the real business logic

Sorted by size (present in zoom lenses, completely absent from primes):

| Fingerprint | Instructions | 4001 location |
|---|---|---|
| `9f87c20b6e3a5642` | **147** | 0x03E3DC |
| `8c3b7813e9f73380` | 76 | 0x03E244 |
| `0b5c9767c9ea7872` | 76 | 0x05F4EC |
| `3eccb866cefcf4ad` | 64 | 0x0297E6 |
| `7e2df981dde770cd` | 63 | 0x05113A |
| `a35d9176b69ddac3` | 57 | 0x0297F4 |
| `36a33adb8b8bcfd4` | 57 | 0x03E4C4 |
| `2bb0271244c92c0c` | 52 | 0x054CC4 |
| `547c5da2a87ac849` | 51 | 0x060378 |
| `371873aef844b6bb` | 43 | 0x048B78 |
| `b61112411f2a1273` | 34 | 0x0296DC |
| `547b7972269b142a` | 32 | 0x03153A |

**The largest, `9f87c20b6e3a5642` (147 instructions @0x03E3DC), disassembles as a
typical command handler:**

```asm
0x03E3DC  push.w {r4,r5,r6,r7,r8,sb,sl,lr}   ; conservative 8-register prologue
0x03E3E0  movs   r5, r0                       ; argument 1
0x03E3E2  movs   r6, r1                       ; argument 2
0x03E3E4  movs   r7, r2                       ; argument 3
0x03E3E6  movs   r4, r3                       ; argument 4
0x03E3EC  movs   r0, #0x13                    ; resource ID 19
0x03E3EE  bl     #0x3dd60                     ; acquire lock
0x03E3F2  cpsid  i                            ; ★ disable interrupts -> critical section
0x03E3F6  ldrb   r0, [r0]                     ; read state
0x03E3F8  tst    r0, r5                       ; bit-state test
0x03E3FA  beq    #0x3e408
0x03E3FC  cpsie  i                            ; enable interrupts
0x03E404  movs   r0, #6                       ; ★ error code 6
0x03E420  movs   r0, #7                       ; ★ error code 7
0x03E426  ldrb.w ip, [r0]
0x03E42A  adds.w ip, ip, #1
0x03E432  cmp.w  ip, #3                       ; ★ ring counter
0x03E438  movs.w ip, #0                       ; wrap around
```

**Recognisable structures:**

| Feature | Meaning |
|---|---|
| `cpsid i` / `cpsie i` | **critical-section protection** (disable/enable interrupts) |
| `movs r0, #0x13` + `bl #0x3dd60` | lock acquisition for **resource ID 19** |
| `movs r0, #6` / `#7` | **error-code return** |
| `adds.w ip,#1` / `cmp ip,#3` / `movs ip,#0` | **modulo-3 ring counter** |

The second one (`8c3b7813e9f73380` @0x03E244) is a **parameter setter**:

```asm
0x03E246  movs   r2, #0
0x03E24C  str    r2, [r3]        ; clear the target
0x03E24E  uxtb   r0, r0          ; parameter as a byte
0x03E254  sxtb   r1, r1          ; parameter as a signed byte
0x03E25A  str    r1, [r0]        ; write to the RAM variable
```

### 18.4 Deliverables

```text
analysis/lens/lens_function_ids.txt            index of the 17 functions shared by all 6 models
analysis/lens/lens_fingerprint_report.txt      full clustering report (classification + runtime-library list)
analysis/lens/lens_shared_biggest.asm          full disassembly of the largest shared function
analysis/lens/lens_zoom_only_funcs.asm         disassembly of the 20 zoom-only functions (★ business logic)
```

### 18.5 Reproduction

```bash
python analysis/lens/lens_cluster.py       # 6-model clustering + index + largest-function disassembly
python analysis/lens/lens_classify.py      # runtime-library identification + zoom-only extraction
python analysis/lens/lens_zoomonly_asm.py  # zoom-only function disassembly
```

### 18.6 Conclusions and methodology takeaway

1. **The code most consistent across models is the compiler runtime library, not
   business logic** — ranking by "sharing degree" alone would mistake
   `__aeabi_fdiv` for a core function
2. **The correct marker of business logic is "model divergence"** (present in
   zoom, absent in prime), not "shared by all models"
3. **20 zoom-only functions have been located**, including a command handler with
   error codes and a critical section
4. **Next**: associate the §7 variable names with these 20 functions, using their
   RAM references (addresses reached via `ldr [pc,#imm]`) to trace variable ownership

---

## 9. Reproduction

```bash
# download (Referer required)
# https://panasonic.jp/support/share2/eww/com/dsc/ff/zip/S-R24105V020.zip
python analysis/lens/lens_analyze.py     # format and segmentation
python analysis/lens/lens_deep.py        # symbol table and code location
python analysis/lens/lens_diff.py        # multi-lens differential
python analysis/lens/lens_common.py      # shared-symbol classification
python analysis/lens/lens_sym_dump.py    # generate the full symbol library
```

---

## 19. ★★ Load base found (0x08000000) — correcting §11.3

After §11.3 withdrew "load address = file offset", the load address remained
open. Re-solving it with **memory-map segment signatures** produced a **definite
answer this time**.

### 19.1 The complete standard Cortex-M memory map

Counting 4-byte values in the whole file by address segment:

| Address segment | Meaning | References |
|---|---|---|
| `0x00000000-0x000FFFFF` | low address/alias | 20,840 |
| `0x08000000-0x08FFFFFF` | **Flash** | **5,191** |
| `0x20000000-0x200FFFFF` | **SRAM** | **4,475** |
| `0x40000000-0x400FFFFF` | **APB/AHB peripherals** | **572** |
| `0xE0000000-0xE00FFFFF` | **Cortex-M SCS (system control)** | **1,346** |

These four segments (Flash / SRAM / peripherals / SCS) make up exactly the
**standard ARM Cortex-M memory map**, which **reconfirms from the memory-layout
angle that this firmware is a Cortex-M program** (consistent with §9).

### 19.2 ★ Decisive evidence: base = 0x08000000

The Flash-segment addresses range over `0x08000000 .. 0x080FFFF1`.
**Checking where they land after subtracting the base:**

```text
0x08000000 -> offset 0x000000: 4c 45 4e 53 2d 55 50 44 41 54 45 2d 46 49 4c 45
                              = "LENS-UPDATE-FILE"   <- exactly the file start!
0x08000019 -> offset 0x000019: 03 07 00 01 00 03 ...   <- header fields
0x0800001A -> offset 0x00001A: 07 00 01 00 03 00 ...   <- header fields
```

**`0x08000000` points exactly at byte 0 of the file, the `"LENS-UPDATE-FILE"`
string** — that is not a coincidence.

**More direct evidence**: the code really does use it as a pointer:

```asm
0x0277D4  ldr  r1, [pc, #0x200]        ; loads 0x08000000
          literal @0x0279D8 = 0x08000000
```

In total **585 `LDR literal` instructions load a Flash-segment address** (the
classic "fetch a data/table address" pattern).

### 19.3 Corrected statement

| | Statement |
|---|---|
| §11.3 original (retracted) | "load address = file offset" ❌ |
| **§19 correction** | **runtime address = file offset + 0x08000000** ✅ |

That is, the `.plf` code/data runs on the device in the Flash space starting at
`0x08000000`, so file offset `X` corresponds to runtime address `0x08000000 + X`.

### 19.4 Address bit distribution: mostly data pointers

```text
1,852 distinct Flash-segment address values:
  even (bit0=0, data pointers)       : 1,585   <- majority
  odd  (bit0=1, Thumb code pointers) :   267
```

**Predominantly data pointers** — meaning the vast majority of these references
point at **constant tables / lookup tables / strings**. A function-pointer table
would show many odd addresses; odd values are only 14%, so **no function-pointer
table was found**.

### 19.5 Unexplained part: out-of-range addresses at the tail

Some addresses exceed the file size once the base is subtracted:

```text
0x080F7C48 -> offset 0x0F7C48   (file is only 0x79756)
0x080FF002 -> offset 0x0FF002
0x080FFFF1 -> offset 0x0FFFF1
```

**The most likely explanation: `.plf` does not contain a complete Flash image**,
only the parts that need updating; the rest of the runtime Flash (initialisation
templates, BSS initial values) is not in the file. This explanation is favoured
because the out-of-range addresses cluster in `0x080F7xxx` / `0x080FFxxx`,
consistent with "the file covers only the low part of Flash".

### 19.6 Significance

1. **It settles the load-address question that §10 / §11.3 had left open**
   (two earlier methods had both failed)
2. **`4001V020.plf` can be loaded directly into Ghidra/IDA with base
   `0x08000000`**, after which all absolute references resolve correctly
3. **Practical benefit for Ghidra**: with the base fixed, recursive descent can
   properly follow `LDR literal → data` and `BL → function`, markedly improving
   automated analysis
4. **Supporting evidence for the Cortex-M verdict of §9**: the memory map matches
   the standard Cortex-M layout exactly

### 19.7 Reproduction

```bash
python analysis/lens/peripheral_scan.py  # address-segment statistics + peripheral/SCS detail
python analysis/lens/verify_base.py      # base 0x08000000 verification + bit distribution
```

### 19.8 Methodology takeaway (compared with the two earlier failures)

| Method | Result |
|---|---|
| Vector-table search (§10.2) | ❌ not found |
| Function-interval test (§11.3) | ❌ vacuous test, retracted |
| **Memory-map segment signatures (§19)** | ✅ **succeeded** |

**Why it worked**: it stopped relying on "the file's internal self-consistency"
(which readily yields trivial conclusions) and instead brought in **external
prior knowledge** — the standard ARM Cortex-M memory map. The fact that
"`0x08000000` points at the file start" only becomes explanatory under that
external constraint, "the standard Cortex-M Flash base".

**Transferable lesson**: when internal evidence repeatedly yields trivial or
contradictory results, bringing in the domain standard (here, the processor
architecture's memory-map conventions) often breaks the deadlock.

---

## 20. No interrupt vector table inside `.plf` (confirming a partial update image)

With the base `0x08000000` known, the vector-table search finally had **precise
conditions**, so the failed attempt of §10.2 was redone.

### 20.1 Search conditions (based on the Cortex-M spec)

A real Cortex-M vector table's first two words must be:

```text
word[0] = initial stack pointer  -> must fall in the SRAM range 0x20000000-0x2003FFFF
word[1] = reset vector           -> must fall in the Flash range, with bit0 = 1 (Thumb state)
```

### 20.2 Result: zero hits

```text
strict (word0 in SRAM, word1 in Flash|1, plus the next 7/8 entries also sane): 0
loose  (only requiring word0 in SRAM and word1 in Flash|1)                   : 0
```

**The file contains no byte combination of "an SRAM address immediately followed
by a Flash|1 address" at all.**

### 20.3 Conclusion: `.plf` is a partial update image

This **independently confirms the §19.5 inference** (which was only a hypothesis
at the time):

> `.plf` **does not contain a complete Flash image**, and therefore contains **no
> runtime interrupt vector table**.

**Corroboration and explanation:**

- file offset `0` holds the `"LENS-UPDATE-FILE-SOF:"` string
- and `0x08000000` **happens to** point at it (§19.2)
- i.e. **byte 1 of the `.plf` = Flash address `0x08000000`**
- but the vector table is a **runtime structure** living in a region the update
  image **does not cover**

**Therefore** the lens MCU's Flash layout should be:

```text
0x08000000  ┌─────────────────────────────┐
            │ ...(not in .plf; vector table?) │  <- factory boot/base firmware
            ├─────────────────────────────┤
            │ .plf-covered region (SOF header + code) │  <- this file
            └─────────────────────────────┘
```

### 20.4 SRAM reference distribution (a side result)

```text
total SRAM-segment references: 3,572
  0x20000000 block: 2,180
  0x20010000 block:   786
  0x20020000 block:   400
  0x20030000 block:   206
```

**SRAM use spans four 64 KB blocks (0x20000000-0x2003FFFF ≈ 256 KB)** — consistent
with the 166 distinct 1 KB blocks of §13.3, indicating the MCU's SRAM is on the
order of 256 KB.

### 20.5 Significance

1. **An incomplete image is itself informative**: it shows the device has a
   separate boot/base firmware region
2. **For Ghidra**: loaded at base `0x08000000` there is **no vector table to
   anchor analysis**, so function entries must be supplied manually (or the 20
   zoom-only functions of §18 used as seeds)
3. **Further analysis needs a complete factory image** of the device, if one can
   be obtained; the `.plf` is only an incremental update package

### 20.6 Reproduction

```bash
python analysis/lens/vector_table.py   # strict/loose vector-table search + SRAM distribution
```

---

## 21. Peripheral register map (250 registers) — and an honest assessment of its signal-to-noise

Using the established base (§19) to parse peripheral accesses, answering "what
peripherals does the lens MCU have".

### 21.1 Peripheral register inventory

```text
0x40000000 segment: 250 distinct registers, 572 references
256B peripheral blocks: 198
```

**Most-referenced registers:**

| Address | References | Inference |
|---|---|---|
| **`0x40011700`** | **48** | ★ busiest — candidate comms data register |
| `0x40000000` | 37 | global control register |
| `0x4000F5A0` | 23 | |
| `0x40078060` | 20 | |
| `0x400170F0` | 16 | |
| `0x400000F0` | 13 | |
| `0x40040000` | 12 | |
| `0x4000F9B0` | 12 | |
| `0x4001EB10` | 12 | |

**Most-referenced peripheral blocks (256B):**

```text
0x40000000 x54    0x40011700 x48    0x4000F500 x27
0x40017000 x24    0x40078000 x20    0x4000F000 x20
0x40040000 x16    0x4000F900 x15    0x4001EB00 x15
```

> **Note**: which peripheral (SPI / UART / I²C / GPIO / Timer) each address belongs
> to **cannot be determined from the address alone** — that needs the MCU's
> reference manual (the part number is unknown). This section provides only the
> **objective address-access hotness**.

### 21.2 ⚠️ The signal-to-noise problem in the function↔address graph (recorded honestly)

Using `LDR literal` pools to build a "function → referenced addresses" mapping gives:

```text
functions with address references: 130
referenced addresses            : 148

most-shared addresses (top 15): all within 0x0801A8xx - 0x0801AAxx
  0x0801A941 referenced by 25 functions
  0x0801A823 by 24
  0x0801A817 by 23
  ...
```

**On the surface this looks like "global data shared by 25 functions", but it is
more likely a statistical artifact**, because:

1. **Seed quality** (noted in §11.5): the `0xB5xx` predicate is ~1/256, and the
   915 seeds include a substantial share of data coincidences
2. **Non-linear scanning**: `walk()` **decodes forward from each seed to the first
   return**; if a seed lands in data or mid-function, its scan range "crosses"
   other functions, causing **the same literal to be counted repeatedly for
   several pseudo-functions**
3. **Tight adjacency**: all hot addresses sit within ~640 bytes
   (`0x0801A8xx-0x0801AAxx`), which looks more like **one contiguous table being
   referenced repeatedly** than 25 independent globals

**So the two results of this section have different reliability:**

| Result | Reliability | Reason |
|---|---|---|
| Peripheral register inventory (§21.1) | **higher** | depends only on the objective condition "byte value falls in the 0x40000000 segment" |
| Function↔address graph (§21.2) | **lower** | depends on seed quality and scan boundaries; includes double counting |

**Fixing the second** requires first solving the seed problem of §11.5 (strict
standard: BL/BLX targets only, landing in a dense code block) — still **open**.

### 21.3 Reproduction

```bash
python analysis/lens/periph_map.py   # peripheral register statistics + function↔address graph
```

### 21.4 Round summary

| Item | Conclusion |
|---|---|
| Load base | ✅ `0x08000000` (§19) |
| Runtime vector table | ❌ not inside `.plf` (§20) |
| Peripheral registers | ✅ 250, busiest `0x40011700` (§21.1) |
| SRAM size | ≈ 256 KB, across four 64 KB blocks (§20.4) |
| Function↔address graph | ⚠️ insufficient signal-to-noise; redo after fixing the seeds (§21.2) |

**Capability available but unused**: since the base is now known, **returning to
Ghidra/IDA is the most efficient next step** — its recursive descent handles the
seeding and boundary problems automatically and is more reliable than hand-rolled
heuristics.

---

## 22. ★ Strict rebuild: the seed problem is quantified (85.5% were data coincidences)

Executing the bottleneck item left over from §11.7 / §21.2: **fix the seeds and
do a real recursive descent**.

### 22.1 Strict standard (double validation)

A function entry must **both**:

1. **be the target of a `BL`/`BLX`** (not a plain `B` — the §11.3 mistake)
2. **itself start with a function prologue** (`PUSH {r0-r7,lr}` = `0xB5xx`, or
   `PUSH.W` with the LR bit)

### 22.2 ★ Result: 915 → 133

```text
all distinct BL/BLX targets        : 2,848
of which are themselves prologues  :   133   (strict)

versus the loose seeds of §11.5 (0xB5xx predicate only): 915
-> under strict validation only 133 remain = 14.5%
-> i.e. 85.5% of the loose seeds were data coincidences
```

**This quantifies the doubt the independent review agent raised in §11.5**
("the predicate is ~1/256, so chance expectation is ~970 hits, close to the
measured 1,147").

### 22.3 A real recursive descent (iterative expansion)

§11.5 had been criticised as "not recursive descent" (it only collected targets
without descending). This round implements real iteration:

```text
round 1: +12 new (total 133)
round 2:  +0     (total 133)
-> immediate convergence
```

**Convergence matters**: the worklist closed completely after adding 12, showing
the **internal call relations of these 133 functions are self-consistent** — they
form a **closed function cluster**. 121 / 133 = 91.0% disassemble fully to a
`return`.

### 22.4 ★ Call-graph self-consistency: 2.3× improvement

```text
strict set (BL target ∩ prologue): BL targets hitting a function entry = 35 / 504 = 6.9%
loose set (prologue predicate only):                                    = 99 / 3308 = 3.0%
```

**The strict standard improves the hit rate 2.3×**, validating the standard.

**But 6.9% is still low, which reveals something new:**

> **`push {..,lr}` is not a complete function-entry test.**
> For **leaf functions** (which call nothing) the ARM compiler often **emits no
> push**, computing directly and returning via `bx lr`; there is also tail-call
> optimisation. So a good many real entries **have no prologue** and are excluded
> by the strict standard.

**Methodology conclusion from this round**: prologues are a **high-precision but
low-recall** criterion.

### 22.5 Function↔address graph: the noise disappears

Redoing the mapping of §21.2 with the strict set:

| | §21.2 (loose seeds) | §22 (strict seeds) |
|---|---|---|
| Functions with address references | 130 | 22 |
| Referenced addresses | 148 | 35 |
| **Max functions sharing one address** | **25** | **2** |

**The "25 functions share one address" artifact disappears entirely, dropping to
at most 2.**

This **directly confirms the §21.2 noise diagnosis** (hot-address clustering came
from double counting) and means: **every "sharing degree" statistic based on
loose seeds is untrustworthy**.

### 22.6 Coverage and size

```text
strict-set functions : 133
instructions covered : 11,255
mean function length : 84.6
median length        : 28
```

The median (28) is far below the mean (84.6) → a **long-tailed distribution**
(a few large functions plus many small ones).

### 22.7 Impact assessment on earlier conclusions

| Earlier conclusion | Affected? |
|---|---|
| Load base `0x08000000` (§19) | ❌ unaffected (depends only on address-segment statistics) |
| Vector table absent from `.plf` (§20) | ❌ unaffected (depends only on byte-pair search) |
| Peripheral register inventory (§21.1) | ❌ unaffected (depends only on address-segment statistics) |
| Cross-model **fingerprint** clustering (§17-18) | ❌ unaffected (fingerprints compare **instruction sequences**, not seed completeness) |
| **Sharing-degree ranking** (§16.2 variable names), function↔address graph (§21.2) | ✅ **affected**, corrected by this section |
| The 694 "trusted functions" (§11.2) | ✅ **overestimate**; the real strict set is 133 |

**Key distinction**: fingerprint clustering (§17) compares **normalised
instruction sequences**, so even with an incomplete entry set, as long as both
models miss/hit the same positions the fingerprints remain comparable — hence
the **245 / 358 shared-function conclusions of §17-18 still hold**.

### 22.8 Reproduction

```bash
python analysis/lens/strict_recursive.py   # strict seeds + real recursive descent + consistency checks
# output: analysis/lens/lens_strict_funcs.txt (the 133 functions)
```

### 22.9 Next step (and why handing off to Ghidra is advisable)

The strict standard fixed **precision**, but **recall** is capped by the
incomplete prologue test: 133 functions / 11,255 instructions is still a low
coverage of a 497 KB file (≈ 2.3% of bytes).

**This is exactly what professional tooling excels at:**

- Ghidra/IDA's recursive descent **does not rely on prologues**: it starts from
  entries and **follows all control flow** (including conditional branches and
  tail calls), deciding code extent by **reachability** rather than pattern matching
- The base is known (`0x08000000`), the ISA is known (ARM Thumb), and there are
  **133 double-validated entries** available as an input seed set

**Suggested next step**: export these 133 entries as a Ghidra script / address
list, load at base `0x08000000`, and let the analyser expand on its own.

---

## 23. ★★ Self-built reachability recursive descent: coverage 2.3% → 36.6%

§22.9 identified "high-precision, low-recall prologue test" and suggested handing
off to Ghidra. **This round reproduces its core mechanism directly with a
reachability method, without external tooling.**

### 23.1 Method: drop pattern matching, use reachability

| | §22 strict | **§23 reachability** |
|---|---|---|
| Entry test | **must have a prologue** (pattern matching) | **just needs to be a BL/BLX target** (no prologue required) |
| Expansion | follow BL only, and only if the target has a prologue | **follow all control flow: `BL`/`BLX`/`B`/`Bcc`** |
| Boundary | first `return` | same, plus branch targets also covered |
| Start set | 133 double-validated entries | same (133 seeds) |

**The core difference**: it no longer asks "does this look like a function?" but
**"is this reachable from known code?"** — the essence of Ghidra's recursive
descent.

### 23.2 ★ Results

```text
iterations          : 1,861,014
reachable code      : 71,507 instructions
function entries    : 133  ->  2,170   (16x)
control-flow edges  : call 98,360  +  branch 192,725  =  291,085

coverage            : 182,184 / 497,494 bytes = 36.6%
```

**Comparison with the §22 strict set:**

| Metric | §22 strict | **§23 reachability** | Change |
|---|---|---|---|
| Function entries | 133 | **2,170** | **16.3×** |
| Instructions covered | 11,255 | **71,507** | **6.4×** |
| Share of file bytes | 2.3% | **36.6%** | **16×** |

**This validates the §22.9 judgement**: the bottleneck was indeed the "prologue
test", not the reachability approach itself.

### 23.3 Call-graph self-consistency 98.9% — but honestly flagged as partly tautological

```text
BL targets hitting a function entry: 13,280 / 13,428 = 98.9%
(compared with: §22 strict 6.9%, §11.5 loose 3.0%)
```

> ⚠️ **Honest caveat**: this 98.9% is **partly tautological**.
> Because this round **defines** "every BL target" as a function entry,
> "BL targets land inside the entry set" largely **follows from the definition**
> and **cannot** be used as an independent quality metric the way §22's 6.9% was.

**The genuinely independent metric is coverage**: 71,507 instructions and
291,085 control-flow edges, all **discovered by reachability** from just 133
seeds — that part **does not depend on the definition** and is real progress.

### 23.4 Function-size statistics are unreliable (cause identified)

```text
"longest function" output:
  0x041108  2469 instructions
  0x041118  2463 instructions
  0x04123C  2352 instructions
```

**A 2,469-instruction single function is implausible** — the cause: this round
also queues **`B`/`Bcc` branch targets for scanning**, so when a branch jumps far
(compiler jump tables, long conditional blocks) the scan **crosses function
boundaries** and the "size" is overestimated.

**Therefore:**
- ✅ **trustworthy**: the reachable code **address set** (71,507 addresses, each
  verified to disassemble validly)
- ❌ **not trustworthy**: function **sizes/boundaries** (affected by branch crossing)

### 23.5 Cumulative progress (§19-23)

| Item | Status |
|---|---|
| Load base | ✅ `0x08000000` (§19) |
| Runtime vector table | ❌ not inside `.plf` (§20) |
| Peripheral registers | ✅ 250, busiest `0x40011700` (§21.1) |
| Strict function set | ✅ 133 double-validated entries (§22) |
| **Reachable code** | ✅ **71,507 instructions / 36.6% of file** (§23) |
| Control-flow graph | ✅ 291,085 edges (call 98,360 / branch 192,725) |
| Function boundaries | ⚠️ recompute after fixing branch crossing |

### 23.6 Reproduction

```bash
python analysis/lens/reachability.py   # reachability descent + coverage + control-flow stats
# output: analysis/lens/lens_reachability.txt (2,170 entries)
```

### 23.7 Next steps (three independent directions)

1. **Fix function boundaries**: separate far cross-function `B`/`Bcc` jumps from
   near intra-function jumps (e.g. do not merge a branch target into the same
   scan when it lies beyond the current function's known extent) → trustworthy sizes
2. **The uncovered 63.4%**: determine whether the remainder is data (constant
   tables/strings) or unreached code; if the latter, the seed set is still incomplete
3. **Apply the reachability method to all six models**: produce each model's
   reachable code set, then compare across models with the §17 fingerprint method
   → a **unified cross-model function correspondence table** (more complete than
   §17's 245)

---

## 24. Function-boundary corrections: the trade-off between three methods is measured

Executing direction 1 of §23.7 (fix boundaries) and measuring the **precision/recall
trade-off** of three methods.

### 24.1 Correction 1: intra-function scan (branches do not cross functions)

Branch following limited to **±8 KB from the entry**, with **branch targets not
starting a new function**:

```text
functions (from the 133 strict seeds) : 133
size median                           : 28 instructions
size mean                             : 148.3
size max                              : 3,255 instructions   <- still implausible
unique coverage                       : 14,644 instructions = 5.9%
call-graph self-consistency           : 90/1747 = 5.2%
```

**Boundary precision improves** (median 28, matching §22), but **coverage drops
to 5.9%** — because it starts only from the 133 seeds and does no global
reachability.

### 24.2 Correction 2: hybrid (all BL targets as entries + intra-function scan)

```text
entry candidates (all BL targets)     : 2,848
valid functions (≥3 instructions)     : 2,726
unique coverage                       : 67,888 instructions = 27.3% of file
size median                           : 88
size mean                             : 189.1
size max                              : 2,469 instructions
★ overlap rate                        : 50,814 / 67,888 = 74.8%
call-graph self-consistency           : 34,105/34,941 = 97.6%
```

**★ The 74.8% overlap rate is a fatal signal** — it shows the **entry set is of
poor quality**: of the 2,848 BL targets obtained by whole-file scanning, **only
133 are themselves prologues**; the remaining 2,715 include many **false "BL"s
detected inside data**. Scanning from false entries necessarily overlaps other
functions heavily.

**Nor does the "max size 2,469 instructions" disappear** — even with the branch
span clamped to 1 KB.

### 24.3 ★ The trade-off between the three methods (the core output of this round)

| Method | Entry source | Precision | Recall | Verdict |
|---|---|---|---|---|
| **§22 strict** | BL target ∩ prologue | **high** (median 28, no anomaly) | **low** (133 functions / 2.3%) | high precision, low recall |
| **§23 reachability** | seeds + control-flow reach | low (boundaries wrong, 2469 insn) | **high** (36.6%) | high recall, low precision |
| **§24 hybrid** | whole-file BL targets | **low** (74.8% overlap) | medium (27.3%) | poor entries, both damaged |

**This is the classic precision-versus-recall trade-off, and this round
quantifies it:**

- **For high precision** a **strong test** (prologue) is required — but that test
  is incomplete (leaf functions have no push)
- **For high recall** the test must be relaxed — which admits false entries from
  data (overlap explodes)
- **Pure reachability (§23)** expands within **known code flow** and introduces no
  false entries, but **boundary determination** needs an extra end-of-function
  condition

### 24.4 Conclusion: the right direction is "collect within the code flow, not whole-file scanning"

Comparing the entry sources of §23 and §24.2:

| | §23 | §24.2 |
|---|---|---|
| Where BL targets come from | **encountered while walking reachable code** | **scanning every byte pair in the file** |
| Result | coverage 36.6%, 98,360 call edges | overlap 74.8%, many false entries |

**§23's approach is the correct one**: collect BL only at positions **already
confirmed to be code**, which inherently excludes data-region false targets.
The whole-file scan of §24.2 introduces contamination.

**Therefore, going forward:**

1. **entries = BL targets found within §23's reachable code flow** (not whole-file scanning)
2. **boundaries = decided by a "return-address stack"** (on `pop pc` / `bx lr` with
   the branch worklist empty) — the structure a compiler-generated function should have
3. **abandon the "whole-file BL scanning" path** (proven to pollute the entry set)

### 24.5 Reproduction

```bash
python analysis/lens/fixed_bounds.py   # correction 1: intra-function scan (±8KB)
python analysis/lens/hybrid.py         # correction 2: all BL targets as entries
# output: analysis/lens/lens_fixed_bounds.txt, analysis/lens/lens_hybrid_funcs.txt
```

### 24.6 Cumulative status (§19-24)

| Item | Status |
|---|---|
| Load base | ✅ `0x08000000` |
| Runtime vector table | ❌ not inside `.plf` |
| Peripheral registers | ✅ 250 |
| Reachable code | ✅ **71,507 instructions / 36.6%** (§23, best coverage so far) |
| Control-flow graph | ✅ 291,085 edges |
| Strict entries | ✅ 133 (double-validated) |
| Function boundaries | ⚠️ three methods measured; the right direction is identified (§24.4), implementation pending |
| Cross-model correspondence | ✅ 245 zoom-shared functions (§17, fingerprint method, unaffected by the boundary problem) |

---

## 25. The correct method implemented: the precision/recall four-quadrant is complete

The correct method identified in §24.4 (collect entries only from the **reachable
code flow** + decide boundaries with a **return stack**) has been implemented.

### 25.1 Implementation points

```python
# entries: accept a BL target as a new function only if it HAS a prologue
for t in set(bls):
    if is_prologue(t):           # <- the key guard against data-region false targets
        entries.add(t)

# boundaries: the branch set is per-function; a return ends the function only
# once the worklist is empty
elif (m == 'pop' and 'pc' in op) or (m == 'bx' and 'lr' in op):
    if work:                     # untraversed branch targets remain -> continue
        progressed = True
    else:                        # worklist empty -> genuine function end
        steps = MAXF
```

### 25.2 ★ Result: clearly the best precision

```text
functions          : 133
code addresses     : 10,203
size median        : 28 instructions
size mean          : 84.6
★ size max         : 981 instructions   (vs 2469 in §23 and §24.2)
★ overlap rate     : 10.3%              (vs 74.8% in §24.2)

BL hitting a prologue entry :  50/790 = 6.3%
BL target landing in code   : 135/790 = 17.1%
```

**Both "max function 981 instructions" and "overlap 10.3%" are the best of the
four experiments** — showing that **return-stack boundaries plus the prologue
guard** do produce a clean function partition.

### 25.3 ★ But the lowest recall: converges immediately after 18

```text
round 1: +18 pending (total 133)
round 2:  +0         (total 133)
-> immediate convergence
```

**The reason for convergence is a highly valuable fact:**

> The other functions called by these 133 **mostly have no prologue** — they are
> **leaf functions** (calling nothing, so the compiler emits no `push`).

**This is the third independent confirmation that "the prologue test is
incomplete"** (raised in §22.9 → generalised in §24.3 → reconfirmed here).
**It also explains why the "915 loose seeds" of §11.5 looked so plentiful**: the
loose predicate happened to catch many leaf functions, but caught an equal number
of data coincidences too.

### 25.4 ★ The four quadrants: the precision/recall trade-off fully measured

| § | Method | Entry test | Size median | Size max | Overlap | Coverage | Position |
|---|---|---|---|---|---|---|---|
| 22 | strict (seeds only) | BL ∩ prologue, follow only prologue targets | 28 | — | — | 2.3% | high precision, low recall |
| **25** | **correct method** | **reachable code flow ∩ prologue + return stack** | **28** | **981** | **10.3%** | **4.1%** | **★ best precision** |
| 24.1 | intra-function scan (±8KB) | 133 seeds | 28 | 3255 | — | 5.9% | boundaries still runaway |
| 24.2 | hybrid (whole-file BL) | whole-file BL targets | 88 | 2469 | **74.8%** | 27.3% | entries polluted |
| 23 | reachability | seeds + all control flow | — | 2469 | — | **36.6%** | **★ best recall** |

**Conclusions:**

1. **Best precision**: the §25 method (overlap 10.3%, max size 981)
2. **Best recall**: §23 reachability (coverage 36.6%)
3. **Why the two cannot be combined**: precision relies on the prologue test, and
   that test is **incomplete** (leaf functions have no prologue)

### 25.5 Practical results already achieved

Even with an incomplete function partition, **the results so far amply support
practical analysis**:

| Capability | Status | Artifact |
|---|---|---|
| Plaintext code location | ✅ | the 71,507-instruction reachable set of §23 |
| Precise (local) function partition | ✅ | the 133 high-precision functions of §25 |
| **Cross-model function correspondence** | ✅ | the 245 shared functions of §17 (fingerprints, boundary-independent) |
| **Business-logic location** | ✅ | the 20 zoom-only functions of §18, disassembled |
| Runtime addressing | ✅ | base `0x08000000` |
| Peripheral inventory | ✅ | the 250 registers of §21.1 |

**Not achieved, and requiring professional tooling**: full function boundaries —
because identifying **leaf functions** does not come from byte patterns but from
**call-graph completeness and data-flow analysis**, which is exactly what the
Ghidra/IDA stack analyser does.

### 25.6 Reproduction

```bash
python analysis/lens/correct_method.py   # collect within the code flow + return-stack boundaries
# output: analysis/lens/lens_correct_method.txt
```

### 25.7 Complete methodology summary for §19-25

**The three most valuable methodology points of this round (§19-25):**

1. **Bring in an external prior to break a deadlock** (§19): after internal
   self-consistency tests failed twice in a row, the standard Cortex-M memory map
   settled the base `0x08000000` in one step
2. **Voluntarily retract a trivial conclusion** (§11.3 → §19): the "interval test
   covering 98.59% of the file" was recognised as vacuous and withdrawn
3. **Turn precision/recall from an argument into a measurement** (§22 → §25):
   four experiments with comparable metrics made each method's applicable range
   explicit and identified the root constraint (the incomplete prologue test)

---

## 26. ★★ Endpoint segmentation: a seed-free method + a code-region distribution map

§25's recall bottleneck lies in "must have a prologue / must be referenced by a
BL". **This round uses a completely independent anchor: the function-end instruction.**

### 26.1 Method

`bx lr` (`70 47`) and `pop {..,pc}` (`0xBDxx` / `0xe8bd..`) are **hard evidence of a
function end**:

```text
whole-file candidate end points: 2,362
  verified as real end instructions: 2,207
    bx lr        840
    pop{..,pc} 1,170
    popw{..,pc}  352
```

**Segmentation rule**: between two adjacent end points, if the region **decodes
continuously from start to end**, it is **a stretch of executable code** —
**depending on neither seeds nor the prologue test at all**.

```text
regions verified: 1,620
regions failed (cross data / misaligned): 583
coverage: 82,267 instructions = 33.1% of file
```

### 26.2 ★ Leaf-function evidence: 73.4% of region starts have no prologue

```text
region starts with a prologue   :   431
region starts without a prologue: 1,189  (73.4%)
```

**This provides direct structural evidence for the inference of §25.3**: the
number of **leaf functions** missed by the prologue test is **nearly 3×** the
so-called "strict set".

### 26.3 Comparison with existing methods

| Method | Instructions | Share |
|---|---|---|
| §25 correct method (from seeds) | 10,203 | 4.1% |
| §23 reachability | 71,507 | 36.6% |
| **§26 endpoint segmentation (seed-free)** | **82,267** | **33.1%** |

**Endpoint segmentation exceeds the reachability method's coverage** while
depending **not at all on seed quality** — because it does not ask "is this a
function entry?" but only "is this a verifiable stretch of code?".

### 26.4 ★★ Merge: the largest trustworthy code region, 34.7%

```text
A reachability (strict version) : 18,501 instructions =  7.4%
B endpoint segmentation        : 82,349 instructions = 33.1%
A ∩ B                          : 14,563
A ∪ B                          : 86,287 instructions = 34.7%
Jaccard                        : 0.169        <- low overlap, the two complement each other
A only                         :  3,938
B only                         : 67,786
```

> **Note**: in reproducing method A this round the prologue constraint was added
> back to BL targets (unlike §23), hence 18,501 rather than §23's 71,507. This was
> a **deliberate tightening**, to measure how much "strict reachability" and
> "seed-free segmentation" complement each other.

**A Jaccard of only 0.169** shows the two are finding **essentially different
regions**:
- **A only (3,938)**: function bodies with complete prologues — regions that have
  a prologue but are not covered by endpoint segmentation
- **B only (67,786)**: mainly the **leaf-function region** (no prologues, which
  reachability cannot enter)

### 26.5 ★★ Code distribution across the file (the most valuable output)

Code share per 32 KB:

```text
offset        code instr/total   share
0x000000      81/16384      0.5%
0x008000     501/16384      3.1%
0x010000     348/16384      2.1%
0x018000     707/16384      4.3%
0x020000     337/16384      2.1%
0x028000    6568/16384     40.1%  ###
0x030000    4393/16384     26.8%  ##########
0x038000    9488/16384     57.9%  #######################
0x040000   11061/16384     67.5%  ###########################
0x048000   13082/16384     79.8%  ###############################
0x050000   13570/16384     82.8%  #################################
0x058000   12112/16384     73.9%  #############################
0x060000   12091/16384     73.8%  #############################
0x068000    1769/16384     10.8%  ####
0x070000     179/16384      1.1%
0x078000       0/2987       0.0%
```

**The file's three-part structure is thereby established:**

| Region | Range | Size | Nature |
|---|---|---|---|
| **Header** | `0x000000` - `0x028000` | ≈160 KB | **metadata** (container header + segment descriptor table + variable dictionary + strings) |
| **Main code region** | **`0x028000` - `0x068000`** | **≈256 KB** | **executable code** (density 26.8%–82.8%) |
| **Tail** | `0x068000` - `0x079756` | ≈70 KB | **data** (density 10.8% → 0.0%) |

**Key correspondences:**

- §7's **variable dictionary sits at `0x4000-0x9000`** (inside the 160 KB header) ✓
- §21's **peripheral register accesses** should concentrate in the main code region ✓
- §23's **reachable code** also lies mainly at `0x028000+` ✓
- **`0x050000` is the densest code area (82.8%)** — where the core logic lives

**This explains a long-standing puzzle**: why §9 found no function prologue near
`0x000000` — **that is the metadata region; there was never any code there**.

### 26.6 Entry candidates: 721 prologue positions

Within the merged code set, the number of **prologue positions that do not depend
on BL validation** is **721** (versus the 133 of §22 obtained by BL ∩ prologue).

**Source of the difference**: §22 requires "referenced by a BL", whereas some
functions may only be called **indirectly** (function-pointer tables / interrupt
vectors) or lie outside this `.plf`'s coverage — so 721 is a lower bound closer to
the true set of entries under a criterion with no caller requirement.

### 26.7 Reproduction

```bash
python analysis/lens/endpoint_segments.py  # endpoint segmentation
python analysis/lens/merge_code.py         # merge + code-region distribution map
# output: analysis/lens/lens_endpoint_segments.txt, analysis/lens/lens_merged_code.txt
```

### 26.8 §19-26 summary: method matrix

| § | Method | Anchor | Coverage | Precision | Key output |
|---|---|---|---|---|---|
| 22 | strict | BL ∩ prologue | 2.3% | high | 133 trustworthy entries |
| 23 | reachability | seeds + control flow | 36.6% | low (boundaries) | 291,085 control-flow edges |
| 24 | hybrid | whole-file BL | 27.3% | low (74.8% overlap) | proving whole-file scanning pollutes |
| 25 | correct method | code-flow BL + return stack | 4.1% | **highest** (overlap 10.3%) | the precision ceiling |
| **26** | **endpoint segmentation** | **function-end instructions** | **33.1%** | medium | **★ code-region distribution map** |

**Final conclusion**: no single method is both high-precision and high-coverage.
**Endpoint segmentation (§26) is the single best method in terms of coverage and
independence**, and **the merged set (§26.4) is the best available approximation
of "the executable code region that can currently be confirmed"**.

---

## 27. ★★★ Cross-checking with Ghidra: 1,095 → 1,824 functions

### 27.1 The next step §22.9 recommended, actually carried out

§22.9 concluded that the remaining work should be handed to a real decompiler
rather than re-implemented. This section reports doing exactly that, and the
result turns out to settle the precision/coverage trade-off left open in §26.8.

### 27.2 Method

| Setting | Value |
|---|---|
| Loader | `BinaryLoader` (`.plf` is a raw binary, not ELF) |
| Base address | `0x08000000` — **must be given explicitly**, otherwise every address is misaligned |
| Language | `ARM:LE:32:Cortex` |
| Seeds | the 133 doubly-verified entries of §22 |

Procedure:

1. Import the image and let Ghidra run its automatic analysis
   (recursive descent + call graph + decompiler switch analysis).
2. Record the baseline function count.
3. Feed the 133 entries as seeds: for each, disassemble
   (`followFlow=True`, **restricted to the code region** `0x028000..0x068000`)
   and create a function at that address.
4. Re-run analysis and compare.

Note on the base address: Ghidra reports
`Successfully applied "-loader-baseAddr" to "Base Address" (old: "null", new: "0x08000000")`.
Without this, the 133 absolute addresses would not match anything.

### 27.3 ★ Result

| Stage | Total | header-meta | main-code | tail-data |
|---|---|---|---|---|
| Ghidra automatic analysis only | **1,095** | 5 | 1,067 | 23 |
| + our 133 entries as seeds | **1,824** | 17 | 1,775 | 32 |
| **delta** | **+729 (+66.6%)** | +12 | **+708** | +9 |

Entry overlap:

| | count | share |
|---|---|---|
| Ghidra found on its own | **46 / 133** | 34.6% |
| **only we provide** | **87 / 133** | **65.4%** |

All 87 new entries produced a function (`failed=0`). The 729 new functions split
into **87 directly at our entry points** and **642 discovered by recursive
descent expanding from them**.

### 27.4 Why the two methods are complementary

**(a) Ghidra's blind spot → our value.**
Ghidra expands outward from what it can already reach by call graph. The 87
entries it cannot reach by itself are exactly the seeds that unlock the 642
additional functions. In other words: **a prologue-based scan and a recursive
descent fail in different places, and the union is substantially larger than
either.**

**(b) Our blind spot → Ghidra's value.**
The prologue criterion of §22 is **structurally blind to leaf functions**:
compilers do not emit a `push` prologue for a function that calls nothing.
§26.2 already measured this (73.4% of region starts carry no prologue). After
seeding, **226 of the 708 new functions in the main code region have no `push`
prologue but do have a return** — i.e. leaf functions that the §22 criterion
could never enumerate.

This closes the §26.8 conclusion. It is not that no method exists with both high
precision and high coverage — it is that **such a method requires a real
recursive descent, which is what a decompiler provides**. The self-built
approaches of §23–26 were the right preparation (they produced the 133 verified
seeds and the code-region distribution map that make the base address and the
region restriction trustworthy), but not the final answer.

### 27.5 Quality verification by region and instruction class

Classification criteria: `push` in the first four instructions = prologue;
`bx lr` or `pop {…,pc}` anywhere = return; mnemonics starting with `v`
(excluding `vpush`/`vpop`), plus `svc`/`udf`/`cdp`/`mcr`/`ldc` = suspicious
(typical of data being read as Thumb instructions).

| Region | n | has prologue | has return | suspicious |
|---|---|---|---|---|
| header-meta (`< 0x028000`) | 17 | 2 (11.8%) | 1 (5.9%) | **8 (47.1%)** |
| **main-code** (`0x028000`–`0x068000`) | **1,775** | 431 (24.3%) | 762 (42.9%) | **24 (1.4%)** |
| tail-data (`> 0x068000`) | 32 | 7 (21.9%) | 22 (68.8%) | 0 (0.0%) |

**97.3% of the 1,824 functions lie in the main code region, where the suspicious
rate is only 1.4%.** The 12 new functions in the header region carry a 47.1%
suspicious rate: these are `followFlow` overshoot into metadata, and they are
**identifiable and excludable by region** — which is only possible because §26
established the region boundaries.

The low prologue share (24.3%) is itself a finding: it means **most functions in
this firmware are leaf functions or use a non-standard prologue**, which is the
quantitative reason the §22 criterion was so restrictive.

### 27.6 An error I made and corrected

Recorded for completeness, because the first version of this measurement was
wrong in two independent ways:

1. **Sampling bias.** My first spot-check sorted the new functions by address and
   inspected the first few. Those happened to be the smallest offsets — which
   land in the header metadata region — so the sample suggested "the new
   functions are mostly garbage". Stratifying by region showed the false
   positives are only 12 of 729 (1.6%), concentrated in one region.

2. **Misread API semantics.** I read the third argument of
   `ArmDisassembleCommand(startAddr, restrictedSet, followFlow)` as a
   "force" flag and set it to `False` to be conservative. It is actually
   `followFlow`. With `False`, 32 of the 87 entries failed to produce a
   function. The correct usage is `followFlow=True` **with `restrictedSet`
   bounded to the code region**, which yields all 87 and keeps the overshoot
   visible and separable.

Both errors are the same failure mode as §21.2 and §22: a plausible reading of a
small sample standing in for a stratified measurement.

### 27.7 Updated method matrix

| § | Method | Anchor | Coverage | Precision | Key output |
|---|---|---|---|---|---|
| 22 | strict | BL ∩ prologue | 2.3% | high | 133 trustworthy entries |
| 23 | reachability | seeds + control flow | 36.6% | low (boundaries) | 291,085 control-flow edges |
| 24 | hybrid | whole-file BL | 27.3% | low (74.8% overlap) | proving whole-file scanning pollutes |
| 25 | correct method | code-flow BL + return stack | 4.1% | highest (overlap 10.3%) | the precision ceiling |
| 26 | endpoint segmentation | function-end instructions | 33.1% | medium | code-region distribution map |
| **27** | **Ghidra + our seeds** | **recursive descent from 133 verified entries** | **1,775 functions in the code region** | **high (1.4% suspicious)** | **★★★ 1,095 → 1,824 functions; 226 leaf functions recovered** |

**Revised conclusion**: the trade-off in §26.8 is real *for a self-built
scanner*, but a real recursive descent removes it. The 133 entries of §22 were
not an end in themselves — they are the input that makes the recursive descent
complete.

### 27.8 Reproduction

```bash
# 1) import once (a raw binary needs an explicit base address)
support/analyzeHeadless.bat <projDir> <projName> \
    -import firmware/4001V020.plf \
    -processor ARM:LE:32:Cortex \
    -loader BinaryLoader -loader-baseAddr 0x08000000

# 2) seed with the verified entries and compare
export GHIDRA_INSTALL_DIR=<ghidra dir>
export JAVA_HOME=<jdk 21>
python analysis/lens/ghidra_crosscheck.py \
    --project-dir <projDir> --project-name <projName> \
    --program /4001V020.plf --outdir out
# output: functions_baseline.tsv, functions_with_seeds.tsv
```

Requires Ghidra 12.1.x (JDK 21) and `pip install pyghidra`.

---

## 28. ★★ A second embedded table: the RTOS resource table

### 28.1 Where this sits relative to §3

§3 reported an embedded symbol table of **578 entries** — the lens's **variable
dictionary**, located in the header at `0x4000`–`0x9000`, and §7 dissected its
record format.

This section reports a **separate, second table**: a set of **RTOS resource
names** that is **not** among those 578 entries and sits in the **code region**,
not the header. It was found while cross-checking string references with Ghidra
(§27): almost no string in this firmware is referenced by an instruction, but
one contiguous run of names in the code region turned out to be a
**fixed-stride resource table**.

### 28.2 The table

Record stride is **12 bytes** (name + NUL, zero-padded), 22 resources plus 2
semaphores, spanning 288 bytes:

| Kind | Count | Names |
|---|---|---|
| **Task** (`_TSK`) | 9 | `INITIAL_TSK` `DATA_LATCH_TSK` `TRANS_TSK` `EXP1_TSK` `EXP2_TSK` `BLCOM_TSK` **`CMD_TSK`** `USER_TSK` `OIS_TSK` |
| **Semaphore** (`SEM_`) | 2 | `SEM_MS_SUBFI` `SEM_MS_SUBO` |
| **Flag** (`_FLG`) | 7 | `USER_FLG` **`UART_FLG`** `OIS_FLG` `EXP1_FLG` `EXP2_FLG` `TRANS_FLG` **`SPI_SUBFI_FLG`** |
| **Data queue** (`_DTQ`) | 4 | `BLCOM_DTQ` **`CMD_DTQ`** `OIS_DTQ` `DATA_LATCH_DTQ` |
| **Cycle** (`_CYC`) | 2 | `USER_CYC` `OIS_CYC` |

Raw bytes around the table start (`4001V020.plf`, file offset `0x2bbc8`):

```text
0002bbc8  fb a0 03 10 91 44 06 10   49 4e 49 54 49 41 4c 5f   .....D..INITIAL_
0002bbd8  54 53 4b 00 44 41 54 41 5f 4c 41 54 43 48 5f 54 53   TSK.DATA_LATCH_TS
0002bbe8  4b 00 00 54 52 41 4e 53 5f 54 53 4b 00 00 00 45 58   K..TRANS_TSK...EX
```

The 8 bytes preceding the first name (`fb a0 03 10 91 44 06 10`) read as two
little-endian words `0x1003a0fb` / `0x10064491` — consistent with code
addresses, i.e. a small pointer/count header ahead of the name block. This is
recorded as an observation, not a confirmed structure.

### 28.3 Cross-model: a clean two-way platform split

Extracting this table from all six lenses gives an unambiguous division that is
**not** the zoom/prime axis:

| Firmware | Lens | Type | `_TSK` | `_FLG` | `_DTQ` | `_CYC` | `SEM_` | table span |
|---|---|---|---|---|---|---|---|---|
| `4001V020.plf` | S-R24105 | zoom | 9 | 7 | 4 | 2 | 2 | `0x2BBD0`–`0x2BCF0` |
| `4002V020.plf` | S-R70200 | zoom | 9 | 7 | 4 | 2 | 2 | `0x2FA40`–`0x2FB60` |
| `4006V020.plf` | S-E2470 | zoom | 9 | 7 | 4 | 2 | 2 | `0x1AFF0`–`0x1B110` |
| **`4003V020.plf`** | **S-X50** | **prime** | **9** | **7** | **4** | **2** | **2** | `0x220`–`0x340` |
| `400CV020.plf` | S-S85 | prime | 0 | 0 | 0 | 0 | 0 | — |
| `400EV020.plf` | S-S50 | prime | 0 | 0 | 0 | 0 | 0 | — |

Four lenses share **all 22 resource names and both semaphore names
identical**, at the same 288-byte stride, only relinked to different offsets.
Two lenses have **none of it**.

### 28.4 `4003` (S-X50) is the informative case

`4003` is a **prime** lens yet carries the **complete** RTOS table — so the
table is not about zoom. But its **subsystem symbols collapse**:

| Firmware | OIS | Iris | Zoom | Focus | Motor | Gyro |
|---|---|---|---|---|---|---|
| `4001` (S-R24105) | 19 | 13 | 5 | 11 | 2 | 16 |
| `4002` (S-R70200) | 19 | 13 | 5 | 11 | 2 | 16 |
| `4006` (S-E2470) | 18 | 11 | 5 | 10 | 2 | 16 |
| **`4003` (S-X50)** | **4** | **0** | **0** | **0** | **0** | **0** |
| `400C` / `400E` | 0 | 0 | 0 | 0 | 0 | 0 |

`4003` keeps the **task framework** but has essentially no **actuator
controller** symbols. Read together with §26, this is self-consistent: the RTOS
skeleton is shared platform code, while the OIS/iris/zoom/focus parameter set is
per-mechanism.

### 28.5 What this establishes

- The lens firmware is a **multi-tasking RTOS**, not a flat control loop: 9
  tasks, 2 semaphores, 7 flags, 4 message queues, 2 periodic cycles.
- **`CMD_TSK` + `CMD_DTQ`** identify the **command path** — a task consuming
  from a dedicated queue. This is the most likely place a host-facing command
  dispatcher lives, and the natural target for anyone analysing the lens
  protocol.
- **`SPI_SUBFI_FLG`** and **`UART_FLG`** name two external interfaces; `BLCOM_*`
  names a third channel with both a task and a queue. `SEM_MS_SUBFI` /
  `SEM_MS_SUBO` are semaphores for a host ("MS") ↔ sub-function path.
- Two of six lenses ship with **no symbols at all** — meaning the symbol set is
  a build-time choice, and any conclusion drawn from symbols must state which
  platform it holds for.

### 28.6 Reproduction

```bash
python analysis/lens/rtos_resources.py firmware/
# lists the resource table, subsystem symbol counts, and the platform split
```

No decompiler is needed — the table is plaintext in the image.
