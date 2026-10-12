# DC-S5M2X Panasonic Private Protocol — How It Was Opened Up

> **Status: ✅ the protocol layer is fully working** — Panasonic-private opcodes
> were enumerated and successfully executed.

---

## 1. Core result

Through the **WPD API** on top of the Windows MTP driver, the camera's private
protocol is reachable with **zero driver modification**:

```
Open ✓  →  Capabilities ✓  →  GetSupportedVendorOpcodes ✓  →  ExecuteCommand ✓
```

### Panasonic private MTP opcodes (enumerated)

| opcode | decimal | Notes |
|---|---|---|
| **0x9102** | 37122 | ✅ verified executable, establishes a read context |
| **0x9103** | 37123 | untested (requires 9102 to be closed first) |
| **0x9104** | 37124 | untested (same) |

---

## 2. Key interface definitions (authoritative source: Windows SDK `PortableDeviceApi.h`)

> ⚠️ **Do not hand-guess vtable slots!** Use `[ComImport]` +
> `InterfaceType(InterfaceIsIUnknown)` and let .NET handle the vtable.

### `IPortableDevice` (IID `625E2DF8-6392-4CF0-9AD1-3CFA5F17775C`)
```
3  Open(LPCWSTR, IPortableDeviceValues*)          <- no out parameter!
4  SendCommand(DWORD, IPortableDeviceValues*, IPortableDeviceValues**)
5  Content(IPortableDeviceContent**)
6  Capabilities(IPortableDeviceCapabilities**)     <- named Capabilities, not GetCapabilities
7  Cancel()
8  Close()
9  Advise(...)  10 Unadvise(LPCWSTR)  11 GetPnPDeviceID(LPWSTR*)
```

### Other IIDs
| Interface | IID |
|---|---|
| `IPortableDeviceValues` | `6848F6F2-3155-4F86-B6F5-263EEEAB3143` |
| `IPortableDeviceCapabilities` | `2C8C6DBF-E3DC-4061-BECC-8542E810D126` |
| `IPortableDeviceKeyCollection` | `DADA2357-E0AD-492E-98DB-DD61C53BA353` |
| `IPortableDevicePropVariantCollection` | `89B2E422-4F1B-4316-BCEF-A44AFE83EB3` |
| `PortableDeviceValues` CoClass | `0C15D503-D017-47CE-9016-7B3F978721CC` |
| `PortableDevicePropVariantCollection` CoClass | `08A99E2F-6D6D-4B80-AF5A-BAF2BCBE4CB9` |
| `PortableDeviceKeyCollection` CoClass | `DE2D022D-2480-43BE-97F0-D1FA2CF98F4F` |

---

## 3. Command format (SendCommand)

`SendCommand(flags=0, pParameters, out ppResults)`; the parameters carry two
properties:

```
WPD_PROPERTY_COMMON_COMMAND_CATEGORY  {F0422A9C-5DC8-4440-B5BD-5DF28835658A} pid 1001  [VT_CLSID]
    = category GUID of the target command
WPD_PROPERTY_COMMON_COMMAND_ID        {F0422A9C-5DC8-4440-B5BD-5DF28835658A} pid 1002  [VT_UI4]
    = PID of the target command
```

### MTP vendor extension category
```
WPD_CATEGORY_MTP_EXT_VENDOR_OPERATIONS = {4D545058-1A2E-4106-A357-771E0819FC56}   // ASCII "MTPX"
```

### MTP_EXT command PIDs (from `WpdMtpExtensions.h`)
| pid | Command | Purpose |
|---|---|---|
| **11** | `GET_SUPPORTED_VENDOR_OPCODES` | enumerate vendor opcodes |
| **12** | `EXECUTE_COMMAND_WITHOUT_DATA_PHASE` | execute with no data phase |
| **13** | `EXECUTE_COMMAND_WITH_DATA_TO_READ` | with a read data phase |
| **14** | `EXECUTE_COMMAND_WITH_DATA_TO_WRITE` | with a write data phase |
| 15 | `READ_DATA` | read a data block |
| 16 | `WRITE_DATA` | write a data block |
| **17** | `END_DATA_TRANSFER` | **close the transfer context (mandatory!)** |
| 18 | `GET_VENDOR_EXTENSION_DESCRIPTION` | vendor extension description |

### MTP_EXT property PIDs (category = MTPX)
| pid | Property | Type |
|---|---|---|
| 1001 | `OPERATION_CODE` | VT_UI4 (opcode to execute) |
| 1002 | `OPERATION_PARAMS` | VT_UNKNOWN (`IPortableDevicePropVariantCollection`, **required**, may be an empty collection) |
| 1003 | `RESPONSE_CODE` | VT_UI4 (MTP response) |
| 1005 | `VENDOR_OPERATION_CODES` | VT_UNKNOWN (enumeration result) |
| 1006 | `TRANSFER_CONTEXT` | VT_LPWSTR (**transfer context handle**) |
| 1007 | `TRANSFER_TOTAL_DATA_SIZE` | VT_UI8 |
| 1012 | `TRANSFER_DATA` | VT_VECTOR\|VT_UI1 |
| 1013 | `OPTIMAL_TRANSFER_BUFFER_SIZE` | VT_UI4 |
| 1014 | `VENDOR_EXTENSION_DESCRIPTION` | VT_LPWSTR |

### COMMON category properties in results
| pid | Property |
|---|---|
| **1003** | `WPD_PROPERTY_COMMON_HRESULT` — command execution HRESULT |
| 1004 | `WPD_PROPERTY_COMMON_DRIVER_ERROR_CODE` |

> Note: pid 1003 under the **COMMON** GUID is an HRESULT, while under **MTPX**
> it is RESPONSE_CODE. When enumerating you must check the fmtid as well.

---

## 4. Verified execution flow

```
1. IPortableDevice.Open(pnPID, clientInfo=PortableDeviceValues)
2. Enumerate vendor opcodes:
   SendCommand(category=MTPX, id=11)
   → result pid 1005 (VT_UNKNOWN) → QI to IPortableDevicePropVariantCollection
   → GetCount/GetAt to pull VT_UI4 → [0x9102, 0x9103, 0x9104]
3. Execute an opcode:
   params = { CATEGORY=MTPX, ID=13, OPERATION_CODE=opcode, OPERATION_PARAMS=empty collection }
   → result returns TRANSFER_CONTEXT + TOTAL_DATA_SIZE + OPTIMAL_BUFFER_SIZE
4. Use the context for READ_DATA(15) / WRITE_DATA(16)
5. ★ END_DATA_TRANSFER(17) is mandatory to close the context, otherwise later
   opcodes return ERROR_BUSY (0x800700AA)
```

### Measured output
```
opcode 0x9102 + cmd13:
   pid=1007 VT_UI8   = 0                    data size
   pid=1013           = 262144 (256KB)      optimal buffer size
   pid=1006           = CCustomReadContext{DD5520F4-630A-41EC-8DC3-6AE702BED193}
   pid=1003 HRESULT   = 0x00000000          <- success
```

---

## 5. Known pitfalls

| Problem | Solution |
|---|---|
| Wrong hand-built vtable slots → `E_POINTER` | use `[ComImport]` and let .NET resolve |
| `Open` signature has no `out` parameter | do not mistake the HRESULT for a device pointer |
| Method is `Capabilities`, not `GetCapabilities` | read the SDK header, do not guess |
| `GetDevices` returns 0 | the device registers as a service; `Open` directly by PnP ID |
| `WPDBusEnum` service stopped | must be started **as administrator** |
| `ref new PROPKEY{...}` compile error | declare the variable first, then `ref` |
| PowerShell `Add-Type` lacks C# 7 | avoid inline `out` declarations |
| **Interrupting the data phase on timeout** | **the device's MTP state machine hangs and software cannot reset it — a USB replug is required** |

---

## 6. Status and next steps

**Achieved**: Panasonic private protocol communication implemented from
scratch; vendor opcodes enumerated and executed.

**Current device state**: due to a timeout during debugging, the device returns
`0x80070141` and **needs a USB replug to reset**.

**To do**:
1. After replugging, complete probing of 0x9103 / 0x9104
2. Try `EXECUTE_COMMAND_WITH_DATA_TO_WRITE` (14) — this is the **write channel for
   controlling the camera**
3. Combine with standard PTP commands (object enumeration, property read/write)
   to implement practical functionality

**Tooling direction**: wrap the verified C# interfaces into a reusable Python
(.NET interop) or C# tool.
