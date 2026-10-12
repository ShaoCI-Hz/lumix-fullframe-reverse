# DC-S5M2X Protocol Layer (USB/PTP) Access — Status and Entry Points

---

## 1. Device identity (confirmed)

| Item | Value |
|---|---|
| Device name | `DC-S5M2X` |
| Vendor | Panasonic |
| VID:PID | `04DA:2382` (tether/PTP mode) |
| | `04DA:2372` (MSC mass-storage mode) |
| PnP ID | `\\?\usb#vid_04da&pid_2382#<SERIAL>#{6bdd1fc6-…}` |
| Hardware ID | `USB\VID_04DA&PID_2382&REV_0100` |
| Driver | `wpdmtp.inf` (MTP USB device), Service=`WUDFWpdMtp` |
| Category | `{Imaging.Camera}` |
| Transport class | `{34C445BA-07EB-4b5d-8EE9-F66BB9DA403B}` (MtpUsbscanTransport) |

WIA already reads the device (`WIA.DeviceManager` → Manufacturer=Panasonic,
Description=DC-S5M2X).

---

## 2. WPD API entry points (calls working)

The proper way to reach PTP/MTP on Windows is the **WPD API** (COM interfaces
in `WpdApi.dll`).

**Confirmed callable** (C# `CoCreateInstance` + vtable):

| Interface | IID | CLSID |
|---|---|---|
| `IPortableDeviceManager` | `A1567595-4C2F-4574-A6FA-ECEF917B9A40` | `0af10cec-2ecd-4b92-9581-34f6ae0637f3` |
| `IPortableDevice` | `625E2DF8-6392-4CF0-9AD1-3CFA5F17775C` | `728a21c5-3d9e-48d7-9810-864848f0f404` |
| `IPortableDeviceValues` | `6848F6F2-3155-4F86-B6F5-263EEEAB3143` | `0c15d503-d017-47ce-9016-7b3f978721cc` |
| `IPortableDeviceContent` | `6A96ED84-7C73-4480-9938-BF5AF477D426` | |
| `IPortableDeviceKeyCollection` | `DADA2357-E0AD-492E-98DB-DD61C53BA353` | |
| `IPortableDevicePropVariantCollection` | `89B2E422-4F1B-4316-BCEF-A44AFEA83EB3` | |
| `IPortableDeviceServiceManager` | `A8ABC4E9-A84A-47A9-80B3-C5D9B172A961` | |

vtable slots: `Open`=3, `GetCapabilities`=4, `GetPnPIdentifier`=5.

**Technical notes**:
- COM interfaces must be called via `CoCreateInstance` +
  `Marshal.GetDelegateForFunctionPointer` against the vtable —
  **`Dispatch` will not work** (WPD is not an automation interface).
- `IPortableDevice::Open`'s `clientInfo` **must not be null** (it returns
  `0x80004003 E_POINTER`); an `IPortableDeviceValues` instance has to be passed in.
- PowerShell `Add-Type` uses an old C# compiler and does not support C# 7 syntax
  such as inline `out IntPtr` declarations.

---

## 3. Current blockers (environmental limits)

| Blocker | Notes |
|---|---|
| ~~Non-admin privileges~~ | ✅ **resolved** — after elevation the `WPDBusEnum` service is running (Running/Automatic) |
| ~~Empty device enumeration~~ | ✅ **resolved** — the device registers as a WPD service, so it does not appear via `GetDevices`; opened directly with `IPortableDevice::Open` using the PnP ID |
| **COM vtable layout** | ⚠️ **current blocker** — `Open` returns S_OK but writes a null pointer; hand-derived vtable slots are not reliable |

**Service already started**:
```powershell
Start-Process powershell -Verb RunAs -ArgumentList '-Command','Start-Service WPDBusEnum'
# verified: WPDBusEnum = Running / Automatic
```

---

## 4. Current status and next steps

**Working**: device identification → WPD COM creation → service start → PnP ID
resolution.

**Current obstacle**: hand-inferring the `IPortableDevice` vtable fails
(`Open` writes a null pointer). Manually marshalling the COM interface requires
the exact IDL definitions from the Windows SDK's `wpdportabledevice.h`.

**Recommended correct approaches** (avoiding a hand-built vtable):

1. **Use the Windows SDK WPD API** — `#include <WpdApi.h>` and let the compiler
   resolve the interfaces
2. **Use a C# COM interop assembly** — `tlbimp WpdApi.dll` to generate a
   strongly-typed wrapper
3. **Ready-made libraries**:
   - `python-wpd` / `libwpd`
   - **`libusb` + WinUSB driver** (swap the driver with zadig) → send PTP bulk
     commands directly, **the most controllable option**
   - `gphoto2` (if it supports Lumix)
4. **`IPortableDeviceServiceManager`** (IID `A8ABC4E9-…`) — since the device
   registers as a service, this route may be smoother

**Goal**: `GetCapabilities` → supported PTP operations → **Panasonic-private
opcodes**.

**This is where protocol-layer analysis lands** — recording what PTP vendor
commands do to the camera (shooting / parameters / live view), without touching
firmware keys.

---

## 5. Relationship to firmware encryption

The firmware data partitions are confirmed to be ciphertext
(`docs/en/03-crypto-analysis.md`: AES-CTR with model-dependent keys).
Protocol-layer analysis **involves no decryption** — it records the device's own
responses and behaviour and requires no key recovery. The same holds for the
logic that decides feature configuration: it lives in `program` at runtime and
is invisible to static analysis.
