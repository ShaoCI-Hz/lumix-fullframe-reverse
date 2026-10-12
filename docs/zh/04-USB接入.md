# DC-S5M2X 协议层(USB/PTP)接入 — 现状与入口

---

## 1. 设备身份(已确认)

| 项 | 值 |
|---|---|
| 设备名 | `DC-S5M2X` |
| 厂商 | Panasonic |
| VID:PID | `04DA:2382`(tether/PTP 模式)|
| | `04DA:2372`(MSC 大容量存储模式)|
| PnP ID | `\\?\usb#vid_04da&pid_2382#<SERIAL>#{6bdd1fc6-...}` |
| 硬件 ID | `USB\VID_04DA&PID_2382&REV_0100` |
| 驱动 | `wpdmtp.inf`(MTP USB 设备),Service=`WUDFWpdMtp` |
| 类别 | `{Imaging.Camera}` |
| 传输类 | `{34C445BA-07EB-4b5d-8EE9-F66BB9DA403B}`(MtpUsbscanTransport)|

WIA 已能读到设备(`WIA.DeviceManager` → Manufacturer=Panasonic, Description=DC-S5M2X)。

---

## 2. WPD API 入口(已打通调用)

Windows 上访问 PTP/MTP 的正道是 **WPD API**(`WpdApi.dll` 的 COM 接口)。

**已确认可调用**(C# `CoCreateInstance` + vtable):

| 接口 | IID | CLSID |
|---|---|---|
| `IPortableDeviceManager` | `A1567595-4C2F-4574-A6FA-ECEF917B9A40` | `0af10cec-2ecd-4b92-9581-34f6ae0637f3` |
| `IPortableDevice` | `625E2DF8-6392-4CF0-9AD1-3CFA5F17775C` | `728a21c5-3d9e-48d7-9810-864848f0f404` |
| `IPortableDeviceValues` | `6848F6F2-3155-4F86-B6F5-263EEEAB3143` | `0c15d503-d017-47ce-9016-7b3f978721cc` |
| `IPortableDeviceContent` | `6A96ED84-7C73-4480-9938-BF5AF477D426` | |
| `IPortableDeviceKeyCollection` | `DADA2357-E0AD-492E-98DB-DD61C53BA353` | |
| `IPortableDevicePropVariantCollection` | `89B2E422-4F1B-4316-BCEF-A44AFEA83EB3` | |
| `IPortableDeviceServiceManager` | `A8ABC4E9-A84A-47A9-80B3-C5D9B172A961` | |

vtable 槽位:`Open`=3, `GetCapabilities`=4, `GetPnPIdentifier`=5。

**技术要点**:
- COM 接口需用 `CoCreateInstance` + `Marshal.GetDelegateForFunctionPointer` 调 vtable,
  **不能用 `Dispatch`**(WPD 不是自动化接口)。
- `IPortableDevice::Open` 的 `clientInfo` **不能传 null**(返回 `0x80004003 E_POINTER`),
  必须创建一个 `IPortableDeviceValues` 传入。
- PowerShell `Add-Type` 用旧版 C# 编译器,不支持 `out IntPtr` 内联声明等 C# 7 语法。

---

## 3. 当前阻塞(环境限制)

| 阻塞 | 说明 |
|---|---|
| ~~非管理员权限~~ | ✅ **已解决** — 提权后 `WPDBusEnum` 服务已启动(Running/Automatic)|
| ~~设备枚举为空~~ | ✅ **已解决** — 设备注册为 WPD service,不走 `GetDevices`;改用 `IPortableDevice::Open` 直接以 PnP ID 打开 |
| **COM vtable 布局** | ⚠️ **当前阻塞** — `Open` 返回 S_OK 但输出 null 指针,手工 vtable 槽位推断不准 |

**服务已启动**:
```powershell
Start-Process powershell -Verb RunAs -ArgumentList '-Command','Start-Service WPDBusEnum'
# 已验证: WPDBusEnum = Running / Automatic
```text

---

## 4. 当前状态与下一步

**已打通**:设备识别 → WPD COM 创建 → 服务启动 → PnP ID 定位。

**当前卡点**:`IPortableDevice` 的 vtable 手工推断失败(`Open` 输出 null 指针)。
手工 marshal COM 接口需要 Windows SDK 准确的 `wpdportabledevice.h` IDL 定义。

**推荐的正确做法**(避免手工 vtable):

1. **用 Windows SDK 的 WPD API** —— 直接 `#include <WpdApi.h>`,让编译器解析接口
2. **用 C# COM Interop 程序集** —— `tlbimp WpdApi.dll` 生成强类型封装
3. **现成库**:
   - [`python-wpd`](https://github.com/) / `libwpd`
   - **`libusb` + WinUSB 驱动**(zadig 换驱动)→ 直接发 PTP bulk 命令,**最可控**
   - `gphoto2`(若支持 Lumix)
4. **`IPortableDeviceServiceManager`**(IID `A8ABC4E9-...`)—— 因设备是 service 注册,这条路可能更顺

**目标**:`GetCapabilities` → 支持的 PTP 操作 → **Panasonic 私有 opcode**。

**协议层分析的落点** —— 记录 PTP 厂商命令对相机(拍摄/参数/取景)的作用,
不涉及固件密钥。

---

## 5. 与固件加密的关系

固件数据分区已确认为密文(`docs/03`:AES-CTR + 机型相关密钥)。
协议层分析**不涉及解密** —— 记录设备自身的响应与行为,无需逆向密钥。
功能配置的判定逻辑同理,位于运行时的 `program` 中,静态分析不可见。
