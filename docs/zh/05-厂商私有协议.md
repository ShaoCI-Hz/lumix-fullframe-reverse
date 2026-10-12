# DC-S5M2X Panasonic 私有协议 — 打通实录

> **状态:✅ 协议层已完全打通** — 枚举到 Panasonic 私有 opcode 并成功执行。

---

## 1. 核心成果

通过 **WPD API** 走 Windows MTP 驱动,**零驱动修改**直接与相机私有协议通信:

```
Open ✓  →  Capabilities ✓  →  GetSupportedVendorOpcodes ✓  →  ExecuteCommand ✓
```

### Panasonic 私有 MTP opcode(已枚举)

| opcode | 十进制 | 说明 |
|---|---|---|
| **0x9102** | 37122 | ✅ 已验证可执行,建立读取上下文 |
| **0x9103** | 37123 | 待测(需在 9102 关闭后) |
| **0x9104** | 37124 | 待测(同上) |

---

## 2. 关键接口定义(权威:Windows SDK `PortableDeviceApi.h`)

> ⚠️ **别手工猜 vtable 槽位!** 用 `[ComImport]` + `InterfaceType(InterfaceIsIUnknown)` 让 .NET 处理 vtable。

### `IPortableDevice`(IID `625E2DF8-6392-4CF0-9AD1-3CFA5F17775C`)
```
3  Open(LPCWSTR, IPortableDeviceValues*)          ← 无 out 参数!
4  SendCommand(DWORD, IPortableDeviceValues*, IPortableDeviceValues**)
5  Content(IPortableDeviceContent**)
6  Capabilities(IPortableDeviceCapabilities**)     ← 名字是 Capabilities,非 GetCapabilities
7  Cancel()
8  Close()
9  Advise(...)  10 Unadvise(LPCWSTR)  11 GetPnPDeviceID(LPWSTR*)
```

### 其它 IID
| 接口 | IID |
|---|---|
| `IPortableDeviceValues` | `6848F6F2-3155-4F86-B6F5-263EEEAB3143` |
| `IPortableDeviceCapabilities` | `2C8C6DBF-E3DC-4061-BECC-8542E810D126` |
| `IPortableDeviceKeyCollection` | `DADA2357-E0AD-492E-98DB-DD61C53BA353` |
| `IPortableDevicePropVariantCollection` | `89B2E422-4F1B-4316-BCEF-A44AFE83EB3` |
| `PortableDeviceValues` CoClass | `0C15D503-D017-47CE-9016-7B3F978721CC` |
| `PortableDevicePropVariantCollection` CoClass | `08A99E2F-6D6D-4B80-AF5A-BAF2BCBE4CB9` |
| `PortableDeviceKeyCollection` CoClass | `DE2D022D-2480-43BE-97F0-D1FA2CF98F4F` |

---

## 3. 命令发送格式(SendCommand)

`SendCommand(flags=0, pParameters, out ppResults)`,参数需两个属性:

```
WPD_PROPERTY_COMMON_COMMAND_CATEGORY  {F0422A9C-5DC8-4440-B5BD-5DF28835658A} pid 1001  [VT_CLSID]
    = 目标命令的 category GUID
WPD_PROPERTY_COMMON_COMMAND_ID        {F0422A9C-5DC8-4440-B5BD-5DF28835658A} pid 1002  [VT_UI4]
    = 目标命令的 PID
```

### MTP 厂商扩展类别(category)
```
WPD_CATEGORY_MTP_EXT_VENDOR_OPERATIONS = {4D545058-1A2E-4106-A357-771E0819FC56}   // ASCII "MTPX"
```

### MTP_EXT 命令 PID(来自 `WpdMtpExtensions.h`)
| pid | 命令 | 用途 |
|---|---|---|
| **11** | `GET_SUPPORTED_VENDOR_OPCODES` | 枚举厂商 opcode |
| **12** | `EXECUTE_COMMAND_WITHOUT_DATA_PHASE` | 无数据阶段执行 |
| **13** | `EXECUTE_COMMAND_WITH_DATA_TO_READ` | 带读数据阶段 |
| **14** | `EXECUTE_COMMAND_WITH_DATA_TO_WRITE` | 带写数据阶段 |
| 15 | `READ_DATA` | 读数据块 |
| 16 | `WRITE_DATA` | 写数据块 |
| **17** | `END_DATA_TRANSFER` | **关闭传输上下文(必做!)** |
| 18 | `GET_VENDOR_EXTENSION_DESCRIPTION` | 厂商扩展描述 |

### MTP_EXT 属性 PID(category = MTPX)
| pid | 属性 | 类型 |
|---|---|---|
| 1001 | `OPERATION_CODE` | VT_UI4(要执行的 opcode)|
| 1002 | `OPERATION_PARAMS` | VT_UNKNOWN(`IPortableDevicePropVariantCollection`,**必填**,可空集合)|
| 1003 | `RESPONSE_CODE` | VT_UI4(MTP 响应)|
| 1005 | `VENDOR_OPERATION_CODES` | VT_UNKNOWN(枚举结果)|
| 1006 | `TRANSFER_CONTEXT` | VT_LPWSTR(**传输上下文句柄**)|
| 1007 | `TRANSFER_TOTAL_DATA_SIZE` | VT_UI8 |
| 1012 | `TRANSFER_DATA` | VT_VECTOR|VT_UI1 |
| 1013 | `OPTIMAL_TRANSFER_BUFFER_SIZE` | VT_UI4 |
| 1014 | `VENDOR_EXTENSION_DESCRIPTION` | VT_LPWSTR |

### 结果中的 COMMON category 属性
| pid | 属性 |
|---|---|
| **1003** | `WPD_PROPERTY_COMMON_HRESULT` — 命令执行 HRESULT |
| 1004 | `WPD_PROPERTY_COMMON_DRIVER_ERROR_CODE` |

> 注意:pid 1003 在 **COMMON** GUID 下是 HRESULT,在 **MTPX** GUID 下是 RESPONSE_CODE,枚举时必须连 fmtid 一起判断。

---

## 4. 验证的执行流程

```
1. IPortableDevice.Open(pnPID, clientInfo=PortableDeviceValues)
2. 枚举厂商 opcode:
   SendCommand(category=MTPX, id=11)
   → 结果 pid 1005 (VT_UNKNOWN) → QI 到 IPortableDevicePropVariantCollection
   → GetCount/GetAt 取出 VT_UI4 → [0x9102, 0x9103, 0x9104]
3. 执行 opcode:
   params = { CATEGORY=MTPX, ID=13, OPERATION_CODE=opcode, OPERATION_PARAMS=空collection }
   → 结果返回 TRANSFER_CONTEXT + TOTAL_DATA_SIZE + OPTIMAL_BUFFER_SIZE
4. 用 context 做 READ_DATA(15) / WRITE_DATA(16)
5. ★ 必须 END_DATA_TRANSFER(17) 关闭 context,否则后续 opcode 返回 ERROR_BUSY(0x800700AA)
```

### 实测输出
```
opcode 0x9102 + cmd13:
   pid=1007 VT_UI8   = 0                    数据大小
   pid=1013           = 262144 (256KB)      最优缓冲区
   pid=1006           = CCustomReadContext{DD5520F4-630A-41EC-8DC3-6AE702BED193}
   pid=1003 HRESULT   = 0x00000000          ← 成功
```

---

## 5. 已知坑

| 问题 | 解决 |
|---|---|
| 手工 vtable 槽位错误 → `E_POINTER` | 用 `[ComImport]` 让 .NET 解析 |
| `Open` 签名无 `out` 参数 | 别把 HRESULT 当设备指针 |
| 方法名 `Capabilities` 而非 `GetCapabilities` | 查 SDK 头文件,别猜 |
| `GetDevices` 返回 0 | 设备是 service 注册;用 PnP ID 直接 `Open` |
| `WPDBusEnum` 服务停止 | 需**管理员**启动 |
| `ref new PROPKEY{...}` 编译错 | 先声明变量再 `ref` |
| PowerShell `Add-Type` 不支持 C# 7 | 避免内联 `out` 声明 |
| **超时中断数据阶段** | **设备 MTP 状态机卡死,软件无法复位,需重新插拔 USB** |

---

## 6. 现状与下一步

**已达成**:从零实现 Panasonic 私有协议通信,枚举并执行厂商 opcode。

**当前设备状态**:因调试中超时中断,设备返回 `0x80070141`,**需重新插拔 USB 复位**。

**待办**:
1. 重新插拔后,完成 0x9103 / 0x9104 的探测
2. 尝试 `EXECUTE_COMMAND_WITH_DATA_TO_WRITE`(14)写入 — 这是**控制相机的写通道**
3. 结合标准 PTP 命令(对象枚举、属性读写)实现实际功能

**工具方向**:把已验证的 C# 接口封装为可复用的 Python(.NET interop)或 C# 工具。
