# 镜头固件 —— 完全明文,含符号表(重大发现)

> **核心发现**:Panasonic **镜头固件未加密**,且保留完整函数/变量符号表。
> 这与机身固件(强加密 + ECDSA 签名)形成鲜明对比,是整条逆向路线中**信息量最大的资源**。

---

## 1. 样本

| 项 | 值 |
|---|---|
| 下载 | `https://panasonic.jp/support/share2/eww/com/dsc/ff/zip/S-R24105V020.zip` |
| ZIP 内容 | `4001V020.plf` |
| 压缩后 / 解压后 | 301,572 B / **497,494 B** |
| 熵 | **6.84**(明文,非加密) |
| 零字节 | 70,625(14.20%) |

**对比:机身固件 90–180 MB 且全加密;镜头固件仅 ~0.5 MB 且完全明文。**

---

## 2. 文件格式

```
0x000000  "LENS-UPDATE-FILE-SOF:"     ← Start of File 标记
0x000013  ...头部字段...
0x000058  "LENS-UPDATE-FILE-EOH:"     ← 头部结束标记
0x000078  "HDFLSPPSLFDI"              ← 段标记
          ...数据(ARM 代码 + 符号表)...
0x069038  "CABRIOLET\0\x01A"          ← 内部项目代号
0x079743  "CABRIOLET"                 ← 第二处
文件尾     大量 0xFF(flash 擦除态)+ 结构化表
```

**已知标记**:`LENS-UPDATE-FILE-SOF:` / `LENS-UPDATE-FILE-EOH:`(整文件各出现一次)

---

## 3. ★ 内嵌符号表(578 个符号)

固件内**保留了调试符号**,直接暴露镜头控制逻辑。按功能分类:

### OIS(防抖)
```
OISPwAdjAdjSet        0x005413
OisDVL                0x0055DB
WstOL / WstOL2 / WstFL / WstFL2
```

### 光圈(Iris)
```
IrsSetCrVel2x16       0x0054EF
IrsAct / IrsJmp / IrsPos
```

### 对焦(Focus)
```
FocDrv                0x005793
FocJmp / FocPos / Foc_FreqActSet
Dist5mm               0x00579B
```

### 变焦 / 马达
```
ZmPosAD               0x00581B
ZmPos256ZmMinPlsZmPosAD2ZmPosTrk
MtrMode / DrvActGr / DrvVel / ActSet
```

### 控制状态
```
DbgMode / DrvMode / MoveMode / TarMode / RestMode
TrgtPos / NowPos / PICnt / Result
```

### 信号处理
```
IntFreq / DifAmpP / DifAmpS / AmpPrev / AmpShiftPhShift
ObsGain / Phase
```

> 完整列表见 `analysis/lens_symbols.txt`(578 项,含偏移)。

---

## 4. ★ 是 ARM Cortex-M 代码

`CABRIOLET` 附近即为**标准 ARM Thumb 指令**:

```
0x068FD8  e1 ee 10 0a | 70 47         ← 70 47 = BX LR(函数返回)
0x068FE8  ff f7 d4 ff | af f3 00 80   ← ff f7 = BL(函数调用)
0x069018  80 b5 ... 02 bd             ← 80 b5 = PUSH {R7,LR};02 bd = POP {R7,PC}
0x069038  43 41 42 52 49 4f 4c 45 54  ← "CABRIOLET\0\x01A"
```

**判定:镜头 MCU 为 ARM Cortex-M,固件可直接反汇编(IDAPython/Ghidra,Thumb 模式)。**

---

## 5. 意义与可行动方向

### 5.1 直接价值:镜头控制协议可完整逆向
符号表 + ARM 代码 = 可还原 OIS / 光圈 / 对焦 / 变焦的完整控制算法与寄存器定义。

### 5.2 战略价值:松下并非"全部加密"
机身固件 = **AES 强加密 + ECDSA 签名**;镜头固件 = **完全明文 + 保留符号**。
说明加密是**针对机身的有意选择**,且镜头的"更新文件"格式是**另一套体系**。

### 5.3 ★ 潜在突破口:**相机必须能处理明文固件**
相机要把 `.plf` 通过卡口下发给镜头,说明**相机的固件处理逻辑存在处理明文格式的分支**。

推论方向:
1. 相机固件更新器支持多种容器格式(`UPD` 加密 / `LENS-UPDATE-FILE` 明文)
2. **若能构造符合镜头更新路径的载荷**,或可观察到相机处理明文固件的行为
3. 抓取 **L 卡口总线**(相机下发 `.plf` 时是明文的)可验证并还原协议

### 5.4 其他样本
L 卡口镜头均可下载,命名规律:
```
https://panasonic.jp/support/share2/eww/com/dsc/ff/zip/<型号>V<版本>.zip
例:S-R24105V020.zip / S-E2470V010.zip / S-S85V010.zip ...
内部文件名如 4001V020.plf(4001 = 镜头内部型号码)
```
多镜头固件差分可定位"共享模板"与"型号补丁",快速通吃全部镜头。

---

## 6. 复现

```bash
# 下载(需 Referer)
# https://panasonic.jp/support/share2/eww/com/dsc/ff/zip/S-R24105V020.zip
python analysis/lens_analyze.py   # 格式与分段
python analysis/lens_deep.py      # 符号表与代码定位
```

---

## 7. 待办

1. 用 Ghidra/IDA(Thumb)反汇编 `CABRIOLET` 区段,还原镜头控制函数
2. 下载多个镜头固件做差分,提取共享通信栈
3. 抓 L 卡口总线,验证相机下发的明文格式
4. 探究相机固件更新器是否接受镜头格式的载荷(需相机在线)
