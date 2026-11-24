# UltraWolves — G-Wolves Fenrir Asym 8K（PAW3950）增强固件与命令行工具包

> **免拆机纯 USB 刷写 · 全功能真机实证 · 随时 60 秒无损退回官方原厂**  
> 本发布包包含面向 **G-Wolves Fenrir Asym 8K** 鼠标的最新 **UltraWolves** 增强固件，以及配套的跨有线/无线命令行配置、传感器快照诊断与安全刷写工具。
>
> 👶 **纯小白 / 懒得看参数表？直接点这里看人话版 3 分钟速通教程 → [docs/00_小白速通指南_ELI5.md](docs/00_小白速通指南_ELI5.md)**

---

## 一、适用硬件与版本门禁（刷前必看！）

本固件与工具**仅适用于以下完全匹配的硬件与官方固件家族**，严禁刷入任何其他型号鼠标或传感器分支：

| 检查项 | 必须满足的值 | 说明 |
| --- | --- | --- |
| **鼠标型号** | G-Wolves Fenrir Asym 8K | nRF52840 + PAW3950 |
| **USB VID:PID** | `0x33E4:0x3508`（APP）/ `0x33E4:0x3506`（Bootloader） | 有线直连识别；8K 接收器为 `0x33E4:0x3517` |
| **原厂基础版本** | `v1.00.39.00`（Bootloader `B0.02.03.00`） | 刷写前后版本仍报 `01.00.39.00` |
| **传感器分支** | **仅限 `ID53`（PAW3950，`0x00:0x00 = 0x53`）** | 工具固件内置 `ID53` 隔离检查，非 `ID53` 拒绝修改 |
| **8K 接收器状态** | **保持原厂 `v1.00.39.00`，无需刷接收器** | 本包不修改、不刷写无线接收器 |

---

## 二、核心增强特性一览

### 1. 刷入即自动生效（0 风险底层修复）
- **运动累加器并发原子保护（`atomic_accum`）**：防止高频 `SPIM3` 传感器中断与主循环/无线发送交错时丢计数。
- **USB `EP81` 队列防覆盖保护（`queue_guard`）**：防止有线高速轮询发送繁忙时丢失微动/位移快照。
- **即时生效 4 段消抖（`0x05` instant reload）**：改完按键消抖无需重插即刻生效，支持 4 段 `0 ms`。
- **`HardFault` 自救弹射 Bootloader**：极端异常自动写入标志并重启进入 `0x3506`，免拆机有线即可救回。
- **独立 `0x000EA000` CRC16 配置页（`v4`）**：高级传感器设置独立保存、掉电不丢，且不污染原厂 DPI/宏配置。

### 2. 真机实测通过的可开关与自定义功能（支持有线 & 8K 无线实时热改）
- ✅ **38 档 PAW3950 FPS 帧率预设 + `255` 完全自定义**：覆盖 `20k`、`19k`..`4k` 及多组动态阶梯档，或自定 `(U, slow, fast)` 三元组。
- ✅ **`downshift`（`05:44=0x45`）+ `fix-a`（`00:4E/4F/51/52=0x0257`）**：关闭停顿自动降帧与 DPI 上限锁定，实测采用 `07:40=0x41` 开锁写入后将 4 寄存器上限提升至 `30,000 CPI` 并在真实芯片读回完全吻合。
- ✅ **`smoothing`（`0C:4D=0x02`）**：可一键关闭高频平滑滤波。
- ✅ **`direct-motion`（传感器中断直发）**：无线实测 92% 运动包直接从 `SPIM3` 中断发出、`0` 推迟、`0` 阻塞。
- ✅ **`ce-static`（静态节能态复用高精度调校）**：将低 DPI 路径 14 项 `Bank 5 / Bank 9` 参数对齐到高性能分支，可随时开关还原。
- ✅ **`lod-raw`（`18:7A` 原始抬起高度）**：无线即可实时微调原始 LOD 寄存器（如 `0x00` 极低 `0.7mm`、`0x85` `1.0mm`、原厂 `0x8F` `2.0mm`）并支持实时读回任意 PAW3950 寄存器（`reg-read`）。
- ✅ **`anti-slam`（落地 / 抬起防误触延时窗口）**：默认保持原厂 `16 ms / 20 ms`，支持 `0..100 ms` 独立自定义。
- ✅ **`plock`（`TIMER1` 调相锁，已修通实机验证）**：抓拍点已前移至 `IRQ9` 入口（`0x008842`，彻底隔离传感器轮询耗时抖动）并采用 `±8 µs` 死区；真机实测 `learn -> entry` 相位误差 `0..1 µs`、`plock_adjusts=0` 零误调，可按需开启。

### 3. 实验功能与禁用边界
- ℹ️ **`eager-wake`（`IRQ6` 静止秒醒）**：默认关闭，按需开启（需同时开启 `direct-motion`）。
- 🚫 **`mouse-abs`（无线 `u16 ABS` 模式）**：**在原厂接收器上严禁开启！** 该模式发出 `type 0x0A` 绝对坐标包，必须配合配套改版接收器使用；原厂接收器无法识别会导致无线指针不动（仅默认关闭作为兼容预留）。

---

## 三、目录结构

```text
UltraWolves/
├── README.md                              # 本说明文档
├── SHA256SUMS.txt                         # 核心文件 SHA-256 校验清单
├── docs/
│   ├── 00_小白速通指南_ELI5.md             # 【推荐新手先看】人话版 3 分钟刷机与抄作业指南
│   ├── 01_刷入固件与安全回滚教程.md         # 从环境安装到有线刷机、回滚原厂与救砖
│   ├── 02_功能总览与推荐日常配置.md         # 各功能实机效果解读与 3 套一键抄作业方案
│   ├── 03_参数自定义完整手册.md             # 38 档 FPS 全表、全部命令行与寄存器说明
│   └── 04_常见问题与避坑指南_FAQ.md         # 高频报错排查与注意事项
├── firmware/
│   ├── UltraWolves_Fenrir_Asym_8K_v1.00.39.00.hex
│   ├── UltraWolves_Fenrir_Asym_8K_v1.00.39.00.manifest.json
│   └── s4_bootloader_B0.02.03.00_verified.json   # Bootloader 安全范围门禁凭证
├── presets/
│   └── example_config_8k_1600dpi.json     # 8K 无线 + 1600DPI + 0ms 消抖配置示例
├── scripts/
│   ├── 00_环境安装.ps1                    # 一键创建 .venv 并安装依赖
│   ├── 01_备份当前配置.ps1                # 自动识别有线/无线并备份 JSON
│   ├── 02_有线刷入增强版固件.ps1           # 校验 SHA-256 -> 只读预检 -> 有线刷入
│   ├── 03_恢复原厂固件.ps1                # 配合官方原厂 HEX + --wipe-ext 干净回滚
│   └── ultrawolves_cli.ps1                     # 自动找 HID 路径的参数调节快捷命令
└── tool/                                  # 纯 Python CLI、固件校验与安全刷写工具源码
```

---

## 四、5 分钟快速上手

1. **安装环境**（Windows 10/11，需提前安装 [Python 3.12+](https://www.python.org/downloads/) 或 `uv`，脚本均会自动识别）：
   ```powershell
   .\scripts\00_环境安装.ps1
   ```
2. **先备份你的原厂配置**（拔掉接收器、有线连鼠标后运行）：
   ```powershell
   .\scripts\01_备份当前配置.ps1 -Mode wired
   ```
3. **有线刷入 UltraWolves 增强固件**（必须拔掉 `0x33E4:0x3517` 接收器，关闭官网驱动/WebHID 网页）：
   ```powershell
   .\scripts\02_有线刷入增强版固件.ps1
   ```
4. **验证并调出你喜欢的参数**（刷完后插线或插回 8K 接收器走无线都可随时调！）：
   ```powershell
   # 无线查看增强版状态（先切回无线，确保鼠标开机）
   .\scripts\ultrawolves_cli.ps1 -Mode wireless adv status

   # 例如：开启 20k 帧率 + 防降帧 (downshift + fix-a) + 关平滑 + 传感器直发
   .\scripts\ultrawolves_cli.ps1 -Mode wireless adv fps --preset 20k --yes
   .\scripts\ultrawolves_cli.ps1 -Mode wireless adv downshift --enable --yes
   .\scripts\ultrawolves_cli.ps1 -Mode wireless adv fix-a --enable --yes
   .\scripts\ultrawolves_cli.ps1 -Mode wireless adv smoothing --enable --yes
   .\scripts\ultrawolves_cli.ps1 -Mode wireless adv p3-ctrl --direct-motion 1 --yes

   # 确认手感满意后，写入独立 Flash 配置页（掉电不丢！）
   .\scripts\ultrawolves_cli.ps1 -Mode wireless adv persist --action save --yes
   ```

👉 详细图文命令请按顺序阅读：
- **[00_小白速通指南_ELI5.md](docs/00_小白速通指南_ELI5.md)**（纯人话，照抄命令 3 分钟搞定）
- [01_刷入固件与安全回滚教程.md](docs/01_刷入固件与安全回滚教程.md)
- [02_功能总览与推荐日常配置.md](docs/02_功能总览与推荐日常配置.md)
- [03_参数自定义完整手册.md](docs/03_参数自定义完整手册.md)
- [04_常见问题与避坑指南_FAQ.md](docs/04_常见问题与避坑指南_FAQ.md)

---

## 五、安全承诺与免责声明

- **绝对不动 Bootloader**：刷写范围严格锁定在 `0x00006000..0x00025000`，代码硬拦截一切 `< 0x00006000` 或 NV 存储页写入。
- **先全字节校验再退出（Verify-Before-Exit）**：全部 `3,968` 包均会先逐字节读回核对，若有任何 1 字节不一致会在退出 `0x3506` 前立即中止，设备安全停在 Bootloader 供直接重刷。
- **不发清配置指令**：工具硬拦截官方升级器退出时的 `0xC0 0x02` 出厂重置指令，保留你自己的按键映射和宏。
- **非官方社区项目**：本项目与 G-Wolves 官方无任何关联，不附带原厂未修改固件镜像；如涉及版权或合规问题请通过 Issue 联系处理。
- **开源协议范围**：根目录 `LICENSE`（MIT）仅适用于本仓库编写的脚本、Python 工具源码与文档，不涵盖任何第三方厂商原厂固件二进制代码。
- 刷机本身仍存在极低概率 USB 物理断线风险（可通过 `03_恢复原厂固件.ps1` 或官方 `FirmwareUpdate.exe` 恢复），使用前请务必阅读 `docs/01_刷入固件与安全回滚教程.md` 并做好个人配置备份；自行刷写即代表理解并自担操作风险。
