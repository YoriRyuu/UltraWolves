# 教程 04：常见问题与避坑指南（FAQ）

### Q1：为什么刷完改完切回无线，回报率变成 `1000 Hz` 了？怎么改回 8K？
**原因**：常规鼠标配置（`0x000EC000`）中的回报率在**有线备份与恢复**时可能会记成有线最高档代码 `1`（1000 Hz）。  
**解决**：切回 8K 接收器无线连接后，跑一条命令即可：
```powershell
.\scripts\ultrawolves_cli.ps1 -Mode wireless set --polling-rate 128 --yes
```

### Q2：跑无线命令时提示 `Pre-flight 2.4G 0x90 reports mouse disconnected (link=0)` 怎么办？
**原因**：这是工具内置的防死锁前置检查——检测到接收器当前没连上鼠标（鼠标关机、深度休眠或未配对），工具主动拦截以免 USB 接口卡死在 `0xA0`。  
**解决**：拨开鼠标开关、动一下或点一下左键唤醒后再重新跑命令即可；如想最稳妥刷配置，插上线用 `-Mode wired`。

### Q3：刷机脚本报错 `Receiver device(s) detected (0x3517)` 不让刷怎么办？
**原因**：保护机制刻意限制“刷机时电脑上**绝对不能插着接收器**”，防止与接收器通道混发 `0xB0` 指令导致接收器进入桥接卡死。  
**解决**：物理拔掉 8K 接收器，只留 USB-C 线直连鼠标本体，然后重跑 `.\scripts\02_有线刷入增强版固件.ps1`。

### Q4：误开启了 `adv mouse-abs` 后无线移动鼠标没反应了怎么恢复？
**原因**：`mouse-abs` 让鼠标发送 `type 0x0A` 无线绝对位移包，而当前接收器为安全考虑保持原厂固件（不识别 `0x0A`）。  
**解决**：
- 若你当时**没有**运行 `adv persist --action save`：直接把鼠标底部电源关掉再打开即可立刻恢复。
- 若已经保存：直接插上有线 USB-C 线（有线走相对位移不受影响），执行：
  ```powershell
  .\scripts\ultrawolves_cli.ps1 -Mode wired adv mouse-abs --disable --yes
  .\scripts\ultrawolves_cli.ps1 -Mode wired adv persist --action save --yes
  ```

### Q5：`plock` 之前听说会频繁微调，现在怎么样了？
已定位根因并彻底修复：此前定时器抓拍排在 `0x01DF40` 传感器采样后面，导致每次采样把函数自身 `10～15 µs` 耗时误算成相位误差，配合 `±2 µs` 窄死区产生每秒 `3,016` 次来回拉锯。新版已将抓拍前移至 `IRQ9` 入口（`0x008842`）并将死区放宽至 `±8 µs`，真机实测 `learn -> entry` 相位误差稳在 `0..1 µs`、`plock_adjusts=0`，已可放心按需开启。

### Q6：刷固件过程中不小心断开了，鼠标停在 Bootloader（`0x3506`）怎么办？
- 鼠标**没有变砖**：Bootloader `< 0x00006000` 从未被改写，且我们的工具在 `Verify` 全过前绝不跳入坏固件。
- 重新插稳 USB-C 线（确保拔掉接收器），直接再次运行 `.\scripts\02_有线刷入增强版固件.ps1` 或 `.\scripts\03_恢复原厂固件.ps1`，脚本会自动认出 `0x3506` 模式跳过切换直接重刷。
- 极端情况下也可用官方原始升级包 `FirmwareUpdate.exe`（仅保留单只待恢复鼠标）直接一键恢复原厂。

### Q7：为什么这个固件没有 `click-core`、`debounce-fixed`、`xtal`、`framesync`？
经过对 `Fenrir+035-8K` 原厂固件与电路硬件逻辑的逐项核实：
- **没有 `click-core`**：本鼠标按键为普通单触点 SPST 微动开关，无双触点引脚可供切换；
- **不需要 `debounce-fixed`**：原厂 `0xC1E8` 消抖引擎与即时重载挂钩已经原生支持 4 段实时 `0 ms`；
- **不需要 `xtal`**：nRF52840 的高频外部晶振（HFXO）在启动与 2.4G 射频入口原本就已常开；
- **不纳入 `framesync`**：按精简与安全范围决策已主动排除。
