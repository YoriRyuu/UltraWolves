**English** | [简体中文](README_zh-CN.md)

# UltraWolves — Unofficial Enhanced Firmware & Toolkit for G-Wolves Fenrir Asym 8K (PAW3950)

> **No-Disassembly USB Flashing · Live-Hardware Verified · 60-Second Lossless Rollback to Stock**  
> This repository contains the **UltraWolves (Phase 3+ with live-verified `fix-a` register unlock sequence)** enhanced firmware for the **G-Wolves Fenrir Asym 8K**, along with wired/wireless configuration tools, sensor snapshot diagnostics, and a byte-verified safe flasher.
>
> 🌐 **Online WebHID Driver (No Install Required for Daily Tuning!)**:  
> **👉 [https://yoriryuu.github.io/uwolevspage/](https://yoriryuu.github.io/uwolevspage/)**  
> Once you flash the UltraWolves firmware over wired USB using the scripts below, you can configure DPI, polling rate, keymap, macros, **and** all UltraWolves enhancements (`fps`, `downshift`, `fix-a`, `smoothing`, `direct-motion`, `plock`, `lod-raw`, `anti-slam`, etc.) directly in **Chrome / Edge** via WebHID! *(Close the WebHID tab while flashing firmware.)*
>
> 👶 **New to this / want the simplest walkthrough? Start with the 3-minute plain-English guide → [docs/en/00_quick_start_eli5.md](docs/en/00_quick_start_eli5.md)**

---

## 1. Hardware & Version Compatibility Gate (Read Before Flashing!)

This firmware and toolkit apply **strictly** to the exact hardware and stock firmware family below. **Never** flash this image onto any other mouse model or sensor variant:

| Check Item | Required Value | Notes |
| --- | --- | --- |
| **Mouse Model** | G-Wolves Fenrir Asym 8K | nRF52840 + PAW3950 |
| **USB VID:PID** | `0x33E4:0x3508` (APP) / `0x33E4:0x3506` (Bootloader) | Wired USB; 8K Receiver uses `0x33E4:0x3517` |
| **Stock Base Version** | `v1.00.39.00` (Bootloader `B0.02.03.00`) | Version string still reports `01.00.39.00` after flashing |
| **Sensor Branch** | **`ID53` only (PAW3950, `0x00:0x00 = 0x53`)** | Firmware enforces `ID53` gate and rejects non-`ID53` writes |
| **8K Wireless Receiver** | **Keep on stock `v1.00.39.00` (do NOT flash receiver)** | This package does not modify or flash the dongle |

---

## 2. Key Enhancements

### 1. Always-On Core Fixes (Active Immediately Upon Flashing)
- **Atomic Motion Accumulator (`atomic_accum`)**: `PRIMASK`-protected motion counter handoff preventing subtle count drops between high-frequency `SPIM3` interrupts and USB/2.4G consumers.
- **USB `EP81` Queue Guard (`queue_guard`)**: Prevents active endpoint overwrite drops during high-rate wired polling.
- **Instant 4-Stage Debounce Reload (`0x05` instant reload)**: Applies button debounce changes immediately without replugging (including `0 ms` across all 4 stages).
- **`HardFault` Bootloader Auto-Recovery**: Writes the bootloader flag and resets into `0x3506` on fault so you can always recover over USB-C without disassembly.
- **Dedicated `0x000EA000` CRC-16 Config Page (`v4`)**: Stores all enhanced sensor settings independently across power cycles without touching stock DPI, keymaps, or macros.

### 2. Live-Verified Runtime Features (Adjustable via WebHID or CLI Over Wired & 8K Wireless)
- ✅ **38 PAW3950 FPS Presets + `255` Full Custom**: Includes `20k`, `19k`..`4k`, dynamic multi-step profiles, or any valid `(U, slow, fast)` triplet.
- ✅ **`downshift` (`05:44=0x45`) + `fix-a` (`00:4E/4F/51/52=0x0257`)**: Disables idle frame-rate downshifting and lifts the internal CPI/frame-rate clamp up to `30,000 CPI` using the verified `07:40=0x41` unlock sequence with chip readback verification.
- ✅ **`smoothing` (`0C:4D=0x02`)**: One-click disable for internal high-frequency smoothing/ripple filtering.
- ✅ **`direct-motion` (SPIM3 ISR Direct Dispatch)**: Dispatches motion packets directly from the sensor interrupt (measured 92%+ direct over 8K wireless with zero queue deferrals or busy stalls).
- ✅ **`ce-static`**: Applies high-performance `Bank 5 / Bank 9` register tuning on the static/low-DPI path (< 7000 CPI), toggleable at runtime.
- ✅ **`lod-raw` (`18:7A` Raw Lift-Off Distance)** + **`reg-read`**: Live wireless adjustment of raw LOD (e.g., `0x00` ~0.7 mm, `0x85` ~1.0 mm, `0x8F` stock ~2.0 mm) and safe bank/register readback.
- ✅ **`anti-slam` (Landing / Lifted Click Guard)**: Retains stock `16 ms / 20 ms` defaults and allows independent `0..100 ms` tuning.
- ✅ **`plock` (`TIMER1` Phase Lock — Fixed & Live-Verified)**: Capture moved to `IRQ9` entry (`0x008842`) ahead of sensor poll jitter with `±8 µs` deadband; live hardware verified `0..1 µs` `learn -> entry` phase error with `plock_adjusts=0`.

### 3. Experimental & Restricted Modes
- ℹ️ **`eager-wake` (`IRQ6` Instant Wake)**: Off by default; optional for idle-to-active wake when `direct-motion` is enabled.
- 🚫 **`mouse-abs` (Wireless `u16 ABS` Mode)**: **NEVER enable on a stock receiver!** It sends `type 0x0A` absolute packets meant only for a custom receiver; enabling it on stock dongle freezes wireless cursor movement.

---

## 3. Repository Structure

```text
UltraWolves/
├── README.md                                  # English README (this file)
├── README_zh-CN.md                            # Simplified Chinese README
├── LICENSE                                    # MIT License (scripts, tool source, docs)
├── SHA256SUMS.txt                             # SHA-256 verification sums
├── docs/
│   ├── en/                                    # English documentation
│   │   ├── 00_quick_start_eli5.md             # 3-minute plain-English quick start
│   │   ├── 01_flashing_and_rollback.md        # Wired flashing, verification & stock rollback
│   │   ├── 02_features_and_presets.md         # Feature overview & ready-to-copy profiles
│   │   ├── 03_configuration_manual.md         # Complete 38-FPS table & CLI reference
│   │   ├── 04_faq_and_troubleshooting.md      # Common issues & recovery FAQ
│   │   └── PROTOCOL.md                        # WebHID frontend protocol specification
│   └── zh-CN/                                 # Simplified Chinese documentation (中文文档)
│       ├── 00_小白速通指南_ELI5.md
│       ├── 01_刷入固件与安全回滚教程.md
│       ├── 02_功能总览与推荐日常配置.md
│       ├── 03_参数自定义完整手册.md
│       ├── 04_常见问题与避坑指南_FAQ.md
│       └── PROTOCOL.md
├── firmware/
│   ├── UltraWolves_Fenrir_Asym_8K_v1.00.39.00.hex
│   ├── UltraWolves_Fenrir_Asym_8K_v1.00.39.00.manifest.json
│   └── s4_bootloader_B0.02.03.00_verified.json
├── presets/
│   └── example_config_8k_1600dpi.json         # Example 8K wireless + 1600 DPI + 0ms debounce JSON
├── scripts/
│   ├── 00_setup_env.ps1                       # Auto-detect uv / Python 3.12+ & build .venv
│   ├── 01_backup_config.ps1                   # Export current stock settings to backups\
│   ├── 02_flash_ultrawolves.ps1               # SHA-256 + dry-run pre-flight + wired flash
│   ├── 03_restore_stock.ps1                   # Clean rollback using official stock HEX + --wipe-ext
│   └── ultrawolves_cli.ps1                    # Auto-locate HID path & run config commands
└── tool/                                      # Python CLI, safety guard, and flasher source
```

---

## 4. 5-Minute Quick Start

1. **Initialize environment** (Windows 10/11 with [Python 3.12+](https://www.python.org/downloads/) or `uv` — auto-detected):
   ```powershell
   .\scripts\00_setup_env.ps1
   ```
2. **Back up your current stock configuration** (unplug the 8K dongle, connect mouse via USB-C):
   ```powershell
   .\scripts\01_backup_config.ps1 -Mode wired
   ```
3. **Flash UltraWolves via wired USB** (8K dongle unplugged; close G-Wolves software and WebHID browser tabs):
   ```powershell
   .\scripts\02_flash_ultrawolves.ps1
   ```
4. **Configure your mouse visually or via CLI** (re-plug the 8K dongle or stay wired):
   - **Option A (Easiest — WebHID Driver)**: Open **[https://yoriryuu.github.io/uwolevspage/](https://yoriryuu.github.io/uwolevspage/)** in Chrome or Edge, connect your mouse/receiver, toggle the features you want, and click **Save to Firmware** (`0x05 save`) when happy.
   - **Option B (PowerShell CLI)**:
     ```powershell
     # Check UltraWolves status over 8K wireless
     .\scripts\ultrawolves_cli.ps1 -Mode wireless adv status

     # Example: 20k FPS + downshift + fix-a + smoothing off + direct-motion
     .\scripts\ultrawolves_cli.ps1 -Mode wireless adv fps --preset 20k --yes
     .\scripts\ultrawolves_cli.ps1 -Mode wireless adv downshift --enable --yes
     .\scripts\ultrawolves_cli.ps1 -Mode wireless adv fix-a --enable --yes
     .\scripts\ultrawolves_cli.ps1 -Mode wireless adv smoothing --enable --yes
     .\scripts\ultrawolves_cli.ps1 -Mode wireless adv p3-ctrl --direct-motion 1 --yes

     # Save enhanced settings permanently to 0x000EA000
     .\scripts\ultrawolves_cli.ps1 -Mode wireless adv persist --action save --yes
     ```

### Documentation Index
- **English**:
  - [00_quick_start_eli5.md](docs/en/00_quick_start_eli5.md) *(Best starting point)*
  - [01_flashing_and_rollback.md](docs/en/01_flashing_and_rollback.md)
  - [02_features_and_presets.md](docs/en/02_features_and_presets.md)
  - [03_configuration_manual.md](docs/en/03_configuration_manual.md)
  - [04_faq_and_troubleshooting.md](docs/en/04_faq_and_troubleshooting.md)
  - [PROTOCOL.md](docs/en/PROTOCOL.md) *(WebHID protocol spec for driver developers)*
- **简体中文**:
  - [00_小白速通指南_ELI5.md](docs/zh-CN/00_小白速通指南_ELI5.md)
  - [01_刷入固件与安全回滚教程.md](docs/zh-CN/01_刷入固件与安全回滚教程.md)
  - [02_功能总览与推荐日常配置.md](docs/zh-CN/02_功能总览与推荐日常配置.md)
  - [03_参数自定义完整手册.md](docs/zh-CN/03_参数自定义完整手册.md)
  - [04_常见问题与避坑指南_FAQ.md](docs/zh-CN/04_常见问题与避坑指南_FAQ.md)
  - [PROTOCOL.md](docs/zh-CN/PROTOCOL.md)

---

## 5. Safety Guarantees, Compliance & Disclaimer

- **Bootloader Never Touched**: Flash range is hard-locked to `0x00006000..0x00025000`; any write below `0x00006000` or to NV storage pages is blocked in code.
- **Verify-Before-Exit**: All `3,968` packets are read back and verified byte-for-byte before exiting Bootloader `0x3506`. Any single-byte mismatch aborts before exit so the mouse stays recoverable in Bootloader.
- **No Factory-Wipe Exit Command**: Blocks the stock updater's `0xC0 0x02` factory-reset exit command so your DPI/keymaps survive flashing.
- **Unofficial Community Project**: Not affiliated with or endorsed by G-Wolves. No unmodified stock firmware image is bundled. Use at your own risk; please back up your settings and read the flashing guide before proceeding.
- **License Scope**: The root [LICENSE](LICENSE) (MIT) applies solely to the original scripts, Python toolkit source code, and documentation written for this project, and does not cover any third-party vendor firmware binary code.

---

## 6. Acknowledgments

Special thanks to the following open-source mouse firmware and reverse-engineering projects whose pioneering work and insights helped inspire and inform **UltraWolves**:

- **[SuperLamzu](https://github.com/Nuitfanee/SuperLamzu)** — for the open-source gaming mouse firmware research and community tooling inspiration.
- **[HyperDrako](https://gitlab.jaceee.dev/open/hyperdrako)** — for the pioneering sensor/firmware enhancement exploration and technical groundwork.

