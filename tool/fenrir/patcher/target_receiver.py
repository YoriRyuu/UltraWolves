"""Verified landmarks & exact stock preimages for the dual-MCU Fenrir receiver (AT32F405 USB + nRF52820 2.4G).

Strict offline target identity (`v1.00.39.00`):
  - AT32F405 USB MCU : `8K_Dongle_USB_App_FW_v1.00.39.00_20250605.hex` (`0x08006000..0x0800B928`, cave `..0x0800BFFF`)
  - nRF52820 2.4G MCU: `8K_Dongle_2.4G_App_FW_v1.00.39.00_20250605.hex` (`0x00007000..0x0000DA20`, cave `..0x0000DFFF`)
"""

from __future__ import annotations

from dataclasses import dataclass

from fenrir.constants import REPO_ROOT
from fenrir.patcher.hex_io import AddressRange, HexImage
from fenrir.patcher.target_mouse import PreimageSpec

# ---------------------------------------------------------------------------
# AT32F405 USB MCU APP landmarks
# ---------------------------------------------------------------------------

RX_USB_TARGET_NAME = "8K_Dongle_USB_App_FW_v1.00.39.00_20250605"
RX_USB_STOCK_HEX_PATH = REPO_ROOT / "work" / "packages" / "receiver" / "payload" / f"{RX_USB_TARGET_NAME}.hex"
RX_USB_SHA256 = "8ff3861eaf60fc52c2584eea0b850a2f593e3272320c15b87d990a805f662e75"

RX_USB_BASE = 0x08006000
RX_USB_END = 0x0800B928
RX_USB_DEFINED_BYTES = 22824
RX_USB_INITIAL_SP = 0x20003190
RX_USB_RESET_VECTOR = 0x080062C1
RX_USB_ENTRY_POINT = 0x080061E1

RX_USB_CAVE_START = 0x0800B928
RX_USB_CAVE_END = 0x0800C000
RX_USB_CAVE_BYTES = RX_USB_CAVE_END - RX_USB_CAVE_START  # 1,752 B

RX_USB_PROTECTED_RANGES: tuple[AddressRange, ...] = (
    AddressRange(0x08000000, 0x08006000, "at32_bootloader_low"),
    AddressRange(0x0800C000, 0x0802C000, "at32_unverified_post_app_flash"),
    AddressRange(0x0802C000, 0x0802D000, "at32_stock_nv_c000_c400"),
)

# Unreferenced SRAM above InitSP (0x20003190) and well below 0x200197FC
RX_USB_RAM_BASE = 0x20003400
RX_USB_RAM_BYTES = 256

# AT32F405 RAM globals (verified from IDA/Capstone)
USB_RAM_TIM6_PHASE = 0x2000001B
USB_RAM_SPI_CNT = 0x20000020
USB_RAM_SPI_IDLE_CNT = 0x20000021
USB_RAM_WD_TICK_23 = 0x20000023
USB_RAM_STICKY_B0 = 0x20000031
USB_RAM_EP81_PKT = 0x20000044
USB_RAM_EP81_WD_CNT = 0x2000005E
USB_RAM_EP81_BUSY_64 = 0x20000064
USB_RAM_EP0_PENDING = 0x20000070
USB_RAM_SPI_RX_BUF = 0x2000071E
USB_RAM_QUEUE_BASE = 0x2000080C
USB_RAM_QUEUE_STRIDE = 0x40C
USB_RAM_CMD_BUF = 0x2000293C
USB_RAM_PDATA = 0x200029BC
USB_RAM_BOOTLOADER_MAGIC = 0x200197FC

# AT32F405 functions
USB_FN_TIM6_IRQ = 0x08006700
USB_FN_SYSRESET = 0x0800678C
USB_FN_EP0_RX = 0x08006870
USB_FN_CLASS_SETUP = 0x080069FC
USB_FN_CHECKSUM_U8 = 0x08007518
USB_FN_LOCAL_CMD_DISP = 0x08008348
USB_FN_EP81_PUMP = 0x08008484
USB_FN_SPI_POLL = 0x08008680
USB_FN_SPI_PARSE = 0x080087F0
USB_FN_QUEUE_PEEK = 0x08008B8C
USB_FN_QUEUE_COMMIT = 0x08008BCC
USB_FN_QUEUE_PUSH = 0x08008C00
USB_FN_EP81_SUBMIT = 0x08009E0C
USB_FN_SOF_CB = 0x08009F04
USB_FN_CTRL_RECV = 0x0800A5E0
USB_FN_CTRL_SEND = 0x0800A61C
USB_FN_CTRL_STALL = 0x0800A65C

# AT32F405 hook sites
USB_HOOK_GET_PROTOCOL = 0x08006A56
USB_HOOK_GET_IDLE = 0x08006A8E
USB_HOOK_SET_REPORT = 0x08006AA2
USB_HOOK_GET_REPORT = 0x08006AB6
USB_HOOK_GET_DESC_BNE_1 = 0x08006B1A
USB_HOOK_GET_DESC_BNE_2 = 0x08006B2C
USB_HOOK_GET_DESC_BNE_3 = 0x08006B48
USB_HOOK_GET_DESC_SEND = 0x08006B4E
USB_HOOK_GET_INTERFACE = 0x08006B5A
USB_HOOK_CTRL_STALL_SITE = 0x08006BA0

USB_HOOK_EP81_COMMIT = 0x080084EE
USB_HOOK_EP81_BUSY_FIX = 0x08008502
USB_HOOK_SPI_PARSE_MOTION = 0x08008852

USB_HOOK_TIM6_COUNTERS = 0x08006748
USB_HOOK_SOF_CNT_20 = 0x08009F0C
USB_HOOK_SOF_CNT_21_23 = 0x08009F26
USB_HOOK_SPI_POLL_GATE = 0x08008694

RX_USB_PREIMAGES: dict[str, PreimageSpec] = {
    "usb_get_protocol": PreimageSpec(
        USB_HOOK_GET_PROTOCOL,
        bytes.fromhex("a08805eb80010122484603f0dcfd"),
        "usb_get_protocol_0x08006a56",
    ),
    "usb_get_idle": PreimageSpec(
        USB_HOOK_GET_IDLE,
        bytes.fromhex("a28805f10c0000eb82010122484603f0befd"),
        "usb_get_idle_0x08006a8e",
    ),
    "usb_set_report": PreimageSpec(
        USB_HOOK_SET_REPORT,
        bytes.fromhex("092085f86c00e28805f12401484603f096fd"),
        "usb_set_report_0x08006aa2",
    ),
    "usb_get_report": PreimageSpec(
        USB_HOOK_GET_REPORT,
        bytes.fromhex("012085f86c0040223c49484603f0abfd"),
        "usb_get_report_0x08006ab6",
    ),
    "usb_get_desc_block": PreimageSpec(
        0x08006AF0,
        bytes.fromhex(
            "60882221b1eb202f14d1a08820b92d4806882d4f23e04be0a088012803d12b48"
            "06882b4f1be0a088022818d129480688294f14e060882121b1eb202f0fd1a088"
            "10b90926254f0ae0a088012802d10926234f04e0a088022801d10926214f3246"
            "3946484603f062fd20e0"
        ),
        "usb_get_descriptor_0x08006af0",
    ),
    "usb_get_interface": PreimageSpec(
        USB_HOOK_GET_INTERFACE,
        bytes.fromhex("a28805f1180000eb82010122484603f058fd"),
        "usb_get_interface_0x08006b5a",
    ),
    "usb_stall_exit": PreimageSpec(
        0x08006B94,
        bytes.fromhex("484603f061fd00bf00bf03e0484603f05bfd00bf00bf5046bde8"),
        "usb_stall_exit_0x08006b94",
    ),
    "usb_sticky_b0_block": PreimageSpec(
        0x080068D6,
        bytes.fromhex("1848407810b916488078f8b115480079b02806d114480078b8b901201249087016e010480078012802d100200e490870"),
        "usb_sticky_b0_check_0x080068d6",
    ),
    "usb_reset_b0_block": PreimageSpec(
        0x08008392,
        bytes.fromhex("2078b02804d1284829490860fef7f5f9"),
        "usb_reset_b0_0x08008392",
    ),
    "usb_ep81_commit": PreimageSpec(
        USB_HOOK_EP81_COMMIT,
        bytes.fromhex("002000f06cfb"),
        "usb_ep81_commit_0x080084ee",
    ),
    "usb_ep81_busy_fix": PreimageSpec(
        USB_HOOK_EP81_BUSY_FIX,
        bytes.fromhex("012057490870002059490880"),
        "usb_ep81_busy_watchdog_0x08008502",
    ),
    "usb_spi_parse_motion": PreimageSpec(
        USB_HOOK_SPI_PARSE_MOTION,
        bytes.fromhex("06216f48401cfef75efe6d49c979884205d106226b49491c002000f0c8f9"),
        "usb_spi_parse_motion_0x08008852",
    ),
    "usb_tim6_counters": PreimageSpec(
        USB_HOOK_TIM6_COUNTERS,
        bytes.fromhex("0c480078401c0b4908700b480078401c0949087009480078401c08490870"),
        "usb_tim6_counters_0x08006748",
    ),
    "usb_sof_cnt_20": PreimageSpec(
        USB_HOOK_SOF_CNT_20,
        bytes.fromhex("63480078401c62490870"),
        "usb_sof_cnt_20_0x08009f0c",
    ),
    "usb_sof_cnt_21_23": PreimageSpec(
        USB_HOOK_SOF_CNT_21_23,
        bytes.fromhex("5f480078401c5d4908705d480078401c5c4908705c480078"),
        "usb_sof_cnt_21_23_0x08009f26",
    ),
    "usb_spi_poll_gate": PreimageSpec(
        USB_HOOK_SPI_POLL_GATE,
        bytes.fromhex("4a48007804287ddb01204749087000204649087046490870"),
        "usb_spi_poll_gate_0x08008694",
    ),
}

# ---------------------------------------------------------------------------
# nRF52820 2.4G MCU APP landmarks
# ---------------------------------------------------------------------------

RX_2G4_TARGET_NAME = "8K_Dongle_2.4G_App_FW_v1.00.39.00_20250605"
RX_2G4_STOCK_HEX_PATH = REPO_ROOT / "work" / "packages" / "receiver" / "payload" / f"{RX_2G4_TARGET_NAME}.hex"
RX_2G4_SHA256 = "5c0aa0f7e9af35db89968ed36df91cb76451cd0258e429f7c5d9d1385862929e"

RX_2G4_BASE = 0x00007000
RX_2G4_END = 0x0000DA20
RX_2G4_DEFINED_BYTES = 27168
RX_2G4_INITIAL_SP = 0x200040C0
RX_2G4_RESET_VECTOR = 0x000073DD
RX_2G4_ENTRY_POINT = 0x00007201

RX_2G4_CAVE_START = 0x0000DA20
RX_2G4_CAVE_END = 0x0000E000
RX_2G4_CAVE_BYTES = RX_2G4_CAVE_END - RX_2G4_CAVE_START  # 1,504 B

RX_2G4_PROTECTED_RANGES: tuple[AddressRange, ...] = (
    AddressRange(0x00000000, 0x00007000, "nrf52820_bootloader_mbr_low"),
    AddressRange(0x0000E000, 0x00027000, "nrf52820_unverified_post_app_flash"),
    AddressRange(0x00027000, 0x00029000, "nrf52820_stock_nv_27000_28000"),
)

# Unreferenced SRAM above InitSP (0x200040C0) and well below 0x20006FFC
RX_2G4_RAM_BASE = 0x20004200
RX_2G4_RAM_BYTES = 256

# nRF52820 RAM & MMIO landmarks
RAD_RAM_TOGGLE_0 = 0x20000063
RAD_RAM_TOGGLE_1 = 0x20000064
RAD_RAM_MERGE_MODE = 0x20000071
RAD_RAM_SPIS_ACQ_FLAG = 0x200001CD
RAD_RAM_SPIS_PREFETCH_FLAG = 0x200001CE
RAD_RAM_SPIS_IDLE_CNT = 0x200001CF
RAD_RAM_QUEUE_BASE = 0x20001584
RAD_RAM_QUEUE_STRIDE = 0x280
RAD_RAM_SPIS_RX_BUF = 0x200028FC
RAD_RAM_SPIS_TX_BUF = 0x2000297C
RAD_RAM_SPIS_IDLE_BASE = 0x200029FC
RAD_RAM_SPIS_RX_SHADOW = 0x20002AFC
RAD_RAM_MOTION_WORK = 0x20002BF8
RAD_RAM_BOOTLOADER_MAGIC = 0x20006FFC

RAD_MMIO_SPIS0_BASE = 0x40003000
RAD_MMIO_GPIOTE_BASE = 0x40006000

# nRF52820 functions
RAD_FN_GPIOTE_IRQ = 0x000074E8
RAD_FN_SPIS0_IRQ = 0x00007650
RAD_FN_SYSRESET = 0x00007A58
RAD_FN_CHECKSUM_U8 = 0x00008FA4
RAD_FN_QUEUE_INIT_3 = 0x00009448
RAD_FN_READY_PIN = 0x00009AC4
RAD_FN_AFD0_DISP = 0x0000AFD0
RAD_FN_B21C_DISP = 0x0000B21C
RAD_FN_RECONNECT = 0x0000BB80
RAD_FN_QUEUE_POP = 0x0000BE10
RAD_FN_QUEUE_PEEK = 0x0000BE70
RAD_FN_QUEUE_COMMIT = 0x0000BEE8
RAD_FN_QUEUE_PUSH = 0x0000BF28
RAD_FN_HEARTBEAT_800 = 0x0000C198
RAD_FN_TIMER0_STOP = 0x0000C638
RAD_FN_TIMER0_START = 0x0000C67C
RAD_FN_SPIS_POLL = 0x0000C8B0
RAD_FN_RF_MOTION_DECODE = 0x0000CA28

# nRF52820 hook sites
RAD_HOOK_QUEUE_INIT_3_TAIL = 0x0000945C
RAD_HOOK_CAPTURE_RF_B0 = 0x0000CA50
RAD_HOOK_DUAL_MERGE_SAT = 0x0000CB5A
RAD_HOOK_Q2_PUSH_MERGED = 0x0000CBC4
RAD_HOOK_Q2_PUSH_M0 = 0x0000CBF2
RAD_HOOK_Q2_PUSH_S0 = 0x0000CC3C
RAD_HOOK_Q2_PUSH_S1 = 0x0000CC8E
RAD_HOOK_Q2_PUSH_S00 = 0x0000CCBA
RAD_HOOK_SPIS_PREFETCH_PEEK = 0x0000C9AA
RAD_HOOK_SPIS_POLL_COMMIT = 0x0000C8B2
RAD_HOOK_SPIS0_IRQ = 0x00007650
RAD_HOOK_GPIOTE_SYNC = 0x000074F8
RAD_HOOK_SPIS_TIMER0_START = 0x0000C974
RAD_HOOK_SPIS_TIMER0_STOP = 0x0000C99A

RX_2G4_PREIMAGES: dict[str, PreimageSpec] = {
    "rad_queue_init3_tail": PreimageSpec(
        RAD_HOOK_QUEUE_INIT_3_TAIL,
        bytes.fromhex("00200249087002490870"),
        "rad_queue_init3_tail_0x00945c",
    ),
    "rad_capture_rf_b0": PreimageSpec(
        RAD_HOOK_CAPTURE_RF_B0,
        bytes.fromhex("9df81000c0f3c0069df8100005110a24"),
        "rad_capture_rf_b0_0x00ca50",
    ),
    "rad_dual_merge_sat": PreimageSpec(
        RAD_HOOK_DUAL_MERGE_SAT,
        bytes.fromhex("c94a5288c84bdb881a4410b2c64a9288c54b1b891a4411b2"),
        "rad_dual_merge_sat_0x00cb5a",
    ),
    "rad_q2_push_merged": PreimageSpec(RAD_HOOK_Q2_PUSH_MERGED, bytes.fromhex("fff7b0f9"), "rad_q2_push_0x00cbc4"),
    "rad_q2_push_m0": PreimageSpec(RAD_HOOK_Q2_PUSH_M0, bytes.fromhex("fff799f9"), "rad_q2_push_0x00cbf2"),
    "rad_q2_push_s0": PreimageSpec(RAD_HOOK_Q2_PUSH_S0, bytes.fromhex("fff774f9"), "rad_q2_push_0x00cc3c"),
    "rad_q2_push_s1": PreimageSpec(RAD_HOOK_Q2_PUSH_S1, bytes.fromhex("fff74bf9"), "rad_q2_push_0x00cc8e"),
    "rad_q2_push_s00": PreimageSpec(RAD_HOOK_Q2_PUSH_S00, bytes.fromhex("fff735f9"), "rad_q2_push_0x00ccba"),
    "rad_spis_prefetch_peek": PreimageSpec(
        RAD_HOOK_SPIS_PREFETCH_PEEK,
        bytes.fromhex("fff731fa"),
        "rad_spis_prefetch_pop_0x00c9aa",
    ),
    "rad_spis_poll_commit": PreimageSpec(
        RAD_HOOK_SPIS_POLL_COMMIT,
        bytes.fromhex("4f480078002871d000204d490870"),
        "rad_spis_poll_commit_0x00c8b2",
    ),
    "rad_spis0_irq": PreimageSpec(
        RAD_HOOK_SPIS0_IRQ,
        bytes.fromhex("0548006838b1002003490860012003498862034908707047"),
        "rad_spis0_irq_0x007650",
    ),
    "rad_gpiote_sync": PreimageSpec(
        RAD_HOOK_GPIOTE_SYNC,
        bytes.fromhex("32480078401c3149087004f049fe"),
        "rad_gpiote_sync_0x0074f8",
    ),
    "rad_spis_timer0_start": PreimageSpec(
        RAD_HOOK_SPIS_TIMER0_START,
        bytes.fromhex("fff782fe"),
        "rad_spis_timer0_start_0x00c974",
    ),
    "rad_spis_timer0_stop": PreimageSpec(
        RAD_HOOK_SPIS_TIMER0_STOP,
        bytes.fromhex("fff74dfe"),
        "rad_spis_timer0_stop_0x00c99a",
    ),
    "rad_reset_b0_block": PreimageSpec(
        0x0000B026,
        bytes.fromhex("2078b02804d1744875490860fcf711fd"),
        "rad_reset_b0_0x00b026",
    ),
}


def verify_rx_usb_image(image: HexImage) -> None:
    """Verify stock AT32F405 receiver USB APP identity, cave emptiness, and preimages."""
    if image.sha256 != RX_USB_SHA256:
        raise ValueError(f"Unexpected USB receiver SHA-256: {image.sha256} != {RX_USB_SHA256}")
    if (image.base, image.end, len(image.mem)) != (RX_USB_BASE, RX_USB_END, RX_USB_DEFINED_BYTES):
        raise ValueError(f"Unexpected USB receiver span: ({image.base:#x}, {image.end:#x}, {len(image.mem)})")
    if (image.u32(RX_USB_BASE), image.u32(RX_USB_BASE + 4), image.entry) != (
        RX_USB_INITIAL_SP,
        RX_USB_RESET_VECTOR,
        RX_USB_ENTRY_POINT,
    ):
        raise ValueError("Unexpected USB receiver vectors or entry point")
    for spec in RX_USB_PREIMAGES.values():
        image.verify_fingerprint(spec.address, spec.expected, label=spec.label)


def verify_rx_2g4_image(image: HexImage) -> None:
    """Verify stock nRF52820 receiver 2.4G APP identity, cave emptiness, and preimages."""
    if image.sha256 != RX_2G4_SHA256:
        raise ValueError(f"Unexpected 2.4G receiver SHA-256: {image.sha256} != {RX_2G4_SHA256}")
    if (image.base, image.end, len(image.mem)) != (RX_2G4_BASE, RX_2G4_END, RX_2G4_DEFINED_BYTES):
        raise ValueError(f"Unexpected 2.4G receiver span: ({image.base:#x}, {image.end:#x}, {len(image.mem)})")
    if (image.u32(RX_2G4_BASE), image.u32(RX_2G4_BASE + 4), image.entry) != (
        RX_2G4_INITIAL_SP,
        RX_2G4_RESET_VECTOR,
        RX_2G4_ENTRY_POINT,
    ):
        raise ValueError("Unexpected 2.4G receiver vectors or entry point")
    for spec in RX_2G4_PREIMAGES.values():
        image.verify_fingerprint(spec.address, spec.expected, label=spec.label)


# ---------------------------------------------------------------------------
# Phase 4 shared retained RAM offsets & inline patch helper
# ---------------------------------------------------------------------------

P4_MAGIC_BYTES = b"FRP4"
P4_MAGIC_U32 = int.from_bytes(P4_MAGIC_BYTES, "little")  # 0x34505246
P4_ABS_JUMP_LIMIT = 0x4000

# AT32F405 Phase 4 RAM offsets from RX_USB_RAM_BASE (0x20003400)
USB_OFF_MAGIC = 0x00              # u32
USB_OFF_ACC_X = 0x04              # u16
USB_OFF_ACC_Y = 0x06              # u16
USB_OFF_PEND_DX = 0x08            # s32
USB_OFF_PEND_DY = 0x0C            # s32
USB_OFF_ABS_VALID = 0x10          # u8
USB_OFF_LAST_EPOCH = 0x11         # u8
USB_OFF_LAST_SEQ = 0x12           # u8
USB_OFF_SOF_LOCKED = 0x13         # u8
USB_OFF_DIAG_STALLS = 0x20        # u32
USB_OFF_DIAG_CLAMPED = 0x24       # u32
USB_OFF_DIAG_Q0_OK = 0x28         # u32
USB_OFF_DIAG_Q0_FULL = 0x2C       # u32
USB_OFF_DIAG_DEDUP = 0x30         # u32
USB_OFF_DIAG_CSUM_ERR = 0x34      # u32
USB_OFF_DIAG_EPOCH_CHG = 0x38     # u32
USB_OFF_DIAG_EP81_COMMIT = 0x3C   # u32
USB_OFF_DIAG_EP81_BUSY = 0x40     # u32
USB_OFF_DIAG_TIM6_TICKS = 0x44    # u32
USB_OFF_DIAG_SOF_TICKS = 0x48     # u32
USB_OFF_DIAG_SPI_POLLS = 0x4C     # u32

# nRF52820 Phase 4 RAM offsets from RX_2G4_RAM_BASE (0x20004200)
RAD_OFF_MAGIC = 0x00              # u32
RAD_OFF_COMMIT_ABS_X = 0x04       # u16
RAD_OFF_COMMIT_ABS_Y = 0x06       # u16
RAD_OFF_PEND_DX = 0x08            # s32
RAD_OFF_PEND_DY = 0x0C            # s32
RAD_OFF_ABS_VALID = 0x10          # u8
RAD_OFF_SESSION_EPOCH = 0x11      # u8 (1..63)
RAD_OFF_TX_SEQ = 0x12             # u8 (0..15)
RAD_OFF_EPOCH_RESET_PEND = 0x13   # u8 (0|1)
RAD_OFF_Q2_PREFETCHED = 0x14      # u8 (0|1)
RAD_OFF_LAST_RF_B0 = 0x15         # u8
RAD_OFF_TIMER0_ACTIVE = 0x16      # u8
RAD_OFF_LAST_TXD_AMT = 0x18       # u32
RAD_OFF_LAST_RXD_AMT = 0x1C       # u32
RAD_OFF_DIAG_Q2_OK = 0x20         # u32
RAD_OFF_DIAG_Q2_SAVED = 0x24      # u32
RAD_OFF_DIAG_SAT_CLAMPS = 0x28    # u32
RAD_OFF_DIAG_ABS_RECOV = 0x2C     # u32
RAD_OFF_DIAG_EPOCH_RST = 0x30     # u32
RAD_OFF_DIAG_Q2_SPI_COMMIT = 0x34 # u32
RAD_OFF_DIAG_SPIS0_IRQS = 0x38    # u32
RAD_OFF_DIAG_GPIOTE_IRQS = 0x3C   # u32
RAD_OFF_DIAG_MODE_TRANS = 0x40    # u32


def patch_inline(
    ctx: "PatchContext",
    site: int,
    expected_old: bytes,
    lines: list[str],
    *,
    name: str,
    module: str,
    symbols: dict[str, int] | None = None,
    reason: str = "",
) -> None:
    """Assemble and Capstone-verify an inline replacement patch exact-sized to expected_old."""
    from fenrir.patcher.thumb import assemble

    merged = dict(ctx.builder.symbols)
    if symbols:
        merged.update(symbols)
    blk = assemble(lines, site, name=name, symbols=merged, verify=True)
    if len(blk.data) > len(expected_old):
        raise ValueError(
            f"[{name}] Patch size {len(blk.data)} exceeds slot {len(expected_old)} at 0x{site:08X}"
        )
    pad_n = len(expected_old) - len(blk.data)
    if pad_n % 2 != 0:
        raise ValueError(f"[{name}] Odd NOP pad {pad_n} at 0x{site:08X}")
    if pad_n:
        blk = assemble(list(lines) + ["nop"] * (pad_n // 2), site, name=name, symbols=merged, verify=True)
    assert len(blk.data) == len(expected_old)
    ctx.builder.edit(site, blk.data, expected_old=expected_old, module=module, reason=reason or name)
    ctx.blocks.append(blk)
