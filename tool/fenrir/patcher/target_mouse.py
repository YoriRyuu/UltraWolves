"""Byte-verified landmark table for Fenrir mouse APP v1.00.39.00.

Every address, original preimage byte string, RAM layout boundary, and Flash
page mapping in this file is sourced strictly from:
    fenrir_dev/docs/phase2_mouse_landmarks.md
which was verified directly against:
    Fenrir+035-8K_Mouse_App_FW_v1.00.39.00_20250605.hex
    SHA-256: fd0ad5f1221bc0d227e423f87ec98d71033573e8a8a497856142c6000d12874f
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fenrir.constants import REFERENCE_FIRMWARES
from fenrir.patcher.hex_io import AddressRange, HexImage

TARGET_NAME = "Fenrir+035-8K Mouse APP v1.00.39.00"
STOCK_FIRMWARE = REFERENCE_FIRMWARES["mouse"]
STOCK_HEX_PATH: Path = STOCK_FIRMWARE.hex_path
STOCK_SHA256: str = STOCK_FIRMWARE.expected_sha256

BASE = 0x00006000
END = 0x00022A0C
DEFINED_BYTES = 117260
INITIAL_SP = 0x2000BCA0
RESET_VECTOR = 0x000064A5
ENTRY_POINT = 0x00006201

# Verified unused Flash tail inside the final APP 4 KiB page (0x22000..0x22FFF).
# Do not spill into 0x23000+ because SoftDevice/Bootloader bounds are unverified.
CAVE_START = 0x00022A0C
CAVE_END = 0x00023000
CAVE_BYTES = CAVE_END - CAVE_START  # 1,524 bytes

# Independent Phase 2 CRC16 config Flash page (0 APP references, disjoint from all stock NV)
FLASH_PAGE_SIZE = 0x1000
PHASE2_CONFIG_FLASH_PAGE = 0x000EA000
PHASE2_CONFIG_FLASH_END = PHASE2_CONFIG_FLASH_PAGE + FLASH_PAGE_SIZE
PHASE2_CONFIG_ALT_PAGE = 0x000ED000

# Protected non-APP / stock NV regions that Phase 2 MUST never touch
PROTECTED_RANGES: tuple[AddressRange, ...] = (
    AddressRange(0x00000000, 0x00006000, "bootloader_mbr_softdevice_low"),
    AddressRange(0x00023000, 0x00050000, "unverified_post_app_flash"),
    AddressRange(0x00050000, 0x00051000, "stock_nv_50000"),
    AddressRange(0x0008C000, 0x0008D000, "stock_nv_8c000_macro_dir"),
    AddressRange(0x00090000, 0x000E0000, "stock_nv_90000_dffff_object_pool"),
    AddressRange(0x000EB000, 0x000EC000, "stock_nv_eb000_identity"),
    AddressRange(0x000EC000, 0x000ED000, "stock_nv_ec000_config"),
)

# Phase 2 static state RAM (outside scatter .data/.bss+stack and below 0x2003FFFC mailbox).
# Note: 0x90AC scatterload only zeros [0x20004344, 0x2000BCA0), so startup hook H4 MUST
# validate & initialize this block explicitly on every reset.
PHASE2_RAM_BASE = 0x2003F000
PHASE2_RAM_END = 0x2003F400

# Bootloader magic mailbox & system reset
BOOTLOADER_MAGIC_ADDR = 0x2003FFFC
BOOTLOADER_MAGIC_VALUE = 0xA55AA55A  # Verified at 0x017C80 (NOT 0xA55A55AA!)
NVIC_SYSTEM_RESET = 0x0000904C

# Core firmware RAM landmarks (.data / .bss)
RAM_TRANSPORT_MODE = 0x20003204  # u8: 0=USB, 1=2.4G, 2=BLE
RAM_SYS_MODE = 0x20003214
RAM_DIRTY_BITSET = 0x20003217  # MUST NOT be repurposed by Phase 2
RAM_SENSOR_BRANCH = 0x20003246  # u8: 0x4F / 0x51 / 0x53 (PAW3950 == 0x53)
RAM_SENSOR_MODE_APPLIED = 0x2000325A
RAM_SENSOR_MODE_TARGET = 0x2000325D  # 1=Mode1, 2=Mode2, 3=Mode3
RAM_SENSOR_CPI_X = 0x20003262  # u16
RAM_SENSOR_CPI_Y = 0x20003264  # u16
RAM_WORKER_STEP = 0x2000326D
RAM_MOTION_GATE = 0x2000326E  # 1=allow burst, 0=paused for worker SPI
RAM_BUTTON_THRESH_LIVE = 0x20003A65  # 6B copied by 0xC1E8 (0x20003A65..0x20003A6A)
RAM_USB_CONFIGURED = 0x200040B9  # u8: 1=wired USB, 0=wireless/unconfigured
RAM_SPI_IDLE = 0x20004114  # u8: 1=SPIM3 free, 0=busy
RAM_SPI_BURST_ACTIVE = 0x20004118  # u8: 1=IRQ motion burst in flight
RAM_SENSOR_ENABLED = 0x2000411C  # u8: 1=active, 0=sleeping/disabled
RAM_ACTIVE_PROFILE = 0x20004380  # u8 (0-based)
RAM_DEBOUNCE_PERSISTED = 0x200043FE  # 4B: [press, release, lock_press, lock_release]
RAM_WORKER_PENDING = 0x20005895  # u8
RAM_WORKER_ACTIVE = 0x20005896  # u8 (1-based: 0=none, 1..8=active)
RAM_WORKER_SLOTS = 0x20005897  # 8x unaligned uint32_t Thumb pointers!
RAM_CMD_BUF = 0x20005FA8  # 64B command buffer (Family A len@+3, group@+4, sub@+5, data@+6)

# Core firmware function landmarks
FN_BUTTON_THRESHOLDS_LOAD_PROFILE = 0x0000C1E8
FN_CRC16_CCITT = 0x0000C990  # r0=ptr, r1=len, r2=0 -> init 0xFFFF, poly 0x1021
FN_FLASH_RMW_4K = 0x0000F1D8
FN_FLASH_RF_PAUSE = 0x0000F2BC
FN_FLASH_RF_RESUME = 0x0000F2DE
FN_FLASH_ERASE = 0x0000F304  # r0=page_addr -> 0 on success
FN_FLASH_WRITE = 0x0000F356  # r0=dst_flash, r1=src_ram, r2=len (4B aligned!) -> 0 on success
FN_STARTUP_LOAD = 0x000111E0
FN_PERSIST_TICK = 0x000177CC
FN_CONFIG_MARK_DIRTY = 0x0001AD9C
FN_SENSOR_POWERUP_ID53 = 0x0001CC6C
FN_SENSOR_MODE_APPLY = 0x0001D4C0
FN_SENSOR_MODE_WORKER = 0x0001D58D  # Thumb fn ptr stored at 0x01D588
FN_WORKER_REGISTER = 0x0001E108  # r0=fn_ptr(|1) -> 0..7 slot, 8=full (ambiguous 0 on null!)
FN_WORKER_KICK = 0x0001E150
FN_WORKER_POLL = 0x0001E1E0
FN_SPI_READ_REG = 0x0001F190  # r0=reg -> u8 (ambiguous 0 on busy or error!)
FN_SPI_WRITE_REG = 0x0001F1F4  # r0=reg, r1=val -> 1=ok, 0=busy

# Hook sites (H1..H8)
HOOK_H1_FAULT_VECTORS = 0x0000600C  # 16B: HardFault, MemManage, BusFault, UsageFault
HOOK_H2_GROUP5_DEFAULT = 0x0001923E  # 8B: def_19216 (R0 = buf[4] >= 5)
GROUP5_COMMON_EXIT = 0x00019246
HOOK_H3_DEBOUNCE_05_CALL = 0x00018AF8  # 4B: BL 0x1AD9C inside Family B 0x05
HOOK_H4_STARTUP_LOAD_CALL = 0x0001301A  # 4B: BL 0x111E0 in main startup
HOOK_H5_MODE_WORKER_PTR = 0x0001D588  # 4B: literal pool ptr to 0x1D58D
HOOK_H6_POWERUP_TAIL = 0x0001D00A  # 4B: POP.W {R3-R9, PC} at end of 0x1CC6C
HOOK_H6_WAKE_CALL = 0x0001FC56  # 4B: BL 0x1CC6C inside 0x1FC30 wake path (alt)
HOOK_H7_MODE_APPLY_TAIL = 0x0001D570  # 4B: POP {R4-R6, PC} + 00 00 pad (R5 = immediate)
HOOK_H8_PERSIST_CALL = 0x0001312E  # 4B: BL 0x177CC in main loop


@dataclass(frozen=True)
class PreimageSpec:
    address: int
    expected: bytes
    label: str


# Exact pre-patch byte fingerprints from fenrir_dev/docs/phase2_mouse_landmarks.md
PREIMAGES: dict[str, PreimageSpec] = {
    "vector_table_64b": PreimageSpec(
        0x00006000,
        bytes.fromhex(
            "a0bc0020a5640000ad640000af640000b1640000b3640000b564000000000000"
            "000000000000000000000000b7640000b964000000000000bb640000bd640000"
        ),
        "vector_table_0x6000_0x603f",
    ),
    "h1_fault_vectors": PreimageSpec(
        HOOK_H1_FAULT_VECTORS,
        bytes.fromhex("af640000b1640000b3640000b5640000"),
        "H1_fault_vectors_0x600c",
    ),
    "default_stubs": PreimageSpec(
        0x000064A4,
        bytes.fromhex("0648804706480047fee7fee7fee7fee7fee7fee7fee7fee7fee7fee7"),
        "default_stubs_0x64a4",
    ),
    "nvic_system_reset": PreimageSpec(
        NVIC_SYSTEM_RESET,
        bytes.fromhex(
            "bff34f8f0648006800f4e06005490843001d03490860bff34f8f00bf00bffde7"
            "0ced00e00000fa05"
        ),
        "nvic_system_reset_0x904c",
    ),
    "stock_bootloader_magic_literal": PreimageSpec(
        0x00017C80,
        bytes.fromhex("5aa55aa5fcff0320"),
        "stock_0xA55AA55A_0x2003FFFC_0x17c80",
    ),
    "group5_switch_block": PreimageSpec(
        0x0001920E,
        bytes.fromhex(
            "25480079052813d2dfe800f00306090c0f00fef7b8fb0fe000f043f80ce000f0"
            "8efd09e0fef75dfa06e0fef738fd03e0a3201849087000bf00bf"
        ),
        "family_a_switch_0x1920e",
    ),
    "h2_group5_default": PreimageSpec(
        HOOK_H2_GROUP5_DEFAULT,
        bytes.fromhex("a3201849087000bf"),
        "H2_group5_default_0x1923e",
    ),
    "group5_common_exit": PreimageSpec(
        GROUP5_COMMON_EXIT,
        bytes.fromhex(
            "00bf16480078a02802d1a1201449087000201349087011488078d0b112480078"
            "b8b90e48c078821d0d490df10600edf728f90a48c078801dc0b28df8040001a9"
            "052008f0def8012802d100200549087000bf17b0bde8f083000074430020a85f"
            "0020f33c0020b9400020"
        ),
        "family_a_common_exit_0x19246",
    ),
    "family_b_05_block": PreimageSpec(
        0x00018AD8,
        bytes.fromhex(
            "21787a48d53880f88a10617880f88b10a17880f88c10e17880f88d1000210820"
            "02f050f904207349487051e3"
        ),
        "family_b_05_0x18ad8",
    ),
    "h3_debounce_05_call": PreimageSpec(
        HOOK_H3_DEBOUNCE_05_CALL,
        bytes.fromhex("02f050f9"),
        "H3_debounce_05_bl_0x18af8",
    ),
    "button_thresholds_load_profile": PreimageSpec(
        FN_BUTTON_THRESHOLDS_LOAD_PROFILE,
        bytes.fromhex(
            "1e48007b00eb80111c488930084440781b4948701948007b00eb801117488930"
            "08448078164988701448007b00eb8011124889300844c0781149c8700f48007b"
            "00eb80110d488930084400790c4908710a48007b00eb80110848893008444079"
            "074948710548007b00eb80110348893008448079024988717047"
        ),
        "button_thresholds_load_profile_0xc1e8",
    ),
    "worker_register": PreimageSpec(
        FN_WORKER_REGISTER,
        bytes.fromhex(
            "0146e9b1002018e00e4a02eb800212688ab90c4a02eb800212688a420bd0094a"
            "02eb80021160074a921e1278521c054b9b1e1a7003e0421cd0b20828e4db00bf7047"
        ),
        "worker_register_0x1e108",
    ),
    "worker_kick": PreimageSpec(
        FN_WORKER_KICK,
        bytes.fromhex(
            "1448007808b9002070471248407808b10020f9e7002119e00e48801c00eb8100"
            "006888b10b48407870b9481c094a50700020094a1070094a107006480078401e"
            "044a10700120dfe7481cc1b20829e3db0020d9e7"
        ),
        "worker_kick_0x1e150",
    ),
    "worker_poll": PreimageSpec(
        FN_WORKER_POLL,
        bytes.fromhex(
            "10b510484078e0b10f480078c8b10d494978491e0b4a921c02eb810108688047"
            "01280ed1002207484078401e0549891c01eb800002600020891e487001200349087010bd"
        ),
        "worker_poll_0x1e1e0",
    ),
    "spi_read_reg": PreimageSpec(
        FN_SPI_READ_REG,
        bytes.fromhex(
            "10b504461448007808b9002010bd0020114908700420f4f7e7ff04f07f000f49"
            "087000230e4a01210c4800f045f80120f5f7e8fd01230a4a0021084800f03cf8"
            "0120f5f7dffd0420f5f79bf80320f5f7d9fd03480078d9e7"
        ),
        "spi_read_reg_0x1f190",
    ),
    "spi_write_reg": PreimageSpec(
        FN_SPI_WRITE_REG,
        bytes.fromhex(
            "70b505460c461048007808b9002070bd00200d4908700420f4f7b4ff45f08000"
            "0a490870084644700023094a022100f011f80120f5f7b4fd0420f5f770f80320"
            "f5f7aefd0120e2e7"
        ),
        "spi_write_reg_0x1f1f4",
    ),
    "h5_mode_worker_ptr": PreimageSpec(
        HOOK_H5_MODE_WORKER_PTR,
        bytes.fromhex("8dd50100"),
        "H5_mode_worker_ptr_0x1d588",
    ),
    "h7_mode_apply_tail": PreimageSpec(
        HOOK_H7_MODE_APPLY_TAIL,
        bytes.fromhex("70bd0000"),
        "H7_mode_apply_tail_0x1d570",
    ),
    "h6_powerup_tail": PreimageSpec(
        HOOK_H6_POWERUP_TAIL,
        bytes.fromhex("bde8f883"),
        "H6_powerup_tail_0x1d00a",
    ),
    "h6_wake_call": PreimageSpec(
        HOOK_H6_WAKE_CALL,
        bytes.fromhex("fdf709f8"),
        "H6_wake_call_0x1fc56",
    ),
    "h4_startup_load_call": PreimageSpec(
        HOOK_H4_STARTUP_LOAD_CALL,
        bytes.fromhex("fef7e1f8"),
        "H4_startup_load_call_0x1301a",
    ),
    "h8_persist_call": PreimageSpec(
        HOOK_H8_PERSIST_CALL,
        bytes.fromhex("04f04dfb"),
        "H8_persist_call_0x1312e",
    ),
    "crc16_ccitt": PreimageSpec(
        FN_CRC16_CCITT,
        bytes.fromhex(
            "30b503460c4612b94ff6ff7100e011880846002110e0051245ea0025a8b25d5c"
            "6840c0f30315684080ea0035a8b205062d0d80ea4500491ca142ecd330bd"
        ),
        "crc16_ccitt_0xc990",
    ),
    "flash_rf_pause": PreimageSpec(
        FN_FLASH_RF_PAUSE,
        bytes.fromhex("10b510f0fff9012805d111f0c7fe002011f09af901e010f0f5f9012010f00afa10bd"),
        "flash_rf_pause_0xf2bc",
    ),
    "flash_rf_resume": PreimageSpec(
        FN_FLASH_RF_RESUME,
        bytes.fromhex("1fb510f0eef9012806d1684612f0adf9684611f0defe01e010f0e3f97d21012010f00dfa1fbd"),
        "flash_rf_resume_0xf2de",
    ),
    "flash_erase": PreimageSpec(
        FN_FLASH_ERASE,
        bytes.fromhex(
            "f8b5054611240020009010f0d7f902280bd1684612df044600bf264626b100bf"
            "3046faf729f800bf00bf9df8000040b100bf280b28df0446faf786f8112cf8d0"
            "05e072b6284604f0f5ff62b60024e0b2f8bd"
        ),
        "flash_erase_0xf304",
    ),
    "flash_write": PreimageSpec(
        FN_FLASH_WRITE,
        bytes.fromhex(
            "2de9f8430746884615460020009010f0acf902280bd1684612df044600bf2646"
            "26b100bf3046f9f7feff00bf00bf9df8000058b100bfe81c82084146384629df"
            "0446faf758f8112cf5d008e072b6e81c82084146384604f0dcff62b60024e0b2bde8f883"
        ),
        "flash_write_0xf356",
    ),
}


def verify_stock_image(image: HexImage) -> None:
    """Verify exact stock identity, vector table, zero refs to 0xEA000, and all landmarks."""
    if image.sha256 != STOCK_SHA256:
        raise ValueError(f"Unexpected mouse HEX SHA-256: {image.sha256} != {STOCK_SHA256}")
    if (image.base, image.end, len(image.mem)) != (BASE, END, DEFINED_BYTES):
        raise ValueError(
            f"Unexpected mouse HEX span: ({image.base:#x}, {image.end:#x}, {len(image.mem)})"
        )
    if (image.u32(BASE), image.u32(BASE + 4), image.entry) != (INITIAL_SP, RESET_VECTOR, ENTRY_POINT):
        raise ValueError("Unexpected mouse APP startup vectors or entry point")
    refs = image.find_u32_refs(PHASE2_CONFIG_FLASH_PAGE)
    if refs:
        raise ValueError(f"Stock APP unexpectedly references 0x{PHASE2_CONFIG_FLASH_PAGE:08X}: {refs}")
    for spec in PREIMAGES.values():
        image.verify_fingerprint(spec.address, spec.expected, label=spec.label)


# ---------------------------------------------------------------------------
# Phase 3 landmarks (atomic motion, EP81 guard, TIMER1 plock, v2 diagnostics)
# ---------------------------------------------------------------------------

# Bootloader at 0x00000000..0x00005FFF has NOT been verified to erase >= 0x23000.
# Phase 3 unlocks [0x00023000, 0x00025000) ONLY for offline emulation/testing.
PHASE3_CAVE_START = 0x00023000
PHASE3_CAVE_END = 0x00025000
PHASE3_CAVE_SIZE = PHASE3_CAVE_END - PHASE3_CAVE_START  # 8,192 B

PHASE3_PROTECTED_RANGES: tuple[AddressRange, ...] = (
    AddressRange(0x00000000, 0x00006000, "bootloader_mbr_softdevice_low"),
    AddressRange(0x00025000, 0x00050000, "unverified_post_phase3_flash"),
    AddressRange(0x00050000, 0x00051000, "stock_nv_50000"),
    AddressRange(0x0008C000, 0x0008D000, "stock_nv_8c000_macro_dir"),
    AddressRange(0x00090000, 0x000E0000, "stock_nv_90000_dffff_object_pool"),
    AddressRange(0x000EB000, 0x000EC000, "stock_nv_eb000_identity"),
    AddressRange(0x000EC000, 0x000ED000, "stock_nv_ec000_config"),
)

# RAM: [0x2003F040 .. 0x2003F0FF] (192 B immediately above 64 B Phase 2 RAM state)
PHASE3_RAM_BASE = 0x2003F040
PHASE3_RAM_BYTES = 192

# Motion accumulator, buffers, and stationary state RAM
RAM_MOTION_FLAGS = 0x2000321A
RAM_DX_ACC = 0x2000321E
RAM_DY_ACC = 0x20003220
RAM_MOTION_STATUS = 0x2000324E
RAM_STAT_MOTION_GATE = 0x2000326E
RAM_BTN_FLAGS_3A4F = 0x20003A4F
RAM_BTN_FLAGS_3A50 = 0x20003A50
RAM_DEBOUNCE_HIST = 0x20003CFC
RAM_HID_PKT = 0x200040C2
RAM_STAT_POLL_ACTIVE = 0x20004119
RAM_STAT_MASTER = 0x2000411C
RAM_WL_PKT = 0x20008EAC
RAM_SPIM3_RX = 0x20008EC4

# Hardware peripherals (nRF52840)
MMIO_TIMER0_BASE = 0x40008000
MMIO_TIMER1_BASE = 0x40009000
TIMER1_TASKS_CAPTURE2 = MMIO_TIMER1_BASE + 0x048
TIMER1_EVENTS_COMPARE0 = MMIO_TIMER1_BASE + 0x140
TIMER1_EVENTS_COMPARE1 = MMIO_TIMER1_BASE + 0x144
TIMER1_CC0 = MMIO_TIMER1_BASE + 0x540
TIMER1_CC1 = MMIO_TIMER1_BASE + 0x544
TIMER1_CC2 = MMIO_TIMER1_BASE + 0x548

# Stock USB EP81 descriptor (Flash const with overwrite/queue guard byte at +0x10 = 0x000222BC)
EP81_DESC_ADDR = 0x000222AC
EP81_QUEUE_FLAG_ADDR = 0x000222BC

# Stock functions used by Phase 3 hooks
FN_USB_EP_UNLOCK_A980 = 0x0000A980
FN_USB_EP_UNLOCK_A98A = 0x0000A98A
FN_BLE_LOOP = 0x0000B298
FN_WL_MOTION_TX = 0x00017FD4
FN_USB_MOTION_TX = 0x0001828C
FN_BLE_MOTION_TX = 0x000199D4
FN_IRQ20_MOTION = 0x0001D150
FN_WL_TX_CLEAR = 0x0001D304
FN_ACC_ACCUM = 0x0001DAD8
FN_IRQ9_MOTION_TICK = 0x0001DF40
FN_GET_TRANSPORT_MODE = 0x0001F6C0
FN_TIMER_PAUSE = 0x0001F6F0
FN_TIMER_RESUME = 0x0001F71C

# Verified Phase 3 hook patch sites
HOOK_P3_SPIM3_CALL = 0x0001DEFE
HOOK_P3_WL_SNAP = 0x00018068
HOOK_P3_WL_POST_TX = 0x000180EE
HOOK_P3_USB_SNAP = 0x000182BC
HOOK_P3_USB_POST_TX = 0x000182EE
HOOK_P3_BLE_SNAP = 0x00019A32
HOOK_P3_BLE_POST_TX = 0x00019A6E
HOOK_P3_BLE_LOOP_CALL = 0x0000B29A
HOOK_P3_IRQ20_SNAP = 0x0001D1A0
HOOK_P3_IRQ20_COMMIT1 = 0x0001D1BE
HOOK_P3_IRQ20_COMMIT2 = 0x0001D2AA
HOOK_P3_EP81_GUARD = 0x00014582
HOOK_P3_IRQ9_STAT = 0x0000887E
HOOK_P3_IRQ9_PLOCK = 0x00008882
HOOK_P3_FLASH_PAUSE_TIMER = 0x0000F2D8
HOOK_P3_FLASH_RESUME_TIMER = 0x0000F2FE

P3_PREIMAGES: dict[str, PreimageSpec] = {
    "p3_spim3_call": PreimageSpec(
        HOOK_P3_SPIM3_CALL,
        bytes.fromhex("fff7ebfd"),
        "spim3_acc_accum_call_0x1defe",
    ),
    "p3_wl_snap": PreimageSpec(
        HOOK_P3_WL_SNAP,
        bytes.fromhex("8448b0f900008649a1f801008048b0f90000a1f80500"),
        "wireless_motion_snap_0x18068",
    ),
    "p3_wl_post_tx": PreimageSpec(
        HOOK_P3_WL_POST_TX,
        bytes.fromhex(
            "012815d1002060490880604908805c4908705a48401c0021"
            "016081808171012005f0f9f85348007820f0040051490870"
        ),
        "wireless_motion_post_tx_0x180ee",
    ),
    "p3_usb_snap": PreimageSpec(
        HOOK_P3_USB_SNAP,
        bytes.fromhex("6c48007888706b480088000ac8706a480078087168480088000a4871"),
        "usb_motion_snap_0x182bc",
    ),
    "p3_usb_post_tx": PreimageSpec(
        HOOK_P3_USB_POST_TX,
        bytes.fromhex(
            "d4b95b48401c002101608180817100205b4908705e490870"
            "5b490880594908805248007820f00400504908700020f2f730fb0020f2f732fb"
        ),
        "usb_motion_post_tx_0x182ee",
    ),
    "p3_ble_snap": PreimageSpec(
        HOOK_P3_BLE_SNAP,
        bytes.fromhex("4b480078887049480088000ac87046480078087145480088000a4871"),
        "ble_motion_snap_0x19a32",
    ),
    "p3_ble_post_tx": PreimageSpec(
        HOOK_P3_BLE_POST_TX,
        bytes.fromhex("70b90020384908703849087038490880384908803248007820f0040030490870"),
        "ble_motion_post_tx_0x19a6e",
    ),
    "p3_ble_loop_call": PreimageSpec(
        HOOK_P3_BLE_LOOP_CALL,
        bytes.fromhex("0ef09bfb"),
        "ble_loop_motion_call_0x0b29a",
    ),
    "p3_irq20_snap": PreimageSpec(
        HOOK_P3_IRQ20_SNAP,
        bytes.fromhex("4a48b0f90000adf800004948b0f90000adf80200"),
        "irq20_motion_snap_0x1d1a0",
    ),
    "p3_irq20_commit1": PreimageSpec(
        HOOK_P3_IRQ20_COMMIT1,
        bytes.fromhex("00204349088041490880"),
        "irq20_motion_commit1_0x1d1be",
    ),
    "p3_irq20_commit2": PreimageSpec(
        HOOK_P3_IRQ20_COMMIT2,
        bytes.fromhex("4ff0000cdff82080a8f800c0dff81480a8f800c0"),
        "irq20_motion_commit2_0x1d2aa",
    ),
    "p3_ep81_guard": PreimageSpec(
        HOOK_P3_EP81_GUARD,
        bytes.fromhex("b8f1000f02d0207c002846d1"),
        "usb_ep_guard_0x14582",
    ),
    "p3_ep81_desc": PreimageSpec(
        EP81_DESC_ADDR,
        bytes.fromhex("388d0020288d0020010000000800000000000000"),
        "ep81_descriptor_0x222ac",
    ),
    "p3_irq9_stationary": PreimageSpec(
        HOOK_P3_IRQ9_STAT,
        bytes.fromhex("15f05ffb"),
        "irq9_stationary_call_0x0887e",
    ),
    "p3_irq9_plock": PreimageSpec(
        HOOK_P3_IRQ9_PLOCK,
        bytes.fromhex("16f01dff"),
        "irq9_plock_mode_call_0x08882",
    ),
    "p3_flash_pause_timer": PreimageSpec(
        HOOK_P3_FLASH_PAUSE_TIMER,
        bytes.fromhex("10f00afa"),
        "flash_pause_timer_call_0x0f2d8",
    ),
    "p3_flash_resume_timer": PreimageSpec(
        HOOK_P3_FLASH_RESUME_TIMER,
        bytes.fromhex("10f00dfa"),
        "flash_resume_timer_call_0x0f2fe",
    ),
    "fn_acc_accum_entry": PreimageSpec(
        FN_ACC_ACCUM,
        bytes.fromhex("0178184a11704178"),
        "acc_accum_entry_0x1dad8",
    ),
    "fn_wl_tx_clear_entry": PreimageSpec(
        FN_WL_TX_CLEAR,
        bytes.fromhex("10b502460b494878"),
        "wl_tx_clear_entry_0x1d304",
    ),
    "fn_usb_ep_unlock_a980": PreimageSpec(
        FN_USB_EP_UNLOCK_A980,
        bytes.fromhex("00b5024600f006f8"),
        "usb_ep_unlock_0x0a980",
    ),
    "fn_usb_ep_unlock_a98a": PreimageSpec(
        FN_USB_EP_UNLOCK_A98A,
        bytes.fromhex("00b5024600f00bf8"),
        "usb_ep_unlock_0x0a98a",
    ),
    "fn_get_transport_mode": PreimageSpec(
        FN_GET_TRANSPORT_MODE,
        bytes.fromhex("0148007870470000"),
        "get_transport_mode_0x1f6c0",
    ),
    "fn_timer_pause_1f6f0": PreimageSpec(
        FN_TIMER_PAUSE,
        bytes.fromhex("70b50446074800eb"),
        "timer_pause_0x1f6f0",
    ),
    "fn_timer_resume_1f71c": PreimageSpec(
        FN_TIMER_RESUME,
        bytes.fromhex("70b505460e461948"),
        "timer_resume_0x1f71c",
    ),
    "fn_irq9_motion_tick": PreimageSpec(
        FN_IRQ9_MOTION_TICK,
        bytes.fromhex("10b52a48007800b9"),
        "irq9_motion_tick_0x1df40",
    ),
    "fn_ble_loop_entry": PreimageSpec(
        FN_BLE_LOOP,
        bytes.fromhex("10b50ef09bfbfff7"),
        "ble_loop_entry_0x0b298",
    ),
}


def verify_phase3_landmarks(image: HexImage) -> None:
    """Verify stock identity plus every Phase 3 hook preimage and target."""
    verify_stock_image(image)
    for spec in P3_PREIMAGES.values():
        image.verify_fingerprint(spec.address, spec.expected, label=spec.label)


# ---------------------------------------------------------------------------
# Phase 3+ (S2b P1) landmarks: fix-a, plock learn/outliers, active mouse ABS
# ---------------------------------------------------------------------------

RAM_MOUSE_CPI_X_VAL = 0x20003262
RAM_MOUSE_CPI_Y_VAL = 0x20003264

FN_Q2_PUSH_21448 = 0x00021448
HOOK_P3P_WL_Q2_PUSH = 0x000180EA
HOOK_P3P_RF_S2_CHK = 0x0001B334
TARGET_P3P_RF_SINGLE = 0x0001B384
HOOK_P3P_RF_B0_TYPE = 0x0001B3EC

# Wave 2 (S2b P2/P3) landmarks: eager-wake, ce-static, lod-raw, anti-slam window
FN_SENSOR_POLL = 0x0001DF40
FN_SENSOR_LOD_SET = 0x0001D388
RAM_POLL_ACTIVE = 0x20004119
RAM_LOD_NV_VAL = 0x2000443E
GPIO_EVENTS_IN_6 = 0x40006118
HOOK_P3P_IRQ6_ENTRY = 0x00006628
RESUME_P3P_IRQ6_BODY = 0x0000662C
HOOK_P3P_ANTI_SLAM_LIFTED = 0x0001C42C
HOOK_P3P_ANTI_SLAM_LANDING = 0x0001C454
HOOK_P3P_LOD_TAIL = 0x0001D4AC
HOOK_P3P_IRQ9_ENTRY_CLEAR = 0x00008842

P3PLUS_PREIMAGES: dict[str, PreimageSpec] = {
    "p3p_wl_q2_push": PreimageSpec(
        HOOK_P3P_WL_Q2_PUSH,
        bytes.fromhex("09f0adf9"),
        "wl_queue2_push_call_0x180ea",
    ),
    "p3p_rf_s2_chk": PreimageSpec(
        HOOK_P3P_RF_S2_CHK,
        bytes.fromhex("baf1010f24dd"),
        "rf_builder_sample2_chk_0x1b334",
    ),
    "p3p_rf_b0_type": PreimageSpec(
        HOOK_P3P_RF_B0_TYPE,
        bytes.fromhex("022180f8db10"),
        "rf_builder_b0_type2_0x1b3ec",
    ),
    "fn_q2_push_21448": PreimageSpec(
        FN_Q2_PUSH_21448,
        bytes.fromhex("70b505460c460c48"),
        "queue_push_21448",
    ),
    "id53_m1_hi_fixa": PreimageSpec(
        0x00007976,
        bytes.fromhex("00217f2017f03bfc95214f2017f037fc00214e2017f033fc9521522017f02ffc0021512017f02bfc0121472017f027fc"),
        "id53_m1_hi_0x7976",
    ),
    "id53_m1_lo_fixa": PreimageSpec(
        0x00007C72,
        bytes.fromhex("00217f2017f0bdfa4f21084617f0b9fa00214e2017f0b5fa4f21522017f0b1fa0021512017f0adfa0121472017f0a9fa"),
        "id53_m1_lo_0x7c72",
    ),
    "id53_m2_fixa": PreimageSpec(
        0x00008110,
        bytes.fromhex("00217f2017f06ef84f21084617f06af800214e2017f066f84f21522017f062f80021512017f05ef80121472017f05af8"),
        "id53_m2_0x8110",
    ),
    "id53_m3_fixa": PreimageSpec(
        0x000085AC,
        bytes.fromhex("00217f2016f020fe4f21084616f01cfe00214e2016f018fe4f21522016f014fe0021512016f010fe0121472016f00cfe"),
        "id53_m3_0x85ac",
    ),
    "p3p_irq9_entry": PreimageSpec(
        0x00008838,
        bytes.fromhex("10b52848006801283cd10020"),
        "irq9_entry_0x08838",
    ),
    "p3p_irq9_entry_clear": PreimageSpec(
        HOOK_P3P_IRQ9_ENTRY_CLEAR,
        bytes.fromhex("002025490860"),
        "irq9_entry_clear_0x08842",
    ),
    "p3p_irq9_plock_block": PreimageSpec(
        0x0000887C,
        bytes.fromhex("087015f05ffb16f01dff012801d113f0cdf81748"),
        "irq9_plock_block_0x0887c",
    ),
    "p3p_irq6_entry": PreimageSpec(
        HOOK_P3P_IRQ6_ENTRY,
        bytes.fromhex("0c480068"),
        "irq6_entry_0x06628",
    ),
    "p3p_sensor_poll": PreimageSpec(
        FN_SENSOR_POLL,
        bytes.fromhex("10b52a48007800b910bd2948007838b9"),
        "sensor_poll_0x1df40",
    ),
    "p3p_lod_1d3d6": PreimageSpec(
        0x0001D3D6,
        bytes.fromhex("36480078532866d118217f2001f007ff85217a2001f003ff00217f2001f0fffe59e0"),
        "lod_id53_0x1d3d6",
    ),
    "p3p_lod_tail_1d4ac": PreimageSpec(
        HOOK_P3P_LOD_TAIL,
        bytes.fromhex("70bd0000"),
        "lod_set_tail_0x1d4ac",
    ),
    "p3p_anti_slam_lifted": PreimageSpec(
        HOOK_P3P_ANTI_SLAM_LIFTED,
        bytes.fromhex("90f81002"),
        "anti_slam_lifted_0x1c42c",
    ),
    "p3p_anti_slam_landing": PreimageSpec(
        HOOK_P3P_ANTI_SLAM_LANDING,
        bytes.fromhex("102004eb4401"),
        "anti_slam_landing_0x1c454",
    ),
}


def verify_phase3plus_landmarks(image: HexImage) -> None:
    """Verify stock, Phase 3, and all S2b P1 landmarks on stock mouse HEX."""
    verify_phase3_landmarks(image)
    for spec in P3PLUS_PREIMAGES.values():
        image.verify_fingerprint(spec.address, spec.expected, label=spec.label)
