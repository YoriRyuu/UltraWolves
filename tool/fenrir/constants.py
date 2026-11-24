"""Repository paths, official package hashes, USB IDs, and protocol constants."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# fenrir_dev/fenrir/constants.py -> parents[2] == repo root (repo root)
REPO_ROOT: Path = Path(__file__).resolve().parents[2]
FENRIR_DEV_ROOT: Path = Path(__file__).resolve().parents[1]
PROOFS_DIR: Path = Path(__file__).resolve().parent / "emu" / "proofs"
CAPTURES_DIR: Path = FENRIR_DEV_ROOT / "captures"

# USB Vendor / Product IDs from work/packages/{mouse,receiver}/payload/Config.ini
# and outputs/full_re/receiver/receiver_full_report.md
VENDOR_ID: int = 0x33E4

MOUSE_APP_PIDS: frozenset[int] = frozenset({0x3508})
MOUSE_BL_PIDS: frozenset[int] = frozenset({0x3506})

RECEIVER_APP_PIDS: frozenset[int] = frozenset(
    {
        0x0017,
        0x3517,
        0x3717,
        0x5317,
        0x2717,
        0x7917,
        0x7717,
        0x7913,
        0x7713,
        0x5917,
        0x5817,
        0x5717,
        0x5417,
        0x3917,
    }
)
RECEIVER_BL_PIDS: frozenset[int] = frozenset({0x0015})

# Mapping from outputs/full_re/receiver/receiver_full_report.md & Config.ini
RECEIVER_PID_LABELS: dict[int, str] = {
    0x0017: "G-Wolves 8K Receiver (Base PID 0017)",
    0x3517: "Fenrir Asym 8K Receiver",
}

BLE_PATH_EXCLUDE_SUBSTR: str = "1000-8000-00805F9B34FB"

# HID frame constants
DEVICE_FRAME_LEN: int = 64
HID_FEATURE_REPORT_LEN: int = 65  # Windows HID Report ID 0x00 + 64B device buffer
EXPECTED_FEATURE_USAGE_PAGE: int = 0xFFFF  # Q1: Mouse 0x21CE4 & Receiver Feature descriptor
EXPECTED_FEATURE_USAGE: int = 0x0000

# Command status bytes (0x20005FA8 on mouse, 0x2000293C on receiver USB, 0x20001338 on receiver 2.4G)
STATUS_IDLE: int = 0x00
STATUS_PENDING: int = 0xA0
STATUS_OK: int = 0xA1
STATUS_FAIL: int = 0xA2
STATUS_INVALID: int = 0xA3
STATUS_RF_DISCONNECTED: int = 0xA4  # 2.4G 0xB21C local status when byte_200028DD == 0 (never sent via 0xD266)

# Expected version/ID replies for official v1.00.39.00 package
EXPECTED_MOUSE_GROUP0_VERSION_BYTES: bytes = bytes.fromhex("010027003508")
EXPECTED_MOUSE_FAMILYB_VERSION_PREFIX: bytes = bytes.fromhex("010027003508")
EXPECTED_RECEIVER_USB_VERSION_BYTES: bytes = bytes.fromhex("010027000017")
EXPECTED_RECEIVER_2G4_VERSION_BYTES: bytes = bytes.fromhex("010027007703")

# Sensor branch byte in Family B 0x81 reply byte[10] (payload[6]) -> branch label
SENSOR_BRANCH_REPLY_TO_ID: dict[int, str] = {
    0x99: "ID4F",
    0x95: "ID51",
    0x50: "ID53",
}
SENSOR_INTERNAL_TO_REPLY_BYTE: dict[int, int] = {
    0x4F: 0x99,
    0x51: 0x95,
    0x53: 0x50,
}


@dataclass(frozen=True)
class ReferenceFirmware:
    name: str
    hex_rel_path: str
    expected_sha256: str
    runtime_bins: tuple[tuple[str, int], ...]

    @property
    def hex_path(self) -> Path:
        return REPO_ROOT / self.hex_rel_path

    def resolved_runtime_bins(self) -> list[tuple[Path, int]]:
        return [(REPO_ROOT / rel, addr) for rel, addr in self.runtime_bins]


REFERENCE_FIRMWARES: dict[str, ReferenceFirmware] = {
    "mouse": ReferenceFirmware(
        name="mouse",
        hex_rel_path="work/packages/mouse/payload/Fenrir+035-8K_Mouse_App_FW_v1.00.39.00_20250605.hex",
        expected_sha256="fd0ad5f1221bc0d227e423f87ec98d71033573e8a8a497856142c6000d12874f",
        runtime_bins=(
            ("work/images/mouse/runtime_20003200_1144.bin", 0x20003200),
            ("work/images/mouse/runtime_20004344_795c.bin", 0x20004344),
        ),
    ),
    "receiver_usb": ReferenceFirmware(
        name="receiver_usb",
        hex_rel_path="work/packages/receiver/payload/8K_Dongle_USB_App_FW_v1.00.39.00_20250605.hex",
        expected_sha256="8ff3861eaf60fc52c2584eea0b850a2f593e3272320c15b87d990a805f662e75",
        runtime_bins=(
            ("work/images/receiver_usb/runtime_20000000_474.bin", 0x20000000),
            ("work/images/receiver_usb/runtime_20000474_2d1c.bin", 0x20000474),
        ),
    ),
    "receiver_2g4": ReferenceFirmware(
        name="receiver_2g4",
        hex_rel_path="work/packages/receiver/payload/8K_Dongle_2.4G_App_FW_v1.00.39.00_20250605.hex",
        expected_sha256="5c0aa0f7e9af35db89968ed36df91cb76451cd0258e429f7c5d9d1385862929e",
        runtime_bins=(
            ("work/images/receiver_2g4/runtime_20000000_26c.bin", 0x20000000),
            ("work/images/receiver_2g4/runtime_2000026c_3e54.bin", 0x2000026C),
        ),
    ),
}
