"""Base transport interfaces and HID device classification."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from fenrir.constants import (
    BLE_PATH_EXCLUDE_SUBSTR,
    EXPECTED_FEATURE_USAGE,
    EXPECTED_FEATURE_USAGE_PAGE,
    MOUSE_APP_PIDS,
    MOUSE_BL_PIDS,
    RECEIVER_APP_PIDS,
    RECEIVER_BL_PIDS,
    RECEIVER_PID_LABELS,
    VENDOR_ID,
)


class DeviceClassification(str, Enum):
    MOUSE_APP = "mouse_app"
    MOUSE_BOOTLOADER = "mouse_bootloader"
    RECEIVER_APP = "receiver_app"
    RECEIVER_BOOTLOADER = "receiver_bootloader"
    UNKNOWN_VENDOR = "unknown_vendor"
    BLE_EXCLUDED = "ble_excluded"


@dataclass(frozen=True)
class HidDeviceInfo:
    path: str
    vid: int
    pid: int
    manufacturer: str
    product: str
    serial: str
    interface_number: int
    usage_page: int
    usage: int
    release_number: int
    classification: DeviceClassification
    is_feature_candidate: bool
    notes: str = ""

    @property
    def vid_hex(self) -> str:
        return f"0x{self.vid:04X}"

    @property
    def pid_hex(self) -> str:
        return f"0x{self.pid:04X}"

    @property
    def is_exact_feature_match(self) -> bool:
        """True when device matches Q1 exact 64B Feature descriptor (usage_page=0xFFFF, usage=0x0000)."""
        return (
            self.classification in (DeviceClassification.MOUSE_APP, DeviceClassification.RECEIVER_APP)
            and self.usage_page == EXPECTED_FEATURE_USAGE_PAGE
            and self.usage == EXPECTED_FEATURE_USAGE
        )

    @property
    def feature_match_priority(self) -> int:
        """Lower score means higher priority as the target 64B HID Feature interface."""
        if self.classification not in (DeviceClassification.MOUSE_APP, DeviceClassification.RECEIVER_APP):
            return 9
        if self.usage_page == EXPECTED_FEATURE_USAGE_PAGE and self.usage == EXPECTED_FEATURE_USAGE:
            return 0
        if self.usage_page == EXPECTED_FEATURE_USAGE_PAGE:
            return 1
        if self.interface_number == 2 and self.usage_page >= 0xFF00:
            return 2
        if self.is_feature_candidate:
            return 3
        return 4

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["classification"] = self.classification.value
        d["is_exact_feature_match"] = self.is_exact_feature_match
        d["feature_match_priority"] = self.feature_match_priority
        d["vid_hex"] = self.vid_hex
        d["pid_hex"] = self.pid_hex
        d["usage_page_hex"] = f"0x{self.usage_page:04X}"
        d["usage_hex"] = f"0x{self.usage:04X}"
        return d


def _feature_note_suffix(usage_page: int, usage: int, is_feature_candidate: bool) -> str:
    if usage_page == EXPECTED_FEATURE_USAGE_PAGE and usage == EXPECTED_FEATURE_USAGE:
        return " [EXACT Feature interface: usage_page=0xFFFF, usage=0x0000]"
    if usage_page == EXPECTED_FEATURE_USAGE_PAGE:
        return f" [Feature candidate usage_page=0xFFFF, usage=0x{usage:04X}]"
    if is_feature_candidate:
        return " [secondary vendor/IF2 candidate; prefer usage_page=0xFFFF]"
    return ""


def prioritize_feature_devices(devices: list[HidDeviceInfo]) -> list[HidDeviceInfo]:
    """Stable-sort enumerated HID devices so exact usage_page=0xFFFF Feature interfaces come first."""
    return sorted(devices, key=lambda d: d.feature_match_priority)


def classify_hid_device(
    vid: int,
    pid: int,
    path: str,
    interface_number: int,
    usage_page: int,
    usage: int = 0,
) -> tuple[DeviceClassification, bool, str]:
    """Classify an enumerated HID entry without opening or writing to it."""
    if BLE_PATH_EXCLUDE_SUBSTR.lower() in path.lower():
        return (
            DeviceClassification.BLE_EXCLUDED,
            False,
            f"Excluded BLE GATT HID path ({BLE_PATH_EXCLUDE_SUBSTR})",
        )

    is_feature_candidate = (
        usage_page == EXPECTED_FEATURE_USAGE_PAGE or usage_page >= 0xFF00 or interface_number == 2
    )
    if vid != VENDOR_ID:
        return DeviceClassification.UNKNOWN_VENDOR, False, f"Non-Fenrir VID 0x{vid:04X}"

    if pid in MOUSE_BL_PIDS:
        return (
            DeviceClassification.MOUSE_BOOTLOADER,
            False,
            "Mouse Bootloader PID detected — L0 only, all packet ops blocked",
        )
    if pid in RECEIVER_BL_PIDS:
        return (
            DeviceClassification.RECEIVER_BOOTLOADER,
            False,
            "Receiver Bootloader PID detected — L0 only, all packet ops blocked",
        )
    suffix = _feature_note_suffix(usage_page, usage, is_feature_candidate)
    if pid in MOUSE_APP_PIDS:
        return DeviceClassification.MOUSE_APP, is_feature_candidate, f"Known Mouse APP PID{suffix}"
    if pid in RECEIVER_APP_PIDS:
        label = RECEIVER_PID_LABELS.get(pid, f"Known Receiver APP PID 0x{pid:04X}")
        return DeviceClassification.RECEIVER_APP, is_feature_candidate, f"{label}{suffix}"
    return (
        DeviceClassification.UNKNOWN_VENDOR,
        is_feature_candidate,
        f"Unknown PID 0x{pid:04X} under VID 0x{vid:04X}",
    )


class FeatureTransport(ABC):
    """Abstract HID Feature report transport."""

    @abstractmethod
    def enumerate_devices(self, vid: int = VENDOR_ID) -> list[HidDeviceInfo]:
        """Enumerate OS HID entries (L0: MUST NOT send packets)."""

    @abstractmethod
    def open(self, path: str) -> HidDeviceInfo:
        """Open a device path for Feature operations."""

    @abstractmethod
    def close(self) -> None:
        """Close currently open handle."""

    @abstractmethod
    def get_feature_report(self, report_id: int = 0, length: int = 65) -> bytes:
        """Read a HID Feature report."""

    @abstractmethod
    def send_feature_report(self, report_65: bytes) -> int:
        """Send a 65B HID Feature report."""
