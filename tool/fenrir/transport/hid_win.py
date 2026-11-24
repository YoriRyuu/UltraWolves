"""Windows hidapi Feature transport and GuardedHidSession."""

from __future__ import annotations

import time
from typing import Any

import hid

from fenrir.constants import (
    HID_FEATURE_REPORT_LEN,
    STATUS_IDLE,
    STATUS_PENDING,
    VENDOR_ID,
)
from fenrir.protocol.catalog import CommandSpec, ProtocolFamily, TargetRole
from fenrir.protocol.frames import (
    ParsedReply,
    from_hid_feature_report,
    parse_family_a_reply,
    parse_family_b_reply,
    to_hid_feature_report,
)
from fenrir.safety.guard import ProbeLevel, ReadOnlyGuard, SafetyViolationError
from fenrir.safety.write_guard import WriteGuard
from fenrir.transport.base import (
    DeviceClassification,
    FeatureTransport,
    HidDeviceInfo,
    classify_hid_device,
    prioritize_feature_devices,
)
from fenrir.transport.capture import CaptureLogger


def _decode_path(raw_path: bytes | str) -> str:
    if isinstance(raw_path, bytes):
        return raw_path.decode("utf-8", errors="replace")
    return str(raw_path)


class HidApiTransport(FeatureTransport):
    """Thin wrapper over python `hid` (hidapi) for Windows HID Feature reports."""

    def __init__(self) -> None:
        self._dev: Any | None = None
        self._current_info: HidDeviceInfo | None = None
        self._cached_infos: dict[str, tuple[HidDeviceInfo, bytes | str]] = {}

    def enumerate_devices(self, vid: int = VENDOR_ID) -> list[HidDeviceInfo]:
        entries = hid.enumerate(vid, 0)
        infos: list[HidDeviceInfo] = []
        self._cached_infos.clear()
        for item in entries:
            raw_path = item.get("path", b"")
            path_str = _decode_path(raw_path)
            item_vid = int(item.get("vendor_id", 0))
            item_pid = int(item.get("product_id", 0))
            iface = int(item.get("interface_number", -1))
            usage_page = int(item.get("usage_page", 0))
            usage = int(item.get("usage", 0))
            rel = int(item.get("release_number", 0))
            classification, is_feat, notes = classify_hid_device(
                item_vid, item_pid, path_str, iface, usage_page, usage=usage
            )
            info = HidDeviceInfo(
                path=path_str,
                vid=item_vid,
                pid=item_pid,
                manufacturer=str(item.get("manufacturer_string") or ""),
                product=str(item.get("product_string") or ""),
                serial=str(item.get("serial_number") or ""),
                interface_number=iface,
                usage_page=usage_page,
                usage=usage,
                release_number=rel,
                classification=classification,
                is_feature_candidate=is_feat,
                notes=notes,
            )
            infos.append(info)
            self._cached_infos[path_str] = (info, raw_path)
        return prioritize_feature_devices(infos)

    def open(self, path: str) -> HidDeviceInfo:
        if self._dev is not None:
            self.close()
        if not self._cached_infos:
            self.enumerate_devices(VENDOR_ID)

        cached = self._cached_infos.get(path)
        if cached is not None:
            info, raw_path = cached
            if info.classification == DeviceClassification.BLE_EXCLUDED:
                raise SafetyViolationError("Refusing to open BLE-excluded HID path")
        else:
            raw_path = path.encode("utf-8")
            info = HidDeviceInfo(
                path=path,
                vid=0,
                pid=0,
                manufacturer="",
                product="",
                serial="",
                interface_number=-1,
                usage_page=0,
                usage=0,
                release_number=0,
                classification=DeviceClassification.UNKNOWN_VENDOR,
                is_feature_candidate=False,
                notes="Opened directly without prior enumeration cache",
            )

        dev = hid.device()
        dev.open_path(raw_path if isinstance(raw_path, bytes) else raw_path.encode("utf-8"))
        self._dev = dev
        self._current_info = info
        return info

    def close(self) -> None:
        if self._dev is not None:
            try:
                self._dev.close()
            finally:
                self._dev = None
                self._current_info = None

    def get_feature_report(self, report_id: int = 0, length: int = HID_FEATURE_REPORT_LEN) -> bytes:
        if self._dev is None:
            raise RuntimeError("HID device is not open")
        data = bytes(self._dev.get_feature_report(report_id, length))
        return data

    def send_feature_report(self, report_65: bytes) -> int:
        if self._dev is None:
            raise RuntimeError("HID device is not open")
        if len(report_65) != HID_FEATURE_REPORT_LEN:
            raise ValueError(f"Expected {HID_FEATURE_REPORT_LEN}B feature report, got {len(report_65)}B")
        return int(self._dev.send_feature_report(report_65))


class GuardedHidSession:
    """All L1/L2 device reads and queries MUST go through this guarded session."""

    def __init__(
        self,
        transport: FeatureTransport,
        guard: ReadOnlyGuard | WriteGuard,
        capture: CaptureLogger | None = None,
    ) -> None:
        self.transport = transport
        self.guard = guard
        self.capture = capture or CaptureLogger("session")
        self._device: HidDeviceInfo | None = None

    def __enter__(self) -> GuardedHidSession:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def enumerate(self, vid: int = VENDOR_ID) -> list[HidDeviceInfo]:
        devices = self.transport.enumerate_devices(vid)
        self.capture.record(
            "L0_enumerate",
            vid=f"0x{vid:04X}",
            devices=[d.to_dict() for d in devices],
        )
        return devices

    def open_for_level(
        self,
        info: HidDeviceInfo,
        level: ProbeLevel,
        *,
        target_role: TargetRole | None = None,
    ) -> HidDeviceInfo:
        if info.classification == DeviceClassification.BLE_EXCLUDED:
            raise SafetyViolationError("Refusing to open BLE-excluded device path")
        self.guard.check_device_allowed(info.vid, info.pid, level, target_role=target_role)
        opened = self.transport.open(info.path)
        self._device = info
        self.capture.record(
            "device_open",
            level=level.name,
            target_role=target_role.value if target_role else None,
            device=info.to_dict(),
        )
        return opened

    def close(self) -> None:
        self.transport.close()
        self._device = None

    def passive_read(self) -> bytes:
        """L1: GET_FEATURE only, zero SET_FEATURE."""
        if self._device is None:
            raise RuntimeError("No device opened")
        self.guard.check_device_allowed(
            self._device.vid, self._device.pid, ProbeLevel.L1_PASSIVE_READ
        )
        raw_report = self.transport.get_feature_report(0, HID_FEATURE_REPORT_LEN)
        frame_64 = from_hid_feature_report(raw_report)
        self.capture.record(
            "L1_passive_get_feature",
            raw_report_hex=raw_report.hex(),
            frame_64_hex=frame_64.hex(),
        )
        return frame_64

    def query(
        self,
        target_role: TargetRole,
        frame_64: bytes,
        *,
        poll_interval_ms: float = 5.0,
        timeout_ms: float = 500.0,
    ) -> tuple[CommandSpec, ParsedReply]:
        """L2: strictly guarded whitelist query with 0xA0 pending polling."""
        if self._device is None:
            raise RuntimeError("No device opened")

        self.guard.check_device_allowed(
            self._device.vid,
            self._device.pid,
            ProbeLevel.L2_WHITELIST_QUERY,
            target_role=target_role,
        )
        # Mandatory gate BEFORE touching transport
        spec = self.guard.validate_outgoing_frame(target_role, frame_64)

        hid_report = to_hid_feature_report(frame_64)
        self.capture.record(
            "L2_tx_set_feature",
            command=spec.name,
            target_role=target_role.value,
            frame_64_hex=frame_64.hex(),
            report_65_hex=hid_report.hex(),
        )
        self.transport.send_feature_report(hid_report)

        deadline = time.monotonic() + (timeout_ms / 1000.0)
        polls: list[str] = []
        reply_64 = b""
        while True:
            raw_report = self.transport.get_feature_report(0, HID_FEATURE_REPORT_LEN)
            reply_64 = from_hid_feature_report(raw_report)
            polls.append(reply_64.hex())
            status = reply_64[0]
            if status not in (STATUS_PENDING, STATUS_IDLE):
                break
            if time.monotonic() >= deadline:
                self.capture.record(
                    "L2_rx_timeout",
                    command=spec.name,
                    poll_count=len(polls),
                    last_frame_hex=reply_64.hex(),
                )
                raise TimeoutError(
                    f"Command {spec.name} timed out after {timeout_ms}ms (last status=0x{status:02X})"
                )
            if poll_interval_ms > 0:
                time.sleep(poll_interval_ms / 1000.0)

        self.capture.record(
            "L2_rx_get_feature",
            command=spec.name,
            poll_count=len(polls),
            polls_hex=polls,
            final_frame_hex=reply_64.hex(),
        )

        if spec.family == ProtocolFamily.A:
            parsed = parse_family_a_reply(
                reply_64,
                expected_group=spec.group,
                expected_subcmd=spec.cmd,
                fallback_len=spec.expected_reply_len,
            )
        else:
            parsed = parse_family_b_reply(
                reply_64,
                expected_cmd=spec.cmd,
                fallback_len=spec.expected_reply_len,
            )
        return spec, parsed
