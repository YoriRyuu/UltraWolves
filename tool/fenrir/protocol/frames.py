"""64-byte device frame and 65-byte Windows HID Feature report builders/parsers."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from fenrir.constants import (
    DEVICE_FRAME_LEN,
    HID_FEATURE_REPORT_LEN,
    SENSOR_BRANCH_REPLY_TO_ID,
    STATUS_FAIL,
    STATUS_IDLE,
    STATUS_INVALID,
    STATUS_OK,
    STATUS_PENDING,
    STATUS_RF_DISCONNECTED,
)


class FrameError(ValueError):
    """Raised when a frame or reply violates structural expectations."""


@dataclass(frozen=True)
class DeviceFrame:
    """Validated 64-byte device-side frame (without Windows Report ID prefix)."""

    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, (bytes, bytearray)) or len(self.data) != DEVICE_FRAME_LEN:
            raise FrameError(f"DeviceFrame must be exactly {DEVICE_FRAME_LEN} bytes")
        object.__setattr__(self, "data", bytes(self.data))

    def to_hid_report(self) -> bytes:
        return to_hid_feature_report(self.data)

    def hex(self) -> str:
        return self.data.hex()


@dataclass(frozen=True)
class ParsedReply:
    """Normalized reply parsed from a 64-byte device buffer."""

    family: str  # "A" or "B"
    status: int
    route: int
    group: int | None
    cmd: int
    length: int
    payload: bytes
    raw: bytes

    @property
    def is_ok(self) -> bool:
        return self.status == STATUS_OK

    @property
    def is_pending(self) -> bool:
        return self.status == STATUS_PENDING

    @property
    def status_name(self) -> str:
        return {
            STATUS_IDLE: "IDLE(0x00)",
            STATUS_PENDING: "PENDING(0xA0)",
            STATUS_OK: "OK(0xA1)",
            STATUS_FAIL: "FAIL(0xA2)",
            STATUS_INVALID: "INVALID(0xA3)",
            STATUS_RF_DISCONNECTED: "RF_DISCONNECTED(0xA4)",
        }.get(self.status, f"UNKNOWN(0x{self.status:02X})")


def to_hid_feature_report(frame_64: bytes) -> bytes:
    """Prepend Windows HID Report ID 0x00 to a 64-byte device frame."""
    if len(frame_64) != DEVICE_FRAME_LEN:
        raise FrameError(f"Expected {DEVICE_FRAME_LEN}B device frame, got {len(frame_64)}B")
    return b"\x00" + bytes(frame_64)


def from_hid_feature_report(report: bytes) -> bytes:
    """Convert a 65-byte Windows HID Feature report (or raw 64B frame) to 64B device frame."""
    raw = bytes(report)
    if len(raw) == HID_FEATURE_REPORT_LEN:
        return raw[1:]
    if len(raw) == DEVICE_FRAME_LEN:
        return raw
    raise FrameError(
        f"Expected {HID_FEATURE_REPORT_LEN}B HID report or {DEVICE_FRAME_LEN}B frame, got {len(raw)}B"
    )


def identify_frame_family(frame_64: bytes) -> str:
    """Return 'A' or 'B' matching firmware 0x18494 routing: byte[1]==0 or byte[2]==0 -> 'A'."""
    if len(frame_64) != DEVICE_FRAME_LEN:
        raise FrameError(f"Expected {DEVICE_FRAME_LEN}B device frame, got {len(frame_64)}B")
    if frame_64[1] == 0 or frame_64[2] == 0:
        return "A"
    return "B"


def build_family_a_frame(
    group: int,
    subcmd: int,
    payload: bytes = b"",
    *,
    route: int = 0,
    status: int = STATUS_IDLE,
    length_override: int | None = None,
) -> DeviceFrame:
    """Build a 64B Family A frame: [status, 0x00, route, len, group, subcmd, *payload]."""
    if not (0 <= group <= 0xFF and 0 <= subcmd <= 0xFF):
        raise FrameError("group and subcmd must be u8")
    if not (0 <= route <= 0xFF and 0 <= status <= 0xFF):
        raise FrameError("route and status must be u8")
    if len(payload) > 58:
        raise FrameError(f"Family A payload too long: {len(payload)} > 58")
    length_byte = len(payload) if length_override is None else length_override
    if not (0 <= length_byte < 0x3A):
        # Firmware 0x18494 subtracts 6 when byte[3] >= 0x3A; prohibit >= 0x3A to avoid aliasing.
        raise FrameError(f"Family A length byte must be 0..57, got {length_byte}")

    buf = bytearray(DEVICE_FRAME_LEN)
    buf[0] = status
    buf[1] = 0x00
    buf[2] = route
    buf[3] = length_byte
    buf[4] = group
    buf[5] = subcmd
    buf[6 : 6 + len(payload)] = payload
    return DeviceFrame(bytes(buf))


def build_family_b_frame(
    cmd: int,
    payload: bytes = b"",
    *,
    route: int = 0,
    length_override: int | None = None,
    status: int = STATUS_IDLE,
) -> DeviceFrame:
    """Build a 64B Family B frame: [status, len(!=0), cmd(!=0), route, *payload]."""
    if not (1 <= cmd <= 0xFF):
        raise FrameError("Family B cmd must be 1..255 (0 routes to Family A)")
    if not (0 <= route <= 0xFF and 0 <= status <= 0xFF):
        raise FrameError("route and status must be u8")
    if len(payload) > 60:
        raise FrameError(f"Family B payload too long: {len(payload)} > 60")
    length_byte = max(1, len(payload)) if length_override is None else length_override
    if not (1 <= length_byte <= 60):
        raise FrameError(f"Family B length byte must be 1..60 (0 routes to Family A), got {length_byte}")

    buf = bytearray(DEVICE_FRAME_LEN)
    buf[0] = status
    buf[1] = length_byte
    buf[2] = cmd
    buf[3] = route
    buf[4 : 4 + len(payload)] = payload
    return DeviceFrame(bytes(buf))


def parse_family_a_reply(
    frame_64: bytes,
    *,
    expected_group: int | None = None,
    expected_subcmd: int | None = None,
    fallback_len: int | None = None,
) -> ParsedReply:
    """Parse a 64B Family A reply."""
    if len(frame_64) != DEVICE_FRAME_LEN:
        raise FrameError(f"Expected {DEVICE_FRAME_LEN}B reply, got {len(frame_64)}B")
    raw = bytes(frame_64)
    status = raw[0]
    route = raw[2]
    length = raw[3]
    group = raw[4]
    cmd = raw[5]

    if expected_group is not None and group != expected_group:
        raise FrameError(f"Family A group echo mismatch: expected {expected_group}, got {group}")
    if expected_subcmd is not None and cmd != expected_subcmd:
        raise FrameError(
            f"Family A subcmd echo mismatch: expected 0x{expected_subcmd:02X}, got 0x{cmd:02X}"
        )

    eff_len = length if length > 0 else (fallback_len or 0)
    eff_len = min(eff_len, DEVICE_FRAME_LEN - 6)
    return ParsedReply(
        family="A",
        status=status,
        route=route,
        group=group,
        cmd=cmd,
        length=length,
        payload=raw[6 : 6 + eff_len],
        raw=raw,
    )


def parse_family_b_reply(
    frame_64: bytes,
    *,
    expected_cmd: int | None = None,
    fallback_len: int | None = None,
) -> ParsedReply:
    """Parse a 64B Family B reply."""
    if len(frame_64) != DEVICE_FRAME_LEN:
        raise FrameError(f"Expected {DEVICE_FRAME_LEN}B reply, got {len(frame_64)}B")
    raw = bytes(frame_64)
    status = raw[0]
    length = raw[1]
    cmd = raw[2]

    if expected_cmd is not None and cmd != expected_cmd:
        raise FrameError(
            f"Family B cmd echo mismatch: expected 0x{expected_cmd:02X}, got 0x{cmd:02X}"
        )

    eff_len = length if length > 0 else (fallback_len or 0)
    eff_len = min(eff_len, DEVICE_FRAME_LEN - 4)
    return ParsedReply(
        family="B",
        status=status,
        route=raw[3],
        group=None,
        cmd=cmd,
        length=length,
        payload=raw[4 : 4 + eff_len],
        raw=raw,
    )


# --- Structured payload decoders ---


def decode_version_6b(payload: bytes) -> dict[str, Any]:
    """Decode 6B version+PID payload from Family A group0 0x81 / receiver 0x81."""
    if len(payload) < 6:
        raise FrameError(f"Expected >= 6B version payload, got {len(payload)}B")
    b = payload[:6]
    return {
        "major": b[0],
        "minor": b[1],
        "patch": b[2],
        "build": b[3],
        "version_str": f"v{b[0]}.{b[1]:02d}.{b[2]:02d}.{b[3]:02d}",
        "tail_bytes_hex": b[4:6].hex(),
        "tail_u16_be": int.from_bytes(b[4:6], "big"),
        "raw_hex": b.hex(),
    }


def decode_family_b_version(payload: bytes) -> dict[str, Any]:
    """Decode 7B Family B 0x81 reply: 6B version/PID + 1B sensor branch mapping."""
    if len(payload) < 7:
        raise FrameError(f"Expected >= 7B Family B 0x81 payload, got {len(payload)}B")
    base = decode_version_6b(payload[:6])
    branch_byte = payload[6]
    base["sensor_branch_byte"] = branch_byte
    base["sensor_branch_byte_hex"] = f"0x{branch_byte:02X}"
    base["sensor_branch_id"] = SENSOR_BRANCH_REPLY_TO_ID.get(
        branch_byte, f"UNKNOWN(0x{branch_byte:02X})"
    )
    base["raw_hex"] = payload[:7].hex()
    return base


def decode_device_id(payload: bytes) -> dict[str, Any]:
    """Decode 4B FICR->DEVICEID[0] reply from Family A group0 0x8A or Family B 0x93."""
    if len(payload) < 4:
        raise FrameError(f"Expected >= 4B device ID payload, got {len(payload)}B")
    b = payload[:4]
    return {
        "raw_hex": b.hex(),
        "u32_le": int.from_bytes(b, "little"),
        "u32_be": int.from_bytes(b, "big"),
    }


def decode_battery_status(payload: bytes) -> dict[str, Any]:
    """Decode 2B battery/charging input status (charging flag, battery pct)."""
    if len(payload) < 2:
        raise FrameError(f"Expected >= 2B battery payload, got {len(payload)}B")
    return {
        "charging": bool(payload[0]),
        "battery_pct": payload[1],
        "battery_raw": payload[0],
        "external_input_raw": payload[1],
        "raw_hex": payload[:2].hex(),
    }


def decode_debounce(payload: bytes) -> dict[str, Any]:
    """Decode 4B debounce thresholds (0x200043FE..0x20004401)."""
    if len(payload) < 4:
        raise FrameError(f"Expected >= 4B debounce payload, got {len(payload)}B")
    return {
        "thresholds": list(payload[:4]),
        "raw_hex": payload[:4].hex(),
    }


def decode_dpi_table(payload: bytes) -> dict[str, Any]:
    """Decode 51B 7-slot DPI table from Family B 0x83."""
    if len(payload) < 51:
        raise FrameError(f"Expected >= 51B DPI table payload, got {len(payload)}B")
    active_slot_1based = payload[0]
    stage_count = payload[1]
    slots = []
    for i in range(7):
        off = 2 + 7 * i
        x_cpi, y_cpi = struct.unpack_from(">HH", payload, off)
        r, g, b = payload[off + 4], payload[off + 5], payload[off + 6]
        slots.append(
            {
                "slot": i + 1,
                "x_cpi": x_cpi,
                "y_cpi": y_cpi,
                "rgb": [r, g, b],
            }
        )
    return {
        "active_slot": active_slot_1based,
        "stage_count": stage_count,
        "slots": slots,
    }


def decode_keymap_6(payload: bytes) -> dict[str, Any]:
    """Decode 36B 6-button mapping from Family B 0x84."""
    if len(payload) < 36:
        raise FrameError(f"Expected >= 36B keymap payload, got {len(payload)}B")
    buttons = []
    for i in range(6):
        entry = payload[6 * i : 6 * (i + 1)]
        buttons.append(
            {
                "button_index": i,
                "action_type": entry[0],
                "data_hex": entry[1:].hex(),
            }
        )
    return {"buttons": buttons}
