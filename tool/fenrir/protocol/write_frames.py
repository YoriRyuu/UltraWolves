"""Phase 1 validated write-frame builders (pure frame construction, zero I/O).

Enforces all RE-proven firmware bounds and safety invariants from
docs/phase1_write_spec.md:
- Family B lenB <= 59, Family A lenA <= 57
- Wireless receiver routing (route != 0) unconditionally rejects frame[4] == 0xB0
- Macro single-page cap (1 <= size <= 4090, chunk <= 52B), id_hi not in {0x00, 0xB0}, id != 0xFFFF
- Never implements bootloader, factory, reset, or restore-defaults write commands
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Sequence

from fenrir.protocol.frames import (
    DeviceFrame,
    FrameError,
    build_family_a_frame,
    build_family_b_frame,
)

MAX_WIRELESS_FAMILY_B_LEN = 59
MAX_FAMILY_A_LEN = 57
MAX_MACRO_OBJECT_SIZE = 4090
MAX_MACRO_CHUNK_LEN = 52
POLLING_RATES_WIRED: frozenset[int] = frozenset({1, 2, 4, 8, 16})
POLLING_RATES_WIRELESS: frozenset[int] = frozenset({1, 2, 4, 8, 16, 32, 64, 128})
VALID_LOD_LEVELS: frozenset[int] = frozenset({1, 2, 3, 7})
VALID_RGB_MODES: frozenset[int] = frozenset({0, 1, 2})
MACRO_ACTION_TYPES: frozenset[int] = frozenset({0x18, 0x19, 0x1A})


@dataclass(frozen=True)
class DpiSlot:
    x_cpi: int
    y_cpi: int
    rgb: tuple[int, int, int] = (255, 0, 0)


@dataclass(frozen=True)
class KeymapEntry:
    action_type: int
    b1: int = 1
    b2: int = 0
    b3: int = 0
    b4: int = 0
    b5: int = 0


def _clamp_int(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(value)))


def _resolve_route(family: str, *, wireless: bool = False, route: int | None = None) -> int:
    if route is not None:
        allowed = (0, 1) if family == "B" else (0, 2)
        if route not in allowed:
            raise FrameError(f"Family {family} route must be in {allowed}, got {route}")
        return route
    if not wireless:
        return 0
    return 1 if family == "B" else 2


def _finalize_b(cmd: int, payload: bytes, *, wireless: bool = False, route: int | None = None) -> DeviceFrame:
    eff_route = _resolve_route("B", wireless=wireless, route=route)
    if len(payload) > MAX_WIRELESS_FAMILY_B_LEN:
        raise FrameError(f"Family B payload length {len(payload)} exceeds {MAX_WIRELESS_FAMILY_B_LEN}")
    frame = build_family_b_frame(cmd, payload, route=eff_route)
    if frame.data[1] > MAX_WIRELESS_FAMILY_B_LEN:
        raise FrameError(f"Family B lenB {frame.data[1]} exceeds {MAX_WIRELESS_FAMILY_B_LEN}")
    if eff_route != 0 and frame.data[4] == 0xB0:
        raise FrameError("Receiver-routed frame[4] == 0xB0 blocked (0x8006870 bootloader SPI bridge trap)")
    return frame


def _finalize_a(
    group: int,
    subcmd: int,
    payload: bytes,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    eff_route = _resolve_route("A", wireless=wireless, route=route)
    if len(payload) > MAX_FAMILY_A_LEN:
        raise FrameError(f"Family A payload length {len(payload)} exceeds {MAX_FAMILY_A_LEN}")
    frame = build_family_a_frame(group, subcmd, payload, route=eff_route)
    if eff_route != 0 and frame.data[4] == 0xB0:
        raise FrameError("Receiver-routed frame[4] == 0xB0 blocked (0x8006870 bootloader SPI bridge trap)")
    return frame


def _validate_macro_object_id(obj_id: int) -> int:
    if not (0 <= obj_id <= 0xFFFF):
        raise FrameError(f"Macro object ID out of u16 range: {obj_id}")
    id_hi = (obj_id >> 8) & 0xFF
    if id_hi in (0x00, 0xB0) or obj_id == 0xFFFF:
        raise FrameError(
            f"Macro object ID 0x{obj_id:04X} forbidden (id_hi in {{0x00, 0xB0}} or 0xFFFF)"
        )
    return obj_id


def build_polling_rate_frame(
    rate_code: int,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x02 polling rate write frame."""
    eff_route = _resolve_route("B", wireless=wireless, route=route)
    allowed = POLLING_RATES_WIRELESS if eff_route != 0 else POLLING_RATES_WIRED
    if rate_code not in allowed:
        raise FrameError(f"Invalid polling rate code 0x{rate_code:02X} for route={eff_route}")
    return _finalize_b(0x02, bytes([rate_code]), route=eff_route)


def _normalize_dpi_slot(item: DpiSlot | Sequence[int]) -> DpiSlot:
    if isinstance(item, DpiSlot):
        slot = item
    elif len(item) == 3 and isinstance(item[2], (tuple, list)):
        slot = DpiSlot(int(item[0]), int(item[1]), (int(item[2][0]), int(item[2][1]), int(item[2][2])))
    elif len(item) == 5:
        slot = DpiSlot(int(item[0]), int(item[1]), (int(item[2]), int(item[3]), int(item[4])))
    else:
        raise FrameError(f"Invalid DPI slot entry: {item!r}")
    if not (1 <= slot.x_cpi <= 0xFFFF and 1 <= slot.y_cpi <= 0xFFFF):
        raise FrameError(f"DPI slot X/Y CPI must be non-zero u16, got ({slot.x_cpi}, {slot.y_cpi})")
    if len(slot.rgb) != 3 or any(not (0 <= c <= 255) for c in slot.rgb):
        raise FrameError(f"DPI slot RGB must be 3 u8 bytes, got {slot.rgb!r}")
    return slot


def build_dpi_table_frame(
    active_slot: int,
    stage_count: int,
    slots: Sequence[DpiSlot | Sequence[int]],
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x03 51B 7-slot DPI table write frame."""
    if not (1 <= active_slot <= stage_count <= 7):
        raise FrameError(f"Must satisfy 1 <= active_slot ({active_slot}) <= stage_count ({stage_count}) <= 7")
    if not (stage_count <= len(slots) <= 7):
        raise FrameError(f"Expected {stage_count}..7 DPI slots, got {len(slots)}")

    norm = [_normalize_dpi_slot(s) for s in slots]
    while len(norm) < 7:
        norm.append(DpiSlot(800, 800, (0, 0, 0)))

    body = bytearray([active_slot, stage_count])
    for s in norm:
        body.extend(struct.pack(">HHBBB", s.x_cpi, s.y_cpi, *s.rgb))
    return _finalize_b(0x03, bytes(body), wireless=wireless, route=route)


def build_debounce_frame(
    press_ms: int,
    release_ms: int,
    lock_press_ms: int,
    lock_release_ms: int,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x05 4-param debounce frame (clamped 0..50 ms)."""
    vals = [_clamp_int(v, 0, 50) for v in (press_ms, release_ms, lock_press_ms, lock_release_ms)]
    return _finalize_b(0x05, bytes(vals), wireless=wireless, route=route)


def build_debounce_press_reload_frame(
    press_ms: int,
    *,
    profile: int = 1,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family A group0 0x08 immediate press debounce reload (profile=1, clamped 0..50 ms)."""
    if profile != 1:
        raise FrameError(f"Only profile=1 permitted (firmware lacks upper bound), got {profile}")
    clamped = _clamp_int(press_ms, 0, 50)
    return _finalize_a(0, 0x08, bytes([profile, clamped]), wireless=wireless, route=route)


def build_lod_frame(
    lod_level: int,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x06 LOD write frame ({1, 2, 3, 7})."""
    if lod_level not in VALID_LOD_LEVELS:
        raise FrameError(f"LOD level must be in {sorted(VALID_LOD_LEVELS)}, got {lod_level}")
    return _finalize_b(0x06, bytes([lod_level]), wireless=wireless, route=route)


def build_motionsync_frame(
    enable: bool,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x11 MotionSync write frame."""
    return _finalize_b(0x11, bytes([1 if enable else 0]), wireless=wireless, route=route)


def build_reg56_frame(
    enable: bool,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x07 sensor reg56 write frame."""
    return _finalize_b(0x07, bytes([1 if enable else 0]), wireless=wireless, route=route)


def build_angle_frame(
    angle_deg: int,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x15 angle write frame (signed int8 clamped -30..30, 0xB0 forbidden)."""
    if (angle_deg & 0xFF) == 0xB0:
        raise FrameError("Raw 0xB0 angle byte unconditionally forbidden")
    clamped = _clamp_int(angle_deg, -30, 30)
    raw_u8 = clamped & 0xFF
    if raw_u8 == 0xB0:
        raise FrameError("Angle byte 0xB0 forbidden")
    return _finalize_b(0x15, bytes([raw_u8]), wireless=wireless, route=route)


def build_sensor_mode_frame(
    high_performance: bool,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x14 sensor mode write frame."""
    return _finalize_b(0x14, bytes([1 if high_performance else 0]), wireless=wireless, route=route)


def build_rgb_led_frame(
    enable: bool,
    effect_mode: int = 2,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x08 5B RGB LED enable & effect mode frame."""
    if effect_mode not in VALID_RGB_MODES:
        raise FrameError(f"RGB effect_mode must be in {sorted(VALID_RGB_MODES)}, got {effect_mode}")
    return _finalize_b(0x08, bytes([1 if enable else 0, effect_mode, 0, 0, 0]), wireless=wireless, route=route)


def build_sleep_timeout_frame(
    seconds: int,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family A group0 0x07 sleep timeout write frame (1..65535 s)."""
    if not (1 <= seconds <= 0xFFFF):
        raise FrameError(f"Sleep timeout must be 1..65535 seconds, got {seconds}")
    return _finalize_a(0, 0x07, struct.pack(">H", seconds), wireless=wireless, route=route)


def _normalize_keymap_entry(item: KeymapEntry | Sequence[int] | bytes) -> bytes:
    if isinstance(item, KeymapEntry):
        vals = (item.action_type, item.b1, item.b2, item.b3, item.b4, item.b5)
    elif len(item) == 6:
        vals = tuple(int(x) for x in item)
    else:
        raise FrameError(f"Keymap entry must have 6 bytes, got {item!r}")

    if any(not (0 <= b <= 0xFF) for b in vals):
        raise FrameError(f"Keymap entry bytes must be u8: {vals!r}")
    action_type, b1, b2 = vals[0], vals[1], vals[2]
    if not (0x00 <= action_type <= 0x1D):
        raise FrameError(f"Keymap action_type 0x{action_type:02X} outside 0x00..0x1D")
    if b1 == 0:
        raise FrameError("Keymap entry b1 must be non-zero (firmware 0x1887A rejects b1==0 with 0xA2)")
    if action_type in MACRO_ACTION_TYPES:
        _validate_macro_object_id((b1 << 8) | b2)
    return bytes(vals)


def build_keymap_frame(
    entries: Sequence[KeymapEntry | Sequence[int] | bytes],
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x04 36B 6-button keymap write frame."""
    if len(entries) != 6:
        raise FrameError(f"Keymap requires exactly 6 entries, got {len(entries)}")
    payload = b"".join(_normalize_keymap_entry(e) for e in entries)
    return _finalize_b(0x04, payload, wireless=wireless, route=route)


def build_macro_create_frame(
    obj_id: int,
    size: int,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x0B macro object create frame (single-page 1..4090B)."""
    _validate_macro_object_id(obj_id)
    if not (1 <= size <= MAX_MACRO_OBJECT_SIZE):
        raise FrameError(f"Macro object size must be 1..{MAX_MACRO_OBJECT_SIZE}, got {size}")
    return _finalize_b(0x0B, struct.pack(">HI", obj_id, size), wireless=wireless, route=route)


def build_macro_delete_frame(
    obj_id: int,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x0C macro object delete frame."""
    _validate_macro_object_id(obj_id)
    return _finalize_b(0x0C, struct.pack(">H", obj_id), wireless=wireless, route=route)


def build_macro_chunk_frame(
    obj_id: int,
    offset: int,
    data: bytes,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Family B 0x0D macro object chunk write frame (1..52B chunk, <=4090B total)."""
    _validate_macro_object_id(obj_id)
    chunk = bytes(data)
    if not (1 <= len(chunk) <= MAX_MACRO_CHUNK_LEN):
        raise FrameError(f"Macro chunk length must be 1..{MAX_MACRO_CHUNK_LEN}, got {len(chunk)}")
    if offset < 0 or offset + len(chunk) > MAX_MACRO_OBJECT_SIZE:
        raise FrameError(
            f"Macro chunk span [{offset}..{offset + len(chunk)}) outside 0..{MAX_MACRO_OBJECT_SIZE}"
        )
    payload = struct.pack(">HIB", obj_id, offset, len(chunk)) + chunk
    return _finalize_b(0x0D, payload, wireless=wireless, route=route)
