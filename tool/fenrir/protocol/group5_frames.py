"""Phase 2 Family A Group 5 frame builders and reply decoders."""

from __future__ import annotations

import struct
from typing import Any

from fenrir.constants import SENSOR_BRANCH_REPLY_TO_ID
from fenrir.protocol.frames import DeviceFrame, FrameError, build_family_a_frame

GROUP5_ID = 5
GROUP5_ABI_MAGIC = b"FNR2"
GROUP5_ABI_VERSION = 1

SUB_GET_STATE = 0x80
SUB_GET_CAPS = 0x80
SUB_SNAP_TRIGGER = 0x01
SUB_SNAP_READ = 0x81
SUB_SET_FPS = 0x02
SUB_SET_DOWNSHIFT = 0x03
SUB_SET_SMOOTHING = 0x04
SUB_PERSIST_CTRL = 0x05
SUB_GET_P3_STATE = 0x82
SUB_GET_P3_DIAG = 0x83
SUB_GET_P1_STATE = 0x84
SUB_GET_P2P3_STATE = 0x85
SUB_SET_P3_CTRL = 0x06
SUB_RESET_P3_DIAG = 0x07
SUB_SET_P1_CFG = 0x08
SUB_SET_LOD_RAW = 0x09
SUB_SET_ANTI_SLAM = 0x0A
SUB_READ_REG = 0x0B

F_SNAPSHOT = 1 << 0
F_FPS_PRESET = 1 << 1
F_FPS_CUSTOM = 1 << 2
F_DOWNSHIFT = 1 << 3
F_SMOOTHING = 1 << 4
F_DEBOUNCE_INSTANT = 1 << 5
F_PERSISTENCE = 1 << 6
F_FAULT_RECOVERY = 1 << 7
F_P3_ATOMIC_MOTION = 1 << 8
F_P3_PLOCK = 1 << 9
F_P3_DIAG = 1 << 10
PHASE3_CAPS_MASK = F_P3_ATOMIC_MOTION | F_P3_PLOCK | F_P3_DIAG
F_P3P_FPS38 = 1 << 11
F_P3P_FIX_A = 1 << 12
F_P3P_PLOCK_LEARN = 1 << 13
F_P3P_MOUSE_ABS = 1 << 14
PHASE3PLUS_CAPS_MASK = (
    PHASE3_CAPS_MASK | F_P3P_FPS38 | F_P3P_FIX_A | F_P3P_PLOCK_LEARN | F_P3P_MOUSE_ABS
)

CAPABILITY_BITS: tuple[tuple[int, str], ...] = (
    (F_SNAPSHOT, "snapshot"),
    (F_FPS_PRESET, "fps_preset"),
    (F_FPS_CUSTOM, "fps_custom"),
    (F_DOWNSHIFT, "downshift"),
    (F_SMOOTHING, "smoothing"),
    (F_DEBOUNCE_INSTANT, "debounce_instant"),
    (F_PERSISTENCE, "persistence"),
    (F_FAULT_RECOVERY, "fault_recovery"),
    (F_P3_ATOMIC_MOTION, "p3_atomic_motion"),
    (F_P3_PLOCK, "p3_plock"),
    (F_P3_DIAG, "p3_diag"),
    (F_P3P_FPS38, "p3p_fps38"),
    (F_P3P_FIX_A, "p3p_fix_a"),
    (F_P3P_PLOCK_LEARN, "p3p_plock_learn"),
    (F_P3P_MOUSE_ABS, "p3p_mouse_abs"),
)

P3_MAGIC_BYTES = b"FRP3"
P3_STATE_BYTES = 20
P1_STATE_BYTES = 32
P2P3_STATE_BYTES = 20
P3_FLAG_ATOMIC_ACCUM = 1 << 0
P3_FLAG_QUEUE_GUARD = 1 << 1
P3_FLAG_DIRECT_MOTION = 1 << 2
P3_FLAG_PLOCK_ENABLE = 1 << 3
P3_FLAG_FIX_A = 1 << 4
P3_FLAG_MOUSE_ABS = 1 << 5
P3_FLAG_EAGER_WAKE = 1 << 6
P3_FLAG_CE_STATIC = 1 << 7
P3_FLAGS_MASK = 0x0F
P3PLUS_FLAGS_MASK = 0xFF
P3_FLAGS_DEFAULT = P3_FLAG_ATOMIC_ACCUM | P3_FLAG_QUEUE_GUARD

F_W2_EAGER_WAKE = 1 << 0
F_W2_CE_STATIC = 1 << 1
F_W2_LOD_RAW = 1 << 2
F_W2_ANTI_SLAM = 1 << 3
F_W2_READ_REG = 1 << 4
W2_CAPS_MASK = F_W2_EAGER_WAKE | F_W2_CE_STATIC | F_W2_LOD_RAW | F_W2_ANTI_SLAM | F_W2_READ_REG

ANTI_SLAM_LANDING_DEFAULT_MS = 16
ANTI_SLAM_LIFTED_DEFAULT_MS = 20
ANTI_SLAM_MAX_MS = 100

PLOCK_MODE_ENTRY = 0
PLOCK_MODE_MEASURE = 1
PLOCK_MODE_LEARN = 2
PLOCK_MODE_KEEP = 0xFF
PLOCK_MODE_NAMES: dict[int, str] = {
    PLOCK_MODE_ENTRY: "entry",
    PLOCK_MODE_MEASURE: "measure",
    PLOCK_MODE_LEARN: "learn",
}
PLOCK_MODE_FROM_NAME: dict[str, int] = {
    "entry": PLOCK_MODE_ENTRY,
    "measure": PLOCK_MODE_MEASURE,
    "learn": PLOCK_MODE_LEARN,
    "keep": PLOCK_MODE_KEEP,
}
P1_ACTION_RESET_MINMAX = 1 << 0
P1_ACTION_CLEAR_LEARNED = 1 << 1
P1_ACTIONS_MASK = 0x03

PLOCK_PERIOD_DEFAULT_US = 125
PLOCK_LEAD_DEFAULT_US = 25
PLOCK_PERIOD_MIN_US = 50
PLOCK_PERIOD_MAX_US = 2000
PLOCK_LEAD_MIN_US = 8

P3_PHASE_STATE_NAMES: dict[int, str] = {
    0: "off",
    1: "locked",
    2: "paused_for_flash",
}

P3_DIAG_NAMES: tuple[str, ...] = (
    "spim3_samples",
    "spim3_motion",
    "race_preserved",
    "tx_ok",
    "tx_busy",
    "ep81_drops_saved",
    "direct_tx_ok",
    "direct_tx_deferred",
    "irq9_ticks",
    "plock_adjusts",
    "plock_resets",
    "flash_pauses",
    "stationary_ticks",
    "active_ticks",
)
P3_DIAG_BYTES = len(P3_DIAG_NAMES) * 4

GROUP5_ERR_NAMES: dict[int, str] = {
    0: "ERR_NONE",
    1: "ERR_NOT_ID53",
    2: "ERR_SPI_WRITE",
    3: "ERR_READBACK_MISMATCH",
    4: "ERR_WORKER_QUEUE_FULL",
    5: "ERR_PERSIST_FAILED",
}

SNAP_STATUS_NAMES: dict[int, str] = {
    0: "idle",
    1: "pending",
    2: "ready",
    3: "error",
}

FPS_PRESET_NAMES: dict[int, str] = {
    0: "stock",
    1: "20k",
    2: "16k",
    3: "14k",
    4: "12k",
    5: "10k",
    6: "8k",
    7: "4k",
    255: "custom",
}
FPS_NAME_TO_CODE: dict[str, int] = {v: k for k, v in FPS_PRESET_NAMES.items()}

FPS_PRESETS_P3PLUS_SPECS: tuple[tuple[int, str, int, int, int], ...] = (
    (0, "stock", 0, 0, 0),
    (1, "20k", 20, 2, 2),
    (2, "16k", 25, 2, 2),
    (3, "14k", 29, 2, 2),
    (4, "12k", 33, 2, 2),
    (5, "10k", 20, 4, 4),
    (6, "8k", 20, 5, 5),
    (7, "4k", 20, 10, 10),
    (8, "19k", 21, 2, 2),
    (9, "18k", 22, 2, 2),
    (10, "17k", 24, 2, 2),
    (11, "15k", 27, 2, 2),
    (12, "13k", 31, 2, 2),
    (13, "11k", 36, 2, 2),
    (14, "9k", 22, 4, 4),
    (15, "7k", 38, 3, 3),
    (16, "6k", 33, 4, 4),
    (17, "5k", 20, 8, 8),
    (18, "13-20k", 20, 3, 2),
    (19, "10-20k", 20, 4, 2),
    (20, "8-20k", 20, 5, 2),
    (21, "6.7-20k", 20, 6, 2),
    (22, "5-20k", 20, 8, 2),
    (23, "8-16k", 25, 4, 2),
    (24, "8-13k", 20, 5, 3),
    (25, "8-12k", 33, 3, 2),
    (26, "9.2k", 29, 3, 3),
    (27, "6.9k", 29, 4, 4),
    (28, "5.5k", 29, 5, 5),
    (29, "4.6k", 29, 6, 6),
    (30, "9.2-13.8k", 29, 3, 2),
    (31, "6.9-13.8k", 29, 4, 2),
    (32, "5.5-13.8k", 29, 5, 2),
    (33, "4-8k", 20, 10, 5),
    (34, "13.3k", 20, 3, 3),
    (35, "16k-cal", 24, 2, 2),
    (36, "16k-cal-fast", 23, 2, 2),
    (37, "13.3k-b", 60, 1, 1),
)
FPS_PRESET_NAMES_P3PLUS: dict[int, str] = {
    **{code: name for code, name, *_ in FPS_PRESETS_P3PLUS_SPECS},
    255: "custom",
}
FPS_NAME_TO_CODE_P3PLUS: dict[str, int] = {v: k for k, v in FPS_PRESET_NAMES_P3PLUS.items()}
FPS_PRESET_COUNT_P3PLUS = 38

PERSIST_ACTIONS: dict[str, int] = {
    "save": 1,
    "reset": 2,
    "async_save": 3,
}

SNAPSHOT_REGISTERS: tuple[tuple[int, int], ...] = (
    (0x07, 0x42),
    (0x06, 0x53),
    (0x06, 0x62),
    (0x06, 0x6D),
    (0x06, 0x6E),
    (0x05, 0x44),
    (0x0C, 0x4D),
    (0x00, 0x40),
)


def _resolve_group5_route(*, wireless: bool = False, route: int | None = None) -> int:
    if route is not None:
        if route not in (0, 2):
            raise FrameError(f"Family A route must be 0 or 2, got {route}")
        return route
    return 2 if wireless else 0


def _build_g5(
    subcmd: int,
    payload: bytes = b"",
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    eff_route = _resolve_group5_route(wireless=wireless, route=route)
    if len(payload) > 57:
        raise FrameError(f"Group 5 payload too long: {len(payload)} > 57")
    frame = build_family_a_frame(GROUP5_ID, subcmd, payload, route=eff_route)
    if eff_route != 0 and frame.data[4] == 0xB0:
        raise FrameError("Receiver-routed frame[4] == 0xB0 blocked")
    return frame


def build_group5_get_state_frame(*, wireless: bool = False, route: int | None = None) -> DeviceFrame:
    """Build Group 5 0x80 GET_STATE / GET_CAPS query frame."""
    return _build_g5(SUB_GET_STATE, b"", wireless=wireless, route=route)


def build_group5_snap_trigger_frame(
    seq: int = 1, *, wireless: bool = False, route: int | None = None
) -> DeviceFrame:
    """Build Group 5 0x01 SNAP_TRIGGER frame (u16 LE seq != 0)."""
    if not (1 <= seq <= 0xFFFF):
        raise FrameError(f"Snapshot seq must be 1..65535, got {seq}")
    return _build_g5(SUB_SNAP_TRIGGER, struct.pack("<H", seq), wireless=wireless, route=route)


def build_group5_snap_read_frame(*, wireless: bool = False, route: int | None = None) -> DeviceFrame:
    """Build Group 5 0x81 SNAP_READ query frame."""
    return _build_g5(SUB_SNAP_READ, b"", wireless=wireless, route=route)


def _parse_named_or_int(val: int | str, mapping: dict[str, int], kind: str) -> int:
    if isinstance(val, bool):
        raise FrameError(f"Invalid {kind}: {val!r}")
    if isinstance(val, str):
        key = val.strip().lower()
        if key in mapping:
            return mapping[key]
        try:
            return int(key, 0)
        except ValueError as exc:
            raise FrameError(f"Invalid {kind}: {val!r}") from exc
    try:
        return int(val)
    except (TypeError, ValueError) as exc:
        raise FrameError(f"Invalid {kind}: {val!r}") from exc


def resolve_fps_mode(mode: int | str, *, allow_p3plus: bool = False) -> int:
    mapping = FPS_NAME_TO_CODE_P3PLUS if allow_p3plus else FPS_NAME_TO_CODE
    max_code = FPS_PRESET_COUNT_P3PLUS - 1 if allow_p3plus else 7
    val = _parse_named_or_int(mode, mapping, "FPS mode")
    if val != 255 and not (0 <= val <= max_code):
        raise FrameError(f"FPS mode must be 0..{max_code} or 255 (custom), got {mode!r}")
    return val


def build_group5_set_fps_frame(
    mode: int | str,
    custom: tuple[int, int, int] | None = None,
    *,
    allow_p3plus: bool = False,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Group 5 0x02 SET_FPS frame (preset 0..7/0..37 or [255, U, slow, fast])."""
    code = resolve_fps_mode(mode, allow_p3plus=allow_p3plus)
    if code == 255:
        if custom is None or len(custom) != 3:
            raise FrameError("Custom FPS mode (255) requires 3-tuple (U, slow, fast)")
        u, slow, fast = (int(custom[0]), int(custom[1]), int(custom[2]))
        if any(not (0 <= x <= 0xFF) for x in (u, slow, fast)):
            raise FrameError(f"Custom FPS bytes must be u8: {custom!r}")
        if u == 0 or fast == 0 or slow < fast:
            raise FrameError(f"Invalid custom FPS tuple (require U!=0, fast!=0, slow>=fast), got {custom!r}")
        payload = bytes((255, u, slow, fast))
    else:
        if custom is not None:
            raise FrameError("custom tuple is only valid when mode == 255 / 'custom'")
        payload = bytes((code,))
    return _build_g5(SUB_SET_FPS, payload, wireless=wireless, route=route)


def build_group5_set_downshift_frame(
    enable: bool | int, *, wireless: bool = False, route: int | None = None
) -> DeviceFrame:
    """Build Group 5 0x03 SET_DOWNSHIFT frame (0 or 1)."""
    val = int(enable) if not isinstance(enable, bool) else (1 if enable else 0)
    if val not in (0, 1):
        raise FrameError(f"Downshift value must be 0 or 1, got {enable!r}")
    return _build_g5(SUB_SET_DOWNSHIFT, bytes((val,)), wireless=wireless, route=route)


def build_group5_set_smoothing_frame(
    enable: bool | int, *, wireless: bool = False, route: int | None = None
) -> DeviceFrame:
    """Build Group 5 0x04 SET_SMOOTHING frame (0 or 1)."""
    val = int(enable) if not isinstance(enable, bool) else (1 if enable else 0)
    if val not in (0, 1):
        raise FrameError(f"Smoothing value must be 0 or 1, got {enable!r}")
    return _build_g5(SUB_SET_SMOOTHING, bytes((val,)), wireless=wireless, route=route)


def build_group5_persist_ctrl_frame(
    action: int | str, *, wireless: bool = False, route: int | None = None
) -> DeviceFrame:
    """Build Group 5 0x05 PERSIST_CTRL frame (1=save, 2=reset, 3=async_save)."""
    code = _parse_named_or_int(action, PERSIST_ACTIONS, "persist action")
    if code not in (1, 2, 3):
        raise FrameError(f"Persist action must be 1(save), 2(reset), or 3(async_save), got {action!r}")
    return _build_g5(SUB_PERSIST_CTRL, bytes((code,)), wireless=wireless, route=route)


def decode_group5_snapshot(payload: bytes) -> dict[str, Any]:
    """Decode 24-byte Group 5 0x01 / 0x81 snapshot payload."""
    if len(payload) < 24:
        raise FrameError(f"Expected >= 24B Group 5 snapshot payload, got {len(payload)}B")
    raw = bytes(payload[:24])
    ver, status, err_step, branch, seq_req, seq_done, mode_tgt, mode_app, cpi_x, cpi_y, rsv = (
        struct.unpack_from("<BBBBHHBBHHH", raw, 0)
    )
    regs = [
        {
            "bank": f"0x{bank:02X}",
            "reg": f"0x{reg:02X}",
            "value": val,
            "value_hex": f"0x{val:02X}",
        }
        for (bank, reg), val in zip(SNAPSHOT_REGISTERS, raw[16:24])
    ]
    return {
        "ver": ver,
        "status": status,
        "status_name": SNAP_STATUS_NAMES.get(status, f"unknown({status})"),
        "err_step": err_step,
        "sensor_branch": branch,
        "sensor_branch_hex": f"0x{branch:02X}",
        "seq_req": seq_req,
        "seq_done": seq_done,
        "mode_target": mode_tgt,
        "mode_applied": mode_app,
        "cpi_x": cpi_x,
        "cpi_y": cpi_y,
        "reserved": rsv,
        "registers": regs,
        "raw_hex": raw.hex(),
    }


def decode_group5_state(payload: bytes) -> dict[str, Any]:
    """Decode 51-byte Group 5 0x80 GET_STATE / 0x02..0x05 tail reply payload."""
    if len(payload) < 51:
        raise FrameError(f"Expected >= 51B Group 5 state payload, got {len(payload)}B")
    p = bytes(payload[:51])
    magic, abi_ver, caps_flags, preset_cnt, branch = struct.unpack_from("<4sBHBB", p, 0)
    if magic != GROUP5_ABI_MAGIC or abi_ver != GROUP5_ABI_VERSION:
        raise FrameError(f"Unexpected Group 5 ABI header magic={magic!r} ver={abi_ver}")

    # p[9..40] mirrors PHASE2_RAM_BASE +4..+35 (32 bytes)
    s = p[9:41]
    save_seq = struct.unpack_from("<H", s, 8)[0]
    last_err = s[27]
    caps = [name for bit, name in CAPABILITY_BITS if caps_flags & bit]

    return {
        "magic": magic.decode("ascii"),
        "abi_version": abi_ver,
        "caps_flags": caps_flags,
        "caps": caps,
        "fps_preset_count": preset_cnt,
        "sensor_branch": branch,
        "sensor_branch_hex": f"0x{branch:02X}",
        "is_id53": branch == 0x53,
        "sensor_reply_hint": SENSOR_BRANCH_REPLY_TO_ID.get(branch),
        "config_version": s[0],
        "persistence": {
            "valid": bool(s[7]),
            "save_seq": save_seq,
            "pending": bool(s[25]),
        },
        "fps": {
            "requested": s[1],
            "requested_name": FPS_PRESET_NAMES_P3PLUS.get(s[1], f"unknown({s[1]})"),
            "custom_requested": [s[4], s[5], s[6]],
            "applied": s[10],
            "applied_name": FPS_PRESET_NAMES_P3PLUS.get(s[10], f"unknown({s[10]})"),
            "pending": bool(s[11]),
            "readback_ok": bool(s[12]),
            "readback_regs": {
                "07:42": s[13],
                "06:53": s[14],
                "06:62": s[15],
            },
            "fail_count": s[16],
        },
        "downshift": {
            "requested": bool(s[2]),
            "applied": bool(s[17]),
            "pending": bool(s[18]),
            "readback_ok": bool(s[19]),
            "readback_val": s[20],
        },
        "smoothing": {
            "requested": bool(s[3]),
            "applied": bool(s[21]),
            "pending": bool(s[22]),
            "readback_ok": bool(s[23]),
            "readback_val": s[24],
        },
        "worker_queued": bool(s[26]),
        "last_err": last_err,
        "last_err_name": GROUP5_ERR_NAMES.get(last_err, f"ERR_UNKNOWN({last_err})"),
        "snapshot_header": {
            "ver": s[28],
            "status": s[29],
            "status_name": SNAP_STATUS_NAMES.get(s[29], f"unknown({s[29]})"),
            "err_step": s[30],
            "sensor_branch": s[31],
        },
        "debounce": {
            "persisted": list(p[41:45]),
            "live_thresholds": list(p[45:51]),
        },
        "raw_hex": p.hex(),
    }


def build_group5_get_p3_state_frame(*, wireless: bool = False, route: int | None = None) -> DeviceFrame:
    """Build Phase 3 Group 5 0x82 GET_P3_STATE query frame (len=0 -> 20B)."""
    return _build_g5(SUB_GET_P3_STATE, b"", wireless=wireless, route=route)


def build_group5_get_p3_diag_frame(*, wireless: bool = False, route: int | None = None) -> DeviceFrame:
    """Build Phase 3 Group 5 0x83 GET_P3_DIAG query frame (len=0 -> 56B)."""
    return _build_g5(SUB_GET_P3_DIAG, b"", wireless=wireless, route=route)


def build_group5_reset_p3_diag_frame(*, wireless: bool = False, route: int | None = None) -> DeviceFrame:
    """Build Phase 3 Group 5 0x07 RESET_P3_DIAG write frame (len=0 -> 56B zeros)."""
    return _build_g5(SUB_RESET_P3_DIAG, b"", wireless=wireless, route=route)


def build_group5_set_p3_ctrl_frame(
    flags: int,
    *,
    period_us: int | None = None,
    lead_us: int | None = None,
    allow_p3plus: bool = False,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Phase 3/3+ Group 5 0x06 SET_P3_CTRL frame (len=4 u32 flags, or len=8 + u16 period/lead)."""
    flags_mask = P3PLUS_FLAGS_MASK if allow_p3plus else P3_FLAGS_MASK
    if isinstance(flags, bool) or not isinstance(flags, int):
        raise FrameError(f"Phase 3 flags must be an integer bitmask, got {flags!r}")
    if flags < 0 or (flags & ~flags_mask):
        raise FrameError(f"Invalid Phase 3 flags 0x{flags:X} (valid mask 0x{flags_mask:02X})")
    if period_us is None and lead_us is None:
        payload = struct.pack("<I", flags)
    elif period_us is None or lead_us is None:
        raise FrameError("period_us and lead_us must both be specified or both omitted")
    else:
        if any(isinstance(v, bool) or not isinstance(v, int) for v in (period_us, lead_us)):
            raise FrameError(f"period_us and lead_us must be integers, got {(period_us, lead_us)!r}")
        if not (PLOCK_PERIOD_MIN_US <= period_us <= PLOCK_PERIOD_MAX_US):
            raise FrameError(
                f"plock period_us {period_us} outside {PLOCK_PERIOD_MIN_US}..{PLOCK_PERIOD_MAX_US}"
            )
        max_lead = period_us - PLOCK_LEAD_MIN_US
        if not (PLOCK_LEAD_MIN_US <= lead_us <= max_lead):
            raise FrameError(f"plock lead_us {lead_us} outside {PLOCK_LEAD_MIN_US}..{max_lead}")
        payload = struct.pack("<IHH", flags, period_us, lead_us)
    return _build_g5(SUB_SET_P3_CTRL, payload, wireless=wireless, route=route)


def decode_group5_p3_state(payload: bytes) -> dict[str, Any]:
    """Decode 20-byte Phase 3 Group 5 0x82 GET_P3_STATE / 0x06 SET_P3_CTRL payload."""
    if len(payload) < P3_STATE_BYTES:
        raise FrameError(f"Expected >= {P3_STATE_BYTES}B Phase 3 state payload, got {len(payload)}B")
    raw = bytes(payload[:P3_STATE_BYTES])
    if raw[:4] != P3_MAGIC_BYTES:
        raise FrameError(f"Unexpected Phase 3 state magic: {raw[:4]!r}")
    _magic, flags, period_us, lead_us, owner, in_flash, phase_st, stat_st, last_err = struct.unpack_from(
        "<IIHHBBBBi", raw, 0
    )
    return {
        "magic": P3_MAGIC_BYTES.decode("ascii"),
        "flags": flags,
        "atomic_accum": bool(flags & P3_FLAG_ATOMIC_ACCUM),
        "queue_guard": bool(flags & P3_FLAG_QUEUE_GUARD),
        "direct_motion": bool(flags & P3_FLAG_DIRECT_MOTION),
        "plock_enable": bool(flags & P3_FLAG_PLOCK_ENABLE),
        "fix_a_enable": bool(flags & P3_FLAG_FIX_A),
        "mouse_abs_enable": bool(flags & P3_FLAG_MOUSE_ABS),
        "eager_wake_enable": bool(flags & P3_FLAG_EAGER_WAKE),
        "ce_static_enable": bool(flags & P3_FLAG_CE_STATIC),
        "plock_period_us": period_us,
        "plock_lead_us": lead_us,
        "in_tx_owner": owner,
        "in_flash_op": in_flash,
        "plock_phase_state": phase_st,
        "plock_phase_state_name": P3_PHASE_STATE_NAMES.get(phase_st, f"unknown({phase_st})"),
        "stationary_state": stat_st,
        "plock_last_err": last_err,
        "raw_hex": raw.hex(),
    }


def decode_group5_p3_diag(payload: bytes) -> dict[str, int]:
    """Decode 56-byte Phase 3 Group 5 0x83 GET_P3_DIAG / 0x07 RESET_P3_DIAG payload (14 x u32 LE)."""
    if len(payload) < P3_DIAG_BYTES:
        raise FrameError(f"Expected >= {P3_DIAG_BYTES}B Phase 3 diag payload, got {len(payload)}B")
    vals = struct.unpack_from(f"<{len(P3_DIAG_NAMES)}I", payload, 0)
    return {name: int(v) for name, v in zip(P3_DIAG_NAMES, vals)}


def build_group5_get_p1_state_frame(*, wireless: bool = False, route: int | None = None) -> DeviceFrame:
    """Build Phase 3+ P1 Group 5 0x84 GET_P1_STATE query frame (len=0 -> 32B)."""
    return _build_g5(SUB_GET_P1_STATE, b"", wireless=wireless, route=route)


def build_group5_set_p1_cfg_frame(
    mode: int | str = PLOCK_MODE_ENTRY,
    *,
    action_mask: int | None = None,
    reset_minmax: bool = False,
    clear_learned: bool = False,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Phase 3+ P1 Group 5 0x08 SET_P1_CFG frame (len=1 [mode] or len=2 [mode, action_mask])."""
    mode_code = _parse_named_or_int(mode, PLOCK_MODE_FROM_NAME, "plock mode")
    if mode_code not in (PLOCK_MODE_ENTRY, PLOCK_MODE_MEASURE, PLOCK_MODE_LEARN, PLOCK_MODE_KEEP):
        raise FrameError(f"Invalid plock mode {mode!r}; expected entry(0), measure(1), learn(2), or keep(0xFF)")
    if action_mask is not None and (isinstance(action_mask, bool) or not (0 <= action_mask <= P1_ACTIONS_MASK)):
        raise FrameError(f"Invalid P1 action_mask {action_mask!r}; expected 0..{P1_ACTIONS_MASK}")
    extra_bits = (P1_ACTION_RESET_MINMAX if reset_minmax else 0) | (
        P1_ACTION_CLEAR_LEARNED if clear_learned else 0
    )
    if action_mask is None and extra_bits == 0:
        if mode_code == PLOCK_MODE_KEEP:
            raise FrameError("plock mode 'keep' (0xFF) requires reset_minmax, clear_learned, or action_mask")
        payload = struct.pack("<B", mode_code)
    else:
        eff_mask = (0 if action_mask is None else action_mask) | extra_bits
        payload = struct.pack("<BB", mode_code, eff_mask)
    return _build_g5(SUB_SET_P1_CFG, payload, wireless=wireless, route=route)


def decode_group5_p1_state(payload: bytes) -> dict[str, Any]:
    """Decode 32-byte Phase 3+ P1 Group 5 0x84 GET_P1_STATE / 0x08 SET_P1_CFG payload."""
    if len(payload) < P1_STATE_BYTES:
        raise FrameError(f"Expected >= {P1_STATE_BYTES}B P1 state payload, got {len(payload)}B")
    raw = bytes(payload[:P1_STATE_BYTES])
    (
        plock_mode,
        expected_us,
        outlier_pend,
        outlier_valid,
        err_min,
        err_max,
        learn_pend,
        fix_a_state,
        abs_x,
        abs_y,
        fix_a_rb_val,
        fix_a_fail_cnt,
        flags_mirror,
        outliers_skipped,
        plock_learned_cnt,
        abs_tx_pkts,
        abs_q2_drops,
    ) = struct.unpack_from("<BbbBbbBBHHHBB4I", raw, 0)
    return {
        "plock_mode": plock_mode,
        "plock_mode_name": PLOCK_MODE_NAMES.get(plock_mode, f"unknown({plock_mode})"),
        "plock_expected_us": expected_us,
        "plock_outlier_pending": outlier_pend,
        "plock_outlier_valid": bool(outlier_valid),
        "plock_err_min": err_min,
        "plock_err_max": err_max,
        "plock_learn_pend": bool(learn_pend),
        "fix_a_state": fix_a_state,
        "fix_a_req": bool(fix_a_state & 1),
        "fix_a_app": bool(fix_a_state & 2),
        "fix_a_pend": bool(fix_a_state & 4),
        "fix_a_rb_ok": bool(fix_a_state & 8),
        "abs_x": abs_x,
        "abs_y": abs_y,
        "fix_a_rb_val": fix_a_rb_val,
        "fix_a_fail_cnt": fix_a_fail_cnt,
        "flags_mirror": flags_mirror,
        "fix_a_enabled": bool(flags_mirror & P3_FLAG_FIX_A),
        "mouse_abs_enabled": bool(flags_mirror & P3_FLAG_MOUSE_ABS),
        "outliers_skipped": outliers_skipped,
        "plock_learned_cnt": plock_learned_cnt,
        "abs_tx_pkts": abs_tx_pkts,
        "abs_q2_drops": abs_q2_drops,
        "raw_hex": raw.hex(),
    }


def build_group5_get_p2p3_state_frame(*, wireless: bool = False, route: int | None = None) -> DeviceFrame:
    """Build Phase 3+ Wave 2 Group 5 0x85 GET_P2P3_STATE query frame (len=0 -> 20B)."""
    return _build_g5(SUB_GET_P2P3_STATE, b"", wireless=wireless, route=route)


def build_group5_set_lod_raw_frame(
    enabled: bool | int,
    raw_val: int = 0,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Phase 3+ Wave 2 Group 5 0x09 SET_LOD_RAW frame (len=1 [0] or len=2 [1, raw_u8])."""
    if isinstance(enabled, bool):
        en_val = 1 if enabled else 0
    elif isinstance(enabled, int) and enabled in (0, 1):
        en_val = enabled
    else:
        raise FrameError(f"lod_raw enabled must be 0/1/bool, got {enabled!r}")
    if en_val == 0:
        payload = b"\x00"
    else:
        if isinstance(raw_val, bool) or not isinstance(raw_val, int) or not (0 <= raw_val <= 0xFF):
            raise FrameError(f"lod_raw value must be u8 (0..255), got {raw_val!r}")
        payload = struct.pack("<BB", 1, raw_val)
    return _build_g5(SUB_SET_LOD_RAW, payload, wireless=wireless, route=route)


def build_group5_set_anti_slam_frame(
    landing_lock_ms: int = ANTI_SLAM_LANDING_DEFAULT_MS,
    lifted_press_ms: int = ANTI_SLAM_LIFTED_DEFAULT_MS,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Phase 3+ Wave 2 Group 5 0x0A SET_ANTI_SLAM frame (len=2 [landing_ms, lifted_ms] 0..100)."""
    for name, val in (("landing_lock_ms", landing_lock_ms), ("lifted_press_ms", lifted_press_ms)):
        if isinstance(val, bool) or not isinstance(val, int) or not (0 <= val <= ANTI_SLAM_MAX_MS):
            raise FrameError(f"anti-slam {name} must be integer in 0..{ANTI_SLAM_MAX_MS}, got {val!r}")
    payload = struct.pack("<BB", landing_lock_ms, lifted_press_ms)
    return _build_g5(SUB_SET_ANTI_SLAM, payload, wireless=wireless, route=route)


def build_group5_read_reg_frame(
    bank: int,
    reg: int,
    *,
    wireless: bool = False,
    route: int | None = None,
) -> DeviceFrame:
    """Build Phase 3+ Wave 2 Group 5 0x0B READ_REG frame (len=2 [bank, reg])."""
    for name, val in (("bank", bank), ("reg", reg)):
        if isinstance(val, bool) or not isinstance(val, int) or not (0 <= val <= 0xFF):
            raise FrameError(f"read_reg {name} must be u8 (0..255), got {val!r}")
    return _build_g5(SUB_READ_REG, struct.pack("<BB", bank, reg), wireless=wireless, route=route)


def decode_group5_p2p3_state(payload: bytes) -> dict[str, Any]:
    """Decode 20-byte Phase 3+ Wave 2 Group 5 0x85 GET_P2P3_STATE / 0x09..0x0B payload."""
    if len(payload) < P2P3_STATE_BYTES:
        raise FrameError(f"Expected >= {P2P3_STATE_BYTES}B Wave 2 P2/P3 state payload, got {len(payload)}B")
    raw = bytes(payload[:P2P3_STATE_BYTES])
    (
        w2_caps,
        flags_u8,
        ce_state,
        ce_fail_cnt,
        lod_en,
        lod_val,
        lod_state,
        lod_rb_val,
        lod_fail_cnt,
        landing_ms,
        lifted_ms,
        eager_hits,
        peek_bank,
        peek_reg,
        peek_val,
        peek_status,
    ) = struct.unpack_from("<H10BI4B", raw, 0)
    return {
        "w2_caps": w2_caps,
        "eager_wake_cap": bool(w2_caps & F_W2_EAGER_WAKE),
        "ce_static_cap": bool(w2_caps & F_W2_CE_STATIC),
        "lod_raw_cap": bool(w2_caps & F_W2_LOD_RAW),
        "anti_slam_cap": bool(w2_caps & F_W2_ANTI_SLAM),
        "read_reg_cap": bool(w2_caps & F_W2_READ_REG),
        "flags_u8": flags_u8,
        "eager_wake_enabled": bool(flags_u8 & P3_FLAG_EAGER_WAKE),
        "ce_static_enabled": bool(flags_u8 & P3_FLAG_CE_STATIC),
        "ce_static_state": ce_state,
        "ce_static_req": bool(ce_state & 1),
        "ce_static_app": bool(ce_state & 2),
        "ce_static_pend": bool(ce_state & 4),
        "ce_static_rb_ok": bool(ce_state & 8),
        "ce_static_fail_cnt": ce_fail_cnt,
        "lod_raw_en": bool(lod_en),
        "lod_raw_val": lod_val,
        "lod_raw_state": lod_state,
        "lod_raw_req": bool(lod_state & 1),
        "lod_raw_app": bool(lod_state & 2),
        "lod_raw_pend": bool(lod_state & 4),
        "lod_raw_rb_ok": bool(lod_state & 8),
        "lod_raw_rb_val": lod_rb_val,
        "lod_raw_fail_cnt": lod_fail_cnt,
        "anti_slam_landing_ms": landing_ms,
        "anti_slam_lifted_ms": lifted_ms,
        "eager_wake_hits": eager_hits,
        "peek_bank": peek_bank,
        "peek_reg": peek_reg,
        "peek_val": peek_val,
        "peek_status": peek_status,
        "peek_valid": bool(peek_status & 1),
        "peek_pending": bool(peek_status & 2),
        "peek_err": bool(peek_status & 4),
        "raw_hex": raw.hex(),
    }
