"""Phase 3 diagnostic counters, retained control block, and Group 5 handlers.

Retained RAM slice: `0x2003F040 .. 0x2003F0FF` (192 bytes immediately above the
64-byte Phase 2 RAM state block at `0x2003F000`).

Group 5 Phase 3 subcommands (preserving all Phase 2 0x01..0x05 / 0x80..0x81):
  - 0x82 GET_P3_STATE   (len_in=0  -> 20 B control/phase/stationary snapshot)
  - 0x83 GET_P3_DIAG    (len_in=0  -> 56 B atomic 14 x u32 diagnostic counters)
  - 0x06 SET_P3_CTRL    (len_in=4 flags u32, or len_in=8 flags u32 + period u16 + lead u16 -> 20 B state)
  - 0x07 RESET_P3_DIAG  (len_in=0  -> 56 B zeroed diagnostic counters)
"""

from __future__ import annotations

import struct
from typing import Any

from fenrir.patcher import target_mouse as T
from fenrir.patcher.thumb import PatchContext

P3_MAGIC_BYTES = b"FRP3"
P3_MAGIC_U32 = int.from_bytes(P3_MAGIC_BYTES, "little")  # 0x33505246

# Phase 3 feature flags (p3_flags bitmask)
P3_FLAG_ATOMIC_ACCUM = 1 << 0   # Atomic PRIMASK s16 read/subtract across producer + 4 consumers (def ON)
P3_FLAG_QUEUE_GUARD = 1 << 1    # EP81 active-queue overwrite guard at 0x014582 (def ON)
P3_FLAG_DIRECT_MOTION = 1 << 2  # SPIM3 immediate dispatch toggle (def OFF = 0)
P3_FLAG_PLOCK_ENABLE = 1 << 3   # TIMER1 plock phase/period trim toggle (def OFF = 0)
P3_FLAG_FIX_A = 1 << 4          # P1: ID53 Bank 00 0x4E/4F/51/52 -> 0x0257 cap removal (def OFF = 0)
P3_FLAG_MOUSE_ABS = 1 << 5      # P1: Active wireless u16 ABS type 0x0A RF packets (def OFF = 0)
P3_FLAG_EAGER_WAKE = 1 << 6     # Wave 2 P2: IRQ6 immediate sensor wake when direct_motion=1 (def OFF = 0)
P3_FLAG_CE_STATIC = 1 << 7      # Wave 2 P3: ID53 Mode1 Bank 05/09 M1_hi tuning <7000 CPI (def OFF = 0)
P3_FLAGS_MASK = 0x0F
P3PLUS_FLAGS_MASK = 0xFF
P3_FLAGS_DEFAULT = P3_FLAG_ATOMIC_ACCUM | P3_FLAG_QUEUE_GUARD

PLOCK_PERIOD_DEFAULT_US = 125
PLOCK_LEAD_DEFAULT_US = 25
ANTI_SLAM_LANDING_DEFAULT_MS = 16
ANTI_SLAM_LIFTED_DEFAULT_MS = 20
ANTI_SLAM_MAX_MS = 100
PLOCK_PERIOD_MIN_US = 50
PLOCK_PERIOD_MAX_US = 2000
PLOCK_LEAD_MIN_US = 8

PLOCK_MODE_ENTRY = 0
PLOCK_MODE_MEASURE = 1
PLOCK_MODE_LEARN = 2
PLOCK_MODE_KEEP = 0xFF
PLOCK_DEADBAND_US = 8
PLOCK_OUTLIER_US = 16
PLOCK_AGREE_US = 8

# RAM Control Block offsets from T.PHASE3_RAM_BASE (0x2003F040)
OFF_P3_MAGIC = 0x00          # u32 (0x50335246 "FRP3")
OFF_P3_FLAGS = 0x04          # u32
OFF_PLOCK_PERIOD_US = 0x08   # u16
OFF_PLOCK_LEAD_US = 0x0A     # u16
OFF_IN_TX_OWNER = 0x0C       # u8 (bit0 = in_direct_tx, bit1 = in_thread_tx)
OFF_IN_FLASH_OP = 0x0D       # u8 (0 = idle, 1 = paused_for_flash)
OFF_PLOCK_PHASE_STATE = 0x0E # u8 (0 = off, 1 = locked, 2 = flash_paused)
OFF_STAT_STATE = 0x0F        # u8 (bit0 = 0x411C master, bit1 = 0x4119 poll, bit2 = 0x326E gate)
OFF_PLOCK_LAST_ERR = 0x10    # s32 (bytes 0..19 exported contiguously in 0x82 GET_P3_STATE)
OFF_PLOCK_LAST_CC0 = 0x14    # u16
OFF_PLOCK_LAST_CC1 = 0x16    # u16
OFF_SNAP_WL = 0x18           # s16 dx, s16 dy (4 B)
OFF_SNAP_USB = 0x1C          # s16 dx, s16 dy (4 B)
OFF_SNAP_BLE = 0x20          # s16 dx, s16 dy (4 B)
OFF_SNAP_IRQ20 = 0x24        # s16 dx, s16 dy (4 B)

# Phase 3+ P1 Control/Telemetry gap (+0x28..+0x37, 16 B aligned)
OFF_PLOCK_MODE = 0x28          # u8 (0=entry, 1=measure, 2=learn)
OFF_PLOCK_EXPECTED = 0x29      # s8 (learned phase bias us)
OFF_PLOCK_OUTLIER_PEND = 0x2A  # s8
OFF_PLOCK_OUTLIER_VALID = 0x2B # u8
OFF_PLOCK_ERR_MIN = 0x2C       # s8 (init +127 = 0x7F)
OFF_PLOCK_ERR_MAX = 0x2D       # s8 (init -128 = 0x80)
OFF_PLOCK_LEARN_PEND = 0x2E    # u8 (0|1)
OFF_FIX_A_STATE = 0x2F         # u8 (bit0=req, bit1=app, bit2=pend, bit3=rb_ok)
OFF_ABS_X = 0x30               # u16
OFF_ABS_Y = 0x32               # u16
OFF_FIX_A_RB_VAL = 0x34        # u16 (readback (4E<<8)|4F)
OFF_FIX_A_FAIL_CNT = 0x36      # u8
OFF_P3P_FLAGS_MIRROR = 0x37    # u8 (p3_flags & 0xFF mirror)

# Wave 2 P2/P3 Control/State gap (+0x38..+0x3F, 8 B aligned)
OFF_CE_STATIC_STATE = 0x38     # u8 (bit0=req, bit1=app, bit2=pend, bit3=rb_ok)
OFF_LOD_RAW_EN = 0x39          # u8 (0=stock 0x1D388, 1=override 0x18:0x7A)
OFF_LOD_RAW_VAL = 0x3A         # u8 (raw 0x18:0x7A byte)
OFF_LOD_RAW_STATE = 0x3B       # u8 (bit0=req, bit1=app, bit2=pend, bit3=rb_ok)
OFF_ANTI_SLAM_LANDING = 0x3C   # u8 (ms, default 16, 0..100)
OFF_ANTI_SLAM_LIFTED = 0x3D    # u8 (ms, default 20, 0..100)
OFF_PEEK_BANK = 0x3E           # u8
OFF_PEEK_REG = 0x3F            # u8

# Diagnostic Counters: 14 x u32 = 56 B at PHASE3_RAM_BASE + 0x40 (0x2003F080..0x2003F0B7)
OFF_DIAG_BASE = 0x40
DIAG_NAMES: tuple[str, ...] = (
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
DIAG_OFFSETS: dict[str, int] = {
    name: OFF_DIAG_BASE + idx * 4 for idx, name in enumerate(DIAG_NAMES)
}
P3_DIAG_BYTES = len(DIAG_NAMES) * 4  # 56 B
P3_STATE_BYTES = 20

# Phase 3+ P1 Diagnostic Counters: 4 x u32 = 16 B at PHASE3_RAM_BASE + 0x78 (0x2003F0B8..0x2003F0C7)
OFF_P1_DIAG_BASE = 0x78
P1_DIAG_NAMES: tuple[str, ...] = (
    "outliers_skipped",
    "plock_learned_cnt",
    "abs_tx_pkts",
    "abs_q2_drops",
)
P1_DIAG_OFFSETS: dict[str, int] = {
    name: OFF_P1_DIAG_BASE + idx * 4 for idx, name in enumerate(P1_DIAG_NAMES)
}
P1_STATE_BYTES = 32

# Wave 2 P2/P3 Diagnostics & Peek Telemetry (+0x88..+0x93, 12 B)
OFF_EAGER_WAKE_HITS = 0x88     # u32
OFF_PEEK_VAL = 0x8C            # u8
OFF_PEEK_VALID = 0x8D          # u8
OFF_PEEK_PENDING = 0x8E        # u8
OFF_PEEK_ERR = 0x8F            # u8
OFF_CE_STATIC_FAIL_CNT = 0x90  # u8
OFF_LOD_RAW_RB_VAL = 0x91      # u8
OFF_LOD_RAW_FAIL_CNT = 0x92    # u8
OFF_W2_RESERVED = 0x93         # u8
P2P3_STATE_BYTES = 20

# Phase 3 & Phase 3+ Group 5 subcommands
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

# Wave 2 capability flags exported inside 0x85 GET_P2P3_STATE (u16 LE)
F_W2_EAGER_WAKE = 1 << 0
F_W2_CE_STATIC = 1 << 1
F_W2_LOD_RAW = 1 << 2
F_W2_ANTI_SLAM = 1 << 3
F_W2_READ_REG = 1 << 4
W2_CAPS_MASK = F_W2_EAGER_WAKE | F_W2_CE_STATIC | F_W2_LOD_RAW | F_W2_ANTI_SLAM | F_W2_READ_REG

# Phase 3 & Phase 3+ extension capability flags (bits 8..14 in GET_STATE caps u16)
F_P3_ATOMIC_MOTION = 1 << 8
F_P3_PLOCK = 1 << 9
F_P3_DIAG = 1 << 10
PHASE3_CAPS_MASK = F_P3_ATOMIC_MOTION | F_P3_PLOCK | F_P3_DIAG

F_P3P_FPS38 = 1 << 11
F_P3P_FIX_A = 1 << 12
F_P3P_PLOCK_LEARN = 1 << 13
F_P3P_MOUSE_ABS = 1 << 14
PHASE3PLUS_CAPS_MASK = PHASE3_CAPS_MASK | F_P3P_FPS38 | F_P3P_FIX_A | F_P3P_PLOCK_LEARN | F_P3P_MOUSE_ABS


def encode_p3_ctrl(
    flags: int,
    *,
    period_us: int | None = None,
    lead_us: int | None = None,
    flags_mask: int = P3_FLAGS_MASK,
) -> bytes:
    """Encode payload bytes for Group 5 subcommand 0x06 SET_P3_CTRL."""
    if flags & ~flags_mask:
        raise ValueError(f"Invalid Phase 3 flags: 0x{flags:08X} (mask=0x{flags_mask:02X})")
    if period_us is None and lead_us is None:
        return struct.pack("<I", flags)
    if period_us is None or lead_us is None:
        raise ValueError("period_us and lead_us must both be specified or both omitted")
    if not (PLOCK_PERIOD_MIN_US <= period_us <= PLOCK_PERIOD_MAX_US):
        raise ValueError(f"period_us out of range: {period_us}")
    if not (PLOCK_LEAD_MIN_US <= lead_us <= period_us - PLOCK_LEAD_MIN_US):
        raise ValueError(f"lead_us out of range: {lead_us} for period {period_us}")
    return struct.pack("<IHH", flags, period_us, lead_us)


def encode_p1_cfg(plock_mode: int = PLOCK_MODE_ENTRY, *, action_mask: int | None = None) -> bytes:
    """Encode payload bytes for Group 5 subcommand 0x08 SET_P1_CFG."""
    if plock_mode not in (PLOCK_MODE_ENTRY, PLOCK_MODE_MEASURE, PLOCK_MODE_LEARN, PLOCK_MODE_KEEP):
        raise ValueError(f"Invalid plock_mode {plock_mode}")
    if action_mask is None:
        if plock_mode == PLOCK_MODE_KEEP:
            raise ValueError("plock_mode=0xFF requires explicit action_mask")
        return struct.pack("<B", plock_mode)
    if action_mask & ~0x03:
        raise ValueError(f"Invalid action_mask 0x{action_mask:02X}")
    return struct.pack("<BB", plock_mode, action_mask)


def decode_p1_state(payload: bytes) -> dict[str, Any]:
    """Decode the 32-byte 0x84 GET_P1_STATE / 0x08 SET_P1_CFG reply payload."""
    if len(payload) < P1_STATE_BYTES:
        raise ValueError(f"Expected >= {P1_STATE_BYTES} bytes for P1 state, got {len(payload)}")
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
    ) = struct.unpack_from("<BbbBbbBBHHHBB4I", payload, 0)
    mode_names = {PLOCK_MODE_ENTRY: "entry", PLOCK_MODE_MEASURE: "measure", PLOCK_MODE_LEARN: "learn"}
    return {
        "plock_mode": plock_mode,
        "plock_mode_name": mode_names.get(plock_mode, f"unknown_{plock_mode}"),
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
    }


def decode_p3_state(payload: bytes) -> dict[str, Any]:
    """Decode the 20-byte 0x82 GET_P3_STATE / 0x06 SET_P3_CTRL payload."""
    if len(payload) < P3_STATE_BYTES:
        raise ValueError(f"Expected >= {P3_STATE_BYTES} bytes for P3 state, got {len(payload)}")
    magic, flags, period_us, lead_us, owner, in_flash, phase_st, stat_st, last_err = struct.unpack_from(
        "<IIHHBBBBi", payload, 0
    )
    return {
        "magic": payload[:4].decode("ascii", errors="replace"),
        "magic_u32": magic,
        "flags": flags,
        "atomic_accum": bool(flags & P3_FLAG_ATOMIC_ACCUM),
        "queue_guard": bool(flags & P3_FLAG_QUEUE_GUARD),
        "direct_motion": bool(flags & P3_FLAG_DIRECT_MOTION),
        "plock_enable": bool(flags & P3_FLAG_PLOCK_ENABLE),
        "plock_period_us": period_us,
        "plock_lead_us": lead_us,
        "in_tx_owner": owner,
        "in_flash_op": in_flash,
        "plock_phase_state": phase_st,
        "stationary_state": stat_st,
        "plock_last_err": last_err,
    }


def decode_p3_diag(payload: bytes) -> dict[str, int]:
    """Decode the 56-byte 0x83 GET_P3_DIAG / 0x07 RESET_P3_DIAG payload."""
    if len(payload) < P3_DIAG_BYTES:
        raise ValueError(f"Expected >= {P3_DIAG_BYTES} bytes for P3 diag, got {len(payload)}")
    vals = struct.unpack_from(f"<{len(DIAG_NAMES)}I", payload, 0)
    return dict(zip(DIAG_NAMES, vals))


def encode_lod_raw(enabled: bool, raw_val: int = 0) -> bytes:
    """Encode payload for Group 5 subcommand 0x09 SET_LOD_RAW."""
    if not enabled:
        return b"\x00"
    if not (0 <= raw_val <= 0xFF):
        raise ValueError(f"raw_val out of u8 range: {raw_val}")
    return struct.pack("<BB", 1, raw_val)


def encode_anti_slam(
    landing_lock_ms: int = ANTI_SLAM_LANDING_DEFAULT_MS,
    lifted_press_ms: int = ANTI_SLAM_LIFTED_DEFAULT_MS,
) -> bytes:
    """Encode payload for Group 5 subcommand 0x0A SET_ANTI_SLAM."""
    if not (0 <= landing_lock_ms <= ANTI_SLAM_MAX_MS):
        raise ValueError(f"landing_lock_ms={landing_lock_ms} out of 0..{ANTI_SLAM_MAX_MS}")
    if not (0 <= lifted_press_ms <= ANTI_SLAM_MAX_MS):
        raise ValueError(f"lifted_press_ms={lifted_press_ms} out of 0..{ANTI_SLAM_MAX_MS}")
    return struct.pack("<BB", landing_lock_ms, lifted_press_ms)


def encode_read_reg(bank: int, reg: int) -> bytes:
    """Encode payload for Group 5 subcommand 0x0B READ_REG."""
    if not (0 <= bank <= 0xFF and 0 <= reg <= 0xFF):
        raise ValueError(f"Invalid bank/reg ({bank}, {reg})")
    return struct.pack("<BB", bank, reg)


def decode_p2p3_state(payload: bytes) -> dict[str, Any]:
    """Decode the 20-byte 0x85 GET_P2P3_STATE / 0x09..0x0B reply payload."""
    if len(payload) < P2P3_STATE_BYTES:
        raise ValueError(f"Expected >= {P2P3_STATE_BYTES} bytes for P2/P3 state, got {len(payload)}")
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
    ) = struct.unpack_from("<H10BI4B", payload, 0)
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
    }


def install(ctx: PatchContext, *, phase3plus: bool = False) -> dict[str, Any]:
    """Emit Phase 3 (or Phase 3+) RAM initializer, diagnostic helpers, and Group 5 extension dispatcher."""
    flags_mask = P3PLUS_FLAGS_MASK if phase3plus else P3_FLAGS_MASK

    if not phase3plus:
        code_lines: list[str] = [
            # void p3_ram_init(void) - zero 192 B [0x2003F040..0x2003F0FF] and write defaults
            "p3_ram_init:",
            f"ldr r0, ={T.PHASE3_RAM_BASE:#x}",
            "movs r1, #0",
            f"movs r2, #{T.PHASE3_RAM_BYTES // 4}",
            "p3_zero_lp:",
            "stmia r0!, {r1}",
            "subs r2, #1",
            "bne p3_zero_lp",
            f"ldr r0, ={T.PHASE3_RAM_BASE:#x}",
            f"ldr r1, ={P3_MAGIC_U32:#x}",
            f"str r1, [r0, #{OFF_P3_MAGIC}]",
            f"movs r1, #{P3_FLAGS_DEFAULT}",
            f"str r1, [r0, #{OFF_P3_FLAGS}]",
            f"movs r1, #{PLOCK_PERIOD_DEFAULT_US}",
            f"strh r1, [r0, #{OFF_PLOCK_PERIOD_US}]",
            f"movs r1, #{PLOCK_LEAD_DEFAULT_US}",
            f"strh r1, [r0, #{OFF_PLOCK_LEAD_US}]",
            "bx lr",

            # void p3_diag_inc(uint32_t offset_from_p3_base) - atomic u32++
            "p3_diag_inc:",
            f"ldr r1, ={T.PHASE3_RAM_BASE:#x}",
            "adds r1, r1, r0",
            "mrs r12, primask",
            "cpsid i",
            "ldr r2, [r1]",
            "adds r2, #1",
            "str r2, [r1]",
            "msr primask, r12",
            "bx lr",

            # void p3_diag_reset(void) - atomically clear all 14 counters + plock_last_err
            "p3_diag_reset:",
            f"ldr r0, ={T.PHASE3_RAM_BASE:#x}",
            "movs r1, #0",
            "mrs r12, primask",
            "cpsid i",
            f"str r1, [r0, #{OFF_PLOCK_LAST_ERR}]",
            f"adds r0, #{OFF_DIAG_BASE}",
            f"movs r2, #{len(DIAG_NAMES)}",
            "p3_rst_lp:",
            "stmia r0!, {r1}",
            "subs r2, #1",
            "bne p3_rst_lp",
            "msr primask, r12",
            "bx lr",

            # uint32_t p3_group5_dispatch(r0=subcmd, r1=len_in, r2=cmd_buf, r3=p2_ram)
            # Returns r0 = 0 (ok), 0xA2 (fail), 0xA3 (invalid/unknown)
            "p3_group5_dispatch:",
            "push {r4, r5, r6, lr}",
            "mov r4, r2",
            f"ldr r5, ={T.PHASE3_RAM_BASE:#x}",
            f"cmp r0, #{SUB_SET_P3_CTRL}",
            "beq p3_cmd_set_ctrl",
            "cmp r1, #0",
            "bne p3_ret_invalid",
            f"cmp r0, #{SUB_GET_P3_STATE}",
            "beq p3_reply_state",
            f"cmp r0, #{SUB_GET_P3_DIAG}",
            "beq p3_reply_diag",
            f"cmp r0, #{SUB_RESET_P3_DIAG}",
            "bne p3_ret_invalid",
            "bl p3_diag_reset",

            # 0x83 GET_P3_DIAG / 0x07 RESET_P3_DIAG -> 56 B diag
            "p3_reply_diag:",
            f"addw r0, r5, #{OFF_DIAG_BASE}",
            f"movs r1, #{P3_DIAG_BYTES}",
            "b p3_reply_copy",

            # 0x06 SET_P3_CTRL: len=4 (u32 flags) or len=8 (u32 flags, u16 period, u16 lead)
            "p3_cmd_set_ctrl:",
            "cmp r1, #4",
            "beq p3_sc_parse",
            "cmp r1, #8",
            "bne p3_ret_invalid",
            "p3_sc_parse:",
            "ldrh r2, [r4, #6]",
            "ldrh r3, [r4, #8]",
            "lsls r3, r3, #16",
            "orrs r2, r3",
            f"bic.w r3, r2, #{P3_FLAGS_MASK:#x}",
            "cmp r3, #0",
            "bne p3_ret_invalid",
            "cmp r1, #8",
            "bne p3_sc_apply",
            "ldrh r3, [r4, #10]",
            "ldrh r6, [r4, #12]",
            f"cmp r3, #{PLOCK_PERIOD_MIN_US}",
            "blo p3_ret_invalid",
            f"movw r0, #{PLOCK_PERIOD_MAX_US}",
            "cmp r3, r0",
            "bhi p3_ret_invalid",
            f"cmp r6, #{PLOCK_LEAD_MIN_US}",
            "blo p3_ret_invalid",
            f"addw r0, r6, #{PLOCK_LEAD_MIN_US}",
            "cmp r0, r3",
            "bhi p3_ret_invalid",
            "p3_sc_apply:",
            "mrs r12, primask",
            "cpsid i",
            f"str r2, [r5, #{OFF_P3_FLAGS}]",
            "cmp r1, #8",
            "bne p3_sc_chk_pl",
            f"strh r3, [r5, #{OFF_PLOCK_PERIOD_US}]",
            f"strh r6, [r5, #{OFF_PLOCK_LEAD_US}]",
            "p3_sc_chk_pl:",
            f"tst.w r2, #{P3_FLAG_PLOCK_ENABLE}",
            "bne p3_sc_done",
            "movs r0, #0",
            f"strb r0, [r5, #{OFF_PLOCK_PHASE_STATE}]",
            "p3_sc_done:",
            "msr primask, r12",

            # 0x82 GET_P3_STATE: 20 B snapshot into [cmd_buf + 6 .. +25], set len = 20
            "p3_reply_state:",
            "mov r0, r5",
            f"movs r1, #{P3_STATE_BYTES}",

            # Shared atomic word-copy helper (r0=src_ram_4b_aligned, r1=byte_count) -> [cmd_buf + 6 ..]
            "p3_reply_copy:",
            "strb r1, [r4, #3]",
            "adds r6, r4, #6",
            "lsrs r2, r1, #2",
            "mrs r12, primask",
            "cpsid i",
            "p3_cp_lp:",
            "ldr r3, [r0], #4",
            "strh r3, [r6, #0]",
            "lsrs r3, r3, #16",
            "strh r3, [r6, #2]",
            "adds r6, #4",
            "subs r2, #1",
            "bne p3_cp_lp",
            "msr primask, r12",
            "movs r0, #0",
            "pop {r4, r5, r6, pc}",

            "p3_ret_invalid:",
            "movs r0, #0xa3",
            "pop {r4, r5, r6, pc}",
            ".ltorg",
        ]
    else:
        code_lines = [
            # void p3_ram_init(void) - zero 192 B [0x2003F040..0x2003F0FF] and write P3 + P1 defaults
            "p3_ram_init:",
            f"ldr r0, ={T.PHASE3_RAM_BASE:#x}",
            "movs r1, #0",
            f"movs r2, #{T.PHASE3_RAM_BYTES // 4}",
            "p3_zero_lp:",
            "stmia r0!, {r1}",
            "subs r2, #1",
            "bne p3_zero_lp",
            f"ldr r0, ={T.PHASE3_RAM_BASE:#x}",
            f"ldr r1, ={P3_MAGIC_U32:#x}",
            f"str r1, [r0, #{OFF_P3_MAGIC}]",
            f"movs r1, #{P3_FLAGS_DEFAULT}",
            f"str r1, [r0, #{OFF_P3_FLAGS}]",
            f"strb.w r1, [r0, #{OFF_P3P_FLAGS_MIRROR}]",
            f"movs r1, #{PLOCK_PERIOD_DEFAULT_US}",
            f"strh r1, [r0, #{OFF_PLOCK_PERIOD_US}]",
            f"movs r1, #{PLOCK_LEAD_DEFAULT_US}",
            f"strh r1, [r0, #{OFF_PLOCK_LEAD_US}]",
            "movs r1, #0x7f",
            f"strb.w r1, [r0, #{OFF_PLOCK_ERR_MIN}]",
            "movs r1, #0x80",
            f"strb.w r1, [r0, #{OFF_PLOCK_ERR_MAX}]",
            f"movs r1, #{ANTI_SLAM_LANDING_DEFAULT_MS}",
            f"strb.w r1, [r0, #{OFF_ANTI_SLAM_LANDING}]",
            f"movs r1, #{ANTI_SLAM_LIFTED_DEFAULT_MS}",
            f"strb.w r1, [r0, #{OFF_ANTI_SLAM_LIFTED}]",
            "bx lr",

            # void p3_diag_inc(uint32_t offset_from_p3_base) - atomic u32++
            "p3_diag_inc:",
            f"ldr r1, ={T.PHASE3_RAM_BASE:#x}",
            "adds r1, r1, r0",
            "mrs r12, primask",
            "cpsid i",
            "ldr r2, [r1]",
            "adds r2, #1",
            "str r2, [r1]",
            "msr primask, r12",
            "bx lr",

            # void p3_diag_reset(void) - atomically clear 14 P3 + 4 P1 diag counters & reset err bounds
            "p3_diag_reset:",
            f"ldr r0, ={T.PHASE3_RAM_BASE:#x}",
            "movs r1, #0",
            "mrs r12, primask",
            "cpsid i",
            f"str r1, [r0, #{OFF_PLOCK_LAST_ERR}]",
            f"strb.w r1, [r0, #{OFF_PLOCK_OUTLIER_VALID}]",
            f"strb.w r1, [r0, #{OFF_FIX_A_FAIL_CNT}]",
            f"strb.w r1, [r0, #{OFF_CE_STATIC_FAIL_CNT}]",
            f"strb.w r1, [r0, #{OFF_LOD_RAW_FAIL_CNT}]",
            f"strb.w r1, [r0, #{OFF_PEEK_ERR}]",
            f"str.w r1, [r0, #{OFF_EAGER_WAKE_HITS}]",
            "movs r2, #0x7f",
            f"strb.w r2, [r0, #{OFF_PLOCK_ERR_MIN}]",
            "movs r2, #0x80",
            f"strb.w r2, [r0, #{OFF_PLOCK_ERR_MAX}]",
            f"adds r0, #{OFF_DIAG_BASE}",
            f"movs r2, #{len(DIAG_NAMES) + len(P1_DIAG_NAMES)}",
            "p3_rst_lp:",
            "stmia r0!, {r1}",
            "subs r2, #1",
            "bne p3_rst_lp",
            "msr primask, r12",
            "bx lr",

            # uint32_t p3_group5_dispatch(r0=subcmd, r1=len_in, r2=cmd_buf, r3=p2_ram)
            # Returns r0 = 0 (ok), 1 (ok + request override_worker), 0xA2 (fail), 0xA3 (invalid)
            "p3_group5_dispatch:",
            "push {r4, r5, r6, r7, lr}",
            "mov r4, r2",
            "mov r7, r3",
            f"ldr r5, ={T.PHASE3_RAM_BASE:#x}",
            f"cmp r0, #{SUB_SET_P3_CTRL}",
            "beq.w p3_cmd_set_ctrl",
            f"cmp r0, #{SUB_SET_P1_CFG}",
            "beq p3_cmd_set_p1",
            f"cmp r0, #{SUB_SET_LOD_RAW}",
            "beq.w p3_cmd_set_lod_raw",
            f"cmp r0, #{SUB_SET_ANTI_SLAM}",
            "beq.w p3_cmd_set_anti_slam",
            f"cmp r0, #{SUB_READ_REG}",
            "beq.w p3_cmd_read_reg",
            "cmp r1, #0",
            "bne.w p3_ret_invalid",
            f"cmp r0, #{SUB_GET_P3_STATE}",
            "beq.w p3_reply_state_z",
            f"cmp r0, #{SUB_GET_P3_DIAG}",
            "beq p3_reply_diag",
            f"cmp r0, #{SUB_GET_P1_STATE}",
            "beq p3_reply_p1_state",
            f"cmp r0, #{SUB_GET_P2P3_STATE}",
            "beq.w p3_reply_p2p3_state",
            f"cmp r0, #{SUB_RESET_P3_DIAG}",
            "bne.w p3_ret_invalid",
            "bl p3_diag_reset",

            # 0x83 GET_P3_DIAG / 0x07 RESET_P3_DIAG -> 56 B diag
            "p3_reply_diag:",
            f"addw r0, r5, #{OFF_DIAG_BASE}",
            f"movs r1, #{P3_DIAG_BYTES}",
            "b.w p3_reply_copy_ret0",

            # 0x08 SET_P1_CFG: len=1 [mode] or len=2 [mode, action_mask]
            # mode: 0=entry, 1=measure, 2=learn, 0xFF=keep; action: bit0=reset_minmax, bit1=clear_expected
            "p3_cmd_set_p1:",
            "cmp r1, #1",
            "beq p3_p1_chk",
            "cmp r1, #2",
            "bne.w p3_ret_invalid",
            "p3_p1_chk:",
            "ldrb r2, [r4, #6]",
            "cmp r2, #2",
            "bls p3_p1_act",
            "cmp r2, #0xff",
            "bne.w p3_ret_invalid",
            "cmp r1, #2",
            "bne.w p3_ret_invalid",
            "p3_p1_act:",
            "movs r3, #0",
            "cmp r1, #2",
            "bne p3_p1_apply",
            "ldrb r3, [r4, #7]",
            "cmp r3, #3",
            "bhi.w p3_ret_invalid",
            "p3_p1_apply:",
            "mrs r12, primask",
            "cpsid i",
            "cmp r2, #0xff",
            "beq p3_p1_do_act",
            f"strb.w r2, [r5, #{OFF_PLOCK_MODE}]",
            "cmp r2, #2",
            "bne p3_p1_not_learn",
            "movs r0, #1",
            f"strb.w r0, [r5, #{OFF_PLOCK_LEARN_PEND}]",
            "movs r0, #0",
            f"strb.w r0, [r5, #{OFF_PLOCK_OUTLIER_VALID}]",
            "b p3_p1_do_act",
            "p3_p1_not_learn:",
            "movs r0, #0",
            f"strb.w r0, [r5, #{OFF_PLOCK_LEARN_PEND}]",
            "p3_p1_do_act:",
            "tst.w r3, #1",
            "beq p3_p1_act2",
            "movs r0, #0x7f",
            f"strb.w r0, [r5, #{OFF_PLOCK_ERR_MIN}]",
            "movs r0, #0x80",
            f"strb.w r0, [r5, #{OFF_PLOCK_ERR_MAX}]",
            "p3_p1_act2:",
            "tst.w r3, #2",
            "beq p3_p1_done",
            "movs r0, #0",
            f"strb.w r0, [r5, #{OFF_PLOCK_EXPECTED}]",
            f"strb.w r0, [r5, #{OFF_PLOCK_LEARN_PEND}]",
            f"strb.w r0, [r5, #{OFF_PLOCK_OUTLIER_VALID}]",
            "p3_p1_done:",
            "msr primask, r12",

            # 0x84 GET_P1_STATE / 0x08 SET_P1_CFG -> 32 B ([+0x28..+0x37] + [+0x78..+0x87])
            "p3_reply_p1_state:",
            f"movs r1, #{P1_STATE_BYTES}",
            "strb r1, [r4, #3]",
            "adds r6, r4, #6",
            "mrs r12, primask",
            "cpsid i",
            f"ldrb r0, [r5, #{OFF_P3_FLAGS}]",
            f"strb.w r0, [r5, #{OFF_P3P_FLAGS_MIRROR}]",
            f"addw r0, r5, #0x28",
            "movs r2, #4",
            "p3_p1_cp1:",
            "ldr r3, [r0], #4",
            "strh r3, [r6, #0]",
            "lsrs r3, r3, #16",
            "strh r3, [r6, #2]",
            "adds r6, #4",
            "subs r2, #1",
            "bne p3_p1_cp1",
            f"addw r0, r5, #{OFF_P1_DIAG_BASE}",
            "movs r2, #4",
            "p3_p1_cp2:",
            "ldr r3, [r0], #4",
            "strh r3, [r6, #0]",
            "lsrs r3, r3, #16",
            "strh r3, [r6, #2]",
            "adds r6, #4",
            "subs r2, #1",
            "bne p3_p1_cp2",
            "msr primask, r12",
            "movs r0, #0",
            "pop {r4, r5, r6, r7, pc}",
            ".ltorg",

            # 0x09 SET_LOD_RAW: len=1 [0] or len=2 [en(0|1), raw_val] -> 20B P2P3_STATE (ret 1 -> queue override_worker)
            "p3_cmd_set_lod_raw:",
            "cmp r1, #1",
            "beq p3_lod_len1",
            "cmp r1, #2",
            "bne.w p3_ret_invalid",
            "ldrb r2, [r4, #6]",
            "ldrb r3, [r4, #7]",
            "cmp r2, #1",
            "bhi.w p3_ret_invalid",
            "b p3_lod_chk_id53",
            "p3_lod_len1:",
            "ldrb r2, [r4, #6]",
            "cmp r2, #0",
            "bne.w p3_ret_invalid",
            "movs r3, #0",
            "p3_lod_chk_id53:",
            "cbz r2, p3_lod_apply",
            f"ldr r0, ={T.RAM_SENSOR_BRANCH:#x}",
            "ldrb r0, [r0, #0]",
            "cmp r0, #0x53",
            "beq p3_lod_apply",
            "movs r0, #1",
            "strb.w r0, [r7, #31]",
            "movs r0, #0xa2",
            "pop {r4, r5, r6, r7, pc}",
            "p3_lod_apply:",
            "mrs r12, primask",
            "cpsid i",
            f"strb.w r2, [r5, #{OFF_LOD_RAW_EN}]",
            "cbz r2, p3_lod_st",
            f"strb.w r3, [r5, #{OFF_LOD_RAW_VAL}]",
            "p3_lod_st:",
            f"ldrb.w r0, [r5, #{OFF_LOD_RAW_STATE}]",
            "and.w r0, r0, #2",
            "orrs r0, r2",
            "orr.w r0, r0, #4",
            f"strb.w r0, [r5, #{OFF_LOD_RAW_STATE}]",
            "msr primask, r12",
            "movs r2, #1",
            "b p3_reply_p2p3_state_ret",

            # 0x0A SET_ANTI_SLAM: len=2 [landing_ms, lifted_ms] (0..100) -> 20B P2P3_STATE
            "p3_cmd_set_anti_slam:",
            "cmp r1, #2",
            "bne.w p3_ret_invalid",
            "ldrb r0, [r4, #6]",
            "ldrb r1, [r4, #7]",
            f"cmp r0, #{ANTI_SLAM_MAX_MS}",
            "bhi.w p3_ret_invalid",
            f"cmp r1, #{ANTI_SLAM_MAX_MS}",
            "bhi.w p3_ret_invalid",
            "mrs r12, primask",
            "cpsid i",
            f"strb.w r0, [r5, #{OFF_ANTI_SLAM_LANDING}]",
            f"strb.w r1, [r5, #{OFF_ANTI_SLAM_LIFTED}]",
            "msr primask, r12",
            "movs r2, #0",
            "b p3_reply_p2p3_state_ret",

            # 0x0B READ_REG: len=2 [bank, reg] -> 20B P2P3_STATE (ret 2 -> queue peek_worker)
            "p3_cmd_read_reg:",
            "cmp r1, #2",
            "bne.w p3_ret_invalid",
            "ldrb r0, [r4, #6]",
            "ldrb r1, [r4, #7]",
            "mrs r12, primask",
            "cpsid i",
            f"strb.w r0, [r5, #{OFF_PEEK_BANK}]",
            f"strb.w r1, [r5, #{OFF_PEEK_REG}]",
            "movs r0, #0",
            f"strb.w r0, [r5, #{OFF_PEEK_VALID}]",
            f"strb.w r0, [r5, #{OFF_PEEK_ERR}]",
            "movs r0, #1",
            f"strb.w r0, [r5, #{OFF_PEEK_PENDING}]",
            "msr primask, r12",
            "movs r2, #2",
            "b p3_reply_p2p3_state_ret",

            # 0x85 GET_P2P3_STATE: 20 B (<H10BI4B) into [cmd_buf + 6 .. +25], returns r2
            "p3_reply_p2p3_state:",
            "movs r2, #0",
            "p3_reply_p2p3_state_ret:",
            "push {r2}",
            f"movs r1, #{P2P3_STATE_BYTES}",
            "strb r1, [r4, #3]",
            "adds r6, r4, #6",
            "mrs r12, primask",
            "cpsid i",
            f"movw r0, #{W2_CAPS_MASK}",
            "strh r0, [r6, #0]",
            f"ldrb r0, [r5, #{OFF_P3_FLAGS}]",
            "strb r0, [r6, #2]",
            f"ldrb.w r0, [r5, #{OFF_CE_STATIC_STATE}]",
            "strb r0, [r6, #3]",
            f"ldrb.w r0, [r5, #{OFF_CE_STATIC_FAIL_CNT}]",
            "strb r0, [r6, #4]",
            f"ldrb.w r0, [r5, #{OFF_LOD_RAW_EN}]",
            "strb r0, [r6, #5]",
            f"ldrb.w r0, [r5, #{OFF_LOD_RAW_VAL}]",
            "strb r0, [r6, #6]",
            f"ldrb.w r0, [r5, #{OFF_LOD_RAW_STATE}]",
            "strb r0, [r6, #7]",
            f"ldrb.w r0, [r5, #{OFF_LOD_RAW_RB_VAL}]",
            "strb r0, [r6, #8]",
            f"ldrb.w r0, [r5, #{OFF_LOD_RAW_FAIL_CNT}]",
            "strb r0, [r6, #9]",
            f"ldrb.w r0, [r5, #{OFF_ANTI_SLAM_LANDING}]",
            "strb r0, [r6, #10]",
            f"ldrb.w r0, [r5, #{OFF_ANTI_SLAM_LIFTED}]",
            "strb r0, [r6, #11]",
            f"ldr.w r0, [r5, #{OFF_EAGER_WAKE_HITS}]",
            "strh r0, [r6, #12]",
            "lsrs r0, r0, #16",
            "strh r0, [r6, #14]",
            f"ldrb.w r0, [r5, #{OFF_PEEK_BANK}]",
            "strb r0, [r6, #16]",
            f"ldrb.w r0, [r5, #{OFF_PEEK_REG}]",
            "strb r0, [r6, #17]",
            f"ldrb.w r0, [r5, #{OFF_PEEK_VAL}]",
            "strb r0, [r6, #18]",
            f"ldrb.w r0, [r5, #{OFF_PEEK_VALID}]",
            "and.w r0, r0, #1",
            f"ldrb.w r1, [r5, #{OFF_PEEK_PENDING}]",
            "and.w r1, r1, #1",
            "lsls r1, r1, #1",
            "orrs r0, r1",
            f"ldrb.w r1, [r5, #{OFF_PEEK_ERR}]",
            "cbz r1, p3_w2_no_perr",
            "orr.w r0, r0, #4",
            "p3_w2_no_perr:",
            "strb r0, [r6, #19]",
            "msr primask, r12",
            "pop {r0}",
            "pop {r4, r5, r6, r7, pc}",

            # 0x06 SET_P3_CTRL: len=4 (u32 flags) or len=8 (u32 flags, u16 period, u16 lead)
            "p3_cmd_set_ctrl:",
            "cmp r1, #4",
            "beq p3_sc_parse",
            "cmp r1, #8",
            "bne p3_ret_invalid",
            "p3_sc_parse:",
            "ldrh r2, [r4, #6]",
            "ldrh r3, [r4, #8]",
            "lsls r3, r3, #16",
            "orrs r2, r3",
            f"bic.w r3, r2, #{flags_mask:#x}",
            "cmp r3, #0",
            "bne.w p3_ret_invalid",
            f"tst.w r2, #{P3_FLAG_FIX_A | P3_FLAG_CE_STATIC}",
            "beq p3_sc_chk_len8",
            f"ldr r0, ={T.RAM_SENSOR_BRANCH:#x}",
            "ldrb r0, [r0, #0]",
            "cmp r0, #0x53",
            "beq p3_sc_chk_len8",
            "movs r0, #1",
            "strb.w r0, [r7, #31]",  # ERR_NOT_ID53 in P2 OFF_LAST_ERR
            "movs r0, #0xa2",
            "pop {r4, r5, r6, r7, pc}",
            "p3_sc_chk_len8:",
            "cmp r1, #8",
            "bne p3_sc_apply",
            "ldrh r3, [r4, #10]",
            "ldrh r6, [r4, #12]",
            f"cmp r3, #{PLOCK_PERIOD_MIN_US}",
            "blo p3_ret_invalid",
            f"movw r0, #{PLOCK_PERIOD_MAX_US}",
            "cmp r3, r0",
            "bhi p3_ret_invalid",
            f"cmp r6, #{PLOCK_LEAD_MIN_US}",
            "blo p3_ret_invalid",
            f"addw r0, r6, #{PLOCK_LEAD_MIN_US}",
            "cmp r0, r3",
            "bhi p3_ret_invalid",
            "p3_sc_apply:",
            "mrs r12, primask",
            "cpsid i",
            f"str r2, [r5, #{OFF_P3_FLAGS}]",
            f"strb.w r2, [r5, #{OFF_P3P_FLAGS_MIRROR}]",
            "cmp r1, #8",
            "bne p3_sc_chk_pl",
            f"strh r3, [r5, #{OFF_PLOCK_PERIOD_US}]",
            f"strh r6, [r5, #{OFF_PLOCK_LEAD_US}]",
            "p3_sc_chk_pl:",
            f"tst.w r2, #{P3_FLAG_PLOCK_ENABLE}",
            "bne p3_sc_chk_fixa",
            "movs r0, #0",
            f"strb r0, [r5, #{OFF_PLOCK_PHASE_STATE}]",
            "p3_sc_chk_fixa:",
            # Set r7 = 1 iff fix_a requested differs from applied or already pending
            "movs r7, #0",
            "ubfx r0, r2, #4, #1",
            f"ldrb.w r1, [r5, #{OFF_FIX_A_STATE}]",
            "ubfx r3, r1, #1, #1",  # app bit
            "cmp r0, r3",
            "bne p3_sc_qow",
            "tst.w r1, #4",
            "beq p3_sc_chk_ce",
            "p3_sc_qow:",
            "and.w r1, r1, #2",
            "orrs r1, r0",
            "orr.w r1, r1, #4",  # req=r0, preserve app, pend=1, rb_ok=0
            f"strb.w r1, [r5, #{OFF_FIX_A_STATE}]",
            "movs r7, #1",
            "p3_sc_chk_ce:",
            "ubfx r0, r2, #7, #1",
            f"ldrb.w r1, [r5, #{OFF_CE_STATIC_STATE}]",
            "ubfx r3, r1, #1, #1",
            "cmp r0, r3",
            "bne p3_sc_ce_qow",
            "tst.w r1, #4",
            "beq p3_sc_done",
            "p3_sc_ce_qow:",
            "and.w r1, r1, #2",
            "orrs r1, r0",
            "orr.w r1, r1, #4",
            f"strb.w r1, [r5, #{OFF_CE_STATIC_STATE}]",
            "movs r7, #1",
            "p3_sc_done:",
            "msr primask, r12",
            "mov r0, r5",
            f"movs r1, #{P3_STATE_BYTES}",
            "mov r2, r7",
            "b p3_reply_copy_ret",

            "p3_reply_state_z:",
            "mov r0, r5",
            f"movs r1, #{P3_STATE_BYTES}",
            "p3_reply_copy_ret0:",
            "movs r2, #0",

            # Shared atomic word-copy helper (r0=src, r1=byte_count, r2=ret_code) -> [cmd_buf + 6 ..]
            "p3_reply_copy_ret:",
            "push {r2}",
            "strb r1, [r4, #3]",
            "adds r6, r4, #6",
            "lsrs r2, r1, #2",
            "mrs r12, primask",
            "cpsid i",
            "p3_cp_lp:",
            "ldr r3, [r0], #4",
            "strh r3, [r6, #0]",
            "lsrs r3, r3, #16",
            "strh r3, [r6, #2]",
            "adds r6, #4",
            "subs r2, #1",
            "bne p3_cp_lp",
            "msr primask, r12",
            "pop {r0}",
            "pop {r4, r5, r6, r7, pc}",

            "p3_ret_invalid:",
            "movs r0, #0xa3",
            "pop {r4, r5, r6, r7, pc}",
            ".ltorg",
        ]

    base = ctx.alloc_asm(
        "phase3_diag_core",
        code_lines,
        align=4,
        export_labels=("p3_ram_init", "p3_diag_inc", "p3_diag_reset", "p3_group5_dispatch"),
        module="phase3_diag",
        reason=(
            "Phase 3+ retained control/diag RAM layout, atomic counter helpers, and Group 5 0x82..0x84/0x06..0x08 handlers"
            if phase3plus
            else "Phase 3 retained control/diag RAM layout, atomic counter helpers, and Group 5 0x82/0x83/0x06/0x07 handlers"
        ),
    )
    return {
        "enabled": True,
        "base": f"0x{base:08X}",
        "ram_base": f"0x{T.PHASE3_RAM_BASE:08X}",
        "ram_bytes": T.PHASE3_RAM_BYTES,
        "p3_ram_init": f"0x{ctx.builder.symbols['p3_ram_init']:08X}",
        "p3_diag_inc": f"0x{ctx.builder.symbols['p3_diag_inc']:08X}",
        "p3_diag_reset": f"0x{ctx.builder.symbols['p3_diag_reset']:08X}",
        "p3_group5_dispatch": f"0x{ctx.builder.symbols['p3_group5_dispatch']:08X}",
    }
