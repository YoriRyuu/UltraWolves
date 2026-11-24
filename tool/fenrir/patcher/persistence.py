"""Independent versioned CRC16 config page at 0x000EA000 (H4 + H8)."""

from __future__ import annotations

import struct
from typing import Any

from fenrir.patcher import phase3_diag as D, target_mouse as T
from fenrir.patcher.thumb import PatchContext

CONFIG_MAGIC_BYTES = b"FNR2"
CONFIG_MAGIC_U32 = int.from_bytes(CONFIG_MAGIC_BYTES, "little")  # 0x32524E46
CONFIG_VERSION = 1
CONFIG_RECORD_BYTES = 16
CONFIG_VERSION_V2 = 2
CONFIG_RECORD_BYTES_V2 = 24
CONFIG_VERSION_V3 = 3
CONFIG_RECORD_BYTES_V3 = 28
CONFIG_VERSION_V4 = 4
CONFIG_RECORD_BYTES_V4 = 32
RAM_STATE_BYTES = 64
FPS_PRESET_COUNT = 8  # 0 = stock, 1..7 = built-in presets, 255 = custom
FPS_PRESET_COUNT_P3PLUS = 38  # 0 = stock, 1..37 = 37 calibrated PAW3950 presets, 255 = custom

# Mirrored compact Phase 2 RAM state layout at 0x2003F000 (64B total):
# - +4..+13 (10B) mirror Flash record +4..+13 word-for-word for O(1) load/save/reset.
# - +4..+35 (32B) exported verbatim in group 5 0x80 GET_STATE payload.
# - +32..+55 (24B) 4B-aligned snapshot record exported in group 5 0x81 SNAP_READ.
# Offsets 4..31 all fit 16-bit LDRB/STRB [Rn, #imm5]; OFF_SAVE_SEQ=12 is u16-aligned.
OFF_MAGIC = 0  # u32
OFF_VERSION = 4  # u8
OFF_FPS_REQ = 5  # u8
OFF_DS_REQ = 6  # u8
OFF_SM_REQ = 7  # u8
OFF_CUSTOM_U = 8  # u8
OFF_CUSTOM_SLOW = 9  # u8
OFF_CUSTOM_FAST = 10  # u8
OFF_PERSIST_VALID = 11  # u8 (mirrored Flash +11 reserved=0 when hashing/saving)
OFF_SAVE_SEQ = 12  # u16
OFF_FPS_APP = 14  # u8
OFF_FPS_PEND = 15  # u8
OFF_FPS_RB_OK = 16  # u8
OFF_FPS_RB_U = 17  # u8
OFF_FPS_RB_SLOW = 18  # u8
OFF_FPS_RB_FAST = 19  # u8
OFF_FPS_FAIL_CNT = 20  # u8
OFF_DS_APP = 21  # u8  (bool_adv block: +0 APP, +1 PEND, +2 RB_OK, +3 RB_VAL)
OFF_DS_PEND = 22  # u8
OFF_DS_RB_OK = 23  # u8
OFF_DS_RB_VAL = 24  # u8
OFF_SM_APP = 25  # u8  (bool_adv block: +0 APP, +1 PEND, +2 RB_OK, +3 RB_VAL)
OFF_SM_PEND = 26  # u8
OFF_SM_RB_OK = 27  # u8
OFF_SM_RB_VAL = 28  # u8
OFF_PERSIST_PEND = 29  # u8
OFF_WORKER_QUEUED = 30  # u8
OFF_LAST_ERR = 31  # u8
OFF_SNAP_BUF = 32  # 24B (+32..+55): +32=ver(1), +33=status(0..3), +34=err_step, +35=branch


def crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
    """CRC-16/CCITT matching stock 0xC990 (poly=0x1021, init=0xFFFF, no xorout)."""
    crc = init & 0xFFFF
    for b in data:
        crc ^= (b << 8) & 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def encode_config_record(
    *,
    fps: int = 0,
    downshift: int = 0,
    smoothing: int = 0,
    custom: tuple[int, int, int] = (0, 0, 0),
    seq: int = 0,
    version: int = CONFIG_VERSION,
) -> bytes:
    """Encode a 16-byte Phase 2 config record with CRC-16/CCITT."""
    if version != CONFIG_VERSION:
        raise ValueError(f"Unsupported version {version}")
    if downshift not in (0, 1) or smoothing not in (0, 1):
        raise ValueError("downshift and smoothing must be 0 or 1")
    if fps != 255 and not (0 <= fps < FPS_PRESET_COUNT):
        raise ValueError(f"Invalid fps preset {fps}")
    if len(custom) != 3 or any(not (0 <= x <= 0xFF) for x in custom):
        raise ValueError("custom must be 3 bytes")
    if fps == 255 and (custom[0] == 0 or custom[2] == 0 or custom[1] < custom[2]):
        raise ValueError("Invalid custom FPS tuple (U!=0, fast!=0, slow>=fast)")
    if not (0 <= seq <= 0xFFFF):
        raise ValueError("seq must be u16")

    body = struct.pack(
        "<4sBBBBBBBBH",
        CONFIG_MAGIC_BYTES,
        version,
        fps,
        downshift & 1,
        smoothing & 1,
        custom[0],
        custom[1],
        custom[2],
        0,
        seq,
    )
    assert len(body) == 14
    return body + struct.pack("<H", crc16_ccitt(body))


def decode_config_record(data: bytes) -> dict[str, Any]:
    """Validate and decode a 16-byte Phase 2 config record."""
    raw = bytes(data)
    if len(raw) != CONFIG_RECORD_BYTES:
        raise ValueError(f"Expected {CONFIG_RECORD_BYTES}B record, got {len(raw)}B")
    magic, version, fps, ds, sm, cu, cs, cf, reserved, seq = struct.unpack("<4sBBBBBBBBH", raw[:14])
    crc = struct.unpack("<H", raw[14:16])[0]
    if magic != CONFIG_MAGIC_BYTES or version != CONFIG_VERSION:
        raise ValueError("Invalid Phase 2 config magic/version")
    if ds not in (0, 1) or sm not in (0, 1) or reserved != 0:
        raise ValueError("Invalid Phase 2 config flags/reserved")
    if fps != 255 and fps >= FPS_PRESET_COUNT:
        raise ValueError(f"Invalid Phase 2 config fps={fps}")
    if fps == 255 and (cu == 0 or cf == 0 or cs < cf):
        raise ValueError("Invalid Phase 2 config custom FPS")
    expected_crc = crc16_ccitt(raw[:14])
    if crc != expected_crc:
        raise ValueError(f"CRC16 mismatch: got 0x{crc:04X}, expected 0x{expected_crc:04X}")
    return {
        "version": version,
        "downshift": ds,
        "smoothing": sm,
        "fps": fps,
        "custom": (cu, cs, cf),
        "seq": seq,
        "crc16": crc,
    }


def encode_config_record_v2(
    *,
    fps: int = 0,
    downshift: int = 0,
    smoothing: int = 0,
    custom: tuple[int, int, int] = (0, 0, 0),
    seq: int = 0,
    p3_flags: int = D.P3_FLAGS_DEFAULT,
    plock_period_us: int = D.PLOCK_PERIOD_DEFAULT_US,
    plock_lead_us: int = D.PLOCK_LEAD_DEFAULT_US,
) -> bytes:
    """Encode a 24-byte Phase 3 (v2) config record with CRC-16/CCITT."""
    if downshift not in (0, 1) or smoothing not in (0, 1):
        raise ValueError("downshift and smoothing must be 0 or 1")
    if fps != 255 and not (0 <= fps < FPS_PRESET_COUNT):
        raise ValueError(f"Invalid fps preset {fps}")
    if len(custom) != 3 or any(not (0 <= x <= 0xFF) for x in custom):
        raise ValueError("custom must be 3 bytes")
    if fps == 255 and (custom[0] == 0 or custom[2] == 0 or custom[1] < custom[2]):
        raise ValueError("Invalid custom FPS tuple (U!=0, fast!=0, slow>=fast)")
    if not (0 <= seq <= 0xFFFF):
        raise ValueError("seq must be u16")
    if p3_flags & ~D.P3_FLAGS_MASK:
        raise ValueError(f"Invalid p3_flags 0x{p3_flags:08X}")
    if not (D.PLOCK_PERIOD_MIN_US <= plock_period_us <= D.PLOCK_PERIOD_MAX_US):
        raise ValueError(f"Invalid plock_period_us={plock_period_us}")
    if not (D.PLOCK_LEAD_MIN_US <= plock_lead_us <= plock_period_us - D.PLOCK_LEAD_MIN_US):
        raise ValueError(f"Invalid plock_lead_us={plock_lead_us}")

    body = struct.pack(
        "<4sBBBBBBBBHIHH",
        CONFIG_MAGIC_BYTES,
        CONFIG_VERSION_V2,
        fps,
        downshift & 1,
        smoothing & 1,
        custom[0],
        custom[1],
        custom[2],
        0,
        seq,
        p3_flags,
        plock_period_us,
        plock_lead_us,
    )
    assert len(body) == 22
    return body + struct.pack("<H", crc16_ccitt(body))


def decode_config_record_any(data: bytes) -> dict[str, Any]:
    """Validate and decode either a 16-byte v1 record (migrating defaults) or 24-byte v2 record."""
    raw = bytes(data)
    if len(raw) < CONFIG_RECORD_BYTES:
        raise ValueError(f"Record too short ({len(raw)}B)")
    ver = raw[4]
    if ver == CONFIG_VERSION:
        rec = decode_config_record(raw[:CONFIG_RECORD_BYTES])
        rec.update(
            {
                "p3_flags": D.P3_FLAGS_DEFAULT,
                "plock_period_us": D.PLOCK_PERIOD_DEFAULT_US,
                "plock_lead_us": D.PLOCK_LEAD_DEFAULT_US,
                "migrated_from_v1": True,
            }
        )
        return rec
    if ver == CONFIG_VERSION_V2:
        if len(raw) < CONFIG_RECORD_BYTES_V2:
            raise ValueError(f"Expected >= {CONFIG_RECORD_BYTES_V2}B for v2, got {len(raw)}B")
        rec_raw = raw[:CONFIG_RECORD_BYTES_V2]
        magic, version, fps, ds, sm, cu, cs, cf, reserved, seq, p3_flags, period, lead = struct.unpack(
            "<4sBBBBBBBBHIHH", rec_raw[:22]
        )
        crc = struct.unpack("<H", rec_raw[22:24])[0]
        if magic != CONFIG_MAGIC_BYTES or version != CONFIG_VERSION_V2:
            raise ValueError("Invalid Phase 3 config magic/version")
        if ds not in (0, 1) or sm not in (0, 1) or reserved != 0:
            raise ValueError("Invalid Phase 3 config flags/reserved")
        if fps != 255 and fps >= FPS_PRESET_COUNT:
            raise ValueError(f"Invalid Phase 3 config fps={fps}")
        if fps == 255 and (cu == 0 or cf == 0 or cs < cf):
            raise ValueError("Invalid Phase 3 config custom FPS")
        if p3_flags & ~D.P3_FLAGS_MASK:
            raise ValueError(f"Invalid Phase 3 p3_flags=0x{p3_flags:08X}")
        if not (D.PLOCK_PERIOD_MIN_US <= period <= D.PLOCK_PERIOD_MAX_US):
            raise ValueError(f"Invalid Phase 3 plock_period_us={period}")
        if not (D.PLOCK_LEAD_MIN_US <= lead <= period - D.PLOCK_LEAD_MIN_US):
            raise ValueError(f"Invalid Phase 3 plock_lead_us={lead}")
        expected_crc = crc16_ccitt(rec_raw[:22])
        if crc != expected_crc:
            raise ValueError(f"CRC16 mismatch: got 0x{crc:04X}, expected 0x{expected_crc:04X}")
        return {
            "version": version,
            "downshift": ds,
            "smoothing": sm,
            "fps": fps,
            "custom": (cu, cs, cf),
            "seq": seq,
            "p3_flags": p3_flags,
            "plock_period_us": period,
            "plock_lead_us": lead,
            "crc16": crc,
            "migrated_from_v1": False,
        }
    if ver == CONFIG_VERSION_V3:
        if len(raw) < CONFIG_RECORD_BYTES_V3:
            raise ValueError(f"Expected >= {CONFIG_RECORD_BYTES_V3}B for v3, got {len(raw)}B")
        rec_raw = raw[:CONFIG_RECORD_BYTES_V3]
        (
            magic,
            version,
            fps,
            ds,
            sm,
            cu,
            cs,
            cf,
            reserved,
            seq,
            p3_flags,
            period,
            lead,
            plock_mode,
            plock_expected,
            resv_u16,
        ) = struct.unpack("<4sBBBBBBBBHIHHBbH", rec_raw[:26])
        crc = struct.unpack("<H", rec_raw[26:28])[0]
        if magic != CONFIG_MAGIC_BYTES or version != CONFIG_VERSION_V3:
            raise ValueError("Invalid Phase 3+ config magic/version")
        if ds not in (0, 1) or sm not in (0, 1) or reserved != 0 or resv_u16 != 0:
            raise ValueError("Invalid Phase 3+ config flags/reserved")
        if fps != 255 and fps >= FPS_PRESET_COUNT_P3PLUS:
            raise ValueError(f"Invalid Phase 3+ config fps={fps}")
        if fps == 255 and (cu == 0 or cf == 0 or cs < cf):
            raise ValueError("Invalid Phase 3+ config custom FPS")
        if p3_flags & ~D.P3PLUS_FLAGS_MASK:
            raise ValueError(f"Invalid Phase 3+ p3_flags=0x{p3_flags:08X}")
        if not (D.PLOCK_PERIOD_MIN_US <= period <= D.PLOCK_PERIOD_MAX_US):
            raise ValueError(f"Invalid Phase 3+ plock_period_us={period}")
        if not (D.PLOCK_LEAD_MIN_US <= lead <= period - D.PLOCK_LEAD_MIN_US):
            raise ValueError(f"Invalid Phase 3+ plock_lead_us={lead}")
        if plock_mode > D.PLOCK_MODE_LEARN:
            raise ValueError(f"Invalid Phase 3+ plock_mode={plock_mode}")
        expected_crc = crc16_ccitt(rec_raw[:26])
        if crc != expected_crc:
            raise ValueError(f"CRC16 mismatch: got 0x{crc:04X}, expected 0x{expected_crc:04X}")
        return {
            "version": version,
            "downshift": ds,
            "smoothing": sm,
            "fps": fps,
            "custom": (cu, cs, cf),
            "seq": seq,
            "p3_flags": p3_flags,
            "plock_period_us": period,
            "plock_lead_us": lead,
            "plock_mode": plock_mode,
            "plock_expected": plock_expected,
            "lod_raw_en": 0,
            "lod_raw_val": 0,
            "anti_slam_landing_ms": D.ANTI_SLAM_LANDING_DEFAULT_MS,
            "anti_slam_lifted_ms": D.ANTI_SLAM_LIFTED_DEFAULT_MS,
            "crc16": crc,
            "migrated_from_v1": False,
        }
    if ver == CONFIG_VERSION_V4:
        if len(raw) < CONFIG_RECORD_BYTES_V4:
            raise ValueError(f"Expected >= {CONFIG_RECORD_BYTES_V4}B for v4, got {len(raw)}B")
        rec_raw = raw[:CONFIG_RECORD_BYTES_V4]
        (
            magic,
            version,
            fps,
            ds,
            sm,
            cu,
            cs,
            cf,
            reserved,
            seq,
            p3_flags,
            period,
            lead,
            plock_mode,
            plock_expected,
            lod_raw_en,
            lod_raw_val,
            anti_slam_landing_ms,
            anti_slam_lifted_ms,
            resv_u16,
        ) = struct.unpack("<4sBBBBBBBBHIHHBbBBBBH", rec_raw[:30])
        crc = struct.unpack("<H", rec_raw[30:32])[0]
        if magic != CONFIG_MAGIC_BYTES or version != CONFIG_VERSION_V4:
            raise ValueError("Invalid Phase 3+ v4 config magic/version")
        if ds not in (0, 1) or sm not in (0, 1) or reserved != 0 or resv_u16 != 0:
            raise ValueError("Invalid Phase 3+ v4 config flags/reserved")
        if fps != 255 and fps >= FPS_PRESET_COUNT_P3PLUS:
            raise ValueError(f"Invalid Phase 3+ v4 config fps={fps}")
        if fps == 255 and (cu == 0 or cf == 0 or cs < cf):
            raise ValueError("Invalid Phase 3+ v4 config custom FPS")
        if p3_flags & ~D.P3PLUS_FLAGS_MASK:
            raise ValueError(f"Invalid Phase 3+ v4 p3_flags=0x{p3_flags:08X}")
        if not (D.PLOCK_PERIOD_MIN_US <= period <= D.PLOCK_PERIOD_MAX_US):
            raise ValueError(f"Invalid Phase 3+ v4 plock_period_us={period}")
        if not (D.PLOCK_LEAD_MIN_US <= lead <= period - D.PLOCK_LEAD_MIN_US):
            raise ValueError(f"Invalid Phase 3+ v4 plock_lead_us={lead}")
        if plock_mode > D.PLOCK_MODE_LEARN:
            raise ValueError(f"Invalid Phase 3+ v4 plock_mode={plock_mode}")
        if lod_raw_en not in (0, 1):
            raise ValueError(f"Invalid Phase 3+ v4 lod_raw_en={lod_raw_en}")
        if anti_slam_landing_ms > D.ANTI_SLAM_MAX_MS or anti_slam_lifted_ms > D.ANTI_SLAM_MAX_MS:
            raise ValueError("Invalid Phase 3+ v4 anti_slam window")
        expected_crc = crc16_ccitt(rec_raw[:30])
        if crc != expected_crc:
            raise ValueError(f"CRC16 mismatch: got 0x{crc:04X}, expected 0x{expected_crc:04X}")
        return {
            "version": version,
            "downshift": ds,
            "smoothing": sm,
            "fps": fps,
            "custom": (cu, cs, cf),
            "seq": seq,
            "p3_flags": p3_flags,
            "plock_period_us": period,
            "plock_lead_us": lead,
            "plock_mode": plock_mode,
            "plock_expected": plock_expected,
            "lod_raw_en": lod_raw_en,
            "lod_raw_val": lod_raw_val,
            "anti_slam_landing_ms": anti_slam_landing_ms,
            "anti_slam_lifted_ms": anti_slam_lifted_ms,
            "crc16": crc,
            "migrated_from_v1": False,
        }
    raise ValueError(f"Unsupported config version {ver}")


def encode_config_record_v3(
    *,
    fps: int = 0,
    downshift: int = 0,
    smoothing: int = 0,
    custom: tuple[int, int, int] = (0, 0, 0),
    seq: int = 0,
    p3_flags: int = D.P3_FLAGS_DEFAULT,
    plock_period_us: int = D.PLOCK_PERIOD_DEFAULT_US,
    plock_lead_us: int = D.PLOCK_LEAD_DEFAULT_US,
    plock_mode: int = D.PLOCK_MODE_ENTRY,
    plock_expected: int = 0,
) -> bytes:
    """Encode a 28-byte Phase 3+ (v3) config record with CRC-16/CCITT."""
    if downshift not in (0, 1) or smoothing not in (0, 1):
        raise ValueError("downshift and smoothing must be 0 or 1")
    if fps != 255 and not (0 <= fps < FPS_PRESET_COUNT_P3PLUS):
        raise ValueError(f"Invalid fps preset {fps}")
    if len(custom) != 3 or any(not (0 <= x <= 0xFF) for x in custom):
        raise ValueError("custom must be 3 bytes")
    if fps == 255 and (custom[0] == 0 or custom[2] == 0 or custom[1] < custom[2]):
        raise ValueError("Invalid custom FPS tuple (U!=0, fast!=0, slow>=fast)")
    if not (0 <= seq <= 0xFFFF):
        raise ValueError("seq must be u16")
    if p3_flags & ~D.P3PLUS_FLAGS_MASK:
        raise ValueError(f"Invalid p3_flags 0x{p3_flags:08X}")
    if not (D.PLOCK_PERIOD_MIN_US <= plock_period_us <= D.PLOCK_PERIOD_MAX_US):
        raise ValueError(f"Invalid plock_period_us={plock_period_us}")
    if not (D.PLOCK_LEAD_MIN_US <= plock_lead_us <= plock_period_us - D.PLOCK_LEAD_MIN_US):
        raise ValueError(f"Invalid plock_lead_us={plock_lead_us}")
    if plock_mode not in (D.PLOCK_MODE_ENTRY, D.PLOCK_MODE_MEASURE, D.PLOCK_MODE_LEARN):
        raise ValueError(f"Invalid plock_mode={plock_mode}")
    if not (-128 <= plock_expected <= 127):
        raise ValueError(f"Invalid plock_expected={plock_expected}")

    body = struct.pack(
        "<4sBBBBBBBBHIHHBbH",
        CONFIG_MAGIC_BYTES,
        CONFIG_VERSION_V3,
        fps,
        downshift & 1,
        smoothing & 1,
        custom[0],
        custom[1],
        custom[2],
        0,
        seq,
        p3_flags,
        plock_period_us,
        plock_lead_us,
        plock_mode,
        plock_expected,
        0,
    )
    assert len(body) == 26
    return body + struct.pack("<H", crc16_ccitt(body))


def encode_config_record_v4(
    *,
    fps: int = 0,
    downshift: int = 0,
    smoothing: int = 0,
    custom: tuple[int, int, int] = (0, 0, 0),
    seq: int = 0,
    p3_flags: int = D.P3_FLAGS_DEFAULT,
    plock_period_us: int = D.PLOCK_PERIOD_DEFAULT_US,
    plock_lead_us: int = D.PLOCK_LEAD_DEFAULT_US,
    plock_mode: int = D.PLOCK_MODE_ENTRY,
    plock_expected: int = 0,
    lod_raw_en: int = 0,
    lod_raw_val: int = 0,
    anti_slam_landing_ms: int = D.ANTI_SLAM_LANDING_DEFAULT_MS,
    anti_slam_lifted_ms: int = D.ANTI_SLAM_LIFTED_DEFAULT_MS,
) -> bytes:
    """Encode a 32-byte Phase 3+ Wave 2 (v4) config record with CRC-16/CCITT."""
    v3_body = encode_config_record_v3(
        fps=fps,
        downshift=downshift,
        smoothing=smoothing,
        custom=custom,
        seq=seq,
        p3_flags=p3_flags,
        plock_period_us=plock_period_us,
        plock_lead_us=plock_lead_us,
        plock_mode=plock_mode,
        plock_expected=plock_expected,
    )[:24]
    if lod_raw_en not in (0, 1) or not (0 <= lod_raw_val <= 0xFF):
        raise ValueError(f"Invalid lod_raw ({lod_raw_en}, {lod_raw_val})")
    if not (0 <= anti_slam_landing_ms <= D.ANTI_SLAM_MAX_MS and 0 <= anti_slam_lifted_ms <= D.ANTI_SLAM_MAX_MS):
        raise ValueError("Invalid anti_slam bounds")
    body = bytearray(v3_body)
    body[4] = CONFIG_VERSION_V4
    body += struct.pack("<BBBBH", lod_raw_en, lod_raw_val, anti_slam_landing_ms, anti_slam_lifted_ms, 0)
    assert len(body) == 30
    return bytes(body) + struct.pack("<H", crc16_ccitt(bytes(body)))


def install(
    ctx: PatchContext,
    *,
    install_persist_loop_hook: bool = True,
    phase3: bool = False,
    phase3plus: bool = False,
) -> dict[str, Any]:
    """Install CRC16 config validation/load/save/reset at 0x000EA000 (H4 + H8)."""
    builder = ctx.builder
    for key in (
        "h4_startup_load_call",
        "h8_persist_call",
        "crc16_ccitt",
        "flash_rf_pause",
        "flash_rf_resume",
        "flash_erase",
        "flash_write",
    ):
        spec = T.PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)

    if builder.stock_image.find_u32_refs(T.PHASE2_CONFIG_FLASH_PAGE):
        raise ValueError(f"Config page 0x{T.PHASE2_CONFIG_FLASH_PAGE:08X} unexpectedly referenced in stock APP")

    if phase3plus:
        phase3 = True
    if not phase3:
        lines = [
            # int valid_fps_tuple(r0=fps, r1=u, r2=slow, r3=fast) -> 1 valid, 0 invalid
            "valid_fps_tuple:",
            "cmp r0, #255",
            "beq vft_cust",
            f"cmp r0, #{FPS_PRESET_COUNT}",
            "bhs vft_bad",
            "vft_ok:",
            "movs r0, #1",
            "bx lr",
            "vft_cust:",
            "cbz r1, vft_bad",
            "cbz r3, vft_bad",
            "cmp r2, r3",
            "bhs vft_ok",
            "vft_bad:",
            "movs r0, #0",
            "bx lr",

            # int cfg_validate(const uint8_t *ptr) -> r0 = 1 valid, 0 invalid
            "cfg_validate:",
            "push {r4, lr}",
            "mov r4, r0",
            "ldr r0, [r4]",
            f"ldr r1, ={CONFIG_MAGIC_U32:#x}",
            "cmp r0, r1",
            "bne val_bad",
            "ldrb r0, [r4, #4]",
            f"cmp r0, #{CONFIG_VERSION}",
            "bne val_bad",
            "ldrb r0, [r4, #6]",
            "ldrb r1, [r4, #7]",
            "orrs r0, r1",
            "cmp r0, #1",
            "bhi val_bad",
            "ldrb r0, [r4, #5]",
            "ldrb r1, [r4, #8]",
            "ldrb r2, [r4, #9]",
            "ldrb r3, [r4, #10]",
            "bl valid_fps_tuple",
            "cbz r0, val_bad",
            "mov r0, r4",
            "movs r1, #14",
            "movs r2, #0",
            f"bl {T.FN_CRC16_CCITT:#x}",
            "ldrh r1, [r4, #14]",
            "cmp r0, r1",
            "bne val_bad",
            "movs r0, #1",
            "pop {r4, pc}",
            "val_bad:",
            "movs r0, #0",
            "pop {r4, pc}",

            # void cfg_load_page(void)
            "cfg_load_page:",
            "push {r4, r5, r6, lr}",
            f"ldr r4, ={T.PHASE2_RAM_BASE:#x}",
            "mov r0, r4",
            "movs r1, #0",
            f"movs r2, #{RAM_STATE_BYTES // 4}",
            "zero_loop:",
            "stmia r0!, {r1}",
            "subs r2, #1",
            "bne zero_loop",
            "movs r0, #1",
            f"strb.w r0, [r4, #{OFF_SNAP_BUF}]",
            f"ldr r5, ={T.PHASE2_CONFIG_FLASH_PAGE:#x}",
            "mov r0, r5",
            "bl cfg_validate",
            "cbz r0, load_done",
            # Direct mirrored 10B copy (+4..+13) from Flash record to RAM state
            "ldr r0, [r5, #4]",
            "str r0, [r4, #4]",
            "ldr r0, [r5, #8]",
            "str r0, [r4, #8]",
            "ldrh r0, [r5, #12]",
            "strh r0, [r4, #12]",
            "movs r0, #1",
            f"strb r0, [r4, #{OFF_PERSIST_VALID}]",
            f"ldrb r1, [r4, #{OFF_FPS_REQ}]",
            "cbz r1, load_bool_pend",
            f"strb r0, [r4, #{OFF_FPS_PEND}]",
            "load_bool_pend:",
            f"ldrb r0, [r4, #{OFF_DS_REQ}]",
            f"strb r0, [r4, #{OFF_DS_PEND}]",
            f"ldrb r0, [r4, #{OFF_SM_REQ}]",
            f"strb r0, [r4, #{OFF_SM_PEND}]",
            "load_done:",
            "pop {r4, r5, r6, pc}",

            # int _flash_program_ea(const void *src_or_null) -> 1 ok, 0 fail (with readback verify)
            "_flash_program_ea:",
            "push {r4, r5, r6, lr}",
            "mov r4, r0",
            "movs r5, #0",
            f"ldr r0, ={T.RAM_TRANSPORT_MODE:#x}",
            "ldrb r0, [r0]",
            "cmp r0, #1",
            "bne prog_erase",
            "movs r5, #1",
            f"bl {T.FN_FLASH_RF_PAUSE:#x}",
            "prog_erase:",
            f"ldr r6, ={T.PHASE2_CONFIG_FLASH_PAGE:#x}",
            "mov r0, r6",
            f"bl {T.FN_FLASH_ERASE:#x}",
            "cbnz r0, prog_fail",
            "cbz r4, prog_chk",
            "mov r0, r6",
            "mov r1, r4",
            f"movs r2, #{CONFIG_RECORD_BYTES}",
            f"bl {T.FN_FLASH_WRITE:#x}",
            "cbnz r0, prog_fail",
            "prog_chk:",
            "movs r3, #4",
            "mov r1, r4",
            "mvns r2, r4",
            "chk_lp:",
            "ldmia r6!, {r0}",
            "cbz r4, chk_cmp",
            "ldmia r1!, {r2}",
            "chk_cmp:",
            "cmp r0, r2",
            "bne prog_fail",
            "subs r3, #1",
            "bne chk_lp",
            "movs r6, #1",
            "b prog_resume",
            "prog_fail:",
            "movs r6, #0",
            "prog_resume:",
            "cbz r5, prog_ret",
            f"bl {T.FN_FLASH_RF_RESUME:#x}",
            "prog_ret:",
            "mov r0, r6",
            "pop {r4, r5, r6, pc}",

            # int cfg_save_page(void) -> 1 ok, 0 fail
            "cfg_save_page:",
            "push {r4, r5, r6, lr}",
            "sub sp, #16",
            "mov r5, sp",
            f"ldr r4, ={T.PHASE2_RAM_BASE:#x}",
            f"ldr r0, ={CONFIG_MAGIC_U32:#x}",
            "str r0, [r5, #0]",
            "ldr r0, [r4, #4]",
            "str r0, [r5, #4]",
            "ldr r0, [r4, #8]",
            "str r0, [r5, #8]",
            f"movs r0, #{CONFIG_VERSION}",
            "strb r0, [r5, #4]",
            "movs r0, #0",
            "strb r0, [r5, #11]",
            "strh r0, [r5, #14]",
            f"ldrh r0, [r4, #{OFF_SAVE_SEQ}]",
            "adds r0, #1",
            "strh r0, [r5, #12]",
            "mov r0, r5",
            "movs r1, #14",
            "movs r2, #0",
            f"bl {T.FN_CRC16_CCITT:#x}",
            "strh r0, [r5, #14]",
            "mov r0, r5",
            "bl _flash_program_ea",
            "cbz r0, save_out",
            "ldrh r0, [r5, #12]",
            f"strh r0, [r4, #{OFF_SAVE_SEQ}]",
            "movs r1, #0",
            f"strb r1, [r4, #{OFF_PERSIST_PEND}]",
            "movs r0, #1",
            f"strb r0, [r4, #{OFF_PERSIST_VALID}]",
            "save_out:",
            "add sp, #16",
            "pop {r4, r5, r6, pc}",

            # int cfg_reset_page(void) -> 1 ok, 0 fail
            "cfg_reset_page:",
            "push {r4, lr}",
            "movs r0, #0",
            "bl _flash_program_ea",
            "cbz r0, rst_out",
            f"ldr r4, ={T.PHASE2_RAM_BASE:#x}",
            "movs r0, #0",
            "str r0, [r4, #4]",
            "str r0, [r4, #8]",
            "strh r0, [r4, #12]",
            f"strb r0, [r4, #{OFF_PERSIST_PEND}]",
            "movs r0, #1",
            "rst_out:",
            "pop {r4, pc}",

            # H4 startup hook
            "startup_hook:",
            "push {r4, lr}",
            f"bl {T.FN_STARTUP_LOAD:#x}",
            "bl cfg_load_page",
            "pop {r4, pc}",

            # H8 main-loop persist hook
            "persist_hook:",
            "push {r4, lr}",
            f"bl {T.FN_PERSIST_TICK:#x}",
            f"ldr r0, ={T.PHASE2_RAM_BASE:#x}",
            f"ldrb r0, [r0, #{OFF_PERSIST_PEND}]",
            "cbz r0, ph_done",
            "bl cfg_save_page",
            "ph_done:",
            "pop {r4, pc}",
            ".ltorg",
        ]
    elif phase3plus:
        p3_ram_init_addr = builder.symbols["p3_ram_init"]
        lines = [
            # int valid_fps_tuple(r0=fps, r1=u, r2=slow, r3=fast) -> 1 valid, 0 invalid (0..37 | 255)
            "valid_fps_tuple:",
            "cmp r0, #255",
            "beq vft_cust",
            f"cmp r0, #{FPS_PRESET_COUNT_P3PLUS}",
            "bhs vft_bad",
            "vft_ok:",
            "movs r0, #1",
            "bx lr",
            "vft_cust:",
            "cbz r1, vft_bad",
            "cbz r3, vft_bad",
            "cmp r2, r3",
            "bhs vft_ok",
            "vft_bad:",
            "movs r0, #0",
            "bx lr",

            # int cfg_validate(const uint8_t *ptr) -> r0 = 1 (v1), 2 (v2), 3 (v3), 0 (invalid)
            "cfg_validate:",
            "push {r4, r5, lr}",
            "mov r4, r0",
            "ldr r0, [r4]",
            f"ldr r1, ={CONFIG_MAGIC_U32:#x}",
            "cmp r0, r1",
            "bne val_bad",
            "ldrb r5, [r4, #4]",
            "ldrb r0, [r4, #6]",
            "ldrb r1, [r4, #7]",
            "orrs r0, r1",
            "cmp r0, #1",
            "bhi val_bad",
            "ldrb r0, [r4, #5]",
            "ldrb r1, [r4, #8]",
            "ldrb r2, [r4, #9]",
            "ldrb r3, [r4, #10]",
            "bl valid_fps_tuple",
            "cmp r0, #0",
            "beq.w val_bad",
            f"cmp r5, #{CONFIG_VERSION}",
            "beq val_v1",
            f"cmp r5, #{CONFIG_VERSION_V2}",
            "beq val_v234_hdr",
            f"cmp r5, #{CONFIG_VERSION_V3}",
            "beq val_v234_hdr",
            f"cmp r5, #{CONFIG_VERSION_V4}",
            "bne val_bad",
            "val_v234_hdr:",
            "ldrh r0, [r4, #14]",
            "ldrh r1, [r4, #16]",
            "lsls r1, r1, #16",
            "orrs r0, r1",
            f"cmp r5, #{CONFIG_VERSION_V2}",
            "bne val_v34_mask",
            f"bic.w r1, r0, #{D.P3_FLAGS_MASK:#x}",
            "b val_mask_chk",
            "val_v34_mask:",
            f"bic.w r1, r0, #{D.P3PLUS_FLAGS_MASK:#x}",
            "val_mask_chk:",
            "cmp r1, #0",
            "bne val_bad",
            "ldrh r0, [r4, #18]",  # period_us
            "ldrh r1, [r4, #20]",  # lead_us
            f"cmp r0, #{D.PLOCK_PERIOD_MIN_US}",
            "blo val_bad",
            f"movw r2, #{D.PLOCK_PERIOD_MAX_US}",
            "cmp r0, r2",
            "bhi val_bad",
            f"cmp r1, #{D.PLOCK_LEAD_MIN_US}",
            "blo val_bad",
            f"addw r2, r1, #{D.PLOCK_LEAD_MIN_US}",
            "cmp r2, r0",
            "bhi val_bad",
            f"cmp r5, #{CONFIG_VERSION_V2}",
            "bne val_v34",
            "mov r0, r4",
            "movs r1, #22",
            "movs r2, #0",
            f"bl {T.FN_CRC16_CCITT:#x}",
            "ldrh r1, [r4, #22]",
            "cmp r0, r1",
            "bne val_bad",
            "movs r0, #2",
            "pop {r4, r5, pc}",
            "val_v34:",
            "ldrb r0, [r4, #22]",  # plock_mode <= 2
            "cmp r0, #2",
            "bhi val_bad",
            f"cmp r5, #{CONFIG_VERSION_V4}",
            "beq val_v4",
            "ldrh r0, [r4, #24]",  # v3 reserved u16 == 0
            "cbnz r0, val_bad",
            "mov r0, r4",
            "movs r1, #26",
            "movs r2, #0",
            f"bl {T.FN_CRC16_CCITT:#x}",
            "ldrh r1, [r4, #26]",
            "cmp r0, r1",
            "bne val_bad",
            "movs r0, #3",
            "pop {r4, r5, pc}",
            "val_v4:",
            "ldrb r0, [r4, #24]",  # lod_raw_en <= 1
            "cmp r0, #1",
            "bhi val_bad",
            "ldrb r0, [r4, #26]",  # anti_slam_landing <= 100
            f"cmp r0, #{D.ANTI_SLAM_MAX_MS}",
            "bhi val_bad",
            "ldrb r0, [r4, #27]",  # anti_slam_lifted <= 100
            f"cmp r0, #{D.ANTI_SLAM_MAX_MS}",
            "bhi val_bad",
            "ldrh r0, [r4, #28]",  # reserved2 u16 == 0
            "cbnz r0, val_bad",
            "mov r0, r4",
            "movs r1, #30",
            "movs r2, #0",
            f"bl {T.FN_CRC16_CCITT:#x}",
            "ldrh r1, [r4, #30]",
            "cmp r0, r1",
            "bne val_bad",
            "movs r0, #4",
            "pop {r4, r5, pc}",
            "val_v1:",
            "mov r0, r4",
            "movs r1, #14",
            "movs r2, #0",
            f"bl {T.FN_CRC16_CCITT:#x}",
            "ldrh r1, [r4, #14]",
            "cmp r0, r1",
            "bne val_bad",
            "movs r0, #1",
            "pop {r4, r5, pc}",
            "val_bad:",
            "movs r0, #0",
            "pop {r4, r5, pc}",

            # void cfg_load_page(void) - accepts v1, v2, and v3
            "cfg_load_page:",
            "push {r4, r5, r6, lr}",
            f"ldr r4, ={T.PHASE2_RAM_BASE:#x}",
            "mov r0, r4",
            "movs r1, #0",
            f"movs r2, #{RAM_STATE_BYTES // 4}",
            "zero_loop:",
            "stmia r0!, {r1}",
            "subs r2, #1",
            "bne zero_loop",
            "movs r0, #1",
            f"strb.w r0, [r4, #{OFF_SNAP_BUF}]",
            f"bl {p3_ram_init_addr:#x}",
            f"ldr r5, ={T.PHASE2_CONFIG_FLASH_PAGE:#x}",
            "mov r0, r5",
            "bl cfg_validate",
            "cmp r0, #0",
            "beq.w load_done",
            "mov r6, r0",
            "ldr r0, [r5, #4]",
            "str r0, [r4, #4]",
            "ldr r0, [r5, #8]",
            "str r0, [r4, #8]",
            "ldrh r0, [r5, #12]",
            "strh r0, [r4, #12]",
            "movs r0, #1",
            f"strb r0, [r4, #{OFF_PERSIST_VALID}]",
            f"ldrb r1, [r4, #{OFF_FPS_REQ}]",
            "cbz r1, load_bool_pend",
            f"strb r0, [r4, #{OFF_FPS_PEND}]",
            "load_bool_pend:",
            f"ldrb r0, [r4, #{OFF_DS_REQ}]",
            f"strb r0, [r4, #{OFF_DS_PEND}]",
            f"ldrb r0, [r4, #{OFF_SM_REQ}]",
            f"strb r0, [r4, #{OFF_SM_PEND}]",
            "cmp r6, #2",
            "blo load_done",
            f"ldr r3, ={T.PHASE3_RAM_BASE:#x}",
            "ldrh r0, [r5, #14]",
            "ldrh r1, [r5, #16]",
            "lsls r1, r1, #16",
            "orrs r0, r1",
            f"str r0, [r3, #{D.OFF_P3_FLAGS}]",
            f"strb.w r0, [r3, #{D.OFF_P3P_FLAGS_MIRROR}]",
            f"tst.w r0, #{D.P3_FLAG_FIX_A}",
            "beq load_chk_ce",
            "movs r1, #5",  # req=1, app=0, pend=1
            f"strb.w r1, [r3, #{D.OFF_FIX_A_STATE}]",
            "load_chk_ce:",
            f"tst.w r0, #{D.P3_FLAG_CE_STATIC}",
            "beq load_pl_params",
            "movs r1, #5",
            f"strb.w r1, [r3, #{D.OFF_CE_STATIC_STATE}]",
            "load_pl_params:",
            "ldrh r0, [r5, #18]",
            f"strh r0, [r3, #{D.OFF_PLOCK_PERIOD_US}]",
            "ldrh r0, [r5, #20]",
            f"strh r0, [r3, #{D.OFF_PLOCK_LEAD_US}]",
            "cmp r6, #3",
            "blo load_done",
            "ldrb r0, [r5, #22]",
            f"strb.w r0, [r3, #{D.OFF_PLOCK_MODE}]",
            "cmp r0, #2",
            "bne load_exp",
            "movs r1, #1",
            f"strb.w r1, [r3, #{D.OFF_PLOCK_LEARN_PEND}]",
            "load_exp:",
            "ldrb r0, [r5, #23]",
            f"strb.w r0, [r3, #{D.OFF_PLOCK_EXPECTED}]",
            "cmp r6, #4",
            "bne load_done",
            "ldrb r0, [r5, #24]",
            f"strb.w r0, [r3, #{D.OFF_LOD_RAW_EN}]",
            "ldrb r1, [r5, #25]",
            f"strb.w r1, [r3, #{D.OFF_LOD_RAW_VAL}]",
            "cbz r0, load_aslam",
            "movs r1, #5",
            f"strb.w r1, [r3, #{D.OFF_LOD_RAW_STATE}]",
            "load_aslam:",
            "ldrb r0, [r5, #26]",
            f"strb.w r0, [r3, #{D.OFF_ANTI_SLAM_LANDING}]",
            "ldrb r0, [r5, #27]",
            f"strb.w r0, [r3, #{D.OFF_ANTI_SLAM_LIFTED}]",
            "load_done:",
            "pop {r4, r5, r6, pc}",

            # int _flash_program_ea(const void *src_or_null) -> 1 ok, 0 fail (28B v3)
            "_flash_program_ea:",
            "push {r4, r5, r6, lr}",
            "mov r4, r0",
            "movs r5, #0",
            f"ldr r0, ={T.RAM_TRANSPORT_MODE:#x}",
            "ldrb r0, [r0]",
            "cmp r0, #1",
            "bne prog_erase",
            "movs r5, #1",
            f"bl {T.FN_FLASH_RF_PAUSE:#x}",
            "prog_erase:",
            f"ldr r6, ={T.PHASE2_CONFIG_FLASH_PAGE:#x}",
            "mov r0, r6",
            f"bl {T.FN_FLASH_ERASE:#x}",
            "cbnz r0, prog_fail",
            "cbz r4, prog_chk",
            "mov r0, r6",
            "mov r1, r4",
            f"movs r2, #{CONFIG_RECORD_BYTES_V4}",
            f"bl {T.FN_FLASH_WRITE:#x}",
            "cbnz r0, prog_fail",
            "prog_chk:",
            f"movs r3, #{CONFIG_RECORD_BYTES_V4 // 4}",
            "mov r1, r4",
            "mvns r2, r4",
            "chk_lp:",
            "ldmia r6!, {r0}",
            "cbz r4, chk_cmp",
            "ldmia r1!, {r2}",
            "chk_cmp:",
            "cmp r0, r2",
            "bne prog_fail",
            "subs r3, #1",
            "bne chk_lp",
            "movs r6, #1",
            "b prog_resume",
            "prog_fail:",
            "movs r6, #0",
            "prog_resume:",
            "cbz r5, prog_ret",
            f"bl {T.FN_FLASH_RF_RESUME:#x}",
            "prog_ret:",
            "mov r0, r6",
            "pop {r4, r5, r6, pc}",

            # int cfg_save_page(void) -> 1 ok, 0 fail (writes 32B v4 record)
            "cfg_save_page:",
            "push {r4, r5, r6, lr}",
            f"sub sp, #{CONFIG_RECORD_BYTES_V4}",
            "mov r5, sp",
            f"ldr r4, ={T.PHASE2_RAM_BASE:#x}",
            f"ldr r0, ={CONFIG_MAGIC_U32:#x}",
            "str r0, [r5, #0]",
            "ldr r0, [r4, #4]",
            "str r0, [r5, #4]",
            "ldr r0, [r4, #8]",
            "str r0, [r5, #8]",
            f"movs r0, #{CONFIG_VERSION_V4}",
            "strb r0, [r5, #4]",
            "movs r0, #0",
            "strb r0, [r5, #11]",
            f"ldrh r0, [r4, #{OFF_SAVE_SEQ}]",
            "adds r0, #1",
            "strh r0, [r5, #12]",
            f"ldr r6, ={T.PHASE3_RAM_BASE:#x}",
            f"ldr r0, [r6, #{D.OFF_P3_FLAGS}]",
            "strh r0, [r5, #14]",
            "lsrs r0, r0, #16",
            "strh r0, [r5, #16]",
            f"ldrh r0, [r6, #{D.OFF_PLOCK_PERIOD_US}]",
            "strh r0, [r5, #18]",
            f"ldrh r0, [r6, #{D.OFF_PLOCK_LEAD_US}]",
            "strh r0, [r5, #20]",
            f"ldrb.w r0, [r6, #{D.OFF_PLOCK_MODE}]",
            "strb r0, [r5, #22]",
            f"ldrb.w r0, [r6, #{D.OFF_PLOCK_EXPECTED}]",
            "strb r0, [r5, #23]",
            f"ldrb.w r0, [r6, #{D.OFF_LOD_RAW_EN}]",
            "strb r0, [r5, #24]",
            f"ldrb.w r0, [r6, #{D.OFF_LOD_RAW_VAL}]",
            "strb r0, [r5, #25]",
            f"ldrb.w r0, [r6, #{D.OFF_ANTI_SLAM_LANDING}]",
            "strb r0, [r5, #26]",
            f"ldrb.w r0, [r6, #{D.OFF_ANTI_SLAM_LIFTED}]",
            "strb r0, [r5, #27]",
            "movs r0, #0",
            "strh r0, [r5, #28]",
            "strh r0, [r5, #30]",
            "mov r0, r5",
            "movs r1, #30",
            "movs r2, #0",
            f"bl {T.FN_CRC16_CCITT:#x}",
            "strh r0, [r5, #30]",
            "mov r0, r5",
            "bl _flash_program_ea",
            "cbz r0, save_out",
            f"movs r0, #{CONFIG_VERSION_V4}",
            f"strb r0, [r4, #{OFF_VERSION}]",
            "ldrh r0, [r5, #12]",
            f"strh r0, [r4, #{OFF_SAVE_SEQ}]",
            "movs r1, #0",
            f"strb r1, [r4, #{OFF_PERSIST_PEND}]",
            "movs r0, #1",
            f"strb r0, [r4, #{OFF_PERSIST_VALID}]",
            "save_out:",
            f"add sp, #{CONFIG_RECORD_BYTES_V4}",
            "pop {r4, r5, r6, pc}",

            # int cfg_reset_page(void) -> 1 ok, 0 fail (erases flash, resets P2+P3+P1 defaults)
            "cfg_reset_page:",
            "push {r4, lr}",
            "movs r0, #0",
            "bl _flash_program_ea",
            "cmp r0, #0",
            "beq.w rst_out",
            f"ldr r4, ={T.PHASE2_RAM_BASE:#x}",
            "movs r0, #0",
            "str r0, [r4, #4]",
            "str r0, [r4, #8]",
            "strh r0, [r4, #12]",
            f"strb r0, [r4, #{OFF_PERSIST_PEND}]",
            f"ldr r1, ={T.PHASE3_RAM_BASE:#x}",
            f"movs r2, #{D.P3_FLAGS_DEFAULT}",
            f"str r2, [r1, #{D.OFF_P3_FLAGS}]",
            f"strb.w r2, [r1, #{D.OFF_P3P_FLAGS_MIRROR}]",
            f"movs r2, #{D.PLOCK_PERIOD_DEFAULT_US}",
            f"strh r2, [r1, #{D.OFF_PLOCK_PERIOD_US}]",
            f"movs r2, #{D.PLOCK_LEAD_DEFAULT_US}",
            f"strh r2, [r1, #{D.OFF_PLOCK_LEAD_US}]",
            f"strb r0, [r1, #{D.OFF_PLOCK_PHASE_STATE}]",
            f"strb.w r0, [r1, #{D.OFF_PLOCK_MODE}]",
            f"strb.w r0, [r1, #{D.OFF_PLOCK_EXPECTED}]",
            f"strb.w r0, [r1, #{D.OFF_PLOCK_OUTLIER_PEND}]",
            f"strb.w r0, [r1, #{D.OFF_PLOCK_OUTLIER_VALID}]",
            f"strb.w r0, [r1, #{D.OFF_PLOCK_LEARN_PEND}]",
            "movs r2, #0x7f",
            f"strb.w r2, [r1, #{D.OFF_PLOCK_ERR_MIN}]",
            "movs r2, #0x80",
            f"strb.w r2, [r1, #{D.OFF_PLOCK_ERR_MAX}]",
            f"strh.w r0, [r1, #{D.OFF_ABS_X}]",
            f"strh.w r0, [r1, #{D.OFF_ABS_Y}]",
            f"ldrb.w r2, [r1, #{D.OFF_FIX_A_STATE}]",
            "tst.w r2, #6",
            "beq rst_fa_clr",
            "and.w r2, r2, #2",
            "orr.w r2, r2, #4",  # req=0, keep app, pend=1
            "b rst_fa_st",
            "rst_fa_clr:",
            "movs r2, #0",
            "rst_fa_st:",
            f"strb.w r2, [r1, #{D.OFF_FIX_A_STATE}]",
            f"strb.w r0, [r1, #{D.OFF_LOD_RAW_EN}]",
            f"strb.w r0, [r1, #{D.OFF_LOD_RAW_VAL}]",
            f"movs r2, #{D.ANTI_SLAM_LANDING_DEFAULT_MS}",
            f"strb.w r2, [r1, #{D.OFF_ANTI_SLAM_LANDING}]",
            f"movs r2, #{D.ANTI_SLAM_LIFTED_DEFAULT_MS}",
            f"strb.w r2, [r1, #{D.OFF_ANTI_SLAM_LIFTED}]",
            f"ldrb.w r2, [r1, #{D.OFF_CE_STATIC_STATE}]",
            "tst.w r2, #6",
            "beq rst_ce_clr",
            "and.w r2, r2, #2",
            "orr.w r2, r2, #4",
            "b rst_ce_st",
            "rst_ce_clr:",
            "movs r2, #0",
            "rst_ce_st:",
            f"strb.w r2, [r1, #{D.OFF_CE_STATIC_STATE}]",
            f"ldrb.w r2, [r1, #{D.OFF_LOD_RAW_STATE}]",
            "tst.w r2, #6",
            "beq rst_lod_clr",
            "and.w r2, r2, #2",
            "orr.w r2, r2, #4",
            "b rst_lod_st",
            "rst_lod_clr:",
            "movs r2, #0",
            "rst_lod_st:",
            f"strb.w r2, [r1, #{D.OFF_LOD_RAW_STATE}]",
            "movs r0, #1",
            "rst_out:",
            "pop {r4, pc}",

            # H4 startup hook
            "startup_hook:",
            "push {r4, lr}",
            f"bl {T.FN_STARTUP_LOAD:#x}",
            "bl cfg_load_page",
            "pop {r4, pc}",

            # H8 main-loop persist hook
            "persist_hook:",
            "push {r4, lr}",
            f"bl {T.FN_PERSIST_TICK:#x}",
            f"ldr r0, ={T.PHASE2_RAM_BASE:#x}",
            f"ldrb r0, [r0, #{OFF_PERSIST_PEND}]",
            "cbz r0, ph_done",
            "bl cfg_save_page",
            "ph_done:",
            "pop {r4, pc}",
            ".ltorg",
        ]
    else:
        p3_ram_init_addr = builder.symbols["p3_ram_init"]
        lines = [
            # int valid_fps_tuple(r0=fps, r1=u, r2=slow, r3=fast) -> 1 valid, 0 invalid
            "valid_fps_tuple:",
            "cmp r0, #255",
            "beq vft_cust",
            f"cmp r0, #{FPS_PRESET_COUNT}",
            "bhs vft_bad",
            "vft_ok:",
            "movs r0, #1",
            "bx lr",
            "vft_cust:",
            "cbz r1, vft_bad",
            "cbz r3, vft_bad",
            "cmp r2, r3",
            "bhs vft_ok",
            "vft_bad:",
            "movs r0, #0",
            "bx lr",

            # int cfg_validate(const uint8_t *ptr) -> r0 = 1 (v1), 2 (v2), 0 (invalid)
            "cfg_validate:",
            "push {r4, r5, lr}",
            "mov r4, r0",
            "ldr r0, [r4]",
            f"ldr r1, ={CONFIG_MAGIC_U32:#x}",
            "cmp r0, r1",
            "bne val_bad",
            "ldrb r5, [r4, #4]",
            "ldrb r0, [r4, #6]",
            "ldrb r1, [r4, #7]",
            "orrs r0, r1",
            "cmp r0, #1",
            "bhi val_bad",
            "ldrb r0, [r4, #5]",
            "ldrb r1, [r4, #8]",
            "ldrb r2, [r4, #9]",
            "ldrb r3, [r4, #10]",
            "bl valid_fps_tuple",
            "cbz r0, val_bad",
            f"cmp r5, #{CONFIG_VERSION}",
            "beq val_v1",
            f"cmp r5, #{CONFIG_VERSION_V2}",
            "bne val_bad",
            # Validate v2 fields (+14..+21)
            "ldrh r0, [r4, #14]",
            "ldrh r1, [r4, #16]",
            "lsls r1, r1, #16",
            "orrs r0, r1",
            f"bic.w r1, r0, #{D.P3_FLAGS_MASK:#x}",
            "cmp r1, #0",
            "bne val_bad",
            "ldrh r0, [r4, #18]",  # period_us
            "ldrh r1, [r4, #20]",  # lead_us
            f"cmp r0, #{D.PLOCK_PERIOD_MIN_US}",
            "blo val_bad",
            f"movw r2, #{D.PLOCK_PERIOD_MAX_US}",
            "cmp r0, r2",
            "bhi val_bad",
            f"cmp r1, #{D.PLOCK_LEAD_MIN_US}",
            "blo val_bad",
            f"addw r2, r1, #{D.PLOCK_LEAD_MIN_US}",
            "cmp r2, r0",
            "bhi val_bad",
            "mov r0, r4",
            "movs r1, #22",
            "movs r2, #0",
            f"bl {T.FN_CRC16_CCITT:#x}",
            "ldrh r1, [r4, #22]",
            "cmp r0, r1",
            "bne val_bad",
            "movs r0, #2",
            "pop {r4, r5, pc}",
            "val_v1:",
            "mov r0, r4",
            "movs r1, #14",
            "movs r2, #0",
            f"bl {T.FN_CRC16_CCITT:#x}",
            "ldrh r1, [r4, #14]",
            "cmp r0, r1",
            "bne val_bad",
            "movs r0, #1",
            "pop {r4, r5, pc}",
            "val_bad:",
            "movs r0, #0",
            "pop {r4, r5, pc}",

            # void cfg_load_page(void) - accepts v1 (migrates Phase 3 defaults) and v2
            "cfg_load_page:",
            "push {r4, r5, r6, lr}",
            f"ldr r4, ={T.PHASE2_RAM_BASE:#x}",
            "mov r0, r4",
            "movs r1, #0",
            f"movs r2, #{RAM_STATE_BYTES // 4}",
            "zero_loop:",
            "stmia r0!, {r1}",
            "subs r2, #1",
            "bne zero_loop",
            "movs r0, #1",
            f"strb.w r0, [r4, #{OFF_SNAP_BUF}]",
            f"bl {p3_ram_init_addr:#x}",
            f"ldr r5, ={T.PHASE2_CONFIG_FLASH_PAGE:#x}",
            "mov r0, r5",
            "bl cfg_validate",
            "cbz r0, load_done",
            "mov r6, r0",
            "ldr r0, [r5, #4]",
            "str r0, [r4, #4]",
            "ldr r0, [r5, #8]",
            "str r0, [r4, #8]",
            "ldrh r0, [r5, #12]",
            "strh r0, [r4, #12]",
            "movs r0, #1",
            f"strb r0, [r4, #{OFF_PERSIST_VALID}]",
            f"ldrb r1, [r4, #{OFF_FPS_REQ}]",
            "cbz r1, load_bool_pend",
            f"strb r0, [r4, #{OFF_FPS_PEND}]",
            "load_bool_pend:",
            f"ldrb r0, [r4, #{OFF_DS_REQ}]",
            f"strb r0, [r4, #{OFF_DS_PEND}]",
            f"ldrb r0, [r4, #{OFF_SM_REQ}]",
            f"strb r0, [r4, #{OFF_SM_PEND}]",
            "cmp r6, #2",
            "bne load_done",
            f"ldr r3, ={T.PHASE3_RAM_BASE:#x}",
            "ldrh r0, [r5, #14]",
            "ldrh r1, [r5, #16]",
            "lsls r1, r1, #16",
            "orrs r0, r1",
            f"str r0, [r3, #{D.OFF_P3_FLAGS}]",
            "ldrh r0, [r5, #18]",
            f"strh r0, [r3, #{D.OFF_PLOCK_PERIOD_US}]",
            "ldrh r0, [r5, #20]",
            f"strh r0, [r3, #{D.OFF_PLOCK_LEAD_US}]",
            "load_done:",
            "pop {r4, r5, r6, pc}",

            # int _flash_program_ea(const void *src_or_null) -> 1 ok, 0 fail (24B v2)
            "_flash_program_ea:",
            "push {r4, r5, r6, lr}",
            "mov r4, r0",
            "movs r5, #0",
            f"ldr r0, ={T.RAM_TRANSPORT_MODE:#x}",
            "ldrb r0, [r0]",
            "cmp r0, #1",
            "bne prog_erase",
            "movs r5, #1",
            f"bl {T.FN_FLASH_RF_PAUSE:#x}",
            "prog_erase:",
            f"ldr r6, ={T.PHASE2_CONFIG_FLASH_PAGE:#x}",
            "mov r0, r6",
            f"bl {T.FN_FLASH_ERASE:#x}",
            "cbnz r0, prog_fail",
            "cbz r4, prog_chk",
            "mov r0, r6",
            "mov r1, r4",
            f"movs r2, #{CONFIG_RECORD_BYTES_V2}",
            f"bl {T.FN_FLASH_WRITE:#x}",
            "cbnz r0, prog_fail",
            "prog_chk:",
            f"movs r3, #{CONFIG_RECORD_BYTES_V2 // 4}",
            "mov r1, r4",
            "mvns r2, r4",
            "chk_lp:",
            "ldmia r6!, {r0}",
            "cbz r4, chk_cmp",
            "ldmia r1!, {r2}",
            "chk_cmp:",
            "cmp r0, r2",
            "bne prog_fail",
            "subs r3, #1",
            "bne chk_lp",
            "movs r6, #1",
            "b prog_resume",
            "prog_fail:",
            "movs r6, #0",
            "prog_resume:",
            "cbz r5, prog_ret",
            f"bl {T.FN_FLASH_RF_RESUME:#x}",
            "prog_ret:",
            "mov r0, r6",
            "pop {r4, r5, r6, pc}",

            # int cfg_save_page(void) -> 1 ok, 0 fail (writes 24B v2 record)
            "cfg_save_page:",
            "push {r4, r5, r6, lr}",
            f"sub sp, #{CONFIG_RECORD_BYTES_V2}",
            "mov r5, sp",
            f"ldr r4, ={T.PHASE2_RAM_BASE:#x}",
            f"ldr r0, ={CONFIG_MAGIC_U32:#x}",
            "str r0, [r5, #0]",
            "ldr r0, [r4, #4]",
            "str r0, [r5, #4]",
            "ldr r0, [r4, #8]",
            "str r0, [r5, #8]",
            f"movs r0, #{CONFIG_VERSION_V2}",
            "strb r0, [r5, #4]",
            "movs r0, #0",
            "strb r0, [r5, #11]",
            f"ldrh r0, [r4, #{OFF_SAVE_SEQ}]",
            "adds r0, #1",
            "strh r0, [r5, #12]",
            f"ldr r6, ={T.PHASE3_RAM_BASE:#x}",
            f"ldr r0, [r6, #{D.OFF_P3_FLAGS}]",
            "strh r0, [r5, #14]",
            "lsrs r0, r0, #16",
            "strh r0, [r5, #16]",
            f"ldrh r0, [r6, #{D.OFF_PLOCK_PERIOD_US}]",
            "strh r0, [r5, #18]",
            f"ldrh r0, [r6, #{D.OFF_PLOCK_LEAD_US}]",
            "strh r0, [r5, #20]",
            "movs r0, #0",
            "strh r0, [r5, #22]",
            "mov r0, r5",
            "movs r1, #22",
            "movs r2, #0",
            f"bl {T.FN_CRC16_CCITT:#x}",
            "strh r0, [r5, #22]",
            "mov r0, r5",
            "bl _flash_program_ea",
            "cbz r0, save_out",
            f"movs r0, #{CONFIG_VERSION_V2}",
            f"strb r0, [r4, #{OFF_VERSION}]",
            "ldrh r0, [r5, #12]",
            f"strh r0, [r4, #{OFF_SAVE_SEQ}]",
            "movs r1, #0",
            f"strb r1, [r4, #{OFF_PERSIST_PEND}]",
            "movs r0, #1",
            f"strb r0, [r4, #{OFF_PERSIST_VALID}]",
            "save_out:",
            f"add sp, #{CONFIG_RECORD_BYTES_V2}",
            "pop {r4, r5, r6, pc}",

            # int cfg_reset_page(void) -> 1 ok, 0 fail (erases flash, resets P2+P3 defaults)
            "cfg_reset_page:",
            "push {r4, lr}",
            "movs r0, #0",
            "bl _flash_program_ea",
            "cbz r0, rst_out",
            f"ldr r4, ={T.PHASE2_RAM_BASE:#x}",
            "movs r0, #0",
            "str r0, [r4, #4]",
            "str r0, [r4, #8]",
            "strh r0, [r4, #12]",
            f"strb r0, [r4, #{OFF_PERSIST_PEND}]",
            f"ldr r1, ={T.PHASE3_RAM_BASE:#x}",
            f"movs r2, #{D.P3_FLAGS_DEFAULT}",
            f"str r2, [r1, #{D.OFF_P3_FLAGS}]",
            f"movs r2, #{D.PLOCK_PERIOD_DEFAULT_US}",
            f"strh r2, [r1, #{D.OFF_PLOCK_PERIOD_US}]",
            f"movs r2, #{D.PLOCK_LEAD_DEFAULT_US}",
            f"strh r2, [r1, #{D.OFF_PLOCK_LEAD_US}]",
            f"strb r0, [r1, #{D.OFF_PLOCK_PHASE_STATE}]",
            "movs r0, #1",
            "rst_out:",
            "pop {r4, pc}",

            # H4 startup hook
            "startup_hook:",
            "push {r4, lr}",
            f"bl {T.FN_STARTUP_LOAD:#x}",
            "bl cfg_load_page",
            "pop {r4, pc}",

            # H8 main-loop persist hook
            "persist_hook:",
            "push {r4, lr}",
            f"bl {T.FN_PERSIST_TICK:#x}",
            f"ldr r0, ={T.PHASE2_RAM_BASE:#x}",
            f"ldrb r0, [r0, #{OFF_PERSIST_PEND}]",
            "cbz r0, ph_done",
            "bl cfg_save_page",
            "ph_done:",
            "pop {r4, pc}",
            ".ltorg",
        ]

    base_addr = ctx.alloc_asm(
        "persistence_core",
        lines,
        align=4,
        export_labels=(
            "valid_fps_tuple",
            "cfg_validate",
            "cfg_load_page",
            "cfg_save_page",
            "cfg_reset_page",
            "startup_hook",
            "persist_hook",
        ),
        module="persistence",
        reason="Independent CRC16 config page at 0x000EA000 using stock 0xC990/0xF2BC/0xF2DE/0xF304/0xF356",
    )

    startup_hook_addr = builder.symbols["startup_hook"]
    persist_hook_addr = builder.symbols["persist_hook"]

    ctx.patch_bl(
        T.HOOK_H4_STARTUP_LOAD_CALL,
        startup_hook_addr,
        expected_old=T.PREIMAGES["h4_startup_load_call"].expected,
        module="persistence",
        reason="H4: Initialize 0x2003F000 Phase 2 state and load CRC16 page 0xEA000 after 0x111E0",
    )

    if install_persist_loop_hook:
        ctx.patch_bl(
            T.HOOK_H8_PERSIST_CALL,
            persist_hook_addr,
            expected_old=T.PREIMAGES["h8_persist_call"].expected,
            module="persistence",
            reason="H8: Service Phase 2 pending_save after stock 0x177CC",
        )

    res = {
        "enabled": True,
        "flash_page": f"0x{T.PHASE2_CONFIG_FLASH_PAGE:08X}",
        "flash_page_size": T.FLASH_PAGE_SIZE,
        "ram_state_base": f"0x{T.PHASE2_RAM_BASE:08X}",
        "ram_state_bytes": RAM_STATE_BYTES,
        "record_magic": CONFIG_MAGIC_BYTES.decode("ascii"),
        "record_version": CONFIG_VERSION_V4 if phase3plus else (CONFIG_VERSION_V2 if phase3 else CONFIG_VERSION),
        "record_bytes": CONFIG_RECORD_BYTES_V4 if phase3plus else (CONFIG_RECORD_BYTES_V2 if phase3 else CONFIG_RECORD_BYTES),
        "crc_fn": f"0x{T.FN_CRC16_CCITT:08X}",
        "code_base": f"0x{base_addr:08X}",
        "symbols": {
            "valid_fps_tuple": f"0x{builder.symbols['valid_fps_tuple']:08X}",
            "cfg_validate": f"0x{builder.symbols['cfg_validate']:08X}",
            "cfg_load_page": f"0x{builder.symbols['cfg_load_page']:08X}",
            "cfg_save_page": f"0x{builder.symbols['cfg_save_page']:08X}",
            "cfg_reset_page": f"0x{builder.symbols['cfg_reset_page']:08X}",
            "startup_hook": f"0x{startup_hook_addr:08X}",
            "persist_hook": f"0x{persist_hook_addr:08X}",
        },
        "stock_dirty_bitset_untouched": f"0x{T.RAM_DIRTY_BITSET:08X}",
    }
    if phase3:
        res["supports_v1_migration"] = True
    if phase3plus:
        res["supports_v2_migration"] = True
        res["supports_v3_migration"] = True
    return res
