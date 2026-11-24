"""Explicit opt-in Phase 1 write gatekeeper enforcing firmware bounds and blacklists."""

from __future__ import annotations

import struct

from fenrir.constants import (
    DEVICE_FRAME_LEN,
    MOUSE_APP_PIDS,
    MOUSE_BL_PIDS,
    RECEIVER_APP_PIDS,
    RECEIVER_BL_PIDS,
    VENDOR_ID,
)
from fenrir.protocol.catalog import (
    CommandSpec,
    ProtocolFamily,
    SafetyLevel,
    TargetRole,
    extract_request_payload,
    get_command_spec,
)
from fenrir.protocol.frames import identify_frame_family
from fenrir.protocol.group5_frames import (
    ANTI_SLAM_MAX_MS,
    FPS_PRESET_COUNT_P3PLUS,
    P1_ACTIONS_MASK,
    P3PLUS_FLAGS_MASK,
    P3_FLAGS_MASK,
    PLOCK_LEAD_MIN_US,
    PLOCK_MODE_ENTRY,
    PLOCK_MODE_KEEP,
    PLOCK_MODE_LEARN,
    PLOCK_MODE_MEASURE,
    PLOCK_PERIOD_MAX_US,
    PLOCK_PERIOD_MIN_US,
)
from fenrir.protocol.write_frames import (
    MACRO_ACTION_TYPES,
    MAX_FAMILY_A_LEN,
    MAX_MACRO_CHUNK_LEN,
    MAX_MACRO_OBJECT_SIZE,
    MAX_WIRELESS_FAMILY_B_LEN,
    POLLING_RATES_WIRED,
    POLLING_RATES_WIRELESS,
    VALID_LOD_LEVELS,
    VALID_RGB_MODES,
)
from fenrir.safety.guard import (
    BootloaderDeviceBlockedError,
    ProbeLevel,
    SafetyViolationError,
)

_RECEIVER_ROLES: tuple[TargetRole, ...] = (
    TargetRole.RECEIVER_USB_LOCAL,
    TargetRole.RECEIVER_2G4_LOCAL,
    TargetRole.RECEIVER_TO_MOUSE_RF,
)
_RECEIVER_2G4_FAMILY_B_CMDS: frozenset[int] = frozenset({0x81, 0x90, 0x93})

_PHASE1_FAMILY_B_WRITE_CMDS: dict[int, str] = {
    0x02: "mouse_b_write_polling_rate",
    0x03: "mouse_b_write_dpi_table",
    0x04: "mouse_b_write_keymap_6",
    0x05: "mouse_b_write_debounce_4",
    0x06: "mouse_b_write_lod",
    0x07: "mouse_b_write_reg56",
    0x08: "mouse_b_write_rgb_led",
    0x0B: "mouse_b_macro_create",
    0x0C: "mouse_b_macro_delete",
    0x0D: "mouse_b_macro_chunk_write",
    0x11: "mouse_b_write_motionsync",
    0x12: "mouse_b_write_wheel_cfg",
    0x14: "mouse_b_write_sensor_mode",
    0x15: "mouse_b_write_angle",
    0x16: "mouse_b_write_sensor_status_override",
}

_PHASE1_FAMILY_A_WRITES: dict[tuple[int, int], str] = {
    (0, 0x07): "mouse_a_g0_write_sleep_u16",
    (0, 0x08): "mouse_a_g0_write_profile_debounce",
    (1, 0x02): "mouse_a_g1_write_active_dpi_slot",
    (1, 0x03): "mouse_a_g1_write_current_xy_cpi",
    (1, 0x04): "mouse_a_g1_write_reg56",
    (1, 0x08): "mouse_a_g1_write_lod",
    (1, 0x09): "mouse_a_g1_write_motionsync",
    (1, 0x0A): "mouse_a_g1_write_reg4f",
    (2, 0x01): "mouse_a_g2_write_dpi_rgb",
    (2, 0x02): "mouse_a_g2_write_rgb_brightness",
    (3, 0x00): "mouse_a_g3_write_keyslot",
}


def _check_macro_id(obj_id: int) -> None:
    id_hi = (obj_id >> 8) & 0xFF
    if id_hi in (0x00, 0xB0) or obj_id == 0xFFFF:
        raise SafetyViolationError(
            f"Macro object ID 0x{obj_id:04X} blocked (id_hi in {{0x00, 0xB0}} or 0xFFFF)"
        )


def _signed_i8(val: int) -> int:
    return val - 256 if val >= 128 else val


class WriteGuard:
    """Explicit opt-in Phase 1 guard allowing bounded writes and readback commands."""

    def __init__(
        self,
        *,
        allow_writes: bool = True,
        allow_group5: bool = False,
        allow_phase3plus: bool = False,
    ) -> None:
        self.allow_writes = allow_writes
        self.allow_group5 = allow_group5
        self.allow_phase3plus = allow_phase3plus

    def check_device_allowed(
        self,
        vid: int,
        pid: int,
        level: ProbeLevel,
        *,
        target_role: TargetRole | None = None,
    ) -> None:
        if pid in MOUSE_BL_PIDS or pid in RECEIVER_BL_PIDS:
            if level > ProbeLevel.L0_ENUMERATE:
                raise BootloaderDeviceBlockedError(
                    f"Device 0x{vid:04X}:0x{pid:04X} is in BOOTLOADER mode; blocked."
                )
            return
        if level == ProbeLevel.L0_ENUMERATE:
            return
        if vid != VENDOR_ID:
            raise SafetyViolationError(f"Unexpected Vendor ID 0x{vid:04X}; expected 0x{VENDOR_ID:04X}")
        if pid not in (MOUSE_APP_PIDS | RECEIVER_APP_PIDS):
            raise SafetyViolationError(f"Unknown PID 0x{pid:04X} blocked beyond L0")
        if target_role == TargetRole.MOUSE_USB and pid not in MOUSE_APP_PIDS:
            raise SafetyViolationError(f"PID 0x{pid:04X} is not a Mouse APP PID")
        if target_role in _RECEIVER_ROLES and pid not in RECEIVER_APP_PIDS:
            raise SafetyViolationError(f"PID 0x{pid:04X} is not a Receiver APP PID")

    def validate_outgoing_frame(self, target_role: TargetRole, frame_64: bytes) -> CommandSpec:
        if not isinstance(frame_64, (bytes, bytearray)) or len(frame_64) != DEVICE_FRAME_LEN:
            raise SafetyViolationError(f"Frame must be exactly {DEVICE_FRAME_LEN} bytes")
        raw = bytes(frame_64)
        fam = ProtocolFamily(identify_frame_family(raw))
        route = raw[2] if fam == ProtocolFamily.A else raw[3]

        # Q3: Unconditional 0xB0 bootloader SPI bridge trap guard on ALL receiver paths & routed frames.
        if (target_role in _RECEIVER_ROLES or route != 0) and raw[4] == 0xB0:
            raise SafetyViolationError(
                f"frame[4] == 0xB0 unconditionally blocked for {target_role.value} (route={route})"
            )

        if target_role in (TargetRole.RECEIVER_USB_LOCAL, TargetRole.RECEIVER_2G4_LOCAL):
            return self._validate_receiver_local(target_role, fam, raw)

        if target_role == TargetRole.MOUSE_USB and route != 0:
            raise SafetyViolationError(f"MOUSE_USB requires route=0, got {route}")
        if target_role == TargetRole.RECEIVER_TO_MOUSE_RF:
            expected_route = 2 if fam == ProtocolFamily.A else 1
            if route != expected_route:
                raise SafetyViolationError(
                    f"RECEIVER_TO_MOUSE_RF Family {fam.value} requires route={expected_route}, got {route}"
                )

        if fam == ProtocolFamily.A:
            return self._validate_mouse_family_a(target_role, route, raw)
        return self._validate_mouse_family_b(target_role, route, raw)

    def _validate_receiver_local(
        self, target_role: TargetRole, fam: ProtocolFamily, raw: bytes
    ) -> CommandSpec:
        if fam == ProtocolFamily.B:
            if target_role != TargetRole.RECEIVER_2G4_LOCAL:
                raise SafetyViolationError("Family B blocked on RECEIVER_USB_LOCAL")
            if raw[3] != 0 or raw[2] not in _RECEIVER_2G4_FAMILY_B_CMDS:
                raise SafetyViolationError("RECEIVER_2G4_LOCAL Family B allows only route=0 and cmd in {0x81,0x90,0x93}")
        else:
            expected_route = 0 if target_role == TargetRole.RECEIVER_USB_LOCAL else 1
            if raw[2] != expected_route or raw[4] != 0 or raw[5] < 0x80:
                raise SafetyViolationError(f"Receiver local write/invalid command blocked: {raw[:8].hex()}")

        spec = get_command_spec(target_role, raw)
        if spec is None or spec.safety != SafetyLevel.READ_ONLY_VERIFIED:
            raise SafetyViolationError(f"Uncatalogued or unsafe receiver local command: {raw[:8].hex()}")
        _, payload, length_byte = extract_request_payload(raw)
        tail = raw[6 + min(length_byte, 58) :] if fam == ProtocolFamily.A else (raw[4:] if not payload else raw[4 + length_byte :])
        if any(b != 0 for b in tail):
            raise SafetyViolationError("Non-zero trailing bytes blocked")
        ok, reason = spec.payload_validator(payload, length_byte)
        if not ok:
            raise SafetyViolationError(reason)
        return spec

    def _validate_mouse_family_a(
        self, target_role: TargetRole, route: int, raw: bytes
    ) -> CommandSpec:
        len_a, group, subcmd = raw[3], raw[4], raw[5]
        if not (0 <= len_a <= MAX_FAMILY_A_LEN):
            raise SafetyViolationError(f"Family A lenA {len_a} exceeds {MAX_FAMILY_A_LEN}")
        if any(b != 0 for b in raw[6 + len_a :]):
            raise SafetyViolationError("Non-zero trailing bytes outside Family A payload")

        if group == 4:
            raise SafetyViolationError("Family A group 4 object pool commands unconditionally blocked")
        if group == 5:
            return self._validate_group5(target_role, route, subcmd, raw[6 : 6 + len_a], len_a)
        if group == 0 and subcmd in (0x00, 0x02):
            raise SafetyViolationError(f"Family A group0 0x{subcmd:02X} unconditionally blocked")
        if group == 2 and subcmd in (0x00, 0x80, 0x03):
            raise SafetyViolationError(f"Family A group2 0x{subcmd:02X} blocked (R6=0 bug / sticky preview)")

        if subcmd >= 0x80:
            spec = get_command_spec(target_role, raw)
            if spec is None or spec.safety != SafetyLevel.READ_ONLY_VERIFIED:
                raise SafetyViolationError(f"Blocked Family A read group={group} subcmd=0x{subcmd:02X}")
            _, payload, length_byte = extract_request_payload(raw)
            ok, reason = spec.payload_validator(payload, length_byte)
            if not ok:
                raise SafetyViolationError(reason)
            return spec

        if not self.allow_writes:
            raise SafetyViolationError("Write commands disabled on this WriteGuard instance")
        name = _PHASE1_FAMILY_A_WRITES.get((group, subcmd))
        if name is None:
            raise SafetyViolationError(f"Uncatalogued/blocked Family A write group={group} subcmd=0x{subcmd:02X}")

        payload = raw[6 : 6 + len_a]
        self._check_family_a_write_bounds(group, subcmd, payload, len_a)
        reply_len = 2 if group == 0 else None
        return CommandSpec(
            key=(target_role, ProtocolFamily.A, route, group, subcmd),
            name=name,
            safety=SafetyLevel.WRITE_BLOCKED,
            evidence_addr="phase1_write_spec",
            payload_validator=lambda _p, _l: (True, "ok"),
            expected_reply_len=reply_len,
        )

    @staticmethod
    def _check_family_a_write_bounds(group: int, subcmd: int, payload: bytes, len_a: int) -> None:
        if group == 0 and subcmd == 0x07:
            if len_a != 2 or struct.unpack(">H", payload)[0] == 0:
                raise SafetyViolationError("group0 0x07 requires lenA=2 and non-zero sleep seconds")
        elif group == 0 and subcmd == 0x08:
            if len_a != 2 or payload[0] != 1 or payload[1] > 50:
                raise SafetyViolationError("group0 0x08 requires profile=1 and press_ms <= 50")
        elif group == 1 and subcmd == 0x02:
            if len_a != 2 or payload[0] != 1 or not (1 <= payload[1] <= 7):
                raise SafetyViolationError("group1 0x02 requires profile=1 and 1 <= slot <= 7")
        elif group == 1 and subcmd == 0x03:
            if len_a != 5 or payload[0] != 1:
                raise SafetyViolationError("group1 0x03 requires lenA=5 and profile=1")
            x_cpi, y_cpi = struct.unpack_from(">HH", payload, 1)
            if x_cpi == 0 or y_cpi == 0:
                raise SafetyViolationError("group1 0x03 requires non-zero X/Y CPI")
        elif group == 1 and subcmd in (0x04, 0x09, 0x0A):
            if len_a != 1 or payload[0] not in (0, 1):
                raise SafetyViolationError(f"group1 0x{subcmd:02X} requires 1-byte boolean (0/1)")
        elif group == 1 and subcmd == 0x08:
            if len_a != 1 or payload[0] not in (1, 2):
                raise SafetyViolationError("group1 0x08 requires LOD in {1, 2}")
        elif group == 2 and subcmd == 0x01:
            if len_a != 22 or payload[0] != 1:
                raise SafetyViolationError("group2 0x01 requires lenA=22 and profile=1")
        elif group == 2 and subcmd == 0x02:
            if len_a != 3 or payload[0] != 1:
                raise SafetyViolationError("group2 0x02 requires lenA=3 and profile=1")
        elif group == 3 and subcmd == 0x00:
            if len_a != 10 or payload[0] != 1 or payload[2] not in (0, 1):
                raise SafetyViolationError("group3 0x00 requires lenA=10, profile=1, sub in {0, 1}")

    def _validate_group5(
        self, target_role: TargetRole, route: int, subcmd: int, payload: bytes, len_a: int
    ) -> CommandSpec:
        if not self.allow_group5:
            raise SafetyViolationError(
                "Family A Group 5 commands are disabled by default; instantiate WriteGuard(allow_group5=True)"
            )
        reads = {
            0x80: ("mouse_a_g5_get_state", 51, "phase2_patcher_design"),
            0x81: ("mouse_a_g5_snap_read", 24, "phase2_patcher_design"),
            0x82: ("mouse_a_g5_get_p3_state", 20, "phase3_patcher_design"),
            0x83: ("mouse_a_g5_get_p3_diag", 56, "phase3_patcher_design"),
        }
        if self.allow_phase3plus:
            reads[0x84] = ("mouse_a_g5_get_p1_state", 32, "phase3plus_patcher_design")
            reads[0x85] = ("mouse_a_g5_get_p2p3_state", 20, "phase3plus_patcher_design")
        if subcmd in reads:
            if len_a != 0:
                raise SafetyViolationError(f"Group 5 read 0x{subcmd:02X} requires lenA=0, got {len_a}")
            name, reply_len, evidence = reads[subcmd]
            return CommandSpec(
                key=(target_role, ProtocolFamily.A, route, 5, subcmd),
                name=name,
                safety=SafetyLevel.READ_ONLY_VERIFIED,
                evidence_addr=evidence,
                payload_validator=lambda _p, _l: (True, "ok"),
                expected_reply_len=reply_len,
            )

        if not self.allow_writes:
            raise SafetyViolationError("Write commands disabled on this WriteGuard instance")

        names = {
            0x01: ("mouse_a_g5_snap_trigger", 24, "phase2_patcher_design"),
            0x02: ("mouse_a_g5_set_fps", 51, "phase2_patcher_design"),
            0x03: ("mouse_a_g5_set_downshift", 51, "phase2_patcher_design"),
            0x04: ("mouse_a_g5_set_smoothing", 51, "phase2_patcher_design"),
            0x05: ("mouse_a_g5_persist_ctrl", 51, "phase2_patcher_design"),
            0x06: ("mouse_a_g5_set_p3_ctrl", 20, "phase3_patcher_design"),
            0x07: ("mouse_a_g5_reset_p3_diag", 56, "phase3_patcher_design"),
        }
        if self.allow_phase3plus:
            names[0x08] = ("mouse_a_g5_set_p1_cfg", 32, "phase3plus_patcher_design")
            names[0x09] = ("mouse_a_g5_set_lod_raw", 20, "phase3plus_patcher_design")
            names[0x0A] = ("mouse_a_g5_set_anti_slam", 20, "phase3plus_patcher_design")
            names[0x0B] = ("mouse_a_g5_read_reg", 20, "phase3plus_patcher_design")
        if subcmd not in names:
            raise SafetyViolationError(f"Unknown or forbidden Group 5 subcmd 0x{subcmd:02X}")

        if subcmd == 0x01:
            if len_a != 2 or struct.unpack("<H", payload)[0] == 0:
                raise SafetyViolationError("Group 5 0x01 SNAP_TRIGGER requires lenA=2 and seq != 0")
        elif subcmd == 0x02:
            max_preset = FPS_PRESET_COUNT_P3PLUS if self.allow_phase3plus else 8
            ok_preset = len_a == 1 and payload[0] < max_preset
            ok_custom = (
                len_a == 4
                and payload[0] == 255
                and payload[1] != 0
                and payload[3] != 0
                and payload[2] >= payload[3]
            )
            if not (ok_preset or ok_custom):
                raise SafetyViolationError("Group 5 0x02 SET_FPS invalid preset or custom tuple")
        elif subcmd in (0x03, 0x04):
            if len_a != 1 or payload[0] not in (0, 1):
                raise SafetyViolationError(f"Group 5 0x{subcmd:02X} requires 1-byte boolean (0/1)")
        elif subcmd == 0x05:
            if len_a != 1 or payload[0] not in (1, 2, 3):
                raise SafetyViolationError("Group 5 0x05 PERSIST_CTRL requires 1=save, 2=reset, or 3=async")
        elif subcmd == 0x06:
            if len_a not in (4, 8):
                raise SafetyViolationError(f"Group 5 0x06 SET_P3_CTRL requires lenA=4 or 8, got {len_a}")
            flags = struct.unpack_from("<I", payload, 0)[0]
            flags_mask = P3PLUS_FLAGS_MASK if self.allow_phase3plus else P3_FLAGS_MASK
            if flags & ~flags_mask:
                raise SafetyViolationError(f"Group 5 0x06 SET_P3_CTRL invalid flags 0x{flags:X}")
            if len_a == 8:
                period_us, lead_us = struct.unpack_from("<HH", payload, 4)
                if not (PLOCK_PERIOD_MIN_US <= period_us <= PLOCK_PERIOD_MAX_US):
                    raise SafetyViolationError(f"Group 5 0x06 SET_P3_CTRL period_us {period_us} out of range")
                if not (PLOCK_LEAD_MIN_US <= lead_us <= period_us - PLOCK_LEAD_MIN_US):
                    raise SafetyViolationError(f"Group 5 0x06 SET_P3_CTRL lead_us {lead_us} out of range")
        elif subcmd == 0x07:
            if len_a != 0:
                raise SafetyViolationError(f"Group 5 0x07 RESET_P3_DIAG requires lenA=0, got {len_a}")
        elif subcmd == 0x08:
            if len_a == 1:
                if payload[0] not in (PLOCK_MODE_ENTRY, PLOCK_MODE_MEASURE, PLOCK_MODE_LEARN):
                    raise SafetyViolationError(f"Group 5 0x08 SET_P1_CFG invalid mode 0x{payload[0]:02X}")
            elif len_a == 2:
                if payload[0] not in (PLOCK_MODE_ENTRY, PLOCK_MODE_MEASURE, PLOCK_MODE_LEARN, PLOCK_MODE_KEEP):
                    raise SafetyViolationError(f"Group 5 0x08 SET_P1_CFG invalid mode 0x{payload[0]:02X}")
                if payload[1] & ~P1_ACTIONS_MASK:
                    raise SafetyViolationError(f"Group 5 0x08 SET_P1_CFG invalid action_mask 0x{payload[1]:02X}")
            else:
                raise SafetyViolationError(f"Group 5 0x08 SET_P1_CFG requires lenA=1 or 2, got {len_a}")
        elif subcmd == 0x09:
            ok_off = len_a == 1 and payload[0] == 0
            ok_on = len_a == 2 and payload[0] == 1
            if not (ok_off or ok_on):
                raise SafetyViolationError("Group 5 0x09 SET_LOD_RAW requires [0] or [1, raw_u8]")
        elif subcmd == 0x0A:
            if len_a != 2 or payload[0] > ANTI_SLAM_MAX_MS or payload[1] > ANTI_SLAM_MAX_MS:
                raise SafetyViolationError(
                    f"Group 5 0x0A SET_ANTI_SLAM requires lenA=2 with ms in 0..{ANTI_SLAM_MAX_MS}"
                )
        elif subcmd == 0x0B:
            if len_a != 2:
                raise SafetyViolationError(f"Group 5 0x0B READ_REG requires lenA=2 [bank, reg], got {len_a}")

        name, reply_len, evidence = names[subcmd]
        return CommandSpec(
            key=(target_role, ProtocolFamily.A, route, 5, subcmd),
            name=name,
            safety=SafetyLevel.WRITE_BLOCKED,
            evidence_addr=evidence,
            payload_validator=lambda _p, _l: (True, "ok"),
            expected_reply_len=reply_len,
        )

    def _validate_mouse_family_b(
        self, target_role: TargetRole, route: int, raw: bytes
    ) -> CommandSpec:
        len_b, cmd = raw[1], raw[2]
        if not (1 <= len_b <= MAX_WIRELESS_FAMILY_B_LEN):
            raise SafetyViolationError(f"Family B lenB {len_b} outside 1..{MAX_WIRELESS_FAMILY_B_LEN}")

        if cmd == 0x09:
            raise SafetyViolationError("Family B 0x09 factory restore/reset unconditionally blocked")

        if cmd in (0x8B, 0x8D):
            return self._validate_bounded_macro_read(target_role, route, cmd, len_b, raw)

        if cmd >= 0x81:
            spec = get_command_spec(target_role, raw)
            if spec is None or spec.safety != SafetyLevel.READ_ONLY_VERIFIED:
                raise SafetyViolationError(f"Unknown or unsafe Family B read cmd 0x{cmd:02X}")
            _, payload, length_byte = extract_request_payload(raw)
            tail = raw[4:] if not payload else raw[4 + len_b :]
            if any(b != 0 for b in tail):
                raise SafetyViolationError("Non-zero trailing bytes in Family B read frame")
            ok, reason = spec.payload_validator(payload, length_byte)
            if not ok:
                raise SafetyViolationError(reason)
            return spec

        if not self.allow_writes:
            raise SafetyViolationError("Write commands disabled on this WriteGuard instance")
        name = _PHASE1_FAMILY_B_WRITE_CMDS.get(cmd)
        if name is None:
            raise SafetyViolationError(f"Unknown or forbidden Family B write cmd 0x{cmd:02X}")
        if any(b != 0 for b in raw[4 + len_b :]):
            raise SafetyViolationError("Non-zero trailing bytes outside Family B write payload")

        payload = raw[4 : 4 + len_b]
        self._check_family_b_write_bounds(cmd, route, payload, len_b)
        return CommandSpec(
            key=(target_role, ProtocolFamily.B, route, None, cmd),
            name=name,
            safety=SafetyLevel.WRITE_BLOCKED,
            evidence_addr="phase1_write_spec",
            payload_validator=lambda _p, _l: (True, "ok"),
            expected_reply_len=None,
        )

    @staticmethod
    def _validate_bounded_macro_read(
        target_role: TargetRole, route: int, cmd: int, len_b: int, raw: bytes
    ) -> CommandSpec:
        if any(b != 0 for b in raw[4 + len_b :]):
            raise SafetyViolationError("Non-zero trailing bytes in macro read frame")
        if cmd == 0x8B:
            if len_b != 2:
                raise SafetyViolationError(f"0x8B requires lenB=2, got {len_b}")
            obj_id = struct.unpack_from(">H", raw, 4)[0]
            _check_macro_id(obj_id)
            return CommandSpec(
                key=(target_role, ProtocolFamily.B, route, None, 0x8B),
                name="mouse_b_macro_size_bounded",
                safety=SafetyLevel.READ_ONLY_VERIFIED,
                evidence_addr="phase1_write_spec",
                payload_validator=lambda _p, _l: (True, "ok"),
                expected_reply_len=6,
            )
        if len_b != 7:
            raise SafetyViolationError(f"0x8D requires lenB=7, got {len_b}")
        obj_id, offset, read_len = struct.unpack_from(">HIB", raw, 4)
        _check_macro_id(obj_id)
        if not (1 <= read_len <= MAX_MACRO_CHUNK_LEN):
            raise SafetyViolationError(f"0x8D read_len {read_len} outside 1..{MAX_MACRO_CHUNK_LEN}")
        if offset + read_len > MAX_MACRO_OBJECT_SIZE:
            raise SafetyViolationError(
                f"0x8D span [{offset}..{offset + read_len}) exceeds {MAX_MACRO_OBJECT_SIZE}"
            )
        return CommandSpec(
            key=(target_role, ProtocolFamily.B, route, None, 0x8D),
            name="mouse_b_macro_chunk_read_bounded",
            safety=SafetyLevel.READ_ONLY_VERIFIED,
            evidence_addr="phase1_write_spec",
            payload_validator=lambda _p, _l: (True, "ok"),
            expected_reply_len=None,
        )

    @staticmethod
    def _check_family_b_write_bounds(cmd: int, route: int, payload: bytes, len_b: int) -> None:
        if cmd == 0x02:
            allowed = POLLING_RATES_WIRELESS if route != 0 else POLLING_RATES_WIRED
            if len_b != 1 or payload[0] not in allowed:
                raise SafetyViolationError(f"0x02 polling rate 0x{payload[0]:02X} invalid for route={route}")
        elif cmd == 0x03:
            if len_b != 51:
                raise SafetyViolationError(f"0x03 DPI table requires lenB=51, got {len_b}")
            active, count = payload[0], payload[1]
            if not (1 <= active <= count <= 7):
                raise SafetyViolationError(f"0x03 invalid active={active} / count={count}")
            for i in range(count):
                x_cpi, y_cpi = struct.unpack_from(">HH", payload, 2 + 7 * i)
                if x_cpi == 0 or y_cpi == 0:
                    raise SafetyViolationError(f"0x03 DPI slot {i + 1} has zero CPI")
        elif cmd == 0x04:
            if len_b != 36:
                raise SafetyViolationError(f"0x04 keymap requires lenB=36, got {len_b}")
            for i in range(6):
                act, b1, b2 = payload[6 * i], payload[6 * i + 1], payload[6 * i + 2]
                if not (0x00 <= act <= 0x1D):
                    raise SafetyViolationError(f"0x04 button {i} action_type 0x{act:02X} > 0x1D")
                if b1 == 0:
                    raise SafetyViolationError(f"0x04 button {i} b1 must be non-zero")
                if act in MACRO_ACTION_TYPES:
                    _check_macro_id((b1 << 8) | b2)
        elif cmd == 0x05:
            if len_b != 4 or any(b > 50 for b in payload):
                raise SafetyViolationError("0x05 debounce requires 4 bytes each <= 50 ms")
        elif cmd == 0x06:
            if len_b != 1 or payload[0] not in VALID_LOD_LEVELS:
                raise SafetyViolationError(f"0x06 LOD {payload[0]} not in {sorted(VALID_LOD_LEVELS)}")
        elif cmd in (0x07, 0x11, 0x14):
            if len_b != 1 or payload[0] not in (0, 1):
                raise SafetyViolationError(f"0x{cmd:02X} requires 1-byte boolean (0/1)")
        elif cmd == 0x08:
            if len_b not in (2, 5) or payload[0] not in (0, 1) or payload[1] not in VALID_RGB_MODES:
                raise SafetyViolationError("0x08 RGB requires lenB in {2,5}, enable in {0,1}, mode in {0,1,2}")
        elif cmd == 0x0B:
            if len_b != 6:
                raise SafetyViolationError(f"0x0B macro create requires lenB=6, got {len_b}")
            obj_id, size = struct.unpack(">HI", payload)
            _check_macro_id(obj_id)
            if not (1 <= size <= MAX_MACRO_OBJECT_SIZE):
                raise SafetyViolationError(f"0x0B macro size {size} outside 1..{MAX_MACRO_OBJECT_SIZE}")
        elif cmd == 0x0C:
            if len_b != 2:
                raise SafetyViolationError(f"0x0C macro delete requires lenB=2, got {len_b}")
            _check_macro_id(struct.unpack(">H", payload)[0])
        elif cmd == 0x0D:
            if len_b < 8:
                raise SafetyViolationError(f"0x0D macro chunk requires lenB >= 8, got {len_b}")
            obj_id, offset, chunk_len = struct.unpack_from(">HIB", payload, 0)
            _check_macro_id(obj_id)
            if not (1 <= chunk_len <= MAX_MACRO_CHUNK_LEN) or len_b != 7 + chunk_len:
                raise SafetyViolationError(f"0x0D chunk_len={chunk_len} mismatch with lenB={len_b}")
            if offset + chunk_len > MAX_MACRO_OBJECT_SIZE:
                raise SafetyViolationError(
                    f"0x0D span [{offset}..{offset + chunk_len}) exceeds {MAX_MACRO_OBJECT_SIZE}"
                )
        elif cmd == 0x12:
            if len_b != 2 or payload[0] > 50:
                raise SafetyViolationError("0x12 wheel config requires lenB=2 and poll_ms <= 50")
        elif cmd == 0x15:
            if len_b != 1 or payload[0] == 0xB0 or not (-30 <= _signed_i8(payload[0]) <= 30):
                raise SafetyViolationError("0x15 angle requires signed int8 in -30..30 and != 0xB0")
        elif cmd == 0x16:
            if len_b != 1 or payload[0] > 50:
                raise SafetyViolationError("0x16 override requires lenB=1 and threshold <= 50 ms")
