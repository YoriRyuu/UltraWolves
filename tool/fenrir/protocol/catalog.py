"""Command safety catalog: explicit read-only whitelist and hazardous blacklist."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable

from fenrir.protocol.frames import DeviceFrame, identify_frame_family


class SafetyLevel(str, Enum):
    READ_ONLY_VERIFIED = "READ_ONLY_VERIFIED"
    READ_ONLY_UNVERIFIED = "READ_ONLY_UNVERIFIED"
    FORBIDDEN_HAZARDOUS = "FORBIDDEN_HAZARDOUS"
    WRITE_BLOCKED = "WRITE_BLOCKED"


class ProtocolFamily(str, Enum):
    A = "A"
    B = "B"


class TargetRole(str, Enum):
    """Supported physical and RF-routed targets in Phase 0."""

    MOUSE_USB = "mouse_usb"
    RECEIVER_USB_LOCAL = "receiver_usb_local"
    RECEIVER_2G4_LOCAL = "receiver_2g4_local"
    RECEIVER_TO_MOUSE_RF = "receiver_to_mouse_rf"


# (target_role, family, route, group_or_none, cmd)
CommandKey = tuple[TargetRole, ProtocolFamily, int, int | None, int]
PayloadValidator = Callable[[bytes, int], tuple[bool, str]]


def _empty_payload(payload: bytes, length_byte: int) -> tuple[bool, str]:
    if payload or length_byte != 0:
        return False, f"expected empty payload and length=0, got len={len(payload)}, byte={length_byte}"
    return True, "ok"


def _family_b_empty_query(payload: bytes, length_byte: int) -> tuple[bool, str]:
    if payload or length_byte != 1:
        return (
            False,
            f"expected empty Family B query payload with length_byte=1, got len={len(payload)}, byte={length_byte}",
        )
    return True, "ok"


def _bounded_length_read(max_len: int) -> PayloadValidator:
    def _validate(payload: bytes, length_byte: int) -> tuple[bool, str]:
        if any(b != 0 for b in payload):
            return False, "read payload bytes must be all zeros"
        if not (1 <= length_byte <= max_len):
            return False, f"length byte {length_byte} outside 1..{max_len}"
        return True, "ok"

    return _validate


def _profile1_only(payload: bytes, length_byte: int) -> tuple[bool, str]:
    if length_byte < 1 or len(payload) < 1:
        return False, "missing 1-based profile index"
    if payload[0] != 1 or any(b != 0 for b in payload[1:]) or length_byte != 1:
        return False, f"only profile=1 with length=1 permitted, got payload={payload.hex()} len={length_byte}"
    return True, "ok"


def _receiver_2g4_0x8b_param2(payload: bytes, length_byte: int) -> tuple[bool, str]:
    if length_byte != 1 or payload != b"\x02":
        return False, f"0x8B requires payload=02 and length=1, got payload={payload.hex()} len={length_byte}"
    return True, "ok"


def _group3_keyslot_read(payload: bytes, length_byte: int) -> tuple[bool, str]:
    # Payload: [profile=1, action_selector(0..7 or mapped), sub(0..1)]
    if length_byte != 3 or len(payload) != 3:
        return False, f"group3 0x80 requires 3-byte payload, got len={len(payload)} byte={length_byte}"
    profile, _selector, sub = payload[0], payload[1], payload[2]
    if profile != 1:
        return False, f"only profile=1 permitted, got {profile}"
    if sub not in (0, 1):
        return False, f"sub index must be 0 or 1 (unbounded in firmware!), got {sub}"
    return True, "ok"


@dataclass(frozen=True)
class CommandSpec:
    key: CommandKey
    name: str
    safety: SafetyLevel
    evidence_addr: str
    payload_validator: PayloadValidator
    expected_reply_len: int | None
    notes: str = ""

    @property
    def target_role(self) -> TargetRole:
        return self.key[0]

    @property
    def family(self) -> ProtocolFamily:
        return self.key[1]

    @property
    def route(self) -> int:
        return self.key[2]

    @property
    def group(self) -> int | None:
        return self.key[3]

    @property
    def cmd(self) -> int:
        return self.key[4]


def _mouse_a(
    group: int,
    cmd: int,
    name: str,
    safety: SafetyLevel,
    evidence: str,
    validator: PayloadValidator,
    reply_len: int | None,
    notes: str = "",
) -> CommandSpec:
    return CommandSpec(
        key=(TargetRole.MOUSE_USB, ProtocolFamily.A, 0, group, cmd),
        name=name,
        safety=safety,
        evidence_addr=evidence,
        payload_validator=validator,
        expected_reply_len=reply_len,
        notes=notes,
    )


def _mouse_b(
    cmd: int,
    name: str,
    safety: SafetyLevel,
    evidence: str,
    validator: PayloadValidator,
    reply_len: int | None,
    notes: str = "",
) -> CommandSpec:
    return CommandSpec(
        key=(TargetRole.MOUSE_USB, ProtocolFamily.B, 0, None, cmd),
        name=name,
        safety=safety,
        evidence_addr=evidence,
        payload_validator=validator,
        expected_reply_len=reply_len,
        notes=notes,
    )


def _rx_usb(
    cmd: int,
    name: str,
    safety: SafetyLevel,
    evidence: str,
    validator: PayloadValidator,
    reply_len: int | None,
    notes: str = "",
) -> CommandSpec:
    return CommandSpec(
        key=(TargetRole.RECEIVER_USB_LOCAL, ProtocolFamily.A, 0, 0, cmd),
        name=name,
        safety=safety,
        evidence_addr=evidence,
        payload_validator=validator,
        expected_reply_len=reply_len,
        notes=notes,
    )


def _rx_2g4(
    cmd: int,
    name: str,
    safety: SafetyLevel,
    evidence: str,
    validator: PayloadValidator,
    reply_len: int | None,
    notes: str = "",
) -> CommandSpec:
    return CommandSpec(
        key=(TargetRole.RECEIVER_2G4_LOCAL, ProtocolFamily.A, 1, 0, cmd),
        name=name,
        safety=safety,
        evidence_addr=evidence,
        payload_validator=validator,
        expected_reply_len=reply_len,
        notes=notes,
    )


def _rx_2g4_b(
    cmd: int,
    name: str,
    safety: SafetyLevel,
    evidence: str,
    validator: PayloadValidator,
    reply_len: int | None,
    notes: str = "",
) -> CommandSpec:
    return CommandSpec(
        key=(TargetRole.RECEIVER_2G4_LOCAL, ProtocolFamily.B, 0, None, cmd),
        name=name,
        safety=safety,
        evidence_addr=evidence,
        payload_validator=validator,
        expected_reply_len=reply_len,
        notes=notes,
    )


def _mirror_mouse_to_rf(spec: CommandSpec) -> CommandSpec:
    """Mirror a MOUSE_USB command into RECEIVER_TO_MOUSE_RF with 0xB21C RF routing."""
    rf_route = 2 if spec.family == ProtocolFamily.A else 1
    rf_notes = f"Forwarded via 0xB21C RF type5 ({spec.notes})" if spec.notes else "Forwarded via 0xB21C RF type5"
    return CommandSpec(
        key=(TargetRole.RECEIVER_TO_MOUSE_RF, spec.family, rf_route, spec.group, spec.cmd),
        name=f"rf_{spec.name}",
        safety=spec.safety,
        evidence_addr=f"rx_2g4:0xB21C->{spec.evidence_addr}",
        payload_validator=spec.payload_validator,
        expected_reply_len=spec.expected_reply_len,
        notes=rf_notes,
    )


_MOUSE_SPECS: list[CommandSpec] = [
    # --- Mouse USB Family A Group 0 (0x17994) ---
    _mouse_a(0, 0x80, "mouse_a_g0_mode_status", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x17994", _empty_payload, 1, "Reads RAM 0x20003214"),
    _mouse_a(0, 0x81, "mouse_a_g0_fw_version", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x17994", _empty_payload, 6, "Hardcoded v1.00.39 + 3508"),
    _mouse_a(0, 0x82, "mouse_a_g0_46b_record", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x17994", _bounded_length_read(46), 46, "Bounded <=46B copy from 0x20004346"),
    _mouse_a(0, 0x83, "mouse_a_g0_battery_status", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x17994", _empty_payload, 2, "Reads 0x20003A80/81 (len byte unchanged)"),
    _mouse_a(0, 0x84, "mouse_a_g0_cfg_header", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x17994", _empty_payload, 1, "Reads 0x2000437F"),
    _mouse_a(0, 0x85, "mouse_a_g0_active_profile", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x17994", _empty_payload, 1, "Reads 0x20004380+1"),
    _mouse_a(0, 0x86, "mouse_a_g0_profile_count", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x17994", _empty_payload, 1, "Reads 0x20004381"),
    _mouse_a(0, 0x87, "mouse_a_g0_sleep_u16", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x17994", _empty_payload, 2, "Reads BE u16 sleep"),
    _mouse_a(0, 0x88, "mouse_a_g0_profile_debounce", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x17994", _profile1_only, 2, "Profile=1 only (firmware lacks upper bound)"),
    _mouse_a(0, 0x89, "mouse_a_g0_radio_link_status", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x17994", _empty_payload, 1, "Calls 0x2109C==6"),
    _mouse_a(0, 0x8A, "mouse_a_g0_ficr_device_id", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x17994", _empty_payload, 4, "Reads FICR->DEVICEID[0]"),
    # --- Mouse USB Family A Group 1 (0x192B0) ---
    _mouse_a(1, 0x80, "mouse_a_g1_polling_rate", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x192B0", _empty_payload, 1),
    _mouse_a(1, 0x81, "mouse_a_g1_dpi_table", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x192B0", _profile1_only, None, "Profile=1 only"),
    _mouse_a(1, 0x82, "mouse_a_g1_active_dpi_slot", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x192B0", _profile1_only, 2, "Profile=1 only"),
    _mouse_a(1, 0x83, "mouse_a_g1_current_xy_cpi", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x192B0", _profile1_only, 5, "Profile=1 only"),
    _mouse_a(1, 0x84, "mouse_a_g1_reg56_flag", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x192B0", _empty_payload, 1),
    _mouse_a(1, 0x88, "mouse_a_g1_lod", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x192B0", _empty_payload, 1),
    _mouse_a(1, 0x89, "mouse_a_g1_motionsync_flag", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x192B0", _empty_payload, 1),
    _mouse_a(1, 0x8A, "mouse_a_g1_reg4f_flag", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x192B0", _empty_payload, 1),
    # --- Mouse USB Family A Group 3 (0x176F0) ---
    _mouse_a(3, 0x80, "mouse_a_g3_keyslot_read", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x176F0", _group3_keyslot_read, None, "Bounded profile=1, sub in {0,1}"),
    # --- Mouse USB Family B (0x18494) ---
    _mouse_b(0x81, "mouse_b_fw_version_sensor", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 7, "Version + sensor branch 4F->99 / 51->95 / 53->50"),
    _mouse_b(0x82, "mouse_b_polling_rate", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 1),
    _mouse_b(0x83, "mouse_b_dpi_table", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 51),
    _mouse_b(0x84, "mouse_b_keymap_6", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 36),
    _mouse_b(0x85, "mouse_b_debounce_4", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 4),
    _mouse_b(0x86, "mouse_b_lod", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 1),
    _mouse_b(0x87, "mouse_b_reg56_flag", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 1),
    _mouse_b(0x88, "mouse_b_sleep_lighting_cfg", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 5),
    _mouse_b(0x8A, "mouse_b_object_pool_free", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 12),
    _mouse_b(0x8E, "mouse_b_object_dir_list", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, None, "Reply len = 1 + 6*count (<=50)"),
    _mouse_b(0x8F, "mouse_b_battery_status", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 2),
    _mouse_b(0x90, "mouse_b_radio_link_status", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 1),
    _mouse_b(0x91, "mouse_b_motionsync_flag", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 1),
    _mouse_b(0x92, "mouse_b_wheel_cfg", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 2),
    _mouse_b(0x93, "mouse_b_ficr_device_id", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 4),
    _mouse_b(0x94, "mouse_b_sensor_mode_flag", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 1),
    _mouse_b(0x95, "mouse_b_angle_flag", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 1),
    _mouse_b(0x96, "mouse_b_sensor_status_override", SafetyLevel.READ_ONLY_VERIFIED, "mouse:0x18494", _family_b_empty_query, 1),
    # --- Explicit FORBIDDEN_HAZARDOUS mouse markers ---
    _mouse_a(0, 0x00, "mouse_a_g0_mode_bl_reset", SafetyLevel.FORBIDDEN_HAZARDOUS, "mouse:0x17994", _empty_payload, None, "Bootloader/Factory/Restore/Reset!"),
    _mouse_a(2, 0x80, "mouse_a_g2_uninit_r6_read", SafetyLevel.FORBIDDEN_HAZARDOUS, "mouse:0x19D4C", _empty_payload, None, "Reads through uninitialized R6=0"),
    _mouse_a(4, 0x81, "mouse_a_g4_obj_size_unverified", SafetyLevel.FORBIDDEN_HAZARDOUS, "mouse:0x17CAC", _empty_payload, None, "Object pool query excluded in Phase 0"),
    _mouse_a(4, 0x83, "mouse_a_g4_obj_chunk_unbounded", SafetyLevel.FORBIDDEN_HAZARDOUS, "mouse:0x17CAC", _empty_payload, None, "Unbounded memcpy in firmware"),
    _mouse_b(0x09, "mouse_b_restore_defaults", SafetyLevel.FORBIDDEN_HAZARDOUS, "mouse:0x18494", _empty_payload, None, "Triggers full factory reset & erase"),
    _mouse_b(0x8B, "mouse_b_obj_size_unverified", SafetyLevel.FORBIDDEN_HAZARDOUS, "mouse:0x18494", _empty_payload, None, "Object pool query excluded in Phase 0"),
    _mouse_b(0x8D, "mouse_b_obj_chunk_unbounded", SafetyLevel.FORBIDDEN_HAZARDOUS, "mouse:0x18494", _empty_payload, None, "Unbounded memcpy in firmware"),
]

_SPECS: list[CommandSpec] = [
    *_MOUSE_SPECS,
    *(_mirror_mouse_to_rf(spec) for spec in _MOUSE_SPECS),
    # --- Receiver USB Local (0x08008348, route=0) ---
    _rx_usb(0x80, "rx_usb_mode_query", SafetyLevel.READ_ONLY_VERIFIED, "rx_usb:0x08008348", _empty_payload, 9, "Sets len=9, read-only"),
    _rx_usb(0x81, "rx_usb_fw_version", SafetyLevel.READ_ONLY_VERIFIED, "rx_usb:0x08008348", _empty_payload, 6, "Returns 01 00 27 00 00 17"),
    _rx_usb(0x82, "rx_usb_test_pattern", SafetyLevel.READ_ONLY_VERIFIED, "rx_usb:0x08008348", _empty_payload, 6, "Returns 01 02 03 04 05 06"),
    _rx_usb(0x00, "rx_usb_mode_bl_reset", SafetyLevel.FORBIDDEN_HAZARDOUS, "rx_usb:0x08008348", _empty_payload, None, "Bootloader/Reset"),
    # --- Receiver 2.4G Local Family A (0xAFD0, route=1) ---
    _rx_2g4(0x80, "rx_2g4_mode_query", SafetyLevel.READ_ONLY_VERIFIED, "rx_2g4:0xAFD0", _empty_payload, 9, "Sets len=9, read-only"),
    _rx_2g4(0x81, "rx_2g4_fw_version", SafetyLevel.READ_ONLY_VERIFIED, "rx_2g4:0xAFD0", _empty_payload, 6, "Returns 01 00 27 00 77 03"),
    _rx_2g4(0x82, "rx_2g4_test_pattern", SafetyLevel.READ_ONLY_VERIFIED, "rx_2g4:0xAFD0", _empty_payload, 6, "Returns 01 02 03 04 05 06"),
    _rx_2g4(0x8A, "rx_2g4_pair_id_read", SafetyLevel.READ_ONLY_VERIFIED, "rx_2g4:0xAFD0", _empty_payload, 4, "Reads paired mouse ID from RAM 0x2000130E..11"),
    _rx_2g4(0x8B, "rx_2g4_rf_state_read", SafetyLevel.READ_ONLY_VERIFIED, "rx_2g4:0xAFD0", _receiver_2g4_0x8b_param2, 6, "Reads RF channel/ID snapshot when param==2"),
    _rx_2g4(0x8C, "rx_2g4_status_flag_read", SafetyLevel.READ_ONLY_VERIFIED, "rx_2g4:0xAFD0", _empty_payload, 1, "Returns 1 byte 0x00"),
    _rx_2g4(0x00, "rx_2g4_mode_bl_factory_reset", SafetyLevel.FORBIDDEN_HAZARDOUS, "rx_2g4:0xAFD0", _empty_payload, None, "Bootloader/Factory RF/Reset"),
    _rx_2g4(0x0A, "rx_2g4_nv_pair_id_write", SafetyLevel.FORBIDDEN_HAZARDOUS, "rx_2g4:0xAFD0", _empty_payload, None, "Writes 41B NV (0x27000) pair ID and marks dirty"),
    _rx_2g4(0x0B, "rx_2g4_pid_vid_write", SafetyLevel.FORBIDDEN_HAZARDOUS, "rx_2g4:0xAFD0", _empty_payload, None, "Writes BOTH 2.4G NV (0x27000) and USB Flash PID/VID"),
    # --- Receiver 2.4G Local Family B (0xB21C, route=byte[3]==0) ---
    _rx_2g4_b(0x81, "rx_2g4_b_fw_version", SafetyLevel.READ_ONLY_VERIFIED, "rx_2g4:0xB21C", _family_b_empty_query, 6, "Returns 6B: 01 00 27 00 77 03"),
    _rx_2g4_b(0x90, "rx_2g4_b_mouse_link_status", SafetyLevel.READ_ONLY_VERIFIED, "rx_2g4:0xB21C", _family_b_empty_query, 1, "Reads mouse RF link status byte_200028DD (0=disconnected, !=0=connected)"),
    _rx_2g4_b(0x93, "rx_2g4_b_ficr_device_id", SafetyLevel.READ_ONLY_VERIFIED, "rx_2g4:0xB21C", _family_b_empty_query, 4, "Reads 2.4G nRF52820 FICR->DEVICEID[0] (4B LE)"),
]

COMMAND_CATALOG: dict[CommandKey, CommandSpec] = {spec.key: spec for spec in _SPECS}


def get_command_spec(target_role: TargetRole, frame_64: bytes) -> CommandSpec | None:
    """Resolve raw 64B frame against COMMAND_CATALOG."""
    fam = ProtocolFamily(identify_frame_family(frame_64))
    route = frame_64[2] if fam == ProtocolFamily.A else frame_64[3]
    group = frame_64[4] if fam == ProtocolFamily.A else None
    cmd = frame_64[5] if fam == ProtocolFamily.A else frame_64[2]
    return COMMAND_CATALOG.get((target_role, fam, route, group, cmd))


def extract_request_payload(frame_64: bytes) -> tuple[ProtocolFamily, bytes, int]:
    """Extract (family, payload_slice, length_byte) from a raw 64B outgoing frame."""
    fam = ProtocolFamily(identify_frame_family(frame_64))
    if fam == ProtocolFamily.A:
        length_byte = frame_64[3]
        # Bounded safely by 58 so slicing never escapes the 64B buffer
        return fam, frame_64[6 : 6 + min(length_byte, 58)], length_byte
    length_byte = frame_64[1]
    # For Family B queries with length_byte=1 and empty payload, check actual non-zero tail
    if length_byte == 1 and all(b == 0 for b in frame_64[4:]):
        return fam, b"", length_byte
    return fam, frame_64[4 : 4 + min(length_byte, 60)], length_byte


def iter_readonly_candidates(target_role: TargetRole | None = None) -> list[CommandSpec]:
    """Return all catalog entries marked READ_ONLY_VERIFIED."""
    return [
        spec
        for spec in COMMAND_CATALOG.values()
        if spec.safety == SafetyLevel.READ_ONLY_VERIFIED
        and (target_role is None or spec.target_role == target_role)
    ]


def build_frame_from_spec(spec: CommandSpec, payload: bytes = b"", length_override: int | None = None) -> DeviceFrame:
    """Convenience helper to construct a frame matching a CommandSpec."""
    from fenrir.protocol.frames import build_family_a_frame, build_family_b_frame

    if spec.family == ProtocolFamily.A:
        assert spec.group is not None
        return build_family_a_frame(
            spec.group,
            spec.cmd,
            payload,
            route=spec.route,
            length_override=length_override,
        )
    return build_family_b_frame(spec.cmd, payload, route=spec.route, length_override=length_override)
