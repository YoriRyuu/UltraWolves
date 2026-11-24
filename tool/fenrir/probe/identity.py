"""Read-only probe suites and package-vs-hardware identity comparator."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from fenrir.constants import (
    EXPECTED_MOUSE_FAMILYB_VERSION_PREFIX,
    EXPECTED_MOUSE_GROUP0_VERSION_BYTES,
    EXPECTED_RECEIVER_2G4_VERSION_BYTES,
    EXPECTED_RECEIVER_USB_VERSION_BYTES,
    MOUSE_APP_PIDS,
    RECEIVER_APP_PIDS,
    VENDOR_ID,
)
from fenrir.protocol.catalog import TargetRole
from fenrir.protocol.frames import (
    build_family_a_frame,
    build_family_b_frame,
    decode_battery_status,
    decode_debounce,
    decode_device_id,
    decode_dpi_table,
    decode_family_b_version,
    decode_keymap_6,
    decode_version_6b,
)
from fenrir.transport.base import HidDeviceInfo
from fenrir.transport.hid_win import GuardedHidSession


class IdentityVerdict(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    INCONCLUSIVE = "INCONCLUSIVE"


class MouseDisconnectedError(RuntimeError):
    """Raised when receiver 2.4G 0x90 reports mouse disconnected (prevents USB 0xA0 hang)."""


def _probe_mouse_common(
    session: GuardedHidSession,
    device: HidDeviceInfo,
    *,
    target_role: TargetRole,
    route_a: int,
    route_b: int,
    via_receiver: bool,
    preflight_replies: dict[str, Any] | None = None,
    mouse_link_raw: int | None = None,
) -> dict[str, Any]:
    """Run read-only L2 mouse query battery over direct USB or receiver RF forwarding."""
    replies: dict[str, Any] = dict(preflight_replies or {})

    def ask_a(name: str, group: int, subcmd: int, payload: bytes = b"") -> bytes:
        frame = build_family_a_frame(group, subcmd, payload, route=route_a).data
        _, parsed = session.query(target_role, frame)
        replies[name] = {
            "status": parsed.status_name,
            "length": parsed.length,
            "payload_hex": parsed.payload.hex(),
            "raw_hex": parsed.raw.hex(),
        }
        return parsed.payload

    def ask_b(name: str, cmd: int) -> bytes:
        frame = build_family_b_frame(cmd, route=route_b).data
        _, parsed = session.query(target_role, frame)
        replies[name] = {
            "status": parsed.status_name,
            "length": parsed.length,
            "payload_hex": parsed.payload.hex(),
            "raw_hex": parsed.raw.hex(),
        }
        return parsed.payload

    g0_ver = decode_version_6b(ask_a("group0_fw_version", 0, 0x81))
    fb_ver = decode_family_b_version(ask_b("familyb_fw_version_sensor", 0x81))
    g0_devid = decode_device_id(ask_a("group0_device_id", 0, 0x8A))
    fb_devid = decode_device_id(ask_b("familyb_device_id", 0x93))

    active_profile = ask_a("group0_active_profile", 0, 0x85)
    profile_count = ask_a("group0_profile_count", 0, 0x86)
    polling_rate = ask_b("familyb_polling_rate", 0x82)
    dpi_table = decode_dpi_table(ask_b("familyb_dpi_table", 0x83))
    keymap = decode_keymap_6(ask_b("familyb_keymap_6", 0x84))
    debounce = decode_debounce(ask_b("familyb_debounce_4", 0x85))
    lod = ask_b("familyb_lod", 0x86)
    reg56 = ask_b("familyb_reg56", 0x87)
    battery = decode_battery_status(ask_b("familyb_battery", 0x8F))
    motionsync = ask_b("familyb_motionsync", 0x91)
    sensor_mode = ask_b("familyb_sensor_mode", 0x94)
    angle = ask_b("familyb_angle", 0x95)

    snapshot: dict[str, Any] = {
        "group0_version": g0_ver,
        "familyb_version_sensor": fb_ver,
        "group0_device_id": g0_devid,
        "familyb_device_id": fb_devid,
        "device_id_consistent": g0_devid["raw_hex"] == fb_devid["raw_hex"],
        "active_profile": active_profile[0] if active_profile else None,
        "profile_count": profile_count[0] if profile_count else None,
        "polling_rate_code": polling_rate[0] if polling_rate else None,
        "dpi_table": dpi_table,
        "keymap": keymap,
        "debounce": debounce,
        "lod_raw": lod[0] if lod else None,
        "reg56_raw": reg56[0] if reg56 else None,
        "motionsync_raw": motionsync[0] if motionsync else None,
        "sensor_mode_raw": sensor_mode[0] if sensor_mode else None,
        "angle_raw": angle[0] if angle else None,
        "battery": battery,
        "via_receiver_rf": via_receiver,
    }
    if mouse_link_raw is not None:
        snapshot["mouse_link_raw"] = mouse_link_raw
        snapshot["mouse_connected"] = bool(mouse_link_raw)

    identity = evaluate_mouse_identity(device, snapshot, via_receiver=via_receiver)
    return {
        "schema_version": "1.0",
        "probed_at_utc": datetime.now(timezone.utc).isoformat(),
        "target_role": target_role.value,
        "usb_device": device.to_dict(),
        "identity": identity,
        "snapshot": snapshot,
        "raw_replies": replies,
    }


def probe_mouse_usb(session: GuardedHidSession, device: HidDeviceInfo) -> dict[str, Any]:
    """Run read-only L2 query battery on a USB-connected Fenrir mouse."""
    return _probe_mouse_common(
        session,
        device,
        target_role=TargetRole.MOUSE_USB,
        route_a=0,
        route_b=0,
        via_receiver=False,
    )


def probe_mouse_via_receiver(session: GuardedHidSession, device: HidDeviceInfo) -> dict[str, Any]:
    """Run read-only L2 mouse query battery via 8K receiver after mandatory 0x90 link check."""
    link_frame = build_family_b_frame(0x90, route=0).data
    _, link_parsed = session.query(TargetRole.RECEIVER_2G4_LOCAL, link_frame)
    mouse_link_raw = link_parsed.payload[0] if link_parsed.payload else 0
    if not link_parsed.is_ok or mouse_link_raw == 0:
        raise MouseDisconnectedError(
            "Receiver 2.4G local 0x90 reports mouse disconnected "
            f"(status={link_parsed.status_name}, link={mouse_link_raw}); "
            "aborting BEFORE sending any forwarded RF frame to avoid USB GET_REPORT 0xA0 hang."
        )

    preflight = {
        "rx_2g4_preflight_mouse_link": {
            "status": link_parsed.status_name,
            "length": link_parsed.length,
            "payload_hex": link_parsed.payload.hex(),
            "raw_hex": link_parsed.raw.hex(),
        }
    }
    return _probe_mouse_common(
        session,
        device,
        target_role=TargetRole.RECEIVER_TO_MOUSE_RF,
        route_a=2,
        route_b=1,
        via_receiver=True,
        preflight_replies=preflight,
        mouse_link_raw=mouse_link_raw,
    )


def probe_receiver_local(
    session: GuardedHidSession,
    device: HidDeviceInfo,
    *,
    include_2g4: bool = True,
) -> dict[str, Any]:
    """Run read-only L2 local query battery on Receiver USB (and optionally 2.4G) MCU."""
    replies: dict[str, Any] = {}

    def ask_a(role: TargetRole, name: str, route: int, subcmd: int, payload: bytes = b"") -> bytes:
        frame = build_family_a_frame(0, subcmd, payload, route=route).data
        _, parsed = session.query(role, frame)
        replies[name] = {
            "status": parsed.status_name,
            "length": parsed.length,
            "payload_hex": parsed.payload.hex(),
            "raw_hex": parsed.raw.hex(),
        }
        return parsed.payload

    def ask_2g4_b(name: str, cmd: int) -> bytes:
        frame = build_family_b_frame(cmd, route=0).data
        _, parsed = session.query(TargetRole.RECEIVER_2G4_LOCAL, frame)
        replies[name] = {
            "status": parsed.status_name,
            "length": parsed.length,
            "payload_hex": parsed.payload.hex(),
            "raw_hex": parsed.raw.hex(),
        }
        return parsed.payload

    usb_ver = decode_version_6b(ask_a(TargetRole.RECEIVER_USB_LOCAL, "rx_usb_fw_version", 0, 0x81))
    usb_pattern = ask_a(TargetRole.RECEIVER_USB_LOCAL, "rx_usb_test_pattern", 0, 0x82)

    g24_ver = None
    g24_b_ver = None
    g24_pattern = None
    g24_pair_id = None
    g24_rf_state = None
    g24_link = None
    g24_devid = None
    if include_2g4:
        g24_ver = decode_version_6b(ask_a(TargetRole.RECEIVER_2G4_LOCAL, "rx_2g4_fw_version", 1, 0x81))
        g24_pattern = ask_a(TargetRole.RECEIVER_2G4_LOCAL, "rx_2g4_test_pattern", 1, 0x82)
        g24_pair_id = ask_a(TargetRole.RECEIVER_2G4_LOCAL, "rx_2g4_pair_id", 1, 0x8A)
        g24_rf_state = ask_a(TargetRole.RECEIVER_2G4_LOCAL, "rx_2g4_rf_state", 1, 0x8B, b"\x02")
        g24_b_ver = decode_version_6b(ask_2g4_b("rx_2g4_b_fw_version", 0x81))
        g24_link = ask_2g4_b("rx_2g4_b_mouse_link_status", 0x90)
        g24_devid = decode_device_id(ask_2g4_b("rx_2g4_b_ficr_device_id", 0x93))

    snapshot = {
        "usb_mcu_version": usb_ver,
        "usb_test_pattern_hex": usb_pattern.hex(),
        "rf_mcu_version": g24_ver,
        "rf_mcu_familyb_version": g24_b_ver,
        "rf_test_pattern_hex": g24_pattern.hex() if g24_pattern is not None else None,
        "paired_mouse_id_hex": g24_pair_id.hex() if g24_pair_id is not None else None,
        "rf_state_hex": g24_rf_state.hex() if g24_rf_state is not None else None,
        "mouse_connected": bool(g24_link[0]) if g24_link else None,
        "mouse_link_raw": g24_link[0] if g24_link else None,
        "rf_mcu_device_id": g24_devid,
    }
    identity = evaluate_receiver_identity(device, snapshot)
    return {
        "schema_version": "1.0",
        "probed_at_utc": datetime.now(timezone.utc).isoformat(),
        "target_role": TargetRole.RECEIVER_2G4_LOCAL.value if include_2g4 else TargetRole.RECEIVER_USB_LOCAL.value,
        "usb_device": device.to_dict(),
        "identity": identity,
        "snapshot": snapshot,
        "raw_replies": replies,
    }


def evaluate_mouse_identity(
    device: HidDeviceInfo,
    snapshot: dict[str, Any],
    *,
    via_receiver: bool = False,
) -> dict[str, Any]:
    """Compare observed mouse probe snapshot against Fenrir+035 v1.00.39 package."""
    reasons: list[str] = []
    mismatches: list[str] = []

    if via_receiver:
        if device.vid != VENDOR_ID or device.pid not in RECEIVER_APP_PIDS:
            mismatches.append(
                f"USB transport VID:PID 0x{device.vid:04X}:0x{device.pid:04X} not in expected Receiver APP PIDs"
            )
        else:
            reasons.append(
                f"USB transport VID:PID 0x{device.vid:04X}:0x{device.pid:04X} matches Receiver APP path (RF forwarding to mouse)"
            )
    elif device.vid != VENDOR_ID or device.pid not in MOUSE_APP_PIDS:
        mismatches.append(
            f"USB VID:PID 0x{device.vid:04X}:0x{device.pid:04X} not in expected Mouse APP PIDs ({[hex(p) for p in MOUSE_APP_PIDS]})"
        )
    else:
        reasons.append(f"USB VID:PID 0x{device.vid:04X}:0x{device.pid:04X} matches Mouse APP path")

    g0_hex = snapshot["group0_version"]["raw_hex"]
    fb_hex = snapshot["familyb_version_sensor"]["raw_hex"][:12]
    exp_g0 = EXPECTED_MOUSE_GROUP0_VERSION_BYTES.hex()
    exp_fb = EXPECTED_MOUSE_FAMILYB_VERSION_PREFIX.hex()

    if g0_hex == exp_g0 and fb_hex == exp_fb:
        reasons.append(f"Firmware version bytes match Fenrir+035 v1.00.39.00 ({exp_g0})")
    else:
        mismatches.append(f"Firmware version mismatch: group0={g0_hex}, familyB={fb_hex}, expected={exp_g0}")

    branch_id = snapshot["familyb_version_sensor"]["sensor_branch_id"]
    if branch_id.startswith("ID"):
        reasons.append(
            f"Sensor branch decoded: {branch_id} (byte {snapshot['familyb_version_sensor']['sensor_branch_byte_hex']})"
        )
    else:
        mismatches.append(f"Unknown sensor branch byte: {snapshot['familyb_version_sensor']['sensor_branch_byte_hex']}")

    if not snapshot.get("device_id_consistent", False):
        mismatches.append("FICR DEVICEID mismatch between group0 0x8A and Family B 0x93")

    if mismatches:
        verdict = IdentityVerdict.MISMATCH
    else:
        verdict = IdentityVerdict.MATCH

    return {
        "verdict": verdict.value,
        "reasons": reasons,
        "mismatches": mismatches,
        "caveat": (
            "Matching APP version/PID confirms protocol & firmware-family alignment, "
            "NOT bootloader signature policy or physical PCB equality (verify via Phase 5 SWD backup before flashing)."
        ),
    }


def evaluate_receiver_identity(device: HidDeviceInfo, snapshot: dict[str, Any]) -> dict[str, Any]:
    """Compare observed receiver probe snapshot against G-Wolves 8K Receiver v1.00.39 package."""
    reasons: list[str] = []
    mismatches: list[str] = []

    if device.vid != VENDOR_ID or device.pid not in RECEIVER_APP_PIDS:
        mismatches.append(f"USB VID:PID 0x{device.vid:04X}:0x{device.pid:04X} not in expected Receiver APP PIDs")
    else:
        reasons.append(f"USB VID:PID 0x{device.vid:04X}:0x{device.pid:04X} matches Receiver APP list")

    usb_hex = snapshot["usb_mcu_version"]["raw_hex"]
    exp_usb = EXPECTED_RECEIVER_USB_VERSION_BYTES.hex()
    if usb_hex == exp_usb:
        reasons.append(f"USB MCU (AT32F405 candidate) version matches v1.00.39.00 ({exp_usb})")
    else:
        mismatches.append(f"USB MCU version mismatch: got={usb_hex}, expected={exp_usb}")

    rf_ver = snapshot.get("rf_mcu_version")
    if rf_ver is not None:
        rf_hex = rf_ver["raw_hex"]
        exp_rf = EXPECTED_RECEIVER_2G4_VERSION_BYTES.hex()
        if rf_hex == exp_rf:
            reasons.append(f"2.4G MCU (nRF52820 candidate) version matches v1.00.39.00 ({exp_rf})")
        else:
            mismatches.append(f"2.4G MCU version mismatch: got={rf_hex}, expected={exp_rf}")

    rf_fb_ver = snapshot.get("rf_mcu_familyb_version")
    if rf_fb_ver is not None:
        exp_rf = EXPECTED_RECEIVER_2G4_VERSION_BYTES.hex()
        if rf_fb_ver["raw_hex"] == exp_rf:
            reasons.append(f"2.4G MCU 0xB21C Family B 0x81 version matches ({exp_rf})")
        else:
            mismatches.append(
                f"2.4G MCU 0xB21C Family B 0x81 mismatch: got={rf_fb_ver['raw_hex']}, expected={exp_rf}"
            )

    if snapshot.get("mouse_connected") is not None:
        link_state = "connected" if snapshot["mouse_connected"] else "disconnected"
        reasons.append(f"2.4G mouse RF link status (0x90): {link_state} (raw={snapshot.get('mouse_link_raw')})")

    if mismatches:
        verdict = IdentityVerdict.MISMATCH
    elif rf_ver is None:
        verdict = IdentityVerdict.INCONCLUSIVE
        reasons.append("2.4G MCU was not queried; receiver USB MCU alone is insufficient for full dual-MCU match")
    else:
        verdict = IdentityVerdict.MATCH

    return {
        "verdict": verdict.value,
        "reasons": reasons,
        "mismatches": mismatches,
        "caveat": (
            "Bootloader signature/anti-rollback policy remains unknown until Phase 5 SWD dump."
        ),
    }


def format_identity_summary(report: dict[str, Any]) -> str:
    """Format a human-readable plain-language + technical summary."""
    ident = report["identity"]
    dev = report["usb_device"]
    snap = report["snapshot"]
    lines = [
        f"=== Fenrir Probe Identity Summary [{ident['verdict']}] ===",
        f"Target Role : {report['target_role']}",
        f"USB Device  : {dev['vid_hex']}:{dev['pid_hex']} ({dev['product']})",
        f"Verdict     : {ident['verdict']}",
    ]
    for r in ident["reasons"]:
        lines.append(f"  + {r}")
    for m in ident["mismatches"]:
        lines.append(f"  ! {m}")

    if "familyb_version_sensor" in snap:
        fb = snap["familyb_version_sensor"]
        if snap.get("via_receiver_rf"):
            lines.append(f"Transport   : Receiver RF type5 (pre-flight 0x90 link={snap.get('mouse_link_raw')})")
        lines.extend(
            [
                f"Mouse FW    : {fb['version_str']} (tail={fb['tail_bytes_hex']})",
                f"Sensor      : {fb['sensor_branch_id']} (byte={fb['sensor_branch_byte_hex']})",
                f"Device ID   : {snap['group0_device_id']['raw_hex']}",
                f"Polling/DPI : rate_code={snap['polling_rate_code']}, active_slot={snap['dpi_table']['active_slot']}, stages={snap['dpi_table']['stage_count']}",
                f"Debounce    : {snap['debounce']['thresholds']}",
            ]
        )
    elif "usb_mcu_version" in snap:
        lines.append(f"RX USB FW   : {snap['usb_mcu_version']['version_str']} (tail={snap['usb_mcu_version']['tail_bytes_hex']})")
        if snap.get("rf_mcu_version"):
            lines.append(f"RX 2.4G FW  : {snap['rf_mcu_version']['version_str']} (tail={snap['rf_mcu_version']['tail_bytes_hex']})")
            lines.append(f"Paired ID   : {snap['paired_mouse_id_hex']}")
        if snap.get("rf_mcu_device_id"):
            lines.append(f"RX 2.4G ID  : {snap['rf_mcu_device_id']['raw_hex']}")
        if snap.get("mouse_connected") is not None:
            link_label = "CONNECTED" if snap["mouse_connected"] else "DISCONNECTED"
            lines.append(f"Mouse Link  : {link_label} (raw={snap.get('mouse_link_raw')})")

    lines.append(f"Note        : {ident['caveat']}")
    return "\n".join(lines)
