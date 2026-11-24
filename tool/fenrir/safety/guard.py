"""Mandatory read-only safety gate for all Phase 0 device interactions."""

from __future__ import annotations

import hashlib
import json
from enum import IntEnum
from pathlib import Path
from typing import Any

from fenrir.constants import (
    DEVICE_FRAME_LEN,
    MOUSE_APP_PIDS,
    MOUSE_BL_PIDS,
    PROOFS_DIR,
    RECEIVER_APP_PIDS,
    RECEIVER_BL_PIDS,
    REFERENCE_FIRMWARES,
    VENDOR_ID,
)
from fenrir.protocol.catalog import (
    CommandKey,
    CommandSpec,
    ProtocolFamily,
    SafetyLevel,
    TargetRole,
    extract_request_payload,
    get_command_spec,
    iter_readonly_candidates,
)
from fenrir.protocol.frames import identify_frame_family


class SafetyViolationError(PermissionError):
    """Raised when a disallowed, hazardous, or uncatalogued command/device is blocked."""


class BootloaderDeviceBlockedError(SafetyViolationError):
    """Raised when any packet operation is attempted against a Bootloader PID."""


class UnprovenCommandError(SafetyViolationError):
    """Raised when a read-only command lacks a valid Unicorn side-effect-free proof."""


class ProbeLevel(IntEnum):
    L0_ENUMERATE = 0
    L1_PASSIVE_READ = 1
    L2_WHITELIST_QUERY = 2


_PROOF_FILES: dict[str, tuple[str, TargetRole]] = {
    "mouse": ("mouse_readonly_proof.json", TargetRole.MOUSE_USB),
    "receiver_usb": ("receiver_usb_readonly_proof.json", TargetRole.RECEIVER_USB_LOCAL),
    "receiver_2g4": ("receiver_2g4_readonly_proof.json", TargetRole.RECEIVER_2G4_LOCAL),
}

_RECEIVER_ROLES: tuple[TargetRole, ...] = (
    TargetRole.RECEIVER_USB_LOCAL,
    TargetRole.RECEIVER_2G4_LOCAL,
    TargetRole.RECEIVER_TO_MOUSE_RF,
)

_RECEIVER_2G4_FAMILY_B_CMDS: frozenset[int] = frozenset({0x81, 0x90, 0x93})


def _check_mouse_family_a_blacklist(group: int, subcmd: int) -> None:
    if group not in (0, 1, 3):
        raise SafetyViolationError(
            f"Mouse Family A group {group} blocked (group2 R6=0 bug / group4 object pool)"
        )
    if group == 2 and subcmd == 0x80:
        raise SafetyViolationError("group2 0x80 reads uninitialized R6=0")
    if group == 4 and subcmd in (0x81, 0x83):
        raise SafetyViolationError("group4 0x81/0x83 blocked")


def _check_mouse_family_b_blacklist(cmd: int) -> None:
    if cmd < 0x81:
        raise SafetyViolationError(
            f"Family B write/control command 0x{cmd:02X} (<0x81) unconditionally blocked"
        )
    if cmd in (0x8B, 0x8D):
        raise SafetyViolationError(
            f"Family B object command 0x{cmd:02X} blocked (unbounded object read / unverified)"
        )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class ReadOnlyGuard:
    """Central gatekeeper enforcing hard blacklists, catalog bounds, and Unicorn proofs."""

    def __init__(
        self,
        proofs_dir: Path | None = None,
        *,
        require_proofs: bool = True,
        verify_firmware_hashes: bool = True,
    ) -> None:
        self.proofs_dir = proofs_dir or PROOFS_DIR
        self.require_proofs = require_proofs
        self.verify_firmware_hashes = verify_firmware_hashes
        self._proven_keys: set[CommandKey] = set()
        self._verified_rf_routes: set[tuple[ProtocolFamily, int]] = set()
        self._proof_docs: dict[str, dict[str, Any]] = {}
        if require_proofs:
            self.reload_and_verify_proofs()

    def reload_and_verify_proofs(self) -> None:
        """Load Unicorn read-only proof JSONs and verify firmware hashes + results."""
        proven: set[CommandKey] = set()
        verified_rf_routes: set[tuple[ProtocolFamily, int]] = set()
        docs: dict[str, dict[str, Any]] = {}

        for fw_name, (filename, default_role) in _PROOF_FILES.items():
            proof_path = self.proofs_dir / filename
            if not proof_path.exists():
                raise UnprovenCommandError(f"Missing required Unicorn proof artifact: {proof_path}")

            try:
                doc = json.loads(proof_path.read_text(encoding="utf-8"))
            except Exception as exc:
                raise UnprovenCommandError(f"Corrupt proof JSON {proof_path}: {exc}") from exc

            ref = REFERENCE_FIRMWARES[fw_name]
            if self.verify_firmware_hashes:
                if not ref.hex_path.exists():
                    raise UnprovenCommandError(f"Reference firmware HEX missing: {ref.hex_path}")
                actual_sha = _sha256_file(ref.hex_path)
                if actual_sha != ref.expected_sha256:
                    raise SafetyViolationError(
                        f"Reference HEX SHA-256 mismatch for {fw_name}: {actual_sha} != {ref.expected_sha256}"
                    )
                recorded_sha = doc.get("firmware", {}).get("hex_sha256")
                if recorded_sha != ref.expected_sha256:
                    raise UnprovenCommandError(
                        f"Proof {filename} firmware SHA-256 mismatch: {recorded_sha} != {ref.expected_sha256}"
                    )

            neg_controls = doc.get("negative_controls", [])
            if not neg_controls or not all(nc.get("caught_as_unsafe") is True for nc in neg_controls):
                raise UnprovenCommandError(f"Proof {filename} missing passing negative controls")

            for entry in doc.get("verified_readonly_commands", []):
                if entry.get("side_effect_free") is not True or entry.get("passed") is not True:
                    continue
                role = TargetRole(entry.get("target_role", default_role.value))
                if role == TargetRole.RECEIVER_TO_MOUSE_RF:
                    # RF-forwarded keys are never trusted standalone; derived below from MOUSE_USB + 0xB21C route proofs.
                    continue
                fam = ProtocolFamily(entry["family"])
                route = int(entry["route"])
                group = entry["group"]
                if group is not None:
                    group = int(group)
                cmd = int(entry["cmd"])
                proven.add((role, fam, route, group, cmd))

            if fw_name == "receiver_2g4":
                for fp in doc.get("verified_forwarding_paths", []):
                    if (
                        fp.get("target_role") == TargetRole.RECEIVER_TO_MOUSE_RF.value
                        and fp.get("passed") is True
                        and fp.get("connected_routed_to_c328") is True
                        and fp.get("connected_side_effect_free") is True
                        and fp.get("disconnected_status") == "0xA4"
                        and fp.get("disconnected_skipped_d266") is True
                        and fp.get("disconnected_side_effect_free") is True
                    ):
                        verified_rf_routes.add((ProtocolFamily(fp["family"]), int(fp["route"])))

            docs[fw_name] = doc

        # RECEIVER_TO_MOUSE_RF requires BOTH the underlying MOUSE_USB proof AND the 0xB21C forwarding path proof.
        for spec in iter_readonly_candidates(TargetRole.RECEIVER_TO_MOUSE_RF):
            mouse_equiv_key: CommandKey = (TargetRole.MOUSE_USB, spec.family, 0, spec.group, spec.cmd)
            if mouse_equiv_key in proven and (spec.family, spec.route) in verified_rf_routes:
                proven.add(spec.key)

        self._proven_keys = proven
        self._verified_rf_routes = verified_rf_routes
        self._proof_docs = docs

    @property
    def proven_keys(self) -> frozenset[CommandKey]:
        return frozenset(self._proven_keys)

    @property
    def verified_rf_routes(self) -> frozenset[tuple[ProtocolFamily, int]]:
        return frozenset(self._verified_rf_routes)

    def check_device_allowed(
        self,
        vid: int,
        pid: int,
        level: ProbeLevel,
        *,
        target_role: TargetRole | None = None,
    ) -> None:
        """Enforce PID and probe-level boundaries before opening or querying a device."""
        if pid in MOUSE_BL_PIDS or pid in RECEIVER_BL_PIDS:
            if level > ProbeLevel.L0_ENUMERATE:
                raise BootloaderDeviceBlockedError(
                    f"Device 0x{vid:04X}:0x{pid:04X} is in BOOTLOADER mode; "
                    "all HID reads/writes beyond L0 enumeration are blocked."
                )
            return

        if level == ProbeLevel.L0_ENUMERATE:
            return

        if vid != VENDOR_ID:
            raise SafetyViolationError(f"Unexpected Vendor ID 0x{vid:04X}; expected 0x{VENDOR_ID:04X}")

        known_app_pids = MOUSE_APP_PIDS | RECEIVER_APP_PIDS
        if pid not in known_app_pids:
            raise SafetyViolationError(
                f"Unknown PID 0x{pid:04X}: only L0 enumeration is allowed without explicit match."
            )

        if target_role == TargetRole.MOUSE_USB and pid not in MOUSE_APP_PIDS:
            raise SafetyViolationError(
                f"PID 0x{pid:04X} is not a known Mouse APP PID ({sorted(hex(p) for p in MOUSE_APP_PIDS)})"
            )
        if target_role in _RECEIVER_ROLES and pid not in RECEIVER_APP_PIDS:
            raise SafetyViolationError(f"PID 0x{pid:04X} is not a known Receiver APP PID")

    def validate_outgoing_frame(self, target_role: TargetRole, frame_64: bytes) -> CommandSpec:
        """Strictly validate a raw 64B outgoing frame before any HID write occurs."""
        if not isinstance(frame_64, (bytes, bytearray)) or len(frame_64) != DEVICE_FRAME_LEN:
            raise SafetyViolationError(f"Frame must be exactly {DEVICE_FRAME_LEN} bytes")
        raw = bytes(frame_64)

        fam = ProtocolFamily(identify_frame_family(raw))
        self._check_hard_blacklist(target_role, fam, raw)

        spec = get_command_spec(target_role, raw)
        if spec is None:
            raise SafetyViolationError(
                f"Uncatalogued command blocked for {target_role.value}: frame prefix={raw[:8].hex()}"
            )
        if spec.safety != SafetyLevel.READ_ONLY_VERIFIED:
            raise SafetyViolationError(
                f"Command {spec.name} has safety level {spec.safety.value}; blocked by Phase 0 gate"
            )

        _, payload, length_byte = extract_request_payload(raw)
        if fam == ProtocolFamily.A:
            tail = raw[6 + min(length_byte, 58) :]
        else:
            expected_route = 1 if target_role == TargetRole.RECEIVER_TO_MOUSE_RF else 0
            if raw[3] != expected_route:
                raise SafetyViolationError(
                    f"Family B byte[3] (route) must be {expected_route} for {target_role.value}, got 0x{raw[3]:02X}"
                )
            tail = raw[4:] if not payload else raw[4 + min(length_byte, 60) :]
        if any(b != 0 for b in tail):
            raise SafetyViolationError("Non-zero trailing bytes outside declared payload span blocked")

        ok, reason = spec.payload_validator(payload, length_byte)
        if not ok:
            raise SafetyViolationError(f"Payload constraint failed for {spec.name}: {reason}")

        if self.require_proofs and spec.key not in self._proven_keys:
            raise UnprovenCommandError(
                f"Command {spec.name} ({spec.key}) has no verified Unicorn read-only proof"
            )
        return spec

    @staticmethod
    def _check_hard_blacklist(target_role: TargetRole, fam: ProtocolFamily, raw: bytes) -> None:
        """Independent hardcoded defense-in-depth blacklist."""
        # Q3: Receiver USB 0x8006870 latches sticky 84B Bootloader SPI bridge whenever frame[4]==0xB0
        # on forwarded frames; block frame[4]==0xB0 unconditionally across ALL receiver TargetRoles.
        if target_role in _RECEIVER_ROLES and raw[4] == 0xB0:
            raise SafetyViolationError(
                f"Receiver frame[4] == 0xB0 unconditionally blocked for {target_role.value} "
                "(0x8006870 sticky 84B bootloader SPI bridge trap)"
            )

        if fam == ProtocolFamily.A:
            route = raw[2]
            len_a = raw[3]
            group = raw[4]
            subcmd = raw[5]

            if len_a >= 0x3A:
                raise SafetyViolationError(f"Family A length byte 0x{len_a:02X} >= 0x3A blocked")
            if subcmd < 0x80:
                raise SafetyViolationError(
                    f"Family A write/control subcommand 0x{subcmd:02X} (<0x80) is unconditionally blocked"
                )
            if group == 0 and subcmd == 0x00:
                raise SafetyViolationError("group0 subcmd 0x00 (BL/Factory/Reset) blocked")
            if raw[6] in (0xA0, 0xB0, 0xC0) and group == 0 and subcmd < 0x80:
                raise SafetyViolationError("Bootloader/Factory/Restore magic byte blocked")

            if target_role == TargetRole.MOUSE_USB:
                if route != 0:
                    raise SafetyViolationError(f"Mouse USB route must be 0, got {route}")
                _check_mouse_family_a_blacklist(group, subcmd)
            elif target_role == TargetRole.RECEIVER_USB_LOCAL:
                if route != 0 or group != 0:
                    raise SafetyViolationError(
                        f"Receiver USB local requires route=0, group=0; got route={route}, group={group}"
                    )
            elif target_role == TargetRole.RECEIVER_2G4_LOCAL:
                if route != 1 or group != 0:
                    raise SafetyViolationError(
                        f"Receiver 2.4G local requires route=1, group=0; got route={route}, group={group}"
                    )
            elif target_role == TargetRole.RECEIVER_TO_MOUSE_RF:
                if route != 2:
                    raise SafetyViolationError(
                        f"Receiver-to-mouse RF Family A requires route=2 (byte[2]==2), got {route}"
                    )
                _check_mouse_family_a_blacklist(group, subcmd)
        else:
            cmd = raw[2]
            route = raw[3]
            if target_role == TargetRole.RECEIVER_USB_LOCAL:
                raise SafetyViolationError("Family B commands are not valid on RECEIVER_USB_LOCAL")
            if target_role == TargetRole.RECEIVER_2G4_LOCAL:
                if route != 0:
                    raise SafetyViolationError(
                        f"RECEIVER_2G4_LOCAL Family B requires byte[3]==0, got 0x{route:02X}"
                    )
                if cmd not in _RECEIVER_2G4_FAMILY_B_CMDS:
                    raise SafetyViolationError(
                        f"RECEIVER_2G4_LOCAL Family B allows ONLY cmd in (0x81, 0x90, 0x93), got 0x{cmd:02X}"
                    )
            elif target_role == TargetRole.MOUSE_USB:
                if route != 0:
                    raise SafetyViolationError(f"Mouse USB Family B requires byte[3]==0, got 0x{route:02X}")
                _check_mouse_family_b_blacklist(cmd)
            elif target_role == TargetRole.RECEIVER_TO_MOUSE_RF:
                if route != 1:
                    raise SafetyViolationError(
                        f"Receiver-to-mouse RF Family B requires route=1 (byte[3]==1), got 0x{route:02X}"
                    )
                _check_mouse_family_b_blacklist(cmd)
