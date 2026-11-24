"""Phase 1 configuration read/apply/verify service over GuardedHidSession."""

from __future__ import annotations

import struct
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from fenrir.config.schema import MouseConfig, diff_configs, validate_config
from fenrir.probe.identity import MouseDisconnectedError
from fenrir.protocol.catalog import TargetRole
from fenrir.protocol.frames import (
    DeviceFrame,
    build_family_a_frame,
    build_family_b_frame,
    decode_debounce,
    decode_dpi_table,
    decode_keymap_6,
)
from fenrir.protocol.write_frames import (
    DpiSlot,
    KeymapEntry,
    build_angle_frame,
    build_debounce_frame,
    build_debounce_press_reload_frame,
    build_dpi_table_frame,
    build_keymap_frame,
    build_lod_frame,
    build_motionsync_frame,
    build_polling_rate_frame,
    build_reg56_frame,
    build_rgb_led_frame,
    build_sensor_mode_frame,
    build_sleep_timeout_frame,
)
from fenrir.transport.hid_win import GuardedHidSession


def _signed_i8(val: int) -> int:
    return val - 256 if val >= 128 else val


@dataclass(frozen=True)
class ApplyStep:
    field: str
    command: str
    status: str
    detail: str = ""


@dataclass
class ApplyReport:
    target_role: str
    dry_run: bool
    changed_fields: list[str]
    planned_frames: list[dict[str, str]] = field(default_factory=list)
    steps: list[ApplyStep] = field(default_factory=list)
    mismatches: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    settled_ms: int = 0
    success: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_role": self.target_role,
            "dry_run": self.dry_run,
            "changed_fields": self.changed_fields,
            "planned_frames": self.planned_frames,
            "steps": [asdict(s) for s in self.steps],
            "mismatches": {k: [v[0], v[1]] for k, v in self.mismatches.items()},
            "settled_ms": self.settled_ms,
            "success": self.success,
        }


class ConfigService:
    """High-level read/diff/apply/readback-verify service for Phase 1 mouse config."""

    def __init__(self, session: GuardedHidSession, target_role: TargetRole) -> None:
        if target_role not in (TargetRole.MOUSE_USB, TargetRole.RECEIVER_TO_MOUSE_RF):
            raise ValueError(
                f"ConfigService requires MOUSE_USB or RECEIVER_TO_MOUSE_RF, got {target_role.value}"
            )
        self.session = session
        self.target_role = target_role

    @property
    def is_wireless(self) -> bool:
        return self.target_role == TargetRole.RECEIVER_TO_MOUSE_RF

    @property
    def _route_a(self) -> int:
        return 2 if self.is_wireless else 0

    @property
    def _route_b(self) -> int:
        return 1 if self.is_wireless else 0

    def ensure_rf_link(self) -> int:
        """Mandatory pre-flight 2.4G local 0x90 check when operating via receiver."""
        if not self.is_wireless:
            return 1
        frame = build_family_b_frame(0x90, route=0).data
        _, parsed = self.session.query(TargetRole.RECEIVER_2G4_LOCAL, frame)
        link_raw = parsed.payload[0] if parsed.payload else 0
        if not parsed.is_ok or link_raw == 0:
            raise MouseDisconnectedError(
                f"Pre-flight 2.4G 0x90 reports mouse disconnected (status={parsed.status_name}, link={link_raw})"
            )
        return link_raw

    def _ask_b(self, cmd: int) -> bytes:
        _, parsed = self.session.query(
            self.target_role, build_family_b_frame(cmd, route=self._route_b).data
        )
        if not parsed.is_ok:
            raise RuntimeError(f"Family B read 0x{cmd:02X} failed: {parsed.status_name}")
        return parsed.payload

    def _ask_a(self, group: int, subcmd: int, payload: bytes = b"") -> bytes:
        _, parsed = self.session.query(
            self.target_role,
            build_family_a_frame(group, subcmd, payload, route=self._route_a).data,
        )
        if not parsed.is_ok:
            raise RuntimeError(f"Family A read ({group}, 0x{subcmd:02X}) failed: {parsed.status_name}")
        return parsed.payload

    def read_config(self) -> MouseConfig:
        """Read full MouseConfig from the target device (runs 0x90 pre-flight on wireless)."""
        self.ensure_rf_link()

        rate = self._ask_b(0x82)[0]
        dpi_raw = decode_dpi_table(self._ask_b(0x83))
        dpi_slots = [
            DpiSlot(s["x_cpi"], s["y_cpi"], (s["rgb"][0], s["rgb"][1], s["rgb"][2]))
            for s in dpi_raw["slots"]
        ]
        km_raw = decode_keymap_6(self._ask_b(0x84))
        keymap = []
        for btn in km_raw["buttons"]:
            act = int(btn["action_type"])
            d = bytes.fromhex(btn["data_hex"])
            if act in (0x18, 0x19, 0x1A):
                keymap.append(KeymapEntry(act, d[0], d[1], d[2], d[3], d[4]))
            else:
                # Firmware 0x84 zeros b1..b5 for non-macro actions; set b1=1 so re-saving passes 0x04 guard.
                keymap.append(KeymapEntry(act, b1=1))

        deb = decode_debounce(self._ask_b(0x85))["thresholds"]
        lod = self._ask_b(0x86)[0]
        reg56 = bool(self._ask_b(0x87)[0])
        rgb_raw = self._ask_b(0x88)
        rgb_enabled = bool(rgb_raw[0])
        rgb_mode = rgb_raw[1] if len(rgb_raw) > 1 else 2
        motionsync = bool(self._ask_b(0x91)[0])
        sensor_mode_hp = bool(self._ask_b(0x94)[0])
        angle_deg = _signed_i8(self._ask_b(0x95)[0])
        sleep_raw = self._ask_a(0, 0x87)
        sleep_sec = struct.unpack(">H", sleep_raw[:2])[0]

        return MouseConfig(
            polling_rate_code=rate,
            dpi_active_slot=int(dpi_raw["active_slot"]),
            dpi_stage_count=int(dpi_raw["stage_count"]),
            dpi_slots=dpi_slots,
            debounce_ms=(deb[0], deb[1], deb[2], deb[3]),
            immediate_debounce_reload=True,
            lod=lod,
            motionsync=motionsync,
            reg56=reg56,
            angle_deg=angle_deg,
            sensor_mode_hp=sensor_mode_hp,
            rgb_enabled=rgb_enabled,
            rgb_effect_mode=rgb_mode,
            sleep_sec=sleep_sec,
            keymap=keymap,
        )

    def _build_ops(
        self, desired: MouseConfig, changed_fields: set[str]
    ) -> list[tuple[str, str, DeviceFrame]]:
        w = self.is_wireless
        ops: list[tuple[str, str, DeviceFrame]] = []
        if "polling_rate_code" in changed_fields:
            ops.append(("polling_rate_code", "b_0x02", build_polling_rate_frame(desired.polling_rate_code, wireless=w)))
        if "dpi" in changed_fields:
            ops.append(
                (
                    "dpi",
                    "b_0x03",
                    build_dpi_table_frame(
                        desired.dpi_active_slot, desired.dpi_stage_count, desired.dpi_slots, wireless=w
                    ),
                )
            )
        if "debounce_ms" in changed_fields:
            ops.append(("debounce_ms", "b_0x05", build_debounce_frame(*desired.debounce_ms, wireless=w)))
            if desired.immediate_debounce_reload:
                ops.append(
                    (
                        "debounce_ms",
                        "g0_0x08",
                        build_debounce_press_reload_frame(desired.debounce_ms[0], wireless=w),
                    )
                )
        if "lod" in changed_fields:
            ops.append(("lod", "b_0x06", build_lod_frame(desired.lod, wireless=w)))
        if "motionsync" in changed_fields:
            ops.append(("motionsync", "b_0x11", build_motionsync_frame(desired.motionsync, wireless=w)))
        if "reg56" in changed_fields:
            ops.append(("reg56", "b_0x07", build_reg56_frame(desired.reg56, wireless=w)))
        if "angle_deg" in changed_fields:
            ops.append(("angle_deg", "b_0x15", build_angle_frame(desired.angle_deg, wireless=w)))
        if "sensor_mode_hp" in changed_fields:
            ops.append(("sensor_mode_hp", "b_0x14", build_sensor_mode_frame(desired.sensor_mode_hp, wireless=w)))
        if "rgb_led" in changed_fields:
            ops.append(
                (
                    "rgb_led",
                    "b_0x08",
                    build_rgb_led_frame(desired.rgb_enabled, desired.rgb_effect_mode, wireless=w),
                )
            )
        if "sleep_sec" in changed_fields:
            ops.append(("sleep_sec", "g0_0x07", build_sleep_timeout_frame(desired.sleep_sec, wireless=w)))
        if "keymap" in changed_fields:
            ops.append(("keymap", "b_0x04", build_keymap_frame(desired.keymap, wireless=w)))
        return ops

    def apply_config(
        self,
        desired: MouseConfig,
        *,
        dry_run: bool = False,
        verify_readback: bool = True,
        settle_ms: int = 550,
        only_changed: bool = True,
    ) -> ApplyReport:
        """Validate, optionally diff, apply writes, settle, and readback-verify."""
        validate_config(desired, wireless=self.is_wireless)

        if only_changed:
            current = self.read_config()
            diffs = diff_configs(current, desired, wireless=self.is_wireless)
            changed = list(diffs.keys())
        else:
            self.ensure_rf_link()
            changed = [
                "polling_rate_code",
                "dpi",
                "debounce_ms",
                "lod",
                "motionsync",
                "reg56",
                "angle_deg",
                "sensor_mode_hp",
                "rgb_led",
                "sleep_sec",
                "keymap",
            ]

        ops = self._build_ops(desired, set(changed))
        planned = [
            {"field": field_name, "command": cmd_name, "frame_hex": frame.hex()}
            for field_name, cmd_name, frame in ops
        ]

        if dry_run or not ops:
            return ApplyReport(
                target_role=self.target_role.value,
                dry_run=dry_run,
                changed_fields=changed,
                planned_frames=planned,
                steps=[],
                mismatches={},
                settled_ms=0,
                success=True,
            )

        self.ensure_rf_link()
        steps: list[ApplyStep] = []
        write_ok = True
        for field_name, cmd_name, frame in ops:
            _, reply = self.session.query(self.target_role, frame.data)
            steps.append(
                ApplyStep(
                    field=field_name,
                    command=cmd_name,
                    status=reply.status_name,
                    detail="" if reply.is_ok else f"unexpected status {reply.status_name}",
                )
            )
            if not reply.is_ok:
                write_ok = False

        if settle_ms > 0:
            time.sleep(settle_ms / 1000.0)

        mismatches: dict[str, tuple[Any, Any]] = {}
        if verify_readback:
            self.ensure_rf_link()
            actual = self.read_config()
            all_diffs = diff_configs(actual, desired, wireless=self.is_wireless)
            mismatches = {k: v for k, v in all_diffs.items() if k in changed}

        return ApplyReport(
            target_role=self.target_role.value,
            dry_run=False,
            changed_fields=changed,
            planned_frames=planned,
            steps=steps,
            mismatches=mismatches,
            settled_ms=settle_ms,
            success=write_ok and (len(mismatches) == 0),
        )
