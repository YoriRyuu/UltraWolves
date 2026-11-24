"""Phase 2 Family A Group 5 host service (diagnostics, sensor overrides, persistence)."""

from __future__ import annotations

import time
from typing import Any

from fenrir.probe.identity import MouseDisconnectedError
from fenrir.protocol.catalog import TargetRole
from fenrir.protocol.frames import DeviceFrame, FrameError, ParsedReply, build_family_b_frame
from fenrir.protocol.group5_frames import (
    ANTI_SLAM_LANDING_DEFAULT_MS,
    ANTI_SLAM_LIFTED_DEFAULT_MS,
    P3_FLAG_ATOMIC_ACCUM,
    P3_FLAG_CE_STATIC,
    P3_FLAG_DIRECT_MOTION,
    P3_FLAG_EAGER_WAKE,
    P3_FLAG_FIX_A,
    P3_FLAG_MOUSE_ABS,
    P3_FLAG_PLOCK_ENABLE,
    P3_FLAG_QUEUE_GUARD,
    P3_FLAGS_MASK,
    build_group5_get_p1_state_frame,
    build_group5_get_p2p3_state_frame,
    build_group5_get_p3_diag_frame,
    build_group5_get_p3_state_frame,
    build_group5_get_state_frame,
    build_group5_persist_ctrl_frame,
    build_group5_read_reg_frame,
    build_group5_reset_p3_diag_frame,
    build_group5_set_anti_slam_frame,
    build_group5_set_downshift_frame,
    build_group5_set_fps_frame,
    build_group5_set_lod_raw_frame,
    build_group5_set_p1_cfg_frame,
    build_group5_set_p3_ctrl_frame,
    build_group5_set_smoothing_frame,
    build_group5_snap_read_frame,
    build_group5_snap_trigger_frame,
    decode_group5_p1_state,
    decode_group5_p2p3_state,
    decode_group5_p3_diag,
    decode_group5_p3_state,
    decode_group5_snapshot,
    decode_group5_state,
)
from fenrir.safety.write_guard import WriteGuard
from fenrir.transport.hid_win import GuardedHidSession


class Group5CommandError(RuntimeError):
    """Raised when the mouse firmware rejects a Group 5 command (e.g. 0xA2 / 0xA3)."""

    def __init__(self, message: str, *, status_byte: int, status_name: str) -> None:
        super().__init__(message)
        self.status_byte = status_byte
        self.status_name = status_name


class Group5Service:
    """High-level Group 5 client over GuardedHidSession (USB or receiver-to-mouse RF)."""

    def __init__(self, session: GuardedHidSession, target_role: TargetRole) -> None:
        if target_role not in (TargetRole.MOUSE_USB, TargetRole.RECEIVER_TO_MOUSE_RF):
            raise ValueError(
                f"Group5Service requires MOUSE_USB or RECEIVER_TO_MOUSE_RF, got {target_role.value}"
            )
        self.session = session
        self.target_role = target_role

    @property
    def is_wireless(self) -> bool:
        return self.target_role == TargetRole.RECEIVER_TO_MOUSE_RF

    def ensure_rf_link(self) -> int:
        """Mandatory pre-flight 2.4G local 0x90 link check before any RF forwarding."""
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

    def _query_g5(self, name: str, frame: DeviceFrame) -> ParsedReply:
        _, parsed = self.session.query(self.target_role, frame.data)
        if not parsed.is_ok:
            raise Group5CommandError(
                f"Group 5 {name} failed: status={parsed.status_name} (0x{parsed.status:02X})",
                status_byte=parsed.status,
                status_name=parsed.status_name,
            )
        return parsed

    @property
    def _guard_allows_p3plus(self) -> bool:
        return bool(getattr(self.session.guard, "allow_phase3plus", False))

    @staticmethod
    def _validate_dry_run(
        role: TargetRole, frame: DeviceFrame, *, allow_phase3plus: bool = False
    ) -> None:
        WriteGuard(
            allow_writes=True,
            allow_group5=True,
            allow_phase3plus=allow_phase3plus,
        ).validate_outgoing_frame(role, frame.data)

    @staticmethod
    def _is_settled(state: dict[str, Any], *, pending_section: str | None) -> bool:
        if state.get("worker_queued"):
            return False
        if pending_section is not None and state.get(pending_section, {}).get("pending"):
            return False
        return True

    def get_state(self) -> dict[str, Any]:
        """Query Group 5 0x80 GET_STATE / capabilities / override status."""
        self.ensure_rf_link()
        parsed = self._query_g5(
            "0x80 GET_STATE",
            build_group5_get_state_frame(wireless=self.is_wireless),
        )
        return decode_group5_state(parsed.payload)

    def read_snapshot(self) -> dict[str, Any]:
        """Query Group 5 0x81 SNAP_READ (last PAW3950/mode snapshot)."""
        self.ensure_rf_link()
        parsed = self._query_g5(
            "0x81 SNAP_READ",
            build_group5_snap_read_frame(wireless=self.is_wireless),
        )
        return decode_group5_snapshot(parsed.payload)

    def trigger_snapshot(self, seq: int = 1, *, dry_run: bool = True) -> dict[str, Any]:
        """Trigger asynchronous Group 5 0x01 SNAP_TRIGGER (dry-run by default)."""
        frame = build_group5_snap_trigger_frame(seq, wireless=self.is_wireless)
        self._validate_dry_run(self.target_role, frame)
        self.ensure_rf_link()
        if dry_run:
            return {
                "target_role": self.target_role.value,
                "dry_run": True,
                "command": "snap_trigger",
                "seq": seq,
                "planned_frame_hex": frame.data.hex(),
            }
        parsed = self._query_g5("0x01 SNAP_TRIGGER", frame)
        return {
            "target_role": self.target_role.value,
            "dry_run": False,
            "command": "snap_trigger",
            "trigger": decode_group5_snapshot(parsed.payload),
        }

    def capture_snapshot(
        self,
        seq: int = 1,
        *,
        poll_attempts: int = 10,
        poll_interval_ms: int = 10,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Trigger 0x01 SNAP_TRIGGER and poll 0x81 SNAP_READ until ready or attempts exhausted."""
        trig_res = self.trigger_snapshot(seq, dry_run=dry_run)
        if dry_run:
            return trig_res
        snap: dict[str, Any] = {}
        for attempt in range(max(1, poll_attempts)):
            snap = self.read_snapshot()
            status = int(snap["status"])
            if status != 1 and (status == 3 or int(snap["seq_done"]) == seq):
                break
            if attempt + 1 < poll_attempts and poll_interval_ms > 0:
                time.sleep(poll_interval_ms / 1000.0)
        return {
            "target_role": self.target_role.value,
            "dry_run": False,
            "command": "snapshot",
            "trigger": trig_res["trigger"],
            "snapshot": snap,
            "completed": int(snap.get("status", 0)) == 2 and int(snap.get("seq_done", 0)) == seq,
        }

    def _write_state_op(
        self,
        *,
        command: str,
        frame: DeviceFrame,
        pending_section: str | None,
        wait_settle: bool = True,
        poll_attempts: int = 20,
        poll_interval_ms: int = 10,
        dry_run: bool = True,
        allow_phase3plus: bool = False,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._validate_dry_run(self.target_role, frame, allow_phase3plus=allow_phase3plus)
        self.ensure_rf_link()
        if dry_run:
            out: dict[str, Any] = {
                "target_role": self.target_role.value,
                "dry_run": True,
                "command": command,
                "planned_frame_hex": frame.data.hex(),
            }
            if extra:
                out.update(extra)
            return out

        parsed = self._query_g5(command, frame)
        ack_state = decode_group5_state(parsed.payload)
        state = ack_state
        if wait_settle and not self._is_settled(state, pending_section=pending_section):
            for attempt in range(max(1, poll_attempts)):
                state = self.get_state()
                if self._is_settled(state, pending_section=pending_section):
                    break
                if attempt + 1 < poll_attempts and poll_interval_ms > 0:
                    time.sleep(poll_interval_ms / 1000.0)

        out = {
            "target_role": self.target_role.value,
            "dry_run": False,
            "command": command,
            "ack_state": ack_state,
            "state": state,
            "settled": self._is_settled(state, pending_section=pending_section),
        }
        if extra:
            out.update(extra)
        return out

    def set_fps(
        self,
        mode: int | str,
        custom: tuple[int, int, int] | None = None,
        *,
        allow_p3plus: bool | None = None,
        dry_run: bool = True,
        poll_attempts: int = 20,
        poll_interval_ms: int = 10,
    ) -> dict[str, Any]:
        """Set Group 5 0x02 PAW3950 FPS preset (0..7 or 0..37 on Phase 3+) or custom (U, slow, fast)."""
        eff_p3p = self._guard_allows_p3plus if allow_p3plus is None else allow_p3plus
        frame = build_group5_set_fps_frame(
            mode,
            custom,
            allow_p3plus=eff_p3p,
            wireless=self.is_wireless,
        )
        return self._write_state_op(
            command="set_fps",
            frame=frame,
            pending_section="fps",
            poll_attempts=poll_attempts,
            poll_interval_ms=poll_interval_ms,
            dry_run=dry_run,
            allow_phase3plus=eff_p3p,
            extra={"mode": mode, "custom": list(custom) if custom is not None else None},
        )

    def set_downshift(
        self,
        enable: bool | int,
        *,
        dry_run: bool = True,
        poll_attempts: int = 20,
        poll_interval_ms: int = 10,
    ) -> dict[str, Any]:
        """Set Group 5 0x03 PAW3950 downshift suppress (0=stock, 1=disable downshift)."""
        frame = build_group5_set_downshift_frame(enable, wireless=self.is_wireless)
        return self._write_state_op(
            command="set_downshift",
            frame=frame,
            pending_section="downshift",
            poll_attempts=poll_attempts,
            poll_interval_ms=poll_interval_ms,
            dry_run=dry_run,
            extra={"enable": bool(int(enable) if not isinstance(enable, bool) else enable)},
        )

    def set_smoothing(
        self,
        enable: bool | int,
        *,
        dry_run: bool = True,
        poll_attempts: int = 20,
        poll_interval_ms: int = 10,
    ) -> dict[str, Any]:
        """Set Group 5 0x04 PAW3950 smoothing/ripple override (0=stock, 1=off)."""
        frame = build_group5_set_smoothing_frame(enable, wireless=self.is_wireless)
        return self._write_state_op(
            command="set_smoothing",
            frame=frame,
            pending_section="smoothing",
            poll_attempts=poll_attempts,
            poll_interval_ms=poll_interval_ms,
            dry_run=dry_run,
            extra={"enable": bool(int(enable) if not isinstance(enable, bool) else enable)},
        )

    def persist_ctrl(
        self,
        action: int | str,
        *,
        dry_run: bool = True,
        poll_attempts: int = 20,
        poll_interval_ms: int = 10,
    ) -> dict[str, Any]:
        """Invoke Group 5 0x05 PERSIST_CTRL (1='save', 2='reset', 3='async_save')."""
        frame = build_group5_persist_ctrl_frame(action, wireless=self.is_wireless)
        action_code = frame.data[6]
        return self._write_state_op(
            command="persist_ctrl",
            frame=frame,
            pending_section=None,
            wait_settle=(action_code in (1, 2)),
            poll_attempts=poll_attempts,
            poll_interval_ms=poll_interval_ms,
            dry_run=dry_run,
            extra={"action": action, "action_code": action_code},
        )

    def get_p3_state(self) -> dict[str, Any]:
        """Query Phase 3 Group 5 0x82 GET_P3_STATE control/phase/stationary state."""
        self.ensure_rf_link()
        parsed = self._query_g5(
            "0x82 GET_P3_STATE",
            build_group5_get_p3_state_frame(wireless=self.is_wireless),
        )
        return decode_group5_p3_state(parsed.payload)

    def get_p3_diag(self) -> dict[str, int]:
        """Query Phase 3 Group 5 0x83 GET_P3_DIAG (14 x u32 diagnostic counters)."""
        self.ensure_rf_link()
        parsed = self._query_g5(
            "0x83 GET_P3_DIAG",
            build_group5_get_p3_diag_frame(wireless=self.is_wireless),
        )
        return decode_group5_p3_diag(parsed.payload)

    def set_p3_ctrl(
        self,
        flags: int,
        *,
        period_us: int | None = None,
        lead_us: int | None = None,
        allow_p3plus: bool | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Update Phase 3/3+ Group 5 0x06 SET_P3_CTRL flags and optional plock timing."""
        eff_p3p = self._guard_allows_p3plus if allow_p3plus is None else allow_p3plus
        frame = build_group5_set_p3_ctrl_frame(
            flags,
            period_us=period_us,
            lead_us=lead_us,
            allow_p3plus=eff_p3p,
            wireless=self.is_wireless,
        )
        self._validate_dry_run(self.target_role, frame, allow_phase3plus=eff_p3p)
        self.ensure_rf_link()
        if dry_run:
            return {
                "target_role": self.target_role.value,
                "dry_run": True,
                "command": "set_p3_ctrl",
                "flags": flags,
                "period_us": period_us,
                "lead_us": lead_us,
                "planned_frame_hex": frame.data.hex(),
            }
        parsed = self._query_g5("0x06 SET_P3_CTRL", frame)
        out: dict[str, Any] = {
            "target_role": self.target_role.value,
            "dry_run": False,
            "command": "set_p3_ctrl",
            "state": decode_group5_p3_state(parsed.payload),
        }
        if eff_p3p and (flags & (P3_FLAG_FIX_A | P3_FLAG_MOUSE_ABS)):
            p1_st = self.get_p1_state()
            for _ in range(10):
                if not p1_st["fix_a_pend"]:
                    break
                time.sleep(0.01)
                p1_st = self.get_p1_state()
            out["p1_state"] = p1_st
        if eff_p3p and (flags & (P3_FLAG_EAGER_WAKE | P3_FLAG_CE_STATIC)):
            p2p3_st = self.get_p2p3_state()
            for _ in range(10):
                if not p2p3_st["ce_static_pend"]:
                    break
                time.sleep(0.01)
                p2p3_st = self.get_p2p3_state()
            out["p2p3_state"] = p2p3_st
        return out

    def patch_p3_ctrl(
        self,
        *,
        flags: int | None = None,
        atomic_accum: int | None = None,
        queue_guard: int | None = None,
        direct_motion: int | None = None,
        plock_enable: int | None = None,
        fix_a: int | None = None,
        mouse_abs: int | None = None,
        eager_wake: int | None = None,
        ce_static: int | None = None,
        period_us: int | None = None,
        lead_us: int | None = None,
        allow_p3plus: bool | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Set explicit Phase 3/3+ flags or overlay individual flag bits onto live 0x82 state."""
        bit_updates = (
            (P3_FLAG_ATOMIC_ACCUM, atomic_accum),
            (P3_FLAG_QUEUE_GUARD, queue_guard),
            (P3_FLAG_DIRECT_MOTION, direct_motion),
            (P3_FLAG_PLOCK_ENABLE, plock_enable),
            (P3_FLAG_FIX_A, fix_a),
            (P3_FLAG_MOUSE_ABS, mouse_abs),
            (P3_FLAG_EAGER_WAKE, eager_wake),
            (P3_FLAG_CE_STATIC, ce_static),
        )
        has_any_bit = any(v is not None for _, v in bit_updates)
        if flags is None and not has_any_bit and period_us is None and lead_us is None:
            raise FrameError("Specify flags or at least one Phase 3 control option")
        eff_flags = self.get_p3_state()["flags"] if flags is None else flags
        for bit, val in bit_updates:
            if val is not None:
                eff_flags = (eff_flags | bit) if val else (eff_flags & ~bit)
        return self.set_p3_ctrl(
            eff_flags,
            period_us=period_us,
            lead_us=lead_us,
            allow_p3plus=allow_p3plus,
            dry_run=dry_run,
        )

    def reset_p3_diag(self, *, dry_run: bool = True) -> dict[str, Any]:
        """Reset Phase 3 Group 5 0x07 RESET_P3_DIAG counters and plock_last_err."""
        frame = build_group5_reset_p3_diag_frame(wireless=self.is_wireless)
        self._validate_dry_run(self.target_role, frame)
        self.ensure_rf_link()
        if dry_run:
            return {
                "target_role": self.target_role.value,
                "dry_run": True,
                "command": "reset_p3_diag",
                "planned_frame_hex": frame.data.hex(),
            }
        parsed = self._query_g5("0x07 RESET_P3_DIAG", frame)
        return {
            "target_role": self.target_role.value,
            "dry_run": False,
            "command": "reset_p3_diag",
            "diag": decode_group5_p3_diag(parsed.payload),
        }

    def get_p1_state(self) -> dict[str, Any]:
        """Query Phase 3+ P1 Group 5 0x84 GET_P1_STATE (plock mode/learning, fix-a, ABS telemetry)."""
        self.ensure_rf_link()
        parsed = self._query_g5(
            "0x84 GET_P1_STATE",
            build_group5_get_p1_state_frame(wireless=self.is_wireless),
        )
        return decode_group5_p1_state(parsed.payload)

    def set_p1_cfg(
        self,
        mode: int | str = "entry",
        *,
        action_mask: int | None = None,
        reset_minmax: bool = False,
        clear_learned: bool = False,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Update Phase 3+ P1 Group 5 0x08 SET_P1_CFG (plock mode and/or reset actions)."""
        frame = build_group5_set_p1_cfg_frame(
            mode,
            action_mask=action_mask,
            reset_minmax=reset_minmax,
            clear_learned=clear_learned,
            wireless=self.is_wireless,
        )
        self._validate_dry_run(self.target_role, frame, allow_phase3plus=True)
        self.ensure_rf_link()
        if dry_run:
            return {
                "target_role": self.target_role.value,
                "dry_run": True,
                "command": "set_p1_cfg",
                "mode": mode,
                "reset_minmax": reset_minmax,
                "clear_learned": clear_learned,
                "planned_frame_hex": frame.data.hex(),
            }
        parsed = self._query_g5("0x08 SET_P1_CFG", frame)
        return {
            "target_role": self.target_role.value,
            "dry_run": False,
            "command": "set_p1_cfg",
            "state": decode_group5_p1_state(parsed.payload),
        }

    def get_p2p3_state(self) -> dict[str, Any]:
        """Query Phase 3+ Wave 2 Group 5 0x85 GET_P2P3_STATE (eager-wake/ce-static/lod-raw/anti-slam/peek)."""
        self.ensure_rf_link()
        parsed = self._query_g5(
            "0x85 GET_P2P3_STATE",
            build_group5_get_p2p3_state_frame(wireless=self.is_wireless),
        )
        return decode_group5_p2p3_state(parsed.payload)

    def set_lod_raw(
        self,
        enabled: bool | int,
        raw_val: int = 0,
        *,
        dry_run: bool = True,
        poll_attempts: int = 10,
        poll_interval_ms: int = 10,
    ) -> dict[str, Any]:
        """Set Phase 3+ Wave 2 Group 5 0x09 SET_LOD_RAW (`0x18:0x7A` override or stock revert)."""
        frame = build_group5_set_lod_raw_frame(enabled, raw_val, wireless=self.is_wireless)
        self._validate_dry_run(self.target_role, frame, allow_phase3plus=True)
        self.ensure_rf_link()
        if dry_run:
            return {
                "target_role": self.target_role.value,
                "dry_run": True,
                "command": "set_lod_raw",
                "enabled": bool(enabled),
                "raw_val": raw_val if enabled else 0,
                "planned_frame_hex": frame.data.hex(),
            }
        parsed = self._query_g5("0x09 SET_LOD_RAW", frame)
        state = decode_group5_p2p3_state(parsed.payload)
        for attempt in range(max(1, poll_attempts)):
            if not state["lod_raw_pend"]:
                break
            if attempt + 1 < poll_attempts and poll_interval_ms > 0:
                time.sleep(poll_interval_ms / 1000.0)
            state = self.get_p2p3_state()
        return {
            "target_role": self.target_role.value,
            "dry_run": False,
            "command": "set_lod_raw",
            "state": state,
        }

    def set_anti_slam(
        self,
        landing_lock_ms: int = ANTI_SLAM_LANDING_DEFAULT_MS,
        lifted_press_ms: int = ANTI_SLAM_LIFTED_DEFAULT_MS,
        *,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Set Phase 3+ Wave 2 Group 5 0x0A SET_ANTI_SLAM window (0..100 ms; stock defaults 16, 20)."""
        frame = build_group5_set_anti_slam_frame(
            landing_lock_ms, lifted_press_ms, wireless=self.is_wireless
        )
        self._validate_dry_run(self.target_role, frame, allow_phase3plus=True)
        self.ensure_rf_link()
        if dry_run:
            return {
                "target_role": self.target_role.value,
                "dry_run": True,
                "command": "set_anti_slam",
                "landing_lock_ms": landing_lock_ms,
                "lifted_press_ms": lifted_press_ms,
                "planned_frame_hex": frame.data.hex(),
            }
        parsed = self._query_g5("0x0A SET_ANTI_SLAM", frame)
        return {
            "target_role": self.target_role.value,
            "dry_run": False,
            "command": "set_anti_slam",
            "state": decode_group5_p2p3_state(parsed.payload),
        }

    def read_sensor_reg(
        self,
        bank: int,
        reg: int,
        *,
        dry_run: bool = True,
        poll_attempts: int = 10,
        poll_interval_ms: int = 10,
    ) -> dict[str, Any]:
        """Trigger Phase 3+ Wave 2 Group 5 0x0B READ_REG (cooperative SPI peek restoring 0x7F=0)."""
        frame = build_group5_read_reg_frame(bank, reg, wireless=self.is_wireless)
        self._validate_dry_run(self.target_role, frame, allow_phase3plus=True)
        self.ensure_rf_link()
        if dry_run:
            return {
                "target_role": self.target_role.value,
                "dry_run": True,
                "command": "read_reg",
                "bank": bank,
                "reg": reg,
                "planned_frame_hex": frame.data.hex(),
            }
        parsed = self._query_g5("0x0B READ_REG", frame)
        state = decode_group5_p2p3_state(parsed.payload)
        for attempt in range(max(1, poll_attempts)):
            if not state["peek_pending"]:
                break
            if attempt + 1 < poll_attempts and poll_interval_ms > 0:
                time.sleep(poll_interval_ms / 1000.0)
            state = self.get_p2p3_state()
        return {
            "target_role": self.target_role.value,
            "dry_run": False,
            "command": "read_reg",
            "bank": state["peek_bank"],
            "reg": state["peek_reg"],
            "value": state["peek_val"],
            "value_hex": f"0x{state['peek_val']:02X}",
            "valid": state["peek_valid"],
            "error": state["peek_err"],
            "state": state,
        }
