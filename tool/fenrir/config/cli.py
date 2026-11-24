"""Command-line interface for Phase 1 configuration & safe macro management."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from fenrir.config.group5 import Group5CommandError, Group5Service
from fenrir.config.macro import SafeMacroManager
from fenrir.config.schema import MouseConfig, diff_configs, load_config, save_config, validate_config
from fenrir.config.service import ConfigService
from fenrir.constants import VENDOR_ID
from fenrir.probe.identity import MouseDisconnectedError
from fenrir.protocol.catalog import TargetRole
from fenrir.protocol.frames import FrameError
from fenrir.protocol.group5_frames import (
    ANTI_SLAM_LANDING_DEFAULT_MS,
    ANTI_SLAM_LIFTED_DEFAULT_MS,
    FPS_PRESETS_P3PLUS_SPECS,
    PHASE3PLUS_CAPS_MASK,
    PHASE3_CAPS_MASK,
    W2_CAPS_MASK,
    build_group5_get_p1_state_frame,
    build_group5_get_p2p3_state_frame,
    build_group5_get_p3_state_frame,
    build_group5_get_state_frame,
    build_group5_read_reg_frame,
    build_group5_set_anti_slam_frame,
    build_group5_set_fps_frame,
    build_group5_set_lod_raw_frame,
    build_group5_set_p1_cfg_frame,
    build_group5_set_p3_ctrl_frame,
    resolve_fps_mode,
)
from fenrir.safety.guard import ProbeLevel, ReadOnlyGuard, SafetyViolationError
from fenrir.safety.write_guard import WriteGuard
from fenrir.transport.capture import CaptureLogger
from fenrir.transport.hid_win import GuardedHidSession, HidApiTransport
from fenrir.transport.mock import (
    PHASE2_MOUSE_HEX_PATH,
    PHASE3PLUS_MOUSE_HEX_PATH,
    PHASE3_MOUSE_HEX_PATH,
    UnicornMockTransport,
)

_TARGET_MAP = {
    "mouse-usb": TargetRole.MOUSE_USB,
    "receiver-to-mouse": TargetRole.RECEIVER_TO_MOUSE_RF,
}


def _resolve_device_by_path(devices: list, path: str):
    for d in devices:
        if d.path == path:
            return d
    raise SystemExit(f"Device path not found in enumeration: {path}")


def _target_role_from_arg(target: str) -> TargetRole:
    return _TARGET_MAP[target]


def _cmd_export(args: argparse.Namespace) -> int:
    role = _target_role_from_arg(args.target)
    guard = ReadOnlyGuard(require_proofs=True)
    capture = CaptureLogger(f"cfg_export_{args.target}")
    try:
        with GuardedHidSession(HidApiTransport(), guard, capture) as session:
            dev = _resolve_device_by_path(session.enumerate(vid=int(args.vid, 0)), args.path)
            session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=role)
            cfg = ConfigService(session, role).read_config()
    except MouseDisconnectedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.output:
        out_path = save_config(cfg, args.output)
        print(f"Exported config to {out_path}")
    else:
        print(json.dumps(cfg.to_dict(), ensure_ascii=False, indent=2))
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    role = _target_role_from_arg(args.target)
    desired = load_config(args.input)
    validate_config(desired, wireless=(role == TargetRole.RECEIVER_TO_MOUSE_RF))
    guard = ReadOnlyGuard(require_proofs=True)
    capture = CaptureLogger(f"cfg_diff_{args.target}")
    try:
        with GuardedHidSession(HidApiTransport(), guard, capture) as session:
            dev = _resolve_device_by_path(session.enumerate(vid=int(args.vid, 0)), args.path)
            session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=role)
            current = ConfigService(session, role).read_config()
    except MouseDisconnectedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    diffs = diff_configs(current, desired, wireless=(role == TargetRole.RECEIVER_TO_MOUSE_RF))
    print(json.dumps({k: {"current": v[0], "desired": v[1]} for k, v in diffs.items()}, indent=2))
    return 0


def _cmd_apply(args: argparse.Namespace) -> int:
    role = _target_role_from_arg(args.target)
    desired = load_config(args.input)
    dry_run = bool(args.dry_run or not args.yes)
    guard = WriteGuard(allow_writes=not dry_run)
    capture = CaptureLogger(f"cfg_apply_{args.target}")
    try:
        with GuardedHidSession(HidApiTransport(), guard, capture) as session:
            dev = _resolve_device_by_path(session.enumerate(vid=int(args.vid, 0)), args.path)
            session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=role)
            report = ConfigService(session, role).apply_config(
                desired,
                dry_run=dry_run,
                verify_readback=not args.no_verify,
                settle_ms=args.settle_ms,
            )
    except MouseDisconnectedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if not dry_run:
        cap_path = capture.save()
        print(f"Capture saved: {cap_path}")
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    return 0 if report.success else 1


def _cmd_set(args: argparse.Namespace) -> int:
    role = _target_role_from_arg(args.target)
    dry_run = bool(args.dry_run or not args.yes)
    guard = WriteGuard(allow_writes=not dry_run)
    capture = CaptureLogger(f"cfg_set_{args.target}")
    try:
        with GuardedHidSession(HidApiTransport(), guard, capture) as session:
            dev = _resolve_device_by_path(session.enumerate(vid=int(args.vid, 0)), args.path)
            session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=role)
            svc = ConfigService(session, role)
            cfg = svc.read_config()
            if args.polling_rate is not None:
                cfg.polling_rate_code = args.polling_rate
            if args.dpi_slot is not None:
                cfg.dpi_active_slot = args.dpi_slot
            if args.lod is not None:
                cfg.lod = args.lod
            if args.angle is not None:
                cfg.angle_deg = args.angle
            if args.motionsync is not None:
                cfg.motionsync = bool(args.motionsync)
            if args.reg56 is not None:
                cfg.reg56 = bool(args.reg56)
            if args.sensor_mode is not None:
                cfg.sensor_mode_hp = bool(args.sensor_mode)
            if args.sleep_sec is not None:
                cfg.sleep_sec = args.sleep_sec
            if args.debounce is not None:
                cfg.debounce_ms = tuple(args.debounce)
            if args.rgb is not None:
                cfg.rgb_enabled = bool(args.rgb[0])
                cfg.rgb_effect_mode = int(args.rgb[1])

            report = svc.apply_config(
                cfg,
                dry_run=dry_run,
                verify_readback=not args.no_verify,
                settle_ms=args.settle_ms,
            )
    except MouseDisconnectedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if not dry_run:
        cap_path = capture.save()
        print(f"Capture saved: {cap_path}")
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    return 0 if report.success else 1


def _cmd_macro_list(args: argparse.Namespace) -> int:
    role = _target_role_from_arg(args.target)
    guard = ReadOnlyGuard(require_proofs=True)
    try:
        with GuardedHidSession(HidApiTransport(), guard, CaptureLogger("cfg_macro_list")) as session:
            dev = _resolve_device_by_path(session.enumerate(vid=int(args.vid, 0)), args.path)
            session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=role)
            entries = SafeMacroManager(session, role).list_macros()
    except MouseDisconnectedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps([{"id": e.obj_id_hex, "size": e.size} for e in entries], indent=2))
    return 0


def _cmd_macro_free(args: argparse.Namespace) -> int:
    role = _target_role_from_arg(args.target)
    guard = ReadOnlyGuard(require_proofs=True)
    try:
        with GuardedHidSession(HidApiTransport(), guard, CaptureLogger("cfg_macro_free")) as session:
            dev = _resolve_device_by_path(session.enumerate(vid=int(args.vid, 0)), args.path)
            session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=role)
            free = SafeMacroManager(session, role).get_free_space()
    except MouseDisconnectedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"total_bytes": free.total_bytes, "free_bytes": free.free_bytes}, indent=2))
    return 0


def _cmd_macro_upload(args: argparse.Namespace) -> int:
    role = _target_role_from_arg(args.target)
    obj_id = int(args.id, 0)
    data = Path(args.file).read_bytes() if args.file else bytes.fromhex(args.hex)
    dry_run = bool(args.dry_run or not args.yes)
    guard = WriteGuard(allow_writes=not dry_run)
    capture = CaptureLogger(f"cfg_macro_upload_{args.target}")
    try:
        with GuardedHidSession(HidApiTransport(), guard, capture) as session:
            dev = _resolve_device_by_path(session.enumerate(vid=int(args.vid, 0)), args.path)
            session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=role)
            res = SafeMacroManager(session, role).upload_macro(
                obj_id, data, verify_readback=not args.no_verify, dry_run=dry_run
            )
    except MouseDisconnectedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if not dry_run:
        cap_path = capture.save()
        res["capture_file"] = str(cap_path)
    print(json.dumps(res, indent=2))
    return 0


def _cmd_macro_delete(args: argparse.Namespace) -> int:
    role = _target_role_from_arg(args.target)
    obj_id = int(args.id, 0)
    dry_run = bool(args.dry_run or not args.yes)
    guard = WriteGuard(allow_writes=not dry_run)
    capture = CaptureLogger(f"cfg_macro_delete_{args.target}")
    try:
        with GuardedHidSession(HidApiTransport(), guard, capture) as session:
            dev = _resolve_device_by_path(session.enumerate(vid=int(args.vid, 0)), args.path)
            session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=role)
            res = SafeMacroManager(session, role).delete_macro(obj_id, dry_run=dry_run)
    except MouseDisconnectedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if not dry_run:
        cap_path = capture.save()
        res["capture_file"] = str(cap_path)
    print(json.dumps(res, indent=2))
    return 0


def _run_selftest_role(
    transport: UnicornMockTransport,
    guard: WriteGuard,
    role: TargetRole,
    path: str,
) -> dict[str, object]:
    with GuardedHidSession(transport, guard, CaptureLogger(f"selftest_{role.value}")) as session:
        dev = _resolve_device_by_path(session.enumerate(vid=VENDOR_ID), path)
        session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=role)
        svc = ConfigService(session, role)
        desired = svc.read_config()
        desired.polling_rate_code = 128 if role == TargetRole.RECEIVER_TO_MOUSE_RF else 8
        desired.debounce_ms = (6, 12, 30, 20)
        desired.lod = 7
        desired.motionsync = False
        desired.reg56 = True
        desired.angle_deg = -10
        desired.rgb_enabled = True
        desired.rgb_effect_mode = 1
        desired.sleep_sec = 120

        dry_rep = svc.apply_config(desired, dry_run=True)
        assert dry_rep.dry_run and len(dry_rep.planned_frames) >= 9

        rep = svc.apply_config(desired, dry_run=False, verify_readback=True, settle_ms=0)
        if not rep.success:
            raise RuntimeError(f"Config apply/verify failed for {role.value}: {rep.mismatches}")

        macros = SafeMacroManager(session, role)
        sample_macro = bytes.fromhex("0101200a010000") * 9  # 63B -> 2 chunks (52B + 11B)
        up = macros.upload_macro(0x0102, sample_macro, verify_readback=True)
        assert up["verified"] is True and up["chunk_count"] == 2
        listed = macros.list_macros()
        assert any(e.obj_id == 0x0102 and e.size == len(sample_macro) for e in listed)
        deleted = macros.delete_macro(0x0102)
        assert deleted["deleted"] is True
        assert not any(e.obj_id == 0x0102 for e in macros.list_macros())

    return {
        "target_role": role.value,
        "changed_fields": rep.changed_fields,
        "steps": len(rep.steps),
        "verified_clean": rep.success,
        "macro_roundtrip": True,
    }


def _cmd_selftest(args: argparse.Namespace) -> int:
    guard = WriteGuard(allow_writes=True)
    results = []
    for role, path in (
        (TargetRole.MOUSE_USB, UnicornMockTransport.MOUSE_PATH),
        (TargetRole.RECEIVER_TO_MOUSE_RF, UnicornMockTransport.RX_USB_PATH),
    ):
        transport = UnicornMockTransport(
            sensor_id=args.sensor_id,
            simulate_pending_polls=1,
            mouse_connected=True,
            stateful=True,
        )
        results.append(_run_selftest_role(transport, guard, role, path))
    print(json.dumps({"selftest": "PASS", "targets": results}, indent=2))
    return 0


def _run_group5_cli_op(
    args: argparse.Namespace,
    *,
    op_name: str,
    allow_writes: bool,
    save_capture: bool,
    action,
    allow_phase3plus: bool = False,
) -> int:
    role = _target_role_from_arg(args.target)
    guard = WriteGuard(
        allow_writes=allow_writes,
        allow_group5=True,
        allow_phase3plus=allow_phase3plus,
    )
    capture = CaptureLogger(f"cfg_adv_{op_name}_{args.target}")
    try:
        with GuardedHidSession(HidApiTransport(), guard, capture) as session:
            dev = _resolve_device_by_path(session.enumerate(vid=int(args.vid, 0)), args.path)
            session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=role)
            res = action(Group5Service(session, role))
    except (MouseDisconnectedError, Group5CommandError, FrameError, SafetyViolationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if save_capture and isinstance(res, dict):
        res["capture_file"] = str(capture.save())
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def _cmd_adv_status(args: argparse.Namespace) -> int:
    return _run_group5_cli_op(
        args,
        op_name="status",
        allow_writes=False,
        save_capture=False,
        action=lambda svc: svc.get_state(),
    )


def _cmd_adv_snapshot_read(args: argparse.Namespace) -> int:
    return _run_group5_cli_op(
        args,
        op_name="snapshot_read",
        allow_writes=False,
        save_capture=False,
        action=lambda svc: svc.read_snapshot(),
    )


def _cmd_adv_snapshot(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    return _run_group5_cli_op(
        args,
        op_name="snapshot",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        action=lambda svc: svc.capture_snapshot(
            seq=args.seq,
            poll_attempts=args.poll_attempts,
            dry_run=dry_run,
        ),
    )


def _cmd_adv_fps(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    custom = tuple(args.custom) if args.custom is not None else None
    allow_p3p = False
    try:
        code = resolve_fps_mode(args.preset, allow_p3plus=True)
        allow_p3p = 8 <= code < 255
    except FrameError:
        pass
    return _run_group5_cli_op(
        args,
        op_name="fps",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        allow_phase3plus=allow_p3p,
        action=lambda svc: svc.set_fps(args.preset, custom, allow_p3plus=allow_p3p, dry_run=dry_run),
    )


def _cmd_adv_fps_presets(_args: argparse.Namespace) -> int:
    presets = [
        {"code": code, "name": name, "reg_07_42_u": u, "reg_06_53_slow": slow, "reg_06_62_fast": fast}
        for code, name, u, slow, fast in FPS_PRESETS_P3PLUS_SPECS
    ]
    print(json.dumps({"count": len(presets), "custom_code": 255, "presets": presets}, indent=2))
    return 0


def _cmd_adv_downshift(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    return _run_group5_cli_op(
        args,
        op_name="downshift",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        action=lambda svc: svc.set_downshift(args.enable_val, dry_run=dry_run),
    )


def _cmd_adv_smoothing(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    return _run_group5_cli_op(
        args,
        op_name="smoothing",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        action=lambda svc: svc.set_smoothing(args.enable_val, dry_run=dry_run),
    )


def _cmd_adv_persist(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    return _run_group5_cli_op(
        args,
        op_name="persist",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        action=lambda svc: svc.persist_ctrl(args.action, dry_run=dry_run),
    )


def _cmd_adv_p3_state(args: argparse.Namespace) -> int:
    return _run_group5_cli_op(
        args,
        op_name="p3_state",
        allow_writes=False,
        save_capture=False,
        action=lambda svc: svc.get_p3_state(),
    )


def _cmd_adv_p3_diag(args: argparse.Namespace) -> int:
    return _run_group5_cli_op(
        args,
        op_name="p3_diag",
        allow_writes=False,
        save_capture=False,
        action=lambda svc: svc.get_p3_diag(),
    )


def _cmd_adv_p3_ctrl(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    parsed_flags: int | None = None
    if args.flags is not None:
        try:
            parsed_flags = int(args.flags, 0)
        except ValueError:
            parsed_flags = None
    allow_p3p = bool(
        args.fix_a is not None
        or args.mouse_abs is not None
        or args.eager_wake is not None
        or args.ce_static is not None
        or (parsed_flags is not None and (parsed_flags & ~0x0F) != 0)
    )

    def _apply_ctrl(svc: Group5Service) -> dict[str, object]:
        flags: int | None = None
        if args.flags is not None:
            try:
                flags = int(args.flags, 0)
            except ValueError as exc:
                raise FrameError(f"Invalid --flags value: {args.flags!r}") from exc
        return svc.patch_p3_ctrl(
            flags=flags,
            atomic_accum=args.atomic_accum,
            queue_guard=args.queue_guard,
            direct_motion=args.direct_motion,
            plock_enable=args.plock,
            fix_a=args.fix_a,
            mouse_abs=args.mouse_abs,
            eager_wake=args.eager_wake,
            ce_static=args.ce_static,
            period_us=args.period_us,
            lead_us=args.lead_us,
            allow_p3plus=allow_p3p,
            dry_run=dry_run,
        )

    return _run_group5_cli_op(
        args,
        op_name="p3_ctrl",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        allow_phase3plus=allow_p3p,
        action=_apply_ctrl,
    )


def _cmd_adv_fix_a(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    return _run_group5_cli_op(
        args,
        op_name="fix_a",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        allow_phase3plus=True,
        action=lambda svc: svc.patch_p3_ctrl(fix_a=args.enable_val, allow_p3plus=True, dry_run=dry_run),
    )


def _cmd_adv_mouse_abs(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    return _run_group5_cli_op(
        args,
        op_name="mouse_abs",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        allow_phase3plus=True,
        action=lambda svc: svc.patch_p3_ctrl(mouse_abs=args.enable_val, allow_p3plus=True, dry_run=dry_run),
    )


def _cmd_adv_p1_state(args: argparse.Namespace) -> int:
    return _run_group5_cli_op(
        args,
        op_name="p1_state",
        allow_writes=False,
        save_capture=False,
        allow_phase3plus=True,
        action=lambda svc: svc.get_p1_state(),
    )


def _cmd_adv_p1_cfg(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)

    def _apply_p1(svc: Group5Service) -> dict[str, object]:
        action_mask: int | None = None
        if args.action_mask is not None:
            try:
                action_mask = int(args.action_mask, 0)
            except ValueError as exc:
                raise FrameError(f"Invalid --action-mask value: {args.action_mask!r}") from exc
        if args.mode is None and not args.reset_minmax and not args.clear_learned and action_mask is None:
            raise FrameError("Specify --mode or at least one action (--reset-minmax / --clear-learned)")
        mode_val = "keep" if args.mode is None else args.mode
        return svc.set_p1_cfg(
            mode_val,
            action_mask=action_mask,
            reset_minmax=args.reset_minmax,
            clear_learned=args.clear_learned,
            dry_run=dry_run,
        )

    return _run_group5_cli_op(
        args,
        op_name="p1_cfg",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        allow_phase3plus=True,
        action=_apply_p1,
    )


def _cmd_adv_p2p3_state(args: argparse.Namespace) -> int:
    return _run_group5_cli_op(
        args,
        op_name="p2p3_state",
        allow_writes=False,
        save_capture=False,
        allow_phase3plus=True,
        action=lambda svc: svc.get_p2p3_state(),
    )


def _cmd_adv_eager_wake(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    return _run_group5_cli_op(
        args,
        op_name="eager_wake",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        allow_phase3plus=True,
        action=lambda svc: svc.patch_p3_ctrl(
            eager_wake=args.enable_val, allow_p3plus=True, dry_run=dry_run
        ),
    )


def _cmd_adv_ce_static(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    return _run_group5_cli_op(
        args,
        op_name="ce_static",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        allow_phase3plus=True,
        action=lambda svc: svc.patch_p3_ctrl(
            ce_static=args.enable_val, allow_p3plus=True, dry_run=dry_run
        ),
    )


def _parse_int_opt(val: str, label: str) -> int:
    try:
        return int(val, 0)
    except ValueError as exc:
        raise FrameError(f"Invalid {label} value: {val!r}") from exc


def _cmd_adv_lod_raw(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)

    def _apply_lod(svc: Group5Service) -> dict[str, object]:
        if args.enable_val == 0:
            return svc.set_lod_raw(False, 0, dry_run=dry_run)
        if args.raw is None:
            raise FrameError("--raw VALUE is required when enabling lod-raw")
        raw_val = _parse_int_opt(args.raw, "--raw")
        return svc.set_lod_raw(True, raw_val, dry_run=dry_run)

    return _run_group5_cli_op(
        args,
        op_name="lod_raw",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        allow_phase3plus=True,
        action=_apply_lod,
    )


def _cmd_adv_anti_slam(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    return _run_group5_cli_op(
        args,
        op_name="anti_slam",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        allow_phase3plus=True,
        action=lambda svc: svc.set_anti_slam(
            args.landing_ms, args.lifted_ms, dry_run=dry_run
        ),
    )


def _cmd_adv_reg_read(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)

    def _apply_peek(svc: Group5Service) -> dict[str, object]:
        bank = _parse_int_opt(args.bank, "--bank")
        reg = _parse_int_opt(args.reg, "--reg")
        return svc.read_sensor_reg(bank, reg, dry_run=dry_run)

    return _run_group5_cli_op(
        args,
        op_name="reg_read",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        allow_phase3plus=True,
        action=_apply_peek,
    )


def _cmd_adv_p3_diag_reset(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    return _run_group5_cli_op(
        args,
        op_name="p3_diag_reset",
        allow_writes=not dry_run,
        save_capture=not dry_run,
        action=lambda svc: svc.reset_p3_diag(dry_run=dry_run),
    )


def _run_adv_selftest_role(
    hex_path: str | Path,
    role: TargetRole,
    path: str,
) -> dict[str, object]:
    transport = UnicornMockTransport(
        sensor_id=0x53,
        simulate_pending_polls=1,
        mouse_connected=True,
        mouse_hex_path=hex_path,
    )
    guard = WriteGuard(allow_writes=True, allow_group5=True, allow_phase3plus=True)
    with GuardedHidSession(transport, guard, CaptureLogger(f"adv_selftest_{role.value}")) as session:
        dev = _resolve_device_by_path(session.enumerate(vid=VENDOR_ID), path)
        session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=role)
        svc = Group5Service(session, role)

        init_state = svc.get_state()
        assert init_state["magic"] == "FNR2" and init_state["is_id53"] is True
        has_p3 = (int(init_state["caps_flags"]) & PHASE3_CAPS_MASK) == PHASE3_CAPS_MASK
        has_p3p = (int(init_state["caps_flags"]) & PHASE3PLUS_CAPS_MASK) == PHASE3PLUS_CAPS_MASK

        dry = svc.set_fps("10k", dry_run=True)
        assert dry["dry_run"] is True

        snap = svc.capture_snapshot(seq=7, poll_attempts=5, poll_interval_ms=0, dry_run=False)
        assert snap["completed"] is True and snap["snapshot"]["seq_done"] == 7
        assert len(snap["snapshot"]["registers"]) == 8

        fps_res = svc.set_fps("10k", dry_run=False, poll_interval_ms=0)
        assert fps_res["state"]["fps"]["applied_name"] == "10k"
        assert fps_res["state"]["fps"]["readback_ok"] is True

        if has_p3p:
            assert init_state["fps_preset_count"] == 38
            p3p_fps = svc.set_fps("13.3k-b", allow_p3plus=True, dry_run=False, poll_interval_ms=0)
            assert p3p_fps["state"]["fps"]["applied"] == 37
            assert p3p_fps["state"]["fps"]["applied_name"] == "13.3k-b"
            assert p3p_fps["state"]["fps"]["readback_ok"] is True

        custom_res = svc.set_fps("custom", (4, 8, 4), dry_run=False, poll_interval_ms=0)
        assert custom_res["state"]["fps"]["applied"] == 255
        assert custom_res["state"]["fps"]["readback_ok"] is True

        ds_res = svc.set_downshift(1, dry_run=False, poll_interval_ms=0)
        assert ds_res["state"]["downshift"]["applied"] is True
        assert ds_res["state"]["downshift"]["readback_ok"] is True

        sm_res = svc.set_smoothing(1, dry_run=False, poll_interval_ms=0)
        assert sm_res["state"]["smoothing"]["applied"] is True
        assert sm_res["state"]["smoothing"]["readback_ok"] is True

        has_w2 = False
        if has_p3:
            p3_init = svc.get_p3_state()
            assert p3_init["magic"] == "FRP3" and p3_init["flags"] == 0x03
            p3_diag = svc.get_p3_diag()
            assert len(p3_diag) == 14
            if has_p3p:
                p2p3_init = svc.get_p2p3_state()
                has_w2 = (p2p3_init["w2_caps"] & W2_CAPS_MASK) == W2_CAPS_MASK
            ctrl_flags = 0xFF if has_w2 else (0x3F if has_p3p else 0x0F)
            p3_set = svc.set_p3_ctrl(
                ctrl_flags, period_us=200, lead_us=25, allow_p3plus=has_p3p, dry_run=False
            )
            assert p3_set["state"]["flags"] == ctrl_flags and p3_set["state"]["plock_period_us"] == 200
            p3_rst = svc.reset_p3_diag(dry_run=False)
            assert len(p3_rst["diag"]) == 14 and all(v == 0 for v in p3_rst["diag"].values())
            if has_p3p:
                p1_chk = svc.get_p1_state()
                assert p1_chk["fix_a_rb_ok"] is True and p1_chk["fix_a_rb_val"] == 0x0257
                assert p1_chk["mouse_abs_enabled"] is True
                p1_meas = svc.set_p1_cfg("measure", dry_run=False)
                assert p1_meas["state"]["plock_mode_name"] == "measure"
                p1_lrn = svc.set_p1_cfg("learn", dry_run=False)
                assert p1_lrn["state"]["plock_learn_pend"] is True
                p1_clr = svc.set_p1_cfg("keep", reset_minmax=True, clear_learned=True, dry_run=False)
                assert p1_clr["state"]["plock_err_min"] == 127 and p1_clr["state"]["plock_err_max"] == -128
                assert p1_clr["state"]["plock_learn_pend"] is False
            if has_w2:
                assert p2p3_init["anti_slam_landing_ms"] == 16 and p2p3_init["anti_slam_lifted_ms"] == 20
                as_res = svc.set_anti_slam(24, 30, dry_run=False)
                assert as_res["state"]["anti_slam_landing_ms"] == 24 and as_res["state"]["anti_slam_lifted_ms"] == 30
                lod_res = svc.set_lod_raw(True, 0x42, dry_run=False)
                assert lod_res["state"]["lod_raw_rb_ok"] is True and lod_res["state"]["lod_raw_rb_val"] == 0x42
                peek_id = svc.read_sensor_reg(0x00, 0x00, dry_run=False)
                assert peek_id["valid"] is True and peek_id["value"] == 0x51
                peek_lod = svc.read_sensor_reg(0x18, 0x7A, dry_run=False)
                assert peek_lod["valid"] is True and peek_lod["value"] == 0x42

        save_res = svc.persist_ctrl("save", dry_run=False, poll_interval_ms=0)
        assert save_res["state"]["persistence"]["valid"] is True

    # Simulate reboot (wipe RAM & sensor, keep Flash) and confirm saved overrides survive H4 startup_hook.
    transport.soft_reset()
    with GuardedHidSession(transport, guard, CaptureLogger(f"adv_selftest_reboot_{role.value}")) as session:
        dev = _resolve_device_by_path(session.enumerate(vid=VENDOR_ID), path)
        session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=role)
        svc = Group5Service(session, role)
        reboot_state = svc.get_state()
        assert reboot_state["persistence"]["valid"] is True
        assert reboot_state["fps"]["requested"] == 255
        assert reboot_state["downshift"]["requested"] is True
        assert reboot_state["smoothing"]["requested"] is True

        p3_reboot_ok = None
        if has_p3:
            p3_reboot = svc.get_p3_state()
            assert p3_reboot["magic"] == "FRP3"
            assert p3_reboot["flags"] == (0xFF if has_w2 else (0x3F if has_p3p else 0x0F))
            assert p3_reboot["plock_period_us"] == 200
            assert p3_reboot["plock_lead_us"] == 25
            p3_reboot_ok = True
            if has_p3p:
                p1_rb = svc.get_p1_state()
                assert p1_rb["fix_a_enabled"] is True and p1_rb["fix_a_req"] is True
                assert p1_rb["fix_a_pend"] is True or p1_rb["fix_a_rb_val"] == 0x0257
                assert p1_rb["mouse_abs_enabled"] is True
            if has_w2:
                w2_rb = svc.get_p2p3_state()
                assert w2_rb["eager_wake_enabled"] is True and w2_rb["ce_static_enabled"] is True
                assert w2_rb["lod_raw_en"] is True and w2_rb["lod_raw_val"] == 0x42
                assert w2_rb["anti_slam_landing_ms"] == 24 and w2_rb["anti_slam_lifted_ms"] == 30

        reset_res = svc.persist_ctrl("reset", dry_run=False, poll_interval_ms=0)
        assert reset_res["state"]["persistence"]["valid"] is False
        assert reset_res["state"]["fps"]["requested"] == 0

    out: dict[str, object] = {
        "target_role": role.value,
        "snapshot_seq_done": snap["snapshot"]["seq_done"],
        "fps_readback_ok": fps_res["state"]["fps"]["readback_ok"],
        "custom_readback_ok": custom_res["state"]["fps"]["readback_ok"],
        "reboot_persistence_ok": reboot_state["persistence"]["valid"],
        "reset_cleared": reset_res["state"]["persistence"]["valid"] is False,
    }
    if has_p3:
        out["p3_caps"] = True
        out["p3_reboot_persistence_ok"] = p3_reboot_ok
    if has_p3p:
        out["p3p_caps"] = True
        out["p3p_38_presets"] = True
        out["p3p_fix_a_rb_val"] = "0x0257"
    if has_w2:
        out["w2_caps"] = True
        out["w2_anti_slam_reboot"] = [24, 30]
        out["w2_lod_raw_reboot"] = "0x42"
    return out


def _cmd_adv_selftest(args: argparse.Namespace) -> int:
    # 1. Fail-closed guard checks: WriteGuard(allow_group5=False) must reject Phase 2/3/3+ Group 5.
    default_guard = WriteGuard(allow_writes=True)
    for role, wireless in ((TargetRole.MOUSE_USB, False), (TargetRole.RECEIVER_TO_MOUSE_RF, True)):
        for frame in (
            build_group5_get_state_frame(wireless=wireless).data,
            build_group5_get_p3_state_frame(wireless=wireless).data,
            build_group5_get_p1_state_frame(wireless=wireless).data,
            build_group5_get_p2p3_state_frame(wireless=wireless).data,
            build_group5_set_p3_ctrl_frame(0xFF, period_us=200, lead_us=25, allow_p3plus=True, wireless=wireless).data,
            build_group5_set_p1_cfg_frame("learn", wireless=wireless).data,
            build_group5_set_lod_raw_frame(True, 0x42, wireless=wireless).data,
            build_group5_set_anti_slam_frame(24, 30, wireless=wireless).data,
            build_group5_read_reg_frame(0x00, 0x00, wireless=wireless).data,
        ):
            try:
                default_guard.validate_outgoing_frame(role, frame)
            except SafetyViolationError:
                pass
            else:
                raise AssertionError(f"Expected fail-closed SafetyViolationError for {role.value}")
    ro_g5_guard = WriteGuard(allow_writes=False, allow_group5=True, allow_phase3plus=True)
    for wframe in (
        build_group5_set_fps_frame("10k").data,
        build_group5_set_p3_ctrl_frame(0x0F).data,
        build_group5_set_p1_cfg_frame("measure").data,
        build_group5_set_lod_raw_frame(True, 0x42).data,
        build_group5_set_anti_slam_frame(24, 30).data,
        build_group5_read_reg_frame(0x00, 0x00).data,
    ):
        try:
            ro_g5_guard.validate_outgoing_frame(TargetRole.MOUSE_USB, wframe)
        except SafetyViolationError:
            pass
        else:
            raise AssertionError("Expected WriteGuard(allow_writes=False) to block Group 5 writes")

    profile = getattr(args, "profile", "both")
    if args.mouse_hex:
        hex_path: str | Path = args.mouse_hex
    elif profile == "phase3":
        hex_path = PHASE3_MOUSE_HEX_PATH
    elif profile == "phase3plus":
        hex_path = PHASE3PLUS_MOUSE_HEX_PATH
    else:
        hex_path = PHASE2_MOUSE_HEX_PATH

    results = [
        _run_adv_selftest_role(hex_path, TargetRole.MOUSE_USB, UnicornMockTransport.MOUSE_PATH),
        _run_adv_selftest_role(hex_path, TargetRole.RECEIVER_TO_MOUSE_RF, UnicornMockTransport.RX_USB_PATH),
    ]

    # 2. Verify non-ID53 isolation: ID4F sensor rejects 0x02 SET_FPS with 0xA2 while 0x80 GET_STATE works.
    id4f_transport = UnicornMockTransport(sensor_id=0x4F, mouse_hex_path=hex_path)
    g5_guard = WriteGuard(allow_writes=True, allow_group5=True, allow_phase3plus=True)
    with GuardedHidSession(id4f_transport, g5_guard, CaptureLogger("adv_selftest_id4f")) as session:
        dev = _resolve_device_by_path(session.enumerate(vid=VENDOR_ID), UnicornMockTransport.MOUSE_PATH)
        session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=TargetRole.MOUSE_USB)
        svc = Group5Service(session, TargetRole.MOUSE_USB)
        st4f = svc.get_state()
        assert st4f["is_id53"] is False
        try:
            svc.set_fps("10k", dry_run=False)
        except Group5CommandError as exc:
            assert exc.status_byte == 0xA2
        else:
            raise AssertionError("Expected ID4F mouse to reject Group 5 0x02 SET_FPS with 0xA2")
        if (int(st4f["caps_flags"]) & PHASE3PLUS_CAPS_MASK) == PHASE3PLUS_CAPS_MASK:
            for bad_id4f in (
                lambda: svc.patch_p3_ctrl(fix_a=1, allow_p3plus=True, dry_run=False),
                lambda: svc.patch_p3_ctrl(ce_static=1, allow_p3plus=True, dry_run=False),
                lambda: svc.set_lod_raw(True, 0x42, dry_run=False),
            ):
                try:
                    bad_id4f()
                except Group5CommandError as exc:
                    assert exc.status_byte == 0xA2
                else:
                    raise AssertionError("Expected ID4F mouse to reject ID53-only Wave 1/2 op with 0xA2")

    # 3. Verify wireless 0x90 pre-flight rejects disconnected mouse before forwarding Group 5.
    disc_transport = UnicornMockTransport(mouse_connected=False, mouse_hex_path=hex_path)
    with GuardedHidSession(disc_transport, g5_guard, CaptureLogger("adv_selftest_disc")) as session:
        dev = _resolve_device_by_path(session.enumerate(vid=VENDOR_ID), UnicornMockTransport.RX_USB_PATH)
        session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=TargetRole.RECEIVER_TO_MOUSE_RF)
        try:
            Group5Service(session, TargetRole.RECEIVER_TO_MOUSE_RF).get_state()
        except MouseDisconnectedError:
            pass
        else:
            raise AssertionError("Expected MouseDisconnectedError on wireless 0x90 pre-flight")

    out_payload: dict[str, object] = {
        "adv_selftest": "PASS",
        "fail_closed_guard": True,
        "id4f_rejected_0xa2": True,
        "wireless_preflight_0x90": True,
        "targets": results,
    }
    if not args.mouse_hex and profile == "both" and PHASE3_MOUSE_HEX_PATH.exists():
        p3_results = [
            _run_adv_selftest_role(PHASE3_MOUSE_HEX_PATH, TargetRole.MOUSE_USB, UnicornMockTransport.MOUSE_PATH),
            _run_adv_selftest_role(
                PHASE3_MOUSE_HEX_PATH, TargetRole.RECEIVER_TO_MOUSE_RF, UnicornMockTransport.RX_USB_PATH
            ),
        ]
        out_payload["phase3"] = {
            "tested": True,
            "hex": PHASE3_MOUSE_HEX_PATH.name,
            "targets": p3_results,
        }
    if not args.mouse_hex and profile == "both" and PHASE3PLUS_MOUSE_HEX_PATH.exists():
        p3p_results = [
            _run_adv_selftest_role(PHASE3PLUS_MOUSE_HEX_PATH, TargetRole.MOUSE_USB, UnicornMockTransport.MOUSE_PATH),
            _run_adv_selftest_role(
                PHASE3PLUS_MOUSE_HEX_PATH, TargetRole.RECEIVER_TO_MOUSE_RF, UnicornMockTransport.RX_USB_PATH
            ),
        ]
        out_payload["phase3plus"] = {
            "tested": True,
            "hex": PHASE3PLUS_MOUSE_HEX_PATH.name,
            "targets": p3p_results,
        }

    print(json.dumps(out_payload, indent=2))
    return 0


def _add_common_target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--target", required=True, choices=["mouse-usb", "receiver-to-mouse"])
    p.add_argument("--path", required=True, help="Exact HID device path from L0 enumerate")
    p.add_argument("--vid", default=f"0x{VENDOR_ID:04X}", help="Vendor ID filter (default 0x33E4)")


def _add_write_safety_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--yes", action="store_true", help="Transmit writes (default is dry-run)")
    p.add_argument("--dry-run", action="store_true", help="Validate & plan without writing (default)")
    p.add_argument("--no-verify", action="store_true", help="Skip post-write readback verification")
    p.add_argument("--settle-ms", type=int, default=550, help="Post-write settle delay (default 550ms)")


def _add_adv_dry_yes_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--yes", action="store_true", help="Transmit writes (default is dry-run)")
    p.add_argument("--dry-run", action="store_true", help="Validate & plan without writing (default)")


def _add_adv_toggle_args(p: argparse.ArgumentParser, label: str) -> None:
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("--enable", action="store_const", const=1, dest="enable_val", help=f"Enable {label} override (1)")
    grp.add_argument("--disable", action="store_const", const=0, dest="enable_val", help=f"Restore stock {label} (0)")
    grp.add_argument("--value", type=int, choices=[0, 1], dest="enable_val", help=f"Explicit {label} value (0 or 1)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fenrir-cfg",
        description="Fenrir Phase 1/2 mouse configuration, safe macro & Group 5 CLI (defaults to dry-run).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    p_exp = sub.add_parser("export", help="Read current mouse configuration to JSON")
    _add_common_target_args(p_exp)
    p_exp.add_argument("--output", help="Optional JSON output file")
    p_exp.set_defaults(func=_cmd_export)

    p_diff = sub.add_parser("diff", help="Compare live mouse config against JSON file")
    _add_common_target_args(p_diff)
    p_diff.add_argument("--input", required=True, help="Input MouseConfig JSON file")
    p_diff.set_defaults(func=_cmd_diff)

    p_app = sub.add_parser("apply", help="Apply MouseConfig JSON (dry-run by default; pass --yes to write)")
    _add_common_target_args(p_app)
    p_app.add_argument("--input", required=True, help="Input MouseConfig JSON file")
    _add_write_safety_args(p_app)
    p_app.set_defaults(func=_cmd_apply)

    p_set = sub.add_parser("set", help="Set individual config fields (dry-run by default; pass --yes)")
    _add_common_target_args(p_set)
    _add_write_safety_args(p_set)
    p_set.add_argument("--polling-rate", type=lambda x: int(x, 0))
    p_set.add_argument("--dpi-slot", type=int)
    p_set.add_argument("--lod", type=int)
    p_set.add_argument("--angle", type=int)
    p_set.add_argument("--motionsync", type=int, choices=[0, 1])
    p_set.add_argument("--reg56", type=int, choices=[0, 1])
    p_set.add_argument("--sensor-mode", type=int, choices=[0, 1])
    p_set.add_argument("--sleep-sec", type=int)
    p_set.add_argument("--debounce", type=int, nargs=4, metavar=("PRESS", "REL", "LOCK_P", "LOCK_R"))
    p_set.add_argument("--rgb", type=int, nargs=2, metavar=("ENABLE", "MODE"))
    p_set.set_defaults(func=_cmd_set)

    p_mac = sub.add_parser("macro", help="Safe serialized macro object pool operations")
    mac_sub = p_mac.add_subparsers(dest="macro_cmd", required=True)

    p_ml = mac_sub.add_parser("list", help="List macro directory entries (0x8E)")
    _add_common_target_args(p_ml)
    p_ml.set_defaults(func=_cmd_macro_list)

    p_mf = mac_sub.add_parser("free", help="Query macro pool free space (0x8A)")
    _add_common_target_args(p_mf)
    p_mf.set_defaults(func=_cmd_macro_free)

    p_mu = mac_sub.add_parser("upload", help="Upload single-page macro (dry-run by default; pass --yes)")
    _add_common_target_args(p_mu)
    p_mu.add_argument("--id", required=True, help="u16 macro ID (e.g. 0x0102; id_hi not 0x00/0xB0)")
    src = p_mu.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="Binary macro bytecode file (1..4090B)")
    src.add_argument("--hex", help="Hex-encoded macro bytecode (1..4090B)")
    p_mu.add_argument("--yes", action="store_true", help="Transmit writes (default is dry-run)")
    p_mu.add_argument("--dry-run", action="store_true", help="Plan only without writing (default)")
    p_mu.add_argument("--no-verify", action="store_true", help="Skip 0x8D readback check")
    p_mu.set_defaults(func=_cmd_macro_upload)

    p_md = mac_sub.add_parser("delete", help="Delete macro object (dry-run by default; pass --yes)")
    _add_common_target_args(p_md)
    p_md.add_argument("--id", required=True, help="u16 macro ID (e.g. 0x0102)")
    p_md.add_argument("--yes", action="store_true", help="Transmit delete (default is dry-run)")
    p_md.add_argument("--dry-run", action="store_true", help="Plan only without deleting (default)")
    p_md.set_defaults(func=_cmd_macro_delete)

    p_adv = sub.add_parser("adv", help="Phase 2 Group 5 advanced sensor diagnostics, overrides & persistence")
    adv_sub = p_adv.add_subparsers(dest="adv_cmd", required=True)

    p_as = adv_sub.add_parser("status", help="Query Group 5 0x80 state, caps & sensor branch")
    _add_common_target_args(p_as)
    p_as.set_defaults(func=_cmd_adv_status)

    p_asr = adv_sub.add_parser("snapshot-read", help="Read last Group 5 0x81 PAW3950 snapshot")
    _add_common_target_args(p_asr)
    p_asr.set_defaults(func=_cmd_adv_snapshot_read)

    p_asn = adv_sub.add_parser("snapshot", help="Trigger 0x01 snapshot and poll 0x81 (dry-run default)")
    _add_common_target_args(p_asn)
    p_asn.add_argument("--seq", type=lambda x: int(x, 0), default=1, help="u16 nonzero sequence ID (default 1)")
    p_asn.add_argument("--poll-attempts", type=int, default=10, help="Max 0x81 poll iterations (default 10)")
    _add_adv_dry_yes_args(p_asn)
    p_asn.set_defaults(func=_cmd_adv_snapshot)

    p_afps = adv_sub.add_parser("fps", help="Set Group 5 0x02 PAW3950 FPS preset or custom tuple (dry-run default)")
    _add_common_target_args(p_afps)
    p_afps.add_argument(
        "--preset",
        required=True,
        help="Preset name (0..7 Phase2/3, 0..37 Phase3+ e.g. 19k/13.3k-b, or custom/255)",
    )
    p_afps.add_argument("--custom", type=int, nargs=3, metavar=("U", "SLOW", "FAST"), help="Custom tuple for preset=custom/255")
    _add_adv_dry_yes_args(p_afps)
    p_afps.set_defaults(func=_cmd_adv_fps)

    p_afpsl = adv_sub.add_parser("fps-presets", help="List all 38 PAW3950 FPS preset codes and register tuples")
    p_afpsl.set_defaults(func=_cmd_adv_fps_presets)

    p_ads = adv_sub.add_parser("downshift", help="Set Group 5 0x03 downshift suppress override (dry-run default)")
    _add_common_target_args(p_ads)
    _add_adv_toggle_args(p_ads, "downshift-suppress")
    _add_adv_dry_yes_args(p_ads)
    p_ads.set_defaults(func=_cmd_adv_downshift)

    p_asm = adv_sub.add_parser("smoothing", help="Set Group 5 0x04 ripple/smoothing override (dry-run default)")
    _add_common_target_args(p_asm)
    _add_adv_toggle_args(p_asm, "smoothing-off")
    _add_adv_dry_yes_args(p_asm)
    p_asm.set_defaults(func=_cmd_adv_smoothing)

    p_apr = adv_sub.add_parser("persist", help="Control Group 5 0x05 dedicated Flash NV persistence (dry-run default)")
    _add_common_target_args(p_apr)
    p_apr.add_argument(
        "--action",
        required=True,
        choices=["save", "reset", "async_save", "1", "2", "3"],
        help="save(1), reset(2), or async_save(3)",
    )
    _add_adv_dry_yes_args(p_apr)
    p_apr.set_defaults(func=_cmd_adv_persist)

    p_ap3s = adv_sub.add_parser("p3-state", help="Query Phase 3 Group 5 0x82 control/plock/stationary state")
    _add_common_target_args(p_ap3s)
    p_ap3s.set_defaults(func=_cmd_adv_p3_state)

    p_ap3d = adv_sub.add_parser("p3-diag", help="Query Phase 3 Group 5 0x83 diagnostic counters (14 x u32)")
    _add_common_target_args(p_ap3d)
    p_ap3d.set_defaults(func=_cmd_adv_p3_diag)

    p_ap3c = adv_sub.add_parser("p3-ctrl", help="Update Phase 3/3+ Group 5 0x06 flags & plock timing (dry-run default)")
    _add_common_target_args(p_ap3c)
    p_ap3c.add_argument("--flags", help="Explicit u32 bitmask (0x00..0x0F Phase 3; 0x00..0xFF Phase 3+)")
    p_ap3c.add_argument("--atomic-accum", type=int, choices=[0, 1], help="Bit 0: atomic PRIMASK accumulators")
    p_ap3c.add_argument("--queue-guard", type=int, choices=[0, 1], help="Bit 1: EP81 busy overwrite guard")
    p_ap3c.add_argument("--direct-motion", type=int, choices=[0, 1], help="Bit 2: SPIM3 immediate dispatch")
    p_ap3c.add_argument("--plock", type=int, choices=[0, 1], help="Bit 3: TIMER1 phase lock")
    p_ap3c.add_argument("--fix-a", type=int, choices=[0, 1], help="Bit 4 (Phase 3+): ID53 Bank0 0x4E/4F/51/52 -> 0x0257")
    p_ap3c.add_argument("--mouse-abs", type=int, choices=[0, 1], help="Bit 5 (Phase 3+): wireless u16 ABS type 0x0A")
    p_ap3c.add_argument("--eager-wake", type=int, choices=[0, 1], help="Bit 6 (Phase 3+ W2): IRQ6 sensor wake")
    p_ap3c.add_argument("--ce-static", type=int, choices=[0, 1], help="Bit 7 (Phase 3+ W2): ID53 Bank05/09 M1_hi")
    p_ap3c.add_argument("--period-us", type=int, help="Plock target period in us (50..2000; requires --lead-us)")
    p_ap3c.add_argument("--lead-us", type=int, help="Plock lead advance in us (8..period-8; requires --period-us)")
    _add_adv_dry_yes_args(p_ap3c)
    p_ap3c.set_defaults(func=_cmd_adv_p3_ctrl)

    p_ap3r = adv_sub.add_parser("p3-diag-reset", help="Reset Phase 3 Group 5 0x07 diagnostic counters (dry-run default)")
    _add_common_target_args(p_ap3r)
    _add_adv_dry_yes_args(p_ap3r)
    p_ap3r.set_defaults(func=_cmd_adv_p3_diag_reset)

    p_afixa = adv_sub.add_parser("fix-a", help="Toggle Phase 3+ ID53 Bank0 0x4E/4F/51/52 fix-a override (dry-run default)")
    _add_common_target_args(p_afixa)
    _add_adv_toggle_args(p_afixa, "fix-a")
    _add_adv_dry_yes_args(p_afixa)
    p_afixa.set_defaults(func=_cmd_adv_fix_a)

    p_amabs = adv_sub.add_parser("mouse-abs", help="Toggle Phase 3+ wireless active u16 ABS type 0x0A (dry-run default)")
    _add_common_target_args(p_amabs)
    _add_adv_toggle_args(p_amabs, "mouse-abs")
    _add_adv_dry_yes_args(p_amabs)
    p_amabs.set_defaults(func=_cmd_adv_mouse_abs)

    p_ap1s = adv_sub.add_parser("p1-state", help="Query Phase 3+ P1 Group 5 0x84 plock learn/fix-a/ABS telemetry")
    _add_common_target_args(p_ap1s)
    p_ap1s.set_defaults(func=_cmd_adv_p1_state)

    p_ap1c = adv_sub.add_parser("p1-cfg", help="Configure Phase 3+ P1 Group 5 0x08 plock mode & reset actions (dry-run default)")
    _add_common_target_args(p_ap1c)
    p_ap1c.add_argument(
        "--mode",
        choices=["entry", "measure", "learn", "keep", "0", "1", "2", "0xff"],
        help="Plock mode: entry(0), measure(1), learn(2), or keep(0xFF with action flags)",
    )
    p_ap1c.add_argument("--reset-minmax", action="store_true", help="Reset plock err_min(+127) / err_max(-128)")
    p_ap1c.add_argument("--clear-learned", action="store_true", help="Clear plock expected_us, learn_pend, outlier_valid")
    p_ap1c.add_argument("--action-mask", help="Explicit u8 action_mask (0..3)")
    _add_adv_dry_yes_args(p_ap1c)
    p_ap1c.set_defaults(func=_cmd_adv_p1_cfg)

    p_ap2s = adv_sub.add_parser("p2p3-state", help="Query Phase 3+ Wave 2 Group 5 0x85 P2/P3 state & reg peek")
    _add_common_target_args(p_ap2s)
    p_ap2s.set_defaults(func=_cmd_adv_p2p3_state)

    p_aew = adv_sub.add_parser("eager-wake", help="Toggle Phase 3+ W2 IRQ6 eager-wake (dry-run default)")
    _add_common_target_args(p_aew)
    _add_adv_toggle_args(p_aew, "eager-wake")
    _add_adv_dry_yes_args(p_aew)
    p_aew.set_defaults(func=_cmd_adv_eager_wake)

    p_aces = adv_sub.add_parser("ce-static", help="Toggle Phase 3+ W2 ID53 Bank05/09 M1_hi ce-static (dry-run default)")
    _add_common_target_args(p_aces)
    _add_adv_toggle_args(p_aces, "ce-static")
    _add_adv_dry_yes_args(p_aces)
    p_aces.set_defaults(func=_cmd_adv_ce_static)

    p_alod = adv_sub.add_parser("lod-raw", help="Set/clear Phase 3+ W2 0x09 raw 0x18:0x7A LOD override (dry-run default)")
    _add_common_target_args(p_alod)
    _add_adv_toggle_args(p_alod, "lod-raw")
    p_alod.add_argument("--raw", help="Raw u8 value for 0x18:0x7A when enabled (hex or dec)")
    _add_adv_dry_yes_args(p_alod)
    p_alod.set_defaults(func=_cmd_adv_lod_raw)

    p_aas = adv_sub.add_parser("anti-slam", help="Configure Phase 3+ W2 0x0A anti-slam landing/lifted ms (dry-run default)")
    _add_common_target_args(p_aas)
    p_aas.add_argument(
        "--landing-ms",
        type=int,
        default=ANTI_SLAM_LANDING_DEFAULT_MS,
        help=f"Landing lock window in ms (0..100, stock default {ANTI_SLAM_LANDING_DEFAULT_MS})",
    )
    p_aas.add_argument(
        "--lifted-ms",
        type=int,
        default=ANTI_SLAM_LIFTED_DEFAULT_MS,
        help=f"Lifted press window in ms (0..100, stock default {ANTI_SLAM_LIFTED_DEFAULT_MS})",
    )
    _add_adv_dry_yes_args(p_aas)
    p_aas.set_defaults(func=_cmd_adv_anti_slam)

    p_arr = adv_sub.add_parser("reg-read", help="Trigger Phase 3+ W2 0x0B cooperative PAW3950 register peek (dry-run default)")
    _add_common_target_args(p_arr)
    p_arr.add_argument("--bank", required=True, help="Register bank (0..255, hex or dec)")
    p_arr.add_argument("--reg", required=True, help="Register address (0..255, hex or dec)")
    _add_adv_dry_yes_args(p_arr)
    p_arr.set_defaults(func=_cmd_adv_reg_read)

    p_ast = adv_sub.add_parser("selftest", help="Offline Phase 2/3/3+ Group 5 Unicorn selftest (wired, RF, persistence, ID4F)")
    p_ast.add_argument("--mouse-hex", help="Optional path to patched mouse HEX (default: Phase 2 + Phase 3 + Phase 3+)")
    p_ast.add_argument(
        "--profile",
        choices=["phase2", "phase3", "phase3plus", "both"],
        default="both",
        help="Offline Unicorn test profile (default: both runs Phase 2, Phase 3, and Phase 3+)",
    )
    p_ast.set_defaults(func=_cmd_adv_selftest)

    p_st = sub.add_parser("selftest", help="Offline stateful Unicorn write->readback & macro selftest")
    p_st.add_argument("--sensor-id", type=lambda x: int(x, 0), default=0x53)
    p_st.set_defaults(func=_cmd_selftest)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
