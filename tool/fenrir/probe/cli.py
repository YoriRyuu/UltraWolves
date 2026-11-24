"""Command-line interface for Phase 0 read-only HID probing (L0/L1/L2)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from fenrir.constants import VENDOR_ID
from fenrir.probe.identity import (
    MouseDisconnectedError,
    format_identity_summary,
    probe_mouse_usb,
    probe_mouse_via_receiver,
    probe_receiver_local,
)
from fenrir.protocol.catalog import TargetRole
from fenrir.safety.guard import ProbeLevel, ReadOnlyGuard
from fenrir.transport.capture import CaptureLogger
from fenrir.transport.hid_win import GuardedHidSession, HidApiTransport
from fenrir.transport.mock import UnicornMockTransport


def _resolve_device_by_path(devices: list, path: str):
    for d in devices:
        if d.path == path:
            return d
    raise SystemExit(f"Device path not found in enumeration: {path}")


def _cmd_enumerate(args: argparse.Namespace) -> int:
    guard = ReadOnlyGuard(require_proofs=False)
    capture = CaptureLogger("L0_enumerate")
    transport = HidApiTransport()
    with GuardedHidSession(transport, guard, capture) as session:
        devices = session.enumerate(vid=int(args.vid, 0))
    if args.json:
        print(json.dumps([d.to_dict() for d in devices], ensure_ascii=False, indent=2))
    else:
        if not devices:
            print(f"No HID devices found for VID {args.vid}")
        for idx, d in enumerate(devices):
            print(
                f"[{idx}] {d.vid_hex}:{d.pid_hex} | class={d.classification.value} | "
                f"if={d.interface_number} up=0x{d.usage_page:04X} usage=0x{d.usage:04X} "
                f"exact_feat={d.is_exact_feature_match} feat_cand={d.is_feature_candidate} | "
                f"product={d.product!r}"
            )
            print(f"    path={d.path}")
            if d.notes:
                print(f"    notes={d.notes}")
    return 0


def _cmd_passive(args: argparse.Namespace) -> int:
    guard = ReadOnlyGuard(require_proofs=False)
    capture = CaptureLogger("L1_passive")
    transport = HidApiTransport()
    with GuardedHidSession(transport, guard, capture) as session:
        devices = session.enumerate(vid=int(args.vid, 0))
        dev = _resolve_device_by_path(devices, args.path)
        session.open_for_level(dev, ProbeLevel.L1_PASSIVE_READ)
        frame = session.passive_read()
    cap_path = capture.save()
    print(f"L1 passive GET_FEATURE (64B): {frame.hex()}")
    print(f"Capture saved: {cap_path}")
    return 0


def _cmd_query(args: argparse.Namespace) -> int:
    guard = ReadOnlyGuard(require_proofs=True)
    capture = CaptureLogger(f"L2_{args.target}")
    transport = HidApiTransport()
    try:
        with GuardedHidSession(transport, guard, capture) as session:
            devices = session.enumerate(vid=int(args.vid, 0))
            dev = _resolve_device_by_path(devices, args.path)
            if args.target == "mouse-usb":
                session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=TargetRole.MOUSE_USB)
                report = probe_mouse_usb(session, dev)
            elif args.target == "receiver-usb":
                session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=TargetRole.RECEIVER_USB_LOCAL)
                report = probe_receiver_local(session, dev, include_2g4=False)
            elif args.target == "receiver-2g4":
                session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=TargetRole.RECEIVER_2G4_LOCAL)
                report = probe_receiver_local(session, dev, include_2g4=True)
            elif args.target == "receiver-to-mouse":
                session.open_for_level(dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=TargetRole.RECEIVER_TO_MOUSE_RF)
                report = probe_mouse_via_receiver(session, dev)
            else:
                raise SystemExit(f"Unsupported target: {args.target}")
    except MouseDisconnectedError as exc:
        cap_path = capture.save()
        print(f"ERROR: {exc}", file=sys.stderr)
        print(f"Capture saved: {cap_path}", file=sys.stderr)
        return 2

    cap_path = capture.save()
    report["capture_file"] = str(cap_path)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Report saved: {out_path}")
    print(format_identity_summary(report))
    print(f"Capture saved: {cap_path}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    doc = json.loads(Path(args.input).read_text(encoding="utf-8"))
    print(format_identity_summary(doc))
    return 0


def _cmd_selftest(args: argparse.Namespace) -> int:
    guard = ReadOnlyGuard(require_proofs=True)
    capture = CaptureLogger("selftest_unicorn")
    transport = UnicornMockTransport(sensor_id=args.sensor_id, simulate_pending_polls=1)

    with GuardedHidSession(transport, guard, capture) as session:
        devices = session.enumerate(vid=VENDOR_ID)
        mouse_dev = next(d for d in devices if d.path == UnicornMockTransport.MOUSE_PATH)
        rx_dev = next(d for d in devices if d.path == UnicornMockTransport.RX_USB_PATH)

        session.open_for_level(mouse_dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=TargetRole.MOUSE_USB)
        mouse_report = probe_mouse_usb(session, mouse_dev)
        session.close()

        session.open_for_level(rx_dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=TargetRole.RECEIVER_2G4_LOCAL)
        rx_report = probe_receiver_local(session, rx_dev, include_2g4=True)
        session.close()

        session.open_for_level(rx_dev, ProbeLevel.L2_WHITELIST_QUERY, target_role=TargetRole.RECEIVER_TO_MOUSE_RF)
        rf_mouse_report = probe_mouse_via_receiver(session, rx_dev)

    print(format_identity_summary(mouse_report))
    print()
    print(format_identity_summary(rx_report))
    print()
    print(format_identity_summary(rf_mouse_report))
    if args.save_capture:
        cap_path = capture.save()
        print(f"\nSelftest capture saved: {cap_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fenrir-probe",
        description="Fenrir Phase 0 read-only HID identity probe (L0/L1/L2 gated).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    p_enum = sub.add_parser("enumerate", help="L0: enumerate HID entries only (zero packets sent)")
    p_enum.add_argument("--vid", default=f"0x{VENDOR_ID:04X}", help="Vendor ID filter (0 for all)")
    p_enum.add_argument("--json", action="store_true", help="Output JSON")
    p_enum.set_defaults(func=_cmd_enumerate)

    p_pas = sub.add_parser("passive", help="L1: open device and call GET_FEATURE only (zero SET_FEATURE)")
    p_pas.add_argument("--path", required=True, help="Exact HID device path from L0 enumerate")
    p_pas.add_argument("--vid", default=f"0x{VENDOR_ID:04X}", help="Vendor ID filter (default 0x33E4; 0 for all)")
    p_pas.set_defaults(func=_cmd_passive)

    p_qry = sub.add_parser("query", help="L2: run Unicorn-proven read-only whitelist queries")
    p_qry.add_argument(
        "--target",
        required=True,
        choices=["mouse-usb", "receiver-usb", "receiver-2g4", "receiver-to-mouse"],
        help="Target endpoint role",
    )
    p_qry.add_argument("--path", required=True, help="Exact HID device path from L0 enumerate")
    p_qry.add_argument("--vid", default=f"0x{VENDOR_ID:04X}", help="Vendor ID filter (default 0x33E4; 0 for all)")
    p_qry.add_argument("--output", help="Optional path to save identity_report.json")
    p_qry.set_defaults(func=_cmd_query)

    p_rep = sub.add_parser("report", help="Print readable summary from saved identity_report.json")
    p_rep.add_argument("--input", required=True, help="Path to saved JSON report")
    p_rep.set_defaults(func=_cmd_report)

    p_st = sub.add_parser("selftest", help="Offline end-to-end probe against Unicorn firmware emulator")
    p_st.add_argument("--sensor-id", type=lambda x: int(x, 0), default=0x53, help="Mock sensor ID (0x4F/0x51/0x53)")
    p_st.add_argument("--save-capture", action="store_true", help="Write selftest capture log to captures/")
    p_st.set_defaults(func=_cmd_selftest)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
