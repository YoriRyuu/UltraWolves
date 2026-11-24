"""Offline-only CLI for Fenrir S2 mouse firmware validation and mock bootloader replay."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from fenrir.constants import REFERENCE_FIRMWARES
from fenrir.flasher.hid_wired import run_phase2_wired_flash, run_phase3plus_wired_flash, run_stock_wired_flash
from fenrir.flasher.protocol import MAX_PROGRAM_CHUNK
from fenrir.flasher.s4_probe import run_s4_blank_probe, run_s4_canary
from fenrir.flasher.safety import (
    MOUSE_APP_START,
    FlashBoundsError,
    FlashSafetyError,
    NotForFlashError,
    OfflineMockBootloader,
    RealHardwareFlashBlockedError,
    assert_offline_only_target,
    enforce_wired_flash_policy,
    run_offline_mock_flash,
    validate_mouse_app_hex,
)


def _cmd_inspect(args: argparse.Namespace) -> int:
    try:
        img = validate_mouse_app_hex(args.hex, allow_last_page_tail=args.allow_tail_page)
    except (FlashSafetyError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    out = img.to_summary()
    out["first_program_hex"] = img.chunks[0].program_report.hex()
    out["last_program_hex"] = img.chunks[-1].program_report.hex()
    print(json.dumps(out, indent=2))
    return 0


def _cmd_plan(args: argparse.Namespace) -> int:
    try:
        if args.execute_hardware:
            enforce_wired_flash_policy(device_id=0, pid=0x3508, offline_mock_only=False)
        img = validate_mouse_app_hex(args.hex, allow_last_page_tail=args.allow_tail_page)
        res = run_offline_mock_flash(img, OfflineMockBootloader(), dry_run=True)
    except (FlashSafetyError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(res, indent=2))
    return 0


def _cmd_mock_replay(args: argparse.Namespace) -> int:
    dry_run = bool(args.dry_run or not args.yes)
    try:
        img = validate_mouse_app_hex(args.hex, allow_last_page_tail=args.allow_tail_page)
        res = run_offline_mock_flash(img, OfflineMockBootloader(), dry_run=dry_run)
    except (FlashSafetyError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(res, indent=2))
    return 0


def _cmd_flash_stock(args: argparse.Namespace) -> int:
    execute = bool(args.yes and not args.dry_run)
    extra = {"wipe_ext": True} if getattr(args, "wipe_ext", False) else {}
    try:
        res = run_stock_wired_flash(
            args.hex,
            execute=execute,
            confirm_stock_s3=bool(args.confirm_stock_s3),
            report_path=args.report,
            **extra,
        )
    except (FlashSafetyError, FileNotFoundError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(res, indent=2))
    return 0


def _cmd_flash_phase2(args: argparse.Namespace) -> int:
    execute = bool(args.yes and not args.dry_run)
    try:
        res = run_phase2_wired_flash(
            args.hex,
            s4_canary_report=args.s4_canary_report,
            execute=execute,
            confirm_phase2_s5=bool(args.confirm_phase2_s5),
            report_path=args.report,
        )
    except (FlashSafetyError, FileNotFoundError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(res, indent=2))
    return 0


def _cmd_flash_phase3plus(args: argparse.Namespace) -> int:
    execute = bool(args.yes and not args.dry_run)
    try:
        res = run_phase3plus_wired_flash(
            args.hex,
            s4_canary_report=args.s4_canary_report,
            execute=execute,
            confirm_phase3plus_s6=bool(args.confirm_phase3plus_s6),
            report_path=args.report,
        )
    except (FlashSafetyError, FileNotFoundError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(res, indent=2))
    return 0


def _cmd_s4_blank_probe(args: argparse.Namespace) -> int:
    execute = bool(args.yes and not args.dry_run)
    try:
        res = run_s4_blank_probe(
            execute=execute,
            confirm_s4=bool(args.confirm_s4),
            report_path=args.report,
        )
    except (FlashSafetyError, FileNotFoundError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(res, indent=2))
    return 0


def _cmd_s4_canary(args: argparse.Namespace) -> int:
    execute = bool(args.yes and not args.dry_run)
    try:
        res = run_s4_canary(
            args.hex,
            blank_probe_report=args.blank_probe_report,
            execute=execute,
            confirm_s4=bool(args.confirm_s4),
            report_path=args.report,
        )
    except (FlashSafetyError, FileNotFoundError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(res, indent=2))
    return 0


def _make_ihex_line(rec_type: int, addr16: int, data: bytes) -> str:
    raw = bytes([len(data), (addr16 >> 8) & 0xFF, addr16 & 0xFF, rec_type]) + data
    ck = (-sum(raw)) & 0xFF
    return ":" + (raw + bytes([ck])).hex().upper() + "\n"


def _cmd_selftest(_args: argparse.Namespace) -> int:
    stock_hex = REFERENCE_FIRMWARES["mouse"].hex_path
    img = validate_mouse_app_hex(stock_hex)
    assert img.base == MOUSE_APP_START
    assert img.byte_length == 117260
    assert len(img.chunks) == 3665
    assert len(img.chunks[-1].data) == 12
    assert img.initial_sp == 0x2000BCA0 and img.reset_vector == 0x000064A5

    # 1. Dry-run + full mock replay (including 4K boundary retry simulation)
    mock = OfflineMockBootloader(inject_4k_retry_once=True)
    dry_res = run_offline_mock_flash(img, mock, dry_run=True)
    assert dry_res["dry_run"] is True and dry_res["executed"] is False and len(mock.tx_log) == 0

    replay_res = run_offline_mock_flash(img, mock, dry_run=False)
    assert replay_res["flash_sha256_match"] is True
    assert replay_res["bootloader_intact"] is True
    assert replay_res["retries_4k"] == 1
    assert replay_res["packets_programmed"] == 3665
    assert replay_res["reset_device_sent"] is False

    # 2. Verify real-HID execution lock & wireless lock
    for bad_call in (
        lambda: assert_offline_only_target(object()),
        lambda: enforce_wired_flash_policy(device_id=0, pid=0x3508, offline_mock_only=False),
        lambda: enforce_wired_flash_policy(device_id=1, pid=0x3508, offline_mock_only=False),
    ):
        try:
            bad_call()
        except FlashSafetyError:
            pass
        else:
            raise AssertionError("Expected real-HID / wireless S2 safety rejection")

    # 3. Verify Erase fail aborts before Program, and Verify mismatch aborts before Exit
    mock_erase_fail = OfflineMockBootloader(inject_erase_fail=True)
    try:
        run_offline_mock_flash(img, mock_erase_fail, dry_run=False)
    except FlashSafetyError:
        assert not any(tx[5] == 0xB0 and tx[6] == 0x02 for tx in mock_erase_fail.tx_log)
    else:
        raise AssertionError("Expected Erase failure to abort S2 flash")

    mock_verify_fail = OfflineMockBootloader(inject_verify_mismatch_addr=MOUSE_APP_START + 64)
    try:
        run_offline_mock_flash(img, mock_verify_fail, dry_run=False)
    except FlashSafetyError:
        assert not any(tx[5] == 0xB0 and tx[6] == 0x04 for tx in mock_verify_fail.tx_log)
        assert mock_verify_fail.in_bootloader is True
    else:
        raise AssertionError("Expected Verify mismatch to abort before Exit")

    # 4. Verify Bootloader (<0x6000), upper bound (>=0x23000), and NOT_FOR_FLASH guards
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        bl_hex = td_path / "bl_touch.hex"
        bl_hex.write_text(
            _make_ihex_line(4, 0, b"\x00\x00")
            + _make_ihex_line(0, 0x5FF0, b"\x00" * 16)
            + _make_ihex_line(1, 0, b""),
            encoding="ascii",
        )
        try:
            validate_mouse_app_hex(bl_hex)
        except FlashBoundsError:
            pass
        else:
            raise AssertionError("Expected <0x6000 Bootloader write to raise FlashBoundsError")

        nff_hex = td_path / "bad_NOT_FOR_FLASH.hex"
        nff_hex.write_text(stock_hex.read_text(encoding="ascii"), encoding="ascii")
        try:
            validate_mouse_app_hex(nff_hex)
        except NotForFlashError:
            pass
        else:
            raise AssertionError("Expected NOT_FOR_FLASH path to raise NotForFlashError")

    print(
        json.dumps(
            {
                "selftest": "PASS",
                "stock_chunks": len(img.chunks),
                "stock_bytes": img.byte_length,
                "max_chunk_bytes": MAX_PROGRAM_CHUNK,
                "retries_4k": replay_res["retries_4k"],
                "flash_sha256_match": replay_res["flash_sha256_match"],
                "bootloader_intact": replay_res["bootloader_intact"],
                "real_hid_locked": True,
                "guards_verified": ["bootloader_lt_0x6000", "not_for_flash", "erase_abort", "verify_abort_no_exit"],
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fenrir-flash",
        description="Fenrir S2 offline mouse HEX validator & mock bootloader replay CLI (real HID locked off).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    p_ins = sub.add_parser("inspect", help="Strictly validate Intel HEX, vector table, no-brick bounds & chunk plan")
    p_ins.add_argument("--hex", required=True, help="Path to mouse APP Intel HEX")
    p_ins.add_argument("--allow-tail-page", action="store_true", help="Allow 0x22A0C..0x22FFF within last 4K page")
    p_ins.set_defaults(func=_cmd_inspect)

    p_pln = sub.add_parser("plan", help="Generate offline S2 flash plan (dry-run; refuses hardware execution)")
    p_pln.add_argument("--hex", required=True, help="Path to mouse APP Intel HEX")
    p_pln.add_argument("--allow-tail-page", action="store_true", help="Allow 0x22A0C..0x22FFF within last 4K page")
    p_pln.add_argument(
        "--execute-hardware",
        action="store_true",
        help="Attempt hardware execution (unconditionally blocked in S2 with RealHardwareFlashBlockedError)",
    )
    p_pln.set_defaults(func=_cmd_plan)

    p_mr = sub.add_parser("mock-replay", help="Replay S2 workflow inside OfflineMockBootloader (dry-run by default)")
    p_mr.add_argument("--hex", required=True, help="Path to mouse APP Intel HEX")
    p_mr.add_argument("--allow-tail-page", action="store_true", help="Allow 0x22A0C..0x22FFF within last 4K page")
    p_mr.add_argument("--yes", action="store_true", help="Execute against in-memory OfflineMockBootloader")
    p_mr.add_argument("--dry-run", action="store_true", help="Plan only without mock execution (default)")
    p_mr.set_defaults(func=_cmd_mock_replay)

    p_fs = sub.add_parser(
        "flash-stock",
        help="S3 strictly-gated stock-only wired mouse flasher (dry-run by default; requires --yes --confirm-stock-s3)",
    )
    p_fs.add_argument("--hex", required=True, help="Path to stock mouse APP Intel HEX (exact SHA-256 whitelist)")
    p_fs.add_argument("--yes", action="store_true", help="Allow wired USB execution (must also pass --confirm-stock-s3)")
    p_fs.add_argument("--dry-run", action="store_true", help="Read-only pre-flight probe without any flash/BL writes (default)")
    p_fs.add_argument(
        "--confirm-stock-s3",
        action="store_true",
        help="Explicit S3 stock-only wired flash confirmation gate",
    )
    p_fs.add_argument(
        "--wipe-ext",
        action="store_true",
        help="Pad stock image with 0xFF through 0x00025000 (3,968 chunks) to cleanly erase Phase 2/3+ tail & ext pages",
    )
    p_fs.add_argument("--report", help="Optional path to save structured JSON execution report")
    p_fs.set_defaults(func=_cmd_flash_stock)

    p_bp = sub.add_parser(
        "s4-blank-probe",
        help="S4 pure read-only VerifyByAddress probe inside 0x3506 Bootloader (dry-run by default)",
    )
    p_bp.add_argument("--yes", action="store_true", help="Allow wired USB Bootloader read probe (must also pass --confirm-s4)")
    p_bp.add_argument("--dry-run", action="store_true", help="Preflight topology/FW check only (default)")
    p_bp.add_argument("--confirm-s4", action="store_true", help="Explicit S4 Bootloader probe confirmation gate")
    p_bp.add_argument("--report", help="Optional path to save structured JSON blank probe report")
    p_bp.set_defaults(func=_cmd_s4_blank_probe)

    p_cn = sub.add_parser(
        "s4-canary",
        help="S4 two-tier canary + erase ceiling check + mandatory pure-stock restore (dry-run by default)",
    )
    p_cn.add_argument("--hex", required=True, help="Path to exact stock mouse APP Intel HEX (SHA-256 whitelisted)")
    p_cn.add_argument("--blank-probe-report", help="Path to s4-blank-probe JSON report (required for live --yes --confirm-s4)")
    p_cn.add_argument("--yes", action="store_true", help="Allow wired USB canary execution (must also pass --confirm-s4)")
    p_cn.add_argument("--dry-run", action="store_true", help="Preflight topology/FW check only (default)")
    p_cn.add_argument("--confirm-s4", action="store_true", help="Explicit S4 canary confirmation gate")
    p_cn.add_argument("--report", help="Optional path to save structured JSON canary report")
    p_cn.set_defaults(func=_cmd_s4_canary)

    p_p2 = sub.add_parser(
        "flash-phase2",
        help="S5 gated Phase 2 wired mouse flasher (dry-run by default; requires --yes --confirm-phase2-s5 --s4-canary-report)",
    )
    p_p2.add_argument("--hex", required=True, help="Path to verified Phase 2 mouse HEX (exact SHA-256 whitelist)")
    p_p2.add_argument("--s4-canary-report", help="Path to S4 canary report JSON proving Tier 1 passed")
    p_p2.add_argument("--yes", action="store_true", help="Allow wired USB execution (must also pass --confirm-phase2-s5)")
    p_p2.add_argument("--dry-run", action="store_true", help="Read-only preflight check only (default)")
    p_p2.add_argument("--confirm-phase2-s5", action="store_true", help="Explicit S5 Phase 2 confirmation gate")
    p_p2.add_argument("--report", help="Optional path to save structured JSON execution report")
    p_p2.set_defaults(func=_cmd_flash_phase2)

    p_p3p = sub.add_parser(
        "flash-phase3plus",
        help="S6 gated Phase 3+ wired mouse flasher (dry-run by default; requires --yes --confirm-phase3plus-s6 --s4-canary-report)",
    )
    p_p3p.add_argument("--hex", required=True, help="Path to verified Phase 3+ mouse HEX (exact SHA-256 whitelist)")
    p_p3p.add_argument("--s4-canary-report", help="Path to S4 canary report JSON proving Tier 1+2 passed")
    p_p3p.add_argument("--yes", action="store_true", help="Allow wired USB execution (must also pass --confirm-phase3plus-s6)")
    p_p3p.add_argument("--dry-run", action="store_true", help="Read-only preflight check only (default)")
    p_p3p.add_argument("--confirm-phase3plus-s6", action="store_true", help="Explicit S6 Phase 3+ confirmation gate")
    p_p3p.add_argument("--report", help="Optional path to save structured JSON execution report")
    p_p3p.set_defaults(func=_cmd_flash_phase3plus)

    p_st = sub.add_parser("selftest", help="Offline S2 validation, safety guard, and mock replay selftest")
    p_st.set_defaults(func=_cmd_selftest)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
