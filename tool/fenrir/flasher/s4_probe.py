"""S4 Flash-ceiling diagnostic tooling: read-only blank probe and reversible 2-tier canary.

Safety invariants enforced unconditionally:
1. `s4-blank-probe`: pure read-only `VerifyByAddress` probe inside `0x3506` Bootloader;
   ZERO `Erase`, ZERO `Program`, ZERO `ResetDevice (0xC0 0x02)`.
2. `s4-canary`: requires exact stock mouse HEX SHA-256 whitelist (`validate_stock_mouse_hex_only`),
   wired-only single-mouse topology (`select_wired_mouse_device`), dual confirmation
   (`--yes --confirm-s4`), AND `--blank-probe-report` confirming `all_ff == true` for any
   region before writing.
3. Mandatory Stock Restore (`try ... finally`): ALWAYS ends by restoring the exact
   3,665-chunk pure stock mouse image (`0x00006000..0x00022A0C`) and verifying `0x3508`
   `GetFW == "01.00.39.00"` with ZERO `ResetDevice (0xC0 0x02)` frames.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from fenrir.constants import MOUSE_APP_PIDS, VENDOR_ID
from fenrir.flasher.hid_wired import (
    STOCK_MOUSE_EXPECTED_BYTES,
    STOCK_MOUSE_EXPECTED_FW,
    ChunkTransferError,
    S3FlashExecutionError,
    _enter_bootloader,
    _erase_bootloader,
    _exit_bootloader_to_app,
    _program_chunks,
    _query_get_bl_fw,
    _query_get_fw,
    _verify_chunks,
    _verify_read_block,
    select_wired_mouse_device,
    validate_stock_mouse_hex_only,
)
from fenrir.flasher.protocol import MAX_PROGRAM_CHUNK, FlashChunk, build_program_plan
from fenrir.flasher.safety import MOUSE_APP_START, FlashSafetyError, ValidatedMouseImage
from fenrir.transport.base import FeatureTransport
from fenrir.transport.hid_win import HidApiTransport

S4_TAIL_SCAN_START = 0x00022A00
S4_TAIL_CHECK_START = 0x00022A0C
S4_TIER1_END_EXCLUSIVE = 0x00023000
S4_TIER1_CANARY_ADDR = 0x00022FFF
S4_TIER1_CHUNKS = 3712

S4_EXT_START = 0x00023000
S4_EXT_END_EXCLUSIVE = 0x00025000
S4_TIER2_CHUNKS = 3968

S4_SAMPLE_UPPER_ADDRS: tuple[int, ...] = (0x00025000, 0x00030000, 0x0004F000)
S4_EA000_START = 0x000EA000
S4_EA000_END_EXCLUSIVE = 0x000EB000
S4_CANARY_BYTE = 0xFE


class S4SafetyError(FlashSafetyError):
    """Raised when S4 prerequisite reports or safety gates forbid execution."""


def _device_summary(dev: Any) -> dict[str, Any]:
    return {
        "vid": dev.vid_hex,
        "pid": dev.pid_hex,
        "path": dev.path,
        "product": dev.product,
    }


def _preflight_read_only(
    transport: FeatureTransport,
    dev: Any,
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> dict[str, Any]:
    if dev.pid in MOUSE_APP_PIDS:
        fw_ver = _query_get_fw(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
        return {"mode": "app", "fw_version": fw_ver}
    bl_ver = _query_get_bl_fw(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
    return {"mode": "bootloader", "bl_fw_version": bl_ver}


def _write_report(report_path: Path | str | None, result: dict[str, Any]) -> None:
    if report_path is None:
        return
    out_p = Path(report_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(result, indent=2), encoding="utf-8")
    result["report_file"] = str(out_p)


def _format_error_details(exc: BaseException) -> dict[str, Any]:
    details: dict[str, Any] = {"message": str(exc)}
    if isinstance(exc, ChunkTransferError):
        details["address"] = f"0x{exc.address:08X}"
        if exc.chunk_index is not None:
            details["chunk_index"] = exc.chunk_index
        if exc.rx1 is not None:
            details["rx1"] = f"0x{exc.rx1:02X}"
        if exc.rx5 is not None:
            details["rx5"] = f"0x{exc.rx5:02X}"
    return details


def _scan_verify_range(
    transport: FeatureTransport,
    start_addr: int,
    end_addr: int,
    *,
    check_from_addr: int | None = None,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> dict[str, Any]:
    """Read 32B blocks across [start_addr..end_addr) via VerifyByAddress (read-only)."""
    check_start = start_addr if check_from_addr is None else check_from_addr
    reads_attempted = 0
    reads_succeeded = 0
    first_non_ff: dict[str, str] | None = None
    error: dict[str, Any] | None = None
    all_ff = True

    for addr in range(start_addr, end_addr, MAX_PROGRAM_CHUNK):
        length = min(MAX_PROGRAM_CHUNK, end_addr - addr)
        reads_attempted += 1
        try:
            plain = _verify_read_block(
                transport,
                addr,
                length,
                retry_max=5,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
        except S3FlashExecutionError as exc:
            all_ff = False
            error = _format_error_details(exc)
            break

        reads_succeeded += 1
        for offset, byte_val in enumerate(plain):
            byte_addr = addr + offset
            if byte_addr < check_start:
                continue
            if byte_val != 0xFF:
                all_ff = False
                if first_non_ff is None:
                    first_non_ff = {
                        "address": f"0x{byte_addr:08X}",
                        "byte_hex": f"0x{byte_val:02X}",
                        "block_hex": plain[offset : offset + 16].hex(),
                    }

    return {
        "start": f"0x{start_addr:08X}",
        "end_exclusive": f"0x{end_addr:08X}",
        "check_from": f"0x{check_start:08X}",
        "reads_attempted": reads_attempted,
        "reads_succeeded": reads_succeeded,
        "all_ff": bool(all_ff and error is None),
        "first_non_ff": first_non_ff,
        "error": error,
    }


def _reenter_bootloader_from_current(
    transport_factory: Callable[[], FeatureTransport],
    transport: FeatureTransport,
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> tuple[FeatureTransport, str]:
    devices = transport.enumerate_devices(VENDOR_ID)
    dev = select_wired_mouse_device(devices)
    new_transport, _bl_dev, bl_fw, _fw_before = _enter_bootloader(
        transport_factory,
        transport,
        dev,
        sleep_fn=sleep_fn,
        perf_counter_fn=perf_counter_fn,
    )
    return new_transport, bl_fw


def run_s4_blank_probe(
    *,
    execute: bool = False,
    confirm_s4: bool = False,
    report_path: Path | str | None = None,
    transport_factory: Callable[[], FeatureTransport] = HidApiTransport,
    sleep_fn: Callable[[float], None] = time.sleep,
    perf_counter_fn: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Run read-only S4 blank probe (`VerifyByAddress` only; zero Erase/Program)."""
    dry_run = not (execute and confirm_s4)
    transport = transport_factory()
    opened = False
    in_bootloader = False

    try:
        devices = transport.enumerate_devices(VENDOR_ID)
        dev = select_wired_mouse_device(devices)
        transport.open(dev.path)
        opened = True

        if dry_run:
            preflight = _preflight_read_only(
                transport, dev, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
            )
            result: dict[str, Any] = {
                "stage": "S4_BLANK_PROBE",
                "dry_run": True,
                "executed": False,
                "writes_sent": 0,
                "erase_count": 0,
                "program_count": 0,
                "device": _device_summary(dev),
                "preflight": preflight,
                "reset_device_sent": False,
            }
        else:
            transport, _bl_dev, bl_fw, fw_before = _enter_bootloader(
                transport_factory,
                transport,
                dev,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            in_bootloader = True

            tail_scan = _scan_verify_range(
                transport,
                S4_TAIL_SCAN_START,
                S4_TIER1_END_EXCLUSIVE,
                check_from_addr=S4_TAIL_CHECK_START,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            ext_scan = _scan_verify_range(
                transport,
                S4_EXT_START,
                S4_EXT_END_EXCLUSIVE,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            sample_upper = {
                f"0x{addr:08X}": _scan_verify_range(
                    transport,
                    addr,
                    addr + MAX_PROGRAM_CHUNK,
                    sleep_fn=sleep_fn,
                    perf_counter_fn=perf_counter_fn,
                )
                for addr in S4_SAMPLE_UPPER_ADDRS
            }
            ea000_scan = _scan_verify_range(
                transport,
                S4_EA000_START,
                S4_EA000_END_EXCLUSIVE,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )

            transport, fw_after = _exit_bootloader_to_app(
                transport_factory,
                transport,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            in_bootloader = False

            result = {
                "stage": "S4_BLANK_PROBE",
                "dry_run": False,
                "executed": True,
                "writes_sent": 0,
                "erase_count": 0,
                "program_count": 0,
                "fw_before": fw_before,
                "bl_fw": bl_fw,
                "fw_after": fw_after,
                "tail_22a0c_22fff_all_ff": tail_scan["all_ff"],
                "ext_23000_24fff_all_ff": ext_scan["all_ff"],
                "ea000_all_ff": ea000_scan["all_ff"],
                "regions": {
                    "tail_page_22a00_23000": tail_scan,
                    "ext_range_23000_25000": ext_scan,
                    "sample_upper": sample_upper,
                    "ea000_config_page": ea000_scan,
                },
                "reset_device_sent": False,
            }
    finally:
        if in_bootloader:
            try:
                transport, _fw = _exit_bootloader_to_app(
                    transport_factory,
                    transport,
                    sleep_fn=sleep_fn,
                    perf_counter_fn=perf_counter_fn,
                )
            except Exception:
                pass
        if opened:
            try:
                transport.close()
            except Exception:
                pass

    _write_report(report_path, result)
    return result


def _load_and_validate_blank_probe_report(report_path: Path | str | None) -> dict[str, Any]:
    if report_path is None:
        raise S4SafetyError(
            "s4-canary live execution requires --blank-probe-report <path> from s4-blank-probe"
        )
    path = Path(report_path)
    if not path.is_file():
        raise S4SafetyError(f"Blank probe report not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise S4SafetyError(f"Invalid JSON in blank probe report {path}: {exc}") from exc

    if not isinstance(data, dict) or data.get("stage") != "S4_BLANK_PROBE":
        raise S4SafetyError(f"Expected S4_BLANK_PROBE report in {path}")
    if data.get("dry_run") is not False or data.get("executed") is not True:
        raise S4SafetyError(
            f"Blank probe report {path} was dry-run / not executed; run s4-blank-probe --yes --confirm-s4 first"
        )
    if data.get("tail_22a0c_22fff_all_ff") is not True:
        raise S4SafetyError(
            "Refusing S4 canary: blank probe report did not confirm 0x00022A0C..0x00022FFF is all 0xFF"
        )
    return data


def _extract_stock_bytes(img: ValidatedMouseImage) -> bytes:
    stock_bytes = b"".join(chunk.data for chunk in img.chunks)
    if len(stock_bytes) != STOCK_MOUSE_EXPECTED_BYTES:
        raise S4SafetyError(
            f"Expected {STOCK_MOUSE_EXPECTED_BYTES} stock bytes, got {len(stock_bytes)}"
        )
    return stock_bytes


def _build_tier1_canary_chunks(stock_bytes: bytes) -> list[FlashChunk]:
    total_len = S4_TIER1_END_EXCLUSIVE - MOUSE_APP_START
    buf = bytearray([0xFF] * total_len)
    buf[: len(stock_bytes)] = stock_bytes
    buf[S4_TIER1_CANARY_ADDR - MOUSE_APP_START] = S4_CANARY_BYTE
    chunks = build_program_plan(MOUSE_APP_START, bytes(buf), device_id=0)
    if len(chunks) != S4_TIER1_CHUNKS:
        raise AssertionError(f"Unexpected Tier 1 chunk count {len(chunks)} != {S4_TIER1_CHUNKS}")
    return chunks


def _build_tier2_canary_chunks(stock_bytes: bytes) -> list[FlashChunk]:
    total_len = S4_EXT_END_EXCLUSIVE - MOUSE_APP_START
    buf = bytearray([0xFF] * total_len)
    buf[: len(stock_bytes)] = stock_bytes
    buf[S4_EXT_START - MOUSE_APP_START] = S4_CANARY_BYTE
    buf[(S4_EXT_END_EXCLUSIVE - 1) - MOUSE_APP_START] = S4_CANARY_BYTE
    chunks = build_program_plan(MOUSE_APP_START, bytes(buf), device_id=0)
    if len(chunks) != S4_TIER2_CHUNKS:
        raise AssertionError(f"Unexpected Tier 2 chunk count {len(chunks)} != {S4_TIER2_CHUNKS}")
    return chunks


def _read_all_ff_flag(
    transport: FeatureTransport,
    addr: int,
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> tuple[bool, dict[str, Any]]:
    try:
        plain = _verify_read_block(
            transport,
            addr,
            MAX_PROGRAM_CHUNK,
            retry_max=5,
            sleep_fn=sleep_fn,
            perf_counter_fn=perf_counter_fn,
        )
    except S3FlashExecutionError as exc:
        return False, {"address": f"0x{addr:08X}", "all_ff": False, "error": _format_error_details(exc)}
    is_ff = all(b == 0xFF for b in plain)
    return is_ff, {"address": f"0x{addr:08X}", "all_ff": is_ff, "data_hex": plain.hex()}


def _run_tier1_canary(
    transport_factory: Callable[[], FeatureTransport],
    transport: FeatureTransport,
    chunks: list[FlashChunk],
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> tuple[FeatureTransport, bool, dict[str, Any]]:
    tier1_res: dict[str, Any] = {
        "span": f"0x{MOUSE_APP_START:08X}..0x{S4_TIER1_END_EXCLUSIVE:08X}",
        "canary_addr": f"0x{S4_TIER1_CANARY_ADDR:08X}",
        "canary_byte": f"0x{S4_CANARY_BYTE:02X}",
        "chunks_planned": len(chunks),
        "erased": False,
        "writable": False,
        "verified": False,
        "boots": False,
        "retries_4k": 0,
        "fw_after": None,
        "error": None,
    }
    try:
        _erase_bootloader(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
        tier1_res["erased"] = True
        tier1_res["retries_4k"] = _program_chunks(
            transport, chunks, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
        )
        tier1_res["writable"] = True
        _verify_chunks(transport, chunks, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
        tier1_res["verified"] = True
    except S3FlashExecutionError as exc:
        tier1_res["error"] = _format_error_details(exc)
        return transport, True, tier1_res

    transport, fw_after = _exit_bootloader_to_app(
        transport_factory, transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
    )
    tier1_res["boots"] = fw_after == STOCK_MOUSE_EXPECTED_FW
    tier1_res["fw_after"] = fw_after
    return transport, False, tier1_res


def _run_tier2_canary(
    transport_factory: Callable[[], FeatureTransport],
    transport: FeatureTransport,
    chunks: list[FlashChunk],
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> tuple[FeatureTransport, bool, dict[str, Any]]:
    tier2_res: dict[str, Any] = {
        "executed": True,
        "span": f"0x{MOUSE_APP_START:08X}..0x{S4_EXT_END_EXCLUSIVE:08X}",
        "canary_addrs": [f"0x{S4_EXT_START:08X}", f"0x{S4_EXT_END_EXCLUSIVE - 1:08X}"],
        "chunks_planned": len(chunks),
        "tier1_erased_cleanly": False,
        "phase3_ext_writable": False,
        "phase3_ext_verified": False,
        "phase3_ext_boots": False,
        "phase3_ext_erased_by_bl": False,
        "retries_4k": 0,
        "fw_after": None,
        "erase_ceiling_checks": {},
        "error": None,
    }
    transport, _bl_fw = _reenter_bootloader_from_current(
        transport_factory, transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
    )
    _erase_bootloader(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
    t1_erased, t1_check = _read_all_ff_flag(
        transport, 0x00022FE0, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
    )
    tier2_res["tier1_erased_cleanly"] = t1_erased
    tier2_res["tier1_erase_check"] = t1_check

    try:
        tier2_res["retries_4k"] = _program_chunks(
            transport, chunks, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
        )
        tier2_res["phase3_ext_writable"] = True
        _verify_chunks(transport, chunks, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
        tier2_res["phase3_ext_verified"] = True
    except S3FlashExecutionError as exc:
        tier2_res["error"] = _format_error_details(exc)
        return transport, True, tier2_res

    transport, fw_after = _exit_bootloader_to_app(
        transport_factory, transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
    )
    tier2_res["phase3_ext_boots"] = fw_after == STOCK_MOUSE_EXPECTED_FW
    tier2_res["fw_after"] = fw_after

    # Re-enter Bootloader and check whether Bootloader Erase clears 0x23000..0x24FFF
    transport, _bl_fw = _reenter_bootloader_from_current(
        transport_factory, transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
    )
    _erase_bootloader(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
    ok_23000, check_23000 = _read_all_ff_flag(
        transport, S4_EXT_START, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
    )
    ok_24fe0, check_24fe0 = _read_all_ff_flag(
        transport, 0x00024FE0, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
    )
    tier2_res["erase_ceiling_checks"] = {
        "0x00023000": check_23000,
        "0x00024FE0": check_24fe0,
    }
    tier2_res["phase3_ext_erased_by_bl"] = bool(ok_23000 and ok_24fe0)
    return transport, True, tier2_res


def _mandatory_stock_restore(
    transport_factory: Callable[[], FeatureTransport],
    transport: FeatureTransport,
    *,
    in_bootloader: bool,
    stock_img: ValidatedMouseImage,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> tuple[FeatureTransport, dict[str, Any]]:
    """Unconditionally flash pure stock mouse APP (3,665 chunks) and exit to 0x3508."""
    if not in_bootloader:
        transport, _bl_fw = _reenter_bootloader_from_current(
            transport_factory, transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
        )
    _erase_bootloader(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
    retries_4k = _program_chunks(
        transport, stock_img.chunks, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
    )
    _verify_chunks(
        transport, stock_img.chunks, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
    )
    transport, fw_after = _exit_bootloader_to_app(
        transport_factory, transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
    )
    return transport, {
        "stock_restored_clean": fw_after == STOCK_MOUSE_EXPECTED_FW,
        "packets_programmed": len(stock_img.chunks),
        "packets_verified": len(stock_img.chunks),
        "retries_4k": retries_4k,
        "fw_after": fw_after,
        "reset_device_sent": False,
    }


def run_s4_canary(
    hex_path: Path | str,
    *,
    blank_probe_report: Path | str | None = None,
    execute: bool = False,
    confirm_s4: bool = False,
    report_path: Path | str | None = None,
    transport_factory: Callable[[], FeatureTransport] = HidApiTransport,
    sleep_fn: Callable[[float], None] = time.sleep,
    perf_counter_fn: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Run strictly-gated S4 2-tier canary with mandatory pure-stock restore."""
    stock_img = validate_stock_mouse_hex_only(hex_path)
    stock_bytes = _extract_stock_bytes(stock_img)
    tier1_chunks = _build_tier1_canary_chunks(stock_bytes)
    tier2_chunks = _build_tier2_canary_chunks(stock_bytes)
    dry_run = not (execute and confirm_s4)

    bp_data: dict[str, Any] | None = None
    if not dry_run:
        bp_data = _load_and_validate_blank_probe_report(blank_probe_report)

    transport = transport_factory()
    opened = False
    in_bootloader = False
    execution_started = False
    restore_result: dict[str, Any] | None = None

    try:
        devices = transport.enumerate_devices(VENDOR_ID)
        dev = select_wired_mouse_device(devices)
        transport.open(dev.path)
        opened = True

        if dry_run:
            preflight = _preflight_read_only(
                transport, dev, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn
            )
            result: dict[str, Any] = {
                "stage": "S4_CANARY",
                "dry_run": True,
                "executed": False,
                "writes_sent": 0,
                "device": _device_summary(dev),
                "preflight": preflight,
                "tier1_planned_chunks": len(tier1_chunks),
                "tier2_planned_chunks": len(tier2_chunks),
                "reset_device_sent": False,
                "image": stock_img.to_summary(),
            }
        else:
            assert bp_data is not None
            tier2_allowed = bp_data.get("ext_23000_24fff_all_ff") is True

            transport, _bl_dev, bl_fw, fw_before = _enter_bootloader(
                transport_factory,
                transport,
                dev,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            in_bootloader = True
            execution_started = True

            transport, in_bootloader, tier1_res = _run_tier1_canary(
                transport_factory,
                transport,
                tier1_chunks,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )

            tier1_passed = bool(
                tier1_res["writable"] and tier1_res["verified"] and tier1_res["boots"]
            )
            if tier2_allowed and tier1_passed:
                transport, in_bootloader, tier2_res = _run_tier2_canary(
                    transport_factory,
                    transport,
                    tier2_chunks,
                    sleep_fn=sleep_fn,
                    perf_counter_fn=perf_counter_fn,
                )
            else:
                reason = (
                    "tier1_failed"
                    if not tier1_passed
                    else "ext_23000_24fff_all_ff is not True in blank probe report"
                )
                tier2_res = {
                    "executed": False,
                    "skipped_reason": reason,
                    "phase3_ext_writable": False,
                    "phase3_ext_boots": False,
                    "phase3_ext_erased_by_bl": False,
                }

            transport, restore_result = _mandatory_stock_restore(
                transport_factory,
                transport,
                in_bootloader=in_bootloader,
                stock_img=stock_img,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            in_bootloader = False

            result = {
                "stage": "S4_CANARY",
                "dry_run": False,
                "executed": True,
                "fw_before": fw_before,
                "bl_fw": bl_fw,
                "blank_probe_report": str(blank_probe_report),
                "tier1": tier1_res,
                "tier2": tier2_res,
                "stock_restore": restore_result,
                "stock_restored_clean": restore_result["stock_restored_clean"],
                "reset_device_sent": False,
                "image": stock_img.to_summary(),
            }
    finally:
        if execution_started and restore_result is None:
            try:
                transport, restore_result = _mandatory_stock_restore(
                    transport_factory,
                    transport,
                    in_bootloader=in_bootloader,
                    stock_img=stock_img,
                    sleep_fn=sleep_fn,
                    perf_counter_fn=perf_counter_fn,
                )
            except Exception:
                pass
        if opened:
            try:
                transport.close()
            except Exception:
                pass

    _write_report(report_path, result)
    return result
