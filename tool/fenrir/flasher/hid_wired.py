"""Strictly-gated S3 stock-only wired USB mouse flasher (`C52840Dongle` state machine).

Safety invariants enforced unconditionally:
1. Stock-only SHA-256 whitelist (`REFERENCE_FIRMWARES["mouse"].expected_sha256`,
   exact span `0x00006000..0x00022A0C`, `117,260 B`, `3,665` chunks).
2. Wired-only topology gate: rejects if ANY receiver PID (`0x3517`/`0x0017`/`0x0015` etc.)
   is present, rejects BLE paths, and requires exactly 1 wired mouse exact Feature
   interface (`usage_page=0xFFFF, usage=0x0000`) on `0x3508` or `0x3506`.
3. Default `--dry-run`: requires BOTH `execute=True` (`--yes`) AND
   `confirm_stock_s3=True` (`--confirm-stock-s3`) before sending any write/BL frame.
4. Strict abort on `Erase` or `VerifyByAddress` failure (`Verify` aborts BEFORE `Exit`,
   leaving device safely in `0x3506` Bootloader), and NEVER emits `ResetDevice (0xC0 0x02)`.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from fenrir.constants import (
    BLE_PATH_EXCLUDE_SUBSTR,
    EXPECTED_FEATURE_USAGE,
    EXPECTED_FEATURE_USAGE_PAGE,
    HID_FEATURE_REPORT_LEN,
    MOUSE_APP_PIDS,
    MOUSE_BL_PIDS,
    RECEIVER_APP_PIDS,
    RECEIVER_BL_PIDS,
    REFERENCE_FIRMWARES,
    VENDOR_ID,
)
from fenrir.flasher.protocol import (
    BL_MAGIC_B0,
    CMD_GET_FW,
    S2_PENDING_STATUSES,
    S2_SUCCESS_STATUSES,
    FlashChunk,
    build_erase_report,
    build_exit_report,
    build_get_bl_fw_report,
    build_get_fw_report,
    build_set_bl_device_mode_report,
    build_verify_by_address_report,
    decode_verify_reply,
    parse_get_bl_fw_reply,
    parse_get_fw_reply,
)
from fenrir.flasher.safety import (
    MOUSE_APP_START,
    MOUSE_OFFICIAL_APP_END,
    FlashSafetyError,
    ValidatedMouseImage,
    validate_mouse_app_hex,
)
from fenrir.transport.base import DeviceClassification, FeatureTransport, HidDeviceInfo
from fenrir.transport.hid_win import HidApiTransport

STOCK_MOUSE_EXPECTED_SHA256 = REFERENCE_FIRMWARES["mouse"].expected_sha256
STOCK_MOUSE_EXPECTED_BYTES = 117_260
STOCK_MOUSE_EXPECTED_CHUNKS = 3665
STOCK_MOUSE_EXPECTED_FW = "01.00.39.00"

PHASE2_MOUSE_EXPECTED_SHA256 = "195eca525c313a3e6747882d4ca2bd09211a9e0f1011dc225a74de2966c90fdd"
PHASE2_MOUSE_EXPECTED_BYTES = 118_784
PHASE2_MOUSE_EXPECTED_CHUNKS = 3712

PHASE3PLUS_MOUSE_EXPECTED_SHA256 = "f12621981f4ae57c8624606f60548827b2304d89ad647795224809f90346f8bd"
PHASE3PLUS_EXT_END_EXCLUSIVE = 0x00025000
PHASE3PLUS_PADDED_BYTES = PHASE3PLUS_EXT_END_EXCLUSIVE - MOUSE_APP_START  # 126,976 B
PHASE3PLUS_PADDED_CHUNKS = PHASE3PLUS_PADDED_BYTES // 32  # 3,968 chunks

_ALL_RECEIVER_PIDS = RECEIVER_APP_PIDS | RECEIVER_BL_PIDS
_ALL_MOUSE_PIDS = MOUSE_APP_PIDS | MOUSE_BL_PIDS


class StockWhitelistError(FlashSafetyError):
    """Raised when an input HEX does not byte-match the official stock mouse firmware."""


class WiredTopologyError(FlashSafetyError):
    """Raised when USB HID topology violates wired-only single-mouse S3 constraints."""


class S3FlashExecutionError(FlashSafetyError):
    """Raised when S3 bootloader transition, erase, program, verify, or exit fails."""


class ChunkTransferError(S3FlashExecutionError):
    """Execution error carrying failing chunk index, flash address, and reply status bytes."""

    def __init__(
        self,
        message: str,
        *,
        address: int,
        chunk_index: int | None = None,
        rx1: int | None = None,
        rx5: int | None = None,
    ) -> None:
        super().__init__(message)
        self.address = address
        self.chunk_index = chunk_index
        self.rx1 = rx1
        self.rx5 = rx5


def validate_stock_mouse_hex_only(hex_path: Path | str) -> ValidatedMouseImage:
    """Enforce S3 stock-only SHA-256 whitelist and exact APP bounds before any HID access."""
    img = validate_mouse_app_hex(hex_path, allow_last_page_tail=False)
    if img.sha256.lower() != STOCK_MOUSE_EXPECTED_SHA256.lower():
        raise StockWhitelistError(
            f"S3 stock-only flasher rejected non-stock HEX SHA-256 {img.sha256}; "
            f"expected {STOCK_MOUSE_EXPECTED_SHA256}"
        )
    if (
        img.base != MOUSE_APP_START
        or img.end_exclusive != MOUSE_OFFICIAL_APP_END
        or img.byte_length != STOCK_MOUSE_EXPECTED_BYTES
        or len(img.chunks) != STOCK_MOUSE_EXPECTED_CHUNKS
    ):
        raise StockWhitelistError(
            f"Unexpected stock image geometry: [0x{img.base:08X}..0x{img.end_exclusive:08X}) "
            f"{img.byte_length}B / {len(img.chunks)} chunks"
        )
    return img


def _is_ble_device(dev: HidDeviceInfo) -> bool:
    return (
        dev.classification == DeviceClassification.BLE_EXCLUDED
        or BLE_PATH_EXCLUDE_SUBSTR.upper() in dev.path.upper()
    )


_BL_FEATURE_USAGES: frozenset[tuple[int, int]] = frozenset(
    {
        (EXPECTED_FEATURE_USAGE_PAGE, EXPECTED_FEATURE_USAGE),
        (0x000C, 0x0001),  # Real hardware 0x33E4:0x3506 "G-Wolves Fenrir Asym updater" single HID IF
    }
)


def _is_wired_mouse_exact_feature(dev: HidDeviceInfo) -> bool:
    if dev.vid != VENDOR_ID or dev.pid not in _ALL_MOUSE_PIDS or _is_ble_device(dev):
        return False
    if dev.pid in MOUSE_BL_PIDS:
        return (dev.usage_page, dev.usage) in _BL_FEATURE_USAGES
    return (
        dev.usage_page == EXPECTED_FEATURE_USAGE_PAGE
        and dev.usage == EXPECTED_FEATURE_USAGE
    )


def select_wired_mouse_device(
    devices: list[HidDeviceInfo],
    *,
    allowed_pids: frozenset[int] = _ALL_MOUSE_PIDS,
) -> HidDeviceInfo:
    """Enforce wired-only single-mouse topology gate (zero receivers, zero BLE, 1 exact Feature IF)."""
    receivers = [d for d in devices if d.vid == VENDOR_ID and d.pid in _ALL_RECEIVER_PIDS]
    if receivers:
        pids = ", ".join(sorted({f"0x{d.pid:04X}" for d in receivers}))
        raise WiredTopologyError(
            f"Receiver device(s) detected ({pids}); unplug all wireless receivers before S3 wired flash"
        )

    ble_mice = [d for d in devices if d.vid == VENDOR_ID and _is_ble_device(d)]
    exact_mice = [d for d in devices if _is_wired_mouse_exact_feature(d)]
    if ble_mice and not exact_mice:
        raise WiredTopologyError("BLE HID mouse path rejected; connect mouse via wired USB-C cable")
    if ble_mice:
        raise WiredTopologyError("BLE HID mouse path present; disable Bluetooth connection before S3 wired flash")

    matching = [d for d in exact_mice if d.pid in allowed_pids]
    if not matching:
        if exact_mice:
            found = ", ".join(f"0x{d.pid:04X}" for d in exact_mice)
            wanted = ", ".join(f"0x{p:04X}" for p in sorted(allowed_pids))
            raise WiredTopologyError(f"Expected wired mouse PID in {{{wanted}}}, found {found}")
        raise WiredTopologyError(
            "No wired Fenrir mouse exact Feature interface (usage_page=0xFFFF, usage=0x0000) found"
        )
    if len(matching) != 1:
        raise WiredTopologyError(
            f"Expected exactly 1 wired mouse exact Feature interface, found {len(matching)}"
        )
    return matching[0]


def _guard_s3_outgoing(tx: bytes) -> None:
    if len(tx) != HID_FEATURE_REPORT_LEN or tx[0] != 0x00:
        raise S3FlashExecutionError(f"Invalid 65B HID report length={len(tx)} report_id=0x{tx[0]:02X}")
    if tx[3] != 0:
        raise S3FlashExecutionError(f"Non-zero device_id={tx[3]} forbidden on S3 wired flash")
    # Never emit factory reset (0xC0 0x02)
    if tx[4] == 0x00 and tx[5] == 0x00 and tx[6] == 0x00 and tx[7] == 0xC0 and tx[8] == 0x02:
        raise S3FlashExecutionError("Hazardous ResetDevice (0xC0 0x02) unconditionally blocked in S3")


def _delay_us(
    us: int,
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> None:
    if us <= 0:
        return
    if us >= 20_000:
        sleep_fn(us / 1_000_000.0)
        return
    start = perf_counter_fn()
    target = us / 1_000_000.0
    while (perf_counter_fn() - start) < target:
        pass


def _read_reply_with_polls(
    transport: FeatureTransport,
    tx: bytes,
    *,
    fast_poll_32b: bool,
    perf_counter_fn: Callable[[], float],
) -> bytes:
    rx = b""
    if fast_poll_32b:
        t0 = perf_counter_fn()
        while True:
            try:
                rx = transport.get_feature_report(0, HID_FEATURE_REPORT_LEN)
            except OSError:
                rx = bytes(HID_FEATURE_REPORT_LEN)
            if len(rx) == HID_FEATURE_REPORT_LEN and rx[1] != 0x00:
                break
            if (perf_counter_fn() - t0) >= 1.0:
                break
    else:
        rx = transport.get_feature_report(0, HID_FEATURE_REPORT_LEN)

    for _ in range(3):
        if len(rx) == HID_FEATURE_REPORT_LEN and rx[1] not in S2_PENDING_STATUSES:
            break
        rx = transport.get_feature_report(0, HID_FEATURE_REPORT_LEN)
    return rx


def _transact(
    transport: FeatureTransport,
    tx: bytes,
    *,
    delay_us: int,
    retry_max: int,
    read_reply: bool = True,
    fast_poll_32b: bool = False,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> bytes:
    _guard_s3_outgoing(tx)
    cur_delay = delay_us
    last_rx = bytes(HID_FEATURE_REPORT_LEN)

    for _ in range(max(1, retry_max)):
        _delay_us(cur_delay, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
        sent = False
        last_exc: Exception | None = None
        for _ in range(5):
            try:
                transport.send_feature_report(tx)
                sent = True
                break
            except OSError as exc:
                last_exc = exc
        if not sent:
            assert last_exc is not None
            raise last_exc
        if not read_reply:
            return b""

        _delay_us(cur_delay, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
        last_rx = _read_reply_with_polls(
            transport, tx, fast_poll_32b=fast_poll_32b, perf_counter_fn=perf_counter_fn
        )
        if len(last_rx) == HID_FEATURE_REPORT_LEN and last_rx[1] in S2_SUCCESS_STATUSES:
            return last_rx

        # Immediate backoff retry within same outer round per C52840Dongle::nk03RsOKd
        transport.send_feature_report(tx)
        _delay_us(cur_delay, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
        last_rx = _read_reply_with_polls(
            transport, tx, fast_poll_32b=fast_poll_32b, perf_counter_fn=perf_counter_fn
        )
        if len(last_rx) == HID_FEATURE_REPORT_LEN and last_rx[1] in S2_SUCCESS_STATUSES:
            return last_rx
        cur_delay += 100

    return last_rx


def _query_get_fw(
    transport: FeatureTransport,
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> str:
    tx = build_get_fw_report(device_id=0)
    last_rx = bytes(HID_FEATURE_REPORT_LEN)
    for attempt in range(5):
        last_rx = _transact(
            transport,
            tx,
            delay_us=200_000,
            retry_max=3,
            sleep_fn=sleep_fn,
            perf_counter_fn=perf_counter_fn,
        )
        if len(last_rx) == HID_FEATURE_REPORT_LEN and last_rx[1] in S2_SUCCESS_STATUSES and last_rx[6] == CMD_GET_FW:
            return parse_get_fw_reply(last_rx)
        if attempt < 4:
            sleep_fn(0.5)
    raise S3FlashExecutionError(
        f"GetFW failed after retries (status=0x{last_rx[1]:02X}, cmd=0x{last_rx[6]:02X})"
    )


def _query_get_bl_fw(
    transport: FeatureTransport,
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> str:
    rx = _transact(
        transport,
        build_get_bl_fw_report(device_id=0),
        delay_us=100_000,
        retry_max=3,
        sleep_fn=sleep_fn,
        perf_counter_fn=perf_counter_fn,
    )
    if len(rx) != HID_FEATURE_REPORT_LEN or rx[1] not in S2_SUCCESS_STATUSES:
        raise S3FlashExecutionError(f"GetBLFW failed: rx[1]=0x{rx[1]:02X}")
    ver, has_b = parse_get_bl_fw_reply(rx)
    if not has_b:
        raise S3FlashExecutionError(f"GetBLFW response {ver!r} missing Bootloader 'B' tag")
    return ver


def _poll_for_device(
    transport: FeatureTransport,
    *,
    allowed_pids: frozenset[int],
    timeout_s: float,
    poll_s: float,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> HidDeviceInfo | None:
    deadline = perf_counter_fn() + timeout_s
    while True:
        devices = transport.enumerate_devices(VENDOR_ID)
        # Always enforce receiver & BLE rejection on every poll
        receivers = [d for d in devices if d.vid == VENDOR_ID and d.pid in _ALL_RECEIVER_PIDS]
        if receivers:
            raise WiredTopologyError("Receiver detected during S3 re-enumeration")
        if any(d.vid == VENDOR_ID and _is_ble_device(d) for d in devices):
            raise WiredTopologyError("BLE path detected during S3 re-enumeration")
        matches = [d for d in devices if _is_wired_mouse_exact_feature(d) and d.pid in allowed_pids]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise WiredTopologyError(f"Multiple wired mice detected ({len(matches)}) during S3 re-enumeration")
        if perf_counter_fn() >= deadline:
            return None
        sleep_fn(poll_s)


def _enter_bootloader(
    transport_factory: Callable[[], FeatureTransport],
    transport: FeatureTransport,
    dev: HidDeviceInfo,
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> tuple[FeatureTransport, HidDeviceInfo, str, str | None]:
    if dev.pid in MOUSE_BL_PIDS:
        bl_fw = _query_get_bl_fw(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
        return transport, dev, bl_fw, None

    fw_before = _query_get_fw(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
    cur_transport = transport
    cur_dev = dev
    for _round in range(30):
        if cur_dev.pid in MOUSE_APP_PIDS:
            for _ in range(3):
                try:
                    _transact(
                        cur_transport,
                        build_set_bl_device_mode_report(device_id=0),
                        delay_us=500_000,
                        retry_max=1,
                        read_reply=False,
                        sleep_fn=sleep_fn,
                        perf_counter_fn=perf_counter_fn,
                    )
                except OSError:
                    # Mouse may immediately disconnect to re-enumerate as 0x3506.
                    break
        cur_transport.close()
        cur_transport = transport_factory()
        bl_dev = _poll_for_device(
            cur_transport,
            allowed_pids=MOUSE_BL_PIDS,
            timeout_s=10.0,
            poll_s=0.5,
            sleep_fn=sleep_fn,
            perf_counter_fn=perf_counter_fn,
        )
        if bl_dev is not None:
            cur_transport.open(bl_dev.path)
            try:
                bl_fw = _query_get_bl_fw(cur_transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
                return cur_transport, bl_dev, bl_fw, fw_before
            except (S3FlashExecutionError, OSError):
                cur_transport.close()
        re_dev = _poll_for_device(
            cur_transport,
            allowed_pids=_ALL_MOUSE_PIDS,
            timeout_s=0.5,
            poll_s=0.5,
            sleep_fn=sleep_fn,
            perf_counter_fn=perf_counter_fn,
        )
        if re_dev is None:
            cur_transport.close()
            raise S3FlashExecutionError("Mouse disappeared while entering 0x3506 Bootloader")
        cur_dev = re_dev
        cur_transport.open(cur_dev.path)

    cur_transport.close()
    raise S3FlashExecutionError("Timed out waiting 30 rounds for mouse to enter 0x3506 Bootloader")


def _exit_bootloader_to_app(
    transport_factory: Callable[[], FeatureTransport],
    transport: FeatureTransport,
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> tuple[FeatureTransport, str]:
    cur_transport = transport
    try:
        _transact(
            cur_transport,
            build_exit_report(device_id=0),
            delay_us=200,
            retry_max=1,
            sleep_fn=sleep_fn,
            perf_counter_fn=perf_counter_fn,
        )
    except OSError:
        # Bootloader may immediately drop USB to reboot into 0x3508 APP.
        pass
    cur_transport.close()
    sleep_fn(0.5)

    deadline = perf_counter_fn() + 20.0
    app_dev: HidDeviceInfo | None = None
    while True:
        cur_transport = transport_factory()
        try:
            app_dev = _poll_for_device(
                cur_transport,
                allowed_pids=MOUSE_APP_PIDS,
                timeout_s=0.0,
                poll_s=0.5,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            if app_dev is not None:
                break
            bl_dev = _poll_for_device(
                cur_transport,
                allowed_pids=MOUSE_BL_PIDS,
                timeout_s=0.0,
                poll_s=0.5,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            if bl_dev is not None:
                cur_transport.open(bl_dev.path)
                try:
                    _query_get_bl_fw(cur_transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
                    _transact(
                        cur_transport,
                        build_exit_report(device_id=0),
                        delay_us=200,
                        retry_max=1,
                        sleep_fn=sleep_fn,
                        perf_counter_fn=perf_counter_fn,
                    )
                except (S3FlashExecutionError, OSError):
                    pass
                finally:
                    cur_transport.close()
        finally:
            if app_dev is None:
                cur_transport.close()
        if perf_counter_fn() >= deadline:
            raise S3FlashExecutionError("Timed out (20s) waiting for mouse to re-enumerate as 0x3508 after Exit")
        sleep_fn(0.5)

    cur_transport.open(app_dev.path)
    fw_deadline = perf_counter_fn() + 15.0
    fw_after = ""
    while True:
        try:
            fw_after = _query_get_fw(cur_transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
            if fw_after == STOCK_MOUSE_EXPECTED_FW:
                break
        except S3FlashExecutionError:
            pass
        if perf_counter_fn() >= fw_deadline:
            raise S3FlashExecutionError(
                f"Post-Exit GetFW check failed within 15s (got {fw_after!r}, expected {STOCK_MOUSE_EXPECTED_FW!r})"
            )
        sleep_fn(0.5)
    return cur_transport, fw_after


def _erase_bootloader(
    transport: FeatureTransport,
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> None:
    """Execute Bootloader Erase and abort immediately on non-{0x02, 0xA1}."""
    erase_rx = _transact(
        transport,
        build_erase_report(device_id=0),
        delay_us=50,
        retry_max=3,
        sleep_fn=sleep_fn,
        perf_counter_fn=perf_counter_fn,
    )
    if len(erase_rx) != HID_FEATURE_REPORT_LEN or erase_rx[1] not in S2_SUCCESS_STATUSES:
        raise ChunkTransferError(
            f"Bootloader Erase aborted before Program (rx[1]=0x{erase_rx[1]:02X})",
            address=0,
            rx1=erase_rx[1] if len(erase_rx) >= 2 else None,
            rx5=erase_rx[5] if len(erase_rx) >= 6 else None,
        )


def _program_chunks(
    transport: FeatureTransport,
    chunks: list[FlashChunk],
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> int:
    """Program contiguous 32B (+ tail) chunks using S2 4K-boundary & backoff retries."""
    retries_4k = 0
    for chunk in chunks:
        rx = _transact(
            transport,
            chunk.program_report,
            delay_us=500,
            retry_max=50,
            fast_poll_32b=(len(chunk.data) == 32),
            sleep_fn=sleep_fn,
            perf_counter_fn=perf_counter_fn,
        )
        if chunk.is_4k_boundary and rx[5] != BL_MAGIC_B0:
            for _ in range(5):
                retries_4k += 1
                sleep_fn(0.05)
                rx = _transact(
                    transport,
                    chunk.program_report,
                    delay_us=500,
                    retry_max=50,
                    fast_poll_32b=(len(chunk.data) == 32),
                    sleep_fn=sleep_fn,
                    perf_counter_fn=perf_counter_fn,
                )
                if rx[5] == BL_MAGIC_B0:
                    break
        if (
            len(rx) != HID_FEATURE_REPORT_LEN
            or rx[1] not in S2_SUCCESS_STATUSES
            or (chunk.is_4k_boundary and rx[5] != BL_MAGIC_B0)
        ):
            raise ChunkTransferError(
                f"Program aborted at chunk #{chunk.index} addr=0x{chunk.address:08X} "
                f"rx[1]=0x{rx[1]:02X} rx[5]=0x{rx[5]:02X}",
                address=chunk.address,
                chunk_index=chunk.index,
                rx1=rx[1] if len(rx) >= 2 else None,
                rx5=rx[5] if len(rx) >= 6 else None,
            )
    return retries_4k


def _verify_read_block(
    transport: FeatureTransport,
    addr: int,
    length: int = 32,
    *,
    verify_report: bytes | None = None,
    chunk_index: int | None = None,
    retry_max: int = 200,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> bytes:
    """Read and XOR-0x55 decode 1..32 bytes at `addr` via Bootloader VerifyByAddress."""
    tx = verify_report if verify_report is not None else build_verify_by_address_report(addr, length=length, device_id=0)
    rx = _transact(
        transport,
        tx,
        delay_us=500,
        retry_max=retry_max,
        sleep_fn=sleep_fn,
        perf_counter_fn=perf_counter_fn,
    )
    if rx[5] != BL_MAGIC_B0:
        for _ in range(5):
            sleep_fn(0.05)
            rx = _transact(
                transport,
                tx,
                delay_us=500,
                retry_max=retry_max,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            if rx[5] == BL_MAGIC_B0:
                break
    try:
        return decode_verify_reply(rx, length)
    except Exception as exc:
        prefix = f"chunk #{chunk_index} " if chunk_index is not None else ""
        raise ChunkTransferError(
            f"VerifyByAddress failed at {prefix}addr=0x{addr:08X}; "
            f"Exit NOT sent (mouse kept in 0x3506 Bootloader): {exc}",
            address=addr,
            chunk_index=chunk_index,
            rx1=rx[1] if len(rx) >= 2 else None,
            rx5=rx[5] if len(rx) >= 6 else None,
        ) from exc


def _verify_chunks(
    transport: FeatureTransport,
    chunks: list[FlashChunk],
    *,
    sleep_fn: Callable[[float], None],
    perf_counter_fn: Callable[[], float],
) -> None:
    """VerifyByAddress all chunks; raise ChunkTransferError BEFORE Exit on mismatch."""
    for chunk in chunks:
        plain = _verify_read_block(
            transport,
            chunk.address,
            len(chunk.data),
            verify_report=chunk.verify_report,
            chunk_index=chunk.index,
            retry_max=200,
            sleep_fn=sleep_fn,
            perf_counter_fn=perf_counter_fn,
        )
        if plain != chunk.data:
            raise ChunkTransferError(
                f"VerifyByAddress byte mismatch at chunk #{chunk.index} addr=0x{chunk.address:08X}; "
                "Exit NOT sent (mouse kept in 0x3506 Bootloader)",
                address=chunk.address,
                chunk_index=chunk.index,
                rx1=0x02,
                rx5=BL_MAGIC_B0,
            )


def run_stock_wired_flash(
    hex_path: Path | str,
    *,
    execute: bool = False,
    confirm_stock_s3: bool = False,
    wipe_ext: bool = False,
    report_path: Path | str | None = None,
    transport_factory: Callable[[], FeatureTransport] = HidApiTransport,
    sleep_fn: Callable[[float], None] = time.sleep,
    perf_counter_fn: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Validate stock mouse HEX + wired topology, run dry-run preflight or full S3 flash."""
    img = validate_stock_mouse_hex_only(hex_path)
    if wipe_ext:
        from fenrir.flasher.protocol import build_program_plan

        padded = bytearray([0xFF] * PHASE3PLUS_PADDED_BYTES)
        padded[: len(img.data)] = img.data
        chunks = list(build_program_plan(MOUSE_APP_START, bytes(padded), device_id=0))
    else:
        chunks = list(img.chunks)
    dry_run = not (execute and confirm_stock_s3)

    transport = transport_factory()
    opened = False
    try:
        devices = transport.enumerate_devices(VENDOR_ID)
        dev = select_wired_mouse_device(devices)
        transport.open(dev.path)
        opened = True

        if dry_run:
            if dev.pid in MOUSE_APP_PIDS:
                fw_ver = _query_get_fw(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
                preflight = {"mode": "app", "fw_version": fw_ver}
            else:
                bl_ver = _query_get_bl_fw(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
                preflight = {"mode": "bootloader", "bl_fw_version": bl_ver}
            result: dict[str, Any] = {
                "stage": "S3",
                "dry_run": True,
                "executed": False,
                "writes_sent": 0,
                "wipe_ext": wipe_ext,
                "planned_chunks": len(chunks),
                "device": {
                    "vid": dev.vid_hex,
                    "pid": dev.pid_hex,
                    "path": dev.path,
                    "product": dev.product,
                },
                "preflight": preflight,
                "reset_device_sent": False,
                "image": img.to_summary(),
            }
        else:
            transport, _bl_dev, bl_fw, fw_before = _enter_bootloader(
                transport_factory,
                transport,
                dev,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )

            # Erase (abort immediately on non-{0x02, 0xA1} before any Program)
            _erase_bootloader(
                transport,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )

            # Program all chunks (3,665 stock or 3,968 with --wipe-ext)
            retries_4k = _program_chunks(
                transport,
                chunks,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )

            # VerifyByAddress all chunks (abort BEFORE Exit on ANY failure/mismatch)
            _verify_chunks(
                transport,
                chunks,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )

            # Exit Bootloader -> APP (never send ResetDevice 0xC0 0x02)
            transport, fw_after = _exit_bootloader_to_app(
                transport_factory,
                transport,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            result = {
                "stage": "S3",
                "dry_run": False,
                "executed": True,
                "wipe_ext": wipe_ext,
                "planned_chunks": len(chunks),
                "fw_before": fw_before,
                "bl_fw": bl_fw,
                "fw_after": fw_after,
                "packets_programmed": len(chunks),
                "packets_verified": len(chunks),
                "retries_4k": retries_4k,
                "reset_device_sent": False,
                "image": img.to_summary(),
            }
    finally:
        if opened:
            try:
                transport.close()
            except Exception:
                pass

    if report_path is not None:
        out_p = Path(report_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(result, indent=2), encoding="utf-8")
        result["report_file"] = str(out_p)
    return result


def validate_phase2_mouse_hex_only(hex_path: Path | str) -> ValidatedMouseImage:
    """Enforce S5 Phase 2 exact SHA-256 whitelist and [0x6000..0x23000) geometry."""
    img = validate_mouse_app_hex(
        hex_path,
        allow_last_page_tail=True,
        allow_whitelisted_not_for_flash_sha256=PHASE2_MOUSE_EXPECTED_SHA256,
    )
    if img.sha256.lower() != PHASE2_MOUSE_EXPECTED_SHA256:
        raise StockWhitelistError(
            f"S5 Phase 2 flasher rejected non-whitelisted HEX SHA-256 {img.sha256}; "
            f"expected {PHASE2_MOUSE_EXPECTED_SHA256}"
        )
    if (
        img.base != MOUSE_APP_START
        or img.end_exclusive != 0x00023000
        or img.byte_length != PHASE2_MOUSE_EXPECTED_BYTES
        or len(img.chunks) != PHASE2_MOUSE_EXPECTED_CHUNKS
    ):
        raise StockWhitelistError(
            f"Unexpected Phase 2 image geometry: [0x{img.base:08X}..0x{img.end_exclusive:08X}) "
            f"{img.byte_length}B / {len(img.chunks)} chunks"
        )
    return img


def _require_s4_tier1_passed(s4_canary_report: Path | str | None) -> dict[str, Any]:
    if s4_canary_report is None:
        raise FlashSafetyError("S5 Phase 2 live flash requires --s4-canary-report proving Tier 1 passed")
    p = Path(s4_canary_report)
    if not p.exists():
        raise FlashSafetyError(f"S4 canary report not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    t1 = data.get("tier1") or {}
    if not (t1.get("writable") and t1.get("verified") and t1.get("boots")):
        raise FlashSafetyError(f"S4 canary report {p} did not prove Tier 1 writable+verified+boots")
    return data


def run_phase2_wired_flash(
    hex_path: Path | str,
    *,
    s4_canary_report: Path | str | None = None,
    execute: bool = False,
    confirm_phase2_s5: bool = False,
    report_path: Path | str | None = None,
    transport_factory: Callable[[], FeatureTransport] = HidApiTransport,
    sleep_fn: Callable[[float], None] = time.sleep,
    perf_counter_fn: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Validate exact Phase 2 mouse HEX + S4 Tier 1 gate + wired topology, run dry-run or live S5 flash."""
    img = validate_phase2_mouse_hex_only(hex_path)
    dry_run = not (execute and confirm_phase2_s5)
    if not dry_run:
        _require_s4_tier1_passed(s4_canary_report)

    transport = transport_factory()
    opened = False
    try:
        devices = transport.enumerate_devices(VENDOR_ID)
        dev = select_wired_mouse_device(devices)
        transport.open(dev.path)
        opened = True

        if dry_run:
            if dev.pid in MOUSE_APP_PIDS:
                fw_ver = _query_get_fw(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
                preflight = {"mode": "app", "fw_version": fw_ver}
            else:
                bl_ver = _query_get_bl_fw(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
                preflight = {"mode": "bootloader", "bl_fw_version": bl_ver}
            result: dict[str, Any] = {
                "stage": "S5_PHASE2",
                "dry_run": True,
                "executed": False,
                "writes_sent": 0,
                "device": {
                    "vid": dev.vid_hex,
                    "pid": dev.pid_hex,
                    "path": dev.path,
                    "product": dev.product,
                },
                "preflight": preflight,
                "reset_device_sent": False,
                "image": img.to_summary(),
            }
        else:
            transport, _bl_dev, bl_fw, fw_before = _enter_bootloader(
                transport_factory,
                transport,
                dev,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            _erase_bootloader(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
            retries_4k = _program_chunks(
                transport,
                img.chunks,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            _verify_chunks(
                transport,
                img.chunks,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            transport, fw_after = _exit_bootloader_to_app(
                transport_factory,
                transport,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            result = {
                "stage": "S5_PHASE2",
                "dry_run": False,
                "executed": True,
                "fw_before": fw_before,
                "bl_fw": bl_fw,
                "fw_after": fw_after,
                "packets_programmed": len(img.chunks),
                "packets_verified": len(img.chunks),
                "retries_4k": retries_4k,
                "reset_device_sent": False,
                "s4_canary_report": str(s4_canary_report),
                "image": img.to_summary(),
            }
    finally:
        if opened:
            try:
                transport.close()
            except Exception:
                pass

    if report_path is not None:
        out_p = Path(report_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(result, indent=2), encoding="utf-8")
        result["report_file"] = str(out_p)
    return result


def validate_phase3plus_mouse_hex_only(hex_path: Path | str) -> ValidatedMouseImage:
    """Enforce S6 Phase 3+ exact SHA-256 whitelist and 0xFF-padded [0x6000..0x25000) image."""
    import struct as _struct
    from fenrir.emu.hex_loader import HexImage, HexParseError
    from fenrir.flasher.protocol import build_program_plan
    from fenrir.flasher.safety import FlashBoundsError

    path = Path(hex_path)
    if not path.exists():
        raise FileNotFoundError(f"HEX file not found: {path}")
    try:
        hex_img = HexImage(path)
    except (HexParseError, ValueError, UnicodeDecodeError) as exc:
        raise FlashBoundsError(f"Strict Intel HEX validation failed for {path}: {exc}") from exc

    if hex_img.sha256.lower() != PHASE3PLUS_MOUSE_EXPECTED_SHA256:
        raise StockWhitelistError(
            f"S6 Phase 3+ flasher rejected non-whitelisted HEX SHA-256 {hex_img.sha256}; "
            f"expected {PHASE3PLUS_MOUSE_EXPECTED_SHA256}"
        )
    if hex_img.base != MOUSE_APP_START or hex_img.end > PHASE3PLUS_EXT_END_EXCLUSIVE:
        raise FlashBoundsError(
            f"Phase 3+ HEX out of S4-verified range [0x{MOUSE_APP_START:08X}..0x{PHASE3PLUS_EXT_END_EXCLUSIVE:08X}): "
            f"[0x{hex_img.base:08X}..0x{hex_img.end:08X})"
        )
    for addr in hex_img.mem:
        if addr < MOUSE_APP_START or addr >= PHASE3PLUS_EXT_END_EXCLUSIVE:
            raise FlashBoundsError(f"Phase 3+ HEX byte at 0x{addr:08X} violates [0x6000..0x25000)")

    # Build contiguous 0xFF-padded 126,976B (3,968 x 32B) image matching S4 Tier 2 geometry
    buf = bytearray([0xFF] * PHASE3PLUS_PADDED_BYTES)
    for addr, val in hex_img.mem.items():
        buf[addr - MOUSE_APP_START] = val
    data = bytes(buf)
    initial_sp, reset_vector = _struct.unpack_from("<II", data, 0)
    if initial_sp != 0x2000BCA0 or reset_vector != 0x000064A5:
        raise FlashBoundsError(
            f"Unexpected Phase 3+ vectors: SP=0x{initial_sp:08X}, Reset=0x{reset_vector:08X}"
        )
    chunks = tuple(build_program_plan(MOUSE_APP_START, data, device_id=0))
    if len(chunks) != PHASE3PLUS_PADDED_CHUNKS:
        raise StockWhitelistError(f"Unexpected Phase 3+ chunk count {len(chunks)} != {PHASE3PLUS_PADDED_CHUNKS}")
    return ValidatedMouseImage(
        path=path,
        sha256=hex_img.sha256,
        base=MOUSE_APP_START,
        end_exclusive=PHASE3PLUS_EXT_END_EXCLUSIVE,
        data=data,
        initial_sp=initial_sp,
        reset_vector=reset_vector,
        chunks=chunks,
    )


def _require_s4_tier2_passed(s4_canary_report: Path | str | None) -> dict[str, Any]:
    data = _require_s4_tier1_passed(s4_canary_report)
    t2 = data.get("tier2") or {}
    if not (
        t2.get("phase3_ext_writable")
        and t2.get("phase3_ext_verified")
        and t2.get("phase3_ext_boots")
    ):
        raise FlashSafetyError(
            f"S4 canary report {s4_canary_report} did not prove Tier 2 (0x23000..0x24FFF) writable+verified+boots"
        )
    return data


def run_phase3plus_wired_flash(
    hex_path: Path | str,
    *,
    s4_canary_report: Path | str | None = None,
    execute: bool = False,
    confirm_phase3plus_s6: bool = False,
    report_path: Path | str | None = None,
    transport_factory: Callable[[], FeatureTransport] = HidApiTransport,
    sleep_fn: Callable[[float], None] = time.sleep,
    perf_counter_fn: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Validate exact Phase 3+ HEX + S4 Tier 1/2 gate + wired topology, run dry-run or live S6 flash."""
    img = validate_phase3plus_mouse_hex_only(hex_path)
    dry_run = not (execute and confirm_phase3plus_s6)
    if not dry_run:
        _require_s4_tier2_passed(s4_canary_report)

    transport = transport_factory()
    opened = False
    try:
        devices = transport.enumerate_devices(VENDOR_ID)
        dev = select_wired_mouse_device(devices)
        transport.open(dev.path)
        opened = True

        if dry_run:
            if dev.pid in MOUSE_APP_PIDS:
                fw_ver = _query_get_fw(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
                preflight = {"mode": "app", "fw_version": fw_ver}
            else:
                bl_ver = _query_get_bl_fw(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
                preflight = {"mode": "bootloader", "bl_fw_version": bl_ver}
            result: dict[str, Any] = {
                "stage": "S6_PHASE3PLUS",
                "dry_run": True,
                "executed": False,
                "writes_sent": 0,
                "device": {
                    "vid": dev.vid_hex,
                    "pid": dev.pid_hex,
                    "path": dev.path,
                    "product": dev.product,
                },
                "preflight": preflight,
                "reset_device_sent": False,
                "image": img.to_summary(),
            }
        else:
            transport, _bl_dev, bl_fw, fw_before = _enter_bootloader(
                transport_factory,
                transport,
                dev,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            _erase_bootloader(transport, sleep_fn=sleep_fn, perf_counter_fn=perf_counter_fn)
            retries_4k = _program_chunks(
                transport,
                img.chunks,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            _verify_chunks(
                transport,
                img.chunks,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            transport, fw_after = _exit_bootloader_to_app(
                transport_factory,
                transport,
                sleep_fn=sleep_fn,
                perf_counter_fn=perf_counter_fn,
            )
            result = {
                "stage": "S6_PHASE3PLUS",
                "dry_run": False,
                "executed": True,
                "fw_before": fw_before,
                "bl_fw": bl_fw,
                "fw_after": fw_after,
                "packets_programmed": len(img.chunks),
                "packets_verified": len(img.chunks),
                "retries_4k": retries_4k,
                "reset_device_sent": False,
                "s4_canary_report": str(s4_canary_report),
                "image": img.to_summary(),
            }
    finally:
        if opened:
            try:
                transport.close()
            except Exception:
                pass

    if report_path is not None:
        out_p = Path(report_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(result, indent=2), encoding="utf-8")
        result["report_file"] = str(out_p)
    return result
