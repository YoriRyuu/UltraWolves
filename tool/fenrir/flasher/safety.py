"""Hard no-brick safety guards and offline-only S2 execution locks."""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fenrir.constants import MOUSE_APP_PIDS, MOUSE_BL_PIDS, VENDOR_ID
from fenrir.emu.hex_loader import HexImage, HexParseError
from fenrir.flasher.protocol import (
    BL_MAGIC_B0,
    CMD_BL_ERASE,
    CMD_BL_EXIT,
    CMD_BL_GET_FW,
    CMD_BL_PROGRAM,
    CMD_BL_VERIFY_ADDR,
    CMD_GET_DEVICE_MODE,
    CMD_GET_FW,
    HID_REPORT_LEN,
    MAX_PROGRAM_CHUNK,
    S2_SUCCESS_STATUSES,
    FlashChunk,
    build_erase_report,
    build_exit_report,
    build_get_bl_fw_report,
    build_get_fw_report,
    build_program_plan,
    build_set_bl_device_mode_report,
    decode_verify_reply,
    parse_get_bl_fw_reply,
    parse_get_fw_reply,
    xor_obfuscate_payload,
)

MOUSE_APP_START = 0x00006000
MOUSE_OFFICIAL_APP_END = 0x00022A0C
MOUSE_APP_PAGE_LIMIT = 0x00023000

PROTECTED_BOOTLOADER_RANGE = (0x00000000, MOUSE_APP_START)
PROTECTED_UPPER_REGIONS: tuple[tuple[int, int, str], ...] = (
    (0x00050000, 0x00051000, "Stock default-clear flash page 0x50000"),
    (0x0008C000, 0x0008D000, "Stock object/macro metadata index page 0x8C000"),
    (0x00090000, 0x000E0000, "Stock dynamic macro/object pool 0x90000..0xDFFFF"),
    (0x000EB000, 0x000EC000, "Stock secondary config page 0xEB000"),
    (0x000EC000, 0x000ED000, "Stock primary config page 0xEC000"),
    (0x10000000, 0x10002000, "nRF52840 FICR / UICR read-only hardware registers"),
)

_FORBIDDEN_MANIFEST_FLAGS: tuple[str, ...] = (
    "not_for_flash",
    "offline_only",
    "extended_flash_range_unverified_by_bootloader",
    "dual_mcu_dependency_high_risk",
)


class FlashSafetyError(PermissionError):
    """Base safety rejection for Fenrir S2 flasher guards."""


class RealHardwareFlashBlockedError(FlashSafetyError):
    """Raised unconditionally whenever real USB/HID flashing is attempted."""


class NotForFlashError(FlashSafetyError):
    """Raised when a HEX/manifest carries NOT_FOR_FLASH or offline-only restrictions."""


class FlashBoundsError(FlashSafetyError):
    """Raised when a HEX image fails checksum, gap, address-bound, or vector checks."""


@dataclass(frozen=True)
class ValidatedMouseImage:
    path: Path
    sha256: str
    base: int
    end_exclusive: int
    data: bytes
    initial_sp: int
    reset_vector: int
    chunks: tuple[FlashChunk, ...]

    @property
    def byte_length(self) -> int:
        return len(self.data)

    def to_summary(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "hex_sha256": self.sha256,
            "image_sha256": hashlib.sha256(self.data).hexdigest(),
            "base": f"0x{self.base:08X}",
            "end_exclusive": f"0x{self.end_exclusive:08X}",
            "bytes": self.byte_length,
            "initial_sp": f"0x{self.initial_sp:08X}",
            "reset_vector": f"0x{self.reset_vector:08X}",
            "chunk_count": len(self.chunks),
            "chunks_4k_boundaries": sum(1 for c in self.chunks if c.is_4k_boundary),
        }


def assert_not_for_flash_free(hex_path: Path) -> None:
    """Reject any path, filename, or sibling manifest marked NOT_FOR_FLASH / offline_only."""
    resolved = Path(hex_path)
    upper_parts = [p.upper() for p in resolved.parts]
    if any("NOT_FOR_FLASH" in part for part in upper_parts):
        raise NotForFlashError(f"Refusing NOT_FOR_FLASH artifact: {resolved}")

    candidates = [
        resolved.with_suffix(".manifest.json"),
        resolved.parent / f"{resolved.name}.manifest.json",
    ]
    for manifest_path in candidates:
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise NotForFlashError(f"Unreadable sibling manifest {manifest_path}: {exc}") from exc
            if not isinstance(manifest, dict):
                raise NotForFlashError(f"Invalid manifest JSON object in {manifest_path}")
            for flag in _FORBIDDEN_MANIFEST_FLAGS:
                if manifest.get(flag):
                    raise NotForFlashError(f"Manifest {manifest_path.name} sets {flag}=true")
            if manifest.get("hardware_flashing_supported") is False:
                raise NotForFlashError(f"Manifest {manifest_path.name} sets hardware_flashing_supported=false")


def _check_address_bounds(addr: int, *, max_end: int) -> None:
    if addr < MOUSE_APP_START:
        raise FlashBoundsError(
            f"Address 0x{addr:08X} enters protected Bootloader/SoftDevice/MBR region (< 0x{MOUSE_APP_START:08X})"
        )
    for lo, hi, desc in PROTECTED_UPPER_REGIONS:
        if lo <= addr < hi:
            raise FlashBoundsError(f"Address 0x{addr:08X} enters protected region: {desc}")
    if addr >= MOUSE_APP_PAGE_LIMIT:
        raise FlashBoundsError(
            f"Address 0x{addr:08X} exceeds verified page boundary < 0x{MOUSE_APP_PAGE_LIMIT:08X}"
        )
    if addr >= max_end:
        raise FlashBoundsError(
            f"Address 0x{addr:08X} exceeds official APP bound 0x{max_end:08X} (enable --allow-tail-page only within 0x22FFF)"
        )


def validate_mouse_app_hex(
    hex_path: Path | str,
    *,
    allow_last_page_tail: bool = False,
    allow_whitelisted_not_for_flash_sha256: str | None = None,
) -> ValidatedMouseImage:
    """Strictly parse Intel HEX and enforce all S2 no-brick & vector invariants."""
    path = Path(hex_path)
    if not path.exists():
        raise FileNotFoundError(f"HEX file not found: {path}")
    if allow_whitelisted_not_for_flash_sha256 is None:
        assert_not_for_flash_free(path)
    else:
        file_sha = hashlib.sha256(path.read_bytes()).hexdigest().lower()
        if file_sha != allow_whitelisted_not_for_flash_sha256.lower():
            assert_not_for_flash_free(path)

    try:
        img = HexImage(path)
    except (HexParseError, ValueError, UnicodeDecodeError) as exc:
        raise FlashBoundsError(f"Strict Intel HEX validation failed for {path}: {exc}") from exc

    max_end = MOUSE_APP_PAGE_LIMIT if allow_last_page_tail else MOUSE_OFFICIAL_APP_END
    for addr in sorted(img.mem):
        _check_address_bounds(addr, max_end=max_end)

    if len(img.ranges) != 1:
        raise FlashBoundsError(
            f"Non-contiguous Intel HEX image rejected (found {len(img.ranges)} spans: {img.ranges}); silent 0x00 gap fill forbidden"
        )
    if img.base != MOUSE_APP_START:
        raise FlashBoundsError(
            f"Mouse APP HEX must start at 0x{MOUSE_APP_START:08X}, got 0x{img.base:08X}"
        )

    data = img.get(img.base, img.end - img.base)
    if len(data) < 8:
        raise FlashBoundsError(f"Mouse APP image too short for ARM vector table ({len(data)}B)")

    initial_sp, reset_vector = struct.unpack_from("<II", data, 0)
    if not (0x20000000 <= initial_sp <= 0x20040000) or (initial_sp & 0x3) != 0:
        raise FlashBoundsError(
            f"Invalid Cortex-M4 initial SP 0x{initial_sp:08X}; expected 4B-aligned nRF52840 SRAM [0x20000000..0x20040000]"
        )
    reset_target = reset_vector & ~1
    if (reset_vector & 1) != 1 or not (img.base <= reset_target < img.end):
        raise FlashBoundsError(
            f"Invalid Cortex-M4 reset vector 0x{reset_vector:08X}; expected Thumb target inside [0x{img.base:08X}, 0x{img.end:08X})"
        )

    chunks = tuple(build_program_plan(img.base, data, device_id=0))
    return ValidatedMouseImage(
        path=path,
        sha256=img.sha256,
        base=img.base,
        end_exclusive=img.end,
        data=data,
        initial_sp=initial_sp,
        reset_vector=reset_vector,
        chunks=chunks,
    )


def enforce_wired_flash_policy(
    *,
    device_id: int = 0,
    vid: int = VENDOR_ID,
    pid: int = 0x3508,
    offline_mock_only: bool = True,
) -> None:
    """Enforce S2 wired-only (`deviceID=0`), Mouse PID-only, and offline real-HID execution lock."""
    if offline_mock_only:
        return
    if device_id != 0:
        raise FlashSafetyError(f"Wireless/non-zero device_id={device_id} forbidden for S2 flasher")
    if vid != VENDOR_ID or pid not in (MOUSE_APP_PIDS | MOUSE_BL_PIDS):
        raise FlashSafetyError(f"Unsupported VID:PID 0x{vid:04X}:0x{pid:04X} for wired mouse S2 flasher")
    raise RealHardwareFlashBlockedError(
        "Real USB/HID flashing is strictly locked off in S2; only --dry-run and offline mock replay are permitted"
    )


def assert_offline_only_target(target: Any) -> None:
    """Block any attempt to execute flash writes against non-mock (e.g., live HID) transports."""
    if not isinstance(target, OfflineMockBootloader):
        raise RealHardwareFlashBlockedError(
            "Real HID / hardware flash execution is locked off; pass an OfflineMockBootloader instance only"
        )


class OfflineMockBootloader:
    """In-memory offline mock implementing S2 APP<->Bootloader HID Feature protocol."""

    def __init__(
        self,
        *,
        app_pid: int = 0x3508,
        fw_version: tuple[int, int, int, int] = (1, 0, 39, 0),
        bl_version: tuple[int, int, int, int] = (0x01, 0x0B, 0x00, 0x01),
        max_app_end: int = MOUSE_APP_PAGE_LIMIT,
        inject_erase_fail: bool = False,
        inject_verify_mismatch_addr: int | None = None,
        inject_4k_retry_once: bool = False,
    ) -> None:
        self.app_pid = app_pid
        self.pid = app_pid
        self.fw_version = fw_version
        self.bl_version = bl_version
        self.max_app_end = max_app_end
        self.inject_erase_fail = inject_erase_fail
        self.inject_verify_mismatch_addr = inject_verify_mismatch_addr
        self.inject_4k_retry_once = inject_4k_retry_once
        self._retry_4k_used = False

        self.in_bootloader = False
        self.flash = bytearray([0xFF] * max_app_end)
        # Sentinel in protected bootloader region (< 0x6000) to assert zero corruption
        self._bootloader_sentinel = bytes((i & 0xFF for i in range(MOUSE_APP_START)))
        self.flash[:MOUSE_APP_START] = self._bootloader_sentinel
        self.last_reply = bytes(HID_REPORT_LEN)
        self.tx_log: list[bytes] = []

    def send_feature(self, tx: bytes) -> None:
        if len(tx) != HID_REPORT_LEN or tx[0] != 0x00:
            raise FlashSafetyError(f"Expected 65B report with tx[0]==0x00, got len={len(tx)}")
        if tx[3] != 0:
            raise FlashSafetyError(f"Mock requires wired device_id=0, got {tx[3]}")
        self.tx_log.append(bytes(tx))
        rx = bytearray(HID_REPORT_LEN)
        rx[0] = 0x00
        rx[1] = 0xA1
        rx[2:6] = tx[2:6]
        rx[6] = tx[6]

        # APP mode handlers
        if not self.in_bootloader:
            if tx[4] == 0x01 and tx[5] == 0x00 and tx[6] == CMD_GET_DEVICE_MODE:
                rx[7] = 0x00
                self.last_reply = bytes(rx)
                return
            if tx[4] == 0x03 and tx[5] == 0x00 and tx[6] == CMD_GET_FW:
                rx[7:11] = bytes(self.fw_version)
                self.last_reply = bytes(rx)
                return
            if tx[4] == 0x01 and tx[5] == 0x00 and tx[6] == 0x00 and tx[7] == BL_MAGIC_B0:
                self.in_bootloader = True
                self.pid = 0x3506
                self.last_reply = bytes(rx)
                return
            if tx[5] == BL_MAGIC_B0:
                rx[1] = 0xA2
                self.last_reply = bytes(rx)
                return
            rx[1] = 0xA3
            self.last_reply = bytes(rx)
            return

        # Bootloader mode (0xB0)
        if tx[5] != BL_MAGIC_B0:
            rx[1] = 0xA3
            self.last_reply = bytes(rx)
            return
        cmd = tx[6]
        if cmd == CMD_BL_GET_FW:
            rx[9:13] = bytes(self.bl_version)
        elif cmd == CMD_BL_ERASE:
            if self.inject_erase_fail:
                rx[1] = 0xA2
            else:
                self.flash[MOUSE_APP_START:self.max_app_end] = b"\xFF" * (self.max_app_end - MOUSE_APP_START)
        elif cmd == CMD_BL_PROGRAM:
            n = tx[7]
            addr = struct.unpack_from(">I", tx, 8)[0]
            if not (1 <= n <= MAX_PROGRAM_CHUNK) or addr < MOUSE_APP_START or addr + n > self.max_app_end:
                rx[1] = 0xA2
            else:
                if self.inject_4k_retry_once and not self._retry_4k_used and ((addr + n) & 0xFFF) == 0:
                    self._retry_4k_used = True
                    rx[1] = 0x01
                    rx[5] = 0x00
                else:
                    plain = xor_obfuscate_payload(bytes(tx[12 : 12 + n]))
                    self.flash[addr : addr + n] = plain
        elif cmd == CMD_BL_VERIFY_ADDR:
            n = tx[7]
            addr = struct.unpack_from(">I", tx, 8)[0]
            if not (1 <= n <= MAX_PROGRAM_CHUNK) or addr < MOUSE_APP_START or addr + n > self.max_app_end:
                rx[1] = 0xA2
            else:
                plain = bytearray(self.flash[addr : addr + n])
                if (
                    self.inject_verify_mismatch_addr is not None
                    and addr <= self.inject_verify_mismatch_addr < addr + n
                ):
                    plain[self.inject_verify_mismatch_addr - addr] ^= 0xFF
                rx[12 : 12 + n] = xor_obfuscate_payload(bytes(plain))
        elif cmd == CMD_BL_EXIT and tx[7] == 0x01:
            self.in_bootloader = False
            self.pid = self.app_pid
        else:
            rx[1] = 0xA3
        self.last_reply = bytes(rx)

    def get_feature(self) -> bytes:
        return self.last_reply

    def exchange(self, tx: bytes) -> bytes:
        self.send_feature(tx)
        return self.get_feature()

    def bootloader_region_intact(self) -> bool:
        return bytes(self.flash[:MOUSE_APP_START]) == self._bootloader_sentinel


def run_offline_mock_flash(
    image: ValidatedMouseImage,
    mock: OfflineMockBootloader,
    *,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Replay full S2 update flow on OfflineMockBootloader only (strictly refuses real HID)."""
    assert_offline_only_target(mock)
    plan_summary = image.to_summary()
    if dry_run:
        return {
            "dry_run": True,
            "mode": "offline_mock_plan_only",
            "image": plan_summary,
            "first_program_hex": image.chunks[0].program_report.hex(),
            "last_program_hex": image.chunks[-1].program_report.hex(),
            "executed": False,
        }

    # Step 1: Wired GetFW fingerprint before entering Bootloader
    fw_before = parse_get_fw_reply(mock.exchange(build_get_fw_report(device_id=0)))

    # Step 2: Enter Bootloader (SetBLDeviceMode is SetFeature-only) & verify GetBLFW contains 'B'
    mock.send_feature(build_set_bl_device_mode_report(device_id=0))
    if mock.pid != 0x3506 or not mock.in_bootloader:
        raise FlashSafetyError(f"Mock failed to enter bootloader PID 0x3506 (pid=0x{mock.pid:04X})")
    bl_ver, has_b = parse_get_bl_fw_reply(mock.exchange(build_get_bl_fw_report(device_id=0)))
    if not has_b:
        raise FlashSafetyError(f"GetBLFW missing 'B' marker: {bl_ver}")

    # Step 3: Erase (STRICT abort on non-{0x02, 0xA1}, fixing official updater bug)
    erase_rx = mock.exchange(build_erase_report(device_id=0))
    if erase_rx[1] not in S2_SUCCESS_STATUSES:
        raise FlashSafetyError(f"Bootloader Erase aborted cleanly on rx[1]=0x{erase_rx[1]:02X}")

    # Step 4: Program all chunks (respecting 4K boundary rx[5]==0xB0 check & retry)
    retries_4k = 0
    for chunk in image.chunks:
        rx = mock.exchange(chunk.program_report)
        if chunk.is_4k_boundary and rx[5] != BL_MAGIC_B0:
            retries_4k += 1
            rx = mock.exchange(chunk.program_report)
        if rx[1] not in S2_SUCCESS_STATUSES or (chunk.is_4k_boundary and rx[5] != BL_MAGIC_B0):
            raise FlashSafetyError(
                f"Program failed at chunk #{chunk.index} addr=0x{chunk.address:08X} rx[1]=0x{rx[1]:02X} rx[5]=0x{rx[5]:02X}"
            )

    # Step 5: Full VerifyByAddress XOR 0x55 check (STRICT abort before Exit on mismatch)
    for chunk in image.chunks:
        rx = mock.exchange(chunk.verify_report)
        decoded = decode_verify_reply(rx, len(chunk.data))
        if decoded != chunk.data:
            raise FlashSafetyError(
                f"VerifyByAddress byte mismatch at addr=0x{chunk.address:08X}; Exit NOT sent"
            )

    # Step 6: Exit Bootloader -> APP (no ResetDevice 0xC0 0x02)
    exit_rx = mock.exchange(build_exit_report(device_id=0))
    if exit_rx[1] not in S2_SUCCESS_STATUSES or mock.in_bootloader or mock.pid != mock.app_pid:
        raise FlashSafetyError(f"Bootloader Exit failed: rx[1]=0x{exit_rx[1]:02X}, pid=0x{mock.pid:04X}")
    fw_after = parse_get_fw_reply(mock.exchange(build_get_fw_report(device_id=0)))

    programmed_slice = bytes(mock.flash[image.base : image.end_exclusive])
    if programmed_slice != image.data:
        raise FlashSafetyError("Simulated flash content mismatch vs validated image")
    if not mock.bootloader_region_intact():
        raise FlashSafetyError("Simulated protected bootloader region (< 0x6000) corrupted")

    return {
        "dry_run": False,
        "mode": "offline_mock_replay",
        "executed": True,
        "fw_before": fw_before,
        "bl_fw": bl_ver,
        "fw_after": fw_after,
        "retries_4k": retries_4k,
        "packets_programmed": len(image.chunks),
        "packets_verified": len(image.chunks),
        "bootloader_intact": True,
        "flash_sha256_match": hashlib.sha256(programmed_slice).hexdigest() == hashlib.sha256(image.data).hexdigest(),
        "reset_device_sent": False,
        "image": plan_summary,
    }
