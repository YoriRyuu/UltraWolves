"""Verified S2 mouse Bootloader wire protocol (65B HID Feature + XOR 0x55 obfuscation).

Matches `fenrir_dev/docs/s2_flash_protocol_spec.md` derived strictly from read-only
disassembly of `FirmwareUpdate.exe` (`C52840Dongle` / `HexHelper`) and `Config.ini`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

HID_REPORT_LEN = 65
XOR_KEY = 0x55
XOR_OFFSET = 12
MAX_PROGRAM_CHUNK = 32
PAGE_CACHE_BYTES = 4096

S2_SUCCESS_STATUSES: frozenset[int] = frozenset({0x02, 0xA1})
S2_PENDING_STATUSES: frozenset[int] = frozenset({0x01, 0xA0})

CMD_GET_DEVICE_MODE = 0x80
CMD_GET_FW = 0x81
CMD_BL_GET_FW = 0x80
CMD_BL_ERASE = 0x01
CMD_BL_PROGRAM = 0x02
CMD_BL_VERIFY_ADDR = 0x83
CMD_BL_EXIT = 0x04

BL_MAGIC_B0 = 0xB0

# Documented hazardous factory-reset trigger (APP group0 subcmd0 0xC0 0x02); NOT sent by default.
HAZARDOUS_RESET_DEVICE_SUBMODE = (0xC0, 0x02)


class FlashProtocolError(ValueError):
    """Raised on malformed S2 HID report inputs or reply framing."""


@dataclass(frozen=True)
class FlashChunk:
    """Single deterministic Program/Verify chunk (1..32 bytes)."""

    index: int
    address: int
    data: bytes
    is_4k_boundary: bool
    program_report: bytes
    verify_report: bytes


def xor_obfuscate_payload(data: bytes) -> bytes:
    """Symmetric bytewise XOR 0x55 used by S2 Program (tx) and VerifyByAddress (rx)."""
    return bytes(b ^ XOR_KEY for b in data)


def _init_report(device_id: int) -> bytearray:
    if isinstance(device_id, bool) or not (0 <= device_id <= 0xFF):
        raise FlashProtocolError(f"device_id must be u8, got {device_id!r}")
    buf = bytearray(HID_REPORT_LEN)
    buf[0] = 0x00  # Windows HID Report ID
    buf[3] = device_id
    return buf


def build_get_device_mode_report(*, device_id: int = 0) -> bytes:
    """Build 65B GetDeviceMode request ([3]=id, [4]=1, [5]=0, [6]=0x80)."""
    buf = _init_report(device_id)
    buf[4] = 0x01
    buf[5] = 0x00
    buf[6] = CMD_GET_DEVICE_MODE
    return bytes(buf)


def build_get_fw_report(*, device_id: int = 0) -> bytes:
    """Build 65B GetFW request ([3]=id, [4]=3, [5]=0, [6]=0x81)."""
    buf = _init_report(device_id)
    buf[4] = 0x03
    buf[5] = 0x00
    buf[6] = CMD_GET_FW
    return bytes(buf)


def build_set_bl_device_mode_report(*, device_id: int = 0) -> bytes:
    """Build 65B SetBLDeviceMode trigger ([3]=id, [4]=1, [5]=0, [6]=0, [7]=0xB0)."""
    buf = _init_report(device_id)
    buf[4] = 0x01
    buf[5] = 0x00
    buf[6] = 0x00
    buf[7] = BL_MAGIC_B0
    return bytes(buf)


def build_get_bl_fw_report(*, device_id: int = 0) -> bytes:
    """Build 65B GetBLFW request ([3]=id, [4]=6, [5]=0xB0, [6]=0x80)."""
    buf = _init_report(device_id)
    buf[4] = 0x06
    buf[5] = BL_MAGIC_B0
    buf[6] = CMD_BL_GET_FW
    return bytes(buf)


def build_erase_report(*, device_id: int = 0) -> bytes:
    """Build 65B Bootloader Erase request ([3]=id, [4]=8, [5]=0xB0, [6]=0x01)."""
    buf = _init_report(device_id)
    buf[4] = 0x08
    buf[5] = BL_MAGIC_B0
    buf[6] = CMD_BL_ERASE
    return bytes(buf)


def build_program_report(addr: int, data: bytes, *, device_id: int = 0) -> bytes:
    """Build 65B Program request with Big-Endian addr and XOR 0x55 over tx[12..64]."""
    if not isinstance(data, (bytes, bytearray)) or not (1 <= len(data) <= MAX_PROGRAM_CHUNK):
        raise FlashProtocolError(f"Program chunk length must be 1..{MAX_PROGRAM_CHUNK}, got {len(data)}")
    if addr < 0 or addr > 0xFFFFFFFF:
        raise FlashProtocolError(f"Invalid 32-bit flash address: 0x{addr:X}")
    buf = _init_report(device_id)
    buf[4] = len(data) + 5
    buf[5] = BL_MAGIC_B0
    buf[6] = CMD_BL_PROGRAM
    buf[7] = len(data)
    struct.pack_into(">I", buf, 8, addr)
    buf[XOR_OFFSET : XOR_OFFSET + len(data)] = data
    for i in range(XOR_OFFSET, HID_REPORT_LEN):
        buf[i] ^= XOR_KEY
    return bytes(buf)


def build_verify_by_address_report(
    addr: int, length: int = MAX_PROGRAM_CHUNK, *, device_id: int = 0
) -> bytes:
    """Build 65B VerifyByAddress request ([4]=0x20, [5]=0xB0, [6]=0x83, [7]=N, [8..11]=addr_BE)."""
    if not (1 <= length <= MAX_PROGRAM_CHUNK):
        raise FlashProtocolError(f"Verify length must be 1..{MAX_PROGRAM_CHUNK}, got {length}")
    if addr < 0 or addr > 0xFFFFFFFF:
        raise FlashProtocolError(f"Invalid 32-bit flash address: 0x{addr:X}")
    buf = _init_report(device_id)
    buf[4] = MAX_PROGRAM_CHUNK
    buf[5] = BL_MAGIC_B0
    buf[6] = CMD_BL_VERIFY_ADDR
    buf[7] = length
    struct.pack_into(">I", buf, 8, addr)
    return bytes(buf)


def build_exit_report(*, device_id: int = 0) -> bytes:
    """Build 65B Bootloader Exit request ([3]=id, [4]=1, [5]=0xB0, [6]=0x04, [7]=0x01)."""
    buf = _init_report(device_id)
    buf[4] = 0x01
    buf[5] = BL_MAGIC_B0
    buf[6] = CMD_BL_EXIT
    buf[7] = 0x01
    return bytes(buf)


def parse_get_fw_reply(rx: bytes) -> str:
    """Parse 65B GetFW reply into `{0:D2}.{1:D2}.{2:D2}.{3:D2}` string."""
    if len(rx) != HID_REPORT_LEN:
        raise FlashProtocolError(f"Expected {HID_REPORT_LEN}B HID report, got {len(rx)}B")
    return f"{rx[7]:02d}.{rx[8]:02d}.{rx[9]:02d}.{rx[10]:02d}"


def parse_get_bl_fw_reply(rx: bytes) -> tuple[str, bool]:
    """Parse 65B GetBLFW reply (`rx[9..12]` X2 format) and confirm bootloader `'B'` tag."""
    if len(rx) != HID_REPORT_LEN:
        raise FlashProtocolError(f"Expected {HID_REPORT_LEN}B HID report, got {len(rx)}B")
    ver = f"{rx[9]:02X}.{rx[10]:02X}.{rx[11]:02X}.{rx[12]:02X}"
    return ver, ("B" in ver)


def decode_verify_reply(rx: bytes, length: int = MAX_PROGRAM_CHUNK) -> bytes:
    """Validate 65B VerifyByAddress reply and XOR-0x55 decode `rx[12..12+length)`."""
    if len(rx) != HID_REPORT_LEN:
        raise FlashProtocolError(f"Expected {HID_REPORT_LEN}B HID report, got {len(rx)}B")
    if not (1 <= length <= MAX_PROGRAM_CHUNK):
        raise FlashProtocolError(f"Verify decode length must be 1..{MAX_PROGRAM_CHUNK}, got {length}")
    if rx[5] != BL_MAGIC_B0:
        raise FlashProtocolError(f"Verify reply missing rx[5]==0xB0, got 0x{rx[5]:02X}")
    if rx[1] not in S2_SUCCESS_STATUSES:
        raise FlashProtocolError(f"Verify reply failed: status rx[1]=0x{rx[1]:02X}")
    return xor_obfuscate_payload(bytes(rx[XOR_OFFSET : XOR_OFFSET + length]))


def build_program_plan(
    base_addr: int,
    image_bytes: bytes,
    *,
    device_id: int = 0,
    verify_full_chunk_len: bool = False,
) -> list[FlashChunk]:
    """Deterministically chunk contiguous image bytes into 32B (+ tail) S2 Program/Verify packets."""
    if not image_bytes:
        raise FlashProtocolError("Cannot build S2 plan from empty image")
    chunks: list[FlashChunk] = []
    cache_rem = PAGE_CACHE_BYTES
    offset = 0
    idx = 0
    total = len(image_bytes)
    while offset < total:
        block = image_bytes[offset : offset + MAX_PROGRAM_CHUNK]
        addr = base_addr + offset
        is_4k = cache_rem <= MAX_PROGRAM_CHUNK
        cache_rem = PAGE_CACHE_BYTES if is_4k else (cache_rem - MAX_PROGRAM_CHUNK)
        verify_len = MAX_PROGRAM_CHUNK if verify_full_chunk_len else len(block)
        chunks.append(
            FlashChunk(
                index=idx,
                address=addr,
                data=block,
                is_4k_boundary=is_4k,
                program_report=build_program_report(addr, block, device_id=device_id),
                verify_report=build_verify_by_address_report(addr, length=verify_len, device_id=device_id),
            )
        )
        offset += len(block)
        idx += 1
    return chunks
