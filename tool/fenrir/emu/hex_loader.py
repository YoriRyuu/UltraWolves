"""Strict Intel HEX parser for offline Unicorn firmware verification."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path


class HexParseError(ValueError):
    """Raised when an Intel HEX file fails strict checksum or layout validation."""


class HexImage:
    """Strict sparse Intel HEX image with range tracking and SHA-256 identity."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.raw = self.path.read_bytes()
        self.sha256 = hashlib.sha256(self.raw).hexdigest()
        self.mem: dict[int, int] = {}
        self.types: dict[int, int] = {}

        hi = 0
        eof = False
        for line_no, line_raw in enumerate(self.raw.splitlines(keepends=True), 1):
            s = line_raw.strip().decode("ascii")
            if not s:
                continue
            if eof:
                raise HexParseError(f"{self.path}:{line_no}: record after EOF")
            if not s.startswith(":"):
                raise HexParseError(f"{self.path}:{line_no}: missing ':'")
            b = bytes.fromhex(s[1:])
            if len(b) != b[0] + 5:
                raise HexParseError(f"{self.path}:{line_no}: record length mismatch")
            if sum(b) % 256 != 0:
                raise HexParseError(f"{self.path}:{line_no}: checksum error")
            n, a, t = b[0], int.from_bytes(b[1:3], "big"), b[3]
            d = b[4 : 4 + n]
            self.types[t] = self.types.get(t, 0) + 1
            if t == 0:
                for i, x in enumerate(d):
                    adr = hi + a + i
                    if adr in self.mem:
                        raise HexParseError(f"{self.path}:{line_no}: overlapping byte at 0x{adr:08X}")
                    self.mem[adr] = x
            elif t == 1:
                if n != 0 or a != 0:
                    raise HexParseError(f"{self.path}:{line_no}: invalid EOF record")
                eof = True
            elif t == 2:
                if n != 2 or a != 0:
                    raise HexParseError(f"{self.path}:{line_no}: invalid type 2 record")
                hi = int.from_bytes(d, "big") << 4
            elif t == 4:
                if n != 2 or a != 0:
                    raise HexParseError(f"{self.path}:{line_no}: invalid type 4 record")
                hi = int.from_bytes(d, "big") << 16
            elif t in (3, 5):
                pass
            else:
                raise HexParseError(f"{self.path}:{line_no}: unsupported record type {t}")

        if not eof or not self.mem:
            raise HexParseError(f"{self.path}: missing EOF or empty image")

        addresses = sorted(self.mem)
        self.base = addresses[0]
        self.end = addresses[-1] + 1
        self.ranges: list[tuple[int, int]] = []
        start = last = addresses[0]
        for addr in addresses[1:]:
            if addr != last + 1:
                self.ranges.append((start, last + 1))
                start = addr
            last = addr
        self.ranges.append((start, last + 1))

    def get(self, addr: int, size: int) -> bytes:
        return bytes(self.mem[x] for x in range(addr, addr + size))

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.get(addr, 4))[0]

    def summary(self) -> dict[str, object]:
        return {
            "file": str(self.path),
            "hex_sha256": self.sha256,
            "defined_bytes": len(self.mem),
            "base": f"0x{self.base:08X}",
            "end_exclusive": f"0x{self.end:08X}",
        }
