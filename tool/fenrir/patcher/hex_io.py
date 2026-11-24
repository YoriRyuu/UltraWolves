"""Strict Intel HEX parser, guarded patch builder, and NOT_FOR_FLASH manifest writer."""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from fenrir.constants import FENRIR_DEV_ROOT, REPO_ROOT

NOT_FOR_FLASH_TAG = "NOT_FOR_FLASH"
NOT_FOR_FLASH_WARNING = (
    "NOT_FOR_FLASH: Offline simulation and verification artifact only. "
    "No flashing/uploading support exists; NEVER write directly to hardware."
)


class HexIoError(ValueError):
    """Base error for strict Intel HEX parsing, patching, and manifest emission."""


class FingerprintMismatchError(HexIoError):
    """Raised when stock firmware bytes or identity fail pre-patch verification."""


class ProtectedRegionError(HexIoError):
    """Raised when an edit, allocation, or output path touches a protected target."""


class AllocationError(HexIoError):
    """Raised when code-cave allocation fails due to alignment, overlap, or capacity."""


@dataclass(frozen=True)
class AddressRange:
    """Half-open memory or Flash address range ``[start, end)``."""

    start: int
    end: int
    label: str = ""

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"Invalid AddressRange [{self.start:#x}, {self.end:#x}) for {self.label}")

    @property
    def size(self) -> int:
        return self.end - self.start

    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.end

    def overlaps(self, start: int, end: int) -> bool:
        return self.start < end and start < self.end

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "start": f"0x{self.start:08X}",
            "end_exclusive": f"0x{self.end:08X}",
            "bytes": self.size,
        }


@dataclass(frozen=True)
class PatchEdit:
    """Recorded modification of existing stock bytes."""

    address: int
    old_bytes: bytes
    new_bytes: bytes
    module: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:08X}",
            "length": len(self.new_bytes),
            "old_hex": self.old_bytes.hex(),
            "new_hex": self.new_bytes.hex(),
            "module": self.module,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CaveAllocation:
    """Recorded allocation in an unused verified code/data cave."""

    name: str
    address: int
    size: int
    kind: str
    module: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "address": f"0x{self.address:08X}",
            "end_exclusive": f"0x{self.address + self.size:08X}",
            "bytes": self.size,
            "kind": self.kind,
            "module": self.module,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class VerifiedFingerprint:
    """Pre-patch stock byte fingerprint verified against the input HEX."""

    address: int
    length: int
    sha256: str
    label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:08X}",
            "bytes": self.length,
            "sha256": self.sha256,
            "label": self.label,
        }


class HexImage:
    """Strict sparse Intel HEX image with range tracking and SHA-256 identity."""

    def __init__(self, path: Path) -> None:
        self.path: Path | None = Path(path)
        raw = self.path.read_bytes()
        self._init_from_bytes(raw, source_label=str(self.path))

    @classmethod
    def from_bytes(cls, raw: bytes, *, source_label: str = "<memory>") -> HexImage:
        obj = cls.__new__(cls)
        obj.path = None
        obj._init_from_bytes(bytes(raw), source_label=source_label)
        return obj

    def _init_from_bytes(self, raw: bytes, *, source_label: str) -> None:
        self.raw = bytes(raw)
        self.sha256 = hashlib.sha256(self.raw).hexdigest()
        self.mem: dict[int, int] = {}
        self.types: dict[int, int] = {}
        self.entry: int | None = None

        hi = 0
        eof = False
        for line_no, line_raw in enumerate(self.raw.splitlines(keepends=True), 1):
            try:
                s = line_raw.strip().decode("ascii")
            except UnicodeDecodeError as exc:
                raise HexIoError(f"{source_label}:{line_no}: non-ASCII line") from exc
            if not s:
                continue
            if eof:
                raise HexIoError(f"{source_label}:{line_no}: record after EOF")
            if not s.startswith(":"):
                raise HexIoError(f"{source_label}:{line_no}: missing ':'")
            try:
                b = bytes.fromhex(s[1:])
            except ValueError as exc:
                raise HexIoError(f"{source_label}:{line_no}: invalid hex characters") from exc
            if len(b) < 5 or len(b) != b[0] + 5:
                raise HexIoError(f"{source_label}:{line_no}: record length mismatch")
            if sum(b) & 0xFF != 0:
                raise HexIoError(f"{source_label}:{line_no}: checksum error")

            n, a, t = b[0], int.from_bytes(b[1:3], "big"), b[3]
            d = b[4 : 4 + n]
            self.types[t] = self.types.get(t, 0) + 1
            if t == 0:
                if a + n > 0x10000:
                    raise HexIoError(f"{source_label}:{line_no}: data crosses 64 KiB boundary")
                for i, x in enumerate(d):
                    adr = hi + a + i
                    if adr in self.mem:
                        raise HexIoError(f"{source_label}:{line_no}: overlapping byte at 0x{adr:08X}")
                    self.mem[adr] = x
            elif t == 1:
                if n != 0 or a != 0:
                    raise HexIoError(f"{source_label}:{line_no}: invalid EOF record")
                eof = True
            elif t == 2:
                if n != 2 or a != 0:
                    raise HexIoError(f"{source_label}:{line_no}: invalid type 2 record")
                hi = int.from_bytes(d, "big") << 4
            elif t == 4:
                if n != 2 or a != 0:
                    raise HexIoError(f"{source_label}:{line_no}: invalid type 4 record")
                hi = int.from_bytes(d, "big") << 16
            elif t == 3:
                if n != 4 or a != 0:
                    raise HexIoError(f"{source_label}:{line_no}: invalid type 3 record")
            elif t == 5:
                if n != 4 or a != 0:
                    raise HexIoError(f"{source_label}:{line_no}: invalid type 5 record")
                self.entry = int.from_bytes(d, "big")
            else:
                raise HexIoError(f"{source_label}:{line_no}: unsupported record type {t}")

        if not eof or not self.mem:
            raise HexIoError(f"{source_label}: missing EOF or empty image")

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

    def has_range(self, addr: int, size: int) -> bool:
        if size < 0:
            raise ValueError(f"negative size {size}")
        return all((addr + i) in self.mem for i in range(size))

    def get(self, addr: int, size: int) -> bytes:
        if size < 0:
            raise ValueError(f"negative size {size}")
        out = bytearray(size)
        for i in range(size):
            a = addr + i
            if a not in self.mem:
                raise HexIoError(f"Undefined address 0x{a:08X} in read [{addr:#x}, {addr + size:#x})")
            out[i] = self.mem[a]
        return bytes(out)

    def u8(self, addr: int) -> int:
        return self.get(addr, 1)[0]

    def u16(self, addr: int) -> int:
        return struct.unpack("<H", self.get(addr, 2))[0]

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.get(addr, 4))[0]

    def find_u32_refs(
        self,
        value: int,
        *,
        start: int | None = None,
        end: int | None = None,
        aligned_only: bool = False,
    ) -> list[int]:
        lo = self.base if start is None else start
        hi = self.end if end is None else end
        step = 4 if aligned_only else 1
        if aligned_only and (lo & 3):
            lo = (lo + 3) & ~3
        target = struct.pack("<I", value & 0xFFFFFFFF)
        hits: list[int] = []
        for addr in range(lo, hi - 3, step):
            if self.has_range(addr, 4) and self.get(addr, 4) == target:
                hits.append(addr)
        return hits

    def verify_fingerprint(self, addr: int, expected: bytes, label: str = "") -> None:
        if not self.has_range(addr, len(expected)):
            raise FingerprintMismatchError(
                f"Fingerprint '{label}' at 0x{addr:08X} ({len(expected)}B) touches undefined HEX bytes"
            )
        actual = self.get(addr, len(expected))
        if actual != expected:
            raise FingerprintMismatchError(
                f"Fingerprint mismatch '{label}' at 0x{addr:08X}: "
                f"expected {expected.hex()}, got {actual.hex()}"
            )

    def to_contiguous_bytes(self, start: int | None = None, end: int | None = None, fill: int = 0xFF) -> bytes:
        lo = self.base if start is None else start
        hi = self.end if end is None else end
        if hi < lo:
            raise ValueError(f"Invalid span [{lo:#x}, {hi:#x})")
        return bytes(self.mem.get(a, fill) for a in range(lo, hi))

    def summary(self) -> dict[str, Any]:
        return {
            "file": str(self.path) if self.path is not None else "<memory>",
            "hex_sha256": self.sha256,
            "defined_bytes": len(self.mem),
            "base": f"0x{self.base:08X}",
            "end_exclusive": f"0x{self.end:08X}",
            "entry": f"0x{self.entry:08X}" if self.entry is not None else None,
            "ranges": [
                {"start": f"0x{a:08X}", "end_exclusive": f"0x{b:08X}", "bytes": b - a}
                for a, b in self.ranges
            ],
        }


def _format_ihex_record(addr16: int, rec_type: int, data: bytes) -> str:
    body = bytes([len(data), (addr16 >> 8) & 0xFF, addr16 & 0xFF, rec_type]) + data
    chk = (-sum(body)) & 0xFF
    return ":" + (body + bytes([chk])).hex().upper()


def render_intel_hex(
    mem: dict[int, int],
    *,
    entry: int | None = None,
    bytes_per_line: int = 16,
    line_ending: str = "\r\n",
) -> bytes:
    """Render sparse memory dict into canonical Intel HEX and verify lossless round-trip."""
    if not mem:
        raise HexIoError("Cannot render empty Intel HEX image")
    if not (1 <= bytes_per_line <= 32):
        raise ValueError(f"bytes_per_line must be 1..32, got {bytes_per_line}")

    records: list[str] = []
    addresses = sorted(mem)
    current_upper: int | None = None

    idx = 0
    total = len(addresses)
    while idx < total:
        start_addr = addresses[idx]
        upper = (start_addr >> 16) & 0xFFFF
        if upper != current_upper:
            records.append(_format_ihex_record(0, 4, upper.to_bytes(2, "big")))
            current_upper = upper

        lo = start_addr & 0xFFFF
        max_in_seg = min(bytes_per_line, 0x10000 - lo)
        buf = bytearray([mem[start_addr] & 0xFF])
        idx += 1
        while idx < total and len(buf) < max_in_seg:
            nxt = addresses[idx]
            if nxt != start_addr + len(buf) or ((nxt >> 16) & 0xFFFF) != upper:
                break
            buf.append(mem[nxt] & 0xFF)
            idx += 1
        records.append(_format_ihex_record(lo, 0, bytes(buf)))

    if entry is not None:
        records.append(_format_ihex_record(0, 5, (entry & 0xFFFFFFFF).to_bytes(4, "big")))
    records.append(_format_ihex_record(0, 1, b""))

    raw = (line_ending.join(records) + line_ending).encode("ascii")
    roundtrip = HexImage.from_bytes(raw, source_label="<rendered>")
    if roundtrip.mem != mem or roundtrip.entry != entry:
        raise HexIoError("Rendered Intel HEX failed round-trip integrity check")
    return raw


def _is_within_dir(candidate: Path, parent: Path) -> bool:
    c = candidate.resolve()
    p = parent.resolve()
    return c == p or p in c.parents


class HexPatchBuilder:
    """Guarded offline patch builder enforcing fingerprints, non-overlap, and protected zones."""

    def __init__(
        self,
        stock_image: HexImage,
        *,
        expected_sha256: str | None = None,
        expected_base: int | None = None,
        expected_end: int | None = None,
        protected_ranges: Sequence[AddressRange] = (),
    ) -> None:
        self.stock_image = stock_image
        if expected_sha256 is not None and stock_image.sha256 != expected_sha256:
            raise FingerprintMismatchError(
                f"Stock HEX SHA-256 mismatch: expected {expected_sha256}, got {stock_image.sha256}"
            )
        if expected_base is not None and stock_image.base != expected_base:
            raise FingerprintMismatchError(
                f"Stock HEX base mismatch: expected 0x{expected_base:08X}, got 0x{stock_image.base:08X}"
            )
        if expected_end is not None and stock_image.end != expected_end:
            raise FingerprintMismatchError(
                f"Stock HEX end mismatch: expected 0x{expected_end:08X}, got 0x{stock_image.end:08X}"
            )

        self.protected_ranges: list[AddressRange] = list(protected_ranges)
        self.cave_pools: list[tuple[int, int, str]] = []  # (cursor, end_exclusive, label)
        self.cave_spans: list[AddressRange] = []
        self.changes: dict[int, int] = {}
        self.edit_records: list[PatchEdit] = []
        self.allocations: list[CaveAllocation] = []
        self.symbols: dict[str, int] = {}
        self.verified_fingerprints: list[VerifiedFingerprint] = []
        self._touched_edit_addrs: dict[int, str] = {}
        self._touched_cave_addrs: dict[int, str] = {}

    def add_protected_range(self, start: int, end: int, label: str) -> None:
        rng = AddressRange(start, end, label)
        for alloc in self.allocations:
            if rng.overlaps(alloc.address, alloc.address + alloc.size):
                raise ProtectedRegionError(
                    f"New protected range {label} overlaps existing allocation {alloc.name}"
                )
        for edit in self.edit_records:
            if rng.overlaps(edit.address, edit.address + len(edit.new_bytes)):
                raise ProtectedRegionError(
                    f"New protected range {label} overlaps existing edit at 0x{edit.address:08X}"
                )
        self.protected_ranges.append(rng)

    def add_code_cave(self, start: int, end: int, label: str = "code_cave") -> None:
        rng = AddressRange(start, end, label)
        if rng.size == 0:
            raise AllocationError(f"Empty code cave {label}")
        for pr in self.protected_ranges:
            if pr.overlaps(start, end):
                raise ProtectedRegionError(
                    f"Code cave '{label}' [0x{start:08X}, 0x{end:08X}) overlaps protected region '{pr.label}' "
                    f"[0x{pr.start:08X}, 0x{pr.end:08X})"
                )
        for addr in range(start, end):
            if addr in self.stock_image.mem:
                raise ProtectedRegionError(
                    f"Code cave '{label}' overlaps defined stock byte at 0x{addr:08X}"
                )
        for c_start, c_end, c_label in self.cave_pools:
            if c_start < end and start < c_end:
                raise AllocationError(
                    f"Code cave '{label}' overlaps existing pool '{c_label}'"
                )
        self.cave_pools.append((start, end, label))
        self.cave_pools.sort(key=lambda x: x[0])
        self.cave_spans.append(rng)

    def _assert_not_protected(self, start: int, end: int, context: str) -> None:
        for pr in self.protected_ranges:
            if pr.overlaps(start, end):
                raise ProtectedRegionError(
                    f"{context} [0x{start:08X}, 0x{end:08X}) overlaps protected region "
                    f"'{pr.label}' [0x{pr.start:08X}, 0x{pr.end:08X})"
                )

    def verify_fingerprint(self, addr: int, expected: bytes, label: str = "") -> None:
        self.stock_image.verify_fingerprint(addr, expected, label)
        self.verified_fingerprints.append(
            VerifiedFingerprint(
                address=addr,
                length=len(expected),
                sha256=hashlib.sha256(expected).hexdigest(),
                label=label,
            )
        )

    def edit(
        self,
        addr: int,
        new_bytes: bytes,
        *,
        expected_old: bytes,
        reason: str,
        module: str = "",
    ) -> None:
        """Overwrite existing stock bytes after strict fingerprint & non-overlap checks."""
        new_b = bytes(new_bytes)
        old_b = bytes(expected_old)
        if not new_b:
            raise HexIoError("edit() requires non-empty bytes")
        if len(new_b) != len(old_b):
            raise HexIoError(
                f"edit() length mismatch at 0x{addr:08X}: new={len(new_b)} != expected_old={len(old_b)}"
            )
        end = addr + len(new_b)
        self._assert_not_protected(addr, end, f"edit '{reason}'")
        self.verify_fingerprint(addr, old_b, label=f"edit:{module}:{reason}")

        for i in range(len(new_b)):
            a = addr + i
            if a in self._touched_cave_addrs:
                raise ProtectedRegionError(f"edit at 0x{a:08X} collides with cave allocation {self._touched_cave_addrs[a]}")
            if a in self._touched_edit_addrs:
                raise HexIoError(
                    f"Overlapping edit at 0x{a:08X}: already edited by '{self._touched_edit_addrs[a]}', "
                    f"new='{reason}'"
                )

        for i, val in enumerate(new_b):
            a = addr + i
            self._touched_edit_addrs[a] = reason
            if val != old_b[i]:
                self.changes[a] = val
        self.edit_records.append(PatchEdit(addr, old_b, new_b, module, reason))

    def edit_u32(
        self,
        addr: int,
        new_value: int,
        *,
        expected_old_u32: int,
        reason: str,
        module: str = "",
    ) -> None:
        self.edit(
            addr,
            struct.pack("<I", new_value & 0xFFFFFFFF),
            expected_old=struct.pack("<I", expected_old_u32 & 0xFFFFFFFF),
            reason=reason,
            module=module,
        )

    def _find_pool_for_allocation(self, size: int, align: int) -> tuple[int, int, int, str]:
        if align <= 0 or (align & (align - 1)) != 0:
            raise AllocationError(f"Alignment must be a positive power of 2, got {align}")
        for idx, (cursor, pool_end, label) in enumerate(self.cave_pools):
            aligned = (cursor + align - 1) & ~(align - 1)
            if aligned + size <= pool_end:
                return idx, aligned, pool_end, label
        raise AllocationError(
            f"No verified code cave has contiguous space for {size} bytes (align={align}); "
            f"remaining={self.remaining_cave_bytes()}B"
        )

    def _commit_cave_bytes(
        self,
        pool_idx: int,
        aligned_start: int,
        data: bytes,
        *,
        name: str,
        pad_pattern: bytes,
        kind: str,
        module: str,
        reason: str,
    ) -> int:
        if name in self.symbols:
            raise AllocationError(f"Duplicate symbol '{name}'")
        cursor, pool_end, _label = self.cave_pools[pool_idx]
        end = aligned_start + len(data)
        if end > pool_end:
            raise AllocationError(f"Allocation '{name}' exceeds pool end 0x{pool_end:08X}")
        self._assert_not_protected(cursor, end, f"allocation '{name}'")

        for a in range(cursor, end):
            if a in self.stock_image.mem:
                raise ProtectedRegionError(f"Allocation '{name}' collides with stock byte at 0x{a:08X}")
            if a in self._touched_cave_addrs or a in self._touched_edit_addrs:
                raise AllocationError(f"Allocation '{name}' collides at 0x{a:08X}")

        pad_len = aligned_start - cursor
        if pad_len:
            if not pad_pattern:
                raise AllocationError("pad_pattern must be non-empty")
            if pad_len % len(pad_pattern) != 0:
                pad = (pad_pattern * ((pad_len // len(pad_pattern)) + 1))[:pad_len]
            else:
                pad = pad_pattern * (pad_len // len(pad_pattern))
            for i, val in enumerate(pad):
                a = cursor + i
                self._touched_cave_addrs[a] = f"{name}:align_pad"
                self.changes[a] = val

        for i, val in enumerate(data):
            a = aligned_start + i
            self._touched_cave_addrs[a] = name
            self.changes[a] = val

        self.cave_pools[pool_idx] = (end, pool_end, _label)
        self.symbols[name] = aligned_start
        self.allocations.append(CaveAllocation(name, aligned_start, len(data), kind, module, reason))
        return aligned_start

    def alloc_bytes(
        self,
        name: str,
        data: bytes,
        *,
        align: int = 4,
        pad_pattern: bytes = b"\xff",
        kind: str = "data",
        module: str = "",
        reason: str = "",
    ) -> int:
        """Allocate raw bytes inside a verified code cave."""
        payload = bytes(data)
        if not payload:
            raise AllocationError(f"Cannot allocate empty data for '{name}'")
        pool_idx, aligned_start, _pool_end, _label = self._find_pool_for_allocation(len(payload), align)
        return self._commit_cave_bytes(
            pool_idx,
            aligned_start,
            payload,
            name=name,
            pad_pattern=pad_pattern,
            kind=kind,
            module=module,
            reason=reason or name,
        )

    def alloc_code(
        self,
        name: str,
        emitter: Callable[[int], bytes],
        *,
        align: int = 2,
        module: str = "",
        reason: str = "",
    ) -> int:
        """Assemble position-dependent code at the exact cave address and commit it."""
        if name in self.symbols:
            raise AllocationError(f"Duplicate symbol '{name}'")
        if align <= 0 or (align & (align - 1)) != 0 or align < 2:
            raise AllocationError(f"Code alignment must be power of 2 >= 2, got {align}")

        for idx, (cursor, pool_end, _label) in enumerate(self.cave_pools):
            aligned = (cursor + align - 1) & ~(align - 1)
            if aligned >= pool_end:
                continue
            code_bytes = bytes(emitter(aligned))
            if not code_bytes:
                raise AllocationError(f"Empty code emitted for '{name}'")
            if aligned + len(code_bytes) <= pool_end:
                pad_pattern = b"\x00\xbf" if (aligned - cursor) % 2 == 0 else b"\xff"
                return self._commit_cave_bytes(
                    idx,
                    aligned,
                    code_bytes,
                    name=name,
                    pad_pattern=pad_pattern,
                    kind="code",
                    module=module,
                    reason=reason or name,
                )
        raise AllocationError(f"No verified code cave fits code block '{name}'")

    def remaining_cave_bytes(self) -> int:
        return sum(end - cur for cur, end, _ in self.cave_pools)

    def patched_mem(self) -> dict[int, int]:
        merged = dict(self.stock_image.mem)
        merged.update(self.changes)
        return merged

    def render_hex(self) -> bytes:
        return render_intel_hex(self.patched_mem(), entry=self.stock_image.entry)

    def patched_image(self) -> HexImage:
        return HexImage.from_bytes(self.render_hex(), source_label="<patched>")

    def assert_safe_output_path(self, dest: Path) -> Path:
        resolved = Path(dest).resolve()
        for protected_dir in (
            REPO_ROOT / "work",
            REPO_ROOT / "outputs",
            FENRIR_DEV_ROOT / "fenrir",
            FENRIR_DEV_ROOT / "tests",
        ):
            if _is_within_dir(resolved, protected_dir):
                raise ProtectedRegionError(
                    f"Refusing to write build artifact inside protected directory: {resolved}"
                )
        if self.stock_image.path is not None and resolved == self.stock_image.path.resolve():
            raise ProtectedRegionError(f"Refusing to overwrite stock firmware HEX: {resolved}")
        return resolved

    def build_manifest(
        self,
        *,
        output_hex_path: Path | None = None,
        output_hex_sha256: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        patched = self.patched_image()
        manifest: dict[str, Any] = {
            "artifact_tag": NOT_FOR_FLASH_TAG,
            "not_for_flash": True,
            "offline_only": True,
            "hardware_flashing_supported": False,
            "warning": NOT_FOR_FLASH_WARNING,
            "built_at_utc": datetime.now(timezone.utc).isoformat(),
            "stock": self.stock_image.summary(),
            "output": {
                "hex_path": str(output_hex_path) if output_hex_path is not None else "<in-memory>",
                "hex_sha256": output_hex_sha256 or patched.sha256,
                "defined_bytes": len(patched.mem),
                "base": f"0x{patched.base:08X}",
                "end_exclusive": f"0x{patched.end:08X}",
                "entry": f"0x{patched.entry:08X}" if patched.entry is not None else None,
                "ranges": [
                    {"start": f"0x{a:08X}", "end_exclusive": f"0x{b:08X}", "bytes": b - a}
                    for a, b in patched.ranges
                ],
            },
            "protected_ranges": [r.to_dict() for r in self.protected_ranges],
            "cave_pools": {
                "initial": [r.to_dict() for r in self.cave_spans],
                "remaining_bytes": self.remaining_cave_bytes(),
                "remaining_spans": [
                    {"label": label, "start": f"0x{cur:08X}", "end_exclusive": f"0x{end:08X}", "bytes": end - cur}
                    for cur, end, label in self.cave_pools
                    if end > cur
                ],
            },
            "stats": {
                "modified_stock_bytes": sum(1 for a in self.changes if a in self.stock_image.mem),
                "added_cave_bytes": sum(1 for a in self.changes if a not in self.stock_image.mem),
                "total_changed_or_added_bytes": len(self.changes),
                "edit_count": len(self.edit_records),
                "allocation_count": len(self.allocations),
                "verified_fingerprint_count": len(self.verified_fingerprints),
            },
            "symbols": {k: f"0x{v:08X}" for k, v in sorted(self.symbols.items())},
            "allocations": [a.to_dict() for a in self.allocations],
            "edits": [e.to_dict() for e in self.edit_records],
            "verified_fingerprints": [f.to_dict() for f in self.verified_fingerprints],
        }
        if extra:
            manifest.update(extra)
        return manifest

    def write_artifacts(
        self,
        hex_path: Path,
        *,
        manifest_path: Path | None = None,
        capstone_report: dict[str, Any] | None = None,
        capstone_path: Path | None = None,
        extra_manifest: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Write patched HEX + JSON manifest + optional Capstone verification report."""
        dest_hex = self.assert_safe_output_path(hex_path)
        if NOT_FOR_FLASH_TAG not in dest_hex.name:
            raise HexIoError(
                f"Output HEX filename MUST contain '{NOT_FOR_FLASH_TAG}' for safety: {dest_hex.name}"
            )
        dest_manifest = (
            self.assert_safe_output_path(manifest_path)
            if manifest_path is not None
            else self.assert_safe_output_path(dest_hex.with_suffix(".manifest.json"))
        )
        dest_cap = (
            self.assert_safe_output_path(capstone_path)
            if capstone_path is not None
            else (self.assert_safe_output_path(dest_hex.with_suffix(".capstone.json")) if capstone_report is not None else None)
        )

        hex_bytes = self.render_hex()
        dest_hex.parent.mkdir(parents=True, exist_ok=True)
        dest_hex.write_bytes(hex_bytes)

        reloaded = HexImage(dest_hex)
        if reloaded.mem != self.patched_mem() or reloaded.entry != self.stock_image.entry:
            raise HexIoError(f"Written HEX at {dest_hex} failed post-write reload verification")

        manifest = self.build_manifest(
            output_hex_path=dest_hex,
            output_hex_sha256=reloaded.sha256,
            extra=extra_manifest,
        )
        if dest_cap is not None and capstone_report is not None:
            manifest["capstone_report_path"] = str(dest_cap)
            dest_cap.parent.mkdir(parents=True, exist_ok=True)
            dest_cap.write_text(json.dumps(capstone_report, indent=2) + "\n", encoding="utf-8")

        dest_manifest.parent.mkdir(parents=True, exist_ok=True)
        dest_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return {
            "hex_path": str(dest_hex),
            "hex_sha256": reloaded.sha256,
            "manifest_path": str(dest_manifest),
            "capstone_path": str(dest_cap) if dest_cap is not None else None,
            "manifest": manifest,
        }
