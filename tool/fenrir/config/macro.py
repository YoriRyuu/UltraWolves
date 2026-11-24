"""Strictly serialized single-page macro object pool manager for Phase 1."""

from __future__ import annotations

import struct
import threading
from dataclasses import dataclass
from typing import Any

from fenrir.probe.identity import MouseDisconnectedError
from fenrir.protocol.catalog import TargetRole
from fenrir.protocol.frames import build_family_b_frame
from fenrir.protocol.write_frames import (
    MAX_MACRO_CHUNK_LEN,
    MAX_MACRO_OBJECT_SIZE,
    build_macro_chunk_frame,
    build_macro_create_frame,
    build_macro_delete_frame,
)
from fenrir.transport.hid_win import GuardedHidSession

MAX_SAFE_MACROS = 9  # 0x8E reply len = 1 + 6*count <= 59B wireless limit (1 + 6*9 = 55B)
MIN_SAFE_FREE_BYTES = 4096


@dataclass(frozen=True)
class MacroEntry:
    obj_id: int
    size: int

    @property
    def obj_id_hex(self) -> str:
        return f"0x{self.obj_id:04X}"


@dataclass(frozen=True)
class MacroPoolFree:
    total_bytes: int
    free_bytes: int


class SafeMacroManager:
    """Serialized macro directory/pool manager avoiding 0x200066D8/0xCA08/0xCC08/0x12D94 bugs."""

    _GLOBAL_LOCK = threading.RLock()

    def __init__(self, session: GuardedHidSession, target_role: TargetRole) -> None:
        if target_role not in (TargetRole.MOUSE_USB, TargetRole.RECEIVER_TO_MOUSE_RF):
            raise ValueError(
                f"SafeMacroManager requires MOUSE_USB or RECEIVER_TO_MOUSE_RF, got {target_role.value}"
            )
        self.session = session
        self.target_role = target_role

    @property
    def is_wireless(self) -> bool:
        return self.target_role == TargetRole.RECEIVER_TO_MOUSE_RF

    @property
    def _route_b(self) -> int:
        return 1 if self.is_wireless else 0

    def _preflight_rf_link(self) -> None:
        if not self.is_wireless:
            return
        _, parsed = self.session.query(
            TargetRole.RECEIVER_2G4_LOCAL, build_family_b_frame(0x90, route=0).data
        )
        link_raw = parsed.payload[0] if parsed.payload else 0
        if not parsed.is_ok or link_raw == 0:
            raise MouseDisconnectedError(
                f"Pre-flight 2.4G 0x90 reports mouse disconnected (status={parsed.status_name}, link={link_raw})"
            )

    def list_macros(self) -> list[MacroEntry]:
        with self._GLOBAL_LOCK:
            self._preflight_rf_link()
            _, parsed = self.session.query(
                self.target_role, build_family_b_frame(0x8E, route=self._route_b).data
            )
            if not parsed.is_ok:
                raise RuntimeError(f"0x8E directory read failed: {parsed.status_name}")
            if not parsed.payload:
                return []
            count = parsed.payload[0]
            entries: list[MacroEntry] = []
            max_fit = (len(parsed.payload) - 1) // 6
            for i in range(min(count, max_fit)):
                obj_id, size = struct.unpack_from(">HI", parsed.payload, 1 + 6 * i)
                entries.append(MacroEntry(obj_id=obj_id, size=size))
            return entries

    def get_free_space(self) -> MacroPoolFree:
        with self._GLOBAL_LOCK:
            self._preflight_rf_link()
            _, parsed = self.session.query(
                self.target_role, build_family_b_frame(0x8A, route=self._route_b).data
            )
            if not parsed.is_ok or len(parsed.payload) < 8:
                raise RuntimeError(f"0x8A free space read failed: {parsed.status_name}")
            total_bytes, free_bytes = struct.unpack_from(">II", parsed.payload, 0)
            return MacroPoolFree(total_bytes=total_bytes, free_bytes=free_bytes)

    def get_macro_size(self, obj_id: int) -> int:
        with self._GLOBAL_LOCK:
            self._preflight_rf_link()
            frame = build_family_b_frame(0x8B, struct.pack(">H", obj_id), route=self._route_b).data
            _, parsed = self.session.query(self.target_role, frame)
            if not parsed.is_ok or len(parsed.payload) < 6:
                raise RuntimeError(f"0x8B size read for 0x{obj_id:04X} failed: {parsed.status_name}")
            _, size = struct.unpack_from(">HI", parsed.payload, 0)
            return int(size)

    def read_macro(self, obj_id: int, size: int | None = None) -> bytes:
        with self._GLOBAL_LOCK:
            self._preflight_rf_link()
            target_size = self.get_macro_size(obj_id) if size is None else size
            if not (1 <= target_size <= MAX_MACRO_OBJECT_SIZE):
                raise ValueError(f"Invalid macro size {target_size} for 0x{obj_id:04X}")
            out = bytearray()
            offset = 0
            while offset < target_size:
                chunk_len = min(MAX_MACRO_CHUNK_LEN, target_size - offset)
                req = build_family_b_frame(
                    0x8D, struct.pack(">HIB", obj_id, offset, chunk_len), route=self._route_b
                ).data
                _, parsed = self.session.query(self.target_role, req)
                if not parsed.is_ok or len(parsed.payload) < 7 + chunk_len:
                    raise RuntimeError(
                        f"0x8D read failed at offset {offset} for 0x{obj_id:04X}: {parsed.status_name}"
                    )
                out.extend(parsed.payload[7 : 7 + chunk_len])
                offset += chunk_len
            return bytes(out)

    def delete_macro(self, obj_id: int, *, dry_run: bool = False) -> dict[str, Any]:
        with self._GLOBAL_LOCK:
            frame = build_macro_delete_frame(obj_id, wireless=self.is_wireless)
            if dry_run:
                return {"obj_id": f"0x{obj_id:04X}", "dry_run": True, "frame_hex": frame.hex(), "deleted": False}
            self._preflight_rf_link()
            _, parsed = self.session.query(self.target_role, frame.data)
            if not parsed.is_ok:
                raise RuntimeError(f"0x0C delete 0x{obj_id:04X} failed: {parsed.status_name}")
            return {"obj_id": f"0x{obj_id:04X}", "dry_run": False, "status": parsed.status_name, "deleted": True}

    def upload_macro(
        self,
        obj_id: int,
        data: bytes,
        *,
        verify_readback: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Atomically allocate, sequentially stream <=52B chunks, flush final page, and verify."""
        payload = bytes(data)
        size = len(payload)
        create_frame = build_macro_create_frame(obj_id, size, wireless=self.is_wireless)
        chunk_frames = []
        offset = 0
        while offset < size:
            part = payload[offset : offset + MAX_MACRO_CHUNK_LEN]
            chunk_frames.append(
                build_macro_chunk_frame(obj_id, offset, part, wireless=self.is_wireless)
            )
            offset += len(part)

        with self._GLOBAL_LOCK:
            self._preflight_rf_link()
            entries = self.list_macros()
            already_exists = any(e.obj_id == obj_id for e in entries)
            if not already_exists and len(entries) >= MAX_SAFE_MACROS:
                raise RuntimeError(
                    f"Macro directory has {len(entries)} entries (Phase 1 safe cap {MAX_SAFE_MACROS}); delete one first"
                )
            free_info = self.get_free_space()
            if not already_exists and free_info.free_bytes <= MIN_SAFE_FREE_BYTES:
                raise RuntimeError(
                    f"Insufficient macro pool free space ({free_info.free_bytes}B <= {MIN_SAFE_FREE_BYTES}B)"
                )

            if dry_run:
                return {
                    "obj_id": f"0x{obj_id:04X}",
                    "size": size,
                    "chunk_count": len(chunk_frames),
                    "dry_run": True,
                    "create_frame_hex": create_frame.hex(),
                    "verified": False,
                }

            _, create_reply = self.session.query(self.target_role, create_frame.data)
            if not create_reply.is_ok:
                raise RuntimeError(f"0x0B create 0x{obj_id:04X} failed: {create_reply.status_name}")

            for idx, cf in enumerate(chunk_frames):
                _, chunk_reply = self.session.query(self.target_role, cf.data)
                if not chunk_reply.is_ok:
                    raise RuntimeError(
                        f"0x0D chunk {idx}/{len(chunk_frames)} failed for 0x{obj_id:04X}: {chunk_reply.status_name}"
                    )

            verified = False
            if verify_readback:
                self._preflight_rf_link()
                read_back = self.read_macro(obj_id, size=size)
                if read_back != payload:
                    raise RuntimeError(
                        f"Macro 0x{obj_id:04X} readback mismatch (wrote {size}B, got {len(read_back)}B)"
                    )
                verified = True

            return {
                "obj_id": f"0x{obj_id:04X}",
                "size": size,
                "chunk_count": len(chunk_frames),
                "dry_run": False,
                "verified": verified,
            }
