"""Offline firmware patch builder for the Fenrir mouse APP (NOT_FOR_FLASH).

This package is strictly offline: it reads verified stock Intel HEX images,
verifies pre-patch byte fingerprints, assembles Thumb/Thumb-2 code with
mandatory Capstone round-trip verification, and writes patched HEX images +
JSON build manifests tagged ``NOT_FOR_FLASH``. It contains zero USB/HID I/O
or flashing functionality.
"""

from __future__ import annotations

from fenrir.patcher.hex_io import (
    NOT_FOR_FLASH_TAG,
    NOT_FOR_FLASH_WARNING,
    AddressRange,
    AllocationError,
    CaveAllocation,
    FingerprintMismatchError,
    HexImage,
    HexIoError,
    HexPatchBuilder,
    PatchEdit,
    ProtectedRegionError,
    render_intel_hex,
)
from fenrir.patcher.thumb import (
    AssembledBlock,
    PatchContext,
    ThumbAssembler,
    ThumbEncodeError,
    VerifiedInstruction,
    assemble,
    disassemble,
    encode_bl,
    encode_b_w,
    verify_branch_patch,
)

__all__ = [
    "NOT_FOR_FLASH_TAG",
    "NOT_FOR_FLASH_WARNING",
    "AddressRange",
    "AllocationError",
    "AssembledBlock",
    "CaveAllocation",
    "FingerprintMismatchError",
    "HexImage",
    "HexIoError",
    "HexPatchBuilder",
    "PatchContext",
    "PatchEdit",
    "ProtectedRegionError",
    "ThumbAssembler",
    "ThumbEncodeError",
    "VerifiedInstruction",
    "assemble",
    "disassemble",
    "encode_b_w",
    "encode_bl",
    "render_intel_hex",
    "verify_branch_patch",
]
