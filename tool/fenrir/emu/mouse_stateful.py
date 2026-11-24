"""Stateful Cortex-M4 Unicorn mouse emulator with synthetic NVMC Flash pages.

Reused across Phase 1 write-path verification (`write_proof.py`) and Phase 2
firmware patch verification (`test_phase2_patcher.py`). Never uses
`UC_HOOK_MEM_READ` on Thumb-2 code (Unicorn IT-block bug); relies exclusively
on `UC_HOOK_CODE` plus RAM/Flash inspections.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_MCLASS, UC_MODE_THUMB, Uc
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_SP,
    UC_CPU_ARM_CORTEX_M4,
)

from fenrir.constants import DEVICE_FRAME_LEN, REFERENCE_FIRMWARES
from fenrir.emu.hex_loader import HexImage
from fenrir.emu.readonly_proof import RETURN_SENTINEL, STACK_TOP, SYNTHETIC_DEVICE_ID

DEFAULT_NV_FLASH_REGIONS: tuple[tuple[int, int], ...] = (
    (0x50000, 0x1000),
    (0x8C000, 0x1000),
    (0x90000, 0x50000),
    (0xEB000, 0x1000),
    (0xEC000, 0x1000),
)

CodeHookFn = Callable[[Uc, int, int], None]


@dataclass
class CallResult:
    returned: bool
    r0: int
    instructions: int
    erased_pages: list[int] = field(default_factory=list)
    hit_watch_sites: list[str] = field(default_factory=list)
    hit_forbidden_sites: list[str] = field(default_factory=list)
    stopped_reason: str | None = None


@dataclass
class DispatchResult(CallResult):
    reply_64: bytes = b""


class StatefulMouseEmu:
    """Persistent-RAM and synthetic-NVMC-Flash Unicorn emulator for mouse firmware."""

    FRAME_BUF_ADDR = 0x20005FA8
    RX_PENDING_FLAG_ADDR = 0x20003CF3
    DIRTY_BITSET_ADDR = 0x20003217
    SAVE_DELAY_TICKS_ADDR = 0x20003218
    SENSOR_ID_ADDR = 0x20003246
    TRANSPORT_MODE_ADDR = 0x20003204
    WIRED_CONFIGURED_ADDR = 0x200040B9
    CONFIG_BLOB_ADDR = 0x20004374
    CONFIG_BLOB_LEN = 531
    NVMC_READY_ADDR = 0x4001E400
    NVMC_ERASEPAGE_ADDR = 0x4001E508
    NVMC_ERASE_WAIT_SITE = 0x1434E

    def __init__(
        self,
        hex_path: Path | None = None,
        *,
        sensor_id: int = 0x53,
        transport_mode: int = 0,
        extra_flash_regions: Sequence[tuple[int, int]] = (),
        nvmc_erase_wait_site: int = NVMC_ERASE_WAIT_SITE,
    ) -> None:
        self.ref = REFERENCE_FIRMWARES["mouse"]
        self.img = HexImage(hex_path or self.ref.hex_path)
        self.sensor_id = sensor_id
        self.transport_mode = transport_mode
        self.nvmc_erase_wait_site = nvmc_erase_wait_site
        self.runtime_bins = [(p, addr, p.read_bytes()) for p, addr in self.ref.resolved_runtime_bins()]

        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)

        code_lo = self.img.base & ~4095
        code_hi = (self.img.end + 4095) & ~4095
        self.uc.mem_map(code_lo, code_hi - code_lo)
        for start, end in self.img.ranges:
            self.uc.mem_write(start, self.img.get(start, end - start))

        self.uc.mem_map(0x20000000, 0x80000)
        for _p, addr, data in self.runtime_bins:
            self.uc.mem_write(addr, data)

        self._mapped_flash: list[tuple[int, int]] = []
        for base, size in (*DEFAULT_NV_FLASH_REGIONS, *extra_flash_regions):
            lo = base & ~4095
            hi = (base + size + 4095) & ~4095
            if hi <= code_lo or lo >= code_hi:
                if not any(m_lo <= lo and hi <= m_hi for m_lo, m_hi in self._mapped_flash):
                    self.uc.mem_map(lo, hi - lo)
                    self.uc.mem_write(lo, b"\xFF" * (hi - lo))
                    self._mapped_flash.append((lo, hi))

        self.uc.mem_map(0x10000000, 0x1000)
        self.uc.mem_write(RETURN_SENTINEL, bytes.fromhex("00be"))
        self.uc.mem_write(0x10000060, struct.pack("<I", SYNTHETIC_DEVICE_ID))

        self.uc.mem_map(0x40000000, 0x30000)
        self.uc.mem_map(0x50000000, 0x1000)
        self.uc.mem_map(0xE000E000, 0x2000)
        self.uc.mem_write(self.NVMC_READY_ADDR, struct.pack("<I", 1))

        self.seed_stock_defaults()

    def seed_stock_defaults(self, *, init_pool: bool = True) -> None:
        self._seed_runtime_flags()
        self.uc.mem_write(self.CONFIG_BLOB_ADDR, self.img.get(0x21692, self.CONFIG_BLOB_LEN))
        self.uc.mem_write(0x20004380, b"\x00\x01")
        self.uc.mem_write(0x20003A80, b"\x64\x00")
        if init_pool:
            self.call(0x12F08)
        self.uc.mem_write(self.DIRTY_BITSET_ADDR, b"\x00")
        self.uc.mem_write(self.SAVE_DELAY_TICKS_ADDR, b"\x00\x00")

    def _seed_runtime_flags(self) -> None:
        self.uc.mem_write(self.TRANSPORT_MODE_ADDR, bytes([self.transport_mode]))
        self.uc.mem_write(self.WIRED_CONFIGURED_ADDR, b"\x01" if self.transport_mode == 0 else b"\x00")
        self.uc.mem_write(self.SENSOR_ID_ADDR, bytes([self.sensor_id]))
        self.uc.mem_write(self.DIRTY_BITSET_ADDR, b"\x00")
        self.uc.mem_write(self.SAVE_DELAY_TICKS_ADDR, b"\x00\x00")

    def simulate_reboot_and_reload(self, boot_init_addr: int = 0x111E0) -> CallResult:
        """Reset RAM from scatter runtime bins while keeping NV Flash, then run boot loader."""
        self.uc.mem_write(0x20003200, b"\x00" * 0x8E00)
        for _p, addr, data in self.runtime_bins:
            self.uc.mem_write(addr, data)
        self._seed_runtime_flags()
        return self.call(boot_init_addr)

    def ram_read(self, addr: int, size: int) -> bytes:
        return bytes(self.uc.mem_read(addr, size))

    def ram_write(self, addr: int, data: bytes) -> None:
        self.uc.mem_write(addr, data)

    def flash_read(self, addr: int, size: int) -> bytes:
        return bytes(self.uc.mem_read(addr, size))

    def flash_write(self, addr: int, data: bytes) -> None:
        self.uc.mem_write(addr, data)

    def call(
        self,
        entry: int,
        args: Sequence[int] = (),
        *,
        watch_sites: dict[int, str] | None = None,
        forbidden_sites: dict[int, str] | None = None,
        code_hook: CodeHookFn | None = None,
        max_steps: int = 300_000,
    ) -> CallResult:
        self.uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN_SENTINEL | 1)
        for i, reg in enumerate((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)):
            self.uc.reg_write(reg, args[i] if i < len(args) else 0)

        erased_pages: list[int] = []
        hit_watch: list[str] = []
        seen_watch: set[int] = set()
        hit_forbidden: list[str] = []
        stopped_reason: list[str | None] = [None]
        returned = [False]
        count = [0]
        w_map = watch_sites or {}
        f_map = forbidden_sites or {}

        def on_code(uc: Uc, addr: int, size: int, _user: object) -> None:
            count[0] += 1
            if addr == RETURN_SENTINEL:
                returned[0] = True
                uc.emu_stop()
                return
            if addr == self.nvmc_erase_wait_site:
                page = struct.unpack("<I", uc.mem_read(self.NVMC_ERASEPAGE_ADDR, 4))[0] & ~4095
                uc.mem_write(page, b"\xFF" * 4096)
                erased_pages.append(page)
            if addr in w_map and addr not in seen_watch:
                seen_watch.add(addr)
                hit_watch.append(f"0x{addr:08X}:{w_map[addr]}")
            if addr in f_map:
                hit_forbidden.append(f"0x{addr:08X}:{f_map[addr]}")
                stopped_reason[0] = f"hit_forbidden:{f_map[addr]}"
                uc.emu_stop()
                return
            if code_hook is not None:
                code_hook(uc, addr, size)

        hook = self.uc.hook_add(UC_HOOK_CODE, on_code)
        try:
            try:
                self.uc.emu_start(entry | 1, 0, count=max_steps)
            except Exception as exc:
                stopped_reason[0] = f"uc_exception:{exc}"
        finally:
            self.uc.hook_del(hook)

        return CallResult(
            returned=returned[0],
            r0=self.uc.reg_read(UC_ARM_REG_R0),
            instructions=max(0, count[0] - 1),
            erased_pages=erased_pages,
            hit_watch_sites=hit_watch,
            hit_forbidden_sites=hit_forbidden,
            stopped_reason=stopped_reason[0],
        )

    def dispatch_frame(
        self,
        frame_64: bytes,
        *,
        watch_sites: dict[int, str] | None = None,
        forbidden_sites: dict[int, str] | None = None,
        code_hook: CodeHookFn | None = None,
    ) -> DispatchResult:
        if len(frame_64) != DEVICE_FRAME_LEN:
            raise ValueError(f"Expected {DEVICE_FRAME_LEN}B frame, got {len(frame_64)}B")
        self.uc.mem_write(self.FRAME_BUF_ADDR, frame_64)
        self.uc.mem_write(self.RX_PENDING_FLAG_ADDR, b"\x01")
        res = self.call(
            0x18494,
            watch_sites=watch_sites,
            forbidden_sites=forbidden_sites,
            code_hook=code_hook,
        )
        reply = bytes(self.uc.mem_read(self.FRAME_BUF_ADDR, DEVICE_FRAME_LEN))
        return DispatchResult(
            returned=res.returned,
            r0=res.r0,
            instructions=res.instructions,
            erased_pages=res.erased_pages,
            hit_watch_sites=res.hit_watch_sites,
            hit_forbidden_sites=res.hit_forbidden_sites,
            stopped_reason=res.stopped_reason,
            reply_64=reply,
        )

    def persist_pending(
        self,
        *,
        watch_sites: dict[int, str] | None = None,
        forbidden_sites: dict[int, str] | None = None,
    ) -> CallResult:
        self.uc.mem_write(self.SAVE_DELAY_TICKS_ADDR, b"\x00\x00")
        return self.call(0x177CC, watch_sites=watch_sites, forbidden_sites=forbidden_sites)
