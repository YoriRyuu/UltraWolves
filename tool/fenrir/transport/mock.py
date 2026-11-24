"""Deterministic mock transport and Unicorn-backed live-firmware offline transport."""

from __future__ import annotations

import struct
from collections import deque
from pathlib import Path
from typing import Any, Callable

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_MCLASS, UC_MODE_THUMB, Uc
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_SP,
    UC_CPU_ARM_CORTEX_M4,
)

from fenrir.constants import (
    DEVICE_FRAME_LEN,
    EXPECTED_FEATURE_USAGE,
    EXPECTED_FEATURE_USAGE_PAGE,
    FENRIR_DEV_ROOT,
    HID_FEATURE_REPORT_LEN,
    REFERENCE_FIRMWARES,
    STATUS_OK,
    STATUS_PENDING,
    VENDOR_ID,
)

PHASE2_MOUSE_HEX_PATH: Path = (
    FENRIR_DEV_ROOT / "build" / "Fenrir+035-8K_Mouse_App_FW_v1.00.39.00_Phase2_NOT_FOR_FLASH.hex"
)
PHASE3_MOUSE_HEX_PATH: Path = (
    FENRIR_DEV_ROOT / "build" / "Fenrir+035-8K_Mouse_App_FW_v1.00.39.00_Phase3_NOT_FOR_FLASH.hex"
)
PHASE3PLUS_MOUSE_HEX_PATH: Path = (
    FENRIR_DEV_ROOT / "build" / "Fenrir+035-8K_Mouse_App_FW_v1.00.39.00_Phase3Plus_NOT_FOR_FLASH.hex"
)
_MOUSE_HEX_ALIASES: dict[str, Path] = {
    "auto": PHASE2_MOUSE_HEX_PATH,
    "phase2": PHASE2_MOUSE_HEX_PATH,
    "phase3": PHASE3_MOUSE_HEX_PATH,
    "phase3plus": PHASE3PLUS_MOUSE_HEX_PATH,
}


class _VirtualPaw3950:
    """Minimal register-level PAW3950 model attached to nRF52840 SPIM3 EasyDMA."""

    def __init__(self) -> None:
        self.bank: int = 0
        self.latched_reg: int = 0
        self.regs: dict[tuple[int, int], int] = {
            (0x00, 0x00): 0x51,
            (0x00, 0x6C): 0x80,
            (0x00, 0x15): 0x00,
            (0x00, 0x40): 0x00,
            (0x05, 0x44): 0x20,
            (0x06, 0x53): 0x03,
            (0x06, 0x62): 0x02,
            (0x06, 0x6D): 0x41,
            (0x06, 0x6E): 0x42,
            (0x07, 0x42): 0x14,
            (0x0C, 0x4D): 0x90,
            (0x0D, 0x4F): 0x7A,
        }
        self.ops: list[tuple[str, int, int, int]] = []

    def write_reg(self, reg: int, val: int) -> None:
        val_b = val & 0xFF
        self.ops.append(("W", self.bank, reg, val_b))
        if reg == 0x7F:
            self.bank = val_b
        else:
            self.regs[(self.bank, reg)] = val_b

    def read_reg(self, reg: int) -> int:
        if reg == 0x7F:
            val = 0x51 if self.bank == 0 else self.bank
        else:
            val = self.regs.get((self.bank, reg), 0)
        self.ops.append(("R", self.bank, reg, val))
        return val
from fenrir.emu.hex_loader import HexImage
from fenrir.emu.readonly_proof import run_mouse_frame, run_rx_usb_frame
from fenrir.protocol.frames import from_hid_feature_report, to_hid_feature_report
from fenrir.transport.base import (
    FeatureTransport,
    HidDeviceInfo,
    classify_hid_device,
)


def make_mock_device(
    path: str,
    pid: int,
    *,
    vid: int = VENDOR_ID,
    product: str = "Fenrir Mock Device",
    interface_number: int = 2,
    usage_page: int = EXPECTED_FEATURE_USAGE_PAGE,
    usage: int = EXPECTED_FEATURE_USAGE,
) -> HidDeviceInfo:
    classification, is_feat, notes = classify_hid_device(
        vid, pid, path, interface_number, usage_page, usage=usage
    )
    return HidDeviceInfo(
        path=path,
        vid=vid,
        pid=pid,
        manufacturer="G-Wolves Mock",
        product=product,
        serial="MOCK-0001",
        interface_number=interface_number,
        usage_page=usage_page,
        usage=usage,
        release_number=0x0100,
        classification=classification,
        is_feature_candidate=is_feat,
        notes=notes,
    )


class MockFeatureTransport(FeatureTransport):
    """Programmable in-memory HID Feature transport for unit tests."""

    def __init__(
        self,
        devices: list[HidDeviceInfo] | None = None,
        responder: Callable[[bytes], list[bytes]] | None = None,
        passive_frame_64: bytes | None = None,
    ) -> None:
        self._devices = list(devices or [])
        self._responder = responder
        self._open_device: HidDeviceInfo | None = None
        self._rx_queue: deque[bytes] = deque()
        self._last_passive = passive_frame_64 or bytes(DEVICE_FRAME_LEN)
        self.sent_reports: list[bytes] = []

    def enumerate_devices(self, vid: int = VENDOR_ID) -> list[HidDeviceInfo]:
        if vid == 0:
            return list(self._devices)
        return [d for d in self._devices if d.vid == vid]

    def open(self, path: str) -> HidDeviceInfo:
        for d in self._devices:
            if d.path == path:
                self._open_device = d
                return d
        raise FileNotFoundError(f"Mock device path not found: {path}")

    def close(self) -> None:
        self._open_device = None

    def get_feature_report(self, report_id: int = 0, length: int = HID_FEATURE_REPORT_LEN) -> bytes:
        if self._open_device is None:
            raise RuntimeError("Mock device is not open")
        if self._rx_queue:
            frame_64 = self._rx_queue.popleft()
        else:
            frame_64 = self._last_passive
        return to_hid_feature_report(frame_64)

    def send_feature_report(self, report_65: bytes) -> int:
        if self._open_device is None:
            raise RuntimeError("Mock device is not open")
        self.sent_reports.append(bytes(report_65))
        frame_64 = from_hid_feature_report(report_65)
        if self._responder is not None:
            replies = self._responder(frame_64)
            self._rx_queue.clear()
            for r in replies:
                self._rx_queue.append(r)
            if replies:
                self._last_passive = replies[-1]
        return len(report_65)


class UnicornMockTransport(FeatureTransport):
    """Offline HID transport executed directly by real firmware instructions in Unicorn."""

    MOUSE_PATH = r"\\?\HID#VID_33E4&PID_3508&MI_02#UNICORN_MOUSE"
    RX_USB_PATH = r"\\?\HID#VID_33E4&PID_0017&MI_02#UNICORN_RX_USB"
    _RETURN_SENTINEL = 0x10000000
    _STACK_TOP = 0x20004000
    _MOUSE_STACK_TOP = 0x2007F000
    _SYNTHETIC_DEVICE_ID = 0x11223344
    _MAX_STEPS = 500_000

    def __init__(
        self,
        *,
        sensor_id: int = 0x53,
        simulate_pending_polls: int = 1,
        mouse_connected: bool = True,
        stateful: bool | None = None,
        mouse_hex_path: Path | str | None = None,
    ) -> None:
        self.sensor_id = sensor_id
        self.simulate_pending_polls = simulate_pending_polls
        self.mouse_connected = mouse_connected
        if mouse_hex_path is None:
            resolved_mouse_hex: Path | None = None
        elif isinstance(mouse_hex_path, str) and mouse_hex_path.lower() in _MOUSE_HEX_ALIASES:
            resolved_mouse_hex = _MOUSE_HEX_ALIASES[mouse_hex_path.lower()]
        else:
            resolved_mouse_hex = Path(mouse_hex_path)
        if resolved_mouse_hex is not None and not resolved_mouse_hex.exists():
            raise FileNotFoundError(f"Mouse firmware HEX not found: {resolved_mouse_hex}")
        self.mouse_hex_path: Path | None = resolved_mouse_hex
        self.stateful: bool = (resolved_mouse_hex is not None) if stateful is None else bool(stateful)
        mouse_src = resolved_mouse_hex if resolved_mouse_hex is not None else REFERENCE_FIRMWARES["mouse"].hex_path
        self._mouse_img = HexImage(mouse_src)
        self._rx_usb_img = HexImage(REFERENCE_FIRMWARES["receiver_usb"].hex_path)
        self._rx_2g4_img = HexImage(REFERENCE_FIRMWARES["receiver_2g4"].hex_path)
        self._devices = [
            make_mock_device(self.MOUSE_PATH, 0x3508, product="Fenrir Unicorn Mouse"),
            make_mock_device(self.RX_USB_PATH, 0x0017, product="Fenrir Unicorn 8K Receiver"),
        ]
        self._open_device: HidDeviceInfo | None = None
        self._rx_queue: deque[bytes] = deque()
        self._last_frame = bytes(DEVICE_FRAME_LEN)
        self.last_2g4_frame = bytes(DEVICE_FRAME_LEN)
        self.last_d266_called = False
        self.last_c328_called = False
        self.last_c328_forwarded_frame: bytes | None = None
        self._mouse_uc: Uc | None = None
        self.paw3950 = _VirtualPaw3950()

    def reset_state(self) -> None:
        """Reset persistent stateful Unicorn mouse RAM/Flash image."""
        self._mouse_uc = None
        self.paw3950 = _VirtualPaw3950()

    def soft_reset(self) -> None:
        """Simulate MCU reset: clear RAM and sensor, preserve Flash NV, and run startup init."""
        if self._mouse_uc is None:
            self.reset_state()
            return
        flash_snapshot = bytes(self._mouse_uc.mem_read(0x50000, 0xA0000))
        self.paw3950 = _VirtualPaw3950()
        self._mouse_uc = self._init_stateful_mouse_uc(flash_snapshot=flash_snapshot)

    def _init_stateful_mouse_uc(self, *, flash_snapshot: bytes | None = None) -> Uc:
        ref = REFERENCE_FIRMWARES["mouse"]
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)

        lo = self._mouse_img.base & ~4095
        hi = (self._mouse_img.end + 4095) & ~4095
        uc.mem_map(lo, hi - lo)
        for start, end in self._mouse_img.ranges:
            uc.mem_write(start, self._mouse_img.get(start, end - start))

        uc.mem_map(0x20000000, 0x80000)
        for bin_path, addr in ref.resolved_runtime_bins():
            uc.mem_write(addr, bin_path.read_bytes())

        # Synthetic NV & object-pool Flash pages (0x50000..0xF0000) erased to 0xFF (or preserved across soft_reset)
        uc.mem_map(0x50000, 0xA0000)
        if flash_snapshot is not None:
            uc.mem_write(0x50000, flash_snapshot)
        else:
            uc.mem_write(0x50000, b"\xFF" * 0xA0000)

        uc.mem_map(0x10000000, 0x1000)
        uc.mem_write(self._RETURN_SENTINEL, bytes.fromhex("00be"))
        uc.mem_write(0x10000060, struct.pack("<I", self._SYNTHETIC_DEVICE_ID))

        uc.mem_map(0x40000000, 0x30000)
        uc.mem_map(0x50000000, 0x1000)
        uc.mem_map(0xE000E000, 0x2000)

        uc.mem_write(0x4001E400, struct.pack("<I", 1))  # NVMC->READY = 1
        uc.mem_write(0x14338, bytes.fromhex("7047"))    # nrfx_nvmc_page_erase -> BX LR (erased by hook)
        uc.mem_write(0x21448, bytes.fromhex("01207047"))  # radio_send_enqueue_gate -> return 1

        uc.mem_write(0x20003204, b"\x00")
        uc.mem_write(0x200040B9, b"\x01")
        uc.mem_write(0x20003246, bytes([self.sensor_id]))
        uc.mem_write(0x20003217, b"\x00")
        uc.mem_write(0x20003218, b"\x00\x00")
        uc.mem_write(0x20004374, self._mouse_img.get(0x21692, 531))
        uc.mem_write(0x20004380, b"\x00")
        uc.mem_write(0x20004381, b"\x01")
        uc.mem_write(0x20003A80, b"\x01\x32")

        self._exec_mouse_uc(uc, 0x111E0)  # Load defaults & init object pool (0x12F08 + 0x10FC4)
        uc.mem_write(0x20003246, bytes([self.sensor_id]))
        uc.mem_write(0x20004380, b"\x00")
        uc.mem_write(0x20004381, b"\x01")
        if self.mouse_hex_path is not None:
            # Seed Phase 2 sensor/SPIM3/RF runtime flags before executing startup_hook (0x1301A).
            uc.mem_write(0x20004114, b"\x01")  # RAM_SPI_IDLE
            uc.mem_write(0x20004118, b"\x00")  # RAM_SPI_BURST_ACTIVE
            uc.mem_write(0x2000411C, b"\x01")  # RAM_SENSOR_ENABLED
            uc.mem_write(0x2000326E, b"\x01")  # RAM_MOTION_GATE
            uc.mem_write(0x2000325D, b"\x01")  # RAM_SENSOR_MODE_TARGET
            uc.mem_write(0x2000325A, b"\x01")  # RAM_SENSOR_MODE_APPLIED
            uc.mem_write(0x20003262, struct.pack("<HH", 1600, 1600))
            uc.mem_write(0x200078F4, b"\x01")  # RF PHY TX ready flag
            self._exec_mouse_uc(uc, 0x1301A, stop_addr=0x1301E)
            self._pump_mouse_workers(uc)
        return uc

    def _exec_mouse_uc(self, uc: Uc, entry: int, *, stop_addr: int = 0) -> None:
        def on_code(u: Uc, addr: int, _size: int, _user: Any) -> None:
            if addr == self._RETURN_SENTINEL or addr == 0x0906A:
                u.emu_stop()
            elif addr == 0x218B0:
                u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR) | 1)
            elif addr == 0x14338:
                page = u.reg_read(UC_ARM_REG_R0) & ~0xFFF
                u.mem_write(page, b"\xFF" * 4096)
            elif addr == 0x1F272:
                tx_ptr = int.from_bytes(u.mem_read(0x4002F544, 4), "little")
                tx_len = int.from_bytes(u.mem_read(0x4002F548, 4), "little")
                rx_ptr = int.from_bytes(u.mem_read(0x4002F534, 4), "little")
                rx_len = int.from_bytes(u.mem_read(0x4002F538, 4), "little")
                if tx_len >= 1:
                    self.paw3950.latched_reg = u.mem_read(tx_ptr, 1)[0] & 0x7F
                if tx_len == 0 and rx_len == 1:
                    u.mem_write(rx_ptr, bytes([self.paw3950.read_reg(self.paw3950.latched_reg)]))
                elif tx_len == 2 and rx_len == 0:
                    val = u.mem_read(tx_ptr, 2)[1]
                    self.paw3950.write_reg(self.paw3950.latched_reg, val)
                u.mem_write(0x20004114, b"\x01")

        hook = uc.hook_add(UC_HOOK_CODE, on_code)
        try:
            uc.reg_write(UC_ARM_REG_SP, self._MOUSE_STACK_TOP)
            uc.reg_write(UC_ARM_REG_LR, self._RETURN_SENTINEL | 1)
            for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3):
                uc.reg_write(reg, 0)
            uc.emu_start(entry | 1, stop_addr, count=self._MAX_STEPS)
        finally:
            uc.hook_del(hook)

    def _pump_mouse_workers(self, uc: Uc, *, max_polls: int = 200) -> None:
        if uc.mem_read(0x20005895, 1)[0] == 0 and uc.mem_read(0x20005896, 1)[0] == 0:
            return
        self._exec_mouse_uc(uc, 0x1E150)  # worker_kick
        for _ in range(max_polls):
            self._exec_mouse_uc(uc, 0x1E1E0)  # worker_poll
            if uc.mem_read(0x20005896, 1)[0] == 0:
                return
        raise RuntimeError("Phase 2 cooperative worker did not go idle within poll limit")

    def _run_mouse(self, frame_64: bytes, *, wired: bool) -> bytes:
        if not self.stateful:
            res = run_mouse_frame(self._mouse_img, frame_64, sensor_id=self.sensor_id)
            return bytes.fromhex(res.output_frame_hex)
        if self._mouse_uc is None:
            self._mouse_uc = self._init_stateful_mouse_uc()
        uc = self._mouse_uc
        uc.mem_write(0x20003204, b"\x00" if wired else b"\x01")
        uc.mem_write(0x200040B9, b"\x01" if wired else b"\x00")
        uc.mem_write(0x20003A80, b"\x01\x32" if wired else b"\x00\x3C")
        uc.mem_write(0x20005FA8, frame_64)
        uc.mem_write(0x20003CF3, b"\x01")
        self._exec_mouse_uc(uc, 0x18494)
        reply = bytes(uc.mem_read(0x20005FA8, DEVICE_FRAME_LEN))
        if self.mouse_hex_path is not None:
            self._pump_mouse_workers(uc)
        return reply

    def read_mouse_mem(self, addr: int, size: int) -> bytes:
        """Inspect stateful Unicorn mouse RAM/Flash bytes (for offline verification)."""
        if self._mouse_uc is None:
            self._mouse_uc = self._init_stateful_mouse_uc()
        return bytes(self._mouse_uc.mem_read(addr, size))

    def enumerate_devices(self, vid: int = VENDOR_ID) -> list[HidDeviceInfo]:
        if vid == 0:
            return list(self._devices)
        return [d for d in self._devices if d.vid == vid]

    def open(self, path: str) -> HidDeviceInfo:
        for d in self._devices:
            if d.path == path:
                self._open_device = d
                return d
        raise FileNotFoundError(f"Unicorn mock device not found: {path}")

    def close(self) -> None:
        self._open_device = None

    def get_feature_report(self, report_id: int = 0, length: int = HID_FEATURE_REPORT_LEN) -> bytes:
        if self._open_device is None:
            raise RuntimeError("Device not open")
        frame_64 = self._rx_queue.popleft() if self._rx_queue else self._last_frame
        return to_hid_feature_report(frame_64)

    def _run_rx_2g4_b21c(self, frame_64: bytes) -> tuple[bytes, bool, bytes | None, bool]:
        """Execute real 2.4G firmware 0xB21C router in Unicorn, capturing 0xC328/0xD266 calls."""
        ref = REFERENCE_FIRMWARES["receiver_2g4"]
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)

        lo = self._rx_2g4_img.base & ~4095
        hi = (self._rx_2g4_img.end + 4095) & ~4095
        uc.mem_map(lo, hi - lo)
        for start, end in self._rx_2g4_img.ranges:
            uc.mem_write(start, self._rx_2g4_img.get(start, end - start))

        uc.mem_map(0x20000000, 0x10000)
        for bin_path, addr in ref.resolved_runtime_bins():
            uc.mem_write(addr, bin_path.read_bytes())

        uc.mem_map(0x10000000, 0x1000)
        uc.mem_write(self._RETURN_SENTINEL, bytes.fromhex("00be"))
        uc.mem_write(0x10000060, struct.pack("<I", self._SYNTHETIC_DEVICE_ID))
        uc.mem_map(0x40000000, 0x30000)
        uc.mem_map(0x50000000, 0x1000)
        uc.mem_map(0xE000E000, 0x2000)

        uc.mem_write(0x2000130E, bytes.fromhex("AABBCCDD"))
        uc.mem_write(0x2000132E, bytes.fromhex("0122334455"))
        uc.mem_write(0x20000014, b"\x01")
        uc.mem_write(0x200028DD, b"\x01" if self.mouse_connected else b"\x00")

        buf = bytearray(frame_64)
        buf[0] = STATUS_PENDING
        uc.mem_write(0x20001338, bytes(buf))

        # Return 1 cleanly from SPI/RF enqueue helpers inside this transport harness while tracing args.
        uc.mem_write(0xC328, bytes.fromhex("01207047"))  # MOVS R0, #1; BX LR
        uc.mem_write(0xD266, bytes.fromhex("01207047"))  # MOVS R0, #1; BX LR

        c328_called = False
        d266_called = False
        forwarded_frame: bytes | None = None

        def on_code(u: Uc, addr: int, _size: int, _user: Any) -> None:
            nonlocal c328_called, d266_called, forwarded_frame
            if addr == self._RETURN_SENTINEL:
                u.emu_stop()
            elif addr == 0xC328:
                c328_called = True
                ptr = u.reg_read(UC_ARM_REG_R1)
                rf_len = min(u.reg_read(UC_ARM_REG_R2), DEVICE_FRAME_LEN)
                forwarded_frame = (bytes(u.mem_read(ptr, rf_len)) + bytes(DEVICE_FRAME_LEN))[:DEVICE_FRAME_LEN]
            elif addr == 0xD266:
                d266_called = True

        hook = uc.hook_add(UC_HOOK_CODE, on_code)
        try:
            uc.reg_write(UC_ARM_REG_SP, self._STACK_TOP)
            uc.reg_write(UC_ARM_REG_LR, self._RETURN_SENTINEL | 1)
            for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3):
                uc.reg_write(reg, 0)
            uc.emu_start(0xB21C | 1, 0, count=self._MAX_STEPS)
        finally:
            uc.hook_del(hook)

        out_2g4 = bytes(uc.mem_read(0x20001338, DEVICE_FRAME_LEN))
        return out_2g4, c328_called, forwarded_frame, d266_called

    def send_feature_report(self, report_65: bytes) -> int:
        if self._open_device is None:
            raise RuntimeError("Device not open")
        frame_64 = from_hid_feature_report(report_65)
        self.last_d266_called = False
        self.last_c328_called = False
        self.last_c328_forwarded_frame = None
        stall_pending = False

        if self._open_device.path == self.MOUSE_PATH:
            final_frame = self._run_mouse(frame_64, wired=True)
        elif self._open_device.path == self.RX_USB_PATH:
            if frame_64[1] == 0 and frame_64[2] == 0:
                res = run_rx_usb_frame(self._rx_usb_img, frame_64)
                out = bytearray.fromhex(res.output_frame_hex)
                if out[0] == STATUS_PENDING:
                    out[0] = STATUS_OK
                final_frame = bytes(out)
            elif frame_64[4] == 0xB0:
                # Q3: USB 0x8006870 latches sticky bootloader SPI bridge instead of forwarding to 0xB21C.
                stall_pending = True
                final_frame = bytes([STATUS_PENDING, *frame_64[1:]])
            else:
                out_2g4, c328_called, forwarded_frame, d266_called = self._run_rx_2g4_b21c(frame_64)
                self.last_2g4_frame = out_2g4
                self.last_c328_called = c328_called
                self.last_c328_forwarded_frame = forwarded_frame
                self.last_d266_called = d266_called

                if c328_called and forwarded_frame is not None:
                    final_frame = self._run_mouse(forwarded_frame, wired=False)
                    self.last_d266_called = True
                elif d266_called:
                    final_frame = out_2g4
                else:
                    # Q2 trap: disconnected mouse sets local 0xA4 without calling 0xD266 -> USB GET_REPORT stuck at 0xA0.
                    stall_pending = True
                    final_frame = bytes([STATUS_PENDING, *frame_64[1:]])
        else:
            raise RuntimeError(f"Unsupported path {self._open_device.path}")

        self._rx_queue.clear()
        if not stall_pending and self.simulate_pending_polls > 0:
            pending = bytearray(frame_64)
            pending[0] = STATUS_PENDING
            for _ in range(self.simulate_pending_polls):
                self._rx_queue.append(bytes(pending))
        self._rx_queue.append(final_frame)
        self._last_frame = final_frame
        return len(report_65)
