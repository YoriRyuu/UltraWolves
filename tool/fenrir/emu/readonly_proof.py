"""Unicorn original-instruction read-only proof generator and verifier.

Runs every candidate read-only command directly through the real firmware
dispatchers (`0x18494` on mouse, `0x08008348` on receiver USB, `0xAFD0` on
receiver 2.4G) with pre/post RAM + MMIO snapshots and UC_HOOK_CODE forbidden-site
monitors (avoiding UC_HOOK_MEM_READ due to Unicorn's Thumb IT-block bug).
"""

from __future__ import annotations

import json
import struct
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
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
    EXPECTED_RECEIVER_2G4_VERSION_BYTES,
    PROOFS_DIR,
    REFERENCE_FIRMWARES,
    REPO_ROOT,
    SENSOR_INTERNAL_TO_REPLY_BYTE,
    STATUS_INVALID,
    STATUS_OK,
    STATUS_PENDING,
    STATUS_RF_DISCONNECTED,
)
from fenrir.emu.hex_loader import HexImage
from fenrir.protocol.catalog import (
    COMMAND_CATALOG,
    CommandSpec,
    ProtocolFamily,
    TargetRole,
    build_frame_from_spec,
    iter_readonly_candidates,
)
from fenrir.protocol.frames import build_family_a_frame, build_family_b_frame

RETURN_SENTINEL = 0x10000000
STACK_TOP = 0x2007F000
STACK_WATCH_FLOOR = 0x2007C000
SYNTHETIC_DEVICE_ID = 0x11223344
MAX_STEPS = 200_000


@dataclass
class EmuExecutionResult:
    returned: bool
    instructions: int
    r0: int
    hit_forbidden_sites: list[str]
    stopped_reason: str | None
    ram_diff_ranges: list[dict[str, Any]]
    mmio_diff_addrs: list[str]
    nvic_diff_addrs: list[str]
    output_frame_hex: str
    wdt_kicked: bool = False
    hit_watch_sites: list[str] = field(default_factory=list)


def _diff_regions(
    before: bytes, after: bytes, base_addr: int
) -> list[tuple[int, int]]:
    """Return contiguous [start, end_exclusive) ranges where bytes differ."""
    if before == after:
        return []
    ranges: list[tuple[int, int]] = []
    in_diff = False
    start = 0
    for i, (a, b) in enumerate(zip(before, after)):
        if a != b and not in_diff:
            start = i
            in_diff = True
        elif a == b and in_diff:
            ranges.append((base_addr + start, base_addr + i))
            in_diff = False
    if in_diff:
        ranges.append((base_addr + start, base_addr + len(before)))
    return ranges


def _ranges_subset_of_allowed(
    diffs: list[tuple[int, int]], allowed: list[tuple[int, int]]
) -> tuple[bool, list[dict[str, Any]]]:
    """Check that every modified byte falls inside `allowed` intervals."""
    outside: list[dict[str, Any]] = []
    for s, e in diffs:
        for addr in range(s, e):
            if not any(lo <= addr < hi for lo, hi in allowed):
                if outside and outside[-1]["end_exclusive"] == addr:
                    outside[-1]["end_exclusive"] = addr + 1
                else:
                    outside.append({"start": addr, "end_exclusive": addr + 1})
    formatted = [
        {"start": f"0x{x['start']:08X}", "end_exclusive": f"0x{x['end_exclusive']:08X}", "size": x["end_exclusive"] - x["start"]}
        for x in outside
    ]
    return len(outside) == 0, formatted


def _new_cortex_m_cpu(img: HexImage, runtime_bins: list[tuple[Path, int]]) -> Uc:
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)

    lo = img.base & ~4095
    hi = (img.end + 4095) & ~4095
    uc.mem_map(lo, hi - lo)
    for start, end in img.ranges:
        uc.mem_write(start, img.get(start, end - start))

    uc.mem_map(0x20000000, 0x80000)
    for bin_path, addr in runtime_bins:
        uc.mem_write(addr, bin_path.read_bytes())

    # FICR + return sentinel block (0x10000000..0x10001000)
    uc.mem_map(0x10000000, 0x1000)
    uc.mem_write(RETURN_SENTINEL, bytes.fromhex("00be"))
    uc.mem_write(0x10000060, struct.pack("<I", SYNTHETIC_DEVICE_ID))

    # Peripheral MMIO + GPIO + NVIC/SCB
    uc.mem_map(0x40000000, 0x30000)
    uc.mem_map(0x50000000, 0x1000)
    uc.mem_map(0xE000E000, 0x2000)
    return uc


def _run_function_and_diff(
    uc: Uc,
    entry: int,
    *,
    ram_watch_lo: int,
    ram_watch_size: int,
    allowed_ram_ranges: list[tuple[int, int]],
    forbidden_sites: dict[int, str],
    frame_buf_addr: int,
    low_flash_sentinel: bool = False,
    init_regs: dict[int, int] | None = None,
    watch_sites: dict[int, str] | None = None,
) -> EmuExecutionResult:
    if low_flash_sentinel:
        # Map 0x00000000..0x00001000 ONLY when testing negative control (group2 0x80 R6=0 bug)
        uc.mem_map(0x00000000, 0x1000)
        uc.mem_write(0x00000000, bytes(range(256)) * 16)

    ram_before = bytes(uc.mem_read(ram_watch_lo, ram_watch_size))
    magic_watch_addrs = [0x2003FFFC, 0x20006FFC, 0x200197FC]
    magic_before = {a: bytes(uc.mem_read(a, 4)) for a in magic_watch_addrs}
    mmio_before = bytes(uc.mem_read(0x40000000, 0x30000))
    gpio_before = bytes(uc.mem_read(0x50000000, 0x1000))
    nvic_before = bytes(uc.mem_read(0xE000E000, 0x2000))

    uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
    uc.reg_write(UC_ARM_REG_LR, RETURN_SENTINEL | 1)
    for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3):
        uc.reg_write(reg, 0)
    if init_regs:
        for reg, val in init_regs.items():
            uc.reg_write(reg, val)

    count = [0]
    returned = [False]
    hit_forbidden: list[str] = []
    hit_watch: list[str] = []
    seen_watch: set[int] = set()
    stopped_reason: list[str | None] = [None]
    watch_map = watch_sites or {}

    def on_code(_uc: Uc, addr: int, _size: int, _user: Any) -> None:
        count[0] += 1
        if addr == RETURN_SENTINEL:
            returned[0] = True
            _uc.emu_stop()
            return
        if addr in watch_map and addr not in seen_watch:
            seen_watch.add(addr)
            hit_watch.append(f"0x{addr:08X}:{watch_map[addr]}")
        if addr in forbidden_sites:
            hit_forbidden.append(f"0x{addr:08X}:{forbidden_sites[addr]}")
            stopped_reason[0] = f"hit_forbidden:{forbidden_sites[addr]}"
            _uc.emu_stop()
            return

    hook = uc.hook_add(UC_HOOK_CODE, on_code)
    try:
        try:
            uc.emu_start(entry | 1, 0, count=MAX_STEPS)
        except Exception as exc:
            stopped_reason[0] = f"uc_exception:{exc}"
    finally:
        uc.hook_del(hook)

    ram_after = bytes(uc.mem_read(ram_watch_lo, ram_watch_size))
    mmio_after = bytes(uc.mem_read(0x40000000, 0x30000))
    gpio_after = bytes(uc.mem_read(0x50000000, 0x1000))
    nvic_after = bytes(uc.mem_read(0xE000E000, 0x2000))

    raw_diffs = _diff_regions(ram_before, ram_after, ram_watch_lo)
    for a in magic_watch_addrs:
        if bytes(uc.mem_read(a, 4)) != magic_before[a]:
            raw_diffs.append((a, a + 4))

    _all_allowed, unexpected_ram = _ranges_subset_of_allowed(raw_diffs, allowed_ram_ranges)

    mmio_diffs = _diff_regions(mmio_before, mmio_after, 0x40000000) + _diff_regions(
        gpio_before, gpio_after, 0x50000000
    )
    # Benign nRF52 WDT reload kick (WDT->RR[0] = 0x6E524635 at 0x40010600, called from 0xF9DC -> 0x205E0)
    wdt_kicked = False
    filtered_mmio_diffs: list[tuple[int, int]] = []
    for s, e in mmio_diffs:
        if s == 0x40010600 and e == 0x40010604 and struct.unpack("<I", uc.mem_read(0x40010600, 4))[0] == 0x6E524635:
            wdt_kicked = True
        else:
            filtered_mmio_diffs.append((s, e))

    nvic_diffs = _diff_regions(nvic_before, nvic_after, 0xE000E000)

    out_frame = bytes(uc.mem_read(frame_buf_addr, DEVICE_FRAME_LEN)).hex()
    return EmuExecutionResult(
        returned=returned[0],
        instructions=max(0, count[0] - 1),
        r0=uc.reg_read(UC_ARM_REG_R0),
        hit_forbidden_sites=hit_forbidden,
        stopped_reason=stopped_reason[0],
        ram_diff_ranges=unexpected_ram,
        mmio_diff_addrs=[f"0x{s:08X}..0x{e:08X}" for s, e in filtered_mmio_diffs],
        nvic_diff_addrs=[f"0x{s:08X}..0x{e:08X}" for s, e in nvic_diffs],
        output_frame_hex=out_frame,
        wdt_kicked=wdt_kicked,
        hit_watch_sites=hit_watch,
    )


# --- Mouse (0x18494) ---

MOUSE_FORBIDDEN_SITES: dict[int, str] = {
    0xF304: "Flash_page_erase_dispatch",
    0xF356: "Flash_write_dispatch",
    0xF1D8: "Flash_RMW_page_retry4",
    0x177CC: "config_persist_pending",
    0x1AD9C: "config_mark_dirty",
    0x9024: "SYSRESETREQ_helper",
    0x904C: "SYSRESETREQ_spin",
    0x2047E: "AIRCR_reset_store",
    0x1E108: "sensor_worker_register",
    0x1F190: "sensor_spi_read_reg",
    0x1F1F4: "sensor_spi_write_reg",
    0x1D068: "candidate_sensor_reg56_feature_apply",
    0x1D388: "candidate_sensor_lod_apply",
    0x1DA14: "candidate_sensor_bank0d_reg48_feature_apply",
    0x1DE38: "candidate_sensor_reg4f_feature_apply",
    0x1D0B0: "candidate_sensor_angle_apply",
    0x1D4C0: "sensor_mode_request_or_apply",
    0xCA08: "object_allocate_index",
    0xCC08: "object_delete",
    0x12D94: "object_compact",
    0x20ACC: "object_chunk_stage_flush",
    0xF2BC: "flash_io_pause_radio_and_sampling",
    0xF2DE: "flash_io_resume_radio_and_sampling",
    0x21448: "radio_send_enqueue_gate",
}


def _setup_mouse_uc(img: HexImage, frame_64: bytes, *, sensor_id: int = 0x53) -> Uc:
    ref = REFERENCE_FIRMWARES["mouse"]
    uc = _new_cortex_m_cpu(img, ref.resolved_runtime_bins())
    # Seed realistic wired USB active configuration so 0x18494 runs pure host path
    uc.mem_write(0x20003204, b"\x00")  # transport_mode = 0 (wired)
    uc.mem_write(0x200040B9, b"\x01")  # wired USB configured = 1
    uc.mem_write(0x20003246, bytes([sensor_id]))  # sensor branch ID4F/51/53 (read at 0x1856A)
    uc.mem_write(0x20003217, b"\x00")  # dirty bitset = 0
    uc.mem_write(0x20003218, b"\x00\x00")  # delay = 0
    # Copy default 531B config template from Flash 0x21692 -> RAM 0x20004374
    # (matches config_load_validate_defaults 0x111E0)
    uc.mem_write(0x20004374, img.get(0x21692, 531))
    uc.mem_write(0x20004380, b"\x00")  # active profile 0-based = 0 (profile 1)
    uc.mem_write(0x20004381, b"\x01")  # profile count = 1
    uc.mem_write(0x20003A80, b"\x64\x00")  # sample battery=100, ext=0
    uc.mem_write(0x20005FA8, frame_64)
    uc.mem_write(0x20003CF3, b"\x01")  # config_rx_pending_flag = 1
    return uc


def _mouse_sample_frame(spec: CommandSpec) -> bytes:
    if spec.family == ProtocolFamily.A:
        if spec.group == 0 and spec.cmd == 0x82:
            return build_frame_from_spec(spec, b"", length_override=46).data
        if spec.group == 0 and spec.cmd == 0x88:
            return build_frame_from_spec(spec, b"\x01").data
        if spec.group == 1 and spec.cmd in (0x81, 0x82, 0x83):
            return build_frame_from_spec(spec, b"\x01").data
        if spec.group == 3 and spec.cmd == 0x80:
            return build_frame_from_spec(spec, bytes([1, 1, 0])).data
        return build_frame_from_spec(spec).data
    return build_frame_from_spec(spec).data


def run_mouse_frame(img: HexImage, frame_64: bytes, *, sensor_id: int = 0x53, low_flash: bool = False) -> EmuExecutionResult:
    uc = _setup_mouse_uc(img, frame_64, sensor_id=sensor_id)
    allowed = [
        (0x20005FA8, 0x20005FE8),  # shared 64B reply buffer
        (0x20003CF3, 0x20003CF4),  # config_rx_pending_flag cleared to 0
    ]
    return _run_function_and_diff(
        uc,
        0x18494,
        ram_watch_lo=0x20003200,
        ram_watch_size=0x8E00,  # 0x20003200..0x2000C000
        allowed_ram_ranges=allowed,
        forbidden_sites=MOUSE_FORBIDDEN_SITES,
        frame_buf_addr=0x20005FA8,
        low_flash_sentinel=low_flash,
    )


def prove_mouse() -> dict[str, Any]:
    ref = REFERENCE_FIRMWARES["mouse"]
    img = HexImage(ref.hex_path)
    verified: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    for spec in iter_readonly_candidates(TargetRole.MOUSE_USB):
        req = _mouse_sample_frame(spec)
        res = run_mouse_frame(img, req, sensor_id=0x53)
        out = bytes.fromhex(res.output_frame_hex)
        side_effect_free = (
            res.returned
            and not res.hit_forbidden_sites
            and not res.ram_diff_ranges
            and not res.mmio_diff_addrs
            and not res.nvic_diff_addrs
        )
        ok_status = out[0] == STATUS_OK
        passed = side_effect_free and ok_status

        extra: dict[str, Any] = {}
        if spec.family == ProtocolFamily.B and spec.cmd == 0x81:
            # Cross-check all three sensor branch IDs (4F/51/53 -> 99/95/50)
            branch_replies = {}
            for sid, expected_b in SENSOR_INTERNAL_TO_REPLY_BYTE.items():
                bres = run_mouse_frame(img, req, sensor_id=sid)
                bout = bytes.fromhex(bres.output_frame_hex)
                if bout[0] != STATUS_OK or bout[10] != expected_b or bres.ram_diff_ranges or bres.hit_forbidden_sites:
                    passed = False
                branch_replies[f"0x{sid:02X}"] = {
                    "reply_byte10": f"0x{bout[10]:02X}",
                    "expected": f"0x{expected_b:02X}",
                    "payload_hex": bout[4 : 4 + bout[1]].hex(),
                }
            extra["sensor_branches_verified"] = branch_replies

        entry = {
            "name": spec.name,
            "target_role": spec.target_role.value,
            "family": spec.family.value,
            "route": spec.route,
            "group": spec.group,
            "cmd": spec.cmd,
            "request_hex": req.hex(),
            "output_hex": res.output_frame_hex,
            "reply_status": f"0x{out[0]:02X}",
            "reply_length_field": out[3] if spec.family == ProtocolFamily.A else out[1],
            "instructions": res.instructions,
            "side_effect_free": side_effect_free,
            "passed": passed,
            "unexpected_ram_diffs": res.ram_diff_ranges,
            "mmio_diffs": res.mmio_diff_addrs,
            "wdt_kicked": res.wdt_kicked,
            "nvic_diffs": res.nvic_diff_addrs,
            "hit_forbidden": res.hit_forbidden_sites,
            "stopped_reason": res.stopped_reason,
            **extra,
        }
        verified.append(entry)
        if not passed:
            failures.append(entry)

    # Negative controls (MUST be caught as unsafe or invalid)
    neg_controls: list[dict[str, Any]] = []

    # 1. group0 0x00 with 0xB0 bootloader entry
    neg_bl = build_family_a_frame(0, 0x00, b"\xB0").data
    r_bl = run_mouse_frame(img, neg_bl)
    caught_bl = (not r_bl.returned) and any("SYSRESETREQ" in s for s in r_bl.hit_forbidden_sites) or bool(r_bl.ram_diff_ranges)
    neg_controls.append(
        {
            "name": "neg_group0_0x00_B0_bootloader",
            "request_hex": neg_bl.hex(),
            "caught_as_unsafe": caught_bl,
            "hit_forbidden": r_bl.hit_forbidden_sites,
            "unexpected_ram_diffs": r_bl.ram_diff_ranges,
        }
    )

    # 2. Family B 0x09 restore defaults
    neg_rst = build_family_b_frame(0x09, b"\x01").data
    r_rst = run_mouse_frame(img, neg_rst)
    caught_rst = bool(r_rst.ram_diff_ranges) or bool(r_rst.hit_forbidden_sites)
    neg_controls.append(
        {
            "name": "neg_familyB_0x09_restore_defaults",
            "request_hex": neg_rst.hex(),
            "caught_as_unsafe": caught_rst,
            "hit_forbidden": r_rst.hit_forbidden_sites,
            "unexpected_ram_diffs": r_rst.ram_diff_ranges,
        }
    )

    # 3. group2 0x80 uninitialized R6=0 low-flash read
    neg_g2 = build_family_a_frame(2, 0x80, b"\x01").data
    r_g2 = run_mouse_frame(img, neg_g2, low_flash=True)
    out_g2 = bytes.fromhex(r_g2.output_frame_hex)
    caught_g2 = out_g2[8:11] == bytes([0, 1, 2])
    neg_controls.append(
        {
            "name": "neg_group2_0x80_uninit_R6_lowflash_read",
            "request_hex": neg_g2.hex(),
            "caught_as_unsafe": caught_g2,
            "leaked_lowflash_prefix_hex": out_g2[8:14].hex(),
        }
    )

    return {
        "firmware": img.summary(),
        "dispatcher": "0x18494",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_candidates": len(verified),
        "total_passed": sum(1 for x in verified if x["passed"]),
        "failures": failures,
        "verified_readonly_commands": verified,
        "negative_controls": neg_controls,
    }


# --- Receiver USB (0x08008348) ---

RX_USB_FORBIDDEN_SITES: dict[int, str] = {
    0x0800678C: "SYSRESETREQ_spin",
    0x08007624: "flash_erase_page",
    0x08007564: "flash_program_halfword",
    0x0800767C: "flash_page_RMW",
    0x0800779C: "flash_write_halfwords",
    0x08008290: "persist_dirty_records_service",
}


def _is_side_effect_free(res: EmuExecutionResult) -> bool:
    return (
        res.returned
        and not res.hit_forbidden_sites
        and not res.ram_diff_ranges
        and not res.mmio_diff_addrs
        and not res.nvic_diff_addrs
    )


def run_rx_usb_frame(img: HexImage, frame_64: bytes) -> EmuExecutionResult:
    ref = REFERENCE_FIRMWARES["receiver_usb"]
    uc = _new_cortex_m_cpu(img, ref.resolved_runtime_bins())
    # Caller sets status=0xA0 before calling 0x08008348 (see query_commands_cpu.json)
    buf = bytearray(frame_64)
    buf[0] = STATUS_PENDING
    uc.mem_write(0x2000293C, bytes(buf))
    allowed = [(0x2000293C, 0x2000297C)]
    return _run_function_and_diff(
        uc,
        0x08008348,
        ram_watch_lo=0x20000000,
        ram_watch_size=0x4000,
        allowed_ram_ranges=allowed,
        forbidden_sites=RX_USB_FORBIDDEN_SITES,
        frame_buf_addr=0x2000293C,
    )


def run_rx_usb_ep0_rx_frame(img: HexImage, frame_64: bytes) -> tuple[EmuExecutionResult, int]:
    """Run receiver_usb EP0 SET_REPORT completion 0x08006870 to observe 0xB0 sticky bridge trap."""
    ref = REFERENCE_FIRMWARES["receiver_usb"]
    uc = _new_cortex_m_cpu(img, ref.resolved_runtime_bins())
    usbd_dev = 0x20000478
    class_ptr = 0x2000007C
    pdata = 0x200029BC
    uc.mem_write(usbd_dev + 4, struct.pack("<I", class_ptr))
    uc.mem_write(class_ptr + 0x24, struct.pack("<I", pdata))
    uc.mem_write(usbd_dev + 0x16C, bytes([0x21, 0x09, 0x00, 0x03, 0x00, 0x00, 0x40, 0x00]))
    uc.mem_write(pdata + 0x6C, b"\x09")
    uc.mem_write(pdata + 0x24, frame_64)
    uc.mem_write(0x20000070, b"\x00")
    uc.mem_write(0x20000031, b"\x00")
    allowed = [
        (0x2000293C, 0x2000297C),
        (0x20000070, 0x20000071),
        (pdata + 0x6C, pdata + 0x6D),
    ]
    res = _run_function_and_diff(
        uc,
        0x08006870,
        ram_watch_lo=0x20000000,
        ram_watch_size=0x4000,
        allowed_ram_ranges=allowed,
        forbidden_sites=RX_USB_FORBIDDEN_SITES,
        frame_buf_addr=0x2000293C,
        init_regs={UC_ARM_REG_R0: usbd_dev},
    )
    sticky_b0_flag = uc.mem_read(0x20000031, 1)[0]
    return res, sticky_b0_flag


def prove_receiver_usb() -> dict[str, Any]:
    ref = REFERENCE_FIRMWARES["receiver_usb"]
    img = HexImage(ref.hex_path)
    verified: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    for spec in iter_readonly_candidates(TargetRole.RECEIVER_USB_LOCAL):
        req = build_frame_from_spec(spec).data
        res = run_rx_usb_frame(img, req)
        out = bytes.fromhex(res.output_frame_hex)
        side_effect_free = (
            res.returned
            and not res.hit_forbidden_sites
            and not res.ram_diff_ranges
            and not res.mmio_diff_addrs
            and not res.nvic_diff_addrs
        )
        # Inner handler 0x08008348 keeps 0xA0 (outer caller converts A0 -> A1)
        passed = side_effect_free and (out[0] == STATUS_PENDING)
        entry = {
            "name": spec.name,
            "target_role": spec.target_role.value,
            "family": spec.family.value,
            "route": spec.route,
            "group": spec.group,
            "cmd": spec.cmd,
            "request_hex": req.hex(),
            "output_hex": res.output_frame_hex,
            "inner_status": f"0x{out[0]:02X}",
            "reply_length_field": out[3],
            "instructions": res.instructions,
            "side_effect_free": side_effect_free,
            "passed": passed,
            "unexpected_ram_diffs": res.ram_diff_ranges,
            "mmio_diffs": res.mmio_diff_addrs,
            "wdt_kicked": res.wdt_kicked,
            "nvic_diffs": res.nvic_diff_addrs,
            "hit_forbidden": res.hit_forbidden_sites,
            "stopped_reason": res.stopped_reason,
        }
        verified.append(entry)
        if not passed:
            failures.append(entry)

    neg_controls: list[dict[str, Any]] = []
    # 1. subcmd 0x00 with 0xB0 bootloader magic
    neg_bl = build_family_a_frame(0, 0x00, b"\xB0", route=0).data
    r_bl = run_rx_usb_frame(img, neg_bl)
    caught_bl = (not r_bl.returned) and any("SYSRESETREQ" in s for s in r_bl.hit_forbidden_sites)
    neg_controls.append(
        {
            "name": "neg_rx_usb_0x00_B0_bootloader",
            "request_hex": neg_bl.hex(),
            "caught_as_unsafe": caught_bl,
            "hit_forbidden": r_bl.hit_forbidden_sites,
            "unexpected_ram_diffs": r_bl.ram_diff_ranges,
        }
    )
    # 2. unknown 0x85 returns 0xA3
    neg_85 = build_family_a_frame(0, 0x85, b"", route=0).data
    r_85 = run_rx_usb_frame(img, neg_85)
    out_85 = bytes.fromhex(r_85.output_frame_hex)
    neg_controls.append(
        {
            "name": "neg_rx_usb_0x85_invalid_A3",
            "request_hex": neg_85.hex(),
            "caught_as_unsafe": out_85[0] == STATUS_INVALID,
            "reply_status": f"0x{out_85[0]:02X}",
        }
    )
    # 3. 0x08006870 sticky 84B bootloader SPI bridge trap when frame[4] == 0xB0
    neg_f4_b0 = build_family_b_frame(0x81, b"\xB0", route=1).data
    r_f4_b0, sticky_b0_flag = run_rx_usb_ep0_rx_frame(img, neg_f4_b0)
    caught_f4_b0 = (
        r_f4_b0.returned
        and sticky_b0_flag == 1
        and any(d["start"] == "0x20000031" for d in r_f4_b0.ram_diff_ranges)
    )
    neg_controls.append(
        {
            "name": "neg_rx_usb_0x6870_frame4_B0_sticky_spi_bridge",
            "request_hex": neg_f4_b0.hex(),
            "caught_as_unsafe": caught_f4_b0,
            "sticky_byte_20000031": sticky_b0_flag,
            "unexpected_ram_diffs": r_f4_b0.ram_diff_ranges,
        }
    )

    return {
        "firmware": img.summary(),
        "dispatcher": "0x08008348",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_candidates": len(verified),
        "total_passed": sum(1 for x in verified if x["passed"]),
        "failures": failures,
        "verified_readonly_commands": verified,
        "negative_controls": neg_controls,
    }


# --- Receiver 2.4G (0xB21C / 0xAFD0) ---

RX_2G4_FORBIDDEN_SITES: dict[int, str] = {
    0x7A58: "SYSRESETREQ_request_and_spin",
    0x8FE4: "NVMC_erase_page",
    0x8FFA: "NVMC_write_words",
    0x9C80: "NVMC_erase_wait_READY",
    0x9CB0: "NVMC_program_words_wait_READY",
    0xAF40: "NV_save_dirty_records",
    0xBB44: "queue_or_dirty_mark",
    0xC3B8: "factory_RADIO_packet_configure",
}

RX_2G4_WATCH_SITES: dict[int, str] = {
    0xAFD0: "local_configuration_command_dispatch",
    0xBDB4: "mouse_rf_link_connected",
    0xC328: "rf_tx_config_chunker",
    0xD266: "spi_tx_config_chunker",
}

_RX_2G4_QUEUE_BASE = 0x20001584
_RX_2G4_QUEUE_STRIDE = 0x280


def _init_rx_2g4_queues(uc: Uc) -> None:
    """Initialize radio queue0/queue1/queue2 matching firmware 0x9448 -> 0xBDC8."""
    for q_idx in range(3):
        base = _RX_2G4_QUEUE_BASE + q_idx * _RX_2G4_QUEUE_STRIDE
        # full=0, empty=1, write=0, read=0, cap=25, item_size=25, pad=0, storage_ptr=base+12
        uc.mem_write(base, struct.pack("<BBBBBBBBI", 0, 1, 0, 0, 25, 25, 0, 0, base + 12))


def _read_rx_2g4_queue_chunks(uc: Uc, q_idx: int, chunk_size: int) -> tuple[int, bytes]:
    base = _RX_2G4_QUEUE_BASE + q_idx * _RX_2G4_QUEUE_STRIDE
    write_count = uc.mem_read(base + 2, 1)[0]
    chunks = [bytes(uc.mem_read(base + 12 + i * 25 + 1, chunk_size)) for i in range(write_count)]
    return write_count, b"".join(chunks)


def run_rx_2g4_frame(img: HexImage, frame_64: bytes) -> EmuExecutionResult:
    ref = REFERENCE_FIRMWARES["receiver_2g4"]
    uc = _new_cortex_m_cpu(img, ref.resolved_runtime_bins())
    # Seed sample paired mouse ID & RF state in RAM 0x2000130C
    uc.mem_write(0x2000130E, bytes.fromhex("AABBCCDD"))
    uc.mem_write(0x2000132E, bytes.fromhex("0122334455"))
    buf = bytearray(frame_64)
    buf[0] = STATUS_PENDING
    uc.mem_write(0x20001338, bytes(buf))
    allowed = [(0x20001338, 0x20001378)]
    return _run_function_and_diff(
        uc,
        0xAFD0,
        ram_watch_lo=0x20000000,
        ram_watch_size=0x4500,
        allowed_ram_ranges=allowed,
        forbidden_sites=RX_2G4_FORBIDDEN_SITES,
        frame_buf_addr=0x20001338,
    )


def run_rx_2g4_b21c_frame(
    img: HexImage,
    frame_64: bytes,
    *,
    mouse_connected: int = 1,
    allow_queue0: bool = False,
    allow_queue1: bool = False,
) -> tuple[EmuExecutionResult, int, bytes, int, bytes]:
    """Execute real top-level 2.4G dispatcher 0xB21C and inspect queue0/queue1 outputs."""
    ref = REFERENCE_FIRMWARES["receiver_2g4"]
    uc = _new_cortex_m_cpu(img, ref.resolved_runtime_bins())
    _init_rx_2g4_queues(uc)
    uc.mem_write(0x2000130E, bytes.fromhex("AABBCCDD"))
    uc.mem_write(0x2000132E, bytes.fromhex("0122334455"))
    uc.mem_write(0x200028DD, bytes([mouse_connected]))
    uc.mem_write(0x20000014, b"\x01")
    buf = bytearray(frame_64)
    buf[0] = STATUS_PENDING
    uc.mem_write(0x20001338, bytes(buf))

    allowed = [
        (0x20000014, 0x20000015),  # rx_config_pending cleared to 0
        (0x20001338, 0x20001378),  # shared 64B command/reply buffer
    ]
    if allow_queue0:
        allowed.append((_RX_2G4_QUEUE_BASE, _RX_2G4_QUEUE_BASE + _RX_2G4_QUEUE_STRIDE))
    if allow_queue1:
        allowed.append(
            (_RX_2G4_QUEUE_BASE + _RX_2G4_QUEUE_STRIDE, _RX_2G4_QUEUE_BASE + 2 * _RX_2G4_QUEUE_STRIDE)
        )

    res = _run_function_and_diff(
        uc,
        0xB21C,
        ram_watch_lo=0x20000000,
        ram_watch_size=0x4500,
        allowed_ram_ranges=allowed,
        forbidden_sites=RX_2G4_FORBIDDEN_SITES,
        frame_buf_addr=0x20001338,
        watch_sites=RX_2G4_WATCH_SITES,
    )
    q0_count, q0_bytes = _read_rx_2g4_queue_chunks(uc, 0, 10)
    q1_count, q1_bytes = _read_rx_2g4_queue_chunks(uc, 1, 6)
    return res, q0_count, q0_bytes, q1_count, q1_bytes


def _prove_rx_2g4_local_entry(img: HexImage, spec: CommandSpec) -> dict[str, Any]:
    if spec.family == ProtocolFamily.A:
        payload = b"\x02" if spec.cmd == 0x8B else b""
        req = build_frame_from_spec(spec, payload).data
        res = run_rx_2g4_frame(img, req)
        out = bytes.fromhex(res.output_frame_hex)
        side_effect_free = _is_side_effect_free(res)
        passed = side_effect_free and (out[0] == STATUS_PENDING)
        return {
            "name": spec.name,
            "target_role": spec.target_role.value,
            "family": spec.family.value,
            "route": spec.route,
            "group": spec.group,
            "cmd": spec.cmd,
            "dispatcher": "0xAFD0",
            "request_hex": req.hex(),
            "output_hex": res.output_frame_hex,
            "inner_status": f"0x{out[0]:02X}",
            "reply_length_field": out[3],
            "instructions": res.instructions,
            "side_effect_free": side_effect_free,
            "passed": passed,
            "unexpected_ram_diffs": res.ram_diff_ranges,
            "mmio_diffs": res.mmio_diff_addrs,
            "wdt_kicked": res.wdt_kicked,
            "nvic_diffs": res.nvic_diff_addrs,
            "hit_forbidden": res.hit_forbidden_sites,
            "stopped_reason": res.stopped_reason,
        }

    # Local Family B (0x81, 0x90, 0x93) via top-level 0xB21C
    req = build_frame_from_spec(spec).data
    res, q0_count, q0_bytes, q1_count, _q1_bytes = run_rx_2g4_b21c_frame(
        img, req, mouse_connected=1, allow_queue0=True, allow_queue1=False
    )
    out = bytes.fromhex(res.output_frame_hex)
    side_effect_free = _is_side_effect_free(res)
    routed_local_d266 = (
        any("0x0000D266" in s for s in res.hit_watch_sites)
        and not any("0x0000C328" in s for s in res.hit_watch_sites)
        and not any("0x0000AFD0" in s for s in res.hit_watch_sites)
        and q1_count == 0
        and q0_count >= 1
    )
    extra: dict[str, Any] = {}
    reply_ok = out[0] == STATUS_OK
    if spec.cmd == 0x81:
        reply_ok = reply_ok and out[1] == 6 and out[4:10] == EXPECTED_RECEIVER_2G4_VERSION_BYTES
    elif spec.cmd == 0x90:
        res_disc, d_q0_count, d_q0_bytes, d_q1_count, _ = run_rx_2g4_b21c_frame(
            img, req, mouse_connected=0, allow_queue0=True, allow_queue1=False
        )
        out_disc = bytes.fromhex(res_disc.output_frame_hex)
        disc_ok = (
            _is_side_effect_free(res_disc)
            and out_disc[0] == STATUS_OK
            and out_disc[1] == 1
            and out_disc[4] == 0
            and d_q1_count == 0
            and d_q0_count >= 1
            and d_q0_bytes[:6] == out_disc[:6]
        )
        reply_ok = reply_ok and out[1] == 1 and out[4] == 1 and disc_ok
        extra["link_states_verified"] = {
            "connected_1": {"status": f"0x{out[0]:02X}", "len": out[1], "link_byte": out[4]},
            "disconnected_0": {"status": f"0x{out_disc[0]:02X}", "len": out_disc[1], "link_byte": out_disc[4]},
        }
    elif spec.cmd == 0x93:
        expected_id = struct.pack("<I", SYNTHETIC_DEVICE_ID)
        reply_ok = reply_ok and out[1] == 4 and out[4:8] == expected_id
        extra["expected_device_id_le_hex"] = expected_id.hex()
    else:
        reply_ok = False

    spi_echo_ok = q0_bytes[: out[1] + 5] == out[: out[1] + 5]
    passed = side_effect_free and routed_local_d266 and reply_ok and spi_echo_ok
    return {
        "name": spec.name,
        "target_role": spec.target_role.value,
        "family": spec.family.value,
        "route": spec.route,
        "group": spec.group,
        "cmd": spec.cmd,
        "dispatcher": "0xB21C",
        "request_hex": req.hex(),
        "output_hex": res.output_frame_hex,
        "reply_status": f"0x{out[0]:02X}",
        "reply_length_field": out[1],
        "spi_chunks_enqueued": q0_count,
        "rf_chunks_enqueued": q1_count,
        "instructions": res.instructions,
        "side_effect_free": side_effect_free,
        "passed": passed,
        "unexpected_ram_diffs": res.ram_diff_ranges,
        "mmio_diffs": res.mmio_diff_addrs,
        "wdt_kicked": res.wdt_kicked,
        "nvic_diffs": res.nvic_diff_addrs,
        "hit_forbidden": res.hit_forbidden_sites,
        "hit_watch_sites": res.hit_watch_sites,
        "stopped_reason": res.stopped_reason,
        **extra,
    }


def _prove_rx_2g4_forwarding_path(
    img: HexImage,
    *,
    family: ProtocolFamily,
    route: int,
    sample_frames: list[tuple[str, bytes]],
) -> dict[str, Any]:
    case_details: list[dict[str, Any]] = []
    all_conn_c328 = True
    all_conn_skip_d266 = True
    all_conn_clean = True
    all_disc_a4 = True
    all_disc_skip_c328 = True
    all_disc_skip_d266 = True
    all_disc_clean = True

    for label, req in sample_frames:
        expected_len = ((req[1] + 5) & 0xFF) if family == ProtocolFamily.B else ((req[3] + 7) & 0xFF)
        # Connected path (byte_200028DD == 1) -> must call 0xC328 into queue1, skip 0xD266 & 0xAFD0
        r_conn, c_q0, _, c_q1, c_q1_bytes = run_rx_2g4_b21c_frame(
            img, req, mouse_connected=1, allow_queue0=False, allow_queue1=True
        )
        c_out = bytes.fromhex(r_conn.output_frame_hex)
        c_hit_c328 = any("0x0000C328" in s for s in r_conn.hit_watch_sites)
        c_skip_d266 = (
            not any("0x0000D266" in s for s in r_conn.hit_watch_sites)
            and not any("0x0000AFD0" in s for s in r_conn.hit_watch_sites)
            and c_q0 == 0
        )
        expected_rf_bytes = bytes([STATUS_PENDING, *req[1:expected_len]])
        c_payload_ok = c_q1 >= 1 and c_q1_bytes[:expected_len] == expected_rf_bytes
        c_clean = _is_side_effect_free(r_conn) and c_out[0] == STATUS_PENDING and c_payload_ok

        all_conn_c328 = all_conn_c328 and c_hit_c328
        all_conn_skip_d266 = all_conn_skip_d266 and c_skip_d266
        all_conn_clean = all_conn_clean and c_clean

        # Disconnected path (byte_200028DD == 0) -> must write F[0]=0xA4, skip 0xC328 & 0xD266
        r_disc, d_q0, _, d_q1, _ = run_rx_2g4_b21c_frame(
            img, req, mouse_connected=0, allow_queue0=False, allow_queue1=False
        )
        d_out = bytes.fromhex(r_disc.output_frame_hex)
        d_is_a4 = d_out[0] == STATUS_RF_DISCONNECTED
        d_skip_c328 = not any("0x0000C328" in s for s in r_disc.hit_watch_sites) and d_q1 == 0
        d_skip_d266 = (
            not any("0x0000D266" in s for s in r_disc.hit_watch_sites)
            and not any("0x0000AFD0" in s for s in r_disc.hit_watch_sites)
            and d_q0 == 0
        )
        d_clean = _is_side_effect_free(r_disc)

        all_disc_a4 = all_disc_a4 and d_is_a4
        all_disc_skip_c328 = all_disc_skip_c328 and d_skip_c328
        all_disc_skip_d266 = all_disc_skip_d266 and d_skip_d266
        all_disc_clean = all_disc_clean and d_clean

        case_details.append(
            {
                "label": label,
                "request_hex": req.hex(),
                "expected_rf_len": expected_len,
                "connected": {
                    "routed_to_c328": c_hit_c328,
                    "skipped_d266": c_skip_d266,
                    "rf_chunks_enqueued": c_q1,
                    "rf_payload_match": c_payload_ok,
                    "side_effect_free": c_clean,
                    "status": f"0x{c_out[0]:02X}",
                    "ram_diffs": r_conn.ram_diff_ranges,
                },
                "disconnected": {
                    "status": f"0x{d_out[0]:02X}",
                    "skipped_c328": d_skip_c328,
                    "skipped_d266": d_skip_d266,
                    "side_effect_free": d_clean,
                    "ram_diffs": r_disc.ram_diff_ranges,
                },
            }
        )

    passed = (
        all_conn_c328
        and all_conn_skip_d266
        and all_conn_clean
        and all_disc_a4
        and all_disc_skip_c328
        and all_disc_skip_d266
        and all_disc_clean
    )
    return {
        "target_role": TargetRole.RECEIVER_TO_MOUSE_RF.value,
        "family": family.value,
        "route": route,
        "passed": passed,
        "connected_routed_to_c328": all_conn_c328,
        "connected_skipped_d266": all_conn_skip_d266,
        "connected_side_effect_free": all_conn_clean,
        "disconnected_status": f"0x{STATUS_RF_DISCONNECTED:02X}" if all_disc_a4 else "UNEXPECTED",
        "disconnected_skipped_c328": all_disc_skip_c328,
        "disconnected_skipped_d266": all_disc_skip_d266,
        "disconnected_side_effect_free": all_disc_clean,
        "cases": case_details,
    }


def prove_receiver_2g4() -> dict[str, Any]:
    ref = REFERENCE_FIRMWARES["receiver_2g4"]
    img = HexImage(ref.hex_path)
    verified: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    for spec in iter_readonly_candidates(TargetRole.RECEIVER_2G4_LOCAL):
        entry = _prove_rx_2g4_local_entry(img, spec)
        verified.append(entry)
        if not entry["passed"]:
            failures.append(entry)

    forwarding_paths = [
        _prove_rx_2g4_forwarding_path(
            img,
            family=ProtocolFamily.B,
            route=1,
            sample_frames=[
                ("rf_mouse_b_fw_version_sensor", build_family_b_frame(0x81, route=1).data),
                ("rf_mouse_b_dpi_table", build_family_b_frame(0x83, route=1).data),
                ("rf_mouse_b_multichunk_12b", build_family_b_frame(0x81, b"\x00" * 12, route=1).data),
            ],
        ),
        _prove_rx_2g4_forwarding_path(
            img,
            family=ProtocolFamily.A,
            route=2,
            sample_frames=[
                ("rf_mouse_a_g0_fw_version", build_family_a_frame(0, 0x81, route=2).data),
                ("rf_mouse_a_g3_keyslot_read", build_family_a_frame(3, 0x80, bytes([1, 1, 0]), route=2).data),
                ("rf_mouse_a_g0_46b_record", build_family_a_frame(0, 0x82, b"", route=2, length_override=46).data),
            ],
        ),
    ]

    neg_controls: list[dict[str, Any]] = []
    # 1. subcmd 0x00 with 0xB0 bootloader magic
    neg_bl = build_family_a_frame(0, 0x00, b"\xB0", route=1).data
    r_bl = run_rx_2g4_frame(img, neg_bl)
    caught_bl = (not r_bl.returned) and any("SYSRESETREQ" in s for s in r_bl.hit_forbidden_sites)
    neg_controls.append(
        {
            "name": "neg_rx_2g4_0x00_B0_bootloader",
            "request_hex": neg_bl.hex(),
            "caught_as_unsafe": caught_bl,
            "hit_forbidden": r_bl.hit_forbidden_sites,
            "unexpected_ram_diffs": r_bl.ram_diff_ranges,
        }
    )
    # 2. subcmd 0x00 with 0xA0 factory RF mode
    neg_fac = build_family_a_frame(0, 0x00, bytes([0xA0, 0, 1, 1, 0xF8, 10, 12, 1, 50, 0xA5]), route=1).data
    r_fac = run_rx_2g4_frame(img, neg_fac)
    caught_fac = bool(r_fac.hit_forbidden_sites) or bool(r_fac.ram_diff_ranges)
    neg_controls.append(
        {
            "name": "neg_rx_2g4_0x00_A0_factory",
            "request_hex": neg_fac.hex(),
            "caught_as_unsafe": caught_fac,
            "hit_forbidden": r_fac.hit_forbidden_sites,
            "unexpected_ram_diffs": r_fac.ram_diff_ranges,
        }
    )
    # 3. invalid 0x8D returns 0xA3
    neg_8d = build_family_a_frame(0, 0x8D, b"", route=1).data
    r_8d = run_rx_2g4_frame(img, neg_8d)
    out_8d = bytes.fromhex(r_8d.output_frame_hex)
    neg_controls.append(
        {
            "name": "neg_rx_2g4_0x8D_invalid_A3",
            "request_hex": neg_8d.hex(),
            "caught_as_unsafe": out_8d[0] == STATUS_INVALID,
            "reply_status": f"0x{out_8d[0]:02X}",
        }
    )
    # 4. 0xAFD0 0x0A writes 41B NV pair ID (0x2000130E) and marks dirty (0xBB44)
    neg_0a = build_family_a_frame(0, 0x0A, bytes.fromhex("11223344"), route=1).data
    r_0a, _, _, _, _ = run_rx_2g4_b21c_frame(img, neg_0a, allow_queue0=False, allow_queue1=False)
    caught_0a = bool(r_0a.hit_forbidden_sites) and bool(r_0a.ram_diff_ranges)
    neg_controls.append(
        {
            "name": "neg_rx_2g4_0x0A_nv_pair_id_write",
            "request_hex": neg_0a.hex(),
            "caught_as_unsafe": caught_0a,
            "hit_forbidden": r_0a.hit_forbidden_sites,
            "unexpected_ram_diffs": r_0a.ram_diff_ranges,
        }
    )
    # 5. 0xAFD0 0x0B writes BOTH 2.4G NV (0x2000132E..) and USB Flash PID/VID
    neg_0b = build_family_a_frame(0, 0x0B, bytes([2, 1, 0x33, 0xE4, 0x35, 0x17]), route=1).data
    r_0b, _, _, _, _ = run_rx_2g4_b21c_frame(img, neg_0b, allow_queue0=False, allow_queue1=False)
    caught_0b = bool(r_0b.hit_forbidden_sites) and bool(r_0b.ram_diff_ranges)
    neg_controls.append(
        {
            "name": "neg_rx_2g4_0x0B_pid_vid_write",
            "request_hex": neg_0b.hex(),
            "caught_as_unsafe": caught_0b,
            "hit_forbidden": r_0b.hit_forbidden_sites,
            "unexpected_ram_diffs": r_0b.ram_diff_ranges,
        }
    )

    return {
        "firmware": img.summary(),
        "dispatcher": "0xB21C / 0xAFD0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_candidates": len(verified),
        "total_passed": sum(1 for x in verified if x["passed"]),
        "failures": failures,
        "verified_readonly_commands": verified,
        "verified_forwarding_paths": forwarding_paths,
        "negative_controls": neg_controls,
    }


def generate_all_proofs(output_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    out_dir = output_dir or PROOFS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    results = {
        "mouse": prove_mouse(),
        "receiver_usb": prove_receiver_usb(),
        "receiver_2g4": prove_receiver_2g4(),
    }
    filenames = {
        "mouse": "mouse_readonly_proof.json",
        "receiver_usb": "receiver_usb_readonly_proof.json",
        "receiver_2g4": "receiver_2g4_readonly_proof.json",
    }
    for key, doc in results.items():
        (out_dir / filenames[key]).write_text(
            json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    return results


def main() -> int:
    results = generate_all_proofs()
    all_ok = True
    for name, doc in results.items():
        total = doc["total_candidates"]
        passed = doc["total_passed"]
        neg_ok = all(nc["caught_as_unsafe"] for nc in doc["negative_controls"])
        fwd_paths = doc.get("verified_forwarding_paths", [])
        fwd_ok = all(fp.get("passed") is True for fp in fwd_paths)
        fwd_str = (
            f" | forwarding: {sum(1 for fp in fwd_paths if fp.get('passed'))}/{len(fwd_paths)} passed"
            if fwd_paths
            else ""
        )
        print(
            f"[{name}] readonly: {passed}/{total} passed{fwd_str} | "
            f"neg_controls: {sum(1 for nc in doc['negative_controls'] if nc['caught_as_unsafe'])}/{len(doc['negative_controls'])} caught"
        )
        if doc["failures"] or not neg_ok or not fwd_ok:
            all_ok = False
            for f in doc["failures"]:
                print(
                    f"  FAIL {f['name']}: status={f['reply_status'] if 'reply_status' in f else f.get('inner_status')}, "
                    f"forbidden={f['hit_forbidden']}, ram={f['unexpected_ram_diffs']}, "
                    f"mmio={f['mmio_diffs']}, reason={f['stopped_reason']}"
                )
            for fp in fwd_paths:
                if not fp.get("passed"):
                    print(f"  FWD_FAIL {fp}")
            for nc in doc["negative_controls"]:
                if not nc["caught_as_unsafe"]:
                    print(f"  NEG_FAIL {nc}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
