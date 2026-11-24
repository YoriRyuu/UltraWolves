"""Composable offline Phase 2, Phase 3, Phase 3+ & Phase 4 firmware patch builder & CLI (NOT_FOR_FLASH).

Usage:
    python -m fenrir.patcher.build
    python -m fenrir.patcher.build --profile phase3
    python -m fenrir.patcher.build --profile phase3plus
    python -m fenrir.patcher.build --profile phase4-receiver
    python -m fenrir.patcher.build --output-dir path/to/out --json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from fenrir.constants import FENRIR_DEV_ROOT
from fenrir.patcher import (
    debounce_mod,
    group5,
    persistence,
    phase3_diag,
    phase3_motion,
    phase3_plock,
    phase3plus_abs,
    phase3plus_w2,
    phase4_abs,
    phase4_sync,
    phase4_usb_bounds,
    recovery,
    target_mouse as T,
    target_receiver as R,
)
from fenrir.patcher.hex_io import NOT_FOR_FLASH_TAG, HexImage, HexPatchBuilder
from fenrir.patcher.thumb import PatchContext

DEFAULT_OUTPUT_DIR = FENRIR_DEV_ROOT / "build"
DEFAULT_OUTPUT_FILENAME = f"Fenrir+035-8K_Mouse_App_FW_v1.00.39.00_Phase2_{NOT_FOR_FLASH_TAG}.hex"
DEFAULT_PHASE3_OUTPUT_FILENAME = f"Fenrir+035-8K_Mouse_App_FW_v1.00.39.00_Phase3_{NOT_FOR_FLASH_TAG}.hex"
DEFAULT_PHASE3PLUS_OUTPUT_FILENAME = f"Fenrir+035-8K_Mouse_App_FW_v1.00.39.00_Phase3Plus_{NOT_FOR_FLASH_TAG}.hex"
DEFAULT_PHASE4_USB_OUTPUT_FILENAME = f"8K_Dongle_USB_App_FW_v1.00.39.00_Phase4_{NOT_FOR_FLASH_TAG}.hex"
DEFAULT_PHASE4_2G4_OUTPUT_FILENAME = f"8K_Dongle_2.4G_App_FW_v1.00.39.00_Phase4_{NOT_FOR_FLASH_TAG}.hex"


def build_phase2_firmware(
    *,
    source_hex: Path | None = None,
    output_dir: Path | None = None,
    output_hex: Path | None = None,
    enable_recovery: bool = True,
    enable_debounce: bool = True,
    enable_persistence: bool = True,
    enable_group5: bool = True,
    install_persist_loop_hook: bool = True,
) -> dict[str, Any]:
    """Build an offline-only Phase 2 patched HEX, JSON manifest, and Capstone report."""
    if enable_group5 and not enable_persistence:
        raise ValueError("group5 depends on persistence symbols; cannot use --no-persistence without --no-group5")

    src_path = Path(source_hex) if source_hex is not None else T.STOCK_HEX_PATH
    stock_image = HexImage(src_path)
    T.verify_stock_image(stock_image)

    builder = HexPatchBuilder(
        stock_image,
        expected_sha256=T.STOCK_SHA256,
        expected_base=T.BASE,
        expected_end=T.END,
        protected_ranges=T.PROTECTED_RANGES,
    )
    builder.add_code_cave(T.CAVE_START, T.CAVE_END, "app_tail_cave")
    ctx = PatchContext(builder)

    modules: dict[str, Any] = {}
    if enable_recovery:
        modules["recovery"] = recovery.install(ctx)
    else:
        modules["recovery"] = {"enabled": False}

    if enable_debounce:
        modules["debounce"] = debounce_mod.install(ctx)
    else:
        modules["debounce"] = {"enabled": False}

    if enable_persistence:
        modules["persistence"] = persistence.install(
            ctx, install_persist_loop_hook=install_persist_loop_hook
        )
    else:
        modules["persistence"] = {"enabled": False}

    if enable_group5:
        modules["group5"] = group5.install(ctx)
    else:
        modules["group5"] = {"enabled": False}

    capstone_report = ctx.capstone_report()
    if not capstone_report.get("all_verified"):
        raise RuntimeError("Capstone round-trip verification failed; refusing to emit HEX")

    if output_hex is not None:
        dest_hex = Path(output_hex)
    else:
        dest_dir = Path(output_dir) if output_dir is not None else DEFAULT_OUTPUT_DIR
        dest_hex = dest_dir / DEFAULT_OUTPUT_FILENAME

    cave_used = T.CAVE_BYTES - builder.remaining_cave_bytes()
    extra_manifest: dict[str, Any] = {
        "phase": "phase2",
        "target_name": T.TARGET_NAME,
        "sensor_branch_target": "ID53 (PAW3950)",
        "cave_budget": {
            "start": f"0x{T.CAVE_START:08X}",
            "end_exclusive": f"0x{T.CAVE_END:08X}",
            "capacity_bytes": T.CAVE_BYTES,
            "used_bytes": cave_used,
            "remaining_bytes": builder.remaining_cave_bytes(),
        },
        "guarantees": {
            "boot_spine_preserved": "Reset_Handler -> USB init -> 0x13008 -> 0x18494 intact",
            "default_overrides_off": True,
            "stock_nv_untouched": ["0x50000", "0x8C000", "0x90000..0xDFFFF", "0xEB000", "0xEC000"],
            "phase2_nv_page": f"0x{T.PHASE2_CONFIG_FLASH_PAGE:08X}",
            "capstone_all_verified": capstone_report["all_verified"],
        },
        "capstone_summary": {
            "all_verified": capstone_report["all_verified"],
            "block_count": capstone_report["block_count"],
            "branch_patch_count": capstone_report["branch_patch_count"],
            "total_verified_instructions": capstone_report["total_verified_instructions"],
        },
        "modules": modules,
    }

    return builder.write_artifacts(
        dest_hex,
        capstone_report=capstone_report,
        extra_manifest=extra_manifest,
    )


def build_phase3_firmware(
    *,
    source_hex: Path | None = None,
    output_dir: Path | None = None,
    output_hex: Path | None = None,
    enable_recovery: bool = True,
    enable_debounce: bool = True,
    enable_persistence: bool = True,
    enable_group5: bool = True,
    install_persist_loop_hook: bool = True,
    enable_motion: bool = True,
    enable_plock: bool = True,
) -> dict[str, Any]:
    """Build an offline-only Phase 3 patched HEX, JSON manifest, and Capstone report."""
    if not enable_persistence:
        raise ValueError("Phase 3 requires persistence (for p3_ram_init / v2 config migration at 0xEA000)")

    src_path = Path(source_hex) if source_hex is not None else T.STOCK_HEX_PATH
    stock_image = HexImage(src_path)
    T.verify_phase3_landmarks(stock_image)

    builder = HexPatchBuilder(
        stock_image,
        expected_sha256=T.STOCK_SHA256,
        expected_base=T.BASE,
        expected_end=T.END,
        protected_ranges=T.PHASE3_PROTECTED_RANGES,
    )
    builder.add_code_cave(T.CAVE_START, T.CAVE_END, "app_tail_cave")
    builder.add_code_cave(T.PHASE3_CAVE_START, T.PHASE3_CAVE_END, "phase3_ext_cave")
    ctx = PatchContext(builder)

    modules: dict[str, Any] = {}
    if enable_recovery:
        modules["recovery"] = recovery.install(ctx)
    else:
        modules["recovery"] = {"enabled": False}

    if enable_debounce:
        modules["debounce"] = debounce_mod.install(ctx)
    else:
        modules["debounce"] = {"enabled": False}

    modules["phase3_diag"] = phase3_diag.install(ctx)
    modules["persistence"] = persistence.install(
        ctx, install_persist_loop_hook=install_persist_loop_hook, phase3=True
    )

    if enable_motion:
        modules["phase3_motion"] = phase3_motion.install(ctx)
    else:
        modules["phase3_motion"] = {"enabled": False}

    if enable_plock:
        modules["phase3_plock"] = phase3_plock.install(ctx)
    else:
        modules["phase3_plock"] = {"enabled": False}

    if enable_group5:
        modules["group5"] = group5.install(
            ctx, phase3_dispatch_addr=builder.symbols["p3_group5_dispatch"]
        )
    else:
        modules["group5"] = {"enabled": False}

    capstone_report = ctx.capstone_report()
    if not capstone_report.get("all_verified"):
        raise RuntimeError("Capstone round-trip verification failed; refusing to emit Phase 3 HEX")

    if output_hex is not None:
        dest_hex = Path(output_hex)
    else:
        dest_dir = Path(output_dir) if output_dir is not None else DEFAULT_OUTPUT_DIR
        dest_hex = dest_dir / DEFAULT_PHASE3_OUTPUT_FILENAME

    total_cap = T.CAVE_BYTES + T.PHASE3_CAVE_SIZE
    cave_used = total_cap - builder.remaining_cave_bytes()
    extra_manifest: dict[str, Any] = {
        "phase": "phase3",
        "profile": "phase3",
        "extended_flash_range_unverified_by_bootloader": True,
        "target_name": T.TARGET_NAME,
        "sensor_branch_target": "ID53 (PAW3950)",
        "cave_budget": {
            "start": f"0x{T.CAVE_START:08X}",
            "end_exclusive": f"0x{T.PHASE3_CAVE_END:08X}",
            "capacity_bytes": total_cap,
            "used_bytes": cave_used,
            "remaining_bytes": builder.remaining_cave_bytes(),
            "spans": [
                {"label": "app_tail_cave", "start": f"0x{T.CAVE_START:08X}", "end_exclusive": f"0x{T.CAVE_END:08X}", "bytes": T.CAVE_BYTES},
                {"label": "phase3_ext_cave", "start": f"0x{T.PHASE3_CAVE_START:08X}", "end_exclusive": f"0x{T.PHASE3_CAVE_END:08X}", "bytes": T.PHASE3_CAVE_SIZE},
            ],
        },
        "guarantees": {
            "boot_spine_preserved": "Reset_Handler -> USB init -> 0x13008 -> 0x18494 intact",
            "default_overrides_off": True,
            "default_phase3_toggles_off": ["direct_motion", "plock_enable"],
            "default_phase3_fixes_on": ["atomic_accum", "queue_guard"],
            "stock_nv_untouched": ["0x50000", "0x8C000", "0x90000..0xDFFFF", "0xEB000", "0xEC000"],
            "phase2_nv_page": f"0x{T.PHASE2_CONFIG_FLASH_PAGE:08X} (v1->v2 backward-compatible)",
            "phase3_ram_range": f"0x{T.PHASE3_RAM_BASE:08X}..0x{T.PHASE3_RAM_BASE + T.PHASE3_RAM_BYTES - 1:08X}",
            "capstone_all_verified": capstone_report["all_verified"],
        },
        "capstone_summary": {
            "all_verified": capstone_report["all_verified"],
            "block_count": capstone_report["block_count"],
            "branch_patch_count": capstone_report["branch_patch_count"],
            "total_verified_instructions": capstone_report["total_verified_instructions"],
        },
        "modules": modules,
    }

    return builder.write_artifacts(
        dest_hex,
        capstone_report=capstone_report,
        extra_manifest=extra_manifest,
    )


def build_phase4_receiver_firmware(
    *,
    source_usb_hex: Path | None = None,
    source_2g4_hex: Path | None = None,
    output_dir: Path | None = None,
    output_usb_hex: Path | None = None,
    output_2g4_hex: Path | None = None,
    enable_usb_bounds: bool = True,
    enable_abs: bool = True,
    enable_sync: bool = True,
) -> dict[str, Any]:
    """Build offline-only paired Phase 4 dual-MCU receiver HEX + manifest + Capstone artifacts."""
    usb_src = Path(source_usb_hex) if source_usb_hex is not None else R.RX_USB_STOCK_HEX_PATH
    rad_src = Path(source_2g4_hex) if source_2g4_hex is not None else R.RX_2G4_STOCK_HEX_PATH

    usb_stock = HexImage(usb_src)
    rad_stock = HexImage(rad_src)
    R.verify_rx_usb_image(usb_stock)
    R.verify_rx_2g4_image(rad_stock)

    dest_dir = Path(output_dir) if output_dir is not None else DEFAULT_OUTPUT_DIR
    dest_usb_hex = Path(output_usb_hex) if output_usb_hex is not None else (dest_dir / DEFAULT_PHASE4_USB_OUTPUT_FILENAME)
    dest_rad_hex = Path(output_2g4_hex) if output_2g4_hex is not None else (dest_dir / DEFAULT_PHASE4_2G4_OUTPUT_FILENAME)

    usb_builder = HexPatchBuilder(
        usb_stock,
        expected_sha256=R.RX_USB_SHA256,
        expected_base=R.RX_USB_BASE,
        expected_end=R.RX_USB_END,
        protected_ranges=R.RX_USB_PROTECTED_RANGES,
    )
    usb_builder.add_code_cave(R.RX_USB_CAVE_START, R.RX_USB_CAVE_END, "at32_tail_cave")
    usb_ctx = PatchContext(usb_builder)

    usb_modules: dict[str, Any] = {}
    usb_modules["phase4_usb_bounds"] = (
        phase4_usb_bounds.install(usb_ctx) if enable_usb_bounds else {"enabled": False}
    )
    usb_modules["phase4_abs"] = phase4_abs.install_usb(usb_ctx) if enable_abs else {"enabled": False}
    usb_modules["phase4_sync"] = phase4_sync.install_usb(usb_ctx) if enable_sync else {"enabled": False}

    usb_cap = usb_ctx.capstone_report()
    if not usb_cap.get("all_verified"):
        raise RuntimeError("AT32F405 USB Capstone verification failed; refusing to emit HEX")

    rad_builder = HexPatchBuilder(
        rad_stock,
        expected_sha256=R.RX_2G4_SHA256,
        expected_base=R.RX_2G4_BASE,
        expected_end=R.RX_2G4_END,
        protected_ranges=R.RX_2G4_PROTECTED_RANGES,
    )
    rad_builder.add_code_cave(R.RX_2G4_CAVE_START, R.RX_2G4_CAVE_END, "nrf52820_tail_cave")
    rad_ctx = PatchContext(rad_builder)

    rad_modules: dict[str, Any] = {}
    rad_modules["phase4_abs"] = phase4_abs.install_2g4(rad_ctx) if enable_abs else {"enabled": False}
    rad_modules["phase4_sync"] = phase4_sync.install_2g4(rad_ctx) if enable_sync else {"enabled": False}

    rad_cap = rad_ctx.capstone_report()
    if not rad_cap.get("all_verified"):
        raise RuntimeError("nRF52820 2.4G Capstone verification failed; refusing to emit HEX")

    usb_used = R.RX_USB_CAVE_BYTES - usb_builder.remaining_cave_bytes()
    rad_used = R.RX_2G4_CAVE_BYTES - rad_builder.remaining_cave_bytes()

    usb_extra: dict[str, Any] = {
        "phase": "phase4",
        "profile": "phase4-receiver",
        "mcu": "AT32F405 (USB MCU)",
        "target_name": R.RX_USB_TARGET_NAME,
        "dual_mcu_dependency_high_risk": True,
        "not_for_flash": True,
        "paired_target": {
            "mcu": "nRF52820 (2.4G MCU)",
            "target_name": R.RX_2G4_TARGET_NAME,
            "stock_sha256": R.RX_2G4_SHA256,
            "output_hex_path": str(dest_rad_hex),
        },
        "cave_budget": {
            "start": f"0x{R.RX_USB_CAVE_START:08X}",
            "end_exclusive": f"0x{R.RX_USB_CAVE_END:08X}",
            "capacity_bytes": R.RX_USB_CAVE_BYTES,
            "used_bytes": usb_used,
            "remaining_bytes": usb_builder.remaining_cave_bytes(),
        },
        "guarantees": {
            "sticky_bridge_b0_preserved": "0x080068D6 (frame[4]==0xB0 -> 0x20000031), 0x08007FB8 & 0x08008A38 intact",
            "local_cmd_0x8348_and_reset_magic_intact": "0x200197FC = 0xA55AA55A -> 0x0800678C untouched",
            "bootloader_missing_offline_only": True,
            "ram_scratch_range": f"0x{R.RX_USB_RAM_BASE:08X}..0x{R.RX_USB_RAM_BASE + R.RX_USB_RAM_BYTES - 1:08X}",
            "capstone_all_verified": usb_cap["all_verified"],
        },
        "capstone_summary": {
            "all_verified": usb_cap["all_verified"],
            "block_count": usb_cap["block_count"],
            "branch_patch_count": usb_cap["branch_patch_count"],
            "total_verified_instructions": usb_cap["total_verified_instructions"],
        },
        "modules": usb_modules,
    }

    rad_extra: dict[str, Any] = {
        "phase": "phase4",
        "profile": "phase4-receiver",
        "mcu": "nRF52820 (2.4G MCU)",
        "target_name": R.RX_2G4_TARGET_NAME,
        "dual_mcu_dependency_high_risk": True,
        "not_for_flash": True,
        "paired_target": {
            "mcu": "AT32F405 (USB MCU)",
            "target_name": R.RX_USB_TARGET_NAME,
            "stock_sha256": R.RX_USB_SHA256,
            "output_hex_path": str(dest_usb_hex),
        },
        "cave_budget": {
            "start": f"0x{R.RX_2G4_CAVE_START:08X}",
            "end_exclusive": f"0x{R.RX_2G4_CAVE_END:08X}",
            "capacity_bytes": R.RX_2G4_CAVE_BYTES,
            "used_bytes": rad_used,
            "remaining_bytes": rad_builder.remaining_cave_bytes(),
        },
        "guarantees": {
            "spi_bootloader_magic_intact": "0x20006FFC = 0xA55AA55A -> 0x00007A58 untouched",
            "spis_10b_wire_compatible": "buf[0..7] stock checksum kept; Phase 4 trailer in buf[8..9]",
            "bootloader_missing_offline_only": True,
            "ram_scratch_range": f"0x{R.RX_2G4_RAM_BASE:08X}..0x{R.RX_2G4_RAM_BASE + R.RX_2G4_RAM_BYTES - 1:08X}",
            "capstone_all_verified": rad_cap["all_verified"],
        },
        "capstone_summary": {
            "all_verified": rad_cap["all_verified"],
            "block_count": rad_cap["block_count"],
            "branch_patch_count": rad_cap["branch_patch_count"],
            "total_verified_instructions": rad_cap["total_verified_instructions"],
        },
        "modules": rad_modules,
    }

    usb_res = usb_builder.write_artifacts(
        dest_usb_hex,
        capstone_report=usb_cap,
        extra_manifest=usb_extra,
    )
    rad_res = rad_builder.write_artifacts(
        dest_rad_hex,
        capstone_report=rad_cap,
        extra_manifest=rad_extra,
    )
    return {
        "profile": "phase4-receiver",
        "not_for_flash": True,
        "dual_mcu_dependency_high_risk": True,
        "usb": usb_res,
        "2g4": rad_res,
    }


def build_phase3plus_firmware(
    *,
    source_hex: Path | None = None,
    output_dir: Path | None = None,
    output_hex: Path | None = None,
    enable_recovery: bool = True,
    enable_debounce: bool = True,
    enable_persistence: bool = True,
    enable_group5: bool = True,
    install_persist_loop_hook: bool = True,
    enable_motion: bool = True,
    enable_plock: bool = True,
    enable_mouse_abs: bool = True,
) -> dict[str, Any]:
    """Build offline-only Phase 3+ (S2b P1) patched mouse HEX, manifest, and Capstone report."""
    if not enable_persistence:
        raise ValueError("Phase 3+ requires persistence (for p3_ram_init / v3 config migration at 0xEA000)")

    src_path = Path(source_hex) if source_hex is not None else T.STOCK_HEX_PATH
    stock_image = HexImage(src_path)
    T.verify_phase3plus_landmarks(stock_image)

    builder = HexPatchBuilder(
        stock_image,
        expected_sha256=T.STOCK_SHA256,
        expected_base=T.BASE,
        expected_end=T.END,
        protected_ranges=T.PHASE3_PROTECTED_RANGES,
    )
    builder.add_code_cave(T.CAVE_START, T.CAVE_END, "app_tail_cave")
    builder.add_code_cave(T.PHASE3_CAVE_START, T.PHASE3_CAVE_END, "phase3_ext_cave")
    ctx = PatchContext(builder)

    modules: dict[str, Any] = {}
    modules["recovery"] = recovery.install(ctx) if enable_recovery else {"enabled": False}
    modules["debounce"] = debounce_mod.install(ctx) if enable_debounce else {"enabled": False}
    modules["phase3_diag"] = phase3_diag.install(ctx, phase3plus=True)
    modules["persistence"] = persistence.install(
        ctx, install_persist_loop_hook=install_persist_loop_hook, phase3=True, phase3plus=True
    )
    modules["phase3_motion"] = phase3_motion.install(ctx) if enable_motion else {"enabled": False}
    modules["phase3_plock"] = phase3_plock.install(ctx, phase3plus=True) if enable_plock else {"enabled": False}
    modules["phase3plus_abs"] = phase3plus_abs.install(ctx) if enable_mouse_abs else {"enabled": False}
    modules["phase3plus_w2"] = phase3plus_w2.install(ctx)
    if enable_group5:
        modules["group5"] = group5.install(
            ctx, phase3_dispatch_addr=builder.symbols["p3_group5_dispatch"], phase3plus=True
        )
    else:
        modules["group5"] = {"enabled": False}

    capstone_report = ctx.capstone_report()
    if not capstone_report.get("all_verified"):
        raise RuntimeError("Capstone round-trip verification failed; refusing to emit Phase 3+ HEX")

    if output_hex is not None:
        dest_hex = Path(output_hex)
    else:
        dest_dir = Path(output_dir) if output_dir is not None else DEFAULT_OUTPUT_DIR
        dest_hex = dest_dir / DEFAULT_PHASE3PLUS_OUTPUT_FILENAME

    total_cap = T.CAVE_BYTES + T.PHASE3_CAVE_SIZE
    cave_used = total_cap - builder.remaining_cave_bytes()
    extra_manifest: dict[str, Any] = {
        "phase": "phase3plus",
        "profile": "phase3plus",
        "not_for_flash": True,
        "extended_flash_range_unverified_by_bootloader": True,
        "target_name": T.TARGET_NAME,
        "sensor_branch_target": "ID53 (PAW3950)",
        "fps_preset_count": persistence.FPS_PRESET_COUNT_P3PLUS,
        "cave_budget": {
            "start": f"0x{T.CAVE_START:08X}",
            "end_exclusive": f"0x{T.PHASE3_CAVE_END:08X}",
            "capacity_bytes": total_cap,
            "used_bytes": cave_used,
            "remaining_bytes": builder.remaining_cave_bytes(),
            "spans": [
                {"label": "app_tail_cave", "start": f"0x{T.CAVE_START:08X}", "end_exclusive": f"0x{T.CAVE_END:08X}", "bytes": T.CAVE_BYTES},
                {"label": "phase3_ext_cave", "start": f"0x{T.PHASE3_CAVE_START:08X}", "end_exclusive": f"0x{T.PHASE3_CAVE_END:08X}", "bytes": T.PHASE3_CAVE_SIZE},
            ],
        },
        "guarantees": {
            "boot_spine_preserved": "Reset_Handler -> USB init -> 0x13008 -> 0x18494 intact",
            "default_overrides_off": True,
            "default_phase3plus_toggles_off": ["direct_motion", "plock_enable", "fix_a", "mouse_abs"],
            "default_phase3plus_fixes_on": ["atomic_accum", "queue_guard"],
            "stock_nv_untouched": ["0x50000", "0x8C000", "0x90000..0xDFFFF", "0xEB000", "0xEC000"],
            "phase2_nv_page": f"0x{T.PHASE2_CONFIG_FLASH_PAGE:08X} (v1->v2->v3 backward-compatible)",
            "phase3_ram_range": f"0x{T.PHASE3_RAM_BASE:08X}..0x{T.PHASE3_RAM_BASE + T.PHASE3_RAM_BYTES - 1:08X}",
            "capstone_all_verified": capstone_report["all_verified"],
        },
        "capstone_summary": {
            "all_verified": capstone_report["all_verified"],
            "block_count": capstone_report["block_count"],
            "branch_patch_count": capstone_report["branch_patch_count"],
            "total_verified_instructions": capstone_report["total_verified_instructions"],
        },
        "modules": modules,
    }

    return builder.write_artifacts(
        dest_hex,
        capstone_report=capstone_report,
        extra_manifest=extra_manifest,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m fenrir.patcher.build",
        description="Build offline Fenrir mouse (phase2/phase3/phase3plus) or dual-MCU receiver (phase4-receiver) HEX artifacts (NOT_FOR_FLASH).",
    )
    parser.add_argument(
        "--profile",
        choices=("phase2", "phase3", "phase3plus", "phase4-receiver"),
        default="phase2",
        help="Target firmware patch profile (default: phase2).",
    )
    parser.add_argument("--source", type=Path, default=None, help="Path to verified stock mouse APP HEX image.")
    parser.add_argument("--source-usb", type=Path, default=None, help="(phase4-receiver) Path to AT32F405 USB receiver HEX.")
    parser.add_argument("--source-2g4", type=Path, default=None, help="(phase4-receiver) Path to nRF52820 2.4G receiver HEX.")
    parser.add_argument("--output-dir", type=Path, default=None, help="Directory for output artifacts.")
    parser.add_argument(
        "--output-hex",
        type=Path,
        default=None,
        help="Explicit output HEX path for single-target profiles (MUST contain NOT_FOR_FLASH).",
    )
    parser.add_argument("--no-recovery", action="store_true", help="Disable H1 fault-to-bootloader patch.")
    parser.add_argument("--no-debounce", action="store_true", help="Disable H3 immediate debounce reload patch.")
    parser.add_argument("--no-persistence", action="store_true", help="Disable 0xEA000 CRC16 persistence (H4/H8).")
    parser.add_argument("--no-group5", action="store_true", help="Disable group 5 dispatcher and sensor workers.")
    parser.add_argument("--no-motion", action="store_true", help="(Phase 3/3+) Disable atomic accumulator / EP81 guard hooks.")
    parser.add_argument("--no-plock", action="store_true", help="(Phase 3/3+) Disable TIMER1 plock / flash sync hooks.")
    parser.add_argument("--no-mouse-abs", action="store_true", help="(Phase 3+) Disable wireless active u16 ABS hook.")
    parser.add_argument("--no-usb-bounds", action="store_true", help="(Phase 4) Disable AT32F405 EP0 SETUP bounds fixes.")
    parser.add_argument("--no-abs", action="store_true", help="(Phase 4) Disable dual-MCU u16 ABS/epoch/dedup/coalescing.")
    parser.add_argument("--no-sync", action="store_true", help="(Phase 4) Disable dual-MCU TIM6/SOF/SPIS0 sync hooks.")
    parser.add_argument(
        "--skip-persist-loop-hook",
        action="store_true",
        help="Do not install H8 main-loop persist hook (0x05 synchronous save/reset still works).",
    )
    parser.add_argument("--json", action="store_true", help="Print full JSON build result.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.profile == "phase4-receiver":
        res4 = build_phase4_receiver_firmware(
            source_usb_hex=args.source_usb,
            source_2g4_hex=args.source_2g4,
            output_dir=args.output_dir,
            enable_usb_bounds=not args.no_usb_bounds,
            enable_abs=not args.no_abs,
            enable_sync=not args.no_sync,
        )
        if args.json:
            print(json.dumps(res4, indent=2))
        else:
            for key in ("usb", "2g4"):
                sub = res4[key]
                manifest = sub["manifest"]
                cave = manifest["cave_budget"]
                cap = manifest["capstone_summary"]
                print(
                    f"[{key.upper()}] Tag : {manifest['artifact_tag']} "
                    f"(not_for_flash={manifest['not_for_flash']}, "
                    f"dual_mcu_dependency_high_risk={manifest['dual_mcu_dependency_high_risk']})"
                )
                print(f"[{key.upper()}] HEX : {sub['hex_path']} (SHA-256: {manifest['output']['hex_sha256']})")
                print(f"[{key.upper()}] Rpt : {sub['capstone_path']} (all_verified={cap['all_verified']}, insns={cap['total_verified_instructions']})")
                print(
                    f"[{key.upper()}] Cave: {cave['used_bytes']} / {cave['capacity_bytes']} B "
                    f"(remaining {cave['remaining_bytes']} B in {cave['start']}..{cave['end_exclusive']})"
                )
        return 0

    if args.profile == "phase3plus":
        result = build_phase3plus_firmware(
            source_hex=args.source,
            output_dir=args.output_dir,
            output_hex=args.output_hex,
            enable_recovery=not args.no_recovery,
            enable_debounce=not args.no_debounce,
            enable_persistence=not args.no_persistence,
            enable_group5=not args.no_group5,
            install_persist_loop_hook=not args.skip_persist_loop_hook,
            enable_motion=not args.no_motion,
            enable_plock=not args.no_plock,
            enable_mouse_abs=not args.no_mouse_abs,
        )
    elif args.profile == "phase3":
        result = build_phase3_firmware(
            source_hex=args.source,
            output_dir=args.output_dir,
            output_hex=args.output_hex,
            enable_recovery=not args.no_recovery,
            enable_debounce=not args.no_debounce,
            enable_persistence=not args.no_persistence,
            enable_group5=not args.no_group5,
            install_persist_loop_hook=not args.skip_persist_loop_hook,
            enable_motion=not args.no_motion,
            enable_plock=not args.no_plock,
        )
    else:
        result = build_phase2_firmware(
            source_hex=args.source,
            output_dir=args.output_dir,
            output_hex=args.output_hex,
            enable_recovery=not args.no_recovery,
            enable_debounce=not args.no_debounce,
            enable_persistence=not args.no_persistence,
            enable_group5=not args.no_group5,
            install_persist_loop_hook=not args.skip_persist_loop_hook,
        )
    manifest = result["manifest"]
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        cave = manifest["cave_budget"]
        cap = manifest["capstone_summary"]
        print(f"Artifact Tag : {manifest['artifact_tag']} (offline-only, hardware_flashing_supported={manifest['hardware_flashing_supported']})")
        print(f"Patched HEX  : {result['hex_path']} (SHA-256: {manifest['output']['hex_sha256']})")
        print(f"Manifest     : {result['manifest_path']}")
        print(f"Capstone Rpt : {result['capstone_path']} (all_verified={cap['all_verified']}, insns={cap['total_verified_instructions']})")
        print(
            f"Cave Usage   : {cave['used_bytes']} / {cave['capacity_bytes']} B "
            f"(remaining {cave['remaining_bytes']} B in {cave['start']}..{cave['end_exclusive']})"
        )
        print(
            f"Changes      : {manifest['stats']['modified_stock_bytes']} stock bytes patched, "
            f"{manifest['stats']['added_cave_bytes']} cave bytes added"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
