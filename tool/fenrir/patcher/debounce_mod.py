"""Immediate button_thresholds_load_profile (0xC1E8) reload on Family B 0x05 (H3)."""

from __future__ import annotations

from typing import Any

from fenrir.patcher import target_mouse as T
from fenrir.patcher.thumb import PatchContext


def install(ctx: PatchContext) -> dict[str, Any]:
    """Patch Family B 0x05 at 0x18AF8 so 0xC1E8 reloads live thresholds immediately."""
    builder = ctx.builder
    for key in ("family_b_05_block", "h3_debounce_05_call", "button_thresholds_load_profile"):
        spec = T.PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)

    # 0x18AF4..0x18AF7 already sets R1=0, R0=8 for config_mark_dirty(8, 0).
    # 0xC1E8 is a leaf function clobbering only R0, R1; 0x18AFC overwrites R0, R1.
    helper_addr = ctx.alloc_asm(
        "debounce_05_immediate_reload",
        [
            "push {r4, lr}",
            f"bl {T.FN_CONFIG_MARK_DIRTY:#x}",
            f"bl {T.FN_BUTTON_THRESHOLDS_LOAD_PROFILE:#x}",
            "pop {r4, pc}",
        ],
        align=2,
        module="debounce_mod",
        reason="Call config_mark_dirty(8, 0) then immediately reload live debounce via 0xC1E8",
    )

    ctx.patch_bl(
        T.HOOK_H3_DEBOUNCE_05_CALL,
        helper_addr,
        expected_old=T.PREIMAGES["h3_debounce_05_call"].expected,
        module="debounce_mod",
        reason="H3: Family B 0x05 immediate 0xC1E8 threshold reload",
    )

    return {
        "enabled": True,
        "hook_site": f"0x{T.HOOK_H3_DEBOUNCE_05_CALL:08X}",
        "helper_address": f"0x{helper_addr:08X}",
        "reload_fn": f"0x{T.FN_BUTTON_THRESHOLDS_LOAD_PROFILE:08X}",
        "persisted_ram": f"0x{T.RAM_DEBOUNCE_PERSISTED:08X}..0x{T.RAM_DEBOUNCE_PERSISTED + 3:08X}",
        "live_ram": f"0x{T.RAM_BUTTON_THRESH_LIVE:08X}..0x{T.RAM_BUTTON_THRESH_LIVE + 5:08X}",
    }
