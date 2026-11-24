"""Phase 3+ (S2b P1) wireless mouse-side active u16 ABS (`type 0x0A`) emitter.

Default OFF (`P3_FLAG_MOUSE_ABS = 0`): stock/unpatched receivers continue receiving
standard `type 0x02` relative deltas. When opted in via `SET_P3_CTRL` (`P3_FLAG_MOUSE_ABS`),
wireless Queue 2 frames (`0x000180EA`) tag bit 7 of `rec[0]` (`& 0x80`, untouched by stock
`0x0001B308/0x0001B354` `and #0x1f`) and accumulate `u16` `(abs_x, abs_y)` ONLY when Queue 2
push (`0x00021448`) succeeds (`r0 == 1`). The RF packet builder (`0x0001B2C4`) forces single-
sample packets across `REL <-> ABS` transitions (`0x0001B334`) and emits RF `b0 = 0x0A`
instead of `0x02` (`0x0001B3EC`). Wired USB (`0x01828C`), BLE (`0x0199D4`), and `IRQ20`
(`0x01D150`) keep consuming relative deltas untouched.
"""

from __future__ import annotations

from typing import Any

from fenrir.patcher import phase3_diag as D, target_mouse as T
from fenrir.patcher.thumb import PatchContext, assemble


def _patch_inline(
    ctx: PatchContext,
    site: int,
    expected_old: bytes,
    lines: list[str],
    *,
    name: str,
    symbols: dict[str, int] | None = None,
    reason: str = "",
) -> None:
    merged = dict(ctx.builder.symbols)
    if symbols:
        merged.update(symbols)
    blk = assemble(lines, site, name=name, symbols=merged, verify=True)
    if len(blk.data) > len(expected_old):
        raise ValueError(f"[{name}] Patch {len(blk.data)}B exceeds slot {len(expected_old)}B at {site:#x}")
    pad_n = len(expected_old) - len(blk.data)
    if pad_n % 2 != 0:
        raise ValueError(f"[{name}] Odd NOP pad {pad_n} at {site:#x}")
    if pad_n:
        blk = assemble(list(lines) + ["nop"] * (pad_n // 2), site, name=name, symbols=merged, verify=True)
    assert len(blk.data) == len(expected_old)
    ctx.builder.edit(site, blk.data, expected_old=expected_old, module="phase3plus_abs", reason=reason or name)
    ctx.blocks.append(blk)


def install(ctx: PatchContext) -> dict[str, Any]:
    """Install wireless-only active u16 ABS (type 0x0A) hooks into the mouse patch builder."""
    builder = ctx.builder
    for key in ("p3p_wl_q2_push", "p3p_rf_s2_chk", "p3p_rf_b0_type", "fn_q2_push_21448"):
        spec = T.P3PLUS_PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)

    p3_base = T.PHASE3_RAM_BASE
    code_lines: list[str] = [
        # int p3p_wl_q2_push(r0 = queue_id(2), r1 = rec_ptr(sp+4)) -> 1 queued, 0 full
        "p3p_wl_q2_push:",
        "push {r4, r5, r6, lr}",
        "mov r4, r0",
        "mov r5, r1",
        f"ldr r6, ={p3_base:#x}",
        f"ldr r0, [r6, #{D.OFF_P3_FLAGS}]",
        f"tst.w r0, #{D.P3_FLAG_MOUSE_ABS}",
        "beq p3p_abs_rel",
        f"bl {T.FN_GET_TRANSPORT_MODE:#x}",
        "cmp r0, #1",
        "bne p3p_abs_rel",

        # Compute candidate wrapped u16 (abs_x, abs_y) without committing yet
        f"ldrh r2, [r6, #{D.OFF_ABS_X}]",
        "ldrh r0, [r5, #4]",
        "sxth r0, r0",
        "adds r2, r2, r0",
        "uxth r2, r2",
        f"ldrh r3, [r6, #{D.OFF_ABS_Y}]",
        "ldrh r0, [r5, #6]",
        "sxth r0, r0",
        "adds r3, r3, r0",
        "uxth r3, r3",
        "strh r2, [r5, #4]",
        "strh r3, [r5, #6]",
        "ldrb r0, [r5, #2]",
        "orr.w r0, r0, #0x80",
        "strb r0, [r5, #2]",
        "push {r2, r3}",
        "mov r0, r4",
        "mov r1, r5",
        f"bl {T.FN_Q2_PUSH_21448:#x}",
        "pop {r2, r3}",
        "cmp r0, #1",
        "bne p3p_abs_q2_full",

        "mrs r12, primask",
        "cpsid i",
        f"strh r2, [r6, #{D.OFF_ABS_X}]",
        f"strh r3, [r6, #{D.OFF_ABS_Y}]",
        f"ldr.w r1, [r6, #{D.P1_DIAG_OFFSETS['abs_tx_pkts']}]",
        "adds r1, #1",
        f"str.w r1, [r6, #{D.P1_DIAG_OFFSETS['abs_tx_pkts']}]",
        "msr primask, r12",
        "movs r0, #1",
        "pop {r4, r5, r6, pc}",

        "p3p_abs_q2_full:",
        "mrs r12, primask",
        "cpsid i",
        f"ldr.w r1, [r6, #{D.P1_DIAG_OFFSETS['abs_q2_drops']}]",
        "adds r1, #1",
        f"str.w r1, [r6, #{D.P1_DIAG_OFFSETS['abs_q2_drops']}]",
        "msr primask, r12",
        "movs r0, #0",
        "pop {r4, r5, r6, pc}",

        "p3p_abs_rel:",
        "ldrb r0, [r5, #2]",
        "bic.w r0, r0, #0x80",
        "strb r0, [r5, #2]",
        "mov r0, r4",
        "mov r1, r5",
        f"bl {T.FN_Q2_PUSH_21448:#x}",
        "pop {r4, r5, r6, pc}",

        # int p3p_rf_check_s2(void) - preserves r4..r11
        # Reads r4=&rec0, r6=idx0, r7=q2_base, r9(sb)=cap, r10(sl)=count -> 1 if 2 same-tag samples
        "p3p_rf_check_s2:",
        "mov r0, r10",
        "cmp r0, #1",
        "bgt p3p_s2_chk_tags",
        "movs r0, #0",
        "bx lr",
        "p3p_s2_chk_tags:",
        "adds r0, r6, #1",
        "mov r1, r9",
        "cmp r0, r1",
        "blt p3p_s2_idx_ok",
        "movs r0, #0",
        "p3p_s2_idx_ok:",
        "lsls r1, r0, #1",
        "adds r0, r0, r1",
        "lsls r0, r0, #2",
        "addw r1, r7, #10",
        "adds r1, r1, r0",
        "ldrb r0, [r4, #0]",
        "lsrs r0, r0, #7",
        "ldrb r1, [r1, #0]",
        "lsrs r1, r1, #7",
        "cmp r0, r1",
        "bne p3p_s2_mixed",
        "movs r0, #1",
        "bx lr",
        "p3p_s2_mixed:",
        "movs r0, #0",
        "bx lr",

        # void p3p_rf_set_type_b0(r0=tx_base, r4=rec_ptr) -> writes [r0+0xdb] = 0x0A (ABS) or 0x02 (REL)
        "p3p_rf_set_type_b0:",
        "ldrb r1, [r4, #0]",
        "tst.w r1, #0x80",
        "beq p3p_b0_rel",
        "movs r1, #0x0a",
        "strb.w r1, [r0, #0xdb]",
        "bx lr",
        "p3p_b0_rel:",
        "movs r1, #0x02",
        "strb.w r1, [r0, #0xdb]",
        "bx lr",
        ".ltorg",
    ]

    base = ctx.alloc_asm(
        "phase3plus_abs_core",
        code_lines,
        align=4,
        export_labels=("p3p_wl_q2_push", "p3p_rf_check_s2", "p3p_rf_set_type_b0"),
        module="phase3plus_abs",
        reason="Active mouse-side wireless u16 ABS (type 0x0A, default OFF) + mixed-packet split guard",
    )

    ctx.patch_bl(
        T.HOOK_P3P_WL_Q2_PUSH,
        builder.symbols["p3p_wl_q2_push"],
        expected_old=T.P3PLUS_PREIMAGES["p3p_wl_q2_push"].expected,
        module="phase3plus_abs",
        reason="Convert wireless Queue 2 motion payload to u16 ABS when P3_FLAG_MOUSE_ABS is enabled",
    )
    _patch_inline(
        ctx,
        T.HOOK_P3P_RF_S2_CHK,
        T.P3PLUS_PREIMAGES["p3p_rf_s2_chk"].expected,
        ["bl p3p_rf_check_s2", "cbz r0, _rf_single"],
        symbols={"_rf_single": T.TARGET_P3P_RF_SINGLE},
        name="rf_builder_s2_abs_rel_guard",
        reason="Force sample_cnt=1 when Queue 2 has mixed REL/ABS samples",
    )
    _patch_inline(
        ctx,
        T.HOOK_P3P_RF_B0_TYPE,
        T.P3PLUS_PREIMAGES["p3p_rf_b0_type"].expected,
        ["bl p3p_rf_set_type_b0"],
        name="rf_builder_b0_type_0a",
        reason="Emit RF b0=0x0A for tagged ABS packets and b0=0x02 for REL packets",
    )

    return {
        "enabled": True,
        "default": "relative (type 0x02)",
        "code_base": f"0x{base:08X}",
        "symbols": {
            "p3p_wl_q2_push": f"0x{builder.symbols['p3p_wl_q2_push']:08X}",
            "p3p_rf_check_s2": f"0x{builder.symbols['p3p_rf_check_s2']:08X}",
            "p3p_rf_set_type_b0": f"0x{builder.symbols['p3p_rf_set_type_b0']:08X}",
        },
    }
