"""Phase 3+ Wave 2 (S2b P2/P3) Mouse Firmware Patch Module (`NOT_FOR_FLASH`).

Implements ONLY the 4 verified-applicable P2/P3 features (all default-OFF or
stock-equivalent):
1. `eager-wake` (P2, default OFF): Hooks `IRQ6` (`0x00006628`) -> `0x0001DF40()`
   only when `P3_FLAG_EAGER_WAKE` and `P3_FLAG_DIRECT_MOTION` are both enabled,
   `!in_flash_op`, `0x2000411C != 0`, `0x20004118 == 0`, and `0x20004119 == 0`,
   counting `eager_wake_hits` without touching `TIMER1->CC[0]` or `TASKS_CLEAR`.
2. `ce-static` (P3, default OFF): Applies verified 14-register `M1_hi` Bank 05/09
   tuning below 7000 CPI when `P3_FLAG_CE_STATIC` is enabled in Mode 1, and cleanly
   reverts to stock `M1_lo` when cleared below 7000 CPI (leaving 0x7F = 0x00).
3. `lod-raw` (P3, default OFF): Enforces custom `ID53` `0x18:0x7A = raw_val` across
   `H5/H6/H7`, `override_worker`, and `0x0001D4AC` tail, reverts via stock
   `0x0001D388`, and provides cooperative `p3p_peek_worker` (`READ_REG`).
4. `anti-slam` (P3, stock defaults 16 ms / 20 ms): Makes `0x0001C454` landing lock
   and `0x0001C42C` lifted press defer configurable in `[0, 100]` ms.
"""

from __future__ import annotations

from typing import Any

from fenrir.patcher import persistence as P, phase3_diag as D, target_mouse as T
from fenrir.patcher.thumb import PatchContext, assemble

# Verified stock PAW3950 ID53 M1_hi vs M1_lo differences:
# Bank 05 (first 4) + Bank 09 (next 10), each (reg, hi_val, lo_val)
CE_STATIC_BANK05_COUNT = 4
CE_STATIC_REGS: tuple[tuple[int, int, int, int], ...] = (
    # (bank, reg, m1_hi, m1_lo)
    (0x05, 0x51, 0x10, 0x40),
    (0x05, 0x5F, 0x80, 0x90),
    (0x05, 0x6D, 0xA7, 0xB8),
    (0x05, 0x6E, 0xCD, 0xCF),
    (0x09, 0x40, 0x03, 0x01),
    (0x09, 0x44, 0x98, 0x88),
    (0x09, 0x47, 0x18, 0x00),
    (0x09, 0x4F, 0x00, 0x0C),
    (0x09, 0x51, 0x11, 0x04),
    (0x09, 0x55, 0x54, 0x3F),
    (0x09, 0x56, 0x54, 0x3F),
    (0x09, 0x59, 0x20, 0x0F),
    (0x09, 0x5A, 0x20, 0x0F),
    (0x09, 0x73, 0x0E, 0x0C),
)
assert sum(1 for b, _, _, _ in CE_STATIC_REGS[:CE_STATIC_BANK05_COUNT] if b == 0x05) == CE_STATIC_BANK05_COUNT
assert sum(1 for b, _, _, _ in CE_STATIC_REGS[CE_STATIC_BANK05_COUNT:] if b == 0x09) == len(CE_STATIC_REGS) - CE_STATIC_BANK05_COUNT


def _patch_inline(
    ctx: PatchContext,
    site: int,
    expected_old: bytes,
    lines: list[str],
    *,
    name: str,
    reason: str = "",
) -> None:
    merged = dict(ctx.builder.symbols)
    blk = assemble(lines, site, name=name, symbols=merged, verify=True)
    if len(blk.data) > len(expected_old):
        raise ValueError(f"[{name}] Patch {len(blk.data)}B exceeds slot {len(expected_old)}B at {site:#x}")
    pad_n = len(expected_old) - len(blk.data)
    if pad_n % 2 != 0:
        raise ValueError(f"[{name}] Odd NOP pad {pad_n} at {site:#x}")
    if pad_n:
        blk = assemble(list(lines) + ["nop"] * (pad_n // 2), site, name=name, symbols=merged, verify=True)
    assert len(blk.data) == len(expected_old)
    ctx.builder.edit(site, blk.data, expected_old=expected_old, module="phase3plus_w2", reason=reason or name)
    ctx.blocks.append(blk)


def install(ctx: PatchContext) -> dict[str, Any]:
    """Install Wave 2 P2/P3 code and stock hooks into the Phase 3+ patch builder."""
    builder = ctx.builder
    for key in (
        "p3p_irq6_entry",
        "p3p_sensor_poll",
        "p3p_lod_1d3d6",
        "p3p_lod_tail_1d4ac",
        "p3p_anti_slam_lifted",
        "p3p_anti_slam_landing",
    ):
        spec = T.P3PLUS_PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)

    off_burst = T.RAM_SPI_BURST_ACTIVE - T.RAM_SPI_IDLE
    off_poll = T.RAM_POLL_ACTIVE - T.RAM_SPI_IDLE
    off_sens_en = T.RAM_SENSOR_ENABLED - T.RAM_SPI_IDLE
    off_mode_tgt = T.RAM_SENSOR_MODE_TARGET - T.RAM_SENSOR_BRANCH
    off_cpi_x = T.RAM_SENSOR_CPI_X - T.RAM_SENSOR_BRANCH
    off_cpi_y = T.RAM_SENSOR_CPI_Y - T.RAM_SENSOR_BRANCH

    ce_tbl_bytes = bytes(v for _, r, hi, lo in CE_STATIC_REGS for v in (r, hi, lo))

    code_lines: list[str] = [
        ".balign 4",
        "w2_ce_tbl:",
        *(f".byte 0x{ce_tbl_bytes[i]:02x}, 0x{ce_tbl_bytes[i + 1]:02x}, 0x{ce_tbl_bytes[i + 2]:02x}" for i in range(0, len(ce_tbl_bytes), 3)),
        ".balign 2",

        # IRQ6 GPIOTE wrapper: runs exact stock 0x00662C..0x00665A, then conditionally calls 0x0001DF40
        "p3p_irq6_hook:",
        "push {r4, lr}",
        f"ldr r0, ={T.GPIO_EVENTS_IN_6:#x}",
        "ldr r0, [r0]",
        "ldr r1, =p3p_irq6_after+1",
        "mov lr, r1",
        f"b.w {T.RESUME_P3P_IRQ6_BODY:#x}",
        "p3p_irq6_after:",
        f"ldr r4, ={T.PHASE3_RAM_BASE:#x}",
        f"ldr r0, [r4, #{D.OFF_P3_MAGIC}]",
        f"ldr r1, ={D.P3_MAGIC_U32:#x}",
        "cmp r0, r1",
        "bne irq6_done",
        f"ldr r0, [r4, #{D.OFF_P3_FLAGS}]",
        f"tst.w r0, #{D.P3_FLAG_EAGER_WAKE}",
        "beq irq6_done",
        f"tst.w r0, #{D.P3_FLAG_DIRECT_MOTION}",
        "beq irq6_done",
        f"ldrb r0, [r4, #{D.OFF_IN_FLASH_OP}]",
        "cbnz r0, irq6_done",
        f"ldr r1, ={T.RAM_SPI_IDLE:#x}",
        f"ldrb r0, [r1, #{off_sens_en}]",
        "cbz r0, irq6_done",
        f"ldrb r0, [r1, #{off_burst}]",
        "cbnz r0, irq6_done",
        f"ldrb r0, [r1, #{off_poll}]",
        "cbnz r0, irq6_done",
        "movs r0, #1",
        f"strb r0, [r1, #{off_poll}]",
        "mrs r12, primask",
        "cpsid i",
        f"ldr.w r0, [r4, #{D.OFF_EAGER_WAKE_HITS}]",
        "adds r0, #1",
        f"str.w r0, [r4, #{D.OFF_EAGER_WAKE_HITS}]",
        "msr primask, r12",
        f"bl {T.FN_SENSOR_POLL:#x}",
        "irq6_done:",
        "pop {r4, pc}",

        # Anti-slam hooks (default 20 ms lifted / 16 ms landing; preserve r2..r11)
        "p3p_anti_slam_lifted:",
        "push {r2, r3}",
        f"ldr r1, ={T.PHASE3_RAM_BASE:#x}",
        f"ldr r2, [r1, #{D.OFF_P3_MAGIC}]",
        f"ldr r3, ={D.P3_MAGIC_U32:#x}",
        "cmp r2, r3",
        "bne asl_stock",
        f"ldrb.w r0, [r1, #{D.OFF_ANTI_SLAM_LIFTED}]",
        "pop {r2, r3}",
        "bx lr",
        "asl_stock:",
        "ldrb.w r0, [r0, #0x210]",
        "pop {r2, r3}",
        "bx lr",

        "p3p_anti_slam_landing:",
        "push {r2, r3}",
        f"ldr r1, ={T.PHASE3_RAM_BASE:#x}",
        f"ldr r2, [r1, #{D.OFF_P3_MAGIC}]",
        f"ldr r3, ={D.P3_MAGIC_U32:#x}",
        "cmp r2, r3",
        "bne asd_stock",
        f"ldrb.w r0, [r1, #{D.OFF_ANTI_SLAM_LANDING}]",
        "b asd_tail",
        "asd_stock:",
        "movs r0, #0x10",
        "asd_tail:",
        "pop {r2, r3}",
        "lsls r1, r4, #1",
        "adds r1, r1, r4",
        "bx lr",

        # LOD tail at 0x0001D4AC (replaces pop {r4,r5,r6,pc}; nop)
        "p3p_lod_tail:",
        f"ldr r0, ={T.PHASE3_RAM_BASE:#x}",
        f"ldr r1, [r0, #{D.OFF_P3_MAGIC}]",
        f"ldr r2, ={D.P3_MAGIC_U32:#x}",
        "cmp r1, r2",
        "bne lod_tail_pop",
        f"ldrb.w r1, [r0, #{D.OFF_LOD_RAW_EN}]",
        "cbz r1, lod_tail_pop",
        f"ldr r1, ={T.RAM_SENSOR_BRANCH:#x}",
        "ldrb r1, [r1, #0]",
        "cmp r1, #0x53",
        "bne lod_tail_pop",
        "push {r4}",
        f"ldrb.w r4, [r0, #{D.OFF_LOD_RAW_VAL}]",
        "movs r0, #0x7f",
        "movs r1, #0x18",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "movs r0, #0x7a",
        "mov r1, r4",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "movs r0, #0x7f",
        "movs r1, #0",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "pop {r4}",
        "lod_tail_pop:",
        "pop {r4, r5, r6, pc}",

        # Local (r0=rb_val, r1=ok) w2_spi_wr_rb(r0=bank, r1=reg, r2=val)
        "w2_spi_wr_rb:",
        "push {r4, r5, r6, lr}",
        "mov r4, r1",
        "mov r5, r2",
        "mov r1, r0",
        "movs r0, #0x7f",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "cbz r0, w2_wr_fail",
        "mov r0, r4",
        "mov r1, r5",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "cbz r0, w2_wr_fail",
        "mov r0, r4",
        f"bl {T.FN_SPI_READ_REG:#x}",
        "cmp r0, r5",
        "bne w2_wr_fail",
        "movs r1, #1",
        "pop {r4, r5, r6, pc}",
        "w2_wr_fail:",
        "movs r1, #0",
        "pop {r4, r5, r6, pc}",
        ".ltorg",

        # int p3p_apply_ce_static(r0=RAM_SENSOR_BRANCH, r1=PHASE2_RAM_BASE) -> 1 if SPI ran else 0
        "p3p_apply_ce_static:",
        "push {r4, r5, r6, r7, lr}",
        f"ldr r4, ={T.PHASE3_RAM_BASE:#x}",
        f"ldrb.w r2, [r4, #{D.OFF_CE_STATIC_STATE}]",
        "tst.w r2, #7",
        "bne ce_go",
        "movs r0, #0",
        "pop {r4, r5, r6, r7, pc}",
        "ce_go:",
        "push {r1}",  # save PHASE2_RAM_BASE
        f"ldrb r3, [r0, #{off_mode_tgt}]",
        "tst.w r2, #1",
        "beq ce_revert_chk",
        "cmp r3, #1",
        "beq ce_apply_hi",
        "pop {r1}",
        "movs r0, #0",
        "pop {r4, r5, r6, r7, pc}",
        "ce_apply_hi:",
        "movs r6, #1",  # hi_offset = 1 inside (reg, hi, lo)
        "b ce_write_tbl",
        "ce_revert_chk:",
        "cmp r3, #1",
        "bne ce_clear_no_spi",
        f"ldrh r2, [r0, #{off_cpi_x}]",
        f"ldrh r3, [r0, #{off_cpi_y}]",
        "movw r1, #7000",
        "cmp r2, r1",
        "bhs ce_clear_no_spi",
        "cmp r3, r1",
        "bhs ce_clear_no_spi",
        "movs r6, #2",  # lo_offset = 2 inside (reg, hi, lo)
        "b ce_write_tbl",
        "ce_clear_no_spi:",
        "pop {r1}",
        "movs r0, #0",
        f"strb.w r0, [r4, #{D.OFF_CE_STATIC_STATE}]",
        "pop {r4, r5, r6, r7, pc}",

        "ce_write_tbl:",
        "ldr r5, =w2_ce_tbl",
        "movs r7, #1",  # all_ok
        "movs r3, #0",  # index 0..13
        "ce_loop:",
        "push {r3}",
        f"cmp r3, #{CE_STATIC_BANK05_COUNT}",
        "blo ce_bank05",
        "movs r0, #9",
        "b ce_wr_one",
        "ce_bank05:",
        "movs r0, #5",
        "ce_wr_one:",
        "ldrb r1, [r5, #0]",
        "ldrb r2, [r5, r6]",
        "bl w2_spi_wr_rb",
        "pop {r3}",
        "cbnz r1, ce_next",
        "movs r7, #0",
        "ce_next:",
        "adds r5, #3",
        "adds r3, #1",
        f"cmp r3, #{len(CE_STATIC_REGS)}",
        "blo ce_loop",
        "movs r0, #0x7f",
        "movs r1, #0",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "cbnz r0, ce_finish",
        "movs r7, #0",
        "ce_finish:",
        "pop {r2}",  # PHASE2_RAM_BASE
        f"ldrb.w r0, [r4, #{D.OFF_CE_STATIC_STATE}]",
        "cbz r7, ce_err",
        "and.w r0, r0, #1",
        "lsls r1, r0, #1",
        "orrs r0, r1",
        "tst.w r0, #1",
        "beq ce_fin_st",
        "orr.w r0, r0, #8",  # rb_ok when enabled
        "ce_fin_st:",
        f"strb.w r0, [r4, #{D.OFF_CE_STATIC_STATE}]",
        "movs r0, #1",
        "pop {r4, r5, r6, r7, pc}",
        "ce_err:",
        "and.w r0, r0, #7",
        f"strb.w r0, [r4, #{D.OFF_CE_STATIC_STATE}]",
        f"ldrb.w r1, [r4, #{D.OFF_CE_STATIC_FAIL_CNT}]",
        "adds r1, #1",
        f"strb.w r1, [r4, #{D.OFF_CE_STATIC_FAIL_CNT}]",
        "movs r1, #3",  # ERR_READBACK_MISMATCH
        f"strb r1, [r2, #{P.OFF_LAST_ERR}]",
        "movs r0, #1",
        "pop {r4, r5, r6, r7, pc}",

        # int p3p_apply_lod_raw(r0=RAM_SENSOR_BRANCH, r1=PHASE2_RAM_BASE) -> 1 if SPI ran else 0
        "p3p_apply_lod_raw:",
        "push {r4, r5, r6, lr}",
        f"ldr r4, ={T.PHASE3_RAM_BASE:#x}",
        f"ldrb.w r2, [r4, #{D.OFF_LOD_RAW_STATE}]",
        "tst.w r2, #7",
        "bne lod_go",
        "movs r0, #0",
        "pop {r4, r5, r6, pc}",
        "lod_go:",
        "mov r5, r1",  # PHASE2_RAM_BASE
        "tst.w r2, #1",
        "beq lod_revert",
        "movs r0, #0x18",
        "movs r1, #0x7a",
        f"ldrb.w r2, [r4, #{D.OFF_LOD_RAW_VAL}]",
        "bl w2_spi_wr_rb",
        f"strb.w r0, [r4, #{D.OFF_LOD_RAW_RB_VAL}]",
        "mov r6, r1",
        "movs r0, #0x7f",
        "movs r1, #0",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "cbnz r0, lod_fin",
        "movs r6, #0",
        "lod_fin:",
        "cbz r6, lod_err",
        "movs r0, #0x0b",  # req=1, app=1, pend=0, rb_ok=1
        f"strb.w r0, [r4, #{D.OFF_LOD_RAW_STATE}]",
        "movs r0, #1",
        "pop {r4, r5, r6, pc}",
        "lod_err:",
        "movs r0, #5",  # req=1, app=0, pend=1, rb_ok=0
        f"strb.w r0, [r4, #{D.OFF_LOD_RAW_STATE}]",
        f"ldrb.w r1, [r4, #{D.OFF_LOD_RAW_FAIL_CNT}]",
        "adds r1, #1",
        f"strb.w r1, [r4, #{D.OFF_LOD_RAW_FAIL_CNT}]",
        "movs r1, #3",  # ERR_READBACK_MISMATCH
        f"strb r1, [r5, #{P.OFF_LAST_ERR}]",
        "movs r0, #1",
        "pop {r4, r5, r6, pc}",
        "lod_revert:",
        f"ldr r0, ={T.RAM_LOD_NV_VAL:#x}",
        "ldrb r0, [r0, #0]",
        "cmp r0, #1",
        "beq lod_nv_ok",
        "cmp r0, #2",
        "beq lod_nv_ok",
        "cmp r0, #7",
        "beq lod_nv_ok",
        "movs r0, #1",
        "lod_nv_ok:",
        "movs r1, #0",
        f"bl {T.FN_SENSOR_LOD_SET:#x}",
        "movs r0, #0",
        f"strb.w r0, [r4, #{D.OFF_LOD_RAW_STATE}]",
        "movs r0, #1",
        "pop {r4, r5, r6, pc}",

        # int p3p_peek_worker(void) -> 1 done, 0 retry
        "p3p_peek_worker:",
        "push {r4, r5, r6, lr}",
        f"ldr r1, ={T.RAM_SPI_IDLE:#x}",
        "ldrb r0, [r1, #0]",
        "cbz r0, pk_retry",
        f"ldrb r0, [r1, #{off_burst}]",
        "cbnz r0, pk_retry",
        f"ldrb r0, [r1, #{off_sens_en}]",
        "cbnz r0, pk_run",
        "pk_retry:",
        "movs r0, #0",
        "pop {r4, r5, r6, pc}",
        "pk_run:",
        f"ldr r4, ={T.PHASE3_RAM_BASE:#x}",
        f"ldrb.w r5, [r4, #{D.OFF_PEEK_BANK}]",
        f"ldrb.w r6, [r4, #{D.OFF_PEEK_REG}]",
        "movs r0, #0x7f",
        "mov r1, r5",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "cbz r0, pk_busy",
        "mov r0, r6",
        f"bl {T.FN_SPI_READ_REG:#x}",
        "mov r5, r0",
        "movs r0, #0x7f",
        "movs r1, #0",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "cbz r0, pk_busy",
        f"strb.w r5, [r4, #{D.OFF_PEEK_VAL}]",
        "movs r0, #1",
        f"strb.w r0, [r4, #{D.OFF_PEEK_VALID}]",
        "movs r0, #0",
        f"strb.w r0, [r4, #{D.OFF_PEEK_PENDING}]",
        f"strb.w r0, [r4, #{D.OFF_PEEK_ERR}]",
        "movs r0, #1",
        "pop {r4, r5, r6, pc}",
        "pk_busy:",
        "movs r0, #1",
        f"strb.w r0, [r4, #{D.OFF_PEEK_ERR}]",
        "movs r0, #0",
        f"strb.w r0, [r4, #{D.OFF_PEEK_PENDING}]",
        "movs r0, #1",
        "pop {r4, r5, r6, pc}",
        ".ltorg",
    ]

    base = ctx.alloc_asm(
        "phase3plus_w2_core",
        code_lines,
        align=4,
        export_labels=(
            "p3p_irq6_hook",
            "p3p_anti_slam_lifted",
            "p3p_anti_slam_landing",
            "p3p_lod_tail",
            "p3p_apply_ce_static",
            "p3p_apply_lod_raw",
            "p3p_peek_worker",
        ),
        module="phase3plus_w2",
        reason="Wave 2 S2b P2/P3 core: eager-wake, ce-static, lod-raw + peek worker, anti-slam window",
    )

    _patch_inline(
        ctx,
        T.HOOK_P3P_IRQ6_ENTRY,
        T.P3PLUS_PREIMAGES["p3p_irq6_entry"].expected,
        ["b.w p3p_irq6_hook"],
        name="irq6_eager_wake_entry",
        reason="Wrap IRQ6 (0x00006628) for conditional eager-wake -> 0x0001DF40 when direct_motion=1",
    )
    _patch_inline(
        ctx,
        T.HOOK_P3P_ANTI_SLAM_LIFTED,
        T.P3PLUS_PREIMAGES["p3p_anti_slam_lifted"].expected,
        ["bl p3p_anti_slam_lifted"],
        name="anti_slam_lifted_ms",
        reason="Configurable lifted press_defer window (stock default 20 ms)",
    )
    _patch_inline(
        ctx,
        T.HOOK_P3P_ANTI_SLAM_LANDING,
        T.P3PLUS_PREIMAGES["p3p_anti_slam_landing"].expected,
        ["bl p3p_anti_slam_landing"],
        name="anti_slam_landing_ms",
        reason="Configurable landing button lock window (stock default 16 ms)",
    )
    _patch_inline(
        ctx,
        T.HOOK_P3P_LOD_TAIL,
        T.P3PLUS_PREIMAGES["p3p_lod_tail_1d4ac"].expected,
        ["b.w p3p_lod_tail"],
        name="lod_1d4ac_tail_override",
        reason="Preserve raw ID53 0x18:0x7A override across stock LOD setter 0x0001D388",
    )

    return {
        "enabled": True,
        "base": f"0x{base:08X}",
        "p3p_irq6_hook": f"0x{builder.symbols['p3p_irq6_hook']:08X}",
        "p3p_anti_slam_lifted": f"0x{builder.symbols['p3p_anti_slam_lifted']:08X}",
        "p3p_anti_slam_landing": f"0x{builder.symbols['p3p_anti_slam_landing']:08X}",
        "p3p_lod_tail": f"0x{builder.symbols['p3p_lod_tail']:08X}",
        "p3p_apply_ce_static": f"0x{builder.symbols['p3p_apply_ce_static']:08X}",
        "p3p_apply_lod_raw": f"0x{builder.symbols['p3p_apply_lod_raw']:08X}",
        "p3p_peek_worker": f"0x{builder.symbols['p3p_peek_worker']:08X}",
    }
