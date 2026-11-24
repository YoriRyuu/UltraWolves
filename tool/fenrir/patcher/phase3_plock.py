"""Phase 3 TIMER1 phase-lock, flash-write coordination, and stationary tracking.

Hooks installed cleanly on stock MOUSE v1.00.39.00:
  - 0x00887E (IRQ9 TIMER1_IRQHandler -> bl 0x01DF40): tracks stationary/active
    ticks from 0x2000411C, 0x20004119, 0x2000326E into `stationary_state` and
    `diag.{stationary_ticks,active_ticks}`.
  - 0x008882 (IRQ9 -> bl 0x01F6C0): preserves exact transport mode return in R0,
    bumps `diag.irq9_ticks`, and when `P3_FLAG_PLOCK_ENABLE` is enabled (default OFF)
    performs non-blocking bounded TIMER1 (0x40009000) CC[0]/CC[1] phase-lock trim.
  - 0x00F2D8 (0x00F2BC flash RF/timer pause -> bl 0x01F6F0): sets `in_flash_op=1`,
    `plock_phase_state=2`, and increments `diag.flash_pauses`.
  - 0x00F2FE (0x00F2DE flash RF/timer resume -> bl 0x01F71C): clears `in_flash_op=0`,
    and when `P3_FLAG_PLOCK_ENABLE` is enabled restores locked CC[0]/CC[1] timing
    and increments `diag.plock_resets`.
"""

from __future__ import annotations

from typing import Any

from fenrir.patcher import phase3_diag as D, target_mouse as T
from fenrir.patcher.thumb import PatchContext, encode_bl, verify_branch_patch


def install(ctx: PatchContext, *, phase3plus: bool = False) -> dict[str, Any]:
    """Install Phase 3 (or Phase 3+) TIMER1 plock, stationary tracking, and flash pause/resume hooks."""
    builder = ctx.builder
    for key in (
        "p3_irq9_stationary",
        "p3_irq9_plock",
        "p3_flash_pause_timer",
        "p3_flash_resume_timer",
        "fn_get_transport_mode",
        "fn_timer_pause_1f6f0",
        "fn_timer_resume_1f71c",
        "fn_irq9_motion_tick",
    ):
        spec = T.P3_PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)
    if phase3plus:
        entry_clear_spec = T.P3PLUS_PREIMAGES["p3p_irq9_entry_clear"]
        builder.verify_fingerprint(
            entry_clear_spec.address,
            entry_clear_spec.expected,
            label=entry_clear_spec.label,
        )

    p3_base = T.PHASE3_RAM_BASE

    code_lines: list[str] = [
        # void p3_irq9_stationary_hook(void) - wraps 0x01DF40 at 0x00887E
        "p3_irq9_stationary_hook:",
        "push {r4, lr}",
        f"bl {T.FN_IRQ9_MOTION_TICK:#x}",
        "movs r0, #0",
        f"ldr r1, ={T.RAM_STAT_MASTER:#x}",
        "ldrb r1, [r1, #0]",
        "cbz r1, p3_st_chk_poll",
        "orr.w r0, r0, #1",
        "p3_st_chk_poll:",
        f"ldr r1, ={T.RAM_STAT_POLL_ACTIVE:#x}",
        "ldrb r1, [r1, #0]",
        "cbz r1, p3_st_chk_gate",
        "orr.w r0, r0, #2",
        "p3_st_chk_gate:",
        f"ldr r1, ={T.RAM_STAT_MOTION_GATE:#x}",
        "ldrb r1, [r1, #0]",
        "cbz r1, p3_st_store",
        "orr.w r0, r0, #4",
        "p3_st_store:",
        f"ldr r4, ={p3_base:#x}",
        "mrs r12, primask",
        "cpsid i",
        f"strb r0, [r4, #{D.OFF_STAT_STATE}]",
        "tst.w r0, #6",
        "beq p3_st_idle",
        f"ldr r1, [r4, #{D.DIAG_OFFSETS['active_ticks']}]",
        "adds r1, #1",
        f"str r1, [r4, #{D.DIAG_OFFSETS['active_ticks']}]",
        "b p3_st_done",
        "p3_st_idle:",
        f"ldr r1, [r4, #{D.DIAG_OFFSETS['stationary_ticks']}]",
        "adds r1, #1",
        f"str r1, [r4, #{D.DIAG_OFFSETS['stationary_ticks']}]",
        "p3_st_done:",
        "msr primask, r12",
        "pop {r4, pc}",

        # uint32_t p3_irq9_plock_hook(void) - wraps 0x01F6C0 at 0x008882, returns mode
        "p3_irq9_plock_hook:",
        *(
            [
                "push {r4, r5, r6, lr}",
                f"bl {T.FN_GET_TRANSPORT_MODE:#x}",
                "mov r4, r0",
                f"ldr r5, ={p3_base:#x}",
                "mrs r12, primask",
                "cpsid i",
                f"ldr r0, [r5, #{D.DIAG_OFFSETS['irq9_ticks']}]",
                "adds r0, #1",
                f"str r0, [r5, #{D.DIAG_OFFSETS['irq9_ticks']}]",
                f"ldr r0, [r5, #{D.OFF_P3_FLAGS}]",
                f"tst.w r0, #{D.P3_FLAG_PLOCK_ENABLE}",
                "bne p3_pl_chk_flash",
                "movs r0, #0",
                f"strb r0, [r5, #{D.OFF_PLOCK_PHASE_STATE}]",
                "b p3_pl_ret",
                "p3_pl_chk_flash:",
                f"ldrb r0, [r5, #{D.OFF_IN_FLASH_OP}]",
                "cbz r0, p3_pl_active",
                "movs r0, #2",
                f"strb r0, [r5, #{D.OFF_PLOCK_PHASE_STATE}]",
                "b p3_pl_ret",
                "p3_pl_active:",
                # Capture TIMER1->CC[2] safely with zero polling loop
                f"ldr r6, ={T.MMIO_TIMER1_BASE:#x}",
                "movs r0, #1",
                "str r0, [r6, #0x48]",       # TASKS_CAPTURE[2]
                "ldr.w r0, [r6, #0x540]",     # r0 = cur CC[0]
                "ldr.w r1, [r6, #0x544]",     # r1 = cur CC[1]
                "ldr.w r2, [r6, #0x548]",     # r2 = cur CC[2]
                f"ldrh r3, [r5, #{D.OFF_PLOCK_PERIOD_US}]",
                "cbnz r2, p3_pl_chk_cc0",
                "movs r2, #0",
                "b p3_pl_store_err",
                "p3_pl_chk_cc0:",
                "cbz r0, p3_pl_zero_err",
                "subs r2, r2, r0",            # signed phase err = cc2 - cc0
                "b p3_pl_store_err",
                "p3_pl_zero_err:",
                "movs r2, #0",
                "p3_pl_store_err:",
                f"str r2, [r5, #{D.OFF_PLOCK_LAST_ERR}]",
                # Bounded +-1 us trim around target_period when |err| > 2
                "cmp r2, #2",
                "ble p3_pl_chk_neg",
                "subs r3, r3, #1",
                "b p3_pl_trim_bounds",
                "p3_pl_chk_neg:",
                "mvns r2, r2",                # ~err = -(err + 1); err < -2 => ~err > 1
                "cmp r2, #1",
                "ble p3_pl_trim_bounds",
                "adds r3, r3, #1",
                "p3_pl_trim_bounds:",
                f"cmp r3, #{D.PLOCK_PERIOD_MIN_US}",
                "bhs p3_pl_hi_bnd",
                f"movs r3, #{D.PLOCK_PERIOD_MIN_US}",
                "p3_pl_hi_bnd:",
                # r2 = desired CC[1] = new_cc0 - lead_us (clamped >= 20)
                f"ldrh r2, [r5, #{D.OFF_PLOCK_LEAD_US}]",
                "subs r2, r3, r2",
                "cmp r2, #20",
                "bge p3_pl_chk_upd",
                "movs r2, #20",
                "p3_pl_chk_upd:",
                "cmp r0, r3",
                "bne p3_pl_do_wr",
                "cmp r1, r2",
                "beq p3_pl_locked",
                "p3_pl_do_wr:",
                "str.w r3, [r6, #0x540]",
                "str.w r2, [r6, #0x544]",
                f"ldr r0, [r5, #{D.DIAG_OFFSETS['plock_adjusts']}]",
                "adds r0, #1",
                f"str r0, [r5, #{D.DIAG_OFFSETS['plock_adjusts']}]",
                "p3_pl_locked:",
                f"strh r3, [r5, #{D.OFF_PLOCK_LAST_CC0}]",
                f"strh r2, [r5, #{D.OFF_PLOCK_LAST_CC1}]",
                "movs r0, #1",
                f"strb r0, [r5, #{D.OFF_PLOCK_PHASE_STATE}]",
                "p3_pl_ret:",
                "msr primask, r12",
                "mov r0, r4",
                "pop {r4, r5, r6, pc}",
            ]
            if not phase3plus
            else [
                "push {r4, r5, r6, r7, lr}",
                f"bl {T.FN_GET_TRANSPORT_MODE:#x}",
                "mov r4, r0",
                f"ldr r5, ={p3_base:#x}",
                "mrs r12, primask",
                "cpsid i",
                f"ldr r0, [r5, #{D.DIAG_OFFSETS['irq9_ticks']}]",
                "adds r0, #1",
                f"str r0, [r5, #{D.DIAG_OFFSETS['irq9_ticks']}]",
                f"ldr r0, [r5, #{D.OFF_P3_FLAGS}]",
                f"tst.w r0, #{D.P3_FLAG_PLOCK_ENABLE}",
                "bne p3p_pl_chk_flash",
                "movs r0, #0",
                f"strb r0, [r5, #{D.OFF_PLOCK_PHASE_STATE}]",
                "b p3p_pl_ret",
                "p3p_pl_chk_flash:",
                f"ldrb r0, [r5, #{D.OFF_IN_FLASH_OP}]",
                "cbz r0, p3p_pl_active",
                "movs r0, #2",
                f"strb r0, [r5, #{D.OFF_PLOCK_PHASE_STATE}]",
                "b p3p_pl_ret",

                "p3p_pl_active:",
                f"ldr r6, ={T.MMIO_TIMER1_BASE:#x}",
                "ldr.w r0, [r6, #0x540]",     # CC[0]
                "ldr.w r2, [r6, #0x548]",     # CC[2] captured at IRQ9 entry (0x008842) before 0x01DF40
                f"ldrh r7, [r5, #{D.OFF_PLOCK_PERIOD_US}]",
                "cbnz r2, p3p_pl_chk_cc0",
                "movs r0, #0",
                "b p3p_pl_wrapped_raw",
                "p3p_pl_chk_cc0:",
                "cbz r0, p3p_pl_zero_raw",
                "subs r0, r2, r0",
                "mov r1, r7",
                "bl p3p_wrap_err",
                "b p3p_pl_wrapped_raw",
                "p3p_pl_zero_raw:",
                "movs r0, #0",

                # r0 = wrapped raw_err
                "p3p_pl_wrapped_raw:",
                f"ldrb.w r1, [r5, #{D.OFF_PLOCK_LEARN_PEND}]",
                "cbz r1, p3p_pl_adj_mode",
                # Learn mode calibration shot: store expected_us = clamp_s8(raw_err), clear learn_pend
                f"str r0, [r5, #{D.OFF_PLOCK_LAST_ERR}]",
                "bl p3p_clamp_s8",
                f"strb.w r0, [r5, #{D.OFF_PLOCK_EXPECTED}]",
                "movs r0, #0",
                f"strb.w r0, [r5, #{D.OFF_PLOCK_LEARN_PEND}]",
                f"strb.w r0, [r5, #{D.OFF_PLOCK_OUTLIER_VALID}]",
                f"ldrb.w r1, [r5, #{D.OFF_PLOCK_MODE}]",
                "cmp r1, #2",
                "bne p3p_pl_learn_cnt",
                f"strb.w r0, [r5, #{D.OFF_PLOCK_MODE}]",
                "p3p_pl_learn_cnt:",
                f"ldr.w r0, [r5, #{D.P1_DIAG_OFFSETS['plock_learned_cnt']}]",
                "adds r0, #1",
                f"str.w r0, [r5, #{D.P1_DIAG_OFFSETS['plock_learned_cnt']}]",
                "movs r0, #1",
                f"strb r0, [r5, #{D.OFF_PLOCK_PHASE_STATE}]",
                "b p3p_pl_ret",

                # entry / measure path: adj_err = wrap(raw_err - expected_us, period_us)
                "p3p_pl_adj_mode:",
                f"ldrb.w r1, [r5, #{D.OFF_PLOCK_EXPECTED}]",
                "sxtb r1, r1",
                "subs r0, r0, r1",
                "mov r1, r7",
                "bl p3p_wrap_err",
                "mov r2, r0",                 # r2 = adj_err
                f"str r2, [r5, #{D.OFF_PLOCK_LAST_ERR}]",

                # r3 = |adj_err|
                "mov r3, r2",
                "cmp r3, #0",
                "bge p3p_pl_abs_ok",
                "mvns r3, r3",
                "adds r3, #1",
                "p3p_pl_abs_ok:",
                f"cmp r3, #{D.PLOCK_OUTLIER_US}",
                "bhs p3p_pl_outlier_chk",
                "movs r0, #0",
                f"strb.w r0, [r5, #{D.OFF_PLOCK_OUTLIER_VALID}]",
                "b p3p_pl_accepted",

                # >= 16 us: require 2 consecutive agreeing samples within AGREE_US = 8 us
                "p3p_pl_outlier_chk:",
                "push {r2}",
                "mov r0, r2",
                "bl p3p_clamp_s8",
                "mov r3, r0",                 # r3 = s_err (-127..127)
                "pop {r2}",
                f"ldrb.w r0, [r5, #{D.OFF_PLOCK_OUTLIER_VALID}]",
                "cbz r0, p3p_pl_out_defer",
                f"ldrb.w r1, [r5, #{D.OFF_PLOCK_OUTLIER_PEND}]",
                "sxtb r1, r1",
                "subs r0, r3, r1",
                "cmp r0, #0",
                "bge p3p_pl_diff_ok",
                "mvns r0, r0",
                "adds r0, #1",
                "p3p_pl_diff_ok:",
                f"cmp r0, #{D.PLOCK_AGREE_US}",
                "bhi p3p_pl_out_defer",
                "movs r0, #0",
                f"strb.w r0, [r5, #{D.OFF_PLOCK_OUTLIER_VALID}]",
                "b p3p_pl_accepted",

                "p3p_pl_out_defer:",
                f"strb.w r3, [r5, #{D.OFF_PLOCK_OUTLIER_PEND}]",
                "movs r0, #1",
                f"strb.w r0, [r5, #{D.OFF_PLOCK_OUTLIER_VALID}]",
                f"strb r0, [r5, #{D.OFF_PLOCK_PHASE_STATE}]",
                f"ldr.w r0, [r5, #{D.P1_DIAG_OFFSETS['outliers_skipped']}]",
                "adds r0, #1",
                f"str.w r0, [r5, #{D.P1_DIAG_OFFSETS['outliers_skipped']}]",
                "b p3p_pl_ret",

                # Accepted sample: update err_min / err_max; skip timer writes if mode == measure (1)
                "p3p_pl_accepted:",
                "push {r2}",
                "mov r0, r2",
                "bl p3p_clamp_s8",
                "pop {r2}",
                f"ldrb.w r1, [r5, #{D.OFF_PLOCK_ERR_MIN}]",
                "sxtb r1, r1",
                "cmp r0, r1",
                "bge p3p_pl_chk_max",
                f"strb.w r0, [r5, #{D.OFF_PLOCK_ERR_MIN}]",
                "p3p_pl_chk_max:",
                f"ldrb.w r1, [r5, #{D.OFF_PLOCK_ERR_MAX}]",
                "sxtb r1, r1",
                "cmp r0, r1",
                "ble p3p_pl_chk_mode",
                f"strb.w r0, [r5, #{D.OFF_PLOCK_ERR_MAX}]",
                "p3p_pl_chk_mode:",
                f"ldrb.w r0, [r5, #{D.OFF_PLOCK_MODE}]",
                "cmp r0, #1",
                "beq p3p_pl_locked_no_wr",

                # entry mode: apply deadband (+-(PLOCK_DEADBAND_US-1) us) and bounded +-1 us CC[0]/CC[1] trim
                "ldr.w r0, [r6, #0x540]",
                "ldr.w r1, [r6, #0x544]",
                "mov r3, r7",
                f"cmp r2, #{D.PLOCK_DEADBAND_US}",
                "blt p3p_pl_chk_neg",
                "subs r3, r3, #1",
                "b p3p_pl_trim_bnds",
                "p3p_pl_chk_neg:",
                "mvns r2, r2",
                f"cmp r2, #{D.PLOCK_DEADBAND_US - 1}",
                "blt p3p_pl_trim_bnds",
                "adds r3, r3, #1",
                "p3p_pl_trim_bnds:",
                f"cmp r3, #{D.PLOCK_PERIOD_MIN_US}",
                "bhs p3p_pl_hi_bnd",
                f"movs r3, #{D.PLOCK_PERIOD_MIN_US}",
                "p3p_pl_hi_bnd:",
                f"ldrh r2, [r5, #{D.OFF_PLOCK_LEAD_US}]",
                "subs r2, r3, r2",
                "cmp r2, #20",
                "bge p3p_pl_chk_upd",
                "movs r2, #20",
                "p3p_pl_chk_upd:",
                "cmp r0, r3",
                "bne p3p_pl_do_wr",
                "cmp r1, r2",
                "beq p3p_pl_locked",
                "p3p_pl_do_wr:",
                "str.w r3, [r6, #0x540]",
                "str.w r2, [r6, #0x544]",
                f"ldr r0, [r5, #{D.DIAG_OFFSETS['plock_adjusts']}]",
                "adds r0, #1",
                f"str r0, [r5, #{D.DIAG_OFFSETS['plock_adjusts']}]",
                "p3p_pl_locked:",
                f"strh r3, [r5, #{D.OFF_PLOCK_LAST_CC0}]",
                f"strh r2, [r5, #{D.OFF_PLOCK_LAST_CC1}]",
                "p3p_pl_locked_no_wr:",
                "movs r0, #1",
                f"strb r0, [r5, #{D.OFF_PLOCK_PHASE_STATE}]",
                "p3p_pl_ret:",
                "msr primask, r12",
                "mov r0, r4",
                "pop {r4, r5, r6, r7, pc}",

                # int32_t p3p_wrap_err(r0=val, r1=period) -> [-period//2, +period//2)
                "p3p_wrap_err:",
                "cmp r1, #0",
                "beq p3p_wr_ret",
                "push {r4}",
                "lsrs r2, r1, #1",
                "movs r3, #0",
                "subs r3, r3, r2",
                "movs r4, #8",
                "p3p_wr_hi:",
                "cmp r0, r2",
                "blt p3p_wr_lo",
                "subs r0, r0, r1",
                "subs r4, #1",
                "bne p3p_wr_hi",
                "b p3p_wr_done",
                "p3p_wr_lo:",
                "cmp r0, r3",
                "bge p3p_wr_done",
                "adds r0, r0, r1",
                "subs r4, #1",
                "bne p3p_wr_lo",
                "p3p_wr_done:",
                "pop {r4}",
                "p3p_wr_ret:",
                "bx lr",

                # int32_t p3p_clamp_s8(r0=val) -> [-127, 127]
                "p3p_clamp_s8:",
                "cmp r0, #127",
                "ble p3p_c8_lo",
                "movs r0, #127",
                "bx lr",
                "p3p_c8_lo:",
                "ldr r1, =-127",
                "cmp r0, r1",
                "bge p3p_c8_ok",
                "mov r0, r1",
                "p3p_c8_ok:",
                "bx lr",

                # Entry capture at 0x008842 (before 0x01DF40 sensor poll jitter)
                "p3p_irq9_entry_capture:",
                f"ldr r1, ={T.MMIO_TIMER1_BASE:#x}",
                "movs r0, #1",
                "str r0, [r1, #0x48]",
                "movs r0, #0",
                "str.w r0, [r1, #0x140]",
                "bx lr",
            ]
        ),

        # void p3_flash_pause_hook(r0) - replaces bl 0x01F6F0 at 0x00F2D8
        "p3_flash_pause_hook:",
        "push {r4, lr}",
        f"bl {T.FN_TIMER_PAUSE:#x}",
        f"ldr r4, ={p3_base:#x}",
        "mrs r12, primask",
        "cpsid i",
        "movs r0, #1",
        f"strb r0, [r4, #{D.OFF_IN_FLASH_OP}]",
        "movs r0, #2",
        f"strb r0, [r4, #{D.OFF_PLOCK_PHASE_STATE}]",
        f"ldr r0, [r4, #{D.DIAG_OFFSETS['flash_pauses']}]",
        "adds r0, #1",
        f"str r0, [r4, #{D.DIAG_OFFSETS['flash_pauses']}]",
        "msr primask, r12",
        "pop {r4, pc}",

        # void p3_flash_resume_hook(r0, r1) - replaces bl 0x01F71C at 0x00F2FE
        "p3_flash_resume_hook:",
        "push {r4, r5, r6, lr}",
        "mov r5, r0",
        "mov r6, r1",
        f"ldr r4, ={p3_base:#x}",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r2, [r4, #{D.OFF_P3_FLAGS}]",
        f"tst.w r2, #{D.P3_FLAG_PLOCK_ENABLE}",
        "beq p3_fr_call",
        f"ldrh r3, [r4, #{D.OFF_PLOCK_PERIOD_US}]",
        "cbz r3, p3_fr_call",
        "mov r6, r3",
        "p3_fr_call:",
        "msr primask, r12",
        "mov r0, r5",
        "mov r1, r6",
        f"bl {T.FN_TIMER_RESUME:#x}",
        "mrs r12, primask",
        "cpsid i",
        "movs r0, #0",
        f"strb r0, [r4, #{D.OFF_IN_FLASH_OP}]",
        f"ldr r1, [r4, #{D.OFF_P3_FLAGS}]",
        f"tst.w r1, #{D.P3_FLAG_PLOCK_ENABLE}",
        "bne p3_fr_resync",
        f"strb r0, [r4, #{D.OFF_PLOCK_PHASE_STATE}]",
        "b p3_fr_done",
        "p3_fr_resync:",
        f"ldrh r1, [r4, #{D.OFF_PLOCK_PERIOD_US}]",
        f"ldrh r2, [r4, #{D.OFF_PLOCK_LEAD_US}]",
        "subs r2, r1, r2",
        "cmp r2, #20",
        "bge p3_fr_wr",
        "movs r2, #20",
        "p3_fr_wr:",
        f"ldr r3, ={T.MMIO_TIMER1_BASE:#x}",
        "str.w r1, [r3, #0x540]",
        "str.w r2, [r3, #0x544]",
        f"strh r1, [r4, #{D.OFF_PLOCK_LAST_CC0}]",
        f"strh r2, [r4, #{D.OFF_PLOCK_LAST_CC1}]",
        "movs r0, #1",
        f"strb r0, [r4, #{D.OFF_PLOCK_PHASE_STATE}]",
        f"ldr r0, [r4, #{D.DIAG_OFFSETS['plock_resets']}]",
        "adds r0, #1",
        f"str r0, [r4, #{D.DIAG_OFFSETS['plock_resets']}]",
        "p3_fr_done:",
        *(
            [
                "movs r0, #0",
                f"strb.w r0, [r4, #{D.OFF_PLOCK_OUTLIER_VALID}]",
            ]
            if phase3plus
            else []
        ),
        "msr primask, r12",
        "pop {r4, r5, r6, pc}",
        ".ltorg",
    ]

    export_labels = [
        "p3_irq9_stationary_hook",
        "p3_irq9_plock_hook",
        "p3_flash_pause_hook",
        "p3_flash_resume_hook",
    ]
    if phase3plus:
        export_labels.append("p3p_irq9_entry_capture")

    base = ctx.alloc_asm(
        "phase3_plock_core",
        code_lines,
        align=4,
        export_labels=tuple(export_labels),
        module="phase3_plock",
        reason="TIMER1 bounded phase-lock + flash pause/resume sync + stationary tracking",
    )

    if phase3plus:
        entry_cap_addr = builder.symbols["p3p_irq9_entry_capture"]
        bl_entry = encode_bl(T.HOOK_P3P_IRQ9_ENTRY_CLEAR, entry_cap_addr)
        ctx.branch_patches.append(
            verify_branch_patch(
                bl_entry,
                T.HOOK_P3P_IRQ9_ENTRY_CLEAR,
                "bl",
                entry_cap_addr,
            )
        )
        builder.edit(
            T.HOOK_P3P_IRQ9_ENTRY_CLEAR,
            bl_entry + b"\x00\xbf",
            expected_old=T.P3PLUS_PREIMAGES["p3p_irq9_entry_clear"].expected,
            module="phase3_plock",
            reason="Capture TIMER1->CC[2] at IRQ9 entry (0x008842) before 0x01DF40 poll latency",
        )

    ctx.patch_bl(
        T.HOOK_P3_IRQ9_STAT,
        builder.symbols["p3_irq9_stationary_hook"],
        expected_old=T.P3_PREIMAGES["p3_irq9_stationary"].expected,
        module="phase3_plock",
        reason="IRQ9 stationary/active tracker hook at 0x00887E",
    )
    ctx.patch_bl(
        T.HOOK_P3_IRQ9_PLOCK,
        builder.symbols["p3_irq9_plock_hook"],
        expected_old=T.P3_PREIMAGES["p3_irq9_plock"].expected,
        module="phase3_plock",
        reason="IRQ9 TIMER1 plock hook at 0x008882",
    )
    ctx.patch_bl(
        T.HOOK_P3_FLASH_PAUSE_TIMER,
        builder.symbols["p3_flash_pause_hook"],
        expected_old=T.P3_PREIMAGES["p3_flash_pause_timer"].expected,
        module="phase3_plock",
        reason="Flash RF/timer pause hook at 0x00F2D8",
    )
    ctx.patch_bl(
        T.HOOK_P3_FLASH_RESUME_TIMER,
        builder.symbols["p3_flash_resume_hook"],
        expected_old=T.P3_PREIMAGES["p3_flash_resume_timer"].expected,
        module="phase3_plock",
        reason="Flash RF/timer resume hook at 0x00F2FE",
    )

    return {
        "enabled": True,
        "base": f"0x{base:08X}",
        "irq9_stationary_hook": f"0x{builder.symbols['p3_irq9_stationary_hook']:08X}",
        "irq9_plock_hook": f"0x{builder.symbols['p3_irq9_plock_hook']:08X}",
        "flash_pause_hook": f"0x{builder.symbols['p3_flash_pause_hook']:08X}",
        "flash_resume_hook": f"0x{builder.symbols['p3_flash_resume_hook']:08X}",
    }
