"""Phase 4 Dual-MCU u16 ABS, session epoch/seq dedup, saturation clamping, and queue coalescing.

Implements paired fixes across both receiver MCUs within their verified tail caves:
  - nRF52820 2.4G MCU (`install_2g4`):
      * `0x0000945C` (`queue_init_3` tail): bump non-zero session epoch (1..63), reset
        ABS anchor, pending deltas, prefetch flag, and sequence counter (`RAD_OFF_*`).
      * `0x0000CA50` (`rf_motion_decode`): capture RF header byte `b0` (`RAD_OFF_LAST_RF_B0`).
      * `0x0000CB5A` (`dual_sample_merge`): when `type 0x0A` (`b0 & 8 != 0`), select latest
        sample instead of summing two absolutes; when relative (`type 2`), perform signed
        32-bit accumulation clamped cleanly to `[-32768, 32767]` (`RAD_OFF_DIAG_SAT_CLAMPS`).
      * All 5 `queue2` push calls (`0x0000CBC4`, `0x0000CBF2`, `0x0000CC3C`, `0x0000CC8E`,
        `0x0000CCBA`): convert `u16 ABS` (`type 0x0A`) to signed delta with `0x4000` jump
        guard, attach Phase 4 10-byte SPI trailer `buf[8..9]` (`0x40` tag, 6-bit epoch,
        4-bit seq, epoch_reset flag), and coalesce `(pend_dx, pend_dy)` whenever `queue2`
        push returns full (`0`).
  - AT32F405 USB MCU (`install_usb`):
      * `0x08008852` (`usb_spi_parse` motion branch): verify stock checksum (`0x08007518`),
        decode Phase 4 trailer `buf[8..9]` for `(epoch, seq)` deduplication & optional
        `is_abs=1` fallback diffing (`P4_ABS_JUMP_LIMIT = 0x4000`), and coalesce
        `(USB_OFF_PEND_DX, USB_OFF_PEND_DY)` whenever `queue0` is full (`0x08008C00`).
      * `0x080084EE` & `0x08008502` (`usb_ep81_pump`): count clean `queue0` commits and
        fix the stock busy bug at `0x08008502` so `USB_RAM_EP81_BUSY_64` (`0x20000064`)
        is NOT falsely set when `ep81_in_submit` (`0x08009E0C`) returns busy.
"""

from __future__ import annotations

from typing import Any

from fenrir.patcher import target_receiver as T
from fenrir.patcher.thumb import PatchContext


def ensure_usb_ram_helper(ctx: PatchContext) -> list[str]:
    """Return asm lines defining `p4_usb_ram_ensure` if not already emitted."""
    if "p4_usb_ram_ensure" in ctx.builder.symbols:
        return []
    usb_ram = T.RX_USB_RAM_BASE
    return [
        "p4_usb_ram_ensure:",
        f"ldr r0, ={usb_ram:#x}",
        "ldr r1, [r0, #0]",
        "mov r12, r2",
        f"ldr r2, ={T.P4_MAGIC_U32:#x}",
        "cmp r1, r2",
        "beq p4u_ram_ready",
        "push {r3}",
        "str r2, [r0, #0]",
        "mov r2, r0",
        "adds r2, #4",
        "movs r1, #0",
        f"movs r3, #{(T.RX_USB_RAM_BYTES // 4) - 1}",
        "p4u_ram_zero:",
        "stmia r2!, {r1}",
        "subs r3, #1",
        "bne p4u_ram_zero",
        "pop {r3}",
        "p4u_ram_ready:",
        "mov r2, r12",
        "bx lr",
    ]


def ensure_rad_ram_helper(ctx: PatchContext) -> list[str]:
    """Return asm lines defining `p4_rad_ram_ensure` if not already emitted."""
    if "p4_rad_ram_ensure" in ctx.builder.symbols:
        return []
    rad_ram = T.RX_2G4_RAM_BASE
    return [
        "p4_rad_ram_ensure:",
        f"ldr r0, ={rad_ram:#x}",
        "ldr r1, [r0, #0]",
        "mov r12, r2",
        f"ldr r2, ={T.P4_MAGIC_U32:#x}",
        "cmp r1, r2",
        "beq p4r_ram_check_ep",
        "push {r3}",
        "str r2, [r0, #0]",
        "mov r2, r0",
        "adds r2, #4",
        "movs r1, #0",
        f"movs r3, #{(T.RX_2G4_RAM_BYTES // 4) - 1}",
        "p4r_ram_zero:",
        "stmia r2!, {r1}",
        "subs r3, #1",
        "bne p4r_ram_zero",
        "movs r1, #1",
        f"strb r1, [r0, #{T.RAD_OFF_SESSION_EPOCH}]",
        "pop {r3}",
        "mov r2, r12",
        "bx lr",
        "p4r_ram_check_ep:",
        "mov r2, r12",
        f"ldrb r1, [r0, #{T.RAD_OFF_SESSION_EPOCH}]",
        "cmp r1, #0",
        "bne p4r_ram_ready",
        "movs r1, #1",
        f"strb r1, [r0, #{T.RAD_OFF_SESSION_EPOCH}]",
        "p4r_ram_ready:",
        "bx lr",
    ]


def install_usb(ctx: PatchContext) -> dict[str, Any]:
    """Install AT32F405 Phase 4 SPI ABS/epoch/dedup/coalescing & EP81 busy watchdog fix."""
    builder = ctx.builder
    for key in ("usb_spi_parse_motion", "usb_ep81_commit", "usb_ep81_busy_fix"):
        spec = T.RX_USB_PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)

    need_ram_ensure = "p4_usb_ram_ensure" not in builder.symbols
    code_lines: list[str] = ensure_usb_ram_helper(ctx) + [
        # (r0 = clamped_s16_in_s32, r1 = was_clamped) p4_usb_clamp_s16(r0 = s32 val)
        "p4_usb_clamp_s16:",
        "ldr r2, =32767",
        "cmp r0, r2",
        "ble p4u_cl_chk_lo",
        "mov r0, r2",
        "movs r1, #1",
        "bx lr",
        "p4u_cl_chk_lo:",
        "ldr r2, =-32768",
        "cmp r0, r2",
        "bge p4u_cl_ok",
        "mov r0, r2",
        "movs r1, #1",
        "bx lr",
        "p4u_cl_ok:",
        "movs r1, #0",
        "bx lr",

        # void p4_usb_spi_motion(void) - called from 0x08008852 inside usb_spi_parse
        "p4_usb_spi_motion:",
        "push {r4, r5, r6, r7, lr}",
        "sub sp, #8",
        "bl p4_usb_ram_ensure",
        "mov r4, r0",
        f"ldr r5, ={T.USB_RAM_SPI_RX_BUF:#x}",
        "adds r0, r5, #1",
        "movs r1, #6",
        f"bl {T.USB_FN_CHECKSUM_U8:#x}",
        "ldrb r1, [r5, #7]",
        "cmp r0, r1",
        "beq p4u_csum_ok",
        "p4u_csum_fail:",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r0, [r4, #{T.USB_OFF_DIAG_CSUM_ERR}]",
        "adds r0, #1",
        f"str r0, [r4, #{T.USB_OFF_DIAG_CSUM_ERR}]",
        "msr primask, r12",
        "b p4u_done",

        "p4u_csum_ok:",
        # Check Phase 4 SPI trailer tag: (buf[9] & 0xC0) == 0x40
        "ldrb r6, [r5, #9]",
        "ubfx r0, r6, #6, #2",
        "cmp r0, #1",
        "beq p4u_tagged",
        "movs r3, #0",
        "b p4u_decode_coords",

        "p4u_tagged:",
        "ldrb r7, [r5, #8]",
        "lsrs r0, r7, #4",
        "ubfx r1, r6, #2, #2",
        "lsls r1, r1, #4",
        "orrs r0, r1",
        "cmp r0, #0",
        "beq p4u_csum_fail",
        "ubfx r1, r7, #0, #4",
        f"ldrb r2, [r4, #{T.USB_OFF_LAST_EPOCH}]",
        "cmp r0, r2",
        "beq p4u_same_epoch",
        f"strb r0, [r4, #{T.USB_OFF_LAST_EPOCH}]",
        "movs r3, #0",
        f"strb r3, [r4, #{T.USB_OFF_ABS_VALID}]",
        "movs r3, #0xff",
        f"strb r3, [r4, #{T.USB_OFF_LAST_SEQ}]",
        f"ldr r2, [r4, #{T.USB_OFF_DIAG_EPOCH_CHG}]",
        "adds r2, #1",
        f"str r2, [r4, #{T.USB_OFF_DIAG_EPOCH_CHG}]",
        "p4u_same_epoch:",
        f"ldrb r2, [r4, #{T.USB_OFF_LAST_SEQ}]",
        "cmp r1, r2",
        "bne p4u_not_dup",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r0, [r4, #{T.USB_OFF_DIAG_DEDUP}]",
        "adds r0, #1",
        f"str r0, [r4, #{T.USB_OFF_DIAG_DEDUP}]",
        "msr primask, r12",
        "b p4u_done",

        "p4u_not_dup:",
        f"strb r1, [r4, #{T.USB_OFF_LAST_SEQ}]",
        "ubfx r0, r6, #1, #1",
        "cmp r0, #0",
        "beq p4u_no_ep_rst",
        "movs r3, #0",
        f"strb r3, [r4, #{T.USB_OFF_ABS_VALID}]",
        "p4u_no_ep_rst:",
        "ubfx r3, r6, #0, #1",

        # r3 = is_abs (0 = relative delta, 1 = u16 ABS)
        "p4u_decode_coords:",
        "ldrb r6, [r5, #3]",
        "ldrb r0, [r5, #4]",
        "lsls r0, r0, #8",
        "orrs r6, r0",
        "ldrb r7, [r5, #5]",
        "ldrb r0, [r5, #6]",
        "lsls r0, r0, #8",
        "orrs r7, r0",
        "cmp r3, #0",
        "bne p4u_abs_coords",

        "movs r0, #0",
        f"strb r0, [r4, #{T.USB_OFF_ABS_VALID}]",
        "sxth r6, r6",
        "sxth r7, r7",
        "b p4u_coalesce_push",

        "p4u_abs_coords:",
        f"ldrb r0, [r4, #{T.USB_OFF_ABS_VALID}]",
        "cmp r0, #0",
        "bne p4u_abs_diff",
        "movs r0, #1",
        f"strb r0, [r4, #{T.USB_OFF_ABS_VALID}]",
        f"strh r6, [r4, #{T.USB_OFF_ACC_X}]",
        f"strh r7, [r4, #{T.USB_OFF_ACC_Y}]",
        "movs r6, #0",
        "movs r7, #0",
        "b p4u_coalesce_push",

        "p4u_abs_diff:",
        f"ldrh r0, [r4, #{T.USB_OFF_ACC_X}]",
        f"ldrh r1, [r4, #{T.USB_OFF_ACC_Y}]",
        f"strh r6, [r4, #{T.USB_OFF_ACC_X}]",
        f"strh r7, [r4, #{T.USB_OFF_ACC_Y}]",
        "subs r2, r6, r0",
        "sxth r2, r2",
        "subs r3, r7, r1",
        "sxth r3, r3",
        f"ldr r0, ={T.P4_ABS_JUMP_LIMIT:#x}",
        "cmp r2, r0",
        "bge p4u_abs_jump",
        "cmp r3, r0",
        "bge p4u_abs_jump",
        f"ldr r0, =-{T.P4_ABS_JUMP_LIMIT:#x}",
        "cmp r2, r0",
        "ble p4u_abs_jump",
        "cmp r3, r0",
        "ble p4u_abs_jump",
        "mov r6, r2",
        "mov r7, r3",
        "b p4u_coalesce_push",

        "p4u_abs_jump:",
        "movs r6, #0",
        "movs r7, #0",

        # r6 = s32 dx, r7 = s32 dy
        "p4u_coalesce_push:",
        f"ldr r0, [r4, #{T.USB_OFF_PEND_DX}]",
        "adds r6, r6, r0",
        f"ldr r0, [r4, #{T.USB_OFF_PEND_DY}]",
        "adds r7, r7, r0",
        "ldrb r0, [r5, #1]",
        "strb.w r0, [sp, #0]",
        "ldrb r0, [r5, #2]",
        "strb.w r0, [sp, #1]",
        "mov r0, r6",
        "bl p4_usb_clamp_s16",
        "strh.w r0, [sp, #2]",
        "subs r6, r6, r0",
        "mov r0, r7",
        "bl p4_usb_clamp_s16",
        "strh.w r0, [sp, #4]",
        "subs r7, r7, r0",
        "movs r0, #0",
        "mov r1, sp",
        "movs r2, #6",
        f"bl {T.USB_FN_QUEUE_PUSH:#x}",
        "cmp r0, #0",
        "beq p4u_q0_full",
        f"str r6, [r4, #{T.USB_OFF_PEND_DX}]",
        f"str r7, [r4, #{T.USB_OFF_PEND_DY}]",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r0, [r4, #{T.USB_OFF_DIAG_Q0_OK}]",
        "adds r0, #1",
        f"str r0, [r4, #{T.USB_OFF_DIAG_Q0_OK}]",
        "msr primask, r12",
        "b p4u_done",

        "p4u_q0_full:",
        "ldrh.w r0, [sp, #2]",
        "sxth r0, r0",
        "adds r6, r6, r0",
        "ldrh.w r1, [sp, #4]",
        "sxth r1, r1",
        "adds r7, r7, r1",
        f"str r6, [r4, #{T.USB_OFF_PEND_DX}]",
        f"str r7, [r4, #{T.USB_OFF_PEND_DY}]",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r0, [r4, #{T.USB_OFF_DIAG_Q0_FULL}]",
        "adds r0, #1",
        f"str r0, [r4, #{T.USB_OFF_DIAG_Q0_FULL}]",
        "msr primask, r12",

        "p4u_done:",
        "add sp, #8",
        "pop {r4, r5, r6, r7, pc}",

        # void p4_usb_ep81_commit_ok(void) - called from 0x080084EE
        "p4_usb_ep81_commit_ok:",
        "push {r4, lr}",
        "movs r0, #0",
        f"bl {T.USB_FN_QUEUE_COMMIT:#x}",
        "bl p4_usb_ram_ensure",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, [r0, #{T.USB_OFF_DIAG_EP81_COMMIT}]",
        "adds r1, #1",
        f"str r1, [r0, #{T.USB_OFF_DIAG_EP81_COMMIT}]",
        "msr primask, r12",
        "pop {r4, pc}",

        # void p4_usb_ep81_busy_fix(void) - leaves 0x20000064 untouched (0) on busy!
        "p4_usb_ep81_busy_fix:",
        "push {r4, lr}",
        "movs r0, #0",
        f"ldr r1, ={T.USB_RAM_EP81_WD_CNT:#x}",
        "strh r0, [r1]",
        "bl p4_usb_ram_ensure",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, [r0, #{T.USB_OFF_DIAG_EP81_BUSY}]",
        "adds r1, #1",
        f"str r1, [r0, #{T.USB_OFF_DIAG_EP81_BUSY}]",
        "msr primask, r12",
        "pop {r4, pc}",
        ".ltorg",
    ]

    export_labels = [
        "p4_usb_clamp_s16",
        "p4_usb_spi_motion",
        "p4_usb_ep81_commit_ok",
        "p4_usb_ep81_busy_fix",
    ]
    if need_ram_ensure:
        export_labels.insert(0, "p4_usb_ram_ensure")

    base = ctx.alloc_asm(
        "phase4_usb_abs_core",
        code_lines,
        align=4,
        export_labels=tuple(export_labels),
        module="phase4_abs",
        reason="AT32F405 Phase 4 SPI ABS/epoch/dedup/coalescing & EP81 watchdog fix",
    )

    T.patch_inline(
        ctx,
        T.USB_HOOK_SPI_PARSE_MOTION,
        T.RX_USB_PREIMAGES["usb_spi_parse_motion"].expected,
        ["bl p4_usb_spi_motion"],
        name="usb_spi_parse_motion_p4",
        module="phase4_abs",
        reason="Hook usb_spi_parse motion packet through Phase 4 ABS/epoch/dedup/coalescing",
    )
    T.patch_inline(
        ctx,
        T.USB_HOOK_EP81_COMMIT,
        T.RX_USB_PREIMAGES["usb_ep81_commit"].expected,
        ["bl p4_usb_ep81_commit_ok"],
        name="usb_ep81_commit_counted",
        module="phase4_abs",
        reason="Commit queue0 cleanly and track EP81 commit diagnostic counter",
    )
    T.patch_inline(
        ctx,
        T.USB_HOOK_EP81_BUSY_FIX,
        T.RX_USB_PREIMAGES["usb_ep81_busy_fix"].expected,
        ["bl p4_usb_ep81_busy_fix"],
        name="usb_ep81_busy_watchdog_fix",
        module="phase4_abs",
        reason="Keep 0x20000064 untouched on EP81 busy to eliminate 5-SOF queue0 stall",
    )

    return {
        "enabled": True,
        "code_base": f"0x{base:08X}",
        "symbols": {k: f"0x{builder.symbols[k]:08X}" for k in export_labels},
    }


def install_2g4(ctx: PatchContext) -> dict[str, Any]:
    """Install nRF52820 Phase 4 epoch reset, type 0x0A ABS diff, saturation merge & queue2 coalescing."""
    builder = ctx.builder
    for key in (
        "rad_queue_init3_tail",
        "rad_capture_rf_b0",
        "rad_dual_merge_sat",
        "rad_q2_push_merged",
        "rad_q2_push_m0",
        "rad_q2_push_s0",
        "rad_q2_push_s1",
        "rad_q2_push_s00",
    ):
        spec = T.RX_2G4_PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)

    need_ram_ensure = "p4_rad_ram_ensure" not in builder.symbols
    code_lines: list[str] = ensure_rad_ram_helper(ctx) + [
        # (r0 = clamped_s16_in_s32, r1 = was_clamped) p4_rad_clamp_s16(r0 = s32 val)
        "p4_rad_clamp_s16:",
        "ldr r2, =32767",
        "cmp r0, r2",
        "ble p4r_cl_lo",
        "mov r0, r2",
        "movs r1, #1",
        "bx lr",
        "p4r_cl_lo:",
        "ldr r2, =-32768",
        "cmp r0, r2",
        "bge p4r_cl_ok",
        "mov r0, r2",
        "movs r1, #1",
        "bx lr",
        "p4r_cl_ok:",
        "movs r1, #0",
        "bx lr",

        # void p4_rad_queue_reset_epoch(void) - replaces 0x0000945C..0x00009465
        "p4_rad_queue_reset_epoch:",
        "push {r4, lr}",
        "movs r0, #0",
        f"ldr r1, ={T.RAD_RAM_TOGGLE_0:#x}",
        "strb r0, [r1]",
        f"ldr r1, ={T.RAD_RAM_TOGGLE_1:#x}",
        "strb r0, [r1]",
        "bl p4_rad_ram_ensure",
        "mrs r12, primask",
        "cpsid i",
        f"ldrb r1, [r0, #{T.RAD_OFF_SESSION_EPOCH}]",
        "adds r1, #1",
        "cmp r1, #64",
        "blt p4r_ep_ok",
        "movs r1, #1",
        "p4r_ep_ok:",
        f"strb r1, [r0, #{T.RAD_OFF_SESSION_EPOCH}]",
        "movs r1, #1",
        f"strb r1, [r0, #{T.RAD_OFF_EPOCH_RESET_PEND}]",
        "movs r1, #0",
        f"strb r1, [r0, #{T.RAD_OFF_ABS_VALID}]",
        f"strb r1, [r0, #{T.RAD_OFF_TX_SEQ}]",
        f"strb r1, [r0, #{T.RAD_OFF_Q2_PREFETCHED}]",
        f"str r1, [r0, #{T.RAD_OFF_PEND_DX}]",
        f"str r1, [r0, #{T.RAD_OFF_PEND_DY}]",
        f"ldr r2, [r0, #{T.RAD_OFF_DIAG_EPOCH_RST}]",
        "adds r2, #1",
        f"str r2, [r0, #{T.RAD_OFF_DIAG_EPOCH_RST}]",
        "msr primask, r12",
        "pop {r4, pc}",

        # uint32_t p4_rad_capture_rf_b0(r0 = b0) -> saves b0 & returns b0 unchanged
        "p4_rad_capture_rf_b0:",
        "push {r4, lr}",
        "mov r4, r0",
        "bl p4_rad_ram_ensure",
        f"strb r4, [r0, #{T.RAD_OFF_LAST_RF_B0}]",
        "mov r0, r4",
        "pop {r4, pc}",

        # (r0 = x_s16, r1 = y_s16) p4_rad_merge_sat_xy(void) - called at 0x0000CB5A
        "p4_rad_merge_sat_xy:",
        "push {r4, r5, r6, lr}",
        "bl p4_rad_ram_ensure",
        f"ldr r4, ={T.RAD_RAM_MOTION_WORK:#x}",
        f"ldrb r1, [r0, #{T.RAD_OFF_LAST_RF_B0}]",
        "ubfx r1, r1, #3, #1",
        "cmp r1, #0",
        "beq p4r_merge_rel",
        # type 0x0A ABS: pick latest sample1 ([+6], [+8]), NEVER double absolutes
        "ldrh r0, [r4, #6]",
        "sxth r0, r0",
        "ldrh r1, [r4, #8]",
        "sxth r1, r1",
        "pop {r4, r5, r6, pc}",

        "p4r_merge_rel:",
        "mov r5, r0",
        "movs r6, #0",
        "ldrh r0, [r4, #2]",
        "sxth r0, r0",
        "ldrh r1, [r4, #6]",
        "sxth r1, r1",
        "adds r0, r0, r1",
        "bl p4_rad_clamp_s16",
        "orrs r6, r1",
        "mov r3, r0",
        "ldrh r0, [r4, #4]",
        "sxth r0, r0",
        "ldrh r1, [r4, #8]",
        "sxth r1, r1",
        "adds r0, r0, r1",
        "push {r3}",
        "bl p4_rad_clamp_s16",
        "orrs r6, r1",
        "mov r1, r0",
        "pop {r0}",
        "cmp r6, #0",
        "beq p4r_merge_done",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r2, [r5, #{T.RAD_OFF_DIAG_SAT_CLAMPS}]",
        "adds r2, #1",
        f"str r2, [r5, #{T.RAD_OFF_DIAG_SAT_CLAMPS}]",
        "msr primask, r12",
        "p4r_merge_done:",
        "pop {r4, r5, r6, pc}",

        # int p4_rad_q2_push_abs(r0=q, r1=frame8_ptr, r2=8)
        "p4_rad_q2_push_abs:",
        "movs r3, #0",
        "b p4r_push_common",

        # int p4_rad_q2_push_rel(r0=q, r1=frame8_ptr, r2=8) - zero-delta button frames
        "p4_rad_q2_push_rel:",
        "movs r3, #1",

        # core(r0=q, r1=frame8_ptr, r2=8, r3=force_rel)
        "p4r_push_common:",
        "push {r4, r5, r6, r7, lr}",
        "sub sp, #12",
        "mov r5, r1",
        "mov r7, r3",
        "bl p4_rad_ram_ensure",
        "mov r4, r0",

        # Load frame8 bytes[0..2] -> tx10[0..2]
        "ldrb r0, [r5, #0]",
        "strb.w r0, [sp, #0]",
        "ldrb r0, [r5, #1]",
        "strb.w r0, [sp, #1]",
        "ldrb r0, [r5, #2]",
        "strb.w r0, [sp, #2]",

        # Unpack u16 x, y from frame8[3..6]
        "ldrb r6, [r5, #3]",
        "ldrb r0, [r5, #4]",
        "lsls r0, r0, #8",
        "orrs r6, r0",
        "ldrb r2, [r5, #5]",
        "ldrb r0, [r5, #6]",
        "lsls r0, r0, #8",
        "orrs r2, r0",
        "mov r5, r2",

        # Check force_rel vs last_rf_b0 bit 3 (type 0x0A ABS)
        "cmp r7, #0",
        "bne p4r_as_rel",
        f"ldrb r0, [r4, #{T.RAD_OFF_LAST_RF_B0}]",
        "ubfx r0, r0, #3, #1",
        "cmp r0, #0",
        "bne p4r_as_abs",

        "p4r_as_rel:",
        "sxth r6, r6",
        "sxth r5, r5",
        "b p4r_coalesce",

        "p4r_as_abs:",
        f"ldrb r0, [r4, #{T.RAD_OFF_ABS_VALID}]",
        "cmp r0, #0",
        "bne p4r_abs_diff",
        "movs r0, #1",
        f"strb r0, [r4, #{T.RAD_OFF_ABS_VALID}]",
        f"strh r6, [r4, #{T.RAD_OFF_COMMIT_ABS_X}]",
        f"strh r5, [r4, #{T.RAD_OFF_COMMIT_ABS_Y}]",
        "movs r6, #0",
        "movs r5, #0",
        "b p4r_bump_abs_recov",

        "p4r_abs_diff:",
        f"ldrh r0, [r4, #{T.RAD_OFF_COMMIT_ABS_X}]",
        f"ldrh r1, [r4, #{T.RAD_OFF_COMMIT_ABS_Y}]",
        f"strh r6, [r4, #{T.RAD_OFF_COMMIT_ABS_X}]",
        f"strh r5, [r4, #{T.RAD_OFF_COMMIT_ABS_Y}]",
        "subs r2, r6, r0",
        "sxth r2, r2",
        "subs r3, r5, r1",
        "sxth r3, r3",
        f"ldr r0, ={T.P4_ABS_JUMP_LIMIT:#x}",
        "cmp r2, r0",
        "bge p4r_abs_jump",
        "cmp r3, r0",
        "bge p4r_abs_jump",
        f"ldr r0, =-{T.P4_ABS_JUMP_LIMIT:#x}",
        "cmp r2, r0",
        "ble p4r_abs_jump",
        "cmp r3, r0",
        "ble p4r_abs_jump",
        "mov r6, r2",
        "mov r5, r3",
        "b p4r_bump_abs_recov",

        "p4r_abs_jump:",
        "movs r6, #0",
        "movs r5, #0",

        "p4r_bump_abs_recov:",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r0, [r4, #{T.RAD_OFF_DIAG_ABS_RECOV}]",
        "adds r0, #1",
        f"str r0, [r4, #{T.RAD_OFF_DIAG_ABS_RECOV}]",
        "msr primask, r12",

        # r6 = dx (s32), r5 = dy (s32)
        "p4r_coalesce:",
        f"ldr r0, [r4, #{T.RAD_OFF_PEND_DX}]",
        "adds r6, r6, r0",
        f"ldr r0, [r4, #{T.RAD_OFF_PEND_DY}]",
        "adds r5, r5, r0",
        "mov r0, r6",
        "bl p4_rad_clamp_s16",
        "strb.w r0, [sp, #3]",
        "lsrs r2, r0, #8",
        "strb.w r2, [sp, #4]",
        "subs r6, r6, r0",
        "mov r7, r1",
        "mov r0, r5",
        "bl p4_rad_clamp_s16",
        "strb.w r0, [sp, #5]",
        "lsrs r2, r0, #8",
        "strb.w r2, [sp, #6]",
        "subs r5, r5, r0",
        "orrs r7, r1",
        "cmp r7, #0",
        "beq p4r_no_cl_diag",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r0, [r4, #{T.RAD_OFF_DIAG_SAT_CLAMPS}]",
        "adds r0, #1",
        f"str r0, [r4, #{T.RAD_OFF_DIAG_SAT_CLAMPS}]",
        "msr primask, r12",

        "p4r_no_cl_diag:",
        "addw r0, sp, #1",
        "movs r1, #6",
        f"bl {T.RAD_FN_CHECKSUM_U8:#x}",
        "strb.w r0, [sp, #7]",

        # Build 2B Phase 4 SPI trailer:
        # tx10[8] = ((epoch & 0xF) << 4) | (seq & 0xF)
        # tx10[9] = 0x40 | ((epoch & 0x30) >> 2) | (epoch_reset_pend << 1)
        f"ldrb r0, [r4, #{T.RAD_OFF_SESSION_EPOCH}]",
        "ubfx r1, r0, #0, #4",
        "lsls r1, r1, #4",
        f"ldrb r2, [r4, #{T.RAD_OFF_TX_SEQ}]",
        "ubfx r2, r2, #0, #4",
        "orrs r1, r2",
        "strb.w r1, [sp, #8]",
        "ubfx r0, r0, #4, #2",
        "lsls r0, r0, #2",
        "movs r1, #0x40",
        "orrs r0, r1",
        f"ldrb r1, [r4, #{T.RAD_OFF_EPOCH_RESET_PEND}]",
        "lsls r1, r1, #1",
        "orrs r0, r1",
        "strb.w r0, [sp, #9]",

        "movs r0, #2",
        "mov r1, sp",
        "movs r2, #10",
        f"bl {T.RAD_FN_QUEUE_PUSH:#x}",
        "cmp r0, #0",
        "beq p4r_q2_full",

        # Success: store remaining (rem_dx, rem_dy), advance seq, clear epoch_reset_pend
        f"str r6, [r4, #{T.RAD_OFF_PEND_DX}]",
        f"str r5, [r4, #{T.RAD_OFF_PEND_DY}]",
        "movs r1, #0",
        f"strb r1, [r4, #{T.RAD_OFF_EPOCH_RESET_PEND}]",
        "mrs r12, primask",
        "cpsid i",
        f"ldrb r1, [r4, #{T.RAD_OFF_TX_SEQ}]",
        "adds r1, #1",
        "ubfx r1, r1, #0, #4",
        f"strb r1, [r4, #{T.RAD_OFF_TX_SEQ}]",
        f"ldr r2, [r4, #{T.RAD_OFF_DIAG_Q2_OK}]",
        "adds r2, #1",
        f"str r2, [r4, #{T.RAD_OFF_DIAG_Q2_OK}]",
        "msr primask, r12",
        "movs r0, #1",
        "b p4r_push_done",

        "p4r_q2_full:",
        # Restore clamped tx10[3..6] + remainder -> pend_dx/dy
        "ldrb.w r0, [sp, #3]",
        "ldrb.w r1, [sp, #4]",
        "lsls r1, r1, #8",
        "orrs r0, r1",
        "sxth r0, r0",
        "adds r6, r6, r0",
        "ldrb.w r0, [sp, #5]",
        "ldrb.w r1, [sp, #6]",
        "lsls r1, r1, #8",
        "orrs r0, r1",
        "sxth r0, r0",
        "adds r5, r5, r0",
        f"str r6, [r4, #{T.RAD_OFF_PEND_DX}]",
        f"str r5, [r4, #{T.RAD_OFF_PEND_DY}]",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r2, [r4, #{T.RAD_OFF_DIAG_Q2_SAVED}]",
        "adds r2, #1",
        f"str r2, [r4, #{T.RAD_OFF_DIAG_Q2_SAVED}]",
        "msr primask, r12",
        "movs r0, #0",

        "p4r_push_done:",
        "add sp, #12",
        "pop {r4, r5, r6, r7, pc}",
        ".ltorg",
    ]

    export_labels = [
        "p4_rad_clamp_s16",
        "p4_rad_queue_reset_epoch",
        "p4_rad_capture_rf_b0",
        "p4_rad_merge_sat_xy",
        "p4_rad_q2_push_abs",
        "p4_rad_q2_push_rel",
    ]
    if need_ram_ensure:
        export_labels.insert(0, "p4_rad_ram_ensure")

    base = ctx.alloc_asm(
        "phase4_2g4_abs_core",
        code_lines,
        align=4,
        export_labels=tuple(export_labels),
        module="phase4_abs",
        reason="nRF52820 Phase 4 epoch, type 0x0A ABS diff, saturation merge & queue2 coalescing",
    )

    T.patch_inline(
        ctx,
        T.RAD_HOOK_QUEUE_INIT_3_TAIL,
        T.RX_2G4_PREIMAGES["rad_queue_init3_tail"].expected,
        ["bl p4_rad_queue_reset_epoch"],
        name="rad_queue_init3_epoch",
        module="phase4_abs",
        reason="Bump non-zero session epoch and clear ABS baseline on queue reset",
    )
    T.patch_inline(
        ctx,
        T.RAD_HOOK_CAPTURE_RF_B0,
        T.RX_2G4_PREIMAGES["rad_capture_rf_b0"].expected,
        [
            "ldrb.w r0, [sp, #0x10]",
            "bl p4_rad_capture_rf_b0",
            "ubfx r6, r0, #3, #1",
            "asrs r5, r0, #4",
            "movs r4, #0xa",
        ],
        name="rad_capture_rf_b0_hook",
        module="phase4_abs",
        reason="Capture RF header byte b0 into RAD_OFF_LAST_RF_B0 while preserving r0, r4..r6",
    )
    T.patch_inline(
        ctx,
        T.RAD_HOOK_DUAL_MERGE_SAT,
        T.RX_2G4_PREIMAGES["rad_dual_merge_sat"].expected,
        ["bl p4_rad_merge_sat_xy"],
        name="rad_dual_merge_sat_hook",
        module="phase4_abs",
        reason="Clamp dual-sample REL sum to s16 and avoid adding type 0x0A absolutes",
    )

    for site, key, helper in (
        (T.RAD_HOOK_Q2_PUSH_MERGED, "rad_q2_push_merged", "p4_rad_q2_push_abs"),
        (T.RAD_HOOK_Q2_PUSH_S0, "rad_q2_push_s0", "p4_rad_q2_push_abs"),
        (T.RAD_HOOK_Q2_PUSH_S1, "rad_q2_push_s1", "p4_rad_q2_push_abs"),
        (T.RAD_HOOK_Q2_PUSH_M0, "rad_q2_push_m0", "p4_rad_q2_push_rel"),
        (T.RAD_HOOK_Q2_PUSH_S00, "rad_q2_push_s00", "p4_rad_q2_push_rel"),
    ):
        T.patch_inline(
            ctx,
            site,
            T.RX_2G4_PREIMAGES[key].expected,
            [f"bl {helper}"],
            name=f"{key}_p4",
            module="phase4_abs",
            reason=f"Route {key} through {helper} for 10B SPI trailer and queue2 coalescing",
        )

    return {
        "enabled": True,
        "code_base": f"0x{base:08X}",
        "symbols": {k: f"0x{builder.symbols[k]:08X}" for k in export_labels},
    }
