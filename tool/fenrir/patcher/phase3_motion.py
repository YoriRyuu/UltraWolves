"""Phase 3 atomic s16 motion accumulator, SPIM3 direct-motion toggle, and EP81 queue guard.

Fixes installed cleanly inside [0x00022A0C..0x00024FFF]:
  1. Producer hook (`SPIM3` at 0x01DEFE -> p3_spim3_hook -> 0x01DAD8):
     - Tracks `spim3_samples` and `spim3_motion` (0x2000324E bit7).
     - Implements `direct_motion` toggle (`P3_FLAG_DIRECT_MOTION`, default OFF = 0)
       with atomic `in_tx_owner` re-entrancy guard and `in_flash_op` deferral.
  2. Atomic `s16` snapshot (`PRIMASK` disabled read) + atomic subtract-only commit across
     all 4 consumers (`Wireless 0x017FD4`, `Wired USB 0x01828C`, `BLE 0x0199D4`, `IRQ20 0x01D150`):
     - Eliminates torn lo/hi byte reads in Wired/BLE and zero-wipe race loss when
       `SPIM3` fires between packet pack and post-TX commit.
     - Keeps `0x2000321A` bit2 (`|= 4`) when residual `cur - snap != 0` and records
       `diag.race_preserved += 1`.
  3. Wired `EP81` active-queue overwrite guard (`0x014582..0x01458D`):
     - When `EP81` (`0x000222AC`) reports busy (`r8 != 0`) and `P3_FLAG_QUEUE_GUARD` is ON
       (default ON), returns busy (`0x1461C -> 4 -> 0x00A3C4 -> 0x11`) so `p3_usb_post_tx`
       preserves deltas/buttons instead of overwriting active EP81 DMA buffers.
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
    """Assemble and Capstone-verify an inline replacement patch exact-sized to expected_old."""
    merged = dict(ctx.builder.symbols)
    if symbols:
        merged.update(symbols)
    blk = assemble(lines, site, name=name, symbols=merged, verify=True)
    if len(blk.data) > len(expected_old):
        raise ValueError(
            f"[{name}] Patch size {len(blk.data)} exceeds slot {len(expected_old)} at 0x{site:08X}"
        )
    pad_n = len(expected_old) - len(blk.data)
    if pad_n % 2 != 0:
        raise ValueError(f"[{name}] Odd NOP pad {pad_n} at 0x{site:08X}")
    if pad_n:
        lines_padded = list(lines) + ["nop"] * (pad_n // 2)
        blk = assemble(lines_padded, site, name=name, symbols=merged, verify=True)
    assert len(blk.data) == len(expected_old)
    ctx.builder.edit(site, blk.data, expected_old=expected_old, module="phase3_motion", reason=reason or name)
    ctx.blocks.append(blk)


def install(ctx: PatchContext) -> dict[str, Any]:
    """Install Phase 3 atomic accumulator, SPIM3 direct toggle, and EP81 guard hooks."""
    builder = ctx.builder
    for key in (
        "p3_spim3_call",
        "p3_wl_snap",
        "p3_wl_post_tx",
        "p3_usb_snap",
        "p3_usb_post_tx",
        "p3_ble_snap",
        "p3_ble_post_tx",
        "p3_ble_loop_call",
        "p3_irq20_snap",
        "p3_irq20_commit1",
        "p3_irq20_commit2",
        "p3_ep81_guard",
        "p3_ep81_desc",
        "fn_acc_accum_entry",
        "fn_wl_tx_clear_entry",
        "fn_usb_ep_unlock_a980",
        "fn_usb_ep_unlock_a98a",
        "fn_get_transport_mode",
        "fn_ble_loop_entry",
    ):
        spec = T.P3_PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)

    p3_base = T.PHASE3_RAM_BASE
    acc_diag_base = p3_base + D.OFF_DIAG_BASE

    code_lines: list[str] = [
        # (dx, dy) in (r0, r1) = p3_acc_snap(r0 = snap_offset in P3 RAM)
        "p3_acc_snap:",
        f"ldr r3, ={p3_base:#x}",
        "adds r0, r3, r0",
        f"ldr r2, ={T.RAM_DX_ACC:#x}",
        "mrs r12, primask",
        "cpsid i",
        "ldrh r1, [r2, #0]",
        "sxth r1, r1",
        "ldrh r2, [r2, #2]",
        "sxth r2, r2",
        "strh r1, [r0, #0]",
        "strh r2, [r0, #2]",
        "msr primask, r12",
        "mov r0, r1",
        "mov r1, r2",
        "bx lr",

        # void p3_acc_commit(r0 = snap_offset) - atomic subtract-only commit + diag
        "p3_acc_commit:",
        "push {r4, r5, r6}",
        f"ldr r3, ={p3_base:#x}",
        f"ldr r2, ={T.RAM_DX_ACC:#x}",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, [r3, #{D.OFF_P3_FLAGS}]",
        f"tst.w r1, #{D.P3_FLAG_ATOMIC_ACCUM}",
        "beq p3_cm_stock_wipe",
        "adds r0, r3, r0",
        "ldrh r1, [r0, #0]",
        "sxth r1, r1",
        "ldrh r4, [r0, #2]",
        "sxth r4, r4",
        "movs r5, #0",
        "str r5, [r0, #0]",
        "ldrh r5, [r2, #0]",
        "sxth r5, r5",
        "ldrh r6, [r2, #2]",
        "sxth r6, r6",
        "subs r5, r5, r1",
        "sxth r5, r5",
        "subs r6, r6, r4",
        "sxth r6, r6",
        "strh r5, [r2, #0]",
        "strh r6, [r2, #2]",
        "orrs r5, r6",
        "cmp r5, #0",
        "beq p3_cm_clr_bit2",
        # Residual delta exists -> keep 0x2000321A bit2 set & bump race_preserved
        f"ldr r0, ={T.RAM_MOTION_FLAGS:#x}",
        "ldrb r1, [r0, #0]",
        "orr.w r1, r1, #4",
        "strb r1, [r0, #0]",
        f"ldr r1, [r3, #{D.DIAG_OFFSETS['race_preserved']}]",
        "adds r1, #1",
        f"str r1, [r3, #{D.DIAG_OFFSETS['race_preserved']}]",
        "b p3_cm_tx_ok",
        "p3_cm_stock_wipe:",
        "adds r0, r3, r0",
        "movs r5, #0",
        "str r5, [r0, #0]",
        "strh r5, [r2, #0]",
        "strh r5, [r2, #2]",
        "p3_cm_clr_bit2:",
        f"ldr r0, ={T.RAM_MOTION_FLAGS:#x}",
        "ldrb r1, [r0, #0]",
        "bic.w r1, r1, #4",
        "strb r1, [r0, #0]",
        "p3_cm_tx_ok:",
        f"ldr r1, [r3, #{D.DIAG_OFFSETS['tx_ok']}]",
        "adds r1, #1",
        f"str r1, [r3, #{D.DIAG_OFFSETS['tx_ok']}]",
        "msr primask, r12",
        "pop {r4, r5, r6}",
        "bx lr",

        # Helper: set/clear thread TX owner bit (r0 != 0 -> |=2, r0 == 0 -> &=~2)
        "p3_set_thread_owner:",
        f"ldr r1, ={p3_base:#x}",
        "mrs r12, primask",
        "cpsid i",
        f"ldrb r2, [r1, #{D.OFF_IN_TX_OWNER}]",
        "cbz r0, p3_sto_clr",
        "orr.w r2, r2, #2",
        "b p3_sto_wr",
        "p3_sto_clr:",
        "bic.w r2, r2, #2",
        "p3_sto_wr:",
        f"strb r2, [r1, #{D.OFF_IN_TX_OWNER}]",
        "msr primask, r12",
        "bx lr",

        # void p3_wl_snap(void): pack WL [0x20008EAC+1, +5] atomically & mark thread owner
        "p3_wl_snap:",
        "push {r4, lr}",
        "movs r0, #1",
        "bl p3_set_thread_owner",
        f"movs r0, #{D.OFF_SNAP_WL}",
        "bl p3_acc_snap",
        f"ldr r2, ={T.RAM_WL_PKT:#x}",
        "strh.w r0, [r2, #1]",
        "strh.w r1, [r2, #5]",
        "pop {r4, pc}",

        # void p3_wl_post_tx(r0 = tx_status; 1 == ok)
        "p3_wl_post_tx:",
        "push {r4, lr}",
        "mov r4, r0",
        "movs r0, #0",
        "bl p3_set_thread_owner",
        "cmp r4, #1",
        "beq p3_wlp_ok",
        f"movs r0, #{D.OFF_SNAP_WL}",
        "b p3_post_busy",
        "p3_wlp_ok:",
        "movs r0, #0",
        f"ldr r1, ={T.RAM_BTN_FLAGS_3A4F:#x}",
        "strb r0, [r1, #0]",
        f"ldr r1, ={T.RAM_DEBOUNCE_HIST + 1:#x}",
        "str r0, [r1, #0]",
        "strh r0, [r1, #4]",
        "strb r0, [r1, #6]",
        "movs r0, #1",
        f"bl {T.FN_WL_TX_CLEAR:#x}",
        f"movs r0, #{D.OFF_SNAP_WL}",
        "bl p3_acc_commit",
        "pop {r4, pc}",

        # Shared busy tail (called with push {r4, lr} already active!): r0 = snap_offset
        "p3_post_busy:",
        f"ldr r1, ={p3_base:#x}",
        "mrs r12, primask",
        "cpsid i",
        "movs r2, #0",
        "str r2, [r1, r0]",
        f"ldr r2, [r1, #{D.DIAG_OFFSETS['tx_busy']}]",
        "adds r2, #1",
        f"str r2, [r1, #{D.DIAG_OFFSETS['tx_busy']}]",
        "msr primask, r12",
        "pop {r4, pc}",

        # void p3_usb_snap(void): pack HID [0x200040C2+2, +4] & preserve r1 == 0x200040C2
        "p3_usb_snap:",
        "push {r4, lr}",
        "movs r0, #1",
        "bl p3_set_thread_owner",
        f"movs r0, #{D.OFF_SNAP_USB}",
        "bl p3_acc_snap",
        f"ldr r2, ={T.RAM_HID_PKT:#x}",
        "strh r0, [r2, #2]",
        "strh r1, [r2, #4]",
        "mov r1, r2",
        "pop {r4, pc}",

        # void p3_usb_post_tx(r0 = r4 status; 0 == ok)
        "p3_usb_post_tx:",
        "push {r4, lr}",
        "mov r4, r0",
        "movs r0, #0",
        "bl p3_set_thread_owner",
        "cbz r4, p3_usbp_ok",
        f"movs r0, #{D.OFF_SNAP_USB}",
        "b p3_post_busy",
        "p3_usbp_ok:",
        "movs r0, #0",
        f"ldr r1, ={T.RAM_DEBOUNCE_HIST + 1:#x}",
        "str r0, [r1, #0]",
        "strh r0, [r1, #4]",
        "strb r0, [r1, #6]",
        f"ldr r1, ={T.RAM_BTN_FLAGS_3A4F:#x}",
        "strb r0, [r1, #0]",
        "strb r0, [r1, #1]",  # 0x20003A50 == 0x20003A4F + 1
        f"movs r0, #{D.OFF_SNAP_USB}",
        "bl p3_acc_commit",
        "movs r0, #0",
        f"bl {T.FN_USB_EP_UNLOCK_A980:#x}",
        "movs r0, #0",
        f"bl {T.FN_USB_EP_UNLOCK_A98A:#x}",
        "pop {r4, pc}",

        # void p3_ble_snap(void): pack BLE [0x200040C2+2, +4] & preserve r1 == 0x200040C2
        "p3_ble_snap:",
        "push {r4, lr}",
        f"movs r0, #{D.OFF_SNAP_BLE}",
        "bl p3_acc_snap",
        f"ldr r2, ={T.RAM_HID_PKT:#x}",
        "strh r0, [r2, #2]",
        "strh r1, [r2, #4]",
        "mov r1, r2",
        "pop {r4, pc}",

        # void p3_ble_post_tx(r0 = status; 0 == ok)
        "p3_ble_post_tx:",
        "push {r4, lr}",
        "cbz r0, p3_blep_ok",
        f"movs r0, #{D.OFF_SNAP_BLE}",
        "b p3_post_busy",
        "p3_blep_ok:",
        "movs r0, #0",
        f"ldr r1, ={T.RAM_BTN_FLAGS_3A4F:#x}",
        "strb r0, [r1, #0]",
        "strb r0, [r1, #1]",
        f"movs r0, #{D.OFF_SNAP_BLE}",
        "bl p3_acc_commit",
        "pop {r4, pc}",

        # void p3_irq20_snap(r0 = sp_ptr) -> stores dx -> [sp], dy -> [sp+2]
        "p3_irq20_snap:",
        "push {r4, lr}",
        "mov r4, r0",
        f"movs r0, #{D.OFF_SNAP_IRQ20}",
        "bl p3_acc_snap",
        "strh r0, [r4, #0]",
        "strh r1, [r4, #2]",
        "pop {r4, pc}",

        # void p3_irq20_commit(void)
        "p3_irq20_commit:",
        f"movs r0, #{D.OFF_SNAP_IRQ20}",
        "b p3_acc_commit",

        # uint32_t p3_ep81_guard(r0 = busy_from_14538, r1 = ep_desc) -> 1 abort to 0x1461C, 0 proceed
        "p3_ep81_guard:",
        "cbz r0, p3_ep_allow",
        "ldrb r2, [r1, #0x10]",
        "cmp r2, #0",
        "bne p3_ep_block_stock",
        f"ldr r2, ={T.EP81_DESC_ADDR:#x}",
        "cmp r1, r2",
        "bne p3_ep_allow",
        f"ldr r2, ={p3_base:#x}",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r3, [r2, #{D.OFF_P3_FLAGS}]",
        f"tst.w r3, #{D.P3_FLAG_QUEUE_GUARD}",
        "beq p3_ep_allow_irqs",
        f"ldr r3, [r2, #{D.DIAG_OFFSETS['ep81_drops_saved']}]",
        "adds r3, #1",
        f"str r3, [r2, #{D.DIAG_OFFSETS['ep81_drops_saved']}]",
        "msr primask, r12",
        "p3_ep_block_stock:",
        "movs r0, #1",
        "bx lr",
        "p3_ep_allow_irqs:",
        "msr primask, r12",
        "p3_ep_allow:",
        "movs r0, #0",
        "bx lr",

        # void p3_spim3_hook(r0 = 0x20008EC4 rx_buf) - replaces bl 0x01DAD8 at 0x01DEFE
        "p3_spim3_hook:",
        "push {r4, lr}",
        f"bl {T.FN_ACC_ACCUM:#x}",
        f"ldr r4, ={p3_base:#x}",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r0, [r4, #{D.DIAG_OFFSETS['spim3_samples']}]",
        "adds r0, #1",
        f"str r0, [r4, #{D.DIAG_OFFSETS['spim3_samples']}]",
        f"ldr r1, ={T.RAM_MOTION_STATUS:#x}",
        "ldrb r1, [r1, #0]",
        "tst.w r1, #0x80",
        "beq p3_sp_chk_dir",
        f"ldr r0, [r4, #{D.DIAG_OFFSETS['spim3_motion']}]",
        "adds r0, #1",
        f"str r0, [r4, #{D.DIAG_OFFSETS['spim3_motion']}]",
        "p3_sp_chk_dir:",
        f"ldr r0, [r4, #{D.OFF_P3_FLAGS}]",
        f"tst.w r0, #{D.P3_FLAG_DIRECT_MOTION}",
        "beq p3_sp_done_irqs",
        # Check if any accumulated motion / bit2 is pending before sending
        f"ldr r1, ={T.RAM_DX_ACC:#x}",
        "ldr r1, [r1, #0]",
        "cbnz r1, p3_sp_has_mot",
        f"ldr r1, ={T.RAM_MOTION_FLAGS:#x}",
        "ldrb r1, [r1, #0]",
        "tst.w r1, #4",
        "beq p3_sp_done_irqs",
        "p3_sp_has_mot:",
        # Re-entrancy and flash-pause guard
        f"ldrb r0, [r4, #{D.OFF_IN_TX_OWNER}]",
        f"ldrb r1, [r4, #{D.OFF_IN_FLASH_OP}]",
        "orrs r0, r1",
        "cbz r0, p3_sp_claim",
        f"ldr r0, [r4, #{D.DIAG_OFFSETS['direct_tx_deferred']}]",
        "adds r0, #1",
        f"str r0, [r4, #{D.DIAG_OFFSETS['direct_tx_deferred']}]",
        "b p3_sp_done_irqs",
        "p3_sp_claim:",
        f"ldrb r0, [r4, #{D.OFF_IN_TX_OWNER}]",
        "orr.w r0, r0, #1",
        f"strb r0, [r4, #{D.OFF_IN_TX_OWNER}]",
        "msr primask, r12",
        f"bl {T.FN_GET_TRANSPORT_MODE:#x}",
        "cbnz r0, p3_sp_try_wl",
        f"bl {T.FN_USB_MOTION_TX:#x}",
        "b p3_sp_rel",
        "p3_sp_try_wl:",
        "cmp r0, #1",
        "bne p3_sp_try_ble",
        f"bl {T.FN_WL_MOTION_TX:#x}",
        "b p3_sp_rel",
        "p3_sp_try_ble:",
        "cmp r0, #2",
        "bne p3_sp_rel",
        f"bl {T.FN_BLE_MOTION_TX:#x}",
        "p3_sp_rel:",
        "mrs r12, primask",
        "cpsid i",
        f"ldrb r0, [r4, #{D.OFF_IN_TX_OWNER}]",
        "bic.w r0, r0, #1",
        f"strb r0, [r4, #{D.OFF_IN_TX_OWNER}]",
        f"ldr r0, [r4, #{D.DIAG_OFFSETS['direct_tx_ok']}]",
        "adds r0, #1",
        f"str r0, [r4, #{D.DIAG_OFFSETS['direct_tx_ok']}]",
        "p3_sp_done_irqs:",
        "msr primask, r12",
        "pop {r4, pc}",

        # void p3_ble_thread_wrap(void) - replaces bl 0x0199D4 at 0x00B29A
        "p3_ble_thread_wrap:",
        "push {r4, lr}",
        "movs r0, #1",
        "bl p3_set_thread_owner",
        f"bl {T.FN_BLE_MOTION_TX:#x}",
        "movs r0, #0",
        "bl p3_set_thread_owner",
        "pop {r4, pc}",
        ".ltorg",
    ]

    base = ctx.alloc_asm(
        "phase3_motion_core",
        code_lines,
        align=4,
        export_labels=(
            "p3_acc_snap",
            "p3_acc_commit",
            "p3_wl_snap",
            "p3_wl_post_tx",
            "p3_usb_snap",
            "p3_usb_post_tx",
            "p3_ble_snap",
            "p3_ble_post_tx",
            "p3_irq20_snap",
            "p3_irq20_commit",
            "p3_ep81_guard",
            "p3_spim3_hook",
            "p3_ble_thread_wrap",
        ),
        module="phase3_motion",
        reason="Atomic s16 accumulator + SPIM3 direct toggle + EP81 overwrite guard",
    )

    # Install exact verified inline hooks in stock ROM
    ctx.patch_bl(
        T.HOOK_P3_SPIM3_CALL,
        builder.symbols["p3_spim3_hook"],
        expected_old=T.P3_PREIMAGES["p3_spim3_call"].expected,
        module="phase3_motion",
        reason="SPIM3 sample hook (0x01DEFE -> p3_spim3_hook -> 0x01DAD8)",
    )

    _patch_inline(
        ctx,
        T.HOOK_P3_WL_SNAP,
        T.P3_PREIMAGES["p3_wl_snap"].expected,
        ["bl p3_wl_snap", "b.w _wl_after_snap"],
        symbols={"_wl_after_snap": 0x0001807E},
        name="p3_wl_snap_hook",
        reason="Wireless atomic s16 snap hook at 0x018068",
    )
    _patch_inline(
        ctx,
        T.HOOK_P3_WL_POST_TX,
        T.P3_PREIMAGES["p3_wl_post_tx"].expected,
        ["bl p3_wl_post_tx", "b.w _wl_after_post"],
        symbols={"_wl_after_post": 0x0001811E},
        name="p3_wl_post_tx_hook",
        reason="Wireless atomic subtract post-TX hook at 0x0180EE",
    )

    _patch_inline(
        ctx,
        T.HOOK_P3_USB_SNAP,
        T.P3_PREIMAGES["p3_usb_snap"].expected,
        ["bl p3_usb_snap", "b.w _usb_after_snap"],
        symbols={"_usb_after_snap": 0x000182D8},
        name="p3_usb_snap_hook",
        reason="Wired USB atomic s16 snap hook at 0x0182BC (preserves r1=0x200040C2)",
    )
    _patch_inline(
        ctx,
        T.HOOK_P3_USB_POST_TX,
        T.P3_PREIMAGES["p3_usb_post_tx"].expected,
        ["mov r0, r4", "bl p3_usb_post_tx", "b.w _usb_after_post"],
        symbols={"_usb_after_post": 0x00018326},
        name="p3_usb_post_tx_hook",
        reason="Wired USB atomic subtract post-TX hook at 0x0182EE",
    )

    _patch_inline(
        ctx,
        T.HOOK_P3_BLE_SNAP,
        T.P3_PREIMAGES["p3_ble_snap"].expected,
        ["bl p3_ble_snap", "b.w _ble_after_snap"],
        symbols={"_ble_after_snap": 0x00019A4E},
        name="p3_ble_snap_hook",
        reason="BLE atomic s16 snap hook at 0x019A32 (preserves r1=0x200040C2)",
    )
    _patch_inline(
        ctx,
        T.HOOK_P3_BLE_POST_TX,
        T.P3_PREIMAGES["p3_ble_post_tx"].expected,
        ["bl p3_ble_post_tx", "b.w _ble_after_post"],
        symbols={"_ble_after_post": 0x00019A8E},
        name="p3_ble_post_tx_hook",
        reason="BLE atomic subtract post-TX hook at 0x019A6E",
    )

    _patch_inline(
        ctx,
        T.HOOK_P3_IRQ20_SNAP,
        T.P3_PREIMAGES["p3_irq20_snap"].expected,
        ["mov r0, sp", "bl p3_irq20_snap", "b.w _i20_after_snap"],
        symbols={"_i20_after_snap": 0x0001D1B4},
        name="p3_irq20_snap_hook",
        reason="IRQ20 atomic s16 snap hook at 0x01D1A0",
    )
    _patch_inline(
        ctx,
        T.HOOK_P3_IRQ20_COMMIT1,
        T.P3_PREIMAGES["p3_irq20_commit1"].expected,
        ["bl p3_irq20_commit"],
        name="p3_irq20_commit1_hook",
        reason="IRQ20 atomic subtract commit path 1 at 0x01D1BE",
    )
    _patch_inline(
        ctx,
        T.HOOK_P3_IRQ20_COMMIT2,
        T.P3_PREIMAGES["p3_irq20_commit2"].expected,
        ["bl p3_irq20_commit", "b.w _i20_after_c2"],
        symbols={"_i20_after_c2": 0x0001D2C2},
        name="p3_irq20_commit2_hook",
        reason="IRQ20 atomic subtract commit path 2 at 0x01D2AA",
    )

    _patch_inline(
        ctx,
        T.HOOK_P3_EP81_GUARD,
        T.P3_PREIMAGES["p3_ep81_guard"].expected,
        ["mov r1, r4", "bl p3_ep81_guard", "cmp r0, #0", "bne _ep81_busy"],
        symbols={"_ep81_busy": 0x0001461C},
        name="p3_ep81_guard_hook",
        reason="Wired EP81 active-queue overwrite guard at 0x014582",
    )
    ctx.patch_bl(
        T.HOOK_P3_BLE_LOOP_CALL,
        builder.symbols["p3_ble_thread_wrap"],
        expected_old=T.P3_PREIMAGES["p3_ble_loop_call"].expected,
        module="phase3_motion",
        reason="BLE thread TX ownership wrapper at 0x00B29A -> 0x0199D4",
    )

    return {
        "enabled": True,
        "base": f"0x{base:08X}",
        "spim3_hook": f"0x{builder.symbols['p3_spim3_hook']:08X}",
        "ep81_guard": f"0x{builder.symbols['p3_ep81_guard']:08X}",
        "hook_sites": [
            f"0x{T.HOOK_P3_SPIM3_CALL:08X}",
            f"0x{T.HOOK_P3_WL_SNAP:08X}",
            f"0x{T.HOOK_P3_WL_POST_TX:08X}",
            f"0x{T.HOOK_P3_USB_SNAP:08X}",
            f"0x{T.HOOK_P3_USB_POST_TX:08X}",
            f"0x{T.HOOK_P3_BLE_SNAP:08X}",
            f"0x{T.HOOK_P3_BLE_POST_TX:08X}",
            f"0x{T.HOOK_P3_BLE_LOOP_CALL:08X}",
            f"0x{T.HOOK_P3_IRQ20_SNAP:08X}",
            f"0x{T.HOOK_P3_IRQ20_COMMIT1:08X}",
            f"0x{T.HOOK_P3_IRQ20_COMMIT2:08X}",
            f"0x{T.HOOK_P3_EP81_GUARD:08X}",
        ],
    }
