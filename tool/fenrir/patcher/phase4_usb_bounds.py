"""Phase 4 AT32F405 USB control SETUP bounds checks (0x080069FC).

Installs 4 USB-IF / HID EP0 request bounds protections while preserving stock
`byte_20000031` (`frame[4]==0xB0`), `0x08006870` EP0 RX, `0x08008348`, and SPI
forwarding intact:
  1. SET_REPORT (`0x09` @ `0x08006AA2`): clamp `wLength <= 64` before `0x0800A5E0`
     (`usbd_ctrl_recv`), preventing overrun into `pdata+0x6C` (`ep0_state`).
  2. GET_PROTOCOL (`0x08006A56`), GET_IDLE (`0x08006A8E`), GET_INTERFACE
     (`0x08006B5A`): enforce `wIndex <= 2`, else STALL (`0x0800A65C`).
  3. GET_DESCRIPTOR (`0x08006AF0..0x08006B57`): redirect invalid descriptor type
     and invalid `wIndex >= 3` branches (`0x08006B1A`, `0x08006B2C`, `0x08006B48`)
     to STALL (`0x08006BA0`) instead of transmitting uninitialized `r6/r7`; also clamp
     valid replies to `min(desc_len, wLength)`.
  4. GET_REPORT (`0x01` @ `0x08006AB6`): send `min(wLength, 64)` instead of fixed 64B.
"""

from __future__ import annotations

from typing import Any

from fenrir.patcher import target_receiver as T
from fenrir.patcher.thumb import PatchContext


def install(ctx: PatchContext) -> dict[str, Any]:
    """Install AT32F405 USB control SETUP bounds fixes into the USB patch builder."""
    builder = ctx.builder
    for key in (
        "usb_get_protocol",
        "usb_get_idle",
        "usb_set_report",
        "usb_get_report",
        "usb_get_desc_block",
        "usb_get_interface",
        "usb_stall_exit",
        "usb_sticky_b0_block",
        "usb_reset_b0_block",
    ):
        spec = T.RX_USB_PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)

    usb_ram = T.RX_USB_RAM_BASE
    code_lines: list[str] = [
        # uint32_t p4_usb_ram_ensure(void) -> returns r0 = RX_USB_RAM_BASE, preserves r2..r11
        "p4_usb_ram_ensure:",
        f"ldr r0, ={usb_ram:#x}",
        "ldr r1, [r0, #0]",
        "mov r12, r2",
        f"ldr r2, ={T.P4_MAGIC_U32:#x}",
        "cmp r1, r2",
        "beq p4u_ready",
        "push {r3}",
        "mov r1, r2",
        "mov r2, r0",
        "str r1, [r0, #0]",
        "movs r1, #0",
        "adds r2, #4",
        f"movs r3, #{(T.RX_USB_RAM_BYTES // 4) - 1}",
        "p4u_zero:",
        "stmia r2!, {r1}",
        "subs r3, #1",
        "bne p4u_zero",
        "pop {r3}",
        "p4u_ready:",
        "mov r2, r12",
        "bx lr",

        # void p4_usb_do_stall(r0 = sb) -> counts diag.usb_setup_stalls & calls 0x0800A65C
        "p4_usb_do_stall:",
        "push {r4, lr}",
        "mov r4, r0",
        "bl p4_usb_ram_ensure",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, [r0, #{T.USB_OFF_DIAG_STALLS}]",
        "adds r1, #1",
        f"str r1, [r0, #{T.USB_OFF_DIAG_STALLS}]",
        "msr primask, r12",
        "mov r0, r4",
        f"bl {T.USB_FN_CTRL_STALL:#x}",
        "pop {r4, pc}",

        # void p4_usb_get_iface_u8(r0 = sb, r1 = pdata_arr_ptr, r2 = wIndex)
        "p4_usb_get_iface_u8:",
        "cmp r2, #2",
        "bhi p4_usb_do_stall",
        "lsls r2, r2, #2",
        "adds r1, r1, r2",
        "movs r2, #1",
        f"b.w {T.USB_FN_CTRL_SEND:#x}",

        # void p4_usb_set_report_bounded(r0 = sb, r1 = pdata, r2 = setup)
        "p4_usb_set_report_bounded:",
        "push {r4, r5, r6, lr}",
        "mov r4, r0",
        "mov r5, r1",
        "ldrh r6, [r2, #6]",
        "movs r0, #9",
        "strb.w r0, [r5, #0x6c]",
        "bl p4_usb_ram_ensure",
        "cmp r6, #0x40",
        "bls p4u_sr_ok",
        "movs r6, #0x40",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, [r0, #{T.USB_OFF_DIAG_CLAMPED}]",
        "adds r1, #1",
        f"str r1, [r0, #{T.USB_OFF_DIAG_CLAMPED}]",
        "msr primask, r12",
        "p4u_sr_ok:",
        "mov r0, r4",
        "addw r1, r5, #0x24",
        "mov r2, r6",
        f"bl {T.USB_FN_CTRL_RECV:#x}",
        "pop {r4, r5, r6, pc}",

        # void p4_usb_get_report_bounded(r0 = sb, r1 = pdata, r2 = setup)
        "p4_usb_get_report_bounded:",
        "push {r4, r5, r6, lr}",
        "mov r4, r0",
        "mov r5, r1",
        "ldrh r6, [r2, #6]",
        "movs r0, #1",
        "strb.w r0, [r5, #0x6c]",
        "bl p4_usb_ram_ensure",
        "cmp r6, #0x40",
        "bls p4u_gr_ok",
        "movs r6, #0x40",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, [r0, #{T.USB_OFF_DIAG_CLAMPED}]",
        "adds r1, #1",
        f"str r1, [r0, #{T.USB_OFF_DIAG_CLAMPED}]",
        "msr primask, r12",
        "p4u_gr_ok:",
        "mov r0, r4",
        f"ldr r1, ={T.USB_RAM_CMD_BUF:#x}",
        "mov r2, r6",
        f"bl {T.USB_FN_CTRL_SEND:#x}",
        "pop {r4, r5, r6, pc}",

        # void p4_usb_send_desc_bounded(r0 = setup, r1 = ptr, r2 = desc_len)
        "p4_usb_send_desc_bounded:",
        "push {r4, r5, r6, lr}",
        "mov r4, r1",
        "mov r5, r2",
        "ldrh r6, [r0, #6]",
        "bl p4_usb_ram_ensure",
        "cmp r5, r6",
        "bls p4u_sd_ok",
        "mov r5, r6",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, [r0, #{T.USB_OFF_DIAG_CLAMPED}]",
        "adds r1, #1",
        f"str r1, [r0, #{T.USB_OFF_DIAG_CLAMPED}]",
        "msr primask, r12",
        "p4u_sd_ok:",
        "mov r0, r9",
        "mov r1, r4",
        "mov r2, r5",
        f"bl {T.USB_FN_CTRL_SEND:#x}",
        "pop {r4, r5, r6, pc}",
        ".ltorg",
    ]

    base = ctx.alloc_asm(
        "phase4_usb_bounds_core",
        code_lines,
        align=4,
        export_labels=(
            "p4_usb_ram_ensure",
            "p4_usb_do_stall",
            "p4_usb_get_iface_u8",
            "p4_usb_set_report_bounded",
            "p4_usb_get_report_bounded",
            "p4_usb_send_desc_bounded",
        ),
        module="phase4_usb_bounds",
        reason="AT32F405 USB control SETUP bounds checks (0x080069FC)",
    )

    T.patch_inline(
        ctx,
        T.USB_HOOK_GET_PROTOCOL,
        T.RX_USB_PREIMAGES["usb_get_protocol"].expected,
        ["ldrh r2, [r4, #4]", "mov r1, r5", "mov r0, r9", "bl p4_usb_get_iface_u8"],
        name="usb_get_protocol_bounds",
        module="phase4_usb_bounds",
        reason="Validate GET_PROTOCOL wIndex <= 2 else STALL",
    )
    T.patch_inline(
        ctx,
        T.USB_HOOK_GET_IDLE,
        T.RX_USB_PREIMAGES["usb_get_idle"].expected,
        ["ldrh r2, [r4, #4]", "addw r1, r5, #0xc", "mov r0, r9", "bl p4_usb_get_iface_u8"],
        name="usb_get_idle_bounds",
        module="phase4_usb_bounds",
        reason="Validate GET_IDLE wIndex <= 2 else STALL",
    )
    T.patch_inline(
        ctx,
        T.USB_HOOK_GET_INTERFACE,
        T.RX_USB_PREIMAGES["usb_get_interface"].expected,
        ["ldrh r2, [r4, #4]", "addw r1, r5, #0x18", "mov r0, r9", "bl p4_usb_get_iface_u8"],
        name="usb_get_interface_bounds",
        module="phase4_usb_bounds",
        reason="Validate GET_INTERFACE wIndex <= 2 else STALL",
    )
    T.patch_inline(
        ctx,
        T.USB_HOOK_SET_REPORT,
        T.RX_USB_PREIMAGES["usb_set_report"].expected,
        ["mov r0, r9", "mov r1, r5", "mov r2, r4", "bl p4_usb_set_report_bounded"],
        name="usb_set_report_clamp",
        module="phase4_usb_bounds",
        reason="Clamp SET_REPORT wLength <= 64 before usbd_ctrl_recv",
    )
    T.patch_inline(
        ctx,
        T.USB_HOOK_GET_REPORT,
        T.RX_USB_PREIMAGES["usb_get_report"].expected,
        ["mov r0, r9", "mov r1, r5", "mov r2, r4", "bl p4_usb_get_report_bounded"],
        name="usb_get_report_clamp",
        module="phase4_usb_bounds",
        reason="Clamp GET_REPORT length to min(wLength, 64)",
    )

    desc_block = T.RX_USB_PREIMAGES["usb_get_desc_block"].expected
    for site, name in (
        (T.USB_HOOK_GET_DESC_BNE_1, "usb_get_desc_stall_report_idx"),
        (T.USB_HOOK_GET_DESC_BNE_2, "usb_get_desc_stall_bad_type"),
        (T.USB_HOOK_GET_DESC_BNE_3, "usb_get_desc_stall_hid_idx"),
    ):
        off = site - 0x08006AF0
        T.patch_inline(
            ctx,
            site,
            desc_block[off : off + 2],
            ["bne _usb_stall"],
            symbols={"_usb_stall": T.USB_HOOK_CTRL_STALL_SITE},
            name=name,
            module="phase4_usb_bounds",
            reason="Redirect invalid GET_DESCRIPTOR type/index to EP0 STALL",
        )

    off_send = T.USB_HOOK_GET_DESC_SEND - 0x08006AF0
    T.patch_inline(
        ctx,
        T.USB_HOOK_GET_DESC_SEND,
        desc_block[off_send : off_send + 10],
        ["mov r2, r6", "mov r1, r7", "mov r0, r4", "bl p4_usb_send_desc_bounded"],
        name="usb_get_desc_len_bound",
        module="phase4_usb_bounds",
        reason="Cap GET_DESCRIPTOR reply to min(desc_len, wLength)",
    )

    stall_block = T.RX_USB_PREIMAGES["usb_stall_exit"].expected
    off_stall = T.USB_HOOK_CTRL_STALL_SITE - 0x08006B94
    T.patch_inline(
        ctx,
        T.USB_HOOK_CTRL_STALL_SITE,
        stall_block[off_stall : off_stall + 6],
        ["mov r0, r9", "bl p4_usb_do_stall"],
        name="usb_ctrl_stall_counted",
        module="phase4_usb_bounds",
        reason="Count USB EP0 STALLs cleanly via p4_usb_do_stall",
    )

    return {
        "enabled": True,
        "code_base": f"0x{base:08X}",
        "symbols": {
            k: f"0x{builder.symbols[k]:08X}"
            for k in (
                "p4_usb_ram_ensure",
                "p4_usb_do_stall",
                "p4_usb_get_iface_u8",
                "p4_usb_set_report_bounded",
                "p4_usb_get_report_bounded",
                "p4_usb_send_desc_bounded",
            )
        },
    }
