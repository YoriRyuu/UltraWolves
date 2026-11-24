"""Phase 4 Dual-MCU SOF/TIM6/SPI atomic counters & SPIS0 peek-then-commit synchronization.

Fixes critical timing/synchronization races across both receiver MCUs:
  - AT32F405 USB MCU (`install_usb`):
      * `0x08006748` (`TIM6_IRQHandler`) & `0x08009F0C` / `0x08009F26` (`SOF` callback):
        protect shared RMW counters (`0x20000020`, `0x20000021`, `0x20000023`) with
        `PRIMASK` critical sections so TIM6 `125 us` and USB `SOF` cannot lose ticks or
        corrupt EP81 watchdog intervals; record `USB_OFF_SOF_LOCKED` & tick counters.
      * `0x0800869C` (`usb_spi_poll`, entry via `0x08008694` and `0x08008692 cbz`):
        atomically latch `0x20000024 = 1`, clear `0x20000020 = 0`, and bump
        `USB_OFF_DIAG_SPI_POLLS` inside `CPSID I`.
  - nRF52820 2.4G MCU (`install_2g4`):
      * `0x0000C9AA` (`spis_poll` prefetch): replace `queue_pop` (`0x0000BE10`) with
        `p4_rad_q2_prefetch_peek`, checking `queue2` emptiness first and calling
        non-destructive `queue_peek` (`0x0000BE70`) + setting `RAD_OFF_Q2_PREFETCHED = 1`
        instead of popping before SPI completes.
      * `0x0000C8B2` (`spis_poll` entry): when `0x200001CD` (`EVENTS_ACQUIRED` flag)
        fires after SPI transaction completion and `RAD_OFF_Q2_PREFETCHED == 1`, commit
        `queue2` (`0x0000BEE8`) and count `RAD_OFF_DIAG_Q2_SPI_COMMIT`.
      * `0x00007650` (`SPIS0_IRQHandler`): handle stock `EVENTS_ACQUIRED` (`0x40003128`)
        -> `TASKS_RELEASE` (`0x40003028`) -> `0x200001CD = 1`, plus clear `EVENTS_END`
        (`0x40003104`) and latch `TXD.AMOUNT` (`0x4000354C`) / `RXD.AMOUNT` (`0x4000353C`).
      * `0x000074F8` (`GPIOTE_IRQ`): wrap shared `0x200001CF` RMW counter in `PRIMASK`
        around `0x0000C198` link-loss heartbeat.
      * `0x0000C974` / `0x0000C99A`: track `0xAA`/`0xCC` `TIMER0` polling transitions.
"""

from __future__ import annotations

from typing import Any

from fenrir.patcher import phase4_abs, target_receiver as T
from fenrir.patcher.thumb import PatchContext


def install_usb(ctx: PatchContext) -> dict[str, Any]:
    """Install AT32F405 TIM6, SOF, and SPI-poll PRIMASK atomic sync hooks."""
    builder = ctx.builder
    for key in (
        "usb_tim6_counters",
        "usb_sof_cnt_20",
        "usb_sof_cnt_21_23",
        "usb_spi_poll_gate",
    ):
        spec = T.RX_USB_PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)

    need_ram_ensure = "p4_usb_ram_ensure" not in builder.symbols
    code_lines: list[str] = phase4_abs.ensure_usb_ram_helper(ctx) + [
        # void p4_usb_tim6_counters(void) - called at 0x08006748
        "p4_usb_tim6_counters:",
        "push {r4, lr}",
        "bl p4_usb_ram_ensure",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, ={T.USB_RAM_SPI_CNT:#x}",
        "ldrb r2, [r1]",
        "adds r2, #1",
        "strb r2, [r1]",
        f"ldr r1, ={T.USB_RAM_SPI_IDLE_CNT:#x}",
        "ldrb r2, [r1]",
        "adds r2, #1",
        "strb r2, [r1]",
        f"ldr r1, ={T.USB_RAM_WD_TICK_23:#x}",
        "ldrb r2, [r1]",
        "adds r2, #1",
        "strb r2, [r1]",
        f"ldr r2, [r0, #{T.USB_OFF_DIAG_TIM6_TICKS}]",
        "adds r2, #1",
        f"str r2, [r0, #{T.USB_OFF_DIAG_TIM6_TICKS}]",
        "msr primask, r12",
        "pop {r4, pc}",

        # void p4_usb_sof_cnt20(void) - called at 0x08009F0C, preserves r4 (0x20000478)
        "p4_usb_sof_cnt20:",
        "push {r4, lr}",
        "bl p4_usb_ram_ensure",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, ={T.USB_RAM_SPI_CNT:#x}",
        "ldrb r2, [r1]",
        "adds r2, #1",
        "strb r2, [r1]",
        "movs r2, #1",
        f"strb r2, [r0, #{T.USB_OFF_SOF_LOCKED}]",
        f"ldr r2, [r0, #{T.USB_OFF_DIAG_SOF_TICKS}]",
        "adds r2, #1",
        f"str r2, [r0, #{T.USB_OFF_DIAG_SOF_TICKS}]",
        "msr primask, r12",
        "pop {r4, pc}",

        # uint32_t p4_usb_sof_cnt21_23(void) -> returns *(u8*)0x20000064
        "p4_usb_sof_cnt21_23:",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, ={T.USB_RAM_SPI_IDLE_CNT:#x}",
        "ldrb r2, [r1]",
        "adds r2, #1",
        "strb r2, [r1]",
        f"ldr r1, ={T.USB_RAM_WD_TICK_23:#x}",
        "ldrb r2, [r1]",
        "adds r2, #1",
        "strb r2, [r1]",
        f"ldr r1, ={T.USB_RAM_EP81_BUSY_64:#x}",
        "ldrb r0, [r1]",
        "msr primask, r12",
        "bx lr",

        # void p4_usb_spi_poll_gate(void) - called at 0x0800869C
        "p4_usb_spi_poll_gate:",
        "push {r4, lr}",
        "bl p4_usb_ram_ensure",
        "mrs r12, primask",
        "cpsid i",
        "movs r2, #1",
        "ldr r1, =0x20000024",
        "strb r2, [r1]",
        "movs r2, #0",
        f"ldr r1, ={T.USB_RAM_SPI_CNT:#x}",
        "strb r2, [r1]",
        f"ldr r2, [r0, #{T.USB_OFF_DIAG_SPI_POLLS}]",
        "adds r2, #1",
        f"str r2, [r0, #{T.USB_OFF_DIAG_SPI_POLLS}]",
        "msr primask, r12",
        "pop {r4, pc}",
        ".ltorg",
    ]

    export_labels = [
        "p4_usb_tim6_counters",
        "p4_usb_sof_cnt20",
        "p4_usb_sof_cnt21_23",
        "p4_usb_spi_poll_gate",
    ]
    if need_ram_ensure:
        export_labels.insert(0, "p4_usb_ram_ensure")

    base = ctx.alloc_asm(
        "phase4_usb_sync_core",
        code_lines,
        align=4,
        export_labels=tuple(export_labels),
        module="phase4_sync",
        reason="AT32F405 Phase 4 TIM6, SOF, and SPI-poll atomic synchronization hooks",
    )

    T.patch_inline(
        ctx,
        T.USB_HOOK_TIM6_COUNTERS,
        T.RX_USB_PREIMAGES["usb_tim6_counters"].expected,
        ["bl p4_usb_tim6_counters"],
        name="usb_tim6_counters_atomic",
        module="phase4_sync",
        reason="Protect shared TIM6/SOF counters with PRIMASK critical section",
    )
    T.patch_inline(
        ctx,
        T.USB_HOOK_SOF_CNT_20,
        T.RX_USB_PREIMAGES["usb_sof_cnt_20"].expected,
        ["bl p4_usb_sof_cnt20"],
        name="usb_sof_cnt20_atomic",
        module="phase4_sync",
        reason="Atomically increment 0x20000020 and track USB SOF lock state",
    )
    T.patch_inline(
        ctx,
        T.USB_HOOK_SOF_CNT_21_23,
        T.RX_USB_PREIMAGES["usb_sof_cnt_21_23"].expected,
        ["bl p4_usb_sof_cnt21_23"],
        name="usb_sof_cnt21_23_atomic",
        module="phase4_sync",
        reason="Atomically update 0x20000021/23 in SOF and return 0x20000064",
    )
    # Note: 0x08008694..0x0800869B keeps the `< 4` branch to 0x08008798 intact while
    # 0x0800869C..0x080086AB handles both `>= 4` fallthrough and `0x08008692 cbz -> 0x0800869C`.
    T.patch_inline(
        ctx,
        T.USB_HOOK_SPI_POLL_GATE + 8,
        T.RX_USB_PREIMAGES["usb_spi_poll_gate"].expected[8:],
        ["bl p4_usb_spi_poll_gate"],
        name="usb_spi_poll_gate_atomic",
        module="phase4_sync",
        reason="Atomically reset 0x20000020 and latch 0x20000024 under PRIMASK",
    )

    return {
        "enabled": True,
        "code_base": f"0x{base:08X}",
        "symbols": {k: f"0x{builder.symbols[k]:08X}" for k in export_labels},
    }


def install_2g4(ctx: PatchContext) -> dict[str, Any]:
    """Install nRF52820 SPIS0 peek-then-commit, IRQ capture, GPIOTE & TIMER0 sync hooks."""
    builder = ctx.builder
    for key in (
        "rad_spis_prefetch_peek",
        "rad_spis_poll_commit",
        "rad_spis0_irq",
        "rad_gpiote_sync",
        "rad_spis_timer0_start",
        "rad_spis_timer0_stop",
    ):
        spec = T.RX_2G4_PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)

    need_ram_ensure = "p4_rad_ram_ensure" not in builder.symbols
    code_lines: list[str] = phase4_abs.ensure_rad_ram_helper(ctx) + [
        # int p4_rad_q2_prefetch_peek(r0 = q, r1 = dst, r2 = size) -> 1 if peeked, 0 if empty
        "p4_rad_q2_prefetch_peek:",
        "push {r4, r5, r6, lr}",
        "mov r4, r0",
        "mov r5, r1",
        "mov r6, r2",
        "lsls r3, r4, #2",
        "adds r3, r3, r4",
        "lsls r3, r3, #7",
        f"ldr r1, ={T.RAD_RAM_QUEUE_BASE:#x}",
        "adds r3, r1, r3",
        "mrs r12, primask",
        "cpsid i",
        "ldrb r1, [r3, #1]",
        "msr primask, r12",
        "cmp r1, #0",
        "beq p4r_peek_nonempty",
        "bl p4_rad_ram_ensure",
        "movs r1, #0",
        f"strb r1, [r0, #{T.RAD_OFF_Q2_PREFETCHED}]",
        "movs r0, #0",
        "pop {r4, r5, r6, pc}",

        "p4r_peek_nonempty:",
        "mov r0, r4",
        "mov r1, r5",
        "mov r2, r6",
        f"bl {T.RAD_FN_QUEUE_PEEK:#x}",
        "bl p4_rad_ram_ensure",
        "movs r1, #1",
        f"strb r1, [r0, #{T.RAD_OFF_Q2_PREFETCHED}]",
        "movs r0, #1",
        "pop {r4, r5, r6, pc}",

        # int p4_rad_spis_poll_entry(void) -> 1 if SPIS_ACQ_FLAG fired (after committing q2), else 0
        "p4_rad_spis_poll_entry:",
        "push {r4, lr}",
        f"ldr r1, ={T.RAD_RAM_SPIS_ACQ_FLAG:#x}",
        "ldrb r0, [r1]",
        "cmp r0, #0",
        "bne p4r_spis_acquired",
        "movs r0, #0",
        "pop {r4, pc}",

        "p4r_spis_acquired:",
        "movs r0, #0",
        f"ldr r1, ={T.RAD_RAM_SPIS_PREFETCH_FLAG:#x}",
        "strb r0, [r1]",
        "bl p4_rad_ram_ensure",
        "mov r4, r0",
        f"ldrb r1, [r4, #{T.RAD_OFF_Q2_PREFETCHED}]",
        "cmp r1, #0",
        "beq p4r_spis_done",
        "movs r1, #0",
        f"strb r1, [r4, #{T.RAD_OFF_Q2_PREFETCHED}]",
        "movs r0, #2",
        f"bl {T.RAD_FN_QUEUE_COMMIT:#x}",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, [r4, #{T.RAD_OFF_DIAG_Q2_SPI_COMMIT}]",
        "adds r1, #1",
        f"str r1, [r4, #{T.RAD_OFF_DIAG_Q2_SPI_COMMIT}]",
        "msr primask, r12",
        "p4r_spis_done:",
        "movs r0, #1",
        "pop {r4, pc}",

        # void p4_rad_spis0_irq_hook(void) - called from 0x00007650 SPIS0_IRQHandler
        "p4_rad_spis0_irq_hook:",
        "push {r4, r5, lr}",
        "bl p4_rad_ram_ensure",
        "mov r4, r0",
        f"ldr r5, ={T.RAD_MMIO_SPIS0_BASE + 0x100:#x}",
        "ldr r0, [r5, #0x04]",
        "cmp r0, #0",
        "beq p4r_spis0_chk_acq",
        "movs r0, #0",
        "str r0, [r5, #0x04]",
        f"ldr r1, ={T.RAD_MMIO_SPIS0_BASE + 0x53C:#x}",
        "ldr r2, [r1, #0]",
        f"str r2, [r4, #{T.RAD_OFF_LAST_RXD_AMT}]",
        "ldr r2, [r1, #0x10]",
        f"str r2, [r4, #{T.RAD_OFF_LAST_TXD_AMT}]",

        "p4r_spis0_chk_acq:",
        "ldr r0, [r5, #0x28]",
        "cmp r0, #0",
        "beq p4r_spis0_diag",
        "movs r0, #0",
        "str r0, [r5, #0x28]",
        "movs r0, #1",
        f"ldr r1, ={T.RAD_MMIO_SPIS0_BASE:#x}",
        "str r0, [r1, #0x28]",
        f"ldr r1, ={T.RAD_RAM_SPIS_ACQ_FLAG:#x}",
        "strb r0, [r1]",

        "p4r_spis0_diag:",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r0, [r4, #{T.RAD_OFF_DIAG_SPIS0_IRQS}]",
        "adds r0, #1",
        f"str r0, [r4, #{T.RAD_OFF_DIAG_SPIS0_IRQS}]",
        "msr primask, r12",
        "pop {r4, r5, pc}",

        # void p4_rad_gpiote_sync_hook(void) - called at 0x000074F8
        "p4_rad_gpiote_sync_hook:",
        "push {r4, lr}",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, ={T.RAD_RAM_SPIS_IDLE_CNT:#x}",
        "ldrb r0, [r1]",
        "adds r0, #1",
        "strb r0, [r1]",
        "msr primask, r12",
        f"bl {T.RAD_FN_HEARTBEAT_800:#x}",
        "bl p4_rad_ram_ensure",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, [r0, #{T.RAD_OFF_DIAG_GPIOTE_IRQS}]",
        "adds r1, #1",
        f"str r1, [r0, #{T.RAD_OFF_DIAG_GPIOTE_IRQS}]",
        "msr primask, r12",
        "pop {r4, pc}",

        # void p4_rad_timer0_start_wrap(r0, r1) -> sets TIMER0_ACTIVE=1 + MODE_TRANS++ -> calls 0xC67C
        "p4_rad_timer0_start_wrap:",
        "push {r4, r5, lr}",
        "mov r4, r0",
        "mov r5, r1",
        "bl p4_rad_ram_ensure",
        "movs r1, #1",
        f"strb r1, [r0, #{T.RAD_OFF_TIMER0_ACTIVE}]",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, [r0, #{T.RAD_OFF_DIAG_MODE_TRANS}]",
        "adds r1, #1",
        f"str r1, [r0, #{T.RAD_OFF_DIAG_MODE_TRANS}]",
        "msr primask, r12",
        "mov r0, r4",
        "mov r1, r5",
        f"bl {T.RAD_FN_TIMER0_START:#x}",
        "pop {r4, r5, pc}",

        # void p4_rad_timer0_stop_wrap(r0) -> sets TIMER0_ACTIVE=0 + MODE_TRANS++ -> calls 0xC638
        "p4_rad_timer0_stop_wrap:",
        "push {r4, lr}",
        "mov r4, r0",
        "bl p4_rad_ram_ensure",
        "movs r1, #0",
        f"strb r1, [r0, #{T.RAD_OFF_TIMER0_ACTIVE}]",
        "mrs r12, primask",
        "cpsid i",
        f"ldr r1, [r0, #{T.RAD_OFF_DIAG_MODE_TRANS}]",
        "adds r1, #1",
        f"str r1, [r0, #{T.RAD_OFF_DIAG_MODE_TRANS}]",
        "msr primask, r12",
        "mov r0, r4",
        f"bl {T.RAD_FN_TIMER0_STOP:#x}",
        "pop {r4, pc}",
        ".ltorg",
    ]

    export_labels = [
        "p4_rad_q2_prefetch_peek",
        "p4_rad_spis_poll_entry",
        "p4_rad_spis0_irq_hook",
        "p4_rad_gpiote_sync_hook",
        "p4_rad_timer0_start_wrap",
        "p4_rad_timer0_stop_wrap",
    ]
    if need_ram_ensure:
        export_labels.insert(0, "p4_rad_ram_ensure")

    base = ctx.alloc_asm(
        "phase4_2g4_sync_core",
        code_lines,
        align=4,
        export_labels=tuple(export_labels),
        module="phase4_sync",
        reason="nRF52820 Phase 4 SPIS0 peek-then-commit, IRQ & GPIOTE/TIMER0 sync hooks",
    )

    T.patch_inline(
        ctx,
        T.RAD_HOOK_SPIS_PREFETCH_PEEK,
        T.RX_2G4_PREIMAGES["rad_spis_prefetch_peek"].expected,
        ["bl p4_rad_q2_prefetch_peek"],
        name="rad_spis_prefetch_peek_p4",
        module="phase4_sync",
        reason="Use non-destructive queue_peek instead of queue_pop at SPIS TX prefetch",
    )
    T.patch_inline(
        ctx,
        T.RAD_HOOK_SPIS_POLL_COMMIT,
        T.RX_2G4_PREIMAGES["rad_spis_poll_commit"].expected,
        [
            "bl p4_rad_spis_poll_entry",
            "cbnz r0, _spis_have",
            "b.w _spis_none",
            "_spis_have:",
        ],
        symbols={"_spis_none": 0x0000C99E},
        name="rad_spis_poll_commit_p4",
        module="phase4_sync",
        reason="Commit prefetched queue2 item only after SPIS0_IRQ EVENTS_ACQUIRED confirmation",
    )
    T.patch_inline(
        ctx,
        T.RAD_HOOK_SPIS0_IRQ,
        T.RX_2G4_PREIMAGES["rad_spis0_irq"].expected,
        ["push {r4, lr}", "bl p4_rad_spis0_irq_hook", "pop {r4, pc}"],
        name="rad_spis0_irq_p4",
        module="phase4_sync",
        reason="Preserve SPIS0 ACQUIRED->RELEASE flow and capture EVENTS_END/TXD/RXD AMOUNT",
    )
    T.patch_inline(
        ctx,
        T.RAD_HOOK_GPIOTE_SYNC,
        T.RX_2G4_PREIMAGES["rad_gpiote_sync"].expected,
        ["bl p4_rad_gpiote_sync_hook"],
        name="rad_gpiote_sync_p4",
        module="phase4_sync",
        reason="Protect shared 0x200001CF idle counter under PRIMASK around 0x0000C198",
    )
    T.patch_inline(
        ctx,
        T.RAD_HOOK_SPIS_TIMER0_START,
        T.RX_2G4_PREIMAGES["rad_spis_timer0_start"].expected,
        ["bl p4_rad_timer0_start_wrap"],
        name="rad_spis_timer0_start_p4",
        module="phase4_sync",
        reason="Track 0xAA TIMER0 active state transition",
    )
    T.patch_inline(
        ctx,
        T.RAD_HOOK_SPIS_TIMER0_STOP,
        T.RX_2G4_PREIMAGES["rad_spis_timer0_stop"].expected,
        ["bl p4_rad_timer0_stop_wrap"],
        name="rad_spis_timer0_stop_p4",
        module="phase4_sync",
        reason="Track 0xCC TIMER0 stop transition",
    )

    return {
        "enabled": True,
        "code_base": f"0x{base:08X}",
        "symbols": {k: f"0x{builder.symbols[k]:08X}" for k in export_labels},
    }
