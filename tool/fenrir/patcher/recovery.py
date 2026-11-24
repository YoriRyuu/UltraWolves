"""No-disassembly Fault-to-Bootloader software eject seat (H1)."""

from __future__ import annotations

from typing import Any

from fenrir.patcher import target_mouse as T
from fenrir.patcher.thumb import PatchContext


def install(ctx: PatchContext) -> dict[str, Any]:
    """Route HardFault/MemManage/BusFault/UsageFault to Bootloader 0xA55AA55A reset."""
    builder = ctx.builder
    for key in (
        "vector_table_64b",
        "h1_fault_vectors",
        "default_stubs",
        "nvic_system_reset",
        "stock_bootloader_magic_literal",
    ):
        spec = T.PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)

    handler_addr = ctx.alloc_asm(
        "fault_bootloader_eject",
        [
            "cpsid i",
            f"ldr r0, ={T.BOOTLOADER_MAGIC_VALUE:#x}",
            f"ldr r1, ={T.BOOTLOADER_MAGIC_ADDR:#x}",
            "str r0, [r1]",
            "dsb sy",
            f"b.w {T.NVIC_SYSTEM_RESET:#x}",
            ".ltorg",
        ],
        align=4,
        module="recovery",
        reason="Stackless fault eject: write 0xA55AA55A to 0x2003FFFC then NVIC_SystemReset",
    )

    thumb_vec = handler_addr | 1
    vector_bytes = thumb_vec.to_bytes(4, "little") * 4
    builder.edit(
        T.HOOK_H1_FAULT_VECTORS,
        vector_bytes,
        expected_old=T.PREIMAGES["h1_fault_vectors"].expected,
        module="recovery",
        reason="H1: Route HardFault/MemManage/BusFault/UsageFault to Bootloader eject seat",
    )

    return {
        "enabled": True,
        "handler_address": f"0x{handler_addr:08X}",
        "thumb_vector": f"0x{thumb_vec:08X}",
        "magic_addr": f"0x{T.BOOTLOADER_MAGIC_ADDR:08X}",
        "magic_value": f"0x{T.BOOTLOADER_MAGIC_VALUE:08X}",
        "reset_fn": f"0x{T.NVIC_SYSTEM_RESET:08X}",
        "patched_vectors": [
            "HardFault(0x600C)",
            "MemManage(0x6010)",
            "BusFault(0x6014)",
            "UsageFault(0x6018)",
        ],
        "protected_untouched": ["InitialSP(0x6000)", "Reset(0x6004)", "NMI(0x6008)", "SVC(0x602C)"],
    }
