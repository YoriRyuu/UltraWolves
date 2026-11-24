"""Family A group 5 extension, cooperative sensor snapshot/workers, and ID53 isolation (H2, H5, H6, H7)."""

from __future__ import annotations

from typing import Any

from fenrir.patcher import persistence as P, phase3_diag as D, target_mouse as T
from fenrir.patcher.thumb import PatchContext, encode_b_w, verify_branch_patch

GROUP5_ABI_MAGIC = b"FNR2"
GROUP5_ABI_VERSION = 1
GROUP5_ID = 5

# Unified group 5 subcommands: 0x01..0x05 SET/action, 0x80..0x81 GET queries
SUB_GET_STATE = 0x80
SUB_GET_CAPS = 0x80  # alias
SUB_SNAP_TRIGGER = 0x01
SUB_SNAP_READ = 0x81
SUB_SET_FPS = 0x02
SUB_SET_DOWNSHIFT = 0x03
SUB_SET_SMOOTHING = 0x04
SUB_PERSIST_CTRL = 0x05

# Capability flags (u16 LE in 0x80 reply)
F_SNAPSHOT = 1 << 0
F_FPS_PRESET = 1 << 1
F_FPS_CUSTOM = 1 << 2
F_DOWNSHIFT = 1 << 3
F_SMOOTHING = 1 << 4
F_DEBOUNCE_INSTANT = 1 << 5
F_PERSISTENCE = 1 << 6
F_FAULT_RECOVERY = 1 << 7
CAPS_FLAGS = (
    F_SNAPSHOT
    | F_FPS_PRESET
    | F_FPS_CUSTOM
    | F_DOWNSHIFT
    | F_SMOOTHING
    | F_DEBOUNCE_INSTANT
    | F_PERSISTENCE
    | F_FAULT_RECOVERY
)

ERR_NONE = 0
ERR_NOT_ID53 = 1
ERR_SPI_WRITE = 2
ERR_READBACK_MISMATCH = 3
ERR_WORKER_QUEUE_FULL = 4
ERR_PERSIST_FAILED = 5

# Curated PAW3950 FPS presets: (name, 07:42 U, 06:53 slow, 06:62 fast).
# Index 0 is stock; custom (0xFF, U, slow, fast) supports any arbitrary rate.
FPS_PRESETS: tuple[tuple[str, int, int, int], ...] = (
    ("stock", 0, 0, 0),
    ("20k", 20, 2, 2),
    ("16k", 25, 2, 2),
    ("14k", 29, 2, 2),
    ("12k", 33, 2, 2),
    ("10k", 20, 4, 4),
    ("8k", 20, 5, 5),
    ("4k", 20, 10, 10),
)
assert len(FPS_PRESETS) == P.FPS_PRESET_COUNT

# Phase 3+ extended 38-entry preset table: legacy 0..7 + 30 appended SuperLamzu PAW3950 presets
FPS_PRESETS_P3PLUS: tuple[tuple[str, int, int, int], ...] = FPS_PRESETS + (
    ("19k", 21, 2, 2),
    ("18k", 22, 2, 2),
    ("17k", 24, 2, 2),
    ("15k", 27, 2, 2),
    ("13k", 31, 2, 2),
    ("11k", 36, 2, 2),
    ("9k", 22, 4, 4),
    ("7k", 38, 3, 3),
    ("6k", 33, 4, 4),
    ("5k", 20, 8, 8),
    ("13-20k", 20, 3, 2),
    ("10-20k", 20, 4, 2),
    ("8-20k", 20, 5, 2),
    ("6.7-20k", 20, 6, 2),
    ("5-20k", 20, 8, 2),
    ("8-16k", 25, 4, 2),
    ("8-13k", 20, 5, 3),
    ("8-12k", 33, 3, 2),
    ("9.2k", 29, 3, 3),
    ("6.9k", 29, 4, 4),
    ("5.5k", 29, 5, 5),
    ("4.6k", 29, 6, 6),
    ("9.2-13.8k", 29, 3, 2),
    ("6.9-13.8k", 29, 4, 2),
    ("5.5-13.8k", 29, 5, 2),
    ("4-8k", 20, 10, 5),
    ("13.3k", 20, 3, 3),
    ("16k-cal", 24, 2, 2),
    ("16k-cal-fast", 23, 2, 2),
    ("13.3k-b", 60, 1, 1),
)
assert len(FPS_PRESETS_P3PLUS) == P.FPS_PRESET_COUNT_P3PLUS

# 8 whitelisted non-burst registers for on-demand snapshot (bank, reg)
SNAPSHOT_REGISTERS: tuple[tuple[int, int], ...] = (
    (0x07, 0x42),
    (0x06, 0x53),
    (0x06, 0x62),
    (0x06, 0x6D),
    (0x06, 0x6E),
    (0x05, 0x44),
    (0x0C, 0x4D),
    (0x00, 0x40),
)


def install(
    ctx: PatchContext,
    *,
    phase3_dispatch_addr: int | None = None,
    phase3plus: bool = False,
) -> dict[str, Any]:
    """Install Group 5 dispatcher, cooperative snapshot/override workers, and ID53 hooks."""
    if phase3plus and phase3_dispatch_addr is None:
        raise ValueError("phase3plus requires phase3_dispatch_addr")
    builder = ctx.builder
    for key in (
        "group5_switch_block",
        "h2_group5_default",
        "group5_common_exit",
        "worker_register",
        "worker_kick",
        "worker_poll",
        "spi_read_reg",
        "spi_write_reg",
        "h5_mode_worker_ptr",
        "h7_mode_apply_tail",
        "h6_powerup_tail",
    ):
        spec = T.PREIMAGES[key]
        builder.verify_fingerprint(spec.address, spec.expected, label=spec.label)

    for req_sym in ("valid_fps_tuple", "cfg_save_page", "cfg_reset_page"):
        if req_sym not in builder.symbols:
            raise ValueError(f"persistence must be installed before group5 (missing {req_sym})")

    off_mode_app = T.RAM_SENSOR_MODE_APPLIED - T.RAM_SENSOR_BRANCH  # 20
    off_mode_tgt = T.RAM_SENSOR_MODE_TARGET - T.RAM_SENSOR_BRANCH  # 23
    off_cpi_x = T.RAM_SENSOR_CPI_X - T.RAM_SENSOR_BRANCH  # 28
    off_cpi_y = T.RAM_SENSOR_CPI_Y - T.RAM_SENSOR_BRANCH  # 30
    off_spi_burst = T.RAM_SPI_BURST_ACTIVE - T.RAM_SPI_IDLE  # 4
    off_sens_en = T.RAM_SENSOR_ENABLED - T.RAM_SPI_IDLE  # 8

    valid_fps_addr = builder.symbols["valid_fps_tuple"]
    cfg_save_addr = builder.symbols["cfg_save_page"]
    cfg_reset_addr = builder.symbols["cfg_reset_page"]

    # Compact RO tables embedded at end of group5_core (4B-aligned for PC-relative ADR, 0 pool cost):
    presets_table = FPS_PRESETS_P3PLUS if phase3plus else FPS_PRESETS
    preset_count = P.FPS_PRESET_COUNT_P3PLUS if phase3plus else P.FPS_PRESET_COUNT
    fps_table_bytes = bytes(v for _, u, s, f in presets_table[1:] for v in (u, s, f))
    snap_regs_bytes = bytes(v for pair in SNAPSHOT_REGISTERS for v in pair)  # 16B
    stock_fps_bytes = bytes((0x14, 3, 2, 0x14, 2, 2, 0x28, 3, 1))  # 9B (M1Lo, M1Hi, M2/3)
    fps_reg_pairs = bytes((7, 0x42, 6, 0x53, 6, 0x62))  # 6B
    if phase3plus:
        eff_caps = CAPS_FLAGS | D.PHASE3PLUS_CAPS_MASK
    elif phase3_dispatch_addr is not None:
        eff_caps = CAPS_FLAGS | D.PHASE3_CAPS_MASK
    else:
        eff_caps = CAPS_FLAGS
    caps_hdr = GROUP5_ABI_MAGIC + bytes(
        (GROUP5_ABI_VERSION, eff_caps & 0xFF, (eff_caps >> 8) & 0xFF, preset_count)
    )  # 8B
    ro_blob = fps_table_bytes + snap_regs_bytes + stock_fps_bytes + fps_reg_pairs + caps_hdr
    off_fps_table = 0
    off_snap_regs = len(fps_table_bytes)
    off_stock_fps = off_snap_regs + len(snap_regs_bytes)
    off_fps_regs = off_stock_fps + len(stock_fps_bytes)
    off_caps_hdr = off_fps_regs + len(fps_reg_pairs)
    ro_byte_lines = [
        ".balign 4",
        "ro_tables:",
        *[
            ".byte " + ", ".join(f"0x{b:02x}" for b in ro_blob[i : i + 12])
            for i in range(0, len(ro_blob), 12)
        ],
    ]

    code_lines = [
        # int spi_bank_read(r0=bank, r1=reg) -> r0=val, r1=ok(1|0)  (falls through into spi_wr_rb)
        "spi_bank_read:",
        "mov.w r2, #-1",
        # int spi_wr_rb(r0=bank, r1=reg, r2=val_or_neg1) -> r0=rb_val, r1=ok(1|0)
        "spi_wr_rb:",
        "push {r4, r5, r6, lr}",
        "mov r4, r1",
        "mov r5, r2",
        "mov r1, r0",
        "movs r0, #0x7f",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "cbz r0, swr_fail",
        "cmp r5, #0",
        "bmi swr_rd",
        "mov r0, r4",
        "mov r1, r5",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "cbz r0, swr_fail",
        "swr_rd:",
        "mov r0, r4",
        f"bl {T.FN_SPI_READ_REG:#x}",
        "cmp r5, #0",
        "bmi swr_ok",
        "cmp r0, r5",
        "bne swr_fail",
        "swr_ok:",
        "movs r1, #1",
        "pop {r4, r5, r6, pc}",
        "swr_fail:",
        "movs r1, #0",
        "pop {r4, r5, r6, pc}",

        # void apply_bool_adv(r0=bank, r1=reg, r2=val, r3=blk_app_off) (r4=PHASE2_RAM_BASE)
        "apply_bool_adv:",
        "push {r5, lr}",
        "mov r5, r3",
        "bl spi_wr_rb",
        "adds r2, r4, r5",
        "strb r0, [r2, #3]",  # RB_VAL
        "cbz r1, aba_err",
        "lsrs r0, r5, #2",
        "adds r0, #1",
        "ldrb r0, [r4, r0]",  # REQ
        "strb r0, [r2, #0]",  # APP
        "movs r0, #0",
        "strb r0, [r2, #1]",  # PEND
        "movs r0, #1",
        "strb r0, [r2, #2]",  # RB_OK
        "pop {r5, pc}",
        "aba_err:",
        "movs r0, #0",
        "strb r0, [r2, #2]",  # RB_OK = 0
        f"movs r0, #{ERR_READBACK_MISMATCH}",
        f"strb r0, [r4, #{P.OFF_LAST_ERR}]",
        "pop {r5, pc}",

        # void apply_id53_overrides(void)  (r5 tracks whether any SPI op ran, avoiding idle 0x7F=0 writes)
        "apply_id53_overrides:",
        "push {r4, r5, r6, r7, lr}",
        f"ldr r6, ={T.RAM_SENSOR_BRANCH:#x}",
        "ldrb r0, [r6, #0]",
        "cmp r0, #0x53",
        "bne aio_early",
        f"ldr r0, ={T.RAM_SPI_IDLE:#x}",
        f"ldrb r0, [r0, #{off_sens_en}]",
        "cbnz r0, aio_work",
        "aio_early:",
        "pop {r4, r5, r6, r7, pc}",
        "aio_work:",
        f"ldr r4, ={T.PHASE2_RAM_BASE:#x}",
        "movs r5, #0",
        # --- Downshift (05:44) ---
        f"ldrb r0, [r4, #{P.OFF_DS_REQ}]",
        f"ldrb r1, [r4, #{P.OFF_DS_APP}]",
        "orrs r0, r1",
        f"ldrb r1, [r4, #{P.OFF_DS_PEND}]",
        "orrs r0, r1",
        "cbz r0, ds_done",
        "movs r5, #1",
        "movs r0, #5",
        "movs r1, #0x44",
        "bl spi_bank_read",
        "cbz r1, ds_err",
        f"ldrb r1, [r4, #{P.OFF_DS_REQ}]",
        "cbz r1, ds_clr",
        "orr.w r2, r0, #0x40",
        "b ds_wr",
        "ds_clr:",
        "bic.w r2, r0, #0x40",
        "ds_wr:",
        "movs r0, #5",
        "movs r1, #0x44",
        f"movs r3, #{P.OFF_DS_APP}",
        "bl apply_bool_adv",
        "b ds_done",
        "ds_err:",
        "movs r0, #0",
        f"strb r0, [r4, #{P.OFF_DS_RB_OK}]",
        f"movs r0, #{ERR_READBACK_MISMATCH}",
        f"strb r0, [r4, #{P.OFF_LAST_ERR}]",
        "ds_done:",
        *(
            [
                "mov r0, r6",
                "mov r1, r4",
                "bl apply_fix_a_helper",
                "orrs r5, r0",
                "mov r0, r6",
                "mov r1, r4",
                "bl p3p_apply_ce_static",
                "orrs r5, r0",
                "mov r0, r6",
                "mov r1, r4",
                "bl p3p_apply_lod_raw",
                "orrs r5, r0",
            ]
            if phase3plus
            else []
        ),

        # --- FPS (07:42, 06:53, 06:62) ---
        f"ldrb r2, [r4, #{P.OFF_FPS_REQ}]",
        f"ldrb r1, [r4, #{P.OFF_FPS_APP}]",
        f"ldrb r0, [r4, #{P.OFF_FPS_PEND}]",
        "orrs r0, r1",
        "orrs r0, r2",
        "cbz r0, fps_done",
        "cbnz r2, fps_not_stock",
        f"ldrb r0, [r6, #{off_mode_tgt}]",
        "movs r2, #2",
        "cmp r0, #1",
        "bne fps_stock_tbl",
        "movs r2, #0",
        f"ldrh r1, [r6, #{off_cpi_x}]",
        f"ldrh r0, [r6, #{off_cpi_y}]",
        "movw r3, #7000",
        "cmp r1, r3",
        "bhs fps_hi",
        "cmp r0, r3",
        "blo fps_stock_tbl",
        "fps_hi:",
        "movs r2, #1",
        "fps_stock_tbl:",
        "movs r0, #3",
        "muls r2, r0",
        "adr r6, ro_tables",
        f"adds r6, #{off_stock_fps}",
        "add r6, r2",
        "b fps_write3",
        "fps_not_stock:",
        "cmp r2, #255",
        "bne fps_preset",
        f"addw r6, r4, #{P.OFF_CUSTOM_U}",
        "b fps_write3",
        "fps_preset:",
        "subs r0, r2, #1",
        "movs r1, #3",
        "muls r0, r1",
        "adr r6, ro_tables",
        "add r6, r0",
        "fps_write3:",
        "movs r0, #1",
        f"strb r0, [r4, #{P.OFF_FPS_RB_OK}]",
        "adr r7, ro_tables",
        f"adds r7, #{off_fps_regs}",
        "movs r5, #0",
        "fps_loop:",
        "ldrb r0, [r7, #0]",
        "ldrb r1, [r7, #1]",
        "adds r7, #2",
        "ldrb r2, [r6, r5]",
        "bl spi_wr_rb",
        f"addw r2, r5, #{P.OFF_FPS_RB_U}",
        "strb r0, [r4, r2]",
        "cbnz r1, fps_next",
        f"strb r1, [r4, #{P.OFF_FPS_RB_OK}]",
        "fps_next:",
        "adds r5, #1",
        "cmp r5, #3",
        "bne fps_loop",
        f"ldrb r0, [r4, #{P.OFF_FPS_RB_OK}]",
        "cbz r0, fps_err",
        f"ldrb r0, [r4, #{P.OFF_FPS_REQ}]",
        f"strb r0, [r4, #{P.OFF_FPS_APP}]",
        "movs r0, #0",
        f"strb r0, [r4, #{P.OFF_FPS_PEND}]",
        "b fps_done",
        "fps_err:",
        f"ldrb r0, [r4, #{P.OFF_FPS_FAIL_CNT}]",
        "adds r0, #1",
        f"strb r0, [r4, #{P.OFF_FPS_FAIL_CNT}]",
        f"movs r0, #{ERR_READBACK_MISMATCH}",
        f"strb r0, [r4, #{P.OFF_LAST_ERR}]",
        "fps_done:",

        # --- Smoothing (0C:4D) ---
        f"ldrb r2, [r4, #{P.OFF_SM_REQ}]",
        f"ldrb r1, [r4, #{P.OFF_SM_APP}]",
        f"ldrb r0, [r4, #{P.OFF_SM_PEND}]",
        "orrs r0, r1",
        "orrs r0, r2",
        "cbz r0, sm_done",
        "movs r5, #1",
        "cbz r2, sm_chk_stock",
        "movs r2, #2",
        "b sm_wr",
        "sm_chk_stock:",
        "movs r2, #2",
        f"ldr r0, ={T.RAM_SENSOR_BRANCH:#x}",
        f"ldrb r0, [r0, #{off_mode_tgt}]",
        "cmp r0, #1",
        "bne sm_wr",
        "movs r2, #0x90",
        "sm_wr:",
        "movs r0, #0x0c",
        "movs r1, #0x4d",
        f"movs r3, #{P.OFF_SM_APP}",
        "bl apply_bool_adv",
        "sm_done:",
        "cbz r5, aio_ret",
        "movs r0, #0x7f",
        "movs r1, #0",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "aio_ret:",
        "pop {r4, r5, r6, r7, pc}",

        # int spi_bus_ready(void) -> r0 = 1 ready, 0 busy
        "spi_bus_ready:",
        f"ldr r1, ={T.RAM_SPI_IDLE:#x}",
        "ldrb r0, [r1, #0]",
        "cbz r0, sbr_no",
        f"ldrb r0, [r1, #{off_spi_burst}]",
        "cbnz r0, sbr_no",
        "movs r0, #1",
        "bx lr",
        "sbr_no:",
        "movs r0, #0",
        "bx lr",

        # int override_worker(void)
        "override_worker:",
        "push {r4, lr}",
        "bl spi_bus_ready",
        "cbz r0, ow_ret",
        "bl apply_id53_overrides",
        f"ldr r4, ={T.PHASE2_RAM_BASE:#x}",
        "movs r0, #0",
        f"strb r0, [r4, #{P.OFF_WORKER_QUEUED}]",
        "movs r0, #1",
        "ow_ret:",
        "pop {r4, pc}",

        # H5 mode worker wrapper around 0x1D58C
        "cave_mode_worker:",
        "push {r4, lr}",
        f"bl {T.FN_SENSOR_MODE_WORKER & ~1:#x}",
        "cbz r0, cmw_out",
        "bl apply_id53_overrides",
        "movs r0, #1",
        "cmw_out:",
        "pop {r4, pc}",

        # H6 powerup tail
        "cave_powerup_tail:",
        "bl apply_id53_overrides",
        "pop.w {r3, r4, r5, r6, r7, r8, r9, pc}",

        # H7 mode apply tail (R5 = immediate)
        "cave_mode_apply_tail:",
        "cbz r5, cmat_pop",
        "bl apply_id53_overrides",
        "cmat_pop:",
        "pop {r4, r5, r6, pc}",
        *( [".ltorg"] if phase3plus else [] ),

        # int snapshot_worker(void)
        "snapshot_worker:",
        "push {r4, r5, r6, r7, lr}",
        "bl spi_bus_ready",
        "cbz r0, sn_retry",
        f"ldr r4, ={T.PHASE2_RAM_BASE:#x}",
        f"addw r7, r4, #{P.OFF_SNAP_BUF}",
        "adr r5, ro_tables",
        f"adds r5, #{off_snap_regs}",
        "movs r6, #0",
        "sn_loop:",
        "ldrb r0, [r5, #0]",
        "ldrb r1, [r5, #1]",
        "adds r5, #2",
        "bl spi_bank_read",
        "cbz r1, sn_bank0",
        "addw r2, r6, #16",
        "strb r0, [r7, r2]",
        "adds r6, #1",
        "cmp r6, #8",
        "bne sn_loop",
        "sn_bank0:",
        "movs r0, #0x7f",
        "movs r1, #0",
        f"bl {T.FN_SPI_WRITE_REG:#x}",
        "cbz r0, sn_fail_post",
        "cmp r6, #8",
        "bne sn_fail_post",
        "ldrh r0, [r7, #4]",
        "strh r0, [r7, #6]",
        f"ldr r1, ={T.RAM_SENSOR_BRANCH:#x}",
        "ldrb r0, [r1, #0]",
        "strb r0, [r7, #3]",
        f"ldrb r0, [r1, #{off_mode_tgt}]",
        "strb r0, [r7, #8]",
        f"ldrb r0, [r1, #{off_mode_app}]",
        "strb r0, [r7, #9]",
        f"ldrh r0, [r1, #{off_cpi_x}]",
        "strh r0, [r7, #10]",
        f"ldrh r0, [r1, #{off_cpi_y}]",
        "strh r0, [r7, #12]",
        "movs r0, #0",
        "strb r0, [r7, #2]",
        "movs r0, #2",
        "strb r0, [r7, #1]",
        "b sn_done",
        "sn_fail_post:",
        "adds r6, #1",
        "strb r6, [r7, #2]",
        "movs r0, #3",
        "strb r0, [r7, #1]",
        "movs r0, #0",
        "str r0, [r7, #16]",
        "str r0, [r7, #20]",
        "sn_done:",
        "movs r0, #1",
        "sn_retry:",
        "pop {r4, r5, r6, r7, pc}",

        # void memcpy_b(r0=dst, r1=src, r2=len) -> returns r0 = dst + len
        "memcpy_b:",
        "cbz r2, mc_done",
        "ldrb r3, [r1], #1",
        "strb r3, [r0], #1",
        "subs r2, #1",
        "b memcpy_b",
        "mc_done:",
        "bx lr",

        # int check_id53(void) -> r0 = 1 ok, 0 not_id53 (r5=PHASE2_RAM_BASE)
        "check_id53:",
        f"ldr r0, ={T.RAM_SENSOR_BRANCH:#x}",
        "ldrb r0, [r0]",
        "cmp r0, #0x53",
        "bne ci_no",
        "movs r0, #1",
        "bx lr",
        "ci_no:",
        f"movs r0, #{ERR_NOT_ID53}",
        f"strb r0, [r5, #{P.OFF_LAST_ERR}]",
        "movs r0, #0",
        "bx lr",

        # H2 trampoline + unified group5_dispatch (R0 = buf[4] >= 5, preserves R4..R9)
        "group5_trampoline:",
        "push {r4, r5, r6}",
        f"ldr r4, ={T.RAM_CMD_BUF:#x}",
        f"cmp r0, #{GROUP5_ID}",
        "bne g5_invalid",

        "group5_dispatch:",
        f"ldr r5, ={T.PHASE2_RAM_BASE:#x}",
        "ldrb r0, [r4, #5]",
        "ldrb r1, [r4, #3]",
        f"cmp r0, #{SUB_SNAP_TRIGGER}",
        "beq cmd_snap_trig",
        f"cmp r0, #{SUB_SET_FPS}",
        "beq cmd_set_fps",
        f"cmp r0, #{SUB_SET_DOWNSHIFT}",
        "beq cmd_set_ds",
        f"cmp r0, #{SUB_SET_SMOOTHING}",
        "beq cmd_set_sm",
        f"cmp r0, #{SUB_PERSIST_CTRL}",
        "beq.w cmd_persist_ctrl" if phase3plus else "beq cmd_persist_ctrl",
        *(
            [
                "cbnz r1, g5_invalid",
                f"cmp r0, #{SUB_GET_STATE}",
                "beq.w cmd_get_state",
                f"cmp r0, #{SUB_SNAP_READ}",
                "beq cmd_snap_read",
            ]
            if phase3_dispatch_addr is None
            else [
                f"cmp r0, #{SUB_GET_STATE}",
                "beq cmd_get_state_zchk",
                f"cmp r0, #{SUB_SNAP_READ}",
                "beq cmd_snap_read_zchk",
                "mov r2, r4",
                "mov r3, r5",
                f"bl {phase3_dispatch_addr:#x}",
                "cmp r0, #0",
                "beq g5_ret",
                *(
                    [
                        "cmp r0, #1",
                        "beq.w p3p_qow_tail",
                        "cmp r0, #2",
                        "beq.w p3p_qpeek_tail",
                    ]
                    if phase3plus
                    else []
                ),
                "cmp r0, #0xa2",
                "beq g5_fail",
            ]
        ),
        "g5_invalid:",
        "movs r0, #0xa3",
        "strb r0, [r4, #0]",
        "g5_ret:",
        "pop {r4, r5, r6}",
        f"b.w {T.GROUP5_COMMON_EXIT:#x}",
        "g5_fail:",
        "movs r0, #0xa2",
        "strb r0, [r4, #0]",
        "b g5_ret",
        *(
            [
                "cmd_get_state_zchk:",
                "cmp r1, #0",
                "bne g5_invalid",
                "b.w cmd_get_state",
                "cmd_snap_read_zchk:",
                "cmp r1, #0",
                "bne g5_invalid",
            ]
            if phase3_dispatch_addr is not None
            else []
        ),

        # 0x81 SNAP_READ: 24B
        "cmd_snap_read:",
        "movs r2, #24",
        "strb r2, [r4, #3]",
        "adds r0, r4, #6",
        f"addw r1, r5, #{P.OFF_SNAP_BUF}",
        "bl memcpy_b",
        "b g5_ret",

        # 0x01 SNAP_TRIGGER: payload = seq(u16 != 0)
        "cmd_snap_trig:",
        "cmp r1, #2",
        "bne g5_invalid",
        "ldrh r6, [r4, #6]",
        "cmp r6, #0",
        "beq g5_invalid",
        f"ldr r0, ={T.RAM_SPI_IDLE:#x}",
        f"ldrb r0, [r0, #{off_sens_en}]",
        "cmp r0, #0",
        "beq g5_fail",
        f"addw r3, r5, #{P.OFF_SNAP_BUF}",
        "ldrb r0, [r3, #1]",
        "cmp r0, #1",
        "beq g5_fail",
        "str r6, [r3, #4]",
        "movs r0, #0",
        "strb r0, [r3, #2]",
        "str r0, [r3, #16]",
        "str r0, [r3, #20]",
        "movs r0, #1",
        "strb r0, [r3, #1]",
        "mov r6, r3",
        "ldr r0, =snapshot_worker+1",
        f"bl {T.FN_WORKER_REGISTER:#x}",
        "cmp r0, #8",
        "blo cmd_snap_read",
        "movs r0, #0xff",
        "strb r0, [r6, #2]",
        "movs r0, #3",
        "strb r0, [r6, #1]",
        f"movs r0, #{ERR_WORKER_QUEUE_FULL}",
        f"strb r0, [r5, #{P.OFF_LAST_ERR}]",
        "b g5_fail",

        # 0x02 SET_FPS: len=1 (preset<8) or len=4 (255, u, slow, fast)
        "cmd_set_fps:",
        "ldrb r6, [r4, #6]",
        "cmp r1, #1",
        "beq sf_preset",
        "cmp r1, #4",
        "bne g5_invalid",
        "cmp r6, #255",
        "bne g5_invalid",
        "mov r0, r6",
        "ldrb r1, [r4, #7]",
        "ldrb r2, [r4, #8]",
        "ldrb r3, [r4, #9]",
        f"bl {valid_fps_addr:#x}",
        "cmp r0, #0",
        "beq g5_invalid",
        "b sf_chk_id53",
        "sf_preset:",
        f"cmp r6, #{preset_count}",
        "bhs g5_invalid",
        "sf_chk_id53:",
        "bl check_id53",
        "cmp r0, #0",
        "beq g5_fail",
        f"strb r6, [r5, #{P.OFF_FPS_REQ}]",
        "cmp r6, #255",
        "bne sf_not_c",
        "ldrb r0, [r4, #7]",
        f"strb r0, [r5, #{P.OFF_CUSTOM_U}]",
        "ldrb r0, [r4, #8]",
        f"strb r0, [r5, #{P.OFF_CUSTOM_SLOW}]",
        "ldrb r0, [r4, #9]",
        f"strb r0, [r5, #{P.OFF_CUSTOM_FAST}]",
        "sf_not_c:",
        "movs r0, #1",
        f"strb r0, [r5, #{P.OFF_FPS_PEND}]",
        "movs r0, #0",
        f"strb r0, [r5, #{P.OFF_FPS_RB_OK}]",
        "b qow_state_tail",

        # 0x03 SET_DOWNSHIFT / 0x04 SET_SMOOTHING (r0 = OFF_DS_REQ=6 or OFF_SM_REQ=7)
        "cmd_set_ds:",
        f"movs r0, #{P.OFF_DS_REQ}",
        "b sb_go",
        "cmd_set_sm:",
        f"movs r0, #{P.OFF_SM_REQ}",
        "sb_go:",
        "mov r6, r0",
        "cmp r1, #1",
        "bne g5_invalid",
        "ldrb r2, [r4, #6]",
        "cmp r2, #1",
        "bhi g5_invalid",
        "bl check_id53",
        "cmp r0, #0",
        "beq g5_fail",
        "ldrb r2, [r4, #6]",
        "strb r2, [r5, r6]",
        "subs r6, #1",
        "lsls r6, r6, #2",
        "adds r6, #2",
        "movs r0, #1",
        "strb r0, [r5, r6]",
        "adds r6, #1",
        "movs r0, #0",
        "strb r0, [r5, r6]",
        "b qow_state_tail",

        # 0x05 PERSIST_CTRL: 1=save now, 2=reset flash + restore stock, 3=queue async save
        "cmd_persist_ctrl:",
        "cmp r1, #1",
        "bne g5_invalid",
        "ldrb r0, [r4, #6]",
        "cmp r0, #1",
        "beq pc_save",
        "cmp r0, #2",
        "beq pc_reset",
        "cmp r0, #3",
        "bne g5_invalid",
        "movs r0, #1",
        f"strb r0, [r5, #{P.OFF_PERSIST_PEND}]",
        "b cmd_get_state",
        "pc_save:",
        f"bl {cfg_save_addr:#x}",
        "pc_chk:",
        "cbnz r0, cmd_get_state",
        f"movs r0, #{ERR_PERSIST_FAILED}",
        f"strb r0, [r5, #{P.OFF_LAST_ERR}]",
        "b g5_fail",
        "pc_reset:",
        f"bl {cfg_reset_addr:#x}",
        "cmp r0, #0",
        "beq pc_chk",
        "movs r2, #0",
        f"ldrb r0, [r5, #{P.OFF_FPS_APP}]",
        f"ldrb r1, [r5, #{P.OFF_FPS_PEND}]",
        "orrs r0, r1",
        "cbz r0, pr_ds",
        "movs r2, #1",
        f"strb r2, [r5, #{P.OFF_FPS_PEND}]",
        "pr_ds:",
        f"ldrb r0, [r5, #{P.OFF_DS_APP}]",
        f"ldrb r1, [r5, #{P.OFF_DS_PEND}]",
        "orrs r0, r1",
        f"strb r0, [r5, #{P.OFF_DS_PEND}]",
        "orrs r2, r0",
        f"ldrb r0, [r5, #{P.OFF_SM_APP}]",
        f"ldrb r1, [r5, #{P.OFF_SM_PEND}]",
        "orrs r0, r1",
        f"strb r0, [r5, #{P.OFF_SM_PEND}]",
        "orrs r2, r0",
        *(
            [
                f"ldr r0, ={T.PHASE3_RAM_BASE:#x}",
                f"ldrb.w r0, [r0, #{D.OFF_FIX_A_STATE}]",
                "tst.w r0, #6",
                "bne pr_fa_set",
                f"ldr r0, ={T.PHASE3_RAM_BASE:#x}",
                f"ldrb.w r0, [r0, #{D.OFF_CE_STATIC_STATE}]",
                "tst.w r0, #6",
                "bne pr_fa_set",
                f"ldr r0, ={T.PHASE3_RAM_BASE:#x}",
                f"ldrb.w r0, [r0, #{D.OFF_LOD_RAW_STATE}]",
                "tst.w r0, #6",
                "beq pr_fa_done",
                "pr_fa_set:",
                "movs r2, #1",
                "pr_fa_done:",
            ]
            if phase3plus
            else []
        ),
        "cbz r2, cmd_get_state",

        # Single shared queue_override_worker tail -> cmd_get_state (or g5_fail)
        "qow_state_tail:",
        f"ldrb r0, [r5, #{P.OFF_WORKER_QUEUED}]",
        "cbnz r0, cmd_get_state",
        f"ldr r0, ={T.RAM_SPI_IDLE:#x}",
        f"ldrb r0, [r0, #{off_sens_en}]",
        "cbz r0, cmd_get_state",
        "ldr r0, =override_worker+1",
        f"bl {T.FN_WORKER_REGISTER:#x}",
        "cmp r0, #8",
        "blo qow_mark",
        f"movs r0, #{ERR_WORKER_QUEUE_FULL}",
        f"strb r0, [r5, #{P.OFF_LAST_ERR}]",
        "b g5_fail",
        "qow_mark:",
        "movs r0, #1",
        f"strb r0, [r5, #{P.OFF_WORKER_QUEUED}]",
        # 0x80 GET_STATE: 51B = caps_hdr(8) + branch(1) + RAM[4..35](32) + deb_pers(4) + deb_live(6)
        "cmd_get_state:",
        "movs r0, #51",
        "strb r0, [r4, #3]",
        "adds r0, r4, #6",
        "adr r1, ro_tables",
        f"adds r1, #{off_caps_hdr}",
        "movs r2, #8",
        "bl memcpy_b",
        f"ldr r1, ={T.RAM_SENSOR_BRANCH:#x}",
        "ldrb r1, [r1]",
        "strb r1, [r0], #1",
        "adds r1, r5, #4",
        "movs r2, #32",
        "bl memcpy_b",
        f"ldr r1, ={T.RAM_DEBOUNCE_PERSISTED:#x}",
        "movs r2, #4",
        "bl memcpy_b",
        f"ldr r1, ={T.RAM_BUTTON_THRESH_LIVE:#x}",
        "movs r2, #6",
        "bl memcpy_b",
        "b g5_ret",
        *ro_byte_lines,
        *(
            [
                ".balign 2",
                # Queue override_worker without overwriting existing reply payload in cmd_buf
                "p3p_qow_tail:",
                f"ldrb r0, [r5, #{P.OFF_WORKER_QUEUED}]",
                "cmp r0, #0",
                "bne.w g5_ret",
                f"ldr r0, ={T.RAM_SPI_IDLE:#x}",
                f"ldrb r0, [r0, #{off_sens_en}]",
                "cmp r0, #0",
                "beq.w g5_ret",
                "ldr r0, =override_worker+1",
                f"bl {T.FN_WORKER_REGISTER:#x}",
                "cmp r0, #8",
                "blo p3p_qow_ok",
                f"movs r0, #{ERR_WORKER_QUEUE_FULL}",
                f"strb r0, [r5, #{P.OFF_LAST_ERR}]",
                "b g5_fail",
                "p3p_qow_ok:",
                "movs r0, #1",
                f"strb r0, [r5, #{P.OFF_WORKER_QUEUED}]",
                "b g5_ret",

                # Queue cooperative SPI peek_worker without overwriting reply payload in cmd_buf
                "p3p_qpeek_tail:",
                f"ldr r0, ={T.RAM_SPI_IDLE:#x}",
                f"ldrb r0, [r0, #{off_sens_en}]",
                "cmp r0, #0",
                "beq.w g5_ret",
                "ldr r0, =p3p_peek_worker+1",
                f"bl {T.FN_WORKER_REGISTER:#x}",
                "cmp r0, #8",
                "blo p3p_qpk_ok",
                f"ldr r1, ={T.PHASE3_RAM_BASE:#x}",
                "movs r0, #0",
                f"strb.w r0, [r1, #{D.OFF_PEEK_PENDING}]",
                f"movs r0, #{ERR_WORKER_QUEUE_FULL}",
                f"strb.w r0, [r1, #{D.OFF_PEEK_ERR}]",
                f"strb r0, [r5, #{P.OFF_LAST_ERR}]",
                "b g5_fail",
                "p3p_qpk_ok:",
                "b g5_ret",
                ".ltorg",

                # int apply_fix_a_helper(r0=RAM_SENSOR_BRANCH, r1=PHASE2_RAM_BASE) -> 1 if SPI ran else 0
                "apply_fix_a_helper:",
                "push {r4, r5, r6, r7, lr}",
                f"ldr r4, ={T.PHASE3_RAM_BASE:#x}",
                f"ldrb.w r2, [r4, #{D.OFF_FIX_A_STATE}]",
                "tst.w r2, #7",
                "bne fa_go",
                "movs r0, #0",
                "pop {r4, r5, r6, r7, pc}",
                "fa_go:",
                "push {r1}",
                "tst.w r2, #1",
                "beq fa_stock_cap",
                "movs r5, #0x57",
                "movs r6, #2",
                "b fa_write_regs",
                "fa_stock_cap:",
                "movs r5, #0x4f",
                "movs r6, #0",
                f"ldrb r2, [r0, #{off_mode_tgt}]",
                "cmp r2, #1",
                "bne fa_write_regs",
                f"ldrh r2, [r0, #{off_cpi_x}]",
                f"ldrh r3, [r0, #{off_cpi_y}]",
                "movw r1, #7000",
                "cmp r2, r1",
                "bhs fa_stock_hi",
                "cmp r3, r1",
                "blo fa_write_regs",
                "fa_stock_hi:",
                "movs r5, #0x95",
                "fa_write_regs:",
                "movs r7, #1",
                # PAW3950 unlock (07:40 = 0x41) before writing Bank 0 0x4E/4F/51/52
                "movs r0, #0x7f",
                "movs r1, #7",
                f"bl {T.FN_SPI_WRITE_REG:#x}",
                "cbnz r0, fa_u1",
                "movs r7, #0",
                "fa_u1:",
                "movs r0, #0x40",
                "movs r1, #0x41",
                f"bl {T.FN_SPI_WRITE_REG:#x}",
                "cbnz r0, fa_u2",
                "movs r7, #0",
                "fa_u2:",
                # Select Bank 0, write 4F/4E/52/51, and latch via 00:47 = 0x01
                "movs r0, #0x7f",
                "movs r1, #0",
                f"bl {T.FN_SPI_WRITE_REG:#x}",
                "cbnz r0, fa_w4f",
                "movs r7, #0",
                "fa_w4f:",
                "movs r0, #0x4f",
                "mov r1, r5",
                f"bl {T.FN_SPI_WRITE_REG:#x}",
                "cbnz r0, fa_w4e",
                "movs r7, #0",
                "fa_w4e:",
                "movs r0, #0x4e",
                "mov r1, r6",
                f"bl {T.FN_SPI_WRITE_REG:#x}",
                "cbnz r0, fa_w52",
                "movs r7, #0",
                "fa_w52:",
                "movs r0, #0x52",
                "mov r1, r5",
                f"bl {T.FN_SPI_WRITE_REG:#x}",
                "cbnz r0, fa_w51",
                "movs r7, #0",
                "fa_w51:",
                "movs r0, #0x51",
                "mov r1, r6",
                f"bl {T.FN_SPI_WRITE_REG:#x}",
                "cbnz r0, fa_w47",
                "movs r7, #0",
                "fa_w47:",
                "movs r0, #0x47",
                "movs r1, #1",
                f"bl {T.FN_SPI_WRITE_REG:#x}",
                "cbnz r0, fa_l1",
                "movs r7, #0",
                "fa_l1:",
                # Lock (07:40 = 0x40) and return cleanly to Bank 0
                "movs r0, #0x7f",
                "movs r1, #7",
                f"bl {T.FN_SPI_WRITE_REG:#x}",
                "cbnz r0, fa_l2",
                "movs r7, #0",
                "fa_l2:",
                "movs r0, #0x40",
                "movs r1, #0x40",
                f"bl {T.FN_SPI_WRITE_REG:#x}",
                "cbnz r0, fa_l3",
                "movs r7, #0",
                "fa_l3:",
                "movs r0, #0x7f",
                "movs r1, #0",
                f"bl {T.FN_SPI_WRITE_REG:#x}",
                "cbnz r0, fa_rb4f",
                "movs r7, #0",
                "fa_rb4f:",
                # Read back all 4 registers after latch + lock
                "movs r0, #0x4f",
                f"bl {T.FN_SPI_READ_REG:#x}",
                f"strb.w r0, [r4, #{D.OFF_FIX_A_RB_VAL}]",
                "cmp r0, r5",
                "beq fa_rb4e",
                "movs r7, #0",
                "fa_rb4e:",
                "movs r0, #0x4e",
                f"bl {T.FN_SPI_READ_REG:#x}",
                f"strb.w r0, [r4, #{D.OFF_FIX_A_RB_VAL + 1}]",
                "cmp r0, r6",
                "beq fa_rb52",
                "movs r7, #0",
                "fa_rb52:",
                "movs r0, #0x52",
                f"bl {T.FN_SPI_READ_REG:#x}",
                "cmp r0, r5",
                "beq fa_rb51",
                "movs r7, #0",
                "fa_rb51:",
                "movs r0, #0x51",
                f"bl {T.FN_SPI_READ_REG:#x}",
                "cmp r0, r6",
                "beq fa_update",
                "movs r7, #0",
                "fa_update:",
                "pop {r2}",
                f"ldrb.w r0, [r4, #{D.OFF_FIX_A_STATE}]",
                "cbz r7, fa_err",
                "and.w r0, r0, #1",
                "lsls r1, r0, #1",
                "orrs r0, r1",
                "orr.w r0, r0, #8",
                f"strb.w r0, [r4, #{D.OFF_FIX_A_STATE}]",
                "movs r0, #1",
                "pop {r4, r5, r6, r7, pc}",
                "fa_err:",
                "and.w r0, r0, #7",
                f"strb.w r0, [r4, #{D.OFF_FIX_A_STATE}]",
                f"ldrb.w r1, [r4, #{D.OFF_FIX_A_FAIL_CNT}]",
                "adds r1, #1",
                f"strb.w r1, [r4, #{D.OFF_FIX_A_FAIL_CNT}]",
                f"movs r1, #{ERR_READBACK_MISMATCH}",
                f"strb r1, [r2, #{P.OFF_LAST_ERR}]",
                "movs r0, #1",
                "pop {r4, r5, r6, r7, pc}",
            ]
            if phase3plus
            else []
        ),
        ".ltorg",
    ]

    core_base = ctx.alloc_asm(
        "group5_core",
        code_lines,
        align=4,
        export_labels=(
            "apply_id53_overrides",
            "override_worker",
            "cave_mode_worker",
            "cave_powerup_tail",
            "cave_mode_apply_tail",
            "snapshot_worker",
            "group5_trampoline",
            "group5_dispatch",
            "ro_tables",
        ),
        module="group5",
        reason="Group 5 unified dispatcher, cooperative snapshot/override workers, and ID53 isolation",
    )

    trampoline_addr = builder.symbols["group5_trampoline"]
    mode_worker_addr = builder.symbols["cave_mode_worker"]
    powerup_tail_addr = builder.symbols["cave_powerup_tail"]
    mode_apply_tail_addr = builder.symbols["cave_mode_apply_tail"]
    ro_base = builder.symbols["ro_tables"]

    # H2: default arm at 0x1923E..0x19245 -> b.w group5_trampoline; nop; nop
    h2_bytes = encode_b_w(T.HOOK_H2_GROUP5_DEFAULT, trampoline_addr)
    verified_h2 = verify_branch_patch(
        h2_bytes,
        T.HOOK_H2_GROUP5_DEFAULT,
        "b.w",
        trampoline_addr,
    )
    builder.edit(
        T.HOOK_H2_GROUP5_DEFAULT,
        h2_bytes + b"\x00\xbf\x00\xbf",
        expected_old=T.PREIMAGES["h2_group5_default"].expected,
        module="group5",
        reason="H2: Redirect Family A switch default (buf[4] >= 5) to group5_trampoline",
    )
    ctx.branch_patches.append(verified_h2)

    # H5: patch literal pointer 0x0001D588 -> cave_mode_worker | 1
    builder.edit_u32(
        T.HOOK_H5_MODE_WORKER_PTR,
        mode_worker_addr | 1,
        expected_old_u32=T.FN_SENSOR_MODE_WORKER,
        module="group5",
        reason="H5: Wrap cooperative mode worker 0x1D58D to re-apply ID53 overrides when done==1",
    )

    # H6: patch sole exit POP.W {R3-R9,PC} of 0x1CC6C -> b.w cave_powerup_tail
    ctx.patch_b_w(
        T.HOOK_H6_POWERUP_TAIL,
        powerup_tail_addr,
        expected_old=T.PREIMAGES["h6_powerup_tail"].expected,
        module="group5",
        reason="H6: Apply ID53 overrides on sensor powerup & wake (0x1D00A)",
    )

    # H7: patch POP {R4-R6,PC}; MOVS R0,R0 of 0x1D570 -> b.w cave_mode_apply_tail
    ctx.patch_b_w(
        T.HOOK_H7_MODE_APPLY_TAIL,
        mode_apply_tail_addr,
        expected_old=T.PREIMAGES["h7_mode_apply_tail"].expected,
        module="group5",
        reason="H7: Re-apply ID53 overrides after immediate mode switch (0x1D570, R5!=0)",
    )

    return {
        "enabled": True,
        "group_id": GROUP5_ID,
        "subcommands": {
            "GET_STATE": f"0x{SUB_GET_STATE:02X}",
            "SNAP_TRIGGER": f"0x{SUB_SNAP_TRIGGER:02X}",
            "SNAP_READ": f"0x{SUB_SNAP_READ:02X}",
            "SET_FPS": f"0x{SUB_SET_FPS:02X}",
            "SET_DOWNSHIFT": f"0x{SUB_SET_DOWNSHIFT:02X}",
            "SET_SMOOTHING": f"0x{SUB_SET_SMOOTHING:02X}",
            "PERSIST_CTRL": f"0x{SUB_PERSIST_CTRL:02X}",
            **(
                {
                    "GET_P3_STATE": f"0x{D.SUB_GET_P3_STATE:02X}",
                    "GET_P3_DIAG": f"0x{D.SUB_GET_P3_DIAG:02X}",
                    "SET_P3_CTRL": f"0x{D.SUB_SET_P3_CTRL:02X}",
                    "RESET_P3_DIAG": f"0x{D.SUB_RESET_P3_DIAG:02X}",
                }
                if phase3_dispatch_addr is not None
                else {}
            ),
            **(
                {
                    "GET_P1_STATE": f"0x{D.SUB_GET_P1_STATE:02X}",
                    "SET_P1_CFG": f"0x{D.SUB_SET_P1_CFG:02X}",
                }
                if phase3plus
                else {}
            ),
        },
        "fps_preset_count": preset_count,
        "ro_tables_base": f"0x{ro_base:08X}",
        "ro_tables_bytes": len(ro_blob),
        "code_base": f"0x{core_base:08X}",
        "symbols": {
            "apply_id53_overrides": f"0x{builder.symbols['apply_id53_overrides']:08X}",
            "override_worker": f"0x{builder.symbols['override_worker']:08X}",
            "snapshot_worker": f"0x{builder.symbols['snapshot_worker']:08X}",
            "group5_trampoline": f"0x{trampoline_addr:08X}",
            "group5_dispatch": f"0x{builder.symbols['group5_dispatch']:08X}",
            "cave_mode_worker": f"0x{mode_worker_addr:08X}",
            "cave_powerup_tail": f"0x{powerup_tail_addr:08X}",
            "cave_mode_apply_tail": f"0x{mode_apply_tail_addr:08X}",
        },
        "id53_isolation_branch_addr": f"0x{T.RAM_SENSOR_BRANCH:08X}",
        "worker_queue_base": f"0x{T.RAM_WORKER_PENDING:08X}",
    }
