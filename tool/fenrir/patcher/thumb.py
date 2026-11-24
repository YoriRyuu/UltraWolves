"""Minimal deterministic Thumb/Thumb-2 encoder with mandatory Capstone round-trip verification."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Any, Sequence

import capstone
from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB
from capstone.arm_const import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

_CS = capstone.Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
_CS.detail = True


class ThumbEncodeError(ValueError):
    """Raised when Thumb assembly syntax, range, or Capstone round-trip verification fails."""


@dataclass(frozen=True)
class VerifiedInstruction:
    """Single Capstone-verified Thumb/Thumb-2 instruction."""

    address: int
    size: int
    hex_bytes: str
    mnemonic: str
    op_str: str
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:08X}",
            "size": self.size,
            "bytes": self.hex_bytes,
            "asm": f"{self.mnemonic} {self.op_str}".strip(),
            "source": self.source,
        }


@dataclass(frozen=True)
class AssembledBlock:
    """Result of assembling and Capstone-verifying a Thumb/Thumb-2 code block."""

    name: str
    address: int
    data: bytes
    labels: dict[str, int]
    instructions: tuple[VerifiedInstruction, ...]
    capstone_verified: bool

    def to_report_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "address": f"0x{self.address:08X}",
            "size": len(self.data),
            "instruction_count": len(self.instructions),
            "capstone_verified": self.capstone_verified,
            "labels": {k: f"0x{v:08X}" for k, v in sorted(self.labels.items())},
            "instructions": [i.to_dict() for i in self.instructions],
        }


_REGS: dict[str, int] = {
    **{f"r{i}": i for i in range(13)},
    "sb": 9,
    "sl": 10,
    "fp": 11,
    "ip": 12,
    "sp": 13,
    "r13": 13,
    "lr": 14,
    "r14": 14,
    "pc": 15,
    "r15": 15,
}

_CONDS: dict[str, int] = {
    "eq": 0x0,
    "ne": 0x1,
    "cs": 0x2,
    "hs": 0x2,
    "cc": 0x3,
    "lo": 0x3,
    "mi": 0x4,
    "pl": 0x5,
    "vs": 0x6,
    "vc": 0x7,
    "hi": 0x8,
    "ls": 0x9,
    "ge": 0xA,
    "lt": 0xB,
    "gt": 0xC,
    "le": 0xD,
}


def _pack16(hw: int) -> bytes:
    return struct.pack("<H", hw & 0xFFFF)


def _pack32_t2(hw1: int, hw2: int) -> bytes:
    return struct.pack("<HH", hw1 & 0xFFFF, hw2 & 0xFFFF)


def _parse_reg(token: str, *, max_reg: int = 15, allow_sp: bool = True, allow_pc: bool = True) -> int:
    key = token.strip().lower()
    if key not in _REGS:
        raise ThumbEncodeError(f"Unknown register '{token}'")
    r = _REGS[key]
    if r > max_reg:
        raise ThumbEncodeError(f"Register '{token}' exceeds r{max_reg} limit for this encoding")
    if r == 13 and not allow_sp:
        raise ThumbEncodeError("SP not permitted in this instruction")
    if r == 15 and not allow_pc:
        raise ThumbEncodeError("PC not permitted in this instruction")
    return r


def _parse_int(token: str) -> int:
    s = token.strip()
    if s.startswith("#"):
        s = s[1:].strip()
    try:
        return int(s, 0)
    except ValueError as exc:
        raise ThumbEncodeError(f"Invalid integer literal '{token}'") from exc


def _eval_expr(expr: str, symbols: dict[str, int]) -> int:
    s = expr.strip()
    if s.startswith("#"):
        s = s[1:].strip()
    if s in symbols:
        return symbols[s]
    # Support simple "sym + off", "sym - off", "sym | 1"
    for op in ("|", "+", "-"):
        if op in s and not s.startswith("-"):
            lhs, rhs = s.split(op, 1)
            lhs_s, rhs_s = lhs.strip(), rhs.strip()
            if lhs_s in symbols:
                lval = symbols[lhs_s]
            else:
                lval = int(lhs_s, 0)
            if rhs_s in symbols:
                rval = symbols[rhs_s]
            else:
                rval = int(rhs_s, 0)
            if op == "+":
                return lval + rval
            if op == "-":
                return lval - rval
            return lval | rval
    try:
        return int(s, 0)
    except ValueError as exc:
        raise ThumbEncodeError(f"Unresolved symbol or expression '{expr}'") from exc


def _split_operands(op_str: str) -> list[str]:
    """Split comma-separated operands respecting [...] and {...} brackets."""
    out: list[str] = []
    cur: list[str] = []
    depth_sq = 0
    depth_cu = 0
    for ch in op_str:
        if ch == "[":
            depth_sq += 1
        elif ch == "]":
            depth_sq -= 1
        elif ch == "{":
            depth_cu += 1
        elif ch == "}":
            depth_cu -= 1
        if ch == "," and depth_sq == 0 and depth_cu == 0:
            part = "".join(cur).strip()
            if part:
                out.append(part)
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def _parse_reglist(token: str) -> set[int]:
    s = token.strip()
    if not (s.startswith("{") and s.endswith("}")):
        raise ThumbEncodeError(f"Expected register list {{...}}, got '{token}'")
    inner = s[1:-1].strip()
    if not inner:
        raise ThumbEncodeError("Empty register list")
    regs: set[int] = set()
    for part in inner.split(","):
        p = part.strip()
        if "-" in p:
            a, b = p.split("-", 1)
            ra = _parse_reg(a)
            rb = _parse_reg(b)
            if rb < ra:
                raise ThumbEncodeError(f"Invalid register range '{p}'")
            for r in range(ra, rb + 1):
                regs.add(r)
        else:
            regs.add(_parse_reg(p))
    return regs


def _parse_mem_operand(token: str) -> tuple[int, int, str | None, bool]:
    """Parse [rn], [rn, #imm], [rn, rm], or [rn], #imm (post-index).

    Returns (rn, offset_imm, index_reg_or_none, post_index).
    """
    s = token.strip()
    m_post = re.fullmatch(r"\[([^\]]+)\]\s*,\s*(#.+|[-+]?(?:0x)?[0-9a-fA-F]+)", s)
    if m_post:
        rn = _parse_reg(m_post.group(1), allow_pc=False)
        imm = _parse_int(m_post.group(2))
        return rn, imm, None, True

    if not (s.startswith("[") and s.endswith("]")):
        raise ThumbEncodeError(f"Expected memory operand [...], got '{token}'")
    inner = [p.strip() for p in s[1:-1].split(",")]
    if len(inner) == 1:
        rn = _parse_reg(inner[0], allow_pc=False)
        return rn, 0, None, False
    if len(inner) == 2:
        rn = _parse_reg(inner[0], allow_pc=False)
        second = inner[1]
        if second.lower() in _REGS:
            return rn, 0, second.lower(), False
        return rn, _parse_int(second), None, False
    raise ThumbEncodeError(f"Unsupported memory operand '{token}'")


def encode_thumb_mod_imm(value: int) -> int | None:
    """Encode a 32-bit value as a 12-bit ThumbExpandImm (i:imm3:abcdefgh), or None."""
    v = value & 0xFFFFFFFF
    if v <= 0xFF:
        return v
    b0 = v & 0xFF
    if v == ((b0 << 16) | b0):
        return (1 << 8) | b0
    b1 = (v >> 8) & 0xFF
    if v == ((b1 << 24) | (b1 << 8)):
        return (2 << 8) | b1
    if v == (b0 | (b0 << 8) | (b0 << 16) | (b0 << 24)):
        return (3 << 8) | b0
    for rot in range(8, 32):
        # ThumbExpandImm rotates 8-bit 1xxxxxxx right by `rot` bits (equivalent to left by 32-rot)
        unrot = ((v << rot) | (v >> (32 - rot))) & 0xFFFFFFFF
        if 0x80 <= unrot <= 0xFF:
            return (rot << 7) | (unrot & 0x7F)
    return None


def encode_bl(pc: int, target: int) -> bytes:
    """Encode Thumb-2 BL (T1) from `pc` to `target`."""
    offset = (target & ~1) - (pc + 4)
    if offset & 1:
        raise ThumbEncodeError(f"Unaligned BL offset {offset}")
    if not (-16777216 <= offset <= 16777214):
        raise ThumbEncodeError(f"BL target 0x{target:08X} out of ±16 MiB range from 0x{pc:08X}")
    s = (offset >> 24) & 1
    i1 = (offset >> 23) & 1
    i2 = (offset >> 22) & 1
    j1 = (~(i1 ^ s)) & 1
    j2 = (~(i2 ^ s)) & 1
    imm10 = (offset >> 12) & 0x3FF
    imm11 = (offset >> 1) & 0x7FF
    hw1 = 0xF000 | (s << 10) | imm10
    hw2 = 0xD000 | (j1 << 13) | (j2 << 11) | imm11
    return _pack32_t2(hw1, hw2)


def encode_b_w(pc: int, target: int) -> bytes:
    """Encode Thumb-2 B.W (T4) from `pc` to `target`."""
    offset = (target & ~1) - (pc + 4)
    if offset & 1:
        raise ThumbEncodeError(f"Unaligned B.W offset {offset}")
    if not (-16777216 <= offset <= 16777214):
        raise ThumbEncodeError(f"B.W target 0x{target:08X} out of ±16 MiB range from 0x{pc:08X}")
    s = (offset >> 24) & 1
    i1 = (offset >> 23) & 1
    i2 = (offset >> 22) & 1
    j1 = (~(i1 ^ s)) & 1
    j2 = (~(i2 ^ s)) & 1
    imm10 = (offset >> 12) & 0x3FF
    imm11 = (offset >> 1) & 0x7FF
    hw1 = 0xF000 | (s << 10) | imm10
    hw2 = 0x9000 | (j1 << 13) | (j2 << 11) | imm11
    return _pack32_t2(hw1, hw2)


def encode_bcc_w(pc: int, cond: int, target: int) -> bytes:
    """Encode Thumb-2 B<cc>.W (T3) from `pc` to `target`."""
    offset = (target & ~1) - (pc + 4)
    if offset & 1:
        raise ThumbEncodeError(f"Unaligned B<cc>.W offset {offset}")
    if not (-1048576 <= offset <= 1048574):
        raise ThumbEncodeError(f"B<cc>.W target 0x{target:08X} out of ±1 MiB range from 0x{pc:08X}")
    s = (offset >> 20) & 1
    j2 = (offset >> 19) & 1
    j1 = (offset >> 18) & 1
    imm6 = (offset >> 12) & 0x3F
    imm11 = (offset >> 1) & 0x7FF
    hw1 = 0xF000 | (s << 10) | (cond << 6) | imm6
    hw2 = 0x8000 | (j1 << 13) | (j2 << 11) | imm11
    return _pack32_t2(hw1, hw2)


def disassemble(data: bytes, base_addr: int) -> list[VerifiedInstruction]:
    """Disassemble bytes via Capstone Thumb-2 M-class engine."""
    return [
        VerifiedInstruction(
            address=insn.address,
            size=insn.size,
            hex_bytes=bytes(insn.bytes).hex(),
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
        )
        for insn in _CS.disasm(data, base_addr)
    ]


def verify_branch_patch(
    raw_bytes: bytes,
    addr: int,
    expected_mnemonic: str,
    expected_target: int,
) -> VerifiedInstruction:
    """Verify a 4-byte BL or B.W patch encoding via Capstone."""
    insns = list(_CS.disasm(raw_bytes, addr))
    if len(insns) != 1 or sum(i.size for i in insns) != len(raw_bytes):
        raise ThumbEncodeError(
            f"Patch at 0x{addr:08X} did not disassemble as single instruction: {raw_bytes.hex()}"
        )
    insn = insns[0]
    if insn.mnemonic != expected_mnemonic:
        raise ThumbEncodeError(
            f"Patch at 0x{addr:08X}: expected '{expected_mnemonic}', Capstone got '{insn.mnemonic} {insn.op_str}'"
        )
    if not insn.operands or insn.operands[0].type != ARM_OP_IMM:
        raise ThumbEncodeError(f"Patch at 0x{addr:08X} missing immediate target")
    actual_target = insn.operands[0].imm & 0xFFFFFFFF
    if actual_target != (expected_target & ~1):
        raise ThumbEncodeError(
            f"Patch at 0x{addr:08X}: target mismatch expected 0x{expected_target & ~1:08X}, "
            f"got 0x{actual_target:08X}"
        )
    return VerifiedInstruction(
        address=insn.address,
        size=insn.size,
        hex_bytes=bytes(insn.bytes).hex(),
        mnemonic=insn.mnemonic,
        op_str=insn.op_str,
        source=f"{expected_mnemonic} 0x{expected_target:08X}",
    )


@dataclass
class _Item:
    kind: str  # "insn" | "data" | "ltorg" | "align"
    offset: int
    size: int
    raw_line: str
    mnemonic: str = ""
    op_str: str = ""
    literal_key: tuple[str, str] | None = None
    pool_idx: int = -1
    data_kind: str = ""
    data_exprs: tuple[str, ...] = ()
    align_n: int = 1


_MNEMONIC_ALIASES: dict[str, set[str]] = {
    "b": {"b", "b.w"},
    "b.w": {"b.w", "b"},
    "bl": {"bl"},
    "mov": {"mov", "mov.w", "movs"},
    "movs": {"movs", "mov", "lsls"},
    "mov.w": {"mov.w", "mov"},
    "add": {"add", "adds", "add.w"},
    "adds": {"adds", "add", "add.w"},
    "add.w": {"add.w", "add"},
    "addw": {"addw", "add.w", "add"},
    "sub": {"sub", "subs", "sub.w"},
    "subs": {"subs", "sub", "sub.w"},
    "sub.w": {"sub.w", "sub"},
    "subw": {"subw", "sub.w", "sub"},
    "cmp.w": {"cmp.w", "cmp"},
    "tst.w": {"tst", "tst.w"},
    "and.w": {"and", "and.w"},
    "orr.w": {"orr", "orr.w"},
    "bic.w": {"bic", "bic.w"},
    "eor.w": {"eor", "eor.w"},
    "lsl.w": {"lsl.w", "lsl"},
    "lsr.w": {"lsr.w", "lsr"},
    "asr.w": {"asr.w", "asr"},
    "ldr": {"ldr", "ldr.w"},
    "ldr.w": {"ldr.w", "ldr"},
    "str": {"str", "str.w"},
    "str.w": {"str.w", "str"},
    "ldrh": {"ldrh", "ldrh.w"},
    "ldrh.w": {"ldrh.w", "ldrh"},
    "strh": {"strh", "strh.w"},
    "strh.w": {"strh.w", "strh"},
    "ldrb": {"ldrb", "ldrb.w"},
    "ldrb.w": {"ldrb.w", "ldrb"},
    "strb": {"strb", "strb.w"},
    "strb.w": {"strb.w", "strb"},
    "push.w": {"push.w", "push"},
    "pop.w": {"pop.w", "pop"},
    "ldmia": {"ldm", "ldmia"},
    "stmia": {"stm", "stmia"},
    "dsb": {"dsb"},
    "isb": {"isb"},
}


def _strip_comment(line: str) -> str:
    for marker in (";", "//"):
        if marker in line:
            line = line.split(marker, 1)[0]
    s = line.strip()
    if s.startswith("#"):
        return ""
    return s


def _combine_mem_ops(ops: list[str]) -> list[str]:
    """Combine post-index '[rn], #imm' split across two operands back into one token."""
    if len(ops) == 3 and ops[1].strip().startswith("[") and ops[1].strip().endswith("]") and ops[2].strip().startswith("#"):
        return [ops[0], f"{ops[1].strip()}, {ops[2].strip()}"]
    return ops


def _determine_insn_size(mnemonic: str, op_str: str) -> int:
    m = mnemonic.lower()
    if m in (
        "bl",
        "b.w",
        "movw",
        "movt",
        "mov.w",
        "add.w",
        "addw",
        "sub.w",
        "subw",
        "cmp.w",
        "tst.w",
        "and.w",
        "orr.w",
        "bic.w",
        "eor.w",
        "lsl.w",
        "lsr.w",
        "asr.w",
        "ubfx",
        "sbfx",
        "mrs",
        "msr",
        "dsb",
        "isb",
        "push.w",
        "pop.w",
        "tbb",
        "tbh",
        "ldr.w",
        "str.w",
        "ldrh.w",
        "strh.w",
        "ldrb.w",
        "strb.w",
    ):
        return 4
    if m.startswith("b") and m.endswith(".w"):
        cond = m[1:-2]
        if cond in _CONDS:
            return 4
    if m in ("ldr", "str", "ldrh", "strh", "ldrb", "strb"):
        ops = _combine_mem_ops(_split_operands(op_str))
        if len(ops) == 2 and ops[1].strip().startswith("["):
            rn, offset, idx_reg, post = _parse_mem_operand(ops[1])
            if post or offset < 0:
                return 4
            if idx_reg is None:
                rt = _parse_reg(ops[0])
                scale = 4 if m in ("ldr", "str") else (2 if m in ("ldrh", "strh") else 1)
                if rn == 13 and m in ("ldr", "str") and rt < 8 and 0 <= offset <= 1020 and offset % 4 == 0:
                    return 2
                if rt < 8 and rn < 8 and 0 <= offset <= 31 * scale and offset % scale == 0:
                    return 2
                return 2
    return 2


def _encode_single_insn(
    mnemonic: str,
    op_str: str,
    pc: int,
    symbols: dict[str, int],
    literal_addr: int | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Encode a single Thumb/Thumb-2 instruction, returning (bytes, expect_meta)."""
    m = mnemonic.lower()
    ops = _split_operands(op_str) if op_str.strip() else []
    meta: dict[str, Any] = {"mnemonic": m}

    if m == "nop" and not ops:
        return _pack16(0xBF00), meta
    if m == "cpsid" and len(ops) == 1 and ops[0].lower() == "i":
        return _pack16(0xB672), meta
    if m == "cpsie" and len(ops) == 1 and ops[0].lower() == "i":
        return _pack16(0xB662), meta
    if m == "bkpt" and len(ops) == 1:
        imm = _parse_int(ops[0])
        if not 0 <= imm <= 255:
            raise ThumbEncodeError(f"bkpt imm out of range: {imm}")
        return _pack16(0xBE00 | imm), meta
    if m == "dsb":
        if ops and ops[0].lower() != "sy":
            raise ThumbEncodeError(f"Unsupported dsb barrier '{ops[0]}'")
        return _pack32_t2(0xF3BF, 0x8F4F), meta
    if m == "isb":
        if ops and ops[0].lower() != "sy":
            raise ThumbEncodeError(f"Unsupported isb barrier '{ops[0]}'")
        return _pack32_t2(0xF3BF, 0x8F6F), meta
    if m == "mrs" and len(ops) == 2:
        rd = _parse_reg(ops[0], max_reg=14, allow_sp=False)
        if ops[1].strip().lower() != "primask":
            raise ThumbEncodeError(f"Only PRIMASK supported for mrs, got '{ops[1]}'")
        return _pack32_t2(0xF3EF, 0x8010 | (rd << 8)), meta
    if m == "msr" and len(ops) == 2:
        if ops[0].strip().lower() != "primask":
            raise ThumbEncodeError(f"Only PRIMASK supported for msr, got '{ops[0]}'")
        rn = _parse_reg(ops[1], max_reg=14, allow_sp=False)
        return _pack32_t2(0xF380 | rn, 0x8810), meta

    if m == "it" and len(ops) == 1:
        cond = _CONDS.get(ops[0].lower())
        if cond is None:
            raise ThumbEncodeError(f"Unknown IT condition '{ops[0]}'")
        return _pack16(0xBF08 | (cond << 4)), meta

    if m == "push" and len(ops) == 1:
        regs = _parse_reglist(ops[0])
        lr_bit = 1 if 14 in regs else 0
        low = {r for r in regs if r < 8}
        if regs - low - ({14} if lr_bit else set()):
            raise ThumbEncodeError("16-bit push only supports r0..r7 and lr; use push.w")
        mask = sum(1 << r for r in low) | (lr_bit << 8)
        return _pack16(0xB400 | mask), meta

    if m == "pop" and len(ops) == 1:
        regs = _parse_reglist(ops[0])
        pc_bit = 1 if 15 in regs else 0
        low = {r for r in regs if r < 8}
        if regs - low - ({15} if pc_bit else set()):
            raise ThumbEncodeError("16-bit pop only supports r0..r7 and pc; use pop.w")
        mask = sum(1 << r for r in low) | (pc_bit << 8)
        return _pack16(0xBC00 | mask), meta

    if m == "push.w" and len(ops) == 1:
        regs = _parse_reglist(ops[0])
        if 13 in regs or 15 in regs:
            raise ThumbEncodeError("push.w cannot include sp or pc")
        if len(regs) < 2:
            raise ThumbEncodeError("push.w requires at least 2 registers")
        mask = sum(1 << r for r in regs)
        return _pack32_t2(0xE92D, mask), meta

    if m == "pop.w" and len(ops) == 1:
        regs = _parse_reglist(ops[0])
        if 13 in regs or (14 in regs and 15 in regs):
            raise ThumbEncodeError("pop.w cannot include sp or both lr and pc")
        if len(regs) < 2:
            raise ThumbEncodeError("pop.w requires at least 2 registers")
        mask = sum(1 << r for r in regs)
        return _pack32_t2(0xE8BD, mask), meta

    if m in ("bx", "blx") and len(ops) == 1:
        rm = _parse_reg(ops[0])
        base = 0x4700 if m == "bx" else 0x4780
        return _pack16(base | (rm << 3)), meta

    if m == "bl" and len(ops) == 1:
        target = _eval_expr(ops[0], symbols)
        meta["branch_target"] = target & ~1
        return encode_bl(pc, target), meta

    if m == "b.w" and len(ops) == 1:
        target = _eval_expr(ops[0], symbols)
        meta["branch_target"] = target & ~1
        return encode_b_w(pc, target), meta

    if m == "b" and len(ops) == 1:
        target = _eval_expr(ops[0], symbols)
        offset = (target & ~1) - (pc + 4)
        if offset & 1 or not (-2048 <= offset <= 2046):
            raise ThumbEncodeError(
                f"16-bit branch 'b {ops[0]}' offset {offset} out of [-2048, +2046]; use b.w"
            )
        meta["branch_target"] = target & ~1
        return _pack16(0xE000 | ((offset >> 1) & 0x7FF)), meta

    if m.startswith("b") and m.endswith(".w") and m[1:-2] in _CONDS and len(ops) == 1:
        cond = _CONDS[m[1:-2]]
        target = _eval_expr(ops[0], symbols)
        meta["branch_target"] = target & ~1
        return encode_bcc_w(pc, cond, target), meta

    if m.startswith("b") and m[1:] in _CONDS and len(ops) == 1:
        cond = _CONDS[m[1:]]
        target = _eval_expr(ops[0], symbols)
        offset = (target & ~1) - (pc + 4)
        if offset & 1 or not (-256 <= offset <= 254):
            raise ThumbEncodeError(
                f"16-bit conditional branch '{m} {ops[0]}' offset {offset} out of [-256, +254]; use {m}.w"
            )
        meta["branch_target"] = target & ~1
        return _pack16(0xD000 | (cond << 8) | ((offset >> 1) & 0xFF)), meta

    if m in ("cbz", "cbnz") and len(ops) == 2:
        rn = _parse_reg(ops[0], max_reg=7)
        target = _eval_expr(ops[1], symbols)
        offset = (target & ~1) - (pc + 4)
        if offset & 1 or not (0 <= offset <= 126):
            raise ThumbEncodeError(
                f"'{m} {ops[0]}, {ops[1]}' forward offset {offset} out of [0, 126] even"
            )
        op_bit = 1 if m == "cbnz" else 0
        imm6 = offset >> 1
        i_bit = (imm6 >> 5) & 1
        imm5 = imm6 & 0x1F
        meta["branch_target"] = target & ~1
        return _pack16(0xB100 | (op_bit << 11) | (i_bit << 9) | (imm5 << 3) | rn), meta

    if m in ("tbb", "tbh") and len(ops) in (1, 2):
        # Syntax: tbb [pc, r0] or tbh [pc, r0, lsl #1]
        s = op_str.strip()
        if not (s.startswith("[") and s.endswith("]")):
            raise ThumbEncodeError(f"Invalid table branch operand '{op_str}'")
        inner = [p.strip().lower() for p in s[1:-1].split(",")]
        rn = _parse_reg(inner[0], allow_sp=False)
        rm = _parse_reg(inner[1], allow_sp=False, allow_pc=False)
        h = 1 if m == "tbh" else 0
        if h == 1 and (len(inner) != 3 or inner[2].replace(" ", "") != "lsl#1"):
            raise ThumbEncodeError(f"tbh requires '[rn, rm, lsl #1]', got '{op_str}'")
        return _pack32_t2(0xE8D0 | rn, 0xF000 | (h << 4) | rm), meta

    if m == "movw" and len(ops) == 2:
        rd = _parse_reg(ops[0], max_reg=14, allow_sp=False)
        imm = _eval_expr(ops[1], symbols)
        if not 0 <= imm <= 0xFFFF:
            raise ThumbEncodeError(f"movw immediate {imm} out of 0..65535")
        imm4 = (imm >> 12) & 0xF
        i_bit = (imm >> 11) & 1
        imm3 = (imm >> 8) & 0x7
        imm8 = imm & 0xFF
        return _pack32_t2(0xF240 | (i_bit << 10) | imm4, (imm3 << 12) | (rd << 8) | imm8), meta

    if m == "movt" and len(ops) == 2:
        rd = _parse_reg(ops[0], max_reg=14, allow_sp=False)
        imm = _eval_expr(ops[1], symbols)
        if not 0 <= imm <= 0xFFFF:
            raise ThumbEncodeError(f"movt immediate {imm} out of 0..65535")
        imm4 = (imm >> 12) & 0xF
        i_bit = (imm >> 11) & 1
        imm3 = (imm >> 8) & 0x7
        imm8 = imm & 0xFF
        return _pack32_t2(0xF2C0 | (i_bit << 10) | imm4, (imm3 << 12) | (rd << 8) | imm8), meta

    if m == "mov" and len(ops) == 2:
        rd = _parse_reg(ops[0])
        rm = _parse_reg(ops[1])
        return _pack16(0x4600 | ((rd >> 3) << 7) | (rm << 3) | (rd & 7)), meta

    if m == "movs" and len(ops) == 2:
        rd = _parse_reg(ops[0], max_reg=7)
        if ops[1].strip().lower() in _REGS:
            rm = _parse_reg(ops[1], max_reg=7)
            return _pack16(0x0000 | (rm << 3) | rd), meta
        imm = _eval_expr(ops[1], symbols)
        if not 0 <= imm <= 255:
            raise ThumbEncodeError(f"movs immediate {imm} out of 0..255")
        return _pack16(0x2000 | (rd << 8) | imm), meta

    if m == "mov.w" and len(ops) == 2:
        rd = _parse_reg(ops[0], max_reg=14, allow_sp=False)
        val = _eval_expr(ops[1], symbols)
        imm12 = encode_thumb_mod_imm(val)
        if imm12 is None:
            raise ThumbEncodeError(f"Value 0x{val & 0xFFFFFFFF:08X} not encodable in mov.w")
        i_bit = (imm12 >> 11) & 1
        imm3 = (imm12 >> 8) & 7
        imm8 = imm12 & 0xFF
        return _pack32_t2(0xF04F | (i_bit << 10), (imm3 << 12) | (rd << 8) | imm8), meta

    if m == "mvns" and len(ops) == 2:
        rd = _parse_reg(ops[0], max_reg=7)
        rm = _parse_reg(ops[1], max_reg=7)
        return _pack16(0x43C0 | (rm << 3) | rd), meta

    if m == "cmp" and len(ops) == 2:
        rn = _parse_reg(ops[0])
        if ops[1].strip().lower() in _REGS:
            rm = _parse_reg(ops[1])
            if rn < 8 and rm < 8:
                return _pack16(0x4280 | (rm << 3) | rn), meta
            return _pack16(0x4500 | ((rn >> 3) << 7) | (rm << 3) | (rn & 7)), meta
        if rn > 7:
            raise ThumbEncodeError("16-bit cmp rn, #imm requires r0..r7; use cmp.w")
        imm = _eval_expr(ops[1], symbols)
        if not 0 <= imm <= 255:
            raise ThumbEncodeError(f"cmp immediate {imm} out of 0..255; use cmp.w")
        return _pack16(0x2800 | (rn << 8) | imm), meta

    if m in ("cmp.w", "tst.w") and len(ops) == 2:
        rn = _parse_reg(ops[0], max_reg=14, allow_pc=False)
        val = _eval_expr(ops[1], symbols)
        imm12 = encode_thumb_mod_imm(val)
        if imm12 is None:
            raise ThumbEncodeError(f"Value 0x{val & 0xFFFFFFFF:08X} not encodable in {m}")
        i_bit = (imm12 >> 11) & 1
        imm3 = (imm12 >> 8) & 7
        imm8 = imm12 & 0xFF
        op = 0xD if m == "cmp.w" else 0x0
        return _pack32_t2(0xF000 | (i_bit << 10) | (op << 5) | (1 << 4) | rn, (imm3 << 12) | 0x0F00 | imm8), meta

    if m in ("ands", "orrs", "eors", "bics", "tst") and len(ops) == 2:
        rdn = _parse_reg(ops[0], max_reg=7)
        rm = _parse_reg(ops[1], max_reg=7)
        opc = {"ands": 0x4000, "eors": 0x4040, "tst": 0x4200, "orrs": 0x4300, "bics": 0x4380}[m]
        return _pack16(opc | (rm << 3) | rdn), meta

    if m in ("and.w", "bic.w", "orr.w", "eor.w", "add.w", "sub.w") and len(ops) == 3:
        rd = _parse_reg(ops[0], max_reg=14, allow_sp=False)
        rn = _parse_reg(ops[1], max_reg=14, allow_pc=False)
        val = _eval_expr(ops[2], symbols)
        imm12 = encode_thumb_mod_imm(val)
        if imm12 is None:
            raise ThumbEncodeError(f"Value 0x{val & 0xFFFFFFFF:08X} not encodable in {m}")
        i_bit = (imm12 >> 11) & 1
        imm3 = (imm12 >> 8) & 7
        imm8 = imm12 & 0xFF
        op = {"and.w": 0x0, "bic.w": 0x1, "orr.w": 0x2, "eor.w": 0x4, "add.w": 0x8, "sub.w": 0xD}[m]
        return _pack32_t2(0xF000 | (i_bit << 10) | (op << 5) | rn, (imm3 << 12) | (rd << 8) | imm8), meta

    if m in ("addw", "subw") and len(ops) == 3:
        rd = _parse_reg(ops[0], max_reg=14, allow_sp=False)
        rn = _parse_reg(ops[1], max_reg=14, allow_pc=False)
        imm = _eval_expr(ops[2], symbols)
        if not 0 <= imm <= 4095:
            raise ThumbEncodeError(f"{m} immediate {imm} out of 0..4095")
        i_bit = (imm >> 11) & 1
        imm3 = (imm >> 8) & 7
        imm8 = imm & 0xFF
        base = 0xF200 if m == "addw" else 0xF2A0
        return _pack32_t2(base | (i_bit << 10) | rn, (imm3 << 12) | (rd << 8) | imm8), meta

    if m == "adds":
        if len(ops) == 2:
            rd = _parse_reg(ops[0], max_reg=7)
            if ops[1].strip().lower() in _REGS:
                rm = _parse_reg(ops[1], max_reg=7)
                return _pack16(0x1800 | (rm << 6) | (rd << 3) | rd), meta
            imm = _eval_expr(ops[1], symbols)
            if not 0 <= imm <= 255:
                raise ThumbEncodeError(f"adds rd, #imm8 out of range: {imm}")
            return _pack16(0x3000 | (rd << 8) | imm), meta
        if len(ops) == 3:
            rd = _parse_reg(ops[0], max_reg=7)
            rn = _parse_reg(ops[1], max_reg=7)
            if ops[2].strip().lower() in _REGS:
                rm = _parse_reg(ops[2], max_reg=7)
                return _pack16(0x1800 | (rm << 6) | (rn << 3) | rd), meta
            imm = _eval_expr(ops[2], symbols)
            if not 0 <= imm <= 7:
                raise ThumbEncodeError(f"adds rd, rn, #imm3 out of 0..7: {imm}")
            return _pack16(0x1C00 | (imm << 6) | (rn << 3) | rd), meta

    if m == "subs":
        if len(ops) == 2:
            rd = _parse_reg(ops[0], max_reg=7)
            if ops[1].strip().lower() in _REGS:
                rm = _parse_reg(ops[1], max_reg=7)
                return _pack16(0x1A00 | (rm << 6) | (rd << 3) | rd), meta
            imm = _eval_expr(ops[1], symbols)
            if not 0 <= imm <= 255:
                raise ThumbEncodeError(f"subs rd, #imm8 out of range: {imm}")
            return _pack16(0x3800 | (rd << 8) | imm), meta
        if len(ops) == 3:
            rd = _parse_reg(ops[0], max_reg=7)
            rn = _parse_reg(ops[1], max_reg=7)
            if ops[2].strip().lower() in _REGS:
                rm = _parse_reg(ops[2], max_reg=7)
                return _pack16(0x1A00 | (rm << 6) | (rn << 3) | rd), meta
            imm = _eval_expr(ops[2], symbols)
            if not 0 <= imm <= 7:
                raise ThumbEncodeError(f"subs rd, rn, #imm3 out of 0..7: {imm}")
            return _pack16(0x1E00 | (imm << 6) | (rn << 3) | rd), meta

    if m == "add":
        if len(ops) == 2:
            if ops[0].strip().lower() == "sp" and ops[1].strip().startswith("#"):
                imm = _parse_int(ops[1])
                if not 0 <= imm <= 508 or imm % 4 != 0:
                    raise ThumbEncodeError(f"add sp, #imm out of 0..508 mult of 4: {imm}")
                return _pack16(0xB000 | (imm // 4)), meta
            rd = _parse_reg(ops[0])
            rm = _parse_reg(ops[1])
            return _pack16(0x4400 | ((rd >> 3) << 7) | (rm << 3) | (rd & 7)), meta
        if len(ops) == 3 and ops[1].strip().lower() == "sp":
            rd = _parse_reg(ops[0], max_reg=7)
            imm = _parse_int(ops[2])
            if not 0 <= imm <= 1020 or imm % 4 != 0:
                raise ThumbEncodeError(f"add rd, sp, #imm out of 0..1020 mult of 4: {imm}")
            return _pack16(0xA800 | (rd << 8) | (imm // 4)), meta

    if m == "sub" and len(ops) == 2 and ops[0].strip().lower() == "sp":
        imm = _parse_int(ops[1])
        if not 0 <= imm <= 508 or imm % 4 != 0:
            raise ThumbEncodeError(f"sub sp, #imm out of 0..508 mult of 4: {imm}")
        return _pack16(0xB080 | (imm // 4)), meta

    if m == "muls":
        if len(ops) == 2:
            rdm = _parse_reg(ops[0], max_reg=7)
            rn = _parse_reg(ops[1], max_reg=7)
            return _pack16(0x4340 | (rn << 3) | rdm), meta
        if len(ops) == 3:
            rdm = _parse_reg(ops[0], max_reg=7)
            rn = _parse_reg(ops[1], max_reg=7)
            rm = _parse_reg(ops[2], max_reg=7)
            if rm != rdm:
                raise ThumbEncodeError("Thumb muls rdm, rn, rdm requires third reg == first reg")
            return _pack16(0x4340 | (rn << 3) | rdm), meta

    if m in ("lsls", "lsrs", "asrs"):
        if len(ops) == 2:
            rdn = _parse_reg(ops[0], max_reg=7)
            rm = _parse_reg(ops[1], max_reg=7)
            opc = {"lsls": 0x4080, "lsrs": 0x40C0, "asrs": 0x4100}[m]
            return _pack16(opc | (rm << 3) | rdn), meta
        if len(ops) == 3:
            rd = _parse_reg(ops[0], max_reg=7)
            rm = _parse_reg(ops[1], max_reg=7)
            imm = _parse_int(ops[2])
            if m == "lsls":
                if not 0 <= imm <= 31:
                    raise ThumbEncodeError(f"lsls shift {imm} out of 0..31")
                return _pack16(0x0000 | (imm << 6) | (rm << 3) | rd), meta
            if not 1 <= imm <= 32:
                raise ThumbEncodeError(f"{m} shift {imm} out of 1..32")
            imm5 = 0 if imm == 32 else imm
            opc = 0x0800 if m == "lsrs" else 0x1000
            return _pack16(opc | (imm5 << 6) | (rm << 3) | rd), meta

    if m in ("lsl.w", "lsr.w", "asr.w") and len(ops) == 3:
        rd = _parse_reg(ops[0], max_reg=14, allow_sp=False)
        rm = _parse_reg(ops[1], max_reg=14, allow_sp=False)
        imm = _parse_int(ops[2])
        if m == "lsl.w":
            if not 0 <= imm <= 31:
                raise ThumbEncodeError(f"lsl.w shift {imm} out of 0..31")
            stype, imm5 = 0, imm
        else:
            if not 1 <= imm <= 32:
                raise ThumbEncodeError(f"{m} shift {imm} out of 1..32")
            stype = 1 if m == "lsr.w" else 2
            imm5 = 0 if imm == 32 else imm
        return _pack32_t2(0xEA4F, ((imm5 >> 2) << 12) | (rd << 8) | ((imm5 & 3) << 6) | (stype << 4) | rm), meta

    if m in ("sxth", "sxtb", "uxth", "uxtb", "rev", "rev16") and len(ops) == 2:
        rd = _parse_reg(ops[0], max_reg=7)
        rm = _parse_reg(ops[1], max_reg=7)
        opc = {
            "sxth": 0xB200,
            "sxtb": 0xB240,
            "uxth": 0xB280,
            "uxtb": 0xB2C0,
            "rev": 0xBA00,
            "rev16": 0xBA40,
        }[m]
        return _pack16(opc | (rm << 3) | rd), meta

    if m in ("ubfx", "sbfx") and len(ops) == 4:
        rd = _parse_reg(ops[0], max_reg=14, allow_sp=False)
        rn = _parse_reg(ops[1], max_reg=14, allow_sp=False)
        lsb = _parse_int(ops[2])
        width = _parse_int(ops[3])
        if not (0 <= lsb <= 31 and 1 <= width <= 32 - lsb):
            raise ThumbEncodeError(f"{m} invalid lsb={lsb}, width={width}")
        base = 0xF3C0 if m == "ubfx" else 0xF340
        return _pack32_t2(base | rn, ((lsb >> 2) << 12) | (rd << 8) | ((lsb & 3) << 6) | (width - 1)), meta

    if m == "adr" and len(ops) == 2:
        rd = _parse_reg(ops[0], max_reg=7)
        target = _eval_expr(ops[1], symbols)
        pc_aligned = (pc + 4) & ~3
        diff = target - pc_aligned
        if diff < 0 or diff > 1020 or diff % 4 != 0:
            raise ThumbEncodeError(
                f"adr {ops[0]}, {ops[1]} target 0x{target:08X} must be 4-byte aligned and 0..1020 bytes ahead of 0x{pc_aligned:08X}"
            )
        meta["pc_target"] = target
        return _pack16(0xA000 | (rd << 8) | (diff // 4)), meta

    if m == "ldr" and len(ops) == 2 and ops[1].strip().startswith("="):
        if literal_addr is None:
            raise ThumbEncodeError("Internal error: literal address missing for ldr =expr")
        rt = _parse_reg(ops[0], max_reg=7)
        pc_aligned = (pc + 4) & ~3
        diff = literal_addr - pc_aligned
        if diff < 0 or diff > 1020 or diff % 4 != 0:
            raise ThumbEncodeError(
                f"Literal pool at 0x{literal_addr:08X} out of ldr [pc] range from 0x{pc:08X} (diff={diff}); place .ltorg earlier"
            )
        meta["pc_target"] = literal_addr
        meta["literal_val"] = _eval_expr(ops[1].strip()[1:], symbols) & 0xFFFFFFFF
        return _pack16(0x4800 | (rt << 8) | (diff // 4)), meta

    if m in ("ldr", "str", "ldrh", "strh", "ldrb", "strb"):
        ops_mem = _combine_mem_ops(ops)
    else:
        ops_mem = ops

    if m in ("ldr", "str", "ldrh", "strh", "ldrb", "strb") and len(ops_mem) == 2:
        rn, offset, idx_reg, post = _parse_mem_operand(ops_mem[1])
        if post or offset < 0:
            rt = _parse_reg(ops_mem[0], max_reg=14, allow_sp=False)
            if not (-255 <= offset <= 255):
                raise ThumbEncodeError(f"{m} offset {offset} out of [-255, 255]")
            size_bits = 2 if m in ("ldr", "str") else (1 if m in ("ldrh", "strh") else 0)
            l_bit = 1 if m.startswith("ldr") else 0
            u_bit = 1 if offset >= 0 else 0
            pw = 0x0900 if post else 0x0C00
            return _pack32_t2(0xF800 | (size_bits << 5) | (l_bit << 4) | rn, (rt << 12) | pw | (u_bit << 9) | abs(offset)), meta
        if idx_reg is not None:
            rt = _parse_reg(ops_mem[0], max_reg=7)
            if rn > 7:
                raise ThumbEncodeError(f"16-bit {m} [rn, rm] requires r0..r7")
            rm = _parse_reg(idx_reg, max_reg=7)
            opc = {
                "str": 0x5000,
                "strh": 0x5200,
                "strb": 0x5400,
                "ldr": 0x5800,
                "ldrh": 0x5A00,
                "ldrb": 0x5C00,
            }[m]
            return _pack16(opc | (rm << 6) | (rn << 3) | rt), meta
        rt = _parse_reg(ops_mem[0], max_reg=7)
        if rn == 13 and m in ("ldr", "str"):
            if not 0 <= offset <= 1020 or offset % 4 != 0:
                raise ThumbEncodeError(f"{m} [sp, #{offset}] out of 0..1020 mult of 4")
            base = 0x9800 if m == "ldr" else 0x9000
            return _pack16(base | (rt << 8) | (offset // 4)), meta
        if rn > 7:
            raise ThumbEncodeError(f"16-bit {m} requires r0..r7; use {m}.w")
        scale = 4 if m in ("ldr", "str") else (2 if m in ("ldrh", "strh") else 1)
        if not 0 <= offset <= 31 * scale or offset % scale != 0:
            raise ThumbEncodeError(
                f"16-bit {m} [r{rn}, #{offset}] out of range; use {m}.w"
            )
        base = {
            "str": 0x6000,
            "ldr": 0x6800,
            "strb": 0x7000,
            "ldrb": 0x7800,
            "strh": 0x8000,
            "ldrh": 0x8800,
        }[m]
        return _pack16(base | ((offset // scale) << 6) | (rn << 3) | rt), meta

    if m in ("ldr.w", "str.w", "ldrh.w", "strh.w", "ldrb.w", "strb.w"):
        ops_mem = _combine_mem_ops(ops)
        if len(ops_mem) == 2:
            rt = _parse_reg(ops_mem[0], max_reg=14, allow_sp=False)
            rn, offset, idx_reg, post = _parse_mem_operand(ops_mem[1])
            if idx_reg is not None:
                raise ThumbEncodeError(f"{m} does not support index register")
            if post or offset < 0:
                if not (-255 <= offset <= 255):
                    raise ThumbEncodeError(f"{m} offset {offset} out of [-255, 255]")
                size_bits = 2 if m in ("ldr.w", "str.w") else (1 if m in ("ldrh.w", "strh.w") else 0)
                l_bit = 1 if m.startswith("ldr") else 0
                u_bit = 1 if offset >= 0 else 0
                pw = 0x0900 if post else 0x0C00
                return _pack32_t2(0xF800 | (size_bits << 5) | (l_bit << 4) | rn, (rt << 12) | pw | (u_bit << 9) | abs(offset)), meta
            if not 0 <= offset <= 4095:
                raise ThumbEncodeError(f"{m} offset {offset} out of 0..4095")
            hw1_base = {
                "strb.w": 0xF880,
                "ldrb.w": 0xF890,
                "strh.w": 0xF8A0,
                "ldrh.w": 0xF8B0,
                "str.w": 0xF8C0,
                "ldr.w": 0xF8D0,
            }[m]
            return _pack32_t2(hw1_base | rn, (rt << 12) | offset), meta

    if m in ("ldmia", "stmia") and len(ops) == 2:
        rn_s = ops[0].strip()
        if not rn_s.endswith("!"):
            raise ThumbEncodeError(f"{m} requires writeback '!' on base register")
        rn = _parse_reg(rn_s[:-1], max_reg=7)
        regs = _parse_reglist(ops[1])
        if any(r > 7 for r in regs):
            raise ThumbEncodeError(f"16-bit {m} only supports r0..r7")
        mask = sum(1 << r for r in regs)
        base = 0xC800 if m == "ldmia" else 0xC000
        return _pack16(base | (rn << 8) | mask), meta

    raise ThumbEncodeError(f"Unsupported or malformed Thumb instruction: '{mnemonic} {op_str}'")


class ThumbAssembler:
    """Two-pass deterministic Thumb/Thumb-2 assembler with Capstone verification."""

    def assemble(
        self,
        lines: Sequence[str] | str,
        base_addr: int,
        *,
        name: str = "<block>",
        symbols: dict[str, int] | None = None,
        verify: bool = True,
    ) -> AssembledBlock:
        if base_addr & 1:
            raise ThumbEncodeError(f"Thumb code base_addr must be 2-byte aligned, got 0x{base_addr:08X}")
        src_lines = lines.splitlines() if isinstance(lines, str) else list(lines)

        items: list[_Item] = []
        label_offsets: dict[str, int] = {}
        ltorg_pools: list[list[tuple[str, str]]] = [[]]  # list of unique literal keys per pool
        pool_offsets: list[int] = []

        cursor = 0
        for raw_line in src_lines:
            cleaned = _strip_comment(raw_line)
            if not cleaned:
                continue

            # Extract optional leading label(s)
            while True:
                m_lbl = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$", cleaned)
                if not m_lbl:
                    break
                lbl = m_lbl.group(1)
                if lbl in label_offsets:
                    raise ThumbEncodeError(f"Duplicate label '{lbl}' in {name}")
                label_offsets[lbl] = cursor
                cleaned = m_lbl.group(2).strip()
                if not cleaned:
                    break
            if not cleaned:
                continue

            low = cleaned.lower()
            if low == ".ltorg":
                pool_idx = len(ltorg_pools) - 1
                if ltorg_pools[pool_idx]:
                    pad = (4 - (cursor % 4)) % 4
                    if pad:
                        items.append(_Item("align", cursor, pad, ".balign 4 (ltorg)", align_n=4))
                        cursor += pad
                    pool_offsets.append(cursor)
                    size = len(ltorg_pools[pool_idx]) * 4
                    items.append(_Item("ltorg", cursor, size, ".ltorg", pool_idx=pool_idx))
                    cursor += size
                else:
                    pool_offsets.append(cursor)
                ltorg_pools.append([])
                continue

            if low.startswith(".balign"):
                parts = cleaned.split()
                if len(parts) != 2:
                    raise ThumbEncodeError(f"Invalid .balign directive '{cleaned}'")
                align_n = int(parts[1], 0)
                if align_n not in (2, 4):
                    raise ThumbEncodeError(f"Unsupported .balign {align_n}")
                pad = (align_n - (cursor % align_n)) % align_n
                if pad:
                    items.append(_Item("align", cursor, pad, cleaned, align_n=align_n))
                    cursor += pad
                continue

            if low.startswith((".byte", ".hword", ".word")):
                parts = cleaned.split(None, 1)
                dk = parts[0].lower()[1:]
                vals = tuple(v.strip() for v in parts[1].split(",") if v.strip()) if len(parts) > 1 else ()
                if not vals:
                    raise ThumbEncodeError(f"Empty {parts[0]} directive")
                elem_size = {"byte": 1, "hword": 2, "word": 4}[dk]
                items.append(_Item("data", cursor, len(vals) * elem_size, cleaned, data_kind=dk, data_exprs=vals))
                cursor += len(vals) * elem_size
                continue

            parts = cleaned.split(None, 1)
            mnemonic = parts[0].lower()
            op_str = parts[1].strip() if len(parts) > 1 else ""
            size = _determine_insn_size(mnemonic, op_str)

            lit_key: tuple[str, str] | None = None
            pool_idx = -1
            if mnemonic == "ldr":
                ops = _split_operands(op_str)
                if len(ops) == 2 and ops[1].strip().startswith("="):
                    expr = ops[1].strip()[1:].strip()
                    lit_key = ("expr", expr)
                    pool_idx = len(ltorg_pools) - 1
                    if lit_key not in ltorg_pools[pool_idx]:
                        ltorg_pools[pool_idx].append(lit_key)

            items.append(
                _Item(
                    kind="insn",
                    offset=cursor,
                    size=size,
                    raw_line=cleaned,
                    mnemonic=mnemonic,
                    op_str=op_str,
                    literal_key=lit_key,
                    pool_idx=pool_idx,
                )
            )
            cursor += size

        # Flush any trailing literal pool automatically
        last_pool_idx = len(ltorg_pools) - 1
        if ltorg_pools[last_pool_idx]:
            pad = (4 - (cursor % 4)) % 4
            if pad:
                items.append(_Item("align", cursor, pad, ".balign 4 (auto ltorg)", align_n=4))
                cursor += pad
            pool_offsets.append(cursor)
            size = len(ltorg_pools[last_pool_idx]) * 4
            items.append(_Item("ltorg", cursor, size, ".ltorg (auto)", pool_idx=last_pool_idx))
            cursor += size
        else:
            pool_offsets.append(cursor)

        resolved_symbols: dict[str, int] = dict(symbols or {})
        resolved_labels: dict[str, int] = {}
        for lbl, off in label_offsets.items():
            addr = base_addr + off
            resolved_labels[lbl] = addr
            resolved_symbols[lbl] = addr

        # Build Pass-2 bytes + track instruction spans for Capstone round-trip verification
        out = bytearray()
        code_spans: list[tuple[int, list[tuple[_Item, bytes, dict[str, Any]]]]] = []
        active_span: tuple[int, list[tuple[_Item, bytes, dict[str, Any]]]] | None = None

        for item in items:
            assert len(out) == item.offset
            if item.kind == "align":
                if item.size % 2 == 0:
                    pad_bytes = b"\x00\xbf" * (item.size // 2)
                else:
                    pad_bytes = b"\x00" * item.size
                if active_span is not None and item.size % 2 == 0:
                    # Treat NOP padding inside code spans as NOP instructions for contiguous decode
                    for i in range(item.size // 2):
                        nop_item = _Item("insn", item.offset + 2 * i, 2, "nop (align)", "nop", "")
                        active_span[1].append((nop_item, b"\x00\xbf", {"mnemonic": "nop"}))
                else:
                    active_span = None
                out.extend(pad_bytes)
            elif item.kind == "data":
                active_span = None
                fmt = {"byte": "<B", "hword": "<H", "word": "<I"}[item.data_kind]
                mask = {"byte": 0xFF, "hword": 0xFFFF, "word": 0xFFFFFFFF}[item.data_kind]
                for expr in item.data_exprs:
                    val = _eval_expr(expr, resolved_symbols)
                    out.extend(struct.pack(fmt, val & mask))
            elif item.kind == "ltorg":
                active_span = None
                for _tag, expr in ltorg_pools[item.pool_idx]:
                    val = _eval_expr(expr, resolved_symbols)
                    out.extend(struct.pack("<I", val & 0xFFFFFFFF))
            elif item.kind == "insn":
                pc = base_addr + item.offset
                lit_addr: int | None = None
                if item.literal_key is not None:
                    slot_idx = ltorg_pools[item.pool_idx].index(item.literal_key)
                    lit_addr = base_addr + pool_offsets[item.pool_idx] + 4 * slot_idx
                encoded, meta = _encode_single_insn(
                    item.mnemonic, item.op_str, pc, resolved_symbols, literal_addr=lit_addr
                )
                if len(encoded) != item.size:
                    raise ThumbEncodeError(
                        f"Internal width mismatch for '{item.raw_line}': expected {item.size}, got {len(encoded)}"
                    )
                if active_span is None:
                    active_span = (item.offset, [])
                    code_spans.append(active_span)
                active_span[1].append((item, encoded, meta))
                out.extend(encoded)

        raw_bytes = bytes(out)
        verified_insns: list[VerifiedInstruction] = []
        if verify:
            verified_insns = self._verify_spans(raw_bytes, base_addr, code_spans, name=name)
        else:
            for _span_off, records in code_spans:
                for item, encoded, _meta in records:
                    verified_insns.append(
                        VerifiedInstruction(
                            address=base_addr + item.offset,
                            size=item.size,
                            hex_bytes=encoded.hex(),
                            mnemonic=item.mnemonic,
                            op_str=item.op_str,
                            source=item.raw_line,
                        )
                    )

        return AssembledBlock(
            name=name,
            address=base_addr,
            data=raw_bytes,
            labels=resolved_labels,
            instructions=tuple(verified_insns),
            capstone_verified=verify,
        )

    @staticmethod
    def _verify_spans(
        raw_bytes: bytes,
        base_addr: int,
        code_spans: list[tuple[int, list[tuple[_Item, bytes, dict[str, Any]]]]],
        *,
        name: str,
    ) -> list[VerifiedInstruction]:
        verified: list[VerifiedInstruction] = []
        for span_offset, records in code_spans:
            span_len = sum(len(enc) for _, enc, _ in records)
            span_addr = base_addr + span_offset
            span_bytes = raw_bytes[span_offset : span_offset + span_len]
            decoded = list(_CS.disasm(span_bytes, span_addr))
            if sum(d.size for d in decoded) != span_len or len(decoded) != len(records):
                raise ThumbEncodeError(
                    f"[{name}] Capstone failed to decode full span at 0x{span_addr:08X} "
                    f"(decoded {len(decoded)}/{len(records)} insns, "
                    f"{sum(d.size for d in decoded)}/{span_len} bytes)"
                )

            in_it_block = False
            for (item, enc, meta), insn in zip(records, decoded):
                expected_addr = base_addr + item.offset
                if insn.address != expected_addr or insn.size != len(enc):
                    raise ThumbEncodeError(
                        f"[{name}] Capstone offset/size mismatch at 0x{expected_addr:08X}: "
                        f"expected {len(enc)}B, got {insn.size}B"
                    )
                if bytes(insn.bytes) != enc:
                    raise ThumbEncodeError(f"[{name}] Capstone byte mismatch at 0x{expected_addr:08X}")

                expected_m = meta["mnemonic"]
                if not in_it_block:
                    allowed_m = _MNEMONIC_ALIASES.get(expected_m, {expected_m})
                    if insn.mnemonic not in allowed_m:
                        raise ThumbEncodeError(
                            f"[{name}] Capstone mnemonic mismatch at 0x{expected_addr:08X} "
                            f"for '{item.raw_line}': got '{insn.mnemonic} {insn.op_str}'"
                        )
                in_it_block = expected_m == "it"

                if "branch_target" in meta:
                    op_idx = 1 if expected_m in ("cbz", "cbnz") else 0
                    if len(insn.operands) <= op_idx or insn.operands[op_idx].type != ARM_OP_IMM:
                        raise ThumbEncodeError(
                            f"[{name}] Capstone branch missing imm target at 0x{expected_addr:08X}: "
                            f"'{insn.mnemonic} {insn.op_str}'"
                        )
                    actual_target = insn.operands[op_idx].imm & 0xFFFFFFFF
                    if actual_target != meta["branch_target"]:
                        raise ThumbEncodeError(
                            f"[{name}] Branch target mismatch at 0x{expected_addr:08X} ('{item.raw_line}'): "
                            f"expected 0x{meta['branch_target']:08X}, Capstone decoded 0x{actual_target:08X}"
                        )

                if "pc_target" in meta:
                    pc_base = (insn.address + 4) & ~3
                    if expected_m == "adr":
                        if len(insn.operands) < 2 or insn.operands[1].type != ARM_OP_IMM:
                            raise ThumbEncodeError(
                                f"[{name}] Capstone ADR missing imm at 0x{expected_addr:08X}"
                            )
                        actual_pc_target = pc_base + insn.operands[1].imm
                    else:
                        if (
                            len(insn.operands) < 2
                            or insn.operands[1].type != ARM_OP_MEM
                            or insn.operands[1].mem.base != ARM_REG_PC
                        ):
                            raise ThumbEncodeError(
                                f"[{name}] Capstone PC-rel LDR mismatch at 0x{expected_addr:08X}: "
                                f"'{insn.mnemonic} {insn.op_str}'"
                            )
                        actual_pc_target = pc_base + insn.operands[1].mem.disp
                    if actual_pc_target != meta["pc_target"]:
                        raise ThumbEncodeError(
                            f"[{name}] PC-relative target mismatch at 0x{expected_addr:08X}: "
                            f"expected 0x{meta['pc_target']:08X}, got 0x{actual_pc_target:08X}"
                        )
                    if "literal_val" in meta:
                        slot_off = actual_pc_target - base_addr
                        stored_val = struct.unpack_from("<I", raw_bytes, slot_off)[0]
                        if stored_val != meta["literal_val"]:
                            raise ThumbEncodeError(
                                f"[{name}] Literal pool value mismatch at 0x{actual_pc_target:08X}: "
                                f"expected 0x{meta['literal_val']:08X}, got 0x{stored_val:08X}"
                            )

                verified.append(
                    VerifiedInstruction(
                        address=insn.address,
                        size=insn.size,
                        hex_bytes=bytes(insn.bytes).hex(),
                        mnemonic=insn.mnemonic,
                        op_str=insn.op_str,
                        source=item.raw_line,
                    )
                )
        return verified


_DEFAULT_ASM = ThumbAssembler()


def assemble(
    lines: Sequence[str] | str,
    base_addr: int,
    *,
    name: str = "<block>",
    symbols: dict[str, int] | None = None,
    verify: bool = True,
) -> AssembledBlock:
    """Assemble Thumb/Thumb-2 code with mandatory Capstone round-trip verification."""
    return _DEFAULT_ASM.assemble(lines, base_addr, name=name, symbols=symbols, verify=verify)


class PatchContext:
    """Composes HexPatchBuilder with ThumbAssembler and tracks Capstone proofs."""

    def __init__(self, builder: Any) -> None:
        self.builder = builder
        self.blocks: list[AssembledBlock] = []
        self.branch_patches: list[VerifiedInstruction] = []

    def alloc_asm(
        self,
        name: str,
        source_or_factory: Sequence[str] | str | Any,
        *,
        align: int = 4,
        symbols: dict[str, int] | None = None,
        export_labels: Sequence[str] = (),
        module: str = "",
        reason: str = "",
    ) -> int:
        """Allocate and assemble Thumb code in a cave with mandatory Capstone round-trip check."""
        captured: list[AssembledBlock] = []

        def _emit(addr: int) -> bytes:
            src = source_or_factory(addr) if callable(source_or_factory) else source_or_factory
            merged_syms = dict(self.builder.symbols)
            if symbols:
                merged_syms.update(symbols)
            blk = assemble(src, addr, name=name, symbols=merged_syms, verify=True)
            captured.clear()
            captured.append(blk)
            return blk.data

        addr = self.builder.alloc_code(name, _emit, align=align, module=module, reason=reason or name)
        if not captured or not captured[0].capstone_verified:
            raise ThumbEncodeError(f"Capstone verification failed for '{name}'")
        blk = captured[0]
        for lbl in export_labels:
            if lbl not in blk.labels:
                raise ThumbEncodeError(f"[{name}] Requested export label '{lbl}' not found")
            if lbl in self.builder.symbols:
                raise ThumbEncodeError(f"[{name}] Duplicate exported symbol '{lbl}'")
            self.builder.symbols[lbl] = blk.labels[lbl]
        self.blocks.append(blk)
        return addr

    def patch_bl(
        self,
        site: int,
        target: int,
        *,
        expected_old: bytes,
        module: str = "",
        reason: str = "",
    ) -> VerifiedInstruction:
        """Overwrite a 4-byte site with a Capstone-verified BL instruction."""
        encoded = encode_bl(site, target)
        verified = verify_branch_patch(encoded, site, "bl", target)
        self.builder.edit(site, encoded, expected_old=expected_old, reason=reason, module=module)
        self.branch_patches.append(verified)
        return verified

    def patch_b_w(
        self,
        site: int,
        target: int,
        *,
        expected_old: bytes,
        module: str = "",
        reason: str = "",
    ) -> VerifiedInstruction:
        """Overwrite a 4-byte site with a Capstone-verified B.W instruction."""
        encoded = encode_b_w(site, target)
        verified = verify_branch_patch(encoded, site, "b.w", target)
        self.builder.edit(site, encoded, expected_old=expected_old, reason=reason, module=module)
        self.branch_patches.append(verified)
        return verified

    def capstone_report(self) -> dict[str, Any]:
        """Return full Capstone round-trip verification summary across all code & hooks."""
        all_blocks_ok = all(b.capstone_verified for b in self.blocks)
        total_insns = sum(len(b.instructions) for b in self.blocks) + len(self.branch_patches)
        return {
            "all_verified": all_blocks_ok,
            "block_count": len(self.blocks),
            "branch_patch_count": len(self.branch_patches),
            "total_verified_instructions": total_insns,
            "branch_patches": [bp.to_dict() for bp in self.branch_patches],
            "blocks": [b.to_report_dict() for b in self.blocks],
        }
