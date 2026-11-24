"""Versioned JSON configuration schema, validation, and diff helpers for Phase 1."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fenrir.protocol.write_frames import (
    MACRO_ACTION_TYPES,
    DpiSlot,
    KeymapEntry,
    build_angle_frame,
    build_debounce_frame,
    build_debounce_press_reload_frame,
    build_dpi_table_frame,
    build_keymap_frame,
    build_lod_frame,
    build_motionsync_frame,
    build_polling_rate_frame,
    build_reg56_frame,
    build_rgb_led_frame,
    build_sensor_mode_frame,
    build_sleep_timeout_frame,
)

SCHEMA_VERSION = "1.0"


def _default_dpi_slots() -> list[DpiSlot]:
    return [
        DpiSlot(400, 400, (255, 0, 0)),
        DpiSlot(800, 800, (0, 255, 0)),
        DpiSlot(1600, 1600, (0, 0, 255)),
        DpiSlot(3200, 3200, (255, 255, 0)),
        DpiSlot(6400, 6400, (0, 255, 255)),
        DpiSlot(800, 800, (255, 0, 255)),
        DpiSlot(800, 800, (255, 255, 255)),
    ]


def _default_keymap() -> list[KeymapEntry]:
    return [
        KeymapEntry(1),
        KeymapEntry(2),
        KeymapEntry(3),
        KeymapEntry(4),
        KeymapEntry(5),
        KeymapEntry(9),
    ]


@dataclass
class MouseConfig:
    """Versioned host representation of Fenrir+035 user-configurable settings."""

    schema_version: str = SCHEMA_VERSION
    polling_rate_code: int = 1
    dpi_active_slot: int = 2
    dpi_stage_count: int = 4
    dpi_slots: list[DpiSlot] = field(default_factory=_default_dpi_slots)
    debounce_ms: tuple[int, int, int, int] = (4, 10, 35, 20)
    immediate_debounce_reload: bool = True
    lod: int = 2
    motionsync: bool = True
    reg56: bool = False
    angle_deg: int = 0
    sensor_mode_hp: bool = False
    rgb_enabled: bool = False
    rgb_effect_mode: int = 2
    sleep_sec: int = 30
    keymap: list[KeymapEntry] = field(default_factory=_default_keymap)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "polling_rate_code": int(self.polling_rate_code),
            "dpi_active_slot": int(self.dpi_active_slot),
            "dpi_stage_count": int(self.dpi_stage_count),
            "dpi_slots": [
                {"x_cpi": s.x_cpi, "y_cpi": s.y_cpi, "rgb": list(s.rgb)} for s in self.dpi_slots
            ],
            "debounce_ms": list(self.debounce_ms),
            "immediate_debounce_reload": bool(self.immediate_debounce_reload),
            "lod": int(self.lod),
            "motionsync": bool(self.motionsync),
            "reg56": bool(self.reg56),
            "angle_deg": int(self.angle_deg),
            "sensor_mode_hp": bool(self.sensor_mode_hp),
            "rgb_enabled": bool(self.rgb_enabled),
            "rgb_effect_mode": int(self.rgb_effect_mode),
            "sleep_sec": int(self.sleep_sec),
            "keymap": [
                {
                    "action_type": k.action_type,
                    "b1": k.b1,
                    "b2": k.b2,
                    "b3": k.b3,
                    "b4": k.b4,
                    "b5": k.b5,
                }
                for k in self.keymap
            ],
        }

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> MouseConfig:
        ver = str(doc.get("schema_version", SCHEMA_VERSION))
        if ver != SCHEMA_VERSION:
            raise ValueError(f"Unsupported config schema_version {ver!r}; expected {SCHEMA_VERSION!r}")
        raw_slots = doc.get("dpi_slots")
        if raw_slots is not None:
            slots = [
                DpiSlot(
                    int(s["x_cpi"]),
                    int(s["y_cpi"]),
                    (int(s["rgb"][0]), int(s["rgb"][1]), int(s["rgb"][2])),
                )
                for s in raw_slots
            ]
        else:
            slots = _default_dpi_slots()

        raw_deb = doc.get("debounce_ms", [4, 10, 35, 20])
        if len(raw_deb) != 4:
            raise ValueError(f"debounce_ms must have 4 elements, got {len(raw_deb)}")

        raw_km = doc.get("keymap")
        if raw_km is not None:
            keymap = [
                KeymapEntry(
                    int(k["action_type"]),
                    int(k.get("b1", 1)),
                    int(k.get("b2", 0)),
                    int(k.get("b3", 0)),
                    int(k.get("b4", 0)),
                    int(k.get("b5", 0)),
                )
                for k in raw_km
            ]
        else:
            keymap = _default_keymap()

        return cls(
            schema_version=ver,
            polling_rate_code=int(doc.get("polling_rate_code", 1)),
            dpi_active_slot=int(doc.get("dpi_active_slot", 2)),
            dpi_stage_count=int(doc.get("dpi_stage_count", 4)),
            dpi_slots=slots,
            debounce_ms=(int(raw_deb[0]), int(raw_deb[1]), int(raw_deb[2]), int(raw_deb[3])),
            immediate_debounce_reload=bool(doc.get("immediate_debounce_reload", True)),
            lod=int(doc.get("lod", 2)),
            motionsync=bool(doc.get("motionsync", True)),
            reg56=bool(doc.get("reg56", False)),
            angle_deg=int(doc.get("angle_deg", 0)),
            sensor_mode_hp=bool(doc.get("sensor_mode_hp", False)),
            rgb_enabled=bool(doc.get("rgb_enabled", False)),
            rgb_effect_mode=int(doc.get("rgb_effect_mode", 2)),
            sleep_sec=int(doc.get("sleep_sec", 30)),
            keymap=keymap,
        )


def load_config(path: Path | str) -> MouseConfig:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return MouseConfig.from_dict(doc)


def save_config(cfg: MouseConfig, path: Path | str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(cfg.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def validate_config(cfg: MouseConfig, *, wireless: bool = False) -> None:
    """Validate all MouseConfig fields via the strict Phase 1 frame builders."""
    if cfg.schema_version != SCHEMA_VERSION:
        raise ValueError(f"Unsupported schema_version {cfg.schema_version!r}")
    if any(not (0 <= int(x) <= 50) for x in cfg.debounce_ms):
        raise ValueError(f"debounce_ms values must be within 0..50 ms, got {cfg.debounce_ms}")
    if not (-30 <= int(cfg.angle_deg) <= 30):
        raise ValueError(f"angle_deg must be within -30..30, got {cfg.angle_deg}")
    build_polling_rate_frame(cfg.polling_rate_code, wireless=wireless)
    build_dpi_table_frame(cfg.dpi_active_slot, cfg.dpi_stage_count, cfg.dpi_slots, wireless=wireless)
    build_debounce_frame(*cfg.debounce_ms, wireless=wireless)
    if cfg.immediate_debounce_reload:
        build_debounce_press_reload_frame(cfg.debounce_ms[0], wireless=wireless)
    build_lod_frame(cfg.lod, wireless=wireless)
    build_motionsync_frame(cfg.motionsync, wireless=wireless)
    build_reg56_frame(cfg.reg56, wireless=wireless)
    build_angle_frame(cfg.angle_deg, wireless=wireless)
    build_sensor_mode_frame(cfg.sensor_mode_hp, wireless=wireless)
    build_rgb_led_frame(cfg.rgb_enabled, cfg.rgb_effect_mode, wireless=wireless)
    build_sleep_timeout_frame(cfg.sleep_sec, wireless=wireless)
    build_keymap_frame(cfg.keymap, wireless=wireless)


def _norm_keymap_cmp(entries: list[KeymapEntry]) -> list[tuple[int, ...]]:
    out: list[tuple[int, ...]] = []
    for k in entries:
        if k.action_type in MACRO_ACTION_TYPES:
            out.append((k.action_type, k.b1, k.b2, k.b3, k.b4, k.b5))
        else:
            out.append((k.action_type,))
    return out


def _norm_polling(code: int, *, wireless: bool) -> int:
    # Wired 0x82 normalizes 0x10 -> 0x01 (both represent 1000 Hz on USB).
    return 1 if (not wireless and code == 16) else code


def diff_configs(
    current: MouseConfig,
    target: MouseConfig,
    *,
    wireless: bool = False,
) -> dict[str, tuple[Any, Any]]:
    """Return {field_name: (current_value, target_value)} for fields that differ."""
    diffs: dict[str, tuple[Any, Any]] = {}

    if _norm_polling(current.polling_rate_code, wireless=wireless) != _norm_polling(
        target.polling_rate_code, wireless=wireless
    ):
        diffs["polling_rate_code"] = (current.polling_rate_code, target.polling_rate_code)

    dpi_cur = (
        current.dpi_active_slot,
        current.dpi_stage_count,
        [(s.x_cpi, s.y_cpi, s.rgb) for s in current.dpi_slots[: current.dpi_stage_count]],
    )
    dpi_tgt = (
        target.dpi_active_slot,
        target.dpi_stage_count,
        [(s.x_cpi, s.y_cpi, s.rgb) for s in target.dpi_slots[: target.dpi_stage_count]],
    )
    if dpi_cur != dpi_tgt:
        diffs["dpi"] = (dpi_cur, dpi_tgt)

    if tuple(current.debounce_ms) != tuple(target.debounce_ms):
        diffs["debounce_ms"] = (tuple(current.debounce_ms), tuple(target.debounce_ms))

    for fname in ("lod", "motionsync", "reg56", "angle_deg", "sensor_mode_hp", "sleep_sec"):
        cv, tv = getattr(current, fname), getattr(target, fname)
        if cv != tv:
            diffs[fname] = (cv, tv)

    if (current.rgb_enabled, current.rgb_effect_mode) != (target.rgb_enabled, target.rgb_effect_mode):
        diffs["rgb_led"] = (
            (current.rgb_enabled, current.rgb_effect_mode),
            (target.rgb_enabled, target.rgb_effect_mode),
        )

    if _norm_keymap_cmp(current.keymap) != _norm_keymap_cmp(target.keymap):
        diffs["keymap"] = (_norm_keymap_cmp(current.keymap), _norm_keymap_cmp(target.keymap))

    return diffs
