"""Unicorn stateful write-path, NVMC persist, and cold-reload verification for Phase 1."""

from __future__ import annotations

import struct
from typing import Any

from fenrir.constants import STATUS_OK
from fenrir.emu.mouse_stateful import StatefulMouseEmu
from fenrir.protocol.frames import (
    build_family_a_frame,
    build_family_b_frame,
    decode_debounce,
    decode_dpi_table,
    decode_keymap_6,
)
from fenrir.protocol.write_frames import (
    MAX_MACRO_CHUNK_LEN,
    MAX_MACRO_OBJECT_SIZE,
    DpiSlot,
    KeymapEntry,
    build_angle_frame,
    build_debounce_frame,
    build_debounce_press_reload_frame,
    build_dpi_table_frame,
    build_keymap_frame,
    build_lod_frame,
    build_macro_chunk_frame,
    build_macro_create_frame,
    build_macro_delete_frame,
    build_motionsync_frame,
    build_polling_rate_frame,
    build_reg56_frame,
    build_rgb_led_frame,
    build_sensor_mode_frame,
    build_sleep_timeout_frame,
)

MOUSE_WRITE_FORBIDDEN_SITES: dict[int, str] = {
    0x9024: "SYSRESETREQ_helper",
    0x904C: "SYSRESETREQ_spin",
    0x2047E: "AIRCR_reset_store",
    0x12D94: "object_compact",
}

MOUSE_WRITE_WATCH_SITES: dict[int, str] = {
    0xC1E8: "button_thresholds_load_profile",
    0xF1D8: "Flash_RMW_page_retry4",
    0x177CC: "config_persist_pending",
    0x111E0: "config_load_validate_defaults",
}


def verify_config_write_persist_readback(*, sensor_id: int = 0x53) -> dict[str, Any]:
    """Prove all Phase 1 config writes apply in RAM, trigger C1E8, persist to Flash, and reload cleanly."""
    emu = StatefulMouseEmu(sensor_id=sensor_id)

    slots = [
        DpiSlot(400, 400, (255, 0, 0)),
        DpiSlot(800, 800, (0, 255, 0)),
        DpiSlot(1600, 1600, (0, 0, 255)),
        DpiSlot(3200, 3200, (255, 255, 0)),
        DpiSlot(6400, 6400, (0, 255, 255)),
    ]
    keymap = [KeymapEntry(i + 1) for i in range(5)] + [KeymapEntry(0x18, b1=0x01, b2=0x02, b3=1)]

    # Verify 0x05 alone does NOT update runtime debounce cache 0x20003A65..3A68 until group0 0x08 calls C1E8
    r_deb = emu.dispatch_frame(
        build_debounce_frame(7, 12, 30, 15).data,
        watch_sites=MOUSE_WRITE_WATCH_SITES,
        forbidden_sites=MOUSE_WRITE_FORBIDDEN_SITES,
    )
    assert r_deb.returned and r_deb.reply_64[0] == STATUS_OK
    assert not any("0x0000C1E8" in s for s in r_deb.hit_watch_sites)
    cache_before_reload = emu.ram_read(0x20003A65, 4)
    assert cache_before_reload != bytes([7, 12, 30, 15])

    r_rel = emu.dispatch_frame(
        build_debounce_press_reload_frame(7).data,
        watch_sites=MOUSE_WRITE_WATCH_SITES,
        forbidden_sites=MOUSE_WRITE_FORBIDDEN_SITES,
    )
    assert r_rel.returned and r_rel.reply_64[0] == STATUS_OK
    assert any("0x0000C1E8" in s for s in r_rel.hit_watch_sites)
    assert emu.ram_read(0x20003A65, 4) == bytes([7, 12, 30, 15])

    write_frames = [
        build_polling_rate_frame(8).data,
        build_dpi_table_frame(3, 5, slots).data,
        build_keymap_frame(keymap).data,
        build_lod_frame(7).data,
        build_motionsync_frame(False).data,
        build_reg56_frame(True).data,
        build_angle_frame(-12).data,
        build_sensor_mode_frame(True).data,
        build_rgb_led_frame(True, effect_mode=1).data,
        build_sleep_timeout_frame(180).data,
    ]
    for frame in write_frames:
        res = emu.dispatch_frame(frame, forbidden_sites=MOUSE_WRITE_FORBIDDEN_SITES)
        assert res.returned and not res.hit_forbidden_sites
        assert res.reply_64[0] == STATUS_OK

    # Persist dirty 531B config to 0xEC000 via 0x177CC, then simulate cold reboot + 0x111E0 reload
    p_res = emu.persist_pending(
        watch_sites=MOUSE_WRITE_WATCH_SITES,
        forbidden_sites=MOUSE_WRITE_FORBIDDEN_SITES,
    )
    assert p_res.returned and not p_res.hit_forbidden_sites
    assert 0xEC000 in p_res.erased_pages
    assert emu.ram_read(emu.DIRTY_BITSET_ADDR, 1)[0] == 0

    rb_res = emu.simulate_reboot_and_reload()
    assert rb_res.returned

    def read_b(cmd: int) -> bytes:
        r = emu.dispatch_frame(build_family_b_frame(cmd).data)
        assert r.returned and r.reply_64[0] == STATUS_OK
        return r.reply_64[4 : 4 + r.reply_64[1]]

    def read_a(group: int, subcmd: int) -> bytes:
        r = emu.dispatch_frame(build_family_a_frame(group, subcmd).data)
        assert r.returned and r.reply_64[0] == STATUS_OK
        return r.reply_64[6 : 6 + r.reply_64[3]]

    assert read_b(0x82)[0] == 8
    dpi = decode_dpi_table(read_b(0x83))
    assert dpi["active_slot"] == 3 and dpi["stage_count"] == 5
    assert (dpi["slots"][2]["x_cpi"], dpi["slots"][2]["rgb"]) == (1600, [0, 0, 255])
    km = decode_keymap_6(read_b(0x84))
    assert km["buttons"][5]["action_type"] == 0x18
    assert bytes.fromhex(km["buttons"][5]["data_hex"])[:3] == bytes([0x01, 0x02, 0x01])
    assert decode_debounce(read_b(0x85))["thresholds"] == [7, 12, 30, 15]
    assert read_b(0x86)[0] == 7
    assert read_b(0x87)[0] == 1
    assert read_b(0x88)[:2] == bytes([1, 1])
    assert read_b(0x91)[0] == 0
    assert read_b(0x94)[0] == 1
    assert read_b(0x95)[0] == (-12 & 0xFF)
    assert struct.unpack(">H", read_a(0, 0x87)[:2])[0] == 180

    return {
        "passed": True,
        "sensor_id": f"0x{sensor_id:02X}",
        "c1e8_immediate_reload_verified": True,
        "erased_pages_on_persist": [f"0x{p:05X}" for p in p_res.erased_pages],
        "cold_reload_verified": True,
    }


def verify_macro_single_page_pool_persist() -> dict[str, Any]:
    """Prove 1..4090B single-page macro create/chunk/flush/reload/readback/delete without 0x12D94."""
    emu = StatefulMouseEmu(sensor_id=0x53)

    def read_free() -> int:
        r = emu.dispatch_frame(build_family_b_frame(0x8A).data)
        assert r.returned and r.reply_64[0] == STATUS_OK
        return struct.unpack_from(">I", r.reply_64, 8)[0]

    def read_dir() -> list[tuple[int, int]]:
        r = emu.dispatch_frame(build_family_b_frame(0x8E).data)
        assert r.returned and r.reply_64[0] == STATUS_OK
        cnt = r.reply_64[4]
        return [struct.unpack_from(">HI", r.reply_64, 5 + 6 * i) for i in range(cnt)]

    def upload_and_verify(obj_id: int, data: bytes) -> int:
        r_c = emu.dispatch_frame(
            build_macro_create_frame(obj_id, len(data)).data,
            forbidden_sites=MOUSE_WRITE_FORBIDDEN_SITES,
        )
        assert r_c.returned and r_c.reply_64[0] == STATUS_OK and not r_c.hit_forbidden_sites
        flushed_pages: list[int] = []
        offset = 0
        chunks = 0
        while offset < len(data):
            part = data[offset : offset + MAX_MACRO_CHUNK_LEN]
            r_ch = emu.dispatch_frame(
                build_macro_chunk_frame(obj_id, offset, part).data,
                forbidden_sites=MOUSE_WRITE_FORBIDDEN_SITES,
            )
            assert r_ch.returned and r_ch.reply_64[0] == STATUS_OK and not r_ch.hit_forbidden_sites
            flushed_pages.extend(r_ch.erased_pages)
            offset += len(part)
            chunks += 1
        assert len(flushed_pages) == 1, f"Expected single-page flush, got {[hex(p) for p in flushed_pages]}"
        return chunks

    def read_macro(obj_id: int, size: int) -> bytes:
        out = bytearray()
        offset = 0
        while offset < size:
            n = min(MAX_MACRO_CHUNK_LEN, size - offset)
            r = emu.dispatch_frame(build_family_b_frame(0x8D, struct.pack(">HIB", obj_id, offset, n)).data)
            assert r.returned and r.reply_64[0] == STATUS_OK
            out.extend(r.reply_64[11 : 11 + n])
            offset += n
        return bytes(out)

    free_start = read_free()
    max_payload = bytes((i * 37 + 1) & 0xFF for i in range(MAX_MACRO_OBJECT_SIZE))
    small_payload = bytes.fromhex("0101200a010000") * 9  # 63B

    c_max = upload_and_verify(0x0102, max_payload)
    c_small = upload_and_verify(0x0203, small_payload)
    assert read_dir() == [(0x0102, MAX_MACRO_OBJECT_SIZE), (0x0203, len(small_payload))]
    assert read_free() == free_start - 2 * 4096

    p_res = emu.persist_pending(forbidden_sites=MOUSE_WRITE_FORBIDDEN_SITES)
    assert p_res.returned and 0x8C000 in p_res.erased_pages

    rb_res = emu.simulate_reboot_and_reload()
    assert rb_res.returned
    assert read_dir() == [(0x0102, MAX_MACRO_OBJECT_SIZE), (0x0203, len(small_payload))]
    assert read_macro(0x0102, MAX_MACRO_OBJECT_SIZE) == max_payload
    assert read_macro(0x0203, len(small_payload)) == small_payload

    r_del = emu.dispatch_frame(
        build_macro_delete_frame(0x0102).data,
        forbidden_sites=MOUSE_WRITE_FORBIDDEN_SITES,
    )
    assert r_del.returned and r_del.reply_64[0] == STATUS_OK
    assert read_dir() == [(0x0203, len(small_payload))]
    assert read_free() == free_start - 4096  # Exact +4096 recovery, zero drift

    return {
        "passed": True,
        "max_single_page_size": MAX_MACRO_OBJECT_SIZE,
        "max_macro_chunks": c_max,
        "small_macro_chunks": c_small,
        "cold_reload_readback_match": True,
        "zero_free_space_drift_after_delete": True,
    }


def main() -> int:
    cfg = verify_config_write_persist_readback()
    mac = verify_macro_single_page_pool_persist()
    print(f"[write_proof] config_persist_reload: {cfg}")
    print(f"[write_proof] macro_pool_single_page: {mac}")
    return 0 if (cfg["passed"] and mac["passed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
