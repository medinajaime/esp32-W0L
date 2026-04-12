"""
Parametric ESP32 Wake-on-LAN enclosure for Fusion 360.

Install:
    pip install cadquery

Run:
    python cad/esp32_enclosure.py

Outputs:
    cad/out/esp32_enclosure_base.step
    cad/out/esp32_enclosure_lid.step
    cad/out/esp32_enclosure_assembly.step
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import cadquery as cq
from cadquery import exporters


@dataclass(frozen=True)
class EnclosureConfig:
    # Roomy default for common NodeMCU-32S / ESP32S variants.
    board_length: float = 51.4
    board_width: float = 25.4
    board_clearance: float = 1.5
    internal_height: float = 14.0

    wall: float = 2.0
    floor: float = 2.0
    lid_thickness: float = 2.0
    corner_radius: float = 4.0

    boss_diameter: float = 6.0
    screw_pilot_diameter: float = 2.2  # M2.5 self-tapping pilot.
    screw_clearance_diameter: float = 2.8
    screw_head_diameter: float = 5.2
    screw_head_depth: float = 1.1

    standoff_diameter: float = 4.2
    standoff_height: float = 2.0
    board_support_width: float = 2.2

    usb_cutout_width: float = 14.0
    usb_cutout_height: float = 8.0
    usb_cutout_z_offset: float = 4.0

    vent_slot_width: float = 2.0
    vent_slot_length: float = 18.0
    vent_slot_count: int = 5
    vent_slot_spacing: float = 5.0

    side_access_width: float = 8.0
    side_access_height: float = 4.5

    bottom_mount_hole_diameter: float = 4.0
    bottom_mount_slot_length: float = 8.0

    label_text: str = "ESP32 WOL"
    label_size: float = 5.0
    label_depth: float = 0.35

    lid_gap: float = 0.25

    @property
    def inner_length(self) -> float:
        return self.board_length + 2 * self.board_clearance

    @property
    def inner_width(self) -> float:
        return self.board_width + 2 * self.board_clearance

    @property
    def outer_length(self) -> float:
        return self.inner_length + 2 * self.wall

    @property
    def outer_width(self) -> float:
        return self.inner_width + 2 * self.wall

    @property
    def base_height(self) -> float:
        return self.floor + self.internal_height

    @property
    def boss_offset_x(self) -> float:
        return self.outer_length / 2 - self.wall - self.boss_diameter / 2 - 1.0

    @property
    def boss_offset_y(self) -> float:
        return self.outer_width / 2 - self.wall - self.boss_diameter / 2 - 1.0


def rounded_box(length: float, width: float, height: float, radius: float) -> cq.Workplane:
    safe_radius = min(radius, length / 2 - 0.1, width / 2 - 0.1)
    return (
        cq.Workplane("XY")
        .rect(length, width)
        .extrude(height)
        .edges("|Z")
        .fillet(safe_radius)
    )


def screw_positions(cfg: EnclosureConfig) -> list[tuple[float, float]]:
    return [
        (-cfg.boss_offset_x, -cfg.boss_offset_y),
        (-cfg.boss_offset_x, cfg.boss_offset_y),
        (cfg.boss_offset_x, -cfg.boss_offset_y),
        (cfg.boss_offset_x, cfg.boss_offset_y),
    ]


def make_base(cfg: EnclosureConfig) -> cq.Workplane:
    base = rounded_box(cfg.outer_length, cfg.outer_width, cfg.base_height, cfg.corner_radius)

    inner = (
        cq.Workplane("XY")
        .workplane(offset=cfg.floor)
        .rect(cfg.inner_length, cfg.inner_width)
        .extrude(cfg.internal_height + 0.2)
        .edges("|Z")
        .fillet(max(0.5, cfg.corner_radius - cfg.wall))
    )
    base = base.cut(inner)

    # Generous USB cutout on the front short wall, centered for Micro-USB/USB-C variance.
    usb_cut = (
        cq.Workplane("XZ")
        .workplane(offset=-cfg.outer_width / 2 - 0.1)
        .center(0, cfg.floor + cfg.usb_cutout_z_offset)
        .rect(cfg.usb_cutout_width, cfg.usb_cutout_height)
        .extrude(cfg.wall + 0.3)
    )
    base = base.cut(usb_cut)

    # Generic side reliefs for BOOT/EN button access or pin probing.
    for side_y in (-1, 1):
        side_cut = (
            cq.Workplane("XZ")
            .workplane(offset=side_y * (cfg.outer_width / 2 + 0.1))
            .center(-cfg.outer_length * 0.18, cfg.floor + cfg.side_access_height / 2 + 1.0)
            .rect(cfg.side_access_width, cfg.side_access_height)
            .extrude(side_y * -(cfg.wall + 0.3))
        )
        base = base.cut(side_cut)

    # Screw bosses rise inside the base and accept M2.5 self-tapping screws.
    for x, y in screw_positions(cfg):
        boss = (
            cq.Workplane("XY")
            .center(x, y)
            .circle(cfg.boss_diameter / 2)
            .extrude(cfg.base_height - cfg.lid_gap)
        )
        pilot = (
            cq.Workplane("XY")
            .center(x, y)
            .circle(cfg.screw_pilot_diameter / 2)
            .extrude(cfg.base_height + 0.2)
        )
        base = base.union(boss).cut(pilot)

    # Low rails support the board while leaving the underside mostly open for airflow.
    rail_y = cfg.board_width / 2 + cfg.board_clearance / 2
    for y in (-rail_y, rail_y):
        rail = (
            cq.Workplane("XY")
            .center(0, y)
            .rect(cfg.board_length, cfg.board_support_width)
            .extrude(cfg.floor + cfg.standoff_height)
        )
        base = base.union(rail)

    # Four small standoffs support board corners without assuming exact mounting holes.
    stand_x = cfg.board_length / 2 - 5.0
    stand_y = cfg.board_width / 2 - 4.0
    for x in (-stand_x, stand_x):
        for y in (-stand_y, stand_y):
            standoff = (
                cq.Workplane("XY")
                .center(x, y)
                .circle(cfg.standoff_diameter / 2)
                .extrude(cfg.floor + cfg.standoff_height)
            )
            base = base.union(standoff)

    # Bottom keyhole-style wall mount, cut shallowly through the floor.
    mount = (
        cq.Workplane("XY")
        .workplane(offset=-0.1)
        .center(0, 0)
        .circle(cfg.bottom_mount_hole_diameter / 2)
        .extrude(cfg.floor + 0.2)
        .union(
            cq.Workplane("XY")
            .workplane(offset=-0.1)
            .center(0, -cfg.bottom_mount_slot_length / 2)
            .rect(cfg.bottom_mount_hole_diameter, cfg.bottom_mount_slot_length)
            .extrude(cfg.floor + 0.2)
        )
    )
    base = base.cut(mount)

    return base


def make_lid(cfg: EnclosureConfig) -> cq.Workplane:
    lid_length = cfg.outer_length
    lid_width = cfg.outer_width

    lid = rounded_box(lid_length, lid_width, cfg.lid_thickness, cfg.corner_radius)

    # Shallow underside lip helps locate the lid on the base.
    lip = (
        cq.Workplane("XY")
        .workplane(offset=-1.0)
        .rect(cfg.inner_length - 2 * cfg.lid_gap, cfg.inner_width - 2 * cfg.lid_gap)
        .extrude(1.0)
        .edges("|Z")
        .fillet(max(0.5, cfg.corner_radius - cfg.wall - cfg.lid_gap))
    )
    lid = lid.union(lip)

    for x, y in screw_positions(cfg):
        screw_hole = (
            cq.Workplane("XY")
            .center(x, y)
            .circle(cfg.screw_clearance_diameter / 2)
            .extrude(cfg.lid_thickness + 1.4)
        )
        head_pocket = (
            cq.Workplane("XY")
            .workplane(offset=cfg.lid_thickness - cfg.screw_head_depth)
            .center(x, y)
            .circle(cfg.screw_head_diameter / 2)
            .extrude(cfg.screw_head_depth + 0.2)
        )
        lid = lid.cut(screw_hole).cut(head_pocket)

    # Vent slots over the ESP32 module area.
    first_y = -((cfg.vent_slot_count - 1) * cfg.vent_slot_spacing) / 2
    for idx in range(cfg.vent_slot_count):
        y = first_y + idx * cfg.vent_slot_spacing
        slot = (
            cq.Workplane("XY")
            .center(0, y)
            .rect(cfg.vent_slot_length, cfg.vent_slot_width)
            .extrude(cfg.lid_thickness + 0.4)
        )
        lid = lid.cut(slot)

    label = (
        cq.Workplane("XY")
        .workplane(offset=cfg.lid_thickness)
        .center(0, -cfg.outer_width * 0.28)
        .text(cfg.label_text, cfg.label_size, cfg.label_depth, combine=True)
    )
    lid = lid.union(label)

    return lid


def make_assembly(cfg: EnclosureConfig) -> cq.Assembly:
    base = make_base(cfg)
    lid = make_lid(cfg)

    assembly = cq.Assembly(name="esp32_wol_enclosure")
    assembly.add(base, name="base", color=cq.Color(0.12, 0.18, 0.22, 1.0))
    assembly.add(
        lid,
        name="lid",
        loc=cq.Location(cq.Vector(0, 0, cfg.base_height + 1.0)),
        color=cq.Color(0.88, 0.88, 0.84, 1.0),
    )
    return assembly


def export_step_files(cfg: EnclosureConfig, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    base = make_base(cfg)
    lid = make_lid(cfg)
    assembly = make_assembly(cfg)

    exporters.export(base, str(out_dir / "esp32_enclosure_base.step"))
    exporters.export(lid, str(out_dir / "esp32_enclosure_lid.step"))
    assembly.save(str(out_dir / "esp32_enclosure_assembly.step"))


def main() -> None:
    cfg = EnclosureConfig()
    out_dir = Path(__file__).resolve().parent / "out"
    export_step_files(cfg, out_dir)
    print(f"Exported STEP files to {out_dir}")


if __name__ == "__main__":
    main()
