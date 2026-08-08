#!/usr/bin/env python3
"""Generate docs/media/pcpulse.ico from the PC Pulse badge mark.

The badge (docs/media/logo-badge.svg) is redrawn programmatically with Pillow
using the exact geometry and colors from the SVG source, because no SVG
rasterizer (ImageMagick/Inkscape/cairosvg) is assumed on the build machine.
Each icon size is rendered independently at high supersampling so small sizes
can adapt: below 48 px the faint monitor grid is dropped and the ECG trace and
cursor are thickened relative to the canvas to keep the mark legible.

Usage:  python scripts/Make-Icon.py
Output: docs/media/pcpulse.ico (16, 24, 32, 48, 64, 128, 256 px frames)

Requires: Pillow (pip install --user pillow)
"""

from __future__ import annotations

import struct
from pathlib import Path

from PIL import Image, ImageDraw

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "docs" / "media" / "pcpulse.ico"

# SVG design space (viewBox 0 0 512 512) and palette, from logo-badge.svg.
DESIGN = 512.0
BADGE_FILL = (0x05, 0x09, 0x07)
BADGE_STROKE = (0x1F, 0x32, 0x27)
GRID = (0x0F, 0x1A, 0x13)
TRACE = (0x52, 0xF0, 0x84)
CURSOR = (0xD8, 0xE9, 0xDE)

# ECG path from logo-badge.svg: ("L", end) or ("C", c1, c2, end) segments.
ECG_START = (56.0, 256.0)
ECG_SEGMENTS = [
    ("L", (148, 256)),
    ("C", (158, 256), (160, 238), (172, 238)),
    ("C", (184, 238), (186, 256), (196, 256)),
    ("L", (222, 256)),
    ("L", (238, 274)),
    ("L", (264, 120)),
    ("L", (290, 330)),
    ("L", (306, 256)),
    ("L", (332, 256)),
    ("C", (342, 256), (348, 232), (360, 232)),
    ("C", (372, 232), (378, 256), (388, 256)),
    ("L", (436, 256)),
]

GRID_LINES = [
    ((60, 152), (452, 152)),
    ((60, 256), (452, 256)),
    ((60, 360), (452, 360)),
    ((158, 72), (158, 440)),
    ((256, 72), (256, 440)),
    ((354, 72), (354, 440)),
]

SIZES = [256, 128, 64, 48, 32, 24, 16]

# Per-size adaptation, in SVG design units (512-wide space).
#   trace: ECG stroke width (SVG uses 18)
#   dot:   cursor dot radius (SVG uses 13)
#   grid:  draw the faint monitor grid
#   glow:  draw the wide low-opacity phosphor glow (SVG width 40 @ 0.22)
#   ring:  draw the cursor halo ring (SVG r 22, width 6 @ 0.35)
ADAPT = {
    256: dict(trace=18, dot=13, grid=True, glow=True, ring=True),
    128: dict(trace=18, dot=13, grid=True, glow=True, ring=True),
    64: dict(trace=18, dot=13, grid=True, glow=True, ring=True),
    48: dict(trace=22, dot=14, grid=True, glow=True, ring=True),
    32: dict(trace=30, dot=18, grid=False, glow=False, ring=False),
    24: dict(trace=36, dot=22, grid=False, glow=False, ring=False),
    16: dict(trace=44, dot=26, grid=False, glow=False, ring=False),
}


def flatten_ecg() -> list[tuple[float, float]]:
    """Flatten the ECG path (lines + cubic beziers) to a dense polyline."""
    points = [ECG_START]
    for segment in ECG_SEGMENTS:
        start = points[-1]
        if segment[0] == "L":
            points.append((float(segment[1][0]), float(segment[1][1])))
        else:
            c1, c2, end = segment[1], segment[2], segment[3]
            for step in range(1, 25):
                t = step / 24.0
                u = 1.0 - t
                x = (
                    u * u * u * start[0]
                    + 3 * u * u * t * c1[0]
                    + 3 * u * t * t * c2[0]
                    + t * t * t * end[0]
                )
                y = (
                    u * u * u * start[1]
                    + 3 * u * u * t * c1[1]
                    + 3 * u * t * t * c2[1]
                    + t * t * t * end[1]
                )
                points.append((x, y))
    return points


def stroke_polyline(
    mask_draw: ImageDraw.ImageDraw,
    points: list[tuple[float, float]],
    width: float,
) -> None:
    """Stroke a polyline with round caps/joins by pairing segments with discs.

    Drawing discs at every vertex (instead of Pillow's joint="curve") avoids
    join artifacts on dense, nearly collinear flattened bezier points.
    """
    radius = width / 2.0
    line_width = max(1, round(width))
    for a, b in zip(points, points[1:]):
        mask_draw.line([a, b], fill=255, width=line_width)
    for x, y in points:
        mask_draw.ellipse(
            [x - radius, y - radius, x + radius, y + radius], fill=255
        )


def paint_stroke(
    image: Image.Image,
    points: list[tuple[float, float]],
    width: float,
    color: tuple[int, int, int],
    opacity: int = 255,
) -> None:
    """Composite a round-capped stroke onto image at the given opacity."""
    mask = Image.new("L", image.size, 0)
    stroke_polyline(ImageDraw.Draw(mask), points, width)
    if opacity != 255:
        mask = mask.point(lambda value: value * opacity // 255)
    layer = Image.new("RGBA", image.size, color + (255,))
    image.paste(layer, (0, 0), mask)


def render(size: int) -> Image.Image:
    adapt = ADAPT[size]
    supersample = 16 if size <= 48 else 4
    canvas = size * supersample
    scale = canvas / DESIGN

    def pt(x: float, y: float) -> tuple[float, float]:
        return (x * scale, y * scale)

    image = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Rounded-square badge plate.
    draw.rounded_rectangle(
        [pt(8, 8), pt(504, 504)],
        radius=104 * scale,
        fill=BADGE_FILL,
        outline=BADGE_STROKE,
        width=max(1, round(4 * scale)),
    )

    # Faint monitor grid (dropped at small sizes for legibility).
    if adapt["grid"]:
        for (x1, y1), (x2, y2) in GRID_LINES:
            draw.line(
                [pt(x1, y1), pt(x2, y2)],
                fill=GRID,
                width=max(1, round(2 * scale)),
            )

    ecg = [pt(x, y) for x, y in flatten_ecg()]

    # Phosphor glow under the trace (SVG: width 40, opacity 0.22).
    if adapt["glow"]:
        paint_stroke(image, ecg, 40 * scale, TRACE, opacity=56)

    # ECG trace.
    paint_stroke(image, ecg, adapt["trace"] * scale, TRACE)

    # Monitor cursor: halo ring then dot.
    cx, cy = pt(446, 256)
    if adapt["ring"]:
        ring = Image.new("L", image.size, 0)
        ring_draw = ImageDraw.Draw(ring)
        radius = 22 * scale
        ring_draw.ellipse(
            [cx - radius, cy - radius, cx + radius, cy + radius],
            outline=255,
            width=max(1, round(6 * scale)),
        )
        ring = ring.point(lambda value: value * 89 // 255)  # opacity 0.35
        layer = Image.new("RGBA", image.size, TRACE + (255,))
        image.paste(layer, (0, 0), ring)
    dot = adapt["dot"] * scale
    draw.ellipse([cx - dot, cy - dot, cx + dot, cy + dot], fill=CURSOR)

    return image.resize((size, size), Image.LANCZOS)


def main() -> None:
    frames = [render(size) for size in SIZES]
    frames[0].save(
        OUTPUT,
        format="ICO",
        append_images=frames[1:],
        sizes=[(size, size) for size in SIZES],
    )

    # Verify the packed directory really contains every requested size.
    data = OUTPUT.read_bytes()
    (_, _, count) = struct.unpack("<HHH", data[:6])
    packed = []
    for index in range(count):
        width, height = struct.unpack_from("<BB", data, 6 + index * 16)
        packed.append((width or 256, height or 256))
    expected = sorted((size, size) for size in SIZES)
    if sorted(packed) != expected:
        raise SystemExit(f"ICO size mismatch: packed {sorted(packed)}")
    print(f"Wrote {OUTPUT} with sizes {sorted(packed)}")


if __name__ == "__main__":
    main()
