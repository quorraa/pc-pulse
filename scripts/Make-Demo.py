#!/usr/bin/env python3
"""Rasterize PC Pulse demo frame dumps into the README GIF tours.

Input:  frames-<theme>.json, produced by the ignored `dev_record_demo`
        test in src/PcPulse.Tui/src/ui.rs:

            PCPULSE_DEMO_DIR=<dir> cargo test -p pcpulse-tui --lib \
                dev_record_demo -- --ignored

        Each file is `{version, generatedAt, frames}`; `frames` is an array
        of `{ms, rows}` where each row is a list of run-length-encoded
        `[text, "#fg", "#bg", bold]` runs covering the full 120x36 cell
        grid. The version/timestamp are printed so a stale dump can never
        masquerade as fresh.

Output: docs/media/demo-vitals.gif and docs/media/demo-avionics.gif —
        infinite-loop GIFs with per-frame durations from the JSON and a
        256-color adaptive palette.

Usage:  python scripts/Make-Demo.py <frames-dir> [out-dir]

Only the Python 3 standard library and Pillow are required. Fonts are read
from C:\\Windows\\Fonts: Cascadia Mono (variable weight for bold) preferred,
Consolas (+ Consolas Bold) as fallback, Segoe UI Symbol for glyphs the
monospace face lacks.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONT_DIR = Path(r"C:\Windows\Fonts")
FONT_SIZE = 15
THEMES = ("vitals", "avionics", "ledger")
SIZE_BUDGET = 8 * 1024 * 1024


def load_fonts() -> tuple[ImageFont.FreeTypeFont, ImageFont.FreeTypeFont, str]:
    """The regular/bold monospace pair used for the terminal grid."""
    cascadia = FONT_DIR / "CascadiaMono.ttf"
    if cascadia.exists():
        regular = ImageFont.truetype(str(cascadia), FONT_SIZE)
        bold = ImageFont.truetype(str(cascadia), FONT_SIZE)
        try:
            regular.set_variation_by_axes([400])
            bold.set_variation_by_axes([700])
            return regular, bold, "Cascadia Mono (variable, wght 400/700)"
        except OSError:
            pass
    regular = ImageFont.truetype(str(FONT_DIR / "consola.ttf"), FONT_SIZE)
    bold = ImageFont.truetype(str(FONT_DIR / "consolab.ttf"), FONT_SIZE)
    return regular, bold, "Consolas + Consolas Bold"


class GlyphPicker:
    """Route characters the monospace face lacks to Segoe UI Symbol.

    Coverage is probed by rendering: a character whose raster matches the
    .notdef box (or is blank while the symbol face draws something) falls
    back. Results are cached per character.
    """

    def __init__(self, regular: ImageFont.FreeTypeFont, bold: ImageFont.FreeTypeFont):
        self.regular = regular
        self.bold = bold
        symbol_path = FONT_DIR / "seguisym.ttf"
        self.symbol = (
            ImageFont.truetype(str(symbol_path), FONT_SIZE) if symbol_path.exists() else None
        )
        self._cache: dict[str, bool] = {}
        self._notdef = self._probe(self.regular, "\u0378")

    @staticmethod
    def _probe(font: ImageFont.FreeTypeFont, char: str) -> bytes:
        canvas = Image.new("L", (FONT_SIZE * 2, FONT_SIZE * 2), 0)
        ImageDraw.Draw(canvas).text((0, 0), char, font=font, fill=255)
        return canvas.tobytes()

    def font_for(self, char: str, bold: bool) -> ImageFont.FreeTypeFont:
        primary = self.bold if bold else self.regular
        if char.isascii() or self.symbol is None:
            return primary
        missing = self._cache.get(char)
        if missing is None:
            raster = self._probe(self.regular, char)
            missing = raster == self._notdef or not any(raster)
            if missing and not any(self._probe(self.symbol, char)):
                missing = False  # neither face draws it; keep the primary
            self._cache[char] = missing
        return self.symbol if missing else primary


def render_frame(
    frame: dict,
    cell_w: int,
    cell_h: int,
    picker: GlyphPicker,
) -> Image.Image:
    rows = frame["rows"]
    height = len(rows)
    width = sum(len(run[0]) for run in rows[0])
    image = Image.new("RGB", (width * cell_w, height * cell_h))
    draw = ImageDraw.Draw(image)
    for y, row in enumerate(rows):
        x = 0
        top = y * cell_h
        for text, fg, bg, bold in row:
            length = len(text)
            draw.rectangle(
                (x * cell_w, top, (x + length) * cell_w - 1, top + cell_h - 1),
                fill=bg,
            )
            if text.strip():
                for index, char in enumerate(text):
                    if char != " ":
                        draw.text(
                            ((x + index) * cell_w, top),
                            char,
                            font=picker.font_for(char, bool(bold)),
                            fill=fg,
                        )
            x += length
    return image


def build_master_palette(rendered: list[Image.Image]) -> Image.Image:
    """One global 256-color palette from a sample strip of rendered frames,
    so every GIF frame shares a single color table (no palette flicker)."""
    step = max(1, len(rendered) // 8)
    sample = rendered[::step]
    strip = Image.new("RGB", (sample[0].width, sample[0].height * len(sample)))
    for index, frame in enumerate(sample):
        strip.paste(frame, (0, index * frame.height))
    return strip.quantize(colors=256, method=Image.Quantize.MEDIANCUT)


def make_gif(frames_path: Path, out_path: Path, inspect_dir: Path | None) -> None:
    payload = json.loads(frames_path.read_text(encoding="utf-8"))
    frames = payload["frames"]
    print(
        f"{frames_path.name}: PC Pulse v{payload['version']}, "
        f"frames generated at unix {payload['generatedAt']}"
    )
    regular, bold, font_name = load_fonts()
    cell_w = round(regular.getlength("M"))
    ascent, descent = regular.getmetrics()
    cell_h = ascent + descent
    picker = GlyphPicker(regular, bold)

    rendered = [render_frame(frame, cell_w, cell_h, picker) for frame in frames]
    durations = [int(frame["ms"]) for frame in frames]

    if inspect_dir is not None:
        theme = frames_path.stem.removeprefix("frames-")
        step = max(1, len(rendered) // 10)
        for index in range(0, len(rendered), step):
            rendered[index].save(inspect_dir / f"inspect-{theme}-{index:02}.png")

    master = build_master_palette(rendered)
    quantized = [
        frame.quantize(palette=master, dither=Image.Dither.NONE) for frame in rendered
    ]

    # Merge consecutive identical frames into one longer hold.
    merged: list[Image.Image] = []
    merged_durations: list[int] = []
    previous_bytes: bytes | None = None
    for frame, duration in zip(quantized, durations):
        raw = frame.tobytes()
        if raw == previous_bytes:
            merged_durations[-1] += duration
        else:
            merged.append(frame)
            merged_durations.append(duration)
            previous_bytes = raw

    out_path.parent.mkdir(parents=True, exist_ok=True)
    merged[0].save(
        out_path,
        save_all=True,
        append_images=merged[1:],
        duration=merged_durations,
        loop=0,
        optimize=True,
    )
    size = out_path.stat().st_size
    print(
        f"{out_path.name}: {len(merged)} frames ({len(rendered)} scripted), "
        f"{sum(merged_durations) / 1000:.1f}s, {rendered[0].width}x{rendered[0].height}px, "
        f"cell {cell_w}x{cell_h}px, {font_name}, {size / 1024:.0f} KiB"
    )
    if size > SIZE_BUDGET:
        raise SystemExit(f"{out_path} exceeds the {SIZE_BUDGET // (1024 * 1024)} MiB budget")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: python scripts/Make-Demo.py <frames-dir> [out-dir]")
    frames_dir = Path(sys.argv[1])
    repo_root = Path(__file__).resolve().parent.parent
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else repo_root / "docs" / "media"
    for theme in THEMES:
        frames_path = frames_dir / f"frames-{theme}.json"
        if not frames_path.exists():
            raise SystemExit(
                f"{frames_path} missing — run: PCPULSE_DEMO_DIR={frames_dir} "
                "cargo test -p pcpulse-tui --lib dev_record_demo -- --ignored"
            )
        make_gif(frames_path, out_dir / f"demo-{theme}.gif", frames_dir)


if __name__ == "__main__":
    main()
