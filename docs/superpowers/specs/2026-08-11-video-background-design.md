# Video background for the TUI

**Date:** 2026-08-11
**Status:** Approved pending user review

## Summary

PC Pulse's TUI gains an ambient video background: any video file the user
picks, rendered as half-block cells (`▀`, two pixels per cell), muted in
color, dimmed toward the active theme's background, and painted behind the
UI on every page. Decoding happens once per video via a spawned
`ffmpeg.exe`; playback streams pre-rendered frames from a cache file with
near-zero CPU. Entirely client-side — the collector service is untouched.

## Decisions made during brainstorming

| Question | Decision |
| --- | --- |
| Placement | Behind everything, all pages, with an off switch in Tune |
| Source | Any video file the user picks (mp4/mkv/webm/gif/…) |
| Rendering style | Half-block pixels (chosen over ASCII ramp and braille, judged visually) |
| Color treatment | Muted color — original hues desaturated ~65% (chosen over full color and theme duotone, judged visually) |
| Decode | One-time conversion via ffmpeg, cached; never re-decoded |
| Length | Full original video length — no trimming or loop cap |
| Frame rate | Flexible: capture at the source's rate (up to 60 fps); playback rate is a live setting. No artificial ceiling — stress-test and optimize rather than cripple upfront |

## Architecture

Three units, one new module each:

### 1. Converter (`clipconvert.rs`, TUI crate)

Runs on the existing worker-thread pattern when the user sets a video path
in Tune.

- Spawns `ffmpeg.exe -i <src> -vf scale=208:117 -r <capture_fps> -f rawvideo -pix_fmt rgb24 -` and reads frames from the pipe. `capture_fps = min(source fps, 60)`, probed via `ffprobe`/ffmpeg stderr; fall back to 30 if probing fails.
- Per frame: apply the muted transform (per-pixel: `p' = gray + (p − gray) × 0.35`), quantize to a fixed 6×7×6 color cube (252 colors, no per-clip palette work), deflate-compress the index buffer.
- Writes `%LOCALAPPDATA%\PcPulse\backgrounds\<hash>.pulseclip` where `hash = fnv(source path, source mtime, grid, capture_fps)`.
- Progress reported through the status line (`converting background… 42%`, from frame count vs. probed duration); cancellable by leaving Tune or quitting (thread is detached and best-effort, same as the analyzer).
- Errors: ffmpeg missing → status error naming `winget install ffmpeg`; nonzero exit or malformed output → status error, background stays off, partial cache file deleted.

`.pulseclip` layout (little-endian):

```
magic "PCLIP1" | u16 grid_w | u16 grid_h | f32 capture_fps | u32 frame_count
u32 seek_table_len | [u64 frame_offset; frame_count]      // random access
frames: [u32 compressed_len | deflate(indexed pixels)]
```

Full-length videos at 60 fps make large caches (~1 MB per 4 s of 60 fps
video after quantize+deflate; a 3-minute clip ≈ 40–60 MB). Accepted: disk
is cheap, and the seek table means RAM never holds more than two frames.

### 2. Player (`background.rs`, TUI crate)

- Opens the `.pulseclip`, keeps the seek table in memory, holds the file handle, and decompresses exactly the frame due now (~1 ms; previous frame kept for reuse when playback fps < capture fps).
- Owns a `next_frame_deadline: Instant`. `run_loop` folds it into the existing poll-timeout min() alongside motion effects and smooth-frame deadlines; when it fires, the player advances (skipping frames if the playback setting is below capture fps) and marks the UI dirty.
- Playback fps is a live setting (1–60, default: capture fps). Changing it never requires reconversion — the player just changes which frames it shows.
- Loops seamlessly (last frame → first frame).
- On any read/decompress error: log to status once, disable playback for the session. Never crash the UI over a background.

### 3. Renderer (in `ui.rs` draw path)

- **Pre-pass:** before panels draw, fill the frame buffer with half-block cells — fg = top pixel, bg = bottom pixel, nearest-neighbor sampled from the 208×117 grid so any terminal size works — each color lerped toward `palette().bg` by the dim setting (default 30%, range 10–60%).
- **Post-pass:** after `ui::draw`, one linear buffer sweep restores the video color as the background of any cell whose bg is the theme default — so text, panels, and gaps all sit on the video instead of punching solid rectangles through it. Cells with intentional backgrounds (selection bars, severity chips, statusline fills) are untouched.
- tachyonfx effects render after both passes, unchanged.

## Settings (Tune page + saved client prefs)

| Setting | Type | Default |
| --- | --- | --- |
| Background video | path (editable text row) | empty (off) |
| Background enabled | toggle | on once a clip exists |
| Background dim | 10–60% | 30% |
| Background fps | 1–60 | clip's capture fps |

Setting a new path triggers conversion; re-selecting a cached video is
instant. Theme switches only change the dim-lerp target — no reconversion.

## Performance

- Steady-state playback cost: one frame decompress (~1 ms) + two buffer sweeps per redraw. No decode processes at runtime.
- The existing smooth-frame budget guardrail (`note_smooth_frame`, three overruns drops a tier) now downshifts the *background* fps (halving, floor 2) before it downshifts the UI refresh tier — the monitor's own readouts always win over ambience.
- Frame render timing is already measured; the Tune row for background fps shows the current effective rate so stress-testing is observable (e.g. `60 → 30 (auto)` when the guardrail has downshifted).
- The deterministic render gallery and demo recorder run with the background disabled; a small synthetic two-frame clip fixture exercises the render path in tests without binary assets.

## Testing

- `.pulseclip` encode → decode round-trip (synthetic frames, exact pixel match after quantization).
- Seek-table random access: decoding frame N cold equals decoding frames 0..N sequentially.
- Muted transform and dim-lerp math (known inputs → known colors).
- Nearest-neighbor sampling at several terminal sizes, including smaller than the grid.
- Cache-key invalidation: touching source mtime changes the hash.
- ffmpeg argument construction (no shell interpolation of the user path; args passed as a vector).
- TestBackend render test: synthetic clip behind a drawn page — UI glyphs and fg colors identical to a no-background render; default-bg cells carry video color; selection/severity backgrounds untouched.
- Guardrail test: repeated overruns downshift background fps and never the UI tier first.

## Out of scope

- Bundled clips, per-theme clips, playlists.
- Audio (obviously), pause/seek UI, trimming.
- Sixel/kitty pixel graphics.
- Collector-side anything.
