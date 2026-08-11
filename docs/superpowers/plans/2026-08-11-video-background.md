# Video Background Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Any user-picked video plays as a dimmed, muted-color, half-block background behind the TUI on every page, converted once via ffmpeg into a seekable cache and streamed with near-zero CPU.

**Architecture:** Three new TUI modules — `pulseclip.rs` (cache file codec), `clipconvert.rs` (one-time ffmpeg conversion on a worker thread), `background.rs` (playback clock + frame streaming) — plus a pre-pass/post-pass in `ui::draw`, four new client rows on the TUNE page, and deadline/guardrail wiring in `main.rs`. Spec: `docs/superpowers/specs/2026-08-11-video-background-design.md`.

**Tech Stack:** Rust, ratatui 0.30 (`Buffer` cell access), flate2 (rust backend), spawned `ffmpeg.exe` (conversion only), serde prefs.

## Global Constraints

- The collector service (`src/PcPulse.Service`) is untouched — no code, schema, or protocol changes.
- No network anywhere in this feature; ffmpeg is spawned as a child process with args passed as a vector (never through a shell).
- Never let the background crash or block the UI: every failure degrades to "background off + one status-line message".
- Grid is fixed at 208×116 pixels (116 even → 58 half-block rows). Capture fps = min(source fps, 60). Playback fps is a live setting; no artificial ceiling below 60.
- Muted color transform: `p' = gray + (p − gray) × 0.35` where `gray = 0.2126 r + 0.7152 g + 0.0722 b`. Dim: lerp toward `palette().bg` by `dim/100`, default 30, range 10–60.
- Gate for every task: `cargo fmt --all`, `cargo test --workspace`, `cargo clippy --workspace --all-targets` — all clean before commit.
- Commits: plain messages, NO co-author trailer.
- Version stays 1.16.3; release bump happens outside this plan.

---

### Task 1: `.pulseclip` codec (`pulseclip.rs`)

**Files:**
- Create: `src/PcPulse.Tui/src/pulseclip.rs`
- Modify: `src/PcPulse.Tui/src/lib.rs` (add `pub mod pulseclip;` alongside the existing module list)
- Modify: `src/PcPulse.Tui/Cargo.toml` (add under `[dependencies]`: `flate2 = { version = "1", default-features = false, features = ["rust_backend"] }`)

**Interfaces:**
- Consumes: nothing (leaf module).
- Produces:
  - `pub struct ClipHeader { pub grid_w: u16, pub grid_h: u16, pub capture_fps: f32, pub frame_count: u32 }`
  - `pub struct ClipWriter` — `pub fn create(path: &Path, grid_w: u16, grid_h: u16, capture_fps: f32) -> Result<Self>`, `pub fn push_frame(&mut self, rgb: &[u8]) -> Result<()>` (len must be `grid_w*grid_h*3`), `pub fn finish(self) -> Result<()>` (writes seek table + final header).
  - `pub struct ClipReader` — `pub fn open(path: &Path) -> Result<Self>`, `pub fn header(&self) -> &ClipHeader`, `pub fn frame(&mut self, index: u32) -> Result<&[u8]>` (decoded RGB, `grid_w*grid_h*3`, cached until the next call).
  - `pub fn mute(rgb: &mut [u8])` — in-place muted transform (Global Constraints formula).
  - `pub fn quantize(rgb: &[u8]) -> Vec<u8>` / `pub fn dequantize(indices: &[u8], out: &mut [u8])` — 6×7×6 color cube, `index = (r*6/256)*42 + (g*7/256)*6 + (b*6/256)`; dequantize maps each level back to its bucket center.

File layout (little-endian), exactly as specced:

```
magic b"PCLIP1" | u16 grid_w | u16 grid_h | f32 capture_fps | u32 frame_count
u32 seek_table_len | [u64 frame_offset; frame_count]
frames: [u32 compressed_len | deflate(quantized indices)]
```

`ClipWriter` writes a zeroed header + placeholder seek slot count first, streams frames while recording offsets, then `finish()` seeks back and writes the real header and table. `ClipReader::frame` seeks via the table, reads one compressed block, inflates, dequantizes into a reusable buffer.

- [ ] **Step 1: Write the failing tests** (`#[cfg(test)] mod tests` in `pulseclip.rs`)

```rust
use super::*;
use std::io::Write as _;

fn synthetic_frame(w: u16, h: u16, seed: u8) -> Vec<u8> {
    (0..u32::from(w) * u32::from(h) * 3)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn roundtrip_preserves_quantized_pixels_and_header() {
    let dir = std::env::temp_dir().join("pulseclip-roundtrip");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("clip.pulseclip");
    let (w, h) = (8u16, 4u16);
    let frames: Vec<Vec<u8>> = (0..3).map(|s| synthetic_frame(w, h, s)).collect();
    let mut writer = ClipWriter::create(&path, w, h, 24.0).unwrap();
    for f in &frames {
        writer.push_frame(f).unwrap();
    }
    writer.finish().unwrap();

    let mut reader = ClipReader::open(&path).unwrap();
    assert_eq!(reader.header().grid_w, 8);
    assert_eq!(reader.header().capture_fps, 24.0);
    assert_eq!(reader.header().frame_count, 3);
    for (i, f) in frames.iter().enumerate() {
        // Decoded output equals quantize->dequantize of the input: the codec
        // is lossy only through the fixed color cube, never through storage.
        let mut expected = vec![0u8; f.len()];
        dequantize(&quantize(f), &mut expected);
        assert_eq!(reader.frame(i as u32).unwrap(), &expected[..]);
    }
}

#[test]
fn random_access_equals_sequential_access() {
    let dir = std::env::temp_dir().join("pulseclip-seek");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("clip.pulseclip");
    let mut writer = ClipWriter::create(&path, 6, 2, 10.0).unwrap();
    for s in 0..5 {
        writer.push_frame(&synthetic_frame(6, 2, s)).unwrap();
    }
    writer.finish().unwrap();
    let mut sequential = ClipReader::open(&path).unwrap();
    let expected: Vec<Vec<u8>> = (0..5).map(|i| sequential.frame(i).unwrap().to_vec()).collect();
    let mut random = ClipReader::open(&path).unwrap();
    assert_eq!(random.frame(3).unwrap(), &expected[3][..]);
    assert_eq!(random.frame(0).unwrap(), &expected[0][..]);
    assert_eq!(random.frame(4).unwrap(), &expected[4][..]);
}

#[test]
fn mute_desaturates_toward_luminance() {
    let mut px = vec![255u8, 0, 0]; // pure red
    mute(&mut px);
    let gray = 0.2126_f32 * 255.0; // ≈ 54.2 for pure red
    assert_eq!(px[0], (gray + (255.0 - gray) * 0.35).round() as u8);
    assert_eq!(px[1], (gray + (0.0 - gray) * 0.35).round() as u8);
    assert_eq!(px[2], (gray + (0.0 - gray) * 0.35).round() as u8);
}

#[test]
fn truncated_file_is_an_error_not_a_panic() {
    let dir = std::env::temp_dir().join("pulseclip-trunc");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.pulseclip");
    std::fs::File::create(&path).unwrap().write_all(b"PCLIP1\x08\x00").unwrap();
    assert!(ClipReader::open(&path).is_err());
}
```

- [ ] **Step 2: Run tests, verify they fail to compile** — `cargo test -p pcpulse-tui pulseclip` → error: module/types not found.

- [ ] **Step 3: Implement `pulseclip.rs`** — the types above, `std::io::{BufReader, BufWriter, Seek}`, `flate2::write::DeflateEncoder` / `flate2::read::DeflateDecoder` (compression level `flate2::Compression::fast()`). Validate magic, lengths, and `frame_count == seek_table_len` on open; every malformed condition is `bail!`, never index math on unchecked values.

- [ ] **Step 4: Run tests, verify pass** — `cargo test -p pcpulse-tui pulseclip` → all pass.

- [ ] **Step 5: Gate + commit**

```bash
cargo fmt --all && cargo test --workspace && cargo clippy --workspace --all-targets
git add -A && git commit -m "Add .pulseclip cache codec for video backgrounds"
```

---

### Task 2: Converter (`clipconvert.rs`)

**Files:**
- Create: `src/PcPulse.Tui/src/clipconvert.rs`
- Modify: `src/PcPulse.Tui/src/lib.rs` (add `pub mod clipconvert;`)

**Interfaces:**
- Consumes: `pulseclip::{ClipWriter, mute}` (Task 1). `ClipWriter::push_frame` takes raw RGB and quantizes internally, so the converter only calls `mute` then `push_frame`.
- Produces:
  - `pub const GRID_W: u16 = 208;` `pub const GRID_H: u16 = 116;`
  - `pub enum ConvertEvent { Progress(u8), Done(std::path::PathBuf), Failed(String) }`
  - `pub fn cache_path(source: &Path) -> Result<PathBuf>` — `%LOCALAPPDATA%\PcPulse\backgrounds\{fnv1a64(path, mtime_ms, GRID_W, GRID_H)}.pulseclip` (dir created on demand; fnv1a64 implemented locally, no new dependency).
  - `pub fn spawn_convert(source: PathBuf) -> crossbeam_channel::Receiver<ConvertEvent>` — detached worker thread; sends `Progress` at most once per percent, then `Done`/`Failed`. If the cache file already exists, sends `Done` immediately without spawning ffmpeg.
  - `pub fn ffmpeg_args(source: &Path, capture_fps: f32) -> Vec<std::ffi::OsString>` — pure, unit-tested: `["-i", source, "-vf", "scale=208:116", "-r", fps, "-f", "rawvideo", "-pix_fmt", "rgb24", "-loglevel", "info", "-"]`.
  - `pub fn parse_probe(stderr_text: &str) -> (f32 /*fps, default 30.0*/, f32 /*duration secs, default 0.0*/)` — parses ffmpeg's banner lines `Duration: HH:MM:SS.cc` and `..., NN fps` / `..., NN.NN fps`; capture fps returned already clamped to `min(fps, 60.0)`.

Worker flow: run `ffmpeg -i <src>` once (no output file) to collect the banner for `parse_probe`; then run the real pipe command, read `208*116*3`-byte frames from stdout, `mute` → `push_frame`, progress = `frames_read / (duration * capture_fps)`. Missing ffmpeg (`ErrorKind::NotFound`) → `Failed("ffmpeg.exe not found — install it with: winget install ffmpeg")`. Nonzero exit/zero frames → `Failed(..)` and the partial cache file is deleted.

- [ ] **Step 1: Write the failing tests** (in `clipconvert.rs`)

```rust
use super::*;

#[test]
fn ffmpeg_args_pass_the_path_as_a_single_vector_item() {
    let args = ffmpeg_args(Path::new(r"C:\videos\my clip (1).mp4"), 48.0);
    let rendered: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    assert_eq!(rendered[0], "-i");
    assert_eq!(rendered[1], r"C:\videos\my clip (1).mp4"); // spaces intact, no quoting
    assert!(rendered.contains(&"scale=208:116".to_string()));
    assert!(rendered.contains(&"48".to_string()));
    assert_eq!(rendered.last().unwrap(), "-");
}

#[test]
fn probe_parses_fps_and_duration_and_clamps_to_60() {
    let banner = "Input #0, mov,mp4, from 'clip.mp4':\n  Duration: 00:03:12.45, start: 0.0, bitrate: 5 kb/s\n  Stream #0:0: Video: h264, yuv420p, 1920x1080, 120 fps, 120 tbr\n";
    let (fps, duration) = parse_probe(banner);
    assert_eq!(fps, 60.0); // 120 clamped
    assert!((duration - 192.45).abs() < 0.01);
}

#[test]
fn probe_defaults_when_the_banner_is_unrecognizable() {
    let (fps, duration) = parse_probe("garbage");
    assert_eq!(fps, 30.0);
    assert_eq!(duration, 0.0);
}

#[test]
fn cache_path_changes_when_source_mtime_changes() {
    let dir = std::env::temp_dir().join("clipconvert-key");
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("v.mp4");
    std::fs::write(&src, b"a").unwrap();
    let first = cache_path(&src).unwrap();
    // Push mtime forward well past filesystem timestamp granularity.
    let later = std::time::SystemTime::now() + std::time::Duration::from_secs(90);
    std::fs::File::options().write(true).open(&src).unwrap().set_modified(later).unwrap();
    let second = cache_path(&src).unwrap();
    assert_ne!(first, second);
    assert!(first.extension().unwrap() == "pulseclip");
}
```

- [ ] **Step 2: Run tests, verify compile failure** — `cargo test -p pcpulse-tui clipconvert`.

- [ ] **Step 3: Implement** — pure helpers first (`ffmpeg_args`, `parse_probe` with plain string scanning — find `" fps"` backwards to the preceding number, find `"Duration: "` and parse `HH:MM:SS.cc`), `cache_path` (fnv1a64 over path bytes, mtime millis, grid consts), then `spawn_convert` following the analyzer's detached-thread pattern (`std::thread::Builder::new().name("pcpulse-clip-convert".into())`, `Stdio::piped()`, `CREATE_NO_WINDOW` flag `0x0800_0000` like `update.rs` uses for curl).

- [ ] **Step 4: Run tests, verify pass.**

- [ ] **Step 5: Gate + commit** — `git commit -m "Add one-time ffmpeg conversion into the background cache"`

---

### Task 3: Player (`background.rs`)

**Files:**
- Create: `src/PcPulse.Tui/src/background.rs`
- Modify: `src/PcPulse.Tui/src/lib.rs` (add `pub mod background;`)

**Interfaces:**
- Consumes: `pulseclip::ClipReader` (Task 1).
- Produces:
  - `pub struct Background` with:
    - `pub fn load(path: &Path) -> anyhow::Result<Self>` — opens the reader, records `started: Instant`, playback fps defaults to the clip's capture fps.
    - `pub fn set_playback_fps(&mut self, fps: u32)` — clamps to `1..=60`, clears any auto-downshift.
    - `pub fn effective_fps(&self) -> u32` and `pub fn is_downshifted(&self) -> bool` (for the TUNE row's `60 → 30 (auto)` display).
    - `pub fn downshift(&mut self) -> bool` — halves effective fps (floor 2); returns false when already at the floor (caller then falls through to the UI-tier guardrail).
    - `pub fn next_deadline(&self) -> Instant` — start of the next playback tick.
    - `pub fn advance_if_due(&mut self, now: Instant) -> bool` — true when a new frame became current (caller marks the UI dirty).
    - `pub fn grid(&self) -> (u16, u16)` and `pub fn current_pixels(&mut self) -> &[u8]` — RGB of the frame due at the last `advance_if_due` time; frame index is computed from wall time, `index = (elapsed_secs * capture_fps) as u64 % frame_count`, so lowering playback fps skips frames and looping is a modulo, exactly as specced.
- Error policy: `current_pixels` never panics; a read/inflate error returns the previously decoded frame and sets `pub fn failed(&self) -> Option<&str>` so the caller can disable playback with one status message.

- [ ] **Step 1: Write the failing tests**

```rust
use super::*;
use std::time::{Duration, Instant};

fn test_clip(frames: u32, fps: f32) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("background-player");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("clip-{frames}-{fps}.pulseclip"));
    let mut w = crate::pulseclip::ClipWriter::create(&path, 4, 2, fps).unwrap();
    for s in 0..frames {
        w.push_frame(&vec![s as u8; 4 * 2 * 3]).unwrap();
    }
    w.finish().unwrap();
    path
}

#[test]
fn frame_index_follows_wall_time_and_loops() {
    let mut bg = Background::load(&test_clip(10, 10.0)).unwrap();
    let t0 = bg.started_for_test();
    bg.advance_if_due(t0 + Duration::from_millis(250));
    assert_eq!(bg.current_pixels()[0], 2); // 0.25s * 10fps = frame 2
    bg.advance_if_due(t0 + Duration::from_millis(1_150));
    assert_eq!(bg.current_pixels()[0], 1); // 11.5 frames % 10 = frame 1 — looped
}

#[test]
fn playback_fps_below_capture_skips_frames_without_reconversion() {
    let mut bg = Background::load(&test_clip(30, 30.0)).unwrap();
    bg.set_playback_fps(10);
    let t0 = bg.started_for_test();
    let d1 = bg.next_deadline();
    assert!(d1 - t0 >= Duration::from_millis(99) && d1 - t0 <= Duration::from_millis(101));
    bg.advance_if_due(t0 + Duration::from_millis(100));
    assert_eq!(bg.current_pixels()[0], 3); // wall time drives index: frame 3, not 1
}

#[test]
fn downshift_halves_to_a_floor_of_two_and_reports_auto() {
    let mut bg = Background::load(&test_clip(4, 60.0)).unwrap();
    assert_eq!(bg.effective_fps(), 60);
    assert!(bg.downshift());
    assert_eq!(bg.effective_fps(), 30);
    assert!(bg.is_downshifted());
    while bg.effective_fps() > 2 {
        assert!(bg.downshift());
    }
    assert!(!bg.downshift()); // at the floor: caller may drop the UI tier instead
    bg.set_playback_fps(60);
    assert!(!bg.is_downshifted()); // explicit user choice clears auto state
}
```

(`started_for_test` is a `#[cfg(test)] pub fn` returning the internal `Instant`.)

- [ ] **Step 2: Run, verify failure.** — `cargo test -p pcpulse-tui background`

- [ ] **Step 3: Implement `Background`** as specified above; keep the last decoded frame in a reusable `Vec<u8>`.

- [ ] **Step 4: Run, verify pass.**

- [ ] **Step 5: Gate + commit** — `git commit -m "Add background clip player with wall-clock frame skipping"`

---

### Task 4: Prefs fields

**Files:**
- Modify: `src/PcPulse.Tui/src/prefs.rs` (`UiPrefs` struct at `prefs.rs:44`, its `Default` impl, and `normalized()`)
- Test: same file's `#[cfg(test)]` module

**Interfaces:**
- Consumes: nothing new.
- Produces (on `UiPrefs`, camelCase in JSON via the existing container attribute):
  - `pub background_video: String` — source path, empty = unset. Default `""`.
  - `pub background_enabled: bool` — default `true` (only meaningful once a video is set).
  - `pub background_dim: u8` — default `30`; `normalized()` clamps to `10..=60`.
  - `pub background_fps: u32` — `0` = "clip's capture fps" sentinel; `normalized()` clamps nonzero to `1..=60`.

The struct already has `#[serde(default)]`, so a pre-upgrade `ui-prefs.json` deserializes with the new defaults — pin that with a test.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn pre_background_prefs_files_gain_background_defaults() {
    let old = r#"{"theme":"ledger","effects":false,"analyzerTimeoutSecs":120,"refreshFps":60,"updateChecks":true,"lastUpdateCheckMs":5}"#;
    let prefs: UiPrefs = serde_json::from_str(old).unwrap();
    assert_eq!(prefs.background_video, "");
    assert!(prefs.background_enabled);
    assert_eq!(prefs.background_dim, 30);
    assert_eq!(prefs.background_fps, 0);
    assert_eq!(prefs.theme, ThemeId::Ledger); // untouched fields survive
}

#[test]
fn normalized_clamps_background_dim_and_fps() {
    let mut prefs = UiPrefs { background_dim: 95, background_fps: 240, ..UiPrefs::default() };
    prefs = prefs.normalized();
    assert_eq!(prefs.background_dim, 60);
    assert_eq!(prefs.background_fps, 60);
    let mut low = UiPrefs { background_dim: 3, background_fps: 0, ..UiPrefs::default() };
    low = low.normalized();
    assert_eq!(low.background_dim, 10);
    assert_eq!(low.background_fps, 0); // sentinel survives normalization
}
```

- [ ] **Step 2: Run, verify failure.** `cargo test -p pcpulse-tui prefs`
- [ ] **Step 3: Add the four fields, defaults, and clamps.** Follow the existing field-comment style (each field carries a doc comment saying what the human gets from it).
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Gate + commit** — `git commit -m "Add background video preferences"`

---

### Task 5: Renderer passes in `ui.rs`

**Files:**
- Modify: `src/PcPulse.Tui/src/ui.rs` (`pub fn draw` at `ui.rs:856`; new private helpers + tests at the end of the file)
- Modify: `src/PcPulse.Tui/src/app.rs` (App gains `pub background: Option<crate::background::Background>`, initialized `None` in `App::new` around `app.rs:1184`)

**Interfaces:**
- Consumes: `Background::{advance_if_due is NOT called here, current_pixels, grid}` (Task 3), `app.client_prefs.{background_enabled, background_dim}` (Task 4).
- Produces:
  - `fn paint_background(buffer: &mut ratatui::buffer::Buffer, pixels: &[u8], grid: (u16, u16), dim_pct: u8)` — pre-pass: every cell gets `▀`, fg = dimmed top pixel, bg = dimmed bottom pixel, nearest-neighbor sampled.
  - `fn restore_background_bg(buffer: &mut ratatui::buffer::Buffer, pixels: &[u8], grid: (u16, u16), dim_pct: u8)` — post-pass: cells whose bg is `Color::Reset` or `palette().bg` get the video bg color back; all other bgs (selection bars, severity fills) untouched.
  - `fn dim_toward_bg(rgb: (u8, u8, u8), dim_pct: u8) -> ratatui::style::Color` — lerp toward `palette().bg` by `dim_pct/100`; shared by both passes.
- Wiring inside `pub fn draw`: first lines become

```rust
let video = app
    .background
    .as_mut()
    .filter(|_| app.client_prefs.background_enabled)
    .map(|bg| (bg.current_pixels().to_vec(), bg.grid()));
if let Some((pixels, grid)) = &video {
    paint_background(frame.buffer_mut(), pixels, *grid, app.client_prefs.background_dim);
}
// ... existing page drawing, unchanged ...
if let Some((pixels, grid)) = &video {
    restore_background_bg(frame.buffer_mut(), pixels, *grid, app.client_prefs.background_dim);
}
```

(The `to_vec` copies one 72 KB frame per redraw to satisfy borrows; acceptable, measured under the existing frame budget.)

- [ ] **Step 1: Write the failing tests** (in `ui.rs` tests, following the existing TestBackend pattern near `ui.rs:6322`)

```rust
#[test]
fn background_paints_under_text_and_respects_intentional_backgrounds() {
    let mut terminal = Terminal::new(TestBackend::new(40, 12)).expect("terminal");
    let mut app = App::new_for_test(); // or the fixture builder the file already uses
    let clip = {
        let dir = std::env::temp_dir().join("ui-bg");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("two-frame.pulseclip");
        let mut w = crate::pulseclip::ClipWriter::create(&path, 4, 2, 2.0).unwrap();
        w.push_frame(&vec![200u8; 4 * 2 * 3]).unwrap();
        w.push_frame(&vec![40u8; 4 * 2 * 3]).unwrap();
        w.finish().unwrap();
        path
    };
    app.background = Some(crate::background::Background::load(&clip).unwrap());
    app.client_prefs.background_enabled = true;
    app.client_prefs.background_dim = 30;

    let mut plain = Terminal::new(TestBackend::new(40, 12)).expect("terminal");
    let mut app_plain = App::new_for_test();
    plain.draw(|f| draw(f, &mut app_plain)).unwrap();
    terminal.draw(|f| draw(f, &mut app)).unwrap();

    let with_bg = terminal.backend().buffer().clone();
    let without = plain.backend().buffer().clone();
    let mut video_backed_text_cells = 0;
    for (a, b) in with_bg.content().iter().zip(without.content().iter()) {
        // Every glyph and fg color the UI drew must be identical — the video
        // may only change backgrounds.
        if b.symbol() != "▀" || a.symbol() != "▀" {
            assert_eq!(a.symbol(), b.symbol());
            assert_eq!(a.fg, b.fg);
        }
        if b.bg != ratatui::style::Color::Reset && b.bg != palette().bg {
            assert_eq!(a.bg, b.bg); // intentional fills survive untouched
        } else if a.symbol() == b.symbol() && a.bg != b.bg {
            video_backed_text_cells += 1;
        }
    }
    assert!(video_backed_text_cells > 0, "no cell ever received video bg");
}

#[test]
fn background_disabled_draws_identically_to_no_background() {
    // With the toggle off, even a loaded clip must change nothing.
    let clip = {
        let dir = std::env::temp_dir().join("ui-bg-off");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("two-frame.pulseclip");
        let mut w = crate::pulseclip::ClipWriter::create(&path, 4, 2, 2.0).unwrap();
        w.push_frame(&vec![200u8; 4 * 2 * 3]).unwrap();
        w.push_frame(&vec![40u8; 4 * 2 * 3]).unwrap();
        w.finish().unwrap();
        path
    };
    let mut with_clip = Terminal::new(TestBackend::new(40, 12)).expect("terminal");
    let mut app = App::new_for_test();
    app.background = Some(crate::background::Background::load(&clip).unwrap());
    app.client_prefs.background_enabled = false;
    with_clip.draw(|f| draw(f, &mut app)).unwrap();

    let mut plain = Terminal::new(TestBackend::new(40, 12)).expect("terminal");
    let mut app_plain = App::new_for_test();
    plain.draw(|f| draw(f, &mut app_plain)).unwrap();

    assert_eq!(with_clip.backend().buffer(), plain.backend().buffer());
}
```

(If `App::new_for_test` doesn't exist, use whatever constructor the existing ui tests at `ui.rs:6322` use — read that test first and copy its setup for both tests.)

- [ ] **Step 2: Run, verify failure.** — `cargo test -p pcpulse-tui background_paints`
- [ ] **Step 3: Implement the three helpers + wiring.** Nearest neighbor: for buffer cell `(cx, cy)` in an `area_w × area_h` buffer, top pixel = `pixels[(py0 * grid_w + px) * 3..]` with `px = cx * grid_w / area_w`, `py0 = (cy * 2) * grid_h / (area_h * 2)`, bottom uses `cy * 2 + 1`.
- [ ] **Step 4: Run, verify pass.** Also run the full ui test module — the gallery/demo tests must be untouched (background defaults to `None` there).
- [ ] **Step 5: Gate + commit** — `git commit -m "Paint the video background beneath every page"`

---

### Task 6: TUNE rows

**Files:**
- Modify: `src/PcPulse.Tui/src/app.rs` — `SettingField` enum (`app.rs:289`), `CLIENT` array (becomes `[Self; 9]`, `app.rs:319`), `ALL` (becomes `[Self; 28]`), `is_client`, `label`, `unit`, `description`, `value`, and the Enter/edit handling where the other client rows commit (`handle_setting_input` at `app.rs:1466` and the client-row apply path near `app.rs:2036`).
- Test: existing app tests module.

**Interfaces:**
- Consumes: `clipconvert::{spawn_convert, cache_path, ConvertEvent}` (Task 2), `background::Background` (Task 3), prefs fields (Task 4).
- Produces four `SettingField` variants (inserted after `ClientUpdates`):
  - `ClientBackgroundVideo` — label "Background video", unit "local", value = the stored path or "off". Enter opens the existing `EditSetting` typed-path input; committing a non-empty path saves the pref and calls `app.start_background_conversion()`; committing empty clears the path and drops `app.background`.
  - `ClientBackgroundEnabled` — label "Background", unit "local", Enter toggles + persists.
  - `ClientBackgroundDim` — label "Background dim", unit "%", Enter opens numeric edit, commit clamps 10–60, persists.
  - `ClientBackgroundFps` — label "Background fps", unit "fps", value shows `auto (matches clip)` for the 0 sentinel, `N` normally, and `N → M (auto)` when `background.is_downshifted()`; Enter opens numeric edit, commit clamps 1–60 (or 0 to return to auto), persists and calls `Background::set_playback_fps`.
- Produces on `App`:
  - `pub fn start_background_conversion(&mut self)` — stores `clipconvert::spawn_convert(path)`'s receiver in `pub convert_rx: Option<Receiver<ConvertEvent>>`; `drain_events` (the existing method `run_loop` already calls) polls it: `Progress(p)` → status `converting background… {p}%`; `Failed(msg)` → status error; `Done(path)` → `self.background = Background::load(&path)` (load error → status error) + status `background ready`.
  - On startup (`App::new` / `adopt_client_prefs`): if `background_video` is set and its `cache_path` exists, load it directly; if set but not cached, kick off conversion automatically.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn background_rows_are_client_rows_and_stay_pinned() {
    for field in [
        SettingField::ClientBackgroundVideo,
        SettingField::ClientBackgroundEnabled,
        SettingField::ClientBackgroundDim,
        SettingField::ClientBackgroundFps,
    ] {
        assert!(field.is_client());
        assert!(SettingField::CLIENT.contains(&field));
        assert!(!field.label().is_empty() && !field.description().is_empty());
    }
}

#[test]
fn committing_a_dim_edit_clamps_and_persists() {
    let mut app = App::new_for_test();
    app.apply_client_setting(SettingField::ClientBackgroundDim, "85");
    assert_eq!(app.client_prefs.background_dim, 60);
    app.apply_client_setting(SettingField::ClientBackgroundDim, "5");
    assert_eq!(app.client_prefs.background_dim, 10);
}

#[test]
fn fps_row_reports_the_auto_downshift() {
    let mut app = App::new_for_test();
    // fixture clip at 60fps as in the ui tests, then:
    app.background.as_mut().unwrap().downshift();
    let value = SettingField::ClientBackgroundFps.value(&app.settings_for_test());
    assert!(value.contains("(auto)"), "value was {value}");
}
```

(Adapt helper names to what the app tests module actually uses — read the neighboring client-row tests first, e.g. the ClientTimeout commit test, and mirror their setup exactly. If commits go through a differently-named method than `apply_client_setting`, use that method; the assertion targets stay the same.)

- [ ] **Step 2: Run, verify failure.**
- [ ] **Step 3: Implement** — extend the enum, the five const/match blocks, the edit plumbing, `start_background_conversion`, and the `drain_events` polling arm. Descriptions follow the house voice (plain language, what the person gets, how Enter behaves), e.g. for `ClientBackgroundVideo`: "Path to a video file to play, muted and dimmed, behind every page. First use converts it once with ffmpeg (winget install ffmpeg); afterwards it costs almost nothing. Enter edits; empty turns it off."
- [ ] **Step 4: Run, verify pass** — plus `client_rows_stay_pinned_above_the_sorted_service_settings` (`ui.rs:4298`) still green with 9 client rows.
- [ ] **Step 5: Gate + commit** — `git commit -m "Add background video rows to TUNE"`

---

### Task 7: run_loop wiring + guardrail

**Files:**
- Modify: `src/PcPulse.Tui/src/main.rs` (`run_loop`, poll-timeout math around `main.rs:298`, frame gating around `main.rs:271`)
- Modify: `src/PcPulse.Tui/src/app.rs` (`note_smooth_frame` at `app.rs:2118`)
- Test: app tests module.

**Interfaces:**
- Consumes: `Background::{advance_if_due, next_deadline, downshift, failed}` (Task 3).
- Produces:
  - In `run_loop`: before the `if dirty || …` gate, `if let Some(bg) = app.background.as_mut() && app.client_prefs.background_enabled && bg.advance_if_due(Instant::now()) { dirty = true; }`. The poll timeout takes `min` with `bg.next_deadline().saturating_duration_since(now)` exactly like the smooth-frame deadline. After each draw, `if let Some(msg) = app.background.as_ref().and_then(|b| b.failed())` → set status error once and `app.background = None`.
  - In `note_smooth_frame`: when the three-overrun trip fires, first try `self.background.as_mut().map_or(false, |b| b.downshift())`; only when that returns false (no background, or already at the 2 fps floor) does the existing refresh-tier drop run. Status line says `background rate lowered to N fps (frame budget)` for the background case, keeping the existing message for the tier drop.
- Produces test hook: `App::note_smooth_frame` is already public — tests drive it directly.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn budget_overruns_downshift_the_background_before_the_ui_tier() {
    let mut app = App::new_for_test();
    // load the 60fps fixture clip (same helper as the ui/background tests)
    app.client_prefs.refresh_fps = 60;
    let over = Duration::from_millis(50);
    let budget = Duration::from_millis(16);
    for _ in 0..3 {
        app.note_smooth_frame(over, budget);
    }
    assert_eq!(app.effective_refresh_fps(), 60, "UI tier must survive the first trip");
    assert_eq!(app.background.as_ref().unwrap().effective_fps(), 30);
    // Drive the background to its floor, then one more trip drops the UI tier.
    while app.background.as_ref().unwrap().effective_fps() > 2 {
        for _ in 0..3 {
            app.note_smooth_frame(over, budget);
        }
    }
    for _ in 0..3 {
        app.note_smooth_frame(over, budget);
    }
    assert_eq!(app.effective_refresh_fps(), 30);
}
```

(Check `note_smooth_frame`'s exact trip semantics at `app.rs:2118` first — if the counter resets differently, adjust the loop counts to whatever provokes exactly one trip, keeping the assertions.)

- [ ] **Step 2: Run, verify failure.**
- [ ] **Step 3: Implement both wirings.**
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Gate + commit** — `git commit -m "Drive background playback from the main loop, guardrail first"`

---

### Task 8: Docs + final verification

**Files:**
- Modify: `README.md` (feature list + a short "Video background" subsection near the theme/Tune documentation: what it does, ffmpeg one-time requirement, the four TUNE rows, cache location, size expectation ~1 MB per 4 s of 60 fps video)
- No code changes.

- [ ] **Step 1: Write the README section** — plain language, mirrors the TUNE descriptions; mention that the collector is uninvolved and nothing touches the network.
- [ ] **Step 2: Full gate** — `cargo fmt --all && cargo test --workspace && cargo clippy --workspace --all-targets`.
- [ ] **Step 3: Live smoke test (do not skip, do not publish anything):** convert a real video (`winget list ffmpeg` first; if absent, tell the user instead of installing silently), set it via TUNE, confirm: conversion progress in the status line, background visible on every page, `t` retint works, dim edit visibly changes depth, fps 60→5 visibly slows it, guardrail message appears under artificial load if reproducible. Screenshot-verify through the freshness-stamped gallery only if a deterministic fixture path is added — otherwise verify by eye with the user.
- [ ] **Step 4: Commit** — `git commit -m "Document the video background"`. No version bump, no release — that is a separate user decision.
