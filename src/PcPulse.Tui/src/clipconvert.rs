//! One-time ffmpeg conversion of a user-picked video into the `.pulseclip`
//! background cache.
//!
//! A video is converted exactly once: `ffmpeg.exe` is probed for its banner
//! (fps, duration, and the source's own pixel size, which decides the
//! capture size), then re-invoked to stream raw RGB frames on stdout —
//! `mute`d and handed to `ClipWriter` one at a time so a multi-minute source
//! never sits fully decoded in memory. The whole thing runs on a detached
//! worker thread, mirroring `analyzer.rs`'s Codex worker: the caller gets a
//! `crossbeam_channel::Receiver` and polls it from the UI loop instead of
//! blocking on ffmpeg. Every ffmpeg invocation passes its arguments as a
//! vector (never through a shell) and runs with `CREATE_NO_WINDOW` so no
//! console flashes up behind the TUI.
//!
//! ## Stopping one
//!
//! A conversion outlives the interest in it all the time: the person picks a
//! different video, cycles the quality preset, or turns the background off
//! while frames are still streaming. Each of those wants a *different* clip
//! out of a different cache file, so the worker already running is producing
//! something nobody will load — and left alone it would burn a core and
//! hundreds of megabytes of disk doing it, with a preset cycled three times
//! stacking three ffmpegs. Every worker therefore carries a cancellation
//! flag ([`ConvertHandle`]), checked between frame reads; raising it kills
//! ffmpeg, drops the half-written clip, and stops the worker **silently** —
//! `Done` and `Failed` are for a receiver somebody still holds.
//!
//! Two deliberate non-cancellations. The probe (the first, short-lived
//! ffmpeg) is uncancellable: it decodes nothing, exits in tens of
//! milliseconds, and the check that would interrupt it lands at the top of
//! the frame loop a moment later anyway. And the TUI exiting needs no
//! cancellation at all — the worker is detached, so it dies with the
//! process, and every handle it held closes with it. ffmpeg's stdout is a
//! pipe whose read end this process owns (see [`convert`]), so closing it
//! fails ffmpeg's next write and ffmpeg exits on its own.
//!
//! ## What a cache file costs
//!
//! Capture size follows the source and the chosen quality preset (see
//! `BackgroundQuality` and `capture_dims`), so cost does too.
//! `pulseclip` quantizes each frame to one byte per pixel and deflates it,
//! and what that compresses to depends almost entirely on the footage:
//! measured through this pipeline, **0.05 bytes/pixel** for flat or
//! synthetic content and **0.17 bytes/pixel** for dense detail, with
//! per-pixel film grain — which deflate cannot do anything with — reaching
//! 0.4.
//!
//! In frames, at the default `High` preset, that is 12-39 KB at the 640x360
//! an SD source keeps and 20-66 KB at the 825x464 a 1080p source is fitted
//! to. At 60 fps: **1-4 MB per second of video**, so a 3-minute 60 fps clip
//! is a 200-700 MB cache file, and a 15 s 30 fps SD clip about 7 MB. Each
//! step down the preset ladder quarters the pixels and roughly quarters
//! that; `Ultra` roughly quadruples it.
//!
//! Bytes/pixel falls as the capture gets finer — the same footage costs 0.164
//! at 208x116 and 0.135 at 416x232 — because finer sampling gives deflate
//! more neighbouring-pixel redundancy to exploit. It falls nowhere near fast
//! enough to pay for the pixels, though: raising the ceiling is a real disk
//! cost, not a free one.

use crate::pulseclip::{ClipReader, ClipWriter, mute};
use anyhow::{Context, Result, anyhow, bail};
use crossbeam_channel::{Receiver, Sender, bounded};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

/// How finely a background video is converted, as the person chooses it on
/// the TUNE page. Each preset is a *ceiling*, not a size: the clip is
/// captured at its own resolution shrunk to fit inside the box with its
/// aspect ratio intact — never stretched, never magnified (see
/// [`capture_dims`]).
///
/// The ladder doubles each axis a step at a time, so each step up is about
/// four times the pixels and, near enough, four times the disk. `High` is
/// the default and the size every clip converted before this preset
/// existed was captured at. Even the smallest preset is finer than most of
/// the terminal it lands in (a full-screen 200x60 window is 200x120
/// half-cells), so the renderer keeps averaging detail into tone rather
/// than magnifying a coarse capture into blocks.
///
/// Every cap height is even, and so is every height derived from one: the
/// renderer consumes two vertical pixels per cell, and an odd height would
/// leave a half-cell row with nothing to sample.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BackgroundQuality {
    Low,
    Medium,
    #[default]
    High,
    Ultra,
}

impl BackgroundQuality {
    /// The resolution ceiling this preset converts to, `(width, height)`.
    pub const fn cap(self) -> (u16, u16) {
        match self {
            Self::Low => (208, 116),
            Self::Medium => (416, 232),
            Self::High => (832, 464),
            Self::Ultra => (1248, 702),
        }
    }

    /// The stored and displayed name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Ultra => "ultra",
        }
    }

    /// The next preset the TUNE row's Enter lands on; the ladder wraps.
    pub const fn next(self) -> Self {
        match self {
            Self::Low => Self::Medium,
            Self::Medium => Self::High,
            Self::High => Self::Ultra,
            Self::Ultra => Self::Low,
        }
    }
}

impl std::str::FromStr for BackgroundQuality {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "ultra" => Ok(Self::Ultra),
            _ => Err(()),
        }
    }
}

/// Windows' own flag: the spawned ffmpeg gets no console window, matching
/// the `DETACHED_PROCESS`-style spawns elsewhere in this crate.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Raw RGB bytes in one frame at `dims`. ffmpeg streams fixed-size frames
/// with no framing of their own, so this number *is* the frame boundary:
/// getting it wrong desynchronizes the stream rather than failing loudly,
/// which is why the dimensions are computed here and handed to ffmpeg as
/// literals instead of being left for ffmpeg to derive.
fn frame_len(dims: (u16, u16)) -> usize {
    usize::from(dims.0) * usize::from(dims.1) * 3
}

/// Progress reported by the conversion worker thread.
pub enum ConvertEvent {
    /// 0..=100, sent at most once per percentage point.
    Progress(u8),
    /// The `.pulseclip` cache file is ready to load.
    Done(PathBuf),
    /// Conversion could not complete; nothing was left at the cache path.
    Failed(String),
}

/// Environment override for the cache root. Set it to redirect every
/// `.pulseclip` this process writes somewhere other than the user profile;
/// the test build redirects itself (see `backgrounds_dir`) so a test run
/// can never deposit cache files in the real `%LOCALAPPDATA%`.
pub const BACKGROUNDS_DIR_ENV: &str = "PCPULSE_BACKGROUNDS_DIR";

/// The single choke point for where converted clips live:
/// `$PCPULSE_BACKGROUNDS_DIR` when set, otherwise
/// `%LOCALAPPDATA%\PcPulse\backgrounds` — and, under `cfg(test)`, a
/// per-process scratch directory under `%TEMP%` instead of the profile.
pub fn backgrounds_dir() -> Result<PathBuf> {
    if let Some(dir) = env::var_os(BACKGROUNDS_DIR_ENV).filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    #[cfg(test)]
    {
        Ok(tests::scratch_backgrounds_dir())
    }
    #[cfg(not(test))]
    {
        let local_app_data =
            env::var_os("LOCALAPPDATA").ok_or_else(|| anyhow!("LOCALAPPDATA is not set"))?;
        Ok(PathBuf::from(local_app_data)
            .join("PcPulse")
            .join("backgrounds"))
    }
}

/// The deterministic cache path for `source` at `cap`:
/// `{backgrounds_dir}\{hash}.pulseclip`, keyed on the source path, its
/// mtime, and the resolution cap in force — so a changed file, or a changed
/// quality preset, reconverts instead of serving a cache captured at some
/// other size.
///
/// The cap, not the converted size: the converted size is a pure function of
/// (source dimensions, cap), and the source's dimensions cannot change
/// without its mtime changing — which is already in the key. Hashing the cap
/// is also the only option available here, because callers ask for the cache
/// path *before* anything has probed the source.
pub fn cache_path(source: &Path, cap: (u16, u16)) -> Result<PathBuf> {
    let metadata = fs::metadata(source)
        .with_context(|| format!("reading metadata for {}", source.display()))?;
    let modified = metadata
        .modified()
        .with_context(|| format!("reading mtime for {}", source.display()))?;
    let mtime_ms = modified
        .duration_since(std::time::UNIX_EPOCH)
        .context("source mtime predates the Unix epoch")?
        .as_millis() as u64;

    let hash = cache_key(source, mtime_ms, cap.0, cap.1);

    let dir = backgrounds_dir()?;
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir.join(format!("{hash:016x}.pulseclip")))
}

/// Delete every converted clip in the cache root except `keep`.
///
/// Exactly one background is ever live, so every other `.pulseclip` beside
/// it is dead weight: a clip converted from a video that has since been
/// replaced, one converted at a quality that has since changed, or the
/// `.pulseclip.tmp` an interrupted conversion abandoned. At up to hundreds
/// of megabytes per clip that directory grew without bound; this is what
/// collects it. Called after a *successful* load, so the survivor is known
/// to be a file that opens.
///
/// The directory swept is `keep`'s own parent rather than a second call to
/// [`backgrounds_dir`], and that is deliberate: every path that reaches
/// here came from [`cache_path`], which builds `backgrounds_dir().join(..)`,
/// so the two are the same directory — and taking it from `keep` makes the
/// sweep and its survivor *provably* the same place. Asking twice could,
/// if the two ever disagreed, sweep a directory the live file is not in and
/// so delete every clip there while sparing nothing.
///
/// Every failure is ignored on purpose. A file still held open by a worker
/// whose conversion was superseded mid-stream, or one locked by something
/// else, is not worth a word in the status line: the next successful load
/// sweeps it instead.
pub fn sweep_superseded(keep: &Path) {
    let (Some(dir), Some(survivor)) = (keep.parent(), keep.file_name()) else {
        return;
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        // Windows filenames are case-insensitive, and nothing else in this
        // directory belongs to anyone else, but the sweep is still confined
        // to the two extensions this module writes.
        if !is_cache_file(&name) || name.eq_ignore_ascii_case(survivor) {
            continue;
        }
        let _ = fs::remove_file(entry.path());
    }
}

/// Whether `name` is something this module wrote: a converted clip or the
/// temp sibling one is streamed into.
fn is_cache_file(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy().to_ascii_lowercase();
    name.ends_with(".pulseclip") || name.ends_with(".pulseclip.tmp")
}

/// The cache filename's hash input, kept separate from `cache_path` so the
/// cap's presence in the key is testable without a filesystem: a move to a
/// different quality preset must land on a different filename, or the cache
/// written at the old one would be served back at the wrong resolution.
fn cache_key(source: &Path, mtime_ms: u64, cap_w: u16, cap_h: u16) -> u64 {
    let mut key = Vec::new();
    key.extend_from_slice(source.to_string_lossy().as_bytes());
    key.extend_from_slice(&mtime_ms.to_le_bytes());
    key.extend_from_slice(&cap_w.to_le_bytes());
    key.extend_from_slice(&cap_h.to_le_bytes());
    fnv1a64(&key)
}

/// The FNV-1a 64-bit hash: small, dependency-free, and more than sufficient
/// to key a local cache filename.
fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// The capture size for a source of `source_dims` under `cap`: the source's
/// own dimensions shrunk to fit inside the cap box with the aspect ratio
/// preserved, **never** enlarged, and always an even height.
///
/// So at the `High` cap a 640x360 clip is captured at 640x360 — every pixel
/// it has, no invented ones — while 1920x1080 is bound by the height and
/// lands at 825x464. A source whose dimensions the banner didn't reveal
/// falls back to the full box; that only happens for input ffmpeg is about
/// to fail on anyway, and a deterministic size keeps the frame boundary
/// well-defined.
///
/// The height is rounded *down* to even rather than to the nearest, because
/// rounding up would enlarge the source by a row — the one thing this is not
/// allowed to do. The single degenerate exception is a source only one pixel
/// tall, which is floored to zero and then lifted back to the two rows a
/// half-block cell needs.
pub fn capture_dims(source_dims: Option<(u32, u32)>, cap: (u16, u16)) -> (u16, u16) {
    let cap_w = u32::from(cap.0);
    let cap_h = u32::from(cap.1);
    let Some((src_w, src_h)) = source_dims.filter(|(w, h)| *w > 0 && *h > 0) else {
        return cap;
    };
    let (width, height) = if src_w <= cap_w && src_h <= cap_h {
        // Already inside the box: keep every pixel the source has.
        (src_w, src_h)
    } else if u64::from(src_w) * u64::from(cap_h) >= u64::from(src_h) * u64::from(cap_w) {
        // Wider than the box's aspect, so the width binds and the height
        // follows from it.
        (
            cap_w,
            round_div(u64::from(src_h) * u64::from(cap_w), u64::from(src_w)),
        )
    } else {
        (
            round_div(u64::from(src_w) * u64::from(cap_h), u64::from(src_h)),
            cap_h,
        )
    };
    (
        width.clamp(1, cap_w) as u16,
        (height & !1).clamp(2, cap_h) as u16,
    )
}

/// Half-up integer division, so an aspect-derived axis lands on the nearest
/// pixel rather than always truncating toward a squarer frame.
fn round_div(numerator: u64, denominator: u64) -> u32 {
    ((numerator + denominator / 2) / denominator).min(u64::from(u32::MAX)) as u32
}

/// Pure argument builder for the frame-streaming ffmpeg invocation. Kept
/// separate from process spawning so it is unit-testable without ffmpeg
/// installed.
///
/// The scale filter carries the literal target size rather than an
/// expression like `min(iw,832)` with `force_original_aspect_ratio=decrease`.
/// Both express the same fit, but only the literal makes *this* code the
/// single authority on the answer, and the answer has to be exact: raw
/// rawvideo frames are unframed, so a size we predicted differently from the
/// one ffmpeg chose would not be an error, it would be a stream read one
/// frame-boundary out of step. The literal also survives sources ffmpeg
/// auto-rotates, where the banner's dimensions and the decoder's output are
/// transposed.
pub fn ffmpeg_args(source: &Path, capture_fps: f32, dims: (u16, u16)) -> Vec<OsString> {
    let (width, height) = dims;
    vec![
        OsString::from("-i"),
        OsString::from(source),
        OsString::from("-vf"),
        OsString::from(format!("scale={width}:{height}")),
        OsString::from("-r"),
        OsString::from(format_fps(capture_fps)),
        OsString::from("-f"),
        OsString::from("rawvideo"),
        OsString::from("-pix_fmt"),
        OsString::from("rgb24"),
        OsString::from("-loglevel"),
        OsString::from("info"),
        OsString::from("-"),
    ]
}

/// Renders a whole-number fps as `"48"` rather than `"48.0"`; ffmpeg accepts
/// either, but a plain integer reads better in a rendered command line.
fn format_fps(fps: f32) -> String {
    if fps.fract() == 0.0 {
        format!("{}", fps as i64)
    } else {
        format!("{fps}")
    }
}

/// What the ffmpeg banner says about a source video.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Probe {
    /// Capture rate, already clamped to the 60 fps ceiling.
    pub fps: f32,
    pub duration_secs: f32,
    /// The source's own pixel size, or `None` when the banner carried no
    /// recognizable one. Only the *fit* derived from it is ever used.
    pub source_dims: Option<(u32, u32)>,
}

/// Parses ffmpeg's banner (written to stderr for every invocation) for the
/// source's fps, duration, and pixel size, defaulting to `30.0`/`0.0`/`None`
/// when any of them is unrecognizable.
pub fn parse_probe(stderr_text: &str) -> Probe {
    Probe {
        fps: parse_fps(stderr_text).unwrap_or(30.0).min(60.0),
        duration_secs: parse_duration(stderr_text).unwrap_or(0.0),
        source_dims: parse_dims(stderr_text),
    }
}

/// Pulls `WxH` off the first video stream's banner line.
///
/// That line is a comma-salad of codec details, several of which contain an
/// `x` between digits — `(avc1 / 0x31637661)` most reliably. Both a zero
/// width and an implausible axis reject a candidate and the scan moves on,
/// which is what tells the real `640x360` from the hex FourCC beside it. The
/// search is confined to the stream line so nothing in a file *path* printed
/// above it can be mistaken for a resolution.
fn parse_dims(text: &str) -> Option<(u32, u32)> {
    /// No real capture is beyond this on either axis, and every false
    /// positive seen in a banner is.
    const PLAUSIBLE: u32 = 32_768;
    let line = text.lines().find(|line| line.contains("Video:"))?;
    let bytes = line.as_bytes();
    for (index, _) in line.match_indices('x') {
        let start = bytes[..index]
            .iter()
            .rposition(|byte| !byte.is_ascii_digit())
            .map_or(0, |at| at + 1);
        let end = index
            + 1
            + bytes[index + 1..]
                .iter()
                .position(|byte| !byte.is_ascii_digit())
                .unwrap_or(bytes.len() - index - 1);
        let (Ok(width), Ok(height)) = (
            line[start..index].parse::<u32>(),
            line[index + 1..end].parse::<u32>(),
        ) else {
            continue;
        };
        if (1..=PLAUSIBLE).contains(&width) && (1..=PLAUSIBLE).contains(&height) {
            return Some((width, height));
        }
    }
    None
}

/// Finds the first `" fps"` marker and walks backward over the digits/dot
/// that precede it — ffmpeg prints fps as e.g. `120 fps` or `29.97 fps`.
fn parse_fps(text: &str) -> Option<f32> {
    let marker = text.find(" fps")?;
    let before = &text[..marker];
    let bytes = before.as_bytes();
    let mut start = bytes.len();
    while start > 0 {
        let byte = bytes[start - 1];
        if byte.is_ascii_digit() || byte == b'.' {
            start -= 1;
        } else {
            break;
        }
    }
    before[start..].parse::<f32>().ok()
}

/// Finds `"Duration: HH:MM:SS.cc"` and converts it to seconds.
fn parse_duration(text: &str) -> Option<f32> {
    const MARKER: &str = "Duration: ";
    let start = text.find(MARKER)? + MARKER.len();
    let after = &text[start..];
    let end = after.find(',').unwrap_or(after.len());
    parse_hms(after[..end].trim())
}

fn parse_hms(text: &str) -> Option<f32> {
    let mut parts = text.split(':');
    let hours: f32 = parts.next()?.parse().ok()?;
    let minutes: f32 = parts.next()?.parse().ok()?;
    let seconds: f32 = parts.next()?.parse().ok()?;
    Some(hours * 3_600.0 + minutes * 60.0 + seconds)
}

/// A running conversion: the channel its worker reports on, and the flag
/// that stops it. The two are one value on purpose — a cancellation token
/// that could be separated from its receiver is a worker somebody can walk
/// away from without stopping.
///
/// Cloning shares the one worker: every clone reads the same channel and
/// raises the same flag, so whoever holds one can stop the conversion.
#[derive(Clone)]
pub struct ConvertHandle {
    /// Progress, and the single terminal `Done`/`Failed` — unless the
    /// conversion is cancelled, which is silent.
    pub events: Receiver<ConvertEvent>,
    cancel: Arc<AtomicBool>,
}

impl ConvertHandle {
    /// Tell the worker to stop. It notices between frames, kills its ffmpeg,
    /// throws away the partial clip, and exits without reporting anything.
    /// Cheap and idempotent: cancelling a worker that has already finished
    /// does nothing at all.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Whether this conversion has been told to stop.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Whether both handles are onto the same worker.
    pub fn same_channel(&self, other: &Self) -> bool {
        self.events.same_channel(&other.events)
    }

    /// A handle onto a channel a test drives by hand: its flag belongs to no
    /// worker, so raising it stops nothing. The real one comes only from
    /// [`spawn_convert`].
    #[cfg(test)]
    pub(crate) fn stub(events: Receiver<ConvertEvent>) -> Self {
        Self {
            events,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Spawns the detached conversion worker and returns the handle it reports
/// progress on and is stopped through. If `cache_path(&source, cap)` already
/// exists, the worker sends `Done` immediately without touching ffmpeg at
/// all — which is what makes this the cheap "load what we already have" path
/// as well.
pub fn spawn_convert(source: PathBuf, cap: (u16, u16)) -> ConvertHandle {
    let (tx, rx) = bounded(16);
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);
    let _ = thread::Builder::new()
        .name("pcpulse-clip-convert".into())
        .spawn(move || run_convert(&source, cap, &tx, &worker_cancel));
    ConvertHandle { events: rx, cancel }
}

fn run_convert(source: &Path, cap: (u16, u16), tx: &Sender<ConvertEvent>, cancel: &AtomicBool) {
    // Superseded before the worker got its first turn on a core. Nothing has
    // been spawned or written yet, so there is nothing to unwind either.
    if cancel.load(Ordering::Relaxed) {
        return;
    }
    let cache = match cache_path(source, cap) {
        Ok(cache) => cache,
        Err(error) => {
            report(tx, cancel, ConvertEvent::Failed(format!("{error:#}")));
            return;
        }
    };
    // An existing cache is only trusted if it still opens. A file left by
    // an interrupted conversion (an older build wrote straight to the final
    // path) or by disk corruption would otherwise short-circuit to `Done`
    // forever, and the player would fail to load it every single time with
    // no way out from the UI. Delete it and convert again instead.
    if cache.exists() {
        if ClipReader::open(&cache).is_ok() {
            report(tx, cancel, ConvertEvent::Done(cache));
            return;
        }
        let _ = fs::remove_file(&cache);
    }
    if let Err(error) = convert(source, &cache, cap, tx, cancel) {
        report(tx, cancel, ConvertEvent::Failed(format!("{error:#}")));
    }
}

/// Sends `event` unless the conversion has been cancelled.
///
/// A cancelled worker is silent by contract: whoever cancelled it has
/// already let go of the receiver, so a `Done` would name a clip that was
/// thrown away and a `Failed` would report the stop the person asked for as
/// an error. The check also catches a cancellation that lands *after* a
/// genuine failure — the flag is raised while the error is on its way up
/// through `run_convert` — which would otherwise put an error on screen for
/// a conversion nobody is waiting for any more.
fn report(tx: &Sender<ConvertEvent>, cancel: &AtomicBool, event: ConvertEvent) {
    if !cancel.load(Ordering::Relaxed) {
        let _ = tx.send(event);
    }
}

/// Runs the two ffmpeg invocations (probe, then frame stream) and drives
/// `ClipWriter`. A failure anywhere in here leaves `cache` untouched: the
/// writer streams into a temp sibling and only moves it into place once
/// `finish()` has written a complete file.
///
/// The probe runs before the first cancellation check and cannot itself be
/// interrupted. That is deliberate: it decodes nothing, exits in tens of
/// milliseconds, and interrupting it would only bring the check that opens
/// the frame loop a moment forward.
fn convert(
    source: &Path,
    cache: &Path,
    cap: (u16, u16),
    tx: &Sender<ConvertEvent>,
    cancel: &AtomicBool,
) -> Result<()> {
    let banner = probe(source)?;
    let Probe {
        fps: capture_fps,
        duration_secs,
        source_dims,
    } = parse_probe(&banner);
    // The capture size is settled here, before a single byte is read: the
    // scale filter, the clip header, and the frame boundary the read loop
    // trusts all come from this one value.
    let dims = capture_dims(source_dims, cap);

    let args = ffmpeg_args(source, capture_fps, dims);
    // stdout is a pipe whose read end this process owns, which is also what
    // makes a TUI exit tidy without any cancellation: the worker is
    // detached, so it dies with the process, the pipe closes with the last
    // handle, and ffmpeg's next write into it fails and takes ffmpeg down.
    let mut child = ffmpeg_command()
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(classify_spawn_error)?;
    let mut stdout = child
        .stdout
        .take()
        .context("ffmpeg produced no stdout pipe")?;

    let mut writer = ClipWriter::create(cache, dims.0, dims.1, capture_fps)?;
    // Guards the progress denominator when the probe couldn't determine a
    // duration: every frame still reports forward progress, just capped
    // below 100% until the stream actually ends.
    let expected_frames = (f64::from(duration_secs) * f64::from(capture_fps)).max(1.0);

    let frames_read =
        match stream_frames(&mut stdout, &mut writer, dims, expected_frames, cancel, tx) {
            Ok(Stream::Ended(frames_read)) => frames_read,
            // Superseded mid-stream. Kill ffmpeg rather than leave it
            // decoding for a clip nobody will load, and let the writer go —
            // dropping it unfinished takes its own scratch file with it, and
            // only its own: the successor converting the same source at the
            // same ceiling shares this final path and must not have its file
            // deleted out from under it (see `pulseclip::temp_sibling`).
            // There is no partial *final* file to delete either, because
            // nothing is written to `cache` before `finish()`, which is past
            // this point.
            Ok(Stream::Cancelled) => {
                let _ = child.kill();
                let _ = child.wait();
                drop(writer);
                // Silence is `report`'s doing: with the flag raised, no `Done`
                // and no `Failed` can leave this worker whatever it returns.
                return Ok(());
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };

    let status = child.wait().context("waiting for ffmpeg to exit")?;
    if !status.success() {
        bail!("ffmpeg exited with {status}");
    }
    if frames_read == 0 {
        bail!("ffmpeg produced no frames");
    }
    writer.finish()?;
    report(tx, cancel, ConvertEvent::Done(cache.to_path_buf()));
    Ok(())
}

/// How the frame stream ended: cleanly at end of input, with the frame count,
/// or because the conversion was cancelled.
enum Stream {
    Ended(u64),
    Cancelled,
}

/// Pumps raw frames from `frames` into `writer`, reporting progress against
/// `expected_frames` and stopping the moment `cancel` is raised.
///
/// Split out of [`convert`] so the cancellation path is testable without
/// ffmpeg: a stub reader stands in for the stream, which is what an
/// unbounded conversion looks like from in here.
///
/// The flag is read once per frame, so a cancellation waits at most one
/// frame read — milliseconds, since a stalled ffmpeg is not the case being
/// stopped. Checking mid-frame would mean interrupting a blocking read on a
/// pipe, which needs the read to be abandonable; the frame boundary is the
/// cheap, exact place where nothing is half-consumed.
fn stream_frames<R: Read>(
    frames: &mut R,
    writer: &mut ClipWriter,
    dims: (u16, u16),
    expected_frames: f64,
    cancel: &AtomicBool,
    tx: &Sender<ConvertEvent>,
) -> Result<Stream> {
    let mut buffer = vec![0u8; frame_len(dims)];
    let mut frames_read: u64 = 0;
    let mut last_percent: u8 = 0;

    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(Stream::Cancelled);
        }
        // A frame that ends short is the one way a size disagreement with
        // ffmpeg can show itself, so the expected size travels with the
        // error.
        if !read_frame(frames, &mut buffer)
            .with_context(|| format!("reading {}x{} frames from ffmpeg", dims.0, dims.1))?
        {
            return Ok(Stream::Ended(frames_read));
        }
        mute(&mut buffer);
        writer.push_frame(&buffer)?;
        frames_read += 1;
        let percent = ((frames_read as f64 / expected_frames) * 100.0).clamp(0.0, 99.0) as u8;
        if percent > last_percent {
            last_percent = percent;
            let _ = tx.send(ConvertEvent::Progress(percent));
        }
    }
}

/// Runs `ffmpeg -i <source>` with no output file purely to capture the
/// banner ffmpeg always writes to stderr; a nonzero exit is expected (no
/// output was requested) and ignored.
fn probe(source: &Path) -> Result<String> {
    let mut child = ffmpeg_command()
        .arg("-i")
        .arg(source)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(classify_spawn_error)?;
    let mut banner = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut banner);
    }
    let _ = child.wait();
    Ok(banner)
}

/// Reads exactly one frame — `buf.len()` bytes, sized by `frame_len` for
/// the capture dimensions in force — from `reader` into `buf`.
/// Returns `Ok(true)` on a full frame, `Ok(false)` on a clean end-of-stream
/// (no bytes read before EOF), and `Err` for a short read that stops
/// mid-frame or any I/O error.
fn read_frame<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        let read = reader.read(&mut buf[filled..])?;
        if read == 0 {
            if filled == 0 {
                return Ok(false);
            }
            bail!(
                "ffmpeg stdout ended mid-frame ({filled} of {} bytes)",
                buf.len()
            );
        }
        filled += read;
    }
    Ok(true)
}

fn ffmpeg_command() -> Command {
    let mut command = Command::new("ffmpeg.exe");
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

/// Maps a `Command::spawn` failure to a friendly, actionable message when
/// ffmpeg simply isn't installed.
fn classify_spawn_error(error: std::io::Error) -> anyhow::Error {
    if error.kind() == std::io::ErrorKind::NotFound {
        anyhow!("ffmpeg.exe not found — install it with: winget install ffmpeg")
    } else {
        anyhow::Error::new(error).context("failed to start ffmpeg")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cache root for the whole test binary: a per-process directory
    /// under `%TEMP%`, never `%LOCALAPPDATA%\PcPulse\backgrounds`.
    /// `backgrounds_dir` routes here for every test, so no test can forget
    /// to opt in and quietly litter the real user profile.
    pub(super) fn scratch_backgrounds_dir() -> PathBuf {
        std::env::temp_dir().join(format!("pcpulse-test-backgrounds-{}", std::process::id()))
    }

    /// The default cap, which is what every test that is not about the
    /// preset ladder itself works at.
    const HIGH: (u16, u16) = BackgroundQuality::High.cap();

    /// A scratch file standing in for a source video.
    fn scratch_source(tag: &str) -> PathBuf {
        let source = std::env::temp_dir().join(format!(
            "pcpulse-clipconvert-{tag}-{}.mp4",
            std::process::id()
        ));
        fs::write(&source, b"stands in for a video file").unwrap();
        source
    }

    #[test]
    fn the_cache_root_is_redirectable_and_never_the_real_profile_in_tests() {
        let source = scratch_source("root");
        let cache = cache_path(&source, HIGH).unwrap();
        assert_eq!(cache.parent().unwrap(), scratch_backgrounds_dir());
        if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
            assert!(
                !cache.starts_with(PathBuf::from(local_app_data).join("PcPulse")),
                "a test run must never write into the real profile: {}",
                cache.display()
            );
        }
        let _ = fs::remove_file(&source);
    }

    #[test]
    fn every_cache_path_lives_directly_in_the_backgrounds_dir() {
        // `sweep_superseded` takes the directory to sweep from the file it
        // is keeping, which is only the cache root because `cache_path`
        // puts it there. Pin that.
        let source = scratch_source("parent");
        let cache = cache_path(&source, HIGH).unwrap();
        assert_eq!(cache.parent().unwrap(), backgrounds_dir().unwrap());
        let _ = fs::remove_file(&source);
    }

    #[test]
    fn the_sweep_keeps_the_live_clip_and_nothing_else_it_wrote() {
        // A directory of this test's own: the scratch cache root is shared
        // by every test in this binary, and a sweep there would delete
        // fixtures other tests are still using.
        let dir = std::env::temp_dir().join(format!("pcpulse-sweep-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let live = dir.join("aaaa000000000001.pulseclip");
        let superseded = dir.join("bbbb000000000002.pulseclip");
        let abandoned = dir.join("cccc000000000003.pulseclip.tmp");
        let bystander = dir.join("notes.txt");
        for file in [&live, &superseded, &abandoned, &bystander] {
            fs::write(file, b"x").unwrap();
        }

        sweep_superseded(&live);

        assert!(live.exists(), "the clip now playing was deleted");
        assert!(!superseded.exists(), "a superseded clip survived");
        assert!(!abandoned.exists(), "an abandoned temp file survived");
        assert!(bystander.exists(), "the sweep reached past its own files");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_sweep_collects_the_scratch_file_of_a_worker_that_never_came_back() {
        // Scratch files carry a per-worker tag so two conversions aimed at
        // one cache file cannot delete each other's, and the sweep is the
        // only thing that ever collects one whose worker died with the
        // process. It recognizes them by their ending, so the tag must not
        // put them out of its reach.
        let dir = std::env::temp_dir().join(format!("pcpulse-sweep-tag-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let live = dir.join("aaaa000000000001.pulseclip");
        fs::write(&live, b"x").unwrap();
        let orphan = {
            let writer =
                ClipWriter::create(&dir.join("bbbb000000000002.pulseclip"), 4, 2, 30.0).unwrap();
            let scratch = writer.temp_path().to_path_buf();
            // The TUI quitting mid-conversion: no `Drop` ever runs.
            std::mem::forget(writer);
            scratch
        };
        assert!(orphan.exists(), "no scratch file to collect");

        sweep_superseded(&live);

        assert!(!orphan.exists(), "a tagged scratch file escaped the sweep");
        assert!(live.exists(), "the clip now playing was deleted");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_sweep_of_a_directory_that_is_not_there_is_silent() {
        // Nothing to collect is not a failure, and neither is a cache root
        // that has not been created yet.
        sweep_superseded(
            &std::env::temp_dir()
                .join("pcpulse-no-such-dir")
                .join("x.pulseclip"),
        );
        sweep_superseded(Path::new("x.pulseclip"));
    }

    /// A stdout that never ends: every read hands back a slice of a frame
    /// after a short pause, the way a real ffmpeg trickles one out. It is the
    /// stand-in for a multi-minute source — a conversion that would run for
    /// as long as the test cared to wait.
    struct EndlessFrames;

    impl Read for EndlessFrames {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            thread::sleep(std::time::Duration::from_millis(2));
            let filled = buf.len().min(64);
            buf[..filled].fill(0x40);
            Ok(filled)
        }
    }

    #[test]
    fn a_cancelled_conversion_stops_promptly_and_leaves_no_temp_file() {
        // Superseding a conversion used to just drop the receiver: the worker
        // kept ffmpeg running to completion for a clip nobody would load.
        let source = scratch_source("cancel-midstream");
        let cache = cache_path(&source, HIGH).unwrap();
        let dims = (4u16, 2u16);
        let mut writer = ClipWriter::create(&cache, dims.0, dims.1, 30.0).unwrap();
        let temp = writer.temp_path().to_path_buf();
        assert!(temp.exists(), "the writer owns a temp file to clean up");

        let cancel = Arc::new(AtomicBool::new(false));
        let raiser = Arc::clone(&cancel);
        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(20));
            raiser.store(true, Ordering::Relaxed);
        });

        let (tx, rx) = bounded(1_024);
        let started = std::time::Instant::now();
        let outcome = stream_frames(
            &mut EndlessFrames,
            &mut writer,
            dims,
            1_000_000.0,
            &cancel,
            &tx,
        )
        .unwrap();
        let elapsed = started.elapsed();

        assert!(matches!(outcome, Stream::Cancelled), "the worker ran on");
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "cancellation took {elapsed:?}"
        );
        // What the worker does on cancel: let the writer go, which takes the
        // temp file with it. Nothing was ever written to the final path.
        drop(writer);
        assert!(
            !temp.exists(),
            "a cancelled conversion left its .tmp behind"
        );
        assert!(
            !cache.exists(),
            "a cancelled conversion left a partial clip"
        );

        // Nobody is listening to a cancelled conversion, so it never reports
        // an outcome — no `Done` to load a half-clip, no `Failed` to shout
        // about a stop the person asked for.
        drop(tx);
        assert!(
            rx.iter()
                .all(|event| matches!(event, ConvertEvent::Progress(_))),
            "a cancelled conversion reported an outcome"
        );
        let _ = fs::remove_file(&source);
    }

    #[test]
    fn a_worker_cancelled_before_it_starts_never_reaches_ffmpeg() {
        // The window between `spawn_convert` and the worker's first frame is
        // small but real: a preset cycled twice in a second lands in it.
        let source = scratch_source("cancel-early");
        let cancel = Arc::new(AtomicBool::new(true));
        let (tx, rx) = bounded(16);

        let started = std::time::Instant::now();
        run_convert(&source, HIGH, &tx, &cancel);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "an already-cancelled worker still probed the source"
        );

        drop(tx);
        assert_eq!(rx.iter().count(), 0, "a cancelled worker spoke");
        let _ = fs::remove_file(&source);
    }

    #[test]
    fn a_handle_shares_one_token_with_every_clone_of_itself() {
        // `App` keeps a handle and hands clones to whoever asks; cancelling
        // through any of them has to stop the one worker behind them all.
        let (tx, rx) = bounded(1);
        drop(tx);
        let handle = ConvertHandle::stub(rx);
        let clone = handle.clone();
        assert!(!handle.is_cancelled() && !clone.is_cancelled());
        assert!(handle.same_channel(&clone));

        clone.cancel();

        assert!(
            handle.is_cancelled(),
            "the clone cancelled a different flag"
        );
    }

    #[test]
    fn a_corrupt_cache_file_is_thrown_away_instead_of_reported_done() {
        let source = scratch_source("corrupt");
        let cache = cache_path(&source, HIGH).unwrap();
        // The 0-byte file an interrupted conversion used to leave at the
        // final path. Trusting `cache.exists()` here reported `Done`
        // instantly and the player failed on it forever.
        fs::write(&cache, b"").unwrap();

        let (tx, rx) = bounded(16);
        run_convert(&source, HIGH, &tx, &AtomicBool::new(false));
        drop(tx);
        let events: Vec<ConvertEvent> = rx.iter().collect();

        assert!(
            !events
                .iter()
                .any(|event| matches!(event, ConvertEvent::Done(_))),
            "an unreadable cache file was reported as ready"
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, ConvertEvent::Failed(_))),
            "the reconversion attempt reported nothing"
        );
        assert!(!cache.exists(), "the unreadable cache file survived");
        let _ = fs::remove_file(&source);
    }

    /// Renders the frame-streaming args for a source of `source_dims`, the
    /// way `convert` composes them.
    fn rendered_args(source_dims: Option<(u32, u32)>) -> Vec<String> {
        ffmpeg_args(
            Path::new(r"C:\videos\my clip (1).mp4"),
            48.0,
            capture_dims(source_dims, HIGH),
        )
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
    }

    #[test]
    fn ffmpeg_args_pass_the_path_as_a_single_vector_item() {
        let rendered = rendered_args(Some((1920, 1080)));
        assert_eq!(rendered[0], "-i");
        assert_eq!(rendered[1], r"C:\videos\my clip (1).mp4"); // spaces intact, no quoting
        assert!(rendered.contains(&"48".to_string()));
        assert_eq!(rendered.last().unwrap(), "-");
    }

    #[test]
    fn a_source_inside_the_cap_is_captured_at_its_own_size() {
        // "More HD" must never mean "invented pixels": a 640x360 clip has
        // 640x360 of real detail and gets converted at exactly that.
        assert_eq!(capture_dims(Some((640, 360)), HIGH), (640, 360));
        assert!(rendered_args(Some((640, 360))).contains(&"scale=640:360".to_string()));
        // ...including a source that is small on both axes.
        assert_eq!(capture_dims(Some((320, 180)), HIGH), (320, 180));
        // ...and one that exactly fills the box.
        assert_eq!(
            capture_dims(Some((u32::from(HIGH.0), u32::from(HIGH.1))), HIGH),
            HIGH
        );
    }

    #[test]
    fn a_1080p_source_is_fitted_inside_the_cap_with_its_aspect_intact() {
        // 1080p is bound by the height: 464/1080 of 1920 is 824.9, so 825.
        let dims = capture_dims(Some((1920, 1080)), HIGH);
        assert_eq!(dims, (825, HIGH.1));
        assert!(rendered_args(Some((1920, 1080))).contains(&"scale=825:464".to_string()));
        // Nothing left the box, and the aspect survived to within a pixel.
        assert!(dims.0 <= HIGH.0 && dims.1 <= HIGH.1);
        assert!((f64::from(dims.0) / f64::from(dims.1) - 16.0 / 9.0).abs() < 0.002);

        // An ultra-wide source binds on the *other* axis instead.
        let wide = capture_dims(Some((3840, 1080)), HIGH);
        assert_eq!(wide, (HIGH.0, 234));
        assert!(wide.0 <= HIGH.0 && wide.1 <= HIGH.1);
    }

    #[test]
    fn an_odd_capture_height_is_rounded_down_to_even_never_up() {
        // The renderer paints two stacked pixels per cell, so an odd height
        // leaves a half-cell row with nothing to sample. Rounding *down* is
        // the point: rounding up would magnify the source by a row.
        assert_eq!(HIGH.1 % 2, 0, "the cap itself must be an even height");
        assert_eq!(capture_dims(Some((640, 361)), HIGH), (640, 360));
        assert_eq!(capture_dims(Some((640, 359)), HIGH), (640, 358));
        // A *fitted* source whose derived height lands odd: 1000x557 is
        // bound by the width, and 557 * 832/1000 is 463.4, which rounds to
        // the odd 463 and then floors to 462.
        let dims = capture_dims(Some((1000, 557)), HIGH);
        assert_eq!(dims, (HIGH.0, 462));
        assert_eq!(dims.1 % 2, 0);
        // Every derived height is even, whatever the source.
        for height in 1..=2_000_u32 {
            let (_, out_h) = capture_dims(Some((1920, height)), HIGH);
            assert_eq!(out_h % 2, 0, "odd capture height for source 1920x{height}");
        }
    }

    #[test]
    fn an_unreadable_source_size_falls_back_to_the_whole_box() {
        // Only reachable for input ffmpeg is about to fail on anyway; what
        // matters is that the frame boundary stays well-defined.
        assert_eq!(capture_dims(None, HIGH), HIGH);
        assert_eq!(capture_dims(Some((0, 1080)), HIGH), HIGH);
        assert_eq!(capture_dims(Some((1920, 0)), HIGH), HIGH);
        // ...and it is the *active* cap it falls back to, not a constant.
        let low = BackgroundQuality::Low.cap();
        assert_eq!(capture_dims(None, low), low);
    }

    #[test]
    fn the_quality_ladder_only_ever_shrinks_what_the_source_already_had() {
        // Every preset is a ceiling, so a source smaller than the ceiling is
        // captured whole whichever preset is chosen, and a source larger
        // than it is fitted inside with the aspect intact.
        for quality in [
            BackgroundQuality::Low,
            BackgroundQuality::Medium,
            BackgroundQuality::High,
            BackgroundQuality::Ultra,
        ] {
            let cap = quality.cap();
            assert_eq!(cap.1 % 2, 0, "{} has an odd cap height", quality.name());
            let fitted = capture_dims(Some((1920, 1080)), cap);
            assert!(
                fitted.0 <= cap.0 && fitted.1 <= cap.1,
                "{} let 1080p out of its box: {fitted:?}",
                quality.name()
            );
            assert_eq!(fitted.1 % 2, 0);
            assert!((f64::from(fitted.0) / f64::from(fitted.1) - 16.0 / 9.0).abs() < 0.01);
            // A 200x100 source is inside every cap on the ladder, so no
            // preset invents a pixel it does not have.
            assert_eq!(capture_dims(Some((200, 100)), cap), (200, 100));
        }

        // The named sizes, and the ladder's shape: each step doubles both
        // axes, so each step is about four times the pixels.
        assert_eq!(BackgroundQuality::Low.cap(), (208, 116));
        assert_eq!(BackgroundQuality::Medium.cap(), (416, 232));
        assert_eq!(BackgroundQuality::High.cap(), (832, 464));
        assert_eq!(BackgroundQuality::Ultra.cap(), (1248, 702));
        // `High` is the default, which is what every clip converted before
        // the preset existed was captured at.
        assert_eq!(BackgroundQuality::default(), BackgroundQuality::High);
    }

    #[test]
    fn the_quality_ladder_cycles_and_round_trips_through_its_name() {
        let mut quality = BackgroundQuality::Low;
        let mut walked = Vec::new();
        for _ in 0..4 {
            walked.push(quality.name());
            assert_eq!(quality.name().parse::<BackgroundQuality>(), Ok(quality));
            quality = quality.next();
        }
        assert_eq!(walked, ["low", "medium", "high", "ultra"]);
        assert_eq!(quality, BackgroundQuality::Low, "the ladder must wrap");
        // A name from a hand-edited or newer prefs file is not a name here.
        assert_eq!("cinematic".parse::<BackgroundQuality>(), Err(()));
    }

    #[test]
    fn two_qualities_of_one_source_are_two_different_cache_files() {
        // Nothing about the *file* changed, so only the cap can move the
        // key — otherwise switching preset would serve back the clip
        // converted at the previous one.
        let source = scratch_source("quality-key");
        let mut seen = Vec::new();
        for quality in [
            BackgroundQuality::Low,
            BackgroundQuality::Medium,
            BackgroundQuality::High,
            BackgroundQuality::Ultra,
        ] {
            let path = cache_path(&source, quality.cap()).unwrap();
            assert!(!seen.contains(&path), "{} reused a cache", quality.name());
            seen.push(path);
        }
        let _ = fs::remove_file(&source);
    }

    #[test]
    fn probe_parses_fps_duration_and_dimensions_and_clamps_fps_to_60() {
        let banner = "Input #0, mov,mp4, from 'clip.mp4':\n  Duration: 00:03:12.45, start: 0.0, bitrate: 5 kb/s\n  Stream #0:0: Video: h264, yuv420p, 1920x1080, 120 fps, 120 tbr\n";
        let probe = parse_probe(banner);
        assert_eq!(probe.fps, 60.0); // 120 clamped
        assert!((probe.duration_secs - 192.45).abs() < 0.01);
        assert_eq!(probe.source_dims, Some((1920, 1080)));
    }

    #[test]
    fn probe_reads_the_real_size_past_the_hex_fourcc_beside_it() {
        // Verbatim from ffmpeg 8.0. `0x31637661` is an `x` between digits on
        // the same line and sits *before* the resolution.
        let banner = "Input #0, mov,mp4,m4a,3gp,3g2,mj2, from 'C:\\clips\\smoke-test.mp4':\n  Duration: 00:00:15.00, start: 0.000000, bitrate: 796 kb/s\n  Stream #0:0[0x1](und): Video: h264 (High) (avc1 / 0x31637661), yuv420p(progressive), 640x360 [SAR 1:1 DAR 16:9], 793 kb/s, 30 fps, 30 tbr, 15360 tbn (default)\n";
        let probe = parse_probe(banner);
        assert_eq!(probe.source_dims, Some((640, 360)));
        assert_eq!(probe.fps, 30.0);
        assert_eq!(capture_dims(probe.source_dims, HIGH), (640, 360));
    }

    #[test]
    fn probe_defaults_when_the_banner_is_unrecognizable() {
        let probe = parse_probe("garbage");
        assert_eq!(probe.fps, 30.0);
        assert_eq!(probe.duration_secs, 0.0);
        assert_eq!(probe.source_dims, None);
    }

    #[test]
    fn the_resolution_cap_is_in_the_cache_key() {
        // Raising the cap has to invalidate every cache written under the
        // old one; the key carries the cap so the filename moves on its own.
        // The *converted* size need not be in the key: it is a pure function
        // of the cap and the source's own dimensions, and those cannot change
        // without the mtime — already hashed — changing with them.
        let source = Path::new(r"C:\videos\clip.mp4");
        assert_ne!(
            cache_key(source, 1_700_000_000_000, HIGH.0, HIGH.1),
            cache_key(source, 1_700_000_000_000, 416, 232),
            "the 416x232 caches would have been served back under the new cap"
        );
    }

    #[test]
    #[ignore = "dev harness: converts a real video with the installed ffmpeg and prices the cache; set PCPULSE_CONVERT_SOURCE and run with --ignored --nocapture"]
    fn dev_bench_conversion_cost() {
        let Some(source) = env::var_os("PCPULSE_CONVERT_SOURCE").map(PathBuf::from) else {
            println!("set PCPULSE_CONVERT_SOURCE to a video file");
            return;
        };
        // `PCPULSE_CONVERT_QUALITY` prices a preset other than the default.
        let cap = env::var("PCPULSE_CONVERT_QUALITY")
            .ok()
            .and_then(|name| name.parse::<BackgroundQuality>().ok())
            .unwrap_or_default()
            .cap();
        // `backgrounds_dir` already routes the test binary to `%TEMP%`, so
        // this can never deposit anything in the real profile.
        let cache = cache_path(&source, cap).unwrap();
        let _ = fs::remove_file(&cache);

        let banner = probe(&source).unwrap();
        let parsed = parse_probe(&banner);
        let dims = capture_dims(parsed.source_dims, cap);
        let started = std::time::Instant::now();
        let (tx, rx) = bounded(1024);
        run_convert(&source, cap, &tx, &AtomicBool::new(false));
        drop(tx);
        let failure = rx.iter().find_map(|event| match event {
            ConvertEvent::Failed(message) => Some(message),
            _ => None,
        });
        let elapsed = started.elapsed();
        assert!(failure.is_none(), "conversion failed: {failure:?}");

        let bytes = fs::metadata(&cache).unwrap().len();
        let mut reader = ClipReader::open(&cache).unwrap();
        let frames = u64::from(reader.header().frame_count);
        let decode_started = std::time::Instant::now();
        for step in 0..200_u32 {
            let _ = reader.frame(step % reader.header().frame_count).unwrap();
        }
        let per_decode = decode_started.elapsed().as_secs_f64() * 1_000.0 / 200.0;

        println!("source     {}", source.display());
        println!("source dims {:?}", parsed.source_dims);
        println!("capture    {}x{} @ {} fps", dims.0, dims.1, parsed.fps);
        println!("raw frame  {} B", frame_len(dims));
        println!("frames     {frames}");
        println!(
            "cache      {bytes} B ({:.2} MB, {:.0} B/frame, {:.3} B/px)",
            bytes as f64 / 1_048_576.0,
            bytes as f64 / frames as f64,
            bytes as f64 / frames as f64 / (f64::from(dims.0) * f64::from(dims.1))
        );
        println!("convert    {:.2} s", elapsed.as_secs_f64());
        println!("decode     {per_decode:.3} ms/frame");
    }

    #[test]
    fn cache_path_changes_when_source_mtime_changes() {
        let dir = std::env::temp_dir().join("clipconvert-key");
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("v.mp4");
        std::fs::write(&src, b"a").unwrap();
        let first = cache_path(&src, HIGH).unwrap();
        // Push mtime forward well past filesystem timestamp granularity.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(90);
        std::fs::File::options()
            .write(true)
            .open(&src)
            .unwrap()
            .set_modified(later)
            .unwrap();
        let second = cache_path(&src, HIGH).unwrap();
        assert_ne!(first, second);
        assert!(first.extension().unwrap() == "pulseclip");
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir(&dir);
    }
}
