//! One-time ffmpeg conversion of a user-picked video into the `.pulseclip`
//! background cache.
//!
//! A video is converted exactly once: `ffmpeg.exe` is probed for its banner
//! (fps/duration), then re-invoked to stream raw RGB frames on stdout —
//! `mute`d and handed to `ClipWriter` one at a time so a multi-minute source
//! never sits fully decoded in memory. The whole thing runs on a detached
//! worker thread, mirroring `analyzer.rs`'s Codex worker: the caller gets a
//! `crossbeam_channel::Receiver` and polls it from the UI loop instead of
//! blocking on ffmpeg. Every ffmpeg invocation passes its arguments as a
//! vector (never through a shell) and runs with `CREATE_NO_WINDOW` so no
//! console flashes up behind the TUI.

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
use std::thread;

/// Fixed capture grid: coarse enough that full video decoding at source
/// resolution would be wasted work once everything is redrawn as half-block
/// terminal cells.
pub const GRID_W: u16 = 208;
pub const GRID_H: u16 = 116;

/// Windows' own flag: the spawned ffmpeg gets no console window, matching
/// the `DETACHED_PROCESS`-style spawns elsewhere in this crate.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const FRAME_LEN: usize = GRID_W as usize * GRID_H as usize * 3;

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

/// The deterministic cache path for `source`: `{backgrounds_dir}\{hash}.pulseclip`,
/// keyed on the source path, its mtime, and the capture grid so a changed
/// file (or a grid-size change in a future release) reconverts instead of
/// serving a stale cache.
pub fn cache_path(source: &Path) -> Result<PathBuf> {
    let metadata = fs::metadata(source)
        .with_context(|| format!("reading metadata for {}", source.display()))?;
    let modified = metadata
        .modified()
        .with_context(|| format!("reading mtime for {}", source.display()))?;
    let mtime_ms = modified
        .duration_since(std::time::UNIX_EPOCH)
        .context("source mtime predates the Unix epoch")?
        .as_millis() as u64;

    let mut key = Vec::new();
    key.extend_from_slice(source.to_string_lossy().as_bytes());
    key.extend_from_slice(&mtime_ms.to_le_bytes());
    key.extend_from_slice(&GRID_W.to_le_bytes());
    key.extend_from_slice(&GRID_H.to_le_bytes());
    let hash = fnv1a64(&key);

    let dir = backgrounds_dir()?;
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir.join(format!("{hash:016x}.pulseclip")))
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

/// Pure argument builder for the frame-streaming ffmpeg invocation. Kept
/// separate from process spawning so it is unit-testable without ffmpeg
/// installed.
pub fn ffmpeg_args(source: &Path, capture_fps: f32) -> Vec<OsString> {
    vec![
        OsString::from("-i"),
        OsString::from(source),
        OsString::from("-vf"),
        OsString::from(format!("scale={GRID_W}:{GRID_H}")),
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

/// Parses ffmpeg's banner (written to stderr for every invocation) for the
/// source's fps and duration, defaulting to `30.0`/`0.0` when either is
/// unrecognizable. The returned fps is already clamped to the capture
/// ceiling.
pub fn parse_probe(stderr_text: &str) -> (f32, f32) {
    let fps = parse_fps(stderr_text).unwrap_or(30.0).min(60.0);
    let duration = parse_duration(stderr_text).unwrap_or(0.0);
    (fps, duration)
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

/// Spawns the detached conversion worker and returns the channel it reports
/// progress on. If `cache_path(&source)` already exists, the worker sends
/// `Done` immediately without touching ffmpeg at all.
pub fn spawn_convert(source: PathBuf) -> Receiver<ConvertEvent> {
    let (tx, rx) = bounded(16);
    let _ = thread::Builder::new()
        .name("pcpulse-clip-convert".into())
        .spawn(move || run_convert(&source, &tx));
    rx
}

fn run_convert(source: &Path, tx: &Sender<ConvertEvent>) {
    let cache = match cache_path(source) {
        Ok(cache) => cache,
        Err(error) => {
            let _ = tx.send(ConvertEvent::Failed(format!("{error:#}")));
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
            let _ = tx.send(ConvertEvent::Done(cache));
            return;
        }
        let _ = fs::remove_file(&cache);
    }
    if let Err(error) = convert(source, &cache, tx) {
        let _ = tx.send(ConvertEvent::Failed(format!("{error:#}")));
    }
}

/// Runs the two ffmpeg invocations (probe, then frame stream) and drives
/// `ClipWriter`. A failure anywhere in here leaves `cache` untouched: the
/// writer streams into a temp sibling and only moves it into place once
/// `finish()` has written a complete file.
fn convert(source: &Path, cache: &Path, tx: &Sender<ConvertEvent>) -> Result<()> {
    let banner = probe(source)?;
    let (capture_fps, duration_secs) = parse_probe(&banner);

    let args = ffmpeg_args(source, capture_fps);
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

    let mut writer = ClipWriter::create(cache, GRID_W, GRID_H, capture_fps)?;
    let mut buffer = vec![0u8; FRAME_LEN];
    let mut frames_read: u64 = 0;
    // Guards the progress denominator when the probe couldn't determine a
    // duration: every frame still reports forward progress, just capped
    // below 100% until the stream actually ends.
    let expected_frames = (f64::from(duration_secs) * f64::from(capture_fps)).max(1.0);
    let mut last_percent: u8 = 0;

    while read_frame(&mut stdout, &mut buffer)? {
        mute(&mut buffer);
        writer.push_frame(&buffer)?;
        frames_read += 1;
        let percent = ((frames_read as f64 / expected_frames) * 100.0).clamp(0.0, 99.0) as u8;
        if percent > last_percent {
            last_percent = percent;
            let _ = tx.send(ConvertEvent::Progress(percent));
        }
    }

    let status = child.wait().context("waiting for ffmpeg to exit")?;
    if !status.success() {
        bail!("ffmpeg exited with {status}");
    }
    if frames_read == 0 {
        bail!("ffmpeg produced no frames");
    }
    writer.finish()?;
    let _ = tx.send(ConvertEvent::Done(cache.to_path_buf()));
    Ok(())
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

/// Reads exactly one frame (`FRAME_LEN` bytes) from `reader` into `buf`.
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
        let cache = cache_path(&source).unwrap();
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
    fn a_corrupt_cache_file_is_thrown_away_instead_of_reported_done() {
        let source = scratch_source("corrupt");
        let cache = cache_path(&source).unwrap();
        // The 0-byte file an interrupted conversion used to leave at the
        // final path. Trusting `cache.exists()` here reported `Done`
        // instantly and the player failed on it forever.
        fs::write(&cache, b"").unwrap();

        let (tx, rx) = bounded(16);
        run_convert(&source, &tx);
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

    #[test]
    fn ffmpeg_args_pass_the_path_as_a_single_vector_item() {
        let args = ffmpeg_args(Path::new(r"C:\videos\my clip (1).mp4"), 48.0);
        let rendered: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
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
        std::fs::File::options()
            .write(true)
            .open(&src)
            .unwrap()
            .set_modified(later)
            .unwrap();
        let second = cache_path(&src).unwrap();
        assert_ne!(first, second);
        assert!(first.extension().unwrap() == "pulseclip");
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir(&dir);
    }
}
