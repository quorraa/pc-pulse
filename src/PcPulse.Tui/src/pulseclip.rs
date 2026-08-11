//! `.pulseclip` cache codec.
//!
//! Video backgrounds are pre-baked into a small custom container instead of
//! decoding a real video format at runtime: PC Pulse renders to a coarse
//! character grid, so full-color, full-resolution video decoding would be
//! wasted work. Each frame is quantized to a fixed 6x7x6 color cube (252
//! levels, one byte per pixel) and the resulting index stream is deflated.
//! A seek table lets the player jump to any frame without re-reading the
//! whole file, which matters for scrubbing and for restarting playback.
//!
//! File layout (little-endian), exactly as specced:
//!
//! ```text
//! magic b"PCLIP1" | u16 grid_w | u16 grid_h | f32 capture_fps | u32 frame_count
//! u32 seek_table_len | [u64 frame_offset; frame_count]
//! frames: [u32 compressed_len | deflate(quantized indices)]
//! ```
//!
//! The seek table sits *before* the frame data, but its size depends on
//! `frame_count`, which isn't known until every frame has been pushed. So
//! `ClipWriter::push_frame` compresses each frame immediately and appends it
//! to an in-memory buffer of already-compressed bytes (never holding more
//! than one frame's raw pixels at a time), and `finish()` writes the real
//! header, seek table, and buffered frame data in a single sequential pass.
//! This lets frames be pushed one at a time without knowing `frame_count` in
//! advance, at the cost of buffering compressed output until `finish()`.
//!
//! Writing is atomic, the same way `PrefsStore::save` is: everything goes to
//! a `.tmp` sibling and only `finish()` moves it onto the real path. A
//! conversion that is interrupted — the TUI quits and takes its detached
//! worker with it, the machine loses power — therefore leaves no file at the
//! cache path at all, rather than a truncated one the player would refuse
//! forever.

use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAGIC: &[u8; 6] = b"PCLIP1";
/// Byte length of the fixed-size header: magic + grid_w + grid_h + capture_fps + frame_count.
const HEADER_LEN: u64 = 6 + 2 + 2 + 4 + 4;

/// Parsed `.pulseclip` header: grid dimensions, capture rate, and frame count.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClipHeader {
    pub grid_w: u16,
    pub grid_h: u16,
    pub capture_fps: f32,
    pub frame_count: u32,
}

impl ClipHeader {
    fn frame_pixel_len(&self) -> usize {
        usize::from(self.grid_w) * usize::from(self.grid_h) * 3
    }
}

/// Streams quantized, deflated frames into a new `.pulseclip` file.
///
/// The on-disk layout puts the seek table *before* the frame data, but the
/// table's size depends on `frame_count`, which isn't known until every
/// frame has been pushed. Writing frames straight to their final on-disk
/// position is therefore impossible in one pass without either knowing the
/// frame count up front or shifting already-written bytes later. Instead,
/// `push_frame` compresses each frame immediately (never holding more than
/// one frame's raw pixels at a time) and appends the resulting bytes to an
/// in-memory buffer; `finish()` then writes the real header, seek table,
/// and buffered frame data in a single sequential pass.
///
/// Nothing is ever written to `path` itself until that final pass succeeds:
/// the writer owns a `.tmp` sibling of its own — one no other writer aimed
/// at the same clip can be handed, see [`temp_sibling`] — and a writer
/// dropped without `finish()` takes that file, and only that file, with it.
pub struct ClipWriter {
    /// `None` once `finish()` has taken the handle — also the marker that
    /// the temp file is no longer this writer's to delete.
    file: Option<File>,
    /// Where the finished clip is committed.
    path: PathBuf,
    /// Where bytes actually land until `finish()` renames it onto `path`.
    temp: PathBuf,
    grid_w: u16,
    grid_h: u16,
    capture_fps: f32,
    offsets: Vec<u64>,
    frames: Vec<u8>,
}

impl ClipWriter {
    /// Opens a scratch `.tmp` sibling of `path` for writing, one belonging
    /// to this writer alone ([`temp_sibling`]); `path` itself is not
    /// touched until `finish()`. The header is written lazily by `finish()`,
    /// once the real frame count is known.
    pub fn create(path: &Path, grid_w: u16, grid_h: u16, capture_fps: f32) -> Result<Self> {
        let temp = temp_sibling(path);
        let file = File::create(&temp)
            .with_context(|| format!("creating pulseclip file at {}", temp.display()))?;
        Ok(Self {
            file: Some(file),
            path: path.to_path_buf(),
            temp,
            grid_w,
            grid_h,
            capture_fps,
            offsets: Vec::new(),
            frames: Vec::new(),
        })
    }

    /// The scratch file this writer owns until `finish()` commits it — its
    /// own, never one it shares with another writer aimed at the same clip
    /// (see [`temp_sibling`]). Exposed so a caller cleaning up after an
    /// interrupted conversion, and the tests that pin that behaviour, name
    /// the file this writer is actually holding rather than guessing at it.
    pub fn temp_path(&self) -> &Path {
        &self.temp
    }

    /// Quantizes, compresses, and appends one frame. `rgb.len()` must equal
    /// `grid_w * grid_h * 3`.
    pub fn push_frame(&mut self, rgb: &[u8]) -> Result<()> {
        let expected = usize::from(self.grid_w) * usize::from(self.grid_h) * 3;
        if rgb.len() != expected {
            bail!(
                "push_frame: expected {expected} bytes ({}x{}x3), got {}",
                self.grid_w,
                self.grid_h,
                rgb.len()
            );
        }
        let indices = quantize(rgb);
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&indices)?;
        let compressed = encoder.finish().context("deflating pulseclip frame")?;

        // Offset relative to the start of the frames section; `finish()`
        // adds the (then-known) frames section's absolute start position.
        self.offsets.push(self.frames.len() as u64);

        let len = u32::try_from(compressed.len())
            .context("pulseclip frame exceeds u32 compressed length")?;
        self.frames.extend_from_slice(&len.to_le_bytes());
        self.frames.extend_from_slice(&compressed);
        Ok(())
    }

    /// Writes the real header, seek table, and buffered frame data in one
    /// sequential pass now that the frame count is known, then commits the
    /// temp file onto the final path.
    pub fn finish(mut self) -> Result<()> {
        let handle = self
            .file
            .take()
            .context("pulseclip writer has already been finished")?;
        let frame_count = u32::try_from(self.offsets.len())
            .context("pulseclip has too many frames for u32 frame_count")?;

        let mut file = BufWriter::new(handle);
        file.write_all(MAGIC)?;
        file.write_all(&self.grid_w.to_le_bytes())?;
        file.write_all(&self.grid_h.to_le_bytes())?;
        file.write_all(&self.capture_fps.to_le_bytes())?;
        file.write_all(&frame_count.to_le_bytes())?;
        file.write_all(&frame_count.to_le_bytes())?; // seek_table_len == frame_count

        let frames_start = HEADER_LEN + 4 + u64::from(frame_count) * 8;
        for relative_offset in &self.offsets {
            file.write_all(&(frames_start + relative_offset).to_le_bytes())?;
        }
        file.write_all(&self.frames)?;

        file.flush().context("flushing pulseclip file")?;
        // The handle has to be closed before the file can be moved.
        drop(file);
        crate::prefs::atomic_replace(&self.temp, &self.path)
    }
}

impl Drop for ClipWriter {
    /// A writer that never reached `finish()` — the conversion failed, or
    /// the process died mid-stream — leaves nothing behind but certainly
    /// nothing at the final path, which a later run would trust.
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

/// The scratch path a clip is streamed into: `clip.<worker>.pulseclip.tmp`
/// beside `clip.pulseclip`, mirroring the `.json.tmp` the prefs store uses —
/// with one addition the prefs store does not need.
///
/// `<worker>` is unique to this writer, because two writers really can be
/// aimed at one final path: a conversion that was superseded and the one
/// that replaced it derive the same cache filename from the same source and
/// ceiling. A shared scratch file there is a live hazard rather than a
/// theoretical one — Rust opens files with `FILE_SHARE_DELETE`, so the
/// abandoned writer's cleanup *succeeds* in unlinking the file the successor
/// still has open, the successor writes on into a handle with no directory
/// entry none the wiser, and the damage only surfaces at its `finish()`,
/// whose rename cannot find the path it is renaming. The conversion that
/// fails is the one somebody is waiting for.
///
/// The tag goes *inside* the name so it still ends `.pulseclip.tmp`: that
/// ending is how `clipconvert`'s cache sweep recognizes a scratch file left
/// by a worker that died with its process, and a leftover the sweep could
/// not see would sit in the cache directory forever.
fn temp_sibling(path: &Path) -> PathBuf {
    /// Distinguishes writers within one process; the process id
    /// distinguishes them across two PC Pulse windows converting at once.
    static NEXT_WRITER: AtomicU64 = AtomicU64::new(0);
    let tag = format!(
        "{:x}-{:x}",
        std::process::id(),
        NEXT_WRITER.fetch_add(1, Ordering::Relaxed)
    );
    let mut name = path.file_stem().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(tag);
    if let Some(extension) = path.extension() {
        name.push(".");
        name.push(extension);
    }
    name.push(".tmp");
    path.with_file_name(name)
}

/// Random-access reader for a `.pulseclip` file, backed by its seek table.
pub struct ClipReader {
    file: BufReader<File>,
    header: ClipHeader,
    offsets: Vec<u64>,
    decode_buf: Vec<u8>,
    frame_buf: Vec<u8>,
    /// Total on-disk file size, captured at `open()` time. Used to reject
    /// length fields read from the file (seek_table_len, compressed_len)
    /// that claim more data than the file could possibly contain, before
    /// they're used to size an allocation — an untrusted u32/u64 length
    /// fed straight into `Vec::with_capacity`/`vec![0; n]` can demand
    /// gigabytes and abort the process, which is worse than the panic this
    /// codec is meant to avoid.
    file_len: u64,
}

impl ClipReader {
    /// Opens `path`, validating the magic, header, and seek table. Any
    /// malformed or truncated input is rejected here rather than surfacing
    /// as an out-of-bounds read later.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("opening pulseclip file at {}", path.display()))?;
        let file_len = file
            .metadata()
            .with_context(|| format!("reading pulseclip file metadata at {}", path.display()))?
            .len();
        let mut file = BufReader::new(file);

        let mut magic = [0u8; 6];
        file.read_exact(&mut magic)
            .context("reading pulseclip magic")?;
        if &magic != MAGIC {
            bail!("not a pulseclip file: bad magic {magic:?}");
        }

        let grid_w = read_u16(&mut file).context("reading grid_w")?;
        let grid_h = read_u16(&mut file).context("reading grid_h")?;
        let capture_fps = read_f32(&mut file).context("reading capture_fps")?;
        let frame_count = read_u32(&mut file).context("reading frame_count")?;
        let seek_table_len = read_u32(&mut file).context("reading seek_table_len")?;

        if seek_table_len != frame_count {
            bail!("pulseclip seek_table_len ({seek_table_len}) != frame_count ({frame_count})");
        }
        if grid_w == 0 || grid_h == 0 {
            bail!("pulseclip grid dimensions must be non-zero, got {grid_w}x{grid_h}");
        }

        // The seek table is `seek_table_len` u64 entries (8 bytes each),
        // starting right after this point (HEADER_LEN + 4 bytes in). Reject
        // a claimed table larger than the file could possibly hold before
        // sizing an allocation from it: `seek_table_len` is an untrusted
        // u32 read straight off disk, and a corrupt file can claim close to
        // u32::MAX entries (~34GB) to force an allocator abort.
        let table_bytes = u64::from(seek_table_len) * 8;
        let remaining_after_header = file_len.saturating_sub(HEADER_LEN + 4);
        if table_bytes > remaining_after_header {
            bail!(
                "pulseclip seek table claims {seek_table_len} entries ({table_bytes} bytes), \
                 but only {remaining_after_header} bytes remain in the file"
            );
        }

        let mut offsets = Vec::with_capacity(seek_table_len as usize);
        for i in 0..seek_table_len {
            offsets.push(
                read_u64(&mut file).with_context(|| format!("reading seek table entry {i}"))?,
            );
        }

        let header = ClipHeader {
            grid_w,
            grid_h,
            capture_fps,
            frame_count,
        };
        let frame_len = header.frame_pixel_len();
        Ok(Self {
            file,
            header,
            offsets,
            decode_buf: Vec::new(),
            frame_buf: vec![0u8; frame_len],
            file_len,
        })
    }

    pub fn header(&self) -> &ClipHeader {
        &self.header
    }

    /// Decodes frame `index`, returning the cached RGB buffer. The buffer is
    /// reused across calls: the returned slice is only valid until the next
    /// call to `frame`.
    pub fn frame(&mut self, index: u32) -> Result<&[u8]> {
        let offset = *self
            .offsets
            .get(index as usize)
            .with_context(|| format!("pulseclip frame index {index} out of range"))?;
        self.file
            .seek(SeekFrom::Start(offset))
            .with_context(|| format!("seeking to pulseclip frame {index}"))?;

        let compressed_len = read_u32(&mut self.file)
            .with_context(|| format!("reading compressed_len for frame {index}"))?;
        // Reject a claimed compressed length larger than the file could
        // possibly hold before allocating: `compressed_len` is an
        // untrusted u32 read straight off disk, and a corrupt file can
        // claim up to u32::MAX bytes (~4GB) to force an allocator abort.
        let remaining = self.file_len.saturating_sub(offset.saturating_add(4));
        if u64::from(compressed_len) > remaining {
            bail!(
                "pulseclip frame {index}: compressed_len {compressed_len} exceeds {remaining} \
                 remaining bytes in the file"
            );
        }
        let mut compressed = vec![0u8; compressed_len as usize];
        self.file
            .read_exact(&mut compressed)
            .with_context(|| format!("reading compressed data for frame {index}"))?;

        let expected_indices = usize::from(self.header.grid_w) * usize::from(self.header.grid_h);
        self.decode_buf.clear();
        let mut decoder = DeflateDecoder::new(&compressed[..]);
        decoder
            .read_to_end(&mut self.decode_buf)
            .with_context(|| format!("inflating pulseclip frame {index}"))?;
        if self.decode_buf.len() != expected_indices {
            bail!(
                "pulseclip frame {index}: expected {expected_indices} quantized indices, got {}",
                self.decode_buf.len()
            );
        }

        dequantize(&self.decode_buf, &mut self.frame_buf);
        Ok(&self.frame_buf[..])
    }
}

fn read_u16<R: Read>(r: &mut R) -> Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_f32<R: Read>(r: &mut R) -> Result<f32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(f32::from_le_bytes(buf))
}

/// Mutes `rgb` in place by pulling each channel 35% of the way toward the
/// pixel's Rec. 709 luminance, desaturating it so text stays legible when
/// drawn over a playing video background.
pub fn mute(rgb: &mut [u8]) {
    for chunk in rgb.chunks_exact_mut(3) {
        let r = f32::from(chunk[0]);
        let g = f32::from(chunk[1]);
        let b = f32::from(chunk[2]);
        let luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b;
        chunk[0] = (luminance + (r - luminance) * 0.35).round() as u8;
        chunk[1] = (luminance + (g - luminance) * 0.35).round() as u8;
        chunk[2] = (luminance + (b - luminance) * 0.35).round() as u8;
    }
}

/// Quantizes an RGB buffer to a 6x7x6 color cube, one index byte per pixel.
pub fn quantize(rgb: &[u8]) -> Vec<u8> {
    rgb.chunks_exact(3)
        .map(|px| {
            let r = u32::from(px[0]) * 6 / 256;
            let g = u32::from(px[1]) * 7 / 256;
            let b = u32::from(px[2]) * 6 / 256;
            (r * 42 + g * 6 + b) as u8
        })
        .collect()
}

/// Expands quantized color-cube indices back to RGB, writing each level's
/// bucket center into `out`.
pub fn dequantize(indices: &[u8], out: &mut [u8]) {
    debug_assert_eq!(out.len(), indices.len() * 3);
    for (index, px) in indices.iter().zip(out.chunks_exact_mut(3)) {
        let index = u32::from(*index);
        let r = index / 42;
        let g = (index / 6) % 7;
        let b = index % 6;
        px[0] = bucket_center(r, 6);
        px[1] = bucket_center(g, 7);
        px[2] = bucket_center(b, 6);
    }
}

/// Maps color-cube level `level` (of `levels` total) back to the center of
/// its source byte range, matching the `x * levels / 256` bucketing used by
/// `quantize`.
fn bucket_center(level: u32, levels: u32) -> u8 {
    let bucket_size = 256 / levels;
    let start = level * bucket_size;
    let end = if level + 1 == levels {
        256
    } else {
        start + bucket_size
    };
    (start + (end - start) / 2).min(255) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_writer_dropped_without_finish_leaves_no_file_at_the_final_path() {
        let dir = std::env::temp_dir().join("pulseclip-interrupted");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clip.pulseclip");
        let _ = std::fs::remove_file(&path);

        let mut writer = ClipWriter::create(&path, 4, 2, 24.0).unwrap();
        writer.push_frame(&synthetic_frame(4, 2, 1)).unwrap();
        assert!(
            !path.exists(),
            "the final path must stay empty until finish()"
        );

        // The TUI quitting mid-conversion, a crash, a failed ffmpeg run: the
        // writer goes away without finishing. What it must not do is leave a
        // truncated clip at the cache path for the next launch to trust.
        let scratch = writer.temp_path().to_path_buf();
        drop(writer);
        assert!(
            !path.exists(),
            "an interrupted conversion poisoned the cache"
        );
        assert!(!scratch.exists(), "the scratch file was left behind");

        // The same path still converts cleanly afterwards.
        let mut writer = ClipWriter::create(&path, 4, 2, 24.0).unwrap();
        writer.push_frame(&synthetic_frame(4, 2, 1)).unwrap();
        writer.finish().unwrap();
        assert_eq!(ClipReader::open(&path).unwrap().header().frame_count, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn two_writers_aimed_at_one_clip_never_share_a_scratch_file() {
        // Two conversions can be aimed at one cache path: a superseded
        // worker and the one that replaced it produce the same filename from
        // the same source and ceiling. If they shared a scratch file, the
        // loser's cleanup would unlink the winner's file out from under its
        // open handle — Windows opens with FILE_SHARE_DELETE, so the delete
        // succeeds, the successor writes on into an unlinked handle none the
        // wiser, and the failure only surfaces at `finish()`, whose rename
        // cannot find the path it is renaming. The conversion the person is
        // actually waiting for is the one that fails.
        let dir = std::env::temp_dir().join("pulseclip-two-writers");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clip.pulseclip");
        let _ = std::fs::remove_file(&path);

        let abandoned = ClipWriter::create(&path, 4, 2, 24.0).unwrap();
        let mut successor = ClipWriter::create(&path, 4, 2, 24.0).unwrap();
        assert_ne!(
            abandoned.temp_path(),
            successor.temp_path(),
            "two writers were handed the same scratch file"
        );
        let kept = successor.temp_path().to_path_buf();

        // The cancelled worker cleaning up after itself.
        drop(abandoned);

        assert!(kept.exists(), "the survivor's scratch file was unlinked");
        successor.push_frame(&synthetic_frame(4, 2, 1)).unwrap();
        successor.finish().unwrap();
        assert_eq!(ClipReader::open(&path).unwrap().header().frame_count, 1);
        // Whatever the tag, the name still ends the way the cache sweep
        // recognizes its own leftovers by.
        assert!(
            kept.to_string_lossy().ends_with(".pulseclip.tmp"),
            "{}",
            kept.display()
        );
        let _ = std::fs::remove_file(&path);
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
        let expected: Vec<Vec<u8>> = (0..5)
            .map(|i| sequential.frame(i).unwrap().to_vec())
            .collect();
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
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"PCLIP1\x08\x00")
            .unwrap();
        assert!(ClipReader::open(&path).is_err());
    }

    #[test]
    fn forged_seek_table_len_is_rejected_without_aborting() {
        let dir = std::env::temp_dir().join("pulseclip-forged-table");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.pulseclip");

        // A header claiming ~4 billion seek table entries (~34GB) in a file
        // that's only 22 bytes long. Vec::with_capacity on the raw claimed
        // length would abort the process; open() must reject it instead.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PCLIP1");
        bytes.extend_from_slice(&1u16.to_le_bytes()); // grid_w
        bytes.extend_from_slice(&1u16.to_le_bytes()); // grid_h
        bytes.extend_from_slice(&1.0f32.to_le_bytes()); // capture_fps
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // frame_count
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // seek_table_len
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();

        let err = match ClipReader::open(&path) {
            Ok(_) => panic!("forged seek_table_len should have been rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("seek table"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn forged_compressed_len_is_rejected_without_aborting() {
        let dir = std::env::temp_dir().join("pulseclip-forged-frame");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.pulseclip");

        // A structurally valid 1-frame file whose seek table is honest, but
        // whose frame declares a compressed_len of ~4GB with no compressed
        // bytes actually following it. vec![0u8; compressed_len] on the raw
        // claimed length would abort the process; frame() must reject it.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PCLIP1");
        bytes.extend_from_slice(&1u16.to_le_bytes()); // grid_w
        bytes.extend_from_slice(&1u16.to_le_bytes()); // grid_h
        bytes.extend_from_slice(&1.0f32.to_le_bytes()); // capture_fps
        bytes.extend_from_slice(&1u32.to_le_bytes()); // frame_count
        bytes.extend_from_slice(&1u32.to_le_bytes()); // seek_table_len
        let frame_offset = bytes.len() as u64 + 8; // right after the 1-entry table
        bytes.extend_from_slice(&frame_offset.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // forged compressed_len
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();

        let mut reader = ClipReader::open(&path).unwrap();
        let err = reader.frame(0).unwrap_err();
        assert!(
            err.to_string().contains("compressed_len"),
            "unexpected error: {err}"
        );
    }
}
