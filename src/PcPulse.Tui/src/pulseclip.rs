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

use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

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
pub struct ClipWriter {
    file: File,
    grid_w: u16,
    grid_h: u16,
    capture_fps: f32,
    offsets: Vec<u64>,
    frames: Vec<u8>,
}

impl ClipWriter {
    /// Creates `path` for writing. The header is written lazily by
    /// `finish()`, once the real frame count is known.
    pub fn create(path: &Path, grid_w: u16, grid_h: u16, capture_fps: f32) -> Result<Self> {
        let file = File::create(path)
            .with_context(|| format!("creating pulseclip file at {}", path.display()))?;
        Ok(Self {
            file,
            grid_w,
            grid_h,
            capture_fps,
            offsets: Vec::new(),
            frames: Vec::new(),
        })
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
    /// sequential pass now that the frame count is known.
    pub fn finish(self) -> Result<()> {
        let frame_count = u32::try_from(self.offsets.len())
            .context("pulseclip has too many frames for u32 frame_count")?;

        let mut file = BufWriter::new(self.file);
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
        Ok(())
    }
}

/// Random-access reader for a `.pulseclip` file, backed by its seek table.
pub struct ClipReader {
    file: BufReader<File>,
    header: ClipHeader,
    offsets: Vec<u64>,
    decode_buf: Vec<u8>,
    frame_buf: Vec<u8>,
}

impl ClipReader {
    /// Opens `path`, validating the magic, header, and seek table. Any
    /// malformed or truncated input is rejected here rather than surfacing
    /// as an out-of-bounds read later.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("opening pulseclip file at {}", path.display()))?;
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
}
