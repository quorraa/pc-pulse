//! Video background player.
//!
//! `.pulseclip` files are decoded on demand rather than pre-expanded into
//! memory: `Background` wraps a `pulseclip::ClipReader` and derives which
//! frame is "current" purely from wall-clock time, using the clip's capture
//! fps. This keeps looping and scrubbing trivial (it's a modulo) and means
//! lowering the playback fps below the capture fps skips frames instead of
//! requiring any re-encoding — the displayed index is always
//! `elapsed_secs * capture_fps`, never a running counter that could drift
//! from real time.
//!
//! Playback fps is a *tick rate*, not the source of the displayed frame: it
//! only decides how often `advance_if_due` bothers checking whether the
//! wall-clock-derived index has moved on. That separation is what lets
//! `downshift` cheaply relieve render pressure (check less often) without
//! touching which frame is actually shown at a given instant.

use crate::pulseclip::ClipReader;
use anyhow::Result;
use std::path::Path;
use std::time::{Duration, Instant};

/// Plays a `.pulseclip` file back by deriving the current frame from wall
/// time rather than advancing a running counter, so looping is a modulo and
/// skipped frames never need re-encoding.
pub struct Background {
    reader: ClipReader,
    capture_fps: f32,
    frame_count: u32,
    /// When playback began; the frame index is always computed relative to
    /// this instant, never accumulated tick-by-tick.
    started: Instant,
    /// The time of the last fired tick. `next_deadline` is always derived
    /// from this plus the current interval, so changing `effective_fps`
    /// reschedules the next check without disturbing `started`.
    last_tick: Instant,
    effective_fps: u32,
    /// True when `effective_fps` was lowered by `downshift` rather than an
    /// explicit `set_playback_fps` call — drives the TUNE row's
    /// `60 -> 30 (auto)` display.
    downshifted: bool,
    /// Index of the frame that should currently be on screen, per wall time.
    current_index: u32,
    /// The last successfully decoded frame's RGB pixels, reused across
    /// calls so a transient decode error can fall back to it.
    pixels: Vec<u8>,
    failed: Option<String>,
}

impl Background {
    /// Opens `path` and starts the wall clock. Playback fps defaults to the
    /// clip's capture fps (clamped to the same `1..=60` range accepted by
    /// `set_playback_fps`).
    pub fn load(path: &Path) -> Result<Self> {
        let mut reader = ClipReader::open(path)?;
        let header = *reader.header();
        let capture_fps = header.capture_fps;
        let frame_count = header.frame_count;
        let effective_fps = clamp_fps(capture_fps.round() as i64);

        // Decode frame 0 up front so `current_pixels` always has something
        // valid to return, even before the first `advance_if_due` call.
        let pixels = reader.frame(0)?.to_vec();

        let now = Instant::now();
        Ok(Self {
            reader,
            capture_fps,
            frame_count,
            started: now,
            last_tick: now,
            effective_fps,
            downshifted: false,
            current_index: 0,
            pixels,
            failed: None,
        })
    }

    /// Returns the internal start instant for deterministic tests.
    #[cfg(test)]
    pub fn started_for_test(&self) -> Instant {
        self.started
    }

    /// Sets the playback tick rate, clamped to `1..=60`. This is an explicit
    /// user choice, so it clears any auto-downshift the caller applied
    /// earlier.
    pub fn set_playback_fps(&mut self, fps: u32) {
        self.effective_fps = clamp_fps(i64::from(fps));
        self.downshifted = false;
    }

    /// The current playback tick rate — either the capture fps, an explicit
    /// user choice, or an auto-downshifted value.
    pub fn effective_fps(&self) -> u32 {
        self.effective_fps
    }

    /// True when `effective_fps` was lowered automatically by `downshift`
    /// and hasn't since been overridden by `set_playback_fps`.
    pub fn is_downshifted(&self) -> bool {
        self.downshifted
    }

    /// Halves the playback tick rate, flooring at 2fps. Returns `false`
    /// when already at the floor, so the caller can fall through to
    /// dropping a UI tier instead.
    pub fn downshift(&mut self) -> bool {
        let halved = (self.effective_fps / 2).max(2);
        if halved == self.effective_fps {
            return false;
        }
        self.effective_fps = halved;
        self.downshifted = true;
        true
    }

    /// The instant of the next scheduled playback tick.
    pub fn next_deadline(&self) -> Instant {
        self.last_tick + self.tick_interval()
    }

    /// The grid dimensions of the underlying clip.
    pub fn grid(&self) -> (u16, u16) {
        let header = self.reader.header();
        (header.grid_w, header.grid_h)
    }

    /// If a new tick is due at `now`, recomputes which frame wall time says
    /// should be current. Returns `true` only when that index actually
    /// changed — the signal callers use to mark the UI dirty.
    pub fn advance_if_due(&mut self, now: Instant) -> bool {
        if now < self.next_deadline() {
            return false;
        }

        // Catch the tick schedule up to `now` rather than leaving
        // `last_tick` stuck in the past, which would make every future call
        // immediately "due" regardless of the configured fps.
        let interval = self.tick_interval();
        while self.last_tick + interval <= now {
            self.last_tick += interval;
        }

        let index = self.index_for(now);
        if index == self.current_index {
            return false;
        }
        self.current_index = index;
        true
    }

    /// RGB pixels of the frame due at the last `advance_if_due` call. Never
    /// panics: a read/inflate error leaves the previously decoded frame in
    /// place and records the failure in `failed()`.
    pub fn current_pixels(&mut self) -> &[u8] {
        match self.reader.frame(self.current_index) {
            Ok(frame) => {
                self.pixels.clear();
                self.pixels.extend_from_slice(frame);
                self.failed = None;
            }
            Err(err) => {
                self.failed = Some(err.to_string());
            }
        }
        &self.pixels
    }

    /// The most recent decode failure, if any, so the caller can disable
    /// playback with a single status message.
    pub fn failed(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_secs_f64(1.0 / f64::from(self.effective_fps))
    }

    /// The frame index wall time says should be current: elapsed time since
    /// `started`, scaled by the clip's *capture* fps (not the playback tick
    /// rate) and wrapped by `frame_count`, exactly as specced.
    fn index_for(&self, now: Instant) -> u32 {
        let elapsed = now.saturating_duration_since(self.started).as_secs_f64();
        let raw = (elapsed * f64::from(self.capture_fps)) as u64;
        (raw % u64::from(self.frame_count)) as u32
    }
}

/// Clamps a playback fps request to the `1..=60` range shared by
/// `set_playback_fps` and `load`'s default.
fn clamp_fps(fps: i64) -> u32 {
    fps.clamp(1, 60) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The `.pulseclip` color cube only gives the R channel 6 distinguishable
    /// levels across `0..256` (roughly 43 raw values per bucket — see
    /// `pulseclip::quantize`). Filling a frame with its own small index
    /// (`0, 1, 2, ...`) would land every frame used here in bucket 0 and make
    /// them indistinguishable after the round trip, defeating the point of
    /// asserting on decoded pixel content. Spacing markers by 50 keeps the
    /// handful of frames these tests inspect in distinct buckets.
    fn marker_for(frame: u32) -> u8 {
        ((frame * 50) % 256) as u8
    }

    /// What `marker_for(frame)` decodes back to after a real
    /// quantize/dequantize round trip, computed through the actual codec
    /// rather than hand-derived, so the assertions track the real bucketing
    /// instead of an assumption about it.
    fn expected_marker(frame: u32) -> u8 {
        let raw = marker_for(frame);
        let indices = crate::pulseclip::quantize(&[raw, raw, raw]);
        let mut out = [0u8; 3];
        crate::pulseclip::dequantize(&indices, &mut out);
        out[0]
    }

    fn test_clip(frames: u32, fps: f32) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("background-player");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("clip-{frames}-{fps}.pulseclip"));
        let mut w = crate::pulseclip::ClipWriter::create(&path, 4, 2, fps).unwrap();
        for s in 0..frames {
            w.push_frame(&[marker_for(s); 4 * 2 * 3]).unwrap();
        }
        w.finish().unwrap();
        path
    }

    #[test]
    fn frame_index_follows_wall_time_and_loops() {
        let mut bg = Background::load(&test_clip(10, 10.0)).unwrap();
        let t0 = bg.started_for_test();
        bg.advance_if_due(t0 + Duration::from_millis(250));
        assert_eq!(bg.current_pixels()[0], expected_marker(2)); // 0.25s * 10fps = frame 2
        bg.advance_if_due(t0 + Duration::from_millis(1_150));
        assert_eq!(bg.current_pixels()[0], expected_marker(1)); // 11.5 frames % 10 = frame 1 — looped
    }

    #[test]
    fn playback_fps_below_capture_skips_frames_without_reconversion() {
        let mut bg = Background::load(&test_clip(30, 30.0)).unwrap();
        bg.set_playback_fps(10);
        let t0 = bg.started_for_test();
        let d1 = bg.next_deadline();
        assert!(d1 - t0 >= Duration::from_millis(99) && d1 - t0 <= Duration::from_millis(101));
        bg.advance_if_due(t0 + Duration::from_millis(100));
        assert_eq!(bg.current_pixels()[0], expected_marker(3)); // wall time drives index: frame 3, not 1
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
}
