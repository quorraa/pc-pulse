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
//! Exactly one decoded frame is held at a time, and it is memoized on its
//! index: `current_pixels` is called once per *draw*, which is 60 times a
//! second in smooth mode, while the clip may only tick at 10-30fps. Without
//! the memo the same frame was inflated from disk over and over — a clip
//! converted from a 1080p source is 825x464, so that is a 1.1 MB inflate,
//! about 3 ms, each time.
//!
//! Frame *dimensions* come from the clip's own header, never from a constant:
//! clips are converted at a size derived from their source (see
//! `clipconvert::capture_dims`), so two clips loaded by the same build can
//! have different grids.
//!
//! Playback fps is a *tick rate*, not the source of the displayed frame: it
//! only decides how often `advance_if_due` bothers checking whether the
//! wall-clock-derived index has moved on. That separation is what lets
//! `downshift` cheaply relieve render pressure (check less often) without
//! touching which frame is actually shown at a given instant.

use crate::pulseclip::ClipReader;
use anyhow::Result;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Hands every loaded player a number no other player in this process will
/// ever wear. Swapping the configured video replaces the whole `Background`,
/// so this is all a downstream cache needs to tell one clip's frame 7 from
/// another's — no bookkeeping at the assignment sites, which are scattered
/// across settings handling, conversion completion, and startup restore.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Plays a `.pulseclip` file back by deriving the current frame from wall
/// time rather than advancing a running counter, so looping is a modulo and
/// skipped frames never need re-encoding.
pub struct Background {
    reader: ClipReader,
    /// This player's process-unique id — see `NEXT_GENERATION`.
    generation: u64,
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
    /// Which frame `pixels` holds, or `None` when nothing has decoded
    /// cleanly yet. `current_pixels` is called once per *draw* — 60 times a
    /// second in smooth mode — while the clip itself ticks at its own fps,
    /// so without this the same frame was inflated from disk dozens of
    /// times over. Decoding now happens only when the index has moved on.
    cached_index: Option<u32>,
    /// Counts real decodes, for the test that proves the cache is hit.
    #[cfg(test)]
    decodes: u32,
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
            generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
            capture_fps,
            frame_count,
            started: now,
            last_tick: now,
            effective_fps,
            downshifted: false,
            current_index: 0,
            pixels,
            cached_index: Some(0),
            #[cfg(test)]
            decodes: 1,
            failed: None,
        })
    }

    /// How many frames have actually been inflated from disk, so a test can
    /// prove a repeated `current_pixels` call served the cache.
    #[cfg(test)]
    pub fn decodes_for_test(&self) -> u32 {
        self.decodes
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

    /// The grid dimensions of the underlying clip, as recorded in its
    /// header. Clips are converted at a size derived from their *source*, so
    /// this is the only authority on how wide a frame is — nothing may assume
    /// a fixed capture grid.
    pub fn grid(&self) -> (u16, u16) {
        let header = self.reader.header();
        (header.grid_w, header.grid_h)
    }

    /// This player's process-unique id. Two clips can easily share a frame
    /// index and a grid; a cache keyed on what is on screen needs this to
    /// tell them apart.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The index wall time says is current — the frame `current_pixels`
    /// will try to serve. It is what actually comes back on every call but
    /// one: a decode that fails serves the previously decoded frame instead
    /// and reports the failure through `failed()`, leaving this index
    /// pointing at the frame that could not be read.
    pub fn current_index(&self) -> u32 {
        self.current_index
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
    ///
    /// The decode is memoized on the frame index. A caller drawing at 60fps
    /// over a 30fps clip therefore inflates each frame once and reads the
    /// cache for the second draw, instead of paying the same decode twice.
    /// A failed decode deliberately does *not* update the cache key, so the
    /// next call retries and `failed()` keeps reporting the live truth
    /// rather than latching on one bad read.
    ///
    /// A cache hit clears `failed` for the same reason it is set on a bad
    /// read: it is a report of what this call served, not a tombstone. The
    /// cached frame did decode cleanly, so returning it while still claiming
    /// a failure would be a lie — one a looping clip can actually tell, by
    /// failing on a late frame and then wrapping back to a cached early one.
    pub fn current_pixels(&mut self) -> &[u8] {
        if self.cached_index == Some(self.current_index) {
            self.failed = None;
            return &self.pixels;
        }
        #[cfg(test)]
        {
            self.decodes += 1;
        }
        match self.reader.frame(self.current_index) {
            Ok(frame) => {
                self.pixels.clear();
                self.pixels.extend_from_slice(frame);
                self.cached_index = Some(self.current_index);
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

    /// A clip file of its own for every call.
    ///
    /// Naming the file after its arguments alone was a race: two tests
    /// asking for the same shape wrote the same `.pulseclip.tmp`
    /// concurrently, and whichever committed second found its temp file
    /// already moved away — an intermittent "cannot find the file
    /// specified" that had nothing to do with what either test was checking.
    fn test_clip(frames: u32, fps: f32) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NONCE: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join("background-player");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!(
            "clip-{frames}-{fps}-{}-{}.pulseclip",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
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
    fn a_second_call_at_the_same_index_serves_the_cache_instead_of_decoding() {
        // `current_pixels` is called once per draw — 60 times a second in
        // smooth mode — while the clip ticks at its own, lower rate. Every
        // call used to re-inflate the same frame from disk.
        let mut bg = Background::load(&test_clip(10, 10.0)).unwrap();
        let t0 = bg.started_for_test();
        assert!(bg.advance_if_due(t0 + Duration::from_millis(250)));

        let first = bg.current_pixels().to_vec();
        let after_first = bg.decodes_for_test();
        let second = bg.current_pixels().to_vec();

        assert_eq!(
            bg.decodes_for_test(),
            after_first,
            "the frame index had not moved, so nothing should have decoded"
        );
        assert_eq!(first, second, "the cached frame must be the same frame");

        // ...and the cache must not outlive the index it was keyed on.
        assert!(bg.advance_if_due(t0 + Duration::from_millis(350)));
        assert_eq!(bg.current_pixels()[0], expected_marker(3));
        assert_eq!(
            bg.decodes_for_test(),
            after_first + 1,
            "an advanced index must decode again"
        );
    }

    #[test]
    fn a_failed_decode_keeps_the_last_frame_and_is_retried_every_call() {
        use std::io::Write;
        let path = test_clip(8, 8.0);
        let mut bg = Background::load(&path).unwrap();
        let last_good = bg.current_pixels().to_vec();
        assert!(bg.failed().is_none());

        // Zero the clip on disk underneath the open reader, so the next
        // real decode fails. Memoizing must not swallow that.
        let len = std::fs::metadata(&path).unwrap().len() as usize;
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .write_all(&vec![0u8; len])
            .unwrap();

        let t0 = bg.started_for_test();
        assert!(bg.advance_if_due(t0 + Duration::from_millis(250))); // frame 2
        assert_eq!(
            bg.current_pixels(),
            &last_good[..],
            "a failed decode must leave the previous frame on screen"
        );
        assert!(bg.failed().is_some(), "the failure must be reported");

        let after_failure = bg.decodes_for_test();
        let _ = bg.current_pixels();
        assert!(
            bg.failed().is_some(),
            "the cache must not paper over a still-failing frame"
        );
        assert_eq!(
            bg.decodes_for_test(),
            after_failure + 1,
            "a frame that failed to decode must be retried, not cached"
        );
    }

    #[test]
    fn wrapping_back_onto_a_good_cached_frame_clears_the_stale_failure() {
        use std::io::Write;
        // `failed()` is a report of what the last call served, not a
        // tombstone. A looping clip really can fail on a late frame and then
        // wrap onto an early one that is still cached and still good; saying
        // "failed" while handing back that good frame is a lie.
        //
        // 16 frames at 8 fps, so this gets its own file: the test scribbles
        // over the clip, and so does the retry test above.
        let path = test_clip(16, 8.0);
        let mut bg = Background::load(&path).unwrap();
        let frame_zero = bg.current_pixels().to_vec();
        let len = std::fs::metadata(&path).unwrap().len() as usize;
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .write_all(&vec![0u8; len])
            .unwrap();

        let t0 = bg.started_for_test();
        assert!(bg.advance_if_due(t0 + Duration::from_millis(250))); // frame 2
        let _ = bg.current_pixels();
        assert!(bg.failed().is_some(), "the bad decode must be reported");

        // One full loop later (16 frames at 8 fps = 2 s) the wall clock is
        // back on frame 0, which never left the cache.
        assert!(bg.advance_if_due(t0 + Duration::from_millis(2_000)));
        let served = bg.current_pixels().to_vec();
        assert_eq!(served, frame_zero, "the cached frame 0 must be served");
        assert!(
            bg.failed().is_none(),
            "a served cache hit is a success, not a still-failing player"
        );
    }

    #[test]
    fn every_loaded_player_gets_its_own_generation() {
        // A render-side cache keyed on the frame index would otherwise serve
        // one clip's frame 7 for another's after a swap.
        // Distinct clips: every `test_clip` call writes its own file, and
        // the first player holds its own open.
        let first = Background::load(&test_clip(5, 4.0)).unwrap();
        let second = Background::load(&test_clip(6, 4.0)).unwrap();
        assert_ne!(first.generation(), second.generation());
        assert_eq!(first.generation(), first.generation()); // stable per player
        assert_eq!(first.current_index(), 0);
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
