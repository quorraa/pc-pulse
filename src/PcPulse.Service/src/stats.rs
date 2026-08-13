//! Streaming statistics primitives shared by baselines, collector diagnostics,
//! and (eventually) the quality gate. Kept dependency-free and leaf-level so
//! any module can pull it in without creating cycles.

use serde::{Deserialize, Serialize};

/// One marker of a P² (Jain & Chlamtac) streaming quantile estimator. Five of
/// these track a single target quantile `p` in O(1) space and O(1) time per
/// observation, without retaining the underlying samples -- important here
/// because sketches are persisted in baseline payloads and re-serialized on
/// every save cadence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct P2Marker {
    /// Target quantile, e.g. 0.5 for the median.
    p: f64,
    /// Estimated marker heights (the current quantile estimates for the 5
    /// tracked cells: min, p/2, p, (1+p)/2, max).
    heights: [f64; 5],
    /// Actual marker positions (counts of observations at or below each
    /// marker).
    positions: [f64; 5],
    /// Desired (ideal, fractional) marker positions.
    desired: [f64; 5],
    /// Per-observation increments to the desired positions.
    increments: [f64; 5],
    /// Buffer for the first 5 observations, sorted once full to seed the
    /// markers. Cleared and unused after initialization.
    init: Vec<f64>,
    initialized: bool,
}

impl P2Marker {
    fn new(p: f64) -> Self {
        Self {
            p,
            heights: [0.0; 5],
            positions: [0.0; 5],
            desired: [0.0; 5],
            increments: [0.0, p / 2.0, p, (1.0 + p) / 2.0, 1.0],
            init: Vec::with_capacity(5),
            initialized: false,
        }
    }

    fn observe(&mut self, value: f64) {
        if !self.initialized {
            self.init.push(value);
            if self.init.len() == 5 {
                self.init.sort_by(|a, b| a.total_cmp(b));
                for (i, sample) in self.init.iter().enumerate() {
                    self.heights[i] = *sample;
                    self.positions[i] = (i + 1) as f64;
                }
                let p = self.p;
                self.desired = [1.0, 1.0 + 2.0 * p, 1.0 + 4.0 * p, 3.0 + 2.0 * p, 5.0];
                self.initialized = true;
                self.init.clear();
            }
            return;
        }

        let k = if value < self.heights[0] {
            self.heights[0] = value;
            0
        } else if value >= self.heights[4] {
            self.heights[4] = value;
            3
        } else {
            (0..4)
                .find(|&i| self.heights[i] <= value && value < self.heights[i + 1])
                .unwrap_or(3)
        };

        for position in self.positions.iter_mut().skip(k + 1) {
            *position += 1.0;
        }
        for (desired, increment) in self.desired.iter_mut().zip(self.increments.iter()) {
            *desired += increment;
        }

        for i in 1..4 {
            let d = self.desired[i] - self.positions[i];
            let right_gap = self.positions[i + 1] - self.positions[i];
            let left_gap = self.positions[i - 1] - self.positions[i];
            if (d >= 1.0 && right_gap > 1.0) || (d <= -1.0 && left_gap < -1.0) {
                let sign = if d >= 0.0 { 1.0 } else { -1.0 };
                let parabolic = self.parabolic(i, sign);
                self.heights[i] =
                    if self.heights[i - 1] < parabolic && parabolic < self.heights[i + 1] {
                        parabolic
                    } else {
                        self.linear(i, sign)
                    };
                self.positions[i] += sign;
            }
        }
    }

    fn parabolic(&self, i: usize, d: f64) -> f64 {
        let q = &self.heights;
        let n = &self.positions;
        q[i] + d / (n[i + 1] - n[i - 1])
            * ((n[i] - n[i - 1] + d) * (q[i + 1] - q[i]) / (n[i + 1] - n[i])
                + (n[i + 1] - n[i] - d) * (q[i] - q[i - 1]) / (n[i] - n[i - 1]))
    }

    fn linear(&self, i: usize, d: f64) -> f64 {
        let q = &self.heights;
        let n = &self.positions;
        let j = (i as f64 + d) as usize;
        q[i] + d * (q[j] - q[i]) / (n[j] - n[i])
    }

    fn quantile(&self) -> Option<f64> {
        self.initialized.then_some(self.heights[2])
    }
}

/// Streaming quantile estimator over an unbounded stream of `f64` samples,
/// tracking the median, p95, and p99 concurrently in constant space via three
/// independent P² marker sets. Safe to persist and restore across restarts.
///
/// **Non-stationarity caveat:** classic P² has no decay or windowing -- every
/// observation ever fed in has equal, permanent influence on the marker
/// positions. In practice this means the median-region marker adapts very
/// slowly to a regime shift (measured: p50 was still reporting ~175 after
/// 5,000 post-shift samples against a true new median of 500), while p95/p99
/// snap to a step change within a few dozen observations because their
/// desired positions sit near the tails where a single out-of-band sample
/// moves the marker a full slot. A caller that persists a `PercentileSketch`
/// across process lifetimes (as baselines do) should treat a long-lived
/// sketch's median as potentially stale after a legitimate behavior change,
/// and should not assume p50 and p95/p99 go stale at the same rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PercentileSketch {
    count: u64,
    p50: P2Marker,
    p95: P2Marker,
    p99: P2Marker,
}

impl PercentileSketch {
    pub fn new() -> Self {
        Self {
            count: 0,
            p50: P2Marker::new(0.5),
            p95: P2Marker::new(0.95),
            p99: P2Marker::new(0.99),
        }
    }

    pub fn observe(&mut self, value: f64) {
        self.count += 1;
        self.p50.observe(value);
        self.p95.observe(value);
        self.p99.observe(value);
    }

    /// Returns the estimated value at quantile `q`. Only the markers this
    /// sketch tracks (0.5, 0.95, 0.99) are supported; anything else, or fewer
    /// than 5 observations so far, yields `None`.
    pub fn quantile(&self, q: f64) -> Option<f64> {
        if self.count < 5 {
            return None;
        }
        const EPSILON: f64 = 1e-9;
        if (q - 0.5).abs() < EPSILON {
            self.p50.quantile()
        } else if (q - 0.95).abs() < EPSILON {
            self.p95.quantile()
        } else if (q - 0.99).abs() < EPSILON {
            self.p99.quantile()
        } else {
            None
        }
    }

    pub fn count(&self) -> u64 {
        self.count
    }
}

impl Default for PercentileSketch {
    fn default() -> Self {
        Self::new()
    }
}

/// A single timestamped sample fed into [`classify_trend`].
#[derive(Debug, Clone, Copy)]
pub struct TrendPoint {
    pub at_ms: i64,
    pub value: f64,
}

/// The shape of a time-ordered series once split into three equal-duration
/// segments and compared segment-to-segment.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrendShape {
    /// Each successive third's mean exceeds the prior by at least `min_step`.
    /// `total_growth` is the last third's mean minus the first third's.
    Monotonic { total_growth: f64 },
    /// Grew from the first third to the middle, then held roughly flat
    /// (within `min_step`) from the middle to the last third.
    Plateau,
    /// Grew, then declined enough (by at least `min_step`) to count as a
    /// release, and the last third's mean landed back close to the first
    /// third's -- within `max(min_step, RETURNING_TOLERANCE_FRACTION *
    /// (middle_mean - first_mean))`. This is a real recovery: safe to treat
    /// as closed/resolved.
    Returning,
    /// Grew, then declined enough to count as a release, but the last
    /// third's mean is still well above the first third's -- outside the
    /// `Returning` tolerance. `remaining` is `last_mean - first_mean`, i.e.
    /// how much of the excursion has *not* been given back (e.g. a process
    /// that grew by 1000 handles and released only 51 of them reports
    /// `remaining` near 949). Callers must treat this as still-open, not as
    /// a resolution -- a small release is not the same as recovery, and
    /// auto-resolve logic (see the alert-calibration reopen/hysteresis path)
    /// must not collapse this into `Returning`.
    PartialRelease { remaining: f64 },
    /// Too little data, or too short a time span, to say anything.
    Inconclusive,
}

/// How much of the growth from the first to the middle third must be given
/// back, as a fraction of that growth, before a decline counts as a full
/// `Returning` rather than a `PartialRelease`. The spec's own worked example
/// (grow ~9.3, decline to ~5.2 away from the first third's mean) needs a
/// fraction of at least ~0.554 to land in `Returning`; 0.25 does not clear
/// it. 0.6 was chosen as the smallest clean value with headroom above that
/// minimum.
const RETURNING_TOLERANCE_FRACTION: f64 = 0.6;

fn segment_mean(points: &[TrendPoint], from_exclusive: Option<i64>, to_inclusive: i64) -> f64 {
    let mut sum = 0.0;
    let mut count = 0usize;
    for point in points {
        let after_start = from_exclusive.is_none_or(|from| point.at_ms > from);
        if after_start && point.at_ms <= to_inclusive {
            sum += point.value;
            count += 1;
        }
    }
    if count == 0 { 0.0 } else { sum / count as f64 }
}

/// Generalization of the collector's original three-segment growth test:
/// split `points` into thirds by elapsed time, then classify the shape of
/// the series from how each third's mean compares to its predecessor.
pub fn classify_trend(points: &[TrendPoint], min_span_ms: i64, min_step: f64) -> TrendShape {
    if points.len() < 6 {
        return TrendShape::Inconclusive;
    }
    let first_ms = points.iter().map(|p| p.at_ms).min().unwrap_or(0);
    let last_ms = points.iter().map(|p| p.at_ms).max().unwrap_or(0);
    let span_ms = last_ms.saturating_sub(first_ms);
    if span_ms < min_span_ms {
        return TrendShape::Inconclusive;
    }

    let third = span_ms / 3;
    let first_end = first_ms + third;
    let middle_end = first_ms + 2 * third;

    let first_mean = segment_mean(points, None, first_end);
    let middle_mean = segment_mean(points, Some(first_end), middle_end);
    let last_mean = segment_mean(points, Some(middle_end), last_ms);

    let first_step = middle_mean - first_mean;
    let second_step = last_mean - middle_mean;

    if first_step >= min_step && second_step >= min_step {
        TrendShape::Monotonic {
            total_growth: last_mean - first_mean,
        }
    } else if first_step >= min_step && second_step.abs() <= min_step {
        TrendShape::Plateau
    } else if first_step >= min_step && second_step <= -min_step {
        // A release was substantial enough to clear `min_step`, but that
        // alone doesn't mean the excursion is over: releasing 5% of a 1000
        // unit spike is still `min_step`-sized while leaving ~950 units
        // stuck. Scale the "back to baseline" tolerance to the size of the
        // excursion itself so a big spike needs a proportionally big give-back.
        let total_excursion = first_step;
        let tolerance = min_step.max(RETURNING_TOLERANCE_FRACTION * total_excursion);
        let remaining = last_mean - first_mean;
        if remaining.abs() <= tolerance {
            TrendShape::Returning
        } else {
            TrendShape::PartialRelease { remaining }
        }
    } else {
        TrendShape::Inconclusive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series(values: &[f64]) -> Vec<TrendPoint> {
        values
            .iter()
            .enumerate()
            .map(|(i, v)| TrendPoint {
                at_ms: i as i64 * 60_000,
                value: *v,
            })
            .collect()
    }

    #[test]
    fn sketch_tracks_quantiles_of_a_known_distribution() {
        let mut sketch = PercentileSketch::new();
        for i in 1..=1000 {
            sketch.observe(f64::from(i));
        }
        let p50 = sketch.quantile(0.5).unwrap();
        let p95 = sketch.quantile(0.95).unwrap();
        let p99 = sketch.quantile(0.99).unwrap();
        assert!((p50 - 500.0).abs() < 25.0, "p50 = {p50}");
        assert!((p95 - 950.0).abs() < 25.0, "p95 = {p95}");
        assert!((p99 - 990.0).abs() < 25.0, "p99 = {p99}");
    }

    #[test]
    fn sketch_has_no_quantiles_before_five_observations() {
        let mut sketch = PercentileSketch::new();
        for i in 0..4 {
            sketch.observe(f64::from(i));
            assert!(sketch.quantile(0.95).is_none());
        }
        sketch.observe(4.0);
        assert!(sketch.quantile(0.95).is_some());
    }

    #[test]
    fn sketch_round_trips_through_serde() {
        let mut sketch = PercentileSketch::new();
        for i in 1..=100 {
            sketch.observe(f64::from(i));
        }
        let json = serde_json::to_string(&sketch).unwrap();
        let back: PercentileSketch = serde_json::from_str(&json).unwrap();
        assert_eq!(back.count(), 100);
        assert!((back.quantile(0.5).unwrap() - sketch.quantile(0.5).unwrap()).abs() < 1e-9);
    }

    #[test]
    fn monotonic_growth_is_classified_as_monotonic() {
        let shape = classify_trend(
            &series(&[10.0, 12.0, 15.0, 18.0, 22.0, 27.0, 33.0, 40.0, 48.0]),
            4 * 60_000,
            2.0,
        );
        assert!(matches!(shape, TrendShape::Monotonic { total_growth } if total_growth > 20.0));
    }

    #[test]
    fn burst_then_flat_is_a_plateau_full_release_is_returning_and_partial_release_stays_open() {
        let plateau = classify_trend(
            &series(&[10.0, 11.0, 30.0, 31.0, 30.5, 30.8, 31.0, 30.6, 30.9]),
            4 * 60_000,
            2.0,
        );
        assert!(matches!(plateau, TrendShape::Plateau));

        // Full release: grows ~9.3, then falls back to within tolerance of
        // where it started -- a genuine recovery.
        let returning = classify_trend(
            &series(&[10.0, 11.0, 30.0, 31.0, 28.0, 20.0, 14.0, 11.0, 10.5]),
            4 * 60_000,
            2.0,
        );
        assert!(matches!(returning, TrendShape::Returning));

        // Partial release: grows by 1000, then gives back only 51 of it
        // (5%). Still sitting ~949 above baseline -- must not read as a
        // resolved excursion.
        let partial_release = classify_trend(
            &series(&[
                100.0, 100.0, 100.0, 1100.0, 1100.0, 1100.0, 1049.0, 1049.0, 1049.0,
            ]),
            4 * 60_000,
            50.0,
        );
        match partial_release {
            TrendShape::PartialRelease { remaining } => {
                assert!((remaining - 949.0).abs() < 1e-9, "remaining = {remaining}");
            }
            other => panic!("expected PartialRelease, got {other:?}"),
        }
    }

    #[test]
    fn short_series_are_inconclusive() {
        assert!(matches!(
            classify_trend(&series(&[1.0, 2.0, 3.0]), 4 * 60_000, 1.0),
            TrendShape::Inconclusive
        ));
    }
}
