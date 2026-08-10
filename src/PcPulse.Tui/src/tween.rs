//! The smooth-refresh tween layer.
//!
//! When the per-user "Refresh rate" preference is 30 or 60 fps, the main
//! loop draws on a fixed cadence and the continuously visible numeric
//! surfaces (meters, heat columns, ribbon shares, gauges, headline digits)
//! ease from the previous telemetry sample toward the newest one over
//! [`TWEEN`] with a cubic-out curve. Everything here is deterministic and
//! clock-injected: the loop stamps `now` into [`SmoothState`] before every
//! draw and render paths only ever read stored instants, so tests can pin
//! any tween phase exactly. At the default event-driven setting (0 fps) the
//! layer is inert — every accessor returns the target value untouched, so
//! the default render path is bit-identical to a build without this module.

use pcpulse_service::models::{HardwareMetrics, Snapshot, SystemMetric};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// How long a newly arrived sample takes to ease in.
pub const TWEEN: Duration = Duration::from_millis(400);

/// Consecutive frame-budget overruns tolerated before the session drops to
/// the next refresh tier.
pub const OVERRUN_LIMIT: u32 = 3;

/// The classic cubic-out easing curve on `0..=1`.
pub fn cubic_out(t: f64) -> f64 {
    let inverse = 1.0 - t.clamp(0.0, 1.0);
    1.0 - inverse * inverse * inverse
}

/// Eased tween progress for a sample that arrived at `started`, sampled at
/// `now`. Saturates to `1.0` once [`TWEEN`] has fully elapsed.
pub fn progress(started: Instant, now: Instant) -> f64 {
    let elapsed = now.saturating_duration_since(started);
    if elapsed >= TWEEN {
        1.0
    } else {
        cubic_out(elapsed.as_secs_f64() / TWEEN.as_secs_f64())
    }
}

/// Linear interpolation that is exact at the endpoint: `t >= 1` returns
/// `target` itself (no floating-point residue), which is what guarantees the
/// settled and event-driven paths render bit-identically.
pub fn lerp(previous: f64, target: f64, t: f64) -> f64 {
    if t >= 1.0 {
        target
    } else {
        previous + (target - previous) * t
    }
}

/// The next tier down the session ladder: 60 → 30 → 0 (event-driven).
pub const fn next_tier(fps: u32) -> u32 {
    match fps {
        60 => 30,
        _ => 0,
    }
}

/// Pure downgrade decision: counts consecutive frame-budget overruns and
/// reports `true` exactly when [`OVERRUN_LIMIT`] is reached, then rearms.
#[derive(Debug, Default)]
pub struct FrameGovernor {
    consecutive_overruns: u32,
}

impl FrameGovernor {
    pub const fn new() -> Self {
        Self {
            consecutive_overruns: 0,
        }
    }

    /// Record one frame's cost against its budget. Returns `true` when the
    /// caller should drop to the next refresh tier.
    pub fn note_frame(&mut self, cost: Duration, budget: Duration) -> bool {
        if cost > budget {
            self.consecutive_overruns += 1;
            if self.consecutive_overruns >= OVERRUN_LIMIT {
                self.consecutive_overruns = 0;
                return true;
            }
        } else {
            self.consecutive_overruns = 0;
        }
        false
    }
}

/// The interpolation inputs kept per process between samples — only the
/// channels a smooth surface actually displays.
#[derive(Debug, Clone, Copy)]
pub struct PrevProcess {
    pub cpu_percent: f64,
    pub working_set_bytes: f64,
    pub io_bytes_per_sec: f64,
}

/// The displayed values captured when a snapshot is superseded: the system
/// sample, the per-PID process channels, and every hardware gauge keyed by a
/// typed label (`temp:`, `core:`, `mem:`, `util:`, plus `clock:cpu`).
#[derive(Debug, Clone, Default)]
pub struct PreviousSample {
    pub system: Option<SystemMetric>,
    pub processes: HashMap<u32, PrevProcess>,
    pub gauges: HashMap<String, f64>,
}

/// Gauge keys for [`PreviousSample::gauges`].
pub fn temp_key(label: &str) -> String {
    format!("temp:{label}")
}
pub fn core_clock_key(gpu: &str) -> String {
    format!("core:{gpu}")
}
pub fn memory_clock_key(gpu: &str) -> String {
    format!("mem:{gpu}")
}
pub fn util_key(gpu: &str) -> String {
    format!("util:{gpu}")
}
pub const CPU_CLOCK_KEY: &str = "clock:cpu";

fn gauge_map(hardware: &HardwareMetrics) -> HashMap<String, f64> {
    let mut gauges = HashMap::new();
    for zone in &hardware.thermal_zones {
        gauges.insert(temp_key(&zone.name), zone.temperature_c);
    }
    if let Some(frequency) = hardware.cpu_frequency_mhz {
        gauges.insert(CPU_CLOCK_KEY.to_string(), frequency);
    }
    for gpu in &hardware.gpus {
        if let Some(temperature) = gpu.temperature_c {
            gauges.insert(temp_key(&gpu.name), temperature);
        }
        if let Some(clock) = gpu.core_clock_mhz {
            gauges.insert(core_clock_key(&gpu.name), clock);
        }
        if let Some(clock) = gpu.memory_clock_mhz {
            gauges.insert(memory_clock_key(&gpu.name), clock);
        }
        if let Some(utilization) = gpu.utilization_percent {
            gauges.insert(util_key(&gpu.name), utilization);
        }
    }
    gauges
}

/// The per-session smooth-refresh state the [`crate::app::App`] owns: the
/// previous displayed sample, the tween clock, and the frame governor with
/// its session tier cap. All time flows in through method arguments.
#[derive(Debug)]
pub struct SmoothState {
    previous: PreviousSample,
    arrived_at: Option<Instant>,
    render_now: Instant,
    governor: FrameGovernor,
    /// Session-only refresh ceiling set by the governor; `None` = uncapped.
    session_cap: Option<u32>,
}

impl Default for SmoothState {
    fn default() -> Self {
        Self {
            previous: PreviousSample::default(),
            arrived_at: None,
            render_now: Instant::now(),
            governor: FrameGovernor::new(),
            session_cap: None,
        }
    }
}

impl SmoothState {
    /// Stamp the frame clock; the loop calls this immediately before every
    /// draw so no render path ever consults the wall clock itself.
    pub fn set_render_now(&mut self, now: Instant) {
        self.render_now = now;
    }

    /// Eased progress of the in-flight tween at the stamped frame clock;
    /// `1.0` when nothing is tweening.
    pub fn t(&self) -> f64 {
        match self.arrived_at {
            Some(arrived) => progress(arrived, self.render_now),
            None => 1.0,
        }
    }

    /// A new snapshot is superseding `outgoing`: capture the values the
    /// screen is showing *right now* (mid-tween positions included, so an
    /// early sample never snaps) and restart the tween clock at `now`.
    pub fn observe_snapshot(&mut self, outgoing: &Snapshot, now: Instant) {
        let t = match self.arrived_at {
            Some(arrived) => progress(arrived, now),
            None => 1.0,
        };
        let mut system = outgoing.system.clone();
        if let Some(previous) = &self.previous.system {
            system.cpu_percent = lerp(previous.cpu_percent, system.cpu_percent, t);
            system.memory_used_bytes = lerp(
                previous.memory_used_bytes as f64,
                system.memory_used_bytes as f64,
                t,
            )
            .round() as u64;
            system.disk_latency_ms = lerp(previous.disk_latency_ms, system.disk_latency_ms, t);
            system.disk_read_bytes_per_sec = lerp(
                previous.disk_read_bytes_per_sec,
                system.disk_read_bytes_per_sec,
                t,
            );
            system.disk_write_bytes_per_sec = lerp(
                previous.disk_write_bytes_per_sec,
                system.disk_write_bytes_per_sec,
                t,
            );
            system.network_bytes_per_sec = lerp(
                previous.network_bytes_per_sec,
                system.network_bytes_per_sec,
                t,
            );
            system.dpc_rate = lerp(previous.dpc_rate, system.dpc_rate, t);
            system.interrupt_rate = lerp(previous.interrupt_rate, system.interrupt_rate, t);
        }
        let processes = outgoing
            .processes
            .iter()
            .map(|process| {
                let target = PrevProcess {
                    cpu_percent: process.cpu_percent,
                    working_set_bytes: process.working_set_bytes as f64,
                    io_bytes_per_sec: process.read_bytes_per_sec + process.write_bytes_per_sec,
                };
                let displayed = match self.previous.processes.get(&process.pid) {
                    Some(previous) => PrevProcess {
                        cpu_percent: lerp(previous.cpu_percent, target.cpu_percent, t),
                        working_set_bytes: lerp(
                            previous.working_set_bytes,
                            target.working_set_bytes,
                            t,
                        ),
                        io_bytes_per_sec: lerp(
                            previous.io_bytes_per_sec,
                            target.io_bytes_per_sec,
                            t,
                        ),
                    },
                    None => target,
                };
                (process.pid, displayed)
            })
            .collect();
        let gauges = gauge_map(&outgoing.hardware)
            .into_iter()
            .map(|(key, target)| {
                let displayed = match self.previous.gauges.get(&key) {
                    Some(previous) => lerp(*previous, target, t),
                    None => target,
                };
                (key, displayed)
            })
            .collect();
        self.previous = PreviousSample {
            system: Some(system),
            processes,
            gauges,
        };
        self.arrived_at = Some(now);
    }

    /// Begin a tween from an explicit previous sample — the deterministic
    /// entry point tests use to pin a tween phase.
    pub fn begin(&mut self, previous: PreviousSample, arrived_at: Instant) {
        self.previous = previous;
        self.arrived_at = Some(arrived_at);
    }

    pub fn previous_system(&self) -> Option<&SystemMetric> {
        self.previous.system.as_ref()
    }

    pub fn previous_process(&self, pid: u32) -> Option<&PrevProcess> {
        self.previous.processes.get(&pid)
    }

    pub fn previous_gauge(&self, key: &str) -> Option<f64> {
        self.previous.gauges.get(key).copied()
    }

    /// Record one smooth frame's cost. Returns `Some(next_tier)` when the
    /// governor demands a downgrade; the cap sticks for the session.
    pub fn note_frame(
        &mut self,
        cost: Duration,
        budget: Duration,
        current_fps: u32,
    ) -> Option<u32> {
        if self.governor.note_frame(cost, budget) {
            let next = next_tier(current_fps);
            self.session_cap = Some(next);
            return Some(next);
        }
        None
    }

    pub fn session_cap(&self) -> Option<u32> {
        self.session_cap
    }

    /// An explicit preference change lifts the session cap and rearms the
    /// governor — the user asked for the new tier, so it gets a fresh try.
    pub fn reset_session(&mut self) {
        self.session_cap = None;
        self.governor = FrameGovernor::new();
    }
}

/// Interpolate a displayed process channel against the captured sample.
pub fn display_process_channel(
    smooth: &SmoothState,
    pid: u32,
    target: f64,
    channel: fn(&PrevProcess) -> f64,
    t: f64,
) -> f64 {
    match smooth.previous_process(pid) {
        Some(previous) if t < 1.0 => lerp(channel(previous), target, t),
        _ => target,
    }
}

/// Interpolate the whole displayed system sample: the tweened channels ease,
/// every other field passes through from `target` untouched.
pub fn display_system(smooth: &SmoothState, target: &SystemMetric, t: f64) -> SystemMetric {
    let mut shown = target.clone();
    if t >= 1.0 {
        return shown;
    }
    let Some(previous) = smooth.previous_system() else {
        return shown;
    };
    shown.cpu_percent = lerp(previous.cpu_percent, target.cpu_percent, t);
    shown.memory_used_bytes = lerp(
        previous.memory_used_bytes as f64,
        target.memory_used_bytes as f64,
        t,
    )
    .round() as u64;
    shown.disk_latency_ms = lerp(previous.disk_latency_ms, target.disk_latency_ms, t);
    shown.disk_read_bytes_per_sec = lerp(
        previous.disk_read_bytes_per_sec,
        target.disk_read_bytes_per_sec,
        t,
    );
    shown.disk_write_bytes_per_sec = lerp(
        previous.disk_write_bytes_per_sec,
        target.disk_write_bytes_per_sec,
        t,
    );
    shown.network_bytes_per_sec = lerp(
        previous.network_bytes_per_sec,
        target.network_bytes_per_sec,
        t,
    );
    shown.dpc_rate = lerp(previous.dpc_rate, target.dpc_rate, t);
    shown.interrupt_rate = lerp(previous.interrupt_rate, target.interrupt_rate, t);
    shown
}

/// A [`PreviousSample`] captured verbatim from a snapshot (no mid-tween
/// blending) — convenient for tests and first-arrival seeding.
pub fn sample_from_snapshot(snapshot: &Snapshot) -> PreviousSample {
    PreviousSample {
        system: Some(snapshot.system.clone()),
        processes: snapshot
            .processes
            .iter()
            .map(|process| {
                (
                    process.pid,
                    PrevProcess {
                        cpu_percent: process.cpu_percent,
                        working_set_bytes: process.working_set_bytes as f64,
                        io_bytes_per_sec: process.read_bytes_per_sec + process.write_bytes_per_sec,
                    },
                )
            })
            .collect(),
        gauges: gauge_map(&snapshot.hardware),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cubic_out_hits_its_endpoints_and_rises_monotonically() {
        assert_eq!(cubic_out(0.0), 0.0);
        assert_eq!(cubic_out(1.0), 1.0);
        assert_eq!(cubic_out(-1.0), 0.0, "clamped below");
        assert_eq!(cubic_out(2.0), 1.0, "clamped above");
        let mut last = 0.0;
        for step in 1..=100 {
            let value = cubic_out(f64::from(step) / 100.0);
            assert!(value >= last, "cubic-out must never regress");
            last = value;
        }
        // Ease-out shape: the first half covers most of the distance.
        assert!(cubic_out(0.5) > 0.8);
    }

    #[test]
    fn lerp_is_exact_at_the_endpoint() {
        assert_eq!(lerp(3.0, 7.0, 0.0), 3.0);
        assert_eq!(lerp(3.0, 7.0, 1.0), 7.0);
        assert_eq!(lerp(0.1, 0.3, 1.0).to_bits(), 0.3_f64.to_bits());
        assert_eq!(lerp(0.0, 10.0, 0.5), 5.0);
    }

    #[test]
    fn progress_saturates_after_the_tween_window() {
        let start = Instant::now();
        assert_eq!(progress(start, start), 0.0);
        assert_eq!(progress(start, start + TWEEN), 1.0);
        assert_eq!(progress(start, start + TWEEN * 4), 1.0);
        let mid = progress(start, start + TWEEN / 2);
        assert!(mid > 0.8 && mid < 1.0, "cubic-out midpoint, got {mid}");
    }

    #[test]
    fn governor_downgrades_only_on_three_consecutive_overruns() {
        let budget = Duration::from_millis(16);
        let over = Duration::from_millis(20);
        let under = Duration::from_millis(4);
        let mut governor = FrameGovernor::new();
        assert!(!governor.note_frame(over, budget));
        assert!(!governor.note_frame(over, budget));
        // A frame back under budget resets the streak.
        assert!(!governor.note_frame(under, budget));
        assert!(!governor.note_frame(over, budget));
        assert!(!governor.note_frame(over, budget));
        assert!(governor.note_frame(over, budget), "third consecutive");
        // The governor rearms after firing.
        assert!(!governor.note_frame(over, budget));
    }

    #[test]
    fn session_ladder_steps_sixty_to_thirty_to_off() {
        assert_eq!(next_tier(60), 30);
        assert_eq!(next_tier(30), 0);
        assert_eq!(next_tier(0), 0);
        let budget = Duration::from_millis(16);
        let over = Duration::from_millis(40);
        let mut smooth = SmoothState::default();
        for _ in 0..2 {
            assert_eq!(smooth.note_frame(over, budget, 60), None);
        }
        assert_eq!(smooth.note_frame(over, budget, 60), Some(30));
        assert_eq!(smooth.session_cap(), Some(30));
        for _ in 0..2 {
            assert_eq!(smooth.note_frame(over, budget, 30), None);
        }
        assert_eq!(smooth.note_frame(over, budget, 30), Some(0));
        assert_eq!(smooth.session_cap(), Some(0));
        smooth.reset_session();
        assert_eq!(smooth.session_cap(), None);
    }

    #[test]
    fn observe_snapshot_captures_mid_tween_display_values() {
        use pcpulse_service::models::Snapshot;
        let mut smooth = SmoothState::default();
        let mut snapshot = Snapshot::default();
        snapshot.system.cpu_percent = 20.0;
        let start = Instant::now();
        smooth.begin(sample_from_snapshot(&snapshot), start);
        // A new sample supersedes the old one exactly at the tween's end:
        // the captured previous is then the old target itself.
        snapshot.system.cpu_percent = 60.0;
        smooth.observe_snapshot(&snapshot, start + TWEEN);
        let previous = smooth.previous_system().expect("captured system");
        assert_eq!(previous.cpu_percent, 60.0);
        // Mid-tween supersession captures the interpolated position, not
        // either endpoint, so the display never snaps.
        smooth.begin(sample_from_snapshot(&Snapshot::default()), start);
        smooth.observe_snapshot(&snapshot, start + TWEEN / 2);
        let previous = smooth.previous_system().expect("captured system");
        assert!(previous.cpu_percent > 0.0 && previous.cpu_percent < 60.0);
    }
}
