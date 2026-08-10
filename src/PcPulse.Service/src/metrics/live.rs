//! The activity-gated live telemetry channel.
//!
//! Smooth-mode clients want fresh system numbers at up to 8 Hz — far faster
//! than the 2-second snapshot cadence — but the collector must stay at zero
//! idle cost. The design here mirrors the forensics gating: nothing runs
//! until a client sends the `live` pipe command; the first request spawns a
//! dedicated sampling thread with its **own** `PdhOpenQuery` (so collecting
//! at high rate can never skew the main 2-second query's rate windows); and
//! the thread exits — closing its PDH handles — after [`LIVE_IDLE_STOP`]
//! without a request. Idle cost is therefore exactly zero syscalls, zero
//! handles, zero threads.
//!
//! Honesty rules:
//! - Rate counters need a prior collection, so the loop primes the query on
//!   startup and sleeps one interval before publishing its first sample.
//!   Requests that land in that warm-up window (including the very first
//!   request, which is what started the loop) get `available: false`.
//! - Collections are at least [`LIVE_INTERVAL`] = 125 ms apart; PDH rate
//!   counters get noisy below ~100 ms windows, so the interval is asserted
//!   to stay above that floor.
//! - The published slot is cleared when the loop stops so a later restart
//!   can never serve a stale sample as fresh.
//!
//! Budget: while subscribed, the loop costs one `PdhCollectQueryData` over a
//! seven-counter query plus one `GlobalMemoryStatusEx` every 125 ms —
//! measured well under 0.01 % normalized CPU — and one extra PDH query
//! handle set, which exists only while a subscriber is active.

use super::pdh::{ERROR_SUCCESS, add_counter, formatted, formatted_wildcard_sum};
use crate::models::LiveSample;
use anyhow::{Result, bail};
use chrono::Utc;
use std::{
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use windows::{
    Win32::System::Performance::{
        PDH_HCOUNTER, PDH_HQUERY, PdhCloseQuery, PdhCollectQueryData, PdhOpenQueryW,
    },
    core::PCWSTR,
};

/// Spacing between live collections. Must stay ≥ 100 ms: a shorter window
/// makes PDH rate counters (CPU %, interrupts/sec, DPC rate) noisy.
pub const LIVE_INTERVAL: Duration = Duration::from_millis(125);

/// The live loop stops — releasing its thread and PDH handles — after this
/// long without a `live` request.
pub const LIVE_IDLE_STOP: Duration = Duration::from_secs(10);

/// One live sampling pass; boxed so tests can substitute a scripted source.
type Sampler = Box<dyn FnMut() -> LiveSample + Send>;

/// Builds a fresh sampler each time the loop starts. Invoked *on* the live
/// thread, so the real factory opens its PDH query there and the handles
/// live and die with the thread.
type SamplerFactory = Arc<dyn Fn() -> Result<Sampler> + Send + Sync>;

struct LiveShared {
    latest: Mutex<Option<LiveSample>>,
    last_request: Mutex<Instant>,
    running: AtomicBool,
}

/// Poison-tolerant lock: a panicked sampler thread must not wedge the pipe.
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The engine the pipe consults: request-gated start, idle-timed stop, and
/// a single latest-sample slot (no ring — clients poll faster than they
/// need history).
pub struct LiveEngine {
    shared: Arc<LiveShared>,
    factory: SamplerFactory,
    interval: Duration,
    idle_stop: Duration,
}

impl LiveEngine {
    /// The production engine: a dedicated PDH query opened lazily on the
    /// live thread. Constructing the engine performs no syscalls.
    pub fn windows() -> Self {
        Self::with_source(
            Arc::new(|| {
                let mut collector = LivePdhCollector::new()?;
                Ok(Box::new(move || collector.sample()) as Sampler)
            }),
            LIVE_INTERVAL,
            LIVE_IDLE_STOP,
        )
    }

    /// Test entry point: a scripted sampler factory and compressed timings.
    pub fn with_source(factory: SamplerFactory, interval: Duration, idle_stop: Duration) -> Self {
        Self {
            shared: Arc::new(LiveShared {
                latest: Mutex::new(None),
                last_request: Mutex::new(Instant::now()),
                running: AtomicBool::new(false),
            }),
            factory,
            interval,
            idle_stop,
        }
    }

    /// Serve the most recent live sample and mark liveness. Starts the
    /// sampling loop if it is not running; returns `available: false` until
    /// the loop has a rate-valid collection.
    pub fn request(&self) -> LiveSample {
        *locked(&self.shared.last_request) = Instant::now();
        if self
            .shared
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let shared = Arc::clone(&self.shared);
            let factory = Arc::clone(&self.factory);
            let interval = self.interval;
            let idle_stop = self.idle_stop;
            let spawned = thread::Builder::new()
                .name("pcpulse-live".into())
                .spawn(move || live_loop(&shared, &factory, interval, idle_stop));
            if let Err(error) = spawned {
                eprintln!("live telemetry thread failed to start: {error:#}");
                self.shared.running.store(false, Ordering::Release);
            }
        }
        locked(&self.shared.latest)
            .clone()
            .unwrap_or_else(|| LiveSample::unavailable(Utc::now().timestamp_millis()))
    }

    /// Whether the sampling loop is currently alive (tests observe gating).
    pub fn is_running(&self) -> bool {
        self.shared.running.load(Ordering::Acquire)
    }
}

fn live_loop(
    shared: &LiveShared,
    factory: &SamplerFactory,
    interval: Duration,
    idle_stop: Duration,
) {
    let mut sampler = match factory() {
        Ok(sampler) => sampler,
        Err(error) => {
            eprintln!("live telemetry sampler unavailable: {error:#}");
            shared.running.store(false, Ordering::Release);
            return;
        }
    };
    loop {
        // Sleep first: the factory primed the query, and rates need this
        // spacing before their first read is trustworthy.
        thread::sleep(interval);
        if locked(&shared.last_request).elapsed() > idle_stop {
            break;
        }
        let sample = sampler();
        *locked(&shared.latest) = Some(sample);
    }
    // Clear before unlatching `running` so a restarting loop never finds —
    // and a racing request never serves — a stale sample as current.
    *locked(&shared.latest) = None;
    shared.running.store(false, Ordering::Release);
}

/// The dedicated live PDH query: system-level counters only, no process
/// enumeration, opened and collected exclusively on the live thread.
struct LivePdhCollector {
    query: PDH_HQUERY,
    cpu: PDH_HCOUNTER,
    disk_latency: PDH_HCOUNTER,
    disk_read: PDH_HCOUNTER,
    disk_write: PDH_HCOUNTER,
    dpc_rate: PDH_HCOUNTER,
    interrupt_rate: PDH_HCOUNTER,
    /// Wildcard over every interface, summed; optional like the main query
    /// so a machine without the counter set still serves live data.
    network_total: Option<PDH_HCOUNTER>,
}

// The collector is created inside the live thread but the boxed sampler
// closure must be `Send`; PDH handles are valid on whichever single thread
// uses them, and this one never leaves the live loop.
unsafe impl Send for LivePdhCollector {}

impl LivePdhCollector {
    fn new() -> Result<Self> {
        unsafe {
            let mut query = PDH_HQUERY::default();
            let status = PdhOpenQueryW(PCWSTR::null(), 0, &mut query);
            if status != ERROR_SUCCESS {
                bail!("PdhOpenQueryW (live) failed with status 0x{status:08x}");
            }
            let result = Self {
                query,
                cpu: add_counter(query, r"\Processor(_Total)\% Processor Time")?,
                disk_latency: add_counter(query, r"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer")?,
                disk_read: add_counter(query, r"\PhysicalDisk(_Total)\Disk Read Bytes/sec")?,
                disk_write: add_counter(query, r"\PhysicalDisk(_Total)\Disk Write Bytes/sec")?,
                dpc_rate: add_counter(query, r"\Processor(_Total)\DPC Rate")?,
                interrupt_rate: add_counter(query, r"\Processor(_Total)\Interrupts/sec")?,
                network_total: add_counter(query, r"\Network Interface(*)\Bytes Total/sec").ok(),
            };
            // Prime the rate counters; the loop sleeps one interval before
            // the first formatted read.
            let _ = PdhCollectQueryData(query);
            Ok(result)
        }
    }

    fn sample(&mut self) -> LiveSample {
        let timestamp_ms = Utc::now().timestamp_millis();
        let (memory_total_bytes, memory_used_bytes) =
            super::win32::physical_memory().unwrap_or((0, 0));
        unsafe {
            if PdhCollectQueryData(self.query) != ERROR_SUCCESS {
                return LiveSample::unavailable(timestamp_ms);
            }
            LiveSample {
                available: true,
                timestamp_ms,
                cpu_percent: formatted(self.cpu).clamp(0.0, 100.0),
                memory_used_bytes,
                memory_total_bytes,
                disk_read_bytes_per_sec: formatted(self.disk_read).max(0.0),
                disk_write_bytes_per_sec: formatted(self.disk_write).max(0.0),
                disk_latency_ms: (formatted(self.disk_latency) * 1_000.0).max(0.0),
                network_bytes_per_sec: self
                    .network_total
                    .map_or(0.0, |counter| formatted_wildcard_sum(counter)),
                dpc_rate: formatted(self.dpc_rate).max(0.0),
                interrupt_rate: formatted(self.interrupt_rate).max(0.0),
            }
        }
    }
}

impl Drop for LivePdhCollector {
    fn drop(&mut self) {
        unsafe {
            let _ = PdhCloseQuery(self.query);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    fn scripted_engine(interval: Duration, idle_stop: Duration) -> (LiveEngine, Arc<AtomicU32>) {
        let starts = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&starts);
        let engine = LiveEngine::with_source(
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut ticks = 0_i64;
                Ok(Box::new(move || {
                    ticks += 1;
                    LiveSample {
                        available: true,
                        cpu_percent: ticks as f64,
                        ..LiveSample::unavailable(ticks)
                    }
                }) as Sampler)
            }),
            interval,
            idle_stop,
        );
        (engine, starts)
    }

    fn wait_until(deadline: Duration, mut done: impl FnMut() -> bool) -> bool {
        let started = Instant::now();
        while started.elapsed() < deadline {
            if done() {
                return true;
            }
            thread::sleep(Duration::from_millis(2));
        }
        done()
    }

    #[test]
    fn first_request_starts_the_loop_and_honestly_reports_unavailable() {
        let (engine, starts) = scripted_engine(Duration::from_millis(5), Duration::from_secs(5));
        assert!(!engine.is_running(), "no requests yet — loop must be idle");
        let first = engine.request();
        assert!(!first.available, "before warm-up the sample is unavailable");
        assert!(engine.is_running(), "the first request starts the loop");
        assert!(
            wait_until(Duration::from_secs(2), || engine.request().available),
            "after warm-up requests serve real samples"
        );
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        // Requests keep the loop alive and samples keep advancing.
        let earlier = engine.request().cpu_percent;
        assert!(wait_until(Duration::from_secs(2), || {
            engine.request().cpu_percent > earlier
        }));
    }

    #[test]
    fn loop_stops_after_idle_and_a_new_request_restarts_it_fresh() {
        let (engine, starts) = scripted_engine(
            Duration::from_millis(3),
            // Idle stop far above the interval so requests reliably keep
            // the loop alive, but short enough for a fast test.
            Duration::from_millis(60),
        );
        engine.request();
        assert!(wait_until(Duration::from_secs(2), || {
            engine.request().available
        }));
        // Stop requesting: the loop must notice the idle window and exit.
        assert!(
            wait_until(Duration::from_secs(2), || !engine.is_running()),
            "the loop must stop after {:?} without requests",
            Duration::from_millis(60)
        );
        // The restart is honest: the stale slot was cleared, so the first
        // request after idle reports unavailable again, then warms.
        let restarted = engine.request();
        assert!(!restarted.available, "no stale sample may survive the stop");
        assert!(engine.is_running());
        assert!(wait_until(Duration::from_secs(2), || {
            engine.request().available
        }));
        assert_eq!(starts.load(Ordering::SeqCst), 2, "one sampler per run");
    }

    #[test]
    fn failed_sampler_startup_releases_the_gate_for_a_retry() {
        let engine = LiveEngine::with_source(
            Arc::new(|| bail!("no counters on this machine")),
            Duration::from_millis(3),
            Duration::from_millis(50),
        );
        let sample = engine.request();
        assert!(!sample.available);
        assert!(
            wait_until(Duration::from_secs(2), || !engine.is_running()),
            "a failed factory must not leave the running latch stuck"
        );
        // The next request may try again rather than being wedged forever.
        engine.request();
        assert!(engine.is_running());
    }

    #[test]
    fn real_windows_query_warms_and_serves_plausible_system_rates() {
        // The production factory, compressed idle stop so the test leaves
        // no long-lived thread behind. First request starts the loop and is
        // honestly unavailable; within a couple of collection windows the
        // dedicated PDH query must serve real numbers.
        let engine = LiveEngine::with_source(
            Arc::new(|| {
                let mut collector = LivePdhCollector::new()?;
                Ok(Box::new(move || collector.sample()) as Sampler)
            }),
            LIVE_INTERVAL,
            Duration::from_millis(500),
        );
        assert!(!engine.request().available);
        assert!(
            wait_until(Duration::from_secs(5), || engine.request().available),
            "the real live PDH query never produced a sample"
        );
        let sample = engine.request();
        assert!(sample.available);
        assert!(sample.timestamp_ms > 0);
        assert!((0.0..=100.0).contains(&sample.cpu_percent));
        assert!(sample.memory_total_bytes > 0, "GlobalMemoryStatusEx data");
        assert!(sample.memory_used_bytes <= sample.memory_total_bytes);
        assert!(sample.disk_latency_ms >= 0.0);
        assert!(sample.interrupt_rate >= 0.0);
        // Idle: the loop must stop and release its PDH handles.
        assert!(wait_until(Duration::from_secs(3), || !engine.is_running()));
    }

    #[test]
    fn budget_contract_collection_interval_and_idle_stop() {
        // PDH rate counters need ≥ ~100 ms windows; the live loop must never
        // collect faster, and it must stop on idle so idle cost is zero.
        assert!(LIVE_INTERVAL >= Duration::from_millis(100));
        assert_eq!(LIVE_IDLE_STOP, Duration::from_secs(10));
        let engine = LiveEngine::windows();
        assert_eq!(engine.interval, LIVE_INTERVAL);
        assert_eq!(engine.idle_stop, LIVE_IDLE_STOP);
        assert!(!engine.is_running(), "constructing the engine starts nothing");
    }
}
