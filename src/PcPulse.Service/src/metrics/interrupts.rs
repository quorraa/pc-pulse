//! ISR/DPC root-cause monitoring for active `dpcInterrupt` findings.
//!
//! The DPC/interrupt detector can say *that* kernel interrupt work is
//! sustained, but not *whose* code is running. While the finding is active,
//! this module captures a short Windows kernel trace (a dedicated system
//! logger session with the ISR and DPC flags), buckets every interrupt
//! service routine and DPC routine address, and maps the buckets to loaded
//! kernel drivers so the finding's evidence can read
//! `storport.sys 41% · ndis.sys 27% · nvlddmkm.sys 12%`.
//!
//! On top of single-trace attribution the engine runs a root-cause verdict:
//! repeated traces across the life of a finding (adaptive cadence, bounded
//! per-finding history), classification of the top driver into a device
//! class, Pearson correlation between the interrupt/DPC rate series and the
//! class-matched device-activity series from the sampling loop, and a
//! `Likely cause` / `Confidence` / `Correlation` evidence triple driven by a
//! pure, unit-tested rubric. With zero successful captures no verdict is
//! ever fabricated — the finding keeps today's honest degraded note.
//!
//! Session discipline: the classic NT Kernel Logger is a singleton and the
//! collector's process-lifecycle session in `crate::etw` must never be
//! disturbed, so the capture uses a **separate** short-lived system logger
//! (`EVENT_TRACE_SYSTEM_LOGGER_MODE`, supported since Windows 10 1703, up to
//! eight concurrent). If the session cannot start — older OS, policy, logger
//! exhaustion, missing privilege — the evidence degrades to an honest note,
//! exactly like leak forensics.
//!
//! Budget discipline: the engine performs **zero syscalls** while no
//! `dpcInterrupt` finding is active ([`InterruptEngine::record_activity`] is
//! pure memory work). While one is active it captures once when the finding
//! fires, then at [`FAST_CAPTURE_SPACING_MS`] spacing until the finding has
//! [`FAST_PHASE_CAPTURES`] successful captures, then backs off to
//! [`CAPTURE_COOLDOWN_MS`]; a failed capture always arms the full cooldown.
//! Each capture is bounded: [`CAPTURE_WINDOW_MS`] of wall time, an
//! [`EVENT_CAP`]-event storm guard, a below-normal-priority consumer thread,
//! and a deterministic `ControlTrace(STOP)` + `CloseTrace` on every path.
//!
//! Privacy boundary: only driver base file names (`nvlddmkm.sys`) and the
//! version-resource description/company strings of the top driver are ever
//! recorded — never routine addresses, process data, or memory content.

use crate::models::{Alert, Evidence, SystemMetric};
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};
use windows::{
    Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, WIN32_ERROR},
        Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW},
        System::{
            Diagnostics::Etw::{
                CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_HEADER_FLAG_32_BIT_HEADER,
                EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG, EVENT_TRACE_FLAG_DPC,
                EVENT_TRACE_FLAG_INTERRUPT, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_SYSTEM_LOGGER_MODE, OpenTraceW,
                PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
                PROCESSTRACE_HANDLE, ProcessTrace, StartTraceW, WNODE_FLAG_TRACED_GUID,
            },
            ProcessStatus::{
                EnumDeviceDrivers, K32GetDeviceDriverBaseNameW, K32GetDeviceDriverFileNameW,
            },
            Threading::{GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL},
        },
    },
    core::{GUID, PCWSTR, PWSTR},
};

/// Backed-off re-capture spacing once a finding has enough successful
/// captures, and the unconditional spacing after any failed capture.
/// Interrupt captures are heavier than handle tables, so the cooldown is ten
/// minutes rather than the forensics minute.
pub const CAPTURE_COOLDOWN_MS: i64 = 10 * 60_000;
/// Fast-phase spacing: while an active finding has fewer than
/// [`FAST_PHASE_CAPTURES`] successful captures, re-captures run this often so
/// the verdict rubric gets its repeated traces quickly.
pub const FAST_CAPTURE_SPACING_MS: i64 = 2 * 60_000;
/// Successful captures a finding needs before the cadence backs off from
/// [`FAST_CAPTURE_SPACING_MS`] to [`CAPTURE_COOLDOWN_MS`].
pub const FAST_PHASE_CAPTURES: usize = 3;
/// Bounded per-finding capture history: the ring keeps the last this many
/// successful attributions.
pub const CAPTURE_HISTORY: usize = 8;
/// Device-activity samples older than this fall off the correlation ring.
pub const ACTIVITY_WINDOW_MS: i64 = 5 * 60_000;
/// Hard cap on the activity ring for aggressive sample intervals.
const ACTIVITY_RING_CAP: usize = 512;
/// Pearson r over fewer aligned samples than this is noise, not signal.
pub const MIN_CORRELATION_SAMPLES: usize = 60;
/// Variance floor: a series' standard deviation must exceed this fraction of
/// its mean magnitude (with an absolute epsilon for all-zero series) before
/// a correlation against it means anything.
const MIN_RELATIVE_SPREAD: f64 = 0.01;
/// Correlation at or above this counts as class-matching evidence in the
/// confidence rubric.
const CONFIDENCE_R_FLOOR: f64 = 0.6;
/// Wall-clock length of one capture.
pub const CAPTURE_WINDOW_MS: u32 = 8_000;
/// Storm guard: once this many consumer callbacks have run, the capture
/// stops early and the evidence notes the cap.
pub const EVENT_CAP: u64 = 400_000;

const DPC_INTERRUPT_KIND: &str = "dpcInterrupt";
const ATTRIBUTION_LABEL: &str = "ISR/DPC attribution";
const TOP_DRIVER_LABEL: &str = "Top driver";
const WINDOW_LABEL: &str = "Trace window";
const LIKELY_CAUSE_LABEL: &str = "Likely cause";
const CONFIDENCE_LABEL: &str = "Confidence";
const CORRELATION_LABEL: &str = "Correlation";
const INTERRUPT_LABELS: [&str; 6] = [
    LIKELY_CAUSE_LABEL,
    CONFIDENCE_LABEL,
    CORRELATION_LABEL,
    ATTRIBUTION_LABEL,
    TOP_DRIVER_LABEL,
    WINDOW_LABEL,
];
const INSUFFICIENT_SIGNAL: &str = "insufficient signal";
const UNATTRIBUTED: &str = "unattributed";
/// Routine addresses are rounded down to 64 KiB so the bucket map stays tiny
/// even during a storm concentrated on a handful of routines.
const BUCKET_MASK: u64 = !0xFFFF;
/// Evidence values render generically in the TUI; keep them terminal-friendly.
const MAX_VALUE_CHARS: usize = 60;

/// The result of one bounded ISR/DPC trace.
#[derive(Debug, Clone, Default)]
pub struct InterruptCapture {
    /// Actual wall time covered (shorter than requested when the storm guard
    /// stopped the capture early).
    pub window_ms: u32,
    /// ISR events decoded.
    pub isr_events: u64,
    /// DPC events decoded (ordinary, timer, and threaded DPCs).
    pub dpc_events: u64,
    /// 64 KiB-aligned routine address -> event count.
    pub buckets: HashMap<u64, u64>,
    /// True when the storm guard ended the capture before the full window.
    pub capped: bool,
}

impl InterruptCapture {
    pub fn total_events(&self) -> u64 {
        self.isr_events + self.dpc_events
    }
}

/// Coarse device class an attributed driver belongs to, used to pick the
/// activity series to correlate against and the follow-up recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceClass {
    Storage,
    Network,
    Gpu,
    Usb,
    Audio,
    Platform,
    Other,
}

impl DeviceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Network => "network",
            Self::Gpu => "gpu",
            Self::Usb => "usb",
            Self::Audio => "audio",
            Self::Platform => "platform",
            Self::Other => "other",
        }
    }
}

/// Keyword table mapping driver base names (and version-resource
/// description/company strings, which vote second) to device classes. First
/// match in table order wins; anything unmatched is [`DeviceClass::Other`].
const CLASS_KEYWORDS: &[(DeviceClass, &[&str])] = &[
    (
        DeviceClass::Storage,
        &[
            "storport", "stornvme", "storahci", "iastor", "amdsata", "disk", "nvme", "scsi",
            "sata", "raid", "storage",
        ],
    ),
    (
        DeviceClass::Network,
        &[
            "ndis", "tcpip", "netio", "e1d", "e2f", "e1i", "rt640", "rtwlan", "netwtw", "mlx",
            "vmxnet", "wlan", "wifi", "ethernet", "network",
        ],
    ),
    (
        DeviceClass::Gpu,
        &[
            "nvlddmkm", "amdkmdag", "igdkmd", "dxgkrnl", "dxgmms", "geforce", "radeon",
            "graphics",
        ],
    ),
    (
        DeviceClass::Usb,
        &["usbxhci", "usbport", "usbhub", "usbccgp", "usbehci", "winusb", "usb"],
    ),
    (
        DeviceClass::Audio,
        &["hdaudbus", "hdaudio", "portcls", "audio"],
    ),
    (
        DeviceClass::Platform,
        &["acpi", "intelppm", "amdppm", "processr", "hal"],
    ),
];

/// One follow-up sentence per identified class, appended to the detector's
/// recommendation. [`DeviceClass::Other`] deliberately appends nothing.
const CLASS_RECOMMENDATIONS: &[(DeviceClass, &str)] = &[
    (
        DeviceClass::Storage,
        "Update or roll back the storage driver first.",
    ),
    (
        DeviceClass::Network,
        "Update or roll back the network driver first.",
    ),
    (DeviceClass::Gpu, "Update or roll back the GPU driver first."),
    (
        DeviceClass::Usb,
        "Update the USB controller driver and reseat recent USB devices first.",
    ),
    (
        DeviceClass::Audio,
        "Update or roll back the audio driver first.",
    ),
    (
        DeviceClass::Platform,
        "Update the chipset, ACPI, and power-management drivers first.",
    ),
];

/// Maps a driver to its device class. The base file name votes first; the
/// version-resource description/company string votes only when the name says
/// nothing, so `nvlddmkm.sys` stays `gpu` even if its description mentioned
/// networking.
pub fn classify_driver(name: &str, description: Option<&str>) -> DeviceClass {
    let name = name.to_ascii_lowercase();
    for (class, keywords) in CLASS_KEYWORDS {
        if keywords.iter().any(|keyword| name.contains(keyword)) {
            return *class;
        }
    }
    if let Some(description) = description {
        let description = description.to_ascii_lowercase();
        for (class, keywords) in CLASS_KEYWORDS {
            if keywords.iter().any(|keyword| description.contains(keyword)) {
                return *class;
            }
        }
    }
    DeviceClass::Other
}

fn class_recommendation(class: DeviceClass) -> Option<&'static str> {
    CLASS_RECOMMENDATIONS
        .iter()
        .find(|(candidate, _)| *candidate == class)
        .map(|(_, sentence)| *sentence)
}

/// One point of the device-activity ring the runtime feeds every sample.
#[derive(Debug, Clone, Copy)]
pub struct ActivityPoint {
    pub timestamp_ms: i64,
    pub interrupt_rate: f64,
    pub dpc_rate: f64,
    pub disk_bytes_per_sec: f64,
    pub disk_latency_ms: f64,
    pub network_bytes_per_sec: f64,
    /// `None` whenever the hardware sampler has no GPU utilization; gpu
    /// correlation is then skipped honestly instead of imputing zeros.
    pub gpu_utilization_percent: Option<f64>,
}

/// One successful attribution in a finding's bounded capture history.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureRecord {
    pub timestamp_ms: i64,
    /// Ranked per-driver share of decoded events in percent, largest first,
    /// including the `unattributed` pseudo-driver.
    pub shares: Vec<(String, f64)>,
    pub total_events: u64,
    pub capped: bool,
}

impl CaptureRecord {
    /// The leading real driver of this capture, skipping `unattributed`.
    fn top_driver(&self) -> Option<&str> {
        self.shares
            .iter()
            .find(|(name, _)| name != UNATTRIBUTED)
            .map(|(name, _)| name.as_str())
    }

    fn share_of(&self, driver: &str) -> f64 {
        self.shares
            .iter()
            .find(|(name, _)| name == driver)
            .map_or(0.0, |(_, share)| *share)
    }

    /// Margin (percentage points) of `driver` over the next-ranked entry,
    /// defined only when `driver` is this capture's top real driver.
    fn margin_over_second(&self, driver: &str) -> Option<f64> {
        if self.top_driver() != Some(driver) {
            return None;
        }
        let share = self.share_of(driver);
        let runner_up = self
            .shares
            .iter()
            .filter(|(name, _)| name != driver)
            .map(|(_, other)| *other)
            .fold(0.0_f64, f64::max);
        Some(share - runner_up)
    }
}

/// Verdict confidence tiers, in the exact rubric [`assess_confidence`]
/// implements (documented verbatim in docs/detectors.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// The pure confidence rubric.
///
/// - HIGH: the top driver is consistent in ≥ 3 captures with ≥ 45% mean
///   share AND (matching-class correlation r ≥ 0.6 OR dominance margin
///   ≥ 25 points).
/// - MEDIUM: consistent top in ≥ 2 captures with ≥ 30% mean share, or a
///   single capture with ≥ 60% share.
/// - LOW: everything else with at least one successful capture (the caller
///   never invokes the rubric with zero captures).
pub fn assess_confidence(
    consistent_captures: usize,
    total_captures: usize,
    mean_share_percent: f64,
    margin_points: f64,
    matched_r: Option<f64>,
) -> Confidence {
    let correlated = matched_r.is_some_and(|r| r >= CONFIDENCE_R_FLOOR);
    if consistent_captures >= 3
        && mean_share_percent >= 45.0
        && (correlated || margin_points >= 25.0)
    {
        Confidence::High
    } else if (consistent_captures >= 2 && mean_share_percent >= 30.0)
        || (total_captures == 1 && consistent_captures == 1 && mean_share_percent >= 60.0)
    {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

/// Successful captures that must agree on a driver family before the
/// attribution counts as repeatable (spec Phase D: "the same driver family
/// as modal candidate across >= 2 successful captures").
pub const REPEATABLE_CAPTURES: usize = 2;

/// How settled a finding's root-cause attribution is, as the notification
/// policy needs to see it. Derived from the same capture history the
/// evidence rows are built from, on every rebuild.
///
/// The distinction the field reports demand is between an attribution that
/// *held* and one that merely *existed*: a single 8-second trace, or labels
/// rotating storage -> graphics -> network, are diagnostic evidence that must
/// never ring a bell by themselves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum VerdictState {
    /// No successful capture, or none that attributed a real driver. There
    /// is no attribution to judge -- not a bad one.
    #[default]
    NoCapture,
    /// A modal driver exists but has not held: too few captures, a
    /// fragmented field, or a leader that keeps changing.
    SingleCapture,
    /// One device family leads a majority of the capture history across at
    /// least [`REPEATABLE_CAPTURES`] captures, and the confidence rubric
    /// rates that lead above [`Confidence::Low`]. `driver_family` is a
    /// [`DeviceClass`] name, so two storage drivers taking turns still read
    /// as one repeatable cause.
    Repeatable { driver_family: String },
    /// A repeatable verdict for a family that replaced an earlier repeatable
    /// verdict for a different one -- both sides passed the same gate, so
    /// this is a change of cause rather than a label flip. It is the DPC
    /// detector's "materially changed fingerprint" for renotification.
    ChangedConfidently { from: String, to: String },
}

impl VerdictState {
    /// Whether the verdict names a family that has held across captures.
    /// [`Self::ChangedConfidently`] counts: it is two repeatable verdicts in
    /// a row, which is more attribution than one, not less -- and it stands
    /// as the engine's answer until the next capture minutes later, so
    /// reading it as unattributed would silence the finding for exactly as
    /// long as the change is newest.
    pub fn is_attributed(&self) -> bool {
        matches!(
            self,
            Self::Repeatable { .. } | Self::ChangedConfidently { .. }
        )
    }

    /// What the quality layer should read for `attribution_stable`. A
    /// verdictless finding has nothing to say and scores neutral; one whose
    /// modal driver never held says so.
    pub fn attribution_stable(&self) -> Option<bool> {
        match self {
            Self::NoCapture => None,
            Self::SingleCapture => Some(false),
            Self::Repeatable { .. } | Self::ChangedConfidently { .. } => Some(true),
        }
    }
}

/// The most-likely-cause summary distilled from a finding's capture history.
#[derive(Debug, Clone, PartialEq)]
pub struct VerdictCandidate {
    pub driver: String,
    /// Captures in the history (all successful by construction).
    pub captures: usize,
    /// Captures where `driver` is the top real driver.
    pub consistent: usize,
    /// Mean share of `driver` across every capture, percent.
    pub mean_share: f64,
    /// Mean margin over the runner-up across captures where `driver` leads.
    pub margin: f64,
}

/// Picks the modal top driver across the capture history: the driver that
/// leads the most captures, ties broken by higher mean share. `None` when no
/// capture attributed a single real driver.
pub fn modal_candidate(history: &[CaptureRecord]) -> Option<VerdictCandidate> {
    let mut leads: HashMap<&str, usize> = HashMap::new();
    for record in history {
        if let Some(top) = record.top_driver() {
            *leads.entry(top).or_insert(0) += 1;
        }
    }
    let driver = leads
        .iter()
        .max_by(|a, b| {
            a.1.cmp(b.1).then_with(|| {
                let share_a: f64 = history.iter().map(|record| record.share_of(a.0)).sum();
                let share_b: f64 = history.iter().map(|record| record.share_of(b.0)).sum();
                share_a.total_cmp(&share_b).then_with(|| b.0.cmp(a.0))
            })
        })
        .map(|(name, _)| (*name).to_string())?;
    let captures = history.len();
    let consistent = leads.get(driver.as_str()).copied().unwrap_or(0);
    let mean_share = history
        .iter()
        .map(|record| record.share_of(&driver))
        .sum::<f64>()
        / captures.max(1) as f64;
    let margins: Vec<f64> = history
        .iter()
        .filter_map(|record| record.margin_over_second(&driver))
        .collect();
    let margin = if margins.is_empty() {
        0.0
    } else {
        margins.iter().sum::<f64>() / margins.len() as f64
    };
    Some(VerdictCandidate {
        driver,
        captures,
        consistent,
        mean_share,
        margin,
    })
}

/// Outcome of correlating the interrupt/DPC rate series against the activity
/// series matched to a device class.
#[derive(Debug, Clone, PartialEq)]
pub enum CorrelationOutcome {
    Measured {
        /// Which activity series produced the strongest correlation.
        series: &'static str,
        r: f64,
        span_ms: i64,
    },
    /// Too few samples, a near-constant series, or no activity series for
    /// the class (usb/audio/platform/other have none).
    Insufficient,
}

impl CorrelationOutcome {
    fn matched_r(&self) -> Option<f64> {
        match self {
            Self::Measured { r, .. } => Some(*r),
            Self::Insufficient => None,
        }
    }
}

/// Pearson correlation coefficient with the honesty guards: `None` for
/// mismatched or short series and for near-constant series on either side,
/// where r would be numerically defined but meaningless.
pub fn pearson(xs: &[f64], ys: &[f64]) -> Option<f64> {
    if xs.len() != ys.len() || xs.len() < MIN_CORRELATION_SAMPLES {
        return None;
    }
    let n = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / n;
    let mean_y = ys.iter().sum::<f64>() / n;
    let mut covariance = 0.0;
    let mut variance_x = 0.0;
    let mut variance_y = 0.0;
    for (x, y) in xs.iter().zip(ys) {
        let dx = x - mean_x;
        let dy = y - mean_y;
        covariance += dx * dy;
        variance_x += dx * dx;
        variance_y += dy * dy;
    }
    if !spread_ok(mean_x, variance_x / n) || !spread_ok(mean_y, variance_y / n) {
        return None;
    }
    Some(covariance / (variance_x.sqrt() * variance_y.sqrt()))
}

/// The variance floor: near-constant series (relative to their own
/// magnitude) fail, as do outright flat ones.
fn spread_ok(mean: f64, variance: f64) -> bool {
    let std_dev = variance.max(0.0).sqrt();
    std_dev > 1e-9 && std_dev >= mean.abs() * MIN_RELATIVE_SPREAD
}

/// Correlates both kernel-rate series (interrupt and DPC) against every
/// activity series matched to `class`, returning the strongest |r|.
///
/// storage → disk read+write bytes/s and disk latency; network → summed
/// network bytes/s; gpu → GPU utilization over the samples where the
/// hardware sampler produced one. Other classes have no honest activity
/// series and report [`CorrelationOutcome::Insufficient`].
pub fn class_correlation(
    activity: &VecDeque<ActivityPoint>,
    class: DeviceClass,
) -> CorrelationOutcome {
    let span_ms = match (activity.front(), activity.back()) {
        (Some(first), Some(last)) => last.timestamp_ms - first.timestamp_ms,
        _ => return CorrelationOutcome::Insufficient,
    };
    type Extract = fn(&ActivityPoint) -> Option<f64>;
    type Rate = fn(&ActivityPoint) -> f64;
    let candidates: &[(&'static str, Extract)] = match class {
        DeviceClass::Storage => &[
            ("storage activity", |point| Some(point.disk_bytes_per_sec)),
            ("disk latency", |point| Some(point.disk_latency_ms)),
        ],
        DeviceClass::Network => &[("network activity", |point| {
            Some(point.network_bytes_per_sec)
        })],
        DeviceClass::Gpu => &[("gpu activity", |point| point.gpu_utilization_percent)],
        _ => &[],
    };
    let rates: [Rate; 2] = [|point| point.interrupt_rate, |point| point.dpc_rate];
    let mut best: Option<(&'static str, f64)> = None;
    for (series, extract) in candidates {
        for rate in &rates {
            let mut xs = Vec::with_capacity(activity.len());
            let mut ys = Vec::with_capacity(activity.len());
            for point in activity {
                if let Some(value) = extract(point) {
                    xs.push(rate(point));
                    ys.push(value);
                }
            }
            if let Some(r) = pearson(&xs, &ys)
                && best.is_none_or(|(_, current)| r.abs() > current.abs())
            {
                best = Some((series, r));
            }
        }
    }
    match best {
        Some((series, r)) => CorrelationOutcome::Measured { series, r, span_ms },
        None => CorrelationOutcome::Insufficient,
    }
}

/// The syscall layer behind the engine, stubbed in unit tests.
pub trait InterruptSource {
    /// Runs one bounded real-time ISR/DPC trace.
    fn capture(&mut self, window_ms: u32, event_cap: u64) -> Result<InterruptCapture>;
    /// `(base address, base file name)` for every loaded kernel driver,
    /// sorted ascending by base. Empty when enumeration is denied.
    fn driver_bases(&mut self) -> Vec<(u64, String)>;
    /// The version-resource `FileDescription` (or `CompanyName`) of a driver
    /// by base file name, e.g. `Microsoft Storage Port Driver`.
    fn driver_description(&mut self, base_name: &str) -> Option<String>;
}

/// Per-finding root-cause state: the latest evidence rows, the bounded ring
/// of successful captures, and the class of the current verdict (for the
/// recommendation sentence).
#[derive(Debug, Default)]
struct FindingState {
    rows: Vec<Evidence>,
    history: VecDeque<CaptureRecord>,
    class: Option<DeviceClass>,
    /// How settled this finding's attribution is, recomputed on every
    /// rebuild alongside the evidence rows.
    verdict: VerdictState,
    /// The last family this finding produced a verdict for that passed the
    /// confidence gate, so a later confident verdict for a different family
    /// is recognizable as a *change* rather than a first attribution.
    confident_family: Option<String>,
}

/// Holds the root-cause state per `dpcInterrupt` alert ID, the adaptive
/// capture cadence, and the device-activity ring. Mirrors
/// [`crate::metrics::forensics::ForensicsEngine`].
pub struct InterruptEngine<S> {
    source: S,
    findings: HashMap<String, FindingState>,
    /// Findings that just resolved survive exactly one extra pass so the
    /// resolution write-back keeps their final attribution state.
    stale: HashSet<String>,
    last_capture_ms: Option<i64>,
    last_capture_failed: bool,
    /// Recent device-activity window fed by the runtime on every sample —
    /// pure memory work, kept warm even with no finding active so the first
    /// verdict already has a correlation window behind it.
    activity: VecDeque<ActivityPoint>,
}

impl<S: InterruptSource> InterruptEngine<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            findings: HashMap::new(),
            stale: HashSet::new(),
            last_capture_ms: None,
            last_capture_failed: false,
            activity: VecDeque::new(),
        }
    }

    pub fn source(&self) -> &S {
        &self.source
    }

    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    /// Feeds one sample of the device-activity ring the correlation runs
    /// over. Called by the runtime on every sampling pass; performs no
    /// syscalls. `gpu_utilization_percent` is the freshest hardware-sampler
    /// GPU utilization, or `None` when NVML has nothing to say.
    pub fn record_activity(&mut self, system: &SystemMetric, gpu_utilization_percent: Option<f64>) {
        self.activity.push_back(ActivityPoint {
            timestamp_ms: system.timestamp_ms,
            interrupt_rate: system.interrupt_rate,
            dpc_rate: system.dpc_rate,
            disk_bytes_per_sec: system.disk_read_bytes_per_sec + system.disk_write_bytes_per_sec,
            disk_latency_ms: system.disk_latency_ms,
            network_bytes_per_sec: system.network_bytes_per_sec,
            gpu_utilization_percent,
        });
        let cutoff = system.timestamp_ms - ACTIVITY_WINDOW_MS;
        while self
            .activity
            .front()
            .is_some_and(|point| point.timestamp_ms < cutoff)
        {
            self.activity.pop_front();
        }
        while self.activity.len() > ACTIVITY_RING_CAP {
            self.activity.pop_front();
        }
    }

    /// Drives captures from the sampling cadence.
    ///
    /// With no active `dpcInterrupt` finding this returns before any source
    /// call — the engine is a strict no-op. While one is active, a capture
    /// runs when the finding first fires, then every
    /// [`FAST_CAPTURE_SPACING_MS`] until each active finding holds
    /// [`FAST_PHASE_CAPTURES`] successful captures, then every
    /// [`CAPTURE_COOLDOWN_MS`]. A failed capture arms the full cooldown
    /// exactly as before, so a denied session is not retried every two
    /// minutes. The capture itself blocks for up to [`CAPTURE_WINDOW_MS`];
    /// the sampling loop resumes afterwards.
    pub fn observe(&mut self, active: &[Alert], now_ms: i64) {
        let ids: HashSet<String> = active
            .iter()
            .filter(|alert| alert.kind == DPC_INTERRUPT_KIND)
            .map(|alert| alert.id.clone())
            .collect();
        // Grace pass: state for findings that resolved on the *previous* pass
        // is dropped now; findings resolving on this pass keep their final
        // rows for the resolution write-back.
        let stale = &self.stale;
        self.findings
            .retain(|id, _| ids.contains(id) || !stale.contains(id));
        self.stale = self
            .findings
            .keys()
            .filter(|id| !ids.contains(*id))
            .cloned()
            .collect();

        if ids.is_empty() {
            self.last_capture_ms = None;
            self.last_capture_failed = false;
            return;
        }
        let spacing = if self.last_capture_failed {
            CAPTURE_COOLDOWN_MS
        } else if ids.iter().any(|id| {
            self.findings
                .get(id)
                .is_none_or(|state| state.history.len() < FAST_PHASE_CAPTURES)
        }) {
            FAST_CAPTURE_SPACING_MS
        } else {
            CAPTURE_COOLDOWN_MS
        };
        let due = self
            .last_capture_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= spacing);
        let has_new = ids.iter().any(|id| !self.findings.contains_key(id));
        if !due && !has_new {
            return;
        }
        // The cadence counts from every capture attempt, including degraded
        // ones — a failing session must not be retried on every sample.
        self.last_capture_ms = Some(now_ms);
        match self.source.capture(CAPTURE_WINDOW_MS, EVENT_CAP) {
            Ok(capture) => {
                self.last_capture_failed = false;
                let (record, capture_rows) = self.build_capture(&capture, now_ms);
                for id in ids {
                    let state = self.findings.entry(id.clone()).or_default();
                    if let Some(record) = &record {
                        state.history.push_back(record.clone());
                        while state.history.len() > CAPTURE_HISTORY {
                            state.history.pop_front();
                        }
                    }
                    self.rebuild_rows(&id, &capture_rows);
                }
            }
            Err(error) => {
                self.last_capture_failed = true;
                let degraded = vec![evidence(
                    ATTRIBUTION_LABEL,
                    format!("capture degraded: {error:#}"),
                )];
                for id in ids {
                    self.findings.entry(id.clone()).or_default();
                    // A finding with earlier successful captures keeps its
                    // verdict; one with none keeps only the honest note.
                    self.rebuild_rows(&id, &degraded);
                }
            }
        }
    }

    /// Attaches the latest root-cause rows to matching alerts, replacing any
    /// rows already present so evidence never accumulates, and keeps the
    /// class recommendation sentence in sync on the recommendation text.
    pub fn decorate(&self, alerts: &mut [Alert]) {
        for alert in alerts.iter_mut() {
            if let Some(state) = self.findings.get(&alert.id) {
                alert
                    .evidence
                    .retain(|item| !INTERRUPT_LABELS.contains(&item.label.as_str()));
                alert.evidence.extend(state.rows.iter().cloned());
                apply_class_recommendation(&mut alert.recommendation, state.class);
            }
        }
    }

    /// Turns one raw capture into (successful attribution record, this
    /// capture's attribution/top-driver/window rows). The record is `None`
    /// for zero-event and undecodable captures, which therefore never enter
    /// a verdict history.
    fn build_capture(
        &mut self,
        capture: &InterruptCapture,
        now_ms: i64,
    ) -> (Option<CaptureRecord>, Vec<Evidence>) {
        let window = format_trace_window(capture);
        if capture.total_events() == 0 {
            return (
                None,
                vec![
                    evidence(ATTRIBUTION_LABEL, "no ISR/DPC events in the trace window".into()),
                    evidence(WINDOW_LABEL, window),
                ],
            );
        }
        let mut drivers = self.source.driver_bases();
        drivers.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let ranked = attribute_buckets(&capture.buckets, &drivers);
        let mut rows = vec![evidence(ATTRIBUTION_LABEL, format_shares(&ranked))];
        if let Some((name, _)) = ranked.iter().find(|(name, _)| name != UNATTRIBUTED) {
            let description = self.source.driver_description(name);
            rows.push(evidence(
                TOP_DRIVER_LABEL,
                format_top_driver(name, description.as_deref()),
            ));
        }
        rows.push(evidence(WINDOW_LABEL, window));
        let record = ranked_to_record(&ranked, capture, now_ms);
        (record, rows)
    }

    /// Rebuilds a finding's evidence rows: verdict triple first (whenever the
    /// finding has at least one successful capture), then the per-capture
    /// rows. With zero successful captures only the honest capture rows
    /// remain — no verdict is ever fabricated.
    fn rebuild_rows(&mut self, id: &str, capture_rows: &[Evidence]) {
        let history: Vec<CaptureRecord> = self
            .findings
            .get(id)
            .map(|state| state.history.iter().cloned().collect())
            .unwrap_or_default();
        // The device class of every driver that leads at least one capture,
        // so family agreement can be counted without asking the version
        // resource the same question twice.
        let mut families: HashMap<String, DeviceClass> = HashMap::new();
        for record in &history {
            if let Some(top) = record.top_driver()
                && !families.contains_key(top)
            {
                let description = self.source.driver_description(top);
                families.insert(
                    top.to_string(),
                    classify_driver(top, description.as_deref()),
                );
            }
        }
        let verdict = modal_candidate(&history).map(|candidate| {
            let description = self.source.driver_description(&candidate.driver);
            let class = classify_driver(&candidate.driver, description.as_deref());
            let correlation = class_correlation(&self.activity, class);
            let confidence = assess_confidence(
                candidate.consistent,
                candidate.captures,
                candidate.mean_share,
                candidate.margin,
                correlation.matched_r(),
            );
            // Family-level agreement, which is deliberately looser than the
            // rubric's driver-level `consistent`: two storage drivers taking
            // turns are one repeatable cause, not two rival ones.
            let agreement = history
                .iter()
                .filter(|record| {
                    record
                        .top_driver()
                        .and_then(|top| families.get(top))
                        .is_some_and(|top_class| *top_class == class)
                })
                .count();
            (
                candidate,
                description,
                class,
                correlation,
                confidence,
                agreement,
            )
        });
        let Some(state) = self.findings.get_mut(id) else {
            return;
        };
        let mut rows = Vec::with_capacity(6);
        state.class = None;
        state.verdict = VerdictState::NoCapture;
        if let Some((candidate, description, class, correlation, confidence, agreement)) = verdict {
            rows.push(evidence(
                LIKELY_CAUSE_LABEL,
                format_likely_cause(&candidate.driver, description.as_deref(), class),
            ));
            rows.push(evidence(
                CONFIDENCE_LABEL,
                format_confidence(confidence, &candidate),
            ));
            rows.push(evidence(CORRELATION_LABEL, format_correlation(&correlation)));
            state.class = Some(class);
            // Repeatable takes three things at once: enough captures naming
            // the family, a *majority* of the history behind it (so a
            // rotating leader can never accumulate its way to a verdict),
            // and the existing confidence rubric above its floor.
            let repeatable = agreement >= REPEATABLE_CAPTURES
                && agreement * 2 > history.len()
                && confidence != Confidence::Low;
            let family = class.as_str().to_string();
            state.verdict = if !repeatable {
                VerdictState::SingleCapture
            } else {
                match state.confident_family.replace(family.clone()) {
                    Some(previous) if previous != family => VerdictState::ChangedConfidently {
                        from: previous,
                        to: family,
                    },
                    _ => VerdictState::Repeatable {
                        driver_family: family,
                    },
                }
            };
        }
        rows.extend(capture_rows.iter().cloned());
        state.rows = rows;
    }

    /// How settled the live `dpcInterrupt` finding's attribution is -- what
    /// the notification policy gates on.
    ///
    /// The detector's engine key is the fixed string `dpcInterrupt`, so at
    /// most one finding is ever live; findings that resolved on this pass are
    /// excluded, and in the impossible case of several the best-evidenced one
    /// answers.
    pub fn verdict_state(&self) -> VerdictState {
        self.live_finding()
            .map_or(VerdictState::NoCapture, |state| state.verdict.clone())
    }

    /// Independent co-signals corroborating the live finding: a class-matched
    /// activity correlation at or above the rubric's floor is one. Pure
    /// memory work over the activity ring, like the rest of the correlation
    /// path.
    pub fn corroborating_signals(&self) -> u32 {
        let Some(class) = self.live_finding().and_then(|state| state.class) else {
            return 0;
        };
        u32::from(
            class_correlation(&self.activity, class)
                .matched_r()
                .is_some_and(|r| r >= CONFIDENCE_R_FLOOR),
        )
    }

    fn live_finding(&self) -> Option<&FindingState> {
        self.findings
            .iter()
            .filter(|(id, _)| !self.stale.contains(*id))
            .map(|(_, state)| state)
            .max_by_key(|state| state.history.len())
    }

    #[cfg(test)]
    fn debug_counts(&self) -> (usize, usize) {
        (self.findings.len(), self.stale.len())
    }
}

/// Converts ranked per-driver counts into a percentage [`CaptureRecord`];
/// `None` when nothing decoded (total zero), so undecodable captures never
/// feed the verdict.
fn ranked_to_record(
    ranked: &[(String, u64)],
    capture: &InterruptCapture,
    now_ms: i64,
) -> Option<CaptureRecord> {
    let total: u64 = ranked.iter().map(|(_, count)| count).sum();
    if total == 0 {
        return None;
    }
    let shares = ranked
        .iter()
        .map(|(name, count)| (name.clone(), *count as f64 * 100.0 / total as f64))
        .collect();
    Some(CaptureRecord {
        timestamp_ms: now_ms,
        shares,
        total_events: capture.total_events(),
        capped: capture.capped,
    })
}

/// Strips any previously appended class sentence, then appends the sentence
/// for the current class — idempotent across repeated decoration and stable
/// when the verdict's class changes.
fn apply_class_recommendation(recommendation: &mut String, class: Option<DeviceClass>) {
    for (_, sentence) in CLASS_RECOMMENDATIONS {
        if let Some(stripped) = recommendation.strip_suffix(sentence) {
            *recommendation = stripped.trim_end().to_string();
        }
    }
    if let Some(sentence) = class.and_then(class_recommendation) {
        if !recommendation.is_empty() && !recommendation.ends_with(' ') {
            recommendation.push(' ');
        }
        recommendation.push_str(sentence);
    }
}

fn evidence(label: &str, value: String) -> Evidence {
    Evidence {
        label: label.into(),
        value,
    }
}

/// Maps each bucket to the loaded driver with the greatest base at or below
/// the bucket address (drivers are contiguous from their base; without image
/// sizes the next driver's base is the boundary). Addresses below every base
/// are `unattributed`. Returns per-driver totals ranked largest first.
fn attribute_buckets(buckets: &HashMap<u64, u64>, drivers: &[(u64, String)]) -> Vec<(String, u64)> {
    let mut counts: HashMap<&str, u64> = HashMap::new();
    for (&address, &count) in buckets {
        let index = drivers.partition_point(|(base, _)| *base <= address);
        let name = if index == 0 {
            UNATTRIBUTED
        } else {
            drivers[index - 1].1.as_str()
        };
        *counts.entry(name).or_insert(0) += count;
    }
    let mut ranked: Vec<(String, u64)> = counts
        .into_iter()
        .map(|(name, count)| (name.to_string(), count))
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked
}

/// Top three shares, largest first, e.g.
/// `storport.sys 41% · ndis.sys 27% · nvlddmkm.sys 12%`.
fn format_shares(ranked: &[(String, u64)]) -> String {
    let total: u64 = ranked.iter().map(|(_, count)| count).sum();
    if total == 0 {
        // Events arrived but no routine address could be decoded — the MOF
        // layout did not match; degrade honestly rather than guess.
        return "routine addresses could not be decoded".into();
    }
    ranked
        .iter()
        .take(3)
        .map(|(name, count)| {
            let percent = (count * 100 + total / 2) / total;
            let name = truncate_value(name, 24);
            if percent == 0 {
                format!("{name} <1%")
            } else {
                format!("{name} {percent}%")
            }
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// `storport.sys — Microsoft Storage Port Driver`, bounded for the TUI.
fn format_top_driver(name: &str, description: Option<&str>) -> String {
    match description {
        Some(description) => truncate_value(&format!("{name} — {description}"), MAX_VALUE_CHARS),
        None => name.to_string(),
    }
}

/// `nvlddmkm.sys — NVIDIA Windows Kernel Mode Driver [gpu]`, truncating the
/// description part so the class tag always survives within the value bound.
fn format_likely_cause(name: &str, description: Option<&str>, class: DeviceClass) -> String {
    let suffix = format!(" [{}]", class.as_str());
    let base = match description {
        Some(description) => format!("{name} — {description}"),
        None => name.to_string(),
    };
    let mut value = truncate_value(&base, MAX_VALUE_CHARS.saturating_sub(suffix.chars().count()));
    value.push_str(&suffix);
    value
}

/// `high — top in 4/4 traces · 58% mean share`.
fn format_confidence(confidence: Confidence, candidate: &VerdictCandidate) -> String {
    truncate_value(
        &format!(
            "{} — top in {}/{} traces · {:.0}% mean share",
            confidence.as_str(),
            candidate.consistent,
            candidate.captures,
            candidate.mean_share
        ),
        MAX_VALUE_CHARS,
    )
}

/// `gpu activity r=0.81 over 5 m`, or the honest `insufficient signal`.
fn format_correlation(outcome: &CorrelationOutcome) -> String {
    match outcome {
        CorrelationOutcome::Measured { series, r, span_ms } => truncate_value(
            &format!("{series} r={r:.2} over {}", format_span(*span_ms)),
            MAX_VALUE_CHARS,
        ),
        CorrelationOutcome::Insufficient => INSUFFICIENT_SIGNAL.into(),
    }
}

/// `5 m` at minute scale, `45 s` below it.
fn format_span(span_ms: i64) -> String {
    if span_ms >= 60_000 {
        format!("{} m", (span_ms + 30_000) / 60_000)
    } else {
        format!("{} s", (span_ms.max(0) + 500) / 1_000)
    }
}

/// `8 s · 214k events`, with `(capped)` when the storm guard stopped early.
fn format_trace_window(capture: &InterruptCapture) -> String {
    let seconds = if capture.window_ms.is_multiple_of(1_000) {
        format!("{} s", capture.window_ms / 1_000)
    } else {
        format!("{:.1} s", f64::from(capture.window_ms) / 1_000.0)
    };
    let suffix = if capture.capped { " (capped)" } else { "" };
    format!(
        "{seconds} · {} events{suffix}",
        format_event_count(capture.total_events())
    )
}

fn format_event_count(count: u64) -> String {
    if count < 1_000 {
        count.to_string()
    } else if count < 1_000_000 {
        format!("{}k", count / 1_000)
    } else {
        format!("{:.1}M", count as f64 / 1_000_000.0)
    }
}

fn truncate_value(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        let mut kept: String = value.chars().take(max_chars.saturating_sub(1)).collect();
        kept.push('…');
        kept
    }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

/// Unique session name; deliberately not the NT Kernel Logger, so the
/// collector's process-lifecycle session is never disturbed.
const SESSION_NAME: &str = "PcPulseIsrDpc";
/// Classic kernel `PerfInfo` MOF class GUID; ISR and DPC events arrive under
/// it in a system logger session.
const PERFINFO_GUID: GUID = GUID::from_u128(0xce1dbfb4_137e_4da6_87b0_3f59aa102cbc);
/// `PERFINFO_LOG_TYPE_*` opcodes for the PerfInfo class.
const OPCODE_THREADED_DPC: u8 = 66;
const OPCODE_ISR: u8 = 67;
const OPCODE_DPC: u8 = 68;
const OPCODE_TIMER_DPC: u8 = 69;

struct CaptureState {
    cap: u64,
    processed: AtomicU64,
    isr: AtomicU64,
    dpc: AtomicU64,
    capped: AtomicBool,
    buckets: Mutex<HashMap<u64, u64>>,
}

/// Consumer callback: minimal work per event. For PerfInfo ISR/DPC events the
/// MOF payload starts with `InitialTime` (8 bytes) followed by the
/// pointer-sized `Routine` address — the layout the probe harness verifies
/// empirically against this machine's loaded-driver ranges.
unsafe extern "system" fn capture_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    unsafe {
        let event = &*record;
        let Some(state) = (event.UserContext as *const CaptureState).as_ref() else {
            return;
        };
        let processed = state.processed.fetch_add(1, Ordering::Relaxed) + 1;
        if processed > state.cap {
            state.capped.store(true, Ordering::Release);
            return;
        }
        if event.EventHeader.ProviderId != PERFINFO_GUID {
            return;
        }
        let opcode = event.EventHeader.EventDescriptor.Opcode;
        let is_isr = opcode == OPCODE_ISR;
        let is_dpc = matches!(opcode, OPCODE_DPC | OPCODE_TIMER_DPC | OPCODE_THREADED_DPC);
        if !is_isr && !is_dpc {
            return;
        }
        if is_isr {
            state.isr.fetch_add(1, Ordering::Relaxed);
        } else {
            state.dpc.fetch_add(1, Ordering::Relaxed);
        }
        let pointer_bytes: usize =
            if u32::from(event.EventHeader.Flags) & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
                4
            } else {
                8
            };
        if event.UserData.is_null() || usize::from(event.UserDataLength) < 8 + pointer_bytes {
            return;
        }
        let routine = if pointer_bytes == 4 {
            u64::from(ptr::read_unaligned(
                event.UserData.cast::<u8>().add(8).cast::<u32>(),
            ))
        } else {
            ptr::read_unaligned(event.UserData.cast::<u8>().add(8).cast::<u64>())
        };
        if routine == 0 {
            return;
        }
        // Single consumer thread: the mutex is uncontended during the trace.
        if let Ok(mut buckets) = state.buckets.lock() {
            *buckets.entry(routine & BUCKET_MASK).or_insert(0) += 1;
        }
    }
}

fn session_properties(name: &[u16]) -> Vec<u64> {
    let property_bytes = size_of::<EVENT_TRACE_PROPERTIES>();
    let name_bytes = std::mem::size_of_val(name);
    let total_bytes = property_bytes + name_bytes;
    let mut buffer = vec![0u64; total_bytes.div_ceil(size_of::<u64>())];
    let properties = unsafe { &mut *buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>() };
    properties.Wnode.BufferSize = total_bytes as u32;
    properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties.Wnode.ClientContext = 1;
    properties.BufferSize = 64; // KiB per ETW buffer; sized for interrupt storms.
    properties.MinimumBuffers = 4;
    properties.MaximumBuffers = 12;
    properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    properties.EnableFlags =
        EVENT_TRACE_FLAG(EVENT_TRACE_FLAG_INTERRUPT.0 | EVENT_TRACE_FLAG_DPC.0);
    properties.FlushTimer = 1;
    properties.LoggerNameOffset = property_bytes as u32;
    unsafe {
        ptr::copy_nonoverlapping(
            name.as_ptr().cast::<u8>(),
            buffer.as_mut_ptr().cast::<u8>().add(property_bytes),
            name_bytes,
        );
    }
    buffer
}

/// Owns the short-lived system logger session; `stop` is idempotent and runs
/// on drop, so every error path tears the session down deterministically.
struct SystemLoggerSession {
    control: CONTROLTRACE_HANDLE,
    name: Vec<u16>,
    stopped: bool,
}

impl SystemLoggerSession {
    fn start() -> Result<Self> {
        let name: Vec<u16> = SESSION_NAME.encode_utf16().chain(Some(0)).collect();
        for attempt in 0..2 {
            let mut properties = session_properties(&name);
            let mut control = CONTROLTRACE_HANDLE::default();
            let status = unsafe {
                StartTraceW(
                    &mut control,
                    PCWSTR(name.as_ptr()),
                    properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
                )
            };
            if status == ERROR_SUCCESS {
                return Ok(Self {
                    control,
                    name,
                    stopped: false,
                });
            }
            if status == ERROR_ALREADY_EXISTS && attempt == 0 {
                // A crashed capture left a stale session behind: stop it by
                // name (handle 0 + name is valid for STOP) and retry once.
                let mut stop_properties = session_properties(&name);
                unsafe {
                    let _ = ControlTraceW(
                        CONTROLTRACE_HANDLE::default(),
                        PCWSTR(name.as_ptr()),
                        stop_properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
                        EVENT_TRACE_CONTROL_STOP,
                    );
                }
                continue;
            }
            if status == ERROR_ACCESS_DENIED {
                bail!("system logger denied; ISR/DPC capture needs the elevated collector");
            }
            bail!("system logger start failed (0x{:08x})", status.0);
        }
        bail!("system logger name stayed busy after stale-session cleanup");
    }

    fn stop(&mut self) -> WIN32_ERROR {
        if self.stopped {
            return ERROR_SUCCESS;
        }
        self.stopped = true;
        let mut properties = session_properties(&self.name);
        unsafe {
            ControlTraceW(
                self.control,
                PCWSTR(self.name.as_ptr()),
                properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
                EVENT_TRACE_CONTROL_STOP,
            )
        }
    }
}

impl Drop for SystemLoggerSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// The real syscall layer. Tracks session/trace balance counters so the probe
/// harness can assert that every capture stops its session and closes its
/// processing handle in the same pass.
#[derive(Default)]
pub struct WindowsInterruptSource {
    /// Base file name (lowercased) -> raw kernel path from the last
    /// enumeration, for version-resource lookups.
    file_paths: HashMap<String, String>,
    descriptions: HashMap<String, Option<String>>,
    sessions_started: u64,
    sessions_stopped: u64,
    traces_opened: u64,
    traces_closed: u64,
}

impl WindowsInterruptSource {
    /// `(sessions started, sessions stopped, traces opened, traces closed)`;
    /// pairs are equal when the per-capture discipline holds.
    pub fn session_balance(&self) -> (u64, u64, u64, u64) {
        (
            self.sessions_started,
            self.sessions_stopped,
            self.traces_opened,
            self.traces_closed,
        )
    }
}

impl InterruptSource for WindowsInterruptSource {
    fn capture(&mut self, window_ms: u32, event_cap: u64) -> Result<InterruptCapture> {
        let mut session = SystemLoggerSession::start()?;
        self.sessions_started += 1;
        // Field report (v1.9.0): three fast-phase captures left ~30 MB of
        // heap residue from ETW consumer processing and tripped the
        // collector's 25 MB budget — the same disease the forensics
        // captures had in v1.7.1. Trim the working set on every exit path
        // once a session has actually run.
        struct TrimGuard;
        impl Drop for TrimGuard {
            fn drop(&mut self) {
                crate::metrics::forensics::trim_working_set();
            }
        }
        let _trim = TrimGuard;
        let state = Arc::new(CaptureState {
            cap: event_cap,
            processed: AtomicU64::new(0),
            isr: AtomicU64::new(0),
            dpc: AtomicU64::new(0),
            capped: AtomicBool::new(false),
            buckets: Mutex::new(HashMap::new()),
        });
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(session.name.as_ptr() as *mut u16),
            Anonymous1: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
            },
            Anonymous2: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(capture_callback),
            },
            // `state` outlives the consumer thread join below, so a borrowed
            // pointer is sound here (unlike the process-lifetime session in
            // `crate::etw`, nothing needs to leak).
            Context: Arc::as_ptr(&state) as *mut c_void,
            ..Default::default()
        };
        let processing = unsafe { OpenTraceW(&mut logfile) };
        if processing == PROCESSTRACE_HANDLE::default() || processing.Value == u64::MAX {
            let _ = session.stop();
            self.sessions_stopped += 1;
            bail!("OpenTraceW failed for the ISR/DPC consumer");
        }
        self.traces_opened += 1;
        let processing_value = processing.Value;
        let consumer = thread::Builder::new()
            .name("pcpulse-isrdpc".into())
            .spawn(move || unsafe {
                // The callback burst during a storm is real CPU; keep it from
                // competing with foreground work.
                let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
                let handle = PROCESSTRACE_HANDLE {
                    Value: processing_value,
                };
                let _ = ProcessTrace(&[handle], None, None);
                let _ = CloseTrace(handle);
            });
        let consumer = match consumer {
            Ok(consumer) => consumer,
            Err(error) => {
                unsafe {
                    let _ = CloseTrace(processing);
                }
                self.traces_closed += 1;
                let _ = session.stop();
                self.sessions_stopped += 1;
                bail!("ISR/DPC consumer thread failed to spawn: {error}");
            }
        };
        let started = Instant::now();
        let window = Duration::from_millis(u64::from(window_ms));
        while started.elapsed() < window && !state.capped.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(100));
        }
        let capped = state.capped.load(Ordering::Acquire);
        let elapsed_ms = if capped {
            u32::try_from(started.elapsed().as_millis()).unwrap_or(window_ms)
        } else {
            window_ms
        };
        // Stopping the session makes ProcessTrace drain and return; the
        // consumer then closes its own processing handle.
        let stop_status = session.stop();
        self.sessions_stopped += 1;
        let joined = consumer.join();
        self.traces_closed += 1;
        if joined.is_err() {
            bail!("ISR/DPC consumer thread panicked");
        }
        if stop_status != ERROR_SUCCESS {
            bail!("system logger stop failed (0x{:08x})", stop_status.0);
        }
        let buckets = state
            .buckets
            .lock()
            .map(|buckets| buckets.clone())
            .unwrap_or_default();
        Ok(InterruptCapture {
            window_ms: elapsed_ms,
            isr_events: state.isr.load(Ordering::Relaxed),
            dpc_events: state.dpc.load(Ordering::Relaxed),
            buckets,
            capped,
        })
    }

    fn driver_bases(&mut self) -> Vec<(u64, String)> {
        let mut bases: Vec<*mut c_void> = vec![ptr::null_mut(); 1_024];
        loop {
            let capacity_bytes = (bases.len() * size_of::<*mut c_void>()) as u32;
            let mut needed = 0u32;
            if unsafe { EnumDeviceDrivers(bases.as_mut_ptr(), capacity_bytes, &mut needed) }
                .is_err()
            {
                return Vec::new();
            }
            let count = needed as usize / size_of::<*mut c_void>();
            if needed <= capacity_bytes {
                bases.truncate(count);
                break;
            }
            bases.resize(count + 64, ptr::null_mut());
        }
        self.file_paths.clear();
        let mut ranges = Vec::with_capacity(bases.len());
        for base in bases {
            if base.is_null() {
                continue;
            }
            let mut name = [0u16; 64];
            let length = unsafe { K32GetDeviceDriverBaseNameW(base, &mut name) } as usize;
            if length == 0 {
                continue;
            }
            let base_name = String::from_utf16_lossy(&name[..length.min(name.len())]);
            let mut path = [0u16; 260];
            let path_length = unsafe { K32GetDeviceDriverFileNameW(base, &mut path) } as usize;
            if path_length > 0 {
                self.file_paths.insert(
                    base_name.to_ascii_lowercase(),
                    String::from_utf16_lossy(&path[..path_length.min(path.len())]),
                );
            }
            ranges.push((base as u64, base_name));
        }
        ranges.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        ranges
    }

    fn driver_description(&mut self, base_name: &str) -> Option<String> {
        let key = base_name.to_ascii_lowercase();
        if let Some(cached) = self.descriptions.get(&key) {
            return cached.clone();
        }
        let described = self
            .file_paths
            .get(&key)
            .map(|raw| normalize_driver_path(raw))
            .and_then(|path| file_description(&path));
        self.descriptions.insert(key, described.clone());
        described
    }
}

/// Kernel image paths arrive as `\SystemRoot\...`, `\??\C:\...`, or bare
/// `System32\...`; normalize to a Win32 path the version APIs accept.
fn normalize_driver_path(raw: &str) -> String {
    let system_root =
        std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with(r"\systemroot") {
        format!("{system_root}{}", &raw[r"\SystemRoot".len()..])
    } else if lower.starts_with(r"\??\") {
        raw[r"\??\".len()..].to_string()
    } else if lower.starts_with(r"system32\") {
        format!(r"{system_root}\{raw}")
    } else {
        raw.to_string()
    }
}

/// Version-resource `FileDescription` (preferred) or `CompanyName` of a
/// driver image, tried across the file's declared translations plus the
/// common US-English fallbacks.
fn file_description(path: &str) -> Option<String> {
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None) };
    if size == 0 {
        return None;
    }
    let mut data = vec![0u8; size as usize];
    unsafe { GetFileVersionInfoW(PCWSTR(wide.as_ptr()), None, size, data.as_mut_ptr().cast()) }
        .ok()?;
    let mut translations = version_translations(&data);
    translations.push((0x0409, 0x04B0));
    translations.push((0x0409, 0x04E4));
    for field in ["FileDescription", "CompanyName"] {
        for (language, codepage) in &translations {
            let sub_block = format!("\\StringFileInfo\\{language:04x}{codepage:04x}\\{field}");
            if let Some(value) = query_version_string(&data, &sub_block) {
                return Some(value);
            }
        }
    }
    None
}

fn version_translations(data: &[u8]) -> Vec<(u16, u16)> {
    let sub_block: Vec<u16> = r"\VarFileInfo\Translation"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut value_ptr: *mut c_void = ptr::null_mut();
    let mut value_len = 0u32;
    let ok = unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            PCWSTR(sub_block.as_ptr()),
            &mut value_ptr,
            &mut value_len,
        )
    };
    if !ok.as_bool() || value_ptr.is_null() {
        return Vec::new();
    }
    let pair_count = value_len as usize / size_of::<u32>();
    (0..pair_count)
        .map(|index| unsafe {
            let entry = ptr::read_unaligned(value_ptr.cast::<u32>().add(index));
            ((entry & 0xFFFF) as u16, (entry >> 16) as u16)
        })
        .collect()
}

fn query_version_string(data: &[u8], sub_block: &str) -> Option<String> {
    let wide: Vec<u16> = sub_block.encode_utf16().chain(Some(0)).collect();
    let mut value_ptr: *mut c_void = ptr::null_mut();
    let mut value_len = 0u32;
    let ok = unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            PCWSTR(wide.as_ptr()),
            &mut value_ptr,
            &mut value_len,
        )
    };
    if !ok.as_bool() || value_ptr.is_null() || value_len == 0 {
        return None;
    }
    let chars =
        unsafe { std::slice::from_raw_parts(value_ptr.cast::<u16>(), value_len as usize) };
    let text = String::from_utf16_lossy(chars)
        .trim_end_matches('\0')
        .trim()
        .to_string();
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    fn dpc_alert(id: &str) -> Alert {
        Alert {
            id: id.into(),
            kind: DPC_INTERRUPT_KIND.into(),
            severity: Severity::Warning,
            first_seen_ms: 0,
            last_seen_ms: 0,
            process_id: None,
            process_name: None,
            title: "High DPC or interrupt activity".into(),
            explanation: String::new(),
            evidence: vec![
                Evidence {
                    label: "DPC rate".into(),
                    value: "42000/s".into(),
                },
                Evidence {
                    label: "Interrupt rate".into(),
                    value: "18000/s".into(),
                },
            ],
            recommendation: String::new(),
            acknowledged: false,
            occurrence_count: 1,
            resolved_at_ms: None,
            archived: false,
            fingerprint: String::new(),
            state: crate::models::IncidentState::Open,
            quality: crate::models::AlertQuality::default(),
            notify: true,
            notify_generation: 0,
        }
    }

    fn other_alert(id: &str, kind: &str) -> Alert {
        Alert {
            kind: kind.into(),
            ..dpc_alert(id)
        }
    }

    fn capture(buckets: &[(u64, u64)]) -> InterruptCapture {
        InterruptCapture {
            window_ms: 8_000,
            isr_events: buckets.iter().map(|(_, count)| count).sum::<u64>() / 4,
            dpc_events: buckets.iter().map(|(_, count)| count).sum::<u64>()
                - buckets.iter().map(|(_, count)| count).sum::<u64>() / 4,
            buckets: buckets.iter().copied().collect(),
            capped: false,
        }
    }

    #[derive(Default)]
    struct StubSource {
        capture_calls: usize,
        driver_calls: usize,
        capture: InterruptCapture,
        drivers: Vec<(u64, String)>,
        descriptions: HashMap<String, String>,
        fail_capture: bool,
    }

    impl InterruptSource for StubSource {
        fn capture(&mut self, window_ms: u32, _event_cap: u64) -> Result<InterruptCapture> {
            self.capture_calls += 1;
            if self.fail_capture {
                bail!("system logger denied; ISR/DPC capture needs the elevated collector");
            }
            let mut capture = self.capture.clone();
            if capture.window_ms == 0 {
                capture.window_ms = window_ms;
            }
            Ok(capture)
        }

        fn driver_bases(&mut self) -> Vec<(u64, String)> {
            self.driver_calls += 1;
            self.drivers.clone()
        }

        fn driver_description(&mut self, base_name: &str) -> Option<String> {
            self.descriptions.get(base_name).cloned()
        }
    }

    fn drivers(pairs: &[(u64, &str)]) -> Vec<(u64, String)> {
        pairs
            .iter()
            .map(|(base, name)| (*base, (*name).to_string()))
            .collect()
    }

    #[test]
    fn no_finding_means_no_source_calls() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.observe(&[], 0);
        engine.observe(&[other_alert("a", "handleGrowth")], 2_000);
        engine.observe(&[other_alert("b", "kernelPoolGrowth")], 4_000);
        assert_eq!(engine.source().capture_calls, 0);
        assert_eq!(engine.source().driver_calls, 0);
    }

    #[test]
    fn adaptive_cadence_runs_a_fast_phase_then_backs_off() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().capture = capture(&[(0xFFFF_F800_0001_0000, 100)]);
        engine.source_mut().drivers = drivers(&[(0xFFFF_F800_0000_0000, "storport.sys")]);
        let alerts = [dpc_alert("d1")];
        engine.observe(&alerts, 0);
        assert_eq!(engine.source().capture_calls, 1, "captures when it fires");
        engine.observe(&alerts, 60_000);
        assert_eq!(engine.source().capture_calls, 1, "fast spacing holds at one minute");
        engine.observe(&alerts, 2 * 60_000);
        assert_eq!(engine.source().capture_calls, 2, "second trace two minutes in");
        engine.observe(&alerts, 3 * 60_000);
        assert_eq!(engine.source().capture_calls, 2, "fast spacing still two minutes");
        engine.observe(&alerts, 4 * 60_000);
        assert_eq!(engine.source().capture_calls, 3, "third trace completes the fast phase");
        engine.observe(&alerts, 6 * 60_000);
        engine.observe(&alerts, 13 * 60_000);
        assert_eq!(engine.source().capture_calls, 3, "backed off to the ten-minute cooldown");
        engine.observe(&alerts, 14 * 60_000);
        assert_eq!(engine.source().capture_calls, 4, "recaptures after ten minutes");
        // Resolution: rows survive exactly one grace pass, then clear.
        engine.observe(&[], 15 * 60_000);
        assert_eq!(engine.debug_counts(), (1, 1), "final rows kept for write-back");
        engine.observe(&[], 16 * 60_000);
        assert_eq!(engine.debug_counts(), (0, 0), "grace pass expired");
        // A refire is a new alert ID: it captures immediately and re-enters
        // the fast phase with an empty history of its own.
        engine.observe(&[dpc_alert("d2")], 17 * 60_000);
        assert_eq!(engine.source().capture_calls, 5);
        engine.observe(&[dpc_alert("d2")], 19 * 60_000);
        assert_eq!(engine.source().capture_calls, 6, "fresh finding is in the fast phase");
    }

    #[test]
    fn a_new_finding_joining_reenters_the_fast_phase() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().capture = capture(&[(0xFFFF_F800_0001_0000, 100)]);
        engine.source_mut().drivers = drivers(&[(0xFFFF_F800_0000_0000, "storport.sys")]);
        let first = [dpc_alert("d1")];
        for now in [0, 2 * 60_000, 4 * 60_000] {
            engine.observe(&first, now);
        }
        assert_eq!(engine.source().capture_calls, 3, "d1 finished its fast phase");
        // d2 fires: an immediate capture despite the backoff, and the next
        // spacing is the fast two minutes because d2's history is short.
        let both = [dpc_alert("d1"), dpc_alert("d2")];
        engine.observe(&both, 5 * 60_000);
        assert_eq!(engine.source().capture_calls, 4, "new finding captures immediately");
        engine.observe(&both, 7 * 60_000);
        assert_eq!(engine.source().capture_calls, 5, "fast spacing for the new finding");
    }

    #[test]
    fn capture_history_ring_is_bounded_per_finding() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().capture = capture(&[(0xFFFF_F800_0001_0000, 100)]);
        engine.source_mut().drivers = drivers(&[(0xFFFF_F800_0000_0000, "storport.sys")]);
        let alerts = [dpc_alert("d1")];
        let mut now = 0;
        for _ in 0..12 {
            engine.observe(&alerts, now);
            now += CAPTURE_COOLDOWN_MS;
        }
        assert_eq!(engine.source().capture_calls, 12);
        let state = engine.findings.get("d1").expect("finding state");
        assert_eq!(state.history.len(), CAPTURE_HISTORY, "ring keeps the last eight");
        assert_eq!(
            state.history.front().map(|record| record.timestamp_ms),
            Some(4 * CAPTURE_COOLDOWN_MS),
            "oldest surviving record is the fifth capture"
        );
    }

    #[test]
    fn buckets_map_to_nearest_driver_at_or_below() {
        let map = drivers(&[
            (0x4000_0000, "ntoskrnl.exe"),
            (0x9000_0000, "storport.sys"),
            (0xC000_0000, "ndis.sys"),
        ]);
        let buckets: HashMap<u64, u64> = [
            (0x1000_0000, 7),  // below every base -> unattributed
            (0xA000_0000, 40), // between storport and ndis -> nearest below
            (0x9000_0000, 2),  // exactly at a base
            (0xF000_0000, 10), // above the highest base -> last driver
        ]
        .into();
        let ranked = attribute_buckets(&buckets, &map);
        assert_eq!(
            ranked,
            vec![
                ("storport.sys".to_string(), 42),
                ("ndis.sys".to_string(), 10),
                (UNATTRIBUTED.to_string(), 7),
            ]
        );
    }

    #[test]
    fn shares_format_ranks_and_truncates_to_three() {
        let ranked = vec![
            ("storport.sys".to_string(), 41_u64),
            ("ndis.sys".to_string(), 27),
            ("nvlddmkm.sys".to_string(), 12),
            ("acpi.sys".to_string(), 11),
            ("hal.dll".to_string(), 9),
        ];
        assert_eq!(
            format_shares(&ranked),
            "storport.sys 41% · ndis.sys 27% · nvlddmkm.sys 12%"
        );
        assert!(format_shares(&ranked).chars().count() <= MAX_VALUE_CHARS);
        assert_eq!(
            format_shares(&[("a.sys".to_string(), 100_000), ("b.sys".to_string(), 1)]),
            "a.sys 100% · b.sys <1%"
        );
        assert_eq!(format_shares(&[]), "routine addresses could not be decoded");
        assert_eq!(
            format_top_driver("storport.sys", Some("Microsoft Storage Port Driver")),
            "storport.sys — Microsoft Storage Port Driver"
        );
        assert!(
            format_top_driver("nvlddmkm.sys", Some(&"x".repeat(200)))
                .chars()
                .count()
                <= MAX_VALUE_CHARS
        );
        assert_eq!(format_top_driver("ndis.sys", None), "ndis.sys");
    }

    #[test]
    fn trace_window_formats_events_and_storm_cap() {
        let mut sample = capture(&[(0xFFFF_0000, 214_231)]);
        assert_eq!(format_trace_window(&sample), "8 s · 214k events");
        sample.capped = true;
        sample.window_ms = 5_200;
        assert_eq!(format_trace_window(&sample), "5.2 s · 214k events (capped)");
        assert_eq!(format_event_count(999), "999");
        assert_eq!(format_event_count(1_500_000), "1.5M");
    }

    #[test]
    fn storm_cap_reaches_evidence_as_a_note() {
        let mut engine = InterruptEngine::new(StubSource::default());
        let mut capped = capture(&[(0xFFFF_F800_0001_0000, 400_000)]);
        capped.capped = true;
        capped.window_ms = 3_100;
        engine.source_mut().capture = capped;
        engine.source_mut().drivers = drivers(&[(0xFFFF_F800_0000_0000, "storport.sys")]);
        let mut alerts = [dpc_alert("d1")];
        engine.observe(&alerts, 0);
        engine.decorate(&mut alerts);
        let window = alerts[0]
            .evidence
            .iter()
            .find(|item| item.label == WINDOW_LABEL)
            .map(|item| item.value.as_str());
        assert_eq!(window, Some("3.1 s · 400k events (capped)"));
    }

    #[test]
    fn evidence_rows_are_replaced_not_accumulated() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().capture = capture(&[(0xFFFF_F800_0001_0000, 100)]);
        engine.source_mut().drivers = drivers(&[(0xFFFF_F800_0000_0000, "storport.sys")]);
        engine
            .source_mut()
            .descriptions
            .insert("storport.sys".into(), "Microsoft Storage Port Driver".into());
        let mut alerts = [dpc_alert("d1")];
        // Simulate a stale attribution row arriving from persisted state.
        alerts[0].evidence.push(Evidence {
            label: ATTRIBUTION_LABEL.into(),
            value: "ndis.sys 99%".into(),
        });
        engine.observe(&alerts, 0);
        engine.decorate(&mut alerts);
        engine.decorate(&mut alerts);
        engine.decorate(&mut alerts);
        let attribution_rows: Vec<&Evidence> = alerts[0]
            .evidence
            .iter()
            .filter(|item| item.label == ATTRIBUTION_LABEL)
            .collect();
        assert_eq!(attribution_rows.len(), 1, "replaced, not appended");
        assert_eq!(attribution_rows[0].value, "storport.sys 100%");
        let top: Vec<&Evidence> = alerts[0]
            .evidence
            .iter()
            .filter(|item| item.label == TOP_DRIVER_LABEL)
            .collect();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].value, "storport.sys — Microsoft Storage Port Driver");
        // The detector's own rows are untouched.
        assert!(alerts[0].evidence.iter().any(|item| item.label == "DPC rate"));
        assert!(
            alerts[0]
                .evidence
                .iter()
                .all(|item| item.value.chars().count() <= MAX_VALUE_CHARS)
        );
    }

    #[test]
    fn degraded_capture_is_surfaced_as_evidence_and_respects_cooldown() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().fail_capture = true;
        let mut alerts = [dpc_alert("d1")];
        engine.observe(&alerts, 0);
        engine.observe(&alerts, 2_000);
        engine.observe(&alerts, 4_000);
        assert_eq!(
            engine.source().capture_calls,
            1,
            "a failing session is not retried on every sample"
        );
        // Failure arms the full ten-minute cooldown, never the fast spacing.
        engine.observe(&alerts, FAST_CAPTURE_SPACING_MS);
        assert_eq!(engine.source().capture_calls, 1, "no fast retry after a failure");
        engine.observe(&alerts, CAPTURE_COOLDOWN_MS);
        assert_eq!(engine.source().capture_calls, 2, "retried after the cooldown");
        engine.decorate(&mut alerts);
        let attribution = alerts[0]
            .evidence
            .iter()
            .find(|item| item.label == ATTRIBUTION_LABEL)
            .map(|item| item.value.as_str())
            .unwrap_or_default();
        assert!(attribution.contains("capture degraded"));
        assert!(attribution.contains("elevated collector"));
        // Never fabricate: zero successful captures means no verdict rows
        // and no class sentence on the recommendation.
        for label in [LIKELY_CAUSE_LABEL, CONFIDENCE_LABEL, CORRELATION_LABEL] {
            assert!(
                !alerts[0].evidence.iter().any(|item| item.label == label),
                "no {label} row without a successful capture"
            );
        }
        assert!(alerts[0].recommendation.is_empty(), "no class sentence appended");
    }

    #[test]
    fn a_failed_recapture_keeps_the_verdict_from_earlier_traces() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().capture = capture(&[(0xFFFF_F800_0001_0000, 100)]);
        engine.source_mut().drivers = drivers(&[(0xFFFF_F800_0000_0000, "storport.sys")]);
        let mut alerts = [dpc_alert("d1")];
        for now in [0, 2 * 60_000, 4 * 60_000] {
            engine.observe(&alerts, now);
        }
        engine.source_mut().fail_capture = true;
        engine.observe(&alerts, 14 * 60_000);
        engine.decorate(&mut alerts);
        let likely = alerts[0]
            .evidence
            .iter()
            .find(|item| item.label == LIKELY_CAUSE_LABEL)
            .expect("verdict survives a degraded recapture");
        assert!(likely.value.contains("storport.sys"));
        let attribution = alerts[0]
            .evidence
            .iter()
            .find(|item| item.label == ATTRIBUTION_LABEL)
            .expect("attribution row");
        assert!(attribution.value.contains("capture degraded"));
    }

    #[test]
    fn zero_event_capture_is_honest() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().capture = capture(&[]);
        let mut alerts = [dpc_alert("d1")];
        engine.observe(&alerts, 0);
        engine.decorate(&mut alerts);
        let attribution = alerts[0]
            .evidence
            .iter()
            .find(|item| item.label == ATTRIBUTION_LABEL)
            .map(|item| item.value.as_str());
        assert_eq!(attribution, Some("no ISR/DPC events in the trace window"));
        assert!(
            !alerts[0].evidence.iter().any(|item| item.label == TOP_DRIVER_LABEL),
            "no top-driver row without events"
        );
        assert_eq!(
            engine.source().driver_calls,
            0,
            "no driver enumeration without events"
        );
        // An empty trace is not a successful attribution: no verdict rows.
        for label in [LIKELY_CAUSE_LABEL, CONFIDENCE_LABEL, CORRELATION_LABEL] {
            assert!(
                !alerts[0].evidence.iter().any(|item| item.label == label),
                "no {label} row for an empty trace"
            );
        }
    }

    fn activity_sample(timestamp_ms: i64) -> SystemMetric {
        SystemMetric {
            timestamp_ms,
            interrupt_rate: 10_000.0,
            dpc_rate: 4_000.0,
            disk_read_bytes_per_sec: 1_000_000.0,
            disk_write_bytes_per_sec: 500_000.0,
            disk_latency_ms: 1.0,
            network_bytes_per_sec: 100_000.0,
            ..SystemMetric::default()
        }
    }

    /// Feeds a five-minute window where the interrupt rate tracks GPU
    /// utilization (and nothing else varies).
    fn feed_gpu_correlated_activity<S: InterruptSource>(engine: &mut InterruptEngine<S>) {
        for index in 0..150_i64 {
            let utilization = (index % 50) as f64 * 2.0;
            let mut sample = activity_sample(index * 2_000);
            sample.interrupt_rate = 10_000.0 + utilization * 100.0;
            engine.record_activity(&sample, Some(utilization));
        }
    }

    #[test]
    fn activity_ring_is_bounded_by_window_and_cap() {
        let mut engine = InterruptEngine::new(StubSource::default());
        // 20 minutes of 2-second samples: only the last five minutes stay.
        for index in 0..600_i64 {
            engine.record_activity(&activity_sample(index * 2_000), None);
        }
        let last = 599 * 2_000;
        assert_eq!(
            engine.activity.front().map(|point| point.timestamp_ms),
            Some(last - ACTIVITY_WINDOW_MS)
        );
        assert_eq!(engine.activity.len(), 151);
        assert_eq!(engine.source().capture_calls, 0, "ring feeding makes no source calls");
        // A pathological sub-window burst still respects the hard cap.
        let mut engine = InterruptEngine::new(StubSource::default());
        for index in 0..600_i64 {
            engine.record_activity(&activity_sample(index * 100), None);
        }
        assert_eq!(engine.activity.len(), 512);
    }

    #[test]
    fn classification_table_maps_names_and_lets_descriptions_vote() {
        use DeviceClass::*;
        for (name, expected) in [
            ("storport.sys", Storage),
            ("stornvme.sys", Storage),
            ("iaStorVD.sys", Storage),
            ("disk.sys", Storage),
            ("ndis.sys", Network),
            ("tcpip.sys", Network),
            ("rt640x64.sys", Network),
            ("Netwtw10.sys", Network),
            ("nvlddmkm.sys", Gpu),
            ("amdkmdag.sys", Gpu),
            ("igdkmd64.sys", Gpu),
            ("USBXHCI.SYS", Usb),
            ("usbport.sys", Usb),
            ("HDAudBus.sys", Audio),
            ("portcls.sys", Audio),
            ("ACPI.sys", Platform),
            ("intelppm.sys", Platform),
            ("amdppm.sys", Platform),
            ("hal.dll", Platform),
            ("mystery.sys", Other),
            ("ntoskrnl.exe", Other),
        ] {
            assert_eq!(classify_driver(name, None), expected, "{name}");
        }
        // Description/company strings vote when the name says nothing…
        assert_eq!(
            classify_driver("xyz64.sys", Some("Contoso Ethernet Adapter Driver")),
            Network
        );
        assert_eq!(
            classify_driver("cwk.sys", Some("Creative Audio Driver")),
            Audio
        );
        // …but the name vote wins over a chatty description.
        assert_eq!(
            classify_driver("nvlddmkm.sys", Some("also handles network streaming")),
            Gpu
        );
        assert_eq!(classify_driver("thing.sys", Some("Widget Runtime")), Other);
    }

    #[test]
    fn pearson_needs_samples_and_variance_on_both_sides() {
        let xs: Vec<f64> = (0..80).map(f64::from).collect();
        let doubled: Vec<f64> = xs.iter().map(|x| 2.0 * x + 1.0).collect();
        let inverted: Vec<f64> = xs.iter().map(|x| -x).collect();
        assert!((pearson(&xs, &doubled).unwrap() - 1.0).abs() < 1e-9);
        assert!((pearson(&xs, &inverted).unwrap() + 1.0).abs() < 1e-9);
        // Fewer than 60 aligned samples is not signal.
        assert_eq!(pearson(&xs[..59], &doubled[..59]), None);
        assert_eq!(pearson(&xs, &doubled[..79]), None, "mismatched lengths");
        // A flat series has no variance to correlate with.
        assert_eq!(pearson(&xs, &vec![5.0; 80]), None);
        // Near-constant relative to its own magnitude fails the floor even
        // though the variance is numerically nonzero.
        let jittered: Vec<f64> = (0..80).map(|i| 1_000.0 + f64::from(i % 2) * 1e-4).collect();
        assert_eq!(pearson(&xs, &jittered), None);
    }

    #[test]
    fn class_correlation_matches_series_or_reports_insufficient_signal() {
        let mut engine = InterruptEngine::new(StubSource::default());
        feed_gpu_correlated_activity(&mut engine);
        match class_correlation(&engine.activity, DeviceClass::Gpu) {
            CorrelationOutcome::Measured { series, r, span_ms } => {
                assert_eq!(series, "gpu activity");
                assert!(r > 0.99, "engineered perfect correlation, got {r}");
                assert_eq!(span_ms, 149 * 2_000);
            }
            CorrelationOutcome::Insufficient => panic!("expected a measured correlation"),
        }
        // The disk and network series are flat in this window, so the
        // storage and network classes fail the variance floor honestly.
        assert_eq!(
            class_correlation(&engine.activity, DeviceClass::Storage),
            CorrelationOutcome::Insufficient
        );
        assert_eq!(
            class_correlation(&engine.activity, DeviceClass::Network),
            CorrelationOutcome::Insufficient
        );
        // Classes without an activity series never pretend to correlate.
        assert_eq!(
            class_correlation(&engine.activity, DeviceClass::Usb),
            CorrelationOutcome::Insufficient
        );
        // No GPU telemetry at all: gpu correlation is skipped, not imputed.
        let mut blind = InterruptEngine::new(StubSource::default());
        for index in 0..150_i64 {
            blind.record_activity(&activity_sample(index * 2_000), None);
        }
        assert_eq!(
            class_correlation(&blind.activity, DeviceClass::Gpu),
            CorrelationOutcome::Insufficient
        );
        // A short window is insufficient even with variance.
        let mut short = InterruptEngine::new(StubSource::default());
        for index in 0..30_i64 {
            let mut sample = activity_sample(index * 2_000);
            sample.interrupt_rate = 10_000.0 + index as f64 * 100.0;
            short.record_activity(&sample, Some(index as f64));
        }
        assert_eq!(
            class_correlation(&short.activity, DeviceClass::Gpu),
            CorrelationOutcome::Insufficient
        );
    }

    fn record(timestamp_ms: i64, shares: &[(&str, f64)]) -> CaptureRecord {
        CaptureRecord {
            timestamp_ms,
            shares: shares
                .iter()
                .map(|(name, share)| ((*name).to_string(), *share))
                .collect(),
            total_events: 10_000,
            capped: false,
        }
    }

    #[test]
    fn modal_candidate_summarizes_consistency_share_and_margin() {
        let history = [
            record(0, &[("a.sys", 50.0), ("b.sys", 30.0), (UNATTRIBUTED, 20.0)]),
            record(1, &[("a.sys", 45.0), ("b.sys", 40.0), (UNATTRIBUTED, 15.0)]),
            record(2, &[("b.sys", 60.0), ("a.sys", 31.0), (UNATTRIBUTED, 9.0)]),
        ];
        let candidate = modal_candidate(&history).expect("candidate");
        assert_eq!(candidate.driver, "a.sys");
        assert_eq!(candidate.captures, 3);
        assert_eq!(candidate.consistent, 2);
        assert!((candidate.mean_share - 42.0).abs() < 1e-9);
        // Margins over #2 in the captures a.sys leads: 20 and 5.
        assert!((candidate.margin - 12.5).abs() < 1e-9);
        // A trace where only unattributed buckets exist yields no candidate.
        assert_eq!(modal_candidate(&[record(0, &[(UNATTRIBUTED, 100.0)])]), None);
        assert_eq!(modal_candidate(&[]), None);
    }

    #[test]
    fn confidence_rubric_tiers() {
        use Confidence::*;
        // HIGH by class-matched correlation.
        assert_eq!(assess_confidence(3, 3, 50.0, 10.0, Some(0.7)), High);
        // HIGH by dominance margin without correlation.
        assert_eq!(assess_confidence(4, 4, 45.0, 25.0, None), High);
        // Correlation below the 0.6 floor cannot lift it to HIGH…
        assert_eq!(assess_confidence(3, 3, 50.0, 10.0, Some(0.59)), Medium);
        // …and a negative correlation never counts as a match.
        assert_eq!(assess_confidence(3, 3, 50.0, 10.0, Some(-0.9)), Medium);
        // Share below 45 blocks HIGH regardless of correlation.
        assert_eq!(assess_confidence(3, 3, 40.0, 30.0, Some(0.9)), Medium);
        // MEDIUM: consistent in two with 30% share.
        assert_eq!(assess_confidence(2, 3, 30.0, 0.0, None), Medium);
        // MEDIUM: single capture with a 60% share.
        assert_eq!(assess_confidence(1, 1, 60.0, 20.0, None), Medium);
        // LOW: single capture below 60%.
        assert_eq!(assess_confidence(1, 1, 59.0, 59.0, None), Low);
        // LOW: inconsistent top across several captures.
        assert_eq!(assess_confidence(1, 4, 80.0, 80.0, None), Low);
        // LOW: consistent but weak share.
        assert_eq!(assess_confidence(2, 4, 20.0, 0.0, None), Low);
    }

    /// The engine-level half of the field report's DPC cases. The
    /// gating half (one incident, silent, stable title) lives in
    /// `alerting.rs`; this is the verdict the gate reads.
    #[test]
    fn verdict_state_holds_only_when_a_family_leads_the_history() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().drivers = drivers(&[
            (0xFFFF_F800_0000_0000, "storport.sys"),
            (0xFFFF_F800_1000_0000, "nvlddmkm.sys"),
        ]);
        let storage = capture(&[(0xFFFF_F800_0001_0000, 100)]);
        let graphics = capture(&[(0xFFFF_F800_1001_0000, 100)]);
        feed_gpu_correlated_activity(&mut engine);
        let alerts = [dpc_alert("d1")];
        assert_eq!(
            engine.verdict_state(),
            VerdictState::NoCapture,
            "no capture, no verdict"
        );
        assert_eq!(engine.corroborating_signals(), 0);

        // One trace is diagnostic evidence only.
        engine.source_mut().capture = storage.clone();
        engine.observe(&alerts, 0);
        assert_eq!(engine.verdict_state(), VerdictState::SingleCapture);

        // A second trace agreeing on the family makes it repeatable.
        engine.observe(&alerts, 2 * 60_000);
        assert_eq!(
            engine.verdict_state(),
            VerdictState::Repeatable {
                driver_family: "storage".into()
            }
        );
        // Storage activity is flat in this window, so nothing corroborates.
        assert_eq!(engine.corroborating_signals(), 0);

        // The cause moves to the GPU. While the history is evenly split the
        // engine says so rather than picking a side.
        engine.source_mut().capture = graphics;
        engine.observe(&alerts, 4 * 60_000);
        assert_eq!(
            engine.verdict_state(),
            VerdictState::Repeatable {
                driver_family: "storage".into()
            },
            "two of three captures still say storage"
        );
        engine.observe(&alerts, 14 * 60_000);
        assert_eq!(
            engine.verdict_state(),
            VerdictState::SingleCapture,
            "an evenly split history names no family"
        );
        engine.observe(&alerts, 24 * 60_000);
        assert_eq!(
            engine.verdict_state(),
            VerdictState::ChangedConfidently {
                from: "storage".into(),
                to: "gpu".into()
            },
            "both sides passed the confidence gate, so this is a real change"
        );
        // The GPU series does track the interrupt rate in this window.
        assert_eq!(engine.corroborating_signals(), 1);
    }

    #[test]
    fn alternating_capture_families_never_reach_a_repeatable_verdict() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().drivers = drivers(&[
            (0xFFFF_F800_0000_0000, "storport.sys"),
            (0xFFFF_F800_1000_0000, "nvlddmkm.sys"),
            (0xFFFF_F800_2000_0000, "ndis.sys"),
        ]);
        // Each trace is a fragmented field whose leader rotates
        // storage -> graphics -> network: exactly the field report.
        let rotation = [
            capture(&[
                (0xFFFF_F800_0001_0000, 40),
                (0xFFFF_F800_1001_0000, 35),
                (0xFFFF_F800_2001_0000, 25),
            ]),
            capture(&[
                (0xFFFF_F800_0001_0000, 25),
                (0xFFFF_F800_1001_0000, 40),
                (0xFFFF_F800_2001_0000, 35),
            ]),
            capture(&[
                (0xFFFF_F800_0001_0000, 35),
                (0xFFFF_F800_1001_0000, 25),
                (0xFFFF_F800_2001_0000, 40),
            ]),
        ];
        let alerts = [dpc_alert("d1")];
        // Minutes: the fast phase, then the ten-minute cooldown.
        for (index, minute) in [0, 2, 4, 14, 24, 34].into_iter().enumerate() {
            engine.source_mut().capture = rotation[index % rotation.len()].clone();
            engine.observe(&alerts, minute * 60_000);
            assert_eq!(
                engine.verdict_state(),
                VerdictState::SingleCapture,
                "no family has held after {} traces",
                index + 1
            );
        }
    }

    #[test]
    fn verdict_rows_reach_the_finding_with_class_and_recommendation() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().capture = capture(&[(0xFFFF_F800_0001_0000, 100)]);
        engine.source_mut().drivers = drivers(&[(0xFFFF_F800_0000_0000, "nvlddmkm.sys")]);
        engine.source_mut().descriptions.insert(
            "nvlddmkm.sys".into(),
            "NVIDIA Windows Kernel Mode Driver".into(),
        );
        feed_gpu_correlated_activity(&mut engine);
        let mut alerts = [dpc_alert("d1")];
        alerts[0].recommendation = "Check recently connected devices.".into();
        for now in [0, 2 * 60_000, 4 * 60_000, 14 * 60_000] {
            engine.observe(&alerts, now);
        }
        engine.decorate(&mut alerts);
        engine.decorate(&mut alerts); // decoration must stay idempotent
        let value = |label: &str| {
            alerts[0]
                .evidence
                .iter()
                .find(|item| item.label == label)
                .map(|item| item.value.clone())
                .unwrap_or_else(|| panic!("{label} row missing"))
        };
        assert_eq!(
            value(LIKELY_CAUSE_LABEL),
            "nvlddmkm.sys — NVIDIA Windows Kernel Mode Driver [gpu]"
        );
        assert_eq!(
            value(CONFIDENCE_LABEL),
            "high — top in 4/4 traces · 100% mean share"
        );
        let correlation = value(CORRELATION_LABEL);
        assert!(
            correlation.starts_with("gpu activity r=1.00 over"),
            "unexpected correlation row: {correlation}"
        );
        assert!(value(ATTRIBUTION_LABEL).contains("nvlddmkm.sys 100%"));
        assert!(
            alerts[0]
                .evidence
                .iter()
                .all(|item| item.value.chars().count() <= MAX_VALUE_CHARS)
        );
        assert_eq!(
            alerts[0].recommendation,
            "Check recently connected devices. Update or roll back the GPU driver first."
        );
        // One verdict row each, even after repeated decoration.
        for label in [LIKELY_CAUSE_LABEL, CONFIDENCE_LABEL, CORRELATION_LABEL] {
            assert_eq!(
                alerts[0]
                    .evidence
                    .iter()
                    .filter(|item| item.label == label)
                    .count(),
                1,
                "{label} must be replaced, not appended"
            );
        }
    }

    #[test]
    fn class_recommendation_is_idempotent_and_swaps_with_the_class() {
        let base = "Check recently connected devices.";
        let mut recommendation = base.to_string();
        apply_class_recommendation(&mut recommendation, Some(DeviceClass::Storage));
        assert_eq!(
            recommendation,
            format!("{base} Update or roll back the storage driver first.")
        );
        apply_class_recommendation(&mut recommendation, Some(DeviceClass::Storage));
        assert_eq!(
            recommendation,
            format!("{base} Update or roll back the storage driver first."),
            "appending twice must not duplicate"
        );
        apply_class_recommendation(&mut recommendation, Some(DeviceClass::Network));
        assert_eq!(
            recommendation,
            format!("{base} Update or roll back the network driver first."),
            "a changed verdict swaps the sentence"
        );
        apply_class_recommendation(&mut recommendation, Some(DeviceClass::Other));
        assert_eq!(recommendation, base, "the other class appends nothing");
        apply_class_recommendation(&mut recommendation, None);
        assert_eq!(recommendation, base);
    }

    #[test]
    fn verdict_formatting_is_bounded_and_exact() {
        let candidate = VerdictCandidate {
            driver: "nvlddmkm.sys".into(),
            captures: 4,
            consistent: 4,
            mean_share: 58.4,
            margin: 30.0,
        };
        assert_eq!(
            format_confidence(Confidence::High, &candidate),
            "high — top in 4/4 traces · 58% mean share"
        );
        let long = format_likely_cause("nvlddmkm.sys", Some(&"N".repeat(200)), DeviceClass::Gpu);
        assert!(long.ends_with(" [gpu]"), "class tag survives truncation: {long}");
        assert!(long.chars().count() <= MAX_VALUE_CHARS);
        assert_eq!(
            format_likely_cause("ndis.sys", None, DeviceClass::Network),
            "ndis.sys [network]"
        );
        assert_eq!(
            format_correlation(&CorrelationOutcome::Measured {
                series: "gpu activity",
                r: 0.812,
                span_ms: 5 * 60_000,
            }),
            "gpu activity r=0.81 over 5 m"
        );
        assert_eq!(
            format_correlation(&CorrelationOutcome::Insufficient),
            "insufficient signal"
        );
        assert_eq!(format_span(45_000), "45 s");
        assert_eq!(format_span(298_000), "5 m");
    }

    #[test]
    fn normalizes_kernel_image_paths() {
        let system_root =
            std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        assert_eq!(
            normalize_driver_path(r"\SystemRoot\System32\drivers\storport.sys"),
            format!(r"{system_root}\System32\drivers\storport.sys")
        );
        assert_eq!(
            normalize_driver_path(r"\??\C:\Windows\system32\drivers\x.sys"),
            r"C:\Windows\system32\drivers\x.sys"
        );
        assert_eq!(
            normalize_driver_path(r"System32\drivers\y.sys"),
            format!(r"{system_root}\System32\drivers\y.sys")
        );
    }

    #[test]
    fn windows_driver_map_is_sorted_and_described() {
        // Real but cheap syscalls; kernel base addresses may be withheld from
        // an unelevated test run, which must degrade to an empty map rather
        // than fail.
        let mut source = WindowsInterruptSource::default();
        let map = source.driver_bases();
        if map.is_empty() {
            eprintln!("driver enumeration returned nothing (unelevated?); degraded path exercised");
            return;
        }
        assert!(map.windows(2).all(|pair| pair[0].0 <= pair[1].0), "sorted by base");
        let kernel = map
            .iter()
            .find(|(_, name)| name.to_ascii_lowercase().starts_with("ntoskrnl"));
        assert!(kernel.is_some(), "kernel image present in the driver map");
        if let Some((_, name)) = kernel {
            let description = source.driver_description(name);
            println!("kernel image description: {description:?}");
        }
    }

    #[test]
    #[ignore = "dev harness: captures a real 3 s ISR/DPC system-logger trace on this machine and prints driver attribution"]
    fn dev_probe_real_isr_dpc_capture() {
        let mut engine = InterruptEngine::new(WindowsInterruptSource::default());
        let map = engine.source_mut().driver_bases();
        println!("driver map: {} drivers", map.len());
        for (base, name) in map.iter().take(3) {
            println!("  {base:#018x} {name}");
        }
        match engine.source_mut().capture(3_000, EVENT_CAP) {
            Err(error) => {
                // Expected without SeSystemProfilePrivilege; the degraded
                // note is exactly what the finding's evidence would carry.
                println!("capture degraded: {error:#}");
            }
            Ok(result) => {
                println!(
                    "window {} ms · {} events (ISR {} / DPC {}) · {} buckets · capped {}",
                    result.window_ms,
                    result.total_events(),
                    result.isr_events,
                    result.dpc_events,
                    result.buckets.len(),
                    result.capped
                );
                let ranked = attribute_buckets(&result.buckets, &map);
                let total: u64 = ranked.iter().map(|(_, count)| count).sum();
                for (name, count) in ranked.iter().take(5) {
                    let percent = (count * 100).checked_div(total).unwrap_or(0);
                    let description = engine
                        .source_mut()
                        .driver_description(name)
                        .unwrap_or_else(|| "(no version resource)".into());
                    println!("  {name:<20} {percent:>3}% ({count})  {description}");
                }
                println!("evidence rows:");
                let (record, rows) = engine.build_capture(&result, 0);
                for row in &rows {
                    println!("  {} = {}", row.label, row.value);
                }
                // The verdict a real finding would carry after this single
                // trace. The probe has no device-activity ring behind it, so
                // the correlation line honestly reads "insufficient signal".
                match record.and_then(|record| modal_candidate(&[record])) {
                    None => println!("verdict: none (no attributable events)"),
                    Some(candidate) => {
                        let description = engine.source_mut().driver_description(&candidate.driver);
                        let class = classify_driver(&candidate.driver, description.as_deref());
                        let correlation = class_correlation(&engine.activity, class);
                        let confidence = assess_confidence(
                            candidate.consistent,
                            candidate.captures,
                            candidate.mean_share,
                            candidate.margin,
                            correlation.matched_r(),
                        );
                        println!(
                            "verdict: {} = {}",
                            LIKELY_CAUSE_LABEL,
                            format_likely_cause(&candidate.driver, description.as_deref(), class)
                        );
                        println!(
                            "verdict: {} = {}",
                            CONFIDENCE_LABEL,
                            format_confidence(confidence, &candidate)
                        );
                        println!(
                            "verdict: {} = {}",
                            CORRELATION_LABEL,
                            format_correlation(&correlation)
                        );
                    }
                }
                if result.total_events() > 0 {
                    assert!(
                        ranked.iter().any(|(name, _)| name != UNATTRIBUTED),
                        "expected at least one bucket to attribute to a known driver"
                    );
                }
            }
        }
        let (started, stopped, opened, closed) = engine.source().session_balance();
        println!("session balance: started {started} stopped {stopped} · traces opened {opened} closed {closed}");
        assert_eq!(started, stopped, "every session started was stopped");
        assert_eq!(opened, closed, "every processing handle was closed");
    }
}
