use crate::{
    alerting::{AlertEngine, InterruptContext, QUIET_PERIOD_MS},
    analysis::{AgentContextSource, build_agent_context},
    baselines::BaselineStore,
    config::Settings,
    etw::{CmdlineCollector, EtwCollector, EtwHealth},
    etw_props::ParsedProcessEvent,
    eventlog::EventLogCollector,
    launches::{CmdlineJoiner, LaunchTracker, LiveProcessInfo},
    metrics::{
        MetricCollector,
        dumps::{DumpEngine, WindowsDumpSource},
        forensics::{ForensicsEngine, WindowsForensicsSource},
        interrupts::{InterruptEngine, WindowsInterruptSource},
        live::LiveEngine,
    },
    models::{
        DiagnosticLogResponse, DiagnosticLogStatus, LaunchCaptureStatus, LaunchEvent,
        OpenIncidentRef, PipeRequest, PipeResponse, ProcessMetric, ProcessNode, Rating,
        RatingVerdict, Snapshot, SystemMetric,
    },
    pipe,
    quality::{Calibration, derive_offsets},
    ratings,
    storage::Storage,
};
use anyhow::{Result, anyhow};
use chrono::Utc;
use serde_json::json;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub struct AppState {
    pub snapshot: RwLock<Snapshot>,
    /// The machine baseline the sampling loop is actually working with,
    /// republished after every sample folds in.
    ///
    /// Baselines are persisted only every five minutes, so anything reading
    /// them back from storage is up to that stale. For a rating that
    /// matters twice: its demand bucket could disagree with the bucket the
    /// engine is scoring incidents against right now, and — once per
    /// machine, forever — a rating given inside that window at the 24-hour
    /// crossing would be stamped `during_learning` and so contribute
    /// nothing to the notification policy it was meant to teach. Seeded from
    /// storage at startup so the window before the first sample is covered
    /// too.
    pub baseline: RwLock<crate::baselines::MachineBaseline>,
    pub settings: RwLock<Settings>,
    pub storage: Arc<Storage>,
    pub alerts: Mutex<AlertEngine>,
    pub log_status: Mutex<DiagnosticLogStatus>,
    issued_contexts: Mutex<VecDeque<IssuedContext>>,
    pub settings_path: PathBuf,
    /// Activity-gated high-rate telemetry for smooth-mode clients: zero
    /// idle cost, started by the first `live` request, stopped on idle.
    pub live: LiveEngine,
}

impl AppState {
    pub fn handle(&self, request: PipeRequest) -> PipeResponse {
        match self.handle_inner(request) {
            Ok(data) => PipeResponse::Ok { data },
            Err(error) => PipeResponse::Error {
                code: "requestFailed".into(),
                message: format!("{error:#}"),
            },
        }
    }

    fn handle_inner(&self, request: PipeRequest) -> Result<serde_json::Value> {
        match request {
            PipeRequest::Ping => Ok(json!({
                "protocolVersion": crate::PROTOCOL_VERSION,
                "serviceVersion": env!("CARGO_PKG_VERSION")
            })),
            PipeRequest::Live => Ok(serde_json::to_value(self.live.request())?),
            PipeRequest::GetSnapshot => Ok(serde_json::to_value(
                self.snapshot
                    .read()
                    .map_err(|_| anyhow!("snapshot lock poisoned"))?
                    .clone(),
            )?),
            PipeRequest::GetHistory {
                from_ms,
                to_ms,
                limit,
            } => {
                if from_ms > to_ms {
                    return Err(anyhow!("fromMs must not be after toMs"));
                }
                Ok(serde_json::to_value(self.storage.history(
                    from_ms,
                    to_ms,
                    limit.min(750),
                )?)?)
            }
            PipeRequest::GetSystemHistory {
                from_ms,
                to_ms,
                limit,
            } => {
                if from_ms > to_ms {
                    return Err(anyhow!("fromMs must not be after toMs"));
                }
                Ok(serde_json::to_value(
                    self.storage
                        .system_history_downsampled(from_ms, to_ms, limit.min(800))?,
                )?)
            }
            PipeRequest::GetAlerts { from_ms, limit } => Ok(serde_json::to_value(
                self.storage.alerts(from_ms, limit.min(300))?,
            )?),
            PipeRequest::GetDiagnosticLogs { from_ms, limit } => {
                let response = DiagnosticLogResponse {
                    status: self
                        .log_status
                        .lock()
                        .map_err(|_| anyhow!("diagnostic-log status lock poisoned"))?
                        .clone(),
                    logs: self.storage.diagnostic_logs(from_ms, limit.min(200))?,
                };
                Ok(serde_json::to_value(response)?)
            }
            PipeRequest::GetAgentContext { window_hours } => {
                if !(1..=24).contains(&window_hours) {
                    return Err(anyhow!("windowHours must be between 1 and 24"));
                }
                let now_ms = Utc::now().timestamp_millis();
                let from_ms = now_ms - i64::from(window_hours) * 3_600_000;
                let history = self
                    .storage
                    .recent_history(from_ms, now_ms, 10_000, 20_000)?;
                let logs = self.storage.diagnostic_logs(from_ms, 5_000)?;
                let alerts = self.storage.alerts(from_ms, 500)?;
                let snapshot = self
                    .snapshot
                    .read()
                    .map_err(|_| anyhow!("snapshot lock poisoned"))?
                    .clone();
                let settings = self
                    .settings
                    .read()
                    .map_err(|_| anyhow!("settings lock poisoned"))?
                    .clone();
                let status = self
                    .log_status
                    .lock()
                    .map_err(|_| anyhow!("diagnostic-log status lock poisoned"))?
                    .clone();
                let context = build_agent_context(AgentContextSource {
                    now_ms,
                    window_hours,
                    snapshot: &snapshot,
                    settings: &settings,
                    history,
                    logs,
                    log_status: status,
                    alerts,
                    rating_offsets: self
                        .alerts
                        .lock()
                        .map_err(|_| anyhow!("alert lock poisoned"))?
                        .rating_offsets()
                        .entries(),
                });
                self.remember_context(&context)?;
                Ok(serde_json::to_value(context)?)
            }
            PipeRequest::GetOptimizationPlans { limit } => Ok(serde_json::to_value(
                self.storage.optimization_plans(limit.min(5))?,
            )?),
            PipeRequest::SaveOptimizationPlan { plan } => {
                plan.validate().map_err(anyhow::Error::msg)?;
                self.validate_plan_context(&plan)?;
                self.storage.save_optimization_plan(&plan)?;
                Ok(json!({ "saved": true, "planId": plan.plan_id }))
            }
            PipeRequest::GetSettings => Ok(serde_json::to_value(
                self.settings
                    .read()
                    .map_err(|_| anyhow!("settings lock poisoned"))?
                    .clone(),
            )?),
            PipeRequest::UpdateSettings { settings } => {
                settings.validate()?;
                settings.save(&self.settings_path)?;
                *self
                    .settings
                    .write()
                    .map_err(|_| anyhow!("settings lock poisoned"))? = settings.clone();
                Ok(serde_json::to_value(settings)?)
            }
            PipeRequest::GetProcessTree => {
                let processes = self
                    .snapshot
                    .read()
                    .map_err(|_| anyhow!("snapshot lock poisoned"))?
                    .processes
                    .clone();
                Ok(serde_json::to_value(build_process_tree(&processes))?)
            }
            PipeRequest::AcknowledgeAlert { alert_id } => {
                let active = self
                    .alerts
                    .lock()
                    .map_err(|_| anyhow!("alert lock poisoned"))?
                    .acknowledge(&alert_id);
                let persisted = self.storage.acknowledge_alert(&alert_id)?;
                if let Some(alert) = active {
                    let mut snapshot = self
                        .snapshot
                        .write()
                        .map_err(|_| anyhow!("snapshot lock poisoned"))?;
                    if let Some(item) = snapshot
                        .active_alerts
                        .iter_mut()
                        .find(|item| item.id == alert_id)
                    {
                        *item = alert;
                    }
                }
                Ok(json!({ "acknowledged": persisted }))
            }
            PipeRequest::ArchiveAlert { alert_id, archived } => {
                let active = self
                    .alerts
                    .lock()
                    .map_err(|_| anyhow!("alert lock poisoned"))?
                    .set_archived(&alert_id, archived);
                let persisted = self.storage.archive_alert(&alert_id, archived)?;
                if let Some(alert) = active {
                    let mut snapshot = self
                        .snapshot
                        .write()
                        .map_err(|_| anyhow!("snapshot lock poisoned"))?;
                    if let Some(item) = snapshot
                        .active_alerts
                        .iter_mut()
                        .find(|item| item.id == alert_id)
                    {
                        *item = alert;
                    }
                }
                Ok(json!({ "archived": persisted }))
            }
            PipeRequest::TerminateProcess { pid, confirmed } => {
                crate::metrics::terminate_process(pid, confirmed)?;
                Ok(json!({ "terminated": true, "pid": pid }))
            }
            PipeRequest::AddRating { verdict } => {
                let rating = self.assemble_rating(verdict)?;
                self.storage.save_rating(&rating)?;
                // The rating just landed is the single source of truth for
                // the notification policy's offsets -- re-derive the
                // engine's cache from it immediately, so the very next
                // evaluation already honors what the user just said.
                self.refresh_rating_offsets()?;
                Ok(serde_json::to_value(rating)?)
            }
            PipeRequest::GetRatings { limit } => {
                // Clamped to the same bound the policy itself is derived
                // from: the TUI reads this to show the offsets it believes
                // are in force, and a transport bound below
                // `POLICY_OFFSET_RATINGS` would let that figure drift from
                // the one the engine applies once the table grows past it.
                Ok(serde_json::to_value(
                    self.storage.ratings(limit.min(POLICY_OFFSET_RATINGS))?,
                )?)
            }
            PipeRequest::GetLaunchGroups {
                from_ms,
                console_hosts_only,
                limit,
            } => {
                let now_ms = Utc::now().timestamp_millis();
                let from_ms = from_ms.unwrap_or(now_ms - LAUNCH_HISTORY_DEFAULT_WINDOW_MS);
                let limit = limit
                    .unwrap_or(GET_LAUNCH_GROUPS_MAX_LIMIT)
                    .min(GET_LAUNCH_GROUPS_MAX_LIMIT);
                let events = self.storage.launch_events(from_ms)?;
                let groups = crate::launches::group_launches(
                    &events,
                    console_hosts_only.unwrap_or(false),
                    limit,
                );
                Ok(json!({ "groups": groups }))
            }
            PipeRequest::GetLaunchOccurrences {
                exe_path,
                lineage_sig,
                from_ms,
                limit,
            } => {
                let now_ms = Utc::now().timestamp_millis();
                let from_ms = from_ms.unwrap_or(now_ms - LAUNCH_HISTORY_DEFAULT_WINDOW_MS);
                let limit = limit
                    .unwrap_or(GET_LAUNCH_OCCURRENCES_MAX_LIMIT)
                    .min(GET_LAUNCH_OCCURRENCES_MAX_LIMIT);
                // `load_launch_events` already orders by start_time_ms DESC
                // (newest first), so filtering preserves that order.
                let mut events = self.storage.launch_events(from_ms)?;
                events.retain(|event| {
                    event.exe_path == exe_path
                        && crate::launches::lineage_sig(&event.lineage) == lineage_sig
                });
                events.truncate(limit);

                // Privacy: launch_events payloads never carry command lines
                // (the runtime clears them before save). A command line is
                // decrypted here, per request, for this response only -- it
                // is never written back or cached. A decrypt failure (e.g. a
                // post-reinstall machine-key change) leaves the occurrence's
                // `command_line` absent rather than failing the whole
                // request; it is only logged.
                for event in &mut events {
                    if let Some(blob) = self
                        .storage
                        .load_launch_cmdline(event.pid, event.start_time_ms)?
                    {
                        match crate::dpapi::unprotect(&blob) {
                            Ok(plaintext) => {
                                event.command_line =
                                    Some(String::from_utf8_lossy(&plaintext).into_owned());
                            }
                            Err(code) => {
                                eprintln!(
                                    "failed to decrypt a captured command line for pid {} (start {}): DPAPI error {code:#x}",
                                    event.pid, event.start_time_ms
                                );
                            }
                        }
                    }
                }

                Ok(json!({ "events": events }))
            }
            PipeRequest::DeleteCommandLines => {
                let deleted = self.storage.delete_all_launch_cmdlines()?;
                Ok(json!({ "deleted": deleted }))
            }
        }
    }
}

/// Default lookback window for `getLaunchGroups`/`getLaunchOccurrences` when
/// the caller omits `fromMs`.
const LAUNCH_HISTORY_DEFAULT_WINDOW_MS: i64 = 7 * 24 * 3600 * 1000;
/// Transport-safe cap on `getLaunchGroups`'s `limit`.
const GET_LAUNCH_GROUPS_MAX_LIMIT: usize = 500;
/// Transport-safe cap on `getLaunchOccurrences`'s `limit`.
const GET_LAUNCH_OCCURRENCES_MAX_LIMIT: usize = 1_000;

#[derive(Debug)]
struct IssuedContext {
    id: String,
    generated_at_ms: i64,
    evidence_refs: HashSet<String>,
}

/// How much rating history the notification policy is derived from. Ratings
/// decay with a 30-day half-life, so anything past the newest couple hundred
/// is arithmetically inaudible long before it is dropped -- and the bound
/// keeps a machine with a thousand stored ratings from re-deriving the whole
/// table on every new one.
///
/// Public because the TUI derives the *same* offsets for display and must
/// read exactly as much history as the engine does: two independently
/// chosen bounds could show the operator a figure the policy is not
/// applying. One constant, one tie, checked by the compiler.
pub const POLICY_OFFSET_RATINGS: usize = 200;

/// Trailing window a rating's demand bucket is classified against (Global
/// Constraints: "trailing 10 min composite").
const RATING_DEMAND_WINDOW_MS: i64 = 10 * 60_000;
/// Trailing window a rating's digest rolls up (mirrors the agent context's
/// own rollup window default).
const RATING_DIGEST_WINDOW_MS: i64 = 3_600_000;

impl AppState {
    /// Re-derive the notify-floor offsets from the rating history and hand
    /// them to the engine. Called once at startup and again whenever a new
    /// rating lands, because the ratings table is the single source of truth
    /// and [`derive_offsets`] is a pure function over it -- there is no
    /// second store to keep in step, only this cache to refresh.
    pub fn refresh_rating_offsets(&self) -> Result<()> {
        let ratings = self.storage.ratings(POLICY_OFFSET_RATINGS)?;
        let offsets = derive_offsets(&ratings, Utc::now().timestamp_millis());
        self.alerts
            .lock()
            .map_err(|_| anyhow!("alert lock poisoned"))?
            .observe_rating_offsets(offsets);
        Ok(())
    }

    /// Assemble a full [`Rating`] server-side from just the user's verdict.
    /// The pipe handler itself stays a thin shell (save + refresh-offsets +
    /// serialize); this is where the record's context comes from, factored
    /// out so it is exercised directly by handler-level tests without
    /// needing the pipe wire format in the loop.
    fn assemble_rating(&self, verdict: RatingVerdict) -> Result<Rating> {
        let now_ms = Utc::now().timestamp_millis();

        // The live baseline the sampling loop republished on its last
        // sample, not the copy storage happens to hold (see
        // [`AppState::baseline`]): the bucket this rating is filed under and
        // the learning state that decides whether it counts at all must
        // agree with what the engine is scoring incidents against right now.
        let machine = self
            .baseline
            .read()
            .map_err(|_| anyhow!("baseline lock poisoned"))?
            .clone();
        let demand_window =
            self.storage
                .recent_history(now_ms - RATING_DEMAND_WINDOW_MS, now_ms, 10_000, 1)?;
        let (demand, demand_detail) = ratings::demand_bucket(&demand_window.system, &machine);

        let snapshot = self
            .snapshot
            .read()
            .map_err(|_| anyhow!("snapshot lock poisoned"))?
            .clone();
        let settings = self
            .settings
            .read()
            .map_err(|_| anyhow!("settings lock poisoned"))?
            .clone();
        let log_status = self
            .log_status
            .lock()
            .map_err(|_| anyhow!("diagnostic-log status lock poisoned"))?
            .clone();

        // Open incidents come from the live snapshot's active alerts, same
        // as the agent context: archived findings are the user filing them
        // away, so they stop counting as "open" for both the record and the
        // unexplained/false-positive judgment below.
        let active_incidents: Vec<crate::models::Alert> = snapshot
            .active_alerts
            .iter()
            .filter(|alert| !alert.archived)
            .cloned()
            .collect();
        let open_incidents: Vec<OpenIncidentRef> = active_incidents
            .iter()
            .map(|alert| OpenIncidentRef {
                fingerprint: alert.fingerprint.clone(),
                kind: alert.kind.clone(),
                severity: alert.severity,
                notify: alert.notify,
                acknowledged: alert.acknowledged,
            })
            .collect();
        // Mirrors `quality::derive_offsets`'s own "notifying" test: a
        // rating's own unexplained/false-positive judgment must agree with
        // the notion of "notifying" the offsets it later feeds are derived
        // from.
        let notifying = open_incidents
            .iter()
            .any(|incident| incident.notify && !incident.acknowledged);

        let learning = machine.is_learning();
        let learning_percent = learning.then(|| machine.learning_progress_pct());
        let digest_history = self.storage.recent_history(
            now_ms - RATING_DIGEST_WINDOW_MS,
            now_ms,
            10_000,
            20_000,
        )?;
        let collector_health = format!(
            "diagnosticLogs enabled={} lastError={}",
            log_status.enabled,
            log_status.last_error.as_deref().unwrap_or("none")
        );
        let digest = ratings::build_digest(ratings::DigestSource {
            history: digest_history,
            snapshot: &snapshot,
            settings: &settings,
            incidents: active_incidents,
            learning,
            learning_percent,
            collector_health,
        });

        Ok(Rating {
            id: uuid::Uuid::new_v4().to_string(),
            at_ms: now_ms,
            verdict,
            demand,
            demand_detail,
            digest,
            open_incidents,
            during_learning: learning,
            // Spec truth table: sluggish + nothing notifying -> true;
            // sluggish + something notifying -> false (the system already
            // called it); good/acceptable -> always false.
            unexplained: verdict == RatingVerdict::Sluggish && !notifying,
        })
    }

    fn remember_context(&self, context: &crate::models::AgentContext) -> Result<()> {
        let evidence_refs = context
            .process_suspects
            .iter()
            .map(|item| item.evidence_ref.clone())
            .chain(
                context
                    .diagnostic_log_rollups
                    .iter()
                    .map(|item| item.evidence_ref.clone()),
            )
            .chain(
                context
                    .recent_alerts
                    .iter()
                    .map(|alert| format!("alert:{}", alert.id)),
            )
            .collect();
        let mut issued = self
            .issued_contexts
            .lock()
            .map_err(|_| anyhow!("issued-context lock poisoned"))?;
        issued.retain(|item| item.id != context.context_id);
        issued.push_back(IssuedContext {
            id: context.context_id.clone(),
            generated_at_ms: context.generated_at_ms,
            evidence_refs,
        });
        while issued.len() > 32 {
            issued.pop_front();
        }
        Ok(())
    }

    fn validate_plan_context(&self, plan: &crate::models::OptimizationPlan) -> Result<()> {
        let now_ms = Utc::now().timestamp_millis();
        let mut issued = self
            .issued_contexts
            .lock()
            .map_err(|_| anyhow!("issued-context lock poisoned"))?;
        issued.retain(|item| now_ms.saturating_sub(item.generated_at_ms) <= 24 * 3_600_000);
        let context = issued
            .iter()
            .find(|item| item.id == plan.context_id)
            .ok_or_else(|| {
                anyhow!(
                    "plan context is unknown or expired; request a fresh agent context before importing"
                )
            })?;
        if context.generated_at_ms != plan.generated_at_ms {
            return Err(anyhow!(
                "plan timestamp does not match its evidence context"
            ));
        }
        for reference in plan
            .diagnoses
            .iter()
            .flat_map(|diagnosis| &diagnosis.evidence_refs)
            .chain(plan.actions.iter().flat_map(|action| &action.evidence_refs))
        {
            if !context.evidence_refs.contains(reference) {
                return Err(anyhow!(
                    "plan cites unknown evidence reference {reference} for its context"
                ));
            }
        }
        Ok(())
    }
}

pub fn run(data_dir: &Path, stop: crossbeam_channel::Receiver<()>) -> Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let settings_path = data_dir.join("settings.json");
    let settings = Settings::load(&settings_path)?;
    let storage = Arc::new(Storage::open(&data_dir.join("history.db"))?);
    // A restart breaks monitoring continuity. Close persisted open findings so the
    // fresh sustained detector can reacquire only conditions that are still present.
    let started_at_ms = Utc::now().timestamp_millis();
    storage.resolve_open_alerts(started_at_ms)?;
    // Those fingerprints stay reopen-eligible for the quiet period: a condition
    // that outlived the restart reattaches to its incident (same id, occurrences
    // continuing) rather than presenting as a brand-new finding.
    let reopen_seed = storage.recent_resolved_alerts(started_at_ms - QUIET_PERIOD_MS)?;
    // Learned per-machine and per-executable norms, carried across restarts.
    // A machine with nothing persisted starts its learning period now rather
    // than dating an empty baseline to the epoch. Restored once here and
    // handed to the sampling loop, so the pipe handler's live copy is right
    // from the first request rather than from the first sample.
    let baselines = BaselineStore::restore(storage.load_baselines()?, started_at_ms);
    let state = Arc::new(AppState {
        snapshot: RwLock::new(Snapshot::default()),
        baseline: RwLock::new(baselines.machine.clone()),
        settings: RwLock::new(settings),
        storage,
        alerts: Mutex::new(AlertEngine::new(reopen_seed)),
        log_status: Mutex::new(DiagnosticLogStatus::default()),
        issued_contexts: Mutex::new(VecDeque::new()),
        settings_path,
        live: LiveEngine::windows(),
    });
    // What the user's past ratings have made of the notification policy. Read
    // once here so the first evaluation after a restart already honors it.
    state.refresh_rating_offsets()?;
    let pipe_stop = Arc::new(AtomicBool::new(false));
    let pipe_state = Arc::clone(&state);
    let pipe_stop_worker = Arc::clone(&pipe_stop);
    let pipe_worker = thread::Builder::new()
        .name("pcpulse-pipe".into())
        .spawn(move || {
            if let Err(error) = pipe::serve(pipe_state, pipe_stop_worker) {
                eprintln!("named-pipe server stopped: {error:#}");
            }
        })?;
    let result = sampling_loop(&state, baselines, stop);
    pipe_stop.store(true, Ordering::Release);
    pipe::wake();
    let _ = pipe_worker.join();
    result
}

/// Trailing window the sampling loop keeps for `Calibration.demand`. Same
/// value as [`RATING_DEMAND_WINDOW_MS`] (both are the Global Constraints'
/// "trailing 10 min composite"), named separately because the two live in
/// different call paths -- one recomputed every sample, the other read once
/// per rating from stored history -- and are free to diverge later.
const DEMAND_WINDOW_MS: i64 = 10 * 60_000;

/// Assemble one sample's [`Calibration`] from the sampling loop's live
/// state. Factored out of `sampling_loop` -- which drives real OS
/// collectors and process/kernel state and so cannot be exercised as a unit
/// test -- specifically so the wiring from the trailing sample window to
/// `Calibration.demand` is a plain, testable function rather than buried in
/// the loop body. That wiring point carried a `TODO(ratings)` through Task
/// 4 (this module always passed `Calibration::default().demand`, i.e.
/// `Light`, regardless of load); pinning it here means a regression back to
/// the default is a unit-test failure, not something only visible on a
/// running, loaded machine.
fn build_calibration<'a>(recent: &[SystemMetric], baselines: &'a BaselineStore) -> Calibration<'a> {
    Calibration {
        learning: baselines.machine.is_learning(),
        baseline_maturity: baselines.machine.maturity(),
        names: Some(baselines),
        // How demanding the workload is right now: the bucket the user's
        // rating offsets are read against, so a rating only ever adjusts
        // the policy under the load it was given at.
        demand: ratings::demand_bucket(recent, &baselines.machine).0,
    }
}

/// Trailing window the nudge's heavy-minutes figure is taken over
/// (spec UX: "the trailing hour contained >= 10 minutes in the heavy
/// bucket").
const HEAVY_MINUTES_WINDOW_MS: i64 = 3_600_000;

/// Fold one sample's demand into the trailing-hour heavy-minutes ring and
/// answer how much of that hour was heavy.
///
/// `marks` holds the minute index (`timestamp_ms / 60_000`) of every minute
/// in the window that contained at least one heavy sample. Counting minutes
/// rather than samples is what keeps the figure independent of
/// `sample_interval_ms`, which the user can change: at a half-second cadence
/// ten heavy *samples* is five seconds, and would otherwise trip a gate that
/// is supposed to mean ten minutes of real load. Timestamps are
/// monotonic, so the ring stays sorted and duplicate minutes can be
/// recognized by looking at the back alone.
fn observe_heavy_minute(
    marks: &mut VecDeque<i64>,
    demand: crate::models::DemandBucket,
    timestamp_ms: i64,
) -> u16 {
    if demand == crate::models::DemandBucket::Heavy {
        let minute = timestamp_ms.div_euclid(60_000);
        if marks.back() != Some(&minute) {
            marks.push_back(minute);
        }
    }
    while marks
        .front()
        .is_some_and(|minute| timestamp_ms - minute * 60_000 > HEAVY_MINUTES_WINDOW_MS)
    {
        marks.pop_front();
    }
    marks.len().min(u16::MAX as usize) as u16
}

/// How often the command-line retention clock runs. Command lines have their
/// own (`commandLineRetentionHours`) window, deliberately shorter and
/// separate from the daily prune everything else rides on.
const CMDLINE_PRUNE_INTERVAL: Duration = Duration::from_secs(3_600);
/// How long the loop waits before retrying a command-line session that
/// failed to start (typically the machine's eight system-logger slots being
/// full). Long enough that a permanently full pool costs one log line and a
/// `StartTraceW` call every five minutes, not one per tick.
const CMDLINE_SESSION_RETRY: Duration = Duration::from_secs(300);

/// One ETW session's loss counters, read as absolute per-session totals.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct EtwCounters {
    dropped_channel: u64,
    etw_events_lost: u64,
    malformed_events: u64,
    events_lost_query_failures: u64,
}

impl EtwCounters {
    fn read(health: &EtwHealth) -> Self {
        Self {
            dropped_channel: health.dropped_channel.load(Ordering::Relaxed),
            etw_events_lost: health.etw_events_lost.load(Ordering::Relaxed),
            malformed_events: health.malformed_events.load(Ordering::Relaxed),
            events_lost_query_failures: health.events_lost_query_failures.load(Ordering::Relaxed),
        }
    }
}

/// Accumulates one ETW session's counters into service-lifetime totals.
///
/// `EtwHealth`'s counters are absolute **per collector session** and restart
/// at zero whenever the collector is rebuilt (see [`EtwHealth`]). A naive
/// `current - previous` underflows across such a restart, so every fold here
/// goes through [`EtwCounterTotals::fold`]: a decrease is read as a restart
/// and the new absolute value counts as the delta, never as negative loss.
/// The service-lifetime totals this produces are what the snapshot reports,
/// so a restart of the ETW collector never rewinds the operator's view of
/// how much was lost.
#[derive(Debug, Default)]
struct EtwCounterTotals {
    last: EtwCounters,
    total: EtwCounters,
}

impl EtwCounterTotals {
    fn observe(&mut self, current: EtwCounters) {
        Self::fold(
            &mut self.total.dropped_channel,
            &mut self.last.dropped_channel,
            current.dropped_channel,
        );
        Self::fold(
            &mut self.total.etw_events_lost,
            &mut self.last.etw_events_lost,
            current.etw_events_lost,
        );
        Self::fold(
            &mut self.total.malformed_events,
            &mut self.last.malformed_events,
            current.malformed_events,
        );
        Self::fold(
            &mut self.total.events_lost_query_failures,
            &mut self.last.events_lost_query_failures,
            current.events_lost_query_failures,
        );
    }

    fn fold(total: &mut u64, last: &mut u64, current: u64) {
        let delta = if current < *last {
            // The session restarted: everything it reports now is new loss.
            current
        } else {
            current - *last
        };
        *total = total.saturating_add(delta);
        *last = current;
    }

    /// The session this was tracking has gone away; the next one starts its
    /// counters from zero.
    fn session_ended(&mut self) {
        self.last = EtwCounters::default();
    }

    fn totals(&self) -> EtwCounters {
        self.total
    }
}

/// One joined command line, ready to be stored encrypted.
struct JoinedCmdline {
    pid: u32,
    start_time_ms: i64,
    redacted: String,
    redacted_fields: u32,
}

/// Attaches captured command lines to the launch rows about to be persisted
/// and returns what to store encrypted.
///
/// Every row is left with `command_line: None` on the way out. `launch_events`
/// payloads are plain JSON on disk, so a command line left on the row would
/// be a second, *unencrypted* at-rest copy of exactly the data the design
/// takes care to redact and DPAPI-protect. The only stored copy is the blob
/// in `launch_cmdlines`; clients get it back through the service's
/// per-request decrypt path.
fn join_command_lines(
    joiner: &mut CmdlineJoiner,
    events: &mut [LaunchEvent],
) -> Vec<JoinedCmdline> {
    let mut joined = Vec::new();
    for event in events.iter_mut() {
        if let Some((redacted, redacted_fields)) = joiner.attach(event) {
            joined.push(JoinedCmdline {
                pid: event.pid,
                start_time_ms: event.start_time_ms,
                redacted,
                redacted_fields,
            });
        }
        event.command_line = None;
    }
    joined
}

fn sampling_loop(
    state: &Arc<AppState>,
    mut baselines: BaselineStore,
    stop: crossbeam_channel::Receiver<()>,
) -> Result<()> {
    let mut etw = match EtwCollector::start() {
        Ok(collector) => Some(collector),
        Err(error) => {
            eprintln!("ETW unavailable; continuing in degraded mode and retrying: {error:#}");
            None
        }
    };
    let mut next_etw_retry = Instant::now() + Duration::from_secs(60);
    let mut collector = MetricCollector::new()?;
    // Leak forensics is a strict no-op (zero syscalls) until a handle- or
    // thread-growth finding is active; then it captures at most once a minute.
    let mut forensics = ForensicsEngine::new(WindowsForensicsSource::default());
    // ISR/DPC attribution is likewise a strict no-op (its per-sample
    // activity ring is pure memory work) until a dpcInterrupt finding is
    // active; then it runs one bounded kernel trace when the finding fires,
    // re-captures on a two-minute cadence until it holds three successful
    // traces, and backs off to every ten minutes.
    let mut interrupts = InterruptEngine::new(WindowsInterruptSource::default());
    // Crash-dump discovery scans the standard dump locations shortly after
    // start and then every five minutes; between scans it is a single
    // timestamp comparison, and triage headers are read once per new dump.
    let mut dumps = DumpEngine::new(WindowsDumpSource);
    let mut event_logs = EventLogCollector::default();
    let mut next_system_write = Instant::now();
    let mut next_process_write = Instant::now();
    let mut next_prune = Instant::now();
    let mut next_event_log_poll = Instant::now();
    let mut next_baseline_save = Instant::now() + Duration::from_secs(5 * 60);
    // Trailing window feeding `Calibration.demand` (`ratings::demand_bucket`,
    // Global Constraints: "trailing 10 min composite"). Bounded by timestamp
    // rather than count, since the sample cadence is a setting the user can
    // change.
    let mut recent_samples: VecDeque<SystemMetric> = VecDeque::new();
    // Which minutes of the trailing hour were heavy; see
    // [`observe_heavy_minute`]. Feeds the client's rating nudge.
    let mut heavy_minutes: VecDeque<i64> = VecDeque::new();
    // Launch history. The tracker turns this tick's drained ETW start/stop
    // events into rows; the joiner holds command lines only while the opt-in
    // setting is on (it is cleared the moment it goes off).
    let mut launches = LaunchTracker::new();
    let mut joiner = CmdlineJoiner::new();
    let mut cmdline_session: Option<CmdlineCollector> = None;
    let mut next_cmdline_session_retry = Instant::now();
    // Due immediately: a service that restarts more often than hourly must
    // still enforce the command-line retention window, and anything already
    // past it should go on this run's first sample, not an hour into it.
    let mut next_cmdline_prune = Instant::now();
    let mut process_totals = EtwCounterTotals::default();
    let mut cmdline_totals = EtwCounterTotals::default();
    let mut cmdlines_captured: u64 = 0;
    let mut cmdlines_redacted_fields: u64 = 0;
    let mut cmdlines_persist_failures: u64 = 0;
    // One line per failure mode, not one per event: a broken DPAPI or a
    // failing insert repeats every tick and must not flood the log.
    let mut cmdline_protect_logged = false;
    loop {
        let started = Instant::now();
        let settings = state
            .settings
            .read()
            .map_err(|_| anyhow!("settings lock poisoned"))?
            .clone();
        if etw.is_none() && Instant::now() >= next_etw_retry {
            match EtwCollector::start() {
                Ok(collector) => {
                    // Fresh session, fresh (zeroed) counters: tell the
                    // accumulator so the new session's totals are counted
                    // from zero rather than diffed against the old one's.
                    process_totals.session_ended();
                    etw = Some(collector);
                }
                Err(error) => {
                    eprintln!("ETW retry failed: {error:#}");
                    next_etw_retry = Instant::now() + Duration::from_secs(60);
                }
            }
        }
        let timestamp_ms = Utc::now().timestamp_millis();
        let etw_snapshot = etw
            .as_ref()
            .map_or_else(crate::etw::EtwSnapshot::default, EtwCollector::snapshot);
        let (system, processes, hardware) =
            collector.collect(timestamp_ms, &settings, &etw_snapshot)?;
        // Slide the trailing demand window: add this sample, then drop
        // whatever has aged out of the last ten minutes.
        recent_samples.push_back(system.clone());
        while recent_samples
            .front()
            .is_some_and(|sample| timestamp_ms - sample.timestamp_ms > DEMAND_WINDOW_MS)
        {
            recent_samples.pop_front();
        }
        // Built against the baseline as it stands *before* this sample is
        // folded into it, so an incident is judged by what was learned
        // before it and never against itself. That ordering is about
        // baseline maturity alone — the demand window this same call
        // classifies deliberately includes the sample just taken, because
        // "how loaded is this machine right now" must not lag a sample
        // behind the reading being judged.
        let calibration = build_calibration(recent_samples.make_contiguous(), &baselines);
        // Copied out so the snapshot block below can reuse this sample's
        // learning state and demand bucket without `calibration`'s
        // `&baselines` borrow living past the mutable baseline updates that
        // follow the evaluation.
        let learning = calibration.learning;
        let demand = calibration.demand;
        let heavy_minutes_trailing_hour =
            observe_heavy_minute(&mut heavy_minutes, demand, timestamp_ms);
        let learning_progress_pct = baselines.machine.learning_progress_pct();
        let learning_remaining_ms = baselines.machine.learning_remaining_ms();
        let (mut evaluation, quarantine) = {
            let mut engine = state
                .alerts
                .lock()
                .map_err(|_| anyhow!("alert lock poisoned"))?;
            // What the interrupt engine has made of the DPC finding so far,
            // and what the machine considers a normal kernel rate. Both gate
            // whether a DPC incident is worth interrupting the user for; the
            // verdict is the previous sample's, since a capture only runs
            // once a finding exists.
            engine.observe_interrupts(InterruptContext {
                verdict: interrupts.verdict_state(),
                corroborating_signals: interrupts.corroborating_signals(),
                dpc_p95: baselines.machine.dpc_rate.quantile(0.95),
                interrupt_p95: baselines.machine.interrupt_rate.quantile(0.95),
            });
            let evaluation = engine.evaluate(&system, &processes, &settings, calibration);
            // Which instances must not be folded into their own name's norm
            // this sample. Read under the same lock as the evaluation that
            // decided it, and small enough (bounded by the growth watch list)
            // to copy rather than hold the lock across the baseline update.
            let quarantine = engine.self_training_quarantine().clone();
            (evaluation, quarantine)
        };
        baselines
            .machine
            .observe(&system, processes.len(), timestamp_ms);
        for process in &processes {
            // An instance that has been climbing monotonically for half an
            // hour stops teaching its own executable name what "normal" is.
            // Note this stops *further* teaching only -- whatever its ramp
            // taught before it qualified is already folded in. See
            // `AlertEngine::self_training_quarantine` for what that does and
            // does not buy.
            if quarantine.contains(&(process.pid, process.started_at_ms)) {
                continue;
            }
            baselines.observe_process(process, timestamp_ms);
        }
        // Republish what the loop now knows about the machine, so a rating
        // arriving over the pipe before the next five-minute save reads this
        // sample's learning state and sketches rather than storage's older
        // copy. See [`AppState::baseline`].
        {
            let mut live = state
                .baseline
                .write()
                .map_err(|_| anyhow!("baseline lock poisoned"))?;
            live.clone_from(&baselines.machine);
        }

        // ---- Launch history --------------------------------------------
        // Opt-in command-line capture, toggled live. While the setting is
        // off there is no session at all, so no command line ever enters
        // this process -- turning it off also drops whatever the joiner was
        // still holding, so nothing captured before the flip can be
        // persisted after it.
        if settings.capture_command_lines {
            if cmdline_session.is_none() && Instant::now() >= next_cmdline_session_retry {
                match CmdlineCollector::start() {
                    Ok(collector) => {
                        cmdline_totals.session_ended();
                        cmdline_session = Some(collector);
                    }
                    Err(error) => {
                        // Fail soft: the machine allows eight system-logger
                        // sessions in total, and an exhausted pool means no
                        // command lines, never a failed sample.
                        eprintln!(
                            "command-line capture session unavailable; \
                             continuing without command lines: {error:#}"
                        );
                        next_cmdline_session_retry = Instant::now() + CMDLINE_SESSION_RETRY;
                    }
                }
            }
        } else if cmdline_session.take().is_some() {
            cmdline_totals.session_ended();
            joiner.clear();
            next_cmdline_session_retry = Instant::now();
        }
        if let Some(collector) = cmdline_session.as_ref() {
            for captured in collector.take_cmdlines() {
                // `offer` redacts before storing; the raw line dies here.
                joiner.offer(captured.pid, captured.start_ms, &captured.command_line);
            }
            // The MOF session sees every process on the machine, while only
            // tracked launches ever claim a line, so the ring must age out on
            // the clock and not merely under cap pressure -- otherwise stale
            // entries at the front push out captures still waiting for their
            // launch row to flush.
            joiner.evict_older_than(timestamp_ms);
        }
        // Drain the process-event queue every tick. The bounded channel is
        // the only thing between the ETW callback and this loop: a tick that
        // skips the drain costs events once 4096 pile up (`droppedChannel`).
        if let Some(collector) = etw.as_ref() {
            let by_pid: HashMap<u32, &ProcessMetric> = processes
                .iter()
                .map(|process| (process.pid, process))
                .collect();
            let live_lookup = |pid: u32| -> Option<LiveProcessInfo> {
                by_pid.get(&pid).map(|process| LiveProcessInfo {
                    name: process.name.clone(),
                    path: (!process.executable_path.is_empty())
                        .then(|| process.executable_path.clone()),
                    parent_pid: process.parent_pid,
                })
            };
            for event in collector.take_process_events() {
                match event {
                    ParsedProcessEvent::Start(props) => launches.on_start(props, &live_lookup),
                    ParsedProcessEvent::Stop(props) => launches.on_stop(props, timestamp_ms),
                }
            }
        }
        // The window sweep this sample already performed: `has_visible_window`
        // is the enumeration result for every sampled pid, which is exactly
        // what decides a launch's final window state.
        for process in &processes {
            launches.observe_window(process.pid, process.has_visible_window);
        }
        // Runs every tick even with ETW down, so pending rows still age out.
        let mut flushable = launches.drain_flushable(timestamp_ms);
        // Attaching only happens while the opt-in is active; with it off the
        // joiner is empty anyway, but the guard keeps that a policy rather
        // than an accident.
        let joined = if settings.capture_command_lines && cmdline_session.is_some() {
            join_command_lines(&mut joiner, &mut flushable)
        } else {
            Vec::new()
        };
        if !flushable.is_empty()
            && let Err(error) = state.storage.save_launches(&flushable)
        {
            eprintln!("failed to persist launch events: {error:#}");
        }
        for line in &joined {
            // Redacted already; encrypted here, so the only at-rest copy of
            // a command line is a DPAPI blob.
            match crate::dpapi::protect(line.redacted.as_bytes()) {
                Ok(blob) => match state.storage.save_launch_cmdline(
                    line.pid,
                    line.start_time_ms,
                    timestamp_ms,
                    &blob,
                ) {
                    Ok(()) => {
                        cmdlines_captured += 1;
                        cmdlines_redacted_fields += u64::from(line.redacted_fields);
                    }
                    Err(error) => {
                        // The join already consumed the capture, so this is
                        // unrecoverable loss: counted, not just logged once.
                        cmdlines_persist_failures += 1;
                        if !cmdline_protect_logged {
                            cmdline_protect_logged = true;
                            eprintln!("failed to persist a captured command line: {error:#}");
                        }
                    }
                },
                Err(status) => {
                    cmdlines_persist_failures += 1;
                    if !cmdline_protect_logged {
                        cmdline_protect_logged = true;
                        eprintln!(
                            "DPAPI encryption of a captured command line failed with status \
                             0x{status:08x}; command lines will not be stored"
                        );
                    }
                }
            }
        }
        if let Some(collector) = etw.as_ref() {
            process_totals.observe(EtwCounters::read(collector.health()));
        }
        if let Some(collector) = cmdline_session.as_ref() {
            cmdline_totals.observe(EtwCounters::read(collector.health()));
        }
        let launch_capture = {
            let process_etw = process_totals.totals();
            let cmdline_etw = cmdline_totals.totals();
            LaunchCaptureStatus {
                dropped_channel: process_etw
                    .dropped_channel
                    .saturating_add(cmdline_etw.dropped_channel),
                etw_events_lost: process_etw
                    .etw_events_lost
                    .saturating_add(cmdline_etw.etw_events_lost),
                malformed_events: process_etw
                    .malformed_events
                    .saturating_add(cmdline_etw.malformed_events),
                events_lost_query_failures: process_etw
                    .events_lost_query_failures
                    .saturating_add(cmdline_etw.events_lost_query_failures),
                cmdline_session_active: cmdline_session.is_some(),
                cmdlines_captured,
                cmdlines_redacted_fields,
                cmdlines_unmatched_evicted: joiner.unmatched_evicted(),
                cmdlines_persist_failures,
                ..launches.status()
            }
        };

        forensics.observe(&evaluation.active, timestamp_ms);
        forensics.decorate(&mut evaluation.active);
        forensics.decorate(&mut evaluation.changed);
        // The correlation window rides on every sample: system rates plus
        // the freshest GPU utilization the hardware sampler produced.
        let gpu_utilization = hardware
            .gpus
            .iter()
            .filter_map(|gpu| gpu.utilization_percent)
            .fold(None, |best: Option<f64>, value| {
                Some(best.map_or(value, |current| current.max(value)))
            });
        interrupts.record_activity(&system, gpu_utilization);
        interrupts.observe(&evaluation.active, timestamp_ms);
        interrupts.decorate(&mut evaluation.active);
        interrupts.decorate(&mut evaluation.changed);
        // Crash-dump findings are produced by their own engine (the dump
        // scan has its own five-minute cadence) and merge into the same
        // alert stream the detectors feed.
        evaluation.changed.extend(dumps.observe(timestamp_ms));
        evaluation.active.extend(dumps.active_alerts());
        evaluation
            .active
            .sort_by_key(|alert| std::cmp::Reverse(alert.first_seen_ms));
        state.storage.upsert_alerts(&evaluation.changed)?;
        {
            let mut snapshot = state
                .snapshot
                .write()
                .map_err(|_| anyhow!("snapshot lock poisoned"))?;
            snapshot.system = system.clone();
            snapshot.processes = processes.clone();
            snapshot.active_alerts = evaluation.active;
            snapshot.hardware = hardware;
            // Captured above, before this sample folded into the baseline --
            // reuse it rather than re-deriving learning state from a baseline
            // that has since observed one more point.
            snapshot.learning = learning;
            snapshot.learning_percent = learning.then_some(learning_progress_pct);
            // Observed minutes still owed, rounded up so a partial minute
            // still reads as time remaining. One learning period is 1 440
            // minutes, comfortably inside u16.
            snapshot.learning_minutes_left = learning.then(|| {
                (learning_remaining_ms.max(0) as u64)
                    .div_ceil(60_000)
                    .min(u16::MAX as u64) as u16
            });
            // The demand context clients read: the bucket the rating
            // offsets are looked up under, and how much of the trailing
            // hour was heavy enough to be worth asking about.
            snapshot.demand = Some(demand);
            snapshot.heavy_minutes_trailing_hour = Some(heavy_minutes_trailing_hour);
            // Launch-capture health, with this tick's ETW loss counters
            // already merged in (see `EtwCounterTotals`).
            snapshot.launch_capture = launch_capture;
        }
        if Instant::now() >= next_system_write {
            state.storage.insert_system(&system)?;
            next_system_write = Instant::now() + Duration::from_secs(10);
        }
        if Instant::now() >= next_process_write {
            state.storage.insert_processes(&processes, 64)?;
            next_process_write = Instant::now() + Duration::from_secs(30);
        }
        if Instant::now() >= next_event_log_poll {
            let logs = event_logs.poll(timestamp_ms, &settings.agent_process_patterns);
            if let Err(error) = state.storage.insert_diagnostic_logs(&logs) {
                let message = format!("failed to persist Windows diagnostic logs: {error:#}");
                eprintln!("{message}");
                event_logs.note_storage_error(message);
            }
            *state
                .log_status
                .lock()
                .map_err(|_| anyhow!("diagnostic-log status lock poisoned"))? = event_logs.status();
            next_event_log_poll = Instant::now() + Duration::from_secs(30);
        }
        if Instant::now() >= next_prune {
            state.storage.prune(&settings, timestamp_ms)?;
            next_prune = Instant::now() + Duration::from_secs(24 * 60 * 60);
        }
        if Instant::now() >= next_cmdline_prune {
            // Command lines run on their own, much shorter clock than the
            // daily prune everything else uses. Runs whether or not capture
            // is currently on: turning the setting off must not leave
            // already-captured lines sitting past their retention.
            let cutoff_ms =
                timestamp_ms - i64::from(settings.command_line_retention_hours) * 3_600_000;
            if let Err(error) = state.storage.prune_launch_cmdlines(cutoff_ms) {
                eprintln!("failed to prune captured command lines: {error:#}");
            }
            next_cmdline_prune = Instant::now() + CMDLINE_PRUNE_INTERVAL;
        }
        if Instant::now() >= next_baseline_save {
            state
                .storage
                .save_baselines(&baselines.to_rows(), timestamp_ms)?;
            next_baseline_save = Instant::now() + Duration::from_secs(5 * 60);
        }
        let delay =
            Duration::from_millis(settings.sample_interval_ms).saturating_sub(started.elapsed());
        match stop.recv_timeout(delay) {
            Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
        }
    }
    // Clean shutdown: keep what this run learned, so the next start resumes
    // its baselines instead of re-entering the learning period. A failure
    // here costs learned norms, never the shutdown itself.
    if let Err(error) = state
        .storage
        .save_baselines(&baselines.to_rows(), Utc::now().timestamp_millis())
    {
        eprintln!("failed to persist baselines on shutdown: {error:#}");
    }
    Ok(())
}

pub fn default_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("PcPulse")
}

pub fn build_process_tree(processes: &[ProcessMetric]) -> Vec<ProcessNode> {
    let by_pid: HashMap<u32, &ProcessMetric> = processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for process in processes {
        children
            .entry(process.parent_pid)
            .or_default()
            .push(process.pid);
    }
    for list in children.values_mut() {
        list.sort_unstable();
    }
    let roots: Vec<u32> = processes
        .iter()
        .filter(|process| {
            process.parent_pid == process.pid || !by_pid.contains_key(&process.parent_pid)
        })
        .map(|process| process.pid)
        .collect();
    let mut visited = HashSet::new();
    let mut result = Vec::new();
    for pid in roots {
        if let Some(node) = build_node(pid, &by_pid, &children, &mut visited) {
            result.push(node);
        }
    }
    for process in processes {
        if let Some(node) = build_node(process.pid, &by_pid, &children, &mut visited) {
            result.push(node);
        }
    }
    result
}

fn build_node(
    pid: u32,
    by_pid: &HashMap<u32, &ProcessMetric>,
    children: &HashMap<u32, Vec<u32>>,
    visited: &mut HashSet<u32>,
) -> Option<ProcessNode> {
    if !visited.insert(pid) {
        return None;
    }
    let process = (*by_pid.get(&pid)?).clone();
    let nodes = children
        .get(&pid)
        .into_iter()
        .flatten()
        .filter_map(|child| build_node(*child, by_pid, children, visited))
        .collect();
    Some(ProcessNode {
        process,
        children: nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DemandBucket, DemandDetail, DiagnosticLogStatus, HistoryResponse, OpenIncidentRef,
        OptimizationPlan, PlanAgent, PlanConstraints, Rating, RatingVerdict, Severity,
    };

    fn process(pid: u32, parent_pid: u32) -> ProcessMetric {
        ProcessMetric {
            timestamp_ms: 0,
            pid,
            parent_pid,
            name: pid.to_string(),
            executable_path: String::new(),
            cpu_percent: 0.0,
            working_set_bytes: 0,
            private_bytes: 0,
            handle_count: 0,
            thread_count: 0,
            read_bytes_per_sec: 0.0,
            write_bytes_per_sec: 0.0,
            total_read_bytes: 0,
            total_write_bytes: 0,
            started_at_ms: i64::from(pid),
            session_id: 0,
            responsive: true,
            has_visible_window: false,
            launch_duration_ms: None,
            is_agent_candidate: false,
        }
    }

    #[test]
    fn stored_ratings_reach_the_engine_and_the_agent_context() {
        // The engine's copy of the policy offsets is a cache of a pure
        // function over the ratings table, so a restart -- or any new rating
        // -- has to be able to rebuild it from storage alone.
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        assert!(
            state.alerts.lock().unwrap().rating_offsets().is_empty(),
            "a machine nobody has rated carries no offsets"
        );

        let now_ms = Utc::now().timestamp_millis();
        state
            .storage
            .save_rating(&Rating {
                id: "rating-1".into(),
                at_ms: now_ms,
                verdict: RatingVerdict::Good,
                demand: DemandBucket::Heavy,
                demand_detail: DemandDetail {
                    cpu_percent: 0.0,
                    cpu_percentile: None,
                    memory_occupancy_pct: 0.0,
                    memory_percentile: None,
                    disk_latency_ms: 0.0,
                    disk_percentile: None,
                    io_bytes_per_sec: 0.0,
                    io_percentile: None,
                },
                digest: serde_json::Value::Null,
                open_incidents: vec![OpenIncidentRef {
                    fingerprint: "collectorBudget:1".into(),
                    kind: "collectorBudget".into(),
                    severity: Severity::Warning,
                    notify: true,
                    acknowledged: false,
                }],
                during_learning: false,
                unexplained: false,
            })
            .unwrap();
        state.refresh_rating_offsets().unwrap();

        let entries = state.alerts.lock().unwrap().rating_offsets().entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, "collectorBudget");
        assert_eq!(entries[0].bucket, DemandBucket::Heavy);
        assert!((entries[0].offset - 0.05).abs() < 1e-9);
    }

    fn launch_event(pid: u32, start_time_ms: i64) -> LaunchEvent {
        LaunchEvent {
            pid,
            start_time_ms,
            stop_time_ms: None,
            exit_code: None,
            exe_name: "x.exe".into(),
            exe_path: r"c:\x.exe".into(),
            raw_image_path: None,
            session_id: 1,
            parent_pid: 4,
            lineage: Vec::new(),
            window_state: crate::models::WindowState::Running,
            console_host: false,
            command_line: None,
        }
    }

    #[test]
    fn etw_counter_totals_accumulate_deltas_and_survive_a_collector_restart() {
        let mut totals = EtwCounterTotals::default();
        totals.observe(EtwCounters {
            dropped_channel: 10,
            etw_events_lost: 4,
            malformed_events: 1,
            events_lost_query_failures: 0,
        });
        totals.observe(EtwCounters {
            dropped_channel: 25,
            etw_events_lost: 4,
            malformed_events: 3,
            events_lost_query_failures: 2,
        });
        assert_eq!(
            totals.totals(),
            EtwCounters {
                dropped_channel: 25,
                etw_events_lost: 4,
                malformed_events: 3,
                events_lost_query_failures: 2,
            }
        );

        // The collector died and was rebuilt: its counters restart at zero.
        // A naive `current - previous` would underflow here; the totals must
        // instead keep what was already counted and add the new session's
        // absolute values as they arrive.
        totals.observe(EtwCounters {
            dropped_channel: 3,
            etw_events_lost: 0,
            malformed_events: 0,
            events_lost_query_failures: 0,
        });
        assert_eq!(
            totals.totals(),
            EtwCounters {
                dropped_channel: 28,
                etw_events_lost: 4,
                malformed_events: 3,
                events_lost_query_failures: 2,
            },
            "a restart must never rewind or underflow the reported loss"
        );
        totals.observe(EtwCounters {
            dropped_channel: 5,
            ..EtwCounters::default()
        });
        assert_eq!(totals.totals().dropped_channel, 30);
    }

    #[test]
    fn etw_counter_totals_count_a_fresh_session_from_zero() {
        // The loop announces a deliberate restart (a new collector built
        // after ETW came back), so the new session's first read is counted
        // in full even if it happens to equal the dead session's last one.
        let mut totals = EtwCounterTotals::default();
        totals.observe(EtwCounters {
            dropped_channel: 7,
            ..EtwCounters::default()
        });
        totals.session_ended();
        totals.observe(EtwCounters {
            dropped_channel: 7,
            ..EtwCounters::default()
        });
        assert_eq!(totals.totals().dropped_channel, 14);
    }

    #[test]
    fn joined_command_lines_never_ride_along_in_the_launch_event_payload() {
        // The redacted line goes to the encrypted table only. A copy left on
        // the LaunchEvent would be written to `launch_events` as plain JSON
        // -- a second, unencrypted at-rest copy of the very data the design
        // redacts and DPAPI-protects.
        let mut joiner = CmdlineJoiner::new();
        joiner.offer(500, 10_000, "tool.exe --password hunter2");
        let mut events = vec![launch_event(500, 10_100), launch_event(600, 10_100)];
        let joined = join_command_lines(&mut joiner, &mut events);

        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].pid, 500);
        assert_eq!(joined[0].start_time_ms, 10_100);
        assert!(!joined[0].redacted.contains("hunter2"));
        assert!(joined[0].redacted_fields >= 1);
        assert!(
            events.iter().all(|event| event.command_line.is_none()),
            "no command line may be persisted in the launch_events payload"
        );
        let payload = serde_json::to_string(&events[0]).unwrap();
        assert!(!payload.contains("commandLine"), "{payload}");
    }

    #[test]
    fn builds_parent_child_tree() {
        let tree = build_process_tree(&[process(10, 0), process(11, 10), process(12, 11)]);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].children[0].children[0].process.pid, 12);
    }

    fn test_state(directory: &tempfile::TempDir) -> AppState {
        AppState {
            snapshot: RwLock::new(Snapshot::default()),
            baseline: RwLock::new(crate::baselines::MachineBaseline::new(0)),
            settings: RwLock::new(Settings::default()),
            storage: Arc::new(Storage::open(&directory.path().join("history.db")).unwrap()),
            alerts: Mutex::new(AlertEngine::default()),
            log_status: Mutex::new(DiagnosticLogStatus::default()),
            issued_contexts: Mutex::new(VecDeque::new()),
            settings_path: directory.path().join("settings.json"),
            live: LiveEngine::windows(),
        }
    }

    #[test]
    fn live_command_serves_a_sample_payload_over_the_pipe_contract() {
        use crate::models::LiveSample;
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        // Mirror the pipe path exactly: parse the wire command, dispatch it,
        // and require a decodable ok payload. The engine has not warmed
        // (this may be the request that starts it), so `available` must be
        // false — never fabricated rates.
        let request: PipeRequest = serde_json::from_str(r#"{"command":"live"}"#).unwrap();
        match state.handle(request) {
            PipeResponse::Ok { data } => {
                let sample: LiveSample = serde_json::from_value(data).unwrap();
                assert!(!sample.available, "unwarmed live channel must say so");
            }
            PipeResponse::Error { code, message } => {
                panic!("live must answer ok on a current service: {code} {message}")
            }
        }
    }

    #[test]
    fn archive_command_persists_the_flag_over_the_pipe_contract() {
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        let alert = crate::models::Alert {
            id: "finding-1".into(),
            kind: "sustainedCpu".into(),
            severity: crate::models::Severity::Warning,
            first_seen_ms: 100,
            last_seen_ms: 200,
            process_id: Some(42),
            process_name: Some("worker.exe".into()),
            title: "Sustained CPU usage".into(),
            explanation: "test".into(),
            evidence: Vec::new(),
            recommendation: "test".into(),
            acknowledged: false,
            occurrence_count: 1,
            resolved_at_ms: None,
            archived: false,
            fingerprint: String::new(),
            state: crate::models::IncidentState::Open,
            quality: crate::models::AlertQuality::default(),
            notify: true,
            notify_generation: 0,
        };
        state.storage.upsert_alerts(&[alert]).unwrap();

        // Mirror the pipe path exactly: serialize the wire command the way a
        // client does, parse it back, dispatch it.
        let wire = serde_json::to_string(&PipeRequest::ArchiveAlert {
            alert_id: "finding-1".into(),
            archived: true,
        })
        .unwrap();
        let request: PipeRequest = serde_json::from_str(&wire).unwrap();
        match state.handle(request) {
            PipeResponse::Ok { data } => assert_eq!(data["archived"], true),
            PipeResponse::Error { code, message } => panic!("archive failed: {code} {message}"),
        }
        assert!(state.storage.alerts(0, 10).unwrap()[0].archived);

        // Recovery is the same command with archived=false; an unknown id
        // answers ok with archived=false, exactly like acknowledge.
        let recover = PipeRequest::ArchiveAlert {
            alert_id: "finding-1".into(),
            archived: false,
        };
        match state.handle(recover) {
            PipeResponse::Ok { data } => assert_eq!(data["archived"], true),
            PipeResponse::Error { code, message } => panic!("recover failed: {code} {message}"),
        }
        assert!(!state.storage.alerts(0, 10).unwrap()[0].archived);
        match state.handle(PipeRequest::ArchiveAlert {
            alert_id: "unknown".into(),
            archived: true,
        }) {
            PipeResponse::Ok { data } => assert_eq!(data["archived"], false),
            PipeResponse::Error { code, message } => panic!("unknown id errored: {code} {message}"),
        }
    }

    #[test]
    fn saved_plan_must_match_a_recent_issued_context() {
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        let now_ms = Utc::now().timestamp_millis();
        let snapshot = Snapshot::default();
        let settings = Settings::default();
        let context = build_agent_context(AgentContextSource {
            now_ms,
            window_hours: 1,
            snapshot: &snapshot,
            settings: &settings,
            history: HistoryResponse {
                system: Vec::new(),
                processes: Vec::new(),
            },
            logs: Vec::new(),
            log_status: DiagnosticLogStatus::default(),
            alerts: Vec::new(),
            rating_offsets: Vec::new(),
        });
        state.remember_context(&context).unwrap();
        let mut plan = OptimizationPlan {
            schema_version: 1,
            plan_id: "plan".into(),
            context_id: context.context_id,
            generated_at_ms: context.generated_at_ms,
            agent: PlanAgent {
                name: "pcpulse-systems-analyzer".into(),
                model: "codex".into(),
            },
            summary: "No defensible issue.".into(),
            confidence: "low".into(),
            diagnoses: Vec::new(),
            actions: Vec::new(),
            constraints: PlanConstraints {
                never_auto_terminate: true,
                never_auto_apply: true,
                confirmation_required_for_mutations: true,
            },
        };
        assert!(state.validate_plan_context(&plan).is_ok());
        plan.context_id = "substituted".into();
        assert!(state.validate_plan_context(&plan).is_err());
    }

    fn system_sample_at(cpu_percent: f64, at_ms: i64) -> SystemMetric {
        SystemMetric {
            timestamp_ms: at_ms,
            cpu_percent,
            memory_used_bytes: 1_000,
            memory_total_bytes: 1_000_000,
            ..SystemMetric::default()
        }
    }

    fn active_alert(kind: &str, notify: bool, acknowledged: bool) -> crate::models::Alert {
        crate::models::Alert {
            id: format!("{kind}-1"),
            kind: kind.into(),
            severity: crate::models::Severity::Warning,
            first_seen_ms: 0,
            last_seen_ms: 0,
            process_id: None,
            process_name: None,
            title: "t".into(),
            explanation: "e".into(),
            evidence: Vec::new(),
            recommendation: "r".into(),
            acknowledged,
            occurrence_count: 1,
            resolved_at_ms: None,
            archived: false,
            fingerprint: format!("{kind}:1"),
            state: crate::models::IncidentState::Open,
            quality: crate::models::AlertQuality::default(),
            notify,
            notify_generation: 0,
        }
    }

    /// A matured (non-learning) baseline published the same way the sampling
    /// loop publishes one, so `assemble_rating`'s live `state.baseline`
    /// handle picks it up. Persisted as well, mirroring the loop's
    /// five-minute save.
    fn seed_matured_baseline(state: &AppState) {
        let mut store = crate::baselines::BaselineStore::new(0);
        store.machine.observed_ms = crate::baselines::LEARNING_PERIOD_MS;
        state
            .storage
            .save_baselines(&store.to_rows(), Utc::now().timestamp_millis())
            .unwrap();
        state.baseline.write().unwrap().clone_from(&store.machine);
    }

    #[test]
    fn rating_commands_use_the_pinned_serde_spelling() {
        // The brief pins these two wire spellings explicitly: `"addRating"`
        // and `"getRatings"`, matching the existing camelCase command
        // convention (see e.g. `"acknowledgeAlert"`, `"archiveAlert"`).
        let add = serde_json::to_string(&PipeRequest::AddRating {
            verdict: RatingVerdict::Good,
        })
        .unwrap();
        assert!(add.contains("\"command\":\"addRating\""), "wire: {add}");
        let get = serde_json::to_string(&PipeRequest::GetRatings { limit: 10 }).unwrap();
        assert!(get.contains("\"command\":\"getRatings\""), "wire: {get}");
    }

    #[test]
    fn add_rating_assembles_a_populated_record() {
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        let now_ms = Utc::now().timestamp_millis();

        // A fresh (unmatured) baseline degrades every percentile to `None`
        // and falls back to the fixed cutoffs -- CPU >= 80 alone is heavy --
        // so seeding just the trailing samples is enough to prove the
        // bucket/detail actually came from them.
        for offset in 0..5 {
            state
                .storage
                .insert_system(&system_sample_at(90.0, now_ms - offset * 60_000))
                .unwrap();
        }
        {
            let mut snapshot = state.snapshot.write().unwrap();
            snapshot.active_alerts = vec![active_alert("sustainedCpu", true, false)];
        }

        let response = state.handle(PipeRequest::AddRating {
            verdict: RatingVerdict::Good,
        });
        let rating: Rating = match response {
            PipeResponse::Ok { data } => serde_json::from_value(data).unwrap(),
            PipeResponse::Error { code, message } => {
                panic!("addRating failed: {code} {message}")
            }
        };

        assert_eq!(rating.demand, DemandBucket::Heavy, "{rating:?}");
        assert_eq!(rating.demand_detail.cpu_percent, 90.0);
        assert_eq!(rating.open_incidents.len(), 1);
        assert_eq!(rating.open_incidents[0].kind, "sustainedCpu");
        assert!(rating.open_incidents[0].notify);
        assert!(
            !rating.digest.is_null(),
            "digest must be populated, not a placeholder"
        );
        assert!(
            rating.digest.get("systemRollup").is_some(),
            "digest missing systemRollup: {}",
            rating.digest
        );
        assert!(!rating.unexplained, "a good rating is never unexplained");

        // Stored, and retrievable via GetRatings.
        let stored = state.storage.ratings(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, rating.id);
    }

    #[test]
    fn add_rating_unexplained_truth_table() {
        // Spec truth table: sluggish + nothing notifying => true;
        // sluggish + something notifying => false; good/acceptable => always
        // false, whatever was open.
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);

        let unexplained_for =
            |state: &AppState, verdict: RatingVerdict, alerts: Vec<crate::models::Alert>| -> bool {
                {
                    let mut snapshot = state.snapshot.write().unwrap();
                    snapshot.active_alerts = alerts;
                }
                match state.handle(PipeRequest::AddRating { verdict }) {
                    PipeResponse::Ok { data } => {
                        serde_json::from_value::<Rating>(data).unwrap().unexplained
                    }
                    PipeResponse::Error { code, message } => {
                        panic!("addRating failed: {code} {message}")
                    }
                }
            };

        assert!(
            unexplained_for(&state, RatingVerdict::Sluggish, Vec::new()),
            "sluggish with nothing notifying must be unexplained"
        );
        assert!(
            !unexplained_for(
                &state,
                RatingVerdict::Sluggish,
                vec![active_alert("sustainedCpu", true, false)]
            ),
            "sluggish while something is notifying is explained"
        );
        assert!(
            !unexplained_for(
                &state,
                RatingVerdict::Good,
                vec![active_alert("sustainedCpu", true, false)]
            ),
            "good is never unexplained"
        );
        assert!(
            !unexplained_for(&state, RatingVerdict::Acceptable, Vec::new()),
            "acceptable is never unexplained"
        );
        // An acknowledged incident does not count as "notifying" -- mirrors
        // `quality::derive_offsets`'s own false-positive definition.
        assert!(
            unexplained_for(
                &state,
                RatingVerdict::Sluggish,
                vec![active_alert("sustainedCpu", true, true)]
            ),
            "an acknowledged incident leaves sluggish unexplained"
        );
    }

    #[test]
    fn add_rating_refreshes_engine_offsets_without_a_separate_call() {
        // Merge-gate item: the AddRating handler must call
        // `refresh_rating_offsets()` itself after saving, so the very next
        // evaluation already honors the rating just given -- the caller
        // should never have to remember to do it.
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        seed_matured_baseline(&state); // non-learning, so the rating is not inert
        {
            let mut snapshot = state.snapshot.write().unwrap();
            snapshot.active_alerts = vec![active_alert("sustainedCpu", true, false)];
        }
        assert!(state.alerts.lock().unwrap().rating_offsets().is_empty());

        match state.handle(PipeRequest::AddRating {
            verdict: RatingVerdict::Good,
        }) {
            PipeResponse::Ok { .. } => {}
            PipeResponse::Error { code, message } => panic!("addRating failed: {code} {message}"),
        }

        let entries = state.alerts.lock().unwrap().rating_offsets().entries();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].kind, "sustainedCpu");
        assert!((entries[0].offset - 0.05).abs() < 1e-9);
    }

    #[test]
    fn get_ratings_returns_newest_first_clamped_to_the_policy_bound() {
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        let base_ms = Utc::now().timestamp_millis();
        let stored = POLICY_OFFSET_RATINGS + 20;
        for index in 0..stored as i64 {
            state
                .storage
                .save_rating(&Rating {
                    id: format!("rating-{index}"),
                    at_ms: base_ms + index,
                    verdict: RatingVerdict::Good,
                    demand: DemandBucket::Light,
                    demand_detail: DemandDetail {
                        cpu_percent: 0.0,
                        cpu_percentile: None,
                        memory_occupancy_pct: 0.0,
                        memory_percentile: None,
                        disk_latency_ms: 0.0,
                        disk_percentile: None,
                        io_bytes_per_sec: 0.0,
                        io_percentile: None,
                    },
                    digest: serde_json::Value::Null,
                    open_incidents: Vec::new(),
                    during_learning: false,
                    unexplained: false,
                })
                .unwrap();
        }

        let response = state.handle(PipeRequest::GetRatings { limit: 1_000 });
        let ratings: Vec<Rating> = match response {
            PipeResponse::Ok { data } => serde_json::from_value(data).unwrap(),
            PipeResponse::Error { code, message } => panic!("getRatings failed: {code} {message}"),
        };
        assert_eq!(
            ratings.len(),
            POLICY_OFFSET_RATINGS,
            "must clamp to the policy bound however high the ask"
        );
        assert_eq!(
            ratings[0].id,
            format!("rating-{}", stored - 1),
            "newest first: {:?}",
            ratings.iter().map(|r| &r.id).take(3).collect::<Vec<_>>()
        );
        assert_eq!(
            ratings[POLICY_OFFSET_RATINGS - 1].id,
            format!("rating-{}", stored - POLICY_OFFSET_RATINGS)
        );

        // The clamp is a ceiling, not a floor: the display and the engine
        // both ask for exactly `POLICY_OFFSET_RATINGS`, and that ask must
        // come back whole -- otherwise the incidents pane's offset figure
        // is derived from less history than the policy applies.
        let response = state.handle(PipeRequest::GetRatings {
            limit: POLICY_OFFSET_RATINGS,
        });
        let ratings: Vec<Rating> = match response {
            PipeResponse::Ok { data } => serde_json::from_value(data).unwrap(),
            PipeResponse::Error { code, message } => panic!("getRatings failed: {code} {message}"),
        };
        assert_eq!(ratings.len(), POLICY_OFFSET_RATINGS);

        // A smaller ask is still honored verbatim.
        let response = state.handle(PipeRequest::GetRatings { limit: 5 });
        let ratings: Vec<Rating> = match response {
            PipeResponse::Ok { data } => serde_json::from_value(data).unwrap(),
            PipeResponse::Error { code, message } => panic!("getRatings failed: {code} {message}"),
        };
        assert_eq!(ratings.len(), 5);
    }

    /// Drives all four demand channels (CPU, memory, disk latency, disk IO)
    /// off the same value, mirroring `ratings::tests::full_sample`: a
    /// baseline seeded only on CPU leaves the other channels at a constant
    /// (degenerate) zero, and a zero-valued sample then reads back as that
    /// channel's own 50th percentile rather than its 0th -- contaminating
    /// the composite into Moderate even for a genuinely idle window.
    fn full_sample_at(value: f64, at_ms: i64) -> SystemMetric {
        SystemMetric {
            timestamp_ms: at_ms,
            cpu_percent: value,
            memory_used_bytes: (value * 10_000_000_000.0) as u64,
            memory_total_bytes: 1_000_000_000_000,
            disk_latency_ms: value,
            disk_read_bytes_per_sec: value * 1_000.0,
            disk_write_bytes_per_sec: value * 1_000.0,
            ..SystemMetric::default()
        }
    }

    #[test]
    fn heavy_minutes_counts_distinct_heavy_minutes_over_a_trailing_hour() {
        // The nudge gate is "at least ten minutes of the trailing hour were
        // heavy". Samples arrive at whatever cadence the user has configured,
        // so heaviness is counted in distinct wall-clock minutes rather than
        // in samples -- a machine sampling twice a second must not reach ten
        // "minutes" in five seconds.
        let mut marks = VecDeque::new();
        let mut minutes = 0;
        for index in 0..24 {
            minutes = observe_heavy_minute(&mut marks, DemandBucket::Heavy, index * 30_000);
        }
        assert_eq!(
            minutes, 12,
            "24 half-minute heavy samples cover 12 distinct minutes"
        );

        // Light and moderate samples add nothing; only the window moves.
        assert_eq!(
            observe_heavy_minute(&mut marks, DemandBucket::Light, 12 * 60_000),
            12
        );
        assert_eq!(
            observe_heavy_minute(&mut marks, DemandBucket::Moderate, 13 * 60_000),
            12
        );

        // The window is trailing: a minute exactly one hour old still counts,
        // and one past that has aged out.
        assert_eq!(
            observe_heavy_minute(&mut marks, DemandBucket::Light, 3_600_000),
            12,
            "the minute at t=0 is exactly one hour old and still counts"
        );
        assert_eq!(
            observe_heavy_minute(&mut marks, DemandBucket::Light, 3_600_001),
            11,
            "one millisecond later the oldest minute has aged out"
        );
        assert_eq!(
            observe_heavy_minute(&mut marks, DemandBucket::Light, 4_320_000),
            0,
            "an hour after the last heavy minute nothing is left"
        );
    }

    #[test]
    fn a_rating_taken_as_the_baseline_matures_is_not_stamped_during_learning() {
        // The sampling loop persists baselines every five minutes, so what
        // storage holds can be up to that stale. If a rating read its
        // learning state from storage, the one rating given inside that
        // window at the 24-hour crossing would be permanently -- and
        // wrongly -- stamped `during_learning`, which makes it inert for the
        // notification policy forever. The rating reads the live handle the
        // sampling loop publishes each sample instead.
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        let now_ms = Utc::now().timestamp_millis();

        // Storage still holds the last periodic save: a baseline that had
        // not yet matured.
        let learning_store = crate::baselines::BaselineStore::new(now_ms);
        assert!(learning_store.machine.is_learning());
        state
            .storage
            .save_baselines(&learning_store.to_rows(), now_ms)
            .unwrap();

        // The live handle -- what the loop is actually working with -- has
        // since crossed maturity.
        let mut matured = crate::baselines::MachineBaseline::new(0);
        matured.observed_ms = crate::baselines::LEARNING_PERIOD_MS;
        assert!(!matured.is_learning());
        *state.baseline.write().unwrap() = matured;

        let rating: Rating = match state.handle(PipeRequest::AddRating {
            verdict: RatingVerdict::Good,
        }) {
            PipeResponse::Ok { data } => serde_json::from_value(data).unwrap(),
            PipeResponse::Error { code, message } => panic!("addRating failed: {code} {message}"),
        };
        assert!(
            !rating.during_learning,
            "a rating given after the live baseline matured must not be inert"
        );
    }

    #[test]
    fn build_calibration_wires_demand_bucket_from_the_trailing_window() {
        // Tripwire for the sampling loop's TODO(ratings) wiring point:
        // this must fail the instant `build_calibration` (the function the
        // loop actually calls) reverts to `Calibration::default().demand`,
        // which is always `Light` regardless of load.
        let mut machine = crate::baselines::MachineBaseline::new(0);
        for i in 0..2_000 {
            let value = (i % 100) as f64;
            machine.observe(
                &full_sample_at(value, i as i64 * 5_000),
                400,
                i as i64 * 5_000,
            );
        }
        let p95 = machine.cpu_percent.quantile(0.95).unwrap();
        let mut baselines = BaselineStore::new(0);
        baselines.machine = machine;

        let heavy_window: Vec<SystemMetric> =
            (0..10).map(|i| full_sample_at(p95, i * 1_000)).collect();
        let calibration = build_calibration(&heavy_window, &baselines);
        assert_eq!(
            calibration.demand,
            DemandBucket::Heavy,
            "a genuinely heavy trailing window must not read back as the default Light bucket"
        );

        let light_window: Vec<SystemMetric> =
            (0..10).map(|i| full_sample_at(0.0, i * 1_000)).collect();
        let light_calibration = build_calibration(&light_window, &baselines);
        assert_eq!(light_calibration.demand, DemandBucket::Light);
    }

    // -- Launch history pipe commands (Task 8) -------------------------

    #[test]
    fn launch_history_commands_use_the_pinned_serde_spelling() {
        let groups = serde_json::to_string(&PipeRequest::GetLaunchGroups {
            from_ms: None,
            console_hosts_only: None,
            limit: None,
        })
        .unwrap();
        assert!(
            groups.contains("\"command\":\"getLaunchGroups\""),
            "wire: {groups}"
        );

        let occurrences = serde_json::to_string(&PipeRequest::GetLaunchOccurrences {
            exe_path: r"c:\a.exe".into(),
            lineage_sig: "explorer.exe".into(),
            from_ms: None,
            limit: None,
        })
        .unwrap();
        assert!(
            occurrences.contains("\"command\":\"getLaunchOccurrences\""),
            "wire: {occurrences}"
        );
        assert!(
            occurrences.contains("\"exe_path\":\"c:\\\\a.exe\""),
            "wire: {occurrences}"
        );
        assert!(
            occurrences.contains("\"lineage_sig\":\"explorer.exe\""),
            "wire: {occurrences}"
        );

        let delete = serde_json::to_string(&PipeRequest::DeleteCommandLines).unwrap();
        assert!(
            delete.contains("\"command\":\"deleteCommandLines\""),
            "wire: {delete}"
        );

        // Requests parse with only fromMs/consoleHostsOnly/limit omitted too
        // -- the request-side optional fields the brief pins.
        let parsed: PipeRequest = serde_json::from_str(r#"{"command":"getLaunchGroups"}"#).unwrap();
        assert!(matches!(
            parsed,
            PipeRequest::GetLaunchGroups {
                from_ms: None,
                console_hosts_only: None,
                limit: None
            }
        ));
    }

    fn launch_event_with_lineage(
        pid: u32,
        start_time_ms: i64,
        exe_path: &str,
        lineage_names: &[&str],
    ) -> LaunchEvent {
        let mut event = launch_event(pid, start_time_ms);
        event.exe_path = exe_path.to_string();
        event.exe_name = exe_path.rsplit(['\\', '/']).next().unwrap().to_string();
        event.console_host = crate::launches::is_console_host(&event.exe_name);
        event.lineage = lineage_names
            .iter()
            .enumerate()
            .map(|(index, name)| crate::models::LineageEntry {
                pid: 900 + index as u32,
                name: name.to_string(),
                path: None,
            })
            .collect();
        event.window_state = crate::models::WindowState::NeverWindowed;
        event.stop_time_ms = Some(start_time_ms + 500);
        event
    }

    #[test]
    fn get_launch_groups_serves_grouped_stored_events() {
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        let now_ms = Utc::now().timestamp_millis();

        let events = vec![
            launch_event_with_lineage(1, now_ms - 1_000, r"c:\a.exe", &["explorer.exe"]),
            launch_event_with_lineage(2, now_ms - 500, r"c:\a.exe", &["explorer.exe"]),
            launch_event_with_lineage(3, now_ms, r"c:\b.exe", &["cmd.exe"]),
        ];
        state.storage.save_launches(&events).unwrap();

        let response = state.handle(PipeRequest::GetLaunchGroups {
            from_ms: None,
            console_hosts_only: None,
            limit: None,
        });
        let data = match response {
            PipeResponse::Ok { data } => data,
            PipeResponse::Error { code, message } => {
                panic!("getLaunchGroups failed: {code} {message}")
            }
        };
        let groups: Vec<crate::launches::LaunchGroup> =
            serde_json::from_value(data["groups"].clone()).unwrap();
        assert_eq!(groups.len(), 2);
        let a_group = groups.iter().find(|g| g.exe_path == r"c:\a.exe").unwrap();
        assert_eq!(a_group.count, 2);
        assert_eq!(a_group.lineage_sig, "explorer.exe");
    }

    #[test]
    fn get_launch_groups_console_hosts_only_filters() {
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        let now_ms = Utc::now().timestamp_millis();

        let events = vec![
            launch_event_with_lineage(1, now_ms, r"c:\windows\system32\cmd.exe", &[]),
            launch_event_with_lineage(2, now_ms, r"c:\a.exe", &[]),
        ];
        state.storage.save_launches(&events).unwrap();

        let response = state.handle(PipeRequest::GetLaunchGroups {
            from_ms: None,
            console_hosts_only: Some(true),
            limit: None,
        });
        let data = match response {
            PipeResponse::Ok { data } => data,
            PipeResponse::Error { code, message } => {
                panic!("getLaunchGroups failed: {code} {message}")
            }
        };
        let groups: Vec<crate::launches::LaunchGroup> =
            serde_json::from_value(data["groups"].clone()).unwrap();
        assert_eq!(groups.len(), 1);
        assert!(groups[0].console_host);
    }

    #[test]
    fn get_launch_groups_limit_is_clamped_to_the_transport_bound() {
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        let response = state.handle(PipeRequest::GetLaunchGroups {
            from_ms: None,
            console_hosts_only: None,
            limit: Some(1_000_000),
        });
        // Nothing is stored, so the clamp itself can only be verified by
        // reading the code path succeeding without error for an absurd ask
        // -- the exhaustive over-cap behavior is covered at the
        // `group_launches` unit level (`limit_truncates_after_sorting_not_before`).
        match response {
            PipeResponse::Ok { .. } => {}
            PipeResponse::Error { code, message } => {
                panic!("getLaunchGroups failed: {code} {message}")
            }
        }
    }

    #[test]
    fn get_launch_occurrences_returns_only_the_matching_group_newest_first() {
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        let now_ms = Utc::now().timestamp_millis();

        let events = vec![
            launch_event_with_lineage(1, now_ms - 2_000, r"c:\a.exe", &["explorer.exe"]),
            launch_event_with_lineage(2, now_ms - 1_000, r"c:\a.exe", &["explorer.exe"]),
            // Different lineage under the same exe: must not appear.
            launch_event_with_lineage(3, now_ms, r"c:\a.exe", &["cmd.exe"]),
            // Different exe entirely: must not appear.
            launch_event_with_lineage(4, now_ms, r"c:\b.exe", &["explorer.exe"]),
        ];
        state.storage.save_launches(&events).unwrap();

        let response = state.handle(PipeRequest::GetLaunchOccurrences {
            exe_path: r"c:\a.exe".into(),
            lineage_sig: "explorer.exe".into(),
            from_ms: None,
            limit: None,
        });
        let data = match response {
            PipeResponse::Ok { data } => data,
            PipeResponse::Error { code, message } => {
                panic!("getLaunchOccurrences failed: {code} {message}")
            }
        };
        let events: Vec<LaunchEvent> = serde_json::from_value(data["events"].clone()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].pid, 2, "newest first");
        assert_eq!(events[1].pid, 1);
    }

    #[test]
    fn get_launch_occurrences_populates_command_line_from_the_encrypted_store() {
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        let now_ms = Utc::now().timestamp_millis();

        let event = launch_event_with_lineage(1, now_ms, r"c:\a.exe", &[]);
        state.storage.save_launches(&[event.clone()]).unwrap();
        let blob = crate::dpapi::protect(b"c:\\a.exe --flag").unwrap();
        state
            .storage
            .save_launch_cmdline(event.pid, event.start_time_ms, now_ms, &blob)
            .unwrap();

        let response = state.handle(PipeRequest::GetLaunchOccurrences {
            exe_path: r"c:\a.exe".into(),
            lineage_sig: String::new(),
            from_ms: None,
            limit: None,
        });
        let data = match response {
            PipeResponse::Ok { data } => data,
            PipeResponse::Error { code, message } => {
                panic!("getLaunchOccurrences failed: {code} {message}")
            }
        };
        let events: Vec<LaunchEvent> = serde_json::from_value(data["events"].clone()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].command_line.as_deref(), Some("c:\\a.exe --flag"));
    }

    #[test]
    fn get_launch_occurrences_without_a_captured_command_line_leaves_it_absent() {
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        let now_ms = Utc::now().timestamp_millis();

        let event = launch_event_with_lineage(1, now_ms, r"c:\a.exe", &[]);
        state.storage.save_launches(&[event]).unwrap();

        let response = state.handle(PipeRequest::GetLaunchOccurrences {
            exe_path: r"c:\a.exe".into(),
            lineage_sig: String::new(),
            from_ms: None,
            limit: None,
        });
        let data = match response {
            PipeResponse::Ok { data } => data,
            PipeResponse::Error { code, message } => {
                panic!("getLaunchOccurrences failed: {code} {message}")
            }
        };
        let events: Vec<LaunchEvent> = serde_json::from_value(data["events"].clone()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].command_line, None);
    }

    #[test]
    fn delete_command_lines_removes_captured_blobs_but_leaves_launch_events_intact() {
        let directory = tempfile::tempdir().unwrap();
        let state = test_state(&directory);
        let now_ms = Utc::now().timestamp_millis();

        let event = launch_event_with_lineage(1, now_ms, r"c:\a.exe", &[]);
        state.storage.save_launches(&[event.clone()]).unwrap();
        let blob = crate::dpapi::protect(b"c:\\a.exe --flag").unwrap();
        state
            .storage
            .save_launch_cmdline(event.pid, event.start_time_ms, now_ms, &blob)
            .unwrap();

        let response = state.handle(PipeRequest::DeleteCommandLines);
        let deleted = match response {
            PipeResponse::Ok { data } => data["deleted"].as_u64().unwrap(),
            PipeResponse::Error { code, message } => {
                panic!("deleteCommandLines failed: {code} {message}")
            }
        };
        assert_eq!(deleted, 1);
        assert_eq!(
            state
                .storage
                .load_launch_cmdline(event.pid, event.start_time_ms)
                .unwrap(),
            None
        );
        // The launch_events row is untouched: they never carried a command
        // line in the first place.
        let events = state.storage.launch_events(0).unwrap();
        assert_eq!(events.len(), 1);
    }
}
