//! Incident quality scoring and the notification policy.
//!
//! Every active incident carries an [`AlertQuality`] recomputed each
//! evaluation ([`score`]), and the policy floors decide whether that incident
//! is worth interrupting the user for ([`decide`]). Suppression is a
//! *notification* decision only: a suppressed incident is still recorded,
//! still evaluated, still visible in history and the agent context, with its
//! scores attached so the suppression is explainable.

use crate::baselines::BaselineStore;
use crate::models::{
    Alert, AlertQuality, DemandBucket, Rating, RatingOffset, RatingVerdict, Severity,
};
use std::collections::{HashMap, HashSet};

/// Breach duration, in sustained windows, at which persistence saturates.
const PERSISTENCE_SATURATION_WINDOWS: f64 = 3.0;
/// Samples behind a breach at which "sample depth" counts as fully deep.
/// Ten samples is two-plus sustained windows at the default cadence -- enough
/// that the reading is not one lucky spike.
const SAMPLE_DEPTH_SATURATION: f64 = 10.0;
/// Confidence weights. The floors are the spec's and are not negotiable, so
/// the weights are what has to make them behave. They sum to 1.0 and are
/// derived from three constraints, each pinned by a test:
///
/// 1. **The confidence floor must still bind after learning.** With a fully
///    matured baseline, the *minimum* achievable confidence (shallowest
///    evidence, no attribution) must sit below 0.5, or every Warning that
///    persists would notify and the floor would be decoration.
///    `0.25 + 0.35·0.1 + 0.40·0.5 = 0.485 < 0.5`.
/// 2. **A well-evidenced Critical must be able to notify on day one.** With
///    maturity at zero, maximum sample depth and a stable attribution must
///    still reach the learning-period floor of 0.6 -- the spec's "a
///    genuinely dying machine should not be silenced by an immature
///    baseline". `0.35 + 0.40 = 0.75 >= 0.6`.
/// 3. **An unknown attribution stays exactly neutral** between a stable and
///    an unstable one, which any weighting satisfies as long as the neutral
///    value is the midpoint (see [`NEUTRAL_ATTRIBUTION`]).
///
/// Attribution therefore leads: naming the thing responsible, repeatably, is
/// the strongest evidence a detector can offer, and it is the one input that
/// does not need a day of history to become available.
const MATURITY_WEIGHT: f64 = 0.25;
const SAMPLE_DEPTH_WEIGHT: f64 = 0.35;
const ATTRIBUTION_WEIGHT: f64 = 0.40;
/// An unknown attribution is neither corroborating nor disqualifying.
const NEUTRAL_ATTRIBUTION: f64 = 0.5;

/// Notification floors, verbatim from the spec's Phase C:
/// `notify = severity >= Warning && persistence >= 0.5 && confidence >= 0.5`,
/// with Critical relaxed to `confidence >= 0.35` (a genuinely dying machine
/// should not be silenced by an immature baseline), and the learning period
/// tightened to `Critical && confidence >= 0.6`.
pub const PERSISTENCE_FLOOR: f64 = 0.5;
pub const CONFIDENCE_FLOOR: f64 = 0.5;
pub const CRITICAL_CONFIDENCE_FLOOR: f64 = 0.35;
pub const LEARNING_CONFIDENCE_FLOOR: f64 = 0.6;

/// How far one rating moves the floors for the (kind, bucket) it speaks
/// about, how far the whole rating history is ever allowed to move them, and
/// how long a rating's say in the matter lasts. All three are the spec's.
pub const RATING_OFFSET_STEP: f64 = 0.05;
pub const RATING_OFFSET_BOUND: f64 = 0.15;
const RATING_OFFSET_HALF_LIFE_DAYS: f64 = 30.0;
const MS_PER_DAY: f64 = 86_400_000.0;

/// The `kind` an offset carries when it applies to *every* kind in its
/// bucket -- what an unexplained `sluggish` rating produces, since the user
/// felt something no detector named. Only ever emitted for display
/// ([`PolicyOffsets::entries`]); [`PolicyOffsets::lookup`] folds it into the
/// answer for whatever kind is asked about.
pub const ALL_KINDS: &str = "*";

/// Tolerance for "is this accumulated/effective offset actually nonzero"
/// checks, in place of an exact `f64 != 0.0` compare.
const OFFSET_EPSILON: f64 = 1e-9;

/// The notify-floor adjustments the user's ratings have earned, per alert
/// kind and demand bucket.
///
/// Derived fresh from the rating history by [`derive_offsets`] -- the
/// `ratings` table is the single source of truth and this is a cache of a
/// pure function over it, never a second mutable store. Decay is therefore
/// applied at derivation time from each rating's age, not by mutating
/// anything on a schedule.
///
/// Two kinds of term live here because the spec's two signals have different
/// reach. A false positive names a kind (that incident was not worth
/// interrupting me for); a false negative names none (something slowed this
/// machine down and nothing told me), so it moves every kind in its bucket,
/// including kinds no rating has ever mentioned and kinds no detector has
/// shipped yet. Enumerating "every kind" is impossible, so the bucket-wide
/// term is stored as itself and added at lookup.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PolicyOffsets {
    /// bucket -> kind -> summed, decayed per-kind term.
    kinds: HashMap<DemandBucket, HashMap<String, f64>>,
    /// bucket -> summed, decayed term applying to every kind in it.
    buckets: HashMap<DemandBucket, f64>,
}

impl PolicyOffsets {
    /// The additive floor adjustment for one alert kind under one demand
    /// bucket. Positive is stricter (harder to notify), negative is more
    /// permissive, and a machine whose user has never rated anything -- or
    /// whose ratings all confirmed the system was right -- gets 0.0.
    pub fn lookup(&self, kind: &str, bucket: DemandBucket) -> f64 {
        let per_kind = self
            .kinds
            .get(&bucket)
            .and_then(|kinds| kinds.get(kind))
            .copied()
            .unwrap_or(0.0);
        let bucket_wide = self.buckets.get(&bucket).copied().unwrap_or(0.0);
        // Both terms are already bounded to +/-RATING_OFFSET_BOUND at
        // accumulation time (see `derive_offsets`), so this clamp is on the
        // *net*: a kind the user called a false positive inside a bucket
        // they called slow is genuinely ambiguous evidence and should land
        // near zero, not at either term's own extreme.
        (per_kind + bucket_wide).clamp(-RATING_OFFSET_BOUND, RATING_OFFSET_BOUND)
    }

    /// Every non-zero *effective* per-kind offset, for the agent context and
    /// the incidents detail pane. Ordered by bucket then kind so the
    /// rendered list is stable between contexts.
    ///
    /// Deliberately reports per-kind offsets only -- never a bucket-wide
    /// [`ALL_KINDS`] row. A bucket-wide term (an unexplained `sluggish`
    /// rating) is already netted into every named kind's effective offset by
    /// [`lookup`](Self::lookup), so surfacing it a second time as its own
    /// row would double-count it for a reader (an LLM agent, the detail
    /// pane) that sums or displays both. A bucket whose only adjustment is
    /// bucket-wide, with no kind ever named, therefore has nothing to show
    /// here; render it via `lookup(kind, bucket)` for a specific kind
    /// instead.
    pub fn entries(&self) -> Vec<RatingOffset> {
        let mut entries = Vec::new();
        for bucket in [
            DemandBucket::Light,
            DemandBucket::Moderate,
            DemandBucket::Heavy,
        ] {
            let mut named: Vec<&String> = self
                .kinds
                .get(&bucket)
                .map(|kinds| kinds.keys().collect())
                .unwrap_or_default();
            named.sort();
            for kind in named {
                let offset = self.lookup(kind, bucket);
                if offset.abs() > OFFSET_EPSILON {
                    entries.push(RatingOffset {
                        kind: kind.clone(),
                        bucket,
                        offset,
                    });
                }
            }
        }
        entries
    }

    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty() && self.buckets.is_empty()
    }
}

/// Read the notification policy's offsets out of the rating history.
///
/// A rating only ever speaks about its own demand bucket. That is the
/// deceptive-comfort guard, and it is the whole reason the bucket is stored
/// on the rating rather than recomputed: a month of "feels fine" collected
/// while the machine idled says nothing about how it behaves under load, and
/// must leave the heavy bucket exactly as strict as the day it shipped.
///
/// Each qualifying rating contributes one [`RATING_OFFSET_STEP`], weighted by
/// a 30-day half-life on its age, and the sum is bounded at lookup:
///
/// - `good`/`acceptable` while a kind was notifying (notify true and not
///   acknowledged) -- a false positive: that kind gets **stricter** in that
///   bucket. One step per rating per kind, not per incident: two open
///   incidents of one kind is that kind being wrong once.
/// - `sluggish` with nothing notifying -- a false negative: **every** kind in
///   that bucket gets more permissive.
/// - `sluggish` while something was notifying -- confirmation: the system was
///   right, so nothing moves.
/// - anything rated during the learning period -- inert: the policy it would
///   adjust is not in effect yet.
pub fn derive_offsets(ratings: &[Rating], now_ms: i64) -> PolicyOffsets {
    let mut offsets = PolicyOffsets::default();
    for rating in ratings {
        if rating.during_learning {
            continue;
        }
        let step = RATING_OFFSET_STEP * decay_weight(now_ms - rating.at_ms);
        let notifying: HashSet<&str> = rating
            .open_incidents
            .iter()
            .filter(|incident| incident.notify && !incident.acknowledged)
            .map(|incident| incident.kind.as_str())
            .collect();
        match rating.verdict {
            RatingVerdict::Good | RatingVerdict::Acceptable => {
                for kind in notifying {
                    let term = offsets
                        .kinds
                        .entry(rating.demand)
                        .or_default()
                        .entry(kind.to_string())
                        .or_insert(0.0);
                    // Clamp the accumulated term itself, not just the netted
                    // total at lookup time. Without this, a raw sum could
                    // run arbitrarily far past the bound while `lookup`
                    // clamped the visible result to it anyway -- so a burst
                    // of contrary feedback in the *other* term would net
                    // against a value the bound was already hiding and the
                    // dial would not move until enough of the original raw
                    // sum decayed away. Clamping here keeps every term
                    // within [-BOUND, BOUND] at all times, so a contrary
                    // rating always shows up in the next `lookup` call.
                    *term = (*term + step).clamp(-RATING_OFFSET_BOUND, RATING_OFFSET_BOUND);
                }
            }
            RatingVerdict::Sluggish if notifying.is_empty() => {
                let term = offsets.buckets.entry(rating.demand).or_insert(0.0);
                *term = (*term - step).clamp(-RATING_OFFSET_BOUND, RATING_OFFSET_BOUND);
            }
            RatingVerdict::Sluggish => {}
        }
    }
    offsets
}

/// How much say a rating still has, halving every 30 days. A rating dated in
/// the future (clock skew across a restart) counts as fresh rather than
/// growing without bound.
fn decay_weight(age_ms: i64) -> f64 {
    let days = age_ms.max(0) as f64 / MS_PER_DAY;
    0.5_f64.powf(days / RATING_OFFSET_HALF_LIFE_DAYS)
}

/// What the runtime knows about the machine's learned baselines when it asks
/// the engine to evaluate a sample.
///
/// `Default` is a fully matured, non-learning machine with no per-name norms:
/// the pre-calibration behavior, so a caller with no baseline store (tests, a
/// future embedder) gates on persistence and detector confidence alone rather
/// than silently suppressing everything.
#[derive(Debug, Clone, Copy)]
pub struct Calibration<'a> {
    /// Machine baseline age < 24 h; raises the notification floor.
    pub learning: bool,
    /// Machine baseline age as a fraction of the learning period, 0-1.
    pub baseline_maturity: f64,
    /// The learned per-executable-name, age-bucketed norms a detector may
    /// judge a process against. Borrowed rather than owned because the
    /// runtime holds the store across the whole sampling loop and feeds it in
    /// *before* this sample is folded into it -- an incident is judged
    /// against what was learned before it, never against itself.
    ///
    /// `None` means "no norms available", which every consuming gate must
    /// treat as passing open, exactly as an unknown name does.
    pub names: Option<&'a BaselineStore>,
    /// How demanding the machine's workload is *right now*, which is the
    /// bucket the user's rating offsets are read against. A rating is only
    /// ever evidence about its own bucket, so the live bucket has to reach
    /// the decision -- an offset earned under heavy load must not quietly
    /// apply while the machine idles, and vice versa.
    pub demand: DemandBucket,
}

impl Default for Calibration<'_> {
    fn default() -> Self {
        Self {
            learning: false,
            baseline_maturity: 1.0,
            names: None,
            // The unrated machine's bucket is immaterial (every lookup
            // answers 0.0), so the least-demanding one is the honest default
            // for a caller that has no demand reading to offer.
            demand: DemandBucket::Light,
        }
    }
}

/// Everything [`score`] needs about one incident at one moment. Held by
/// reference: the caller owns the alert it is scoring.
pub struct QualityInputs<'a> {
    pub alert: &'a Alert,
    /// The detector's sustained window (`required_samples × interval`).
    pub sustained_window_ms: i64,
    /// Time since the incident's breach streak began -- the first breaching
    /// sample of the run that produced it, not the moment the incident
    /// opened and not its `first_seen_ms`.
    ///
    /// It keeps accruing while the engine holds an incident open through
    /// hysteresis (value below the entry threshold but above the exit
    /// threshold), because that hold *is* the condition continuing: the
    /// engine only closes the incident once the value has cleared the exit
    /// threshold for a full window. So this is "how long this incident has
    /// been going on", which is deliberately not the same as "how many
    /// samples breached the entry threshold".
    pub breach_duration_ms: i64,
    /// Machine baseline age / 24 h, clamped to 0-1.
    pub baseline_maturity: f64,
    /// Whether the detector's attribution (e.g. a DPC driver-family verdict)
    /// has held steady. `None` when the detector has no attribution to
    /// offer, which scores neutral rather than either way.
    pub attribution_stable: Option<bool>,
    /// Count of independent co-signals corroborating the incident.
    pub corroborating_signals: u32,
    /// Count of user-facing impact signals (hung window, slow launch,
    /// foreground involvement).
    pub user_impact_signals: u32,
    /// Whether this incident has ever been marked notifiable before.
    pub notified_before: bool,
    /// When it was last marked notifiable, if ever.
    pub last_notified_ms: Option<i64>,
}

/// The policy's verdict for one incident this evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyDecision {
    /// Whether the incident is currently worth a notification at all.
    pub notify: bool,
    /// Whether an already-notified incident earns a *fresh* notification --
    /// the tray pops once per `(id, notify_generation)`, so bumping the
    /// generation is what makes an existing incident pop again.
    pub bump_generation: bool,
}

/// Score one incident. Every component is 0-1 and every component is
/// recorded, whether or not it moves the notification decision.
pub fn score(inputs: &QualityInputs) -> AlertQuality {
    let window_ms = inputs.sustained_window_ms.max(1) as f64;
    let windows = inputs.breach_duration_ms.max(0) as f64 / window_ms;
    let persistence =
        windows.clamp(0.0, PERSISTENCE_SATURATION_WINDOWS) / PERSISTENCE_SATURATION_WINDOWS;

    let sample_depth =
        (f64::from(inputs.alert.occurrence_count) / SAMPLE_DEPTH_SATURATION).clamp(0.0, 1.0);
    let attribution = inputs
        .attribution_stable
        .map_or(NEUTRAL_ATTRIBUTION, |stable| if stable { 1.0 } else { 0.0 });
    let confidence = (inputs.baseline_maturity.clamp(0.0, 1.0) * MATURITY_WEIGHT
        + sample_depth * SAMPLE_DEPTH_WEIGHT
        + attribution * ATTRIBUTION_WEIGHT)
        .clamp(0.0, 1.0);

    AlertQuality {
        confidence,
        persistence,
        corroboration: saturating_signal(inputs.corroborating_signals),
        user_impact: saturating_signal(inputs.user_impact_signals),
        novelty: novelty(inputs),
    }
}

/// Independent signals pointing at the same incident, with diminishing
/// returns: each one closes half the remaining distance to certainty, so one
/// signal scores 0.5, two 0.75, three 0.875.
fn saturating_signal(signals: u32) -> f64 {
    1.0 - 0.5_f64.powi(signals.min(32) as i32)
}

/// How much new information is left in this incident.
///
/// A fingerprint the user has never been told about is fully novel. After a
/// notification, each further occurrence halves what is left to say -- an
/// incident that has been chattering for hours since we last spoke is not
/// news. Occurrences since the last notification are measured in sustained
/// windows of elapsed time, bounded by the occurrences the incident has
/// actually accrued (it cannot have recurred more often than it occurred).
fn novelty(inputs: &QualityInputs) -> f64 {
    if !inputs.notified_before {
        return 1.0;
    }
    let window_ms = inputs.sustained_window_ms.max(1);
    let occurrences_since = match inputs.last_notified_ms {
        Some(at_ms) => (((inputs.alert.last_seen_ms - at_ms).max(0) / window_ms) as u64)
            .min(u64::from(inputs.alert.occurrence_count)),
        None => u64::from(inputs.alert.occurrence_count),
    };
    0.5_f64.powi(occurrences_since.min(32) as i32)
}

/// Apply the notification floors to a scored incident.
///
/// `previous` is this incident's state before the current evaluation (absent
/// for an incident that has just opened). `material_change` is the
/// detector-supplied "the thing I am describing is materially different now"
/// flag -- e.g. a *confident* DPC driver-family verdict change, never a
/// low-confidence label flip.
///
/// The spec lists three renotify conditions. (1) severity escalation and
/// (2) a materially changed fingerprint are decided here. (3) "recurrence
/// after a full quiet period" is vacuously covered: the engine only reopens
/// an incident *inside* the quiet period, so a recurrence after a full quiet
/// period is a genuinely new incident with a fresh id and generation 0, and
/// the tray has by definition never seen that pair. There is nothing to bump.
///
/// `offset` is the user's rating feedback for this alert's kind under the
/// machine's *current* demand bucket ([`PolicyOffsets::lookup`]), added to
/// both floors: positive makes this kind harder to notify, negative easier.
/// It is bounded to ±0.15 by construction, and 0.0 -- the value for a machine
/// nobody has rated -- reproduces the shipped policy exactly.
pub fn decide(
    alert: &Alert,
    quality: &AlertQuality,
    learning: bool,
    previous: Option<&Alert>,
    material_change: bool,
    offset: f64,
) -> NotifyDecision {
    let severity_ok = match alert.severity {
        // Info findings are history-only by construction.
        Severity::Info => false,
        // The learning period demands Critical, whatever the warning says.
        Severity::Warning => !learning,
        Severity::Critical => true,
    };
    let confidence_floor = match (alert.severity, learning) {
        (Severity::Critical, true) => LEARNING_CONFIDENCE_FLOOR,
        (Severity::Critical, false) => CRITICAL_CONFIDENCE_FLOOR,
        _ => CONFIDENCE_FLOOR,
    };
    let notify = severity_ok
        && quality.persistence >= PERSISTENCE_FLOOR + offset
        && quality.confidence >= confidence_floor + offset;

    // Only an incident that was already popping can *re*-notify. One that was
    // suppressed needs no bump: the tray never recorded a suppressed
    // `(id, generation)`, so it pops the moment the incident becomes
    // notifiable.
    let already_notifying = previous.is_some_and(|previous| previous.notify);
    let escalated = previous.is_some_and(|previous| rank(alert.severity) > rank(previous.severity));
    let bump_generation = notify && already_notifying && (escalated || material_change);

    NotifyDecision {
        notify,
        bump_generation,
    }
}

/// Severity ordering. `Severity` is a wire enum without `Ord`; ranking it
/// here keeps the derive surface of the protocol type untouched.
fn rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Critical => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DemandDetail, IncidentState, OpenIncidentRef};

    const WINDOW_MS: i64 = 6_000;

    fn alert(severity: Severity) -> Alert {
        Alert {
            id: "incident-1".into(),
            kind: "sustainedCpu".into(),
            severity,
            first_seen_ms: 0,
            last_seen_ms: 0,
            process_id: Some(42),
            process_name: Some("worker.exe".into()),
            title: "Sustained CPU usage".into(),
            explanation: String::new(),
            evidence: Vec::new(),
            recommendation: String::new(),
            acknowledged: false,
            occurrence_count: 1,
            resolved_at_ms: None,
            archived: false,
            fingerprint: "sustainedCpu:42:1".into(),
            state: IncidentState::Open,
            quality: AlertQuality::default(),
            notify: false,
            notify_generation: 0,
        }
    }

    fn inputs<'a>(alert: &'a Alert, breach_duration_ms: i64) -> QualityInputs<'a> {
        QualityInputs {
            alert,
            sustained_window_ms: WINDOW_MS,
            breach_duration_ms,
            baseline_maturity: 1.0,
            attribution_stable: None,
            corroborating_signals: 0,
            user_impact_signals: 0,
            notified_before: false,
            last_notified_ms: None,
        }
    }

    fn quality(persistence: f64, confidence: f64) -> AlertQuality {
        AlertQuality {
            persistence,
            confidence,
            ..AlertQuality::default()
        }
    }

    #[test]
    fn persistence_rises_with_breach_duration_and_saturates_at_three_windows() {
        let alert = alert(Severity::Warning);
        let at =
            |windows: f64| score(&inputs(&alert, (windows * WINDOW_MS as f64) as i64)).persistence;
        assert!((at(0.0) - 0.0).abs() < 1e-9);
        assert!(
            (at(1.5) - 0.5).abs() < 1e-9,
            "1.5 windows must sit on the floor"
        );
        assert!((at(3.0) - 1.0).abs() < 1e-9, "3 windows must saturate");
        assert!((at(10.0) - 1.0).abs() < 1e-9, "past saturation stays 1.0");
        // Monotonic in between, never above 1.0.
        let mut previous = -1.0;
        for step in 0..40 {
            let value = at(f64::from(step) * 0.25);
            assert!(
                value >= previous,
                "persistence must never fall: {value} < {previous}"
            );
            assert!((0.0..=1.0).contains(&value));
            previous = value;
        }
    }

    #[test]
    fn corroboration_and_user_impact_close_half_the_remaining_gap_per_signal() {
        let alert = alert(Severity::Warning);
        let with = |corroborating, impact| {
            let mut probe = inputs(&alert, WINDOW_MS);
            probe.corroborating_signals = corroborating;
            probe.user_impact_signals = impact;
            score(&probe)
        };
        assert!((with(0, 0).corroboration - 0.0).abs() < 1e-9);
        assert!((with(1, 0).corroboration - 0.5).abs() < 1e-9);
        assert!((with(2, 0).corroboration - 0.75).abs() < 1e-9);
        assert!((with(3, 0).corroboration - 0.875).abs() < 1e-9);
        assert!((with(0, 2).user_impact - 0.75).abs() < 1e-9);
    }

    #[test]
    fn confidence_blends_maturity_sample_depth_and_attribution() {
        let mut alert = alert(Severity::Warning);
        alert.occurrence_count = 10;
        let with = |maturity, attribution, occurrences| {
            let mut subject = alert.clone();
            subject.occurrence_count = occurrences;
            let mut probe = inputs(&subject, WINDOW_MS);
            probe.baseline_maturity = maturity;
            probe.attribution_stable = attribution;
            score(&probe).confidence
        };
        // Monotonic in every input.
        assert!(with(0.0, None, 10) < with(0.5, None, 10));
        assert!(with(0.5, None, 10) < with(1.0, None, 10));
        assert!(with(1.0, None, 2) < with(1.0, None, 10));
        assert!(with(1.0, Some(false), 10) < with(1.0, None, 10));
        assert!(with(1.0, None, 10) < with(1.0, Some(true), 10));
        // An unknown attribution is exactly neutral between the two verdicts.
        let neutral = with(1.0, None, 10);
        let midpoint = (with(1.0, Some(true), 10) + with(1.0, Some(false), 10)) / 2.0;
        assert!((neutral - midpoint).abs() < 1e-9);
        // A fully learned, deeply sampled, confidently attributed incident is
        // total confidence; the empty opposite is zero.
        assert!((with(1.0, Some(true), 10) - 1.0).abs() < 1e-9);
        assert!((with(0.0, Some(false), 0) - 0.0).abs() < 1e-9);
    }

    /// Confidence weight constraint 1: after learning, the *weakest* evidence
    /// must still fall short of the confidence floor, or the floor is
    /// decoration and every persisting Warning notifies.
    #[test]
    fn a_shallow_warning_stays_gated_by_confidence_after_learning() {
        let mut shallow = alert(Severity::Warning);
        shallow.occurrence_count = 1;
        let probe = inputs(&shallow, 10 * WINDOW_MS);
        let scored = score(&probe);
        assert!(
            (scored.persistence - 1.0).abs() < 1e-9,
            "the condition itself is unambiguous"
        );
        assert!(
            scored.confidence < CONFIDENCE_FLOOR,
            "a matured baseline with one sample and no attribution: {}",
            scored.confidence
        );
        assert!(!decide(&shallow, &scored, false, None, false, 0.0).notify);
        // Depth alone gets it over the floor, which is the point: the gate is
        // evidence, not time.
        let mut deep = shallow.clone();
        deep.occurrence_count = 10;
        let scored = score(&inputs(&deep, 10 * WINDOW_MS));
        assert!(scored.confidence >= CONFIDENCE_FLOOR);
        assert!(decide(&deep, &scored, false, None, false, 0.0).notify);
    }

    /// Confidence weight constraint 2: a machine that is dying on its first
    /// day must be able to say so, if the evidence is there.
    #[test]
    fn a_well_evidenced_critical_notifies_on_day_one() {
        let mut dying = alert(Severity::Critical);
        dying.occurrence_count = 10;
        let mut probe = inputs(&dying, 3 * WINDOW_MS);
        // Nothing learned yet -- the machine started an hour ago.
        probe.baseline_maturity = 0.0;
        probe.attribution_stable = Some(true);
        let scored = score(&probe);
        assert!(
            scored.confidence >= LEARNING_CONFIDENCE_FLOOR,
            "deep, repeatably attributed evidence must clear the learning floor: {}",
            scored.confidence
        );
        assert!(decide(&dying, &scored, true, None, false, 0.0).notify);
        // Without the attribution it is a guess against an unlearned machine,
        // and the learning period keeps it quiet.
        probe.attribution_stable = None;
        let unattributed = score(&probe);
        assert!(unattributed.confidence < LEARNING_CONFIDENCE_FLOOR);
        assert!(!decide(&dying, &unattributed, true, None, false, 0.0).notify);
    }

    #[test]
    fn novelty_is_full_until_we_notify_then_halves_per_further_occurrence() {
        let mut alert = alert(Severity::Warning);
        alert.occurrence_count = 100;
        let mut probe = inputs(&alert, WINDOW_MS);
        assert!((score(&probe).novelty - 1.0).abs() < 1e-9);
        probe.notified_before = true;
        probe.last_notified_ms = Some(0);
        // Still the same moment we notified: nothing has recurred yet.
        assert!((score(&probe).novelty - 1.0).abs() < 1e-9);
        let mut later = alert.clone();
        later.last_seen_ms = 3 * WINDOW_MS;
        let mut probe = inputs(&later, WINDOW_MS);
        probe.notified_before = true;
        probe.last_notified_ms = Some(0);
        assert!((score(&probe).novelty - 0.125).abs() < 1e-9);
        // It cannot have recurred more often than it has occurred.
        let mut thin = later.clone();
        thin.occurrence_count = 1;
        let mut probe = inputs(&thin, WINDOW_MS);
        probe.notified_before = true;
        probe.last_notified_ms = Some(0);
        assert!((score(&probe).novelty - 0.5).abs() < 1e-9);
    }

    #[test]
    fn a_persistent_confident_warning_notifies() {
        let alert = alert(Severity::Warning);
        let decision = decide(&alert, &quality(0.5, 0.5), false, None, false, 0.0);
        assert_eq!(
            decision,
            NotifyDecision {
                notify: true,
                bump_generation: false
            }
        );
    }

    #[test]
    fn a_warning_below_either_floor_is_suppressed() {
        let warning = alert(Severity::Warning);
        assert!(!decide(&warning, &quality(0.5, 0.49), false, None, false, 0.0).notify);
        assert!(!decide(&warning, &quality(0.49, 0.9), false, None, false, 0.0).notify);
        // Info never notifies however good it looks.
        assert!(
            !decide(
                &alert(Severity::Info),
                &quality(1.0, 1.0),
                false,
                None,
                false,
                0.0
            )
            .notify
        );
    }

    #[test]
    fn a_critical_notifies_down_to_the_lower_confidence_floor() {
        let alert = alert(Severity::Critical);
        assert!(decide(&alert, &quality(0.5, 0.35), false, None, false, 0.0).notify);
        assert!(!decide(&alert, &quality(0.5, 0.34), false, None, false, 0.0).notify);
        // The relaxed floor is confidence only: persistence still gates.
        assert!(!decide(&alert, &quality(0.49, 1.0), false, None, false, 0.0).notify);
    }

    #[test]
    fn the_learning_period_suppresses_warnings_however_good() {
        let alert = alert(Severity::Warning);
        assert!(decide(&alert, &quality(1.0, 1.0), false, None, false, 0.0).notify);
        assert!(!decide(&alert, &quality(1.0, 1.0), true, None, false, 0.0).notify);
    }

    #[test]
    fn the_learning_period_lets_a_critical_through_at_six_tenths_confidence() {
        let alert = alert(Severity::Critical);
        assert!(decide(&alert, &quality(0.5, 0.6), true, None, false, 0.0).notify);
        assert!(!decide(&alert, &quality(0.5, 0.59), true, None, false, 0.0).notify);
    }

    #[test]
    fn renotification_needs_an_escalation_or_a_material_change() {
        let mut previous = alert(Severity::Warning);
        previous.notify = true;
        let good = quality(1.0, 1.0);

        // Same incident, same severity, nothing materially changed: notify
        // stays true (the tray has already seen this generation) but nothing
        // bumps.
        let steady = decide(
            &alert(Severity::Warning),
            &good,
            false,
            Some(&previous),
            false,
            0.0,
        );
        assert_eq!(
            steady,
            NotifyDecision {
                notify: true,
                bump_generation: false
            }
        );
        // (1) Severity escalation.
        assert!(
            decide(
                &alert(Severity::Critical),
                &good,
                false,
                Some(&previous),
                false,
                0.0
            )
            .bump_generation
        );
        // De-escalation is not an escalation.
        let mut was_critical = alert(Severity::Critical);
        was_critical.notify = true;
        assert!(
            !decide(
                &alert(Severity::Warning),
                &good,
                false,
                Some(&was_critical),
                false,
                0.0
            )
            .bump_generation
        );
        // (2) The detector-supplied materially-changed flag.
        assert!(
            decide(
                &alert(Severity::Warning),
                &good,
                false,
                Some(&previous),
                true,
                0.0
            )
            .bump_generation
        );
        // A suppressed incident never bumps -- it has nothing to renotify.
        assert!(
            !decide(
                &alert(Severity::Warning),
                &quality(0.1, 0.1),
                false,
                Some(&previous),
                true,
                0.0
            )
            .bump_generation
        );
        // Neither does one that was not notifying before: it pops on its own
        // unseen `(id, generation)` instead.
        let mut suppressed = alert(Severity::Warning);
        suppressed.notify = false;
        assert!(
            !decide(
                &alert(Severity::Critical),
                &good,
                false,
                Some(&suppressed),
                true,
                0.0
            )
            .bump_generation
        );
        // A brand-new incident has no previous state and cannot renotify.
        assert!(!decide(&alert(Severity::Critical), &good, false, None, true, 0.0).bump_generation);
    }

    /// One rating, with whatever was notifying when it was given.
    fn rating(
        verdict: RatingVerdict,
        demand: DemandBucket,
        at_ms: i64,
        notifying: &[&str],
    ) -> Rating {
        Rating {
            id: format!("rating-{at_ms}"),
            at_ms,
            verdict,
            demand,
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
            open_incidents: notifying
                .iter()
                .map(|kind| OpenIncidentRef {
                    fingerprint: format!("{kind}:1"),
                    kind: (*kind).to_string(),
                    severity: Severity::Warning,
                    notify: true,
                    acknowledged: false,
                })
                .collect(),
            during_learning: false,
            unexplained: verdict == RatingVerdict::Sluggish && notifying.is_empty(),
        }
    }

    const DAY_MS: i64 = 86_400_000;

    #[test]
    fn a_good_rating_while_a_kind_was_notifying_makes_that_kind_stricter() {
        // Spec test 3: the false-positive path. The user says the machine is
        // fine while the collector-budget incident is interrupting them, so
        // that (kind, bucket) has to earn its notification harder next time.
        let now_ms = 100 * DAY_MS;
        let one = derive_offsets(
            &[rating(
                RatingVerdict::Good,
                DemandBucket::Moderate,
                now_ms,
                &["collectorBudget"],
            )],
            now_ms,
        );
        assert!((one.lookup("collectorBudget", DemandBucket::Moderate) - 0.05).abs() < 1e-9);
        // Untouched kinds and buckets stay exactly where they were.
        assert_eq!(one.lookup("sustainedCpu", DemandBucket::Moderate), 0.0);
        assert_eq!(one.lookup("collectorBudget", DemandBucket::Heavy), 0.0);

        // An `acceptable` rating is the same signal.
        let acceptable = derive_offsets(
            &[rating(
                RatingVerdict::Acceptable,
                DemandBucket::Moderate,
                now_ms,
                &["collectorBudget"],
            )],
            now_ms,
        );
        assert!((acceptable.lookup("collectorBudget", DemandBucket::Moderate) - 0.05).abs() < 1e-9);
    }

    #[test]
    fn repeated_false_positives_cap_the_offset_at_fifteen_hundredths() {
        // Spec test 3's tail: three ratings reach the bound and no number of
        // further ratings pushes past it.
        let now_ms = 100 * DAY_MS;
        let of = |count: usize| {
            let ratings: Vec<Rating> = (0..count)
                .map(|index| {
                    rating(
                        RatingVerdict::Good,
                        DemandBucket::Moderate,
                        now_ms - index as i64,
                        &["collectorBudget"],
                    )
                })
                .collect();
            derive_offsets(&ratings, now_ms).lookup("collectorBudget", DemandBucket::Moderate)
        };
        assert!((of(2) - 0.10).abs() < 1e-6);
        assert!((of(3) - 0.15).abs() < 1e-6);
        assert!((of(9) - 0.15).abs() < 1e-6, "the bound is a bound");
    }

    #[test]
    fn a_contrary_rating_moves_the_dial_immediately_not_only_after_decay() {
        // A per-*term* clamp, not just a clamp on the netted total at
        // lookup. Twenty same-day false positives push the kind term's raw
        // sum far past the bound (20 x 0.05 = 1.0); if only the net were
        // ever clamped, that raw excess would sit there until enough of it
        // decayed away, and one fresh contrary rating landing in the
        // *other* term would net against a number the bound was already
        // hiding -- invisible at lookup, indistinguishable from doing
        // nothing.
        let now_ms = 100 * DAY_MS;
        let false_positives: Vec<Rating> = (0..20)
            .map(|index| {
                rating(
                    RatingVerdict::Good,
                    DemandBucket::Moderate,
                    now_ms - index as i64,
                    &["collectorBudget"],
                )
            })
            .collect();
        let before = derive_offsets(&false_positives, now_ms)
            .lookup("collectorBudget", DemandBucket::Moderate);
        assert!((before - 0.15).abs() < 1e-6, "starts pinned at the bound");

        let mut with_one_contrary = false_positives.clone();
        with_one_contrary.push(rating(
            RatingVerdict::Sluggish,
            DemandBucket::Moderate,
            now_ms,
            &[],
        ));
        let after = derive_offsets(&with_one_contrary, now_ms)
            .lookup("collectorBudget", DemandBucket::Moderate);
        assert!(
            (after - 0.10).abs() < 1e-6,
            "one contrary rating must move the dial by a full step \
             immediately, not stay pinned at the bound: got {after}"
        );
    }

    #[test]
    fn one_rating_moves_a_kind_one_step_however_many_incidents_of_it_were_open() {
        // A rating is one piece of evidence about one (kind, bucket). Two
        // open incidents of the same kind is that one kind being wrong once,
        // not twice.
        let now_ms = 100 * DAY_MS;
        let mut rating = rating(
            RatingVerdict::Good,
            DemandBucket::Heavy,
            now_ms,
            &["sustainedCpu"],
        );
        let mut second = rating.open_incidents[0].clone();
        second.fingerprint = "sustainedCpu:2".into();
        rating.open_incidents.push(second);
        let offsets = derive_offsets(&[rating], now_ms);
        assert!((offsets.lookup("sustainedCpu", DemandBucket::Heavy) - 0.05).abs() < 1e-9);
    }

    #[test]
    fn an_acknowledged_incident_is_not_a_false_positive() {
        // The spec's false-positive trigger is "notifying (notify true, not
        // acknowledged)". An incident the user has already dealt with is not
        // the thing they are calling fine.
        let now_ms = 100 * DAY_MS;
        let mut only = rating(
            RatingVerdict::Good,
            DemandBucket::Light,
            now_ms,
            &["diskLatency"],
        );
        only.open_incidents[0].acknowledged = true;
        assert_eq!(
            derive_offsets(&[only], now_ms).lookup("diskLatency", DemandBucket::Light),
            0.0
        );
    }

    #[test]
    fn a_sluggish_rating_with_nothing_notifying_relaxes_the_whole_bucket() {
        // Spec test 4: the false-negative path. The detectors missed what the
        // user felt, so every kind in that bucket gets more permissive --
        // including kinds no rating has ever named.
        let now_ms = 100 * DAY_MS;
        let offsets = derive_offsets(
            &[rating(
                RatingVerdict::Sluggish,
                DemandBucket::Heavy,
                now_ms,
                &[],
            )],
            now_ms,
        );
        assert!((offsets.lookup("sustainedCpu", DemandBucket::Heavy) + 0.05).abs() < 1e-9);
        assert!((offsets.lookup("neverSeenBefore", DemandBucket::Heavy) + 0.05).abs() < 1e-9);
        // Its own bucket only.
        assert_eq!(offsets.lookup("sustainedCpu", DemandBucket::Light), 0.0);
        assert_eq!(offsets.lookup("sustainedCpu", DemandBucket::Moderate), 0.0);
    }

    #[test]
    fn a_sluggish_rating_while_notifying_confirms_and_changes_nothing() {
        // Spec test's confirmation path: the system was right, so the policy
        // stays exactly where it is.
        let now_ms = 100 * DAY_MS;
        let offsets = derive_offsets(
            &[rating(
                RatingVerdict::Sluggish,
                DemandBucket::Heavy,
                now_ms,
                &["sustainedCpu"],
            )],
            now_ms,
        );
        assert_eq!(offsets.lookup("sustainedCpu", DemandBucket::Heavy), 0.0);
        assert_eq!(offsets.lookup("diskLatency", DemandBucket::Heavy), 0.0);
        assert!(offsets.entries().is_empty());
    }

    #[test]
    fn a_sixty_day_old_rating_contributes_a_quarter_of_a_step() {
        // Spec test 6: a 30-day half-life means two half-lives at 60 days.
        let now_ms = 100 * DAY_MS;
        let offsets = derive_offsets(
            &[rating(
                RatingVerdict::Good,
                DemandBucket::Light,
                now_ms - 60 * DAY_MS,
                &["collectorBudget"],
            )],
            now_ms,
        );
        assert!(
            (offsets.lookup("collectorBudget", DemandBucket::Light) - 0.0125).abs() < 1e-9,
            "0.05 x 0.5^(60/30) = 0.0125, got {}",
            offsets.lookup("collectorBudget", DemandBucket::Light)
        );
        // Thirty days is exactly half.
        let half = derive_offsets(
            &[rating(
                RatingVerdict::Good,
                DemandBucket::Light,
                now_ms - 30 * DAY_MS,
                &["collectorBudget"],
            )],
            now_ms,
        );
        assert!((half.lookup("collectorBudget", DemandBucket::Light) - 0.025).abs() < 1e-9);
    }

    #[test]
    fn learning_period_ratings_never_move_the_policy() {
        // The policy a learning-period rating would adjust is not yet in
        // effect, so the rating is recorded and inert.
        let now_ms = 100 * DAY_MS;
        let mut inert = rating(
            RatingVerdict::Good,
            DemandBucket::Heavy,
            now_ms,
            &["collectorBudget"],
        );
        inert.during_learning = true;
        let mut also_inert = rating(RatingVerdict::Sluggish, DemandBucket::Heavy, now_ms, &[]);
        also_inert.during_learning = true;
        let offsets = derive_offsets(&[inert, also_inert], now_ms);
        assert_eq!(offsets.lookup("collectorBudget", DemandBucket::Heavy), 0.0);
        assert_eq!(offsets.lookup("sustainedCpu", DemandBucket::Heavy), 0.0);
        assert!(offsets.entries().is_empty());
    }

    #[test]
    fn a_bucket_wide_relaxation_nets_against_a_kinds_own_tightening() {
        // The two terms are the same policy dial seen from two directions,
        // so a kind the user called a false positive and a bucket the user
        // said felt slow cancel out rather than shadowing each other.
        let now_ms = 100 * DAY_MS;
        let offsets = derive_offsets(
            &[
                rating(
                    RatingVerdict::Good,
                    DemandBucket::Heavy,
                    now_ms,
                    &["collectorBudget"],
                ),
                rating(RatingVerdict::Sluggish, DemandBucket::Heavy, now_ms, &[]),
            ],
            now_ms,
        );
        assert!(offsets.lookup("collectorBudget", DemandBucket::Heavy).abs() < 1e-9);
        assert!((offsets.lookup("sustainedCpu", DemandBucket::Heavy) + 0.05).abs() < 1e-9);
    }

    #[test]
    fn effective_offsets_are_reported_per_kind_only_never_bucket_wide() {
        // A pure bucket-wide relaxation (no kind ever named in that bucket)
        // must not appear in `entries()` at all -- an agent reading the list
        // would otherwise double-count it once here and again inside every
        // named kind's own (already-netted) effective offset.
        let now_ms = 100 * DAY_MS;
        let offsets = derive_offsets(
            &[
                rating(
                    RatingVerdict::Good,
                    DemandBucket::Light,
                    now_ms,
                    &["collectorBudget"],
                ),
                rating(RatingVerdict::Sluggish, DemandBucket::Heavy, now_ms, &[]),
            ],
            now_ms,
        );
        let entries = offsets.entries();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].kind, "collectorBudget");
        assert_eq!(entries[0].bucket, DemandBucket::Light);
        assert!((entries[0].offset - 0.05).abs() < 1e-9);
        assert!(
            entries.iter().all(|entry| entry.kind != ALL_KINDS),
            "no row may name {ALL_KINDS:?}: {entries:?}"
        );
        // The Heavy bucket-wide relaxation is still live -- it is netted
        // into any named kind's effective offset, just never its own row.
        assert!((offsets.lookup("sustainedCpu", DemandBucket::Heavy) + 0.05).abs() < 1e-9);

        // When a kind *is* named in a bucket that also carries a bucket-wide
        // term, `entries()` reports that kind's already-netted effective
        // offset -- one row, not two -- as long as the net is itself
        // nonzero (two same-day false positives net +0.05 against one
        // bucket-wide -0.05).
        let mixed = derive_offsets(
            &[
                rating(
                    RatingVerdict::Good,
                    DemandBucket::Heavy,
                    now_ms,
                    &["sustainedCpu"],
                ),
                rating(
                    RatingVerdict::Good,
                    DemandBucket::Heavy,
                    now_ms,
                    &["sustainedCpu"],
                ),
                rating(RatingVerdict::Sluggish, DemandBucket::Heavy, now_ms, &[]),
            ],
            now_ms,
        );
        let entries = mixed.entries();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].kind, "sustainedCpu");
        assert_eq!(entries[0].bucket, DemandBucket::Heavy);
        assert!(
            (entries[0].offset - 0.05).abs() < 1e-9,
            "0.10 - 0.05 nets to 0.05, reported as one row: {entries:?}"
        );

        // And when the net genuinely lands at zero, the row is dropped too
        // -- "non-zero effective offset" means the net, not either term.
        let cancels = derive_offsets(
            &[
                rating(
                    RatingVerdict::Good,
                    DemandBucket::Heavy,
                    now_ms,
                    &["sustainedCpu"],
                ),
                rating(RatingVerdict::Sluggish, DemandBucket::Heavy, now_ms, &[]),
            ],
            now_ms,
        );
        assert!(
            cancels.entries().is_empty(),
            "a kind whose net offset is exactly zero has nothing to report: {:?}",
            cancels.entries()
        );
    }

    #[test]
    fn an_offset_moves_both_notification_floors() {
        let warning = alert(Severity::Warning);
        // Exactly on the floors: notifies at zero offset, suppressed once the
        // user's ratings have made this kind stricter.
        assert!(decide(&warning, &quality(0.5, 0.5), false, None, false, 0.0).notify);
        assert!(!decide(&warning, &quality(0.5, 0.5), false, None, false, 0.05).notify);
        assert!(decide(&warning, &quality(0.55, 0.55), false, None, false, 0.05).notify);
        // And a relaxation lets a below-floor incident through -- both floors
        // move, so each one alone still gates.
        assert!(decide(&warning, &quality(0.4, 0.4), false, None, false, -0.1).notify);
        assert!(!decide(&warning, &quality(0.4, 0.45), false, None, false, -0.05).notify);
        assert!(!decide(&warning, &quality(0.45, 0.4), false, None, false, -0.05).notify);
        // The relaxed Critical floor moves with it too.
        let critical = alert(Severity::Critical);
        assert!(decide(&critical, &quality(0.5, 0.25), false, None, false, -0.1).notify);
        assert!(!decide(&critical, &quality(0.5, 0.25), false, None, false, 0.0).notify);
    }

    #[test]
    fn light_bucket_comfort_never_softens_the_heavy_bucket() {
        // Spec test 5, the deceptive-comfort guard: a month of "it's fine"
        // ratings given at idle must leave the heavy-load policy exactly as
        // strict as the day it shipped.
        let now_ms = 100 * DAY_MS;
        let comfortable: Vec<Rating> = (0..30)
            .map(|day| {
                rating(
                    RatingVerdict::Good,
                    DemandBucket::Light,
                    now_ms - day * DAY_MS,
                    &["sustainedCpu"],
                )
            })
            .collect();
        let offsets = derive_offsets(&comfortable, now_ms);
        assert!(
            (offsets.lookup("sustainedCpu", DemandBucket::Light) - 0.15).abs() < 1e-9,
            "the light bucket did learn from them"
        );
        assert_eq!(
            offsets.lookup("sustainedCpu", DemandBucket::Heavy),
            0.0,
            "a month of idle comfort must not touch the heavy bucket"
        );

        // And the decision that matters: a heavy-load incident sitting
        // exactly on the shipped floors still notifies at full sensitivity.
        let heavy = alert(Severity::Warning);
        let on_the_floor = quality(0.5, 0.5);
        assert!(
            decide(
                &heavy,
                &on_the_floor,
                false,
                None,
                false,
                offsets.lookup("sustainedCpu", DemandBucket::Heavy)
            )
            .notify,
            "the heavy bucket must still notify at the shipped floors"
        );
        // The same incident under the light workload those ratings described
        // is the one that got stricter.
        assert!(
            !decide(
                &heavy,
                &on_the_floor,
                false,
                None,
                false,
                offsets.lookup("sustainedCpu", DemandBucket::Light)
            )
            .notify
        );
    }
}
