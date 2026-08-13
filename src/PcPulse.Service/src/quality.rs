//! Incident quality scoring and the notification policy.
//!
//! Every active incident carries an [`AlertQuality`] recomputed each
//! evaluation ([`score`]), and the policy floors decide whether that incident
//! is worth interrupting the user for ([`decide`]). Suppression is a
//! *notification* decision only: a suppressed incident is still recorded,
//! still evaluated, still visible in history and the agent context, with its
//! scores attached so the suppression is explainable.

use crate::models::{Alert, AlertQuality, Severity};

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

/// What the runtime knows about the machine's learned baselines when it asks
/// the engine to evaluate a sample.
///
/// `Default` is a fully matured, non-learning machine: the pre-calibration
/// behavior, so a caller with no baseline store (tests, a future embedder)
/// gates on persistence and detector confidence alone rather than silently
/// suppressing everything.
#[derive(Debug, Clone, Copy)]
pub struct Calibration {
    /// Machine baseline age < 24 h; raises the notification floor.
    pub learning: bool,
    /// Machine baseline age as a fraction of the learning period, 0-1.
    pub baseline_maturity: f64,
}

impl Default for Calibration {
    fn default() -> Self {
        Self {
            learning: false,
            baseline_maturity: 1.0,
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
pub fn decide(
    alert: &Alert,
    quality: &AlertQuality,
    learning: bool,
    previous: Option<&Alert>,
    material_change: bool,
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
        && quality.persistence >= PERSISTENCE_FLOOR
        && quality.confidence >= confidence_floor;

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
    use crate::models::IncidentState;

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
        assert!(!decide(&shallow, &scored, false, None, false).notify);
        // Depth alone gets it over the floor, which is the point: the gate is
        // evidence, not time.
        let mut deep = shallow.clone();
        deep.occurrence_count = 10;
        let scored = score(&inputs(&deep, 10 * WINDOW_MS));
        assert!(scored.confidence >= CONFIDENCE_FLOOR);
        assert!(decide(&deep, &scored, false, None, false).notify);
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
        assert!(decide(&dying, &scored, true, None, false).notify);
        // Without the attribution it is a guess against an unlearned machine,
        // and the learning period keeps it quiet.
        probe.attribution_stable = None;
        let unattributed = score(&probe);
        assert!(unattributed.confidence < LEARNING_CONFIDENCE_FLOOR);
        assert!(!decide(&dying, &unattributed, true, None, false).notify);
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
        let decision = decide(&alert, &quality(0.5, 0.5), false, None, false);
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
        assert!(!decide(&warning, &quality(0.5, 0.49), false, None, false).notify);
        assert!(!decide(&warning, &quality(0.49, 0.9), false, None, false).notify);
        // Info never notifies however good it looks.
        assert!(
            !decide(
                &alert(Severity::Info),
                &quality(1.0, 1.0),
                false,
                None,
                false
            )
            .notify
        );
    }

    #[test]
    fn a_critical_notifies_down_to_the_lower_confidence_floor() {
        let alert = alert(Severity::Critical);
        assert!(decide(&alert, &quality(0.5, 0.35), false, None, false).notify);
        assert!(!decide(&alert, &quality(0.5, 0.34), false, None, false).notify);
        // The relaxed floor is confidence only: persistence still gates.
        assert!(!decide(&alert, &quality(0.49, 1.0), false, None, false).notify);
    }

    #[test]
    fn the_learning_period_suppresses_warnings_however_good() {
        let alert = alert(Severity::Warning);
        assert!(decide(&alert, &quality(1.0, 1.0), false, None, false).notify);
        assert!(!decide(&alert, &quality(1.0, 1.0), true, None, false).notify);
    }

    #[test]
    fn the_learning_period_lets_a_critical_through_at_six_tenths_confidence() {
        let alert = alert(Severity::Critical);
        assert!(decide(&alert, &quality(0.5, 0.6), true, None, false).notify);
        assert!(!decide(&alert, &quality(0.5, 0.59), true, None, false).notify);
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
                false
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
                false
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
                true
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
                true
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
                true
            )
            .bump_generation
        );
        // A brand-new incident has no previous state and cannot renotify.
        assert!(!decide(&alert(Severity::Critical), &good, false, None, true).bump_generation);
    }
}
