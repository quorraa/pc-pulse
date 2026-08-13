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
/// Confidence weights; they sum to 1.0. Baseline maturity leads because a
/// learned norm is what separates "unusual" from "Tuesday".
const MATURITY_WEIGHT: f64 = 0.4;
const SAMPLE_DEPTH_WEIGHT: f64 = 0.3;
const ATTRIBUTION_WEIGHT: f64 = 0.3;
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
    /// How long the underlying condition has been breaching, measured from
    /// the first breaching sample -- not from when the incident opened.
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
