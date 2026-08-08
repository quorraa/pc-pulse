use crate::{
    app::{App, InputMode, Page},
    ui::{self, AMBER, AMETHYST, BG, CORAL, ICE, PHOSPHOR, SURFACE, SURFACE_RAISED, UiRegions},
};
use pcpulse_service::models::Severity;
use ratatui::{
    Frame,
    buffer::Buffer,
    layout::{Margin, Rect},
    style::Style,
};
use std::{collections::VecDeque, time::Duration as StdDuration};
use tachyonfx::{
    CellFilter, ColorSpace, Duration as FxDuration, Effect, EffectManager, Interpolation,
    IntoEffect, Motion, SimpleRng, fx,
    fx::{ExpandDirection, Glitch},
    pattern::{DiagonalPattern, RadialPattern, SweepPattern},
};

const FRAME_INTERVAL: StdDuration = StdDuration::from_millis(16);
const IDLE_INTERVAL: StdDuration = StdDuration::from_millis(250);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
enum EffectKey {
    #[default]
    Startup,
    Page,
    Focus,
    Connection,
    Alert,
    Sample,
    Modal,
    Footer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModeKind {
    Normal,
    Search,
    Chat,
    ConfirmTerminate,
    EditSetting,
}

impl From<&InputMode> for ModeKind {
    fn from(mode: &InputMode) -> Self {
        match mode {
            InputMode::Normal => Self::Normal,
            InputMode::Search(_) => Self::Search,
            InputMode::Chat(_) => Self::Chat,
            InputMode::ConfirmTerminate { .. } => Self::ConfirmTerminate,
            InputMode::EditSetting { .. } => Self::EditSetting,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VisualState {
    page: Page,
    selection: Option<usize>,
    mode: ModeKind,
    connected: bool,
    sample_timestamp: Option<i64>,
    active_alerts: Vec<(String, Severity)>,
    status: String,
    status_is_error: bool,
}

impl VisualState {
    fn capture(app: &App) -> Self {
        let selection = match app.page {
            Page::Processes => app.process_state.selected(),
            Page::Tree => app.tree_state.selected(),
            Page::Alerts => app.alert_state.selected(),
            Page::Analyzer => app
                .chat_history_focused
                .then(|| app.chat_session_state.selected())
                .flatten(),
            Page::Settings => app.setting_state.selected(),
            _ => None,
        };
        let active_alerts = app
            .snapshot
            .as_ref()
            .map(|snapshot| {
                let mut values = snapshot
                    .active_alerts
                    .iter()
                    .map(|alert| (alert.id.clone(), alert.severity))
                    .collect::<Vec<_>>();
                values.sort_unstable_by(|left, right| left.0.cmp(&right.0));
                values
            })
            .unwrap_or_default();
        Self {
            page: app.page,
            selection,
            mode: (&app.mode).into(),
            connected: app.connected,
            sample_timestamp: app
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.system.timestamp_ms),
            active_alerts,
            status: app.status.clone(),
            status_is_error: app.status_is_error,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MotionCue {
    Startup,
    Page { forward: bool },
    Focus(Page),
    Connected,
    Disconnected,
    Alert(Severity),
    Sample(Page),
    ModalOpen,
    ModalClose,
    InputOpen,
    Success,
    Failure,
}

/// Coordinates finite TachyonFX compositions while preserving a completely idle render loop.
pub struct MotionSystem {
    manager: EffectManager<EffectKey>,
    pending: VecDeque<MotionCue>,
    previous: VisualState,
    enabled: bool,
    cleanup_frame: bool,
    reset_elapsed: bool,
}

impl MotionSystem {
    pub fn new(app: &App, enabled: bool) -> Self {
        let mut pending = VecDeque::new();
        if enabled {
            pending.push_back(MotionCue::Startup);
        }
        Self {
            manager: EffectManager::default(),
            pending,
            previous: VisualState::capture(app),
            enabled,
            cleanup_frame: false,
            reset_elapsed: enabled,
        }
    }

    pub fn observe(&mut self, app: &App) {
        let next = VisualState::capture(app);
        if !self.enabled {
            self.previous = next;
            return;
        }

        if next.page != self.previous.page {
            let old = page_index(self.previous.page);
            let new = page_index(next.page);
            self.queue(MotionCue::Page {
                forward: page_distance(old, new) >= 0,
            });
        } else if next.selection != self.previous.selection {
            self.queue(MotionCue::Focus(next.page));
        }

        if next.connected != self.previous.connected {
            self.queue(if next.connected {
                MotionCue::Connected
            } else {
                MotionCue::Disconnected
            });
        }

        if self.previous.sample_timestamp.is_some()
            && next.sample_timestamp != self.previous.sample_timestamp
        {
            self.queue(MotionCue::Sample(next.page));
        }

        let new_alert = next
            .active_alerts
            .iter()
            .filter(|(id, _)| {
                !self
                    .previous
                    .active_alerts
                    .iter()
                    .any(|(old_id, _)| old_id == id)
            })
            .map(|(_, severity)| *severity)
            .max_by_key(|severity| severity_rank(*severity));
        if let Some(severity) = new_alert {
            self.queue(MotionCue::Alert(severity));
        }

        if next.mode != self.previous.mode {
            match (self.previous.mode, next.mode) {
                (_, ModeKind::ConfirmTerminate) => self.queue(MotionCue::ModalOpen),
                (ModeKind::ConfirmTerminate, _) => self.queue(MotionCue::ModalClose),
                (_, ModeKind::Search | ModeKind::EditSetting) => {
                    self.queue(MotionCue::InputOpen);
                }
                _ => {}
            }
        }

        if next.status != self.previous.status && !next.status.is_empty() {
            if next.status_is_error {
                self.queue(MotionCue::Failure);
            } else if is_action_status(&next.status) {
                self.queue(MotionCue::Success);
            }
        }
        self.previous = next;
    }

    pub fn toggle(&mut self) -> bool {
        self.enabled = !self.enabled;
        self.manager = EffectManager::default();
        self.pending.clear();
        self.cleanup_frame = true;
        self.reset_elapsed = self.enabled;
        if self.enabled {
            self.pending.push_back(MotionCue::Startup);
        }
        self.enabled
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn is_animating(&self) -> bool {
        self.enabled && (self.manager.is_running() || !self.pending.is_empty())
    }

    pub fn poll_interval(&self) -> StdDuration {
        if self.is_animating() {
            FRAME_INTERVAL
        } else {
            IDLE_INTERVAL
        }
    }

    pub fn render(&mut self, frame: &mut Frame<'_>, elapsed: StdDuration) {
        let area = frame.area();
        self.process_buffer(elapsed, frame.buffer_mut(), area);
    }

    pub fn take_cleanup_frame(&mut self) -> bool {
        std::mem::take(&mut self.cleanup_frame)
    }

    fn process_buffer(&mut self, elapsed: StdDuration, buffer: &mut Buffer, area: Rect) {
        if !self.enabled || area.is_empty() {
            return;
        }
        let regions = ui::regions(area);
        while let Some(cue) = self.pending.pop_front() {
            self.start(cue, regions);
        }
        let elapsed = if std::mem::take(&mut self.reset_elapsed) {
            StdDuration::ZERO
        } else {
            elapsed.min(StdDuration::from_millis(50))
        };
        let was_running = self.manager.is_running();
        self.manager
            .process_effects(elapsed.into(), buffer, regions.full);
        if was_running && !self.manager.is_running() {
            // Some transforms finish away from the authored palette. One final base render
            // restores exact cell styles, then the loop becomes event-driven again.
            self.cleanup_frame = true;
        }
    }

    fn queue(&mut self, cue: MotionCue) {
        if !self.manager.is_running() && self.pending.is_empty() {
            self.reset_elapsed = true;
        }
        self.pending.push_back(cue);
    }

    fn start(&mut self, cue: MotionCue, regions: UiRegions) {
        match cue {
            MotionCue::Startup => {
                let reveal = fx::parallel(&[
                    fx::coalesce((420, Interpolation::ExpoOut))
                        .with_pattern(RadialPattern::new(0.16, 0.0).with_transition_width(7.0))
                        .with_rng(SimpleRng::new(0x5043_5055))
                        .with_filter(CellFilter::NonEmpty)
                        .with_area(regions.full),
                    fx::fade_from(PHOSPHOR, BG, (460, Interpolation::CubicOut))
                        .with_color_space(ColorSpace::Hsv)
                        .with_area(regions.full),
                ]);
                let signature = fx::sweep_in(
                    Motion::LeftToRight,
                    12,
                    0,
                    BG,
                    (220, Interpolation::QuadOut),
                )
                .with_filter(CellFilter::NonEmpty)
                .with_area(regions.header);
                self.manager
                    .add_unique_effect(EffectKey::Startup, fx::sequence(&[reveal, signature]));
            }
            MotionCue::Page { forward } => {
                let direction = if forward {
                    Motion::LeftToRight
                } else {
                    Motion::RightToLeft
                };
                let pattern = if forward {
                    SweepPattern::left_to_right(16)
                } else {
                    SweepPattern::right_to_left(16)
                };
                let effect = fx::parallel(&[
                    fx::slide_in(direction, 8, 1, BG, (210, Interpolation::CubicOut))
                        .with_rng(SimpleRng::new(0x51A7_1001))
                        .with_area(regions.body),
                    fx::fade_from_fg(AMETHYST, (280, Interpolation::SineOut))
                        .with_pattern(pattern)
                        .with_color_space(ColorSpace::Hsv)
                        .with_filter(CellFilter::NonEmpty)
                        .with_area(regions.body),
                    fx::saturate_fg(0.24, (240, Interpolation::QuadOut))
                        .with_pattern(pattern)
                        .with_filter(CellFilter::NonEmpty)
                        .with_area(regions.tabs),
                ]);
                self.manager.add_unique_effect(EffectKey::Page, effect);
            }
            MotionCue::Focus(focus_page) => {
                let area = ui::focus_region(focus_page, regions.body);
                let text = CellFilter::AllOf(vec![
                    CellFilter::NonEmpty,
                    CellFilter::Inner(Margin::new(1, 1)),
                ]);
                let effect = fx::parallel(&[
                    fx::ping_pong(
                        fx::lighten_fg(0.16, (75, Interpolation::SineInOut))
                            .with_pattern(RadialPattern::new(0.0, 0.5).with_transition_width(5.0)),
                    )
                    .with_filter(text.clone())
                    .with_area(area),
                    fx::ping_pong(
                        fx::hsl_shift_fg([14.0, 12.0, 6.0], (85, Interpolation::SineInOut))
                            .with_pattern(SweepPattern::left_to_right(12)),
                    )
                    .with_filter(text)
                    .with_area(area),
                ]);
                self.manager.add_unique_effect(EffectKey::Focus, effect);
            }
            MotionCue::Connected => {
                let effect = fx::parallel(&[
                    fx::coalesce_from(
                        Style::default().fg(PHOSPHOR).bg(BG),
                        (360, Interpolation::ExpoOut),
                    )
                    .with_pattern(RadialPattern::new(0.08, 0.0).with_transition_width(6.0))
                    .with_rng(SimpleRng::new(0xC011_EC7D))
                    .with_filter(CellFilter::NonEmpty)
                    .with_area(regions.body),
                    fx::sweep_in(
                        Motion::LeftToRight,
                        10,
                        0,
                        BG,
                        (260, Interpolation::CubicOut),
                    )
                    .with_area(regions.header),
                ]);
                self.manager
                    .add_unique_effect(EffectKey::Connection, effect);
            }
            MotionCue::Disconnected => {
                let glitch = Glitch::builder()
                    .cell_glitch_ratio(0.035)
                    .action_start_delay_ms(0..90)
                    .action_ms(35..130)
                    .build()
                    .into_effect()
                    .with_rng(SimpleRng::new(0xD15C_0001))
                    .with_filter(CellFilter::NonEmpty)
                    .with_area(regions.full);
                let effect = fx::parallel(&[
                    fx::with_duration(FxDuration::from_millis(230), glitch),
                    fx::fade_from_fg(CORAL, (360, Interpolation::CircOut))
                        .with_pattern(DiagonalPattern::top_right_to_bottom_left())
                        .with_filter(CellFilter::NonEmpty)
                        .with_area(regions.full),
                    fx::ping_pong(
                        fx::darken(Some(0.22), Some(0.12), (120, Interpolation::SineInOut))
                            .with_pattern(SweepPattern::right_to_left(18)),
                    )
                    .with_area(regions.body),
                ]);
                self.manager
                    .add_unique_effect(EffectKey::Connection, effect);
            }
            MotionCue::Alert(severity) => {
                let accent = match severity {
                    Severity::Info => ICE,
                    Severity::Warning => AMBER,
                    Severity::Critical => CORAL,
                };
                let alert_body = fx::sweep_in(
                    Motion::LeftToRight,
                    18,
                    if severity == Severity::Critical { 3 } else { 1 },
                    BG,
                    (340, Interpolation::ExpoOut),
                )
                .with_rng(SimpleRng::new(0xA1E4_7001))
                .with_color_space(ColorSpace::Hsv)
                .with_filter(CellFilter::NonEmpty)
                .with_area(regions.body);
                let pulse = fx::prolong_end(
                    55,
                    fx::ping_pong(
                        fx::fade_to_fg(accent, (105, Interpolation::SineInOut)).with_pattern(
                            DiagonalPattern::top_left_to_bottom_right().with_transition_width(7.0),
                        ),
                    ),
                )
                .with_filter(CellFilter::NonEmpty)
                .with_area(regions.header);
                let mut effects = vec![alert_body, pulse];
                if severity == Severity::Critical {
                    let glitch = Glitch::builder()
                        .cell_glitch_ratio(0.028)
                        .action_start_delay_ms(0..70)
                        .action_ms(25..100)
                        .build()
                        .into_effect()
                        .with_rng(SimpleRng::new(0xC417_1CA1))
                        .with_filter(CellFilter::NonEmpty)
                        .with_area(regions.header);
                    effects.push(fx::with_duration(FxDuration::from_millis(190), glitch));
                }
                self.manager
                    .add_unique_effect(EffectKey::Alert, fx::parallel(&effects));
            }
            MotionCue::Sample(page) => {
                let signal_colors = CellFilter::AnyOf(vec![
                    CellFilter::FgColor(PHOSPHOR),
                    CellFilter::FgColor(AMETHYST),
                    CellFilter::FgColor(ICE),
                    CellFilter::FgColor(AMBER),
                ]);
                let mut effects = vec![
                    fx::ping_pong(
                        fx::lighten_fg(0.2, (120, Interpolation::SineInOut))
                            .with_pattern(SweepPattern::left_to_right(14)),
                    )
                    .with_filter(CellFilter::NonEmpty)
                    .with_area(regions.header),
                ];
                if page == Page::Overview {
                    effects.push(
                        fx::ping_pong(
                            fx::hsl_shift_fg([12.0, 10.0, 8.0], (110, Interpolation::SineInOut))
                                .with_pattern(SweepPattern::left_to_right(18)),
                        )
                        .with_filter(signal_colors)
                        .with_area(regions.body),
                    );
                }
                self.manager
                    .add_unique_effect(EffectKey::Sample, fx::parallel(&effects));
            }
            MotionCue::ModalOpen => {
                let area = ui::modal_region(regions.full);
                let base = Style::default().fg(CORAL).bg(SURFACE_RAISED);
                let effect = fx::parallel(&[
                    fx::expand(
                        ExpandDirection::Horizontal,
                        Style::default().fg(CORAL).bg(BG),
                        (250, Interpolation::BackOut),
                    )
                    .with_area(area),
                    fx::coalesce_from(base, (300, Interpolation::ExpoOut))
                        .with_pattern(RadialPattern::center().with_transition_width(4.0))
                        .with_rng(SimpleRng::new(0xDA7E_600D))
                        .with_filter(CellFilter::NonEmpty)
                        .with_area(area),
                    fx::slide_in(Motion::UpToDown, 5, 0, BG, (220, Interpolation::CubicOut))
                        .with_area(area),
                ]);
                self.manager.add_unique_effect(EffectKey::Modal, effect);
            }
            MotionCue::ModalClose => {
                let effect = fx::sequence(&[
                    fx::dissolve_to(
                        Style::default().fg(PHOSPHOR).bg(SURFACE),
                        (90, Interpolation::QuadIn),
                    )
                    .with_pattern(SweepPattern::right_to_left(8))
                    .with_rng(SimpleRng::new(0xC105_E001))
                    .with_filter(CellFilter::NonEmpty)
                    .with_area(regions.footer),
                    fx::fade_from_fg(PHOSPHOR, (130, Interpolation::QuadOut))
                        .with_area(regions.footer),
                ]);
                self.manager.add_unique_effect(EffectKey::Modal, effect);
            }
            MotionCue::InputOpen => {
                let effect = fx::sweep_in(
                    Motion::LeftToRight,
                    9,
                    0,
                    BG,
                    (180, Interpolation::CubicOut),
                )
                .with_filter(CellFilter::NonEmpty)
                .with_area(regions.footer);
                self.manager.add_unique_effect(EffectKey::Footer, effect);
            }
            MotionCue::Success => {
                self.manager
                    .add_unique_effect(EffectKey::Footer, action_effect(PHOSPHOR, regions.footer));
            }
            MotionCue::Failure => {
                self.manager
                    .add_unique_effect(EffectKey::Footer, action_effect(CORAL, regions.footer));
            }
        }
    }
}

fn action_effect(accent: ratatui::style::Color, area: Rect) -> Effect {
    fx::parallel(&[
        fx::sweep_in(
            Motion::LeftToRight,
            8,
            0,
            BG,
            (190, Interpolation::CubicOut),
        )
        .with_area(area),
        fx::ping_pong(
            fx::fade_to_fg(accent, (90, Interpolation::SineInOut))
                .with_pattern(SweepPattern::left_to_right(10)),
        )
        .with_filter(CellFilter::NonEmpty)
        .with_area(area),
    ])
}

fn page_index(page: Page) -> i32 {
    Page::ALL
        .iter()
        .position(|candidate| *candidate == page)
        .unwrap_or_default() as i32
}

fn page_distance(old: i32, new: i32) -> i32 {
    let length = Page::ALL.len() as i32;
    let direct = new - old;
    if direct.abs() <= length / 2 {
        direct
    } else if direct > 0 {
        direct - length
    } else {
        direct + length
    }
}

const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Critical => 2,
    }
}

fn is_action_status(status: &str) -> bool {
    let lower = status.to_ascii_lowercase();
    ["saved", "acknowledged", "completed", "changed locally"]
        .iter()
        .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{buffer::Cell, style::Color};

    #[test]
    fn startup_is_finite_and_requests_a_clean_base_frame() {
        let app = App::new_inert();
        let mut motion = MotionSystem::new(&app, true);
        let area = Rect::new(0, 0, 120, 36);
        let mut cell = Cell::new("X");
        cell.set_style(Style::default().fg(Color::White).bg(BG));
        let mut buffer = Buffer::filled(area, cell);

        assert!(motion.is_animating());
        for _ in 0..20 {
            motion.process_buffer(StdDuration::from_millis(100), &mut buffer, area);
        }

        assert!(!motion.is_animating());
        assert!(motion.take_cleanup_frame());
    }

    #[test]
    fn unchanged_snapshot_does_not_restart_motion() {
        let mut app = App::new_inert();
        app.connected = true;
        app.snapshot = Some(pcpulse_service::models::Snapshot::default());
        let mut motion = MotionSystem::new(&app, true);
        motion.pending.clear();
        motion.observe(&app);
        assert!(motion.pending.is_empty());
        assert!(!motion.is_animating());
    }

    #[test]
    fn new_snapshot_queues_a_bounded_sample_scan() {
        let mut app = App::new_inert();
        app.connected = true;
        app.snapshot = Some(pcpulse_service::models::Snapshot::default());
        let mut motion = MotionSystem::new(&app, true);
        motion.pending.clear();
        app.snapshot.as_mut().expect("snapshot").system.timestamp_ms += 2_000;
        motion.observe(&app);
        assert_eq!(
            motion.pending.pop_front(),
            Some(MotionCue::Sample(Page::Overview))
        );
    }

    #[test]
    fn long_idle_time_cannot_skip_a_new_effect() {
        let app = App::new_inert();
        let mut motion = MotionSystem::new(&app, true);
        motion.pending.clear();
        motion.reset_elapsed = false;
        motion.queue(MotionCue::Page { forward: true });
        let area = Rect::new(0, 0, 120, 36);
        let mut cell = Cell::new("X");
        cell.set_style(Style::default().fg(Color::White).bg(BG));
        let mut buffer = Buffer::filled(area, cell);
        let baseline = buffer.clone();

        motion.process_buffer(StdDuration::from_secs(30), &mut buffer, area);
        assert!(motion.is_animating());

        buffer = baseline.clone();
        motion.process_buffer(StdDuration::from_millis(16), &mut buffer, area);
        assert_ne!(buffer, baseline, "the next frame must visibly mutate cells");
    }

    #[test]
    fn page_and_focus_changes_replace_their_own_effect_channels() {
        let mut app = App::new_inert();
        let mut motion = MotionSystem::new(&app, true);
        motion.pending.clear();

        app.page = Page::Processes;
        motion.observe(&app);
        assert_eq!(
            motion.pending.pop_front(),
            Some(MotionCue::Page { forward: true })
        );

        app.process_state.select(Some(4));
        motion.observe(&app);
        assert_eq!(
            motion.pending.pop_front(),
            Some(MotionCue::Focus(Page::Processes))
        );
    }

    #[test]
    fn disabled_motion_keeps_the_long_idle_poll_interval() {
        let app = App::new_inert();
        let motion = MotionSystem::new(&app, false);
        assert!(!motion.enabled());
        assert_eq!(motion.poll_interval(), IDLE_INTERVAL);
    }
}
