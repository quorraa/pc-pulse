use crate::{
    analyzer::ChatRole,
    app::{AlertSort, App, InputMode, Page, ProcessSort, SettingSort, SuspectSort, TreeSort},
    format,
};
use pcpulse_service::models::{
    Alert, OptimizationPlan, PlanAction, PlanRisk, ProcessMetric, Severity,
};
use ratatui::{
    Frame,
    crossterm::event::{MouseButton, MouseEvent, MouseEventKind},
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Style},
    symbols,
    text::{Line, Span, Text},
    widgets::{
        Axis, Block, BorderType, Borders, Cell, Chart, Clear, Dataset, GraphType, HighlightSpacing,
        List, ListItem, Padding, Paragraph, Row, Table, Wrap,
    },
};

// "Night signal" palette: low-glare graphite with phosphor and amethyst telemetry.
pub(crate) const BG: Color = Color::Rgb(7, 10, 15);
pub(crate) const SURFACE: Color = Color::Rgb(13, 19, 28);
pub(crate) const SURFACE_RAISED: Color = Color::Rgb(17, 27, 38);
pub(crate) const BORDER: Color = Color::Rgb(34, 50, 68);
pub(crate) const BORDER_HOT: Color = Color::Rgb(55, 81, 103);
pub(crate) const TEXT: Color = Color::Rgb(220, 231, 238);
pub(crate) const MUTED: Color = Color::Rgb(113, 134, 152);
pub(crate) const FAINT: Color = Color::Rgb(66, 85, 102);
pub(crate) const PHOSPHOR: Color = Color::Rgb(112, 225, 193);
pub(crate) const AMETHYST: Color = Color::Rgb(180, 142, 250);
pub(crate) const ICE: Color = Color::Rgb(123, 207, 246);
pub(crate) const AMBER: Color = Color::Rgb(241, 189, 99);
pub(crate) const CORAL: Color = Color::Rgb(255, 110, 138);
pub(crate) const SELECT_BG: Color = Color::Rgb(48, 38, 76);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiRegions {
    pub full: Rect,
    pub header: Rect,
    pub tabs: Rect,
    pub body: Rect,
    pub footer: Rect,
}

pub fn regions(area: Rect) -> UiRegions {
    let chunks = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(12),
        Constraint::Length(3),
    ])
    .split(area);
    let header = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(chunks[0]);
    UiRegions {
        full: area,
        header: chunks[0],
        tabs: header[1],
        body: chunks[1],
        footer: chunks[2],
    }
}

pub fn handle_mouse(app: &mut App, event: MouseEvent, area: Rect) -> bool {
    let mut chat_dismissed = false;
    if matches!(app.mode, InputMode::Chat(_)) {
        if let MouseEventKind::Down(MouseButton::Left) = event.kind {
            let point = (event.column, event.row);
            let layout = regions(area);
            let inside_chat = app.page == Page::Analyzer
                && (point_in(analyzer_transcript(layout.body), point)
                    || point_in(layout.footer, point));
            if inside_chat {
                return false;
            }
            app.mode = InputMode::Normal;
            chat_dismissed = true;
        } else {
            return false;
        }
    } else if !matches!(app.mode, InputMode::Normal) {
        return false;
    }
    let handled = match event.kind {
        MouseEventKind::ScrollUp => {
            mouse_scroll(app, -3);
            true
        }
        MouseEventKind::ScrollDown => {
            mouse_scroll(app, 3);
            true
        }
        MouseEventKind::Down(button @ (MouseButton::Left | MouseButton::Right)) => {
            let point = (event.column, event.row);
            let regions = regions(area);
            if button == MouseButton::Left
                && point_in(regions.tabs, point)
                && let Some(page) = route_at(event.column, regions.tabs)
            {
                app.select_page(page);
                return true;
            }
            if !point_in(regions.body, point) {
                return false;
            }
            mouse_body_click(app, point, button, regions.body)
        }
        _ => false,
    };
    chat_dismissed || handled
}

fn mouse_scroll(app: &mut App, delta: isize) {
    match app.page {
        Page::Timeline => {
            if delta < 0 {
                app.timeline_hours = (app.timeline_hours / 2).max(1);
            } else {
                app.timeline_hours = (app.timeline_hours * 2).min(336);
            }
            app.refresh_page();
        }
        Page::Processes | Page::Tree | Page::Alerts | Page::Analyzer | Page::Settings => {
            app.move_selection(delta);
        }
        _ => {}
    }
}

fn mouse_body_click(app: &mut App, point: (u16, u16), button: MouseButton, body: Rect) -> bool {
    match app.page {
        Page::Overview if button == MouseButton::Left => {
            let table = overview_suspect_area(body);
            if point.1 == table.y.saturating_add(1)
                && let Some(sort) = suspect_sort_at(table, point.0)
            {
                app.suspect_sort = sort;
                app.status = "Overview suspect matrix sorted by clicked header".into();
                app.status_is_error = false;
                return true;
            }
            false
        }
        Page::Processes => {
            let sections =
                Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)])
                    .split(body);
            let table = inset(sections[0]);
            if button == MouseButton::Left
                && point.1 == table.y.saturating_add(1)
                && let Some(sort) = process_sort_at(table, point.0)
            {
                app.process_sort = sort;
                app.process_state.select(Some(0));
                app.status = format!("Processes sorted by {}", sort.label());
                app.status_is_error = false;
                return true;
            }
            if let Some(index) = table_row_at(
                table,
                point,
                2,
                app.process_state.offset(),
                app.visible_processes().len(),
            ) {
                app.process_state.select(Some(index));
                if button == MouseButton::Right {
                    app.begin_termination();
                }
                return true;
            }
            false
        }
        Page::Tree => {
            let sections =
                Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)])
                    .split(body);
            let table = inset(sections[0]);
            if button == MouseButton::Left
                && point.1 == table.y.saturating_add(1)
                && let Some(sort) = tree_sort_at(table, point.0)
            {
                app.tree_sort = sort;
                app.tree_state.select(Some(0));
                app.status = format!("Process tree sorted by {}", sort.label());
                app.status_is_error = false;
                return true;
            }
            if let Some(index) = table_row_at(
                table,
                point,
                2,
                app.tree_state.offset(),
                app.visible_tree_rows().len(),
            ) {
                app.tree_state.select(Some(index));
                if button == MouseButton::Right {
                    app.begin_termination();
                }
                return true;
            }
            false
        }
        Page::Alerts => {
            let sections =
                Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)])
                    .split(body);
            let table = inset(sections[0]);
            if button == MouseButton::Left
                && point.1 == table.y.saturating_add(1)
                && let Some(sort) = alert_sort_at(table, point.0)
            {
                app.alert_sort = sort;
                app.alert_state.select(Some(0));
                app.status = "Findings sorted by clicked header".into();
                app.status_is_error = false;
                return true;
            }
            if let Some(index) = table_row_at(
                table,
                point,
                2,
                app.alert_state.offset(),
                app.visible_alerts().len(),
            ) {
                app.alert_state.select(Some(index));
                return true;
            }
            false
        }
        Page::Analyzer if button == MouseButton::Left && !app.analyzer_running => {
            let rows = Layout::vertical([Constraint::Length(6), Constraint::Min(12)]).split(body);
            let columns = Layout::horizontal([
                Constraint::Percentage(68),
                Constraint::Length(1),
                Constraint::Percentage(32),
            ])
            .split(rows[1]);
            let right = Layout::vertical([
                Constraint::Percentage(34),
                Constraint::Percentage(40),
                Constraint::Percentage(26),
            ])
            .split(columns[2]);
            let history = inset(right[0]);
            if let Some(index) = list_item_at(
                history,
                point,
                1,
                app.chat_session_state.offset(),
                app.chat_sessions.len() + 1,
            ) {
                app.chat_session_state.select(Some(index));
                app.activate_chat_history_index(index);
                return true;
            }
            if point_in(inset(columns[0]), point) {
                app.mode = InputMode::Chat(String::new());
                return true;
            }
            false
        }
        Page::Settings if button == MouseButton::Left => {
            let table = inset(body);
            if point.1 == table.y.saturating_add(1)
                && let Some(sort) = setting_sort_at(table, point.0)
            {
                app.setting_sort = sort;
                app.setting_state.select(Some(0));
                app.status = "Settings sorted by clicked header".into();
                app.status_is_error = false;
                return true;
            }
            if let Some(index) = table_row_at(
                table,
                point,
                2,
                app.setting_state.offset(),
                app.visible_setting_fields().len(),
            ) {
                app.setting_state.select(Some(index));
                app.begin_setting_edit();
                return true;
            }
            false
        }
        _ => false,
    }
}

fn route_at(column: u16, area: Rect) -> Option<Page> {
    let compact = area.width < 112;
    let mut x = area.x;
    for (index, page) in Page::ALL.iter().copied().enumerate() {
        if index > 0 {
            x = x.saturating_add(5);
        }
        let label = if compact {
            route_short(page)
        } else {
            route_name(page)
        };
        let width = (label.chars().count() + 5).min(u16::MAX as usize) as u16;
        if column >= x && column < x.saturating_add(width) {
            return Some(page);
        }
        x = x.saturating_add(width);
    }
    None
}

fn process_constraints() -> [Constraint; 8] {
    [
        Constraint::Length(7),
        Constraint::Min(18),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Length(6),
    ]
}

fn tree_constraints() -> [Constraint; 5] {
    [
        Constraint::Length(7),
        Constraint::Min(28),
        Constraint::Length(8),
        Constraint::Length(11),
        Constraint::Length(11),
    ]
}

fn alert_constraints() -> [Constraint; 5] {
    [
        Constraint::Length(5),
        Constraint::Min(18),
        Constraint::Length(16),
        Constraint::Length(9),
        Constraint::Length(12),
    ]
}

fn setting_constraints() -> [Constraint; 3] {
    [
        Constraint::Percentage(40),
        Constraint::Percentage(48),
        Constraint::Percentage(12),
    ]
}

fn sortable_header_cell(label: &'static str, active: bool, accent: Color) -> Cell<'static> {
    Cell::from(label).style(if active {
        Style::default().fg(BG).bg(accent).bold()
    } else {
        Style::default().fg(accent).bg(SURFACE_RAISED).bold()
    })
}

fn process_sort_at(table: Rect, column: u16) -> Option<ProcessSort> {
    let inner = table.inner(Margin::new(1, 1));
    let columns = Rect::new(
        inner.x.saturating_add(2),
        inner.y,
        inner.width.saturating_sub(2),
        1,
    );
    let rects = Layout::horizontal(process_constraints())
        .spacing(1)
        .split(columns);
    let sorts = [
        ProcessSort::Pid,
        ProcessSort::Name,
        ProcessSort::Cpu,
        ProcessSort::Memory,
        ProcessSort::Io,
        ProcessSort::Handles,
        ProcessSort::Threads,
        ProcessSort::Age,
    ];
    rects
        .iter()
        .zip(sorts)
        .find_map(|(rect, sort)| (column >= rect.x && column < rect.right()).then_some(sort))
}

fn tree_sort_at(table: Rect, column: u16) -> Option<TreeSort> {
    sort_index_at(table, column, &tree_constraints(), 2).and_then(|index| {
        [
            TreeSort::Pid,
            TreeSort::Name,
            TreeSort::Cpu,
            TreeSort::Memory,
            TreeSort::Io,
        ]
        .get(index)
        .copied()
    })
}

fn alert_sort_at(table: Rect, column: u16) -> Option<AlertSort> {
    sort_index_at(table, column, &alert_constraints(), 2).and_then(|index| {
        [
            AlertSort::Severity,
            AlertSort::Title,
            AlertSort::Owner,
            AlertSort::State,
            AlertSort::FirstSeen,
        ]
        .get(index)
        .copied()
    })
}

fn setting_sort_at(table: Rect, column: u16) -> Option<SettingSort> {
    sort_index_at(table, column, &setting_constraints(), 2).and_then(|index| {
        [SettingSort::Name, SettingSort::Value, SettingSort::Unit]
            .get(index)
            .copied()
    })
}

fn suspect_constraints() -> [Constraint; 7] {
    [
        Constraint::Length(3),
        Constraint::Min(17),
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Length(11),
        Constraint::Length(10),
    ]
}

fn suspect_sort_at(table: Rect, column: u16) -> Option<SuspectSort> {
    let inner = Rect::new(
        table.x.saturating_add(1),
        table.y.saturating_add(1),
        table.width.saturating_sub(1),
        table.height.saturating_sub(1),
    );
    let rects = Layout::horizontal(suspect_constraints())
        .spacing(1)
        .split(inner);
    let sorts = [
        SuspectSort::Heat,
        SuspectSort::Name,
        SuspectSort::Heat,
        SuspectSort::Cpu,
        SuspectSort::Memory,
        SuspectSort::Io,
        SuspectSort::HandlesThreads,
    ];
    rects
        .iter()
        .zip(sorts)
        .find_map(|(rect, sort)| (column >= rect.x && column < rect.right()).then_some(sort))
}

fn sort_index_at(
    table: Rect,
    column: u16,
    constraints: &[Constraint],
    selection_width: u16,
) -> Option<usize> {
    let inner = table.inner(Margin::new(1, 1));
    let columns = Rect::new(
        inner.x.saturating_add(selection_width),
        inner.y,
        inner.width.saturating_sub(selection_width),
        1,
    );
    Layout::horizontal(constraints.to_vec())
        .spacing(1)
        .split(columns)
        .iter()
        .position(|rect| column >= rect.x && column < rect.right())
}

fn analyzer_transcript(body: Rect) -> Rect {
    let rows = Layout::vertical([Constraint::Length(6), Constraint::Min(12)]).split(body);
    let columns = Layout::horizontal([
        Constraint::Percentage(68),
        Constraint::Length(1),
        Constraint::Percentage(32),
    ])
    .split(rows[1]);
    inset(columns[0])
}

fn overview_suspect_area(body: Rect) -> Rect {
    let canvas = body.inner(Margin::new(1, 0));
    let vertical = Layout::vertical([
        Constraint::Min(17),
        Constraint::Length(if canvas.height >= 29 { 9 } else { 7 }),
    ])
    .split(canvas);
    let primary = Layout::horizontal([
        Constraint::Percentage(66),
        Constraint::Length(1),
        Constraint::Min(30),
    ])
    .split(vertical[0]);
    Layout::vertical([
        Constraint::Percentage(43),
        Constraint::Length(1),
        Constraint::Min(8),
    ])
    .split(primary[0])[2]
}

fn table_row_at(
    table: Rect,
    point: (u16, u16),
    header_height: u16,
    offset: usize,
    item_count: usize,
) -> Option<usize> {
    if !point_in(table, point) {
        return None;
    }
    let first_row = table.y.saturating_add(1).saturating_add(header_height);
    if point.1 < first_row || point.1 >= table.bottom().saturating_sub(1) {
        return None;
    }
    let index = offset.saturating_add((point.1 - first_row) as usize);
    (index < item_count).then_some(index)
}

fn list_item_at(
    list: Rect,
    point: (u16, u16),
    item_height: u16,
    offset: usize,
    item_count: usize,
) -> Option<usize> {
    if !point_in(list, point) || point.1 <= list.y || point.1 >= list.bottom().saturating_sub(1) {
        return None;
    }
    let visible_index = (point.1 - list.y - 1) / item_height.max(1);
    let index = offset.saturating_add(visible_index as usize);
    (index < item_count).then_some(index)
}

fn point_in(rect: Rect, point: (u16, u16)) -> bool {
    point.0 >= rect.x && point.0 < rect.right() && point.1 >= rect.y && point.1 < rect.bottom()
}

pub fn focus_region(page: Page, body: Rect) -> Rect {
    match page {
        Page::Processes | Page::Tree => {
            Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)]).split(body)
                [1]
        }
        Page::Alerts => {
            Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).split(body)
                [1]
        }
        Page::Analyzer => {
            Layout::horizontal([Constraint::Percentage(68), Constraint::Percentage(32)]).split(body)
                [0]
        }
        _ => body,
    }
}

pub fn modal_region(area: Rect) -> Rect {
    centered_rect(62, 11, area)
}

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().fg(TEXT).bg(BG)),
        area,
    );
    if area.width < 72 || area.height < 20 {
        frame.render_widget(
            Paragraph::new(
                "PC Pulse needs at least 72 columns × 20 rows. Resize the terminal.\n\nq  quit",
            )
            .alignment(Alignment::Center)
            .block(panel(" Terminal too small ")),
            area,
        );
        return;
    }
    let regions = regions(area);
    render_header(frame, app, regions.header);
    match app.page {
        Page::Overview => render_overview(frame, app, regions.body),
        Page::Processes => render_processes(frame, app, regions.body),
        Page::Tree => render_tree(frame, app, regions.body),
        Page::Alerts => render_alerts(frame, app, regions.body),
        Page::Timeline => render_timeline(frame, app, regions.body),
        Page::Analyzer => render_analyzer(frame, app, regions.body),
        Page::Settings => render_settings(frame, app, regions.body),
        Page::Help => render_help(frame, regions.body),
    }
    render_footer(frame, app, regions.footer);
    render_modal(frame, app);
}

fn render_header(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let (status, status_color) = if app.connected {
        let etw = app
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.system.etw_active);
        (
            if etw {
                "LINKED / ETW"
            } else {
                "LINKED / ETW DEGRADED"
            },
            if etw { PHOSPHOR } else { AMBER },
        )
    } else {
        ("SIGNAL LOST", CORAL)
    };
    let version = app
        .snapshot
        .as_ref()
        .map(|snapshot| snapshot.service_version.as_str())
        .unwrap_or("—");
    let active = app
        .snapshot
        .as_ref()
        .map_or(0, |snapshot| snapshot.active_alerts.len());
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Length(1),
    ])
    .split(area);
    let top =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).split(rows[0]);
    let brand = vec![
        Line::from(vec![
            Span::styled(
                " PCPULSE::NIGHTWATCH ",
                Style::default().fg(BG).bg(PHOSPHOR).bold(),
            ),
            Span::styled(" / RUNTIME FORENSICS", Style::default().fg(MUTED).bold()),
        ]),
        Line::from(vec![
            Span::styled(
                format!(" {:02} {} ", page_index(app.page) + 1, route_name(app.page)),
                Style::default().fg(AMETHYST).bold(),
            ),
            Span::styled(route_description(app.page), Style::default().fg(FAINT)),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(brand).style(Style::default().fg(TEXT).bg(SURFACE)),
        top[0],
    );

    let telemetry = if let Some(snapshot) = &app.snapshot {
        let memory = percent(
            snapshot.system.memory_used_bytes,
            snapshot.system.memory_total_bytes,
        );
        format!(
            "CPU {:>5.1}%  MEM {:>5.1}%  {:>4}P / {:>5}T",
            snapshot.system.cpu_percent,
            memory,
            snapshot.system.process_count,
            snapshot.system.thread_count
        )
    } else {
        "awaiting first telemetry frame".into()
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    format!("● {status}"),
                    Style::default().fg(status_color).bold(),
                ),
                Span::styled(
                    format!("   ⚑ {active} OPEN   v{version} "),
                    Style::default()
                        .fg(if active > 0 { AMBER } else { MUTED })
                        .bold(),
                ),
            ])
            .alignment(Alignment::Right),
            Line::styled(telemetry, Style::default().fg(MUTED)).alignment(Alignment::Right),
        ])
        .style(Style::default().bg(SURFACE)),
        top[1],
    );

    render_route(frame, app, rows[1]);
    frame.render_widget(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(BORDER_HOT))
            .style(Style::default().bg(SURFACE)),
        rows[2],
    );
}

fn render_route(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let compact = area.width < 112;
    let mut spans = Vec::new();
    for (index, page) in Page::ALL.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled("  ›  ", Style::default().fg(BORDER_HOT)));
        }
        let label = if compact {
            route_short(*page)
        } else {
            route_name(*page)
        };
        let text = format!(" {:02} {label} ", index + 1);
        spans.push(if *page == app.page {
            Span::styled(text, Style::default().fg(BG).bg(AMETHYST).bold())
        } else {
            Span::styled(text, Style::default().fg(MUTED))
        });
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(SURFACE)),
        area,
    );
}

fn route_name(page: Page) -> &'static str {
    match page {
        Page::Overview => "OBSERVE",
        Page::Processes => "HUNT",
        Page::Tree => "LINEAGE",
        Page::Alerts => "INCIDENTS",
        Page::Timeline => "CHRONICLE",
        Page::Analyzer => "ORACLE",
        Page::Settings => "TUNE",
        Page::Help => "MANUAL",
    }
}

fn route_short(page: Page) -> &'static str {
    match page {
        Page::Overview => "OBS",
        Page::Processes => "HUNT",
        Page::Tree => "TREE",
        Page::Alerts => "ALERT",
        Page::Timeline => "TIME",
        Page::Analyzer => "ASK",
        Page::Settings => "TUNE",
        Page::Help => "HELP",
    }
}

fn route_description(page: Page) -> &'static str {
    match page {
        Page::Overview => "pressure map / likely culprits / live incidents",
        Page::Processes => "rank / filter / inspect process pressure",
        Page::Tree => "trace ownership through parent-child lineages",
        Page::Alerts => "explain sustained findings with evidence",
        Page::Timeline => "read persisted system pressure over time",
        Page::Analyzer => "question a systems analyst grounded in live evidence",
        Page::Settings => "shape baselines and sustained thresholds",
        Page::Help => "operate the console without leaving the keyboard",
    }
}

fn page_index(page: Page) -> usize {
    Page::ALL
        .iter()
        .position(|candidate| *candidate == page)
        .unwrap_or_default()
}

fn render_overview(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        render_offline(frame, app, area);
        return;
    };
    let canvas = area.inner(Margin::new(1, 0));
    let vertical = Layout::vertical([
        Constraint::Min(17),
        Constraint::Length(if canvas.height >= 29 { 9 } else { 7 }),
    ])
    .split(canvas);
    let primary = Layout::horizontal([
        Constraint::Percentage(66),
        Constraint::Length(1),
        Constraint::Min(30),
    ])
    .split(vertical[0]);
    let left = Layout::vertical([
        Constraint::Percentage(43),
        Constraint::Length(1),
        Constraint::Min(8),
    ])
    .split(primary[0]);
    let right = Layout::vertical([
        Constraint::Percentage(57),
        Constraint::Length(1),
        Constraint::Min(7),
    ])
    .split(primary[2]);

    render_pressure_field(frame, app, left[0]);
    render_suspect_matrix(frame, app, left[2]);
    render_system_vector(frame, app, right[0]);
    render_agent_swarm(frame, app, right[2]);
    render_incident_tape(frame, app, vertical[1]);

    let _ = snapshot;
}

fn render_pressure_field(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        return;
    };
    let minimum = app
        .live_history
        .front()
        .map_or(0.0, |point| point.timestamp_ms as f64);
    let maximum = app
        .live_history
        .back()
        .map_or(minimum + 1.0, |point| point.timestamp_ms as f64)
        .max(minimum + 1.0);
    let cpu = app
        .live_history
        .iter()
        .map(|point| (point.timestamp_ms as f64, point.cpu_percent))
        .collect::<Vec<_>>();
    let memory = app
        .live_history
        .iter()
        .map(|point| {
            (
                point.timestamp_ms as f64,
                percent(point.memory_used_bytes, point.memory_total_bytes),
            )
        })
        .collect::<Vec<_>>();
    let memory_now = percent(
        snapshot.system.memory_used_bytes,
        snapshot.system.memory_total_bytes,
    );
    let title = format!(
        " ∿ PRESSURE FIELD  CPU {:>5.1}%  /  MEM {:>5.1}% ",
        snapshot.system.cpu_percent, memory_now
    );
    let datasets = vec![
        Dataset::default()
            .name("CPU")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(PHOSPHOR))
            .data(&cpu),
        Dataset::default()
            .name("MEM")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(AMETHYST))
            .data(&memory),
    ];
    frame.render_widget(
        Chart::new(datasets)
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(field_block(&title, PHOSPHOR))
            .x_axis(Axis::default().bounds([minimum, maximum]))
            .y_axis(
                Axis::default()
                    .style(Style::default().fg(FAINT))
                    .bounds([0.0, 100.0])
                    .labels([
                        Line::styled("0", Style::default().fg(FAINT)),
                        Line::styled("50", Style::default().fg(MUTED)),
                        Line::styled("100", Style::default().fg(FAINT)),
                    ]),
            ),
        area,
    );
}

fn render_suspect_matrix(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        return;
    };
    let mut suspects = snapshot.processes.iter().collect::<Vec<_>>();
    suspects.sort_by(|left, right| match app.suspect_sort {
        SuspectSort::Heat => triage_heat(right, app)
            .total_cmp(&triage_heat(left, app))
            .then_with(|| right.cpu_percent.total_cmp(&left.cpu_percent)),
        SuspectSort::Name => left
            .name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase()),
        SuspectSort::Cpu => right.cpu_percent.total_cmp(&left.cpu_percent),
        SuspectSort::Memory => right.working_set_bytes.cmp(&left.working_set_bytes),
        SuspectSort::Io => (right.read_bytes_per_sec + right.write_bytes_per_sec)
            .total_cmp(&(left.read_bytes_per_sec + left.write_bytes_per_sec)),
        SuspectSort::HandlesThreads => {
            (right.handle_count + right.thread_count).cmp(&(left.handle_count + left.thread_count))
        }
    });
    let capacity = usize::from(area.height.saturating_sub(3)).max(1);
    let rows = suspects
        .into_iter()
        .filter(|process| process.pid > 4)
        .take(capacity)
        .enumerate()
        .map(|(index, process)| {
            let heat = triage_heat(process, app);
            let owner_style = if !process.responsive {
                Style::default().fg(CORAL).bold()
            } else if process.is_agent_candidate {
                Style::default().fg(AMETHYST).bold()
            } else {
                Style::default().fg(TEXT)
            };
            Row::new(vec![
                Cell::from(format!("{:02}", index + 1)).style(Style::default().fg(FAINT)),
                Cell::from(Line::from(vec![
                    Span::styled(
                        if !process.responsive {
                            "HNG "
                        } else if process.is_agent_candidate {
                            "AGT "
                        } else {
                            "    "
                        },
                        owner_style,
                    ),
                    Span::styled(format::truncate(&process.name, 28), owner_style),
                ])),
                Cell::from(Line::from(vec![
                    Span::styled(
                        meter(heat / 100.0, 7),
                        Style::default().fg(heat_color(heat)),
                    ),
                    Span::styled(
                        format!(" {heat:>3.0}"),
                        Style::default().fg(heat_color(heat)),
                    ),
                ])),
                Cell::from(format!("{:>5.1}%", process.cpu_percent)),
                Cell::from(format::bytes(process.working_set_bytes)),
                Cell::from(format::rate(
                    process.read_bytes_per_sec + process.write_bytes_per_sec,
                )),
                Cell::from(format!("{}/{}", process.handle_count, process.thread_count)),
            ])
            .style(Style::default().bg(if index.is_multiple_of(2) {
                SURFACE
            } else {
                SURFACE_RAISED
            }))
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Table::new(rows, suspect_constraints())
            .header(
                Row::new([
                    sortable_header_cell("#", app.suspect_sort == SuspectSort::Heat, AMETHYST),
                    sortable_header_cell("TARGET", app.suspect_sort == SuspectSort::Name, AMETHYST),
                    sortable_header_cell(
                        "TRIAGE HEAT",
                        app.suspect_sort == SuspectSort::Heat,
                        AMETHYST,
                    ),
                    sortable_header_cell("CPU", app.suspect_sort == SuspectSort::Cpu, AMETHYST),
                    sortable_header_cell("RSS", app.suspect_sort == SuspectSort::Memory, AMETHYST),
                    sortable_header_cell("I/O", app.suspect_sort == SuspectSort::Io, AMETHYST),
                    sortable_header_cell(
                        "H/T",
                        app.suspect_sort == SuspectSort::HandlesThreads,
                        AMETHYST,
                    ),
                ])
                .style(Style::default().fg(AMETHYST).bg(SURFACE_RAISED).bold()),
            )
            .block(field_block(
                " ⌖ SUSPECT MATRIX  relative pressure / not an alert score ",
                AMETHYST,
            )),
        area,
    );
}

fn render_system_vector(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        return;
    };
    let system = &snapshot.system;
    let memory = percent(system.memory_used_bytes, system.memory_total_bytes);
    let io = system.disk_read_bytes_per_sec + system.disk_write_bytes_per_sec;
    let pool = system.paged_pool_bytes + system.nonpaged_pool_bytes;
    let meter_width = usize::from(area.width.saturating_sub(25).clamp(5, 14));
    let mut lines = vec![
        vector_line(
            "CPU",
            system.cpu_percent / 100.0,
            format!("{:.1}%", system.cpu_percent),
            meter_width,
        ),
        vector_line("MEM", memory / 100.0, format!("{memory:.1}%"), meter_width),
        vector_line(
            "DISK",
            system.disk_latency_ms / app.settings.disk_latency_ms.max(1.0),
            format!("{:.1} ms", system.disk_latency_ms),
            meter_width,
        ),
        vector_line(
            "I/O",
            io / (app.settings.io_mb_per_sec.max(1.0) * 1024.0 * 1024.0),
            format::rate(io),
            meter_width,
        ),
        vector_line(
            "DPC",
            system.dpc_rate / app.settings.dpc_rate.max(1.0),
            format!("{:.0}/s", system.dpc_rate),
            meter_width,
        ),
        vector_line(
            "IRQ",
            system.interrupt_rate / app.settings.interrupt_rate.max(1.0),
            format!("{:.0}/s", system.interrupt_rate),
            meter_width,
        ),
        Line::from(vec![
            Span::styled(" POOL ", Style::default().fg(ICE).bold()),
            Span::styled(format::bytes(pool), Style::default().fg(TEXT)),
            Span::styled("   R/W ", Style::default().fg(FAINT)),
            Span::styled(
                format!(
                    "{} / {}",
                    format::rate(system.disk_read_bytes_per_sec),
                    format::rate(system.disk_write_bytes_per_sec)
                ),
                Style::default().fg(MUTED),
            ),
        ]),
        Line::styled("", Style::default()),
    ];
    let collector_ratio = (system.collector_working_set_bytes as f64 / (25.0 * 1024.0 * 1024.0))
        .max(system.collector_cpu_percent / 0.2)
        .max(f64::from(system.collector_handle_count) / 250.0);
    lines.push(Line::from(vec![
        Span::styled(" COLLECTOR ", Style::default().fg(BG).bg(ICE).bold()),
        Span::styled(
            format!(
                "  {}  {:.3}%  {}H ",
                format::bytes(system.collector_working_set_bytes),
                system.collector_cpu_percent,
                system.collector_handle_count
            ),
            Style::default().fg(ratio_color(collector_ratio)).bold(),
        ),
    ]));
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(field_block(" ◇ SYSTEM VECTOR  threshold-relative ", ICE)),
        area,
    );
}

fn render_agent_swarm(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        return;
    };
    let mut agents = snapshot
        .processes
        .iter()
        .filter(|process| process.is_agent_candidate)
        .collect::<Vec<_>>();
    agents.sort_by(|left, right| triage_heat(right, app).total_cmp(&triage_heat(left, app)));
    let cpu = agents
        .iter()
        .map(|process| process.cpu_percent)
        .sum::<f64>();
    let memory = agents
        .iter()
        .map(|process| process.working_set_bytes)
        .sum::<u64>();
    let abandoned = snapshot
        .active_alerts
        .iter()
        .filter(|alert| alert.kind.contains("abandoned"))
        .count();
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" {:02} TRACKED ", agents.len()),
                Style::default().fg(BG).bg(AMETHYST).bold(),
            ),
            Span::styled(
                format!("  CPU {cpu:.1}%  RSS {}", format::bytes(memory)),
                Style::default().fg(TEXT),
            ),
        ]),
        Line::from(vec![
            Span::styled(" ABANDONED ", Style::default().fg(FAINT).bold()),
            Span::styled(
                format!("{abandoned} sustained finding(s)"),
                Style::default()
                    .fg(if abandoned > 0 { CORAL } else { MUTED })
                    .bold(),
            ),
        ]),
    ];
    let capacity = usize::from(area.height.saturating_sub(4));
    for process in agents.into_iter().take(capacity) {
        lines.push(Line::from(vec![
            Span::styled("  ├─ ", Style::default().fg(BORDER_HOT)),
            Span::styled(format!("{:<6}", process.pid), Style::default().fg(AMETHYST)),
            Span::styled(
                format!("{:<18}", format::truncate(&process.name, 17)),
                Style::default().fg(TEXT).bold(),
            ),
            Span::styled(
                format!(
                    " {:>5.1}%  {}",
                    process.cpu_percent,
                    format::bytes(process.working_set_bytes)
                ),
                Style::default().fg(MUTED),
            ),
        ]));
    }
    if lines.len() == 2 {
        lines.push(Line::styled(
            "  no configured agent process patterns are active",
            Style::default().fg(FAINT),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(field_block(
                " ⑂ AGENT SWARM  parallel-run footprint ",
                AMETHYST,
            )),
        area,
    );
}

fn render_incident_tape(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        return;
    };
    let capacity = usize::from(area.height.saturating_sub(2)).max(1);
    let mut lines = snapshot
        .active_alerts
        .iter()
        .take(capacity)
        .map(|alert| {
            let owner = alert.process_name.as_deref().unwrap_or("system / driver");
            let evidence = alert
                .evidence
                .first()
                .map(|item| format!("{} {}", item.label, item.value))
                .unwrap_or_else(|| "sustained condition confirmed".into());
            Line::from(vec![
                Span::styled(
                    format!(" {} ", severity_label(alert.severity)),
                    severity_badge(alert.severity),
                ),
                Span::styled(
                    format!(" {:<24}", format::truncate(owner, 23)),
                    Style::default().fg(TEXT).bold(),
                ),
                Span::styled(
                    format!(" {:<34}", format::truncate(&alert.title, 33)),
                    Style::default().fg(severity_color(alert.severity)),
                ),
                Span::styled(
                    format!("  :: {}", format::truncate(&evidence, 44)),
                    Style::default().fg(MUTED),
                ),
            ])
        })
        .collect::<Vec<_>>();
    if lines.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(" QUIET ", Style::default().fg(BG).bg(PHOSPHOR).bold()),
            Span::styled(
                "  no sustained deviations in the active window",
                Style::default().fg(MUTED),
            ),
        ]));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(field_block(
                " ⚑ INCIDENT TAPE  owner / condition / evidence ",
                AMBER,
            )),
        area,
    );
}

fn vector_line(label: &'static str, ratio: f64, value: String, width: usize) -> Line<'static> {
    let color = ratio_color(ratio);
    Line::from(vec![
        Span::styled(format!(" {label:<5}"), Style::default().fg(MUTED).bold()),
        Span::styled(meter(ratio, width), Style::default().fg(color)),
        Span::styled(format!("  {value}"), Style::default().fg(color).bold()),
    ])
}

fn meter(ratio: f64, width: usize) -> String {
    let filled = (ratio.clamp(0.0, 1.0) * width as f64).round() as usize;
    format!(
        "{}{}",
        "━".repeat(filled),
        "┄".repeat(width.saturating_sub(filled))
    )
}

fn ratio_color(ratio: f64) -> Color {
    if ratio >= 1.0 {
        CORAL
    } else if ratio >= 0.72 {
        AMBER
    } else {
        PHOSPHOR
    }
}

fn heat_color(heat: f64) -> Color {
    ratio_color(heat / 70.0)
}

fn triage_heat(process: &ProcessMetric, app: &App) -> f64 {
    let Some(snapshot) = &app.snapshot else {
        return 0.0;
    };
    let cpu = process.cpu_percent / app.settings.cpu_percent.max(1.0);
    let io = (process.read_bytes_per_sec + process.write_bytes_per_sec)
        / (app.settings.io_mb_per_sec.max(1.0) * 1024.0 * 1024.0);
    let memory_target = (snapshot.system.memory_total_bytes as f64 * 0.08).max(1.0);
    let memory = process.working_set_bytes as f64 / memory_target;
    let handles = f64::from(process.handle_count) / 1_500.0;
    let threads = f64::from(process.thread_count) / 150.0;
    let weighted = cpu.clamp(0.0, 2.0) * 0.40
        + io.clamp(0.0, 2.0) * 0.22
        + memory.clamp(0.0, 2.0) * 0.18
        + handles.clamp(0.0, 2.0) * 0.10
        + threads.clamp(0.0, 2.0) * 0.10;
    (weighted * 70.0
        + if process.responsive { 0.0 } else { 20.0 }
        + if process.is_agent_candidate { 4.0 } else { 0.0 })
    .clamp(0.0, 100.0)
}

fn field_block<'a>(title: &'a str, accent: Color) -> Block<'a> {
    Block::default()
        .borders(Borders::TOP | Borders::LEFT)
        .border_type(BorderType::QuadrantOutside)
        .border_style(Style::default().fg(BORDER_HOT))
        .style(Style::default().fg(TEXT).bg(SURFACE))
        .title(title)
        .title_style(Style::default().fg(accent).bold())
}

fn render_processes(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let sections =
        Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)]).split(area);
    let processes = app.visible_processes();
    let rows = processes
        .iter()
        .enumerate()
        .map(|(index, process)| process_row(process, index))
        .collect::<Vec<_>>();
    let title = format!(
        " ⌘ PROCESS SPECTRUM · {} shown · {} · sort {} · filter {} ",
        rows.len(),
        if app.agents_only {
            "AGENT FOCUS"
        } else {
            "all"
        },
        app.process_sort.label(),
        if app.process_filter.is_empty() {
            "none"
        } else {
            &app.process_filter
        }
    );
    let table = Table::new(rows, process_constraints())
        .header(
            Row::new([
                process_header_cell("PID", ProcessSort::Pid, app.process_sort),
                process_header_cell("NAME", ProcessSort::Name, app.process_sort),
                process_header_cell("CPU", ProcessSort::Cpu, app.process_sort),
                process_header_cell("MEM", ProcessSort::Memory, app.process_sort),
                process_header_cell("I/O", ProcessSort::Io, app.process_sort),
                process_header_cell("HANDLES", ProcessSort::Handles, app.process_sort),
                process_header_cell("THR", ProcessSort::Threads, app.process_sort),
                process_header_cell("AGE", ProcessSort::Age, app.process_sort),
            ])
            .style(Style::default().fg(AMETHYST).bg(SURFACE_RAISED).bold())
            .bottom_margin(1),
        )
        .block(accent_panel(
            &title,
            if app.agents_only { AMETHYST } else { PHOSPHOR },
        ))
        .row_highlight_style(Style::default().fg(TEXT).bg(SELECT_BG).bold())
        .highlight_symbol("▌ ")
        .highlight_spacing(HighlightSpacing::Always);
    frame.render_stateful_widget(table, inset(sections[0]), &mut app.process_state);
    render_process_detail(frame, app.selected_process(), inset(sections[1]));
}

fn process_header_cell(
    label: &'static str,
    column: ProcessSort,
    current: ProcessSort,
) -> Cell<'static> {
    Cell::from(label).style(if column == current {
        Style::default().fg(BG).bg(PHOSPHOR).bold()
    } else {
        Style::default().fg(AMETHYST).bg(SURFACE_RAISED).bold()
    })
}

fn process_row(process: &&ProcessMetric, index: usize) -> Row<'static> {
    let status_style = if !process.responsive {
        Style::default().fg(CORAL).bold()
    } else if process.is_agent_candidate {
        Style::default().fg(AMETHYST)
    } else {
        Style::default().fg(TEXT)
    };
    Row::new(vec![
        Cell::from(process.pid.to_string()),
        Cell::from(Line::from(vec![
            if process.is_agent_candidate {
                Span::styled(" AGT ", Style::default().fg(BG).bg(AMETHYST).bold())
            } else if !process.responsive {
                Span::styled(" HNG ", Style::default().fg(BG).bg(CORAL).bold())
            } else {
                Span::raw("")
            },
            Span::raw(if process.is_agent_candidate || !process.responsive {
                " "
            } else {
                ""
            }),
            Span::styled(format::truncate(&process.name, 24), status_style),
        ])),
        Cell::from(format!("{:.1}%", process.cpu_percent)).style(if process.cpu_percent >= 80.0 {
            Style::default().fg(CORAL).bold()
        } else if process.cpu_percent >= 30.0 {
            Style::default().fg(AMBER)
        } else {
            Style::default().fg(PHOSPHOR)
        }),
        Cell::from(format::bytes(process.working_set_bytes)),
        Cell::from(format::rate(
            process.read_bytes_per_sec + process.write_bytes_per_sec,
        )),
        Cell::from(process.handle_count.to_string()),
        Cell::from(process.thread_count.to_string()),
        Cell::from(format::age(process.started_at_ms, process.timestamp_ms)),
    ])
    .style(Style::default().fg(TEXT).bg(if index.is_multiple_of(2) {
        SURFACE
    } else {
        SURFACE_RAISED
    }))
}

fn render_process_detail(frame: &mut Frame<'_>, process: Option<&ProcessMetric>, area: Rect) {
    let text = if let Some(process) = process {
        Text::from(vec![
            Line::styled(process.name.clone(), Style::default().fg(PHOSPHOR).bold()),
            Line::styled(
                if process.is_agent_candidate {
                    "◆ AGENT PATTERN MATCH"
                } else if !process.responsive {
                    "! WINDOW NOT RESPONDING"
                } else {
                    "● PROCESS TELEMETRY"
                },
                Style::default()
                    .fg(if process.is_agent_candidate {
                        AMETHYST
                    } else if !process.responsive {
                        CORAL
                    } else {
                        MUTED
                    })
                    .bold(),
            ),
            detail_line(
                "PID / parent",
                format!("{} / {}", process.pid, process.parent_pid),
            ),
            detail_line("CPU", format!("{:.2}%", process.cpu_percent)),
            detail_line("Working set", format::bytes(process.working_set_bytes)),
            detail_line("Private", format::bytes(process.private_bytes)),
            detail_line("Read", format::rate(process.read_bytes_per_sec)),
            detail_line("Write", format::rate(process.write_bytes_per_sec)),
            detail_line("Handles", process.handle_count.to_string()),
            detail_line("Threads", process.thread_count.to_string()),
            detail_line("Session", process.session_id.to_string()),
            detail_line("Responsive", yes_no(process.responsive)),
            detail_line("Visible window", yes_no(process.has_visible_window)),
            detail_line("Agent candidate", yes_no(process.is_agent_candidate)),
            Line::raw(""),
            Line::styled(
                format::truncate(&process.executable_path, 90),
                Style::default().fg(MUTED),
            ),
            Line::raw(""),
            Line::styled(
                "[ x ]  REQUEST TERMINATION",
                Style::default().fg(AMBER).bold(),
            ),
            Line::styled("Exact PID entry is required.", Style::default().fg(MUTED)),
        ])
    } else {
        Text::from("No process selected")
    };
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(accent_panel(" ◇ PROCESS LENS ", AMETHYST)),
        area,
    );
}

fn render_tree(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let sections =
        Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)]).split(area);
    let rows = app
        .visible_tree_rows()
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            let branch = if app.tree_sort != TreeSort::Lineage || row.depth == 0 {
                "".into()
            } else {
                format!("{}└─ ", "  ".repeat(row.depth.saturating_sub(1)))
            };
            Row::new(vec![
                Cell::from(row.process.pid.to_string()),
                Cell::from(Line::from(vec![
                    Span::styled(branch, Style::default().fg(FAINT)),
                    if row.process.is_agent_candidate {
                        Span::styled("◆ ", Style::default().fg(AMETHYST).bold())
                    } else {
                        Span::raw("· ")
                    },
                    Span::styled(
                        format::truncate(&row.process.name, 40),
                        Style::default().fg(if row.process.is_agent_candidate {
                            AMETHYST
                        } else {
                            TEXT
                        }),
                    ),
                ])),
                Cell::from(format!("{:.1}%", row.process.cpu_percent)),
                Cell::from(format::bytes(row.process.working_set_bytes)),
                Cell::from(format::rate(
                    row.process.read_bytes_per_sec + row.process.write_bytes_per_sec,
                )),
            ])
            .style(Style::default().fg(TEXT).bg(if index.is_multiple_of(2) {
                SURFACE
            } else {
                SURFACE_RAISED
            }))
        })
        .collect::<Vec<_>>();
    let title = format!(
        " ⑂ LINEAGE MAP · sort {} · r restores lineage ",
        app.tree_sort.label()
    );
    let table = Table::new(rows, tree_constraints())
        .header(
            Row::new([
                sortable_header_cell("PID", app.tree_sort == TreeSort::Pid, ICE),
                sortable_header_cell("PROCESS TREE", app.tree_sort == TreeSort::Name, ICE),
                sortable_header_cell("CPU", app.tree_sort == TreeSort::Cpu, ICE),
                sortable_header_cell("MEM", app.tree_sort == TreeSort::Memory, ICE),
                sortable_header_cell("I/O", app.tree_sort == TreeSort::Io, ICE),
            ])
            .style(Style::default().fg(ICE).bg(SURFACE_RAISED).bold())
            .bottom_margin(1),
        )
        .block(accent_panel(&title, ICE))
        .row_highlight_style(Style::default().fg(TEXT).bg(SELECT_BG).bold())
        .highlight_symbol("▌ ")
        .highlight_spacing(HighlightSpacing::Always);
    frame.render_stateful_widget(table, inset(sections[0]), &mut app.tree_state);
    render_process_detail(frame, app.selected_tree_process(), inset(sections[1]));
}

fn render_alerts(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let sections =
        Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).split(area);
    let rows = app
        .visible_alerts()
        .into_iter()
        .enumerate()
        .map(|(index, alert)| {
            let state = if alert.resolved_at_ms.is_some() {
                "resolved"
            } else if alert.acknowledged {
                "ack"
            } else {
                "ACTIVE"
            };
            Row::new(vec![
                Cell::from(severity_label(alert.severity)).style(severity_badge(alert.severity)),
                Cell::from(format::truncate(&alert.title, 42))
                    .style(Style::default().fg(TEXT).bold()),
                Cell::from(
                    alert
                        .process_name
                        .as_deref()
                        .unwrap_or("system / driver")
                        .to_string(),
                )
                .style(Style::default().fg(MUTED)),
                Cell::from(state).style(
                    Style::default()
                        .fg(if state == "ACTIVE" { AMBER } else { FAINT })
                        .bold(),
                ),
                Cell::from(format::timestamp(alert.first_seen_ms))
                    .style(Style::default().fg(FAINT)),
            ])
            .style(Style::default().bg(if index.is_multiple_of(2) {
                SURFACE
            } else {
                SURFACE_RAISED
            }))
        })
        .collect::<Vec<_>>();
    let table = Table::new(rows, alert_constraints())
        .header(
            Row::new([
                sortable_header_cell("SEV", app.alert_sort == AlertSort::Severity, AMBER),
                sortable_header_cell("FINDING", app.alert_sort == AlertSort::Title, AMBER),
                sortable_header_cell("OWNER", app.alert_sort == AlertSort::Owner, AMBER),
                sortable_header_cell("STATE", app.alert_sort == AlertSort::State, AMBER),
                sortable_header_cell("SEEN", app.alert_sort == AlertSort::FirstSeen, AMBER),
            ])
            .style(Style::default().fg(AMBER).bg(SURFACE_RAISED).bold())
            .bottom_margin(1),
        )
        .block(accent_panel(
            " ⚑ FINDING ARCHIVE · click headers to sort · a acknowledge ",
            AMBER,
        ))
        .row_highlight_style(Style::default().fg(TEXT).bg(SELECT_BG).bold())
        .highlight_symbol("▌ ")
        .highlight_spacing(HighlightSpacing::Always);
    frame.render_stateful_widget(table, inset(sections[0]), &mut app.alert_state);
    render_alert_detail(frame, app.selected_alert(), inset(sections[1]));
}

fn render_alert_detail(frame: &mut Frame<'_>, alert: Option<&Alert>, area: Rect) {
    let Some(alert) = alert else {
        frame.render_widget(
            Paragraph::new("No findings in the selected retention window.")
                .style(Style::default().fg(MUTED).bg(SURFACE))
                .block(accent_panel(" ◇ EVIDENCE ", AMETHYST)),
            area,
        );
        return;
    };
    let mut lines = vec![
        Line::styled(
            alert.title.clone(),
            Style::default().fg(severity_color(alert.severity)).bold(),
        ),
        detail_line("Severity", format!("{:?}", alert.severity)),
        detail_line(
            "State",
            if alert.resolved_at_ms.is_some() {
                "resolved"
            } else if alert.acknowledged {
                "acknowledged"
            } else {
                "active"
            }
            .into(),
        ),
        detail_line(
            "Owner",
            alert
                .process_name
                .as_ref()
                .map(|name| format!("{name} · PID {}", alert.process_id.unwrap_or(0)))
                .unwrap_or_else(|| "system / driver".into()),
        ),
        detail_line("First seen", format::timestamp(alert.first_seen_ms)),
        detail_line("Last seen", format::timestamp(alert.last_seen_ms)),
        detail_line("Occurrences", alert.occurrence_count.to_string()),
        Line::raw(""),
        Line::styled("▸ DIAGNOSIS", Style::default().fg(AMETHYST).bold()),
        Line::raw(alert.explanation.clone()),
        Line::raw(""),
        Line::styled("▸ SIGNAL EVIDENCE", Style::default().fg(ICE).bold()),
    ];
    for evidence in &alert.evidence {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {}  ", evidence.label.to_ascii_uppercase()),
                Style::default().fg(BG).bg(BORDER_HOT).bold(),
            ),
            Span::raw(" "),
            Span::styled(evidence.value.clone(), Style::default().fg(TEXT)),
        ]));
    }
    lines.extend([
        Line::raw(""),
        Line::styled("▸ SAFE NEXT MOVE", Style::default().fg(PHOSPHOR).bold()),
        Line::raw(alert.recommendation.clone()),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(accent_panel(" ◈ ATTRIBUTION / EVIDENCE ", AMETHYST)),
        area,
    );
}

fn render_analyzer(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let rows = Layout::vertical([Constraint::Length(6), Constraint::Min(12)]).split(area);
    render_chat_status(frame, app, inset(rows[0]));
    let columns = Layout::horizontal([
        Constraint::Percentage(68),
        Constraint::Length(1),
        Constraint::Percentage(32),
    ])
    .split(rows[1]);
    render_chat_transcript(frame, app, inset(columns[0]));
    let right = Layout::vertical([
        Constraint::Percentage(34),
        Constraint::Percentage(40),
        Constraint::Percentage(26),
    ])
    .split(columns[2]);
    render_chat_history(frame, app, inset(right[0]));
    render_chat_brief(frame, app, inset(right[1]));
    render_diagnostic_feed(frame, app, inset(right[2]));
}

fn render_chat_history(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let mut items = vec![ListItem::new(Line::styled(
        "＋ NEW CHAT",
        Style::default().fg(PHOSPHOR).bold(),
    ))];
    items.extend(app.chat_sessions.iter().map(|session| {
        let current = session.conversation_id == app.conversation_id;
        ListItem::new(Line::from(vec![
            Span::styled(
                if current { "◆ " } else { "◇ " },
                Style::default().fg(if current { AMETHYST } else { FAINT }),
            ),
            Span::styled(
                format::truncate(&session.title, area.width.saturating_sub(8) as usize),
                Style::default()
                    .fg(if current { TEXT } else { MUTED })
                    .bold(),
            ),
        ]))
    }));
    let accent = if app.chat_history_focused {
        AMBER
    } else {
        AMETHYST
    };
    frame.render_stateful_widget(
        List::new(items)
            .block(accent_panel(" ◇ CHAT VAULT · h focus · n new ", accent))
            .highlight_style(Style::default().fg(BG).bg(accent).bold())
            .highlight_symbol("▌ "),
        area,
        &mut app.chat_session_state,
    );
}

fn render_chat_status(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let status = &app.diagnostics.status;
    let ingest_color = if status.last_error.is_some() {
        CORAL
    } else if status.last_success_ms.is_some() {
        PHOSPHOR
    } else {
        AMBER
    };
    let auth = app.codex_auth_status.as_deref().unwrap_or_else(|| {
        if app.codex_auth_error.is_some() {
            "AUTH REQUIRED"
        } else {
            "CHECKING SESSION"
        }
    });
    let auth_color = if app.codex_auth_status.is_some() {
        PHOSPHOR
    } else if app.codex_auth_error.is_some() {
        CORAL
    } else {
        AMBER
    };
    let state = if app.analyzer_running {
        "RECONSTRUCTING / ESC CANCEL"
    } else {
        "READY / ENTER TO ASK"
    };
    let sections = Layout::horizontal([
        Constraint::Percentage(40),
        Constraint::Percentage(32),
        Constraint::Percentage(28),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("● EVENT INGEST  ", Style::default().fg(ingest_color).bold()),
                Span::styled(
                    status
                        .last_success_ms
                        .map(format::timestamp)
                        .unwrap_or_else(|| "awaiting poll".into()),
                    Style::default().fg(TEXT),
                ),
            ]),
            Line::styled(
                format!(
                    "{} STORED · {} VISIBLE · {} MALFORMED",
                    status.events_stored,
                    app.diagnostics.logs.len(),
                    status.malformed_events
                ),
                Style::default().fg(MUTED),
            ),
        ])
        .style(Style::default().bg(SURFACE))
        .block(accent_panel(" ⌁ EVIDENCE BUS ", ingest_color)),
        sections[0],
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(auth, Style::default().fg(auth_color).bold()),
            Line::styled(
                "saved Codex login · ChatGPT subscription",
                Style::default().fg(MUTED),
            ),
        ])
        .style(Style::default().bg(SURFACE))
        .block(accent_panel(" ◈ CODEX LINK ", auth_color)),
        sections[1],
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                state,
                Style::default()
                    .fg(if app.analyzer_running {
                        AMBER
                    } else {
                        AMETHYST
                    })
                    .bold(),
            ),
            Line::styled(
                format!(
                    "fresh {}h · {} turns · {} saved chats",
                    app.analyzer_window_hours,
                    app.chat_messages.len(),
                    app.chat_sessions.len()
                ),
                Style::default().fg(MUTED),
            ),
        ])
        .style(Style::default().bg(SURFACE))
        .block(accent_panel(" ◇ ANALYST CORE ", AMETHYST)),
        sections[2],
    );
}

fn render_chat_transcript(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let mut lines = Vec::new();
    if app.chat_messages.is_empty() {
        lines.extend([
            Line::styled("THE MACHINE HAS RECEIPTS.", Style::default().fg(AMETHYST).bold()),
            Line::raw(""),
            Line::styled("Ask what slowed the PC, which agent tree is leaking, why disk or kernel activity climbed, or what can be changed safely.", Style::default().fg(TEXT)),
            Line::raw(""),
            Line::styled("TRY A TRACE", Style::default().fg(PHOSPHOR).bold()),
            Line::styled("  › What was responsible for the last slowdown?", Style::default().fg(MUTED)),
            Line::styled("  › Are any agent process trees abandoned or growing?", Style::default().fg(MUTED)),
            Line::styled("  › Give me a low-risk optimization plan with evidence.", Style::default().fg(MUTED)),
            Line::raw(""),
            Line::styled("Every answer receives a fresh, redacted evidence bundle. No action is executed here.", Style::default().fg(FAINT)),
        ]);
    } else {
        for message in &app.chat_messages {
            let (badge, color) = match message.role {
                ChatRole::User => (" YOU ", ICE),
                ChatRole::Assistant => (" ANALYST ", AMETHYST),
            };
            lines.push(Line::from(vec![
                Span::styled(badge, Style::default().fg(BG).bg(color).bold()),
                Span::styled(
                    format!("  {}", format::timestamp(message.timestamp_ms)),
                    Style::default().fg(FAINT),
                ),
            ]));
            for text in message.text.lines() {
                lines.push(Line::styled(format!("  {text}"), Style::default().fg(TEXT)));
            }
            if !message.evidence_refs.is_empty() {
                lines.push(Line::styled(
                    format!("  ↳ {}", message.evidence_refs.join("  ·  ")),
                    Style::default().fg(PHOSPHOR),
                ));
            }
            lines.push(Line::raw(""));
        }
    }
    if app.analyzer_running {
        lines.push(Line::from(vec![
            Span::styled(" ANALYST ", Style::default().fg(BG).bg(AMBER).bold()),
            Span::styled(
                "  ░ correlating processes, incidents, baselines, and event logs…",
                Style::default().fg(AMBER),
            ),
        ]));
    }
    let block = accent_panel(" ◈ INTERROGATION CHANNEL ", AMETHYST);
    let inner_width = area.width.saturating_sub(2).max(1);
    let visible = area.height.saturating_sub(2) as usize;
    let rendered_lines: usize = lines
        .iter()
        .map(|line| line.width().max(1).div_ceil(inner_width as usize))
        .sum();
    let paragraph = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .style(Style::default().fg(TEXT).bg(SURFACE))
        .block(block);
    let bottom = rendered_lines.saturating_sub(visible);
    let scroll = bottom.saturating_sub(app.chat_scroll_from_bottom as usize);
    frame.render_widget(
        paragraph.scroll((scroll.min(u16::MAX as usize) as u16, 0)),
        area,
    );
}

fn render_chat_brief(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let mut lines = Vec::new();
    if let Some(response) = &app.latest_chat {
        lines.push(Line::styled(
            "PROPOSED MOVES",
            Style::default().fg(PHOSPHOR).bold(),
        ));
        if response.proposed_actions.is_empty() {
            lines.push(Line::styled(
                "  No action justified by current evidence.",
                Style::default().fg(MUTED),
            ));
        }
        for action in &response.proposed_actions {
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {:02} ", action.priority),
                    Style::default().fg(BG).bg(risk_color(action.risk)).bold(),
                ),
                Span::styled(
                    format!(" {}", action.title),
                    Style::default().fg(TEXT).bold(),
                ),
            ]));
            lines.push(Line::styled(
                if action.requires_confirmation {
                    "    confirmation required"
                } else {
                    "    observational / non-mutating"
                },
                Style::default().fg(if action.requires_confirmation {
                    AMBER
                } else {
                    MUTED
                }),
            ));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "NEXT QUESTIONS",
            Style::default().fg(ICE).bold(),
        ));
        for follow_up in &response.suggested_follow_ups {
            lines.push(Line::styled(
                format!("  › {follow_up}"),
                Style::default().fg(MUTED),
            ));
        }
    } else {
        lines.extend([
            Line::styled("GROUND RULES", Style::default().fg(PHOSPHOR).bold()),
            Line::styled(
                "  ✓ exact PC Pulse evidence refs",
                Style::default().fg(TEXT),
            ),
            Line::styled(
                "  ✓ sustained conditions over spikes",
                Style::default().fg(TEXT),
            ),
            Line::styled(
                "  ✓ confirmation + rollback for changes",
                Style::default().fg(TEXT),
            ),
            Line::styled("  ✓ bounded local conversation", Style::default().fg(TEXT)),
            Line::styled(
                "  × no automatic process termination",
                Style::default().fg(AMBER),
            ),
            Line::styled(
                "  × no API-key billing fallback",
                Style::default().fg(AMBER),
            ),
        ]);
        if let Some(error) = &app.codex_auth_error {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                format::truncate(error, 180),
                Style::default().fg(CORAL),
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(accent_panel(" ◇ ACTION ORBIT ", PHOSPHOR)),
        area,
    );
}

#[allow(dead_code)]
fn render_analyzer_legacy(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let rows = Layout::vertical([Constraint::Length(6), Constraint::Min(12)]).split(area);
    render_analyzer_status(frame, app, inset(rows[0]));
    let columns =
        Layout::horizontal([Constraint::Percentage(43), Constraint::Percentage(57)]).split(rows[1]);
    let Some(plan) = app.plans.first().cloned() else {
        render_diagnostic_feed(frame, app, inset(columns[0]));
        let lines = vec![
            Line::styled(
                "NO SYNTHESIS HAS BEEN COMMITTED",
                Style::default().fg(AMETHYST).bold(),
            ),
            Line::raw(""),
            Line::raw(
                "Press a to launch the dedicated PC Pulse systems analyzer. It receives a bounded, redacted evidence bundle and runs as the interactive user—not as LocalSystem.",
            ),
            Line::raw(""),
            Line::styled("SAFETY ENVELOPE", Style::default().fg(PHOSPHOR).bold()),
            Line::raw("  • Codex runs in a read-only sandbox"),
            Line::raw("  • no recommendation is executed"),
            Line::raw("  • direct termination commands are rejected"),
            Line::raw("  • mutations require confirmation + rollback"),
            Line::raw("  • every claim must cite collected evidence"),
            Line::raw(""),
            Line::styled(
                "CLI  PcPulse.exe analyze 1",
                Style::default().fg(ICE).bold(),
            ),
            Line::styled(
                "API  PcPulse.exe agent-context 1",
                Style::default().fg(MUTED),
            ),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .style(Style::default().fg(TEXT).bg(SURFACE))
                .block(accent_panel(" ◈ AGENT CONTRACT ", AMETHYST)),
            inset(columns[1]),
        );
        return;
    };
    render_plan_index(frame, app, &plan, inset(columns[0]));
    let selected = app
        .plan_action_state
        .selected()
        .and_then(|index| plan.actions.get(index));
    render_plan_action(frame, &plan, selected, inset(columns[1]));
}

fn render_analyzer_status(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let status = &app.diagnostics.status;
    let ingest_color = if status.last_error.is_some() {
        CORAL
    } else if status.last_success_ms.is_some() {
        PHOSPHOR
    } else {
        AMBER
    };
    let last_poll = status
        .last_success_ms
        .map(format::timestamp)
        .unwrap_or_else(|| "awaiting first poll".into());
    let latest_plan = app.plans.first();
    let plan_state = if app.analyzer_running {
        "ANALYZING / READ-ONLY".to_string()
    } else if let Some(plan) = latest_plan {
        format!(
            "PLAN {} · {} CONFIDENCE",
            format::truncate(&plan.plan_id, 8),
            plan.confidence.to_ascii_uppercase()
        )
    } else {
        "READY / NO PLAN".into()
    };
    let sections =
        Layout::horizontal([Constraint::Percentage(57), Constraint::Percentage(43)]).split(area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("● EVENT INGEST  ", Style::default().fg(ingest_color).bold()),
                Span::styled(last_poll, Style::default().fg(TEXT)),
            ]),
            Line::styled(
                format!(
                    "{} STORED  ·  {} DUP  ·  {} MALFORMED  ·  {} VISIBLE",
                    status.events_stored,
                    status.duplicate_events,
                    status.malformed_events,
                    app.diagnostics.logs.len()
                ),
                Style::default().fg(MUTED),
            ),
        ])
        .style(Style::default().bg(SURFACE))
        .block(accent_panel(" ⌁ WINDOWS DIAGNOSTIC SIGNAL ", ingest_color)),
        sections[0],
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                plan_state,
                Style::default()
                    .fg(if app.analyzer_running {
                        AMBER
                    } else {
                        AMETHYST
                    })
                    .bold(),
            ),
            Line::styled(
                format!(
                    "a synthesize  ·  [ ] evidence window: {}h  ·  r reload",
                    app.analyzer_window_hours
                ),
                Style::default().fg(MUTED),
            ),
        ])
        .style(Style::default().bg(SURFACE))
        .block(accent_panel(" ◇ SYSTEMS ANALYZER ", AMETHYST)),
        sections[1],
    );
}

fn render_diagnostic_feed(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let lines = app
        .diagnostics
        .logs
        .iter()
        .take(area.height.saturating_sub(2) as usize / 2)
        .flat_map(|log| {
            vec![
                Line::from(vec![
                    Span::styled(
                        format!(" {:?} ", log.level).to_ascii_uppercase(),
                        Style::default().fg(BG).bg(match log.level {
                            pcpulse_service::models::DiagnosticLevel::Critical => CORAL,
                            pcpulse_service::models::DiagnosticLevel::Error => AMBER,
                            pcpulse_service::models::DiagnosticLevel::Warning => ICE,
                        }),
                    ),
                    Span::styled(
                        format!(" {:?} ", log.category).to_ascii_uppercase(),
                        Style::default().fg(AMETHYST).bold(),
                    ),
                    Span::styled(
                        format::timestamp(log.timestamp_ms),
                        Style::default().fg(FAINT),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(
                        format!("  {} / {}", log.provider, log.event_id),
                        Style::default().fg(TEXT),
                    ),
                    Span::styled(
                        log.related_process
                            .as_ref()
                            .map(|name| format!("  ⟶ {name}"))
                            .unwrap_or_default(),
                        Style::default().fg(PHOSPHOR),
                    ),
                ]),
            ]
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(if lines.is_empty() {
            vec![Line::styled(
                "No warning/error/critical Application or System events in the visible window.",
                Style::default().fg(MUTED),
            )]
        } else {
            lines
        })
        .wrap(Wrap { trim: true })
        .style(Style::default().fg(TEXT).bg(SURFACE))
        .block(accent_panel(" ⌁ RAW SIGNAL FEED ", ICE)),
        area,
    );
}

fn render_plan_index(frame: &mut Frame<'_>, app: &mut App, plan: &OptimizationPlan, area: Rect) {
    let sections =
        Layout::vertical([Constraint::Percentage(44), Constraint::Percentage(56)]).split(area);
    let mut diagnosis_lines = vec![
        Line::styled(plan.summary.clone(), Style::default().fg(TEXT).bold()),
        Line::raw(""),
    ];
    for diagnosis in &plan.diagnoses {
        diagnosis_lines.push(Line::from(vec![
            Span::styled(
                format!(" {} ", severity_label(diagnosis.severity)),
                severity_badge(diagnosis.severity),
            ),
            Span::raw(" "),
            Span::styled(diagnosis.title.clone(), Style::default().fg(TEXT)),
        ]));
    }
    if plan.diagnoses.is_empty() {
        diagnosis_lines.push(Line::styled(
            "No defensible sustained diagnosis.",
            Style::default().fg(MUTED),
        ));
    }
    frame.render_widget(
        Paragraph::new(diagnosis_lines)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(accent_panel(" ◈ SYNTHESIS ", AMETHYST)),
        sections[0],
    );
    let actions = plan
        .actions
        .iter()
        .map(|action| {
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(
                        format!(" {:02} ", action.priority),
                        Style::default().fg(BG).bg(risk_color(action.risk)).bold(),
                    ),
                    Span::raw(" "),
                    Span::styled(action.title.clone(), Style::default().fg(TEXT).bold()),
                ]),
                Line::from(vec![
                    Span::styled(
                        format!("  {:?}", action.category).to_ascii_uppercase(),
                        Style::default().fg(AMETHYST),
                    ),
                    Span::styled(
                        format!(" · {:?} RISK", action.risk).to_ascii_uppercase(),
                        Style::default().fg(risk_color(action.risk)),
                    ),
                    Span::styled(
                        if action.requires_confirmation {
                            " · CONFIRM"
                        } else {
                            " · READ-ONLY"
                        },
                        Style::default().fg(MUTED),
                    ),
                ]),
            ])
        })
        .collect::<Vec<_>>();
    frame.render_stateful_widget(
        List::new(actions)
            .highlight_style(Style::default().fg(TEXT).bg(SELECT_BG).bold())
            .highlight_symbol("▌ ")
            .block(accent_panel(" ⟐ ORDERED ACTION QUEUE ", PHOSPHOR)),
        sections[1],
        &mut app.plan_action_state,
    );
}

fn render_plan_action(
    frame: &mut Frame<'_>,
    plan: &OptimizationPlan,
    action: Option<&PlanAction>,
    area: Rect,
) {
    let Some(action) = action else {
        frame.render_widget(
            Paragraph::new("The analyzer found no evidence-backed action to recommend.")
                .style(Style::default().fg(MUTED).bg(SURFACE))
                .block(accent_panel(" ⟐ INTEGRATION DETAIL ", PHOSPHOR)),
            area,
        );
        return;
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" PRIORITY {} ", action.priority),
                Style::default().fg(BG).bg(risk_color(action.risk)).bold(),
            ),
            Span::styled(
                format!("  {:?} RISK", action.risk).to_ascii_uppercase(),
                Style::default().fg(risk_color(action.risk)).bold(),
            ),
        ]),
        Line::styled(action.title.clone(), Style::default().fg(TEXT).bold()),
        detail_line("Target", action.target.clone()),
        Line::raw(""),
        Line::styled("WHY", Style::default().fg(AMETHYST).bold()),
        Line::raw(action.reason.clone()),
        Line::raw(""),
        Line::styled("STEPS", Style::default().fg(ICE).bold()),
    ];
    for (index, step) in action.steps.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {}. {:?} ", index + 1, step.kind).to_ascii_uppercase(),
                Style::default()
                    .fg(BG)
                    .bg(if step.mutates_system { AMBER } else { ICE })
                    .bold(),
            ),
            Span::raw(" "),
            Span::styled(step.description.clone(), Style::default().fg(TEXT)),
        ]));
        if let Some(command) = &step.command {
            lines.push(Line::styled(
                format!("    PS> {command}"),
                Style::default().fg(PHOSPHOR),
            ));
        }
        if let Some(prompt) = &step.confirmation_prompt {
            lines.push(Line::styled(
                format!("    CONFIRM: {prompt}"),
                Style::default().fg(AMBER),
            ));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "VALIDATE",
        Style::default().fg(PHOSPHOR).bold(),
    ));
    for item in &action.validation {
        lines.push(Line::raw(format!("  ✓ {item}")));
    }
    if !action.rollback.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("ROLLBACK", Style::default().fg(AMBER).bold()));
        for item in &action.rollback {
            lines.push(Line::raw(format!("  ↶ {item}")));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!("EVIDENCE  {}", action.evidence_refs.join(" · ")),
        Style::default().fg(FAINT),
    ));
    lines.push(Line::styled(
        format!("PLAN  {} / {}", plan.plan_id, plan.context_id),
        Style::default().fg(FAINT),
    ));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(accent_panel(
                " ⟐ INTEGRATION DETAIL · DISPLAY ONLY ",
                PHOSPHOR,
            )),
        area,
    );
}

fn risk_color(risk: PlanRisk) -> Color {
    match risk {
        PlanRisk::Low => PHOSPHOR,
        PlanRisk::Medium => AMBER,
        PlanRisk::High => CORAL,
    }
}

fn render_timeline(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let rows =
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).split(area);
    let points = &app.persisted_history.system;
    if points.len() < 2 {
        frame.render_widget(
            Paragraph::new(
                "Loading persisted history…\n\nr refresh   [ shorter window   ] longer window",
            )
            .style(Style::default().fg(MUTED).bg(SURFACE))
            .alignment(Alignment::Center)
            .block(accent_panel(" ∿ SIGNAL HISTORY ", PHOSPHOR)),
            area,
        );
        return;
    }
    let minimum = points.first().map_or(0.0, |item| item.timestamp_ms as f64);
    let maximum = points
        .last()
        .map_or(minimum + 1.0, |item| item.timestamp_ms as f64);
    let cpu = points
        .iter()
        .map(|item| (item.timestamp_ms as f64, item.cpu_percent))
        .collect::<Vec<_>>();
    let memory = points
        .iter()
        .map(|item| {
            (
                item.timestamp_ms as f64,
                percent(item.memory_used_bytes, item.memory_total_bytes),
            )
        })
        .collect::<Vec<_>>();
    let latency = points
        .iter()
        .map(|item| (item.timestamp_ms as f64, item.disk_latency_ms))
        .collect::<Vec<_>>();
    let cpu_data = vec![
        Dataset::default()
            .name("CPU")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(PHOSPHOR))
            .data(&cpu),
        Dataset::default()
            .name("Memory")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(AMETHYST))
            .data(&memory),
    ];
    frame.render_widget(
        Chart::new(cpu_data)
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(accent_panel(
                &format!(" ∿ RESOURCE FIELD · last {}h ", app.timeline_hours),
                PHOSPHOR,
            ))
            .x_axis(
                Axis::default()
                    .style(Style::default().fg(FAINT))
                    .bounds([minimum, maximum]),
            )
            .y_axis(
                Axis::default()
                    .style(Style::default().fg(MUTED))
                    .bounds([0.0, 100.0])
                    .labels([
                        Line::styled("0%", Style::default().fg(FAINT)),
                        Line::styled("50%", Style::default().fg(MUTED)),
                        Line::styled("100%", Style::default().fg(AMBER).bold()),
                    ]),
            ),
        inset(rows[0]),
    );
    let latency_max = latency
        .iter()
        .map(|(_, value)| *value)
        .fold(app.settings.disk_latency_ms, f64::max)
        .max(1.0);
    frame.render_widget(
        Chart::new(vec![
            Dataset::default()
                .name("latency ms")
                .marker(symbols::Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(AMBER))
                .data(&latency),
        ])
        .style(Style::default().fg(TEXT).bg(SURFACE))
        .block(accent_panel(" ≋ DISK LATENCY FIELD ", AMBER))
        .x_axis(
            Axis::default()
                .style(Style::default().fg(FAINT))
                .bounds([minimum, maximum]),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(MUTED))
                .bounds([0.0, latency_max])
                .labels(vec![
                    Line::styled("0", Style::default().fg(FAINT)),
                    Line::styled(
                        format!("{latency_max:.0} ms"),
                        Style::default().fg(AMBER).bold(),
                    ),
                ]),
        ),
        inset(rows[1]),
    );
}

fn render_settings(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let rows = app
        .visible_setting_fields()
        .into_iter()
        .enumerate()
        .map(|(index, field)| {
            Row::new([
                Cell::from(Line::from(vec![
                    Span::styled("◇ ", Style::default().fg(AMETHYST)),
                    Span::styled(field.label(), Style::default().fg(TEXT)),
                ])),
                Cell::from(field.value(&app.settings)).style(Style::default().fg(PHOSPHOR)),
                Cell::from(field.unit()).style(Style::default().fg(MUTED)),
            ])
            .style(Style::default().bg(if index.is_multiple_of(2) {
                SURFACE
            } else {
                SURFACE_RAISED
            }))
        })
        .collect::<Vec<_>>();
    let title = if app.settings_dirty {
        " ⚙ DETECTOR MATRIX · UNSAVED CHANGES · Enter edit · s save · r discard/reload "
    } else {
        " ⚙ DETECTOR MATRIX · Enter edit · s save · r reload "
    };
    let table = Table::new(rows, setting_constraints())
        .header(
            Row::new([
                sortable_header_cell("SETTING", app.setting_sort == SettingSort::Name, AMETHYST),
                sortable_header_cell("VALUE", app.setting_sort == SettingSort::Value, AMETHYST),
                sortable_header_cell("UNIT", app.setting_sort == SettingSort::Unit, AMETHYST),
            ])
            .style(
                Style::default()
                    .fg(if app.settings_dirty { AMBER } else { AMETHYST })
                    .bg(SURFACE_RAISED)
                    .bold(),
            )
            .bottom_margin(1),
        )
        .block(accent_panel(
            title,
            if app.settings_dirty { AMBER } else { AMETHYST },
        ))
        .row_highlight_style(Style::default().fg(TEXT).bg(SELECT_BG).bold())
        .highlight_symbol("▌ ");
    frame.render_stateful_widget(table, inset(area), &mut app.setting_state);
}

fn render_help(frame: &mut Frame<'_>, area: Rect) {
    let columns = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area.inner(Margin::new(2, 1)));
    let global = vec![
        help_line("1–8", "jump to a page"),
        help_line("Tab / Shift-Tab", "next / previous page"),
        help_line("j / k, ↑ / ↓", "move selection"),
        help_line("PgUp / PgDn", "move ten rows"),
        help_line("r", "refresh current page"),
        help_line("mouse click", "select rows, tabs, prompts, and settings"),
        help_line("mouse wheel", "scroll the active view"),
        help_line("m", "toggle finite motion effects"),
        help_line("q / Ctrl-C", "quit"),
        help_line("?", "this page"),
        Line::raw(""),
        Line::styled(
            "The collector continues when the TUI exits.",
            Style::default().fg(MUTED),
        ),
    ];
    let contextual = vec![
        help_line("/", "filter process name, path, or PID"),
        help_line("o", "cycle process sort"),
        help_line("g", "toggle agent-only process focus"),
        help_line("x", "request termination; exact PID required"),
        help_line("a", "acknowledge selected finding"),
        help_line("[ / ]", "shorter / longer timeline"),
        help_line("Enter on Oracle", "ask the embedded systems analyzer"),
        help_line("h / n on Oracle", "focus chat history / begin a new chat"),
        help_line("[ / ] on Oracle", "change fresh evidence window"),
        help_line("table header click", "sort by the clicked column"),
        help_line("process right-click", "open typed-PID confirmation"),
        help_line("Enter / e", "edit selected setting"),
        help_line("s", "save settings"),
        help_line("Esc", "cancel input or confirmation"),
        Line::raw(""),
        Line::styled(
            "PC Pulse never terminates a process automatically.",
            Style::default().fg(AMBER).bold(),
        ),
    ];
    frame.render_widget(
        Paragraph::new(global)
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(accent_panel(" ◈ NAVIGATION RUNES ", PHOSPHOR))
            .wrap(Wrap { trim: false }),
        columns[0],
    );
    frame.render_widget(
        Paragraph::new(contextual)
            .style(Style::default().fg(TEXT).bg(SURFACE))
            .block(accent_panel(" ◇ CONTEXT RITES ", AMETHYST))
            .wrap(Wrap { trim: false }),
        columns[1],
    );
}

fn render_footer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let interaction = match &app.mode {
        InputMode::Normal => normal_footer(app.page),
        InputMode::Search(value) => Line::from(vec![
            Span::styled(
                " / FILTER SIGNAL  ",
                Style::default().fg(BG).bg(PHOSPHOR).bold(),
            ),
            Span::raw("  "),
            Span::styled(value, Style::default().fg(TEXT).bold()),
            Span::styled("█", Style::default().fg(PHOSPHOR)),
        ]),
        InputMode::Chat(value) => Line::from(vec![
            Span::styled(
                " ASK THE MACHINE  ",
                Style::default().fg(BG).bg(AMETHYST).bold(),
            ),
            Span::raw("  "),
            Span::styled(value, Style::default().fg(TEXT).bold()),
            Span::styled("█", Style::default().fg(AMETHYST)),
            Span::styled("  Enter send · Esc cancel", Style::default().fg(MUTED)),
        ]),
        InputMode::ConfirmTerminate { pid, typed, .. } => Line::from(vec![
            Span::styled(
                format!("TYPE PID {pid} TO CONFIRM  "),
                Style::default().fg(CORAL).bold(),
            ),
            Span::raw(typed),
            Span::styled("█", Style::default().fg(CORAL)),
        ]),
        InputMode::EditSetting { field, typed } => Line::from(vec![
            Span::styled(
                format!("{}  ", field.label().to_ascii_uppercase()),
                Style::default().fg(AMETHYST).bold(),
            ),
            Span::raw(typed),
            Span::styled("█", Style::default().fg(AMETHYST)),
            Span::styled("  Enter apply · Esc cancel", Style::default().fg(MUTED)),
        ]),
    };
    let status = if !app.connected {
        Line::from(vec![
            Span::styled(" OFFLINE ", Style::default().fg(BG).bg(CORAL).bold()),
            Span::styled(
                format!(
                    "  {}",
                    app.last_error.as_deref().unwrap_or("Collector unavailable")
                ),
                Style::default().fg(CORAL),
            ),
        ])
    } else if !app.status.is_empty() {
        Line::from(vec![
            Span::styled(
                if app.status_is_error {
                    " ERROR "
                } else {
                    " STATUS "
                },
                Style::default()
                    .fg(BG)
                    .bg(if app.status_is_error { CORAL } else { ICE })
                    .bold(),
            ),
            Span::styled(
                format!("  {}", app.status),
                Style::default().fg(if app.status_is_error { CORAL } else { MUTED }),
            ),
        ])
    } else {
        Line::styled(
            " mouse  click select / focus  ·  wheel scroll  ·  table headers sort  ·  right-click process confirms",
            Style::default().fg(FAINT),
        )
    };
    frame.render_widget(
        Paragraph::new(vec![interaction, status]).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(BORDER_HOT))
                .style(Style::default().fg(TEXT).bg(SURFACE_RAISED)),
        ),
        area,
    );
}

fn normal_footer(page: Page) -> Line<'static> {
    let contextual = match page {
        Page::Overview => "2 hunt  ·  4 incidents  ·  r sample",
        Page::Processes => "/ query  ·  o rank  ·  g agents  ·  x terminate",
        Page::Tree => "j/k trace  ·  r rebuild  ·  x terminate",
        Page::Alerts => "j/k inspect  ·  a acknowledge  ·  r refresh",
        Page::Timeline => "[ ] window  ·  r reload",
        Page::Analyzer => "Enter ask  ·  n new  ·  h history  ·  [ ] evidence  ·  j/k scroll",
        Page::Settings => "Enter edit  ·  s commit  ·  r revert",
        Page::Help => "1–8 route  ·  Tab cycle",
    };
    Line::from(vec![
        Span::styled(" NORMAL ", Style::default().fg(BG).bg(PHOSPHOR).bold()),
        Span::styled(
            format!(
                "  {:02}/08 {}  ::  {contextual}   ",
                page_index(page) + 1,
                route_name(page)
            ),
            Style::default().fg(TEXT),
        ),
        key_badge("Tab"),
        Span::styled(" route  ", Style::default().fg(MUTED)),
        key_badge("m"),
        Span::styled(" motion  ", Style::default().fg(MUTED)),
        key_badge("?"),
        Span::styled(" manual  ", Style::default().fg(MUTED)),
        key_badge("q"),
        Span::styled(" exit", Style::default().fg(MUTED)),
    ])
}

fn render_modal(frame: &mut Frame<'_>, app: &App) {
    let InputMode::ConfirmTerminate {
        pid,
        process_name,
        typed,
    } = &app.mode
    else {
        return;
    };
    let area = modal_region(frame.area());
    frame.render_widget(Clear, area);
    let text = vec![
        Line::styled(
            format!("End {process_name}?"),
            Style::default().fg(CORAL).bold(),
        ),
        Line::raw(""),
        Line::raw("Unsaved work may be lost. No action occurs unless the exact PID is entered."),
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                format!(" TYPE {pid} "),
                Style::default().fg(BG).bg(AMBER).bold(),
            ),
            Span::raw("  "),
            Span::styled(typed.clone(), Style::default().fg(TEXT).bold()),
            Span::styled("█", Style::default().fg(CORAL)),
        ]),
        Line::raw(""),
        Line::styled("Enter confirm · Esc cancel", Style::default().fg(MUTED)),
    ];
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(CORAL))
                .style(Style::default().fg(TEXT).bg(SURFACE_RAISED))
                .title(" ! DESTRUCTIVE GATE ")
                .title_style(Style::default().fg(CORAL).bold())
                .padding(Padding::uniform(1)),
        ),
        area,
    );
}

fn render_offline(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let error = app
        .last_error
        .as_deref()
        .unwrap_or("Waiting for the first collector snapshot");
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("×  COLLECTOR DARK", Style::default().fg(CORAL).bold()),
            Line::raw(""),
            Line::raw(error),
            Line::raw(""),
            Line::styled(
                "The TUI retries every two seconds. Verify the PcPulseCollector service.",
                Style::default().fg(MUTED),
            ),
        ])
        .style(Style::default().fg(TEXT).bg(SURFACE))
        .alignment(Alignment::Center)
        .block(accent_panel(" × SIGNAL LOST ", CORAL).border_type(BorderType::Double)),
        area.inner(Margin::new(4, 2)),
    );
}

fn panel<'a>(title: &'a str) -> Block<'a> {
    accent_panel(title, MUTED)
}

fn accent_panel<'a>(title: &'a str, accent: Color) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().fg(TEXT).bg(SURFACE))
        .title(title)
        .title_style(Style::default().fg(accent).bold())
}

fn inset(area: Rect) -> Rect {
    area.inner(Margin::new(1, 0))
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(area.height.saturating_sub(height) / 2),
            Constraint::Length(height.min(area.height)),
            Constraint::Min(0),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(area.width.saturating_sub(width) / 2),
            Constraint::Length(width.min(area.width)),
            Constraint::Min(0),
        ])
        .split(vertical[1])[1]
}

fn detail_line(label: &'static str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(MUTED)),
        Span::styled(value, Style::default().fg(TEXT)),
    ])
}

fn help_line(key: &'static str, description: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {key:<16} "),
            Style::default().fg(BG).bg(SELECT_BG).bold(),
        ),
        Span::raw("  "),
        Span::styled(description, Style::default().fg(TEXT)),
    ])
}

fn key_badge(key: &'static str) -> Span<'static> {
    Span::styled(
        format!(" {key} "),
        Style::default().fg(BG).bg(PHOSPHOR).bold(),
    )
}

fn yes_no(value: bool) -> String {
    if value { "yes" } else { "no" }.into()
}

fn percent(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        used as f64 * 100.0 / total as f64
    }
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Info => ICE,
        Severity::Warning => AMBER,
        Severity::Critical => CORAL,
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "INFO",
        Severity::Warning => "WARN",
        Severity::Critical => "CRIT",
    }
}

fn severity_badge(severity: Severity) -> Style {
    Style::default().fg(BG).bg(severity_color(severity)).bold()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcpulse_service::models::{ProcessMetric, Snapshot, SystemMetric};
    use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};

    #[test]
    fn night_signal_palette_has_distinct_semantic_channels() {
        let channels = [PHOSPHOR, AMETHYST, ICE, AMBER, CORAL];
        for (index, color) in channels.iter().enumerate() {
            assert!(!channels[..index].contains(color));
        }
        assert_ne!(BG, SURFACE);
        assert_ne!(SURFACE, SURFACE_RAISED);
        assert_ne!(TEXT, MUTED);
        assert_ne!(BORDER, BORDER_HOT);
    }

    #[test]
    fn overview_renders_authored_shell_and_palette() {
        let mut app = sample_app();
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("PCPULSE::NIGHTWATCH"));
        assert!(text.contains("PRESSURE FIELD"));
        assert!(text.contains("SUSPECT MATRIX"));
        assert!(text.contains("AGENT SWARM"));
        assert!(text.contains("INCIDENT TAPE"));
        assert!(text.contains("QUIET"));
        assert!(!text.contains("CPU SIGNAL"));
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .filter(|cell| cell.bg == SURFACE)
                .count()
                > 100
        );
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .any(|cell| cell.fg == PHOSPHOR)
        );
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .any(|cell| cell.fg == AMETHYST)
        );
    }

    #[test]
    fn suspect_heat_prioritizes_the_active_agent() {
        let app = sample_app();
        let active = &app.snapshot.as_ref().expect("snapshot").processes[0];
        let mut idle = active.clone();
        idle.pid = 9000;
        idle.name = "idle-helper.exe".into();
        idle.cpu_percent = 0.0;
        idle.working_set_bytes = 1024 * 1024;
        idle.handle_count = 8;
        idle.thread_count = 1;
        idle.read_bytes_per_sec = 0.0;
        idle.write_bytes_per_sec = 0.0;
        idle.is_agent_candidate = false;
        idle.responsive = true;
        assert!(triage_heat(active, &app) > triage_heat(&idle, &app));
    }

    #[test]
    fn compact_terminal_keeps_every_investigation_region_visible() {
        let mut app = sample_app();
        let backend = render_size(&mut app, 110, 37);
        let text = buffer_text(backend.buffer());
        for label in [
            "PRESSURE FIELD",
            "SUSPECT MATRIX",
            "SYSTEM VECTOR",
            "AGENT SWARM",
            "INCIDENT TAPE",
        ] {
            assert!(text.contains(label), "missing {label}");
        }
        assert!(text.contains("01 OBS"));
        assert!(text.contains("06 ASK"));
        assert!(text.contains("08 HELP"));
    }

    #[test]
    fn analyzer_route_exposes_embedded_chat_and_safety_contract() {
        let mut app = sample_app();
        app.page = Page::Analyzer;
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("EVIDENCE BUS"));
        assert!(text.contains("CODEX LINK"));
        assert!(text.contains("INTERROGATION CHANNEL"));
        assert!(text.contains("CHAT VAULT"));
        assert!(text.contains("ChatGPT subscription"));
        assert!(text.contains("no automatic process termination"));
    }

    #[test]
    fn status_messages_never_replace_page_shortcuts() {
        let mut app = sample_app();
        app.page = Page::Analyzer;
        app.status = "Systems analyzer answered from current PC Pulse evidence".into();
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("Enter ask"));
        assert!(text.contains("Systems analyzer answered from current PC Pulse evidence"));
    }

    #[test]
    fn every_process_header_click_selects_its_exact_sort_key() {
        let mut app = sample_app();
        app.page = Page::Processes;
        let area = Rect::new(0, 0, 160, 48);
        let body = regions(area).body;
        let sections = Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)])
            .split(body);
        let table = inset(sections[0]);
        for expected in [
            ProcessSort::Pid,
            ProcessSort::Name,
            ProcessSort::Cpu,
            ProcessSort::Memory,
            ProcessSort::Io,
            ProcessSort::Handles,
            ProcessSort::Threads,
            ProcessSort::Age,
        ] {
            let column = (table.x..table.right())
                .find(|column| process_sort_at(table, *column) == Some(expected))
                .expect("sort column should have a clickable cell");
            let event = MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column,
                row: table.y + 1,
                modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
            };
            assert!(handle_mouse(&mut app, event, area));
            assert_eq!(app.process_sort, expected);
        }
    }

    #[test]
    fn mouse_tabs_and_oracle_canvas_are_clickable() {
        let mut app = sample_app();
        let area = Rect::new(0, 0, 160, 48);
        let tabs = regions(area).tabs;
        let oracle_column = (tabs.x..tabs.right())
            .find(|column| route_at(*column, tabs) == Some(Page::Analyzer))
            .expect("Oracle tab should have a clickable cell");
        assert!(handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: oracle_column,
                row: tabs.y,
                modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
            },
            area,
        ));
        assert_eq!(app.page, Page::Analyzer);

        let body = regions(area).body;
        let rows = Layout::vertical([Constraint::Length(6), Constraint::Min(12)]).split(body);
        let transcript = Layout::horizontal([
            Constraint::Percentage(68),
            Constraint::Length(1),
            Constraint::Percentage(32),
        ])
        .split(rows[1])[0];
        assert!(handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: transcript.x + 2,
                row: transcript.y + 2,
                modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
            },
            area,
        ));
        assert!(matches!(app.mode, InputMode::Chat(ref text) if text.is_empty()));

        let hunt_column = (tabs.x..tabs.right())
            .find(|column| route_at(*column, tabs) == Some(Page::Processes))
            .expect("Hunt tab should have a clickable cell");
        assert!(handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: hunt_column,
                row: tabs.y,
                modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
            },
            area,
        ));
        assert_eq!(app.page, Page::Processes);
        assert!(matches!(app.mode, InputMode::Normal));
    }

    #[test]
    fn every_other_table_exposes_clickable_sort_headers() {
        let table = Rect::new(2, 8, 120, 25);
        for expected in [
            TreeSort::Pid,
            TreeSort::Name,
            TreeSort::Cpu,
            TreeSort::Memory,
            TreeSort::Io,
        ] {
            assert!((table.x..table.right()).any(|x| tree_sort_at(table, x) == Some(expected)));
        }
        for expected in [
            AlertSort::Severity,
            AlertSort::Title,
            AlertSort::Owner,
            AlertSort::State,
            AlertSort::FirstSeen,
        ] {
            assert!((table.x..table.right()).any(|x| alert_sort_at(table, x) == Some(expected)));
        }
        for expected in [SettingSort::Name, SettingSort::Value, SettingSort::Unit] {
            assert!((table.x..table.right()).any(|x| setting_sort_at(table, x) == Some(expected)));
        }
        for expected in [
            SuspectSort::Heat,
            SuspectSort::Name,
            SuspectSort::Cpu,
            SuspectSort::Memory,
            SuspectSort::Io,
            SuspectSort::HandlesThreads,
        ] {
            assert!((table.x..table.right()).any(|x| suspect_sort_at(table, x) == Some(expected)));
        }
    }

    #[test]
    fn clicking_non_chat_content_dismisses_chat_input() {
        let mut app = sample_app();
        app.page = Page::Analyzer;
        app.mode = InputMode::Chat("unfinished question".into());
        let area = Rect::new(0, 0, 160, 48);
        let body = regions(area).body;
        assert!(handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: body.right() - 3,
                row: body.y + 9,
                modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
            },
            area,
        ));
        assert!(matches!(app.mode, InputMode::Normal));
    }

    #[test]
    fn agent_focus_and_destructive_gate_have_unique_visual_states() {
        let mut app = sample_app();
        app.page = Page::Processes;
        app.agents_only = true;
        app.process_state.select(None);
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("PROCESS SPECTRUM"));
        assert!(text.contains("AGENT FOCUS"));
        assert!(text.contains("AGT"));
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .filter(|cell| cell.bg == AMETHYST)
                .count()
                >= 3
        );

        app.mode = InputMode::ConfirmTerminate {
            pid: 4242,
            process_name: "codex.exe".into(),
            typed: "42".into(),
        };
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("DESTRUCTIVE GATE"));
        assert!(text.contains("TYPE 4242"));
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .any(|cell| cell.fg == CORAL)
        );
    }

    fn sample_app() -> App {
        let mut app = App::new_inert();
        let system = SystemMetric {
            timestamp_ms: 1_800_000_000_000,
            cpu_percent: 17.4,
            memory_used_bytes: 32 * 1024 * 1024 * 1024,
            memory_total_bytes: 64 * 1024 * 1024 * 1024,
            disk_latency_ms: 1.8,
            disk_read_bytes_per_sec: 12.0 * 1024.0 * 1024.0,
            disk_write_bytes_per_sec: 3.0 * 1024.0 * 1024.0,
            paged_pool_bytes: 2 * 1024 * 1024 * 1024,
            nonpaged_pool_bytes: 4 * 1024 * 1024 * 1024,
            dpc_rate: 44.0,
            interrupt_rate: 18_000.0,
            process_count: 420,
            thread_count: 12_000,
            collector_working_set_bytes: 16 * 1024 * 1024,
            collector_cpu_percent: 0.04,
            collector_handle_count: 210,
            etw_active: true,
            ..SystemMetric::default()
        };
        let process = ProcessMetric {
            timestamp_ms: system.timestamp_ms,
            pid: 4242,
            parent_pid: 4000,
            name: "codex.exe".into(),
            executable_path: r"C:\tools\codex.exe".into(),
            cpu_percent: 42.0,
            working_set_bytes: 768 * 1024 * 1024,
            private_bytes: 700 * 1024 * 1024,
            handle_count: 1_200,
            thread_count: 88,
            read_bytes_per_sec: 8.0 * 1024.0 * 1024.0,
            write_bytes_per_sec: 2.0 * 1024.0 * 1024.0,
            total_read_bytes: 0,
            total_write_bytes: 0,
            started_at_ms: system.timestamp_ms - 600_000,
            session_id: 1,
            responsive: true,
            has_visible_window: false,
            launch_duration_ms: None,
            is_agent_candidate: true,
        };
        app.connected = true;
        app.live_history.push_back(system.clone());
        app.snapshot = Some(Snapshot {
            protocol_version: 1,
            service_version: "1.4.3".into(),
            system,
            processes: vec![process],
            active_alerts: Vec::new(),
        });
        app
    }

    fn render(app: &mut App) -> TestBackend {
        render_size(app, 150, 46)
    }

    fn render_size(app: &mut App, width: u16, height: u16) -> TestBackend {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal.draw(|frame| draw(frame, app)).expect("draw");
        terminal.backend().clone()
    }

    fn buffer_text(buffer: &Buffer) -> String {
        buffer.content().iter().map(|cell| cell.symbol()).collect()
    }
}
