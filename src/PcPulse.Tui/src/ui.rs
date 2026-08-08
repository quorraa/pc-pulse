use crate::{
    analyzer::ChatRole,
    app::{AlertSort, App, InputMode, Page, ProcessSort, SettingSort, SuspectSort, TreeSort},
    format,
    theme::{self, LayoutKind, palette},
};
use pcpulse_service::models::{
    Alert, OptimizationPlan, PlanAction, PlanRisk, ProcessMetric, Severity, SystemMetric,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiRegions {
    pub full: Rect,
    pub header: Rect,
    pub tabs: Rect,
    pub body: Rect,
    pub footer: Rect,
}

/// Below this footprint the rail structure loses more than it shows — the
/// gallery proved a narrower rail truncates every status line — so the rail
/// profile then borrows the statusline shape wholesale (palette still
/// applies).
const RAIL_MIN_WIDTH: u16 = 96;
const RAIL_MIN_HEIGHT: u16 = 26;
const RAIL_WIDTH: u16 = 16;
const RAIL_BRAND_HEIGHT: u16 = 3;
const RAIL_STATUS_HEIGHT: u16 = 8;
const ANNUNCIATOR_HEIGHT: u16 = 3;

/// The rail column width when the avionics rail structure applies to this
/// terminal size, or `None` when the statusline shape is used instead.
fn rail_width(area: Rect) -> Option<u16> {
    (theme::active().layout == LayoutKind::Rail
        && area.width >= RAIL_MIN_WIDTH
        && area.height >= RAIL_MIN_HEIGHT)
        .then_some(RAIL_WIDTH)
}

pub fn regions(area: Rect) -> UiRegions {
    match rail_width(area) {
        Some(width) => rail_regions(area, width),
        None => statusline_regions(area),
    }
}

/// Avionics MFD shape: left rail full height, annunciator strip across the
/// top of the remaining width, main canvas below. Region mapping for the
/// effects layer: `header` = annunciator strip, `tabs` = the rail's bezel
/// page keys, `footer` = the rail's bottom status block, `body` = canvas.
fn rail_regions(area: Rect, rail_width: u16) -> UiRegions {
    let columns =
        Layout::horizontal([Constraint::Length(rail_width), Constraint::Min(10)]).split(area);
    let rail = Layout::vertical([
        Constraint::Length(RAIL_BRAND_HEIGHT),
        Constraint::Min(8),
        Constraint::Length(RAIL_STATUS_HEIGHT),
    ])
    .split(columns[0]);
    let canvas = Layout::vertical([Constraint::Length(ANNUNCIATOR_HEIGHT), Constraint::Min(10)])
        .split(columns[1]);
    UiRegions {
        full: area,
        header: canvas[0],
        tabs: rail[1],
        body: canvas[1],
        footer: rail[2],
    }
}

fn statusline_regions(area: Rect) -> UiRegions {
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
            let rail = rail_width(area).is_some();
            let regions = regions(area);
            if button == MouseButton::Left && point_in(regions.tabs, point) {
                let page = if rail {
                    rail_key_at(event.row, regions.tabs)
                } else {
                    route_at(event.column, regions.tabs)
                };
                if let Some(page) = page {
                    app.select_page(page);
                    return true;
                }
            }
            if !point_in(regions.body, point) {
                return false;
            }
            mouse_body_click(app, point, button, regions.body, rail)
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

/// One bezel key per row, in [`Page::ALL`] order.
fn rail_key_at(row: u16, tabs: Rect) -> Option<Page> {
    if row < tabs.y {
        return None;
    }
    Page::ALL.get(usize::from(row - tabs.y)).copied()
}

fn mouse_body_click(
    app: &mut App,
    point: (u16, u16),
    button: MouseButton,
    body: Rect,
    rail: bool,
) -> bool {
    match app.page {
        Page::Overview if button == MouseButton::Left => {
            if rail {
                return pressure_map_click(app, point, body);
            }
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
                if button == MouseButton::Left {
                    // A second left click on the same row within the
                    // double-click window opens the investigation.
                    app.register_finding_click(index);
                } else {
                    app.alert_state.select(Some(index));
                }
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

/// Minimum cell widths for each column family. Numeric cells must never
/// render partially truncated: when a table is too narrow for its full
/// column set, whole trailing columns are dropped instead of squeezing.
/// The declared order therefore doubles as the order of loss (last first):
/// processes lose AGE, then THR, then HANDLES, then I/O.
const PROCESS_COLUMN_WIDTHS: [u16; 8] = [7, 18, 7, 10, 10, 7, 6, 6];
/// Tree drops only I/O; PID / name / CPU / MEM always stay.
const TREE_COLUMN_WIDTHS: [u16; 5] = [7, 28, 8, 11, 11];
/// Suspect matrix loses H/T, then I/O, then RSS.
const SUSPECT_COLUMN_WIDTHS: [u16; 7] = [3, 17, 12, 7, 10, 11, 10];

/// How many leading columns of a family fit in `content` cells, counting the
/// one-cell inter-column spacing. Never fewer than `keep`, so the table
/// degrades to its identity columns instead of vanishing on absurd widths.
fn fitted_columns(widths: &[u16], content: u16, keep: usize) -> usize {
    let mut used = 0u16;
    let mut count = 0usize;
    for (index, width) in widths.iter().enumerate() {
        let need = width.saturating_add(u16::from(index > 0));
        if count >= keep && used.saturating_add(need) > content {
            break;
        }
        used = used.saturating_add(need);
        count += 1;
    }
    count
}

/// Content cells the process/tree tables can spend on columns: the rounded
/// panel border eats one cell per side and the persistent highlight gutter
/// ("▌ ") two more.
fn framed_table_content_width(table: Rect) -> u16 {
    table.width.saturating_sub(4)
}

fn column_constraints(widths: &[u16], count: usize) -> Vec<Constraint> {
    let mut constraints = widths[..count]
        .iter()
        .map(|width| Constraint::Length(*width))
        .collect::<Vec<_>>();
    if constraints.len() > 1 {
        // The name column absorbs whatever width the dropped columns free up.
        constraints[1] = Constraint::Min(widths[1]);
    }
    constraints
}

fn process_column_count(table: Rect) -> usize {
    fitted_columns(&PROCESS_COLUMN_WIDTHS, framed_table_content_width(table), 4)
}

fn process_constraints(count: usize) -> Vec<Constraint> {
    column_constraints(&PROCESS_COLUMN_WIDTHS, count)
}

fn tree_column_count(table: Rect) -> usize {
    fitted_columns(&TREE_COLUMN_WIDTHS, framed_table_content_width(table), 4)
}

fn tree_constraints(count: usize) -> Vec<Constraint> {
    column_constraints(&TREE_COLUMN_WIDTHS, count)
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
        Style::default().fg(palette().bg).bg(accent).bold()
    } else {
        Style::default()
            .fg(accent)
            .bg(palette().surface_raised)
            .bold()
    })
}

fn row_highlight_style() -> Style {
    Style::default()
        .fg(palette().text)
        .bg(palette().select_bg)
        .bold()
}

fn process_sort_at(table: Rect, column: u16) -> Option<ProcessSort> {
    let inner = table.inner(Margin::new(1, 1));
    let columns = Rect::new(
        inner.x.saturating_add(2),
        inner.y,
        inner.width.saturating_sub(2),
        1,
    );
    // Same responsive column set as the renderer, so header hit-tests can
    // never drift from the headers actually drawn.
    let count = process_column_count(table);
    let rects = Layout::horizontal(process_constraints(count))
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
        .zip(sorts.into_iter().take(count))
        .find_map(|(rect, sort)| (column >= rect.x && column < rect.right()).then_some(sort))
}

fn tree_sort_at(table: Rect, column: u16) -> Option<TreeSort> {
    let count = tree_column_count(table);
    sort_index_at(table, column, &tree_constraints(count), 2).and_then(|index| {
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

/// The suspect matrix sits in a [`field_block`] (TOP|LEFT borders only), so
/// its content is inset by a single column.
fn suspect_column_count(table: Rect) -> usize {
    fitted_columns(&SUSPECT_COLUMN_WIDTHS, table.width.saturating_sub(1), 4)
}

fn suspect_constraints(count: usize) -> Vec<Constraint> {
    column_constraints(&SUSPECT_COLUMN_WIDTHS, count)
}

fn suspect_sort_at(table: Rect, column: u16) -> Option<SuspectSort> {
    let inner = Rect::new(
        table.x.saturating_add(1),
        table.y.saturating_add(1),
        table.width.saturating_sub(1),
        table.height.saturating_sub(1),
    );
    // Same responsive column set as the renderer, so header hit-tests can
    // never drift from the headers actually drawn.
    let count = suspect_column_count(table);
    let rects = Layout::horizontal(suspect_constraints(count))
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
        .zip(sorts.into_iter().take(count))
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

/// Rail Observe click: resolve the pressure-map tile under the cursor and
/// target its process in the HUNT selection (`app.process_state`), the same
/// selection state the process pages read. The hit-test replays the exact
/// renderer pipeline — same items, same canvas, same layouter — so tiles and
/// clicks can never drift apart.
fn pressure_map_click(app: &mut App, point: (u16, u16), body: Rect) -> bool {
    let canvas = pressure_map_canvas(rail_overview_layout(body).map);
    if !point_in(canvas, point) {
        return false;
    }
    let (items, pids) = pressure_map_items(app);
    let weights = items.iter().map(|item| item.weight).collect::<Vec<_>>();
    let tiles = crate::treemap::layout(&weights, canvas);
    let Some(tile) = tiles.iter().find(|tile| point_in(tile.rect, point)) else {
        return false;
    };
    let [index] = tile.indices.as_slice() else {
        app.status = "Merged remainder tile — open HUNT for the full spectrum".into();
        app.status_is_error = false;
        return true;
    };
    let pid = pids[*index];
    let name = items[*index].label.clone();
    if let Some(position) = app
        .visible_processes()
        .iter()
        .position(|process| process.pid == pid)
    {
        app.process_state.select(Some(position));
        app.status = format!("{name} targeted from the pressure map");
    } else {
        app.status = format!("{name} is hidden by the current HUNT filter");
    }
    app.status_is_error = false;
    true
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

/// The destructive-gate modal's rect for the whole frame `area`. Layout
/// aware: under the rail layout the modal centers inside the canvas body so
/// it never straddles the rail or annunciator; the statusline layout keeps
/// the full-frame center. effects.rs calls this with the frame area for the
/// Modal cue, so the layout resolution must live here, not at call sites.
pub fn modal_region(area: Rect) -> Rect {
    let host = if rail_width(area).is_some() {
        regions(area).body
    } else {
        area
    };
    centered_rect(62, 11, host)
}

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().fg(palette().text).bg(palette().bg)),
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
    let rail = rail_width(area).is_some();
    let regions = regions(area);
    if rail {
        render_rail(frame, app, regions);
        render_annunciator(frame, app, regions.header);
    } else {
        render_header(frame, app, regions.header);
    }
    match app.page {
        Page::Overview if rail => render_overview_rail(frame, app, regions.body),
        Page::Overview => render_overview(frame, app, regions.body),
        Page::Processes => render_processes(frame, app, regions.body),
        Page::Tree => render_tree(frame, app, regions.body),
        Page::Alerts => render_alerts(frame, app, regions.body),
        Page::Timeline => render_timeline(frame, app, regions.body),
        Page::Analyzer => render_analyzer(frame, app, regions.body),
        Page::Settings => render_settings(frame, app, regions.body),
        Page::Help => render_help(frame, regions.body),
    }
    if !rail {
        render_footer(frame, app, regions.footer);
    }
    render_modal(frame, app);
}

/// The full-height avionics rail: brand block, stacked bezel page keys, and
/// the bottom status block that absorbs the statusline footer's duties.
fn render_rail(frame: &mut Frame<'_>, app: &App, regions: UiRegions) {
    let rail = Rect {
        x: regions.full.x,
        y: regions.full.y,
        width: regions.tabs.width,
        height: regions.full.height,
    };
    frame.render_widget(
        Block::default()
            .borders(Borders::RIGHT)
            .border_style(Style::default().fg(palette().border_hot))
            .style(Style::default().fg(palette().text).bg(palette().surface)),
        rail,
    );
    let brand_area = Rect {
        height: RAIL_BRAND_HEIGHT.min(rail.height),
        ..rail
    };
    let brand_label = if rail.width >= RAIL_WIDTH {
        " PCPULSE ▮ MFD "
    } else {
        " PCPULSE▮MFD"
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                brand_label,
                Style::default().fg(palette().bg).bg(palette().ok).bold(),
            ),
            Line::styled(
                format!(" {:02} {}", page_index(app.page) + 1, route_short(app.page)),
                Style::default().fg(palette().alt).bold(),
            ),
        ])
        .style(Style::default().bg(palette().surface)),
        brand_area,
    );
    render_rail_keys(frame, app, regions.tabs);
    render_rail_status(frame, app, regions.footer);
}

fn render_rail_keys(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let width = usize::from(area.width.saturating_sub(1));
    let lines = Page::ALL
        .iter()
        .enumerate()
        .map(|(index, page)| {
            let label = format!(" [{}] {:<width$}", index + 1, route_short(*page));
            if *page == app.page {
                Line::styled(
                    label,
                    Style::default().fg(palette().bg).bg(palette().alt).bold(),
                )
            } else {
                Line::styled(label, Style::default().fg(palette().muted))
            }
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).style(Style::default().bg(palette().surface)),
        area,
    );
}

/// Bottom status block: link state, sample clock, motion badge, abbreviated
/// contextual hints, then the status/error line — the footer's whole
/// contract, folded into the rail.
fn render_rail_status(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let (link, link_color) = if app.connected {
        let etw = app
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.system.etw_active);
        (
            if etw { "♥ LINKED" } else { "♥ ETW DEG" },
            if etw { palette().ok } else { palette().warn },
        )
    } else {
        ("♥ LOST", palette().crit)
    };
    let open = app
        .snapshot
        .as_ref()
        .map_or(0, |snapshot| snapshot.active_alerts.len());
    let clock = app
        .snapshot
        .as_ref()
        .and_then(|snapshot| {
            chrono::DateTime::from_timestamp_millis(snapshot.system.timestamp_ms).map(|utc| {
                utc.with_timezone(&chrono::Local)
                    .format("%H:%M:%S")
                    .to_string()
            })
        })
        .unwrap_or_else(|| "--:--:--".into());
    let mut lines = vec![rail_mode_line(app), rail_input_line(app)];
    lines.push(Line::styled(link, Style::default().fg(link_color).bold()));
    lines.push(Line::from(vec![
        Span::styled(format!(" {clock}"), Style::default().fg(palette().muted)),
        Span::styled(
            format!(" ⚑{open}"),
            Style::default().fg(if open > 0 {
                palette().warn
            } else {
                palette().faint
            }),
        ),
    ]));
    lines.push(Line::from(vec![
        key_badge("m"),
        Span::styled(" fx ", Style::default().fg(palette().muted)),
        key_badge("t"),
        Span::styled(" thm", Style::default().fg(palette().muted)),
    ]));
    lines.push(Line::from(vec![
        key_badge("?"),
        Span::styled(" man ", Style::default().fg(palette().muted)),
        key_badge("q"),
        Span::styled(" exit", Style::default().fg(palette().muted)),
    ]));
    lines.push(rail_status_line(app));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(palette().border_hot))
                .style(
                    Style::default()
                        .fg(palette().text)
                        .bg(palette().surface_raised),
                ),
        ),
        area,
    );
}

fn rail_mode_line(app: &App) -> Line<'static> {
    match &app.mode {
        InputMode::Normal => Line::from(vec![
            Span::styled(
                " NORMAL ",
                Style::default().fg(palette().bg).bg(palette().ok).bold(),
            ),
            Span::styled(
                format!(" {:02}/08", page_index(app.page) + 1),
                Style::default().fg(palette().muted),
            ),
        ]),
        InputMode::Search(_) => Line::styled(
            " / FILTER ",
            Style::default().fg(palette().bg).bg(palette().ok).bold(),
        ),
        InputMode::Chat(_) => Line::styled(
            " ASK ",
            Style::default().fg(palette().bg).bg(palette().alt).bold(),
        ),
        InputMode::ConfirmTerminate { pid, .. } => Line::styled(
            format!(" PID {pid}? "),
            Style::default().fg(palette().bg).bg(palette().crit).bold(),
        ),
        InputMode::EditSetting { .. } => Line::styled(
            " EDIT ",
            Style::default().fg(palette().bg).bg(palette().alt).bold(),
        ),
    }
}

/// Typed input tail while an input mode is live; abbreviated page hints in
/// Normal mode.
fn rail_input_line(app: &App) -> Line<'static> {
    let (typed, cursor) = match &app.mode {
        InputMode::Normal => {
            let hints = match app.page {
                Page::Overview => "2 hunt · 4 inc",
                Page::Processes => "/ o g x",
                Page::Tree => "j/k r x",
                Page::Alerts => "j/k a i r",
                Page::Timeline => "[ ] r",
                Page::Analyzer => "↵ ask n h",
                Page::Settings => "↵ edit s",
                Page::Help => "1–8 Tab",
            };
            return Line::styled(format!(" {hints}"), Style::default().fg(palette().faint));
        }
        InputMode::Search(value) | InputMode::Chat(value) => (value.clone(), palette().ok),
        InputMode::ConfirmTerminate { typed, .. } => (typed.clone(), palette().crit),
        InputMode::EditSetting { typed, .. } => (typed.clone(), palette().alt),
    };
    // Keep the caret visible in the narrow rail: show the tail of the input.
    let tail = typed.chars().rev().take(12).collect::<Vec<_>>();
    let tail = tail.into_iter().rev().collect::<String>();
    Line::from(vec![
        Span::styled(
            format!(" {tail}"),
            Style::default().fg(palette().text).bold(),
        ),
        Span::styled("█", Style::default().fg(cursor)),
    ])
}

fn rail_status_line(app: &App) -> Line<'static> {
    if !app.connected {
        Line::styled(
            format!(
                " ×{}",
                format::truncate(app.last_error.as_deref().unwrap_or("collector dark"), 14)
            ),
            Style::default().fg(palette().crit).bold(),
        )
    } else if !app.status.is_empty() {
        Line::styled(
            format!(" {}", app.status),
            Style::default().fg(if app.status_is_error {
                palette().crit
            } else {
                palette().muted
            }),
        )
    } else {
        Line::styled(" ready", Style::default().fg(palette().faint))
    }
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
            if etw { palette().ok } else { palette().warn },
        )
    } else {
        ("SIGNAL LOST", palette().crit)
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
                " PCPULSE::VITALS ",
                Style::default().fg(palette().bg).bg(palette().ok).bold(),
            ),
            Span::styled(
                " / RUNTIME FORENSICS",
                Style::default().fg(palette().muted).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!(" {:02} {} ", page_index(app.page) + 1, route_name(app.page)),
                Style::default().fg(palette().alt).bold(),
            ),
            Span::styled(
                route_description(app.page),
                Style::default().fg(palette().faint),
            ),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(brand).style(Style::default().fg(palette().text).bg(palette().surface)),
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
                    format!("♥ {status}"),
                    Style::default().fg(status_color).bold(),
                ),
                Span::styled(
                    format!("   ⚑ {active} OPEN   v{version} "),
                    Style::default()
                        .fg(if active > 0 {
                            palette().warn
                        } else {
                            palette().muted
                        })
                        .bold(),
                ),
            ])
            .alignment(Alignment::Right),
            Line::styled(telemetry, Style::default().fg(palette().muted))
                .alignment(Alignment::Right),
        ])
        .style(Style::default().bg(palette().surface)),
        top[1],
    );

    render_route(frame, app, rows[1]);
    frame.render_widget(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(palette().border_hot))
            .style(Style::default().bg(palette().surface)),
        rows[2],
    );
}

fn render_route(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let compact = area.width < 112;
    let mut spans = Vec::new();
    for (index, page) in Page::ALL.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(
                "  ›  ",
                Style::default().fg(palette().border_hot),
            ));
        }
        let label = if compact {
            route_short(*page)
        } else {
            route_name(*page)
        };
        let text = format!(" {:02} {label} ", index + 1);
        spans.push(if *page == app.page {
            Span::styled(
                text,
                Style::default().fg(palette().bg).bg(palette().alt).bold(),
            )
        } else {
            Span::styled(text, Style::default().fg(palette().muted))
        });
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(palette().surface)),
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
        // "pressure map" is the avionics treemap's name; the vitals Observe
        // page centers on the PRESSURE FIELD chart instead.
        Page::Overview if theme::active().layout == LayoutKind::Rail => {
            "pressure map / likely culprits / live incidents"
        }
        Page::Overview => "pressure field / likely culprits / live incidents",
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
    // The load-composition donut needs at least ~20x9 cells of its own plus
    // room for the system vector and agent swarm panes; below that the right
    // column keeps its original two-pane split.
    let donut_fits = primary[2].width >= DONUT_MIN_WIDTH && primary[2].height >= 28;
    let right = if donut_fits {
        Layout::vertical([
            Constraint::Min(10),
            Constraint::Length(1),
            Constraint::Length(DONUT_MIN_HEIGHT),
            Constraint::Length(1),
            Constraint::Min(7),
        ])
        .split(primary[2])
    } else {
        Layout::vertical([
            Constraint::Percentage(57),
            Constraint::Length(1),
            Constraint::Min(7),
        ])
        .split(primary[2])
    };

    render_pressure_field(frame, app, left[0]);
    render_suspect_matrix(frame, app, left[2]);
    render_system_vector(frame, app, right[0]);
    if donut_fits {
        render_load_composition(frame, app, right[2]);
        render_agent_swarm(frame, app, right[4]);
    } else {
        render_agent_swarm(frame, app, right[2]);
    }
    render_incident_tape(frame, app, vertical[1]);

    let _ = snapshot;
}

/// Every finding class gets one caution/warning lamp on the annunciator
/// strip. Kinds that do not map to a dedicated lamp light the SYS catch-all
/// instead of being dropped.
const ANNUNCIATOR_LAMPS: [&str; 10] = [
    "CPU", "MEM", "IO", "HANG", "LAUNCH", "AGENT", "POOL", "DPC", "BUDGET", "SYS",
];

fn lamp_for_kind(kind: &str) -> &'static str {
    match kind {
        "sustainedCpu" => "CPU",
        "memoryGrowth" => "MEM",
        "sustainedIo" | "diskLatency" => "IO",
        "unresponsive" => "HANG",
        "slowLaunch" => "LAUNCH",
        "abandonedAgent" => "AGENT",
        "kernelPoolGrowth" => "POOL",
        "dpcInterrupt" => "DPC",
        "collectorBudget" | "collectorGrowth" => "BUDGET",
        // handleGrowth, threadGrowth, and any future kind.
        _ => "SYS",
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Critical => 2,
    }
}

/// Top annunciator strip: lamp per finding class (lit in the severity color
/// of the highest matching active finding, faint when clear) plus a compact
/// telemetry line, so findings stay visible from every page.
fn render_annunciator(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(palette().border_hot))
        .style(Style::default().fg(palette().text).bg(palette().surface));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut worst: [Option<Severity>; ANNUNCIATOR_LAMPS.len()] = [None; ANNUNCIATOR_LAMPS.len()];
    if let Some(snapshot) = &app.snapshot {
        for alert in &snapshot.active_alerts {
            let lamp = lamp_for_kind(&alert.kind);
            let index = ANNUNCIATOR_LAMPS
                .iter()
                .position(|label| *label == lamp)
                .unwrap_or(ANNUNCIATOR_LAMPS.len() - 1);
            let lit = worst[index]
                .is_none_or(|current| severity_rank(alert.severity) > severity_rank(current));
            if lit {
                worst[index] = Some(alert.severity);
            }
        }
    }
    let lamps = ANNUNCIATOR_LAMPS
        .iter()
        .zip(worst)
        .map(|(label, severity)| match severity {
            Some(severity) => Span::styled(
                format!(" {label} "),
                Style::default()
                    .fg(palette().bg)
                    .bg(severity_color(severity))
                    .bold(),
            ),
            None => Span::styled(
                format!(" {label} "),
                Style::default().fg(palette().faint).bg(palette().surface),
            ),
        })
        .collect::<Vec<_>>();
    let telemetry = if let Some(snapshot) = &app.snapshot {
        let memory = percent(
            snapshot.system.memory_used_bytes,
            snapshot.system.memory_total_bytes,
        );
        format!(
            " CPU {:>5.1}%  MEM {:>5.1}%  {:>4}P / {:>5}T  v{}",
            snapshot.system.cpu_percent,
            memory,
            snapshot.system.process_count,
            snapshot.system.thread_count,
            snapshot.service_version
        )
    } else {
        " awaiting first telemetry frame".into()
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(lamps),
            Line::styled(telemetry, Style::default().fg(palette().muted)),
        ])
        .style(Style::default().bg(palette().surface)),
        inner,
    );
}

/// The Observe recomposition under the rail layout, shared by the renderer
/// and the mouse hit-tests.
struct RailOverviewLayout {
    vector: Option<Rect>,
    map: Rect,
    tape: Rect,
    ribbon: Option<Rect>,
}

/// Rail Observe is the spatial view: a slim System Vector column on the
/// left, the rest of the canvas dominated by the PRESSURE MAP process
/// treemap, and a bottom strip running the Incident Tape full-width with
/// the load-composition ribbon docked at its right end when it fits. The
/// Suspect Matrix and Agent Swarm stay on their own pages (and in vitals);
/// here agent candidates surface as AGT-badged tiles instead.
fn rail_overview_layout(body: Rect) -> RailOverviewLayout {
    const RIBBON_DOCK_WIDTH: u16 = 34;
    let canvas = body.inner(Margin::new(1, 0));
    let ribbon_docked = canvas.height >= 30 && canvas.width >= 42 + RIBBON_DOCK_WIDTH;
    let tape_height = if ribbon_docked {
        DONUT_MIN_HEIGHT + 1
    } else if canvas.height >= 29 {
        9
    } else {
        7
    };
    let vertical =
        Layout::vertical([Constraint::Min(15), Constraint::Length(tape_height)]).split(canvas);
    // The System Vector cedes ground as the canvas narrows: 30 columns on a
    // wide canvas, 24 below 130, and below 100 it disappears entirely — the
    // annunciator strip already carries CPU/MEM, so the PRESSURE MAP takes
    // the full width instead.
    let vector_width = if canvas.width >= 130 {
        Some(30)
    } else if canvas.width >= 100 {
        Some(24)
    } else {
        None
    };
    let (vector, map) = match vector_width {
        Some(width) => {
            let columns = Layout::horizontal([Constraint::Length(width), Constraint::Min(30)])
                .split(vertical[0]);
            (Some(columns[0]), columns[1])
        }
        None => (None, vertical[0]),
    };
    let (tape, ribbon) = if ribbon_docked {
        let strip =
            Layout::horizontal([Constraint::Min(40), Constraint::Length(RIBBON_DOCK_WIDTH)])
                .split(vertical[1]);
        (strip[0], Some(strip[1]))
    } else {
        (vertical[1], None)
    };
    RailOverviewLayout {
        vector,
        map,
        tape,
        ribbon,
    }
}

fn render_overview_rail(frame: &mut Frame<'_>, app: &App, area: Rect) {
    if app.snapshot.is_none() {
        render_offline(frame, app, area);
        return;
    }
    let layout = rail_overview_layout(area);
    if let Some(vector) = layout.vector {
        render_system_vector(frame, app, vector);
    }
    render_pressure_map(frame, app, layout.map);
    render_incident_tape(frame, app, layout.tape);
    if let Some(ribbon) = layout.ribbon {
        render_load_composition(frame, app, ribbon);
    }
}

/// Processes shown on the pressure map: enough for a landscape, few enough
/// that tiles stay readable.
const PRESSURE_MAP_PROCESSES: usize = 24;

/// Build the treemap items (and their PIDs, index-aligned) for the pressure
/// map from the current snapshot. Rebuilt every frame — the widget itself is
/// stateless like the rest of this module; selection rides on
/// `app.process_state` exactly as the HUNT page uses it.
///
/// Dominant-channel rule per tile:
/// - `crit` overrides when the process owns an active finding;
/// - `warn` marks agent candidates (the AGT badge rides along), heat = the
///   hottest of its three channel ratios;
/// - otherwise the channel with the highest threshold-relative pressure
///   wins: CPU vs `settings.cpu_percent` → `ok`, working set vs 8% of total
///   RAM (the same target `triage_heat` uses) → `alt`, combined read+write
///   IO vs `settings.io_mb_per_sec` → `info`.
///
/// Heat is that dominant ratio clamped to 0..1, so a tile glows exactly as
/// hard as it presses against its own threshold.
fn pressure_map_items(app: &App) -> (Vec<crate::treemap::TreemapItem>, Vec<u32>) {
    let Some(snapshot) = &app.snapshot else {
        return (Vec::new(), Vec::new());
    };
    let selected_pid = app.selected_process().map(|process| process.pid);
    let mut processes = snapshot
        .processes
        .iter()
        .filter(|process| process.pid > 4)
        .collect::<Vec<_>>();
    processes.sort_by(|left, right| {
        right
            .working_set_bytes
            .cmp(&left.working_set_bytes)
            .then(left.pid.cmp(&right.pid))
    });
    processes.truncate(PRESSURE_MAP_PROCESSES);
    let mut items = Vec::with_capacity(processes.len());
    let mut pids = Vec::with_capacity(processes.len());
    for process in processes {
        let cpu = process.cpu_percent / app.settings.cpu_percent.max(1.0);
        let memory_target = (snapshot.system.memory_total_bytes as f64 * 0.08).max(1.0);
        let memory = process.working_set_bytes as f64 / memory_target;
        let io = (process.read_bytes_per_sec + process.write_bytes_per_sec)
            / (app.settings.io_mb_per_sec.max(1.0) * 1024.0 * 1024.0);
        let hottest = cpu.max(memory).max(io);
        let alerted = snapshot
            .active_alerts
            .iter()
            .any(|alert| alert.process_id == Some(process.pid));
        let (color, heat) = if alerted {
            // A confirmed finding always reads hot, whatever its ratios say.
            (palette().crit, hottest.max(0.85))
        } else if process.is_agent_candidate {
            (palette().warn, hottest)
        } else if cpu >= memory && cpu >= io {
            (palette().ok, cpu)
        } else if memory >= io {
            (palette().alt, memory)
        } else {
            (palette().info, io)
        };
        items.push(crate::treemap::TreemapItem {
            label: process.name.clone(),
            weight: process.working_set_bytes.max(1),
            color,
            heat: heat.clamp(0.0, 1.0),
            badge: process.is_agent_candidate.then_some("AGT"),
            selected: selected_pid == Some(process.pid),
            detail: format!(
                "RSS {}  CPU {:.1}%",
                format::bytes(process.working_set_bytes),
                process.cpu_percent
            ),
        });
        pids.push(process.pid);
    }
    (items, pids)
}

/// The cell region the treemap tiles occupy inside the pressure-map pane —
/// [`field_block`] keeps TOP|LEFT borders, so the canvas is inset by one on
/// each of those edges. Shared with the mouse hit-tests.
fn pressure_map_canvas(map: Rect) -> Rect {
    Rect::new(
        map.x.saturating_add(1),
        map.y.saturating_add(1),
        map.width.saturating_sub(1),
        map.height.saturating_sub(1),
    )
}

fn render_pressure_map(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let block = field_block(
        " ▦ PRESSURE MAP  working-set area · channel pressure · click targets HUNT ",
        palette().ok,
    );
    frame.render_widget(block, area);
    let canvas = pressure_map_canvas(area);
    let (items, _pids) = pressure_map_items(app);
    if items.is_empty() {
        frame.render_widget(
            Paragraph::new("no process telemetry in this snapshot")
                .alignment(Alignment::Center)
                .style(Style::default().fg(palette().muted).bg(palette().surface)),
            canvas,
        );
        return;
    }
    let weights = items.iter().map(|item| item.weight).collect::<Vec<_>>();
    let tiles = crate::treemap::layout(&weights, canvas);
    crate::treemap::render(frame, &items, &tiles, canvas);
}

/// The `[min, max]` timestamp span of a series, widened to a non-empty
/// window. Chart x-bounds must clamp to the span of the data actually being
/// drawn — never a positional or wall-clock guess — so whatever history
/// exists always fills the pane width.
fn time_span(timestamps: impl Iterator<Item = i64>) -> (f64, f64) {
    let mut minimum = f64::INFINITY;
    let mut maximum = f64::NEG_INFINITY;
    for timestamp in timestamps {
        let timestamp = timestamp as f64;
        minimum = minimum.min(timestamp);
        maximum = maximum.max(timestamp);
    }
    if minimum > maximum {
        (0.0, 1.0)
    } else {
        (minimum, maximum.max(minimum + 1.0))
    }
}

/// Round `value` up to a clean axis step: 1/2/5 times a power of ten.
fn clean_ceiling(value: f64) -> f64 {
    if value <= 0.0 {
        return 0.0;
    }
    let magnitude = 10f64.powf(value.log10().floor());
    for step in [1.0, 2.0, 5.0] {
        let candidate = step * magnitude;
        if candidate >= value {
            return candidate;
        }
    }
    10.0 * magnitude
}

fn render_pressure_field(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        return;
    };
    let (minimum, maximum) = time_span(app.live_history.iter().map(|point| point.timestamp_ms));
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
    // Half-block cells paint a dense field; braille reads as scattered dots
    // for slowly-varying series at live-pane sizes.
    let datasets = vec![
        Dataset::default()
            .name("CPU")
            .marker(symbols::Marker::HalfBlock)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(palette().ok))
            .data(&cpu),
        Dataset::default()
            .name("MEM")
            .marker(symbols::Marker::HalfBlock)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(palette().alt))
            .data(&memory),
    ];
    frame.render_widget(
        Chart::new(datasets)
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(field_block(&title, palette().ok))
            .x_axis(Axis::default().bounds([minimum, maximum]))
            .y_axis(
                Axis::default()
                    .style(Style::default().fg(palette().faint))
                    .bounds([0.0, 100.0])
                    .labels([
                        Line::styled("0", Style::default().fg(palette().faint)),
                        Line::styled("50", Style::default().fg(palette().muted)),
                        Line::styled("100", Style::default().fg(palette().faint)),
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
    let column_count = suspect_column_count(area);
    let rows = suspects
        .into_iter()
        .filter(|process| process.pid > 4)
        .take(capacity)
        .enumerate()
        .map(|(index, process)| {
            let heat = triage_heat(process, app);
            let owner_style = if !process.responsive {
                Style::default().fg(palette().crit).bold()
            } else if process.is_agent_candidate {
                Style::default().fg(palette().alt).bold()
            } else {
                Style::default().fg(palette().text)
            };
            let mut cells = vec![
                Cell::from(format!("{:02}", index + 1)).style(Style::default().fg(palette().faint)),
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
            ];
            cells.truncate(column_count);
            Row::new(cells).style(Style::default().bg(if index.is_multiple_of(2) {
                palette().surface
            } else {
                palette().surface_raised
            }))
        })
        .collect::<Vec<_>>();
    let mut header_cells = vec![
        sortable_header_cell("#", app.suspect_sort == SuspectSort::Heat, palette().alt),
        sortable_header_cell(
            "TARGET",
            app.suspect_sort == SuspectSort::Name,
            palette().alt,
        ),
        sortable_header_cell(
            "TRIAGE HEAT",
            app.suspect_sort == SuspectSort::Heat,
            palette().alt,
        ),
        sortable_header_cell("CPU", app.suspect_sort == SuspectSort::Cpu, palette().alt),
        sortable_header_cell(
            "RSS",
            app.suspect_sort == SuspectSort::Memory,
            palette().alt,
        ),
        sortable_header_cell("I/O", app.suspect_sort == SuspectSort::Io, palette().alt),
        sortable_header_cell(
            "H/T",
            app.suspect_sort == SuspectSort::HandlesThreads,
            palette().alt,
        ),
    ];
    header_cells.truncate(column_count);
    frame.render_widget(
        Table::new(rows, suspect_constraints(column_count))
            .header(
                Row::new(header_cells).style(
                    Style::default()
                        .fg(palette().alt)
                        .bg(palette().surface_raised)
                        .bold(),
                ),
            )
            .block(field_block(
                " ⌖ SUSPECT MATRIX  relative pressure / not an alert score ",
                palette().alt,
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
        pool_line(system, area),
        Line::styled("", Style::default()),
    ];
    let collector_ratio = (system.collector_working_set_bytes as f64 / (25.0 * 1024.0 * 1024.0))
        .max(system.collector_cpu_percent / 0.2)
        .max(f64::from(system.collector_handle_count) / 250.0);
    // Shed whole trailing stat segments when the pane is narrow — a clipped
    // "210H" would read as a different number.
    let content = usize::from(area.width.saturating_sub(1));
    let mut collector_stats = format!(
        "  {}  {:.3}%  {}H ",
        format::bytes(system.collector_working_set_bytes),
        system.collector_cpu_percent,
        system.collector_handle_count
    );
    if content < 11 + collector_stats.chars().count() {
        collector_stats = format!(
            "  {}  {:.3}% ",
            format::bytes(system.collector_working_set_bytes),
            system.collector_cpu_percent
        );
    }
    if content < 11 + collector_stats.chars().count() {
        collector_stats = format!("  {} ", format::bytes(system.collector_working_set_bytes));
    }
    lines.push(Line::from(vec![
        Span::styled(
            " COLLECTOR ",
            Style::default().fg(palette().bg).bg(palette().info).bold(),
        ),
        Span::styled(
            collector_stats,
            Style::default().fg(ratio_color(collector_ratio)).bold(),
        ),
    ]));
    // The "threshold-relative" suffix rides along only when the pane can
    // hold every glyph of it; otherwise the title stops after the name so it
    // never truncates mid-word.
    let title = if area.width >= 39 {
        " ◇ SYSTEM VECTOR  threshold-relative "
    } else {
        " ◇ SYSTEM VECTOR "
    };
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(field_block(title, palette().info)),
        area,
    );
}

/// The POOL summary keeps its R/W read/write pair only when the pane can hold
/// every glyph: a clipped rate ("3.00 M") misreports the number, and the I/O
/// meter above already carries the combined rate.
fn pool_line(system: &SystemMetric, area: Rect) -> Line<'static> {
    let pool = system.paged_pool_bytes + system.nonpaged_pool_bytes;
    let pool_text = format::bytes(pool);
    let rw_text = format!(
        "{} / {}",
        format::rate(system.disk_read_bytes_per_sec),
        format::rate(system.disk_write_bytes_per_sec)
    );
    let mut spans = vec![
        Span::styled(" POOL ", Style::default().fg(palette().info).bold()),
        Span::styled(pool_text.clone(), Style::default().fg(palette().text)),
    ];
    let full_width = 6 + pool_text.chars().count() + 7 + rw_text.chars().count();
    if usize::from(area.width.saturating_sub(1)) >= full_width {
        spans.push(Span::styled("   R/W ", Style::default().fg(palette().faint)));
        spans.push(Span::styled(rw_text, Style::default().fg(palette().muted)));
    }
    Line::from(spans)
}

const DONUT_MIN_WIDTH: u16 = 20;
const DONUT_MIN_HEIGHT: u16 = 9;
// Below this system CPU there is no meaningful load to attribute; an
// idle-dominated disc would render as a featureless field.
const DONUT_QUIESCENT_CPU: f64 = 2.0;

fn render_load_composition(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        return;
    };
    let busy = snapshot.system.cpu_percent.clamp(0.0, 100.0);
    let block = field_block(" ◔ LOAD COMPOSITION  share of busy cpu ", palette().ok);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if busy < DONUT_QUIESCENT_CPU {
        frame.render_widget(
            Paragraph::new(vec![
                Line::default(),
                Line::styled(
                    format!("cpu quiescent  {busy:.1}%"),
                    Style::default().fg(palette().muted),
                ),
                Line::styled("nothing to attribute", Style::default().fg(palette().faint)),
            ])
            .alignment(Alignment::Center)
            .style(Style::default().fg(palette().text).bg(palette().surface)),
            inner,
        );
        return;
    }
    let mut suspects = snapshot
        .processes
        .iter()
        .filter(|process| process.pid > 4)
        .collect::<Vec<_>>();
    suspects.sort_by(|left, right| right.cpu_percent.total_cmp(&left.cpu_percent));
    let cycle = [palette().ok, palette().alt, palette().info, palette().warn];
    let mut slices = suspects
        .iter()
        .take(4)
        .enumerate()
        .map(|(index, process)| {
            // Alarm red only for a suspect currently past the CPU threshold;
            // otherwise cycle the four monitor channels.
            let color = if process.cpu_percent >= app.settings.cpu_percent.max(1.0) {
                palette().crit
            } else {
                cycle[index % cycle.len()]
            };
            (
                format::truncate(&process.name, 9),
                process.cpu_percent.max(0.0),
                color,
            )
        })
        .collect::<Vec<_>>();
    let named = slices.iter().map(|slice| slice.1).sum::<f64>();
    slices.push(("other".into(), (busy - named).max(0.0), palette().muted));
    // The disc shows only busy CPU: each slice is a share of the work being
    // done, so an 83%-idle machine still yields a readable attribution.
    let total = slices
        .iter()
        .map(|slice| slice.1)
        .sum::<f64>()
        .max(f64::MIN_POSITIVE);

    // One proportional ribbon row instead of a disc: colored segments read at
    // any terminal resolution, unlike a mostly-empty braille pie.
    let width = inner.width.max(1) as usize;
    let mut widths = slices
        .iter()
        .map(|(_, value, _)| {
            if *value > 0.0 {
                (((value / total) * width as f64).round() as usize).max(1)
            } else {
                0
            }
        })
        .collect::<Vec<_>>();
    // Reconcile rounding so the ribbon exactly fills its row.
    let mut assigned = widths.iter().sum::<usize>();
    while assigned > width {
        if let Some(widest) = widths
            .iter()
            .enumerate()
            .filter(|(_, w)| **w > 1)
            .max_by_key(|(_, w)| **w)
            .map(|(index, _)| index)
        {
            widths[widest] -= 1;
            assigned -= 1;
        } else {
            break;
        }
    }
    if let Some(widest) = widths
        .iter()
        .enumerate()
        .max_by_key(|(_, w)| **w)
        .map(|(index, _)| index)
        && assigned < width
    {
        widths[widest] += width - assigned;
    }
    let ribbon = Line::from(
        slices
            .iter()
            .zip(&widths)
            .filter(|(_, w)| **w > 0)
            .map(|((_, _, color), w)| Span::styled("█".repeat(*w), Style::default().fg(*color)))
            .collect::<Vec<_>>(),
    );

    let rows = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(inner);
    frame.render_widget(
        Paragraph::new(ribbon).style(Style::default().fg(palette().text).bg(palette().surface)),
        rows[0],
    );
    // A slice whose share would print as 0.0% earns no legend row — the
    // gallery showed a meaningless "other 0.0%" entry on quiet fixtures.
    let mut legend = slices
        .iter()
        .filter(|(_, value, _)| value / total * 100.0 >= 0.05)
        .map(|(label, value, color)| {
            Line::from(vec![
                Span::styled("■ ", Style::default().fg(*color)),
                Span::styled(format!("{label:<12}"), Style::default().fg(palette().text)),
                Span::styled(
                    format!("{:>5.1}%", value / total * 100.0),
                    Style::default().fg(*color).bold(),
                ),
            ])
        })
        .collect::<Vec<_>>();
    legend.push(Line::from(vec![
        Span::styled("  busy        ", Style::default().fg(palette().muted)),
        Span::styled(format!("{busy:>5.1}%"), Style::default().fg(palette().ok)),
    ]));
    legend.push(Line::from(vec![
        Span::styled("  idle        ", Style::default().fg(palette().muted)),
        Span::styled(
            format!("{:>5.1}%", 100.0 - busy),
            Style::default().fg(palette().faint),
        ),
    ]));
    frame.render_widget(
        Paragraph::new(legend).style(Style::default().fg(palette().text).bg(palette().surface)),
        rows[1],
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
    // A clipped tail misquotes the number ("RSS 2." for 2.06 GB), so the
    // summary sheds whole segments when the pane cannot hold every glyph.
    let content = usize::from(area.width.saturating_sub(1));
    let summary_full = format!("  CPU {cpu:.1}%  RSS {}", format::bytes(memory));
    let summary = if content >= 12 + summary_full.chars().count() {
        summary_full
    } else {
        format!("  CPU {cpu:.1}%")
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" {:02} TRACKED ", agents.len()),
                Style::default().fg(palette().bg).bg(palette().alt).bold(),
            ),
            Span::styled(summary, Style::default().fg(palette().text)),
        ]),
        Line::from(vec![
            Span::styled(" ABANDONED ", Style::default().fg(palette().faint).bold()),
            Span::styled(
                // Whole words or the short form — never a clipped tail.
                if content >= 11 + format!("{abandoned} sustained finding(s)").chars().count() {
                    format!("{abandoned} sustained finding(s)")
                } else {
                    format!("{abandoned} findings")
                },
                Style::default()
                    .fg(if abandoned > 0 {
                        palette().crit
                    } else {
                        palette().muted
                    })
                    .bold(),
            ),
        ]),
    ];
    let capacity = usize::from(area.height.saturating_sub(4));
    for process in agents.into_iter().take(capacity) {
        let mut spans = vec![
            Span::styled("  ├─ ", Style::default().fg(palette().border_hot)),
            Span::styled(
                format!("{:<6}", process.pid),
                Style::default().fg(palette().alt),
            ),
            Span::styled(
                format!("{:<18}", format::truncate(&process.name, 17)),
                Style::default().fg(palette().text).bold(),
            ),
        ];
        let stats_full = format!(
            " {:>5.1}%  {}",
            process.cpu_percent,
            format::bytes(process.working_set_bytes)
        );
        // Same rule as the summary: whole stat segments or none at all.
        if content >= 29 + stats_full.chars().count() {
            spans.push(Span::styled(stats_full, Style::default().fg(palette().muted)));
        } else if content >= 29 + 7 {
            spans.push(Span::styled(
                format!(" {:>5.1}%", process.cpu_percent),
                Style::default().fg(palette().muted),
            ));
        }
        lines.push(Line::from(spans));
    }
    if lines.len() == 2 {
        lines.push(Line::styled(
            "  no configured agent process patterns are active",
            Style::default().fg(palette().faint),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(field_block(
                " ⑂ AGENT SWARM  parallel-run footprint ",
                palette().alt,
            )),
        area,
    );
}

fn render_incident_tape(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        return;
    };
    let capacity = usize::from(area.height.saturating_sub(2)).max(1);
    // Badge (6) + owner (25) + condition (35) columns; the evidence column
    // adds its "  :: " lead-in plus up to 44 glyphs. When the pane cannot
    // hold the whole evidence column it is dropped entirely (and the title
    // loses its "/ evidence" suffix) — a mid-string ":: sustained" stub
    // reads as data.
    let content = usize::from(area.width.saturating_sub(1));
    let show_evidence = content >= 6 + 25 + 35 + 5 + 44;
    let mut lines = snapshot
        .active_alerts
        .iter()
        .take(capacity)
        .map(|alert| {
            let owner = alert.process_name.as_deref().unwrap_or("system / driver");
            let mut spans = vec![
                Span::styled(
                    format!(" {} ", severity_label(alert.severity)),
                    severity_badge(alert.severity),
                ),
                Span::styled(
                    format!(" {:<24}", format::truncate(owner, 23)),
                    Style::default().fg(palette().text).bold(),
                ),
                Span::styled(
                    format!(" {:<34}", format::truncate(&alert.title, 33)),
                    Style::default().fg(severity_color(alert.severity)),
                ),
            ];
            if show_evidence {
                let evidence = alert
                    .evidence
                    .first()
                    .map(|item| format!("{} {}", item.label, item.value))
                    .unwrap_or_else(|| "sustained condition confirmed".into());
                spans.push(Span::styled(
                    format!("  :: {}", format::truncate(&evidence, 44)),
                    Style::default().fg(palette().muted),
                ));
            }
            Line::from(spans)
        })
        .collect::<Vec<_>>();
    if lines.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(
                " QUIET ",
                Style::default().fg(palette().bg).bg(palette().ok).bold(),
            ),
            Span::styled(
                "  no sustained deviations in the active window",
                Style::default().fg(palette().muted),
            ),
        ]));
    }
    let title = if show_evidence {
        " ⚑ INCIDENT TAPE  owner / condition / evidence "
    } else {
        " ⚑ INCIDENT TAPE  owner / condition "
    };
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(field_block(title, palette().warn)),
        area,
    );
}

fn vector_line(label: &'static str, ratio: f64, value: String, width: usize) -> Line<'static> {
    let color = ratio_color(ratio);
    Line::from(vec![
        Span::styled(
            format!(" {label:<5}"),
            Style::default().fg(palette().muted).bold(),
        ),
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
        palette().crit
    } else if ratio >= 0.72 {
        palette().warn
    } else {
        palette().ok
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
        .border_style(Style::default().fg(palette().border_hot))
        .style(Style::default().fg(palette().text).bg(palette().surface))
        .title(title)
        .title_style(Style::default().fg(accent).bold())
}

fn render_processes(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let sections =
        Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)]).split(area);
    let table_area = inset(sections[0]);
    let column_count = process_column_count(table_area);
    let processes = app.visible_processes();
    let rows = processes
        .iter()
        .enumerate()
        .map(|(index, process)| process_row(process, index, column_count))
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
    let mut header_cells = vec![
        sortable_header_cell("PID", app.process_sort == ProcessSort::Pid, palette().ok),
        sortable_header_cell("NAME", app.process_sort == ProcessSort::Name, palette().ok),
        sortable_header_cell("CPU", app.process_sort == ProcessSort::Cpu, palette().ok),
        sortable_header_cell("MEM", app.process_sort == ProcessSort::Memory, palette().ok),
        sortable_header_cell("I/O", app.process_sort == ProcessSort::Io, palette().ok),
        sortable_header_cell(
            "HANDLES",
            app.process_sort == ProcessSort::Handles,
            palette().ok,
        ),
        sortable_header_cell(
            "THR",
            app.process_sort == ProcessSort::Threads,
            palette().ok,
        ),
        sortable_header_cell("AGE", app.process_sort == ProcessSort::Age, palette().ok),
    ];
    header_cells.truncate(column_count);
    let table = Table::new(rows, process_constraints(column_count))
        .header(
            Row::new(header_cells).style(
                Style::default()
                    .fg(palette().alt)
                    .bg(palette().surface_raised)
                    .bold(),
            )
            .bottom_margin(1),
        )
        .block(accent_panel(
            &title,
            if app.agents_only {
                palette().alt
            } else {
                palette().ok
            },
        ))
        .row_highlight_style(row_highlight_style())
        .highlight_symbol("▌ ")
        .highlight_spacing(HighlightSpacing::Always);
    frame.render_stateful_widget(table, table_area, &mut app.process_state);
    render_process_detail(frame, app.selected_process(), inset(sections[1]));
}

fn process_row(process: &&ProcessMetric, index: usize, column_count: usize) -> Row<'static> {
    let status_style = if !process.responsive {
        Style::default().fg(palette().crit).bold()
    } else if process.is_agent_candidate {
        Style::default().fg(palette().alt)
    } else {
        Style::default().fg(palette().text)
    };
    let mut cells = vec![
        Cell::from(process.pid.to_string()),
        Cell::from(Line::from(vec![
            if process.is_agent_candidate {
                Span::styled(
                    " AGT ",
                    Style::default().fg(palette().bg).bg(palette().alt).bold(),
                )
            } else if !process.responsive {
                Span::styled(
                    " HNG ",
                    Style::default().fg(palette().bg).bg(palette().crit).bold(),
                )
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
            Style::default().fg(palette().crit).bold()
        } else if process.cpu_percent >= 30.0 {
            Style::default().fg(palette().warn)
        } else {
            Style::default().fg(palette().ok)
        }),
        Cell::from(format::bytes(process.working_set_bytes)),
        Cell::from(format::rate(
            process.read_bytes_per_sec + process.write_bytes_per_sec,
        )),
        Cell::from(process.handle_count.to_string()),
        Cell::from(process.thread_count.to_string()),
        Cell::from(format::age(process.started_at_ms, process.timestamp_ms)),
    ];
    cells.truncate(column_count);
    Row::new(cells).style(
        Style::default()
            .fg(palette().text)
            .bg(if index.is_multiple_of(2) {
                palette().surface
            } else {
                palette().surface_raised
            }),
    )
}

fn render_process_detail(frame: &mut Frame<'_>, process: Option<&ProcessMetric>, area: Rect) {
    let text = if let Some(process) = process {
        Text::from(vec![
            Line::styled(
                process.name.clone(),
                Style::default().fg(palette().ok).bold(),
            ),
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
                        palette().alt
                    } else if !process.responsive {
                        palette().crit
                    } else {
                        palette().muted
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
                Style::default().fg(palette().muted),
            ),
            Line::raw(""),
            Line::styled(
                "[ x ]  REQUEST TERMINATION",
                Style::default().fg(palette().warn).bold(),
            ),
            Line::styled(
                "Exact PID entry is required.",
                Style::default().fg(palette().muted),
            ),
        ])
    } else {
        Text::from("No process selected")
    };
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(accent_panel(" ◇ PROCESS LENS ", palette().alt)),
        area,
    );
}

fn render_tree(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let sections =
        Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)]).split(area);
    let table_area = inset(sections[0]);
    let column_count = tree_column_count(table_area);
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
            let mut cells = vec![
                Cell::from(row.process.pid.to_string()),
                Cell::from(Line::from(vec![
                    Span::styled(branch, Style::default().fg(palette().faint)),
                    if row.process.is_agent_candidate {
                        Span::styled("◆ ", Style::default().fg(palette().alt).bold())
                    } else {
                        Span::raw("· ")
                    },
                    Span::styled(
                        format::truncate(&row.process.name, 40),
                        Style::default().fg(if row.process.is_agent_candidate {
                            palette().alt
                        } else {
                            palette().text
                        }),
                    ),
                ])),
                Cell::from(format!("{:.1}%", row.process.cpu_percent)),
                Cell::from(format::bytes(row.process.working_set_bytes)),
                Cell::from(format::rate(
                    row.process.read_bytes_per_sec + row.process.write_bytes_per_sec,
                )),
            ];
            cells.truncate(column_count);
            Row::new(cells).style(Style::default().fg(palette().text).bg(
                if index.is_multiple_of(2) {
                    palette().surface
                } else {
                    palette().surface_raised
                },
            ))
        })
        .collect::<Vec<_>>();
    let title = format!(
        " ⑂ LINEAGE MAP · sort {} · r restores lineage ",
        app.tree_sort.label()
    );
    let mut header_cells = vec![
        sortable_header_cell("PID", app.tree_sort == TreeSort::Pid, palette().info),
        sortable_header_cell(
            "PROCESS TREE",
            app.tree_sort == TreeSort::Name,
            palette().info,
        ),
        sortable_header_cell("CPU", app.tree_sort == TreeSort::Cpu, palette().info),
        sortable_header_cell("MEM", app.tree_sort == TreeSort::Memory, palette().info),
        sortable_header_cell("I/O", app.tree_sort == TreeSort::Io, palette().info),
    ];
    header_cells.truncate(column_count);
    let table = Table::new(rows, tree_constraints(column_count))
        .header(
            Row::new(header_cells).style(
                Style::default()
                    .fg(palette().info)
                    .bg(palette().surface_raised)
                    .bold(),
            )
            .bottom_margin(1),
        )
        .block(accent_panel(&title, palette().info))
        .row_highlight_style(row_highlight_style())
        .highlight_symbol("▌ ")
        .highlight_spacing(HighlightSpacing::Always);
    frame.render_stateful_widget(table, table_area, &mut app.tree_state);
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
                    .style(Style::default().fg(palette().text).bold()),
                Cell::from(
                    alert
                        .process_name
                        .as_deref()
                        .unwrap_or("system / driver")
                        .to_string(),
                )
                .style(Style::default().fg(palette().muted)),
                Cell::from(state).style(
                    Style::default()
                        .fg(if state == "ACTIVE" {
                            palette().warn
                        } else {
                            palette().faint
                        })
                        .bold(),
                ),
                Cell::from(format::timestamp(alert.first_seen_ms))
                    .style(Style::default().fg(palette().faint)),
            ])
            .style(Style::default().bg(if index.is_multiple_of(2) {
                palette().surface
            } else {
                palette().surface_raised
            }))
        })
        .collect::<Vec<_>>();
    let table = Table::new(rows, alert_constraints())
        .header(
            Row::new([
                sortable_header_cell("SEV", app.alert_sort == AlertSort::Severity, palette().warn),
                sortable_header_cell(
                    "FINDING",
                    app.alert_sort == AlertSort::Title,
                    palette().warn,
                ),
                sortable_header_cell("OWNER", app.alert_sort == AlertSort::Owner, palette().warn),
                sortable_header_cell("STATE", app.alert_sort == AlertSort::State, palette().warn),
                sortable_header_cell(
                    "SEEN",
                    app.alert_sort == AlertSort::FirstSeen,
                    palette().warn,
                ),
            ])
            .style(
                Style::default()
                    .fg(palette().warn)
                    .bg(palette().surface_raised)
                    .bold(),
            )
            .bottom_margin(1),
        )
        .block(accent_panel(
            " ⚑ FINDING ARCHIVE · click headers to sort · a acknowledge ",
            palette().warn,
        ))
        .row_highlight_style(row_highlight_style())
        .highlight_symbol("▌ ")
        .highlight_spacing(HighlightSpacing::Always);
    frame.render_stateful_widget(table, inset(sections[0]), &mut app.alert_state);
    render_alert_detail(frame, app.selected_alert(), inset(sections[1]));
}

fn render_alert_detail(frame: &mut Frame<'_>, alert: Option<&Alert>, area: Rect) {
    let Some(alert) = alert else {
        frame.render_widget(
            Paragraph::new("No findings in the selected retention window.")
                .style(Style::default().fg(palette().muted).bg(palette().surface))
                .block(accent_panel(" ◇ EVIDENCE ", palette().alt)),
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
        Line::styled("▸ DIAGNOSIS", Style::default().fg(palette().alt).bold()),
        Line::raw(alert.explanation.clone()),
        Line::raw(""),
        Line::styled(
            "▸ SIGNAL EVIDENCE",
            Style::default().fg(palette().info).bold(),
        ),
    ];
    for evidence in &alert.evidence {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {}  ", evidence.label.to_ascii_uppercase()),
                Style::default()
                    .fg(palette().bg)
                    .bg(palette().border_hot)
                    .bold(),
            ),
            Span::raw(" "),
            Span::styled(evidence.value.clone(), Style::default().fg(palette().text)),
        ]));
    }
    lines.extend([
        Line::raw(""),
        Line::styled("▸ SAFE NEXT MOVE", Style::default().fg(palette().ok).bold()),
        Line::raw(alert.recommendation.clone()),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(accent_panel(" ◈ ATTRIBUTION / EVIDENCE ", palette().alt)),
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
        Style::default().fg(palette().ok).bold(),
    ))];
    items.extend(app.chat_sessions.iter().map(|session| {
        let current = session.conversation_id == app.conversation_id;
        ListItem::new(Line::from(vec![
            Span::styled(
                if current { "◆ " } else { "◇ " },
                Style::default().fg(if current {
                    palette().alt
                } else {
                    palette().faint
                }),
            ),
            Span::styled(
                format::truncate(&session.title, area.width.saturating_sub(8) as usize),
                Style::default()
                    .fg(if current {
                        palette().text
                    } else {
                        palette().muted
                    })
                    .bold(),
            ),
        ]))
    }));
    let accent = if app.chat_history_focused {
        palette().warn
    } else {
        palette().alt
    };
    frame.render_stateful_widget(
        List::new(items)
            .block(accent_panel(" ◇ CHAT VAULT · h focus · n new ", accent))
            .highlight_style(Style::default().fg(palette().bg).bg(accent).bold())
            .highlight_symbol("▌ "),
        area,
        &mut app.chat_session_state,
    );
}

fn render_chat_status(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let status = &app.diagnostics.status;
    let ingest_color = if status.last_error.is_some() {
        palette().crit
    } else if status.last_success_ms.is_some() {
        palette().ok
    } else {
        palette().warn
    };
    let auth = app.codex_auth_status.as_deref().unwrap_or_else(|| {
        if app.codex_auth_error.is_some() {
            "AUTH REQUIRED"
        } else {
            "CHECKING SESSION"
        }
    });
    let auth_color = if app.codex_auth_status.is_some() {
        palette().ok
    } else if app.codex_auth_error.is_some() {
        palette().crit
    } else {
        palette().warn
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
                    Style::default().fg(palette().text),
                ),
            ]),
            Line::styled(
                format!(
                    "{} STORED · {} VISIBLE · {} MALFORMED",
                    status.events_stored,
                    app.diagnostics.logs.len(),
                    status.malformed_events
                ),
                Style::default().fg(palette().muted),
            ),
        ])
        .style(Style::default().bg(palette().surface))
        .block(accent_panel(" ⌁ EVIDENCE BUS ", ingest_color)),
        sections[0],
    );
    // The subtitle keeps its full phrasing only when the pane holds every
    // word; the short variant is a complete phrase, never a clipped tail.
    let link_subtitle = if usize::from(sections[1].width.saturating_sub(2))
        >= "saved Codex login · ChatGPT subscription".chars().count()
    {
        "saved Codex login · ChatGPT subscription"
    } else {
        "ChatGPT-authenticated"
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(auth, Style::default().fg(auth_color).bold()),
            Line::styled(link_subtitle, Style::default().fg(palette().muted)),
        ])
        .style(Style::default().bg(palette().surface))
        .block(accent_panel(" ◈ CODEX LINK ", auth_color)),
        sections[1],
    );
    // While a submission is in flight the stat line yields to the live
    // timeout ticker; the elapsed clock advances with every drawn frame.
    let core_detail = match app.analyzer_progress() {
        Some((elapsed, budget)) if app.analyzer_running => Line::styled(
            analyzer_progress_text(elapsed, budget),
            Style::default().fg(palette().warn),
        ),
        _ => Line::styled(
            analyst_core_stats(app, sections[2].width.saturating_sub(2)),
            Style::default().fg(palette().muted),
        ),
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                state,
                Style::default()
                    .fg(if app.analyzer_running {
                        palette().warn
                    } else {
                        palette().alt
                    })
                    .bold(),
            ),
            core_detail,
        ])
        .style(Style::default().bg(palette().surface))
        .block(accent_panel(" ◇ ANALYST CORE ", palette().alt)),
        sections[2],
    );
}

/// The ANALYST CORE line while a submission is running: elapsed time against
/// the Codex wait budget, plus the one escape hatch.
fn analyzer_progress_text(elapsed: u64, budget: u64) -> String {
    format!(
        "analyzing {}m{}s / {}m{}s · Esc cancels",
        elapsed / 60,
        elapsed % 60,
        budget / 60,
        budget % 60
    )
}

/// The ANALYST CORE stat line sheds whole segments (then whole words) as the
/// pane narrows — "0 saved chats" degrades to "0 saved", never "0 saved ch".
fn analyst_core_stats(app: &App, width: u16) -> String {
    let hours = app.analyzer_window_hours;
    let turns = app.chat_messages.len();
    let saved = app.chat_sessions.len();
    let candidates = [
        format!("fresh {hours}h · {turns} turns · {saved} saved chats"),
        format!("fresh {hours}h · {turns} turns · {saved} saved"),
        format!("{turns} turns · {saved} saved"),
        format!("{saved} saved"),
    ];
    let width = usize::from(width);
    candidates
        .iter()
        .find(|candidate| candidate.chars().count() <= width)
        .cloned()
        .unwrap_or_else(|| candidates[candidates.len() - 1].clone())
}

fn render_chat_transcript(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let mut lines = Vec::new();
    if app.chat_messages.is_empty() {
        lines.extend([
            Line::styled("THE MACHINE HAS RECEIPTS.", Style::default().fg(palette().alt).bold()),
            Line::raw(""),
            Line::styled("Ask what slowed the PC, which agent tree is leaking, why disk or kernel activity climbed, or what can be changed safely.", Style::default().fg(palette().text)),
            Line::raw(""),
            Line::styled("TRY A TRACE", Style::default().fg(palette().ok).bold()),
            Line::styled("  › What was responsible for the last slowdown?", Style::default().fg(palette().muted)),
            Line::styled("  › Are any agent process trees abandoned or growing?", Style::default().fg(palette().muted)),
            Line::styled("  › Give me a low-risk optimization plan with evidence.", Style::default().fg(palette().muted)),
            Line::raw(""),
            Line::styled("Every answer receives a fresh, redacted evidence bundle. No action is executed here.", Style::default().fg(palette().faint)),
        ]);
    } else {
        for message in &app.chat_messages {
            // Failed turns wear the crit channel and a ✗ badge instead of
            // the ordinary analyst styling.
            let (badge, color) = match message.role {
                ChatRole::User => (" YOU ", palette().info),
                ChatRole::Assistant if message.is_error => (" ✗ ANALYST ", palette().crit),
                ChatRole::Assistant => (" ANALYST ", palette().alt),
            };
            let body_color = if message.is_error {
                palette().crit
            } else {
                palette().text
            };
            lines.push(Line::from(vec![
                Span::styled(badge, Style::default().fg(palette().bg).bg(color).bold()),
                Span::styled(
                    format!("  {}", format::timestamp(message.timestamp_ms)),
                    Style::default().fg(palette().faint),
                ),
            ]));
            for text in message.text.lines() {
                lines.push(Line::styled(
                    format!("  {text}"),
                    Style::default().fg(body_color),
                ));
            }
            if !message.evidence_refs.is_empty() {
                lines.push(Line::styled(
                    format!("  ↳ {}", message.evidence_refs.join("  ·  ")),
                    Style::default().fg(palette().ok),
                ));
            }
            lines.push(Line::raw(""));
        }
    }
    if app.analyzer_running {
        lines.push(Line::from(vec![
            Span::styled(
                " ANALYST ",
                Style::default().fg(palette().bg).bg(palette().warn).bold(),
            ),
            Span::styled(
                "  ░ correlating processes, incidents, baselines, and event logs…",
                Style::default().fg(palette().warn),
            ),
        ]));
    }
    let mut block = accent_panel(" ◈ INTERROGATION CHANNEL ", palette().alt);
    if let Some(error) = &app.analyzer_last_error {
        // Sticky failure banner: pinned to the pane's bottom edge so it can
        // never scroll away, and it outlives routine status updates until
        // the next submission or a new chat clears it.
        block = block.title_bottom(Line::styled(
            format!(
                " ✗ {} ",
                format::truncate(error, usize::from(area.width.saturating_sub(8)))
            ),
            Style::default().fg(palette().crit).bold(),
        ));
    }
    let inner_width = area.width.saturating_sub(2).max(1);
    let visible = area.height.saturating_sub(2) as usize;
    let rendered_lines: usize = lines
        .iter()
        .map(|line| line.width().max(1).div_ceil(inner_width as usize))
        .sum();
    let paragraph = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .style(Style::default().fg(palette().text).bg(palette().surface))
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
            Style::default().fg(palette().ok).bold(),
        ));
        if response.proposed_actions.is_empty() {
            lines.push(Line::styled(
                "  No action justified by current evidence.",
                Style::default().fg(palette().muted),
            ));
        }
        for action in &response.proposed_actions {
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {:02} ", action.priority),
                    Style::default()
                        .fg(palette().bg)
                        .bg(risk_color(action.risk))
                        .bold(),
                ),
                Span::styled(
                    format!(" {}", action.title),
                    Style::default().fg(palette().text).bold(),
                ),
            ]));
            lines.push(Line::styled(
                if action.requires_confirmation {
                    "    confirmation required"
                } else {
                    "    observational / non-mutating"
                },
                Style::default().fg(if action.requires_confirmation {
                    palette().warn
                } else {
                    palette().muted
                }),
            ));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "NEXT QUESTIONS",
            Style::default().fg(palette().info).bold(),
        ));
        for follow_up in &response.suggested_follow_ups {
            lines.push(Line::styled(
                format!("  › {follow_up}"),
                Style::default().fg(palette().muted),
            ));
        }
    } else {
        lines.push(Line::styled(
            "GROUND RULES",
            Style::default().fg(palette().ok).bold(),
        ));
        let width = area.width.saturating_sub(2);
        for (marker, rule, color) in [
            ("✓", "exact PC Pulse evidence refs", palette().text),
            ("✓", "sustained conditions over spikes", palette().text),
            ("✓", "confirmation + rollback for changes", palette().text),
            ("✓", "bounded local conversation", palette().text),
            ("×", "no automatic process termination", palette().warn),
            ("×", "no API-key billing fallback", palette().warn),
        ] {
            lines.extend(ground_rule_lines(marker, rule, color, width));
        }
        if let Some(error) = &app.codex_auth_error {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                format::truncate(error, 180),
                Style::default().fg(palette().crit),
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(accent_panel(" ◇ ACTION ORBIT ", palette().ok)),
        area,
    );
}

/// One ACTION ORBIT ground-rule bullet, pre-wrapped with a hanging indent so
/// continuation lines rest at the rule-text column instead of dangling as
/// full-width orphan words.
fn ground_rule_lines(
    marker: &'static str,
    rule: &'static str,
    color: Color,
    width: u16,
) -> Vec<Line<'static>> {
    let indent = 4;
    let column = usize::from(width).saturating_sub(indent).max(8);
    wrap_words(rule, column)
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            let prefix = if index == 0 {
                format!("  {marker} ")
            } else {
                " ".repeat(indent)
            };
            Line::styled(format!("{prefix}{row}"), Style::default().fg(color))
        })
        .collect()
}

/// Greedy word wrap with no mid-word cuts: every returned row fits `width`
/// cells unless a single word alone exceeds it.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let mut rows = Vec::new();
    let mut row = String::new();
    for word in text.split_whitespace() {
        if row.is_empty() {
            row = word.to_string();
        } else if row.chars().count() + 1 + word.chars().count() <= width {
            row.push(' ');
            row.push_str(word);
        } else {
            rows.push(std::mem::take(&mut row));
            row = word.to_string();
        }
    }
    if !row.is_empty() {
        rows.push(row);
    }
    if rows.is_empty() {
        rows.push(String::new());
    }
    rows
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
                Style::default().fg(palette().alt).bold(),
            ),
            Line::raw(""),
            Line::raw(
                "Press a to launch the dedicated PC Pulse systems analyzer. It receives a bounded, redacted evidence bundle and runs as the interactive user—not as LocalSystem.",
            ),
            Line::raw(""),
            Line::styled("SAFETY ENVELOPE", Style::default().fg(palette().ok).bold()),
            Line::raw("  • Codex runs in a read-only sandbox"),
            Line::raw("  • no recommendation is executed"),
            Line::raw("  • direct termination commands are rejected"),
            Line::raw("  • mutations require confirmation + rollback"),
            Line::raw("  • every claim must cite collected evidence"),
            Line::raw(""),
            Line::styled(
                "CLI  PcPulse.exe analyze 1",
                Style::default().fg(palette().info).bold(),
            ),
            Line::styled(
                "API  PcPulse.exe agent-context 1",
                Style::default().fg(palette().muted),
            ),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .style(Style::default().fg(palette().text).bg(palette().surface))
                .block(accent_panel(" ◈ AGENT CONTRACT ", palette().alt)),
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
        palette().crit
    } else if status.last_success_ms.is_some() {
        palette().ok
    } else {
        palette().warn
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
                Span::styled(last_poll, Style::default().fg(palette().text)),
            ]),
            Line::styled(
                format!(
                    "{} STORED  ·  {} DUP  ·  {} MALFORMED  ·  {} VISIBLE",
                    status.events_stored,
                    status.duplicate_events,
                    status.malformed_events,
                    app.diagnostics.logs.len()
                ),
                Style::default().fg(palette().muted),
            ),
        ])
        .style(Style::default().bg(palette().surface))
        .block(accent_panel(" ⌁ WINDOWS DIAGNOSTIC SIGNAL ", ingest_color)),
        sections[0],
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                plan_state,
                Style::default()
                    .fg(if app.analyzer_running {
                        palette().warn
                    } else {
                        palette().alt
                    })
                    .bold(),
            ),
            Line::styled(
                format!(
                    "a synthesize  ·  [ ] evidence window: {}h  ·  r reload",
                    app.analyzer_window_hours
                ),
                Style::default().fg(palette().muted),
            ),
        ])
        .style(Style::default().bg(palette().surface))
        .block(accent_panel(" ◇ SYSTEMS ANALYZER ", palette().alt)),
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
                        Style::default().fg(palette().bg).bg(match log.level {
                            pcpulse_service::models::DiagnosticLevel::Critical => palette().crit,
                            pcpulse_service::models::DiagnosticLevel::Error => palette().warn,
                            pcpulse_service::models::DiagnosticLevel::Warning => palette().info,
                        }),
                    ),
                    Span::styled(
                        format!(" {:?} ", log.category).to_ascii_uppercase(),
                        Style::default().fg(palette().alt).bold(),
                    ),
                    Span::styled(
                        format::timestamp(log.timestamp_ms),
                        Style::default().fg(palette().faint),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(
                        format!("  {} / {}", log.provider, log.event_id),
                        Style::default().fg(palette().text),
                    ),
                    Span::styled(
                        log.related_process
                            .as_ref()
                            .map(|name| format!("  ⟶ {name}"))
                            .unwrap_or_default(),
                        Style::default().fg(palette().ok),
                    ),
                ]),
            ]
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(if lines.is_empty() {
            vec![Line::styled(
                "No warning/error/critical Application or System events in the visible window.",
                Style::default().fg(palette().muted),
            )]
        } else {
            lines
        })
        .wrap(Wrap { trim: true })
        .style(Style::default().fg(palette().text).bg(palette().surface))
        .block(accent_panel(" ⌁ RAW SIGNAL FEED ", palette().info)),
        area,
    );
}

fn render_plan_index(frame: &mut Frame<'_>, app: &mut App, plan: &OptimizationPlan, area: Rect) {
    let sections =
        Layout::vertical([Constraint::Percentage(44), Constraint::Percentage(56)]).split(area);
    let mut diagnosis_lines = vec![
        Line::styled(
            plan.summary.clone(),
            Style::default().fg(palette().text).bold(),
        ),
        Line::raw(""),
    ];
    for diagnosis in &plan.diagnoses {
        diagnosis_lines.push(Line::from(vec![
            Span::styled(
                format!(" {} ", severity_label(diagnosis.severity)),
                severity_badge(diagnosis.severity),
            ),
            Span::raw(" "),
            Span::styled(diagnosis.title.clone(), Style::default().fg(palette().text)),
        ]));
    }
    if plan.diagnoses.is_empty() {
        diagnosis_lines.push(Line::styled(
            "No defensible sustained diagnosis.",
            Style::default().fg(palette().muted),
        ));
    }
    frame.render_widget(
        Paragraph::new(diagnosis_lines)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(accent_panel(" ◈ SYNTHESIS ", palette().alt)),
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
                        Style::default()
                            .fg(palette().bg)
                            .bg(risk_color(action.risk))
                            .bold(),
                    ),
                    Span::raw(" "),
                    Span::styled(
                        action.title.clone(),
                        Style::default().fg(palette().text).bold(),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(
                        format!("  {:?}", action.category).to_ascii_uppercase(),
                        Style::default().fg(palette().alt),
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
                        Style::default().fg(palette().muted),
                    ),
                ]),
            ])
        })
        .collect::<Vec<_>>();
    frame.render_stateful_widget(
        List::new(actions)
            .highlight_style(row_highlight_style())
            .highlight_symbol("▌ ")
            .block(accent_panel(" ⟐ ORDERED ACTION QUEUE ", palette().ok)),
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
                .style(Style::default().fg(palette().muted).bg(palette().surface))
                .block(accent_panel(" ⟐ INTEGRATION DETAIL ", palette().ok)),
            area,
        );
        return;
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" PRIORITY {} ", action.priority),
                Style::default()
                    .fg(palette().bg)
                    .bg(risk_color(action.risk))
                    .bold(),
            ),
            Span::styled(
                format!("  {:?} RISK", action.risk).to_ascii_uppercase(),
                Style::default().fg(risk_color(action.risk)).bold(),
            ),
        ]),
        Line::styled(
            action.title.clone(),
            Style::default().fg(palette().text).bold(),
        ),
        detail_line("Target", action.target.clone()),
        Line::raw(""),
        Line::styled("WHY", Style::default().fg(palette().alt).bold()),
        Line::raw(action.reason.clone()),
        Line::raw(""),
        Line::styled("STEPS", Style::default().fg(palette().info).bold()),
    ];
    for (index, step) in action.steps.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {}. {:?} ", index + 1, step.kind).to_ascii_uppercase(),
                Style::default()
                    .fg(palette().bg)
                    .bg(if step.mutates_system {
                        palette().warn
                    } else {
                        palette().info
                    })
                    .bold(),
            ),
            Span::raw(" "),
            Span::styled(
                step.description.clone(),
                Style::default().fg(palette().text),
            ),
        ]));
        if let Some(command) = &step.command {
            lines.push(Line::styled(
                format!("    PS> {command}"),
                Style::default().fg(palette().ok),
            ));
        }
        if let Some(prompt) = &step.confirmation_prompt {
            lines.push(Line::styled(
                format!("    CONFIRM: {prompt}"),
                Style::default().fg(palette().warn),
            ));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "VALIDATE",
        Style::default().fg(palette().ok).bold(),
    ));
    for item in &action.validation {
        lines.push(Line::raw(format!("  ✓ {item}")));
    }
    if !action.rollback.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "ROLLBACK",
            Style::default().fg(palette().warn).bold(),
        ));
        for item in &action.rollback {
            lines.push(Line::raw(format!("  ↶ {item}")));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!("EVIDENCE  {}", action.evidence_refs.join(" · ")),
        Style::default().fg(palette().faint),
    ));
    lines.push(Line::styled(
        format!("PLAN  {} / {}", plan.plan_id, plan.context_id),
        Style::default().fg(palette().faint),
    ));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(accent_panel(
                " ⟐ INTEGRATION DETAIL · DISPLAY ONLY ",
                palette().ok,
            )),
        area,
    );
}

fn risk_color(risk: PlanRisk) -> Color {
    match risk {
        PlanRisk::Low => palette().ok,
        PlanRisk::Medium => palette().warn,
        PlanRisk::High => palette().crit,
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
            .style(Style::default().fg(palette().muted).bg(palette().surface))
            .alignment(Alignment::Center)
            .block(accent_panel(" ∿ SIGNAL HISTORY ", palette().ok)),
            area,
        );
        return;
    }
    let (minimum, maximum) = time_span(points.iter().map(|item| item.timestamp_ms));
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
            .style(Style::default().fg(palette().ok))
            .data(&cpu),
        Dataset::default()
            .name("Memory")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(palette().alt))
            .data(&memory),
    ];
    frame.render_widget(
        Chart::new(cpu_data)
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(accent_panel(
                &format!(" ∿ RESOURCE FIELD · last {}h ", app.timeline_hours),
                palette().ok,
            ))
            .x_axis(
                Axis::default()
                    .style(Style::default().fg(palette().faint))
                    .bounds([minimum, maximum]),
            )
            .y_axis(
                Axis::default()
                    .style(Style::default().fg(palette().muted))
                    .bounds([0.0, 100.0])
                    .labels([
                        Line::styled("0%", Style::default().fg(palette().faint)),
                        Line::styled("50%", Style::default().fg(palette().muted)),
                        Line::styled("100%", Style::default().fg(palette().warn).bold()),
                    ]),
            ),
        inset(rows[0]),
    );
    // Autoscale to the data: a fixed ceiling flatlines sub-threshold latency
    // (0.6–2 ms real data against a 30 ms axis reads as a dead sensor).
    let data_max = latency.iter().map(|(_, value)| *value).fold(0.0, f64::max);
    let latency_max = clean_ceiling(data_max * 1.25).max(5.0);
    let latency_mid = latency_max / 2.0;
    frame.render_widget(
        Chart::new(vec![
            Dataset::default()
                .name("latency ms")
                .marker(symbols::Marker::HalfBlock)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(palette().warn))
                .data(&latency),
        ])
        .style(Style::default().fg(palette().text).bg(palette().surface))
        .block(accent_panel(" ≋ DISK LATENCY FIELD ", palette().warn))
        .x_axis(
            Axis::default()
                .style(Style::default().fg(palette().faint))
                .bounds([minimum, maximum]),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(palette().muted))
                .bounds([0.0, latency_max])
                .labels(vec![
                    Line::styled("0", Style::default().fg(palette().faint)),
                    Line::styled(format_axis_ms(latency_mid), Style::default().fg(palette().muted)),
                    Line::styled(
                        format!("{} ms", format_axis_ms(latency_max)),
                        Style::default().fg(palette().warn).bold(),
                    ),
                ]),
        ),
        inset(rows[1]),
    );
}

/// Axis-label number: whole values print bare, halves keep one decimal.
fn format_axis_ms(value: f64) -> String {
    if (value - value.round()).abs() < f64::EPSILON {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    }
}

fn render_settings(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let rows = app
        .visible_setting_fields()
        .into_iter()
        .enumerate()
        .map(|(index, field)| {
            Row::new([
                Cell::from(Line::from(vec![
                    Span::styled("◇ ", Style::default().fg(palette().alt)),
                    Span::styled(field.label(), Style::default().fg(palette().text)),
                ])),
                Cell::from(field.value(&app.settings)).style(Style::default().fg(palette().ok)),
                Cell::from(field.unit()).style(Style::default().fg(palette().muted)),
            ])
            .style(Style::default().bg(if index.is_multiple_of(2) {
                palette().surface
            } else {
                palette().surface_raised
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
                sortable_header_cell(
                    "SETTING",
                    app.setting_sort == SettingSort::Name,
                    palette().alt,
                ),
                sortable_header_cell(
                    "VALUE",
                    app.setting_sort == SettingSort::Value,
                    palette().alt,
                ),
                sortable_header_cell("UNIT", app.setting_sort == SettingSort::Unit, palette().alt),
            ])
            .style(
                Style::default()
                    .fg(if app.settings_dirty {
                        palette().warn
                    } else {
                        palette().alt
                    })
                    .bg(palette().surface_raised)
                    .bold(),
            )
            .bottom_margin(1),
        )
        .block(accent_panel(
            title,
            if app.settings_dirty {
                palette().warn
            } else {
                palette().alt
            },
        ))
        .row_highlight_style(row_highlight_style())
        .highlight_symbol("▌ ");
    frame.render_stateful_widget(table, inset(area), &mut app.setting_state);
}

/// Key/description rows for both help panes. Descriptions are short enough
/// to sit on one line at ≥100 terminal columns; anything that still must
/// wrap does so through [`help_lines`]' hanging indent, so the two-column
/// grid never sheds orphan full-width words.
const HELP_GLOBAL: [(&str, &str); 11] = [
    ("1–8", "jump to a page"),
    ("Tab / Shift-Tab", "next / previous page"),
    ("j / k, ↑ / ↓", "move selection"),
    ("PgUp / PgDn", "move ten rows"),
    ("r", "refresh current page"),
    ("mouse click", "select rows, tabs, prompts"),
    ("mouse wheel", "scroll the active view"),
    ("m", "toggle motion effects"),
    ("t", "vitals / avionics profile"),
    ("q / Ctrl-C", "quit"),
    ("?", "this page"),
];
const HELP_CONTEXTUAL: [(&str, &str); 15] = [
    ("/", "filter name / path / PID"),
    ("o", "cycle process sort"),
    ("g", "agent-only process focus"),
    ("x", "typed-PID termination request"),
    ("a", "acknowledge finding"),
    ("i", "investigate the selected finding in Oracle"),
    ("[ / ]", "shorter / longer timeline"),
    ("Enter on Oracle", "ask the systems analyzer"),
    ("h / n on Oracle", "chat history / new chat"),
    ("[ / ] on Oracle", "fresh evidence window"),
    ("table header click", "sort by clicked column"),
    ("process right-click", "typed-PID confirmation"),
    ("Enter / e", "edit selected setting"),
    ("s", "save settings"),
    ("Esc", "cancel input / modal"),
];

fn render_help(frame: &mut Frame<'_>, area: Rect) {
    let columns = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area.inner(Margin::new(2, 1)));
    let global_width = columns[0].width.saturating_sub(2);
    let contextual_width = columns[1].width.saturating_sub(2);
    let mut global = Vec::new();
    for (key, description) in HELP_GLOBAL {
        global.extend(help_lines(key, description, global_width));
    }
    global.push(Line::raw(""));
    for hint in [
        "Launch with --theme vitals|avionics to pick a profile.",
        "The collector continues when the TUI exits.",
    ] {
        for row in wrap_words(hint, usize::from(global_width).max(8)) {
            global.push(Line::styled(row, Style::default().fg(palette().muted)));
        }
    }
    let mut contextual = Vec::new();
    for (key, description) in HELP_CONTEXTUAL {
        contextual.extend(help_lines(key, description, contextual_width));
    }
    contextual.push(Line::raw(""));
    for row in wrap_words(
        "PC Pulse never terminates a process automatically.",
        usize::from(contextual_width).max(8),
    ) {
        contextual.push(Line::styled(
            row,
            Style::default().fg(palette().warn).bold(),
        ));
    }
    // Lines are pre-wrapped at word boundaries above; no Paragraph wrap, so
    // a description can never spill into the key column as an orphan row.
    frame.render_widget(
        Paragraph::new(global)
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(accent_panel(" ◈ NAVIGATION RUNES ", palette().ok)),
        columns[0],
    );
    frame.render_widget(
        Paragraph::new(contextual)
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(accent_panel(" ◇ CONTEXT RITES ", palette().alt)),
        columns[1],
    );
}

fn render_footer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let interaction = match &app.mode {
        InputMode::Normal => normal_footer(app.page),
        InputMode::Search(value) => Line::from(vec![
            Span::styled(
                " / FILTER SIGNAL  ",
                Style::default().fg(palette().bg).bg(palette().ok).bold(),
            ),
            Span::raw("  "),
            Span::styled(value, Style::default().fg(palette().text).bold()),
            Span::styled("█", Style::default().fg(palette().ok)),
        ]),
        InputMode::Chat(value) => Line::from(vec![
            Span::styled(
                " ASK THE MACHINE  ",
                Style::default().fg(palette().bg).bg(palette().alt).bold(),
            ),
            Span::raw("  "),
            Span::styled(value, Style::default().fg(palette().text).bold()),
            Span::styled("█", Style::default().fg(palette().alt)),
            Span::styled(
                "  Enter send · Esc cancel",
                Style::default().fg(palette().muted),
            ),
        ]),
        InputMode::ConfirmTerminate { pid, typed, .. } => Line::from(vec![
            Span::styled(
                format!("TYPE PID {pid} TO CONFIRM  "),
                Style::default().fg(palette().crit).bold(),
            ),
            Span::raw(typed),
            Span::styled("█", Style::default().fg(palette().crit)),
        ]),
        InputMode::EditSetting { field, typed } => Line::from(vec![
            Span::styled(
                format!("{}  ", field.label().to_ascii_uppercase()),
                Style::default().fg(palette().alt).bold(),
            ),
            Span::raw(typed),
            Span::styled("█", Style::default().fg(palette().alt)),
            Span::styled(
                "  Enter apply · Esc cancel",
                Style::default().fg(palette().muted),
            ),
        ]),
    };
    let status = if !app.connected {
        Line::from(vec![
            Span::styled(
                " OFFLINE ",
                Style::default().fg(palette().bg).bg(palette().crit).bold(),
            ),
            Span::styled(
                format!(
                    "  {}",
                    app.last_error.as_deref().unwrap_or("Collector unavailable")
                ),
                Style::default().fg(palette().crit),
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
                    .fg(palette().bg)
                    .bg(if app.status_is_error {
                        palette().crit
                    } else {
                        palette().info
                    })
                    .bold(),
            ),
            Span::styled(
                format!("  {}", app.status),
                Style::default().fg(if app.status_is_error {
                    palette().crit
                } else {
                    palette().muted
                }),
            ),
        ])
    } else {
        Line::styled(
            " mouse  click select / focus  ·  wheel scroll  ·  table headers sort  ·  right-click process confirms",
            Style::default().fg(palette().faint),
        )
    };
    frame.render_widget(
        Paragraph::new(vec![interaction, status]).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(palette().border_hot))
                .style(
                    Style::default()
                        .fg(palette().text)
                        .bg(palette().surface_raised),
                ),
        ),
        area,
    );
}

fn normal_footer(page: Page) -> Line<'static> {
    let contextual = match page {
        Page::Overview => "2 hunt  ·  4 incidents  ·  r sample",
        Page::Processes => "/ query  ·  o rank  ·  g agents  ·  x terminate",
        Page::Tree => "j/k trace  ·  r rebuild  ·  x terminate",
        Page::Alerts => "j/k inspect  ·  a acknowledge  ·  i investigate  ·  r refresh",
        Page::Timeline => "[ ] window  ·  r reload",
        Page::Analyzer => "Enter ask  ·  n new  ·  h history  ·  [ ] evidence  ·  j/k scroll",
        Page::Settings => "Enter edit  ·  s commit  ·  r revert",
        Page::Help => "1–8 route  ·  Tab cycle",
    };
    Line::from(vec![
        Span::styled(
            " NORMAL ",
            Style::default().fg(palette().bg).bg(palette().ok).bold(),
        ),
        Span::styled(
            format!(
                "  {:02}/08 {}  ::  {contextual}   ",
                page_index(page) + 1,
                route_name(page)
            ),
            Style::default().fg(palette().text),
        ),
        key_badge("Tab"),
        Span::styled(" route  ", Style::default().fg(palette().muted)),
        key_badge("m"),
        Span::styled(" motion  ", Style::default().fg(palette().muted)),
        key_badge("?"),
        Span::styled(" manual  ", Style::default().fg(palette().muted)),
        key_badge("q"),
        Span::styled(" exit", Style::default().fg(palette().muted)),
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
            Style::default().fg(palette().crit).bold(),
        ),
        Line::raw(""),
        Line::raw("Unsaved work may be lost. No action occurs unless the exact PID is entered."),
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                format!(" TYPE {pid} "),
                Style::default().fg(palette().bg).bg(palette().warn).bold(),
            ),
            Span::raw("  "),
            Span::styled(typed.clone(), Style::default().fg(palette().text).bold()),
            Span::styled("█", Style::default().fg(palette().crit)),
        ]),
        Line::raw(""),
        Line::styled(
            "Enter confirm · Esc cancel",
            Style::default().fg(palette().muted),
        ),
    ];
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(palette().crit))
                .style(
                    Style::default()
                        .fg(palette().text)
                        .bg(palette().surface_raised),
                )
                .title(" ! DESTRUCTIVE GATE ")
                .title_style(Style::default().fg(palette().crit).bold())
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
            Line::styled(
                "×  COLLECTOR DARK",
                Style::default().fg(palette().crit).bold(),
            ),
            Line::raw(""),
            Line::raw(error),
            Line::raw(""),
            Line::styled(
                "The TUI retries every two seconds. Verify the PcPulseCollector service.",
                Style::default().fg(palette().muted),
            ),
        ])
        .style(Style::default().fg(palette().text).bg(palette().surface))
        .alignment(Alignment::Center)
        .block(accent_panel(" × SIGNAL LOST ", palette().crit).border_type(BorderType::Double)),
        area.inner(Margin::new(4, 2)),
    );
}

fn panel<'a>(title: &'a str) -> Block<'a> {
    accent_panel(title, palette().muted)
}

fn accent_panel<'a>(title: &'a str, accent: Color) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(palette().border))
        .style(Style::default().fg(palette().text).bg(palette().surface))
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
        Span::styled(format!("{label}: "), Style::default().fg(palette().muted)),
        Span::styled(value, Style::default().fg(palette().text)),
    ])
}

/// One help-grid entry: badge + first description row, then continuation
/// rows indented to the description column (hanging indent). `width` is the
/// pane's inner width in cells.
fn help_lines(key: &'static str, description: &'static str, width: u16) -> Vec<Line<'static>> {
    let badge = format!(" {key:<13} ");
    let indent = badge.chars().count() + 2;
    let column = usize::from(width).saturating_sub(indent).max(8);
    wrap_words(description, column)
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            if index == 0 {
                Line::from(vec![
                    Span::styled(
                        badge.clone(),
                        Style::default()
                            .fg(palette().text)
                            .bg(palette().select_bg)
                            .bold(),
                    ),
                    Span::raw("  "),
                    Span::styled(row, Style::default().fg(palette().text)),
                ])
            } else {
                Line::from(vec![
                    Span::raw(" ".repeat(indent)),
                    Span::styled(row, Style::default().fg(palette().text)),
                ])
            }
        })
        .collect()
}

fn key_badge(key: &'static str) -> Span<'static> {
    Span::styled(
        format!(" {key} "),
        Style::default().fg(palette().bg).bg(palette().ok).bold(),
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
        Severity::Info => palette().info,
        Severity::Warning => palette().warn,
        Severity::Critical => palette().crit,
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
    Style::default()
        .fg(palette().bg)
        .bg(severity_color(severity))
        .bold()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::TreeRow;
    use pcpulse_service::models::{ProcessMetric, ProcessNode, Snapshot, SystemMetric};
    use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};

    #[test]
    fn every_profile_palette_has_distinct_semantic_channels() {
        for profile in theme::ALL {
            let p = profile.palette;
            let channels = [p.ok, p.alt, p.info, p.warn, p.crit];
            for (index, color) in channels.iter().enumerate() {
                assert!(
                    !channels[..index].contains(color),
                    "{}: duplicate accent channel",
                    profile.name
                );
            }
            assert_ne!(p.bg, p.surface, "{}", profile.name);
            assert_ne!(p.surface, p.surface_raised, "{}", profile.name);
            assert_ne!(p.text, p.muted, "{}", profile.name);
            assert_ne!(p.border, p.border_hot, "{}", profile.name);
        }
    }

    #[test]
    fn overview_renders_authored_shell_and_palette() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("PCPULSE::VITALS"));
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
                .filter(|cell| cell.bg == palette().surface)
                .count()
                > 100
        );
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .any(|cell| cell.fg == palette().ok)
        );
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .any(|cell| cell.fg == palette().alt)
        );
    }

    #[test]
    fn load_composition_donut_renders_with_legend_at_full_size() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("LOAD COMPOSITION"));
        assert!(text.contains("codex.exe"));
        // The fixture's named suspects exceed busy CPU, so the "other"
        // remainder is zero and earns no legend row.
        assert!(!text.contains("other"));
        assert!(text.contains("idle"));
        // The donut must join, not replace, the right-column panes.
        assert!(text.contains("SYSTEM VECTOR"));
        assert!(text.contains("AGENT SWARM"));
        // The ribbon shows shares of busy CPU only, so the fixture's dominant
        // suspect paints full-block segment cells in its signal channel.
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .any(|cell| cell.symbol() == "█" && cell.fg == palette().ok)
        );
    }

    #[test]
    fn load_ribbon_legend_keeps_real_remainders_and_skips_zero_rows() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        // Busy CPU above the named suspects leaves a real remainder: the
        // "other" row returns with its share.
        if let Some(snapshot) = app.snapshot.as_mut() {
            snapshot.system.cpu_percent = 60.0;
        }
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("other"));
        assert!(!text.contains("other          0.0%"));
        // Back at the default fixture the remainder is zero and vanishes.
        let mut app = sample_app();
        let backend = render(&mut app);
        assert!(!buffer_text(backend.buffer()).contains("other"));
    }

    #[test]
    fn load_composition_reports_quiescence_instead_of_an_idle_disc() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        if let Some(snapshot) = app.snapshot.as_mut() {
            snapshot.system.cpu_percent = 0.8;
        }
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("LOAD COMPOSITION"));
        assert!(text.contains("cpu quiescent"));
        assert!(text.contains("nothing to attribute"));
        // No slice legend when there is no load worth attributing; the
        // pressure-field charts legitimately keep their own braille cells.
        assert!(!text.contains('■'));
    }

    #[test]
    fn load_composition_donut_yields_to_text_panes_on_small_terminals() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        let backend = render_size(&mut app, 110, 37);
        let text = buffer_text(backend.buffer());
        assert!(!text.contains("LOAD COMPOSITION"));
        assert!(text.contains("SYSTEM VECTOR"));
        assert!(text.contains("AGENT SWARM"));
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
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
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
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
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
    fn failed_turns_render_with_a_crit_cross_marker() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        app.page = Page::Analyzer;
        app.chat_messages.push_back(crate::analyzer::ChatMessage {
            role: ChatRole::User,
            timestamp_ms: 1_800_000_000_000,
            text: "Why is the disk thrashing?".into(),
            evidence_refs: Vec::new(),
            is_error: false,
        });
        app.chat_messages.push_back(crate::analyzer::ChatMessage {
            role: ChatRole::Assistant,
            timestamp_ms: 1_800_000_060_000,
            text: "Analysis failed: Codex systems chat timed out after 300s".into(),
            evidence_refs: Vec::new(),
            is_error: true,
        });
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("✗ ANALYST"));
        let error_row = (0..backend.buffer().area.height)
            .find(|y| row_text(backend.buffer(), *y).contains("Analysis failed:"))
            .expect("the failed turn must be visible");
        let width = usize::from(backend.buffer().area.width);
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .enumerate()
                .any(|(index, cell)| (index / width) as u16 == error_row
                    && cell.fg == palette().crit),
            "the failed turn body must use the crit channel"
        );
        // The healthy user turn keeps the ordinary text channel.
        let user_row = (0..backend.buffer().area.height)
            .find(|y| row_text(backend.buffer(), *y).contains("Why is the disk thrashing?"))
            .expect("the user turn must be visible");
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .enumerate()
                .any(|(index, cell)| (index / width) as u16 == user_row
                    && cell.fg == palette().text)
        );
    }

    #[test]
    fn oracle_pins_the_sticky_error_banner_until_cleared() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        app.page = Page::Analyzer;
        app.analyzer_last_error = Some("Codex systems chat timed out after 300s".into());
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("✗ Codex systems chat timed out after 300s"));
        let width = usize::from(backend.buffer().area.width);
        let banner_row = (0..backend.buffer().area.height)
            .find(|y| row_text(backend.buffer(), *y).contains("✗ Codex systems chat"))
            .expect("banner row");
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .enumerate()
                .any(|(index, cell)| (index / width) as u16 == banner_row
                    && cell.fg == palette().crit)
        );
        // Cleared error, no banner.
        app.analyzer_last_error = None;
        let backend = render(&mut app);
        assert!(!buffer_text(backend.buffer()).contains("✗ Codex"));
    }

    #[test]
    fn analyst_core_ticks_the_timeout_budget_while_running() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        app.page = Page::Analyzer;
        app.analyzer_running = true;
        app.analyzer_started_at = Some(std::time::Instant::now());
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        let budget = crate::analyzer::analyzer_timeout_secs();
        assert!(text.contains(&format!(
            "analyzing 0m0s / {}m{}s · Esc cancels",
            budget / 60,
            budget % 60
        )));
        assert!(text.contains("RECONSTRUCTING / ESC CANCEL"));
        // Idle again: the stat line returns.
        app.analyzer_running = false;
        app.analyzer_started_at = None;
        let text = buffer_text(render(&mut app).buffer());
        assert!(!text.contains("analyzing 0m0s"));
        assert!(text.contains("saved"));
    }

    #[test]
    fn double_clicking_a_finding_row_opens_an_investigation() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = gallery_app();
        app.page = Page::Alerts;
        let area = Rect::new(0, 0, 160, 48);
        let body = regions(area).body;
        let sections = Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(body);
        let table = inset(sections[0]);
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: table.x + 4,
            row: table.y + 3,
            modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
        };
        assert!(handle_mouse(&mut app, click, area));
        assert_eq!(app.page, Page::Alerts, "a single click only selects");
        assert!(app.chat_messages.is_empty());
        assert!(handle_mouse(&mut app, click, area));
        assert_eq!(app.page, Page::Analyzer);
        assert!(
            app.chat_messages
                .front()
                .is_some_and(|turn| turn.text.starts_with("Investigate finding"))
        );
    }

    #[test]
    fn status_messages_never_replace_page_shortcuts() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
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
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
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
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
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
    fn narrow_suspect_matrix_drops_whole_columns_instead_of_squeezing() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        // Wide: the full column family is present.
        let backend = render_size(&mut app, 150, 46);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("RSS"));
        assert!(text.contains("H/T"));
        // 100 columns: H/T and I/O give way; RSS keeps its full value + unit.
        let backend = render_size(&mut app, 100, 30);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("RSS"));
        assert!(text.contains("768 MB"));
        assert!(!text.contains("H/T"));
        // 80 columns: RSS goes too — the header row keeps only the identity
        // columns, so no truncated numeric fragments remain. ("RSS" itself
        // still appears in the agent swarm pane, so read the header row.)
        let area = Rect::new(0, 0, 80, 24);
        let table = overview_suspect_area(regions(area).body);
        let backend = render_size(&mut app, 80, 24);
        let header = row_text(backend.buffer(), table.y + 1);
        assert!(header.contains("TARGET"));
        assert!(header.contains("CPU"));
        assert!(!header.contains("RSS"));
        assert!(!header.contains("I/O"));
        assert!(!header.contains("H/T"));
    }

    #[test]
    fn narrow_suspect_header_hit_tests_match_the_rendered_columns() {
        // 64 columns keeps # / TARGET / HEAT / CPU / RSS; the dropped I/O and
        // H/T sort keys must not be reachable by click.
        let table = Rect::new(2, 8, 64, 20);
        for expected in [
            SuspectSort::Heat,
            SuspectSort::Name,
            SuspectSort::Cpu,
            SuspectSort::Memory,
        ] {
            assert!((table.x..table.right()).any(|x| suspect_sort_at(table, x) == Some(expected)));
        }
        assert!((table.x..table.right()).all(|x| !matches!(
            suspect_sort_at(table, x),
            Some(SuspectSort::Io | SuspectSort::HandlesThreads)
        )));
    }

    #[test]
    fn narrow_process_table_drops_columns_in_declared_order() {
        // Order of loss: AGE, then THR, then HANDLES, then I/O.
        assert_eq!(process_column_count(Rect::new(0, 0, 82, 30)), 8);
        assert_eq!(process_column_count(Rect::new(0, 0, 75, 30)), 7);
        assert_eq!(process_column_count(Rect::new(0, 0, 70, 30)), 6);
        assert_eq!(process_column_count(Rect::new(0, 0, 60, 30)), 5);
        assert_eq!(process_column_count(Rect::new(0, 0, 49, 30)), 4);
        // Tree drops only I/O.
        assert_eq!(tree_column_count(Rect::new(0, 0, 75, 30)), 5);
        assert_eq!(tree_column_count(Rect::new(0, 0, 62, 30)), 4);
        // Hit-tests stay in lockstep with the rendered set.
        let table = Rect::new(0, 0, 70, 30);
        assert!((table.x..table.right()).all(|x| !matches!(
            process_sort_at(table, x),
            Some(ProcessSort::Threads | ProcessSort::Age)
        )));
        assert!(
            (table.x..table.right()).any(|x| process_sort_at(table, x)
                == Some(ProcessSort::Handles))
        );
    }

    #[test]
    fn avionics_hunt_at_120_never_truncates_numeric_columns() {
        let _theme = theme::test_support::activate(theme::ThemeId::Avionics);
        let mut app = sample_app();
        app.page = Page::Processes;
        let backend = render_size(&mut app, 120, 36);
        let text = buffer_text(backend.buffer());
        // HANDLES fits whole; THR and AGE are dropped rather than crushed.
        assert!(text.contains("HANDLES"));
        assert!(!text.contains("THR"));
        // The I/O rate renders with its full unit, never a clipped "10.0 M".
        assert!(text.contains("10.0 MB/s"));
    }

    #[test]
    fn clean_ceiling_rounds_up_to_1_2_5_steps() {
        for (value, expected) in [
            (0.9, 1.0),
            (1.2, 2.0),
            (2.5, 5.0),
            (6.0, 10.0),
            (30.0, 50.0),
            (0.0, 0.0),
        ] {
            assert!(
                (clean_ceiling(value) - expected).abs() < 1e-9,
                "clean_ceiling({value}) = {}, expected {expected}",
                clean_ceiling(value)
            );
        }
    }

    #[test]
    fn disk_latency_axis_autoscales_to_the_data() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = gallery_app();
        app.page = Page::Timeline;
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("DISK LATENCY FIELD"));
        // 0.6–2.0 ms of data: 2.0 * 1.25 rounds up to the 5 ms floor, with a
        // half-scale gridline label — never the old fixed threshold ceiling.
        assert!(text.contains("5 ms"));
        assert!(text.contains("2.5"));
        assert!(!text.contains("30 ms"));
    }

    #[test]
    fn pressure_field_spans_the_full_history_width() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = gallery_app();
        let area = Rect::new(0, 0, 150, 46);
        let body = regions(area).body;
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
        let field = Layout::vertical([
            Constraint::Percentage(43),
            Constraint::Length(1),
            Constraint::Min(8),
        ])
        .split(primary[0])[0];
        let backend = render(&mut app);
        let buffer = backend.buffer();
        let width = usize::from(buffer.area.width);
        // The CPU series must paint a dense half-block band across the pane,
        // not a couple of stray dots pinned to one edge.
        let dense = buffer
            .content()
            .iter()
            .enumerate()
            .filter(|(index, cell)| {
                let x = (index % width) as u16;
                let y = (index / width) as u16;
                point_in(field, (x, y))
                    && matches!(cell.symbol(), "▀" | "▄" | "█")
                    && (cell.fg == palette().ok || cell.bg == palette().ok)
            })
            .count();
        assert!(dense > 40, "pressure field too sparse: {dense} cells");
    }

    #[test]
    fn clicking_non_chat_content_dismisses_chat_input() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
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
    fn vitals_regions_keep_the_statusline_shape() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let area = Rect::new(0, 0, 150, 46);
        assert_eq!(regions(area), statusline_regions(area));
    }

    #[test]
    fn rail_regions_carve_rail_annunciator_and_canvas() {
        let _theme = theme::test_support::activate(theme::ThemeId::Avionics);
        let area = Rect::new(0, 0, 150, 46);
        let regions = regions(area);
        assert_eq!(regions.full, area);
        // Bezel page keys occupy the rail between brand and status blocks.
        assert_eq!(regions.tabs, Rect::new(0, 3, 16, 35));
        // The bottom status block absorbs the footer.
        assert_eq!(regions.footer, Rect::new(0, 38, 16, 8));
        // The annunciator strip spans the remaining width; the canvas fills
        // everything beneath it.
        assert_eq!(regions.header, Rect::new(16, 0, 134, 3));
        assert_eq!(regions.body, Rect::new(16, 3, 134, 43));
    }

    #[test]
    fn rail_yields_to_the_statusline_shape_below_its_dignity_floor() {
        let _theme = theme::test_support::activate(theme::ThemeId::Avionics);
        // At the floor the full 16-column rail applies — there is no
        // intermediate narrow-rail tier any more.
        let floor = regions(Rect::new(0, 0, 96, 26));
        assert_eq!(floor.tabs.width, 16);
        // One column or row under the floor borrows the statusline shape
        // wholesale (the amber palette still applies).
        let narrow = Rect::new(0, 0, 95, 30);
        assert_eq!(regions(narrow), statusline_regions(narrow));
        let short = Rect::new(0, 0, 120, 25);
        assert_eq!(regions(short), statusline_regions(short));
    }

    #[test]
    fn rail_modal_centers_inside_the_canvas_body() {
        let area = Rect::new(0, 0, 150, 46);
        {
            let _theme = theme::test_support::activate(theme::ThemeId::Avionics);
            let body = regions(area).body;
            let modal = modal_region(area);
            // Centered within the canvas: never straddling the rail or the
            // annunciator strip.
            assert_eq!(modal.x, body.x + (body.width - modal.width) / 2);
            assert_eq!(modal.y, body.y + (body.height - modal.height) / 2);
            assert!(modal.x >= body.x && modal.bottom() <= body.bottom());
        }
        // The statusline layout keeps the full-frame center.
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        assert_eq!(modal_region(area), centered_rect(62, 11, area));
    }

    #[test]
    fn rail_observe_sheds_the_system_vector_as_the_canvas_narrows() {
        let _theme = theme::test_support::activate(theme::ThemeId::Avionics);
        let mut app = crowded_app();
        // Wide canvas: the vector keeps its 30-column berth. Even there the
        // 30-cell pane cannot hold the "threshold-relative" suffix, so the
        // title stops after the name instead of truncating mid-word.
        let layout = rail_overview_layout(regions(Rect::new(0, 0, 170, 48)).body);
        assert_eq!(layout.vector.expect("vector column").width, 30);
        let text = buffer_text(render_size(&mut app, 170, 48).buffer());
        assert!(text.contains("SYSTEM VECTOR"));
        assert!(!text.contains("threshold-relati"));
        // Canvas below 130: the column shrinks to 24 and the title drops its
        // suffix whole instead of truncating mid-word.
        let layout = rail_overview_layout(regions(Rect::new(0, 0, 120, 36)).body);
        assert_eq!(layout.vector.expect("vector column").width, 24);
        let text = buffer_text(render_size(&mut app, 120, 36).buffer());
        assert!(text.contains("SYSTEM VECTOR"));
        assert!(!text.contains("threshold"));
        // Canvas below 100: the column disappears and the map takes the
        // full width — the annunciator already carries CPU/MEM.
        let body = regions(Rect::new(0, 0, 100, 30)).body;
        let layout = rail_overview_layout(body);
        assert!(layout.vector.is_none());
        assert_eq!(layout.map.width, body.width - 2);
        let text = buffer_text(render_size(&mut app, 100, 30).buffer());
        assert!(!text.contains("SYSTEM VECTOR"));
        assert!(text.contains("PRESSURE MAP"));
    }

    #[test]
    fn incident_tape_drops_the_evidence_column_whole_when_narrow() {
        let _theme = theme::test_support::activate(theme::ThemeId::Avionics);
        let mut app = gallery_app();
        // Wide: the evidence column and its title suffix are present.
        let text = buffer_text(render_size(&mut app, 170, 48).buffer());
        assert!(text.contains("/ evidence"));
        assert!(text.contains(" :: "));
        // Narrow: the whole column goes, not a ":: sustained" stub.
        let text = buffer_text(render_size(&mut app, 100, 30).buffer());
        assert!(text.contains("INCIDENT TAPE"));
        assert!(!text.contains("/ evidence"));
        assert!(!text.contains("::"));
    }

    #[test]
    fn help_grid_wraps_with_a_hanging_indent_and_no_orphans() {
        // Continuation rows land at the description column, never at the key
        // column, and no row is cut mid-word.
        let lines = help_lines("x", "typed-PID termination request", 36);
        assert!(lines.len() > 1, "expected the description to wrap");
        // Badge is " x            " (15 cells) plus the two-cell gutter.
        let indent = " ".repeat(17);
        for line in &lines[1..] {
            let text = line
                .spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>();
            assert!(text.starts_with(&indent), "no hanging indent: {text:?}");
            assert!(!text.trim().is_empty());
        }
        for line in &lines {
            assert!(line.width() <= 36, "row exceeds the pane: {}", line.width());
        }
        // At ≥100 columns every description sits on one line.
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        app.page = Page::Help;
        let backend = render_size(&mut app, 100, 30);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("typed-PID termination request"));
        for orphan in ["required", "settings)", "avionics)"] {
            for y in 0..backend.buffer().area.height {
                let row = row_text(backend.buffer(), y);
                assert_ne!(row.trim(), orphan, "orphan row {orphan:?} at y={y}");
            }
        }
    }

    #[test]
    fn gallery_fixture_populates_lineage_and_finding_archive() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = gallery_app();
        app.page = Page::Tree;
        let text = buffer_text(render(&mut app).buffer());
        assert!(text.contains("LINEAGE MAP"));
        assert!(text.contains("codex.exe"));
        assert!(text.contains("└─"), "lineage branches must render");
        app.page = Page::Alerts;
        let text = buffer_text(render(&mut app).buffer());
        assert!(text.contains("FINDING ARCHIVE"));
        assert!(text.contains("ACTIVE"));
        assert!(text.contains("resolved"));
        assert!(text.contains("ack"));
        assert!(text.contains("i investigate"), "Findings footer hint");
    }

    #[test]
    fn avionics_profile_renders_the_rail_shell_in_its_own_palette() {
        let _theme = theme::test_support::activate(theme::ThemeId::Avionics);
        let avionics = theme::palette();
        let vitals_surface = Color::Rgb(10, 17, 13);
        let mut app = sample_app();
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        // Rail chrome: brand block and the eight stacked bezel page keys.
        assert!(text.contains("PCPULSE ▮ MFD"));
        for key in [
            "[1] OBS",
            "[2] HUNT",
            "[3] TREE",
            "[4] ALERT",
            "[5] TIME",
            "[6] ASK",
            "[7] TUNE",
            "[8] HELP",
        ] {
            assert!(text.contains(key), "missing bezel key {key}");
        }
        // Annunciator lamps: one per finding class plus the SYS catch-all.
        assert!(
            row_text(backend.buffer(), 0)
                .contains("CPU  MEM  IO  HANG  LAUNCH  AGENT  POOL  DPC  BUDGET  SYS")
        );
        // Rail status block absorbs the footer duties.
        assert!(text.contains("♥ LINKED"));
        assert!(text.contains("NORMAL"));
        // Observe is the spatial view: treemap centerpiece, vector strip,
        // and the findings strip — the tabular panes live on other pages.
        for label in [
            "PRESSURE MAP",
            "SYSTEM VECTOR",
            "INCIDENT TAPE",
            "LOAD COMPOSITION",
        ] {
            assert!(text.contains(label), "missing {label}");
        }
        assert!(!text.contains("SUSPECT MATRIX"));
        assert!(!text.contains("AGENT SWARM"));
        // The shell carries the amber-CRT palette, and no vitals cell leaks.
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .filter(|cell| cell.bg == avionics.surface)
                .count()
                > 100
        );
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .any(|cell| cell.fg == avionics.ok)
        );
        assert!(
            !backend
                .buffer()
                .content()
                .iter()
                .any(|cell| cell.bg == vitals_surface)
        );
    }

    #[test]
    fn other_pages_render_their_content_inside_the_rail_canvas() {
        let _theme = theme::test_support::activate(theme::ThemeId::Avionics);
        let mut app = sample_app();
        app.page = Page::Processes;
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("PROCESS SPECTRUM"));
        assert!(text.contains("[2] HUNT"));
    }

    #[test]
    fn annunciator_lamps_light_only_while_a_matching_finding_is_active() {
        let _theme = theme::test_support::activate(theme::ThemeId::Avionics);
        let mut app = sample_app();
        let area = Rect::new(0, 0, 150, 46);
        let strip = regions(area).header;

        let backend = render(&mut app);
        assert_eq!(lit_cells(backend.buffer(), strip, palette().warn), 0);
        assert_eq!(lit_cells(backend.buffer(), strip, palette().crit), 0);

        if let Some(snapshot) = app.snapshot.as_mut() {
            snapshot
                .active_alerts
                .push(sample_alert("sustainedCpu", Severity::Warning));
            // Kinds without a dedicated lamp light the SYS catch-all.
            snapshot
                .active_alerts
                .push(sample_alert("handleGrowth", Severity::Critical));
        }
        let backend = render(&mut app);
        assert!(lit_cells(backend.buffer(), strip, palette().warn) >= 3);
        assert!(lit_cells(backend.buffer(), strip, palette().crit) >= 3);
        // Lamp text renders dark on the lit severity color.
        let row = row_text(backend.buffer(), strip.y);
        assert!(row.contains("CPU"));
        assert!(row.contains("SYS"));
    }

    #[test]
    fn clicking_a_rail_bezel_key_switches_pages() {
        let _theme = theme::test_support::activate(theme::ThemeId::Avionics);
        let mut app = sample_app();
        let area = Rect::new(0, 0, 150, 46);
        let tabs = regions(area).tabs;
        assert!(handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: tabs.x + 2,
                row: tabs.y + 5,
                modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
            },
            area,
        ));
        assert_eq!(app.page, Page::Analyzer);
        // Rows below the eighth key are inert rail chrome.
        assert!(!handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: tabs.x + 2,
                row: tabs.y + 10,
                modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
            },
            area,
        ));
        assert_eq!(app.page, Page::Analyzer);
    }

    /// A snapshot with several distinct processes so the pressure map has a
    /// landscape to tile; kept out of `sample_app` so the vitals fixtures
    /// stay byte-identical.
    fn crowded_app() -> App {
        let mut app = sample_app();
        if let Some(snapshot) = app.snapshot.as_mut() {
            let base = snapshot.processes[0].clone();
            let mut chrome = base.clone();
            chrome.pid = 5100;
            chrome.name = "chrome.exe".into();
            chrome.cpu_percent = 3.0;
            chrome.working_set_bytes = 1536 * 1024 * 1024;
            chrome.read_bytes_per_sec = 0.0;
            chrome.write_bytes_per_sec = 0.0;
            chrome.is_agent_candidate = false;
            let mut indexer = base.clone();
            indexer.pid = 5200;
            indexer.name = "indexer.exe".into();
            indexer.cpu_percent = 1.0;
            indexer.working_set_bytes = 400 * 1024 * 1024;
            indexer.read_bytes_per_sec = 60.0 * 1024.0 * 1024.0;
            indexer.write_bytes_per_sec = 20.0 * 1024.0 * 1024.0;
            indexer.is_agent_candidate = false;
            snapshot.processes.push(chrome);
            snapshot.processes.push(indexer);
        }
        app
    }

    #[test]
    fn avionics_observe_is_a_process_pressure_treemap() {
        let _theme = theme::test_support::activate(theme::ThemeId::Avionics);
        let mut app = crowded_app();
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("PRESSURE MAP"));
        // Multiple process tiles carry their own names.
        assert!(text.contains("codex.exe"));
        assert!(text.contains("chrome.exe"));
        assert!(text.contains("indexer.exe"));
        // Agent candidates surface as AGT-badged tiles, not a swarm list.
        assert!(text.contains("AGT"));
        assert!(!text.contains("SUSPECT MATRIX"));
        assert!(!text.contains("AGENT SWARM"));
        // Findings are never hidden by the recomposition.
        assert!(text.contains("INCIDENT TAPE"));
        // Tile labels use exact channel colors so the bounded telemetry scan
        // shimmers them: codex is an agent candidate (warn channel) and
        // chrome is memory-dominant (alt channel).
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .any(|cell| cell.fg == palette().warn)
        );
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .any(|cell| cell.fg == palette().alt)
        );
    }

    #[test]
    fn clicking_a_pressure_tile_targets_the_process() {
        let _theme = theme::test_support::activate(theme::ThemeId::Avionics);
        let mut app = crowded_app();
        let area = Rect::new(0, 0, 150, 46);
        let body = regions(area).body;
        let canvas = pressure_map_canvas(rail_overview_layout(body).map);
        let (items, pids) = pressure_map_items(&app);
        let chrome = items
            .iter()
            .position(|item| item.label == "chrome.exe")
            .expect("chrome.exe must be on the map");
        assert_eq!(pids[chrome], 5100);
        let weights = items.iter().map(|item| item.weight).collect::<Vec<_>>();
        let tile = crate::treemap::layout(&weights, canvas)
            .into_iter()
            .find(|tile| tile.indices == vec![chrome])
            .expect("chrome.exe must own its own tile");
        assert!(handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: tile.rect.x + tile.rect.width / 2,
                row: tile.rect.y + tile.rect.height / 2,
                modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
            },
            area,
        ));
        assert_eq!(
            app.selected_process().map(|process| process.pid),
            Some(5100)
        );
        assert!(app.status.contains("chrome.exe"));
        // The re-render marks the targeted tile with the inverted label band.
        let backend = render(&mut app);
        assert!(buffer_text(backend.buffer()).contains("▌chrome.exe"));
    }

    fn sample_alert(kind: &str, severity: Severity) -> Alert {
        Alert {
            id: format!("{kind}-test"),
            kind: kind.into(),
            severity,
            first_seen_ms: 1_800_000_000_000,
            last_seen_ms: 1_800_000_000_000,
            process_id: Some(4242),
            process_name: Some("codex.exe".into()),
            title: "Sustained pressure".into(),
            explanation: "test fixture".into(),
            evidence: Vec::new(),
            recommendation: "observe".into(),
            acknowledged: false,
            occurrence_count: 1,
            resolved_at_ms: None,
        }
    }

    fn row_text(buffer: &Buffer, y: u16) -> String {
        let width = buffer.area.width;
        buffer
            .content()
            .iter()
            .skip(usize::from(y) * usize::from(width))
            .take(usize::from(width))
            .map(|cell| cell.symbol())
            .collect()
    }

    fn lit_cells(buffer: &Buffer, region: Rect, color: Color) -> usize {
        let width = usize::from(buffer.area.width);
        buffer
            .content()
            .iter()
            .enumerate()
            .filter(|(index, cell)| {
                let x = (index % width) as u16;
                let y = (index / width) as u16;
                point_in(region, (x, y)) && cell.bg == color
            })
            .count()
    }

    #[test]
    fn agent_focus_and_destructive_gate_have_unique_visual_states() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
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
                .filter(|cell| cell.bg == palette().alt)
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
                .any(|cell| cell.fg == palette().crit)
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

    /// A believable mixed workload so every page of the gallery has substance:
    /// browsers, agents, services, a hot suspect, live alerts, and history.
    fn gallery_app() -> App {
        let mut app = sample_app();
        let base = app.snapshot.as_ref().expect("snapshot").system.clone();
        let template = app.snapshot.as_ref().expect("snapshot").processes[0].clone();
        let roster: [(&str, f64, u64, bool); 14] = [
            ("firefox.exe", 6.4, 1_400, false),
            ("chrome.exe", 8.9, 1_900, false),
            ("claude.exe", 2.2, 640, true),
            ("dwm.exe", 1.8, 310, false),
            ("svchost.exe", 0.9, 240, false),
            ("WmiPrvSE.exe", 3.1, 150, false),
            ("Spotify.exe", 0.7, 480, false),
            ("msedgewebview2.exe", 0.4, 380, false),
            ("explorer.exe", 0.6, 350, false),
            ("node.exe", 4.8, 700, true),
            ("SearchIndexer.exe", 0.3, 210, false),
            ("RustDesk.exe", 0.1, 90, false),
            ("Discord.exe", 1.2, 520, false),
            ("HWiNFO64.EXE", 0.5, 120, false),
        ];
        {
            let snapshot = app.snapshot.as_mut().expect("snapshot");
            for (index, (name, cpu, mem_mb, agent)) in roster.iter().enumerate() {
                let mut process = template.clone();
                process.pid = 5_000 + index as u32 * 4;
                process.parent_pid = if *agent { 4242 } else { 1_000 };
                process.name = (*name).into();
                process.executable_path = format!(r"C:\apps\{name}");
                process.cpu_percent = *cpu;
                process.working_set_bytes = mem_mb * 1024 * 1024;
                process.private_bytes = process.working_set_bytes;
                process.is_agent_candidate = *agent;
                snapshot.processes.push(process);
            }
            snapshot.system.cpu_percent = 46.0;
            snapshot.active_alerts = vec![
                sample_alert("sustainedCpu", Severity::Critical),
                sample_alert("memoryGrowth", Severity::Warning),
                sample_alert("diskLatency", Severity::Info),
            ];
        }
        // LINEAGE and the FINDING ARCHIVE normally arrive via pipe fetches
        // (`WorkerEvent::Tree` / `WorkerEvent::Alerts`), so the fixture
        // mirrors them: a ProcessNode forest flattened depth-first exactly as
        // `App` does, and an alert archive spanning every lifecycle state.
        let processes = app.snapshot.as_ref().expect("snapshot").processes.clone();
        let by_name = |name: &str| {
            processes
                .iter()
                .find(|process| process.name == name)
                .unwrap_or_else(|| panic!("{name} missing from the roster"))
                .clone()
        };
        let forest = vec![
            ProcessNode {
                process: processes[0].clone(),
                children: vec![
                    ProcessNode {
                        process: by_name("claude.exe"),
                        children: Vec::new(),
                    },
                    ProcessNode {
                        process: by_name("node.exe"),
                        children: Vec::new(),
                    },
                ],
            },
            ProcessNode {
                process: by_name("explorer.exe"),
                children: vec![ProcessNode {
                    process: by_name("chrome.exe"),
                    children: Vec::new(),
                }],
            },
            ProcessNode {
                process: by_name("svchost.exe"),
                children: Vec::new(),
            },
        ];
        fn flatten(nodes: &[ProcessNode], depth: usize, rows: &mut Vec<TreeRow>) {
            for node in nodes {
                rows.push(TreeRow {
                    depth,
                    process: node.process.clone(),
                });
                flatten(&node.children, depth + 1, rows);
            }
        }
        flatten(&forest, 0, &mut app.tree);
        let mut resolved = sample_alert("memoryGrowth", Severity::Warning);
        resolved.title = "Working set growth".into();
        resolved.resolved_at_ms = Some(resolved.last_seen_ms + 60_000);
        let mut acknowledged = sample_alert("diskLatency", Severity::Info);
        acknowledged.title = "Disk latency drift".into();
        acknowledged.acknowledged = true;
        app.alerts = vec![
            sample_alert("sustainedCpu", Severity::Critical),
            resolved,
            acknowledged,
        ];
        // History must stay chronological (oldest first, ending at the
        // snapshot timestamp), matching the push_back invariant `App`
        // maintains for `live_history`.
        app.live_history.clear();
        for step in 0..180_i64 {
            let mut point = base.clone();
            point.timestamp_ms = base.timestamp_ms - (179 - step) * 10_000;
            let phase = step as f64 / 9.0;
            point.cpu_percent = 24.0 + 18.0 * phase.sin().abs() + (step % 7) as f64;
            point.memory_used_bytes = base.memory_used_bytes
                + ((phase * 0.5).sin().abs() * 6.0 * 1024.0 * 1024.0 * 1024.0) as u64;
            point.disk_latency_ms = 0.6 + 1.4 * (phase * 0.8).cos().abs();
            app.live_history.push_back(point.clone());
            app.persisted_history.system.push(point);
        }
        app.status = "Settings saved".into();
        app
    }

    fn css_color(color: Color, fallback: &str) -> String {
        match color {
            Color::Rgb(r, g, b) => format!("rgb({r},{g},{b})"),
            _ => fallback.to_string(),
        }
    }

    /// Serialize a rendered buffer to HTML, merging runs of identically
    /// styled cells so the gallery stays a reasonable size.
    fn buffer_html(buffer: &Buffer) -> String {
        let area = *buffer.area();
        let content = buffer.content();
        let mut html = String::from("<pre>");
        for y in 0..area.height {
            let mut run = String::new();
            let mut run_style: Option<(String, String, bool)> = None;
            let flush =
                |html: &mut String, style: &Option<(String, String, bool)>, run: &mut String| {
                    if let Some((fg, bg, bold)) = style
                        && !run.is_empty()
                    {
                        let weight = if *bold { ";font-weight:700" } else { "" };
                        html.push_str(&format!(
                            "<span style=\"color:{fg};background:{bg}{weight}\">{run}</span>"
                        ));
                    }
                    run.clear();
                };
            for x in 0..area.width {
                let cell = &content[(y as usize) * (area.width as usize) + x as usize];
                let style = (
                    css_color(cell.fg, "#c8d0d8"),
                    css_color(cell.bg, "#000"),
                    cell.modifier.contains(ratatui::style::Modifier::BOLD),
                );
                if run_style.as_ref() != Some(&style) {
                    flush(&mut html, &run_style, &mut run);
                    run_style = Some(style);
                }
                run.push_str(
                    &cell
                        .symbol()
                        .replace('&', "&amp;")
                        .replace('<', "&lt;")
                        .replace('>', "&gt;"),
                );
            }
            flush(&mut html, &run_style, &mut run);
            html.push('\n');
        }
        html.push_str("</pre>");
        html
    }

    #[test]
    #[ignore = "dev harness: set PCPULSE_GALLERY_DIR to write an HTML gallery of every page, profile, and size"]
    fn dev_render_gallery() {
        let Ok(directory) = std::env::var("PCPULSE_GALLERY_DIR") else {
            return;
        };
        let sizes: [(u16, u16); 4] = [(80, 24), (100, 30), (120, 36), (170, 48)];
        let mut html = String::from(
            "<!doctype html><meta charset=\"utf-8\"><style>\
             body{background:#111;color:#eee;font-family:monospace}\
             pre{font-family:'Cascadia Mono','Consolas',monospace;font-size:11px;\
             line-height:1.08;display:inline-block;border:1px solid #333;padding:2px;margin:2px 0}\
             h2{margin:28px 0 4px;color:#fc6}h3{margin:16px 0 2px;color:#9ad}\
             h4{margin:10px 0 2px;color:#8a8}</style>",
        );
        for theme_id in [theme::ThemeId::Vitals, theme::ThemeId::Avionics] {
            let _guard = theme::test_support::activate(theme_id);
            html.push_str(&format!("<h2 id=\"{theme_id:?}\">{theme_id:?}</h2>"));
            for (width, height) in sizes {
                html.push_str(&format!("<h3>{theme_id:?} {width}x{height}</h3>"));
                for page in Page::ALL {
                    let mut app = gallery_app();
                    app.page = page;
                    let backend = render_size(&mut app, width, height);
                    html.push_str(&format!("<h4>{theme_id:?} {page:?} {width}x{height}</h4>"));
                    html.push_str(&buffer_html(backend.buffer()));
                }
                let mut app = gallery_app();
                app.page = Page::Processes;
                app.mode = InputMode::ConfirmTerminate {
                    pid: 4242,
                    process_name: "codex.exe".into(),
                    typed: "42".into(),
                };
                let backend = render_size(&mut app, width, height);
                html.push_str(&format!("<h4>{theme_id:?} Modal {width}x{height}</h4>"));
                html.push_str(&buffer_html(backend.buffer()));
            }
        }
        std::fs::write(std::path::Path::new(&directory).join("gallery.html"), html)
            .expect("write gallery");
    }
}
