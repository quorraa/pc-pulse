use crate::{
    analyzer::ChatRole,
    app::{
        AlertSort, App, InputMode, Page, ProcessSort, SettingField, SettingSort, SuspectSort,
        TreeSort,
    },
    format,
    theme::{self, LayoutKind, palette},
};
use pcpulse_service::models::{
    Alert, HardwareMetrics, OptimizationPlan, PlanAction, PlanRisk, ProcessMetric, Severity,
    SystemMetric,
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

/// Broadsheet masthead: brand line, dateline, printed page index, double
/// rule. Folio: one thin rule plus the printed folio line.
const MASTHEAD_HEIGHT: u16 = 4;
const FOLIO_HEIGHT: u16 = 2;
/// Below this width the headline block digits lose more than they show, so
/// the front page degrades to plain numerals.
const HEADLINE_MIN_WIDTH: u16 = 100;

/// The rail column width when the avionics rail structure applies to this
/// terminal size, or `None` when the statusline shape is used instead.
fn rail_width(area: Rect) -> Option<u16> {
    (theme::active().layout == LayoutKind::Rail
        && area.width >= RAIL_MIN_WIDTH
        && area.height >= RAIL_MIN_HEIGHT)
        .then_some(RAIL_WIDTH)
}

/// True when the ledger broadsheet structure applies. Unlike the rail it has
/// no size floor: masthead + folio cost one row less than the statusline
/// chrome, so it holds at every supported terminal size.
fn broadsheet() -> bool {
    theme::active().layout == LayoutKind::Broadsheet
}

pub fn regions(area: Rect) -> UiRegions {
    if let Some(width) = rail_width(area) {
        return rail_regions(area, width);
    }
    if broadsheet() {
        return broadsheet_regions(area);
    }
    statusline_regions(area)
}

/// Ledger broadsheet shape: a full-width masthead on top (brand, dateline,
/// printed page index, double rule), the page body beneath, and a printed
/// folio line at the bottom. Region mapping for the effects layer:
/// `header` = the whole masthead, `tabs` = the masthead's page-index line,
/// `footer` = the folio block, `body` = the rest.
fn broadsheet_regions(area: Rect) -> UiRegions {
    let chunks = Layout::vertical([
        Constraint::Length(MASTHEAD_HEIGHT),
        Constraint::Min(12),
        Constraint::Length(FOLIO_HEIGHT),
    ])
    .split(area);
    let masthead = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(chunks[0]);
    UiRegions {
        full: area,
        header: chunks[0],
        tabs: masthead[2],
        body: chunks[1],
        footer: chunks[2],
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
    // The keys overlay owns the mouse exactly as it owns the keyboard:
    // the wheel scrolls it, any click dismisses it, nothing reaches the
    // page underneath.
    if let Some(scroll) = app.help_overlay {
        return match event.kind {
            MouseEventKind::ScrollUp => {
                app.help_overlay = Some(scroll.saturating_sub(3));
                true
            }
            MouseEventKind::ScrollDown => {
                app.help_overlay = Some(scroll.saturating_add(3));
                true
            }
            MouseEventKind::Down(_) => {
                app.help_overlay = None;
                true
            }
            _ => false,
        };
    }
    // The vault rename band owns input the same way: a click dismisses it
    // like Esc, and nothing reaches the page underneath.
    if app.vault_rename.is_some() {
        return match event.kind {
            MouseEventKind::Down(_) => {
                app.vault_rename = None;
                true
            }
            _ => false,
        };
    }
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
    } else if matches!(app.mode, InputMode::EditSetting { .. }) {
        // Clicking away from the edited value cancels the edit like Esc,
        // then the click acts normally (selecting another row re-enters
        // editing there). Clicking the row being edited keeps the edit.
        if let MouseEventKind::Down(MouseButton::Left) = event.kind {
            let point = (event.column, event.row);
            let table = inset(settings_regions(regions(area).body).0);
            let clicked_row = table_row_at(
                table,
                point,
                2,
                app.setting_state.offset(),
                app.visible_setting_fields().len(),
            );
            if clicked_row.is_some() && clicked_row == app.setting_state.selected() {
                return false;
            }
            app.mode = InputMode::Normal;
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
                } else if broadsheet() {
                    masthead_route_at(event.column, regions.tabs)
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
            if broadsheet() {
                // The front page is a printed sheet: headline digits and the
                // suspect ledger read, they do not click. Keyboard sorts
                // (`o` on HUNT, header clicks elsewhere) are unaffected.
                return false;
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
                app.register_vault_click(index);
                return true;
            }
            if point_in(inset(columns[0]), point) {
                app.mode = InputMode::Chat(String::new());
                return true;
            }
            false
        }
        Page::Settings if button == MouseButton::Left => {
            let table = inset(settings_regions(body).0);
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
    let broadsheet = !rail && broadsheet();
    let regions = regions(area);
    if rail {
        render_rail(frame, app, regions);
        render_annunciator(frame, app, regions.header);
    } else if broadsheet {
        render_masthead(frame, app, regions.header);
    } else {
        render_header(frame, app, regions.header);
    }
    match app.page {
        Page::Overview if rail => render_overview_rail(frame, app, regions.body),
        Page::Overview if broadsheet => render_overview_broadsheet(frame, app, regions.body),
        Page::Overview => render_overview(frame, app, regions.body),
        Page::Processes => render_processes(frame, app, regions.body),
        Page::Tree => render_tree(frame, app, regions.body),
        Page::Alerts => render_alerts(frame, app, regions.body),
        Page::Timeline => render_timeline(frame, app, regions.body),
        Page::Analyzer => render_analyzer(frame, app, regions.body),
        Page::Settings => render_settings(frame, app, regions.body),
        Page::Help => render_help(frame, regions.body),
        Page::Hardware => render_hardware(frame, app, regions.body),
    }
    if broadsheet {
        render_folio(frame, app, regions.footer);
    } else if !rail {
        render_footer(frame, app, regions.footer);
    }
    render_modal(frame, app);
    render_help_overlay(frame, app, regions.body);
}

/// The '?' overlay rect: a centered panel filling ~80% of the page body.
fn help_overlay_region(body: Rect) -> Rect {
    let width = (body.width * 4 / 5).clamp(40.min(body.width), body.width);
    let height = (body.height * 4 / 5).clamp(10.min(body.height), body.height);
    centered_rect(width, height, body)
}

/// The keys reference as a popup over whatever page is active: the same
/// content the Keys page shows, in one scrollable column, without leaving
/// the page. `j`/`k` or the wheel scroll it; Esc, `?`, or a click closes it.
fn render_help_overlay(frame: &mut Frame<'_>, app: &App, body: Rect) {
    let Some(scroll) = app.help_overlay else {
        return;
    };
    let area = help_overlay_region(body);
    frame.render_widget(Clear, area);
    let inner_width = area.width.saturating_sub(4);
    let mut lines = vec![Line::styled(
        "◈ NAVIGATION RUNES",
        Style::default().fg(palette().ok).bold(),
    )];
    for (key, description) in HELP_GLOBAL {
        lines.extend(help_lines(key, description, inner_width));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "◇ CONTEXT RITES",
        Style::default().fg(palette().alt).bold(),
    ));
    for (key, description) in HELP_CONTEXTUAL {
        lines.extend(help_lines(key, description, inner_width));
    }
    lines.push(Line::raw(""));
    for row in wrap_words(
        "PC Pulse never terminates a process automatically.",
        usize::from(inner_width).max(8),
    ) {
        lines.push(Line::styled(
            row,
            Style::default().fg(palette().warn).bold(),
        ));
    }
    let visible = area.height.saturating_sub(2);
    let max_scroll = (lines.len().min(u16::MAX as usize) as u16).saturating_sub(visible);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll.min(max_scroll), 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Double)
                    .border_style(Style::default().fg(palette().info))
                    .style(
                        Style::default()
                            .fg(palette().text)
                            .bg(palette().surface_raised),
                    )
                    .title(" ? KEYS · j/k scroll · Esc or ? close ")
                    .title_style(Style::default().fg(palette().info).bold())
                    .padding(Padding::horizontal(1)),
            ),
        area,
    );
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
                format!(" {:02}/{:02}", page_index(app.page) + 1, Page::ALL.len()),
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
            " EDITING ",
            Style::default().fg(palette().bg).bg(palette().warn).bold(),
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
                Page::Analyzer => "↵ ask e n h y",
                Page::Settings => "↵ edit s",
                Page::Help => "1–9 Tab",
                Page::Hardware => "r sample",
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
        Page::Hardware => "GAUGES",
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
        Page::Hardware => "GAUGE",
    }
}

fn route_description(page: Page) -> &'static str {
    match page {
        // "pressure map" is the avionics treemap's name; the vitals Observe
        // page centers on the PRESSURE FIELD chart instead.
        Page::Overview if theme::active().layout == LayoutKind::Rail => {
            "pressure map / likely culprits / live incidents"
        }
        Page::Overview if theme::active().layout == LayoutKind::Broadsheet => {
            "headline figures / suspect ledger / notices"
        }
        Page::Overview => "pressure field / likely culprits / live incidents",
        Page::Processes => "rank / filter / inspect process pressure",
        Page::Tree => "trace ownership through parent-child lineages",
        Page::Alerts => "explain sustained findings with evidence",
        Page::Timeline => "read persisted system pressure over time",
        Page::Analyzer => "question a systems analyst grounded in live evidence",
        Page::Settings => "shape baselines and sustained thresholds",
        Page::Help => "operate the console without leaving the keyboard",
        Page::Hardware => "watch temperatures and clocks, best-effort by sensor",
    }
}

fn page_index(page: Page) -> usize {
    Page::ALL
        .iter()
        .position(|candidate| *candidate == page)
        .unwrap_or_default()
}

// ---- Ledger broadsheet chrome ------------------------------------------
//
// The ledger profile draws no box borders anywhere: structure comes from
// typography. A full-width masthead (brand, dateline, printed page index,
// double rule) replaces the header, section headings are printed rules, and
// a folio line replaces the footer.

const LEDGER_BRAND: &str = "PC PULSE — WORKSTATION LEDGER";

/// One printed page-index entry: "3 LINEAGE" (or "3 TREE" when compact).
fn masthead_label(index: usize, page: Page, compact: bool) -> String {
    format!(
        "{} {}",
        index + 1,
        if compact {
            route_short(page)
        } else {
            route_name(page)
        }
    )
}

fn masthead_separator(compact: bool) -> &'static str {
    if compact { " " } else { " · " }
}

/// Where the centered page-index line begins, and whether it uses the
/// compact labels. Shared by the renderer and the mouse hit-test so the
/// printed index and its click targets can never drift apart.
fn masthead_index_origin(area: Rect) -> (u16, bool) {
    let compact = area.width < 112;
    let separator = masthead_separator(compact).chars().count();
    let total = Page::ALL
        .iter()
        .enumerate()
        .map(|(index, page)| masthead_label(index, *page, compact).chars().count())
        .sum::<usize>()
        + separator * (Page::ALL.len() - 1);
    let x = area.x + (usize::from(area.width).saturating_sub(total) / 2) as u16;
    (x, compact)
}

fn masthead_route_at(column: u16, area: Rect) -> Option<Page> {
    let (mut x, compact) = masthead_index_origin(area);
    let separator = masthead_separator(compact).chars().count() as u16;
    for (index, page) in Page::ALL.iter().copied().enumerate() {
        if index > 0 {
            x = x.saturating_add(separator);
        }
        let width = masthead_label(index, page, compact).chars().count() as u16;
        if column >= x && column < x.saturating_add(width) {
            return Some(page);
        }
        x = x.saturating_add(width);
    }
    None
}

fn render_masthead(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(Line::styled(
            LEDGER_BRAND,
            Style::default().fg(palette().text).bold(),
        ))
        .alignment(Alignment::Center)
        .style(Style::default().bg(palette().bg)),
        rows[0],
    );
    // Dateline: link state, telemetry sample, edition version, page name.
    let (link, link_color) = if app.connected {
        let etw = app
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.system.etw_active);
        (
            if etw { "LINKED / ETW" } else { "LINKED / ETW DEGRADED" },
            if etw { palette().ok } else { palette().warn },
        )
    } else {
        ("SIGNAL LOST", palette().crit)
    };
    let mut dateline = vec![Span::styled(link, Style::default().fg(link_color).bold())];
    if let Some(snapshot) = &app.snapshot {
        let memory = percent(
            snapshot.system.memory_used_bytes,
            snapshot.system.memory_total_bytes,
        );
        dateline.push(Span::styled(
            format!(
                " · CPU {:.1}% · MEM {memory:.1}% · {}P/{}T · v{}",
                snapshot.system.cpu_percent,
                snapshot.system.process_count,
                snapshot.system.thread_count,
                snapshot.service_version
            ),
            Style::default().fg(palette().muted),
        ));
    } else {
        dateline.push(Span::styled(
            " · awaiting first telemetry frame",
            Style::default().fg(palette().muted),
        ));
    }
    dateline.push(Span::styled(
        format!(
            " · PAGE {:02} — {}",
            page_index(app.page) + 1,
            route_name(app.page)
        ),
        Style::default().fg(palette().alt).bold(),
    ));
    frame.render_widget(
        Paragraph::new(Line::from(dateline))
            .alignment(Alignment::Center)
            .style(Style::default().bg(palette().bg)),
        rows[1],
    );
    render_masthead_index(frame, app, rows[2]);
    frame.render_widget(
        Paragraph::new(Line::styled(
            "═".repeat(usize::from(rows[3].width)),
            Style::default().fg(palette().border_hot),
        )),
        rows[3],
    );
}

/// The printed page index: every page as "N NAME", the active one inverted
/// like a rubber-stamped entry.
fn render_masthead_index(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let compact = area.width < 112;
    let mut spans = Vec::new();
    for (index, page) in Page::ALL.iter().copied().enumerate() {
        if index > 0 {
            spans.push(Span::styled(
                masthead_separator(compact),
                Style::default().fg(palette().faint),
            ));
        }
        let label = masthead_label(index, page, compact);
        spans.push(if page == app.page {
            Span::styled(
                label,
                Style::default().fg(palette().bg).bg(palette().text).bold(),
            )
        } else {
            Span::styled(label, Style::default().fg(palette().muted))
        });
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans))
            .alignment(Alignment::Center)
            .style(Style::default().bg(palette().bg)),
        area,
    );
}

/// The folio: one thin printed rule, then a single line carrying the page
/// number, contextual hints (or the live input band), and the status.
fn render_folio(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);
    frame.render_widget(
        Paragraph::new(Line::styled(
            "─".repeat(usize::from(rows[0].width)),
            Style::default().fg(palette().border),
        )),
        rows[0],
    );
    let mut spans = match &app.mode {
        InputMode::Normal => vec![
            Span::styled(
                format!(
                    " №{:02}/{:02} {}",
                    page_index(app.page) + 1,
                    Page::ALL.len(),
                    route_name(app.page)
                ),
                Style::default().fg(palette().alt).bold(),
            ),
            Span::styled(
                format!("  {}", page_hints(app.page)),
                Style::default().fg(palette().muted),
            ),
            Span::styled(
                "  ·  t profile · m motion · ? keys · q quit",
                Style::default().fg(palette().faint),
            ),
        ],
        InputMode::Search(value) => vec![
            Span::styled(" FILTER» ", Style::default().fg(palette().ok).bold()),
            Span::styled(value.clone(), Style::default().fg(palette().text).bold()),
            Span::styled("█", Style::default().fg(palette().ok)),
        ],
        InputMode::Chat(value) => vec![
            Span::styled(" ASK» ", Style::default().fg(palette().alt).bold()),
            Span::styled(value.clone(), Style::default().fg(palette().text).bold()),
            Span::styled("█", Style::default().fg(palette().alt)),
            Span::styled(
                "  Enter send · Esc cancel",
                Style::default().fg(palette().muted),
            ),
        ],
        InputMode::ConfirmTerminate { pid, typed, .. } => vec![
            Span::styled(
                format!(" TYPE PID {pid} TO CONFIRM» "),
                Style::default().fg(palette().crit).bold(),
            ),
            Span::styled(typed.clone(), Style::default().fg(palette().text).bold()),
            Span::styled("█", Style::default().fg(palette().crit)),
        ],
        InputMode::EditSetting { field, typed } => vec![
            Span::styled(" EDIT» ", Style::default().fg(palette().warn).bold()),
            Span::styled(
                format!("{}  ", field.label().to_ascii_uppercase()),
                Style::default().fg(palette().alt).bold(),
            ),
            Span::styled(typed.clone(), Style::default().fg(palette().text).bold()),
            Span::styled("█", Style::default().fg(palette().warn)),
            Span::styled(
                "  Enter apply · Esc cancel",
                Style::default().fg(palette().muted),
            ),
        ],
    };
    if !app.connected {
        spans.push(Span::styled(
            format!(
                "  — OFFLINE: {}",
                app.last_error.as_deref().unwrap_or("collector unavailable")
            ),
            Style::default().fg(palette().crit).bold(),
        ));
    } else if !app.status.is_empty() {
        spans.push(Span::styled(
            format!("  — {}", app.status),
            Style::default().fg(if app.status_is_error {
                palette().crit
            } else {
                palette().muted
            }),
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(palette().bg)),
        rows[1],
    );
}

/// 3-row block-digit glyphs (built from █ ▀ ▄ and space only) for the
/// broadsheet headline figures. Covers 0–9, the decimal point, and the
/// percent sign; anything else renders as a one-cell gap.
fn block_glyph(character: char) -> Option<[&'static str; 3]> {
    Some(match character {
        '0' => ["█▀█", "█ █", "▀▀▀"],
        '1' => ["▄█ ", " █ ", "▀▀▀"],
        '2' => ["▀▀█", "█▀▀", "▀▀▀"],
        '3' => ["▀▀█", " ▀█", "▀▀▀"],
        '4' => ["█ █", "▀▀█", "  █"],
        '5' => ["█▀▀", "▀▀█", "▀▀▀"],
        '6' => ["█▀▀", "█▀█", "▀▀▀"],
        '7' => ["▀▀█", "  █", "  █"],
        '8' => ["█▀█", "█▀█", "▀▀▀"],
        '9' => ["█▀█", "▀▀█", "▀▀▀"],
        '.' => [" ", " ", "▄"],
        '%' => ["▀ █", " █ ", "█ ▄"],
        _ => return None,
    })
}

/// Render `text` as three rows of block-digit glyphs joined by one-cell
/// gaps. Every returned row has the same display width.
fn block_digits(text: &str) -> [String; 3] {
    let mut rows = [String::new(), String::new(), String::new()];
    for (position, character) in text.chars().enumerate() {
        let glyph = block_glyph(character);
        for (row, line) in rows.iter_mut().enumerate() {
            if position > 0 {
                line.push(' ');
            }
            match glyph {
                Some(glyph) => line.push_str(glyph[row]),
                None => line.push(' '),
            }
        }
    }
    rows
}

/// Direction glyph for a headline figure: prior sample vs the current one.
fn headline_trend(previous: Option<f64>, current: f64, threshold: f64) -> &'static str {
    match previous {
        Some(previous) if current - previous > threshold => "▲",
        Some(previous) if previous - current > threshold => "▼",
        _ => "·",
    }
}

/// The Observe front page under the broadsheet layout: headline block-digit
/// figures across the top like a newspaper headline, then the SUSPECT LEDGER
/// and NOTICES columns separated by a thin printed rule, with the
/// CIRCULATION bar docked under the notices.
fn render_overview_broadsheet(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        render_offline(frame, app, area);
        return;
    };
    let canvas = area.inner(Margin::new(1, 0));
    let headline_height = if canvas.width >= HEADLINE_MIN_WIDTH { 5 } else { 2 };
    let vertical = Layout::vertical([Constraint::Length(headline_height), Constraint::Min(8)])
        .split(canvas);
    render_headline_figures(frame, app, vertical[0]);
    let columns = Layout::horizontal([
        Constraint::Percentage(56),
        Constraint::Length(1),
        Constraint::Min(30),
    ])
    .split(vertical[1]);
    render_suspect_matrix(frame, app, columns[0]);
    render_column_rule(frame, columns[1]);
    let right = Layout::vertical([Constraint::Min(6), Constraint::Length(4)]).split(columns[2]);
    render_notices(frame, app, right[0]);
    render_circulation(frame, app, right[1]);
    let _ = snapshot;
}

/// A thin vertical printed rule between broadsheet columns.
fn render_column_rule(frame: &mut Frame<'_>, area: Rect) {
    let lines = (0..area.height)
        .map(|_| Line::styled("│", Style::default().fg(palette().border)))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

/// CPU %, MEM %, and DISK ms as headline block digits, each with a caption
/// and a trend arrow; below [`HEADLINE_MIN_WIDTH`] columns the figures
/// degrade to one plain-numeral line.
fn render_headline_figures(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        return;
    };
    let memory = percent(
        snapshot.system.memory_used_bytes,
        snapshot.system.memory_total_bytes,
    );
    let previous = app.live_history.iter().rev().nth(1);
    let figures: [(&str, String, &'static str, Color); 3] = [
        (
            "CPU LOAD %",
            format!("{:.0}", snapshot.system.cpu_percent),
            headline_trend(
                previous.map(|point| point.cpu_percent),
                snapshot.system.cpu_percent,
                0.5,
            ),
            palette().ok,
        ),
        (
            "MEMORY %",
            format!("{memory:.0}"),
            headline_trend(
                previous.map(|point| percent(point.memory_used_bytes, point.memory_total_bytes)),
                memory,
                0.5,
            ),
            palette().alt,
        ),
        (
            "DISK MS",
            format!("{:.1}", snapshot.system.disk_latency_ms),
            headline_trend(
                previous.map(|point| point.disk_latency_ms),
                snapshot.system.disk_latency_ms,
                0.2,
            ),
            palette().warn,
        ),
    ];
    if area.width < HEADLINE_MIN_WIDTH {
        // Plain numerals: the whole headline on one bold line.
        let mut spans = Vec::new();
        for (index, (caption, value, trend, accent)) in figures.iter().enumerate() {
            if index > 0 {
                spans.push(Span::styled("   ", Style::default()));
            }
            let (label, unit) = match *caption {
                "MEMORY %" => ("MEM", "%"),
                "DISK MS" => ("DISK", " ms"),
                _ => ("CPU", "%"),
            };
            spans.push(Span::styled(
                format!("{label} {value}{unit}"),
                Style::default().fg(palette().text).bold(),
            ));
            spans.push(Span::styled(
                format!(" {trend}"),
                Style::default().fg(*accent).bold(),
            ));
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)).style(Style::default().bg(palette().bg)),
            area,
        );
        return;
    }
    let columns = Layout::horizontal([
        Constraint::Percentage(33),
        Constraint::Percentage(34),
        Constraint::Percentage(33),
    ])
    .split(area);
    for (column, (caption, value, trend, accent)) in columns.iter().zip(figures) {
        let digits = block_digits(&value);
        let mut lines = digits
            .iter()
            .map(|row| Line::styled(row.clone(), Style::default().fg(palette().text).bold()))
            .collect::<Vec<_>>();
        lines.push(Line::from(vec![
            Span::styled(caption, Style::default().fg(palette().muted)),
            Span::styled(format!("  {trend}"), Style::default().fg(accent).bold()),
        ]));
        frame.render_widget(
            Paragraph::new(lines)
                .alignment(Alignment::Center)
                .style(Style::default().bg(palette().bg)),
            *column,
        );
    }
}

/// Printed severity tag for the NOTICES column — typographic, no badge bg.
fn severity_tag(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "[NOTICE]",
        Severity::Warning => "[WARNING]",
        Severity::Critical => "[CRITICAL]",
    }
}

/// The incident tape restyled as classified-ads entries: a printed severity
/// tag, the owner, the condition, and one indented evidence line each.
fn render_notices(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        return;
    };
    let block = field_block(" NOTICES — sustained findings ", palette().warn);
    let capacity = (usize::from(area.height.saturating_sub(1)) / 2).max(1);
    let mut lines = Vec::new();
    for alert in snapshot.active_alerts.iter().take(capacity) {
        let owner = alert.process_name.as_deref().unwrap_or("system / driver");
        lines.push(Line::from(vec![
            Span::styled(
                severity_tag(alert.severity),
                Style::default().fg(severity_color(alert.severity)).bold(),
            ),
            Span::styled(
                format!(" {}", format::truncate(owner, 22)),
                Style::default().fg(palette().text).bold(),
            ),
            Span::styled(
                format!(" — {}", format::truncate(&alert.title, 34)),
                Style::default().fg(severity_color(alert.severity)),
            ),
        ]));
        let evidence = alert
            .evidence
            .first()
            .map(|item| format!("{} {}", item.label, item.value))
            .unwrap_or_else(|| "sustained condition confirmed".into());
        lines.push(Line::styled(
            format!("   {}", format::truncate(&evidence, 52)),
            Style::default().fg(palette().muted),
        ));
    }
    if lines.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("NO NOTICES", Style::default().fg(palette().ok).bold()),
            Span::styled(
                " — no sustained deviations in the active window",
                Style::default().fg(palette().muted),
            ),
        ]));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(block),
        area,
    );
}

/// The load ribbon as a thin "circulation" bar: one proportional row of the
/// busiest suspects' share of busy CPU, with the busy/idle tally beneath.
fn render_circulation(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        return;
    };
    let busy = snapshot.system.cpu_percent.clamp(0.0, 100.0);
    let block = field_block(" CIRCULATION — share of busy cpu ", palette().info);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines = Vec::new();
    if busy < DONUT_QUIESCENT_CPU {
        lines.push(Line::styled(
            format!("cpu quiescent {busy:.1}% — nothing to attribute"),
            Style::default().fg(palette().muted),
        ));
    } else {
        let mut suspects = snapshot
            .processes
            .iter()
            .filter(|process| process.pid > 4)
            .collect::<Vec<_>>();
        suspects.sort_by(|left, right| right.cpu_percent.total_cmp(&left.cpu_percent));
        let cycle = [palette().ok, palette().alt, palette().info, palette().warn];
        let mut segments = suspects
            .iter()
            .take(4)
            .enumerate()
            .map(|(index, process)| (process.cpu_percent.max(0.0), cycle[index % cycle.len()]))
            .collect::<Vec<_>>();
        let named = segments.iter().map(|(value, _)| *value).sum::<f64>();
        segments.push(((busy - named).max(0.0), palette().muted));
        let total = segments
            .iter()
            .map(|(value, _)| *value)
            .sum::<f64>()
            .max(f64::MIN_POSITIVE);
        let width = usize::from(inner.width.max(1));
        let mut spans = Vec::new();
        let mut used = 0usize;
        for (value, color) in &segments {
            if *value <= 0.0 || used >= width {
                continue;
            }
            let cells = (((value / total) * width as f64).round() as usize).clamp(1, width - used);
            spans.push(Span::styled(
                "█".repeat(cells),
                Style::default().fg(*color),
            ));
            used += cells;
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(vec![
        Span::styled(
            format!("busy {busy:.1}%"),
            Style::default().fg(palette().ok),
        ),
        Span::styled(
            format!(" · idle {:.1}%", 100.0 - busy),
            Style::default().fg(palette().faint),
        ),
    ]));
    frame.render_widget(
        Paragraph::new(lines).style(Style::default().fg(palette().text).bg(palette().surface)),
        inner,
    );
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
                if broadsheet() {
                    " SUSPECT LEDGER — relative pressure / not an alert score "
                } else {
                    " ⌖ SUSPECT MATRIX  relative pressure / not an alert score "
                },
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
        // Network has no detector threshold of its own; the I/O rate limit
        // is the panel's reference scale so the NET meter reads in the same
        // threshold-relative grammar as the I/O row above it.
        vector_line(
            "NET",
            system.network_bytes_per_sec
                / (app.settings.io_mb_per_sec.max(1.0) * 1024.0 * 1024.0),
            format::rate(system.network_bytes_per_sec),
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
        spans.push(Span::styled(
            "   R/W ",
            Style::default().fg(palette().faint),
        ));
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
            spans.push(Span::styled(
                stats_full,
                Style::default().fg(palette().muted),
            ));
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
    if broadsheet() {
        // A printed section rule with a spaced heading — never a box.
        return Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(palette().border))
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .title(title)
            .title_style(Style::default().fg(accent).bold());
    }
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
            Row::new(header_cells)
                .style(
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
            Row::new(header_cells)
                .style(
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
    let title = if app.vault_rename.is_some() {
        " ◇ CHAT VAULT · ✎ rename "
    } else if app.chat_history_focused {
        " ◇ CHAT VAULT "
    } else {
        " ◇ CHAT VAULT · h focus · n new "
    };
    let mut block = accent_panel(title, accent);
    if let Some(typed) = &app.vault_rename {
        // Inline rename band, pinned to the panel's bottom edge next to the
        // selected row — the same edit-band grammar as the TUNE editor.
        block = block.title_bottom(Line::from(vec![
            Span::styled(
                " ✎ ",
                Style::default().fg(palette().bg).bg(palette().warn).bold(),
            ),
            Span::styled(
                format!(" {typed}"),
                Style::default().fg(palette().text).bold(),
            ),
            Span::styled("█", Style::default().fg(palette().warn)),
            Span::styled(" ↵ apply · Esc ", Style::default().fg(palette().muted)),
        ]));
    } else if app.chat_history_focused {
        block = block.title_bottom(Line::styled(
            " ↵ restore · r rename · d delete ",
            Style::default().fg(palette().muted),
        ));
    }
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
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

/// What the analyzer wait line claims to be doing right now. The phases stay
/// honest about the pipeline: evidence is collected first, then correlated
/// into the bundle, then the model is consulted for the rest of the run.
/// `Writing` exists for the final compose step, but its start is not knowable
/// client-side, so [`analyzer_phase`] keeps `Consulting` as the terminal
/// loop and `Writing` stays available to callers that do know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyzerPhase {
    Reading,
    Correlating,
    Consulting,
    Writing,
}

const READING_PHRASE: &str = "reading fresh evidence: samples, findings, and event logs…";
const CORRELATING_PHRASE: &str = "correlating processes, incidents, baselines, and event logs…";
const CONSULTING_PHRASE: &str = "consulting the analyst over your Codex session…";
const WRITING_PHRASE: &str = "writing the validated answer…";

/// Bright scanner window width (chars) and sweep step for the reading phase.
const SCANNER_WINDOW: usize = 4;
const SCANNER_STEP_MS: u64 = 150;
/// One correlating segment holds its pulse for this long.
const PULSE_BEAT_MS: u64 = 600;
/// Full muted→bright→muted breath while consulting.
const BREATH_PERIOD_MS: u64 = 2400;
/// Typewriter cadence and the full-reveal pause (in character steps).
const TYPE_STEP_MS: u64 = 90;
const TYPE_HOLD_STEPS: u64 = 14;

/// The wait-line phase for a given elapsed time. Purely elapsed-driven: the
/// evidence bundle is built during the first seconds, correlated next, and
/// the model consult dominates the remainder of the budget.
pub fn analyzer_phase(elapsed_ms: u64) -> AnalyzerPhase {
    match elapsed_ms {
        0..3_000 => AnalyzerPhase::Reading,
        3_000..8_000 => AnalyzerPhase::Correlating,
        _ => AnalyzerPhase::Consulting,
    }
}

/// The animated wait-line body: pure function of phase, elapsed milliseconds,
/// the timeout budget (consulting ticker only), and the columns available for
/// the phrase. Every frame keeps the phrase legible — only the typewriter's
/// not-yet-revealed tail is hidden — and derives deterministically from
/// `elapsed_ms`, so tests can assert exact frames.
pub fn analyzer_pending_spans(
    phase: AnalyzerPhase,
    elapsed_ms: u64,
    budget_secs: u64,
    width: u16,
) -> Vec<Span<'static>> {
    match phase {
        AnalyzerPhase::Reading => scanner_spans(READING_PHRASE, elapsed_ms, width),
        AnalyzerPhase::Correlating => pulse_spans(CORRELATING_PHRASE, elapsed_ms, width),
        AnalyzerPhase::Consulting => {
            breathing_spans(CONSULTING_PHRASE, elapsed_ms, budget_secs, width)
        }
        AnalyzerPhase::Writing => typewriter_spans(WRITING_PHRASE, elapsed_ms, width),
    }
}

/// The phrase, bounded to the pane so the animation reads on one row.
fn fit_phrase(phrase: &str, width: u16) -> Vec<char> {
    format::truncate(phrase, usize::from(width).max(12))
        .chars()
        .collect()
}

/// Group consecutive same-styled characters into spans.
fn styled_runs(chars: &[char], style_at: impl Fn(usize) -> Style) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut run = String::new();
    let mut current: Option<Style> = None;
    for (index, character) in chars.iter().enumerate() {
        let style = style_at(index);
        if current != Some(style) {
            if let Some(style) = current.take()
                && !run.is_empty()
            {
                spans.push(Span::styled(std::mem::take(&mut run), style));
            }
            current = Some(style);
        }
        run.push(*character);
    }
    if let Some(style) = current
        && !run.is_empty()
    {
        spans.push(Span::styled(run, style));
    }
    spans
}

/// Reading: a 4-char bright window sweeps left-to-right across the phrase —
/// a scanner passing over the evidence. Outside the window the words stay
/// muted but fully readable.
fn scanner_spans(phrase: &str, elapsed_ms: u64, width: u16) -> Vec<Span<'static>> {
    let chars = fit_phrase(phrase, width);
    let period = (chars.len() + SCANNER_WINDOW).max(1) as u64;
    let head = ((elapsed_ms / SCANNER_STEP_MS) % period) as usize;
    styled_runs(&chars, |index| {
        if index < head && index + SCANNER_WINDOW >= head {
            Style::default().fg(palette().info).bold()
        } else {
            Style::default().fg(palette().muted)
        }
    })
}

/// Correlating: the comma-separated evidence sources take turns holding a
/// bold ok-colored beat while the rest stay muted — cross-referencing.
fn pulse_spans(phrase: &str, elapsed_ms: u64, width: u16) -> Vec<Span<'static>> {
    let text: String = fit_phrase(phrase, width).into_iter().collect();
    let segments: Vec<&str> = text.split(", ").collect();
    let active = ((elapsed_ms / PULSE_BEAT_MS) as usize) % segments.len().max(1);
    let mut spans = Vec::new();
    for (index, segment) in segments.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(
                ", ".to_string(),
                Style::default().fg(palette().muted),
            ));
        }
        let style = if index == active {
            Style::default().fg(palette().ok).bold()
        } else {
            Style::default().fg(palette().muted)
        };
        spans.push(Span::styled((*segment).to_string(), style));
    }
    spans
}

/// Blend two palette RGB colors; `level` 0 is `from`, 1 is `to`.
fn mix_rgb(from: Color, to: Color, level: f64) -> Color {
    let level = level.clamp(0.0, 1.0);
    match (from, to) {
        (Color::Rgb(r0, g0, b0), Color::Rgb(r1, g1, b1)) => {
            let mix =
                |a: u8, b: u8| (f64::from(a) + (f64::from(b) - f64::from(a)) * level).round() as u8;
            Color::Rgb(mix(r0, r1), mix(g0, g1), mix(b0, b1))
        }
        _ => to,
    }
}

/// Consulting: the whole phrase breathes between muted and full text
/// brightness on a cosine ease, with the elapsed/budget ticker beside it —
/// the slow wait on the model, clock in view.
fn breathing_spans(
    phrase: &str,
    elapsed_ms: u64,
    budget_secs: u64,
    width: u16,
) -> Vec<Span<'static>> {
    let text: String = fit_phrase(phrase, width).into_iter().collect();
    let turn = (elapsed_ms % BREATH_PERIOD_MS) as f64 / BREATH_PERIOD_MS as f64;
    let level = 0.5 - 0.5 * (turn * std::f64::consts::TAU).cos();
    let elapsed_secs = elapsed_ms / 1_000;
    vec![
        Span::styled(
            text,
            Style::default().fg(mix_rgb(palette().muted, palette().text, level)),
        ),
        Span::styled(
            format!(
                " · {}m{}s / {}m{}s",
                elapsed_secs / 60,
                elapsed_secs % 60,
                budget_secs / 60,
                budget_secs % 60
            ),
            Style::default().fg(palette().faint),
        ),
    ]
}

/// Writing: characters reveal progressively behind a block caret; revealed
/// text is fully readable, only the not-yet-revealed tail is hidden. Loops
/// after a pause at full reveal.
fn typewriter_spans(phrase: &str, elapsed_ms: u64, width: u16) -> Vec<Span<'static>> {
    let chars = fit_phrase(phrase, width);
    let cycle = (chars.len() as u64 + TYPE_HOLD_STEPS).max(1);
    let revealed = (((elapsed_ms / TYPE_STEP_MS) % cycle) as usize).min(chars.len());
    let mut spans = Vec::new();
    if revealed > 0 {
        spans.push(Span::styled(
            chars[..revealed].iter().collect::<String>(),
            Style::default().fg(palette().text),
        ));
    }
    if revealed < chars.len() {
        spans.push(Span::styled(
            "▌".to_string(),
            Style::default().fg(palette().info).bold(),
        ));
    }
    spans
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
        // The wait line mimics the pipeline phase it is in; every frame is a
        // pure function of the elapsed time, redrawn by the main loop's
        // ~4 fps analyzer repaint. The ANALYST badge itself stays static.
        let elapsed_ms = app.analyzer_elapsed_ms().unwrap_or(0);
        let budget_secs = app.analyzer_progress().map_or(0, |(_, budget)| budget);
        let mut pending = vec![
            Span::styled(
                " ANALYST ",
                Style::default().fg(palette().bg).bg(palette().warn).bold(),
            ),
            Span::styled("  ░ ", Style::default().fg(palette().warn)),
        ];
        pending.extend(analyzer_pending_spans(
            analyzer_phase(elapsed_ms),
            elapsed_ms,
            budget_secs,
            area.width.saturating_sub(16),
        ));
        lines.push(Line::from(pending));
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
                    Line::styled(
                        format_axis_ms(latency_mid),
                        Style::default().fg(palette().muted),
                    ),
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

/// GAUGES temperature scale: every thermal meter spans 45–95°C so zones
/// and GPUs read against the same ruler.
const TEMP_METER_FLOOR_C: f64 = 45.0;
const TEMP_METER_CEIL_C: f64 = 95.0;

/// Where a temperature sits on the shared 45–95°C meter scale.
fn temperature_ratio(celsius: f64) -> f64 {
    ((celsius - TEMP_METER_FLOOR_C) / (TEMP_METER_CEIL_C - TEMP_METER_FLOOR_C)).clamp(0.0, 1.0)
}

/// [`ratio_color`]'s ok/warn/crit semantics applied to the 45–95°C span:
/// ok below ~60°C, warn to ~80°C, crit above.
fn temperature_color(celsius: f64) -> Color {
    if celsius >= 80.0 {
        palette().crit
    } else if celsius >= 60.0 {
        palette().warn
    } else {
        palette().ok
    }
}

/// A one-row block sparkline of a trace's most recent points on the shared
/// 45–95°C scale.
fn temperature_spark(points: &std::collections::VecDeque<f64>, width: usize) -> String {
    const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let skip = points.len().saturating_sub(width);
    points
        .iter()
        .skip(skip)
        .map(|value| LEVELS[((temperature_ratio(*value) * 7.0).round() as usize).min(7)])
        .collect()
}

/// Every temperature source on the GAUGES page, zones first then GPUs, in
/// the same order the sparkline traces are recorded.
fn hardware_temperature_sources(hardware: &HardwareMetrics) -> Vec<(&str, f64)> {
    hardware
        .thermal_zones
        .iter()
        .map(|zone| (zone.name.as_str(), zone.temperature_c))
        .chain(hardware.gpus.iter().filter_map(|gpu| {
            gpu.temperature_c
                .map(|temperature| (gpu.name.as_str(), temperature))
        }))
        .collect()
}

fn render_hardware(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        render_offline(frame, app, area);
        return;
    };
    let hardware = &snapshot.hardware;
    if !hardware.available {
        render_hardware_unavailable(frame, hardware, area);
        return;
    }
    let rows =
        Layout::vertical([Constraint::Percentage(58), Constraint::Percentage(42)]).split(area);
    render_thermal_panel(frame, app, hardware, inset(rows[0]));
    render_clock_panel(frame, hardware, inset(rows[1]));
}

/// The honest empty state: no source produced data, so the page says why
/// instead of drawing meters full of fabricated zeros.
fn render_hardware_unavailable(frame: &mut Frame<'_>, hardware: &HardwareMetrics, area: Rect) {
    let host = area.inner(Margin::new(4, 2));
    let width = usize::from(host.width.saturating_sub(6)).max(16);
    let mut lines = vec![
        Line::styled(
            "◌  HARDWARE TELEMETRY UNAVAILABLE",
            Style::default().fg(palette().warn).bold(),
        ),
        Line::raw(""),
    ];
    let detail = if hardware.detail.is_empty() {
        "the collector reported no temperature or clock sources"
    } else {
        hardware.detail.as_str()
    };
    for row in wrap_words(detail, width) {
        lines.push(Line::styled(row, Style::default().fg(palette().text)));
    }
    lines.push(Line::raw(""));
    for row in wrap_words(
        "Temperatures may require the installed LocalSystem collector service — \
         a console-mode collector often lacks ACPI thermal access.",
        width,
    ) {
        lines.push(Line::styled(row, Style::default().fg(palette().muted)));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .block(accent_panel(" ◉ GAUGES ", palette().warn)),
        host,
    );
}

/// One row per thermal zone and GPU: name, a 45–95°C meter, the reading,
/// and the recent history sparkline from the client-side trace buffer.
fn render_thermal_panel(frame: &mut Frame<'_>, app: &App, hardware: &HardwareMetrics, area: Rect) {
    let sources = hardware_temperature_sources(hardware);
    let content = usize::from(area.width.saturating_sub(3));
    // Label + meter + reading are the identity columns; the sparkline takes
    // whatever honest width remains and disappears before it would clip.
    let meter_width = content.saturating_sub(20 + 9 + 3).clamp(8, 22);
    let spark_width = content
        .saturating_sub(20 + meter_width + 9 + 3)
        .min(usize::from(LIVE_SPARK_MAX));
    let mut lines = Vec::new();
    if sources.is_empty() {
        lines.push(Line::styled(
            " no temperature sources reported",
            Style::default().fg(palette().muted),
        ));
    }
    let capacity = usize::from(area.height.saturating_sub(3)).max(1);
    for (name, temperature) in sources.iter().take(capacity) {
        let color = temperature_color(*temperature);
        let mut spans = vec![
            Span::styled(
                format!(" {:<19}", format::truncate(name, 18)),
                Style::default().fg(palette().text).bold(),
            ),
            Span::styled(
                meter(temperature_ratio(*temperature), meter_width),
                Style::default().fg(color),
            ),
            Span::styled(
                format!(" {temperature:>5.1}°C"),
                Style::default().fg(color).bold(),
            ),
        ];
        if spark_width >= 4
            && let Some(trace) = app
                .hardware_history
                .iter()
                .find(|trace| trace.label == *name)
        {
            spans.push(Span::styled(
                format!("  {}", temperature_spark(&trace.points, spark_width - 2)),
                Style::default().fg(color),
            ));
        }
        lines.push(Line::from(spans));
    }
    if !hardware.detail.is_empty() {
        lines.push(Line::styled(
            format!(
                " ◌ {}",
                format::truncate(&hardware.detail, content.max(8) - 3)
            ),
            Style::default().fg(palette().faint),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(accent_panel(
                " ◉ THERMALS · meters span 45–95°C ",
                palette().warn,
            )),
        area,
    );
}

/// Sparkline cap: matches the bounded trace so a wide terminal never asks
/// for more history than the buffer holds.
const LIVE_SPARK_MAX: u16 = 60;

/// CPU effective MHz plus per-GPU core/memory clocks and utilization.
fn render_clock_panel(frame: &mut Frame<'_>, hardware: &HardwareMetrics, area: Rect) {
    let mut lines = Vec::new();
    match hardware.cpu_frequency_mhz {
        Some(frequency) => lines.push(Line::from(vec![
            Span::styled(" CPU  ", Style::default().fg(palette().muted).bold()),
            Span::styled(
                format!("{frequency:>6.0} MHz"),
                Style::default().fg(palette().ok).bold(),
            ),
            Span::styled(
                "  effective (base × performance)",
                Style::default().fg(palette().faint),
            ),
        ])),
        None => lines.push(Line::from(vec![
            Span::styled(" CPU  ", Style::default().fg(palette().muted).bold()),
            Span::styled(
                "frequency counter unavailable",
                Style::default().fg(palette().faint),
            ),
        ])),
    }
    let content = usize::from(area.width.saturating_sub(3));
    let util_meter_width = content.saturating_sub(14).clamp(6, 16);
    for gpu in &hardware.gpus {
        lines.push(Line::styled(
            format!(" {}", format::truncate(&gpu.name, content.max(2) - 1)),
            Style::default().fg(palette().alt).bold(),
        ));
        let clock = |value: Option<f64>| match value {
            Some(mhz) => format!("{mhz:>6.0} MHz"),
            None => "     —    ".into(),
        };
        lines.push(Line::from(vec![
            Span::styled("   CORE ", Style::default().fg(palette().muted)),
            Span::styled(
                clock(gpu.core_clock_mhz),
                Style::default().fg(palette().info).bold(),
            ),
            Span::styled("   MEM ", Style::default().fg(palette().muted)),
            Span::styled(
                clock(gpu.memory_clock_mhz),
                Style::default().fg(palette().info).bold(),
            ),
        ]));
        if let Some(utilization) = gpu.utilization_percent {
            let ratio = (utilization / 100.0).clamp(0.0, 1.0);
            lines.push(Line::from(vec![
                Span::styled("   UTIL ", Style::default().fg(palette().muted)),
                Span::styled(
                    meter(ratio, util_meter_width),
                    Style::default().fg(ratio_color(ratio)),
                ),
                Span::styled(
                    format!(" {utilization:>3.0}%"),
                    Style::default().fg(ratio_color(ratio)).bold(),
                ),
            ]));
        }
    }
    if hardware.gpus.is_empty() {
        lines.push(Line::styled(
            " no GPU telemetry (NVML unavailable or no NVIDIA adapter)",
            Style::default().fg(palette().muted),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .block(accent_panel(
                " ⌁ CLOCKS · sampled every 5s ",
                palette().info,
            )),
        area,
    );
}

/// TUNE body split: the settings table above, the plain-language detail
/// strip below. Shared with the mouse hit-tests so clicks in the strip can
/// never masquerade as table rows.
fn settings_regions(body: Rect) -> (Rect, Rect) {
    let sections = Layout::vertical([Constraint::Min(8), Constraint::Length(5)]).split(body);
    (sections[0], sections[1])
}

fn render_settings(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let editing = match &app.mode {
        InputMode::EditSetting { field, typed } => Some((*field, typed.clone())),
        _ => None,
    };
    let (table_area, detail_area) = settings_regions(area);
    let rows = app
        .visible_setting_fields()
        .into_iter()
        .enumerate()
        .map(|(index, field)| {
            let is_edited = editing.as_ref().is_some_and(|(edited, _)| *edited == field);
            // While one row is being edited, the rest recede so the eye
            // lands on the input band.
            let dimmed = editing.is_some() && !is_edited;
            let (marker, marker_color) = if field.is_client() {
                ("◆ ", palette().info)
            } else {
                ("◇ ", palette().alt)
            };
            let text_color = if dimmed {
                palette().faint
            } else {
                palette().text
            };
            let value_cell = if let (true, Some((_, typed))) = (is_edited, editing.as_ref()) {
                Cell::from(Line::from(vec![
                    Span::styled(
                        format!(" {typed}"),
                        Style::default()
                            .fg(palette().text)
                            .bg(palette().select_bg)
                            .bold(),
                    ),
                    Span::styled(
                        "▏",
                        Style::default()
                            .fg(palette().warn)
                            .bg(palette().select_bg)
                            .bold(),
                    ),
                ]))
            } else {
                Cell::from(app.setting_value(field)).style(Style::default().fg(if dimmed {
                    palette().faint
                } else {
                    palette().ok
                }))
            };
            Row::new([
                Cell::from(Line::from(vec![
                    Span::styled(
                        marker,
                        Style::default().fg(if dimmed {
                            palette().faint
                        } else {
                            marker_color
                        }),
                    ),
                    Span::styled(field.label(), Style::default().fg(text_color)),
                ])),
                value_cell,
                Cell::from(field.unit()).style(Style::default().fg(if dimmed {
                    palette().faint
                } else {
                    palette().muted
                })),
            ])
            .style(Style::default().bg(if index.is_multiple_of(2) {
                palette().surface
            } else {
                palette().surface_raised
            }))
        })
        .collect::<Vec<_>>();
    let (title, accent) = if editing.is_some() {
        (
            " ⚙ DETECTOR MATRIX · ✎ EDITING · Enter apply · Esc cancel ",
            palette().warn,
        )
    } else if app.settings_dirty {
        (
            " ⚙ DETECTOR MATRIX · UNSAVED CHANGES · Enter edit · s save · r discard/reload ",
            palette().warn,
        )
    } else {
        (
            " ⚙ DETECTOR MATRIX · Enter edit · s save · r reload ",
            palette().alt,
        )
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
                    .fg(if app.settings_dirty || editing.is_some() {
                        palette().warn
                    } else {
                        palette().alt
                    })
                    .bg(palette().surface_raised)
                    .bold(),
            )
            .bottom_margin(1),
        )
        .block(accent_panel(title, accent))
        .row_highlight_style(row_highlight_style())
        .highlight_symbol("▌ ");
    frame.render_stateful_widget(table, inset(table_area), &mut app.setting_state);
    render_setting_detail(frame, app, editing.map(|(field, _)| field), detail_area);
}

/// The plain-language strip under the TUNE table: what the selected (or
/// edited) setting means for the user, plus whether it is a local client
/// preference or a service-validated detector setting.
fn render_setting_detail(
    frame: &mut Frame<'_>,
    app: &App,
    edited: Option<SettingField>,
    area: Rect,
) {
    let selected = app.setting_state.selected().unwrap_or(0);
    let Some(field) = edited.or_else(|| app.visible_setting_fields().get(selected).copied()) else {
        return;
    };
    let scope = if field.is_client() {
        Span::styled(
            "  · local client preference — saved per user, not service-validated",
            Style::default().fg(palette().info),
        )
    } else {
        Span::styled(
            "  · service setting — press s to save",
            Style::default().fg(palette().muted),
        )
    };
    let mut lines = vec![Line::from(vec![
        Span::styled(field.label(), Style::default().fg(palette().text).bold()),
        scope,
    ])];
    let width = usize::from(area.width.saturating_sub(4)).max(16);
    for row in wrap_words(field.description(), width) {
        lines.push(Line::styled(row, Style::default().fg(palette().muted)));
    }
    let (title, accent) = if edited.is_some() {
        (" ✎ EDITING · Enter apply · Esc cancel ", palette().warn)
    } else {
        (" ◈ WHAT THIS MEANS ", palette().info)
    };
    frame.render_widget(
        Paragraph::new(lines).block(accent_panel(title, accent)),
        inset(area),
    );
}

/// Key/description rows for both help panes. Descriptions are short enough
/// to sit on one line at ≥100 terminal columns; anything that still must
/// wrap does so through [`help_lines`]' hanging indent, so the two-column
/// grid never sheds orphan full-width words.
const HELP_GLOBAL: [(&str, &str); 11] = [
    ("1–9", "jump to a page"),
    ("Tab / Shift-Tab", "next / previous page"),
    ("j / k, ↑ / ↓", "move selection"),
    ("PgUp / PgDn", "move ten rows"),
    ("r", "refresh current page"),
    ("mouse click", "select rows, tabs, prompts"),
    ("mouse wheel", "scroll the active view"),
    ("m", "toggle motion effects"),
    ("t", "cycle presentation profile"),
    ("q / Ctrl-C", "quit"),
    ("?", "keys overlay on any page"),
];
const HELP_CONTEXTUAL: [(&str, &str); 19] = [
    ("/", "filter name / path / PID"),
    ("o", "cycle process sort"),
    ("g", "agent-only process focus"),
    ("x", "typed-PID termination request"),
    ("a", "acknowledge finding"),
    ("i", "investigate the selected finding in Oracle"),
    ("[ / ]", "shorter / longer timeline"),
    ("Enter on Oracle", "ask the systems analyzer"),
    ("e on Oracle", "edit + resubmit your last question"),
    ("h / n on Oracle", "chat history / new chat"),
    ("r / F2 in Chat Vault", "rename the selected chat"),
    (
        "d / Del in Chat Vault",
        "delete the selected chat (press twice)",
    ),
    ("y on Oracle", "copy the latest answer"),
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
        "Launch with --theme vitals|avionics|ledger to pick a profile.",
        "t / m choices persist per user; CLI flags override one run.",
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
                " ✎ EDITING  ",
                Style::default().fg(palette().bg).bg(palette().warn).bold(),
            ),
            Span::styled(
                format!("  {}  ", field.label().to_ascii_uppercase()),
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

/// Per-page contextual hints, shared by the statusline footer and the
/// broadsheet folio line.
fn page_hints(page: Page) -> &'static str {
    match page {
        Page::Overview => "2 hunt  ·  4 incidents  ·  r sample",
        Page::Processes => "/ query  ·  o rank  ·  g agents  ·  x terminate",
        Page::Tree => "j/k trace  ·  r rebuild  ·  x terminate",
        Page::Alerts => "j/k inspect  ·  a acknowledge  ·  i investigate  ·  r refresh",
        Page::Timeline => "[ ] window  ·  r reload",
        Page::Analyzer => {
            "Enter ask  ·  e edit last  ·  n new  ·  h vault (r rename · d delete)  ·  y copy  ·  [ ] evidence"
        }
        Page::Settings => "Enter edit  ·  s commit  ·  r revert",
        Page::Help => "1–9 route  ·  Tab cycle",
        Page::Hardware => "temperatures + clocks resample every 5s  ·  r refresh",
    }
}

fn normal_footer(page: Page) -> Line<'static> {
    let contextual = page_hints(page);
    Line::from(vec![
        Span::styled(
            " NORMAL ",
            Style::default().fg(palette().bg).bg(palette().ok).bold(),
        ),
        Span::styled(
            format!(
                "  {:02}/{:02} {}  ::  {contextual}   ",
                page_index(page) + 1,
                Page::ALL.len(),
                route_name(page)
            ),
            Style::default().fg(palette().text),
        ),
        key_badge("Tab"),
        Span::styled(" route  ", Style::default().fg(palette().muted)),
        key_badge("m"),
        Span::styled(" motion  ", Style::default().fg(palette().muted)),
        key_badge("?"),
        Span::styled(" keys  ", Style::default().fg(palette().muted)),
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
    if broadsheet() {
        // Ruled region instead of a rounded box; the horizontal padding
        // keeps content columns where the boxed layouts put them, so shared
        // hit-tests stay aligned.
        return Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(palette().border))
            .style(Style::default().fg(palette().text).bg(palette().surface))
            .title(title)
            .title_style(Style::default().fg(accent).bold())
            .padding(Padding::horizontal(1));
    }
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
    use crate::app::{HardwareTrace, TreeRow};
    use pcpulse_service::models::{
        GpuMetrics, ProcessMetric, ProcessNode, Snapshot, SystemMetric, ThermalZone,
    };
    use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};
    use std::collections::VecDeque;

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
    fn system_vector_carries_a_net_row_in_io_grammar() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        // The NET row sits with the other meters and renders its rate in the
        // same format grammar as the I/O row.
        assert!(text.contains(" NET"), "NET row missing from the System Vector");
        assert!(text.contains("2.50 MB/s"), "network rate missing: {text}");
        // Old services report no network counter; the row stays honest at
        // zero instead of disappearing.
        if let Some(snapshot) = app.snapshot.as_mut() {
            snapshot.system.network_bytes_per_sec = 0.0;
        }
        let text = buffer_text(render(&mut app).buffer());
        assert!(text.contains(" NET"));
        assert!(text.contains("0 B/s"));
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
                .any(
                    |(index, cell)| (index / width) as u16 == user_row && cell.fg == palette().text
                )
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

    fn spans_text(spans: &[Span<'_>]) -> String {
        spans.iter().map(|span| span.content.as_ref()).collect()
    }

    fn text_with_fg(spans: &[Span<'_>], color: Color) -> String {
        spans
            .iter()
            .filter(|span| span.style.fg == Some(color))
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn analyzer_phases_advance_by_elapsed_and_hold_at_consulting() {
        assert_eq!(analyzer_phase(0), AnalyzerPhase::Reading);
        assert_eq!(analyzer_phase(2_999), AnalyzerPhase::Reading);
        assert_eq!(analyzer_phase(3_000), AnalyzerPhase::Correlating);
        assert_eq!(analyzer_phase(7_999), AnalyzerPhase::Correlating);
        assert_eq!(analyzer_phase(8_000), AnalyzerPhase::Consulting);
        // Terminal loop: writing is not knowable client-side.
        assert_eq!(analyzer_phase(600_000), AnalyzerPhase::Consulting);
    }

    #[test]
    fn reading_scanner_window_sweeps_while_the_phrase_stays_whole() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let early = analyzer_pending_spans(AnalyzerPhase::Reading, 600, 300, 80);
        let later = analyzer_pending_spans(AnalyzerPhase::Reading, 1_500, 300, 80);
        // The full phrase is present in every frame.
        assert_eq!(spans_text(&early), READING_PHRASE);
        assert_eq!(spans_text(&later), READING_PHRASE);
        // 600 ms / 150 ms-per-step puts the 4-char window over "read";
        // 1500 ms has swept it forward to "g fr".
        assert_eq!(text_with_fg(&early, palette().info), "read");
        assert_eq!(text_with_fg(&later, palette().info), "g fr");
        // Everything outside the window stays muted-readable.
        assert_eq!(text_with_fg(&early, palette().muted), &READING_PHRASE[4..]);
    }

    #[test]
    fn correlating_segments_take_turns_pulsing() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let beat0 = analyzer_pending_spans(AnalyzerPhase::Correlating, 0, 300, 80);
        let beat1 = analyzer_pending_spans(AnalyzerPhase::Correlating, 600, 300, 80);
        let beat2 = analyzer_pending_spans(AnalyzerPhase::Correlating, 1_200, 300, 80);
        for frame in [&beat0, &beat1, &beat2] {
            assert_eq!(spans_text(frame), CORRELATING_PHRASE);
        }
        assert_eq!(text_with_fg(&beat0, palette().ok), "correlating processes");
        assert_eq!(text_with_fg(&beat1, palette().ok), "incidents");
        assert_eq!(text_with_fg(&beat2, palette().ok), "baselines");
        // The pulse wraps back to the first segment after the last one.
        let wrapped = analyzer_pending_spans(AnalyzerPhase::Correlating, 2_400, 300, 80);
        assert_eq!(
            text_with_fg(&wrapped, palette().ok),
            "correlating processes"
        );
    }

    #[test]
    fn consulting_breathes_between_muted_and_text_with_the_ticker_beside() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        // Cycle start rests at muted; mid-cycle peaks at full text brightness.
        let rest = analyzer_pending_spans(AnalyzerPhase::Consulting, 0, 300, 80);
        assert_eq!(rest[0].style.fg, Some(palette().muted));
        let peak = analyzer_pending_spans(AnalyzerPhase::Consulting, 1_200, 300, 80);
        assert_eq!(peak[0].style.fg, Some(palette().text));
        // The words never change, and the elapsed/budget ticker rides along.
        assert_eq!(rest[0].content.as_ref(), CONSULTING_PHRASE);
        assert_eq!(
            spans_text(&peak),
            format!("{CONSULTING_PHRASE} · 0m1s / 5m0s")
        );
        let deep = analyzer_pending_spans(AnalyzerPhase::Consulting, 154_000, 300, 80);
        assert!(spans_text(&deep).ends_with(" · 2m34s / 5m0s"));
    }

    #[test]
    fn writing_typewriter_reveals_monotonically_and_pauses_at_full() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let phrase_len = WRITING_PHRASE.chars().count();
        let mut previous = 0;
        for elapsed in (0..2_700).step_by(450) {
            let frame = analyzer_pending_spans(AnalyzerPhase::Writing, elapsed, 300, 80);
            let revealed: String = text_with_fg(&frame, palette().text);
            // Only ever a prefix of the phrase — never garbled tail text.
            assert!(WRITING_PHRASE.starts_with(&revealed), "{elapsed}ms");
            assert!(revealed.chars().count() >= previous, "{elapsed}ms");
            previous = revealed.chars().count();
            if previous < phrase_len {
                assert_eq!(spans_text(&frame), format!("{revealed}▌"));
                let caret = frame.last().expect("caret span");
                assert_eq!(caret.style.fg, Some(palette().info));
            }
        }
        // Fully revealed: the caret rests and the whole phrase reads.
        let held = analyzer_pending_spans(
            AnalyzerPhase::Writing,
            phrase_len as u64 * TYPE_STEP_MS + 90,
            300,
            80,
        );
        assert_eq!(spans_text(&held), WRITING_PHRASE);
        // The loop restarts after the hold.
        let cycle_ms = (phrase_len as u64 + TYPE_HOLD_STEPS) * TYPE_STEP_MS;
        let looped = analyzer_pending_spans(AnalyzerPhase::Writing, cycle_ms + 450, 300, 80);
        assert!(spans_text(&looped).chars().count() < phrase_len);
    }

    #[test]
    fn vault_focus_hints_and_rename_band_render_in_the_vault_panel() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        app.page = Page::Analyzer;
        // Unfocused: the original focus hint; no vault action hints yet.
        let text = buffer_text(render(&mut app).buffer());
        assert!(text.contains("h focus"));
        assert!(!text.contains("↵ restore"));
        // Focused: restore/rename/delete hints appear on the panel.
        app.chat_history_focused = true;
        let text = buffer_text(render(&mut app).buffer());
        assert!(text.contains("↵ restore · r rename · d delete"));
        // Renaming: the edit band with the typed title and caret takes over.
        app.vault_rename = Some("Morning hunt".into());
        let text = buffer_text(render(&mut app).buffer());
        assert!(text.contains("✎ rename"));
        assert!(text.contains("Morning hunt█"));
        assert!(text.contains("↵ apply · Esc"));
        // A click anywhere dismisses the band without reaching the page.
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 2,
            row: 2,
            modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
        };
        assert!(handle_mouse(&mut app, click, Rect::new(0, 0, 150, 46)));
        assert!(app.vault_rename.is_none());
        assert_eq!(app.page, Page::Analyzer);
    }

    #[test]
    fn running_transcript_animates_the_reading_phase_behind_a_static_badge() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        app.page = Page::Analyzer;
        app.analyzer_running = true;
        app.analyzer_started_at = Some(std::time::Instant::now());
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        // Fresh submission: the wait line is in the reading phase, and the
        // static ANALYST badge introduces it.
        assert!(text.contains("reading fresh evidence"));
        assert!(!text.contains("correlating processes"));
        let badge_row = (0..backend.buffer().area.height)
            .find(|y| row_text(backend.buffer(), *y).contains("reading fresh evidence"))
            .expect("pending line row");
        assert!(row_text(backend.buffer(), badge_row).contains("ANALYST"));
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
    fn clicking_away_from_a_setting_edit_cancels_it_like_esc() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        app.page = Page::Settings;
        let area = Rect::new(0, 0, 160, 48);
        let table = inset(settings_regions(regions(area).body).0);
        let click = |app: &mut App, column: u16, row: u16| {
            handle_mouse(
                app,
                MouseEvent {
                    kind: MouseEventKind::Down(MouseButton::Left),
                    column,
                    row,
                    modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
                },
                area,
            )
        };
        // Click the CLIENT timeout row (index 2) to start a typed edit.
        // Rows begin at table.y + 1 + header_height(2).
        click(&mut app, table.x + 2, table.y + 3 + 2);
        assert!(matches!(
            app.mode,
            InputMode::EditSetting {
                field: SettingField::ClientTimeout,
                ..
            }
        ));
        // Clicking the row being edited keeps the edit.
        click(&mut app, table.x + 4, table.y + 3 + 2);
        assert!(matches!(
            app.mode,
            InputMode::EditSetting {
                field: SettingField::ClientTimeout,
                ..
            }
        ));
        // Clicking another editable row cancels this edit and begins there.
        click(&mut app, table.x + 2, table.y + 3 + 4);
        match &app.mode {
            InputMode::EditSetting { field, .. } => {
                assert_ne!(*field, SettingField::ClientTimeout)
            }
            InputMode::Normal => {}
            other => panic!("unexpected mode after clicking another row: {other:?}"),
        }
        // Re-enter the timeout edit, then click a tab: the edit cancels and
        // the navigation happens — no Esc required.
        app.page = Page::Settings;
        app.mode = InputMode::EditSetting {
            field: SettingField::ClientTimeout,
            typed: "120".into(),
        };
        let tabs = regions(area).tabs;
        let hunt_column = (tabs.x..tabs.right())
            .find(|column| route_at(*column, tabs) == Some(Page::Processes))
            .expect("Hunt tab should have a clickable cell");
        assert!(click(&mut app, hunt_column, tabs.y));
        assert!(matches!(app.mode, InputMode::Normal));
        assert_eq!(app.page, Page::Processes);
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
            (table.x..table.right())
                .any(|x| process_sort_at(table, x) == Some(ProcessSort::Handles))
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
    fn settings_edit_mode_renders_band_badge_cursor_and_dims_the_rest() {
        for theme_id in [theme::ThemeId::Vitals, theme::ThemeId::Avionics] {
            let _theme = theme::test_support::activate(theme_id);
            let mut app = sample_app();
            app.page = Page::Settings;
            let index = app
                .visible_setting_fields()
                .iter()
                .position(|field| *field == SettingField::Sustained)
                .expect("Sustained row");
            app.setting_state.select(Some(index));
            app.mode = InputMode::EditSetting {
                field: SettingField::Sustained,
                typed: "7".into(),
            };
            let backend = render(&mut app);
            let text = buffer_text(backend.buffer());
            // The EDITING badge and the apply/cancel hint are unmissable.
            assert!(text.contains("✎ EDITING"), "{theme_id:?}");
            assert!(text.contains("Enter apply · Esc cancel"), "{theme_id:?}");
            let width = usize::from(backend.buffer().area.width);
            let edited_row = (0..backend.buffer().area.height)
                .find(|y| row_text(backend.buffer(), *y).contains("Sustained samples"))
                .expect("edited row visible");
            // The VALUE cell is an input band: typed text on select_bg with a
            // visible caret glyph. (The row-highlight patch owns the fg on
            // the selected row, so the glyph and band bg are the contract.)
            assert!(
                backend
                    .buffer()
                    .content()
                    .iter()
                    .enumerate()
                    .any(|(index, cell)| (index / width) as u16 == edited_row
                        && cell.symbol() == "▏"
                        && cell.bg == palette().select_bg),
                "{theme_id:?}: caret missing from the value band"
            );
            // Unedited rows recede so the eye lands on the edit.
            let dim_row = (0..backend.buffer().area.height)
                .find(|y| row_text(backend.buffer(), *y).contains("Sample interval"))
                .expect("unedited row visible");
            assert!(
                backend
                    .buffer()
                    .content()
                    .iter()
                    .enumerate()
                    .any(|(index, cell)| (index / width) as u16 == dim_row
                        && cell.fg == palette().faint),
                "{theme_id:?}: unedited rows must dim"
            );
        }
    }

    #[test]
    fn settings_detail_strip_translates_the_selected_setting() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        app.page = Page::Settings;
        let index = app
            .visible_setting_fields()
            .iter()
            .position(|field| *field == SettingField::Sustained)
            .expect("Sustained row");
        app.setting_state.select(Some(index));
        let text = buffer_text(render(&mut app).buffer());
        assert!(text.contains("WHAT THIS MEANS"));
        assert!(text.contains("checks in a row"));
        assert!(text.contains("service setting"));
        // Client rows announce that they are local, not service-validated.
        app.setting_state.select(Some(0));
        let text = buffer_text(render(&mut app).buffer());
        assert!(text.contains("Theme profile"));
        assert!(text.contains("local client preference"));
        assert!(text.contains("not service-validated"));
    }

    #[test]
    fn keys_overlay_floats_above_the_page_without_replacing_it() {
        let _theme = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        assert_eq!(app.page, Page::Overview);
        app.help_overlay = Some(0);
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        // The overlay shows the same keys content the Keys page carries…
        assert!(text.contains("? KEYS"));
        assert!(text.contains("jump to a page"));
        assert!(text.contains("copy the latest answer"));
        // …while the page beneath is unchanged and still peeking out.
        assert_eq!(app.page, Page::Overview);
        assert!(text.contains("PRESSURE FIELD"));
        // A click dismisses it instead of reaching the page.
        let area = Rect::new(0, 0, 150, 46);
        assert!(handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 5,
                row: 5,
                modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
            },
            area,
        ));
        assert_eq!(app.help_overlay, None);
        assert_eq!(app.page, Page::Overview);
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

    #[test]
    fn broadsheet_regions_are_masthead_index_body_and_folio() {
        let _theme = theme::test_support::activate(theme::ThemeId::Ledger);
        let area = Rect::new(0, 0, 150, 46);
        let regions = regions(area);
        assert_eq!(regions.full, area);
        // Masthead: brand, dateline, page index, double rule.
        assert_eq!(regions.header, Rect::new(0, 0, 150, 4));
        // The printed page index is the masthead's third line.
        assert_eq!(regions.tabs, Rect::new(0, 2, 150, 1));
        // Folio: one thin rule plus the folio line.
        assert_eq!(regions.footer, Rect::new(0, 44, 150, 2));
        assert_eq!(regions.body, Rect::new(0, 4, 150, 40));
    }

    #[test]
    fn ledger_masthead_prints_brand_dateline_index_and_rules() {
        let _theme = theme::test_support::activate(theme::ThemeId::Ledger);
        let mut app = gallery_app();
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("PC PULSE — WORKSTATION LEDGER"));
        assert!(text.contains("LINKED / ETW"));
        // Full page names in the printed index at this width.
        assert!(text.contains("1 OBSERVE"));
        assert!(text.contains("6 ORACLE"));
        assert!(text.contains("9 GAUGES"));
        // The double rule under the masthead and the folio rule beneath.
        assert!(text.contains("═══"));
        assert!(text.contains("───"));
        // The active index entry is inverted like a rubber stamp.
        assert!(
            backend
                .buffer()
                .content()
                .iter()
                .any(|cell| cell.bg == palette().text)
        );
        // The folio carries the page number, hints, and the status.
        assert!(text.contains("№01/09 OBSERVE"));
        assert!(text.contains("t profile"));
        assert!(text.contains("Settings saved"));
    }

    #[test]
    fn ledger_never_draws_a_box_border_on_any_page() {
        let _theme = theme::test_support::activate(theme::ThemeId::Ledger);
        for page in Page::ALL {
            let mut app = gallery_app();
            app.page = page;
            let text = buffer_text(render(&mut app).buffer());
            // The panel chrome's corner glyphs: rounded (accent_panel),
            // quadrant (field_block), double (modal — not open here). Chart
            // axes may legitimately draw a plain └, so plain corners are
            // exempt.
            for corner in ['╭', '╮', '╰', '╯', '▛', '▜', '▙', '▟', '╔', '╗', '╚', '╝'] {
                assert!(!text.contains(corner), "{page:?} draws box corner {corner}");
            }
        }
    }

    #[test]
    fn block_digit_font_renders_every_numeral_pattern() {
        let expected: [(&str, [&str; 3]); 10] = [
            ("0", ["█▀█", "█ █", "▀▀▀"]),
            ("1", ["▄█ ", " █ ", "▀▀▀"]),
            ("2", ["▀▀█", "█▀▀", "▀▀▀"]),
            ("3", ["▀▀█", " ▀█", "▀▀▀"]),
            ("4", ["█ █", "▀▀█", "  █"]),
            ("5", ["█▀▀", "▀▀█", "▀▀▀"]),
            ("6", ["█▀▀", "█▀█", "▀▀▀"]),
            ("7", ["▀▀█", "  █", "  █"]),
            ("8", ["█▀█", "█▀█", "▀▀▀"]),
            ("9", ["█▀█", "▀▀█", "▀▀▀"]),
        ];
        for (text, rows) in expected {
            assert_eq!(block_digits(text), rows.map(String::from), "digit {text}");
            // Only the block pieces and space build the glyphs.
            for row in rows {
                assert!(row.chars().all(|c| " █▀▄".contains(c)), "digit {text}");
            }
        }
        // Every digit reads as itself: no two glyphs collide.
        for (left, left_rows) in &expected {
            for (right, right_rows) in &expected {
                if left != right {
                    assert_ne!(left_rows, right_rows, "{left} collides with {right}");
                }
            }
        }
        // Multi-character figures join with a one-cell gap, equal widths.
        let joined = block_digits("1.8");
        for row in &joined {
            assert_eq!(row.chars().count(), 3 + 1 + 1 + 1 + 3);
        }
        assert_eq!(joined[2], "▀▀▀ ▄ ▀▀▀");
    }

    #[test]
    fn ledger_observe_front_page_prints_headline_ledger_and_notices() {
        let _theme = theme::test_support::activate(theme::ThemeId::Ledger);
        let mut app = gallery_app();
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        // Headline figures: CPU 46 and MEM 50 as block digits with captions.
        assert!(text.contains("█ █ █▀▀"), "CPU 46 headline row 0");
        assert!(text.contains("▀▀█ █▀█"), "CPU 46 headline row 1");
        assert!(text.contains("█▀▀ █▀█"), "MEM 50 headline row 0");
        assert!(text.contains("CPU LOAD %"));
        assert!(text.contains("MEMORY %"));
        assert!(text.contains("DISK MS"));
        // The two printed columns and the circulation bar.
        assert!(text.contains("SUSPECT LEDGER"));
        assert!(text.contains("NOTICES"));
        assert!(text.contains("CIRCULATION"));
        // Findings wear printed tags, not colored badges.
        assert!(text.contains("[CRITICAL]"));
        assert!(text.contains("[WARNING]"));
        assert!(text.contains("[NOTICE]"));
        // The vitals/avionics Observe centerpieces stay off this page.
        assert!(!text.contains("PRESSURE FIELD"));
        assert!(!text.contains("PRESSURE MAP"));
        assert!(!text.contains("SUSPECT MATRIX"));
    }

    #[test]
    fn ledger_headline_degrades_to_plain_numerals_when_narrow() {
        let _theme = theme::test_support::activate(theme::ThemeId::Ledger);
        let mut app = gallery_app();
        let backend = render_size(&mut app, 90, 28);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("CPU 46%"), "plain numerals");
        assert!(text.contains("MEM 50%"));
        assert!(text.contains("DISK 1.8 ms"));
        assert!(!text.contains("█▀█"), "no block digits below the floor");
        assert!(text.contains("SUSPECT LEDGER"));
    }

    #[test]
    fn clicking_the_masthead_index_switches_pages() {
        let _theme = theme::test_support::activate(theme::ThemeId::Ledger);
        let mut app = sample_app();
        let area = Rect::new(0, 0, 150, 46);
        let tabs = regions(area).tabs;
        let oracle_column = (tabs.x..tabs.right())
            .find(|column| masthead_route_at(*column, tabs) == Some(Page::Analyzer))
            .expect("Oracle index entry should have a clickable cell");
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
        // Every page owns a reachable entry on the printed index.
        for (index, page) in Page::ALL.iter().copied().enumerate() {
            assert!(
                (tabs.x..tabs.right()).any(|x| masthead_route_at(x, tabs) == Some(page)),
                "index entry {index} unreachable"
            );
        }
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
            network_bytes_per_sec: 2.5 * 1024.0 * 1024.0,
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
        let hardware = HardwareMetrics {
            sampled_at_ms: system.timestamp_ms,
            cpu_frequency_mhz: Some(4_212.0),
            thermal_zones: vec![
                ThermalZone {
                    name: "TZ00".into(),
                    temperature_c: 48.9,
                },
                ThermalZone {
                    name: "TZ01".into(),
                    temperature_c: 62.3,
                },
            ],
            gpus: vec![GpuMetrics {
                name: "NVIDIA GeForce RTX 4080".into(),
                temperature_c: Some(62.0),
                core_clock_mhz: Some(2_550.0),
                memory_clock_mhz: Some(10_500.0),
                utilization_percent: Some(34.0),
            }],
            available: true,
            detail: String::new(),
        };
        app.connected = true;
        app.live_history.push_back(system.clone());
        app.snapshot = Some(Snapshot {
            protocol_version: 1,
            service_version: env!("CARGO_PKG_VERSION").into(),
            system,
            processes: vec![process],
            active_alerts: Vec::new(),
            hardware,
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
        // GAUGES sparklines: the traces the App would have accumulated from
        // ~10 minutes of 5-second hardware samples, one per source.
        let temperature_trace = |label: &str, base: f64| HardwareTrace {
            label: label.into(),
            points: (0..120_i64)
                .map(|step| base + 5.0 * (step as f64 / 9.0).sin())
                .collect::<VecDeque<f64>>(),
        };
        app.hardware_history = vec![
            temperature_trace("TZ00", 48.9),
            temperature_trace("TZ01", 62.3),
            temperature_trace("NVIDIA GeForce RTX 4080", 62.0),
        ];
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
    fn gauges_page_renders_meters_and_values_in_both_profiles() {
        for theme_id in [theme::ThemeId::Vitals, theme::ThemeId::Avionics] {
            let _guard = theme::test_support::activate(theme_id);
            let mut app = gallery_app();
            app.page = Page::Hardware;
            let backend = render(&mut app);
            let text = buffer_text(backend.buffer());
            assert!(text.contains("THERMALS"), "{theme_id:?}: thermal panel");
            assert!(text.contains("CLOCKS"), "{theme_id:?}: clock panel");
            assert!(text.contains("TZ00"), "{theme_id:?}: zone row");
            assert!(text.contains("48.9°C"), "{theme_id:?}: zone reading");
            assert!(
                text.contains("NVIDIA GeForce RTX 4080"),
                "{theme_id:?}: GPU row"
            );
            assert!(text.contains("62.0°C"), "{theme_id:?}: GPU temperature");
            assert!(text.contains("4212 MHz"), "{theme_id:?}: CPU frequency");
            assert!(text.contains("2550 MHz"), "{theme_id:?}: core clock");
            assert!(text.contains("10500 MHz"), "{theme_id:?}: memory clock");
            assert!(text.contains("34%"), "{theme_id:?}: utilization");
            assert!(text.contains("━"), "{theme_id:?}: meters render");
            assert!(
                ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█']
                    .iter()
                    .any(|glyph| text.contains(*glyph)),
                "{theme_id:?}: history sparkline renders"
            );
        }
    }

    #[test]
    fn gauges_meters_use_the_temperature_ratio_semantics() {
        let _guard = theme::test_support::activate(theme::ThemeId::Vitals);
        assert_eq!(temperature_ratio(45.0), 0.0);
        assert_eq!(temperature_ratio(95.0), 1.0);
        assert_eq!(temperature_color(48.9), palette().ok);
        assert_eq!(temperature_color(62.0), palette().warn);
        assert_eq!(temperature_color(84.0), palette().crit);
    }

    #[test]
    fn gauges_unavailable_state_shows_the_detail_and_the_service_hint() {
        let _guard = theme::test_support::activate(theme::ThemeId::Vitals);
        let mut app = sample_app();
        app.page = Page::Hardware;
        if let Some(snapshot) = app.snapshot.as_mut() {
            snapshot.hardware = HardwareMetrics {
                available: false,
                detail: "thermal zones unavailable: access denied; \
                         GPU telemetry unavailable: nvml.dll not present"
                    .into(),
                ..HardwareMetrics::default()
            };
        }
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("HARDWARE TELEMETRY UNAVAILABLE"));
        assert!(text.contains("access denied"));
        assert!(
            text.contains("LocalSystem"),
            "hints at the installed service"
        );
        assert!(!text.contains("°C"), "no fabricated readings");
    }

    #[test]
    fn gauges_key_9_reaches_the_page_and_the_rail_lists_it() {
        let _guard = theme::test_support::activate(theme::ThemeId::Avionics);
        let mut app = sample_app();
        app.handle_key(ratatui::crossterm::event::KeyEvent::new(
            ratatui::crossterm::event::KeyCode::Char('9'),
            ratatui::crossterm::event::KeyModifiers::NONE,
        ));
        assert_eq!(app.page, Page::Hardware);
        let backend = render(&mut app);
        let text = buffer_text(backend.buffer());
        assert!(text.contains("[9] GAUGE"), "rail bezel key for the page");
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
        for theme_id in [
            theme::ThemeId::Vitals,
            theme::ThemeId::Avionics,
            theme::ThemeId::Ledger,
        ] {
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

    // ---- README demo recorder ------------------------------------------
    //
    // `dev_record_demo` scripts one guided tour per presentation profile and
    // dumps every rendered frame as compact JSON for
    // `scripts/Make-Demo.py`, which rasterizes the dumps into
    // `docs/media/demo-<theme>.gif`. The tour drives the real `draw` +
    // `MotionSystem` pipeline exactly like `main.rs` does, with a scripted
    // clock instead of wall time.

    const DEMO_PROMPT: &str = "What has made the performance worse?";
    const DEMO_ANSWER: &str = "Firefox PID 50784 shows sustained handle growth; interrupts are elevated — likely driver-level. CPU, memory, and disk otherwise healthy.";

    /// A scripted state change applied to the demo [`App`] before a step's
    /// frames render.
    type DemoAct = Box<dyn FnOnce(&mut App)>;

    /// One scripted beat of the demo tour.
    struct DemoStep {
        /// State change applied (then observed by the motion system) before
        /// this step's frames render. `None` keeps the current animation
        /// rolling.
        act: Option<DemoAct>,
        /// Frames captured for this step.
        frames: usize,
        /// Motion-clock advance per captured frame; split into <=50 ms
        /// chunks to respect the effect manager's elapsed clamp.
        step_ms: u64,
        /// GIF hold per captured frame, written into the dump.
        delay_ms: u64,
    }

    fn act(
        apply: impl FnOnce(&mut App) + 'static,
        frames: usize,
        step_ms: u64,
        delay_ms: u64,
    ) -> DemoStep {
        DemoStep {
            act: Some(Box::new(apply)),
            frames,
            step_ms,
            delay_ms,
        }
    }

    /// Keep animating: capture `frames` frames without touching state.
    fn roll(frames: usize, step_ms: u64, delay_ms: u64) -> DemoStep {
        DemoStep {
            act: None,
            frames,
            step_ms,
            delay_ms,
        }
    }

    /// A single long-hold frame on the current screen.
    fn hold(delay_ms: u64) -> DemoStep {
        roll(1, 50, delay_ms)
    }

    /// Fake an in-flight analyzer submission that started `elapsed_ms` ago,
    /// the same way the ticker tests do, so the wait-line phases render at
    /// scripted elapsed values.
    fn backdate_analyzer(app: &mut App, elapsed_ms: u64) {
        app.analyzer_started_at =
            std::time::Instant::now().checked_sub(std::time::Duration::from_millis(elapsed_ms));
    }

    /// The gallery fixture plus a populated Chat Vault so the Oracle page
    /// shows saved conversations beside the transcript.
    fn demo_app() -> App {
        let mut app = gallery_app();
        for (index, title) in ["Tuesday slowdown hunt", "Chrome tab leak triage"]
            .iter()
            .enumerate()
        {
            app.chat_sessions.push(crate::chat_history::ChatSession {
                conversation_id: format!("demo-{index}"),
                created_at_ms: 1_799_990_000_000 + index as i64 * 3_600_000,
                updated_at_ms: 1_799_993_600_000 + index as i64 * 3_600_000,
                title: (*title).to_string(),
                title_pinned: true,
                messages: Vec::new(),
                latest_response: None,
            });
        }
        app
    }

    /// The scripted tour, shared by both profiles (theme is per-GIF).
    fn demo_script() -> Vec<DemoStep> {
        let mut steps = vec![
            // a. Startup: the monitor-boot sweep plus the header signature.
            roll(10, 100, 90),
            hold(1_000),
            // b. Observe: a fresh sample triggers the telemetry shimmer.
            act(
                |app| {
                    app.snapshot
                        .as_mut()
                        .expect("demo snapshot")
                        .system
                        .timestamp_ms += 2_000;
                },
                3,
                80,
                100,
            ),
            hold(900),
            // c. Page tour: Processes -> Tree -> Findings.
            act(|app| app.page = Page::Processes, 4, 70, 80),
            hold(1_100),
            act(|app| app.page = Page::Tree, 4, 70, 80),
            hold(1_000),
            act(|app| app.page = Page::Alerts, 4, 70, 80),
            act(|app| app.alert_state.select(Some(1)), 2, 80, 120),
            hold(1_200),
            // d. Oracle: vault visible, then the scripted interrogation.
            act(|app| app.page = Page::Analyzer, 4, 70, 80),
            hold(900),
        ];
        for length in [3usize, 8, 13, 21, 29, DEMO_PROMPT.chars().count()] {
            steps.push(act(
                move |app| {
                    app.mode = InputMode::Chat(DEMO_PROMPT.chars().take(length).collect());
                },
                1,
                50,
                150,
            ));
        }
        steps.push(act(
            |app| {
                app.mode = InputMode::Normal;
                app.chat_messages.push_back(crate::analyzer::ChatMessage {
                    role: ChatRole::User,
                    timestamp_ms: 1_800_000_000_000,
                    text: DEMO_PROMPT.into(),
                    evidence_refs: Vec::new(),
                    is_error: false,
                });
                app.analyzer_running = true;
                backdate_analyzer(app, 300);
            },
            1,
            50,
            420,
        ));
        // Reading: the 4-char scanner window sweeps the phrase (0-3 s).
        for elapsed in [700_u64, 1_600, 2_500] {
            steps.push(act(move |app| backdate_analyzer(app, elapsed), 1, 50, 460));
        }
        // Correlating: the evidence segments take turns pulsing (3-8 s).
        for elapsed in [3_300_u64, 4_500, 5_100, 6_300] {
            steps.push(act(move |app| backdate_analyzer(app, elapsed), 1, 50, 450));
        }
        // Consulting: the phrase breathes with the elapsed ticker (8 s+).
        for elapsed in [8_400_u64, 9_600, 10_800, 21_000] {
            steps.push(act(move |app| backdate_analyzer(app, elapsed), 1, 50, 500));
        }
        steps.push(act(
            |app| {
                app.analyzer_running = false;
                app.analyzer_started_at = None;
                app.chat_messages.push_back(crate::analyzer::ChatMessage {
                    role: ChatRole::Assistant,
                    timestamp_ms: 1_800_000_021_000,
                    text: DEMO_ANSWER.into(),
                    evidence_refs: vec![
                        "process:firefox.exe/50784".into(),
                        "detector:interruptRate".into(),
                    ],
                    is_error: false,
                });
            },
            1,
            50,
            1_400,
        ));
        steps.push(hold(1_200));
        // e. Settings: select a detector row and open the edit band.
        steps.push(act(|app| app.page = Page::Settings, 4, 70, 80));
        steps.push(act(
            |app| {
                app.setting_state.select(
                    SettingField::ALL
                        .iter()
                        .position(|field| *field == SettingField::Sustained),
                );
            },
            2,
            70,
            200,
        ));
        steps.push(act(
            |app| {
                app.mode = InputMode::EditSetting {
                    field: SettingField::Sustained,
                    typed: "9".into(),
                };
            },
            2,
            60,
            350,
        ));
        steps.push(act(
            |app| {
                app.mode = InputMode::EditSetting {
                    field: SettingField::Sustained,
                    typed: "90".into(),
                };
            },
            1,
            50,
            700,
        ));
        // f. Keys overlay.
        steps.push(act(
            |app| {
                app.mode = InputMode::Normal;
                app.help_overlay = Some(0);
            },
            1,
            50,
            1_000,
        ));
        steps.push(act(|app| app.help_overlay = Some(4), 1, 50, 800));
        // g. End the tour back on Observe with a final hold.
        steps.push(act(
            |app| {
                app.help_overlay = None;
                app.page = Page::Overview;
            },
            4,
            70,
            80,
        ));
        steps.push(hold(1_600));
        steps
    }

    /// Serialize one rendered frame as `{ms, rows}`: each row is a
    /// run-length-encoded list of `[text, fg, bg, bold]` runs, mirroring the
    /// HTML gallery serializer in JSON for the GIF rasterizer.
    fn frame_json(buffer: &Buffer, delay_ms: u64) -> serde_json::Value {
        fn hex(color: Color, fallback: Color) -> String {
            let resolved = match color {
                Color::Rgb(..) => color,
                _ => fallback,
            };
            match resolved {
                Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
                _ => "#000000".into(),
            }
        }
        fn flush(
            runs: &mut Vec<serde_json::Value>,
            style: Option<&(String, String, bool)>,
            text: &mut String,
        ) {
            if let Some((fg, bg, bold)) = style
                && !text.is_empty()
            {
                runs.push(serde_json::json!([
                    std::mem::take(text),
                    fg,
                    bg,
                    u8::from(*bold)
                ]));
            }
        }
        let area = *buffer.area();
        let content = buffer.content();
        let mut rows = Vec::new();
        let mut populated = false;
        for y in 0..area.height {
            let mut runs = Vec::new();
            let mut text = String::new();
            let mut style: Option<(String, String, bool)> = None;
            for x in 0..area.width {
                let cell = &content[usize::from(y) * usize::from(area.width) + usize::from(x)];
                let next = (
                    hex(cell.fg, palette().text),
                    hex(cell.bg, palette().bg),
                    cell.modifier.contains(ratatui::style::Modifier::BOLD),
                );
                if style.as_ref() != Some(&next) {
                    flush(&mut runs, style.as_ref(), &mut text);
                    style = Some(next);
                }
                let symbol = cell.symbol();
                populated |= !symbol.trim().is_empty();
                // Wide-glyph continuation cells carry an empty symbol; keep
                // the column count exact for the rasterizer's grid.
                text.push_str(if symbol.is_empty() { " " } else { symbol });
            }
            flush(&mut runs, style.as_ref(), &mut text);
            rows.push(serde_json::Value::Array(runs));
        }
        assert!(populated, "demo frame must not be empty");
        serde_json::json!({ "ms": delay_ms, "rows": rows })
    }

    #[test]
    #[ignore = "dev harness: set PCPULSE_DEMO_DIR to dump the scripted README demo tours as frame JSON for scripts/Make-Demo.py"]
    fn dev_record_demo() {
        let Ok(directory) = std::env::var("PCPULSE_DEMO_DIR") else {
            return;
        };
        for theme_id in [
            theme::ThemeId::Vitals,
            theme::ThemeId::Avionics,
            theme::ThemeId::Ledger,
        ] {
            let _guard = theme::test_support::activate(theme_id);
            let mut app = demo_app();
            let mut terminal = Terminal::new(TestBackend::new(120, 36)).expect("demo terminal");
            let mut motion = crate::effects::MotionSystem::new(&app, true);
            let mut frames = Vec::new();
            for step in demo_script() {
                if let Some(apply) = step.act {
                    apply(&mut app);
                    motion.observe(&app);
                }
                for _ in 0..step.frames {
                    let mut remaining = step.step_ms.max(1);
                    while remaining > 0 {
                        let chunk = remaining.min(50);
                        terminal
                            .draw(|frame| {
                                draw(frame, &mut app);
                                motion.render(frame, std::time::Duration::from_millis(chunk));
                            })
                            .expect("demo draw");
                        remaining -= chunk;
                    }
                    let _ = motion.take_cleanup_frame();
                    frames.push(frame_json(terminal.backend().buffer(), step.delay_ms));
                }
            }
            assert!(
                frames.len() >= 60,
                "{theme_id:?}: tour is too thin ({} frames)",
                frames.len()
            );
            let payload = serde_json::to_string(&serde_json::Value::Array(frames))
                .expect("serialize demo frames");
            std::fs::write(
                std::path::Path::new(&directory).join(format!("frames-{}.json", theme_id.name())),
                payload,
            )
            .expect("write demo frames");
        }
    }
}
