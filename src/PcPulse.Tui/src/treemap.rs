//! Squarified process-pressure treemap: the avionics Observe centerpiece.
//!
//! No stock ratatui widget draws one of these. The layouter implements the
//! classic squarify algorithm (Bruls, Huizing, van Wijk) over integer cell
//! coordinates: items are laid into strips along the shorter visual edge of
//! the remaining rectangle, growing each strip while the worst tile aspect
//! ratio keeps improving. Terminal cells are roughly twice as tall as they
//! are wide, so aspect math runs in visual units (height ×2) to keep tiles
//! square to the eye rather than to the cell grid.
//!
//! Guarantees the tests pin down: every input weight is represented (small
//! remainders merge into a single "· smaller ·" tile instead of being
//! dropped), tiles never overlap, they tile the canvas exactly, and no tile
//! falls below [`MIN_TILE_WIDTH`] × [`MIN_TILE_HEIGHT`] when the canvas
//! itself is at least that large.

use crate::theme::palette;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph},
};

/// Below 8×3 cells a tile cannot carry a readable label; smaller allotments
/// merge into the shared remainder tile.
pub const MIN_TILE_WIDTH: u16 = 8;
pub const MIN_TILE_HEIGHT: u16 = 3;

/// One process fed to the treemap. Rendering is fully snapshot-driven: the
/// caller rebuilds items every frame and selection travels in `selected`.
#[derive(Debug, Clone, PartialEq)]
pub struct TreemapItem {
    pub label: String,
    /// Tile area is proportional to this weight (working-set bytes).
    pub weight: u64,
    /// Dominant pressure channel color; also the label fg, which lets the
    /// effects layer's bounded telemetry scan shimmer tile labels without
    /// any treemap-specific effect code.
    pub color: Color,
    /// 0..1 pressure relative to the channel threshold; scales the tile
    /// fill from near-surface (cool) toward the channel color (hot).
    pub heat: f64,
    /// Short inverse-styled marker, e.g. `AGT` for agent candidates.
    pub badge: Option<&'static str>,
    pub selected: bool,
    /// Second label row when the tile is tall enough, e.g. `RSS 1.2 GB  CPU 3.4%`.
    pub detail: String,
}

/// A laid-out tile: the cells it owns plus the input indices it represents —
/// one index normally, several for the merged "· smaller ·" remainder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tile {
    pub rect: Rect,
    pub indices: Vec<usize>,
}

/// Squarify `weights` into `area`. Deterministic: ties break on input index.
pub fn layout(weights: &[u64], area: Rect) -> Vec<Tile> {
    let mut tiles = Vec::new();
    if weights.is_empty() || area.width == 0 || area.height == 0 {
        return tiles;
    }
    let mut order: Vec<usize> = (0..weights.len()).collect();
    order.sort_by(|left, right| {
        effective(weights[*right])
            .cmp(&effective(weights[*left]))
            .then(left.cmp(right))
    });
    place(&order, weights, area, &mut tiles);
    tiles
}

/// Zero-weight items still deserve cells; treat them as weight 1.
fn effective(weight: u64) -> u64 {
    weight.max(1)
}

fn total_weight(order: &[usize], weights: &[u64]) -> f64 {
    order
        .iter()
        .map(|index| effective(weights[*index]) as f64)
        .sum()
}

/// Recursive squarify step: cut one strip off `rect`, subdivide it among a
/// prefix of `order`, recurse on the rest.
fn place(order: &[usize], weights: &[u64], rect: Rect, out: &mut Vec<Tile>) {
    if order.is_empty() {
        return;
    }
    let can_cut_columns = rect.width >= 2 * MIN_TILE_WIDTH;
    let can_cut_rows = rect.height >= 2 * MIN_TILE_HEIGHT;
    if order.len() == 1 || (!can_cut_columns && !can_cut_rows) {
        out.push(Tile {
            rect,
            indices: order.to_vec(),
        });
        return;
    }
    // Visual units: a cell is ~half as wide as it is tall.
    let visual_width = f64::from(rect.width);
    let visual_height = f64::from(rect.height) * 2.0;
    let column_strip = if can_cut_columns && can_cut_rows {
        visual_width >= visual_height
    } else {
        can_cut_columns
    };
    let (long, short) = if column_strip {
        (visual_width, visual_height)
    } else {
        (visual_height, visual_width)
    };
    let total = total_weight(order, weights);
    let prefix = choose_prefix(order, weights, total, long, short);
    let row_weight = total_weight(&order[..prefix], weights);
    if prefix == order.len() {
        // Everything fits one strip: stack it along the short visual axis.
        split_strip(order, weights, rect, column_strip, out);
        return;
    }
    if column_strip {
        let ideal = (row_weight / total * f64::from(rect.width)).round() as u16;
        let columns = ideal.clamp(MIN_TILE_WIDTH, rect.width - MIN_TILE_WIDTH);
        let strip = Rect::new(rect.x, rect.y, columns, rect.height);
        let rest = Rect::new(rect.x + columns, rect.y, rect.width - columns, rect.height);
        split_strip(&order[..prefix], weights, strip, true, out);
        place(&order[prefix..], weights, rest, out);
    } else {
        let ideal = (row_weight / total * f64::from(rect.height)).round() as u16;
        let rows = ideal.clamp(MIN_TILE_HEIGHT, rect.height - MIN_TILE_HEIGHT);
        let strip = Rect::new(rect.x, rect.y, rect.width, rows);
        let rest = Rect::new(rect.x, rect.y + rows, rect.width, rect.height - rows);
        split_strip(&order[..prefix], weights, strip, false, out);
        place(&order[prefix..], weights, rest, out);
    }
}

/// Grow the strip while the worst aspect ratio of its tiles keeps improving —
/// the heart of squarify.
fn choose_prefix(order: &[usize], weights: &[u64], total: f64, long: f64, short: f64) -> usize {
    let mut prefix = 1;
    let mut worst = worst_aspect(&order[..1], weights, total, long, short);
    while prefix < order.len() {
        let candidate = worst_aspect(&order[..prefix + 1], weights, total, long, short);
        if candidate <= worst {
            worst = candidate;
            prefix += 1;
        } else {
            break;
        }
    }
    prefix
}

/// Worst tile aspect ratio (>= 1.0, 1.0 = square) if `row` becomes one strip.
fn worst_aspect(row: &[usize], weights: &[u64], total: f64, long: f64, short: f64) -> f64 {
    let row_weight = total_weight(row, weights);
    let thickness = (row_weight / total * long).max(f64::MIN_POSITIVE);
    row.iter()
        .map(|index| {
            let length =
                (effective(weights[*index]) as f64 / row_weight * short).max(f64::MIN_POSITIVE);
            (thickness / length).max(length / thickness)
        })
        .fold(1.0, f64::max)
}

/// Subdivide one strip along its stacking axis. Items that cannot get their
/// minimum extent merge into a single trailing remainder tile — nothing is
/// dropped.
fn split_strip(
    order: &[usize],
    weights: &[u64],
    strip: Rect,
    stack_vertically: bool,
    out: &mut Vec<Tile>,
) {
    let minimum = if stack_vertically {
        MIN_TILE_HEIGHT
    } else {
        MIN_TILE_WIDTH
    };
    let mut cursor = 0u16;
    let mut remaining_length = if stack_vertically {
        strip.height
    } else {
        strip.width
    };
    let mut start = 0usize;
    while start < order.len() {
        let rest = &order[start..];
        let pending = rest.len() as u16;
        // Not enough room to give every remaining item its minimum: merge.
        if rest.len() == 1 || remaining_length < pending * minimum {
            out.push(Tile {
                rect: strip_slice(strip, stack_vertically, cursor, remaining_length),
                indices: rest.to_vec(),
            });
            return;
        }
        let rest_weight = total_weight(rest, weights);
        let ideal = (effective(weights[rest[0]]) as f64 / rest_weight * f64::from(remaining_length))
            .round() as u16;
        let length = ideal.clamp(minimum, remaining_length - (pending - 1) * minimum);
        out.push(Tile {
            rect: strip_slice(strip, stack_vertically, cursor, length),
            indices: vec![rest[0]],
        });
        cursor += length;
        remaining_length -= length;
        start += 1;
    }
}

fn strip_slice(strip: Rect, stack_vertically: bool, offset: u16, length: u16) -> Rect {
    if stack_vertically {
        Rect::new(strip.x, strip.y + offset, strip.width, length)
    } else {
        Rect::new(strip.x + offset, strip.y, length, strip.height)
    }
}

/// Linear interpolation between two palette colors; `t` = 0 yields `base`.
pub fn mix(base: Color, accent: Color, t: f64) -> Color {
    let (Color::Rgb(br, bg, bb), Color::Rgb(ar, ag, ab)) = (base, accent) else {
        return base;
    };
    let t = t.clamp(0.0, 1.0);
    let channel = |from: u8, to: u8| -> u8 {
        (f64::from(from) + (f64::from(to) - f64::from(from)) * t).round() as u8
    };
    Color::Rgb(channel(br, ar), channel(bg, ag), channel(bb, ab))
}

/// Paint the laid-out tiles. Tiles read as solid panes of glass: a filled
/// heat-scaled background with a one-cell gutter of raw canvas `bg` on the
/// right and bottom instead of box-drawing borders. The selected tile gets
/// an inverted label band (chosen over corner glyphs — it survives narrow
/// tiles and reads instantly).
pub fn render(frame: &mut Frame<'_>, items: &[TreemapItem], tiles: &[Tile], canvas: Rect) {
    frame.render_widget(
        Block::default().style(Style::default().bg(palette().bg)),
        canvas,
    );
    for tile in tiles {
        let inner = Rect::new(
            tile.rect.x,
            tile.rect.y,
            tile.rect.width.saturating_sub(1),
            tile.rect.height.saturating_sub(1),
        );
        if inner.width == 0 || inner.height == 0 {
            continue;
        }
        match tile.indices.as_slice() {
            [index] => {
                if let Some(item) = items.get(*index) {
                    render_item_tile(frame, item, inner, tile.rect.height);
                }
            }
            merged => render_merged_tile(frame, items, merged, inner, tile.rect.height),
        }
    }
}

fn render_item_tile(frame: &mut Frame<'_>, item: &TreemapItem, inner: Rect, tile_height: u16) {
    // Cool tiles sit just above the panel surface; hot tiles climb toward
    // their channel color. Capped at 0.48 so a full-brightness channel label
    // stays readable on its own dimmed hue.
    let fill = mix(
        palette().surface,
        item.color,
        0.10 + 0.38 * item.heat.clamp(0.0, 1.0),
    );
    let width_budget = usize::from(inner.width);
    let mut label_spans = Vec::new();
    let mut name_budget = width_budget.saturating_sub(1);
    if item.selected {
        label_spans.push(Span::styled("▌", Style::default().fg(palette().text)));
        let mut band = String::new();
        if let Some(badge) = item.badge {
            band.push_str(badge);
            band.push(' ');
        }
        band.push_str(&crate::format::truncate(
            &item.label,
            name_budget.saturating_sub(band.chars().count()),
        ));
        let pad = name_budget.saturating_sub(band.chars().count());
        band.push_str(&" ".repeat(pad));
        label_spans.push(Span::styled(
            band,
            Style::default().fg(palette().bg).bg(item.color).bold(),
        ));
    } else {
        if let Some(badge) = item.badge {
            label_spans.push(Span::styled(
                badge,
                Style::default().fg(palette().bg).bg(item.color).bold(),
            ));
            label_spans.push(Span::raw(" "));
            name_budget = name_budget.saturating_sub(badge.chars().count() + 1);
        }
        // Exact channel fg: the telemetry-scan shimmer keys on this color.
        label_spans.push(Span::styled(
            crate::format::truncate(&item.label, name_budget),
            Style::default().fg(item.color).bold(),
        ));
    }
    let mut lines = vec![Line::from(label_spans)];
    if tile_height >= 4 {
        lines.push(Line::styled(
            format!(
                " {}",
                crate::format::truncate(&item.detail, width_budget.saturating_sub(1))
            ),
            Style::default().fg(palette().text),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).style(Style::default().fg(palette().text).bg(fill)),
        inner,
    );
}

fn render_merged_tile(
    frame: &mut Frame<'_>,
    items: &[TreemapItem],
    merged: &[usize],
    inner: Rect,
    tile_height: u16,
) {
    let combined: u64 = merged
        .iter()
        .filter_map(|index| items.get(*index))
        .map(|item| item.weight)
        .sum();
    let mut lines = vec![Line::styled(
        "· smaller ·",
        Style::default().fg(palette().muted),
    )];
    if tile_height >= 4 {
        lines.push(Line::styled(
            format!(" {} × {}", merged.len(), crate::format::bytes(combined)),
            Style::default().fg(palette().faint),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).style(
            Style::default()
                .fg(palette().muted)
                .bg(palette().surface_raised),
        ),
        inner,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Cell-exact accounting: which tile owns each cell of the canvas.
    fn coverage(tiles: &[Tile], area: Rect) -> HashMap<(u16, u16), usize> {
        let mut owners = HashMap::new();
        for (tile_index, tile) in tiles.iter().enumerate() {
            for y in tile.rect.y..tile.rect.bottom() {
                for x in tile.rect.x..tile.rect.right() {
                    assert!(
                        x >= area.x && x < area.right() && y >= area.y && y < area.bottom(),
                        "tile {tile_index} escapes the canvas at ({x},{y})"
                    );
                    let previous = owners.insert((x, y), tile_index);
                    assert_eq!(
                        previous, None,
                        "cell ({x},{y}) owned by two tiles: {previous:?} and {tile_index}"
                    );
                }
            }
        }
        owners
    }

    fn represented_indices(tiles: &[Tile]) -> Vec<usize> {
        let mut indices: Vec<usize> = tiles
            .iter()
            .flat_map(|tile| tile.indices.iter().copied())
            .collect();
        indices.sort_unstable();
        indices
    }

    #[test]
    fn tiles_cover_the_canvas_exactly_without_overlap() {
        let weights = [40, 30, 20, 10, 5, 5];
        let area = Rect::new(2, 1, 64, 20);
        let tiles = layout(&weights, area);
        let owners = coverage(&tiles, area);
        assert_eq!(
            owners.len(),
            usize::from(area.width) * usize::from(area.height),
            "tiling must fill every canvas cell"
        );
        assert_eq!(
            represented_indices(&tiles),
            (0..weights.len()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn tile_areas_track_weights_within_rounding() {
        let weights = [40u64, 30, 20, 10];
        let area = Rect::new(0, 0, 60, 24);
        let tiles = layout(&weights, area);
        let total_cells = f64::from(area.width) * f64::from(area.height);
        let total_weight: u64 = weights.iter().sum();
        for tile in &tiles {
            let tile_cells = f64::from(tile.rect.width) * f64::from(tile.rect.height);
            let tile_weight: u64 = tile.indices.iter().map(|index| weights[*index]).sum();
            let expected = tile_weight as f64 / total_weight as f64 * total_cells;
            let deviation = (tile_cells - expected).abs() / expected;
            assert!(
                deviation <= 0.25,
                "tile {:?} covers {tile_cells} cells, expected ~{expected:.0} (deviation {deviation:.2})",
                tile.indices
            );
        }
    }

    #[test]
    fn no_tile_falls_below_the_readable_minimum() {
        let weights = [500u64, 300, 200, 90, 60, 40, 20, 10, 5, 2];
        let area = Rect::new(0, 0, 72, 18);
        for tile in layout(&weights, area) {
            assert!(
                tile.rect.width >= MIN_TILE_WIDTH && tile.rect.height >= MIN_TILE_HEIGHT,
                "tile {:?} is {}x{}",
                tile.indices,
                tile.rect.width,
                tile.rect.height
            );
        }
    }

    #[test]
    fn small_remainders_merge_instead_of_dropping() {
        // Far more items than a 24x9 canvas can host at 8x3 each.
        let weights: Vec<u64> = (1..=30).map(|value| value as u64).collect();
        let area = Rect::new(0, 0, 24, 9);
        let tiles = layout(&weights, area);
        assert_eq!(
            represented_indices(&tiles),
            (0..weights.len()).collect::<Vec<_>>(),
            "every input weight must be represented"
        );
        assert!(
            tiles.iter().any(|tile| tile.indices.len() > 1),
            "the overflow must land in a merged remainder tile"
        );
        let owners = coverage(&tiles, area);
        assert_eq!(
            owners.len(),
            usize::from(area.width) * usize::from(area.height)
        );
        for tile in &tiles {
            assert!(tile.rect.width >= MIN_TILE_WIDTH && tile.rect.height >= MIN_TILE_HEIGHT);
        }
    }

    #[test]
    fn zero_weights_are_still_represented() {
        let weights = [0u64, 100, 0];
        let tiles = layout(&weights, Rect::new(0, 0, 40, 12));
        assert_eq!(represented_indices(&tiles), vec![0, 1, 2]);
    }

    #[test]
    fn mix_interpolates_between_palette_colors() {
        let base = Color::Rgb(10, 20, 30);
        let accent = Color::Rgb(210, 120, 130);
        assert_eq!(mix(base, accent, 0.0), base);
        assert_eq!(mix(base, accent, 1.0), accent);
        assert_eq!(mix(base, accent, 0.5), Color::Rgb(110, 70, 80));
    }
}
