# PC Pulse presentation profiles — design

Date: 2026-08-08
Status: proposed (implemented in this session; review welcome)
Builds on: 2026-08-08-vital-signs-theme-design.md

## Intent

Make themes runtime-switchable, and make a theme more than a palette: a
**presentation profile** = palette + structural layout. Two profiles ship:

- **VITALS** (default) — the existing vital-signs palette and the current
  top-header / top-tabs / bottom-footer structure. Unchanged visually.
- **AVIONICS** — a new profile that does not follow the current structure:
  a cockpit multi-function-display identity with its own placement.

## Switching

- CLI: `--theme vitals|avionics` (combinable with `--no-effects`).
- Hot-swap: `t` key in Normal mode cycles profiles live; fires a dedicated
  theme-switch motion cue (full-frame sweep) and a status message.
- Default: vitals. No persistence yet (follow-up if wanted).

## Architecture

New `theme.rs` module in the TUI crate:

- `struct Palette` with **semantic field names** replacing the vitals-specific
  const names: `bg, surface, surface_raised, border, border_hot, text, muted,
  faint, ok, alt, info, warn, crit, select_bg` (mapping: PHOSPHOR→ok,
  AMETHYST→alt, ICE→info, AMBER→warn, CORAL→crit).
- `enum ThemeId { Vitals, Avionics }`, `enum LayoutKind { Statusline, Rail }`,
  `struct Theme { id, name, palette: Palette, layout: LayoutKind }`.
- Two `static` theme definitions; active selection in a `static AtomicU8`;
  `fn active() -> &'static Theme` and `fn palette() -> &'static Palette`
  accessors so ~460 call sites stay expression-shaped (`palette().text`).
- ui.rs and effects.rs both read through the accessors — the exact-RGB
  `CellFilter::FgColor` couplings stay correct automatically because both
  read the same live palette on every frame/effect build.

`ui::regions(area)` becomes layout-aware and remains the single source of
truth for effect areas (`UiRegions` keeps its `full/header/tabs/body/footer`
fields; in Rail layout `header` = annunciator strip, `tabs` = the rail's key
column, `footer` = the rail's status block, so every existing motion cue
lands somewhere sensible without per-theme effect code).

Effects gain one cue: `MotionCue::ThemeSwitch` — a finite full-frame sweep in
the incoming profile's `ok` color (same constraints as all other cues; added
to `VisualState` diffing via the active theme id).

## AVIONICS profile

Palette — amber-CRT avionics glass (exact values tuned during implementation,
distinctness test still applies): near-black amber-tinted bg; amber-white
text; chrome in dim amber; accents: avionics green (`ok`), electric magenta
(`alt`), cyan (`info`), bright amber-orange (`warn`), warning-lamp red
(`crit`); selection band deep amber.

Structure (Rail layout) — deliberately different placement:

- **Left rail, 16 cols, full height**: brand block `PCPULSE ▮ MFD` on top;
  the eight pages as stacked bezel keys (`[1] OBS`, `[2] HUNT`, …) with the
  active key inverted; bottom block absorbs the footer — link `♥`, sample
  clock, motion badge, contextual hint lines, status/error line.
- **Top annunciator strip** (3 rows, spans the remaining width): a
  caution/warning lamp grid with one lamp per finding class (CPU, MEM, IO,
  HANG, LAUNCH, AGENT, POOL, DPC, BUDGET) — lit in severity color while a
  matching finding is active, faint when clear. This makes findings visible
  from every page, which the current structure only gives Observe.
- **Main canvas** fills the rest. Observe is the **spatial view**, built
  around a custom widget no stock ratatui component provides — the
  **PRESSURE MAP**, a squarified process treemap (`treemap.rs`):
  - Tile area ∝ working-set bytes for the top ~24 processes (PID > 4);
    remainders too small to label merge into a `· smaller ·` tile so
    nothing is dropped silently. Minimum tile 8×3 cells; squarify aspect
    math runs in visual units (cell height ×2) so tiles look square.
  - Tile color = the process's dominant pressure channel: `crit` when it
    owns an active finding, `warn` for agent candidates (with an inverse
    `AGT` badge), otherwise whichever threshold-relative ratio is highest —
    CPU vs `cpu_percent` → `ok`, working set vs 8% of RAM → `alt`,
    read+write IO vs `io_mb_per_sec` → `info`. Heat (the dominant ratio,
    0..1) scales the fill from near-surface toward the channel color.
  - Tiles are solid panes separated by one-cell `bg` gutters — no
    box-drawing borders. Labels use the exact channel fg colors, so the
    bounded telemetry-scan shimmer picks them up with zero effect-layer
    changes. Clicking a tile targets that process in the HUNT selection
    (`app.process_state`); the selected tile shows an inverted label band.
  - Around the map: a slim System Vector column on the left, and the
    bottom strip keeps the Incident Tape full-width with the
    load-composition ribbon docked at its right end when space allows.
  - The Suspect Matrix and Agent Swarm are deliberately absent here: they
    remain on their own pages and in the vitals Observe. (Supersedes the
    first-ship recomposition, which was the same five vitals panes
    rearranged — review feedback: shuffled, not unique.)
- Other pages keep their internal widgets but render inside the rail frame.
- Modal/offline panels unchanged (centered), themed by palette.

## Constraints carried forward

All ten effect contracts from the vitals spec hold for both profiles and for
the theme-switch cue (finite, bounded, non-occluding, deterministic).
Existing buffer/color tests become profile-relative (they assert against the
default vitals profile; distinctness test runs per palette). New tests:
regions() shape for both layouts, rail navigation render, annunciator lamp
lit/clear rendering, hot-swap cycles and repaints cleanly, `--theme` parsing.
Treemap layouter tests pin exact tiling (no overlap, full coverage), area ∝
weight within rounding, minimum tile size, and merge-not-drop; render tests
pin the PRESSURE MAP composition and tile-click targeting.
