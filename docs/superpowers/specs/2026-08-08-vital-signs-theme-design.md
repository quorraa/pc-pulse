# PC Pulse "Vital Signs" theme — design

Date: 2026-08-08
Status: proposed (implemented in this session; review welcome)

## Intent

Replace the current "Night signal" (blue/teal/violet) look with a theme that is
unique to PC Pulse rather than generic dark-terminal: a **patient-monitor /
vital-signs** identity. The product is literally named PC Pulse and presents a
workstation's vital telemetry; hospital bedside monitors are the strongest
real-world visual language for "channels of vital signs on a dark screen":
near-black screen, one vivid color per channel (ECG green, SpO2 cyan,
respiration yellow, arterial magenta, alarm red), quiet gray chrome.

Three directions were considered:

1. **Vital-signs monitor** (chosen) — on-brand with the product name, maps
   1:1 onto the existing five accent channels, and gives the effects layer a
   natural motion language (heartbeat pulse, defib flash, monitor boot).
2. Thermal/infrared forensics — striking but collides with the existing
   `ratio_color` heat semantics and reads worse for non-heat data (chat, tree).
3. CRT oscilloscope mono-green — too close to a thousand "hacker green"
   themes; loses the five-channel severity language.

## Constraints discovered in the sweeps

- Palette is 14 `pub(crate) const Color` values at `ui.rs:22-36`; **const
  names must not change** — `effects.rs` imports 9 by name and
  `CellFilter::FgColor(PHOSPHOR|AMETHYST|ICE|AMBER)` matches exact RGB, so
  effects and ui must keep reading the same constants.
- `ui.rs` tests are const-relative but require the 5 accents to stay mutually
  distinct (`night_signal_palette_has_distinct_semantic_channels`).
- Effects contracts (all preserved): finite/event-scoped only, bounded Sample
  scan (header always, body only on Observe, filter limited to the four signal
  colors), no effect may occlude or erase incident rows (`CellFilter::NonEmpty`
  color transforms only), idle clock reset, 50 ms delayed-frame clamp, one
  cleanup frame, unique per-channel effects, deterministic seeded RNG,
  first-snapshot suppression.

## Palette

Same const names, new values ("vital signs" ward palette — green-black glass,
five monitor channels):

| Const | New RGB | Monitor role |
|---|---|---|
| `BG` | 5, 9, 7 | screen glass, near-black with green undertone |
| `SURFACE` | 10, 17, 13 | panel fill |
| `SURFACE_RAISED` | 15, 25, 19 | headers, odd rows, footer, modal |
| `BORDER` | 31, 50, 39 | panel borders |
| `BORDER_HOT` | 52, 82, 64 | rules, active borders |
| `TEXT` | 216, 233, 222 | primary text, green-white |
| `MUTED` | 111, 133, 119 | secondary text |
| `FAINT` | 63, 81, 69 | tertiary, axis labels |
| `PHOSPHOR` | 82, 240, 132 | ECG green — CPU, OK, brand |
| `AMETHYST` | 217, 128, 250 | arterial magenta-violet — memory, agents, active tab |
| `ICE` | 92, 219, 255 | SpO2 cyan — info, system vector |
| `AMBER` | 255, 211, 82 | respiration yellow — warning, latency |
| `CORAL` | 255, 92, 100 | alarm red — critical, destructive |
| `SELECT_BG` | 21, 61, 41 | selection band, deep monitor green |

Identity flourishes (small, restrained):

- Brand chip becomes ` PCPULSE::VITALS ` (was `::NIGHTWATCH`).
- Header link-status dot becomes a `♥` pulse glyph (same three state colors).
- Palette comment/test names renamed from "night signal" to "vital signs".
- Fold `process_header_cell` into `sortable_header_cell` and deduplicate the
  copy-pasted row-highlight style (5 sites) into one helper — targeted cleanup
  in code the theme touches anyway.

## Load-composition pane

New Observe sub-pane: a compact CPU **load composition** view — top suspects'
share of busy CPU plus an "other" remainder, with busy/idle footer lines —
colored from the accent constants. It renders only when its pane is at least
~20×9 cells; below that the pane falls back to the existing text meters.

History: first shipped as a tui-piechart donut; replaced with a proportional
segmented ribbon bar after review showed a braille pie disc is unreadable at
terminal resolution (idle-dominated discs render as a featureless dot field).
The dependency was removed with the swap. Under 2% system CPU the pane
reports "cpu quiescent" instead of drawing a chart.

## Effects: monitor motion language

Same eight channels, same constraints; compositions restyled (all finite):

- **Startup — "monitor boot"**: flatline sweep across the body (horizontal
  sweep in ECG green) into `coalesce`, brand chip resolves with an
  `evolve`-style character reveal. ≤ ~1.2 s total.
- **Critical alert — "defib"**: two short bright pulses (`repeat(2)` of a
  lighten ping-pong) plus the existing bounded glitch; warning/info keep a
  single soft pulse.
- **Page change — "channel switch"**: existing slide plus a very short
  darken dip, evoking a monitor switching leads.
- **Sample cue**: semantics unchanged (bounded, header + Observe body only);
  hue-shift values retuned so the shimmer reads on the green palette.
- Success/failure/footer/modal cues keep their shapes with retuned colors.

## Testing

- `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`
  stay green.
- Existing const-relative buffer tests carry over; distinctness test keeps
  guarding the five channels; effects contract tests (finite startup, bounded
  sample scan, idle clamp, channel uniqueness, disabled idle poll) must pass
  unmodified in behavior even if durations shift.
- New donut gets a `TestBackend` render test (draws without panic, legend
  labels present, falls back below minimum size).
