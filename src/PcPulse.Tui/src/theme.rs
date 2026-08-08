//! Presentation profiles: a theme is a palette plus a structural layout.
//!
//! Two profiles ship: **vitals** (the patient-monitor identity, statusline
//! layout) and **avionics** (an amber-CRT multi-function-display identity,
//! rail layout). The active profile lives in a process-wide atomic so the
//! ~460 color call sites in `ui.rs`/`effects.rs` stay expression-shaped:
//! `palette().text`, `palette().ok`, and so on. Both modules read through
//! the same accessors, which keeps the exact-RGB `CellFilter::FgColor`
//! couplings in the effects layer correct automatically.

use ratatui::style::Color;
use std::sync::atomic::{AtomicU8, Ordering};

/// Semantic palette. Accent mapping from the vitals-era const names:
/// PHOSPHOR→`ok`, AMETHYST→`alt`, ICE→`info`, AMBER→`warn`, CORAL→`crit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    pub bg: Color,
    pub surface: Color,
    pub surface_raised: Color,
    pub border: Color,
    pub border_hot: Color,
    pub text: Color,
    pub muted: Color,
    pub faint: Color,
    pub ok: Color,
    pub alt: Color,
    pub info: Color,
    pub warn: Color,
    pub crit: Color,
    pub select_bg: Color,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThemeId {
    Vitals = 0,
    Avionics = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutKind {
    /// Top header / top tabs / bottom footer (the current structure).
    Statusline,
    /// Left rail + top annunciator strip (avionics MFD structure).
    Rail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub id: ThemeId,
    pub name: &'static str,
    pub palette: Palette,
    pub layout: LayoutKind,
}

/// "Vital signs" ward palette: green-black glass, five monitor channels.
static VITALS: Theme = Theme {
    id: ThemeId::Vitals,
    name: "vitals",
    layout: LayoutKind::Statusline,
    palette: Palette {
        bg: Color::Rgb(5, 9, 7),
        surface: Color::Rgb(10, 17, 13),
        surface_raised: Color::Rgb(15, 25, 19),
        border: Color::Rgb(31, 50, 39),
        border_hot: Color::Rgb(52, 82, 64),
        text: Color::Rgb(216, 233, 222),
        muted: Color::Rgb(111, 133, 119),
        faint: Color::Rgb(63, 81, 69),
        ok: Color::Rgb(82, 240, 132),
        alt: Color::Rgb(217, 128, 250),
        info: Color::Rgb(92, 219, 255),
        warn: Color::Rgb(255, 211, 82),
        crit: Color::Rgb(255, 92, 100),
        select_bg: Color::Rgb(21, 61, 41),
    },
};

/// Amber-CRT avionics glass: near-black amber-tinted bg, amber-white text,
/// dim amber chrome, avionics-green/magenta/cyan/amber/red accents.
static AVIONICS: Theme = Theme {
    id: ThemeId::Avionics,
    name: "avionics",
    layout: LayoutKind::Rail,
    palette: Palette {
        bg: Color::Rgb(8, 6, 0),
        surface: Color::Rgb(14, 11, 2),
        surface_raised: Color::Rgb(20, 16, 4),
        border: Color::Rgb(60, 48, 12),
        border_hot: Color::Rgb(94, 76, 20),
        text: Color::Rgb(255, 220, 150),
        muted: Color::Rgb(150, 122, 66),
        faint: Color::Rgb(92, 74, 38),
        ok: Color::Rgb(96, 240, 128),
        alt: Color::Rgb(255, 96, 255),
        info: Color::Rgb(0, 214, 255),
        warn: Color::Rgb(255, 168, 0),
        crit: Color::Rgb(255, 72, 72),
        select_bg: Color::Rgb(64, 48, 8),
    },
};

/// Every shipped profile, in cycle order.
pub static ALL: [&Theme; 2] = [&VITALS, &AVIONICS];

static ACTIVE: AtomicU8 = AtomicU8::new(ThemeId::Vitals as u8);

/// The active presentation profile.
pub fn active() -> &'static Theme {
    match ACTIVE.load(Ordering::Relaxed) {
        1 => &AVIONICS,
        _ => &VITALS,
    }
}

/// The active profile's palette (the hot path for every styled cell).
pub fn palette() -> &'static Palette {
    &active().palette
}

pub fn set_active(id: ThemeId) {
    ACTIVE.store(id as u8, Ordering::Relaxed);
}

/// Advance to the next profile in [`ALL`] order and return it.
pub fn cycle() -> &'static Theme {
    let next = match active().id {
        ThemeId::Vitals => ThemeId::Avionics,
        ThemeId::Avionics => ThemeId::Vitals,
    };
    set_active(next);
    active()
}

impl std::str::FromStr for ThemeId {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        ALL.iter()
            .find(|theme| theme.name.eq_ignore_ascii_case(input))
            .map(|theme| theme.id)
            .ok_or_else(|| format!("unknown theme \"{input}\""))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Tests share one process, and the active theme is process-wide state.
    //! Every test that renders or asserts palette colors must hold this
    //! guard: it serializes theme-dependent tests and restores the default
    //! vitals profile when dropped.

    use super::{ThemeId, set_active};
    use std::sync::{Mutex, MutexGuard, PoisonError};

    static LOCK: Mutex<()> = Mutex::new(());

    pub(crate) struct ThemeGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for ThemeGuard {
        fn drop(&mut self) {
            set_active(ThemeId::Vitals);
        }
    }

    pub(crate) fn activate(id: ThemeId) -> ThemeGuard {
        let lock = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        set_active(id);
        ThemeGuard { _lock: lock }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_names_parse_for_the_cli_flag() {
        assert_eq!("vitals".parse::<ThemeId>(), Ok(ThemeId::Vitals));
        assert_eq!("avionics".parse::<ThemeId>(), Ok(ThemeId::Avionics));
        assert_eq!("AVIONICS".parse::<ThemeId>(), Ok(ThemeId::Avionics));
        assert!("nightwatch".parse::<ThemeId>().is_err());
        assert!("".parse::<ThemeId>().is_err());
    }

    #[test]
    fn cycle_walks_the_profiles_in_order_and_wraps() {
        let _guard = test_support::activate(ThemeId::Vitals);
        assert_eq!(active().id, ThemeId::Vitals);
        assert_eq!(cycle().id, ThemeId::Avionics);
        assert_eq!(active().layout, LayoutKind::Rail);
        assert_eq!(cycle().id, ThemeId::Vitals);
        assert_eq!(active().layout, LayoutKind::Statusline);
    }

    #[test]
    fn both_palettes_keep_five_distinct_accent_channels() {
        for theme in ALL {
            let p = theme.palette;
            let channels = [p.ok, p.alt, p.info, p.warn, p.crit];
            for (index, color) in channels.iter().enumerate() {
                assert!(
                    !channels[..index].contains(color),
                    "{}: accent {index} duplicates an earlier channel",
                    theme.name
                );
            }
            assert_ne!(p.bg, p.surface, "{}", theme.name);
            assert_ne!(p.surface, p.surface_raised, "{}", theme.name);
            assert_ne!(p.text, p.muted, "{}", theme.name);
            assert_ne!(p.border, p.border_hot, "{}", theme.name);
        }
    }

    #[test]
    fn both_palettes_keep_readable_contrast_on_surfaces() {
        for theme in ALL {
            let p = theme.palette;
            assert!(
                contrast(p.text, p.surface) >= 7.0,
                "{}: text on surface contrast {:.2}",
                theme.name,
                contrast(p.text, p.surface)
            );
            assert!(
                contrast(p.muted, p.surface) >= 3.0,
                "{}: muted on surface contrast {:.2}",
                theme.name,
                contrast(p.muted, p.surface)
            );
            for (label, accent) in [
                ("ok", p.ok),
                ("alt", p.alt),
                ("info", p.info),
                ("warn", p.warn),
                ("crit", p.crit),
            ] {
                assert!(
                    contrast(accent, p.bg) >= 3.0,
                    "{}: {label} on bg contrast {:.2}",
                    theme.name,
                    contrast(accent, p.bg)
                );
            }
        }
    }

    /// WCAG relative-luminance contrast ratio.
    fn contrast(a: Color, b: Color) -> f64 {
        let (lighter, darker) = if luminance(a) >= luminance(b) {
            (luminance(a), luminance(b))
        } else {
            (luminance(b), luminance(a))
        };
        (lighter + 0.05) / (darker + 0.05)
    }

    fn luminance(color: Color) -> f64 {
        let Color::Rgb(r, g, b) = color else {
            panic!("palette colors are always Color::Rgb");
        };
        fn channel(value: u8) -> f64 {
            let v = f64::from(value) / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        }
        0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
    }
}
