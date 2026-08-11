//! Per-user terminal-client preferences.
//!
//! A small JSON document at `%LOCALAPPDATA%\PcPulse\ui-prefs.json` remembers
//! the choices that belong to this user's terminal rather than to the
//! collector service: the presentation profile, the motion-effects switch,
//! and the Oracle analysis time budget. Loading is tolerant — a missing,
//! corrupt, or partially unknown file falls back to defaults field by field —
//! and saving uses the same write-then-atomically-replace pattern as the chat
//! history store. CLI flags (`--theme`, `--no-effects`) override the stored
//! values for one run via [`UiPrefs::overridden`] without rewriting the file;
//! only an explicit in-app choice (`t`, `m`, or a TUNE edit) persists.

use crate::theme::ThemeId;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};
use windows::{
    Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW},
    core::PCWSTR,
};

/// Bounds mirrored from the analyzer's `PCPULSE_ANALYZER_TIMEOUT_SECS`
/// clamp so a stored preference can never widen the accepted range.
pub const MIN_ANALYZER_TIMEOUT_SECS: u64 = 30;
pub const MAX_ANALYZER_TIMEOUT_SECS: u64 = 1_800;
pub const DEFAULT_ANALYZER_TIMEOUT_SECS: u64 = 300;

/// Bounds for the background-video dim percentage: how much the video is
/// darkened toward the theme background so foreground text stays legible.
pub const MIN_BACKGROUND_DIM: u8 = 10;
pub const MAX_BACKGROUND_DIM: u8 = 60;
pub const DEFAULT_BACKGROUND_DIM: u8 = 30;

/// Bounds for a fixed background-video playback rate; `0` is the sentinel
/// meaning "use the clip's own capture fps" and is left untouched by the
/// clamp.
pub const MIN_BACKGROUND_FPS: u32 = 1;
pub const MAX_BACKGROUND_FPS: u32 = 60;

/// Normalize a stored refresh-rate preference to the supported tiers:
/// `0` stays event-driven, everything else snaps to 30 or 60 fps.
pub fn normalize_refresh_fps(fps: u32) -> u32 {
    match fps {
        0 => 0,
        1..=45 => 30,
        _ => 60,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UiPrefs {
    #[serde(with = "theme_name")]
    pub theme: ThemeId,
    pub effects: bool,
    pub analyzer_timeout_secs: u64,
    /// Smooth-refresh rate: `0` = event-driven (default), else 30 or 60 fps
    /// fixed-cadence drawing with tweened meters.
    pub refresh_fps: u32,
    /// Whether the TUI may ask GitHub for a newer release at launch. Off
    /// means no update-related network request is ever made.
    pub update_checks: bool,
    /// When the last release check completed (Unix ms); launches within the
    /// 20-hour cadence window skip the check entirely.
    pub last_update_check_ms: i64,
    /// Source path of the video clip painted behind the UI; empty means no
    /// background has been set yet.
    pub background_video: String,
    /// Whether the configured background video is drawn. Only meaningful
    /// once `background_video` names a clip.
    pub background_enabled: bool,
    /// How much the background video is darkened toward the theme's
    /// background color, as a percent; higher keeps foreground text legible.
    pub background_dim: u8,
    /// Playback rate for the background video, in frames per second; `0`
    /// means "use the clip's own capture fps" instead of a fixed rate.
    pub background_fps: u32,
}

impl Default for UiPrefs {
    fn default() -> Self {
        Self {
            theme: ThemeId::Vitals,
            effects: true,
            analyzer_timeout_secs: DEFAULT_ANALYZER_TIMEOUT_SECS,
            refresh_fps: 0,
            update_checks: true,
            last_update_check_ms: 0,
            background_video: String::new(),
            background_enabled: true,
            background_dim: DEFAULT_BACKGROUND_DIM,
            background_fps: 0,
        }
    }
}

impl UiPrefs {
    /// The preferences in force for this run after CLI overrides. Flags win
    /// for the session but are never written back to disk.
    pub fn overridden(mut self, cli_theme: Option<ThemeId>, cli_effects_off: bool) -> Self {
        if let Some(theme) = cli_theme {
            self.theme = theme;
        }
        if cli_effects_off {
            self.effects = false;
        }
        self
    }

    fn normalized(mut self) -> Self {
        self.analyzer_timeout_secs = self
            .analyzer_timeout_secs
            .clamp(MIN_ANALYZER_TIMEOUT_SECS, MAX_ANALYZER_TIMEOUT_SECS);
        self.refresh_fps = normalize_refresh_fps(self.refresh_fps);
        self.background_dim = self
            .background_dim
            .clamp(MIN_BACKGROUND_DIM, MAX_BACKGROUND_DIM);
        if self.background_fps != 0 {
            self.background_fps = self
                .background_fps
                .clamp(MIN_BACKGROUND_FPS, MAX_BACKGROUND_FPS);
        }
        self
    }
}

/// Theme identifiers travel as their CLI names (`"vitals"` / `"avionics"` /
/// `"ledger"`).
/// An unknown name — perhaps written by a newer release — degrades to the
/// default profile instead of poisoning the whole document.
mod theme_name {
    use crate::theme::ThemeId;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(id: &ThemeId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(id.name())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<ThemeId, D::Error> {
        let name = String::deserialize(deserializer)?;
        Ok(name.parse().unwrap_or(ThemeId::Vitals))
    }
}

#[derive(Debug, Clone)]
pub struct PrefsStore {
    path: PathBuf,
}

impl PrefsStore {
    pub fn discover() -> Option<Self> {
        env::var_os("LOCALAPPDATA").map(|root| Self {
            path: PathBuf::from(root).join("PcPulse").join("ui-prefs.json"),
        })
    }

    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load the stored preferences; a missing, unreadable, or corrupt file
    /// yields the defaults, and the timeout is always re-clamped.
    pub fn load(&self) -> UiPrefs {
        fs::read(&self.path)
            .ok()
            .and_then(|payload| serde_json::from_slice::<UiPrefs>(&payload).ok())
            .unwrap_or_default()
            .normalized()
    }

    pub fn save(&self, prefs: &UiPrefs) -> Result<()> {
        let parent = self.path.parent().context("ui-prefs path has no parent")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        let payload = serde_json::to_vec_pretty(&prefs.clone().normalized())?;
        let temporary = self.path.with_extension("json.tmp");
        fs::write(&temporary, payload)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        atomic_replace(&temporary, &self.path)
    }
}

/// Commit `source` onto `destination` in one step, replacing whatever was
/// there. This is the crate's write-then-replace primitive: `ClipWriter`
/// commits a converted background the same way this store commits prefs, so
/// an interrupted write can never be observed as a half-written file.
pub(crate) fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        MoveFileExW(
            PCWSTR(source_wide.as_ptr()),
            PCWSTR(destination_wide.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .with_context(|| format!("failed to commit {}", destination.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_store(tag: &str) -> (PrefsStore, PathBuf) {
        let path = env::temp_dir().join(format!(
            "pcpulse-ui-prefs-{tag}-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_millis()
        ));
        (PrefsStore::at(path.clone()), path)
    }

    #[test]
    fn preferences_round_trip_through_disk() {
        let (store, path) = scratch_store("roundtrip");
        let prefs = UiPrefs {
            theme: ThemeId::Avionics,
            effects: false,
            analyzer_timeout_secs: 600,
            refresh_fps: 30,
            update_checks: false,
            last_update_check_ms: 1_800_000_000_000,
            background_video: "C:\\clips\\demo.pulseclip".to_string(),
            background_enabled: false,
            background_dim: 45,
            background_fps: 24,
        };
        store.save(&prefs).unwrap();
        assert_eq!(store.load(), prefs);
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"avionics\""));
        assert!(raw.contains("analyzerTimeoutSecs"));
        assert!(raw.contains("refreshFps"));
        assert!(raw.contains("updateChecks"));
        assert!(raw.contains("lastUpdateCheckMs"));
        assert!(raw.contains("backgroundVideo"));
        assert!(raw.contains("backgroundEnabled"));
        assert!(raw.contains("backgroundDim"));
        assert!(raw.contains("backgroundFps"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn ledger_theme_name_persists_round_trip() {
        let (store, path) = scratch_store("ledger");
        store
            .save(&UiPrefs {
                theme: ThemeId::Ledger,
                ..UiPrefs::default()
            })
            .unwrap();
        assert_eq!(store.load().theme, ThemeId::Ledger);
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"ledger\""));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn cli_overrides_apply_for_the_run_without_touching_the_stored_file() {
        let (store, path) = scratch_store("cli-override");
        let stored = UiPrefs {
            theme: ThemeId::Avionics,
            effects: true,
            analyzer_timeout_secs: 450,
            refresh_fps: 60,
            ..UiPrefs::default()
        };
        store.save(&stored).unwrap();
        let effective = store.load().overridden(Some(ThemeId::Vitals), true);
        assert_eq!(effective.theme, ThemeId::Vitals);
        assert!(!effective.effects);
        assert_eq!(effective.analyzer_timeout_secs, 450);
        // The file still carries the user's persisted choices.
        assert_eq!(store.load(), stored);
        // Absent flags change nothing.
        assert_eq!(store.load().overridden(None, false), stored);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn missing_or_corrupt_files_fall_back_to_defaults() {
        let (store, _) = scratch_store("missing");
        assert_eq!(store.load(), UiPrefs::default());
        let (store, path) = scratch_store("corrupt");
        fs::write(&path, b"{not json at all").unwrap();
        assert_eq!(store.load(), UiPrefs::default());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unknown_fields_and_unknown_theme_names_are_tolerated() {
        let (store, path) = scratch_store("tolerant");
        fs::write(
            &path,
            br#"{ "theme": "nightwatch", "futureKnob": 42, "analyzerTimeoutSecs": 900 }"#,
        )
        .unwrap();
        let prefs = store.load();
        assert_eq!(prefs.theme, ThemeId::Vitals, "unknown theme degrades");
        assert!(prefs.effects, "missing field keeps its default");
        assert_eq!(prefs.analyzer_timeout_secs, 900);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn refresh_fps_round_trips_and_clamps_to_supported_tiers() {
        assert_eq!(normalize_refresh_fps(0), 0);
        assert_eq!(normalize_refresh_fps(1), 30);
        assert_eq!(normalize_refresh_fps(30), 30);
        assert_eq!(normalize_refresh_fps(45), 30);
        assert_eq!(normalize_refresh_fps(46), 60);
        assert_eq!(normalize_refresh_fps(60), 60);
        assert_eq!(normalize_refresh_fps(240), 60);
        let (store, path) = scratch_store("refresh");
        store
            .save(&UiPrefs {
                refresh_fps: 60,
                ..UiPrefs::default()
            })
            .unwrap();
        assert_eq!(store.load().refresh_fps, 60);
        // A hand-edited or future value snaps to a supported tier on load,
        // and an absent field keeps the event-driven default.
        fs::write(&path, br#"{ "refreshFps": 144 }"#).unwrap();
        assert_eq!(store.load().refresh_fps, 60);
        fs::write(&path, br#"{ "refreshFps": 15 }"#).unwrap();
        assert_eq!(store.load().refresh_fps, 30);
        fs::write(&path, br#"{ "theme": "vitals" }"#).unwrap();
        assert_eq!(store.load().refresh_fps, 0);
        // Saving clamps too: the file never carries an unsupported tier.
        store
            .save(&UiPrefs {
                refresh_fps: 200,
                ..UiPrefs::default()
            })
            .unwrap();
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("\"refreshFps\": 60")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn update_check_prefs_round_trip_and_default_to_on() {
        // Absent fields (files written by pre-v1.16 releases) mean checks
        // are on and never performed yet.
        let (store, path) = scratch_store("updates");
        fs::write(&path, br#"{ "theme": "vitals" }"#).unwrap();
        let prefs = store.load();
        assert!(prefs.update_checks, "the toggle defaults to on");
        assert_eq!(prefs.last_update_check_ms, 0);
        // An explicit off and a stamped check time survive the round trip.
        store
            .save(&UiPrefs {
                update_checks: false,
                last_update_check_ms: 1_755_000_000_123,
                ..UiPrefs::default()
            })
            .unwrap();
        let reloaded = store.load();
        assert!(!reloaded.update_checks);
        assert_eq!(reloaded.last_update_check_ms, 1_755_000_000_123);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn pre_background_prefs_files_gain_background_defaults() {
        let old = r#"{"theme":"ledger","effects":false,"analyzerTimeoutSecs":120,"refreshFps":60,"updateChecks":true,"lastUpdateCheckMs":5}"#;
        let prefs: UiPrefs = serde_json::from_str(old).unwrap();
        assert_eq!(prefs.background_video, "");
        assert!(prefs.background_enabled);
        assert_eq!(prefs.background_dim, 30);
        assert_eq!(prefs.background_fps, 0);
        assert_eq!(prefs.theme, ThemeId::Ledger); // untouched fields survive
    }

    #[test]
    fn normalized_clamps_background_dim_and_fps() {
        let mut prefs = UiPrefs {
            background_dim: 95,
            background_fps: 240,
            ..UiPrefs::default()
        };
        prefs = prefs.normalized();
        assert_eq!(prefs.background_dim, 60);
        assert_eq!(prefs.background_fps, 60);
        let mut low = UiPrefs {
            background_dim: 3,
            background_fps: 0,
            ..UiPrefs::default()
        };
        low = low.normalized();
        assert_eq!(low.background_dim, 10);
        assert_eq!(low.background_fps, 0); // sentinel survives normalization
    }

    #[test]
    fn analyzer_timeout_is_clamped_on_load_and_save() {
        let (store, path) = scratch_store("clamp");
        fs::write(&path, br#"{ "analyzerTimeoutSecs": 5 }"#).unwrap();
        assert_eq!(
            store.load().analyzer_timeout_secs,
            MIN_ANALYZER_TIMEOUT_SECS
        );
        store
            .save(&UiPrefs {
                analyzer_timeout_secs: 1_000_000,
                ..UiPrefs::default()
            })
            .unwrap();
        assert_eq!(
            store.load().analyzer_timeout_secs,
            MAX_ANALYZER_TIMEOUT_SECS
        );
        let _ = fs::remove_file(path);
    }
}
