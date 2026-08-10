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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UiPrefs {
    #[serde(with = "theme_name")]
    pub theme: ThemeId,
    pub effects: bool,
    pub analyzer_timeout_secs: u64,
}

impl Default for UiPrefs {
    fn default() -> Self {
        Self {
            theme: ThemeId::Vitals,
            effects: true,
            analyzer_timeout_secs: DEFAULT_ANALYZER_TIMEOUT_SECS,
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
        let payload = serde_json::to_vec_pretty(&prefs.normalized())?;
        let temporary = self.path.with_extension("json.tmp");
        fs::write(&temporary, payload)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        atomic_replace(&temporary, &self.path)
    }
}

fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
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
        };
        store.save(&prefs).unwrap();
        assert_eq!(store.load(), prefs);
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"avionics\""));
        assert!(raw.contains("analyzerTimeoutSecs"));
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
