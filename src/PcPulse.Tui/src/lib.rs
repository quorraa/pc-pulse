#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod analyzer;
pub mod app;
pub mod chat_history;
pub mod client;
pub mod effects;
pub mod format;
pub mod notifier;
pub mod prefs;
pub mod theme;
pub mod treemap;
pub mod tween;
pub mod ui;
