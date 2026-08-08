use crate::analyzer::{ChatMessage, ChatResponse, ChatRole};
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

const MAX_SESSIONS: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatSession {
    pub conversation_id: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub title: String,
    /// True once the user renamed the session: an explicit title outlives
    /// every future derived-title refresh. Absent in files written by older
    /// releases, which is exactly the derived (unpinned) state.
    #[serde(default)]
    pub title_pinned: bool,
    pub messages: Vec<ChatMessage>,
    pub latest_response: Option<ChatResponse>,
}

impl ChatSession {
    pub fn from_conversation(
        conversation_id: String,
        messages: Vec<ChatMessage>,
        latest_response: Option<ChatResponse>,
        previous_created_at_ms: Option<i64>,
        pinned_title: Option<String>,
        now_ms: i64,
    ) -> Self {
        let (title, title_pinned) = match pinned_title {
            Some(title) => (truncate_title(&title, 52), true),
            None => (
                messages
                    .iter()
                    .find(|message| message.role == ChatRole::User)
                    .map(|message| truncate_title(&message.text, 52))
                    .unwrap_or_else(|| "Untitled analysis".into()),
                false,
            ),
        };
        Self {
            conversation_id,
            created_at_ms: previous_created_at_ms.unwrap_or(now_ms),
            updated_at_ms: now_ms,
            title,
            title_pinned,
            messages,
            latest_response,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChatHistoryStore {
    path: PathBuf,
}

impl ChatHistoryStore {
    pub fn discover() -> Option<Self> {
        env::var_os("LOCALAPPDATA").map(|root| Self {
            path: PathBuf::from(root)
                .join("PcPulse")
                .join("chat-history.json"),
        })
    }

    #[cfg(test)]
    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn load(&self) -> Result<Vec<ChatSession>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let payload = fs::read(&self.path)
            .with_context(|| format!("failed to read {}", self.path.display()))?;
        let mut sessions: Vec<ChatSession> = serde_json::from_slice(&payload)
            .with_context(|| format!("failed to parse {}", self.path.display()))?;
        normalize(&mut sessions);
        Ok(sessions)
    }

    pub fn save(&self, sessions: &[ChatSession]) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("chat-history path has no parent")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        let mut bounded = sessions.to_vec();
        normalize(&mut bounded);
        let payload = serde_json::to_vec_pretty(&bounded)?;
        let temporary = self.path.with_extension("json.tmp");
        fs::write(&temporary, payload)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        atomic_replace(&temporary, &self.path)?;
        Ok(())
    }

    pub fn upsert(&self, sessions: &mut Vec<ChatSession>, session: ChatSession) -> Result<()> {
        if let Some(existing) = sessions
            .iter_mut()
            .find(|item| item.conversation_id == session.conversation_id)
        {
            *existing = session;
        } else {
            sessions.push(session);
        }
        normalize(sessions);
        self.save(sessions)
    }
}

fn normalize(sessions: &mut Vec<ChatSession>) {
    for session in sessions.iter_mut() {
        if session.messages.len() > 16 {
            session.messages = session.messages.split_off(session.messages.len() - 16);
        }
        session.title = truncate_title(&session.title, 52);
    }
    sessions.sort_by_key(|session| std::cmp::Reverse(session.updated_at_ms));
    let mut seen = std::collections::HashSet::new();
    sessions.retain(|session| seen.insert(session.conversation_id.clone()));
    sessions.truncate(MAX_SESSIONS);
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

pub(crate) fn truncate_title(value: &str, maximum: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut characters = compact.chars();
    let mut result: String = characters.by_ref().take(maximum).collect();
    if characters.next().is_some() {
        result.push('…');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_round_trips_and_orders_bounded_sessions() {
        let path = env::temp_dir().join(format!(
            "pcpulse-chat-history-test-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_millis()
        ));
        let store = ChatHistoryStore::at(path.clone());
        let mut sessions = Vec::new();
        for index in 0..30 {
            store
                .upsert(
                    &mut sessions,
                    ChatSession::from_conversation(
                        format!("chat-{index}"),
                        vec![ChatMessage {
                            role: ChatRole::User,
                            timestamp_ms: index,
                            text: format!("question {index}"),
                            evidence_refs: Vec::new(),
                            is_error: false,
                        }],
                        None,
                        None,
                        None,
                        index,
                    ),
                )
                .unwrap();
        }
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), MAX_SESSIONS);
        assert_eq!(loaded[0].conversation_id, "chat-29");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn failed_turns_round_trip_through_the_store() {
        let path = env::temp_dir().join(format!(
            "pcpulse-chat-history-failure-test-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_millis()
        ));
        let store = ChatHistoryStore::at(path.clone());
        let mut sessions = Vec::new();
        store
            .upsert(
                &mut sessions,
                ChatSession::from_conversation(
                    "chat-failed".into(),
                    vec![
                        ChatMessage {
                            role: ChatRole::User,
                            timestamp_ms: 1,
                            text: "Why is the disk slow?".into(),
                            evidence_refs: Vec::new(),
                            is_error: false,
                        },
                        ChatMessage {
                            role: ChatRole::Assistant,
                            timestamp_ms: 2,
                            text: "Analysis failed: Codex systems chat timed out after 300s"
                                .into(),
                            evidence_refs: Vec::new(),
                            is_error: true,
                        },
                    ],
                    None,
                    None,
                    None,
                    2,
                ),
            )
            .unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].messages.len(), 2);
        assert!(!loaded[0].messages[0].is_error);
        assert!(loaded[0].messages[1].is_error);
        assert!(loaded[0].messages[1].text.contains("timed out"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn legacy_history_without_error_flag_still_parses() {
        let path = env::temp_dir().join(format!(
            "pcpulse-chat-history-legacy-test-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_millis()
        ));
        // Written by a release that predates the failed-turn flag.
        let legacy_payload = r#"[
            {
                "conversationId": "chat-legacy",
                "createdAtMs": 1,
                "updatedAtMs": 2,
                "title": "old question",
                "messages": [
                    {
                        "role": "user",
                        "timestampMs": 1,
                        "text": "old question",
                        "evidenceRefs": []
                    }
                ],
                "latestResponse": null
            }
        ]"#;
        fs::write(&path, legacy_payload).unwrap();
        let store = ChatHistoryStore::at(path.clone());
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].conversation_id, "chat-legacy");
        assert!(!loaded[0].messages[0].is_error);
        // Files that predate rename support parse as derived (unpinned) titles.
        assert!(!loaded[0].title_pinned);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn explicit_titles_survive_the_store_and_beat_derived_titles() {
        let path = env::temp_dir().join(format!(
            "pcpulse-chat-history-rename-test-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_millis()
        ));
        let store = ChatHistoryStore::at(path.clone());
        let question = ChatMessage {
            role: ChatRole::User,
            timestamp_ms: 1,
            text: "Why did the machine slow down this morning?".into(),
            evidence_refs: Vec::new(),
            is_error: false,
        };
        let mut sessions = Vec::new();
        store
            .upsert(
                &mut sessions,
                ChatSession::from_conversation(
                    "chat-renamed".into(),
                    vec![question.clone()],
                    None,
                    None,
                    Some("Morning slowdown hunt".into()),
                    1,
                ),
            )
            .unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded[0].title, "Morning slowdown hunt");
        assert!(loaded[0].title_pinned, "renames persist as pinned");

        // A later derived-title save (no pin) would revert the name; the
        // caller re-supplies the pinned title, and it wins over derivation.
        store
            .upsert(
                &mut sessions,
                ChatSession::from_conversation(
                    "chat-renamed".into(),
                    vec![question],
                    None,
                    Some(1),
                    Some("Morning slowdown hunt".into()),
                    2,
                ),
            )
            .unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].title, "Morning slowdown hunt");
        assert!(loaded[0].title_pinned);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn pinned_titles_are_bounded_like_derived_ones() {
        let session = ChatSession::from_conversation(
            "chat-long".into(),
            Vec::new(),
            None,
            None,
            Some("x".repeat(90)),
            1,
        );
        assert_eq!(session.title.chars().count(), 53); // 52 + ellipsis
        assert!(session.title.ends_with('…'));
        assert!(session.title_pinned);
    }
}
