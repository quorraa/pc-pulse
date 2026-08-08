use pcpulse_tui::analyzer::{ChatMessage, ChatRole, chat};
use std::sync::{Arc, atomic::AtomicBool};

/// Opt-in release smoke test: requires the installed collector, Codex CLI, and a
/// saved ChatGPT login. Normal offline test runs intentionally skip it.
#[test]
#[ignore = "requires a live PC Pulse service and ChatGPT-authenticated Codex CLI"]
fn embedded_chat_answers_from_live_evidence() {
    let conversation_id = format!("live-smoke-{}", std::process::id());
    let conversation = vec![ChatMessage {
        role: ChatRole::User,
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
        text: "Briefly summarize the strongest sustained performance signal in the current evidence. If none is defensible, say so.".into(),
        evidence_refs: Vec::new(),
        is_error: false,
    }];
    let response = chat(
        &conversation_id,
        &conversation,
        1,
        Arc::new(AtomicBool::new(false)),
    )
    .expect("live embedded chat should complete");
    assert_eq!(response.conversation_id, conversation_id);
    assert!(!response.answer.trim().is_empty());
}
