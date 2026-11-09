//! Manual verification against the *installed* collector service.
//!
//! Run explicitly with `cargo test -p pcpulse-tui --test live_pipe -- --ignored`.
//! On a pre-1.11 service this proves the degrade contract for real: the
//! `live` command comes back as the unknown-command `invalidRequest` error
//! the worker's session-sticky fallback keys on. On a 1.11+ service it
//! proves the happy path instead: a decodable sample that becomes
//! `available` once the loop warms.

use pcpulse_tui::client::PipeClient;

#[test]
#[ignore = "requires the installed PC Pulse collector service"]
fn live_against_the_installed_service_serves_or_degrades_cleanly() {
    match PipeClient.live() {
        Err(error) => {
            // Pre-1.11 service: exactly the error shape the TUI worker
            // detects to stop asking for the session.
            let text = format!("{error:#}");
            assert!(
                text.contains("(invalidRequest)"),
                "an old service must answer live with invalidRequest, got: {text}"
            );
        }
        Ok(first) => {
            // 1.11+ service: the first request may honestly report the
            // warm-up window; within a second the loop must serve data.
            let mut latest = first;
            for _ in 0..8 {
                if latest.available {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(150));
                latest = PipeClient.live().expect("live must keep answering");
            }
            assert!(latest.available, "live loop never warmed up");
            assert!(latest.memory_total_bytes > 0);
            assert!((0.0..=100.0).contains(&latest.cpu_percent));
        }
    }
}

#[test]
#[ignore = "requires the updated installed PC Pulse collector service"]
fn notification_state_uses_a_compact_payload_without_process_telemetry() {
    let state = PipeClient
        .notification_state()
        .expect("compact tray endpoint");
    let settings = PipeClient.settings().expect("settings");
    assert_eq!(state.notifications_enabled, settings.notifications_enabled);
    let compact = serde_json::to_value(&state).unwrap();
    assert!(compact.get("processes").is_none());
    assert!(compact.get("hardware").is_none());
    let snapshot = PipeClient.snapshot().expect("snapshot");
    let compact_bytes = serde_json::to_vec(&state).unwrap().len();
    let snapshot_bytes = serde_json::to_vec(&snapshot).unwrap().len();
    println!("Tray payload: {compact_bytes} bytes; full snapshot: {snapshot_bytes} bytes");
    assert!(compact_bytes < snapshot_bytes);
}
