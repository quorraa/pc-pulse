#![windows_subsystem = "windows"]

fn main() {
    if let Err(error) = pcpulse_tui::notifier::run() {
        let _ = pcpulse_tui::notifier::show_fatal_error(&format!("{error:#}"));
    }
}
