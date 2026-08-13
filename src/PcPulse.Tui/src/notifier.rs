use crate::{client::PipeClient, format};
use anyhow::{Context, Result, bail};
use pcpulse_service::models::{Alert, Severity};
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use windows::{
    Win32::{
        Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            Shell::{
                NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIIF_WARNING,
                NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW, Shell_NotifyIconW,
            },
            WindowsAndMessaging::{
                CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DispatchMessageW,
                GetMessageW, GetSystemMetrics, HICON, HWND_MESSAGE, IDI_INFORMATION, IMAGE_ICON,
                LR_DEFAULTCOLOR, LoadIconW, LoadImageW, MSG, PostQuitMessage, RegisterClassW,
                SM_CXSMICON, SM_CYSMICON, TranslateMessage, WINDOW_EX_STYLE, WM_APP, WM_CLOSE,
                WM_DESTROY, WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_RBUTTONUP, WNDCLASSW, WS_OVERLAPPED,
            },
        },
    },
    core::{PCWSTR, w},
};

const ICON_ID: u32 = 1;
/// Resource id of the icon embedded by build.rs: winresource registers
/// docs/media/pcpulse.ico as the executable's first icon resource with the
/// numeric id 1 (`1 ICON "pcpulse.ico"` in its generated resource script).
const TRAY_ICON_RESOURCE_ID: usize = 1;
const CALLBACK_MESSAGE: u32 = WM_APP + 42;
static EXITING: AtomicBool = AtomicBool::new(false);

pub fn run() -> Result<()> {
    EXITING.store(false, Ordering::Release);
    let module = unsafe { GetModuleHandleW(None) }.context("GetModuleHandleW failed")?;
    let instance = HINSTANCE(module.0);
    let class_name = w!("PcPulseNotificationWindow");
    let class = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        lpszClassName: class_name,
        ..Default::default()
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        bail!(
            "RegisterClassW failed: {}",
            windows::core::Error::from_thread()
        );
    }
    let window = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_name,
            w!("PC Pulse notifications"),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(instance),
            None,
        )
    }
    .context("CreateWindowExW failed")?;
    add_icon(window)?;

    let stopping = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stopping);
    let window_address = window.0 as usize;
    let worker = thread::Builder::new()
        .name("pcpulse-notifications".into())
        .spawn(move || poll_alerts(HWND(window_address as *mut std::ffi::c_void), worker_stop))?;

    let mut message = MSG::default();
    while unsafe { GetMessageW(&mut message, None, 0, 0) }.as_bool() {
        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    stopping.store(true, Ordering::Release);
    let _ = worker.join();
    delete_icon(window);
    Ok(())
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        CALLBACK_MESSAGE => match lparam.0 as u32 {
            WM_LBUTTONUP | WM_LBUTTONDBLCLK => {
                open_tui();
                LRESULT(0)
            }
            WM_RBUTTONUP => {
                EXITING.store(true, Ordering::Release);
                unsafe { PostQuitMessage(0) };
                LRESULT(0)
            }
            _ => LRESULT(0),
        },
        WM_CLOSE | WM_DESTROY => {
            EXITING.store(true, Ordering::Release);
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(window, message, wparam, lparam) },
    }
}

fn load_tray_icon() -> Result<HICON> {
    // Prefer the PC Pulse badge icon embedded in this executable's resources.
    if let Ok(module) = unsafe { GetModuleHandleW(None) } {
        let embedded = unsafe {
            LoadImageW(
                Some(HINSTANCE(module.0)),
                PCWSTR(TRAY_ICON_RESOURCE_ID as *const u16),
                IMAGE_ICON,
                GetSystemMetrics(SM_CXSMICON),
                GetSystemMetrics(SM_CYSMICON),
                LR_DEFAULTCOLOR,
            )
        };
        if let Ok(handle) = embedded
            && !handle.is_invalid()
        {
            return Ok(HICON(handle.0));
        }
    }
    // Fallback: the stock information icon, as before branding.
    unsafe { LoadIconW(None, IDI_INFORMATION) }.context("LoadIconW failed")
}

fn add_icon(window: HWND) -> Result<()> {
    let mut data = base_icon_data(window);
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    data.hIcon = load_tray_icon()?;
    copy_wide(
        &mut data.szTip,
        "PC Pulse — double-click to open; right-click to exit",
    );
    if !unsafe { Shell_NotifyIconW(NIM_ADD, &data) }.as_bool() {
        bail!("Shell_NotifyIconW(NIM_ADD) failed");
    }
    Ok(())
}

fn delete_icon(window: HWND) {
    let data = base_icon_data(window);
    unsafe {
        let _ = Shell_NotifyIconW(NIM_DELETE, &data);
    }
}

fn base_icon_data(window: HWND) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: window,
        uID: ICON_ID,
        uCallbackMessage: CALLBACK_MESSAGE,
        ..Default::default()
    }
}

fn poll_alerts(window: HWND, stopping: Arc<AtomicBool>) {
    let client = PipeClient;
    let mut seen = HashSet::new();
    let mut initialized = false;
    let mut failures = 0_u32;
    let mut notifications_enabled = true;
    let mut settings_counter = 0_u32;
    while !stopping.load(Ordering::Acquire) && !EXITING.load(Ordering::Acquire) {
        if settings_counter == 0 {
            if let Ok(settings) = client.settings() {
                notifications_enabled = settings.notifications_enabled;
            }
            settings_counter = 15;
        }
        settings_counter = settings_counter.saturating_sub(1);
        match client.snapshot() {
            Ok(snapshot) => {
                if failures >= 3 && notifications_enabled {
                    show_balloon(
                        window,
                        "PC Pulse collector reconnected",
                        "Live performance attribution has resumed.",
                        Severity::Info,
                    );
                }
                failures = 0;
                let pending =
                    pending_notifications(&snapshot.active_alerts, &mut seen, initialized);
                if notifications_enabled {
                    for alert in pending {
                        notify_alert(window, alert);
                    }
                }
                initialized = true;
            }
            Err(_) => {
                failures = failures.saturating_add(1);
                if failures == 3 && notifications_enabled {
                    show_balloon(
                        window,
                        "PC Pulse collector is offline",
                        "The notification helper will keep retrying. Open PC Pulse for service details.",
                        Severity::Warning,
                    );
                }
            }
        }
        for _ in 0..20 {
            if stopping.load(Ordering::Acquire) || EXITING.load(Ordering::Acquire) {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

/// One tray-notification identity. The tray pops once per incident *and*
/// notification generation, so bumping the generation (the service's renotify
/// signal) re-pops a live incident and nothing else does.
type NotificationKey = (String, u32);

fn notification_key(alert: &Alert) -> NotificationKey {
    (alert.id.clone(), alert.notify_generation)
}

/// Ceiling on remembered notifications before the poller forgets everything
/// no longer on screen. Distinct incidents arrive at a rate of a few a day on
/// a struggling machine, so this is a safety valve, not a working limit.
const SEEN_CAP: usize = 512;

/// Which active findings should pop a balloon this poll, updating what the
/// poller has seen.
///
/// Extracted from [`poll_alerts`] so the policy is testable without a window
/// handle or a live collector -- the rest of that loop is Win32 plumbing.
///
/// A finding pops when the service marked it notifiable (`notify`), the user
/// has not acknowledged or archived it, and this `(id, generation)` pair is
/// new. Old-service compatibility rides on the model defaults: a record
/// without the calibration fields deserializes as `notify = true,
/// notify_generation = 0`, which is exactly the pre-calibration behavior.
fn pending_notifications<'a>(
    active: &'a [Alert],
    seen: &mut HashSet<NotificationKey>,
    initialized: bool,
) -> Vec<&'a Alert> {
    let pending: Vec<&Alert> = if initialized {
        active
            .iter()
            // Acknowledged and archived findings are both deliberate user
            // decisions; neither pops a balloon.
            .filter(|alert| {
                alert.notify
                    && !alert.acknowledged
                    && !alert.archived
                    && !seen.contains(&notification_key(alert))
            })
            .collect()
    } else {
        Vec::new()
    };
    // Remember only what the service considers notifiable. A suppressed
    // finding is deliberately not recorded: when its quality later clears the
    // notification floor it has to pop, even though its generation never
    // changed.
    //
    // The memory outlives the finding on purpose. An incident that resolves
    // and reopens inside the service's quiet period comes back with the same
    // id and the same generation, and reopening is deliberately silent -- a
    // per-poll snapshot of what is on screen would have forgotten it and
    // popped the same balloon twice.
    for alert in active.iter().filter(|alert| alert.notify) {
        seen.insert(notification_key(alert));
    }
    if seen.len() > SEEN_CAP {
        // A safety valve, not a policy: drop everything that is not still on
        // screen rather than growing without bound across a long session.
        let live: HashSet<&str> = active.iter().map(|alert| alert.id.as_str()).collect();
        seen.retain(|(id, _)| live.contains(id.as_str()));
    }
    pending
}

fn notify_alert(window: HWND, alert: &Alert) {
    let owner = alert
        .process_name
        .as_ref()
        .map(|name| format!("{name} · PID {}", alert.process_id.unwrap_or(0)))
        .unwrap_or_else(|| "System / driver".into());
    let body = format!("{owner}\n{}\n{}", alert.explanation, alert.recommendation);
    show_balloon(
        window,
        &alert.title,
        &format::truncate(&body, 250),
        alert.severity,
    );
}

fn show_balloon(window: HWND, title: &str, body: &str, severity: Severity) {
    let mut data = base_icon_data(window);
    data.uFlags = NIF_INFO;
    copy_wide(&mut data.szInfoTitle, &format::truncate(title, 62));
    copy_wide(&mut data.szInfo, &format::truncate(body, 250));
    data.dwInfoFlags = match severity {
        Severity::Info => NIIF_INFO,
        Severity::Warning => NIIF_WARNING,
        Severity::Critical => NIIF_ERROR,
    };
    unsafe {
        let _ = Shell_NotifyIconW(NIM_MODIFY, &data);
    }
}

fn copy_wide<const N: usize>(target: &mut [u16; N], value: &str) {
    target.fill(0);
    for (slot, character) in target
        .iter_mut()
        .take(N.saturating_sub(1))
        .zip(value.encode_utf16())
    {
        *slot = character;
    }
}

fn open_tui() {
    let Ok(mut path) = std::env::current_exe() else {
        return;
    };
    path.set_file_name("PcPulse.exe");
    // ShellExecuteW, not Command::spawn: this helper is a GUI process with
    // no console, and std::process hands its (invalid) stdio handles to the
    // child — the TUI then draws into nothing while its fresh console sits
    // blank. An Explorer-style launch gives the console app clean handles.
    let wide_path = wide(&path.to_string_lossy());
    unsafe {
        use windows::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};
        ShellExecuteW(
            None,
            PCWSTR::null(),
            PCWSTR(wide_path.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }
}

pub fn show_fatal_error(message: &str) -> Result<()> {
    use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    let title = wide("PC Pulse notification helper");
    let body = wide(message);
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcpulse_service::models::{AlertQuality, IncidentState};

    fn alert(id: &str) -> Alert {
        Alert {
            id: id.into(),
            kind: "sustainedCpu".into(),
            severity: Severity::Warning,
            first_seen_ms: 0,
            last_seen_ms: 0,
            process_id: Some(42),
            process_name: Some("worker.exe".into()),
            title: "Sustained CPU usage".into(),
            explanation: String::new(),
            evidence: Vec::new(),
            recommendation: String::new(),
            acknowledged: false,
            occurrence_count: 1,
            resolved_at_ms: None,
            archived: false,
            fingerprint: "sustainedCpu:42:1".into(),
            state: IncidentState::Open,
            quality: AlertQuality::default(),
            notify: true,
            notify_generation: 0,
        }
    }

    fn ids(pending: Vec<&Alert>) -> Vec<String> {
        pending.iter().map(|alert| alert.id.clone()).collect()
    }

    #[test]
    fn the_first_poll_primes_without_popping() {
        let mut seen = HashSet::new();
        let active = vec![alert("a"), alert("b")];
        assert!(pending_notifications(&active, &mut seen, false).is_empty());
        // Everything present at startup is now remembered, so the next poll
        // stays quiet too.
        assert!(pending_notifications(&active, &mut seen, true).is_empty());
    }

    #[test]
    fn a_notifiable_finding_pops_once_and_not_again() {
        let mut seen = HashSet::new();
        pending_notifications(&[], &mut seen, false);
        let active = vec![alert("a")];
        assert_eq!(ids(pending_notifications(&active, &mut seen, true)), ["a"]);
        assert!(pending_notifications(&active, &mut seen, true).is_empty());
    }

    #[test]
    fn a_generation_bump_pops_the_same_incident_again() {
        let mut seen = HashSet::new();
        let mut active = vec![alert("a")];
        pending_notifications(&active, &mut seen, false);
        assert!(pending_notifications(&active, &mut seen, true).is_empty());
        // The service escalated (or the fingerprint materially changed) and
        // bumped the generation: the same incident earns a fresh balloon.
        active[0].notify_generation = 1;
        assert_eq!(ids(pending_notifications(&active, &mut seen, true)), ["a"]);
        assert!(pending_notifications(&active, &mut seen, true).is_empty());
        // Nothing else about the record re-pops it.
        active[0].occurrence_count = 99;
        active[0].last_seen_ms = 500;
        active[0].quality.confidence = 0.9;
        assert!(pending_notifications(&active, &mut seen, true).is_empty());
    }

    #[test]
    fn a_suppressed_finding_stays_silent_until_the_service_marks_it_notifiable() {
        let mut seen = HashSet::new();
        let mut active = vec![alert("a")];
        active[0].notify = false;
        pending_notifications(&active, &mut seen, false);
        for _ in 0..3 {
            assert!(pending_notifications(&active, &mut seen, true).is_empty());
        }
        // Its quality cleared the floor. The generation never moved, so the
        // poller must not have banked this pair while it was suppressed.
        active[0].notify = true;
        assert_eq!(ids(pending_notifications(&active, &mut seen, true)), ["a"]);
        assert!(pending_notifications(&active, &mut seen, true).is_empty());
    }

    #[test]
    fn a_reopened_incident_the_user_already_saw_stays_silent() {
        let mut seen = HashSet::new();
        pending_notifications(&[], &mut seen, false);
        let active = vec![alert("a")];
        assert_eq!(ids(pending_notifications(&active, &mut seen, true)), ["a"]);
        // It resolves and leaves the snapshot for a while.
        for _ in 0..3 {
            assert!(pending_notifications(&[], &mut seen, true).is_empty());
        }
        // The service reopens it inside the quiet period: same incident, same
        // generation, and the user has already been told about it.
        assert!(pending_notifications(&active, &mut seen, true).is_empty());
        // A refire past the quiet period is a new incident with a new id, and
        // that is news.
        let fresh = vec![alert("b")];
        assert_eq!(ids(pending_notifications(&fresh, &mut seen, true)), ["b"]);
    }

    #[test]
    fn the_poller_remembers_within_a_bound() {
        let mut seen = HashSet::new();
        pending_notifications(&[], &mut seen, false);
        for index in 0..(SEEN_CAP * 2) {
            let active = vec![alert(&format!("incident-{index}"))];
            assert_eq!(
                ids(pending_notifications(&active, &mut seen, true)).len(),
                1
            );
            assert!(seen.len() <= SEEN_CAP + 1, "memory must stay bounded");
        }
    }

    #[test]
    fn acknowledged_and_archived_findings_never_pop() {
        for decide in [
            |alert: &mut Alert| alert.acknowledged = true,
            |alert: &mut Alert| alert.archived = true,
        ] {
            let mut seen = HashSet::new();
            pending_notifications(&[], &mut seen, false);
            let mut active = vec![alert("a")];
            decide(&mut active[0]);
            assert!(pending_notifications(&active, &mut seen, true).is_empty());
            // The user's decision is remembered, so undoing it does not pop a
            // balloon for a finding they already dealt with.
            active[0].acknowledged = false;
            active[0].archived = false;
            assert!(pending_notifications(&active, &mut seen, true).is_empty());
        }
    }

    #[test]
    fn a_pre_calibration_record_notifies_exactly_as_it_used_to() {
        // A payload from a service that predates the quality layer: no
        // notify, no generation, no quality. It must pop like it always did.
        let legacy: Alert = serde_json::from_str(
            r#"{"id":"legacy","kind":"sustainedCpu","severity":"warning","firstSeenMs":1,
                "lastSeenMs":2,"processId":42,"processName":"worker.exe","title":"t",
                "explanation":"e","evidence":[],"recommendation":"r","acknowledged":false,
                "occurrenceCount":1,"resolvedAtMs":null}"#,
        )
        .unwrap();
        assert!(legacy.notify && legacy.notify_generation == 0);
        let mut seen = HashSet::new();
        pending_notifications(&[], &mut seen, false);
        let active = vec![legacy];
        assert_eq!(
            ids(pending_notifications(&active, &mut seen, true)),
            ["legacy"]
        );
    }
}
