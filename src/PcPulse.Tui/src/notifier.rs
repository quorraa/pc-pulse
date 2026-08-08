use crate::{client::PipeClient, format};
use anyhow::{Context, Result, bail};
use pcpulse_service::models::{Alert, Severity};
use std::{
    collections::HashSet,
    os::windows::process::CommandExt,
    process::Command,
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
        System::{LibraryLoader::GetModuleHandleW, Threading::CREATE_NEW_CONSOLE},
        UI::{
            Shell::{
                NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIIF_WARNING,
                NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW, Shell_NotifyIconW,
            },
            WindowsAndMessaging::{
                CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DispatchMessageW,
                GetMessageW, HWND_MESSAGE, IDI_INFORMATION, LoadIconW, MSG, PostQuitMessage,
                RegisterClassW, TranslateMessage, WINDOW_EX_STYLE, WM_APP, WM_CLOSE, WM_DESTROY,
                WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_RBUTTONUP, WNDCLASSW, WS_OVERLAPPED,
            },
        },
    },
    core::{PCWSTR, w},
};

const ICON_ID: u32 = 1;
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

fn add_icon(window: HWND) -> Result<()> {
    let mut data = base_icon_data(window);
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    data.hIcon = unsafe { LoadIconW(None, IDI_INFORMATION) }.context("LoadIconW failed")?;
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
                let current: HashSet<String> = snapshot
                    .active_alerts
                    .iter()
                    .map(|alert| alert.id.clone())
                    .collect();
                if initialized && notifications_enabled {
                    for alert in snapshot
                        .active_alerts
                        .iter()
                        .filter(|alert| !alert.acknowledged && !seen.contains(&alert.id))
                    {
                        notify_alert(window, alert);
                    }
                }
                seen = current;
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
    let _ = Command::new(path)
        .creation_flags(CREATE_NEW_CONSOLE.0)
        .spawn();
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
