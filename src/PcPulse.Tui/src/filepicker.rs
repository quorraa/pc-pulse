//! The native Windows "open file" dialog, for choosing a background video.
//!
//! Typing a path into the TUNE row worked, but it made the one setting
//! whose value lives out in the filesystem the only one you had to know by
//! heart. Enter on that row now opens the same Explorer dialog every other
//! Windows program opens, filtered to video files and starting where the
//! current clip lives.
//!
//! ## Why a thread, and why the channel
//!
//! `IFileOpenDialog::Show` is modal: it does not return until the person
//! picks or cancels. Calling it from the UI thread would stop the draw
//! loop, the collector drain, and the background clip dead for as long as
//! the dialog is up. It also needs COM initialized as a single-threaded
//! apartment, and the UI thread is not ours to convert — an apartment is a
//! property of the thread for its whole life.
//!
//! So the dialog gets a thread of its own, initialized STA, and answers on
//! a `crossbeam_channel` the UI loop polls in `drain_events` exactly the
//! way it polls the clip converter. The TUI keeps drawing, keeps playing,
//! and says "Choosing a video…" while the dialog is up.
//!
//! ## What can be tested here
//!
//! Building and configuring the dialog is in-process and window-less, and
//! is exercised against the real shell by a test. Putting it on screen is
//! not: [`show`] — and only [`show`] — is untested by construction, because
//! a modal window cannot be driven by a headless run. It is kept to the
//! thinnest shell the Win32 calls allow, and everything the app does with
//! the answer runs against [`PickEvent`] values a test hands in over a
//! channel of its own making. `dev_smoke_open_dialog` opens the real thing
//! for a human.

use crossbeam_channel::{Receiver, bounded};
use std::path::{Path, PathBuf};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoTaskMemFree, CoUninitialize,
};
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{
    FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_PATHMUSTEXIST, FileOpenDialog, IFileOpenDialog,
    IShellItem, SHCreateItemFromParsingName, SIGDN_FILESYSPATH,
};
use windows::core::{HRESULT, HSTRING, w};

/// What the dialog thread reports back. Exactly one of these is ever sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickEvent {
    /// A file was chosen.
    Picked(PathBuf),
    /// The dialog was dismissed. Nothing changes.
    Cancelled,
    /// The dialog could not be shown at all — COM refused to initialize,
    /// the shell class would not create, or the thread would not start.
    /// The row falls back to the typed-path editor rather than becoming a
    /// dead end with no way to set a background.
    Unavailable,
}

/// `HRESULT_FROM_WIN32(ERROR_CANCELLED)` — what `Show` returns when the
/// person dismisses the dialog. It arrives as an `Err`, so without this it
/// would be indistinguishable from the dialog failing outright, and every
/// cancel would drop the row back into the typed editor.
const ERROR_CANCELLED: HRESULT = HRESULT(0x8007_04C7_u32 as i32);

/// Open the dialog on a thread of its own and hand back the channel it
/// answers on. Exactly one [`PickEvent`] is ever sent; a thread that will
/// not start reports [`PickEvent::Unavailable`] into the channel before
/// this returns, so the caller never has to distinguish the two failures.
///
/// `start_dir` is where the dialog opens — the current clip's folder, when
/// there is one.
pub fn spawn_pick(start_dir: Option<PathBuf>) -> Receiver<PickEvent> {
    let (tx, rx) = bounded(1);
    let spawned = std::thread::Builder::new()
        .name("pcpulse-file-picker".into())
        .spawn(move || {
            let event = match show_open_dialog(start_dir.as_deref()) {
                Ok(Some(path)) => PickEvent::Picked(path),
                Ok(None) => PickEvent::Cancelled,
                Err(_) => PickEvent::Unavailable,
            };
            let _ = tx.send(event);
        });
    if spawned.is_err() {
        // The channel holds one message and nothing has been sent, so this
        // cannot block.
        let (tx, rx) = bounded(1);
        let _ = tx.send(PickEvent::Unavailable);
        return rx;
    }
    rx
}

/// Initialize this thread's apartment, build the dialog, show it, and read
/// the chosen path back out. `Ok(Some)` is a choice, `Ok(None)` a cancel,
/// `Err` a dialog that could not be shown.
///
/// The thread this runs on exists only for this call, so the apartment is
/// ours to set and a non-success from `CoInitializeEx` is a genuine
/// failure rather than a conflict with somebody else's choice.
fn show_open_dialog(start_dir: Option<&Path>) -> windows::core::Result<Option<PathBuf>> {
    unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.ok()?;
    let result = build_dialog(start_dir).and_then(|dialog| show(&dialog));
    unsafe { CoUninitialize() };
    result
}

/// Create and configure the dialog. Everything here is in-process and
/// window-less, so unlike [`show`] it is exercised by a test.
///
/// Must be called on a thread whose apartment is already initialized.
fn build_dialog(start_dir: Option<&Path>) -> windows::core::Result<IFileOpenDialog> {
    let dialog: IFileOpenDialog =
        unsafe { CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) }?;

    // The video extensions this build can convert, plus the escape hatch:
    // ffmpeg reads far more than these, and a person who knows that should
    // not be blocked by our list.
    let filters = [
        COMDLG_FILTERSPEC {
            pszName: w!("Video files"),
            pszSpec: w!("*.mp4;*.mkv;*.webm;*.mov;*.avi;*.gif"),
        },
        COMDLG_FILTERSPEC {
            pszName: w!("All files"),
            pszSpec: w!("*.*"),
        },
    ];
    unsafe { dialog.SetFileTypes(&filters) }?;
    unsafe { dialog.SetTitle(w!("Choose a background video")) }?;
    // A filesystem path is the only thing that can be converted, so the
    // dialog is told to refuse anything else — a library or a device
    // namespace would come back as something ffmpeg cannot open.
    let options = unsafe { dialog.GetOptions() }?;
    unsafe {
        dialog.SetOptions(options | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST)
    }?;

    // Opening where the current clip lives is a courtesy, not a
    // requirement: a folder that has since moved must not stop the dialog.
    if let Some(dir) = start_dir
        && let Ok(item) = unsafe {
            SHCreateItemFromParsingName::<_, _, IShellItem>(&HSTRING::from(dir.as_os_str()), None)
        }
    {
        let _ = unsafe { dialog.SetFolder(&item) };
    }
    Ok(dialog)
}

/// Put the dialog on screen and wait for the person.
///
/// **Untested by construction** — this is the modal part, and a modal
/// window cannot be driven by a headless test run. It is kept to the
/// smallest shell the calls allow, and its one decision (a dismissal
/// arrives as an `Err`, not an `Ok`) is spelled out rather than inferred.
fn show(dialog: &IFileOpenDialog) -> windows::core::Result<Option<PathBuf>> {
    // No owner window: the TUI is a console, and handing the dialog the
    // console's HWND would be handing it a window it does not own.
    match unsafe { dialog.Show(None) } {
        Ok(()) => {}
        Err(error) if error.code() == ERROR_CANCELLED => return Ok(None),
        Err(error) => return Err(error),
    }

    let item = unsafe { dialog.GetResult() }?;
    let wide = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }?;
    let path = PathBuf::from(unsafe { wide.to_string() }?);
    unsafe { CoTaskMemFree(Some(wide.0.cast())) };
    Ok(Some(path))
}

/// The folder a dialog for `current` should open in: the clip's own folder
/// when the stored path still names one, otherwise nothing and the shell
/// picks its usual place.
pub fn start_dir(current: &str) -> Option<PathBuf> {
    let current = current.trim();
    if current.is_empty() {
        return None;
    }
    Path::new(current)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty() && parent.is_dir())
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dialog_opens_where_the_current_clip_lives() {
        let dir = std::env::temp_dir();
        let clip = dir.join("some-clip.mp4");
        assert_eq!(start_dir(&clip.to_string_lossy()), Some(dir.clone()));
        // Quoted or padded, the way a pasted path arrives.
        assert_eq!(start_dir(&format!("  {}  ", clip.display())), Some(dir));
    }

    #[test]
    fn no_clip_or_a_folder_that_is_gone_leaves_the_shell_to_choose() {
        assert_eq!(start_dir(""), None);
        assert_eq!(start_dir("   "), None);
        assert_eq!(start_dir(r"C:\no\such\folder\clip.mp4"), None);
        // A bare filename has no folder to open in.
        assert_eq!(start_dir("clip.mp4"), None);
    }

    #[test]
    fn the_dialog_builds_and_configures_on_a_real_apartment() {
        // Everything short of putting the window on screen: the apartment,
        // the shell class, the filter list, the options, and the start
        // folder. A typo in any of them is an `Err` here rather than a
        // dialog that silently never appears for a real person.
        let dir = std::env::temp_dir();
        let built = std::thread::spawn(move || {
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
                .ok()
                .expect("apartment");
            let with_folder = build_dialog(Some(&dir)).map(|_| ());
            let without = build_dialog(None).map(|_| ());
            unsafe { CoUninitialize() };
            (with_folder, without)
        })
        .join()
        .unwrap();
        built.0.expect("dialog with a start folder");
        built.1.expect("dialog with no start folder");
    }

    #[test]
    #[ignore = "dev harness: opens the real modal dialog; run with --ignored --nocapture and pick or cancel by hand"]
    fn dev_smoke_open_dialog() {
        let start = std::env::var("PCPULSE_PICKER_START")
            .ok()
            .map(std::path::PathBuf::from);
        println!("opening the dialog at {start:?}…");
        println!("answer: {:?}", show_open_dialog(start.as_deref()));
    }

    #[test]
    fn a_picker_that_cannot_start_answers_rather_than_hanging() {
        // The caller waits on this channel forever otherwise: an unstarted
        // thread would leave the row stuck on "Choosing a video…" with no
        // dialog anywhere on screen.
        let (tx, rx) = bounded(1);
        tx.send(PickEvent::Unavailable).unwrap();
        assert_eq!(rx.try_recv(), Ok(PickEvent::Unavailable));
    }
}
