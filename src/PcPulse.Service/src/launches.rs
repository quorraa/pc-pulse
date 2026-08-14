//! Pure helpers for launch-history tracking: kernel image-path normalization
//! and console-host classification. Kept dependency-free where possible so
//! the logic is exhaustively unit-testable; the one Win32 call
//! (`build_device_map`) is a thin wrapper isolated from the pure functions
//! below it. Task 4 adds the stateful tracker that consumes these.

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

/// Console host executable names (lowercase, exact match only -- no
/// substring matching, so e.g. "mycmd.exe" does not match "cmd.exe").
const CONSOLE_HOSTS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "conhost.exe",
    "wt.exe",
    "windowsterminal.exe",
    "openconsole.exe",
];

/// Maps `\Device\HarddiskVolumeN\...` to `c:\...` using a supplied device
/// map, and lowercases the result either way. `device_map` entries are
/// `(device_path, drive)` pairs, both already lowercase (see
/// `build_device_map`). Matching uses the longest device-path prefix so that
/// a device map is never ambiguous even if entries share a common prefix.
///
/// Returns `(normalized_or_original_lowercased, mapped)`, where `mapped` is
/// `true` only if a device prefix was substituted.
pub fn normalize_image_path(raw: &str, device_map: &[(String, String)]) -> (String, bool) {
    let lower = raw.to_lowercase();

    let best = device_map
        .iter()
        .filter(|(device, _)| lower.starts_with(device.as_str()))
        .max_by_key(|(device, _)| device.len());

    match best {
        Some((device, drive)) => {
            let rest = &lower[device.len()..];
            (format!("{drive}{rest}"), true)
        }
        None => (lower, false),
    }
}

/// Builds a live `\Device\HarddiskVolumeN` -> drive-letter map by calling
/// `QueryDosDeviceW` for each drive letter A:..Z:. Only existing mappings
/// are returned. Callers should cache the result rather than rebuilding it
/// per lookup -- drive mappings rarely change during a service's lifetime.
pub fn build_device_map() -> Vec<(String, String)> {
    let mut map = Vec::new();

    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let wide_drive: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();

        let mut buf = [0u16; 260];
        // SAFETY: `wide_drive` is a valid NUL-terminated wide string and
        // `buf` is a valid, appropriately-sized output buffer for the
        // duration of the call.
        let len = unsafe { QueryDosDeviceW(PCWSTR(wide_drive.as_ptr()), Some(&mut buf)) };
        if len == 0 {
            continue;
        }

        let device = String::from_utf16_lossy(&buf[..(len as usize).saturating_sub(1)]);
        if device.is_empty() {
            continue;
        }

        map.push((device.to_lowercase(), drive.to_lowercase()));
    }

    map
}

/// Returns the last path component (the executable file name), unchanged
/// otherwise -- callers are expected to lowercase separately if needed.
pub fn exe_name_from_path(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// Whether `exe_name` names a known console host, matched case-insensitively
/// and by exact full name (no substring matching).
pub fn is_console_host(exe_name: &str) -> bool {
    let lower = exe_name.to_lowercase();
    CONSOLE_HOSTS.contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_device_path_and_flags_mapping() {
        let map = vec![(r"\device\harddiskvolume4".to_string(), "c:".to_string())];
        let (p, mapped) =
            normalize_image_path(r"\Device\HarddiskVolume4\Windows\System32\CMD.EXE", &map);
        assert_eq!(p, r"c:\windows\system32\cmd.exe");
        assert!(mapped);
    }

    #[test]
    fn unmapped_device_path_preserved_lowercased_and_flagged() {
        let (p, mapped) = normalize_image_path(r"\Device\Mup\share\x.exe", &[]);
        assert_eq!(p, r"\device\mup\share\x.exe");
        assert!(!mapped);
    }

    #[test]
    fn console_hosts_recognized_case_insensitively() {
        for n in [
            "cmd.exe",
            "PowerShell.exe",
            "pwsh.exe",
            "conhost.exe",
            "wt.exe",
            "WindowsTerminal.exe",
            "OpenConsole.exe",
        ] {
            assert!(is_console_host(n), "{n}");
        }
        assert!(!is_console_host("notepad.exe"));
        assert!(!is_console_host("mycmd.exe")); // exact-name match only, no substring matching
    }

    #[test]
    fn exe_name_is_last_component() {
        assert_eq!(
            exe_name_from_path(r"c:\windows\system32\cmd.exe"),
            "cmd.exe"
        );
        assert_eq!(exe_name_from_path("cmd.exe"), "cmd.exe");
    }
}
