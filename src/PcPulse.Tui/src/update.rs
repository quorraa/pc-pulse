//! Client-side release update check against GitHub, and the verified
//! installer download the `u` key drives.
//!
//! Mirrors the `analyzer.rs`/`crashdump.rs` house pattern: shell out to
//! tools that already ship with Windows — `curl.exe` for HTTPS and
//! `certutil.exe` for SHA-256 — under explicit timeouts with bounded
//! output, and no new crate dependencies. The check runs at most once per
//! TUI launch on the worker thread, rate-limited by the `lastUpdateCheckMs`
//! timestamp in `ui-prefs.json` and switched off entirely by the
//! `updateChecks` preference (the TUNE CLIENT row).
//!
//! Network boundary: this module and the Oracle/cdb paths are the only
//! network touchpoints in PC Pulse, and all of them live in the client.
//! The collector service never uses the network.
//!
//! Failures here stay out of the user's way: offline, rate-limited, or
//! curl-less machines produce `Err` values the app layer swallows silently
//! — an update check is a courtesy, never a status error.

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// The GitHub "latest release" endpoint for this repository.
pub const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/quorraa/pc-pulse/releases/latest";
/// One check per 20 hours: often enough to hear about a release within a
/// day, rare enough to stay invisible in GitHub's unauthenticated quota.
pub const UPDATE_CHECK_INTERVAL_MS: i64 = 20 * 3_600_000;
/// The GitHub API answer is a few KB; anything past this is not a release.
const MAX_API_RESPONSE_BYTES: usize = 1_024 * 1_024;
/// The checksum manifest is a handful of lines.
const MAX_MANIFEST_BYTES: u64 = 64 * 1_024;
const API_TIMEOUT_SECS: u32 = 15;
const DOWNLOAD_TIMEOUT_SECS: u32 = 300;
/// GitHub's API requires a User-Agent; identify honestly.
const USER_AGENT: &str = concat!("pc-pulse/", env!("CARGO_PKG_VERSION"));

/// A newer published release: what to show, what to download, and what to
/// verify it against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateInfo {
    /// Normalized dotted version, no leading `v` — e.g. `1.16.0`.
    pub version: String,
    /// The release page, for anyone who prefers a browser.
    pub html_url: String,
    pub msi_name: String,
    pub msi_url: String,
    pub msi_size_bytes: u64,
    pub sums_name: String,
    pub sums_url: String,
}

/// The transport seam, exactly like the service's `ForensicsSource`: the
/// real implementation shells out to curl/certutil, tests substitute a
/// stub so no test ever touches the network.
pub trait UpdateTransport {
    /// GET a small text document (the API payload); bounded and timed.
    fn fetch_text(&self, url: &str) -> Result<String>;
    /// Download one release asset to `destination`, replacing any file
    /// already there.
    fn download(&self, url: &str, destination: &Path) -> Result<()>;
    /// The SHA-256 of a local file as lowercase hex.
    fn sha256(&self, file: &Path) -> Result<String>;
}

/// The real transport: Windows' bundled `curl.exe` and `certutil.exe`.
pub struct SystemTransport;

impl UpdateTransport for SystemTransport {
    fn fetch_text(&self, url: &str) -> Result<String> {
        let output = curl_command()?
            .args([
                "--silent",
                "--show-error",
                "--location",
                "--fail",
                "--max-time",
                &API_TIMEOUT_SECS.to_string(),
                "--user-agent",
                USER_AGENT,
                "--header",
                "Accept: application/vnd.github+json",
            ])
            .arg(url)
            .stdin(Stdio::null())
            .output()
            .context("failed to run curl for the update check")?;
        if !output.status.success() {
            bail!(
                "curl failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        if output.stdout.len() > MAX_API_RESPONSE_BYTES {
            bail!("release payload exceeded the bounded response size");
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn download(&self, url: &str, destination: &Path) -> Result<()> {
        let status = curl_command()?
            .args([
                "--silent",
                "--show-error",
                "--location",
                "--fail",
                "--max-time",
                &DOWNLOAD_TIMEOUT_SECS.to_string(),
                "--user-agent",
                USER_AGENT,
                "--output",
            ])
            .arg(destination)
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("failed to run curl for the download")?;
        if !status.success() {
            // Never leave a partial file behind to be mistaken for a
            // verified download.
            let _ = fs::remove_file(destination);
            bail!("download failed ({status})");
        }
        Ok(())
    }

    fn sha256(&self, file: &Path) -> Result<String> {
        let output = Command::new(system32_tool("certutil.exe"))
            .arg("-hashfile")
            .arg(file)
            .arg("SHA256")
            .stdin(Stdio::null())
            .output()
            .context("failed to run certutil for checksum verification")?;
        if !output.status.success() {
            bail!("certutil failed ({})", output.status);
        }
        parse_certutil_hash(&String::from_utf8_lossy(&output.stdout))
            .ok_or_else(|| anyhow!("certutil produced no SHA-256 hash"))
    }
}

/// Windows ships curl at `%SystemRoot%\System32\curl.exe`; requiring that
/// exact binary keeps the check off machines where PATH holds an alias.
fn curl_command() -> Result<Command> {
    let curl = system32_tool("curl.exe");
    if !curl.is_file() {
        bail!("curl.exe was not found at {}", curl.display());
    }
    Ok(Command::new(curl))
}

fn system32_tool(name: &str) -> PathBuf {
    env::var_os("SystemRoot")
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
        .join("System32")
        .join(name)
}

/// The `<hex>` line of `certutil -hashfile` output: 64 hex characters,
/// tolerating the space-grouped form older builds print.
fn parse_certutil_hash(output: &str) -> Option<String> {
    output
        .lines()
        .map(|line| line.split_whitespace().collect::<String>())
        .find(|packed| packed.len() == 64 && packed.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|packed| packed.to_ascii_lowercase())
}

/// Three dotted numbers with an optional leading `v`/`V`; anything else —
/// prereleases, garbage, a renamed tag — is malformed and never an update.
pub fn parse_semver(text: &str) -> Option<(u64, u64, u64)> {
    let trimmed = text.trim();
    let digits = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    let mut parts = digits.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// True only when both versions parse and `candidate` is strictly newer.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_semver(candidate), parse_semver(current)) {
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

#[derive(Debug, Deserialize)]
struct ReleasePayload {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    #[serde(default)]
    name: String,
    #[serde(default)]
    browser_download_url: String,
    #[serde(default)]
    size: u64,
}

/// Interpret a GitHub "latest release" payload against the running version.
/// `Ok(None)` covers everything that is not an actionable update: an older
/// or equal release, a malformed tag, or a release missing its `.msi` or
/// `SHA256SUMS.txt` asset — never a panic, never a spurious badge.
pub fn select_release(payload: &str, current_version: &str) -> Result<Option<UpdateInfo>> {
    let release: ReleasePayload =
        serde_json::from_str(payload).context("GitHub release payload was not valid JSON")?;
    if !is_newer(&release.tag_name, current_version) {
        return Ok(None);
    }
    let Some(version) = parse_semver(&release.tag_name) else {
        return Ok(None);
    };
    let msi = release
        .assets
        .iter()
        .find(|asset| asset.name.to_ascii_lowercase().ends_with(".msi"));
    let sums = release
        .assets
        .iter()
        .find(|asset| asset.name.eq_ignore_ascii_case("SHA256SUMS.txt"));
    let (Some(msi), Some(sums)) = (msi, sums) else {
        return Ok(None);
    };
    Ok(Some(UpdateInfo {
        version: format!("{}.{}.{}", version.0, version.1, version.2),
        html_url: release.html_url.clone(),
        msi_name: msi.name.clone(),
        msi_url: msi.browser_download_url.clone(),
        msi_size_bytes: msi.size,
        sums_name: sums.name.clone(),
        sums_url: sums.browser_download_url.clone(),
    }))
}

/// One launch-time check: fetch the latest-release document and decide
/// whether it is a downloadable update over `current_version`.
pub fn check_for_update(
    transport: &dyn UpdateTransport,
    current_version: &str,
) -> Result<Option<UpdateInfo>> {
    let payload = transport.fetch_text(LATEST_RELEASE_URL)?;
    select_release(&payload, current_version)
}

/// The expected hash for `file_name` out of a `SHA256SUMS.txt` manifest:
/// `<hex> *<name>` per line (the release script's format), tolerating the
/// text-mode two-space form and case differences in the name.
pub fn expected_sha256(manifest: &str, file_name: &str) -> Option<String> {
    for line in manifest.lines() {
        let mut tokens = line.split_whitespace();
        let Some(hash) = tokens.next() else { continue };
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let name = tokens.collect::<Vec<_>>().join(" ");
        let name = name.strip_prefix('*').unwrap_or(&name);
        if name.eq_ignore_ascii_case(file_name) {
            return Some(hash.to_ascii_lowercase());
        }
    }
    None
}

/// The user's Downloads folder, where the installer lands in plain sight.
pub fn downloads_directory() -> Result<PathBuf> {
    let profile =
        env::var_os("USERPROFILE").ok_or_else(|| anyhow!("USERPROFILE is not defined"))?;
    Ok(PathBuf::from(profile).join("Downloads"))
}

/// Download the MSI and its `SHA256SUMS.txt` into `directory`, verify the
/// MSI's SHA-256 against the manifest line, and return the installer path.
/// A file that fails verification is deleted, never left behind.
pub fn download_and_verify(
    transport: &dyn UpdateTransport,
    info: &UpdateInfo,
    directory: &Path,
) -> Result<PathBuf> {
    fs::create_dir_all(directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;
    let msi_path = directory.join(&info.msi_name);
    let sums_path = directory.join(&info.sums_name);
    transport
        .download(&info.msi_url, &msi_path)
        .with_context(|| format!("failed to download {}", info.msi_name))?;
    let verified = verify_download(transport, info, &msi_path, &sums_path);
    if verified.is_err() {
        // A file that failed verification must not linger looking real.
        let _ = fs::remove_file(&msi_path);
    }
    verified?;
    Ok(msi_path)
}

fn verify_download(
    transport: &dyn UpdateTransport,
    info: &UpdateInfo,
    msi_path: &Path,
    sums_path: &Path,
) -> Result<()> {
    transport
        .download(&info.sums_url, sums_path)
        .with_context(|| format!("failed to download {}", info.sums_name))?;
    if fs::metadata(sums_path).map(|meta| meta.len()).unwrap_or(0) > MAX_MANIFEST_BYTES {
        bail!("checksum manifest exceeded its bounded size");
    }
    let manifest = fs::read_to_string(sums_path)
        .with_context(|| format!("failed to read {}", sums_path.display()))?;
    let expected = expected_sha256(&manifest, &info.msi_name).ok_or_else(|| {
        anyhow!("{} has no entry for {}", info.sums_name, info.msi_name)
    })?;
    let actual = transport.sha256(msi_path)?;
    if !actual.eq_ignore_ascii_case(&expected) {
        bail!(
            "checksum mismatch for {} — expected {expected}, computed {actual}",
            info.msi_name
        );
    }
    Ok(())
}

/// Hand the verified MSI to `msiexec.exe /i` detached — msiexec raises its
/// own UAC prompt and owns the install from here. Never silent, never
/// automatic: this runs only on the user's second `u` press.
pub fn launch_installer(msi: &Path) -> Result<()> {
    Command::new("msiexec.exe")
        .arg("/i")
        .arg(msi)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to launch msiexec for {}", msi.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A canned GitHub payload shaped like the real endpoint's answer,
    /// including a decoy asset so selection must actually pick the MSI.
    fn canned_payload(tag: &str) -> String {
        format!(
            r#"{{
              "tag_name": "{tag}",
              "html_url": "https://github.com/quorraa/pc-pulse/releases/tag/{tag}",
              "assets": [
                {{ "name": "PcPulse-symbols.zip", "browser_download_url": "https://example.invalid/symbols.zip", "size": 999 }},
                {{ "name": "PcPulse-1.16.0-x64.msi", "browser_download_url": "https://example.invalid/PcPulse-1.16.0-x64.msi", "size": 2097152 }},
                {{ "name": "SHA256SUMS.txt", "browser_download_url": "https://example.invalid/SHA256SUMS.txt", "size": 260 }}
              ]
            }}"#
        )
    }

    #[test]
    fn semver_parses_with_and_without_the_leading_v() {
        assert_eq!(parse_semver("1.16.0"), Some((1, 16, 0)));
        assert_eq!(parse_semver("v1.16.0"), Some((1, 16, 0)));
        assert_eq!(parse_semver("V2.0.10"), Some((2, 0, 10)));
        assert_eq!(parse_semver(" v1.2.3 "), Some((1, 2, 3)));
        assert_eq!(parse_semver("1.16"), None);
        assert_eq!(parse_semver("1.16.0.1"), None);
        assert_eq!(parse_semver("1.16.0-rc1"), None);
        assert_eq!(parse_semver("release-soon"), None);
        assert_eq!(parse_semver(""), None);
    }

    #[test]
    fn newer_older_equal_and_malformed_tags_compare_safely() {
        assert!(is_newer("v1.16.0", "1.15.0"));
        assert!(is_newer("2.0.0", "1.99.99"));
        assert!(is_newer("1.15.1", "1.15.0"));
        assert!(!is_newer("v1.15.0", "1.15.0"), "equal is not an update");
        assert!(!is_newer("1.14.9", "1.15.0"), "older is not an update");
        assert!(!is_newer("not-a-version", "1.15.0"), "malformed = no update");
        assert!(!is_newer("v1.16.0", "garbage"), "unparsable current = no update");
    }

    #[test]
    fn release_selection_picks_the_msi_and_manifest_assets() {
        let info = select_release(&canned_payload("v1.16.0"), "1.15.0")
            .unwrap()
            .expect("a newer release with both assets is an update");
        assert_eq!(info.version, "1.16.0");
        assert_eq!(info.msi_name, "PcPulse-1.16.0-x64.msi");
        assert_eq!(
            info.msi_url,
            "https://example.invalid/PcPulse-1.16.0-x64.msi"
        );
        assert_eq!(info.msi_size_bytes, 2_097_152);
        assert_eq!(info.sums_name, "SHA256SUMS.txt");
        assert!(info.html_url.contains("/releases/tag/v1.16.0"));
    }

    #[test]
    fn equal_older_and_malformed_releases_are_not_updates() {
        assert_eq!(select_release(&canned_payload("v1.15.0"), "1.15.0").unwrap(), None);
        assert_eq!(select_release(&canned_payload("v1.14.2"), "1.15.0").unwrap(), None);
        assert_eq!(
            select_release(&canned_payload("nightly"), "1.15.0").unwrap(),
            None,
            "a malformed tag is silently no update"
        );
        assert!(select_release("{not json", "1.15.0").is_err());
    }

    #[test]
    fn a_release_missing_its_msi_or_manifest_is_not_an_update() {
        let no_msi = r#"{ "tag_name": "v9.0.0", "html_url": "x", "assets": [
            { "name": "SHA256SUMS.txt", "browser_download_url": "u", "size": 1 } ] }"#;
        assert_eq!(select_release(no_msi, "1.15.0").unwrap(), None);
        let no_sums = r#"{ "tag_name": "v9.0.0", "html_url": "x", "assets": [
            { "name": "PcPulse-9.0.0-x64.msi", "browser_download_url": "u", "size": 1 } ] }"#;
        assert_eq!(select_release(no_sums, "1.15.0").unwrap(), None);
        let no_assets = r#"{ "tag_name": "v9.0.0", "html_url": "x" }"#;
        assert_eq!(select_release(no_assets, "1.15.0").unwrap(), None);
    }

    #[test]
    fn manifest_lines_match_by_name_in_both_manifest_forms() {
        let manifest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa *PcPulse-1.16.0-x64.msi\r\n\
                        BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB  PcPulse.Notify.exe\r\n\
                        not-a-hash-line\r\n";
        assert_eq!(
            expected_sha256(manifest, "PcPulse-1.16.0-x64.msi").as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        // Text-mode (no `*`) rows and hash case both normalize.
        assert_eq!(
            expected_sha256(manifest, "pcpulse.notify.exe").as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        assert_eq!(expected_sha256(manifest, "missing.msi"), None);
        assert_eq!(expected_sha256("", "anything.msi"), None);
    }

    #[test]
    fn certutil_output_parses_in_compact_and_spaced_forms() {
        let modern = "SHA256 hash of file.msi:\r\nAB12ab12AB12ab12AB12ab12AB12ab12AB12ab12AB12ab12AB12ab12AB12ab12\r\nCertUtil: -hashfile command completed successfully.\r\n";
        assert_eq!(
            parse_certutil_hash(modern).as_deref(),
            Some("ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12")
        );
        let spaced = "SHA256 hash of file.msi:\r\nab 12 ab 12 ab 12 ab 12 ab 12 ab 12 ab 12 ab 12 ab 12 ab 12 ab 12 ab 12 ab 12 ab 12 ab 12 ab 12\r\n";
        assert_eq!(
            parse_certutil_hash(spaced).as_deref(),
            Some("ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12")
        );
        assert_eq!(parse_certutil_hash("CertUtil: file not found"), None);
    }

    /// A stub transport that "downloads" canned bytes and reports a scripted
    /// hash — the test double for the curl/certutil seam.
    struct StubTransport {
        msi_bytes: &'static [u8],
        manifest: String,
        sha256: String,
        downloads: RefCell<Vec<String>>,
    }

    impl UpdateTransport for StubTransport {
        fn fetch_text(&self, _url: &str) -> Result<String> {
            bail!("fetch_text is not part of the download path");
        }

        fn download(&self, url: &str, destination: &Path) -> Result<()> {
            self.downloads.borrow_mut().push(url.to_string());
            if url.ends_with("SHA256SUMS.txt") {
                fs::write(destination, &self.manifest)?;
            } else {
                fs::write(destination, self.msi_bytes)?;
            }
            Ok(())
        }

        fn sha256(&self, _file: &Path) -> Result<String> {
            Ok(self.sha256.clone())
        }
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "pcpulse-update-{tag}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_millis()
        ))
    }

    fn stub_info() -> UpdateInfo {
        UpdateInfo {
            version: "1.16.0".into(),
            html_url: "https://example.invalid/release".into(),
            msi_name: "PcPulse-1.16.0-x64.msi".into(),
            msi_url: "https://example.invalid/PcPulse-1.16.0-x64.msi".into(),
            msi_size_bytes: 11,
            sums_name: "SHA256SUMS.txt".into(),
            sums_url: "https://example.invalid/SHA256SUMS.txt".into(),
        }
    }

    #[test]
    fn download_and_verify_accepts_a_matching_checksum() {
        let hash = "cc".repeat(32);
        let transport = StubTransport {
            msi_bytes: b"msi payload",
            manifest: format!("{hash} *PcPulse-1.16.0-x64.msi\r\n"),
            sha256: hash.to_ascii_uppercase(),
            downloads: RefCell::new(Vec::new()),
        };
        let directory = scratch_dir("ok");
        let installer = download_and_verify(&transport, &stub_info(), &directory).unwrap();
        assert_eq!(installer, directory.join("PcPulse-1.16.0-x64.msi"));
        assert!(installer.is_file(), "the verified installer stays on disk");
        assert_eq!(
            transport.downloads.borrow().as_slice(),
            [
                "https://example.invalid/PcPulse-1.16.0-x64.msi",
                "https://example.invalid/SHA256SUMS.txt"
            ]
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn a_checksum_mismatch_deletes_the_downloaded_file() {
        let transport = StubTransport {
            msi_bytes: b"tampered payload",
            manifest: format!("{} *PcPulse-1.16.0-x64.msi\r\n", "dd".repeat(32)),
            sha256: "ee".repeat(32),
            downloads: RefCell::new(Vec::new()),
        };
        let directory = scratch_dir("mismatch");
        let error = download_and_verify(&transport, &stub_info(), &directory)
            .expect_err("a mismatched hash must fail");
        assert!(format!("{error:#}").contains("checksum mismatch"), "{error:#}");
        assert!(
            !directory.join("PcPulse-1.16.0-x64.msi").exists(),
            "the bad file must be deleted"
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn a_manifest_without_the_msi_line_deletes_the_download() {
        let transport = StubTransport {
            msi_bytes: b"msi payload",
            manifest: format!("{} *SomethingElse.msi\r\n", "aa".repeat(32)),
            sha256: "aa".repeat(32),
            downloads: RefCell::new(Vec::new()),
        };
        let directory = scratch_dir("no-entry");
        let error = download_and_verify(&transport, &stub_info(), &directory)
            .expect_err("a manifest without the file's line must fail");
        assert!(format!("{error:#}").contains("no entry"), "{error:#}");
        assert!(!directory.join("PcPulse-1.16.0-x64.msi").exists());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn check_for_update_reads_through_the_transport() {
        struct Canned;
        impl UpdateTransport for Canned {
            fn fetch_text(&self, url: &str) -> Result<String> {
                assert_eq!(url, LATEST_RELEASE_URL);
                Ok(super::tests::canned_payload("v1.16.0"))
            }
            fn download(&self, _: &str, _: &Path) -> Result<()> {
                bail!("not used")
            }
            fn sha256(&self, _: &Path) -> Result<String> {
                bail!("not used")
            }
        }
        let info = check_for_update(&Canned, "1.15.0").unwrap().unwrap();
        assert_eq!(info.version, "1.16.0");
        assert_eq!(check_for_update(&Canned, "1.16.0").unwrap(), None);
    }

    #[test]
    #[ignore = "dev harness: queries the live GitHub API once and prints the latest release tag"]
    fn dev_probe_latest_release() {
        match SystemTransport.fetch_text(LATEST_RELEASE_URL) {
            Ok(payload) => {
                let release: serde_json::Value =
                    serde_json::from_str(&payload).expect("GitHub answered non-JSON");
                let tag = release["tag_name"].as_str().unwrap_or("<missing tag_name>");
                println!("latest tag: {tag}");
                if let Some(assets) = release["assets"].as_array() {
                    for asset in assets {
                        println!(
                            "asset: {} ({} bytes)",
                            asset["name"].as_str().unwrap_or("?"),
                            asset["size"].as_u64().unwrap_or(0)
                        );
                    }
                }
                match select_release(&payload, env!("CARGO_PKG_VERSION")) {
                    Ok(Some(info)) => println!("update available: v{}", info.version),
                    Ok(None) => println!("no update over v{}", env!("CARGO_PKG_VERSION")),
                    Err(error) => println!("degrade: {error:#}"),
                }
            }
            Err(error) => println!("degrade: {error:#}"),
        }
    }
}
