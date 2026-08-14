use anyhow::{Context, Result, anyhow, bail};
use pcpulse_service::{
    PIPE_NAME,
    config::Settings,
    launches::LaunchGroup,
    models::{
        AgentContext, Alert, DiagnosticLogResponse, HistoryResponse, LaunchEvent, LiveSample,
        OptimizationPlan, PipeRequest, PipeResponse, ProcessNode, Rating, RatingVerdict, Snapshot,
    },
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::{
    thread,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING, ReadFile, WriteFile,
        },
        System::Pipes::WaitNamedPipeW,
    },
    core::PCWSTR,
};

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// The `getLaunchGroups` envelope. The service answers `{"groups": [...]}`
/// rather than a bare array, so the wrapper is mirrored here exactly as the
/// other response envelopes are — the `LaunchGroup` payload itself is the
/// service's own struct, so the two can never drift.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchGroupsResponse {
    pub groups: Vec<LaunchGroup>,
}

/// The `getLaunchOccurrences` envelope (`{"events": [...]}`), newest first.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchOccurrencesResponse {
    pub events: Vec<LaunchEvent>,
}

/// The `deleteCommandLines` envelope (`{"deleted": n}`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteCommandLinesResponse {
    pub deleted: usize,
}

pub struct PipeClient;

impl PipeClient {
    pub fn ping(&self) -> Result<serde_json::Value> {
        self.send(&PipeRequest::Ping)
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        self.send(&PipeRequest::GetSnapshot)
    }

    /// The most recent high-rate system sample; also keeps the service's
    /// live sampling loop alive. Old services answer with an
    /// `invalidRequest` error, which callers treat as "not supported".
    pub fn live(&self) -> Result<LiveSample> {
        self.send(&PipeRequest::Live)
    }

    pub fn history(&self, from_ms: i64, to_ms: i64, limit: u32) -> Result<HistoryResponse> {
        self.send(&PipeRequest::GetHistory {
            from_ms,
            to_ms,
            limit,
        })
    }

    pub fn system_history(
        &self,
        from_ms: i64,
        to_ms: i64,
        limit: u32,
    ) -> Result<Vec<pcpulse_service::models::SystemMetric>> {
        self.send(&PipeRequest::GetSystemHistory {
            from_ms,
            to_ms,
            limit,
        })
    }

    pub fn alerts(&self, from_ms: i64, limit: u32) -> Result<Vec<Alert>> {
        self.send(&PipeRequest::GetAlerts { from_ms, limit })
    }

    pub fn diagnostic_logs(&self, from_ms: i64, limit: u32) -> Result<DiagnosticLogResponse> {
        self.send(&PipeRequest::GetDiagnosticLogs { from_ms, limit })
    }

    pub fn agent_context(&self, window_hours: u32) -> Result<AgentContext> {
        self.send(&PipeRequest::GetAgentContext { window_hours })
    }

    pub fn optimization_plans(&self, limit: u32) -> Result<Vec<OptimizationPlan>> {
        self.send(&PipeRequest::GetOptimizationPlans { limit })
    }

    pub fn save_optimization_plan(&self, plan: OptimizationPlan) -> Result<serde_json::Value> {
        self.send(&PipeRequest::SaveOptimizationPlan { plan })
    }

    pub fn settings(&self) -> Result<Settings> {
        self.send(&PipeRequest::GetSettings)
    }

    pub fn update_settings(&self, settings: Settings) -> Result<Settings> {
        self.send(&PipeRequest::UpdateSettings { settings })
    }

    pub fn process_tree(&self) -> Result<Vec<ProcessNode>> {
        self.send(&PipeRequest::GetProcessTree)
    }

    pub fn acknowledge(&self, alert_id: String) -> Result<serde_json::Value> {
        self.send(&PipeRequest::AcknowledgeAlert { alert_id })
    }

    /// Set or clear a finding's presentation-only archive flag (`archived:
    /// false` recovers it). Pre-archive services answer with the ordinary
    /// unknown-command `invalidRequest` error.
    pub fn archive(&self, alert_id: String, archived: bool) -> Result<serde_json::Value> {
        self.send(&PipeRequest::ArchiveAlert { alert_id, archived })
    }

    pub fn terminate(&self, pid: u32, confirmed: bool) -> Result<serde_json::Value> {
        self.send(&PipeRequest::TerminateProcess { pid, confirmed })
    }

    /// Submit a quick in-app performance rating; the service assembles the
    /// full record (demand context, digest, open incidents) server-side and
    /// returns it. Never affects baselines, detector thresholds, or
    /// severities -- only the notification policy's floors.
    pub fn add_rating(&self, verdict: RatingVerdict) -> Result<Rating> {
        self.send(&PipeRequest::AddRating { verdict })
    }

    /// Rating history, newest first.
    pub fn ratings(&self, limit: usize) -> Result<Vec<Rating>> {
        self.send(&PipeRequest::GetRatings { limit })
    }

    /// Recorded launches bucketed by `(exe_path, lineage_sig)` over the
    /// service's default 7-day window. Services that predate launch history
    /// answer with the ordinary unknown-command `invalidRequest` error.
    pub fn launch_groups(
        &self,
        console_hosts_only: bool,
        limit: usize,
    ) -> Result<LaunchGroupsResponse> {
        self.send(&PipeRequest::GetLaunchGroups {
            from_ms: None,
            console_hosts_only: Some(console_hosts_only),
            limit: Some(limit),
        })
    }

    /// One group's individual occurrences, newest first. `exe_path` and
    /// `lineage_sig` must be the byte-exact values `getLaunchGroups`
    /// returned: the service matches them literally against its stored
    /// (already-lowercased) values, so re-casing or normalizing them here
    /// would silently match nothing.
    pub fn launch_occurrences(
        &self,
        exe_path: String,
        lineage_sig: String,
        limit: usize,
    ) -> Result<LaunchOccurrencesResponse> {
        self.send(&PipeRequest::GetLaunchOccurrences {
            exe_path,
            lineage_sig,
            from_ms: None,
            limit: Some(limit),
        })
    }

    /// Forget every captured command line. Never touches launch-event rows,
    /// which never carried a command line in the first place.
    pub fn delete_command_lines(&self) -> Result<DeleteCommandLinesResponse> {
        self.send(&PipeRequest::DeleteCommandLines)
    }

    pub fn send<T: DeserializeOwned>(&self, request: &PipeRequest) -> Result<T> {
        let payload = serde_json::to_vec(request)?;
        if payload.len() > MAX_MESSAGE_BYTES {
            bail!("request exceeds the one-MiB protocol limit");
        }
        let handle = connect(Duration::from_secs(5))?;
        let _guard = HandleGuard(handle);
        let mut written = 0;
        unsafe { WriteFile(handle, Some(&payload), Some(&mut written), None) }
            .context("named-pipe write failed")?;
        if written as usize != payload.len() {
            bail!("named-pipe write was incomplete");
        }
        let mut buffer = vec![0_u8; MAX_MESSAGE_BYTES];
        let mut bytes_read = 0;
        unsafe { ReadFile(handle, Some(&mut buffer), Some(&mut bytes_read), None) }
            .context("named-pipe read failed")?;
        if bytes_read == 0 {
            bail!("collector closed the named pipe without a response");
        }
        let response: PipeResponse = serde_json::from_slice(&buffer[..bytes_read as usize])
            .context("collector returned invalid JSON")?;
        match response {
            PipeResponse::Ok { data } => {
                serde_json::from_value(data).context("invalid response data")
            }
            PipeResponse::Error { code, message } => Err(anyhow!("{message} ({code})")),
        }
    }
}

fn connect(timeout: Duration) -> Result<HANDLE> {
    let name = wide(PIPE_NAME);
    let started = Instant::now();
    let mut last_error = None;
    loop {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            let details = last_error
                .map(|error: windows::core::Error| format!(": {error}"))
                .unwrap_or_default();
            bail!(
                "PC Pulse collector did not create its named pipe within {:.1}s{details}",
                timeout.as_secs_f32()
            );
        }

        let wait_slice = remaining.min(Duration::from_millis(250));
        let wait_result = unsafe {
            WaitNamedPipeW(
                PCWSTR(name.as_ptr()),
                wait_slice.as_millis().max(1).min(u128::from(u32::MAX)) as u32,
            )
        }
        .ok();
        if let Err(error) = wait_result {
            if !is_transient_pipe_error(&error) {
                return Err(error).context("PC Pulse collector named pipe is unavailable");
            }
            last_error = Some(error);
            thread::sleep(remaining.min(Duration::from_millis(75)));
            continue;
        }

        match unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        } {
            Ok(handle) => return Ok(handle),
            Err(error) if is_transient_pipe_error(&error) => {
                last_error = Some(error);
                thread::sleep(remaining.min(Duration::from_millis(75)));
            }
            Err(error) => return Err(error).context("failed to connect to PC Pulse collector"),
        }
    }
}

fn is_transient_pipe_error(error: &windows::core::Error) -> bool {
    matches!(error.code().0 as u32 & 0xffff, 2 | 121 | 231 | 233)
}

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_and_pipe_race_errors_are_retryable() {
        for code in [2_u32, 121, 231, 233] {
            let error = windows::core::Error::from_hresult(windows::core::HRESULT(
                (0x8007_0000_u32 | code) as i32,
            ));
            assert!(is_transient_pipe_error(&error));
        }
    }

    #[test]
    fn access_denied_is_not_retryable() {
        let error =
            windows::core::Error::from_hresult(windows::core::HRESULT(0x8007_0005_u32 as i32));
        assert!(!is_transient_pipe_error(&error));
    }
}
