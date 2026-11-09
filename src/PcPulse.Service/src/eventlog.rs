use crate::models::{
    DiagnosticCategory, DiagnosticField, DiagnosticLevel, DiagnosticLog, DiagnosticLogStatus,
};
use anyhow::{Context, Result, anyhow, bail};
use chrono::DateTime;
use serde::Deserialize;
use std::collections::{HashSet, VecDeque};
use windows::{
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS},
        System::EventLog::{
            EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
            EvtRender, EvtRenderEventXml,
        },
    },
    core::{HRESULT, HSTRING},
};

const CHANNELS: [&str; 2] = ["System", "Application"];
const INITIAL_LOOKBACK_MS: i64 = 15 * 60 * 1_000;
const STEADY_LOOKBACK_MS: i64 = 2 * 60 * 1_000;
const MAX_EVENTS_PER_CHANNEL: usize = 128;
const MAX_RECENT_IDENTITIES: usize = 4_096;
const MAX_EVENT_XML_BYTES: u32 = 64 * 1_024;
const MAX_FIELDS: usize = 20;
const MAX_FIELD_CHARS: usize = 320;

pub struct EventLogCollector {
    initial_poll: bool,
    recent_order: VecDeque<String>,
    recent: HashSet<String>,
    status: DiagnosticLogStatus,
}

impl Default for EventLogCollector {
    fn default() -> Self {
        Self {
            initial_poll: true,
            recent_order: VecDeque::with_capacity(MAX_RECENT_IDENTITIES),
            recent: HashSet::with_capacity(MAX_RECENT_IDENTITIES),
            status: DiagnosticLogStatus::default(),
        }
    }
}

impl EventLogCollector {
    pub fn poll(&mut self, now_ms: i64, agent_patterns: &[String]) -> Vec<DiagnosticLog> {
        self.status.last_poll_ms = Some(now_ms);
        let lookback = if self.initial_poll {
            INITIAL_LOOKBACK_MS
        } else {
            STEADY_LOOKBACK_MS
        };
        self.initial_poll = false;
        let mut result = Vec::new();
        let mut errors = Vec::new();
        for channel in CHANNELS {
            match query_channel(channel, lookback, agent_patterns) {
                Ok((events, truncated, malformed)) => {
                    self.accept_events(events, truncated, malformed, &mut result);
                }
                Err(error) => errors.push(format!("{channel}: {error:#}")),
            }
        }
        if errors.is_empty() {
            self.status.last_success_ms = Some(now_ms);
            self.status.last_error = None;
        } else {
            self.status.last_error = Some(errors.join("; "));
        }
        result
    }

    /// Recover high-signal network events crowded out of a capped general
    /// poll. The caller invokes this only when that poll's truncation counter
    /// advances and network monitoring is enabled. It shares parsing, bounds,
    /// and deduplication with the ordinary collector; it is not another
    /// standing event-log scan.
    pub fn poll_network_signals(
        &mut self,
        now_ms: i64,
        agent_patterns: &[String],
    ) -> Vec<DiagnosticLog> {
        self.status.last_poll_ms = Some(now_ms);
        let mut result = Vec::new();
        match query_channel_with_filter("System", &network_signal_query(), agent_patterns) {
            Ok((events, truncated, malformed)) => {
                self.accept_events(events, truncated, malformed, &mut result);
                // A successful fallback cannot erase an error from the
                // general poll, whose other channels still matter.
            }
            Err(error) => {
                let message = format!("System network fallback: {error:#}");
                self.status.last_error = Some(match self.status.last_error.take() {
                    Some(previous) => format!("{previous}; {message}"),
                    None => message,
                });
            }
        }
        result
    }

    pub fn status(&self) -> DiagnosticLogStatus {
        self.status.clone()
    }

    pub fn note_storage_error(&mut self, message: String) {
        self.status.last_error = Some(message);
    }

    fn accept_events(
        &mut self,
        events: Vec<DiagnosticLog>,
        truncated: bool,
        malformed: u64,
        result: &mut Vec<DiagnosticLog>,
    ) {
        self.status.malformed_events = self.status.malformed_events.saturating_add(malformed);
        if truncated {
            self.status.truncated_polls = self.status.truncated_polls.saturating_add(1);
        }
        for event in events {
            self.status.events_seen = self.status.events_seen.saturating_add(1);
            let identity = format!(
                "{}:{}:{}",
                event.channel, event.record_id, event.timestamp_ms
            );
            if !self.remember(identity) {
                self.status.duplicate_events = self.status.duplicate_events.saturating_add(1);
                continue;
            }
            self.status.events_stored = self.status.events_stored.saturating_add(1);
            result.push(event);
        }
    }

    fn remember(&mut self, identity: String) -> bool {
        if !self.recent.insert(identity.clone()) {
            return false;
        }
        self.recent_order.push_back(identity);
        while self.recent_order.len() > MAX_RECENT_IDENTITIES {
            if let Some(oldest) = self.recent_order.pop_front() {
                self.recent.remove(&oldest);
            }
        }
        true
    }
}

fn query_channel(
    channel: &str,
    lookback_ms: i64,
    agent_patterns: &[String],
) -> Result<(Vec<DiagnosticLog>, bool, u64)> {
    let query = format!(
        "*[System[((Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= {lookback_ms}])]]"
    );
    query_channel_with_filter(channel, &query, agent_patterns)
}

fn network_signal_query() -> String {
    format!(
        "*[System[TimeCreated[timediff(@SystemTime) <= {STEADY_LOOKBACK_MS}] and \
         ((Provider[@Name='Microsoft-Windows-DNS-Client'] and EventID=1014) or \
         ((Provider[@Name='Tcpip'] or Provider[@Name='Microsoft-Windows-TCPIP']) and \
         (EventID=4231 or EventID=4227)))]]"
    )
}

fn query_channel_with_filter(
    channel: &str,
    filter: &str,
    agent_patterns: &[String],
) -> Result<(Vec<DiagnosticLog>, bool, u64)> {
    let path = HSTRING::from(channel);
    let query = HSTRING::from(filter);
    let handle = unsafe {
        EvtQuery(
            None,
            &path,
            &query,
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
    }
    .with_context(|| format!("failed to query {channel} event log"))?;
    let _query_guard = EvtHandle(handle);
    let mut result = Vec::new();
    let mut malformed = 0_u64;
    let mut examined = 0_usize;
    let mut no_more_items = false;
    while examined < MAX_EVENTS_PER_CHANNEL {
        let mut handles = [0_isize; 16];
        let mut returned = 0_u32;
        match unsafe { EvtNext(handle, &mut handles, 0, 0, &mut returned) } {
            Ok(()) => {}
            Err(error) if error.code() == HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0) => {
                no_more_items = true;
                break;
            }
            Err(error) => return Err(error).context("failed to enumerate Windows events"),
        }
        if returned == 0 {
            no_more_items = true;
            break;
        }
        for raw in handles.into_iter().take(returned as usize) {
            let event_handle = EVT_HANDLE(raw);
            let _event_guard = EvtHandle(event_handle);
            if examined >= MAX_EVENTS_PER_CHANNEL {
                continue;
            }
            examined += 1;
            match render_xml(event_handle)
                .and_then(|xml| parse_event_xml(channel, &xml, agent_patterns))
            {
                Ok(event) => result.push(event),
                Err(_) => malformed += 1,
            }
        }
    }
    let truncated = !no_more_items && examined >= MAX_EVENTS_PER_CHANNEL;
    Ok((result, truncated, malformed))
}

fn render_xml(event: EVT_HANDLE) -> Result<String> {
    let mut bytes_used = 0_u32;
    let mut property_count = 0_u32;
    let first = unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut bytes_used,
            &mut property_count,
        )
    };
    if let Err(error) = first
        && error.code() != HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0)
    {
        return Err(error).context("failed to size Windows event XML");
    }
    if bytes_used == 0 || bytes_used > MAX_EVENT_XML_BYTES {
        bail!("Windows event XML size {bytes_used} is outside bounded limits");
    }
    let mut buffer = vec![0_u16; (bytes_used as usize).div_ceil(2)];
    unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            bytes_used,
            Some(buffer.as_mut_ptr().cast()),
            &mut bytes_used,
            &mut property_count,
        )
    }
    .context("failed to render Windows event XML")?;
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..length]).context("Windows event XML was not valid UTF-16")
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Event")]
struct XmlEvent {
    #[serde(rename = "System")]
    system: XmlSystem,
    #[serde(rename = "EventData", default)]
    event_data: XmlEventData,
}

#[derive(Debug, Deserialize)]
struct XmlSystem {
    #[serde(rename = "Provider")]
    provider: XmlProvider,
    #[serde(rename = "EventID")]
    event_id: XmlNumber<u32>,
    #[serde(rename = "Level")]
    level: XmlNumber<u8>,
    #[serde(rename = "TimeCreated")]
    time_created: XmlTimeCreated,
    #[serde(rename = "EventRecordID")]
    record_id: XmlNumber<u64>,
    #[serde(rename = "Execution", default)]
    execution: XmlExecution,
}

#[derive(Debug, Deserialize)]
struct XmlProvider {
    #[serde(rename = "@Name")]
    name: String,
}

#[derive(Debug, Deserialize)]
struct XmlNumber<T> {
    #[serde(rename = "$text")]
    value: T,
}

#[derive(Debug, Deserialize)]
struct XmlTimeCreated {
    #[serde(rename = "@SystemTime")]
    system_time: String,
}

#[derive(Debug, Default, Deserialize)]
struct XmlExecution {
    #[serde(rename = "@ProcessID")]
    process_id: Option<u32>,
    #[serde(rename = "@ThreadID")]
    thread_id: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct XmlEventData {
    #[serde(rename = "Data", default)]
    data: Vec<XmlData>,
}

#[derive(Debug, Deserialize)]
struct XmlData {
    #[serde(rename = "@Name")]
    name: Option<String>,
    #[serde(rename = "$text")]
    value: Option<String>,
}

fn parse_event_xml(channel: &str, xml: &str, agent_patterns: &[String]) -> Result<DiagnosticLog> {
    let parsed: XmlEvent = quick_xml::de::from_str(xml).context("malformed Windows event XML")?;
    let timestamp_ms = DateTime::parse_from_rfc3339(&parsed.system.time_created.system_time)
        .map_err(|error| anyhow!("invalid Windows event timestamp: {error}"))?
        .timestamp_millis();
    let level = match parsed.system.level.value {
        1 => DiagnosticLevel::Critical,
        2 => DiagnosticLevel::Error,
        3 => DiagnosticLevel::Warning,
        value => bail!("unexpected diagnostic level {value}"),
    };
    let fields: Vec<DiagnosticField> = parsed
        .event_data
        .data
        .into_iter()
        .enumerate()
        .filter_map(|(index, field)| {
            let name = field.name.unwrap_or_else(|| format!("param{}", index + 1));
            let value = redact_field(&name, field.value.as_deref().unwrap_or_default());
            (!value.is_empty()).then(|| DiagnosticField {
                name: truncate(&sanitize(&name), 96),
                value,
            })
        })
        .take(MAX_FIELDS)
        .collect();
    let related_process = find_related_process(&fields);
    let category = classify(
        channel,
        &parsed.system.provider.name,
        parsed.system.event_id.value,
        related_process.as_deref(),
        &fields,
        agent_patterns,
    );
    let fingerprint = truncate(
        &format!(
            "{}:{}:{}",
            parsed.system.provider.name.to_ascii_lowercase(),
            parsed.system.event_id.value,
            related_process
                .as_deref()
                .unwrap_or("system")
                .to_ascii_lowercase()
        ),
        512,
    );
    Ok(DiagnosticLog {
        timestamp_ms,
        channel: channel.to_string(),
        provider: truncate(&sanitize(&parsed.system.provider.name), 160),
        event_id: parsed.system.event_id.value,
        record_id: parsed.system.record_id.value,
        level,
        category,
        process_id: parsed.system.execution.process_id.filter(|pid| *pid != 0),
        thread_id: parsed.system.execution.thread_id.filter(|tid| *tid != 0),
        related_process,
        fingerprint,
        fields,
    })
}

fn redact_field(name: &str, raw: &str) -> String {
    let lower_name = name.to_ascii_lowercase();
    if [
        "password",
        "passwd",
        "token",
        "secret",
        "credential",
        "authorization",
        "cookie",
    ]
    .iter()
    .any(|needle| lower_name.contains(needle))
    {
        return "<redacted>".into();
    }
    let profile_redacted = redact_user_profile(raw);
    let inline_redacted = redact_inline_secrets(&profile_redacted);
    truncate(&sanitize(&inline_redacted), MAX_FIELD_CHARS)
}

/// Replaces every `<drive>:\Users\<name>` prefix with `%USERPROFILE%`.
/// Shared with the crash-dump scanner, which surfaces per-user WER paths.
pub(crate) fn redact_user_profile(value: &str) -> String {
    let mut result = value.to_string();
    loop {
        let lower = result.to_ascii_lowercase();
        let Some(marker) = lower.find(":\\users\\") else {
            break;
        };
        let profile_start = marker.saturating_sub(1);
        let username_start = marker + ":\\users\\".len();
        let username_end = result[username_start..]
            .find('\\')
            .map_or(result.len(), |offset| username_start + offset);
        result.replace_range(profile_start..username_end, "%USERPROFILE%");
    }
    result
}

fn redact_inline_secrets(value: &str) -> String {
    let sensitive = ["password", "passwd", "token", "secret", "authorization"];
    let mut result = Vec::new();
    let mut redact_next = false;
    for part in value.split_whitespace() {
        if redact_next {
            result.push("<redacted>".to_string());
            redact_next = false;
            continue;
        }
        let lower = part.to_ascii_lowercase();
        if let Some((key, _)) = part.split_once('=')
            && sensitive
                .iter()
                .any(|needle| key.to_ascii_lowercase().contains(needle))
        {
            result.push(format!("{key}=<redacted>"));
            continue;
        }
        if let Some((key, _)) = part.split_once(':')
            && sensitive
                .iter()
                .any(|needle| key.to_ascii_lowercase().contains(needle))
        {
            result.push(format!("{key}:<redacted>"));
            continue;
        }
        if sensitive
            .iter()
            .any(|needle| lower == format!("--{needle}") || lower == format!("/{needle}"))
        {
            result.push(part.to_string());
            redact_next = true;
        } else {
            result.push(part.to_string());
        }
    }
    result.join(" ")
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() && !character.is_whitespace() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate(value: &str, maximum_chars: usize) -> String {
    let mut result: String = value.chars().take(maximum_chars).collect();
    if value.chars().count() > maximum_chars {
        result.push('…');
    }
    result
}

fn find_related_process(fields: &[DiagnosticField]) -> Option<String> {
    let named = fields.iter().find(|field| {
        let name = field.name.to_ascii_lowercase();
        [
            "appname",
            "applicationname",
            "faultingapplicationname",
            "processname",
            "exename",
        ]
        .iter()
        .any(|candidate| name.replace([' ', '_'], "").contains(candidate))
    });
    named
        .or_else(|| {
            fields.iter().find(|field| {
                let lower = field.value.to_ascii_lowercase();
                lower.ends_with(".exe") || lower.contains(".exe,")
            })
        })
        .map(|field| {
            let normalized = field.value.replace('/', "\\");
            normalized
                .rsplit('\\')
                .next()
                .unwrap_or(&normalized)
                .split(',')
                .next()
                .unwrap_or(&normalized)
                .trim()
                .to_string()
        })
        .filter(|value| !value.is_empty())
}

fn classify(
    channel: &str,
    provider: &str,
    event_id: u32,
    related_process: Option<&str>,
    fields: &[DiagnosticField],
    agent_patterns: &[String],
) -> DiagnosticCategory {
    let provider = provider.to_ascii_lowercase();
    if !agent_patterns.is_empty() {
        let searchable = format!(
            "{} {} {}",
            provider,
            related_process.unwrap_or_default().to_ascii_lowercase(),
            fields
                .iter()
                .map(|field| field.value.to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(" ")
        );
        if agent_patterns
            .iter()
            .filter(|pattern| pattern.len() >= 3)
            .any(|pattern| searchable.contains(&pattern.to_ascii_lowercase()))
        {
            return DiagnosticCategory::AgentRuntime;
        }
    }
    if provider.contains("whea") {
        DiagnosticCategory::Hardware
    } else if ["disk", "storport", "stornvme", "storahci", "ntfs", "volmgr"]
        .iter()
        .any(|needle| provider.contains(needle))
    {
        DiagnosticCategory::Storage
    } else if ["display", "nvlddmkm", "amdkmdag", "igfx"]
        .iter()
        .any(|needle| provider.contains(needle))
    {
        DiagnosticCategory::Graphics
    } else if channel.eq_ignore_ascii_case("System")
        && provider == "microsoft-windows-resource-exhaustion-detector"
        && event_id == 2004
    {
        DiagnosticCategory::ResourceExhaustion
    } else if channel.eq_ignore_ascii_case("Application")
        && matches!(provider.as_str(), "application hang" | "applicationhang")
        && event_id == 1002
    {
        DiagnosticCategory::ApplicationHang
    } else if channel.eq_ignore_ascii_case("Application")
        && provider == "application error"
        && event_id == 1000
    {
        DiagnosticCategory::ApplicationCrash
    } else if channel.eq_ignore_ascii_case("Application")
        && provider == "windows error reporting"
        && event_id == 1001
    {
        classify_wer_report(fields)
    } else if provider.contains("kernel-power") || provider.contains("power") {
        DiagnosticCategory::Power
    } else if provider.contains("service control manager") {
        DiagnosticCategory::Service
    } else if ["tcpip", "dns", "ndis", "wlan"]
        .iter()
        .any(|needle| provider.contains(needle))
    {
        DiagnosticCategory::Network
    } else {
        DiagnosticCategory::Other
    }
}

fn classify_wer_report(fields: &[DiagnosticField]) -> DiagnosticCategory {
    // WER also reports hangs, memory leak checks and live kernel events.
    // The event ID alone does not identify an application crash.
    let Some(report_type) = fields
        .iter()
        .find(|field| field.name.eq_ignore_ascii_case("EventName"))
        .map(|field| field.value.trim().to_ascii_lowercase())
    else {
        return DiagnosticCategory::Other;
    };
    if report_type.starts_with("apphang") || report_type.starts_with("moapphang") {
        DiagnosticCategory::ApplicationHang
    } else if matches!(
        report_type.as_str(),
        "appcrash" | "bex" | "bex64" | "clr20r3" | "moappcrash" | "mobex" | "mobex64"
    ) {
        DiagnosticCategory::ApplicationCrash
    } else {
        DiagnosticCategory::Other
    }
}

/// Correct labels written by the old ID-only classifier without rewriting
/// history. AgentRuntime retains the pattern match made when it was collected.
pub(crate) fn normalize_legacy_category(log: &mut DiagnosticLog) {
    if matches!(
        log.category,
        DiagnosticCategory::ApplicationCrash
            | DiagnosticCategory::ApplicationHang
            | DiagnosticCategory::ResourceExhaustion
    ) {
        log.category = classify(
            &log.channel,
            &log.provider,
            log.event_id,
            log.related_process.as_deref(),
            &log.fields,
            &[],
        );
    }
}

struct EvtHandle(EVT_HANDLE);

impl Drop for EvtHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = EvtClose(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT_XML: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Application Error"/><EventID Qualifiers="0">1000</EventID><Level>2</Level><TimeCreated SystemTime="2026-08-08T12:34:56.1234567Z"/><EventRecordID>42</EventRecordID><Execution ProcessID="123" ThreadID="456"/><Channel>Application</Channel></System><EventData><Data Name="AppName">codex.exe</Data><Data Name="Path">C:\Users\xavier\work\codex.exe</Data><Data Name="ApiToken">do-not-store</Data></EventData></Event>"#;

    #[test]
    fn fallback_ingestion_shares_dedupe_and_coverage_counters() {
        let mut collector = EventLogCollector::default();
        let mut already_seen = parse_event_xml("System", EVENT_XML, &[]).unwrap();
        already_seen.provider = "Tcpip".into();
        already_seen.event_id = 4231;
        let mut recovered = already_seen.clone();
        recovered.record_id += 1;
        let mut general = Vec::new();
        collector.accept_events(vec![already_seen.clone()], true, 1, &mut general);
        let mut fallback = Vec::new();
        collector.accept_events(
            vec![already_seen, recovered.clone()],
            false,
            2,
            &mut fallback,
        );
        assert_eq!(general.len(), 1);
        assert_eq!(fallback, vec![recovered]);
        assert_eq!(collector.status.events_seen, 3);
        assert_eq!(collector.status.events_stored, 2);
        assert_eq!(collector.status.duplicate_events, 1);
        assert_eq!(collector.status.malformed_events, 3);
        assert_eq!(collector.status.truncated_polls, 1);
        assert_eq!(collector.recent.len(), 2);
    }

    #[test]
    fn parses_classifies_and_redacts_event_xml() {
        let event = parse_event_xml("Application", EVENT_XML, &["codex".into()]).unwrap();
        assert_eq!(event.event_id, 1000);
        assert_eq!(event.record_id, 42);
        assert_eq!(event.level, DiagnosticLevel::Error);
        assert_eq!(event.category, DiagnosticCategory::AgentRuntime);
        assert_eq!(event.related_process.as_deref(), Some("codex.exe"));
        assert!(event.fields[1].value.contains("%USERPROFILE%"));
        assert_eq!(event.fields[2].value, "<redacted>");
    }

    #[test]
    fn classifies_high_signal_providers() {
        assert_eq!(
            classify(
                "System",
                "Microsoft-Windows-WHEA-Logger",
                18,
                None,
                &[],
                &[]
            ),
            DiagnosticCategory::Hardware
        );
        assert_eq!(
            classify("System", "disk", 153, None, &[], &[]),
            DiagnosticCategory::Storage
        );
        assert_eq!(
            classify(
                "System",
                "Microsoft-Windows-Resource-Exhaustion-Detector",
                2004,
                None,
                &[],
                &[]
            ),
            DiagnosticCategory::ResourceExhaustion
        );
    }

    #[test]
    fn crash_hang_and_exhaustion_ids_are_scoped_to_their_providers() {
        for event_id in [1000, 1001, 1002, 2004] {
            assert_eq!(
                classify("Application", "vmauthd", event_id, None, &[], &[]),
                DiagnosticCategory::Other,
                "unrelated provider event {event_id}"
            );
        }
        let cases = [
            (
                "Application",
                "Application Error",
                1000,
                DiagnosticCategory::ApplicationCrash,
            ),
            (
                "application",
                "APPLICATION HANG",
                1002,
                DiagnosticCategory::ApplicationHang,
            ),
            (
                "Application",
                "ApplicationHang",
                1002,
                DiagnosticCategory::ApplicationHang,
            ),
            (
                "System",
                "Microsoft-Windows-Resource-Exhaustion-Detector",
                2004,
                DiagnosticCategory::ResourceExhaustion,
            ),
            (
                "System",
                "Application Error",
                1000,
                DiagnosticCategory::Other,
            ),
            (
                "Application",
                "Application Error",
                1001,
                DiagnosticCategory::Other,
            ),
            (
                "Application",
                "Application Hang",
                1000,
                DiagnosticCategory::Other,
            ),
            (
                "System",
                "Microsoft-Windows-Resource-Exhaustion-Detector",
                1000,
                DiagnosticCategory::Other,
            ),
            (
                "Application",
                "Custom Application Error Provider",
                1000,
                DiagnosticCategory::Other,
            ),
            (
                "Application",
                "Custom Application Hang Provider",
                1002,
                DiagnosticCategory::Other,
            ),
        ];
        for (channel, provider, event_id, expected) in cases {
            assert_eq!(
                classify(channel, provider, event_id, None, &[], &[]),
                expected,
                "{channel}/{provider}/{event_id}"
            );
        }
    }

    #[test]
    fn wer_report_type_distinguishes_hangs_crashes_and_other_reports() {
        for (report_type, expected) in [
            ("AppHangB1", DiagnosticCategory::ApplicationHang),
            ("AppHangXProcB1", DiagnosticCategory::ApplicationHang),
            ("AppHangTransient", DiagnosticCategory::ApplicationHang),
            ("MoAppHang", DiagnosticCategory::ApplicationHang),
            (" apphangb1 ", DiagnosticCategory::ApplicationHang),
            ("APPCRASH", DiagnosticCategory::ApplicationCrash),
            ("BEX", DiagnosticCategory::ApplicationCrash),
            ("BEX64", DiagnosticCategory::ApplicationCrash),
            ("CLR20r3", DiagnosticCategory::ApplicationCrash),
            ("MoAppCrash", DiagnosticCategory::ApplicationCrash),
            ("MoBEX", DiagnosticCategory::ApplicationCrash),
            ("MoBEX64", DiagnosticCategory::ApplicationCrash),
            ("LiveKernelEvent", DiagnosticCategory::Other),
            ("BlueScreen", DiagnosticCategory::Other),
            ("RADAR_PRE_LEAK_64", DiagnosticCategory::Other),
            ("UnknownReport", DiagnosticCategory::Other),
            ("", DiagnosticCategory::Other),
        ] {
            let fields = [DiagnosticField {
                name: "eventname".into(),
                value: report_type.into(),
            }];
            assert_eq!(
                classify(
                    "Application",
                    "Windows Error Reporting",
                    1001,
                    None,
                    &fields,
                    &[]
                ),
                expected,
                "WER report {report_type}"
            );
        }
        let app_name_only = [DiagnosticField {
            name: "AppName".into(),
            value: "AppHangB1.exe".into(),
        }];
        assert_eq!(
            classify(
                "Application",
                "Windows Error Reporting",
                1001,
                None,
                &app_name_only,
                &[]
            ),
            DiagnosticCategory::Other
        );
        let fields = [DiagnosticField {
            name: "EventName".into(),
            value: "APPCRASH".into(),
        }];
        assert_eq!(
            classify(
                "Application",
                "Windows Error Reporting",
                1000,
                None,
                &fields,
                &[]
            ),
            DiagnosticCategory::Other
        );
        assert_eq!(
            classify(
                "System",
                "Windows Error Reporting",
                1001,
                None,
                &fields,
                &[]
            ),
            DiagnosticCategory::Other
        );
    }

    #[test]
    fn xml_classification_preserves_vmware_events_and_wer_hang_evidence() {
        let vmware_xml = EVENT_XML.replace("Application Error", "vmauthd");
        let vmware = parse_event_xml("Application", &vmware_xml, &[]).unwrap();
        assert_eq!(vmware.category, DiagnosticCategory::Other);
        assert_eq!(vmware.record_id, 42);
        assert_eq!(vmware.fields.len(), 3);
        let hang_xml = EVENT_XML
            .replace("Application Error", "Windows Error Reporting")
            .replace(">1000</EventID>", ">1001</EventID>")
            .replace(
                "<EventData>",
                "<EventData><Data Name=\"EventName\">AppHangB1</Data>",
            );
        let hang = parse_event_xml("Application", &hang_xml, &[]).unwrap();
        assert_eq!(hang.category, DiagnosticCategory::ApplicationHang);
        assert_eq!(hang.related_process.as_deref(), Some("codex.exe"));
        assert_eq!(hang.fields[0].value, "AppHangB1");
        assert_eq!(
            parse_event_xml("Application", &hang_xml, &["CoDeX".into()])
                .unwrap()
                .category,
            DiagnosticCategory::AgentRuntime
        );
    }

    #[test]
    fn redacts_separate_secret_arguments_and_multiple_profiles() {
        assert_eq!(
            redact_inline_secrets("tool --token abc --mode safe password:hunter2"),
            "tool --token <redacted> --mode safe password:<redacted>"
        );
        assert_eq!(
            redact_user_profile(r"C:\Users\alice\a.log copied to D:\Users\bob\b.log"),
            r"%USERPROFILE%\a.log copied to %USERPROFILE%\b.log"
        );
    }

    #[test]
    fn recent_identity_cache_is_bounded_and_deduplicates() {
        let mut collector = EventLogCollector::default();
        assert!(collector.remember("a".into()));
        assert!(!collector.remember("a".into()));
        for index in 0..(MAX_RECENT_IDENTITIES + 10) {
            assert!(collector.remember(format!("item-{index}")));
        }
        assert!(collector.recent.len() <= MAX_RECENT_IDENTITIES);
        assert!(collector.recent_order.len() <= MAX_RECENT_IDENTITIES);
    }

    #[test]
    fn polls_local_application_and_system_channels() {
        let mut collector = EventLogCollector::default();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let _ = collector.poll(now_ms, &[]);
        let status = collector.status();
        assert_eq!(status.last_poll_ms, Some(now_ms));
        assert_eq!(
            status.last_success_ms,
            Some(now_ms),
            "{:?}",
            status.last_error
        );
        assert!(status.last_error.is_none());
    }
}
