use crate::client::PipeClient;
use anyhow::{Context, Result, anyhow, bail};
use pcpulse_service::models::{AgentContext, Alert, OptimizationPlan, PlanAction};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const AGENT_PROMPT: &str = include_str!("../../../agents/pcpulse-systems-analyzer.md");
const PLAN_SCHEMA: &str = include_str!("../../../agents/optimization-plan.schema.json");
const CHAT_PROMPT: &str = include_str!("../../../agents/pcpulse-systems-chat.md");
const CHAT_SCHEMA: &str = include_str!("../../../agents/chat-response.schema.json");
const MAX_AGENT_ERROR_BYTES: usize = 8 * 1_024;
const MAX_FAILURE_LOG_BYTES: usize = 64 * 1_024;
const DEFAULT_ANALYZER_TIMEOUT_SECS: u64 = 300;
const MIN_ANALYZER_TIMEOUT_SECS: u64 = 30;
const MAX_ANALYZER_TIMEOUT_SECS: u64 = 1_800;
pub const ANALYZER_ERROR_LOG_NAME: &str = "analyzer-last-error.log";

/// The active Codex wait budget in seconds: `PCPULSE_ANALYZER_TIMEOUT_SECS`
/// clamped to 30..=1800, defaulting to 300 when unset or unparsable.
pub fn analyzer_timeout_secs() -> u64 {
    clamp_timeout_secs(env::var("PCPULSE_ANALYZER_TIMEOUT_SECS").ok().as_deref())
}

fn clamp_timeout_secs(value: Option<&str>) -> u64 {
    value
        .and_then(|text| text.trim().parse::<u64>().ok())
        .map_or(DEFAULT_ANALYZER_TIMEOUT_SECS, |seconds| {
            seconds.clamp(MIN_ANALYZER_TIMEOUT_SECS, MAX_ANALYZER_TIMEOUT_SECS)
        })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ChatRole {
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatMessage {
    pub role: ChatRole,
    pub timestamp_ms: i64,
    pub text: String,
    pub evidence_refs: Vec<String>,
    /// True for assistant-role turns that record an analyzer failure instead of
    /// an answer. Absent in chat-history files written by older releases, so it
    /// defaults to false, and it is omitted from serialized output when false
    /// to keep the Codex prompt payload unchanged for ordinary turns.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatResponse {
    pub schema_version: u32,
    pub conversation_id: String,
    pub context_id: String,
    pub generated_at_ms: i64,
    pub agent_name: String,
    pub answer: String,
    pub evidence_refs: Vec<String>,
    pub proposed_actions: Vec<PlanAction>,
    pub suggested_follow_ups: Vec<String>,
}

pub const fn agent_prompt() -> &'static str {
    AGENT_PROMPT
}

pub const fn plan_schema() -> &'static str {
    PLAN_SCHEMA
}

pub fn chatgpt_subscription_status() -> Result<String> {
    let executable = find_codex().ok_or_else(|| {
        anyhow!("Codex CLI was not found in PATH; install Codex and sign in with ChatGPT")
    })?;
    let output = codex_command(&executable)
        .args(["login", "status"])
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to check Codex login at {}", executable.display()))?;
    if !output.status.success() {
        let details = combined_output(&output.stdout, &output.stderr);
        bail!("Codex login check failed: {details}");
    }
    let status = combined_output(&output.stdout, &output.stderr);
    if !status.to_ascii_lowercase().contains("chatgpt") {
        bail!(
            "PC Pulse chat requires Codex signed in with ChatGPT subscription access; active status: {status}"
        );
    }
    Ok(status)
}

fn combined_output(stdout: &[u8], stderr: &[u8]) -> String {
    [stdout, stderr]
        .into_iter()
        .map(|bytes| String::from_utf8_lossy(bytes).trim().to_string())
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}

pub fn chat(
    conversation_id: &str,
    conversation: &[ChatMessage],
    window_hours: u32,
    focus_alert: Option<Alert>,
    cancelled: Arc<AtomicBool>,
) -> Result<ChatResponse> {
    chatgpt_subscription_status()?;
    let client = PipeClient;
    let mut context = client.agent_context(window_hours)?;
    inject_focus_alert(&mut context, focus_alert);
    let temporary = TemporaryArtifacts::create(CHAT_SCHEMA, "chat-response")?;
    run_chat(
        conversation_id,
        conversation,
        &context,
        &temporary,
        &cancelled,
    )
    .map_err(|error| annotate_failure(&temporary, "systems chat", error))
}

fn run_chat(
    conversation_id: &str,
    conversation: &[ChatMessage],
    context: &AgentContext,
    temporary: &TemporaryArtifacts,
    cancelled: &AtomicBool,
) -> Result<ChatResponse> {
    let prompt = format!(
        "{CHAT_PROMPT}\n\nconversationId: {conversation_id}\ncontextId: {}\ngeneratedAtMs: {}\n\nPCPULSE_CONVERSATION_JSON\n{}\n\nPCPULSE_EVIDENCE_BUNDLE_JSON\n{}\n",
        context.context_id,
        context.generated_at_ms,
        serde_json::to_string(conversation)?,
        serde_json::to_string(context)?,
    );
    let mut child = spawn_codex(temporary, &prompt)?;
    wait_for_codex(
        &mut child,
        temporary,
        cancelled,
        "systems chat",
        Duration::from_secs(analyzer_timeout_secs()),
    )?;
    let payload = fs::read_to_string(&temporary.output_path)
        .context("Codex completed without writing a chat response")?;
    let response: ChatResponse =
        serde_json::from_str(&payload).context("Codex returned an invalid chat response")?;
    validate_chat_response(&response, conversation_id, context)?;
    Ok(response)
}

pub fn generate_and_save(
    window_hours: u32,
    cancelled: Arc<AtomicBool>,
) -> Result<OptimizationPlan> {
    chatgpt_subscription_status()?;
    let client = PipeClient;
    let context = client.agent_context(window_hours)?;
    let plan = generate(&context, cancelled)?;
    client.save_optimization_plan(plan.clone())?;
    Ok(plan)
}

pub fn generate(context: &AgentContext, cancelled: Arc<AtomicBool>) -> Result<OptimizationPlan> {
    if cancelled.load(Ordering::Acquire) {
        bail!("systems analysis was cancelled");
    }
    let temporary = TemporaryArtifacts::create(PLAN_SCHEMA, "optimization-plan")?;
    run_generate(context, &temporary, &cancelled)
        .map_err(|error| annotate_failure(&temporary, "systems analysis", error))
}

fn run_generate(
    context: &AgentContext,
    temporary: &TemporaryArtifacts,
    cancelled: &AtomicBool,
) -> Result<OptimizationPlan> {
    let prompt = format!(
        "{AGENT_PROMPT}\n\nPCPULSE_EVIDENCE_BUNDLE_JSON\n{}\n",
        serde_json::to_string(context)?
    );
    let mut child = spawn_codex(temporary, &prompt)?;
    wait_for_codex(
        &mut child,
        temporary,
        cancelled,
        "systems analysis",
        Duration::from_secs(analyzer_timeout_secs()),
    )?;
    let payload = fs::read_to_string(&temporary.output_path)
        .context("Codex completed without writing an optimization plan")?;
    let plan: OptimizationPlan =
        serde_json::from_str(&payload).context("Codex returned an invalid optimization plan")?;
    validate_against_context(&plan, context)?;
    Ok(plan)
}

fn spawn_codex(temporary: &TemporaryArtifacts, prompt: &str) -> Result<Child> {
    let executable = find_codex().ok_or_else(|| {
        anyhow!(
            "Codex CLI was not found in PATH; install/authenticate Codex or use `PcPulse.exe agent-context` with another agent"
        )
    })?;
    let stderr = fs::File::create(&temporary.stderr_path)
        .context("failed to create analyzer diagnostic output")?;
    let schema_path = temporary.schema_path.to_string_lossy();
    let output_path = temporary.output_path.to_string_lossy();
    let arguments = [
        "--ask-for-approval",
        "never",
        "exec",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--ignore-user-config",
        "--output-schema",
        schema_path.as_ref(),
        "--output-last-message",
        output_path.as_ref(),
        "-",
    ];
    let mut command = codex_command(&executable);
    let mut child = command
        .args(arguments)
        .current_dir(&temporary.directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("failed to start Codex CLI at {}", executable.display()))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to open Codex analyzer input"))?;
    if let Err(error) = stdin.write_all(prompt.as_bytes()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("failed to send evidence to Codex analyzer");
    }
    drop(stdin);
    Ok(child)
}

fn wait_for_codex(
    child: &mut Child,
    temporary: &TemporaryArtifacts,
    cancelled: &AtomicBool,
    operation: &str,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    loop {
        if cancelled.load(Ordering::Acquire) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{operation} was cancelled");
        }
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("failed to monitor Codex {operation}"))?
        {
            if !status.success() {
                let details = stderr_tail(temporary);
                bail!("Codex {operation} failed ({status}): {details}");
            }
            return Ok(());
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            // Read the stderr tail now, while the temporary artifacts still exist.
            let details = stderr_tail(temporary);
            bail!(
                "Codex {operation} timed out after {}s (budget {}s, set PCPULSE_ANALYZER_TIMEOUT_SECS to adjust): {details}",
                started.elapsed().as_secs(),
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn stderr_tail(temporary: &TemporaryArtifacts) -> String {
    read_bounded(&temporary.stderr_path, MAX_AGENT_ERROR_BYTES)
        .unwrap_or_else(|_| "Codex did not return diagnostic output".into())
}

/// Preserve failure evidence before `TemporaryArtifacts` cleanup deletes it:
/// the Codex stderr tail and the error are copied into
/// `%LOCALAPPDATA%\PcPulse\analyzer-last-error.log` (overwritten on each
/// failure), and the user-facing error is annotated with the log name.
/// User-initiated cancellations pass through untouched.
fn annotate_failure(
    temporary: &TemporaryArtifacts,
    operation: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    let message = format!("{error:#}");
    if message.ends_with("was cancelled") {
        return error;
    }
    let tail = stderr_tail(temporary);
    if let Some(path) = error_log_path() {
        let _ = write_failure_log(&path, operation, &message, &tail);
    }
    anyhow!("{message} · details: {ANALYZER_ERROR_LOG_NAME}")
}

fn error_log_path() -> Option<PathBuf> {
    env::var_os("LOCALAPPDATA").map(|root| {
        PathBuf::from(root)
            .join("PcPulse")
            .join(ANALYZER_ERROR_LOG_NAME)
    })
}

fn write_failure_log(path: &Path, operation: &str, error_text: &str, tail: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut contents = format!(
        "PC Pulse analyzer failure ({operation}) at {}\r\nerror: {error_text}\r\n\r\ncodex stderr tail:\r\n{tail}\r\n",
        chrono::Utc::now().to_rfc3339()
    );
    if contents.len() > MAX_FAILURE_LOG_BYTES {
        let mut boundary = MAX_FAILURE_LOG_BYTES;
        while !contents.is_char_boundary(boundary) {
            boundary -= 1;
        }
        contents.truncate(boundary);
    }
    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
}

fn validate_against_context(plan: &OptimizationPlan, context: &AgentContext) -> Result<()> {
    plan.validate().map_err(anyhow::Error::msg)?;
    if plan.context_id != context.context_id {
        bail!("optimization plan does not match the requested evidence context");
    }
    if plan.generated_at_ms != context.generated_at_ms {
        bail!("optimization plan changed the evidence generation timestamp");
    }
    if plan.agent.name != "pcpulse-systems-analyzer" {
        bail!("optimization plan was not produced under the systems-analyzer contract");
    }
    let mut evidence: HashSet<String> = context
        .process_suspects
        .iter()
        .map(|item| item.evidence_ref.clone())
        .chain(
            context
                .diagnostic_log_rollups
                .iter()
                .map(|item| item.evidence_ref.clone()),
        )
        .collect();
    evidence.extend(
        context
            .recent_alerts
            .iter()
            .map(|alert| format!("alert:{}", alert.id)),
    );
    for reference in plan
        .diagnoses
        .iter()
        .flat_map(|diagnosis| &diagnosis.evidence_refs)
        .chain(plan.actions.iter().flat_map(|action| &action.evidence_refs))
    {
        if !evidence.contains(reference) {
            bail!("optimization plan cites unknown evidence reference {reference}");
        }
    }
    for action in &plan.actions {
        for step in &action.steps {
            let command = step
                .command
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if [
                "stop-process",
                "taskkill",
                "terminateprocess",
                "wmic process",
            ]
            .iter()
            .any(|forbidden| command.contains(forbidden))
            {
                bail!(
                    "optimization plan action {} contains a forbidden direct termination command",
                    action.id
                );
            }
        }
    }
    Ok(())
}

fn validate_chat_response(
    response: &ChatResponse,
    conversation_id: &str,
    context: &AgentContext,
) -> Result<()> {
    if response.schema_version != 1
        || response.agent_name != "pcpulse-systems-analyzer"
        || response.conversation_id != conversation_id
        || response.context_id != context.context_id
        || response.generated_at_ms != context.generated_at_ms
        || response.answer.trim().is_empty()
    {
        bail!("Codex chat response does not match the active conversation and evidence context");
    }
    if response.answer.len() > 6_000
        || response.proposed_actions.len() > 6
        || response.suggested_follow_ups.len() > 4
    {
        bail!("Codex chat response exceeds bounded limits");
    }
    let evidence = evidence_set(context);
    for reference in response.evidence_refs.iter().chain(
        response
            .proposed_actions
            .iter()
            .flat_map(|action| &action.evidence_refs),
    ) {
        if !evidence.contains(reference) {
            bail!("Codex chat cites unknown evidence reference {reference}");
        }
    }
    for action in &response.proposed_actions {
        if action.steps.iter().any(|step| step.mutates_system)
            && (!action.requires_confirmation
                || action
                    .steps
                    .iter()
                    .filter(|step| step.mutates_system)
                    .any(|step| step.confirmation_prompt.as_deref().unwrap_or("").is_empty()))
        {
            bail!("chat action {} mutates without confirmation", action.id);
        }
        for step in &action.steps {
            let command = step
                .command
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if [
                "stop-process",
                "taskkill",
                "terminateprocess",
                "wmic process",
            ]
            .iter()
            .any(|forbidden| command.contains(forbidden))
            {
                bail!("chat action {} contains direct termination", action.id);
            }
        }
    }
    Ok(())
}

/// An investigated finding may have aged out of the fresh-context window;
/// fold it into the bundle so the analyzer sees its data and the citation
/// contract accepts `alert:<id>` references to it.
fn inject_focus_alert(context: &mut AgentContext, focus_alert: Option<Alert>) {
    if let Some(alert) = focus_alert
        && !context.recent_alerts.iter().any(|item| item.id == alert.id)
    {
        context.recent_alerts.push(alert);
    }
}

fn evidence_set(context: &AgentContext) -> HashSet<String> {
    context
        .process_suspects
        .iter()
        .map(|item| item.evidence_ref.clone())
        .chain(
            context
                .diagnostic_log_rollups
                .iter()
                .map(|item| item.evidence_ref.clone()),
        )
        .chain(
            context
                .recent_alerts
                .iter()
                .map(|alert| format!("alert:{}", alert.id)),
        )
        .collect()
}

fn find_codex() -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for directory in env::split_paths(&path) {
        for name in ["codex.exe", "codex.cmd"] {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn codex_command(executable: &Path) -> Command {
    if executable
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("cmd"))
    {
        let mut command = Command::new("cmd.exe");
        command.args(["/d", "/c"]).arg(executable);
        command
    } else {
        Command::new(executable)
    }
}

fn read_bounded(path: &Path, maximum: usize) -> Result<String> {
    let bytes = fs::read(path)?;
    let start = bytes.len().saturating_sub(maximum);
    Ok(String::from_utf8_lossy(&bytes[start..]).trim().to_string())
}

struct TemporaryArtifacts {
    directory: PathBuf,
    schema_path: PathBuf,
    output_path: PathBuf,
    stderr_path: PathBuf,
}

impl TemporaryArtifacts {
    fn create(schema: &str, stem: &str) -> Result<Self> {
        let directory = env::temp_dir().join(format!(
            "PcPulse-Analyzer-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_millis()
        ));
        fs::create_dir(&directory)
            .with_context(|| format!("failed to create {}", directory.display()))?;
        let schema_path = directory.join(format!("{stem}.schema.json"));
        let output_path = directory.join(format!("{stem}.json"));
        let stderr_path = directory.join("codex.stderr.log");
        fs::write(&schema_path, schema).context("failed to stage Codex output schema")?;
        Ok(Self {
            directory,
            schema_path,
            output_path,
            stderr_path,
        })
    }
}

impl Drop for TemporaryArtifacts {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.schema_path);
        let _ = fs::remove_file(&self.output_path);
        let _ = fs::remove_file(&self.stderr_path);
        let _ = fs::remove_dir(&self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcpulse_service::{
        config::Settings,
        models::{AgentSystemRollup, DiagnosticLogStatus, PlanAgent, PlanConstraints, Snapshot},
    };

    fn context() -> AgentContext {
        AgentContext {
            schema_version: 1,
            context_id: "context-1".into(),
            generated_at_ms: 123,
            requested_window_hours: 1,
            effective_history_from_ms: None,
            privacy: Vec::new(),
            safety_constraints: Vec::new(),
            collector_status: DiagnosticLogStatus::default(),
            current: Snapshot::default(),
            settings: Settings::default(),
            system_rollup: AgentSystemRollup {
                sample_count: 0,
                first_sample_ms: None,
                last_sample_ms: None,
                cpu_average_percent: 0.0,
                cpu_p95_percent: 0.0,
                cpu_max_percent: 0.0,
                memory_average_percent: 0.0,
                memory_p95_percent: 0.0,
                memory_max_percent: 0.0,
                disk_latency_p95_ms: 0.0,
                disk_latency_max_ms: 0.0,
                dpc_p95_per_sec: 0.0,
                interrupt_p95_per_sec: 0.0,
            },
            process_suspects: Vec::new(),
            diagnostic_log_rollups: Vec::new(),
            recent_alerts: Vec::new(),
            limitations: Vec::new(),
        }
    }

    fn focus_alert(id: &str) -> Alert {
        Alert {
            id: id.into(),
            kind: "sustainedCpu".into(),
            severity: pcpulse_service::models::Severity::Warning,
            first_seen_ms: 1,
            last_seen_ms: 2,
            process_id: Some(4242),
            process_name: Some("codex.exe".into()),
            title: "Sustained CPU".into(),
            explanation: "test".into(),
            evidence: Vec::new(),
            recommendation: "observe".into(),
            acknowledged: false,
            occurrence_count: 1,
            resolved_at_ms: None,
        }
    }

    #[test]
    fn focus_alert_joins_the_evidence_bundle_exactly_once() {
        let mut bundle = context();
        inject_focus_alert(&mut bundle, Some(focus_alert("aged-out")));
        assert_eq!(bundle.recent_alerts.len(), 1);
        assert!(evidence_set(&bundle).contains("alert:aged-out"));
        // Already-present findings are not duplicated.
        inject_focus_alert(&mut bundle, Some(focus_alert("aged-out")));
        assert_eq!(bundle.recent_alerts.len(), 1);
        inject_focus_alert(&mut bundle, None);
        assert_eq!(bundle.recent_alerts.len(), 1);
    }

    fn empty_plan() -> OptimizationPlan {
        OptimizationPlan {
            schema_version: 1,
            plan_id: "plan-1".into(),
            context_id: "context-1".into(),
            generated_at_ms: 123,
            agent: PlanAgent {
                name: "pcpulse-systems-analyzer".into(),
                model: "codex".into(),
            },
            summary: "No sustained problem is visible.".into(),
            confidence: "low".into(),
            diagnoses: Vec::new(),
            actions: Vec::new(),
            constraints: PlanConstraints {
                never_auto_terminate: true,
                never_auto_apply: true,
                confirmation_required_for_mutations: true,
            },
        }
    }

    #[test]
    fn accepts_plan_bound_to_context() {
        validate_against_context(&empty_plan(), &context()).unwrap();
    }

    #[test]
    fn rejects_context_substitution() {
        let mut plan = empty_plan();
        plan.context_id = "different".into();
        assert!(validate_against_context(&plan, &context()).is_err());
    }

    #[test]
    fn accepts_chat_response_bound_to_conversation_and_context() {
        let response = ChatResponse {
            schema_version: 1,
            conversation_id: "conversation-1".into(),
            context_id: "context-1".into(),
            generated_at_ms: 123,
            agent_name: "pcpulse-systems-analyzer".into(),
            answer: "No sustained problem is visible in the current window.".into(),
            evidence_refs: Vec::new(),
            proposed_actions: Vec::new(),
            suggested_follow_ups: vec!["Inspect a longer evidence window?".into()],
        };
        validate_chat_response(&response, "conversation-1", &context()).unwrap();
    }

    #[test]
    fn rejects_chat_context_or_conversation_substitution() {
        let response = ChatResponse {
            schema_version: 1,
            conversation_id: "different".into(),
            context_id: "context-1".into(),
            generated_at_ms: 123,
            agent_name: "pcpulse-systems-analyzer".into(),
            answer: "Answer".into(),
            evidence_refs: Vec::new(),
            proposed_actions: Vec::new(),
            suggested_follow_ups: Vec::new(),
        };
        assert!(validate_chat_response(&response, "conversation-1", &context()).is_err());
    }

    #[test]
    fn wait_for_codex_kills_child_on_timeout_and_reports_elapsed_with_stderr_tail() {
        let temporary = TemporaryArtifacts::create("{}", "timeout-test").unwrap();
        fs::write(&temporary.stderr_path, "codex stub stderr line").unwrap();
        let mut child = Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let cancelled = AtomicBool::new(false);
        let error = wait_for_codex(
            &mut child,
            &temporary,
            &cancelled,
            "systems chat",
            Duration::from_millis(250),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("timed out after"), "{error}");
        assert!(error.contains("codex stub stderr line"), "{error}");
        assert!(
            child.try_wait().unwrap().is_some(),
            "child must be reaped after timeout"
        );
    }

    #[test]
    fn timeout_budget_is_defaulted_and_clamped() {
        assert_eq!(clamp_timeout_secs(None), 300);
        assert_eq!(clamp_timeout_secs(Some("not-a-number")), 300);
        assert_eq!(clamp_timeout_secs(Some("5")), 30);
        assert_eq!(clamp_timeout_secs(Some("999999")), 1_800);
        assert_eq!(clamp_timeout_secs(Some(" 600 ")), 600);
    }

    #[test]
    fn failure_log_is_written_and_bounded() {
        let path = env::temp_dir().join(format!(
            "pcpulse-analyzer-error-test-{}-{}.log",
            std::process::id(),
            chrono::Utc::now().timestamp_millis()
        ));
        let noisy_tail = "x".repeat(200 * 1_024);
        write_failure_log(
            &path,
            "systems chat",
            "Codex systems chat failed (exit code: 1)",
            &noisy_tail,
        )
        .unwrap();
        let written = fs::read(&path).unwrap();
        assert!(written.len() <= MAX_FAILURE_LOG_BYTES);
        let text = String::from_utf8(written).unwrap();
        assert!(text.contains("Codex systems chat failed"));
        assert!(text.contains("codex stderr tail:"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn chat_messages_without_error_flag_deserialize_as_ordinary_turns() {
        let legacy = r#"{"role":"user","timestampMs":1,"text":"question","evidenceRefs":[]}"#;
        let message: ChatMessage = serde_json::from_str(legacy).unwrap();
        assert!(!message.is_error);
        // Ordinary turns serialize without the flag, keeping the Codex prompt payload unchanged.
        assert!(!serde_json::to_string(&message).unwrap().contains("isError"));
    }

    #[test]
    fn login_status_accepts_output_from_either_stream() {
        assert_eq!(
            combined_output(b"", b"Logged in using ChatGPT\r\n"),
            "Logged in using ChatGPT"
        );
        assert_eq!(
            combined_output(b"Logged in using ChatGPT\n", b""),
            "Logged in using ChatGPT"
        );
    }

    #[test]
    fn checked_in_agent_context_fixture_matches_wire_model() {
        let fixture = include_str!("../../../tests/agent-context.sample.json");
        let context: AgentContext = serde_json::from_str(fixture).unwrap();
        assert_eq!(context.schema_version, 1);
        assert_eq!(context.process_suspects.len(), 1);
        assert_eq!(
            context.process_suspects[0].evidence_ref,
            "process:4242:1786186800000"
        );
    }
}
