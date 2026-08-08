use crate::client::PipeClient;
use anyhow::{Context, Result, anyhow, bail};
use pcpulse_service::models::{AgentContext, OptimizationPlan, PlanAction};
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
    time::Duration,
};

const AGENT_PROMPT: &str = include_str!("../../../agents/pcpulse-systems-analyzer.md");
const PLAN_SCHEMA: &str = include_str!("../../../agents/optimization-plan.schema.json");
const CHAT_PROMPT: &str = include_str!("../../../agents/pcpulse-systems-chat.md");
const CHAT_SCHEMA: &str = include_str!("../../../agents/chat-response.schema.json");
const MAX_AGENT_ERROR_BYTES: usize = 8 * 1_024;

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
    cancelled: Arc<AtomicBool>,
) -> Result<ChatResponse> {
    chatgpt_subscription_status()?;
    let client = PipeClient;
    let context = client.agent_context(window_hours)?;
    let temporary = TemporaryArtifacts::create(CHAT_SCHEMA, "chat-response")?;
    let prompt = format!(
        "{CHAT_PROMPT}\n\nconversationId: {conversation_id}\ncontextId: {}\ngeneratedAtMs: {}\n\nPCPULSE_CONVERSATION_JSON\n{}\n\nPCPULSE_EVIDENCE_BUNDLE_JSON\n{}\n",
        context.context_id,
        context.generated_at_ms,
        serde_json::to_string(conversation)?,
        serde_json::to_string(&context)?,
    );
    let mut child = spawn_codex(&temporary, &prompt)?;
    wait_for_codex(&mut child, &temporary, &cancelled, "systems chat")?;
    let payload = fs::read_to_string(&temporary.output_path)
        .context("Codex completed without writing a chat response")?;
    let response: ChatResponse =
        serde_json::from_str(&payload).context("Codex returned an invalid chat response")?;
    validate_chat_response(&response, conversation_id, &context)?;
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
    let prompt = format!(
        "{AGENT_PROMPT}\n\nPCPULSE_EVIDENCE_BUNDLE_JSON\n{}\n",
        serde_json::to_string(context)?
    );
    let mut child = spawn_codex(&temporary, &prompt)?;
    wait_for_codex(&mut child, &temporary, &cancelled, "systems analysis")?;
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
) -> Result<()> {
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
                let details = read_bounded(&temporary.stderr_path, MAX_AGENT_ERROR_BYTES)
                    .unwrap_or_else(|_| "Codex did not return diagnostic output".into());
                bail!("Codex {operation} failed ({status}): {details}");
            }
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
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
