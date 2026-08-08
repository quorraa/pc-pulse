# Systems-analyzer integration

PC Pulse separates evidence collection, reasoning, and execution:

1. The LocalSystem collector reads metrics and warning/error/critical records from the local Windows Application and System event logs. It never invokes an AI and never uses the network.
2. `getAgentContext` converts recent raw history into a bounded evidence bundle: system percentiles, sustained process rollups, current high-pressure/agent processes, repeated diagnostic-event fingerprints, alerts, collector health, privacy notes, and known limitations.
3. The per-user client invokes the dedicated `pcpulse-systems-analyzer` through Codex in an ephemeral read-only sandbox. Chat responses must match `agents/chat-response.schema.json`; one-shot plans must match `agents/optimization-plan.schema.json`.
4. The client validates conversation identity, evidence identity, references, action safety, and size bounds before displaying the answer. Nothing in a response is automatically executed.

## Embedded chatbot

Open route `6` (**Oracle**), press `Enter` or `/`, type a question, and press `Enter` to submit. The TUI owns the entire workflow; another terminal command or external chat is not required.

Each turn obtains a new one-to-24-hour evidence bundle and includes at most 16 recent local conversation messages. `j`/`k` and Page Up/Page Down scroll, `[`/`]` change the evidence window, `n`/`c` starts a new conversation, `h` focuses Chat Vault, and `Esc` cancels a running answer. Collector snapshot polling continues on the independent worker while Codex runs.

Oracle requires Codex on the interactive user's `PATH` and a saved ChatGPT login. It runs `codex login status` and proceeds only when the active method is ChatGPT. This intentionally uses the user's Codex/ChatGPT subscription access and rejects API-key sessions rather than silently falling back to usage billing. PC Pulse invokes Codex with:

- an ephemeral session;
- a read-only sandbox;
- no approval escalation;
- the embedded systems-analyzer prompt;
- the strict chat-response output schema.

The model receives only the explicit redacted evidence bundle and bounded conversation. It has no PC Pulse tools and cannot execute its proposed actions. Chat Vault persists up to 24 per-user sessions in `%LOCALAPPDATA%\PcPulse\chat-history.json`, with at most 16 messages per session. The store contains conversations and validated responses, not raw evidence bundles or Windows event records.

## One-shot plan interface

Automation can still generate and store a structured plan from the last hour:

```powershell
PcPulse.exe analyze 1
```

Ctrl-C cancels the run and terminates the child analyzer process. This interface uses the same ChatGPT authentication gate and safety validation.

## External-agent contract

Any agent can integrate without using the built-in Codex runner:

```powershell
PcPulse.exe agent-context 1 > evidence.json
PcPulse.exe plan-schema > optimization-plan.schema.json
PcPulse.exe agent-prompt > pcpulse-systems-analyzer.md
# The external agent reads those three files and writes plan.json.
PcPulse.exe validate-plan .\plan.json
PcPulse.exe import-plan .\plan.json
PcPulse.exe plan
```

The evidence window accepts 1–24 hours. `agent-context` is compact by design and reports `effectiveHistoryFromMs`, so an agent can see the actual persisted coverage rather than assuming it received the entire requested window.

Evidence references are stable within a bundle:

- `process:<pid>:<startedAtMs>` identifies a process instance without PID-reuse ambiguity.
- `log:<channel>:<recordId>` identifies a representative Windows diagnostic record.
- `alert:<id>` identifies a persisted PC Pulse finding.

Every diagnosis and action must cite known references. The built-in runner rejects hallucinated references and context substitution before saving.

The service keeps only the 32 most recent issued context identities and reference sets in bounded memory; they expire after 24 hours and are cleared on service restart. If an import is rejected as unknown or expired, request a fresh bundle and re-run the analysis.

## Plan safety and agentic execution

Plans are structured for downstream review or controlled orchestration. Each action includes priority, category, target, rationale, risk, prerequisites, typed steps, evidence references, validation, and rollback. Each step declares whether it mutates the system or requires elevation.

These are hard invariants:

- `neverAutoTerminate`, `neverAutoApply`, and `confirmationRequiredForMutations` must all be true.
- A mutating step requires action-level confirmation and its own non-empty confirmation prompt.
- Direct process-kill commands are rejected. Containment must route through PC Pulse's typed-PID confirmation UI.
- Importing or viewing a plan never executes it.

A downstream execution agent should treat the plan as untrusted advice, present one action at a time, re-check its evidence against a fresh bundle, request confirmation for every mutation, capture pre-change state, run validation, and use the supplied rollback if validation fails. PC Pulse intentionally does not implement unattended plan execution.

## Diagnostic-log scope and privacy

The collector polls every 30 seconds and initially looks back 15 minutes. Subsequent polls overlap by two minutes and deduplicate records by channel, record ID, and timestamp. Each channel is capped at 128 examined records per poll; truncation is surfaced in collector health.

Collected fields are bounded to 20 values and 320 characters each. User-profile path segments become `%USERPROFILE%`; password, token, secret, credential, authorization, and cookie fields are redacted. Inline secret-style arguments are redacted. Security event logs, command lines, environment variables, file contents, browser data, and keystrokes are never collected.

SQLite fingerprints repeated records by provider, event ID, and related process. Categories cover hardware/WHEA, storage, graphics, application crashes and hangs, resource exhaustion, power, services, networking, agent runtime, and other. Retention follows the existing `retentionDays` setting.
