use anyhow::{Result, bail};
use pcpulse_tui::{
    analyzer,
    app::{App, InputMode},
    bootstrap,
    client::PipeClient,
    effects::MotionSystem,
    prefs, theme, ui,
};
use ratatui::{
    crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
        execute,
    },
    layout::Rect,
};
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

fn main() {
    if let Err(error) = entry() {
        eprintln!("PC Pulse: {error:#}");
        std::process::exit(1);
    }
}

fn entry() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    // A leading TUI flag (or no arguments at all) means an interactive run;
    // parse_tui_flags then rejects anything it does not recognize.
    if arguments
        .first()
        .is_none_or(|argument| is_tui_flag(argument))
    {
        let options = parse_tui_flags(&arguments)?;
        return run_tui(options);
    }
    match arguments.first().map(String::as_str) {
        Some("--version" | "version") => {
            println!("PC Pulse {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("snapshot") => print_json(PipeClient.snapshot()?),
        Some("alerts") => {
            let from = chrono::Utc::now().timestamp_millis() - 30 * 86_400_000;
            print_json(PipeClient.alerts(from, 300)?)
        }
        Some("logs") => {
            let hours = parse_hours(&arguments, 24)?;
            let from = chrono::Utc::now().timestamp_millis() - i64::from(hours) * 3_600_000;
            print_json(PipeClient.diagnostic_logs(from, 200)?)
        }
        Some("agent-context") => {
            let hours = parse_hours(&arguments, 1)?;
            print_json(PipeClient.agent_context(hours)?)
        }
        Some("plans") => print_json(PipeClient.optimization_plans(5)?),
        Some("plan") if arguments.len() == 1 => {
            let plan = PipeClient
                .optimization_plans(1)?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("no systems-analyzer plan has been saved"))?;
            print_json(plan)
        }
        Some("analyze") => {
            let hours = parse_hours(&arguments, 1)?;
            let cancelled = Arc::new(AtomicBool::new(false));
            let handler_flag = Arc::clone(&cancelled);
            ctrlc::set_handler(move || handler_flag.store(true, Ordering::Release))?;
            print_json(analyzer::generate_and_save(hours, cancelled)?)
        }
        Some("import-plan") if arguments.len() == 2 => {
            let payload = std::fs::read_to_string(&arguments[1])?;
            let plan: pcpulse_service::models::OptimizationPlan = serde_json::from_str(&payload)?;
            plan.validate().map_err(anyhow::Error::msg)?;
            print_json(PipeClient.save_optimization_plan(plan)?)
        }
        Some("validate-plan") if arguments.len() == 2 => {
            let payload = std::fs::read_to_string(&arguments[1])?;
            let plan: pcpulse_service::models::OptimizationPlan = serde_json::from_str(&payload)?;
            plan.validate().map_err(anyhow::Error::msg)?;
            print_json(serde_json::json!({
                "valid": true,
                "planId": plan.plan_id,
                "contextId": plan.context_id
            }))
        }
        Some("plan-schema") if arguments.len() == 1 => {
            let value: serde_json::Value = serde_json::from_str(analyzer::plan_schema())?;
            print_json(value)
        }
        Some("agent-prompt") if arguments.len() == 1 => print_text(analyzer::agent_prompt()),
        Some("settings") => print_json(PipeClient.settings()?),
        Some("ping") => print_json(PipeClient.ping()?),
        _ => bail!(
            "usage: PcPulse.exe [snapshot | alerts | logs [hours] | agent-context [hours] | analyze [hours] | plan | plans | import-plan <file> | validate-plan <file> | plan-schema | agent-prompt | settings | ping | --theme <vitals|avionics|ledger> | --no-effects | --version]"
        ),
    }
}

/// CLI flags override the stored per-user preferences for one run without
/// rewriting them, so both are optional here: `None` / `false` means "let
/// the preference decide".
#[derive(Debug, Clone, Copy)]
struct TuiOptions {
    effects_off: bool,
    theme: Option<theme::ThemeId>,
}

fn is_tui_flag(argument: &str) -> bool {
    matches!(argument, "--no-effects" | "--reduced-motion" | "--theme")
        || argument.starts_with("--theme=")
}

fn parse_tui_flags(arguments: &[String]) -> Result<TuiOptions> {
    let mut options = TuiOptions {
        effects_off: false,
        theme: None,
    };
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--no-effects" | "--reduced-motion" => options.effects_off = true,
            "--theme" => {
                index += 1;
                let name = arguments
                    .get(index)
                    .ok_or_else(|| anyhow::anyhow!("--theme requires a value{THEME_USAGE}"))?;
                options.theme = Some(parse_theme(name)?);
            }
            other => {
                if let Some(name) = other.strip_prefix("--theme=") {
                    options.theme = Some(parse_theme(name)?);
                } else {
                    bail!("unknown option \"{other}\"{THEME_USAGE}");
                }
            }
        }
        index += 1;
    }
    Ok(options)
}

const THEME_USAGE: &str = " (usage: PcPulse.exe [--theme vitals|avionics|ledger] [--no-effects])";

fn parse_theme(name: &str) -> Result<theme::ThemeId> {
    name.parse::<theme::ThemeId>()
        .map_err(|error| anyhow::anyhow!("{error}{THEME_USAGE}"))
}

fn parse_hours(arguments: &[String], default: u32) -> Result<u32> {
    if arguments.len() > 2 {
        bail!("expected at most one evidence-window argument in hours");
    }
    let hours = arguments
        .get(1)
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(default);
    if !(1..=24).contains(&hours) {
        bail!("evidence window must be between 1 and 24 hours");
    }
    Ok(hours)
}

fn print_json(value: impl serde::Serialize) -> Result<()> {
    let mut payload = serde_json::to_vec_pretty(&value)?;
    payload.push(b'\n');
    match std::io::stdout().write_all(&payload) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn print_text(value: &str) -> Result<()> {
    let mut stdout = std::io::stdout();
    match writeln!(stdout, "{value}") {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Opt the interactive UI back into color regardless of the inherited
/// environment. The tray helper launches this process via ShellExecuteW, so
/// the TUI inherits whatever environment the tray itself was started from —
/// including a NO_COLOR left behind by a script or automation shell (field
/// incident: a tray started from a test shell produced a monochrome TUI
/// until it was manually restarted). Crossterm honors NO_COLOR by stripping
/// every ANSI color sequence; the themes are the product, so the full-screen
/// run always forces color output. The JSON/CLI subcommands never emit color
/// and are unaffected.
fn force_tui_colors() {
    ratatui::crossterm::style::force_color_output(true);
}

fn run_tui(options: TuiOptions) -> Result<()> {
    // First thing, before any thread exists: load the per-user preferences
    // and feed the analyzer's existing env-var budget. An explicit
    // PCPULSE_ANALYZER_TIMEOUT_SECS in the environment always wins.
    let store = prefs::PrefsStore::discover();
    let saved = store
        .as_ref()
        .map(prefs::PrefsStore::load)
        .unwrap_or_default();
    if std::env::var_os("PCPULSE_ANALYZER_TIMEOUT_SECS").is_none() {
        // SAFETY: run_tui is called from `main` before `App::new` spawns the
        // worker/analyzer threads, so no other thread can be reading the
        // environment concurrently.
        unsafe {
            std::env::set_var(
                "PCPULSE_ANALYZER_TIMEOUT_SECS",
                saved.analyzer_timeout_secs.to_string(),
            );
        }
    }
    let effective = saved.overridden(options.theme, options.effects_off);
    theme::set_active(effective.theme);
    // Self-heal the companions before the terminal takes over and before
    // App::new spawns the worker: start a stopped collector service and
    // bring back a missing tray helper. Best-effort and bounded — every
    // failure degrades to the existing offline panel, and the pipe-retry
    // loop meets a freshly started service as it comes up.
    let healed = bootstrap::ensure_companions();
    force_tui_colors();
    let mut terminal = ratatui::try_init()?;
    if let Err(error) = execute!(std::io::stdout(), EnableMouseCapture) {
        let _ = ratatui::try_restore();
        return Err(error.into());
    }
    let result = terminal
        .clear()
        .map_err(anyhow::Error::from)
        .and_then(|_| run_loop(&mut terminal, effective, store, healed));
    let mouse_restore =
        execute!(std::io::stdout(), DisableMouseCapture).map_err(anyhow::Error::from);
    let restore = ratatui::try_restore().map_err(anyhow::Error::from);
    result.and(mouse_restore).and(restore)
}

fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    effective: prefs::UiPrefs,
    store: Option<prefs::PrefsStore>,
    healed: Option<String>,
) -> Result<()> {
    let mut app = App::new();
    let effects = effective.effects;
    app.adopt_client_prefs(effective, store);
    // Surface a launch-time heal once, before the first draw; the next
    // worker event replaces it like any other status line.
    if let Some(message) = healed {
        app.status = message;
        app.status_is_error = false;
    }
    let mut motion = MotionSystem::new(&app, effects);
    // MotionSystem does not expose its enabled state; mirror it so TUNE
    // toggles can be reconciled through `toggle()`.
    let mut motion_enabled = effects;
    let mut dirty = true;
    let mut last_frame = Instant::now();
    let mut terminal_area = Rect::default();
    // Smooth refresh: the next fixed-cadence frame deadline while the
    // per-user refresh rate is 30/60 fps; `None` in event-driven mode.
    let mut next_smooth_frame: Option<Instant> = None;
    loop {
        if app.drain_events() {
            motion.observe(&app);
            dirty = true;
        }
        let fps = app.effective_refresh_fps();
        if fps == 0 {
            next_smooth_frame = None;
        }
        let frame_budget = Duration::from_micros(1_000_000 / u64::from(fps.max(1)));
        let smooth_due =
            fps > 0 && next_smooth_frame.is_none_or(|deadline| Instant::now() >= deadline);
        if dirty || motion.is_animating() || smooth_due {
            let elapsed = last_frame.elapsed();
            let frame_started = Instant::now();
            app.set_render_now(frame_started);
            terminal.draw(|frame| {
                terminal_area = frame.area();
                ui::draw(frame, &mut app);
                motion.render(frame, elapsed);
            })?;
            last_frame = Instant::now();
            dirty = motion.take_cleanup_frame();
            if fps > 0 {
                // Guardrail: three consecutive budget overruns drop the
                // session a tier so the TUI never consumes a core silently.
                if app.note_smooth_frame(frame_started.elapsed(), frame_budget) {
                    dirty = true;
                    motion.observe(&app);
                }
                // Keep the cadence anchored to the previous deadline, but
                // never schedule into the past after a slow frame.
                let target = next_smooth_frame
                    .map_or_else(|| frame_started + frame_budget, |at| at + frame_budget);
                next_smooth_frame = Some(target.max(Instant::now()));
            }
        }
        // Event-driven mode polls on the motion system's cadence; smooth
        // mode caps the wait at the remaining frame budget (take the min).
        let poll_timeout = match next_smooth_frame {
            Some(deadline) if app.effective_refresh_fps() > 0 => motion
                .poll_interval()
                .min(deadline.saturating_duration_since(Instant::now())),
            _ => motion.poll_interval(),
        };
        if event::poll(poll_timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Release
                        && key.code == KeyCode::Char('m')
                        && matches!(app.mode, InputMode::Normal)
                        && app.help_overlay.is_none()
                        && app.vault_rename.is_none()
                    {
                        motion_enabled = motion.toggle();
                        app.status = format!(
                            "Motion effects {} · saved for your user",
                            if motion_enabled {
                                "enabled"
                            } else {
                                "disabled"
                            }
                        );
                        app.status_is_error = false;
                        app.client_prefs.effects = motion_enabled;
                        app.persist_client_prefs();
                        motion.observe(&app);
                        dirty = true;
                        continue;
                    }
                    if key.kind != KeyEventKind::Release
                        && key.code == KeyCode::Char('t')
                        && matches!(app.mode, InputMode::Normal)
                        && app.help_overlay.is_none()
                        && app.vault_rename.is_none()
                    {
                        let active = theme::cycle();
                        app.status = format!("Theme: {} · saved for your user", active.name);
                        app.status_is_error = false;
                        app.client_prefs.theme = active.id;
                        app.persist_client_prefs();
                        // The base draw repaints every cell, but clear the
                        // backend diff so no stale-bg cell survives the swap.
                        terminal.clear()?;
                        motion.observe(&app);
                        dirty = true;
                        continue;
                    }
                    if app.handle_key(key) {
                        break;
                    }
                    // A TUNE client-row edit may have cycled the theme or
                    // asked for a motion-effects state this loop owns.
                    if let Some(enabled) = app.take_effects_request()
                        && enabled != motion_enabled
                    {
                        motion_enabled = motion.toggle();
                    }
                    if app.take_terminal_clear() {
                        terminal.clear()?;
                    }
                    motion.observe(&app);
                    dirty = true;
                }
                Event::Resize(_, _) => dirty = true,
                Event::Mouse(mouse) if ui::handle_mouse(&mut app, mouse, terminal_area) => {
                    motion.observe(&app);
                    dirty = true;
                }
                _ => {}
            }
        } else if app.analyzer_running {
            // The worker stays silent for the whole Codex run, so while a
            // submission is in flight the finite poll timeout is the wakeup
            // that advances the "analyzing …" ticker. Idle behavior without
            // an active analysis is untouched.
            dirty = true;
        }
    }
    Ok(())
}

#[cfg(test)]
mod color_tests {
    use ratatui::crossterm::style::{Color, Colored};

    /// Reproduces the tray-launch incident end to end: NO_COLOR in the
    /// inherited environment makes crossterm strip color sequences, and
    /// force_tui_colors must win over it.
    #[test]
    fn interactive_run_forces_color_despite_inherited_no_color() {
        // SAFETY: this test target has a single test, so nothing else reads
        // the environment concurrently.
        unsafe { std::env::set_var("NO_COLOR", "1") };
        let stripped = format!("{}", Colored::ForegroundColor(Color::Green));
        assert!(
            stripped.is_empty(),
            "expected NO_COLOR to strip the sequence, got {stripped:?}"
        );
        super::force_tui_colors();
        let restored = format!("{}", Colored::ForegroundColor(Color::Green));
        assert!(
            !restored.is_empty(),
            "force_tui_colors must override an inherited NO_COLOR"
        );
    }
}
