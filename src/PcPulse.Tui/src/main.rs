use anyhow::{Result, bail};
use pcpulse_tui::{
    analyzer,
    app::{App, InputMode},
    client::PipeClient,
    effects::MotionSystem,
    ui,
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
    time::Instant,
};

fn main() {
    if let Err(error) = entry() {
        eprintln!("PC Pulse: {error:#}");
        std::process::exit(1);
    }
}

fn entry() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        None => run_tui(true),
        Some("--no-effects" | "--reduced-motion") if arguments.len() == 1 => run_tui(false),
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
            "usage: PcPulse.exe [snapshot | alerts | logs [hours] | agent-context [hours] | analyze [hours] | plan | plans | import-plan <file> | validate-plan <file> | plan-schema | agent-prompt | settings | ping | --no-effects | --version]"
        ),
    }
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

fn run_tui(effects_enabled: bool) -> Result<()> {
    let mut terminal = ratatui::try_init()?;
    if let Err(error) = execute!(std::io::stdout(), EnableMouseCapture) {
        let _ = ratatui::try_restore();
        return Err(error.into());
    }
    let result = terminal
        .clear()
        .map_err(anyhow::Error::from)
        .and_then(|_| run_loop(&mut terminal, effects_enabled));
    let mouse_restore =
        execute!(std::io::stdout(), DisableMouseCapture).map_err(anyhow::Error::from);
    let restore = ratatui::try_restore().map_err(anyhow::Error::from);
    result.and(mouse_restore).and(restore)
}

fn run_loop(terminal: &mut ratatui::DefaultTerminal, effects_enabled: bool) -> Result<()> {
    let mut app = App::new();
    let mut motion = MotionSystem::new(&app, effects_enabled);
    let mut dirty = true;
    let mut last_frame = Instant::now();
    let mut terminal_area = Rect::default();
    loop {
        if app.drain_events() {
            motion.observe(&app);
            dirty = true;
        }
        if dirty || motion.is_animating() {
            let elapsed = last_frame.elapsed();
            terminal.draw(|frame| {
                terminal_area = frame.area();
                ui::draw(frame, &mut app);
                motion.render(frame, elapsed);
            })?;
            last_frame = Instant::now();
            dirty = motion.take_cleanup_frame();
        }
        if event::poll(motion.poll_interval())? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Release
                        && key.code == KeyCode::Char('m')
                        && matches!(app.mode, InputMode::Normal)
                    {
                        let enabled = motion.toggle();
                        app.status = format!(
                            "Motion effects {}",
                            if enabled { "enabled" } else { "disabled" }
                        );
                        app.status_is_error = false;
                        motion.observe(&app);
                        dirty = true;
                        continue;
                    }
                    if app.handle_key(key) {
                        break;
                    }
                    motion.observe(&app);
                    dirty = true;
                }
                Event::Resize(_, _) => dirty = true,
                Event::Mouse(mouse)
                    if ui::handle_mouse(&mut app, mouse, terminal_area) =>
                {
                    motion.observe(&app);
                    dirty = true;
                }
                _ => {}
            }
        }
    }
    Ok(())
}
