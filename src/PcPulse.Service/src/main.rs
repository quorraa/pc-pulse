use anyhow::{Result, bail};
use pcpulse_service::{runtime, service};
use std::path::PathBuf;

fn main() {
    if let Err(error) = entry() {
        eprintln!("PC Pulse: {error:#}");
        std::process::exit(1);
    }
}

fn entry() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.is_empty() {
        return service::dispatch();
    }
    if arguments[0] == "--console" {
        let data_dir = argument_value(&arguments, "--data-dir")
            .map(PathBuf::from)
            .unwrap_or_else(runtime::default_data_dir);
        let (stop_tx, stop_rx) = crossbeam_channel::bounded(1);
        ctrlc::set_handler(move || {
            let _ = stop_tx.try_send(());
        })?;
        println!("PC Pulse collector running. Press Ctrl+C to stop.");
        return runtime::run(&data_dir, stop_rx);
    }
    if arguments[0] == "--version" {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    bail!("usage: PcPulse.Service.exe [--console [--data-dir PATH] | --version]")
}

fn argument_value<'a>(arguments: &'a [String], key: &str) -> Option<&'a str> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == key)
        .map(|pair| pair[1].as_str())
}
