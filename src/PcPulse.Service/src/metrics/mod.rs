pub mod forensics;
mod hardware;
pub mod interrupts;
pub mod live;
mod pdh;
mod win32;

use crate::{
    config::Settings,
    etw::EtwSnapshot,
    models::{HardwareMetrics, ProcessMetric, SystemMetric},
};
use anyhow::Result;
use std::time::Instant;

pub struct MetricCollector {
    pdh: pdh::PdhCollector,
    processes: win32::ProcessCollector,
    hardware: hardware::HardwareSampler,
    last_sample: Instant,
}

impl MetricCollector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            pdh: pdh::PdhCollector::new()?,
            processes: win32::ProcessCollector::default(),
            hardware: hardware::HardwareSampler::new(),
            last_sample: Instant::now(),
        })
    }

    pub fn collect(
        &mut self,
        timestamp_ms: i64,
        settings: &Settings,
        etw: &EtwSnapshot,
    ) -> Result<(SystemMetric, Vec<ProcessMetric>, HardwareMetrics)> {
        let now = Instant::now();
        let elapsed = now
            .duration_since(self.last_sample)
            .as_secs_f64()
            .max(0.001);
        self.last_sample = now;
        let pdh = self.pdh.sample();
        let mut processes = self
            .processes
            .collect(timestamp_ms, elapsed, settings, etw)?;
        processes.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent));
        let mut system = win32::system_metric(timestamp_ms)?;
        system.cpu_percent = pdh.cpu_percent;
        system.disk_latency_ms = pdh.disk_latency_ms;
        system.dpc_rate = pdh.dpc_rate;
        system.interrupt_rate = pdh.interrupt_rate;
        system.network_bytes_per_sec = pdh.network_bytes_per_sec;
        system.disk_read_bytes_per_sec = processes.iter().map(|p| p.read_bytes_per_sec).sum();
        system.disk_write_bytes_per_sec = processes.iter().map(|p| p.write_bytes_per_sec).sum();
        system.etw_events_per_sec = etw.events_per_sec;
        system.dropped_etw_events = etw.dropped_events;
        system.etw_active = etw.active;
        if let Some(collector) = processes
            .iter()
            .find(|process| process.pid == std::process::id())
        {
            system.collector_working_set_bytes = collector.working_set_bytes;
            system.collector_cpu_percent = collector.cpu_percent;
            system.collector_handle_count = collector.handle_count;
        }
        // Cached internally to one probe pass per five seconds; the PDH
        // frequency reading rides along for free on every pass.
        let hardware = self.hardware.sample(timestamp_ms, pdh.cpu_frequency_mhz);
        Ok((system, processes, hardware))
    }
}

pub fn terminate_process(pid: u32, confirmed: bool) -> Result<()> {
    win32::terminate_process(pid, confirmed)
}
