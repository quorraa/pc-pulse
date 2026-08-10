use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    pub sample_interval_ms: u64,
    pub retention_days: u32,
    pub sustained_samples: u32,
    pub baseline_sigma: f64,
    pub cpu_percent: f64,
    pub memory_growth_mb: f64,
    pub handle_growth: u32,
    pub thread_growth: u32,
    pub disk_latency_ms: f64,
    pub io_mb_per_sec: f64,
    pub kernel_pool_growth_mb: f64,
    pub dpc_rate: f64,
    pub interrupt_rate: f64,
    pub unresponsive_seconds: u32,
    pub slow_launch_ms: u64,
    pub abandoned_agent_minutes: u32,
    pub notifications_enabled: bool,
    /// Absolute CPU budget for the collector's own self-monitoring, as a
    /// normalized percentage. Serde-defaulted so pre-1.15 settings files
    /// load unchanged.
    #[serde(default = "default_collector_cpu_percent")]
    pub collector_cpu_percent: f64,
    pub agent_process_patterns: Vec<String>,
}

fn default_collector_cpu_percent() -> f64 {
    0.2
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            sample_interval_ms: 2_000,
            retention_days: 14,
            sustained_samples: 5,
            baseline_sigma: 3.0,
            cpu_percent: 80.0,
            memory_growth_mb: 256.0,
            handle_growth: 500,
            thread_growth: 50,
            disk_latency_ms: 30.0,
            io_mb_per_sec: 100.0,
            kernel_pool_growth_mb: 128.0,
            dpc_rate: 1_000.0,
            interrupt_rate: 20_000.0,
            unresponsive_seconds: 10,
            slow_launch_ms: 8_000,
            abandoned_agent_minutes: 30,
            notifications_enabled: true,
            collector_cpu_percent: default_collector_cpu_percent(),
            agent_process_patterns: vec![
                "codex".into(),
                "claude".into(),
                "agent".into(),
                "mcp".into(),
            ],
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        if !(1_000..=60_000).contains(&self.sample_interval_ms) {
            bail!("sampleIntervalMs must be between 1000 and 60000");
        }
        if !(1..=365).contains(&self.retention_days) {
            bail!("retentionDays must be between 1 and 365");
        }
        if !(2..=120).contains(&self.sustained_samples) {
            bail!("sustainedSamples must be between 2 and 120");
        }
        if !(1.0..=10.0).contains(&self.baseline_sigma) {
            bail!("baselineSigma must be between 1 and 10");
        }
        if !(1.0..=100.0).contains(&self.cpu_percent) {
            bail!("cpuPercent must be between 1 and 100");
        }
        if !(0.05..=10.0).contains(&self.collector_cpu_percent) {
            bail!("collectorCpuPercent must be between 0.05 and 10");
        }
        if self.agent_process_patterns.len() > 32
            || self.agent_process_patterns.iter().any(|x| x.len() > 64)
        {
            bail!("agentProcessPatterns contains too many or overly long entries");
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let json = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let settings: Self = serde_json::from_str(&json)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, serde_json::to_vec_pretty(self)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Settings::default().validate().unwrap();
    }

    #[test]
    fn rejects_spike_prone_sampling() {
        let settings = Settings {
            sample_interval_ms: 250,
            ..Settings::default()
        };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn settings_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        let settings = Settings::default();
        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path).unwrap(), settings);
    }
}
