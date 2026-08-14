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
    /// Opt-in capture of process command lines for launch history. Default
    /// **false**, and a settings file written before 1.20 has no such field,
    /// so it migrates to false: opting in is always an explicit act. While
    /// this is off no command-line data enters the process in any form --
    /// the MOF session that carries it is not even started.
    #[serde(default)]
    pub capture_command_lines: bool,
    /// How long captured (redacted, DPAPI-encrypted) command lines are kept,
    /// on their own clock independent of the 7-day launch-event window.
    /// Serde-defaulted so pre-1.20 settings files load unchanged.
    #[serde(default = "default_command_line_retention_hours")]
    pub command_line_retention_hours: u32,
}

fn default_collector_cpu_percent() -> f64 {
    0.2
}

fn default_command_line_retention_hours() -> u32 {
    24
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
            capture_command_lines: false,
            command_line_retention_hours: default_command_line_retention_hours(),
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
        if !(1..=168).contains(&self.command_line_retention_hours) {
            bail!("commandLineRetentionHours must be between 1 and 168");
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
    fn pre_1_20_settings_file_migrates_to_capture_off() {
        // A settings file written before launch history has neither field.
        // Opting in must never happen by migration: absent means off, and
        // the retention clock falls back to its 24h default.
        let json = r#"{
            "sampleIntervalMs": 2000,
            "retentionDays": 14,
            "sustainedSamples": 5,
            "baselineSigma": 3.0,
            "cpuPercent": 80.0,
            "memoryGrowthMb": 256.0,
            "handleGrowth": 500,
            "threadGrowth": 50,
            "diskLatencyMs": 30.0,
            "ioMbPerSec": 100.0,
            "kernelPoolGrowthMb": 128.0,
            "dpcRate": 1000.0,
            "interruptRate": 20000.0,
            "unresponsiveSeconds": 10,
            "slowLaunchMs": 8000,
            "abandonedAgentMinutes": 30,
            "notificationsEnabled": true,
            "agentProcessPatterns": ["codex"]
        }"#;
        let settings: Settings = serde_json::from_str(json).unwrap();
        assert!(!settings.capture_command_lines);
        assert_eq!(settings.command_line_retention_hours, 24);
        settings.validate().unwrap();
    }

    #[test]
    fn command_line_retention_hours_range_is_enforced() {
        let with = |hours: u32| Settings {
            command_line_retention_hours: hours,
            ..Settings::default()
        };
        assert!(with(0).validate().is_err());
        assert!(with(169).validate().is_err());
        assert!(with(1).validate().is_ok());
        assert!(with(168).validate().is_ok());
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
