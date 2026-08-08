use chrono::{DateTime, Local};
use std::time::Duration;

pub fn bytes(value: u64) -> String {
    bytes_f64(value as f64)
}

pub fn bytes_f64(value: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut amount = value.max(0.0);
    let mut unit = 0;
    while amount >= 1024.0 && unit < UNITS.len() - 1 {
        amount /= 1024.0;
        unit += 1;
    }
    if unit == 0 || amount >= 100.0 {
        format!("{amount:.0} {}", UNITS[unit])
    } else if amount >= 10.0 {
        format!("{amount:.1} {}", UNITS[unit])
    } else {
        format!("{amount:.2} {}", UNITS[unit])
    }
}

pub fn rate(value: f64) -> String {
    format!("{}/s", bytes_f64(value))
}

pub fn age(started_at_ms: i64, now_ms: i64) -> String {
    if started_at_ms <= 0 || now_ms <= started_at_ms {
        return "--".into();
    }
    duration(Duration::from_millis((now_ms - started_at_ms) as u64))
}

pub fn duration(value: Duration) -> String {
    let seconds = value.as_secs();
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {}s", seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

pub fn timestamp(epoch_ms: i64) -> String {
    DateTime::from_timestamp_millis(epoch_ms)
        .map(|utc| {
            utc.with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".into())
}

pub fn truncate(value: &str, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value.to_string();
    }
    let mut result: String = value.chars().take(maximum.saturating_sub(1)).collect();
    result.push('…');
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes_and_durations() {
        assert_eq!(bytes(1024), "1.00 KB");
        assert_eq!(rate(1024.0 * 1024.0), "1.00 MB/s");
        assert_eq!(duration(Duration::from_secs(3_661)), "1h 1m");
    }

    #[test]
    fn truncation_is_unicode_safe() {
        assert_eq!(truncate("agentic", 5), "agen…");
        assert_eq!(truncate("ééé", 3), "ééé");
    }
}
