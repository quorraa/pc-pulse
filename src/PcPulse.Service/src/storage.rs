use crate::{
    config::Settings,
    models::{
        Alert, DiagnosticLog, Evidence, HistoryResponse, IncidentState, OptimizationPlan,
        ProcessMetric, Rating, SystemMetric,
    },
};
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use std::{path::Path, sync::Mutex};

pub struct Storage {
    connection: Mutex<Connection>,
}

/// Evidence label the startup force-resolve stamps on findings it closes.
const RESTART_RESOLUTION_LABEL: &str = "Resolved by";

impl Storage {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("failed to open history database {}", path.display()))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA temp_store=MEMORY;
             PRAGMA busy_timeout=3000;
             PRAGMA auto_vacuum=INCREMENTAL;
             CREATE TABLE IF NOT EXISTS system_samples (
               timestamp_ms INTEGER PRIMARY KEY,
               payload TEXT NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS process_samples (
               timestamp_ms INTEGER NOT NULL,
               pid INTEGER NOT NULL,
               started_at_ms INTEGER NOT NULL,
               payload TEXT NOT NULL,
               PRIMARY KEY (timestamp_ms, pid, started_at_ms)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS idx_process_identity
               ON process_samples(pid, started_at_ms, timestamp_ms);
             CREATE TABLE IF NOT EXISTS alerts (
               id TEXT PRIMARY KEY,
               first_seen_ms INTEGER NOT NULL,
               last_seen_ms INTEGER NOT NULL,
               resolved_at_ms INTEGER,
               payload TEXT NOT NULL
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS idx_alert_time ON alerts(first_seen_ms DESC);
             CREATE TABLE IF NOT EXISTS diagnostic_logs (
               timestamp_ms INTEGER NOT NULL,
               channel TEXT NOT NULL,
               record_id INTEGER NOT NULL,
               fingerprint TEXT NOT NULL,
               payload TEXT NOT NULL,
               PRIMARY KEY (channel, record_id, timestamp_ms)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS idx_diagnostic_time
               ON diagnostic_logs(timestamp_ms DESC);
             CREATE INDEX IF NOT EXISTS idx_diagnostic_fingerprint
               ON diagnostic_logs(fingerprint, timestamp_ms DESC);
             CREATE TABLE IF NOT EXISTS optimization_plans (
               plan_id TEXT PRIMARY KEY,
               generated_at_ms INTEGER NOT NULL,
               context_id TEXT NOT NULL,
               payload TEXT NOT NULL
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS idx_optimization_plan_time
               ON optimization_plans(generated_at_ms DESC);
             CREATE TABLE IF NOT EXISTS baselines (
               scope TEXT PRIMARY KEY,
               payload TEXT NOT NULL,
               updated_ms INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS ratings (
               id TEXT PRIMARY KEY,
               at_ms INTEGER NOT NULL,
               payload TEXT NOT NULL
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS idx_rating_time ON ratings(at_ms DESC);",
        )?;
        // Databases created before the archive feature lack the column; the
        // flag itself also rides in the alert payload (like `acknowledged`),
        // so the column and JSON stay in step.
        add_column_if_missing(
            &connection,
            "ALTER TABLE alerts ADD COLUMN archived INTEGER NOT NULL DEFAULT 0",
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn insert_system(&self, metric: &SystemMetric) -> Result<()> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        connection.execute(
            "INSERT OR REPLACE INTO system_samples(timestamp_ms, payload) VALUES (?1, ?2)",
            params![metric.timestamp_ms, serde_json::to_string(metric)?],
        )?;
        Ok(())
    }

    /// Upsert learned-baseline rows (`(scope, JSON payload)`, from
    /// `baselines::BaselineStore::to_rows`) at the given persist timestamp.
    /// Called on the baseline persist cadence and on clean shutdown.
    pub fn save_baselines(&self, rows: &[(String, String)], now_ms: i64) -> Result<()> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        for (scope, payload) in rows {
            connection.execute(
                "INSERT INTO baselines(scope, payload, updated_ms) VALUES (?1, ?2, ?3)
                 ON CONFLICT(scope) DO UPDATE SET payload = excluded.payload, updated_ms = excluded.updated_ms",
                params![scope, payload, now_ms],
            )?;
        }
        Ok(())
    }

    /// Load every persisted baseline row, for
    /// `baselines::BaselineStore::from_rows` to reconstruct from at start.
    pub fn load_baselines(&self) -> Result<Vec<(String, String)>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut statement = connection.prepare_cached("SELECT scope, payload FROM baselines")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn insert_processes(&self, processes: &[ProcessMetric], maximum: usize) -> Result<()> {
        let mut ranked: Vec<&ProcessMetric> = processes.iter().collect();
        ranked.sort_by(|a, b| {
            let score_a = a.cpu_percent * 10.0
                + (a.read_bytes_per_sec + a.write_bytes_per_sec) / (1024.0 * 1024.0)
                + a.working_set_bytes as f64 / (128.0 * 1024.0 * 1024.0);
            let score_b = b.cpu_percent * 10.0
                + (b.read_bytes_per_sec + b.write_bytes_per_sec) / (1024.0 * 1024.0)
                + b.working_set_bytes as f64 / (128.0 * 1024.0 * 1024.0);
            score_b.total_cmp(&score_a)
        });
        ranked.truncate(maximum);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let transaction = connection.transaction()?;
        {
            let mut statement = transaction.prepare_cached(
                "INSERT OR REPLACE INTO process_samples(timestamp_ms, pid, started_at_ms, payload)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            for process in ranked {
                statement.execute(params![
                    process.timestamp_ms,
                    process.pid,
                    process.started_at_ms,
                    serde_json::to_string(process)?
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn upsert_alerts(&self, alerts: &[Alert]) -> Result<()> {
        if alerts.is_empty() {
            return Ok(());
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let transaction = connection.transaction()?;
        {
            let mut statement = transaction.prepare_cached(
                "INSERT INTO alerts(id, first_seen_ms, last_seen_ms, resolved_at_ms, archived, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET last_seen_ms=excluded.last_seen_ms,
                   resolved_at_ms=excluded.resolved_at_ms, archived=excluded.archived,
                   payload=excluded.payload",
            )?;
            for alert in alerts {
                statement.execute(params![
                    alert.id,
                    alert.first_seen_ms,
                    alert.last_seen_ms,
                    alert.resolved_at_ms,
                    alert.archived,
                    serde_json::to_string(alert)?
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn resolve_open_alerts(&self, resolved_at_ms: i64) -> Result<usize> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut open = query_json_rows::<Alert>(
            &connection,
            "SELECT payload FROM alerts WHERE resolved_at_ms IS NULL",
            [],
        )?;
        if open.is_empty() {
            return Ok(0);
        }
        for alert in &mut open {
            alert.resolved_at_ms = Some(resolved_at_ms);
            alert.state = IncidentState::Resolved;
            // A restart closes findings for lack of continuity, not because
            // the condition went away; the note says so, and the fingerprint
            // keeps the incident reopen-eligible.
            if !alert
                .evidence
                .iter()
                .any(|row| row.label == RESTART_RESOLUTION_LABEL)
            {
                alert.evidence.push(Evidence {
                    label: RESTART_RESOLUTION_LABEL.into(),
                    value: "Service restart".into(),
                });
            }
        }
        let transaction = connection.transaction()?;
        {
            let mut statement = transaction
                .prepare_cached("UPDATE alerts SET resolved_at_ms=?2, payload=?3 WHERE id=?1")?;
            for alert in &open {
                statement.execute(params![
                    alert.id,
                    resolved_at_ms,
                    serde_json::to_string(alert)?
                ])?;
            }
        }
        transaction.commit()?;
        Ok(open.len())
    }

    /// Alerts resolved at or after `since_ms` that carry an incident
    /// fingerprint, newest resolution first. Seeds `AlertEngine::new`'s
    /// reopen memory at startup so a condition that outlived a service
    /// restart reattaches to its incident instead of minting a sibling.
    /// Records without a fingerprint predate incident tracking and cannot be
    /// reattached to anything, so they are left out.
    pub fn recent_resolved_alerts(&self, since_ms: i64) -> Result<Vec<Alert>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let alerts = query_json_rows::<Alert>(
            &connection,
            "SELECT payload FROM alerts WHERE resolved_at_ms IS NOT NULL AND resolved_at_ms>=?1
             ORDER BY resolved_at_ms DESC LIMIT 5000",
            params![since_ms],
        )?;
        Ok(alerts
            .into_iter()
            .filter(|alert| !alert.fingerprint.is_empty())
            .collect())
    }

    pub fn acknowledge_alert(&self, id: &str) -> Result<bool> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let payload: Option<String> = connection
            .query_row("SELECT payload FROM alerts WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .optional()?;
        let Some(payload) = payload else {
            return Ok(false);
        };
        let mut alert: Alert = serde_json::from_str(&payload)?;
        alert.acknowledged = true;
        connection.execute(
            "UPDATE alerts SET payload=?2 WHERE id=?1",
            params![id, serde_json::to_string(&alert)?],
        )?;
        Ok(true)
    }

    /// Set or clear an alert's presentation-only archive flag. Mirrors
    /// [`Self::acknowledge_alert`]: the flag lives in the JSON payload, and
    /// the `archived` column is kept in step for the same row.
    pub fn archive_alert(&self, id: &str, archived: bool) -> Result<bool> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let payload: Option<String> = connection
            .query_row("SELECT payload FROM alerts WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .optional()?;
        let Some(payload) = payload else {
            return Ok(false);
        };
        let mut alert: Alert = serde_json::from_str(&payload)?;
        alert.archived = archived;
        connection.execute(
            "UPDATE alerts SET archived=?2, payload=?3 WHERE id=?1",
            params![id, archived, serde_json::to_string(&alert)?],
        )?;
        Ok(true)
    }

    pub fn history(&self, from_ms: i64, to_ms: i64, limit: u32) -> Result<HistoryResponse> {
        let limit = i64::from(limit.clamp(1, 10_000));
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let system = query_json_rows::<SystemMetric>(
            &connection,
            "SELECT payload FROM system_samples WHERE timestamp_ms BETWEEN ?1 AND ?2 ORDER BY timestamp_ms LIMIT ?3",
            params![from_ms, to_ms, limit],
        )?;
        let processes = query_json_rows::<ProcessMetric>(
            &connection,
            "SELECT payload FROM process_samples WHERE timestamp_ms BETWEEN ?1 AND ?2 ORDER BY timestamp_ms LIMIT ?3",
            params![from_ms, to_ms, limit],
        )?;
        Ok(HistoryResponse { system, processes })
    }

    pub fn system_history_downsampled(
        &self,
        from_ms: i64,
        to_ms: i64,
        limit: u32,
    ) -> Result<Vec<SystemMetric>> {
        let limit = i64::from(limit.clamp(1, 800));
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        query_json_rows::<SystemMetric>(
            &connection,
            "WITH ranked AS (
               SELECT timestamp_ms, payload,
                 ROW_NUMBER() OVER (ORDER BY timestamp_ms) AS row_number,
                 COUNT(*) OVER () AS total_count
               FROM system_samples
               WHERE timestamp_ms BETWEEN ?1 AND ?2
             )
             SELECT payload FROM ranked
             WHERE (row_number - 1) % MAX(1, (total_count + ?3 - 1) / ?3) = 0
             ORDER BY timestamp_ms
             LIMIT ?3",
            params![from_ms, to_ms, limit],
        )
    }

    pub fn alerts(&self, from_ms: i64, limit: u32) -> Result<Vec<Alert>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        query_json_rows::<Alert>(
            &connection,
            "SELECT payload FROM alerts WHERE first_seen_ms>=?1 ORDER BY first_seen_ms DESC LIMIT ?2",
            params![from_ms, i64::from(limit.clamp(1, 5_000))],
        )
    }

    pub fn insert_diagnostic_logs(&self, logs: &[DiagnosticLog]) -> Result<usize> {
        if logs.is_empty() {
            return Ok(0);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let transaction = connection.transaction()?;
        let mut inserted = 0;
        {
            let mut statement = transaction.prepare_cached(
                "INSERT OR IGNORE INTO diagnostic_logs(
                   timestamp_ms, channel, record_id, fingerprint, payload
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for log in logs {
                let record_id = i64::try_from(log.record_id)
                    .context("Windows event record ID exceeds SQLite integer range")?;
                inserted += statement.execute(params![
                    log.timestamp_ms,
                    log.channel,
                    record_id,
                    log.fingerprint,
                    serde_json::to_string(log)?
                ])?;
            }
        }
        transaction.commit()?;
        Ok(inserted)
    }

    pub fn diagnostic_logs(&self, from_ms: i64, limit: u32) -> Result<Vec<DiagnosticLog>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        query_json_rows::<DiagnosticLog>(
            &connection,
            "SELECT payload FROM diagnostic_logs WHERE timestamp_ms>=?1
             ORDER BY timestamp_ms DESC LIMIT ?2",
            params![from_ms, i64::from(limit.clamp(1, 5_000))],
        )
    }

    pub fn save_optimization_plan(&self, plan: &OptimizationPlan) -> Result<()> {
        plan.validate().map_err(anyhow::Error::msg)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        connection.execute(
            "INSERT INTO optimization_plans(plan_id, generated_at_ms, context_id, payload)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(plan_id) DO UPDATE SET generated_at_ms=excluded.generated_at_ms,
               context_id=excluded.context_id, payload=excluded.payload",
            params![
                plan.plan_id,
                plan.generated_at_ms,
                plan.context_id,
                serde_json::to_string(plan)?
            ],
        )?;
        Ok(())
    }

    pub fn optimization_plans(&self, limit: u32) -> Result<Vec<OptimizationPlan>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        query_json_rows::<OptimizationPlan>(
            &connection,
            "SELECT payload FROM optimization_plans ORDER BY generated_at_ms DESC LIMIT ?1",
            [i64::from(limit.clamp(1, 100))],
        )
    }

    /// Persist a performance rating, then enforce the 1,000-row cap by
    /// evicting the oldest rows (by `at_ms`) beyond that count. Ratings are
    /// deliberately excluded from `prune()`'s retention window -- see there.
    pub fn save_rating(&self, rating: &Rating) -> Result<()> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        connection.execute(
            "INSERT INTO ratings(id, at_ms, payload) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET at_ms=excluded.at_ms, payload=excluded.payload",
            params![rating.id, rating.at_ms, serde_json::to_string(rating)?],
        )?;
        connection.execute(
            "DELETE FROM ratings WHERE id NOT IN (
               SELECT id FROM ratings ORDER BY at_ms DESC LIMIT 1000
             )",
            [],
        )?;
        Ok(())
    }

    /// Most recent ratings, newest first. Corrupt payload rows (e.g. from a
    /// future schema this build doesn't understand) are skipped rather than
    /// failing the whole query, mirroring `BaselineStore::from_rows`.
    pub fn ratings(&self, limit: usize) -> Result<Vec<Rating>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut statement = connection
            .prepare_cached("SELECT payload FROM ratings ORDER BY at_ms DESC LIMIT ?1")?;
        let rows = statement.query_map(params![limit.min(10_000) as i64], |row| {
            row.get::<_, String>(0)
        })?;
        let mut result = Vec::new();
        for payload in rows {
            if let Ok(rating) = serde_json::from_str::<Rating>(&payload?) {
                result.push(rating);
            }
        }
        Ok(result)
    }

    pub fn recent_history(
        &self,
        from_ms: i64,
        to_ms: i64,
        system_limit: u32,
        process_limit: u32,
    ) -> Result<HistoryResponse> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut system = query_json_rows::<SystemMetric>(
            &connection,
            "SELECT payload FROM system_samples WHERE timestamp_ms BETWEEN ?1 AND ?2
             ORDER BY timestamp_ms DESC LIMIT ?3",
            params![from_ms, to_ms, i64::from(system_limit.clamp(1, 10_000))],
        )?;
        let mut processes = query_json_rows::<ProcessMetric>(
            &connection,
            "SELECT payload FROM process_samples WHERE timestamp_ms BETWEEN ?1 AND ?2
             ORDER BY timestamp_ms DESC LIMIT ?3",
            params![from_ms, to_ms, i64::from(process_limit.clamp(1, 20_000))],
        )?;
        system.reverse();
        processes.reverse();
        Ok(HistoryResponse { system, processes })
    }

    pub fn prune(&self, settings: &Settings, now_ms: i64) -> Result<()> {
        let cutoff = now_ms - i64::from(settings.retention_days) * 86_400_000;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        connection.execute(
            "DELETE FROM system_samples WHERE timestamp_ms < ?1",
            [cutoff],
        )?;
        connection.execute(
            "DELETE FROM process_samples WHERE timestamp_ms < ?1",
            [cutoff],
        )?;
        connection.execute("DELETE FROM alerts WHERE last_seen_ms < ?1", [cutoff])?;
        connection.execute(
            "DELETE FROM diagnostic_logs WHERE timestamp_ms < ?1",
            [cutoff],
        )?;
        connection.execute(
            "DELETE FROM optimization_plans WHERE generated_at_ms < ?1",
            [cutoff],
        )?;
        connection.execute_batch("PRAGMA incremental_vacuum(256);")?;
        Ok(())
    }
}

/// Run an `ALTER TABLE … ADD COLUMN` migration, tolerating a database that
/// already has the column (SQLite reports it as a duplicate-column error).
fn add_column_if_missing(connection: &Connection, sql: &str) -> Result<()> {
    match connection.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(error) if error.to_string().contains("duplicate column name") => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn query_json_rows<T: serde::de::DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    parameters: impl rusqlite::Params,
) -> Result<Vec<T>> {
    let mut statement = connection.prepare_cached(sql)?;
    let rows = statement.query_map(parameters, |row| row.get::<_, String>(0))?;
    let mut result = Vec::new();
    for payload in rows {
        result.push(serde_json::from_str(&payload?)?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DiagnosticCategory, DiagnosticField, DiagnosticLevel};

    #[test]
    fn persists_and_queries_system_history() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(&directory.path().join("history.db")).unwrap();
        let metric = SystemMetric {
            timestamp_ms: 123,
            cpu_percent: 42.0,
            ..SystemMetric::default()
        };
        storage.insert_system(&metric).unwrap();
        let history = storage.history(0, 1_000, 10).unwrap();
        assert_eq!(history.system, vec![metric]);
    }

    #[test]
    fn downsampled_system_history_is_bounded_across_the_window() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(&directory.path().join("history.db")).unwrap();
        for timestamp_ms in 1..=10 {
            storage
                .insert_system(&SystemMetric {
                    timestamp_ms,
                    cpu_percent: timestamp_ms as f64,
                    ..SystemMetric::default()
                })
                .unwrap();
        }
        let history = storage.system_history_downsampled(0, 20, 3).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].timestamp_ms, 1);
        assert_eq!(history[1].timestamp_ms, 5);
        assert_eq!(history[2].timestamp_ms, 9);
    }

    #[test]
    fn restart_resolution_updates_column_and_alert_payload() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(&directory.path().join("history.db")).unwrap();
        let alert = Alert {
            id: "open-alert".into(),
            kind: "collectorBudget".into(),
            severity: crate::models::Severity::Critical,
            first_seen_ms: 100,
            last_seen_ms: 200,
            process_id: Some(42),
            process_name: Some("PcPulse.Service.exe".into()),
            title: "Collector resource budget exceeded".into(),
            explanation: "test".into(),
            evidence: Vec::new(),
            recommendation: "test".into(),
            acknowledged: false,
            occurrence_count: 1,
            resolved_at_ms: None,
            archived: false,
            fingerprint: String::new(),
            state: crate::models::IncidentState::Open,
            quality: crate::models::AlertQuality::default(),
            notify: true,
            notify_generation: 0,
        };
        storage.upsert_alerts(&[alert]).unwrap();

        assert_eq!(storage.resolve_open_alerts(300).unwrap(), 1);
        let alerts = storage.alerts(0, 10).unwrap();
        assert_eq!(alerts[0].resolved_at_ms, Some(300));
        assert_eq!(storage.resolve_open_alerts(400).unwrap(), 0);
    }

    fn stored_alert(id: &str) -> Alert {
        Alert {
            id: id.into(),
            kind: "sustainedCpu".into(),
            severity: crate::models::Severity::Warning,
            first_seen_ms: 100,
            last_seen_ms: 200,
            process_id: Some(42),
            process_name: Some("worker.exe".into()),
            title: "Sustained CPU usage".into(),
            explanation: "test".into(),
            evidence: Vec::new(),
            recommendation: "test".into(),
            acknowledged: false,
            occurrence_count: 1,
            resolved_at_ms: None,
            archived: false,
            fingerprint: String::new(),
            state: crate::models::IncidentState::Open,
            quality: crate::models::AlertQuality::default(),
            notify: true,
            notify_generation: 0,
        }
    }

    #[test]
    fn restart_resolution_leaves_fingerprints_reopen_eligible() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(&directory.path().join("history.db")).unwrap();
        let mut fingerprinted = stored_alert("finding-1");
        fingerprinted.fingerprint = "sustainedCpu:42:1".into();
        storage
            .upsert_alerts(&[fingerprinted, stored_alert("legacy-finding")])
            .unwrap();

        assert_eq!(storage.resolve_open_alerts(1_000).unwrap(), 2);
        let recent = storage.recent_resolved_alerts(0).unwrap();
        assert_eq!(
            recent.len(),
            1,
            "records without a fingerprint cannot reattach to anything"
        );
        assert_eq!(recent[0].id, "finding-1");
        assert_eq!(recent[0].state, crate::models::IncidentState::Resolved);
        assert!(
            recent[0]
                .evidence
                .iter()
                .any(|row| row.value == "Service restart"),
            "the force-resolve records why it closed"
        );
        assert!(
            storage.recent_resolved_alerts(2_000).unwrap().is_empty(),
            "resolutions older than the window are not reopen-eligible"
        );
    }

    #[test]
    fn archive_flag_round_trips_and_recovers() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(&directory.path().join("history.db")).unwrap();
        storage.upsert_alerts(&[stored_alert("finding-1")]).unwrap();

        assert!(!storage.archive_alert("unknown", true).unwrap());
        assert!(storage.archive_alert("finding-1", true).unwrap());
        let alerts = storage.alerts(0, 10).unwrap();
        assert!(alerts[0].archived, "payload must carry the flag");

        // Recovery is the same command with archived=false.
        assert!(storage.archive_alert("finding-1", false).unwrap());
        assert!(!storage.alerts(0, 10).unwrap()[0].archived);
    }

    #[test]
    fn archive_flag_survives_resolution_and_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.db");
        {
            let storage = Storage::open(&path).unwrap();
            storage.upsert_alerts(&[stored_alert("finding-1")]).unwrap();
            assert!(storage.archive_alert("finding-1", true).unwrap());
            assert_eq!(storage.resolve_open_alerts(300).unwrap(), 1);
        }
        // Reopening runs the tolerant migration against a database that
        // already has the column, and the persisted flag is intact.
        let storage = Storage::open(&path).unwrap();
        let alerts = storage.alerts(0, 10).unwrap();
        assert!(alerts[0].archived);
        assert_eq!(alerts[0].resolved_at_ms, Some(300));
    }

    #[test]
    fn pre_archive_alert_payload_reads_as_unarchived() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(&directory.path().join("history.db")).unwrap();
        // Simulate a row persisted by a pre-archive service: no `archived`
        // key in the JSON payload.
        let mut payload = serde_json::to_value(stored_alert("old-alert")).unwrap();
        payload.as_object_mut().unwrap().remove("archived");
        {
            let connection = storage.connection.lock().unwrap();
            connection
                .execute(
                    "INSERT INTO alerts(id, first_seen_ms, last_seen_ms, resolved_at_ms, payload)
                     VALUES ('old-alert', 100, 200, NULL, ?1)",
                    [serde_json::to_string(&payload).unwrap()],
                )
                .unwrap();
        }
        let alerts = storage.alerts(0, 10).unwrap();
        assert_eq!(alerts.len(), 1);
        assert!(!alerts[0].archived);
        // And the old row can still be archived in place.
        assert!(storage.archive_alert("old-alert", true).unwrap());
        assert!(storage.alerts(0, 10).unwrap()[0].archived);
    }

    #[test]
    fn diagnostic_log_identity_is_deduplicated_and_query_is_recent_first() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(&directory.path().join("history.db")).unwrap();
        let mut first = DiagnosticLog {
            timestamp_ms: 100,
            channel: "System".into(),
            provider: "disk".into(),
            event_id: 153,
            record_id: 42,
            level: DiagnosticLevel::Warning,
            category: DiagnosticCategory::Storage,
            process_id: None,
            thread_id: None,
            related_process: None,
            fingerprint: "disk:153:system".into(),
            fields: vec![DiagnosticField {
                name: "Device".into(),
                value: r"\Device\Harddisk0".into(),
            }],
        };
        assert_eq!(storage.insert_diagnostic_logs(&[first.clone()]).unwrap(), 1);
        assert_eq!(storage.insert_diagnostic_logs(&[first.clone()]).unwrap(), 0);
        first.timestamp_ms = 200;
        first.record_id = 43;
        assert_eq!(storage.insert_diagnostic_logs(&[first]).unwrap(), 1);
        let logs = storage.diagnostic_logs(0, 10).unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].timestamp_ms, 200);
    }

    fn sample_rating(id: &str, at_ms: i64) -> crate::models::Rating {
        crate::models::Rating {
            id: id.into(),
            at_ms,
            verdict: crate::models::RatingVerdict::Good,
            demand: crate::models::DemandBucket::Heavy,
            demand_detail: crate::models::DemandDetail {
                cpu_percent: 12.5,
                cpu_percentile: Some(0.4),
                memory_occupancy_pct: 33.0,
                memory_percentile: None,
                disk_latency_ms: 2.0,
                disk_percentile: Some(0.9),
                io_bytes_per_sec: 1024.0,
                io_percentile: None,
            },
            digest: serde_json::json!({"summary": "steady"}),
            open_incidents: vec![crate::models::OpenIncidentRef {
                fingerprint: "sustainedCpu:1:1".into(),
                kind: "sustainedCpu".into(),
                severity: crate::models::Severity::Warning,
                notify: true,
                acknowledged: false,
            }],
            during_learning: false,
            unexplained: false,
        }
    }

    #[test]
    fn rating_round_trips_with_pinned_serde_spellings() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(&directory.path().join("history.db")).unwrap();
        let rating = sample_rating("rating-1", 1_000);
        storage.save_rating(&rating).unwrap();

        let loaded = storage.ratings(10).unwrap();
        assert_eq!(loaded, vec![rating.clone()]);

        let payload = serde_json::to_value(&rating).unwrap();
        assert_eq!(payload["verdict"], "good");
        assert_eq!(payload["demand"], "heavy");
    }

    #[test]
    fn ratings_are_returned_newest_first() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(&directory.path().join("history.db")).unwrap();
        storage.save_rating(&sample_rating("a", 100)).unwrap();
        storage.save_rating(&sample_rating("b", 300)).unwrap();
        storage.save_rating(&sample_rating("c", 200)).unwrap();

        let loaded = storage.ratings(10).unwrap();
        let ids: Vec<&str> = loaded.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["b", "c", "a"]);
    }

    #[test]
    fn rating_count_is_capped_at_one_thousand_evicting_oldest() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(&directory.path().join("history.db")).unwrap();
        for at_ms in 0..1_005 {
            storage
                .save_rating(&sample_rating(&format!("r{at_ms}"), at_ms))
                .unwrap();
        }
        let loaded = storage.ratings(2_000).unwrap();
        assert_eq!(loaded.len(), 1_000);
        // The five oldest (at_ms 0..=4) were evicted; the oldest surviving
        // row is at_ms == 5.
        let oldest_surviving = loaded.iter().map(|r| r.at_ms).min().unwrap();
        assert_eq!(oldest_surviving, 5);
    }

    #[test]
    fn ratings_survive_retention_prune() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(&directory.path().join("history.db")).unwrap();
        let now_ms = 1_000_000_000_000_i64;
        let old_at_ms = now_ms - 400 * 86_400_000;
        storage
            .save_rating(&sample_rating("ancient", old_at_ms))
            .unwrap();

        storage.prune(&Settings::default(), now_ms).unwrap();

        let loaded = storage.ratings(10).unwrap();
        assert_eq!(
            loaded.len(),
            1,
            "ratings are excluded from the retention prune job"
        );
        assert_eq!(loaded[0].id, "ancient");
    }

    #[test]
    fn corrupt_rating_payload_is_skipped_without_panic() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(&directory.path().join("history.db")).unwrap();
        storage.save_rating(&sample_rating("good", 500)).unwrap();
        {
            let connection = storage.connection.lock().unwrap();
            connection
                .execute(
                    "INSERT INTO ratings(id, at_ms, payload) VALUES ('bad', 600, 'not json')",
                    [],
                )
                .unwrap();
        }

        let loaded = storage.ratings(10).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "good");
    }
}
