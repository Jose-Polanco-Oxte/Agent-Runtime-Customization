use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObservabilityEvent {
    pub id: i64,
    pub timestamp_unix_ms: i64,
    pub event_type: String,
    pub level: String,
    pub provider: Option<String>,
    pub workspace_id: Option<String>,
    pub session_id: Option<String>,
    pub turn_id: Option<String>,
    pub execution_id: Option<String>,
    pub invocation_id: Option<String>,
    pub guard_id: Option<String>,
    pub process_id: u32,
    pub reason_code: Option<String>,
    pub duration_ms: Option<i64>,
    pub details: Value,
}

#[derive(Debug, Clone, Default)]
pub struct NewObservabilityEvent {
    pub event_type: String,
    pub level: String,
    pub provider: Option<String>,
    pub workspace_id: Option<String>,
    pub session_id: Option<String>,
    pub turn_id: Option<String>,
    pub execution_id: Option<String>,
    pub invocation_id: Option<String>,
    pub guard_id: Option<String>,
    pub reason_code: Option<String>,
    pub duration_ms: Option<i64>,
    pub details: Value,
}

#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub after_id: i64,
    pub workspace_id: Option<String>,
    pub session_id: Option<String>,
    pub execution_id: Option<String>,
    pub minimum_level: Option<String>,
    pub event_types: Vec<String>,
    pub limit: usize,
}

pub struct ObservabilityJournal {
    connection: Mutex<Connection>,
    retention_max_age: Option<std::time::Duration>,
    insert_count: std::sync::atomic::AtomicU64,
}

pub const DEFAULT_RETENTION_MAX_AGE: std::time::Duration =
    std::time::Duration::from_secs(30 * 24 * 60 * 60);

impl ObservabilityJournal {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_retention(path, Some(DEFAULT_RETENTION_MAX_AGE))
    }

    pub fn open_with_retention(
        path: &Path,
        retention_max_age: Option<std::time::Duration>,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating Arc runtime directory at {parent:?}"))?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("failed opening Arc runtime database at {path:?}"))?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection
            .create_scalar_function(
                "arc_event_type_key",
                1,
                FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
                |context| {
                    let value = context.get::<String>(0)?;
                    Ok(normalize_event_type(&value))
                },
            )
            .context("failed registering Arc event-type normalization")?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS observability_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp_unix_ms INTEGER NOT NULL,
                 event_type TEXT NOT NULL,
                 level TEXT NOT NULL,
                 provider TEXT,
                 workspace_id TEXT,
                 session_id TEXT,
                 turn_id TEXT,
                 execution_id TEXT,
                 invocation_id TEXT,
                 guard_id TEXT,
                 process_id INTEGER NOT NULL,
                 reason_code TEXT,
                 duration_ms INTEGER,
                 details_json TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS observability_events_workspace
                 ON observability_events(workspace_id, id);
             CREATE INDEX IF NOT EXISTS observability_events_session
                 ON observability_events(session_id, id);
             CREATE INDEX IF NOT EXISTS observability_events_execution
                 ON observability_events(execution_id, id);
             CREATE INDEX IF NOT EXISTS observability_events_timestamp
                 ON observability_events(timestamp_unix_ms);",
        )?;

        let journal = Self {
            connection: Mutex::new(connection),
            retention_max_age,
            insert_count: std::sync::atomic::AtomicU64::new(0),
        };

        if let Some(max_age) = retention_max_age {
            let _ = journal.purge_expired(max_age);
        }

        Ok(journal)
    }

    /// Purges observability events older than max_age without touching guards, workspaces, or trusted IRs (L3).
    pub fn purge_expired(&self, max_age: std::time::Duration) -> Result<usize> {
        let cutoff_unix_ms = now_unix_ms().saturating_sub(max_age.as_millis() as i64);
        let connection = self.connection.lock().unwrap();
        let deleted = connection.execute(
            "DELETE FROM observability_events WHERE timestamp_unix_ms < ?1",
            params![cutoff_unix_ms],
        )?;
        Ok(deleted)
    }

    pub fn append(&self, event: NewObservabilityEvent) -> Result<i64> {
        // Opportunistic purge every 100 inserts if retention is configured
        let count = self
            .insert_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count > 0 && count % 100 == 0 {
            if let Some(max_age) = self.retention_max_age {
                let _ = self.purge_expired(max_age);
            }
        }

        let connection = self.connection.lock().unwrap();
        connection.execute(
            "INSERT INTO observability_events(
                timestamp_unix_ms, event_type, level, provider, workspace_id, session_id,
                turn_id, execution_id, invocation_id, guard_id, process_id, reason_code,
                duration_ms, details_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                now_unix_ms(),
                event.event_type,
                normalize_level(&event.level),
                event.provider,
                event.workspace_id,
                event.session_id,
                event.turn_id,
                event.execution_id,
                event.invocation_id,
                event.guard_id,
                std::process::id(),
                event.reason_code,
                event.duration_ms,
                serde_json::to_string(&event.details)?
            ],
        )?;
        Ok(connection.last_insert_rowid())
    }

    pub fn query(&self, query: &EventQuery) -> Result<Vec<ObservabilityEvent>> {
        let connection = self.connection.lock().unwrap();
        let requested_limit = if query.limit == 0 {
            500
        } else {
            query.limit.min(10_000)
        };
        // Apply the same Rust normalization inside SQLite, before LIMIT. A
        // bound JSON array avoids dynamic SQL and SQLite's parameter-count cap.
        let event_types = if query.event_types.is_empty() {
            None
        } else {
            Some(serde_json::to_string(
                &query
                    .event_types
                    .iter()
                    .map(|value| normalize_event_type(value))
                    .collect::<Vec<_>>(),
            )?)
        };
        let mut statement = connection.prepare(
            "SELECT id, timestamp_unix_ms, event_type, level, provider, workspace_id,
                    session_id, turn_id, execution_id, invocation_id, guard_id, process_id,
                    reason_code, duration_ms, details_json
             FROM observability_events
             WHERE id > ?1
               AND (?2 IS NULL OR workspace_id = ?2)
               AND (?3 IS NULL OR session_id = ?3)
               AND (?4 IS NULL OR execution_id = ?4)
               AND (CASE level WHEN 'error' THEN 3 WHEN 'warn' THEN 2 WHEN 'info' THEN 1 ELSE 0 END)
                   >= (CASE COALESCE(?5, 'debug') WHEN 'error' THEN 3 WHEN 'warn' THEN 2 WHEN 'info' THEN 1 ELSE 0 END)
               AND (?6 IS NULL OR arc_event_type_key(event_type) IN (SELECT value FROM json_each(?6)))
             ORDER BY id ASC LIMIT ?7",
        )?;
        let rows = statement.query_map(
            params![
                query.after_id,
                query.workspace_id,
                query.session_id,
                query.execution_id,
                query.minimum_level,
                event_types,
                requested_limit as i64
            ],
            |row| {
                let details_json: String = row.get(14)?;
                Ok(ObservabilityEvent {
                    id: row.get(0)?,
                    timestamp_unix_ms: row.get(1)?,
                    event_type: row.get(2)?,
                    level: row.get(3)?,
                    provider: row.get(4)?,
                    workspace_id: row.get(5)?,
                    session_id: row.get(6)?,
                    turn_id: row.get(7)?,
                    execution_id: row.get(8)?,
                    invocation_id: row.get(9)?,
                    guard_id: row.get(10)?,
                    process_id: row.get(11)?,
                    reason_code: row.get(12)?,
                    duration_ms: row.get(13)?,
                    details: serde_json::from_str(&details_json).unwrap_or(Value::Null),
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn workspace_id(&self, canonical_root: &Path) -> Result<Option<String>> {
        let root = canonical_root.to_string_lossy();
        let connection = self.connection.lock().unwrap();
        Ok(connection
            .query_row(
                "SELECT workspace_id FROM workspaces WHERE canonical_root = ?1",
                [root.as_ref()],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn latest_session(&self, workspace_id: Option<&str>) -> Result<Option<String>> {
        let connection = self.connection.lock().unwrap();
        Ok(connection
            .query_row(
                "SELECT session_id FROM observability_events
             WHERE session_id IS NOT NULL AND (?1 IS NULL OR workspace_id = ?1)
             ORDER BY id DESC LIMIT 1",
                [workspace_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn latest_event_id(&self) -> Result<i64> {
        let connection = self.connection.lock().unwrap();
        Ok(connection.query_row(
            "SELECT COALESCE(MAX(id), 0) FROM observability_events",
            [],
            |row| row.get(0),
        )?)
    }

    /// Deletes observability only. Guard execution state and workspace identities are untouched.
    pub fn clear_events(
        &self,
        workspace_id: Option<&str>,
        session_id: Option<&str>,
        execution_id: Option<&str>,
    ) -> Result<usize> {
        let connection = self.connection.lock().unwrap();
        Ok(connection.execute(
            "DELETE FROM observability_events
             WHERE (?1 IS NULL OR workspace_id = ?1)
               AND (?2 IS NULL OR session_id = ?2)
               AND (?3 IS NULL OR execution_id = ?3)",
            params![workspace_id, session_id, execution_id],
        )?)
    }
}

fn normalize_level(level: &str) -> &str {
    match level.to_ascii_lowercase().as_str() {
        "error" => "error",
        "warn" | "warning" => "warn",
        "debug" => "debug",
        _ => "info",
    }
}

fn normalize_event_type(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn new_invocation_id() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_open_enables_bounded_retention() {
        let path =
            std::env::temp_dir().join(format!("arc_journal_retention_{}.sqlite3", Uuid::new_v4()));
        let journal = ObservabilityJournal::open(&path).unwrap();
        assert_eq!(journal.retention_max_age, Some(DEFAULT_RETENTION_MAX_AGE));
        drop(journal);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn journal_round_trips_and_filters_events() {
        let path = std::env::temp_dir().join(format!("arc_journal_{}.sqlite3", Uuid::new_v4()));
        let journal = ObservabilityJournal::open(&path).unwrap();
        journal
            .append(NewObservabilityEvent {
                event_type: "StateTransition".into(),
                level: "warn".into(),
                session_id: Some("session-a".into()),
                details: serde_json::json!({"to":"abort"}),
                ..Default::default()
            })
            .unwrap();
        let events = journal
            .query(&EventQuery {
                session_id: Some("session-a".into()),
                minimum_level: Some("warn".into()),
                event_types: vec!["state-transition".into()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].details["to"], "abort");
        assert!(journal.latest_event_id().unwrap() > 0);
        assert_eq!(
            journal.clear_events(None, Some("session-a"), None).unwrap(),
            1
        );
        assert!(journal.query(&EventQuery::default()).unwrap().is_empty());
        drop(journal);
        let _ = std::fs::remove_file(path);
    }
}
