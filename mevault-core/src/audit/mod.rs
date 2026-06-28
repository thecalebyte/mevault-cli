use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    FromRow, SqlitePool,
};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Allowed,
    Denied,
    Locked,
    Unlocked,
    SessionStarted,
    SessionEnded,
    SecretAdded,
    SecretRemoved,
    Error,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Locked => "locked",
            Self::Unlocked => "unlocked",
            Self::SessionStarted => "session_started",
            Self::SessionEnded => "session_ended",
            Self::SecretAdded => "secret_added",
            Self::SecretRemoved => "secret_removed",
            Self::Error => "error",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for EventType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "allowed" => Ok(Self::Allowed),
            "denied" => Ok(Self::Denied),
            "locked" => Ok(Self::Locked),
            "unlocked" => Ok(Self::Unlocked),
            "session_started" => Ok(Self::SessionStarted),
            "session_ended" => Ok(Self::SessionEnded),
            "secret_added" => Ok(Self::SecretAdded),
            "secret_removed" => Ok(Self::SecretRemoved),
            "error" => Ok(Self::Error),
            other => anyhow::bail!("unknown event type: {other}"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuditEvent {
    pub event_type: Option<EventType>,
    pub secret_name: Option<String>,
    pub process_path: Option<String>,
    pub process_pid: Option<u32>,
    pub parent_path: Option<String>,
    pub working_dir: Option<String>,
    pub vault_name: Option<String>,
    pub reason: Option<String>,
    pub signature_valid: Option<bool>,
    pub session_id: Option<String>,
}

impl AuditEvent {
    pub fn new(event_type: EventType) -> Self {
        Self {
            event_type: Some(event_type),
            ..Default::default()
        }
    }

    pub fn secret(mut self, name: impl Into<String>) -> Self {
        self.secret_name = Some(name.into());
        self
    }

    pub fn process(mut self, path: impl Into<String>, pid: u32) -> Self {
        self.process_path = Some(path.into());
        self.process_pid = Some(pid);
        self
    }

    pub fn parent(mut self, path: impl Into<String>) -> Self {
        self.parent_path = Some(path.into());
        self
    }

    pub fn vault(mut self, name: impl Into<String>) -> Self {
        self.vault_name = Some(name.into());
        self
    }

    pub fn reason(mut self, r: impl Into<String>) -> Self {
        self.reason = Some(r.into());
        self
    }

    pub fn signature(mut self, valid: bool) -> Self {
        self.signature_valid = Some(valid);
        self
    }

    pub fn session(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    pub fn working_dir(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditRecord {
    pub id: i64,
    pub timestamp: String,
    pub event_type: String,
    pub secret_name: Option<String>,
    pub process_path: Option<String>,
    pub process_pid: Option<i64>,
    pub parent_path: Option<String>,
    pub working_dir: Option<String>,
    pub vault_name: Option<String>,
    pub reason: Option<String>,
    pub signature_valid: Option<i64>,
    pub session_id: Option<String>,
}

pub struct AuditLog {
    pool: SqlitePool,
}

impl AuditLog {
    /// Open (or create) the audit log at the given path and run migrations.
    pub async fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating dir {}", parent.display()))?;
        }

        let options = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .with_context(|| format!("opening audit db at {}", db_path.display()))?;

        Self::run_migrations(&pool).await?;

        Ok(Self { pool })
    }

    async fn run_migrations(pool: &SqlitePool) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit_events (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp        TEXT    NOT NULL,
                event_type       TEXT    NOT NULL,
                secret_name      TEXT,
                process_path     TEXT,
                process_pid      INTEGER,
                parent_path      TEXT,
                working_dir      TEXT,
                vault_name       TEXT,
                reason           TEXT,
                signature_valid  INTEGER,
                session_id       TEXT
            )",
        )
        .execute(pool)
        .await
        .context("creating audit_events table")?;

        for idx in &[
            "CREATE INDEX IF NOT EXISTS idx_timestamp    ON audit_events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_event_type   ON audit_events(event_type)",
            "CREATE INDEX IF NOT EXISTS idx_secret_name  ON audit_events(secret_name)",
            "CREATE INDEX IF NOT EXISTS idx_process_path ON audit_events(process_path)",
        ] {
            sqlx::query(idx).execute(pool).await?;
        }
        Ok(())
    }

    pub async fn write(&self, event: AuditEvent) -> Result<i64> {
        let timestamp = Utc::now().to_rfc3339();
        let event_type = event
            .event_type
            .as_ref()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown".into());

        let sig: Option<i64> = event.signature_valid.map(|v| if v { 1 } else { 0 });
        let pid: Option<i64> = event.process_pid.map(|p| p as i64);

        let id = sqlx::query(
            "INSERT INTO audit_events
                (timestamp, event_type, secret_name, process_path, process_pid,
                 parent_path, working_dir, vault_name, reason, signature_valid, session_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .bind(&timestamp)
        .bind(&event_type)
        .bind(&event.secret_name)
        .bind(&event.process_path)
        .bind(pid)
        .bind(&event.parent_path)
        .bind(&event.working_dir)
        .bind(&event.vault_name)
        .bind(&event.reason)
        .bind(sig)
        .bind(&event.session_id)
        .execute(&self.pool)
        .await
        .context("inserting audit event")?
        .last_insert_rowid();

        Ok(id)
    }

    pub async fn query(
        &self,
        event_type: Option<&str>,
        secret_name: Option<&str>,
        since_hours: Option<u32>,
        limit: u32,
    ) -> Result<Vec<AuditRecord>> {
        let rows: Vec<AuditRecord> = sqlx::query_as(
            "SELECT id, timestamp, event_type, secret_name, process_path, process_pid,
                    parent_path, working_dir, vault_name, reason, signature_valid, session_id
             FROM audit_events
             ORDER BY id DESC
             LIMIT 10000",
        )
        .fetch_all(&self.pool)
        .await
        .context("querying audit log")?;

        let since = since_hours.map(|h| Utc::now() - chrono::Duration::hours(h as i64));

        let filtered: Vec<AuditRecord> = rows
            .into_iter()
            .filter(|r| {
                if let Some(et) = event_type {
                    if r.event_type != et {
                        return false;
                    }
                }
                if let Some(sn) = secret_name {
                    if r.secret_name.as_deref() != Some(sn) {
                        return false;
                    }
                }
                if let Some(since_dt) = since {
                    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&r.timestamp) {
                        if ts < since_dt {
                            return false;
                        }
                    }
                }
                true
            })
            .take(limit as usize)
            .collect();

        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_and_query() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        let log = AuditLog::open(&db_path).await.unwrap();

        log.write(
            AuditEvent::new(EventType::Allowed)
                .secret("DATABASE_URL")
                .vault("TestVault")
                .reason("allow_list match"),
        )
        .await
        .unwrap();

        log.write(
            AuditEvent::new(EventType::Denied)
                .secret("OPENAI_KEY")
                .process("claude.exe", 1234)
                .reason("always_deny"),
        )
        .await
        .unwrap();

        let all = log.query(None, None, None, 100).await.unwrap();
        assert_eq!(all.len(), 2);

        let denied = log.query(Some("denied"), None, None, 100).await.unwrap();
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].reason.as_deref(), Some("always_deny"));
    }
}
