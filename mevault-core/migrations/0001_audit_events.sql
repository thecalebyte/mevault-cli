CREATE TABLE IF NOT EXISTS audit_events (
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
);

CREATE INDEX IF NOT EXISTS idx_timestamp    ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_event_type   ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_secret_name  ON audit_events(secret_name);
CREATE INDEX IF NOT EXISTS idx_process_path ON audit_events(process_path);
