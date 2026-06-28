use serde::{Deserialize, Serialize};

// ── Runtime pipe (\\.\pipe\mevault-runtime) ──────────────────────────────────

/// Request sent by any process over the runtime pipe to read secrets.
/// Wire format: one JSON line terminated by `\n`.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    GetSecret { name: String },
    ListSecrets,
}

/// Response from the runtime pipe server.
#[derive(Debug, Serialize)]
pub struct IpcResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl IpcResponse {
    pub fn value(v: impl Into<String>) -> Self {
        Self { ok: true, value: Some(v.into()), names: None, error: None, reason: None }
    }
    pub fn names(names: Vec<String>) -> Self {
        Self { ok: true, value: None, names: Some(names), error: None, reason: None }
    }
    pub fn err(error: impl Into<String>, reason: impl Into<Option<String>>) -> Self {
        Self { ok: false, value: None, names: None, error: Some(error.into()), reason: reason.into() }
    }
}

// ── Control pipe (\\.\pipe\mevault-control) ──────────────────────────────────

/// Management command sent by the CLI or UI over the control pipe.
/// Only callers whose exe name matches the management allow-list are served.
/// Wire format: one JSON line terminated by `\n`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Query vault status without changing state.
    Status,
    /// Gracefully lock the vault, flush the audit log, and exit.
    Lock,
}

/// Response from the control pipe server.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ControlResponse {
    pub fn ok_simple() -> Self {
        Self { ok: true, vault_name: None, active: None, error: None }
    }
    pub fn status(vault_name: Option<String>, active: bool) -> Self {
        Self { ok: true, vault_name, active: Some(active), error: None }
    }
    pub fn err(error: impl Into<String>) -> Self {
        Self { ok: false, vault_name: None, active: None, error: Some(error.into()) }
    }
}
