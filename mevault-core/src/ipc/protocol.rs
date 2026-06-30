use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Runtime pipe (\\.\pipe\mevault-runtime) ──────────────────────────────────

fn default_protocol_version() -> u16 {
    1
}

/// Outer envelope parsed from the wire. The `operation` field is flattened
/// so existing SDK clients — which send `{"op":"get_secret","name":"X"}` — are
/// accepted without any changes.
#[derive(Debug, Deserialize)]
pub struct IpcRequest {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u16,
    #[serde(default)]
    pub request_id: Option<Uuid>,
    #[serde(flatten)]
    pub operation: Operation,
}

/// The actual request payload. Tag is the `"op"` key, matching what the SDK
/// already serializes (`{"op":"get_secret",...}` / `{"op":"list_secrets"}`).
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Operation {
    GetSecret { name: String },
    ListSecrets,
}

/// Response from the runtime pipe server.
#[derive(Debug, Serialize)]
pub struct IpcResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
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
        Self {
            ok: true,
            request_id: None,
            value: Some(v.into()),
            names: None,
            error: None,
            reason: None,
        }
    }
    pub fn names(names: Vec<String>) -> Self {
        Self {
            ok: true,
            request_id: None,
            value: None,
            names: Some(names),
            error: None,
            reason: None,
        }
    }
    pub fn err(error: impl Into<String>, reason: impl Into<Option<String>>) -> Self {
        Self {
            ok: false,
            request_id: None,
            value: None,
            names: None,
            error: Some(error.into()),
            reason: reason.into(),
        }
    }
    /// Attach the caller's `request_id` to any response so it can be correlated.
    pub fn with_request_id(mut self, id: Option<Uuid>) -> Self {
        self.request_id = id;
        self
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
        Self {
            ok: true,
            vault_name: None,
            active: None,
            error: None,
        }
    }
    pub fn status(vault_name: Option<String>, active: bool) -> Self {
        Self {
            ok: true,
            vault_name,
            active: Some(active),
            error: None,
        }
    }
    pub fn err(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            vault_name: None,
            active: None,
            error: Some(error.into()),
        }
    }
}
