//! MeVault SDK — synchronous named-pipe client for the MeVault secrets broker.
//!
//! # Quick start
//!
//! ```rust,no_run
//! let db_url = mevault_sdk::get("DATABASE_URL")?;
//! // use db_url.expose_secret() to get the &str value
//! # Ok::<_, mevault_sdk::Error>(())
//! ```
//!
//! The SDK connects to `\\.\pipe\mevault-runtime` for each call, sends a
//! single JSON request, and returns the value in a [`secrecy::SecretString`]
//! that is zeroized on drop. No secrets are written to disk or logs.

use std::io::{BufRead, BufReader, Write};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

pub use secrecy;

const RUNTIME_PIPE: &str = r"\\.\pipe\mevault-runtime";

// ── Public error type ─────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The vault is not running, the pipe is unavailable, or I/O failed.
    #[error("vault not available: {0}")]
    Io(#[from] std::io::Error),
    /// The server returned an unexpected or malformed response.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The broker denied the request (vault locked, access denied, etc.).
    #[error("{reason}")]
    Vault { reason: String },
}

pub type Result<T> = std::result::Result<T, Error>;

// ── Internal wire types ───────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request<'a> {
    GetSecret { name: &'a str },
    ListSecrets,
}

#[derive(Deserialize)]
struct Response {
    ok: bool,
    value: Option<String>,
    names: Option<Vec<String>>,
    error: Option<String>,
    reason: Option<String>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Retrieve a single secret from the MeVault runtime.
///
/// Opens a connection to `\\.\pipe\mevault-runtime`, sends a `get_secret`
/// request, and returns the value in a [`SecretString`] that is zeroized when
/// dropped. The caller's process identity is verified by the broker — no
/// credentials are passed by the SDK.
pub fn get(name: &str) -> Result<SecretString> {
    let resp = send(&Request::GetSecret { name })?;
    if resp.ok {
        let value = resp
            .value
            .ok_or_else(|| Error::Protocol("missing 'value' in ok response".to_owned()))?;
        Ok(SecretString::new(value))
    } else {
        Err(Error::Vault {
            reason: resp
                .reason
                .or(resp.error)
                .unwrap_or_else(|| "vault denied the request".to_owned()),
        })
    }
}

/// List the secret names that the broker permits the current process to access.
///
/// Does not return secret values — only names.
pub fn list() -> Result<Vec<String>> {
    let resp = send(&Request::ListSecrets)?;
    if resp.ok {
        Ok(resp.names.unwrap_or_default())
    } else {
        Err(Error::Vault {
            reason: resp
                .reason
                .or(resp.error)
                .unwrap_or_else(|| "vault denied the request".to_owned()),
        })
    }
}

// ── Internal transport ────────────────────────────────────────────────────────

fn send(req: &impl Serialize) -> Result<Response> {
    let mut line = serde_json::to_string(req).map_err(|e| Error::Protocol(e.to_string()))?;
    line.push('\n');

    let mut pipe = open_pipe(RUNTIME_PIPE)?;
    pipe.write_all(line.as_bytes())?;
    pipe.flush()?;

    let mut reader = BufReader::new(&mut pipe);
    let mut response_line = String::new();
    reader.read_line(&mut response_line)?;

    serde_json::from_str::<Response>(response_line.trim_end())
        .map_err(|e| Error::Protocol(format!("invalid JSON from broker: {e}")))
}

// ── Platform-specific pipe open ───────────────────────────────────────────────

#[cfg(windows)]
fn open_pipe(path: &str) -> std::io::Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match OpenOptions::new().read(true).write(true).open(path) {
            Ok(f) => return Ok(f),
            // ERROR_PIPE_BUSY (231) — all server instances are handling other clients.
            // Retry until the deadline rather than failing immediately.
            Err(e) if e.raw_os_error() == Some(231) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
}

/// On non-Windows builds the SDK compiles but always returns Unsupported.
/// This allows cross-compilation and crate-level documentation to build.
#[cfg(not(windows))]
fn open_pipe(_path: &str) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "MeVault named pipes are only available on Windows",
    ))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Serialization ─────────────────────────────────────────────────────────

    #[test]
    fn get_secret_request_serializes() {
        let req = Request::GetSecret { name: "DB_URL" };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains("\"op\":\"get_secret\""),
            "missing op tag: {json}"
        );
        assert!(json.contains("\"name\":\"DB_URL\""), "missing name: {json}");
    }

    #[test]
    fn list_secrets_request_serializes() {
        let req = Request::ListSecrets;
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"op":"list_secrets"}"#);
    }

    // ── Response deserialization ──────────────────────────────────────────────

    #[test]
    fn ok_value_response_deserializes() {
        let json = r#"{"ok":true,"value":"postgres://user:pass@localhost/db"}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert_eq!(
            resp.value.as_deref(),
            Some("postgres://user:pass@localhost/db")
        );
        assert!(resp.names.is_none());
    }

    #[test]
    fn ok_names_response_deserializes() {
        let json = r#"{"ok":true,"names":["DB_URL","API_KEY","REDIS_URL"]}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert_eq!(
            resp.names.as_deref(),
            Some(
                &[
                    "DB_URL".to_owned(),
                    "API_KEY".to_owned(),
                    "REDIS_URL".to_owned()
                ][..]
            )
        );
    }

    #[test]
    fn error_response_deserializes() {
        let json = r#"{"ok":false,"error":"vault_locked","reason":"vault is not unlocked"}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.as_deref(), Some("vault_locked"));
        assert_eq!(resp.reason.as_deref(), Some("vault is not unlocked"));
    }

    #[test]
    fn minimal_error_response_deserializes() {
        let json = r#"{"ok":false,"error":"access_denied"}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        assert!(!resp.ok);
        assert!(resp.reason.is_none());
    }

    // ── Vault error conversion ────────────────────────────────────────────────

    #[test]
    fn vault_error_uses_reason_first() {
        let json = r#"{"ok":false,"error":"access_denied","reason":"policy denied DB_URL"}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        let err = Error::Vault {
            reason: resp.reason.or(resp.error).unwrap_or_default(),
        };
        assert!(matches!(err, Error::Vault { reason } if reason == "policy denied DB_URL"));
    }

    #[test]
    fn vault_error_falls_back_to_error_field() {
        let json = r#"{"ok":false,"error":"vault_locked"}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        let err = Error::Vault {
            reason: resp.reason.or(resp.error).unwrap_or_default(),
        };
        assert!(matches!(err, Error::Vault { reason } if reason == "vault_locked"));
    }

    // ── Live-pipe behaviour (vault unavailable) ──────────────────────────────
    // The vault may be absent (Io error) or locked/inaccessible (Vault error).
    // Both cases must return Err without panicking or hanging.

    fn is_unavailable(e: &Error) -> bool {
        matches!(e, Error::Io(_) | Error::Vault { .. } | Error::Protocol(_))
    }

    #[test]
    #[ignore = "requires no vault session running; use `cargo test -- --ignored` in CI"]
    fn get_returns_error_when_vault_unavailable() {
        let result = get("SHOULD_NOT_EXIST");
        assert!(
            result.as_ref().err().map(is_unavailable).unwrap_or(false),
            "expected unavailable error, got: {result:?}"
        );
    }

    #[test]
    #[ignore = "requires no vault session running; use `cargo test -- --ignored` in CI"]
    fn list_returns_error_when_vault_unavailable() {
        let result = list();
        assert!(
            result.as_ref().err().map(is_unavailable).unwrap_or(false),
            "expected unavailable error, got: {result:?}"
        );
    }
}
