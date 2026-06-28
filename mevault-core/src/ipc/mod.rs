pub mod protocol;

use std::future::Future;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use tokio::sync::mpsc;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;

use crate::{
    allowlist,
    audit::{AuditEvent, AuditLog, EventType},
    config::ProjectConfig,
    identity,
    session::SharedSession,
    vault::SecretStoreBridge,
};
pub use protocol::{ControlRequest, ControlResponse, IpcRequest, IpcResponse};

/// Secret-request pipe: any process may connect; identity is the gate.
pub const RUNTIME_PIPE: &str = r"\\.\pipe\mevault-runtime";

/// Management pipe: only approved management executables are served.
/// Used by `mevault lock`, `mevault status`, and the desktop UI.
pub const CONTROL_PIPE: &str = r"\\.\pipe\mevault-control";

/// Exes allowed to connect to the control pipe.
const MANAGEMENT_EXES: &[&str] = &["mevault.exe", "mevault-app.exe"];

/// Run the named-pipe runtime server until `shutdown` resolves.
///
/// Accepts connections on `\\.\pipe\mevault-runtime`. For every connection the
/// kernel provides the real caller PID via `GetNamedPipeClientProcessId` —
/// the caller cannot forge this. The PID is then fed through the full
/// identity + allow-list chain before any secret is returned.
pub async fn run_pipe_server(
    session: SharedSession,
    audit: Arc<AuditLog>,
    config: Arc<ProjectConfig>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(RUNTIME_PIPE)
        .context("creating named pipe mevault-runtime")?;

    tracing::info!("MeVault runtime pipe listening on {RUNTIME_PIPE}");

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,

            result = server.connect() => {
                result.context("pipe accept")?;

                // Create the next server instance BEFORE handing off the connected one
                // so there is no window where incoming clients get ERROR_PIPE_NOT_FOUND.
                let next = ServerOptions::new()
                    .create(RUNTIME_PIPE)
                    .context("creating next pipe instance")?;
                let current = std::mem::replace(&mut server, next);

                let session = Arc::clone(&session);
                let audit   = Arc::clone(&audit);
                let config  = Arc::clone(&config);

                tokio::spawn(async move {
                    if let Err(e) = handle_client(current, session, audit, config).await {
                        tracing::debug!("ipc client error: {e}");
                    }
                });
            }
        }
    }

    tracing::info!("named pipe server stopped");
    Ok(())
}

// ── Per-connection handler ──────────────────────────────────────────────────

async fn handle_client(
    pipe: NamedPipeServer,
    session: SharedSession,
    audit: Arc<AuditLog>,
    config: Arc<ProjectConfig>,
) -> Result<()> {
    // Step 1: kernel-provided PID — unforgeable.
    let pid = client_pid(&pipe).context("GetNamedPipeClientProcessId")?;

    // Step 2: record grant immediately — binds PID to its creation timestamp
    // and exe path so every subsequent request can detect PID recycling.
    let grant = identity::record_grant(pid).context("recording process grant")?;

    let (reader, mut writer) = tokio::io::split(pipe);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await.context("pipe read")? > 0 {
        let trimmed = line.trim();
        let response = if trimmed.is_empty() {
            line.clear();
            continue;
        } else {
            match serde_json::from_str::<IpcRequest>(trimmed) {
                Ok(req) => dispatch(&req, &grant, &session, &audit, &config).await,
                Err(_) => IpcResponse::err("invalid_request", None),
            }
        };

        let mut encoded = serde_json::to_string(&response).unwrap_or_default();
        encoded.push('\n');
        writer.write_all(encoded.as_bytes()).await.context("pipe write")?;
        line.clear();
    }

    Ok(())
}

// ── Request dispatcher ──────────────────────────────────────────────────────

async fn dispatch(
    req: &IpcRequest,
    grant: &identity::ProcessGrant,
    session: &SharedSession,
    audit: &Arc<AuditLog>,
    config: &Arc<ProjectConfig>,
) -> IpcResponse {
    // Re-verify the grant on every request: if the original process exited and
    // a new process recycled the PID, the creation timestamp will differ.
    if !identity::verify_grant(grant) {
        tracing::warn!(
            "grant verification failed for PID {} — process identity changed",
            grant.pid
        );
        return IpcResponse::err("grant_invalid", Some("process identity changed since connection".to_owned()));
    }

    let pid = grant.pid;

    match req {
        IpcRequest::ListSecrets => {
            let lock = session.read().await;
            let sess = match lock.as_ref() {
                Some(s) if s.is_active() => s,
                Some(_) => return IpcResponse::err("session_expired", None),
                None    => return IpcResponse::err("vault_locked", None),
            };
            if config.security.require_identity_check {
                match identity::build_process_chain(pid) {
                    Ok(chain) => {
                        let decision = allowlist::check_access(&chain, "", config, &sess.project_root);
                        if !decision.is_allowed() {
                            return IpcResponse::err("access_denied", Some(decision.reason().to_owned()));
                        }
                    }
                    Err(e) => {
                        tracing::warn!("build_process_chain({pid}): {e}");
                        return IpcResponse::err("identity_unknown", None);
                    }
                }
            }
            IpcResponse::names(sess.secret_names())
            // lock released here
        }

        IpcRequest::GetSecret { name } => {
            // Scope the lock so it is released BEFORE any blocking PS call.
            // In lazy mode, keep only owned clones; in preloaded mode, the
            // value is extracted as an owned String before the lock is dropped.
            let (allowed, deny_reason, preloaded, lazy_params, vault_name, session_id) = {
                let lock = session.read().await;
                let sess = match lock.as_ref() {
                    Some(s) if s.is_active() => s,
                    Some(_) => return IpcResponse::err("session_expired", None),
                    None    => return IpcResponse::err("vault_locked", None),
                };

                let (allowed, deny_reason) = if config.security.require_identity_check {
                    match identity::build_process_chain(pid) {
                        Ok(chain) => {
                            let dec = allowlist::check_access(&chain, name, config, &sess.project_root);
                            if dec.is_allowed() {
                                (true, None)
                            } else {
                                (false, Some(dec.reason().to_owned()))
                            }
                        }
                        Err(e) => {
                            tracing::warn!("build_process_chain({pid}): {e}");
                            (false, Some("identity_unknown".to_owned()))
                        }
                    }
                } else {
                    (true, None::<String>)
                };

                (
                    allowed,
                    deny_reason,
                    sess.get_secret(name).map(|s| {
                        use secrecy::ExposeSecret;
                        s.expose_secret().to_owned()
                    }),
                    sess.lazy_params(),
                    sess.vault_name.clone(),
                    sess.id.to_string(),
                )
                // lock released here — no lock held beyond this point
            };

            if !allowed {
                let reason = deny_reason.unwrap_or_default();
                if reason == "identity_unknown" {
                    return IpcResponse::err("identity_unknown", None);
                }
                write_audit(
                    audit,
                    AuditEvent::new(EventType::Denied)
                        .secret(name)
                        .vault(&vault_name)
                        .session(session_id)
                        .reason(&reason),
                );
                return IpcResponse::err("access_denied", Some(reason));
            }

            // Preloaded mode: value already in memory.
            if let Some(value) = preloaded {
                write_audit(
                    audit,
                    AuditEvent::new(EventType::Allowed)
                        .secret(name)
                        .vault(&vault_name)
                        .session(session_id),
                );
                return IpcResponse::value(value);
            }

            // Lazy mode: decrypt on demand (spawns a PS subprocess, lock already free).
            if let Some((password, lazy_vault)) = lazy_params {
                let name_clone = name.clone();
                let result = tokio::task::spawn_blocking(move || {
                    SecretStoreBridge::new().get_secret(&name_clone, &lazy_vault, Some(&password))
                })
                .await;

                return match result {
                    Ok(Ok(secret)) => {
                        use secrecy::ExposeSecret;
                        write_audit(
                            audit,
                            AuditEvent::new(EventType::Allowed)
                                .secret(name)
                                .vault(&vault_name)
                                .session(session_id),
                        );
                        IpcResponse::value(secret.expose_secret().to_owned())
                    }
                    Ok(Err(_)) => IpcResponse::err("secret_not_found", Some(name.clone())),
                    Err(_) => IpcResponse::err("internal_error", None),
                };
            }

            IpcResponse::err("secret_not_found", Some(name.clone()))
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Get the PID of the process on the other end of a connected named pipe.
/// This comes from the Windows kernel — the caller cannot spoof it.
fn client_pid(pipe: &NamedPipeServer) -> Result<u32> {
    // as_raw_handle() returns *mut c_void, which is what HANDLE wraps in windows-rs 0.48+
    let handle = HANDLE(pipe.as_raw_handle());
    let mut pid = 0u32;
    unsafe {
        GetNamedPipeClientProcessId(handle, &mut pid)
            .context("GetNamedPipeClientProcessId")?;
    }
    Ok(pid)
}

fn write_audit(audit: &Arc<AuditLog>, event: AuditEvent) {
    let audit = Arc::clone(audit);
    tokio::spawn(async move {
        if let Err(e) = audit.write(event).await {
            tracing::warn!("audit write failed: {e}");
        }
    });
}

// ── Control pipe server ──────────────────────────────────────────────────────

/// Run the control pipe server until `shutdown` resolves.
///
/// Accepts connections on `\\.\pipe\mevault-control`. Each caller's exe is
/// verified against `MANAGEMENT_EXES` before any command is dispatched.
/// When a `Lock` command is received the server fires `shutdown_trigger`,
/// which the caller (unlock/run) uses to shut down all servers gracefully.
pub async fn run_control_server(
    session: SharedSession,
    shutdown_trigger: mpsc::Sender<()>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    run_control_server_on(CONTROL_PIPE, MANAGEMENT_EXES, session, shutdown_trigger, shutdown).await
}

/// Internal: start the control server on an arbitrary pipe name and exe allow-list.
/// Keeping this separate from the public function allows tests to use a unique name
/// (avoiding collisions with a running vault) and a custom exe allow-list.
async fn run_control_server_on(
    pipe_name: &str,
    allowed_exes: &'static [&'static str],
    session: SharedSession,
    shutdown_trigger: mpsc::Sender<()>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe_name)
        .with_context(|| format!("creating named pipe {pipe_name}"))?;

    tracing::info!("MeVault control pipe listening on {pipe_name}");
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,

            result = server.connect() => {
                result.context("control pipe accept")?;

                let next = ServerOptions::new()
                    .create(pipe_name)
                    .context("creating next control pipe instance")?;
                let current = std::mem::replace(&mut server, next);

                let session      = Arc::clone(&session);
                let trigger      = shutdown_trigger.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_control_client(current, allowed_exes, session, trigger).await {
                        tracing::debug!("control client error: {e}");
                    }
                });
            }
        }
    }

    tracing::info!("control pipe server stopped");
    Ok(())
}

fn is_management_exe(exe_path: &std::path::Path, allowed: &[&str]) -> bool {
    let name = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    allowed.iter().any(|&m| m.eq_ignore_ascii_case(&name))
}

async fn handle_control_client(
    pipe: NamedPipeServer,
    allowed_exes: &[&str],
    session: SharedSession,
    shutdown_trigger: mpsc::Sender<()>,
) -> Result<()> {
    let pid   = client_pid(&pipe).context("GetNamedPipeClientProcessId")?;
    let grant = identity::record_grant(pid).context("recording control grant")?;

    if !is_management_exe(&grant.exe_path, allowed_exes) {
        let resp = ControlResponse::err("unauthorized");
        let encoded = format!("{}\n", serde_json::to_string(&resp).unwrap_or_default());
        let (_, mut writer) = tokio::io::split(pipe);
        writer.write_all(encoded.as_bytes()).await.ok();
        tracing::warn!("control pipe: rejected caller PID {pid} (not in management exe list)");
        return Ok(());
    }

    let (reader, mut writer) = tokio::io::split(pipe);
    let mut reader = BufReader::new(reader);
    let mut line   = String::new();

    while reader.read_line(&mut line).await.context("control pipe read")? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let response = match serde_json::from_str::<ControlRequest>(trimmed) {
            Err(_) => ControlResponse::err("invalid_request"),

            Ok(ControlRequest::Status) => {
                let lock = session.read().await;
                match lock.as_ref() {
                    Some(s) => ControlResponse::status(Some(s.vault_name.clone()), s.is_active()),
                    None    => ControlResponse::status(None, false),
                }
            }

            Ok(ControlRequest::Lock) => {
                // Signal all servers to shut down, then acknowledge.
                let _ = shutdown_trigger.send(()).await;
                ControlResponse::ok_simple()
            }
        };

        let encoded = format!("{}\n", serde_json::to_string(&response).unwrap_or_default());
        writer.write_all(encoded.as_bytes()).await.context("control pipe write")?;
        line.clear();
    }

    Ok(())
}

// ── Control pipe client ──────────────────────────────────────────────────────

/// Connect to `\\.\pipe\mevault-control` and send a single command,
/// returning the server's response. Used by `mevault lock` and `mevault status`.
pub async fn send_control(req: &ControlRequest) -> Result<ControlResponse> {
    let pipe = ClientOptions::new()
        .open(CONTROL_PIPE)
        .context("connecting to mevault-control (is the vault unlocked?)")?;

    let (reader, mut writer) = tokio::io::split(pipe);
    let mut reader = BufReader::new(reader);

    let encoded = format!("{}\n", serde_json::to_string(req).context("encoding control request")?);
    writer.write_all(encoded.as_bytes()).await.context("sending control request")?;

    let mut line = String::new();
    reader.read_line(&mut line).await.context("reading control response")?;

    serde_json::from_str::<ControlResponse>(line.trim()).context("parsing control response")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // ── Unit tests: protocol serde ────────────────────────────────────────────

    #[test]
    fn control_request_lock_serializes() {
        let json = serde_json::to_string(&ControlRequest::Lock).unwrap();
        assert_eq!(json, r#"{"op":"lock"}"#);
    }

    #[test]
    fn control_request_status_serializes() {
        let json = serde_json::to_string(&ControlRequest::Status).unwrap();
        assert_eq!(json, r#"{"op":"status"}"#);
    }

    #[test]
    fn control_response_serde_roundtrip() {
        let resp = ControlResponse::status(Some("my-vault".to_owned()), true);
        let json = serde_json::to_string(&resp).unwrap();
        let back: ControlResponse = serde_json::from_str(&json).unwrap();
        assert!(back.ok);
        assert_eq!(back.vault_name.as_deref(), Some("my-vault"));
        assert_eq!(back.active, Some(true));
        assert!(back.error.is_none());
    }

    #[test]
    fn control_response_err_roundtrip() {
        let resp = ControlResponse::err("unauthorized");
        let json = serde_json::to_string(&resp).unwrap();
        let back: ControlResponse = serde_json::from_str(&json).unwrap();
        assert!(!back.ok);
        assert_eq!(back.error.as_deref(), Some("unauthorized"));
        assert!(back.vault_name.is_none());
        assert!(back.active.is_none());
    }

    // ── Unit tests: management exe allow-list ─────────────────────────────────

    #[test]
    fn management_exe_approves_known_names() {
        use std::path::Path;
        let allowed = &["mevault.exe", "mevault-app.exe"];
        assert!(is_management_exe(Path::new("mevault.exe"), allowed));
        assert!(is_management_exe(Path::new("MEVAULT.EXE"), allowed));
        assert!(is_management_exe(Path::new(r"C:\Program Files\MeVault\mevault.exe"), allowed));
        assert!(is_management_exe(Path::new("mevault-app.exe"), allowed));
    }

    #[test]
    fn management_exe_rejects_unknown_names() {
        use std::path::Path;
        let allowed = &["mevault.exe", "mevault-app.exe"];
        assert!(!is_management_exe(Path::new("python.exe"), allowed));
        assert!(!is_management_exe(Path::new("claude.exe"), allowed));
        assert!(!is_management_exe(Path::new("node.exe"), allowed));
        assert!(!is_management_exe(Path::new(""), allowed));
    }

    // ── Integration tests: control pipe behavior ──────────────────────────────

    fn locked_session() -> SharedSession {
        Arc::new(RwLock::new(None))
    }

    /// Helper: connect to `pipe_name`, send one JSON request, return the response.
    async fn roundtrip(pipe_name: &str, req: &ControlRequest) -> ControlResponse {
        let pipe = ClientOptions::new()
            .open(pipe_name)
            .expect("failed to open control pipe");
        let (reader, mut writer) = tokio::io::split(pipe);
        let mut reader = BufReader::new(reader);

        let encoded = format!("{}\n", serde_json::to_string(req).unwrap());
        writer.write_all(encoded.as_bytes()).await.unwrap();

        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        serde_json::from_str(line.trim()).expect("invalid JSON from server")
    }

    #[tokio::test]
    async fn control_pipe_rejects_non_management_exe() {
        // The test binary is NOT in MANAGEMENT_EXES, so the server must return unauthorized.
        let pipe_name = r"\\.\pipe\mevault-ctrl-test-reject";
        let session = locked_session();
        let (kill_tx, _kill_rx) = mpsc::channel::<()>(1);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(run_control_server_on(
            pipe_name,
            MANAGEMENT_EXES,
            Arc::clone(&session),
            kill_tx,
            async move { let _ = done_rx.await; },
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = roundtrip(pipe_name, &ControlRequest::Status).await;
        assert!(!resp.ok, "expected unauthorized");
        assert_eq!(resp.error.as_deref(), Some("unauthorized"));

        let _ = done_tx.send(());
    }

    #[tokio::test]
    async fn control_pipe_status_locked_vault() {
        // Allow the test binary so we can test the actual Status dispatch.
        let test_exe_name: &'static str = Box::leak(
            std::env::current_exe().unwrap()
                .file_name().unwrap()
                .to_str().unwrap()
                .to_string()
                .into_boxed_str(),
        );
        let allowed: &'static [&'static str] =
            Box::leak(vec!["mevault.exe", test_exe_name].into_boxed_slice());

        let pipe_name = r"\\.\pipe\mevault-ctrl-test-status";
        let session = locked_session();
        let (kill_tx, _kill_rx) = mpsc::channel::<()>(1);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(run_control_server_on(
            pipe_name,
            allowed,
            Arc::clone(&session),
            kill_tx,
            async move { let _ = done_rx.await; },
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = roundtrip(pipe_name, &ControlRequest::Status).await;
        assert!(resp.ok);
        // Vault is locked (session = None), so active must be false.
        assert_eq!(resp.active, Some(false));

        let _ = done_tx.send(());
    }

    #[tokio::test]
    async fn control_pipe_lock_fires_shutdown_trigger() {
        let test_exe_name: &'static str = Box::leak(
            std::env::current_exe().unwrap()
                .file_name().unwrap()
                .to_str().unwrap()
                .to_string()
                .into_boxed_str(),
        );
        let allowed: &'static [&'static str] =
            Box::leak(vec!["mevault.exe", test_exe_name].into_boxed_slice());

        let pipe_name = r"\\.\pipe\mevault-ctrl-test-lock";
        let session = locked_session();
        let (kill_tx, mut kill_rx) = mpsc::channel::<()>(1);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(run_control_server_on(
            pipe_name,
            allowed,
            Arc::clone(&session),
            kill_tx,
            async move { let _ = done_rx.await; },
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send Lock and verify the server acknowledges it.
        let resp = roundtrip(pipe_name, &ControlRequest::Lock).await;
        assert!(resp.ok, "Lock should return ok:true");
        assert!(resp.error.is_none());

        // The shutdown trigger must have fired within a reasonable time.
        let received = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            kill_rx.recv(),
        )
        .await;
        assert!(received.is_ok(), "shutdown_trigger was not fired by Lock command");

        let _ = done_tx.send(());
    }
}
