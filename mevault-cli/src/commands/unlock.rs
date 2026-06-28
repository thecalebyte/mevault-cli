use anyhow::{bail, Context, Result};
use mevault_core::{
    audit::{AuditEvent, AuditLog, EventType},
    config::{ProjectConfig, SystemPolicy},
    ipc::{self, ControlRequest},
    session::{Session, SessionManager},
    vault::SecretStoreBridge,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

use crate::commands::add::prompt_vault_password;

/// Path where we write the active session info (token, PID, port).
pub fn session_file_path() -> Result<PathBuf> {
    let appdata = std::env::var("APPDATA").context("APPDATA env var not set")?;
    Ok(PathBuf::from(appdata).join("MeVault").join("session.json"))
}

pub async fn run() -> Result<()> {
    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut cfg = ProjectConfig::load(&project_root)
        .context("no mevault.toml found — run `mevault init` first")?;

    // Apply system policy (requires admin to change) over project config.
    SystemPolicy::load().apply_to(&mut cfg.security);

    // Refuse if a session is already active (check via control pipe).
    if is_vault_active().await {
        bail!("A vault session is already active. Run `mevault lock` first.");
    }

    println!("Unlocking vault '{}'…", cfg.project.vault_name);
    let password = prompt_vault_password()?;

    // Lazy path: unlock + list names in one PS call; don't preload values.
    let bridge = SecretStoreBridge::new();
    let secret_names = bridge
        .unlock_and_list_names(&cfg.project.vault_name, &password)
        .context("failed to unlock vault")?;

    let count = secret_names.len();
    println!("Found {count} secret(s) — decryption is on-demand.");

    let manager = SessionManager::new();
    let session = Session::new_lazy(
        &cfg.project.vault_name,
        cfg.session.expiry_mode.clone(),
        Some(cfg.session.expiry_hours),
        std::process::id(),
        project_root.clone(),
        password,
        secret_names,
    );
    let session_id = session.id.to_string();
    manager.start(session).await;

    // Write session info so `mevault run` and `mevault lock` can find this process.
    let session_path = session_file_path()?;
    write_session_file(&session_path, &session_id, &cfg.project.vault_name)?;

    let appdata = std::env::var("APPDATA").context("APPDATA env var not set")?;
    let db_path = PathBuf::from(appdata).join("MeVault").join("audit.db");
    let audit = Arc::new(AuditLog::open(&db_path).await.context("opening audit log")?);

    audit
        .write(
            AuditEvent::new(EventType::SessionStarted)
                .vault(&cfg.project.vault_name)
                .session(&session_id),
        )
        .await?;

    println!("Vault unlocked.");
    println!("  Runtime pipe : \\\\.\\pipe\\mevault-runtime");
    println!("  Control pipe : \\\\.\\pipe\\mevault-control");
    println!("Press Ctrl+C or run `mevault lock` to lock the vault.");

    // Single mpsc channel; both Ctrl+C and a Lock pipe command fire it.
    let (kill_tx, mut kill_rx) = mpsc::channel::<()>(1);
    let kill_tx_ctrlc = kill_tx.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        println!("\nShutting down…");
        let _ = kill_tx_ctrlc.send(()).await;
    });

    let (pipe_tx, pipe_rx) = oneshot::channel::<()>();
    let (ctrl_tx, ctrl_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        kill_rx.recv().await;
        let _ = pipe_tx.send(());
        let _ = ctrl_tx.send(());
    });

    let pipe_session = manager.shared();
    let pipe_audit   = Arc::clone(&audit);
    let pipe_config  = Arc::new(cfg.clone());
    let ctrl_session = manager.shared();

    let (pipe_result, ctrl_result) = tokio::join!(
        ipc::run_pipe_server(pipe_session, pipe_audit, pipe_config, async move { let _ = pipe_rx.await; }),
        ipc::run_control_server(ctrl_session, kill_tx, async move { let _ = ctrl_rx.await; }),
    );

    let _ = std::fs::remove_file(&session_path);
    manager.end().await;
    audit
        .write(
            AuditEvent::new(EventType::SessionEnded)
                .vault(&cfg.project.vault_name)
                .session(&session_id),
        )
        .await?;

    println!("Vault locked.");
    pipe_result.and(ctrl_result)
}

fn write_session_file(path: &Path, session_id: &str, vault_name: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let info = json!({
        "session_id": session_id,
        "vault_name": vault_name,
        "pid": std::process::id(),
    });
    std::fs::write(path, info.to_string())
        .with_context(|| format!("writing session file to {}", path.display()))
}

/// Check whether a vault session is already running by querying the control pipe.
/// Returns true only when the vault is unlocked and active.
async fn is_vault_active() -> bool {
    matches!(
        ipc::send_control(&ControlRequest::Status).await,
        Ok(resp) if resp.ok && resp.active.unwrap_or(false)
    )
}
