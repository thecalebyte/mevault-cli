use anyhow::{bail, Context, Result};
use mevault_core::{
    audit::{AuditEvent, AuditLog, EventType},
    config::{ProjectConfig, SystemPolicy},
    identity,
    ipc::{self, ControlRequest},
    session::{Session, SessionManager},
    vault::VaultStore,
};
use secrecy::ExposeSecret;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

use crate::commands::add::prompt_vault_password;

/// `mevault run [--inject-env] <program> [args…]`
///
/// Two modes:
///   1. A session is already running (`mevault unlock`): spawn the child
///      directly — it uses the named pipes for secrets.
///   2. No session running: unlock inline, start ephemeral pipe servers,
///      place the child in a Job Object, run it, then shut everything down.
///
/// With `--inject-env`, secrets are injected as environment variables instead
/// of being served through the proxy. This is less secure (values visible to
/// child sub-processes) and always requires an inline unlock.
pub async fn run(program: &str, args: &[String], inject_env: bool) -> Result<()> {
    if program.is_empty() {
        bail!("Usage: mevault run <program> [args…]");
    }

    // ── Check for an existing session via the control pipe ────────────────
    // --inject-env always uses inline unlock so we have direct vault access.
    if !inject_env && matches!(
        ipc::send_control(&ControlRequest::Status).await,
        Ok(resp) if resp.ok && resp.active.unwrap_or(false)
    ) {
        return spawn_child_in_job(program, args, None).await;
    }

    // ── Inline unlock + ephemeral pipe servers ────────────────────────────
    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut cfg = ProjectConfig::load(&project_root)
        .context("no mevault.toml found — run `mevault init` first")?;

    SystemPolicy::load().apply_to(&mut cfg.security);

    println!("Unlocking vault '{}'…", cfg.project.vault_name);
    let password = prompt_vault_password()?;

    // Unlock vault once — Argon2 runs here; DEK cached in UnlockedVault.
    let vault = Arc::new(
        VaultStore::new()
            .unlock(&cfg.project.vault_name, &password)
            .context("failed to unlock vault")?,
    );
    let names = vault.secret_names().unwrap_or_default();
    let count = names.len();

    // Collect secrets for env injection before the pipe servers start.
    let env_vars: Option<HashMap<String, String>> = if inject_env {
        eprintln!("⚠ --inject-env: secrets will be visible to child sub-processes and in the environment.");
        let mut map = HashMap::with_capacity(count);
        for name in &names {
            if let Ok(val) = vault.get_secret(name) {
                map.insert(name.clone(), val.expose_secret().to_owned());
            }
        }
        Some(map)
    } else {
        None
    };

    println!("Found {count} secret(s). Starting runtime pipe…");

    let manager = SessionManager::new();
    let session = Session::new(
        Arc::clone(&vault),
        cfg.session.expiry_mode.clone(),
        Some(cfg.session.expiry_hours),
        std::process::id(),
        project_root.clone(),
    );
    let session_id = session.id.to_string();
    manager.start(session).await;

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

    // Runtime pipe + control pipe; both die when the child exits.
    let (kill_tx, mut kill_rx) = mpsc::channel::<()>(1);
    let kill_tx_after_child = kill_tx.clone();

    let (pipe_tx, pipe_rx) = oneshot::channel::<()>();
    let (ctrl_tx, ctrl_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        kill_rx.recv().await;
        let _ = pipe_tx.send(());
        let _ = ctrl_tx.send(());
    });

    let pipe_handle = tokio::spawn(ipc::run_pipe_server(
        manager.shared(),
        Arc::clone(&audit),
        Arc::new(cfg.clone()),
        async move { let _ = pipe_rx.await; },
    ));
    let ctrl_handle = tokio::spawn(ipc::run_control_server(
        manager.shared(),
        kill_tx,
        async move { let _ = ctrl_rx.await; },
    ));

    // Give pipe servers a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let exit_status = spawn_child_in_job(program, args, env_vars.as_ref()).await;

    let _ = kill_tx_after_child.send(()).await;
    let _ = pipe_handle.await;
    let _ = ctrl_handle.await;

    manager.end().await;
    audit
        .write(
            AuditEvent::new(EventType::SessionEnded)
                .vault(&cfg.project.vault_name)
                .session(&session_id),
        )
        .await?;

    exit_status
}

/// Spawn `program` in a Windows Job Object with KILL_ON_JOB_CLOSE.
/// Dropping the returned job kills the child and any processes it spawned.
/// `env_vars` — when `Some`, injects those key/value pairs into the child's
/// environment in addition to the inherited environment (--inject-env mode).
async fn spawn_child_in_job(
    program: &str,
    args: &[String],
    env_vars: Option<&HashMap<String, String>>,
) -> Result<()> {
    let job = identity::create_job_object().context("creating job object")?;

    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);
    if let Some(vars) = env_vars {
        cmd.envs(vars);
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning '{program}'"))?;

    // Assign child to job before it can create any grandchildren.
    if let Some(pid) = child.id() {
        if let Err(e) = identity::assign_to_job(&job, pid) {
            tracing::warn!("failed to assign '{program}' (PID {pid}) to job object: {e}");
        }
    }

    let status = child
        .wait()
        .await
        .with_context(|| format!("waiting for '{program}'"))?;

    // `job` is dropped here — kills any lingering child processes.
    drop(job);

    if !status.success() {
        let code = status.code().unwrap_or(-1);
        bail!("'{program}' exited with code {code}");
    }
    Ok(())
}
