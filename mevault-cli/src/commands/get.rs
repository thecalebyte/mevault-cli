use anyhow::{Context, Result};
use mevault_core::{
    audit::{AuditEvent, AuditLog, EventType},
    config::ProjectConfig,
    vault::SecretStoreBridge,
};
use secrecy::ExposeSecret;
use std::io::{self, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::commands::add::prompt_vault_password;

pub async fn run(name: String, reveal: bool) -> Result<()> {
    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cfg = ProjectConfig::load(&project_root)
        .context("no mevault.toml found — run `mevault init` first")?;

    if !reveal {
        // Without --reveal just tell the user what to do.
        eprintln!("Use `mevault get {name} --reveal` to display the value.");
        eprintln!("Requires [security] allow_cli_reveal = true in mevault.toml.");
        return Ok(());
    }

    if !cfg.security.allow_cli_reveal {
        eprintln!(
            "Reveal is disabled. Set [security] allow_cli_reveal = true in mevault.toml to enable it."
        );
        std::process::exit(1);
    }

    // Refuse if stdout is not connected to a terminal.
    if !atty::is(atty::Stream::Stdout) {
        anyhow::bail!("stdout is not a terminal — refusing to reveal secret to a pipe or file");
    }

    let vault_name = &cfg.project.vault_name;
    let vault_pw = prompt_vault_password()?;

    let bridge = SecretStoreBridge::new();
    let secret = bridge
        .get_secret(&name, vault_name, Some(&vault_pw))
        .with_context(|| format!("retrieving secret '{name}' from vault '{vault_name}'"))?;

    // Confirmation prompt.
    eprint!("This will display {name} in your terminal.\nContinue? [y/N]: ");
    io::stderr().flush().ok();

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let answer = answer.trim();

    if answer != "y" && answer != "Y" {
        println!("Aborted.");
        return Ok(());
    }

    // Reveal — wrap in Zeroizing so the heap copy is zeroed on drop.
    {
        let value: Zeroizing<String> = Zeroizing::new(secret.expose_secret().to_owned());
        println!("{}", *value);
        println!(); // blank line after
    } // value is zeroized here

    // Audit the reveal.
    let appdata = std::env::var("APPDATA").context("APPDATA env var not set")?;
    let db_path = PathBuf::from(appdata).join("MeVault").join("audit.db");
    if let Ok(audit) = AuditLog::open(&db_path).await {
        let _ = audit
            .write(
                AuditEvent::new(EventType::Allowed)
                    .secret(&name)
                    .vault(vault_name)
                    .reason("cli_reveal"),
            )
            .await;
    }

    Ok(())
}
