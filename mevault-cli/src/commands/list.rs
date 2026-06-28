use anyhow::{Context, Result};
use mevault_core::{config::ProjectConfig, vault::SecretStoreBridge};
use std::path::PathBuf;

pub fn run(vault: Option<String>) -> Result<()> {
    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let vault_name = if let Some(v) = vault {
        v
    } else {
        ProjectConfig::load(&project_root)
            .context("no mevault.toml found — run `mevault init` first")?
            .project
            .vault_name
    };

    let bridge = SecretStoreBridge::new();

    // Try listing without the password first — Get-SecretInfo may work while locked.
    // If the vault is locked (Interaction=None), fall back to prompting for the password.
    let secrets = match bridge.list_secrets(&vault_name, None) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Vault is locked. Enter your vault password to list secrets.");
            let password = crate::commands::add::prompt_vault_password()?;
            bridge
                .list_secrets(&vault_name, Some(&password))
                .with_context(|| format!("listing secrets in vault '{vault_name}'"))?
        }
    };

    if secrets.is_empty() {
        println!("No secrets in vault '{vault_name}'.");
        println!("Add one with: mevault add <NAME>");
        return Ok(());
    }

    println!("Vault: {vault_name}");
    println!("{:<40} {}", "NAME", "TYPE");
    println!("{}", "-".repeat(50));
    for s in &secrets {
        println!("{:<40} {}", s.name, s.kind);
    }
    println!("\n{} secret(s) — values never shown here.", secrets.len());

    Ok(())
}
