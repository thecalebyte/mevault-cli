use anyhow::{Context, Result};
use mevault_core::{
    audit::{AuditEvent, AuditLog, EventType},
    config::ProjectConfig,
    export::import_auto,
    vault::SecretStoreBridge,
};
use secrecy::SecretString;
use std::path::PathBuf;

use crate::commands::add::prompt_vault_password;

pub async fn run(file: PathBuf, vault_override: Option<String>) -> Result<()> {
    if !file.exists() {
        anyhow::bail!("File not found: {}", file.display());
    }

    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cfg = ProjectConfig::load(&project_root)
        .context("no mevault.toml found — run `mevault init` first")?;
    let vault_name = vault_override.as_deref().unwrap_or(&cfg.project.vault_name);

    // Determine whether we need a decryption password for the file.
    let file_name = file.to_string_lossy().to_lowercase();
    let needs_file_pw = file_name.ends_with(".env.mvenc") || file_name.ends_with(".mvx");
    let file_pw: Option<SecretString> = if needs_file_pw {
        let pw = rpassword::prompt_password("File decryption password: ")
            .context("reading file password")?;
        Some(SecretString::new(pw.into()))
    } else {
        None
    };

    let entries = import_auto(&file, file_pw.as_ref()).context("reading import file")?;

    if entries.is_empty() {
        println!("No secrets found in {}.", file.display());
        return Ok(());
    }

    println!(
        "Found {} secret(s) in {}. Importing into vault '{}'…",
        entries.len(),
        file.display(),
        vault_name
    );

    println!("Enter vault password to store secrets:");
    let vault_pw = prompt_vault_password()?;

    let bridge = SecretStoreBridge::new();
    let appdata = std::env::var("APPDATA").context("APPDATA env var not set")?;
    let db_path = PathBuf::from(appdata).join("MeVault").join("audit.db");
    let audit = AuditLog::open(&db_path).await.context("opening audit log")?;

    let mut count = 0usize;
    for entry in &entries {
        bridge
            .set_secret(
                &entry.name,
                &SecretString::new(entry.value.clone().into()),
                vault_name,
                Some(&vault_pw),
            )
            .with_context(|| format!("storing '{}'", entry.name))?;

        audit
            .write(
                AuditEvent::new(EventType::SecretAdded)
                    .secret(&entry.name)
                    .vault(vault_name),
            )
            .await?;

        count += 1;
    }

    println!("Imported {count} secret(s) into vault '{vault_name}'.");
    Ok(())
}
