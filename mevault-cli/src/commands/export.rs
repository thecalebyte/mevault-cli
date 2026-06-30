use anyhow::{bail, Context, Result};
use mevault_core::{
    config::ProjectConfig,
    export::{export_encrypted_env, export_mvx, SecretEntry},
    vault::SecretStoreBridge,
};
use secrecy::SecretString;
use std::path::PathBuf;

use crate::commands::add::prompt_vault_password;

pub async fn run(
    format: &str,
    output: Option<PathBuf>,
    vault_override: Option<String>,
) -> Result<()> {
    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cfg = ProjectConfig::load(&project_root)
        .context("no mevault.toml found — run `mevault init` first")?;

    let vault_name = vault_override.as_deref().unwrap_or(&cfg.project.vault_name);

    let default_ext = match format {
        "mvx" => ".mvx",
        _ => ".env.mvenc",
    };
    let out_path = output.unwrap_or_else(|| PathBuf::from(format!("{vault_name}{default_ext}")));

    println!("Unlocking vault '{}' to read secrets…", vault_name);
    let password = prompt_vault_password()?;

    let bridge = SecretStoreBridge::new();
    let names = bridge
        .list_secrets(vault_name, Some(&password))
        .context("listing secrets")?;

    if names.is_empty() {
        println!("Vault '{}' has no secrets — nothing to export.", vault_name);
        return Ok(());
    }

    // Fetch each value.
    let mut entries: Vec<SecretEntry> = Vec::with_capacity(names.len());
    for meta in &names {
        let val = bridge
            .get_secret(&meta.name, vault_name, Some(&password))
            .with_context(|| format!("reading '{}'", meta.name))?;
        use secrecy::ExposeSecret;
        entries.push(SecretEntry {
            name: meta.name.clone(),
            value: val.expose_secret().to_owned(),
        });
    }

    let count = match format {
        "mvx" => {
            let enc_pw = prompt_export_password()?;
            export_mvx(&entries, &out_path, vault_name, &enc_pw).context("exporting mvx bundle")?
        }
        _ => {
            let enc_pw = prompt_export_password()?;
            export_encrypted_env(&entries, &out_path, vault_name, &enc_pw)
                .context("exporting encrypted env")?
        }
    };

    println!("Exported {count} secret(s) to {}.", out_path.display());

    // Suggest adding to .gitignore if this looks like a git repo.
    if project_root.join(".git").exists() {
        let gitignore = project_root.join(".gitignore");
        let file_name = out_path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        if file_name.ends_with(".env") || file_name.ends_with(".env.mvenc") {
            let existing = std::fs::read_to_string(&gitignore).unwrap_or_default();
            if !existing.contains(file_name) {
                let mut content = existing;
                if !content.ends_with('\n') && !content.is_empty() {
                    content.push('\n');
                }
                content.push_str(file_name);
                content.push('\n');
                let _ = std::fs::write(&gitignore, content);
                eprintln!("Added '{}' to .gitignore.", file_name);
            }
        }
    }

    Ok(())
}

fn prompt_export_password() -> Result<SecretString> {
    let pw = rpassword::prompt_password("Encryption password (for export): ")
        .context("reading export password")?;
    if pw.len() < 8 {
        bail!("Encryption password must be at least 8 characters");
    }
    let confirm = rpassword::prompt_password("Confirm password: ")
        .context("reading export password confirmation")?;
    if pw != confirm {
        bail!("Passwords do not match");
    }
    Ok(SecretString::new(pw))
}
