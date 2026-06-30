use anyhow::Context;
use mevault_core::{config::ProjectConfig, vault::SecretStoreBridge};
use secrecy::ExposeSecret;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::commands::add::prompt_vault_password;

pub fn run(name: String, from_file: Option<PathBuf>) -> ExitCode {
    match run_inner(name, from_file) {
        Ok(matched) => {
            if matched {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run_inner(name: String, from_file: Option<PathBuf>) -> anyhow::Result<bool> {
    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cfg = ProjectConfig::load(&project_root)
        .context("no mevault.toml found — run `mevault init` first")?;
    let vault_name = &cfg.project.vault_name;

    let vault_pw = prompt_vault_password()?;

    let bridge = SecretStoreBridge::new();
    let secret = bridge
        .get_secret(&name, vault_name, Some(&vault_pw))
        .with_context(|| format!("retrieving secret '{name}' from vault '{vault_name}'"))?;

    let stored: Zeroizing<Vec<u8>> = Zeroizing::new(secret.expose_secret().as_bytes().to_vec());

    let expected: Zeroizing<Vec<u8>> = if let Some(file_path) = from_file {
        read_file_zeroizing(&file_path)
            .with_context(|| format!("reading file '{}'", file_path.display()))?
    } else {
        let raw =
            rpassword::prompt_password("Expected value: ").context("reading expected value")?;
        Zeroizing::new(raw.into_bytes())
    };

    // Constant-time comparison to avoid timing side-channels.
    let matched = stored.ct_eq(&expected).into();

    if matched {
        println!("\u{2713} {name} matches");
    } else {
        println!("\u{2717} {name} does not match");
    }

    Ok(matched)
}

fn read_file_zeroizing(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading '{}'", path.display()))?;
    // Strip a single trailing newline (LF or CRLF) so that files created with
    // a text editor compare correctly against values that were stored without
    // a trailing newline.
    let trimmed = if bytes.ends_with(b"\r\n") {
        bytes[..bytes.len() - 2].to_vec()
    } else if bytes.ends_with(b"\n") {
        bytes[..bytes.len() - 1].to_vec()
    } else {
        bytes
    };
    Ok(Zeroizing::new(trimmed))
}
