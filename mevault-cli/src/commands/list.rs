use anyhow::{Context, Result};
use mevault_core::{config::ProjectConfig, ipc::RUNTIME_PIPE, vault::SecretStoreBridge};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ClientOptions;

pub async fn run(vault: Option<String>) -> Result<()> {
    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let vault_name = if let Some(v) = vault {
        v
    } else {
        ProjectConfig::load(&project_root)
            .context("no mevault.toml found — run `mevault init` first")?
            .project
            .vault_name
    };

    // First, try to get names via an active IPC session (no password needed).
    if let Ok(names) = try_ipc_list().await {
        print_list(&vault_name, &names);
        return Ok(());
    }

    // Fall back: prompt for password, unlock, list.
    let password = crate::commands::add::prompt_vault_password()?;
    let bridge = SecretStoreBridge::new();
    let secrets = bridge
        .list_secrets(&vault_name, Some(&password))
        .with_context(|| format!("listing secrets in vault '{vault_name}'"))?;

    if secrets.is_empty() {
        println!("No secrets in vault '{vault_name}'.");
        println!("Add one with: mevault add <NAME>");
        return Ok(());
    }

    let names: Vec<String> = secrets.into_iter().map(|s| s.name).collect();
    print_list(&vault_name, &names);
    Ok(())
}

fn print_list(vault_name: &str, names: &[String]) {
    println!("Vault: {vault_name}");
    println!("Secrets: {}", names.len());
    println!();
    for name in names {
        println!("\u{2713} {name}");
    }
    println!();
    println!("Values are encrypted. Use `mevault verify <NAME>` to validate one.");
}

/// Attempt to list secret names through the runtime named pipe.
/// Returns Ok(names) if the vault is unlocked and responds, Err otherwise.
async fn try_ipc_list() -> Result<Vec<String>> {
    let pipe = ClientOptions::new()
        .open(RUNTIME_PIPE)
        .context("connecting to runtime pipe")?;

    let (reader, mut writer) = tokio::io::split(pipe);
    let mut reader = BufReader::new(reader);

    // IpcRequest::ListSecrets wire format (tag = "op", rename_all = "snake_case")
    let encoded = "{\"op\":\"list_secrets\"}\n";
    writer
        .write_all(encoded.as_bytes())
        .await
        .context("sending IPC request to runtime pipe")?;

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("reading IPC response")?;

    let resp: serde_json::Value =
        serde_json::from_str(line.trim()).context("parsing IPC response")?;

    if resp["ok"].as_bool().unwrap_or(false) {
        if let Some(arr) = resp["names"].as_array() {
            let names: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
            return Ok(names);
        }
    }

    anyhow::bail!("vault_locked or no names in response")
}
