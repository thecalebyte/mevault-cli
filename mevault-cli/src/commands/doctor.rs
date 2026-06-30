use anyhow::Result;
use mevault_core::{
    config::ProjectConfig,
    ipc::{self, ControlRequest, CONTROL_PIPE, RUNTIME_PIPE},
    vault::VaultStore,
};
use std::path::PathBuf;

const UPDATER_ENDPOINT: &str =
    "https://github.com/thecalebyte/mevault-cli/releases/latest/download/latest.json";

const SEPARATOR: &str = "══════════════════════════════════════════";

pub async fn run(command: Option<Vec<String>>) -> Result<()> {
    println!("MeVault Doctor");
    println!("{SEPARATOR}");
    println!();

    let cli_version = env!("CARGO_PKG_VERSION");

    // ── 1. Version header ─────────────────────────────────────────────────────
    println!("CLI Version:         {cli_version}");

    // Try to get the desktop app version via control pipe.
    let desktop_version = fetch_desktop_version().await;
    println!("Desktop Version:     {desktop_version}");
    println!();

    // ── 2. Project root and mevault.toml ─────────────────────────────────────
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config_path = cwd.join("mevault.toml");

    println!("Configuration");

    match ProjectConfig::load(&cwd) {
        Ok(cfg) => {
            let config_exists = config_path.exists();
            println!(
                "  Config path:       {} {}",
                config_path.display(),
                if config_exists { "✓" } else { "✗" }
            );
            println!("  Vault name:        {}", cfg.project.vault_name);

            // ── 3. Vault file existence ───────────────────────────────────────
            let store = VaultStore::new();
            let (vault_format, vault_exists) = match store.vault_diagnostic(&cfg.project.vault_name)
            {
                Ok(diag) => {
                    println!("  Vault format:      {} ✓", diag.format_version);
                    println!("  Vault exists:      ✓");
                    (diag.format_version, true)
                }
                Err(_) => {
                    println!("  Vault format:      unknown");
                    println!("  Vault exists:      ✗ (run `mevault init`)");
                    ("unknown".to_owned(), false)
                }
            };
            let _ = (vault_format, vault_exists);

            println!();

            // ── 4. Session status ─────────────────────────────────────────────
            println!("Session");
            match ipc::send_control(&ControlRequest::Status).await {
                Ok(resp) if resp.ok && resp.active.unwrap_or(false) => {
                    println!("  Status:            unlocked");
                    if let Some(vn) = &resp.vault_name {
                        println!("  Vault:             {vn}");
                    }
                }
                Ok(resp) if resp.ok => {
                    println!("  Status:            locked");
                    println!("  Hint:              run `mevault unlock` to start a session");
                }
                _ => {
                    println!("  Status:            inactive (broker not running)");
                }
            }
            println!();

            // ── 5. Broker pipes ───────────────────────────────────────────────
            println!("Broker");
            let control_ok = probe_pipe(CONTROL_PIPE);
            println!(
                "  Control pipe:      {} {}",
                CONTROL_PIPE,
                if control_ok {
                    "✓"
                } else {
                    "✗ (vault not unlocked)"
                }
            );
            let runtime_ok = probe_pipe(RUNTIME_PIPE);
            println!(
                "  Runtime pipe:      {} {}",
                RUNTIME_PIPE,
                if runtime_ok {
                    "✓"
                } else {
                    "✗ (vault not unlocked)"
                }
            );
            println!();

            // ── 6. Policy summary ─────────────────────────────────────────────
            println!("Policy");
            let allow_count = cfg.allow_list.rules.len();
            let process_count = cfg.process_rules.len();
            println!(
                "  Allow-list rules:  {} {}",
                allow_count,
                if allow_count > 0 {
                    "✓"
                } else {
                    "✗ (no rules defined)"
                }
            );
            println!(
                "  Process rules:     {} {}",
                process_count,
                if process_count > 0 { "✓" } else { "(none)" }
            );

            // Validate policy: all process rules must have non-empty executable and secrets.
            let policy_valid = validate_policy(&cfg);
            println!(
                "  Policy valid:      {}",
                if policy_valid {
                    "✓"
                } else {
                    "✗ (see warnings above)"
                }
            );
            println!();

            // ── 7. SDK detection ──────────────────────────────────────────────
            println!("SDK");
            let python_sdk = cwd.join("sdk").join("python");
            let python_found = python_sdk.exists()
                || cwd
                    .parent()
                    .map(|p| p.join("sdk").join("python").exists())
                    .unwrap_or(false)
                || locate_sdk_relative(&cwd, "sdk/python");
            println!(
                "  Python SDK:        {}",
                if python_found {
                    "found (sdk/python/)".to_owned()
                } else {
                    "not found".to_owned()
                }
            );

            let rust_sdk = locate_sdk_relative(&cwd, "crates/mevault-sdk");
            println!(
                "  Rust SDK:          {}",
                if rust_sdk {
                    "found (crates/mevault-sdk/)".to_owned()
                } else {
                    "not found".to_owned()
                }
            );
            println!();

            // ── 8. Updater endpoint ───────────────────────────────────────────
            println!("Updater");
            println!("  Endpoint:          {UPDATER_ENDPOINT}");
            match check_updater_endpoint(UPDATER_ENDPOINT).await {
                Ok(version) => {
                    println!("  Status:            reachable ✓ (latest: {version})");
                }
                Err(e) => {
                    println!("  Status:            unreachable ✗");
                    println!("  Error:             {e}");
                    println!(
                        "  Hint:              check that a published release with latest.json exists"
                    );
                }
            }
            println!();

            // ── 9. Launch simulation (--command) ─────────────────────────────
            if let Some(cmd_args) = &command {
                let program = cmd_args.first().map(|s| s.as_str()).unwrap_or("");
                let trailing = if cmd_args.len() > 1 {
                    &cmd_args[1..]
                } else {
                    &[]
                };
                let full_cmd = cmd_args.join(" ");
                println!("Launch simulation: {full_cmd}");
                println!();

                // Try to find a matching [[process]] rule.
                let matched = cfg.process_rules.iter().find(|r| {
                    let resolved = r.resolve_paths(&cwd);
                    std::path::Path::new(program).ends_with(&resolved.executable)
                        || resolved.executable.contains(program)
                        || program.ends_with(&resolved.executable)
                });

                match matched {
                    Some(rule) => {
                        let resolved = rule.resolve_paths(&cwd);

                        // Attempt to resolve the full executable path.
                        let resolved_exe = which_executable(&resolved.executable)
                            .unwrap_or_else(|| resolved.executable.clone());
                        println!("  Resolved executable:  {resolved_exe}");
                        println!("  Matching rule:        {}", rule.name);

                        // Working dir check.
                        if let Some(dir) = &resolved.working_dir {
                            let cwd_str = cwd.to_string_lossy();
                            let dir_match = cwd_str.as_ref() == dir.as_str()
                                || cwd_str.starts_with(dir.as_str());
                            println!(
                                "  Working directory:    {} {}",
                                dir,
                                if dir_match {
                                    "✓"
                                } else {
                                    "✗ (cwd mismatch)"
                                }
                            );
                        } else {
                            println!("  Working directory:    {} ✓", cwd.display());
                        }

                        let sig_required = rule.signed;
                        println!(
                            "  Signature:            {}",
                            if sig_required {
                                "required"
                            } else {
                                "not required"
                            }
                        );

                        println!("  Allowed secrets:      {}", rule.secrets.join(", "));

                        // Command args check.
                        let args_ok = if !rule.command.is_empty() {
                            let trailing_strs: Vec<&str> =
                                trailing.iter().map(|s| s.as_str()).collect();
                            let rule_strs: Vec<&str> =
                                rule.command.iter().map(|s| s.as_str()).collect();
                            trailing_strs.starts_with(&rule_strs)
                        } else {
                            true
                        };

                        if args_ok {
                            println!();
                            println!("  Result: WOULD BE ALLOWED ✓");
                        } else {
                            println!();
                            println!("  Result: WOULD BE DENIED ✗");
                            println!(
                                "  Reason: command arguments do not match rule '{}'",
                                rule.name
                            );
                        }
                    }
                    None => {
                        println!("  Result: WOULD BE DENIED ✗");
                        println!("  Reason: no [[process]] rule matches '{program}'");
                        println!(
                            "  Hint:   add a [[process]] entry to mevault.toml for this command"
                        );
                    }
                }
                println!();
            }
        }
        Err(e) => {
            println!("  Config path:       {} ✗", config_path.display());
            println!("  Error:             {e}");
            println!("  Hint:              run `mevault init` to initialise this directory");
            println!();

            // Still check session and pipes even without a config.
            println!("Session");
            match ipc::send_control(&ControlRequest::Status).await {
                Ok(resp) if resp.ok && resp.active.unwrap_or(false) => {
                    println!("  Status:            unlocked");
                }
                Ok(_) => {
                    println!("  Status:            locked");
                }
                Err(_) => {
                    println!("  Status:            inactive (broker not running)");
                }
            }
            println!();

            println!("Broker");
            let control_ok = probe_pipe(CONTROL_PIPE);
            println!(
                "  Control pipe:      {} {}",
                CONTROL_PIPE,
                if control_ok { "✓" } else { "✗" }
            );
            let runtime_ok = probe_pipe(RUNTIME_PIPE);
            println!(
                "  Runtime pipe:      {} {}",
                RUNTIME_PIPE,
                if runtime_ok { "✓" } else { "✗" }
            );
            println!();

            println!("Updater");
            println!("  Endpoint:          {UPDATER_ENDPOINT}");
            match check_updater_endpoint(UPDATER_ENDPOINT).await {
                Ok(version) => {
                    println!("  Status:            reachable ✓ (latest: {version})");
                }
                Err(e) => {
                    println!("  Status:            unreachable ✗");
                    println!("  Error:             {e}");
                }
            }
            println!();
        }
    }

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Try to open the named pipe to see if the broker is reachable.
/// Returns true if the pipe can be opened (even briefly).
fn probe_pipe(pipe_path: &str) -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe_path)
        .is_ok()
}

/// Attempt to get a desktop version string from the control pipe status.
async fn fetch_desktop_version() -> String {
    // The desktop app doesn't currently report a version via the control pipe.
    // If the control pipe is reachable, we know the app is running but can't
    // get its version without a dedicated command. Report what we know.
    match ipc::send_control(&ControlRequest::Status).await {
        Ok(resp) if resp.ok => "unknown (app running)".to_owned(),
        _ => "unknown (app not running)".to_owned(),
    }
}

/// Run a basic policy validation: check for obviously broken rules.
/// Returns true when no problems are detected.
fn validate_policy(cfg: &ProjectConfig) -> bool {
    let mut ok = true;

    for rule in &cfg.allow_list.rules {
        if rule.exe_path.is_empty() {
            eprintln!(
                "  Warning: allow-list rule '{}' has an empty exe_path",
                rule.name
            );
            ok = false;
        }
        if rule.secrets.is_empty() {
            eprintln!(
                "  Warning: allow-list rule '{}' has no secrets defined",
                rule.name
            );
            ok = false;
        }
    }

    for rule in &cfg.process_rules {
        if rule.executable.is_empty() {
            eprintln!(
                "  Warning: process rule '{}' has an empty executable",
                rule.name
            );
            ok = false;
        }
        if rule.secrets.is_empty() {
            eprintln!(
                "  Warning: process rule '{}' has no secrets defined",
                rule.name
            );
            ok = false;
        }
    }

    ok
}

/// Walk up from `cwd` looking for a sub-directory matching `rel_path`.
fn locate_sdk_relative(cwd: &std::path::Path, rel_path: &str) -> bool {
    let mut dir = Some(cwd);
    while let Some(d) = dir {
        if d.join(rel_path).exists() {
            return true;
        }
        dir = d.parent();
    }
    false
}

/// Try to find the absolute path of an executable by checking PATH.
/// Returns None if not found.
fn which_executable(name: &str) -> Option<String> {
    // Use the `where` command on Windows to locate the executable.
    let output = std::process::Command::new("where")
        .arg(name)
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let first_line = stdout.lines().next()?.trim().to_owned();
        if !first_line.is_empty() {
            return Some(first_line);
        }
    }
    None
}

async fn check_updater_endpoint(url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let resp = client.get(url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {status}");
    }
    let json: serde_json::Value = resp.json().await?;
    let version = json["version"]
        .as_str()
        .unwrap_or("unknown version")
        .to_owned();
    Ok(version)
}
