use anyhow::{Context, Result};
use std::io::BufRead as _;
use std::path::Path;

use mevault_core::config::{ProcessRule, ProjectConfig};

use crate::ConfigAction;

pub async fn run(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Validate => validate(),
        ConfigAction::Migrate => migrate(),
    }
}

fn validate() -> Result<()> {
    let root = std::env::current_dir().context("cannot determine current directory")?;

    // Loading the config already catches TOML parse errors.
    let cfg = ProjectConfig::load(&root).context("loading mevault.toml")?;

    let mut errors: Vec<String> = vec![];

    // Validate process rules.
    for (i, rule) in cfg.process_rules.iter().enumerate() {
        if rule.name.is_empty() {
            errors.push(format!("process rule #{}: name is required", i + 1));
        }
        if rule.executable.is_empty() {
            errors.push(format!(
                "process rule '{}': executable is required",
                rule.name
            ));
        }
        if rule.secrets.is_empty() {
            errors.push(format!(
                "process rule '{}': secrets list is empty — process will have no access",
                rule.name
            ));
        }
        // Wildcard without allow_all_secrets is a misconfiguration.
        if rule.secrets.iter().any(|s| s == "*") && !rule.allow_all_secrets {
            errors.push(format!(
                "process rule '{}': secrets = [\"*\"] requires allow_all_secrets = true \
                 (explicit opt-in for wildcard access)",
                rule.name
            ));
        }
        // Check whether the resolved executable exists (skip glob/variable patterns).
        let resolved_exe = rule
            .executable
            .replace("${PROJECT_ROOT}", &root.to_string_lossy());
        if !resolved_exe.contains('*') && !resolved_exe.contains("${") {
            let exe_path = Path::new(&resolved_exe);
            if !exe_path.exists() {
                errors.push(format!(
                    "process rule '{}': executable not found: {}",
                    rule.name, resolved_exe
                ));
            }
        }
    }

    // Validate allow-list rules.
    for (i, rule) in cfg.allow_list.rules.iter().enumerate() {
        if rule.name.is_empty() {
            errors.push(format!("allow-list rule #{}: name is required", i + 1));
        }
        if rule.secrets.is_empty() {
            errors.push(format!(
                "allow-list rule '{}': secrets list is empty",
                rule.name
            ));
        }
    }

    if errors.is_empty() {
        println!("mevault.toml is valid");
        println!("  Vault: {}", cfg.project.vault_name);
        println!("  Process rules: {}", cfg.process_rules.len());
        println!("  Allow-list rules: {}", cfg.allow_list.rules.len());
        Ok(())
    } else {
        for e in &errors {
            eprintln!("  {e}");
        }
        anyhow::bail!("{} validation error(s) in mevault.toml", errors.len())
    }
}

fn migrate() -> Result<()> {
    let root = std::env::current_dir().context("cannot determine current directory")?;
    let cfg = ProjectConfig::load(&root).context("loading mevault.toml")?;

    if cfg.allow_list.rules.is_empty() {
        println!("No allow-list rules to migrate.");
        return Ok(());
    }

    // Back up original.
    let toml_path = root.join("mevault.toml");
    let backup_path = root.join("mevault.toml.bak");
    std::fs::copy(&toml_path, &backup_path).context("creating backup mevault.toml.bak")?;
    println!("Backup saved to mevault.toml.bak");

    let stdin = std::io::stdin();
    let mut new_rules: Vec<ProcessRule> = vec![];
    let mut skipped = 0usize;

    for rule in &cfg.allow_list.rules {
        let has_wildcard = rule.secrets.iter().any(|s| s == "*");

        // Ask confirmation for wildcard rules.
        let allow_all = if has_wildcard {
            eprint!(
                "Rule '{}' has wildcard secret access (*). Allow all secrets? [y/N]: ",
                rule.name
            );
            let mut line = String::new();
            stdin.lock().read_line(&mut line).ok();
            if line.trim().eq_ignore_ascii_case("y") {
                true
            } else {
                println!("Skipping rule '{}' (wildcard not confirmed)", rule.name);
                skipped += 1;
                continue;
            }
        } else {
            false
        };

        let process_rule = ProcessRule {
            name: rule.name.clone(),
            executable: rule.exe_path.clone(),
            working_dir: rule.working_dir.clone(),
            command: vec![],
            launch_only: true, // conservative default
            signed: rule.signed,
            secrets: rule.secrets.clone(),
            allow_all_secrets: allow_all,
        };
        new_rules.push(process_rule);
    }

    println!(
        "Converting {} rule(s) ({} skipped)...",
        new_rules.len(),
        skipped
    );

    // Migration is additive — original allow_list is preserved so the user can
    // verify the new [[process]] rules before removing the legacy ones.
    let mut new_cfg = cfg.clone();
    new_cfg.process_rules = new_rules;
    new_cfg.save(&root).context("saving updated mevault.toml")?;

    println!("Migration complete. Review mevault.toml and run `mevault config validate`.");
    println!(
        "  The original allow-list rules were preserved — remove them manually once verified."
    );
    println!("  Backup: {}", backup_path.display());

    Ok(())
}
