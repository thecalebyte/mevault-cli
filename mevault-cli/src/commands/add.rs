use anyhow::{bail, Context, Result};
use mevault_core::{
    audit::{AuditEvent, AuditLog, EventType},
    config::ProjectConfig,
    vault::SecretStoreBridge,
};
use secrecy::SecretString;
use std::path::PathBuf;

pub async fn run(
    name: Option<String>,
    from_env: Option<PathBuf>,
    generate: bool,
) -> Result<()> {
    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cfg = ProjectConfig::load(&project_root)
        .context("no mevault.toml found — run `mevault init` first")?;

    let password = prompt_vault_password()?;

    let audit = open_audit().await?;
    let bridge = SecretStoreBridge::new();

    if let Some(env_path) = from_env {
        import_from_dotenv(&env_path, &cfg.project.vault_name, &bridge, Some(&password), &audit)
            .await?;
        return Ok(());
    }

    let secret_name = match name {
        Some(n) => n,
        None => {
            eprint!("Secret name: ");
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf)?;
            buf.trim().to_owned()
        }
    };

    if secret_name.is_empty() {
        bail!("Secret name cannot be empty");
    }

    let value = if generate {
        let v = generate_secret();
        eprintln!("Generated secret for '{secret_name}' (value not shown)");
        v
    } else {
        SecretString::new(
            rpassword::prompt_password(format!("Value for '{secret_name}': "))
                .context("reading secret value")?
                .into(),
        )
    };

    bridge
        .set_secret(&secret_name, &value, &cfg.project.vault_name, Some(&password))
        .with_context(|| format!("storing '{secret_name}'"))?;

    audit
        .write(
            AuditEvent::new(EventType::SecretAdded)
                .secret(&secret_name)
                .vault(&cfg.project.vault_name),
        )
        .await?;

    println!("Secret '{secret_name}' added to vault '{}'.", cfg.project.vault_name);
    Ok(())
}

async fn import_from_dotenv(
    path: &PathBuf,
    vault_name: &str,
    bridge: &SecretStoreBridge,
    password: Option<&SecretString>,
    audit: &AuditLog,
) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    // Collect all entries first so we only prompt for the vault password once.
    let entries: Vec<(String, String)> = content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, val) = line.split_once('=')?;
            let key = key.trim().to_owned();
            // Strip optional surrounding quotes from the value.
            let val = val.trim().trim_matches('"').trim_matches('\'').to_owned();
            Some((key, val))
        })
        .collect();

    if entries.is_empty() {
        println!("No key=value entries found in {}.", path.display());
        return Ok(());
    }

    // Use the password only on the first call; SecretStore remains unlocked
    // for its PasswordTimeout window (default 15 min) so subsequent calls don't need it.
    let mut first = true;
    let mut count = 0usize;
    for (key, val) in &entries {
        let pw = if first { password } else { None };
        bridge
            .set_secret(key, &SecretString::new(val.clone().into()), vault_name, pw)
            .with_context(|| format!("storing '{key}'"))?;
        audit
            .write(
                AuditEvent::new(EventType::SecretAdded)
                    .secret(key)
                    .vault(vault_name),
            )
            .await?;
        first = false;
        count += 1;
    }

    println!(
        "Imported {count} secret(s) from {} into vault '{vault_name}'.",
        path.display()
    );
    Ok(())
}

fn generate_secret() -> SecretString {
    use rand::Rng;
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();
    let s: String = (0..40)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect();
    SecretString::new(s.into())
}

pub fn prompt_vault_password() -> Result<SecretString> {
    let pw = rpassword::prompt_password("Vault password: ").context("reading vault password")?;
    if pw.is_empty() {
        bail!("Password cannot be empty");
    }
    Ok(SecretString::new(pw.into()))
}

async fn open_audit() -> Result<AuditLog> {
    let appdata = std::env::var("APPDATA").context("APPDATA env var not set")?;
    let db_path = PathBuf::from(appdata).join("MeVault").join("audit.db");
    AuditLog::open(&db_path).await
}
