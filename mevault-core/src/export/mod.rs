use anyhow::{Context, Result};
use chrono::Utc;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::crypto::{self, CryptoPolicy};

// ── Types ──────────────────────────────────────────────────────────────────

/// A single secret name+value pair used in export/import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub name: String,
    pub value: String,
}

/// Encrypted MeVault bundle (.mvx).
#[derive(Debug, Serialize, Deserialize)]
pub struct MvxBundle {
    pub format: String,
    pub version: String,
    pub vault: String,
    pub exported_at: String,
    pub algorithm: String,
    pub kdf: String,
    pub kdf_params: KdfParams,
    #[serde(flatten)]
    pub blob: crypto::EncryptedBlob,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KdfParams {
    pub m: u32, // memory KiB
    pub t: u32, // iterations
    pub p: u32, // parallelism
}

// ── Export ──────────────────────────────────────────────────────────────────

/// Write plaintext `.env` file. Returns the number of secrets written.
pub fn export_dotenv(secrets: &[SecretEntry], path: &Path, vault_name: &str) -> Result<usize> {
    let mut lines = vec![
        format!("# MeVault Export — {vault_name}"),
        format!("# Exported: {}", Utc::now().to_rfc3339()),
        "# WARNING: This file contains plaintext secrets. Store securely.".into(),
        String::new(),
    ];
    for s in secrets {
        // Quote values that contain spaces or special characters.
        let safe_val = shell_quote(&s.value);
        lines.push(format!("{}={}", s.name, safe_val));
    }
    std::fs::write(path, lines.join("\n") + "\n")
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(secrets.len())
}

/// Write AES-256-GCM encrypted `.env.mvenc` file.
pub fn export_encrypted_env(
    secrets: &[SecretEntry],
    path: &Path,
    vault_name: &str,
    password: &SecretString,
) -> Result<usize> {
    // Build the plaintext in .env format first.
    let mut lines = vec![
        format!("# MeVault Export — {vault_name}"),
        format!("# Exported: {}", Utc::now().to_rfc3339()),
        String::new(),
    ];
    for s in secrets {
        lines.push(format!("{}={}", s.name, s.value));
    }
    let plaintext = (lines.join("\n") + "\n").into_bytes();

    let blob = crypto::encrypt(
        &plaintext,
        password,
        b"mevault-env-enc",
        &CryptoPolicy::production(),
    )
    .context("encrypting export")?;
    let json = serde_json::to_string_pretty(&blob).context("serializing encrypted export")?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(secrets.len())
}

/// Write encrypted MeVault bundle (`.mvx`).
pub fn export_mvx(
    secrets: &[SecretEntry],
    path: &Path,
    vault_name: &str,
    password: &SecretString,
) -> Result<usize> {
    let inner_json = serde_json::to_string(secrets).context("serializing secret list")?;
    let blob = crypto::encrypt(
        inner_json.as_bytes(),
        password,
        vault_name.as_bytes(),
        &CryptoPolicy::production(),
    )
    .context("encrypting mvx")?;

    let bundle = MvxBundle {
        format: "mevault-export".into(),
        version: "1".into(),
        vault: vault_name.to_owned(),
        exported_at: Utc::now().to_rfc3339(),
        algorithm: "AES-256-GCM".into(),
        kdf: "argon2id".into(),
        kdf_params: KdfParams {
            m: 65_536,
            t: 3,
            p: 4,
        },
        blob,
    };

    let json = serde_json::to_string_pretty(&bundle).context("serializing mvx")?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(secrets.len())
}

// ── Import ──────────────────────────────────────────────────────────────────

/// Parse a plaintext `.env` file into entries.
pub fn import_dotenv(path: &Path) -> Result<Vec<SecretEntry>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(parse_env_lines(&content))
}

/// Decrypt and parse a `.env.mvenc` file.
pub fn import_encrypted_env(path: &Path, password: &SecretString) -> Result<Vec<SecretEntry>> {
    let json =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let blob: crypto::EncryptedBlob =
        serde_json::from_str(&json).context("parsing encrypted env file")?;
    let plaintext = crypto::decrypt(
        &blob,
        password,
        b"mevault-env-enc",
        &CryptoPolicy::production(),
    )
    .context("decrypting env file")?;
    let text = std::str::from_utf8(&plaintext)
        .context("decrypted content is not UTF-8")?
        .to_owned();
    Ok(parse_env_lines(&text))
}

/// Decrypt and parse a `.mvx` bundle.
pub fn import_mvx(path: &Path, password: &SecretString) -> Result<(String, Vec<SecretEntry>)> {
    let json =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let bundle: MvxBundle = serde_json::from_str(&json).context("parsing mvx file")?;
    let plaintext = crypto::decrypt(
        &bundle.blob,
        password,
        bundle.vault.as_bytes(),
        &CryptoPolicy::production(),
    )
    .context("decrypting mvx")?;
    let entries: Vec<SecretEntry> =
        serde_json::from_slice(&plaintext).context("parsing decrypted secret list")?;
    Ok((bundle.vault, entries))
}

/// Auto-detect format by extension and import.
pub fn import_auto(path: &Path, password: Option<&SecretString>) -> Result<Vec<SecretEntry>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    if name.ends_with(".env.mvenc") {
        let pw = password.context("password required for .env.mvenc files")?;
        import_encrypted_env(path, pw)
    } else if ext == "mvx" {
        let pw = password.context("password required for .mvx files")?;
        let (_vault, entries) = import_mvx(path, pw)?;
        Ok(entries)
    } else {
        // .env or any plain text
        import_dotenv(path)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn parse_env_lines(text: &str) -> Vec<SecretEntry> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, val) = line.split_once('=')?;
            let key = key.trim().to_owned();
            let val = val.trim().trim_matches('"').trim_matches('\'').to_owned();
            if key.is_empty() {
                return None;
            }
            Some(SecretEntry {
                name: key,
                value: val,
            })
        })
        .collect()
}

/// Minimal shell quoting — wrap in single quotes if value has spaces/special chars.
fn shell_quote(val: &str) -> String {
    if val
        .chars()
        .any(|c| matches!(c, ' ' | '\t' | '"' | '\'' | '$' | '\\' | '`' | '!'))
    {
        // Escape any single quotes inside, then wrap.
        format!("'{}'", val.replace('\'', r"'\''"))
    } else {
        val.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn entries() -> Vec<SecretEntry> {
        vec![
            SecretEntry {
                name: "DB_URL".into(),
                value: "postgres://localhost".into(),
            },
            SecretEntry {
                name: "API_KEY".into(),
                value: "sk-abc123".into(),
            },
        ]
    }

    fn pw() -> SecretString {
        SecretString::new("test-password-phrase-here".to_owned())
    }

    #[test]
    fn dotenv_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.env");
        let n = export_dotenv(&entries(), &path, "TestVault").unwrap();
        assert_eq!(n, 2);
        let parsed = import_dotenv(&path).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "DB_URL");
        assert_eq!(parsed[1].name, "API_KEY");
    }

    #[test]
    fn encrypted_env_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.env.mvenc");
        export_encrypted_env(&entries(), &path, "TestVault", &pw()).unwrap();
        let parsed = import_encrypted_env(&path, &pw()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].value, "postgres://localhost");
    }

    #[test]
    fn mvx_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.mvx");
        export_mvx(&entries(), &path, "TestVault", &pw()).unwrap();
        let (vault, parsed) = import_mvx(&path, &pw()).unwrap();
        assert_eq!(vault, "TestVault");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].name, "API_KEY");
    }

    #[test]
    fn wrong_password_fails_import() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.mvx");
        export_mvx(&entries(), &path, "V", &pw()).unwrap();
        let bad = SecretString::new("wrong".to_owned());
        assert!(import_mvx(&path, &bad).is_err());
    }
}
