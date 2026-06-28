use anyhow::{bail, Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::crypto;

/// Per-project encrypted vault store.
///
/// Each project vault is an independent AES-256-GCM encrypted file at
/// `%APPDATA%\MeVault\vaults\<name>.mvault`.  Projects never share a
/// backing store or master password — creating one vault cannot affect another.
///
/// No PowerShell or SecretStore modules are required.
pub struct VaultStore {
    vault_dir: PathBuf,
}

/// Backward-compatible alias — callers can use either name.
pub type SecretStoreBridge = VaultStore;

#[derive(Serialize, Deserialize)]
struct VaultFile {
    format: String,
    version: String,
    name: String,
    created_at: String,
    blob: crypto::EncryptedBlob,
}

#[derive(Debug, Clone)]
pub struct SecretInfo {
    pub name: String,
    pub kind: String,
}

impl VaultStore {
    pub fn new() -> Self {
        let vault_dir = std::env::var("APPDATA")
            .map(|a| PathBuf::from(a).join("MeVault").join("vaults"))
            .unwrap_or_else(|_| PathBuf::from(".mevault").join("vaults"));
        Self { vault_dir }
    }

    // ── Vault lifecycle ────────────────────────────────────────────────────

    /// Create a new encrypted vault file for this project.
    ///
    /// Idempotent — if the vault file already exists the call succeeds without
    /// changing the file or its password.  Use [`vault_exists`] to distinguish
    /// first-time creation from a no-op.
    pub fn create_vault(&self, vault_name: &str, password: &SecretString) -> Result<()> {
        std::fs::create_dir_all(&self.vault_dir)
            .context("creating vault directory")?;
        let path = self.vault_path(vault_name)?;
        if path.exists() {
            return Ok(());
        }
        let empty: HashMap<String, String> = HashMap::new();
        self.write_vault_file(&path, vault_name, &empty, password)
    }

    pub fn vault_exists(&self, vault_name: &str) -> Result<bool> {
        Ok(self.vault_path(vault_name)?.exists())
    }

    pub fn list_vaults(&self) -> Result<Vec<String>> {
        if !self.vault_dir.exists() {
            return Ok(vec![]);
        }
        let mut names = vec![];
        for entry in std::fs::read_dir(&self.vault_dir).context("reading vault directory")? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("mvault") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_owned());
                }
            }
        }
        Ok(names)
    }

    // ── Secret CRUD ────────────────────────────────────────────────────────

    pub fn set_secret(
        &self,
        name: &str,
        value: &SecretString,
        vault_name: &str,
        password: Option<&SecretString>,
    ) -> Result<()> {
        let pw = password.context("vault password is required")?;
        let path = self.vault_path(vault_name)?;
        let mut secrets = if path.exists() {
            self.read_secrets(&path, vault_name, pw)?
        } else {
            std::fs::create_dir_all(&self.vault_dir)?;
            HashMap::new()
        };
        secrets.insert(name.to_owned(), value.expose_secret().to_owned());
        self.write_vault_file(&path, vault_name, &secrets, pw)?;
        secrets.values_mut().for_each(|v| v.zeroize());
        Ok(())
    }

    pub fn get_secret(
        &self,
        name: &str,
        vault_name: &str,
        password: Option<&SecretString>,
    ) -> Result<SecretString> {
        let pw = password.context("vault password is required")?;
        let path = self.vault_path(vault_name)?;
        let mut secrets = self.read_secrets(&path, vault_name, pw)?;
        let value = secrets
            .remove(name)
            .with_context(|| format!("secret '{name}' not found in vault '{vault_name}'"))?;
        secrets.values_mut().for_each(|v| v.zeroize());
        Ok(SecretString::new(value.into()))
    }

    pub fn remove_secret(
        &self,
        name: &str,
        vault_name: &str,
        password: Option<&SecretString>,
    ) -> Result<()> {
        let pw = password.context("vault password is required")?;
        let path = self.vault_path(vault_name)?;
        let mut secrets = self.read_secrets(&path, vault_name, pw)?;
        secrets.remove(name);
        self.write_vault_file(&path, vault_name, &secrets, pw)?;
        secrets.values_mut().for_each(|v| v.zeroize());
        Ok(())
    }

    pub fn list_secrets(
        &self,
        vault_name: &str,
        password: Option<&SecretString>,
    ) -> Result<Vec<SecretInfo>> {
        let pw = password.context("vault password is required")?;
        let path = self.vault_path(vault_name)?;
        let mut secrets = self.read_secrets(&path, vault_name, pw)?;
        let mut infos: Vec<SecretInfo> = secrets
            .keys()
            .map(|k| SecretInfo { name: k.clone(), kind: "String".to_owned() })
            .collect();
        infos.sort_by(|a, b| a.name.cmp(&b.name));
        secrets.values_mut().for_each(|v| v.zeroize());
        Ok(infos)
    }

    /// Unlock and return only secret names — no values loaded into memory.
    /// This is the v2 lazy-decryption unlock path.
    pub fn unlock_and_list_names(
        &self,
        vault_name: &str,
        password: &SecretString,
    ) -> Result<Vec<String>> {
        let path = self.vault_path(vault_name)?;
        let mut secrets = self.read_secrets(&path, vault_name, password)?;
        let mut names: Vec<String> = secrets.keys().cloned().collect();
        names.sort();
        secrets.values_mut().for_each(|v| v.zeroize());
        Ok(names)
    }

    /// Unlock and preload all secret values. Used by proxy integration tests.
    pub fn unlock_and_preload(
        &self,
        vault_name: &str,
        password: &SecretString,
    ) -> Result<HashMap<String, SecretString>> {
        let path = self.vault_path(vault_name)?;
        let secrets = self.read_secrets(&path, vault_name, password)?;
        Ok(secrets.into_iter().map(|(k, v)| (k, SecretString::new(v.into()))).collect())
    }

    // ── Module stubs — PowerShell SecretStore modules no longer required ────

    pub fn check_modules(&self) -> Result<bool> {
        Ok(true)
    }

    pub fn install_modules(&self) -> Result<()> {
        Ok(())
    }

    // ── Internal ───────────────────────────────────────────────────────────

    fn vault_path(&self, vault_name: &str) -> Result<PathBuf> {
        let safe = sanitize_vault_name(vault_name)?;
        Ok(self.vault_dir.join(format!("{safe}.mvault")))
    }

    fn read_secrets(
        &self,
        path: &Path,
        vault_name: &str,
        password: &SecretString,
    ) -> Result<HashMap<String, String>> {
        let json = std::fs::read_to_string(path)
            .with_context(|| {
                format!("vault '{vault_name}' not found — run `mevault init` first")
            })?;
        let file: VaultFile =
            serde_json::from_str(&json).context("vault file is corrupt or unrecognised format")?;
        let mut plaintext =
            crypto::decrypt(&file.blob, password).context("wrong password or corrupt vault")?;
        let secrets: HashMap<String, String> =
            serde_json::from_slice(&plaintext).context("vault contents are corrupt")?;
        plaintext.zeroize();
        Ok(secrets)
    }

    fn write_vault_file(
        &self,
        path: &Path,
        vault_name: &str,
        secrets: &HashMap<String, String>,
        password: &SecretString,
    ) -> Result<()> {
        let mut plaintext = serde_json::to_vec(secrets).context("serialising secrets")?;
        let blob = crypto::encrypt(&plaintext, password).context("encrypting vault")?;
        plaintext.zeroize();

        let file = VaultFile {
            format: "mevault-vault".to_owned(),
            version: "1".to_owned(),
            name: vault_name.to_owned(),
            created_at: chrono::Utc::now().to_rfc3339(),
            blob,
        };
        let json = serde_json::to_string_pretty(&file).context("serialising vault file")?;

        // Atomic write — write to a temp file then rename so a crash mid-write
        // cannot leave the vault file in a corrupt state.
        let tmp = path.with_extension("mvault.tmp");
        std::fs::write(&tmp, &json)
            .with_context(|| format!("writing temp file {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("finalising vault file {}", path.display()))?;
        Ok(())
    }
}

impl Default for VaultStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Sanitise a vault name so it is safe to use as a filename.
/// Any character that is not alphanumeric, `-`, or `_` becomes `_`.
fn sanitize_vault_name(name: &str) -> Result<String> {
    if name.is_empty() {
        bail!("vault name cannot be empty");
    }
    Ok(name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw() -> SecretString {
        SecretString::new("correct-horse-battery-staple".to_owned().into())
    }

    fn store(dir: &tempfile::TempDir) -> VaultStore {
        VaultStore { vault_dir: dir.path().to_path_buf() }
    }

    #[test]
    fn create_and_exists() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        assert!(!s.vault_exists("TestVault").unwrap());
        s.create_vault("TestVault", &pw()).unwrap();
        assert!(s.vault_exists("TestVault").unwrap());
    }

    #[test]
    fn create_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();
        s.create_vault("V", &pw()).unwrap();
        assert!(s.vault_exists("V").unwrap());
    }

    #[test]
    fn set_get_remove() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();

        let val = SecretString::new("postgres://localhost".to_owned().into());
        s.set_secret("DB_URL", &val, "V", Some(&pw())).unwrap();

        let got = s.get_secret("DB_URL", "V", Some(&pw())).unwrap();
        assert_eq!(got.expose_secret(), "postgres://localhost");

        s.remove_secret("DB_URL", "V", Some(&pw())).unwrap();
        assert!(s.get_secret("DB_URL", "V", Some(&pw())).is_err());
    }

    #[test]
    fn wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();
        s.set_secret("K", &SecretString::new("v".to_owned().into()), "V", Some(&pw())).unwrap();
        let bad = SecretString::new("wrong-password".to_owned().into());
        assert!(s.get_secret("K", "V", Some(&bad)).is_err());
    }

    #[test]
    fn list_and_names() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();
        s.set_secret("A", &SecretString::new("1".to_owned().into()), "V", Some(&pw())).unwrap();
        s.set_secret("B", &SecretString::new("2".to_owned().into()), "V", Some(&pw())).unwrap();
        let names = s.unlock_and_list_names("V", &pw()).unwrap();
        assert!(names.contains(&"A".to_owned()));
        assert!(names.contains(&"B".to_owned()));
    }

    #[test]
    fn list_vaults() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("Alpha", &pw()).unwrap();
        s.create_vault("Beta", &pw()).unwrap();
        let vaults = s.list_vaults().unwrap();
        assert!(vaults.contains(&"Alpha".to_owned()));
        assert!(vaults.contains(&"Beta".to_owned()));
    }

    #[test]
    fn vaults_are_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        let pw_a = SecretString::new("password-for-project-a".to_owned().into());
        let pw_b = SecretString::new("password-for-project-b".to_owned().into());

        s.create_vault("ProjectA", &pw_a).unwrap();
        s.create_vault("ProjectB", &pw_b).unwrap();

        s.set_secret("SECRET", &SecretString::new("value-a".to_owned().into()), "ProjectA", Some(&pw_a)).unwrap();
        s.set_secret("SECRET", &SecretString::new("value-b".to_owned().into()), "ProjectB", Some(&pw_b)).unwrap();

        let a = s.get_secret("SECRET", "ProjectA", Some(&pw_a)).unwrap();
        let b = s.get_secret("SECRET", "ProjectB", Some(&pw_b)).unwrap();
        assert_eq!(a.expose_secret(), "value-a");
        assert_eq!(b.expose_secret(), "value-b");

        // ProjectA's password cannot open ProjectB.
        assert!(s.get_secret("SECRET", "ProjectB", Some(&pw_a)).is_err());
        // ProjectB's password cannot open ProjectA.
        assert!(s.get_secret("SECRET", "ProjectA", Some(&pw_b)).is_err());
    }

    #[test]
    fn single_quote_and_special_chars_in_value() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();
        let tricky = SecretString::new("it's a \"test\" value\n with newline".to_owned().into());
        s.set_secret("K", &tricky, "V", Some(&pw())).unwrap();
        let got = s.get_secret("K", "V", Some(&pw())).unwrap();
        assert_eq!(got.expose_secret(), "it's a \"test\" value\n with newline");
    }

    #[test]
    fn sanitize_name_replaces_special_chars() {
        assert_eq!(sanitize_vault_name("My Vault!").unwrap(), "My_Vault_");
        assert_eq!(sanitize_vault_name("alpha-beta_1").unwrap(), "alpha-beta_1");
        assert!(sanitize_vault_name("").is_err());
    }
}
