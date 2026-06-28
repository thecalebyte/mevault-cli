use anyhow::{bail, Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, CryptoPolicy};

// ── SecretMap ─────────────────────────────────────────────────────────────────
// RAII wrapper around HashMap<String, String> that zeroes all values on drop.

struct SecretMap(HashMap<String, String>);

impl SecretMap {
    fn into_secret_strings(mut self) -> HashMap<String, SecretString> {
        self.0.drain().map(|(k, v)| (k, SecretString::new(v.into()))).collect()
    }
}

impl std::ops::Deref for SecretMap {
    type Target = HashMap<String, String>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl std::ops::DerefMut for SecretMap {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl Drop for SecretMap {
    fn drop(&mut self) {
        for v in self.0.values_mut() { v.zeroize(); }
    }
}

// ── V1 vault file ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct VaultFile {
    format: String,
    version: String,
    name: String,
    created_at: String,
    #[serde(default)]
    updated_at: String,
    blob: crypto::EncryptedBlob,
}

// ── V2 vault file ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct KeyProtection {
    mem_kib: u32,
    iters: u32,
    para: u32,
    salt: String,
    nonce: String,
    wrapped_dek: String,
}

#[derive(Serialize, Deserialize)]
struct VaultFileV2 {
    format: String,
    version: String,
    vault_id: String,
    name: String,
    created_at: String,
    updated_at: String,
    key_protection: KeyProtection,
    payload_nonce: String,
    payload: String,
}

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecretInfo {
    pub name: String,
    pub kind: String,
}

/// An unlocked vault session holding a cached Data-Encryption Key.
///
/// All secret operations use the cached DEK — Argon2 is not run again after
/// the initial unlock. Dropping this struct zeroizes the DEK.
pub struct UnlockedVault {
    vault_dir: PathBuf,
    // Retained for future policy-based CRUD decisions (e.g., re-encrypt on policy upgrade).
    #[allow(dead_code)]
    policy: CryptoPolicy,
    vault_id: String,
    vault_name: String,
    dek: Zeroizing<[u8; 32]>,
}

impl UnlockedVault {
    pub fn vault_name(&self) -> &str { &self.vault_name }
    pub fn vault_id(&self) -> &str { &self.vault_id }

    pub fn get_secret(&self, name: &str) -> Result<SecretString> {
        let path = self.vault_path()?;
        let vf = self.read_v2(&path)?;
        let secrets = self.decrypt_payload(&vf)?;
        secrets.get(name)
            .map(|v| SecretString::new(v.clone().into()))
            .with_context(|| format!("secret '{name}' not found in vault '{}'", self.vault_name))
    }

    pub fn set_secret(&self, name: &str, value: &SecretString) -> Result<()> {
        self.with_lock(|| {
            let path = self.vault_path()?;
            let mut vf = self.read_v2(&path)?;
            let mut secrets = self.decrypt_payload(&vf)?;
            secrets.insert(name.to_owned(), value.expose_secret().to_owned());
            self.encrypt_and_write(&mut vf, &path, &secrets)
        })
    }

    pub fn set_secrets_bulk(&self, new_secrets: &HashMap<String, SecretString>) -> Result<()> {
        self.with_lock(|| {
            let path = self.vault_path()?;
            let mut vf = self.read_v2(&path)?;
            let mut secrets = self.decrypt_payload(&vf)?;
            for (k, v) in new_secrets {
                secrets.insert(k.clone(), v.expose_secret().to_owned());
            }
            self.encrypt_and_write(&mut vf, &path, &secrets)
        })
    }

    pub fn remove_secret(&self, name: &str) -> Result<()> {
        self.with_lock(|| {
            let path = self.vault_path()?;
            let mut vf = self.read_v2(&path)?;
            let mut secrets = self.decrypt_payload(&vf)?;
            secrets.remove(name);
            self.encrypt_and_write(&mut vf, &path, &secrets)
        })
    }

    pub fn list_secrets(&self) -> Result<Vec<SecretInfo>> {
        let path = self.vault_path()?;
        let vf = self.read_v2(&path)?;
        let secrets = self.decrypt_payload(&vf)?;
        let mut infos: Vec<SecretInfo> = secrets.keys()
            .map(|k| SecretInfo { name: k.clone(), kind: "String".to_owned() })
            .collect();
        infos.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(infos)
    }

    pub fn secret_names(&self) -> Result<Vec<String>> {
        let path = self.vault_path()?;
        let vf = self.read_v2(&path)?;
        let secrets = self.decrypt_payload(&vf)?;
        let mut names: Vec<String> = secrets.keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    pub fn unlock_and_preload(&self) -> Result<HashMap<String, SecretString>> {
        let path = self.vault_path()?;
        let vf = self.read_v2(&path)?;
        let secrets = self.decrypt_payload(&vf)?;
        Ok(secrets.into_secret_strings())
    }

    // ── Internal helpers ───────────────────────────────────────────────────

    fn vault_path(&self) -> Result<PathBuf> {
        let safe = sanitize_vault_name(&self.vault_name)?;
        Ok(self.vault_dir.join(format!("{safe}.mvault")))
    }

    fn with_lock<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        use fs2::FileExt;
        let safe = sanitize_vault_name(&self.vault_name)?;
        std::fs::create_dir_all(&self.vault_dir).context("creating vault directory")?;
        let lock_path = self.vault_dir.join(format!("{safe}.lock"));
        let lock_file = std::fs::OpenOptions::new()
            .create(true).write(true)
            .open(&lock_path)
            .with_context(|| format!("opening lock file for vault '{}'", self.vault_name))?;
        lock_file.lock_exclusive()
            .with_context(|| format!("acquiring lock for vault '{}'", self.vault_name))?;
        let result = f();
        let _ = lock_file.unlock();
        result
    }

    fn read_v2(&self, path: &Path) -> Result<VaultFileV2> {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("reading vault '{}'", self.vault_name))?;
        let vf: VaultFileV2 = serde_json::from_str(&json)
            .context("vault file is corrupt or in an incompatible format")?;
        if vf.format != "mevault-vault" {
            bail!("vault file has unexpected format '{}'", vf.format);
        }
        if vf.version != "2" {
            bail!("UnlockedVault got a non-v2 file (version '{}')", vf.version);
        }
        if vf.name != self.vault_name {
            bail!("vault name mismatch: file has '{}', expected '{}'", vf.name, self.vault_name);
        }
        Ok(vf)
    }

    fn payload_aad(&self) -> Vec<u8> {
        format!("mevault-payload\0{}\0{}", self.vault_id, self.vault_name).into_bytes()
    }

    fn decrypt_payload(&self, vf: &VaultFileV2) -> Result<SecretMap> {
        let aad = self.payload_aad();
        let plaintext = crypto::decrypt_payload(&vf.payload_nonce, &vf.payload, &self.dek, &aad)
            .context("payload decryption failed")?;
        let secrets: HashMap<String, String> = serde_json::from_slice(&plaintext)
            .context("vault contents are corrupt")?;
        Ok(SecretMap(secrets))
    }

    fn encrypt_and_write(&self, vf: &mut VaultFileV2, path: &Path, secrets: &HashMap<String, String>) -> Result<()> {
        let aad = self.payload_aad();
        let plaintext = Zeroizing::new(serde_json::to_vec(secrets).context("serialising secrets")?);
        let (nonce, ct) = crypto::encrypt_payload(&plaintext, &self.dek, &aad)
            .context("payload encryption failed")?;
        vf.payload_nonce = nonce;
        vf.payload = ct;
        vf.updated_at = chrono::Utc::now().to_rfc3339();

        let json = serde_json::to_string_pretty(vf).context("serialising vault file")?;
        atomic_write(path, json.as_bytes())
    }
}

// ── VaultStore ────────────────────────────────────────────────────────────────

pub struct VaultStore {
    vault_dir: PathBuf,
    policy: CryptoPolicy,
}

/// Backward-compatible alias.
pub type SecretStoreBridge = VaultStore;

impl VaultStore {
    pub fn new() -> Self {
        let vault_dir = std::env::var("APPDATA")
            .map(|a| PathBuf::from(a).join("MeVault").join("vaults"))
            .unwrap_or_else(|_| PathBuf::from(".mevault").join("vaults"));
        Self { vault_dir, policy: CryptoPolicy::production() }
    }

    pub fn new_at(vault_dir: PathBuf) -> Self {
        Self { vault_dir, policy: CryptoPolicy::production() }
    }

    #[cfg(debug_assertions)]
    pub fn new_at_with_policy(vault_dir: PathBuf, policy: CryptoPolicy) -> Self {
        Self { vault_dir, policy }
    }

    // ── Vault lifecycle ────────────────────────────────────────────────────

    /// Create a new encrypted vault (v2 format).
    ///
    /// If the vault already exists the call verifies the supplied password
    /// before returning `Ok(())`.
    pub fn create_vault(&self, vault_name: &str, password: &SecretString) -> Result<()> {
        self.with_vault_lock(vault_name, || {
            let path = self.vault_path(vault_name)?;
            if path.exists() {
                return self.verify_existing_vault(&path, vault_name, password);
            }
            std::fs::create_dir_all(&self.vault_dir).context("creating vault directory")?;
            self.create_v2_vault_file(&path, vault_name, password)
        })
    }

    /// Unlock a vault and return an `UnlockedVault` holding the cached DEK.
    ///
    /// Argon2 runs exactly once here. All subsequent CRUD operations on the
    /// returned `UnlockedVault` use the DEK directly — no further KDF work.
    ///
    /// V1 vaults are auto-migrated to the v2 format on first unlock.
    pub fn unlock(&self, vault_name: &str, password: &SecretString) -> Result<UnlockedVault> {
        let path = self.vault_path(vault_name)?;
        if !path.exists() {
            bail!("vault '{}' not found — run `mevault init` first", vault_name);
        }

        let raw_json = std::fs::read_to_string(&path)
            .with_context(|| format!("reading vault '{vault_name}'"))?;
        let raw: serde_json::Value = serde_json::from_str(&raw_json)
            .context("vault file is corrupt")?;

        match raw["version"].as_str().unwrap_or("1") {
            "2" => self.unlock_v2_from_json(&raw_json, vault_name, password),
            "1" => {
                // Migration: acquire lock, re-read inside lock, then write v2.
                self.with_vault_lock(vault_name, || {
                    let raw_json = std::fs::read_to_string(&path)?;
                    self.migrate_v1_to_v2(&path, &raw_json, vault_name, password)
                })
            }
            v => bail!("unsupported vault version '{}' in '{}'", v, vault_name),
        }
    }

    /// Change the vault password without re-encrypting the payload.
    ///
    /// Derives a new KEK from `new_password`, rewraps the DEK, and writes
    /// only the `key_protection` section. The secrets payload is untouched.
    pub fn change_password(
        &self,
        vault_name: &str,
        old_password: &SecretString,
        new_password: &SecretString,
    ) -> Result<()> {
        self.with_vault_lock(vault_name, || {
            let path = self.vault_path(vault_name)?;
            let raw_json = std::fs::read_to_string(&path)?;
            let raw: serde_json::Value = serde_json::from_str(&raw_json)?;

            // Migrate v1 first if needed.
            if raw["version"].as_str().unwrap_or("1") == "1" {
                let vault = self.migrate_v1_to_v2(&path, &raw_json, vault_name, old_password)?;
                // Recursion-free: re-read the v2 and rewrap.
                let raw_json = std::fs::read_to_string(&path)?;
                return self.rewrap_dek_v2(&path, &raw_json, vault_name, vault, new_password);
            }

            let vault = self.unlock_v2_from_json(&raw_json, vault_name, old_password)?;
            let raw_json = std::fs::read_to_string(&path)?;
            self.rewrap_dek_v2(&path, &raw_json, vault_name, vault, new_password)
        })
    }

    pub fn vault_exists(&self, vault_name: &str) -> Result<bool> {
        Ok(self.vault_path(vault_name)?.exists())
    }

    pub fn list_vaults(&self) -> Result<Vec<String>> {
        if !self.vault_dir.exists() { return Ok(vec![]); }
        let mut names = vec![];
        for entry in std::fs::read_dir(&self.vault_dir).context("reading vault directory")? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("mvault") {
                if let Ok(json) = std::fs::read_to_string(&path) {
                    if let Ok(vf) = serde_json::from_str::<VaultFile>(&json) {
                        names.push(vf.name);
                        continue;
                    }
                    if let Ok(vf) = serde_json::from_str::<VaultFileV2>(&json) {
                        names.push(vf.name);
                        continue;
                    }
                }
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_owned());
                }
            }
        }
        Ok(names)
    }

    // ── Legacy one-off CRUD (unlock + op in one call) ──────────────────────
    //
    // These run Argon2 once per call (unlock) then use the DEK for the
    // operation.  They exist for backward compat with callers that supply a
    // password per-operation (Tauri GUI, CLI add/remove commands).

    pub fn set_secret(
        &self,
        name: &str,
        value: &SecretString,
        vault_name: &str,
        password: Option<&SecretString>,
    ) -> Result<()> {
        let pw = password.context("vault password is required")?;
        self.unlock(vault_name, pw)?.set_secret(name, value)
    }

    pub fn set_secrets_bulk(
        &self,
        new_secrets: &HashMap<String, SecretString>,
        vault_name: &str,
        password: &SecretString,
    ) -> Result<()> {
        self.unlock(vault_name, password)?.set_secrets_bulk(new_secrets)
    }

    pub fn get_secret(
        &self,
        name: &str,
        vault_name: &str,
        password: Option<&SecretString>,
    ) -> Result<SecretString> {
        let pw = password.context("vault password is required")?;
        self.unlock(vault_name, pw)?.get_secret(name)
    }

    pub fn remove_secret(
        &self,
        name: &str,
        vault_name: &str,
        password: Option<&SecretString>,
    ) -> Result<()> {
        let pw = password.context("vault password is required")?;
        self.unlock(vault_name, pw)?.remove_secret(name)
    }

    pub fn list_secrets(
        &self,
        vault_name: &str,
        password: Option<&SecretString>,
    ) -> Result<Vec<SecretInfo>> {
        let pw = password.context("vault password is required")?;
        self.unlock(vault_name, pw)?.list_secrets()
    }

    pub fn unlock_and_list_names(&self, vault_name: &str, password: &SecretString) -> Result<Vec<String>> {
        self.unlock(vault_name, password)?.secret_names()
    }

    pub fn unlock_and_preload(
        &self,
        vault_name: &str,
        password: &SecretString,
    ) -> Result<HashMap<String, SecretString>> {
        self.unlock(vault_name, password)?.unlock_and_preload()
    }

    // ── Module stubs ───────────────────────────────────────────────────────

    pub fn check_modules(&self) -> Result<bool> { Ok(true) }
    pub fn install_modules(&self) -> Result<()> { Ok(()) }

    // ── Internal ───────────────────────────────────────────────────────────

    fn vault_path(&self, vault_name: &str) -> Result<PathBuf> {
        let safe = sanitize_vault_name(vault_name)?;
        Ok(self.vault_dir.join(format!("{safe}.mvault")))
    }

    fn with_vault_lock<F, T>(&self, vault_name: &str, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        use fs2::FileExt;
        let safe = sanitize_vault_name(vault_name)?;
        std::fs::create_dir_all(&self.vault_dir).context("creating vault directory")?;
        let lock_path = self.vault_dir.join(format!("{safe}.lock"));
        let lock_file = std::fs::OpenOptions::new()
            .create(true).write(true)
            .open(&lock_path)
            .with_context(|| format!("opening lock file for vault '{vault_name}'"))?;
        lock_file.lock_exclusive()
            .with_context(|| format!("acquiring lock for vault '{vault_name}'"))?;
        let result = f();
        let _ = lock_file.unlock();
        result
    }

    // ── V2 helpers ─────────────────────────────────────────────────────────

    fn create_v2_vault_file(&self, path: &Path, vault_name: &str, password: &SecretString) -> Result<()> {
        let (vf, _dek) = self.build_new_v2(vault_name, password, None, HashMap::new())?;
        let json = serde_json::to_string_pretty(&vf).context("serialising vault file")?;
        atomic_write(path, json.as_bytes())
    }

    /// Build a new v2 VaultFile, optionally reusing an existing vault_id and created_at.
    fn build_new_v2(
        &self,
        vault_name: &str,
        password: &SecretString,
        existing_meta: Option<(&str, &str)>, // (vault_id, created_at)
        secrets: HashMap<String, String>,
    ) -> Result<(VaultFileV2, Zeroizing<[u8; 32]>)> {
        // Wrap immediately so any early `?` exit zeroizes the secrets map.
        let secrets_map = SecretMap(secrets);

        let vault_id = existing_meta
            .map(|(id, _)| id.to_owned())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let created_at = existing_meta
            .map(|(_, ts)| ts.to_owned())
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

        let dek = crypto::generate_dek();
        let kek_salt = crypto::new_kek_salt();
        let (mem, iters, para) = self.policy.kdf_profile.params();

        let mut kek = crypto::derive_kek(password, kek_salt.as_str(), mem, iters, para, &self.policy)
            .context("deriving key-encryption key")?;

        let kek_aad = format!("mevault-kek\0{vault_id}\0{vault_name}").into_bytes();
        let (kp_nonce, wrapped_dek) = crypto::wrap_dek(&dek, &kek, &kek_aad)
            .context("wrapping data-encryption key")?;
        kek.zeroize();

        let payload_aad = format!("mevault-payload\0{vault_id}\0{vault_name}").into_bytes();
        let plaintext = Zeroizing::new(serde_json::to_vec(&*secrets_map)?);
        let (payload_nonce, payload_ct) = crypto::encrypt_payload(&plaintext, &dek, &payload_aad)
            .context("encrypting vault payload")?;

        let vf = VaultFileV2 {
            format: "mevault-vault".to_owned(),
            version: "2".to_owned(),
            vault_id,
            name: vault_name.to_owned(),
            created_at,
            updated_at: chrono::Utc::now().to_rfc3339(),
            key_protection: KeyProtection {
                mem_kib: mem,
                iters,
                para,
                salt: kek_salt.to_string(),
                nonce: kp_nonce,
                wrapped_dek,
            },
            payload_nonce,
            payload: payload_ct,
        };

        Ok((vf, dek))
    }

    fn unlock_v2_from_json(&self, json: &str, vault_name: &str, password: &SecretString) -> Result<UnlockedVault> {
        let vf: VaultFileV2 = serde_json::from_str(json)
            .context("parsing v2 vault file")?;

        if vf.format != "mevault-vault" {
            bail!("vault file has unexpected format '{}'", vf.format);
        }
        if vf.name != vault_name {
            bail!("vault name mismatch: file has '{}', requested '{}'", vf.name, vault_name);
        }

        let kp = &vf.key_protection;
        self.policy.validate_blob_params(kp.mem_kib, kp.iters, kp.para)?;

        let mut kek = crypto::derive_kek(password, &kp.salt, kp.mem_kib, kp.iters, kp.para, &self.policy)
            .context("deriving key-encryption key")?;
        let kek_aad = format!("mevault-kek\0{}\0{vault_name}", vf.vault_id).into_bytes();
        let dek = crypto::unwrap_dek(&kp.nonce, &kp.wrapped_dek, &kek, &kek_aad)
            .context("wrong password or corrupt vault")?;
        kek.zeroize();

        Ok(UnlockedVault {
            vault_dir: self.vault_dir.clone(),
            policy: self.policy.clone(),
            vault_id: vf.vault_id,
            vault_name: vault_name.to_owned(),
            dek,
        })
    }

    fn migrate_v1_to_v2(
        &self,
        path: &Path,
        raw_json: &str,
        vault_name: &str,
        password: &SecretString,
    ) -> Result<UnlockedVault> {
        // Parse and validate v1.
        let vf_v1: VaultFile = serde_json::from_str(raw_json)
            .context("parsing v1 vault file")?;

        if vf_v1.format != "mevault-vault" {
            bail!("vault file has unexpected format '{}'", vf_v1.format);
        }
        if vf_v1.name != vault_name {
            bail!("vault name mismatch: file has '{}', expected '{}'", vf_v1.name, vault_name);
        }

        // Decrypt v1 secrets.
        let plaintext = crypto::decrypt(&vf_v1.blob, password, vault_name.as_bytes(), &self.policy)
            .context("wrong password or corrupt v1 vault")?;
        let secrets: HashMap<String, String> = serde_json::from_slice(&plaintext)
            .context("v1 vault contents corrupt")?;

        // Build v2 file (reuse vault's created_at; assign a fresh vault_id).
        let vault_id = uuid::Uuid::new_v4().to_string();
        let (vf_v2, dek) = self.build_new_v2(
            vault_name,
            password,
            Some((&vault_id, &vf_v1.created_at)),
            secrets,
        )?;
        let vault_id = vf_v2.vault_id.clone();

        // ── Mandatory backup of the v1 file ───────────────────────────────
        // Backup failure is a hard error — we must never lose the original
        // before we have verified the new v2 file is correct.
        let bak = path.with_extension("v1.bak");
        let v1_bytes = std::fs::read(path)
            .context("reading v1 vault file for backup")?;

        if bak.exists() {
            // A prior interrupted migration left a .v1.bak.  Compare content:
            // if identical we can reuse it; if different create a unique one.
            let existing_bak = std::fs::read(&bak)
                .context("reading existing .v1.bak for comparison")?;
            if existing_bak != v1_bytes {
                let unique_bak = path.with_extension(
                    format!("v1.bak.{}", uuid::Uuid::new_v4()),
                );
                write_and_sync(&unique_bak, &v1_bytes)
                    .context("creating unique v1 migration backup")?;
            }
            // else: .v1.bak already contains exactly this content — reuse it.
        } else {
            write_and_sync(&bak, &v1_bytes)
                .context("creating mandatory v1 migration backup")?;
        }

        // ── Atomic write with full payload verification before promotion ───
        //
        // The verification closure parses the written JSON, re-derives the KEK,
        // unwraps the DEK, and decrypts the payload all the way to a secrets map.
        // Only if the round-trip succeeds does rename() happen; on any failure the
        // temp file is deleted by TempFileGuard and the original v1 file is intact.
        let json = serde_json::to_string_pretty(&vf_v2).context("serialising v2 vault file")?;

        // Capture what we need inside the closure (policy + password).
        let policy_clone = self.policy.clone();
        let pw_clone = password.clone();
        let vn = vault_name.to_owned();

        atomic_write_verified(path, json.as_bytes(), move |tmp_path| {
            let written = std::fs::read_to_string(tmp_path)
                .context("re-reading v2 temp file for verification")?;
            let vf: VaultFileV2 = serde_json::from_str(&written)
                .context("v2 temp file is not valid JSON")?;
            if vf.format != "mevault-vault" || vf.version != "2" || vf.name != vn {
                bail!("v2 temp file has unexpected header fields");
            }
            let kp = &vf.key_protection;
            policy_clone.validate_blob_params(kp.mem_kib, kp.iters, kp.para)?;
            let kek_aad = format!("mevault-kek\0{}\0{vn}", vf.vault_id).into_bytes();
            let mut kek = crypto::derive_kek(&pw_clone, &kp.salt, kp.mem_kib, kp.iters, kp.para, &policy_clone)
                .context("re-deriving KEK for migration verification")?;
            let dek_check = crypto::unwrap_dek(&kp.nonce, &kp.wrapped_dek, &kek, &kek_aad)
                .context("DEK unwrap failed during migration verification")?;
            kek.zeroize();
            let payload_aad = format!("mevault-payload\0{}\0{vn}", vf.vault_id).into_bytes();
            let pt = crypto::decrypt_payload(&vf.payload_nonce, &vf.payload, &dek_check, &payload_aad)
                .context("payload decryption failed during migration verification")?;
            let verified: HashMap<String, String> = serde_json::from_slice(&pt)
                .context("secrets map is corrupt in migrated v2 file")?;
            let _verified = SecretMap(verified); // zeroizes all values on drop
            Ok(())
        })?;

        Ok(UnlockedVault {
            vault_dir: self.vault_dir.clone(),
            policy: self.policy.clone(),
            vault_id,
            vault_name: vault_name.to_owned(),
            dek,
        })
    }

    fn verify_existing_vault(&self, path: &Path, vault_name: &str, password: &SecretString) -> Result<()> {
        let raw_json = std::fs::read_to_string(path)?;
        let raw: serde_json::Value = serde_json::from_str(&raw_json)?;

        let stored_name = raw["name"].as_str().unwrap_or("");
        if !stored_name.is_empty() && stored_name != vault_name {
            bail!(
                "vault name '{}' conflicts with existing vault '{}' \
                 (both map to the same filename '{}'); choose a different name",
                vault_name,
                stored_name,
                sanitize_vault_name(vault_name)?
            );
        }

        match raw["version"].as_str().unwrap_or("1") {
            "2" => { self.unlock_v2_from_json(&raw_json, vault_name, password)?; }
            _ => {
                // V1: verify by decrypting.
                let vf: VaultFile = serde_json::from_str(&raw_json)?;
                crypto::decrypt(&vf.blob, password, vault_name.as_bytes(), &self.policy)
                    .context("vault already exists but the password is incorrect")?;
            }
        }
        Ok(())
    }

    fn rewrap_dek_v2(
        &self,
        path: &Path,
        raw_json: &str,
        vault_name: &str,
        vault: UnlockedVault,
        new_password: &SecretString,
    ) -> Result<()> {
        let mut vf: VaultFileV2 = serde_json::from_str(raw_json)?;
        let kek_salt = crypto::new_kek_salt();
        let (mem, iters, para) = self.policy.kdf_profile.params();
        let mut new_kek = crypto::derive_kek(new_password, kek_salt.as_str(), mem, iters, para, &self.policy)?;
        let kek_aad = format!("mevault-kek\0{}\0{vault_name}", vf.vault_id).into_bytes();
        let (new_nonce, new_wrapped) = crypto::wrap_dek(&vault.dek, &new_kek, &kek_aad)?;
        new_kek.zeroize();

        vf.key_protection = KeyProtection {
            mem_kib: mem, iters, para,
            salt: kek_salt.to_string(),
            nonce: new_nonce,
            wrapped_dek: new_wrapped,
        };
        vf.updated_at = chrono::Utc::now().to_rfc3339();

        let json = serde_json::to_string_pretty(&vf)?;
        atomic_write(path, json.as_bytes())
    }

}

impl Default for VaultStore {
    fn default() -> Self { Self::new() }
}

fn sanitize_vault_name(name: &str) -> Result<String> {
    if name.is_empty() { bail!("vault name cannot be empty"); }
    Ok(name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect())
}

// ── Durable file I/O helpers ──────────────────────────────────────────────────

/// Write `data` to `path` and call `sync_all` before returning.
/// Opens with write access so `sync_all` works on Windows (requires the handle
/// to have been opened for writing — a read-only handle is rejected by
/// `FlushFileBuffers`).
fn write_and_sync(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(path)
        .with_context(|| format!("opening {} for write+sync", path.display()))?;
    f.write_all(data)
        .with_context(|| format!("writing {}", path.display()))?;
    f.sync_all()
        .with_context(|| format!("flushing {}", path.display()))?;
    Ok(())
}

/// RAII guard that deletes the temp file on drop.
///
/// After a successful `rename` the file no longer exists at the guarded path,
/// so `remove_file` harmlessly returns `NotFound`.  No `mem::forget` needed.
struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Write `data` to a unique temp file, run `verify`, then atomically rename
/// to `path`.  The temp name embeds the PID and a UUID so concurrent writers
/// never collide, and a stale temp from a prior crash cannot block a new write.
///
/// On any failure the temp file is deleted by `TempFileGuard`.  After a
/// successful rename the guard's `Drop` calls `remove_file` on the now-missing
/// path, which returns `NotFound` and is silently ignored — no leak occurs.
fn atomic_write_verified<F>(path: &Path, data: &[u8], verify: F) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    use std::io::Write;

    let file_name = path
        .file_name()
        .context("path has no filename component")?
        .to_string_lossy();
    let tmp = path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4(),
    ));

    let _guard = TempFileGuard(tmp.clone());

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .with_context(|| format!("creating temp file {}", tmp.display()))?;
    file.write_all(data)
        .with_context(|| format!("writing vault data to {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing vault data to {}", tmp.display()))?;
    drop(file);

    verify(&tmp)?; // if this returns Err, guard fires and deletes tmp

    std::fs::rename(&tmp, path)
        .with_context(|| format!("promoting {} to {}", tmp.display(), path.display()))?;

    // _guard drops here; remove_file sees NotFound (rename moved the file) and ignores it.

    // Best-effort parent directory sync so the rename is durable on Linux.
    if let Some(parent) = path.parent() {
        let _ = std::fs::File::open(parent).and_then(|f| f.sync_all());
    }

    Ok(())
}

/// Convenience wrapper when no post-write verification is needed.
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    atomic_write_verified(path, data, |_| Ok(()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoPolicy;

    fn pw() -> SecretString {
        SecretString::new("correct-horse-battery-staple".to_owned().into())
    }

    fn store(dir: &tempfile::TempDir) -> VaultStore {
        VaultStore::new_at_with_policy(dir.path().to_path_buf(), CryptoPolicy::fast_test())
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
    fn create_wrong_password_on_existing_vault_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();
        let wrong = SecretString::new("wrong-password".to_owned().into());
        assert!(s.create_vault("V", &wrong).is_err());
    }

    #[test]
    fn name_sanitization_collision_detected() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("My Vault", &pw()).unwrap();
        let err = s.create_vault("My?Vault", &pw());
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("conflicts"));
    }

    #[test]
    fn unlock_and_crud() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();
        let vault = s.unlock("V", &pw()).unwrap();

        let val = SecretString::new("postgres://localhost".to_owned().into());
        vault.set_secret("DB_URL", &val).unwrap();
        assert_eq!(vault.get_secret("DB_URL").unwrap().expose_secret(), "postgres://localhost");

        vault.remove_secret("DB_URL").unwrap();
        assert!(vault.get_secret("DB_URL").is_err());
    }

    #[test]
    fn set_get_remove_via_legacy_api() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();

        let val = SecretString::new("secret-value".to_owned().into());
        s.set_secret("K", &val, "V", Some(&pw())).unwrap();
        assert_eq!(s.get_secret("K", "V", Some(&pw())).unwrap().expose_secret(), "secret-value");
        s.remove_secret("K", "V", Some(&pw())).unwrap();
        assert!(s.get_secret("K", "V", Some(&pw())).is_err());
    }

    #[test]
    fn set_secrets_bulk_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();

        let mut batch = HashMap::new();
        for i in 0..10usize {
            batch.insert(format!("K{i}"), SecretString::new(format!("v{i}").into()));
        }
        s.set_secrets_bulk(&batch, "V", &pw()).unwrap();

        for i in 0..10usize {
            assert_eq!(
                s.get_secret(&format!("K{i}"), "V", Some(&pw())).unwrap().expose_secret(),
                &format!("v{i}")
            );
        }
    }

    #[test]
    fn unlock_no_argon2_on_crud() {
        // Verify fast bulk CRUD via UnlockedVault (no per-op Argon2).
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();
        let vault = s.unlock("V", &pw()).unwrap();

        let mut batch = HashMap::new();
        for i in 0..20usize {
            batch.insert(format!("K{i}"), SecretString::new(format!("v{i}").into()));
        }
        vault.set_secrets_bulk(&batch).unwrap();
        assert_eq!(vault.secret_names().unwrap().len(), 20);
        for i in 0..20usize {
            assert_eq!(vault.get_secret(&format!("K{i}")).unwrap().expose_secret(), &format!("v{i}"));
        }
    }

    #[test]
    fn wrong_password_unlock_fails() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();
        let bad = SecretString::new("wrong-password".to_owned().into());
        assert!(s.unlock("V", &bad).is_err());
    }

    #[test]
    fn change_password_rewraps_dek() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();

        let val = SecretString::new("precious-secret".to_owned().into());
        s.set_secret("K", &val, "V", Some(&pw())).unwrap();

        let new_pw = SecretString::new("new-horse-battery-staple".to_owned().into());
        s.change_password("V", &pw(), &new_pw).unwrap();

        // Old password must fail.
        assert!(s.unlock("V", &pw()).is_err());
        // New password must succeed and preserve secrets.
        let vault = s.unlock("V", &new_pw).unwrap();
        assert_eq!(vault.get_secret("K").unwrap().expose_secret(), "precious-secret");
    }

    #[test]
    fn v2_vault_id_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("V", &pw()).unwrap();
        let v1 = s.unlock("V", &pw()).unwrap();
        let v2 = s.unlock("V", &pw()).unwrap();
        assert_eq!(v1.vault_id(), v2.vault_id());
        assert!(!v1.vault_id().is_empty());
    }

    #[test]
    fn cross_vault_ciphertext_cannot_be_moved() {
        // Transplanting the payload from vault A into vault B must fail
        // because the payload AAD encodes the vault_id.
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.create_vault("A", &pw()).unwrap();
        s.create_vault("B", &pw()).unwrap();

        let val = SecretString::new("secret-a".to_owned().into());
        s.set_secret("K", &val, "A", Some(&pw())).unwrap();

        // Read A's vault file and extract the payload fields.
        let path_a = s.vault_path("A").unwrap();
        let a_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path_a).unwrap()).unwrap();
        let a_payload = a_json["payload"].as_str().unwrap().to_owned();
        let a_payload_nonce = a_json["payload_nonce"].as_str().unwrap().to_owned();

        // Transplant A's payload into B's vault file.
        let path_b = s.vault_path("B").unwrap();
        let mut b_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path_b).unwrap()).unwrap();
        b_json["payload"] = serde_json::Value::String(a_payload);
        b_json["payload_nonce"] = serde_json::Value::String(a_payload_nonce);
        std::fs::write(&path_b, serde_json::to_string_pretty(&b_json).unwrap()).unwrap();

        // Unlocking B must fail because the payload AAD (vault_id of B) doesn't match.
        let vault_b = s.unlock("B", &pw()).unwrap();
        assert!(vault_b.get_secret("K").is_err(), "transplanted payload must be rejected");
    }

    #[test]
    fn v1_vault_auto_migrates_on_unlock() {
        // Create a v1 vault by writing the old format directly.
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);

        // Write a v1 vault file directly.
        let vault_dir = dir.path().to_path_buf();
        std::fs::create_dir_all(&vault_dir).unwrap();
        let path = vault_dir.join("V.mvault");

        let aad = b"V";
        let blob = crypto::encrypt(b"{\"K\":\"v1-secret\"}", &pw(), aad, &CryptoPolicy::fast_test()).unwrap();
        let v1 = VaultFile {
            format: "mevault-vault".to_owned(),
            version: "1".to_owned(),
            name: "V".to_owned(),
            created_at: "2024-01-01T00:00:00Z".to_owned(),
            updated_at: "2024-01-01T00:00:00Z".to_owned(),
            blob,
        };
        std::fs::write(&path, serde_json::to_string_pretty(&v1).unwrap()).unwrap();

        // unlock() should migrate v1→v2 and return a working UnlockedVault.
        let vault = s.unlock("V", &pw()).unwrap();
        assert_eq!(vault.get_secret("K").unwrap().expose_secret(), "v1-secret");

        // The on-disk file should now be v2.
        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(on_disk["version"].as_str().unwrap(), "2");
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

        s.set_secret("S", &SecretString::new("value-a".to_owned().into()), "ProjectA", Some(&pw_a)).unwrap();
        s.set_secret("S", &SecretString::new("value-b".to_owned().into()), "ProjectB", Some(&pw_b)).unwrap();

        assert_eq!(s.get_secret("S", "ProjectA", Some(&pw_a)).unwrap().expose_secret(), "value-a");
        assert_eq!(s.get_secret("S", "ProjectB", Some(&pw_b)).unwrap().expose_secret(), "value-b");
        assert!(s.get_secret("S", "ProjectB", Some(&pw_a)).is_err());
        assert!(s.get_secret("S", "ProjectA", Some(&pw_b)).is_err());
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

    #[test]
    fn failed_atomic_verification_preserves_destination() {
        // If the verify closure returns an error, the destination must be
        // untouched and the temp file must be cleaned up.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.mvault");
        std::fs::write(&path, b"original").unwrap();

        let result = atomic_write_verified(&path, b"replacement", |_| {
            anyhow::bail!("injected verification failure")
        });

        assert!(result.is_err());
        // Original content must be intact.
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        // No temp files should remain.
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftover.is_empty(), "temp file must be cleaned up after verification failure");
    }
}
