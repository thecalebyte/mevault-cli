use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::config::ExpiryMode;

// ── Session ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Active,
    Expired,
    Locked,
}

/// Internal storage mode for secrets in a session.
enum SecretStorage {
    /// All secrets preloaded at unlock time. Fast O(1) lookup; all values in memory.
    /// Used in tests and when calling Session::new() directly.
    Preloaded(HashMap<String, SecretString>),
    /// Only the vault password is held; secrets are decrypted on demand per-request.
    /// Minimises the number of plaintext values in memory at any moment.
    Lazy {
        password: SecretString,
        names: Vec<String>,
    },
}

pub struct Session {
    pub id: Uuid,
    pub vault_name: String,
    pub started_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub expiry_mode: ExpiryMode,
    /// PID of the terminal that called `mevault unlock`.
    pub terminal_pid: u32,
    /// Project root — used for working-dir checks in the allow-list engine.
    pub project_root: PathBuf,
    storage: SecretStorage,
}

impl Session {
    /// Preloaded constructor — all secrets already decrypted and in memory.
    /// Used by tests and by the legacy (v1) unlock path.
    pub fn new(
        vault_name: impl Into<String>,
        expiry_mode: ExpiryMode,
        expiry_hours: Option<u32>,
        terminal_pid: u32,
        project_root: PathBuf,
        secrets: HashMap<String, SecretString>,
    ) -> Self {
        Self::build(
            vault_name,
            expiry_mode,
            expiry_hours,
            terminal_pid,
            project_root,
            SecretStorage::Preloaded(secrets),
        )
    }

    /// Lazy constructor — only the vault password and secret names are kept.
    /// Each `get_secret_lazy` call decrypts one secret on demand via the bridge.
    pub fn new_lazy(
        vault_name: impl Into<String>,
        expiry_mode: ExpiryMode,
        expiry_hours: Option<u32>,
        terminal_pid: u32,
        project_root: PathBuf,
        vault_password: SecretString,
        secret_names: Vec<String>,
    ) -> Self {
        Self::build(
            vault_name,
            expiry_mode,
            expiry_hours,
            terminal_pid,
            project_root,
            SecretStorage::Lazy { password: vault_password, names: secret_names },
        )
    }

    fn build(
        vault_name: impl Into<String>,
        expiry_mode: ExpiryMode,
        expiry_hours: Option<u32>,
        terminal_pid: u32,
        project_root: PathBuf,
        storage: SecretStorage,
    ) -> Self {
        let id = Uuid::new_v4();
        let started_at = Utc::now();
        let expires_at = match expiry_mode {
            ExpiryMode::Time | ExpiryMode::Both => {
                let h = expiry_hours.unwrap_or(8) as i64;
                Some(started_at + chrono::Duration::hours(h))
            }
            ExpiryMode::Terminal => None,
        };
        Self {
            id,
            vault_name: vault_name.into(),
            started_at,
            expires_at,
            expiry_mode,
            terminal_pid,
            project_root,
            storage,
        }
    }

    pub fn state(&self) -> SessionState {
        if let Some(exp) = self.expires_at {
            if Utc::now() >= exp {
                return SessionState::Expired;
            }
        }
        SessionState::Active
    }

    pub fn is_active(&self) -> bool {
        self.state() == SessionState::Active
    }

    pub fn time_remaining(&self) -> Option<chrono::Duration> {
        self.expires_at.map(|exp| exp - Utc::now())
    }

    /// Fast synchronous lookup — only works in preloaded mode.
    /// Returns None in lazy mode (use `get_secret_lazy` instead).
    pub fn get_secret(&self, name: &str) -> Option<&SecretString> {
        match &self.storage {
            SecretStorage::Preloaded(map) => map.get(name),
            SecretStorage::Lazy { .. } => None,
        }
    }

    /// Returns true when the session uses lazy (per-request) decryption.
    pub fn is_lazy(&self) -> bool {
        matches!(self.storage, SecretStorage::Lazy { .. })
    }

    /// Extract the data needed for a lazy secret fetch.
    /// Returns `(vault_password_clone, vault_name_clone)` if in lazy mode.
    pub fn lazy_params(&self) -> Option<(SecretString, String)> {
        match &self.storage {
            SecretStorage::Lazy { password, .. } => {
                Some((SecretString::new(password.expose_secret().to_owned().into()), self.vault_name.clone()))
            }
            SecretStorage::Preloaded(_) => None,
        }
    }

    pub fn secret_names(&self) -> Vec<String> {
        match &self.storage {
            SecretStorage::Preloaded(map) => map.keys().cloned().collect(),
            SecretStorage::Lazy { names, .. } => names.clone(),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let SecretStorage::Preloaded(ref mut map) = self.storage {
            for val in map.values_mut() {
                *val = SecretString::new(String::new().into());
            }
            map.clear();
        }
        // In lazy mode, `SecretString::drop` zeroizes the vault_password automatically.
    }
}

// ── SessionManager ────────────────────────────────────────────────────────
//
// Holds the single active session in a shared RwLock so both the proxy server
// (which runs as a tokio task) and the CLI can read/modify it concurrently.

pub type SharedSession = Arc<RwLock<Option<Session>>>;

#[derive(Clone)]
pub struct SessionManager {
    inner: SharedSession,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn start(&self, session: Session) {
        let mut lock = self.inner.write().await;
        *lock = Some(session);
    }

    pub async fn end(&self) {
        let mut lock = self.inner.write().await;
        // Dropping the Session triggers its Drop impl which zeroizes all secrets.
        *lock = None;
    }

    pub async fn is_active(&self) -> bool {
        let lock = self.inner.read().await;
        lock.as_ref().map(|s| s.is_active()).unwrap_or(false)
    }

    pub async fn with_session<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&Session) -> R,
    {
        let lock = self.inner.read().await;
        lock.as_ref().filter(|s| s.is_active()).map(f)
    }

    pub fn shared(&self) -> SharedSession {
        Arc::clone(&self.inner)
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExpiryMode;

    #[tokio::test]
    async fn session_lifecycle() {
        let manager = SessionManager::new();
        assert!(!manager.is_active().await);

        let secrets = HashMap::from([
            ("DB_URL".to_owned(), SecretString::new("postgres://test".to_owned().into())),
        ]);
        let session = Session::new(
            "TestVault",
            ExpiryMode::Both,
            Some(8),
            std::process::id(),
            PathBuf::from("."),
            secrets,
        );
        manager.start(session).await;
        assert!(manager.is_active().await);

        let found = manager
            .with_session(|s| s.get_secret("DB_URL").is_some())
            .await;
        assert_eq!(found, Some(true));

        manager.end().await;
        assert!(!manager.is_active().await);
    }

    #[test]
    fn expired_session_not_active() {
        let mut session = Session::new(
            "TestVault",
            ExpiryMode::Time,
            Some(1),
            1234,
            PathBuf::from("."),
            HashMap::new(),
        );
        // Force expiry by backdating.
        session.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        assert!(!session.is_active());
    }
}
