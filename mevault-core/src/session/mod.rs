use chrono::{DateTime, Utc};
use secrecy::SecretString;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::config::ExpiryMode;
use crate::vault::UnlockedVault;

// ── Session ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Active,
    Expired,
    Locked,
}

pub struct Session {
    pub id: Uuid,
    pub vault_name: String,
    pub started_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub expiry_mode: ExpiryMode,
    pub terminal_pid: u32,
    pub project_root: PathBuf,
    vault: Arc<UnlockedVault>,
}

impl Session {
    pub fn new(
        vault: Arc<UnlockedVault>,
        expiry_mode: ExpiryMode,
        expiry_hours: Option<u32>,
        terminal_pid: u32,
        project_root: PathBuf,
    ) -> Self {
        let id = Uuid::new_v4();
        let started_at = Utc::now();
        let vault_name = vault.vault_name().to_owned();
        let expires_at = match expiry_mode {
            ExpiryMode::Time | ExpiryMode::Both => {
                let h = expiry_hours.unwrap_or(8) as i64;
                Some(started_at + chrono::Duration::hours(h))
            }
            ExpiryMode::Terminal => None,
        };
        Self {
            id,
            vault_name,
            started_at,
            expires_at,
            expiry_mode,
            terminal_pid,
            project_root,
            vault,
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

    pub fn vault(&self) -> Arc<UnlockedVault> {
        Arc::clone(&self.vault)
    }

    pub fn get_secret(&self, name: &str) -> Option<SecretString> {
        self.vault.get_secret(name).ok()
    }

    pub fn secret_names(&self) -> Vec<String> {
        self.vault.secret_names().unwrap_or_default()
    }
}

// ── SessionManager ────────────────────────────────────────────────────────

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

    /// Store a session and, if it has a time-based expiry, spawn a task that
    /// drops it (and therefore zeroizes the DEK) when the expiry fires.
    ///
    /// The task holds only a `Weak` reference so it does not prevent the
    /// `SessionManager` or the vault from being dropped normally.
    pub async fn start(&self, session: Session) {
        let id = session.id;
        let expires_at = session.expires_at;

        // Downgrade BEFORE storing the session so the task never holds a
        // strong Arc that would keep the Session alive on its own.
        let weak_inner: Weak<RwLock<Option<Session>>> = Arc::downgrade(&self.inner);

        *self.inner.write().await = Some(session);

        if let Some(expiry) = expires_at {
            tokio::spawn(async move {
                let delay = (expiry - Utc::now()).to_std().unwrap_or_default(); // clamp to zero if already past
                tokio::time::sleep(delay).await;

                // Upgrade only if SessionManager still exists.
                if let Some(inner) = weak_inner.upgrade() {
                    let mut guard = inner.write().await;
                    // Only drop if this is still the same session — a newer
                    // session started after this one must not be evicted.
                    if guard.as_ref().map(|s| s.id) == Some(id) {
                        guard.take(); // drops Arc<UnlockedVault> → zeroizes DEK
                    }
                }
            });
        }
    }

    pub async fn end(&self) {
        let mut lock = self.inner.write().await;
        lock.take(); // drops Session → Arc<UnlockedVault> → zeroizes DEK
    }

    pub async fn is_active(&self) -> bool {
        // Use write lock so we can eagerly purge expired sessions.
        let mut guard = self.inner.write().await;
        match guard.as_ref() {
            Some(s) if s.is_active() => true,
            Some(_) => {
                guard.take();
                false
            }
            None => false,
        }
    }

    /// Run `f` against the active session. Eagerly drops the session (and
    /// zeroizes the DEK) if it has expired rather than leaving it in memory.
    pub async fn with_session<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&Session) -> R,
    {
        let mut guard = self.inner.write().await;
        match guard.as_ref() {
            Some(session) if session.is_active() => Some(f(session)),
            Some(_) => {
                guard.take(); // eager DEK zeroization on expiry
                None
            }
            None => None,
        }
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
    use crate::crypto::CryptoPolicy;
    use crate::vault::VaultStore;
    use secrecy::SecretString;

    fn setup_test_vault() -> (tempfile::TempDir, Arc<UnlockedVault>) {
        let dir = tempfile::tempdir().unwrap();
        let store =
            VaultStore::new_at_with_policy(dir.path().to_path_buf(), CryptoPolicy::fast_test());
        let pw = SecretString::new("test-password".to_owned());
        store.create_vault("TestVault", &pw).unwrap();
        store
            .set_secret(
                "DB_URL",
                &SecretString::new("postgres://test".to_owned()),
                "TestVault",
                Some(&pw),
            )
            .unwrap();
        let vault = Arc::new(store.unlock("TestVault", &pw).unwrap());
        (dir, vault)
    }

    #[tokio::test]
    async fn session_lifecycle() {
        let (_dir, vault) = setup_test_vault();
        let manager = SessionManager::new();
        assert!(!manager.is_active().await);

        let session = Session::new(
            vault,
            ExpiryMode::Both,
            Some(8),
            std::process::id(),
            PathBuf::from("."),
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
        let (_dir, vault) = setup_test_vault();
        let mut session = Session::new(vault, ExpiryMode::Time, Some(1), 1234, PathBuf::from("."));
        session.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        assert!(!session.is_active());
    }

    #[tokio::test]
    async fn expired_session_is_eagerly_purged_by_with_session() {
        let (_dir, vault) = setup_test_vault();
        let manager = SessionManager::new();

        let mut session = Session::new(vault, ExpiryMode::Time, Some(1), 1234, PathBuf::from("."));
        session.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        manager.start(session).await;

        // with_session must return None AND drop the session.
        let result = manager.with_session(|_| "should not run").await;
        assert!(result.is_none());

        // The slot must now be empty (DEK already zeroized).
        let guard = manager.inner.read().await;
        assert!(
            guard.is_none(),
            "expired session must be removed from manager"
        );
    }

    #[tokio::test]
    async fn expiry_task_drops_session_after_timeout() {
        let (_dir, vault) = setup_test_vault();
        let manager = SessionManager::new();

        let mut session = Session::new(vault, ExpiryMode::Time, Some(1), 1234, PathBuf::from("."));
        // Set expiry 50 ms in the future so the spawned task fires quickly.
        session.expires_at = Some(Utc::now() + chrono::Duration::milliseconds(50));
        manager.start(session).await;

        assert!(
            manager.is_active().await,
            "session must be active before expiry"
        );

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // The expiry task must have fired and cleared the session.
        let guard = manager.inner.read().await;
        assert!(guard.is_none(), "expiry task must have dropped the session");
    }

    #[tokio::test]
    async fn expiry_task_does_not_evict_replacement_session() {
        let (_dir, vault1) = setup_test_vault();
        let (_dir2, vault2) = setup_test_vault();
        let manager = SessionManager::new();

        // Start session 1 with a very short expiry.
        let mut s1 = Session::new(vault1, ExpiryMode::Time, Some(1), 1, PathBuf::from("."));
        s1.expires_at = Some(Utc::now() + chrono::Duration::milliseconds(50));
        manager.start(s1).await;

        // Replace it with session 2 before the expiry fires.
        let s2 = Session::new(vault2, ExpiryMode::Both, Some(8), 2, PathBuf::from("."));
        let s2_id = s2.id;
        manager.start(s2).await;

        // Wait for session 1's expiry task to fire.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // Session 2 must still be present — the old timer must not evict it.
        let guard = manager.inner.read().await;
        assert!(
            guard.is_some(),
            "replacement session must not be evicted by old timer"
        );
        assert_eq!(guard.as_ref().map(|s| s.id), Some(s2_id));
    }
}
