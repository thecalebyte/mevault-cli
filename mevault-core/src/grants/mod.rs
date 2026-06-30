use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct LaunchGrant {
    pub id: Uuid,
    pub session_id: Uuid,
    pub root_pid: u32,
    /// Windows FILETIME (100-nanosecond intervals since 1601-01-01). Never zero.
    pub process_created_at: u64,
    pub executable: PathBuf,
    pub working_directory: PathBuf,
    pub allowed_secrets: HashSet<String>,
    pub created_at: SystemTime,
}

impl LaunchGrant {
    pub fn allows_secret(&self, name: &str) -> bool {
        self.allowed_secrets.contains("*") || self.allowed_secrets.contains(name)
    }
}

/// Global registry of processes launched by `mevault run`.
/// Stored as a process-global singleton so IPC handlers can look up grants.
/// The map key is `(pid, process_created_at)` to prevent PID-reuse attacks.
pub struct LaunchGrantRegistry {
    grants: RwLock<HashMap<(u32, u64), LaunchGrant>>,
}

impl LaunchGrantRegistry {
    pub fn new() -> Self {
        Self {
            grants: RwLock::new(HashMap::new()),
        }
    }

    /// Register a launch grant. Panics if `process_created_at` is zero -- a zero
    /// timestamp means `GetProcessTimes` was never called and the grant would be
    /// trivially forgeable via PID reuse.
    pub fn register(&self, grant: LaunchGrant) {
        assert!(
            grant.process_created_at != 0,
            "LaunchGrant.process_created_at must not be zero"
        );
        let key = (grant.root_pid, grant.process_created_at);
        self.grants.write().unwrap().insert(key, grant);
    }

    pub fn revoke(&self, pid: u32, created_at: u64) {
        self.grants.write().unwrap().remove(&(pid, created_at));
    }

    /// Revoke by PID alone — scans all entries. Used by the UI where creation
    /// time is not tracked (best-effort; handles only one grant per PID).
    pub fn revoke_by_pid(&self, pid: u32) {
        let mut g = self.grants.write().unwrap();
        g.retain(|k, _| k.0 != pid);
    }

    pub fn get(&self, pid: u32, created_at: u64) -> Option<LaunchGrant> {
        self.grants.read().unwrap().get(&(pid, created_at)).cloned()
    }

    pub fn clear(&self) {
        self.grants.write().unwrap().clear();
    }

    pub fn list(&self) -> Vec<LaunchGrant> {
        self.grants.read().unwrap().values().cloned().collect()
    }
}

impl Default for LaunchGrantRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-global registry -- initialized once, used from both CLI run.rs and IPC handlers.
static REGISTRY: std::sync::OnceLock<Arc<LaunchGrantRegistry>> = std::sync::OnceLock::new();

pub fn global() -> &'static Arc<LaunchGrantRegistry> {
    REGISTRY.get_or_init(|| Arc::new(LaunchGrantRegistry::new()))
}
