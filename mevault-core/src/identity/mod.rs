/// A grant is created at named-pipe connection time and binds the caller's
/// identity to six fields. Every subsequent request re-verifies the grant
/// so that a PID-recycled process cannot impersonate the original caller.
#[derive(Debug, Clone)]
pub struct ProcessGrant {
    pub pid: u32,
    /// Creation timestamp from GetProcessTimes (100-ns intervals since 1601-01-01).
    /// If a process exits and a new one gets the same PID, this value changes.
    pub created_at: u64,
    pub exe_path: std::path::PathBuf,
}

/// RAII wrapper around a Windows Job Object handle.
/// Dropping this struct kills every process assigned to the job
/// (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`). Used in `mevault run` to ensure
/// the child (and any grandchildren it spawned) are terminated when the
/// ephemeral vault session ends or the CLI process crashes.
pub struct JobObject(
    #[cfg(target_os = "windows")]
    windows::Win32::Foundation::HANDLE,
    #[cfg(not(target_os = "windows"))]
    (),
);

// SAFETY: HANDLE is an opaque OS pointer we own exclusively via this struct.
unsafe impl Send for JobObject {}
unsafe impl Sync for JobObject {}

#[cfg(target_os = "windows")]
impl Drop for JobObject {
    fn drop(&mut self) {
        win32::drop_job_object(self.0);
    }
}

/// Hardcoded deny list — never configurable by the user.
pub const ALWAYS_DENY: &[&str] = &[
    "claude.exe",
    "claude-code.exe",
    "copilot.exe",
    "cursor.exe",
    "windsurf.exe",
    "codeium.exe",
    "github-copilot.exe",
];

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exe_path: std::path::PathBuf,
    pub parent_pid: Option<u32>,
    pub parent_exe_path: Option<std::path::PathBuf>,
    pub working_dir: Option<std::path::PathBuf>,
    pub signature_valid: bool,
    pub signature_subject: Option<String>,
}

impl ProcessInfo {
    pub fn exe_name(&self) -> Option<&str> {
        self.exe_path.file_name()?.to_str()
    }

    pub fn is_always_denied(&self) -> bool {
        let name = self.exe_name().unwrap_or("").to_lowercase();
        ALWAYS_DENY.iter().any(|d| d.to_lowercase() == name)
    }
}

/// Returns true if any exe in the chain matches the always-deny list.
pub fn chain_is_denied(chain: &[ProcessInfo]) -> bool {
    chain.iter().any(|p| p.is_always_denied())
}

// Platform-specific implementation lives below.
// Win32 calls will be added in Phase 2.
#[cfg(target_os = "windows")]
mod win32;

#[cfg(target_os = "windows")]
pub use win32::{
    assign_to_job, build_process_chain, create_job_object, find_connection_pid, record_grant,
    terminate_process, verify_grant,
};

#[cfg(not(target_os = "windows"))]
pub fn build_process_chain(_pid: u32) -> anyhow::Result<Vec<ProcessInfo>> {
    anyhow::bail!("process identity is only supported on Windows")
}

#[cfg(not(target_os = "windows"))]
pub fn find_connection_pid(_local: u16, _remote: u16) -> anyhow::Result<u32> {
    anyhow::bail!("find_connection_pid is only supported on Windows")
}

#[cfg(not(target_os = "windows"))]
pub fn terminate_process(_pid: u32) {
    eprintln!("terminate_process not supported on this platform");
}

#[cfg(not(target_os = "windows"))]
pub fn record_grant(_pid: u32) -> anyhow::Result<ProcessGrant> {
    anyhow::bail!("process grants are only supported on Windows")
}

#[cfg(not(target_os = "windows"))]
pub fn verify_grant(_grant: &ProcessGrant) -> bool {
    false
}

#[cfg(not(target_os = "windows"))]
pub fn create_job_object() -> anyhow::Result<JobObject> {
    anyhow::bail!("job objects are only supported on Windows")
}

#[cfg(not(target_os = "windows"))]
pub fn assign_to_job(_job: &JobObject, _pid: u32) -> anyhow::Result<()> {
    anyhow::bail!("job objects are only supported on Windows")
}
