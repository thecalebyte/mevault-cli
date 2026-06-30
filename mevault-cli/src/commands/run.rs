use anyhow::{bail, Context, Result};
use mevault_core::{
    audit::{AuditEvent, AuditLog, EventType},
    config::{ProcessRule, ProjectConfig, SystemPolicy},
    grants::{self, LaunchGrant},
    ipc::{self, ControlRequest},
    session::{Session, SessionManager},
    vault::VaultStore,
};
use secrecy::ExposeSecret;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::commands::add::prompt_vault_password;

/// `mevault run [--inject-env] <program> [args...]`
///
/// Two modes:
///   1. A session is already running (`mevault unlock`): spawn the child
///      directly -- it uses the named pipes for secrets.
///   2. No session running: unlock inline, start ephemeral pipe servers,
///      place the child in a Job Object, run it, then shut everything down.
///
/// With `--inject-env`, secrets are injected as environment variables instead
/// of being served through the proxy. This is less secure (values visible to
/// child sub-processes) and always requires an inline unlock.
pub async fn run(program: &str, args: &[String], inject_env: bool) -> Result<()> {
    if program.is_empty() {
        bail!("Usage: mevault run <program> [args...]");
    }

    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    // Check for an existing session via the control pipe.
    // --inject-env always uses inline unlock so we have direct vault access.
    if !inject_env
        && matches!(
            ipc::send_control(&ControlRequest::Status).await,
            Ok(resp) if resp.ok && resp.active.unwrap_or(false)
        )
    {
        // Fail-closed: policy must be evaluated even for existing-session runs.
        let allowed_secrets = resolve_allowed_secrets(program, &project_root)?;
        let code = spawn_in_job(program, args, inject_env, allowed_secrets, Uuid::nil()).await?;
        if code != 0 {
            bail!("'{program}' exited with code {code}");
        }
        return Ok(());
    }

    // Inline unlock + ephemeral pipe servers.
    let mut cfg = ProjectConfig::load(&project_root)
        .context("no mevault.toml found -- run `mevault init` first")?;

    SystemPolicy::load().apply_to(&mut cfg.security);

    // Fail-closed: refuse to launch if no process rule matches.
    let allowed_secrets = resolve_allowed_secrets(program, &project_root)?;

    println!("Unlocking vault '{}'…", cfg.project.vault_name);
    let password = prompt_vault_password()?;

    // Unlock vault once -- Argon2 runs here; DEK cached in UnlockedVault.
    let vault = Arc::new(
        VaultStore::new()
            .unlock(&cfg.project.vault_name, &password)
            .context("failed to unlock vault")?,
    );
    let names = vault.secret_names().unwrap_or_default();
    let count = names.len();

    // Collect secrets for env injection before the pipe servers start.
    let env_vars_map: Option<HashMap<String, String>> = if inject_env {
        eprintln!(
            "WARNING --inject-env: secrets will be visible to child sub-processes and in the environment."
        );
        let mut map = HashMap::with_capacity(count);
        for name in &names {
            if let Ok(val) = vault.get_secret(name) {
                map.insert(name.clone(), val.expose_secret().to_owned());
            }
        }
        Some(map)
    } else {
        None
    };

    println!("Found {count} secret(s). Starting runtime pipe...");

    let manager = SessionManager::new();
    let session = Session::new(
        Arc::clone(&vault),
        cfg.session.expiry_mode.clone(),
        Some(cfg.session.expiry_hours),
        std::process::id(),
        project_root.clone(),
    );
    let session_id = session.id;
    let session_id_str = session_id.to_string();
    manager.start(session).await;

    let appdata = std::env::var("APPDATA").context("APPDATA env var not set")?;
    let db_path = PathBuf::from(appdata).join("MeVault").join("audit.db");
    let audit = Arc::new(
        AuditLog::open(&db_path)
            .await
            .context("opening audit log")?,
    );

    audit
        .write(
            AuditEvent::new(EventType::SessionStarted)
                .vault(&cfg.project.vault_name)
                .session(&session_id_str),
        )
        .await?;

    // Runtime pipe + control pipe; both die when the child exits.
    let (kill_tx, mut kill_rx) = mpsc::channel::<()>(1);
    let kill_tx_after_child = kill_tx.clone();

    let (pipe_tx, pipe_rx) = oneshot::channel::<()>();
    let (ctrl_tx, ctrl_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        kill_rx.recv().await;
        let _ = pipe_tx.send(());
        let _ = ctrl_tx.send(());
    });

    // If --inject-env, set the variables in the current process environment so
    // that the child inherits them.  This avoids threading the map through to
    // spawn_in_job (which already inherits the parent env).
    if let Some(ref vars) = env_vars_map {
        for (k, v) in vars {
            std::env::set_var(k, v);
        }
    }

    let pipe_handle = tokio::spawn(ipc::run_pipe_server(
        manager.shared(),
        Arc::clone(&audit),
        Arc::new(cfg.clone()),
        async move {
            let _ = pipe_rx.await;
        },
    ));
    let ctrl_handle = tokio::spawn(ipc::run_control_server(
        manager.shared(),
        kill_tx,
        async move {
            let _ = ctrl_rx.await;
        },
    ));

    // Give pipe servers a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let exit_code = spawn_in_job(program, args, inject_env, allowed_secrets, session_id).await;

    let _ = kill_tx_after_child.send(()).await;
    let _ = pipe_handle.await;
    let _ = ctrl_handle.await;

    manager.end().await;
    audit
        .write(
            AuditEvent::new(EventType::SessionEnded)
                .vault(&cfg.project.vault_name)
                .session(&session_id_str),
        )
        .await?;

    match exit_code {
        Ok(code) if code != 0 => bail!("'{program}' exited with code {code}"),
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Load project config and find the [[process]] rule matching `program`.
/// Returns the list of allowed secret names for that rule.
/// Returns an error if no rule matches (fail-closed policy).
fn resolve_allowed_secrets(program: &str, project_root: &Path) -> Result<Vec<String>> {
    let cfg = ProjectConfig::load(project_root)
        .context("no mevault.toml found — run `mevault init` first")?;

    let matching_rule = cfg.process_rules.iter().find(|r| {
        let resolved = r.resolve_paths(project_root);
        executable_matches(program, Path::new(&resolved.executable))
    });

    let rule = matching_rule.ok_or_else(|| {
        anyhow::anyhow!(
            "no process rule matches '{program}'. Add a [[process]] rule to mevault.toml."
        )
    })?;

    Ok(allowed_secrets_for_rule(rule))
}

fn executable_matches(program: &str, configured: &Path) -> bool {
    let program_path = Path::new(program);

    // A bare command such as `notepad.exe` may match the filename of a fully
    // qualified configured path. If the caller supplied any path components,
    // require the whole path to match so an untrusted lookalike cannot match a
    // trusted executable merely by sharing its filename.
    if program_path.components().count() == 1 {
        return match (program_path.file_name(), configured.file_name()) {
            (Some(actual), Some(expected)) => names_equal(actual, expected),
            _ => false,
        };
    }

    let actual = program_path
        .canonicalize()
        .unwrap_or_else(|_| program_path.to_path_buf());
    let expected = configured
        .canonicalize()
        .unwrap_or_else(|_| configured.to_path_buf());
    paths_equal(&actual, &expected)
}

#[cfg(windows)]
fn names_equal(actual: &std::ffi::OsStr, expected: &std::ffi::OsStr) -> bool {
    actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
}

#[cfg(not(windows))]
fn names_equal(actual: &std::ffi::OsStr, expected: &std::ffi::OsStr) -> bool {
    actual == expected
}

#[cfg(windows)]
fn paths_equal(actual: &Path, expected: &Path) -> bool {
    actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
}

#[cfg(not(windows))]
fn paths_equal(actual: &Path, expected: &Path) -> bool {
    actual == expected
}

fn allowed_secrets_for_rule(rule: &ProcessRule) -> Vec<String> {
    if rule.secrets.iter().any(|secret| secret == "*") && !rule.allow_all_secrets {
        Vec::new()
    } else {
        rule.secrets.clone()
    }
}

// Windows native process launch

/// Search the `PATH` for `program`, trying common Windows executable extensions.
/// Returns the canonicalized path if found, otherwise returns an error.
#[cfg(windows)]
fn resolve_exe(program: &str) -> Result<PathBuf> {
    // If the caller gave an absolute path, just canonicalize it.
    let p = std::path::Path::new(program);
    if p.is_absolute() {
        return p
            .canonicalize()
            .with_context(|| format!("canonicalizing '{program}'"));
    }

    // Try as-is first (covers relative paths and names with extensions).
    if let Ok(canon) = p.canonicalize() {
        return Ok(canon);
    }

    // Walk PATH entries and try common extensions.
    let path_var = std::env::var("PATH").unwrap_or_default();
    let exts = &[".exe", ".cmd", ".bat", ""];
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate = dir.join(format!("{program}{ext}"));
            if candidate.exists() {
                if let Ok(canon) = candidate.canonicalize() {
                    return Ok(canon);
                }
            }
        }
    }

    bail!("could not find '{program}' in PATH")
}

/// RAII guard that terminates and closes a suspended child process on drop.
/// Disarmed by calling `disarm()` once the process is safely running.
#[cfg(windows)]
struct ChildProcessGuard {
    process_handle: windows::Win32::Foundation::HANDLE,
    thread_handle: windows::Win32::Foundation::HANDLE,
    #[allow(dead_code)]
    pid: u32,
    created_at: u64,
    disarmed: bool,
}

#[cfg(windows)]
impl ChildProcessGuard {
    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

#[cfg(windows)]
impl Drop for ChildProcessGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            unsafe {
                use windows::Win32::Foundation::CloseHandle;
                use windows::Win32::System::Threading::TerminateProcess;
                // Terminate if still running (handles suspended-then-failed case).
                TerminateProcess(self.process_handle, 1).ok();
                CloseHandle(self.process_handle).ok();
                CloseHandle(self.thread_handle).ok();
            }
        }
    }
}

/// Owns a Win32 handle and closes it on every return or unwind path.
#[cfg(windows)]
struct CloseHandleGuard(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for CloseHandleGuard {
    fn drop(&mut self) {
        unsafe {
            use windows::Win32::Foundation::CloseHandle;
            CloseHandle(self.0).ok();
        }
    }
}

/// RAII guard that revokes a launch grant from the global registry on drop.
/// Disarmed after a clean child exit to prevent double-revocation.
#[cfg(windows)]
struct GrantGuard {
    pid: u32,
    created_at: u64,
    armed: bool,
}

#[cfg(windows)]
impl GrantGuard {
    fn new(pid: u32, created_at: u64) -> Self {
        Self {
            pid,
            created_at,
            armed: true,
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(windows)]
impl Drop for GrantGuard {
    fn drop(&mut self) {
        if self.armed {
            grants::global().revoke(self.pid, self.created_at);
        }
    }
}

/// Spawn `program` with `args` inside a Job Object, register a launch grant,
/// and wait for it to exit. Returns the process exit code.
#[cfg(windows)]
pub async fn spawn_in_job(
    program: &str,
    args: &[String],
    _inject_env: bool,
    allowed_secrets: Vec<String>,
    session_id: Uuid,
) -> Result<u32> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{FILETIME, WAIT_OBJECT_0};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, GetProcessTimes, ResumeThread, WaitForSingleObject, CREATE_NEW_CONSOLE,
        CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
    };

    // Step 1: Resolve and canonicalize the executable path.
    let exe_path = resolve_exe(program)?;
    let working_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    // Build the command line: "exe" arg1 arg2 ...
    let mut cmd_line = format!("\"{}\"", exe_path.display());
    for arg in args {
        cmd_line.push(' ');
        cmd_line.push_str(arg);
    }
    let mut cmd_line_wide: Vec<u16> = OsStr::new(&cmd_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Step 3: Create the Job Object.
    let job_handle = unsafe {
        CreateJobObjectW(None, windows::core::PCWSTR::null()).context("CreateJobObjectW")?
    };
    let _job_guard = CloseHandleGuard(job_handle);

    // Step 4: Set JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
    let job_result = unsafe {
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job_handle,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    job_result.map_err(|e| anyhow::anyhow!("SetInformationJobObject: {e}"))?;

    // Step 5: Create the child process suspended.
    let creation_flags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP;

    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    let create_result = unsafe {
        CreateProcessW(
            windows::core::PCWSTR::null(), // lpApplicationName -- use command line
            PWSTR(cmd_line_wide.as_mut_ptr()), // lpCommandLine
            None,                          // lpProcessAttributes
            None,                          // lpThreadAttributes
            false,                         // bInheritHandles
            creation_flags,
            None,                          // lpEnvironment -- inherit parent environment
            windows::core::PCWSTR::null(), // lpCurrentDirectory -- inherit
            &si,
            &mut pi,
        )
    };

    create_result.map_err(|e| anyhow::anyhow!("CreateProcessW: {e}"))?;

    // Step 6: PID is in pi.dwProcessId.
    let child_pid = pi.dwProcessId;

    // RAII guard -- terminates the suspended process if anything goes wrong
    // before we disarm it.
    let mut guard = ChildProcessGuard {
        process_handle: pi.hProcess,
        thread_handle: pi.hThread,
        pid: child_pid,
        created_at: 0,
        disarmed: false,
    };

    // Step 7: Get process creation timestamp via GetProcessTimes.
    let created_at_raw: u64 = unsafe {
        let mut creation_time = FILETIME::default();
        let mut exit_time = FILETIME::default();
        let mut kernel_time = FILETIME::default();
        let mut user_time = FILETIME::default();
        GetProcessTimes(
            pi.hProcess,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
        .with_context(|| "GetProcessTimes on child process")?;
        ((creation_time.dwHighDateTime as u64) << 32) | creation_time.dwLowDateTime as u64
    };

    if created_at_raw == 0 {
        return Err(anyhow::anyhow!(
            "GetProcessTimes returned zero creation timestamp"
        ));
    }
    guard.created_at = created_at_raw;

    // Step 8: Assign the child to the Job Object.
    if let Err(e) = unsafe { AssignProcessToJobObject(job_handle, pi.hProcess) } {
        return Err(anyhow::anyhow!("AssignProcessToJobObject: {e}"));
        // guard drops here -> TerminateProcess
    }

    // Step 9: Register the launch grant. GrantGuard revokes it on any
    // subsequent panic or early return, preventing grant leaks.
    let grant = LaunchGrant {
        id: Uuid::new_v4(),
        session_id,
        root_pid: child_pid,
        process_created_at: created_at_raw,
        executable: exe_path.clone(),
        working_directory: working_dir.clone(),
        allowed_secrets: allowed_secrets.into_iter().collect::<HashSet<_>>(),
        created_at: SystemTime::now(),
    };
    grants::global().register(grant);
    let mut grant_guard = GrantGuard::new(child_pid, created_at_raw);

    // Step 10: Resume the primary thread -- child starts executing.
    // ResumeThread returns the previous suspend count, or u32::MAX on error.
    let resume_result = unsafe { ResumeThread(pi.hThread) };
    if resume_result == u32::MAX {
        return Err(anyhow::anyhow!("ResumeThread failed"));
        // grant_guard drops here → revoke
    }

    // Process is now running -- disarm the guard so Drop does NOT terminate it.
    guard.disarm();

    // We still hold the handles; transfer them out of the guard so we can
    // wait and then close them manually.
    // HANDLE is *mut c_void which is not Send, so we transmit the raw pointer
    // value as usize (a Send type) and reconstruct inside the blocking thread.
    let process_raw = guard.process_handle.0 as usize;
    let thread_raw = guard.thread_handle.0 as usize;
    std::mem::forget(guard); // handles are now our responsibility

    // Step 11: Wait for the child to exit (offload to blocking thread).
    let exit_code = tokio::task::spawn_blocking(move || unsafe {
        use windows::Win32::Foundation::HANDLE;
        let process_handle = HANDLE(process_raw as *mut std::ffi::c_void);
        let thread_handle = HANDLE(thread_raw as *mut std::ffi::c_void);
        let _process_guard = CloseHandleGuard(process_handle);
        let _thread_guard = CloseHandleGuard(thread_handle);

        let wait_result = WaitForSingleObject(process_handle, u32::MAX /* INFINITE */);
        if wait_result != WAIT_OBJECT_0 {
            return Err(anyhow::anyhow!(
                "WaitForSingleObject returned unexpected value"
            ));
        }

        // Retrieve exit code.
        let mut code: u32 = 0;
        windows::Win32::System::Threading::GetExitCodeProcess(process_handle, &mut code)
            .map_err(|e| anyhow::anyhow!("GetExitCodeProcess: {e}"))?;

        Ok(code)
    })
    .await
    .context("spawn_blocking for WaitForSingleObject")??;

    // Step 12: Disarm the guard (clean exit) then revoke explicitly.
    grant_guard.disarm();
    grants::global().revoke(child_pid, created_at_raw);

    Ok(exit_code)
}

/// Non-Windows stub -- returns an error immediately.
#[cfg(not(windows))]
pub async fn spawn_in_job(
    program: &str,
    _args: &[String],
    _inject_env: bool,
    _allowed_secrets: Vec<String>,
    _session_id: Uuid,
) -> Result<u32> {
    bail!("spawn_in_job is only supported on Windows (tried to run '{program}')");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(secrets: Vec<&str>, allow_all_secrets: bool) -> ProcessRule {
        ProcessRule {
            name: "test".to_owned(),
            executable: "notepad.exe".to_owned(),
            working_dir: None,
            command: Vec::new(),
            launch_only: true,
            signed: false,
            secrets: secrets.into_iter().map(str::to_owned).collect(),
            allow_all_secrets,
        }
    }

    #[test]
    fn launch_grant_wildcard_requires_explicit_opt_in() {
        assert!(allowed_secrets_for_rule(&rule(vec!["*"], false)).is_empty());
        assert_eq!(
            allowed_secrets_for_rule(&rule(vec!["*"], true)),
            vec!["*".to_owned()]
        );
    }

    #[test]
    fn executable_match_is_not_a_substring_match() {
        assert!(executable_matches(
            "notepad.exe",
            Path::new(r"C:\Windows\System32\notepad.exe")
        ));
        assert!(!executable_matches(
            "notepad.exe",
            Path::new(r"C:\Windows\System32\notepad.exe.backup")
        ));
    }
}
