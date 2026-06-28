use super::{JobObject, ProcessGrant, ProcessInfo};
use anyhow::{bail, Context, Result};
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{CloseHandle, FILETIME, HANDLE},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID,
            TCP_TABLE_OWNER_PID_ALL,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW,
                JobObjectExtendedLimitInformation, SetInformationJobObject,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            Threading::{
                GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
                PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_SET_QUOTA, PROCESS_TERMINATE,
            },
        },
    },
};

#[cfg(target_os = "windows")]
pub fn build_process_chain(pid: u32) -> Result<Vec<ProcessInfo>> {
    let mut chain = Vec::new();
    let mut current_pid = pid;

    for _ in 0..6 {
        // Stop at the system idle and system processes.
        if current_pid == 0 || current_pid == 4 {
            break;
        }

        let exe_path = query_exe_path(current_pid)
            .unwrap_or_else(|_| PathBuf::from("<unknown>"));

        let parent_pid = get_parent_pid(current_pid).ok();

        // Code signature check — best-effort, don't fail the chain on error.
        let (signature_valid, signature_subject) =
            verify_signature(&exe_path).unwrap_or((false, None));

        chain.push(ProcessInfo {
            pid: current_pid,
            exe_path,
            parent_pid,
            parent_exe_path: None, // filled in after walking up
            working_dir: None,     // GetProcessImageFileName doesn't give cwd
            signature_valid,
            signature_subject,
        });

        match parent_pid {
            Some(ppid) => current_pid = ppid,
            None => break,
        }
    }

    // Back-fill parent_exe_path for each entry.
    for i in 0..chain.len() {
        if i + 1 < chain.len() {
            let parent_path = chain[i + 1].exe_path.clone();
            chain[i].parent_exe_path = Some(parent_path);
        }
    }

    Ok(chain)
}

/// Find the PID of the process that owns a local TCP connection.
/// Used by the proxy to determine who is making a request.
#[cfg(target_os = "windows")]
pub fn find_connection_pid(local_port: u16, remote_port: u16) -> Result<u32> {
    let mut buf_size: u32 = 0;
    // First call to get required buffer size.
    unsafe {
        GetExtendedTcpTable(
            None,
            &mut buf_size,
            false,
            2, // AF_INET
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    let mut buf = vec![0u8; buf_size as usize];
    let result = unsafe {
        GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as _),
            &mut buf_size,
            false,
            2,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != 0 {
        bail!("GetExtendedTcpTable failed: error {result}");
    }

    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    let rows = unsafe {
        std::slice::from_raw_parts(
            table.table.as_ptr(),
            count,
        )
    };

    for row in rows {
        let row_local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let row_remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
        if row_local_port == local_port && row_remote_port == remote_port {
            return Ok(row.dwOwningPid);
        }
    }

    bail!(
        "no TCP connection found for local:{local_port} remote:{remote_port}"
    )
}

#[cfg(target_os = "windows")]
fn query_exe_path(pid: u32) -> Result<PathBuf> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .context("OpenProcess")?;
        let _guard = HandleGuard(handle);

        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size)
            .context("QueryFullProcessImageNameW")?;

        let path_str = String::from_utf16_lossy(&buf[..size as usize]);
        Ok(PathBuf::from(path_str))
    }
}

#[cfg(target_os = "windows")]
fn get_parent_pid(pid: u32) -> Result<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .context("CreateToolhelp32Snapshot")?;
        let _guard = HandleGuard(snapshot);

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    return Ok(entry.th32ParentProcessID);
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }
    bail!("process {pid} not found in snapshot")
}

#[cfg(target_os = "windows")]
fn verify_signature(path: &PathBuf) -> Result<(bool, Option<String>)> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_DATA_PROVIDER_FLAGS,
        WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };
    use windows::core::GUID;

    let path_wide: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: windows::core::PCWSTR(path_wide.as_ptr()),
        ..Default::default()
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
        ..Default::default()
    };

    // WINTRUST_ACTION_GENERIC_VERIFY_V2
    let mut action_id = GUID {
        data1: 0x00AAC56B,
        data2: 0xCD44,
        data3: 0x11D0,
        data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };

    // WinVerifyTrust takes an optional HWND; null = no UI owner.
    let result = unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action_id,
            &mut trust_data as *mut _ as _,
        )
    };

    // result == 0 means the signature is valid.
    Ok((result == 0, None))
}

// RAII guard to close Win32 handles.
#[cfg(target_os = "windows")]
struct HandleGuard(HANDLE);

#[cfg(target_os = "windows")]
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.0); }
    }
}

/// Create a Windows Job Object with KILL_ON_JOB_CLOSE set.
/// When the returned `JobObject` is dropped, all processes in the job die.
#[cfg(target_os = "windows")]
pub fn create_job_object() -> Result<JobObject> {
    unsafe {
        let handle = CreateJobObjectW(None, windows::core::PCWSTR::null())
            .context("CreateJobObjectW")?;

        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            handle,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .context("SetInformationJobObject")?;

        Ok(JobObject(handle))
    }
}

/// Assign the process at `pid` to `job` so it is contained and will be killed
/// when the job handle is dropped (i.e. when the vault locks).
#[cfg(target_os = "windows")]
pub fn assign_to_job(job: &JobObject, pid: u32) -> Result<()> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, pid)
            .context("OpenProcess for job assignment")?;
        let _guard = HandleGuard(process_handle);
        AssignProcessToJobObject(job.0, process_handle).context("AssignProcessToJobObject")
    }
}

/// Close the Job Object handle — called by `JobObject::drop`.
#[cfg(target_os = "windows")]
pub(super) fn drop_job_object(handle: HANDLE) {
    unsafe { let _ = CloseHandle(handle); }
}

/// Get the process creation time as a 64-bit FILETIME.
/// Returns Err if the process does not exist or cannot be opened.
#[cfg(target_os = "windows")]
fn get_process_creation_time(pid: u32) -> Result<u64> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .context("OpenProcess for creation time")?;
        let _guard = HandleGuard(handle);

        let mut creation = FILETIME::default();
        let mut exit    = FILETIME::default();
        let mut kernel  = FILETIME::default();
        let mut user    = FILETIME::default();

        GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user)
            .context("GetProcessTimes")?;

        // Combine the two 32-bit halves into one 64-bit timestamp.
        Ok(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
    }
}

/// Capture PID + creation time + exe path at pipe-connection time.
/// Call immediately after GetNamedPipeClientProcessId returns.
#[cfg(target_os = "windows")]
pub fn record_grant(pid: u32) -> Result<ProcessGrant> {
    let created_at = get_process_creation_time(pid)
        .context("reading process creation time")?;
    let exe_path = query_exe_path(pid)
        .context("reading process exe path")?;
    Ok(ProcessGrant { pid, created_at, exe_path })
}

/// Re-verify that the process at grant.pid is still the same process that
/// connected. Returns false if the PID has been recycled or the process exited.
/// This is called on every named-pipe request before serving secrets.
#[cfg(target_os = "windows")]
pub fn verify_grant(grant: &ProcessGrant) -> bool {
    match get_process_creation_time(grant.pid) {
        Ok(t) => t == grant.created_at,
        Err(_) => false, // Process exited — PID may have been recycled.
    }
}

/// Send a SIGTERM-equivalent to the given process.
#[cfg(target_os = "windows")]
pub fn terminate_process(pid: u32) {
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
            let _ = TerminateProcess(handle, 0);
            let _ = CloseHandle(handle);
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn build_process_chain(_pid: u32) -> Result<Vec<ProcessInfo>> {
    bail!("process identity is only supported on Windows")
}

#[cfg(not(target_os = "windows"))]
pub fn find_connection_pid(_local: u16, _remote: u16) -> Result<u32> {
    bail!("find_connection_pid is only supported on Windows")
}

#[cfg(not(target_os = "windows"))]
pub fn terminate_process(_pid: u32) {
    eprintln!("terminate_process not supported on this platform");
}
