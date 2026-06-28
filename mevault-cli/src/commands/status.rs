use anyhow::Result;
use mevault_core::ipc::{self, ControlRequest};

use crate::commands::unlock::session_file_path;

pub async fn run() -> Result<()> {
    match ipc::send_control(&ControlRequest::Status).await {
        Ok(resp) if resp.ok && resp.active.unwrap_or(false) => {
            let vault = resp.vault_name.as_deref().unwrap_or("?");
            println!("Status: active");
            println!("  Vault: {vault}");
        }
        Ok(_) => {
            // Vault is running but reports locked/expired — clean up stale session file.
            let session_path = session_file_path()?;
            let _ = std::fs::remove_file(&session_path);
            println!("Status: locked");
        }
        Err(_) => {
            // Control pipe not available — no vault running.
            let session_path = session_file_path()?;
            let _ = std::fs::remove_file(&session_path);
            println!("Status: locked (no active vault)");
        }
    }

    Ok(())
}
