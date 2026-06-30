use anyhow::{bail, Context, Result};
use mevault_core::ipc::{self, ControlRequest};

pub async fn run() -> Result<()> {
    let resp = ipc::send_control(&ControlRequest::Lock)
        .await
        .context("could not connect to vault control pipe — is the vault unlocked?")?;

    if resp.ok {
        println!("Vault locked.");
        Ok(())
    } else {
        bail!(
            "lock failed: {}",
            resp.error.unwrap_or_else(|| "unknown error".to_owned())
        )
    }
}
