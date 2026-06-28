use anyhow::{bail, Context, Result};
use secrecy::{ExposeSecret, SecretString};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Thin wrapper over PowerShell SecretManagement / SecretStore.
///
/// Security invariant: secret values are embedded in stdin, never in command-line args.
/// PS single-quoted strings are used so `'` is the only character that needs escaping (`''`).
pub struct SecretStoreBridge {
    ps_path: PathBuf,
}

impl SecretStoreBridge {
    pub fn new() -> Self {
        Self {
            ps_path: PathBuf::from(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ),
        }
    }

    // ── Module management ──────────────────────────────────────────────────

    pub fn check_modules(&self) -> Result<bool> {
        let out = self.run_ps(
            r#"
            $sm = Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement
            $ss = Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretStore
            if ($sm -and $ss) { 'true' } else { 'false' }
            "#,
            &[],
        )?;
        Ok(out.trim() == "true")
    }

    pub fn install_modules(&self) -> Result<()> {
        self.run_ps(
            r#"
            Install-Module Microsoft.PowerShell.SecretManagement -Force -Scope CurrentUser
            Install-Module Microsoft.PowerShell.SecretStore      -Force -Scope CurrentUser
            "#,
            &[],
        )
        .context("installing SecretManagement modules")?;
        Ok(())
    }

    // ── Vault lifecycle ────────────────────────────────────────────────────

    /// Create and configure a new SecretStore vault.
    ///
    /// Uses `Reset-SecretStore` to properly initialize the SecretStore with the given
    /// password, then registers the named vault.  `Set-SecretStoreConfiguration` alone
    /// does not correctly initialize a fresh SecretStore — it creates a corrupted state
    /// where subsequent `Unlock-SecretStore` calls fail with an integrity error.
    ///
    /// WARNING: `Reset-SecretStore -Force` clears any pre-existing secrets in the store.
    /// On a truly fresh install there are none, so this is safe.  Phase 2 will add a
    /// check that warns the user before overwriting an existing store.
    pub fn create_vault(&self, vault_name: &str, password: &SecretString) -> Result<()> {
        let script = format!(
            r#"
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
            Import-Module Microsoft.PowerShell.SecretStore      -ErrorAction Stop
            $secure = ConvertTo-SecureString -String $mevault_pw -AsPlainText -Force
            # Reset-SecretStore properly initialises the store so that
            # Unlock-SecretStore works in subsequent PS subprocesses.
            # -Force suppresses the confirmation prompt.
            Reset-SecretStore `
                -Authentication Password `
                -Password $secure `
                -Interaction None `
                -Force `
                -ErrorAction Stop
            # Register the vault if it is not already registered.
            $existing = Get-SecretVault -Name '{vault_name}' -ErrorAction SilentlyContinue
            if (-not $existing) {{
                Register-SecretVault `
                    -Name '{vault_name}' `
                    -ModuleName Microsoft.PowerShell.SecretStore `
                    -ErrorAction Stop
            }}
            "#,
            vault_name = vault_name
        );
        self.run_ps(&script, &[("mevault_pw", password.expose_secret())])
            .with_context(|| format!("creating vault '{vault_name}'"))?;
        Ok(())
    }

    /// Unlock the SecretStore for subsequent operations in the same PS session.
    /// Note: SecretStore caches the unlock state for its PasswordTimeout window
    /// (default 15 min), so operations within that window don't need re-authentication.
    pub fn unlock_vault(&self, password: &SecretString) -> Result<()> {
        self.run_ps(
            r#"
            Import-Module Microsoft.PowerShell.SecretStore -ErrorAction Stop
            $secure = ConvertTo-SecureString -String $mevault_pw -AsPlainText -Force
            Unlock-SecretStore -Password $secure -ErrorAction Stop
            "#,
            &[("mevault_pw", password.expose_secret())],
        )
        .context("unlocking SecretStore")?;
        Ok(())
    }

    // ── Secret CRUD ────────────────────────────────────────────────────────

    /// Store a secret. Provide `unlock_password` when the vault is locked.
    /// For Phase 2 proxy usage, call `unlock_vault` once per session instead.
    pub fn set_secret(
        &self,
        name: &str,
        value: &SecretString,
        vault_name: &str,
        unlock_password: Option<&SecretString>,
    ) -> Result<()> {
        let (script, vars): (String, Vec<(&str, &str)>) = match unlock_password {
            Some(pw) => (
                format!(
                    r#"
                    Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
                    Import-Module Microsoft.PowerShell.SecretStore      -ErrorAction Stop
                    $secure = ConvertTo-SecureString -String $mevault_pw -AsPlainText -Force
                    Unlock-SecretStore -Password $secure -ErrorAction Stop
                    Set-Secret -Name '{name}' -Secret $mevault_val -Vault '{vault_name}' -ErrorAction Stop
                    "#,
                    name = name,
                    vault_name = vault_name
                ),
                vec![
                    ("mevault_pw", pw.expose_secret()),
                    ("mevault_val", value.expose_secret()),
                ],
            ),
            None => (
                format!(
                    r#"
                    Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
                    Set-Secret -Name '{name}' -Secret $mevault_val -Vault '{vault_name}' -ErrorAction Stop
                    "#,
                    name = name,
                    vault_name = vault_name
                ),
                vec![("mevault_val", value.expose_secret())],
            ),
        };
        self.run_ps(&script, &vars)
            .with_context(|| format!("setting secret '{name}' in vault '{vault_name}'"))?;
        Ok(())
    }

    /// Fetch a secret value. Provide `unlock_password` when the vault is locked.
    pub fn get_secret(
        &self,
        name: &str,
        vault_name: &str,
        unlock_password: Option<&SecretString>,
    ) -> Result<SecretString> {
        let (script, vars): (String, Vec<(&str, &str)>) = match unlock_password {
            Some(pw) => (
                format!(
                    r#"
                    Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
                    Import-Module Microsoft.PowerShell.SecretStore      -ErrorAction Stop
                    $secure = ConvertTo-SecureString -String $mevault_pw -AsPlainText -Force
                    Unlock-SecretStore -Password $secure -ErrorAction Stop
                    Write-Output (Get-Secret -Name '{name}' -Vault '{vault_name}' -AsPlainText -ErrorAction Stop)
                    "#,
                    name = name,
                    vault_name = vault_name
                ),
                vec![("mevault_pw", pw.expose_secret())],
            ),
            None => (
                format!(
                    r#"
                    Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
                    Write-Output (Get-Secret -Name '{name}' -Vault '{vault_name}' -AsPlainText -ErrorAction Stop)
                    "#,
                    name = name,
                    vault_name = vault_name
                ),
                vec![],
            ),
        };
        let raw = self
            .run_ps(&script, &vars)
            .with_context(|| format!("getting secret '{name}' from vault '{vault_name}'"))?;
        Ok(SecretString::new(raw.trim().to_owned().into()))
    }

    /// Unlock the vault and return only the secret names — no values loaded.
    ///
    /// This is the v2 unlock path used with lazy decryption: the vault password
    /// is kept in `Session`; individual secrets are decrypted per-request.
    /// One PowerShell subprocess is spawned (unlock + list in a single call).
    pub fn unlock_and_list_names(
        &self,
        vault_name: &str,
        password: &SecretString,
    ) -> Result<Vec<String>> {
        let script = format!(
            r#"
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
            Import-Module Microsoft.PowerShell.SecretStore      -ErrorAction Stop
            $secure = ConvertTo-SecureString -String $mevault_pw -AsPlainText -Force
            Unlock-SecretStore -Password $secure -ErrorAction Stop
            Get-SecretInfo -Vault '{vault_name}' | ForEach-Object {{ $_.Name }}
            "#,
            vault_name = vault_name,
        );
        let out = self
            .run_ps(&script, &[("mevault_pw", password.expose_secret())])
            .with_context(|| format!("unlocking vault '{vault_name}' and listing names"))?;
        Ok(out.lines().map(|l| l.trim().to_owned()).filter(|l| !l.is_empty()).collect())
    }

    /// Unlock the vault and load ALL secrets into memory in one PS subprocess.
    ///
    /// This is the Phase 2 unlock path: the proxy serves secrets from the returned
    /// HashMap without further PS calls. SecretString zeroizes on drop.
    pub fn unlock_and_preload(
        &self,
        vault_name: &str,
        password: &SecretString,
    ) -> Result<std::collections::HashMap<String, SecretString>> {
        // Single PS script: unlock, iterate all secrets, output JSON.
        // Using ConvertTo-Json so values with '=', quotes, or newlines are safe.
        let script = format!(
            r#"
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
            Import-Module Microsoft.PowerShell.SecretStore      -ErrorAction Stop
            $secure = ConvertTo-SecureString -String $mevault_pw -AsPlainText -Force
            Unlock-SecretStore -Password $secure -ErrorAction Stop
            $result = @{{}}
            Get-SecretInfo -Vault '{vault_name}' | ForEach-Object {{
                $result[$_.Name] = (Get-Secret -Name $_.Name -Vault '{vault_name}' -AsPlainText)
            }}
            $result | ConvertTo-Json -Compress
            "#,
            vault_name = vault_name
        );

        let json = self
            .run_ps(&script, &[("mevault_pw", password.expose_secret())])
            .with_context(|| format!("unlocking and preloading vault '{vault_name}'"))?;

        let json = json.trim();
        if json.is_empty() || json == "null" {
            return Ok(std::collections::HashMap::new());
        }

        let raw: serde_json::Value =
            serde_json::from_str(json).context("parsing preloaded secrets JSON")?;

        let mut map = std::collections::HashMap::new();
        if let Some(obj) = raw.as_object() {
            for (key, val) in obj {
                if let Some(s) = val.as_str() {
                    map.insert(key.clone(), SecretString::new(s.to_owned().into()));
                }
            }
        }
        Ok(map)
    }

    pub fn remove_secret(
        &self,
        name: &str,
        vault_name: &str,
        unlock_password: Option<&SecretString>,
    ) -> Result<()> {
        let (script, vars): (String, Vec<(&str, &str)>) = match unlock_password {
            Some(pw) => (
                format!(
                    r#"
                    Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
                    Import-Module Microsoft.PowerShell.SecretStore      -ErrorAction Stop
                    $secure = ConvertTo-SecureString -String $mevault_pw -AsPlainText -Force
                    Unlock-SecretStore -Password $secure -ErrorAction Stop
                    Remove-Secret -Name '{name}' -Vault '{vault_name}' -ErrorAction Stop
                    "#,
                    name = name,
                    vault_name = vault_name
                ),
                vec![("mevault_pw", pw.expose_secret())],
            ),
            None => (
                format!(
                    r#"
                    Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
                    Remove-Secret -Name '{name}' -Vault '{vault_name}' -ErrorAction Stop
                    "#,
                    name = name,
                    vault_name = vault_name
                ),
                vec![],
            ),
        };
        self.run_ps(&script, &vars)
            .with_context(|| format!("removing secret '{name}' from vault '{vault_name}'"))?;
        Ok(())
    }

    /// List secret metadata. Provide `unlock_password` when the vault is locked.
    /// Note: `Get-SecretInfo` returns metadata (name/type), not values. On some
    /// SecretStore configurations it works without unlocking; if it fails with a
    /// vault-locked error the caller should retry with a password.
    pub fn list_secrets(
        &self,
        vault_name: &str,
        unlock_password: Option<&SecretString>,
    ) -> Result<Vec<SecretInfo>> {
        let (script, vars): (String, Vec<(&str, &str)>) = match unlock_password {
            Some(pw) => (
                format!(
                    r#"
                    Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
                    Import-Module Microsoft.PowerShell.SecretStore      -ErrorAction Stop
                    $secure = ConvertTo-SecureString -String $mevault_pw -AsPlainText -Force
                    Unlock-SecretStore -Password $secure -ErrorAction Stop
                    Get-SecretInfo -Vault '{vault_name}' | ForEach-Object {{ "$($_.Name)|$($_.Type)" }}
                    "#,
                    vault_name = vault_name
                ),
                vec![("mevault_pw", pw.expose_secret())],
            ),
            None => (
                format!(
                    r#"
                    Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
                    Get-SecretInfo -Vault '{vault_name}' | ForEach-Object {{ "$($_.Name)|$($_.Type)" }}
                    "#,
                    vault_name = vault_name
                ),
                vec![],
            ),
        };
        let out = self
            .run_ps(&script, &vars)
            .with_context(|| format!("listing secrets in vault '{vault_name}'"))?;

        let secrets = out
            .lines()
            .filter(|l| !l.is_empty())
            .map(|line| {
                let mut parts = line.splitn(2, '|');
                SecretInfo {
                    name: parts.next().unwrap_or("").trim().to_owned(),
                    kind: parts.next().unwrap_or("String").trim().to_owned(),
                }
            })
            .collect();

        Ok(secrets)
    }

    pub fn list_vaults(&self) -> Result<Vec<String>> {
        let out = self.run_ps(
            r#"
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
            Get-SecretVault | Select-Object -ExpandProperty Name
            "#,
            &[],
        )?;
        Ok(out
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect())
    }

    pub fn vault_exists(&self, vault_name: &str) -> Result<bool> {
        let script = format!(
            r#"
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
            $v = Get-SecretVault -Name '{vault_name}' -ErrorAction SilentlyContinue
            if ($v) {{ 'true' }} else {{ 'false' }}
            "#,
            vault_name = vault_name
        );
        let out = self.run_ps(&script, &[])?;
        Ok(out.trim() == "true")
    }

    // ── Internal ───────────────────────────────────────────────────────────

    /// Run a PowerShell script, optionally embedding named secret variables.
    ///
    /// Each entry in `vars` becomes a PS variable assignment prepended to the script:
    ///   `$name = 'value'`   (single-quote escaped — safe for arbitrary string content)
    ///
    /// This keeps values out of command-line arguments (which would be visible in the
    /// process list) and out of the value/script interleaving that the old `$input`
    /// approach attempted.
    fn run_ps(&self, script: &str, vars: &[(&str, &str)]) -> Result<String> {
        // Build preamble: one PS variable assignment per entry.
        let mut preamble = String::new();
        for (name, val) in vars {
            // In PS single-quoted strings, the only escape is '' for a literal '.
            let escaped = val.replace('\'', "''");
            preamble.push_str(&format!("${name} = '{escaped}'\n"));
        }
        let full_script = format!("{preamble}{script}");

        let mut child = Command::new(&self.ps_path)
            .args([
                "-NonInteractive",
                "-NoProfile",
                "-WindowStyle",
                "Hidden",
                "-Command",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning PowerShell")?;

        let stdin = child.stdin.take().expect("stdin configured");
        {
            let mut w = std::io::BufWriter::new(stdin);
            w.write_all(full_script.as_bytes())
                .context("writing script to PowerShell stdin")?;
        }

        let out = child
            .wait_with_output()
            .context("waiting for PowerShell process")?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            bail!(
                "PowerShell exited {}: {}{}",
                out.status.code().unwrap_or(-1),
                stderr.trim(),
                if stdout.trim().is_empty() {
                    String::new()
                } else {
                    format!("\n{}", stdout.trim())
                }
            );
        }

        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl Default for SecretStoreBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct SecretInfo {
    pub name: String,
    pub kind: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that run_ps embeds variables correctly and the script can read them.
    /// This test does not touch SecretStore — it only checks the PS invocation plumbing.
    #[test]
    #[cfg(target_os = "windows")]
    fn run_ps_variable_embedding() {
        let bridge = SecretStoreBridge::new();
        let out = bridge
            .run_ps("Write-Output $mevault_val", &[("mevault_val", "hello world")])
            .expect("PS invocation failed");
        assert_eq!(out.trim(), "hello world");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn run_ps_single_quote_escape() {
        let bridge = SecretStoreBridge::new();
        let tricky = "it's a test";
        let out = bridge
            .run_ps("Write-Output $mevault_val", &[("mevault_val", tricky)])
            .expect("PS invocation failed");
        assert_eq!(out.trim(), tricky);
    }
}
