use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ── Project config (mevault.toml in project root) ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRule {
    pub name: String,
    /// Path to executable. Supports ${PROJECT_ROOT} variable.
    pub executable: String,
    /// Expected working directory. Supports ${PROJECT_ROOT}.
    #[serde(default)]
    pub working_dir: Option<String>,
    /// Expected command arguments (after the executable).
    #[serde(default)]
    pub command: Vec<String>,
    /// If true, only allow access when launched via `mevault run` (in a Job Object).
    #[serde(default = "bool_true")]
    pub launch_only: bool,
    /// Whether to require the executable to be signed.
    #[serde(default)]
    pub signed: bool,
    /// Explicit list of secrets this process may access. Empty = no access.
    pub secrets: Vec<String>,
    /// Explicit opt-in required when `secrets` contains `"*"`.
    /// Without this flag, a wildcard entry is treated as a misconfiguration and
    /// grants *no* access (fail-closed). Set to `true` only when you genuinely
    /// want to allow the process to access every secret in the vault.
    #[serde(default)]
    pub allow_all_secrets: bool,
}

impl ProcessRule {
    pub fn resolve_paths(&self, project_root: &std::path::Path) -> ProcessRule {
        let root = project_root.to_string_lossy();
        let resolve = |s: &str| s.replace("${PROJECT_ROOT}", &root);
        ProcessRule {
            name: self.name.clone(),
            executable: resolve(&self.executable),
            working_dir: self.working_dir.as_deref().map(resolve),
            command: self.command.clone(),
            launch_only: self.launch_only,
            signed: self.signed,
            secrets: self.secrets.clone(),
            allow_all_secrets: self.allow_all_secrets,
        }
    }

    /// Check if this rule permits access to `secret_name`.
    ///
    /// Wildcard access (`secrets = ["*"]`) requires explicit double opt-in via
    /// `allow_all_secrets = true`. Without it the wildcard is treated as a
    /// misconfiguration and the rule grants *no* access (fail-closed).
    pub fn allows_secret(&self, secret_name: &str) -> bool {
        if self.secrets.iter().any(|s| s == "*") {
            // Wildcard requires explicit double opt-in.
            if !self.allow_all_secrets {
                return false;
            }
            return true;
        }
        self.secrets.iter().any(|s| s == secret_name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub project: ProjectMeta,
    pub session: SessionConfig,
    pub security: SecurityConfig,
    #[serde(default)]
    pub allow_list: AllowListConfig,
    #[serde(default)]
    pub deny_list: DenyListConfig,
    #[serde(default, rename = "process")]
    pub process_rules: Vec<ProcessRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub name: String,
    pub vault_name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    #[serde(default = "default_expiry_mode")]
    pub expiry_mode: ExpiryMode,
    #[serde(default = "default_expiry_hours")]
    pub expiry_hours: u32,
}

fn default_expiry_mode() -> ExpiryMode {
    ExpiryMode::Both
}
fn default_expiry_hours() -> u32 {
    8
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryMode {
    Terminal,
    Time,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_unknown_process_mode")]
    pub unknown_process_mode: UnknownProcessMode,
    /// Verify caller identity via Win32 before serving secrets.
    /// Set to false in tests / development to skip the TCP table lookup.
    #[serde(default = "bool_true")]
    pub require_identity_check: bool,
    #[serde(default = "bool_true")]
    pub require_signature_check: bool,
    #[serde(default = "bool_true")]
    pub require_parent_check: bool,
    #[serde(default = "bool_true")]
    pub require_working_dir_check: bool,
    /// Allow `mevault get --reveal` to display a secret value in the terminal.
    /// Defaults to false; user must explicitly opt in by setting this to true.
    #[serde(default)]
    pub allow_cli_reveal: bool,
}

fn default_unknown_process_mode() -> UnknownProcessMode {
    UnknownProcessMode::DenyAndLog
}
fn bool_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UnknownProcessMode {
    DenyAndLog,
    LockAll,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllowListConfig {
    #[serde(default)]
    pub rules: Vec<AllowRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowRule {
    pub name: String,
    pub exe_path: String,
    #[serde(default)]
    pub parent_not: Vec<String>,
    pub working_dir: Option<String>,
    #[serde(default = "bool_true")]
    pub signed: bool,
    pub secrets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyListConfig {
    #[serde(default = "default_always_deny")]
    pub always_deny: Vec<String>,
}

impl Default for DenyListConfig {
    fn default() -> Self {
        Self {
            always_deny: default_always_deny(),
        }
    }
}

fn default_always_deny() -> Vec<String> {
    vec![
        "claude.exe".into(),
        "claude-code.exe".into(),
        "copilot.exe".into(),
        "cursor.exe".into(),
        "windsurf.exe".into(),
        "codeium.exe".into(),
        "github-copilot.exe".into(),
    ]
}

impl ProjectConfig {
    pub fn load(project_root: &Path) -> Result<Self> {
        let path = project_root.join("mevault.toml");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, project_root: &Path) -> Result<()> {
        let path = project_root.join("mevault.toml");
        let text = toml::to_string_pretty(self).context("serializing project config")?;
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))
    }

    pub fn new(name: impl Into<String>, vault_name: impl Into<String>) -> Self {
        Self {
            project: ProjectMeta {
                name: name.into(),
                vault_name: vault_name.into(),
                created_at: chrono::Utc::now().to_rfc3339(),
            },
            session: SessionConfig {
                expiry_mode: ExpiryMode::Both,
                expiry_hours: 8,
            },
            security: SecurityConfig {
                unknown_process_mode: UnknownProcessMode::DenyAndLog,
                require_identity_check: true,
                require_signature_check: true,
                require_parent_check: true,
                require_working_dir_check: true,
                allow_cli_reveal: false,
            },
            allow_list: AllowListConfig {
                rules: default_allow_rules(),
            },
            deny_list: DenyListConfig::default(),
            process_rules: vec![],
        }
    }
}

fn default_allow_rules() -> Vec<AllowRule> {
    vec![
        AllowRule {
            name: "uvicorn".into(),
            exe_path: "**\\uvicorn.exe".into(),
            parent_not: vec![
                "claude.exe".into(),
                "cursor.exe".into(),
                "windsurf.exe".into(),
                "copilot.exe".into(),
            ],
            working_dir: Some("${PROJECT_ROOT}".into()),
            signed: true,
            secrets: vec!["*".into()],
        },
        AllowRule {
            name: "node".into(),
            exe_path: "**\\node.exe".into(),
            parent_not: vec![
                "claude.exe".into(),
                "cursor.exe".into(),
                "windsurf.exe".into(),
            ],
            working_dir: Some("${PROJECT_ROOT}".into()),
            signed: true,
            secrets: vec!["*".into()],
        },
    ]
}

// ── System policy (%ProgramData%\MeVault\policy.toml) ────────────────────
//
// Written by an administrator; requires elevated rights to change.
// Overrides the per-project mevault.toml security settings so that no
// project (or AI agent that edits mevault.toml) can weaken them.

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemPolicy {
    /// If Some(true), always enforce identity checking regardless of project config.
    /// An admin sets this to prevent projects from disabling the identity check.
    pub require_identity_check: Option<bool>,
    /// If Some(true), always enforce signature checking.
    pub require_signature_check: Option<bool>,
    /// Supplemental exe names added by the admin to the always-deny list.
    #[serde(default)]
    pub extra_deny_list: Vec<String>,
}

impl SystemPolicy {
    /// Load from `%ProgramData%\MeVault\policy.toml`.
    /// Returns a default (all-None, empty) policy if the file is absent or unreadable.
    pub fn load() -> Self {
        let program_data =
            std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_owned());
        let path = std::path::PathBuf::from(program_data)
            .join("MeVault")
            .join("policy.toml");

        if !path.exists() {
            return Self::default();
        }

        match std::fs::read_to_string(&path) {
            Ok(content) => toml::from_str(&content).unwrap_or_else(|e| {
                tracing::warn!("failed to parse system policy {}: {e}", path.display());
                Self::default()
            }),
            Err(e) => {
                tracing::warn!("failed to read system policy {}: {e}", path.display());
                Self::default()
            }
        }
    }

    /// Apply the system policy to a project security config, overriding any
    /// settings that the policy locks down. Call after loading ProjectConfig.
    pub fn apply_to(&self, security: &mut SecurityConfig) {
        if let Some(v) = self.require_identity_check {
            security.require_identity_check = v;
        }
        if let Some(v) = self.require_signature_check {
            security.require_signature_check = v;
        }
    }
}

// ── Global app config (%APPDATA%\MeVault\config.toml) ─────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub app: AppMeta,
    pub auth: AuthConfig,
    pub updates: UpdatesConfig,
    pub proxy: ProxyConfig,
    pub notifications: NotificationsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppMeta {
    pub version: String,
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default)]
    pub first_run_complete: bool,
}

fn default_theme() -> String {
    "system".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub biometrics_enabled: bool,
    #[serde(default = "default_biometrics_type")]
    pub biometrics_type: String,
}

fn default_biometrics_type() -> String {
    "none".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatesConfig {
    #[serde(default = "bool_true")]
    pub auto_download: bool,
    #[serde(default = "default_channel")]
    pub channel: String,
    pub last_checked: Option<String>,
}

fn default_channel() -> String {
    "stable".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    #[serde(default = "default_proxy_bind")]
    pub bind: String,
}

fn default_proxy_port() -> u16 {
    52731
}
fn default_proxy_bind() -> String {
    "127.0.0.1".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationsConfig {
    #[serde(default = "bool_true")]
    pub unknown_process_notify: bool,
    #[serde(default = "default_warn_minutes")]
    pub session_expiry_warn_minutes: u32,
}

fn default_warn_minutes() -> u32 {
    5
}

impl AppConfig {
    pub fn app_dir() -> Result<PathBuf> {
        let appdata = std::env::var("APPDATA").context("APPDATA env var not set")?;
        Ok(PathBuf::from(appdata).join("MeVault"))
    }

    pub fn config_path() -> Result<PathBuf> {
        Ok(Self::app_dir()?.join("config.toml"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn load_or_default() -> Result<Self> {
        match Self::load() {
            Ok(cfg) => Ok(cfg),
            Err(_) => Ok(Self::default()),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self).context("serializing app config")?;
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            app: AppMeta {
                version: env!("CARGO_PKG_VERSION").into(),
                theme: "system".into(),
                first_run_complete: false,
            },
            auth: AuthConfig::default(),
            updates: UpdatesConfig {
                auto_download: true,
                channel: "stable".into(),
                last_checked: None,
            },
            proxy: ProxyConfig {
                port: 52731,
                bind: "127.0.0.1".into(),
            },
            notifications: NotificationsConfig {
                unknown_process_notify: true,
                session_expiry_warn_minutes: 5,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_config_roundtrip() {
        let cfg = ProjectConfig::new("TestProject", "TestProject");
        let text = toml::to_string_pretty(&cfg).unwrap();
        let parsed: ProjectConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.project.name, "TestProject");
        assert_eq!(parsed.project.vault_name, "TestProject");
        assert_eq!(parsed.session.expiry_hours, 8);
        assert_eq!(parsed.deny_list.always_deny.len(), 7);
    }

    #[test]
    fn app_config_roundtrip() {
        let cfg = AppConfig::default();
        let text = toml::to_string_pretty(&cfg).unwrap();
        let parsed: AppConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.proxy.port, 52731);
        assert_eq!(parsed.proxy.bind, "127.0.0.1");
    }

    #[test]
    fn allows_secret_exact_match() {
        let rule = ProcessRule {
            name: "myapp".into(),
            executable: "myapp.exe".into(),
            working_dir: None,
            command: vec![],
            launch_only: true,
            signed: false,
            secrets: vec!["DB_URL".into(), "API_KEY".into()],
            allow_all_secrets: false,
        };
        assert!(rule.allows_secret("DB_URL"));
        assert!(rule.allows_secret("API_KEY"));
        assert!(!rule.allows_secret("STRIPE_KEY"));
    }

    #[test]
    fn allows_secret_wildcard_requires_double_optin() {
        // Wildcard without allow_all_secrets: deny (fail-closed)
        let rule_no_optin = ProcessRule {
            name: "myapp".into(),
            executable: "myapp.exe".into(),
            working_dir: None,
            command: vec![],
            launch_only: true,
            signed: false,
            secrets: vec!["*".into()],
            allow_all_secrets: false,
        };
        assert!(
            !rule_no_optin.allows_secret("DB_URL"),
            "wildcard without allow_all_secrets must deny"
        );
        assert!(
            !rule_no_optin.allows_secret("anything"),
            "wildcard without allow_all_secrets must deny"
        );

        // Wildcard WITH allow_all_secrets: allow
        let rule_optin = ProcessRule {
            allow_all_secrets: true,
            ..rule_no_optin
        };
        assert!(
            rule_optin.allows_secret("DB_URL"),
            "wildcard with allow_all_secrets must allow"
        );
        assert!(
            rule_optin.allows_secret("anything"),
            "wildcard with allow_all_secrets must allow"
        );
    }

    #[test]
    fn process_rule_deny_unknown_fields() {
        // Valid TOML with unknown field should fail to parse.
        let toml = r#"
name = "myapp"
executable = "myapp.exe"
secrets = ["DB_URL"]
unknown_field = "bad"
"#;
        let result: Result<ProcessRule, _> = toml::from_str(toml);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown keys"
        );
    }
}
