use crate::config::{AllowRule, ProjectConfig};
use crate::identity::{chain_is_denied, ProcessInfo};
use std::path::{Path, PathBuf};

/// Outcome of an allow-list check.
#[derive(Debug, Clone, PartialEq)]
pub enum AccessDecision {
    Allow,
    Deny { reason: String },
}

impl AccessDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn reason(&self) -> &str {
        match self {
            Self::Allow => "allow_list match",
            Self::Deny { reason } => reason,
        }
    }
}

/// Check whether a process chain is permitted to access a named secret.
///
/// Order of checks (mirrors the proxy flow in the design doc):
/// 1. Always-deny list — hardcoded, cannot be overridden.
/// 2. Project allow-list rules.
/// 3. Unknown process mode — deny or lock.
pub fn check_access(
    chain: &[ProcessInfo],
    secret_name: &str,
    config: &ProjectConfig,
    project_root: &Path,
) -> AccessDecision {
    let requester = match chain.first() {
        Some(p) => p,
        None => {
            return AccessDecision::Deny {
                reason: "empty process chain".into(),
            }
        }
    };

    // ── 1. Always-deny ────────────────────────────────────────────────────
    if chain_is_denied(chain) {
        let denied_name = chain
            .iter()
            .find(|p| p.is_always_denied())
            .and_then(|p| p.exe_name())
            .unwrap_or("unknown");
        return AccessDecision::Deny {
            reason: format!("always_deny: {denied_name}"),
        };
    }

    // ── 2. Allow-list rules ───────────────────────────────────────────────
    if config.security.require_signature_check && !requester.signature_valid {
        return AccessDecision::Deny {
            reason: format!("signature_invalid: {}", requester.exe_path.display()),
        };
    }

    for rule in &config.allow_list.rules {
        if rule_matches(rule, chain, secret_name, project_root, config) {
            return AccessDecision::Allow;
        }
    }

    // ── 3. No matching rule — unknown process mode ─────────────────────────
    use crate::config::UnknownProcessMode;
    let exe = requester.exe_name().unwrap_or("unknown");
    match config.security.unknown_process_mode {
        UnknownProcessMode::DenyAndLog => AccessDecision::Deny {
            reason: format!("not_in_allow_list: {exe}"),
        },
        UnknownProcessMode::LockAll => AccessDecision::Deny {
            reason: format!("lock_all: not_in_allow_list: {exe}"),
        },
    }
}

fn rule_matches(
    rule: &AllowRule,
    chain: &[ProcessInfo],
    secret_name: &str,
    project_root: &Path,
    config: &ProjectConfig,
) -> bool {
    let requester = &chain[0];

    // exe_path glob match
    if !glob_match(&rule.exe_path, &requester.exe_path.to_string_lossy()) {
        return false;
    }

    // parent_not: deny if any ancestor matches a forbidden exe name
    if config.security.require_parent_check {
        for forbidden in &rule.parent_not {
            for ancestor in chain.iter().skip(1) {
                if let Some(name) = ancestor.exe_name() {
                    if name.eq_ignore_ascii_case(forbidden) {
                        return false;
                    }
                }
            }
        }
    }

    // working_dir check
    if config.security.require_working_dir_check {
        if let Some(required_dir) = &rule.working_dir {
            let required = resolve_dir(required_dir, project_root);
            if let Some(cwd) = &requester.working_dir {
                if !paths_match(&required, cwd) {
                    return false;
                }
            }
            // If we can't determine cwd, skip the check (working_dir is best-effort in Phase 2).
        }
    }

    // secrets: "*" means all, otherwise exact match
    if !rule.secrets.iter().any(|s| s == "*" || s == secret_name) {
        return false;
    }

    true
}

/// Simple glob: supports `**\` prefix patterns (Windows path separator).
/// Only `*` and `**` wildcards are supported for now.
fn glob_match(pattern: &str, path: &str) -> bool {
    use glob::Pattern;
    // Normalise separators to forward slash for glob matching.
    let pat = pattern.replace('\\', "/");
    let p = path.replace('\\', "/");
    Pattern::new(&pat).map(|g| g.matches(&p)).unwrap_or(false)
}

fn resolve_dir(dir: &str, project_root: &Path) -> PathBuf {
    let resolved = dir.replace("${PROJECT_ROOT}", &project_root.to_string_lossy());
    PathBuf::from(resolved)
}

fn paths_match(a: &Path, b: &Path) -> bool {
    // Case-insensitive on Windows.
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AllowListConfig, AllowRule, DenyListConfig, ExpiryMode, ProjectConfig, ProjectMeta,
        SecurityConfig, SessionConfig, UnknownProcessMode,
    };
    use std::path::PathBuf;

    fn make_process(exe: &str, signed: bool) -> ProcessInfo {
        ProcessInfo {
            pid: 1000,
            exe_path: PathBuf::from(format!(r"C:\Python39\{exe}")),
            parent_pid: Some(500),
            parent_exe_path: Some(PathBuf::from(r"C:\Windows\explorer.exe")),
            working_dir: Some(PathBuf::from(r"C:\projects\myapp")),
            signature_valid: signed,
            signature_subject: None,
        }
    }

    fn make_config(extra_rules: Vec<AllowRule>) -> ProjectConfig {
        ProjectConfig {
            project: ProjectMeta {
                name: "Test".into(),
                vault_name: "Test".into(),
                created_at: chrono::Utc::now().to_rfc3339(),
            },
            session: SessionConfig {
                expiry_mode: ExpiryMode::Both,
                expiry_hours: 8,
            },
            security: SecurityConfig {
                unknown_process_mode: UnknownProcessMode::DenyAndLog,
                require_identity_check: false,
                require_signature_check: false,
                require_parent_check: true,
                require_working_dir_check: false,
                allow_cli_reveal: false,
            },
            allow_list: AllowListConfig { rules: extra_rules },
            deny_list: DenyListConfig::default(),
            process_rules: vec![],
        }
    }

    fn uvicorn_rule() -> AllowRule {
        AllowRule {
            name: "uvicorn".into(),
            exe_path: r"**\uvicorn.exe".into(),
            parent_not: vec!["claude.exe".into(), "cursor.exe".into()],
            working_dir: Some("${PROJECT_ROOT}".into()),
            signed: true,
            secrets: vec!["*".into()],
        }
    }

    #[test]
    fn always_deny_blocks_claude() {
        let chain = vec![ProcessInfo {
            pid: 100,
            exe_path: PathBuf::from(r"C:\Users\test\AppData\Local\Programs\claude.exe"),
            parent_pid: None,
            parent_exe_path: None,
            working_dir: None,
            signature_valid: true,
            signature_subject: None,
        }];
        let cfg = make_config(vec![]);
        let result = check_access(&chain, "DB_URL", &cfg, Path::new("."));
        assert!(!result.is_allowed());
        assert!(result.reason().contains("always_deny"));
    }

    #[test]
    fn uvicorn_is_allowed() {
        let chain = vec![make_process("uvicorn.exe", true)];
        let cfg = make_config(vec![uvicorn_rule()]);
        let result = check_access(&chain, "DB_URL", &cfg, Path::new(r"C:\projects\myapp"));
        assert!(
            result.is_allowed(),
            "uvicorn should be allowed; got: {result:?}"
        );
    }

    #[test]
    fn uvicorn_launched_by_claude_is_denied() {
        let uvicorn = ProcessInfo {
            pid: 200,
            exe_path: PathBuf::from(r"C:\Python39\uvicorn.exe"),
            parent_pid: Some(100),
            parent_exe_path: Some(PathBuf::from(r"C:\Programs\claude.exe")),
            working_dir: Some(PathBuf::from(r"C:\projects\myapp")),
            signature_valid: true,
            signature_subject: None,
        };
        let claude = ProcessInfo {
            pid: 100,
            exe_path: PathBuf::from(r"C:\Programs\claude.exe"),
            parent_pid: None,
            parent_exe_path: None,
            working_dir: None,
            signature_valid: true,
            signature_subject: None,
        };
        let chain = vec![uvicorn, claude];
        let cfg = make_config(vec![uvicorn_rule()]);
        let result = check_access(&chain, "DB_URL", &cfg, Path::new("."));
        // claude.exe is in the chain → always_deny fires before the parent_not check
        assert!(!result.is_allowed());
        assert!(result.reason().contains("always_deny"));
    }

    #[test]
    fn unknown_process_is_denied() {
        let chain = vec![make_process("myapp.exe", true)];
        let cfg = make_config(vec![]);
        let result = check_access(&chain, "DB_URL", &cfg, Path::new("."));
        assert!(!result.is_allowed());
        assert!(result.reason().contains("not_in_allow_list"));
    }
}
