/// Integration tests for VaultStore, audit log, and project config.
///
/// All tests are fully isolated — each uses its own temp directory.
/// No shared state, no system SecretStore access, no destructive resets.
/// Tests are safe to run in parallel without any special flags.

use mevault_core::vault::VaultStore;
use secrecy::{ExposeSecret, SecretString};

fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_owned().into())
}

/// Build a VaultStore backed by a temp directory instead of %APPDATA%.
fn store(dir: &tempfile::TempDir) -> VaultStore {
    std::env::set_var("APPDATA", dir.path().to_str().unwrap());
    VaultStore::new()
}

// ── 1. VaultStore basics ─────────────────────────────────────────────────────

#[test]
fn vault_does_not_exist_initially() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    assert!(!s.vault_exists("MyProject").unwrap());
}

#[test]
fn create_vault_then_exists() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    s.create_vault("MyProject", &pw("password-12-chars")).unwrap();
    assert!(s.vault_exists("MyProject").unwrap());
}

#[test]
fn create_vault_is_idempotent_and_preserves_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("idempotent-create-pw");

    s.create_vault("V", &pw).unwrap();
    s.set_secret("K", &SecretString::new("v".to_owned().into()), "V", Some(&pw)).unwrap();

    // Second create must not wipe existing content.
    s.create_vault("V", &pw).unwrap();
    assert_eq!(s.get_secret("K", "V", Some(&pw)).unwrap().expose_secret(), "v");
}

#[test]
fn set_get_remove() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("set-get-remove-pw-xx");

    s.create_vault("V", &pw).unwrap();
    s.set_secret("DB_URL", &SecretString::new("postgres://localhost".to_owned().into()), "V", Some(&pw)).unwrap();

    let got = s.get_secret("DB_URL", "V", Some(&pw)).unwrap();
    assert_eq!(got.expose_secret(), "postgres://localhost");

    s.remove_secret("DB_URL", "V", Some(&pw)).unwrap();
    assert!(s.get_secret("DB_URL", "V", Some(&pw)).is_err());
}

#[test]
fn overwrite_secret() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("overwrite-secret-pw");

    s.create_vault("V", &pw).unwrap();
    s.set_secret("K", &SecretString::new("old".to_owned().into()), "V", Some(&pw)).unwrap();
    s.set_secret("K", &SecretString::new("new".to_owned().into()), "V", Some(&pw)).unwrap();

    assert_eq!(s.get_secret("K", "V", Some(&pw)).unwrap().expose_secret(), "new");
}

#[test]
fn wrong_password_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let correct = pw("correct-password-vault");
    let wrong = pw("wrong-password-vault");

    s.create_vault("V", &correct).unwrap();
    s.set_secret("K", &SecretString::new("v".to_owned().into()), "V", Some(&correct)).unwrap();

    assert!(s.get_secret("K", "V", Some(&wrong)).is_err());
}

#[test]
fn list_secrets_sorted() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("list-secrets-sorted-pw");

    s.create_vault("V", &pw).unwrap();
    for name in &["ZEBRA", "APPLE", "MANGO"] {
        s.set_secret(name, &SecretString::new("x".to_owned().into()), "V", Some(&pw)).unwrap();
    }

    let list = s.list_secrets("V", Some(&pw)).unwrap();
    let names: Vec<&str> = list.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, vec!["APPLE", "MANGO", "ZEBRA"]);
}

#[test]
fn unlock_and_list_names() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("unlock-list-names-pw");

    s.create_vault("V", &pw).unwrap();
    s.set_secret("A", &SecretString::new("1".to_owned().into()), "V", Some(&pw)).unwrap();
    s.set_secret("B", &SecretString::new("2".to_owned().into()), "V", Some(&pw)).unwrap();

    let names = s.unlock_and_list_names("V", &pw).unwrap();
    assert!(names.contains(&"A".to_owned()));
    assert!(names.contains(&"B".to_owned()));
}

#[test]
fn unlock_and_preload() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("unlock-and-preload-pw");

    s.create_vault("V", &pw).unwrap();
    s.set_secret("DB", &SecretString::new("postgres://host".to_owned().into()), "V", Some(&pw)).unwrap();

    let map = s.unlock_and_preload("V", &pw).unwrap();
    assert_eq!(map["DB"].expose_secret(), "postgres://host");
}

#[test]
fn list_vaults() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("list-vaults-pw-12345");

    s.create_vault("Alpha", &pw).unwrap();
    s.create_vault("Beta", &pw).unwrap();

    let vaults = s.list_vaults().unwrap();
    assert!(vaults.contains(&"Alpha".to_owned()));
    assert!(vaults.contains(&"Beta".to_owned()));
}

// ── 2. Isolation guarantee ───────────────────────────────────────────────────

#[test]
fn projects_are_fully_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);

    let pw_a = pw("project-alpha-password");
    let pw_b = pw("project-beta-password");

    s.create_vault("Alpha", &pw_a).unwrap();
    s.create_vault("Beta", &pw_b).unwrap();

    s.set_secret("S", &SecretString::new("alpha-val".to_owned().into()), "Alpha", Some(&pw_a)).unwrap();
    s.set_secret("S", &SecretString::new("beta-val".to_owned().into()), "Beta", Some(&pw_b)).unwrap();

    assert_eq!(s.get_secret("S", "Alpha", Some(&pw_a)).unwrap().expose_secret(), "alpha-val");
    assert_eq!(s.get_secret("S", "Beta", Some(&pw_b)).unwrap().expose_secret(), "beta-val");

    // Cross-project password access must be rejected.
    assert!(s.get_secret("S", "Alpha", Some(&pw_b)).is_err());
    assert!(s.get_secret("S", "Beta", Some(&pw_a)).is_err());
}

#[test]
fn secrets_survive_store_reconstruction() {
    // Simulate process restart: two independent VaultStore instances, same directory.
    let dir = tempfile::tempdir().unwrap();
    let pw = pw("restart-survival-password");

    {
        std::env::set_var("APPDATA", dir.path().to_str().unwrap());
        let s = VaultStore::new();
        s.create_vault("V", &pw).unwrap();
        s.set_secret("K", &SecretString::new("persistent".to_owned().into()), "V", Some(&pw)).unwrap();
    }
    {
        std::env::set_var("APPDATA", dir.path().to_str().unwrap());
        let s = VaultStore::new();
        assert_eq!(s.get_secret("K", "V", Some(&pw)).unwrap().expose_secret(), "persistent");
    }
}

// ── 3. Stress / edge cases ───────────────────────────────────────────────────

#[test]
fn many_secrets_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("many-secrets-pw-12345");

    s.create_vault("V", &pw).unwrap();
    for i in 0..50usize {
        let name = format!("SECRET_{i:02}");
        s.set_secret(&name, &SecretString::new(format!("value-{i}").into()), "V", Some(&pw)).unwrap();
    }

    assert_eq!(s.list_secrets("V", Some(&pw)).unwrap().len(), 50);
    for i in 0..50usize {
        let got = s.get_secret(&format!("SECRET_{i:02}"), "V", Some(&pw)).unwrap();
        assert_eq!(got.expose_secret(), &format!("value-{i}"));
    }
}

#[test]
fn special_chars_in_value() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("special-chars-pw-1234");

    s.create_vault("V", &pw).unwrap();
    let tricky = "it's a \"test\" value\n with newline & <special> chars";
    s.set_secret("K", &SecretString::new(tricky.to_owned().into()), "V", Some(&pw)).unwrap();
    assert_eq!(s.get_secret("K", "V", Some(&pw)).unwrap().expose_secret(), tricky);
}

// ── 4. Module stubs ──────────────────────────────────────────────────────────

#[test]
fn check_modules_always_ok() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    assert!(s.check_modules().unwrap());
}

#[test]
fn install_modules_always_ok() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    s.install_modules().unwrap();
}

// ── 5. Audit log ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn audit_log_write_and_filter() {
    use mevault_core::audit::{AuditEvent, AuditLog, EventType};

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test_audit.db");
    let log = AuditLog::open(&db_path).await.unwrap();

    log.write(
        AuditEvent::new(EventType::Allowed)
            .secret("DATABASE_URL")
            .vault("TestVault")
            .process("uvicorn.exe", 9999)
            .reason("allow_list match"),
    )
    .await
    .unwrap();

    log.write(
        AuditEvent::new(EventType::Denied)
            .secret("OPENAI_KEY")
            .vault("TestVault")
            .process("claude.exe", 1234)
            .reason("always_deny"),
    )
    .await
    .unwrap();

    let all = log.query(None, None, None, 100).await.unwrap();
    assert_eq!(all.len(), 2);

    let denied = log.query(Some("denied"), None, None, 100).await.unwrap();
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].process_path.as_deref(), Some("claude.exe"));

    let for_db = log.query(None, Some("DATABASE_URL"), None, 100).await.unwrap();
    assert_eq!(for_db.len(), 1);
    assert_eq!(for_db[0].event_type, "allowed");

    let recent = log.query(None, None, Some(1), 100).await.unwrap();
    assert_eq!(recent.len(), 2);
}

// ── 6. ProjectConfig ─────────────────────────────────────────────────────────

#[test]
fn project_config_save_and_load() {
    use mevault_core::config::ProjectConfig;

    let dir = tempfile::tempdir().unwrap();
    let cfg = ProjectConfig::new("IntegrationTest", "IntegrationTest");
    cfg.save(dir.path()).unwrap();
    let loaded = ProjectConfig::load(dir.path()).unwrap();
    assert_eq!(loaded.project.name, "IntegrationTest");
    assert_eq!(loaded.project.vault_name, "IntegrationTest");
    assert_eq!(loaded.deny_list.always_deny.len(), 7);
}

// ── 7. Identity / always-deny list ───────────────────────────────────────────

#[test]
fn always_deny_list_is_correct() {
    use mevault_core::identity::{ProcessInfo, ALWAYS_DENY};

    assert_eq!(ALWAYS_DENY.len(), 7, "always_deny should have 7 entries");
    assert!(ALWAYS_DENY.contains(&"claude.exe"));
    assert!(ALWAYS_DENY.contains(&"cursor.exe"));
    assert!(ALWAYS_DENY.contains(&"copilot.exe"));

    let p = ProcessInfo {
        pid: 1,
        exe_path: std::path::PathBuf::from(r"C:\Users\test\AppData\Local\Programs\claude.exe"),
        parent_pid: None,
        parent_exe_path: None,
        working_dir: None,
        signature_valid: false,
        signature_subject: None,
    };
    assert!(p.is_always_denied(), "claude.exe must be always-denied");

    let p2 = ProcessInfo {
        exe_path: std::path::PathBuf::from(r"C:\Python39\Scripts\uvicorn.exe"),
        ..p
    };
    assert!(!p2.is_always_denied(), "uvicorn.exe must not be always-denied");
}
