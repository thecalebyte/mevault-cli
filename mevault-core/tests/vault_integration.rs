/// Integration tests for VaultStore, audit log, and project config.
///
/// All tests are fully isolated — each uses its own temp directory.
/// No shared state, no system SecretStore access, no destructive resets.
/// Tests are safe to run in parallel without any special flags.
use mevault_core::{
    crypto::{self, CryptoPolicy},
    vault::VaultStore,
};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;

fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

/// Build a VaultStore backed by a temp directory using fast KDF params so the
/// integration suite finishes in seconds rather than minutes.
fn store(dir: &tempfile::TempDir) -> VaultStore {
    VaultStore::new_at_with_policy(dir.path().join("vaults"), CryptoPolicy::fast_test())
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
    s.create_vault("MyProject", &pw("password-12-chars"))
        .unwrap();
    assert!(s.vault_exists("MyProject").unwrap());
}

#[test]
fn create_vault_is_idempotent_and_preserves_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("idempotent-create-pw");

    s.create_vault("V", &pw).unwrap();
    s.set_secret("K", &SecretString::new("v".to_owned()), "V", Some(&pw))
        .unwrap();

    s.create_vault("V", &pw).unwrap();
    assert_eq!(
        s.get_secret("K", "V", Some(&pw)).unwrap().expose_secret(),
        "v"
    );
}

#[test]
fn create_vault_wrong_password_on_existing_vault_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    s.create_vault("V", &pw("correct-password-here")).unwrap();

    let err = s.create_vault("V", &pw("wrong-password-here"));
    assert!(
        err.is_err(),
        "wrong password on existing vault must return an error"
    );
}

#[test]
fn set_get_remove() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("set-get-remove-pw-xx");

    s.create_vault("V", &pw).unwrap();
    s.set_secret(
        "DB_URL",
        &SecretString::new("postgres://localhost".to_owned()),
        "V",
        Some(&pw),
    )
    .unwrap();

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
    s.set_secret("K", &SecretString::new("old".to_owned()), "V", Some(&pw))
        .unwrap();
    s.set_secret("K", &SecretString::new("new".to_owned()), "V", Some(&pw))
        .unwrap();

    assert_eq!(
        s.get_secret("K", "V", Some(&pw)).unwrap().expose_secret(),
        "new"
    );
}

#[test]
fn wrong_password_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let correct = pw("correct-password-vault");
    let wrong = pw("wrong-password-vault");

    s.create_vault("V", &correct).unwrap();
    s.set_secret("K", &SecretString::new("v".to_owned()), "V", Some(&correct))
        .unwrap();

    assert!(s.get_secret("K", "V", Some(&wrong)).is_err());
}

#[test]
fn list_secrets_sorted() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("list-secrets-sorted-pw");

    s.create_vault("V", &pw).unwrap();
    for name in &["ZEBRA", "APPLE", "MANGO"] {
        s.set_secret(name, &SecretString::new("x".to_owned()), "V", Some(&pw))
            .unwrap();
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
    s.set_secret("A", &SecretString::new("1".to_owned()), "V", Some(&pw))
        .unwrap();
    s.set_secret("B", &SecretString::new("2".to_owned()), "V", Some(&pw))
        .unwrap();

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
    s.set_secret(
        "DB",
        &SecretString::new("postgres://host".to_owned()),
        "V",
        Some(&pw),
    )
    .unwrap();

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

// ── 2. Bug regression tests ──────────────────────────────────────────────────

#[test]
fn name_sanitization_collision_detected() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("collision-test-password");

    s.create_vault("My Vault", &pw).unwrap();
    let err = s.create_vault("My?Vault", &pw);
    assert!(err.is_err(), "colliding sanitized names must be rejected");
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("conflicts"),
        "error should mention 'conflicts': {msg}"
    );
}

#[test]
fn created_at_preserved_on_secret_update() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("created-at-preserve-pw");

    s.create_vault("V", &pw).unwrap();

    let vault_path = dir.path().join("vaults").join("V.mvault");
    let vf1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vault_path).unwrap()).unwrap();
    let original_ts = vf1["created_at"].as_str().unwrap().to_owned();

    s.set_secret("K1", &SecretString::new("a".to_owned()), "V", Some(&pw))
        .unwrap();
    s.set_secret("K2", &SecretString::new("b".to_owned()), "V", Some(&pw))
        .unwrap();
    s.remove_secret("K1", "V", Some(&pw)).unwrap();

    let vf2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vault_path).unwrap()).unwrap();
    assert_eq!(
        vf2["created_at"].as_str().unwrap(),
        original_ts,
        "created_at must not change on update"
    );
    assert!(
        !vf2["updated_at"].as_str().unwrap_or("").is_empty(),
        "updated_at must be populated after writes"
    );
}

#[test]
fn set_secrets_bulk_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("bulk-set-round-trip-pw");

    s.create_vault("V", &pw).unwrap();

    let mut batch: HashMap<String, SecretString> = HashMap::new();
    for i in 0..20usize {
        batch.insert(format!("KEY_{i:02}"), SecretString::new(format!("val-{i}")));
    }
    s.set_secrets_bulk(&batch, "V", &pw).unwrap();

    assert_eq!(s.list_secrets("V", Some(&pw)).unwrap().len(), 20);
    for i in 0..20usize {
        assert_eq!(
            s.get_secret(&format!("KEY_{i:02}"), "V", Some(&pw))
                .unwrap()
                .expose_secret(),
            &format!("val-{i}")
        );
    }
}

#[test]
fn set_secrets_bulk_merges_with_existing() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("bulk-merge-test-password");

    s.create_vault("V", &pw).unwrap();
    s.set_secret(
        "EXISTING",
        &SecretString::new("keep-me".to_owned()),
        "V",
        Some(&pw),
    )
    .unwrap();

    let mut batch = HashMap::new();
    batch.insert("NEW_KEY".to_owned(), SecretString::new("new-val".into()));
    s.set_secrets_bulk(&batch, "V", &pw).unwrap();

    assert_eq!(
        s.get_secret("EXISTING", "V", Some(&pw))
            .unwrap()
            .expose_secret(),
        "keep-me"
    );
    assert_eq!(
        s.get_secret("NEW_KEY", "V", Some(&pw))
            .unwrap()
            .expose_secret(),
        "new-val"
    );
}

#[test]
fn kdf_params_stored_in_key_protection() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("kdf-params-stored-test");

    s.create_vault("V", &pw).unwrap();

    let vault_path = dir.path().join("vaults").join("V.mvault");
    let vf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vault_path).unwrap()).unwrap();

    assert_eq!(
        vf["version"].as_str().unwrap(),
        "2",
        "new vaults must be v2"
    );
    assert!(
        vf["key_protection"]["mem_kib"].as_u64().unwrap() > 0,
        "mem_kib must be stored"
    );
    assert!(
        vf["key_protection"]["iters"].as_u64().unwrap() > 0,
        "iters must be stored"
    );
    assert!(
        vf["key_protection"]["para"].as_u64().unwrap() > 0,
        "para must be stored"
    );
    assert!(
        !vf["key_protection"]["salt"]
            .as_str()
            .unwrap_or("")
            .is_empty(),
        "salt must be present"
    );
    assert!(
        !vf["vault_id"].as_str().unwrap_or("").is_empty(),
        "vault_id must be present"
    );
}

#[test]
fn header_wrong_format_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    s.create_vault("V", &pw("pw")).unwrap();

    let vault_path = dir.path().join("vaults").join("V.mvault");
    let json = std::fs::read_to_string(&vault_path).unwrap();
    let tampered = json.replace("\"mevault-vault\"", "\"unknown-format\"");
    std::fs::write(&vault_path, tampered).unwrap();

    let err = s.get_secret("K", "V", Some(&pw("pw")));
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("format"),
        "error should mention format field: {msg}"
    );
}

#[test]
fn header_wrong_version_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    s.create_vault("V", &pw("pw")).unwrap();

    let vault_path = dir.path().join("vaults").join("V.mvault");
    let json = std::fs::read_to_string(&vault_path).unwrap();
    let tampered = json.replace("\"version\": \"2\"", "\"version\": \"99\"");
    std::fs::write(&vault_path, tampered).unwrap();

    let err = s.get_secret("K", "V", Some(&pw("pw")));
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("version"),
        "error should mention version field: {msg}"
    );
}

#[test]
fn kdf_mem_above_max_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    s.create_vault("V", &pw("pw")).unwrap();

    let vault_path = dir.path().join("vaults").join("V.mvault");
    let json = std::fs::read_to_string(&vault_path).unwrap();
    let current_mem: u64 = serde_json::from_str::<serde_json::Value>(&json).unwrap()
        ["key_protection"]["mem_kib"]
        .as_u64()
        .unwrap();
    // 262145 KiB = MAX_MEM_KIB + 1
    let tampered = json.replace(
        &format!("\"mem_kib\": {current_mem}"),
        "\"mem_kib\": 262145",
    );
    std::fs::write(&vault_path, tampered).unwrap();

    let err = s.get_secret("K", "V", Some(&pw("pw")));
    assert!(err.is_err(), "mem_kib above max must be rejected");
}

#[test]
fn kdf_iters_zero_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    s.create_vault("V", &pw("pw")).unwrap();

    let vault_path = dir.path().join("vaults").join("V.mvault");
    let json = std::fs::read_to_string(&vault_path).unwrap();
    let current_iters: u64 = serde_json::from_str::<serde_json::Value>(&json).unwrap()
        ["key_protection"]["iters"]
        .as_u64()
        .unwrap();
    let tampered = json.replace(&format!("\"iters\": {current_iters}"), "\"iters\": 0");
    std::fs::write(&vault_path, tampered).unwrap();

    let err = s.get_secret("K", "V", Some(&pw("pw")));
    assert!(err.is_err(), "iters = 0 must be rejected");
}

// ── 3. Isolation guarantee ───────────────────────────────────────────────────

#[test]
fn projects_are_fully_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);

    let pw_a = pw("project-alpha-password");
    let pw_b = pw("project-beta-password");

    s.create_vault("Alpha", &pw_a).unwrap();
    s.create_vault("Beta", &pw_b).unwrap();

    s.set_secret(
        "S",
        &SecretString::new("alpha-val".to_owned()),
        "Alpha",
        Some(&pw_a),
    )
    .unwrap();
    s.set_secret(
        "S",
        &SecretString::new("beta-val".to_owned()),
        "Beta",
        Some(&pw_b),
    )
    .unwrap();

    assert_eq!(
        s.get_secret("S", "Alpha", Some(&pw_a))
            .unwrap()
            .expose_secret(),
        "alpha-val"
    );
    assert_eq!(
        s.get_secret("S", "Beta", Some(&pw_b))
            .unwrap()
            .expose_secret(),
        "beta-val"
    );

    assert!(s.get_secret("S", "Alpha", Some(&pw_b)).is_err());
    assert!(s.get_secret("S", "Beta", Some(&pw_a)).is_err());
}

#[test]
fn secrets_survive_store_reconstruction() {
    // Simulate process restart: two independent VaultStore instances, same directory.
    let dir = tempfile::tempdir().unwrap();
    let pw = pw("restart-survival-password");
    let vault_dir = dir.path().join("vaults");

    {
        let s = VaultStore::new_at_with_policy(vault_dir.clone(), CryptoPolicy::fast_test());
        s.create_vault("V", &pw).unwrap();
        s.set_secret(
            "K",
            &SecretString::new("persistent".to_owned()),
            "V",
            Some(&pw),
        )
        .unwrap();
    }
    {
        let s = VaultStore::new_at_with_policy(vault_dir, CryptoPolicy::fast_test());
        assert_eq!(
            s.get_secret("K", "V", Some(&pw)).unwrap().expose_secret(),
            "persistent"
        );
    }
}

// ── 4. Stress / edge cases ───────────────────────────────────────────────────

#[test]
fn many_secrets_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let pw = pw("many-secrets-pw-12345");

    s.create_vault("V", &pw).unwrap();
    for i in 0..50usize {
        let name = format!("SECRET_{i:02}");
        s.set_secret(
            &name,
            &SecretString::new(format!("value-{i}")),
            "V",
            Some(&pw),
        )
        .unwrap();
    }

    assert_eq!(s.list_secrets("V", Some(&pw)).unwrap().len(), 50);
    for i in 0..50usize {
        let got = s
            .get_secret(&format!("SECRET_{i:02}"), "V", Some(&pw))
            .unwrap();
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
    s.set_secret("K", &SecretString::new(tricky.to_owned()), "V", Some(&pw))
        .unwrap();
    assert_eq!(
        s.get_secret("K", "V", Some(&pw)).unwrap().expose_secret(),
        tricky
    );
}

// ── 5. Module stubs ──────────────────────────────────────────────────────────

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

// ── 6. Audit log ─────────────────────────────────────────────────────────────

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

    let for_db = log
        .query(None, Some("DATABASE_URL"), None, 100)
        .await
        .unwrap();
    assert_eq!(for_db.len(), 1);
    assert_eq!(for_db[0].event_type, "allowed");

    let recent = log.query(None, None, Some(1), 100).await.unwrap();
    assert_eq!(recent.len(), 2);
}

// ── 7. ProjectConfig ─────────────────────────────────────────────────────────

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

// ── 8. Identity / always-deny list ───────────────────────────────────────────

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
    assert!(
        !p2.is_always_denied(),
        "uvicorn.exe must not be always-denied"
    );
}

// ── 9. v1 migration backup ────────────────────────────────────────────────────

#[test]
fn v1_migration_preserves_bak_file() {
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().join("vaults");
    std::fs::create_dir_all(&vault_dir).unwrap();

    // Write a v1 vault directly.
    let path = vault_dir.join("V.mvault");
    let blob = crypto::encrypt(
        b"{\"MIGRATED_KEY\":\"migrated-value\"}",
        &pw("migration-bak-password"),
        b"V",
        &CryptoPolicy::fast_test(),
    )
    .unwrap();

    #[derive(serde::Serialize)]
    struct V1File {
        format: &'static str,
        version: &'static str,
        name: &'static str,
        created_at: &'static str,
        updated_at: &'static str,
        blob: crypto::EncryptedBlob,
    }
    let v1 = V1File {
        format: "mevault-vault",
        version: "1",
        name: "V",
        created_at: "2024-01-01T00:00:00Z",
        updated_at: "2024-01-01T00:00:00Z",
        blob,
    };
    std::fs::write(&path, serde_json::to_string_pretty(&v1).unwrap()).unwrap();

    // Unlock triggers auto-migration.
    let s = VaultStore::new_at_with_policy(vault_dir.clone(), CryptoPolicy::fast_test());
    let vault = s.unlock("V", &pw("migration-bak-password")).unwrap();

    // Secret survived migration.
    assert_eq!(
        vault.get_secret("MIGRATED_KEY").unwrap().expose_secret(),
        "migrated-value"
    );

    // On-disk file is now v2.
    let on_disk: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(on_disk["version"].as_str().unwrap(), "2");

    // The original v1 file was preserved as a .v1.bak.
    let bak_path = vault_dir.join("V.v1.bak");
    assert!(bak_path.exists(), ".v1.bak should exist after migration");
    let bak_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&bak_path).unwrap()).unwrap();
    assert_eq!(
        bak_json["version"].as_str().unwrap(),
        "1",
        ".v1.bak should contain the original v1 vault"
    );
}

// ── 10. Concurrent write safety ───────────────────────────────────────────────

#[test]
fn concurrent_thread_writes_are_serialized() {
    // Multiple threads race to write distinct secrets to the same vault.
    // The fs2 exclusive lock must serialize them without corruption.
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().join("vaults");
    let s = Arc::new(VaultStore::new_at_with_policy(
        vault_dir.clone(),
        CryptoPolicy::fast_test(),
    ));
    let pw_val = pw("concurrent-thread-lock-pw");
    s.create_vault("ThreadVault", &pw_val).unwrap();

    let n = 8usize;
    let mut handles = vec![];
    for i in 0..n {
        let store = Arc::clone(&s);
        let pw_clone = pw("concurrent-thread-lock-pw");
        handles.push(std::thread::spawn(move || {
            let val = SecretString::new(format!("val-{i}"));
            store
                .set_secret(&format!("K{i}"), &val, "ThreadVault", Some(&pw_clone))
                .expect("set_secret should not fail under concurrent lock");
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // Verify all n secrets landed intact.
    for i in 0..n {
        let got = s
            .get_secret(&format!("K{i}"), "ThreadVault", Some(&pw_val))
            .unwrap();
        assert_eq!(got.expose_secret(), &format!("val-{i}"));
    }
    assert_eq!(
        s.list_secrets("ThreadVault", Some(&pw_val)).unwrap().len(),
        n
    );
}

/// Helper: spawn vault-write-helper with credentials over stdin JSON.
#[cfg(feature = "test-helper")]
fn spawn_helper(
    vault_dir: &std::path::Path,
    vault_name: &str,
    secret_name: &str,
    secret_value: &str,
    password: &str,
) -> std::process::Child {
    use std::process::Stdio;

    let helper = env!("CARGO_BIN_EXE_vault-write-helper");
    let mut child = std::process::Command::new(helper)
        .arg(vault_dir.to_str().unwrap())
        .arg(vault_name)
        .arg(secret_name)
        .stdin(Stdio::piped())
        .spawn()
        .expect("failed to spawn vault-write-helper");

    {
        let stdin = child.stdin.take().expect("helper stdin unavailable");
        serde_json::to_writer(
            stdin,
            &serde_json::json!({ "secret_value": secret_value, "password": password }),
        )
        .expect("writing helper stdin");
    } // closes the pipe so helper can read EOF
    child
}

#[cfg(feature = "test-helper")]
#[test]
fn cross_process_concurrent_writes_are_serialized() {
    // Spawn N real child processes that each write a distinct secret to the
    // same vault.  The fs2 exclusive lock in VaultStore must serialize the
    // writes so no write is lost and the file stays valid.
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().join("vaults");
    let pw_str = "cross-process-lock-test-pw";
    let s = VaultStore::new_at_with_policy(vault_dir.clone(), CryptoPolicy::fast_test());
    s.create_vault("LockVault", &pw(pw_str)).unwrap();

    let n = 5usize;
    let mut children: Vec<std::process::Child> = (0..n)
        .map(|i| {
            spawn_helper(
                &vault_dir,
                "LockVault",
                &format!("KEY_{i}"),
                &format!("val_{i}"),
                pw_str,
            )
        })
        .collect();

    for child in &mut children {
        let status = child.wait().unwrap();
        assert!(
            status.success(),
            "vault-write-helper exited with non-zero status"
        );
    }

    let pw_val = pw(pw_str);
    for i in 0..n {
        let got = s
            .get_secret(&format!("KEY_{i}"), "LockVault", Some(&pw_val))
            .unwrap_or_else(|_| panic!("KEY_{i} missing after cross-process concurrent writes"));
        assert_eq!(got.expose_secret(), &format!("val_{i}"));
    }
    assert_eq!(
        s.list_secrets("LockVault", Some(&pw_val)).unwrap().len(),
        n,
        "vault should contain exactly {n} secrets after concurrent writes"
    );
}

#[cfg(feature = "test-helper")]
#[test]
fn helper_handles_multiline_secret_value() {
    // Newlines in a secret value must survive the JSON-over-stdin framing.
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().join("vaults");
    let pw_str = "multiline-helper-pw";
    let s = VaultStore::new_at_with_policy(vault_dir.clone(), CryptoPolicy::fast_test());
    s.create_vault("MLVault", &pw(pw_str)).unwrap();

    let multiline_val = "line1\nline2\nline3";
    let mut child = spawn_helper(&vault_dir, "MLVault", "ML_KEY", multiline_val, pw_str);
    assert!(child.wait().unwrap().success());

    let got = s
        .get_secret("ML_KEY", "MLVault", Some(&pw(pw_str)))
        .unwrap();
    assert_eq!(got.expose_secret(), multiline_val);
}

// ── 11. Atomic write durability ───────────────────────────────────────────────

#[test]
fn stale_tmp_file_does_not_block_new_write() {
    // A leftover `.tmp` file from a prior crashed write must not prevent a
    // subsequent write.  The new write uses a UUID-based temp name so it
    // never collides with the stale file.
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().join("vaults");
    let s = VaultStore::new_at_with_policy(vault_dir.clone(), CryptoPolicy::fast_test());
    s.create_vault("StaleVault", &pw("stale-pw")).unwrap();

    // Simulate a stale temp file left by a prior crash — use the old fixed
    // name pattern so we know it won't clash with the UUID-based one.
    let stale_tmp = vault_dir.join("StaleVault.mvault.tmp");
    std::fs::write(&stale_tmp, b"corrupt garbage").unwrap();
    assert!(stale_tmp.exists());

    // Writing a secret must succeed despite the stale file.
    let val = secrecy::SecretString::new("value".to_owned());
    s.set_secret("K", &val, "StaleVault", Some(&pw("stale-pw")))
        .unwrap();

    // The stale temp file was not touched (our write used a different name).
    assert!(
        stale_tmp.exists(),
        "stale tmp should still be present (untouched)"
    );

    // The actual secret is readable.
    assert_eq!(
        s.get_secret("K", "StaleVault", Some(&pw("stale-pw")))
            .unwrap()
            .expose_secret(),
        "value"
    );
}

// ── 12. Migration hardening ───────────────────────────────────────────────────

/// Helper: create a v1 vault file at `path` with the given secrets JSON.
fn write_v1_vault(
    path: &std::path::Path,
    name: &str,
    secrets_json: &[u8],
    password: &secrecy::SecretString,
) {
    #[derive(serde::Serialize)]
    struct V1File {
        format: &'static str,
        version: &'static str,
        name: String,
        created_at: &'static str,
        updated_at: &'static str,
        blob: crypto::EncryptedBlob,
    }
    let blob = crypto::encrypt(
        secrets_json,
        password,
        name.as_bytes(),
        &CryptoPolicy::fast_test(),
    )
    .unwrap();
    let v1 = V1File {
        format: "mevault-vault",
        version: "1",
        name: name.to_owned(),
        created_at: "2024-01-01T00:00:00Z",
        updated_at: "2024-01-01T00:00:00Z",
        blob,
    };
    std::fs::write(path, serde_json::to_string_pretty(&v1).unwrap()).unwrap();
}

#[test]
fn migration_aborts_when_backup_write_fails() {
    // We make the backup impossible by placing a *directory* at .v1.bak with
    // content that differs from the vault (so the code does not reuse it).
    // The backup path is <vault_dir>/<name>.v1.bak — we pre-create that path
    // as a sub-directory so std::fs::write fails.
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().join("vaults");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let path = vault_dir.join("V.mvault");
    let pw = pw("mig-abort-pw");
    write_v1_vault(&path, "V", b"{}", &pw);

    // Read the actual v1 bytes so we can put *different* bytes in the bak dir
    // to force the "existing bak differs" branch (which then tries to write a
    // new unique bak — but the *original* bak target creation below will be
    // skipped in that branch, so we instead block the unique bak path).
    // Simpler: just make the .v1.bak path a directory — that blocks write.
    let bak_dir = vault_dir.join("V.v1.bak");
    std::fs::create_dir_all(&bak_dir).unwrap();

    let s = VaultStore::new_at_with_policy(vault_dir.clone(), CryptoPolicy::fast_test());
    let result = s.unlock("V", &pw);
    assert!(
        result.is_err(),
        "migration must fail when backup cannot be written"
    );

    // Original v1 file must still be intact.
    let on_disk: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        on_disk["version"].as_str().unwrap(),
        "1",
        "v1 file must be untouched after backup failure"
    );
}

#[test]
fn v1_backup_matches_original_after_successful_migration() {
    // Verify that after a successful v1→v2 migration, the .v1.bak file is a
    // byte-for-byte copy of the original v1 file (not some modified version).
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().join("vaults");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let path = vault_dir.join("V.mvault");
    let pw = pw("unchanged-pw");
    write_v1_vault(&path, "V", b"{\"K\":\"original\"}", &pw);
    let original_bytes = std::fs::read(&path).unwrap();

    let s = VaultStore::new_at_with_policy(vault_dir.clone(), CryptoPolicy::fast_test());
    s.unlock("V", &pw).unwrap(); // migration succeeds

    let bak_path = vault_dir.join("V.v1.bak");
    assert!(bak_path.exists());
    let bak_bytes = std::fs::read(&bak_path).unwrap();
    assert_eq!(
        bak_bytes, original_bytes,
        ".v1.bak must be byte-for-byte identical to the original v1 file"
    );
}

#[test]
fn interrupted_migration_retry_reuses_identical_bak() {
    // Simulate an interrupted migration: .v1.bak already exists and contains
    // exactly the same bytes as the current .mvault.  A retry must succeed
    // without error — the bak is reused, not duplicated.
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().join("vaults");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let path = vault_dir.join("V.mvault");
    let pw = pw("retry-pw");
    write_v1_vault(&path, "V", b"{\"K\":\"retry-val\"}", &pw);

    // Pre-create .v1.bak with identical content (interrupted migration).
    let bak_path = vault_dir.join("V.v1.bak");
    std::fs::copy(&path, &bak_path).unwrap();

    let s = VaultStore::new_at_with_policy(vault_dir.clone(), CryptoPolicy::fast_test());
    // Retry must succeed.
    let vault = s.unlock("V", &pw).unwrap();
    assert_eq!(vault.get_secret("K").unwrap().expose_secret(), "retry-val");

    // .v1.bak still present and no extra unique bak was created.
    let bak_count = std::fs::read_dir(&vault_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".v1.bak"))
        .count();
    assert_eq!(
        bak_count, 1,
        "retry should reuse existing .v1.bak, not create a new one"
    );
}
