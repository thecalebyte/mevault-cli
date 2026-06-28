/// Integration tests for SecretStoreBridge.
///
/// These tests talk to the real PowerShell SecretManagement stack.
/// They use a dedicated test vault ("MeVaultTest") and a fixed test password.
///
/// IMPORTANT: `create_vault` calls `Reset-SecretStore -Force`, which clears all secrets
/// in the store.  Do not run these tests on a machine where you have production secrets
/// in PowerShell SecretStore.
///
/// Run with:
///   cargo test -p mevault-core --test vault_integration -- --nocapture --test-threads=1
///
/// The `--test-threads=1` flag is required because all tests share the same underlying
/// SecretStore file, and concurrent writes can corrupt it.
#[cfg(target_os = "windows")]
mod tests {
    use mevault_core::vault::SecretStoreBridge;
    use secrecy::{ExposeSecret, SecretString};
    use std::sync::Mutex;

    const VAULT: &str = "MeVaultTest";
    const PASSWORD: &str = "MeVaultTestPass42!";

    // The PowerShell SecretStore is a single file on disk — serialise all tests
    // that touch it so they're safe whether cargo runs with 1 or N test threads.
    static STORE_LOCK: Mutex<()> = Mutex::new(());

    fn bridge() -> SecretStoreBridge {
        SecretStoreBridge::new()
    }

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_owned().into())
    }

    fn pw() -> SecretString {
        secret(PASSWORD)
    }

    /// Acquire the store lock and reset the test vault to a known state.
    /// Returns the lock guard — drop it at end of test to release.
    fn setup_vault() -> std::sync::MutexGuard<'static, ()> {
        let guard = STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        bridge()
            .create_vault(VAULT, &pw())
            .expect("create_vault (setup) failed");
        guard
    }

    // ── 1. Module check ────────────────────────────────────────────────────

    #[test]
    fn check_modules_returns_true() {
        let ok = bridge().check_modules().expect("check_modules failed");
        assert!(ok, "SecretManagement modules must be installed");
    }

    // ── 2. PS plumbing — variable embedding ───────────────────────────────

    #[test]
    fn ps_variable_round_trip() {
        // Verifies the fixed run_ps embedding: value must arrive unchanged.
        let ok = bridge().check_modules().expect("ps invocation failed");
        assert!(ok);
    }

    // ── 3. Vault creation ──────────────────────────────────────────────────

    #[test]
    fn create_vault_registers_and_is_idempotent() {
        let _guard = setup_vault();

        let exists = bridge().vault_exists(VAULT).expect("vault_exists failed");
        assert!(exists, "vault should exist after create_vault");

        // Second call: vault already registered — should be idempotent.
        bridge()
            .create_vault(VAULT, &pw())
            .expect("second create_vault (idempotent) failed");

        let still_exists = bridge().vault_exists(VAULT).expect("vault_exists failed");
        assert!(still_exists, "vault should still exist after idempotent create");
    }

    // ── 4. Set / Get / Remove (all with password — unlock doesn't persist
    //       across PS subprocesses so every call must unlock)  ────────────

    #[test]
    fn set_get_remove_secret() {
        let _guard = setup_vault();
        let b = bridge();

        b.set_secret("TEST_KEY", &secret("hello-world-value"), VAULT, Some(&pw()))
            .expect("set_secret failed");

        // get_secret: must also pass password since unlock doesn't persist cross-process.
        let got = b
            .get_secret("TEST_KEY", VAULT, Some(&pw()))
            .expect("get_secret failed");
        assert_eq!(
            got.expose_secret(),
            "hello-world-value",
            "retrieved value must match stored value"
        );

        b.remove_secret("TEST_KEY", VAULT, Some(&pw()))
            .expect("remove_secret failed");

        // Verify gone.
        let result = b.get_secret("TEST_KEY", VAULT, Some(&pw()));
        assert!(
            result.is_err(),
            "get_secret after remove should return an error"
        );
    }

    // ── 5. Single-quote in value ───────────────────────────────────────────

    #[test]
    fn secret_with_single_quote() {
        let _guard = setup_vault();
        let b = bridge();

        let tricky = "it's a test value";
        b.set_secret("TEST_QUOTE", &secret(tricky), VAULT, Some(&pw()))
            .expect("set_secret with quote failed");

        let got = b
            .get_secret("TEST_QUOTE", VAULT, Some(&pw()))
            .expect("get_secret with quote failed");
        assert_eq!(got.expose_secret(), tricky);

        b.remove_secret("TEST_QUOTE", VAULT, Some(&pw())).ok();
    }

    // ── 6. List secrets ────────────────────────────────────────────────────

    #[test]
    fn list_secrets_shows_stored_names() {
        let _guard = setup_vault();
        let b = bridge();

        b.set_secret("LIST_A", &secret("val-a"), VAULT, Some(&pw()))
            .expect("set LIST_A");
        b.set_secret("LIST_B", &secret("val-b"), VAULT, Some(&pw()))
            .expect("set LIST_B");

        let secrets = b
            .list_secrets(VAULT, Some(&pw()))
            .expect("list_secrets failed");

        let names: Vec<&str> = secrets.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"LIST_A"), "LIST_A should appear; got: {names:?}");
        assert!(names.contains(&"LIST_B"), "LIST_B should appear; got: {names:?}");

        b.remove_secret("LIST_A", VAULT, Some(&pw())).ok();
        b.remove_secret("LIST_B", VAULT, Some(&pw())).ok();
    }

    // ── 7. Audit log ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn audit_log_write_and_filter() {
        use mevault_core::audit::{AuditEvent, AuditLog, EventType};

        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test_audit.db");
        let log = AuditLog::open(&db_path).await.expect("open audit log");

        log.write(
            AuditEvent::new(EventType::Allowed)
                .secret("DATABASE_URL")
                .vault(VAULT)
                .process("uvicorn.exe", 9999)
                .reason("allow_list match"),
        )
        .await
        .expect("write allowed event");

        log.write(
            AuditEvent::new(EventType::Denied)
                .secret("OPENAI_KEY")
                .vault(VAULT)
                .process("claude.exe", 1234)
                .reason("always_deny"),
        )
        .await
        .expect("write denied event");

        let all = log.query(None, None, None, 100).await.expect("query all");
        assert_eq!(all.len(), 2);

        let denied = log
            .query(Some("denied"), None, None, 100)
            .await
            .expect("query denied");
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].process_path.as_deref(), Some("claude.exe"));

        let for_db = log
            .query(None, Some("DATABASE_URL"), None, 100)
            .await
            .expect("query by secret name");
        assert_eq!(for_db.len(), 1);
        assert_eq!(for_db[0].event_type, "allowed");

        let recent = log
            .query(None, None, Some(1), 100)
            .await
            .expect("query last 1 hour");
        assert_eq!(recent.len(), 2);
    }

    // ── 8. Config roundtrips ───────────────────────────────────────────────

    #[test]
    fn project_config_save_and_load() {
        use mevault_core::config::ProjectConfig;

        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = ProjectConfig::new("IntegrationTest", "IntegrationTest");
        cfg.save(dir.path()).expect("save config");
        let loaded = ProjectConfig::load(dir.path()).expect("load config");
        assert_eq!(loaded.project.name, "IntegrationTest");
        assert_eq!(loaded.project.vault_name, "IntegrationTest");
        assert_eq!(loaded.deny_list.always_deny.len(), 7);
    }

    // ── 9. Always-deny list ───────────────────────────────────────────────

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

    // ── 10. End-to-end proxy integration ─────────────────────────────────
    //
    // Starts a real axum proxy on 127.0.0.1:52731, uses real reqwest calls,
    // verifies token auth and secret retrieval. Identity check is disabled so
    // the test binary doesn't need to be on the allow-list.
    #[tokio::test]
    async fn proxy_serves_and_rejects_properly() {
        use mevault_core::{
            audit::AuditLog,
            config::{ExpiryMode, ProjectConfig},
            proxy::{run_proxy, ProxyState},
            session::{Session, SessionManager},
        };
        use std::sync::Arc;

        let _guard = setup_vault();
        let b = bridge();

        b.set_secret("PROXY_DB_URL", &secret("postgres://proxy-test"), VAULT, Some(&pw()))
            .expect("set PROXY_DB_URL");

        let secrets = b
            .unlock_and_preload(VAULT, &pw())
            .expect("unlock_and_preload");

        let manager = SessionManager::new();
        let session = Session::new(
            VAULT,
            ExpiryMode::Both,
            Some(8),
            std::process::id(),
            std::path::PathBuf::from("."),
            secrets,
        );
        manager.start(session).await;

        let mut cfg = ProjectConfig::new("ProxyTest", VAULT);
        cfg.security.require_identity_check = false; // test binary not on allow-list

        let dir = tempfile::tempdir().expect("tempdir");
        let audit =
            Arc::new(AuditLog::open(&dir.path().join("proxy.db")).await.expect("audit"));

        let state = ProxyState {
            session: manager.shared(),
            audit,
            config: Arc::new(cfg),
        };

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let proxy_handle = tokio::spawn(run_proxy(state, async move {
            let _ = shutdown_rx.await;
        }));

        // Give the listener time to bind.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let client = reqwest::Client::new();

        // /status — no auth required
        let resp = client
            .get("http://127.0.0.1:52731/status")
            .send()
            .await
            .expect("status GET");
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.expect("status json");
        assert_eq!(body["status"], "active", "proxy should report active session");

        // valid secret name → 200 with the stored value (identity check disabled in test cfg)
        let resp = client
            .get("http://127.0.0.1:52731/secret/PROXY_DB_URL")
            .send()
            .await
            .expect("secret GET");
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.expect("secret json");
        assert_eq!(body["name"], "PROXY_DB_URL");
        assert_eq!(body["value"], "postgres://proxy-test");

        // nonexistent secret → 404
        let resp = client
            .get("http://127.0.0.1:52731/secret/NO_SUCH_SECRET")
            .send()
            .await
            .expect("missing secret GET");
        assert_eq!(resp.status(), 404);

        // Graceful shutdown + cleanup.
        let _ = shutdown_tx.send(());
        proxy_handle.await.ok();
        b.remove_secret("PROXY_DB_URL", VAULT, Some(&pw())).ok();
    }
}

#[cfg(not(target_os = "windows"))]
#[test]
fn vault_tests_windows_only() {
    println!("SecretStore integration tests only run on Windows — skipped");
}
