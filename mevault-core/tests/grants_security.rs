use mevault_core::{
    config::ProcessRule,
    grants::{LaunchGrant, LaunchGrantRegistry},
};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::SystemTime;
use uuid::Uuid;

fn make_grant(pid: u32, process_created_at: u64, secrets: Vec<String>) -> LaunchGrant {
    LaunchGrant {
        id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        root_pid: pid,
        process_created_at,
        executable: PathBuf::from("test.exe"),
        working_directory: PathBuf::from("."),
        allowed_secrets: secrets.into_iter().collect::<HashSet<_>>(),
        created_at: SystemTime::now(),
    }
}

fn make_rule(secrets: Vec<&str>, allow_all_secrets: bool) -> ProcessRule {
    ProcessRule {
        name: "test-rule".to_owned(),
        executable: "test.exe".to_owned(),
        working_dir: None,
        command: vec![],
        launch_only: false,
        signed: false,
        secrets: secrets.into_iter().map(str::to_owned).collect(),
        allow_all_secrets,
    }
}

#[test]
fn pid_reuse_cannot_forge_grant() {
    let registry = LaunchGrantRegistry::new();
    let pid = 999_u32;
    let real_ts = 12345_u64;
    let forged_ts = 99999_u64;

    registry.register(make_grant(pid, real_ts, vec![]));

    // Mismatched timestamp — must be denied.
    assert!(
        registry.get(pid, forged_ts).is_none(),
        "lookup with mismatched creation time must return None"
    );

    // Correct pair — must succeed.
    assert!(
        registry.get(pid, real_ts).is_some(),
        "lookup with correct (pid, created_at) must succeed"
    );
}

#[test]
fn revoke_by_pid_removes_grant() {
    let registry = LaunchGrantRegistry::new();
    let pid = 1234_u32;
    let created_at = 42_u64;

    registry.register(make_grant(pid, created_at, vec![]));
    assert!(registry.get(pid, created_at).is_some());

    registry.revoke_by_pid(pid);

    assert!(
        registry.get(pid, created_at).is_none(),
        "grant must be absent after revoke_by_pid"
    );
}

#[test]
#[should_panic(expected = "process_created_at must not be zero")]
fn zero_created_at_panics() {
    let registry = LaunchGrantRegistry::new();
    registry.register(make_grant(1, 0, vec![]));
}

#[test]
fn wildcard_without_allow_all_secrets_denied() {
    let rule = make_rule(vec!["*"], false);
    assert!(
        !rule.allows_secret("MY_SECRET"),
        "wildcard must not grant access without allow_all_secrets = true"
    );
}

#[test]
fn wildcard_with_allow_all_secrets_allowed() {
    let rule = make_rule(vec!["*"], true);
    assert!(
        rule.allows_secret("MY_SECRET"),
        "wildcard must grant access when allow_all_secrets = true"
    );
}

#[test]
fn explicit_secret_list_allows_correct_lookup() {
    let grant = make_grant(5678, 100, vec!["DB_URL".to_owned()]);

    assert!(grant.allows_secret("DB_URL"), "DB_URL must be allowed");
    assert!(!grant.allows_secret("API_KEY"), "API_KEY must be denied");
}
