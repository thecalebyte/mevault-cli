/// Subprocess helper used exclusively by cross-process concurrency integration
/// tests.  Only built when the `test-helper` feature is enabled.
///
/// Usage: vault-write-helper <vault_dir> <vault_name> <secret_name>
///
/// Credentials (secret_value, password) are read from stdin as a single JSON
/// object so they never appear in process listings:
///   {"secret_value": "...", "password": "..."}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: vault-write-helper <vault_dir> <vault_name> <secret_name>");
        std::process::exit(2);
    }

    #[derive(serde::Deserialize)]
    struct HelperInput {
        secret_value: String,
        password: String,
    }

    let input: HelperInput =
        serde_json::from_reader(std::io::stdin().lock())
            .unwrap_or_else(|e| {
                eprintln!("vault-write-helper: invalid stdin JSON: {e}");
                std::process::exit(2);
            });

    let vault_dir = std::path::PathBuf::from(&args[1]);
    let vault_name = &args[2];
    let secret_name = &args[3];

    #[cfg(debug_assertions)]
    let store = mevault_core::vault::VaultStore::new_at_with_policy(
        vault_dir,
        mevault_core::crypto::CryptoPolicy::fast_test(),
    );
    #[cfg(not(debug_assertions))]
    let store = mevault_core::vault::VaultStore::new_at(vault_dir);

    let pw = secrecy::SecretString::new(input.password.into());
    let val = secrecy::SecretString::new(input.secret_value.into());

    if let Err(e) = store.set_secret(secret_name, &val, vault_name, Some(&pw)) {
        eprintln!("vault-write-helper: set_secret failed: {e}");
        std::process::exit(1);
    }
}
