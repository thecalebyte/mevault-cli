use anyhow::{bail, Context, Result};
use mevault_core::{
    config::ProjectConfig,
    vault::SecretStoreBridge,
};
use secrecy::SecretString;
use std::path::PathBuf;

pub fn run(name: Option<String>, vault_dir: Option<PathBuf>) -> Result<()> {
    let project_root = vault_dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let toml_path = project_root.join("mevault.toml");
    if toml_path.exists() {
        bail!(
            "mevault.toml already exists in {}. Run `mevault add` to add secrets.",
            project_root.display()
        );
    }

    let vault_name = name.unwrap_or_else(|| {
        project_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("MyVault")
            .to_owned()
    });

    println!("Initializing MeVault for project: {vault_name}");
    println!("Project root: {}", project_root.display());

    let bridge = SecretStoreBridge::new();

    // Check modules
    print!("Checking PowerShell SecretManagement modules... ");
    match bridge.check_modules() {
        Ok(true) => println!("OK"),
        Ok(false) => {
            println!("not found");
            print!("Installing modules (requires internet)... ");
            bridge.install_modules().context("installing SecretManagement modules")?;
            println!("done");
        }
        Err(e) => {
            println!("error: {e}");
            bail!("Cannot check PowerShell modules. Ensure PowerShell 5.1+ is installed.");
        }
    }

    // Check if vault already registered
    if bridge.vault_exists(&vault_name)? {
        println!("Vault '{vault_name}' already exists in SecretStore — reusing it.");
    } else {
        println!("\nSet master password for vault '{vault_name}':");
        let password = read_password_confirmed()?;
        print!("Creating vault '{vault_name}'... ");
        bridge
            .create_vault(&vault_name, &password)
            .context("creating SecretStore vault")?;
        println!("done");
    }

    // Write mevault.toml
    let cfg = ProjectConfig::new(&vault_name, &vault_name);
    cfg.save(&project_root)
        .context("writing mevault.toml")?;

    println!("\nSetup complete!");
    println!("  Vault:   {vault_name}");
    println!("  Config:  {}", toml_path.display());
    println!("\nNext steps:");
    println!("  mevault add DATABASE_URL    # add your first secret");
    println!("  mevault unlock              # start a session");
    println!("  mevault run <your-server>   # run with secrets available via named pipe");

    Ok(())
}

fn read_password_confirmed() -> Result<SecretString> {
    loop {
        let pw1 = rpassword::prompt_password("Password: ")
            .context("reading password")?;
        if pw1.len() < 12 {
            eprintln!("Password must be at least 12 characters. Try again.");
            continue;
        }
        let pw2 = rpassword::prompt_password("Confirm:  ")
            .context("reading confirmation")?;
        if pw1 != pw2 {
            eprintln!("Passwords do not match. Try again.");
            continue;
        }
        return Ok(SecretString::new(pw1.into()));
    }
}
