mod commands;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "mevault",
    version,
    about = "Local-first secret manager for developers",
    long_about = "MeVault keeps your secrets encrypted locally and only reveals them to\n\
                  verified, allow-listed processes — never to AI agents.\n\n\
                  Quick start:\n  \
                  mevault init\n  \
                  mevault unlock\n  \
                  mevault run uvicorn app.main:app"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Validate the current mevault.toml for errors
    Validate,
    /// Migrate legacy allow-list rules to [[process]] format
    Migrate,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault in the current project
    Init {
        #[arg(long, help = "Vault/project name (defaults to folder name)")]
        name: Option<String>,
        #[arg(long, help = "Project root directory (defaults to cwd)")]
        vault_dir: Option<PathBuf>,
    },

    /// Unlock the vault and start the proxy server (blocks until Ctrl+C or lock)
    Unlock,

    /// Lock the vault immediately (terminates the proxy server)
    Lock,

    /// Show current session and proxy status
    Status,

    /// Run system diagnostics: project config, vault, session, proxy, updater
    Doctor {
        /// Simulate a launch: show whether this command would be allowed
        #[arg(long, num_args = 1.., value_name = "ARGS")]
        command: Option<Vec<String>>,
    },

    /// Run a command with MeVault secrets available via the proxy
    Run {
        /// Program to run
        program: String,
        /// Arguments passed to the program
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        /// Inject secrets as environment variables (less secure — values
        /// visible to child subprocesses; use only for legacy apps that
        /// cannot use the MeVault SDK or named-pipe proxy)
        #[arg(long)]
        inject_env: bool,
    },

    /// Add a secret to the vault
    Add {
        /// Secret name (e.g. DATABASE_URL)
        name: Option<String>,
        /// Import all variables from a .env file
        #[arg(long = "from-env", value_name = "FILE")]
        from_env: Option<PathBuf>,
        /// Auto-generate a secure random value
        #[arg(long)]
        generate: bool,
    },

    /// List secret names in the vault (values never shown)
    List {
        #[arg(long)]
        vault: Option<String>,
    },

    /// View the audit log
    Log {
        /// Show last N events (default: 50)
        #[arg(long, default_value = "50")]
        tail: u32,
        /// Filter by event type (allowed, denied, locked, etc.)
        #[arg(long = "type", value_name = "TYPE")]
        event_type: Option<String>,
        /// Filter by secret name
        #[arg(long)]
        secret: Option<String>,
        /// Show events from the last N hours
        #[arg(long)]
        since: Option<u32>,
        /// Export results to a JSON file
        #[arg(long)]
        export: Option<PathBuf>,
    },

    /// Export secrets to an encrypted file
    Export {
        /// Format: encrypt (.env.mvenc, default), mvx (encrypted bundle)
        #[arg(long, default_value = "encrypt")]
        format: String,
        /// Output file path
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// Override vault name
        #[arg(long)]
        vault: Option<String>,
    },

    /// Import secrets from a .env, .env.mvenc, or .mvx file
    Import {
        /// File to import
        file: PathBuf,
        /// Override vault name
        #[arg(long)]
        vault: Option<String>,
    },

    /// Verify a stored secret matches an expected value without revealing it
    Verify {
        /// Secret name to verify
        name: String,
        /// Compare against file contents instead of interactive input
        #[arg(long = "from-file", value_name = "FILE")]
        from_file: Option<PathBuf>,
    },

    /// Retrieve a secret value (requires explicit --reveal flag)
    Get {
        /// Secret name
        name: String,
        /// Display the value in the terminal (requires allow_cli_reveal = true in config)
        #[arg(long)]
        reveal: bool,
    },

    /// Validate or migrate mevault.toml project configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { name, vault_dir } => {
            if let Err(e) = commands::init::run(name, vault_dir) {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
        Commands::Unlock => {
            if let Err(e) = commands::unlock::run().await {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
        Commands::Lock => {
            if let Err(e) = commands::lock::run().await {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
        Commands::Status => {
            if let Err(e) = commands::status::run().await {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
        Commands::Doctor { command } => {
            if let Err(e) = commands::doctor::run(command).await {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
        Commands::Run {
            program,
            args,
            inject_env,
        } => {
            if let Err(e) = commands::run::run(&program, &args, inject_env).await {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
        Commands::Add {
            name,
            from_env,
            generate,
        } => {
            if let Err(e) = commands::add::run(name, from_env, generate).await {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
        Commands::List { vault } => {
            if let Err(e) = commands::list::run(vault).await {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
        Commands::Log {
            tail,
            event_type,
            secret,
            since,
            export,
        } => {
            if let Err(e) = commands::log::run(tail, event_type, secret, since, export).await {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
        Commands::Export {
            format,
            output,
            vault,
        } => {
            if let Err(e) = commands::export::run(&format, output, vault).await {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
        Commands::Import { file, vault } => {
            if let Err(e) = commands::import::run(file, vault).await {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
        Commands::Verify { name, from_file } => {
            return commands::verify::run(name, from_file);
        }
        Commands::Get { name, reveal } => {
            if let Err(e) = commands::get::run(name, reveal).await {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
        Commands::Config { action } => {
            if let Err(e) = commands::config::run(action).await {
                eprintln!("Error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}
