mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

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

    /// Run a command with MeVault secrets available via the proxy
    Run {
        /// Program to run
        program: String,
        /// Arguments passed to the program
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { name, vault_dir } => {
            commands::init::run(name, vault_dir)?;
        }
        Commands::Unlock => {
            commands::unlock::run().await?;
        }
        Commands::Lock => {
            commands::lock::run().await?;
        }
        Commands::Status => {
            commands::status::run().await?;
        }
        Commands::Run { program, args } => {
            commands::run::run(&program, &args).await?;
        }
        Commands::Add { name, from_env, generate } => {
            commands::add::run(name, from_env, generate).await?;
        }
        Commands::List { vault } => {
            commands::list::run(vault)?;
        }
        Commands::Log { tail, event_type, secret, since, export } => {
            commands::log::run(tail, event_type, secret, since, export).await?;
        }
        Commands::Export { format, output, vault } => {
            commands::export::run(&format, output, vault).await?;
        }
        Commands::Import { file, vault } => {
            commands::import::run(file, vault).await?;
        }
    }

    Ok(())
}
