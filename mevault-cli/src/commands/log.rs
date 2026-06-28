use anyhow::{Context, Result};
use mevault_core::audit::AuditLog;
use std::path::PathBuf;

pub async fn run(
    tail: u32,
    event_type: Option<String>,
    secret: Option<String>,
    since_hours: Option<u32>,
    export_path: Option<PathBuf>,
) -> Result<()> {
    let appdata = std::env::var("APPDATA").context("APPDATA env var not set")?;
    let db_path = PathBuf::from(appdata).join("MeVault").join("audit.db");

    if !db_path.exists() {
        println!("No audit log found at {}.", db_path.display());
        return Ok(());
    }

    let log = AuditLog::open(&db_path).await.context("opening audit log")?;

    let events = log
        .query(
            event_type.as_deref(),
            secret.as_deref(),
            since_hours,
            tail,
        )
        .await
        .context("querying audit log")?;

    if events.is_empty() {
        println!("No events match the filter.");
        return Ok(());
    }

    if let Some(path) = export_path {
        let json = serde_json::to_string_pretty(&events).context("serializing events")?;
        std::fs::write(&path, json)
            .with_context(|| format!("writing {}", path.display()))?;
        println!("Exported {} event(s) to {}.", events.len(), path.display());
        return Ok(());
    }

    // Terminal display.
    println!(
        "{:<20} {:<10} {:<25} {:<20} {}",
        "Timestamp", "Event", "Secret", "Process", "Reason"
    );
    println!("{}", "─".repeat(90));
    for e in &events {
        let ts = e.timestamp.chars().take(19).collect::<String>(); // trim sub-seconds
        let event = e.event_type.as_str();
        let secret = e.secret_name.as_deref().unwrap_or("—");
        let process = e
            .process_path
            .as_deref()
            .and_then(|p| p.rsplit(['/', '\\']).next())
            .unwrap_or("—");
        let reason = e.reason.as_deref().unwrap_or("—");

        let prefix = match event {
            "allowed" => "✓",
            "denied" => "✗",
            _ => "·",
        };

        println!(
            "{ts:<20} {prefix}{event:<9} {secret:<25} {process:<20} {reason}"
        );
    }
    println!("{}", "─".repeat(90));
    println!("{} event(s) shown.", events.len());

    Ok(())
}
