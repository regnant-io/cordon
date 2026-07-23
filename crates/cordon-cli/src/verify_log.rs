//! cordon-verify-log — Client-side audit log integrity verifier
//!
//! Implements §9.3: verifies Merkle chain + Ed25519 signatures.
//! Requires only: exported log + client's K_log public key.
//! No connection to Cordon node required.
//!
//! Usage:
//!   cordon-verify-log --log <path> --key <hex> --deployment-id <id>

use std::path::PathBuf;
use anyhow::{Context, Result};
use clap::Parser;
use chrono::Utc;

use cordon_crypto::signing::VerifyingKey;
use cordon_audit::verify::verify_log_chain;

#[derive(Parser)]
#[command(
    name = "cordon-verify-log",
    about = "Verify Cordon audit log integrity",
    long_about = "Verifies the Merkle chain and Ed25519 signatures of a Cordon audit log.\n\
        Requires the client's K_log verifying key (the PUBLIC key — safe to use offline).\n\
        No connection to the Cordon node is required.\n\n\
        Exit code: 0 = valid, 1 = invalid/tampered, 2 = error",
)]
struct Cli {
    /// Path to audit log file or directory containing .jsonl files
    #[arg(short, long)]
    log: PathBuf,

    /// K_log verifying key (hex, 32 bytes / 64 hex chars)
    #[arg(short, long)]
    key: String,

    /// Deployment ID (used to verify genesis entry)
    #[arg(short, long)]
    deployment_id: String,

    /// Output format (text or json)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Show event summary statistics
    #[arg(long)]
    summary: bool,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(valid) => {
            if valid {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<bool> {
    // Parse verifying key
    let vk = VerifyingKey::from_hex(&cli.key)
        .context("Invalid K_log verifying key hex")?;

    // Run verification
    let started = std::time::Instant::now();
    let result = verify_log_chain(&cli.log, &vk, &cli.deployment_id)
        .context("Log verification failed")?;
    let elapsed_ms = started.elapsed().as_millis();

    match cli.format.as_str() {
        "json" => {
            let output = serde_json::json!({
                "valid": result.valid,
                "entries_verified": result.entries_verified,
                "first_entry": result.first_entry,
                "last_entry": result.last_entry,
                "log_tail_hash": result.log_tail_hash,
                "violations": result.violations,
                "elapsed_ms": elapsed_ms,
                "verified_at": Utc::now(),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => {
            println!("Cordon Audit Log Verifier");
            println!("══════════════════════════");
            println!("Log path:    {:?}", cli.log);
            println!("Deployment:  {}", cli.deployment_id);
            println!("Verified at: {}", Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
            println!();

            if result.valid {
                println!("✓ VALID — chain intact, all signatures verified");
            } else {
                println!("✗ INVALID — log has been tampered with");
            }

            println!();
            println!("Entries verified: {}", result.entries_verified);

            if let Some(first) = result.first_entry {
                println!("First entry:      {}", first.format("%Y-%m-%d %H:%M:%S UTC"));
            }
            if let Some(last) = result.last_entry {
                println!("Last entry:       {}", last.format("%Y-%m-%d %H:%M:%S UTC"));
            }
            if let Some(tail) = &result.log_tail_hash {
                println!("Tail hash:        {}", &tail[..32.min(tail.len())]);
            }
            println!("Elapsed:          {}ms", elapsed_ms);

            if !result.violations.is_empty() {
                println!();
                println!("VIOLATIONS ({}):", result.violations.len());
                for v in &result.violations {
                    println!("  ✗ {}", v);
                }
            }

            if cli.summary {
                println!();
                println!("Event summary:");
                let paths: Vec<_> = if cli.log.is_dir() {
                    let mut v: Vec<_> = std::fs::read_dir(&cli.log)
                        .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path())
                             .filter(|p| p.extension().map(|e| e == "jsonl").unwrap_or(false))
                             .collect())
                        .unwrap_or_default();
                    v.sort();
                    v
                } else {
                    vec![cli.log.clone()]
                };
                let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
                let mut total = 0usize;
                for path in &paths {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        for line in content.lines() {
                            if line.trim().is_empty() { continue; }
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                                let etype = val.get("payload")
                                    .and_then(|p| p.get("event_type"))
                                    .and_then(|e| e.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                *counts.entry(etype).or_insert(0) += 1;
                                total += 1;
                            }
                        }
                    }
                }
                let mut sorted: Vec<_> = counts.iter().collect();
                sorted.sort_by(|a, b| b.1.cmp(a.1));
                for (event_type, count) in sorted {
                    println!("  {:20} {}", event_type, count);
                }
                println!("  Total:               {}", total);
            }
        }
    }

    Ok(result.valid)
}
