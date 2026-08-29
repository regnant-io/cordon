//! `cordon pull`, `cordon models`, and `cordon remove`.

use std::path::Path;

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};

use cordon_core::hub::{self, HubClient, ModelRef};

/// Fetch a model from the Hub into `model_dir`.
pub async fn pull(reference: &str, model_dir: &Path) -> Result<()> {
    let model = ModelRef::parse(reference).context("invalid model reference")?;
    let client = HubClient::new()?;

    println!("Resolving {}…", model);
    let resolved = client.resolve(&model).await?;

    println!("  repository  {}", resolved.repo_id);
    println!("  revision    {}", short_revision(&resolved.revision));
    println!("  file        {}", resolved.filename);
    if let Some(quant) = &resolved.quant {
        println!("  quant       {}", quant);
    }
    println!();

    let local_id = model.local_id();
    let bar = ProgressBar::new(0);
    bar.set_style(
        ProgressStyle::with_template(
            "  {bar:34.cyan/blue} {bytes:>10}/{total_bytes:<10} {bytes_per_sec:>11}  eta {eta}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("━━╸"),
    );

    let mut total_known = false;
    let downloaded = client
        .download(&resolved, &local_id, model_dir, |progress| {
            if let Some(total) = progress.total {
                if !total_known {
                    bar.set_length(total);
                    total_known = true;
                }
            }
            bar.set_position(progress.downloaded);
        })
        .await?;

    bar.finish_and_clear();

    println!("Pulled {}", downloaded.id);
    println!("  path        {}", downloaded.path.display());
    println!("  size        {}", human_bytes(downloaded.size_bytes));
    println!("  sha256      {}", downloaded.sha256);
    if downloaded.digest_verified {
        println!("  integrity   verified against the digest published by the Hub");
    } else {
        // Say so plainly. A digest that was computed but not checked against
        // anything proves only that the bytes were hashed after arrival.
        println!("  integrity   UNVERIFIED — the Hub published no content digest for");
        println!("              this file, so the hash above records what arrived and");
        println!("              does not confirm it is what the publisher uploaded.");
    }
    println!();
    println!("Serve it with:");
    println!("    cordon run {}", downloaded.id);
    Ok(())
}

/// List models present in `model_dir`.
pub fn list(model_dir: &Path) -> Result<()> {
    let models = hub::list_local_models(model_dir)?;

    if models.is_empty() {
        println!("No models in {}.", model_dir.display());
        println!();
        println!("Fetch one:");
        println!("    cordon pull HuggingFaceTB/SmolLM2-360M-Instruct-GGUF");
        return Ok(());
    }

    let width = models.iter().map(|m| m.id.len()).max().unwrap_or(4).max(4);
    println!("{:<width$}  {:>10}  {:<9}  SOURCE", "ID", "SIZE", "QUANT");
    for model in &models {
        println!(
            "{:<width$}  {:>10}  {:<9}  {}",
            model.id,
            human_bytes(model.size_bytes),
            model.quant.as_deref().unwrap_or("—"),
            model.repo_id,
            width = width
        );
    }

    let unverified = models.iter().filter(|m| !m.digest_verified).count();
    if unverified > 0 {
        println!();
        println!(
            "{} model(s) were downloaded without a publisher digest to check against.",
            unverified
        );
    }
    Ok(())
}

/// Remove a model and its record.
pub fn remove(id: &str, model_dir: &Path) -> Result<()> {
    if hub::remove_local_model(model_dir, id)? {
        println!("Removed {}", id);
        Ok(())
    } else {
        bail!(
            "no model named '{}' in {}. Run `cordon models` to see what is available.",
            id,
            model_dir.display()
        )
    }
}

fn short_revision(revision: &str) -> String {
    if revision.len() > 12 && revision.chars().all(|c| c.is_ascii_hexdigit()) {
        revision[..12].to_string()
    } else {
        revision.to_string()
    }
}

/// Format a byte count for a human reader.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_byte_counts() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(229_118_944), "218.5 MiB");
        assert_eq!(human_bytes(5_000_000_000), "4.7 GiB");
    }

    #[test]
    fn shortens_commit_hashes_only() {
        assert_eq!(short_revision("main"), "main");
        assert_eq!(
            short_revision("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"),
            "a1b2c3d4e5f6"
        );
        assert_eq!(short_revision("release-2024"), "release-2024");
    }
}
