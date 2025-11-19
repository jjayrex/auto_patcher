use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::Deserialize;

const MANIFEST_URL: &str = "https://example.com/manifest.json.zst";

#[derive(Deserialize)]
struct Patch {
    /// Patch name
    patch: String,
    /// Version detection key
    key: Key,
    /// Files to add
    #[serde(default)]
    added: Vec<PathBuf>,
    /// Files to patch
    #[serde(default)]
    modified: Vec<PathBuf>,
    /// URL for files to add
    source_added: Vec<String>,
    /// URL for files to patch
    source_modified: Vec<String>,
    /// Expected hashes to verify against
    verify: Vec<u32>,
}

#[derive(Deserialize)]
struct Key {
    hash: u32,
    file: PathBuf,
}

fn main() -> Result<()> {
    let root = std::env::current_dir().context("Failed to get current directory")?;

    let manifest_bytes = download_bytes(&MANIFEST_URL).context("Failed to download manifest")?;

    let decompressed =
        zstd::stream::decode_all(&manifest_bytes[..]).context("Failed to decompress zstd")?;

    let patches: Vec<Patch> =
        serde_json::from_slice(&decompressed).context("Failed to parse manifest JSON")?;

    if patches.is_empty() {
        bail!("Manifest contains no patches");
    }

    let mut any_applied = false;

    for patch in &patches {
        println!("Checking patch: {}", patch.patch);

        let key_path = root.join(&patch.key.file);
        let current_crc = crc32c_file(&key_path).with_context(|| {
            format!(
                "Failed to compute CRC32C for key file: {}",
                key_path.display()
            )
        })?;

        if current_crc != patch.key.hash {
            continue;
        }

        println!("  Key hash matches. Applying patch {} ...", patch.patch);
        validate_patch(patch)?;

        apply_patch(patch, &root)?;
        any_applied = true;

        println!("  Patch {} applied successfully.", patch.patch);
        println!();
    }

    if !any_applied {
        println!("No matching patch found for current version.");
    } else {
        println!("All applicable patches applied.");
    }

    Ok(())
}

fn validate_patch(patch: &Patch) -> Result<()> {
    if patch.added.len() != patch.source_added.len() {
        bail!(
            "Patch {}: `added` and `source_added` length mismatch ({} vs {}).",
            patch.patch,
            patch.added.len(),
            patch.source_added.len()
        );
    }
    if patch.modified.len() != patch.source_modified.len()
        || patch.modified.len() != patch.verify.len()
    {
        bail!(
            "Patch {}: `modified`, `source_modified`, `verify` length mismatch ({} / {} / {}).",
            patch.patch,
            patch.modified.len(),
            patch.source_modified.len(),
            patch.verify.len()
        );
    }
    Ok(())
}

fn apply_patch(patch: &Patch, root: &Path) -> Result<()> {
    let mp = MultiProgress::new();

    let style = ProgressStyle::with_template(
        "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}",
    )?
        .progress_chars("=>-");

    // Handle added files
    if !patch.added.is_empty() {
        let pb_added =
            mp.add(ProgressBar::new(patch.added.len() as u64).with_style(style.clone()));
        pb_added.set_message("added");

        let pb_added_for_threads = pb_added.clone();

        patch
            .added
            .par_iter()
            .enumerate()
            .try_for_each(|(idx, rel_path)| -> Result<()> {
                let url = &patch.source_added[idx];
                let dest_path = root.join(rel_path);

                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("Failed to create parent directories for {}", dest_path.display())
                    })?;
                }

                let data = download_bytes(url).with_context(|| {
                    format!("Failed to download new file from {}", url)
                })?;

                fs::write(&dest_path, &data).with_context(|| {
                    format!("Failed to write new file {}", dest_path.display())
                })?;

                pb_added_for_threads.inc(1);
                Ok(())
            })?;

        pb_added.finish_with_message("added");
    }

    // Handle modified files
    if !patch.modified.is_empty() {
        let pb_mod =
            mp.add(ProgressBar::new(patch.modified.len() as u64).with_style(style.clone()));
        pb_mod.set_message("patched");

        let pb_mod_for_threads = pb_mod.clone();

        patch
            .modified
            .par_iter()
            .enumerate()
            .try_for_each(|(idx, rel_path)| -> Result<()> {
                let diff_url = &patch.source_modified[idx];
                let expected_crc = patch.verify[idx];

                let target_path = root.join(rel_path);

                // Read original file
                let original = fs::read(&target_path).with_context(|| {
                    format!("Failed to read original file {}", target_path.display())
                })?;

                // Download diff
                let diff = download_bytes(diff_url)
                    .with_context(|| format!("Failed to download diff from {}", diff_url))?;

                // Apply xdelta
                let new_data = xdelta3::decode(&diff, &original).ok_or_else(|| {
                    anyhow!(
                        "xdelta3 decode failed for {} (diff URL: {})",
                        target_path.display(),
                        diff_url
                    )
                })?;

                // Verify CRC32C
                let actual_crc = crc32c::crc32c(&new_data);
                if actual_crc != expected_crc {
                    bail!(
                        "CRC32C mismatch after patching {}: expected {}, got {}",
                        target_path.display(),
                        expected_crc,
                        actual_crc
                    );
                }

                // Write to temp file then replace
                let tmp_path = target_path.with_extension("tmp_patch");

                if let Some(parent) = tmp_path.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("Failed to create parent directory for {}", tmp_path.display())
                    })?;
                }

                fs::write(&tmp_path, &new_data).with_context(|| {
                    format!("Failed to write temp patched file {}", tmp_path.display())
                })?;

                fs::rename(&tmp_path, &target_path).with_context(|| {
                    format!(
                        "Failed to replace original file {} with patched version",
                        target_path.display()
                    )
                })?;

                pb_mod_for_threads.inc(1);
                Ok(())
            })?;

        pb_mod.finish_with_message("patched");
    }

    let _ = mp.clear();

    Ok(())
}

fn download_bytes(url: &str) -> Result<Vec<u8>> {
    use reqwest::blocking::get;

    let resp = get(url).with_context(|| format!("HTTP GET failed for {url}"))?;

    if !resp.status().is_success() {
        bail!("HTTP GET {} returned status {}", url, resp.status());
    }

    let bytes = resp.bytes().context("Failed to read HTTP response body")?;
    Ok(bytes.to_vec())
}

fn crc32c_file(path: &Path) -> Result<u32> {
    let data = fs::read(path)
        .with_context(|| format!("Failed to read file for CRC32C: {}", path.display()))?;
    Ok(crc32c::crc32c(&data))
}
