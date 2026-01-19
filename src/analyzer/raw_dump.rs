use eyre::Result;
use std::fs;
use std::path::{Path, PathBuf};

fn abbreviate_path(path: &Path, datadir: &Path, output: &Path) -> String {
    let path_str = path.to_string_lossy();
    let datadir_str = datadir.to_string_lossy();
    let output_str = output.to_string_lossy();

    if path_str.starts_with(&*output_str) {
        path_str.replace(&*output_str, "<outdir>")
    } else if path_str.starts_with(&*datadir_str) {
        path_str.replace(&*datadir_str, "<datadir>")
    } else {
        path_str.to_string()
    }
}

pub fn dump_raw_files(datadir: &Path, output: &Path) -> Result<()> {
    println!();

    // Dump consensus files
    dump_consensus_raw(datadir, output)?;

    // Dump static files
    dump_static_files_raw(datadir, output)?;

    println!();
    println!("Dump complete. Results saved to: {}", output.display());

    Ok(())
}

fn dump_consensus_raw(datadir: &Path, output: &Path) -> Result<()> {
    let consensus_path = datadir.join("consensus");

    // Get absolute paths for abbreviation
    let datadir_abs = datadir.canonicalize().unwrap_or(datadir.to_path_buf());
    let output_abs = output.canonicalize().unwrap_or(output.to_path_buf());

    println!("Consensus Storage:");

    // Key files to examine
    let important_files = vec![
        ("engine-finalized_blocks-freezer-value/0000000000000000", "finalized_blocks_value.hex"),
        ("engine-finalized_blocks-freezer-key/0000000000000000", "finalized_blocks_key.hex"),
        ("engine-finalized_blocks-ordinal/0000000000000000", "finalized_blocks_ordinal.hex"),
        ("engine-cache-cache-0-notarized-value/0000000000000000", "notarized_value.hex"),
        ("engine-cache-cache-0-notarized-key/0000000000000000", "notarized_key.hex"),
        ("engine-cache-cache-0-verified-value/0000000000000000", "verified_value.hex"),
        ("engine-cache-cache-0-verified-key/0000000000000000", "verified_key.hex"),
        ("engine-finalizations-by-height-freezer-value/0000000000000000", "finalizations_value.hex"),
        ("engine-finalizations-by-height-ordinal/0000000000000000", "finalizations_ordinal.hex"),
        ("engine_dkg_manager_events/0000000000000000", "dkg_events.hex"),
    ];

    for (rel_path, out_name) in important_files {
        let file_path = consensus_path.join(rel_path);
        if file_path.exists() {
            let data = fs::read(&file_path)?;
            let hex_data = hex::encode(&data);

            let out_path = output.join(format!("raw_{}", out_name));
            fs::write(&out_path, &hex_data)?;

            let out_path_abs = out_path.canonicalize().unwrap_or(out_path.clone());
            let file_path_abs = file_path.canonicalize().unwrap_or(file_path.clone());

            println!("dumped {} bytes", data.len());
            println!("- out: {}", abbreviate_path(&out_path_abs, &datadir_abs, &output_abs));
            println!("- src: {}", abbreviate_path(&file_path_abs, &datadir_abs, &output_abs));
        }
    }

    println!();
    Ok(())
}

fn dump_static_files_raw(datadir: &Path, output: &Path) -> Result<()> {
    let static_path = datadir.join("static_files");

    if !static_path.exists() {
        return Ok(());
    }

    // Get absolute paths for abbreviation
    let datadir_abs = datadir.canonicalize().unwrap_or(datadir.to_path_buf());
    let output_abs = output.canonicalize().unwrap_or(output.to_path_buf());

    println!("Static Files:");

    // Find all static file segments
    let entries = fs::read_dir(&static_path)?;
    let mut segments = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let filename = path.file_name().unwrap().to_str().unwrap();
            if !filename.ends_with(".off") && !filename.ends_with(".conf") && filename != "lock" {
                segments.push((filename.to_string(), path));
            }
        }
    }

    segments.sort_by(|a, b| a.0.cmp(&b.0));

    for (filename, file_path) in segments {
        let data = fs::read(&file_path)?;
        let hex_data = hex::encode(&data);

        let out_name = format!("{}.hex", filename);
        let out_path = output.join(format!("raw_{}", out_name));
        fs::write(&out_path, &hex_data)?;

        let out_path_abs = out_path.canonicalize().unwrap_or(out_path.clone());
        let file_path_abs = file_path.canonicalize().unwrap_or(file_path.clone());

        println!("dumped {} bytes", data.len());
        println!("- out: {}", abbreviate_path(&out_path_abs, &datadir_abs, &output_abs));
        println!("- src: {}", abbreviate_path(&file_path_abs, &datadir_abs, &output_abs));
    }

    println!();
    Ok(())
}
