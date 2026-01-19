use crate::analyzer::static_file::StaticFileAnalyzer;
use crate::StaticFileAction;
use eyre::Result;
use std::path::Path;

pub fn handle_command(
    datadir: &Path,
    output: &Path,
    action: Option<StaticFileAction>,
    skip_full_dump: bool,
) -> Result<()> {
    let analyzer = StaticFileAnalyzer::new(datadir)?;

    match action {
        Some(StaticFileAction::ListSegments) => {
            println!("=== Static File Segments ===\n");
            let segments = analyzer.list_segments()?;
            for segment in segments {
                println!("  - {}", segment);
            }
        }
        Some(StaticFileAction::Summary) | None => {
            println!("=== Static Files Summary ===\n");
            let summary = analyzer.get_summary()?;
            summary.print_summary();

            // Save summary to JSON
            let summary_path = output.join("static_files_summary.json");
            let json = serde_json::to_string_pretty(&summary)?;
            std::fs::write(&summary_path, json)?;
            println!("\n✓ Summary saved to: {}", summary_path.display());
        }
        Some(StaticFileAction::GetBlock { block_number }) => {
            if let Some(key_info) = analyzer.get_block(block_number)? {
                let json = serde_json::to_string_pretty(&key_info)?;
                println!("{}", json);
            } else {
                println!("Block not found: {}", block_number);
            }
        }
        Some(StaticFileAction::GetTx { tx_hash }) => {
            if let Some(key_info) = analyzer.get_tx(&tx_hash)? {
                let json = serde_json::to_string_pretty(&key_info)?;
                println!("{}", json);
            } else {
                println!("Transaction not found: {}", tx_hash);
            }
        }
        Some(StaticFileAction::GetReceipt { tx_hash }) => {
            if let Some(key_info) = analyzer.get_receipt(&tx_hash)? {
                let json = serde_json::to_string_pretty(&key_info)?;
                println!("{}", json);
            } else {
                println!("Receipt not found: {}", tx_hash);
            }
        }
        Some(StaticFileAction::DumpAll) => {
            if skip_full_dump {
                println!("Skipping full dump (--skip-full-dump enabled)");
                return Ok(());
            }

            println!("=== Dumping all static file data ===");
            println!("Note: This is not yet fully implemented.");
            println!("Would iterate through all segments and export to JSON files.");
        }
    }

    Ok(())
}
