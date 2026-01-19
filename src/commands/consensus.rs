use crate::analyzer::consensus::ConsensusAnalyzer;
use crate::ConsensusAction;
use eyre::Result;
use std::path::Path;

pub async fn handle_command(
    datadir: &Path,
    output: &Path,
    action: Option<ConsensusAction>,
    skip_full_dump: bool,
) -> Result<()> {
    let analyzer = ConsensusAnalyzer::new(datadir)?;

    match action {
        Some(ConsensusAction::Summary) | None => {
            println!("=== Consensus Storage Summary ===\n");
            let summary = analyzer.get_summary().await?;
            summary.print_summary();

            // Save summary to JSON
            let summary_path = output.join("consensus_summary.json");
            let json = serde_json::to_string_pretty(&summary)?;
            std::fs::write(&summary_path, json)?;
            println!("\n✓ Summary saved to: {}", summary_path.display());
        }
        Some(ConsensusAction::GetBlock { height }) => {
            if let Some(key_info) = analyzer.get_block(height).await? {
                let json = serde_json::to_string_pretty(&key_info)?;
                println!("{}", json);
            } else {
                println!("Block not found at height {}", height);
            }
        }
        Some(ConsensusAction::ListFinalizations { start, end }) => {
            let finalizations = analyzer.list_finalizations(start, end).await?;
            println!("Found {} finalizations", finalizations.len());

            if !finalizations.is_empty() {
                let json = serde_json::to_string_pretty(&finalizations)?;
                let output_path = output.join(format!("finalizations_{}_{}.json", start, end));
                std::fs::write(&output_path, json)?;
                println!("✓ Saved to: {}", output_path.display());
            }
        }
        Some(ConsensusAction::DumpAll) => {
            if skip_full_dump {
                println!("Skipping full dump (--skip-full-dump enabled)");
                return Ok(());
            }

            println!("=== Dumping all consensus data ===");
            println!("Note: This is not yet fully implemented.");
            println!("Would iterate through all partitions and export to JSON files.");
        }
    }

    Ok(())
}
