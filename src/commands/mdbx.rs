use crate::analyzer::mdbx::MdbxAnalyzer;
use crate::MdbxAction;
use eyre::Result;
use std::path::Path;

pub fn handle_command(
    datadir: &Path,
    output: &Path,
    action: Option<MdbxAction>,
    skip_full_dump: bool,
) -> Result<()> {
    let analyzer = MdbxAnalyzer::new(datadir)?;

    match action {
        Some(MdbxAction::ListTables) => {
            println!("=== MDBX Tables ===\n");
            let tables = analyzer.list_tables()?;
            for table in tables {
                println!("  - {}", table);
            }
        }
        Some(MdbxAction::Summary) | None => {
            println!("=== MDBX Database Summary ===\n");
            let summary = analyzer.get_summary()?;
            summary.print_summary();

            // Save summary to JSON
            let summary_path = output.join("mdbx_summary.json");
            let json = serde_json::to_string_pretty(&summary)?;
            std::fs::write(&summary_path, json)?;
            println!("\n✓ Summary saved to: {}", summary_path.display());
        }
        Some(MdbxAction::GetHeader { block_number }) => {
            if let Some(key_info) = analyzer.get_header(block_number)? {
                let json = serde_json::to_string_pretty(&key_info)?;
                println!("{}", json);
            } else {
                println!("Header not found for block {}", block_number);
            }
        }
        Some(MdbxAction::GetAccount { address }) => {
            if let Some(key_info) = analyzer.get_account(&address)? {
                let json = serde_json::to_string_pretty(&key_info)?;
                println!("{}", json);
            } else {
                println!("Account not found: {}", address);
            }
        }
        Some(MdbxAction::DumpAll) => {
            if skip_full_dump {
                println!("Skipping full dump (--skip-full-dump enabled)");
                return Ok(());
            }

            println!("=== Dumping all MDBX data ===\n");

            // Dump all tables
            let all_data = analyzer.dump_all_data(skip_full_dump)?;

            // Save each table to a separate JSON file
            for (table_name, entries) in all_data {
                let filename = output.join(format!("mdbx_{}_dump.json", table_name));
                let json = serde_json::to_string_pretty(&entries)?;
                std::fs::write(&filename, json)?;
                println!("✓ Saved {} entries to: {}", entries.len(), filename.display());
            }

            println!("\n✓ All MDBX data dumped successfully");
        }
    }

    Ok(())
}
