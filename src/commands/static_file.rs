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

            println!("=== Dumping all static file data ===\n");

            // Dump headers
            println!("Parsing headers...");
            let (headers, header_files) = analyzer.dump_all_headers()?;
            if !headers.is_empty() {
                let headers_path = output.join("static_file_headers.json");
                let json = serde_json::to_string_pretty(&headers)?;
                std::fs::write(&headers_path, json)?;
                println!("✓ Dumped {} headers to: {}", headers.len(), headers_path.display());
                println!("  Source files: {:?}", header_files);
            } else {
                println!("✗ No headers found");
            }

            // Dump transactions
            println!("\nParsing transactions...");
            let (transactions, tx_files) = analyzer.dump_all_transactions()?;
            if !transactions.is_empty() {
                let txs_path = output.join("static_file_transactions.json");
                let json = serde_json::to_string_pretty(&transactions)?;
                std::fs::write(&txs_path, json)?;
                println!("✓ Dumped {} transactions to: {}", transactions.len(), txs_path.display());
                println!("  Source files: {:?}", tx_files);
            } else {
                println!("✗ No transactions found");
            }

            // Dump receipts
            println!("\nParsing receipts...");
            let (receipts, receipt_files) = analyzer.dump_all_receipts()?;
            if !receipts.is_empty() {
                let receipts_path = output.join("static_file_receipts.json");
                let json = serde_json::to_string_pretty(&receipts)?;
                std::fs::write(&receipts_path, json)?;
                println!("✓ Dumped {} receipts to: {}", receipts.len(), receipts_path.display());
                println!("  Source files: {:?}", receipt_files);
            } else {
                println!("✗ No receipts found");
            }
        }
        Some(StaticFileAction::DumpHeaders) => {
            println!("=== Dumping Headers ===\n");
            let (headers, source_files) = analyzer.dump_all_headers()?;
            if !headers.is_empty() {
                let headers_path = output.join("static_file_headers.json");
                let json = serde_json::to_string_pretty(&headers)?;
                std::fs::write(&headers_path, json)?;
                println!("✓ Dumped {} headers to: {}", headers.len(), headers_path.display());
                println!("  Source files: {:?}", source_files);
            } else {
                println!("✗ No headers found");
            }
        }
        Some(StaticFileAction::DumpTransactions) => {
            println!("=== Dumping Transactions ===\n");
            let (transactions, source_files) = analyzer.dump_all_transactions()?;
            if !transactions.is_empty() {
                let txs_path = output.join("static_file_transactions.json");
                let json = serde_json::to_string_pretty(&transactions)?;
                std::fs::write(&txs_path, json)?;
                println!("✓ Dumped {} transactions to: {}", transactions.len(), txs_path.display());
                println!("  Source files: {:?}", source_files);
            } else {
                println!("✗ No transactions found");
            }
        }
        Some(StaticFileAction::DumpReceipts) => {
            println!("=== Dumping Receipts ===\n");
            let (receipts, source_files) = analyzer.dump_all_receipts()?;
            if !receipts.is_empty() {
                let receipts_path = output.join("static_file_receipts.json");
                let json = serde_json::to_string_pretty(&receipts)?;
                std::fs::write(&receipts_path, json)?;
                println!("✓ Dumped {} receipts to: {}", receipts.len(), receipts_path.display());
                println!("  Source files: {:?}", source_files);
            } else {
                println!("✗ No receipts found");
            }
        }
    }

    Ok(())
}
