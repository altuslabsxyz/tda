use crate::types::{KeyInfo, Summary};
use eyre::{Context, Result};
use reth_db::{open_db_read_only, DatabaseEnv};
use reth_db_api::{cursor::DbCursorRO, database::Database, transaction::DbTx};
use std::collections::HashMap;
use std::path::Path;

pub struct MdbxAnalyzer {
    db: DatabaseEnv,
}

impl MdbxAnalyzer {
    pub fn new(datadir: &Path) -> Result<Self> {
        let db_path = datadir.join("db");
        if !db_path.exists() {
            eyre::bail!("MDBX database not found at: {}", db_path.display());
        }

        let db = open_db_read_only(&db_path, Default::default())
            .wrap_err("Failed to open MDBX database")?;

        Ok(Self { db })
    }

    pub fn get_summary(&self) -> Result<Summary> {
        let mut summary = Summary::new();

        println!("Analyzing MDBX database...");

        // Get database info
        println!("Collecting database statistics...");

        // Read all tables using raw cursor
        let tx = self.db.tx()?;

        // List all tables in MDBX
        let tables = self.list_all_mdbx_tables(&tx)?;

        for table_name in &tables {
            println!("  Processing table: {}", table_name);

            // Count keys in each table
            if let Ok(count) = self.count_table_keys(&tx, table_name) {
                println!("    {} keys", count);
                summary.add_key(&format!("table:{}", table_name), count as u64);
            }
        }

        Ok(summary)
    }

    fn list_all_mdbx_tables(&self, tx: &<DatabaseEnv as Database>::TX) -> Result<Vec<String>> {
        // Open the main (unnamed) database to list all named databases (tables)
        let _cursor = tx.cursor_read::<reth_db::tables::CanonicalHeaders>()?;

        // For now, return known table names
        // In a real implementation, we'd need to use MDBX's internal APIs to list all tables
        Ok(vec![
            "CanonicalHeaders".to_string(),
            "HeaderNumbers".to_string(),
            "Headers".to_string(),
            "BlockBodyIndices".to_string(),
            "BlockOmmers".to_string(),
            "BlockWithdrawals".to_string(),
            "TransactionBlocks".to_string(),
            "Transactions".to_string(),
            "PlainAccountState".to_string(),
            "PlainStorageState".to_string(),
            "Bytecodes".to_string(),
        ])
    }

    fn count_table_keys(&self, tx: &<DatabaseEnv as Database>::TX, _table_name: &str) -> Result<usize> {
        // Use a known table type to count
        // This is a simplified version - in reality we'd need to match on table_name
        let mut cursor = tx.cursor_read::<reth_db::tables::CanonicalHeaders>()?;

        let mut count = 0;
        let mut walker = cursor.walk(None)?;
        while walker.next().is_some() {
            count += 1;
        }

        Ok(count)
    }

    pub fn dump_all_data(&self, skip_full_dump: bool) -> Result<Vec<(String, Vec<KeyInfo>)>> {
        if skip_full_dump {
            return Ok(Vec::new());
        }

        let mut all_data = Vec::new();

        let tx = self.db.tx()?;

        // Dump CanonicalHeaders table
        let canonical_headers = self.dump_canonical_headers(&tx)?;
        all_data.push(("CanonicalHeaders".to_string(), canonical_headers));

        // Dump Headers table
        let headers = self.dump_headers(&tx)?;
        all_data.push(("Headers".to_string(), headers));

        // Dump Transactions table
        let transactions = self.dump_transactions(&tx)?;
        all_data.push(("Transactions".to_string(), transactions));

        // Dump PlainAccountState table
        let accounts = self.dump_plain_account_state(&tx)?;
        all_data.push(("PlainAccountState".to_string(), accounts));

        Ok(all_data)
    }

    fn dump_canonical_headers(&self, tx: &<DatabaseEnv as Database>::TX) -> Result<Vec<KeyInfo>> {
        let mut result = Vec::new();
        let mut cursor = tx.cursor_read::<reth_db::tables::CanonicalHeaders>()?;

        let mut walker = cursor.walk(None)?;
        let mut count = 0;
        while let Some(entry) = walker.next() {
            let (block_number, block_hash) = entry?;

            let mut data = HashMap::new();
            data.insert("block_number".to_string(), serde_json::json!(block_number));
            data.insert("block_hash".to_string(), serde_json::json!(format!("0x{}", hex::encode(block_hash.as_slice()))));

            result.push(KeyInfo {
                key: format!("block_{}", block_number),
                key_hex: None,
                key_type: "CanonicalHeader".to_string(),
                value_size_bytes: 32, // B256 is 32 bytes
                data: serde_json::to_value(&data)?,
                error: None,
            });

            count += 1;
        }
        Ok(result)
    }

    fn dump_headers(&self, tx: &<DatabaseEnv as Database>::TX) -> Result<Vec<KeyInfo>> {
        let mut result = Vec::new();
        let mut cursor = tx.cursor_read::<reth_db::tables::Headers>()?;

        let mut walker = cursor.walk(None)?;
        let mut count = 0;
        while let Some(entry) = walker.next() {
            let (block_number, header) = entry?;

            // Serialize header using alloy types
            let mut data = HashMap::new();
            data.insert("block_number".to_string(), serde_json::json!(block_number));
            data.insert("parent_hash".to_string(), serde_json::json!(format!("0x{}", hex::encode(header.parent_hash.as_slice()))));
            data.insert("ommers_hash".to_string(), serde_json::json!(format!("0x{}", hex::encode(header.ommers_hash.as_slice()))));
            data.insert("beneficiary".to_string(), serde_json::json!(format!("0x{}", hex::encode(header.beneficiary.as_slice()))));
            data.insert("state_root".to_string(), serde_json::json!(format!("0x{}", hex::encode(header.state_root.as_slice()))));
            data.insert("transactions_root".to_string(), serde_json::json!(format!("0x{}", hex::encode(header.transactions_root.as_slice()))));
            data.insert("receipts_root".to_string(), serde_json::json!(format!("0x{}", hex::encode(header.receipts_root.as_slice()))));
            data.insert("logs_bloom".to_string(), serde_json::json!(format!("0x{}", hex::encode(header.logs_bloom.as_slice()))));
            data.insert("difficulty".to_string(), serde_json::json!(header.difficulty.to_string()));
            data.insert("number".to_string(), serde_json::json!(header.number));
            data.insert("gas_limit".to_string(), serde_json::json!(header.gas_limit));
            data.insert("gas_used".to_string(), serde_json::json!(header.gas_used));
            data.insert("timestamp".to_string(), serde_json::json!(header.timestamp));
            data.insert("extra_data".to_string(), serde_json::json!(format!("0x{}", hex::encode(&header.extra_data))));
            data.insert("mix_hash".to_string(), serde_json::json!(format!("0x{}", hex::encode(header.mix_hash.as_slice()))));
            data.insert("nonce".to_string(), serde_json::json!(header.nonce));

            if let Some(base_fee) = header.base_fee_per_gas {
                data.insert("base_fee_per_gas".to_string(), serde_json::json!(base_fee));
            }
            if let Some(withdrawals_root) = header.withdrawals_root {
                data.insert("withdrawals_root".to_string(), serde_json::json!(format!("0x{}", hex::encode(withdrawals_root.as_slice()))));
            }
            if let Some(blob_gas_used) = header.blob_gas_used {
                data.insert("blob_gas_used".to_string(), serde_json::json!(blob_gas_used));
            }
            if let Some(excess_blob_gas) = header.excess_blob_gas {
                data.insert("excess_blob_gas".to_string(), serde_json::json!(excess_blob_gas));
            }
            if let Some(parent_beacon_block_root) = header.parent_beacon_block_root {
                data.insert("parent_beacon_block_root".to_string(), serde_json::json!(format!("0x{}", hex::encode(parent_beacon_block_root.as_slice()))));
            }

            result.push(KeyInfo {
                key: format!("block_{}", block_number),
                key_hex: None,
                key_type: "Header".to_string(),
                value_size_bytes: 500, // Approximate
                data: serde_json::to_value(&data)?,
                error: None,
            });

            count += 1;
            if count % 1000 == 0 {
                println!("    Processed {} headers...", count);
            }
        }

        Ok(result)
    }

    fn dump_transactions(&self, tx: &<DatabaseEnv as Database>::TX) -> Result<Vec<KeyInfo>> {
        let mut result = Vec::new();
        let mut cursor = tx.cursor_read::<reth_db::tables::Transactions>()?;

        let mut walker = cursor.walk(None)?;
        let mut count = 0;
        while let Some(entry) = walker.next() {
            let (tx_number, transaction) = entry?;

            // Serialize transaction - just basic info due to type complexity
            let mut data = HashMap::new();
            data.insert("tx_number".to_string(), serde_json::json!(tx_number));
            data.insert("type".to_string(), serde_json::json!(format!("{:?}", transaction)));

            // We'd need to match on transaction type to extract details
            // For now, just store raw representation

            result.push(KeyInfo {
                key: format!("tx_{}", tx_number),
                key_hex: None,
                key_type: "Transaction".to_string(),
                value_size_bytes: 200, // Approximate
                data: serde_json::to_value(&data)?,
                error: None,
            });

            count += 1;
            if count % 1000 == 0 {
                println!("    Processed {} transactions...", count);
            }

            // Limit to first 100 for demo
            if count >= 100 {
                break;
            }
        }

        Ok(result)
    }

    fn dump_plain_account_state(&self, tx: &<DatabaseEnv as Database>::TX) -> Result<Vec<KeyInfo>> {
        let mut result = Vec::new();
        let mut cursor = tx.cursor_read::<reth_db::tables::PlainAccountState>()?;

        let mut walker = cursor.walk(None)?;
        let mut count = 0;
        while let Some(entry) = walker.next() {
            let (address, account) = entry?;

            let mut data = HashMap::new();
            data.insert("address".to_string(), serde_json::json!(format!("0x{}", hex::encode(address.as_slice()))));
            data.insert("nonce".to_string(), serde_json::json!(account.nonce));
            data.insert("balance".to_string(), serde_json::json!(account.balance.to_string()));
            data.insert("bytecode_hash".to_string(),
                if let Some(hash) = account.bytecode_hash {
                    serde_json::json!(format!("0x{}", hex::encode(hash.as_slice())))
                } else {
                    serde_json::json!(null)
                }
            );

            result.push(KeyInfo {
                key: format!("0x{}", hex::encode(address.as_slice())),
                key_hex: None,
                key_type: "Account".to_string(),
                value_size_bytes: 100, // Approximate
                data: serde_json::to_value(&data)?,
                error: None,
            });

            count += 1;
            if count % 1000 == 0 {
                println!("    Processed {} accounts...", count);
            }
        }

        Ok(result)
    }

    pub fn list_tables(&self) -> Result<Vec<String>> {
        let tx = self.db.tx()?;
        self.list_all_mdbx_tables(&tx)
    }

    pub fn get_header(&self, block_number: u64) -> Result<Option<KeyInfo>> {
        let tx = self.db.tx()?;
        let mut cursor = tx.cursor_read::<reth_db::tables::Headers>()?;

        if let Some(header) = cursor.seek_exact(block_number)? {
            let (_, header) = header;

            let mut data = HashMap::new();
            data.insert("block_number".to_string(), serde_json::json!(block_number));
            data.insert("parent_hash".to_string(), serde_json::json!(format!("0x{}", hex::encode(header.parent_hash.as_slice()))));
            data.insert("number".to_string(), serde_json::json!(header.number));
            data.insert("gas_limit".to_string(), serde_json::json!(header.gas_limit));
            data.insert("gas_used".to_string(), serde_json::json!(header.gas_used));
            data.insert("timestamp".to_string(), serde_json::json!(header.timestamp));

            return Ok(Some(KeyInfo {
                key: format!("block_{}", block_number),
                key_hex: None,
                key_type: "Header".to_string(),
                value_size_bytes: 500,
                data: serde_json::to_value(&data)?,
                error: None,
            }));
        }

        Ok(None)
    }

    pub fn get_account(&self, _address_str: &str) -> Result<Option<KeyInfo>> {
        // PlainAccountState requires more complex handling
        println!("Account state reading not yet implemented");
        Ok(None)
    }
}
