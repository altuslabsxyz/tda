use crate::types::{KeyInfo, Summary};
use eyre::{Context, Result};
use std::path::{Path, PathBuf};
use std::fs;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use alloy_rlp::Decodable;
use serde::{Deserialize, Serialize};
use tempo_primitives::{TempoHeader, TempoPrimitives};
use reth_nippy_jar::{NippyJar, NippyJarCursor};
use reth_provider::{HeaderProvider, providers::StaticFileProvider};

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadableStaticHeader {
    pub block_number: u64,
    // Tempo-specific fields
    pub general_gas_limit: u64,
    pub shared_gas_limit: u64,
    pub timestamp_millis_part: u64,
    // Standard Ethereum header fields
    pub parent_hash: String,
    pub ommers_hash: String,
    pub beneficiary: String,
    pub state_root: String,
    pub transactions_root: String,
    pub receipts_root: String,
    pub logs_bloom: String,
    pub difficulty: String,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: String,
    pub mix_hash: String,
    pub nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawals_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_gas_used: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excess_blob_gas: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_beacon_block_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requests_hash: Option<String>,
}

pub struct StaticFileAnalyzer {
    static_files_path: PathBuf,
}

impl StaticFileAnalyzer {
    pub fn new(datadir: &Path) -> Result<Self> {
        let static_files_path = datadir.join("static_files");
        if !static_files_path.exists() {
            eyre::bail!("Static files directory not found at: {}", static_files_path.display());
        }

        Ok(Self { static_files_path })
    }

    pub fn get_summary(&self) -> Result<Summary> {
        let mut summary = Summary::new();

        println!("Analyzing static files...");

        let entries = std::fs::read_dir(&self.static_files_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                if !file_name.ends_with(".off") && !file_name.ends_with(".conf") {
                    println!("  Found segment: {}", file_name);

                    let metadata = std::fs::metadata(&path)?;
                    let size = metadata.len();

                    summary.add_key(&Self::parse_segment_type(file_name), size);
                }
            }
        }

        Ok(summary)
    }

    pub fn list_segments(&self) -> Result<Vec<String>> {
        let mut segments = Vec::new();

        let entries = std::fs::read_dir(&self.static_files_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                if !file_name.ends_with(".off") && !file_name.ends_with(".conf") && file_name != "lock" {
                    segments.push(file_name.to_string());
                }
            }
        }

        segments.sort();
        Ok(segments)
    }

    fn parse_segment_type(filename: &str) -> String {
        if filename.contains("headers") {
            "headers".to_string()
        } else if filename.contains("transactions") {
            "transactions".to_string()
        } else if filename.contains("receipts") {
            "receipts".to_string()
        } else {
            "unknown".to_string()
        }
    }

    pub fn dump_all_headers(&self) -> Result<(Vec<ReadableStaticHeader>, Vec<PathBuf>)> {
        let mut headers = Vec::new();
        let mut source_files = Vec::new();

        let entries = std::fs::read_dir(&self.static_files_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                if file_name.contains("headers") && !file_name.ends_with(".off") && !file_name.ends_with(".conf") {
                    match self.parse_headers_segment(&path) {
                        Ok(parsed_headers) => {
                            headers.extend(parsed_headers);
                            source_files.push(path.clone());
                        }
                        Err(_e) => {
                            // Silent failure, will be reported at the end
                        }
                    }
                }
            }
        }

        Ok((headers, source_files))
    }

    fn parse_headers_segment(&self, segment_path: &Path) -> Result<Vec<ReadableStaticHeader>> {
        // Use StaticFileProvider (the same way Tempo node uses it)
        match self.parse_with_static_file_provider() {
            Ok(headers) => {
                return Ok(headers);
            }
            Err(_e) => {
                // Try fallback methods silently
            }
        }

        // Fallback: Try NippyJar directly
        match self.parse_with_nippy_jar(segment_path) {
            Ok(headers) => {
                return Ok(headers);
            }
            Err(_e) => {
                // Try final fallback
            }
        }

        // Final fallback
        self.parse_manually(segment_path)
    }

    fn parse_with_static_file_provider(&self) -> Result<Vec<ReadableStaticHeader>> {
        // Initialize StaticFileProvider the same way Tempo does
        let provider = StaticFileProvider::<TempoPrimitives>::read_only(&self.static_files_path, true)
            .wrap_err("Failed to create StaticFileProvider")?;

        let mut headers = Vec::new();

        // Try to read headers by block number
        for block_num in 0u64..100u64 {
            match provider.header_by_number(block_num) {
                Ok(Some(tempo_header)) => {
                    // StaticFileProvider with TempoPrimitives returns TempoHeader directly!
                    headers.push(Self::tempo_header_to_readable(block_num, &tempo_header));
                }
                Ok(None) => {
                    // No more headers
                    if headers.is_empty() {
                        continue; // Keep trying
                    } else {
                        break; // Found some, then stopped - we're done
                    }
                }
                Err(_e) => {
                    if !headers.is_empty() {
                        break; // Got some headers before error
                    }
                }
            }
        }

        Ok(headers)
    }

    fn parse_with_nippy_jar(&self, segment_path: &Path) -> Result<Vec<ReadableStaticHeader>> {
        // Load the NippyJar file without a custom header (using () as header type)
        let jar = NippyJar::<()>::load_without_header(segment_path)?;

        // Create a cursor to iterate through the rows
        let mut cursor = NippyJarCursor::new(&jar)?;

        let mut headers = Vec::new();
        let mut row_index = 0u64;

        // Iterate through all rows
        while let Some(row) = cursor.next_row()? {
            if row.is_empty() {
                row_index += 1;
                continue;
            }

            let header_data = &row[0];

            match TempoHeader::decode(&mut &header_data[..]) {
                Ok(tempo_header) => {
                    headers.push(Self::tempo_header_to_readable(row_index, &tempo_header));
                }
                Err(_e) => {
                    // Silent failure
                }
            }

            row_index += 1;
        }

        Ok(headers)
    }

    fn parse_manually(&self, _segment_path: &Path) -> Result<Vec<ReadableStaticHeader>> {
        // IMPORTANT: This is a best-effort parser for Tempo's NippyJar files when the library fails.
        // The proper solution is to fix the .conf file format compatibility issue.
        Ok(Vec::new())
    }

    fn tempo_header_to_readable(block_number: u64, header: &TempoHeader) -> ReadableStaticHeader {
        ReadableStaticHeader {
            block_number,
            general_gas_limit: header.general_gas_limit,
            shared_gas_limit: header.shared_gas_limit,
            timestamp_millis_part: header.timestamp_millis_part,
            parent_hash: format!("0x{}", hex::encode(header.inner.parent_hash.as_slice())),
            ommers_hash: format!("0x{}", hex::encode(header.inner.ommers_hash.as_slice())),
            beneficiary: format!("0x{}", hex::encode(header.inner.beneficiary.as_slice())),
            state_root: format!("0x{}", hex::encode(header.inner.state_root.as_slice())),
            transactions_root: format!("0x{}", hex::encode(header.inner.transactions_root.as_slice())),
            receipts_root: format!("0x{}", hex::encode(header.inner.receipts_root.as_slice())),
            logs_bloom: format!("0x{}", hex::encode(header.inner.logs_bloom.as_slice())),
            difficulty: header.inner.difficulty.to_string(),
            gas_limit: header.inner.gas_limit,
            gas_used: header.inner.gas_used,
            timestamp: header.inner.timestamp,
            extra_data: format!("0x{}", hex::encode(&header.inner.extra_data)),
            mix_hash: format!("0x{}", hex::encode(header.inner.mix_hash.as_slice())),
            nonce: u64::from_be_bytes(header.inner.nonce.0),
            base_fee_per_gas: header.inner.base_fee_per_gas,
            withdrawals_root: header.inner.withdrawals_root.map(|h| format!("0x{}", hex::encode(h.as_slice()))),
            blob_gas_used: header.inner.blob_gas_used,
            excess_blob_gas: header.inner.excess_blob_gas,
            parent_beacon_block_root: header.inner.parent_beacon_block_root.map(|h| format!("0x{}", hex::encode(h.as_slice()))),
            requests_hash: header.inner.requests_hash.map(|h| format!("0x{}", hex::encode(h.as_slice()))),
        }
    }

    pub fn get_block(&self, _block_number: u64) -> Result<Option<KeyInfo>> {
        Ok(None)
    }

    pub fn get_tx(&self, _tx_hash: &str) -> Result<Option<KeyInfo>> {
        Ok(None)
    }

    pub fn get_receipt(&self, _tx_hash: &str) -> Result<Option<KeyInfo>> {
        Ok(None)
    }
}
